"""Validated, venue-specific instrument catalog and execution contracts.

The module is offline-only: it describes how a canonical instrument binds to
a venue contract and what that venue may support. It grants no dispatch
authority and performs no transport or market-data access.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from enum import StrEnum
from typing import NoReturn, Protocol, SupportsIndex

from leviathan_core.execution.broker_port_v1 import (
    AccountViewV1,
    BalanceV1,
    BrokerEnvironment,
    BrokerPortError,
    BrokerVenue,
    EquityEvidenceV1,
    VenueIdentityV1,
    require_account_view,
)
from leviathan_core.execution.cancel_policy import MassCancelResultV1
from leviathan_core.execution.order_models import OrderTypeV1, TimeInForceV1
from leviathan_core.numeric import NumericError, exact_mul, parse_decimal

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z", re.ASCII)
_CURRENCY = re.compile(r"[A-Z]{3}\Z", re.ASCII)
_JURISDICTION = re.compile(r"[A-Z]{2}\Z", re.ASCII)
_DIGEST = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)


class ExecutionContractError(ValueError):
    """Input-free validation error for the execution contract."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class _Frozen:
    def __copy__(self) -> NoReturn:
        raise TypeError("EXECUTION_CONTRACT_COPY_FORBIDDEN")

    def __deepcopy__(self, memo: dict[int, object]) -> NoReturn:
        raise TypeError("EXECUTION_CONTRACT_COPY_FORBIDDEN")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise TypeError("EXECUTION_CONTRACT_PICKLE_FORBIDDEN")


def _id(value: object) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise ExecutionContractError("INVALID_IDENTIFIER")
    return value


def _decimal(value: object, *, positive: bool = False) -> Decimal:
    if type(value) is not Decimal or not value.is_finite():
        raise ExecutionContractError("INVALID_DECIMAL")
    digits = value.as_tuple().digits
    significant = len(digits)
    while significant > 1 and digits[significant - 1] == 0:
        significant -= 1
    if significant > 34 or abs(value.adjusted()) > 38 or (positive and value <= 0):
        raise ExecutionContractError("INVALID_DECIMAL")
    try:
        return parse_decimal(value, field="contract_decimal")
    except NumericError:
        raise ExecutionContractError("INVALID_DECIMAL") from None


class AssetClassV1(StrEnum):
    EQUITY = "EQUITY"
    INDEX = "INDEX"
    FUTURE = "FUTURE"
    OPTION = "OPTION"
    FOREX = "FOREX"
    METAL = "METAL"
    CRYPTO = "CRYPTO"
    PREDICTION = "PREDICTION"


class RollPolicyV1(StrEnum):
    NONE = "NONE"
    CALENDAR = "CALENDAR"
    VOLUME = "VOLUME"
    OPEN_INTEREST = "OPEN_INTEREST"
    MANUAL = "MANUAL"


class SessionCalendarPortV1(Protocol):
    """Resolve an instant to the venue's trading date for a calendar ref."""

    def trading_date(self, calendar_ref: str, as_of: datetime) -> date: ...


class MassCancelCompletionV1(StrEnum):
    COMPLETE = "COMPLETE"
    COMPLETE_WITH_REJECTIONS = "COMPLETE_WITH_REJECTIONS"
    COMPLETE_WITH_UNCONFIRMED = "COMPLETE_WITH_UNCONFIRMED"
    IN_PROGRESS = "IN_PROGRESS"


@dataclass(frozen=True, slots=True)
class VenueInstrumentBindingV1(_Frozen):
    """One canonical instrument's exact symbol and contract at one venue."""

    instrument_id: str
    venue: BrokerVenue
    environment: BrokerEnvironment
    venue_symbol: str
    native_contract_id: str
    asset_class: AssetClassV1
    tick_size: Decimal
    lot_size: Decimal
    currency: str
    session_calendar_ref: str
    revision: str
    contract_multiplier: Decimal | None = None
    expiry: date | None = None
    roll_policy: RollPolicyV1 = RollPolicyV1.NONE
    jurisdiction: str | None = None
    product_flags: tuple[str, ...] = ()
    listed_at: date | None = None
    last_trade: date | None = None

    def __post_init__(self) -> None:
        for value in (
            self.instrument_id,
            self.venue_symbol,
            self.native_contract_id,
            self.session_calendar_ref,
            self.revision,
        ):
            _id(value)
        if (
            type(self.venue) is not BrokerVenue
            or type(self.environment) is not BrokerEnvironment
            or type(self.asset_class) is not AssetClassV1
            or type(self.roll_policy) is not RollPolicyV1
            or type(self.currency) is not str
            or _CURRENCY.fullmatch(self.currency) is None
        ):
            raise ExecutionContractError("INVALID_INSTRUMENT_BINDING")
        object.__setattr__(self, "tick_size", _decimal(self.tick_size, positive=True))
        object.__setattr__(self, "lot_size", _decimal(self.lot_size, positive=True))
        if self.contract_multiplier is not None:
            object.__setattr__(
                self, "contract_multiplier", _decimal(self.contract_multiplier, positive=True)
            )
        if any(
            value is not None and type(value) is not date
            for value in (self.expiry, self.listed_at, self.last_trade)
        ):
            raise ExecutionContractError("INVALID_INSTRUMENT_BINDING")
        if (
            self.listed_at is not None
            and self.last_trade is not None
            and self.listed_at > self.last_trade
        ):
            raise ExecutionContractError("INVALID_CONTRACT_DATES")
        if (
            self.last_trade is not None
            and self.expiry is not None
            and self.last_trade > self.expiry
        ):
            raise ExecutionContractError("INVALID_CONTRACT_DATES")
        if self.listed_at is not None and self.expiry is not None and self.listed_at > self.expiry:
            raise ExecutionContractError("INVALID_CONTRACT_DATES")
        if self.roll_policy is RollPolicyV1.NONE and (
            self.expiry is not None or self.last_trade is not None
        ):
            # A dated contract must describe how its successor is selected.
            raise ExecutionContractError("INVALID_ROLL_METADATA")
        if self.jurisdiction is not None and (
            type(self.jurisdiction) is not str or _JURISDICTION.fullmatch(self.jurisdiction) is None
        ):
            raise ExecutionContractError("INVALID_JURISDICTION")
        if (
            type(self.product_flags) is not tuple
            or any(
                type(flag) is not str or _ID.fullmatch(flag) is None for flag in self.product_flags
            )
            or len(set(self.product_flags)) != len(self.product_flags)
        ):
            raise ExecutionContractError("INVALID_PRODUCT_FLAGS")
        if self.asset_class is AssetClassV1.PREDICTION:
            if self.jurisdiction is None or not self.product_flags:
                raise ExecutionContractError("PREDICTION_PRODUCT_SCOPE_REQUIRED")
        elif self.jurisdiction is not None:
            raise ExecutionContractError("JURISDICTION_NOT_APPLICABLE")


@dataclass(frozen=True, slots=True)
class VenueInstrumentCatalogV1(_Frozen):
    revision: str
    bindings: tuple[VenueInstrumentBindingV1, ...]

    def __post_init__(self) -> None:
        _id(self.revision)
        if type(self.bindings) is not tuple or not self.bindings:
            raise ExecutionContractError("INVALID_INSTRUMENT_CATALOG")
        if any(type(binding) is not VenueInstrumentBindingV1 for binding in self.bindings):
            raise ExecutionContractError("INVALID_INSTRUMENT_CATALOG")
        native_keys = [
            (item.venue, item.environment, item.venue_symbol, item.expiry or item.last_trade)
            for item in self.bindings
        ]
        if len(set(native_keys)) != len(native_keys):
            raise ExecutionContractError("CONFLICTING_VENUE_INSTRUMENT_BINDING")
        instrument_month_keys = [
            (
                item.instrument_id,
                item.venue,
                item.environment,
                item.expiry or item.last_trade,
            )
            for item in self.bindings
        ]
        if len(set(instrument_month_keys)) != len(instrument_month_keys):
            raise ExecutionContractError("AMBIGUOUS_INSTRUMENT_BINDING")

    def resolve_order_binding(self, request: object) -> VenueInstrumentBindingV1:
        """Resolve the exact bound contract named by an OMS request."""
        from leviathan_core.execution.order_models import OrderRequest

        if type(request) is not OrderRequest:
            raise ExecutionContractError("INVALID_ORDER_ADMISSION")
        try:
            venue = BrokerVenue(request.venue)
            environment = BrokerEnvironment(request.environment.upper())
        except ValueError:
            raise ExecutionContractError("INSTRUMENT_BINDING_NOT_FOUND") from None
        matches = tuple(
            item
            for item in self.resolve(request.instrument_id, venue, environment)
            if item.native_contract_id == request.native_contract_id
        )
        if len(matches) != 1:
            raise ExecutionContractError(
                "INSTRUMENT_BINDING_NOT_FOUND" if not matches else "AMBIGUOUS_INSTRUMENT_BINDING"
            )
        return matches[0]

    def resolve(
        self,
        instrument_id: str,
        venue: BrokerVenue,
        environment: BrokerEnvironment,
    ) -> tuple[VenueInstrumentBindingV1, ...]:
        _id(instrument_id)
        if type(venue) is not BrokerVenue or type(environment) is not BrokerEnvironment:
            raise ExecutionContractError("INVALID_VENUE_SCOPE")
        return tuple(
            item
            for item in self.bindings
            if item.instrument_id == instrument_id
            and item.venue is venue
            and item.environment is environment
        )

    def resolve_for_month(
        self,
        instrument_id: str,
        venue: BrokerVenue,
        environment: BrokerEnvironment,
        *,
        expiry: date | None,
    ) -> VenueInstrumentBindingV1:
        """Resolve exactly one binding, requiring the month when a chain exists."""
        if expiry is not None and type(expiry) is not date:
            raise ExecutionContractError("INVALID_CONTRACT_DATES")
        matches = tuple(
            item
            for item in self.resolve(instrument_id, venue, environment)
            if (item.expiry or item.last_trade) == expiry
        )
        if len(matches) != 1:
            raise ExecutionContractError("INSTRUMENT_BINDING_NOT_UNIQUE")
        return matches[0]


def require_tradeable(
    binding: VenueInstrumentBindingV1,
    as_of: date | datetime,
    *,
    session_calendar: SessionCalendarPortV1 | None = None,
) -> None:
    """Reject dated bindings before listing or on/after their final trade date.

    Date inputs are already trading-calendar dates. UTC datetime inputs use
    the referenced calendar when supplied, otherwise their UTC civil date.
    The calendar reference is always passed through to the calendar port.
    """
    if type(binding) is not VenueInstrumentBindingV1:
        raise ExecutionContractError("INVALID_INSTRUMENT_BINDING")
    if type(as_of) is date:
        trading_date = as_of
    elif type(as_of) is datetime:
        if as_of.utcoffset() != timedelta(0):
            raise ExecutionContractError("INVALID_AS_OF")
        if session_calendar is None:
            trading_date = as_of.astimezone(UTC).date()
        else:
            try:
                trading_date = session_calendar.trading_date(
                    binding.session_calendar_ref, as_of.astimezone(UTC)
                )
            except Exception:
                raise ExecutionContractError("INVALID_SESSION_CALENDAR") from None
            if type(trading_date) is not date:
                raise ExecutionContractError("INVALID_SESSION_CALENDAR")
    else:
        raise ExecutionContractError("INVALID_AS_OF")
    if binding.listed_at is not None and trading_date < binding.listed_at:
        raise ExecutionContractError("INSTRUMENT_NOT_YET_LISTED")
    final_trade_date = min(
        (value for value in (binding.last_trade, binding.expiry) if value is not None),
        default=None,
    )
    if final_trade_date is not None and trading_date >= final_trade_date:
        raise ExecutionContractError("INSTRUMENT_EXPIRED")


@dataclass(frozen=True, slots=True)
class AccountSnapshotV1(_Frozen):
    """Complete account evidence view for consumers needing all core fields."""

    account_view: AccountViewV1
    venue_identity: VenueIdentityV1
    cash_balances: tuple[BalanceV1, ...]
    equity: EquityEvidenceV1
    buying_power: BalanceV1
    currency: str
    as_of: datetime
    evidence_digest: str

    def __post_init__(self) -> None:
        try:
            view = require_account_view(self.account_view)
        except BrokerPortError:
            raise ExecutionContractError("INVALID_ACCOUNT_SNAPSHOT") from None
        if (
            type(self.venue_identity) is not VenueIdentityV1
            or type(self.cash_balances) is not tuple
            or not self.cash_balances
            or any(type(item) is not BalanceV1 for item in self.cash_balances)
            or type(self.equity) is not EquityEvidenceV1
            or type(self.buying_power) is not BalanceV1
        ):
            raise ExecutionContractError("INVALID_ACCOUNT_SNAPSHOT")
        for item in (*self.cash_balances, self.buying_power):
            try:
                item.assert_sealed()
            except BrokerPortError:
                raise ExecutionContractError("INVALID_ACCOUNT_SNAPSHOT") from None
        try:
            self.equity.assert_sealed()
            self.venue_identity.assert_sealed()
        except BrokerPortError:
            raise ExecutionContractError("INVALID_ACCOUNT_SNAPSHOT") from None
        if (
            type(self.as_of) is not datetime
            or self.as_of.tzinfo is not UTC
            or type(self.currency) is not str
            or _CURRENCY.fullmatch(self.currency) is None
            or type(self.evidence_digest) is not str
            or _DIGEST.fullmatch(self.evidence_digest) is None
        ):
            raise ExecutionContractError("INVALID_ACCOUNT_SNAPSHOT")
        if (
            view.venue_identity != self.venue_identity
            or view.balances != self.cash_balances
            or view.equity != self.equity
            or view.buying_power != self.buying_power
            or view.account_currency != self.currency
            or view.broker_observed_at != self.as_of
            or self.equity.currency != self.currency
            or self.buying_power.currency != self.currency
            or self.evidence_digest != view.evidence_digest
        ):
            raise ExecutionContractError("INVALID_ACCOUNT_SNAPSHOT")


def account_snapshot_from_view(view: AccountViewV1) -> AccountSnapshotV1:
    """Require complete optional evidence before exposing the common snapshot."""
    try:
        verified = require_account_view(view)
    except BrokerPortError:
        raise ExecutionContractError("INVALID_ACCOUNT_SNAPSHOT") from None
    if (
        verified.venue_identity is None
        or verified.balances is None
        or not verified.balances
        or verified.equity is None
        or verified.buying_power is None
        or verified.account_currency is None
        or verified.broker_observed_at is None
    ):
        raise ExecutionContractError("INCOMPLETE_ACCOUNT_SNAPSHOT")
    return AccountSnapshotV1(
        verified,
        verified.venue_identity,
        verified.balances,
        verified.equity,
        verified.buying_power,
        verified.account_currency,
        verified.broker_observed_at,
        verified.evidence_digest,
    )


@dataclass(frozen=True, slots=True)
class VenueOrderSupportV1(_Frozen):
    venue: BrokerVenue
    environment: BrokerEnvironment
    order_types: tuple[OrderTypeV1, ...]
    time_in_force: tuple[TimeInForceV1, ...]
    bracket_via_oco: bool = False

    def __post_init__(self) -> None:
        if (
            type(self.venue) is not BrokerVenue
            or type(self.environment) is not BrokerEnvironment
            or type(self.order_types) is not tuple
            or not self.order_types
            or any(type(item) is not OrderTypeV1 for item in self.order_types)
            or len(set(self.order_types)) != len(self.order_types)
            or type(self.time_in_force) is not tuple
            or not self.time_in_force
            or any(type(item) is not TimeInForceV1 for item in self.time_in_force)
            or len(set(self.time_in_force)) != len(self.time_in_force)
            or type(self.bracket_via_oco) is not bool
        ):
            raise ExecutionContractError("INVALID_VENUE_ORDER_SUPPORT")


@dataclass(frozen=True, slots=True)
class VenueOrderAdmissionV1(_Frozen):
    """OMS admission context for catalog-bound orders.

    The OMS evaluates this context at intent creation and immediately before
    broker dispatch. The clock and optional session calendar are injected by
    the composition layer; this value carries no transport authority.
    """

    catalog: VenueInstrumentCatalogV1
    support: tuple[VenueOrderSupportV1, ...]
    clock: Callable[[], date | datetime]
    session_calendar: SessionCalendarPortV1 | None = None

    def __post_init__(self) -> None:
        if (
            type(self.catalog) is not VenueInstrumentCatalogV1
            or type(self.support) is not tuple
            or not self.support
            or any(type(item) is not VenueOrderSupportV1 for item in self.support)
            or not callable(self.clock)
            or (
                self.session_calendar is not None
                and not callable(getattr(self.session_calendar, "trading_date", None))
            )
        ):
            raise ExecutionContractError("INVALID_ORDER_ADMISSION")
        support_keys = [(item.venue, item.environment) for item in self.support]
        if len(set(support_keys)) != len(support_keys):
            raise ExecutionContractError("INVALID_ORDER_ADMISSION")
        required_keys = {(item.venue, item.environment) for item in self.catalog.bindings}
        if not required_keys.issubset(set(support_keys)):
            raise ExecutionContractError("VENUE_ORDER_SUPPORT_NOT_FOUND")

    def validate_request(self, request: object) -> None:
        binding = self.catalog.resolve_order_binding(request)
        support_matches = tuple(
            item
            for item in self.support
            if item.venue is binding.venue and item.environment is binding.environment
        )
        if len(support_matches) != 1:
            raise ExecutionContractError("VENUE_ORDER_SUPPORT_NOT_FOUND")
        try:
            as_of = self.clock()
        except Exception:
            raise ExecutionContractError("ORDER_ADMISSION_CLOCK_UNAVAILABLE") from None
        if type(as_of) is not date and type(as_of) is not datetime:
            raise ExecutionContractError("INVALID_AS_OF")
        validate_venue_order_request(
            request,
            binding,
            support_matches[0],
            as_of,
            session_calendar=self.session_calendar,
        )


def validate_venue_order_request(
    request: object,
    binding: VenueInstrumentBindingV1,
    support: VenueOrderSupportV1,
    as_of: date | datetime,
    *,
    bracket_or_oco: bool = False,
    session_calendar: SessionCalendarPortV1 | None = None,
) -> None:
    """Validate OMS request identity, declared venue support and date eligibility.

    This is the cross-venue admission check: ``OrderRequest`` alone has no
    binding or capability context, so callers must invoke this before routing.
    """
    from leviathan_core.execution.order_models import OrderRequest

    if (
        type(request) is not OrderRequest
        or type(binding) is not VenueInstrumentBindingV1
        or type(support) is not VenueOrderSupportV1
        or type(bracket_or_oco) is not bool
    ):
        raise ExecutionContractError("INVALID_ORDER_ADMISSION")
    if (
        request.instrument_id != binding.instrument_id
        or request.native_contract_id != binding.native_contract_id
        or request.venue.upper() != binding.venue.value
        or request.environment.upper() != binding.environment.value
        or support.venue is not binding.venue
        or support.environment is not binding.environment
    ):
        raise ExecutionContractError("ORDER_BINDING_MISMATCH")
    try:
        order_type = OrderTypeV1(request.order_type)
        time_in_force = TimeInForceV1(request.time_in_force)
    except ValueError:
        raise ExecutionContractError("UNSUPPORTED_ORDER_COMBINATION") from None
    if order_type not in support.order_types or time_in_force not in support.time_in_force:
        raise ExecutionContractError("UNSUPPORTED_ORDER_COMBINATION")
    uses_bracket_or_oco = (
        bracket_or_oco or request.root_order_id is not None or request.parent_order_id is not None
    )
    if uses_bracket_or_oco and not support.bracket_via_oco:
        raise ExecutionContractError("UNSUPPORTED_BRACKET_OCO")
    if (
        binding.expiry is not None
        or binding.last_trade is not None
        or binding.listed_at is not None
    ):
        require_tradeable(binding, as_of, session_calendar=session_calendar)


def summarize_mass_cancel(result: MassCancelResultV1) -> MassCancelCompletionV1:
    """Separate pagination completion from per-order cancellation certainty.

    COMPLETE only means every result page was accounted for. A venue-side
    cancellation that is not reconciled remains COMPLETE_WITH_UNCONFIRMED.
    """
    from leviathan_core.execution.cancel_policy import require_mass_cancel_result

    if type(result) is not MassCancelResultV1:
        raise ExecutionContractError("INVALID_MASS_CANCEL_RESULT")
    result = require_mass_cancel_result(result)
    if not result.complete:
        return MassCancelCompletionV1.IN_PROGRESS
    if any(
        item.lifecycle_state == "CANCEL_REQUESTED_UNCONFIRMED"
        or (item.lifecycle_state == "CANCELED" and not item.reconciled)
        for item in result.results
    ):
        return MassCancelCompletionV1.COMPLETE_WITH_UNCONFIRMED
    if any(item.lifecycle_state == "REJECTED" for item in result.results):
        return MassCancelCompletionV1.COMPLETE_WITH_REJECTIONS
    return MassCancelCompletionV1.COMPLETE


class FXValuationPortV1(Protocol):
    def value_amount(
        self,
        amount: Decimal,
        source_currency: str,
        target_currency: str,
        *,
        as_of_ns: int,
    ) -> FXValuationV1: ...


@dataclass(frozen=True, slots=True)
class FXValuationV1(_Frozen):
    source_currency: str
    target_currency: str
    source_amount: Decimal
    target_amount: Decimal
    rate: Decimal
    as_of_ns: int
    evidence_digest: str

    def __post_init__(self) -> None:
        if (
            type(self.source_currency) is not str
            or _CURRENCY.fullmatch(self.source_currency) is None
            or type(self.target_currency) is not str
            or _CURRENCY.fullmatch(self.target_currency) is None
            or self.source_currency == self.target_currency
            or type(self.as_of_ns) is not int
            or self.as_of_ns < 0
            or type(self.evidence_digest) is not str
            or _DIGEST.fullmatch(self.evidence_digest) is None
        ):
            raise ExecutionContractError("INVALID_FX_VALUATION")
        source = _decimal(self.source_amount)
        target = _decimal(self.target_amount)
        rate = _decimal(self.rate, positive=True)
        try:
            calculated = exact_mul(source, rate)
        except NumericError:
            raise ExecutionContractError("FX_VALUATION_MISMATCH") from None
        if calculated != target:
            raise ExecutionContractError("FX_VALUATION_MISMATCH")
        object.__setattr__(self, "source_amount", source)
        object.__setattr__(self, "target_amount", target)
        object.__setattr__(self, "rate", rate)


__all__ = [
    "AccountSnapshotV1",
    "AssetClassV1",
    "ExecutionContractError",
    "FXValuationPortV1",
    "FXValuationV1",
    "MassCancelCompletionV1",
    "RollPolicyV1",
    "SessionCalendarPortV1",
    "VenueInstrumentBindingV1",
    "VenueInstrumentCatalogV1",
    "VenueOrderAdmissionV1",
    "VenueOrderSupportV1",
    "account_snapshot_from_view",
    "require_tradeable",
    "summarize_mass_cancel",
    "validate_venue_order_request",
]
