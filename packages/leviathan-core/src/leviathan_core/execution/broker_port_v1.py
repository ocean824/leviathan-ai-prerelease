"""Venue-neutral, fake-transport-first broker boundary from ADR-0008.

This module defines data and a Protocol. It never submits an order, opens a
connection, reads credentials, or grants dispatch authority.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import InitVar, dataclass, field, fields, is_dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from enum import StrEnum
from typing import Any, NoReturn, Protocol, SupportsIndex, TypeVar, cast, runtime_checkable

from leviathan_core.execution.order_models import (
    BrokerObservation,
    OrderRequest,
    OrderSnapshot,
    OrderState,
)
from leviathan_core.numeric import NumericError, canonical_json, parse_decimal, parse_int
from leviathan_core.seal import Issuer, SealError
from leviathan_core.seal import require as _seal_require

_ISSUER = object()
_SEAL_TAG = "broker.port.v1"
_SEAL_ISSUER = Issuer(_SEAL_TAG)
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z", re.ASCII)


class BrokerPortError(RuntimeError):
    """A closed, input-free port error."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class BrokerUnknownCode(StrEnum):
    UNKNOWN_SUBMIT = "UNKNOWN_SUBMIT"
    UNKNOWN_CANCEL = "UNKNOWN_CANCEL"
    UNKNOWN_READ_ORDER = "UNKNOWN_READ_ORDER"
    UNKNOWN_ACCOUNT_VIEW = "UNKNOWN_ACCOUNT_VIEW"


class BrokerRejectionCode(StrEnum):
    VENUE_REJECTED = "VENUE_REJECTED"
    DUPLICATE_CLIENT_ORDER_ID = "DUPLICATE_CLIENT_ORDER_ID"
    UNSUPPORTED_ORDER_CLASS = "UNSUPPORTED_ORDER_CLASS"
    UNSUPPORTED_INSTRUMENT = "UNSUPPORTED_INSTRUMENT"
    INVALID_ORDER = "INVALID_ORDER"
    ACCOUNT_MISMATCH = "ACCOUNT_MISMATCH"
    ENVIRONMENT_MISMATCH = "ENVIRONMENT_MISMATCH"
    RATE_LIMITED = "RATE_LIMITED"
    SHORT_SALE_UNSUPPORTED = "SHORT_SALE_UNSUPPORTED"


class BrokerOutcomeUnknown(BrokerPortError):  # noqa: N818 - ADR-0008 public name
    """Transport outcome is uncertain; OMS must reconcile, never blind retry."""

    def __init__(self, code: BrokerUnknownCode) -> None:
        if type(code) is not BrokerUnknownCode:
            raise BrokerPortError("INVALID_UNKNOWN_CODE")
        super().__init__(code.value)


class BrokerRejected(BrokerPortError):  # noqa: N818 - ADR-0008 public name
    """A conclusive local or venue rejection with no venue text."""

    def __init__(self, code: BrokerRejectionCode) -> None:
        if type(code) is not BrokerRejectionCode:
            raise BrokerPortError("INVALID_REJECTION_CODE")
        super().__init__(code.value)


class BrokerVenue(StrEnum):
    IBKR = "IBKR"
    MT5_FOREXCOM = "MT5_FOREXCOM"
    COINBASE_SPOT = "COINBASE_SPOT"
    KALSHI = "KALSHI"
    POLYMARKET = "POLYMARKET"
    IBKR_TWS = "IBKR_TWS"
    MT5 = "MT5"
    ALPACA = "ALPACA"


class BrokerEnvironment(StrEnum):
    PAPER = "PAPER"
    DEMO = "DEMO"
    LIVE = "LIVE"


class EquityEvidenceKindV1(StrEnum):
    NET_LIQUIDATION = "NET_LIQUIDATION"
    TOTAL_EQUITY = "TOTAL_EQUITY"


def _identifier(value: object) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise BrokerPortError("INVALID_BROKER_IDENTITY")
    return value


def _utc_datetime(value: object) -> datetime:
    if type(value) is not datetime or value.tzinfo is None:
        raise BrokerPortError("INVALID_EXECUTION_TIME")
    try:
        if value.utcoffset() is None:
            raise BrokerPortError("INVALID_EXECUTION_TIME")
        return value.astimezone(UTC)
    except Exception:
        raise BrokerPortError("INVALID_EXECUTION_TIME") from None


class _IssuedValue:
    """Only module-private factories issue records; OMS must check every return."""

    __slots__ = ()

    def seal_payload(self) -> object:
        raise NotImplementedError

    def assert_sealed(self) -> None:
        if type(self) not in _ISSUED_RECORD_TYPES:
            raise BrokerPortError("UNISSUED_BROKER_RECORD")
        _require_exact_broker_record(self, type(self))

    def __copy__(self) -> NoReturn:
        raise BrokerPortError("COPY_FORBIDDEN")

    def __deepcopy__(self, memo: dict[int, Any]) -> NoReturn:
        raise BrokerPortError("COPY_FORBIDDEN")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise BrokerPortError("PICKLE_FORBIDDEN")

    def __setstate__(self, state: object) -> NoReturn:
        raise BrokerPortError("REINIT_FORBIDDEN")

    def __repr__(self) -> str:
        return f"{type(self).__name__}(<sealed>)"


def _typed_payload(value: object, ancestors: set[int]) -> object:
    """Legacy compatibility encoding; it is not used as issuance authority."""
    if value is None:
        return ["none"]
    if type(value) is bool:
        return ["bool", value]
    if type(value) is int:
        return ["int", value]
    if type(value) is str:
        return ["str", value]
    if type(value) is Decimal:
        return ["decimal", value]
    if type(value) is datetime:
        if value.tzinfo is not UTC:
            raise BrokerPortError("INVALID_BROKER_RECORD")
        return ["datetime", value.isoformat()]
    if type(value) is timedelta:
        return ["timedelta", value.days, value.seconds, value.microseconds]
    if isinstance(value, StrEnum):
        return ["enum", type(value).__module__, type(value).__qualname__, value.value]
    if type(value) is tuple:
        identity = id(value)
        if identity in ancestors:
            raise BrokerPortError("INVALID_BROKER_RECORD")
        ancestors.add(identity)
        try:
            return ["tuple", [_typed_payload(item, ancestors) for item in value]]
        finally:
            ancestors.remove(identity)
    if type(value) in {
        VenueDispatchCapabilityV1,
        VenueIdentityV1,
        SubmitResultV1,
        CancelResultV1,
        ExecutionV1,
        BalanceV1,
        EquityEvidenceV1,
        AccountViewV1,
        BrokerObservation,
    }:
        identity = id(value)
        if identity in ancestors:
            raise BrokerPortError("INVALID_BROKER_RECORD")
        if ancestors and isinstance(value, _IssuedValue):
            _require_exact_broker_record(value, type(value))
        ancestors.add(identity)
        try:
            record_fields: tuple[tuple[str, object], ...]
            if type(value) is VenueDispatchCapabilityV1:
                record_fields = (
                    ("atomic_revision_dispatch", value.atomic_revision_dispatch),
                    ("settle_window", value.settle_window),
                )
            else:
                declared_fields = fields(cast(Any, value))
                # Keep the v1.3 audit helper's original omission for additive v1.4 equity.
                if type(value) is AccountViewV1:
                    optional_absent = {
                        "equity": value.equity,
                        "venue_identity": value.venue_identity,
                        "account_currency": value.account_currency,
                        "buying_power": value.buying_power,
                    }
                    declared_fields = tuple(
                        field
                        for field in declared_fields
                        if field.name not in optional_absent
                        or optional_absent[field.name] is not None
                    )
                record_fields = tuple(
                    (field.name, getattr(value, field.name)) for field in declared_fields
                )
            return [
                "record",
                type(value).__module__,
                type(value).__qualname__,
                [[name, _typed_payload(item, ancestors)] for name, item in record_fields],
            ]
        finally:
            ancestors.remove(identity)
    raise BrokerPortError("INVALID_BROKER_RECORD")


def _digest(value: _IssuedValue) -> bytes:
    """Compatibility-only digest retained for existing consumers and tests."""
    try:
        payload = canonical_json(_typed_payload(value, set()))
    except BrokerPortError:
        raise
    except Exception:
        raise BrokerPortError("INVALID_BROKER_RECORD") from None
    return hashlib.sha256(payload).digest()


def _register(value: _IssuedValue) -> None:
    try:
        _SEAL_ISSUER.issue(value)
    except SealError as exc:
        if exc.code == "SEAL_ALREADY_ISSUED":
            raise BrokerPortError("REINIT_FORBIDDEN") from None
        if exc.code in {"SEAL_UNSUPPORTED_TYPE", "SEAL_DIGEST_LIMIT"}:
            raise BrokerPortError("INVALID_BROKER_RECORD") from None
        raise BrokerPortError("INVALID_BROKER_RECORD") from None


_RecordType = TypeVar("_RecordType", bound=type[_IssuedValue])


def _guard_issued_record(cls: _RecordType) -> _RecordType:
    """Override slot-dataclass state hooks and reject re-init before assignment."""
    original_init = cls.__init__

    def guarded_init(self: _IssuedValue, *args: Any, **kwargs: Any) -> None:
        try:
            _seal_require(self, _SEAL_TAG)
        except SealError as exc:
            if exc.code != "SEAL_NOT_ISSUED":
                raise BrokerPortError("REINIT_FORBIDDEN") from None
        else:
            raise BrokerPortError("REINIT_FORBIDDEN")
        original_init(self, *args, **kwargs)

    def deny_state(self: _IssuedValue, *args: Any, **kwargs: Any) -> NoReturn:
        raise BrokerPortError("REINIT_FORBIDDEN")

    setattr(cls, "__init__", guarded_init)  # noqa: B010 - dynamic dataclass hook
    setattr(cls, "__getstate__", deny_state)  # noqa: B010 - dynamic dataclass hook
    setattr(cls, "__setstate__", deny_state)  # noqa: B010 - dynamic dataclass hook
    return cls


@_guard_issued_record
@dataclass(frozen=True, slots=True, weakref_slot=True, repr=False, init=False)
class VenueDispatchCapabilityV1(_IssuedValue):
    atomic_revision_dispatch: bool
    _settle_window_microseconds: int | None = field(init=False)
    _issuer: InitVar[object] = None

    def __init__(
        self,
        atomic_revision_dispatch: bool,
        settle_window: timedelta | None = None,
        _issuer: object = None,
    ) -> None:
        if _issuer is not _ISSUER:
            raise BrokerPortError("UNISSUED_BROKER_RECORD")
        if type(atomic_revision_dispatch) is not bool:
            raise BrokerPortError("INVALID_VENUE_CAPABILITY")
        if atomic_revision_dispatch:
            if settle_window is not None:
                raise BrokerPortError("INVALID_VENUE_CAPABILITY")
        elif type(settle_window) is not timedelta or settle_window <= timedelta(0):
            raise BrokerPortError("INVALID_VENUE_CAPABILITY")
        microseconds = (
            None
            if settle_window is None
            else ((settle_window.days * 86_400 + settle_window.seconds) * 1_000_000)
            + settle_window.microseconds
        )
        object.__setattr__(self, "atomic_revision_dispatch", atomic_revision_dispatch)
        object.__setattr__(self, "_settle_window_microseconds", microseconds)
        _register(self)

    @property
    def settle_window(self) -> timedelta | None:
        value = self._settle_window_microseconds
        return None if value is None else timedelta(microseconds=value)

    def seal_payload(self) -> object:
        window = self.settle_window
        return [
            self.atomic_revision_dispatch,
            None if window is None else [window.days, window.seconds, window.microseconds],
        ]


@_guard_issued_record
@dataclass(frozen=True, slots=True, weakref_slot=True, repr=False)
class VenueIdentityV1(_IssuedValue):
    venue: BrokerVenue
    environment: BrokerEnvironment
    account_id: str
    _issuer: InitVar[object] = None

    def __post_init__(self, _issuer: object) -> None:
        if _issuer is not _ISSUER:
            raise BrokerPortError("UNISSUED_BROKER_RECORD")
        if type(self.venue) is not BrokerVenue or type(self.environment) is not BrokerEnvironment:
            raise BrokerPortError("INVALID_VENUE_IDENTITY")
        _identifier(self.account_id)
        _register(self)

    def seal_payload(self) -> object:
        return [self.venue.value, self.environment.value, self.account_id]


@_guard_issued_record
@dataclass(frozen=True, slots=True, weakref_slot=True, repr=False)
class SubmitResultV1(_IssuedValue):
    venue_order_id: str | None
    state: OrderState
    rejection_code: BrokerRejectionCode | None = None
    _issuer: InitVar[object] = None

    def __post_init__(self, _issuer: object) -> None:
        if _issuer is not _ISSUER:
            raise BrokerPortError("UNISSUED_BROKER_RECORD")
        if type(self.state) is not OrderState:
            raise BrokerPortError("INVALID_SUBMIT_RESULT")
        if self.state is OrderState.WORKING:
            if self.venue_order_id is None or self.rejection_code is not None:
                raise BrokerPortError("INVALID_SUBMIT_RESULT")
            _identifier(self.venue_order_id)
        elif self.state is OrderState.REJECTED:
            if (
                self.venue_order_id is not None
                or type(self.rejection_code) is not BrokerRejectionCode
            ):
                raise BrokerPortError("INVALID_SUBMIT_RESULT")
        else:
            raise BrokerPortError("INVALID_SUBMIT_RESULT")
        _register(self)

    def seal_payload(self) -> object:
        return [
            self.venue_order_id,
            self.state.value,
            self.rejection_code.value if self.rejection_code is not None else None,
        ]


@_guard_issued_record
@dataclass(frozen=True, slots=True, weakref_slot=True, repr=False)
class CancelResultV1(_IssuedValue):
    confirmed: bool
    _issuer: InitVar[object] = None

    def __post_init__(self, _issuer: object) -> None:
        if _issuer is not _ISSUER or type(self.confirmed) is not bool:
            raise BrokerPortError("INVALID_CANCEL_RESULT")
        _register(self)

    def seal_payload(self) -> object:
        return [self.confirmed]


@_guard_issued_record
@dataclass(frozen=True, slots=True, weakref_slot=True, repr=False)
class ExecutionV1(_IssuedValue):
    """One exact broker execution in a complete account reconciliation window."""

    execution_id: str
    venue_order_id: str
    client_order_id: str | None
    instrument_id: str
    side: str
    quantity: Decimal
    price: Decimal
    executed_at: datetime
    _issuer: InitVar[object] = None

    def __post_init__(self, _issuer: object) -> None:
        if _issuer is not _ISSUER:
            raise BrokerPortError("UNISSUED_BROKER_RECORD")
        for value in (self.execution_id, self.venue_order_id, self.instrument_id):
            _identifier(value)
        if self.client_order_id is not None:
            _identifier(self.client_order_id)
        if type(self.side) is not str or self.side not in {"BUY", "SELL"}:
            raise BrokerPortError("INVALID_EXECUTION")
        if type(self.quantity) is not Decimal or type(self.price) is not Decimal:
            raise BrokerPortError("INVALID_EXECUTION")
        try:
            quantity = parse_decimal(self.quantity, field="execution_quantity")
            price = parse_decimal(self.price, field="execution_price")
        except NumericError:
            raise BrokerPortError("INVALID_EXECUTION") from None
        if quantity <= 0 or price <= 0:
            raise BrokerPortError("INVALID_EXECUTION")
        object.__setattr__(self, "quantity", quantity)
        object.__setattr__(self, "price", price)
        object.__setattr__(self, "executed_at", _utc_datetime(self.executed_at))
        _register(self)

    def seal_payload(self) -> object:
        return [
            self.execution_id,
            self.venue_order_id,
            self.client_order_id,
            self.instrument_id,
            self.side,
            self.quantity,
            self.price,
            self.executed_at.isoformat(),
        ]


@_guard_issued_record
@dataclass(frozen=True, slots=True, weakref_slot=True, repr=False)
class BalanceV1(_IssuedValue):
    """One exact account cash/balance amount in one uppercase currency code."""

    currency: str
    amount: Decimal
    _issuer: InitVar[object] = None

    def __post_init__(self, _issuer: object) -> None:
        if _issuer is not _ISSUER:
            raise BrokerPortError("UNISSUED_BROKER_RECORD")
        if type(self.currency) is not str or re.fullmatch(r"[A-Z]{3}", self.currency) is None:
            raise BrokerPortError("INVALID_ACCOUNT_BALANCE")
        if type(self.amount) is not Decimal:
            raise BrokerPortError("INVALID_ACCOUNT_BALANCE")
        try:
            amount = parse_decimal(self.amount, field="account_balance")
        except NumericError:
            raise BrokerPortError("INVALID_ACCOUNT_BALANCE") from None
        object.__setattr__(self, "amount", amount)
        _register(self)

    def seal_payload(self) -> object:
        return [self.currency, self.amount]


@_guard_issued_record
@dataclass(frozen=True, slots=True, weakref_slot=True, repr=False)
class EquityEvidenceV1(_IssuedValue):
    """Adapter-declared equity semantics, independent of per-currency balances."""

    currency: str
    amount: Decimal
    kind: EquityEvidenceKindV1
    broker_observed_at_ns: int
    semantics_declared_by: str
    _issuer: InitVar[object] = None

    def __post_init__(self, _issuer: object) -> None:
        if _issuer is not _ISSUER:
            raise BrokerPortError("UNISSUED_BROKER_RECORD")
        if type(self.currency) is not str or re.fullmatch(r"[A-Z]{3}", self.currency) is None:
            raise BrokerPortError("INVALID_EQUITY_EVIDENCE")
        if type(self.amount) is not Decimal:
            raise BrokerPortError("INVALID_EQUITY_EVIDENCE")
        try:
            amount = parse_decimal(self.amount, field="equity_amount")
            observed_at_ns = parse_int(
                self.broker_observed_at_ns,
                field="broker_observed_at_ns",
                min_value=0,
                max_value=2**63 - 1,
            )
        except NumericError:
            raise BrokerPortError("INVALID_EQUITY_EVIDENCE") from None
        if type(self.kind) is not EquityEvidenceKindV1:
            raise BrokerPortError("INVALID_EQUITY_EVIDENCE")
        try:
            semantics_declared_by = _identifier(self.semantics_declared_by)
        except BrokerPortError:
            raise BrokerPortError("INVALID_EQUITY_EVIDENCE") from None
        object.__setattr__(self, "amount", amount)
        object.__setattr__(self, "broker_observed_at_ns", observed_at_ns)
        object.__setattr__(self, "semantics_declared_by", semantics_declared_by)
        _register(self)

    def seal_payload(self) -> object:
        return [
            self.currency,
            self.amount,
            self.kind.value,
            self.broker_observed_at_ns,
            self.semantics_declared_by,
        ]


@_guard_issued_record
@dataclass(frozen=True, slots=True, weakref_slot=True, repr=False)
class AccountViewV1(_IssuedValue):
    """A complete exact-account snapshot; uncertainty must raise outcome unknown.

    ``balances`` carries per-currency cash/balance evidence when available;
    the strict cross-venue ``AccountSnapshotV1`` projection requires cash,
    equity, buying power, account currency, and observation time explicitly.
    """

    account_id: str
    open_orders: tuple[BrokerObservation, ...]
    positions: tuple[tuple[str, Decimal], ...]
    broker_revision: int
    executions: tuple[ExecutionV1, ...]
    executions_since: datetime
    balances: tuple[BalanceV1, ...] | None = None
    broker_observed_at: datetime | None = None
    session_id: str | None = None
    _issuer: InitVar[object] = None
    equity: EquityEvidenceV1 | None = None
    venue_identity: VenueIdentityV1 | None = None
    account_currency: str | None = None
    buying_power: BalanceV1 | None = None

    def __post_init__(self, _issuer: object) -> None:
        if _issuer is not _ISSUER:
            raise BrokerPortError("UNISSUED_BROKER_RECORD")
        _identifier(self.account_id)
        if type(self.open_orders) is not tuple or any(
            type(order) is not BrokerObservation
            or order.account_id != self.account_id
            or order.status not in {OrderState.WORKING, OrderState.PARTIALLY_FILLED}
            for order in self.open_orders
        ):
            raise BrokerPortError("INVALID_ACCOUNT_VIEW")
        if type(self.positions) is not tuple:
            raise BrokerPortError("INVALID_ACCOUNT_VIEW")
        positions: list[tuple[str, Decimal]] = []
        for pair in self.positions:
            if type(pair) is not tuple or len(pair) != 2:
                raise BrokerPortError("INVALID_ACCOUNT_VIEW")
            instrument_id, quantity = pair
            _identifier(instrument_id)
            try:
                positions.append(
                    (instrument_id, parse_decimal(quantity, field="position_quantity"))
                )
            except NumericError:
                raise BrokerPortError("INVALID_ACCOUNT_VIEW") from None
        if len({instrument for instrument, _ in positions}) != len(positions):
            raise BrokerPortError("INVALID_ACCOUNT_VIEW")
        if [instrument for instrument, _ in positions] != sorted(
            instrument for instrument, _ in positions
        ):
            raise BrokerPortError("INVALID_ACCOUNT_VIEW")
        object.__setattr__(self, "positions", tuple(positions))
        try:
            parse_int(
                self.broker_revision, field="broker_revision", min_value=0, max_value=2**63 - 1
            )
        except NumericError:
            raise BrokerPortError("INVALID_BROKER_REVISION") from None
        if type(self.executions) is not tuple:
            raise BrokerPortError("INVALID_ACCOUNT_VIEW")
        execution_ids: list[str] = []
        for execution in self.executions:
            if type(execution) is not ExecutionV1:
                raise BrokerPortError("INVALID_ACCOUNT_VIEW")
            execution.assert_sealed()
            execution_ids.append(execution.execution_id)
        if execution_ids != sorted(set(execution_ids)):
            raise BrokerPortError("INVALID_ACCOUNT_VIEW")
        since = _utc_datetime(self.executions_since)
        if any(execution.executed_at < since for execution in self.executions):
            raise BrokerPortError("INVALID_ACCOUNT_VIEW")
        object.__setattr__(self, "executions_since", since)
        balances = self.balances
        if balances is not None:
            if type(balances) is not tuple or any(
                type(balance) is not BalanceV1 for balance in balances
            ):
                raise BrokerPortError("INVALID_ACCOUNT_VIEW")
            currencies: list[str] = []
            for balance in balances:
                balance.assert_sealed()
                currencies.append(balance.currency)
            if currencies != sorted(set(currencies)):
                raise BrokerPortError("INVALID_ACCOUNT_VIEW")
        if self.equity is not None:
            if type(self.equity) is not EquityEvidenceV1:
                raise BrokerPortError("INVALID_ACCOUNT_VIEW")
            self.equity.assert_sealed()
        if self.venue_identity is not None:
            if (
                type(self.venue_identity) is not VenueIdentityV1
                or self.venue_identity.account_id != self.account_id
            ):
                raise BrokerPortError("INVALID_ACCOUNT_VIEW")
            self.venue_identity.assert_sealed()
        if self.account_currency is not None and (
            type(self.account_currency) is not str
            or re.fullmatch(r"[A-Z]{3}", self.account_currency) is None
        ):
            raise BrokerPortError("INVALID_ACCOUNT_VIEW")
        if self.buying_power is not None:
            if type(self.buying_power) is not BalanceV1:
                raise BrokerPortError("INVALID_ACCOUNT_VIEW")
            self.buying_power.assert_sealed()
        observed_at = self.broker_observed_at
        if observed_at is not None:
            if type(observed_at) is not datetime or observed_at.tzinfo is None:
                raise BrokerPortError("INVALID_BROKER_OBSERVED_AT")
            try:
                if observed_at.utcoffset() is None:
                    raise BrokerPortError("INVALID_BROKER_OBSERVED_AT")
                observed_at = observed_at.astimezone(UTC)
            except Exception:
                raise BrokerPortError("INVALID_BROKER_OBSERVED_AT") from None
            object.__setattr__(self, "broker_observed_at", observed_at)
        if self.session_id is not None:
            try:
                _identifier(self.session_id)
            except BrokerPortError:
                raise BrokerPortError("INVALID_BROKER_SESSION_ID") from None
        _register(self)

    def seal_payload(self) -> object:
        payload = {
            "account_id": self.account_id,
            "open_orders": [order.payload() for order in self.open_orders],
            "positions": self.positions,
            "broker_revision": self.broker_revision,
            "executions": [execution.seal_payload() for execution in self.executions],
            "executions_since": self.executions_since.isoformat(),
            "balances": None
            if self.balances is None
            else [balance.seal_payload() for balance in self.balances],
            "broker_observed_at": (
                None if self.broker_observed_at is None else self.broker_observed_at.isoformat()
            ),
            "session_id": self.session_id,
        }
        if self.equity is not None:
            payload["equity"] = self.equity.seal_payload()
        if self.venue_identity is not None:
            payload["venue_identity"] = self.venue_identity.seal_payload()
        if self.account_currency is not None:
            payload["account_currency"] = self.account_currency
        if self.buying_power is not None:
            payload["buying_power"] = self.buying_power.seal_payload()
        return payload

    @property
    def evidence_digest(self) -> str:
        """Canonical SHA-256 over the complete sealed snapshot evidence."""
        self.assert_sealed()
        return hashlib.sha256(canonical_json(self.seal_payload())).hexdigest()


_ISSUED_RECORD_TYPES = (
    VenueDispatchCapabilityV1,
    VenueIdentityV1,
    SubmitResultV1,
    CancelResultV1,
    ExecutionV1,
    BalanceV1,
    EquityEvidenceV1,
    AccountViewV1,
)


def _require_exact_broker_record(value: object, expected_type: type[_IssuedValue]) -> _IssuedValue:
    if type(value) is not expected_type:
        raise BrokerPortError("UNISSUED_BROKER_RECORD")
    for item in fields(cast(Any, value)):
        try:
            child = getattr(value, item.name)
        except AttributeError:
            continue
        _require_nested_records(child, {id(value)})
    try:
        _seal_require(value, _SEAL_TAG)
    except SealError as exc:
        if exc.code == "SEAL_NOT_ISSUED":
            raise BrokerPortError("UNISSUED_BROKER_RECORD") from None
        if exc.code == "SEAL_TAMPERED":
            raise BrokerPortError("BROKER_RECORD_TAMPERED") from None
        if exc.code in {"SEAL_UNSUPPORTED_TYPE", "SEAL_DIGEST_LIMIT"}:
            raise BrokerPortError("INVALID_BROKER_RECORD") from None
        raise BrokerPortError("UNISSUED_BROKER_RECORD") from None
    return value


def _require_nested_records(value: object, ancestors: set[int]) -> None:
    """Preserve the broker boundary's precise nested-unissued error behavior."""
    identity = id(value)
    if identity in ancestors:
        return
    if type(value) in _ISSUED_RECORD_TYPES:
        try:
            _seal_require(value, _SEAL_TAG)
        except SealError as exc:
            if exc.code == "SEAL_NOT_ISSUED":
                raise BrokerPortError("UNISSUED_BROKER_RECORD") from None
            if exc.code == "SEAL_TAMPERED":
                raise BrokerPortError("BROKER_RECORD_TAMPERED") from None
            raise BrokerPortError("INVALID_BROKER_RECORD") from None
        return
    if type(value) in (tuple, list):
        ancestors.add(identity)
        try:
            for item in cast(tuple[object, ...] | list[object], value):
                _require_nested_records(item, ancestors)
        finally:
            ancestors.remove(identity)
        return
    if is_dataclass(value) and not isinstance(value, type):
        ancestors.add(identity)
        try:
            for item in fields(cast(Any, value)):
                _require_nested_records(getattr(value, item.name), ancestors)
        finally:
            ancestors.remove(identity)


def require_venue_dispatch_capability(value: object) -> VenueDispatchCapabilityV1:
    """Require one issued venue capability of its exact public type."""
    return cast(
        VenueDispatchCapabilityV1, _require_exact_broker_record(value, VenueDispatchCapabilityV1)
    )


def require_venue_identity(value: object) -> VenueIdentityV1:
    """Require one issued venue identity of its exact public type."""
    return cast(VenueIdentityV1, _require_exact_broker_record(value, VenueIdentityV1))


def require_submit_result(value: object) -> SubmitResultV1:
    """Require one issued submit result of its exact public type."""
    return cast(SubmitResultV1, _require_exact_broker_record(value, SubmitResultV1))


def require_cancel_result(value: object) -> CancelResultV1:
    """Require one issued cancel result of its exact public type."""
    return cast(CancelResultV1, _require_exact_broker_record(value, CancelResultV1))


def require_execution(value: object) -> ExecutionV1:
    """Require one issued execution of its exact public type."""
    return cast(ExecutionV1, _require_exact_broker_record(value, ExecutionV1))


def require_balance(value: object) -> BalanceV1:
    """Require one issued balance of its exact public type."""
    return cast(BalanceV1, _require_exact_broker_record(value, BalanceV1))


def require_equity_evidence(value: object) -> EquityEvidenceV1:
    """Require one issued equity evidence value of its exact public type."""
    return cast(EquityEvidenceV1, _require_exact_broker_record(value, EquityEvidenceV1))


def require_account_view(value: object) -> AccountViewV1:
    """Require one issued account view of its exact public type."""
    return cast(AccountViewV1, _require_exact_broker_record(value, AccountViewV1))


def _issue_venue_identity(
    venue: BrokerVenue, environment: BrokerEnvironment, account_id: str
) -> VenueIdentityV1:
    return VenueIdentityV1(venue, environment, account_id, _issuer=_ISSUER)


def _issue_venue_capability(
    atomic_revision_dispatch: bool, settle_window: timedelta | None = None
) -> VenueDispatchCapabilityV1:
    return VenueDispatchCapabilityV1(atomic_revision_dispatch, settle_window, _issuer=_ISSUER)


def _issue_submit_result(
    venue_order_id: str | None,
    state: OrderState,
    rejection_code: BrokerRejectionCode | None = None,
) -> SubmitResultV1:
    return SubmitResultV1(venue_order_id, state, rejection_code, _issuer=_ISSUER)


def _issue_cancel_result(confirmed: bool) -> CancelResultV1:
    return CancelResultV1(confirmed, _issuer=_ISSUER)


def _issue_execution(
    execution_id: str,
    venue_order_id: str,
    client_order_id: str | None,
    instrument_id: str,
    side: str,
    quantity: Decimal,
    price: Decimal,
    executed_at: datetime,
) -> ExecutionV1:
    return ExecutionV1(
        execution_id,
        venue_order_id,
        client_order_id,
        instrument_id,
        side,
        quantity,
        price,
        executed_at,
        _issuer=_ISSUER,
    )


def _issue_balance(currency: str, amount: object) -> BalanceV1:
    return BalanceV1(currency, cast(Decimal, amount), _issuer=_ISSUER)


def _issue_equity_evidence(
    currency: str,
    amount: object,
    kind: EquityEvidenceKindV1,
    broker_observed_at_ns: int,
    semantics_declared_by: str,
) -> EquityEvidenceV1:
    return EquityEvidenceV1(
        currency,
        cast(Decimal, amount),
        kind,
        broker_observed_at_ns,
        semantics_declared_by,
        _issuer=_ISSUER,
    )


def _issue_account_view(
    account_id: str,
    open_orders: tuple[BrokerObservation, ...],
    positions: tuple[tuple[str, Decimal], ...],
    broker_revision: int,
    executions: tuple[ExecutionV1, ...],
    executions_since: datetime,
    *,
    complete: bool,
    balances: tuple[BalanceV1, ...] | None = None,
    broker_observed_at: datetime | None = None,
    session_id: str | None = None,
    equity: EquityEvidenceV1 | None = None,
    venue_identity: VenueIdentityV1 | None = None,
    account_currency: str | None = None,
    buying_power: BalanceV1 | None = None,
) -> AccountViewV1:
    if complete is not True:
        raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_ACCOUNT_VIEW)
    return AccountViewV1(
        account_id,
        open_orders,
        positions,
        broker_revision,
        executions,
        executions_since,
        balances,
        broker_observed_at,
        session_id,
        _issuer=_ISSUER,
        equity=equity,
        venue_identity=venue_identity,
        account_currency=account_currency,
        buying_power=buying_power,
    )


class DispatchPermitV1(Protocol):
    """Single-use OMS-issued permit; a broker adapter consumes before transport."""

    @property
    def order_id(self) -> str: ...

    def consume(self, order_id: str, request_digest: str, expected_revision: int) -> None: ...


@runtime_checkable
class BrokerPortV1(Protocol):
    @property
    def capability(self) -> VenueDispatchCapabilityV1: ...

    @property
    def venue(self) -> VenueIdentityV1: ...

    def submit(
        self, request: OrderRequest, permit: DispatchPermitV1, expected_revision: int
    ) -> SubmitResultV1: ...

    def cancel(self, order: OrderSnapshot) -> CancelResultV1: ...

    def read_order(self, order: OrderSnapshot) -> BrokerObservation | None: ...

    def read_account_view(self, account_id: str) -> AccountViewV1:
        """Return a complete exact-account view or raise BrokerOutcomeUnknown."""
        ...


__all__ = [
    "AccountViewV1",
    "BalanceV1",
    "BrokerEnvironment",
    "BrokerObservation",
    "BrokerOutcomeUnknown",
    "BrokerPortError",
    "BrokerPortV1",
    "BrokerRejected",
    "BrokerRejectionCode",
    "BrokerUnknownCode",
    "BrokerVenue",
    "CancelResultV1",
    "DispatchPermitV1",
    "EquityEvidenceKindV1",
    "EquityEvidenceV1",
    "ExecutionV1",
    "OrderRequest",
    "OrderSnapshot",
    "SubmitResultV1",
    "VenueDispatchCapabilityV1",
    "VenueIdentityV1",
    "require_account_view",
    "require_balance",
    "require_cancel_result",
    "require_equity_evidence",
    "require_execution",
    "require_submit_result",
    "require_venue_dispatch_capability",
    "require_venue_identity",
]
