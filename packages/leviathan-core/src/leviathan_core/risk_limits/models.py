"""Versioned, immutable inputs and outputs for the offline hard-limit kernel.

The verifier port is deliberately separate from assessment. A future trusted
adapter must authenticate the operator signature before minting an envelope.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, fields
from decimal import Decimal
from typing import Any, NoReturn, Protocol, SupportsIndex, cast

_INTEGER_FIELDS = frozenset(
    {
        "version",
        "priority",
        "effective_from_ns",
        "effective_until_ns",
        "max_order_rate",
        "order_rate_window_ns",
        "max_data_age_ns",
        "price_source_ns",
        "price_ingest_ns",
        "source_ns",
        "ingest_ns",
        "equity_source_ns",
        "equity_ingest_ns",
        "window_ns",
        "count",
        "as_of_ns",
    }
)
_DECIMAL_FIELDS = frozenset(
    {
        "quantity",
        "price",
        "mark_price",
        "contract_multiplier",
        "equity",
        "buying_power",
        "realized_pnl",
        "unrealized_pnl",
        "base_units_per_unit",
    }
)
_CAP_FIELDS = frozenset(
    {
        "max_order_quantity",
        "max_order_notional",
        "max_projected_position",
        "max_gross_exposure",
        "max_net_exposure",
        "max_leverage",
        "max_daily_loss",
    }
)
_IDENTITY_FIELDS = frozenset(
    {
        "revision",
        "environment",
        "account_id",
        "scope",
        "limit_currency",
        "strategy_id",
        "venue_id",
        "instrument_id",
        "request_id",
        "attempt_id",
        "currency",
        "base_currency",
        "price_source_id",
        "source_id",
        "account_status",
        "last_committed_event_id",
        "verifier_id",
        "key_id",
        "policy_digest",
    }
)
_DECIMAL_TEXT = re.compile(r"(?:0|[1-9][0-9]*)(?:\.[0-9]+)?", re.ASCII)
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]*", re.ASCII)
_CURRENCY = re.compile(r"[A-Z0-9]{3,8}", re.ASCII)
_MAX_DATA_AGE_NS = 300_000_000_000


def _valid_id(value: object, *, wildcard: bool = False) -> bool:
    return (wildcard and value == "*") or (
        isinstance(value, str) and _IDENTIFIER.fullmatch(value) is not None
    )


class RiskLimitInputError(ValueError):
    """Allowlisted invalid-input code; never includes caller-supplied values."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _decimal_bounds(value: Decimal) -> None:
    if not value.is_finite():
        raise RiskLimitInputError("DECIMAL_INVALID")
    digits = value.as_tuple().digits
    trailing = 0
    for digit in reversed(digits):
        if digit != 0:
            break
        trailing += 1
    significant = len(digits) - min(trailing, len(digits) - 1)
    if significant > 34:
        raise RiskLimitInputError("PRECISION_EXCEEDED")
    if abs(value.adjusted()) > 38:
        raise RiskLimitInputError("DECIMAL_OUT_OF_BOUNDS")


class _FrozenValue:
    """Prevent mutable aliases and serialization of assessment evidence."""

    __slots__ = ()

    def __post_init__(self) -> None:
        def immutable(value: object) -> bool:
            if value is None or type(value) in (str, int, bool, float, Decimal):
                return True
            if isinstance(value, _FrozenValue):
                return True
            return type(value) is tuple and all(immutable(item) for item in value)

        for field in fields(cast(Any, self)):
            value = getattr(self, field.name)
            if not immutable(value):
                raise RiskLimitInputError("MUTABLE_EVIDENCE")
            if value is None:
                continue
            if field.name in _INTEGER_FIELDS and type(value) is not int:
                raise RiskLimitInputError("INTEGER_REQUIRED")
            if field.name in _DECIMAL_FIELDS:
                if type(value) is not Decimal:
                    raise RiskLimitInputError("DECIMAL_REQUIRED")
                _decimal_bounds(value)
            if field.name in _CAP_FIELDS:
                if not isinstance(value, str) or _DECIMAL_TEXT.fullmatch(value) is None:
                    raise RiskLimitInputError("DECIMAL_TEXT_REQUIRED")
                _decimal_bounds(Decimal(value))
            if field.name == "is_manual" and type(value) is not bool:
                raise RiskLimitInputError("BOOLEAN_REQUIRED")
            if field.name in _IDENTITY_FIELDS and (
                not isinstance(value, str) or not value.isascii()
            ):
                raise RiskLimitInputError("ASCII_IDENTIFIER_REQUIRED")

    def __copy__(self) -> NoReturn:
        raise TypeError("risk evidence cannot be copied")

    def __deepcopy__(self, _memo: dict[int, object]) -> NoReturn:
        raise TypeError("risk evidence cannot be copied")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> NoReturn:
        raise TypeError("risk evidence cannot be serialized")


@dataclass(frozen=True, slots=True)
class DatedInstrumentV1(_FrozenValue):
    instrument_id: str
    effective_from_ns: int
    effective_until_ns: int

    def __post_init__(self) -> None:
        super(DatedInstrumentV1, self).__post_init__()
        if not _valid_id(self.instrument_id, wildcard=True):
            raise RiskLimitInputError("POLICY_SELECTOR_INVALID")
        if (
            type(self.effective_from_ns) is not int
            or type(self.effective_until_ns) is not int
            or self.effective_from_ns < 0
            or self.effective_until_ns <= self.effective_from_ns
        ):
            raise RiskLimitInputError("POLICY_INTERVAL_INVALID")


@dataclass(frozen=True, slots=True)
class HardLimitsV1(_FrozenValue):
    version: int
    revision: str
    environment: str
    account_id: str
    scope: str  # ACCOUNT, STRATEGY, VENUE or INSTRUMENT
    effective_from_ns: int
    effective_until_ns: int
    limit_currency: str
    priority: int = 0
    strategy_id: str | None = None
    venue_id: str | None = None
    instrument_id: str | None = None
    allowed_strategies: tuple[str, ...] | None = None
    allowed_venues: tuple[str, ...] | None = None
    allowed_instruments: tuple[DatedInstrumentV1, ...] | None = None
    max_order_quantity: str | None = None
    max_order_notional: str | None = None
    max_projected_position: str | None = None
    max_gross_exposure: str | None = None
    max_net_exposure: str | None = None
    max_leverage: str | None = None
    max_daily_loss: str | None = None
    max_order_rate: int | None = None
    order_rate_window_ns: int | None = None
    max_data_age_ns: int | None = None

    def __post_init__(self) -> None:
        super(HardLimitsV1, self).__post_init__()
        if (
            self.version != 1
            or not all(
                _valid_id(value) for value in (self.revision, self.environment, self.account_id)
            )
            or not isinstance(self.limit_currency, str)
            or _CURRENCY.fullmatch(self.limit_currency) is None
        ):
            raise RiskLimitInputError("POLICY_INVALID")
        if (
            type(self.effective_from_ns) is not int
            or type(self.effective_until_ns) is not int
            or self.effective_from_ns < 0
            or self.effective_until_ns <= self.effective_from_ns
        ):
            raise RiskLimitInputError("POLICY_INTERVAL_INVALID")
        if type(self.priority) is not int or self.priority < 0:
            raise RiskLimitInputError("POLICY_OUT_OF_BOUNDS")
        if self.max_data_age_ns is not None and not 0 <= self.max_data_age_ns <= _MAX_DATA_AGE_NS:
            raise RiskLimitInputError("POLICY_OUT_OF_BOUNDS")
        selectors = (self.strategy_id, self.venue_id, self.instrument_id)
        required = {
            "ACCOUNT": (False, False, False),
            "STRATEGY": (True, False, False),
            "VENUE": (False, True, False),
            "INSTRUMENT": (False, False, True),
        }.get(self.scope)
        if required is None or tuple(item is not None for item in selectors) != required:
            raise RiskLimitInputError("POLICY_SELECTOR_INVALID")
        if any(item is not None and not _valid_id(item, wildcard=True) for item in selectors):
            raise RiskLimitInputError("POLICY_SELECTOR_INVALID")
        for entries in (self.allowed_strategies, self.allowed_venues):
            if entries is not None and (
                type(entries) is not tuple
                or not entries
                or any(not _valid_id(item, wildcard=True) for item in entries)
            ):
                raise RiskLimitInputError("POLICY_SELECTOR_INVALID")
        if self.allowed_instruments is not None and (
            type(self.allowed_instruments) is not tuple
            or not self.allowed_instruments
            or any(not isinstance(item, DatedInstrumentV1) for item in self.allowed_instruments)
        ):
            raise RiskLimitInputError("POLICY_SELECTOR_INVALID")
        if self.max_order_rate is not None and self.max_order_rate < 0:
            raise RiskLimitInputError("POLICY_OUT_OF_BOUNDS")
        if self.order_rate_window_ns is not None and self.order_rate_window_ns <= 0:
            raise RiskLimitInputError("POLICY_OUT_OF_BOUNDS")
        if (self.max_order_rate is None) != (self.order_rate_window_ns is None):
            raise RiskLimitInputError("POLICY_INCOMPLETE")
        if self.scope == "ACCOUNT" and (
            any(getattr(self, cap) is None for cap in _CAP_FIELDS)
            or self.max_order_rate is None
            or self.max_data_age_ns is None
            or self.allowed_strategies is None
            or self.allowed_venues is None
            or self.allowed_instruments is None
        ):
            raise RiskLimitInputError("POLICY_INCOMPLETE")


@dataclass(frozen=True, slots=True)
class PositionV1(_FrozenValue):
    instrument_id: str
    quantity: Decimal
    mark_price: Decimal
    contract_multiplier: Decimal
    currency: str
    price_source_ns: int
    price_ingest_ns: int
    price_source_id: str


@dataclass(frozen=True, slots=True)
class WorkingOrderV1(_FrozenValue):
    request_id: str
    attempt_id: str
    instrument_id: str
    side: str  # BUY or SELL
    quantity: Decimal
    price: Decimal
    contract_multiplier: Decimal
    currency: str
    price_source_ns: int
    price_ingest_ns: int
    price_source_id: str


@dataclass(frozen=True, slots=True)
class FxRateV1(_FrozenValue):
    currency: str
    base_currency: str
    base_units_per_unit: Decimal
    source_ns: int
    ingest_ns: int
    source_id: str


@dataclass(frozen=True, slots=True)
class RollingRateCountV1(_FrozenValue):
    window_ns: int
    count: int
    as_of_ns: int


@dataclass(frozen=True, slots=True)
class RiskStateV1(_FrozenValue):
    environment: str
    account_id: str
    account_status: str
    source_ns: int
    ingest_ns: int
    last_committed_event_id: str
    base_currency: str
    equity: Decimal | None
    buying_power: Decimal | None
    equity_source_ns: int | None
    equity_ingest_ns: int | None
    realized_pnl: Decimal | None
    unrealized_pnl: Decimal | None
    positions: tuple[PositionV1, ...] | None
    committed_orders: tuple[WorkingOrderV1, ...] | None
    reserved_orders: tuple[WorkingOrderV1, ...] | None
    fx_rates: tuple[FxRateV1, ...] | None
    rolling_rate_counts: tuple[RollingRateCountV1, ...] | None


@dataclass(frozen=True, slots=True)
class ProjectedOrderV1(_FrozenValue):
    environment: str
    account_id: str
    request_id: str
    attempt_id: str
    strategy_id: str
    venue_id: str
    instrument_id: str
    side: str
    quantity: Decimal
    price: Decimal
    contract_multiplier: Decimal
    currency: str
    price_source_ns: int
    price_ingest_ns: int
    price_source_id: str
    # Untrusted caller claims are recorded but deliberately have no effect.
    override_token: str | None = None
    is_manual: bool = False
    role: str | None = None
    agent_instruction: str | None = None


@dataclass(frozen=True, slots=True)
class PolicyVerificationV1(_FrozenValue):
    verifier_id: str
    key_id: str
    policy_digest: str

    def __post_init__(self) -> None:
        super(PolicyVerificationV1, self).__post_init__()
        if (
            not _valid_id(self.verifier_id)
            or not _valid_id(self.key_id)
            or not isinstance(self.policy_digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", self.policy_digest, re.ASCII) is None
        ):
            raise RiskLimitInputError("POLICY_VERIFICATION_INVALID")


class PolicyVerifier(Protocol):
    """Trusted adapter port; production implementation is a later signing gate."""

    def verify(
        self, policies: tuple[HardLimitsV1, ...], policy_digest: str
    ) -> PolicyVerificationV1: ...


class VerifiedHardLimitsV1(_FrozenValue):
    """Opaque capability minted only by ``verify_hard_limits``.

    Plain construction, JSON and dict rehydration cannot produce a usable
    envelope. The actual verifier adapter remains a separately reviewed trust
    boundary; a test fake must never be wired to production.
    """

    __slots__ = ("_policies", "_seal", "_verification")
    _policies: tuple[HardLimitsV1, ...]
    _seal: object
    _verification: PolicyVerificationV1

    def __new__(cls, *_args: object, **_kwargs: object) -> VerifiedHardLimitsV1:
        raise TypeError("verified policy envelopes require a PolicyVerifier")

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("verified policy envelopes are immutable")

    def __post_init__(self) -> None:
        if (
            type(self._policies) is not tuple
            or not self._policies
            or any(not isinstance(item, HardLimitsV1) for item in self._policies)
            or not isinstance(self._verification, PolicyVerificationV1)
        ):
            raise RiskLimitInputError("POLICY_VERIFICATION_INVALID")

    @property
    def policies(self) -> tuple[HardLimitsV1, ...]:
        return self._policies

    @property
    def verification(self) -> PolicyVerificationV1:
        return self._verification


@dataclass(frozen=True, slots=True)
class LimitAssessmentV1(_FrozenValue):
    decision: str  # ALLOW or DENY
    reason_codes: tuple[str, ...]
    matched_policy_revisions: tuple[str, ...]
    observed_values: tuple[tuple[str, str], ...]
    projected_values: tuple[tuple[str, str], ...]
    state_event_id: str | None
    evidence_digest: str
