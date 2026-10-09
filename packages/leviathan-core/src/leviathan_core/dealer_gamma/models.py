"""Immutable, Decimal-only evidence and output contracts for GEX-001.

UTC nanoseconds are integers. Dates are exchange-local dates supplied by the
versioned calendar; the kernel never guesses a timezone or an expiry cutoff.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import InitVar, dataclass, fields, is_dataclass, replace
from dataclasses import field as dataclass_field
from datetime import date
from decimal import (
    ROUND_HALF_EVEN,
    Clamped,
    Context,
    Decimal,
    DivisionByZero,
    FloatOperation,
    Inexact,
    InvalidOperation,
    Overflow,
    Subnormal,
    Underflow,
    localcontext,
)
from fractions import Fraction
from hashlib import sha256
from itertools import pairwise
from typing import Any, NoReturn, SupportsIndex
from weakref import WeakSet, ref

ZERO = Decimal("0")
ONE = Decimal("1")
ADJUSTMENT_VERSION_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
CURRENCY_RE = re.compile(r"^[A-Z]{3}$", re.ASCII)
KERNEL_CONTEXT = Context(
    prec=34, rounding=ROUND_HALF_EVEN, Emin=-38, Emax=38,
    traps=[InvalidOperation, DivisionByZero, Overflow, Underflow, Subnormal,
           Clamped, FloatOperation],
)
EXACT_CONTEXT = KERNEL_CONTEXT.copy()
EXACT_CONTEXT.traps[Inexact] = True
MIN_COVERAGE = Decimal("0.80")
MAX_SPOT_AGE_NS = 2_000_000_000
MAX_IV_AGE_NS = 10_000_000_000
MAX_QUOTE_AGE_NS = 10_000_000_000
MAX_GREEK_AGE_NS = 10_000_000_000
MAX_OI_AGE_NS = 172_800_000_000_000
_RESULT_SENTINEL = object()
_RESULT_ISSUING: ContextVar[bool] = ContextVar("gex_result_issuing", default=False)


class _Issuance:
    """Identity handle; unlike value-equal results, WeakSet entries stay distinct."""

    __slots__ = ("__weakref__", "owner")

    def __init__(self, instance: Any) -> None:
        self.owner = ref(instance)


_ISSUED: WeakSet[_Issuance] = WeakSet()


def _is_issued(instance: Any) -> bool:
    handle = getattr(instance, "_seal", None)
    return (isinstance(handle, _Issuance) and handle in _ISSUED
            and handle.owner() is instance)


class DecimalOutOfBoundsError(ValueError):
    """A Decimal cannot safely enter the bounded kernel context."""


class PrecisionExceededError(ValueError):
    """An input has more significant digits than the kernel precision."""


class IntegerFieldError(ValueError):
    """An integer field received a bool, non-integer, or negative value."""


class PolicyOutOfBoundsError(ValueError):
    """A caller tried to loosen a PRD-governed policy bound."""


class _NoCopyMixin:
    def __copy__(self) -> NoReturn:
        raise TypeError("FROZEN_MODEL_COPY_FORBIDDEN")

    def __deepcopy__(self, memo: Any) -> NoReturn:
        raise TypeError("FROZEN_MODEL_COPY_FORBIDDEN")

    def __reduce__(self) -> NoReturn:
        raise TypeError("FROZEN_MODEL_PICKLE_FORBIDDEN")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise TypeError("FROZEN_MODEL_PICKLE_FORBIDDEN")


def canonical_decimal(value: Decimal) -> Decimal:
    if type(value) is not Decimal or not value.is_finite():
        raise DecimalOutOfBoundsError("DECIMAL_OUT_OF_BOUNDS")
    parts = value.as_tuple()
    if value.is_zero():
        return ZERO
    if abs(value.adjusted()) > 38:
        raise DecimalOutOfBoundsError("DECIMAL_OUT_OF_BOUNDS")
    digits = parts.digits
    exponent = parts.exponent
    if not isinstance(exponent, int):
        raise DecimalOutOfBoundsError("DECIMAL_OUT_OF_BOUNDS")
    trimmed = len(digits)
    while trimmed > 1 and digits[trimmed - 1] == 0:
        trimmed -= 1
        exponent += 1
    if trimmed > 34:
        raise PrecisionExceededError("PRECISION_EXCEEDED")
    return Decimal((parts.sign, digits[:trimmed], exponent))


def exact_fraction_decimal(value: Fraction) -> Decimal:
    """Convert a terminating rational without bounded intermediate arithmetic."""
    denominator = value.denominator
    twos = fives = 0
    while denominator % 2 == 0:
        denominator //= 2
        twos += 1
    while denominator % 5 == 0:
        denominator //= 5
        fives += 1
    if denominator != 1:
        raise PrecisionExceededError("PRECISION_EXCEEDED")
    scale = max(twos, fives)
    coefficient = abs(value.numerator) * 2 ** (scale - twos) * 5 ** (scale - fives)
    digits = tuple(int(digit) for digit in str(coefficient))
    result = Decimal((int(value < 0), digits, -scale))
    try:
        return canonical_decimal(result)
    except DecimalOutOfBoundsError:
        raise PrecisionExceededError("PRECISION_EXCEEDED") from None


@contextmanager
def _issue_results() -> Iterator[None]:
    """Permit only the kernel evaluation path to issue sealed result records."""
    token = _RESULT_ISSUING.set(True)
    try:
        yield
    finally:
        _RESULT_ISSUING.reset(token)


def _seal_result(instance: Any, issue_token: object) -> None:
    if issue_token is not _RESULT_SENTINEL or not _RESULT_ISSUING.get():
        raise ValueError("RESULT_SEAL_INVALID")
    handle = _Issuance(instance)
    object.__setattr__(instance, "_seal", handle)
    _ISSUED.add(handle)
    if not _is_issued(instance):
        raise ValueError("RESULT_SEAL_INVALID")


def _reissue_result(instance: Any, **changes: Any) -> Any:
    if not _RESULT_ISSUING.get() or not _is_issued(instance):
        raise ValueError("RESULT_SEAL_INVALID")
    return replace(instance, _issue_token=_RESULT_SENTINEL, **changes)


def _frozen_value(value: Any) -> Any:
    if type(value) is Decimal:
        return canonical_decimal(value)
    if type(value) is float:
        raise ValueError("binary floats are prohibited in gamma evidence and results")
    if type(value) is tuple:
        return tuple(_frozen_value(item) for item in value)
    if isinstance(value, (list, dict, set, frozenset)):
        raise ValueError("MUTABLE_COLLECTION_FORBIDDEN")
    if isinstance(value, _NoCopyMixin):
        return value
    if type(value) in (str, int, bool, date) or value is None:
        return value
    raise ValueError("INVALID_FIELD_TYPE")


def normalize_frozen(instance: Any) -> None:
    """Canonicalize Decimals and reject shared mutable values on every construction."""
    for field in fields(instance):
        value = getattr(instance, field.name)
        canonical_value = _frozen_value(value)
        if canonical_value is not value:
            object.__setattr__(instance, field.name, canonical_value)


def reject_floats(value: Any) -> None:
    """Reject binary floats even in optional metadata and output constructors."""
    if type(value) is float:
        raise ValueError("binary floats are prohibited in gamma evidence and results")
    if isinstance(value, (tuple, list, set, frozenset)):
        for item in value:
            reject_floats(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            reject_floats(key)
            reject_floats(item)
    elif is_dataclass(value) and not isinstance(value, type):
        for field in fields(value):
            reject_floats(getattr(value, field.name))


def require_decimal(value: Decimal, name: str, *, minimum: Decimal | None = None) -> None:
    canonical_decimal(value)
    if minimum is not None and value < minimum:
        raise ValueError(f"{name} must be >= {minimum}")


def require_ns(value: int, name: str) -> None:
    if type(value) is not int or value < 0:
        raise IntegerFieldError("INTEGER_REQUIRED")


@dataclass(frozen=True, slots=True)
class ExchangeCalendarV1(_NoCopyMixin):
    calendar_id: str
    version: str
    trade_date: date
    session_open_ns: int
    session_close_ns: int
    early_close: bool = False
    trading_session: bool = True

    def __post_init__(self) -> None:
        normalize_frozen(self)
        if not self.calendar_id or not self.version or type(self.trade_date) is not date:
            raise ValueError("versioned exchange-local calendar is required")
        if type(self.early_close) is not bool or type(self.trading_session) is not bool:
            raise ValueError("calendar session flags must be booleans")
        require_ns(self.session_open_ns, "session_open_ns")
        require_ns(self.session_close_ns, "session_close_ns")
        if self.session_close_ns <= self.session_open_ns:
            raise ValueError("session close must follow open")


@dataclass(frozen=True, slots=True)
class DeliverableLegV1(_NoCopyMixin):
    """One current deliverable leg; cash and other assets remain evidence."""

    kind: str  # UNDERLIER | CASH | OTHER_ASSET
    asset_id: str
    units: Decimal
    currency: str

    def __post_init__(self) -> None:
        normalize_frozen(self)
        if type(self.kind) is not str or self.kind not in {"UNDERLIER", "CASH", "OTHER_ASSET"}:
            raise ValueError("invalid deliverable leg kind")
        if not self.asset_id or type(self.asset_id) is not str:
            raise ValueError("deliverable asset_id required")
        if type(self.currency) is not str or not CURRENCY_RE.fullmatch(self.currency):
            raise ValueError("deliverable currency must be a three-letter ASCII ISO 4217 code")
        require_decimal(self.units, "deliverable units", minimum=ZERO)


@dataclass(frozen=True, slots=True)
class OptionSeriesEvidenceV1(_NoCopyMixin):
    series_id: str
    underlier: str
    contract: str
    venue: str
    option_type: str  # CALL | PUT
    strike: Decimal
    expiry_date: date  # exchange-local date
    expiry_kind: str  # WEEKLY | MONTHLY
    settlement: str  # AM | PM
    expiry_cutoff_ns: int  # last eligible instant, UTC; includes early close
    multiplier: Decimal
    currency: str
    open_interest: Decimal
    oi_asof_ns: int
    spot: Decimal
    spot_observed_ns: int
    spot_available_ns: int
    bid: Decimal | None
    ask: Decimal | None
    quote_observed_ns: int
    quote_available_ns: int
    implied_vol: Decimal
    iv_observed_ns: int
    iv_available_ns: int
    gamma: Decimal
    gamma_units: str  # PER_UNDERLYING_UNIT
    greek_observed_ns: int
    greek_available_ns: int
    source_id: str
    dataset_id: str
    entitlement_id: str
    entitlement_status: str  # ENTITLED | DENIED | UNKNOWN
    corporate_action_version: str
    split_factor: Decimal = ONE  # source strike / current-underlier strike
    halted: bool = False
    chain_complete: bool = True
    expected_series_count: int | None = None
    multiplier_basis: str | None = None  # PRE_ACTION | POST_ACTION_ADJUSTED
    adjustment_version: str | None = None
    deliverable_units: tuple[DeliverableLegV1, ...] | None = None

    def __post_init__(self) -> None:
        normalize_frozen(self)
        for name in ("series_id", "underlier", "contract", "venue", "currency", "source_id",
                     "dataset_id", "corporate_action_version"):
            if not getattr(self, name):
                raise ValueError(f"{name} is required")
        if type(self.currency) is not str or not CURRENCY_RE.fullmatch(self.currency):
            raise ValueError("INVALID_CURRENCY")
        if self.option_type not in {"CALL", "PUT"}:
            raise ValueError("option_type must be CALL or PUT")
        if self.expiry_kind not in {"WEEKLY", "MONTHLY"}:
            raise ValueError("expiry_kind must be WEEKLY or MONTHLY")
        if self.settlement not in {"AM", "PM"}:
            raise ValueError("settlement must be AM or PM")
        if type(self.expiry_date) is not date:
            raise ValueError("expiry_date must be an exchange-local date")
        if self.entitlement_status not in {"ENTITLED", "DENIED", "UNKNOWN"}:
            raise ValueError("invalid entitlement_status")
        if type(self.halted) is not bool:
            raise ValueError("halted must be a boolean")
        if type(self.chain_complete) is not bool:
            raise ValueError("chain_complete must be a boolean")
        if self.expected_series_count is not None and (type(self.expected_series_count) is not int
                                                       or self.expected_series_count < 0):
            raise ValueError("expected_series_count must be nonnegative")
        if self.adjustment_version is not None and (
                type(self.adjustment_version) is not str
                or not ADJUSTMENT_VERSION_RE.fullmatch(self.adjustment_version)):
            raise ValueError("adjustment_version must be a typed ASCII identifier")
        if self.deliverable_units is not None and (
                type(self.deliverable_units) is not tuple
                or any(not isinstance(leg, DeliverableLegV1) for leg in self.deliverable_units)):
            raise ValueError("deliverable_units must be a tuple of DeliverableLegV1")
        for name in ("strike", "multiplier", "spot", "implied_vol"):
            require_decimal(getattr(self, name), name, minimum=ZERO)
            if getattr(self, name) == ZERO:
                raise ValueError(f"{name} must be positive")
        require_decimal(self.split_factor, "split_factor")
        for name in ("open_interest", "gamma"):
            require_decimal(getattr(self, name), name, minimum=ZERO)
        for name in ("bid", "ask"):
            value = getattr(self, name)
            if value is not None:
                require_decimal(value, name, minimum=ZERO)
        if self.bid is not None and self.ask is not None and self.ask < self.bid:
            raise ValueError("ask below bid")
        for name in ("expiry_cutoff_ns", "oi_asof_ns", "spot_observed_ns",
                     "spot_available_ns", "quote_observed_ns", "quote_available_ns",
                     "iv_observed_ns", "iv_available_ns", "greek_observed_ns",
                     "greek_available_ns"):
            require_ns(getattr(self, name), name)
        for observed, available in ((self.spot_observed_ns, self.spot_available_ns),
                                    (self.quote_observed_ns, self.quote_available_ns),
                                    (self.iv_observed_ns, self.iv_available_ns),
                                    (self.greek_observed_ns, self.greek_available_ns)):
            if available < observed:
                raise ValueError("availability cannot precede observation")


@dataclass(frozen=True, slots=True)
class DealerExposureAssumptionV1(_NoCopyMixin):
    assumption_id: str
    version: str
    description: str
    call_sign: int
    put_sign: int
    oi_fraction: Decimal = ONE

    def __post_init__(self) -> None:
        normalize_frozen(self)
        if not self.assumption_id or not self.version or not self.description:
            raise ValueError("named, versioned dealer-side assumption is required")
        if type(self.call_sign) is not int or self.call_sign not in {-1, 0, 1}:
            raise ValueError("call_sign must be -1, 0, or 1")
        if type(self.put_sign) is not int or self.put_sign not in {-1, 0, 1}:
            raise ValueError("put_sign must be -1, 0, or 1")
        require_decimal(self.oi_fraction, "oi_fraction", minimum=ZERO)
        if self.oi_fraction > ONE:
            raise ValueError("scenario fraction cannot exceed open interest")


@dataclass(frozen=True, slots=True)
class ChainSnapshotV1(_NoCopyMixin):
    snapshot_id: str
    data_state: str  # LIVE | SETTLED
    underlier: str
    venue: str
    observed_ns: int
    available_ns: int
    revision: int
    source_id: str
    dataset_id: str
    calendar: ExchangeCalendarV1
    eligible_expiries: tuple[date, ...]
    eligible_oi_denominator: Decimal | None
    chain_complete: bool
    expected_series_count: int | None
    series: tuple[OptionSeriesEvidenceV1, ...]

    def __post_init__(self) -> None:
        normalize_frozen(self)
        if not all((self.snapshot_id, self.underlier, self.venue, self.source_id,
                    self.dataset_id)):
            raise ValueError("snapshot identity and source are required")
        if self.data_state not in {"LIVE", "SETTLED"}:
            raise ValueError("data_state must be LIVE or SETTLED")
        if not isinstance(self.calendar, ExchangeCalendarV1):
            raise ValueError("versioned exchange calendar is required")
        if type(self.chain_complete) is not bool:
            raise ValueError("chain_complete must be a boolean")
        require_ns(self.observed_ns, "observed_ns")
        require_ns(self.available_ns, "available_ns")
        if self.available_ns < self.observed_ns:
            raise ValueError("snapshot availability precedes observation")
        if type(self.revision) is not int or self.revision < 0:
            raise ValueError("revision must be nonnegative")
        if self.expected_series_count is not None and (type(self.expected_series_count) is not int
                                                       or self.expected_series_count < 0):
            raise ValueError("expected_series_count must be nonnegative")
        if self.eligible_oi_denominator is not None:
            require_decimal(self.eligible_oi_denominator, "eligible_oi_denominator",
                            minimum=ZERO)
        if type(self.series) is not tuple or type(self.eligible_expiries) is not tuple:
            raise ValueError("series and eligible_expiries must be tuples")
        if any(not isinstance(s, OptionSeriesEvidenceV1) for s in self.series):
            raise ValueError("series must contain OptionSeriesEvidenceV1")
        if len(set(self.eligible_expiries)) != len(self.eligible_expiries):
            raise ValueError("duplicate eligible expiry")
        if any(type(expiry) is not date for expiry in self.eligible_expiries):
            raise ValueError("eligible_expiries must be exchange-local dates")
        keys = [s.series_id for s in self.series]
        if len(set(keys)) != len(keys):
            raise ValueError("duplicate series identity")
        contracts = [(s.contract, s.venue) for s in self.series]
        if len(set(contracts)) != len(contracts):
            raise ValueError("duplicate option contract identity")
        if any(s.underlier != self.underlier or s.venue != self.venue for s in self.series):
            raise ValueError("mixed underlier or venue")


@dataclass(frozen=True, slots=True)
class GammaSnapshotV1(_NoCopyMixin):
    live: ChainSnapshotV1 | None
    settled: ChainSnapshotV1 | None = None

    def __post_init__(self) -> None:
        normalize_frozen(self)
        if self.live is None and self.settled is None:
            raise ValueError("at least one independently timestamped horizon is required")
        if self.live is not None and not isinstance(self.live, ChainSnapshotV1):
            raise ValueError("live must be a ChainSnapshotV1")
        if self.settled is not None and not isinstance(self.settled, ChainSnapshotV1):
            raise ValueError("settled must be a ChainSnapshotV1")
        if self.live is not None and self.live.data_state != "LIVE":
            raise ValueError("live horizon must have LIVE state")
        if self.settled is not None and self.settled.data_state != "SETTLED":
            raise ValueError("settled horizon must have SETTLED state")
        if self.live and self.settled and self.live.underlier != self.settled.underlier:
            raise ValueError("live and settled underliers differ")


@dataclass(frozen=True, slots=True)
class GammaPolicyV1(_NoCopyMixin):
    policy_id: str
    version: str
    calc_version: str
    expiry_policy_version: str
    eligible_expiries: tuple[date, ...]
    assumption: DealerExposureAssumptionV1 | None
    flip_spot_grid: tuple[Decimal, ...]
    flip_tolerance: Decimal
    wall_method: str = "OI_NOTIONAL"  # OI_NOTIONAL | GAMMA_WEIGHTED
    coverage_threshold: Decimal = Decimal("0.80")
    max_spot_age_ns: int = 2_000_000_000
    max_iv_age_ns: int = 10_000_000_000
    max_quote_age_ns: int = 10_000_000_000
    max_greek_age_ns: int = 10_000_000_000
    max_oi_age_ns: int = 172_800_000_000_000
    pin_band_width_pct: Decimal = Decimal("0.20")
    notional_scaling: str = "DOLLAR_GAMMA_1PCT_V1"
    greek_reprice_model: str = "BS_SPOT_ZERO_CARRY_SHAPE_V1"
    settled_eligible_expiries: tuple[date, ...] | None = None

    def __post_init__(self) -> None:
        normalize_frozen(self)
        if not all((self.policy_id, self.version, self.calc_version,
                    self.expiry_policy_version)):
            raise ValueError("versioned policy and calculation identity required")
        if self.assumption is not None and not isinstance(self.assumption,
                                                          DealerExposureAssumptionV1):
            raise ValueError("assumption must be DealerExposureAssumptionV1")
        if self.wall_method not in {"OI_NOTIONAL", "GAMMA_WEIGHTED"}:
            raise ValueError("unsupported wall method")
        if self.notional_scaling != "DOLLAR_GAMMA_1PCT_V1":
            raise ValueError("unsupported notional scaling")
        if self.greek_reprice_model != "BS_SPOT_ZERO_CARRY_SHAPE_V1":
            raise ValueError("unsupported Greek repricing model")
        if type(self.eligible_expiries) is not tuple or not self.eligible_expiries:
            raise ValueError("explicit eligible expiry set required")
        if len(set(self.eligible_expiries)) != len(self.eligible_expiries):
            raise ValueError("duplicate policy expiry")
        if any(type(e) is not date for e in self.eligible_expiries):
            raise ValueError("eligible expiries must be exchange-local dates")
        settled_expiries = self.settled_eligible_expiries
        if (settled_expiries is not None
                and (type(settled_expiries) is not tuple
                     or not settled_expiries
                     or any(type(e) is not date for e in settled_expiries)
                     or len(set(settled_expiries)) != len(settled_expiries))):
            raise ValueError("settled eligible expiries must be a nonempty unique date tuple")
        if type(self.flip_spot_grid) is not tuple or len(self.flip_spot_grid) < 2:
            raise ValueError("flip grid needs at least two spot prices")
        for spot in self.flip_spot_grid:
            require_decimal(spot, "flip grid spot", minimum=ZERO)
            if spot == ZERO:
                raise ValueError("flip grid spot must be positive")
        if any(a >= b for a, b in pairwise(self.flip_spot_grid)):
            raise ValueError("flip grid must be strictly increasing")
        require_decimal(self.flip_tolerance, "flip_tolerance", minimum=ZERO)
        if self.flip_tolerance == ZERO:
            raise ValueError("flip_tolerance must be positive")
        require_decimal(self.coverage_threshold, "coverage_threshold")
        if self.coverage_threshold < MIN_COVERAGE or self.coverage_threshold > ONE:
            raise PolicyOutOfBoundsError("POLICY_OUT_OF_BOUNDS")
        require_decimal(self.pin_band_width_pct, "pin_band_width_pct", minimum=ZERO)
        for name, maximum in (("max_spot_age_ns", MAX_SPOT_AGE_NS),
                              ("max_iv_age_ns", MAX_IV_AGE_NS),
                              ("max_quote_age_ns", MAX_QUOTE_AGE_NS),
                              ("max_greek_age_ns", MAX_GREEK_AGE_NS),
                              ("max_oi_age_ns", MAX_OI_AGE_NS)):
            value = getattr(self, name)
            if type(value) is not int or value < 0 or value > maximum:
                raise PolicyOutOfBoundsError("POLICY_OUT_OF_BOUNDS")


@dataclass(frozen=True, slots=True)
class ModelLevelV1(_NoCopyMixin):
    value: Decimal
    label: str = "MODEL_ESTIMATE"
    method: str = ""
    strength: Decimal | None = None
    lower_bracket: Decimal | None = None
    upper_bracket: Decimal | None = None
    error_bound: Decimal | None = None

    def __post_init__(self) -> None:
        normalize_frozen(self)
        if self.label != "MODEL_ESTIMATE" or type(self.method) is not str:
            raise ValueError("INVALID_MODEL_LEVEL")
        require_decimal(self.value, "level value")
        for name in ("strength", "lower_bracket", "upper_bracket", "error_bound"):
            value = getattr(self, name)
            if value is not None:
                require_decimal(value, name)


@dataclass(frozen=True, slots=True)
class WallLevelsV1(_NoCopyMixin):
    primary: ModelLevelV1 | None
    secondary: ModelLevelV1 | None
    method: str

    def __post_init__(self) -> None:
        normalize_frozen(self)
        if (type(self.method) is not str
                or (self.primary is not None and not isinstance(self.primary, ModelLevelV1))
                or (self.secondary is not None and not isinstance(self.secondary, ModelLevelV1))):
            raise ValueError("INVALID_WALL_LEVELS")


@dataclass(frozen=True, slots=True)
class MagnetV1(_NoCopyMixin):
    strike: Decimal
    weight: Decimal
    label: str = "MODEL_ESTIMATE"

    def __post_init__(self) -> None:
        normalize_frozen(self)
        if self.label != "MODEL_ESTIMATE":
            raise ValueError("INVALID_MAGNET")
        require_decimal(self.strike, "magnet strike")
        require_decimal(self.weight, "magnet weight", minimum=ZERO)


@dataclass(frozen=True, slots=True)
class ExcludedSeriesV1(_NoCopyMixin):
    series_id: str
    reason: str
    status: str = "EXCLUDED"

    def __post_init__(self) -> None:
        normalize_frozen(self)
        if not self.series_id or not self.reason or self.status != "EXCLUDED":
            raise ValueError("excluded series requires identity, reason and EXCLUDED status")


@dataclass(frozen=True, slots=True)
class CurrencyExposureV1(_NoCopyMixin):
    currency: str
    aggregate_gamma: Decimal

    def __post_init__(self) -> None:
        normalize_frozen(self)
        if type(self.currency) is not str or not CURRENCY_RE.fullmatch(self.currency):
            raise ValueError("INVALID_CURRENCY")
        require_decimal(self.aggregate_gamma, "aggregate_gamma")


@dataclass(frozen=True, slots=True, weakref_slot=True)
class HorizonEstimateV1(_NoCopyMixin):
    data_state: str
    status: str
    reasons: tuple[str, ...]
    snapshot_id: str
    revision: int
    observed_ns: int
    available_ns: int
    source_ids: tuple[str, ...]
    calendar_id: str
    calendar_version: str
    expiry_set: tuple[date, ...]
    active_expiry_set: tuple[date, ...]
    settlement_conventions: tuple[str, ...]
    assumption_id: str | None
    assumption_version: str | None
    multiplier_bases: tuple[str, ...]
    adjustment_versions: tuple[str, ...]
    gamma_units: str | None
    excluded_series: tuple[ExcludedSeriesV1, ...]
    sign_label: str
    aggregate_gamma: Decimal | None
    currency_exposures: tuple[CurrencyExposureV1, ...]
    gamma_sign_regime: str
    gamma_sign_regime_label: str
    gamma_sign_confidence: Decimal
    gamma_sign_reason: str | None
    regime: str
    regime_label: str
    regime_confidence: Decimal
    regime_reason: str | None
    coverage_ratio: Decimal | None
    spot_age_ns: int | None
    iv_age_ns: int | None
    oi_age_ns: int | None
    confidence: Decimal
    confidence_method: str
    confidence_inputs: tuple[tuple[str, Decimal], ...]
    flip: ModelLevelV1 | None
    flip_reason: str | None
    call_wall: WallLevelsV1 | None
    put_wall: WallLevelsV1 | None
    max_pain_weekly: ModelLevelV1 | None
    max_pain_monthly: ModelLevelV1 | None
    has_0dte: bool
    magnet_levels: tuple[MagnetV1, ...]
    pin_probability: None
    coverage_exact: tuple[int, int] | None = None
    _issue_token: InitVar[object] = None
    _seal: object = dataclass_field(default=None, init=False, repr=False, compare=False)

    def __post_init__(self, _issue_token: object) -> None:
        normalize_frozen(self)
        if self.pin_probability is not None:
            raise ValueError("PIN_PROBABILITY_UNAVAILABLE")
        if (self.coverage_exact is not None
                and (type(self.coverage_exact) is not tuple
                     or len(self.coverage_exact) != 2
                     or type(self.coverage_exact[0]) is not int
                     or type(self.coverage_exact[1]) is not int
                     or self.coverage_exact[0] < 0
                     or self.coverage_exact[1] <= 0)):
            raise ValueError("INVALID_EXACT_COVERAGE")
        if (self.coverage_exact is None) != (self.coverage_ratio is None):
            raise ValueError("COVERAGE_EVIDENCE_MISMATCH")
        if self.coverage_exact is not None:
            exact = Fraction(*self.coverage_exact)
            if (exact.numerator != self.coverage_exact[0]
                    or exact.denominator != self.coverage_exact[1]):
                raise ValueError("INVALID_EXACT_COVERAGE")
            with localcontext(KERNEL_CONTEXT):
                displayed = Decimal(exact.numerator) / Decimal(exact.denominator)
            if displayed != self.coverage_ratio:
                raise ValueError("COVERAGE_EVIDENCE_MISMATCH")
            if (exact < Fraction(MIN_COVERAGE)
                    and "LOW_OI_COVERAGE" not in self.reasons):
                raise ValueError("COVERAGE_REASON_MISMATCH")
            if exact > 1 and "OI_DENOMINATOR_UNDERCOUNTS" not in self.reasons:
                raise ValueError("COVERAGE_REASON_MISMATCH")
        if self.status == "OK" and (self.coverage_exact is None or self.reasons):
            raise ValueError("OK_COVERAGE_MISMATCH")
        if type(self.has_0dte) is not bool:
            raise ValueError("INVALID_0DTE_FLAG")
        if self.data_state not in {"LIVE", "SETTLED"}:
            raise ValueError("INVALID_DATA_STATE")
        if self.status not in {"OK", "DEGRADED", "STALE", "UNAVAILABLE"}:
            raise ValueError("INVALID_STATUS")
        for name in ("revision", "observed_ns", "available_ns"):
            require_ns(getattr(self, name), name)
        for name in ("spot_age_ns", "iv_age_ns", "oi_age_ns"):
            value = getattr(self, name)
            if value is not None and type(value) is not int:
                raise IntegerFieldError("INTEGER_REQUIRED")
        if (self.gamma_sign_regime_label != "MODEL_ESTIMATE"
                or self.regime_label != "MODEL_ESTIMATE"):
            raise ValueError("INVALID_REGIME_LABEL")
        if (self.gamma_sign_regime not in {"NEUTRAL", "POSITIVE_GAMMA", "NEGATIVE_GAMMA"}
                or self.regime not in {"NEUTRAL", "POSITIVE_GAMMA", "NEGATIVE_GAMMA"}):
            raise ValueError("INVALID_REGIME")
        if self.gamma_units not in {None, "PER_UNDERLYING_UNIT"}:
            raise ValueError("INVALID_GAMMA_UNITS")
        for name in ("reasons", "source_ids", "expiry_set", "active_expiry_set",
                     "settlement_conventions", "multiplier_bases", "adjustment_versions",
                     "excluded_series", "currency_exposures", "confidence_inputs",
                     "magnet_levels"):
            if type(getattr(self, name)) is not tuple:
                raise ValueError("MUTABLE_COLLECTION_FORBIDDEN")
        if any(type(reason) is not str for reason in self.reasons):
            raise ValueError("INVALID_REASON")
        if any(not isinstance(item, CurrencyExposureV1) for item in self.currency_exposures):
            raise ValueError("INVALID_CURRENCY_EXPOSURE")
        if any(not isinstance(item, ExcludedSeriesV1) for item in self.excluded_series):
            raise ValueError("INVALID_EXCLUDED_SERIES")
        if any(not isinstance(item, MagnetV1) for item in self.magnet_levels):
            raise ValueError("INVALID_MAGNET")
        if any(type(item) is not tuple or len(item) != 2 or type(item[0]) is not str
               or type(item[1]) is not Decimal for item in self.confidence_inputs):
            raise ValueError("INVALID_CONFIDENCE_INPUT")
        for name in ("aggregate_gamma", "coverage_ratio"):
            value = getattr(self, name)
            if value is not None:
                require_decimal(value, name)
        for name in ("gamma_sign_confidence", "regime_confidence", "confidence"):
            require_decimal(getattr(self, name), name, minimum=ZERO)
        if self.status == "OK" and self.aggregate_gamma is None:
            raise ValueError("OK_REQUIRES_AGGREGATE")
        if len(self.currency_exposures) > 1 and self.aggregate_gamma is not None:
            raise ValueError("MIXED_CURRENCY_HAS_NO_TOTAL")
        if self.status == "OK" and (len(self.currency_exposures) != 1
                                    or self.currency_exposures[0].aggregate_gamma
                                    != self.aggregate_gamma):
            raise ValueError("CURRENCY_AGGREGATE_MISMATCH")
        if len(self.currency_exposures) > 1 and "MIXED_CURRENCY" not in self.reasons:
            raise ValueError("MIXED_CURRENCY_REASON_MISSING")
        _seal_result(self, _issue_token)


@dataclass(frozen=True, slots=True, weakref_slot=True)
class GammaEstimateV1(_NoCopyMixin):
    underlier: str
    asof_ns: int
    policy_id: str
    policy_version: str
    calc_version: str
    expiry_policy_version: str
    notional_scaling: str
    greek_reprice_model: str
    wall_method: str
    live: HorizonEstimateV1 | None
    settled: HorizonEstimateV1 | None
    settled_missing: bool
    semantic_digest: str
    _issue_token: InitVar[object] = None
    _seal: object = dataclass_field(default=None, init=False, repr=False, compare=False)

    def __post_init__(self, _issue_token: object) -> None:
        normalize_frozen(self)
        if self.live is None and self.settled is None:
            raise ValueError("MISSING_HORIZON")
        if self.live is not None and not isinstance(self.live, HorizonEstimateV1):
            raise ValueError("INVALID_LIVE_HORIZON")
        if self.settled is not None and not isinstance(self.settled, HorizonEstimateV1):
            raise ValueError("INVALID_SETTLED_HORIZON")
        if ((self.live is not None and not _is_issued(self.live))
                or (self.settled is not None and not _is_issued(self.settled))):
            raise ValueError("RESULT_SEAL_INVALID")
        if self.live is not None and self.live.data_state != "LIVE":
            raise ValueError("INVALID_LIVE_HORIZON")
        if self.settled is not None and self.settled.data_state != "SETTLED":
            raise ValueError("INVALID_SETTLED_HORIZON")
        if type(self.settled_missing) is not bool or self.settled_missing != (self.settled is None):
            raise ValueError("INVALID_SETTLED_MISSING")
        require_ns(self.asof_ns, "asof_ns")
        if type(self.semantic_digest) is not str:
            raise ValueError("INVALID_SEMANTIC_DIGEST")
        _seal_result(self, _issue_token)


def canonical(value: Any) -> Any:
    """Canonical JSON value; no binary float or dataclass insertion-order dependency."""
    if isinstance(value, (HorizonEstimateV1, GammaEstimateV1)) and not _is_issued(value):
        raise ValueError("RESULT_SEAL_INVALID")
    if type(value) is Decimal:
        if not value.is_finite():
            raise ValueError("nonfinite Decimal cannot be canonicalized")
        if value == ZERO:
            return "0"
        sign, digit_tuple, exponent = value.as_tuple()
        if not isinstance(exponent, int):
            raise ValueError("nonfinite Decimal exponent")
        digits = list(digit_tuple)
        while digits[-1] == 0:
            digits.pop()
            exponent += 1
        return ("-" if sign else "") + "".join(str(digit) for digit in digits) + f"e{exponent}"
    if type(value) is date:
        return value.isoformat()
    if is_dataclass(value) and not isinstance(value, type):
        return {f.name: canonical(getattr(value, f.name)) for f in fields(value)
                if f.name != "_seal"}
    if isinstance(value, tuple):
        return [canonical(item) for item in value]
    if type(value) in (str, int, bool) or value is None:
        return value
    raise TypeError(f"noncanonical value: {type(value).__name__}")


def semantic_digest(value: Any) -> str:
    payload = json.dumps(canonical(value), sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True, allow_nan=False).encode("ascii")
    return sha256(payload).hexdigest()
