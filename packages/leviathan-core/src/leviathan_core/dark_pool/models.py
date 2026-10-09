"""Immutable inputs and outputs for the offline dark-pool lens.

All timestamps are UTC nanoseconds. Monetary inputs must be ``Decimal``; a
binary float is never silently accepted as a price, quantity, or FX rate.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import InitVar, asdict, dataclass, field
from datetime import date
from decimal import ROUND_HALF_EVEN, Context, Decimal, DecimalException, Inexact, localcontext
from fractions import Fraction
from typing import NoReturn, SupportsIndex, TypeVar


class DarkLensError(ValueError):
    """A stable, caller-visible rejection reason."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


_DECIMAL_CONTEXT = Context(prec=34, rounding=ROUND_HALF_EVEN, Emin=-38, Emax=38)
_EXACT_CONTEXT = _DECIMAL_CONTEXT.copy()
_EXACT_CONTEXT.traps[Inexact] = True
_RESULT_ISSUER = object()
_T = TypeVar("_T")


class _FrozenV1:
    __slots__ = ()

    def __copy__(self) -> NoReturn:
        raise DarkLensError("IMMUTABLE_COPY", "copy is not supported for frozen evidence")

    def __deepcopy__(self, memo: object) -> NoReturn:
        raise DarkLensError("IMMUTABLE_COPY", "deepcopy is not supported for frozen evidence")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise DarkLensError("IMMUTABLE_COPY", "pickle is not supported for frozen evidence")


def _canonical_decimal(value: Decimal, name: str) -> Decimal:
    if not isinstance(value, Decimal) or not value.is_finite():
        raise DarkLensError("INVALID_VALUE", f"{name} must be a finite Decimal")
    digits = value.as_tuple().digits
    significant = len(digits)
    while significant > 1 and digits[significant - 1] == 0:
        significant -= 1
    if significant > 34:
        raise DarkLensError("PRECISION_EXCEEDED", f"{name} exceeds 34 significant digits")
    if value and abs(value.adjusted()) > 38:
        raise DarkLensError("DECIMAL_OUT_OF_BOUNDS", f"{name} exceeds decimal bounds")
    try:
        with localcontext(_EXACT_CONTEXT):
            rounded = +value
            return Decimal(0) if rounded == 0 else rounded.normalize()
    except DecimalException as exc:
        raise DarkLensError("DECIMAL_OUT_OF_BOUNDS", f"{name} exceeds decimal bounds") from exc


def _positive(value: Decimal, name: str) -> Decimal:
    result = _canonical_decimal(value, name)
    if result <= 0:
        raise DarkLensError("INVALID_VALUE", f"{name} must be a finite positive Decimal")
    return result


def _nonnegative(value: Decimal, name: str) -> Decimal:
    result = _canonical_decimal(value, name)
    if result < 0:
        raise DarkLensError("INVALID_VALUE", f"{name} must be a finite nonnegative Decimal")
    return result


def _identity(value: str, name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise DarkLensError("INVALID_PROVENANCE", f"{name} is required")


def _timestamp(value: int | None, name: str) -> None:
    if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value < 0):
        raise DarkLensError("INVALID_TIME", f"{name} must be a UTC nanosecond integer")


def _bool(value: bool, name: str) -> None:
    if type(value) is not bool:
        raise DarkLensError("INVALID_FLAG", f"{name} must be a boolean")


def _tuple_of(value: object, member_type: type[_T], name: str) -> tuple[_T, ...]:
    if isinstance(value, (str, bytes)) or (
        name == "condition_codes" and not isinstance(value, tuple)
    ):
        raise DarkLensError("INVALID_COLLECTION", f"{name} must be a frozen tuple")
    try:
        members: tuple[_T, ...] = tuple(value)  # type: ignore[arg-type]
    except TypeError as exc:
        raise DarkLensError("INVALID_COLLECTION", f"{name} must be a collection") from exc
    if any(not isinstance(member, member_type) for member in members):
        raise DarkLensError("INVALID_COLLECTION", f"{name} has an invalid element")
    return members


@dataclass(frozen=True, slots=True)
class DarkPrintV1(_FrozenV1):
    instrument_id: str
    source_id: str
    dataset_id: str
    venue: str
    native_id: str
    event_ns: int
    published_ns: int | None
    available_ns: int | None
    exchange_tz: str
    calendar_version: str
    price: Decimal
    size: Decimal
    fx_rate: Decimal = Decimal("1")
    fx_version: str = "v1"
    split_factor: Decimal = Decimal("1")
    split_version: str = "v1"
    condition_codes: tuple[str, ...] = ()
    is_odd_lot: bool = False
    entitlement_status: str = "SYNTHETIC"
    source_state: str = "SYNTHETIC"
    side: str = "U"
    reference_mid: Decimal | None = None
    correction_id: str = "0"
    supersedes_id: str | None = None
    entitlement_evidence_id: str | None = None

    def __post_init__(self) -> None:
        for name in (
            "instrument_id",
            "source_id",
            "dataset_id",
            "venue",
            "native_id",
            "exchange_tz",
            "calendar_version",
            "fx_version",
            "split_version",
            "correction_id",
        ):
            _identity(getattr(self, name), name)
        for name in ("event_ns", "published_ns", "available_ns"):
            _timestamp(getattr(self, name), name)
        for name in ("price", "size", "fx_rate", "split_factor"):
            object.__setattr__(self, name, _positive(getattr(self, name), name))
        _bool(self.is_odd_lot, "is_odd_lot")
        if self.reference_mid is not None and not isinstance(self.reference_mid, Decimal):
            raise DarkLensError("INVALID_VALUE", "reference_mid must be a Decimal")
        if self.reference_mid is not None and self.reference_mid.is_finite():
            object.__setattr__(
                self, "reference_mid", _canonical_decimal(self.reference_mid, "reference_mid")
            )
        if self.side not in {"B", "S", "U"}:
            raise DarkLensError("INVALID_SIDE", "side must be B, S, or U")
        if self.source_state not in {"SYNTHETIC", "UNVERIFIED", "LICENSED_PRINT"}:
            raise DarkLensError("AGGREGATE_ONLY", "aggregate data cannot become a dark print")
        if self.entitlement_status not in {"SYNTHETIC", "UNVERIFIED", "VERIFIED"}:
            raise DarkLensError("INVALID_ENTITLEMENT", "unknown entitlement evidence status")
        if self.source_state != "LICENSED_PRINT" and self.entitlement_status == "VERIFIED":
            raise DarkLensError("INVALID_ENTITLEMENT", "fixture evidence is not licensed")
        if self.source_state == "LICENSED_PRINT" and (
            self.entitlement_status != "VERIFIED"
            or not self.entitlement_evidence_id
            or not self.entitlement_evidence_id.strip()
        ):
            raise DarkLensError("INVALID_ENTITLEMENT", "licensed print needs verified evidence ID")
        object.__setattr__(
            self, "condition_codes", _tuple_of(self.condition_codes, str, "condition_codes")
        )


@dataclass(frozen=True, slots=True)
class LitTradeV1(_FrozenV1):
    instrument_id: str
    source_id: str
    dataset_id: str
    venue: str
    native_id: str
    event_ns: int
    published_ns: int | None
    available_ns: int | None
    exchange_tz: str
    calendar_version: str
    price: Decimal
    size: Decimal
    fx_rate: Decimal = Decimal("1")
    fx_version: str = "v1"
    split_factor: Decimal = Decimal("1")
    split_version: str = "v1"
    condition_codes: tuple[str, ...] = ()
    is_odd_lot: bool = False
    entitlement_status: str = "SYNTHETIC"
    source_state: str = "SYNTHETIC"
    is_off_exchange: bool = False
    correction_id: str = "0"
    supersedes_id: str | None = None
    entitlement_evidence_id: str | None = None

    def __post_init__(self) -> None:
        for name in (
            "instrument_id",
            "source_id",
            "dataset_id",
            "venue",
            "native_id",
            "exchange_tz",
            "calendar_version",
            "fx_version",
            "split_version",
            "correction_id",
        ):
            _identity(getattr(self, name), name)
        for name in ("event_ns", "published_ns", "available_ns"):
            _timestamp(getattr(self, name), name)
        for name in ("price", "size", "fx_rate", "split_factor"):
            object.__setattr__(self, name, _positive(getattr(self, name), name))
        _bool(self.is_odd_lot, "is_odd_lot")
        _bool(self.is_off_exchange, "is_off_exchange")
        if self.source_state not in {"SYNTHETIC", "UNVERIFIED", "LICENSED_PRINT"}:
            raise DarkLensError("INVALID_SOURCE", "lit trade needs print-level source state")
        if self.entitlement_status not in {"SYNTHETIC", "UNVERIFIED", "VERIFIED"}:
            raise DarkLensError("INVALID_ENTITLEMENT", "unknown entitlement evidence status")
        if self.source_state != "LICENSED_PRINT" and self.entitlement_status == "VERIFIED":
            raise DarkLensError("INVALID_ENTITLEMENT", "fixture evidence is not licensed")
        if self.source_state == "LICENSED_PRINT" and (
            self.entitlement_status != "VERIFIED"
            or not self.entitlement_evidence_id
            or not self.entitlement_evidence_id.strip()
        ):
            raise DarkLensError("INVALID_ENTITLEMENT", "licensed trade needs verified evidence ID")
        object.__setattr__(
            self, "condition_codes", _tuple_of(self.condition_codes, str, "condition_codes")
        )


@dataclass(frozen=True, slots=True)
class AggregateContextV1(_FrozenV1):
    """Delayed ATS/OTC context; it can never participate in print arithmetic."""

    instrument_id: str
    source_id: str
    dataset_id: str
    venue: str
    native_id: str
    event_ns: int
    published_ns: int | None
    available_ns: int | None
    exchange_tz: str
    calendar_version: str
    release_vintage: str
    entitlement_status: str = "UNVERIFIED"
    source_state: str = "AGGREGATE_ONLY"

    def __post_init__(self) -> None:
        for name in (
            "instrument_id",
            "source_id",
            "dataset_id",
            "venue",
            "native_id",
            "exchange_tz",
            "calendar_version",
            "release_vintage",
        ):
            _identity(getattr(self, name), name)
        for name in ("event_ns", "published_ns", "available_ns"):
            _timestamp(getattr(self, name), name)
        if self.source_state != "AGGREGATE_ONLY":
            raise DarkLensError("INVALID_SOURCE", "aggregate context is AGGREGATE_ONLY")
        if self.entitlement_status not in {"UNVERIFIED", "VERIFIED"}:
            raise DarkLensError("INVALID_ENTITLEMENT", "aggregate entitlement status invalid")


@dataclass(frozen=True, slots=True)
class ExchangeSessionV1(_FrozenV1):
    trading_day: date
    open_ns: int
    close_ns: int
    exchange_tz: str
    calendar_version: str
    local_open_time: str = "09:30"
    utc_offset_minutes: int | None = None

    def __post_init__(self) -> None:
        _timestamp(self.open_ns, "open_ns")
        _timestamp(self.close_ns, "close_ns")
        if self.open_ns >= self.close_ns:
            raise DarkLensError("INVALID_CALENDAR", "session open must precede close")
        _identity(self.exchange_tz, "exchange_tz")
        _identity(self.calendar_version, "calendar_version")
        if not isinstance(self.local_open_time, str) or not re.fullmatch(
            r"[0-9]{2}:[0-9]{2}", self.local_open_time
        ):
            raise DarkLensError("INVALID_CALENDAR", "local open must be ASCII HH:MM")
        try:
            hour, minute = (int(part) for part in self.local_open_time.split(":"))
        except ValueError as exc:
            raise DarkLensError("INVALID_CALENDAR", "local open must be HH:MM") from exc
        if not (0 <= hour < 24 and 0 <= minute < 60):
            raise DarkLensError("INVALID_CALENDAR", "local open must be HH:MM")
        if self.utc_offset_minutes is not None and (
            isinstance(self.utc_offset_minutes, bool)
            or not isinstance(self.utc_offset_minutes, int)
            or not -840 <= self.utc_offset_minutes <= 840
        ):
            raise DarkLensError("INVALID_CALENDAR", "UTC offset is outside supported range")


@dataclass(frozen=True, slots=True)
class VenueRuleV1(_FrozenV1):
    """Injected closed venue classification; free-text venue guessing is forbidden."""

    venue: str
    market_type: str

    def __post_init__(self) -> None:
        if not isinstance(self.venue, str) or not re.fullmatch(
            r"[A-Z][A-Z0-9_-]{1,31}", self.venue
        ):
            raise DarkLensError("INVALID_VENUE", "venue registry key must be ASCII")
        if self.market_type not in {"LIT", "OFF_EXCHANGE"}:
            raise DarkLensError("INVALID_VENUE", "venue market type is unsupported")


@dataclass(frozen=True, slots=True)
class BaselineSampleV1(_FrozenV1):
    trading_day: date
    window_start_ns: int
    divergence: Decimal
    published_ns: int | None
    available_ns: int | None
    source_id: str
    instrument_id: str = field(kw_only=True)
    window_end_ns: int = field(kw_only=True)
    window_family: str = field(default="rolling-v1", kw_only=True)
    adjustment_scope: str = field(default="base-v1", kw_only=True)

    def __post_init__(self) -> None:
        for name in ("window_start_ns", "window_end_ns", "published_ns", "available_ns"):
            _timestamp(getattr(self, name), name)
        object.__setattr__(self, "divergence", _canonical_decimal(self.divergence, "divergence"))
        for name in ("source_id", "instrument_id", "window_family", "adjustment_scope"):
            _identity(getattr(self, name), name)
        if self.window_end_ns <= self.window_start_ns:
            raise DarkLensError("INVALID_BASELINE", "baseline window must have positive duration")
        if (self.available_ns is not None and self.available_ns < self.window_end_ns) or (
            self.published_ns is not None and self.published_ns < self.window_end_ns
        ):
            raise DarkLensError("INVALID_BASELINE", "baseline cannot publish before window ends")


@dataclass(frozen=True, slots=True)
class DarkLensPolicyV1(_FrozenV1):
    instrument_id: str
    window_start_ns: int
    window_end_ns: int
    calendar_version: str
    bucket_scheme: str = "fixed"
    fixed_thresholds: tuple[Decimal, ...] = (
        Decimal("1000000"),
        Decimal("5000000"),
        Decimal("10000000"),
    )
    quantile_count: int = 5
    min_notional: Decimal = Decimal("100000")
    min_lit_volume: Decimal = Decimal("50000")
    include_odd_lots: bool = False
    counts_low: bool = False
    venue_filter: str = "lit_all"
    allowed_conditions: tuple[str, ...] = ()
    open_minutes: int = 60
    lunch_start: str = "11:30"
    lunch_end: str = "13:30"
    close_minutes: int = 60
    session_rule_version: str = "backend-v1"
    side_rule_version: str = "mid-v1"
    baseline_version: str = "prior30-v1"
    pressure_threshold_bp: Decimal = Decimal("150")
    policy_version: str = "dp-v1"
    bucket_rule_version: str = "backend-v1"
    window_family: str = "rolling-v1"
    adjustment_scope: str = "base-v1"

    def __post_init__(self) -> None:
        _identity(self.instrument_id, "instrument_id")
        _identity(self.calendar_version, "calendar_version")
        for name in ("window_start_ns", "window_end_ns"):
            _timestamp(getattr(self, name), name)
        if self.window_start_ns >= self.window_end_ns:
            raise DarkLensError("INVALID_WINDOW", "window must be half-open with start < end")
        if self.bucket_scheme not in {"fixed", "quantile"}:
            raise DarkLensError("INVALID_BUCKET", "bucket scheme must be fixed or quantile")
        if isinstance(self.quantile_count, bool) or self.quantile_count not in {5, 10}:
            raise DarkLensError("INVALID_BUCKET", "quantile_count must be 5 or 10")
        thresholds = _tuple_of(self.fixed_thresholds, Decimal, "fixed_thresholds")
        if self.bucket_scheme == "fixed" and not thresholds:
            raise DarkLensError("INVALID_BUCKET", "fixed buckets require thresholds")
        thresholds = tuple(_positive(threshold, "fixed_threshold") for threshold in thresholds)
        if thresholds != tuple(sorted(set(thresholds))):
            raise DarkLensError("INVALID_BUCKET", "fixed thresholds must increase uniquely")
        object.__setattr__(self, "fixed_thresholds", thresholds)
        for name in ("min_notional", "min_lit_volume", "pressure_threshold_bp"):
            object.__setattr__(self, name, _nonnegative(getattr(self, name), name))
        _bool(self.include_odd_lots, "include_odd_lots")
        _bool(self.counts_low, "counts_low")
        if self.venue_filter != "lit_all":
            raise DarkLensError("INVALID_VENUE_FILTER", "only lit_all is supported")
        if (
            isinstance(self.open_minutes, bool)
            or not isinstance(self.open_minutes, int)
            or isinstance(self.close_minutes, bool)
            or not isinstance(self.close_minutes, int)
            or self.open_minutes <= 0
            or self.close_minutes <= 0
        ):
            raise DarkLensError("INVALID_SESSION", "open and close minutes must be positive")
        lunch_minutes = []
        for value in (self.lunch_start, self.lunch_end):
            if not isinstance(value, str) or not re.fullmatch(r"[0-9]{2}:[0-9]{2}", value):
                raise DarkLensError("INVALID_SESSION", "lunch times must be ASCII HH:MM")
            try:
                hour, minute = (int(part) for part in value.split(":"))
            except (ValueError, TypeError) as exc:
                raise DarkLensError("INVALID_SESSION", "lunch times must be HH:MM") from exc
            if not (0 <= hour < 24 and 0 <= minute < 60):
                raise DarkLensError("INVALID_SESSION", "lunch times must be HH:MM")
            lunch_minutes.append(hour * 60 + minute)
        if lunch_minutes[0] >= lunch_minutes[1]:
            raise DarkLensError("INVALID_SESSION", "lunch start must precede end")
        for name in (
            "policy_version",
            "bucket_rule_version",
            "session_rule_version",
            "side_rule_version",
            "baseline_version",
            "window_family",
            "adjustment_scope",
        ):
            _identity(getattr(self, name), name)
        if self.side_rule_version != "mid-v1":
            raise DarkLensError("INVALID_SIDE_RULE", "unsupported side inference rule")
        object.__setattr__(
            self,
            "allowed_conditions",
            _tuple_of(self.allowed_conditions, str, "allowed_conditions"),
        )


@dataclass(frozen=True, slots=True)
class DarkLensSnapshotV1(_FrozenV1):
    dark_prints: tuple[DarkPrintV1, ...] = ()
    lit_trades: tuple[LitTradeV1, ...] = ()
    calendar: tuple[ExchangeSessionV1, ...] = ()
    baseline_samples: tuple[BaselineSampleV1, ...] = ()
    aggregate_context: tuple[AggregateContextV1, ...] = ()
    mode: str = "OFFLINE"
    revision: int = 0
    venue_registry: tuple[VenueRuleV1, ...] = ()

    def __post_init__(self) -> None:
        typed = (
            ("dark_prints", DarkPrintV1),
            ("lit_trades", LitTradeV1),
            ("calendar", ExchangeSessionV1),
            ("baseline_samples", BaselineSampleV1),
            ("aggregate_context", AggregateContextV1),
            ("venue_registry", VenueRuleV1),
        )
        for name, member_type in typed:
            object.__setattr__(self, name, _tuple_of(getattr(self, name), member_type, name))
        venue_names = [rule.venue for rule in self.venue_registry]
        if len(venue_names) != len(set(venue_names)):
            raise DarkLensError("INVALID_VENUE", "venue registry contains duplicate keys")
        if self.mode not in {"ONLINE", "OFFLINE"}:
            raise DarkLensError("INVALID_MODE", "mode must be ONLINE or OFFLINE")
        if (
            isinstance(self.revision, bool)
            or not isinstance(self.revision, int)
            or self.revision < 0
        ):
            raise DarkLensError("INVALID_REVISION", "revision must be nonnegative")


@dataclass(frozen=True, slots=True)
class RankedPrintV1(_FrozenV1):
    rank: int
    source_key: str
    event_ns: int
    venue: str
    notional: Decimal
    side: str
    side_inferred: bool
    bucket: str

    def __post_init__(self) -> None:
        if isinstance(self.rank, bool) or not isinstance(self.rank, int) or self.rank <= 0:
            raise DarkLensError("INVALID_RESULT", "rank must be positive")
        _timestamp(self.event_ns, "event_ns")
        object.__setattr__(self, "notional", _nonnegative(self.notional, "notional"))
        _bool(self.side_inferred, "side_inferred")
        for name in ("source_key", "venue", "bucket"):
            _identity(getattr(self, name), name)
        if self.side not in {"B", "S", "U"}:
            raise DarkLensError("INVALID_SIDE", "ranked side is invalid")


@dataclass(frozen=True, slots=True)
class BucketCountV1(_FrozenV1):
    bucket: str
    count: int
    total_notional: Decimal

    def __post_init__(self) -> None:
        _identity(self.bucket, "bucket")
        if isinstance(self.count, bool) or not isinstance(self.count, int) or self.count < 0:
            raise DarkLensError("INVALID_RESULT", "bucket count is invalid")
        object.__setattr__(
            self, "total_notional", _nonnegative(self.total_notional, "total_notional")
        )


@dataclass(frozen=True, slots=True)
class SessionMetricV1(_FrozenV1):
    session_id: str
    start_ns: int
    end_ns: int
    buy_notional: Decimal
    sell_notional: Decimal
    unknown_notional: Decimal
    imbalance_bp: Decimal | None
    dp_vs_lit_volume_ratio: Decimal | None
    cluster_label: str

    def __post_init__(self) -> None:
        _identity(self.session_id, "session_id")
        _identity(self.cluster_label, "cluster_label")
        _timestamp(self.start_ns, "start_ns")
        _timestamp(self.end_ns, "end_ns")
        for name in ("buy_notional", "sell_notional", "unknown_notional"):
            object.__setattr__(self, name, _nonnegative(getattr(self, name), name))
        for name in ("imbalance_bp", "dp_vs_lit_volume_ratio"):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, _canonical_decimal(value, name))


@dataclass(frozen=True, slots=True)
class DarkLensResultV1(_FrozenV1):
    instrument_id: str
    window_start_ns: int
    window_end_ns: int
    asof_ns: int
    revision: int
    source_state: str
    delay_label: str
    observed_lag_ns: int | None
    earliest_usable_ns: int | None
    source_ids: tuple[str, ...]
    source_event_ids: tuple[str, ...]
    aggregate_context_ids: tuple[str, ...]
    adjustment_versions: tuple[str, ...]
    min_notional: Decimal
    policy_version: str
    bucket_rule_version: str
    bucket_scheme: str
    bucket_thresholds: tuple[Decimal, ...]
    quantile_count: int
    include_odd_lots: bool
    counts_low_requested: bool
    venue_filter: str
    side_rule_version: str
    calendar_version: str
    session_rule_version: str
    baseline_version: str
    window_id: str
    session_ids: tuple[str, ...]
    ranked_prints: tuple[RankedPrintV1, ...] = ()
    bucket_counts: tuple[BucketCountV1, ...] = ()
    counts_low: int | None = None
    total_dp_trades: int = 0
    total_notional: Decimal | None = None
    total_notional_ranked: Decimal | None = None
    vwap_basis: str = "ALL_ELIGIBLE_PRINTS"
    avg_trade_size: Decimal | None = None
    dp_vwap: Decimal | None = None
    lit_vwap: Decimal | None = None
    divergence: Decimal | None = None
    divergence_z: Decimal | None = None
    lit_volume: Decimal = Decimal("0")
    dp_volume: Decimal = Decimal("0")
    buy_sell_imbalance_bp: Decimal | None = None
    session_metrics: tuple[SessionMetricV1, ...] = ()
    valid: bool = False
    reason_if_invalid: str | None = None
    z_reason: str | None = None
    recompute_pending: bool = False
    flags: tuple[str, ...] = ()
    digest: str = field(default="")
    _issuer: InitVar[object] = None
    _seal: bool = field(init=False, repr=False, compare=False)

    def __post_init__(self, _issuer: object) -> None:
        if _issuer is not _RESULT_ISSUER:
            raise DarkLensError("UNISSUED_RESULT", "result requires kernel issuance")
        for name in (
            "window_start_ns",
            "window_end_ns",
            "asof_ns",
            "observed_lag_ns",
            "earliest_usable_ns",
        ):
            _timestamp(getattr(self, name), name)
        for name in ("revision", "quantile_count", "total_dp_trades"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise DarkLensError("INVALID_RESULT", f"{name} must be a nonnegative integer")
        if self.counts_low is not None and (
            isinstance(self.counts_low, bool)
            or not isinstance(self.counts_low, int)
            or self.counts_low < 0
        ):
            raise DarkLensError("INVALID_RESULT", "counts_low must be a nonnegative integer")
        for name in ("ranked_prints", "bucket_counts", "session_metrics"):
            member_type = {
                "ranked_prints": RankedPrintV1,
                "bucket_counts": BucketCountV1,
                "session_metrics": SessionMetricV1,
            }[name]
            object.__setattr__(self, name, _tuple_of(getattr(self, name), member_type, name))
        for name in (
            "source_ids",
            "source_event_ids",
            "aggregate_context_ids",
            "adjustment_versions",
            "session_ids",
            "flags",
        ):
            object.__setattr__(self, name, _tuple_of(getattr(self, name), str, name))
        object.__setattr__(
            self,
            "bucket_thresholds",
            tuple(
                _positive(value, "bucket_threshold")
                for value in _tuple_of(self.bucket_thresholds, Decimal, "bucket_thresholds")
            ),
        )
        for name in ("include_odd_lots", "counts_low_requested", "valid", "recompute_pending"):
            _bool(getattr(self, name), name)
        for name in ("min_notional", "lit_volume", "dp_volume"):
            object.__setattr__(self, name, _nonnegative(getattr(self, name), name))
        for name in (
            "total_notional",
            "total_notional_ranked",
            "avg_trade_size",
            "dp_vwap",
            "lit_vwap",
            "divergence",
            "divergence_z",
            "buy_sell_imbalance_bp",
        ):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, _canonical_decimal(value, name))
        object.__setattr__(self, "_seal", True)
        if self.digest:
            if _result_hash(self) != self.digest:
                raise DarkLensError("RESULT_INTEGRITY", "result fields do not match digest")
            _validate_result_totals(self)


def _result_hash(result: DarkLensResultV1) -> str:
    payload = asdict(result)
    payload.pop("_seal")
    payload["digest"] = ""

    def canonical(value: object) -> str:
        if isinstance(value, Decimal):
            if value == 0:
                return "0"
            with localcontext(_DECIMAL_CONTEXT):
                return str(value.normalize())
        return str(value)

    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=canonical)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _validate_result_totals(result: DarkLensResultV1) -> None:
    ranked_total = sum((Fraction(row.notional) for row in result.ranked_prints), Fraction(0))
    if result.flags == ("OVERFLOW",):
        if (
            result.valid
            or result.total_notional is not None
            or result.total_notional_ranked is not None
            or result.ranked_prints
            or result.bucket_counts
        ):
            raise DarkLensError("RESULT_INTEGRITY", "overflow result contains financial totals")
        return
    if (
        result.total_notional_ranked is None
        or Fraction(result.total_notional_ranked) != ranked_total
    ):
        raise DarkLensError("RESULT_INTEGRITY", "ranked total does not match print rows")
    if result.total_notional is None or Fraction(result.total_notional) < ranked_total:
        raise DarkLensError("RESULT_INTEGRITY", "total notional does not reconcile")
    if result.vwap_basis != "ALL_ELIGIBLE_PRINTS":
        raise DarkLensError("RESULT_INTEGRITY", "VWAP basis is unsupported")
    if result.dp_volume:
        with localcontext(_DECIMAL_CONTEXT):
            expected_vwap = result.total_notional / result.dp_volume
        if result.dp_vwap != expected_vwap:
            raise DarkLensError("RESULT_INTEGRITY", "dark VWAP does not reconcile")
    elif result.dp_vwap is not None or result.total_notional != 0:
        raise DarkLensError("RESULT_INTEGRITY", "empty dark volume has a dark price")
    if result.total_dp_trades < len(result.ranked_prints):
        raise DarkLensError("RESULT_INTEGRITY", "rank count exceeds trade count")
    if any(row.notional < result.min_notional for row in result.ranked_prints):
        raise DarkLensError("RESULT_INTEGRITY", "rank includes a subminimum print")
    if result.counts_low_requested:
        if (
            result.counts_low is None
            or result.total_dp_trades != len(result.ranked_prints) + result.counts_low
        ):
            raise DarkLensError("RESULT_INTEGRITY", "low count does not reconcile")
    elif result.counts_low is not None:
        raise DarkLensError("RESULT_INTEGRITY", "unrequested low count is present")
    if sum((row.count for row in result.bucket_counts), 0) != len(result.ranked_prints):
        raise DarkLensError("RESULT_INTEGRITY", "bucket counts do not reconcile")
    if (
        sum((Fraction(row.total_notional) for row in result.bucket_counts), Fraction(0))
        != ranked_total
    ):
        raise DarkLensError("RESULT_INTEGRITY", "bucket notionals do not reconcile")
