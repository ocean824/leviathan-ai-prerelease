"""Immutable, point-in-time contracts for the offline event metrics kernel."""

from __future__ import annotations

from dataclasses import InitVar, dataclass, field, fields
from datetime import date
from decimal import ROUND_HALF_EVEN, Context, Decimal
from hashlib import sha256
from typing import Literal, NoReturn, SupportsIndex

EventState = Literal["scheduled", "confirmed", "revised", "delayed", "canceled", "completed"]
EventPrecision = Literal["exact", "session", "date"]
EventSession = Literal["pre", "regular", "post", "unknown"]
EvidenceKind = Literal["spot", "adjusted_close", "iv30d", "straddle"]
MetricStatus = Literal[
    "OK", "PARTIAL", "MISSING", "STALE", "QUARANTINED", "CANCELED", "UNAVAILABLE"
]
FeedState = Literal["SYNTHETIC", "ENTITLED", "UNVERIFIED", "UNENTITLED"]
DECIMAL_CONTEXT = Context(prec=34, rounding=ROUND_HALF_EVEN)


class PrecisionExceededError(ValueError):
    """An input cannot be represented exactly at the kernel's precision."""

    code = "PRECISION_EXCEEDED"

    def __init__(self) -> None:
        super().__init__(self.code)


class IntegerFieldTypeError(TypeError):
    """A model integer field received a bool or non-integer value."""

    code = "INVALID_INTEGER"

    def __init__(self, name: str) -> None:
        super().__init__(f"{self.code}:{name}")


class FrozenRecordReconstructionError(TypeError):
    """A public frozen record cannot be copied or deserialized."""

    code = "FROZEN_RECORD_RECONSTRUCTION_FORBIDDEN"

    def __init__(self) -> None:
        super().__init__(self.code)


class SealedResultError(ValueError):
    """A result was not issued by the kernel or its field binding changed."""

    code = "RESULT_CONTENT_MISMATCH"

    def __init__(self) -> None:
        super().__init__(self.code)


@dataclass(frozen=True, slots=True)
class _ResultSeal:
    content_hash: str


_ISSUER = object()


class _NoReconstructionV1:
    def __copy__(self) -> NoReturn:
        raise FrozenRecordReconstructionError()

    def __deepcopy__(self, memo: dict[int, object]) -> NoReturn:
        raise FrozenRecordReconstructionError()

    def __reduce__(self) -> NoReturn:
        raise FrozenRecordReconstructionError()

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise FrozenRecordReconstructionError()


def _integers(record: object, names: tuple[str, ...], *, optional: tuple[str, ...] = ()) -> None:
    for name in names:
        value = getattr(record, name)
        if value is None and name in optional:
            continue
        if type(value) is not int:
            raise IntegerFieldTypeError(name)


def _text(value: str | None, name: str, *, optional: bool = False) -> None:
    if value is None and optional:
        return
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a nonempty string")


def canonical_decimal(value: Decimal, name: str, *, allow_zero: bool = False,
                      allow_negative: bool = False) -> Decimal:
    """Normalize exactly without rounding, then bound a stored input."""
    if not isinstance(value, Decimal) or not value.is_finite():
        raise ValueError(f"{name} must be a finite Decimal")
    raw = value.as_tuple()
    if value.is_zero():
        if abs(value.adjusted()) > 38:
            raise ValueError(f"{name} exceeds decimal bounds")
        if not allow_zero:
            raise ValueError(f"{name} must be positive")
        return Decimal(0)
    digits = raw.digits
    end = len(digits)
    while end > 1 and digits[end - 1] == 0:
        end -= 1
    if end > DECIMAL_CONTEXT.prec:
        raise PrecisionExceededError()
    if abs(value.adjusted()) > 38:
        raise ValueError(f"{name} exceeds decimal bounds")
    result = Decimal((raw.sign, digits[:end], int(raw.exponent) + len(digits) - end))
    if abs(result.adjusted()) > 38:
        raise ValueError(f"{name} exceeds decimal bounds")
    if result < 0 and not allow_negative:
        raise ValueError(f"{name} must be nonnegative")
    return result


def _decimal_fields(record: object, names: tuple[str, ...], *,
                    optional: tuple[str, ...] = (), signed: tuple[str, ...] = (),
                    zero: tuple[str, ...] = ()) -> None:
    for name in names:
        value = getattr(record, name)
        if value is None and name in optional:
            continue
        object.__setattr__(record, name, canonical_decimal(
            value, name, allow_zero=name in zero, allow_negative=name in signed
        ))


def _strings(value: tuple[str, ...], name: str, *, unique: bool = True) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)):
        raise ValueError(f"{name} must be a sequence of strings")
    frozen = tuple(value)
    if any(not isinstance(item, str) or not item for item in frozen):
        raise ValueError(f"{name} contains an empty or non-string value")
    if unique and len(set(frozen)) != len(frozen):
        raise ValueError(f"{name} contains duplicates")
    return frozen


@dataclass(frozen=True, slots=True)
class ExpectedMoveWindowV1(_NoReconstructionV1):
    """A typed pair of trading-session dates, checked against the injected calendar."""

    start_session_date: date
    end_session_date: date

    def __post_init__(self) -> None:
        if not isinstance(self.start_session_date, date) or not isinstance(
            self.end_session_date, date
        ):
            raise ValueError("expected window requires session dates")
        if self.start_session_date > self.end_session_date:
            raise ValueError("expected window begins after it ends")


@dataclass(frozen=True, slots=True)
class CorporateActionSnapshotV1(_NoReconstructionV1):
    """As-of-visible factors that map different close vintages to one basis."""

    snapshot_id: str
    source: str
    available_ns: int
    basis_version: str
    factors: tuple[tuple[str, Decimal], ...]

    def __post_init__(self) -> None:
        _integers(self, ("available_ns",))
        for name in ("snapshot_id", "source", "basis_version"):
            _text(getattr(self, name), name)
        frozen = tuple((version, canonical_decimal(factor, "action factor"))
                       for version, factor in self.factors)
        for version, _ in frozen:
            _text(version, "adjustment version")
        if len({x[0] for x in frozen}) != len(frozen):
            raise ValueError("duplicate or empty adjustment version")
        object.__setattr__(self, "factors", tuple(sorted(frozen)))


@dataclass(frozen=True, slots=True)
class CorporateEventRevisionV1(_NoReconstructionV1):
    """One append-only vendor observation, with a stable canonical event ID."""

    event_id: str
    issuer_id: str
    ticker: str
    event_type: str
    state: EventState
    source: str
    native_id: str | None
    vendor_revision: int
    event_start_ns: int
    event_end_ns: int
    precision: EventPrecision
    session: EventSession
    exchange_tz: str
    published_ns: int
    received_ns: int
    available_ns: int
    fiscal_year: int | None = None
    fiscal_quarter: int | None = None
    related_tickers: tuple[str, ...] = ()
    correction_of_revision: int | None = None
    identity_mapping_version: str | None = None
    feed_state: FeedState = "SYNTHETIC"

    def __post_init__(self) -> None:
        _integers(self, ("vendor_revision", "event_start_ns", "event_end_ns",
                         "published_ns", "received_ns", "available_ns", "fiscal_year",
                         "fiscal_quarter", "correction_of_revision"),
                  optional=("fiscal_year", "fiscal_quarter", "correction_of_revision"))
        object.__setattr__(self, "related_tickers", _strings(self.related_tickers,
                                                               "related_tickers"))
        for name in ("event_id", "issuer_id", "ticker", "event_type", "source",
                     "exchange_tz"):
            _text(getattr(self, name), name)
        for name in ("native_id", "identity_mapping_version"):
            _text(getattr(self, name), name, optional=True)
        if self.vendor_revision < 1 or self.event_start_ns > self.event_end_ns:
            raise ValueError("invalid revision or event time range")
        if self.precision == "exact" and self.event_start_ns != self.event_end_ns:
            raise ValueError("exact event time must be a single instant")
        if self.precision != "exact" and self.event_start_ns == self.event_end_ns:
            raise ValueError("uncertain event time must be a range")
        if self.available_ns < max(self.published_ns, self.received_ns):
            raise ValueError("availability precedes publication or receipt")
        if self.correction_of_revision is not None and not (
            0 < self.correction_of_revision < self.vendor_revision
        ):
            raise ValueError("correction must name an earlier revision")
        if self.fiscal_quarter is not None and self.fiscal_quarter not in (1, 2, 3, 4):
            raise ValueError("fiscal quarter must be 1..4")
        if self.state not in ("scheduled", "confirmed", "revised", "delayed", "canceled",
                              "completed"):
            raise ValueError("unknown event state")
        if self.precision not in ("exact", "session", "date") or self.session not in (
            "pre", "regular", "post", "unknown"
        ):
            raise ValueError("unknown event time precision or session")
        if self.feed_state not in ("SYNTHETIC", "ENTITLED", "UNVERIFIED", "UNENTITLED"):
            raise ValueError("unknown event feed state")


@dataclass(frozen=True, slots=True)
class ExchangeSessionV1(_NoReconstructionV1):
    session_date: date
    open_ns: int
    close_ns: int

    def __post_init__(self) -> None:
        _integers(self, ("open_ns", "close_ns"))
        if not isinstance(self.session_date, date):
            raise ValueError("session date must be a date")
        if self.open_ns >= self.close_ns:
            raise ValueError("session open must precede close")


@dataclass(frozen=True, slots=True)
class EventMarketEvidenceV1(_NoReconstructionV1):
    """A versioned numeric observation; adjusted closes are already split-adjusted."""

    kind: EvidenceKind
    ticker: str
    observed_ns: int
    published_ns: int
    received_ns: int
    available_ns: int
    value: Decimal
    source: str
    native_id: str
    revision: int = 1
    correction_of_revision: int | None = None
    adjustment_version: str | None = None
    feed_state: FeedState = "SYNTHETIC"
    dataset: str = "default"
    schema_version: str = "1"
    option_expiry_ns: int | None = None
    strike: Decimal | None = None
    call_bid: Decimal | None = None
    call_ask: Decimal | None = None
    put_bid: Decimal | None = None
    put_ask: Decimal | None = None

    def __post_init__(self) -> None:
        _integers(self, ("observed_ns", "published_ns", "received_ns", "available_ns",
                         "revision", "correction_of_revision", "option_expiry_ns"),
                  optional=("correction_of_revision", "option_expiry_ns"))
        for name in ("ticker", "source", "native_id", "dataset", "schema_version"):
            _text(getattr(self, name), name)
        _text(self.adjustment_version, "adjustment_version", optional=True)
        if self.option_expiry_ns is not None and self.option_expiry_ns <= 0:
            raise ValueError("option expiry must be a positive UTC nanosecond instant")
        if self.revision < 1 or self.available_ns < max(self.published_ns, self.received_ns):
            raise ValueError("invalid evidence revision or availability")
        if self.kind not in ("spot", "adjusted_close", "iv30d", "straddle"):
            raise ValueError("unknown market evidence kind")
        object.__setattr__(self, "value", canonical_decimal(self.value, "market value"))
        for name in ("strike", "call_bid", "call_ask", "put_bid", "put_ask"):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, canonical_decimal(
                    value, name, allow_zero=name != "strike"
                ))
        if (self.call_bid is not None and self.call_ask is not None
                and self.call_bid > self.call_ask):
            raise ValueError("crossed call quote")
        if (self.put_bid is not None and self.put_ask is not None
                and self.put_bid > self.put_ask):
            raise ValueError("crossed put quote")
        if self.correction_of_revision is not None and not (
            0 < self.correction_of_revision < self.revision
        ):
            raise ValueError("correction must name an earlier revision")
        if self.feed_state not in ("SYNTHETIC", "ENTITLED", "UNVERIFIED", "UNENTITLED"):
            raise ValueError("unknown market feed state")


@dataclass(frozen=True, slots=True)
class EventMetricPolicyV1(_NoReconstructionV1):
    version: str = "evt-v1"
    lookback_trading_days: int = 252
    min_iv_samples: int = 20
    max_evidence_age_ns: int = 60_000_000_000
    expected_method: Literal["straddle", "iv"] = "straddle"
    day_count_basis: int = 365
    expected_window: ExpectedMoveWindowV1 | None = None
    source_priority: tuple[str, ...] = ()
    atm_tolerance_relative: Decimal = Decimal("0.05")
    overlay_baseline_days: int = 20
    min_overlay_samples: int = 10
    overlay_z_threshold: Decimal = Decimal(2)
    flow_window_before_days: int = 3
    flow_window_after_days: int = 1
    dp_window_before_days: int = 5
    dp_window_after_days: int = 1

    def __post_init__(self) -> None:
        _integers(self, ("lookback_trading_days", "min_iv_samples", "max_evidence_age_ns",
                         "day_count_basis", "overlay_baseline_days", "min_overlay_samples",
                         "flow_window_before_days", "flow_window_after_days",
                         "dp_window_before_days", "dp_window_after_days"))
        _text(self.version, "policy version")
        if self.expected_window is not None and not isinstance(
            self.expected_window, ExpectedMoveWindowV1
        ):
            raise ValueError("expected window must be typed")
        object.__setattr__(self, "source_priority", _strings(self.source_priority,
                                                              "source_priority"))
        if not (1 <= self.min_iv_samples <= self.lookback_trading_days):
            raise ValueError("invalid IV sample policy")
        if not (1 <= self.min_overlay_samples <= self.overlay_baseline_days):
            raise ValueError("invalid overlay baseline policy")
        if self.max_evidence_age_ns <= 0 or self.day_count_basis <= 0:
            raise ValueError("age and day-count basis must be positive")
        if self.expected_method not in ("straddle", "iv"):
            raise ValueError("unknown expected move method")
        object.__setattr__(self, "overlay_z_threshold", canonical_decimal(
            self.overlay_z_threshold, "overlay threshold", allow_zero=True
        ))
        object.__setattr__(self, "atm_tolerance_relative", canonical_decimal(
            self.atm_tolerance_relative, "ATM tolerance", allow_zero=True
        ))
        if min(self.flow_window_before_days, self.flow_window_after_days,
               self.dp_window_before_days, self.dp_window_after_days) < 0:
            raise ValueError("overlay window bounds must be nonnegative")


@dataclass(frozen=True, slots=True)
class FlowOverlayEvidenceV1(_NoReconstructionV1):
    """Typed fixture port for FLOW-001; only reviewed adapters may populate it later."""

    ticker: str
    observed_ns: int
    published_ns: int
    received_ns: int
    available_ns: int
    metric_value: Decimal
    source: str
    native_id: str
    revision: int = 1
    source_contract: Literal["FLOW-001"] = "FLOW-001"
    feed_state: FeedState = "SYNTHETIC"
    dataset: str = "default"
    schema_version: str = "1"
    metric_name: Literal["notional", "options_volume"] = "notional"
    metric_unit: Literal["currency", "contracts"] = "currency"
    series_id: str = "default"

    def __post_init__(self) -> None:
        _validate_overlay_evidence(self)
        if self.source_contract != "FLOW-001":
            raise ValueError("flow evidence must identify FLOW-001")
        if self.metric_name not in ("notional", "options_volume") or self.metric_unit not in (
            "currency", "contracts"
        ):
            raise ValueError("invalid flow metric identity")


@dataclass(frozen=True, slots=True)
class DpOverlayEvidenceV1(_NoReconstructionV1):
    """Typed fixture port for DP-001; aggregate-only context is not a print."""

    ticker: str
    observed_ns: int
    published_ns: int
    received_ns: int
    available_ns: int
    metric_value: Decimal
    source: str
    native_id: str
    revision: int = 1
    source_contract: Literal["DP-001"] = "DP-001"
    price_band_low: Decimal | None = None
    price_band_high: Decimal | None = None
    feed_state: FeedState = "SYNTHETIC"
    dataset: str = "default"
    schema_version: str = "1"
    metric_name: Literal["cluster_notional", "print_volume"] = "cluster_notional"
    metric_unit: Literal["currency", "shares"] = "currency"
    series_id: str = "default"

    def __post_init__(self) -> None:
        _validate_overlay_evidence(self)
        if self.source_contract != "DP-001":
            raise ValueError("DP evidence must identify DP-001")
        if self.metric_name not in ("cluster_notional", "print_volume") or self.metric_unit not in (
            "currency", "shares"
        ):
            raise ValueError("invalid DP metric identity")
        if self.price_band_low is not None:
            object.__setattr__(self, "price_band_low", canonical_decimal(
                self.price_band_low, "price band low"
            ))
        if self.price_band_high is not None:
            object.__setattr__(self, "price_band_high", canonical_decimal(
                self.price_band_high, "price band high"
            ))
        if ((self.price_band_low is None) != (self.price_band_high is None)) or (
            self.price_band_low is not None and self.price_band_high is not None
            and self.price_band_low > self.price_band_high
        ):
            raise ValueError("invalid DP price band")


def _validate_overlay_evidence(item: FlowOverlayEvidenceV1 | DpOverlayEvidenceV1) -> None:
    _integers(item, ("observed_ns", "published_ns", "received_ns", "available_ns",
                     "revision"))
    for name in ("ticker", "source", "native_id", "dataset", "schema_version",
                 "series_id"):
        _text(getattr(item, name), name)
    if item.available_ns < max(item.published_ns, item.received_ns) or item.revision < 1:
        raise ValueError("invalid overlay availability or revision")
    object.__setattr__(item, "metric_value", canonical_decimal(
        item.metric_value, "overlay metric", allow_zero=True
    ))
    if item.feed_state not in ("SYNTHETIC", "ENTITLED", "UNVERIFIED", "UNENTITLED"):
        raise ValueError("unknown overlay feed state")


@dataclass(frozen=True, slots=True)
class EventSnapshotV1(_NoReconstructionV1):
    phase: Literal["pre", "post"]
    session_date: date
    close_ns: int
    iv_rank: Decimal | None
    iv_sample_count: int
    iv_value: Decimal | None
    adjusted_close: Decimal | None
    status: MetricStatus
    reasons: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    available_ns: int | None = None

    def __post_init__(self) -> None:
        _integers(self, ("close_ns", "iv_sample_count", "available_ns"),
                  optional=("available_ns",))
        if not isinstance(self.session_date, date):
            raise ValueError("snapshot session date must be a date")
        _decimal_fields(self, ("iv_rank", "iv_value", "adjusted_close"),
                        optional=("iv_rank", "iv_value", "adjusted_close"),
                        zero=("iv_rank",))
        if self.phase not in ("pre", "post") or self.status not in (
            "OK", "PARTIAL", "MISSING", "STALE", "QUARANTINED", "CANCELED"
        ):
            raise ValueError("invalid snapshot phase or status")
        object.__setattr__(self, "reasons", _strings(self.reasons, "snapshot reasons",
                                                     unique=False))
        object.__setattr__(self, "evidence_ids", _strings(self.evidence_ids,
                                                         "snapshot evidence IDs",
                                                         unique=False))


@dataclass(frozen=True, slots=True)
class EventOverlayV1(_NoReconstructionV1):
    kind: Literal["flow", "dp"]
    observed_ns: int
    z_score: Decimal | None
    threshold_crossed: bool
    baseline_count: int
    status: MetricStatus
    reason: str | None
    source_id: str
    policy_version: str
    metric_value: Decimal
    available_ns: int
    price_band_low: Decimal | None = None
    price_band_high: Decimal | None = None

    def __post_init__(self) -> None:
        _integers(self, ("observed_ns", "baseline_count", "available_ns"))
        _decimal_fields(self, ("z_score", "metric_value", "price_band_low",
                               "price_band_high"),
                        optional=("z_score", "price_band_low", "price_band_high"),
                        signed=("z_score",), zero=("z_score", "metric_value"))
        if type(self.threshold_crossed) is not bool:
            raise ValueError("INVALID_BOOLEAN:threshold_crossed")
        for name in ("source_id", "policy_version"):
            _text(getattr(self, name), name)
        _text(self.reason, "overlay reason", optional=True)
        if self.kind not in ("flow", "dp") or self.status not in (
            "OK", "PARTIAL", "MISSING", "STALE", "QUARANTINED", "CANCELED"
        ):
            raise ValueError("invalid overlay kind or status")


@dataclass(frozen=True, slots=True)
class AlertCandidateV1(_NoReconstructionV1):
    key: str
    kind: str
    due_ns: int
    event_id: str
    scheduled_ns: int
    available_ns: int

    def __post_init__(self) -> None:
        _integers(self, ("due_ns", "scheduled_ns", "available_ns"))
        for name in ("key", "kind", "event_id"):
            _text(getattr(self, name), name)
        if self.due_ns != max(self.scheduled_ns, self.available_ns):
            raise ValueError("alert due time precedes required availability")


@dataclass(frozen=True, slots=True)
class EventMetricsV1(_NoReconstructionV1):
    event_id: str | None
    vendor_revision: int | None
    asof_ns: int
    policy_version: str
    result_version: str
    status: MetricStatus
    reasons: tuple[str, ...]
    revision: CorporateEventRevisionV1 | None
    pre: EventSnapshotV1 | None
    post: EventSnapshotV1 | None
    expected_method: str | None
    expected_window: ExpectedMoveWindowV1 | None
    realized_window: ExpectedMoveWindowV1 | None
    days_to_window: Decimal | None
    day_count_basis: int | None
    iv_tenor_days: int | None
    expected_abs_move_relative: Decimal | None
    expected_abs_move_currency: Decimal | None
    realized_abs_log_move: Decimal | None
    signed_simple_percent: Decimal | None
    signed_dollar_move: Decimal | None
    surprise: Decimal | None
    surprise_unit: str | None
    surprise_method_id: str | None
    surprise_reason: str | None
    overlays: tuple[EventOverlayV1, ...]
    alert_candidates: tuple[AlertCandidateV1, ...]
    event_start_exchange_local: str | None
    event_end_exchange_local: str | None
    event_start_requested_local: str | None
    event_end_requested_local: str | None
    _issuer: InitVar[object | None] = field(default=None, kw_only=True)
    _seal: _ResultSeal = field(init=False, repr=False, compare=False)

    def __post_init__(self, _issuer: object | None) -> None:
        self._validate_fields()
        if _issuer is not _ISSUER:
            raise SealedResultError()
        object.__setattr__(self, "_seal", _ResultSeal(_result_content_hash(self)))

    @property
    def content_hash(self) -> str:
        return self._seal.content_hash

    def _validate_fields(self) -> None:
        _integers(self, ("vendor_revision", "asof_ns", "day_count_basis",
                         "iv_tenor_days"),
                  optional=("vendor_revision", "day_count_basis", "iv_tenor_days"))
        _decimal_fields(self, ("days_to_window", "expected_abs_move_relative",
                               "expected_abs_move_currency", "realized_abs_log_move",
                               "signed_simple_percent", "signed_dollar_move", "surprise"),
                        optional=("days_to_window", "expected_abs_move_relative",
                                  "expected_abs_move_currency", "realized_abs_log_move",
                                  "signed_simple_percent", "signed_dollar_move", "surprise"),
                        signed=("signed_simple_percent", "signed_dollar_move", "surprise"),
                        zero=("realized_abs_log_move", "signed_simple_percent",
                              "signed_dollar_move", "surprise"))
        for name, model in (("revision", CorporateEventRevisionV1),
                            ("pre", EventSnapshotV1), ("post", EventSnapshotV1),
                            ("expected_window", ExpectedMoveWindowV1),
                            ("realized_window", ExpectedMoveWindowV1)):
            value = getattr(self, name)
            if value is not None and not isinstance(value, model):
                raise ValueError(f"{name} must be a typed record")
        _text(self.event_id, "event_id", optional=True)
        for name in ("policy_version", "result_version"):
            _text(getattr(self, name), name)
        for name in ("expected_method", "surprise_unit", "surprise_method_id",
                     "surprise_reason", "event_start_exchange_local",
                     "event_end_exchange_local", "event_start_requested_local",
                     "event_end_requested_local"):
            _text(getattr(self, name), name, optional=True)
        if self.status not in ("OK", "PARTIAL", "MISSING", "STALE", "QUARANTINED",
                               "CANCELED", "UNAVAILABLE"):
            raise ValueError("invalid metric status")
        object.__setattr__(self, "reasons", _strings(self.reasons, "metric reasons"))
        object.__setattr__(self, "overlays", tuple(self.overlays))
        object.__setattr__(self, "alert_candidates", tuple(self.alert_candidates))
        if any(not isinstance(item, EventOverlayV1) for item in self.overlays):
            raise ValueError("metric overlays must be typed")
        if any(not isinstance(item, AlertCandidateV1) for item in self.alert_candidates):
            raise ValueError("metric alerts must be typed")


def _result_content_hash(result: EventMetricsV1) -> str:
    """Bind every public field, including result_version, to the issued seal."""
    content = tuple((item.name, getattr(result, item.name))
                    for item in fields(EventMetricsV1) if item.name != "_seal")
    return sha256(repr(content).encode("utf-8")).hexdigest()


def _issue_event_metrics(**values: object) -> EventMetricsV1:
    """Private trusted constructor used only after the kernel computes a result."""
    names = {item.name for item in fields(EventMetricsV1) if item.name != "_seal"}
    if values.keys() != names:
        raise ValueError("incomplete event metrics result")
    return EventMetricsV1(**values, _issuer=_ISSUER)  # type: ignore[arg-type]
