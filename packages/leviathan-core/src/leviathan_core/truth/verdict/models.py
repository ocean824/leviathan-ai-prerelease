"""Immutable v1 truth evidence contracts; no route authority or I/O."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from enum import StrEnum
from types import MappingProxyType
from typing import Never, SupportsIndex


class InvalidTruthInputError(ValueError):
    """Invalid request, policy, or evidence snapshot."""

    code = "INVALID_TRUTH_INPUT"


class ClockSkewError(InvalidTruthInputError):
    """Client timestamp exceeds the versioned policy's skew bound."""

    code = "CLOCK_SKEW"


class PrecisionExceededError(InvalidTruthInputError):
    """A numeric input exceeds the exact 34-digit kernel precision."""

    code = "PRECISION_EXCEEDED"


class PolicyOutOfBoundsError(InvalidTruthInputError):
    """A policy violates a source-governed bound or evidence floor."""

    code = "POLICY_OUT_OF_BOUNDS"


class EvidenceStateError(InvalidTruthInputError):
    """Evidence state, timestamp and payload are inconsistent."""

    code = "EVIDENCE_STATE_INCONSISTENT"


class _NoCopy:
    def __copy__(self) -> None:
        raise InvalidTruthInputError("truth kernel objects cannot be copied")

    def __deepcopy__(self, memo: dict[int, object]) -> None:
        raise InvalidTruthInputError("truth kernel objects cannot be copied")

    def __reduce__(self) -> Never:
        raise InvalidTruthInputError("truth kernel objects cannot be serialized")

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        raise InvalidTruthInputError("truth kernel objects cannot be serialized")


class Verdict(StrEnum):
    PASS = "PASS"
    SOFT_FAIL = "SOFT_FAIL"
    HARD_FAIL = "HARD_FAIL"
    UNKNOWN = "UNKNOWN"


class TruthSource(StrEnum):
    ORDER_BOOK = "ORDER_BOOK"
    OPTIONS_FLOW = "OPTIONS_FLOW"
    EVENTS = "EVENTS"
    SENTIMENT = "SENTIMENT"


class InstrumentClass(StrEnum):
    EQUITY = "equity"
    FUTURE = "future"
    FX = "fx"
    CRYPTO = "crypto"
    OPTION = "option"
    OTHER = "other"


class SourceState(StrEnum):
    AVAILABLE = "AVAILABLE"
    MISSING = "MISSING"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class Side(StrEnum):
    BUY = "BUY"
    SELL = "SELL"


class Action(StrEnum):
    ENTER = "ENTER"
    EXIT = "EXIT"
    AMEND = "AMEND"
    CANCEL = "CANCEL"


class ReasonCode(StrEnum):
    CROSSED_MARKET = "CROSSED_MARKET"
    DEGRADE_AUTHORIZED = "DEGRADE_AUTHORIZED"
    DEPTH_BREACH = "DEPTH_BREACH"
    EVENTS_MISSING = "EVENTS_MISSING"
    EVENTS_STALE = "EVENTS_STALE"
    EVENT_EMBARGO = "EVENT_EMBARGO"
    EXIT_DURING_EMBARGO = "EXIT_DURING_EMBARGO"
    FLOW_CONTRADICT = "FLOW_CONTRADICT"
    FLOW_WEAK = "FLOW_WEAK"
    HALT_ACTIVE = "HALT_ACTIVE"
    IMBALANCE_BREACH = "IMBALANCE_BREACH"
    INSUFFICIENT_USABLE_EVIDENCE = "INSUFFICIENT_USABLE_EVIDENCE"
    LOCKED_MARKET = "LOCKED_MARKET"
    LULD_ACTIVE = "LULD_ACTIVE"
    NO_APPLICABLE_EVIDENCE = "NO_APPLICABLE_EVIDENCE"
    NO_USABLE_EVIDENCE = "NO_USABLE_EVIDENCE"
    OPTIONS_MISSING = "OPTIONS_MISSING"
    OPTIONS_STALE = "OPTIONS_STALE"
    ORDERBOOK_MISSING = "ORDERBOOK_MISSING"
    ORDERBOOK_STALE = "ORDERBOOK_STALE"
    POLICY_MISSING = "POLICY_MISSING"
    SENTIMENT_BREACH = "SENTIMENT_BREACH"
    SENTIMENT_MISSING = "SENTIMENT_MISSING"
    SENTIMENT_STALE = "SENTIMENT_STALE"
    SLIPPAGE_BREACH = "SLIPPAGE_BREACH"
    SPREAD_BREACH = "SPREAD_BREACH"


def _finite(value: Decimal | int | float | str, label: str) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (Decimal, int, float, str)):
        raise InvalidTruthInputError(f"{label} must be finite numeric data")
    if isinstance(value, Decimal):
        result = value
    else:
        if isinstance(value, int) and value.bit_length() > 130:
            raise PrecisionExceededError(f"{label} exceeds kernel numeric bounds")
        if isinstance(value, str) and len(value) > 128:
            raise PrecisionExceededError(f"{label} exceeds kernel numeric bounds")
        if isinstance(value, str) and not re.fullmatch(
            r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?", value
        ):
            raise InvalidTruthInputError(f"{label} must be finite numeric data")
        try:
            result = Decimal(str(value))
        except (InvalidOperation, ValueError):
            raise InvalidTruthInputError(f"{label} must be finite numeric data") from None
    if not result.is_finite():
        raise InvalidTruthInputError(f"{label} must be finite numeric data")
    digits = result.as_tuple().digits
    significant = len(digits)
    while significant > 1 and digits[significant - 1] == 0:
        significant -= 1
    if significant > 34 or abs(result.adjusted()) > 38:
        raise PrecisionExceededError(f"{label} exceeds kernel numeric bounds")
    return result


def _utc(value: datetime, label: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise InvalidTruthInputError(f"{label} must be timezone-aware")
    try:
        if value.utcoffset() is None:
            raise InvalidTruthInputError(f"{label} must be timezone-aware")
        return value.astimezone(UTC)
    except (OverflowError, ValueError, TypeError):
        raise InvalidTruthInputError(f"{label} must be valid timezone-aware data") from None


def _nonempty(value: str, label: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise InvalidTruthInputError(f"{label} must be nonempty")


@dataclass(frozen=True, slots=True)
class TruthRequestV1(_NoCopy):
    request_id: str
    instrument_id: str
    asset_class: str
    side: Side
    action: Action
    quantity: Decimal
    strategy_id: str
    account_id: str
    venue: str
    client_timestamp: datetime
    risk_profile: str = "normal"

    def __post_init__(self) -> None:
        for label in (
            "request_id",
            "instrument_id",
            "asset_class",
            "strategy_id",
            "account_id",
            "venue",
            "risk_profile",
        ):
            _nonempty(getattr(self, label), label)
        if not isinstance(self.side, Side) or not isinstance(self.action, Action):
            raise InvalidTruthInputError("side and action must use the closed enums")
        quantity = _finite(self.quantity, "quantity")
        if quantity <= 0:
            raise InvalidTruthInputError("quantity must be positive")
        object.__setattr__(self, "quantity", quantity)
        object.__setattr__(
            self, "client_timestamp", _utc(self.client_timestamp, "client_timestamp")
        )


@dataclass(frozen=True, slots=True)
class TruthPolicyV1(_NoCopy):
    policy_id: str
    version: str
    max_clock_skew_ms: int = 1000
    max_spread_bps: Decimal = Decimal("10")
    min_depth_qty: Decimal = Decimal("1")
    min_imbalance: Decimal = Decimal("0")
    max_slippage_bps: Decimal = Decimal("10")
    min_flow_score: Decimal = Decimal("0")
    flow_contradiction_gap: Decimal = Decimal("0.5")
    min_uvr: Decimal = Decimal("0")
    min_sentiment: Decimal = Decimal("-0.25")
    max_sentiment: Decimal = Decimal("0.25")
    on_sentiment_breach: Verdict = Verdict.SOFT_FAIL
    exit_override: bool = False
    allow_degrade: bool = False
    required_sources: frozenset[TruthSource] = field(default_factory=lambda: frozenset(TruthSource))
    min_usable_sources: int = 1
    instrument_classes: Mapping[str, InstrumentClass] = field(default_factory=dict)
    applicable_sources_by_class: Mapping[InstrumentClass, frozenset[TruthSource]] = field(
        default_factory=dict
    )
    orderbook_max_age_ms: int = 50
    options_max_age_ms: int = 5000
    events_max_age_ms: int = 1000
    sentiment_max_age_ms: int = 30000

    def __post_init__(self) -> None:
        _nonempty(self.policy_id, "policy_id")
        _nonempty(self.version, "version")
        for label in (
            "max_clock_skew_ms",
            "orderbook_max_age_ms",
            "options_max_age_ms",
            "events_max_age_ms",
            "sentiment_max_age_ms",
        ):
            value = getattr(self, label)
            if isinstance(value, bool) or not isinstance(value, int):
                raise InvalidTruthInputError(f"{label} must be an integer")
            if value < 0:
                raise PolicyOutOfBoundsError(f"{label} must be nonnegative")
        for label, bound in (
            ("orderbook_max_age_ms", 50),
            ("options_max_age_ms", 5000),
            ("events_max_age_ms", 1000),
            ("sentiment_max_age_ms", 30000),
        ):
            if getattr(self, label) > bound:
                raise PolicyOutOfBoundsError(f"{label} exceeds the governed bound")
        if type(self.exit_override) is not bool or type(self.allow_degrade) is not bool:
            raise InvalidTruthInputError("policy flags must be booleans")
        for label in (
            "max_spread_bps",
            "min_depth_qty",
            "min_imbalance",
            "max_slippage_bps",
            "min_flow_score",
            "flow_contradiction_gap",
            "min_uvr",
            "min_sentiment",
            "max_sentiment",
        ):
            object.__setattr__(self, label, _finite(getattr(self, label), label))
        for label in (
            "max_spread_bps",
            "min_depth_qty",
            "min_imbalance",
            "max_slippage_bps",
            "min_flow_score",
            "flow_contradiction_gap",
            "min_uvr",
        ):
            if getattr(self, label) < 0:
                raise PolicyOutOfBoundsError(f"{label} must be nonnegative")
        if self.min_imbalance > 1 or self.min_sentiment > self.max_sentiment:
            raise PolicyOutOfBoundsError("invalid policy bounds")
        if not isinstance(self.on_sentiment_breach, Verdict) or self.on_sentiment_breach not in (
            Verdict.SOFT_FAIL,
            Verdict.HARD_FAIL,
        ):
            raise InvalidTruthInputError("on_sentiment_breach must be SOFT_FAIL or HARD_FAIL")
        if type(self.min_usable_sources) is not int:
            raise InvalidTruthInputError("min_usable_sources must be an integer")
        if not 1 <= self.min_usable_sources <= len(TruthSource):
            raise PolicyOutOfBoundsError("min_usable_sources exceeds the governed bounds")
        try:
            sources = frozenset(self.required_sources)
        except TypeError:
            raise InvalidTruthInputError("required_sources must be a source collection") from None
        if not all(isinstance(source, TruthSource) for source in sources):
            raise InvalidTruthInputError("required_sources must contain TruthSource values")
        if not sources:
            raise PolicyOutOfBoundsError("required_sources must be nonempty")
        object.__setattr__(self, "required_sources", sources)
        if not isinstance(self.instrument_classes, Mapping) or not isinstance(
            self.applicable_sources_by_class, Mapping
        ):
            raise InvalidTruthInputError("policy applicability must be mappings")
        classes: dict[str, InstrumentClass] = {}
        for instrument_id, instrument_class in self.instrument_classes.items():
            _nonempty(instrument_id, "instrument_id")
            if not isinstance(instrument_class, InstrumentClass):
                raise InvalidTruthInputError("policy instrument class must use the closed enum")
            classes[instrument_id] = instrument_class
        applicable: dict[InstrumentClass, frozenset[TruthSource]] = {}
        for instrument_class, source_values in self.applicable_sources_by_class.items():
            if not isinstance(instrument_class, InstrumentClass):
                raise InvalidTruthInputError("applicability class must use the closed enum")
            try:
                source_set = frozenset(source_values)
            except TypeError:
                raise InvalidTruthInputError("applicability sources must be a collection") from None
            if not all(isinstance(source, TruthSource) for source in source_set):
                raise InvalidTruthInputError("applicability sources must use TruthSource")
            applicable[instrument_class] = source_set
        object.__setattr__(self, "instrument_classes", MappingProxyType(classes))
        object.__setattr__(self, "applicable_sources_by_class", MappingProxyType(applicable))


@dataclass(frozen=True, slots=True)
class OrderBookMetricsV1(_NoCopy):
    spread_bps: Decimal
    depth_near_qty: Decimal
    depth_far_qty: Decimal
    imbalance: Decimal
    est_slippage_bps: Decimal
    crossed: bool = False
    locked: bool = False
    halt_active: bool = False
    luld_active: bool = False

    def __post_init__(self) -> None:
        for label in (
            "spread_bps",
            "depth_near_qty",
            "depth_far_qty",
            "imbalance",
            "est_slippage_bps",
        ):
            object.__setattr__(self, label, _finite(getattr(self, label), label))
        if self.depth_near_qty < 0 or self.depth_far_qty < 0 or self.est_slippage_bps < 0:
            raise InvalidTruthInputError("depth and slippage must be nonnegative")
        if not -1 <= self.imbalance <= 1:
            raise InvalidTruthInputError("imbalance must be in [-1, 1]")
        if any(
            type(getattr(self, label)) is not bool
            for label in ("crossed", "locked", "halt_active", "luld_active")
        ):
            raise InvalidTruthInputError("order book flags must be booleans")


@dataclass(frozen=True, slots=True)
class OptionsFlowMetricsV1(_NoCopy):
    flow_score: Decimal
    unusual_volume_ratio: Decimal
    directional: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "flow_score", _finite(self.flow_score, "flow_score"))
        object.__setattr__(
            self, "unusual_volume_ratio", _finite(self.unusual_volume_ratio, "unusual_volume_ratio")
        )
        if self.unusual_volume_ratio < 0:
            raise InvalidTruthInputError("unusual_volume_ratio must be nonnegative")
        if type(self.directional) is not bool:
            raise InvalidTruthInputError("directional must be boolean")


@dataclass(frozen=True, slots=True)
class EventMetricsV1(_NoCopy):
    embargo_active: bool = False

    def __post_init__(self) -> None:
        if type(self.embargo_active) is not bool:
            raise InvalidTruthInputError("embargo_active must be boolean")


@dataclass(frozen=True, slots=True)
class SentimentMetricsV1(_NoCopy):
    score: Decimal
    confidence: Decimal

    def __post_init__(self) -> None:
        object.__setattr__(self, "score", _finite(self.score, "score"))
        object.__setattr__(self, "confidence", _finite(self.confidence, "confidence"))
        if not 0 <= self.confidence <= 1:
            raise InvalidTruthInputError("confidence must be in [0, 1]")


@dataclass(frozen=True, slots=True)
class TruthEvidenceV1(_NoCopy):
    source: TruthSource
    source_id: str
    state: SourceState
    observed_at: datetime | None = None
    order_book: OrderBookMetricsV1 | None = None
    options_flow: OptionsFlowMetricsV1 | None = None
    events: EventMetricsV1 | None = None
    sentiment: SentimentMetricsV1 | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.source, TruthSource) or not isinstance(self.state, SourceState):
            raise InvalidTruthInputError("source and state must use the closed enums")
        _nonempty(self.source_id, "source_id")
        for label, expected in (
            ("order_book", OrderBookMetricsV1),
            ("options_flow", OptionsFlowMetricsV1),
            ("events", EventMetricsV1),
            ("sentiment", SentimentMetricsV1),
        ):
            value = getattr(self, label)
            if value is not None and not isinstance(value, expected):
                raise EvidenceStateError("evidence payload has the wrong type")
        payloads = {
            TruthSource.ORDER_BOOK: self.order_book,
            TruthSource.OPTIONS_FLOW: self.options_flow,
            TruthSource.EVENTS: self.events,
            TruthSource.SENTIMENT: self.sentiment,
        }
        populated = sum(value is not None for value in payloads.values())
        if self.state is SourceState.AVAILABLE:
            if self.observed_at is None or populated != 1 or payloads[self.source] is None:
                raise EvidenceStateError(
                    "AVAILABLE evidence needs its timestamp and matching payload"
                )
            object.__setattr__(self, "observed_at", _utc(self.observed_at, "observed_at"))
        elif self.observed_at is not None or populated:
            raise EvidenceStateError("MISSING/NOT_APPLICABLE evidence has no timestamp or payload")


@dataclass(frozen=True, slots=True)
class TruthVerdictV1(_NoCopy):
    verdict: Verdict
    reason_codes: tuple[ReasonCode, ...]
    data_freshness_ms: Mapping[TruthSource, int | None]
    source_timestamps: Mapping[TruthSource, datetime | None]
    evaluation_ts: datetime
    policy_id: str | None
    policy_version: str | None
    trace_id: str
    hash_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.verdict, Verdict):
            raise InvalidTruthInputError("verdict must use the closed enum")
        if not isinstance(self.reason_codes, tuple) or not all(
            isinstance(code, ReasonCode) for code in self.reason_codes
        ):
            raise InvalidTruthInputError("reason_codes must use the closed enum")
        if tuple(sorted(set(self.reason_codes), key=lambda code: code.value)) != self.reason_codes:
            raise InvalidTruthInputError("reason_codes must be unique and sorted")
        object.__setattr__(self, "evaluation_ts", _utc(self.evaluation_ts, "evaluation_ts"))
        if not isinstance(self.data_freshness_ms, Mapping) or not isinstance(
            self.source_timestamps, Mapping
        ):
            raise InvalidTruthInputError("source maps must be mappings")
        if not all(isinstance(source, TruthSource) for source in self.data_freshness_ms) or not all(
            isinstance(source, TruthSource) for source in self.source_timestamps
        ):
            raise InvalidTruthInputError("source maps must use TruthSource keys")
        if set(self.data_freshness_ms) != set(TruthSource) or set(self.source_timestamps) != set(
            TruthSource
        ):
            raise InvalidTruthInputError("source maps must cover every source")
        normalized_timestamps: dict[TruthSource, datetime | None] = {}
        for source in TruthSource:
            age = self.data_freshness_ms[source]
            timestamp = self.source_timestamps[source]
            if age is not None and (type(age) is not int or age < 0):
                raise InvalidTruthInputError("source freshness must be nonnegative integer")
            normalized_timestamps[source] = (
                _utc(timestamp, "source timestamp") if timestamp is not None else None
            )
            if (age is None) != (timestamp is None):
                raise InvalidTruthInputError("source freshness and timestamp disagree")
        object.__setattr__(
            self, "data_freshness_ms", MappingProxyType(dict(self.data_freshness_ms))
        )
        object.__setattr__(self, "source_timestamps", MappingProxyType(normalized_timestamps))
        if (self.policy_id is None) != (self.policy_version is None):
            raise InvalidTruthInputError("policy identity must include both ID and version")
        if self.policy_id is not None:
            _nonempty(self.policy_id, "policy_id")
            assert self.policy_version is not None
            _nonempty(self.policy_version, "policy_version")
        _nonempty(self.trace_id, "trace_id")
        _nonempty(self.hash_id, "hash_id")
