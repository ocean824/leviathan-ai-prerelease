"""Closed, in-memory metrics catalog for bounded telemetry fakes."""

from __future__ import annotations

import re
import threading
from collections import defaultdict, deque
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from enum import StrEnum
from time import monotonic_ns


class MetricKind(StrEnum):
    HISTOGRAM = "histogram"
    GAUGE = "gauge"
    COUNTER = "counter"


class MetricName(StrEnum):
    DECISION_LATENCY = "leviathan_decision_latency_seconds"
    ORDER_ACK_LATENCY = "leviathan_order_ack_latency_seconds"
    PIPELINE_LAG = "leviathan_pipeline_lag_seconds"
    STREAM_FRESHNESS_LAG = "leviathan_stream_freshness_lag_seconds"
    TIME_SYNC_OFFSET = "leviathan_time_sync_offset_seconds"
    HALT_ENGAGED = "leviathan_halt_engaged"
    ORDERS_TOTAL = "leviathan_orders_total"
    RISK_DENIALS_TOTAL = "leviathan_risk_denials_total"
    LABEL_OVERFLOW_TOTAL = "leviathan_label_overflow_total"


class MetricNameV2(StrEnum):
    """PRD-aligned metric names with explicit units and percentile series."""

    PIPELINE_INGEST_THROUGHPUT = "pipeline_ingest_throughput_msgs_per_s"
    PIPELINE_LAG = "pipeline_lag_ms"
    DECISION_LATENCY_P50 = "decision_latency_ms_p50"
    DECISION_LATENCY_P95 = "decision_latency_ms_p95"
    DECISION_LATENCY_P99 = "decision_latency_ms_p99"
    ORDER_SUBMIT_LATENCY_P50 = "order_submit_latency_ms_p50"
    ORDER_SUBMIT_LATENCY_P95 = "order_submit_latency_ms_p95"
    ORDER_SUBMIT_LATENCY_P99 = "order_submit_latency_ms_p99"
    ORDER_GATEWAY_THROUGHPUT = "order_gateway_throughput_orders_per_s"
    EXECUTION_FILLS_TOTAL = "execution_fills_total"
    EXECUTION_FILL_RATIO = "execution_fill_ratio"
    ERROR_RATE_PER_S = "error_rate_per_s"
    QUEUE_DEPTH = "queue_depth"
    CACHE_HIT_RATIO = "cache_hit_ratio"
    CONNECTOR_CONNECTIVITY_STATUS = "connector_connectivity_status"
    HEARTBEAT_SKEW_MS = "heartbeat_skew_ms"
    STREAM_FRESHNESS_LAG = "leviathan_stream_freshness_lag_seconds"
    HALT_ENGAGED = "leviathan_halt_engaged"
    RISK_DENIALS_TOTAL = "leviathan_risk_denials_total"
    LABEL_OVERFLOW_TOTAL = "leviathan_label_overflow_total"


class OrderOutcome(StrEnum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    UNKNOWN = "unknown"
    CANCELLED = "cancelled"
    FILLED = "filled"


class RiskDenialReason(StrEnum):
    HALT = "halt"
    LIMIT = "limit"
    STALE_DATA = "stale_data"
    POLICY = "policy"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class MetricDefinitionV1:
    name: MetricName
    kind: MetricKind
    unit: str
    label: str | None = None


@dataclass(frozen=True, slots=True)
class MetricDefinitionV2:
    name: MetricNameV2
    kind: MetricKind
    unit: str
    additional_labels: tuple[str, ...] = ()
    percentile: int | None = None
    is_extension: bool = False

    def __post_init__(self) -> None:
        if (
            type(self.name) is not MetricNameV2
            or type(self.kind) is not MetricKind
            or type(self.unit) is not str
            or not self.unit
            or type(self.additional_labels) is not tuple
            or any(
                type(label) is not str
                or re.fullmatch(r"[a-z][a-z0-9_]{0,31}", label, re.ASCII) is None
                for label in self.additional_labels
            )
            or len(set(self.additional_labels)) != len(self.additional_labels)
            or type(self.is_extension) is not bool
            or (
                self.percentile is not None
                and (type(self.percentile) is not int or self.percentile not in (50, 95, 99))
            )
            or (self.kind is MetricKind.HISTOGRAM) != (self.percentile is not None)
            or (
                self.percentile is not None and not self.name.value.endswith(f"_p{self.percentile}")
            )
        ):
            raise MetricError("METRIC_DEFINITION_INVALID")

    @property
    def required_labels(self) -> tuple[str, ...]:
        return (*METRIC_LABELS_V2_REQUIRED, *self.additional_labels)


METRIC_CATALOG_V1: tuple[MetricDefinitionV1, ...] = (
    MetricDefinitionV1(MetricName.DECISION_LATENCY, MetricKind.HISTOGRAM, "seconds"),
    MetricDefinitionV1(MetricName.ORDER_ACK_LATENCY, MetricKind.HISTOGRAM, "seconds"),
    MetricDefinitionV1(MetricName.PIPELINE_LAG, MetricKind.HISTOGRAM, "seconds"),
    MetricDefinitionV1(MetricName.STREAM_FRESHNESS_LAG, MetricKind.GAUGE, "seconds"),
    MetricDefinitionV1(MetricName.TIME_SYNC_OFFSET, MetricKind.GAUGE, "seconds"),
    MetricDefinitionV1(MetricName.HALT_ENGAGED, MetricKind.GAUGE, "boolean"),
    MetricDefinitionV1(MetricName.ORDERS_TOTAL, MetricKind.COUNTER, "count", "outcome"),
    MetricDefinitionV1(MetricName.RISK_DENIALS_TOTAL, MetricKind.COUNTER, "count", "reason"),
    MetricDefinitionV1(MetricName.LABEL_OVERFLOW_TOTAL, MetricKind.COUNTER, "count"),
)

_DEFINITION_BY_NAME = {definition.name: definition for definition in METRIC_CATALOG_V1}
_LABEL_VALUE = re.compile(r"[A-Za-z0-9._:-]{1,64}\Z", re.ASCII)
_CREDENTIAL = re.compile(
    r"(?i)(?:bearer\s+|(?:api[_-]?key|token|secret|password)\s*[=:])"
    r"|[A-F0-9]{32,}|[A-Za-z0-9_-]{20,}"
)
_LONG_DIGITS = re.compile(r"(?<![A-Za-z0-9])[0-9]{12,}(?![A-Za-z0-9])")
_PHONE_LIKE = re.compile(r"[0-9][0-9:.-]{5,}[0-9]\Z", re.ASCII)
_SEGMENTED_TOKEN = re.compile(
    r"(?<![A-Za-z0-9_-])(?:[A-Za-z0-9_-]{4,}\.){2}[A-Za-z0-9_-]{4,}"
    r"(?![A-Za-z0-9_-])",
    re.ASCII,
)
_REQUIRED_LABELS = ("service", "component", "env", "region", "instance")
_OPTIONAL_LABELS = ("strategy", "symbol", "venue")
_MAX_OPTIONAL_VALUES = 100
_MAX_SERIES_PER_METRIC = 1000
_MAX_SAMPLES_PER_SERIES = 1024
_MAX_DECIMAL_DIGITS = 38
_SAFE_OVERFLOW_LABELS = {
    "service": "telemetry",
    "component": "metrics",
    "env": "unknown",
    "region": "unknown",
    "instance": "unknown",
}

METRIC_LABELS_V2_REQUIRED = ("service", "component", "env", "region", "instance", "venue")
METRIC_LABELS_V2_OPTIONAL = ("strategy_id", "symbol")


def _safe_label(value: object) -> bool:
    return (
        type(value) is str
        and _LABEL_VALUE.fullmatch(value) is not None
        and _CREDENTIAL.search(value) is None
        and _LONG_DIGITS.search(value) is None
        and _SEGMENTED_TOKEN.search(value) is None
        and not (
            sum(char.isdigit() for char in value) >= 7 and _PHONE_LIKE.fullmatch(value) is not None
        )
    )


class MetricError(ValueError):
    """Content-free failure for invalid metric operations."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class MetricLabelsV2:
    service: str
    component: str
    env: str
    region: str
    instance: str
    venue: str
    strategy_id: str | None = None
    symbol: str | None = None
    error_code: str | None = None
    queue: str | None = None
    reason: RiskDenialReason | None = None

    def __post_init__(self) -> None:
        for name in METRIC_LABELS_V2_REQUIRED:
            if not _safe_label(getattr(self, name)):
                raise MetricError("METRIC_LABEL_INVALID")
        for name in (*METRIC_LABELS_V2_OPTIONAL, "error_code", "queue"):
            value = getattr(self, name)
            if value is not None and not _safe_label(value):
                raise MetricError("METRIC_LABEL_INVALID")
        if self.reason is not None and type(self.reason) is not RiskDenialReason:
            raise MetricError("METRIC_LABEL_INVALID")

    def as_dict(self) -> dict[str, str]:
        values = {name: getattr(self, name) for name in METRIC_LABELS_V2_REQUIRED}
        for name in (*METRIC_LABELS_V2_OPTIONAL, "error_code", "queue"):
            value = getattr(self, name)
            if value is not None:
                values[name] = value
        if self.reason is not None:
            values["reason"] = self.reason.value
        return values


METRIC_CATALOG_V2: tuple[MetricDefinitionV2, ...] = (
    MetricDefinitionV2(
        MetricNameV2.PIPELINE_INGEST_THROUGHPUT,
        MetricKind.GAUGE,
        "messages/second",
    ),
    MetricDefinitionV2(MetricNameV2.PIPELINE_LAG, MetricKind.GAUGE, "milliseconds"),
    MetricDefinitionV2(
        MetricNameV2.DECISION_LATENCY_P50,
        MetricKind.HISTOGRAM,
        "milliseconds",
        percentile=50,
    ),
    MetricDefinitionV2(
        MetricNameV2.DECISION_LATENCY_P95,
        MetricKind.HISTOGRAM,
        "milliseconds",
        percentile=95,
    ),
    MetricDefinitionV2(
        MetricNameV2.DECISION_LATENCY_P99,
        MetricKind.HISTOGRAM,
        "milliseconds",
        percentile=99,
    ),
    MetricDefinitionV2(
        MetricNameV2.ORDER_SUBMIT_LATENCY_P50,
        MetricKind.HISTOGRAM,
        "milliseconds",
        percentile=50,
    ),
    MetricDefinitionV2(
        MetricNameV2.ORDER_SUBMIT_LATENCY_P95,
        MetricKind.HISTOGRAM,
        "milliseconds",
        percentile=95,
    ),
    MetricDefinitionV2(
        MetricNameV2.ORDER_SUBMIT_LATENCY_P99,
        MetricKind.HISTOGRAM,
        "milliseconds",
        percentile=99,
    ),
    MetricDefinitionV2(
        MetricNameV2.ORDER_GATEWAY_THROUGHPUT,
        MetricKind.GAUGE,
        "orders/second",
    ),
    MetricDefinitionV2(MetricNameV2.EXECUTION_FILLS_TOTAL, MetricKind.COUNTER, "count"),
    MetricDefinitionV2(MetricNameV2.EXECUTION_FILL_RATIO, MetricKind.GAUGE, "ratio"),
    MetricDefinitionV2(
        MetricNameV2.ERROR_RATE_PER_S,
        MetricKind.GAUGE,
        "errors/second",
        ("error_code",),
    ),
    MetricDefinitionV2(MetricNameV2.QUEUE_DEPTH, MetricKind.GAUGE, "count", ("queue",)),
    MetricDefinitionV2(MetricNameV2.CACHE_HIT_RATIO, MetricKind.GAUGE, "ratio"),
    MetricDefinitionV2(
        MetricNameV2.CONNECTOR_CONNECTIVITY_STATUS,
        MetricKind.GAUGE,
        "0|1",
    ),
    MetricDefinitionV2(MetricNameV2.HEARTBEAT_SKEW_MS, MetricKind.GAUGE, "milliseconds"),
    MetricDefinitionV2(
        MetricNameV2.STREAM_FRESHNESS_LAG,
        MetricKind.GAUGE,
        "seconds",
        is_extension=True,
    ),
    MetricDefinitionV2(
        MetricNameV2.HALT_ENGAGED,
        MetricKind.GAUGE,
        "boolean",
        is_extension=True,
    ),
    MetricDefinitionV2(
        MetricNameV2.RISK_DENIALS_TOTAL,
        MetricKind.COUNTER,
        "count",
        ("reason",),
        is_extension=True,
    ),
    MetricDefinitionV2(
        MetricNameV2.LABEL_OVERFLOW_TOTAL,
        MetricKind.COUNTER,
        "count",
        is_extension=True,
    ),
)


def _number(value: object) -> Decimal:
    if type(value) is Decimal:
        result = value
    elif type(value) is int:
        result = Decimal(value)
    elif type(value) is float:
        try:
            # str(float) is Python's shortest decimal string that round-trips.
            result = Decimal(str(value))
        except (InvalidOperation, TypeError, ValueError):
            raise MetricError("METRIC_VALUE_INVALID") from None
    else:
        raise MetricError("METRIC_VALUE_INVALID")
    parts = result.as_tuple()
    exponent = parts.exponent
    if not result.is_finite() or len(parts.digits) > _MAX_DECIMAL_DIGITS:
        raise MetricError("METRIC_VALUE_INVALID")
    if type(exponent) is not int or not -18 <= exponent <= 38:
        raise MetricError("METRIC_VALUE_INVALID")
    return result


@dataclass(frozen=True, slots=True)
class MetricLabelsV1:
    service: str
    component: str
    env: str
    region: str
    instance: str
    strategy: str | None = None
    symbol: str | None = None
    venue: str | None = None

    def __post_init__(self) -> None:
        for name in _REQUIRED_LABELS + _OPTIONAL_LABELS:
            value = getattr(self, name)
            if name in _OPTIONAL_LABELS and value is None:
                continue
            if (
                type(value) is not str
                or _LABEL_VALUE.fullmatch(value) is None
                or _CREDENTIAL.search(value) is not None
                or _LONG_DIGITS.search(value) is not None
                or _SEGMENTED_TOKEN.search(value) is not None
                or (
                    sum(char.isdigit() for char in value) >= 7
                    and _PHONE_LIKE.fullmatch(value) is not None
                )
            ):
                raise MetricError("METRIC_LABEL_INVALID")

    def as_dict(self) -> dict[str, str]:
        values = {name: getattr(self, name) for name in _REQUIRED_LABELS}
        values.update(
            {
                name: getattr(self, name)
                for name in _OPTIONAL_LABELS
                if getattr(self, name) is not None
            }
        )
        return values


@dataclass(frozen=True, slots=True)
class MetricSeriesV1:
    name: MetricName
    labels: tuple[tuple[str, str], ...]
    value: Decimal | int | tuple[Decimal, Decimal, Decimal] | bool
    count: int = 0


class MetricCollectorV1:
    """Thread-safe fake collector with fixed cardinality and sample bounds."""

    def __init__(
        self,
        *,
        monotonic_ns: Callable[[], int] = monotonic_ns,
        max_samples_per_series: int = 1024,
        max_optional_values: int = _MAX_OPTIONAL_VALUES,
        max_series_per_metric: int = _MAX_SERIES_PER_METRIC,
    ) -> None:
        if (
            not callable(monotonic_ns)
            or type(max_samples_per_series) is not int
            or not 1 <= max_samples_per_series <= _MAX_SAMPLES_PER_SERIES
            or type(max_optional_values) is not int
            or not 1 <= max_optional_values <= _MAX_OPTIONAL_VALUES
            or type(max_series_per_metric) is not int
            or not 1 <= max_series_per_metric <= _MAX_SERIES_PER_METRIC
        ):
            raise MetricError("METRIC_CONFIG_INVALID")
        self._clock = monotonic_ns
        self._max_samples = max_samples_per_series
        self._max_optional = max_optional_values
        self._max_series = max_series_per_metric
        self._lock = threading.RLock()
        self._values: dict[
            tuple[MetricName, tuple[tuple[str, str], ...]],
            Decimal | int | deque[Decimal],
        ] = {}
        self._counts: dict[tuple[MetricName, tuple[tuple[str, str], ...]], int] = defaultdict(int)
        self._optional_values: dict[str, set[str]] = {name: set() for name in _OPTIONAL_LABELS}
        self._overflow_total = 0

    def _key(
        self, name: MetricName, labels: MetricLabelsV1, extra: tuple[str, str] | None = None
    ) -> tuple[MetricName, tuple[tuple[str, str], ...]]:
        values = labels.as_dict()
        if extra is not None:
            values[extra[0]] = extra[1]
        for label in _OPTIONAL_LABELS:
            value = values.get(label)
            if value is None:
                continue
            known = self._optional_values[label]
            if value not in known and len(known) >= self._max_optional:
                values[label] = "__overflow__"
                self._overflow_total += 1
            else:
                known.add(value)
        key_labels = tuple(sorted(values.items()))
        key = (name, key_labels)
        metric_series = sum(1 for metric, _ in self._values if metric is name)
        # Reserve one bounded series per metric for all overflow traffic.
        regular_series_limit = self._max_series - 1
        if key not in self._values and metric_series >= regular_series_limit:
            values = dict(_SAFE_OVERFLOW_LABELS)
            for label in _OPTIONAL_LABELS:
                if label in labels.as_dict():
                    values[label] = "__overflow__"
            if extra is not None:
                values[extra[0]] = "__overflow__"
            key_labels = tuple(sorted(values.items()))
            key = (name, key_labels)
            self._overflow_total += 1
        return key

    def _record(
        self,
        name: MetricName,
        labels: MetricLabelsV1,
        value: Decimal,
        *,
        extra: tuple[str, str] | None = None,
    ) -> bool:
        if type(name) is not MetricName or type(labels) is not MetricLabelsV1:
            raise MetricError("METRIC_INPUT_INVALID")
        with self._lock:
            key = self._key(name, labels, extra)
            definition = _DEFINITION_BY_NAME[name]
            if definition.kind is MetricKind.HISTOGRAM:
                samples = self._values.get(key)
                if samples is None:
                    samples = deque(maxlen=self._max_samples)
                    self._values[key] = samples
                assert isinstance(samples, deque)
                samples.append(value)
                self._counts[key] += 1
            elif definition.kind is MetricKind.GAUGE:
                self._values[key] = value
            else:
                prior = self._values.get(key, 0)
                assert type(prior) is int
                self._values[key] = prior + int(value)
            return True

    def increment(
        self,
        name: MetricName,
        labels: MetricLabelsV1,
        *,
        value: int = 1,
        outcome: OrderOutcome | None = None,
        reason: RiskDenialReason | None = None,
    ) -> bool:
        if type(name) is not MetricName or type(labels) is not MetricLabelsV1:
            raise MetricError("METRIC_INPUT_INVALID")
        definition = _DEFINITION_BY_NAME.get(name)
        if definition is None or definition.kind is not MetricKind.COUNTER:
            raise MetricError("METRIC_KIND_MISMATCH")
        if type(value) is not int or not 1 <= value <= 1_000_000_000:
            raise MetricError("METRIC_VALUE_INVALID")
        extra: tuple[str, str] | None = None
        if name is MetricName.ORDERS_TOTAL:
            if type(outcome) is not OrderOutcome or reason is not None:
                raise MetricError("METRIC_LABEL_INVALID")
            extra = ("outcome", outcome.value)
        elif name is MetricName.RISK_DENIALS_TOTAL:
            if type(reason) is not RiskDenialReason or outcome is not None:
                raise MetricError("METRIC_LABEL_INVALID")
            extra = ("reason", reason.value)
        elif outcome is not None or reason is not None:
            raise MetricError("METRIC_LABEL_INVALID")
        return self._record(name, labels, Decimal(value), extra=extra)

    def observe(
        self, name: MetricName, value: Decimal | int | float, labels: MetricLabelsV1
    ) -> bool:
        if type(name) is not MetricName or type(labels) is not MetricLabelsV1:
            raise MetricError("METRIC_INPUT_INVALID")
        definition = _DEFINITION_BY_NAME.get(name)
        if definition is None or definition.kind is not MetricKind.HISTOGRAM:
            raise MetricError("METRIC_KIND_MISMATCH")
        number = _number(value)
        if number < 0:
            raise MetricError("METRIC_VALUE_INVALID")
        return self._record(name, labels, number)

    def set_gauge(
        self, name: MetricName, value: Decimal | int | float | bool, labels: MetricLabelsV1
    ) -> bool:
        if type(name) is not MetricName or type(labels) is not MetricLabelsV1:
            raise MetricError("METRIC_INPUT_INVALID")
        definition = _DEFINITION_BY_NAME.get(name)
        if definition is None or definition.kind is not MetricKind.GAUGE:
            raise MetricError("METRIC_KIND_MISMATCH")
        if name is MetricName.HALT_ENGAGED:
            if value not in (False, True, 0, 1) or type(value) not in (bool, int):
                raise MetricError("METRIC_VALUE_INVALID")
            number = Decimal(int(value))
        else:
            number = _number(value)
        return self._record(name, labels, number)

    @contextmanager
    def measure(self, name: MetricName, labels: MetricLabelsV1) -> Iterator[None]:
        if name not in (
            MetricName.DECISION_LATENCY,
            MetricName.ORDER_ACK_LATENCY,
            MetricName.PIPELINE_LAG,
        ):
            raise MetricError("METRIC_KIND_MISMATCH")
        started = self._clock()
        if type(started) is not int or started < 0:
            raise MetricError("METRIC_CLOCK_INVALID")
        try:
            yield
        finally:
            ended = self._clock()
            if type(ended) is not int or ended < started:
                raise MetricError("METRIC_CLOCK_INVALID")
            self.observe(name, Decimal(ended - started) / Decimal(1_000_000_000), labels)

    @property
    def overflow_count(self) -> int:
        with self._lock:
            return self._overflow_total

    def snapshot(self) -> tuple[MetricSeriesV1, ...]:
        with self._lock:
            result: list[MetricSeriesV1] = []
            for key, raw in self._values.items():
                name, labels = key
                if isinstance(raw, deque):
                    ordered = sorted(raw)
                    result.append(
                        MetricSeriesV1(
                            name,
                            labels,
                            (
                                _quantile(ordered, Decimal("0.50")),
                                _quantile(ordered, Decimal("0.95")),
                                _quantile(ordered, Decimal("0.99")),
                            ),
                            self._counts[key],
                        )
                    )
                else:
                    result.append(MetricSeriesV1(name, labels, raw, self._counts[key]))
            if self._overflow_total:
                result.append(
                    MetricSeriesV1(
                        MetricName.LABEL_OVERFLOW_TOTAL,
                        tuple(sorted(_SAFE_OVERFLOW_LABELS.items())),
                        self._overflow_total,
                        self._overflow_total,
                    )
                )
            return tuple(sorted(result, key=lambda item: (item.name.value, item.labels)))


def _quantile(values: list[Decimal], q: Decimal) -> Decimal:
    if not values:
        return Decimal(0)
    rank = int((q * len(values)).to_integral_value(rounding="ROUND_CEILING"))
    index = max(0, min(len(values) - 1, rank - 1))
    return values[index]


__all__ = [
    "METRIC_CATALOG_V1",
    "METRIC_CATALOG_V2",
    "METRIC_LABELS_V2_OPTIONAL",
    "METRIC_LABELS_V2_REQUIRED",
    "MetricCollectorV1",
    "MetricDefinitionV1",
    "MetricDefinitionV2",
    "MetricError",
    "MetricKind",
    "MetricLabelsV1",
    "MetricLabelsV2",
    "MetricName",
    "MetricNameV2",
    "MetricSeriesV1",
    "OrderOutcome",
    "RiskDenialReason",
]
