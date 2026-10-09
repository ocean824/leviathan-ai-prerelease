"""Bounded, closed-value telemetry envelopes for synthetic MT bridge events.

This module defines an offline envelope only. It has no transport, storage,
terminal, or live-agent integration.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from decimal import Decimal
from enum import StrEnum
from typing import Any, Final, Literal, cast

from pydantic import ValidationError

from leviathan_core.execution.broker_port_v1 import BrokerVenue
from leviathan_core.numeric import NumericError, parse_decimal
from leviathan_core.observability.models import ErrorCode
from leviathan_core.seal import Issuer, SealedModel, SealError, require
from leviathan_core.text.safe_label import is_safe_identifier

_TAG: Final = "mtbr.telemetry_envelope.v1"
_ISSUER: Final = Issuer(_TAG)
_MARKER: Final = object()
_MAX_UTC_NS: Final = (1 << 63) - 1
_MAX_IDENTIFIER_CHARS: Final = 64
_MAX_LABELS_PER_METRIC: Final = 9
_MAX_ALERTS: Final = 32
_MAX_METRICS: Final = 128
_MAX_DISTINCT_LABEL_VALUES: Final = 100
_MAX_SERIES: Final = 1000
_MAX_ENVELOPE_BYTES: Final = 32_768
_DEFAULT_FUTURE_TOLERANCE_NS: Final = 5_000_000_000
_MAX_FUTURE_TOLERANCE_NS: Final = 60_000_000_000
_IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z", re.ASCII)
_SYMBOL_VALUE = re.compile(r"[A-Z0-9.-]{1,20}\Z", re.ASCII)
_LONG_DIGIT_RUN = re.compile(r"[0-9]{9,}", re.ASCII)


class TelemetryErrorCodeV1(StrEnum):
    INPUT_INVALID = "TELEMETRY_INPUT_INVALID"
    VERSION_UNSUPPORTED = "TELEMETRY_VERSION_UNSUPPORTED"
    IDENTIFIER_INVALID = "TELEMETRY_IDENTIFIER_INVALID"
    TIME_INVALID = "TELEMETRY_TIME_INVALID"
    LABEL_INVALID = "TELEMETRY_LABEL_INVALID"
    LIMIT_EXCEEDED = "TELEMETRY_LIMIT_EXCEEDED"
    PAYLOAD_TOO_LARGE = "TELEMETRY_PAYLOAD_TOO_LARGE"
    SEAL_INVALID = "TELEMETRY_SEAL_INVALID"


class TelemetryError(ValueError):
    """Content-free telemetry error carrying only a fixed code."""

    def __init__(self, code: TelemetryErrorCodeV1) -> None:
        self.code = (
            code if type(code) is TelemetryErrorCodeV1 else TelemetryErrorCodeV1.INPUT_INVALID
        )
        super().__init__(self.code.value)


class TelemetryEventTypeV1(StrEnum):
    AGENT_TELEMETRY = "AGENT_TELEMETRY"


class TelemetryAlertCodeV1(StrEnum):
    AGENT_OFFLINE = "AGENT_OFFLINE"
    BUILD_FAILED = "BUILD_FAILED"
    CHECKSUM_MISMATCH = "CHECKSUM_MISMATCH"
    DEPLOYMENT_BLOCKED = "DEPLOYMENT_BLOCKED"
    HEALTH_CHECK_FAILED = "HEALTH_CHECK_FAILED"
    INSTALL_FAILED = "INSTALL_FAILED"
    SYMBOL_MISMATCH = "SYMBOL_MISMATCH"
    ACTIVATION_FAILED = "ACTIVATION_FAILED"
    UNKNOWN = "UNKNOWN"


class TelemetryAlertSeverityV1(StrEnum):
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class TelemetryEnvironmentV1(StrEnum):
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"
    TEST = "test"


class TelemetryRiskDenialReasonV1(StrEnum):
    HALT = "halt"
    LIMIT = "limit"
    STALE_DATA = "stale_data"
    POLICY = "policy"
    UNKNOWN = "unknown"


class TelemetryServiceV1(StrEnum):
    API = "api"
    SIDECAR = "sidecar"
    TERMINAL = "terminal"
    LICENSING_WORKER = "licensing-worker"
    MT_BRIDGE = "mt-bridge"
    OMS = "oms"
    RISK = "risk"
    MARKET_DATA = "market-data"


class TelemetryRegionV1(StrEnum):
    LOCAL = "local"
    US_EAST = "us-east"
    US_WEST = "us-west"
    EU = "eu"
    AP = "ap"


class TelemetryQueueV1(StrEnum):
    ORDERS_INBOUND = "orders.inbound"


class TelemetryMetricNameV1(StrEnum):
    """Closed names copied from the integrated METRIC_CATALOG_V2 catalog."""

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


class TelemetryLabelNameV1(StrEnum):
    """Label vocabulary aligned with METRIC_LABELS_V2."""

    SERVICE = "service"
    COMPONENT = "component"
    ENV = "env"
    REGION = "region"
    INSTANCE = "instance"
    VENUE = "venue"
    STRATEGY_ID = "strategy_id"
    SYMBOL = "symbol"
    ERROR_CODE = "error_code"
    QUEUE = "queue"
    REASON = "reason"


@dataclass(frozen=True, slots=True, repr=False)
class TelemetryLabelV1:
    """One closed-name label; its value domain is enforced at envelope creation."""

    name: TelemetryLabelNameV1
    value: str | StrEnum

    def __repr__(self) -> str:
        return "TelemetryLabelV1(<closed-value>)"


@dataclass(frozen=True, slots=True, repr=False)
class TelemetryAlertSummaryV1:
    """Compact alert summary with no text, account data, or raw payload field."""

    code: TelemetryAlertCodeV1
    severity: TelemetryAlertSeverityV1
    count: int = 1

    def __repr__(self) -> str:
        code = self.code.value if type(self.code) is TelemetryAlertCodeV1 else "UNKNOWN"
        severity = (
            self.severity.value if type(self.severity) is TelemetryAlertSeverityV1 else "UNKNOWN"
        )
        return f"TelemetryAlertSummaryV1(code={code!r}, severity={severity!r})"


@dataclass(frozen=True, slots=True, repr=False)
class TelemetryMetricSummaryV1:
    """Exact scalar summary; labels are validated on envelope creation."""

    name: TelemetryMetricNameV1
    value: Decimal | int | str
    labels: tuple[TelemetryLabelV1, ...]

    def __repr__(self) -> str:
        name = self.name.value if type(self.name) is TelemetryMetricNameV1 else "UNKNOWN"
        return f"TelemetryMetricSummaryV1(name={name!r}, value=<closed-value>)"


def _safe_identifier(value: object) -> bool:
    if (
        type(value) is not str
        or len(value) > _MAX_IDENTIFIER_CHARS
        or _IDENTIFIER.fullmatch(value) is None
    ):
        return False
    return is_safe_identifier(value)


def _validate_label_value(name: TelemetryLabelNameV1, value: object) -> str:
    def enum_value(expected: type[StrEnum] | tuple[type[StrEnum], ...]) -> str:
        if type(value) not in (expected if isinstance(expected, tuple) else (expected,)):
            raise TelemetryError(TelemetryErrorCodeV1.LABEL_INVALID)
        return cast(StrEnum, value).value

    if name is TelemetryLabelNameV1.ENV:
        return enum_value(TelemetryEnvironmentV1)
    if name is TelemetryLabelNameV1.REASON:
        return enum_value(TelemetryRiskDenialReasonV1)
    if name is TelemetryLabelNameV1.SERVICE:
        return enum_value(TelemetryServiceV1)
    if name is TelemetryLabelNameV1.REGION:
        return enum_value(TelemetryRegionV1)
    if name is TelemetryLabelNameV1.VENUE:
        return enum_value(BrokerVenue)
    if name is TelemetryLabelNameV1.QUEUE:
        return enum_value(TelemetryQueueV1)
    if name is TelemetryLabelNameV1.ERROR_CODE:
        return enum_value((TelemetryErrorCodeV1, ErrorCode))
    if type(value) is not str:
        raise TelemetryError(TelemetryErrorCodeV1.LABEL_INVALID)
    if len(value) >= 9 and all("0" <= char <= "9" for char in value):
        raise TelemetryError(TelemetryErrorCodeV1.LABEL_INVALID)
    if name is TelemetryLabelNameV1.SYMBOL:
        if _SYMBOL_VALUE.fullmatch(value) is None:
            raise TelemetryError(TelemetryErrorCodeV1.LABEL_INVALID)
        return value.lower()
    if not _safe_identifier(value):
        raise TelemetryError(TelemetryErrorCodeV1.LABEL_INVALID)
    if (
        name
        in {
            TelemetryLabelNameV1.COMPONENT,
            TelemetryLabelNameV1.INSTANCE,
            TelemetryLabelNameV1.STRATEGY_ID,
        }
        and _LONG_DIGIT_RUN.search(value) is not None
    ):
        raise TelemetryError(TelemetryErrorCodeV1.LABEL_INVALID)
    return value


_BASE_LABELS: Final = frozenset(
    {
        TelemetryLabelNameV1.SERVICE,
        TelemetryLabelNameV1.COMPONENT,
        TelemetryLabelNameV1.ENV,
        TelemetryLabelNameV1.REGION,
        TelemetryLabelNameV1.INSTANCE,
        TelemetryLabelNameV1.VENUE,
    }
)
_OPTIONAL_LABELS: Final = frozenset({TelemetryLabelNameV1.STRATEGY_ID, TelemetryLabelNameV1.SYMBOL})
_EXTRA_REQUIRED_LABEL: Final = {
    TelemetryMetricNameV1.ERROR_RATE_PER_S: TelemetryLabelNameV1.ERROR_CODE,
    TelemetryMetricNameV1.QUEUE_DEPTH: TelemetryLabelNameV1.QUEUE,
    TelemetryMetricNameV1.RISK_DENIALS_TOTAL: TelemetryLabelNameV1.REASON,
}


class _AlertDataV1(SealedModel):
    code: TelemetryAlertCodeV1
    severity: TelemetryAlertSeverityV1
    count: int


class _LabelDataV1(SealedModel):
    name: TelemetryLabelNameV1
    value: str


class _MetricDataV1(SealedModel):
    name: TelemetryMetricNameV1
    value: Decimal
    labels: tuple[_LabelDataV1, ...]


class TelemetryEnvelopeV1(SealedModel):
    """Issued immutable MT bridge telemetry envelope, schema version 1."""

    schema_version: Literal[1]
    event_type: TelemetryEventTypeV1
    agent_id: str
    artifact_id: str
    correlation_id: str
    occurred_utc_ns: int
    alerts: tuple[_AlertDataV1, ...]
    metrics: tuple[_MetricDataV1, ...]

    def __init__(self, *, _construction_marker: object | None = None, **data: object) -> None:
        if _construction_marker is not _MARKER:
            raise TelemetryError(TelemetryErrorCodeV1.INPUT_INVALID)
        try:
            super().__init__(**data)
        except (ValidationError, TypeError, ValueError):
            raise TelemetryError(TelemetryErrorCodeV1.INPUT_INVALID) from None

    @classmethod
    def create(
        cls,
        *,
        agent_id: str,
        artifact_id: str,
        correlation_id: str,
        occurred_utc_ns: int,
        utc_ns: Callable[[], int],
        alerts: tuple[TelemetryAlertSummaryV1, ...] = (),
        metrics: tuple[TelemetryMetricSummaryV1, ...] = (),
        event_type: TelemetryEventTypeV1 = TelemetryEventTypeV1.AGENT_TELEMETRY,
        schema_version: int = 1,
        future_tolerance_ns: int = _DEFAULT_FUTURE_TOLERANCE_NS,
    ) -> TelemetryEnvelopeV1:
        if type(schema_version) is not int or schema_version != 1:
            raise TelemetryError(TelemetryErrorCodeV1.VERSION_UNSUPPORTED)
        if type(event_type) is not TelemetryEventTypeV1:
            raise TelemetryError(TelemetryErrorCodeV1.INPUT_INVALID)
        if (
            not _safe_identifier(agent_id)
            or not _safe_identifier(artifact_id)
            or not _safe_identifier(correlation_id)
        ):
            raise TelemetryError(TelemetryErrorCodeV1.IDENTIFIER_INVALID)
        if (
            not callable(utc_ns)
            or type(future_tolerance_ns) is not int
            or not 0 <= future_tolerance_ns <= _MAX_FUTURE_TOLERANCE_NS
            or type(occurred_utc_ns) is not int
            or not 0 <= occurred_utc_ns <= _MAX_UTC_NS
        ):
            raise TelemetryError(TelemetryErrorCodeV1.TIME_INVALID)
        try:
            now_ns = utc_ns()
        except Exception:
            raise TelemetryError(TelemetryErrorCodeV1.TIME_INVALID) from None
        if (
            type(now_ns) is not int
            or not 0 <= now_ns <= _MAX_UTC_NS
            or occurred_utc_ns > min(_MAX_UTC_NS, now_ns + future_tolerance_ns)
        ):
            raise TelemetryError(TelemetryErrorCodeV1.TIME_INVALID)
        if type(alerts) is not tuple or type(metrics) is not tuple:
            raise TelemetryError(TelemetryErrorCodeV1.INPUT_INVALID)
        if len(alerts) > _MAX_ALERTS or len(metrics) > _MAX_METRICS:
            raise TelemetryError(TelemetryErrorCodeV1.LIMIT_EXCEEDED)

        safe_alerts: list[_AlertDataV1] = []
        for alert in alerts:
            if (
                type(alert) is not TelemetryAlertSummaryV1
                or type(alert.code) is not TelemetryAlertCodeV1
                or type(alert.severity) is not TelemetryAlertSeverityV1
                or type(alert.count) is not int
                or not 1 <= alert.count <= 1_000_000_000
            ):
                raise TelemetryError(TelemetryErrorCodeV1.INPUT_INVALID)
            try:
                safe_alerts.append(
                    _AlertDataV1(code=alert.code, severity=alert.severity, count=alert.count)
                )
            except (ValidationError, TypeError, ValueError):
                raise TelemetryError(TelemetryErrorCodeV1.INPUT_INVALID) from None

        safe_metrics: list[_MetricDataV1] = []
        label_values: dict[TelemetryLabelNameV1, set[str]] = {}
        series: set[tuple[str, tuple[tuple[str, str], ...]]] = set()
        for metric in metrics:
            if (
                type(metric) is not TelemetryMetricSummaryV1
                or type(metric.name) is not TelemetryMetricNameV1
                or type(metric.labels) is not tuple
                or len(metric.labels) > _MAX_LABELS_PER_METRIC
            ):
                raise TelemetryError(TelemetryErrorCodeV1.INPUT_INVALID)
            try:
                value = parse_decimal(
                    metric.value,
                    field="value",
                    max_sig_digits=34,
                    max_abs_adjusted=38,
                )
            except NumericError:
                raise TelemetryError(TelemetryErrorCodeV1.INPUT_INVALID) from None

            names: set[TelemetryLabelNameV1] = set()
            safe_labels: list[_LabelDataV1] = []
            normalized_labels: list[tuple[str, str]] = []
            for label in metric.labels:
                if (
                    type(label) is not TelemetryLabelV1
                    or type(label.name) is not TelemetryLabelNameV1
                ):
                    raise TelemetryError(TelemetryErrorCodeV1.LABEL_INVALID)
                if label.name in names:
                    raise TelemetryError(TelemetryErrorCodeV1.LABEL_INVALID)
                names.add(label.name)
                safe_value = _validate_label_value(label.name, label.value)
                seen = label_values.setdefault(label.name, set())
                seen.add(safe_value)
                if len(seen) > _MAX_DISTINCT_LABEL_VALUES:
                    raise TelemetryError(TelemetryErrorCodeV1.LIMIT_EXCEEDED)
                normalized_labels.append((label.name.value, safe_value))
                try:
                    safe_labels.append(_LabelDataV1(name=label.name, value=safe_value))
                except (ValidationError, TypeError, ValueError):
                    raise TelemetryError(TelemetryErrorCodeV1.LABEL_INVALID) from None

            required = _BASE_LABELS | (
                {_EXTRA_REQUIRED_LABEL[metric.name]}
                if metric.name in _EXTRA_REQUIRED_LABEL
                else set()
            )
            allowed = required | _OPTIONAL_LABELS
            if not required.issubset(names) or not names.issubset(allowed):
                raise TelemetryError(TelemetryErrorCodeV1.LABEL_INVALID)
            series.add((metric.name.value, tuple(sorted(normalized_labels))))
            if len(series) > _MAX_SERIES:
                raise TelemetryError(TelemetryErrorCodeV1.LIMIT_EXCEEDED)
            try:
                safe_metrics.append(
                    _MetricDataV1(
                        name=metric.name,
                        value=value,
                        labels=tuple(safe_labels),
                    )
                )
            except (ValidationError, TypeError, ValueError):
                raise TelemetryError(TelemetryErrorCodeV1.INPUT_INVALID) from None

        try:
            event = cls(
                _construction_marker=_MARKER,
                schema_version=1,
                event_type=event_type,
                agent_id=agent_id,
                artifact_id=artifact_id,
                correlation_id=correlation_id,
                occurred_utc_ns=occurred_utc_ns,
                alerts=tuple(safe_alerts),
                metrics=tuple(safe_metrics),
            )
            # Measure before sealing: the seal walk has a smaller structural
            # budget than the envelope byte cap and must not mask size errors.
            encoded = super(TelemetryEnvelopeV1, event).model_dump_json().encode("utf-8")
        except TelemetryError:
            raise
        except (SealError, ValidationError, TypeError, ValueError):
            raise TelemetryError(TelemetryErrorCodeV1.INPUT_INVALID) from None
        if len(encoded) > _MAX_ENVELOPE_BYTES:
            raise TelemetryError(TelemetryErrorCodeV1.PAYLOAD_TOO_LARGE)
        try:
            return _ISSUER.issue(event)
        except SealError:
            raise TelemetryError(TelemetryErrorCodeV1.LIMIT_EXCEEDED) from None

    def model_dump(self, **kwargs: Any) -> dict[str, Any]:
        try:
            require(self, _TAG)
            return super().model_dump(**kwargs)
        except TelemetryError:
            raise
        except SealError:
            raise TelemetryError(TelemetryErrorCodeV1.SEAL_INVALID) from None

    def model_dump_json(self, **kwargs: Any) -> str:
        if kwargs:
            raise TelemetryError(TelemetryErrorCodeV1.INPUT_INVALID)
        try:
            require(self, _TAG)
            result = super().model_dump_json()
        except TelemetryError:
            raise
        except SealError:
            raise TelemetryError(TelemetryErrorCodeV1.SEAL_INVALID) from None
        if len(result.encode("utf-8")) > _MAX_ENVELOPE_BYTES:
            raise TelemetryError(TelemetryErrorCodeV1.PAYLOAD_TOO_LARGE)
        return result

    @classmethod
    def model_validate(cls, obj: Any, **kwargs: Any) -> TelemetryEnvelopeV1:
        del obj, kwargs
        raise TelemetryError(TelemetryErrorCodeV1.INPUT_INVALID)

    @classmethod
    def model_validate_json(cls, json_data: Any, **kwargs: Any) -> TelemetryEnvelopeV1:
        del json_data, kwargs
        raise TelemetryError(TelemetryErrorCodeV1.INPUT_INVALID)

    @classmethod
    def model_validate_strings(cls, obj: Any, **kwargs: Any) -> TelemetryEnvelopeV1:
        del obj, kwargs
        raise TelemetryError(TelemetryErrorCodeV1.INPUT_INVALID)

    def model_copy(self, *, update: Any = None, deep: bool = False) -> TelemetryEnvelopeV1:
        del update, deep
        raise TelemetryError(TelemetryErrorCodeV1.INPUT_INVALID)

    def __repr__(self) -> str:
        return "TelemetryEnvelopeV1(<closed-value>)"

    def __str__(self) -> str:
        return "TelemetryEnvelopeV1(<closed-value>)"

    def to_json(self) -> str:
        try:
            require(self, _TAG)
            return self.model_dump_json()
        except TelemetryError:
            raise
        except SealError:
            raise TelemetryError(TelemetryErrorCodeV1.SEAL_INVALID) from None
        except (ValidationError, TypeError, ValueError):
            raise TelemetryError(TelemetryErrorCodeV1.SEAL_INVALID) from None

    @property
    def serialized_size_bytes(self) -> int:
        return len(self.to_json().encode("utf-8"))


__all__ = [
    "TelemetryAlertCodeV1",
    "TelemetryAlertSeverityV1",
    "TelemetryAlertSummaryV1",
    "TelemetryEnvelopeV1",
    "TelemetryEnvironmentV1",
    "TelemetryError",
    "TelemetryErrorCodeV1",
    "TelemetryEventTypeV1",
    "TelemetryLabelNameV1",
    "TelemetryLabelV1",
    "TelemetryMetricNameV1",
    "TelemetryMetricSummaryV1",
    "TelemetryQueueV1",
    "TelemetryRegionV1",
    "TelemetryRiskDenialReasonV1",
    "TelemetryServiceV1",
]
