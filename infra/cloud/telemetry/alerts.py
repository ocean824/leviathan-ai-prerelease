"""Fake-first alert rules and a bounded in-memory delivery outbox.

This module evaluates closed, sanitized observations only. It does not contact
an alert provider, page a person, or configure global logging.
"""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass
from decimal import Decimal
from enum import StrEnum
from typing import Final, cast

from infra.cloud.telemetry.catalog import MetricLabelsV1

from leviathan_core.observability.context import DiagnosticIdFactoryV1, GeneratedIdV1
from leviathan_core.observability.models import LogLevel

_NS: Final = 1_000_000_000
_MAX_UTC_NS: Final = (1 << 63) - 1
_MAX_ROOTS: Final = 10_000
_MAX_OUTBOX: Final = 100_000
_REF = re.compile(r"[a-z][a-z0-9._/-]{0,95}\Z", re.ASCII)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)


class AlertError(ValueError):
    """Content-free alert kernel failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class AlertFailureModeV1(StrEnum):
    DECISION_LATENCY = "decision_latency"
    ORDER_ACK_LATENCY = "order_ack_latency"
    PIPELINE_LAG = "pipeline_lag"
    CONNECTOR_DOWN = "connector_down"
    ERROR_RATE = "error_rate"
    TIME_SYNC_SKEW = "time_sync_skew"
    READINESS_FAILURE = "readiness_failure"


class AlertQueueResultV1(StrEnum):
    QUEUED = "queued"
    DROPPED_LOW_PRIORITY = "dropped_low_priority"
    BACKPRESSURED = "backpressured"


@dataclass(frozen=True, slots=True)
class AlertObservationV1:
    """One synthetic telemetry frame consumed by the rules engine.

    ``error_rate_5m`` is the already-windowed five-minute error ratio. Other
    sustained rules are timed by the engine from successive observations.
    """

    timestamp_utc_ns: int
    labels: MetricLabelsV1
    decision_p99_seconds: Decimal | None = None
    order_ack_p99_seconds: Decimal | None = None
    pipeline_lag_seconds: Decimal | None = None
    connector_up: bool | None = None
    error_rate_5m: Decimal | None = None
    time_sync_offset_seconds: Decimal | None = None
    readiness_ready: bool | None = None
    market_hours: bool = False
    dashboard_ref: str = "unavailable"
    runbook_ref: str = "unavailable"
    deployment_sha256: str = "0" * 64
    affected_ids: tuple[GeneratedIdV1, ...] = ()

    def __post_init__(self) -> None:
        if (
            type(self.timestamp_utc_ns) is not int
            or not 0 <= self.timestamp_utc_ns <= _MAX_UTC_NS
            or type(self.labels) is not MetricLabelsV1
            or type(self.market_hours) is not bool
            or type(self.affected_ids) is not tuple
            or any(type(value) is not GeneratedIdV1 for value in self.affected_ids)
        ):
            raise AlertError("ALERT_OBSERVATION_INVALID")
        for value, nonnegative in (
            (self.decision_p99_seconds, True),
            (self.order_ack_p99_seconds, True),
            (self.pipeline_lag_seconds, True),
            (self.error_rate_5m, True),
            (self.time_sync_offset_seconds, False),
        ):
            if value is not None and (
                type(value) is not Decimal or not value.is_finite() or (nonnegative and value < 0)
            ):
                raise AlertError("ALERT_OBSERVATION_INVALID")
        if self.error_rate_5m is not None and self.error_rate_5m > 1:
            raise AlertError("ALERT_OBSERVATION_INVALID")
        if self.connector_up is not None and type(self.connector_up) is not bool:
            raise AlertError("ALERT_OBSERVATION_INVALID")
        if self.readiness_ready is not None and type(self.readiness_ready) is not bool:
            raise AlertError("ALERT_OBSERVATION_INVALID")
        if (
            type(self.dashboard_ref) is not str
            or type(self.runbook_ref) is not str
            or type(self.deployment_sha256) is not str
            or _REF.fullmatch(self.dashboard_ref) is None
            or _REF.fullmatch(self.runbook_ref) is None
            or _SHA256.fullmatch(self.deployment_sha256) is None
        ):
            raise AlertError("ALERT_OBSERVATION_INVALID")


@dataclass(frozen=True, slots=True)
class AlertPageV1:
    """Safe page metadata; raw event text and principal data are absent."""

    page_id: GeneratedIdV1
    root_cause_id: str
    failure_mode: AlertFailureModeV1
    labels: MetricLabelsV1
    fired_utc_ns: int
    observed_value: Decimal | bool
    dashboard_ref: str
    runbook_ref: str
    deployment_sha256: str
    affected_ids: tuple[GeneratedIdV1, ...]

    def __post_init__(self) -> None:
        if (
            type(self.page_id) is not GeneratedIdV1
            or type(self.root_cause_id) is not str
            or _SHA256.fullmatch(self.root_cause_id) is None
            or type(self.failure_mode) is not AlertFailureModeV1
            or type(self.labels) is not MetricLabelsV1
            or type(self.fired_utc_ns) is not int
            or not 0 <= self.fired_utc_ns <= _MAX_UTC_NS
            or type(self.observed_value) not in (Decimal, bool)
            or (type(self.observed_value) is Decimal and not self.observed_value.is_finite())
            or type(self.dashboard_ref) is not str
            or _REF.fullmatch(self.dashboard_ref) is None
            or type(self.runbook_ref) is not str
            or _REF.fullmatch(self.runbook_ref) is None
            or type(self.deployment_sha256) is not str
            or _SHA256.fullmatch(self.deployment_sha256) is None
            or type(self.affected_ids) is not tuple
            or any(type(token) is not GeneratedIdV1 for token in self.affected_ids)
        ):
            raise AlertError("ALERT_PAGE_INVALID")


@dataclass(frozen=True, slots=True)
class _Rule:
    mode: AlertFailureModeV1
    field: str
    threshold: Decimal | None
    duration_ns: int
    direction: str


_RULES: Final[tuple[_Rule, ...]] = (
    _Rule(AlertFailureModeV1.DECISION_LATENCY, "decision_p99_seconds", Decimal("0.008"), 0, "gt"),
    _Rule(AlertFailureModeV1.ORDER_ACK_LATENCY, "order_ack_p99_seconds", Decimal("0.012"), 0, "gt"),
    _Rule(
        AlertFailureModeV1.PIPELINE_LAG,
        "pipeline_lag_seconds",
        Decimal("0.500"),
        300 * _NS,
        "gt",
    ),
    _Rule(AlertFailureModeV1.CONNECTOR_DOWN, "connector_up", None, 60 * _NS, "false"),
    _Rule(AlertFailureModeV1.ERROR_RATE, "error_rate_5m", Decimal("0.02"), 0, "gt"),
    _Rule(
        AlertFailureModeV1.TIME_SYNC_SKEW,
        "time_sync_offset_seconds",
        Decimal("0.050"),
        120 * _NS,
        "abs_gt",
    ),
    _Rule(AlertFailureModeV1.READINESS_FAILURE, "readiness_ready", None, 120 * _NS, "false_market"),
)


class AlertEngineV1:
    """Stateful, bounded rule engine that emits at most one page per incident."""

    def __init__(self, id_factory: DiagnosticIdFactoryV1, *, max_roots: int = 1000) -> None:
        if (
            type(id_factory) is not DiagnosticIdFactoryV1
            or type(max_roots) is not int
            or not 1 <= max_roots <= _MAX_ROOTS
        ):
            raise AlertError("ALERT_CONFIG_INVALID")
        self._ids = id_factory
        self._max_roots = max_roots
        self._lock = threading.RLock()
        self._started: dict[tuple[str, AlertFailureModeV1], int] = {}
        self._paged: set[tuple[str, str, AlertFailureModeV1]] = set()
        self._active_sources: dict[tuple[str, AlertFailureModeV1], set[str]] = {}
        self._last_timestamp: dict[str, int] = {}
        self._stream_meta: dict[str, tuple[str, str | None]] = {}

    def evaluate(self, observation: AlertObservationV1) -> tuple[AlertPageV1, ...]:
        if type(observation) is not AlertObservationV1:
            raise AlertError("ALERT_OBSERVATION_INVALID")
        if any(not self._ids.owns(token, token.kind) for token in observation.affected_ids):
            raise AlertError("ALERT_ID_INVALID")
        labels = observation.labels.as_dict()
        group = "|".join(labels.get(name, "") for name in ("service", "component"))
        source = "|".join(labels.get(name, "") for name in ("env", "region", "instance", "venue"))
        stream = f"{group}|{source}"
        with self._lock:
            if stream not in self._last_timestamp and len(self._last_timestamp) >= self._max_roots:
                raise AlertError("ALERT_CAPACITY_EXCEEDED")
            self._stream_meta[stream] = (labels["service"], labels.get("venue"))
            previous = self._last_timestamp.get(stream)
            if previous is not None and observation.timestamp_utc_ns < previous:
                raise AlertError("ALERT_CLOCK_REGRESSION")
            self._last_timestamp[stream] = observation.timestamp_utc_ns
            frame: list[tuple[_Rule, object, int]] = []
            for rule in _RULES:
                value = getattr(observation, rule.field)
                if (
                    rule.mode is AlertFailureModeV1.READINESS_FAILURE
                    and not observation.market_hours
                ):
                    value = True
                breach = self._breaches(rule, value)
                key = (stream, rule.mode)
                root_key = (group, rule.mode)
                if not breach:
                    self._started.pop(key, None)
                    sources = self._active_sources.get(root_key)
                    if sources is not None:
                        sources.discard(stream)
                        if not sources:
                            self._active_sources.pop(root_key, None)
                            self._paged.discard((group, self._root_id(group, rule.mode), rule.mode))
                    continue
                sources = self._active_sources.get(root_key)
                if sources is None:
                    if len(self._active_sources) >= self._max_roots:
                        raise AlertError("ALERT_CAPACITY_EXCEEDED")
                    sources = set()
                    self._active_sources[root_key] = sources
                sources.add(stream)
                start = self._started.setdefault(key, observation.timestamp_utc_ns)
                elapsed = observation.timestamp_utc_ns - start
                frame.append((rule, value, elapsed))
            active_connector = any(
                mode is AlertFailureModeV1.CONNECTOR_DOWN
                and any(
                    self._stream_meta.get(source, ("", None))[0] == labels["service"]
                    and (
                        self._stream_meta.get(source, ("", None))[1] is None
                        or self._stream_meta.get(source, ("", None))[1] == labels.get("venue")
                    )
                    and observation.timestamp_utc_ns - self._started.get((source, mode), 0)
                    > 60 * _NS
                    for source in sources
                )
                for (_group, mode), sources in self._active_sources.items()
            )
            pages: list[AlertPageV1] = []
            for rule, value, elapsed in frame:
                root = (group, self._root_id(group, rule.mode), rule.mode)
                if (rule.duration_ns > 0 and elapsed <= rule.duration_ns) or root in self._paged:
                    continue
                if (
                    rule.mode is not AlertFailureModeV1.CONNECTOR_DOWN
                    and active_connector
                    and labels.get("venue") is not None
                ):
                    continue
                if len(self._paged) >= self._max_roots:
                    raise AlertError("ALERT_CAPACITY_EXCEEDED")
                if not self._ids.owns((page_id := self._ids.mint_event_id()), "event"):
                    raise AlertError("ALERT_ID_INVALID")
                pages.append(
                    AlertPageV1(
                        page_id=page_id,
                        root_cause_id=root[1],
                        failure_mode=rule.mode,
                        labels=observation.labels,
                        fired_utc_ns=observation.timestamp_utc_ns,
                        observed_value=cast(Decimal | bool, value),
                        dashboard_ref=observation.dashboard_ref,
                        runbook_ref=observation.runbook_ref,
                        deployment_sha256=observation.deployment_sha256,
                        affected_ids=observation.affected_ids,
                    )
                )
                self._paged.add(root)
            return tuple(pages)

    @staticmethod
    def _breaches(rule: _Rule, value: object) -> bool:
        if rule.direction == "false":
            return value is False
        if rule.direction == "false_market":
            return value is False
        if rule.direction == "abs_gt":
            return type(value) is Decimal and abs(value) > rule.threshold  # type: ignore[operator]
        return type(value) is Decimal and value > rule.threshold  # type: ignore[operator]

    @staticmethod
    def _root_id(group: str, mode: AlertFailureModeV1) -> str:
        return hashlib.sha256(f"{group}|{mode.value}".encode("ascii")).hexdigest()


@dataclass(frozen=True, slots=True)
class _QueuedPage:
    level: LogLevel
    page: AlertPageV1


@dataclass(frozen=True, slots=True)
class AlertDeliveryV1:
    level: LogLevel
    page: AlertPageV1


class AlertOutboxV1:
    """Bounded fake delivery queue; critical events are backpressured, not lost."""

    def __init__(self, *, max_items: int = 1024) -> None:
        if type(max_items) is not int or not 1 <= max_items <= _MAX_OUTBOX:
            raise AlertError("ALERT_CONFIG_INVALID")
        self._max_items = max_items
        self._lock = threading.Lock()
        self._items: list[_QueuedPage] = []

    def submit(self, page: AlertPageV1, level: LogLevel) -> AlertQueueResultV1:
        if type(page) is not AlertPageV1 or type(level) is not LogLevel:
            raise AlertError("ALERT_INPUT_INVALID")
        with self._lock:
            if len(self._items) >= self._max_items:
                if level in {LogLevel.TRACE, LogLevel.DEBUG}:
                    return AlertQueueResultV1.DROPPED_LOW_PRIORITY
                removable = next(
                    (
                        index
                        for index, item in enumerate(self._items)
                        if item.level in {LogLevel.TRACE, LogLevel.DEBUG}
                    ),
                    None,
                )
                if removable is not None:
                    self._items.pop(removable)
                elif level in {LogLevel.INFO, LogLevel.WARN, LogLevel.ERROR}:
                    return AlertQueueResultV1.BACKPRESSURED
            self._items.append(_QueuedPage(level, page))
            return AlertQueueResultV1.QUEUED

    def drain(self, *, limit: int = 100) -> tuple[AlertDeliveryV1, ...]:
        if type(limit) is not int or not 1 <= limit <= self._max_items:
            raise AlertError("ALERT_LIMIT_INVALID")
        with self._lock:
            items = self._items[:limit]
            del self._items[:limit]
            return tuple(AlertDeliveryV1(item.level, item.page) for item in items)

    @property
    def pending(self) -> int:
        with self._lock:
            return len(self._items)


__all__ = [
    "AlertDeliveryV1",
    "AlertEngineV1",
    "AlertError",
    "AlertFailureModeV1",
    "AlertObservationV1",
    "AlertOutboxV1",
    "AlertPageV1",
    "AlertQueueResultV1",
]
