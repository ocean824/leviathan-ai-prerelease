"""Bounded in-memory ingress. Sink ACK is the sole commit boundary."""

from __future__ import annotations

import heapq
import time
import weakref
from collections.abc import Callable, Mapping
from contextvars import ContextVar
from dataclasses import InitVar, dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Literal, Protocol

from leviathan_market_data.health import SourceHealthSnapshot, _SourceHealth
from leviathan_market_data.normalization import (
    NormalizationError,
    NormalizerPort,
    VendorRecord,
)
from leviathan_market_data.schema import (
    INT64_MAX,
    MarketDataValueError,
    NoCopy,
    NormalizedMarketEventV1,
)

StreamKey = tuple[str, str, str, str, str]
SequencePolicy = Literal[
    "contiguous", "monotonic_noncontiguous_session_reset", "unavailable",
]
_ISSUER = object()
_ISSUING: ContextVar[bool] = ContextVar("market_data_receipt_issuing", default=False)
_ISSUED: weakref.WeakSet[IngestReceipt] = weakref.WeakSet()


class IngestStatus(StrEnum):
    ACCEPTED = "ACCEPTED"
    DUPLICATE = "DUPLICATE"
    QUARANTINED = "QUARANTINED"
    BACKPRESSURE = "BACKPRESSURE"
    BUFFERED = "BUFFERED"
    SINK_FAULT = "SINK_FAULT"


@dataclass(frozen=True, slots=True)
class SinkAck(NoCopy):
    accepted: bool = False
    backpressure: bool = False

    def __post_init__(self) -> None:
        if type(self.accepted) is not bool or type(self.backpressure) is not bool:
            raise MarketDataValueError("INVALID_BOOLEAN")
        if self.accepted == self.backpressure:
            raise MarketDataValueError("INVALID_SINK_ACK")


class IngressSink(Protocol):
    """accept must be idempotent by event.idempotency_key across recovery."""

    def accept(self, event: NormalizedMarketEventV1) -> SinkAck: ...


@dataclass(frozen=True, slots=True, weakref_slot=True, eq=False)
class IngestReceipt(NoCopy):
    status: IngestStatus
    reason: str | None = None
    event: NormalizedMarketEventV1 | None = None
    correction: bool = False
    execution_eligible: bool = False
    drained_receipts: tuple[IngestReceipt, ...] = ()
    source: Literal["INGRESS_CAPACITY", "INGRESS_CLOCK", "SINK"] | None = None
    sink_count: int = 0
    _issuer: InitVar[object | None] = None

    def __new__(cls, *args: object, **kwargs: object) -> IngestReceipt:
        if cls is not IngestReceipt or not _ISSUING.get():
            raise MarketDataValueError("UNAUTHORIZED_RECEIPT")
        receipt = object.__new__(cls)
        _ISSUED.add(receipt)
        return receipt

    def __post_init__(self, _issuer: object | None) -> None:
        if _issuer is not _ISSUER or self not in _ISSUED:
            raise MarketDataValueError("UNAUTHORIZED_RECEIPT")
        if any(type(value) is not bool for value in
               (self.correction, self.execution_eligible)):
            raise MarketDataValueError("INVALID_BOOLEAN")
        if type(self.sink_count) is not int or self.sink_count < 0:
            raise MarketDataValueError("INVALID_INTEGER")
        if not isinstance(self.status, IngestStatus):
            raise MarketDataValueError("INVALID_RECEIPT")
        if (not isinstance(self.drained_receipts, tuple)
                or any(not isinstance(item, IngestReceipt)
                       for item in self.drained_receipts)):
            raise MarketDataValueError("INVALID_RECEIPT")
        if self.source not in (None, "INGRESS_CAPACITY", "INGRESS_CLOCK", "SINK"):
            raise MarketDataValueError("INVALID_RECEIPT")
        if self.status is IngestStatus.ACCEPTED and (
            self.reason != "SINK_ACK" or self.event is None or self.sink_count < 1
        ):
            raise MarketDataValueError("INVALID_RECEIPT")
        if self.reason == "SINK_ACK" and self.status is not IngestStatus.ACCEPTED:
            raise MarketDataValueError("INVALID_RECEIPT")
        if self.execution_eligible and (
            self.status is not IngestStatus.ACCEPTED or self.event is None
            or self.event.source_mode != "live" or self.event.reconstructed
        ):
            raise MarketDataValueError("OFFLINE_EXECUTION_FORBIDDEN")


def _receipt(
    status: IngestStatus, reason: str | None = None,
    event: NormalizedMarketEventV1 | None = None, *,
    correction: bool = False, execution_eligible: bool = False,
    drained_receipts: tuple[IngestReceipt, ...] = (),
    source: Literal["INGRESS_CAPACITY", "INGRESS_CLOCK", "SINK"] | None = None,
    sink_count: int = 0,
) -> IngestReceipt:
    token = _ISSUING.set(True)
    try:
        return IngestReceipt(status, reason, event, correction, execution_eligible,
                             drained_receipts, source, sink_count, _issuer=_ISSUER)
    finally:
        _ISSUING.reset(token)


def is_issued_receipt(receipt: object) -> bool:
    """Verify an ingress-issued receipt before granting downstream authority."""
    return type(receipt) is IngestReceipt and receipt in _ISSUED


@dataclass(slots=True)
class _Pending:
    event: NormalizedMarketEventV1
    digest: str
    arrival_ns: int


@dataclass(frozen=True, slots=True)
class _Committed:
    digest: str
    event_time_ns: int
    native_trade_id: str | None
    native_sequence: int | None
    provider_session_id: str | None
    source_time_ns: int | None
    exchange_time_ns: int | None


@dataclass(slots=True)
class _SequenceCursor:
    maximum: int | None = None
    continuity_known: bool = False
    retained_keys: int = 0


@dataclass(slots=True)
class _StreamState:
    committed: dict[str, _Committed] = field(default_factory=dict)
    committed_by_time: list[tuple[int, str]] = field(default_factory=list)
    watermark_ns: int | None = None
    active_session_id: str | None = None
    sequence_by_session: dict[str | None, _SequenceCursor] = field(default_factory=dict)
    queue: list[_Pending] = field(default_factory=list)
    retry_pending: _Pending | None = None
    fault_pending: _Pending | None = None
    health: _SourceHealth = field(default_factory=_SourceHealth)


class NormalizedIngress(NoCopy):
    """Single-process bounded producer with explicit caller-driven live draining.

    BUFFERED is nonterminal. Pre-sink BACKPRESSURE retains nothing, and its caller
    may resubmit under normal event-time rules. Sink BACKPRESSURE holds one item;
    retry() or resubmission re-offers that same copy while later releases block.
    SINK_FAULT requires recover() and an idempotent sink. No method asserts
    execution eligibility.
    """

    _POLICY_FIELDS = frozenset({
        "sequence_policy", "sequence_policy_version", "historical_range_ns",
        "max_committed_keys", "dedupe_window_ns", "hot_window_ns",
        "hot_max_messages", "correction_window_ns",
    })

    def __setattr__(self, name: str, value: object) -> None:
        if name in self._POLICY_FIELDS and getattr(self, "_policy_frozen", False):
            raise MarketDataValueError("POLICY_IMMUTABLE")
        object.__setattr__(self, name, value)

    def __init__(
        self,
        normalizer: NormalizerPort,
        sink: IngressSink,
        *,
        clock_ns: Callable[[], int] = time.time_ns,
        arrival_clock_ns: Callable[[], int] = time.monotonic_ns,
        sequence_policy: SequencePolicy | Mapping[tuple[str, str], SequencePolicy] = "unavailable",
        sequence_policy_version: str = "sequence-policy/1",
        historical_range_ns: tuple[int, int] | None = None,
        max_committed_keys: int = 50_000,
        dedupe_window_ns: int = 24 * 60 * 60 * 1_000_000_000,
        hot_window_ns: int = 150_000_000,
        hot_max_messages: int = 500,
        correction_window_ns: int = 2_000_000_000,
    ) -> None:
        bounds = (
            (max_committed_keys, 1, 50_000),
            (dedupe_window_ns, 24 * 60 * 60 * 1_000_000_000, None),
            (hot_window_ns, 1, 150_000_000),
            (hot_max_messages, 1, 500),
            (correction_window_ns, 1, 2_000_000_000),
        )
        if any(type(value) is not int for value, _, _ in bounds):
            raise MarketDataValueError("INVALID_INTEGER")
        if any(value < lower
               or (upper is not None and value > upper)
               for value, lower, upper in bounds):
            raise MarketDataValueError("POLICY_OUT_OF_BOUNDS")
        if (historical_range_ns is not None
                and isinstance(historical_range_ns, tuple)
                and len(historical_range_ns) == 2
                and any(type(value) is not int for value in historical_range_ns)):
            raise MarketDataValueError("INVALID_INTEGER")
        if historical_range_ns is not None and (
            not isinstance(historical_range_ns, tuple)
            or len(historical_range_ns) != 2
            or any(type(value) is not int or not 0 < value <= INT64_MAX
                   for value in historical_range_ns)
            or historical_range_ns[0] > historical_range_ns[1]
        ):
            raise MarketDataValueError("POLICY_OUT_OF_BOUNDS")
        if (not isinstance(sequence_policy_version, str)
                or not sequence_policy_version
                or sequence_policy_version.strip() != sequence_policy_version):
            raise MarketDataValueError("POLICY_OUT_OF_BOUNDS")
        allowed_policies = {
            "contiguous", "monotonic_noncontiguous_session_reset", "unavailable",
        }
        if isinstance(sequence_policy, Mapping):
            if any(not isinstance(key, tuple) or len(key) != 2
                   or any(not isinstance(part, str) or not part for part in key)
                   or policy not in allowed_policies
                   for key, policy in sequence_policy.items()):
                raise MarketDataValueError("POLICY_OUT_OF_BOUNDS")
            sequence_policy = MappingProxyType(dict(sequence_policy))
        elif sequence_policy not in allowed_policies:
            raise MarketDataValueError("POLICY_OUT_OF_BOUNDS")
        self.normalizer = normalizer
        self.sink = sink
        self.clock_ns = clock_ns
        self.arrival_clock_ns = arrival_clock_ns
        self.sequence_policy = sequence_policy
        self.sequence_policy_version = sequence_policy_version
        self.historical_range_ns = historical_range_ns
        self.max_committed_keys = max_committed_keys
        self.dedupe_window_ns = dedupe_window_ns
        self.hot_window_ns = hot_window_ns
        self.hot_max_messages = hot_max_messages
        self.correction_window_ns = correction_window_ns
        self._streams: dict[StreamKey, _StreamState] = {}
        self._node_clock_offset_ms: float | None = None
        self._policy_frozen = True

    def set_trusted_node_clock_offset_ms(self, offset_ms: float | None) -> None:
        if offset_ms is not None and (
            type(offset_ms) not in (int, float)
            or offset_ms != offset_ms or abs(offset_ms) == float("inf")
        ):
            raise MarketDataValueError("INVALID_NODE_OFFSET")
        self._node_clock_offset_ms = offset_ms

    @property
    def node_drift_alert(self) -> bool:
        return self._node_clock_offset_ms is not None and abs(self._node_clock_offset_ms) > 2

    @property
    def node_publish_blocked(self) -> bool:
        return self._node_clock_offset_ms is not None and abs(self._node_clock_offset_ms) > 10

    def ingest(self, record: VendorRecord) -> IngestReceipt:
        now_ns = self.clock_ns()
        arrival_ns = self.arrival_clock_ns()
        if type(arrival_ns) is not int or arrival_ns < 0:
            raise MarketDataValueError("INVALID_INTEGER")
        try:
            event = self.normalizer.normalize(record, now_ns=now_ns)
        except NormalizationError as exc:
            return _receipt(IngestStatus.QUARANTINED, reason=exc.reason)
        key = self.stream_key(event)
        state = self._streams.setdefault(key, _StreamState())
        digest = self.normalizer.semantic_digest(record, event)
        pending = _Pending(event, digest, arrival_ns)
        state.health.last_received_time_ns = event.received_time_ns
        state.health.last_provider_time_ns = event.source_time_ns
        state.health.last_exchange_time_ns = event.exchange_time_ns
        state.health.last_event_clock_adjusted = "clock_adjusted" in event.quality_flags
        if state.fault_pending is not None:
            state.health.unhealthy = True
            return _receipt(IngestStatus.SINK_FAULT, "STREAM_FAULTED", event)
        if self.historical_range_ns is not None and event.source_mode == "historical":
            start, end = self.historical_range_ns
            if not start <= event.event_time_ns <= end:
                return _receipt(IngestStatus.QUARANTINED, "OUTSIDE_HISTORICAL_RANGE", event)
        prior = state.committed.get(event.idempotency_key)
        if prior is not None:
            return _receipt(
                IngestStatus.DUPLICATE if prior.digest == digest else IngestStatus.QUARANTINED,
                "DUPLICATE" if prior.digest == digest else "QUARANTINED_CONFLICT", event,
            )
        if state.retry_pending is not None:
            retry = state.retry_pending
            if retry.event.idempotency_key != event.idempotency_key:
                state.health.unhealthy = True
                return _receipt(IngestStatus.BACKPRESSURE, "RETRY_PENDING", event,
                                     source="SINK")
            if retry.digest != digest:
                return _receipt(IngestStatus.QUARANTINED, "QUARANTINED_CONFLICT", event)
            return self._deliver(
                state, _Pending(retry.event, digest, arrival_ns),
                correction="late_correction" in retry.event.quality_flags,
            )
        for queued in state.queue:
            if queued.event.idempotency_key == event.idempotency_key:
                return _receipt(
                    IngestStatus.BUFFERED if queued.digest == digest else IngestStatus.QUARANTINED,
                    "ALREADY_BUFFERED" if queued.digest == digest else "QUARANTINED_CONFLICT",
                    event,
                )
        if event.source_mode == "live" and self.node_publish_blocked:
            state.health.unhealthy = True
            return _receipt(IngestStatus.BACKPRESSURE, "NODE_CLOCK_BLOCK", event,
                                 source="INGRESS_CLOCK")
        if (event.source_mode == "live" and state.watermark_ns is not None
                and event.event_time_ns < state.watermark_ns - self.correction_window_ns):
            state.health.late_count += 1
            return _receipt(IngestStatus.QUARANTINED, "TOO_LATE", event)
        if state.watermark_ns is not None and (
            event.event_time_ns < state.watermark_ns - self.dedupe_window_ns
        ):
            state.health.unhealthy = True
            return _receipt(IngestStatus.BACKPRESSURE, "DEDUPE_WINDOW_EXHAUSTED", event,
                                 source="INGRESS_CAPACITY")
        if event.source_mode != "live":
            correction = state.watermark_ns is not None and event.event_time_ns < state.watermark_ns
            return self._deliver(state, pending, correction=correction)
        if state.watermark_ns is not None and event.event_time_ns < state.watermark_ns:
            flagged = event.validated_update(
                quality_flags=tuple(sorted((*event.quality_flags, "late_correction"))),
            )
            return self._deliver(state, _Pending(flagged, digest, arrival_ns), correction=True)
        if len(state.queue) >= self.hot_max_messages:
            state.health.unhealthy = True
            return _receipt(IngestStatus.BACKPRESSURE, "HOT_BUFFER_FULL", event,
                                 source="INGRESS_CAPACITY")
        state.queue.append(pending)
        released: tuple[IngestReceipt, ...] = ()
        if len(state.queue) >= self.hot_max_messages or (
            state.queue and arrival_ns - min(item.arrival_ns for item in state.queue)
            >= self.hot_window_ns
        ):
            released = self._drain_stream(state, arrival_ns, force=True)
        return _receipt(IngestStatus.BUFFERED, "AWAITING_DRAIN", event,
                             drained_receipts=released)

    def drain(self, *, now_ns: int | None = None, stream: StreamKey | None = None,
              force: bool = False) -> tuple[IngestReceipt, ...]:
        if now_ns is not None and (type(now_ns) is not int or now_ns < 0):
            raise MarketDataValueError("INVALID_INTEGER")
        if type(force) is not bool:
            raise MarketDataValueError("INVALID_BOOLEAN")
        arrival_ns = self.arrival_clock_ns() if now_ns is None else now_ns
        if type(arrival_ns) is not int or arrival_ns < 0:
            raise MarketDataValueError("INVALID_INTEGER")
        keys = (stream,) if stream is not None else tuple(sorted(self._streams))
        receipts: list[IngestReceipt] = []
        for key in keys:
            state = self._streams.get(key)
            if state is not None:
                receipts.extend(self._drain_stream(state, arrival_ns, force=force))
        return tuple(receipts)

    def flush(self, *, now_ns: int | None = None, stream: StreamKey | None = None,
              force: bool = True) -> tuple[IngestReceipt, ...]:
        return self.drain(now_ns=now_ns, stream=stream, force=force)

    def recover(self, stream: StreamKey) -> IngestReceipt:
        """Explicitly re-offer the faulting identity to an idempotent sink."""
        state = self._streams.get(stream)
        if state is None or state.fault_pending is None:
            return _receipt(IngestStatus.QUARANTINED, "NO_SINK_FAULT")
        pending = state.fault_pending
        if pending.event.source_mode == "live" and self.node_publish_blocked:
            state.health.unhealthy = True
            return _receipt(IngestStatus.BACKPRESSURE, "NODE_CLOCK_BLOCK", pending.event,
                            source="INGRESS_CLOCK")
        state.fault_pending = None
        return self._deliver(state, pending,
                             correction="late_correction" in pending.event.quality_flags)

    def retry(self, stream: StreamKey) -> IngestReceipt:
        """Retry exactly the single held item after an explicit sink backpressure ACK."""
        state = self._streams.get(stream)
        if state is None or state.retry_pending is None:
            return _receipt(IngestStatus.QUARANTINED, "NO_SINK_RETRY")
        if state.fault_pending is not None:
            return _receipt(IngestStatus.SINK_FAULT, "STREAM_FAULTED",
                                 state.fault_pending.event)
        pending = state.retry_pending
        return self._deliver(state, pending,
                             correction="late_correction" in pending.event.quality_flags)

    def _drain_stream(self, state: _StreamState, arrival_ns: int, *,
                      force: bool) -> tuple[IngestReceipt, ...]:
        if (not state.queue or state.retry_pending is not None
                or state.fault_pending is not None):
            return ()
        if not force and len(state.queue) < self.hot_max_messages and (
            arrival_ns - min(item.arrival_ns for item in state.queue) < self.hot_window_ns
        ):
            return ()
        state.queue.sort(key=lambda item: (
            item.event.event_time_ns, item.event.provider, item.event.dataset,
            item.event.source_record_key or item.event.idempotency_key,
            item.event.idempotency_key,
        ))
        receipts: list[IngestReceipt] = []
        while state.queue:
            item = state.queue.pop(0)
            if state.watermark_ns is not None and item.event.event_time_ns < state.watermark_ns:
                lag_ns = state.watermark_ns - item.event.event_time_ns
                if lag_ns > self.correction_window_ns:
                    state.health.late_count += 1
                    receipts.append(_receipt(IngestStatus.QUARANTINED, "TOO_LATE",
                                                  item.event))
                    continue
                flagged = item.event.validated_update(
                    quality_flags=tuple(sorted((*item.event.quality_flags,
                                                "late_correction"))),
                )
                item = _Pending(flagged, item.digest, item.arrival_ns)
            result = self._deliver(state, item,
                                   correction="late_correction" in item.event.quality_flags)
            receipts.append(result)
            if result.source == "INGRESS_CLOCK":
                state.queue.insert(0, item)
            if result.status in (IngestStatus.BACKPRESSURE, IngestStatus.SINK_FAULT):
                break
        return tuple(receipts)

    def _deliver(self, state: _StreamState, pending: _Pending, *,
                 correction: bool) -> IngestReceipt:
        event = pending.event
        if event.sequence_policy_version != self.sequence_policy_version:
            event = event.validated_update(
                sequence_policy_version=self.sequence_policy_version,
            )
        old = state.committed.get(event.idempotency_key)
        if old is not None:
            return _receipt(
                IngestStatus.DUPLICATE if old.digest == pending.digest
                else IngestStatus.QUARANTINED,
                "DUPLICATE" if old.digest == pending.digest else "QUARANTINED_CONFLICT", event,
                correction=correction,
            )
        watermark = state.watermark_ns
        if watermark is not None and event.event_time_ns < watermark - self.dedupe_window_ns:
            state.health.unhealthy = True
            return self._backpressure(state, pending, "DEDUPE_WINDOW_EXHAUSTED", correction)
        prospective = max(watermark or event.event_time_ns, event.event_time_ns)
        if len(state.committed) >= self.max_committed_keys:
            stale = sum(1 for timestamp, _ in state.committed_by_time
                        if timestamp < prospective - self.dedupe_window_ns)
            if len(state.committed) - stale >= self.max_committed_keys:
                state.health.unhealthy = True
                return self._backpressure(
                    state, pending, "DEDUPE_CAPACITY_EXHAUSTED", correction,
                )
        flags = set(event.quality_flags)
        policy = self._policy(event)
        session = event.provider_session_id
        active_session = state.active_session_id
        session_cursor = state.sequence_by_session.get(session)
        active_cursor = state.sequence_by_session.get(active_session)
        new_session = bool(
            event.session_transition_confirmed and session is not None
            and session != active_session and state.sequence_by_session
        )
        # An unconfirmed new session cannot lower the previously ACKed floor.
        # A known old session uses its own floor, never the active session's.
        baseline = (None if new_session else
                    session_cursor.maximum if session_cursor is not None else
                    active_cursor.maximum if active_cursor is not None else None)
        if new_session:
            flags.add("RESET")
            if policy != "unavailable":
                flags.add("UNKNOWN_CONTINUITY")
        if event.native_sequence is None:
            flags.add("UNKNOWN_CONTINUITY")
        if policy != "unavailable" and event.native_sequence is not None:
            if baseline is not None and event.native_sequence < baseline:
                reason = (self._correction_lineage(state, event)
                          if correction and event.source_mode == "live"
                          else "SEQUENCE_REGRESSION")
                if reason is not None:
                    if reason == "SEQUENCE_REGRESSION":
                        state.health.sequence_regression_count += 1
                    elif reason == "LATE_CORRECTION":
                        state.health.late_count += 1
                    state.health.unhealthy = True
                    return _receipt(IngestStatus.QUARANTINED, reason, event)
            if policy == "contiguous" and not new_session:
                if (baseline is None or session_cursor is None
                        or not session_cursor.continuity_known
                        or session is None or session != active_session):
                    flags.add("UNKNOWN_CONTINUITY")
                elif event.native_sequence > baseline + 1:
                    missing_count = event.native_sequence - baseline - 1
                    buffered_between = {
                        item.event.native_sequence for item in state.queue
                        if item.event.native_sequence is not None
                        and item.event.provider_session_id == session
                        and baseline < item.event.native_sequence
                        < event.native_sequence
                    }
                    if len(buffered_between) < missing_count:
                        flags.add("gap_detected")
        if flags != set(event.quality_flags):
            event = event.validated_update(quality_flags=tuple(sorted(flags)))
        if event.source_mode == "live" and self.node_publish_blocked:
            state.health.unhealthy = True
            return _receipt(IngestStatus.BACKPRESSURE, "NODE_CLOCK_BLOCK", event,
                            correction=correction, source="INGRESS_CLOCK")
        try:
            ack = self.sink.accept(event)
        except Exception:
            return self._sink_fault(state, pending, event, correction)
        if not isinstance(ack, SinkAck):
            return self._sink_fault(state, pending, event, correction)
        if not ack.accepted:
            state.health.unhealthy = True
            return self._backpressure(state, pending, "SINK_BACKPRESSURE", correction)
        state.retry_pending = None
        cutoff = prospective - self.dedupe_window_ns
        while state.committed_by_time and state.committed_by_time[0][0] < cutoff:
            _, stale_key = heapq.heappop(state.committed_by_time)
            stale_commit = state.committed.pop(stale_key)
            stale_cursor = state.sequence_by_session[stale_commit.provider_session_id]
            stale_cursor.retained_keys -= 1
            if (stale_cursor.retained_keys == 0
                    and stale_commit.provider_session_id != state.active_session_id):
                del state.sequence_by_session[stale_commit.provider_session_id]
        initial_known_session = (
            active_session is None and not state.sequence_by_session
            and session is not None
        )
        session_cursor = state.sequence_by_session.get(session)
        state.committed[event.idempotency_key] = _Committed(
            pending.digest, event.event_time_ns, event.native_trade_id,
            event.native_sequence, event.provider_session_id,
            event.source_time_ns, event.exchange_time_ns,
        )
        heapq.heappush(state.committed_by_time, (event.event_time_ns, event.idempotency_key))
        state.watermark_ns = prospective
        if initial_known_session or new_session:
            state.active_session_id = session
        if new_session or session_cursor is None:
            session_cursor = _SequenceCursor(
                retained_keys=session_cursor.retained_keys
                if session_cursor is not None else 0,
            )
            state.sequence_by_session[session] = session_cursor
        if new_session:
            session_cursor.maximum = event.native_sequence
        elif event.native_sequence is not None:
            session_cursor.maximum = max(session_cursor.maximum or 0,
                                         event.native_sequence)
        session_cursor.continuity_known = bool(
            policy == "contiguous" and event.native_sequence is not None
            and session is not None
        )
        session_cursor.retained_keys += 1
        if (new_session and active_session in state.sequence_by_session
                and active_session != session):
            prior_cursor = state.sequence_by_session[active_session]
            if prior_cursor.retained_keys == 0:
                del state.sequence_by_session[active_session]
        health = state.health
        health.last_processed_time_ns = event.processing_time_ns
        health.gap_count += "gap_detected" in event.quality_flags
        health.late_count += correction
        health.unhealthy = False
        return _receipt(IngestStatus.ACCEPTED, "SINK_ACK", event,
                        correction=correction, sink_count=1)

    def _backpressure(self, state: _StreamState, pending: _Pending, reason: str,
                      correction: bool) -> IngestReceipt:
        if reason == "SINK_BACKPRESSURE":
            state.retry_pending = pending
        return _receipt(IngestStatus.BACKPRESSURE, reason, pending.event,
                             correction=correction,
                             source="SINK" if reason == "SINK_BACKPRESSURE"
                             else "INGRESS_CAPACITY")

    def _sink_fault(self, state: _StreamState, pending: _Pending,
                    event: NormalizedMarketEventV1, correction: bool) -> IngestReceipt:
        state.fault_pending = pending
        state.health.unhealthy = True
        state.health.fault_count += 1
        return _receipt(IngestStatus.SINK_FAULT, "SINK_FAULT", event,
                             correction=correction)

    def _correction_lineage(self, state: _StreamState,
                            event: NormalizedMarketEventV1) -> str | None:
        native = event.native_provenance
        if native.correction not in ("correction", "cancel"):
            return "SEQUENCE_REGRESSION"
        ref_id = native.referenced_native_id
        ref_sequence = native.referenced_native_sequence
        session = event.provider_session_id
        if session is None or (ref_id is None and ref_sequence is None):
            return "SEQUENCE_REGRESSION"
        originals = tuple(
            (key, committed) for key, committed in state.committed.items()
            if committed.provider_session_id == session
        )
        by_id = tuple(
            (key, committed) for key, committed in originals
            if ref_id is not None and (ref_id == key or ref_id == committed.native_trade_id)
        )
        by_sequence = tuple(
            (key, committed) for key, committed in originals
            if ref_sequence is not None and ref_sequence == committed.native_sequence
        )
        if ref_id is not None and ref_sequence is not None:
            if len(by_id) == 1 and len(by_sequence) == 1:
                if by_id[0][0] != by_sequence[0][0]:
                    return "CORRECTION_LINEAGE_CONFLICT"
            elif (len(by_id) == 1) != (len(by_sequence) == 1):
                return "CORRECTION_LINEAGE_CONFLICT"
            else:
                return "SEQUENCE_REGRESSION"
        elif ((ref_id is not None and len(by_id) != 1)
              or (ref_sequence is not None and len(by_sequence) != 1)):
            return "SEQUENCE_REGRESSION"
        original = by_id[0][1] if ref_id is not None else by_sequence[0][1]
        if event.source_time_ns is not None and original.source_time_ns is not None:
            correction_time, original_time = event.source_time_ns, original.source_time_ns
        elif event.exchange_time_ns is not None and original.exchange_time_ns is not None:
            correction_time, original_time = event.exchange_time_ns, original.exchange_time_ns
        else:
            return "SEQUENCE_REGRESSION"
        age_ns = correction_time - original_time
        if age_ns < 0:
            return "SEQUENCE_REGRESSION"
        if age_ns > self.correction_window_ns:
            return "LATE_CORRECTION"
        return None

    def _policy(self, event: NormalizedMarketEventV1) -> SequencePolicy:
        if isinstance(self.sequence_policy, Mapping):
            return self.sequence_policy.get((event.provider, event.channel), "unavailable")
        return self.sequence_policy

    @staticmethod
    def stream_key(event: NormalizedMarketEventV1) -> StreamKey:
        return (event.provider, event.dataset, event.venue,
                event.instrument_id, event.channel)

    def health(self, stream: StreamKey) -> SourceHealthSnapshot:
        state = self._streams.get(stream, _StreamState())
        health = state.health
        return SourceHealthSnapshot(
            *stream,
            last_received_time_ns=health.last_received_time_ns,
            last_processed_time_ns=health.last_processed_time_ns,
            last_provider_time_ns=health.last_provider_time_ns,
            last_exchange_time_ns=health.last_exchange_time_ns,
            gap_count=health.gap_count,
            late_count=health.late_count,
            node_clock_offset_ms=self._node_clock_offset_ms,
            node_drift_alert=self.node_drift_alert,
            node_publish_blocked=self.node_publish_blocked,
            last_event_clock_adjusted=health.last_event_clock_adjusted,
            queued_count=len(state.queue),
            queue_pressure=len(state.queue) / self.hot_max_messages,
            unhealthy=health.unhealthy or state.retry_pending is not None
            or state.fault_pending is not None or self.node_publish_blocked,
            freshness="DEGRADED" if self.node_publish_blocked else "UNKNOWN",
            faulted=state.fault_pending is not None,
            fault_count=health.fault_count,
            sequence_regression_count=health.sequence_regression_count,
        )

    def committed_count(self, stream: StreamKey) -> int:
        state = self._streams.get(stream)
        return len(state.committed) if state is not None else 0

    def queued_count(self, stream: StreamKey) -> int:
        state = self._streams.get(stream)
        return len(state.queue) if state is not None else 0
