"""Fake-port subscription lifecycle with injected UTC and monotonic clocks."""

from __future__ import annotations

from collections import deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal
from typing import Protocol

from leviathan_core.seal import SealError
from leviathan_core.seal import require as seal_require
from leviathan_market_data.schema import (
    DECIMAL_MAX_ADJUSTED_EXPONENT,
    DECIMAL_MAX_DIGITS,
    DECIMAL_PRECISION,
    INT64_MAX,
    MarketDataValueError,
    NormalizedMarketEventV1,
    exact_decimal,
)

from .freshness import FreshnessPolicyV1, evaluate_freshness, reconnect_backoff_ns
from .models import (
    EntitlementState,
    FreshnessState,
    FreshnessVerdictV1,
    LiveHeartbeatV1,
    LiveStateError,
    LiveSubscriptionV1,
    SourceState,
    StreamHealthV1,
    StreamKey,
    _is_issued_subscription,
    _issue_health,
    _issue_verdict,
    _valid_resume_token,
)

_RATE_WINDOW_NS = 1_000_000_000


class ClockPort(Protocol):
    """Clock seam used by every freshness boundary and test."""

    def utc_now_ns(self) -> int: ...

    def monotonic_ns(self) -> int: ...


class LiveSourcePort(Protocol):
    """Transport-neutral subscribe boundary; implementations are injected fakes here."""

    def subscribe(
        self, subscription: LiveSubscriptionV1, resume_token: str | None
    ) -> str | None: ...

    def unsubscribe(self, subscription: LiveSubscriptionV1) -> None: ...

    def poll(
        self, subscription: LiveSubscriptionV1
    ) -> Sequence[LiveHeartbeatV1 | NormalizedMarketEventV1]: ...


@dataclass(slots=True)
class _Stream:
    key: StreamKey
    spec: LiveSubscriptionV1
    entitlement: EntitlementState
    source_status: SourceState = "UNKNOWN"
    last_heartbeat_utc_ns: int | None = None
    last_heartbeat_monotonic_ns: int | None = None
    provider_time_ns: int | None = None
    # No trusted clock-drift sample means freshness remains UNKNOWN and fail closed.
    node_drift_ms: Decimal | None = None
    node_drift_ns: int | None = None
    resume_token: str | None = None
    active: bool = True
    monotonic_regression: bool = False
    last_observed_monotonic_ns: int | None = None
    forced_reason: str | None = None


class LiveSubscriptionKernel:
    """Own subscription and freshness state; contains no provider or route code."""

    def __init__(
        self,
        *,
        clock: ClockPort,
        source: LiveSourcePort,
        policy: FreshnessPolicyV1 | None = None,
        max_streams: int,
        required_groups: Mapping[str, Sequence[StreamKey]] | None = None,
    ) -> None:
        if type(max_streams) is not int or not 1 <= max_streams <= 50_000:
            raise LiveStateError("INVALID_POLICY")
        self._clock = clock
        self._source = source
        self._policy = policy or FreshnessPolicyV1()
        self._max_streams = max_streams
        self._streams: dict[StreamKey, _Stream] = {}
        self._required: dict[str, set[StreamKey]] = {}
        self._explicit_required: set[tuple[str, StreamKey]] = set()
        groups = required_groups or {}
        if len(groups) > max_streams:
            raise LiveStateError("CAPACITY_EXCEEDED")
        for group, keys in groups.items():
            if type(group) is not str or not group or group != group.strip() or len(group) > 128:
                raise LiveStateError("INVALID_POLICY")
            if type(keys) not in (tuple, list) or len(keys) > max_streams:
                raise LiveStateError("INVALID_POLICY")
            if any(not self._valid_key(key) for key in keys):
                raise LiveStateError("INVALID_POLICY")
            frozen_keys = set(keys)
            if len(frozen_keys) != len(keys):
                raise LiveStateError("INVALID_POLICY")
            self._required[group] = frozen_keys
            self._explicit_required.update((group, key) for key in frozen_keys)
        if self._known_stream_count() > max_streams:
            raise LiveStateError("CAPACITY_EXCEEDED")
        self._subscribe_times: deque[int] = deque()
        self._halted = False

    def subscribe(
        self,
        spec: LiveSubscriptionV1,
        *,
        entitlement: EntitlementState = "UNKNOWN",
        resume_token: str | None = None,
    ) -> StreamHealthV1:
        if not isinstance(spec, LiveSubscriptionV1) or not _is_issued_subscription(spec):
            raise LiveStateError("INVALID_SUBSCRIPTION")
        if entitlement not in ("GRANTED", "DENIED", "UNKNOWN"):
            raise LiveStateError("INVALID_STATE")
        key = spec.stream_key
        if key in self._streams:
            raise LiveStateError("SUBSCRIPTION_EXISTS")
        if len(self._streams) >= self._max_streams:
            raise LiveStateError("CAPACITY_EXCEEDED")
        if spec.required and not spec.required_group:
            raise LiveStateError("INVALID_POLICY")
        if resume_token is not None and not _valid_resume_token(resume_token):
            raise LiveStateError("INVALID_RESUME_TOKEN")
        if key not in self._known_keys() and self._known_stream_count() >= self._max_streams:
            raise LiveStateError("CAPACITY_EXCEEDED")
        self._record_subscribe()
        returned_token = self._source_subscribe(spec, resume_token)
        if returned_token is not None and not _valid_resume_token(returned_token):
            self._compensate_invalid_token(
                spec=spec,
                key=key,
                entitlement=entitlement,
                prior_token=resume_token,
            )
        now = self._monotonic()
        stream = _Stream(
            key=key,
            spec=spec,
            entitlement=entitlement,
            source_status="ACTIVE",
            resume_token=returned_token if returned_token is not None else resume_token,
            last_observed_monotonic_ns=now,
        )
        self._streams[key] = stream
        if spec.required:
            self._required.setdefault(spec.required_group or "", set()).add(key)
        return self._health(stream)

    def unsubscribe(self, key: StreamKey) -> StreamHealthV1:
        stream = self._stream(key)
        if not self._check_stream_spec(stream):
            return self._health(stream)
        try:
            self._source.unsubscribe(stream.spec)
        except Exception:
            stream.active = False
            stream.source_status = "UNKNOWN"
            stream.forced_reason = "SOURCE_FAILURE"
            return self._health(stream)
        stream.active = False
        stream.source_status = "DISCONNECTED"
        snapshot = self._health(stream)
        self._streams.pop(key, None)
        group = stream.spec.required_group
        if (
            stream.spec.required
            and group is not None
            and (group, key) not in self._explicit_required
        ):
            self._required.get(group, set()).discard(key)
        return snapshot

    def reconnect(
        self,
        key: StreamKey,
        *,
        attempt: int,
        jitter_basis_points: int,
    ) -> tuple[StreamHealthV1, int]:
        """Resume the same stream with its exact token and return delay, without sleeping."""
        stream = self._stream(key)
        if not self._check_stream_spec(stream):
            return self._health(stream), 0
        if not stream.active and stream.forced_reason == "SOURCE_FAILURE":
            raise LiveStateError("SOURCE_FAILURE") from None
        delay_ns = reconnect_backoff_ns(attempt, jitter_basis_points)
        self._record_subscribe()
        try:
            returned_token = self._source_subscribe(stream.spec, stream.resume_token)
        except LiveStateError:
            stream.active = False
            stream.source_status = "DISCONNECTED"
            raise
        if returned_token is not None and not _valid_resume_token(returned_token):
            self._compensate_invalid_token(
                spec=stream.spec,
                key=stream.key,
                entitlement=stream.entitlement,
                prior_token=stream.resume_token,
                existing=stream,
            )
        if returned_token is not None:
            stream.resume_token = returned_token
        now = self._monotonic()
        stream.last_heartbeat_utc_ns = None
        stream.last_heartbeat_monotonic_ns = None
        stream.provider_time_ns = None
        stream.active = True
        stream.source_status = "ACTIVE"
        stream.monotonic_regression = False
        stream.last_observed_monotonic_ns = now
        stream.forced_reason = None
        return self._health(stream), delay_ns

    def on_heartbeat(
        self,
        key: StreamKey,
        *,
        session_id: str,
        provider_time_ns: int | None = None,
        resume_token: str | None = None,
    ) -> FreshnessVerdictV1:
        stream = self._stream(key)
        if not self._check_stream_spec(stream):
            return self._verdict(stream, "INVALID_SUBSCRIPTION")
        received_monotonic_ns = self._observe_monotonic(stream)
        if stream.monotonic_regression:
            return self._verdict(stream, "MONOTONIC_CLOCK_REGRESSION")
        if stream.forced_reason is not None:
            return self._verdict(stream, stream.forced_reason)
        if not stream.active or stream.source_status != "ACTIVE":
            code = "SOURCE_HALTED" if stream.source_status == "HALTED" else "SOURCE_DISCONNECTED"
            return self._verdict(stream, code)
        if session_id != stream.spec.session_id:
            stream.source_status = "DISCONNECTED"
            return self._verdict(stream, "SESSION_MISMATCH")
        received_utc_ns = self._clock.utc_now_ns()
        self._utc(received_utc_ns)
        if provider_time_ns is not None:
            self._utc(provider_time_ns)
        if resume_token is not None and not _valid_resume_token(resume_token):
            raise LiveStateError("INVALID_RESUME_TOKEN")
        stream.last_heartbeat_utc_ns = received_utc_ns
        stream.last_heartbeat_monotonic_ns = received_monotonic_ns
        stream.provider_time_ns = provider_time_ns
        # Resume tokens are opaque; preserve the source value exactly.
        if resume_token is not None:
            stream.resume_token = resume_token
        stream.source_status = "ACTIVE"
        stream.forced_reason = None
        return self._verdict(stream)

    def poll(self, key: StreamKey) -> tuple[FreshnessVerdictV1, ...]:
        """Consume bounded typed frames from the source without publishing them."""
        stream = self._stream(key)
        if not self._check_stream_spec(stream):
            return (self._verdict(stream, "INVALID_SUBSCRIPTION"),)
        self._observe_monotonic(stream)
        if stream.monotonic_regression:
            return (self._verdict(stream, "MONOTONIC_CLOCK_REGRESSION"),)
        if not stream.active:
            return (self._verdict(stream, "SOURCE_DISCONNECTED"),)
        try:
            frames = self._source.poll(stream.spec)
        except Exception:
            stream.active = False
            stream.source_status = "DISCONNECTED"
            return (self._verdict(stream, "SOURCE_DISCONNECTED"),)
        if type(frames) not in (tuple, list) or len(frames) > 1_024:
            stream.active = False
            stream.source_status = "DISCONNECTED"
            reason = "SOURCE_BATCH_TOO_LARGE" if type(frames) in (tuple, list) else "INVALID_EVENT"
            return (self._verdict(stream, reason),)
        for frame in frames:
            if isinstance(frame, LiveHeartbeatV1) and self._valid_heartbeat(frame):
                if frame.session_id != stream.spec.session_id:
                    stream.active = False
                    stream.source_status = "DISCONNECTED"
                    return (self._verdict(stream, "SESSION_MISMATCH"),)
                continue
            if isinstance(frame, NormalizedMarketEventV1):
                event_key = (
                    frame.provider,
                    frame.dataset,
                    frame.venue,
                    frame.instrument_id,
                    frame.channel,
                    frame.provider_session_id,
                )
                if event_key == key:
                    continue
            stream.active = False
            stream.source_status = "DISCONNECTED"
            return (self._verdict(stream, "INVALID_EVENT"),)
        verdicts: list[FreshnessVerdictV1] = []
        for frame in frames:
            if isinstance(frame, LiveHeartbeatV1):
                verdicts.append(
                    self.on_heartbeat(
                        key,
                        session_id=frame.session_id,
                        provider_time_ns=frame.provider_time_ns,
                        resume_token=frame.resume_token,
                    )
                )
            elif isinstance(frame, NormalizedMarketEventV1):
                verdicts.append(self.authorize_publication(frame))
        return tuple(verdicts)

    def set_entitlement(self, key: StreamKey, state: EntitlementState) -> None:
        if state not in ("GRANTED", "DENIED", "UNKNOWN"):
            raise LiveStateError("INVALID_STATE")
        self._stream(key).entitlement = state

    def set_source_status(self, key: StreamKey, state: SourceState) -> None:
        if state not in ("ACTIVE", "HALTED", "DISCONNECTED", "UNKNOWN"):
            raise LiveStateError("INVALID_STATE")
        self._stream(key).source_status = state

    def set_node_drift(self, key: StreamKey, drift_ms: Decimal | int | None) -> None:
        stream = self._stream(key)
        if drift_ms is None:
            stream.node_drift_ms = None
            stream.node_drift_ns = None
            return
        if type(drift_ms) not in (Decimal, int):
            raise LiveStateError("INVALID_DRIFT")
        try:
            bounded = exact_decimal(str(drift_ms))
            if len(bounded.as_tuple().digits) > DECIMAL_MAX_DIGITS:
                raise MarketDataValueError("PRECISION_EXCEEDED")
            if bounded != 0 and abs(bounded.adjusted()) > DECIMAL_MAX_ADJUSTED_EXPONENT:
                raise MarketDataValueError("DECIMAL_OUT_OF_BOUNDS")
            sign, digits, exponent = bounded.as_tuple()
            if type(exponent) is not int:
                raise MarketDataValueError("INVALID_DECIMAL")
            coefficient = 0
            if len(digits) > DECIMAL_PRECISION:
                significant = len(digits)
                while significant > 1 and digits[significant - 1] == 0:
                    significant -= 1
                if significant > DECIMAL_PRECISION:
                    raise MarketDataValueError("PRECISION_EXCEEDED")
            for digit in digits:
                coefficient = coefficient * 10 + digit
            if coefficient == 0:
                nanoseconds = 0
            else:
                shift = exponent + 6
                if shift >= 0:
                    nanoseconds = coefficient * (10**shift)
                else:
                    divisor = 10 ** (-shift)
                    if coefficient % divisor:
                        raise MarketDataValueError("PRECISION_EXCEEDED")
                    nanoseconds = coefficient // divisor
                if sign:
                    nanoseconds = -nanoseconds
        except (MarketDataValueError, ValueError, OverflowError):
            raise LiveStateError("INVALID_DRIFT") from None
        stream.node_drift_ms = bounded
        stream.node_drift_ns = nanoseconds

    def set_halt(self, active: bool) -> None:
        if type(active) is not bool:
            raise LiveStateError("INVALID_STATE")
        self._halted = active

    def evaluate(self, key: StreamKey) -> FreshnessVerdictV1:
        stream = self._streams.get(key)
        if stream is None:
            return self._missing_verdict(key)
        if not self._check_stream_spec(stream):
            return self._verdict(stream, "INVALID_SUBSCRIPTION")
        return self._verdict(stream)

    def health(self, key: StreamKey) -> StreamHealthV1:
        """Return a sealed read-only health snapshot without changing subscription state."""
        stream = self._stream(key)
        if not self._check_stream_spec(stream):
            return self._health(stream)
        return self._health(stream)

    def authorize_publication(self, event: NormalizedMarketEventV1) -> FreshnessVerdictV1:
        """Return a freshness decision only; never modifies or publishes the event."""
        if not isinstance(event, NormalizedMarketEventV1):
            return self._standalone("INVALID_EVENT")
        if event.source_mode != "live" or event.reconstructed:
            return self._standalone("NON_LIVE_EVENT")
        if event.provider_session_id is None:
            return self._standalone("UNKNOWN_SESSION")
        key = (
            event.provider,
            event.dataset,
            event.venue,
            event.instrument_id,
            event.channel,
            event.provider_session_id,
        )
        stream = self._streams.get(key)
        if stream is None:
            return self._missing_verdict(key)
        if not self._check_stream_spec(stream):
            return self._verdict(stream, "INVALID_SUBSCRIPTION")
        group = stream.spec.required_group if stream.spec.required else None
        if group is not None:
            for required_key in sorted(self._required.get(group, set())):
                required_stream = self._streams.get(required_key)
                if required_stream is None:
                    return self._verdict(stream, "REQUIRED_STREAM_MISSING")
                if not self._check_stream_spec(required_stream):
                    return self._verdict(stream, "REQUIRED_STREAM_UNHEALTHY")
                required_verdict = self._verdict(required_stream)
                if not required_verdict.publication_allowed or required_verdict.state != "HEALTHY":
                    return self._verdict(stream, "REQUIRED_STREAM_UNHEALTHY")
        return self.evaluate(key)

    def evaluate_required(self) -> tuple[FreshnessVerdictV1, ...]:
        """Evaluate every declared required stream, including subscriptions not yet present."""
        return tuple(
            self.evaluate(key)
            for group in sorted(self._required)
            for key in sorted(self._required[group])
        )

    def _verdict(
        self, stream: _Stream, forced_reason: str | None = None
    ) -> FreshnessVerdictV1:
        valid_spec = self._check_stream_spec(stream)
        if not valid_spec:
            forced_reason = "INVALID_SUBSCRIPTION"
        if stream.monotonic_regression:
            forced_reason = "MONOTONIC_CLOCK_REGRESSION"
        if forced_reason is None and stream.forced_reason is not None:
            forced_reason = stream.forced_reason
        state: FreshnessState
        reasons: tuple[str, ...]
        age: int | None
        if forced_reason is not None:
            state = "STALE" if forced_reason == "MONOTONIC_CLOCK_REGRESSION" else "DISCONNECTED"
            reasons = (forced_reason,)
            age = None
        else:
            state, reasons, age = self._state(stream)
        allowed = state in ("HEALTHY", "DEGRADED")
        return _issue_verdict(
            stream_key=stream.key,
            state=state,
            evaluated_utc_ns=self._utc(self._clock.utc_now_ns()),
            publication_allowed=allowed,
            heartbeat_age_ns=age,
            node_drift_ms=stream.node_drift_ms,
            reason_codes=reasons,
        )

    def _health(self, stream: _Stream) -> StreamHealthV1:
        state: FreshnessState
        reasons: tuple[str, ...]
        age: int | None
        if not self._check_stream_spec(stream):
            state, reasons, age = "DISCONNECTED", ("INVALID_SUBSCRIPTION",), None
        elif stream.monotonic_regression:
            state, reasons, age = "STALE", ("MONOTONIC_CLOCK_REGRESSION",), None
        elif stream.forced_reason is not None:
            state, reasons, age = "DISCONNECTED", (stream.forced_reason,), None
        else:
            state, reasons, age = self._state(stream)
        return _issue_health(
            stream_key=stream.key,
            state=state,
            last_heartbeat_utc_ns=stream.last_heartbeat_utc_ns,
            last_heartbeat_monotonic_ns=stream.last_heartbeat_monotonic_ns,
            last_provider_time_ns=stream.provider_time_ns,
            evaluated_utc_ns=self._utc(self._clock.utc_now_ns()),
            heartbeat_age_ns=age,
            node_drift_ms=stream.node_drift_ms,
            entitlement=stream.entitlement,
            source_status=stream.source_status,
            resume_token=stream.resume_token,
            reason_codes=reasons,
        )

    def _state(
        self, stream: _Stream
    ) -> tuple[FreshnessState, tuple[str, ...], int | None]:
        try:
            self._policy.__post_init__()
        except LiveStateError:
            return "UNKNOWN", ("INVALID_POLICY",), None
        if not self._check_stream_spec(stream):
            return "DISCONNECTED", ("INVALID_SUBSCRIPTION",), None
        now_monotonic_ns = self._observe_monotonic(stream)
        if stream.monotonic_regression:
            return "STALE", ("MONOTONIC_CLOCK_REGRESSION",), None
        return evaluate_freshness(
            now_monotonic_ns=now_monotonic_ns,
            heartbeat_interval_ns=stream.spec.heartbeat_interval_ns,
            last_heartbeat_monotonic_ns=stream.last_heartbeat_monotonic_ns,
            node_drift_ns=stream.node_drift_ns,
            entitlement=stream.entitlement,
            source_status=stream.source_status,
            halted=self._halted,
            active=stream.active,
            policy=self._policy,
        )

    def _missing_verdict(self, key: StreamKey) -> FreshnessVerdictV1:
        return _issue_verdict(
            stream_key=key,
            state="UNKNOWN",
            evaluated_utc_ns=self._utc(self._clock.utc_now_ns()),
            publication_allowed=False,
            heartbeat_age_ns=None,
            node_drift_ms=None,
            reason_codes=("REQUIRED_STREAM_MISSING",),
        )

    def _standalone(self, reason: str) -> FreshnessVerdictV1:
        return _issue_verdict(
            stream_key=None,
            state="UNKNOWN",
            evaluated_utc_ns=self._utc(self._clock.utc_now_ns()),
            publication_allowed=False,
            heartbeat_age_ns=None,
            node_drift_ms=None,
            reason_codes=(reason,),
        )

    def _stream(self, key: StreamKey) -> _Stream:
        try:
            return self._streams[key]
        except (KeyError, TypeError):
            raise LiveStateError("SUBSCRIPTION_MISSING") from None

    @staticmethod
    def _valid_key(key: object) -> bool:
        return (
            type(key) is tuple
            and len(key) == 6
            and all(type(part) is str and part and len(part) <= 128 for part in key)
        )

    def _known_keys(self) -> set[StreamKey]:
        return set(self._streams).union(*(keys for keys in self._required.values()))

    def _known_stream_count(self) -> int:
        return len(self._known_keys())

    def _check_stream_spec(self, stream: _Stream) -> bool:
        try:
            seal_require(stream.spec, "md004.subscription.v1")
        except SealError:
            pass
        else:
            if _is_issued_subscription(stream.spec) and stream.spec.stream_key == stream.key:
                return True
        stream.active = False
        stream.source_status = "UNKNOWN"
        stream.forced_reason = "INVALID_SUBSCRIPTION"
        return False

    def _observe_monotonic(self, stream: _Stream) -> int:
        now = self._monotonic()
        previous = stream.last_observed_monotonic_ns
        if previous is not None and now < previous:
            stream.monotonic_regression = True
        if previous is None or now > previous:
            stream.last_observed_monotonic_ns = now
        return now

    def _monotonic(self) -> int:
        value = self._clock.monotonic_ns()
        if type(value) is not int or not 0 <= value <= INT64_MAX:
            raise LiveStateError("INVALID_TIME")
        return value

    @staticmethod
    def _utc(value: int) -> int:
        if type(value) is not int or not 0 < value <= INT64_MAX:
            raise LiveStateError("INVALID_TIME")
        return value

    def _trim_subscribe_times(self, now: int) -> None:
        while self._subscribe_times and now - self._subscribe_times[0] >= _RATE_WINDOW_NS:
            self._subscribe_times.popleft()

    def _record_subscribe(self) -> None:
        now = self._monotonic()
        self._trim_subscribe_times(now)
        if len(self._subscribe_times) >= self._policy.subscribe_limit_per_second:
            raise LiveStateError("RATE_LIMITED")
        self._subscribe_times.append(now)

    def _source_subscribe(
        self, spec: LiveSubscriptionV1, resume_token: str | None
    ) -> str | None:
        try:
            seal_require(spec, "md004.subscription.v1")
        except SealError:
            raise LiveStateError("INVALID_SUBSCRIPTION") from None
        if not _is_issued_subscription(spec):
            raise LiveStateError("INVALID_SUBSCRIPTION")
        if resume_token is not None and not _valid_resume_token(resume_token):
            raise LiveStateError("INVALID_RESUME_TOKEN")
        try:
            returned_token = self._source.subscribe(spec, resume_token)
        except Exception:
            raise LiveStateError("SOURCE_FAILURE") from None
        return returned_token

    def _compensate_invalid_token(
        self,
        *,
        spec: LiveSubscriptionV1,
        key: StreamKey,
        entitlement: EntitlementState,
        prior_token: str | None,
        existing: _Stream | None = None,
    ) -> None:
        """Undo a remote subscribe with invalid token; retain only failed cleanup state."""
        cleanup_failed = False
        try:
            seal_require(spec, "md004.subscription.v1")
            self._source.unsubscribe(spec)
        except Exception:
            cleanup_failed = True
        if cleanup_failed:
            now = self._monotonic()
            stream = existing or _Stream(
                key=key,
                spec=spec,
                entitlement=entitlement,
                last_observed_monotonic_ns=now,
            )
            stream.active = False
            stream.source_status = "UNKNOWN"
            stream.last_heartbeat_utc_ns = None
            stream.last_heartbeat_monotonic_ns = None
            stream.provider_time_ns = None
            stream.resume_token = prior_token
            stream.forced_reason = "SOURCE_FAILURE"
            self._streams[key] = stream
            if spec.required:
                self._required.setdefault(spec.required_group or "", set()).add(key)
            raise LiveStateError("SOURCE_FAILURE") from None
        if existing is not None:
            existing.active = False
            existing.source_status = "DISCONNECTED"
            existing.last_heartbeat_utc_ns = None
            existing.last_heartbeat_monotonic_ns = None
            existing.provider_time_ns = None
            self._evict_stream(key, existing)
        raise LiveStateError("INVALID_RESUME_TOKEN") from None

    def _evict_stream(self, key: StreamKey, stream: _Stream) -> None:
        self._streams.pop(key, None)
        group = stream.spec.required_group
        if (
            stream.spec.required
            and group is not None
            and (group, key) not in self._explicit_required
        ):
            self._required.get(group, set()).discard(key)

    @staticmethod
    def _valid_heartbeat(frame: LiveHeartbeatV1) -> bool:
        try:
            seal_require(frame, "md004.heartbeat.v1")
        except SealError:
            return False
        return True
