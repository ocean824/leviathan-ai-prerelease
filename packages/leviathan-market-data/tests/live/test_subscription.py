from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, Inexact, localcontext

import pytest

from leviathan_market_data.live import (
    FreshnessPolicyV1,
    LiveStateError,
    LiveSubscriptionKernel,
    LiveSubscriptionV1,
    make_live_heartbeat,
    make_live_subscription,
    reconnect_backoff_ns,
    validate_envelope_size,
)


@dataclass
class FakeClock:
    utc: int = 1_800_000_000_000_000_000
    monotonic: int = 10_000_000_000

    def utc_now_ns(self) -> int:
        return self.utc

    def monotonic_ns(self) -> int:
        return self.monotonic


class FakeSource:
    def __init__(self) -> None:
        self.subscriptions: list[tuple[LiveSubscriptionV1, str | None]] = []
        self.unsubscriptions: list[LiveSubscriptionV1] = []
        self.next_token: str | None = "resume-opaque"
        self.frames: tuple[object, ...] = ()
        self.raise_on_unsubscribe = False

    def subscribe(
        self, subscription: LiveSubscriptionV1, resume_token: str | None
    ) -> str | None:
        self.subscriptions.append((subscription, resume_token))
        return self.next_token

    def unsubscribe(self, subscription: LiveSubscriptionV1) -> None:
        self.unsubscriptions.append(subscription)
        if self.raise_on_unsubscribe:
            raise RuntimeError("SYNTHETIC_UNSUBSCRIBE_CANARY")

    def poll(self, subscription: LiveSubscriptionV1) -> tuple[object, ...]:
        del subscription
        return self.frames


def make_spec(instrument_id: str = "ABC") -> LiveSubscriptionV1:
    return make_live_subscription(
        provider="fake",
        dataset="equities",
        venue="XNAS",
        instrument_id=instrument_id,
        channel="trades",
        session_id="session-1",
        heartbeat_interval_ns=1_000_000_000,
        sequence_policy="unavailable",
        required_group="test-streams",
    )


def setup() -> tuple[FakeClock, FakeSource, LiveSubscriptionKernel, LiveSubscriptionV1]:
    clock = FakeClock()
    source = FakeSource()
    kernel = LiveSubscriptionKernel(clock=clock, source=source, max_streams=128)
    spec = make_spec()
    kernel.subscribe(spec, entitlement="GRANTED")
    kernel.set_node_drift(spec.stream_key, Decimal("0"))
    kernel.set_entitlement(spec.stream_key, "GRANTED")
    kernel.set_node_drift(spec.stream_key, Decimal("0"))
    return clock, source, kernel, spec


def test_subscription_starts_unknown_then_heartbeat_uses_injected_clock() -> None:
    clock = FakeClock()
    source = FakeSource()
    spec = make_spec()
    kernel = LiveSubscriptionKernel(
        clock=clock,
        source=source,
        max_streams=128,
        required_groups={"test-streams": (spec.stream_key,)},
    )

    initial = kernel.subscribe(spec, entitlement="GRANTED")
    assert initial.state == "UNKNOWN"
    assert initial.reason_codes == ("HEARTBEAT_UNKNOWN",)
    assert source.subscriptions == [(spec, None)]

    kernel.set_node_drift(spec.stream_key, Decimal("0"))
    result = kernel.on_heartbeat(
        spec.stream_key,
        session_id="session-1",
        provider_time_ns=clock.utc - 1,
    )
    assert result.state == "HEALTHY"
    assert result.publication_allowed is True
    assert result.execution_eligible is False


@pytest.mark.parametrize(
    ("offset_ns", "expected_state", "reason"),
    [
        (2_000_000_000, "HEALTHY", ()),
        (2_000_000_001, "STALE", ("HEARTBEAT_STALE",)),
        (3_000_000_001, "STALE", ("HEARTBEAT_GAP",)),
    ],
)
def test_heartbeat_age_boundaries_fail_closed(
    offset_ns: int, expected_state: str, reason: tuple[str, ...]
) -> None:
    clock, _, kernel, spec = setup()
    kernel.on_heartbeat(
        spec.stream_key,
        session_id="session-1",
    )
    clock.monotonic += offset_ns

    verdict = kernel.evaluate(spec.stream_key)

    assert verdict.state == expected_state
    assert verdict.reason_codes == reason
    assert verdict.publication_allowed is (expected_state == "HEALTHY")


@pytest.mark.parametrize(
    ("drift_ms", "expected_state", "expected_reason"),
    [
        (Decimal("2"), "HEALTHY", ()),
        (Decimal("2.0001"), "DEGRADED", ("CLOCK_DRIFT_ALERT",)),
        (Decimal("10"), "DEGRADED", ("CLOCK_DRIFT_ALERT",)),
        (Decimal("10.0001"), "STALE", ("DRIFT_EXCEEDED",)),
    ],
)
def test_clock_drift_thresholds_are_exact(
    drift_ms: Decimal, expected_state: str, expected_reason: tuple[str, ...]
) -> None:
    _, _, kernel, spec = setup()
    kernel.on_heartbeat(
        spec.stream_key,
        session_id="session-1",
    )
    kernel.set_node_drift(spec.stream_key, drift_ms)

    verdict = kernel.evaluate(spec.stream_key)

    assert verdict.state == expected_state
    assert verdict.reason_codes == expected_reason
    assert verdict.publication_allowed is (expected_state in ("HEALTHY", "DEGRADED"))


@pytest.mark.parametrize(
    ("mutate", "expected_state", "expected_reason"),
    [
        (lambda k, s: k.set_halt(True), "HALTED", ("GLOBAL_HALT",)),
        (
            lambda k, s: k.set_entitlement(s.stream_key, "UNKNOWN"),
            "UNENTITLED",
            ("ENTITLEMENT_UNKNOWN",),
        ),
        (
            lambda k, s: k.set_entitlement(s.stream_key, "DENIED"),
            "UNENTITLED",
            ("ENTITLEMENT_DENIED",),
        ),
        (lambda k, s: k.set_source_status(s.stream_key, "HALTED"), "HALTED", ("SOURCE_HALTED",)),
        (
            lambda k, s: k.set_source_status(s.stream_key, "DISCONNECTED"),
            "DISCONNECTED",
            ("SOURCE_DISCONNECTED",),
        ),
    ],
)
def test_halt_entitlement_and_disconnect_fail_closed(
    mutate, expected_state, expected_reason
) -> None:
    _, _, kernel, spec = setup()
    mutate(kernel, spec)

    verdict = kernel.evaluate(spec.stream_key)

    assert verdict.state == expected_state
    assert verdict.reason_codes == expected_reason
    assert verdict.publication_allowed is False


def test_unknown_drift_and_missing_required_stream_fail_closed() -> None:
    clock = FakeClock()
    source = FakeSource()
    spec = make_spec()
    kernel = LiveSubscriptionKernel(
        clock=clock,
        source=source,
        max_streams=128,
        required_groups={"test-streams": (spec.stream_key,)},
    )
    assert kernel.evaluate_required()[0].reason_codes == ("REQUIRED_STREAM_MISSING",)
    kernel.subscribe(spec, entitlement="GRANTED")
    kernel.on_heartbeat(
        spec.stream_key,
        session_id="session-1",
    )
    verdict = kernel.evaluate(spec.stream_key)
    assert verdict.state == "UNKNOWN"
    assert verdict.reason_codes == ("CLOCK_DRIFT_UNKNOWN",)
    assert verdict.publication_allowed is False


def test_session_mismatch_disconnects_and_never_claims_freshness() -> None:
    _, _, kernel, spec = setup()
    verdict = kernel.on_heartbeat(
        spec.stream_key,
        session_id="wrong-session",
    )
    assert verdict.state == "DISCONNECTED"
    assert verdict.reason_codes == ("SESSION_MISMATCH",)
    assert verdict.publication_allowed is False


def test_reconnect_forwards_exact_resume_token_and_returns_bounded_delay() -> None:
    clock, source, kernel, spec = setup()
    source.next_token = "token-as-provider-returned"
    health, delay = kernel.reconnect(spec.stream_key, attempt=5, jitter_basis_points=5_000)

    assert source.subscriptions[-1] == (spec, "resume-opaque")
    assert health.resume_token == "token-as-provider-returned"
    assert health.state == "UNKNOWN"
    assert delay == 2_600_000_000
    assert reconnect_backoff_ns(99, 10_000) == 5_000_000_000
    assert reconnect_backoff_ns(0, 0) == 200_000_000
    assert clock.monotonic == 10_000_000_000


def test_source_port_emits_issued_typed_heartbeat_frames() -> None:
    clock = FakeClock()
    source = FakeSource()
    kernel = LiveSubscriptionKernel(clock=clock, source=source, max_streams=128)
    spec = make_spec()
    kernel.subscribe(spec, entitlement="GRANTED")
    kernel.set_node_drift(spec.stream_key, Decimal("0"))
    kernel.set_node_drift(spec.stream_key, Decimal("0"))
    source.frames = (
        make_live_heartbeat(
            session_id="session-1",
            provider_time_ns=clock.utc - 10,
            resume_token="provider-token-1",
        ),
    )

    results = kernel.poll(spec.stream_key)

    assert len(results) == 1
    assert results[0].state == "HEALTHY"
    assert results[0].publication_allowed is True
    snapshot = kernel.health(spec.stream_key)
    assert snapshot.heartbeat_age_ns == 0
    assert snapshot.last_heartbeat_utc_ns == clock.utc
    assert snapshot.last_provider_time_ns == clock.utc - 10
    assert snapshot.evaluated_utc_ns == clock.utc


@pytest.mark.parametrize(
    ("frames", "reason"),
    [
        ((object(),), "INVALID_EVENT"),
        (tuple(object() for _ in range(1_025)), "SOURCE_BATCH_TOO_LARGE"),
    ],
)
def test_malformed_or_oversized_source_batch_disconnects(
    frames: tuple[object, ...], reason: str
) -> None:
    _, source, kernel, spec = setup()
    source.frames = frames

    verdicts = kernel.poll(spec.stream_key)

    assert len(verdicts) == 1
    assert verdicts[0].state == "DISCONNECTED"
    assert verdicts[0].reason_codes == (reason,)
    assert kernel.evaluate(spec.stream_key).state == "DISCONNECTED"


def test_poll_preflights_entire_batch_before_returning_any_allowed_verdict() -> None:
    _, source, kernel, spec = setup()
    source.frames = (
        make_live_heartbeat(session_id="session-1"),
        object(),
    )

    verdicts = kernel.poll(spec.stream_key)

    assert len(verdicts) == 1
    assert verdicts[0].state == "DISCONNECTED"
    assert verdicts[0].reason_codes == ("INVALID_EVENT",)
    snapshot = kernel.health(spec.stream_key)
    assert snapshot.last_heartbeat_monotonic_ns is None


def test_disconnected_stream_requires_explicit_reconnect_before_heartbeat_recovery() -> None:
    clock, _, kernel, spec = setup()
    kernel.set_source_status(spec.stream_key, "DISCONNECTED")

    denied = kernel.on_heartbeat(spec.stream_key, session_id="session-1")
    assert denied.reason_codes == ("SOURCE_DISCONNECTED",)
    assert not denied.publication_allowed

    kernel.reconnect(spec.stream_key, attempt=0, jitter_basis_points=0)
    recovered = kernel.on_heartbeat(spec.stream_key, session_id="session-1")
    assert recovered.publication_allowed
    assert kernel.health(spec.stream_key).last_heartbeat_utc_ns == clock.utc


def test_unsubscribe_marks_stream_disconnected() -> None:
    _, source, kernel, spec = setup()
    health = kernel.unsubscribe(spec.stream_key)
    assert source.unsubscriptions == [spec]
    assert health.state == "DISCONNECTED"


def test_subscribe_rate_limit_is_ten_per_second() -> None:
    clock = FakeClock()
    source = FakeSource()
    kernel = LiveSubscriptionKernel(clock=clock, source=source, max_streams=128)
    for index in range(10):
        kernel.subscribe(make_spec(f"SYM{index}"))

    with pytest.raises(LiveStateError) as raised:
        kernel.subscribe(make_spec("SYM10"))
    assert raised.value.code == "RATE_LIMITED"
    clock.monotonic += 1_000_000_000
    assert kernel.subscribe(make_spec("SYM10")).state == "UNENTITLED"


def test_policy_rejects_looser_or_bool_thresholds() -> None:
    with pytest.raises(LiveStateError) as raised:
        FreshnessPolicyV1(stale_multiplier=3)
    assert raised.value.code == "INVALID_POLICY"
    with pytest.raises(LiveStateError) as raised:
        FreshnessPolicyV1(subscribe_limit_per_second=True)
    assert raised.value.code == "INVALID_POLICY"


def test_reconnect_jitter_and_envelope_caps_are_closed_and_bounded() -> None:
    assert reconnect_backoff_ns(3, 0) == 200_000_000
    assert reconnect_backoff_ns(3, 10_000) == 1_600_000_000
    validate_envelope_size(b"x" * 65_536)
    with pytest.raises(LiveStateError) as raised:
        validate_envelope_size(b"x" * 65_537)
    assert raised.value.code == "ENVELOPE_TOO_LARGE"
    with pytest.raises(LiveStateError) as raised:
        validate_envelope_size(bytearray())  # type: ignore[arg-type]
    assert raised.value.code == "INVALID_ENVELOPE"


def test_retained_subscription_seal_is_rechecked_before_freshness_use() -> None:
    _, _, kernel, spec = setup()
    kernel.on_heartbeat(spec.stream_key, session_id=spec.session_id)
    object.__setattr__(spec, "heartbeat_interval_ns", 10_000_000_000)

    denied = kernel.evaluate(spec.stream_key)

    assert denied.state == "DISCONNECTED"
    assert denied.reason_codes == ("INVALID_SUBSCRIPTION",)
    assert not denied.publication_allowed


def test_drift_comparison_is_context_independent_and_num_bounded() -> None:
    _, _, kernel, spec = setup()
    kernel.on_heartbeat(spec.stream_key, session_id=spec.session_id)
    with localcontext() as context:
        context.prec = 2
        context.traps[Inexact] = True
        kernel.set_node_drift(spec.stream_key, Decimal("10.0001"))
        denied = kernel.evaluate(spec.stream_key)
    assert denied.state == "STALE"
    assert denied.reason_codes == ("DRIFT_EXCEEDED",)
    assert not denied.publication_allowed
    with pytest.raises(LiveStateError) as raised:
        kernel.set_node_drift(spec.stream_key, Decimal("1E+100000"))
    assert raised.value.code == "INVALID_DRIFT"


def test_unsubscribe_failure_is_sanitized_and_fail_closed() -> None:
    _, source, kernel, spec = setup()
    kernel.on_heartbeat(spec.stream_key, session_id=spec.session_id)
    source.raise_on_unsubscribe = True

    health = kernel.unsubscribe(spec.stream_key)
    denied = kernel.evaluate(spec.stream_key)

    assert health.reason_codes == ("SOURCE_FAILURE",)
    assert denied.reason_codes == ("SOURCE_FAILURE",)
    assert not denied.publication_allowed
    assert "SYNTHETIC_UNSUBSCRIBE_CANARY" not in str(health.model_dump())


def test_monotonic_regression_is_sticky_until_explicit_reconnect() -> None:
    clock, _, kernel, spec = setup()
    kernel.on_heartbeat(spec.stream_key, session_id=spec.session_id)
    clock.monotonic -= 1
    regression = kernel.evaluate(spec.stream_key)
    clock.monotonic += 1
    heartbeat = kernel.on_heartbeat(spec.stream_key, session_id=spec.session_id)

    assert regression.reason_codes == ("MONOTONIC_CLOCK_REGRESSION",)
    assert heartbeat.reason_codes == ("MONOTONIC_CLOCK_REGRESSION",)
    assert not heartbeat.publication_allowed
    kernel.reconnect(spec.stream_key, attempt=0, jitter_basis_points=0)
    assert kernel.evaluate(spec.stream_key).state == "UNKNOWN"


def test_invalid_initial_resume_token_is_compensated_or_retained_fail_closed() -> None:
    clock = FakeClock()
    source = FakeSource()
    source.next_token = "invalid token"
    kernel = LiveSubscriptionKernel(clock=clock, source=source, max_streams=8)
    spec = make_spec()

    with pytest.raises(LiveStateError) as cleaned:
        kernel.subscribe(spec, entitlement="GRANTED")
    assert cleaned.value.code == "INVALID_RESUME_TOKEN"
    assert source.subscriptions == [(spec, None)]
    assert source.unsubscriptions == [spec]
    assert kernel.evaluate(spec.stream_key).reason_codes == ("REQUIRED_STREAM_MISSING",)

    retry_spec = make_spec("XYZ")
    source.raise_on_unsubscribe = True
    with pytest.raises(LiveStateError) as failed_cleanup:
        kernel.subscribe(retry_spec, entitlement="GRANTED")
    assert failed_cleanup.value.code == "SOURCE_FAILURE"
    assert "SYNTHETIC_UNSUBSCRIBE_CANARY" not in str(failed_cleanup.value)
    retained = kernel.health(retry_spec.stream_key)
    assert retained.reason_codes == ("SOURCE_FAILURE",)
    assert retained.resume_token is None
    assert not kernel.evaluate(retry_spec.stream_key).publication_allowed
    with pytest.raises(LiveStateError) as blocked_reconnect:
        kernel.reconnect(retry_spec.stream_key, attempt=0, jitter_basis_points=0)
    assert blocked_reconnect.value.code == "SOURCE_FAILURE"
    assert source.subscriptions.count((retry_spec, None)) == 1

    source.raise_on_unsubscribe = False
    kernel.unsubscribe(retry_spec.stream_key)
    with pytest.raises(LiveStateError) as missing:
        kernel.health(retry_spec.stream_key)
    assert missing.value.code == "SUBSCRIPTION_MISSING"


def test_invalid_reconnect_resume_token_compensates_and_retains_retry_state() -> None:
    _, source, kernel, spec = setup()
    source.next_token = "invalid token"

    with pytest.raises(LiveStateError) as cleanup_success:
        kernel.reconnect(spec.stream_key, attempt=0, jitter_basis_points=0)
    assert cleanup_success.value.code == "INVALID_RESUME_TOKEN"
    assert source.unsubscriptions == [spec]
    assert kernel.evaluate(spec.stream_key).reason_codes == ("REQUIRED_STREAM_MISSING",)

    # Recreate an active stream to exercise the reconnect compensation failure branch.
    active_spec = make_spec("QRS")
    source.next_token = "resume-valid"
    kernel.subscribe(active_spec, entitlement="GRANTED")
    source.next_token = "invalid token"
    source.raise_on_unsubscribe = True
    with pytest.raises(LiveStateError) as cleanup_failure:
        kernel.reconnect(active_spec.stream_key, attempt=0, jitter_basis_points=0)
    assert cleanup_failure.value.code == "SOURCE_FAILURE"
    retained = kernel.health(active_spec.stream_key)
    assert retained.reason_codes == ("SOURCE_FAILURE",)
    assert retained.resume_token == "resume-valid"
    assert not kernel.on_heartbeat(
        active_spec.stream_key, session_id=active_spec.session_id
    ).publication_allowed

    source.raise_on_unsubscribe = False
    kernel.unsubscribe(active_spec.stream_key)
    with pytest.raises(LiveStateError) as missing:
        kernel.health(active_spec.stream_key)
    assert missing.value.code == "SUBSCRIPTION_MISSING"
