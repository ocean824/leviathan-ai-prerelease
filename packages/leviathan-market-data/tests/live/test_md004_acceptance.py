from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import FrozenInstanceError
from decimal import Decimal, localcontext

import pytest
from pydantic import ValidationError

from leviathan_core.seal import SealError
from leviathan_market_data.live import (
    FreshnessPolicyV1,
    LiveStateError,
    LiveSubscriptionKernel,
    StreamKey,
    make_live_heartbeat,
    make_live_subscription,
    reconnect_backoff_ns,
    validate_envelope_size,
)
from leviathan_market_data.normalization import Normalizer, VendorRecord
from leviathan_market_data.schema import NormalizedMarketEventV1
from leviathan_market_data.symbology import InstrumentMapping, MappingRegistry

NS = 1_000_000_000
EVENT_NS = 1_770_000_000_000_000_000
HEARTBEAT_NS = 100 * NS


class FakeClock:
    def __init__(self, *, utc_ns: int = EVENT_NS + NS, monotonic_ns: int = 50 * NS) -> None:
        self.utc = utc_ns
        self.monotonic = monotonic_ns

    def utc_now_ns(self) -> int:
        return self.utc

    def monotonic_ns(self) -> int:
        return self.monotonic


class FakeLiveSource:
    def __init__(self, tokens: tuple[str | None, ...] = ("resume-1", "resume-2")) -> None:
        self.tokens = list(tokens)
        self.subscriptions: list[tuple[object, str | None]] = []
        self.unsubscriptions: list[object] = []
        self.frames: object = ()
        self.raise_on_subscribe = False
        self.raise_on_unsubscribe = False

    def subscribe(self, subscription: object, resume_token: str | None) -> str | None:
        if self.raise_on_subscribe:
            raise RuntimeError("synthetic source reconnect failure")
        self.subscriptions.append((subscription, resume_token))
        index = len(self.subscriptions) - 1
        return self.tokens[index] if index < len(self.tokens) else None

    def unsubscribe(self, subscription: object) -> None:
        self.unsubscriptions.append(subscription)
        if self.raise_on_unsubscribe:
            raise RuntimeError("SYNTHETIC_UNSUBSCRIBE_CANARY")

    def poll(self, subscription: object) -> object:
        return self.frames


def spec(
    instrument_id: str = "SYN-1",
    *,
    channel: str = "trades",
    session_id: str = "session-1",
    sequence_policy: str = "contiguous",
    required: bool = True,
    required_group: str | None = "synthetic-required",
):
    return make_live_subscription(
        provider="synthetic-feed",
        dataset="synthetic-v1",
        venue="XTEST",
        instrument_id=instrument_id,
        channel=channel,
        session_id=session_id,
        heartbeat_interval_ns=HEARTBEAT_NS,
        sequence_policy=sequence_policy,  # type: ignore[arg-type]
        required=required,
        required_group=required_group,
    )


def kernel(
    *,
    clock: FakeClock | None = None,
    source: FakeLiveSource | None = None,
    required_groups: Mapping[str, Sequence[StreamKey]] | None = None,
    max_streams: int = 128,
) -> tuple[LiveSubscriptionKernel, FakeClock, FakeLiveSource]:
    active_clock = clock or FakeClock()
    active_source = source or FakeLiveSource()
    instance = LiveSubscriptionKernel(
        clock=active_clock,
        source=active_source,
        required_groups=required_groups,
        max_streams=max_streams,
    )
    return instance, active_clock, active_source


def subscribe_granted(instance: LiveSubscriptionKernel, requested):
    return instance.subscribe(requested, entitlement="GRANTED")


def heartbeat(
    instance: LiveSubscriptionKernel,
    clock: FakeClock,
    subscription,
    *,
    session_id: str | None = None,
    resume_token: str | None = None,
):
    instance.set_node_drift(subscription.stream_key, Decimal("0"))
    return instance.on_heartbeat(
        subscription.stream_key,
        session_id=session_id or subscription.session_id,
        provider_time_ns=clock.utc,
        resume_token=resume_token,
    )


def live_event(*, source_mode: str = "live", session_id: str | None = "session-1"):
    mapping = InstrumentMapping(
        provider="synthetic-feed",
        dataset="synthetic-v1",
        venue="XTEST",
        native_symbol="SYN",
        instrument_id="SYN-1",
        leviathan_symbol="SYN",
        instrument_type="equity",
        mapping_version="synthetic-v1",
        tick_size="0.01",
    )
    record = VendorRecord(
        provider="synthetic-feed",
        dataset="synthetic-v1",
        venue="XTEST",
        native_symbol="SYN",
        channel="trades",
        event_type="trade",
        event_time_ns=EVENT_NS,
        source_record_ref="synthetic://md004/event-1",
        payload={"price": "12.50", "size": "2", "side": "buy"},
        source_mode=source_mode,  # type: ignore[arg-type]
        source_time_ns=EVENT_NS,
        exchange_time_ns=EVENT_NS,
        native_sequence=7,
        native_trade_id="synthetic-trade-7",
        provider_session_id=session_id,
    )
    return Normalizer(MappingRegistry((mapping,))).normalize(record, now_ns=EVENT_NS + NS)


def live_quote_event(*, session_id: str = "session-quote"):
    mapping = InstrumentMapping(
        provider="synthetic-feed",
        dataset="synthetic-v1",
        venue="XTEST",
        native_symbol="SYN",
        instrument_id="SYN-Q-1",
        leviathan_symbol="SYN",
        instrument_type="equity",
        mapping_version="synthetic-v1",
        tick_size="0.01",
    )
    record = VendorRecord(
        provider="synthetic-feed",
        dataset="synthetic-v1",
        venue="XTEST",
        native_symbol="SYN",
        channel="quotes",
        event_type="quote",
        event_time_ns=EVENT_NS,
        source_record_ref="synthetic://md004/quote-28",
        source_record_key="synthetic-quote-28",
        payload={
            "bid_present": True,
            "ask_present": True,
            "bid_price": "12.49",
            "ask_price": "12.51",
            "bid_size": "5",
            "ask_size": "8",
            "bid_time_ns": EVENT_NS,
            "ask_time_ns": EVENT_NS,
        },
        source_mode="live",
        source_time_ns=EVENT_NS,
        exchange_time_ns=EVENT_NS,
        native_sequence=28,
        provider_session_id=session_id,
    )
    return Normalizer(MappingRegistry((mapping,))).normalize(record, now_ns=EVENT_NS + NS)


def test_startup_is_unknown_until_heartbeat_and_required_absence_fails_closed() -> None:
    requested = spec()
    instance, clock, _source = kernel(
        required_groups={"synthetic-required": (requested.stream_key,)}
    )

    health = subscribe_granted(instance, requested)
    verdict = instance.evaluate(requested.stream_key)
    missing = instance.evaluate(
        ("synthetic-feed", "synthetic-v1", "XTEST", "MISSING", "trades", "s1")
    )

    assert health.state == "UNKNOWN"
    assert verdict.state == "UNKNOWN"
    assert not verdict.publication_allowed
    assert verdict.reason_codes == ("HEARTBEAT_UNKNOWN",)
    assert not instance.evaluate_required()[0].publication_allowed
    assert missing.state == "UNKNOWN"
    assert "REQUIRED_STREAM_MISSING" in missing.reason_codes
    assert heartbeat(instance, clock, requested).publication_allowed


def test_default_entitlement_is_unknown_and_requires_explicit_grant() -> None:
    requested = spec()
    instance, clock, _source = kernel()

    health = instance.subscribe(requested)
    assert health.entitlement == "UNKNOWN"
    denied = heartbeat(instance, clock, requested)
    assert denied.state == "UNENTITLED"
    assert denied.reason_codes == ("ENTITLEMENT_UNKNOWN",)
    assert not denied.publication_allowed

    instance.set_entitlement(requested.stream_key, "GRANTED")
    assert heartbeat(instance, clock, requested).publication_allowed


def test_missing_node_drift_fails_closed_after_heartbeat() -> None:
    requested = spec()
    instance, _clock, _source = kernel()
    subscribe_granted(instance, requested)
    verdict = instance.on_heartbeat(
        requested.stream_key, session_id=requested.session_id, provider_time_ns=EVENT_NS
    )
    assert verdict.state == "UNKNOWN"
    assert verdict.reason_codes == ("CLOCK_DRIFT_UNKNOWN",)
    assert not verdict.publication_allowed


def test_heartbeat_stale_and_gap_thresholds_are_strict_and_monotonic() -> None:
    requested = spec()
    instance, clock, _source = kernel()
    subscribe_granted(instance, requested)
    heartbeat(instance, clock, requested)

    clock.monotonic += HEARTBEAT_NS * 2
    at_two = instance.evaluate(requested.stream_key)
    assert at_two.heartbeat_age_ns == HEARTBEAT_NS * 2
    assert at_two.state == "HEALTHY"

    clock.monotonic += 1
    over_two = instance.evaluate(requested.stream_key)
    assert over_two.state == "STALE"
    assert over_two.reason_codes == ("HEARTBEAT_STALE",)

    clock.monotonic = 50 * NS + HEARTBEAT_NS * 3
    at_three = instance.evaluate(requested.stream_key)
    assert at_three.state == "STALE"
    assert at_three.reason_codes == ("HEARTBEAT_STALE",)
    clock.monotonic += 1
    over_three = instance.evaluate(requested.stream_key)
    assert over_three.reason_codes == ("HEARTBEAT_GAP",)
    assert not over_three.publication_allowed
    assert over_three.execution_eligible is False


def test_drift_alert_and_block_boundaries_use_exact_decimal_values() -> None:
    requested = spec()
    instance, clock, _source = kernel()
    subscribe_granted(instance, requested)
    heartbeat(instance, clock, requested)

    instance.set_node_drift(requested.stream_key, Decimal("2"))
    at_alert = instance.evaluate(requested.stream_key)
    assert at_alert.state == "HEALTHY"
    assert at_alert.node_drift_ms == Decimal("2")

    instance.set_node_drift(requested.stream_key, Decimal("2.001"))
    over_alert = instance.evaluate(requested.stream_key)
    assert over_alert.state == "DEGRADED"
    assert over_alert.reason_codes == ("CLOCK_DRIFT_ALERT",)
    assert over_alert.publication_allowed
    assert over_alert.execution_eligible is False

    instance.set_node_drift(requested.stream_key, Decimal("10"))
    at_block = instance.evaluate(requested.stream_key)
    assert at_block.state == "DEGRADED"
    instance.set_node_drift(requested.stream_key, Decimal("10.001"))
    over_block = instance.evaluate(requested.stream_key)
    assert over_block.state == "STALE"
    assert over_block.reason_codes == ("DRIFT_EXCEEDED",)
    assert not over_block.publication_allowed


@pytest.mark.parametrize(
    ("transition", "expected_state", "expected_reason"),
    [
        ("halt", "HALTED", "GLOBAL_HALT"),
        ("denied", "UNENTITLED", "ENTITLEMENT_DENIED"),
        ("unknown_entitlement", "UNENTITLED", "ENTITLEMENT_UNKNOWN"),
        ("source_halt", "HALTED", "SOURCE_HALTED"),
        ("source_disconnect", "DISCONNECTED", "SOURCE_DISCONNECTED"),
        ("source_unknown", "DISCONNECTED", "SOURCE_UNKNOWN"),
    ],
)
def test_halt_entitlement_and_source_states_fail_closed(
    transition: str, expected_state: str, expected_reason: str
) -> None:
    requested = spec()
    instance, clock, _source = kernel()
    subscribe_granted(instance, requested)
    heartbeat(instance, clock, requested)

    if transition == "halt":
        instance.set_halt(True)
    elif transition == "denied":
        instance.set_entitlement(requested.stream_key, "DENIED")
    elif transition == "unknown_entitlement":
        instance.set_entitlement(requested.stream_key, "UNKNOWN")
    else:
        status = {
            "source_halt": "HALTED",
            "source_disconnect": "DISCONNECTED",
            "source_unknown": "UNKNOWN",
        }[transition]
        instance.set_source_status(requested.stream_key, status)  # type: ignore[arg-type]

    verdict = instance.evaluate(requested.stream_key)
    assert verdict.state == expected_state
    assert expected_reason in verdict.reason_codes
    assert not verdict.publication_allowed
    assert verdict.execution_eligible is False


def test_subscribe_rate_limit_is_ten_per_monotonic_second() -> None:
    instance, clock, _source = kernel()
    for index in range(10):
        subscribe_granted(instance, spec(f"SYN-{index}"))

    with pytest.raises(LiveStateError) as caught:
        subscribe_granted(instance, spec("SYN-10"))
    assert caught.value.code == "RATE_LIMITED"
    assert str(caught.value) == "RATE_LIMITED"

    clock.monotonic += NS
    assert subscribe_granted(instance, spec("SYN-10")).state == "UNKNOWN"


def test_reconnect_resumes_exact_token_clears_heartbeat_and_reports_bounded_delay() -> None:
    requested = spec()
    instance, clock, source = kernel()
    subscribe_granted(instance, requested)
    heartbeat(instance, clock, requested)
    assert instance.evaluate(requested.stream_key).state == "HEALTHY"

    health, delay = instance.reconnect(requested.stream_key, attempt=4, jitter_basis_points=7_500)

    assert source.subscriptions == [(requested, None), (requested, "resume-1")]
    assert 200_000_000 <= delay <= 5_000_000_000
    assert health.resume_token == "resume-2"
    assert health.state == "UNKNOWN"
    assert not instance.evaluate(requested.stream_key).publication_allowed


def test_reconnect_backoff_and_envelope_byte_limits_are_deterministic() -> None:
    assert reconnect_backoff_ns(0, 0) == 200_000_000
    assert reconnect_backoff_ns(0, 10_000) == 200_000_000
    assert reconnect_backoff_ns(20, 10_000) == 5_000_000_000
    for invalid in ((True, 0), (0, True), (-1, 0), (0, 10_001)):
        with pytest.raises(LiveStateError) as caught:
            reconnect_backoff_ns(*invalid)
        assert caught.value.code == "INVALID_POLICY"

    validate_envelope_size(b"x" * 65_536)
    with pytest.raises(LiveStateError) as caught:
        validate_envelope_size(b"secret-synthetic-payload" * 3_000)
    assert caught.value.code == "ENVELOPE_TOO_LARGE"
    assert "secret-synthetic-payload" not in str(caught.value)
    with pytest.raises(LiveStateError) as caught:
        validate_envelope_size("not-bytes")  # type: ignore[arg-type]
    assert caught.value.code == "INVALID_ENVELOPE"


def test_replay_and_reconstructed_events_never_gain_live_publication_authority() -> None:
    requested = spec()
    instance, clock, _source = kernel()
    subscribe_granted(instance, requested)
    heartbeat(instance, clock, requested)

    historical = live_event(source_mode="historical")
    reconstructed = live_event(source_mode="reconstructed")
    assert isinstance(historical, NormalizedMarketEventV1)
    for event in (historical, reconstructed):
        verdict = instance.authorize_publication(event)
        assert not verdict.publication_allowed
        assert verdict.reason_codes == ("NON_LIVE_EVENT",)
        assert verdict.execution_eligible is False

    event = live_event()
    allowed = instance.authorize_publication(event)
    assert allowed.publication_allowed
    assert allowed.execution_eligible is False
    assert event.source_mode == "live"


def test_wrong_session_heartbeat_disconnects_and_wrong_session_event_stays_unknown() -> None:
    requested = spec()
    instance, clock, _source = kernel()
    subscribe_granted(instance, requested)

    verdict = heartbeat(instance, clock, requested, session_id="other-session")
    assert verdict.state == "DISCONNECTED"
    assert verdict.reason_codes == ("SESSION_MISMATCH",)
    assert not verdict.publication_allowed
    assert not instance.authorize_publication(
        live_event(session_id="other-session")
    ).publication_allowed


def test_noncontiguous_quote_policy_is_preserved_without_claiming_sequence_continuity() -> None:
    requested = spec(
        "SYN-Q-1",
        channel="quotes",
        sequence_policy="monotonic_noncontiguous_session_reset",
        required=False,
        required_group=None,
    )
    instance, _clock, source = kernel()
    health = subscribe_granted(instance, requested)
    quote = live_quote_event(session_id=requested.session_id)
    source.frames = (quote,)
    sequence_only = instance.poll(requested.stream_key)

    assert source.subscriptions[0][0].sequence_policy == ("monotonic_noncontiguous_session_reset")
    assert health.state == "UNKNOWN"
    assert quote.native_sequence == 28
    assert sequence_only[0].state == "UNKNOWN"
    assert not sequence_only[0].publication_allowed
    assert sequence_only[0].reason_codes == ("HEARTBEAT_UNKNOWN",)
    assert sequence_only[0].execution_eligible is False


def test_poll_captures_clocks_and_returns_verdicts_without_publishing() -> None:
    requested = spec()
    instance, clock, source = kernel()
    subscribe_granted(instance, requested)
    instance.set_node_drift(requested.stream_key, Decimal("0"))
    event = live_event()
    source.frames = (
        make_live_heartbeat(
            session_id=requested.session_id,
            provider_time_ns=EVENT_NS,
            resume_token="resume-from-heartbeat",
        ),
        event,
    )

    verdicts = instance.poll(requested.stream_key)
    health = instance.health(requested.stream_key)

    assert len(verdicts) == 2
    assert all(verdict.publication_allowed for verdict in verdicts)
    assert all(verdict.execution_eligible is False for verdict in verdicts)
    assert all(verdict.evaluated_utc_ns == clock.utc for verdict in verdicts)
    assert health.last_heartbeat_utc_ns == clock.utc
    assert health.last_heartbeat_monotonic_ns == clock.monotonic
    assert health.last_provider_time_ns == EVENT_NS
    assert health.evaluated_utc_ns == clock.utc
    assert health.resume_token == "resume-from-heartbeat"
    assert event.source_mode == "live"
    assert not hasattr(source, "publish")


def test_poll_invalid_frame_and_oversized_batch_fail_closed_with_typed_reasons() -> None:
    requested = spec()
    instance, _clock, source = kernel()
    subscribe_granted(instance, requested)

    source.frames = (
        make_live_heartbeat(session_id=requested.session_id, provider_time_ns=EVENT_NS),
        live_event(),
        object(),
    )
    invalid = instance.poll(requested.stream_key)
    health = instance.health(requested.stream_key)
    assert len(invalid) == 1
    assert invalid[0].state == "DISCONNECTED"
    assert invalid[0].reason_codes == ("INVALID_EVENT",)
    assert not invalid[0].publication_allowed
    assert health.last_heartbeat_utc_ns is None

    second_spec = spec("SYN-2")
    second_instance, _clock, second_source = kernel()
    subscribe_granted(second_instance, second_spec)
    second_source.frames = tuple(object() for _ in range(1_025))
    too_large = second_instance.poll(second_spec.stream_key)
    assert too_large[0].state == "DISCONNECTED"
    assert too_large[0].reason_codes == ("SOURCE_BATCH_TOO_LARGE",)
    assert not too_large[0].publication_allowed


def test_disconnected_stream_requires_successful_reconnect_before_heartbeat_recovery() -> None:
    requested = spec()
    instance, clock, source = kernel()
    subscribe_granted(instance, requested)
    instance.set_node_drift(requested.stream_key, Decimal("0"))
    instance.set_source_status(requested.stream_key, "DISCONNECTED")

    ignored = heartbeat(instance, clock, requested)
    assert not ignored.publication_allowed
    assert ignored.state == "DISCONNECTED"

    source.raise_on_subscribe = True
    with pytest.raises(LiveStateError) as caught:
        instance.reconnect(requested.stream_key, attempt=1, jitter_basis_points=5_000)
    assert caught.value.code == "SOURCE_FAILURE"
    assert not heartbeat(instance, clock, requested).publication_allowed

    source.raise_on_subscribe = False
    resumed, _delay = instance.reconnect(requested.stream_key, attempt=1, jitter_basis_points=5_000)
    assert resumed.state == "UNKNOWN"
    assert heartbeat(instance, clock, requested).publication_allowed


def test_freshness_policy_thresholds_are_fixed_and_outputs_are_immutable() -> None:
    policy = FreshnessPolicyV1()
    with pytest.raises(LiveStateError) as caught:
        FreshnessPolicyV1(stale_multiplier=3)
    assert caught.value.code == "INVALID_POLICY"

    requested = spec()
    instance, _clock, _source = kernel()
    health = subscribe_granted(instance, requested)
    with pytest.raises(
        (FrozenInstanceError, AttributeError, TypeError, ValidationError, SealError)
    ):
        health.state = "HEALTHY"  # type: ignore[misc]
    assert policy.drift_alert_ms == Decimal("2")
    assert policy.drift_block_ms == Decimal("10")


def test_tampered_stored_subscription_cannot_authorize_healthy_publication() -> None:
    requested = spec()
    instance, clock, _source = kernel()
    subscribe_granted(instance, requested)
    heartbeat(instance, clock, requested)

    object.__setattr__(requested, "heartbeat_interval_ns", HEARTBEAT_NS * 100)
    verdict = instance.evaluate(requested.stream_key)

    assert verdict.reason_codes == ("INVALID_SUBSCRIPTION",)
    assert verdict.state != "HEALTHY"
    assert not verdict.publication_allowed


def test_drift_exceedance_is_context_independent_and_huge_exponents_are_rejected() -> None:
    requested = spec()
    instance, clock, _source = kernel()
    subscribe_granted(instance, requested)
    heartbeat(instance, clock, requested)

    with localcontext() as context:
        context.prec = 2
        instance.set_node_drift(requested.stream_key, Decimal("10.0001"))
        over_limit = instance.evaluate(requested.stream_key)

    assert over_limit.reason_codes == ("DRIFT_EXCEEDED",)
    assert not over_limit.publication_allowed
    with pytest.raises(LiveStateError) as caught:
        instance.set_node_drift(requested.stream_key, Decimal("1E+100000"))
    assert caught.value.code == "INVALID_DRIFT"


def test_unsubscribe_exception_fails_closed_and_does_not_expose_port_text() -> None:
    requested = spec()
    source = FakeLiveSource()
    instance, clock, _source = kernel(source=source)
    subscribe_granted(instance, requested)
    heartbeat(instance, clock, requested)
    assert instance.evaluate(requested.stream_key).publication_allowed
    source.raise_on_unsubscribe = True

    unsubscribed = instance.unsubscribe(requested.stream_key)
    assert unsubscribed.reason_codes == ("SOURCE_FAILURE",)
    assert "SYNTHETIC_UNSUBSCRIBE_CANARY" not in repr(unsubscribed)

    health = instance.health(requested.stream_key)
    verdict = instance.evaluate(requested.stream_key)
    assert health.state != "HEALTHY"
    assert verdict.state != "HEALTHY"
    assert not verdict.publication_allowed
    assert "SYNTHETIC_UNSUBSCRIBE_CANARY" not in repr(health)
    assert "SYNTHETIC_UNSUBSCRIBE_CANARY" not in repr(verdict)


def test_monotonic_regression_stays_blocked_after_later_heartbeat() -> None:
    requested = spec()
    instance, clock, _source = kernel()
    subscribe_granted(instance, requested)
    heartbeat(instance, clock, requested)

    clock.monotonic += NS
    assert instance.evaluate(requested.stream_key).publication_allowed
    clock.monotonic -= 2 * NS
    regressed = instance.evaluate(requested.stream_key)
    assert not regressed.publication_allowed

    clock.monotonic += NS // 2
    after_heartbeat = heartbeat(instance, clock, requested)
    assert not after_heartbeat.publication_allowed
    assert not instance.evaluate(requested.stream_key).publication_allowed


def test_required_streams_are_auto_rostered_and_group_publication_fails_closed() -> None:
    first = spec("SYN-1", required_group="equities")
    sibling = spec("SYN-2", required_group="equities")
    instance, clock, _source = kernel(
        required_groups={"equities": (first.stream_key, sibling.stream_key)}
    )
    subscribe_granted(instance, first)
    heartbeat(instance, clock, first)

    missing_sibling = instance.authorize_publication(live_event())
    assert not missing_sibling.publication_allowed
    assert missing_sibling.reason_codes == ("REQUIRED_STREAM_MISSING",)
    required_verdicts = instance.evaluate_required()
    assert any(not verdict.publication_allowed for verdict in required_verdicts)
    assert any(
        verdict.reason_codes == ("REQUIRED_STREAM_MISSING",)
        for verdict in required_verdicts
    )

    subscribe_granted(instance, sibling)
    heartbeat(instance, clock, first)
    unhealthy_sibling = instance.authorize_publication(live_event())
    assert not unhealthy_sibling.publication_allowed
    assert unhealthy_sibling.reason_codes == ("REQUIRED_STREAM_UNHEALTHY",)

    heartbeat(instance, clock, sibling)
    assert instance.authorize_publication(live_event()).publication_allowed


def test_active_stream_capacity_denies_until_successful_unsubscribe_evicts() -> None:
    first = spec("SYN-1")
    second = spec("SYN-2")
    instance, _clock, source = kernel(max_streams=1)
    subscribe_granted(instance, first)

    with pytest.raises(LiveStateError) as caught:
        subscribe_granted(instance, second)
    assert caught.value.code == "CAPACITY_EXCEEDED"
    assert not instance.authorize_publication(live_event()).publication_allowed

    health = instance.unsubscribe(first.stream_key)
    assert health.state != "HEALTHY"
    assert source.unsubscriptions == [first]
    assert subscribe_granted(instance, second).state == "UNKNOWN"


def test_resume_token_none_preserves_prior_and_invalid_token_inputs_are_rejected() -> None:
    requested = spec()
    instance, clock, _source = kernel()
    health = subscribe_granted(instance, requested)
    prior = health.resume_token
    assert prior == "resume-1"

    heartbeat(instance, clock, requested, resume_token=None)
    assert instance.health(requested.stream_key).resume_token == prior

    for invalid in (True, "x" * 257, "bad token"):
        with pytest.raises(LiveStateError) as caught:
            instance.on_heartbeat(
                requested.stream_key,
                session_id=requested.session_id,
                resume_token=invalid,  # type: ignore[arg-type]
            )
        assert caught.value.code == "INVALID_RESUME_TOKEN"


@pytest.mark.parametrize("operation", ["subscribe", "reconnect"])
@pytest.mark.parametrize("compensation_fails", [False, True])
def test_invalid_remote_resume_token_is_compensated_and_cleanup_is_retryable(
    operation: str, compensation_fails: bool
) -> None:
    requested = spec()
    responses = ("bad token",) if operation == "subscribe" else ("resume-1", "bad token")
    source = FakeLiveSource(tokens=responses)
    instance, _clock, _source = kernel(source=source)
    retained_token: str | None = None

    if operation == "reconnect":
        initial = subscribe_granted(instance, requested)
        retained_token = initial.resume_token
        assert retained_token == "resume-1"

    source.raise_on_unsubscribe = compensation_fails
    with pytest.raises(LiveStateError) as caught:
        if operation == "subscribe":
            subscribe_granted(instance, requested)
        else:
            instance.reconnect(requested.stream_key, attempt=1, jitter_basis_points=0)

    expected_code = "SOURCE_FAILURE" if compensation_fails else "INVALID_RESUME_TOKEN"
    assert caught.value.code == expected_code
    assert str(caught.value) == expected_code
    assert caught.value.args == (expected_code,)
    assert "bad token" not in repr(caught.value)
    assert source.unsubscriptions == [requested]

    if compensation_fails:
        health = instance.health(requested.stream_key)
        assert health.resume_token == retained_token
        assert health.state != "HEALTHY"
        assert not instance.evaluate(requested.stream_key).publication_allowed

        subscribe_count = len(source.subscriptions)
        with pytest.raises(LiveStateError) as blocked_reconnect:
            instance.reconnect(requested.stream_key, attempt=1, jitter_basis_points=0)
        assert blocked_reconnect.value.code == "SOURCE_FAILURE"
        assert str(blocked_reconnect.value) == "SOURCE_FAILURE"
        assert len(source.subscriptions) == subscribe_count

        source.raise_on_unsubscribe = False
        cleaned = instance.unsubscribe(requested.stream_key)
        assert cleaned.state != "HEALTHY"
        assert source.unsubscriptions == [requested, requested]
        assert not instance.evaluate(requested.stream_key).publication_allowed
    elif operation == "reconnect":
        with pytest.raises(LiveStateError) as missing:
            instance.health(requested.stream_key)
        assert missing.value.code == "SUBSCRIPTION_MISSING"
        assert not instance.evaluate(requested.stream_key).publication_allowed
    else:
        assert instance.evaluate(requested.stream_key).state == "UNKNOWN"
        assert not instance.evaluate(requested.stream_key).publication_allowed
