"""Independent MTBR-AGENT-HEALTH-001 acceptance tests from wave25-refill section 3."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from leviathan_core.mt_export_agent_health import (
    AgentHealthError,
    AgentHealthPolicyV1,
    AgentHealthReasonV1,
    AgentHealthStateV1,
    AgentHealthV1,
    AgentHeartbeatV1,
    AgentReportedStatusV1,
    MtPlatformV1,
    evaluate_agent_health,
    is_issued_agent_health,
    make_agent_health_policy,
    require_agent_health,
)

NOW = 1_800_000_000_000_000_000
MAX_AGE_NS = 10_000_000_000
MAX_CLOCK_SKEW_NS = 2_000_000_000
MIN_DISK_BYTES = 1_000_000
MIN_BUILD = 100
REQUIRED_CAPABILITIES = frozenset({"codegen", "compile"})


@dataclass
class _Clock:
    now: int
    calls: int = 0

    def now_utc_ns(self) -> int:
        self.calls += 1
        return self.now


def _policy(**changes: object):
    values: dict[str, object] = {
        "expected_platform": MtPlatformV1.MT5,
        "min_terminal_build": MIN_BUILD,
        "min_free_disk_bytes": MIN_DISK_BYTES,
        "max_clock_skew_ns": MAX_CLOCK_SKEW_NS,
        "required_capabilities": REQUIRED_CAPABILITIES,
        "allowed_builds": None,
    }
    values.update(changes)
    return make_agent_health_policy(**values)  # type: ignore[arg-type]


def _heartbeat(**changes: object) -> AgentHeartbeatV1:
    values: dict[str, object] = {
        "heartbeat_utc_ns": NOW,
        "free_disk_bytes": MIN_DISK_BYTES,
        "platform": MtPlatformV1.MT5,
        "terminal_build": MIN_BUILD,
        "status": AgentReportedStatusV1.OK,
        "capabilities": REQUIRED_CAPABILITIES,
    }
    values.update(changes)
    return AgentHeartbeatV1(**values)  # type: ignore[arg-type]


def _reason_values(result: AgentHealthV1) -> tuple[str, ...]:
    return tuple(code.value for code in result.reason_codes)


def _assert_agent_health_error(call, code: str) -> None:
    with pytest.raises(AgentHealthError) as caught:
        call()
    assert caught.value.code == code
    assert caught.value.args == (code,)


def test_freshness_uses_the_injected_clock_once_and_healthy_is_not_activation() -> None:
    clock = _Clock(NOW)
    result = evaluate_agent_health(_heartbeat(), _policy(), clock)

    assert clock.calls == 1
    assert result.healthy is True
    assert result.heartbeat_age_ns == 0
    assert result.activation_permitted is False


def test_exact_ten_second_age_is_fresh_and_one_nanosecond_more_is_stale() -> None:
    policy = _policy()
    boundary_clock = _Clock(NOW)
    boundary = evaluate_agent_health(
        _heartbeat(heartbeat_utc_ns=NOW - MAX_AGE_NS), policy, boundary_clock
    )
    stale = evaluate_agent_health(
        _heartbeat(heartbeat_utc_ns=NOW - MAX_AGE_NS - 1), policy, _Clock(NOW)
    )

    assert boundary.healthy is True
    assert boundary.heartbeat_age_ns == MAX_AGE_NS
    assert stale.healthy is False
    assert _reason_values(stale) == (AgentHealthReasonV1.HEARTBEAT_STALE.value,)
    assert stale.activation_permitted is False


def test_absent_heartbeat_is_unhealthy_with_a_reason_and_no_activation() -> None:
    result = evaluate_agent_health(None, _policy(), _Clock(NOW))

    assert result.healthy is False
    assert _reason_values(result) == (AgentHealthReasonV1.HEARTBEAT_MISSING.value,)
    assert result.activation_permitted is False


def test_future_heartbeat_within_skew_has_zero_age_but_excess_skew_is_unhealthy() -> None:
    within_skew = evaluate_agent_health(
        _heartbeat(heartbeat_utc_ns=NOW + MAX_CLOCK_SKEW_NS),
        _policy(),
        _Clock(NOW),
    )
    beyond_skew = evaluate_agent_health(
        _heartbeat(heartbeat_utc_ns=NOW + MAX_CLOCK_SKEW_NS + 1),
        _policy(),
        _Clock(NOW),
    )

    assert within_skew.healthy is True
    assert within_skew.heartbeat_age_ns == 0
    assert beyond_skew.healthy is False
    assert _reason_values(beyond_skew) == (AgentHealthReasonV1.CLOCK_SKEW.value,)


def test_disk_threshold_is_inclusive_and_unknown_or_low_disk_is_unhealthy() -> None:
    policy = _policy()
    exactly_enough = evaluate_agent_health(
        _heartbeat(free_disk_bytes=MIN_DISK_BYTES), policy, _Clock(NOW)
    )
    too_little = evaluate_agent_health(
        _heartbeat(free_disk_bytes=MIN_DISK_BYTES - 1), policy, _Clock(NOW)
    )
    unknown = evaluate_agent_health(_heartbeat(free_disk_bytes=None), policy, _Clock(NOW))

    assert exactly_enough.healthy is True
    assert too_little.healthy is False
    assert unknown.healthy is False
    assert _reason_values(too_little) == (AgentHealthReasonV1.DISK_LOW.value,)
    assert _reason_values(unknown) == (AgentHealthReasonV1.DISK_UNKNOWN.value,)


@pytest.mark.parametrize(
    ("changes", "policy_changes", "reason"),
    [
        ({"platform": MtPlatformV1.MT4}, {}, AgentHealthReasonV1.PLATFORM_INCOMPATIBLE),
        ({"terminal_build": MIN_BUILD - 1}, {}, AgentHealthReasonV1.BUILD_BELOW_MINIMUM),
        (
            {"terminal_build": MIN_BUILD + 1},
            {"allowed_builds": (MIN_BUILD,)},
            AgentHealthReasonV1.BUILD_NOT_ALLOWED,
        ),
        ({"terminal_build": "not-a-build"}, {}, AgentHealthReasonV1.BUILD_UNPARSABLE),
        (
            {"capabilities": frozenset({"codegen"})},
            {},
            AgentHealthReasonV1.CAPABILITY_MISSING,
        ),
    ],
)
def test_platform_build_allowlist_and_capability_must_match(
    changes: dict[str, object],
    policy_changes: dict[str, object],
    reason: AgentHealthReasonV1,
) -> None:
    result = evaluate_agent_health(_heartbeat(**changes), _policy(**policy_changes), _Clock(NOW))

    assert result.healthy is False
    assert reason.value in _reason_values(result)
    assert result.activation_permitted is False


@pytest.mark.parametrize(
    ("status", "reason"),
    [
        (None, AgentHealthReasonV1.STATUS_MISSING),
        ("UNKNOWN", AgentHealthReasonV1.STATUS_UNKNOWN),
        (AgentReportedStatusV1.DEGRADED, AgentHealthReasonV1.STATUS_DEGRADED),
        (AgentReportedStatusV1.ERROR, AgentHealthReasonV1.STATUS_ERROR),
    ],
)
def test_only_explicit_ok_status_is_healthy(status: object, reason: AgentHealthReasonV1) -> None:
    result = evaluate_agent_health(_heartbeat(status=status), _policy(), _Clock(NOW))

    assert result.healthy is False
    assert _reason_values(result) == (reason.value,)


def test_missing_heartbeat_timestamp_is_unhealthy_not_synthesized_from_local_time() -> None:
    clock = _Clock(NOW)
    result = evaluate_agent_health(_heartbeat(heartbeat_utc_ns=None), _policy(), clock)

    assert clock.calls == 1
    assert result.healthy is False
    assert _reason_values(result) == (AgentHealthReasonV1.HEARTBEAT_TIMESTAMP_MISSING.value,)
    assert result.activation_permitted is False


def test_malformed_fact_values_do_not_echo_canary_into_health_reasons() -> None:
    canary = "HEALTH_SECRET_CANARY_api_key=never-echo"
    result = evaluate_agent_health(
        _heartbeat(
            platform=canary,
            terminal_build=canary,
            status=canary,
            capabilities=frozenset({canary}),
        ),
        _policy(),
        _Clock(NOW),
    )

    assert result.healthy is False
    assert result.activation_permitted is False
    assert canary not in repr(result)
    assert all(canary not in code for code in _reason_values(result))


def test_clock_exceptions_and_non_integer_clock_values_are_typed_and_redacted() -> None:
    canary = "CLOCK_SECRET_CANARY"

    class RaisingClock:
        def now_utc_ns(self) -> int:
            raise RuntimeError(canary)

    class BoolClock:
        def now_utc_ns(self) -> int:
            return True  # type: ignore[return-value]

    _assert_agent_health_error(
        lambda: evaluate_agent_health(_heartbeat(), _policy(), RaisingClock()),
        "CLOCK_UNAVAILABLE",
    )
    _assert_agent_health_error(
        lambda: evaluate_agent_health(_heartbeat(), _policy(), BoolClock()),
        "CLOCK_INVALID",
    )
    try:
        evaluate_agent_health(_heartbeat(), _policy(), RaisingClock())
    except AgentHealthError as error:
        assert canary not in str(error)
        assert canary not in repr(error.args)


@pytest.mark.parametrize(
    ("changes", "code"),
    [
        ({"min_free_disk_bytes": 0}, "POLICY_OUT_OF_BOUNDS"),
        ({"min_terminal_build": 0}, "POLICY_OUT_OF_BOUNDS"),
        ({"max_clock_skew_ns": MAX_CLOCK_SKEW_NS + 1}, "POLICY_OUT_OF_BOUNDS"),
        ({"min_free_disk_bytes": True}, "INVALID_POLICY"),
        ({"min_terminal_build": True}, "INVALID_POLICY"),
        ({"max_clock_skew_ns": True}, "INVALID_POLICY"),
    ],
)
def test_policy_bounds_use_exact_integers_and_cannot_be_loosened(
    changes: dict[str, object], code: str
) -> None:
    _assert_agent_health_error(lambda: _policy(**changes), code)


def test_healthy_result_requires_issuance_and_detects_post_issue_tampering() -> None:
    result = evaluate_agent_health(_heartbeat(), _policy(), _Clock(NOW))

    assert result.healthy is True
    assert is_issued_agent_health(result) is True
    assert require_agent_health(result) is result
    object.__setattr__(result, "heartbeat_age_ns", 7)

    assert result.healthy is False
    assert is_issued_agent_health(result) is False
    _assert_agent_health_error(lambda: require_agent_health(result), "UNISSUED_HEALTH")


def test_publicly_constructed_health_output_is_never_healthy_or_a_capability() -> None:
    candidate = AgentHealthV1(
        state=AgentHealthStateV1.HEALTHY,
        reason_codes=(),
        observed_at_utc_ns=NOW,
        heartbeat_age_ns=0,
        activation_permitted=False,
    )

    assert candidate.healthy is False
    assert is_issued_agent_health(candidate) is False
    assert candidate.activation_permitted is False
    _assert_agent_health_error(lambda: require_agent_health(candidate), "UNISSUED_HEALTH")


def test_directly_constructed_policy_is_rejected_at_evaluation() -> None:
    candidate = AgentHealthPolicyV1(
        expected_platform=MtPlatformV1.MT5,
        min_terminal_build=MIN_BUILD,
        min_free_disk_bytes=MIN_DISK_BYTES,
        max_clock_skew_ns=MAX_CLOCK_SKEW_NS,
        required_capabilities=tuple(sorted(REQUIRED_CAPABILITIES)),
        allowed_builds=None,
    )

    _assert_agent_health_error(
        lambda: evaluate_agent_health(_heartbeat(), candidate, _Clock(NOW)),
        "INVALID_POLICY",
    )


def test_allowed_build_generator_is_capped_during_iteration() -> None:
    pulls = 0

    def million_builds():
        nonlocal pulls
        for build in range(1, 1_000_001):
            pulls += 1
            yield build

    _assert_agent_health_error(
        lambda: _policy(allowed_builds=million_builds()), "POLICY_OUT_OF_BOUNDS"
    )

    assert pulls == 129


def test_required_capability_generator_is_capped_during_iteration() -> None:
    pulls = 0

    def million_capabilities():
        nonlocal pulls
        for index in range(1_000_000):
            pulls += 1
            yield f"capability-{index}"

    _assert_agent_health_error(
        lambda: _policy(required_capabilities=million_capabilities()), "INVALID_POLICY"
    )

    assert pulls == 65
