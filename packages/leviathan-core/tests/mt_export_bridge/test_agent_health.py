"""Unit tests for the fake-first MT terminal-agent health kernel."""

from __future__ import annotations

import pytest

from leviathan_core.mt_export_agent_health import (
    AgentHealthError,
    AgentHealthReasonV1,
    AgentHealthStateV1,
    AgentHeartbeatV1,
    AgentReportedStatusV1,
    MtPlatformV1,
    evaluate_agent_health,
    is_issued_agent_health,
    make_agent_health_policy,
    require_agent_health,
)

_NOW = 1_800_000_000_000_000_000


class _FakeClock:
    def __init__(self, value: object) -> None:
        self.value = value
        self.calls = 0

    def now_utc_ns(self) -> object:
        self.calls += 1
        if isinstance(self.value, Exception):
            raise self.value
        return self.value


def _policy(**changes: object):
    values: dict[str, object] = {
        "expected_platform": MtPlatformV1.MT5,
        "min_terminal_build": 4000,
        "min_free_disk_bytes": 1024,
        "max_clock_skew_ns": 250_000_000,
        "required_capabilities": ("compile", "package"),
        "allowed_builds": None,
    }
    values.update(changes)
    return make_agent_health_policy(**values)  # type: ignore[arg-type]


def _heartbeat(**changes: object) -> AgentHeartbeatV1:
    values: dict[str, object] = {
        "heartbeat_utc_ns": _NOW,
        "free_disk_bytes": 1024,
        "platform": MtPlatformV1.MT5,
        "terminal_build": "4000",
        "status": AgentReportedStatusV1.OK,
        "capabilities": ("compile", "package"),
    }
    values.update(changes)
    return AgentHeartbeatV1(**values)  # type: ignore[arg-type]


def _evaluate(
    heartbeat: AgentHeartbeatV1 | None,
    *,
    policy: object | None = None,
    now: object = _NOW,
):
    return evaluate_agent_health(
        heartbeat,
        _policy() if policy is None else policy,  # type: ignore[arg-type]
        _FakeClock(now),  # type: ignore[arg-type]
    )


def test_exact_ten_second_boundary_is_healthy_and_one_ns_older_is_stale() -> None:
    policy = _policy()
    exact = evaluate_agent_health(
        _heartbeat(heartbeat_utc_ns=_NOW - 10_000_000_000), policy, _FakeClock(_NOW)
    )
    stale = evaluate_agent_health(
        _heartbeat(heartbeat_utc_ns=_NOW - 10_000_000_001), policy, _FakeClock(_NOW)
    )

    assert exact.healthy
    assert exact.heartbeat_age_ns == 10_000_000_000
    assert stale.state is AgentHealthStateV1.UNHEALTHY
    assert stale.reason_codes == (AgentHealthReasonV1.HEARTBEAT_STALE,)


def test_absent_heartbeat_is_unhealthy_and_issued() -> None:
    result = _evaluate(None)

    assert result.state is AgentHealthStateV1.UNHEALTHY
    assert result.reason_codes == (AgentHealthReasonV1.HEARTBEAT_MISSING,)
    assert is_issued_agent_health(result)
    assert result.activation_permitted is False


def test_future_heartbeat_within_policy_skew_has_zero_age_and_beyond_is_clock_skew() -> None:
    policy = _policy(max_clock_skew_ns=250_000_000)
    tolerated = evaluate_agent_health(
        _heartbeat(heartbeat_utc_ns=_NOW + 250_000_000), policy, _FakeClock(_NOW)
    )
    rejected = evaluate_agent_health(
        _heartbeat(heartbeat_utc_ns=_NOW + 250_000_001), policy, _FakeClock(_NOW)
    )

    assert tolerated.healthy
    assert tolerated.heartbeat_age_ns == 0
    assert rejected.reason_codes == (AgentHealthReasonV1.CLOCK_SKEW,)


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"free_disk_bytes": None}, AgentHealthReasonV1.DISK_UNKNOWN),
        ({"free_disk_bytes": True}, AgentHealthReasonV1.DISK_UNKNOWN),
        ({"free_disk_bytes": 1023}, AgentHealthReasonV1.DISK_LOW),
        ({"status": None}, AgentHealthReasonV1.STATUS_MISSING),
        ({"status": "NOT_A_STATUS"}, AgentHealthReasonV1.STATUS_UNKNOWN),
        ({"status": AgentReportedStatusV1.DEGRADED}, AgentHealthReasonV1.STATUS_DEGRADED),
        ({"status": AgentReportedStatusV1.ERROR}, AgentHealthReasonV1.STATUS_ERROR),
        ({"platform": None}, AgentHealthReasonV1.PLATFORM_MISSING),
        ({"platform": "MT6"}, AgentHealthReasonV1.PLATFORM_UNKNOWN),
        ({"platform": MtPlatformV1.MT4}, AgentHealthReasonV1.PLATFORM_INCOMPATIBLE),
        ({"terminal_build": None}, AgentHealthReasonV1.BUILD_MISSING),
        ({"terminal_build": "build-4000"}, AgentHealthReasonV1.BUILD_UNPARSABLE),
        ({"terminal_build": "3999"}, AgentHealthReasonV1.BUILD_BELOW_MINIMUM),
        ({"capabilities": ()}, AgentHealthReasonV1.CAPABILITY_MISSING),
    ],
)
def test_health_fails_closed_for_unhealthy_source_facts(
    changes: dict[str, object], reason: AgentHealthReasonV1
) -> None:
    result = _evaluate(_heartbeat(**changes))

    assert result.state is AgentHealthStateV1.UNHEALTHY
    assert reason in result.reason_codes
    assert result.reason_codes == tuple(
        sorted(set(result.reason_codes), key=lambda item: item.value)
    )
    assert result.activation_permitted is False


def test_build_minimum_and_exact_allowlist_are_both_enforced() -> None:
    policy = _policy(min_terminal_build=4000, allowed_builds=(4000, 4002))
    accepted = evaluate_agent_health(
        _heartbeat(terminal_build="4002"), policy, _FakeClock(_NOW)
    )
    denied = evaluate_agent_health(
        _heartbeat(terminal_build="4001"), policy, _FakeClock(_NOW)
    )

    assert accepted.healthy
    assert denied.reason_codes == (AgentHealthReasonV1.BUILD_NOT_ALLOWED,)


def test_required_capabilities_must_be_explicitly_present() -> None:
    missing = _evaluate(_heartbeat(capabilities=("compile",)))
    unknown = _evaluate(_heartbeat(capabilities=None))

    assert missing.reason_codes == (AgentHealthReasonV1.CAPABILITY_MISSING,)
    assert unknown.reason_codes == (AgentHealthReasonV1.CAPABILITIES_UNKNOWN,)


def test_policy_bounds_are_required_and_cannot_be_loosened() -> None:
    with pytest.raises(AgentHealthError) as bool_bound:
        _policy(min_free_disk_bytes=True)
    with pytest.raises(AgentHealthError) as skew_bound:
        _policy(max_clock_skew_ns=2_000_000_001)
    with pytest.raises(AgentHealthError) as zero_disk:
        _policy(min_free_disk_bytes=0)

    assert bool_bound.value.code == "INVALID_POLICY"
    assert skew_bound.value.code == "POLICY_OUT_OF_BOUNDS"
    assert zero_disk.value.code == "POLICY_OUT_OF_BOUNDS"


def test_bounded_policy_collections_stop_at_their_item_limit() -> None:
    build_pulls = 0

    def million_builds():
        nonlocal build_pulls
        for build in range(1, 1_000_001):
            build_pulls += 1
            yield build

    with pytest.raises(AgentHealthError) as builds_error:
        _policy(allowed_builds=million_builds())

    capability_pulls = 0

    def million_capabilities():
        nonlocal capability_pulls
        for index in range(1_000_000):
            capability_pulls += 1
            yield f"capability-{index}"

    with pytest.raises(AgentHealthError) as capabilities_error:
        _policy(required_capabilities=million_capabilities())

    assert builds_error.value.code == "POLICY_OUT_OF_BOUNDS"
    assert build_pulls == 129
    assert capabilities_error.value.code == "INVALID_POLICY"
    assert capability_pulls == 65


def test_unissued_or_tampered_policy_is_rejected() -> None:
    issued = _policy()
    direct = type(issued)(
        expected_platform=MtPlatformV1.MT5,
        min_terminal_build=4000,
        min_free_disk_bytes=1,
        max_clock_skew_ns=0,
        required_capabilities=("compile", "package"),
        allowed_builds=None,
    )
    with pytest.raises(AgentHealthError) as direct_error:
        _evaluate(_heartbeat(), policy=direct)

    assert direct_error.value.code == "INVALID_POLICY"
    object.__setattr__(issued, "min_free_disk_bytes", 1)
    with pytest.raises(AgentHealthError) as tampered_error:
        _evaluate(_heartbeat(), policy=issued)
    assert tampered_error.value.code == "INVALID_POLICY"


def test_health_result_requires_issuance_and_is_not_an_activation_permit() -> None:
    issued = _evaluate(_heartbeat())
    direct = type(issued)(
        state=AgentHealthStateV1.HEALTHY,
        reason_codes=(),
        observed_at_utc_ns=_NOW,
        heartbeat_age_ns=0,
        activation_permitted=False,
    )

    assert issued.healthy
    assert issued.activation_permitted is False
    assert not direct.healthy
    with pytest.raises(AgentHealthError) as exc:
        require_agent_health(direct)
    assert exc.value.code == "UNISSUED_HEALTH"


def test_invalid_clock_is_typed_content_free_and_read_once() -> None:
    clock = _FakeClock(True)
    with pytest.raises(AgentHealthError) as exc:
        evaluate_agent_health(_heartbeat(), _policy(), clock)  # type: ignore[arg-type]

    assert exc.value.code == "CLOCK_INVALID"
    assert exc.value.args == ("CLOCK_INVALID",)
    assert "True" not in str(exc.value)
    assert clock.calls == 1

    failing = _FakeClock(RuntimeError("private canary"))
    with pytest.raises(AgentHealthError) as failed_clock:
        evaluate_agent_health(_heartbeat(), _policy(), failing)  # type: ignore[arg-type]
    assert failed_clock.value.code == "CLOCK_UNAVAILABLE"
    assert "private canary" not in str(failed_clock.value)


def test_replace_revalidates_policy_but_does_not_reissue_it() -> None:
    policy = _policy()
    changed = policy.model_copy(update={"min_free_disk_bytes": 2048})

    assert changed.min_free_disk_bytes == 2048
    with pytest.raises(AgentHealthError) as exc:
        _evaluate(_heartbeat(), policy=changed)
    assert exc.value.code == "INVALID_POLICY"
