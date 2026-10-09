from __future__ import annotations

import socket

import pytest

from leviathan_core.mt_export_bridge_artifacts import MtPlatformV1
from leviathan_core.mt_export_deploy_plan import (
    DeploymentAccountKindV1,
    DeploymentActionV1,
    DeploymentArtifactSnapshotV1,
    DeploymentHealthV1,
    DeploymentPlanError,
    DeploymentPlanRequestV1,
    DeploymentTargetSnapshotV1,
    plan_deployment,
    require_deployment_plan,
)


def _artifact(
    platform: MtPlatformV1 = MtPlatformV1.MT5,
) -> DeploymentArtifactSnapshotV1:
    return DeploymentArtifactSnapshotV1("artifact-synthetic-7", platform)


def _target(
    target_id: str,
    *,
    platform: MtPlatformV1 = MtPlatformV1.MT5,
    account_kind: DeploymentAccountKindV1 = DeploymentAccountKindV1.PAPER,
    capabilities: tuple[str, ...] = ("download", "stage", "activate"),
    health: DeploymentHealthV1 = DeploymentHealthV1.HEALTHY,
    observed_at_ns: int = 990,
) -> DeploymentTargetSnapshotV1:
    return DeploymentTargetSnapshotV1(
        target_id=target_id,
        platform=platform,
        account_kind=account_kind,
        capabilities=capabilities,
        health=health,
        observed_at_ns=observed_at_ns,
    )


def _request(
    targets: tuple[DeploymentTargetSnapshotV1, ...],
    *,
    artifact: DeploymentArtifactSnapshotV1 | None = None,
    action: DeploymentActionV1 = DeploymentActionV1.ACTIVATE,
    required_capabilities: tuple[str, ...] = ("activate",),
    now_ns: int = 1_000,
    maximum_health_age_ns: int = 20,
    canary_percentage: int = 50,
) -> DeploymentPlanRequestV1:
    return DeploymentPlanRequestV1(
        artifact=_artifact() if artifact is None else artifact,
        targets=targets,
        action=action,
        required_capabilities=required_capabilities,
        now_ns=now_ns,
        maximum_health_age_ns=maximum_health_age_ns,
        canary_percentage=canary_percentage,
    )


def test_valid_multi_target_plan_is_sealed_data_only_and_preserves_each_target() -> None:
    request = _request(
        (
            _target("terminal-b"),
            _target("terminal-a"),
            _target("terminal-live", account_kind=DeploymentAccountKindV1.LIVE),
        )
    )

    plan = plan_deployment(request)

    assert require_deployment_plan(plan) is plan
    assert plan.schema_version == "mtbr.deployment-plan/1"
    assert plan.artifact_id == "artifact-synthetic-7"
    assert tuple(item.target_id for item in plan.target_decisions) == (
        "terminal-b",
        "terminal-a",
        "terminal-live",
    )
    decisions = {item.target_id: item for item in plan.target_decisions}
    assert decisions["terminal-a"].decision == "ACTIVATE"
    assert decisions["terminal-b"].decision == "ACTIVATE"
    assert decisions["terminal-live"].decision == "PLAN_BLOCKED"
    assert decisions["terminal-live"].block_code == "LIVE_ACCOUNT_OPERATOR_SWITCH_REQUIRED"
    assert decisions["terminal-live"].operator_switch_required is True
    assert plan.blocked_target_ids == ("terminal-live",)
    assert plan.execution_permitted is False
    assert all(item.execution_permitted is False for item in plan.target_decisions)


def test_post_issue_plan_tampering_fails_seal_verification() -> None:
    plan = plan_deployment(_request((_target("terminal-a"),)))
    object.__setattr__(plan, "execution_permitted", True)

    with pytest.raises(DeploymentPlanError) as error:
        require_deployment_plan(plan)

    assert error.value.code == "PLAN_SEAL_INVALID"


@pytest.mark.parametrize(
    ("action", "required_capability"),
    [
        (DeploymentActionV1.DOWNLOAD_ONLY, "download"),
        (DeploymentActionV1.STAGED, "stage"),
        (DeploymentActionV1.ACTIVATE, "activate"),
    ],
)
def test_each_supported_action_is_only_a_plan_intent(
    action: DeploymentActionV1,
    required_capability: str,
) -> None:
    plan = plan_deployment(
        _request(
            (_target("terminal-paper"),),
            action=action,
            required_capabilities=(required_capability,),
        )
    )

    decision = plan.target_decisions[0]
    assert decision.decision == action.value
    assert decision.execution_permitted is False
    assert plan.execution_permitted is False
    assert not callable(getattr(plan, "execute", None))
    assert not callable(getattr(plan, "deploy", None))


def test_platform_capability_and_health_failures_are_blocked_per_target() -> None:
    plan = plan_deployment(
        _request(
            (
                _target("wrong-platform", platform=MtPlatformV1.MT4),
                _target("missing-capability", capabilities=("download",)),
                _target("failed-health", health=DeploymentHealthV1.FAILED),
                _target("stale-health", observed_at_ns=979),
                _target("future-health", observed_at_ns=1_001),
            )
        )
    )

    assert {item.target_id: item.block_code for item in plan.target_decisions} == {
        "wrong-platform": "PLATFORM_MISMATCH",
        "missing-capability": "CAPABILITY_MISSING",
        "failed-health": "HEALTH_FAILED",
        "stale-health": "HEALTH_STALE",
        "future-health": "HEALTH_TIMESTAMP_INVALID",
    }
    assert plan.blocked_target_ids == (
        "wrong-platform",
        "missing-capability",
        "failed-health",
        "stale-health",
        "future-health",
    )
    assert plan.canary_target_ids == ()
    assert plan.remainder_target_ids == ()
    assert plan.execution_permitted is False


@pytest.mark.parametrize(
    ("percentage", "expected_canary", "expected_remainder"),
    [
        (0, (), ("terminal-a", "terminal-b")),
        (100, ("terminal-a", "terminal-b"), ()),
    ],
)
def test_canary_percentage_boundaries_partition_all_eligible_targets(
    percentage: int,
    expected_canary: tuple[str, ...],
    expected_remainder: tuple[str, ...],
) -> None:
    plan = plan_deployment(
        _request(
            (_target("terminal-b"), _target("terminal-a")),
            canary_percentage=percentage,
        )
    )

    assert tuple(sorted(plan.canary_target_ids)) == expected_canary
    assert tuple(sorted(plan.remainder_target_ids)) == expected_remainder
    assert set(plan.canary_target_ids).isdisjoint(plan.remainder_target_ids)
    assert set(plan.canary_target_ids + plan.remainder_target_ids) == {
        "terminal-a",
        "terminal-b",
    }


def test_canary_partition_is_deterministic_across_target_input_order() -> None:
    first = plan_deployment(
        _request((_target("terminal-c"), _target("terminal-a"), _target("terminal-b")))
    )
    second = plan_deployment(
        _request((_target("terminal-b"), _target("terminal-c"), _target("terminal-a")))
    )

    assert (
        set(first.canary_target_ids)
        == set(second.canary_target_ids)
        == {
            "terminal-a",
            "terminal-b",
        }
    )
    assert set(first.remainder_target_ids) == set(second.remainder_target_ids) == {"terminal-c"}


@pytest.mark.parametrize("percentage", [-1, 101, True])
def test_invalid_canary_percentage_fails_closed(percentage: int) -> None:
    with pytest.raises(DeploymentPlanError) as error:
        plan_deployment(_request((_target("terminal-a"),), canary_percentage=percentage))

    assert error.value.code == "INVALID_CANARY_PERCENTAGE"
    assert str(error.value) == "INVALID_CANARY_PERCENTAGE"


def test_duplicate_target_ids_are_rejected_without_echoing_identifier() -> None:
    with pytest.raises(DeploymentPlanError) as error:
        plan_deployment(_request((_target("duplicate-target"), _target("duplicate-target"))))

    assert error.value.code == "DUPLICATE_TARGET"
    assert str(error.value) == "DUPLICATE_TARGET"
    assert "duplicate-target" not in str(error.value)


def test_plan_is_offline_and_cannot_call_a_deployment_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def deny_network(*args: object, **kwargs: object) -> None:
        raise AssertionError("deployment plan attempted a network call")

    monkeypatch.setattr(socket, "socket", deny_network)
    monkeypatch.setattr(socket, "create_connection", deny_network)

    plan = plan_deployment(_request((_target("synthetic-terminal"),)))

    assert require_deployment_plan(plan) is plan
    assert plan.execution_permitted is False
    assert plan.target_decisions[0].execution_permitted is False
    assert not callable(getattr(plan, "execute", None))
    assert not callable(getattr(plan, "deploy", None))
