"""Unit checks for the offline MT deployment-plan kernel."""

from __future__ import annotations

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
from leviathan_core.seal import SealError


def _artifact(*, platform: MtPlatformV1 = MtPlatformV1.MT5) -> DeploymentArtifactSnapshotV1:
    return DeploymentArtifactSnapshotV1(artifact_id="artifact-1", platform=platform)


def _target(
    target_id: str,
    *,
    platform: MtPlatformV1 = MtPlatformV1.MT5,
    account_kind: DeploymentAccountKindV1 = DeploymentAccountKindV1.PAPER,
    capabilities: tuple[str, ...] = ("download", "activate"),
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


def test_plan_preserves_every_target_and_is_sealed_non_executable() -> None:
    result = plan_deployment(
        _request(
            (
                _target("target-b"),
                _target("target-a"),
                _target("target-live", account_kind=DeploymentAccountKindV1.LIVE),
            )
        )
    )

    assert require_deployment_plan(result) is result
    assert tuple(item.target_id for item in result.target_decisions) == (
        "target-b",
        "target-a",
        "target-live",
    )
    decisions = {item.target_id: item for item in result.target_decisions}
    assert decisions["target-a"].decision == "ACTIVATE"
    assert decisions["target-a"].canary_partition == "CANARY"
    assert decisions["target-b"].decision == "ACTIVATE"
    assert decisions["target-live"].decision == "PLAN_BLOCKED"
    assert decisions["target-live"].block_code == "LIVE_ACCOUNT_OPERATOR_SWITCH_REQUIRED"
    assert decisions["target-live"].operator_switch_required is True
    assert result.blocked_target_ids == ("target-live",)
    assert result.execution_permitted is False
    assert all(item.execution_permitted is False for item in result.target_decisions)


def test_per_target_platform_capability_health_and_freshness_fail_closed() -> None:
    result = plan_deployment(
        _request(
            (
                _target("platform", platform=MtPlatformV1.MT4),
                _target("capability", capabilities=("download",)),
                _target("health", health=DeploymentHealthV1.FAILED),
                _target("stale", observed_at_ns=900),
                _target("future", observed_at_ns=1_001),
            )
        )
    )

    assert {item.target_id: item.block_code for item in result.target_decisions} == {
        "platform": "PLATFORM_MISMATCH",
        "capability": "CAPABILITY_MISSING",
        "health": "HEALTH_FAILED",
        "stale": "HEALTH_STALE",
        "future": "HEALTH_TIMESTAMP_INVALID",
    }
    assert result.blocked_target_ids == ("platform", "capability", "health", "stale", "future")
    assert result.canary_target_ids == ()
    assert result.remainder_target_ids == ()


@pytest.mark.parametrize(
    ("percentage", "expected_canary"),
    [(0, ()), (100, ("target-a", "target-b"))],
)
def test_canary_percentage_boundaries_are_exact(
    percentage: int, expected_canary: tuple[str, ...]
) -> None:
    result = plan_deployment(
        _request(
            (_target("target-b"), _target("target-a")),
            canary_percentage=percentage,
        )
    )

    assert tuple(sorted(result.canary_target_ids)) == expected_canary


def test_canary_membership_is_deterministic_independent_of_input_order() -> None:
    first = plan_deployment(
        _request((_target("target-c"), _target("target-a"), _target("target-b")))
    )
    second = plan_deployment(
        _request((_target("target-b"), _target("target-c"), _target("target-a")))
    )

    assert set(first.canary_target_ids) == set(second.canary_target_ids) == {"target-a", "target-b"}
    assert set(first.remainder_target_ids) == set(second.remainder_target_ids) == {"target-c"}


def test_duplicate_target_is_rejected_without_echoing_target_input() -> None:
    with pytest.raises(DeploymentPlanError) as raised:
        plan_deployment(_request((_target("duplicate-id"), _target("duplicate-id"))))

    assert raised.value.code == "DUPLICATE_TARGET"
    assert str(raised.value) == "DUPLICATE_TARGET"
    assert "duplicate-id" not in str(raised.value)


@pytest.mark.parametrize("percentage", [-1, 101, True])
def test_invalid_canary_percentage_is_rejected(percentage: int) -> None:
    with pytest.raises(DeploymentPlanError) as raised:
        plan_deployment(_request((_target("target-a"),), canary_percentage=percentage))

    assert raised.value.code == "INVALID_CANARY_PERCENTAGE"


def test_directly_constructed_plan_is_not_accepted_as_issued() -> None:
    plan = plan_deployment(_request((_target("target-a"),)))

    with pytest.raises(SealError) as constructed:
        type(plan).model_construct(
            schema_version="mtbr.deployment-plan/1",
            artifact_id="artifact-1",
            action=DeploymentActionV1.ACTIVATE,
            evaluated_at_ns=1_000,
            target_decisions=(),
            canary_target_ids=(),
            remainder_target_ids=(),
            blocked_target_ids=(),
            execution_permitted=False,
        )
    assert "SEAL_FORBIDDEN_OPERATION" in str(constructed.value)
