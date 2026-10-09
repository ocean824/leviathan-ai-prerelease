from __future__ import annotations

import copy
import pickle
import socket

import pytest

from leviathan_core.mt_export_bridge_artifacts import DeploymentModeV1, MtPlatformV1
from leviathan_core.mt_export_rollback_plan import (
    RollbackArtifactV1,
    RollbackPlanError,
    RollbackPlanV1,
    RollbackProposalV1,
    RollbackTargetV1,
    _issue_rollback_artifact,
    _issue_rollback_proposal,
    _issue_rollback_target,
    validate_rollback_proposal,
)
from leviathan_core.seal import SealError


def _target(
    *,
    target_id: str = "terminal-a",
    platform: MtPlatformV1 = MtPlatformV1.MT5,
    mode: DeploymentModeV1 = DeploymentModeV1.PAPER,
) -> RollbackTargetV1:
    return _issue_rollback_target(
        target_id=target_id,
        platform=platform,
        mode=mode,
    )


def _artifact(
    *,
    artifact_id: str,
    target_id: str = "terminal-a",
    platform: MtPlatformV1 = MtPlatformV1.MT5,
    created_at_ns: int,
    artifact_sha256: str,
    provenance_sha256: str = "c" * 64,
) -> RollbackArtifactV1:
    return _issue_rollback_artifact(
        artifact_id=artifact_id,
        target_id=target_id,
        platform=platform,
        created_at_ns=created_at_ns,
        artifact_sha256=artifact_sha256,
        provenance_sha256=provenance_sha256,
    )


def _proposal(
    *,
    target: RollbackTargetV1 | None = None,
    current: RollbackArtifactV1 | None = None,
    prior: RollbackArtifactV1 | None = None,
    include_default_prior: bool = True,
    forward_deployment_id: str = "deploy-forward-42",
) -> RollbackProposalV1:
    if target is None:
        target = _target()
    if current is None:
        current = _artifact(
            artifact_id="artifact-current",
            created_at_ns=200,
            artifact_sha256="a" * 64,
        )
    if prior is None and include_default_prior:
        prior = _artifact(
            artifact_id="artifact-prior",
            created_at_ns=100,
            artifact_sha256="b" * 64,
        )
    return _issue_rollback_proposal(
        target=target,
        current_artifact=current,
        prior_artifact=prior,
        forward_deployment_id=forward_deployment_id,
    )


def _ready_plan() -> RollbackPlanV1:
    return validate_rollback_proposal(_proposal())


def _issued_records() -> tuple[
    RollbackTargetV1,
    RollbackArtifactV1,
    RollbackArtifactV1,
    RollbackProposalV1,
    RollbackPlanV1,
]:
    target = _target()
    current = _artifact(
        artifact_id="artifact-current",
        created_at_ns=200,
        artifact_sha256="a" * 64,
    )
    prior = _artifact(
        artifact_id="artifact-prior",
        created_at_ns=100,
        artifact_sha256="b" * 64,
    )
    proposal = _issue_rollback_proposal(
        target=target,
        current_artifact=current,
        prior_artifact=prior,
        forward_deployment_id="deploy-forward-42",
    )
    plan = validate_rollback_proposal(proposal)
    return target, current, prior, proposal, plan


def test_valid_prior_produces_sealed_data_only_plan_retaining_forward_identity() -> None:
    plan = _ready_plan()

    assert plan.status.value == "READY"
    assert plan.target_id == "terminal-a"
    assert plan.platform is MtPlatformV1.MT5
    assert plan.current_artifact_id == "artifact-current"
    assert plan.prior_artifact_id == "artifact-prior"
    assert plan.forward_deployment_id == "deploy-forward-42"
    assert plan.block_code is None
    assert plan.executable is False
    plan.assert_sealed()


def test_missing_prior_returns_blocked_non_executable_plan() -> None:
    plan = validate_rollback_proposal(_proposal(prior=None, include_default_prior=False))

    assert plan.status.value == "BLOCKED"
    assert plan.block_code == "NO_PRIOR_ARTIFACT"
    assert plan.prior_artifact_id is None
    assert plan.forward_deployment_id == "deploy-forward-42"
    assert plan.executable is False
    plan.assert_sealed()


def test_live_target_is_always_plan_blocked_without_becoming_executable() -> None:
    live_proposal = _proposal(
        target=_target(mode=DeploymentModeV1.LIVE),
    )

    plan = validate_rollback_proposal(live_proposal)

    assert plan.status.value == "BLOCKED"
    assert plan.block_code == "LIVE_OPERATOR_SWITCH"
    assert plan.executable is False
    assert plan.forward_deployment_id == "deploy-forward-42"
    plan.assert_sealed()


@pytest.mark.parametrize(
    ("prior_target_id", "prior_platform", "expected_code"),
    [
        ("terminal-b", MtPlatformV1.MT5, "TARGET_MISMATCH"),
        ("terminal-a", MtPlatformV1.MT4, "PLATFORM_MISMATCH"),
    ],
)
def test_prior_must_match_target_and_platform(
    prior_target_id: str,
    prior_platform: MtPlatformV1,
    expected_code: str,
) -> None:
    prior = _artifact(
        artifact_id="artifact-prior",
        target_id=prior_target_id,
        platform=prior_platform,
        created_at_ns=100,
        artifact_sha256="b" * 64,
    )

    with pytest.raises(RollbackPlanError) as error:
        validate_rollback_proposal(_proposal(prior=prior))

    assert error.value.code == expected_code
    assert str(error.value) == expected_code


@pytest.mark.parametrize("prior_created_at_ns", [200, 201])
def test_prior_artifact_must_be_strictly_earlier(prior_created_at_ns: int) -> None:
    prior = _artifact(
        artifact_id="artifact-prior",
        created_at_ns=prior_created_at_ns,
        artifact_sha256="b" * 64,
    )
    proposal = _proposal(prior=prior)

    with pytest.raises(RollbackPlanError) as error:
        validate_rollback_proposal(proposal)

    assert error.value.code == "PRIOR_NOT_EARLIER"


@pytest.mark.parametrize(
    ("prior_id", "prior_hash"),
    [
        ("artifact-current", "b" * 64),
        ("artifact-prior", "a" * 64),
    ],
)
def test_prior_must_have_distinct_artifact_id_and_content_hash(
    prior_id: str,
    prior_hash: str,
) -> None:
    prior = _artifact(
        artifact_id=prior_id,
        created_at_ns=100,
        artifact_sha256=prior_hash,
    )

    with pytest.raises(RollbackPlanError) as error:
        validate_rollback_proposal(_proposal(prior=prior))

    assert error.value.code == "ARTIFACT_NOT_DISTINCT"


def test_tampered_provenance_fails_closed_without_echoing_payload() -> None:
    current = _artifact(
        artifact_id="artifact-current",
        created_at_ns=200,
        artifact_sha256="a" * 64,
    )
    proposal = _proposal(current=current)
    object.__setattr__(current, "provenance_sha256", "not-a-digest-secret-like-value")

    with pytest.raises(RollbackPlanError) as error:
        validate_rollback_proposal(proposal)

    assert error.value.code == "PROVENANCE_INVALID"
    assert "not-a-digest-secret-like-value" not in str(error.value)


def test_reinitializing_issued_plan_fails_before_mutating_its_state() -> None:
    plan = _ready_plan()
    before = (
        plan.status,
        plan.target_id,
        plan.platform,
        plan.current_artifact_id,
        plan.prior_artifact_id,
        plan.forward_deployment_id,
        plan.block_code,
        plan.executable,
    )

    reinitialize = object.__getattribute__(plan, "__init__")
    with pytest.raises(SealError) as error:
        reinitialize(
            status=plan.status,
            target_id="reinitialized-target",
            platform=plan.platform,
            mode=plan.mode,
            current_artifact_id=plan.current_artifact_id,
            prior_artifact_id=plan.prior_artifact_id,
            forward_deployment_id=plan.forward_deployment_id,
            block_code=plan.block_code,
            executable=True,
        )
    assert error.value.code == "SEAL_FORBIDDEN_OPERATION"

    after = (
        plan.status,
        plan.target_id,
        plan.platform,
        plan.current_artifact_id,
        plan.prior_artifact_id,
        plan.forward_deployment_id,
        plan.block_code,
        plan.executable,
    )
    assert after == before
    plan.assert_sealed()


def test_issued_records_reject_copy_deepcopy_and_pickle_clones() -> None:
    for record in _issued_records():
        with pytest.raises(SealError) as copy_error:
            copy.copy(record)
        assert copy_error.value.code == "SEAL_FORBIDDEN_OPERATION"

        with pytest.raises(SealError) as deepcopy_error:
            copy.deepcopy(record)
        assert deepcopy_error.value.code == "SEAL_FORBIDDEN_OPERATION"

        with pytest.raises(SealError) as pickle_error:
            pickle.loads(pickle.dumps(record))
        assert pickle_error.value.code == "SEAL_FORBIDDEN_OPERATION"


def test_invalid_forward_deployment_identity_is_rejected() -> None:
    for invalid_id in ("", "not valid", "\n"):
        with pytest.raises(RollbackPlanError) as error:
            _proposal(forward_deployment_id=invalid_id)
        assert error.value.code == "INVALID_INPUT"


def test_plan_has_no_action_authority_or_network_effect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def deny_network(*args: object, **kwargs: object) -> None:
        raise AssertionError("rollback validator attempted a network call")

    monkeypatch.setattr(socket, "socket", deny_network)
    monkeypatch.setattr(socket, "create_connection", deny_network)
    plan = _ready_plan()

    assert plan.executable is False
    assert not callable(getattr(plan, "execute", None))
    assert not callable(getattr(plan, "redeploy", None))
    assert not callable(getattr(plan, "rollback", None))
