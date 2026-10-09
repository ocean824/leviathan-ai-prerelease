from __future__ import annotations

import copy
import pickle
from dataclasses import FrozenInstanceError

import pytest

from leviathan_core.mt_export_bridge_artifacts import DeploymentModeV1, MtPlatformV1
from leviathan_core.mt_export_rollback_plan import (
    RollbackPlanError,
    RollbackPlanStatusV1,
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
):
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
):
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
    target=None,
    current=None,
    prior="default",
    forward_deployment_id: str = "deploy-forward-42",
):
    if prior == "default":
        prior = _artifact(
            artifact_id="artifact-prior",
            created_at_ns=100,
            artifact_sha256="b" * 64,
        )
    return _issue_rollback_proposal(
        target=target or _target(),
        current_artifact=current
        or _artifact(
            artifact_id="artifact-current",
            created_at_ns=200,
            artifact_sha256="a" * 64,
        ),
        prior_artifact=prior,
        forward_deployment_id=forward_deployment_id,
    )


def test_valid_prior_returns_sealed_data_only_plan() -> None:
    proposal = _proposal()
    result = validate_rollback_proposal(proposal)

    assert result.status is RollbackPlanStatusV1.READY
    assert result.target_id == "terminal-a"
    assert result.platform is MtPlatformV1.MT5
    assert result.current_artifact_id == "artifact-current"
    assert result.prior_artifact_id == "artifact-prior"
    assert result.forward_deployment_id == "deploy-forward-42"
    assert result.block_code is None
    assert result.executable is False
    result.assert_sealed()
    with pytest.raises(FrozenInstanceError):
        result.executable = True  # type: ignore[misc]
    assert not callable(getattr(result, "execute", None))


def test_missing_prior_is_a_blocked_non_executable_plan() -> None:
    result = validate_rollback_proposal(_proposal(prior=None))

    assert result.status is RollbackPlanStatusV1.BLOCKED
    assert result.block_code == "NO_PRIOR_ARTIFACT"
    assert result.prior_artifact_id is None
    assert result.forward_deployment_id == "deploy-forward-42"
    assert result.executable is False
    result.assert_sealed()


def test_live_target_is_always_blocked() -> None:
    result = validate_rollback_proposal(_proposal(target=_target(mode=DeploymentModeV1.LIVE)))

    assert result.status is RollbackPlanStatusV1.BLOCKED
    assert result.block_code == "LIVE_OPERATOR_SWITCH"
    assert result.executable is False
    assert result.forward_deployment_id == "deploy-forward-42"
    result.assert_sealed()


@pytest.mark.parametrize(
    ("prior_changes", "code"),
    [
        ({"artifact_id": "artifact-current"}, "ARTIFACT_NOT_DISTINCT"),
        ({"artifact_sha256": "a" * 64}, "ARTIFACT_NOT_DISTINCT"),
        ({"created_at_ns": 200}, "PRIOR_NOT_EARLIER"),
        ({"created_at_ns": 201}, "PRIOR_NOT_EARLIER"),
        ({"target_id": "terminal-b"}, "TARGET_MISMATCH"),
        ({"platform": MtPlatformV1.MT4}, "PLATFORM_MISMATCH"),
    ],
)
def test_invalid_prior_facts_raise_content_free_code(prior_changes, code: str) -> None:
    prior = _artifact(
        artifact_id=prior_changes.get("artifact_id", "artifact-prior"),
        target_id=prior_changes.get("target_id", "terminal-a"),
        platform=prior_changes.get("platform", MtPlatformV1.MT5),
        created_at_ns=prior_changes.get("created_at_ns", 100),
        artifact_sha256=prior_changes.get("artifact_sha256", "b" * 64),
    )

    with pytest.raises(RollbackPlanError) as error:
        validate_rollback_proposal(_proposal(prior=prior))

    assert error.value.code == code
    assert str(error.value) == code


def test_forward_target_mismatch_is_rejected() -> None:
    with pytest.raises(RollbackPlanError) as error:
        validate_rollback_proposal(_proposal(target=_target(target_id="terminal-b")))

    assert error.value.code == "TARGET_MISMATCH"


def test_tampered_provenance_is_rejected_without_echoing_value() -> None:
    current = _artifact(
        artifact_id="artifact-current",
        created_at_ns=200,
        artifact_sha256="a" * 64,
    )
    proposal = _proposal(current=current)
    object.__setattr__(current, "provenance_sha256", "sensitive-tampered-content")

    with pytest.raises(RollbackPlanError) as error:
        validate_rollback_proposal(proposal)

    assert error.value.code == "PROVENANCE_INVALID"
    assert "sensitive-tampered-content" not in str(error.value)


@pytest.mark.parametrize("deployment_id", ["", "not valid", "\n"])
def test_forward_deployment_identity_is_required_and_grammar_checked(
    deployment_id: str,
) -> None:
    with pytest.raises(RollbackPlanError) as error:
        _proposal(forward_deployment_id=deployment_id)

    assert error.value.code == "INVALID_INPUT"


def test_artifact_digest_fields_are_validated() -> None:
    with pytest.raises(RollbackPlanError) as error:
        _artifact(
            artifact_id="artifact-x",
            created_at_ns=1,
            artifact_sha256="not-a-sha256",
        )

    assert error.value.code == "INVALID_INPUT"


def test_reinitialization_of_issued_plan_is_rejected_before_any_field_write() -> None:
    result = validate_rollback_proposal(_proposal())
    original = (
        result.status,
        result.target_id,
        result.platform,
        result.mode,
        result.current_artifact_id,
        result.prior_artifact_id,
        result.forward_deployment_id,
        result.block_code,
        result.executable,
    )

    with pytest.raises(SealError) as error:
        result.__init__(
            status=RollbackPlanStatusV1.BLOCKED,
            target_id="changed-target",
            platform=MtPlatformV1.MT4,
            mode=DeploymentModeV1.LIVE,
            current_artifact_id="changed-current",
            prior_artifact_id=None,
            forward_deployment_id="changed-forward",
            block_code="LIVE_OPERATOR_SWITCH",
            executable=True,
        )

    assert error.value.code == "SEAL_FORBIDDEN_OPERATION"
    assert (
        result.status,
        result.target_id,
        result.platform,
        result.mode,
        result.current_artifact_id,
        result.prior_artifact_id,
        result.forward_deployment_id,
        result.block_code,
        result.executable,
    ) == original
    result.assert_sealed()


def test_reinitialization_of_any_issued_input_record_is_rejected() -> None:
    target = _target()
    current = _artifact(
        artifact_id="artifact-current",
        created_at_ns=200,
        artifact_sha256="a" * 64,
    )
    proposal = _proposal(target=target, current=current)

    with pytest.raises(SealError, match="SEAL_FORBIDDEN_OPERATION"):
        target.__init__(
            target_id="changed-target", platform=MtPlatformV1.MT4, mode=DeploymentModeV1.LIVE
        )
    with pytest.raises(SealError, match="SEAL_FORBIDDEN_OPERATION"):
        current.__init__(
            artifact_id="changed-artifact",
            target_id="terminal-a",
            platform=MtPlatformV1.MT5,
            created_at_ns=1,
            artifact_sha256="d" * 64,
            provenance_sha256="e" * 64,
        )
    with pytest.raises(SealError, match="SEAL_FORBIDDEN_OPERATION"):
        proposal.__init__(
            target=target,
            current_artifact=current,
            prior_artifact=None,
            forward_deployment_id="changed-forward",
        )

    target.assert_sealed()
    current.assert_sealed()
    proposal.assert_sealed()


@pytest.mark.parametrize(
    "value",
    [
        _target(),
        _artifact(
            artifact_id="artifact-copy",
            created_at_ns=1,
            artifact_sha256="a" * 64,
        ),
        _proposal(),
        validate_rollback_proposal(_proposal()),
    ],
)
def test_issued_records_cannot_be_copied_deepcopied_or_pickled(value) -> None:
    with pytest.raises(SealError, match="SEAL_FORBIDDEN_OPERATION"):
        copy.copy(value)
    with pytest.raises(SealError, match="SEAL_FORBIDDEN_OPERATION"):
        copy.deepcopy(value)
    with pytest.raises(SealError, match="SEAL_FORBIDDEN_OPERATION"):
        pickle.dumps(value)
