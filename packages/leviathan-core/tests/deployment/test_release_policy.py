from __future__ import annotations

import copy
import pickle
import sys
from pathlib import Path

import pytest
from pydantic import BaseModel

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from leviathan_core.deployment_release_policy import (
    ApprovalEvidence,
    FindingEvidence,
    FindingSeverity,
    ReadinessBlocker,
    ReleasePolicyError,
    TestEvidence,
    evaluate_release_readiness,
    issue_release_evidence,
    issue_release_policy,
)
from leviathan_core.seal import SealError


def _policy(
    *,
    minimum_approvers: int = 2,
    required_approver_roles: tuple[str, ...] = ("release-manager", "security-reviewer"),
):
    return issue_release_policy(
        required_test_ids=("unit-tests", "integration-tests"),
        disallowed_open_severities=(FindingSeverity.CRITICAL, FindingSeverity.HIGH),
        minimum_approvers=minimum_approvers,
        required_approver_roles=required_approver_roles,
    )


def _evidence(**overrides):
    values = {
        "release_id": "release-002",
        "release_author_id": "person-author",
        "release_requester_id": "person-requester",
        "created_utc_ns": 2_000,
        "promotion_approved": True,
        "approvals": (
            ApprovalEvidence(approver_id="person-1", role="release-manager", approved=True),
            ApprovalEvidence(approver_id="person-2", role="security-reviewer", approved=True),
        ),
        "image_digest": "sha256:" + "a" * 64,
        "deterministic": True,
        "tests": (
            TestEvidence(test_id="unit-tests", passed=True),
            TestEvidence(test_id="integration-tests", passed=True),
        ),
        "findings": (),
        "secret_refs": (),
        "rollback_of": None,
    }
    values.update(overrides)
    return issue_release_evidence(**values)


def test_complete_issued_evidence_is_ready_and_report_is_issued() -> None:
    evidence = _evidence()
    report = evaluate_release_readiness(evidence, _policy())

    assert report.ready is True
    assert report.blockers == ()
    with pytest.raises(SealError):
        report.ready = False
    with pytest.raises(SealError):
        evidence.tests[0].passed = False


def test_each_required_gate_blocks_readiness_with_fixed_codes() -> None:
    evidence = _evidence(
        promotion_approved=False,
        approvals=(
            ApprovalEvidence(approver_id="person-1", role="release-manager", approved=True),
        ),
        deterministic=False,
        tests=(TestEvidence(test_id="unit-tests", passed=False),),
        findings=(
            FindingEvidence(
                finding_id="finding-1", severity=FindingSeverity.HIGH, open=True
            ),
        ),
    )

    report = evaluate_release_readiness(evidence, _policy())

    assert report.ready is False
    assert report.blockers == (
        ReadinessBlocker.PROMOTION_NOT_APPROVED,
        ReadinessBlocker.APPROVALS_INSUFFICIENT,
        ReadinessBlocker.APPROVAL_ROLE_MISSING,
        ReadinessBlocker.IMAGE_NOT_DETERMINISTIC,
        ReadinessBlocker.REQUIRED_TEST_MISSING,
        ReadinessBlocker.REQUIRED_TEST_FAILED,
        ReadinessBlocker.DISALLOWED_FINDING_OPEN,
    )


def test_closed_findings_and_unrequired_failed_tests_do_not_block() -> None:
    evidence = _evidence(
        tests=(
            TestEvidence(test_id="unit-tests", passed=True),
            TestEvidence(test_id="integration-tests", passed=True),
            TestEvidence(test_id="optional-check", passed=False),
        ),
        findings=(
            FindingEvidence(
                finding_id="finding-closed", severity=FindingSeverity.CRITICAL, open=False
            ),
            FindingEvidence(finding_id="finding-low", severity=FindingSeverity.LOW, open=True),
        ),
    )

    assert evaluate_release_readiness(evidence, _policy()).ready is True


def test_distinct_approvals_and_required_roles_are_enforced() -> None:
    evidence = _evidence(
        approvals=(
            ApprovalEvidence(approver_id="person-1", role="release-manager", approved=True),
            ApprovalEvidence(approver_id="person-2", role="release-manager", approved=True),
        ),
    )

    report = evaluate_release_readiness(evidence, _policy())

    assert report.blockers == (ReadinessBlocker.APPROVAL_ROLE_MISSING,)


def test_default_approver_threshold_is_two_and_cannot_be_lowered() -> None:
    policy = issue_release_policy(
        required_test_ids=("unit-tests",),
        disallowed_open_severities=(FindingSeverity.HIGH,),
    )
    assert policy.minimum_approvers == 2

    with pytest.raises(ReleasePolicyError) as caught:
        _policy(minimum_approvers=1)
    assert caught.value.code == "POLICY_INVALID"


def test_one_approval_and_duplicate_principal_do_not_meet_default_threshold() -> None:
    policy = _policy(required_approver_roles=())
    one_approval = _evidence(
        approvals=(ApprovalEvidence("person-1", "operator", True),)
    )
    duplicate_principal = _evidence(
        approvals=(
            ApprovalEvidence("person-1", "operator", True),
            ApprovalEvidence("person-1", "reviewer", True),
        )
    )

    assert evaluate_release_readiness(one_approval, policy).blockers == (
        ReadinessBlocker.APPROVALS_INSUFFICIENT,
    )
    assert evaluate_release_readiness(duplicate_principal, policy).blockers == (
        ReadinessBlocker.APPROVALS_INSUFFICIENT,
    )


def test_author_and_requester_approvals_are_not_counted() -> None:
    evidence = _evidence(
        approvals=(
            ApprovalEvidence("person-author", "release-manager", True),
            ApprovalEvidence("person-requester", "security-reviewer", True),
        )
    )

    assert evaluate_release_readiness(evidence, _policy()).blockers == (
        ReadinessBlocker.APPROVALS_INSUFFICIENT,
        ReadinessBlocker.APPROVAL_ROLE_MISSING,
    )


def test_two_distinct_non_author_approvers_are_ready() -> None:
    evidence = _evidence(
        approvals=(
            ApprovalEvidence("person-1", "release-manager", True),
            ApprovalEvidence("person-2", "security-reviewer", True),
        )
    )

    assert evaluate_release_readiness(evidence, _policy()).ready is True


def test_rollback_requires_an_issued_prior_release_and_does_not_rewrite_it() -> None:
    prior = _evidence(release_id="release-001", created_utc_ns=1_000)
    rollback = _evidence(rollback_of="release-001")

    assert evaluate_release_readiness(rollback, _policy()).blockers == (
        ReadinessBlocker.ROLLBACK_LINEAGE_INVALID,
    )
    assert evaluate_release_readiness(
        rollback, _policy(), prior_releases=(prior,)
    ).ready is True
    assert prior.release_id == "release-001"
    assert prior.created_utc_ns == 1_000
    with pytest.raises(SealError):
        prior.release_id = "release-rewritten"


def test_rollback_to_current_or_future_release_is_invalid() -> None:
    current = _evidence(rollback_of="release-future")
    future = _evidence(release_id="release-future", created_utc_ns=3_000)

    report = evaluate_release_readiness(current, _policy(), prior_releases=(future,))

    assert report.blockers == (ReadinessBlocker.ROLLBACK_LINEAGE_INVALID,)


def test_tampered_evidence_and_policy_fail_closed() -> None:
    evidence = _evidence()
    policy = _policy()
    object.__setattr__(evidence, "deterministic", False)
    evidence_report = evaluate_release_readiness(evidence, policy)
    assert evidence_report.ready is False
    assert evidence_report.blockers == (ReadinessBlocker.EVIDENCE_UNTRUSTED,)

    evidence = _evidence()
    object.__setattr__(policy, "minimum_approvers", 1)
    policy_report = evaluate_release_readiness(evidence, policy)
    assert policy_report.ready is False
    assert policy_report.blockers == (ReadinessBlocker.POLICY_UNTRUSTED,)


def test_sealed_records_reject_copy_pickle_reinitialization_and_unissued_copies() -> None:
    evidence = _evidence()

    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(SealError):
            operation(evidence)
    with pytest.raises(SealError):
        type(evidence).model_construct(release_id="release-forged")
    with pytest.raises(SealError):
        BaseModel.__init__(evidence, deterministic=False)
    with pytest.raises(SealError):
        BaseModel.__setstate__(evidence, {"__dict__": {"deterministic": False}})

    detached = evidence.model_copy(update={"deterministic": False})
    detached_report = evaluate_release_readiness(detached, _policy())
    assert detached_report.ready is False
    assert detached_report.blockers == (ReadinessBlocker.EVIDENCE_UNTRUSTED,)
    assert evidence.deterministic is True


def test_only_logical_vault_refs_are_accepted_and_errors_do_not_echo_values() -> None:
    valid = _evidence(
        secret_refs=("vault://leviathan-ai/development/cloudflare/WORKER_TOKEN",)
    )
    assert evaluate_release_readiness(valid, _policy()).ready is True

    canary = "sk-live-super-secret-canary"
    with pytest.raises(ReleasePolicyError) as caught:
        _evidence(secret_refs=(canary,))
    assert caught.value.code == "EVIDENCE_INVALID"
    assert canary not in str(caught.value)
    assert canary not in repr(caught.value.args)

    with pytest.raises(ReleasePolicyError) as id_error:
        _evidence(release_id="sk-live-canary-123456")
    assert id_error.value.code == "EVIDENCE_INVALID"


def test_invalid_policy_bounds_and_non_tuple_collections_are_rejected() -> None:
    with pytest.raises(ReleasePolicyError) as empty_tests:
        issue_release_policy(
            required_test_ids=(),
            disallowed_open_severities=(FindingSeverity.HIGH,),
        )
    assert empty_tests.value.code == "POLICY_INVALID"

    with pytest.raises(ReleasePolicyError) as empty_severity_policy:
        issue_release_policy(
            required_test_ids=("unit-tests",),
            disallowed_open_severities=(),
        )
    assert empty_severity_policy.value.code == "POLICY_INVALID"

    with pytest.raises(ReleasePolicyError) as bool_count:
        issue_release_policy(
            required_test_ids=("unit-tests",),
            disallowed_open_severities=(),
            minimum_approvers=True,
        )
    assert bool_count.value.code == "POLICY_INVALID"

    with pytest.raises(ReleasePolicyError) as mutable_tests:
        issue_release_policy(
            required_test_ids=["unit-tests"],
            disallowed_open_severities=(),
        )
    assert mutable_tests.value.code == "POLICY_INVALID"


def test_policy_exposes_no_provider_or_runtime_approval_field() -> None:
    from leviathan_core.deployment_release_policy import ReleaseEvidence

    assert "provider" not in ReleaseEvidence.model_fields
    assert "runtime" not in ReleaseEvidence.model_fields
