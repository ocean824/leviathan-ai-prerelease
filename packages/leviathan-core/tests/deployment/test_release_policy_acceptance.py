"""Independent offline acceptance for deployment release readiness evidence."""

from __future__ import annotations

import copy
import pickle
from contextlib import suppress
from typing import Any

import pytest

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

REQUIRED_TESTS = ("build-unit", "build-integration")
DISALLOWED = (FindingSeverity.CRITICAL, FindingSeverity.HIGH)
_ISSUED_AT = 1_800_000_000_000_000_000
_VALID_DIGEST = "sha256:" + "a" * 64
_SBOM_DIGEST = "sha256:" + "b" * 64


def _policy(
    *,
    required_test_ids: tuple[str, ...] = REQUIRED_TESTS,
    disallowed_open_severities: tuple[FindingSeverity, ...] = DISALLOWED,
    minimum_approvers: int = 2,
    required_approver_roles: tuple[str, ...] = (),
):
    return issue_release_policy(
        required_test_ids=required_test_ids,
        disallowed_open_severities=disallowed_open_severities,
        minimum_approvers=minimum_approvers,
        required_approver_roles=required_approver_roles,
    )


def _evidence(
    *,
    release_id: str = "synthetic-release-002",
    release_author_id: str = "synthetic-release-author",
    release_requester_id: str = "synthetic-release-requester",
    created_utc_ns: int = _ISSUED_AT,
    promotion_approved: bool = True,
    approvals: tuple[ApprovalEvidence, ...] | None = None,
    image_digest: str | None = _VALID_DIGEST,
    deterministic: bool = True,
    tests: tuple[TestEvidence, ...] | None = None,
    findings: tuple[FindingEvidence, ...] = (),
    secret_refs: tuple[str, ...] = (),
    rollback_of: str | None = None,
):
    return issue_release_evidence(
        release_id=release_id,
        created_utc_ns=created_utc_ns,
        promotion_approved=promotion_approved,
        release_author_id=release_author_id,
        release_requester_id=release_requester_id,
        approvals=(
            (
                ApprovalEvidence(
                    approver_id="synthetic-approver-001", role="operator", approved=True
                ),
                ApprovalEvidence(
                    approver_id="synthetic-approver-002", role="operator", approved=True
                ),
            )
        )
        if approvals is None
        else approvals,
        image_digest=image_digest,
        deterministic=deterministic,
        tests=(
            tuple(TestEvidence(test_id=test_id, passed=True) for test_id in REQUIRED_TESTS)
            if tests is None
            else tests
        ),
        findings=findings,
        secret_refs=secret_refs,
        rollback_of=rollback_of,
    )


def _readiness(evidence: Any, policy: Any = None, *, prior_releases: tuple[Any, ...] = ()):
    return evaluate_release_readiness(
        evidence,
        _policy() if policy is None else policy,
        prior_releases=prior_releases,
    )


def test_complete_synthetic_evidence_is_ready_without_runtime_or_activation_claims() -> None:
    evidence = _evidence(secret_refs=("vault://leviathan-ai/production/synthetic-db/primary",))

    result = _readiness(evidence)

    assert result.ready is True
    assert result.blockers == ()
    assert not hasattr(evidence, "runtime_provider")
    assert not hasattr(evidence, "deploy")


@pytest.mark.parametrize("missing_test", REQUIRED_TESTS)
def test_each_missing_required_test_blocks_readiness(missing_test: str) -> None:
    tests = tuple(
        TestEvidence(test_id=test_id, passed=True)
        for test_id in REQUIRED_TESTS
        if test_id != missing_test
    )

    result = _readiness(_evidence(tests=tests))

    assert result.ready is False
    assert ReadinessBlocker.REQUIRED_TEST_MISSING in result.blockers


def test_failed_required_test_blocks_even_when_the_other_gates_pass() -> None:
    tests = (
        TestEvidence(test_id=REQUIRED_TESTS[0], passed=True),
        TestEvidence(test_id=REQUIRED_TESTS[1], passed=False),
    )

    result = _readiness(_evidence(tests=tests))

    assert result.ready is False
    assert ReadinessBlocker.REQUIRED_TEST_FAILED in result.blockers


def test_unapproved_promotion_and_nondeterministic_image_block() -> None:
    for evidence in (
        _evidence(promotion_approved=False),
        _evidence(deterministic=False),
    ):
        result = _readiness(evidence)
        assert result.ready is False
        assert ReadinessBlocker.PROMOTION_NOT_APPROVED in result.blockers or (
            ReadinessBlocker.IMAGE_NOT_DETERMINISTIC in result.blockers
        )


def test_missing_image_digest_is_rejected_at_evidence_boundary() -> None:
    with pytest.raises(ReleasePolicyError) as caught:
        _evidence(image_digest=None)  # type: ignore[arg-type]
    assert caught.value.code == "EVIDENCE_INVALID"


def test_approval_count_and_required_roles_are_enforced_by_policy() -> None:
    policy = _policy(minimum_approvers=2, required_approver_roles=("release_manager",))
    one = (
        ApprovalEvidence(
            approver_id="synthetic-approver-001", role="release_manager", approved=True
        ),
    )
    duplicate_identity = (
        ApprovalEvidence(
            approver_id="synthetic-approver-001", role="release_manager", approved=True
        ),
        ApprovalEvidence(approver_id="synthetic-approver-001", role="operator", approved=True),
    )
    wrong_role = (
        ApprovalEvidence(approver_id="synthetic-approver-001", role="operator", approved=True),
        ApprovalEvidence(approver_id="synthetic-approver-002", role="operator", approved=True),
    )

    assert _readiness(_evidence(approvals=one), policy).ready is False
    assert _readiness(_evidence(approvals=duplicate_identity), policy).ready is False
    assert _readiness(_evidence(approvals=wrong_role), policy).ready is False

    valid_pair = (
        ApprovalEvidence(
            approver_id="synthetic-approver-001", role="release_manager", approved=True
        ),
        ApprovalEvidence(approver_id="synthetic-approver-002", role="operator", approved=True),
    )
    assert _readiness(_evidence(approvals=valid_pair), policy).ready is True


def test_default_policy_requires_two_distinct_eligible_approvers() -> None:
    one_approval = (
        ApprovalEvidence(
            approver_id="synthetic-eligible-approver-001", role="operator", approved=True
        ),
    )
    duplicate_principal = (
        ApprovalEvidence(
            approver_id="synthetic-eligible-approver-001", role="operator", approved=True
        ),
        ApprovalEvidence(
            approver_id="synthetic-eligible-approver-001", role="release_manager", approved=True
        ),
    )
    two_distinct = (
        ApprovalEvidence(
            approver_id="synthetic-eligible-approver-001", role="operator", approved=True
        ),
        ApprovalEvidence(
            approver_id="synthetic-eligible-approver-002", role="release_manager", approved=True
        ),
    )

    assert _readiness(_evidence(approvals=one_approval)).ready is False
    assert _readiness(_evidence(approvals=duplicate_principal)).ready is False
    assert _readiness(_evidence(approvals=two_distinct)).ready is True


@pytest.mark.parametrize("excluded_role", ("author", "requester"))
def test_author_and_requester_approvals_do_not_count(excluded_role: str) -> None:
    author_id = "synthetic-release-author"
    requester_id = "synthetic-release-requester"
    excluded_id = author_id if excluded_role == "author" else requester_id
    approvals = (
        ApprovalEvidence(approver_id=excluded_id, role="operator", approved=True),
        ApprovalEvidence(
            approver_id="synthetic-eligible-approver-001", role="operator", approved=True
        ),
    )

    result = _readiness(
        _evidence(
            release_author_id=author_id,
            release_requester_id=requester_id,
            approvals=approvals,
        )
    )

    assert result.ready is False


def test_policy_rejects_minimum_approvers_below_two() -> None:
    with pytest.raises(ReleasePolicyError) as caught:
        _policy(minimum_approvers=1)

    assert caught.value.code == "POLICY_INVALID"
    assert str(caught.value) == caught.value.code
    assert caught.value.args == (caught.value.code,)


def test_release_author_and_requester_fields_are_mandatory() -> None:
    with pytest.raises(TypeError):
        issue_release_evidence(
            release_id="synthetic-missing-release-roles",
            created_utc_ns=_ISSUED_AT,
            promotion_approved=True,
            approvals=(),
            image_digest=_VALID_DIGEST,
            deterministic=True,
            tests=(),
            findings=(),
        )


def test_disallowed_open_findings_block_but_closed_or_allowed_severity_does_not() -> None:
    policy = _policy(disallowed_open_severities=(FindingSeverity.CRITICAL, FindingSeverity.HIGH))
    blocked = _readiness(
        _evidence(
            findings=(
                FindingEvidence(
                    finding_id="synthetic-finding-1",
                    severity=FindingSeverity.CRITICAL,
                    open=True,
                ),
            )
        ),
        policy,
    )
    allowed_open = _readiness(
        _evidence(
            findings=(
                FindingEvidence(
                    finding_id="synthetic-finding-2", severity=FindingSeverity.LOW, open=True
                ),
            )
        ),
        policy,
    )
    closed_critical = _readiness(
        _evidence(
            findings=(
                FindingEvidence(
                    finding_id="synthetic-finding-3",
                    severity=FindingSeverity.CRITICAL,
                    open=False,
                ),
            )
        ),
        policy,
    )

    assert blocked.ready is False
    assert ReadinessBlocker.DISALLOWED_FINDING_OPEN in blocked.blockers
    assert allowed_open.ready is True
    assert closed_critical.ready is True


@pytest.mark.parametrize(
    "literal",
    (
        "synthetic-secret-value-do-not-persist",
        "password=synthetic-secret-value",
        "-----BEGIN PRIVATE KEY-----synthetic-only-----END PRIVATE KEY-----",
    ),
)
def test_secret_material_is_rejected_and_never_echoed(literal: str) -> None:
    with pytest.raises((TypeError, ValueError)) as caught:
        _evidence(secret_refs=(literal,))

    rendered = repr(caught.value) + str(caught.value) + repr(caught.value.args)
    assert literal not in rendered
    assert str(len(literal)) not in rendered


def test_only_logical_vault_references_are_accepted_as_secret_metadata() -> None:
    evidence = _evidence(secret_refs=("vault://leviathan-ai/staging/synthetic-service/api-key",))

    assert _readiness(evidence).ready is True
    assert not hasattr(evidence, "secret_values")


def test_provider_specific_runtime_is_not_an_approved_release_input() -> None:
    with pytest.raises(TypeError):
        issue_release_evidence(
            release_id="synthetic-oci-release",
            release_author_id="synthetic-release-author",
            release_requester_id="synthetic-release-requester",
            created_utc_ns=_ISSUED_AT,
            promotion_approved=True,
            approvals=(ApprovalEvidence("synthetic-approver", "operator", True),),
            image_digest=_VALID_DIGEST,
            deterministic=True,
            tests=tuple(TestEvidence(test_id=test_id, passed=True) for test_id in REQUIRED_TESTS),
            findings=(),
            secret_refs=(),
            rollback_of=None,
            runtime_provider="OCI",
        )


def test_sealed_evidence_copy_and_tampering_cannot_preserve_readiness() -> None:
    evidence = _evidence()
    policy = _policy()
    assert _readiness(evidence, policy).ready is True

    for copier in (copy.copy, copy.deepcopy):
        try:
            copied = copier(evidence)
        except (TypeError, ValueError):
            continue
        assert _readiness(copied, policy).ready is False

    try:
        restored = pickle.loads(pickle.dumps(evidence))
    except (TypeError, ValueError):
        pass
    else:
        assert _readiness(restored, policy).ready is False

    try:
        object.__setattr__(evidence, "promotion_approved", False)
    except (AttributeError, TypeError, ValueError):
        assert _readiness(evidence, policy).ready is True
    else:
        assert _readiness(evidence, policy).ready is False


def test_rollback_requires_a_prior_release_and_preserves_its_identity() -> None:
    prior = _evidence(release_id="synthetic-release-prior", created_utc_ns=_ISSUED_AT - 10)
    rollback = _evidence(
        release_id="synthetic-release-rollback",
        created_utc_ns=_ISSUED_AT,
        rollback_of="synthetic-release-prior",
    )
    absent = _readiness(rollback)
    valid = _readiness(rollback, prior_releases=(prior,))
    future_prior = _evidence(
        release_id="synthetic-release-future-prior",
        created_utc_ns=_ISSUED_AT + 1,
    )
    future = _readiness(
        _evidence(
            release_id="synthetic-release-rollback-2",
            rollback_of="synthetic-release-future-prior",
        ),
        prior_releases=(future_prior,),
    )
    same_id = _readiness(
        _evidence(release_id="synthetic-release-prior", rollback_of="synthetic-release-prior"),
        prior_releases=(prior,),
    )

    assert absent.ready is False
    assert ReadinessBlocker.ROLLBACK_LINEAGE_INVALID in absent.blockers
    assert valid.ready is True
    assert future.ready is False
    assert ReadinessBlocker.ROLLBACK_LINEAGE_INVALID in future.blockers
    assert same_id.ready is False
    assert ReadinessBlocker.ROLLBACK_LINEAGE_INVALID in same_id.blockers
    assert prior.release_id == "synthetic-release-prior"
    assert prior.image_digest == _VALID_DIGEST


def test_tampered_prior_release_cannot_satisfy_rollback_lineage() -> None:
    prior = _evidence(release_id="synthetic-release-prior-tamper", created_utc_ns=_ISSUED_AT - 10)
    rollback = _evidence(
        release_id="synthetic-release-rollback-tamper",
        created_utc_ns=_ISSUED_AT,
        rollback_of="synthetic-release-prior-tamper",
    )
    with suppress(AttributeError, TypeError, ValueError):
        object.__setattr__(prior, "image_digest", "sha256:" + "c" * 64)

    result = _readiness(rollback, prior_releases=(prior,))

    assert result.ready is False
    assert "PRIOR_RELEASE_UNTRUSTED" in {str(blocker) for blocker in result.blockers}
