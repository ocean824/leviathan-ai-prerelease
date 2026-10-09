"""Offline release-evidence readiness policy.

This module evaluates immutable, caller-supplied evidence. It has no deployment,
CI, provider, database, or network integration.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Self

from pydantic import ConfigDict, StrictBool, StrictInt, StrictStr, field_validator, model_validator

from leviathan_core.seal import Issuer, SealedModel, SealError, require

_EVIDENCE_TAG = "deployment_release_policy.evidence"
_POLICY_TAG = "deployment_release_policy.policy"
_RESULT_TAG = "deployment_release_policy.result"
_ID = re.compile(r"[a-z][a-z0-9]*(?:[-_.][a-z0-9]+)*\Z", re.ASCII)
_SECRET_TOKEN = re.compile(
    r"(?:^|[-_.])(?:api[_-]?key|secret|password|passwd|credential|token|private[_-]?key|access[_-]?key)(?:$|[-_.])"
    r"|(?:^|[-_])sk-(?:live|test|proj)-[a-z0-9_-]{3,}"
    r"|(?:^|[-_])(?:gh[pousr]|xox[baprs])-[a-z0-9_-]{8,}"
    r"|AKIA[0-9A-Z]{16}",
    re.IGNORECASE | re.ASCII,
)
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z", re.ASCII)
_VAULT_REF = re.compile(
    r"vault://leviathan-ai/(?:development|test|staging|production|live)/"
    r"[a-z0-9]+(?:-[a-z0-9]+)*/[A-Za-z][A-Za-z0-9_-]{0,79}\Z",
    re.ASCII,
)


class ReleasePolicyError(ValueError):
    """Content-free failure at the public release-policy boundary."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class FindingSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ReadinessBlocker(StrEnum):
    PROMOTION_NOT_APPROVED = "PROMOTION_NOT_APPROVED"
    APPROVALS_INSUFFICIENT = "APPROVALS_INSUFFICIENT"
    APPROVAL_ROLE_MISSING = "APPROVAL_ROLE_MISSING"
    IMAGE_NOT_DETERMINISTIC = "IMAGE_NOT_DETERMINISTIC"
    REQUIRED_TEST_MISSING = "REQUIRED_TEST_MISSING"
    REQUIRED_TEST_FAILED = "REQUIRED_TEST_FAILED"
    DISALLOWED_FINDING_OPEN = "DISALLOWED_FINDING_OPEN"
    ROLLBACK_LINEAGE_INVALID = "ROLLBACK_LINEAGE_INVALID"
    EVIDENCE_UNTRUSTED = "EVIDENCE_UNTRUSTED"
    POLICY_UNTRUSTED = "POLICY_UNTRUSTED"
    PRIOR_RELEASE_UNTRUSTED = "PRIOR_RELEASE_UNTRUSTED"


class _ReleaseModel(SealedModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        revalidate_instances="always",
        strict=True,
    )


def _identifier(value: str) -> str:
    if (
        type(value) is not str
        or len(value) > 64
        or _ID.fullmatch(value) is None
        or _SECRET_TOKEN.search(value) is not None
    ):
        raise ValueError
    return value


class ApprovalEvidence(_ReleaseModel):
    approver_id: StrictStr
    role: StrictStr
    approved: StrictBool

    def __init__(self, approver_id: str, role: str, approved: bool) -> None:
        values: dict[str, object] = {
            "approver_id": approver_id,
            "role": role,
            "approved": approved,
        }
        super().__init__(**values)

    @field_validator("approver_id", "role")
    @classmethod
    def _safe_identifier(cls, value: str) -> str:
        return _identifier(value)


class TestEvidence(_ReleaseModel):
    __test__ = False

    test_id: StrictStr
    passed: StrictBool

    @field_validator("test_id")
    @classmethod
    def _safe_test_id(cls, value: str) -> str:
        return _identifier(value)


class FindingEvidence(_ReleaseModel):
    finding_id: StrictStr
    severity: FindingSeverity
    open: StrictBool

    @field_validator("severity", mode="before")
    @classmethod
    def _parse_severity(cls, value: object) -> object:
        if type(value) is str:
            try:
                return FindingSeverity(value)
            except ValueError:
                raise ValueError from None
        return value

    @field_validator("finding_id")
    @classmethod
    def _safe_finding_id(cls, value: str) -> str:
        return _identifier(value)


class ReleasePolicy(_ReleaseModel):
    required_test_ids: tuple[StrictStr, ...]
    disallowed_open_severities: tuple[FindingSeverity, ...]
    minimum_approvers: StrictInt = 2
    required_approver_roles: tuple[StrictStr, ...] = ()

    @field_validator("required_test_ids", "required_approver_roles", mode="before")
    @classmethod
    def _tuple_only(cls, value: object) -> object:
        if type(value) is not tuple:
            raise ValueError
        return value

    @field_validator("disallowed_open_severities", mode="before")
    @classmethod
    def _parse_severity_tuple(cls, value: object) -> object:
        if type(value) is not tuple:
            raise ValueError
        try:
            return tuple(
                item if type(item) is FindingSeverity else FindingSeverity(item)
                if type(item) is str else item
                for item in value
            )
        except ValueError:
            raise ValueError from None

    @field_validator("required_test_ids", "required_approver_roles")
    @classmethod
    def _safe_unique_ids(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(_identifier(item) for item in values)
        if len(set(normalized)) != len(normalized):
            raise ValueError
        return normalized

    @field_validator("minimum_approvers")
    @classmethod
    def _bounded_approver_count(cls, value: int) -> int:
        if type(value) is not int or not 2 <= value <= 10:
            raise ValueError
        return value

    @model_validator(mode="after")
    def _valid_policy(self) -> Self:
        if not self.required_test_ids or not self.disallowed_open_severities:
            raise ValueError
        if len(set(self.disallowed_open_severities)) != len(self.disallowed_open_severities):
            raise ValueError
        return self


class ReleaseEvidence(_ReleaseModel):
    release_id: StrictStr
    release_author_id: StrictStr
    release_requester_id: StrictStr
    created_utc_ns: StrictInt
    promotion_approved: StrictBool
    approvals: tuple[ApprovalEvidence, ...]
    image_digest: StrictStr
    deterministic: StrictBool
    tests: tuple[TestEvidence, ...]
    findings: tuple[FindingEvidence, ...]
    secret_refs: tuple[StrictStr, ...] = ()
    rollback_of: StrictStr | None = None

    @field_validator("approvals", "tests", "findings", "secret_refs", mode="before")
    @classmethod
    def _tuple_only(cls, value: object) -> object:
        if type(value) is not tuple:
            raise ValueError
        return value

    @field_validator("release_id", "release_author_id", "release_requester_id", "rollback_of")
    @classmethod
    def _safe_release_id(cls, value: str | None) -> str | None:
        return None if value is None else _identifier(value)

    @field_validator("created_utc_ns")
    @classmethod
    def _valid_created_time(cls, value: int) -> int:
        if type(value) is not int or value <= 0:
            raise ValueError
        return value

    @field_validator("image_digest")
    @classmethod
    def _valid_image_digest(cls, value: str) -> str:
        if type(value) is not str or _SHA256.fullmatch(value) is None:
            raise ValueError
        return value

    @field_validator("secret_refs")
    @classmethod
    def _logical_secret_refs_only(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(type(value) is not str or _VAULT_REF.fullmatch(value) is None for value in values):
            raise ValueError
        if len(set(values)) != len(values):
            raise ValueError
        return values

    @model_validator(mode="after")
    def _unique_evidence_ids(self) -> Self:
        if len({item.test_id for item in self.tests}) != len(self.tests):
            raise ValueError
        if len({item.finding_id for item in self.findings}) != len(self.findings):
            raise ValueError
        return self


class ReleaseReadiness(_ReleaseModel):
    ready: StrictBool
    blockers: tuple[ReadinessBlocker, ...]

    @model_validator(mode="after")
    def _consistent_result(self) -> Self:
        if self.ready != (not self.blockers):
            raise ValueError
        if len(set(self.blockers)) != len(self.blockers):
            raise ValueError
        return self


_EVIDENCE_ISSUER = Issuer(_EVIDENCE_TAG)
_POLICY_ISSUER = Issuer(_POLICY_TAG)
_RESULT_ISSUER = Issuer(_RESULT_TAG)


def issue_release_policy(
    *,
    required_test_ids: tuple[str, ...],
    disallowed_open_severities: tuple[FindingSeverity | str, ...],
    minimum_approvers: int = 2,
    required_approver_roles: tuple[str, ...] = (),
) -> ReleasePolicy:
    """Validate and issue immutable, caller-supplied readiness thresholds."""
    try:
        severities = tuple(
            value if type(value) is FindingSeverity else FindingSeverity(value)
            for value in disallowed_open_severities
        )
        return _POLICY_ISSUER.issue(
            ReleasePolicy(
                required_test_ids=required_test_ids,
                disallowed_open_severities=severities,
                minimum_approvers=minimum_approvers,
                required_approver_roles=required_approver_roles,
            )
        )
    except (SealError, TypeError, ValueError):
        raise ReleasePolicyError("POLICY_INVALID") from None


def issue_release_evidence(
    *,
    release_id: str,
    release_author_id: str,
    release_requester_id: str,
    created_utc_ns: int,
    promotion_approved: bool,
    approvals: tuple[ApprovalEvidence, ...],
    image_digest: str,
    deterministic: bool,
    tests: tuple[TestEvidence, ...],
    findings: tuple[FindingEvidence, ...],
    secret_refs: tuple[str, ...] = (),
    rollback_of: str | None = None,
) -> ReleaseEvidence:
    """Validate and issue one immutable release-evidence record."""
    try:
        return _EVIDENCE_ISSUER.issue(
            ReleaseEvidence(
                release_id=release_id,
                release_author_id=release_author_id,
                release_requester_id=release_requester_id,
                created_utc_ns=created_utc_ns,
                promotion_approved=promotion_approved,
                approvals=approvals,
                image_digest=image_digest,
                deterministic=deterministic,
                tests=tests,
                findings=findings,
                secret_refs=secret_refs,
                rollback_of=rollback_of,
            )
        )
    except (SealError, TypeError, ValueError):
        raise ReleasePolicyError("EVIDENCE_INVALID") from None


def _blocked_result(blocker: ReadinessBlocker) -> ReleaseReadiness:
    return _RESULT_ISSUER.issue(ReleaseReadiness(ready=False, blockers=(blocker,)))


def _require_issued(value: object, issuer: Issuer) -> bool:
    try:
        require(value, issuer.tag)
    except SealError:
        return False
    return True


def evaluate_release_readiness(
    evidence: ReleaseEvidence,
    policy: ReleasePolicy,
    *,
    prior_releases: tuple[ReleaseEvidence, ...] = (),
) -> ReleaseReadiness:
    """Return a sealed readiness report, failing closed on invalid evidence."""
    if type(prior_releases) is not tuple:
        raise ReleasePolicyError("PRIOR_RELEASES_INVALID")
    if not _require_issued(evidence, _EVIDENCE_ISSUER):
        return _blocked_result(ReadinessBlocker.EVIDENCE_UNTRUSTED)
    if not _require_issued(policy, _POLICY_ISSUER):
        return _blocked_result(ReadinessBlocker.POLICY_UNTRUSTED)
    for prior in prior_releases:
        if not _require_issued(prior, _EVIDENCE_ISSUER):
            return _blocked_result(ReadinessBlocker.PRIOR_RELEASE_UNTRUSTED)

    blockers: list[ReadinessBlocker] = []
    if not evidence.promotion_approved:
        blockers.append(ReadinessBlocker.PROMOTION_NOT_APPROVED)
    excluded_approvers = {evidence.release_author_id, evidence.release_requester_id}
    approved = tuple(
        item
        for item in evidence.approvals
        if item.approved and item.approver_id not in excluded_approvers
    )
    if len({item.approver_id for item in approved}) < policy.minimum_approvers:
        blockers.append(ReadinessBlocker.APPROVALS_INSUFFICIENT)
    if not set(policy.required_approver_roles).issubset({item.role for item in approved}):
        blockers.append(ReadinessBlocker.APPROVAL_ROLE_MISSING)
    if not evidence.deterministic:
        blockers.append(ReadinessBlocker.IMAGE_NOT_DETERMINISTIC)
    tests = {item.test_id: item.passed for item in evidence.tests}
    if any(test_id not in tests for test_id in policy.required_test_ids):
        blockers.append(ReadinessBlocker.REQUIRED_TEST_MISSING)
    if any(tests.get(test_id) is False for test_id in policy.required_test_ids):
        blockers.append(ReadinessBlocker.REQUIRED_TEST_FAILED)
    if any(
        item.open and item.severity in policy.disallowed_open_severities
        for item in evidence.findings
    ):
        blockers.append(ReadinessBlocker.DISALLOWED_FINDING_OPEN)
    if evidence.rollback_of is not None and (
        evidence.rollback_of == evidence.release_id
        or not any(
            prior.release_id == evidence.rollback_of
            and prior.created_utc_ns < evidence.created_utc_ns
            for prior in prior_releases
        )
    ):
        blockers.append(ReadinessBlocker.ROLLBACK_LINEAGE_INVALID)

    try:
        result = ReleaseReadiness(ready=not blockers, blockers=tuple(blockers))
        return _RESULT_ISSUER.issue(result)
    except (SealError, TypeError, ValueError):
        raise ReleasePolicyError("READINESS_INVALID") from None


__all__ = [
    "ApprovalEvidence",
    "FindingEvidence",
    "FindingSeverity",
    "ReadinessBlocker",
    "ReleaseEvidence",
    "ReleasePolicy",
    "ReleasePolicyError",
    "ReleaseReadiness",
    "TestEvidence",
    "evaluate_release_readiness",
    "issue_release_evidence",
    "issue_release_policy",
]
