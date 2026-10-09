"""Pure threshold, quorum, resource-cap and reviewer-exception evaluation."""

from __future__ import annotations

import hashlib
from decimal import Decimal

from pydantic import Field, field_validator

from leviathan_core.numeric import NumericError, canonical_json, exact_add
from leviathan_core.seal import Issuer, SealError, require

from .leak_models import (
    _CRITIQUE_ISSUER,
    _EXCEPTION_ISSUER,
    CRITIQUE_DECISION_TAG,
    MAX_METRICS,
    MAX_RUNS,
    BudgetDimension,
    CriticError,
    CritiqueDecisionV1,
    CritiqueMetricsV1,
    CritiquePolicyV1,
    CritiqueReason,
    CritiqueStatus,
    CritiqueStatusV1,
    LeakDecisionV1,
    MetricEvidenceV1,
    MetricFailureV1,
    MetricName,
    MetricThresholdV1,
    PublicationExceptionV1,
    ReviewerEvidenceClaimV1,
    ReviewerEvidenceVerifier,
    _KernelModel,
)
from .leak_rules import require_leak_decision


class ReviewerEvidenceV1(_KernelModel):
    """Opaque trusted reviewer assertion; only the verifier issues one."""

    kernel_error_code = "CRITIC_EVIDENCE_INVALID"
    kernel_error_type = CriticError

    experiment_id: str
    revision_hash: str
    author_id: str
    reviewer_id: str
    metric_names: tuple[MetricName, ...] = Field(min_length=1, max_length=MAX_METRICS)
    policy_digest: str
    reason: str
    schema_version: str = "1.0.0"

    @field_validator("metric_names")
    @classmethod
    def valid_metric_names(cls, values: tuple[MetricName, ...]) -> tuple[MetricName, ...]:
        if tuple(sorted(set(values))) != values:
            raise ValueError("reviewer scope invalid")
        return values

    @field_validator("policy_digest")
    @classmethod
    def valid_policy_digest(cls, value: str) -> str:
        if (
            type(value) is not str
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
        ):
            raise ValueError("policy digest invalid")
        return value


REVIEWER_EVIDENCE_TAG = "agent002.reviewer_evidence.v1"
_REVIEWER_ISSUER = Issuer(REVIEWER_EVIDENCE_TAG)


def critique_policy_digest(policy: CritiquePolicyV1) -> str:
    """Hash the full typed policy with NUM-001 canonical JSON."""
    if type(policy) is not CritiquePolicyV1:
        raise CriticError("CRITIQUE_POLICY_INVALID") from None
    try:
        checked = CritiquePolicyV1.model_validate(policy.model_dump(mode="python"))
        return hashlib.sha256(canonical_json(checked.model_dump(mode="python"))).hexdigest()
    except Exception:
        raise CriticError("CRITIQUE_POLICY_INVALID") from None


def issue_reviewer_evidence(
    claim: ReviewerEvidenceClaimV1, verifier: ReviewerEvidenceVerifier
) -> ReviewerEvidenceV1:
    """Issue reviewer evidence only after exact-True verifier attestation."""
    if type(claim) is not ReviewerEvidenceClaimV1:
        raise CriticError("REVIEWER_EVIDENCE_INVALID") from None
    if claim.author_id == claim.reviewer_id:
        raise CriticError("REVIEWER_NOT_DISTINCT") from None
    try:
        result = verifier.verify(claim)
    except Exception:
        raise CriticError("VERIFIER_RESULT_INVALID") from None
    if type(result) is not bool or result is not True:
        raise CriticError("VERIFIER_RESULT_INVALID") from None
    evidence = ReviewerEvidenceV1(
        experiment_id=claim.experiment_id,
        revision_hash=claim.revision_hash,
        author_id=claim.author_id,
        reviewer_id=claim.reviewer_id,
        metric_names=claim.metric_names,
        policy_digest=claim.policy_digest,
        reason=claim.reason,
    )
    return _REVIEWER_ISSUER.issue(evidence)


def require_reviewer_evidence(value: ReviewerEvidenceV1) -> ReviewerEvidenceV1:
    try:
        if type(value) is not ReviewerEvidenceV1:
            raise SealError("SEAL_NOT_ISSUED")
        return require(value, REVIEWER_EVIDENCE_TAG)
    except SealError:
        raise CriticError("REVIEWER_EVIDENCE_UNTRUSTED") from None


def _budget_failure(
    policy: CritiquePolicyV1,
    metrics: tuple[MetricEvidenceV1, ...],
    input_rows: int,
) -> BudgetDimension:
    if input_rows > policy.max_input_rows:
        return "INPUT_ROWS"
    if len(metrics) > policy.max_runs:
        return "RUNS"
    if any(
        item.critique_metrics is not None
        and len(item.critique_metrics.metrics) > policy.max_metrics
        for item in metrics
    ):
        return "METRICS"
    cost = Decimal(0)
    elapsed = 0
    compute = 0
    for item in metrics:
        try:
            cost = exact_add(cost, item.cost_usd)
        except NumericError:
            return "COST"
        elapsed += item.elapsed_ns
        compute += item.compute_units
    if cost > policy.max_evaluation_cost_usd:
        return "COST"
    if elapsed > policy.max_elapsed_ns:
        return "ELAPSED"
    if compute > policy.max_compute_units:
        return "COMPUTE"
    return "NONE"


def _empty_decision(
    *,
    leak_decision: LeakDecisionV1,
    status: CritiqueStatus,
    completed_runs: int,
    required_runs: int,
    reason: CritiqueReason,
    budget_dimension: BudgetDimension,
    revision_hash: str | None = None,
) -> CritiqueDecisionV1:
    failed_rules = leak_decision.failed_rule_ids
    resolved_status = CritiqueStatusV1.LEAK_FAILURE if failed_rules else status
    resolved_revision = revision_hash or leak_decision.revision_hash
    leak_digest = hashlib.sha256(
        canonical_json(leak_decision.model_dump(mode="python"))
    ).hexdigest()
    decision = CritiqueDecisionV1(
        experiment_id=leak_decision.experiment_id,
        revision_hash=resolved_revision,
        snapshot_hash=leak_decision.snapshot_hash,
        leak_digest=leak_digest,
        status=resolved_status,
        passed=False,
        completed_runs=completed_runs,
        required_runs=required_runs,
        metric_failures=(),
        risk_flags=(),
        leak_failures=failed_rules,
        publication_exception=None,
        reason=reason,
        budget_dimension=budget_dimension,
    )
    return _CRITIQUE_ISSUER.issue(decision)


def _make_exception(
    evidence: ReviewerEvidenceV1,
    failures: tuple[MetricFailureV1, ...],
    policy_digest: str,
) -> PublicationExceptionV1:
    names = tuple(sorted({failure.metric for failure in failures}))
    result = PublicationExceptionV1(
        experiment_id=evidence.experiment_id,
        revision_hash=evidence.revision_hash,
        author_id=evidence.author_id,
        reviewer_id=evidence.reviewer_id,
        policy_digest=policy_digest,
        reason=evidence.reason,
        metric_names=names,
    )
    return result


def evaluate_critique(
    policy: CritiquePolicyV1,
    metrics: tuple[MetricEvidenceV1, ...],
    leak: object,
    *,
    input_rows: int,
    reviewer_evidence: ReviewerEvidenceV1 | None = None,
) -> CritiqueDecisionV1:
    """Evaluate bounded completed-run evidence, preserving leak and metric failures."""
    if type(policy) is not CritiquePolicyV1 or type(metrics) is not tuple:
        raise CriticError("CRITIQUE_EVIDENCE_INVALID") from None
    try:
        policy_thresholds = object.__getattribute__(policy, "thresholds")
        if type(policy_thresholds) is not tuple or len(policy_thresholds) > 5:
            raise CriticError("CRITIQUE_POLICY_INVALID")
    except CriticError:
        raise
    except Exception:
        raise CriticError("CRITIQUE_POLICY_INVALID") from None
    try:
        policy = CritiquePolicyV1.model_validate(policy.model_dump(mode="python"))
        leak_decision = require_leak_decision(leak)  # type: ignore[arg-type]
    except (CriticError, SealError):
        raise CriticError("CRITIQUE_EVIDENCE_INVALID") from None
    if type(input_rows) is not int or input_rows < 0:
        raise CriticError("CRITIQUE_EVIDENCE_INVALID") from None
    if input_rows != leak_decision.input_rows:
        raise CriticError("CRITIQUE_EVIDENCE_MISMATCH") from None

    policy_digest = critique_policy_digest(policy)

    # Inputs above the module ceiling are rejected by count without expanding
    # any item. Within that bound, reject duplicate evidence identities before
    # a caller-controlled quorum can count them.
    if len(metrics) > MAX_RUNS:
        return _empty_decision(
            leak_decision=leak_decision,
            status=CritiqueStatusV1.INSUFFICIENT_EVIDENCE,
            completed_runs=0,
            required_runs=policy.minimum_completed_runs,
            reason="EVALUATION_BUDGET_EXCEEDED",
            budget_dimension="RUNS",
        )
    run_ids: set[str] = set()
    result_digests: set[str] = set()
    checked: list[MetricEvidenceV1] = []
    try:
        for item in metrics:
            if type(item) is not MetricEvidenceV1:
                raise CriticError("CRITIQUE_EVIDENCE_INVALID")
            nested_metrics = item.critique_metrics
            if nested_metrics is not None and (
                type(nested_metrics) is not CritiqueMetricsV1
                or type(nested_metrics.metrics) is not tuple
                or len(nested_metrics.metrics) > MAX_METRICS
            ):
                raise CriticError("CRITIQUE_EVIDENCE_INVALID")
            if item.run_id in run_ids or item.result_digest in result_digests:
                raise CriticError("CRITIQUE_EVIDENCE_DUPLICATE_RUN")
            run_ids.add(item.run_id)
            result_digests.add(item.result_digest)
            checked.append(MetricEvidenceV1.model_validate(item.model_dump(mode="python")))
    except CriticError:
        raise
    except Exception:
        raise CriticError("CRITIQUE_EVIDENCE_INVALID") from None
    metrics = tuple(checked)

    all_ids = {item.experiment_id for item in metrics}
    revisions = {item.revision_hash for item in metrics}
    authors = {item.author_id for item in metrics}
    if (
        len(all_ids) > 1
        or len(revisions) > 1
        or len(authors) > 1
        or (all_ids and all_ids != {leak_decision.experiment_id})
        or (revisions and revisions != {leak_decision.revision_hash})
    ):
        raise CriticError("CRITIQUE_EVIDENCE_MISMATCH") from None
    experiment_id = leak_decision.experiment_id
    revision_hash = leak_decision.revision_hash
    author_id = next(iter(authors), "")

    if input_rows > policy.max_input_rows:
        return _empty_decision(
            leak_decision=leak_decision,
            status=CritiqueStatusV1.INSUFFICIENT_EVIDENCE,
            completed_runs=0,
            required_runs=policy.minimum_completed_runs,
            reason="EVALUATION_BUDGET_EXCEEDED",
            budget_dimension="INPUT_ROWS",
        )
    if len(metrics) > policy.max_runs:
        return _empty_decision(
            leak_decision=leak_decision,
            status=CritiqueStatusV1.INSUFFICIENT_EVIDENCE,
            completed_runs=0,
            required_runs=policy.minimum_completed_runs,
            reason="EVALUATION_BUDGET_EXCEEDED",
            budget_dimension="RUNS",
        )
    if any(
        item.critique_metrics is not None
        and len(item.critique_metrics.metrics) > policy.max_metrics
        for item in metrics
    ):
        return _empty_decision(
            leak_decision=leak_decision,
            status=CritiqueStatusV1.INSUFFICIENT_EVIDENCE,
            completed_runs=0,
            required_runs=policy.minimum_completed_runs,
            reason="EVALUATION_BUDGET_EXCEEDED",
            budget_dimension="METRICS",
        )

    dimension = _budget_failure(policy, metrics, input_rows)
    if dimension != "NONE":
        return _empty_decision(
            leak_decision=leak_decision,
            status=CritiqueStatusV1.INSUFFICIENT_EVIDENCE,
            completed_runs=0,
            required_runs=policy.minimum_completed_runs,
            reason="EVALUATION_BUDGET_EXCEEDED",
            budget_dimension=dimension,
        )

    completed = tuple(item for item in metrics if item.status == "completed")
    if len(completed) < policy.minimum_completed_runs:
        return _empty_decision(
            leak_decision=leak_decision,
            status=(
                CritiqueStatusV1.LEAK_FAILURE
                if leak_decision.failed_rule_ids
                else CritiqueStatusV1.INSUFFICIENT_EVIDENCE
            ),
            completed_runs=len(completed),
            required_runs=policy.minimum_completed_runs,
            reason="EVIDENCE_MISSING",
            budget_dimension="NONE",
        )

    for evidence in completed:
        if evidence.critique_metrics is None:
            return _empty_decision(
                leak_decision=leak_decision,
                status=(
                    CritiqueStatusV1.LEAK_FAILURE
                    if leak_decision.failed_rule_ids
                    else CritiqueStatusV1.INSUFFICIENT_EVIDENCE
                ),
                completed_runs=len(completed),
                required_runs=policy.minimum_completed_runs,
                reason="EVIDENCE_MISSING",
                budget_dimension="NONE",
            )

    failures: list[MetricFailureV1] = []
    required_by_name: dict[MetricName, MetricThresholdV1] = {
        item.name: item for item in policy.thresholds
    }
    risk_flags = tuple(sorted({flag for item in completed for flag in item.risk_flags}))
    for evidence in completed:
        assert evidence.critique_metrics is not None
        actual_by_name: dict[MetricName, Decimal] = {
            item.name: item.value for item in evidence.critique_metrics.metrics
        }
        for name, threshold in required_by_name.items():
            actual = actual_by_name.get(name)
            if actual is None:
                return _empty_decision(
                    leak_decision=leak_decision,
                    status=(
                        CritiqueStatusV1.LEAK_FAILURE
                        if leak_decision.failed_rule_ids
                        else CritiqueStatusV1.INSUFFICIENT_EVIDENCE
                    ),
                    completed_runs=len(completed),
                    required_runs=policy.minimum_completed_runs,
                    reason="EVIDENCE_MISSING",
                    budget_dimension="NONE",
                )
            passed = (
                actual >= threshold.threshold
                if threshold.comparison == "gte"
                else actual <= threshold.threshold
            )
            if not passed:
                failures.append(
                    MetricFailureV1(
                        run_id=evidence.run_id,
                        metric=name,
                        actual=actual,
                        comparison=threshold.comparison,
                        threshold=threshold.threshold,
                    )
                )

    leak_failures = leak_decision.failed_rule_ids
    status = (
        CritiqueStatusV1.LEAK_FAILURE
        if leak_failures
        else CritiqueStatusV1.RISK_FLAG_FAILURE
        if risk_flags
        else CritiqueStatusV1.METRIC_FAILURE
        if failures
        else CritiqueStatusV1.PASS
    )
    publication_exception = None
    if failures and not leak_failures and not risk_flags and reviewer_evidence is not None:
        reviewer = require_reviewer_evidence(reviewer_evidence)
        if (
            reviewer.experiment_id != experiment_id
            or reviewer.revision_hash != revision_hash
            or reviewer.author_id != author_id
            or reviewer.policy_digest != policy_digest
        ):
            raise CriticError("REVIEWER_EVIDENCE_MISMATCH") from None
        if reviewer.author_id == reviewer.reviewer_id:
            raise CriticError("REVIEWER_NOT_DISTINCT") from None
        failing_names = {failure.metric for failure in failures}
        if not failing_names.issubset(set(reviewer.metric_names)):
            raise CriticError("REVIEWER_SCOPE_MISMATCH") from None
        publication_exception = _make_exception(reviewer, tuple(failures), policy_digest)

    decision = CritiqueDecisionV1(
        experiment_id=experiment_id,
        revision_hash=revision_hash,
        snapshot_hash=leak_decision.snapshot_hash,
        leak_digest=hashlib.sha256(
            canonical_json(leak_decision.model_dump(mode="python"))
        ).hexdigest(),
        status=status,
        passed=status == CritiqueStatusV1.PASS,
        completed_runs=len(completed),
        required_runs=policy.minimum_completed_runs,
        metric_failures=tuple(failures),
        risk_flags=risk_flags,
        leak_failures=leak_failures,
        publication_exception=publication_exception,
        reason="RISK_FLAGS_PRESENT" if status == CritiqueStatusV1.RISK_FLAG_FAILURE else "NONE",
        budget_dimension="NONE",
    )
    if decision.publication_exception is not None:
        _EXCEPTION_ISSUER.issue(decision.publication_exception)
    return _CRITIQUE_ISSUER.issue(decision)


def require_critique_decision(value: CritiqueDecisionV1) -> CritiqueDecisionV1:
    try:
        if type(value) is not CritiqueDecisionV1:
            raise SealError("SEAL_NOT_ISSUED")
        return require(value, CRITIQUE_DECISION_TAG)
    except SealError:
        raise CriticError("CRITIQUE_RESULT_UNTRUSTED") from None


def require_publication_exception(value: PublicationExceptionV1) -> PublicationExceptionV1:
    try:
        if type(value) is not PublicationExceptionV1:
            raise SealError("SEAL_NOT_ISSUED")
        return require(value, "agent002.publication_exception.v1")
    except SealError:
        raise CriticError("PUBLICATION_EXCEPTION_UNTRUSTED") from None


__all__ = [
    "ReviewerEvidenceV1",
    "critique_policy_digest",
    "evaluate_critique",
    "issue_reviewer_evidence",
    "require_critique_decision",
    "require_publication_exception",
    "require_reviewer_evidence",
]
