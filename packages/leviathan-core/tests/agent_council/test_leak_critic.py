from __future__ import annotations

from decimal import Decimal

import pytest

from leviathan_core.agent_council.critic_policy import (
    critique_policy_digest,
    evaluate_critique,
    issue_reviewer_evidence,
)
from leviathan_core.agent_council.leak_models import (
    CriticError,
    CritiqueMetricsV1,
    CritiquePolicyV1,
    FeatureAsOfV1,
    LabelWindowV1,
    LeakError,
    LeakEvidenceV1,
    MetricEvidenceV1,
    MetricThresholdV1,
    NamedMetricV1,
    ReviewerEvidenceClaimV1,
    SplitMembershipV1,
)
from leviathan_core.agent_council.leak_rules import evaluate_leaks, require_leak_decision
from leviathan_core.agent_council.state_models import TimeWindowV1

_HASH_A = "a" * 64
_HASH_B = "b" * 64
_HASH_C = "c" * 64


def _leak_evidence(**changes: object) -> LeakEvidenceV1:
    values: dict[str, object] = {
        "experiment_id": "exp-1",
        "revision_hash": _HASH_B,
        "snapshot_hash": _HASH_A,
        "train_window": TimeWindowV1(start_ns=10, end_ns=20),
        "test_window": TimeWindowV1(start_ns=20, end_ns=30),
        "holdout_window": TimeWindowV1(start_ns=30, end_ns=40),
        "features": (
            FeatureAsOfV1(signal_id="close", sample_at_ns=15, available_at_ns=15, offset_ns=0),
            FeatureAsOfV1(signal_id="close", sample_at_ns=25, available_at_ns=24, offset_ns=0),
            FeatureAsOfV1(signal_id="close", sample_at_ns=35, available_at_ns=34, offset_ns=0),
        ),
        "labels": (
            LabelWindowV1(sample_at_ns=15, label_start_ns=15, label_end_ns=20, split="train"),
            LabelWindowV1(sample_at_ns=25, label_start_ns=25, label_end_ns=30, split="test"),
            LabelWindowV1(sample_at_ns=35, label_start_ns=35, label_end_ns=40, split="holdout"),
        ),
        "normalization_fit_window": TimeWindowV1(start_ns=10, end_ns=20),
        "split_memberships": (
            SplitMembershipV1(row_digest=_HASH_A, split="train"),
            SplitMembershipV1(row_digest=_HASH_B, split="test"),
            SplitMembershipV1(row_digest=_HASH_C, split="holdout"),
        ),
        "engine_version": "engine-v1",
        "holdout_used_for_training": False,
    }
    values.update(changes)
    return LeakEvidenceV1(**values)  # type: ignore[arg-type]


def _policy(**changes: object) -> CritiquePolicyV1:
    values: dict[str, object] = {
        "version": "policy-v1",
        "thresholds": (
            MetricThresholdV1(name="sharpe_ratio", comparison="gte", threshold=Decimal("1.5")),
            MetricThresholdV1(name="max_drawdown_pct", comparison="lte", threshold=Decimal("15")),
        ),
        "minimum_completed_runs": 1,
        "max_input_rows": 100,
        "max_runs": 5,
        "max_metrics": 5,
        "max_evaluation_cost_usd": Decimal("10"),
        "max_elapsed_ns": 1000,
        "max_compute_units": 1000,
    }
    values.update(changes)
    return CritiquePolicyV1(**values)  # type: ignore[arg-type]


def _metric(**changes: object) -> MetricEvidenceV1:
    values: dict[str, object] = {
        "experiment_id": "exp-1",
        "run_id": "run-1",
        "author_id": "author-1",
        "revision_hash": _HASH_B,
        "result_digest": _HASH_C,
        "status": "completed",
        "critique_metrics": CritiqueMetricsV1(
            version="metrics-v1",
            metrics=(
                NamedMetricV1(name="sharpe_ratio", value=Decimal("2.0")),
                NamedMetricV1(name="max_drawdown_pct", value=Decimal("10")),
            ),
        ),
        "risk_flags": (),
        "cost_usd": Decimal("1"),
        "elapsed_ns": 10,
        "compute_units": 5,
    }
    values.update(changes)
    return MetricEvidenceV1(**values)  # type: ignore[arg-type]


def test_all_four_leak_rules_pass_and_result_is_issued() -> None:
    decision = evaluate_leaks(_leak_evidence())
    assert decision.passed is True
    assert len(decision.results) == 4
    assert require_leak_decision(decision) is decision


@pytest.mark.parametrize(
    ("field", "expected"),
    [
        ("features", "FORWARD_OFFSET_DETECTED"),
        ("labels", "LABEL_LEAKAGE_DETECTED"),
        ("normalization_fit_window", "FUTURE_FIT_DETECTED"),
        ("split_memberships", "SPLIT_CONTAMINATION_DETECTED"),
    ],
)
def test_each_leak_rule_fails_closed(field: str, expected: str) -> None:
    if field == "features":
        value: object = (
            FeatureAsOfV1(signal_id="close", sample_at_ns=15, available_at_ns=15, offset_ns=1),
        )
    elif field == "labels":
        value = (LabelWindowV1(sample_at_ns=15, label_start_ns=15, label_end_ns=21, split="train"),)
    elif field == "normalization_fit_window":
        value = TimeWindowV1(start_ns=19, end_ns=21)
    else:
        value = (
            SplitMembershipV1(row_digest=_HASH_A, split="train"),
            SplitMembershipV1(row_digest=_HASH_A, split="test"),
            SplitMembershipV1(row_digest=_HASH_C, split="holdout"),
        )
    decision = evaluate_leaks(_leak_evidence(**{field: value}))
    result = next(item for item in decision.results if item.code == expected)
    assert result.passed is False
    assert decision.passed is False


def test_holdout_training_and_missing_evidence_block() -> None:
    holdout = evaluate_leaks(_leak_evidence(holdout_used_for_training=True))
    assert "SPLIT_CONTAMINATION" in holdout.failed_rule_ids
    assert (
        next(item for item in holdout.results if item.rule_id == "SPLIT_CONTAMINATION").code
        == "HOLDOUT_TRAINING_DETECTED"
    )

    missing = evaluate_leaks(_leak_evidence(features=()))
    assert (
        next(item for item in missing.results if item.rule_id == "FORWARD_FEATURE_OFFSET").code
        == "EVIDENCE_MISSING"
    )


def test_test_labels_may_not_reach_holdout() -> None:
    decision = evaluate_leaks(
        _leak_evidence(
            labels=(
                LabelWindowV1(sample_at_ns=15, label_start_ns=15, label_end_ns=20, split="train"),
                LabelWindowV1(sample_at_ns=25, label_start_ns=25, label_end_ns=31, split="test"),
                LabelWindowV1(sample_at_ns=35, label_start_ns=35, label_end_ns=40, split="holdout"),
            )
        )
    )
    label_rule = next(item for item in decision.results if item.rule_id == "LABEL_LEAKAGE")
    assert label_rule.code == "LABEL_LEAKAGE_DETECTED"
    assert decision.passed is False


def test_critic_thresholds_quorum_and_budget_are_deterministic() -> None:
    leak = evaluate_leaks(_leak_evidence())
    result = evaluate_critique(_policy(), (_metric(),), leak, input_rows=3)
    assert result.passed is True
    assert result.status == "PASS"

    failed = evaluate_critique(
        _policy(),
        (
            _metric(
                critique_metrics=CritiqueMetricsV1(
                    version="metrics-v1",
                    metrics=(
                        NamedMetricV1(name="sharpe_ratio", value=Decimal("1")),
                        NamedMetricV1(name="max_drawdown_pct", value=Decimal("20")),
                    ),
                )
            ),
        ),
        leak,
        input_rows=3,
    )
    assert failed.status == "METRIC_FAILURE"
    assert {item.metric for item in failed.metric_failures} == {"sharpe_ratio", "max_drawdown_pct"}

    budget = evaluate_critique(_policy(max_elapsed_ns=5), (_metric(),), leak, input_rows=3)
    assert budget.status == "INSUFFICIENT_EVIDENCE"
    assert budget.reason == "EVALUATION_BUDGET_EXCEEDED"
    assert budget.budget_dimension == "ELAPSED"
    assert budget.revision_hash == _HASH_B
    assert budget.snapshot_hash == _HASH_A
    assert len(budget.leak_digest) == 64


@pytest.mark.parametrize(
    ("second_run_id", "second_result_digest"),
    [("run-1", "d" * 64), ("run-2", _HASH_C)],
)
def test_duplicate_run_or_result_cannot_satisfy_quorum(
    second_run_id: str, second_result_digest: str
) -> None:
    leak = evaluate_leaks(_leak_evidence())
    runs = (
        _metric(),
        _metric(run_id=second_run_id, result_digest=second_result_digest),
        _metric(run_id="run-3", result_digest="e" * 64),
    )
    with pytest.raises(CriticError, match="CRITIQUE_EVIDENCE_DUPLICATE_RUN"):
        evaluate_critique(
            _policy(minimum_completed_runs=3, max_runs=3),
            runs,
            leak,
            input_rows=3,
        )


def test_critique_rejects_metrics_for_another_revision() -> None:
    leak = evaluate_leaks(_leak_evidence())
    with pytest.raises(CriticError, match="CRITIQUE_EVIDENCE_MISMATCH"):
        evaluate_critique(
            _policy(),
            (_metric(revision_hash=_HASH_C),),
            leak,
            input_rows=3,
        )


def test_budget_overrun_preserves_leak_failure_and_linkage() -> None:
    leak = evaluate_leaks(
        _leak_evidence(
            features=(
                FeatureAsOfV1(
                    signal_id="close",
                    sample_at_ns=15,
                    available_at_ns=15,
                    offset_ns=1,
                ),
            )
        )
    )
    decision = evaluate_critique(
        _policy(max_elapsed_ns=5),
        (_metric(elapsed_ns=10),),
        leak,
        input_rows=3,
    )
    assert decision.status == "LEAK_FAILURE"
    assert decision.passed is False
    assert decision.leak_failures == leak.failed_rule_ids
    assert decision.reason == "EVALUATION_BUDGET_EXCEEDED"
    assert decision.budget_dimension == "ELAPSED"
    assert decision.revision_hash == leak.revision_hash
    assert decision.snapshot_hash == leak.snapshot_hash


class _Verifier:
    def verify(self, _claim: ReviewerEvidenceClaimV1) -> bool:
        return True


def test_distinct_reviewer_exception_preserves_failure_and_never_goes_live() -> None:
    claim = ReviewerEvidenceClaimV1(
        experiment_id="exp-1",
        revision_hash=_HASH_B,
        author_id="author-1",
        reviewer_id="reviewer-1",
        metric_names=("sharpe_ratio",),
        policy_digest=critique_policy_digest(_policy()),
        reason="Reviewed metric exception",
    )
    reviewer = issue_reviewer_evidence(claim, _Verifier())
    metric = _metric(
        critique_metrics=CritiqueMetricsV1(
            version="metrics-v1",
            metrics=(
                NamedMetricV1(name="sharpe_ratio", value=Decimal("1")),
                NamedMetricV1(name="max_drawdown_pct", value=Decimal("10")),
            ),
        )
    )
    result = evaluate_critique(
        _policy(),
        (metric,),
        evaluate_leaks(_leak_evidence()),
        input_rows=3,
        reviewer_evidence=reviewer,
    )
    assert result.passed is False
    assert result.status == "METRIC_FAILURE"
    assert result.publication_exception is not None
    assert result.live_activation is False

    assert result.publication_exception.metric_names == ("sharpe_ratio",)
    assert result.publication_exception.policy_digest == critique_policy_digest(_policy())

    drawdown_failure = _metric(
        critique_metrics=CritiqueMetricsV1(
            version="metrics-v1",
            metrics=(
                NamedMetricV1(name="sharpe_ratio", value=Decimal("2")),
                NamedMetricV1(name="max_drawdown_pct", value=Decimal("20")),
            ),
        )
    )
    with pytest.raises(CriticError, match="REVIEWER_SCOPE_MISMATCH"):
        evaluate_critique(
            _policy(),
            (drawdown_failure,),
            evaluate_leaks(_leak_evidence()),
            input_rows=3,
            reviewer_evidence=reviewer,
        )

    with pytest.raises(CriticError, match="REVIEWER_NOT_DISTINCT"):
        issue_reviewer_evidence(
            ReviewerEvidenceClaimV1(
                experiment_id="exp-1",
                revision_hash=_HASH_B,
                author_id="same",
                reviewer_id="same",
                metric_names=("sharpe_ratio",),
                policy_digest=critique_policy_digest(_policy()),
                reason="Not independent",
            ),
            _Verifier(),
        )


def test_public_models_reject_raw_invalid_input_without_echo() -> None:
    with pytest.raises(LeakError) as error:
        FeatureAsOfV1(signal_id="secret-canary", sample_at_ns=True, available_at_ns=1, offset_ns=0)
    assert "secret-canary" not in str(error.value)
    assert "secret-canary" not in repr(error.value.args)
