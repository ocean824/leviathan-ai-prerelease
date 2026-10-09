"""Independent contract acceptance tests for the AGENT-002 leak and critic kernel."""

from __future__ import annotations

import copy
import pickle
from decimal import Decimal, localcontext

import pytest

from leviathan_core.agent_council.critic_policy import (
    ReviewerEvidenceClaimV1,
    ReviewerEvidenceV1,
    critique_policy_digest,
    evaluate_critique,
    issue_reviewer_evidence,
    require_critique_decision,
    require_publication_exception,
)
from leviathan_core.agent_council.leak_models import (
    CriticError,
    CritiqueDecisionV1,
    CritiqueMetricsV1,
    CritiquePolicyV1,
    FeatureAsOfV1,
    LabelWindowV1,
    LeakError,
    LeakEvidenceV1,
    MetricEvidenceV1,
    MetricThresholdV1,
    NamedMetricV1,
    SplitMembershipV1,
)
from leviathan_core.agent_council.leak_rules import (
    evaluate_leaks,
    require_leak_decision,
)
from leviathan_core.agent_council.state_models import TimeWindowV1
from leviathan_core.seal import SealError

EXPERIMENT = "experiment-acceptance-1"
SNAPSHOT_HASH = "a" * 64
REVISION_HASH = "b" * 64
ENGINE_VERSION = "engine-v1"
RESULT_PREFIX = "c"
RULE_CASES = (
    ("FORWARD_FEATURE_OFFSET", "FORWARD_OFFSET_DETECTED"),
    ("LABEL_LEAKAGE", "LABEL_LEAKAGE_DETECTED"),
    ("FUTURE_FIT_NORMALIZATION", "FUTURE_FIT_DETECTED"),
    ("SPLIT_CONTAMINATION", "SPLIT_CONTAMINATION_DETECTED"),
)
RULE_IDS = tuple(rule_id for rule_id, _ in RULE_CASES)


class ReviewerVerifier:
    def __init__(self, result: object = True) -> None:
        self.result = result

    def verify(self, claim: ReviewerEvidenceClaimV1) -> object:
        return self.result


def leak_evidence(**overrides: object) -> LeakEvidenceV1:
    values: dict[str, object] = {
        "experiment_id": EXPERIMENT,
        "snapshot_hash": SNAPSHOT_HASH,
        "revision_hash": REVISION_HASH,
        "train_window": TimeWindowV1(start_ns=100, end_ns=200),
        "test_window": TimeWindowV1(start_ns=200, end_ns=300),
        "holdout_window": TimeWindowV1(start_ns=300, end_ns=400),
        "features": (
            FeatureAsOfV1(
                signal_id="signal-close-v1",
                sample_at_ns=150,
                available_at_ns=150,
                offset_ns=0,
            ),
        ),
        "labels": (
            LabelWindowV1(
                sample_at_ns=190,
                label_start_ns=190,
                label_end_ns=200,
                split="train",
            ),
            LabelWindowV1(
                sample_at_ns=220,
                label_start_ns=220,
                label_end_ns=230,
                split="test",
            ),
            LabelWindowV1(
                sample_at_ns=320,
                label_start_ns=320,
                label_end_ns=330,
                split="holdout",
            ),
        ),
        "normalization_fit_window": TimeWindowV1(start_ns=110, end_ns=190),
        "split_memberships": (
            SplitMembershipV1(row_digest="1" * 64, split="train"),
            SplitMembershipV1(row_digest="2" * 64, split="test"),
            SplitMembershipV1(row_digest="3" * 64, split="holdout"),
        ),
        "engine_version": ENGINE_VERSION,
        "holdout_used_for_training": False,
    }
    values.update(overrides)
    return LeakEvidenceV1(**values)


def metric_evidence(
    run_id: str,
    value: Decimal,
    *,
    experiment_id: str = EXPERIMENT,
    author_id: str = "author-1",
    revision_hash: str = REVISION_HASH,
    status: str = "completed",
    risk_flags: tuple[str, ...] = (),
    cost_usd: Decimal = Decimal("0"),
    elapsed_ns: int = 0,
    compute_units: int = 0,
    result_digest: str | None = None,
    metric_values: tuple[NamedMetricV1, ...] | None = None,
) -> MetricEvidenceV1:
    return MetricEvidenceV1(
        experiment_id=experiment_id,
        run_id=run_id,
        author_id=author_id,
        revision_hash=revision_hash,
        result_digest=result_digest
        or RESULT_PREFIX + run_id.encode().hex().ljust(63, "0")[:63],
        status=status,
        critique_metrics=CritiqueMetricsV1(
            version="1",
            metrics=metric_values
            or (NamedMetricV1(name="sharpe_ratio", value=value),),
        ),
        risk_flags=risk_flags,
        cost_usd=cost_usd,
        elapsed_ns=elapsed_ns,
        compute_units=compute_units,
    )


def critique_policy(**overrides: object) -> CritiquePolicyV1:
    values: dict[str, object] = {
        "version": "policy-v1",
        "thresholds": (
            MetricThresholdV1(
                name="sharpe_ratio", comparison="gte", threshold=Decimal("1.00")
            ),
        ),
        "minimum_completed_runs": 2,
        "max_input_rows": 100,
        "max_runs": 10,
        "max_metrics": 5,
        "max_evaluation_cost_usd": Decimal("1"),
        "max_elapsed_ns": 1_000_000_000,
        "max_compute_units": 10_000,
    }
    values.update(overrides)
    return CritiquePolicyV1(**values)


def issue_reviewer(
    *,
    author_id: str = "author-1",
    reviewer_id: str = "reviewer-1",
    policy: CritiquePolicyV1 | None = None,
    metric_names: tuple[str, ...] = ("sharpe_ratio",),
) -> ReviewerEvidenceV1:
    bound_policy = policy or critique_policy()
    claim = ReviewerEvidenceClaimV1(
        experiment_id=EXPERIMENT,
        revision_hash=REVISION_HASH,
        author_id=author_id,
        reviewer_id=reviewer_id,
        metric_names=metric_names,
        policy_digest=critique_policy_digest(bound_policy),
        reason="Independent review permits this metric-only publication exception.",
    )
    return issue_reviewer_evidence(claim, ReviewerVerifier())


def test_valid_evidence_passes_all_four_rules_in_stable_order() -> None:
    first = evaluate_leaks(leak_evidence())
    second = evaluate_leaks(leak_evidence())

    assert first == second
    assert first.experiment_id == EXPERIMENT
    assert first.snapshot_hash == SNAPSHOT_HASH
    assert first.revision_hash == REVISION_HASH
    assert first.input_rows == 3
    assert first.passed is True
    assert first.failed_rule_ids == ()
    assert tuple(result.rule_id for result in first.results) == RULE_IDS
    assert all(result.passed and result.code == "PASS" for result in first.results)


def test_leak_evidence_requires_revision_hash_and_decision_binds_it() -> None:
    payload = leak_evidence().model_dump()
    payload.pop("revision_hash")
    with pytest.raises(LeakError) as missing_revision:
        LeakEvidenceV1.model_validate(payload)
    assert missing_revision.value.code == "LEAK_EVIDENCE_INVALID"

    decision = evaluate_leaks(leak_evidence(revision_hash="d" * 64))
    assert decision.revision_hash == "d" * 64


@pytest.mark.parametrize(
    ("evidence_changes", "expected_rule", "expected_code"),
    [
        (
            {
                "features": (
                    FeatureAsOfV1(
                        signal_id="signal-close-v1",
                        sample_at_ns=150,
                        available_at_ns=151,
                        offset_ns=0,
                    ),
                )
            },
            "FORWARD_FEATURE_OFFSET",
            "FORWARD_OFFSET_DETECTED",
        ),
        (
            {
                "labels": (
                    LabelWindowV1(
                        sample_at_ns=190,
                        label_start_ns=190,
                        label_end_ns=201,
                        split="train",
                    ),
                )
            },
            "LABEL_LEAKAGE",
            "LABEL_LEAKAGE_DETECTED",
        ),
        (
            {"normalization_fit_window": TimeWindowV1(start_ns=110, end_ns=201)},
            "FUTURE_FIT_NORMALIZATION",
            "FUTURE_FIT_DETECTED",
        ),
        (
            {
                "split_memberships": (
                    SplitMembershipV1(row_digest="1" * 64, split="train"),
                    SplitMembershipV1(row_digest="1" * 64, split="test"),
                )
            },
            "SPLIT_CONTAMINATION",
            "SPLIT_CONTAMINATION_DETECTED",
        ),
        (
            {"holdout_used_for_training": True},
            "SPLIT_CONTAMINATION",
            "HOLDOUT_TRAINING_DETECTED",
        ),
    ],
)
def test_each_leak_rule_fails_closed_and_keeps_its_stable_id(
    evidence_changes: dict[str, object], expected_rule: str, expected_code: str
) -> None:
    decision = evaluate_leaks(leak_evidence(**evidence_changes))

    assert decision.passed is False
    assert expected_rule in decision.failed_rule_ids
    result = next(item for item in decision.results if item.rule_id == expected_rule)
    assert result.passed is False
    assert result.code == expected_code


def test_missing_leak_evidence_never_defaults_to_pass() -> None:
    decision = evaluate_leaks(
        leak_evidence(
            train_window=None,
            features=(),
            labels=(),
            normalization_fit_window=None,
            split_memberships=(),
        )
    )

    assert decision.passed is False
    assert set(decision.failed_rule_ids) == set(RULE_IDS)
    assert all(not item.passed for item in decision.results)


def test_critique_input_row_count_must_match_sealed_leak_result() -> None:
    with pytest.raises(CriticError) as caught:
        evaluate_critique(
            critique_policy(),
            (),
            evaluate_leaks(leak_evidence()),
            input_rows=2,
        )

    assert caught.value.code == "CRITIQUE_EVIDENCE_MISMATCH"


def test_half_open_train_test_boundary_is_valid() -> None:
    decision = evaluate_leaks(
        leak_evidence(
            train_window=TimeWindowV1(start_ns=100, end_ns=200),
            test_window=TimeWindowV1(start_ns=200, end_ns=300),
            labels=(
                LabelWindowV1(
                    sample_at_ns=190,
                    label_start_ns=190,
                    label_end_ns=200,
                    split="train",
                ),
                LabelWindowV1(
                    sample_at_ns=220,
                    label_start_ns=220,
                    label_end_ns=230,
                    split="test",
                ),
                LabelWindowV1(
                    sample_at_ns=320,
                    label_start_ns=320,
                    label_end_ns=330,
                    split="holdout",
                ),
            ),
        )
    )

    assert decision.passed is True


def test_test_labels_must_end_at_or_before_holdout_start() -> None:
    valid = evaluate_leaks(
        leak_evidence(
            labels=(
                LabelWindowV1(
                    sample_at_ns=190,
                    label_start_ns=190,
                    label_end_ns=200,
                    split="train",
                ),
                LabelWindowV1(
                    sample_at_ns=220,
                    label_start_ns=220,
                    label_end_ns=300,
                    split="test",
                ),
                LabelWindowV1(
                    sample_at_ns=320,
                    label_start_ns=320,
                    label_end_ns=330,
                    split="holdout",
                ),
            )
        )
    )
    leaking = evaluate_leaks(
        leak_evidence(
            labels=(
                LabelWindowV1(
                    sample_at_ns=190,
                    label_start_ns=190,
                    label_end_ns=200,
                    split="train",
                ),
                LabelWindowV1(
                    sample_at_ns=220,
                    label_start_ns=220,
                    label_end_ns=301,
                    split="test",
                ),
                LabelWindowV1(
                    sample_at_ns=320,
                    label_start_ns=320,
                    label_end_ns=330,
                    split="holdout",
                ),
            )
        )
    )

    assert valid.passed is True
    assert leaking.passed is False
    assert leaking.results[1].code == "LABEL_LEAKAGE_DETECTED"


def test_duplicate_run_or_result_digest_precedes_quorum_and_budget() -> None:
    runs_by_duplicate = (
        (
            metric_evidence(
                "duplicate-run", Decimal("2"), status="failed", result_digest="d" * 64
            ),
            metric_evidence(
                "duplicate-run", Decimal("2"), status="failed", result_digest="e" * 64
            ),
        ),
        (
            metric_evidence(
                "run-one", Decimal("2"), status="failed", result_digest="f" * 64
            ),
            metric_evidence(
                "run-two", Decimal("2"), status="failed", result_digest="f" * 64
            ),
        ),
    )

    for runs in runs_by_duplicate:
        with pytest.raises(CriticError) as duplicate:
            evaluate_critique(
                critique_policy(max_runs=1, minimum_completed_runs=1),
                runs,
                evaluate_leaks(leak_evidence()),
                input_rows=3,
            )
        assert duplicate.value.code == "CRITIQUE_EVIDENCE_DUPLICATE_RUN"


def test_positive_offset_is_rejected_even_when_availability_is_not_future() -> None:
    decision = evaluate_leaks(
        leak_evidence(
            features=(
                FeatureAsOfV1(
                    signal_id="future-offset-signal",
                    sample_at_ns=150,
                    available_at_ns=150,
                    offset_ns=1,
                ),
            )
        )
    )

    assert decision.passed is False
    assert "FORWARD_FEATURE_OFFSET" in decision.failed_rule_ids
    assert decision.results[0].code == "FORWARD_OFFSET_DETECTED"


@pytest.mark.parametrize(
    ("sample_at_ns", "offset_ns"),
    ((150, -1), (220, -7), (320, 0)),
)
def test_historical_or_zero_offset_is_valid_inside_each_split(
    sample_at_ns: int, offset_ns: int
) -> None:
    decision = evaluate_leaks(
        leak_evidence(
            features=(
                FeatureAsOfV1(
                    signal_id="historical-feature",
                    sample_at_ns=sample_at_ns,
                    available_at_ns=sample_at_ns - 1,
                    offset_ns=offset_ns,
                ),
            )
        )
    )

    assert decision.passed is True
    assert decision.results[0].code == "PASS"


def test_feature_sample_outside_all_declared_splits_is_missing_evidence() -> None:
    decision = evaluate_leaks(
        leak_evidence(
            features=(
                FeatureAsOfV1(
                    signal_id="out-of-window-feature",
                    sample_at_ns=400,
                    available_at_ns=399,
                    offset_ns=-1,
                ),
            )
        )
    )

    assert decision.passed is False
    assert decision.results[0].code == "EVIDENCE_MISSING"
    assert "FORWARD_FEATURE_OFFSET" in decision.failed_rule_ids


def test_overlapping_train_test_windows_are_rejected_at_construction() -> None:
    with pytest.raises(LeakError) as caught:
        leak_evidence(
            train_window=TimeWindowV1(start_ns=100, end_ns=201),
            test_window=TimeWindowV1(start_ns=200, end_ns=300),
        )

    assert caught.value.code == "LEAK_EVIDENCE_INVALID"


def test_metric_threshold_equality_passes_and_every_completed_run_counts() -> None:
    decision = evaluate_critique(
        critique_policy(),
        (
            metric_evidence("run-1", Decimal("1.0")),
            metric_evidence("run-2", Decimal("1.00")),
        ),
        evaluate_leaks(leak_evidence()),
        input_rows=3,
    )

    assert decision.status == "PASS"
    assert decision.passed is True
    assert decision.completed_runs == 2
    assert decision.required_runs == 2
    assert decision.revision_hash == REVISION_HASH
    assert decision.snapshot_hash == SNAPSHOT_HASH
    assert len(decision.leak_digest) == 64
    assert all(char in "0123456789abcdef" for char in decision.leak_digest)
    assert decision.metric_failures == ()
    assert decision.leak_failures == ()
    assert decision.publication_exception is None
    assert decision.live_activation is False


def test_lte_threshold_uses_exact_decimal_boundary() -> None:
    policy = critique_policy(
        thresholds=(
            MetricThresholdV1(
                name="max_drawdown_pct", comparison="lte", threshold=Decimal("10.00")
            ),
        ),
        minimum_completed_runs=1,
    )
    run = metric_evidence(
        "run-drawdown",
        Decimal("1"),
        metric_values=(
            NamedMetricV1(name="max_drawdown_pct", value=Decimal("10.0")),
        ),
    )
    decision = evaluate_critique(
        policy,
        (run,),
        evaluate_leaks(leak_evidence()),
        input_rows=3,
    )

    assert decision.status == "PASS"
    assert decision.passed is True


def test_one_below_threshold_run_is_not_hidden_by_another_passing_run() -> None:
    decision = evaluate_critique(
        critique_policy(),
        (
            metric_evidence("run-pass", Decimal("2")),
            metric_evidence("run-fail", Decimal("0.99")),
        ),
        evaluate_leaks(leak_evidence()),
        input_rows=3,
    )

    assert decision.status == "METRIC_FAILURE"
    assert decision.passed is False
    assert [item.run_id for item in decision.metric_failures] == ["run-fail"]
    failure = decision.metric_failures[0]
    assert (failure.metric, failure.actual, failure.comparison, failure.threshold) == (
        "sharpe_ratio",
        Decimal("0.99"),
        "gte",
        Decimal("1.00"),
    )
    assert decision.publication_exception is None
    assert decision.live_activation is False


def test_distinct_trusted_reviewer_can_issue_metric_only_exception() -> None:
    reviewer = issue_reviewer()
    decision = evaluate_critique(
        critique_policy(),
        (
            metric_evidence("run-pass", Decimal("2")),
            metric_evidence("run-fail", Decimal("0.99")),
        ),
        evaluate_leaks(leak_evidence()),
        input_rows=3,
        reviewer_evidence=reviewer,
    )

    assert decision.status == "METRIC_FAILURE"
    assert decision.passed is False
    assert len(decision.metric_failures) == 1
    assert decision.publication_exception is not None
    assert reviewer.metric_names == ("sharpe_ratio",)
    assert reviewer.policy_digest == critique_policy_digest(critique_policy())
    assert require_publication_exception(decision.publication_exception) is (
        decision.publication_exception
    )
    assert decision.publication_exception.experiment_id == EXPERIMENT
    assert decision.publication_exception.revision_hash == REVISION_HASH
    assert decision.publication_exception.author_id == "author-1"
    assert decision.publication_exception.reviewer_id == "reviewer-1"
    assert decision.publication_exception.metric_names == ("sharpe_ratio",)
    assert decision.publication_exception.policy_digest == critique_policy_digest(
        critique_policy()
    )
    assert decision.live_activation is False


def test_reviewer_exception_is_limited_to_approved_metric_names() -> None:
    policy = critique_policy()
    reviewer = issue_reviewer(metric_names=("max_drawdown_pct",))
    with pytest.raises(CriticError) as scope_mismatch:
        evaluate_critique(
            policy,
            (
                metric_evidence("run-pass", Decimal("2")),
                metric_evidence("run-fail", Decimal("0.99")),
            ),
            evaluate_leaks(leak_evidence()),
            input_rows=3,
            reviewer_evidence=reviewer,
        )

    assert scope_mismatch.value.code == "REVIEWER_SCOPE_MISMATCH"


def test_reviewer_exception_is_bound_to_current_policy_digest() -> None:
    approved_policy = critique_policy()
    current_policy = critique_policy(version="policy-v2")
    reviewer = issue_reviewer(policy=approved_policy)
    runs = (
        metric_evidence("run-pass", Decimal("2")),
        metric_evidence("run-fail", Decimal("0.99")),
    )

    try:
        decision = evaluate_critique(
            current_policy,
            runs,
            evaluate_leaks(leak_evidence()),
            input_rows=3,
            reviewer_evidence=reviewer,
        )
    except CriticError as error:
        assert error.code in {
            "REVIEWER_EVIDENCE_MISMATCH",
            "CRITIQUE_EVIDENCE_MISMATCH",
        }
    else:
        assert decision.status == "METRIC_FAILURE"
        assert decision.passed is False
        assert decision.publication_exception is None
        assert decision.live_activation is False


def test_policy_digest_is_stable_and_binds_policy_content() -> None:
    policy = critique_policy()
    same_policy = critique_policy()
    changed_policy = critique_policy(version="policy-v2")
    digest = critique_policy_digest(policy)

    assert len(digest) == 64
    assert all(char in "0123456789abcdef" for char in digest)
    assert digest == critique_policy_digest(same_policy)
    assert digest != critique_policy_digest(changed_policy)


@pytest.mark.parametrize(
    "metric_names",
    [
        ("sharpe_ratio", "sharpe_ratio"),
        ("trade_count", "sharpe_ratio"),
        ("unknown_metric",),
    ],
)
def test_reviewer_claim_metric_scope_is_closed_sorted_and_unique(
    metric_names: tuple[str, ...],
) -> None:
    with pytest.raises(CriticError) as invalid_claim:
        ReviewerEvidenceClaimV1(
            experiment_id=EXPERIMENT,
            revision_hash=REVISION_HASH,
            author_id="author-1",
            reviewer_id="reviewer-1",
            metric_names=metric_names,
            policy_digest=critique_policy_digest(critique_policy()),
            reason="review reason",
        )
    assert invalid_claim.value.code == "CRITIC_EVIDENCE_INVALID"


@pytest.mark.parametrize(
    "metric_names",
    [
        ("sharpe_ratio", "sharpe_ratio"),
        ("trade_count", "sharpe_ratio"),
        ("unknown_metric",),
    ],
)
def test_reviewer_evidence_metric_scope_is_closed_sorted_and_unique(
    metric_names: tuple[str, ...],
) -> None:
    with pytest.raises(CriticError) as invalid_evidence:
        ReviewerEvidenceV1(
            experiment_id=EXPERIMENT,
            revision_hash=REVISION_HASH,
            author_id="author-1",
            reviewer_id="reviewer-1",
            metric_names=metric_names,
            policy_digest=critique_policy_digest(critique_policy()),
            reason="untrusted evidence fixture",
        )
    assert invalid_evidence.value.code == "CRITIC_EVIDENCE_INVALID"


@pytest.mark.parametrize("verifier_result", [False, "true", 1, None])
def test_reviewer_verifier_requires_literal_true(verifier_result: object) -> None:
    claim = ReviewerEvidenceClaimV1(
        experiment_id=EXPERIMENT,
        revision_hash=REVISION_HASH,
        author_id="author-1",
        reviewer_id="reviewer-1",
        metric_names=("sharpe_ratio",),
        policy_digest=critique_policy_digest(critique_policy()),
        reason="review reason",
    )

    with pytest.raises(CriticError) as caught:
        issue_reviewer_evidence(claim, ReviewerVerifier(verifier_result))

    assert caught.value.code == "VERIFIER_RESULT_INVALID"
    assert EXPERIMENT not in str(caught.value)


def test_reviewer_must_be_distinct_and_reason_must_be_nonempty() -> None:
    with pytest.raises(CriticError) as same_person:
        issue_reviewer(author_id="same-person", reviewer_id="same-person")
    assert same_person.value.code == "REVIEWER_NOT_DISTINCT"

    canary = "review-canary-7f3a"
    with pytest.raises(CriticError) as missing_reason:
        ReviewerEvidenceClaimV1(
            experiment_id=EXPERIMENT,
            revision_hash=REVISION_HASH,
            author_id="author-1",
            reviewer_id="reviewer-1",
            metric_names=("sharpe_ratio",),
            policy_digest=critique_policy_digest(critique_policy()),
            reason="   ",
        )
    assert canary not in str(missing_reason.value)
    assert canary not in repr(missing_reason.value.args)

    with pytest.raises(CriticError) as oversized_reason:
        ReviewerEvidenceClaimV1(
            experiment_id=EXPERIMENT,
            revision_hash=REVISION_HASH,
            author_id="author-1",
            reviewer_id="reviewer-1",
            metric_names=("sharpe_ratio",),
            policy_digest=critique_policy_digest(critique_policy()),
            reason=canary + ("x" * 1000),
        )
    assert canary not in str(oversized_reason.value)
    assert canary not in repr(oversized_reason.value.args)


def test_forged_reviewer_record_cannot_authorize_metric_exception() -> None:
    forged = ReviewerEvidenceV1(
        experiment_id=EXPERIMENT,
        revision_hash=REVISION_HASH,
        author_id="author-1",
        reviewer_id="reviewer-1",
        metric_names=("sharpe_ratio",),
        policy_digest=critique_policy_digest(critique_policy()),
        reason="forged approval",
    )

    with pytest.raises(CriticError) as caught:
        evaluate_critique(
            critique_policy(),
            (
                metric_evidence("run-pass", Decimal("2")),
                metric_evidence("run-fail", Decimal("0.99")),
            ),
            evaluate_leaks(leak_evidence()),
            input_rows=3,
            reviewer_evidence=forged,
        )

    assert caught.value.code == "REVIEWER_EVIDENCE_UNTRUSTED"
    assert "forged approval" not in str(caught.value)


def test_reviewer_evidence_must_bind_to_the_same_experiment_revision_and_author() -> None:
    mismatched_claim = ReviewerEvidenceClaimV1(
        experiment_id=EXPERIMENT,
        revision_hash="d" * 64,
        author_id="author-1",
        reviewer_id="reviewer-1",
        metric_names=("sharpe_ratio",),
        policy_digest=critique_policy_digest(critique_policy()),
        reason="The revision mismatch must not authorize publication.",
    )
    token = issue_reviewer_evidence(mismatched_claim, ReviewerVerifier())

    with pytest.raises(CriticError) as caught:
        evaluate_critique(
            critique_policy(),
            (
                metric_evidence("run-pass", Decimal("2")),
                metric_evidence("run-fail", Decimal("0.99")),
            ),
            evaluate_leaks(leak_evidence()),
            input_rows=3,
            reviewer_evidence=token,
        )

    assert caught.value.code == "REVIEWER_EVIDENCE_MISMATCH"
    assert "d" * 64 not in str(caught.value)


def test_metric_evidence_revision_must_match_the_leak_decision_revision() -> None:
    with pytest.raises(CriticError) as caught:
        evaluate_critique(
            critique_policy(),
            (
                metric_evidence("run-one", Decimal("2"), revision_hash="d" * 64),
                metric_evidence("run-two", Decimal("2"), revision_hash="d" * 64),
            ),
            evaluate_leaks(leak_evidence(revision_hash=REVISION_HASH)),
            input_rows=3,
        )

    assert caught.value.code == "CRITIQUE_EVIDENCE_MISMATCH"


def test_leak_failure_and_risk_flags_cannot_be_overridden() -> None:
    reviewer = issue_reviewer()
    leaking = evaluate_leaks(
        leak_evidence(
            features=(
                FeatureAsOfV1(
                    signal_id="future-signal",
                    sample_at_ns=150,
                    available_at_ns=151,
                    offset_ns=1,
                ),
            )
        )
    )
    runs = (
        metric_evidence("run-pass", Decimal("2")),
        metric_evidence("run-fail", Decimal("0.99")),
    )
    leak_decision = evaluate_critique(
        critique_policy(), runs, leaking, input_rows=3, reviewer_evidence=reviewer
    )
    risk_decision = evaluate_critique(
        critique_policy(),
        (
            metric_evidence("run-pass", Decimal("2"), risk_flags=("DRAWDOWN_CAP",)),
            metric_evidence("run-fail", Decimal("0.99")),
        ),
        evaluate_leaks(leak_evidence()),
        input_rows=3,
        reviewer_evidence=reviewer,
    )

    assert leak_decision.status == "LEAK_FAILURE"
    assert leak_decision.passed is False
    assert leak_decision.leak_failures
    assert leak_decision.publication_exception is None
    assert leak_decision.live_activation is False
    assert risk_decision.status == "RISK_FLAG_FAILURE"
    assert risk_decision.reason == "RISK_FLAGS_PRESENT"
    assert risk_decision.risk_flags == ("DRAWDOWN_CAP",)
    assert risk_decision.publication_exception is None
    assert risk_decision.live_activation is False


def test_policy_rejects_duplicate_thresholds_and_quorum_above_run_cap() -> None:
    duplicate = MetricThresholdV1(
        name="sharpe_ratio", comparison="gte", threshold=Decimal("1")
    )
    with pytest.raises(CriticError) as duplicate_error:
        critique_policy(thresholds=(duplicate, duplicate))
    assert duplicate_error.value.code == "CRITIC_EVIDENCE_INVALID"

    with pytest.raises(CriticError) as quorum_error:
        critique_policy(minimum_completed_runs=3, max_runs=2)
    assert quorum_error.value.code == "CRITIC_EVIDENCE_INVALID"


def test_partial_completed_run_quorum_is_insufficient_evidence() -> None:
    decision = evaluate_critique(
        critique_policy(minimum_completed_runs=3),
        (
            metric_evidence("run-1", Decimal("1.5")),
            metric_evidence("run-2", Decimal("1.5"), status="failed"),
        ),
        evaluate_leaks(leak_evidence()),
        input_rows=3,
    )

    assert decision.status == "INSUFFICIENT_EVIDENCE"
    assert decision.passed is False
    assert decision.completed_runs == 1
    assert decision.required_runs == 3
    assert decision.revision_hash == REVISION_HASH
    assert decision.snapshot_hash == SNAPSHOT_HASH
    assert len(decision.leak_digest) == 64
    assert decision.publication_exception is None
    assert decision.live_activation is False


def test_metric_runs_must_bind_to_the_same_experiment_revision_and_author() -> None:
    with pytest.raises(CriticError) as caught:
        evaluate_critique(
            critique_policy(),
            (
                metric_evidence("run-1", Decimal("2")),
                metric_evidence("run-2", Decimal("2"), revision_hash="d" * 64),
            ),
            evaluate_leaks(leak_evidence()),
            input_rows=3,
        )

    assert caught.value.code == "CRITIQUE_EVIDENCE_MISMATCH"
    assert "d" * 64 not in str(caught.value)


def test_leak_failure_remains_a_hard_gate_for_critique() -> None:
    leaking = evaluate_leaks(
        leak_evidence(
            features=(
                FeatureAsOfV1(
                    signal_id="future-signal",
                    sample_at_ns=150,
                    available_at_ns=151,
                    offset_ns=1,
                ),
            )
        )
    )
    decision = evaluate_critique(
        critique_policy(),
        (
            metric_evidence("run-1", Decimal("2")),
            metric_evidence("run-2", Decimal("2")),
        ),
        leaking,
        input_rows=3,
    )

    assert decision.status == "LEAK_FAILURE"
    assert decision.passed is False
    assert decision.leak_failures
    assert decision.publication_exception is None
    assert decision.live_activation is False


def test_risk_flags_are_retained_even_when_all_metrics_pass() -> None:
    decision = evaluate_critique(
        critique_policy(),
        (
            metric_evidence("run-1", Decimal("2"), risk_flags=("DRAWDOWN_CAP",)),
            metric_evidence("run-2", Decimal("2")),
        ),
        evaluate_leaks(leak_evidence()),
        input_rows=3,
    )

    assert "DRAWDOWN_CAP" in decision.risk_flags
    assert decision.status == "RISK_FLAG_FAILURE"
    assert decision.passed is False
    assert decision.publication_exception is None
    assert decision.live_activation is False


@pytest.mark.parametrize(
    ("policy_changes", "runs", "input_rows", "expected_dimension"),
    [
        ({"max_input_rows": 2}, (), 3, "INPUT_ROWS"),
        (
            {"max_runs": 1, "minimum_completed_runs": 1},
            (
                metric_evidence("run-1", Decimal("2")),
                metric_evidence("run-2", Decimal("2")),
            ),
            3,
            "RUNS",
        ),
        (
            {"max_metrics": 1},
            (
                metric_evidence(
                    "run-1",
                    Decimal("2"),
                    metric_values=(
                        NamedMetricV1(name="sharpe_ratio", value=Decimal("2")),
                        NamedMetricV1(name="trade_count", value=Decimal("20")),
                    ),
                ),
            ),
            3,
            "METRICS",
        ),
        (
            {"max_evaluation_cost_usd": Decimal("0.5")},
            (
                metric_evidence("run-1", Decimal("2"), cost_usd=Decimal("0.3")),
                metric_evidence("run-2", Decimal("2"), cost_usd=Decimal("0.3")),
            ),
            3,
            "COST",
        ),
        (
            {"max_elapsed_ns": 10},
            (
                metric_evidence("run-1", Decimal("2"), elapsed_ns=6),
                metric_evidence("run-2", Decimal("2"), elapsed_ns=6),
            ),
            3,
            "ELAPSED",
        ),
        (
            {"max_compute_units": 10},
            (
                metric_evidence("run-1", Decimal("2"), compute_units=6),
                metric_evidence("run-2", Decimal("2"), compute_units=6),
            ),
            3,
            "COMPUTE",
        ),
    ],
)
def test_every_aggregate_evaluation_budget_fails_closed(
    policy_changes: dict[str, object],
    runs: tuple[MetricEvidenceV1, ...],
    input_rows: int,
    expected_dimension: str,
) -> None:
    leak = evaluate_leaks(leak_evidence())
    decision = evaluate_critique(
        critique_policy(**policy_changes),
        runs,
        leak,
        input_rows=input_rows,
    )

    assert decision.status == "INSUFFICIENT_EVIDENCE"
    assert decision.passed is False
    assert decision.reason == "EVALUATION_BUDGET_EXCEEDED"
    assert decision.budget_dimension == expected_dimension
    assert decision.revision_hash == REVISION_HASH
    assert decision.snapshot_hash == SNAPSHOT_HASH
    assert len(decision.leak_digest) == 64
    assert decision.publication_exception is None
    assert decision.live_activation is False


def test_leak_failure_precedes_budget_status_but_preserves_budget_reason() -> None:
    leak = evaluate_leaks(
        leak_evidence(
            features=(
                FeatureAsOfV1(
                    signal_id="forward-feature",
                    sample_at_ns=150,
                    available_at_ns=151,
                    offset_ns=0,
                ),
            )
        )
    )
    decision = evaluate_critique(
        critique_policy(max_input_rows=2),
        (),
        leak,
        input_rows=3,
    )

    assert decision.status == "LEAK_FAILURE"
    assert decision.passed is False
    assert decision.reason == "EVALUATION_BUDGET_EXCEEDED"
    assert decision.budget_dimension == "INPUT_ROWS"
    assert decision.leak_failures
    assert decision.revision_hash == REVISION_HASH
    assert decision.snapshot_hash == SNAPSHOT_HASH
    assert len(decision.leak_digest) == 64
    assert decision.publication_exception is None
    assert decision.live_activation is False


def test_policy_caps_cannot_exceed_the_fixed_kernel_ceiling() -> None:
    with pytest.raises(CriticError) as caught:
        critique_policy(max_input_rows=100_001)

    assert caught.value.code == "CRITIQUE_POLICY_INVALID"
    assert "100001" not in str(caught.value)


def test_bool_is_not_an_integer_budget_or_timestamp() -> None:
    with pytest.raises(CriticError) as policy_error:
        critique_policy(max_runs=True)
    assert policy_error.value.code == "CRITIQUE_POLICY_INVALID"

    with pytest.raises(CriticError) as feature_error:
        FeatureAsOfV1(
            signal_id="signal-close-v1",
            sample_at_ns=True,
            available_at_ns=150,
            offset_ns=0,
        )
    assert feature_error.value.code == "LEAK_EVIDENCE_INVALID"

    with pytest.raises(CriticError) as evaluation_error:
        evaluate_critique(
            critique_policy(),
            (),
            evaluate_leaks(leak_evidence()),
            input_rows=True,
        )
    assert evaluation_error.value.code == "CRITIQUE_EVIDENCE_INVALID"


def test_decimal_normalization_and_budget_sum_ignore_ambient_context() -> None:
    normalized = NamedMetricV1(
        name="sharpe_ratio", value=Decimal("1." + ("0" * 40))
    )
    assert normalized.value == Decimal("1")

    with localcontext() as context:
        context.prec = 2
        context.Emax = 9
        decision = evaluate_critique(
            critique_policy(max_evaluation_cost_usd=Decimal("0.2")),
            (
                metric_evidence("run-1", Decimal("1"), cost_usd=Decimal("0.1")),
                metric_evidence("run-2", Decimal("1"), cost_usd=Decimal("0.1")),
            ),
            evaluate_leaks(leak_evidence()),
            input_rows=3,
        )

    assert decision.status == "PASS"
    assert decision.passed is True


def test_excess_decimal_precision_fails_with_a_sanitized_error() -> None:
    exact_value = Decimal("1." + "1234567890" * 4)
    with pytest.raises(CriticError) as caught:
        NamedMetricV1(name="sharpe_ratio", value=exact_value)

    assert caught.value.code == "CRITIC_EVIDENCE_INVALID"
    assert str(exact_value) not in str(caught.value)


def test_very_large_integer_metric_fails_without_echoing_the_value() -> None:
    huge = 10**5000
    with pytest.raises(CriticError) as caught:
        NamedMetricV1(name="trade_count", value=huge)

    assert caught.value.code == "CRITIC_EVIDENCE_INVALID"
    assert str(caught.value) == caught.value.code


def test_boundary_model_validation_errors_do_not_echo_unknown_field_values() -> None:
    canary = "validation-canary-19a7"
    payload = leak_evidence().model_dump()
    payload[canary] = canary

    with pytest.raises(LeakError) as caught:
        LeakEvidenceV1.model_validate(payload)

    assert caught.value.code == "LEAK_EVIDENCE_INVALID"
    assert canary not in str(caught.value)
    assert canary not in repr(caught.value.args)
    assert caught.value.__cause__ is None
    chained = caught.value.__context__
    assert chained is None or canary not in repr(chained)


def test_sealed_leak_and_critique_results_reject_copy_and_tampering() -> None:
    leak = evaluate_leaks(leak_evidence())
    critique = evaluate_critique(
        critique_policy(),
        (
            metric_evidence("run-1", Decimal("2")),
            metric_evidence("run-2", Decimal("2")),
        ),
        leak,
        input_rows=3,
    )
    assert require_leak_decision(leak) is leak
    assert require_critique_decision(critique) is critique

    for model_type, issued, require, error_type, expected_code in (
        (
            type(leak),
            leak,
            require_leak_decision,
            LeakError,
            "LEAK_RESULT_UNTRUSTED",
        ),
        (
            type(critique),
            critique,
            require_critique_decision,
            CriticError,
            "CRITIQUE_RESULT_UNTRUSTED",
        ),
    ):
        try:
            reconstructed = model_type.model_validate_json(issued.model_dump_json())
        except (LeakError, CriticError):
            continue
        with pytest.raises(error_type) as untrusted:
            require(reconstructed)
        assert untrusted.value.code == expected_code

    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises((SealError, TypeError)):
            operation(leak)
        with pytest.raises((SealError, TypeError)):
            operation(critique)

    with pytest.raises(LeakError) as model_copy_error:
        leak.model_copy(update={"passed": False})
    assert model_copy_error.value.code == "LEAK_RESULT_INVALID"
    with pytest.raises(CriticError) as model_construct_error:
        CritiqueDecisionV1.model_construct(status="PASS", passed=True)
    assert model_construct_error.value.code == "CRITIQUE_RESULT_INVALID"

    with pytest.raises(LeakError):
        del leak.passed

    object.__setattr__(leak.results[0], "code", "FORWARD_OFFSET_DETECTED")
    with pytest.raises(LeakError) as leak_seal_error:
        require_leak_decision(leak)
    assert leak_seal_error.value.code == "LEAK_RESULT_UNTRUSTED"

    object.__setattr__(critique, "passed", False)
    with pytest.raises(CriticError) as critique_seal_error:
        require_critique_decision(critique)
    assert critique_seal_error.value.code == "CRITIQUE_RESULT_UNTRUSTED"


def test_binary_float_is_not_accepted_as_metric_or_threshold() -> None:
    with pytest.raises(CriticError):
        NamedMetricV1(name="sharpe_ratio", value=1.0)

    with pytest.raises(CriticError):
        MetricThresholdV1(name="sharpe_ratio", comparison="gte", threshold=1.0)
