"""Deterministic, fail-closed checks for temporal and split leakage."""

from __future__ import annotations

from leviathan_core.seal import SealError, require

from .leak_models import (
    _LEAK_ISSUER,
    LEAK_DECISION_TAG,
    MAX_INPUT_ROWS,
    FeatureAsOfV1,
    LabelWindowV1,
    LeakDecisionV1,
    LeakError,
    LeakEvidenceV1,
    LeakRuleCode,
    LeakRuleId,
    LeakRuleResultV1,
    SplitMembershipV1,
)

_RULES: tuple[LeakRuleId, ...] = (
    "FORWARD_FEATURE_OFFSET",
    "LABEL_LEAKAGE",
    "FUTURE_FIT_NORMALIZATION",
    "SPLIT_CONTAMINATION",
)


def _inside(timestamp_ns: int, start_ns: int, end_ns: int) -> bool:
    return start_ns <= timestamp_ns < end_ns


def _forward_rule(evidence: LeakEvidenceV1) -> LeakRuleCode:
    if not evidence.features or evidence.train_window is None or evidence.holdout_window is None:
        return "EVIDENCE_MISSING"
    windows = (evidence.train_window, evidence.test_window, evidence.holdout_window)
    for feature in evidence.features:
        if type(feature) is not FeatureAsOfV1:
            return "EVIDENCE_MISSING"
        if feature.available_at_ns > feature.sample_at_ns or feature.offset_ns > 0:
            return "FORWARD_OFFSET_DETECTED"
        if not any(_inside(feature.sample_at_ns, w.start_ns, w.end_ns) for w in windows):
            return "EVIDENCE_MISSING"
    return "PASS"


def _label_rule(evidence: LeakEvidenceV1) -> LeakRuleCode:
    if not evidence.labels or evidence.train_window is None or evidence.holdout_window is None:
        return "EVIDENCE_MISSING"
    windows = {
        "train": evidence.train_window,
        "test": evidence.test_window,
        "holdout": evidence.holdout_window,
    }
    for label in evidence.labels:
        if type(label) is not LabelWindowV1:
            return "EVIDENCE_MISSING"
        window = windows[label.split]
        if not _inside(label.sample_at_ns, window.start_ns, window.end_ns):
            return "EVIDENCE_MISSING"
        # A train target may not reach the first test observation. All intervals
        # are half-open, so equality at the boundary is safe.
        if label.split == "train" and label.label_end_ns > evidence.test_window.start_ns:
            return "LABEL_LEAKAGE_DETECTED"
        # Test labels may not include observations from the holdout interval.
        if label.split == "test" and label.label_end_ns > evidence.holdout_window.start_ns:
            return "LABEL_LEAKAGE_DETECTED"
    return "PASS"


def _normalization_rule(evidence: LeakEvidenceV1) -> LeakRuleCode:
    fit = evidence.normalization_fit_window
    train = evidence.train_window
    if fit is None or train is None:
        return "EVIDENCE_MISSING"
    if fit.start_ns < train.start_ns or fit.end_ns > train.end_ns:
        return "FUTURE_FIT_DETECTED"
    return "PASS"


def _split_rule(evidence: LeakEvidenceV1) -> LeakRuleCode:
    if (
        evidence.train_window is None
        or evidence.holdout_window is None
        or not evidence.split_memberships
    ):
        return "EVIDENCE_MISSING"
    seen: dict[str, str] = {}
    counts: set[str] = set()
    for membership in evidence.split_memberships:
        if type(membership) is not SplitMembershipV1:
            return "EVIDENCE_MISSING"
        counts.add(membership.split)
        prior = seen.get(membership.row_digest)
        if prior is not None and prior != membership.split:
            return "SPLIT_CONTAMINATION_DETECTED"
        seen[membership.row_digest] = membership.split
    if counts != {"train", "test", "holdout"}:
        return "EVIDENCE_MISSING"
    if evidence.holdout_used_for_training:
        return "HOLDOUT_TRAINING_DETECTED"
    return "PASS"


def evaluate_leaks(evidence: LeakEvidenceV1) -> LeakDecisionV1:
    """Return one sealed result for the four mandatory leak rules."""
    if type(evidence) is not LeakEvidenceV1:
        raise LeakError("LEAK_EVIDENCE_INVALID") from None
    try:
        # Reject oversized or malformed containers before model_dump expands
        # their contents into a new object graph.
        for field in ("features", "labels", "split_memberships"):
            values = object.__getattribute__(evidence, field)
            if type(values) is not tuple or len(values) > MAX_INPUT_ROWS:
                raise LeakError("LEAK_EVIDENCE_INVALID")
        evidence = LeakEvidenceV1.model_validate(evidence.model_dump(mode="python"))
    except (LeakError, SealError, ValueError, AttributeError):
        raise LeakError("LEAK_EVIDENCE_INVALID") from None
    codes = (
        _forward_rule(evidence),
        _label_rule(evidence),
        _normalization_rule(evidence),
        _split_rule(evidence),
    )
    results = tuple(
        LeakRuleResultV1(rule_id=rule, passed=code == "PASS", code=code)
        for rule, code in zip(_RULES, codes, strict=True)
    )
    failed = tuple(item.rule_id for item in results if not item.passed)
    decision = LeakDecisionV1(
        experiment_id=evidence.experiment_id,
        revision_hash=evidence.revision_hash,
        snapshot_hash=evidence.snapshot_hash,
        input_rows=len(evidence.split_memberships),
        passed=not failed,
        results=results,
        failed_rule_ids=failed,
    )
    return _LEAK_ISSUER.issue(decision)


def require_leak_decision(value: LeakDecisionV1) -> LeakDecisionV1:
    """Require an intact kernel-issued leak decision."""
    try:
        if type(value) is not LeakDecisionV1:
            raise SealError("SEAL_NOT_ISSUED")
        return require(value, LEAK_DECISION_TAG)
    except SealError:
        raise LeakError("LEAK_RESULT_UNTRUSTED") from None


__all__ = ["evaluate_leaks", "require_leak_decision"]
