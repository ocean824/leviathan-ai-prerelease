"""TRUTH-001 bounded offline kernel checks."""

import copy
import pickle
import subprocess
import sys
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal, localcontext
from random import Random

import pytest

from leviathan_core.truth.verdict import (
    Action,
    ClockSkewError,
    EventMetricsV1,
    EvidenceStateError,
    InstrumentClass,
    InvalidTruthInputError,
    OptionsFlowMetricsV1,
    OrderBookMetricsV1,
    PolicyOutOfBoundsError,
    PrecisionExceededError,
    ReasonCode,
    SentimentMetricsV1,
    Side,
    SourceState,
    TruthEvidenceV1,
    TruthPolicyV1,
    TruthRequestV1,
    TruthSource,
    Verdict,
    evaluate_truth,
)

NOW = datetime(2026, 9, 30, 12, tzinfo=UTC)


def request(*, action: Action = Action.ENTER, side: Side = Side.BUY) -> TruthRequestV1:
    return TruthRequestV1(
        "trace-1",
        "ESZ6",
        "future",
        side,
        action,
        Decimal("2"),
        "strategy-1",
        "account-1",
        "XCME",
        NOW,
    )


def snapshot(
    *,
    book_age_ms: int = 0,
    embargo: bool = False,
    options_state: SourceState = SourceState.AVAILABLE,
) -> tuple[TruthEvidenceV1, ...]:
    return (
        TruthEvidenceV1(
            TruthSource.ORDER_BOOK,
            "book:1",
            SourceState.AVAILABLE,
            NOW - timedelta(milliseconds=book_age_ms),
            order_book=OrderBookMetricsV1(2, 10, 10, Decimal("0.6"), 2),
        ),
        TruthEvidenceV1(
            TruthSource.OPTIONS_FLOW,
            "options:1",
            options_state,
            NOW if options_state is SourceState.AVAILABLE else None,
            options_flow=OptionsFlowMetricsV1(1, 2)
            if options_state is SourceState.AVAILABLE
            else None,
        ),
        TruthEvidenceV1(
            TruthSource.EVENTS,
            "events:1",
            SourceState.AVAILABLE,
            NOW,
            events=EventMetricsV1(embargo),
        ),
        TruthEvidenceV1(
            TruthSource.SENTIMENT,
            "sentiment:1",
            SourceState.AVAILABLE,
            NOW,
            sentiment=SentimentMetricsV1(0, 1),
        ),
    )


def test_pass_is_deterministic_and_options_not_applicable_does_not_fail() -> None:
    policy = TruthPolicyV1(
        "policy-1",
        "v1",
        required_sources=frozenset(set(TruthSource) - {TruthSource.OPTIONS_FLOW}),
        instrument_classes={"ESZ6": InstrumentClass.FUTURE},
        applicable_sources_by_class={
            InstrumentClass.FUTURE: frozenset(set(TruthSource) - {TruthSource.OPTIONS_FLOW})
        },
    )
    evidence = snapshot(options_state=SourceState.NOT_APPLICABLE)
    first = evaluate_truth(request(), policy, evidence, evaluation_ts=NOW)
    second = evaluate_truth(request(), policy, tuple(reversed(evidence)), evaluation_ts=NOW)
    assert first.verdict is Verdict.PASS
    assert first.hash_id == second.hash_id
    assert first.reason_codes == ()
    assert first.source_timestamps[TruthSource.OPTIONS_FLOW] is None


def test_not_applicable_requires_policy_bound_instrument_context() -> None:
    base = snapshot()
    for source in TruthSource:
        rows = tuple(
            TruthEvidenceV1(source, "na-source", SourceState.NOT_APPLICABLE)
            if row.source is source
            else row
            for row in base
        )
        result = evaluate_truth(request(), TruthPolicyV1("p", "v1"), rows, evaluation_ts=NOW)
        assert result.verdict is Verdict.UNKNOWN
        assert result.reason_codes
    all_na = tuple(
        TruthEvidenceV1(source, "na-source", SourceState.NOT_APPLICABLE) for source in TruthSource
    )
    result = evaluate_truth(request(), TruthPolicyV1("p", "v1"), all_na, evaluation_ts=NOW)
    assert result.verdict is Verdict.UNKNOWN
    assert ReasonCode.NO_APPLICABLE_EVIDENCE in result.reason_codes


def test_required_source_not_satisfied_by_policy_authorized_not_applicable() -> None:
    policy = TruthPolicyV1(
        "p",
        "v1",
        instrument_classes={"ESZ6": InstrumentClass.FUTURE},
        applicable_sources_by_class={InstrumentClass.FUTURE: frozenset()},
    )
    rows = tuple(
        TruthEvidenceV1(row.source, "na-source", SourceState.NOT_APPLICABLE)
        if row.source is TruthSource.ORDER_BOOK
        else row
        for row in snapshot()
    )
    result = evaluate_truth(request(), policy, rows, evaluation_ts=NOW)
    assert result.verdict is Verdict.UNKNOWN
    assert ReasonCode.ORDERBOOK_MISSING in result.reason_codes


def test_policy_requires_a_nonempty_source_floor() -> None:
    with pytest.raises(PolicyOutOfBoundsError) as empty:
        TruthPolicyV1("p", "v1", required_sources=frozenset())
    assert empty.value.code == "POLICY_OUT_OF_BOUNDS"
    for floor in (0, -1, len(TruthSource) + 1):
        with pytest.raises(PolicyOutOfBoundsError):
            TruthPolicyV1("p", "v1", min_usable_sources=floor)
    with pytest.raises(InvalidTruthInputError):
        TruthPolicyV1("p", "v1", min_usable_sources=True)  # type: ignore[arg-type]


def test_raised_usable_floor_requires_multiple_passing_sources() -> None:
    policy = TruthPolicyV1(
        "p",
        "v1",
        required_sources=frozenset({TruthSource.ORDER_BOOK}),
        min_usable_sources=2,
    )
    rows = tuple(
        row
        if row.source is TruthSource.ORDER_BOOK
        else TruthEvidenceV1(row.source, "missing", SourceState.MISSING)
        for row in snapshot()
    )
    result = evaluate_truth(request(), policy, rows, evaluation_ts=NOW)
    assert result.verdict is Verdict.UNKNOWN
    assert result.reason_codes == (ReasonCode.INSUFFICIENT_USABLE_EVIDENCE,)
    with_options = tuple(
        row if row.source is not TruthSource.OPTIONS_FLOW else snapshot()[1] for row in rows
    )
    assert (
        evaluate_truth(request(), policy, with_options, evaluation_ts=NOW).verdict is Verdict.PASS
    )


def test_seeded_zero_usable_evidence_never_passes() -> None:
    rng = Random(20261001)
    policy = TruthPolicyV1("p", "v1")
    for _ in range(256):
        states = tuple(rng.choice(("missing", "not_applicable", "stale")) for _ in TruthSource)
        rows = tuple(
            replace(row, observed_at=NOW - timedelta(minutes=1))
            if state == "stale"
            else TruthEvidenceV1(
                row.source,
                "unusable",
                SourceState.MISSING if state == "missing" else SourceState.NOT_APPLICABLE,
            )
            for row, state in zip(snapshot(), states, strict=True)
        )
        result = evaluate_truth(request(), policy, rows, evaluation_ts=NOW)
        assert result.verdict is Verdict.UNKNOWN
        assert ReasonCode.NO_USABLE_EVIDENCE in result.reason_codes


def test_policy_applicability_is_deep_frozen_and_bound_to_instrument_class() -> None:
    classes = {"ESZ6": InstrumentClass.FUTURE}
    sources = {
        InstrumentClass.FUTURE: {TruthSource.ORDER_BOOK, TruthSource.EVENTS, TruthSource.SENTIMENT}
    }
    policy = TruthPolicyV1(
        "p",
        "v1",
        required_sources=frozenset(sources[InstrumentClass.FUTURE]),
        instrument_classes=classes,
        applicable_sources_by_class=sources,  # type: ignore[arg-type]
    )
    classes["ESZ6"] = InstrumentClass.EQUITY
    sources[InstrumentClass.FUTURE].add(TruthSource.OPTIONS_FLOW)
    rows = snapshot(options_state=SourceState.NOT_APPLICABLE)
    assert evaluate_truth(request(), policy, rows, evaluation_ts=NOW).verdict is Verdict.PASS
    mismatch = replace(request(), asset_class="equity")
    assert evaluate_truth(mismatch, policy, rows, evaluation_ts=NOW).verdict is Verdict.UNKNOWN
    with pytest.raises(FrozenInstanceError) as caught:
        policy.policy_id = "canary-secret"
    assert "canary-secret" not in str(caught.value)
    assert "canary-secret" not in repr(caught.value.args)


def test_missing_required_unknown_and_versioned_degrade_soft() -> None:
    evidence = snapshot(options_state=SourceState.MISSING)
    unknown = evaluate_truth(request(), TruthPolicyV1("p", "v1"), evidence, evaluation_ts=NOW)
    degraded = evaluate_truth(
        request(),
        TruthPolicyV1("p", "v2", allow_degrade=True),
        evidence,
        evaluation_ts=NOW,
    )
    assert unknown.verdict is Verdict.UNKNOWN
    assert unknown.reason_codes == (ReasonCode.OPTIONS_MISSING,)
    assert degraded.verdict is Verdict.SOFT_FAIL
    assert ReasonCode.DEGRADE_AUTHORIZED in degraded.reason_codes


def test_stale_book_degrades_but_hard_fail_has_precedence() -> None:
    policy = TruthPolicyV1("p", "v1", allow_degrade=True)
    stale = evaluate_truth(request(), policy, snapshot(book_age_ms=51), evaluation_ts=NOW)
    assert stale.verdict is Verdict.SOFT_FAIL
    assert ReasonCode.ORDERBOOK_STALE in stale.reason_codes
    hard = evaluate_truth(
        request(),
        TruthPolicyV1("p", "v1"),
        snapshot(book_age_ms=51, embargo=True),
        evaluation_ts=NOW,
    )
    assert hard.verdict is Verdict.HARD_FAIL
    assert hard.reason_codes == (ReasonCode.EVENT_EMBARGO, ReasonCode.ORDERBOOK_STALE)


def test_freshness_boundary_does_not_truncate_fractional_milliseconds() -> None:
    policy = TruthPolicyV1("p", "v1")
    fresh = evaluate_truth(request(), policy, snapshot(book_age_ms=50), evaluation_ts=NOW)
    book = replace(snapshot()[0], observed_at=NOW - timedelta(microseconds=50_001))
    stale = evaluate_truth(request(), policy, (book, *snapshot()[1:]), evaluation_ts=NOW)
    assert fresh.verdict is Verdict.PASS
    assert stale.verdict is Verdict.UNKNOWN
    assert stale.data_freshness_ms[TruthSource.ORDER_BOOK] == 51


def test_exit_override_is_policy_bound() -> None:
    evidence = snapshot(embargo=True)
    policy = TruthPolicyV1("p", "v2", exit_override=True)
    result = evaluate_truth(request(action=Action.EXIT), policy, evidence, evaluation_ts=NOW)
    assert result.verdict is Verdict.PASS
    assert result.reason_codes == (ReasonCode.EXIT_DURING_EMBARGO,)
    enter = evaluate_truth(request(), policy, evidence, evaluation_ts=NOW)
    assert enter.verdict is Verdict.HARD_FAIL


def test_skew_is_typed_error_and_not_a_verdict() -> None:
    late = replace(request(), client_timestamp=NOW - timedelta(milliseconds=1001))
    with pytest.raises(ClockSkewError):
        evaluate_truth(late, TruthPolicyV1("p", "v1"), snapshot(), evaluation_ts=NOW)


def test_snapshot_hash_covers_identity_and_canonical_decimal() -> None:
    policy = TruthPolicyV1("p", "v1")
    baseline = evaluate_truth(request(), policy, snapshot(), evaluation_ts=NOW)
    equivalent = evaluate_truth(
        replace(request(), quantity=Decimal("2.000")),
        policy,
        snapshot(),
        evaluation_ts=NOW,
    )
    changed = evaluate_truth(
        request(),
        policy,
        (replace(snapshot()[0], source_id="book:2"), *snapshot()[1:]),
        evaluation_ts=NOW,
    )
    assert baseline.hash_id == equivalent.hash_id
    assert baseline.hash_id != changed.hash_id


def test_frozen_copy_pickle_and_replace_validation() -> None:
    item = snapshot()[0]
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(InvalidTruthInputError):
            operation(item)
    with pytest.raises(InvalidTruthInputError):
        replace(item, order_book=None)
    verdict = evaluate_truth(request(), TruthPolicyV1("p", "v1"), snapshot(), evaluation_ts=NOW)
    with pytest.raises(TypeError):
        verdict.data_freshness_ms[TruthSource.ORDER_BOOK] = 100  # type: ignore[index]


def test_numeric_bounds_policy_bounds_and_typed_booleans() -> None:
    with pytest.raises(PrecisionExceededError):
        replace(request(), quantity=Decimal("1.1234567890123456789012345678901234"))
    with pytest.raises(PolicyOutOfBoundsError):
        TruthPolicyV1("p", "v1", orderbook_max_age_ms=51)
    with pytest.raises(InvalidTruthInputError):
        TruthPolicyV1("p", "v1", max_clock_skew_ms=True)  # type: ignore[arg-type]
    with pytest.raises(InvalidTruthInputError):
        EventMetricsV1("false")  # type: ignore[arg-type]
    with pytest.raises(InvalidTruthInputError):
        OrderBookMetricsV1(1, 1, 1, 0, 1, luld_active="false")  # type: ignore[arg-type]
    with pytest.raises(PrecisionExceededError) as compact_error:
        replace(request(), quantity=Decimal("1E+100000"))
    assert compact_error.value.code == "PRECISION_EXCEEDED"
    assert "100000" not in str(compact_error.value)
    assert "100000" not in repr(compact_error.value.args)
    with pytest.raises(InvalidTruthInputError) as policy_error:
        replace(TruthPolicyV1("p", "v1"), required_sources=None)  # type: ignore[arg-type]
    assert policy_error.value.code == "INVALID_TRUTH_INPUT"
    with pytest.raises(PolicyOutOfBoundsError):
        replace(TruthPolicyV1("p", "v1"), max_spread_bps=Decimal("-1"))


def test_missing_or_not_applicable_never_carries_freshness() -> None:
    for state in (SourceState.MISSING, SourceState.NOT_APPLICABLE):
        with pytest.raises(EvidenceStateError) as caught:
            TruthEvidenceV1(TruthSource.OPTIONS_FLOW, "source-id", state, NOW)
        assert caught.value.code == "EVIDENCE_STATE_INCONSISTENT"
        assert "source-id" not in str(caught.value)
        assert "source-id" not in repr(caught.value.args)


def test_ambient_decimal_context_does_not_change_hash_or_verdict() -> None:
    policy = TruthPolicyV1("p", "v1")
    baseline = evaluate_truth(request(), policy, snapshot(), evaluation_ts=NOW)
    with localcontext() as context:
        context.prec = 2
        context.Emax = 2
        context.Emin = -2
        repeated = evaluate_truth(request(), policy, snapshot(), evaluation_ts=NOW)
    assert repeated == baseline
    assert repeated.hash_id == baseline.hash_id


def test_import_and_evaluation_do_not_load_downstream_authorities() -> None:
    script = """
import sys
from datetime import datetime, timezone
from leviathan_core.truth.verdict import TruthPolicyV1, Verdict
assert Verdict.PASS.value == 'PASS'
assert TruthPolicyV1('p', 'v1').policy_id == 'p'
assert not any(name.startswith('leviathan_core.risk') for name in sys.modules)
assert not any(name.startswith('leviathan_core.execution') for name in sys.modules)
assert not any('route_guard' in name for name in sys.modules)
"""
    result = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr
