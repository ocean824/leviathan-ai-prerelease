from __future__ import annotations

import ast
import copy
import dataclasses
import inspect
import pickle
import random
from datetime import UTC, datetime, timedelta
from decimal import Decimal, Inexact, localcontext
from pathlib import Path

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
    TruthVerdictV1,
    Verdict,
    evaluate_truth,
)

UTC = UTC
NOW = datetime(2026, 1, 5, 15, 0, tzinfo=UTC)
_AUTO_TIMESTAMP = object()


def request(
    *,
    action: Action = Action.ENTER,
    timestamp: datetime = NOW,
    quantity: Decimal = Decimal("1"),
    side: Side = Side.BUY,
) -> TruthRequestV1:
    return TruthRequestV1(
        request_id="req-1",
        instrument_id="XYZ",
        asset_class="equity",
        side=side,
        action=action,
        quantity=quantity,
        strategy_id="strategy-1",
        account_id="account-1",
        venue="NYSE",
        client_timestamp=timestamp,
    )


def policy(**overrides: object) -> TruthPolicyV1:
    values: dict[str, object] = {"policy_id": "policy-1", "version": "v1"}
    values.update(overrides)
    return TruthPolicyV1(**values)  # type: ignore[arg-type]


def book(
    *,
    spread: Decimal = Decimal("5"),
    depth: Decimal = Decimal("10"),
    imbalance: Decimal = Decimal("1"),
    slippage: Decimal = Decimal("2"),
    crossed: bool = False,
    locked: bool = False,
    halt: bool = False,
    luld: bool = False,
) -> OrderBookMetricsV1:
    return OrderBookMetricsV1(
        spread_bps=spread,
        depth_near_qty=depth,
        depth_far_qty=depth,
        imbalance=imbalance,
        est_slippage_bps=slippage,
        crossed=crossed,
        locked=locked,
        halt_active=halt,
        luld_active=luld,
    )


def evidence(
    source: TruthSource,
    *,
    observed_at: datetime | None | object = _AUTO_TIMESTAMP,
    state: SourceState = SourceState.AVAILABLE,
    order_book: OrderBookMetricsV1 | None = None,
    options_flow: OptionsFlowMetricsV1 | None = None,
    events: EventMetricsV1 | None = None,
    sentiment: SentimentMetricsV1 | None = None,
) -> TruthEvidenceV1:
    if observed_at is _AUTO_TIMESTAMP:
        observed_at = NOW if state is SourceState.AVAILABLE else None
    return TruthEvidenceV1(
        source=source,
        source_id=f"{source.value.lower()}-snapshot-1",
        state=state,
        observed_at=observed_at,  # type: ignore[arg-type]
        order_book=order_book,
        options_flow=options_flow,
        events=events,
        sentiment=sentiment,
    )


def complete_evidence(
    *,
    spread: Decimal = Decimal("5"),
    flow_score: Decimal = Decimal("1"),
    sentiment_score: Decimal = Decimal("0"),
    embargo: bool = False,
    order_book_at: datetime | None = NOW,
) -> tuple[TruthEvidenceV1, ...]:
    return (
        evidence(
            TruthSource.ORDER_BOOK,
            observed_at=order_book_at,
            order_book=book(spread=spread),
        ),
        evidence(
            TruthSource.OPTIONS_FLOW,
            options_flow=OptionsFlowMetricsV1(
                flow_score=flow_score,
                unusual_volume_ratio=Decimal("2"),
                directional=True,
            ),
        ),
        evidence(
            TruthSource.EVENTS,
            events=EventMetricsV1(embargo_active=embargo),
        ),
        evidence(
            TruthSource.SENTIMENT,
            sentiment=SentimentMetricsV1(
                score=sentiment_score,
                confidence=Decimal("1"),
            ),
        ),
    )


def zero_usable_evidence(source: TruthSource, state: str) -> TruthEvidenceV1:
    if state == "missing":
        return evidence(source, state=SourceState.MISSING)
    if state == "not_applicable":
        return evidence(source, state=SourceState.NOT_APPLICABLE)

    stale_at = NOW - timedelta(days=2)
    payloads = {
        TruthSource.ORDER_BOOK: {"order_book": book()},
        TruthSource.OPTIONS_FLOW: {
            "options_flow": OptionsFlowMetricsV1(Decimal("1"), Decimal("2"))
        },
        TruthSource.EVENTS: {"events": EventMetricsV1()},
        TruthSource.SENTIMENT: {"sentiment": SentimentMetricsV1(Decimal("0"), Decimal("1"))},
    }
    return evidence(source, observed_at=stale_at, **payloads[source])


def passing_payload(source: TruthSource) -> TruthEvidenceV1:
    payloads = {
        TruthSource.ORDER_BOOK: {"order_book": book()},
        TruthSource.OPTIONS_FLOW: {
            "options_flow": OptionsFlowMetricsV1(Decimal("1"), Decimal("2"))
        },
        TruthSource.EVENTS: {"events": EventMetricsV1()},
        TruthSource.SENTIMENT: {"sentiment": SentimentMetricsV1(Decimal("0"), Decimal("1"))},
    }
    return evidence(source, **payloads[source])


def evaluate(
    *,
    req: TruthRequestV1 | None = None,
    pol: TruthPolicyV1 | None = None,
    rows: tuple[TruthEvidenceV1, ...] | None = None,
    missing_policy_verdict: Verdict = Verdict.SOFT_FAIL,
):
    return evaluate_truth(
        request() if req is None else req,
        policy() if pol is None else pol,
        complete_evidence() if rows is None else rows,
        evaluation_ts=NOW,
        missing_policy_verdict=missing_policy_verdict,
    )


def _reason_values(result: object) -> tuple[str, ...]:
    return tuple(code.value for code in result.reason_codes)  # type: ignore[attr-defined]


def test_verdict_precedence_is_hard_fail_then_unknown_then_soft_fail_then_pass() -> None:
    hard_and_unknown_and_soft = evaluate(
        rows=(
            evidence(TruthSource.ORDER_BOOK, order_book=book(spread=Decimal("11"))),
            evidence(
                TruthSource.OPTIONS_FLOW,
                options_flow=OptionsFlowMetricsV1(
                    flow_score=Decimal("-1"),
                    unusual_volume_ratio=Decimal("0"),
                    directional=True,
                ),
            ),
            evidence(TruthSource.EVENTS, state=SourceState.MISSING, events=None),
            evidence(
                TruthSource.SENTIMENT,
                sentiment=SentimentMetricsV1(score=Decimal("2"), confidence=Decimal("1")),
            ),
        )
    )
    unknown_and_soft = evaluate(
        pol=policy(required_sources=frozenset({TruthSource.OPTIONS_FLOW})),
        rows=(
            evidence(TruthSource.ORDER_BOOK, order_book=book()),
            evidence(TruthSource.OPTIONS_FLOW, state=SourceState.MISSING),
            evidence(TruthSource.EVENTS, events=EventMetricsV1()),
            evidence(
                TruthSource.SENTIMENT,
                sentiment=SentimentMetricsV1(Decimal("2"), Decimal("1")),
            ),
        ),
    )
    soft_only = evaluate(rows=complete_evidence(flow_score=Decimal("-1")))
    passed = evaluate()

    assert hard_and_unknown_and_soft.verdict is Verdict.HARD_FAIL
    assert unknown_and_soft.verdict is Verdict.UNKNOWN
    assert soft_only.verdict is Verdict.SOFT_FAIL
    assert passed.verdict is Verdict.PASS


def test_not_applicable_is_not_failure() -> None:
    rows = (
        evidence(TruthSource.ORDER_BOOK, order_book=book()),
        evidence(TruthSource.OPTIONS_FLOW, state=SourceState.NOT_APPLICABLE),
        evidence(TruthSource.EVENTS, events=EventMetricsV1()),
        evidence(TruthSource.SENTIMENT, sentiment=SentimentMetricsV1(Decimal("0"), Decimal("1"))),
    )
    result = evaluate(
        pol=policy(
            required_sources=frozenset(set(TruthSource) - {TruthSource.OPTIONS_FLOW}),
            instrument_classes={"XYZ": InstrumentClass.EQUITY},
            applicable_sources_by_class={
                InstrumentClass.EQUITY: frozenset(set(TruthSource) - {TruthSource.OPTIONS_FLOW})
            },
        ),
        rows=rows,
    )

    assert result.verdict is Verdict.PASS
    assert result.reason_codes == ()


@pytest.mark.parametrize(
    ("source", "missing_reason"),
    (
        (TruthSource.ORDER_BOOK, ReasonCode.ORDERBOOK_MISSING),
        (TruthSource.OPTIONS_FLOW, ReasonCode.OPTIONS_MISSING),
        (TruthSource.EVENTS, ReasonCode.EVENTS_MISSING),
        (TruthSource.SENTIMENT, ReasonCode.SENTIMENT_MISSING),
    ),
)
def test_unauthorized_not_applicable_source_is_unknown(
    source: TruthSource, missing_reason: ReasonCode
) -> None:
    rows = tuple(
        evidence(item, state=SourceState.NOT_APPLICABLE)
        if item is source
        else next(row for row in complete_evidence() if row.source is item)
        for item in TruthSource
    )

    result = evaluate(rows=rows)

    assert result.verdict is Verdict.UNKNOWN
    assert missing_reason in result.reason_codes


def test_all_sources_not_applicable_under_default_policy_is_unknown() -> None:
    rows = tuple(evidence(source, state=SourceState.NOT_APPLICABLE) for source in TruthSource)

    result = evaluate(rows=rows)

    assert result.verdict is Verdict.UNKNOWN
    assert {
        ReasonCode.ORDERBOOK_MISSING,
        ReasonCode.OPTIONS_MISSING,
        ReasonCode.EVENTS_MISSING,
        ReasonCode.SENTIMENT_MISSING,
    } <= set(result.reason_codes)


@pytest.mark.parametrize(
    "policy_overrides",
    (
        {
            "instrument_classes": {"OTHER": InstrumentClass.EQUITY},
            "applicable_sources_by_class": {
                InstrumentClass.EQUITY: frozenset(set(TruthSource) - {TruthSource.OPTIONS_FLOW})
            },
            "required_sources": frozenset(set(TruthSource) - {TruthSource.OPTIONS_FLOW}),
        },
        {
            "instrument_classes": {"XYZ": InstrumentClass.EQUITY},
            "applicable_sources_by_class": {
                InstrumentClass.EQUITY: frozenset(TruthSource),
            },
            "required_sources": frozenset(set(TruthSource) - {TruthSource.OPTIONS_FLOW}),
        },
        {
            "instrument_classes": {"XYZ": InstrumentClass.EQUITY},
            "applicable_sources_by_class": {
                InstrumentClass.EQUITY: frozenset(set(TruthSource) - {TruthSource.OPTIONS_FLOW})
            },
            "required_sources": frozenset(TruthSource),
        },
    ),
)
def test_not_applicable_is_rejected_without_complete_policy_match(
    policy_overrides: dict[str, object],
) -> None:
    rows = tuple(
        evidence(source, state=SourceState.NOT_APPLICABLE)
        if source is TruthSource.OPTIONS_FLOW
        else next(row for row in complete_evidence() if row.source is source)
        for source in TruthSource
    )

    result = evaluate(pol=policy(**policy_overrides), rows=rows)

    assert result.verdict is Verdict.UNKNOWN
    assert ReasonCode.OPTIONS_MISSING in result.reason_codes


def test_missing_required_source_is_unknown_or_authorized_soft_degrade() -> None:
    rows = tuple(row for row in complete_evidence() if row.source is not TruthSource.OPTIONS_FLOW)
    required = policy(required_sources=frozenset({TruthSource.OPTIONS_FLOW}))
    unknown = evaluate(pol=required, rows=rows)
    degraded = evaluate(
        pol=policy(
            required_sources=frozenset({TruthSource.OPTIONS_FLOW}),
            allow_degrade=True,
        ),
        rows=rows,
    )

    assert unknown.verdict is Verdict.UNKNOWN
    assert degraded.verdict is Verdict.SOFT_FAIL
    assert ReasonCode.DEGRADE_AUTHORIZED in degraded.reason_codes


def test_empty_required_sources_policy_is_rejected_at_construction() -> None:
    with pytest.raises(PolicyOutOfBoundsError):
        policy(required_sources=frozenset())


def test_all_four_missing_sources_are_unknown_with_no_usable_evidence() -> None:
    rows = tuple(evidence(source, state=SourceState.MISSING) for source in TruthSource)

    result = evaluate(rows=rows)

    assert result.verdict is Verdict.UNKNOWN
    assert "NO_USABLE_EVIDENCE" in _reason_values(result)
    assert {
        ReasonCode.ORDERBOOK_MISSING,
        ReasonCode.OPTIONS_MISSING,
        ReasonCode.EVENTS_MISSING,
        ReasonCode.SENTIMENT_MISSING,
    } <= set(result.reason_codes)


def test_empty_evidence_is_unknown_with_no_usable_evidence() -> None:
    result = evaluate(rows=())

    assert result.verdict is Verdict.UNKNOWN
    assert "NO_USABLE_EVIDENCE" in _reason_values(result)


def test_min_usable_sources_has_positive_integer_bound_and_caller_can_raise_it() -> None:
    with pytest.raises(PolicyOutOfBoundsError) as zero_floor:
        policy(min_usable_sources=0)
    assert zero_floor.value.code == "POLICY_OUT_OF_BOUNDS"
    with pytest.raises(PolicyOutOfBoundsError) as excessive_floor:
        policy(min_usable_sources=5)
    assert excessive_floor.value.code == "POLICY_OUT_OF_BOUNDS"
    with pytest.raises(InvalidTruthInputError):
        policy(min_usable_sources=True)

    raised = policy(min_usable_sources=2)

    assert raised.min_usable_sources == 2


def test_pass_requires_configured_count_of_fresh_passing_sources() -> None:
    pol = policy(
        required_sources=frozenset({TruthSource.ORDER_BOOK}),
        min_usable_sources=2,
    )
    one_fresh = (
        passing_payload(TruthSource.ORDER_BOOK),
        zero_usable_evidence(TruthSource.OPTIONS_FLOW, "stale"),
        zero_usable_evidence(TruthSource.EVENTS, "stale"),
        zero_usable_evidence(TruthSource.SENTIMENT, "stale"),
    )
    two_fresh = (
        passing_payload(TruthSource.ORDER_BOOK),
        passing_payload(TruthSource.OPTIONS_FLOW),
        zero_usable_evidence(TruthSource.EVENTS, "stale"),
        zero_usable_evidence(TruthSource.SENTIMENT, "stale"),
    )

    below_threshold = evaluate(pol=pol, rows=one_fresh)
    at_threshold = evaluate(pol=pol, rows=two_fresh)

    assert below_threshold.verdict is Verdict.UNKNOWN
    assert "INSUFFICIENT_USABLE_EVIDENCE" in _reason_values(below_threshold)
    assert at_threshold.verdict is Verdict.PASS


def test_seeded_zero_usable_source_states_never_pass() -> None:
    rng = random.Random(731_004)
    unavailable_states = ("missing", "not_applicable", "stale")

    for _ in range(256):
        rows = tuple(
            zero_usable_evidence(source, rng.choice(unavailable_states)) for source in TruthSource
        )

        result = evaluate(rows=rows)

        assert result.verdict is Verdict.UNKNOWN
        assert "NO_USABLE_EVIDENCE" in _reason_values(result)


def test_missing_evidence_rejects_timestamp_with_content_free_typed_error() -> None:
    with pytest.raises(EvidenceStateError) as error:
        evidence(
            TruthSource.OPTIONS_FLOW,
            state=SourceState.MISSING,
            observed_at=NOW,
        )

    assert error.value.code == "EVIDENCE_STATE_INCONSISTENT"
    assert NOW.isoformat() not in str(error.value)
    assert NOW.isoformat() not in repr(error.value.args)


def test_skew_boundary_is_inclusive_and_excess_is_a_typed_error() -> None:
    allowed = evaluate(
        req=request(timestamp=NOW - timedelta(milliseconds=1000)),
        pol=policy(max_clock_skew_ms=1000),
    )

    assert allowed.verdict is Verdict.PASS
    with pytest.raises(ClockSkewError):
        evaluate(
            req=request(timestamp=NOW - timedelta(milliseconds=1001)),
            pol=policy(max_clock_skew_ms=1000),
        )


def test_allowlisted_reason_codes_are_sorted_by_enum_value() -> None:
    result = evaluate(
        rows=(
            evidence(
                TruthSource.ORDER_BOOK,
                order_book=book(spread=Decimal("11"), halt=True, luld=True),
            ),
            evidence(
                TruthSource.OPTIONS_FLOW,
                options_flow=OptionsFlowMetricsV1(
                    flow_score=Decimal("-1"),
                    unusual_volume_ratio=Decimal("0"),
                    directional=True,
                ),
            ),
            evidence(TruthSource.EVENTS, events=EventMetricsV1()),
            evidence(
                TruthSource.SENTIMENT,
                sentiment=SentimentMetricsV1(Decimal("0"), Decimal("1")),
            ),
        )
    )
    values = _reason_values(result)
    allowed = {member.value for member in ReasonCode}

    assert set(values) <= allowed
    assert values == tuple(sorted(values))


def test_identical_snapshot_hashes_match_and_semantic_input_changes_hash() -> None:
    first = evaluate()
    repeated = evaluate()
    equivalent_decimal = evaluate(req=request(quantity=Decimal("1.00")))
    changed = evaluate(req=request(quantity=Decimal("2")))

    assert first.hash_id == repeated.hash_id == equivalent_decimal.hash_id
    assert first.hash_id != changed.hash_id


def test_enter_embargo_hard_fails_and_exit_override_is_explicit_and_versioned() -> None:
    enter = evaluate(rows=complete_evidence(embargo=True))
    exit_without_override = evaluate(
        req=request(action=Action.EXIT),
        pol=policy(exit_override=False),
        rows=complete_evidence(embargo=True),
    )
    exit_with_override = evaluate(
        req=request(action=Action.EXIT),
        pol=policy(policy_id="exit-policy", version="2026-01", exit_override=True),
        rows=complete_evidence(embargo=True),
    )

    assert enter.verdict is Verdict.HARD_FAIL
    assert ReasonCode.EVENT_EMBARGO in enter.reason_codes
    assert exit_without_override.verdict is Verdict.HARD_FAIL
    assert exit_with_override.verdict is Verdict.PASS
    assert ReasonCode.EXIT_DURING_EMBARGO in exit_with_override.reason_codes
    assert exit_with_override.policy_version == "2026-01"


def test_prd_thresholds_are_exact_and_orderbook_staleness_degrades_fail_closed() -> None:
    at_spread_limit = evaluate(
        pol=policy(max_spread_bps=Decimal("10")),
        rows=complete_evidence(spread=Decimal("10")),
    )
    over_spread_limit = evaluate(
        pol=policy(max_spread_bps=Decimal("10")),
        rows=complete_evidence(spread=Decimal("10.0000000000000000001")),
    )
    fresh_boundary = evaluate(
        pol=policy(allow_degrade=True),
        rows=complete_evidence(order_book_at=NOW - timedelta(milliseconds=50)),
    )
    stale = evaluate(
        pol=policy(allow_degrade=True),
        rows=complete_evidence(order_book_at=NOW - timedelta(milliseconds=51)),
    )

    assert at_spread_limit.verdict is Verdict.PASS
    assert over_spread_limit.verdict is Verdict.HARD_FAIL
    assert ReasonCode.SPREAD_BREACH in over_spread_limit.reason_codes
    assert fresh_boundary.verdict is Verdict.PASS
    assert stale.verdict is Verdict.SOFT_FAIL
    assert ReasonCode.ORDERBOOK_STALE in stale.reason_codes


def test_flow_contradiction_gap_comparison_is_exact_at_the_policy_boundary() -> None:
    at_gap = evaluate(
        pol=policy(flow_contradiction_gap=Decimal("0.5")),
        rows=complete_evidence(flow_score=Decimal("-0.5")),
    )
    below_gap = evaluate(
        pol=policy(flow_contradiction_gap=Decimal("0.5")),
        rows=complete_evidence(flow_score=Decimal("-0.499999999999999999")),
    )

    assert ReasonCode.FLOW_CONTRADICT in at_gap.reason_codes
    assert ReasonCode.FLOW_CONTRADICT not in below_gap.reason_codes


def test_sentiment_breach_uses_policy_selected_verdict() -> None:
    soft = evaluate(
        pol=policy(min_sentiment=Decimal("-0.25"), on_sentiment_breach=Verdict.SOFT_FAIL),
        rows=complete_evidence(sentiment_score=Decimal("-0.5")),
    )
    hard = evaluate(
        pol=policy(min_sentiment=Decimal("-0.25"), on_sentiment_breach=Verdict.HARD_FAIL),
        rows=complete_evidence(sentiment_score=Decimal("-0.5")),
    )

    assert soft.verdict is Verdict.SOFT_FAIL
    assert hard.verdict is Verdict.HARD_FAIL
    assert ReasonCode.SENTIMENT_BREACH in soft.reason_codes


def test_missing_policy_returns_configured_verdict_and_allowlisted_reason() -> None:
    result = evaluate_truth(
        request(),
        None,
        complete_evidence(),
        evaluation_ts=NOW,
        missing_policy_verdict=Verdict.SOFT_FAIL,
    )
    hard_missing = evaluate_truth(
        request(),
        None,
        complete_evidence(),
        evaluation_ts=NOW,
        missing_policy_verdict=Verdict.HARD_FAIL,
    )

    assert result.verdict is Verdict.SOFT_FAIL
    assert ReasonCode.POLICY_MISSING in result.reason_codes
    assert hard_missing.verdict is Verdict.HARD_FAIL


def test_verdict_has_no_permit_field_and_module_imports_no_risk_or_route_authority() -> None:
    assert "permit" not in {field.name for field in dataclasses.fields(TruthVerdictV1)}
    module_dir = Path(inspect.getsourcefile(evaluate_truth)).parent
    forbidden = {"risk", "route", "c101", "c_101"}
    imported: set[str] = set()
    for source in module_dir.glob("*.py"):
        tree = ast.parse(source.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.lower() for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.lower())

    assert not any(
        part in forbidden for module in imported for part in module.replace("-", "_").split(".")
    )


def test_frozen_models_and_policy_replacement_enforce_validation() -> None:
    req = request()
    pol = policy()
    result = evaluate()
    for value in (req, pol, result):
        for operation in (
            lambda value=value: copy.copy(value),
            lambda value=value: copy.deepcopy(value),
            lambda value=value: pickle.dumps(value),
        ):
            with pytest.raises(InvalidTruthInputError):
                operation()

    with pytest.raises(PolicyOutOfBoundsError):
        dataclasses.replace(pol, max_spread_bps=Decimal("-1"))
    with pytest.raises(InvalidTruthInputError):
        dataclasses.replace(pol, max_clock_skew_ms=True)


def test_precision_boundary_and_integer_bool_inputs_have_typed_errors() -> None:
    with pytest.raises(PrecisionExceededError) as precision:
        policy(max_spread_bps=Decimal("1.2345678901234567890123456789012345"))
    assert precision.value.code == "PRECISION_EXCEEDED"

    with pytest.raises(InvalidTruthInputError):
        policy(max_clock_skew_ms=True)

    with pytest.raises(PolicyOutOfBoundsError):
        policy(max_spread_bps=Decimal("-1"))


def test_decimal_magnitude_is_checked_before_expansion_and_error_is_content_free() -> None:
    accepted = request(quantity=Decimal("1E+34"))
    assert accepted.quantity == Decimal("1E+34")

    raw = "1E+100000"
    with pytest.raises(InvalidTruthInputError) as error:
        request(quantity=Decimal(raw))

    assert raw not in str(error.value)
    assert raw not in repr(error.value.args)


def test_kernel_decimal_work_is_independent_of_ambient_context() -> None:
    ordinary = evaluate()
    with localcontext() as context:
        context.prec = 2
        context.traps[Inexact] = True
        constrained = evaluate()

    assert ordinary.verdict is constrained.verdict is Verdict.PASS
    assert ordinary.hash_id == constrained.hash_id
