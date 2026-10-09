from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from decimal import Decimal

import pytest
from pydantic import ValidationError

from leviathan_core.flow_radar.filters import evaluate_flow
from leviathan_core.flow_radar.models import (
    Entitlement,
    OptionPrint,
    OptionSide,
    SessionCalendar,
    SourceStamp,
    TradeSide,
    TradingSession,
    UnderlyingMid,
)
from leviathan_core.intel import (
    EvidenceRefV1,
    FactorAbstentionV1,
    FactorScoreV1,
    FlowFactorAdapter,
    StructureFactorAdapter,
    build_trace,
    evidence_from_payload,
    flow_context_for,
    issue_as_of_context,
    structure_context_for,
)
from leviathan_core.intel.models import FutureEvidenceError, unix_ns
from leviathan_core.intel.trace import (
    IntelExplanationTraceV1,
    TraceExclusionV1,
    TraceValidationError,
)
from leviathan_core.signal.signal_models import (
    ConfirmedStructurePivot,
    FinalizedStructureBar,
    StructureContext,
    StructureEvaluation,
    StructureSignalV1,
)
from leviathan_core.signal.structure_events import evaluate_structure

_FAMILIES = (
    "book_l2_l3",
    "order_flow",
    "structure",
    "volume",
    "momentum",
    "gex",
    "dex",
    "dark_pool",
    "insider",
    "macro",
    "regime",
    "indicator",
    "prediction_market",
    "doctrine",
)
_AS_OF_NS = 2_000_000_000_000_000_000
_CLOSE = datetime(2026, 9, 30, 15, 0, tzinfo=UTC)


def _evidence(
    *, source: str = "fixture", value: str = "one", as_of_ns: int = _AS_OF_NS
) -> EvidenceRefV1:
    return evidence_from_payload(
        source=source,
        payload={"value": value},
        source_event_ns=as_of_ns,
        as_of_ns=as_of_ns,
    )


def _score(**overrides: object) -> FactorScoreV1:
    values: dict[str, object] = {
        "factor_id": "acceptance.factor",
        "family": "structure",
        "instrument": "NQ",
        "venue": "XCME",
        "direction": "long",
        "strength": "0.7",
        "reliability": "0.8",
        "as_of_ns": _AS_OF_NS,
        "source_event_ns": _AS_OF_NS,
        "freshness": "fresh",
        "method": "acceptance",
        "method_version": "1",
        "evidence_refs": (_evidence(),),
    }
    values.update(overrides)
    return FactorScoreV1(**values)  # type: ignore[arg-type]


def _structure() -> StructureSignalV1:
    evaluation = StructureEvaluation(
        context=StructureContext(
            symbol="NQ",
            venue="XCME",
            timeframe="1m",
            detector_id="acceptance-structure",
            detector_version="1",
        ),
        bar=FinalizedStructureBar(
            bar_id="acceptance-bar",
            close_time=_CLOSE,
            previous_close=Decimal("100"),
            close=Decimal("111"),
            input_version="fixture-v1",
        ),
        pivots=(
            ConfirmedStructurePivot(
                pivot_id="acceptance-pivot",
                kind="high",
                pivot_time=_CLOSE - timedelta(minutes=3),
                confirmed_at=_CLOSE - timedelta(minutes=1),
                price=Decimal("110"),
                feature_version="fixture-v1",
            ),
        ),
        observed_at=_CLOSE,
    )
    events = evaluate_structure(evaluation)
    signals = [event for event in events if isinstance(event, StructureSignalV1)]
    assert len(signals) == 1
    return signals[0]


def _flow(event_ns: int = 1_790_774_000_000_000_000):
    calendar = SessionCalendar(
        sessions=(
            TradingSession(
                date(2026, 9, 30),
                event_ns - 10_000_000_000,
                event_ns + 10_000_000_000,
            ),
        )
    )
    stamp = SourceStamp(
        provider="massive",
        dataset="options",
        session="intel-acceptance-session",
        venue="XNAS",
        native_record_key=f"trade-{event_ns}",
        event_ns=event_ns,
        available_ns=event_ns,
        entitlement=Entitlement.ENTITLED,
    )
    trade = OptionPrint(
        stamp=stamp,
        ticker="ABC",
        expiry=date(2026, 10, 16),
        strike=Decimal("105"),
        cp=OptionSide.CALL,
        trade_side=TradeSide.BUY,
        size=Decimal("10"),
        price=Decimal("2"),
        multiplier=Decimal("100"),
        aggression_score=Decimal("0.9"),
    )
    underlying_stamp = SourceStamp(
        provider="massive",
        dataset="quotes",
        session="intel-acceptance-session",
        venue="XNAS",
        native_record_key=f"quote-{event_ns}",
        event_ns=event_ns,
        available_ns=event_ns,
        entitlement=Entitlement.ENTITLED,
    )
    underlying = UnderlyingMid(stamp=underlying_stamp, ticker="ABC", mid=Decimal("100"))
    return evaluate_flow(trade, calendar, underlying=underlying)


def test_factor_contract_bounds_families_abstention_exclusivity_and_evidence() -> None:
    for family in _FAMILIES:
        result = _score(family=family, factor_id=f"acceptance.{family}")
        assert result.family == family

    for field in ("strength", "reliability"):
        for value in ("-0.001", "1.001"):
            with pytest.raises(ValidationError):
                _score(**{field: value})
    assert _score(strength="0", reliability="1").strength == "0"

    abstention_fields: dict[str, object] = {
        "factor_id": "acceptance.abstain",
        "family": "structure",
        "instrument": "NQ",
        "venue": "XCME",
        "as_of_ns": _AS_OF_NS,
        "source_event_ns": _AS_OF_NS,
        "freshness": "unknown",
        "method": "acceptance",
        "method_version": "1",
        "evidence_refs": (),
        "reason": "MISSING_EVIDENCE",
    }
    assert isinstance(FactorAbstentionV1(**abstention_fields), FactorAbstentionV1)
    for forbidden in (
        {"direction": "long"},
        {"strength": "0.5"},
        {"reliability": "0.5"},
    ):
        with pytest.raises(ValidationError):
            FactorAbstentionV1(**{**abstention_fields, **forbidden})
    with pytest.raises(ValidationError):
        _score(direction=None)
    with pytest.raises(ValidationError):
        _score(reason="STALE_EVIDENCE")
    with pytest.raises(ValidationError):
        _score(evidence_refs=())


def test_as_of_boundaries_and_nonfresh_inputs_abstain_with_typed_reasons() -> None:
    exact = _evidence(as_of_ns=_AS_OF_NS)
    context = issue_as_of_context(
        decision_as_of_ns=_AS_OF_NS, freshness="fresh", evidence_refs=(exact,)
    )
    assert context.evidence_refs == (exact,)
    assert isinstance(_score(evidence_refs=(exact,)), FactorScoreV1)

    for future_ref in (
        evidence_from_payload(
            source="future-event",
            payload={"v": 1},
            source_event_ns=_AS_OF_NS + 1,
            as_of_ns=_AS_OF_NS,
        ),
        evidence_from_payload(
            source="future-availability",
            payload={"v": 2},
            source_event_ns=_AS_OF_NS,
            as_of_ns=_AS_OF_NS + 1,
        ),
    ):
        with pytest.raises(FutureEvidenceError, match="FUTURE_EVIDENCE"):
            issue_as_of_context(
                decision_as_of_ns=_AS_OF_NS,
                freshness="fresh",
                evidence_refs=(future_ref,),
            )

    signal = _structure()
    decision_ns = _AS_OF_NS
    adapter = StructureFactorAdapter()
    for freshness, expected_reason in (
        ("stale", "STALE_EVIDENCE"),
        ("unknown", "UNKNOWN_FRESHNESS"),
    ):
        stale_context = structure_context_for(
            signal, decision_as_of_ns=decision_ns, freshness=freshness
        )
        result = adapter.evaluate(signal, stale_context)
        assert isinstance(result, FactorAbstentionV1)
        assert result.reason == expected_reason

    missing = issue_as_of_context(
        decision_as_of_ns=decision_ns, freshness="fresh", evidence_refs=()
    )
    missing_result = adapter.evaluate(signal, missing)
    assert isinstance(missing_result, FactorAbstentionV1)
    assert missing_result.reason == "MISSING_EVIDENCE"


def test_trace_hash_binds_content_exclusions_and_preserves_canonical_order() -> None:
    evidence_a = _evidence(source="a", value="alpha")
    evidence_b = _evidence(source="b", value="beta")
    score = _score(evidence_refs=(evidence_a, evidence_b))
    trace = build_trace(
        decision_as_of_ns=_AS_OF_NS,
        evidence_refs=(evidence_b, evidence_a),
        normalized_event_refs=(evidence_a, evidence_b),
        factor_outcomes=(score,),
    )
    replay = build_trace(
        decision_as_of_ns=_AS_OF_NS,
        evidence_refs=(evidence_a, evidence_b),
        normalized_event_refs=(evidence_b, evidence_a),
        factor_outcomes=(score,),
    )
    assert trace.trace_sha256 == replay.trace_sha256
    assert trace.evidence_refs == tuple(sorted((evidence_a, evidence_b), key=lambda r: r.source))

    changed_evidence = _evidence(source="b", value="changed")
    changed = build_trace(
        decision_as_of_ns=_AS_OF_NS,
        evidence_refs=(evidence_a, changed_evidence),
        normalized_event_refs=(evidence_a, evidence_b),
        factor_outcomes=(score,),
    )
    assert changed.trace_sha256 != trace.trace_sha256

    changed_source = _evidence(source="changed-source", value="alpha")
    source_changed_trace = build_trace(
        decision_as_of_ns=_AS_OF_NS,
        evidence_refs=(evidence_a, changed_source),
        normalized_event_refs=(evidence_a, evidence_b),
        factor_outcomes=(score,),
    )
    assert source_changed_trace.trace_sha256 != trace.trace_sha256

    metadata_values = evidence_a.model_dump()
    metadata_values["source_record_key"] = "different-record-key"
    changed_metadata = EvidenceRefV1(**metadata_values)
    metadata_changed_trace = build_trace(
        decision_as_of_ns=_AS_OF_NS,
        evidence_refs=(changed_metadata, evidence_b),
        normalized_event_refs=(evidence_a, evidence_b),
        factor_outcomes=(score,),
    )
    assert metadata_changed_trace.trace_sha256 != trace.trace_sha256

    excluded = build_trace(
        decision_as_of_ns=_AS_OF_NS,
        evidence_refs=(evidence_a, evidence_b),
        normalized_event_refs=(evidence_a, evidence_b),
        factor_outcomes=(score,),
        exclusions=(TraceExclusionV1(evidence_digest="c" * 64, reason="STALE"),),
    )
    assert excluded.trace_sha256 != trace.trace_sha256

    ordered_content = IntelExplanationTraceV1(
        decision_as_of_ns=trace.decision_as_of_ns,
        evidence_refs=tuple(reversed(trace.evidence_refs)),
        normalized_event_refs=tuple(reversed(trace.normalized_event_refs)),
        factor_outcomes=trace.factor_outcomes,
        exclusions=trace.exclusions,
    )
    assert ordered_content.trace_sha256 == trace.trace_sha256
    assert ordered_content.evidence_refs == trace.evidence_refs
    assert ordered_content.normalized_event_refs == trace.normalized_event_refs

    conflicting_metadata = EvidenceRefV1(
        **{
            **evidence_a.model_dump(),
            "source_record_key": "conflicting-key",
        }
    )
    with pytest.raises(TraceValidationError, match="CONFLICTING_TRACE_REF"):
        build_trace(
            decision_as_of_ns=_AS_OF_NS,
            evidence_refs=(evidence_a, conflicting_metadata),
            normalized_event_refs=(evidence_a, evidence_b),
            factor_outcomes=(score,),
        )
    with pytest.raises((TypeError, ValidationError)):
        trace.evidence_refs = ()  # type: ignore[misc]


def test_sig_and_flow_reference_adapters_map_fake_snapshots_and_retain_refs() -> None:
    signal = _structure()
    sig_context = structure_context_for(signal, decision_as_of_ns=_AS_OF_NS)
    sig_result = StructureFactorAdapter().evaluate(signal, sig_context)
    assert isinstance(sig_result, FactorScoreV1)
    assert sig_result.direction == "long"
    assert sig_result.strength == "1"
    assert sig_result.reliability == "1"
    assert sig_result.evidence_refs == sig_context.evidence_refs

    flow = _flow()
    flow_context = flow_context_for(flow, decision_as_of_ns=flow.print.stamp.event_ns + 1)
    flow_result = FlowFactorAdapter().evaluate(flow, flow_context)
    assert isinstance(flow_result, FactorScoreV1)
    assert flow_result.direction == "long"
    assert flow_result.strength == "0.9"
    assert flow_result.reliability == "1"
    assert flow_result.evidence_refs == flow_context.evidence_refs

    stale_sig = StructureFactorAdapter().evaluate(
        signal,
        structure_context_for(signal, decision_as_of_ns=_AS_OF_NS, freshness="stale"),
    )
    stale_flow = FlowFactorAdapter().evaluate(
        flow,
        flow_context_for(flow, decision_as_of_ns=flow.print.stamp.event_ns + 1, freshness="stale"),
    )
    assert isinstance(stale_sig, FactorAbstentionV1)
    assert stale_sig.reason == "STALE_EVIDENCE"
    assert isinstance(stale_flow, FactorAbstentionV1)
    assert stale_flow.reason == "STALE_EVIDENCE"

    future_decision_ns = flow.print.stamp.event_ns - 1
    assert flow.print.stamp.event_ns == future_decision_ns + 1
    with pytest.raises(FutureEvidenceError, match="FUTURE_EVIDENCE"):
        flow_context_for(flow, decision_as_of_ns=future_decision_ns)

    signal_event_ns = unix_ns(signal.ts_event)
    assert signal_event_ns == (signal_event_ns // 1_000) * 1_000
    with pytest.raises(FutureEvidenceError, match="FUTURE_EVIDENCE"):
        structure_context_for(signal, decision_as_of_ns=signal_event_ns - 1)
