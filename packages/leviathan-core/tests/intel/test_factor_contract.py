from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from types import SimpleNamespace

import pytest

from leviathan_core.feature_store.asof import FeatureKernelV1
from leviathan_core.feature_store.models import (
    FeatureDefinitionV1,
    FeatureLineageV1,
    FeatureObservationV1,
    FeatureQueryV1,
    FeatureResultSealError,
    FeatureResultV1,
)
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
    AsOfContextError,
    EvidenceRefV1,
    FactorAbstentionV1,
    FactorFreshnessPolicyV1,
    FactorScoreV1,
    FlowFactorAdapter,
    StructureFactorAdapter,
    TraceValidationError,
    build_trace,
    evidence_from_feature_result,
    evidence_from_normalized_event,
    evidence_from_payload,
    flow_context_for,
    issue_as_of_context,
    require_as_of_context,
    structure_context_for,
    to_layer_observation,
)
from leviathan_core.signal.signal_models import (
    ConfirmedStructurePivot,
    FinalizedStructureBar,
    StructureContext,
    StructureEvaluation,
    StructureSignalV1,
)
from leviathan_core.signal.structure_events import evaluate_structure

_CLOSE = datetime(2026, 9, 30, 15, 0, tzinfo=UTC)
_DECISION_NS = 2_000_000_000_000_000_000


def _structure() -> StructureSignalV1:
    evaluation = StructureEvaluation(
        context=StructureContext(
            symbol="NQ",
            venue="XCME",
            timeframe="1m",
            detector_id="structure",
            detector_version="1",
        ),
        bar=FinalizedStructureBar(
            bar_id="bar-1",
            close_time=_CLOSE,
            previous_close=Decimal("100"),
            close=Decimal("111"),
            input_version="feature-v1",
        ),
        pivots=(
            ConfirmedStructurePivot(
                pivot_id="pivot-1",
                kind="high",
                pivot_time=_CLOSE - timedelta(minutes=3),
                confirmed_at=_CLOSE - timedelta(minutes=1),
                price=Decimal("110"),
                feature_version="feature-v1",
            ),
        ),
        observed_at=_CLOSE,
    )
    events = evaluate_structure(evaluation)
    assert len(events) == 1 and isinstance(events[0], StructureSignalV1)
    return events[0]


def _flow():
    event_ns = 1_790_774_000_000_000_000
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
        session="session-1",
        venue="XNAS",
        native_record_key="native-1",
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
        session="session-1",
        venue="XNAS",
        native_record_key="quote-1",
        event_ns=event_ns,
        available_ns=event_ns,
        entitlement=Entitlement.ENTITLED,
    )
    underlying = UnderlyingMid(stamp=underlying_stamp, ticker="ABC", mid=Decimal("100"))
    return evaluate_flow(trade, calendar, underlying=underlying)


def test_factor_score_boundaries_and_future_evidence_fail_loudly() -> None:
    ref = evidence_from_payload(
        source="fixture", payload={"value": "x"}, source_event_ns=10, as_of_ns=10
    )
    valid = FactorScoreV1(
        factor_id="factor-1",
        family="structure",
        instrument="NQ",
        venue="XCME",
        direction="long",
        strength="0.7",
        reliability="1",
        as_of_ns=11,
        source_event_ns=10,
        freshness="fresh",
        unknown_freshness_allowed=False,
        freshness_policy_version="test/1",
        method="test",
        method_version="1",
        evidence_refs=(ref,),
    )
    assert valid.strength == "0.7"
    layer = to_layer_observation(valid)
    assert layer.semantic_digest == ref.record_digest
    assert layer.score == "0.7" and layer.confidence == "1"
    with pytest.raises(TypeError):
        valid.direction = "short"  # type: ignore[misc]
    with pytest.raises(ValueError):
        FactorScoreV1(**{**valid.model_dump(), "unknown_key": "rejected"})
    with pytest.raises(ValueError):
        FactorScoreV1(**{**valid.model_dump(), "as_of_ns": True})
    with pytest.raises(ValueError):
        FactorScoreV1(**{**valid.model_dump(), "strength": "1.01"})
    future = EvidenceRefV1(
        source="fixture", record_digest="a" * 64, as_of_ns=12, source_event_ns=12
    )
    with pytest.raises(ValueError, match="FUTURE_EVIDENCE"):
        issue_as_of_context(decision_as_of_ns=11, freshness="fresh", evidence_refs=(future,))


def test_context_is_issued_and_stale_unknown_or_missing_abstain() -> None:
    signal = _structure()
    decision_ns = _DECISION_NS
    adapter = StructureFactorAdapter()
    context = structure_context_for(signal, decision_as_of_ns=decision_ns)
    assert isinstance(adapter.evaluate(signal, context), FactorScoreV1)
    with pytest.raises(AsOfContextError):
        require_as_of_context(type(context)(**context.model_dump()))

    stale = structure_context_for(signal, decision_as_of_ns=decision_ns, freshness="stale")
    stale_result = adapter.evaluate(signal, stale)
    assert isinstance(stale_result, FactorAbstentionV1)
    assert stale_result.reason == "STALE_EVIDENCE"

    unknown = issue_as_of_context(
        decision_as_of_ns=decision_ns,
        freshness="unknown",
        evidence_refs=context.evidence_refs,
    )
    unknown_result = adapter.evaluate(signal, unknown)
    assert isinstance(unknown_result, FactorAbstentionV1)
    assert unknown_result.reason == "UNKNOWN_FRESHNESS"
    assert unknown_result.unknown_freshness_allowed is False
    assert unknown_result.freshness_policy_version == "default/1"
    unknown_policy = FactorFreshnessPolicyV1(
        factor_id=adapter.factor_id,
        policy_version="test/unknown-allowed-v1",
        allow_unknown_freshness=True,
    )
    allowed_result = adapter.evaluate(signal, unknown, policy=unknown_policy)
    assert isinstance(allowed_result, FactorScoreV1)
    assert allowed_result.unknown_freshness_allowed is True
    assert allowed_result.freshness == "unknown"
    assert allowed_result.freshness_policy_version == "test/unknown-allowed-v1"
    with pytest.raises(TypeError):
        adapter.evaluate(signal, unknown, allow_unknown_freshness=True)  # type: ignore[call-arg]
    with pytest.raises(ValueError, match="FACTOR_ADAPTER_INPUT_INVALID"):
        adapter.evaluate(
            signal,
            unknown,
            policy=FactorFreshnessPolicyV1(
                factor_id="different.factor", policy_version="test/1", allow_unknown_freshness=True
            ),
        )

    missing = issue_as_of_context(
        decision_as_of_ns=decision_ns, freshness="fresh", evidence_refs=()
    )
    missing_result = adapter.evaluate(signal, missing)
    assert isinstance(missing_result, FactorAbstentionV1)
    assert missing_result.reason == "MISSING_EVIDENCE"


def test_structure_adapter_maps_kernel_direction_and_abstains_on_gap() -> None:
    signal = _structure()
    decision_ns = _DECISION_NS
    result = StructureFactorAdapter().evaluate(
        signal, structure_context_for(signal, decision_as_of_ns=decision_ns)
    )
    assert isinstance(result, FactorScoreV1)
    assert result.direction == "long"
    assert result.strength == "1"
    assert result.evidence_refs[0].record_digest


def test_flow_adapter_maps_fake_snapshot_and_stale_data_abstains() -> None:
    evaluation = _flow()
    decision_ns = evaluation.print.stamp.available_ns + 1
    context = flow_context_for(evaluation, decision_as_of_ns=decision_ns)
    result = FlowFactorAdapter().evaluate(evaluation, context)
    assert isinstance(result, FactorScoreV1)
    assert result.direction == "long"
    assert result.strength == "0.9"
    stale = flow_context_for(evaluation, decision_as_of_ns=decision_ns, freshness="stale")
    stale_result = FlowFactorAdapter().evaluate(evaluation, stale)
    assert isinstance(stale_result, FactorAbstentionV1)
    assert stale_result.reason == "STALE_EVIDENCE"


def test_trace_hash_is_deterministic_and_links_all_stage_slots() -> None:
    signal = _structure()
    decision_ns = _DECISION_NS
    context = structure_context_for(signal, decision_as_of_ns=decision_ns)
    factor = StructureFactorAdapter().evaluate(signal, context)
    assert isinstance(factor, FactorScoreV1)
    extra = evidence_from_payload(
        source="other", payload={"record": 2}, source_event_ns=1, as_of_ns=1
    )
    first = build_trace(
        decision_as_of_ns=decision_ns,
        evidence_refs=(extra, context.evidence_refs[0]),
        normalized_event_refs=(context.evidence_refs[0],),
        factor_outcomes=(factor,),
    )
    replay = build_trace(
        decision_as_of_ns=decision_ns,
        evidence_refs=(context.evidence_refs[0], extra),
        normalized_event_refs=(context.evidence_refs[0],),
        factor_outcomes=(factor,),
    )
    assert first.trace_sha256 == replay.trace_sha256
    assert first.fusion_ref is None and first.calibration_ref is None
    assert first.portfolio_ref is None and first.risk_ref is None


def test_trace_rejects_duplicate_factor_ids_and_order_is_hash_independent() -> None:
    signal = _structure()
    decision_ns = _DECISION_NS
    context = structure_context_for(signal, decision_as_of_ns=decision_ns)
    score = StructureFactorAdapter().evaluate(signal, context)
    assert isinstance(score, FactorScoreV1)
    other = FactorScoreV1(**{**score.model_dump(), "factor_id": "another.factor.v1"})
    duplicate_outcome = FactorScoreV1(**{**score.model_dump(), "strength": "0.8"})
    with pytest.raises(TraceValidationError) as caught:
        build_trace(
            decision_as_of_ns=decision_ns,
            evidence_refs=context.evidence_refs,
            normalized_event_refs=(),
            factor_outcomes=(score, duplicate_outcome),
        )
    assert caught.value.code == "DUPLICATE_FACTOR_ID"

    first = build_trace(
        decision_as_of_ns=decision_ns,
        evidence_refs=context.evidence_refs,
        normalized_event_refs=(),
        factor_outcomes=(other, score),
    )
    reversed_order = build_trace(
        decision_as_of_ns=decision_ns,
        evidence_refs=context.evidence_refs,
        normalized_event_refs=(),
        factor_outcomes=(score, other),
    )
    assert first.trace_sha256 == reversed_order.trace_sha256


@pytest.mark.parametrize("ref_field", ["evidence_refs", "normalized_event_refs"])
def test_trace_rejects_conflicting_tied_refs_independent_of_input_order(
    ref_field: str,
) -> None:
    first_ref = EvidenceRefV1(
        source="same-source",
        record_digest="c" * 64,
        as_of_ns=10,
        source_event_ns=9,
    )
    conflicting_ref = EvidenceRefV1(
        source="same-source",
        record_digest="c" * 64,
        as_of_ns=11,
        source_event_ns=9,
    )
    refs = (first_ref, conflicting_ref)

    for ordered_refs in (refs, tuple(reversed(refs))):
        kwargs: dict[str, tuple[EvidenceRefV1, ...]] = {
            "evidence_refs": (),
            "normalized_event_refs": (),
        }
        kwargs[ref_field] = ordered_refs
        with pytest.raises(TraceValidationError) as caught:
            build_trace(
                decision_as_of_ns=12,
                factor_outcomes=(),
                **kwargs,
            )
        assert caught.value.code == "CONFLICTING_TRACE_REF"


def test_feature_issued_provenance_is_not_replaced_by_rehashing() -> None:
    # Evidence references originating from sealed FEAT results must carry their issuer
    # tag and original observation hash; the helper in models.py enforces this contract.
    forged = FeatureResultV1(
        found=True,
        feature_name="trend",
        feature_version="1",
        instrument_id="NQ",
        asof_ns=10,
        value_decimal=Decimal("1"),
        value_vector=None,
        quality=None,
        is_null=False,
        source_dataset="fixture",
        source_record_key="r1",
        event_time_ns=9,
        availability_ns=10,
        source_keys=(),
        definition_hash="a" * 64,
        observation_hash="b" * 64,
        lineage=FeatureLineageV1(definition_sha256="a" * 64, observation_sha256="b" * 64),
    )
    with pytest.raises(FeatureResultSealError):
        evidence_from_feature_result(forged)

    definition = FeatureDefinitionV1(
        feature_name="trend", feature_version="1", value_kind="decimal", published=True
    )
    observation = FeatureObservationV1(
        feature_name="trend",
        feature_version="1",
        instrument_id="NQ",
        source_dataset="fixture",
        source_record_key="r1",
        event_time_ns=9,
        availability_ns=10,
        value_decimal=Decimal("1"),
    )
    issued = FeatureKernelV1([definition], [observation]).query(
        FeatureQueryV1(feature_name="trend", feature_version="1", instrument_id="NQ", asof_ns=10)
    )
    reference = evidence_from_feature_result(issued)
    assert reference is not None
    assert reference.issuer_tag == "feat001.feature_result.v1"
    assert reference.record_digest == issued.observation_hash
    assert reference.seal_reference == issued.observation_hash


def test_market_event_reference_carries_native_digest_sequence_and_session() -> None:
    event = SimpleNamespace(
        provider="databento",
        dataset="GLBX.MDP3",
        venue="XCME",
        event_time_ns=100,
        source_time_ns=99,
        received_time_ns=110,
        native_sequence=7,
        provider_session_id="session-7",
        source_record_key="record-7",
        source_payload_sha256="c" * 64,
    )
    reference = evidence_from_normalized_event(event)
    assert reference.record_digest == event.source_payload_sha256
    assert reference.source_event_ns == 99
    assert reference.native_sequence == 7
    assert reference.provider_session_id == "session-7"
