"""SEAL-001 issuance behavior for C-101 records."""

from __future__ import annotations

import copy
import hashlib
import pickle
from collections.abc import Callable
from datetime import UTC, datetime, timedelta, timezone
from decimal import Decimal

import pytest

from leviathan_core.pipeline import (
    LiveFlowPipeline,
    PipelineResult,
    PreparedReplay,
    _issue_pipeline_result,
    require_pipeline_result,
)
from leviathan_core.schemas.decision import DecisionPacket
from leviathan_core.schemas.enums import (
    Direction,
    EventRisk,
    OrderbookBias,
    Permission,
    RiskAction,
    TradeOutcome,
    TruthStatus,
)
from leviathan_core.schemas.journal import (
    TradeJournalRecord,
    _issue_trade_journal_record,
    require_trade_journal_record,
)
from leviathan_core.schemas.risk import (
    RiskVerdict,
    _issue_risk_verdict,
    require_risk_verdict,
)
from leviathan_core.schemas.setup import CandidateSetup
from leviathan_core.schemas.truth import TruthValidationResult
from leviathan_core.seal import SealError
from leviathan_core.state.session_classifier import SessionContext


def _verdict() -> RiskVerdict:
    return RiskVerdict(
        decision_id="decision_seal_test",
        action=RiskAction.REJECT,
        reason="fixture_block",
        execution_capable=False,
    )


def _journal() -> TradeJournalRecord:
    return TradeJournalRecord(
        trade_id="trade_golden",
        setup_id="setup_golden",
        decision_id="decision_golden",
        entry=Decimal("100.25"),
        exit=Decimal("101.50"),
        mae=Decimal("-0.75"),
        mfe=Decimal("2.00"),
        outcome=TradeOutcome.WIN,
        post_trade_notes="paper_sim target_hit pnl=1.25",
    )


def _assert_not_issued(callable_: Callable[[], object]) -> None:
    with pytest.raises(SealError, match="SEAL_NOT_ISSUED"):
        callable_()


def _prepared_replay(assessment: RiskVerdict, permission: Permission) -> PreparedReplay:
    setup = CandidateSetup(
        setup_id="setup_pipeline_wrapper",
        instrument="NQ",
        timestamp=datetime(2026, 4, 15, 14, 35, tzinfo=UTC),
    )
    decision = DecisionPacket(
        decision_id="decision_pipeline_wrapper",
        setup_id=setup.setup_id,
        permission=permission,
        direction=Direction.FLAT,
        confidence=Decimal("0.75"),
        entry_style="market",
        scaling_allowed=False,
        justification="wrapper provenance test",
    )
    assessment = assessment.model_copy(update={"decision_id": decision.decision_id})
    return PreparedReplay(
        setup=setup,
        session=SessionContext(label="ny_overlap", quality=Decimal("1"), is_dead_time=False),
        range_context=None,
        truth=TruthValidationResult(
            setup_id=setup.setup_id,
            orderbook_bias=OrderbookBias.NEUTRAL,
            options_context="none",
            event_risk=EventRisk.SAFE,
            sentiment_modifier=Decimal("0"),
            truth_status=TruthStatus.CONFIRMED,
        ),
        decision=decision,
        assessment=assessment,
        risk_snapshot=None,
        bars=(),
        context=None,
        requested_size=Decimal("1"),
        stop_loss=None,
        take_profit=None,
    )


def test_risk_verdict_issuance_is_identity_and_content_bound() -> None:
    value = _verdict()
    assert require_risk_verdict(_issue_risk_verdict(value)) is value
    original = value.model_dump_json()
    with pytest.raises(SealError, match="SEAL_FORBIDDEN_OPERATION"):
        value.__init__(**value.model_dump())
    assert value.model_dump_json() == original
    assert require_risk_verdict(value) is value

    _assert_not_issued(lambda: require_risk_verdict(_verdict()))
    _assert_not_issued(lambda: require_risk_verdict(copy.copy(value)))
    _assert_not_issued(lambda: require_risk_verdict(copy.deepcopy(value)))
    _assert_not_issued(lambda: require_risk_verdict(pickle.loads(pickle.dumps(value))))
    with pytest.raises(SealError, match="SEAL_INVALID_MODEL"):
        require_risk_verdict(object())

    object.__setattr__(value, "reason", "mutated")
    with pytest.raises(SealError, match="SEAL_TAMPERED"):
        require_risk_verdict(value)


def test_journal_issuance_and_prechange_json_bytes_are_stable() -> None:
    value = _journal()
    payload = value.model_dump_json().encode("utf-8")
    assert payload == (
        b'{"trade_id":"trade_golden","setup_id":"setup_golden",'
        b'"decision_id":"decision_golden","entry":"100.25",'
        b'"exit":"101.50","mae":"-0.75","mfe":"2.00",'
        b'"outcome":"win","post_trade_notes":"paper_sim target_hit pnl=1.25"}'
    )
    assert hashlib.sha256(payload).hexdigest() == (
        "d03924afd7824b3efefbf71c099bd3129f43ba2577302fdc729a972b84f1ab0d"
    )
    assert require_trade_journal_record(_issue_trade_journal_record(value)) is value
    original = value.model_dump_json()
    with pytest.raises(SealError, match="SEAL_FORBIDDEN_OPERATION"):
        value.__init__(**value.model_dump())
    assert value.model_dump_json() == original
    assert require_trade_journal_record(value) is value

    _assert_not_issued(lambda: require_trade_journal_record(_journal()))
    _assert_not_issued(lambda: require_trade_journal_record(copy.copy(value)))
    _assert_not_issued(lambda: require_trade_journal_record(copy.deepcopy(value)))
    _assert_not_issued(lambda: require_trade_journal_record(pickle.loads(pickle.dumps(value))))
    with pytest.raises(SealError, match="SEAL_INVALID_MODEL"):
        require_trade_journal_record(object())

    object.__setattr__(value, "post_trade_notes", "changed")
    with pytest.raises(SealError, match="SEAL_TAMPERED"):
        require_trade_journal_record(value)


def test_pipeline_require_rejects_unissued_exact_model_and_other_types() -> None:
    value = object.__new__(PipelineResult)
    with pytest.raises(SealError, match="SEAL_NOT_ISSUED"):
        require_pipeline_result(value)
    with pytest.raises(SealError, match="SEAL_INVALID_MODEL"):
        require_pipeline_result(object())


def test_pipeline_result_issuance_binds_nested_records_and_final_links() -> None:
    setup = CandidateSetup(
        setup_id="setup_pipeline_seal",
        instrument="NQ",
        timestamp=datetime(2026, 4, 15, 14, 35, tzinfo=UTC),
    )
    decision = DecisionPacket(
        decision_id="decision_pipeline_seal",
        setup_id=setup.setup_id,
        permission=Permission.REJECT,
        direction=Direction.FLAT,
        confidence=Decimal("0.75"),
        entry_style="market",
        scaling_allowed=False,
        justification="seal test",
    )
    verdict = _issue_risk_verdict(
        RiskVerdict(
            decision_id=decision.decision_id,
            action=RiskAction.REJECT,
            reason="seal test",
            execution_capable=False,
        )
    )
    final_verdict = _issue_risk_verdict(
        RiskVerdict(
            decision_id=decision.decision_id,
            action=RiskAction.REJECT,
            reason="final seal test",
            execution_capable=False,
        )
    )
    journal = _issue_trade_journal_record(
        TradeJournalRecord(
            trade_id="trade_pipeline_seal",
            setup_id=setup.setup_id,
            decision_id=decision.decision_id,
            outcome=TradeOutcome.BLOCKED,
        )
    )
    result = PipelineResult(
        setup=setup,
        session=SessionContext(label="ny_overlap", quality=Decimal("1"), is_dead_time=False),
        range_context=None,
        truth=TruthValidationResult(
            setup_id=setup.setup_id,
            orderbook_bias=OrderbookBias.NEUTRAL,
            options_context="none",
            event_risk=EventRisk.SAFE,
            sentiment_modifier=Decimal("0"),
            truth_status=TruthStatus.CONFIRMED,
        ),
        decision=decision,
        verdict=verdict,
        final_verdict=final_verdict,
        findings=(),
        intent=None,
        journal_record=journal,
        final=True,
    )

    issued = _issue_pipeline_result(result)
    assert require_pipeline_result(issued) is issued
    assert issued.verdict is verdict
    assert issued.final_verdict is final_verdict
    assert issued.journal_record is journal

    original = issued.model_dump_json()
    with pytest.raises(SealError, match="SEAL_FORBIDDEN_OPERATION"):
        issued.__init__(**issued.model_dump())
    assert issued.model_dump_json() == original
    assert require_pipeline_result(issued) is issued

    mismatched_journal = _issue_trade_journal_record(
        TradeJournalRecord(
            trade_id="trade_pipeline_mismatch",
            setup_id="other",
            decision_id=decision.decision_id,
            outcome=TradeOutcome.BLOCKED,
        )
    )
    mismatched = result.model_copy(update={"journal_record": mismatched_journal})
    with pytest.raises(SealError, match="SEAL_NOT_ISSUED"):
        require_pipeline_result(mismatched)
    with pytest.raises(SealError, match="SEAL_INVALID_MODEL"):
        _issue_pipeline_result(mismatched)

    object.__setattr__(issued, "failure_reason", "tampered")
    with pytest.raises(SealError, match="SEAL_TAMPERED"):
        require_pipeline_result(issued)

    offset_setup = setup.model_copy(
        update={
            "timestamp": datetime(
                2026, 4, 15, 20, 5, tzinfo=timezone(timedelta(hours=5, minutes=30))
            )
        }
    )
    offset_result = result.model_copy(update={"setup": offset_setup})
    normalized = _issue_pipeline_result(offset_result)
    assert normalized.setup.timestamp == setup.timestamp
    assert normalized.setup.timestamp.tzinfo is UTC

    naive_setup = setup.model_copy(update={"timestamp": datetime(2026, 4, 15, 14, 35)})
    naive_result = result.model_copy(update={"setup": naive_setup})
    with pytest.raises(SealError, match="SEAL_INVALID_MODEL") as error:
        _issue_pipeline_result(naive_result)
    assert error.value.__cause__ is None
    assert error.value.args == ("SEAL_INVALID_MODEL",)


def test_pipeline_wrappers_never_launder_caller_built_c101_records() -> None:
    pipeline = object.__new__(LiveFlowPipeline)
    forged_allow = RiskVerdict(
        decision_id="decision_pipeline_wrapper",
        action=RiskAction.ALLOW,
        reason="caller supplied allow",
        adjusted_size=Decimal("999999"),
        execution_capable=True,
    )
    prepared = _prepared_replay(forged_allow, Permission.REJECT)
    matching_journal = TradeJournalRecord(
        trade_id="trade_wrapper_forgery",
        setup_id=prepared.setup.setup_id,
        decision_id=prepared.decision.decision_id,
        outcome=TradeOutcome.BLOCKED,
    )

    # The legacy wrapper still returns its result, but neither the rewritten
    # verdict nor the wrapper-created journal receives trusted issuance.
    blocked_verdict, blocked_journal = pipeline.block_prepared(prepared, forged_allow)
    _assert_not_issued(lambda: require_risk_verdict(blocked_verdict))
    _assert_not_issued(lambda: require_trade_journal_record(blocked_journal))

    # A caller-built assessment plus matching caller-built final pair cannot
    # be promoted to an issued PipelineResult.
    legacy_result = pipeline.result_from_prepared(
        prepared,
        forged_allow,
        None,
        matching_journal,
    )
    _assert_not_issued(lambda: require_pipeline_result(legacy_result))

    # Mixed issued/unissued C-101 inputs are untrusted as a whole.
    issued_assessment = _issue_risk_verdict(prepared.assessment)
    mixed_prepared = prepared.model_copy(update={"assessment": issued_assessment})
    mixed_result = pipeline.result_from_prepared(
        mixed_prepared,
        forged_allow,
        None,
        matching_journal,
    )
    _assert_not_issued(lambda: require_pipeline_result(mixed_result))

    # A fully issued source flow remains consumable through the wrapper.
    issued_final = _issue_risk_verdict(
        RiskVerdict(
            decision_id=prepared.decision.decision_id,
            action=RiskAction.REJECT,
            reason="pipeline source flow",
            execution_capable=False,
        )
    )
    issued_journal = _issue_trade_journal_record(matching_journal)
    issued_result = pipeline.result_from_prepared(
        mixed_prepared,
        issued_final,
        None,
        issued_journal,
    )
    assert require_pipeline_result(issued_result) is issued_result
