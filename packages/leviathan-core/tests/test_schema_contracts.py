"""The replay fixture must parse cleanly into every Layer-1 contract,
and the cross-layer contract rules must hold end to end."""

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from leviathan_core.contracts import (
    ContractViolationError,
    assert_decision_respects_truth,
    assert_intent_is_authorized,
    assert_trade_is_executable,
)
from leviathan_core.schemas import (
    CandidateSetup,
    DecisionPacket,
    ExecutionIntent,
    Permission,
    RiskSnapshot,
    StrategyGenome,
    TradeJournalRecord,
    TruthStatus,
    TruthValidationResult,
)

FIXTURE = Path(__file__).parent / "fixtures" / "replay_nq_breakout.json"


@pytest.fixture(scope="module")
def replay() -> dict:
    return json.loads(FIXTURE.read_text())


def test_fixture_parses_into_all_layer1_contracts(replay: dict) -> None:
    StrategyGenome.model_validate(replay["strategy_genome"])
    CandidateSetup.model_validate(replay["candidate_setup"])
    TruthValidationResult.model_validate(replay["truth_validation"])
    DecisionPacket.model_validate(replay["decision_packet"])
    RiskSnapshot.model_validate(replay["risk_snapshot"])
    ExecutionIntent.model_validate(replay["execution_intent"])
    TradeJournalRecord.model_validate(replay["trade_journal_record"])


def test_contract_rules_hold_across_the_replay(replay: dict) -> None:
    setup = CandidateSetup.model_validate(replay["candidate_setup"])
    truth = TruthValidationResult.model_validate(replay["truth_validation"])
    decision = DecisionPacket.model_validate(replay["decision_packet"])
    risk = RiskSnapshot.model_validate(replay["risk_snapshot"])
    intent = ExecutionIntent.model_validate(replay["execution_intent"])

    assert_decision_respects_truth(decision, truth)
    assert_trade_is_executable(decision, risk, instrument=setup.instrument)
    assert_intent_is_authorized(intent, risk)


def test_execution_cannot_bypass_unapproved_decision(replay: dict) -> None:
    risk = RiskSnapshot.model_validate(replay["risk_snapshot"])
    rejected = DecisionPacket.model_validate(
        {**replay["decision_packet"], "permission": "reject"}
    )
    with pytest.raises(ContractViolationError):
        assert_trade_is_executable(rejected, risk, instrument="NQ")


def test_decision_cannot_approve_rejected_truth(replay: dict) -> None:
    truth = TruthValidationResult.model_validate(
        {**replay["truth_validation"], "truth_status": "rejected"}
    )
    decision = DecisionPacket.model_validate(replay["decision_packet"])
    assert decision.permission is Permission.APPROVE
    assert truth.truth_status is TruthStatus.REJECTED
    with pytest.raises(ContractViolationError):
        assert_decision_respects_truth(decision, truth)


def test_intent_must_carry_authorizing_risk_session(replay: dict) -> None:
    risk = RiskSnapshot.model_validate(replay["risk_snapshot"])
    foreign = ExecutionIntent.model_validate(
        {**replay["execution_intent"], "risk_session_id": "session_someone_else"}
    )
    with pytest.raises(ContractViolationError):
        assert_intent_is_authorized(foreign, risk)


def test_intent_size_capped_by_frozen_snapshot(replay: dict) -> None:
    risk = RiskSnapshot.model_validate(replay["risk_snapshot"])
    oversized = ExecutionIntent.model_validate(
        {**replay["execution_intent"], "size": "9.99"}
    )
    with pytest.raises(ContractViolationError):
        assert_intent_is_authorized(oversized, risk)


def test_blocked_trades_journal_without_prices() -> None:
    TradeJournalRecord(
        trade_id="trade_blocked01",
        setup_id="setup_x",
        decision_id="dec_x",
        outcome="blocked",
        post_trade_notes="Vetoed by risk engine; journaled anyway.",
    )


def test_executed_trades_require_prices() -> None:
    with pytest.raises(ValidationError):
        TradeJournalRecord(
            trade_id="trade_badwin01",
            setup_id="setup_x",
            decision_id="dec_x",
            outcome="win",
        )


def test_contracts_are_immutable(replay: dict) -> None:
    risk = RiskSnapshot.model_validate(replay["risk_snapshot"])
    with pytest.raises(ValidationError):
        risk.max_position_size = 999  # type: ignore[misc]
