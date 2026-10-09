"""Terminal council denials preserve the historical risk assessment."""

from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest
from pydantic import ValidationError

from leviathan_core.pipeline import LiveFlowPipeline, PreparedReplay
from leviathan_core.risk.policy import RiskPolicy, load_risk_policy
from leviathan_core.schemas import (
    CandidateSetup,
    DecisionPacket,
    GateFinding,
    Permission,
    RiskAction,
    RiskVerdict,
    TradeOutcome,
    TruthValidationResult,
)
from leviathan_core.state.session_classifier import classify_session

LOCK_FILE = (
    Path(__file__).resolve().parents[3]
    / "tests/fixtures/risk_lock/risk_governance.lock.yaml"
)


def _prepared(permission: Permission, assessment: RiskVerdict) -> PreparedReplay:
    setup = CandidateSetup(
        setup_id="setup_council", instrument="NQ",
        timestamp=datetime(2026, 9, 30, tzinfo=UTC), signal_features=("breakout",),
    )
    decision = DecisionPacket(
        decision_id=assessment.decision_id, setup_id=setup.setup_id,
        permission=permission, direction="long", confidence=0.8,
        entry_style="paper_market", scaling_allowed=False, justification="fixture",
    )
    return PreparedReplay(
        setup=setup,
        session=classify_session(setup.timestamp),
        range_context=None,
        truth=TruthValidationResult(
            setup_id=setup.setup_id, orderbook_bias="bullish",
            options_context="fixture", event_risk="safe",
            sentiment_modifier=0.0, truth_status="confirmed",
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


@pytest.mark.parametrize(
    ("permission", "action"),
    [
        (Permission.REJECT, RiskAction.REJECT),
        (Permission.WAIT, RiskAction.WAIT),
        (Permission.SIGNAL_ONLY, RiskAction.REJECT),
    ],
)
def test_council_denial_is_new_terminal_verdict_with_historical_evidence(
    permission: Permission, action: RiskAction,
) -> None:
    assessment = RiskVerdict(
        decision_id="decision_council", action=RiskAction.REDUCE_SIZE,
        reason="risk_allows_smaller", adjusted_size=Decimal("0.5"),
        execution_capable=True, halts_engaged=("prior_halt",),
        findings=(GateFinding.STREAM_UNKNOWN,),
    )
    prepared = _prepared(permission, assessment)
    pipeline = LiveFlowPipeline.__new__(LiveFlowPipeline)

    final, journal = pipeline.block_prepared(prepared)

    assert final is not assessment
    assert prepared.assessment is assessment
    assert assessment.action is RiskAction.REDUCE_SIZE
    assert assessment.adjusted_size == Decimal("0.5")
    assert final.decision_id == assessment.decision_id
    assert final.action is action
    assert final.reason == f"council_permission_{permission.value}"
    assert final.adjusted_size is None and final.execution_capable is False
    assert final.findings == assessment.findings
    assert final.halts_engaged == assessment.halts_engaged
    assert journal.outcome is TradeOutcome.BLOCKED
    assert journal.decision_id == final.decision_id
    assert f"risk={action.value} reason={final.reason}" in journal.post_trade_notes


def test_stronger_halt_assessment_is_preserved() -> None:
    assessment = RiskVerdict(
        decision_id="decision_council", action=RiskAction.HALT_ALL_TRADING,
        reason="halt_active:operator", halts_engaged=("operator",),
        findings=(GateFinding.GLOBAL_KILL,),
    )
    prepared = _prepared(Permission.WAIT, assessment)
    pipeline = LiveFlowPipeline.__new__(LiveFlowPipeline)

    final, journal = pipeline.block_prepared(prepared)

    assert final is assessment
    assert final.action is RiskAction.HALT_ALL_TRADING
    assert final.findings == (GateFinding.GLOBAL_KILL,)
    assert journal.outcome is TradeOutcome.BLOCKED
    assert "reason=halt_active:operator" in journal.post_trade_notes


def test_locked_policy_copy_revalidates_every_nested_rule() -> None:
    policy = load_risk_policy(LOCK_FILE)
    nested = (
        policy.drawdown, policy.heat, policy.leverage, policy.correlation,
        policy.news_embargo, policy.loss_streak, policy.instrument_limits,
        policy.instrument_limits.default, *policy.instrument_limits.overrides.values(),
        policy.kill_switches, policy.audit, policy.self_evolution,
    )
    assert policy.model_copy(deep=True) == policy
    with pytest.raises(ValidationError):
        policy.model_copy(update={"version": "not_an_integer"})
    with pytest.raises(ValidationError):
        policy.self_evolution.model_copy(update={"triton_can_apply_changes": True})
    with pytest.raises(ValidationError):
        policy.model_copy(update={
            "self_evolution": {
                **policy.self_evolution.model_dump(mode="python"),
                "triton_can_apply_changes": True,
            }
        })
    with pytest.raises(TypeError):
        RiskPolicy.model_construct()
    for rule in nested:
        assert rule.model_copy() == rule
        with pytest.raises(TypeError):
            type(rule).model_construct()
