"""Independent C101-FIX-002 terminal council denial acceptance cases."""

import json
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path

import pytest

from leviathan_core.decision.engine import CouncilDecisionEngine
from leviathan_core.execution.paper_sim import PaperExecutionEngine
from leviathan_core.pipeline import LiveFlowPipeline, PreparedReplay
from leviathan_core.risk import (
    HaltAuthority,
    RiskAuditLog,
    RouteGuard,
    VetoEngine,
    load_risk_policy,
)
from leviathan_core.schemas import (
    AccountState,
    Bar,
    CandidateSetup,
    GateFinding,
    KillState,
    Permission,
    RequiredStream,
    RiskAction,
    RiskGateContext,
    RiskVerdict,
    StrategyGenome,
    StreamFreshness,
    TradeOutcome,
    TruthValidationResult,
)
from leviathan_core.truth.provider import StaticTruthProvider

REPO_ROOT = Path(__file__).resolve().parents[3]
LOCK_FILE = REPO_ROOT / "tests/fixtures/risk_lock/risk_governance.lock.yaml"
LOCK_SHA256 = "46a03497679f8a59c82229ba28cef4bf56b7c1d7c30ae936016f876c9eaf3c51"
FIXTURE = Path(__file__).parent / "fixtures/replay_nq_breakout.json"


@pytest.fixture
def replay_data() -> dict[str, object]:
    return json.loads(FIXTURE.read_text())


@pytest.fixture
def pipeline(tmp_path: Path, replay_data: dict[str, object]) -> LiveFlowPipeline:
    truth = StaticTruthProvider(
        TruthValidationResult.model_validate(replay_data["truth_validation"])
    )
    veto = VetoEngine(
        policy=load_risk_policy(LOCK_FILE),
        halt_authority=HaltAuthority(),
        audit_log=RiskAuditLog(tmp_path / "audit.jsonl"),
        route_guard=RouteGuard(LOCK_FILE, LOCK_SHA256),
    )
    return LiveFlowPipeline(
        truth_provider=truth,
        decision_engine=CouncilDecisionEngine(),
        veto_engine=veto,
        paper_engine=PaperExecutionEngine(),
        risk_lock_sha256=LOCK_SHA256,
    )


def _prepared(
    pipeline: LiveFlowPipeline, replay_data: dict[str, object], permission: Permission
) -> PreparedReplay:
    start = datetime(2026, 4, 15, 14, 35, tzinfo=UTC)
    ohlc = [
        ("18250", "18258", "18246", "18255"),
        ("18255", "18262", "18248", "18260"),
        ("18260", "18266", "18255", "18264"),
        ("18264", "18272", "18260", "18270"),
    ]
    bars = tuple(
        Bar(
            instrument="NQ",
            timestamp=start + timedelta(minutes=index),
            open=Decimal(open_),
            high=Decimal(high),
            low=Decimal(low),
            close=Decimal(close),
            volume=Decimal(1000),
        )
        for index, (open_, high, low, close) in enumerate(ohlc)
    )
    at = bars[-1].timestamp
    context = RiskGateContext(
        as_of=at,
        required=(RequiredStream(stream_id="bars.1m", symbol="NQ", provider="demo"),),
        observed=(
            StreamFreshness(
                stream_id="bars.1m",
                symbol="NQ",
                provider="demo",
                source_ts=at,
                exchange_ts=at,
                received_at=at,
            ),
        ),
        kill=KillState(),
    )
    prepared = pipeline.prepare_replay(
        CandidateSetup.model_validate(replay_data["candidate_setup"]),
        bars,
        AccountState(equity=Decimal("100000"), daily_pnl_pct=Decimal(0)),
        genome=StrategyGenome.model_validate(replay_data["strategy_genome"]),
        requested_size=Decimal("1"),
        stop_loss=Decimal("18240"),
        take_profit=Decimal("18270"),
        context=context,
    )
    assert prepared.assessment.action is RiskAction.ALLOW
    candidate = prepared.model_dump(mode="json")
    candidate["decision"]["permission"] = permission.value
    return PreparedReplay.model_validate(candidate)


@pytest.mark.parametrize(
    ("permission", "expected_action"),
    [
        (Permission.REJECT, RiskAction.REJECT),
        (Permission.WAIT, RiskAction.WAIT),
        (Permission.SIGNAL_ONLY, RiskAction.REJECT),
    ],
)
def test_nonapprove_permission_commits_terminal_verdict_without_mutating_assessment(
    pipeline: LiveFlowPipeline,
    replay_data: dict[str, object],
    permission: Permission,
    expected_action: RiskAction,
) -> None:
    prepared = _prepared(pipeline, replay_data, permission)
    original_assessment = prepared.assessment
    assert original_assessment.action is RiskAction.ALLOW

    final, journal = pipeline.block_prepared(prepared)

    assert final is not original_assessment
    assert final.decision_id == prepared.decision.decision_id
    assert final.action is expected_action
    assert final.reason == f"council_permission_{permission.value}"
    assert final.execution_capable is False
    assert final.adjusted_size is None
    assert final.findings == original_assessment.findings
    assert final.halts_engaged == original_assessment.halts_engaged
    assert prepared.assessment is original_assessment
    assert prepared.assessment.action is RiskAction.ALLOW
    assert journal.decision_id == prepared.decision.decision_id
    assert journal.outcome is TradeOutcome.BLOCKED
    assert expected_action.value in journal.post_trade_notes
    assert final.reason in journal.post_trade_notes


def test_blocking_risk_assessment_is_not_weakened_by_council_denial(
    pipeline: LiveFlowPipeline, replay_data: dict[str, object]
) -> None:
    prepared = _prepared(pipeline, replay_data, Permission.WAIT)
    stronger = RiskVerdict(
        decision_id=prepared.decision.decision_id,
        action=RiskAction.HALT_ALL_TRADING,
        reason="global_kill_active",
        halts_engaged=("operator_kill",),
        execution_capable=False,
        findings=(GateFinding.GLOBAL_KILL,),
    )
    candidate = prepared.model_dump(mode="json")
    candidate["assessment"] = stronger.model_dump(mode="json")
    prepared = PreparedReplay.model_validate(candidate)

    final, journal = pipeline.block_prepared(prepared)

    assert final == stronger
    assert final.action is RiskAction.HALT_ALL_TRADING
    assert final.findings == (GateFinding.GLOBAL_KILL,)
    assert journal.outcome is TradeOutcome.BLOCKED
    assert "global_kill_active" in journal.post_trade_notes


def test_reblocking_same_decision_is_stable_and_does_not_change_history(
    pipeline: LiveFlowPipeline, replay_data: dict[str, object]
) -> None:
    prepared = _prepared(pipeline, replay_data, Permission.REJECT)
    before = prepared.assessment.model_dump(mode="json")

    first, first_journal = pipeline.block_prepared(prepared)
    second, second_journal = pipeline.block_prepared(prepared)

    assert first == second
    assert first.decision_id == second.decision_id == prepared.decision.decision_id
    assert first.reason == "council_permission_reject"
    assert first_journal.decision_id == second_journal.decision_id
    assert first_journal.outcome is second_journal.outcome is TradeOutcome.BLOCKED
    assert prepared.assessment.model_dump(mode="json") == before


def test_c101_risk_policy_model_copy_cannot_bypass_policy_validation() -> None:
    policy = load_risk_policy(LOCK_FILE)
    try:
        unsafe_evolution = policy.self_evolution.model_copy(
            update={"triton_can_apply_changes": True}
        )
    except (TypeError, ValueError):
        return

    try:
        copied = policy.model_copy(update={"self_evolution": unsafe_evolution})
    except (TypeError, ValueError):
        return

    assert copied.self_evolution.triton_can_apply_changes is False
