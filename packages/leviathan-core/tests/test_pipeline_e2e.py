"""End-to-end replay: the module-map handoff standard, executable.

A single fixture enters the pipeline, is classified by session/range/
state, validated by truth, judged by decision and sovereign risk,
simulated by paper execution, and recorded by the journal layer.
"""

import json
import shutil
import threading
from collections.abc import Callable
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
    RiskPolicy,
    RouteGuard,
    VetoEngine,
    load_risk_policy,
)
from leviathan_core.risk.transaction_port import ClaimReceipt
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
    StrategyGenome,
    StreamFreshness,
    TradeOutcome,
    TruthValidationResult,
)
from leviathan_core.truth.provider import StaticTruthProvider

REPO_ROOT = Path(__file__).resolve().parents[3]
LOCK_FILE = REPO_ROOT / "tests" / "fixtures" / "risk_lock" / "risk_governance.lock.yaml"
LOCK_SHA256 = "46a03497679f8a59c82229ba28cef4bf56b7c1d7c30ae936016f876c9eaf3c51"
FIXTURE = Path(__file__).parent / "fixtures" / "replay_nq_breakout.json"


def _bars() -> tuple[Bar, ...]:
    """NY-overlap breakout that retests, then runs to the target."""
    t0 = datetime(2026, 4, 15, 14, 35, tzinfo=UTC)
    ohlc = [
        ("18250", "18258", "18246", "18255"),
        ("18255", "18262", "18248", "18260"),
        ("18260", "18266", "18255", "18264"),
        ("18264", "18272", "18260", "18270"),
    ]
    return tuple(
        Bar(
            instrument="NQ",
            timestamp=t0 + timedelta(minutes=i),
            open=Decimal(o),
            high=Decimal(h),
            low=Decimal(lo),
            close=Decimal(c),
            volume=Decimal(1000),
        )
        for i, (o, h, lo, c) in enumerate(ohlc)
    )


@pytest.fixture
def gate_context() -> RiskGateContext:
    at = _bars()[-1].timestamp
    return RiskGateContext(
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


@pytest.fixture
def replay() -> dict:
    return json.loads(FIXTURE.read_text())


@pytest.fixture
def pipeline(tmp_path: Path, replay: dict) -> LiveFlowPipeline:
    truth = StaticTruthProvider(TruthValidationResult.model_validate(replay["truth_validation"]))
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
        paper_engine=PaperExecutionEngine(slippage=Decimal("0.25")),
        risk_lock_sha256=LOCK_SHA256,
    )


def test_full_replay_approves_and_journals_a_win(
    pipeline: LiveFlowPipeline, replay: dict, gate_context: RiskGateContext
) -> None:
    setup = CandidateSetup.model_validate(replay["candidate_setup"])
    genome = StrategyGenome.model_validate(replay["strategy_genome"])
    account = AccountState(equity=Decimal(100000), daily_pnl_pct=Decimal(0))

    result = pipeline.run_replay(
        setup,
        _bars(),
        account,
        genome=genome,
        requested_size=Decimal("1"),
        stop_loss=Decimal("18240"),
        take_profit=Decimal("18270"),
        context=gate_context,
        fixture_only=True,
    )

    assert result.session.label.value == "ny_overlap"
    assert result.decision.permission is Permission.APPROVE
    assert result.decision.direction.value == "long"
    assert result.verdict.action is RiskAction.ALLOW
    assert result.intent is not None
    assert result.intent.risk_session_id  # frozen snapshot linkage
    assert result.journal_record.outcome is TradeOutcome.WIN
    assert result.journal_record.exit == Decimal("18270")
    assert result.journal_record.mfe is not None and result.journal_record.mfe > 0


@pytest.mark.parametrize(
    "mutation",
    ["context", "snapshot", "bars", "setup", "decision", "assessment", "stop", "target"],
)
def test_claimed_consumption_rejects_changed_candidate_before_simulation(
    pipeline: LiveFlowPipeline,
    replay: dict,
    gate_context: RiskGateContext,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    prepared = pipeline.prepare_replay(
        CandidateSetup.model_validate(replay["candidate_setup"]),
        _bars(),
        AccountState(equity=Decimal(100000), daily_pnl_pct=Decimal(0)),
        genome=StrategyGenome.model_validate(replay["strategy_genome"]),
        requested_size=Decimal("1"),
        stop_loss=Decimal("18240"),
        take_profit=Decimal("18270"),
        context=gate_context,
    )
    assert prepared.actionable and prepared.risk_snapshot is not None
    receipt = ClaimReceipt(
        decision_id=prepared.decision.decision_id,
        token="claim_one",
        version=2,
        policy_digest=LOCK_SHA256,
        candidate_identity=prepared.candidate_identity(LOCK_SHA256),
    )
    changes = {
        "context": {"context": gate_context.model_copy(update={"max_staleness_ms": 1})},
        "snapshot": {
            "risk_snapshot": prepared.risk_snapshot.model_copy(update={"session_id": "other"})
        },
        "bars": {
            "bars": (
                prepared.bars[0].model_copy(update={"open": Decimal("18251")}),
                *prepared.bars[1:],
            )
        },
        "setup": {"setup": prepared.setup.model_copy(update={"signal_features": ("other",)})},
        "decision": {"decision": prepared.decision.model_copy(update={"justification": "other"})},
        "assessment": {"assessment": prepared.assessment.model_copy(update={"reason": "other"})},
        "stop": {"stop_loss": Decimal("1")},
        "target": {"take_profit": Decimal("999999")},
    }
    changed: PreparedReplay = prepared.model_copy(update=changes[mutation])

    def forbidden(*_args: object, **_kwargs: object) -> None:
        pytest.fail("paper simulation ran for a candidate different from the committed claim")

    monkeypatch.setattr(pipeline._paper, "simulate", forbidden)
    with pytest.raises(ValueError, match="claim receipt"):
        pipeline.consume_claimed(changed, receipt)


def test_nondurable_replay_requires_explicit_fixture_mode(
    pipeline: LiveFlowPipeline,
    replay: dict,
    gate_context: RiskGateContext,
) -> None:
    setup = CandidateSetup.model_validate(replay["candidate_setup"])
    with pytest.raises(RuntimeError, match="explicit test fixtures"):
        pipeline.run_replay(
            setup,
            _bars(),
            AccountState(equity=Decimal(100000), daily_pnl_pct=Decimal(0)),
            context=gate_context,
        )


def test_drawdown_breach_blocks_and_still_journals(
    pipeline: LiveFlowPipeline, replay: dict, gate_context: RiskGateContext
) -> None:
    setup = CandidateSetup.model_validate(replay["candidate_setup"])
    wounded = AccountState(equity=Decimal(100000), daily_pnl_pct=Decimal("-3.5"))

    result = pipeline.run_replay(
        setup,
        _bars(),
        wounded,
        requested_size=Decimal("1"),
        context=gate_context,
        fixture_only=True,
    )

    assert result.verdict.action is RiskAction.HALT_ALL_TRADING
    assert result.intent is None
    assert result.journal_record.outcome is TradeOutcome.BLOCKED
    assert "daily_drawdown_breach" in result.journal_record.post_trade_notes


def test_rejected_truth_never_reaches_execution(
    tmp_path: Path, replay: dict, gate_context: RiskGateContext
) -> None:
    rejected = TruthValidationResult.model_validate(
        {**replay["truth_validation"], "truth_status": "rejected", "orderbook_bias": "bearish"}
    )
    pipeline = LiveFlowPipeline(
        truth_provider=StaticTruthProvider(rejected),
        decision_engine=CouncilDecisionEngine(),
        veto_engine=VetoEngine(
            policy=load_risk_policy(LOCK_FILE),
            halt_authority=HaltAuthority(),
            audit_log=RiskAuditLog(tmp_path / "audit.jsonl"),
            route_guard=RouteGuard(LOCK_FILE, LOCK_SHA256),
        ),
        paper_engine=PaperExecutionEngine(),
    )
    setup = CandidateSetup.model_validate(replay["candidate_setup"])
    account = AccountState(equity=Decimal(100000), daily_pnl_pct=Decimal(0))

    result = pipeline.run_replay(setup, _bars(), account, context=gate_context, fixture_only=True)

    assert result.decision.permission is Permission.REJECT
    assert result.intent is None
    assert result.journal_record.outcome is TradeOutcome.BLOCKED


@pytest.mark.parametrize(
    ("bars", "requested_size", "stop_loss", "take_profit", "reason"),
    [
        ((), Decimal(1), None, None, "execution_input_invalid:bars_empty"),
        (_bars(), Decimal(0), None, None, "execution_input_invalid:requested_size"),
        (_bars(), Decimal(1), Decimal(0), None, "execution_input_invalid:stop_loss"),
        (_bars(), Decimal(1), None, Decimal(0), "execution_input_invalid:take_profit"),
    ],
)
def test_invalid_actionable_input_has_final_blocked_audit_and_journal(
    pipeline: LiveFlowPipeline,
    replay: dict,
    gate_context: RiskGateContext,
    tmp_path: Path,
    bars: tuple[Bar, ...],
    requested_size: Decimal,
    stop_loss: Decimal | None,
    take_profit: Decimal | None,
    reason: str,
) -> None:
    setup = CandidateSetup.model_validate(replay["candidate_setup"])
    genome = StrategyGenome.model_validate(replay["strategy_genome"])
    account = AccountState(equity=Decimal(100000), daily_pnl_pct=Decimal(0))

    result = pipeline.run_replay(
        setup,
        bars,
        account,
        genome=genome,
        requested_size=requested_size,
        stop_loss=stop_loss,
        take_profit=take_profit,
        context=gate_context,
        fixture_only=True,
    )

    assert result.decision.permission is Permission.APPROVE
    assert result.intent is None
    assert result.final_verdict.action is RiskAction.REJECT
    assert result.final_verdict.reason == reason
    assert result.journal_record.outcome is TradeOutcome.BLOCKED
    entries = RiskAuditLog(tmp_path / "audit.jsonl").entries()
    assert len(entries) == 1
    assert entries[0]["final"] is False
    assert entries[0]["legacy_final"] is True
    assert entries[0]["reason"] == reason


def _run_core_policy_probe(
    tmp_path: Path,
    replay: dict,
    gate_context: RiskGateContext,
    policy: RiskPolicy,
    lock_path: Path,
    mutate_after_build: Callable[[], None] | None = None,
) -> tuple[RiskAction, bool, tuple[GateFinding, ...]]:
    truth = StaticTruthProvider(TruthValidationResult.model_validate(replay["truth_validation"]))
    guard = RouteGuard(lock_path, LOCK_SHA256)
    assert guard.check(gate_context) == ()
    veto = VetoEngine(
        policy=policy,
        halt_authority=HaltAuthority(),
        audit_log=RiskAuditLog(tmp_path / "core-policy-audit.jsonl"),
        route_guard=guard,
    )
    pipeline = LiveFlowPipeline(
        truth_provider=truth,
        decision_engine=CouncilDecisionEngine(),
        veto_engine=veto,
        paper_engine=PaperExecutionEngine(),
        risk_lock_sha256=LOCK_SHA256,
    )
    if mutate_after_build is not None:
        mutate_after_build()
    setup = CandidateSetup.model_validate(replay["candidate_setup"])
    genome = StrategyGenome.model_validate(replay["strategy_genome"])
    result = pipeline.run_replay(
        setup,
        _bars(),
        AccountState(equity=Decimal(100000), daily_pnl_pct=Decimal(0)),
        genome=genome,
        requested_size=Decimal(5),
        context=gate_context,
        fixture_only=True,
    )
    return result.final_verdict.action, result.intent is not None, result.findings


def test_core_guard_without_caller_digest_rejects_wrong_policy_bytes(
    tmp_path: Path, replay: dict, gate_context: RiskGateContext
) -> None:
    copied_lock = tmp_path / "risk_governance.lock.yaml"
    original = LOCK_FILE.read_bytes()
    changed = original.replace(
        b"NQ:     { max_position_units: 3,",
        b"NQ:     { max_position_units: 10,",
    )
    assert changed != original
    copied_lock.write_bytes(changed)
    wrong_policy = load_risk_policy(copied_lock)
    copied_lock.write_bytes(original)

    action, has_intent, findings = _run_core_policy_probe(
        tmp_path, replay, gate_context, wrong_policy, copied_lock
    )
    assert action is RiskAction.HALT_ALL_TRADING
    assert has_intent is False
    assert GateFinding.LOCK_TAMPERED in findings


def test_core_guard_detects_policy_object_mutated_after_construction(
    tmp_path: Path, replay: dict, gate_context: RiskGateContext
) -> None:
    copied_lock = tmp_path / "risk_governance.lock.yaml"
    shutil.copyfile(LOCK_FILE, copied_lock)
    policy = load_risk_policy(copied_lock)

    def mutate_policy() -> None:
        nq = policy.instrument_limits.overrides["NQ"]
        policy.instrument_limits.overrides["NQ"] = nq.model_copy(
            update={"max_position_units": Decimal(10)}
        )

    action, has_intent, findings = _run_core_policy_probe(
        tmp_path, replay, gate_context, policy, copied_lock, mutate_policy
    )
    assert action is RiskAction.HALT_ALL_TRADING
    assert has_intent is False
    assert GateFinding.LOCK_TAMPERED in findings


def test_halt_linearizes_with_final_paper_consumption(
    pipeline: LiveFlowPipeline,
    replay: dict,
    gate_context: RiskGateContext,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = pipeline.prepare_replay(
        CandidateSetup.model_validate(replay["candidate_setup"]),
        _bars(),
        AccountState(equity=Decimal(100000), daily_pnl_pct=Decimal(0)),
        genome=StrategyGenome.model_validate(replay["strategy_genome"]),
        context=gate_context,
    )
    assert prepared.actionable
    receipt = ClaimReceipt(
        decision_id=prepared.decision.decision_id,
        token="claim_linearization",
        version=2,
        policy_digest=LOCK_SHA256,
        candidate_identity=prepared.candidate_identity(LOCK_SHA256),
    )
    simulating = threading.Event()
    release_simulator = threading.Event()
    halt_committed = threading.Event()
    original_simulate = pipeline._paper.simulate
    calls = 0

    def paused_simulator(*args: object, **kwargs: object):  # type: ignore[no-untyped-def]
        nonlocal calls
        calls += 1
        simulating.set()
        assert release_simulator.wait(timeout=5)
        return original_simulate(*args, **kwargs)

    monkeypatch.setattr(pipeline._paper, "simulate", paused_simulator)
    consumed: list[tuple] = []
    consumer = threading.Thread(
        target=lambda: consumed.append(pipeline.consume_claimed(prepared, receipt))
    )
    consumer.start()
    assert simulating.wait(timeout=5)

    def engage() -> None:
        pipeline._veto.halt_authority.engage("operator_halt")
        halt_committed.set()

    halter = threading.Thread(target=engage)
    halter.start()
    assert not halt_committed.wait(timeout=0.1)
    release_simulator.set()
    consumer.join(timeout=5)
    halter.join(timeout=5)
    assert not consumer.is_alive() and not halter.is_alive()
    assert consumed[0][1] is not None and halt_committed.is_set()
    second = pipeline.consume_claimed(prepared, receipt)
    assert second[1] is None and calls == 1
    assert GateFinding.GLOBAL_KILL in second[0].findings
