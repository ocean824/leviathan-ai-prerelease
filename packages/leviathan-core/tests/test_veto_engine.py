"""Sovereign veto engine: priority order, named reasons, audit-first."""

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path

import pytest

from leviathan_core.risk import HaltAuthority, RiskAuditLog, VetoEngine, load_risk_policy
from leviathan_core.schemas import (
    AccountState,
    DecisionPacket,
    Direction,
    EconomicEvent,
    OpenPosition,
    Permission,
    RiskAction,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
LOCK_FILE = REPO_ROOT / "infra" / "risk" / "risk_governance.lock.yaml"
AT = datetime(2026, 4, 15, 14, 35, tzinfo=UTC)


def _decision() -> DecisionPacket:
    return DecisionPacket(
        decision_id="dec_test01",
        setup_id="setup_test01",
        permission=Permission.APPROVE,
        direction=Direction.LONG,
        confidence=0.8,
        entry_style="breakout",
        scaling_allowed=False,
        justification="test",
    )


def _account(**overrides: object) -> AccountState:
    base: dict = {
        "equity": Decimal(100000),
        "daily_pnl_pct": Decimal("0"),
        "weekly_pnl_pct": Decimal("0"),
        "trailing_dd_pct": Decimal("0"),
        "consecutive_losses": 0,
        "open_positions": (),
    }
    base.update(overrides)
    return AccountState(**base)


@pytest.fixture
def engine(tmp_path: Path) -> VetoEngine:
    return VetoEngine(
        policy=load_risk_policy(LOCK_FILE),
        halt_authority=HaltAuthority(),
        audit_log=RiskAuditLog(tmp_path / "risk_audit.jsonl"),
    )


def test_policy_loads_real_lock_file() -> None:
    policy = load_risk_policy(LOCK_FILE)
    assert policy.schema_id == "leviathan.tiamat.risk.v1"
    assert policy.drawdown.max_daily_pct == Decimal("3.0")
    assert policy.instrument_limits.for_instrument("NQ").max_position_units == Decimal(3)
    assert policy.self_evolution.triton_can_apply_changes is False


def test_clean_account_is_allowed(engine: VetoEngine) -> None:
    v = engine.assess(_decision(), _account(), "NQ", Decimal(1), AT)
    assert v.action is RiskAction.ALLOW
    assert v.reason == "within_all_sovereign_limits"


def test_daily_drawdown_halts_everything(engine: VetoEngine) -> None:
    v = engine.assess(
        _decision(), _account(daily_pnl_pct=Decimal("-3.5")), "NQ", Decimal(1), AT
    )
    assert v.action is RiskAction.HALT_ALL_TRADING
    assert v.reason == "daily_drawdown_breach"
    # Halt persists: even a clean account is now refused.
    v2 = engine.assess(_decision(), _account(), "NQ", Decimal(1), AT)
    assert v2.action is RiskAction.HALT_ALL_TRADING
    assert "daily_drawdown_breach" in v2.reason


def test_news_embargo_forces_wait(engine: VetoEngine) -> None:
    cpi = EconomicEvent(name="CPI", scheduled_at=AT + timedelta(minutes=10), tier=1)
    v = engine.assess(_decision(), _account(), "NQ", Decimal(1), AT, upcoming_events=(cpi,))
    assert v.action is RiskAction.WAIT
    assert v.reason == "news_embargo:CPI"


def test_loss_streak_cuts_size_50pct(engine: VetoEngine) -> None:
    v = engine.assess(_decision(), _account(consecutive_losses=3), "NQ", Decimal(2), AT)
    assert v.action is RiskAction.REDUCE_SIZE
    assert v.reason == "loss_streak_throttle"
    assert v.adjusted_size == Decimal(1)


def test_instrument_unit_cap_resizes(engine: VetoEngine) -> None:
    v = engine.assess(_decision(), _account(), "NQ", Decimal(10), AT)
    assert v.action is RiskAction.REDUCE_SIZE
    assert v.reason == "instrument_unit_cap"
    assert v.adjusted_size == Decimal(3)


def test_portfolio_heat_cap_rejects(engine: VetoEngine) -> None:
    hot = tuple(
        OpenPosition(
            instrument=f"SYM{i}",
            direction=Direction.LONG,
            size=Decimal(1),
            entry_price=Decimal(100),
            risk_pct=Decimal("2.5"),
        )
        for i in range(2)
    )
    v = engine.assess(_decision(), _account(open_positions=hot), "NQ", Decimal(1), AT)
    assert v.action is RiskAction.REJECT
    assert v.reason == "portfolio_heat_cap"


def test_max_open_positions_per_symbol(engine: VetoEngine) -> None:
    existing = (
        OpenPosition(
            instrument="NQ",
            direction=Direction.LONG,
            size=Decimal(1),
            entry_price=Decimal(18000),
            risk_pct=Decimal("0.5"),
        ),
    )
    v = engine.assess(_decision(), _account(open_positions=existing), "NQ", Decimal(1), AT)
    assert v.action is RiskAction.REJECT
    assert v.reason == "max_open_positions_reached:NQ"


def test_every_verdict_is_audited(tmp_path: Path) -> None:
    audit = RiskAuditLog(tmp_path / "audit.jsonl")
    engine = VetoEngine(
        policy=load_risk_policy(LOCK_FILE), halt_authority=HaltAuthority(), audit_log=audit
    )
    engine.assess(_decision(), _account(), "NQ", Decimal(1), AT)
    engine.assess(_decision(), _account(daily_pnl_pct=Decimal("-4")), "NQ", Decimal(1), AT)
    entries = audit.entries()
    assert len(entries) == 2
    assert entries[0]["action"] == "allow"
    assert entries[1]["action"] == "halt_all_trading"
    assert all(e["reason"] for e in entries)


def test_lock_tamper_engages_halt(tmp_path: Path) -> None:
    halts = HaltAuthority()
    engine = VetoEngine(
        policy=load_risk_policy(LOCK_FILE),
        halt_authority=halts,
        audit_log=RiskAuditLog(tmp_path / "audit.jsonl"),
        lock_path=LOCK_FILE,
        expected_lock_sha256="0" * 64,
    )
    v = engine.assess(_decision(), _account(), "NQ", Decimal(1), AT)
    assert v.action is RiskAction.HALT_ALL_TRADING
    assert v.reason.startswith("lock_verification_failed")
    assert halts.halted
