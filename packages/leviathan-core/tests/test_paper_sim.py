"""Paper simulator: fills, brackets, conservative same-bar rule, MAE/MFE."""

from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest

from leviathan_core.execution.paper_sim import PaperExecutionEngine
from leviathan_core.schemas import (
    Bar,
    BrokerPath,
    Direction,
    ExecutionIntent,
    OrderType,
    RiskSnapshot,
    TimeInForce,
    TradeOutcome,
)


def _bar(i: int, o: str, h: str, lo: str, c: str) -> Bar:
    return Bar(
        instrument="NQ",
        timestamp=datetime(2026, 4, 15, 14, 35, tzinfo=UTC) + timedelta(minutes=i),
        open=Decimal(o),
        high=Decimal(h),
        low=Decimal(lo),
        close=Decimal(c),
    )


def _risk(session: str = "sess_1") -> RiskSnapshot:
    return RiskSnapshot(
        session_id=session,
        max_daily_drawdown_pct=Decimal(3),
        max_position_size=Decimal(1),
        allowed_instruments=("NQ",),
        frozen_at=datetime(2026, 4, 15, 14, 34, tzinfo=UTC),
    )


def _intent(order_type: OrderType = OrderType.MARKET) -> ExecutionIntent:
    return ExecutionIntent(
        decision_id="dec_x",
        risk_session_id="sess_1",
        broker_path=BrokerPath.PAPER_SIM,
        order_type=order_type,
        size=Decimal(1),
        stop_loss=Decimal(18240),
        take_profit=Decimal(18270),
        time_in_force=TimeInForce.DAY,
    )


def test_long_target_hit_is_a_win() -> None:
    bars = (
        _bar(0, "18250", "18255", "18248", "18252"),
        _bar(1, "18252", "18275", "18250", "18272"),
    )
    rec = PaperExecutionEngine(slippage=Decimal(0)).simulate(
        _intent(), Direction.LONG, Decimal(18250), bars, _risk(), "setup_x"
    )
    assert rec.outcome is TradeOutcome.WIN
    assert rec.exit == Decimal(18270)
    assert rec.mfe is not None and rec.mfe >= Decimal(20)


def test_long_stop_hit_is_a_loss() -> None:
    bars = (_bar(0, "18250", "18252", "18235", "18238"),)
    rec = PaperExecutionEngine(slippage=Decimal(0)).simulate(
        _intent(), Direction.LONG, Decimal(18250), bars, _risk(), "setup_x"
    )
    assert rec.outcome is TradeOutcome.LOSS
    assert rec.exit == Decimal(18240)


def test_same_bar_touch_both_stop_wins() -> None:
    bars = (_bar(0, "18250", "18280", "18230", "18260"),)
    rec = PaperExecutionEngine(slippage=Decimal(0)).simulate(
        _intent(), Direction.LONG, Decimal(18250), bars, _risk(), "setup_x"
    )
    assert rec.outcome is TradeOutcome.LOSS
    assert rec.exit == Decimal(18240)


def test_unfilled_limit_is_journaled_blocked() -> None:
    bars = (_bar(0, "18260", "18265", "18258", "18262"),)
    rec = PaperExecutionEngine().simulate(
        _intent(OrderType.LIMIT), Direction.LONG, Decimal(18200), bars, _risk(), "setup_x"
    )
    assert rec.outcome is TradeOutcome.BLOCKED
    assert rec.entry is None


def test_market_fill_applies_slippage() -> None:
    bars = (_bar(0, "18250", "18275", "18248", "18272"),)
    rec = PaperExecutionEngine(slippage=Decimal("0.5")).simulate(
        _intent(), Direction.LONG, Decimal(18250), bars, _risk(), "setup_x"
    )
    assert rec.entry == Decimal("18250.5")


def test_foreign_risk_session_is_refused() -> None:
    from leviathan_core.contracts import ContractViolationError

    bars = (_bar(0, "18250", "18275", "18248", "18272"),)
    with pytest.raises(ContractViolationError):
        PaperExecutionEngine().simulate(
            _intent(), Direction.LONG, Decimal(18250), bars, _risk("other_session"), "setup_x"
        )
