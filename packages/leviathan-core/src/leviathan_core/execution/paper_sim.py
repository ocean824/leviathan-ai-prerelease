"""Paper execution simulator — the replay spine's execution engine.

Simulates a bracket order (entry, stop, target) against a chronological
bar sequence. Conservative fill discipline: when a bar touches both the
stop and the target, the stop is assumed to have filled first. DAY
intents that never resolve exit at the final bar's close.
"""

from decimal import Decimal

from leviathan_core.contracts import assert_intent_is_authorized
from leviathan_core.schemas import (
    Bar,
    Direction,
    ExecutionIntent,
    OrderType,
    RiskSnapshot,
    TradeJournalRecord,
    TradeOutcome,
    new_id,
)


class PaperExecutionEngine:
    def __init__(self, slippage: Decimal = Decimal("0.25")) -> None:
        self._slippage = slippage

    def simulate(
        self,
        intent: ExecutionIntent,
        direction: Direction,
        entry_price: Decimal,
        bars: tuple[Bar, ...],
        risk: RiskSnapshot,
        setup_id: str,
    ) -> TradeJournalRecord:
        assert_intent_is_authorized(intent, risk)
        if direction is Direction.FLAT:
            raise ValueError("cannot simulate a flat trade")
        if not bars:
            raise ValueError("paper simulation requires at least one bar")

        entry = self._fill_entry(intent, direction, entry_price, bars)
        if entry is None:
            return TradeJournalRecord(
                trade_id=new_id("trade"),
                setup_id=setup_id,
                decision_id=intent.decision_id,
                outcome=TradeOutcome.BLOCKED,
                post_trade_notes="limit order never filled within replay window",
            )
        fill_price, fill_index = entry

        is_long = direction is Direction.LONG
        exit_price = bars[-1].close
        best = worst = fill_price
        exit_note = "day_close_exit"

        for bar in bars[fill_index:]:
            if is_long:
                worst = min(worst, bar.low)
                best = max(best, bar.high)
                if bar.low <= intent.stop_loss:
                    exit_price, exit_note = intent.stop_loss, "stop_hit"
                    break
                if bar.high >= intent.take_profit:
                    exit_price, exit_note = intent.take_profit, "target_hit"
                    break
            else:
                worst = max(worst, bar.high)
                best = min(best, bar.low)
                if bar.high >= intent.stop_loss:
                    exit_price, exit_note = intent.stop_loss, "stop_hit"
                    break
                if bar.low <= intent.take_profit:
                    exit_price, exit_note = intent.take_profit, "target_hit"
                    break

        pnl = (exit_price - fill_price) if is_long else (fill_price - exit_price)
        mae = (worst - fill_price) if is_long else (fill_price - worst)
        mfe = (best - fill_price) if is_long else (fill_price - best)

        outcome = (
            TradeOutcome.WIN if pnl > 0 else TradeOutcome.LOSS if pnl < 0 else TradeOutcome.SCRATCH
        )
        return TradeJournalRecord(
            trade_id=new_id("trade"),
            setup_id=setup_id,
            decision_id=intent.decision_id,
            entry=fill_price,
            exit=exit_price,
            mae=mae,
            mfe=mfe,
            outcome=outcome,
            post_trade_notes=f"paper_sim {exit_note} pnl={pnl}",
        )

    def _fill_entry(
        self,
        intent: ExecutionIntent,
        direction: Direction,
        entry_price: Decimal,
        bars: tuple[Bar, ...],
    ) -> tuple[Decimal, int] | None:
        if intent.order_type is OrderType.MARKET:
            slip = self._slippage if direction is Direction.LONG else -self._slippage
            return bars[0].open + slip, 0
        # LIMIT / STOP: fill when a bar trades through the entry price.
        for i, bar in enumerate(bars):
            if bar.low <= entry_price <= bar.high:
                return entry_price, i
        return None
