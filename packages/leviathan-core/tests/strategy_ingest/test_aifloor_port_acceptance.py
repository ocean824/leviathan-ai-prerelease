from datetime import UTC, datetime
from decimal import Decimal

import pytest

from leviathan_core.strategy_ingest.library.asset_recovery.ai_trading_floor import backtest_adapter
from leviathan_core.strategy_ingest.library.asset_recovery.ai_trading_floor.strategies import (
    STRATEGY_IDS,
    AIFloorOHLCVBarV1,
    AIFloorSignalV1,
    AIFloorStrategySpecV1,
    evaluate_signals,
)


def _bar(
    i: int,
    close: int,
    *,
    open_: int | None = None,
    high: int | None = None,
    low: int | None = None,
) -> AIFloorOHLCVBarV1:
    o = close if open_ is None else open_
    h = max(o, close) + 1 if high is None else high
    low_value = min(o, close) - 1 if low is None else low
    return AIFloorOHLCVBarV1(
        i, Decimal(o), Decimal(h), Decimal(low_value), Decimal(close), Decimal(10)
    )


def _utc_ns(value: datetime) -> int:
    delta = value - datetime(1970, 1, 1, tzinfo=UTC)
    return (delta.days * 86400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1000


def test_port_exposes_only_the_closed_source_strategy_set() -> None:
    assert set(STRATEGY_IDS) == {
        "anchored_vwap_trend",
        "bollinger_meanrev",
        "breakout",
        "donchian_trend",
        "dual_momentum",
        "rsi_reversion",
        "short_breakdown",
        "short_trend",
        "sma_crossover",
        "vol_gate_trend",
    }


def test_sma_breakout_and_short_breakdown_match_sanitized_source_formulas() -> None:
    rising = tuple(_bar(i + 1, close) for i, close in enumerate((10, 11, 12, 13)))
    sma = evaluate_signals(
        rising, AIFloorStrategySpecV1("sma_crossover", (("fast", 2), ("slow", 3)))
    )
    assert tuple(signal.position for signal in sma) == ("FLAT", "FLAT", "LONG", "LONG")

    breakout_bars = (
        _bar(1, 10, high=10, low=9),
        _bar(2, 12, high=13, low=10),
        _bar(3, 13, high=13, low=12),
    )
    breakout = evaluate_signals(
        breakout_bars, AIFloorStrategySpecV1("breakout", (("lookback", 1),))
    )
    assert breakout[0].position == "FLAT"
    assert breakout[1].position == "LONG"  # compares against the prior high, not its own high
    assert breakout[2].position == "FLAT"  # equality is not a breakout.

    breakdown_bars = (_bar(1, 10, high=11, low=9), _bar(2, 8, high=9, low=7))
    breakdown = evaluate_signals(
        breakdown_bars, AIFloorStrategySpecV1("short_breakdown", (("lookback", 1),))
    )
    assert tuple(signal.position for signal in breakdown) == ("FLAT", "SHORT")


def test_rsi_bollinger_and_anchored_vwap_parity_fixtures() -> None:
    falling = tuple(_bar(i + 1, close) for i, close in enumerate((10, 9, 8)))
    rsi = evaluate_signals(
        falling,
        AIFloorStrategySpecV1(
            "rsi_reversion", (("rsi_period", 2), ("buy_rsi", 30), ("sell_rsi", 55))
        ),
    )
    assert rsi[-1].position == "LONG"  # RSI is below the source entry threshold.

    bb_closes = (10,) * 19 + (8,)
    bb_bars = tuple(_bar(i + 1, close) for i, close in enumerate(bb_closes))
    bollinger = evaluate_signals(
        bb_bars,
        AIFloorStrategySpecV1("bollinger_meanrev", (("band_period", 20), ("rsi_period", 14))),
    )
    assert bollinger[-1].position == "LONG"
    assert bollinger[-1].stop_price is not None

    pivot_bars = (
        _bar(1, 10, high=11, low=10),
        _bar(2, 10, high=10, low=9),
        _bar(3, 14, high=14, low=11),
    )
    anchored = evaluate_signals(
        pivot_bars, AIFloorStrategySpecV1("anchored_vwap_trend", (("pivot_lookback", 1),))
    )
    assert anchored[-1].position == "LONG"  # pivot is usable only after right-side confirmation.


def test_long_warmup_strategies_match_source_direction_and_are_deterministic() -> None:
    rising = tuple(_bar(i + 1, i + 11) for i in range(273))
    falling = tuple(_bar(i + 1, 210 - i) for i in range(200))
    cases = (
        ("dual_momentum", rising, (), "LONG"),
        ("vol_gate_trend", rising, (("max_vol", Decimal("0.2")),), "LONG"),
        ("short_trend", falling, (), "SHORT"),
    )
    for strategy_id, bars, parameters, expected in cases:
        spec = AIFloorStrategySpecV1(strategy_id, parameters)
        first = evaluate_signals(bars, spec)
        second = evaluate_signals(bars, spec)
        assert first == second
        assert first[-1].position == expected

    donchian_bars = (
        *(_bar(i + 1, 100) for i in range(2)),
        _bar(3, 103, open_=100, high=104, low=99),
    )
    donchian = evaluate_signals(
        donchian_bars,
        AIFloorStrategySpecV1("donchian_trend", (("entry_lookback", 2), ("exit_lookback", 1))),
    )
    assert donchian[-1].position == "LONG"
    assert donchian[-1].stop_price is not None


def test_replay_fills_only_next_bar_and_applies_both_costs() -> None:
    bars = (
        _bar(1, 10, open_=10, high=10, low=9),
        _bar(2, 12, open_=10, high=12, low=9),  # signal at T
        _bar(3, 14, open_=13, high=15, low=12),  # first eligible fill, at T+1
        _bar(4, 12, open_=14, high=15, low=11),
        _bar(5, 12, open_=14, high=15, low=11),  # exit after the signal turns flat
    )
    result = backtest_adapter.replay_strategy(
        bars,
        AIFloorStrategySpecV1("breakout", (("lookback", 1),)),
        backtest_adapter.AIFloorReplayPolicyV1("USD", 2, Decimal("1000"), 100, 100),
    )
    trade = result.trades[0]
    assert trade.entry_ns == 3 and trade.exit_ns == 5
    assert trade.entry_price == Decimal("13.13")
    assert trade.exit_price == Decimal("13.86")
    assert trade.fees == Decimal("0.27")
    assert trade.net_pnl == Decimal("0.46")
    assert trade.entry_ns != bars[1].timestamp_ns


def test_replay_resolves_entry_bar_stop_at_the_adverse_stop_price() -> None:
    flat = tuple(_bar(i + 1, 100, high=101, low=99) for i in range(55))
    trigger = _bar(56, 103, open_=100, high=104, low=99)
    stop_bar = _bar(57, 99, open_=100, high=101, low=98)
    bars = (*flat, trigger, stop_bar)
    result = backtest_adapter.replay_strategy(
        bars,
        AIFloorStrategySpecV1("donchian_trend", (("entry_lookback", 55), ("exit_lookback", 20))),
        backtest_adapter.AIFloorReplayPolicyV1("USD", 2, Decimal("10000"), 0, 0),
    )
    stopped = next(trade for trade in result.trades if trade.entry_ns == 57)
    assert stopped.exit_ns == 57
    stop_signal = evaluate_signals(
        bars,
        AIFloorStrategySpecV1("donchian_trend", (("entry_lookback", 55), ("exit_lookback", 20))),
    )[55]
    assert stopped.exit_price == stop_signal.stop_price


def test_replay_signals_uses_adverse_stop_when_stop_and_target_hit_same_bar() -> None:
    bars = (
        _bar(1, 100, open_=100, high=101, low=99),
        _bar(2, 100, open_=100, high=101, low=99),
        _bar(3, 100, open_=100, high=101, low=99),
        _bar(4, 100, open_=100, high=111, low=89),
    )
    signals = (
        AIFloorSignalV1(1, "FLAT"),
        AIFloorSignalV1(2, "LONG", Decimal("90"), Decimal("110")),
        AIFloorSignalV1(3, "LONG", Decimal("90"), Decimal("110")),
        AIFloorSignalV1(4, "FLAT"),
    )
    result = backtest_adapter.replay_signals(
        bars, signals, backtest_adapter.AIFloorReplayPolicyV1("USD", 2, Decimal("1000"), 0, 0)
    )
    trade = result.trades[0]
    assert trade.entry_ns == 3 and trade.exit_ns == 4
    assert trade.exit_price == Decimal("90")
    assert trade.ambiguous_stop is True


def test_replay_signals_rejects_misaligned_signal_timestamps() -> None:
    bars = (_bar(1, 100), _bar(2, 101))
    signals = (AIFloorSignalV1(1, "FLAT"), AIFloorSignalV1(99, "LONG"))
    with pytest.raises(ValueError) as error:
        backtest_adapter.replay_signals(
            bars, signals, backtest_adapter.AIFloorReplayPolicyV1("USD", 2, Decimal("1000"), 0, 0)
        )
    assert getattr(error.value, "code", None) == "SIGNAL_SERIES_INVALID"


def test_eastern_naive_mapping_tracks_both_sides_of_spring_dst() -> None:
    before = backtest_adapter.eastern_naive_to_utc_ns(datetime(2024, 3, 10, 1, 30))
    after = backtest_adapter.eastern_naive_to_utc_ns(datetime(2024, 3, 10, 3, 30))
    assert before == _utc_ns(datetime(2024, 3, 10, 6, 30, tzinfo=UTC))
    assert after == _utc_ns(datetime(2024, 3, 10, 7, 30, tzinfo=UTC))
    with pytest.raises(ValueError) as nonexistent:
        backtest_adapter.eastern_naive_to_utc_ns(datetime(2024, 3, 10, 2, 30))
    assert getattr(nonexistent.value, "code", None) == "TIMESTAMP_NONEXISTENT"
    with pytest.raises(ValueError) as ambiguous:
        backtest_adapter.eastern_naive_to_utc_ns(datetime(2024, 11, 3, 1, 30))
    assert getattr(ambiguous.value, "code", None) == "TIMESTAMP_AMBIGUOUS"


def test_portfolio_weights_are_lagged_and_invalid_timestamps_rejected() -> None:
    weights = ((Decimal("0.8"),), (Decimal("0.5"),), (Decimal("0.2"),))
    assert backtest_adapter.lag_portfolio_weights((1, 2, 3), weights) == (
        (Decimal(0),),
        weights[0],
        weights[1],
    )
    with pytest.raises(ValueError):
        backtest_adapter.lag_portfolio_weights((2, 1, 3), weights)
