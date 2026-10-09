from datetime import datetime
from decimal import Decimal

import pytest

from leviathan_core.strategy_ingest.library.asset_recovery.ai_trading_floor import backtest_adapter
from leviathan_core.strategy_ingest.library.asset_recovery.ai_trading_floor.backtest_adapter import (  # noqa: E501
    AIFloorReplayPolicyV1,
    eastern_naive_to_utc_ns,
    lag_portfolio_weights,
    replay_signals,
    replay_strategy,
)
from leviathan_core.strategy_ingest.library.asset_recovery.ai_trading_floor.strategies import (
    AIFloorOHLCVBarV1,
    AIFloorPortError,
    AIFloorSignalV1,
    AIFloorStrategySpecV1,
    evaluate_signals,
)


def _bar(t: int, o: str, h: str, low: str, c: str) -> AIFloorOHLCVBarV1:
    return AIFloorOHLCVBarV1(t, Decimal(o), Decimal(h), Decimal(low), Decimal(c), Decimal("10"))


def test_breakout_signal_is_filled_at_next_bar_open() -> None:
    bars = (
        _bar(1, "10", "10", "9", "10"),
        _bar(2, "11", "12", "10", "12"),
        _bar(3, "13", "14", "12", "13"),
    )
    spec = AIFloorStrategySpecV1("breakout", (("lookback", 1),))
    signals = evaluate_signals(bars, spec)
    assert signals[1].position == "LONG"
    result = replay_strategy(bars, spec, AIFloorReplayPolicyV1("USD", 2, Decimal("1000"), 0, 0))
    assert result.trades[0].entry_ns == 3
    assert result.trades[0].entry_price == Decimal("13")


def test_eastern_time_rejects_ambiguous_and_nonexistent_dst_times() -> None:
    assert eastern_naive_to_utc_ns(datetime(2024, 1, 2, 9, 30)) > 0
    with pytest.raises(AIFloorPortError) as ambiguous:
        eastern_naive_to_utc_ns(datetime(2024, 11, 3, 1, 30))
    assert ambiguous.value.code == "TIMESTAMP_AMBIGUOUS"
    with pytest.raises(AIFloorPortError):
        eastern_naive_to_utc_ns(datetime(2024, 3, 10, 2, 30))


def test_portfolio_weights_are_lagged_one_observation() -> None:
    times = (1, 2, 3)
    weights = (
        (Decimal("0.8"), Decimal("0.2")),
        (Decimal("0.5"), Decimal("0.5")),
        (Decimal("0.1"), Decimal("0.9")),
    )
    assert lag_portfolio_weights(times, weights) == (
        (Decimal(0), Decimal(0)),
        weights[0],
        weights[1],
    )


def test_signal_inputs_reject_boolean_integer_parameter() -> None:
    with pytest.raises(AIFloorPortError):
        AIFloorStrategySpecV1("breakout", (("lookback", True),))


def test_same_bar_stop_and_target_resolves_adversely(monkeypatch: pytest.MonkeyPatch) -> None:
    bars = (_bar(1, "10", "10", "9", "10"), _bar(2, "10", "13", "7", "10"))
    signals = (
        AIFloorSignalV1(1, "LONG", Decimal("8"), Decimal("12")),
        AIFloorSignalV1(2, "FLAT"),
    )
    monkeypatch.setattr(backtest_adapter, "evaluate_signals", lambda _bars, _spec: signals)
    result = replay_strategy(
        bars,
        AIFloorStrategySpecV1("breakout", (("lookback", 1),)),
        AIFloorReplayPolicyV1("USD", 2, Decimal("1000"), 0, 0),
    )
    assert result.trades[0].ambiguous_stop is True
    assert result.trades[0].exit_price == Decimal("8")


def test_public_signal_replay_rejects_misaligned_evidence() -> None:
    bars = (_bar(1, "10", "10", "9", "10"), _bar(2, "10", "13", "7", "10"))
    policy = AIFloorReplayPolicyV1("USD", 2, Decimal("1000"), 0, 0)
    with pytest.raises(AIFloorPortError) as error:
        replay_signals(bars, (AIFloorSignalV1(9, "LONG"), AIFloorSignalV1(2, "FLAT")), policy)
    assert error.value.code == "SIGNAL_SERIES_INVALID"


def test_public_signal_replay_resolves_same_bar_stop_and_target() -> None:
    bars = (_bar(1, "10", "10", "9", "10"), _bar(2, "10", "13", "7", "10"))
    signals = (
        AIFloorSignalV1(1, "LONG", Decimal("8"), Decimal("12")),
        AIFloorSignalV1(2, "FLAT"),
    )
    result = replay_signals(bars, signals, AIFloorReplayPolicyV1("USD", 2, Decimal("1000"), 0, 0))
    assert result.trades[0].ambiguous_stop is True
    assert result.trades[0].exit_price == Decimal("8")
