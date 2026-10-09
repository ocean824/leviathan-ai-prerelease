from __future__ import annotations

import ast
from dataclasses import fields
from decimal import Decimal, localcontext
from pathlib import Path

import pytest
import yaml

from leviathan_core.strategy_ingest.library.asset_recovery.hftcode.signals import (
    HftCodeAction,
    HftCodeBarV1,
    HftCodeError,
    HftCodePositionV1,
    HftCodeReason,
    HftCodeSignalV1,
    HftCodeStrategyId,
    evaluate_hftcode_signal,
)

_SIGNALS_PATH = (
    Path(__file__).parents[2]
    / "src"
    / "leviathan_core"
    / "strategy_ingest"
    / "library"
    / "asset_recovery"
    / "hftcode"
    / "signals.py"
)


def _bars(closes: list[str], *, start: int = 1) -> tuple[HftCodeBarV1, ...]:
    return tuple(
        HftCodeBarV1(timestamp_ns=start + index, close=Decimal(close))
        for index, close in enumerate(closes)
    )


def test_sma_strategies_emit_only_long_entry_on_closed_bar_golden_cross() -> None:
    bars = _bars(["100"] * 50 + ["101"])
    for strategy_id, expected_instrument in (
        (HftCodeStrategyId.BHP_ASX_SMA_10_50, "BHP.ASX"),
        (HftCodeStrategyId.NVDA_US_SMA_10_50, "NVDA.US"),
    ):
        signal = evaluate_hftcode_signal(strategy_id, bars)
        assert signal.action is HftCodeAction.ENTER_LONG
        assert signal.reason is HftCodeReason.GOLDEN_CROSS
        assert signal.instrument_id == expected_instrument
        assert signal.timestamp_ns == 51
        assert dict(signal.indicators) == {
            "fast_sma_10": Decimal("100.1"),
            "slow_sma_50": Decimal("100.02"),
        }
        assert len(signal.source_sha256) == 64


def test_sma_death_cross_and_position_risk_thresholds_are_exit_only() -> None:
    above_then_down = _bars(["99"] * 40 + ["101"] * 10 + ["70"])
    signal = evaluate_hftcode_signal(
        HftCodeStrategyId.BHP_ASX_SMA_10_50,
        above_then_down,
        HftCodePositionV1("LONG", Decimal("100")),
    )
    assert (signal.action, signal.reason) == (HftCodeAction.EXIT, HftCodeReason.DEATH_CROSS)

    still_above = _bars(["99"] * 40 + ["101"] * 11)
    stop = evaluate_hftcode_signal(
        HftCodeStrategyId.NVDA_US_SMA_10_50,
        still_above,
        HftCodePositionV1("LONG", Decimal("105")),
    )
    target = evaluate_hftcode_signal(
        HftCodeStrategyId.NVDA_US_SMA_10_50,
        still_above,
        HftCodePositionV1("LONG", Decimal("95")),
    )
    assert (stop.action, stop.reason) == (HftCodeAction.EXIT, HftCodeReason.STOP_LOSS)
    assert (target.action, target.reason) == (HftCodeAction.EXIT, HftCodeReason.PROFIT_TARGET)


def test_sma_requires_previous_closed_state_and_rejects_short_position() -> None:
    warmup = evaluate_hftcode_signal(
        HftCodeStrategyId.BHP_ASX_SMA_10_50,
        _bars(["100"] * 50),
    )
    assert (warmup.action, warmup.reason) == (
        HftCodeAction.HOLD,
        HftCodeReason.INSUFFICIENT_HISTORY,
    )
    with pytest.raises(HftCodeError) as error:
        evaluate_hftcode_signal(
            HftCodeStrategyId.BHP_ASX_SMA_10_50,
            _bars(["100"] * 51),
            HftCodePositionV1("SHORT", Decimal("100")),
        )
    assert error.value.code == "INVALID_INPUT"


def test_rsi14_simple_window_thresholds_and_exit_reasons() -> None:
    falling = _bars([str(value) for value in range(115, 100, -1)])
    rising = _bars([str(value) for value in range(100, 115)])
    long_entry = evaluate_hftcode_signal(HftCodeStrategyId.EURUSD_RSI14, falling)
    short_entry = evaluate_hftcode_signal(HftCodeStrategyId.EURUSD_RSI14, rising)
    assert (long_entry.action, long_entry.reason) == (
        HftCodeAction.ENTER_LONG,
        HftCodeReason.RSI_OVERSOLD,
    )
    assert dict(long_entry.indicators)["rsi_14"] == Decimal(0)
    assert (short_entry.action, short_entry.reason) == (
        HftCodeAction.ENTER_SHORT,
        HftCodeReason.RSI_OVERBOUGHT,
    )
    long_neutral_exit = evaluate_hftcode_signal(
        HftCodeStrategyId.EURUSD_RSI14,
        rising,
        HftCodePositionV1("LONG", Decimal("1.0000")),
    )
    assert (long_neutral_exit.action, long_neutral_exit.reason) == (
        HftCodeAction.EXIT,
        HftCodeReason.RSI_NEUTRAL_EXIT,
    )


def test_rsi14_uses_fixed_pip_risk_thresholds() -> None:
    flat = _bars(["1.0000"] * 14 + ["0.9950"])
    stopped = evaluate_hftcode_signal(
        HftCodeStrategyId.EURUSD_RSI14,
        flat,
        HftCodePositionV1("LONG", Decimal("1.0000")),
    )
    assert (stopped.action, stopped.reason) == (HftCodeAction.EXIT, HftCodeReason.STOP_LOSS)

    target_bars = _bars(["1.0000"] * 14 + ["1.0100"])
    target = evaluate_hftcode_signal(
        HftCodeStrategyId.EURUSD_RSI14,
        target_bars,
        HftCodePositionV1("SHORT", Decimal("1.0200")),
    )
    assert (target.action, target.reason) == (HftCodeAction.EXIT, HftCodeReason.PROFIT_TARGET)


def test_bollinger20_population_bands_breakout_and_middle_exit() -> None:
    high_breakout = _bars(["100"] * 19 + ["130"])
    long_signal = evaluate_hftcode_signal(HftCodeStrategyId.XAUUSD_BOLLINGER20, high_breakout)
    assert (long_signal.action, long_signal.reason) == (
        HftCodeAction.ENTER_LONG,
        HftCodeReason.UPPER_BAND_BREAKOUT,
    )
    assert dict(long_signal.indicators)["middle_band"] == Decimal("101.5")

    low_breakout = _bars(["100"] * 19 + ["70"])
    short_signal = evaluate_hftcode_signal(HftCodeStrategyId.XAUUSD_BOLLINGER20, low_breakout)
    assert (short_signal.action, short_signal.reason) == (
        HftCodeAction.ENTER_SHORT,
        HftCodeReason.LOWER_BAND_BREAKOUT,
    )
    middle_exit = evaluate_hftcode_signal(
        HftCodeStrategyId.XAUUSD_BOLLINGER20,
        _bars(["100"] * 20),
        HftCodePositionV1("LONG", Decimal("90")),
    )
    assert (middle_exit.action, middle_exit.reason) == (
        HftCodeAction.EXIT,
        HftCodeReason.MIDDLE_BAND_REVERSION,
    )


def test_signal_is_data_only_no_order_or_fill_authority() -> None:
    signal = evaluate_hftcode_signal(
        HftCodeStrategyId.XAUUSD_BOLLINGER20,
        _bars(["100"] * 20),
    )
    names = {field.name for field in fields(HftCodeSignalV1)}
    assert names == {
        "strategy_id",
        "instrument_id",
        "action",
        "reason",
        "timestamp_ns",
        "reference_price",
        "indicators",
        "source_sha256",
    }
    assert not {"order_id", "fill_id", "filled_quantity", "broker"} & names
    assert signal.action is HftCodeAction.HOLD


def test_specs_pin_the_exact_reviewed_source_member_hashes() -> None:
    specs_path = _SIGNALS_PATH.with_name("specs.yaml")
    specs = yaml.safe_load(specs_path.read_text(encoding="utf-8"))
    assert specs["source_archive"]["sha256"] == (
        "1f4ebed80a4e9bdf18892aaa2058139bd10d4fbde4d7355e1e78f2392843d82a"
    )
    source_hashes = {item["strategy_id"]: item["source_sha256"] for item in specs["strategies"]}
    for strategy_id, expected in (
        (
            HftCodeStrategyId.BHP_ASX_SMA_10_50,
            "3105e06ae981f43f3556c63b111952c9d8c6ea0d5ba8cafee03cf8519f858231",
        ),
        (
            HftCodeStrategyId.NVDA_US_SMA_10_50,
            "8ea97df7aa579d11a88582a74df15dbbf9dd9d85b69223bf8d6a5a4882868db6",
        ),
        (
            HftCodeStrategyId.EURUSD_RSI14,
            "838a76eea3fde4a55090c9f11901ac16ec9e75aef839c4542f7bc19e4affd62c",
        ),
        (
            HftCodeStrategyId.XAUUSD_BOLLINGER20,
            "fa7887400605e4010cfb80ef06ce2ea39de606d42beae4ff0a2e1bfade66ee2f",
        ),
    ):
        assert source_hashes[strategy_id.value] == expected
        signal = evaluate_hftcode_signal(strategy_id, _bars(["100"] * 20))
        assert signal.source_sha256 == expected


def test_inputs_are_bounded_ordered_and_exact_decimal() -> None:
    with pytest.raises(HftCodeError) as error:
        evaluate_hftcode_signal(
            HftCodeStrategyId.XAUUSD_BOLLINGER20,
            (HftCodeBarV1(1, Decimal("10")), HftCodeBarV1(1, Decimal("11"))),
        )
    assert error.value.code == "INVALID_INPUT"
    with pytest.raises(HftCodeError) as error:
        HftCodeBarV1(1, Decimal("NaN"))
    assert error.value.code == "INVALID_INPUT"
    with pytest.raises(HftCodeError) as error:
        HftCodeBarV1(1, 10.0)  # type: ignore[arg-type]
    assert error.value.code == "INVALID_INPUT"
    too_many = tuple(HftCodeBarV1(i, Decimal("1")) for i in range(1, 10_002))
    with pytest.raises(HftCodeError) as error:
        evaluate_hftcode_signal(HftCodeStrategyId.EURUSD_RSI14, too_many)
    assert error.value.code == "INVALID_INPUT"


def test_decimal_results_are_independent_of_callers_global_context() -> None:
    bars = _bars(["100"] * 50 + ["101"])
    baseline = evaluate_hftcode_signal(HftCodeStrategyId.BHP_ASX_SMA_10_50, bars)
    with localcontext() as context:
        context.prec = 6
        changed_context = evaluate_hftcode_signal(HftCodeStrategyId.BHP_ASX_SMA_10_50, bars)
    assert changed_context == baseline


def test_module_has_no_broker_or_order_submission_surface() -> None:
    tree = ast.parse(_SIGNALS_PATH.read_text(encoding="utf-8"))
    imported = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imported.update(
        node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
    )
    assert not any("broker" in name or "execution" in name for name in imported)
    assert not any(
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name in {"on_start", "place_order", "submit_order", "cancel_order"}
        for node in ast.walk(tree)
    )
