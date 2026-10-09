from __future__ import annotations

import ast
from dataclasses import fields
from decimal import Decimal, localcontext
from pathlib import Path

import pytest
import yaml

from leviathan_core.strategy_ingest.library.asset_recovery.hftcode import signals as hftcode_signals
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

_SIGNALS_PATH = Path(hftcode_signals.__file__)
_SPECS_PATH = _SIGNALS_PATH.with_name("specs.yaml")


def _bars(closes: list[str], *, start: int = 1) -> tuple[HftCodeBarV1, ...]:
    return tuple(
        HftCodeBarV1(timestamp_ns=start + index, close=Decimal(close))
        for index, close in enumerate(closes)
    )


def _bars_from_changes(changes: list[str], *, start: str = "100") -> tuple[HftCodeBarV1, ...]:
    close = Decimal(start)
    closes = [close]
    for change in changes:
        close += Decimal(change)
        closes.append(close)
    return tuple(
        HftCodeBarV1(timestamp_ns=index + 1, close=value) for index, value in enumerate(closes)
    )


def test_sma_crossovers_use_previous_and_current_closed_bar_windows() -> None:
    bars = _bars(["100"] * 50 + ["101"])
    expected = (
        (
            HftCodeStrategyId.BHP_ASX_SMA_10_50,
            "BHP.ASX",
            "3105e06ae981f43f3556c63b111952c9d8c6ea0d5ba8cafee03cf8519f858231",
        ),
        (
            HftCodeStrategyId.NVDA_US_SMA_10_50,
            "NVDA.US",
            "8ea97df7aa579d11a88582a74df15dbbf9dd9d85b69223bf8d6a5a4882868db6",
        ),
    )
    for strategy_id, instrument_id, source_sha256 in expected:
        signal = evaluate_hftcode_signal(strategy_id, bars)
        assert (signal.action, signal.reason) == (
            HftCodeAction.ENTER_LONG,
            HftCodeReason.GOLDEN_CROSS,
        )
        assert signal.instrument_id == instrument_id
        assert signal.timestamp_ns == 51
        assert signal.reference_price == Decimal("101")
        assert signal.source_sha256 == source_sha256
        assert dict(signal.indicators) == {
            "fast_sma_10": Decimal("100.1"),
            "slow_sma_50": Decimal("100.02"),
        }

    death_cross = evaluate_hftcode_signal(
        HftCodeStrategyId.BHP_ASX_SMA_10_50,
        _bars(["99"] * 40 + ["101"] * 10 + ["70"]),
        HftCodePositionV1("LONG", Decimal("100")),
    )
    assert (death_cross.action, death_cross.reason) == (
        HftCodeAction.EXIT,
        HftCodeReason.DEATH_CROSS,
    )
    assert dict(death_cross.indicators) == {
        "fast_sma_10": Decimal("97.9"),
        "slow_sma_50": Decimal("98.82"),
    }


def test_sma_position_risk_exits_are_advisory_only() -> None:
    at_stop = _bars(["90"] * 40 + ["100"] * 10 + ["97"])
    at_target = _bars(["90"] * 40 + ["100"] * 10 + ["105"])
    stop = evaluate_hftcode_signal(
        HftCodeStrategyId.NVDA_US_SMA_10_50,
        at_stop,
        HftCodePositionV1("LONG", Decimal("100")),
    )
    target = evaluate_hftcode_signal(
        HftCodeStrategyId.NVDA_US_SMA_10_50,
        at_target,
        HftCodePositionV1("LONG", Decimal("100")),
    )
    assert (stop.action, stop.reason) == (HftCodeAction.EXIT, HftCodeReason.STOP_LOSS)
    assert (target.action, target.reason) == (
        HftCodeAction.EXIT,
        HftCodeReason.PROFIT_TARGET,
    )
    assert stop.reference_price == Decimal("97")
    assert target.reference_price == Decimal("105")


def test_rsi14_strict_entry_thresholds_and_neutral_exits() -> None:
    falling = _bars([str(value) for value in range(115, 100, -1)])
    rising = _bars([str(value) for value in range(100, 115)])
    long_entry = evaluate_hftcode_signal(HftCodeStrategyId.EURUSD_RSI14, falling)
    short_entry = evaluate_hftcode_signal(HftCodeStrategyId.EURUSD_RSI14, rising)
    assert (long_entry.action, long_entry.reason) == (
        HftCodeAction.ENTER_LONG,
        HftCodeReason.RSI_OVERSOLD,
    )
    assert long_entry.source_sha256 == (
        "838a76eea3fde4a55090c9f11901ac16ec9e75aef839c4542f7bc19e4affd62c"
    )
    assert dict(long_entry.indicators)["rsi_14"] == Decimal("0")
    assert (short_entry.action, short_entry.reason) == (
        HftCodeAction.ENTER_SHORT,
        HftCodeReason.RSI_OVERBOUGHT,
    )
    assert short_entry.source_sha256 == long_entry.source_sha256
    assert dict(short_entry.indicators)["rsi_14"] == Decimal("100")

    at_30 = _bars_from_changes(["1"] * 3 + ["-1"] * 7 + ["0"] * 4)
    at_70 = _bars_from_changes(["1"] * 7 + ["-1"] * 3 + ["0"] * 4)
    boundary_30 = evaluate_hftcode_signal(HftCodeStrategyId.EURUSD_RSI14, at_30)
    boundary_70 = evaluate_hftcode_signal(HftCodeStrategyId.EURUSD_RSI14, at_70)
    assert dict(boundary_30.indicators)["rsi_14"] >= Decimal("30")
    assert dict(boundary_70.indicators)["rsi_14"] == Decimal("70")
    assert (boundary_30.action, boundary_30.reason) == (
        HftCodeAction.HOLD,
        HftCodeReason.NO_SIGNAL,
    )
    assert (boundary_70.action, boundary_70.reason) == (
        HftCodeAction.HOLD,
        HftCodeReason.NO_SIGNAL,
    )

    at_55 = _bars_from_changes(["1"] * 11 + ["-3"] * 3 + ["0"] * 0)
    at_45 = _bars_from_changes(["1"] * 9 + ["-3"] + ["-2"] * 4)
    long_neutral_exit = evaluate_hftcode_signal(
        HftCodeStrategyId.EURUSD_RSI14,
        at_55,
        HftCodePositionV1("LONG", Decimal("100")),
    )
    short_neutral_exit = evaluate_hftcode_signal(
        HftCodeStrategyId.EURUSD_RSI14,
        at_45,
        HftCodePositionV1("SHORT", Decimal("98")),
    )
    assert dict(long_neutral_exit.indicators)["rsi_14"] == Decimal("55")
    assert dict(short_neutral_exit.indicators)["rsi_14"] <= Decimal("45")
    assert (long_neutral_exit.action, long_neutral_exit.reason) == (
        HftCodeAction.EXIT,
        HftCodeReason.RSI_NEUTRAL_EXIT,
    )
    assert (short_neutral_exit.action, short_neutral_exit.reason) == (
        HftCodeAction.EXIT,
        HftCodeReason.RSI_NEUTRAL_EXIT,
    )


def test_rsi_uses_fixed_eurusd_pip_units_for_stop_and_target() -> None:
    # EURUSD uses one pip = 0.0001: these are exactly 50 adverse and 100
    # favorable pips, while RSI is outside the corresponding neutral-exit side.
    stop = evaluate_hftcode_signal(
        HftCodeStrategyId.EURUSD_RSI14,
        _bars(["1.0000"] * 14 + ["0.9950"]),
        HftCodePositionV1("LONG", Decimal("1.0000")),
    )
    target = evaluate_hftcode_signal(
        HftCodeStrategyId.EURUSD_RSI14,
        _bars(["1.0000"] * 14 + ["1.0100"]),
        HftCodePositionV1("SHORT", Decimal("1.0200")),
    )
    assert (stop.action, stop.reason) == (HftCodeAction.EXIT, HftCodeReason.STOP_LOSS)
    assert (target.action, target.reason) == (
        HftCodeAction.EXIT,
        HftCodeReason.PROFIT_TARGET,
    )


def test_strategies_require_closed_bar_warmup_and_strict_timestamp_order() -> None:
    cases = (
        (HftCodeStrategyId.BHP_ASX_SMA_10_50, _bars(["100"] * 50)),
        (HftCodeStrategyId.EURUSD_RSI14, _bars(["1.0000"] * 14)),
        (HftCodeStrategyId.XAUUSD_BOLLINGER20, _bars(["100"] * 19)),
    )
    for strategy_id, bars in cases:
        signal = evaluate_hftcode_signal(strategy_id, bars)
        assert (signal.action, signal.reason) == (
            HftCodeAction.HOLD,
            HftCodeReason.INSUFFICIENT_HISTORY,
        )

    out_of_order = (HftCodeBarV1(2, Decimal("100")), HftCodeBarV1(1, Decimal("101")))
    with pytest.raises(HftCodeError) as error:
        evaluate_hftcode_signal(HftCodeStrategyId.XAUUSD_BOLLINGER20, out_of_order)
    assert error.value.code == "INVALID_INPUT"


def test_bollinger20_population_breakouts_and_middle_reversion() -> None:
    upper = evaluate_hftcode_signal(
        HftCodeStrategyId.XAUUSD_BOLLINGER20,
        _bars(["100"] * 19 + ["130.01"]),
    )
    lower = evaluate_hftcode_signal(
        HftCodeStrategyId.XAUUSD_BOLLINGER20,
        _bars(["100"] * 19 + ["70"]),
    )
    assert (upper.action, upper.reason) == (
        HftCodeAction.ENTER_LONG,
        HftCodeReason.UPPER_BAND_BREAKOUT,
    )
    assert upper.instrument_id == "XAUUSD"
    assert upper.reference_price == Decimal("130.01")
    assert upper.source_sha256 == (
        "fa7887400605e4010cfb80ef06ce2ea39de606d42beae4ff0a2e1bfade66ee2f"
    )
    assert dict(upper.indicators)["middle_band"] == Decimal("101.5005")
    with localcontext() as context:
        context.prec = 28
        closes = [Decimal("100")] * 19 + [Decimal("130.01")]
        middle = sum(closes, Decimal(0)) / Decimal(20)
        variance = sum(((price - middle) ** 2 for price in closes), Decimal(0)) / Decimal(20)
        expected_upper = middle + Decimal(2) * variance.sqrt()
    assert dict(upper.indicators)["upper_band"] == expected_upper
    assert (lower.action, lower.reason) == (
        HftCodeAction.ENTER_SHORT,
        HftCodeReason.LOWER_BAND_BREAKOUT,
    )

    long_reversion = evaluate_hftcode_signal(
        HftCodeStrategyId.XAUUSD_BOLLINGER20,
        _bars(["100"] * 19 + ["99.9"]),
        HftCodePositionV1("LONG", Decimal("100.5")),
    )
    short_reversion = evaluate_hftcode_signal(
        HftCodeStrategyId.XAUUSD_BOLLINGER20,
        _bars(["100"] * 19 + ["100.1"]),
        HftCodePositionV1("SHORT", Decimal("99.5")),
    )
    assert (long_reversion.action, long_reversion.reason) == (
        HftCodeAction.EXIT,
        HftCodeReason.MIDDLE_BAND_REVERSION,
    )
    assert (short_reversion.action, short_reversion.reason) == (
        HftCodeAction.EXIT,
        HftCodeReason.MIDDLE_BAND_REVERSION,
    )


def test_bollinger_risk_exits_use_fractional_not_tick_or_pip_scaling() -> None:
    bars_long_stop = _bars(["90"] * 19 + ["98.5"])
    bars_long_target = _bars(["90"] * 19 + ["103"])
    bars_short_stop = _bars(["110"] * 19 + ["101.5"])
    bars_short_target = _bars(["110"] * 19 + ["97"])
    stop = evaluate_hftcode_signal(
        HftCodeStrategyId.XAUUSD_BOLLINGER20,
        bars_long_stop,
        HftCodePositionV1("LONG", Decimal("100")),
    )
    target = evaluate_hftcode_signal(
        HftCodeStrategyId.XAUUSD_BOLLINGER20,
        bars_long_target,
        HftCodePositionV1("LONG", Decimal("100")),
    )
    short_stop = evaluate_hftcode_signal(
        HftCodeStrategyId.XAUUSD_BOLLINGER20,
        bars_short_stop,
        HftCodePositionV1("SHORT", Decimal("100")),
    )
    short_target = evaluate_hftcode_signal(
        HftCodeStrategyId.XAUUSD_BOLLINGER20,
        bars_short_target,
        HftCodePositionV1("SHORT", Decimal("100")),
    )
    assert (stop.action, stop.reason) == (HftCodeAction.EXIT, HftCodeReason.STOP_LOSS)
    assert (target.action, target.reason) == (
        HftCodeAction.EXIT,
        HftCodeReason.PROFIT_TARGET,
    )
    assert (short_stop.action, short_stop.reason) == (
        HftCodeAction.EXIT,
        HftCodeReason.STOP_LOSS,
    )
    assert (short_target.action, short_target.reason) == (
        HftCodeAction.EXIT,
        HftCodeReason.PROFIT_TARGET,
    )


def test_specs_pin_source_hashes_and_execution_authority_boundaries() -> None:
    specs = yaml.safe_load(_SPECS_PATH.read_text(encoding="utf-8"))
    assert specs["schema_version"] == "1"
    assert specs["port_id"] == "STRAT-HFTCODE-PORT-001"
    assert specs["source_archive"]["sha256"] == (
        "1f4ebed80a4e9bdf18892aaa2058139bd10d4fbde4d7355e1e78f2392843d82a"
    )
    expected_hashes = {
        HftCodeStrategyId.BHP_ASX_SMA_10_50: (
            "3105e06ae981f43f3556c63b111952c9d8c6ea0d5ba8cafee03cf8519f858231"
        ),
        HftCodeStrategyId.NVDA_US_SMA_10_50: (
            "8ea97df7aa579d11a88582a74df15dbbf9dd9d85b69223bf8d6a5a4882868db6"
        ),
        HftCodeStrategyId.EURUSD_RSI14: (
            "838a76eea3fde4a55090c9f11901ac16ec9e75aef839c4542f7bc19e4affd62c"
        ),
        HftCodeStrategyId.XAUUSD_BOLLINGER20: (
            "fa7887400605e4010cfb80ef06ce2ea39de606d42beae4ff0a2e1bfade66ee2f"
        ),
    }
    rows = {HftCodeStrategyId(row["strategy_id"]): row for row in specs["strategies"]}
    assert {strategy: row["source_sha256"] for strategy, row in rows.items()} == expected_hashes

    execution = specs["execution"]
    assert execution == {
        "output_authority": "advisory_signal_only",
        "order_submission": "existing_OMS_with_sovereign_risk_only",
        "accepted_order_is_fill": False,
        "startup_orders": "none",
        "close_state": "unchanged_until_broker_reconciliation",
    }

    signal = evaluate_hftcode_signal(
        HftCodeStrategyId.EURUSD_RSI14,
        _bars_from_changes(["1"] * 7 + ["-1"] * 7),
    )
    assert {field.name for field in fields(HftCodeSignalV1)} == {
        "strategy_id",
        "instrument_id",
        "action",
        "reason",
        "timestamp_ns",
        "reference_price",
        "indicators",
        "source_sha256",
    }
    assert not {"order_id", "fill_id", "filled_quantity", "broker_order_id"} & {
        field.name for field in fields(HftCodeSignalV1)
    }
    assert signal.action is HftCodeAction.HOLD


def test_signal_module_has_no_broker_order_network_or_execution_surface() -> None:
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
    forbidden_import_parts = (
        "broker",
        "execution",
        "ibapi",
        "ib_insync",
        "httpx",
        "requests",
        "socket",
    )
    assert not any(part in name.lower() for name in imported for part in forbidden_import_parts)
    forbidden_calls = {"place_order", "submit_order", "send_order", "cancel_order", "connect"}
    calls = {
        node.func.id if isinstance(node.func, ast.Name) else node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, (ast.Name, ast.Attribute))
    }
    assert not (calls & forbidden_calls)
    assert not any(isinstance(node, ast.AsyncFunctionDef) for node in ast.walk(tree))
