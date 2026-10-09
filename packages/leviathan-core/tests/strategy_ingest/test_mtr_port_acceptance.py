from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

import pytest
import yaml

from leviathan_core.strategy_ingest.library.asset_recovery.mtr.liquidation import (
    LiquidationActionV1,
    LiquidationInputV1,
    evaluate_liquidation,
)
from leviathan_core.strategy_ingest.library.asset_recovery.mtr.regime_grid import (
    GridAddInputV1,
    MtrPortError,
    MtrRegimeInputV1,
    RegimeStateV1,
    SovereignCapsV1,
    TradeSideV1,
    classify_regime,
    propose_grid_add,
)

OBSERVED_AT = datetime(2026, 10, 6, 12, tzinfo=UTC)


def observation(**updates: object) -> MtrRegimeInputV1:
    values: dict[str, object] = {
        "observed_at": OBSERVED_AT,
        "timeframe": "M5",
        "closed_bar": True,
        "price": Decimal("99.5"),
        "atr_h1": Decimal("1"),
        "donchian_low_h4": Decimal("100"),
        "donchian_high_h4": Decimal("110"),
        "ema50_h1": Decimal("100"),
        "ema50_slope_h1": Decimal("0"),
        "bars_on_ema_side": 0,
        "adx_h1": Decimal("20"),
        "atr_percentile_h1": Decimal("50"),
        "donchian_breakout": False,
        "adx_rising": False,
        "trend_persistence_bars": 0,
        "spread_multiple": Decimal("1"),
        "realized_vol_percentile": Decimal("50"),
        "recovery_active": False,
    }
    values.update(updates)
    return MtrRegimeInputV1(**values)  # type: ignore[arg-type]


def add_request(**updates: object) -> GridAddInputV1:
    values: dict[str, object] = {
        "regime": observation(),
        "side": TradeSideV1.BUY,
        "last_add_price": Decimal("99.85"),
        "base_order_units": Decimal("0.25"),
        "adds_count": 0,
        "current_position_units": Decimal("0.25"),
        "gross_leverage": Decimal("1"),
        "net_leverage": Decimal("1"),
        "daily_drawdown_pct": Decimal("0"),
        "weekly_drawdown_pct": Decimal("0"),
        "trailing_drawdown_pct": Decimal("0"),
        "portfolio_heat_pct": Decimal("0"),
        "per_position_heat_pct": Decimal("0"),
        "zone_armed": True,
        "halted": False,
        "trading_hour": True,
    }
    values.update(updates)
    return GridAddInputV1(**values)  # type: ignore[arg-type]


def liquidation_input(**updates: object) -> LiquidationInputV1:
    values: dict[str, object] = {
        "observed_at": OBSERVED_AT,
        "timeframe": "M5",
        "closed_bar": True,
        "margin_level_pct": Decimal("500"),
        "account_drawdown_pct": Decimal("1"),
        "floating_drawdown_pct": Decimal("1"),
        "basket_age_days": Decimal("1"),
        "mae_atr": Decimal("1"),
        "spread_multiple": Decimal("1"),
        "trading_hour": True,
        "session_gap": False,
        "halt_active": False,
        "slippage_cap_exceeded": False,
    }
    values.update(updates)
    return LiquidationInputV1(**values)  # type: ignore[arg-type]


def test_documented_six_regime_states_are_distinguished() -> None:
    cases = (
        (observation(), RegimeStateV1.RANGE_NORMAL),
        (
            observation(
                price=Decimal("101"),
                ema50_slope_h1=Decimal("1"),
                bars_on_ema_side=12,
                adx_h1=Decimal("25.01"),
            ),
            RegimeStateV1.TREND_UP,
        ),
        (
            observation(
                price=Decimal("99"),
                ema50_slope_h1=Decimal("-1"),
                bars_on_ema_side=12,
                adx_h1=Decimal("25.01"),
            ),
            RegimeStateV1.TREND_DOWN,
        ),
        (
            observation(
                atr_percentile_h1=Decimal("70.01"),
                donchian_breakout=True,
                adx_rising=True,
            ),
            RegimeStateV1.VOL_EXPANSION,
        ),
        (
            observation(
                price=Decimal("101"),
                ema50_slope_h1=Decimal("1"),
                bars_on_ema_side=12,
                adx_h1=Decimal("25.01"),
                trend_persistence_bars=24,
                spread_multiple=Decimal("2.01"),
                realized_vol_percentile=Decimal("90.01"),
            ),
            RegimeStateV1.CRISIS_ONE_WAY,
        ),
        (observation(recovery_active=True), RegimeStateV1.RECOVERY_MODE),
    )

    assert tuple(classify_regime(item) for item, _ in cases) == tuple(
        expected for _, expected in cases
    )


def test_grid_step_uses_greater_of_price_fraction_and_h1_atr_fraction() -> None:
    atr_dominates = propose_grid_add(add_request())
    assert atr_dominates.grid_step_price == Decimal("0.35")

    price_dominates = propose_grid_add(
        add_request(
            regime=observation(
                price=Decimal("200"),
                atr_h1=Decimal("1"),
                donchian_low_h4=Decimal("199"),
                donchian_high_h4=Decimal("200"),
            ),
            last_add_price=Decimal("200.5"),
        )
    )
    assert price_dominates.grid_step_price == Decimal("0.5000")
    assert price_dominates.allowed


def test_grid_side_regime_matrix_and_adverse_trigger_are_preserved() -> None:
    buy_in_downtrend = propose_grid_add(
        add_request(
            regime=observation(
                price=Decimal("99"),
                ema50_slope_h1=Decimal("-1"),
                bars_on_ema_side=12,
                adx_h1=Decimal("26"),
            ),
            last_add_price=Decimal("99.35"),
        )
    )
    assert buy_in_downtrend.allowed
    assert buy_in_downtrend.regime is RegimeStateV1.TREND_DOWN

    sell_in_uptrend = propose_grid_add(
        add_request(
            regime=observation(
                price=Decimal("101"),
                ema50_slope_h1=Decimal("1"),
                bars_on_ema_side=12,
                adx_h1=Decimal("26"),
            ),
            side=TradeSideV1.SELL,
            last_add_price=Decimal("100.6465"),
        )
    )
    assert sell_in_uptrend.allowed
    assert sell_in_uptrend.regime is RegimeStateV1.TREND_UP


@pytest.mark.parametrize(
    ("adds_count", "expected_units"),
    [
        (0, Decimal("0.25")),
        (1, Decimal("0.25")),
        (2, Decimal("0.25")),
        (3, Decimal("0.3125")),
        (4, Decimal("0.3125")),
        (5, Decimal("0.375")),
    ],
)
def test_documented_add_lot_multiplier_schedule(adds_count: int, expected_units: Decimal) -> None:
    decision = propose_grid_add(
        add_request(adds_count=adds_count, current_position_units=Decimal("0")),
        caps=SovereignCapsV1(max_adds=6, max_position_units=Decimal("1")),
    )
    assert decision.allowed
    assert decision.proposed_units == expected_units


@pytest.mark.parametrize(
    ("updates", "reason"),
    [
        ({"zone_armed": False}, "ZONE_NOT_ARMED"),
        ({"trading_hour": False}, "OUTSIDE_TRADING_HOURS"),
        ({"adds_count": 2}, "MAX_ADDS"),
        (
            {
                "regime": observation(
                    atr_percentile_h1=Decimal("71"),
                    donchian_breakout=True,
                    adx_rising=True,
                )
            },
            "REGIME_BLOCK",
        ),
        ({"regime": observation(spread_multiple=Decimal("3.01"))}, "SPREAD_LIMIT"),
        ({"last_add_price": Decimal("99.6")}, "ADVERSE_GRID_TRIGGER_NOT_MET"),
    ],
)
def test_grid_add_requires_each_documented_gate(updates: dict[str, object], reason: str) -> None:
    decision = propose_grid_add(add_request(**updates))
    assert not decision.allowed
    assert decision.reason == reason


def test_halt_and_sovereign_caps_deny_adds_without_clamping() -> None:
    halted = propose_grid_add(add_request(halted=True, daily_drawdown_pct=Decimal("3")))
    assert not halted.allowed and halted.reason == "HALT_ACTIVE"

    capped = propose_grid_add(
        add_request(daily_drawdown_pct=Decimal("3")),
        caps=SovereignCapsV1(max_adds=6, max_position_units=Decimal("1")),
    )
    assert not capped.allowed
    assert capped.reason == "SOVEREIGN_DAILY_DRAWDOWN_PCT"
    assert capped.proposed_units == Decimal("0.25")

    with pytest.raises(MtrPortError) as caught:
        SovereignCapsV1(max_gross_leverage=Decimal("5.01"))
    assert caught.value.code == "SOVEREIGN_CAP_INVALID"
    assert str(caught.value) == "SOVEREIGN_CAP_INVALID"

    order_cap = propose_grid_add(add_request(base_order_units=Decimal("1.01")))
    assert not order_cap.allowed and order_cap.reason == "ORDER_SIZE_CAP"
    position_cap = propose_grid_add(add_request(current_position_units=Decimal("0.9")))
    assert not position_cap.allowed and position_cap.reason == "POSITION_SIZE_CAP"


@pytest.mark.parametrize(
    ("metric", "reason"),
    [
        ("gross_leverage", "SOVEREIGN_GROSS_LEVERAGE"),
        ("net_leverage", "SOVEREIGN_NET_LEVERAGE"),
        ("daily_drawdown_pct", "SOVEREIGN_DAILY_DRAWDOWN_PCT"),
        ("weekly_drawdown_pct", "SOVEREIGN_WEEKLY_DRAWDOWN_PCT"),
        ("trailing_drawdown_pct", "SOVEREIGN_TRAILING_DRAWDOWN_PCT"),
        ("portfolio_heat_pct", "SOVEREIGN_PORTFOLIO_HEAT_PCT"),
        ("per_position_heat_pct", "SOVEREIGN_PER_POSITION_HEAT_PCT"),
    ],
)
def test_each_sovereign_limit_denies_a_qualifying_add(metric: str, reason: str) -> None:
    request = add_request(**{metric: getattr(SovereignCapsV1(), f"max_{metric}")})
    decision = propose_grid_add(request)
    assert not decision.allowed
    assert decision.reason == reason


def test_closed_m5_only_and_offset_timestamps_are_normalized_to_utc() -> None:
    local = timezone(timedelta(hours=-5))
    parsed = observation(observed_at=datetime(2026, 10, 6, 7, tzinfo=local))
    assert parsed.observed_at == OBSERVED_AT
    assert parsed.observed_at.tzinfo is UTC

    for updates, expected_code in (
        ({"closed_bar": False}, "CLOSED_M5_BAR_REQUIRED"),
        ({"timeframe": "H1"}, "CLOSED_M5_BAR_REQUIRED"),
        ({"observed_at": datetime(2026, 10, 6, 12)}, "TIMEZONE_REQUIRED"),
    ):
        with pytest.raises(MtrPortError) as caught:
            observation(**updates)
        assert caught.value.code == expected_code
        assert str(caught.value) == expected_code


def test_liquidation_uses_documented_priority_and_sovereign_precedence() -> None:
    multi_trigger = evaluate_liquidation(
        liquidation_input(
            margin_level_pct=Decimal("299.99"),
            account_drawdown_pct=Decimal("8"),
            floating_drawdown_pct=Decimal("9"),
            basket_age_days=Decimal("46"),
            mae_atr=Decimal("11"),
        )
    )
    assert multi_trigger.action is LiquidationActionV1.CLOSE_WORST_MARGIN_EFFICIENCY
    assert multi_trigger.priority == 1
    assert multi_trigger.reason == "MARGIN_LT_300"
    assert multi_trigger.halt_required

    dd_only = evaluate_liquidation(
        liquidation_input(
            account_drawdown_pct=Decimal("8"),
            floating_drawdown_pct=Decimal("9"),
            basket_age_days=Decimal("46"),
            mae_atr=Decimal("11"),
        )
    )
    assert dd_only.action is LiquidationActionV1.HALT_NEW_ADDS
    assert dd_only.priority is None
    assert dd_only.reason == "SOVEREIGN_TRAILING_DRAWDOWN"
    assert dd_only.halt_required

    ordinary_priorities = (
        (
            liquidation_input(
                floating_drawdown_pct=Decimal("8.01"),
                basket_age_days=Decimal("46"),
                mae_atr=Decimal("11"),
            ),
            LiquidationActionV1.PARTIAL_UNWIND,
            3,
        ),
        (
            liquidation_input(basket_age_days=Decimal("46"), mae_atr=Decimal("11")),
            LiquidationActionV1.CLOSE_BASKET,
            4,
        ),
        (
            liquidation_input(mae_atr=Decimal("10.01")),
            LiquidationActionV1.CLOSE_BASKET,
            5,
        ),
    )
    for source_input, expected_action, expected_priority in ordinary_priorities:
        plan = evaluate_liquidation(source_input)
        assert plan.action is expected_action
        assert plan.priority == expected_priority

    halt = evaluate_liquidation(liquidation_input(halt_active=True))
    assert halt.action is LiquidationActionV1.MANUAL_REVIEW_HALT
    assert halt.reason == "HALT_ACTIVE"
    assert halt.halt_required and halt.resume_requires_manual_review

    slippage = evaluate_liquidation(
        liquidation_input(
            margin_level_pct=Decimal("190"),
            slippage_cap_exceeded=True,
        )
    )
    assert slippage.action is LiquidationActionV1.MANUAL_REVIEW_HALT
    assert slippage.reason == "SLIPPAGE_CAP_EXCEEDED"


@pytest.mark.parametrize("completed_chunks", [0, 1, 2, 3])
def test_partial_unwind_escalation_is_stateless_before_four_chunks(
    completed_chunks: int,
) -> None:
    plan = evaluate_liquidation(
        liquidation_input(
            floating_drawdown_pct=Decimal("8.01"),
            completed_partial_chunks=completed_chunks,
        )
    )
    assert plan.action is LiquidationActionV1.PARTIAL_UNWIND
    assert plan.priority == 3
    assert plan.reason == "FLOATING_DD_GT_8"


def test_four_completed_partial_chunks_escalate_and_cleared_trigger_does_not() -> None:
    escalated = evaluate_liquidation(
        liquidation_input(
            floating_drawdown_pct=Decimal("8.01"),
            completed_partial_chunks=4,
        )
    )
    assert escalated.action is LiquidationActionV1.CLOSE_NON_HEDGE_EXPOSURE
    assert escalated.priority == 2
    assert escalated.reason == "FLOATING_DD_ESCALATED_AFTER_4_CHUNKS"
    assert escalated.halt_required and escalated.resume_requires_manual_review

    cleared = evaluate_liquidation(
        liquidation_input(
            floating_drawdown_pct=Decimal("8"),
            completed_partial_chunks=4,
        )
    )
    assert cleared.action is LiquidationActionV1.NONE
    assert cleared.reason == "NO_TRIGGER"


def test_variant_lineage_hashes_and_nonperformance_scope_are_explicit() -> None:
    specs_path = (
        Path(__file__).parents[2]
        / "src"
        / "leviathan_core"
        / "strategy_ingest"
        / "library"
        / "asset_recovery"
        / "mtr"
        / "specs.yaml"
    )
    specs = yaml.safe_load(specs_path.read_text(encoding="utf-8"))

    assert specs["classification_source"]["archive_sha256"] == (
        "7d9413c1b4cadedad5dc02d02d5d7417f7106fdbcf32a15f6e96d550d7045f6d"
    )
    for variant in specs["variants"].values():
        for source in variant.get("source_files", []):
            digest = source["sha256"]
            assert len(digest) == 64
            assert all(char in "0123456789abcdef" for char in digest)
    documented = specs["variants"]["documented_regime_grid_v0"]
    assert documented["selected_for_port"] is True
    source_paths = {entry["path"]: entry["sha256"] for entry in documented["source_files"]}
    assert source_paths["docs/mtr_strategy_spec_v0.md"] == (
        "e9a53544f30643dadeb3905e81027e865858320687cdd0b46108041ba09db2cc"
    )
    assert source_paths["MQL5/Include/MTR/GridAdd.mqh"] == (
        "3de5457541a8c8900802cf7ddc2337d96e5c87a152f8c1dee0ab97fafa223f97"
    )
    assert source_paths["MQL5/Include/MTR/RegimeEngine.mqh"] == (
        "103019b54265fab13bc538acd9b360bf02213151488d287a35596c500a0b04db"
    )
    assert specs["variants"]["source_regime_engine_mql5"]["selected_for_port"] is False
    source_differences = specs["variants"]["source_regime_engine_mql5"]["differences"]
    assert any("9 closed H1 bars" in item and "12" in item for item in source_differences)
    assert any("ATR ratio" in item and "realized-volatility" in item for item in source_differences)
    assert specs["variants"]["regime_score_r1a"]["selected_for_port"] is False
    assert specs["variants"]["pure_ea_flow_logic"]["selected_for_port"] is False
    assert specs["liquidation"]["source_priority"] == [
        "margin_lt_300",
        "account_dd_gt_12",
        "floating_dd_gt_8",
        "age_gt_45_days",
        "mae_gt_10_atr",
    ]
    assert specs["execution_scope"] == "research_replay_paper_only"
    assert specs["order_routing"] is False
    assert specs["performance_claim"] is False
    evidence = [item["evidence"] for item in specs["preserved_failure_evidence"]]
    assert any("OOS_STAGE1_FAIL" in item for item in evidence)
    assert any("latency" in item.lower() for item in evidence)
