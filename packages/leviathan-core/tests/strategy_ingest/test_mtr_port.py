from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

import pytest
import yaml

from leviathan_core.strategy_ingest.library.asset_recovery.mtr.liquidation import (
    BasketRiskV1,
    LiquidationActionV1,
    LiquidationInputV1,
    evaluate_liquidation,
    margin_efficiency,
    partial_unwind_units,
    select_largest_non_hedge,
    select_worst_margin_efficiency,
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

NOW = datetime(2026, 10, 6, 12, tzinfo=UTC)


def regime(**updates: object) -> MtrRegimeInputV1:
    fields: dict[str, object] = {
        "observed_at": NOW,
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
    fields.update(updates)
    return MtrRegimeInputV1(**fields)  # type: ignore[arg-type]


def grid_request(**updates: object) -> GridAddInputV1:
    fields: dict[str, object] = {
        "regime": regime(),
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
    fields.update(updates)
    return GridAddInputV1(**fields)  # type: ignore[arg-type]


def liquidation(**updates: object) -> LiquidationInputV1:
    fields: dict[str, object] = {
        "observed_at": NOW,
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
    fields.update(updates)
    return LiquidationInputV1(**fields)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("updates", "expected"),
    [
        ({}, RegimeStateV1.RANGE_NORMAL),
        (
            {
                "price": Decimal("101"),
                "ema50_h1": Decimal("100"),
                "ema50_slope_h1": Decimal("1"),
                "bars_on_ema_side": 12,
                "adx_h1": Decimal("26"),
            },
            RegimeStateV1.TREND_UP,
        ),
        (
            {
                "price": Decimal("99"),
                "ema50_h1": Decimal("100"),
                "ema50_slope_h1": Decimal("-1"),
                "bars_on_ema_side": 12,
                "adx_h1": Decimal("26"),
            },
            RegimeStateV1.TREND_DOWN,
        ),
        (
            {
                "atr_percentile_h1": Decimal("70.01"),
                "donchian_breakout": True,
                "adx_rising": True,
            },
            RegimeStateV1.VOL_EXPANSION,
        ),
        (
            {
                "price": Decimal("101"),
                "ema50_h1": Decimal("100"),
                "ema50_slope_h1": Decimal("1"),
                "bars_on_ema_side": 12,
                "adx_h1": Decimal("26"),
                "trend_persistence_bars": 24,
                "spread_multiple": Decimal("2.01"),
                "realized_vol_percentile": Decimal("90.01"),
            },
            RegimeStateV1.CRISIS_ONE_WAY,
        ),
        ({"recovery_active": True}, RegimeStateV1.RECOVERY_MODE),
    ],
)
def test_classifies_documented_six_states(
    updates: dict[str, object], expected: RegimeStateV1
) -> None:
    assert classify_regime(regime(**updates)) is expected


def test_classification_thresholds_are_strict_and_recovery_overlays_market_regime() -> None:
    assert (
        classify_regime(
            regime(atr_percentile_h1=Decimal("70"), donchian_breakout=True, adx_rising=True)
        )
        is RegimeStateV1.RANGE_NORMAL
    )
    assert (
        classify_regime(
            regime(
                price=Decimal("101"),
                ema50_h1=Decimal("100"),
                ema50_slope_h1=Decimal("1"),
                bars_on_ema_side=12,
                adx_h1=Decimal("26"),
                trend_persistence_bars=24,
                spread_multiple=Decimal("2.01"),
                realized_vol_percentile=Decimal("90.01"),
                recovery_active=True,
            )
        )
        is RegimeStateV1.RECOVERY_MODE
    )


def test_specs_preserve_source_hashes_conflicts_and_oos_failures() -> None:
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
    assert specs["variants"]["documented_regime_grid_v0"]["source_files"][0]["sha256"] == (
        "e9a53544f30643dadeb3905e81027e865858320687cdd0b46108041ba09db2cc"
    )
    assert specs["variants"]["documented_regime_grid_v0"]["source_files"][2]["sha256"] == (
        "3de5457541a8c8900802cf7ddc2337d96e5c87a152f8c1dee0ab97fafa223f97"
    )
    assert specs["variants"]["source_regime_engine_mql5"]["selected_for_port"] is False
    assert specs["variants"]["pure_ea_flow_logic"]["selected_for_port"] is False
    assert specs["preserved_failure_evidence"][0]["evidence"].startswith("CLOSED_EMPIRICAL")
    assert specs["execution_scope"] == "research_replay_paper_only"
    assert specs["performance_claim"] is False
    assert specs["sovereign_overrides"]["limits"]["daily_drawdown_pct"] == "3"
    assert specs["sovereign_overrides"]["limits"]["max_position_units"] == "1"
    assert specs["sovereign_overrides"]["max_adds_configuration"].startswith("Typed field")


@pytest.mark.parametrize(
    ("updates", "code"),
    [
        ({"closed_bar": False}, "CLOSED_M5_BAR_REQUIRED"),
        ({"timeframe": "H1"}, "CLOSED_M5_BAR_REQUIRED"),
        ({"observed_at": datetime(2026, 10, 6, 12)}, "TIMEZONE_REQUIRED"),
        ({"price": Decimal("NaN")}, "INPUT_INVALID"),
        ({"atr_h1": Decimal("0")}, "INPUT_INVALID"),
    ],
)
def test_regime_rejects_unclosed_naive_or_invalid_input(
    updates: dict[str, object], code: str
) -> None:
    with pytest.raises(MtrPortError) as caught:
        regime(**updates)
    assert caught.value.code == code
    assert str(caught.value) == code


def test_timestamp_normalizes_to_utc_without_using_wall_clock() -> None:
    local = timezone(timedelta(hours=-5))
    parsed = regime(observed_at=datetime(2026, 10, 6, 7, tzinfo=local))
    assert parsed.observed_at == NOW
    assert parsed.observed_at.tzinfo is UTC


def test_grid_add_formula_and_sovereign_size_cap() -> None:
    allowed = propose_grid_add(grid_request())
    assert allowed.allowed
    assert allowed.grid_step_price == Decimal("0.35")
    assert allowed.proposed_units == Decimal("0.25")
    too_large = propose_grid_add(grid_request(base_order_units=Decimal("1.01")))
    assert not too_large.allowed and too_large.reason == "ORDER_SIZE_CAP"
    position_cap = propose_grid_add(grid_request(current_position_units=Decimal("0.9")))
    assert not position_cap.allowed and position_cap.reason == "POSITION_SIZE_CAP"


@pytest.mark.parametrize(
    ("updates", "reason"),
    [
        ({"halted": True}, "HALT_ACTIVE"),
        ({"trading_hour": False}, "OUTSIDE_TRADING_HOURS"),
        ({"zone_armed": False}, "ZONE_NOT_ARMED"),
        ({"adds_count": 2}, "MAX_ADDS"),
        ({"gross_leverage": Decimal("5")}, "SOVEREIGN_GROSS_LEVERAGE"),
        ({"net_leverage": Decimal("3")}, "SOVEREIGN_NET_LEVERAGE"),
        ({"daily_drawdown_pct": Decimal("3")}, "SOVEREIGN_DAILY_DRAWDOWN_PCT"),
        ({"weekly_drawdown_pct": Decimal("6")}, "SOVEREIGN_WEEKLY_DRAWDOWN_PCT"),
        ({"trailing_drawdown_pct": Decimal("8")}, "SOVEREIGN_TRAILING_DRAWDOWN_PCT"),
        ({"portfolio_heat_pct": Decimal("5")}, "SOVEREIGN_PORTFOLIO_HEAT_PCT"),
        ({"per_position_heat_pct": Decimal("1")}, "SOVEREIGN_PER_POSITION_HEAT_PCT"),
        (
            {
                "regime": regime(
                    atr_percentile_h1=Decimal("71"), donchian_breakout=True, adx_rising=True
                )
            },
            "REGIME_BLOCK",
        ),
        ({"regime": regime(spread_multiple=Decimal("3.01"))}, "SPREAD_LIMIT"),
        ({"last_add_price": Decimal("99.6")}, "ADVERSE_GRID_TRIGGER_NOT_MET"),
    ],
)
def test_grid_add_fails_closed_on_halt_regime_time_and_risk_caps(
    updates: dict[str, object], reason: str
) -> None:
    result = propose_grid_add(grid_request(**updates))
    assert not result.allowed
    assert result.reason == reason


def test_grid_caps_cannot_be_widened_past_project_risk_lock() -> None:
    with pytest.raises(MtrPortError, match=r"^SOVEREIGN_CAP_INVALID$"):
        SovereignCapsV1(max_adds=7)
    with pytest.raises(MtrPortError, match=r"^SOVEREIGN_CAP_INVALID$"):
        SovereignCapsV1(max_gross_leverage=Decimal("5.01"))
    with pytest.raises(MtrPortError, match=r"^SOVEREIGN_CAP_INVALID$"):
        SovereignCapsV1(max_net_leverage=Decimal("3.01"))
    with pytest.raises(MtrPortError, match=r"^SOVEREIGN_CAP_INVALID$"):
        SovereignCapsV1(max_position_units=Decimal("1.01"))
    assert SovereignCapsV1().max_adds == 2
    assert SovereignCapsV1(max_adds=6).max_adds == 6


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
def test_source_lot_multiplier_sequence_is_preserved_under_explicit_config(
    adds_count: int, expected_units: Decimal
) -> None:
    result = propose_grid_add(
        grid_request(adds_count=adds_count, current_position_units=Decimal("0")),
        caps=SovereignCapsV1(max_adds=6),
    )
    assert result.allowed
    assert result.proposed_units == expected_units


def test_source_side_regimes_are_preserved_and_wrong_side_rejects() -> None:
    trend_up = regime(
        price=Decimal("101"),
        ema50_h1=Decimal("100"),
        ema50_slope_h1=Decimal("1"),
        bars_on_ema_side=12,
        adx_h1=Decimal("26"),
    )
    sell = propose_grid_add(
        grid_request(regime=trend_up, side=TradeSideV1.SELL, last_add_price=Decimal("100.6"))
    )
    buy = propose_grid_add(grid_request(regime=trend_up))
    assert sell.allowed
    assert not buy.allowed and buy.reason == "REGIME_BLOCK"


@pytest.mark.parametrize(
    ("updates", "action", "priority", "reason"),
    [
        (
            {"margin_level_pct": Decimal("299.99")},
            LiquidationActionV1.CLOSE_WORST_MARGIN_EFFICIENCY,
            1,
            "MARGIN_LT_300",
        ),
        (
            {"account_drawdown_pct": Decimal("8")},
            LiquidationActionV1.HALT_NEW_ADDS,
            None,
            "SOVEREIGN_TRAILING_DRAWDOWN",
        ),
        (
            {"floating_drawdown_pct": Decimal("8.01")},
            LiquidationActionV1.PARTIAL_UNWIND,
            3,
            "FLOATING_DD_GT_8",
        ),
        ({"basket_age_days": Decimal("45.01")}, LiquidationActionV1.CLOSE_BASKET, 4, "MAX_AGE"),
        ({"mae_atr": Decimal("10.01")}, LiquidationActionV1.CLOSE_BASKET, 5, "MAX_MAE"),
        ({"halt_active": True}, LiquidationActionV1.MANUAL_REVIEW_HALT, None, "HALT_ACTIVE"),
        (
            {"slippage_cap_exceeded": True},
            LiquidationActionV1.MANUAL_REVIEW_HALT,
            None,
            "SLIPPAGE_CAP_EXCEEDED",
        ),
    ],
)
def test_liquidation_priority_and_sovereign_override(
    updates: dict[str, object],
    action: LiquidationActionV1,
    priority: int | None,
    reason: str,
) -> None:
    plan = evaluate_liquidation(liquidation(**updates))
    assert (plan.action, plan.priority, plan.reason) == (action, priority, reason)


def test_margin_survival_action_precedes_drawdown_add_halt() -> None:
    plan = evaluate_liquidation(
        liquidation(
            margin_level_pct=Decimal("199"),
            account_drawdown_pct=Decimal("8"),
            spread_multiple=Decimal("4"),
        )
    )
    assert plan.action is LiquidationActionV1.EMERGENCY_CLOSE_AND_HALT
    assert plan.halt_required


@pytest.mark.parametrize("completed_chunks", [0, 1, 2, 3])
def test_floating_drawdown_keeps_partial_unwind_before_four_chunks(
    completed_chunks: int,
) -> None:
    plan = evaluate_liquidation(
        liquidation(
            floating_drawdown_pct=Decimal("8.01"),
            completed_partial_chunks=completed_chunks,
        )
    )
    assert plan.action is LiquidationActionV1.PARTIAL_UNWIND
    assert plan.priority == 3
    assert plan.reason == "FLOATING_DD_GT_8"


def test_floating_drawdown_promotes_after_four_chunks_but_not_when_cleared() -> None:
    escalated = evaluate_liquidation(
        liquidation(
            floating_drawdown_pct=Decimal("8.01"),
            completed_partial_chunks=4,
        )
    )
    assert escalated.action is LiquidationActionV1.CLOSE_NON_HEDGE_EXPOSURE
    assert escalated.priority == 2
    assert escalated.reason == "FLOATING_DD_ESCALATED_AFTER_4_CHUNKS"
    assert escalated.halt_required and escalated.resume_requires_manual_review

    cleared = evaluate_liquidation(
        liquidation(
            floating_drawdown_pct=Decimal("8"),
            completed_partial_chunks=4,
        )
    )
    assert cleared.action is LiquidationActionV1.NONE
    assert cleared.priority is None


@pytest.mark.parametrize(
    ("margin", "expected"),
    [
        (Decimal("250"), LiquidationActionV1.MINIMUM_EXPOSURE_CLOSE_AND_HALT),
        (Decimal("200"), LiquidationActionV1.EMERGENCY_CLOSE_AND_HALT),
        (Decimal("249.99"), LiquidationActionV1.MINIMUM_EXPOSURE_CLOSE_AND_HALT),
        (Decimal("199.99"), LiquidationActionV1.EMERGENCY_CLOSE_AND_HALT),
        (Decimal("250.01"), LiquidationActionV1.WAIT_FOR_LIQUIDITY),
    ],
)
def test_illiquid_margin_override_tiers_are_explicit(
    margin: Decimal, expected: LiquidationActionV1
) -> None:
    plan = evaluate_liquidation(
        liquidation(margin_level_pct=margin, spread_multiple=Decimal("3.01"))
    )
    assert plan.action is expected
    assert plan.halt_required is (margin <= Decimal("250"))


@pytest.mark.parametrize(
    ("updates", "code"),
    [
        ({"timeframe": "H1"}, "CLOSED_M5_BAR_REQUIRED"),
        ({"closed_bar": False}, "CLOSED_M5_BAR_REQUIRED"),
        ({"observed_at": datetime(2026, 10, 6, 12)}, "TIMEZONE_REQUIRED"),
        ({"margin_level_pct": Decimal("NaN")}, "INPUT_INVALID"),
        ({"mae_atr": Decimal("-1")}, "INPUT_INVALID"),
        ({"completed_partial_chunks": -1}, "INPUT_INVALID"),
        ({"completed_partial_chunks": True}, "INPUT_INVALID"),
    ],
)
def test_liquidation_rejects_invalid_or_nonclosed_inputs(
    updates: dict[str, object], code: str
) -> None:
    with pytest.raises(MtrPortError) as caught:
        liquidation(**updates)
    assert caught.value.code == code


def basket(
    basket_id: str,
    *,
    margin: str,
    loss: str,
    exposure: str = "1",
    hedge: bool = False,
) -> BasketRiskV1:
    return BasketRiskV1(
        basket_id=basket_id,
        margin_released=Decimal(margin),
        realized_loss_at_close=Decimal(loss),
        exposure_units=Decimal(exposure),
        is_hedge=hedge,
    )


def test_margin_efficiency_uses_absolute_loss_and_source_epsilon() -> None:
    assert margin_efficiency(basket("loss", margin="1", loss="-2")) == margin_efficiency(
        basket("gain", margin="1", loss="2")
    )
    assert margin_efficiency(basket("zero", margin="0.001", loss="0")) == 1


def test_worst_margin_efficiency_selection_and_tie_break_are_deterministic() -> None:
    lower = basket("z-lower", margin="4", loss="2")
    tie_z = basket("z-tie", margin="10", loss="2")
    tie_a = basket("a-tie", margin="5", loss="1")
    assert select_worst_margin_efficiency((lower, tie_z, tie_a)) is tie_a


def test_largest_non_hedge_selection_skips_hedges_and_tie_breaks_by_id() -> None:
    small = basket("small", margin="1", loss="1", exposure="2")
    tie_z = basket("z-large", margin="1", loss="1", exposure="3")
    tie_a = basket("a-large", margin="1", loss="1", exposure="3")
    hedge = basket("hedge", margin="1", loss="1", exposure="99", hedge=True)
    assert select_largest_non_hedge((small, tie_z, tie_a, hedge)) is tie_a


def test_basket_selectors_reject_bad_collections_and_no_nonhedge_candidate() -> None:
    first = basket("same", margin="1", loss="1")
    duplicate = basket("same", margin="2", loss="1")
    for selector in (select_worst_margin_efficiency, select_largest_non_hedge):
        with pytest.raises(MtrPortError, match=r"^INPUT_INVALID$"):
            selector([first])  # type: ignore[arg-type]
        with pytest.raises(MtrPortError, match=r"^INPUT_INVALID$"):
            selector((first, duplicate))
    hedge = basket("hedge", margin="1", loss="1", hedge=True)
    with pytest.raises(MtrPortError, match=r"^NO_NON_HEDGE_CANDIDATE$"):
        select_largest_non_hedge((hedge,))


@pytest.mark.parametrize(
    ("units", "expected"),
    [(Decimal("4"), Decimal("1")), (Decimal("0.4"), Decimal("0.100"))],
)
def test_partial_unwind_uses_exact_source_quarter_chunks(units: Decimal, expected: Decimal) -> None:
    assert partial_unwind_units(units) == expected
