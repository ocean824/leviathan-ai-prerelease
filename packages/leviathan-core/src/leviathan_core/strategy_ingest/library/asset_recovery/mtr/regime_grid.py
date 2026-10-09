"""Typed, offline MTR regime and grid-add proposal kernel.

This module is research/replay-only. It never routes orders. Its rule source is
the documented MTR v0 regime/grid specification; source-code disagreements are
listed in the adjacent ``specs.yaml`` rather than silently blended in.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from enum import StrEnum
from typing import Final


class MtrPortError(ValueError):
    """Stable content-free error for malformed or unsafe MTR inputs."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class RegimeStateV1(StrEnum):
    RANGE_NORMAL = "RANGE_NORMAL"
    TREND_UP = "TREND_UP"
    TREND_DOWN = "TREND_DOWN"
    VOL_EXPANSION = "VOL_EXPANSION"
    CRISIS_ONE_WAY = "CRISIS_ONE_WAY"
    RECOVERY_MODE = "RECOVERY_MODE"


class TradeSideV1(StrEnum):
    BUY = "BUY"
    SELL = "SELL"


_ZERO: Final = Decimal("0")
_ONE: Final = Decimal("1")
_TWO: Final = Decimal("2")
_THREE: Final = Decimal("3")
_FIVE: Final = Decimal("5")
_EIGHT: Final = Decimal("8")
_TWELVE: Final = Decimal("12")
_TWENTY_FIVE: Final = Decimal("25")
_SEVENTY: Final = Decimal("70")
_NINETY: Final = Decimal("90")
_GRID_PCT: Final = Decimal("0.0025")
_GRID_ATR: Final = Decimal("0.35")
_ADX_THRESHOLD: Final = Decimal("25")
_DEFAULT_MAX_ADDS: Final = 2
_SOURCE_MAX_ADDS: Final = 6


def _decimal(value: object) -> Decimal:
    if type(value) is not Decimal or not value.is_finite():
        raise MtrPortError("INPUT_INVALID")
    exponent = value.as_tuple().exponent
    if (
        type(exponent) is not int
        or len(value.as_tuple().digits) > 64
        or abs(exponent) > 64
        or abs(value.adjusted()) > 64
    ):
        raise MtrPortError("INPUT_INVALID")
    return value


def _timestamp(value: datetime, closed_bar: bool, timeframe: str) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise MtrPortError("TIMEZONE_REQUIRED")
    if type(closed_bar) is not bool or not closed_bar or timeframe != "M5":
        raise MtrPortError("CLOSED_M5_BAR_REQUIRED")
    return value.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class MtrRegimeInputV1:
    """Closed M5 observation with completed higher-timeframe features."""

    observed_at: datetime
    timeframe: str
    closed_bar: bool
    price: Decimal
    atr_h1: Decimal
    donchian_low_h4: Decimal
    donchian_high_h4: Decimal
    ema50_h1: Decimal
    ema50_slope_h1: Decimal
    bars_on_ema_side: int
    adx_h1: Decimal
    atr_percentile_h1: Decimal
    donchian_breakout: bool
    adx_rising: bool
    trend_persistence_bars: int
    spread_multiple: Decimal
    realized_vol_percentile: Decimal
    recovery_active: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "observed_at", _timestamp(self.observed_at, self.closed_bar, self.timeframe)
        )
        for name in (
            "price",
            "atr_h1",
            "donchian_low_h4",
            "donchian_high_h4",
            "ema50_h1",
            "ema50_slope_h1",
            "adx_h1",
            "atr_percentile_h1",
            "spread_multiple",
            "realized_vol_percentile",
        ):
            _decimal(getattr(self, name))
        if self.price <= _ZERO or self.atr_h1 <= _ZERO:
            raise MtrPortError("INPUT_INVALID")
        if self.donchian_high_h4 <= self.donchian_low_h4:
            raise MtrPortError("INPUT_INVALID")
        if (
            type(self.bars_on_ema_side) is not int
            or type(self.trend_persistence_bars) is not int
            or self.bars_on_ema_side < 0
            or self.trend_persistence_bars < 0
        ):
            raise MtrPortError("INPUT_INVALID")
        if (
            self.adx_h1 < _ZERO
            or self.adx_h1 > Decimal("100")
            or self.atr_percentile_h1 < _ZERO
            or self.atr_percentile_h1 > Decimal("100")
        ):
            raise MtrPortError("INPUT_INVALID")
        if (
            self.spread_multiple < _ZERO
            or self.realized_vol_percentile < _ZERO
            or self.realized_vol_percentile > Decimal("100")
        ):
            raise MtrPortError("INPUT_INVALID")
        if type(self.donchian_breakout) is not bool or type(self.adx_rising) is not bool:
            raise MtrPortError("INPUT_INVALID")
        if type(self.recovery_active) is not bool:
            raise MtrPortError("INPUT_INVALID")


@dataclass(frozen=True, slots=True)
class SovereignCapsV1:
    """Risk ceilings plus the typed strategy-level add-count configuration."""

    max_adds: int = _DEFAULT_MAX_ADDS
    max_order_units: Decimal = Decimal("1")
    max_position_units: Decimal = Decimal("1")
    max_gross_leverage: Decimal = _FIVE
    max_net_leverage: Decimal = Decimal("3")
    max_daily_drawdown_pct: Decimal = Decimal("3")
    max_weekly_drawdown_pct: Decimal = Decimal("6")
    max_trailing_drawdown_pct: Decimal = Decimal("8")
    max_portfolio_heat_pct: Decimal = Decimal("5")
    max_per_position_heat_pct: Decimal = Decimal("1")

    def __post_init__(self) -> None:
        if type(self.max_adds) is not int or not 0 <= self.max_adds <= _SOURCE_MAX_ADDS:
            raise MtrPortError("SOVEREIGN_CAP_INVALID")
        for name in (
            "max_order_units",
            "max_position_units",
            "max_gross_leverage",
            "max_net_leverage",
            "max_daily_drawdown_pct",
            "max_weekly_drawdown_pct",
            "max_trailing_drawdown_pct",
            "max_portfolio_heat_pct",
            "max_per_position_heat_pct",
        ):
            val = _decimal(getattr(self, name))
            if val <= _ZERO:
                raise MtrPortError("SOVEREIGN_CAP_INVALID")
        if self.max_order_units > Decimal("1") or self.max_position_units > Decimal("1"):
            raise MtrPortError("SOVEREIGN_CAP_INVALID")
        if self.max_gross_leverage > _FIVE:
            raise MtrPortError("SOVEREIGN_CAP_INVALID")
        if self.max_net_leverage > Decimal("3"):
            raise MtrPortError("SOVEREIGN_CAP_INVALID")
        if self.max_daily_drawdown_pct > Decimal("3"):
            raise MtrPortError("SOVEREIGN_CAP_INVALID")
        if self.max_weekly_drawdown_pct > Decimal("6"):
            raise MtrPortError("SOVEREIGN_CAP_INVALID")
        if self.max_trailing_drawdown_pct > _EIGHT:
            raise MtrPortError("SOVEREIGN_CAP_INVALID")
        if self.max_portfolio_heat_pct > _FIVE or self.max_per_position_heat_pct > _ONE:
            raise MtrPortError("SOVEREIGN_CAP_INVALID")


DEFAULT_SOVEREIGN_CAPS_V1 = SovereignCapsV1()


@dataclass(frozen=True, slots=True)
class GridAddInputV1:
    regime: MtrRegimeInputV1
    side: TradeSideV1
    last_add_price: Decimal
    base_order_units: Decimal
    adds_count: int
    current_position_units: Decimal
    gross_leverage: Decimal
    net_leverage: Decimal
    daily_drawdown_pct: Decimal
    weekly_drawdown_pct: Decimal
    trailing_drawdown_pct: Decimal
    portfolio_heat_pct: Decimal
    per_position_heat_pct: Decimal
    zone_armed: bool
    halted: bool
    trading_hour: bool


@dataclass(frozen=True, slots=True)
class GridAddDecisionV1:
    allowed: bool
    reason: str
    regime: RegimeStateV1
    grid_step_price: Decimal
    proposed_units: Decimal
    normalized_at: datetime


def classify_regime(observation: MtrRegimeInputV1) -> RegimeStateV1:
    """Classify using the documented six-state v0 rules on a closed M5 bar."""
    if type(observation) is not MtrRegimeInputV1:
        raise MtrPortError("INPUT_INVALID")
    trend_up = (
        observation.ema50_slope_h1 > _ZERO
        and observation.price > observation.ema50_h1
        and observation.bars_on_ema_side >= 12
        and observation.adx_h1 > _ADX_THRESHOLD
    )
    trend_down = (
        observation.ema50_slope_h1 < _ZERO
        and observation.price < observation.ema50_h1
        and observation.bars_on_ema_side >= 12
        and observation.adx_h1 > _ADX_THRESHOLD
    )
    if observation.recovery_active:
        return RegimeStateV1.RECOVERY_MODE
    crisis = (
        (trend_up or trend_down)
        and observation.trend_persistence_bars >= 24
        and observation.spread_multiple > _TWO
        and observation.realized_vol_percentile > _NINETY
    )
    if crisis:
        return RegimeStateV1.CRISIS_ONE_WAY
    if (
        observation.atr_percentile_h1 > _SEVENTY
        and observation.donchian_breakout
        and observation.adx_rising
    ):
        return RegimeStateV1.VOL_EXPANSION
    if trend_up:
        return RegimeStateV1.TREND_UP
    if trend_down:
        return RegimeStateV1.TREND_DOWN
    within_range = (
        observation.donchian_low_h4 - Decimal("0.5") * observation.atr_h1
        <= observation.price
        <= observation.donchian_high_h4 + Decimal("0.5") * observation.atr_h1
    )
    if observation.adx_h1 < _ADX_THRESHOLD and within_range:
        return RegimeStateV1.RANGE_NORMAL
    raise MtrPortError("REGIME_UNCLASSIFIED")


def propose_grid_add(
    request: GridAddInputV1, *, caps: SovereignCapsV1 = DEFAULT_SOVEREIGN_CAPS_V1
) -> GridAddDecisionV1:
    """Return a deterministic advisory grid-add proposal, never an order."""
    if type(request) is not GridAddInputV1 or type(caps) is not SovereignCapsV1:
        raise MtrPortError("INPUT_INVALID")
    observed = request.regime
    regime = classify_regime(observed)
    price = _decimal(observed.price)
    atr = _decimal(observed.atr_h1)
    last = _decimal(request.last_add_price)
    base = _decimal(request.base_order_units)
    current_units = _decimal(request.current_position_units)
    if type(request.side) is not TradeSideV1 or type(request.adds_count) is not int:
        raise MtrPortError("INPUT_INVALID")
    if request.adds_count < 0 or current_units < _ZERO or last <= _ZERO or base <= _ZERO:
        raise MtrPortError("INPUT_INVALID")
    step = max(price * _GRID_PCT, atr * _GRID_ATR)
    multiplier = Decimal("1")
    if request.adds_count in (3, 4):
        multiplier = Decimal("1.25")
    elif request.adds_count >= 5:
        multiplier = Decimal("1.5")
    proposed = base * multiplier
    normalized_at = observed.observed_at
    metrics = (
        ("gross_leverage", request.gross_leverage, caps.max_gross_leverage),
        ("net_leverage", request.net_leverage, caps.max_net_leverage),
        ("daily_drawdown_pct", request.daily_drawdown_pct, caps.max_daily_drawdown_pct),
        ("weekly_drawdown_pct", request.weekly_drawdown_pct, caps.max_weekly_drawdown_pct),
        ("trailing_drawdown_pct", request.trailing_drawdown_pct, caps.max_trailing_drawdown_pct),
        ("portfolio_heat_pct", request.portfolio_heat_pct, caps.max_portfolio_heat_pct),
        ("per_position_heat_pct", request.per_position_heat_pct, caps.max_per_position_heat_pct),
    )
    parsed_metrics: list[tuple[str, Decimal, Decimal]] = []
    for name, raw, cap in metrics:
        value = _decimal(raw)
        if value < _ZERO:
            raise MtrPortError("INPUT_INVALID")
        parsed_metrics.append((name, value, cap))

    reason = "ALLOWED"
    if any(
        type(value) is not bool
        for value in (request.zone_armed, request.halted, request.trading_hour)
    ):
        raise MtrPortError("INPUT_INVALID")
    if request.halted:
        reason = "HALT_ACTIVE"
    elif not request.trading_hour:
        reason = "OUTSIDE_TRADING_HOURS"
    elif not request.zone_armed:
        reason = "ZONE_NOT_ARMED"
    elif request.adds_count < 0 or request.adds_count >= caps.max_adds:
        reason = "MAX_ADDS"
    elif (
        request.side is TradeSideV1.BUY
        and regime not in (RegimeStateV1.RANGE_NORMAL, RegimeStateV1.TREND_DOWN)
    ) or (
        request.side is TradeSideV1.SELL
        and regime not in (RegimeStateV1.RANGE_NORMAL, RegimeStateV1.TREND_UP)
    ):
        reason = "REGIME_BLOCK"
    elif observed.spread_multiple > _THREE:
        reason = "SPREAD_LIMIT"
    elif not (
        (request.side is TradeSideV1.BUY and price <= last - step)
        or (request.side is TradeSideV1.SELL and price >= last + step)
    ):
        reason = "ADVERSE_GRID_TRIGGER_NOT_MET"
    else:
        if base > caps.max_order_units or proposed > caps.max_order_units:
            reason = "ORDER_SIZE_CAP"
        elif current_units + proposed > caps.max_position_units:
            reason = "POSITION_SIZE_CAP"
        else:
            for name, value, cap in parsed_metrics:
                if value >= cap:
                    reason = f"SOVEREIGN_{name.upper()}"
                    break
    return GridAddDecisionV1(
        allowed=reason == "ALLOWED",
        reason=reason,
        regime=regime,
        grid_step_price=step,
        proposed_units=proposed,
        normalized_at=normalized_at,
    )
