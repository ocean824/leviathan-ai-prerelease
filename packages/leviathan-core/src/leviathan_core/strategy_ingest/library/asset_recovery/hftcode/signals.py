"""Pure, closed-bar signal calculations ported from the reviewed HFTCODE assets.

This module has no broker, network, order, or persistence integration. Its
outputs are advisory signals; an accepted order is not a fill and positions
must come from reconciled execution state.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from decimal import Decimal, localcontext
from enum import StrEnum
from itertools import pairwise
from typing import Literal

_MAX_BARS = 10_000
_D = Decimal
_ZERO = _D("0")
_ONE = _D("1")


class HftCodeError(ValueError):
    """Content-free validation failure for HFTCODE signal inputs."""

    def __init__(self, code: Literal["INVALID_INPUT", "UNSUPPORTED_STRATEGY"]) -> None:
        self.code = code
        super().__init__(code)


class HftCodeStrategyId(StrEnum):
    BHP_ASX_SMA_10_50 = "BHP_ASX_SMA_10_50"
    NVDA_US_SMA_10_50 = "NVDA_US_SMA_10_50"
    EURUSD_RSI14 = "EURUSD_RSI14"
    XAUUSD_BOLLINGER20 = "XAUUSD_BOLLINGER20"


class HftCodeAction(StrEnum):
    HOLD = "HOLD"
    ENTER_LONG = "ENTER_LONG"
    ENTER_SHORT = "ENTER_SHORT"
    EXIT = "EXIT"


class HftCodeReason(StrEnum):
    INSUFFICIENT_HISTORY = "INSUFFICIENT_HISTORY"
    NO_SIGNAL = "NO_SIGNAL"
    POSITION_HELD = "POSITION_HELD"
    GOLDEN_CROSS = "GOLDEN_CROSS"
    DEATH_CROSS = "DEATH_CROSS"
    STOP_LOSS = "STOP_LOSS"
    PROFIT_TARGET = "PROFIT_TARGET"
    RSI_OVERSOLD = "RSI_OVERSOLD"
    RSI_OVERBOUGHT = "RSI_OVERBOUGHT"
    RSI_NEUTRAL_EXIT = "RSI_NEUTRAL_EXIT"
    LOWER_BAND_BREAKOUT = "LOWER_BAND_BREAKOUT"
    UPPER_BAND_BREAKOUT = "UPPER_BAND_BREAKOUT"
    MIDDLE_BAND_REVERSION = "MIDDLE_BAND_REVERSION"


@dataclass(frozen=True, slots=True)
class HftCodeBarV1:
    """One finalized bar; timestamps are UTC nanoseconds and closes are exact."""

    timestamp_ns: int
    close: Decimal

    def __post_init__(self) -> None:
        if type(self.timestamp_ns) is not int or self.timestamp_ns < 0:
            raise HftCodeError("INVALID_INPUT")
        if type(self.close) is not Decimal or not self.close.is_finite() or self.close <= _ZERO:
            raise HftCodeError("INVALID_INPUT")


@dataclass(frozen=True, slots=True)
class HftCodePositionV1:
    """A currently reconciled position supplied by the caller."""

    side: Literal["LONG", "SHORT"]
    entry_price: Decimal

    def __post_init__(self) -> None:
        if self.side not in {"LONG", "SHORT"}:
            raise HftCodeError("INVALID_INPUT")
        if (
            type(self.entry_price) is not Decimal
            or not self.entry_price.is_finite()
            or self.entry_price <= _ZERO
        ):
            raise HftCodeError("INVALID_INPUT")


@dataclass(frozen=True, slots=True)
class HftCodeSignalV1:
    """Non-executable signal evidence. It contains no order or fill field."""

    strategy_id: HftCodeStrategyId
    instrument_id: str
    action: HftCodeAction
    reason: HftCodeReason
    timestamp_ns: int
    reference_price: Decimal
    indicators: tuple[tuple[str, Decimal], ...]
    source_sha256: str


# Hashes bind the selected source text used for this clean-room algorithm port.
_SOURCE_SHA256: dict[HftCodeStrategyId, str] = {
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

_INSTRUMENT: dict[HftCodeStrategyId, str] = {
    HftCodeStrategyId.BHP_ASX_SMA_10_50: "BHP.ASX",
    HftCodeStrategyId.NVDA_US_SMA_10_50: "NVDA.US",
    HftCodeStrategyId.EURUSD_RSI14: "EURUSD",
    HftCodeStrategyId.XAUUSD_BOLLINGER20: "XAUUSD",
}


def _validate_inputs(
    strategy_id: HftCodeStrategyId,
    bars: Sequence[HftCodeBarV1],
    position: HftCodePositionV1 | None,
) -> tuple[HftCodeBarV1, ...]:
    if type(strategy_id) is not HftCodeStrategyId:
        raise HftCodeError("UNSUPPORTED_STRATEGY")
    if type(bars) not in {tuple, list} or not 1 <= len(bars) <= _MAX_BARS:
        raise HftCodeError("INVALID_INPUT")
    if position is not None and type(position) is not HftCodePositionV1:
        raise HftCodeError("INVALID_INPUT")
    values = tuple(bars)
    if any(type(bar) is not HftCodeBarV1 for bar in values):
        raise HftCodeError("INVALID_INPUT")
    if any(left.timestamp_ns >= right.timestamp_ns for left, right in pairwise(values)):
        raise HftCodeError("INVALID_INPUT")
    if (
        strategy_id
        in {
            HftCodeStrategyId.BHP_ASX_SMA_10_50,
            HftCodeStrategyId.NVDA_US_SMA_10_50,
        }
        and position is not None
        and position.side != "LONG"
    ):
        raise HftCodeError("INVALID_INPUT")
    return values


def _signal(
    strategy_id: HftCodeStrategyId,
    bars: tuple[HftCodeBarV1, ...],
    action: HftCodeAction,
    reason: HftCodeReason,
    indicators: tuple[tuple[str, Decimal], ...] = (),
) -> HftCodeSignalV1:
    latest = bars[-1]
    return HftCodeSignalV1(
        strategy_id=strategy_id,
        instrument_id=_INSTRUMENT[strategy_id],
        action=action,
        reason=reason,
        timestamp_ns=latest.timestamp_ns,
        reference_price=latest.close,
        indicators=indicators,
        source_sha256=_SOURCE_SHA256[strategy_id],
    )


def _sma(values: tuple[HftCodeBarV1, ...], period: int) -> Decimal:
    window = values[-period:]
    return sum((bar.close for bar in window), _ZERO) / _D(period)


def _evaluate_sma(
    strategy_id: HftCodeStrategyId,
    bars: tuple[HftCodeBarV1, ...],
    position: HftCodePositionV1 | None,
) -> HftCodeSignalV1:
    if len(bars) < 51:
        return _signal(strategy_id, bars, HftCodeAction.HOLD, HftCodeReason.INSUFFICIENT_HISTORY)
    fast_now, slow_now = _sma(bars, 10), _sma(bars, 50)
    previous = bars[:-1]
    fast_before, slow_before = _sma(previous, 10), _sma(previous, 50)
    up = fast_now > slow_now and fast_before <= slow_before
    down = fast_now <= slow_now and fast_before > slow_before
    price = bars[-1].close
    values = (("fast_sma_10", fast_now), ("slow_sma_50", slow_now))
    if position is None:
        if up:
            return _signal(
                strategy_id, bars, HftCodeAction.ENTER_LONG, HftCodeReason.GOLDEN_CROSS, values
            )
        return _signal(strategy_id, bars, HftCodeAction.HOLD, HftCodeReason.NO_SIGNAL, values)
    with localcontext() as context:
        context.prec = 28
        pnl = (price - position.entry_price) / position.entry_price
    if down:
        reason = HftCodeReason.DEATH_CROSS
    elif pnl <= _D("-0.03"):
        reason = HftCodeReason.STOP_LOSS
    elif pnl >= _D("0.05"):
        reason = HftCodeReason.PROFIT_TARGET
    else:
        return _signal(strategy_id, bars, HftCodeAction.HOLD, HftCodeReason.POSITION_HELD, values)
    return _signal(strategy_id, bars, HftCodeAction.EXIT, reason, values)


def _rsi(bars: tuple[HftCodeBarV1, ...]) -> Decimal:
    changes = tuple(right.close - left.close for left, right in pairwise(bars))[-14:]
    gains = sum((change for change in changes if change > _ZERO), _ZERO)
    losses = sum((-change for change in changes if change < _ZERO), _ZERO)
    avg_gain, avg_loss = gains / _D(14), losses / _D(14)
    # Preserve the source algorithm's zero-loss convention, including a flat window.
    if avg_loss == _ZERO:
        return _D(100)
    if avg_gain == _ZERO:
        return _ZERO
    relative_strength = avg_gain / avg_loss
    return _D(100) - (_D(100) / (_ONE + relative_strength))


def _evaluate_rsi(
    bars: tuple[HftCodeBarV1, ...], position: HftCodePositionV1 | None
) -> HftCodeSignalV1:
    strategy_id = HftCodeStrategyId.EURUSD_RSI14
    if len(bars) < 15:
        return _signal(strategy_id, bars, HftCodeAction.HOLD, HftCodeReason.INSUFFICIENT_HISTORY)
    with localcontext() as context:
        context.prec = 28
        rsi = _rsi(bars)
    current = bars[-1].close
    indicators = (("rsi_14", rsi),)
    if position is None:
        if rsi < _D(30):
            return _signal(
                strategy_id, bars, HftCodeAction.ENTER_LONG, HftCodeReason.RSI_OVERSOLD, indicators
            )
        if rsi > _D(70):
            return _signal(
                strategy_id,
                bars,
                HftCodeAction.ENTER_SHORT,
                HftCodeReason.RSI_OVERBOUGHT,
                indicators,
            )
        return _signal(strategy_id, bars, HftCodeAction.HOLD, HftCodeReason.NO_SIGNAL, indicators)
    pip = _D("0.0001")
    if position.side == "LONG":
        pnl_pips = (current - position.entry_price) / pip
        rsi_exit = rsi >= _D(55)
    else:
        pnl_pips = (position.entry_price - current) / pip
        rsi_exit = rsi <= _D(45)
    if rsi_exit:
        reason = HftCodeReason.RSI_NEUTRAL_EXIT
    elif pnl_pips <= _D(-50):
        reason = HftCodeReason.STOP_LOSS
    elif pnl_pips >= _D(100):
        reason = HftCodeReason.PROFIT_TARGET
    else:
        return _signal(
            strategy_id, bars, HftCodeAction.HOLD, HftCodeReason.POSITION_HELD, indicators
        )
    return _signal(strategy_id, bars, HftCodeAction.EXIT, reason, indicators)


def _evaluate_bollinger(
    bars: tuple[HftCodeBarV1, ...], position: HftCodePositionV1 | None
) -> HftCodeSignalV1:
    strategy_id = HftCodeStrategyId.XAUUSD_BOLLINGER20
    if len(bars) < 20:
        return _signal(strategy_id, bars, HftCodeAction.HOLD, HftCodeReason.INSUFFICIENT_HISTORY)
    with localcontext() as context:
        context.prec = 28
        window = tuple(bar.close for bar in bars[-20:])
        middle = sum(window, _ZERO) / _D(20)
        variance = sum(((price - middle) ** 2 for price in window), _ZERO) / _D(20)
        deviation = variance.sqrt()
        upper, lower = middle + (_D(2) * deviation), middle - (_D(2) * deviation)
        price = bars[-1].close
        indicators = (("lower_band", lower), ("middle_band", middle), ("upper_band", upper))
        if position is None:
            if price > upper:
                return _signal(
                    strategy_id,
                    bars,
                    HftCodeAction.ENTER_LONG,
                    HftCodeReason.UPPER_BAND_BREAKOUT,
                    indicators,
                )
            if price < lower:
                return _signal(
                    strategy_id,
                    bars,
                    HftCodeAction.ENTER_SHORT,
                    HftCodeReason.LOWER_BAND_BREAKOUT,
                    indicators,
                )
            return _signal(
                strategy_id, bars, HftCodeAction.HOLD, HftCodeReason.NO_SIGNAL, indicators
            )
        if position.side == "LONG":
            pnl = (price - position.entry_price) / position.entry_price
            reverted = price <= middle
        else:
            pnl = (position.entry_price - price) / position.entry_price
            reverted = price >= middle
        if reverted:
            reason = HftCodeReason.MIDDLE_BAND_REVERSION
        elif pnl <= _D("-0.015"):
            reason = HftCodeReason.STOP_LOSS
        elif pnl >= _D("0.03"):
            reason = HftCodeReason.PROFIT_TARGET
        else:
            return _signal(
                strategy_id, bars, HftCodeAction.HOLD, HftCodeReason.POSITION_HELD, indicators
            )
        return _signal(strategy_id, bars, HftCodeAction.EXIT, reason, indicators)


def evaluate_hftcode_signal(
    strategy_id: HftCodeStrategyId,
    bars: Sequence[HftCodeBarV1],
    position: HftCodePositionV1 | None = None,
) -> HftCodeSignalV1:
    """Evaluate one closed-bar window without side effects or execution authority."""
    values = _validate_inputs(strategy_id, bars, position)
    # Pin precision so a caller's process-global Decimal context cannot alter
    # the emitted signal or the strategy's comparison thresholds.
    with localcontext() as context:
        context.prec = 28
        if strategy_id in {
            HftCodeStrategyId.BHP_ASX_SMA_10_50,
            HftCodeStrategyId.NVDA_US_SMA_10_50,
        }:
            return _evaluate_sma(strategy_id, values, position)
        if strategy_id is HftCodeStrategyId.EURUSD_RSI14:
            return _evaluate_rsi(values, position)
        if strategy_id is HftCodeStrategyId.XAUUSD_BOLLINGER20:
            return _evaluate_bollinger(values, position)
    raise HftCodeError("UNSUPPORTED_STRATEGY")
