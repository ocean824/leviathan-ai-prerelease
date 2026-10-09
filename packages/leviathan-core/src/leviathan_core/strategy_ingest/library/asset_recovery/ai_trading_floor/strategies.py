"""Typed, deterministic port of the AI Trading Floor signal rules.

Parity conventions follow the source's ``CONVENTIONS.md`` and strategy docs:
signals are lagged one bar, breakouts exclude the current bar, RSI uses Wilder
smoothing, Bollinger deviation is sample standard deviation, and pivots are
usable only after their right-hand confirmation bars. This module is pure.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass
from decimal import Decimal, localcontext
from fractions import Fraction
from typing import Literal

from leviathan_core.numeric import Ratio, parse_decimal, quotient_final
from leviathan_core.numeric._context import numeric_context

Position = Literal["LONG", "SHORT", "FLAT"]
STRATEGY_IDS = (
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
)


class AIFloorPortError(ValueError):
    """Content-free strategy input error."""

    def __init__(self, code: str = "STRATEGY_INPUT_INVALID") -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class AIFloorOHLCVBarV1:
    timestamp_ns: int
    open: Decimal
    high: Decimal
    low: Decimal
    close: Decimal
    volume: Decimal

    def __post_init__(self) -> None:
        if (
            type(self.timestamp_ns) is not int
            or not 0 <= self.timestamp_ns <= 253402300799999999999
        ):
            raise AIFloorPortError()
        for name in ("open", "high", "low", "close", "volume"):
            value = getattr(self, name)
            try:
                parse_decimal(value, field=name)
            except (TypeError, ValueError):
                raise AIFloorPortError() from None
            if value < 0 or (name != "volume" and value == 0):
                raise AIFloorPortError()
        if self.high < max(self.open, self.close, self.low) or self.low > min(
            self.open, self.close
        ):
            raise AIFloorPortError()


@dataclass(frozen=True, slots=True)
class AIFloorStrategySpecV1:
    strategy_id: str
    parameters: tuple[tuple[str, Decimal | int], ...] = ()

    def __post_init__(self) -> None:
        if self.strategy_id not in STRATEGY_IDS or type(self.parameters) is not tuple:
            raise AIFloorPortError()
        names: set[str] = set()
        for item in self.parameters:
            if type(item) is not tuple or len(item) != 2 or type(item[0]) is not str:
                raise AIFloorPortError()
            name, value = item
            if not name or name in names:
                raise AIFloorPortError()
            names.add(name)
            if type(value) is int:
                if value <= 0:
                    raise AIFloorPortError()
            else:
                try:
                    parse_decimal(value, field=name)
                except (TypeError, ValueError):
                    raise AIFloorPortError() from None

    def get(self, name: str, default: Decimal | int) -> Decimal | int:
        return dict(self.parameters).get(name, default)


@dataclass(frozen=True, slots=True)
class AIFloorSignalV1:
    timestamp_ns: int
    position: Position
    stop_price: Decimal | None = None
    target_price: Decimal | None = None

    def __post_init__(self) -> None:
        if type(self.timestamp_ns) is not int or self.timestamp_ns < 0:
            raise AIFloorPortError()
        if self.position not in ("LONG", "SHORT", "FLAT"):
            raise AIFloorPortError()
        for value in (self.stop_price, self.target_price):
            if value is not None:
                try:
                    parse_decimal(value, field="price")
                except (TypeError, ValueError):
                    raise AIFloorPortError() from None
                if value <= 0:
                    raise AIFloorPortError()


def _mean(xs: list[Decimal]) -> Decimal:
    total = sum((Fraction(x) for x in xs), Fraction())
    return quotient_final(Ratio(total.numerator, total.denominator), len(xs))


def _std(xs: list[Decimal], sample: bool = False) -> Decimal:
    n = len(xs) - int(sample)
    if n <= 0:
        return Decimal(0)
    mean = sum((Fraction(x) for x in xs), Fraction()) / len(xs)
    variance = sum(((Fraction(x) - mean) ** 2 for x in xs), Fraction()) / n
    # Deterministic decimal square root by integer scaling; final output is rounded once.
    scale = 10**18
    q = variance.numerator * scale * scale // variance.denominator
    root = __import__("math").isqrt(q)
    return Decimal(root).scaleb(-18)


def _rsi(closes: list[Decimal], period: int) -> list[Decimal]:
    out = [Decimal(50)] * len(closes)
    if len(closes) <= period:
        return out
    gains = [max(closes[i] - closes[i - 1], Decimal(0)) for i in range(1, len(closes))]
    losses = [max(closes[i - 1] - closes[i], Decimal(0)) for i in range(1, len(closes))]
    ag, al = _mean(gains[:period]), _mean(losses[:period])

    def value(g: Decimal, loss: Decimal) -> Decimal:
        if loss == 0:
            return Decimal(100) if g else Decimal(50)
        result = Fraction(100) * Fraction(g) / (Fraction(g) + Fraction(loss))
        return quotient_final(Ratio(result.numerator, result.denominator), 1)

    out[period] = value(ag, al)
    for i in range(period + 1, len(closes)):
        agf = (Fraction(ag * (period - 1)) + Fraction(gains[i - 1])) / period
        alf = (Fraction(al * (period - 1)) + Fraction(losses[i - 1])) / period
        ag = quotient_final(Ratio(agf.numerator, agf.denominator), 1)
        al = quotient_final(Ratio(alf.numerator, alf.denominator), 1)
        out[i] = value(ag, al)
    return out


def _atr(bars: tuple[AIFloorOHLCVBarV1, ...], period: int) -> list[Decimal]:
    ranges: list[Decimal] = []
    for i, bar in enumerate(bars):
        prior = bars[i - 1].close if i else bar.close
        ranges.append(max(bar.high - bar.low, abs(bar.high - prior), abs(bar.low - prior)))
    return [_mean(ranges[max(0, i - period + 1) : i + 1]) for i in range(len(ranges))]


def _evaluate_signals(
    bars: tuple[AIFloorOHLCVBarV1, ...], spec: AIFloorStrategySpecV1
) -> tuple[AIFloorSignalV1, ...]:
    """Evaluate a source strategy without future-bar access."""
    if type(bars) is not tuple or not bars or any(type(x) is not AIFloorOHLCVBarV1 for x in bars):
        raise AIFloorPortError()
    if any(a.timestamp_ns >= b.timestamp_ns for a, b in itertools.pairwise(bars)):
        raise AIFloorPortError()
    closes = [x.close for x in bars]
    highs = [x.high for x in bars]
    lows = [x.low for x in bars]
    volumes = [x.volume for x in bars]
    n = len(bars)
    fast, slow = int(spec.get("fast", 20)), int(spec.get("slow", 50))
    lookback = int(spec.get("lookback", 20))
    rsi_period = int(spec.get("rsi_period", 14))
    atr_period = int(spec.get("atr_period", 14))
    rsi = _rsi(closes, rsi_period)
    atr = _atr(bars, atr_period)
    positions: list[Position] = ["FLAT"] * n
    stops: list[Decimal | None] = [None] * n
    active: Position = "FLAT"
    pivot: Decimal | None = None
    vwap_num = Fraction()
    vwap_den = Fraction()
    for i in range(n):
        close = closes[i]
        i - 1
        if spec.strategy_id == "sma_crossover":
            active = (
                "LONG"
                if i + 1 >= slow
                and _mean(closes[i + 1 - fast : i + 1]) > _mean(closes[i + 1 - slow : i + 1])
                else "FLAT"
            )
        elif spec.strategy_id == "breakout":
            active = "LONG" if i >= lookback and close > max(highs[i - lookback : i]) else "FLAT"
        elif spec.strategy_id == "short_breakdown":
            active = "SHORT" if i >= lookback and close < min(lows[i - lookback : i]) else "FLAT"
        elif spec.strategy_id == "short_trend":
            active = (
                "SHORT"
                if i >= 199
                and close < _mean(closes[i - 49 : i + 1])
                and _mean(closes[i - 49 : i + 1]) < _mean(closes[i - 199 : i + 1])
                else "FLAT"
            )
        elif spec.strategy_id == "rsi_reversion":
            buy, sell = spec.get("buy_rsi", 30), spec.get("sell_rsi", 55)
            active = (
                "LONG"
                if (active == "LONG" and rsi[i] <= sell) or (active != "LONG" and rsi[i] < buy)
                else "FLAT"
            )
        elif spec.strategy_id == "breakout" or spec.strategy_id == "donchian_trend":
            entry, exit_ = int(spec.get("entry_lookback", 55)), int(spec.get("exit_lookback", 20))
            active = (
                "LONG"
                if (active == "LONG" and i >= exit_ and close >= min(lows[i - exit_ : i]))
                or (active != "LONG" and i >= entry and close > max(highs[i - entry : i]))
                else "FLAT"
            )
            if active == "LONG" and spec.strategy_id == "donchian_trend":
                stops[i] = close - Decimal(2) * atr[i]
        elif spec.strategy_id in ("bollinger_meanrev", "vol_gate_trend", "dual_momentum"):
            if spec.strategy_id == "bollinger_meanrev":
                window = int(spec.get("band_period", 20))
                band = _mean(closes[max(0, i - window + 1) : i + 1]) - Decimal(2) * _std(
                    closes[max(0, i - window + 1) : i + 1], sample=True
                )
                active = (
                    "LONG"
                    if close < band
                    and (i < 199 or close > _mean(closes[i - 199 : i + 1]))
                    and rsi[i] < 35
                    else "FLAT"
                )
                if active == "LONG":
                    stops[i] = bars[i].low - Decimal("0.5") * atr[i]
            elif spec.strategy_id == "vol_gate_trend":
                returns = []
                for j in range(max(1, i - 19), i + 1):
                    ret = Fraction(closes[j] - closes[j - 1]) / Fraction(closes[j - 1])
                    returns.append(quotient_final(Ratio(ret.numerator, ret.denominator), 1))
                vol = _std(returns) * Decimal("15.874507866") if len(returns) > 1 else Decimal(0)
                active = (
                    "LONG"
                    if i >= 199
                    and close > _mean(closes[i - 49 : i + 1]) > _mean(closes[i - 199 : i + 1])
                    and vol < spec.get("max_vol", Decimal("0.20"))
                    else "FLAT"
                )
                if active == "LONG":
                    stops[i] = close - Decimal(3) * atr[i]
            else:
                lb, skip = int(spec.get("momentum_lookback", 252)), int(spec.get("skip", 21))
                active = (
                    "LONG"
                    if i >= lb
                    and close > _mean(closes[i - 199 : i + 1])
                    and closes[i - skip] > closes[i - lb]
                    else "FLAT"
                )
        elif spec.strategy_id == "anchored_vwap_trend":
            confirmation = int(spec.get("pivot_lookback", 5))
            p = i - confirmation
            if (
                p >= confirmation
                and lows[p] < min(lows[p - confirmation : p])
                and lows[p] < min(lows[p + 1 : p + confirmation + 1])
            ):
                pivot = lows[p]
                vwap_num, vwap_den = Fraction(), Fraction()
            hlc_fraction = (
                Fraction(bars[i].high) + Fraction(bars[i].low) + Fraction(bars[i].close)
            ) / 3
            hlc3 = quotient_final(Ratio(hlc_fraction.numerator, hlc_fraction.denominator), 1)
            vwap_num += Fraction(hlc3) * Fraction(volumes[i])
            vwap_den += Fraction(volumes[i])
            vwap_value = vwap_num / vwap_den if vwap_den else Fraction(close)
            vwap = quotient_final(Ratio(vwap_value.numerator, vwap_value.denominator), 1)
            active = (
                "LONG"
                if pivot is not None
                and close > vwap
                and (i < 49 or close > _mean(closes[i - 49 : i + 1]))
                else "FLAT"
            )
        positions[i] = active
    return tuple(AIFloorSignalV1(bars[i].timestamp_ns, positions[i], stops[i]) for i in range(n))


def evaluate_signals(
    bars: tuple[AIFloorOHLCVBarV1, ...], spec: AIFloorStrategySpecV1
) -> tuple[AIFloorSignalV1, ...]:
    """Run the signal implementation in a kernel-owned bounded Decimal context."""
    with localcontext(numeric_context(final_quotient=True)):
        return _evaluate_signals(bars, spec)
