"""Deterministic, paper-gated ports of the bitcoin-course OHLC strategies.

The source calls three proxies HMM, order flow, and pairs trading. They are
labelled here by what the code actually computes: volatility-percentile regime,
signed-volume order-flow proxy, and single-series mean-reversion proxy. This
module emits signals and offline accounting only; it cannot submit orders.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from decimal import Decimal, localcontext
from itertools import pairwise
from typing import Literal, NoReturn, SupportsIndex, cast

from leviathan_core.numeric import NumericError, parse_decimal
from leviathan_core.numeric._context import numeric_context

CourseStrategyId = Literal[
    "momentum",
    "mean_reversion",
    "vwap",
    "kalman_trend",
    "volatility_percentile_regime_proxy",
    "signed_volume_order_flow_proxy",
    "spread_decomposition",
    "volatility_term_structure",
    "single_series_pairs_proxy",
    "ohlc_market_making_proxy",
]

_ZERO = Decimal("0")
_ONE = Decimal("1")
_TWO = Decimal("2")
_HUNDRED = Decimal("100")
_LABELS: dict[CourseStrategyId, str] = {
    "momentum": "ROC momentum with EMA trend filter",
    "mean_reversion": "Bollinger and RSI mean reversion",
    "vwap": "OHLCV VWAP deviation proxy",
    "kalman_trend": "single-price Kalman trend",
    "volatility_percentile_regime_proxy": "volatility-percentile regime proxy (not HMM)",
    "signed_volume_order_flow_proxy": "signed-volume order-flow proxy (not an order book)",
    "spread_decomposition": "high-low spread proxy",
    "volatility_term_structure": "single-series volatility term structure proxy",
    "single_series_pairs_proxy": "single-series moving-average proxy (not cointegration)",
    "ohlc_market_making_proxy": "OHLC market-making proxy (not L2 market making)",
}


class BitcoinCourseStrategyError(ValueError):
    """Content-free invalid-input error for the pure strategy port."""

    _CODES = frozenset(
        {
            "INVALID_BAR",
            "INVALID_CONFIG",
            "INVALID_STRATEGY",
            "INVALID_BACKTEST_INPUT",
            "INVALID_DECIMAL",
            "PRECISION_EXCEEDED",
            "MAGNITUDE_OUT_OF_BOUNDS",
        }
    )

    def __init__(self, code: str) -> None:
        self.code = code if type(code) is str and code in self._CODES else "INVALID_BAR"
        super().__init__(self.code)


class _FrozenNoCopy:
    """Immutable public records cannot be copied or serialized into a new value."""

    __slots__ = ()

    def __copy__(self) -> NoReturn:
        raise TypeError("COPY_FORBIDDEN")

    def __deepcopy__(self, memo: object) -> NoReturn:
        raise TypeError("COPY_FORBIDDEN")

    def __reduce__(self) -> NoReturn:
        raise TypeError("PICKLE_FORBIDDEN")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise TypeError("PICKLE_FORBIDDEN")


def _decimal(value: object, field: str, *, minimum: Decimal | str | None = None) -> Decimal:
    try:
        return parse_decimal(value, field=field, min_value=minimum)
    except NumericError as exc:
        raise BitcoinCourseStrategyError(exc.code) from None


def _positive_int(value: object, *, minimum: int = 1, maximum: int = 10_000) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise BitcoinCourseStrategyError("INVALID_CONFIG")
    return value


@dataclass(frozen=True, slots=True)
class CourseBarV1(_FrozenNoCopy):
    """One ordered OHLCV observation; all prices and volume are exact decimals."""

    timestamp_ns: int
    open: Decimal
    high: Decimal
    low: Decimal
    close: Decimal
    volume: Decimal

    def __post_init__(self) -> None:
        if type(self.timestamp_ns) is not int or not 0 < self.timestamp_ns <= (1 << 63) - 1:
            raise BitcoinCourseStrategyError("INVALID_BAR")
        for name in ("open", "high", "low", "close"):
            object.__setattr__(
                self,
                name,
                _decimal(getattr(self, name), name, minimum="0.000000000000000000000000000000001"),
            )
        object.__setattr__(self, "volume", _decimal(self.volume, "volume", minimum="0"))
        if not self.low <= min(self.open, self.close) <= max(self.open, self.close) <= self.high:
            raise BitcoinCourseStrategyError("INVALID_BAR")


@dataclass(frozen=True, slots=True)
class CourseStrategyConfigV1(_FrozenNoCopy):
    """Source defaults and bounded parameters for every app.py strategy."""

    momentum_lookback: int = 20
    momentum_threshold: Decimal = Decimal("0.02")
    bollinger_period: int = 20
    bollinger_std: Decimal = Decimal("2")
    rsi_period: int = 14
    vwap_deviation_threshold: Decimal = Decimal("0.02")
    kalman_process_noise: Decimal = Decimal("0.01")
    kalman_measurement_noise: Decimal = Decimal("0.1")
    regime_lookback: int = 20
    regime_percentile_window: int = 100
    order_flow_lookback: int = 10
    order_flow_threshold: Decimal = Decimal("0.6")
    spread_lookback: int = 20
    volatility_short_period: int = 5
    volatility_long_period: int = 20
    pairs_lookback: int = 20
    pairs_entry_z: Decimal = Decimal("2")
    market_making_gamma: Decimal = Decimal("0.1")
    market_making_k: Decimal = Decimal("1.5")

    def __post_init__(self) -> None:
        for name in (
            "momentum_lookback",
            "bollinger_period",
            "rsi_period",
            "regime_lookback",
            "regime_percentile_window",
            "order_flow_lookback",
            "spread_lookback",
            "volatility_short_period",
            "volatility_long_period",
            "pairs_lookback",
        ):
            object.__setattr__(self, name, _positive_int(getattr(self, name)))
        for name in (
            "momentum_threshold",
            "bollinger_std",
            "vwap_deviation_threshold",
            "kalman_process_noise",
            "kalman_measurement_noise",
            "order_flow_threshold",
            "pairs_entry_z",
            "market_making_gamma",
            "market_making_k",
        ):
            object.__setattr__(
                self,
                name,
                _decimal(getattr(self, name), name, minimum="0.000000000000000000000000000000001"),
            )
        if self.volatility_short_period >= self.volatility_long_period:
            raise BitcoinCourseStrategyError("INVALID_CONFIG")


@dataclass(frozen=True, slots=True)
class CourseSignalV1(_FrozenNoCopy):
    strategy_id: CourseStrategyId
    label: str
    timestamp_ns: int
    signal: Literal[-1, 0, 1]


@dataclass(frozen=True, slots=True)
class CourseBacktestPointV1(_FrozenNoCopy):
    timestamp_ns: int
    signal: int
    lagged_position: int
    gross_return: Decimal
    commission_cost: Decimal
    net_return: Decimal
    equity: Decimal


_DEFAULT_COURSE_CONFIG = CourseStrategyConfigV1()


def _rolling_mean(values: Sequence[Decimal | None], period: int, end: int) -> Decimal | None:
    start = end - period + 1
    if start < 0 or any(value is None for value in values[start : end + 1]):
        return None
    with localcontext(numeric_context(final_quotient=True)):
        return sum(
            (value for value in values[start : end + 1] if value is not None), _ZERO
        ) / Decimal(period)


def _rolling_std(values: Sequence[Decimal | None], period: int, end: int) -> Decimal | None:
    if period < 2:
        return None
    start = end - period + 1
    if start < 0 or any(value is None for value in values[start : end + 1]):
        return None
    with localcontext(numeric_context(final_quotient=True)):
        samples = [value for value in values[start : end + 1] if value is not None]
        mean = sum(samples, _ZERO) / Decimal(period)
        variance = sum(((value - mean) ** 2 for value in samples), _ZERO) / Decimal(period - 1)
        return variance.sqrt()


def _ema_adjusted(values: tuple[Decimal, ...], span: int) -> list[Decimal]:
    """Pandas ewm(span=..., adjust=True) used by the source app."""
    with localcontext(numeric_context(final_quotient=True)):
        alpha = _TWO / Decimal(span + 1)
        decay = _ONE - alpha
        numerator = _ZERO
        denominator = _ZERO
        result: list[Decimal] = []
        for value in values:
            numerator = value + decay * numerator
            denominator = _ONE + decay * denominator
            result.append(numerator / denominator)
        return result


def _returns(closes: tuple[Decimal, ...]) -> list[Decimal | None]:
    with localcontext(numeric_context(final_quotient=True)):
        return [
            None,
            *((closes[index] / closes[index - 1] - _ONE) for index in range(1, len(closes))),
        ]


def _rsi(closes: tuple[Decimal, ...], period: int) -> list[Decimal | None]:
    changes: list[Decimal | None] = [_ZERO]
    for before, after in pairwise(closes):
        changes.append(after - before)
    gains = [None if change is None else max(change, _ZERO) for change in changes]
    losses = [None if change is None else max(-change, _ZERO) for change in changes]
    result: list[Decimal | None] = []
    with localcontext(numeric_context(final_quotient=True)):
        for index in range(len(closes)):
            gain = _rolling_mean(gains, period, index)
            loss = _rolling_mean(losses, period, index)
            if gain is None or loss is None or (gain == 0 and loss == 0):
                result.append(None)
            elif loss == 0:
                result.append(_HUNDRED)
            else:
                ratio = gain / loss
                result.append(_HUNDRED - _HUNDRED / (_ONE + ratio))
    return result


def _build_signals(
    strategy_id: CourseStrategyId, bars: tuple[CourseBarV1, ...], config: CourseStrategyConfigV1
) -> list[int]:
    closes = tuple(bar.close for bar in bars)
    count = len(bars)
    signal = [0] * count
    with localcontext(numeric_context(final_quotient=True)):
        if strategy_id == "momentum":
            ema_short, ema_long = _ema_adjusted(closes, 10), _ema_adjusted(closes, 30)
            for i in range(count):
                if i < config.momentum_lookback:
                    continue
                roc = closes[i] / closes[i - config.momentum_lookback] - _ONE
                trend_up = ema_short[i] > ema_long[i]
                if roc > config.momentum_threshold and trend_up:
                    signal[i] = 1
                elif roc < -config.momentum_threshold and not trend_up:
                    signal[i] = -1
        elif strategy_id == "mean_reversion":
            rsi = _rsi(closes, config.rsi_period)
            for i in range(count):
                average = _rolling_mean(list(closes), config.bollinger_period, i)
                deviation = _rolling_std(list(closes), config.bollinger_period, i)
                if average is None or deviation is None or rsi[i] is None:
                    continue
                upper = average + deviation * config.bollinger_std
                lower = average - deviation * config.bollinger_std
                rsi_value = rsi[i]
                if rsi_value is None:
                    continue
                if closes[i] < lower and rsi_value < Decimal("30"):
                    signal[i] = 1
                elif closes[i] > upper and rsi_value > Decimal("70"):
                    signal[i] = -1
        elif strategy_id == "vwap":
            cumulative_value = _ZERO
            cumulative_volume = _ZERO
            ema = _ema_adjusted(closes, 20)
            for i, bar in enumerate(bars):
                typical = (bar.high + bar.low + bar.close) / Decimal("3")
                cumulative_value += typical * bar.volume
                cumulative_volume += bar.volume
                if cumulative_volume == 0:
                    continue
                vwap = cumulative_value / cumulative_volume
                deviation = closes[i] / vwap - _ONE
                if deviation < -config.vwap_deviation_threshold and closes[i] > ema[i]:
                    signal[i] = 1
                elif deviation > config.vwap_deviation_threshold and closes[i] <= ema[i]:
                    signal[i] = -1
        elif strategy_id == "kalman_trend":
            estimate = closes[0] if closes else _ZERO
            covariance = _ONE
            estimates = [estimate]
            for price in closes[1:]:
                predicted_covariance = covariance + config.kalman_process_noise
                gain = predicted_covariance / (
                    predicted_covariance + config.kalman_measurement_noise
                )
                estimate += gain * (price - estimate)
                covariance = (_ONE - gain) * predicted_covariance
                estimates.append(estimate)
            for i in range(1, count):
                signal[i] = (
                    1
                    if estimates[i] > estimates[i - 1]
                    else -1
                    if estimates[i] < estimates[i - 1]
                    else 0
                )
        elif strategy_id == "volatility_percentile_regime_proxy":
            returns = _returns(closes)
            volatility = [_rolling_std(returns, config.regime_lookback, i) for i in range(count)]
            ema_short, ema_long = _ema_adjusted(closes, 10), _ema_adjusted(closes, 30)
            for i in range(count):
                start = i - config.regime_percentile_window + 1
                window = volatility[start : i + 1]
                if start < 0 or any(value is None for value in window) or volatility[i] is None:
                    continue
                target = volatility[i]
                assert target is not None
                values = [value for value in window if value is not None]
                less = sum(value < target for value in values)
                equal = sum(value == target for value in values)
                percentile = Decimal(2 * less + equal + 1) / (Decimal("2") * Decimal(len(values)))
                trend = 1 if ema_short[i] > ema_long[i] else -1 if ema_short[i] < ema_long[i] else 0
                mean = _rolling_mean(list(closes), 20, i)
                reversion = (
                    1
                    if mean is not None and closes[i] < mean * Decimal("0.98")
                    else -1
                    if mean is not None and closes[i] > mean * Decimal("1.02")
                    else 0
                )
                signal[i] = trend if percentile < Decimal("0.5") else reversion
        elif strategy_id == "signed_volume_order_flow_proxy":
            buy = [_ZERO]
            sell = [_ZERO]
            for i in range(1, count):
                buy.append(bars[i].volume if closes[i] > closes[i - 1] else _ZERO)
                sell.append(bars[i].volume if closes[i] < closes[i - 1] else _ZERO)
            for i in range(count):
                rolling_buy = _rolling_mean(buy, config.order_flow_lookback, i)
                rolling_sell = _rolling_mean(sell, config.order_flow_lookback, i)
                if rolling_buy is None or rolling_sell is None:
                    continue
                total = rolling_buy + rolling_sell
                imbalance = _ZERO if total == 0 else (rolling_buy - rolling_sell) / total
                signal[i] = (
                    1
                    if imbalance > config.order_flow_threshold
                    else -1
                    if imbalance < -config.order_flow_threshold
                    else 0
                )
        elif strategy_id == "spread_decomposition":
            effective = [(bar.high - bar.low) / bar.close for bar in bars]
            momentum = [
                None,
                *(
                    (closes[i] / closes[i - config.spread_lookback] - _ONE)
                    if i >= config.spread_lookback
                    else None
                    for i in range(1, count)
                ),
            ]
            for i in range(count):
                average = _rolling_mean(effective, config.spread_lookback, i)
                deviation = _rolling_std(effective, config.spread_lookback, i)
                momentum_value = momentum[i]
                if average is None or deviation is None or momentum_value is None:
                    continue
                zscore = (effective[i] - average) / (deviation if deviation != 0 else _ONE)
                if zscore < 0:
                    signal[i] = 1 if momentum_value > 0 else -1 if momentum_value < 0 else 0
        elif strategy_id == "volatility_term_structure":
            returns = _returns(closes)
            short = [_rolling_std(returns, config.volatility_short_period, i) for i in range(count)]
            long = [_rolling_std(returns, config.volatility_long_period, i) for i in range(count)]
            ema_short, ema_long = _ema_adjusted(closes, 10), _ema_adjusted(closes, 30)
            for i in range(count):
                short_value, long_value = short[i], long[i]
                if short_value is None or long_value is None:
                    continue
                ratio = _ONE if long_value == 0 else short_value / long_value
                if ratio < _ONE:
                    signal[i] = (
                        1
                        if ema_short[i] > ema_long[i]
                        else -1
                        if ema_short[i] <= ema_long[i]
                        else 0
                    )
        elif strategy_id == "single_series_pairs_proxy":
            rolling_close = [
                _rolling_mean(list(closes), config.pairs_lookback, i) for i in range(count)
            ]
            spread_series: list[Decimal | None] = []
            for i in range(count):
                rolling_value = rolling_close[i]
                spread_series.append(None if rolling_value is None else closes[i] - rolling_value)
            for i in range(count):
                average = _rolling_mean(spread_series, config.pairs_lookback, i)
                deviation = _rolling_std(spread_series, config.pairs_lookback, i)
                spread_value = spread_series[i]
                if average is None or deviation is None or spread_value is None:
                    continue
                zscore = (spread_value - average) / (deviation if deviation != 0 else _ONE)
                signal[i] = (
                    1
                    if zscore < -config.pairs_entry_z
                    else -1
                    if zscore > config.pairs_entry_z
                    else 0
                )
        elif strategy_id == "ohlc_market_making_proxy":
            volatility = [_rolling_std(_returns(closes), 20, i) for i in range(count)]
            fair = [_rolling_mean(list(closes), 10, i) for i in range(count)]
            gamma, k = config.market_making_gamma, config.market_making_k
            optimal_spread = (_TWO / gamma) * (_ONE + gamma / k).ln()
            for i in range(count):
                volatility_value, fair_value = volatility[i], fair[i]
                if volatility_value is None or fair_value is None or fair_value == 0:
                    continue
                spread_width = optimal_spread + volatility_value
                deviation = (closes[i] - fair_value) / fair_value
                signal[i] = (
                    1
                    if deviation < -spread_width / _TWO
                    else -1
                    if deviation > spread_width / _TWO
                    else 0
                )
        else:
            raise BitcoinCourseStrategyError("INVALID_STRATEGY")
    return signal


def generate_course_signals(
    strategy_id: CourseStrategyId,
    bars: tuple[CourseBarV1, ...],
    config: CourseStrategyConfigV1 = _DEFAULT_COURSE_CONFIG,
) -> tuple[CourseSignalV1, ...]:
    """Evaluate one source strategy without I/O, order routing or hidden data."""
    if type(strategy_id) is not str or strategy_id not in _LABELS:
        raise BitcoinCourseStrategyError("INVALID_STRATEGY")
    if type(config) is not CourseStrategyConfigV1:
        raise BitcoinCourseStrategyError("INVALID_CONFIG")
    if type(bars) is not tuple or any(type(bar) is not CourseBarV1 for bar in bars):
        raise BitcoinCourseStrategyError("INVALID_BAR")
    if len(bars) > 1 and any(
        left.timestamp_ns >= right.timestamp_ns for left, right in pairwise(bars)
    ):
        raise BitcoinCourseStrategyError("INVALID_BAR")
    signal_values = _build_signals(strategy_id, bars, config)
    return tuple(
        CourseSignalV1(
            strategy_id=strategy_id,
            label=_LABELS[strategy_id],
            timestamp_ns=bar.timestamp_ns,
            signal=cast(Literal[-1, 0, 1], value),
        )
        for bar, value in zip(bars, signal_values, strict=True)
    )


def run_course_backtest(
    bars: tuple[CourseBarV1, ...],
    signals: tuple[CourseSignalV1, ...],
    *,
    initial_capital: Decimal = Decimal("100000"),
    commission: Decimal = Decimal("0.001"),
) -> tuple[CourseBacktestPointV1, ...]:
    """Apply source-style one-bar lag and commission per change in position."""
    if type(bars) is not tuple or type(signals) is not tuple or len(bars) != len(signals):
        raise BitcoinCourseStrategyError("INVALID_BACKTEST_INPUT")
    capital = _decimal(
        initial_capital, "initial_capital", minimum="0.000000000000000000000000000000001"
    )
    fee = _decimal(commission, "commission", minimum="0")
    if (
        any(type(bar) is not CourseBarV1 for bar in bars)
        or any(type(item) is not CourseSignalV1 for item in signals)
        or any(
            bar.timestamp_ns != item.timestamp_ns for bar, item in zip(bars, signals, strict=True)
        )
    ):
        raise BitcoinCourseStrategyError("INVALID_BACKTEST_INPUT")
    output: list[CourseBacktestPointV1] = []
    position = 0
    equity = capital
    with localcontext(numeric_context(final_quotient=True)):
        for index, (bar, item) in enumerate(zip(bars, signals, strict=True)):
            if type(item.signal) is not int or item.signal not in {-1, 0, 1}:
                raise BitcoinCourseStrategyError("INVALID_BACKTEST_INPUT")
            held = 0 if index == 0 else signals[index - 1].signal
            gross = _ZERO if index == 0 else held * (bar.close / bars[index - 1].close - _ONE)
            cost = Decimal(abs(held - position)) * fee
            net = gross - cost
            equity *= _ONE + net
            output.append(
                CourseBacktestPointV1(
                    timestamp_ns=bar.timestamp_ns,
                    signal=item.signal,
                    lagged_position=held,
                    gross_return=gross,
                    commission_cost=cost,
                    net_return=net,
                    equity=equity,
                )
            )
            position = held
    return tuple(output)


__all__ = [
    "BitcoinCourseStrategyError",
    "CourseBacktestPointV1",
    "CourseBarV1",
    "CourseSignalV1",
    "CourseStrategyConfigV1",
    "CourseStrategyId",
    "generate_course_signals",
    "run_course_backtest",
]
