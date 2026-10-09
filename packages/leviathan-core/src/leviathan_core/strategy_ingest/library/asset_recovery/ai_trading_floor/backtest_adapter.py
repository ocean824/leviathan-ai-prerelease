"""C-102-compatible deterministic OHLC replay adapter.

Fills occur at the next bar open. Stops are side-aware; a stop crossed on the
entry bar is resolved at the adverse reachable price. Fees/slippage are explicit
policy inputs, and portfolio weights are lagged one full observation.

This adapts AI Trading Floor ``CONVENTIONS.md`` sections 1-2 and 4-7:
close-derived signals execute on the next bar, stops stay on the losing side,
intrabar stop/target collisions choose the conservative stop and are reported,
costs are explicit, and naive source timestamps follow ``DATA_CONTRACT.md``'s
Eastern-time convention.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal, localcontext
from fractions import Fraction

from leviathan_core.numeric import Ratio, parse_decimal, quotient_final
from leviathan_core.numeric._context import numeric_context

from .strategies import (
    AIFloorOHLCVBarV1,
    AIFloorPortError,
    AIFloorSignalV1,
    AIFloorStrategySpecV1,
    evaluate_signals,
)

_UTC = UTC
_NS = 1_000_000_000


def eastern_naive_to_utc_ns(value: datetime) -> int:
    """Map source-local naive Eastern timestamps to UTC; reject DST ambiguity/gaps."""
    if type(value) is not datetime or value.tzinfo is not None:
        raise AIFloorPortError("TIMESTAMP_INVALID")
    if value.year < 2007:
        raise AIFloorPortError("TIMESTAMP_RULES_UNAVAILABLE")

    def nth_sunday(month: int, nth: int) -> int:
        first = datetime(value.year, month, 1)
        first_sunday = 1 + ((6 - first.weekday()) % 7)
        return first_sunday + 7 * (nth - 1)

    # US Eastern rules since 2007: spring transition 02:00 on the second Sunday
    # in March; fall transition 02:00 on the first Sunday in November.
    spring_day, fall_day = nth_sunday(3, 2), nth_sunday(11, 1)
    spring_gap = datetime(value.year, 3, spring_day, 2)
    fall_fold = datetime(value.year, 11, fall_day, 1)
    if spring_gap <= value < spring_gap + timedelta(hours=1):
        raise AIFloorPortError("TIMESTAMP_NONEXISTENT")
    if fall_fold <= value < fall_fold + timedelta(hours=1):
        raise AIFloorPortError("TIMESTAMP_AMBIGUOUS")
    daylight_start = datetime(value.year, 3, spring_day, 3)
    daylight_end = datetime(value.year, 11, fall_day, 1)
    offset = timedelta(hours=-4 if daylight_start <= value < daylight_end else -5)
    utc_value = (value - offset).replace(tzinfo=_UTC)
    delta = utc_value - datetime(1970, 1, 1, tzinfo=_UTC)
    return (delta.days * 86400 + delta.seconds) * _NS + delta.microseconds * 1000


def _bps_ceil(amount: Decimal, bps: int, minor_units: int) -> Decimal:
    units = Fraction(amount) * bps / 10_000
    scaled = units * 10**minor_units
    minor = scaled.numerator // scaled.denominator
    if scaled.numerator % scaled.denominator:
        minor += 1
    return Decimal(minor).scaleb(-minor_units)


def _slipped(price: Decimal, bps: int, side: str, entering: bool) -> Decimal:
    adverse_up = (side == "LONG") == entering
    factor = Fraction(10_000 + (bps if adverse_up else -bps), 10_000)
    product = Fraction(price) * factor
    return quotient_final(Ratio(product.numerator, product.denominator), 1)


@dataclass(frozen=True, slots=True)
class AIFloorReplayPolicyV1:
    currency: str
    minor_units: int
    initial_equity: Decimal
    fee_bps: int
    slippage_bps: int

    def __post_init__(self) -> None:
        if (
            type(self.currency) is not str
            or not self.currency.isalpha()
            or len(self.currency) != 3
            or type(self.minor_units) is not int
            or not 0 <= self.minor_units <= 8
            or type(self.fee_bps) is not int
            or not 0 <= self.fee_bps <= 10_000
            or type(self.slippage_bps) is not int
            or not 0 <= self.slippage_bps <= 10_000
        ):
            raise AIFloorPortError("REPLAY_POLICY_INVALID")
        try:
            parse_decimal(self.initial_equity, field="initial_equity")
        except (TypeError, ValueError):
            raise AIFloorPortError("REPLAY_POLICY_INVALID") from None
        if self.initial_equity <= 0:
            raise AIFloorPortError("REPLAY_POLICY_INVALID")


@dataclass(frozen=True, slots=True)
class AIFloorReplayTradeV1:
    entry_ns: int
    exit_ns: int
    side: str
    entry_price: Decimal
    exit_price: Decimal
    gross_pnl: Decimal
    fees: Decimal
    net_pnl: Decimal
    ambiguous_stop: bool


@dataclass(frozen=True, slots=True)
class AIFloorReplayV1:
    timestamps_ns: tuple[int, ...]
    period_returns: tuple[Decimal, ...]
    trades: tuple[AIFloorReplayTradeV1, ...]
    final_equity: Decimal


def _round_minor(value: Decimal, minor_units: int) -> Decimal:
    return value.quantize(Decimal(1).scaleb(-minor_units))


def _replay_signals(
    bars: tuple[AIFloorOHLCVBarV1, ...],
    signals: tuple[AIFloorSignalV1, ...],
    policy: AIFloorReplayPolicyV1,
) -> AIFloorReplayV1:
    """Replay typed timestamp-aligned signals with conservative stop fills."""
    if (
        type(bars) is not tuple
        or len(bars) < 2
        or any(type(bar) is not AIFloorOHLCVBarV1 for bar in bars)
    ):
        raise AIFloorPortError("INSUFFICIENT_BARS")
    if any(a.timestamp_ns >= b.timestamp_ns for a, b in itertools.pairwise(bars)):
        raise AIFloorPortError("BAR_SERIES_INVALID")
    if (
        type(signals) is not tuple
        or len(signals) != len(bars)
        or any(type(signal) is not AIFloorSignalV1 for signal in signals)
        or any(
            signal.timestamp_ns != bar.timestamp_ns
            for signal, bar in zip(signals, bars, strict=True)
        )
    ):
        raise AIFloorPortError("SIGNAL_SERIES_INVALID")
    if type(policy) is not AIFloorReplayPolicyV1:
        raise AIFloorPortError("REPLAY_POLICY_INVALID")
    equity = policy.initial_equity
    returns: list[Decimal] = []
    period_starts: list[Decimal] = []
    trades: list[AIFloorReplayTradeV1] = []
    active: tuple[str, int, Decimal, Decimal | None, Decimal | None] | None = None
    for i in range(1, len(bars)):
        prior_signal = signals[i - 1]
        bar = bars[i]
        period_pnl = Decimal(0)
        closed_this_bar = False
        if active is not None:
            side, entry_i, entry, stop, target = active
            stopped = stop is not None and (
                (side == "LONG" and bar.low <= stop) or (side == "SHORT" and bar.high >= stop)
            )
            targeted = target is not None and (
                (side == "LONG" and bar.high >= target) or (side == "SHORT" and bar.low <= target)
            )
            should_exit = stopped or targeted or prior_signal.position != side
            if should_exit:
                stop_value = stop if stop is not None else bar.open
                target_value = target if target is not None else bar.open
                ambiguous = stopped and targeted
                if stopped:
                    raw_exit = (
                        min(bar.open, stop_value) if side == "LONG" else max(bar.open, stop_value)
                    )
                elif targeted:
                    raw_exit = (
                        max(bar.open, target_value)
                        if side == "LONG"
                        else min(bar.open, target_value)
                    )
                else:
                    raw_exit = bar.open
                exit_price = _slipped(raw_exit, policy.slippage_bps, side, False)
                gross = exit_price - entry if side == "LONG" else entry - exit_price
                fees = _bps_ceil(entry + exit_price, policy.fee_bps, policy.minor_units)
                net = _round_minor(gross - fees, policy.minor_units)
                period_pnl += net
                trades.append(
                    AIFloorReplayTradeV1(
                        bars[entry_i].timestamp_ns,
                        bar.timestamp_ns,
                        side,
                        entry,
                        exit_price,
                        gross,
                        fees,
                        net,
                        ambiguous,
                    )
                )
                equity += net
                active = None
                closed_this_bar = True
        if active is None and not closed_this_bar and prior_signal.position in ("LONG", "SHORT"):
            side = prior_signal.position
            entry = _slipped(bar.open, policy.slippage_bps, side, True)
            stop = prior_signal.stop_price
            target = prior_signal.target_price
            stopped = stop is not None and (
                (side == "LONG" and bar.low <= stop) or (side == "SHORT" and bar.high >= stop)
            )
            targeted = target is not None and (
                (side == "LONG" and bar.high >= target) or (side == "SHORT" and bar.low <= target)
            )
            if stopped or targeted:
                stop_value = stop if stop is not None else bar.open
                target_value = target if target is not None else bar.open
                if stopped:
                    exit_raw = (
                        min(bar.open, stop_value) if side == "LONG" else max(bar.open, stop_value)
                    )
                else:
                    exit_raw = (
                        max(bar.open, target_value)
                        if side == "LONG"
                        else min(bar.open, target_value)
                    )
                exit_price = _slipped(exit_raw, policy.slippage_bps, side, False)
                gross = exit_price - entry if side == "LONG" else entry - exit_price
                fees = _bps_ceil(entry + exit_price, policy.fee_bps, policy.minor_units)
                net = _round_minor(gross - fees, policy.minor_units)
                period_pnl += net
                trades.append(
                    AIFloorReplayTradeV1(
                        bar.timestamp_ns,
                        bar.timestamp_ns,
                        side,
                        entry,
                        exit_price,
                        gross,
                        fees,
                        net,
                        stopped and targeted,
                    )
                )
                equity += net
            else:
                active = (side, i, entry, stop, target)
        if equity != period_pnl:
            ret = Fraction(period_pnl) / Fraction(equity - period_pnl)
            returns.append(quotient_final(Ratio(ret.numerator, ret.denominator), 1))
            period_starts.append(equity - period_pnl)
        else:
            returns.append(Decimal(0))
            period_starts.append(equity)
    # Open positions are marked to the final close, without lookahead.
    if active is not None:
        side, entry_i, entry, _, _ = active
        last = bars[-1]
        exit_price = _slipped(last.close, policy.slippage_bps, side, False)
        gross = exit_price - entry if side == "LONG" else entry - exit_price
        fees = _bps_ceil(entry + exit_price, policy.fee_bps, policy.minor_units)
        net = _round_minor(gross - fees, policy.minor_units)
        trades.append(
            AIFloorReplayTradeV1(
                bars[entry_i].timestamp_ns,
                last.timestamp_ns,
                side,
                entry,
                exit_price,
                gross,
                fees,
                net,
                False,
            )
        )
        final_return = Fraction(returns[-1]) * Fraction(period_starts[-1]) + Fraction(net)
        final_return /= Fraction(period_starts[-1])
        returns[-1] = quotient_final(Ratio(final_return.numerator, final_return.denominator), 1)
        equity += net
    return AIFloorReplayV1(
        tuple(x.timestamp_ns for x in bars[1:]), tuple(returns), tuple(trades), equity
    )


def _replay_strategy(
    bars: tuple[AIFloorOHLCVBarV1, ...],
    spec: AIFloorStrategySpecV1,
    policy: AIFloorReplayPolicyV1,
) -> AIFloorReplayV1:
    """Replay source signals with next-bar fills and explicit costs."""
    return _replay_signals(bars, evaluate_signals(bars, spec), policy)


def replay_signals(
    bars: tuple[AIFloorOHLCVBarV1, ...],
    signals: tuple[AIFloorSignalV1, ...],
    policy: AIFloorReplayPolicyV1,
) -> AIFloorReplayV1:
    """Replay precomputed typed signals, useful for controlled C-102 fixtures.

    The input remains pure evidence: each signal must correspond exactly to one
    bar. This makes same-bar stop/target ambiguity testable without injecting a
    special case into a source strategy.
    """
    with localcontext(numeric_context(final_quotient=True)):
        return _replay_signals(bars, signals, policy)


def replay_strategy(
    bars: tuple[AIFloorOHLCVBarV1, ...],
    spec: AIFloorStrategySpecV1,
    policy: AIFloorReplayPolicyV1,
) -> AIFloorReplayV1:
    """Replay under the kernel's own bounded Decimal arithmetic context."""
    with localcontext(numeric_context(final_quotient=True)):
        return _replay_strategy(bars, spec, policy)


def lag_portfolio_weights(
    timestamps_ns: tuple[int, ...], weights: tuple[tuple[Decimal, ...], ...]
) -> tuple[tuple[Decimal, ...], ...]:
    """Apply source convention weights[T] = weights learned through T-1."""
    if len(timestamps_ns) != len(weights) or any(
        a >= b for a, b in itertools.pairwise(timestamps_ns)
    ):
        raise AIFloorPortError("WEIGHT_SERIES_INVALID")
    if not weights:
        return ()
    return (tuple(Decimal(0) for _ in weights[0]), *weights[:-1])
