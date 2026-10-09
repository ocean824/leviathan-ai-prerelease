"""Swing-point detection — the skeleton of market structure (SIREN).

A swing is a local pivot: a bar whose high dominates its neighbours (a
swing high) or whose low is dominated by them (a swing low). Structure,
liquidity, and displacement are all read from swings, so they are the
first thing SIREN extracts from raw bars. Detection is fractal and
lagging by design — a pivot is only *confirmed* once enough bars have
printed on both sides, because a high that later gets exceeded was never
a high. We never anticipate a swing; we wait for the market to prove it.
"""

from datetime import datetime
from decimal import Decimal
from typing import Literal

from leviathan_core.schemas import Bar
from leviathan_core.schemas.base import LeviathanModel

SwingKind = Literal["high", "low"]


class SwingPoint(LeviathanModel):
    """A confirmed pivot, anchored to the bar that formed it."""

    index: int
    timestamp: datetime
    price: Decimal
    kind: SwingKind


class SwingDetector:
    """Extract confirmed swing highs and lows from a bar sequence.

    ``lookback`` is the number of bars required on *each* side of a pivot
    before it is confirmed. A larger lookback filters noise into fewer,
    more significant structural points; the default of 2 is the working
    intraday setting. Bars nearer the sequence edges than ``lookback``
    cannot be confirmed and are intentionally omitted.
    """

    def __init__(self, lookback: int = 2) -> None:
        if lookback < 1:
            raise ValueError("swing lookback must be at least 1 bar per side")
        self._lookback = lookback

    def detect(self, bars: tuple[Bar, ...]) -> tuple[SwingPoint, ...]:
        n = len(bars)
        span = self._lookback
        swings: list[SwingPoint] = []
        for i in range(span, n - span):
            pivot = bars[i]
            neighbours = [bars[j] for j in range(i - span, i + span + 1) if j != i]
            if all(pivot.high > b.high for b in neighbours):
                swings.append(
                    SwingPoint(
                        index=i, timestamp=pivot.timestamp, price=pivot.high, kind="high"
                    )
                )
            if all(pivot.low < b.low for b in neighbours):
                swings.append(
                    SwingPoint(
                        index=i, timestamp=pivot.timestamp, price=pivot.low, kind="low"
                    )
                )
        return tuple(swings)
