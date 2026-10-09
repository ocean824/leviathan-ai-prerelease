"""Market-structure & liquidity interpretation (SIREN).

Swings answer *where* the pivots are; structure answers *what they mean*.
Two languages are spoken here. The first is trend structure: a close
through the most recent confirmed swing is a break of structure (BOS /
MSB) and marks a shift in who is in control. The second is liquidity:
equal highs and lows are resting stops that price is drawn toward, and a
sweep is the market reaching beyond a pivot to take that liquidity before
snapping back inside — a trap, not a trend. We separate the two because
the Decision Domain treats a genuine break and a liquidity grab as
opposite evidence.
"""

from decimal import Decimal

from leviathan_core.schemas import Bar
from leviathan_core.schemas.base import LeviathanModel
from leviathan_core.signal.swings import SwingPoint


class StructureReport(LeviathanModel):
    """Structure and liquidity features read off the final bar.

    ``signal_features`` carries directional break-of-structure evidence;
    ``liquidity_features`` carries equal-level and sweep evidence. Both
    map directly onto the corresponding :class:`CandidateSetup` fields.
    """

    signal_features: tuple[str, ...] = ()
    liquidity_features: tuple[str, ...] = ()


class MarketStructureAnalyzer:
    """Read break-of-structure and liquidity events from swings + bars.

    ``equal_tolerance`` is the fractional band (default 0.05%) within
    which two swings of the same kind count as "equal" — resting
    liquidity rather than distinct pivots. Judgement is made against the
    *last* bar in the sequence: structure is a statement about the
    present relative to the confirmed past.
    """

    def __init__(self, equal_tolerance: Decimal = Decimal("0.0005")) -> None:
        if equal_tolerance < 0:
            raise ValueError("equal tolerance must be non-negative")
        self._equal_tol = equal_tolerance

    def analyze(
        self, bars: tuple[Bar, ...], swings: tuple[SwingPoint, ...]
    ) -> StructureReport:
        if not bars:
            return StructureReport()
        last = bars[-1]
        highs = tuple(s for s in swings if s.kind == "high")
        lows = tuple(s for s in swings if s.kind == "low")

        signal: list[str] = []
        liquidity: list[str] = []

        self._detect_break(last, highs, lows, signal)
        self._detect_equal_levels(highs, lows, liquidity)
        self._detect_sweep(last, highs, lows, liquidity)

        return StructureReport(
            signal_features=tuple(signal), liquidity_features=tuple(liquidity)
        )

    def _detect_break(
        self,
        last: Bar,
        highs: tuple[SwingPoint, ...],
        lows: tuple[SwingPoint, ...],
        out: list[str],
    ) -> None:
        # The most recent confirmed pivot is the reference level to break.
        if highs and last.close > highs[-1].price:
            out.append("msb_up")
        if lows and last.close < lows[-1].price:
            out.append("msb_down")

    def _detect_equal_levels(
        self,
        highs: tuple[SwingPoint, ...],
        lows: tuple[SwingPoint, ...],
        out: list[str],
    ) -> None:
        if self._within_tolerance(highs):
            out.append("equal_highs")
        if self._within_tolerance(lows):
            out.append("equal_lows")

    def _detect_sweep(
        self,
        last: Bar,
        highs: tuple[SwingPoint, ...],
        lows: tuple[SwingPoint, ...],
        out: list[str],
    ) -> None:
        # A sweep pierces a prior pivot with the wick but closes back inside.
        if highs and last.high > highs[-1].price and last.close < highs[-1].price:
            out.append("sweep_high")
        if lows and last.low < lows[-1].price and last.close > lows[-1].price:
            out.append("sweep_low")

    def _within_tolerance(self, swings: tuple[SwingPoint, ...]) -> bool:
        if len(swings) < 2:
            return False
        a, b = swings[-1].price, swings[-2].price
        ref = max(abs(a), abs(b))
        if ref == 0:
            return a == b
        return abs(a - b) / ref <= self._equal_tol
