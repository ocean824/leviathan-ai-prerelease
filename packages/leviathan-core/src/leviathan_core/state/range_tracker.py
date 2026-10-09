"""Previous-day & range tracking — structural boundary interpretation.

Consumes bars chronologically, maintains PDH/PDL/midpoint and the
opening range, and labels where price sits relative to those levels.
"""

from datetime import date, datetime, timedelta
from decimal import Decimal

from leviathan_core.schemas import Bar
from leviathan_core.schemas.base import LeviathanModel


class RangeContext(LeviathanModel):
    pdh: Decimal | None
    pdl: Decimal | None
    midpoint: Decimal | None
    opening_range_high: Decimal | None
    opening_range_low: Decimal | None
    range_label: str


class RangeTracker:
    """Stateful per-instrument tracker; feed bars in chronological order."""

    def __init__(self, opening_range_minutes: int = 30) -> None:
        self._or_window = timedelta(minutes=opening_range_minutes)
        self._day: date | None = None
        self._day_high: Decimal | None = None
        self._day_low: Decimal | None = None
        self._pdh: Decimal | None = None
        self._pdl: Decimal | None = None
        self._or_high: Decimal | None = None
        self._or_low: Decimal | None = None
        self._day_open_ts: datetime | None = None

    def update(self, bar: Bar) -> RangeContext:
        bar_day = bar.timestamp.date()
        if bar_day != self._day:
            self._pdh, self._pdl = self._day_high, self._day_low
            self._day = bar_day
            self._day_high, self._day_low = bar.high, bar.low
            self._or_high, self._or_low = bar.high, bar.low
            self._day_open_ts = bar.timestamp
        else:
            self._day_high = max(self._day_high or bar.high, bar.high)
            self._day_low = min(self._day_low or bar.low, bar.low)
            if self._day_open_ts and bar.timestamp - self._day_open_ts < self._or_window:
                self._or_high = max(self._or_high or bar.high, bar.high)
                self._or_low = min(self._or_low or bar.low, bar.low)

        return RangeContext(
            pdh=self._pdh,
            pdl=self._pdl,
            midpoint=self._midpoint(),
            opening_range_high=self._or_high,
            opening_range_low=self._or_low,
            range_label=self._label(bar.close),
        )

    def _midpoint(self) -> Decimal | None:
        if self._pdh is None or self._pdl is None:
            return None
        return (self._pdh + self._pdl) / 2

    def _label(self, price: Decimal) -> str:
        if self._or_high is not None and price > self._or_high:
            return "above_opening_range_high"
        if self._or_low is not None and price < self._or_low:
            return "below_opening_range_low"
        if self._pdh is not None and price > self._pdh:
            return "above_pdh"
        if self._pdl is not None and price < self._pdl:
            return "below_pdl"
        return "inside_range"
