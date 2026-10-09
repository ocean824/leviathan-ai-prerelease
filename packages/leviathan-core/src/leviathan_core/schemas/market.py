"""Market data and account-state contracts.

Bars are the replay currency: the paper spine, backtester, and state
engines all consume the same Bar object regardless of which provider
(replay fixture, Polygon, broker feed) produced it.
"""

from datetime import datetime
from decimal import Decimal

from pydantic import Field, model_validator

from leviathan_core.schemas.base import LeviathanModel
from leviathan_core.schemas.enums import Direction


class Bar(LeviathanModel):
    instrument: str
    timestamp: datetime
    open: Decimal
    high: Decimal
    low: Decimal
    close: Decimal
    volume: Decimal = Decimal(0)

    @model_validator(mode="after")
    def _ohlc_sane(self) -> "Bar":
        if not (self.low <= self.open <= self.high and self.low <= self.close <= self.high):
            raise ValueError(f"incoherent OHLC for {self.instrument} @ {self.timestamp}")
        return self


class EconomicEvent(LeviathanModel):
    """AEGIR-flagged calendar event; drives the news embargo."""

    name: str
    scheduled_at: datetime
    tier: int = Field(ge=1, le=3)


class OpenPosition(LeviathanModel):
    instrument: str
    direction: Direction
    size: Decimal
    entry_price: Decimal
    risk_pct: Decimal = Field(ge=0, description="% equity at risk on this position")
    sector: str = "unclassified"


class AccountState(LeviathanModel):
    """Live account telemetry the veto engine judges against."""

    equity: Decimal
    daily_pnl_pct: Decimal
    weekly_pnl_pct: Decimal = Decimal(0)
    trailing_dd_pct: Decimal = Decimal(0)
    consecutive_losses: int = 0
    open_positions: tuple[OpenPosition, ...] = ()

    @property
    def open_heat_pct(self) -> Decimal:
        return sum((p.risk_pct for p in self.open_positions), Decimal(0))

    def positions_in_sector(self, sector: str) -> int:
        return sum(1 for p in self.open_positions if p.sector == sector)

    def open_count(self, instrument: str) -> int:
        return sum(1 for p in self.open_positions if p.instrument == instrument)
