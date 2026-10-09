"""StrategyGenome — Research Domain contract.

Stores validated trading doctrine and deployment constraints for a
strategy family. The full production genome carries 40+ fields; this is
the canonical Layer-1 core that every other layer may rely on.
"""

from pydantic import Field

from leviathan_core.schemas.base import LeviathanModel
from leviathan_core.schemas.enums import MarketState


class StrategyGenome(LeviathanModel):
    strategy_id: str
    family: str
    market: str
    timeframe: str
    session_dependencies: tuple[str, ...] = Field(default=())
    state_dependencies: tuple[MarketState, ...] = Field(default=())
    entry_conditions: tuple[str, ...] = Field(default=())
    exit_conditions: tuple[str, ...] = Field(default=())
    risk_profile: str
    failure_modes: tuple[str, ...] = Field(default=())
    prop_firm_compatible: bool = True
