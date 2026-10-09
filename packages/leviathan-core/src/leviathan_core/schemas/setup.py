"""CandidateSetup — Signal / Session / State contract.

A possible trade opportunity entering the LEVIATHAN pipeline. A setup is
evidence, never permission: only the Decision Domain grants capital.
"""

from datetime import datetime

from pydantic import Field

from leviathan_core.schemas.base import LeviathanModel
from leviathan_core.schemas.enums import MarketState


class CandidateSetup(LeviathanModel):
    setup_id: str
    instrument: str
    timestamp: datetime
    signal_features: tuple[str, ...] = Field(default=())
    session_label: str | None = None
    range_label: str | None = None
    state_label: MarketState | None = None
    liquidity_features: tuple[str, ...] = Field(default=())
