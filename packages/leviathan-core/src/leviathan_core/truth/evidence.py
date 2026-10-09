"""Truth evidence source protocols and evidence models.

Each source returns its domain evidence or None — None means the source
is unavailable (no API key, no live feed). Unavailability is distinct from
a bearish/bullish signal; callers must handle None explicitly.

Doctrine: missing evidence degrades toward MIXED, never toward CONFIRMED.
"""

from typing import Protocol, runtime_checkable

from pydantic import Field

from leviathan_core.schemas.base import LeviathanModel
from leviathan_core.schemas.enums import EventRisk, OrderbookBias

# ---------------------------------------------------------------------------
# Evidence models
# ---------------------------------------------------------------------------


class OrderFlowEvidence(LeviathanModel):
    """Level-2 order book / tape reading evidence.

    ``orderbook_bias`` is the dominant flow direction as classified by the
    order-flow source (Rithmic/Bookmap L2 in production, stub in tests).
    ``notes`` carries a human-readable summary of the tape behaviour.
    """

    orderbook_bias: OrderbookBias
    notes: str


class OptionsEvidence(LeviathanModel):
    """Unusual Whales / options flow evidence.

    ``bearish_sweep_detected`` is the primary boolean signal: a large
    bearish sweep in near-dated contracts is a hard warning that
    sophisticated money has positioned against the bullish thesis.
    ``context`` holds a descriptive summary of options activity.
    """

    context: str
    bearish_sweep_detected: bool


class EventEvidence(LeviathanModel):
    """Economic calendar / macro event risk evidence.

    ``event_risk`` maps to the three-tier EventRisk enum:
    - SAFE: no imminent high-impact event within embargo window.
    - REDUCED_RISK: event present but outside lockout, smaller tier.
    - NO_TRADE: hard lockout — event too close or tier-1 imminent.
    """

    event_risk: EventRisk


class SentimentEvidence(LeviathanModel):
    """Retail / social sentiment modifier.

    ``modifier`` is bounded to ±0.25 — sentiment may tilt a decision but
    can never override order-book truth. A positive modifier indicates
    net-bullish retail sentiment; negative indicates net-bearish.
    """

    modifier: float = Field(ge=-0.25, le=0.25)


# ---------------------------------------------------------------------------
# Source protocols
# ---------------------------------------------------------------------------


@runtime_checkable
class OrderFlowSource(Protocol):
    """Level-2 / tape reading data source."""

    def get_order_flow(self) -> OrderFlowEvidence | None:
        """Return order-flow evidence, or None if the source is unavailable."""
        ...


@runtime_checkable
class OptionsSource(Protocol):
    """Options flow data source (Unusual Whales or equivalent)."""

    def get_options(self) -> OptionsEvidence | None:
        """Return options evidence, or None if the source is unavailable."""
        ...


@runtime_checkable
class EventSource(Protocol):
    """Economic calendar / macro event risk source."""

    def get_event_risk(self) -> EventEvidence | None:
        """Return event risk evidence, or None if the source is unavailable."""
        ...


@runtime_checkable
class SentimentSource(Protocol):
    """Retail / social sentiment data source."""

    def get_sentiment(self) -> SentimentEvidence | None:
        """Return sentiment evidence, or None if the source is unavailable."""
        ...
