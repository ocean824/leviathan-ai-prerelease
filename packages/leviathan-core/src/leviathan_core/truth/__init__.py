"""Truth Domain — order-flow, options, event, sentiment validation (SCYLLA).

Phase 3 implementation target. Consumes CandidateSetup + live market
evidence, emits TruthValidationResult. Order-book truth outranks chart
cosmetics; sentiment is a bounded modifier only.
"""

from leviathan_core.truth.composite import CompositeTruthProvider
from leviathan_core.truth.evidence import (
    EventEvidence,
    EventSource,
    OptionsEvidence,
    OptionsSource,
    OrderFlowEvidence,
    OrderFlowSource,
    SentimentEvidence,
    SentimentSource,
)
from leviathan_core.truth.provider import StaticTruthProvider, TruthProvider
from leviathan_core.truth.replay import ReplayTruthProvider

__all__ = [
    "CompositeTruthProvider",
    "EventEvidence",
    "EventSource",
    "OptionsEvidence",
    "OptionsSource",
    "OrderFlowEvidence",
    "OrderFlowSource",
    "ReplayTruthProvider",
    "SentimentEvidence",
    "SentimentSource",
    "StaticTruthProvider",
    "TruthProvider",
]
