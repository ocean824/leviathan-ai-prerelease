"""Shared enumerations for the LEVIATHAN contract layer.

Values mirror docs/oracle-schema-contracts-and-example-payloads.md and the
README domain definitions in the source architecture repo.
"""

from enum import StrEnum


class OperatingMode(StrEnum):
    """The 7 named permission modes controlling execution capability."""

    RESEARCH = "research"
    ADVISORY = "advisory"
    SEMI_AUTO = "semi_auto"
    FULL_AUTO = "full_auto"
    PROP_FIRM = "prop_firm"
    RECOVERY = "recovery"
    SIGNAL_ONLY = "signal_only"


class MarketState(StrEnum):
    """State Domain labels — the market as a moving state machine.

    First eight are the canonical states from the transition matrix;
    the rest are the extended vocabulary from the master writeup.
    """

    COMPRESSION = "compression"
    BREAKOUT = "breakout"
    TREND_CONTINUATION = "trend_continuation"
    EXPANSION = "expansion"
    DISTRIBUTION = "distribution"
    ACCUMULATION = "accumulation"
    MEAN_REVERSION = "mean_reversion"
    EVENT_LOCKED = "event_locked"
    # extended vocabulary
    BROAD_RANGE = "broad_range"
    NARROW_RANGE = "narrow_range"
    BREAKOUT_FAILURE = "breakout_failure"
    DRIFT = "drift"
    EXHAUSTION = "exhaustion"
    REVERSAL = "reversal"
    INSTABILITY = "instability"
    HAZARD = "hazard"


class SessionLabel(StrEnum):
    """Session Domain — time-of-day as a first-class edge (MERMAID)."""

    ASIAN = "asian"
    LONDON_OPEN = "london_open"
    LONDON_CONTINUATION = "london_continuation"
    NY_OPEN = "ny_open"
    NY_OVERLAP = "ny_overlap"
    NY_MIDDAY = "ny_midday"
    NY_CLOSE = "ny_close"
    ROLLOVER = "rollover"


class TransitionRiskClass(StrEnum):
    """Semantics of a state transition (market-state-transition-matrix)."""

    STABLE = "stable"
    CAUTION = "caution"
    UNSTABLE = "unstable"


class PolicyAction(StrEnum):
    """Policy consequence of a state transition."""

    EVALUATE_NORMALLY = "evaluate_normally"
    REQUIRE_RETEST_CONFIRMATION = "require_retest_confirmation"
    REDUCE_SIZE_AND_CONFIDENCE = "reduce_size_and_confidence"
    NO_AUTONOMOUS_TRADE_APPROVAL = "no_autonomous_trade_approval"
    WAIT_FOR_POST_EVENT_NORMALIZATION = "wait_for_post_event_normalization"
    MANUAL_REVIEW_REQUIRED = "manual_review_required"


class RiskAction(StrEnum):
    """Sovereign risk verdict actions (risk-veto-policy-matrix)."""

    ALLOW = "allow"
    REDUCE_SIZE = "reduce_size"
    WAIT = "wait"
    REJECT = "reject"
    HALT_ALL_TRADING = "halt_all_trading"
    FORCE_FLAT_BY_SESSION_END = "force_flat_by_session_end"


class OrderbookBias(StrEnum):
    BULLISH = "bullish"
    BEARISH = "bearish"
    NEUTRAL = "neutral"


class EventRisk(StrEnum):
    SAFE = "safe"
    REDUCED_RISK = "reduced_risk"
    NO_TRADE = "no_trade"


class TruthStatus(StrEnum):
    CONFIRMED = "confirmed"
    MIXED = "mixed"
    REJECTED = "rejected"


class Permission(StrEnum):
    """Decision Domain output — capital permission, not prediction."""

    REJECT = "reject"
    WAIT = "wait"
    APPROVE = "approve"
    SIGNAL_ONLY = "signal_only"


class Direction(StrEnum):
    LONG = "long"
    SHORT = "short"
    FLAT = "flat"


class BrokerPath(StrEnum):
    PAPER_SIM = "paper_sim"
    MT5 = "mt5"
    DIRECT_BROKER = "direct_broker"


class OrderType(StrEnum):
    MARKET = "market"
    LIMIT = "limit"
    STOP = "stop"


class TimeInForce(StrEnum):
    DAY = "DAY"
    GTC = "GTC"


class TradeOutcome(StrEnum):
    WIN = "win"
    LOSS = "loss"
    SCRATCH = "scratch"
    BLOCKED = "blocked"
