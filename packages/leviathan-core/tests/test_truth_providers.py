"""Tests for Truth Domain: CompositeTruthProvider, ReplayTruthProvider, evidence models."""

from datetime import UTC, datetime
from decimal import Decimal

import pytest

from leviathan_core.schemas import CandidateSetup, TruthValidationResult
from leviathan_core.schemas.enums import EventRisk, MarketState, OrderbookBias, TruthStatus
from leviathan_core.truth import (
    CompositeTruthProvider,
    EventEvidence,
    OptionsEvidence,
    OrderFlowEvidence,
    ReplayTruthProvider,
    SentimentEvidence,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TS = datetime(2026, 4, 15, 14, 35, tzinfo=UTC)


def _bullish_setup(setup_id: str = "setup_bull_01") -> CandidateSetup:
    return CandidateSetup(
        setup_id=setup_id,
        instrument="NQ",
        timestamp=_TS,
        signal_features=("msb_up", "opening_range_break", "ema_alignment"),
        session_label="ny_open",
        state_label=MarketState.BREAKOUT,
    )


def _bearish_setup(setup_id: str = "setup_bear_01") -> CandidateSetup:
    return CandidateSetup(
        setup_id=setup_id,
        instrument="NQ",
        timestamp=_TS,
        signal_features=("msb_down", "breakdown"),
        session_label="ny_open",
        state_label=MarketState.REVERSAL,
    )


def _neutral_setup(setup_id: str = "setup_neutral_01") -> CandidateSetup:
    """No directional keywords — neutral setup."""
    return CandidateSetup(
        setup_id=setup_id,
        instrument="NQ",
        timestamp=_TS,
        signal_features=("compression",),
        session_label="ny_midday",
    )


# ---------------------------------------------------------------------------
# Stub source implementations
# ---------------------------------------------------------------------------


class _BullishOrderFlow:
    def get_order_flow(self) -> OrderFlowEvidence:
        return OrderFlowEvidence(orderbook_bias=OrderbookBias.BULLISH, notes="buyers lifted offer")


class _BearishOrderFlow:
    def get_order_flow(self) -> OrderFlowEvidence:
        return OrderFlowEvidence(orderbook_bias=OrderbookBias.BEARISH, notes="sellers hammered bid")


class _NeutralOrderFlow:
    def get_order_flow(self) -> OrderFlowEvidence:
        return OrderFlowEvidence(orderbook_bias=OrderbookBias.NEUTRAL, notes="balanced tape")


class _NoSweepOptions:
    def get_options(self) -> OptionsEvidence:
        return OptionsEvidence(context="No large bearish sweep.", bearish_sweep_detected=False)


class _SweepOptions:
    def get_options(self) -> OptionsEvidence:
        return OptionsEvidence(context="Large bearish sweep detected.", bearish_sweep_detected=True)


class _SafeEvent:
    def get_event_risk(self) -> EventEvidence:
        return EventEvidence(event_risk=EventRisk.SAFE)


class _NoTradeEvent:
    def get_event_risk(self) -> EventEvidence:
        return EventEvidence(event_risk=EventRisk.NO_TRADE)


class _PositiveSentiment:
    def get_sentiment(self) -> SentimentEvidence:
        return SentimentEvidence(modifier=0.07)


class _NullOrderFlow:
    def get_order_flow(self) -> None:
        return None


class _NullOptions:
    def get_options(self) -> None:
        return None


class _NullSentiment:
    def get_sentiment(self) -> None:
        return None


# ---------------------------------------------------------------------------
# CompositeTruthProvider: CONFIRMED path
# ---------------------------------------------------------------------------


def test_confirmed_all_sources_aligned() -> None:
    """All four sources present and aligned → CONFIRMED."""
    provider = CompositeTruthProvider(
        order_flow_source=_BullishOrderFlow(),
        options_source=_NoSweepOptions(),
        event_source=_SafeEvent(),
        sentiment_source=_PositiveSentiment(),
    )
    result = provider.validate(_bullish_setup())
    assert result.truth_status is TruthStatus.CONFIRMED
    assert result.orderbook_bias is OrderbookBias.BULLISH
    assert result.event_risk is EventRisk.SAFE
    assert result.sentiment_modifier == Decimal("0.07")


# ---------------------------------------------------------------------------
# CompositeTruthProvider: REJECTED paths
# ---------------------------------------------------------------------------


def test_rejected_order_flow_contradiction_bullish_setup_bearish_flow() -> None:
    """Bearish order flow on bullish setup → REJECTED (order-book truth outranks chart)."""
    provider = CompositeTruthProvider(
        order_flow_source=_BearishOrderFlow(),
        options_source=_NoSweepOptions(),
        event_source=_SafeEvent(),
        sentiment_source=_PositiveSentiment(),
    )
    result = provider.validate(_bullish_setup())
    assert result.truth_status is TruthStatus.REJECTED
    assert result.orderbook_bias is OrderbookBias.BEARISH


def test_rejected_order_flow_contradiction_bearish_setup_bullish_flow() -> None:
    """Bullish order flow on bearish setup → REJECTED."""
    provider = CompositeTruthProvider(
        order_flow_source=_BullishOrderFlow(),
        options_source=_NoSweepOptions(),
        event_source=_SafeEvent(),
        sentiment_source=_PositiveSentiment(),
    )
    result = provider.validate(_bearish_setup())
    assert result.truth_status is TruthStatus.REJECTED


def test_rejected_event_no_trade() -> None:
    """Event source returns NO_TRADE → REJECTED regardless of order flow."""
    provider = CompositeTruthProvider(
        order_flow_source=_BullishOrderFlow(),
        options_source=_NoSweepOptions(),
        event_source=_NoTradeEvent(),
        sentiment_source=_PositiveSentiment(),
    )
    result = provider.validate(_bullish_setup())
    assert result.truth_status is TruthStatus.REJECTED
    assert result.event_risk is EventRisk.NO_TRADE


def test_event_no_trade_takes_priority_over_order_flow_contradiction() -> None:
    """NO_TRADE fires before order-flow contradiction check."""
    provider = CompositeTruthProvider(
        order_flow_source=_BearishOrderFlow(),
        options_source=_SweepOptions(),
        event_source=_NoTradeEvent(),
        sentiment_source=_PositiveSentiment(),
    )
    result = provider.validate(_bullish_setup())
    # Event lockout fires first.
    assert result.truth_status is TruthStatus.REJECTED
    assert result.event_risk is EventRisk.NO_TRADE


# ---------------------------------------------------------------------------
# CompositeTruthProvider: MIXED paths
# ---------------------------------------------------------------------------


def test_mixed_missing_order_flow_source() -> None:
    """No order-flow source → at most MIXED."""
    provider = CompositeTruthProvider(
        order_flow_source=None,
        options_source=_NoSweepOptions(),
        event_source=_SafeEvent(),
        sentiment_source=_PositiveSentiment(),
    )
    result = provider.validate(_bullish_setup())
    assert result.truth_status is TruthStatus.MIXED


def test_mixed_order_flow_source_returns_none() -> None:
    """Order-flow source present but returns None → at most MIXED."""
    provider = CompositeTruthProvider(
        order_flow_source=_NullOrderFlow(),  # type: ignore[arg-type]
        options_source=_NoSweepOptions(),
        event_source=_SafeEvent(),
        sentiment_source=_PositiveSentiment(),
    )
    result = provider.validate(_bullish_setup())
    assert result.truth_status is TruthStatus.MIXED


def test_mixed_bearish_options_sweep_on_bullish_setup() -> None:
    """Bearish options sweep on bullish setup → MIXED (options warns, not overrides)."""
    provider = CompositeTruthProvider(
        order_flow_source=_BullishOrderFlow(),
        options_source=_SweepOptions(),
        event_source=_SafeEvent(),
        sentiment_source=_PositiveSentiment(),
    )
    result = provider.validate(_bullish_setup())
    assert result.truth_status is TruthStatus.MIXED


def test_mixed_partial_sources_options_missing() -> None:
    """Order flow aligned but options absent → MIXED."""
    provider = CompositeTruthProvider(
        order_flow_source=_BullishOrderFlow(),
        options_source=None,
        event_source=_SafeEvent(),
        sentiment_source=_PositiveSentiment(),
    )
    result = provider.validate(_bullish_setup())
    assert result.truth_status is TruthStatus.MIXED


def test_mixed_partial_sources_event_missing() -> None:
    """Order flow aligned but event source absent → MIXED (safe assumed, missing coverage)."""
    provider = CompositeTruthProvider(
        order_flow_source=_BullishOrderFlow(),
        options_source=_NoSweepOptions(),
        event_source=None,
        sentiment_source=_PositiveSentiment(),
    )
    result = provider.validate(_bullish_setup())
    assert result.truth_status is TruthStatus.MIXED


def test_sentiment_defaults_to_zero_when_source_missing() -> None:
    """Absent sentiment source → modifier=0.0 in result."""
    provider = CompositeTruthProvider(
        order_flow_source=_BullishOrderFlow(),
        options_source=_NoSweepOptions(),
        event_source=_SafeEvent(),
        sentiment_source=None,
    )
    result = provider.validate(_bullish_setup())
    assert result.sentiment_modifier == pytest.approx(0.0)
    # Still MIXED because sentiment source is absent.
    assert result.truth_status is TruthStatus.MIXED


def test_sentiment_source_returns_none_defaults_to_zero() -> None:
    """Sentiment source present but returns None → modifier=0.0."""
    provider = CompositeTruthProvider(
        order_flow_source=_BullishOrderFlow(),
        options_source=_NoSweepOptions(),
        event_source=_SafeEvent(),
        sentiment_source=_NullSentiment(),  # type: ignore[arg-type]
    )
    result = provider.validate(_bullish_setup())
    assert result.sentiment_modifier == pytest.approx(0.0)


def test_all_sources_missing_is_mixed() -> None:
    """No sources at all → MIXED (missing order flow alone ensures this)."""
    provider = CompositeTruthProvider()
    result = provider.validate(_neutral_setup())
    assert result.truth_status is TruthStatus.MIXED


# ---------------------------------------------------------------------------
# ReplayTruthProvider
# ---------------------------------------------------------------------------

_REPLAY_PAYLOAD: dict[str, dict[str, object]] = {
    "setup_6fc2a3d4c211": {
        "setup_id": "setup_6fc2a3d4c211",
        "orderbook_bias": "bullish",
        "options_context": "No large bearish sweep detected in near-dated contracts.",
        "event_risk": "safe",
        "sentiment_modifier": 0.07,
        "truth_status": "confirmed",
        "notes": "Aggressive buyers lifted the offer.",
    },
    "setup_rejected_001": {
        "setup_id": "setup_rejected_001",
        "orderbook_bias": "bearish",
        "options_context": "Large bearish sweep.",
        "event_risk": "no_trade",
        "sentiment_modifier": -0.15,
        "truth_status": "rejected",
        "notes": "Event lockout engaged.",
    },
}


def _nq_setup() -> CandidateSetup:
    return CandidateSetup(
        setup_id="setup_6fc2a3d4c211",
        instrument="NQ",
        timestamp=_TS,
        signal_features=("msb_up", "opening_range_break"),
        session_label="ny_open",
        state_label=MarketState.BREAKOUT,
    )


def test_replay_returns_stored_confirmed_result() -> None:
    provider = ReplayTruthProvider(_REPLAY_PAYLOAD)  # type: ignore[arg-type]
    result = provider.validate(_nq_setup())
    assert isinstance(result, TruthValidationResult)
    assert result.truth_status is TruthStatus.CONFIRMED
    assert result.setup_id == "setup_6fc2a3d4c211"
    assert result.orderbook_bias is OrderbookBias.BULLISH
    assert result.sentiment_modifier == Decimal("0.07")


def test_replay_returns_stored_rejected_result() -> None:
    setup = CandidateSetup(
        setup_id="setup_rejected_001",
        instrument="NQ",
        timestamp=_TS,
        signal_features=("msb_down",),
    )
    provider = ReplayTruthProvider(_REPLAY_PAYLOAD)  # type: ignore[arg-type]
    result = provider.validate(setup)
    assert result.truth_status is TruthStatus.REJECTED
    assert result.event_risk is EventRisk.NO_TRADE


def test_replay_raises_key_error_for_unknown_setup() -> None:
    provider = ReplayTruthProvider(_REPLAY_PAYLOAD)  # type: ignore[arg-type]
    unknown_setup = CandidateSetup(
        setup_id="setup_does_not_exist",
        instrument="NQ",
        timestamp=_TS,
        signal_features=(),
    )
    with pytest.raises(KeyError, match="setup_does_not_exist"):
        provider.validate(unknown_setup)


def test_replay_validates_payload_at_construction() -> None:
    """Bad payload field raises ValidationError at construction time."""
    from pydantic import ValidationError

    bad_payload = {
        "setup_bad": {
            "setup_id": "setup_bad",
            "orderbook_bias": "not_a_valid_bias",  # invalid enum value
            "options_context": "ok",
            "event_risk": "safe",
            "sentiment_modifier": 0.0,
            "truth_status": "mixed",
        }
    }
    with pytest.raises(ValidationError):
        ReplayTruthProvider(bad_payload)  # type: ignore[arg-type]


def test_replay_empty_payload_raises_on_any_lookup() -> None:
    provider = ReplayTruthProvider({})
    with pytest.raises(KeyError, match="<empty>"):
        provider.validate(_nq_setup())


# ---------------------------------------------------------------------------
# SentimentEvidence boundary validation
# ---------------------------------------------------------------------------


def test_sentiment_evidence_bounds_enforced() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        SentimentEvidence(modifier=0.26)  # exceeds +0.25

    with pytest.raises(ValidationError):
        SentimentEvidence(modifier=-0.26)  # below -0.25

    # Exact boundaries are allowed.
    pos = SentimentEvidence(modifier=0.25)
    assert pos.modifier == pytest.approx(0.25)
    neg = SentimentEvidence(modifier=-0.25)
    assert neg.modifier == pytest.approx(-0.25)
