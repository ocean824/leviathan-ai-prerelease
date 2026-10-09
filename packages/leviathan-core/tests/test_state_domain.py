"""State domain: transition matrix, session windows, range tracking."""

from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest

from leviathan_core.schemas import Bar, MarketState, PolicyAction, SessionLabel, TransitionRiskClass
from leviathan_core.state.range_tracker import RangeTracker
from leviathan_core.state.session_classifier import classify_session
from leviathan_core.state.transition_engine import TransitionEngine


@pytest.fixture
def engine() -> TransitionEngine:
    return TransitionEngine()


def test_compression_to_breakout_is_stable(engine: TransitionEngine) -> None:
    t = engine.classify(MarketState.COMPRESSION, MarketState.BREAKOUT)
    assert t.risk_class is TransitionRiskClass.STABLE
    assert t.policy_action is PolicyAction.EVALUATE_NORMALLY


def test_any_state_to_event_locked_blocks_autonomy(engine: TransitionEngine) -> None:
    for prior in (MarketState.BREAKOUT, MarketState.EXPANSION, MarketState.DRIFT):
        t = engine.classify(prior, MarketState.EVENT_LOCKED)
        assert t.risk_class is TransitionRiskClass.UNSTABLE
        assert t.policy_action is PolicyAction.NO_AUTONOMOUS_TRADE_APPROVAL


def test_unlisted_transition_requires_manual_review(engine: TransitionEngine) -> None:
    t = engine.classify(MarketState.DRIFT, MarketState.EXHAUSTION)
    assert t.risk_class is TransitionRiskClass.UNSTABLE
    assert t.policy_action is PolicyAction.MANUAL_REVIEW_REQUIRED


def test_confidence_penalties(engine: TransitionEngine) -> None:
    stable = engine.classify(MarketState.COMPRESSION, MarketState.BREAKOUT)
    caution = engine.classify(MarketState.BREAKOUT, MarketState.MEAN_REVERSION)
    unstable = engine.classify(MarketState.DRIFT, MarketState.EXHAUSTION)
    assert engine.adjust_confidence(0.8, stable) == pytest.approx(0.8)
    assert engine.adjust_confidence(0.8, caution) == pytest.approx(0.65)
    assert engine.adjust_confidence(0.8, unstable) == pytest.approx(0.45)
    assert engine.adjust_confidence(0.1, unstable) == 0.0


def test_session_windows() -> None:
    ny_overlap = classify_session(datetime(2026, 4, 15, 15, 0, tzinfo=UTC))
    assert ny_overlap.label is SessionLabel.NY_OVERLAP
    assert ny_overlap.quality == 1.0
    midday = classify_session(datetime(2026, 4, 15, 17, 0, tzinfo=UTC))
    assert midday.label is SessionLabel.NY_MIDDAY
    assert midday.is_dead_time


def test_session_requires_tz_aware() -> None:
    with pytest.raises(ValueError, match="tz-aware"):
        classify_session(datetime(2026, 4, 15, 15, 0))


def _bar(day: int, hour: int, minute: int, lo: str, hi: str) -> Bar:
    low, high = Decimal(lo), Decimal(hi)
    return Bar(
        instrument="NQ",
        timestamp=datetime(2026, 4, day, hour, minute, tzinfo=UTC),
        open=low,
        high=high,
        low=low,
        close=high,
        volume=Decimal(100),
    )


def test_range_tracker_pdh_pdl_and_opening_range() -> None:
    tracker = RangeTracker(opening_range_minutes=30)
    tracker.update(_bar(14, 14, 0, "18000", "18100"))
    tracker.update(_bar(14, 15, 0, "17950", "18050"))
    ctx = tracker.update(_bar(15, 13, 30, "18060", "18080"))
    assert ctx.pdh == Decimal("18100")
    assert ctx.pdl == Decimal("17950")
    assert ctx.midpoint == Decimal("18025")
    later = tracker.update(_bar(15, 14, 30, "18120", "18150"))
    assert later.range_label == "above_opening_range_high"


def test_bar_rejects_incoherent_ohlc() -> None:
    with pytest.raises(ValueError, match="incoherent"):
        Bar(
            instrument="NQ",
            timestamp=datetime(2026, 4, 15, tzinfo=UTC),
            open=Decimal(100),
            high=Decimal(90),
            low=Decimal(95),
            close=Decimal(100),
        )


def test_timedelta_sanity() -> None:
    assert timedelta(minutes=30) > timedelta(minutes=29)
