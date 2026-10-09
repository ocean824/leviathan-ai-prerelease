"""Signal domain: swing detection, market structure, volatility, facade.

Bar sequences are hand-crafted so each assertion isolates one doctrine:
a swing must be dominated on both sides, a break of structure needs a
close through the last pivot, a sweep must reclaim, and the facade only
speaks when there is evidence to report.
"""

from datetime import UTC, datetime, timedelta
from decimal import Decimal

from leviathan_core.schemas import Bar, CandidateSetup, MarketState
from leviathan_core.signal import (
    MarketStructureAnalyzer,
    SignalDetector,
    SwingDetector,
    VolatilityStateDetector,
)

_START = datetime(2026, 4, 15, 14, 0, tzinfo=UTC)


def _bar(i: int, o: str, h: str, low: str, c: str) -> Bar:
    return Bar(
        instrument="NQ",
        timestamp=_START + timedelta(minutes=i),
        open=Decimal(o),
        high=Decimal(h),
        low=Decimal(low),
        close=Decimal(c),
        volume=Decimal(100),
    )


def _flat(i: int, level: str, width: str = "1") -> Bar:
    """A quiet bar of fixed intrabar width centred on ``level``."""
    lo = Decimal(level)
    hi = lo + Decimal(width)
    return Bar(
        instrument="NQ",
        timestamp=_START + timedelta(minutes=i),
        open=lo,
        high=hi,
        low=lo,
        close=lo,
        volume=Decimal(100),
    )


# --- swing detection ---------------------------------------------------------


def test_swing_high_is_confirmed_when_dominant_both_sides() -> None:
    bars = (
        _bar(0, "100", "101", "100", "100"),
        _bar(1, "100", "102", "100", "101"),
        _bar(2, "101", "110", "101", "105"),  # dominant peak at index 2
        _bar(3, "103", "103", "102", "102"),
        _bar(4, "101", "102", "100", "100"),
    )
    swings = SwingDetector(lookback=2).detect(bars)
    highs = [s for s in swings if s.kind == "high"]
    assert len(highs) == 1
    assert highs[0].index == 2
    assert highs[0].price == Decimal("110")


def test_swing_low_is_confirmed_when_dominated_both_sides() -> None:
    bars = (
        _bar(0, "110", "110", "108", "109"),
        _bar(1, "109", "109", "106", "107"),
        _bar(2, "106", "106", "100", "103"),  # dominant trough at index 2
        _bar(3, "104", "107", "104", "106"),
        _bar(4, "106", "110", "105", "109"),
    )
    swings = SwingDetector(lookback=2).detect(bars)
    lows = [s for s in swings if s.kind == "low"]
    assert len(lows) == 1
    assert lows[0].index == 2
    assert lows[0].price == Decimal("100")


def test_edge_bars_cannot_be_confirmed_swings() -> None:
    # A rising staircase: no interior bar is a local pivot.
    bars = tuple(_bar(i, str(100 + i), str(101 + i), str(100 + i), str(100 + i)) for i in range(6))
    assert SwingDetector(lookback=2).detect(bars) == ()


# --- market structure --------------------------------------------------------


def test_msb_up_when_close_breaks_last_swing_high() -> None:
    bars = (
        _bar(0, "100", "101", "100", "100"),
        _bar(1, "100", "102", "100", "101"),
        _bar(2, "101", "110", "101", "105"),  # swing high at 110
        _bar(3, "104", "106", "103", "104"),
        _bar(4, "104", "108", "103", "105"),
        _bar(5, "105", "112", "105", "111"),  # closes above 110 -> msb_up
    )
    detector = SwingDetector(lookback=2)
    swings = detector.detect(bars)
    report = MarketStructureAnalyzer().analyze(bars, swings)
    assert "msb_up" in report.signal_features
    assert "msb_down" not in report.signal_features


def test_equal_highs_are_liquidity() -> None:
    # Two swing highs at 110.00 and 110.04 — inside the 0.05% band.
    bars = (
        _bar(0, "100", "101", "100", "100"),
        _bar(1, "100", "102", "100", "101"),
        _bar(2, "101", "110", "101", "105"),  # swing high 110.00
        _bar(3, "103", "103", "102", "102"),
        _bar(4, "102", "104", "101", "103"),
        _bar(5, "103", "110.04", "103", "105"),  # swing high 110.04
        _bar(6, "102", "103", "102", "102"),
        _bar(7, "100", "102", "100", "100"),
    )
    swings = SwingDetector(lookback=2).detect(bars)
    report = MarketStructureAnalyzer().analyze(bars, swings)
    assert "equal_highs" in report.liquidity_features


def test_sweep_high_pierces_then_reclaims() -> None:
    bars = (
        _bar(0, "100", "101", "100", "100"),
        _bar(1, "100", "102", "100", "101"),
        _bar(2, "101", "110", "101", "105"),  # swing high 110
        _bar(3, "104", "106", "103", "104"),
        _bar(4, "104", "108", "103", "105"),
        _bar(5, "105", "112", "104", "108"),  # wicks to 112, closes back at 108
    )
    swings = SwingDetector(lookback=2).detect(bars)
    report = MarketStructureAnalyzer().analyze(bars, swings)
    assert "sweep_high" in report.liquidity_features
    assert "msb_up" not in report.signal_features


# --- volatility regime -------------------------------------------------------


def _series(widths: list[str]) -> tuple[Bar, ...]:
    return tuple(_flat(i, "100", w) for i, w in enumerate(widths))


def test_compression_when_recent_range_collapses() -> None:
    bars = _series(["10"] * 20 + ["1"] * 5)  # 5-bar TR = 1 vs baseline 10
    assert VolatilityStateDetector().detect(bars) is MarketState.COMPRESSION


def test_expansion_when_recent_range_explodes() -> None:
    bars = _series(["4"] * 20 + ["20"] * 5)  # 5-bar TR = 20 vs baseline 4
    assert VolatilityStateDetector().detect(bars) is MarketState.EXPANSION


def test_no_regime_when_range_is_steady() -> None:
    bars = _series(["10"] * 25)
    assert VolatilityStateDetector().detect(bars) is None


def test_no_regime_without_enough_history() -> None:
    bars = _series(["10"] * 10)
    assert VolatilityStateDetector().detect(bars) is None


# --- facade ------------------------------------------------------------------


def _breakout_window() -> tuple[Bar, ...]:
    """20 quiet baseline bars, then a swing high and an expansion break."""
    bars: list[Bar] = [_flat(i, "100", "1") for i in range(20)]
    # Build a confirmed swing high at ~110, then a wide bar closing above it.
    bars.append(_bar(20, "100", "104", "100", "102"))
    bars.append(_bar(21, "102", "110", "101", "105"))  # pivot high 110
    bars.append(_bar(22, "105", "106", "104", "105"))
    bars.append(_bar(23, "105", "107", "104", "106"))
    bars.append(_bar(24, "106", "125", "106", "124"))  # wide + close above 110
    return tuple(bars)


def test_facade_produces_breakout_setup() -> None:
    bars = _breakout_window()
    setup = SignalDetector().detect(bars)
    assert isinstance(setup, CandidateSetup)
    assert setup.instrument == "NQ"
    assert setup.timestamp == bars[-1].timestamp
    assert setup.setup_id.startswith("setup_")
    assert "msb_up" in setup.signal_features
    assert setup.state_label is MarketState.BREAKOUT


def test_facade_returns_none_on_flat_bars() -> None:
    bars = tuple(_flat(i, "100", "1") for i in range(30))
    assert SignalDetector().detect(bars) is None
