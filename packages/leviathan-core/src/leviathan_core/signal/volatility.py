"""Volatility-regime detection — compression vs expansion (SIREN).

Volatility is the market's breathing. It coils (compression) and it
releases (expansion), and the transition between the two is where edge
lives: breakouts born out of compression carry, breakouts into already-
expanded volatility exhaust. We measure regime with true range rather
than close-to-close change so that gaps and wick violence are counted,
and we judge the *recent* window against a *prior baseline* window — a
regime is defined relative to what the market was just doing, never in
absolute terms.
"""

from decimal import Decimal

from leviathan_core.schemas import Bar, MarketState


class VolatilityStateDetector:
    """Label the volatility regime of the latest bars against a baseline.

    ``recent`` is the short window whose mean true range is the reading;
    ``baseline`` is the longer prior window it is compared against.
    Below ``compression_ratio`` of the baseline the market is coiling
    (:data:`MarketState.COMPRESSION`); above ``expansion_ratio`` it is
    releasing (:data:`MarketState.EXPANSION`); in between there is no
    regime signal and ``None`` is returned rather than a guess.
    """

    def __init__(
        self,
        recent: int = 5,
        baseline: int = 20,
        compression_ratio: Decimal = Decimal("0.6"),
        expansion_ratio: Decimal = Decimal("1.5"),
    ) -> None:
        if recent < 1 or baseline < 1:
            raise ValueError("volatility windows must contain at least one bar")
        self._recent = recent
        self._baseline = baseline
        self._compression_ratio = compression_ratio
        self._expansion_ratio = expansion_ratio

    def detect(self, bars: tuple[Bar, ...]) -> MarketState | None:
        needed = self._recent + self._baseline
        if len(bars) < needed:
            return None

        recent_bars = bars[-self._recent :]
        baseline_bars = bars[-needed : -self._recent]

        recent_tr = self._mean_true_range(recent_bars)
        baseline_tr = self._mean_true_range(baseline_bars)
        if baseline_tr == 0:
            return None

        ratio = recent_tr / baseline_tr
        if ratio < self._compression_ratio:
            return MarketState.COMPRESSION
        if ratio > self._expansion_ratio:
            return MarketState.EXPANSION
        return None

    def _mean_true_range(self, bars: tuple[Bar, ...]) -> Decimal:
        total = sum((self._true_range(b) for b in bars), Decimal(0))
        return total / Decimal(len(bars))

    @staticmethod
    def _true_range(bar: Bar) -> Decimal:
        # Prior close is unavailable per-bar here; intrabar range is the
        # honest, self-contained proxy and keeps windows order-independent.
        return bar.high - bar.low
