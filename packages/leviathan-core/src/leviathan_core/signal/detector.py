"""SignalDetector — the SIREN facade over a bar window.

This is the single entry point the pipeline calls. It orchestrates swing
detection, structure/liquidity reading, and volatility regime, then folds
the evidence into one :class:`CandidateSetup`. Two doctrines are encoded
here. First, a setup is *evidence, never permission*: we populate features
and a state label and hand them upstream — we never decide. Second, a
break of structure that coincides with a volatility expansion is the
canonical breakout, so it is labelled :data:`MarketState.BREAKOUT`
regardless of the raw compression/expansion reading. When no feature at
all is present the window is silent and we return ``None`` rather than
manufacturing a setup.
"""

from leviathan_core.schemas import Bar, CandidateSetup, MarketState
from leviathan_core.schemas.base import new_id
from leviathan_core.signal.structure import MarketStructureAnalyzer
from leviathan_core.signal.swings import SwingDetector
from leviathan_core.signal.volatility import VolatilityStateDetector

_MSB_FEATURES = ("msb_up", "msb_down")


class SignalDetector:
    """Compose the SIREN sub-detectors into a single setup verdict.

    Construction wires the three collaborators with their defaults; pass
    pre-tuned instances to override lookback, tolerance, or volatility
    windows without changing call sites.
    """

    def __init__(
        self,
        swings: SwingDetector | None = None,
        structure: MarketStructureAnalyzer | None = None,
        volatility: VolatilityStateDetector | None = None,
    ) -> None:
        self._swings = swings or SwingDetector()
        self._structure = structure or MarketStructureAnalyzer()
        self._volatility = volatility or VolatilityStateDetector()

    def detect(self, bars: tuple[Bar, ...]) -> CandidateSetup | None:
        if not bars:
            return None

        swings = self._swings.detect(bars)
        report = self._structure.analyze(bars, swings)
        regime = self._volatility.detect(bars)

        if not report.signal_features and not report.liquidity_features:
            return None

        last = bars[-1]
        return CandidateSetup(
            setup_id=new_id("setup"),
            instrument=last.instrument,
            timestamp=last.timestamp,
            signal_features=report.signal_features,
            liquidity_features=report.liquidity_features,
            state_label=self._state_label(report.signal_features, regime),
        )

    @staticmethod
    def _state_label(
        signal_features: tuple[str, ...], regime: MarketState | None
    ) -> MarketState | None:
        broke_structure = any(f in signal_features for f in _MSB_FEATURES)
        if broke_structure and regime is MarketState.EXPANSION:
            return MarketState.BREAKOUT
        return regime
