"""Signal Domain — structure, liquidity, and volatility reading (SIREN).

Phase 2 implementation. SIREN is the market's first reader: it turns a
window of raw bars into structural and liquidity evidence, never into a
verdict. It houses:
    swings      — fractal swing-high / swing-low pivot detection
    structure   — break-of-structure (MSB/BOS), equal highs/lows, sweeps
    volatility  — true-range compression / expansion regime labeling
    detector    — the SignalDetector facade producing a CandidateSetup

Its only output is evidence (:class:`CandidateSetup`); permission to
trade is granted downstream, by the Decision Domain alone.
"""

from leviathan_core.signal.detector import SignalDetector
from leviathan_core.signal.structure import MarketStructureAnalyzer, StructureReport
from leviathan_core.signal.swings import SwingDetector, SwingKind, SwingPoint
from leviathan_core.signal.volatility import VolatilityStateDetector

__all__ = [
    "MarketStructureAnalyzer",
    "SignalDetector",
    "StructureReport",
    "SwingDetector",
    "SwingKind",
    "SwingPoint",
    "VolatilityStateDetector",
]
