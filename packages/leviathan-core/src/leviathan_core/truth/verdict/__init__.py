"""Offline truth verdict kernel; advisory evidence, never route permission.

The live pipeline still uses ``leviathan_core.truth.TruthProvider`` and
``TruthValidationResult``. A separate adapter will bridge these contracts.
"""

from leviathan_core.truth.verdict.evaluator import evaluate_truth
from leviathan_core.truth.verdict.models import (
    Action,
    ClockSkewError,
    EventMetricsV1,
    EvidenceStateError,
    InstrumentClass,
    InvalidTruthInputError,
    OptionsFlowMetricsV1,
    OrderBookMetricsV1,
    PolicyOutOfBoundsError,
    PrecisionExceededError,
    ReasonCode,
    SentimentMetricsV1,
    Side,
    SourceState,
    TruthEvidenceV1,
    TruthPolicyV1,
    TruthRequestV1,
    TruthSource,
    TruthVerdictV1,
    Verdict,
)

__all__ = [
    "Action",
    "ClockSkewError",
    "EventMetricsV1",
    "EvidenceStateError",
    "InstrumentClass",
    "InvalidTruthInputError",
    "OptionsFlowMetricsV1",
    "OrderBookMetricsV1",
    "PolicyOutOfBoundsError",
    "PrecisionExceededError",
    "ReasonCode",
    "SentimentMetricsV1",
    "Side",
    "SourceState",
    "TruthEvidenceV1",
    "TruthPolicyV1",
    "TruthRequestV1",
    "TruthSource",
    "TruthVerdictV1",
    "Verdict",
    "evaluate_truth",
]
