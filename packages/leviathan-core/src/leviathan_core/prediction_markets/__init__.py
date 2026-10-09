"""Offline prediction-market identity, normalization and taxonomy mapping."""

from .mapping import map_event
from .models import (
    FXRateV1,
    MappingAuditIntentV1,
    MappingDecisionV1,
    MappingRuleV1,
    NormalizedPriorV1,
    OutcomeProbabilityV1,
    PredictionError,
    PredictionMarketIdentityV1,
    PredictionSourceRecordV1,
    ResolutionEventV1,
    SourceReferenceV1,
    require_mapping,
    require_prior,
)
from .normalization import normalize

__all__ = [
    "FXRateV1",
    "MappingAuditIntentV1",
    "MappingDecisionV1",
    "MappingRuleV1",
    "NormalizedPriorV1",
    "OutcomeProbabilityV1",
    "PredictionError",
    "PredictionMarketIdentityV1",
    "PredictionSourceRecordV1",
    "ResolutionEventV1",
    "SourceReferenceV1",
    "map_event",
    "normalize",
    "require_mapping",
    "require_prior",
]
