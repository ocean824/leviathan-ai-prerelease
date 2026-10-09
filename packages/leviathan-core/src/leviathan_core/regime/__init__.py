"""Deterministic offline regime awareness kernel (LEV-REQ-027)."""

from .kernel import score
from .models import (
    DEFAULT_WEIGHT_VERSION,
    RegimeClockV1,
    RegimeError,
    RegimeFactorV1,
    RegimeResultV1,
    RegimeSnapshotV1,
    RegimeSourceIdV1,
    RegimeSourceRecordV1,
    RegimeSourceRegistryV1,
    RegimeWeightPolicyV1,
)

__all__ = [
    "DEFAULT_WEIGHT_VERSION",
    "RegimeClockV1",
    "RegimeError",
    "RegimeFactorV1",
    "RegimeResultV1",
    "RegimeSnapshotV1",
    "RegimeSourceIdV1",
    "RegimeSourceRecordV1",
    "RegimeSourceRegistryV1",
    "RegimeWeightPolicyV1",
    "score",
]
