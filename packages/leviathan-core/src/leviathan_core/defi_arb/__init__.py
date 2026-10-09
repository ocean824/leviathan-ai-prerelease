"""Synthetic, offline arbitrage route math; no chain or broadcast capability."""

from .models import (
    ArbInputError,
    ArbPolicyV1,
    ArbRouteV1,
    FlashLoanV1,
    ForkSnapshotV1,
    GasEvidenceV1,
    SimulationResultV1,
    SwapLegV1,
    TokenV1,
)
from .simulation import require_simulation_result, simulate_route

__all__ = [
    "ArbInputError",
    "ArbPolicyV1",
    "ArbRouteV1",
    "FlashLoanV1",
    "ForkSnapshotV1",
    "GasEvidenceV1",
    "SimulationResultV1",
    "SwapLegV1",
    "TokenV1",
    "require_simulation_result",
    "simulate_route",
]
