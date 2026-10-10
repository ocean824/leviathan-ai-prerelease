"""INTEL projection for the DEX-001 sealed estimate."""

from __future__ import annotations

from datetime import date
from decimal import Decimal
from typing import TYPE_CHECKING

from leviathan_core.dealer_gamma.models import GammaEstimateV1, semantic_digest
from leviathan_core.intel.kernel_adapters import (
    FactorAdapterInputError,
    GammaFactorAdapter,
    _projection,
)
from leviathan_core.intel.models import (
    AsOfContextV1,
    EvidenceRefV1,
    FactorFreshnessPolicyV1,
    FactorOutcomeV1,
    Freshness,
    evidence_from_payload,
    issue_as_of_context,
    require_as_of_context,
)

from .kernel import require_dex_estimate
from .models import DexEstimateV1

if TYPE_CHECKING:
    from leviathan_core.dealer_gamma.models import HorizonEstimateV1


class DexFactorAdapter:
    """Bind a DEX expiry projection to the matching GEX chain and evidence."""

    factor_id = "dex001.dealer-delta.v1"
    method = "dex001.delta-oi-multiplier-signed-by-assumption"
    method_version = "1"

    def __init__(self, *, scale: Decimal) -> None:
        if type(scale) is not Decimal or not scale.is_finite() or scale <= 0:
            raise ValueError("INVALID_DEX_FACTOR_SCALE")
        self.scale = scale

    @staticmethod
    def _dex_reference(estimate: DexEstimateV1, gamma: GammaEstimateV1) -> EvidenceRefV1:
        horizon = DexFactorAdapter._matching_gamma(estimate, gamma)
        return evidence_from_payload(
            source=f"dex001.estimate:{estimate.provider}:{estimate.dataset}",
            payload={
                "semantic_digest": estimate.semantic_digest,
                "chain_snapshot_id": estimate.chain_snapshot_id,
                "chain_observed_ns": estimate.chain_observed_ns,
                "dex_policy_id": estimate.policy_id,
                "dex_policy_version": estimate.policy_version,
                "gex_policy_id": gamma.policy_id,
                "gex_policy_version": gamma.policy_version,
                "gex_assumption_id": horizon.assumption_id,
                "gex_assumption_version": horizon.assumption_version,
            },
            source_event_ns=estimate.observed_ns,
            as_of_ns=estimate.available_ns,
        )

    @staticmethod
    def context_for(
        estimate: DexEstimateV1,
        gamma: GammaEstimateV1,
        *,
        decision_as_of_ns: int,
        freshness: Freshness = "fresh",
    ) -> AsOfContextV1:
        checked = require_dex_estimate(estimate)
        semantic_digest(gamma)
        DexFactorAdapter._matching_gamma(checked, gamma)
        dex_reference = DexFactorAdapter._dex_reference(checked, gamma)
        gamma_reference = GammaFactorAdapter.evidence_reference(gamma)
        refs = tuple(
            sorted(
                (dex_reference, gamma_reference),
                key=lambda ref: (ref.source, ref.record_digest),
            )
        )
        return issue_as_of_context(
            decision_as_of_ns=decision_as_of_ns,
            freshness=freshness,
            evidence_refs=refs,
        )

    @staticmethod
    def _matching_gamma(estimate: DexEstimateV1, gamma: GammaEstimateV1) -> HorizonEstimateV1:
        horizons = tuple(
            horizon
            for horizon in (gamma.live, gamma.settled)
            if horizon is not None and horizon.snapshot_id == estimate.chain_snapshot_id
        )
        if len(horizons) != 1:
            raise FactorAdapterInputError()
        horizon = horizons[0]
        if (
            horizon.observed_ns != estimate.chain_observed_ns
            or horizon.available_ns != estimate.available_ns
            or estimate.provider not in horizon.source_ids
            or gamma.underlier != estimate.underlier
            or estimate.provenance_digest != gamma.semantic_digest
        ):
            raise FactorAdapterInputError()
        return horizon

    def evaluate(
        self,
        estimate: DexEstimateV1,
        gamma: GammaEstimateV1,
        expiry: date,
        context: AsOfContextV1,
        policy: FactorFreshnessPolicyV1 | None = None,
    ) -> FactorOutcomeV1:
        checked = require_dex_estimate(estimate)
        semantic_digest(gamma)  # checks the existing GEX issuance registry.
        self._matching_gamma(checked, gamma)
        dex_reference = self._dex_reference(checked, gamma)
        gamma_reference = GammaFactorAdapter.evidence_reference(gamma)
        issued = require_as_of_context(context)
        refs = tuple(
            sorted(
                (dex_reference, gamma_reference),
                key=lambda ref: (ref.source, ref.record_digest),
            )
        )
        if issued.evidence_refs != refs:
            raise FactorAdapterInputError()
        exposure = next(
            (
                row.signed_delta_contracts
                for row in checked.expiry_exposures
                if row.expiry == expiry
            ),
            None,
        )
        factor_id = f"{self.factor_id}:{expiry.isoformat()}"
        return _projection(
            factor_id=factor_id,
            family="dex",
            method=self.method,
            method_version=self.method_version,
            instrument=checked.underlier,
            venue=checked.venue,
            value=exposure,
            scale=self.scale,
            reliability=Decimal("1"),
            source_event_ns=checked.observed_ns,
            context=issued,
            policy=policy,
            ineligible=False,
            missing_reason="MISSING_DELTA",
        )


__all__ = ["DexFactorAdapter"]
