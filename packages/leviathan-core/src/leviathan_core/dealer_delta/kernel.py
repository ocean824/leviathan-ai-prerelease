"""DEX-001 clean-room dealer delta exposure scenario kernel.

For each option series, this estimates signed delta-equivalent underlying units as
``delta * open_interest * contract_multiplier * dealer_side_sign`` and sums
them by expiry. The call/put signs are an explicit scenario assumption, not
observed dealer inventory. Inputs carry delta availability and source lineage;
missing delta abstains for the whole snapshot, and future evidence is rejected.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from datetime import date
from fractions import Fraction
from typing import Literal

from leviathan_core.dealer_gamma.models import exact_fraction_decimal
from leviathan_core.numeric import canonical_json
from leviathan_core.seal import Issuer, SealError, require

from .models import DexChainEvidenceV1, DexEstimateV1, DexExpiryExposureV1, DexPolicyV1

_ISSUER = Issuer("dex001.estimate.v1")


class DexKernelError(ValueError):
    """Content-free DEX kernel failure."""

    _CODES = frozenset({"INVALID_INPUT", "FUTURE_EVIDENCE", "UNISSUED_RESULT"})

    def __init__(self, code: str) -> None:
        self.code = code if code in self._CODES else "INVALID_INPUT"
        super().__init__(self.code)


def is_issued_dex_estimate(value: object) -> bool:
    if type(value) is not DexEstimateV1:
        return False
    try:
        require(value, _ISSUER.tag)
    except SealError:
        return False
    return True


def require_dex_estimate(value: object) -> DexEstimateV1:
    if not is_issued_dex_estimate(value):
        raise DexKernelError("UNISSUED_RESULT")
    assert isinstance(value, DexEstimateV1)
    return value


def _semantic_payload(
    evidence: DexChainEvidenceV1,
    policy: DexPolicyV1,
    exposures: tuple[DexExpiryExposureV1, ...],
    status: str,
    missing: int,
    effective_observed_ns: int,
) -> dict[str, object]:
    return {
        "status": status,
        "chain_snapshot_id": evidence.chain_snapshot_id,
        "underlier": evidence.underlier,
        "venue": evidence.venue,
        "provider": evidence.provider,
        "dataset": evidence.dataset,
        "chain_observed_ns": evidence.observed_ns,
        "observed_ns": effective_observed_ns,
        "available_ns": evidence.available_ns,
        "provenance_digest": evidence.provenance_digest,
        "series": tuple(
            row.model_dump(mode="json")
            for row in sorted(
                evidence.series,
                key=lambda item: (
                    item.series_id,
                    item.expiry.isoformat(),
                ),
            )
        ),
        "policy_id": policy.policy_id,
        "policy_version": policy.version,
        "call_dealer_sign": policy.call_dealer_sign,
        "put_dealer_sign": policy.put_dealer_sign,
        "expiry_exposures": tuple(row.model_dump(mode="json") for row in exposures),
        "missing_delta_count": missing,
    }


def calculate_dex(
    evidence: DexChainEvidenceV1,
    policy: DexPolicyV1,
    *,
    decision_as_of_ns: int,
) -> DexEstimateV1:
    """Calculate exact signed delta-equivalent exposure, grouped by expiry."""
    if type(evidence) is not DexChainEvidenceV1 or type(policy) is not DexPolicyV1:
        raise DexKernelError("INVALID_INPUT")
    if type(decision_as_of_ns) is not int or decision_as_of_ns < 0:
        raise DexKernelError("INVALID_INPUT")
    if evidence.observed_ns > decision_as_of_ns or evidence.available_ns > decision_as_of_ns:
        raise DexKernelError("FUTURE_EVIDENCE")
    if any(
        row.delta_observed_ns > decision_as_of_ns
        or row.delta_available_ns > decision_as_of_ns
        or row.oi_asof_ns > decision_as_of_ns
        for row in evidence.series
    ):
        raise DexKernelError("FUTURE_EVIDENCE")

    # Preserve the latest observation timestamp among every input used by this calculation.
    effective_observed_ns = max(
        evidence.observed_ns, *(row.delta_observed_ns for row in evidence.series)
    )
    missing = sum(row.delta is None for row in evidence.series)
    if missing:
        exposures: tuple[DexExpiryExposureV1, ...] = ()
        status: Literal["OK", "MISSING_DELTA"] = "MISSING_DELTA"
    else:
        totals: defaultdict[date, Fraction] = defaultdict(Fraction)
        counts: defaultdict[date, int] = defaultdict(int)
        for row in evidence.series:
            assert row.delta is not None
            sign = policy.call_dealer_sign if row.option_type == "CALL" else policy.put_dealer_sign
            totals[row.expiry] += (
                Fraction(row.delta) * Fraction(row.open_interest) * Fraction(row.multiplier) * sign
            )
            counts[row.expiry] += 1
        exposures = tuple(
            DexExpiryExposureV1(
                expiry=expiry,
                signed_delta_contracts=exact_fraction_decimal(total),
                series_count=counts[expiry],
            )
            for expiry, total in sorted(totals.items())
        )
        status = "OK"

    reason: Literal["NONE", "MISSING_DELTA"] = "NONE" if status == "OK" else "MISSING_DELTA"
    semantic = hashlib.sha256(
        canonical_json(
            _semantic_payload(evidence, policy, exposures, status, missing, effective_observed_ns)
        )
    ).hexdigest()
    estimate = DexEstimateV1(
        status=status,
        reason=reason,
        chain_snapshot_id=evidence.chain_snapshot_id,
        underlier=evidence.underlier,
        venue=evidence.venue,
        provider=evidence.provider,
        dataset=evidence.dataset,
        chain_observed_ns=evidence.observed_ns,
        observed_ns=effective_observed_ns,
        available_ns=evidence.available_ns,
        provenance_digest=evidence.provenance_digest,
        policy_id=policy.policy_id,
        policy_version=policy.version,
        expiry_exposures=exposures,
        missing_delta_count=missing,
        semantic_digest=semantic,
    )
    return _ISSUER.issue(estimate)


__all__ = ["DexKernelError", "calculate_dex", "is_issued_dex_estimate", "require_dex_estimate"]
