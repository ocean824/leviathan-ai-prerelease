"""Pure, fail-closed four-layer confirmation before independent risk evaluation."""

from __future__ import annotations

import hashlib
from collections import defaultdict
from decimal import localcontext
from typing import Any

from leviathan_core.decision_fusion.models import (
    FeatureAttributionV1,
    FeatureSnapshotV1,
    FusionPolicyV1,
    FusionRequestV1,
    FusionResultV1,
    FusionStatus,
    IdempotencyCheck,
    LayerName,
    LayerObservationV1,
    LayerStatus,
    LayerVerdictV1,
    canonical_decimal,
    finite_decimal,
)
from leviathan_core.numeric import canonical_json
from leviathan_core.numeric._context import numeric_context

_LAYERS: tuple[LayerName, ...] = ("L1", "L2", "L3", "L4")


def _encoded(value: Any) -> bytes:
    return canonical_json(value)


def _hash(value: Any) -> str:
    return hashlib.sha256(_encoded(value)).hexdigest()


def _decimal_or_original(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        return canonical_decimal(value)
    except ValueError:
        return value


def _observation_data(observation: LayerObservationV1) -> dict[str, Any]:
    data = observation.model_dump(mode="json")
    for name in ("score", "confidence"):
        data[name] = _decimal_or_original(data[name])
    return data


def _request_data(
    request: FusionRequestV1,
    observations: tuple[LayerObservationV1, ...],
    snapshots: tuple[FeatureSnapshotV1, ...],
    attributions: tuple[FeatureAttributionV1, ...],
) -> dict[str, Any]:
    """Canonical content deliberately excludes the caller's previous hash."""
    data = request.model_dump(
        mode="json",
        exclude={"prior_input_hash", "observations", "feature_snapshots", "feature_attributions"},
    )
    data["observations"] = sorted((_observation_data(item) for item in observations), key=_encoded)
    data["feature_snapshots"] = sorted(
        (item.model_dump(mode="json") for item in snapshots), key=_encoded
    )
    data["feature_attributions"] = sorted(
        (item.model_dump(mode="json") for item in attributions), key=_encoded
    )
    return data


def _policy_data(policy: FusionPolicyV1) -> dict[str, Any]:
    data = policy.model_dump(mode="json")
    data["required_sources"] = sorted(data["required_sources"], key=lambda pair: pair[0])
    return data


def _identity(request: FusionRequestV1, observations: tuple[LayerObservationV1, ...]) -> str:
    fingerprints = sorted(
        (item.layer, item.source, item.source_version, item.semantic_digest)
        for item in observations
    )
    return _hash(
        {
            "tenant_id": request.tenant_id,
            "strategy_revision": request.strategy_revision,
            "symbol": request.symbol,
            "window_id": request.window_id,
            "signal_fingerprints": fingerprints,
        }
    )


def _layer_score(observation: LayerObservationV1, layer: str) -> str | None:
    if layer == "L2" or layer == "L4":
        return _decimal_or_original(observation.score)
    if layer == "L3":
        return _decimal_or_original(observation.confidence)
    return None


def _layer_verdict(
    layer: LayerName,
    observations: list[LayerObservationV1],
    request: FusionRequestV1,
    policy: FusionPolicyV1,
    sources: dict[LayerName, str],
) -> LayerVerdictV1:
    threshold = {
        "L1": "ok",
        "L2": policy.min_l2_score,
        "L3": policy.min_l3_confidence,
        "L4": policy.min_l4_score,
    }[layer]
    if not observations:
        return LayerVerdictV1(
            layer=layer,
            status="MISSING",
            reason_codes=("MISSING_LAYER",),
            threshold=threshold,
            score=None,
            source=None,
            source_version=None,
            event_ns=None,
            available_ns=None,
        )

    ordered = sorted(observations, key=lambda item: _encoded(_observation_data(item)))
    item = ordered[0]
    reasons: list[str] = []
    if len(ordered) > 1:
        code = (
            "DUPLICATE_LAYER"
            if all(_observation_data(other) == _observation_data(item) for other in ordered[1:])
            else "CONFLICTING_LAYER"
        )
        reasons.append(code)
    if item.source != sources[layer]:
        reasons.append("UNSUPPORTED_SOURCE")
    if item.available_ns > request.evaluation_ns:
        reasons.append("FUTURE_LAYER")
    if item.event_ns > request.evaluation_ns:
        reasons.append("FUTURE_LAYER")
    elif item.event_ns < request.evaluation_ns - policy.window_ns:
        reasons.append("STALE_LAYER")

    score = _layer_score(item, layer)
    if layer == "L1":
        if item.integrity != "ok":
            reasons.append("INVALID_LAYER_DATA")
    else:
        if score is None:
            reasons.append("INVALID_LAYER_DATA")
        else:
            try:
                number = finite_decimal(score)
            except ValueError:
                reasons.append("INVALID_LAYER_DATA")
            else:
                if not 0 <= number <= 1:
                    reasons.append("INVALID_LAYER_DATA")
                elif number < finite_decimal(threshold):
                    reasons.append("BELOW_THRESHOLD")

    reasons = sorted(set(reasons))
    status: LayerStatus = "PASS"
    if reasons:
        status = "STALE" if "STALE_LAYER" in reasons else "FAIL"
    return LayerVerdictV1(
        layer=layer,
        status=status,
        reason_codes=tuple(reasons),
        threshold=threshold,
        score=score,
        source=item.source,
        source_version=item.source_version,
        event_ns=item.event_ns,
        available_ns=item.available_ns,
    )


def _top_attributions(
    attributions: tuple[FeatureAttributionV1, ...],
) -> tuple[FeatureAttributionV1, ...]:
    return tuple(
        sorted(
            attributions,
            key=lambda item: (
                -abs(finite_decimal(item.contribution)),
                item.feature,
                item.contribution,
            ),
        )[:5]
    )


def _asof_observations(
    request: FusionRequestV1,
) -> tuple[tuple[LayerObservationV1, ...], tuple[LayerObservationV1, ...]]:
    visible = tuple(
        item for item in request.observations if item.available_ns <= request.evaluation_ns
    )
    visible_layers = {item.layer for item in visible}
    identity_inputs = tuple(
        item
        for item in request.observations
        if item.available_ns <= request.evaluation_ns
        or (item.layer in _LAYERS and item.layer not in visible_layers)
    )
    return visible, identity_inputs


def _asof_snapshots(
    request: FusionRequestV1,
) -> tuple[tuple[FeatureSnapshotV1, ...], tuple[FeatureSnapshotV1, ...]]:
    visible = tuple(
        item for item in request.feature_snapshots if item.available_ns <= request.evaluation_ns
    )
    identity_inputs = visible if visible else request.feature_snapshots
    return visible, identity_inputs


def _asof_attributions(
    request: FusionRequestV1,
    snapshots: tuple[FeatureSnapshotV1, ...],
) -> tuple[FeatureAttributionV1, ...]:
    """Keep only attributions with visible snapshot or availability provenance."""
    visible_ids = {item.snapshot_id for item in snapshots if item.event_ns <= request.evaluation_ns}
    return tuple(
        item
        for item in request.feature_attributions
        if (item.snapshot_id is not None or item.available_ns is not None)
        and (item.snapshot_id is None or item.snapshot_id in visible_ids)
        and (item.available_ns is None or item.available_ns <= request.evaluation_ns)
    )


def evaluate(request: FusionRequestV1, policy: FusionPolicyV1) -> FusionResultV1:
    """Evaluate complete as-of evidence; candidate status cannot authorize routing.

    A caller can supply the stored prior request-and-policy hash for the same
    semantic key. Comparing it here keeps this kernel stateless and makes
    changed-policy conflict explicit.
    """
    with localcontext(numeric_context()):
        return _evaluate(request, policy)


def _evaluate(request: FusionRequestV1, policy: FusionPolicyV1) -> FusionResultV1:
    visible_observations, identity_observations = _asof_observations(request)
    visible_snapshots, identity_snapshots = _asof_snapshots(request)
    visible_attributions = _asof_attributions(request, visible_snapshots)
    policy_data = _policy_data(policy)
    input_hash = _hash(
        {
            "request": _request_data(
                request, identity_observations, identity_snapshots, visible_attributions
            ),
            "policy": policy_data,
        }
    )
    policy_hash = _hash(policy_data)
    idempotency_key = _identity(request, identity_observations)
    sources = dict(policy.required_sources)
    grouped: dict[str, list[LayerObservationV1]] = defaultdict(list)
    global_reasons: list[str] = []
    for item in visible_observations:
        if item.layer in _LAYERS:
            grouped[item.layer].append(item)
        else:
            global_reasons.append("UNSUPPORTED_LAYER")

    verdicts = tuple(
        _layer_verdict(layer, grouped[layer], request, policy, sources) for layer in _LAYERS
    )
    for layer in _LAYERS:
        if not grouped[layer] and any(
            item.layer == layer and item.available_ns > request.evaluation_ns
            for item in request.observations
        ):
            global_reasons.append("FUTURE_LAYER")
    if all(len(grouped[layer]) == 1 for layer in _LAYERS):
        times = [grouped[layer][0].event_ns for layer in _LAYERS]
        if max(times) - min(times) > policy.max_source_skew_ns:
            global_reasons.append("SOURCE_SKEW")

    if request.feature_snapshots and not visible_snapshots:
        global_reasons.append("FUTURE_FEATURE")
    for snapshot in sorted(visible_snapshots, key=lambda item: item.snapshot_id):
        if snapshot.event_ns > request.evaluation_ns:
            global_reasons.append("FUTURE_FEATURE")
        elif snapshot.event_ns < request.evaluation_ns - policy.window_ns:
            global_reasons.append("STALE_FEATURE")

    if request.market_context.truth_rejected:
        global_reasons.append("TRUTH_REJECTED")
    if request.market_context.global_risk_off:
        global_reasons.append("RISK_OFF")
    if request.market_context.halted:
        global_reasons.append("MARKET_HALT")
    idempotency_check: IdempotencyCheck = "NOT_PERFORMED"
    if request.prior_input_hash is not None:
        idempotency_check = "MATCH" if request.prior_input_hash == input_hash else "CONFLICT"
    if idempotency_check == "CONFLICT":
        global_reasons.append("IDEMPOTENCY_CONFLICT")

    reason_set = set(global_reasons)
    for verdict in verdicts:
        reason_set.update(verdict.reason_codes)
    reasons = tuple(sorted(reason_set))
    status: FusionStatus = "NO_INTENT" if reasons else "CAPITAL_CANDIDATE"
    rationale = (
        "Four as-of layers passed; candidate for downstream risk and sizing only."
        if not reasons
        else "Fusion withheld: " + ", ".join(reasons) + "."
    )
    return FusionResultV1(
        status=status,
        idempotency_check=idempotency_check,
        reason_codes=reasons,
        layer_verdicts=verdicts,
        layer_scores=tuple((item.layer, item.score) for item in verdicts),
        attributions=_top_attributions(visible_attributions),
        rationale=rationale,
        evaluation_ns=request.evaluation_ns,
        input_hash=input_hash,
        policy_hash=policy_hash,
        idempotency_key=idempotency_key,
    )
