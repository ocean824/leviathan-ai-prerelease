"""Pure, point-in-time regime scoring; no adapter, storage or route authority."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from dataclasses import replace
from decimal import ROUND_HALF_EVEN, Context, Decimal, DecimalException, localcontext
from fractions import Fraction
from math import isqrt
from statistics import median

from .models import (
    _RESULT_ISSUER,
    FACTOR_KINDS,
    RELEASE_LAGS_NS,
    FactorKind,
    Readiness,
    RegimeError,
    RegimeFactorV1,
    RegimeResultV1,
    RegimeSnapshotV1,
    RegimeSourceRegistryV1,
    RegimeWeightPolicyV1,
    canonical_decimal,
)

ZERO = Decimal(0)
ONE = Decimal(1)
TWO = Decimal(2)
FOUR = Decimal(4)
KERNEL_CONTEXT = Context(prec=34, rounding=ROUND_HALF_EVEN)


def _clamp(value: Decimal, lower: Decimal, upper: Decimal) -> Decimal:
    return min(max(value, lower), upper)


def _bucket(raw: Fraction) -> int:
    if raw < Fraction(-6, 5):
        return -2
    if raw < Fraction(-2, 5):
        return -1
    if raw <= Fraction(2, 5):
        return 0
    if raw <= Fraction(6, 5):
        return 1
    return 2


def _hash(
    snapshot: RegimeSnapshotV1, policy: RegimeWeightPolicyV1,
    source_registry: RegimeSourceRegistryV1, asof_ns: int | None = None,
) -> str:
    clock = snapshot.clock
    payload = {
        "schema": "regime-inputs-v1",
        "evaluation_asof_ns": clock.asof_ns if asof_ns is None else asof_ns,
        "clock": [clock.bar_id, clock.bar_index, clock.session_id, clock.symbol,
                  clock.universe, clock.calendar_version, clock.asof_ns, clock.finalized,
                  clock.window_sec, clock.horizon_sec],
        "record_available_ns": snapshot.record_available_ns,
        "factors": [
            [factor.kind, canonical_decimal(factor.value), factor.source, factor.source_version,
             factor.semantic_digest, factor.event_ns, factor.available_ns,
             factor.baseline_available_ns, factor.valid, factor.fresh_until_ns,
             factor.scope, factor.scope_key, factor.window_sec, factor.horizon_sec,
             factor.entitlement, factor.entitled, factor.release_lag,
             factor.release_lag_ns, factor.feature_available_ns,
             factor.upstream_interface_id, factor.quality, factor.source_type]
            for factor in sorted(snapshot.factors, key=lambda factor: factor.kind)
        ],
        "signal": snapshot.signal_status,
        "truth": snapshot.truth_status,
        "flow": [snapshot.flow_source, snapshot.flow_quality],
        "weight_version": policy.version,
        "source_registry": [source_registry.version, [
            [record.source_id, record.trust_class, record.entitlement,
             record.allowed_interface_ids]
            for record in sorted(source_registry.records, key=lambda record: record.source_id)
        ]],
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _exclusion(
    factor: RegimeFactorV1, snapshot: RegimeSnapshotV1, asof_ns: int,
    freshness_ns: int, source_registry: RegimeSourceRegistryV1,
) -> str | None:
    clock = snapshot.clock
    if not factor.value.is_finite() or not factor.valid:
        return "INVALID"
    if not factor.source or not factor.source_version or not factor.semantic_digest:
        return "SOURCE_UNKNOWN"
    source_record = source_registry.lookup(factor.source)
    if source_record is None or source_record.trust_class != "PIPELINE":
        return "UNTRUSTED_SOURCE"
    if factor.source_type != source_record.trust_class:
        return "UNTRUSTED_SOURCE"
    if (
        factor.upstream_interface_id is not None
        and factor.upstream_interface_id not in source_record.allowed_interface_ids
    ):
        return "UNTRUSTED_INTERFACE"
    if not factor.entitled or factor.entitlement == "UNENTITLED" or (
        source_record.entitlement == "UNENTITLED"
        or factor.entitlement != source_record.entitlement
    ):
        return "UNENTITLED"
    if factor.release_lag_ns != RELEASE_LAGS_NS[factor.release_lag]:
        return "RELEASE_LAG_MISMATCH"
    if factor.quality != "GOOD":
        return "QUALITY"
    if factor.event_ns > clock.asof_ns:
        return "EVENT_FUTURE"
    if factor.available_ns > asof_ns:
        return "UNPUBLISHED"
    if factor.baseline_available_ns > asof_ns:
        return "BASELINE_FUTURE"
    if factor.feature_available_ns is not None and factor.feature_available_ns > asof_ns:
        return "FEATURE_FUTURE"
    if factor.event_ns + factor.release_lag_ns > asof_ns:
        return "RELEASE_LAG"
    if factor.fresh_until_ns < freshness_ns:
        return "STALE"
    if factor.scope == "symbol" and factor.scope_key != clock.symbol:
        return "SCOPE"
    if factor.scope == "class" and factor.scope_key != clock.universe:
        return "SCOPE"
    if clock.window_sec is not None and factor.window_sec != clock.window_sec:
        return "WINDOW"
    if clock.horizon_sec is not None and factor.horizon_sec != clock.horizon_sec:
        return "HORIZON"
    if factor.kind == "flow":
        if factor.upstream_interface_id is None:
            return "UNTRUSTED_INTERFACE"
        if snapshot.flow_source != factor.source:
            return "FLOW_SOURCE"
        if snapshot.flow_quality != "GOOD":
            return "FLOW_QUALITY"
    return None


def _basic(
    snapshot: RegimeSnapshotV1, policy: RegimeWeightPolicyV1, asof_ns: int,
    freshness_ns: int, source_registry: RegimeSourceRegistryV1,
) -> tuple[Decimal | None, Fraction | None, int | None,
           tuple[FactorKind, ...], tuple[str, ...]]:
    reasons: list[str] = []
    if not snapshot.clock.finalized:
        reasons.append("UNFINALIZED_BAR")
    if snapshot.weight_version != policy.version:
        reasons.append("WEIGHT_VERSION_MISMATCH")
    factors = {factor.kind: factor for factor in snapshot.factors}
    anchor = next((factors[kind] for kind in FACTOR_KINDS if kind in factors), None)
    expected_window = snapshot.clock.window_sec or (anchor.window_sec if anchor else None)
    expected_horizon = snapshot.clock.horizon_sec or (anchor.horizon_sec if anchor else None)
    eligible: list[tuple[Decimal, Decimal]] = []
    missing: list[FactorKind] = []
    for kind, weight in zip(FACTOR_KINDS, policy.weights, strict=True):
        factor = factors.get(kind)
        problem = (
            "ABSENT" if factor is None else _exclusion(
                factor, snapshot, asof_ns, freshness_ns, source_registry,
            )
        )
        if problem is None and factor is not None:
            if factor.window_sec != expected_window:
                problem = "WINDOW"
            elif factor.horizon_sec != expected_horizon:
                problem = "HORIZON"
        if problem is not None:
            missing.append(kind)
            reasons.append(
                problem if problem == "UNTRUSTED_INTERFACE" else f"{problem}_{kind.upper()}"
            )
        elif factor is not None:
            eligible.append((weight, _clamp(factor.value, -FOUR, FOUR)))
    if not snapshot.clock.finalized or snapshot.weight_version != policy.version:
        return None, None, None, tuple(missing), tuple(reasons)
    if len(eligible) < 2:
        reasons.append("TOO_FEW_FACTORS")
        return None, None, None, tuple(missing), tuple(reasons)
    denominator = sum((abs(Fraction(weight)) for weight, _ in eligible), Fraction())
    if denominator == 0:
        reasons.append("ZERO_AVAILABLE_WEIGHT")
        return None, None, None, tuple(missing), tuple(reasons)
    if missing:
        reasons.append("PARTIAL")
    weighted = sum((Fraction(weight) * Fraction(value) for weight, value in eligible),
                   Fraction())
    exact_raw = min(max(weighted / denominator, Fraction(-2)), Fraction(2))
    # This Decimal is a display value. The threshold decision uses the exact ratio.
    raw = Decimal(exact_raw.numerator) / Decimal(exact_raw.denominator)
    return raw, exact_raw, _bucket(exact_raw), tuple(missing), tuple(reasons)


def _sample_variance(values: Sequence[Fraction]) -> Fraction:
    count = len(values)
    total = sum(values, Fraction())
    square_total = sum((value * value for value in values), Fraction())
    return (square_total - total * total / count) / (count - 1)


def _sqrt_bounds(value: Fraction, digits: int) -> tuple[Fraction, Fraction]:
    if value == 0:
        return Fraction(), Fraction()
    scale = 10 ** digits
    scaled_numerator = value.numerator * scale * scale
    root = isqrt(scaled_numerator // value.denominator)
    lower = Fraction(root, scale)
    upper = lower if root * root * value.denominator == scaled_numerator else Fraction(
        root + 1, scale,
    )
    return lower, upper


def _confidence_bounds(
    values: Sequence[Fraction], regimes: Sequence[int], policy: RegimeWeightPolicyV1,
    missing_count: int, digits: int,
) -> tuple[Fraction, Fraction]:
    short_low, short_high = _sqrt_bounds(_sample_variance(values[-30:]), digits)
    k = Fraction(policy.k)
    lower = Fraction(3, 5) / (1 + k * short_high)
    upper = Fraction(3, 5) / (1 + k * short_low)
    if len(values) >= 120:
        long_bounds = [
            _sqrt_bounds(_sample_variance(values[end - 120:end]), digits)
            for end in range(120, len(values) + 1)
        ]
        recent = long_bounds[-policy.median_window:]
        epsilon = Fraction(policy.epsilon)
        baseline_low = max(median([bound[0] for bound in recent]), epsilon)
        baseline_high = max(median([bound[1] for bound in recent]), epsilon)
        last_low, last_high = long_bounds[-1]
        lower += Fraction(2, 5) * (1 - last_high / baseline_low)
        upper += Fraction(2, 5) * (1 - last_low / baseline_high)
    run_length = 0
    for regime in reversed(regimes):
        if regime != regimes[-1]:
            break
        run_length += 1
    persistence = min(Fraction(1), Fraction(run_length, 30))
    missing_scale = Fraction(4 - missing_count, 4)
    lower = min(max(lower * persistence, Fraction()), Fraction(1)) * missing_scale
    upper = min(max(upper * persistence, Fraction()), Fraction(1)) * missing_scale
    return lower, upper


def _display_fraction(value: Fraction) -> Decimal:
    return Decimal(value.numerator) / Decimal(value.denominator)


def _visible_prior(prior: RegimeResultV1 | None, asof_ns: int) -> RegimeResultV1 | None:
    if prior is None:
        return None
    if prior.evaluation_asof_ns > asof_ns or prior.clock.asof_ns > asof_ns:
        return None
    return prior


def _confidence(
    values: Sequence[Fraction], regimes: Sequence[int], policy: RegimeWeightPolicyV1,
    missing_count: int,
) -> tuple[Decimal, Readiness, tuple[str, ...]]:
    if len(values) < 30:
        return ZERO, "HOLD", ("WARMUP_30", "WARMUP_120")
    reasons = ("WARMUP_120",) if len(values) < 120 else ()
    for digits in (40, 80, 160, 320, 640):
        lower, upper = _confidence_bounds(values, regimes, policy, missing_count, digits)
        displayed_low, displayed_high = _display_fraction(lower), _display_fraction(upper)
        if displayed_low != displayed_high:
            continue
        if reasons:
            return displayed_low, "HOLD", reasons
        if lower >= Fraction(7, 10):
            return displayed_low, "READY", reasons
        if lower >= Fraction(2, 5) and upper < Fraction(7, 10):
            return displayed_low, "DEGRADED", reasons
        if upper < Fraction(2, 5):
            return displayed_low, "HOLD", reasons
    raise RegimeError("PRECISION_EXCEEDED")


def _series(
    snapshots: Sequence[RegimeSnapshotV1], policy: RegimeWeightPolicyV1,
    asof_ns: int, latest_index: int,
    source_registry: RegimeSourceRegistryV1,
) -> list[RegimeResultV1]:
    results: list[RegimeResultV1] = []
    values: list[Fraction] = []
    regimes: list[int] = []
    previous_index: int | None = None
    for item in snapshots:
        clock = item.clock
        if previous_index is not None and clock.bar_index != previous_index + 1:
            values.clear()
            regimes.clear()
        previous_index = clock.bar_index
        evaluation_asof = asof_ns
        freshness_ns = clock.asof_ns if clock.bar_index < latest_index else evaluation_asof
        raw, exact_raw, regime, missing, basic_reasons = _basic(
            item, policy, evaluation_asof, freshness_ns, source_registry,
        )
        reasons = list(basic_reasons)
        if item.signal_status != "FINALIZED":
            reasons.append("SIGNAL_NOT_FINALIZED")
        if item.truth_status != "PASS":
            reasons.append("TRUTH_" + item.truth_status.upper())
        prior = _visible_prior(item.prior_result, evaluation_asof)
        previous_revision = prior.revision if prior is not None else None
        revision = (
            0 if prior is None else prior.revision + (
                prior.inputs_hash != _hash(item, policy, source_registry, evaluation_asof)
            )
        )
        if raw is None or exact_raw is None or regime is None:
            values.clear()
            regimes.clear()
            prior_regime = next(
                (result.composite_regime for result in reversed(results)
                 if result.composite_regime is not None), None,
            )
            carried = prior_regime is not None
            result = RegimeResultV1(
                clock=clock, composite_raw=None, composite_regime=prior_regime,
                confidence=ZERO, readiness="HOLD", status="INSUFFICIENT_DATA",
                missing_factors=missing, reason_codes=tuple(reasons), carried_forward=carried,
                revision=revision, inputs_hash=_hash(
                    item, policy, source_registry, evaluation_asof,
                ),
                weight_version=policy.version,
                publish_current=clock.finalized and clock.bar_index > latest_index - 2,
                previous_revision=previous_revision,
                factor_provenance=tuple(sorted(item.factors, key=lambda factor: factor.kind)),
                evaluation_asof_ns=evaluation_asof,
                _issuer_token=_RESULT_ISSUER,
            )
        else:
            values.append(exact_raw)
            regimes.append(regime)
            confidence, readiness, warmup_reasons = _confidence(
                values, regimes, policy, len(missing),
            )
            reasons.extend(warmup_reasons)
            if missing and readiness == "READY":
                readiness = "DEGRADED"
            if warmup_reasons or item.signal_status != "FINALIZED" or item.truth_status != "PASS":
                readiness = "HOLD"
            result = RegimeResultV1(
                clock=clock, composite_raw=raw, composite_regime=regime,
                confidence=confidence, readiness=readiness,
                status="PARTIAL" if missing else "SCORED", missing_factors=missing,
                reason_codes=tuple(reasons), carried_forward=False, revision=revision,
                inputs_hash=_hash(item, policy, source_registry, evaluation_asof),
                weight_version=policy.version,
                publish_current=clock.finalized and clock.bar_index > latest_index - 2,
                previous_revision=previous_revision,
                factor_provenance=tuple(sorted(item.factors, key=lambda factor: factor.kind)),
                evaluation_asof_ns=evaluation_asof,
                _issuer_token=_RESULT_ISSUER,
            )
        results.append(result)
        if missing or item.signal_status != "FINALIZED" or item.truth_status != "PASS":
            # A partial or vetoed bar is not complete warmup evidence for later bars.
            values.clear()
            regimes.clear()
    return results


def _score(
    snapshot: RegimeSnapshotV1,
    policy: RegimeWeightPolicyV1,
    history: Sequence[RegimeSnapshotV1],
    asof_ns: int,
    source_registry: RegimeSourceRegistryV1,
) -> RegimeResultV1:
    """Score a finalized bar from source snapshots; return correction lineage without I/O.

    ``history`` consists of prior finalized bar snapshots, not cached score values.
    Replaying them from source makes a changed bar update all affected rolling windows.
    The caller owns publication and storage; ``publish_current`` only marks eligibility.
    """
    if policy.status != "ACTIVE":
        raise RegimeError("PROPOSED_POLICY")
    if not isinstance(history, Sequence):
        raise RegimeError("HISTORY_INVALID")
    if type(asof_ns) is not int or asof_ns < 0:
        raise RegimeError("ASOF_INVALID")
    if asof_ns < snapshot.clock.asof_ns:
        raise RegimeError("ASOF_INVALID")
    if snapshot.record_available_ns > asof_ns:
        raise RegimeError("RECORD_NOT_VISIBLE")
    if snapshot.prior_result is not _visible_prior(snapshot.prior_result, asof_ns):
        snapshot = replace(snapshot, prior_result=None)
    identity = (snapshot.clock.symbol, snapshot.clock.universe, snapshot.clock.calendar_version)
    visible_history: list[RegimeSnapshotV1] = []
    for item in history:
        if not isinstance(item, RegimeSnapshotV1):
            raise RegimeError("HISTORY_INVALID")
        if item.record_available_ns > asof_ns:
            continue
        if item.prior_result is not _visible_prior(item.prior_result, asof_ns):
            item = replace(item, prior_result=None)
        if (item.clock.symbol, item.clock.universe, item.clock.calendar_version) != identity:
            raise RegimeError("HISTORY_SCOPE_MISMATCH")
        if item.clock.finalized and item.clock.asof_ns <= asof_ns:
            visible_history.append(item)
    latest_index = max(
        (item.clock.bar_index for item in visible_history),
        default=snapshot.clock.bar_index,
    )
    if snapshot.clock.finalized:
        latest_index = max(latest_index, snapshot.clock.bar_index)
    by_index: dict[int, RegimeSnapshotV1] = {}
    for item in sorted(visible_history, key=lambda item: (item.clock.bar_index,
                                                           item.clock.asof_ns,
                                                           _hash(item, policy, source_registry))):
        prior_at_index = by_index.get(item.clock.bar_index)
        if prior_at_index is not None and (
            prior_at_index.clock.bar_id != item.clock.bar_id
            or _hash(prior_at_index, policy, source_registry) != _hash(
                item, policy, source_registry,
            )
            or prior_at_index.prior_result != item.prior_result
        ):
            raise RegimeError("HISTORY_CONFLICT")
        by_index[item.clock.bar_index] = item
    prior = by_index.get(snapshot.clock.bar_index)
    if prior is not None and prior.clock.bar_id != snapshot.clock.bar_id:
        raise RegimeError("HISTORY_CONFLICT")
    old_results = _series(
        [by_index[index] for index in sorted(by_index)], policy,
        asof_ns, latest_index, source_registry,
    ) if prior is not None else []
    if prior is not None and snapshot.prior_result is None:
        # The original bar is available as lineage, even when the caller did not
        # carry a previously published result object.
        prior_results = _series([prior], policy, asof_ns, latest_index,
                                source_registry)
        prior_result = prior_results[0]
        if prior_result.inputs_hash != _hash(snapshot, policy, source_registry, asof_ns):
            snapshot = replace(snapshot, prior_result=prior_result)
    by_index[snapshot.clock.bar_index] = snapshot
    ordered = [by_index[index] for index in sorted(by_index)]
    results = _series(ordered, policy, asof_ns, latest_index, source_registry)
    target_position = next(index for index, item in enumerate(ordered) if item is snapshot)
    target = results[target_position]
    if snapshot.clock.bar_index <= latest_index - 2:
        return replace(target, status="HISTORY_ONLY", readiness="HOLD",
                       publish_current=False, reason_codes=(*target.reason_codes, "HISTORY_ONLY"),
                       _issuer_token=_RESULT_ISSUER)
    if target_position < len(results) - 1:
        affected: list[RegimeResultV1] = []
        old_by_bar = {item.clock.bar_id: item for item in old_results}
        for new_result in results[target_position + 1:]:
            old_result = old_by_bar.get(new_result.clock.bar_id)
            if old_result is not None and (
                new_result.composite_raw != old_result.composite_raw
                or new_result.composite_regime != old_result.composite_regime
                or new_result.confidence != old_result.confidence
                or new_result.readiness != old_result.readiness
            ):
                new_result = replace(
                    new_result, revision=old_result.revision + 1,
                    previous_revision=old_result.revision,
                    reason_codes=(*new_result.reason_codes, "UPSTREAM_CORRECTION"),
                    _issuer_token=_RESULT_ISSUER,
                )
            affected.append(new_result)
        target = replace(target, affected_results=tuple(affected),
                         _issuer_token=_RESULT_ISSUER)
    return target


def score(
    snapshot: RegimeSnapshotV1,
    policy: RegimeWeightPolicyV1,
    history: Sequence[RegimeSnapshotV1],
    asof_ns: int,
    source_registry: RegimeSourceRegistryV1 | None = None,
) -> RegimeResultV1:
    """Run one deterministic replay in the kernel-owned Decimal context."""
    if not isinstance(snapshot, RegimeSnapshotV1):
        raise RegimeError("SNAPSHOT_INVALID")
    if not isinstance(policy, RegimeWeightPolicyV1):
        raise RegimeError("POLICY_OUT_OF_BOUNDS")
    if source_registry is None:
        source_registry = RegimeSourceRegistryV1(version="unconfigured", records=())
    if not isinstance(source_registry, RegimeSourceRegistryV1):
        raise RegimeError("SOURCE_REGISTRY_INVALID")
    with localcontext(KERNEL_CONTEXT):
        try:
            return _score(snapshot, policy, history, asof_ns, source_registry)
        except DecimalException as exc:
            raise RegimeError("ARITHMETIC_ERROR") from exc
