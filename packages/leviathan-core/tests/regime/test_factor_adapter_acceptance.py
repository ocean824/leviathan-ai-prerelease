from __future__ import annotations

import copy
import pickle
import warnings
from dataclasses import replace
from decimal import Decimal, localcontext

import pytest

from leviathan_core.feature_store.models import FeatureLineageV1, FeatureResultV1
from leviathan_core.regime.factor_adapter import (
    RegimeAdapterError,
    RegimeFactorAdapterPolicyV1,
    RegimeFactorMappingV1,
    RegimeFactorSourcePortV1,
    RegimeFeatureBaselineBindingV1,
    RegimeScopeBindingV1,
    RegimeSignalPortV1,
    RegimeTruthPortV1,
    adapt_regime_factors,
)
from leviathan_core.regime.models import (
    RegimeClockV1,
    RegimeError,
    RegimeSourceIdV1,
    RegimeSourceRecordV1,
    RegimeSourceRegistryV1,
)

NOW = 1_000_000
SYMBOL = "XYZ"
UNIVERSE = "US-EQUITY"
DEFINITION = "definition:fixture-v1"
OBSERVATION = "observation:fixture-v1"
TRUTH_POLICY_ID = "truth-policy:fixture"
TRUTH_POLICY_VERSION = "truth-policy-v1"
FAMILY_BY_KIND = {
    "dealer": "GEX",
    "flow": "FLOW",
    "dp": "DP",
    "macro": "COT",
}
INTERFACE_BY_KIND = {
    "dealer": "fixture:gex-interface:v1",
    "flow": "fixture:flow-interface:v1",
    "dp": "fixture:dp-interface:v1",
    "macro": "fixture:cot-interface:v1",
}
LAG_NS = {
    "fixture-release": 0,
    "5m": 300_000_000_000,
    "15m": 900_000_000_000,
    "24h": 86_400_000_000_000,
    "48h": 172_800_000_000_000,
    "72h": 259_200_000_000_000,
}


def _clock(*, asof: int = NOW, finalized: bool = True) -> RegimeClockV1:
    return RegimeClockV1(
        bar_id="bar:fixture-1",
        bar_index=10,
        session_id="session:fixture-1",
        symbol=SYMBOL,
        universe=UNIVERSE,
        calendar_version="calendar:fixture-v1",
        asof_ns=asof,
        finalized=finalized,
        window_sec=60,
        horizon_sec=60,
    )


def _source_id(name: str) -> RegimeSourceIdV1:
    return RegimeSourceIdV1(f"fixture:{name}:v1")


def _mapping(
    kind: str,
    source_id: RegimeSourceIdV1,
    *,
    source_version: str = "source-v1",
    raw_unit: str = "fixture-unit",
    training_end: int = NOW - 100,
    baseline_available: int | None = None,
    release_lag: str = "fixture-release",
    max_age_ns: int = 1_000_000_000_000_000,
) -> RegimeFactorMappingV1:
    return RegimeFactorMappingV1(
        kind=kind,
        family=FAMILY_BY_KIND[kind],
        source_id=source_id,
        source_version=source_version,
        raw_unit=raw_unit,
        feature_name=f"{kind}.standardized",
        feature_version="z-v1",
        definition_hash=DEFINITION,
        baseline_version="baseline:fixture-v1",
        training_start_ns=0,
        training_end_ns=training_end,
        baseline_available_ns=(training_end if baseline_available is None else baseline_available),
        release_lag=release_lag,
        release_lag_ns=LAG_NS[release_lag],
        window_sec=60,
        horizon_sec=60,
        max_age_ns=max_age_ns,
    )


def _binding(
    scope_type: str = "instrument",
    scope_id: str | None = SYMBOL,
    target_scope: str = "symbol",
    target_scope_key: str | None = SYMBOL,
) -> RegimeScopeBindingV1:
    return RegimeScopeBindingV1(
        scope_type=scope_type,
        scope_id=scope_id,
        target_scope=target_scope,
        target_scope_key=target_scope_key,
    )


def _feature(
    kind: str,
    source_id: RegimeSourceIdV1,
    record_id: str,
    value: Decimal = Decimal("1.25"),
    *,
    asof: int = NOW,
    event: int = NOW - 100,
    available: int = NOW - 50,
    quality: str = "GOOD",
    source_keys: tuple[str, ...] | None = None,
    definition_hash: str = DEFINITION,
    observation_hash: str | None = OBSERVATION,
    value_vector: tuple[Decimal, ...] | None = None,
) -> FeatureResultV1:
    return FeatureResultV1(
        found=True,
        feature_name=f"{kind}.standardized",
        feature_version="z-v1",
        instrument_id=SYMBOL,
        asof_ns=asof,
        value_decimal=value,
        value_vector=value_vector,
        quality=quality,
        is_null=False,
        source_dataset=str(source_id),
        source_record_key=record_id,
        event_time_ns=event,
        availability_ns=available,
        source_keys=(record_id,) if source_keys is None else source_keys,
        definition_hash=definition_hash,
        observation_hash=observation_hash,
        lineage=FeatureLineageV1(
            definition_sha256=definition_hash,
            observation_sha256=observation_hash,
            source_dataset=str(source_id),
            source_record_key=record_id,
        ),
    )


def _source(
    kind: str = "dealer",
    *,
    family: str | None = None,
    name: str | None = None,
    source_id: RegimeSourceIdV1 | None = None,
    source_version: str = "source-v1",
    record_id: str = "record:fixture-1",
    revision: int = 0,
    correction_of: str | None = None,
    event: int = NOW - 100,
    available: int = NOW - 50,
    fresh_until: int = NOW + 100,
    scope_type: str = "instrument",
    scope_id: str | None = SYMBOL,
    raw_value: Decimal | None = Decimal("999"),
    raw_unit: str = "fixture-unit",
    entitlement: str = "SYNTHETIC",
    quality: str = "GOOD",
    feature: FeatureResultV1 | None = None,
    feature_value: Decimal = Decimal("1.25"),
    feature_asof: int = NOW,
    feature_event: int | None = None,
    feature_available: int | None = None,
    feature_quality: str = "GOOD",
    source_keys: tuple[str, ...] | None = None,
    definition_hash: str = DEFINITION,
    observation_hash: str | None = OBSERVATION,
    upstream_interface_id: str | None = None,
) -> RegimeFactorSourcePortV1:
    selected_id = source_id or _source_id(name or kind)
    iface = upstream_interface_id
    if iface is None:
        iface = INTERFACE_BY_KIND[kind]
    if feature is None:
        feature = _feature(
            kind,
            selected_id,
            record_id,
            feature_value,
            asof=feature_asof,
            event=event if feature_event is None else feature_event,
            available=available if feature_available is None else feature_available,
            quality=feature_quality,
            source_keys=source_keys,
            definition_hash=definition_hash,
            observation_hash=observation_hash,
        )
    return RegimeFactorSourcePortV1(
        kind=kind,
        family=FAMILY_BY_KIND[kind] if family is None else family,
        source_id=selected_id,
        source_version=source_version,
        record_id=record_id,
        revision=revision,
        correction_of=correction_of,
        event_ns=event,
        available_ns=available,
        fresh_until_ns=fresh_until,
        scope_type=scope_type,
        scope_id=scope_id,
        raw_value=raw_value,
        raw_unit=raw_unit,
        entitlement=entitlement,
        quality=quality,
        feature=feature,
        upstream_interface_id=iface,
    )


def _registry(
    sources: tuple[RegimeFactorSourcePortV1, ...],
    *,
    source_ids: tuple[RegimeSourceIdV1, ...] | None = None,
    allowed: tuple[str, ...] | None = None,
) -> RegimeSourceRegistryV1:
    ids = source_ids or tuple(dict.fromkeys(source.source_id for source in sources))
    kind_by_id = {source.source_id: source.kind for source in sources}
    default_kind = sources[0].kind if sources else "dealer"
    return RegimeSourceRegistryV1(
        version="registry:fixture-v1",
        records=tuple(
            RegimeSourceRecordV1(
                source_id=source_id,
                trust_class="PIPELINE",
                entitlement="SYNTHETIC",
                allowed_interface_ids=(
                    allowed
                    if allowed is not None
                    else (INTERFACE_BY_KIND[kind_by_id.get(source_id, default_kind)],)
                ),
            )
            for source_id in ids
        ),
    )


def _policy(
    sources: tuple[RegimeFactorSourcePortV1, ...] = (),
    *,
    mappings: tuple[RegimeFactorMappingV1, ...] | None = None,
    bindings: tuple[RegimeScopeBindingV1, ...] | None = None,
    status: str = "APPROVED",
    approval_ref: str | None = "approval:fixture-v1",
    baseline_bindings: tuple[RegimeFeatureBaselineBindingV1, ...] | None = None,
    truth_policy_id: str | None = TRUTH_POLICY_ID,
    truth_policy_version: str | None = TRUTH_POLICY_VERSION,
) -> RegimeFactorAdapterPolicyV1:
    if mappings is None:
        unique_sources = {
            (source.kind, source.source_id, source.source_version): source for source in sources
        }
        mappings = tuple(
            _mapping(
                source.kind,
                source.source_id,
                source_version=source.source_version,
                raw_unit=source.raw_unit,
            )
            for source in unique_sources.values()
        )
    if baseline_bindings is None:
        mapping_by_key = {
            (item.kind, item.source_id, item.source_version): item for item in mappings
        }
        source_by_key = {(item.kind, item.source_id, item.source_version): item for item in sources}
        baseline_by_key = {}
        for key, mapping in mapping_by_key.items():
            source = source_by_key.get(key)
            feature = source.feature if source is not None else None
            if feature is not None and feature.observation_hash is not None:
                baseline = RegimeFeatureBaselineBindingV1(
                    feature_name=mapping.feature_name,
                    feature_version=mapping.feature_version,
                    definition_hash=mapping.definition_hash,
                    observation_hash=feature.observation_hash,
                    baseline_version=mapping.baseline_version,
                    training_start_ns=mapping.training_start_ns,
                    training_end_ns=mapping.training_end_ns,
                    baseline_available_ns=mapping.baseline_available_ns,
                )
                baseline_by_key[
                    (
                        baseline.feature_name,
                        baseline.feature_version,
                        baseline.definition_hash,
                        baseline.observation_hash,
                    )
                ] = baseline
        baseline_bindings = tuple(baseline_by_key.values())
    if bindings is None:
        unique = {(source.scope_type, source.scope_id) for source in sources}
        bindings = tuple(
            _binding(
                scope,
                scope_id,
                "global"
                if scope == "global"
                else "class"
                if scope in ("book", "sector")
                else "symbol",
                None if scope == "global" else UNIVERSE if scope in ("book", "sector") else SYMBOL,
            )
            for scope, scope_id in sorted(unique, key=lambda item: (item[0], str(item[1])))
        )
        if not bindings:
            bindings = (_binding(),)
    return RegimeFactorAdapterPolicyV1(
        version="adapter-policy:fixture-v1",
        mappings=mappings,
        scope_bindings=bindings,
        status=status,
        approval_ref=approval_ref,
        baseline_bindings=baseline_bindings,
        truth_policy_id=truth_policy_id,
        truth_policy_version=truth_policy_version,
    )


def _signal(
    *, status: str = "FINALIZED", revision: int = 0, event: int = NOW, available: int | None = None
) -> RegimeSignalPortV1:
    return RegimeSignalPortV1(
        signal_id="signal:fixture-1",
        bar_id="bar:fixture-1",
        session_id="session:fixture-1",
        symbol=SYMBOL,
        event_ns=event,
        available_ns=event if available is None else available,
        status=status,
        revision=revision,
    )


def _truth(
    *,
    verdict: str = "PASS",
    available: int | None = None,
    target_symbol: str = SYMBOL,
    target_bar_id: str = "bar:fixture-1",
    target_session_id: str = "session:fixture-1",
    target_asof: int = NOW,
    policy_id: str = TRUTH_POLICY_ID,
    policy_version: str = TRUTH_POLICY_VERSION,
) -> RegimeTruthPortV1:
    selected_available = target_asof if available is None else available
    return RegimeTruthPortV1(
        verdict=verdict,
        evaluation_ns=target_asof,
        available_ns=selected_available,
        trace_id="truth-trace:fixture-1",
        policy_version=policy_version,
        target_symbol=target_symbol,
        target_bar_id=target_bar_id,
        target_session_id=target_session_id,
        target_asof_ns=target_asof,
        policy_id=policy_id,
    )


def _adapt(
    sources: tuple[RegimeFactorSourcePortV1, ...] = (),
    *,
    clock: RegimeClockV1 | None = None,
    policy: RegimeFactorAdapterPolicyV1 | None = None,
    source_registry: RegimeSourceRegistryV1 | None = None,
    signal: RegimeSignalPortV1 | None = None,
    truth: RegimeTruthPortV1 | None = None,
    asof: int = NOW,
):
    selected_clock = _clock() if clock is None else clock
    return adapt_regime_factors(
        target_clock=selected_clock,
        sources=sources,
        signal=_signal(event=selected_clock.asof_ns) if signal is None else signal,
        truth=(
            _truth(
                available=selected_clock.asof_ns,
                target_symbol=selected_clock.symbol,
                target_bar_id=selected_clock.bar_id,
                target_session_id=selected_clock.session_id,
                target_asof=selected_clock.asof_ns,
            )
            if truth is None
            else truth
        ),
        policy=_policy(sources) if policy is None else policy,
        source_registry=_registry(sources) if source_registry is None else source_registry,
        asof_ns=asof,
    )


def _factor(result, kind: str):
    return next((factor for factor in result.snapshot.factors if factor.kind == kind), None)


def test_feature_decimal_is_the_standardized_factor_and_raw_value_is_audit_only():
    low_raw = _source(raw_value=Decimal("1"), feature_value=Decimal("0.75"))
    high_raw = replace(low_raw, raw_value=Decimal("987654"))
    policy = _policy((low_raw,))
    registry = _registry((low_raw,))

    first = _adapt((low_raw,), policy=policy, source_registry=registry)
    second = _adapt((high_raw,), policy=policy, source_registry=registry)

    assert _factor(first, "dealer").value == Decimal("0.75")
    assert _factor(second, "dealer").value == Decimal("0.75")
    assert first.audit_digest != second.audit_digest


def test_registry_ids_are_exact_and_source_versions_must_match_the_mapping():
    source = _source(name="feed-a")
    prefix_neighbor = _source(name="feed-ab")
    policy = _policy((source,))
    registry = _registry((source,), source_ids=(prefix_neighbor.source_id,))

    rejected_id = _adapt((source,), policy=policy, source_registry=registry)
    assert _factor(rejected_id, "dealer") is None
    assert ("dealer", "UNTRUSTED_SOURCE") in rejected_id.exclusions

    other_version = replace(source, source_version="source-v2")
    version_result = _adapt(
        (other_version,),
        policy=policy,
        source_registry=_registry((other_version,)),
    )
    assert _factor(version_result, "dealer") is None
    assert ("dealer", "MAPPING_UNAPPROVED") in version_result.exclusions


def test_mapping_family_and_raw_unit_must_match_exactly():
    source = _source()
    wrong_unit = replace(_mapping("dealer", source.source_id), raw_unit="other-unit")

    result = _adapt(
        (source,),
        policy=_policy((source,), mappings=(wrong_unit,)),
        source_registry=_registry((source,)),
    )
    assert _factor(result, "dealer") is None
    assert ("dealer", "MAPPING_UNAPPROVED") in result.exclusions

    with pytest.raises(RegimeAdapterError) as invalid_family:
        _source(kind="dealer", family="DP")
    assert invalid_family.value.code == "SOURCE_FAMILY_INVALID"


def test_interfaces_are_exactly_allowlisted_and_flow_requires_an_interface():
    flow = _source("flow", upstream_interface_id="fixture:flow-interface:v1")
    wrong = replace(flow, upstream_interface_id="fixture:flow-interface:v10")
    denied = _adapt((wrong,), policy=_policy((wrong,)), source_registry=_registry((wrong,)))
    assert _factor(denied, "flow") is None
    assert ("flow", "UNTRUSTED_INTERFACE") in denied.exclusions

    missing = replace(flow, upstream_interface_id=None)
    denied_missing = _adapt(
        (missing,), policy=_policy((missing,)), source_registry=_registry((missing,))
    )
    assert ("flow", "UNTRUSTED_INTERFACE") in denied_missing.exclusions


def test_asof_filter_precedes_correction_reconciliation_and_is_permutation_invariant():
    original = _source(
        name="flow-feed",
        kind="flow",
        record_id="record:flow-original",
        event=NOW - 100,
        available=NOW - 50,
        fresh_until=NOW + 1_000,
        feature_value=Decimal("0.5"),
        feature_available=NOW - 50,
    )
    correction = _source(
        name="flow-feed",
        kind="flow",
        record_id="record:flow-correction",
        revision=1,
        correction_of=original.record_id,
        event=original.event_ns,
        available=NOW + 1,
        fresh_until=NOW + 1_000,
        feature_value=Decimal("1.5"),
        feature_asof=NOW + 1,
        feature_available=NOW + 1,
    )
    policy = _policy((original, correction))
    registry = _registry((original, correction))

    baseline = _adapt((original,), policy=policy, source_registry=registry, asof=NOW)
    with_future = _adapt((original, correction), policy=policy, source_registry=registry, asof=NOW)
    reversed_with_future = _adapt(
        (correction, original), policy=policy, source_registry=registry, asof=NOW
    )

    assert _factor(baseline, "flow").value == Decimal("0.5")
    assert _factor(with_future, "flow").value == Decimal("0.5")
    assert baseline.audit_digest == with_future.audit_digest
    assert with_future.audit_digest == reversed_with_future.audit_digest
    assert baseline.inputs_hash == with_future.inputs_hash
    assert with_future.inputs_hash == reversed_with_future.inputs_hash

    corrected = _adapt(
        (original, correction), policy=policy, source_registry=registry, asof=NOW + 1
    )
    assert _factor(corrected, "flow").value == Decimal("1.5")


def test_future_feat_delivery_of_same_visible_record_does_not_change_earlier_result():
    source = _source()
    no_feature = replace(source, feature=None)
    future_feature = replace(
        source,
        feature=source.feature.model_copy(update={"asof_ns": NOW + 1, "availability_ns": NOW + 1}),
    )
    policy = _policy((source,))
    registry = _registry((source,))

    baseline = _adapt((no_feature,), policy=policy, source_registry=registry, asof=NOW)
    with_future_delivery = _adapt(
        (no_feature, future_feature), policy=policy, source_registry=registry, asof=NOW
    )

    assert baseline.snapshot == with_future_delivery.snapshot
    assert baseline.inputs_hash == with_future_delivery.inputs_hash
    assert baseline.audit_digest == with_future_delivery.audit_digest


def test_visible_revision_chain_is_order_independent_and_unlinked_revision_fails_closed():
    original = _source(record_id="record:root", feature_value=Decimal("0.25"))
    revision = _source(
        record_id="record:revision-1",
        revision=1,
        correction_of=original.record_id,
        feature_value=Decimal("0.75"),
    )
    policy = _policy((original, revision))
    registry = _registry((original, revision))

    forward = _adapt((original, revision), policy=policy, source_registry=registry)
    reverse = _adapt((revision, original), policy=policy, source_registry=registry)
    assert _factor(forward, "dealer").value == Decimal("0.75")
    assert forward.audit_digest == reverse.audit_digest
    assert forward.inputs_hash == reverse.inputs_hash

    bad_link = replace(revision, correction_of="record:unrelated")
    rejected = _adapt(
        (original, bad_link),
        policy=_policy((original, bad_link)),
        source_registry=_registry((original, bad_link)),
    )
    assert _factor(rejected, "dealer").value == Decimal("0.25")
    assert ("dealer", "UNLINKED_CORRECTION") in rejected.exclusions


@pytest.mark.parametrize(
    ("kind", "lag"),
    (("dp", "24h"), ("macro", "72h")),
)
def test_delayed_finra_and_cot_are_unavailable_before_their_release(kind: str, lag: str):
    source_id = _source_id(f"delayed-{kind}")
    delay = LAG_NS[lag]
    event = 5_000
    release = event + delay
    source = _source(
        kind,
        source_id=source_id,
        name=f"delayed-{kind}",
        event=event,
        available=release,
        fresh_until=release + 100,
        feature_asof=release,
        feature_event=event,
        feature_available=release,
    )
    mapping = _mapping(
        kind,
        source_id,
        training_end=event,
        baseline_available=event,
        release_lag=lag,
    )
    policy = _policy((source,), mappings=(mapping,))
    registry = _registry((source,))
    before_clock = _clock(asof=release - 1)
    release_clock = _clock(asof=release)
    before_release = _adapt(
        (source,),
        clock=before_clock,
        policy=policy,
        source_registry=registry,
        asof=release - 1,
    )
    at_release = _adapt(
        (source,),
        clock=release_clock,
        policy=policy,
        source_registry=registry,
        asof=release,
    )

    assert _factor(before_release, kind) is None
    assert _factor(at_release, kind) is not None


@pytest.mark.parametrize(("fresh_until", "expected"), ((NOW, True), (NOW - 1, False)))
def test_freshness_threshold_is_inclusive(fresh_until: int, expected: bool):
    source = _source(fresh_until=fresh_until)
    result = _adapt((source,), policy=_policy((source,)), source_registry=_registry((source,)))
    assert (_factor(result, "dealer") is not None) is expected
    if not expected:
        assert ("dealer", "SOURCE_STALE") in result.exclusions


def test_unentitled_unknown_quality_and_missing_values_never_become_neutral_factors():
    base = _source()
    variants = (
        (replace(base, entitlement="UNENTITLED"), "UNENTITLED"),
        (replace(base, quality="UNKNOWN"), "SOURCE_QUALITY"),
        (replace(base, raw_value=None), "SOURCE_MISSING"),
    )
    for source, reason in variants:
        result = _adapt((source,), policy=_policy((source,)), source_registry=_registry((source,)))
        assert _factor(result, "dealer") is None
        assert ("dealer", reason) in result.exclusions

    empty = _adapt(())
    assert empty.snapshot.factors == ()
    assert ("dealer", "SOURCE_MISSING") in empty.exclusions


def test_feature_lineage_and_future_normalization_are_rejected():
    base = _source()
    bad_lineage = replace(
        base,
        feature=_feature(
            "dealer",
            base.source_id,
            base.record_id,
            source_keys=("record:other",),
        ),
    )
    lineage_result = _adapt(
        (bad_lineage,),
        policy=_policy((bad_lineage,)),
        source_registry=_registry((bad_lineage,)),
    )
    assert ("dealer", "FEATURE_LINEAGE") in lineage_result.exclusions

    future_mapping = _mapping(
        "dealer",
        base.source_id,
        training_end=NOW + 1,
        baseline_available=NOW + 1,
    )
    future_result = _adapt(
        (base,),
        policy=_policy((base,), mappings=(future_mapping,)),
        source_registry=_registry((base,)),
    )
    assert _factor(future_result, "dealer") is None
    assert ("dealer", "NORMALIZATION_FUTURE") in future_result.exclusions

    future_feature = replace(
        base,
        feature=_feature(
            "dealer",
            base.source_id,
            base.record_id,
            asof=NOW + 1,
            available=NOW + 1,
        ),
    )
    future_feature_result = _adapt(
        (future_feature,),
        policy=_policy((future_feature,)),
        source_registry=_registry((future_feature,)),
    )
    assert _factor(future_feature_result, "dealer") is None


def test_sig_finalization_revision_and_truth_verdicts_remain_explicit_gates():
    source = _source()
    approved = _policy((source,))
    registry = _registry((source,))

    provisional = _adapt(
        (source,),
        policy=approved,
        source_registry=registry,
        signal=_signal(status="PROVISIONAL"),
        truth=_truth(),
    )
    assert provisional.snapshot.signal_status == "PROVISIONAL"
    assert provisional.snapshot.clock.finalized is False

    revised = _adapt(
        (source,),
        policy=approved,
        source_registry=registry,
        signal=_signal(status="FINALIZED", revision=1),
        truth=_truth(),
    )
    assert revised.snapshot.signal_status == "FINALIZED"

    for verdict in ("HARD_FAIL", "UNKNOWN", "SOFT_FAIL"):
        result = _adapt(
            (source,),
            policy=approved,
            source_registry=registry,
            signal=_signal(),
            truth=_truth(verdict=verdict),
        )
        assert result.snapshot.truth_status == verdict


def test_fixture_only_mapping_cannot_turn_pass_into_a_trusted_snapshot():
    source = _source()
    policy = _policy((source,), status="FIXTURE_ONLY", approval_ref=None)
    result = _adapt(
        (source,),
        policy=policy,
        source_registry=_registry((source,)),
        signal=_signal(),
        truth=_truth(verdict="PASS"),
    )
    assert result.snapshot.truth_status == "UNKNOWN"
    assert "SOURCE_MAPPING_UNAPPROVED" in result.activation_gates
    assert result.snapshot.factors


def test_scope_specificity_selects_instrument_over_sector_book_and_global():
    definitions = (
        ("global", None, Decimal("0"), "global"),
        ("book", "book:fixture", Decimal("1"), "book"),
        ("sector", "sector:fixture", Decimal("2"), "sector"),
        ("instrument", SYMBOL, Decimal("3"), "instrument"),
    )
    sources = tuple(
        _source(
            name=f"scope-{name}",
            source_id=_source_id(f"scope-{name}"),
            record_id=f"record:scope-{name}",
            scope_type=scope,
            scope_id=scope_id,
            feature_value=value,
        )
        for scope, scope_id, value, name in definitions
    )
    bindings = (
        _binding("global", None, "global", None),
        _binding("book", "book:fixture", "class", UNIVERSE),
        _binding("sector", "sector:fixture", "class", UNIVERSE),
        _binding("instrument", SYMBOL, "symbol", SYMBOL),
    )
    result = _adapt(
        sources,
        policy=_policy(sources, bindings=bindings),
        source_registry=_registry(sources),
    )
    factor = _factor(result, "dealer")
    assert factor.scope == "symbol"
    assert factor.scope_key == SYMBOL
    assert factor.value == Decimal("3")


def test_equal_priority_scope_collision_fails_closed():
    book_a = _source(
        name="book-source-a",
        source_id=_source_id("book-source-a"),
        record_id="record:book-a",
        scope_type="book",
        scope_id="book:fixture-a",
        feature_value=Decimal("1"),
    )
    book_b = _source(
        name="book-source-b",
        source_id=_source_id("book-source-b"),
        record_id="record:book-b",
        scope_type="book",
        scope_id="book:fixture-b",
        feature_value=Decimal("2"),
    )
    bindings = (
        _binding("book", "book:fixture-a", "class", UNIVERSE),
        _binding("book", "book:fixture-b", "class", UNIVERSE),
    )
    with pytest.raises(RegimeAdapterError) as caught:
        _adapt(
            (book_a, book_b),
            policy=_policy((book_a, book_b), bindings=bindings),
            source_registry=_registry((book_a, book_b)),
        )
    assert caught.value.code == "SCOPE_CONFLICT"


def test_input_permutation_ambient_decimal_context_and_numeric_scale_do_not_change_digest():
    dealer = _source(raw_value=Decimal("1"), feature_value=Decimal("0.50"))
    flow = _source(
        "flow",
        name="flow-source",
        record_id="record:flow",
        raw_value=Decimal("2"),
        feature_value=Decimal("-0.25"),
    )
    policy = _policy((dealer, flow))
    registry = _registry((dealer, flow))
    forward = _adapt((dealer, flow), policy=policy, source_registry=registry)
    reverse = _adapt((flow, dealer), policy=policy, source_registry=registry)
    scaled_dealer = replace(dealer, raw_value=Decimal("1.0"))
    scaled = _adapt((scaled_dealer, flow), policy=policy, source_registry=registry)

    with localcontext() as ambient:
        ambient.prec = 2
        ambient.Emax = 9
        ambient.Emin = -9
        altered_context = _adapt((dealer, flow), policy=policy, source_registry=registry)

    assert forward.audit_digest == reverse.audit_digest
    assert forward.inputs_hash == reverse.inputs_hash
    assert forward.audit_digest == scaled.audit_digest
    assert forward.audit_digest == altered_context.audit_digest


def test_numeric_limits_exact_comparisons_and_bool_integer_rejection():
    with pytest.raises(RegimeAdapterError) as precise:
        _source(raw_value=Decimal("1.2345678901234567890123456789012345"))
    assert precise.value.code == "PRECISION_EXCEEDED"
    assert "1.2345678901234567890123456789012345" not in str(precise.value)

    with pytest.raises(RegimeAdapterError) as huge:
        _source(raw_value=Decimal("1E+100000"))
    assert huge.value.code == "MAGNITUDE_OUT_OF_BOUNDS"

    accepted_huge_coefficient = _source(raw_value=Decimal("1E+34"))
    assert accepted_huge_coefficient.raw_value == Decimal("1E+34")

    base = _source()
    for invalid in (
        lambda: replace(base, revision=True),
        lambda: replace(base, available_ns=True),
    ):
        with pytest.raises(RegimeAdapterError) as invalid_integer:
            invalid()
        assert invalid_integer.value.code in {"INVALID_INTEGER", "OUT_OF_RANGE"}


def test_frozen_objects_block_copy_pickle_and_replace_revalidates():
    source = _source()
    policy = _policy((source,))
    result = _adapt((source,), policy=policy, source_registry=_registry((source,)))
    frozen = (
        source,
        policy.mappings[0],
        policy.scope_bindings[0],
        policy,
        _signal(),
        _truth(),
        result,
    )
    for value in frozen:
        for operation in (copy.copy, copy.deepcopy, pickle.dumps):
            with pytest.raises((RegimeAdapterError, RegimeError)) as blocked:
                operation(value)
            assert blocked.value.code == "IMMUTABLE_COPY"

    with pytest.raises(RegimeAdapterError) as invalid_replace:
        replace(policy, approval_ref=None)
    assert invalid_replace.value.code == "POLICY_UNAPPROVED"


def test_public_errors_are_typed_and_do_not_echo_untrusted_input():
    canary = "SENSITIVE_SOURCE_INPUT_CANARY"
    with pytest.raises(RegimeAdapterError) as caught:
        RegimeFactorSourcePortV1(
            kind="dealer",
            family="GEX",
            source_id=_source_id("bad"),
            source_version="source-v1",
            record_id=canary,
            revision=True,
            correction_of=None,
            event_ns=NOW,
            available_ns=NOW,
            fresh_until_ns=NOW,
            scope_type="instrument",
            scope_id=SYMBOL,
            raw_value=Decimal("1"),
            raw_unit="fixture-unit",
            entitlement="SYNTHETIC",
            quality="GOOD",
            feature=None,
        )
    assert caught.value.code == "INVALID_INTEGER"
    assert canary not in str(caught.value)
    assert canary not in repr(caught.value.args)


def test_pydantic_copy_and_construct_bypasses_are_redacted_at_the_source_boundary():
    source = _source()
    copied_feature = source.feature.model_copy(update={"value_decimal": "FEATURE_COPY_CANARY"})
    payload = source.feature.model_dump()
    payload["value_decimal"] = "FEATURE_CONSTRUCT_CANARY"
    constructed_feature = FeatureResultV1.model_construct(**payload)

    for feature, canary in (
        (copied_feature, "FEATURE_COPY_CANARY"),
        (constructed_feature, "FEATURE_CONSTRUCT_CANARY"),
    ):
        with warnings.catch_warnings(record=True) as emitted:
            warnings.simplefilter("always")
            with pytest.raises(RegimeAdapterError) as caught:
                replace(source, feature=feature)
        assert caught.value.code == "FEATURE_INVALID"
        assert canary not in str(caught.value)
        assert canary not in repr(caught.value.args)
        assert all(canary not in str(warning.message) for warning in emitted)


def test_frozen_pydantic_feature_assignment_does_not_echo_the_supplied_value():
    feature = _source().feature
    canary = "FEATURE_ASSIGNMENT_CANARY"
    with pytest.raises(Exception) as caught:
        feature.value_decimal = canary
    error = caught.value
    assert canary not in str(error)
    assert canary not in repr(error.args)
    if hasattr(error, "errors"):
        assert canary not in repr(error.errors())


def test_frozen_pydantic_feature_deletion_does_not_echo_a_caller_value():
    feature = _source().feature
    with pytest.raises(Exception) as caught:
        del feature.value_decimal
    error = caught.value
    assert "FEATURE_ASSIGNMENT_CANARY" not in str(error)
    assert "FEATURE_ASSIGNMENT_CANARY" not in repr(error.args)
    if hasattr(error, "errors"):
        assert "FEATURE_ASSIGNMENT_CANARY" not in repr(error.errors())


def test_adapter_result_cannot_be_forged_or_reissued_through_public_dataclass_apis():
    source = _source()
    result = _adapt((source,), policy=_policy((source,)), source_registry=_registry((source,)))
    with pytest.raises(RegimeAdapterError) as replaced:
        replace(result, policy_version="adapter-policy:attacker")
    assert replaced.value.code == "ADAPTER_RESULT_SEALED"

    result.require_issued()
    assert "_issue_token" not in type(result).__slots__
    assert "_input_payload" not in type(result).__slots__
    with pytest.raises(RegimeAdapterError) as forged:
        type(result)(
            snapshot=result.snapshot,
            exclusions=result.exclusions,
            activation_gates=result.activation_gates,
            policy_version=result.policy_version,
            _issue_token=result.audit_digest,
        )
    assert forged.value.code == "ADAPTER_RESULT_SEALED"


def test_target_asof_must_not_precede_finalized_clock():
    source = _source()
    with pytest.raises(RegimeAdapterError) as caught:
        _adapt(
            (source,),
            policy=_policy((source,)),
            source_registry=_registry((source,)),
            asof=NOW - 1,
        )
    assert caught.value.code == "ASOF_BEFORE_BAR"


def test_issued_result_reinitialization_and_setstate_fail_before_mutation():
    source = _source()
    result = _adapt((source,), policy=_policy((source,)), source_registry=_registry((source,)))
    original_snapshot = result.snapshot
    original_digest = result.audit_digest
    tampered_snapshot = replace(original_snapshot, truth_status="HARD_FAIL")

    with pytest.raises(RegimeAdapterError) as reinitialized:
        result.__init__(
            snapshot=tampered_snapshot,
            exclusions=result.exclusions,
            activation_gates=result.activation_gates,
            policy_version=result.policy_version,
        )
    assert reinitialized.value.code == "ADAPTER_RESULT_SEALED"
    assert result.snapshot is original_snapshot
    assert result.audit_digest == original_digest
    result.require_issued()

    with pytest.raises(RegimeAdapterError) as restored:
        result.__setstate__({"snapshot": tampered_snapshot})
    assert restored.value.code == "ADAPTER_RESULT_SEALED"
    assert result.snapshot is original_snapshot
    assert result.audit_digest == original_digest
    result.require_issued()


@pytest.mark.parametrize("tamper", ("truth", "factor"))
def test_issued_result_detects_object_setattr_safety_field_tampering(tamper: str):
    source = _source()
    result = _adapt((source,), policy=_policy((source,)), source_registry=_registry((source,)))
    if tamper == "truth":
        object.__setattr__(result.snapshot, "truth_status", "HARD_FAIL")
    else:
        factor = _factor(result, "dealer")
        object.__setattr__(factor, "value", Decimal("999"))

    with pytest.raises(RegimeAdapterError) as caught:
        result.require_issued()
    assert caught.value.code == "ADAPTER_RESULT_SEALED"


@pytest.mark.parametrize(
    "truth_changes",
    (
        {"target_symbol": "OTHER"},
        {"target_bar_id": "bar:other"},
        {"target_session_id": "session:other"},
        {"target_asof": NOW - 1},
        {"policy_id": "truth-policy:other"},
        {"policy_version": "truth-policy-v2"},
    ),
)
def test_truth_pass_for_other_target_or_policy_is_unusable(truth_changes: dict[str, str | int]):
    source = _source()
    result = _adapt(
        (source,),
        policy=_policy((source,)),
        source_registry=_registry((source,)),
        truth=_truth(**truth_changes),
    )
    assert result.snapshot.truth_status == "UNKNOWN"
    assert "TRUTH_MISMATCH" in result.activation_gates


def test_truth_policy_must_be_explicitly_bound_by_adapter_policy():
    source = _source()
    policy = _policy((source,), truth_policy_id=None, truth_policy_version=None)
    result = _adapt((source,), policy=policy, source_registry=_registry((source,)))
    assert result.snapshot.truth_status == "UNKNOWN"
    assert "TRUTH_POLICY_UNBOUND" in result.activation_gates


def test_truth_pass_evaluated_before_target_clock_is_premature():
    source = _source()
    truth = replace(_truth(), evaluation_ns=0, available_ns=1)
    result = _adapt(
        (source,),
        policy=_policy((source,)),
        source_registry=_registry((source,)),
        truth=truth,
    )

    assert result.snapshot.truth_status == "UNKNOWN"
    assert "TRUTH_PREMATURE" in result.activation_gates


def test_feat_availability_cannot_postdate_the_feat_asof_it_claims():
    source = _source(
        feature_asof=NOW - 50,
        feature_available=NOW - 49,
    )
    result = _adapt((source,), policy=_policy((source,)), source_registry=_registry((source,)))
    assert _factor(result, "dealer") is None
    assert ("dealer", "FEATURE_FUTURE") in result.exclusions


def test_contradictory_feat_lineage_is_typed_and_all_lineage_is_hash_bound():
    source = _source()
    policy = _policy((source,))
    registry = _registry((source,))
    valid_result = _adapt((source,), policy=policy, source_registry=registry)

    contradictory_feature = source.feature.model_copy(
        update={
            "lineage": FeatureLineageV1(
                definition_sha256=DEFINITION,
                observation_sha256=OBSERVATION,
                source_dataset="fixture:foreign-source:v1",
                source_record_key="record:foreign",
            )
        },
    )
    contradictory_source = replace(source, feature=contradictory_feature)
    with pytest.raises(RegimeAdapterError) as conflict:
        _adapt(
            (contradictory_source,),
            policy=_policy((contradictory_source,)),
            source_registry=_registry((contradictory_source,)),
        )
    assert conflict.value.code == "LINEAGE_CONFLICT"

    foreign_key = "record:foreign-key"
    internally_consistent_feature = source.feature.model_copy(
        update={
            "source_record_key": foreign_key,
            "source_keys": (foreign_key,),
            "lineage": FeatureLineageV1(
                definition_sha256=DEFINITION,
                observation_sha256=OBSERVATION,
                source_dataset=str(source.source_id),
                source_record_key=foreign_key,
            ),
        },
    )
    lineage_source = replace(source, feature=internally_consistent_feature)
    lineage_result = _adapt(
        (lineage_source,),
        policy=_policy((lineage_source,)),
        source_registry=_registry((lineage_source,)),
    )
    assert _factor(lineage_result, "dealer") is None
    assert ("dealer", "FEATURE_LINEAGE") in lineage_result.exclusions
    assert lineage_result.inputs_hash != valid_result.inputs_hash
    assert lineage_result.audit_digest != valid_result.audit_digest


def test_source_fresh_until_cannot_loosen_the_reviewed_max_age():
    source = _source(fresh_until=NOW + 100_000)
    mapping = _mapping(
        "dealer",
        source.source_id,
        source_version=source.source_version,
        raw_unit=source.raw_unit,
        max_age_ns=50,
    )
    result = _adapt(
        (source,),
        policy=_policy((source,), mappings=(mapping,)),
        source_registry=_registry((source,)),
    )
    assert _factor(result, "dealer") is None
    assert ("dealer", "SOURCE_STALE") in result.exclusions


def test_timestamp_changing_visible_correction_replaces_its_record_at_asof():
    original = _source(
        name="timestamped-source",
        record_id="record:timestamp-root",
        event=NOW - 200,
        available=NOW - 100,
        feature_event=NOW - 200,
        feature_available=NOW - 100,
        feature_value=Decimal("0.5"),
    )
    correction = _source(
        name="timestamped-source",
        record_id="record:timestamp-revision",
        revision=1,
        correction_of=original.record_id,
        event=NOW - 90,
        available=NOW - 50,
        feature_event=NOW - 90,
        feature_available=NOW - 50,
        feature_value=Decimal("2.5"),
    )
    result = _adapt(
        (original, correction),
        policy=_policy((original, correction)),
        source_registry=_registry((original, correction)),
        asof=NOW,
    )
    factor = _factor(result, "dealer")
    assert factor.value == Decimal("2.5")
    assert factor.event_ns == NOW - 90
    assert ("dealer", "UNLINKED_CORRECTION") not in result.exclusions


def test_scalar_factor_rejects_a_simultaneous_vector_feat_value():
    source = _source()
    contradictory = replace(
        source,
        feature=source.feature.model_copy(update={"value_vector": (Decimal("999"),)}),
    )
    result = _adapt(
        (contradictory,),
        policy=_policy((contradictory,)),
        source_registry=_registry((contradictory,)),
    )
    assert _factor(result, "dealer") is None
    assert ("dealer", "FEATURE_VALUE_CONFLICT") in result.exclusions


def test_mapping_baseline_version_requires_an_exact_reviewed_feat_binding():
    source = _source()
    default_policy = _policy((source,))
    binding = replace(
        default_policy.baseline_bindings[0],
        baseline_version="baseline:wrong-v1",
    )
    policy = _policy((source,), baseline_bindings=(binding,))
    result = _adapt((source,), policy=policy, source_registry=_registry((source,)))
    assert _factor(result, "dealer") is None
    assert ("dealer", "BASELINE_UNBOUND") in result.exclusions


@pytest.mark.parametrize("kind", ("dealer", "flow", "dp", "macro"))
def test_every_source_family_requires_an_exact_registry_interface(kind: str):
    source = _source(kind)
    without_interface = replace(source, upstream_interface_id=None)
    result = _adapt(
        (without_interface,),
        policy=_policy((without_interface,)),
        source_registry=_registry((without_interface,)),
    )
    assert _factor(result, kind) is None
    assert (kind, "UNTRUSTED_INTERFACE") in result.exclusions


def test_signal_event_must_pin_the_exact_target_bar_clock():
    source = _source()
    with pytest.raises(RegimeAdapterError) as caught:
        _adapt(
            (source,),
            policy=_policy((source,)),
            source_registry=_registry((source,)),
            signal=_signal(event=NOW - 1),
        )
    assert caught.value.code == "SIGNAL_MISMATCH"
