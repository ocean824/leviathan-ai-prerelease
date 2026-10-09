from __future__ import annotations

import copy
import json
import pickle
import random
from dataclasses import fields, replace
from decimal import Decimal, localcontext
from pathlib import Path

import pytest

from leviathan_core.regime import (
    RegimeClockV1,
    RegimeError,
    RegimeFactorV1,
    RegimeResultV1,
    RegimeSnapshotV1,
    RegimeSourceIdV1,
    RegimeSourceRecordV1,
    RegimeSourceRegistryV1,
    RegimeWeightPolicyV1,
    score,
)

FIXTURES = Path(__file__).parent / "fixtures" / "kernel"
ASOF = 1_000_000_000
DEFAULT_REGISTRY = RegimeSourceRegistryV1(
    version="fixture-v1",
    records=tuple(
        RegimeSourceRecordV1(
            RegimeSourceIdV1(f"{kind}-fixture"), "PIPELINE", "SYNTHETIC",
            ("FLOW-001:acceptance",) if kind == "flow" else (),
        )
        for kind in ("dealer", "flow", "dp", "macro")
    ),
)


def _score(snapshot, policy, history, asof, *, source_registry=DEFAULT_REGISTRY):
    return score(snapshot, policy, history, asof, source_registry=source_registry)


def _clock(*, index=50, finalized=True, asof=ASOF, symbol="XYZ", universe="US-EQUITY"):
    return RegimeClockV1(
        bar_id=f"bar-{index}", bar_index=index, session_id="RTH-1", symbol=symbol,
        universe=universe, calendar_version="cal-v1", asof_ns=asof,
        finalized=finalized,
    )


def _factor(kind, value="0", *, available=ASOF, baseline=ASOF, feature=None, source_type="PIPELINE",
            fresh=ASOF + 1, lag=0, entitled=True, valid=True, event=ASOF,
            source=None, scope="symbol", scope_key="XYZ", entitlement="SYNTHETIC",
            release_lag="fixture-release", upstream_interface_id=None):
    return RegimeFactorV1(
        kind=kind, value=Decimal(value), source=source or f"{kind}-fixture", source_version="v1",
        semantic_digest=f"{kind}-digest", event_ns=event, available_ns=available,
        baseline_available_ns=baseline, valid=valid, fresh_until_ns=fresh,
        scope=scope, window_sec=60, horizon_sec=60, entitlement=entitlement,
        release_lag=release_lag, feature_available_ns=feature, source_type=source_type,
        release_lag_ns=lag, entitled=entitled,
        upstream_interface_id=(upstream_interface_id or
                               ("FLOW-001:acceptance" if kind == "flow" else None)),
        scope_key=scope_key,
    )


def _snapshot(factors, *, truth="PASS", signal="FINALIZED", index=50, prior=None,
              finalized=True, asof=ASOF, symbol="XYZ", universe="US-EQUITY",
              flow_source=None, flow_quality="GOOD", record_available_ns=None):
    flows = [factor for factor in factors if factor.kind == "flow"]
    return RegimeSnapshotV1(
        clock=_clock(index=index, finalized=finalized, asof=asof, symbol=symbol,
                     universe=universe), factors=tuple(factors), truth_status=truth,
        record_available_ns=asof if record_available_ns is None else record_available_ns,
        signal_status=signal, prior_result=prior,
        flow_source=flow_source or (flows[0].source if flows else None),
        flow_quality=flow_quality if flows else None,
    )


def test_unknown_default_truth_and_signal_cannot_grant_readiness():
    factors = tuple(_factor(k, "1") for k in ("dealer", "flow", "dp", "macro"))
    snapshot = RegimeSnapshotV1(clock=_clock(), factors=factors, record_available_ns=ASOF)
    result = _score(snapshot, RegimeWeightPolicyV1(), (), ASOF)
    assert result.readiness == "HOLD"
    assert "TRUTH" in " ".join(result.reason_codes)


def test_exact_discrete_threshold_endpoints():
    fixture = json.loads((FIXTURES / "score_boundaries.json").read_text(encoding="utf-8-sig"))
    for raw, expected in zip(fixture["thresholds"], fixture["expected_regimes"], strict=True):
        factors = tuple(_factor(k, raw) for k in ("dealer", "flow", "dp", "macro"))
        result = _score(_snapshot(factors), RegimeWeightPolicyV1(), (), ASOF)
        assert result.composite_raw == Decimal(raw)
        assert result.composite_regime == expected


def test_exact_weighted_threshold_comparison_does_not_round_into_neutral_bucket():
    factors = (
        _factor("dealer", "0.8000000000000000000000000000000001"),
        _factor("flow", "0"),
    )
    result = _score(_snapshot(factors), RegimeWeightPolicyV1(), (), ASOF)
    assert result.composite_regime == 1
    assert result.composite_raw is not None
    assert result.composite_raw >= Decimal("0.4")

def test_three_factors_use_l1_renormalization_and_report_missing_feed():
    factors = (_factor("dealer", "2"), _factor("dp", "0"), _factor("macro", "0"))
    result = _score(_snapshot(factors), RegimeWeightPolicyV1(), (), ASOF)
    assert result.status == "PARTIAL"
    assert result.composite_raw == Decimal("0.8571428571428571428571428571428571")
    assert result.missing_factors == ("flow",)
    assert result.readiness in {"DEGRADED", "HOLD"}


def test_stale_unentitled_future_baseline_and_future_factor_are_missing_not_neutral():
    factors = (
        _factor("dealer", "1", fresh=ASOF - 1),
        _factor("flow", "1", available=ASOF + 1),
        _factor("dp", "1", entitled=False),
        _factor("macro", "1", baseline=ASOF + 1),
    )
    result = _score(_snapshot(factors), RegimeWeightPolicyV1(), (), ASOF)
    assert result.composite_raw is None
    assert result.composite_regime is None
    assert result.status == "INSUFFICIENT_DATA"
    assert result.missing_factors == ("dealer", "flow", "dp", "macro")
    assert result.confidence == Decimal("0")
    assert result.readiness == "HOLD"
    assert result.carried_forward is False


def test_truth_unknown_or_provisional_signal_cannot_become_ready():
    factors = tuple(_factor(k, "1") for k in ("dealer", "flow", "dp", "macro"))
    for kwargs in ({"truth": "UNKNOWN"}, {"signal": "PROVISIONAL"}):
        result = _score(_snapshot(factors, **kwargs), RegimeWeightPolicyV1(), (), ASOF)
        assert result.readiness == "HOLD"


def test_input_permutation_preserves_hash_and_score():
    factors = tuple(_factor(k, "0.5") for k in ("dealer", "flow", "dp", "macro"))
    forward = _score(_snapshot(factors), RegimeWeightPolicyV1(), (), ASOF)
    reversed_result = _score(_snapshot(tuple(reversed(factors))), RegimeWeightPolicyV1(), (), ASOF)
    assert forward.inputs_hash == reversed_result.inputs_hash
    assert forward.composite_raw == reversed_result.composite_raw







def test_one_eligible_factor_is_insufficient_and_two_factors_are_partial():
    one = _score(_snapshot((_factor("dealer", "2"),)), RegimeWeightPolicyV1(), (), ASOF)
    assert one.status == "INSUFFICIENT_DATA"
    assert one.composite_raw is None
    assert one.composite_regime is None
    assert one.confidence == Decimal("0")
    two = _score(_snapshot((_factor("dealer", "1"), _factor("dp", "0"))),
                RegimeWeightPolicyV1(), (), ASOF)
    assert two.status == "PARTIAL"
    assert two.composite_raw == Decimal("0.6")
    assert two.missing_factors == ("flow", "macro")
    assert two.readiness != "READY"


def test_winsorization_and_composite_clamp_preserve_documented_limits():
    high = tuple(_factor(k, "100") for k in ("dealer", "flow", "dp", "macro"))
    low = tuple(_factor(k, "-100") for k in ("dealer", "flow", "dp", "macro"))
    positive = _score(_snapshot(high), RegimeWeightPolicyV1(), (), ASOF)
    negative = _score(_snapshot(low), RegimeWeightPolicyV1(), (), ASOF)
    assert positive.composite_raw == Decimal("2")
    assert negative.composite_raw == Decimal("-2")


def test_release_lag_feature_availability_and_untrusted_agent_source_are_excluded():
    policy = RegimeWeightPolicyV1()
    factors = (
        _factor("dealer", "1", event=ASOF - 5, lag=10),
        _factor("flow", "1", feature=ASOF + 1),
        _factor("dp", "1", source_type="MODEL"),
        _factor("macro", "0"),
    )
    prior_factors = tuple(
        _factor(kind, "0.5", event=ASOF - 2, available=ASOF - 2, baseline=ASOF - 2)
        for kind in ("dealer", "flow", "dp", "macro")
    )
    prior_snapshot = _snapshot(prior_factors, index=49)
    prior_result = _score(prior_snapshot, policy, (), ASOF)
    result = _score(_snapshot(factors), policy, (prior_snapshot,), ASOF)
    assert result.status == "INSUFFICIENT_DATA"
    assert result.composite_raw is None
    assert result.confidence == Decimal("0")
    assert result.readiness == "HOLD"
    assert result.carried_forward is True
    assert result.composite_regime == prior_result.composite_regime
    assert result.missing_factors == ("dealer", "flow", "dp")
    assert any(reason.startswith("RELEASE_LAG") for reason in result.reason_codes)
    assert any(reason.startswith("FEATURE_FUTURE") for reason in result.reason_codes)
    assert any(reason.startswith("UNTRUSTED_SOURCE") for reason in result.reason_codes)


def test_confidence_warmup_requires_30_then_120_complete_finalized_bars():
    policy = RegimeWeightPolicyV1()
    factors = tuple(_factor(k, "0") for k in ("dealer", "flow", "dp", "macro"))

    def scored_length(length):
        history = tuple(_snapshot(factors, index=i) for i in range(length - 1))
        target = _snapshot(factors, index=length - 1)
        return _score(target, policy, history, ASOF)

    short = scored_length(29)
    warm = scored_length(30)
    full = scored_length(120)
    assert short.confidence == Decimal("0")
    assert "WARMUP_30" in short.reason_codes
    assert warm.confidence == Decimal("0.6")
    assert warm.readiness != "READY"
    assert full.confidence == Decimal("1")
    assert full.readiness == "READY"


def test_exact_120_bar_confidence_boundary_holds_when_display_rounds_to_point_four():
    policy = RegimeWeightPolicyV1()
    low = "0.5"
    high = "0.8277306934167250185409818578228585"
    history = tuple(
        _snapshot(
            tuple(_factor(kind, low if index < 105 else high)
                  for kind in ("dealer", "flow", "dp", "macro")),
            index=index,
        )
        for index in range(119)
    )
    target = _snapshot(
        tuple(_factor(kind, high) for kind in ("dealer", "flow", "dp", "macro")),
        index=119,
    )

    result = _score(target, policy, history, ASOF)

    assert result.status == "SCORED"
    assert result.confidence == Decimal("0.4")
    assert result.readiness == "HOLD"


def test_future_prior_result_does_not_change_earlier_asof_replay():
    policy = RegimeWeightPolicyV1()
    factors = tuple(
        _factor(kind, "0.5", available=100, baseline=100, event=100, fresh=1_000)
        for kind in ("dealer", "flow", "dp", "macro")
    )
    original = _snapshot(factors, index=0, asof=100, record_available_ns=100)
    earlier = _score(original, policy, (), 100)
    corrected_factors = tuple(
        _factor(kind, "1" if kind == "dealer" else "0.5",
                available=200, baseline=100, event=100, fresh=1_000)
        for kind in ("dealer", "flow", "dp", "macro")
    )
    corrected_snapshot = _snapshot(
        corrected_factors, index=0, asof=200, record_available_ns=200, prior=earlier,
    )
    later_result = _score(corrected_snapshot, policy, (), 200)
    assert later_result.revision == earlier.revision + 1
    visible_snapshot_with_future_lineage = replace(original, prior_result=later_result)

    replay = _score(visible_snapshot_with_future_lineage, policy, (), 100)

    assert repr(replay).encode("utf-8") == repr(earlier).encode("utf-8")


def test_result_replace_cannot_promote_zero_confidence_to_ready():
    factors = tuple(_factor(kind, "0.5") for kind in ("dealer", "flow", "dp", "macro"))
    result = _score(_snapshot(factors), RegimeWeightPolicyV1(), (), ASOF)

    with pytest.raises(RegimeError) as invariant_error:
        replace(result, readiness="READY", confidence=Decimal("0"))
    assert invariant_error.value.code == "RESULT_INVALID"

    with pytest.raises(RegimeError) as replace_error:
        replace(result)
    assert replace_error.value.code == "RESULT_SEALED"

    public_fields = {item.name: getattr(result, item.name)
                     for item in fields(RegimeResultV1) if item.init}
    with pytest.raises(RegimeError) as construction_error:
        RegimeResultV1(**public_fields)
    assert construction_error.value.code == "RESULT_SEALED"

    for forged_seal in (result.content_digest, object()):
        with pytest.raises(TypeError):
            replace(result, readiness="HOLD", _seal=forged_seal)
    with pytest.raises((TypeError, ValueError)):
        replace(result, content_digest=result.content_digest)


def test_incomplete_or_unknown_bars_cannot_supply_warmup_or_publish_current():
    policy = RegimeWeightPolicyV1()
    partial_factors = (_factor("dealer", "1"), _factor("flow", "1"))
    bad_history = tuple(_snapshot(partial_factors, index=i) for i in range(119))
    complete = tuple(_factor(k, "1") for k in ("dealer", "flow", "dp", "macro"))
    target = _snapshot(complete, index=119)
    result = _score(target, policy, bad_history, ASOF)
    assert result.readiness != "READY"
    assert result.confidence < Decimal("0.7")


def test_correction_revision_and_older_history_only_status_are_explicit():
    policy = RegimeWeightPolicyV1()
    complete = tuple(_factor(k, "0") for k in ("dealer", "flow", "dp", "macro"))
    original = _snapshot(complete, index=10)
    initial = _score(original, policy, (), ASOF)
    revised_factors = tuple(_factor(k, "0.5" if k == "dealer" else "0")
                            for k in ("dealer", "flow", "dp", "macro"))
    revised = _snapshot(revised_factors, index=10, prior=initial)
    correction = _score(revised, policy, (), ASOF)
    assert correction.revision == 1
    assert correction.previous_revision == 0

    old = _snapshot(complete, index=5)
    old_history = tuple(_snapshot(complete, index=i) for i in range(6, 11))
    old_result = _score(old, policy, old_history, ASOF)
    assert old_result.status == "HISTORY_ONLY"
    assert old_result.publish_current is False


def test_correction_exactly_two_finalized_bars_late_is_history_only():
    policy = RegimeWeightPolicyV1()
    complete = tuple(_factor(kind, "0") for kind in ("dealer", "flow", "dp", "macro"))
    target = _snapshot(complete, index=8, prior=None)
    future_history = tuple(_snapshot(complete, index=index) for index in (9, 10))
    result = _score(target, policy, future_history, ASOF)
    assert result.status == "HISTORY_ONLY"
    assert result.publish_current is False


def test_future_history_never_warms_confidence_or_promotes_ready():
    policy = RegimeWeightPolicyV1()
    complete = tuple(_factor(kind, "0") for kind in ("dealer", "flow", "dp", "macro"))
    future_history = tuple(
        _snapshot(complete, index=index, asof=ASOF + 1)
        for index in range(119)
    )
    target = _snapshot(complete, index=119)
    result = _score(target, policy, future_history, ASOF)
    assert result.readiness != "READY"
    assert result.confidence == Decimal("0")
    assert "WARMUP_30" in result.reason_codes


def test_symbol_scope_requires_a_matching_symbol_key():
    factors = (
        _factor("dealer", "1", scope="symbol", scope_key="OTHER"),
        _factor("flow", "1"), _factor("dp", "1"), _factor("macro", "1"),
    )
    result = _score(_snapshot(factors, symbol="XYZ"), RegimeWeightPolicyV1(), (), ASOF)
    assert result.status == "PARTIAL"
    assert result.missing_factors == ("dealer",)
    assert "SCOPE_DEALER" in result.reason_codes


def test_agent_model_unverified_flow_and_lag_mismatch_factors_are_ineligible():
    factors = (
        _factor("dealer", "1", source="feed/agent:untrusted", source_type="PIPELINE"),
        _factor("flow", "1"),
        _factor("dp", "1", source_type="MODEL"),
        _factor("macro", "1", release_lag="72h", lag=0),
    )
    snapshot = _snapshot(factors, flow_quality="BAD")
    result = _score(snapshot, RegimeWeightPolicyV1(), (), ASOF)
    assert result.status == "INSUFFICIENT_DATA"
    assert result.composite_raw is None
    assert result.missing_factors == ("dealer", "flow", "dp", "macro")
    assert any(reason.startswith("UNTRUSTED_SOURCE") for reason in result.reason_codes)
    assert any(reason.startswith("FLOW_QUALITY") for reason in result.reason_codes)
    assert any(reason.startswith("RELEASE_LAG_MISMATCH") for reason in result.reason_codes)


def test_registered_agent_model_and_unregistered_sources_fail_closed():
    registry = RegimeSourceRegistryV1(
        version="fixture-v1",
        records=(
            *DEFAULT_REGISTRY.records,
            RegimeSourceRecordV1(RegimeSourceIdV1("agent-source"), "AGENT", "SYNTHETIC"),
            RegimeSourceRecordV1(RegimeSourceIdV1("model-source"), "MODEL", "SYNTHETIC"),
        ),
    )
    factors = (
        _factor("dealer", "1", source="agent-source", source_type="AGENT"),
        _factor("flow", "1"),
        _factor("dp", "1", source="model-source", source_type="MODEL"),
        _factor("macro", "1", source="unregistered-source"),
    )
    result = _score(
        _snapshot(factors), RegimeWeightPolicyV1(), (), ASOF,
        source_registry=registry,
    )
    assert result.status == "INSUFFICIENT_DATA"
    assert result.missing_factors == ("dealer", "dp", "macro")
    assert result.composite_raw is None
    assert any(reason.startswith("UNTRUSTED_SOURCE") for reason in result.reason_codes)


def test_flow_interface_must_exactly_match_its_source_registry_binding():
    ordinary = tuple(_factor(kind, "1") for kind in ("dealer", "flow", "dp", "macro"))
    exact = _score(_snapshot(ordinary), RegimeWeightPolicyV1(), (), ASOF)
    assert "flow" not in exact.missing_factors
    flow_factor = next(factor for factor in exact.factor_provenance if factor.kind == "flow")
    assert flow_factor.upstream_interface_id == "FLOW-001:acceptance"

    for spoofed_interface in (
        "FLOW-001:agent:untrusted",
        "FLOW-001:acceptance:arbitrary-suffix",
    ):
        spoofed = tuple(
            _factor(
                kind, "1", upstream_interface_id=(
                    spoofed_interface if kind == "flow" else None
                ),
            )
            for kind in ("dealer", "flow", "dp", "macro")
        )
        result = _score(_snapshot(spoofed), RegimeWeightPolicyV1(), (), ASOF)
        assert "flow" in result.missing_factors
        assert "UNTRUSTED_INTERFACE" in result.reason_codes

    non_flow_claim = tuple(
        _factor(
            kind, "1", upstream_interface_id=(
                "FLOW-001:acceptance:claimed" if kind == "dealer" else None
            ),
        )
        for kind in ("dealer", "flow", "dp", "macro")
    )
    result = _score(_snapshot(non_flow_claim), RegimeWeightPolicyV1(), (), ASOF)
    assert "dealer" in result.missing_factors
    assert "UNTRUSTED_INTERFACE" in result.reason_codes


def test_text_booleans_are_rejected_by_factor_and_clock_models():
    factor = _factor("dealer")
    with pytest.raises(RegimeError):
        replace(factor, valid="false")
    with pytest.raises(RegimeError):
        replace(factor, entitled="false")
    with pytest.raises(RegimeError):
        replace(_clock(), finalized="false")


def test_correction_visibility_uses_its_own_availability_time():
    policy = RegimeWeightPolicyV1()
    old_clock = ASOF - 100
    corrected = tuple(
        _factor(kind, "1" if kind == "dealer" else "0", available=ASOF - 1,
                baseline=old_clock, event=old_clock, fresh=ASOF + 1)
        for kind in ("dealer", "flow", "dp", "macro")
    )
    snapshot = _snapshot(corrected, index=20, asof=old_clock)
    result = _score(snapshot, policy, (), ASOF)
    assert result.composite_raw is not None
    assert result.factor_provenance
    assert all(factor.available_ns == ASOF - 1 for factor in result.factor_provenance)


def test_decimal_ambient_context_and_equal_representations_preserve_hash_and_score():
    factors = tuple(
        _factor(kind, "0.500" if kind == "dealer" else "0.25")
        for kind in ("dealer", "flow", "dp", "macro")
    )
    snapshot = _snapshot(factors)
    expected = _score(snapshot, RegimeWeightPolicyV1(), (), ASOF)
    with localcontext() as context:
        context.prec = 6
        context.Emax = 9
        constrained = _score(snapshot, RegimeWeightPolicyV1(), (), ASOF)
    equivalent_factors = tuple(
        _factor(kind, "0.5" if kind == "dealer" else "0.25")
        for kind in ("dealer", "flow", "dp", "macro")
    )
    equivalent = _score(_snapshot(equivalent_factors), RegimeWeightPolicyV1(), (), ASOF)
    assert constrained.inputs_hash == expected.inputs_hash
    assert constrained.composite_raw == expected.composite_raw
    assert equivalent.inputs_hash == expected.inputs_hash
    assert repr(expected).encode("utf-8") == repr(equivalent).encode("utf-8")
    assert expected.factor_provenance == equivalent.factor_provenance


def test_visible_correction_presentation_in_history_or_current_preserves_confidence():
    policy = RegimeWeightPolicyV1()
    def bar(index):
        clock = 1000 + index
        factors = tuple(
            _factor(kind, "1", available=clock, baseline=clock, event=clock,
                    fresh=clock + 10)
            for kind in ("dealer", "flow", "dp", "macro")
        )
        return _snapshot(factors, index=index, asof=clock)

    history_before_correction = tuple(bar(index) for index in range(118))
    old_118 = bar(118)
    corrected_118_factors = tuple(
        _factor(kind, "2" if kind == "dealer" else "1", available=ASOF,
                baseline=1118, event=1118, fresh=1128)
        for kind in ("dealer", "flow", "dp", "macro")
    )
    corrected_118 = _snapshot(corrected_118_factors, index=118, asof=1118)
    current_119 = bar(119)
    correction_path = _score(
        corrected_118, policy, (*history_before_correction, old_118, current_119), ASOF,
    )
    direct_current_path = _score(
        current_119, policy, (*history_before_correction, corrected_118), ASOF,
    )
    assert correction_path.affected_results
    assert correction_path.affected_results[-1].clock.bar_id == current_119.clock.bar_id
    assert correction_path.affected_results[-1].confidence == direct_current_path.confidence


def test_history_conflict_raises_typed_error_and_unfinalized_bar_is_not_published():
    policy = RegimeWeightPolicyV1()
    factors = tuple(_factor(kind, "0") for kind in ("dealer", "flow", "dp", "macro"))
    first = _snapshot(factors, index=49)
    conflict = _snapshot(
        tuple(_factor(kind, "1" if kind == "dealer" else "0")
              for kind in ("dealer", "flow", "dp", "macro")),
        index=49,
    )
    target = _snapshot(factors, index=50)
    with pytest.raises(RegimeError) as exc:
        _score(target, policy, (first, conflict), ASOF)
    assert exc.value.code == "HISTORY_CONFLICT"

    unfinalized = _snapshot(factors, index=51, finalized=False)
    withheld = _score(unfinalized, policy, (), ASOF)
    assert withheld.publish_current is False
    assert withheld.readiness == "HOLD"


def test_future_available_same_bar_corrections_cannot_change_earlier_replay():
    policy = RegimeWeightPolicyV1()
    factors = tuple(_factor(kind, "0.5") for kind in ("dealer", "flow", "dp", "macro"))
    earlier = _snapshot(factors, index=49, asof=ASOF)
    target = _snapshot(factors, index=50, asof=ASOF)
    expected = _score(target, policy, (earlier,), ASOF)
    generator = random.Random(20260930)

    for _ in range(24):
        future_asof = ASOF + generator.randint(1, 1_000_000)
        revised_factors = tuple(
            _factor(
                kind, str(generator.randint(-10, 10) / 10),
                available=future_asof, baseline=future_asof, event=future_asof,
                fresh=future_asof + 1,
            )
            for kind in ("dealer", "flow", "dp", "macro")
        )
        future_revision = _snapshot(
            revised_factors, index=49, asof=future_asof,
            record_available_ns=future_asof,
        )
        replay = _score(target, policy, (earlier, future_revision), ASOF)
        assert repr(replay).encode("utf-8") == repr(expected).encode("utf-8")


def test_regime_decimal_bounds_reject_overflow_and_copy_pickle_are_blocked():
    with pytest.raises(RegimeError):
        _factor("dealer", "1e1000000")
    with pytest.raises(RegimeError):
        _factor("dealer", "123456789012345678901234567890123456789012345678901")
    factors = tuple(_factor(kind) for kind in ("dealer", "flow", "dp", "macro"))
    factor = factors[0]
    snapshot = _snapshot(factors)
    policy = RegimeWeightPolicyV1()
    result = _score(snapshot, policy, (), ASOF)
    public_models = (factor, _clock(), policy, snapshot, result)
    for model in public_models:
        with pytest.raises(RegimeError) as copy_error:
            copy.copy(model)
        assert copy_error.value.code == "IMMUTABLE_COPY"
        with pytest.raises(RegimeError) as deepcopy_error:
            copy.deepcopy(model)
        assert deepcopy_error.value.code == "IMMUTABLE_COPY"
        with pytest.raises(RegimeError) as pickle_error:
            pickle.dumps(model)
        assert pickle_error.value.code == "IMMUTABLE_COPY"
    replacement = replace(factor, value=Decimal("0.5"))
    assert replacement.value == Decimal("0.5")
    with pytest.raises(RegimeError):
        replace(snapshot, factors=list(factors))
    with pytest.raises(RegimeError) as policy_error:
        replace(policy, w_dealer=Decimal("1.5"))
    assert policy_error.value.code == "POLICY_OUT_OF_BOUNDS"


def test_regime_precision_over_34_digits_is_rejected_without_rounding():
    with pytest.raises(RegimeError) as exc:
        _factor("dealer", "1.12345678901234567890123456789012345")
    assert exc.value.code == "PRECISION_EXCEEDED"


def test_boolean_is_rejected_for_every_integer_clock_factor_policy_result_and_asof_field():
    factor = _factor("dealer")
    policy = RegimeWeightPolicyV1()
    clock = _clock()
    snapshot = _snapshot((factor,))
    result = _score(snapshot, policy, (), ASOF)
    invalid_replacements = (
        lambda: replace(factor, available_ns=True),
        lambda: replace(factor, release_lag_ns=True),
        lambda: replace(factor, window_sec=True),
        lambda: replace(clock, bar_index=True),
        lambda: replace(clock, asof_ns=True),
        lambda: replace(policy, median_window=True),
        lambda: replace(snapshot, clock=replace(clock, asof_ns=True)),
        lambda: replace(result, revision=True),
        lambda: _score(snapshot, policy, (), True),
    )
    for reconstruct in invalid_replacements:
        with pytest.raises(RegimeError):
            reconstruct()


