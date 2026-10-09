"""Focused deterministic tests for the REG-001 offline kernel."""

import copy
import pickle
import random
from collections.abc import Sequence
from dataclasses import replace
from decimal import Decimal, localcontext

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
)
from leviathan_core.regime import (
    score as kernel_score,
)

TRUSTED_SOURCES = RegimeSourceRegistryV1(
    version="test-v1",
    records=(RegimeSourceRecordV1(
        source_id=RegimeSourceIdV1("source"), trust_class="PIPELINE",
        entitlement="LICENSED", allowed_interface_ids=("FLOW-001:fixture",),
    ),),
)


def score(
    current: RegimeSnapshotV1, policy: RegimeWeightPolicyV1,
    history: Sequence[RegimeSnapshotV1], asof_ns: int,
    source_registry: RegimeSourceRegistryV1 = TRUSTED_SOURCES,
) -> RegimeResultV1:
    return kernel_score(current, policy, history, asof_ns, source_registry)


def factor(kind: str, value: str, **changes: object) -> RegimeFactorV1:
    base = RegimeFactorV1(
        kind=kind,  # type: ignore[arg-type]
        value=Decimal(value),
        source=RegimeSourceIdV1("source"), source_version="v1", semantic_digest="digest",
        event_ns=1, available_ns=1, baseline_available_ns=1, valid=True,
        fresh_until_ns=10_000, scope="global", window_sec=60, horizon_sec=60,
        entitlement="LICENSED", release_lag="none",
        upstream_interface_id="FLOW-001:fixture" if kind == "flow" else None,
    )
    return replace(base, **changes)


def snapshot(index: int, values: tuple[str, ...] = ("0", "0", "0", "0"),
             **changes: object) -> RegimeSnapshotV1:
    clock = RegimeClockV1(
        bar_id=f"bar-{index}", bar_index=index, session_id="session", symbol="ES",
        universe="futures", calendar_version="v1", asof_ns=index + 10,
        window_sec=60, horizon_sec=60,
    )
    base = RegimeSnapshotV1(
        clock=clock,
        factors=tuple(factor(kind, value) for kind, value in zip(
            ("dealer", "flow", "dp", "macro"), values, strict=True,
        )),
        record_available_ns=clock.asof_ns,
        signal_status="FINALIZED", truth_status="PASS",
        flow_source="source", flow_quality="GOOD",
    )
    return replace(base, **changes)


@pytest.mark.parametrize(
    ("value", "bucket"),
    [
        ("-2", -2), ("-1.2", -1), ("-0.4", 0), ("0.4", 0),
        ("1.2", 1), ("2", 2),
    ],
)
def test_threshold_endpoints(value: str, bucket: int) -> None:
    current = snapshot(0, (value,) * 4)
    result = score(current, RegimeWeightPolicyV1(), [], current.clock.asof_ns)
    assert result.composite_raw == Decimal(value)
    assert result.composite_regime == bucket


def test_winsorization_clamp_and_missing_weight_normalization() -> None:
    current = snapshot(0, ("10", "10", "0", "0"))
    full = score(current, RegimeWeightPolicyV1(), [], current.clock.asof_ns)
    assert full.composite_raw == Decimal("2")
    partial = replace(current, factors=current.factors[:2])
    reduced = score(partial, RegimeWeightPolicyV1(), [], partial.clock.asof_ns)
    assert reduced.composite_raw == Decimal("2")
    assert reduced.status == "PARTIAL"
    assert reduced.missing_factors == ("dp", "macro")
    assert "ABSENT_DP" in reduced.reason_codes
    assert reduced.confidence <= full.confidence


def test_one_factor_carries_previous_regime_without_new_score() -> None:
    previous = snapshot(0, ("1",) * 4)
    current = replace(snapshot(1), factors=snapshot(1).factors[:1])
    result = score(current, RegimeWeightPolicyV1(), [previous], current.clock.asof_ns)
    assert result.status == "INSUFFICIENT_DATA"
    assert result.composite_raw is None
    assert result.composite_regime == 1
    assert result.carried_forward
    assert result.confidence == 0
    assert result.readiness == "HOLD"


def test_time_gates_and_unknown_evidence() -> None:
    current = snapshot(0)
    gated = replace(
        current, factors=(
            replace(current.factors[0], available_ns=100),
            replace(current.factors[1], fresh_until_ns=0),
            replace(current.factors[2], release_lag="5m", release_lag_ns=300_000_000_000),
            current.factors[3],
        ),
        truth_status="UNKNOWN", signal_status="PROVISIONAL",
    )
    result = score(gated, RegimeWeightPolicyV1(), [], gated.clock.asof_ns)
    assert result.status == "INSUFFICIENT_DATA"
    assert {"UNPUBLISHED_DEALER", "STALE_FLOW", "RELEASE_LAG_DP"}.issubset(
        result.reason_codes
    )
    unknown = replace(current, truth_status="UNKNOWN", signal_status="UNKNOWN")
    history = [snapshot(index) for index in range(119)]
    unknown = replace(unknown, clock=replace(unknown.clock, bar_index=119, bar_id="bar-119",
                                             asof_ns=129), record_available_ns=129)
    held = score(unknown, RegimeWeightPolicyV1(), history, unknown.clock.asof_ns)
    assert held.readiness == "HOLD"
    assert "TRUTH_UNKNOWN" in held.reason_codes
    assert "SIGNAL_NOT_FINALIZED" in held.reason_codes


def test_evaluation_time_is_part_of_replay_identity() -> None:
    current = snapshot(0, ("1",) * 4)
    policy = RegimeWeightPolicyV1()
    on_time = score(current, policy, [], current.clock.asof_ns)
    stale = score(current, policy, [], 10_001)
    assert on_time.composite_raw == Decimal("1")
    assert stale.composite_raw is None
    assert "STALE_DEALER" in stale.reason_codes
    assert stale.inputs_hash != on_time.inputs_hash
    assert stale.evaluation_asof_ns == 10_001


def test_warmup_and_replay_permutation() -> None:
    policy = RegimeWeightPolicyV1()
    history = [snapshot(index, ("1",) * 4) for index in range(119)]
    current = snapshot(119, ("1",) * 4)
    result = score(current, policy, history, current.clock.asof_ns)
    assert result.confidence == 1
    assert result.readiness == "READY"
    permuted = score(current, policy, list(reversed(history)), current.clock.asof_ns)
    assert result == permuted
    cold = score(snapshot(29, ("1",) * 4), policy, history[:29], 39)
    assert cold.readiness == "HOLD"
    assert "WARMUP_120" in cold.reason_codes


def test_correction_window_and_proposed_policy() -> None:
    policy = RegimeWeightPolicyV1()
    history = [snapshot(index) for index in range(5)]
    changed = snapshot(3, ("1",) * 4)
    corrected = score(changed, policy, history, history[-1].clock.asof_ns)
    assert corrected.revision == 1
    assert corrected.publish_current
    assert len(corrected.affected_results) == 1
    changed_again = replace(snapshot(3, ("2",) * 4), prior_result=corrected)
    second = score(changed_again, policy, [*history[:3], changed, history[4]],
                   history[-1].clock.asof_ns)
    assert second.revision == 2
    assert second.previous_revision == 1
    old = score(snapshot(1, ("1",) * 4), policy, history, history[-1].clock.asof_ns)
    assert old.status == "HISTORY_ONLY"
    assert not old.publish_current
    proposed = RegimeWeightPolicyV1(version="candidate", status="PROPOSED")
    with pytest.raises(ValueError, match="PROPOSED_POLICY"):
        score(changed, proposed, history, changed.clock.asof_ns)


def test_missing_and_agent_sources_reduce_warmed_confidence() -> None:
    policy = RegimeWeightPolicyV1()
    history = [snapshot(index, ("1",) * 4) for index in range(119)]
    current = snapshot(119, ("1",) * 4)
    full = score(current, policy, history, current.clock.asof_ns)
    partial = score(replace(current, factors=current.factors[:3]), policy,
                    history, current.clock.asof_ns)
    assert full.confidence == 1
    assert partial.confidence == Decimal("0.75")
    assert partial.readiness == "DEGRADED"
    rejected = replace(current, factors=(
        replace(current.factors[0], source_type="AGENT"), *current.factors[1:],
    ))
    result = score(rejected, policy, history, current.clock.asof_ns)
    assert "UNTRUSTED_SOURCE_DEALER" in result.reason_codes
    assert result.missing_factors == ("dealer",)


def test_history_must_be_complete_and_version_consistent_for_ready() -> None:
    policy = RegimeWeightPolicyV1()
    history = [snapshot(index, ("1",) * 4) for index in range(119)]
    current = snapshot(119, ("1",) * 4)
    gap = [item for item in history if item.clock.bar_index != 50]
    assert score(current, policy, gap, current.clock.asof_ns).readiness == "HOLD"
    different_version = [
        replace(item, weight_version="other") if item.clock.bar_index == 50 else item
        for item in history
    ]
    assert score(current, policy, different_version, current.clock.asof_ns).readiness == "HOLD"
    unknown_truth = [
        replace(item, truth_status="UNKNOWN") if item.clock.bar_index == 50 else item
        for item in history
    ]
    assert score(current, policy, unknown_truth, current.clock.asof_ns).readiness == "HOLD"
    partial_bar = [
        replace(item, factors=item.factors[:3]) if item.clock.bar_index == 50 else item
        for item in history
    ]
    assert score(current, policy, partial_bar, current.clock.asof_ns).readiness == "HOLD"


def test_late_correction_revises_affected_rolling_confidence() -> None:
    policy = RegimeWeightPolicyV1()
    history = [snapshot(index) for index in range(120)]
    changed = snapshot(118, ("2",) * 4)
    result = score(changed, policy, history, history[-1].clock.asof_ns)
    assert result.revision == 1
    assert len(result.affected_results) == 1
    revised_current = result.affected_results[0]
    assert revised_current.clock.bar_index == 119
    assert revised_current.revision == 1
    assert revised_current.previous_revision == 0
    assert "UPSTREAM_CORRECTION" in revised_current.reason_codes
    assert revised_current.confidence < Decimal("1")


def test_exactly_two_finalized_bars_late_is_history_only() -> None:
    history = [snapshot(index) for index in range(3)]
    changed = snapshot(0, ("1",) * 4)
    result = score(changed, RegimeWeightPolicyV1(), history, history[-1].clock.asof_ns)
    assert result.status == "HISTORY_ONLY"
    assert not result.publish_current
    assert result.revision == 1
    assert not result.affected_results


def test_future_history_cannot_warm_confidence() -> None:
    future = []
    for index in range(120):
        item = snapshot(index, ("1",) * 4)
        future.append(replace(
            item, clock=replace(item.clock, asof_ns=2000), record_available_ns=2000,
            factors=tuple(replace(f, available_ns=2000, baseline_available_ns=2000)
                          for f in item.factors),
        ))
    target = replace(snapshot(120, ("1",) * 4),
                     clock=replace(snapshot(120).clock, asof_ns=1000),
                     record_available_ns=1000)
    result = score(target, RegimeWeightPolicyV1(), future, 1000)
    assert result.confidence == 0
    assert result.readiness == "HOLD"
    assert "WARMUP_30" in result.reason_codes


def test_symbol_scope_requires_matching_key() -> None:
    current = snapshot(0, ("1",) * 4)
    no_key = replace(current, factors=tuple(replace(f, scope="symbol") for f in current.factors))
    assert score(no_key, RegimeWeightPolicyV1(), [], 10).status == "INSUFFICIENT_DATA"
    scoped = replace(current, factors=tuple(
        replace(f, scope="symbol", scope_key="ES") for f in current.factors
    ))
    assert score(scoped, RegimeWeightPolicyV1(), [], 10).status == "SCORED"
    other = replace(scoped, clock=replace(scoped.clock, symbol="OTHER"))
    assert score(other, RegimeWeightPolicyV1(), [], 10).status == "INSUFFICIENT_DATA"


def test_untrusted_unverified_unentitled_and_lag_mismatch_are_missing() -> None:
    current = snapshot(0)
    gated = replace(current, factors=(
        replace(current.factors[0], source="agent:untrusted"),
        replace(current.factors[1], upstream_interface_id=None),
        replace(current.factors[2], entitlement="UNENTITLED"),
        replace(current.factors[3], release_lag="72h", release_lag_ns=0),
    ))
    result = score(gated, RegimeWeightPolicyV1(), [], 10)
    assert result.status == "INSUFFICIENT_DATA"
    assert {"UNTRUSTED_SOURCE_DEALER", "UNTRUSTED_INTERFACE", "UNENTITLED_DP",
            "RELEASE_LAG_MISMATCH_MACRO"}.issubset(result.reason_codes)
    blank_flow_id = replace(current, factors=(
        current.factors[0], replace(current.factors[1], upstream_interface_id="FLOW-001:"),
        *current.factors[2:],
    ))
    assert "UNTRUSTED_INTERFACE" in score(
        blank_flow_id, RegimeWeightPolicyV1(), [], 10
    ).reason_codes
    with pytest.raises(RegimeError, match="BOOLEAN_REQUIRED"):
        replace(current.factors[0], valid="False")
    with pytest.raises(RegimeError, match="BOOLEAN_REQUIRED"):
        replace(current.factors[0], entitled="False")


def test_flow_interface_requires_exact_source_registry_binding() -> None:
    policy = RegimeWeightPolicyV1()
    history = tuple(snapshot(index, ("1",) * 4) for index in range(119))
    current = snapshot(119, ("1",) * 4)
    trusted = score(current, policy, history, 129)
    assert trusted.status == "SCORED"
    assert trusted.readiness == "READY"
    assert trusted.confidence == Decimal(1)

    suffixes = ["FLOW-001:agent:untrusted"]
    rng = random.Random(157)
    suffixes.extend(
        f"FLOW-001:fixture:{rng.getrandbits(48):012x}" for _ in range(12)
    )
    for interface_id in suffixes:
        changed = replace(current, factors=(
            current.factors[0],
            replace(current.factors[1], upstream_interface_id=interface_id),
            *current.factors[2:],
        ))
        result = score(changed, policy, history, 129)
        assert result.status == "PARTIAL"
        assert result.readiness != "READY"
        assert result.missing_factors == ("flow",)
        assert "UNTRUSTED_INTERFACE" in result.reason_codes

    non_flow_claim = replace(current, factors=(
        replace(current.factors[0], upstream_interface_id="FLOW-001:agent:untrusted"),
        *current.factors[1:],
    ))
    non_flow_result = score(non_flow_claim, policy, history, 129)
    assert non_flow_result.missing_factors == ("dealer",)
    assert "UNTRUSTED_INTERFACE" in non_flow_result.reason_codes

    alternate = RegimeSourceRegistryV1(
        version="test-v2", records=(replace(
            TRUSTED_SOURCES.records[0],
            allowed_interface_ids=("FLOW-001:fixture", "FLOW-001:agent:untrusted"),
        ),),
    )
    registered = replace(current, factors=(
        current.factors[0],
        replace(current.factors[1], upstream_interface_id="FLOW-001:agent:untrusted"),
        *current.factors[2:],
    ))
    rebound = score(registered, policy, history, 129, alternate)
    assert rebound.readiness == "READY"
    assert rebound.inputs_hash != trusted.inputs_hash
    with pytest.raises(RegimeError, match="INTERFACE_INVALID"):
        replace(TRUSTED_SOURCES.records[0], allowed_interface_ids=("FLOW-001:fixture",) * 2)


def test_late_correction_uses_own_availability_and_bar_freshness() -> None:
    history = [snapshot(10), snapshot(11)]
    original = history[0]
    corrected = replace(original, factors=(
        replace(original.factors[0], value=Decimal("1"), available_ns=30),
        *(replace(f, fresh_until_ns=25) for f in original.factors[1:]),
    ))
    too_early = score(corrected, RegimeWeightPolicyV1(), history, 21)
    assert "UNPUBLISHED_DEALER" in too_early.reason_codes
    visible = score(corrected, RegimeWeightPolicyV1(), history, 30)
    assert visible.status == "SCORED"
    assert visible.composite_raw == Decimal("0.30")
    assert visible.revision == 1


def test_decimal_context_bounds_and_equal_hashes() -> None:
    policy = RegimeWeightPolicyV1()
    current = snapshot(0, ("0.123456789",) * 4)
    expected = score(current, policy, [], 10)
    with localcontext() as context:
        context.prec = 6
        actual = score(current, policy, [], 10)
    assert actual.composite_raw == expected.composite_raw
    assert actual.inputs_hash == expected.inputs_hash
    equivalent = snapshot(0, ("0.1234567890",) * 4)
    assert score(equivalent, policy, [], 10).inputs_hash == expected.inputs_hash
    with pytest.raises(RegimeError, match="DECIMAL_OUT_OF_BOUNDS"):
        factor("dealer", "1E+39")
    with pytest.raises(RegimeError, match="DECIMAL_OUT_OF_BOUNDS"):
        factor("dealer", "0E+39")
    with pytest.raises(RegimeError, match="PRECISION_EXCEEDED"):
        factor("dealer", "0." + "1" * 35)
    with pytest.raises(RegimeError, match="POLICY_OUT_OF_BOUNDS"):
        RegimeWeightPolicyV1(
            version="candidate", status="PROPOSED",
            w_dealer=Decimal("1.5" + "0" * 31 + "1"),
            w_flow=Decimal("1.5"), w_dp=Decimal("0"), w_macro=Decimal("0"),
        )


def test_conflicting_history_unfinalized_and_freeze_semantics() -> None:
    policy = RegimeWeightPolicyV1()
    first = snapshot(0)
    second = snapshot(0, ("1",) * 4)
    with pytest.raises(RegimeError, match="HISTORY_CONFLICT"):
        score(snapshot(1), policy, (first, second), 11)
    unfinalized = replace(first, clock=replace(first.clock, finalized=False))
    result = score(unfinalized, policy, (), 10)
    assert not result.publish_current
    with pytest.raises(RegimeError, match="RESULT_INVALID"):
        replace(result, publish_current=True)
    with pytest.raises(RegimeError, match="REVISION_INVALID"):
        replace(snapshot(1), prior_result=result)
    with pytest.raises(RegimeError, match="TIME_INVALID"):
        replace(first.factors[0], available_ns=True)
    with pytest.raises(RegimeError, match="CLOCK_INVALID"):
        replace(first.clock, bar_index=True)
    with pytest.raises(RegimeError, match="RESULT_INVALID"):
        replace(result, revision=True)
    for item in (first.clock, first.factors[0], first, policy, result):
        with pytest.raises(RegimeError, match="IMMUTABLE_COPY"):
            copy.copy(item)
        with pytest.raises(RegimeError, match="IMMUTABLE_COPY"):
            copy.deepcopy(item)
        with pytest.raises(RegimeError, match="IMMUTABLE_COPY"):
            pickle.dumps(item)


def test_exact_regime_boundary_uses_unrounded_ratio() -> None:
    current = snapshot(0, ("0.8000000000000000000000000000000001", "0", "0", "0"))
    current = replace(current, factors=current.factors[:2])
    result = score(current, RegimeWeightPolicyV1(), (), 10)
    assert result.composite_raw == Decimal("0.4")  # rounded display
    assert result.composite_regime == 1  # exact value is above 0.4


def test_trust_requires_registered_source_id_and_registry_is_hashed() -> None:
    current = snapshot(0, ("1",) * 4)
    wrapped = replace(current, factors=(
        replace(current.factors[0], source=RegimeSourceIdV1("feed/agent:untrusted")),
        *current.factors[1:],
    ))
    result = score(wrapped, RegimeWeightPolicyV1(), (), 10)
    assert result.missing_factors == ("dealer",)
    assert "UNTRUSTED_SOURCE_DEALER" in result.reason_codes
    assert score(current, RegimeWeightPolicyV1(), (), 10,
                 RegimeSourceRegistryV1("empty", ())).composite_raw is None
    other_registry = RegimeSourceRegistryV1(
        "test-v2", (RegimeSourceRecordV1(
            RegimeSourceIdV1("source"), "AGENT", "LICENSED",
        ),),
    )
    other = score(current, RegimeWeightPolicyV1(), (), 10, other_registry)
    assert other.composite_raw is None
    assert other.inputs_hash != score(current, RegimeWeightPolicyV1(), (), 10).inputs_hash


def test_public_result_and_provenance_are_decimal_canonical() -> None:
    first = score(snapshot(0, ("0.5",) * 4), RegimeWeightPolicyV1(), (), 10)
    second = score(snapshot(0, ("0.500",) * 4), RegimeWeightPolicyV1(), (), 10)
    assert first.inputs_hash == second.inputs_hash
    assert repr(first) == repr(second)
    assert first.content_digest == second.content_digest
    changed = score(snapshot(0, ("0.6",) * 4), RegimeWeightPolicyV1(), (), 10)
    assert changed.content_digest != first.content_digest
    with pytest.raises(RegimeError, match="RESULT_INVALID"):
        replace(first, readiness="READY", confidence=Decimal(0))
    with pytest.raises(RegimeError, match="RESULT_SEALED"):
        replace(first, confidence=first.confidence)
    assert all(factor.value.as_tuple() == Decimal("0.5").as_tuple()
               for factor in second.factor_provenance)
    policy = RegimeWeightPolicyV1(w_dealer=Decimal("0.300"))
    assert policy.w_dealer.as_tuple() == Decimal("0.3").as_tuple()


def test_compact_decimal_magnitude_and_source_freeze() -> None:
    assert factor("dealer", "1E+34").value == Decimal("1E+34")
    with pytest.raises(RegimeError, match="DECIMAL_OUT_OF_BOUNDS"):
        factor("dealer", "1E+100000")
    with pytest.raises(RegimeError, match="PRECISION_EXCEEDED"):
        factor("dealer", "1." + "1" * 34)
    with pytest.raises(RegimeError, match="POLICY_OUT_OF_BOUNDS"):
        replace(RegimeWeightPolicyV1(), median_window=31)
    with pytest.raises(RegimeError, match="SOURCE_TYPE_INVALID"):
        replace(TRUSTED_SOURCES.records[0], trust_class="UNKNOWN")
    with pytest.raises(RegimeError, match="SOURCE_REGISTRY_INVALID"):
        replace(TRUSTED_SOURCES, records=TRUSTED_SOURCES.records * 2)
    for item in (RegimeSourceIdV1("source"), TRUSTED_SOURCES.records[0], TRUSTED_SOURCES):
        with pytest.raises(RegimeError, match="IMMUTABLE_COPY"):
            copy.copy(item)
        with pytest.raises(RegimeError, match="IMMUTABLE_COPY"):
            copy.deepcopy(item)
        with pytest.raises(RegimeError, match="IMMUTABLE_COPY"):
            pickle.dumps(item)


def test_correction_presentation_invariant_at_caller_asof() -> None:
    history = [snapshot(index, ("1",) * 4) for index in range(120)]
    original = history[118]
    corrected = replace(original, factors=(
        replace(original.factors[0], value=Decimal("2"), available_ns=130),
        *original.factors[1:],
    ))
    from_history = score(history[119], RegimeWeightPolicyV1(),
                         [*history[:118], corrected], 130)
    from_current = score(corrected, RegimeWeightPolicyV1(), history, 130)
    affected = from_current.affected_results[0]
    assert from_history.composite_raw == affected.composite_raw
    assert from_history.composite_regime == affected.composite_regime
    assert from_history.confidence == affected.confidence
    assert from_history.readiness == affected.readiness


def test_future_revision_insertions_cannot_change_prior_asof_result() -> None:
    rng = random.Random(1729)
    policy = RegimeWeightPolicyV1()
    history = [snapshot(index, ("1",) * 4) for index in range(5)]
    current = snapshot(5, ("1",) * 4)
    asof_ns = current.clock.asof_ns
    expected = score(current, policy, history, asof_ns)
    inserted: list[RegimeSnapshotV1] = []
    for _ in range(64):
        index = rng.randrange(6)
        original = current if index == 5 else history[index]
        future_ns = asof_ns + rng.randrange(1, 100)
        changed = replace(
            original,
            factors=(
                replace(original.factors[0], value=Decimal(rng.randrange(-4, 5)),
                        available_ns=future_ns),
                *original.factors[1:],
            ),
            record_available_ns=future_ns,
        )
        if rng.randrange(2):
            changed = replace(changed, clock=replace(changed.clock, symbol="OTHER"))
        inserted.append(changed)
        assert repr(score(current, policy, [*history, *inserted], asof_ns)) == repr(expected)

    visible_conflict = replace(history[0], factors=snapshot(0, ("2",) * 4).factors)
    with pytest.raises(RegimeError, match="HISTORY_CONFLICT"):
        score(current, policy, [*history, visible_conflict], asof_ns)
    with pytest.raises(RegimeError, match="RECORD_NOT_VISIBLE"):
        score(replace(current, record_available_ns=asof_ns + 1), policy, history, asof_ns)
    with pytest.raises(RegimeError, match="RECORD_AVAILABILITY_INVALID"):
        replace(current, record_available_ns=True)
