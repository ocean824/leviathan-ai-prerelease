"""Independent compatibility tests for the two revision-hash profiles."""

from __future__ import annotations

from decimal import Decimal

import pytest

from leviathan_core.agent_council.runner_models import CouncilRunCommandV1, RunBudgetV1
from leviathan_core.agent_council.runner_service import _revision_hash
from leviathan_core.agent_council.state_machine import _semantic_hash
from leviathan_core.agent_council.state_models import (
    DatasetSnapshotRefV1,
    ExperimentSpecV1,
    HypothesisV1,
    SignalRefV1,
    TimeWindowV1,
)
from leviathan_core.agent_revision_hash import (
    CouncilStateSemanticDigestV1,
    HypothesisFullRevisionDigestV1,
    RevisionHashCode,
    RevisionHashError,
    council_state_semantic,
    hypothesis_full_revision,
)

HASH_A = "a" * 64
HASH_B = "b" * 64
DEFAULT_REFS = (
    SignalRefV1(signal_id="signal-z", version="2"),
    SignalRefV1(signal_id="signal-a", version="11"),
    SignalRefV1(signal_id="signal-a", version="3"),
)


def make_hypothesis(
    *,
    hypothesis_id: str = "hypothesis-base",
    version: int = 1,
    signal_refs: tuple[SignalRefV1, ...] = DEFAULT_REFS,
    strategy_name: str = "synthetic-strategy",
    markets: tuple[str, ...] = ("SYNTH-A", "SYNTH-B"),
    target_metrics: tuple[str, ...] = ("return", "drawdown"),
    max_leverage: Decimal = Decimal("1.25"),
    max_loss_per_trade: Decimal = Decimal("0.0125"),
    seed: int = 17,
) -> HypothesisV1:
    return HypothesisV1(
        hypothesis_id=hypothesis_id,
        version=version,
        strategy_name=strategy_name,
        signal_refs=signal_refs,
        markets=markets,
        horizon=TimeWindowV1(start_ns=1, end_ns=10_000),
        target_metrics=target_metrics,
        max_leverage=max_leverage,
        max_loss_per_trade=max_loss_per_trade,
        seed_policy="fixed",
        seed=seed,
        source_hashes=(HASH_A, HASH_B),
    )


def make_command(hypothesis: HypothesisV1) -> CouncilRunCommandV1:
    snapshot = DatasetSnapshotRefV1(
        snapshot_id="snapshot-synthetic",
        version=1,
        content_hash=HASH_A,
        horizon=TimeWindowV1(start_ns=1, end_ns=10_000),
    )
    experiment = ExperimentSpecV1(
        hypothesis_id=hypothesis.hypothesis_id,
        hypothesis_version=hypothesis.version,
        dataset=snapshot,
        signal_refs=hypothesis.signal_refs,
        engine_version="synthetic-engine-v1",
        parameters_json='{"window":20}',
        seed=hypothesis.seed,
        train_window=TimeWindowV1(start_ns=100, end_ns=200),
        test_window=TimeWindowV1(start_ns=300, end_ns=400),
        idempotency_key="synthetic-experiment-key",
    )
    return CouncilRunCommandV1(
        idempotency_key="synthetic-command-key",
        actor_id="synthetic-researcher",
        hypothesis=hypothesis,
        snapshot=snapshot,
        experiments=(experiment,),
        seed=hypothesis.seed,
        calendar_id="synthetic-calendar-v1",
        slippage_model_id="synthetic-slippage-v1",
        latency_model_id="synthetic-latency-v1",
        budget=RunBudgetV1(
            max_runs=1,
            min_successful_runs=1,
            max_actions=4,
            max_elapsed_ns=1_000_000,
            max_compute_units=100,
            max_cost_usd=Decimal("10"),
            max_data_gap_retries=1,
        ),
    )


def test_semantic_profile_matches_legacy_hash_for_multiple_hypotheses() -> None:
    hypotheses = (
        make_hypothesis(),
        make_hypothesis(
            strategy_name="second-strategy",
            markets=("SYNTH-C",),
            max_leverage=Decimal("2.50"),
            seed=99,
        ),
        make_hypothesis(
            hypothesis_id="hypothesis-other",
            version=9,
            signal_refs=tuple(reversed(DEFAULT_REFS)),
        ),
    )

    results = tuple(council_state_semantic(item) for item in hypotheses)

    assert all(type(result) is CouncilStateSemanticDigestV1 for result in results)
    assert all(result.profile == "council_state_semantic" for result in results)
    for hypothesis, result in zip(hypotheses, results, strict=True):
        assert result.sha256_hex == _semantic_hash(hypothesis)
        assert len(result.sha256_hex) == 64
        assert result.sha256_hex == result.sha256_hex.lower()


def test_semantic_profile_sorts_signal_refs_and_ignores_identity_and_version() -> None:
    original = make_hypothesis()
    relabeled_and_reordered = make_hypothesis(
        hypothesis_id="hypothesis-renamed",
        version=12,
        signal_refs=tuple(reversed(DEFAULT_REFS)),
    )
    changed_semantics = make_hypothesis(
        hypothesis_id="hypothesis-renamed",
        version=12,
        signal_refs=tuple(reversed(DEFAULT_REFS)),
        strategy_name="semantically-different-strategy",
    )

    original_result = council_state_semantic(original)
    relabeled_result = council_state_semantic(relabeled_and_reordered)
    changed_result = council_state_semantic(changed_semantics)

    assert original_result.sha256_hex == _semantic_hash(original)
    assert relabeled_result.sha256_hex == _semantic_hash(relabeled_and_reordered)
    assert original_result.sha256_hex == relabeled_result.sha256_hex
    assert changed_result.sha256_hex == _semantic_hash(changed_semantics)
    assert changed_result.sha256_hex != original_result.sha256_hex


def test_full_revision_profile_matches_legacy_hash_and_binds_order_identity_version() -> None:
    base = make_hypothesis()
    changed_order = make_hypothesis(signal_refs=tuple(reversed(DEFAULT_REFS)))
    changed_identity = make_hypothesis(hypothesis_id="hypothesis-renamed")
    changed_version = make_hypothesis(version=2)
    commands = tuple(
        make_command(item) for item in (base, changed_order, changed_identity, changed_version)
    )

    results = tuple(hypothesis_full_revision(command) for command in commands)

    assert all(type(result) is HypothesisFullRevisionDigestV1 for result in results)
    assert all(result.profile == "hypothesis_full_revision" for result in results)
    for command, result in zip(commands, results, strict=True):
        assert result.sha256_hex == _revision_hash(command)
        assert len(result.sha256_hex) == 64
        assert result.sha256_hex == result.sha256_hex.lower()
    assert len({result.sha256_hex for result in results}) == len(results)


def test_results_are_stable_and_cross_profile_comparison_is_rejected() -> None:
    hypothesis = make_hypothesis()
    semantic_first = council_state_semantic(hypothesis)
    semantic_second = council_state_semantic(hypothesis)
    full = hypothesis_full_revision(make_command(hypothesis))
    full_second = hypothesis_full_revision(make_command(hypothesis))

    assert semantic_first == semantic_second
    assert semantic_first.sha256_hex == semantic_second.sha256_hex
    assert full == full_second
    assert full.sha256_hex == full_second.sha256_hex
    assert semantic_first.profile != full.profile
    with pytest.raises(TypeError, match=r"^PROFILE_MISMATCH$"):
        _ = semantic_first == full
    with pytest.raises(TypeError, match=r"^PROFILE_MISMATCH$"):
        _ = full == semantic_first


@pytest.mark.parametrize("invalid", [None, "SYNTHETIC_CANARY", 23, object()])
def test_wrong_input_types_fail_with_fixed_content_free_code(invalid: object) -> None:
    with pytest.raises(RevisionHashError) as semantic_error:
        council_state_semantic(invalid)  # type: ignore[arg-type]
    with pytest.raises(RevisionHashError) as full_error:
        hypothesis_full_revision(invalid)  # type: ignore[arg-type]

    for error in (semantic_error.value, full_error.value):
        assert error.code is RevisionHashCode.INVALID_INPUT
        assert str(error) == "INVALID_INPUT"
        assert error.args == ("INVALID_INPUT",)
        assert "SYNTHETIC_CANARY" not in repr(error.args)


@pytest.mark.parametrize(
    "invalid_number",
    [0.125, float("nan"), Decimal("NaN"), Decimal("Infinity"), object()],
)
def test_noncanonical_hypothesis_value_fails_with_fixed_code(
    invalid_number: object,
) -> None:
    hypothesis = make_hypothesis()
    object.__setattr__(hypothesis, "max_leverage", invalid_number)
    command = make_command(make_hypothesis())
    object.__setattr__(command, "hypothesis", hypothesis)

    with pytest.raises(RevisionHashError) as semantic_error:
        council_state_semantic(hypothesis)
    with pytest.raises(RevisionHashError) as full_error:
        hypothesis_full_revision(command)

    assert semantic_error.value.code is RevisionHashCode.INVALID_INPUT
    assert full_error.value.code is RevisionHashCode.INVALID_INPUT
    assert str(semantic_error.value) == str(full_error.value) == "INVALID_INPUT"
