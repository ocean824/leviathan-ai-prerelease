"""Shared, profile-separated adapters for the existing agent revision hashes."""

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
    RevisionHashCode,
    RevisionHashError,
    council_state_semantic,
    hypothesis_full_revision,
)
from leviathan_core.seal import require, verify

HASH = "a" * 64


def hypothesis(
    *,
    hypothesis_id: str = "hypothesis-1",
    version: int = 1,
    signal_refs: tuple[SignalRefV1, ...] | None = None,
) -> HypothesisV1:
    return HypothesisV1(
        hypothesis_id=hypothesis_id,
        version=version,
        strategy_name="synthetic-strategy",
        signal_refs=signal_refs
        or (
            SignalRefV1(signal_id="signal-b", version="2"),
            SignalRefV1(signal_id="signal-a", version="1"),
        ),
        markets=("SYNTH",),
        horizon=TimeWindowV1(start_ns=1, end_ns=1000),
        target_metrics=("sharpe_ratio",),
        max_leverage=Decimal("1.25"),
        max_loss_per_trade=Decimal("0.01"),
        seed_policy="fixed",
        seed=17,
        source_hashes=(HASH,),
    )


def command(value: HypothesisV1 | None = None) -> CouncilRunCommandV1:
    candidate = value or hypothesis(signal_refs=(SignalRefV1(signal_id="close-v1", version="1"),))
    snapshot = DatasetSnapshotRefV1(
        snapshot_id="snapshot-1",
        version=1,
        content_hash=HASH,
        horizon=TimeWindowV1(start_ns=1, end_ns=1000),
    )
    experiment = ExperimentSpecV1(
        hypothesis_id=candidate.hypothesis_id,
        hypothesis_version=candidate.version,
        dataset=snapshot,
        signal_refs=candidate.signal_refs,
        engine_version="engine-v1",
        parameters_json='{"window":20}',
        seed=17,
        train_window=TimeWindowV1(start_ns=100, end_ns=200),
        test_window=TimeWindowV1(start_ns=300, end_ns=400),
        idempotency_key="experiment-key",
    )
    return CouncilRunCommandV1(
        idempotency_key="command-key",
        actor_id="researcher-1",
        hypothesis=candidate,
        snapshot=snapshot,
        experiments=(experiment,),
        seed=17,
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


def test_council_state_profile_matches_private_hash_and_normalization() -> None:
    original = hypothesis()
    renamed_revision = hypothesis(
        hypothesis_id="different-identity",
        version=8,
        signal_refs=tuple(reversed(original.signal_refs)),
    )

    actual = council_state_semantic(original)
    revised = council_state_semantic(renamed_revision)

    assert actual.profile == "council_state_semantic"
    assert actual.sha256_hex == _semantic_hash(original)
    assert revised.sha256_hex == _semantic_hash(renamed_revision)
    assert actual.sha256_hex == revised.sha256_hex
    assert council_state_semantic(original) == actual
    assert verify(actual, "agent.revision_hash.semantic.v1")
    require(actual, "agent.revision_hash.semantic.v1")


def test_full_revision_profile_matches_private_hash_and_binds_identity_version() -> None:
    original = command()
    changed_revision = command(
        hypothesis(
            hypothesis_id="different-identity",
            version=2,
            signal_refs=(SignalRefV1(signal_id="close-v1", version="1"),),
        )
    )

    actual = hypothesis_full_revision(original)
    revised = hypothesis_full_revision(changed_revision)

    assert actual.profile == "hypothesis_full_revision"
    assert actual.sha256_hex == _revision_hash(original)
    assert revised.sha256_hex == _revision_hash(changed_revision)
    assert actual.sha256_hex != revised.sha256_hex
    assert hypothesis_full_revision(original) == actual
    assert verify(actual, "agent.revision_hash.full.v1")
    require(actual, "agent.revision_hash.full.v1")


def test_profile_typed_results_reject_cross_profile_comparison() -> None:
    semantic = council_state_semantic(hypothesis())
    full = hypothesis_full_revision(command())

    with pytest.raises(TypeError, match=r"^PROFILE_MISMATCH$"):
        _ = semantic == full
    with pytest.raises(TypeError, match=r"^PROFILE_MISMATCH$"):
        _ = full == semantic


@pytest.mark.parametrize("value", [None, "SYNTHETIC_INPUT_CANARY", 17])
def test_wrong_input_has_fixed_content_free_error(value: object) -> None:
    with pytest.raises(RevisionHashError) as caught:
        council_state_semantic(value)  # type: ignore[arg-type]

    assert caught.value.code is RevisionHashCode.INVALID_INPUT
    assert str(caught.value) == "INVALID_INPUT"
    assert "SYNTHETIC_INPUT_CANARY" not in str(caught.value)
    with pytest.raises(RevisionHashError) as caught_command:
        hypothesis_full_revision(value)  # type: ignore[arg-type]
    assert caught_command.value.code is RevisionHashCode.INVALID_INPUT
    assert str(caught_command.value) == "INVALID_INPUT"
