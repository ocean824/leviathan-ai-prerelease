"""Golden compatibility checks for consumers of shared revision profiles."""

from __future__ import annotations

import subprocess
import sys
from decimal import Decimal

from leviathan_core.agent_council.runner_models import CouncilRunCommandV1, RunBudgetV1
from leviathan_core.agent_council.runner_service import _revision_hash
from leviathan_core.agent_council.scribe_service import _hypothesis_revision_hash
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
    hypothesis_full_revision_from_hypothesis,
)

_HASH_A = "a" * 64
_HASH_B = "b" * 64
_SEMANTIC_GOLDEN = "9e6576c701580ae37e2a4c360863d50aa75b64873dd8ad10397e59f327efb7b8"
_FULL_REVISION_GOLDEN = "ffe87461145421dee13c8c57fcc25458b780466700c318bec52961b49a3e6724"


def _hypothesis() -> HypothesisV1:
    return HypothesisV1(
        hypothesis_id="hypothesis-base",
        version=1,
        strategy_name="synthetic-strategy",
        signal_refs=(
            SignalRefV1(signal_id="signal-z", version="2"),
            SignalRefV1(signal_id="signal-a", version="11"),
            SignalRefV1(signal_id="signal-a", version="3"),
        ),
        markets=("SYNTH-A", "SYNTH-B"),
        horizon=TimeWindowV1(start_ns=1, end_ns=10_000),
        target_metrics=("return", "drawdown"),
        max_leverage=Decimal("1.25"),
        max_loss_per_trade=Decimal("0.0125"),
        seed_policy="fixed",
        seed=17,
        source_hashes=(_HASH_A, _HASH_B),
    )


def _command(hypothesis: HypothesisV1) -> CouncilRunCommandV1:
    snapshot = DatasetSnapshotRefV1(
        snapshot_id="snapshot-synthetic",
        version=1,
        content_hash=_HASH_A,
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


def test_state_semantic_consumer_delegates_without_changing_digest_bytes() -> None:
    hypothesis = _hypothesis()

    profile = council_state_semantic(hypothesis)
    consumer = _semantic_hash(hypothesis)

    assert profile.profile == "council_state_semantic"
    assert profile.sha256_hex == _SEMANTIC_GOLDEN
    assert consumer.encode("ascii") == profile.sha256_hex.encode("ascii")
    assert consumer == _SEMANTIC_GOLDEN


def test_runner_revision_consumer_delegates_without_changing_digest_bytes() -> None:
    command = _command(_hypothesis())

    profile = hypothesis_full_revision(command)
    consumer = _revision_hash(command)

    assert profile.profile == "hypothesis_full_revision"
    assert profile.sha256_hex == _FULL_REVISION_GOLDEN
    assert consumer.encode("ascii") == profile.sha256_hex.encode("ascii")
    assert consumer == _FULL_REVISION_GOLDEN


def test_command_and_hypothesis_full_revision_profiles_are_identical() -> None:
    hypothesis = _hypothesis()
    command_profile = hypothesis_full_revision(_command(hypothesis))
    hypothesis_profile = hypothesis_full_revision_from_hypothesis(hypothesis)

    assert type(hypothesis_profile) is type(command_profile)
    assert hypothesis_profile.profile == "hypothesis_full_revision"
    assert hypothesis_profile.sha256_hex == command_profile.sha256_hex
    assert hypothesis_profile.sha256_hex == _FULL_REVISION_GOLDEN
    assert _hypothesis_revision_hash(hypothesis).encode("ascii") == (
        hypothesis_profile.sha256_hex.encode("ascii")
    )


def test_hypothesis_profile_helper_rejects_non_exact_hypothesis() -> None:
    try:
        hypothesis_full_revision_from_hypothesis("synthetic canary")  # type: ignore[arg-type]
    except RevisionHashError as error:
        assert error.code is RevisionHashCode.INVALID_INPUT
        assert str(error) == "INVALID_INPUT"
    else:
        raise AssertionError("non-hypothesis input was accepted")


def test_hash_module_and_council_import_as_first_modules_in_fresh_processes() -> None:
    for module in (
        "leviathan_core.agent_revision_hash",
        "leviathan_core.agent_council",
    ):
        result = subprocess.run(
            [sys.executable, "-c", f"import {module}"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        assert result.returncode == 0, f"fresh import failed for {module}: {result.stderr}"
