"""Independent compatibility acceptance for revision-hash adoption."""

from __future__ import annotations

from decimal import Decimal

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
    council_state_semantic,
    hypothesis_full_revision,
)

HASH_A = "a" * 64
HASH_B = "b" * 64
SEMANTIC_GOLDEN = "9e6576c701580ae37e2a4c360863d50aa75b64873dd8ad10397e59f327efb7b8"
FULL_REVISION_GOLDEN = "ffe87461145421dee13c8c57fcc25458b780466700c318bec52961b49a3e6724"


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
        source_hashes=(HASH_A, HASH_B),
    )


def _command(hypothesis: HypothesisV1) -> CouncilRunCommandV1:
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


def test_council_state_semantic_adoption_preserves_golden_bytes() -> None:
    hypothesis = _hypothesis()

    adopted = council_state_semantic(hypothesis)
    consumer = _semantic_hash(hypothesis)

    assert type(adopted) is CouncilStateSemanticDigestV1
    assert adopted.profile == "council_state_semantic"
    assert adopted.sha256_hex == SEMANTIC_GOLDEN
    assert consumer.encode("ascii") == adopted.sha256_hex.encode("ascii")
    assert consumer == SEMANTIC_GOLDEN


def test_full_revision_adoption_preserves_golden_bytes() -> None:
    command = _command(_hypothesis())

    adopted = hypothesis_full_revision(command)
    consumer = _revision_hash(command)

    assert type(adopted) is HypothesisFullRevisionDigestV1
    assert adopted.profile == "hypothesis_full_revision"
    assert adopted.sha256_hex == FULL_REVISION_GOLDEN
    assert consumer.encode("ascii") == adopted.sha256_hex.encode("ascii")
    assert consumer == FULL_REVISION_GOLDEN
