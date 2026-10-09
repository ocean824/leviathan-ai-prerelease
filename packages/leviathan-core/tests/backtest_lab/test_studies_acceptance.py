"""Independent BT-005 acceptance tests from the sweep and Monte Carlo contract."""

from __future__ import annotations

import json
import math
import os
import subprocess
import sys
from dataclasses import FrozenInstanceError, replace
from decimal import Decimal, localcontext
from pathlib import Path

import pytest

from leviathan_core.backtest_lab.events import (
    CoverageReportV1,
    DatasetManifestV1,
    SessionWindowV1,
    StreamSpecV1,
    UniverseMemberV1,
)
from leviathan_core.backtest_lab.fold_metrics import MetricValueV1
from leviathan_core.backtest_lab.monte_carlo import (
    DEFAULT_REPETITIONS,
    MAX_REPETITIONS,
    MAX_TOTAL_PATH_POINTS,
    CompletedRunV1,
    DegeneratePathSpaceError,
    MonteCarloBudgetError,
    MonteCarloSpecError,
    MonteCarloSpecV1,
    ReturnObservationV1,
    RunHistoryInsufficientError,
    RunIntegrityError,
    completed_run_sha256,
    transform_paths,
)
from leviathan_core.backtest_lab.sweeps import (
    MAX_DOMAIN_CONFIGURATIONS,
    MAX_TRIALS,
    InequalityV1,
    ParameterDomainV1,
    ParameterVectorV1,
    PinnedProposalManifestV1,
    ProposalManifestError,
    SweepBudgetError,
    SweepSpecError,
    SweepSpecV1,
    TrialFoldMetricsV1,
    TrialManifestV1,
    TrialOutcomeError,
    TrialOutcomeV1,
    build_leaderboard,
    enumerate_trials,
    pinned_proposal_sha256,
    trial_outcome_sha256,
)
from leviathan_core.backtest_lab.walkforward import (
    DatasetCoverageV1,
    WalkForwardSpecV1,
    split,
)

FIXTURES = Path(__file__).parent / "fixtures" / "studies"
REPO_ROOT = Path(__file__).resolve().parents[4]
CHECKSUM_A = "a" * 64


def _fold_manifest():
    session = SessionWindowV1("XNYS", "1970-01-01", 0, 1000)
    dataset = DatasetManifestV1(
        dataset_id="bt005-synthetic",
        dataset_version="v1",
        universe_version="universe-v1",
        symbol_mapping_version="symbols-v1",
        calendar_id="synthetic-calendar",
        calendar_version="v1",
        adjustment_version="raw-v1",
        as_of_ns=1000,
        start_ns=0,
        end_ns=1000,
        source_checksums=(("synthetic-feed", CHECKSUM_A),),
        universe=(UniverseMemberV1("SYNTH", "XNYS", 0),),
        sessions=(session,),
        streams=(StreamSpecV1("synthetic-stream", "synthetic-feed", "XNYS", 0),),
        max_identity_cache=16,
    )
    report = CoverageReportV1(
        observed_gaps=(),
        skipped_unavailable=0,
        covered_sessions=((session.venue, session.session_date),),
        uncovered_sessions=(),
        complete=True,
    )
    coverage = DatasetCoverageV1(dataset, report)
    spec = WalkForwardSpecV1(
        scheme="fixed",
        is_length_ns=200,
        oos_length_ns=100,
        step_ns=100,
        embargo_ns=0,
    )
    return split(spec, coverage)


def _grid_spec(
    parameters: tuple[ParameterDomainV1, ...],
    *,
    mode: str = "grid",
    inequalities: tuple[InequalityV1, ...] = (),
    max_trials: int = 20,
    seed: int = 17,
    proposals: PinnedProposalManifestV1 | None = None,
) -> SweepSpecV1:
    return SweepSpecV1(
        study_id="acceptance-study",
        study_version="v1",
        mode=mode,
        parameters=parameters,
        inequalities=inequalities,
        max_trials=max_trials,
        seed=seed,
        objective="net_return",
        direction="maximize",
        pinned_proposals=proposals,
    )


def _run_fixture() -> tuple[CompletedRunV1, dict[str, object]]:
    payload = json.loads((FIXTURES / "monte_carlo_returns.json").read_text(encoding="utf-8"))
    observations = tuple(
        ReturnObservationV1(
            item["index"],
            Decimal(item["return_value"]),
            item["order_arrival_ns"],
        )
        for item in payload["observations"]
    )
    source_run_id = payload["source_run_id"]
    source_result_sha256 = payload["bt003_result_sha256"]
    run = CompletedRunV1(
        source_run_id,
        source_result_sha256,
        observations,
        completed_run_sha256(source_run_id, source_result_sha256, observations),
    )
    return run, payload


def _outcome(
    manifest: TrialManifestV1,
    trial_id: str,
    status: str,
    fold_metrics: tuple[TrialFoldMetricsV1, ...] = (),
    *,
    trial_manifest_sha256: str | None = None,
    fold_manifest_sha256: str | None = None,
):
    bound_trial_manifest = trial_manifest_sha256 or manifest.manifest_sha256
    bound_fold_manifest = fold_manifest_sha256 or manifest.fold_manifest_sha256
    checksum = trial_outcome_sha256(
        bound_trial_manifest,
        bound_fold_manifest,
        trial_id,
        status,
        fold_metrics,  # type: ignore[arg-type]
    )
    return TrialOutcomeV1(
        bound_trial_manifest,
        bound_fold_manifest,
        trial_id,
        status,
        fold_metrics,
        checksum,
    )  # type: ignore[arg-type]


def _mc_spec(transform: str, **kwargs: object) -> MonteCarloSpecV1:
    kwargs.setdefault("min_observations", 2)
    return MonteCarloSpecV1(transform, **kwargs)  # type: ignore[arg-type]


def test_grid_sweep_enumerates_only_exactly_feasible_bounded_configs() -> None:
    fixture = json.loads((FIXTURES / "sweep_acceptance.json").read_text(encoding="utf-8"))
    grid = fixture["grid"]
    parameters = (
        ParameterDomainV1("fast", "integer", min(grid["fast_values"]), max(grid["fast_values"]), 1),
        ParameterDomainV1("slow", "integer", min(grid["slow_values"]), max(grid["slow_values"]), 1),
    )
    spec = _grid_spec(parameters, inequalities=(InequalityV1("fast", "lt", "slow"),))

    manifest = enumerate_trials(spec, _fold_manifest())
    actual = {
        (dict(trial.parameters.values)["fast"], dict(trial.parameters.values)["slow"])
        for trial in manifest.trials
    }
    expected = {tuple(pair) for pair in grid["expected_feasible"]}

    assert actual == expected
    assert len({trial.trial_id for trial in manifest.trials}) == len(expected)
    assert all(
        trial.fold_ids == tuple(fold.fold_id for fold in _fold_manifest().folds)
        for trial in manifest.trials
    )
    assert (manifest.effective_trials, manifest.distinct_configurations) == (6, 6)
    assert manifest.effective_trials < len(grid["fast_values"]) * len(grid["slow_values"])
    assert manifest.monte_carlo_paths == 0
    assert manifest.rng_algorithm == "none"
    assert manifest.require_integrity() is manifest
    assert enumerate_trials(spec, _fold_manifest()).canonical_bytes() == manifest.canonical_bytes()

    decimal_manifest = enumerate_trials(
        _grid_spec(
            (ParameterDomainV1("step", "decimal", Decimal("0.1"), Decimal("0.3"), Decimal("0.1")),)
        ),
        _fold_manifest(),
    )
    assert [trial.parameters.values[0][1] for trial in decimal_manifest.trials] == [
        Decimal("0.1"),
        Decimal("0.2"),
        Decimal("0.3"),
    ]


def test_sweep_budget_rejects_grid_overflow_and_bounds_random_trials() -> None:
    assert MAX_TRIALS == 500
    assert MAX_DOMAIN_CONFIGURATIONS == 50_000
    domain = (ParameterDomainV1("period", "integer", 1, 8, 1),)
    too_small = _grid_spec(domain, max_trials=7)
    with pytest.raises(SweepBudgetError) as grid_error:
        enumerate_trials(too_small, _fold_manifest())
    assert grid_error.value.code == "SWEEP_BUDGET_EXCEEDED"

    random_spec = _grid_spec(domain, mode="random", max_trials=3, seed=91)
    first = enumerate_trials(random_spec, _fold_manifest())
    second = enumerate_trials(random_spec, _fold_manifest())
    assert len(first.trials) == 3
    assert len({trial.trial_id for trial in first.trials}) == 3
    assert first.canonical_bytes() == second.canonical_bytes()
    assert first.effective_trials == 3
    assert first.distinct_configurations == 3
    assert first.rng_algorithm == "python.random.MT19937/v1"

    with pytest.raises(SweepBudgetError) as cap_error:
        replace(random_spec, max_trials=MAX_TRIALS + 1)
    assert cap_error.value.code == "SWEEP_BUDGET_EXCEEDED"

    at_domain_bound = ParameterDomainV1("wide", "integer", 1, MAX_DOMAIN_CONFIGURATIONS, 1)
    assert len(at_domain_bound.values) == MAX_DOMAIN_CONFIGURATIONS
    with pytest.raises(SweepBudgetError):
        ParameterDomainV1("too_wide", "integer", 1, MAX_DOMAIN_CONFIGURATIONS + 1, 1)


def test_bayesian_sweep_requires_pinned_deterministic_in_bounds_proposals() -> None:
    risk = ParameterDomainV1("risk", "decimal", Decimal("0.1"), Decimal("0.3"), Decimal("0.1"))
    valid = ParameterVectorV1((("risk", Decimal("0.2")),))
    proposals = (valid, valid, valid, valid)
    pinned = PinnedProposalManifestV1(
        "fixture-router",
        "v1",
        True,
        proposals,
        pinned_proposal_sha256("fixture-router", "v1", proposals),
    )
    manifest = enumerate_trials(
        _grid_spec((risk,), mode="bayesian", max_trials=4, seed=44, proposals=pinned),
        _fold_manifest(),
    )
    assert [trial.parameters.values for trial in manifest.trials] == [valid.values] * 4
    assert manifest.effective_trials == 4
    assert manifest.distinct_configurations == 1

    with pytest.raises(ProposalManifestError) as nondeterministic:
        PinnedProposalManifestV1(
            "fixture-router",
            "v1",
            False,
            proposals,
            pinned_proposal_sha256("fixture-router", "v1", proposals),
        )
    assert nondeterministic.value.code == "BAYESIAN_PROPOSAL_INVALID"

    out_of_bounds = ParameterVectorV1((("risk", Decimal("0.4")),))
    invalid_proposals = (out_of_bounds,)
    invalid_pinned = PinnedProposalManifestV1(
        "fixture-router",
        "v1",
        True,
        invalid_proposals,
        pinned_proposal_sha256("fixture-router", "v1", invalid_proposals),
    )
    invalid_spec = _grid_spec((risk,), mode="bayesian", proposals=invalid_pinned)
    with pytest.raises(ProposalManifestError) as rejected:
        enumerate_trials(invalid_spec, _fold_manifest())
    assert rejected.value.code == "BAYESIAN_PROPOSAL_INVALID"


def test_bayesian_large_domain_and_max_proposals_remain_bounded() -> None:
    domain = ParameterDomainV1("period", "integer", 1, MAX_DOMAIN_CONFIGURATIONS, 1)
    proposals = tuple(
        ParameterVectorV1((("period", candidate),)) for candidate in range(1, MAX_TRIALS + 1)
    )
    pinned = PinnedProposalManifestV1(
        "fixture-router",
        "v1",
        True,
        proposals,
        pinned_proposal_sha256("fixture-router", "v1", proposals),
    )
    manifest = enumerate_trials(
        _grid_spec(
            (domain,),
            mode="bayesian",
            max_trials=MAX_TRIALS,
            seed=404,
            proposals=pinned,
        ),
        _fold_manifest(),
    )
    assert len(manifest.trials) == MAX_TRIALS
    assert manifest.effective_trials == MAX_TRIALS
    assert manifest.distinct_configurations == MAX_TRIALS
    assert [trial.parameters.values[0][1] for trial in manifest.trials] == list(
        range(1, MAX_TRIALS + 1)
    )


def test_distinct_configurations_preserve_scalar_types() -> None:
    values = (1, True, Decimal(1))
    parameter_vectors = tuple(ParameterVectorV1((("value", value),)) for value in values)
    pinned = PinnedProposalManifestV1(
        "fixture-router",
        "v1",
        True,
        parameter_vectors,
        pinned_proposal_sha256("fixture-router", "v1", parameter_vectors),
    )
    domain = ParameterDomainV1("value", "choice", choices=values)
    manifest = enumerate_trials(
        _grid_spec(
            (domain,),
            mode="bayesian",
            max_trials=len(values),
            proposals=pinned,
        ),
        _fold_manifest(),
    )
    assert manifest.effective_trials == 3
    assert manifest.distinct_configurations == 3
    assert {type(trial.parameters.values[0][1]) for trial in manifest.trials} == {
        int,
        bool,
        Decimal,
    }


def test_effective_and_distinct_counts_include_instantiated_failed_and_stopped_trials() -> None:
    fixture = json.loads((FIXTURES / "sweep_acceptance.json").read_text(encoding="utf-8"))
    risk = ParameterVectorV1((("risk", Decimal(fixture["duplicate_bayesian_proposals"]["risk"])),))
    proposals = (risk,) * fixture["duplicate_bayesian_proposals"]["count"]
    pinned = PinnedProposalManifestV1(
        "fixture-router",
        "v1",
        True,
        proposals,
        pinned_proposal_sha256("fixture-router", "v1", proposals),
    )
    spec = _grid_spec(
        (ParameterDomainV1("risk", "decimal", Decimal("0.1"), Decimal("0.3"), Decimal("0.1")),),
        mode="bayesian",
        max_trials=4,
        seed=77,
        proposals=pinned,
    )
    manifest = enumerate_trials(spec, _fold_manifest())
    assert (manifest.effective_trials, manifest.distinct_configurations) == (4, 1)
    assert manifest.monte_carlo_paths == 0
    assert manifest.rng_algorithm == "none"
    assert manifest.manifest_sha256 in manifest.canonical_bytes().decode("utf-8")
    assert manifest.tie_break == "trial_id_asc"

    fold_id = manifest.trials[0].fold_ids[0]
    completed_metrics = (
        TrialFoldMetricsV1(
            fold_id,
            (MetricValueV1("net_return", Decimal("0.25")),),
            (MetricValueV1("net_return", Decimal("-12.5")),),
        ),
    )
    statuses = fixture["duplicate_bayesian_proposals"]["statuses"]
    outcomes = tuple(
        _outcome(
            manifest,
            trial.trial_id,
            status,
            completed_metrics if status == "COMPLETED" else (),
        )
        for trial, status in zip(manifest.trials, statuses, strict=True)
        if status != "PENDING"
    )
    leaderboard = build_leaderboard(manifest, outcomes, fold_id, "net_return")
    entries = {item.trial_id: item for item in leaderboard}
    assert [entries[trial.trial_id].status for trial in manifest.trials] == statuses
    completed = entries[manifest.trials[2].trial_id]
    assert (completed.train_value, completed.oos_value, completed.rank) == (
        Decimal("0.25"),
        Decimal("-12.5"),
        1,
    )

    rejected = ParameterVectorV1((("risk", Decimal("0.4")),))
    rejected_proposals = (rejected,)
    rejected_manifest = PinnedProposalManifestV1(
        "fixture-router",
        "v1",
        True,
        rejected_proposals,
        pinned_proposal_sha256("fixture-router", "v1", rejected_proposals),
    )
    with pytest.raises(ProposalManifestError):
        enumerate_trials(
            _grid_spec(spec.parameters, mode="bayesian", proposals=rejected_manifest),
            _fold_manifest(),
        )
    assert manifest.effective_trials == 4

    other_seed = enumerate_trials(replace(spec, seed=78), _fold_manifest())
    assert (other_seed.effective_trials, other_seed.distinct_configurations) == (4, 1)
    assert {trial.trial_id for trial in other_seed.trials}.isdisjoint(
        trial.trial_id for trial in manifest.trials
    )

    with pytest.raises(FrozenInstanceError):
        manifest.effective_trials = 99  # type: ignore[misc]
    with pytest.raises(SweepSpecError):
        replace(manifest, effective_trials=99)


def test_leaderboard_ranks_only_completed_same_fold_in_sample_metric() -> None:
    domain = (ParameterDomainV1("period", "integer", 1, 4, 1),)
    manifest = enumerate_trials(_grid_spec(domain, max_trials=4), _fold_manifest())
    fold_id = manifest.trials[0].fold_ids[0]
    outcomes = (
        _outcome(
            manifest,
            manifest.trials[0].trial_id,
            "COMPLETED",
            (
                TrialFoldMetricsV1(
                    fold_id,
                    (MetricValueV1("net_return", Decimal("0.50")),),
                    (MetricValueV1("net_return", Decimal("99")),),
                ),
            ),
        ),
        _outcome(
            manifest,
            manifest.trials[1].trial_id,
            "COMPLETED",
            (
                TrialFoldMetricsV1(
                    fold_id,
                    (MetricValueV1("net_return", Decimal("0.75")),),
                    (MetricValueV1("net_return", Decimal("-99")),),
                ),
            ),
        ),
        _outcome(
            manifest,
            manifest.trials[2].trial_id,
            "COMPLETED",
            (
                TrialFoldMetricsV1(
                    fold_id,
                    (MetricValueV1("net_return", Decimal("0.75")),),
                    (MetricValueV1("net_return", Decimal("500")),),
                ),
            ),
        ),
    )

    board = build_leaderboard(manifest, outcomes, fold_id, "net_return")
    ranked = [item for item in board if item.rank is not None]
    assert [item.rank for item in ranked] == [1, 2, 3]
    assert [item.trial_id for item in ranked[:2]] == sorted(
        (manifest.trials[1].trial_id, manifest.trials[2].trial_id)
    )
    assert [item.train_value for item in ranked[:2]] == [Decimal("0.75")] * 2
    assert sum(item.status == "PENDING" for item in board) == 1
    assert ranked[2].trial_id == manifest.trials[0].trial_id
    assert ranked[2].oos_value == Decimal("99")
    with pytest.raises(TrialOutcomeError) as wrong_metric:
        build_leaderboard(manifest, outcomes, fold_id, "other_metric")
    assert wrong_metric.value.code == "TRIAL_OUTCOME_INVALID"
    with pytest.raises(TrialOutcomeError):
        replace(outcomes[0], result_sha256="f" * 64)


def test_leaderboard_rejects_outcomes_bound_to_foreign_trial_or_fold_manifest() -> None:
    manifest = enumerate_trials(
        _grid_spec((ParameterDomainV1("period", "integer", 1, 2, 1),), max_trials=2),
        _fold_manifest(),
    )
    trial = manifest.trials[0]
    fold_id = trial.fold_ids[0]
    metrics = (
        TrialFoldMetricsV1(
            fold_id,
            (MetricValueV1("net_return", Decimal("0.5")),),
            (MetricValueV1("net_return", Decimal("0.5")),),
        ),
    )
    foreign_trial = _outcome(
        manifest,
        trial.trial_id,
        "COMPLETED",
        metrics,
        trial_manifest_sha256="e" * 64,
    )
    with pytest.raises(TrialOutcomeError) as trial_binding:
        build_leaderboard(manifest, (foreign_trial,), fold_id, "net_return")
    assert trial_binding.value.code == "TRIAL_OUTCOME_INVALID"

    foreign_fold = _outcome(
        manifest,
        trial.trial_id,
        "COMPLETED",
        metrics,
        fold_manifest_sha256="d" * 64,
    )
    with pytest.raises(TrialOutcomeError) as fold_binding:
        build_leaderboard(manifest, (foreign_fold,), fold_id, "net_return")
    assert fold_binding.value.code == "TRIAL_OUTCOME_INVALID"


def test_leaderboard_honors_minimize_and_declared_trial_id_tie_break() -> None:
    manifest = enumerate_trials(
        replace(
            _grid_spec((ParameterDomainV1("period", "integer", 1, 3, 1),), max_trials=3),
            direction="minimize",
        ),
        _fold_manifest(),
    )
    fold_id = manifest.trials[0].fold_ids[0]
    outcomes = tuple(
        _outcome(
            manifest,
            trial.trial_id,
            "COMPLETED",
            (
                TrialFoldMetricsV1(
                    fold_id,
                    (MetricValueV1("net_return", value),),
                    (MetricValueV1("net_return", Decimal(0)),),
                ),
            ),
        )
        for trial, value in zip(
            manifest.trials,
            (Decimal("0.5"), Decimal("0.25"), Decimal("0.25")),
            strict=True,
        )
    )
    board = build_leaderboard(manifest, outcomes, fold_id, "net_return")
    assert [entry.rank for entry in board] == [1, 2, 3]
    tied_ids = {manifest.trials[1].trial_id, manifest.trials[2].trial_id}
    tied_ranked = [entry.trial_id for entry in board if entry.rank in (1, 2)]
    assert tied_ranked == sorted(tied_ids)


def test_monte_carlo_default_cap_seed_and_cross_process_manifest_are_reproducible() -> None:
    run, fixture = _run_fixture()
    default_spec = _mc_spec("IID_BOOTSTRAP", seed=1234, autocorrelation_policy="IID")
    assert DEFAULT_REPETITIONS == 50
    assert MAX_REPETITIONS == 500
    assert MAX_TOTAL_PATH_POINTS == 100_000
    assert default_spec.repetitions == DEFAULT_REPETITIONS
    default_manifest = transform_paths(default_spec, run)
    assert default_manifest.monte_carlo_paths == 50
    assert len(default_manifest.paths) == 50
    assert default_manifest.min_observations == 2
    assert (
        default_manifest.path_space_bound.kind,
        default_manifest.path_space_bound.observation_count,
        default_manifest.path_space_bound.block_length,
    ) == ("IID_N_POWER_N", len(run.observations), None)

    cap_observations = tuple(ReturnObservationV1(index, Decimal("0.01")) for index in range(10))
    cap_run_id = "bt005-repetition-cap"
    cap_bt003_sha256 = "e" * 64
    cap_run = CompletedRunV1(
        cap_run_id,
        cap_bt003_sha256,
        cap_observations,
        completed_run_sha256(cap_run_id, cap_bt003_sha256, cap_observations),
    )
    capped = transform_paths(
        _mc_spec(
            "IID_BOOTSTRAP",
            seed=1234,
            repetitions=MAX_REPETITIONS,
            autocorrelation_policy="IID",
        ),
        cap_run,
    )
    assert capped.monte_carlo_paths == MAX_REPETITIONS
    with pytest.raises(MonteCarloBudgetError) as over_cap:
        _mc_spec(
            "IID_BOOTSTRAP",
            seed=1234,
            repetitions=MAX_REPETITIONS + 1,
            autocorrelation_policy="IID",
        )
    assert over_cap.value.code == "MONTE_CARLO_BUDGET_EXCEEDED"

    script = """
import json, sys
from decimal import Decimal
from leviathan_core.backtest_lab.monte_carlo import (
    CompletedRunV1, MonteCarloSpecV1, ReturnObservationV1,
    completed_run_sha256, transform_paths,
)
payload = json.loads(sys.argv[1])
observations = tuple(ReturnObservationV1(
    item["index"], Decimal(item["return_value"]), item["order_arrival_ns"]
) for item in payload["observations"])
source_run_id = payload["source_run_id"]
bt003_result_sha256 = payload["bt003_result_sha256"]
run = CompletedRunV1(
    source_run_id, bt003_result_sha256, observations,
    completed_run_sha256(source_run_id, bt003_result_sha256, observations),
)
manifest = transform_paths(MonteCarloSpecV1(
    "IID_BOOTSTRAP", seed=1234, min_observations=2, repetitions=7,
    autocorrelation_policy="IID"
), run)
print(manifest.canonical_bytes().hex())
"""
    environment = os.environ.copy()
    source_path = str(REPO_ROOT / "packages" / "leviathan-core" / "src")
    current_pythonpath = environment.get("PYTHONPATH", "")
    environment["PYTHONPATH"] = os.pathsep.join(
        item for item in (source_path, current_pythonpath) if item
    )
    payload = json.dumps(fixture, separators=(",", ":"))
    process_outputs = []
    for _ in range(2):
        result = subprocess.run(
            [sys.executable, "-c", script, payload],
            cwd=REPO_ROOT,
            env=environment,
            check=True,
            capture_output=True,
            text=True,
        )
        process_outputs.append(result.stdout.strip())
    parent_manifest = transform_paths(
        _mc_spec("IID_BOOTSTRAP", seed=1234, repetitions=7, autocorrelation_policy="IID"),
        run,
    )
    assert process_outputs == [parent_manifest.canonical_bytes().hex()] * 2
    assert parent_manifest.source_run_id == run.source_run_id
    assert parent_manifest.bt003_result_sha256 == run.bt003_result_sha256
    assert parent_manifest.rng_algorithm == "python.random.MT19937/v1"
    assert parent_manifest.observation_count == len(run.observations)
    assert all(
        path.path_sha256.encode() in parent_manifest.canonical_bytes()
        for path in parent_manifest.paths
    )


def test_monte_carlo_transforms_retain_index_provenance_and_exact_summaries() -> None:
    run, _ = _run_fixture()
    block = transform_paths(
        _mc_spec("BLOCK_BOOTSTRAP", seed=56, repetitions=4, block_length=2), run
    )
    assert block.transform == "BLOCK_BOOTSTRAP"
    assert block.monte_carlo_paths == 4
    assert block.observation_count == len(run.observations)
    assert (
        block.path_space_bound.kind,
        block.path_space_bound.observation_count,
        block.path_space_bound.block_length,
    ) == ("BLOCK_START_SEQUENCES", len(run.observations), 2)
    assert block.source_run_id == run.source_run_id
    assert block.bt003_result_sha256 == run.bt003_result_sha256
    for path in block.paths:
        assert path.transform == "BLOCK_BOOTSTRAP"
        assert path.source_run_sha256 == run.result_sha256
        assert len(path.path_sha256) == 64
        assert len(path.original_indices) == len(run.observations)
        assert all(0 <= index < block.observation_count for index in path.original_indices)
        for offset in (0, 2):
            first, second = path.original_indices[offset : offset + 2]
            assert second == first + 1
    with pytest.raises(MonteCarloSpecError):
        replace(block.paths[0], transform="IID_BOOTSTRAP")
    with pytest.raises(MonteCarloSpecError):
        replace(block, seed=block.seed + 1)

    iid = transform_paths(
        _mc_spec("IID_BOOTSTRAP", seed=56, repetitions=4, autocorrelation_policy="IID"),
        run,
    )
    assert iid.transform == "IID_BOOTSTRAP"
    assert iid.paths != block.paths

    values = tuple(item.return_value for item in run.observations)
    with localcontext() as context:
        context.prec = 50
        for path in iid.paths:
            sampled = tuple(values[index] for index in path.original_indices)
            expected_sum = sum(sampled, Decimal(0))
            expected_mean = expected_sum / Decimal(len(sampled))
            assert path.return_sum == expected_sum
            assert path.return_mean == expected_mean

    arrivals = transform_paths(
        _mc_spec(
            "ORDER_ARRIVAL_PERMUTATION",
            seed=57,
            repetitions=4,
            autocorrelation_policy="ORDER_PERMUTATION",
        ),
        run,
    )
    assert arrivals.transform == "ORDER_ARRIVAL_PERMUTATION"
    assert arrivals.observation_count == len(run.observations)
    assert arrivals.rng_algorithm == "python.random.MT19937/v1"
    assert (
        arrivals.path_space_bound.kind,
        arrivals.path_space_bound.observation_count,
        arrivals.path_space_bound.block_length,
    ) == ("N_FACTORIAL", len(run.observations), None)
    assert all(path.transform == "ORDER_ARRIVAL_PERMUTATION" for path in arrivals.paths)
    for path in arrivals.paths:
        assert sorted(path.original_indices) == list(range(len(run.observations)))
        assert path.transform == arrivals.transform
        assert len(path.path_sha256) == 64

    different_seed = transform_paths(
        _mc_spec("IID_BOOTSTRAP", seed=57, repetitions=4, autocorrelation_policy="IID"),
        run,
    )
    assert tuple(path.path_seed for path in iid.paths) != tuple(
        path.path_seed for path in different_seed.paths
    )
    assert (iid.monte_carlo_paths, different_seed.monte_carlo_paths) == (4, 4)
    assert all(path.path_sha256 for path in (*iid.paths, *different_seed.paths))


def test_monte_carlo_rejects_repetition_counts_above_each_path_space() -> None:
    run, _ = _run_fixture()
    observation_count = len(run.observations)

    iid_space = observation_count**observation_count
    iid_at_bound = transform_paths(
        _mc_spec(
            "IID_BOOTSTRAP",
            seed=71,
            repetitions=iid_space,
            autocorrelation_policy="IID",
        ),
        run,
    )
    assert iid_at_bound.monte_carlo_paths == iid_space
    assert iid_at_bound.path_space_bound.kind == "IID_N_POWER_N"
    assert iid_at_bound.path_space_bound.observation_count == observation_count
    with pytest.raises(DegeneratePathSpaceError) as iid_degenerate:
        transform_paths(
            _mc_spec(
                "IID_BOOTSTRAP",
                seed=71,
                repetitions=iid_space + 1,
                autocorrelation_policy="IID",
            ),
            run,
        )
    assert iid_degenerate.value.code == "DEGENERATE_PATH_SPACE"

    block_length = 2
    block_space = (observation_count - block_length + 1) ** (
        (observation_count + block_length - 1) // block_length
    )
    block_at_bound = transform_paths(
        _mc_spec(
            "BLOCK_BOOTSTRAP",
            seed=72,
            repetitions=block_space,
            block_length=block_length,
        ),
        run,
    )
    assert block_at_bound.monte_carlo_paths == block_space
    assert block_at_bound.path_space_bound.kind == "BLOCK_START_SEQUENCES"
    assert block_at_bound.path_space_bound.block_length == block_length
    with pytest.raises(DegeneratePathSpaceError) as block_degenerate:
        transform_paths(
            _mc_spec(
                "BLOCK_BOOTSTRAP",
                seed=72,
                repetitions=block_space + 1,
                block_length=block_length,
            ),
            run,
        )
    assert block_degenerate.value.code == "DEGENERATE_PATH_SPACE"

    permutation_space = math.factorial(observation_count)
    permutation_at_bound = transform_paths(
        _mc_spec(
            "ORDER_ARRIVAL_PERMUTATION",
            seed=73,
            repetitions=permutation_space,
            autocorrelation_policy="ORDER_PERMUTATION",
        ),
        run,
    )
    assert permutation_at_bound.monte_carlo_paths == permutation_space
    assert permutation_at_bound.path_space_bound.kind == "N_FACTORIAL"
    with pytest.raises(DegeneratePathSpaceError) as permutation_degenerate:
        transform_paths(
            _mc_spec(
                "ORDER_ARRIVAL_PERMUTATION",
                seed=73,
                repetitions=permutation_space + 1,
                autocorrelation_policy="ORDER_PERMUTATION",
            ),
            run,
        )
    assert permutation_degenerate.value.code == "DEGENERATE_PATH_SPACE"


def test_monte_carlo_rejects_insufficient_history_and_unverified_run() -> None:
    run, _ = _run_fixture()
    with pytest.raises(TypeError):
        MonteCarloSpecV1("IID_BOOTSTRAP", seed=1)  # type: ignore[call-arg]

    short_history = _mc_spec(
        "IID_BOOTSTRAP",
        seed=1,
        min_observations=len(run.observations) + 1,
        autocorrelation_policy="IID",
    )
    with pytest.raises(RunHistoryInsufficientError) as minimum_history_error:
        transform_paths(short_history, run)
    assert minimum_history_error.value.code == "INSUFFICIENT_HISTORY"

    too_long = _mc_spec("BLOCK_BOOTSTRAP", seed=1, repetitions=2, block_length=5)
    with pytest.raises(RunHistoryInsufficientError) as history_error:
        transform_paths(too_long, run)
    assert history_error.value.code == "INSUFFICIENT_HISTORY"

    with pytest.raises(RunIntegrityError) as integrity_error:
        replace(run, result_sha256="0" * 64)
    assert integrity_error.value.code == "RUN_INTEGRITY_INVALID"

    with pytest.raises(MonteCarloSpecError):
        _mc_spec("BLOCK_BOOTSTRAP", seed=1, repetitions=1, block_length=1)

    boundary_observations = tuple(
        ReturnObservationV1(index, Decimal("0.01")) for index in range(200)
    )
    boundary_run_id = "bt005-path-budget-boundary"
    source_result_sha256 = "d" * 64
    boundary_run = CompletedRunV1(
        boundary_run_id,
        source_result_sha256,
        boundary_observations,
        completed_run_sha256(boundary_run_id, source_result_sha256, boundary_observations),
    )
    boundary_manifest = transform_paths(
        _mc_spec(
            "IID_BOOTSTRAP",
            seed=1,
            repetitions=MAX_REPETITIONS,
            autocorrelation_policy="IID",
        ),
        boundary_run,
    )
    assert boundary_manifest.monte_carlo_paths * boundary_manifest.observation_count == (
        MAX_TOTAL_PATH_POINTS
    )

    long_run_observations = tuple(
        ReturnObservationV1(index, Decimal("0.01")) for index in range(201)
    )
    long_run_id = "bt005-path-budget"
    source_result_sha256 = "c" * 64
    long_run = CompletedRunV1(
        long_run_id,
        source_result_sha256,
        long_run_observations,
        completed_run_sha256(long_run_id, source_result_sha256, long_run_observations),
    )
    with pytest.raises(MonteCarloBudgetError) as point_budget:
        transform_paths(
            _mc_spec(
                "IID_BOOTSTRAP",
                seed=1,
                repetitions=MAX_REPETITIONS,
                autocorrelation_policy="IID",
            ),
            long_run,
        )
    assert point_budget.value.code == "MONTE_CARLO_BUDGET_EXCEEDED"
