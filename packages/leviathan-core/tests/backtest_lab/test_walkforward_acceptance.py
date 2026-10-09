"""Independent BT-004 acceptance tests from the walk-forward contract."""

from __future__ import annotations

import json
from dataclasses import fields
from decimal import Decimal
from inspect import Parameter, signature
from pathlib import Path

import pytest

from leviathan_core.backtest_lab.events import (
    CoverageReportV1,
    DatasetManifestV1,
    SessionWindowV1,
    StreamSpecV1,
    UniverseMemberV1,
)
from leviathan_core.backtest_lab.fold_metrics import (
    CompletedFoldMetricsV1,
    IncompleteFoldAggregationError,
    MetricValueV1,
    aggregate_oos,
)
from leviathan_core.backtest_lab.walkforward import (
    MAX_FEATURE_ROWS,
    MAX_FOLDS,
    CalendarInvalidError,
    CoverageInsufficientError,
    DatasetCoverageError,
    DatasetCoverageV1,
    EmptyFoldError,
    FeatureUnavailableError,
    FoldOverlapError,
    InputTooLargeError,
    OOSSelectionAccessError,
    WalkForwardSpecV1,
    select_parameters,
    split,
    training_view,
)
from leviathan_core.feature_store.models import FeatureLineageV1, FeatureResultV1

FIXTURES = Path(__file__).parent / "fixtures" / "walkforward"
CHECKSUM_A = "a" * 64
CHECKSUM_B = "b" * 64


def _sessions(start_ns: int, end_ns: int) -> tuple[SessionWindowV1, ...]:
    return (SessionWindowV1("XNYS", "1970-01-01", start_ns, end_ns),)


def _coverage(
    *,
    start_ns: int = 0,
    end_ns: int = 1000,
    sessions: tuple[SessionWindowV1, ...] | None = None,
    covered_sessions: tuple[tuple[str, str], ...] | None = None,
    uncovered_sessions: tuple[tuple[str, str], ...] = (),
    feature_rows: tuple[FeatureResultV1, ...] = (),
    dataset_version: str = "dataset-v1",
) -> DatasetCoverageV1:
    declared_sessions = sessions or _sessions(start_ns, end_ns)
    keys = tuple((session.venue, session.session_date) for session in declared_sessions)
    covered = keys if covered_sessions is None else covered_sessions
    manifest = DatasetManifestV1(
        dataset_id="synthetic-walk-forward",
        dataset_version=dataset_version,
        universe_version="universe-v1",
        symbol_mapping_version="symbol-map-v1",
        calendar_id="synthetic-calendar",
        calendar_version="calendar-v1",
        adjustment_version="raw-v1",
        as_of_ns=end_ns,
        start_ns=start_ns,
        end_ns=end_ns,
        source_checksums=(("synthetic-feed", CHECKSUM_A),),
        universe=(UniverseMemberV1("SYNTH", "XNYS", start_ns),),
        sessions=declared_sessions,
        streams=(StreamSpecV1("synthetic-stream", "synthetic-feed", "XNYS", 0),),
        max_identity_cache=16,
    )
    report = CoverageReportV1(
        observed_gaps=(),
        skipped_unavailable=0,
        covered_sessions=covered,
        uncovered_sessions=uncovered_sessions,
        complete=not uncovered_sessions,
    )
    return DatasetCoverageV1(manifest, report, feature_rows)


def _feature(
    asof_ns: int,
    *,
    event_ns: int | None = None,
    availability_ns: int | None = None,
    feature_name: str = "close",
    value: str = "1.25",
    source_key: str | None = None,
) -> FeatureResultV1:
    event = asof_ns if event_ns is None else event_ns
    available = asof_ns if availability_ns is None else availability_ns
    record_key = source_key or f"row-{asof_ns}"
    return FeatureResultV1(
        found=True,
        feature_name=feature_name,
        feature_version="v1",
        instrument_id="SYNTH",
        asof_ns=asof_ns,
        value_decimal=Decimal(value),
        source_dataset="synthetic-feature-source",
        source_record_key=record_key,
        event_time_ns=event,
        availability_ns=available,
        source_keys=(record_key,),
        definition_hash=CHECKSUM_A,
        observation_hash=CHECKSUM_B,
        lineage=FeatureLineageV1(
            definition_sha256=CHECKSUM_A,
            observation_sha256=CHECKSUM_B,
            source_dataset="synthetic-feature-source",
            source_record_key=record_key,
        ),
    )


def _spec(
    scheme: str = "rolling",
    *,
    is_length_ns: int = 200,
    oos_length_ns: int = 100,
    step_ns: int = 200,
    embargo_ns: int = 10,
    min_oos_fraction: Decimal = Decimal("1"),
    warm_start_policy: str = "reset",
    anchor_ns: int | None = None,
) -> WalkForwardSpecV1:
    return WalkForwardSpecV1(
        scheme=scheme,  # type: ignore[arg-type]
        is_length_ns=is_length_ns,
        oos_length_ns=oos_length_ns,
        step_ns=step_ns,
        embargo_ns=embargo_ns,
        warm_start_policy=warm_start_policy,  # type: ignore[arg-type]
        min_oos_fraction=min_oos_fraction,
        feature_allowlist=(("close", "v1"),),
        anchor_ns=anchor_ns,
    )


@pytest.mark.parametrize("scheme", ["fixed", "rolling", "expanding", "anchored"])
def test_all_declared_schemes_emit_utc_half_open_disjoint_oos_folds(scheme: str) -> None:
    coverage = _coverage()
    anchor = 90 if scheme == "anchored" else None
    manifest = split(_spec(scheme, anchor_ns=anchor), coverage)

    assert manifest.folds
    assert len({fold.fold_id for fold in manifest.folds}) == len(manifest.folds)
    starts = [fold.is_start_ns for fold in manifest.folds]
    ends = [fold.is_end_ns for fold in manifest.folds]
    if scheme == "fixed":
        assert starts == [0]
        assert ends == [200]
    elif scheme == "rolling":
        assert starts == [0, 200, 400, 600]
        assert ends == [200, 400, 600, 800]
    elif scheme == "expanding":
        assert starts == [0, 0, 0, 0]
        assert ends == [200, 400, 600, 800]
    else:
        assert starts == [90, 90, 90, 90]
        assert ends == [290, 490, 690, 890]
        dropped = manifest.dropped_folds
        assert len(dropped) == 1
        assert (
            dropped[0].index,
            dropped[0].is_start_ns,
            dropped[0].is_end_ns,
            dropped[0].oos_start_ns,
            dropped[0].oos_end_ns,
            dropped[0].reason,
        ) == (5, 90, 1090, 1000, 1000, "PARTIAL_TAIL")
    for index, fold in enumerate(manifest.folds):
        assert fold.is_start_ns < fold.is_end_ns
        assert fold.oos_start_ns < fold.oos_end_ns
        assert fold.is_end_ns + fold.embargo_ns <= fold.oos_start_ns
        assert fold.warm_start_policy == "reset"
        assert fold.feature_allowlist == (("close", "v1"),)
        # Cycle-1 ruling: starts use [open, close); exclusive ends use (open, close].
        for boundary in (
            fold.is_start_ns,
            fold.oos_start_ns,
        ):
            assert any(
                session.open_ns <= boundary < session.close_ns
                for session in coverage.dataset_manifest.sessions
            )
        for boundary in (
            fold.is_end_ns,
            fold.oos_end_ns,
        ):
            assert any(
                session.open_ns < boundary <= session.close_ns
                for session in coverage.dataset_manifest.sessions
            )
        if index:
            assert manifest.folds[index - 1].oos_end_ns <= fold.oos_start_ns


def test_fixed_fold_preserves_embargo_and_half_open_boundaries() -> None:
    manifest = split(_spec("fixed"), _coverage())

    assert len(manifest.folds) == 1
    fold = manifest.folds[0]
    assert (fold.is_start_ns, fold.is_end_ns) == (0, 200)
    assert (fold.oos_start_ns, fold.oos_end_ns) == (210, 310)
    assert fold.is_end_ns + 10 == fold.oos_start_ns
    assert fold.is_coverage == (200, 200)
    assert fold.oos_coverage == (100, 100)


def test_embargo_must_be_explicitly_supplied() -> None:
    assert signature(WalkForwardSpecV1).parameters["embargo_ns"].default is Parameter.empty
    with pytest.raises(TypeError):
        WalkForwardSpecV1(scheme="fixed", is_length_ns=1, oos_length_ns=1, step_ns=1)


def test_feature_rows_at_declared_maximum_are_accepted() -> None:
    rows = tuple(_feature(index) for index in range(MAX_FEATURE_ROWS))
    coverage = _coverage(end_ns=MAX_FEATURE_ROWS + 1, feature_rows=rows)

    manifest = split(
        _spec("fixed", is_length_ns=1, oos_length_ns=1, step_ns=1, embargo_ns=0),
        coverage,
    )

    assert len(coverage.feature_rows) == MAX_FEATURE_ROWS
    assert len(manifest.folds) == 1


def test_feature_rows_over_declared_maximum_fail_with_content_free_error() -> None:
    rows = tuple(_feature(index) for index in range(MAX_FEATURE_ROWS + 1))

    with pytest.raises(InputTooLargeError) as caught:
        _coverage(end_ns=MAX_FEATURE_ROWS + 2, feature_rows=rows)

    assert caught.value.code == "INPUT_TOO_LARGE"
    assert str(caught.value) == "INPUT_TOO_LARGE"


def test_maximum_complete_fold_count_accepts_clipped_terminal_tail() -> None:
    coverage = _coverage(end_ns=MAX_FOLDS + 1)
    spec = _spec(
        "rolling",
        is_length_ns=1,
        oos_length_ns=1,
        step_ns=1,
        embargo_ns=0,
    )

    manifest = split(spec, coverage)

    assert len(manifest.folds) == MAX_FOLDS
    assert len(manifest.dropped_folds) == 1
    tail = manifest.dropped_folds[0]
    assert tail.index == MAX_FOLDS + 1
    assert tail.reason == "PARTIAL_TAIL"
    assert tail.oos_start_ns == coverage.dataset_manifest.end_ns
    assert tail.oos_end_ns == coverage.dataset_manifest.end_ns
    assert tail.oos_start_ns <= tail.oos_end_ns


def test_complete_fold_candidate_over_declared_maximum_is_rejected() -> None:
    coverage = _coverage(end_ns=MAX_FOLDS + 2)
    spec = _spec(
        "rolling",
        is_length_ns=1,
        oos_length_ns=1,
        step_ns=1,
        embargo_ns=0,
    )

    with pytest.raises(InputTooLargeError) as caught:
        split(spec, coverage)

    assert caught.value.code == "INPUT_TOO_LARGE"
    assert str(caught.value) == "INPUT_TOO_LARGE"


def test_session_open_start_and_session_close_end_are_valid_boundaries() -> None:
    sessions = (
        SessionWindowV1("XNYS", "1970-01-01", 0, 200),
        SessionWindowV1("XNYS", "1970-01-02", 210, 310),
    )
    coverage = _coverage(start_ns=0, end_ns=310, sessions=sessions)

    manifest = split(
        _spec("fixed", is_length_ns=200, oos_length_ns=100),
        coverage,
    )

    fold = manifest.folds[0]
    assert fold.is_start_ns == sessions[0].open_ns
    assert fold.is_end_ns == sessions[0].close_ns
    assert fold.oos_start_ns == sessions[1].open_ns
    assert fold.oos_end_ns == sessions[1].close_ns


def test_training_view_includes_is_start_and_excludes_is_end_and_oos() -> None:
    rows = tuple(_feature(point) for point in (0, 199, 200, 210, 309, 310))
    coverage = _coverage(feature_rows=rows)
    manifest = split(_spec("fixed"), coverage)

    view = training_view(manifest, manifest.folds[0].fold_id, coverage)

    assert [row.asof_ns for row in view.training_features] == [0, 199]
    assert (view.is_start_ns, view.is_end_ns) == (0, 200)
    names = {field.name for field in fields(view)}
    assert not any(name.startswith("oos_") for name in names)
    assert "training_features" in names


def test_training_view_applies_the_fold_feature_allowlist() -> None:
    rows = (
        _feature(10, feature_name="close"),
        _feature(11, feature_name="volume"),
    )
    coverage = _coverage(feature_rows=rows)
    manifest = split(_spec("fixed"), coverage)

    view = training_view(manifest, manifest.folds[0].fold_id, coverage)

    assert [(row.feature_name, row.feature_version) for row in view.training_features] == [
        ("close", "v1")
    ]


def test_feature_event_and_availability_must_not_exceed_asof_cutoff() -> None:
    with pytest.raises(FeatureUnavailableError):
        _coverage(feature_rows=(_feature(100, availability_ns=101),))

    with pytest.raises(FeatureUnavailableError):
        _coverage(feature_rows=(_feature(100, event_ns=101),))


def test_selector_receives_only_training_view_and_pins_its_output() -> None:
    coverage = _coverage(feature_rows=(_feature(10), _feature(250)))
    manifest = split(_spec("fixed"), coverage)
    view = training_view(manifest, manifest.folds[0].fold_id, coverage)
    received: list[tuple[int, ...]] = []

    def selector(training: object) -> dict[str, str]:
        received.append(tuple(row.asof_ns for row in training.training_features))  # type: ignore[attr-defined]
        return {"threshold": "0.5"}

    selected = select_parameters(view, selector)

    assert received == [(10,)]
    assert selected.fold_id == view.fold_id
    assert selected.training_snapshot_sha256 == view.training_snapshot_sha256
    assert selected.parameters == (("threshold", "0.5"),)
    assert len(selected.parameters_sha256) == 64


def test_selector_attempt_to_read_oos_from_view_fails_closed() -> None:
    coverage = _coverage(feature_rows=(_feature(10),))
    manifest = split(_spec("fixed"), coverage)
    view = training_view(manifest, manifest.folds[0].fold_id, coverage)

    with pytest.raises(OOSSelectionAccessError):
        select_parameters(view, lambda training: training.oos_features)  # type: ignore[attr-defined]


def test_manifest_pins_dataset_universe_and_feature_snapshot_hashes() -> None:
    first_coverage = _coverage(feature_rows=(_feature(10, value="1"),))
    changed_feature_coverage = _coverage(feature_rows=(_feature(10, value="2"),))
    changed_dataset_coverage = _coverage(dataset_version="dataset-v2")

    first = split(_spec("fixed"), first_coverage)
    changed_feature = split(_spec("fixed"), changed_feature_coverage)
    changed_dataset = split(_spec("fixed"), changed_dataset_coverage)

    assert len(first.dataset_snapshot_sha256) == 64
    assert len(first.universe_snapshot_sha256) == 64
    assert len(first.feature_snapshot_sha256) == 64
    assert first.feature_snapshot_sha256 != changed_feature.feature_snapshot_sha256
    assert first.dataset_snapshot_sha256 != changed_dataset.dataset_snapshot_sha256
    assert first.manifest_sha256 != changed_feature.manifest_sha256


def test_training_view_rejects_a_different_coverage_snapshot() -> None:
    source = _coverage(feature_rows=(_feature(10, value="1"),))
    other = _coverage(feature_rows=(_feature(10, value="2"),))
    manifest = split(_spec("fixed"), source)

    with pytest.raises(DatasetCoverageError):
        training_view(manifest, manifest.folds[0].fold_id, other)


def test_calendar_fixture_preserves_dst_shifted_utc_session_boundaries() -> None:
    raw = json.loads((FIXTURES / "nyse_dst_sessions.json").read_text(encoding="utf-8"))
    sessions = tuple(SessionWindowV1(**item) for item in raw["sessions"])
    coverage = _coverage(
        start_ns=sessions[0].open_ns,
        end_ns=sessions[-1].close_ns,
        sessions=sessions,
    )
    anchor = sessions[1].open_ns

    manifest = split(
        _spec(
            "anchored",
            is_length_ns=60 * 60 * 1_000_000_000,
            oos_length_ns=30 * 60 * 1_000_000_000,
            step_ns=30 * 60 * 1_000_000_000,
            embargo_ns=0,
            anchor_ns=anchor,
        ),
        coverage,
    )

    assert manifest.folds[0].is_start_ns == 1710163800000000000
    assert manifest.folds[0].is_end_ns == anchor + 60 * 60 * 1_000_000_000


def test_anchored_start_outside_a_calendar_session_is_rejected() -> None:
    coverage = _coverage()

    with pytest.raises(CalendarInvalidError):
        split(_spec("anchored", anchor_ns=1001), coverage)


def test_anchored_start_inside_nontrading_gap_yields_no_valid_folds() -> None:
    sessions = (
        SessionWindowV1("XNYS", "1970-01-01", 0, 100),
        SessionWindowV1("XNYS", "1970-01-02", 200, 1000),
    )
    coverage = _coverage(start_ns=0, end_ns=1000, sessions=sessions)

    with pytest.raises(EmptyFoldError) as caught:
        split(_spec("anchored", anchor_ns=150), coverage)
    assert caught.value.code == "NO_VALID_FOLDS"


def test_gap_boundary_candidate_is_recorded_without_snapping_or_ending_windows() -> None:
    sessions = (
        SessionWindowV1("XNYS", "1970-01-01", 0, 311),
        SessionWindowV1("XNYS", "1970-01-02", 400, 1000),
    )
    coverage = _coverage(start_ns=0, end_ns=1000, sessions=sessions)

    manifest = split(
        _spec("rolling", step_ns=150, embargo_ns=10),
        coverage,
    )

    gap_drop = next(
        dropped
        for dropped in manifest.dropped_folds
        if dropped.reason == "BOUNDARY_OUTSIDE_SESSION"
    )
    assert (
        gap_drop.index,
        gap_drop.is_start_ns,
        gap_drop.is_end_ns,
        gap_drop.oos_start_ns,
        gap_drop.oos_end_ns,
    ) == (2, 150, 350, 360, 460)
    assert gap_drop.reason == "BOUNDARY_OUTSIDE_SESSION"
    assert manifest.folds[1].is_start_ns == 300
    assert manifest.folds[1].is_end_ns == 500
    assert manifest.folds[1].is_coverage == (111, 111)


@pytest.mark.parametrize("scheme", ["rolling", "expanding"])
def test_partial_final_candidate_is_dropped_and_recorded(scheme: str) -> None:
    coverage = _coverage(end_ns=605)

    manifest = split(_spec(scheme), coverage)

    assert all(fold.oos_end_ns <= 605 for fold in manifest.folds)
    partial = [drop for drop in manifest.dropped_folds if drop.reason == "PARTIAL_TAIL"]
    assert len(partial) == 1
    drop = partial[0]
    assert (
        drop.index,
        drop.is_start_ns,
        drop.is_end_ns,
        drop.oos_start_ns,
        drop.oos_end_ns,
    ) == (3, 400 if scheme == "rolling" else 0, 600, 605, 605)
    assert drop.oos_start_ns <= drop.oos_end_ns


def test_expanding_dataset_start_outside_all_sessions_has_no_valid_folds() -> None:
    sessions = (SessionWindowV1("XNYS", "1970-01-01", 100, 1000),)
    coverage = _coverage(start_ns=0, end_ns=1000, sessions=sessions)

    with pytest.raises(EmptyFoldError) as caught:
        split(_spec("expanding"), coverage)

    assert caught.value.code == "NO_VALID_FOLDS"


def test_zero_valid_folds_has_content_free_no_valid_folds_code() -> None:
    sessions = (
        SessionWindowV1("XNYS", "1970-01-01", 0, 100),
        SessionWindowV1("XNYS", "1970-01-02", 200, 300),
    )
    coverage = _coverage(start_ns=0, end_ns=300, sessions=sessions)

    with pytest.raises(EmptyFoldError) as caught:
        split(_spec("fixed", is_length_ns=100, oos_length_ns=50), coverage)

    assert caught.value.code == "NO_VALID_FOLDS"
    assert str(caught.value) == "NO_VALID_FOLDS"


def test_calendar_windows_without_a_complete_in_sample_fold_fail_typed() -> None:
    coverage = _coverage(end_ns=100)

    with pytest.raises(EmptyFoldError):
        split(_spec("fixed"), coverage)


def test_uncovered_training_session_fails_instead_of_emitting_a_fold() -> None:
    coverage = _coverage(covered_sessions=(), uncovered_sessions=(("XNYS", "1970-01-01"),))

    with pytest.raises(CoverageInsufficientError):
        split(_spec("fixed"), coverage)


def test_uncovered_oos_session_fails_when_oos_fraction_threshold_is_full() -> None:
    sessions = (
        SessionWindowV1("XNYS", "1970-01-01", 0, 201),
        SessionWindowV1("XNYS", "1970-01-02", 210, 311),
    )
    coverage = _coverage(
        start_ns=0,
        end_ns=311,
        sessions=sessions,
        covered_sessions=(("XNYS", "1970-01-01"),),
        uncovered_sessions=(("XNYS", "1970-01-02"),),
    )

    with pytest.raises(CoverageInsufficientError):
        split(_spec("fixed"), coverage)


def test_minimum_oos_fraction_uses_exact_inclusive_threshold() -> None:
    sessions = (
        SessionWindowV1("XNYS", "1970-01-01", 0, 100),
        SessionWindowV1("XNYS", "1970-01-02", 100, 199),
        SessionWindowV1("XNYS", "1970-01-03", 199, 300),
    )
    coverage = _coverage(
        start_ns=0,
        end_ns=300,
        sessions=sessions,
        covered_sessions=(("XNYS", "1970-01-01"), ("XNYS", "1970-01-02")),
        uncovered_sessions=(("XNYS", "1970-01-03"),),
    )
    spec_args = {
        "is_length_ns": 99,
        "oos_length_ns": 200,
        "step_ns": 200,
        "embargo_ns": 0,
    }

    at_threshold = split(_spec("fixed", min_oos_fraction=Decimal("0.5"), **spec_args), coverage)
    assert at_threshold.folds[0].oos_coverage == (100, 200)

    with pytest.raises(CoverageInsufficientError):
        split(
            _spec("fixed", min_oos_fraction=Decimal("0.5001"), **spec_args),
            coverage,
        )


def test_oos_windows_cannot_overlap() -> None:
    with pytest.raises(FoldOverlapError):
        _spec("rolling", oos_length_ns=200, step_ns=199)


def test_checkpoint_choice_is_frozen_into_each_fold() -> None:
    manifest = split(
        _spec("rolling", warm_start_policy="checkpoint"),
        _coverage(end_ns=700),
    )

    assert all(fold.warm_start_policy == "checkpoint" for fold in manifest.folds)


def _fold_artifact(
    fold_id: str,
    manifest_sha256: str,
    is_value: str,
    oos_value: str,
) -> CompletedFoldMetricsV1:
    return CompletedFoldMetricsV1(
        fold_id=fold_id,
        fold_manifest_sha256=manifest_sha256,
        is_metrics=(MetricValueV1("return", Decimal(is_value)),),
        oos_metrics=(MetricValueV1("return", Decimal(oos_value)),),
    )


def test_oos_aggregation_reports_is_and_oos_separately_and_keeps_failed_fold() -> None:
    raw = json.loads((FIXTURES / "closed_empirical_oos.json").read_text(encoding="utf-8"))
    coverage = _coverage(end_ns=700)
    manifest = split(_spec("rolling"), coverage)
    rows = [
        _fold_artifact(
            fold.fold_id,
            manifest.manifest_sha256,
            item["is_metric"],
            item["oos_metric"],
        )
        for fold, item in zip(manifest.folds, raw["folds"], strict=True)
    ]

    aggregate = aggregate_oos(manifest, rows)

    assert raw["evidence_label"] == "CLOSED_EMPIRICAL"
    assert aggregate.fold_ids == tuple(fold.fold_id for fold in manifest.folds)
    assert len(aggregate.metrics) == 1
    assert aggregate.metrics[0].is_mean == Decimal("0.7")
    assert aggregate.metrics[0].oos_mean == Decimal("0.25")


@pytest.mark.parametrize(
    "mutate",
    [
        lambda rows: rows[:-1],
        lambda rows: [*rows, rows[0]],
        lambda rows: [*rows, _fold_artifact("extra-fold", "c" * 64, "0", "0")],
    ],
)
def test_oos_aggregation_rejects_missing_duplicate_and_extra_folds(mutate: object) -> None:
    manifest = split(_spec("rolling"), _coverage(end_ns=700))
    rows = [
        _fold_artifact(fold.fold_id, manifest.manifest_sha256, "0.1", "-0.2")
        for fold in manifest.folds
    ]

    with pytest.raises(IncompleteFoldAggregationError):
        aggregate_oos(manifest, mutate(rows))  # type: ignore[operator]


def test_oos_aggregation_rejects_wrong_manifest_binding_and_metric_sets() -> None:
    manifest = split(_spec("rolling"), _coverage(end_ns=700))
    first, second = manifest.folds
    wrong_binding = [
        _fold_artifact(first.fold_id, "f" * 64, "1", "1"),
        _fold_artifact(second.fold_id, manifest.manifest_sha256, "1", "1"),
    ]
    inconsistent_metrics = [
        _fold_artifact(first.fold_id, manifest.manifest_sha256, "1", "1"),
        CompletedFoldMetricsV1(
            second.fold_id,
            manifest.manifest_sha256,
            (MetricValueV1("other", Decimal("1")),),
            (MetricValueV1("other", Decimal("1")),),
        ),
    ]

    with pytest.raises(IncompleteFoldAggregationError):
        aggregate_oos(manifest, wrong_binding)
    with pytest.raises(IncompleteFoldAggregationError):
        aggregate_oos(manifest, inconsistent_metrics)
