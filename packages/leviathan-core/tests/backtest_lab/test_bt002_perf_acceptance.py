"""Contract-level performance and behavior acceptance for BT-002 iteration."""

from __future__ import annotations

import os
import re
from collections.abc import Callable
from dataclasses import replace
from decimal import Decimal
from time import perf_counter, process_time

import pytest

from leviathan_core.backtest_lab.clock import (
    CheckpointCursorV1,
    PreparedEventStreamV1,
    StreamTamperedError,
    prepare_events,
    verify_prepared_stream,
)
from leviathan_core.backtest_lab.events import (
    AdjustmentPolicyV1,
    CorporateActionSnapshotV1,
    CorporateActionV1,
    DatasetManifestV1,
    EventClockError,
    MarketEventV1,
    SealedStreamTamperedError,
    SessionWindowV1,
    StreamSpecV1,
    UniverseMemberV1,
)
from leviathan_core.seal import digest

# Captured from the current canonical clock.py at SHA-256
# 30721012f55d1b48d1bf6eda21acad4a7197c95dd03c14fba90ac45d22b3f5c4.
_GOLDEN_ORDER = ("tick-0", "tick-1", "tick-2", "tick-3", "tick-4")
_GOLDEN_EVENT_DIGESTS = (
    "693e7c613cdbc114fb9408258ae0bda18d2fc080282d595179a119390a2fde0f",
    "ae440054de72eabb8c984ab5445cf202892f3b5461c39e06e2ff5e101dc41844",
    "5e15deeb6bfe2f6db365aa526b97dbd6dac3ef21a1a2eb7654d304d0ac10b2fa",
    "e87705e00deafbfd8eeba5c548c8084bc13cbf8b33ff6aee3b42cf7629283668",
    "2fab6504191e782bbe9ee3ae380677d4fb68d9c2c5de5e31f4bd62bd876e5c31",
)
_GOLDEN_STREAM_DIGEST = "9bd9979d4b5f69c53acef54253fcb1ba41855a42900c937465947f33ed2d7140"


def _synthetic_stream(
    event_count: int,
    *,
    dataset_id: str,
    first_event_ns: int = 1,
    event_step_ns: int = 1,
    dataset_end_ns: int | None = None,
    adjustment_mode: str = "raw",
    limit: int | None = None,
) -> PreparedEventStreamV1:
    close_ns = first_event_ns + (event_count - 1) * event_step_ns + 1
    end_ns = close_ns if dataset_end_ns is None else dataset_end_ns
    session = SessionWindowV1("XPERF", "1970-01-01", 0, end_ns)
    manifest = DatasetManifestV1(
        dataset_id=dataset_id,
        dataset_version="v1",
        universe_version="u1",
        symbol_mapping_version="map1",
        calendar_id="perf-calendar",
        calendar_version="calendar-v1",
        adjustment_version="raw-v1",
        as_of_ns=end_ns,
        start_ns=0,
        end_ns=end_ns,
        source_checksums=(("perf-feed", "a" * 64),),
        universe=(UniverseMemberV1("SYN", "XPERF", 0),),
        sessions=(session,),
        streams=(StreamSpecV1("ticks", "perf-feed", "XPERF", 0),),
        max_identity_cache=event_count + 16,
    )
    events = tuple(
        MarketEventV1(
            dataset_id=dataset_id,
            dataset_version="v1",
            universe_version="u1",
            source="perf-feed",
            source_id=f"tick-{index}",
            correction_key="original",
            stream_id="ticks",
            event_ns=first_event_ns + index * event_step_ns,
            available_ns=first_event_ns + index * event_step_ns,
            instrument="SYN",
            venue="XPERF",
            sequence=index + 1,
            kind="trade",
            price=Decimal("100") + Decimal(index) / Decimal("4"),
            size=Decimal(index + 1),
        )
        for index in range(event_count)
    )
    action_snapshot = None
    view = "PIT"
    if adjustment_mode != "raw":
        effective_ns = first_event_ns + (event_count // 2) * event_step_ns
        action_event = MarketEventV1(
            dataset_id=dataset_id,
            dataset_version="v1",
            universe_version="u1",
            source="perf-feed",
            source_id="split-1",
            correction_key="original",
            stream_id="ticks",
            event_ns=effective_ns,
            available_ns=effective_ns,
            instrument="SYN",
            venue="XPERF",
            sequence=None,
            kind="corporate_action",
            action=CorporateActionV1(
                action="split",
                effective_ns=effective_ns,
                announced_ns=effective_ns,
                available_ns=effective_ns,
                split_ratio=Decimal("2"),
            ),
        )
        action_snapshot = CorporateActionSnapshotV1(
            snapshot_id=f"actions-{dataset_id}",
            as_of_ns=end_ns,
            adjustment_version="raw-v1",
            actions=(action_event,),
        )
        view = "BACK_ADJUSTED"
    return prepare_events(
        manifest,
        events,
        AdjustmentPolicyV1(mode=adjustment_mode, version="raw-v1", view=view),
        limit=limit,
        action_snapshot=action_snapshot,
    )


def _matrix_stream(
    kind: str = "raw",
    *,
    limit: int | None = None,
    cursor: CheckpointCursorV1 | None = None,
) -> PreparedEventStreamV1:
    dataset_id = "dataset"
    events = tuple(
        MarketEventV1(
            dataset_id=dataset_id,
            dataset_version="v1",
            universe_version="u1",
            source="vendor",
            source_id=f"e{index}",
            correction_key="base",
            stream_id="s",
            event_ns=10 + index,
            available_ns=10 + index,
            instrument="ABC",
            venue="X",
            sequence=index + 1,
            kind="trade",
            price=Decimal(10 + index),
            size=Decimal("2"),
        )
        for index in range(6)
    )
    manifest = DatasetManifestV1(
        dataset_id,
        "v1",
        "u1",
        "map1",
        "calendar",
        "cal1",
        "a1",
        1000,
        0,
        1000,
        (("vendor", "a" * 64),),
        (UniverseMemberV1("ABC", "X", 0),),
        (SessionWindowV1("X", "1970-01-01", 0, 1000),),
        (StreamSpecV1("s", "vendor", "X", 0),),
        1000,
    )
    adjustment_mode = "raw" if kind == "raw" else "split_only"
    view = "PIT" if kind == "raw" else "BACK_ADJUSTED"
    action_snapshot = None
    if kind == "adjusted":
        action = CorporateActionV1("split", 200, 190, 190, split_ratio=Decimal("2"))
        action_event = MarketEventV1(
            dataset_id,
            "v1",
            "u1",
            "vendor",
            "act",
            "base",
            "s",
            200,
            190,
            "ABC",
            "X",
            None,
            "corporate_action",
            action=action,
        )
        action_snapshot = CorporateActionSnapshotV1("snap-1", 1000, "a1", (action_event,))
    policy = AdjustmentPolicyV1(adjustment_mode, "a1", view)
    return prepare_events(
        manifest,
        events,
        policy,
        cursor,
        limit=limit,
        action_snapshot=action_snapshot,
    )


def _assert_content_free_stream_error(
    operation: Callable[[], object],
    error_type: type[EventClockError] = SealedStreamTamperedError,
) -> None:
    try:
        operation()
    except error_type as error:
        assert type(error) is error_type
        code = str(error)
        assert error.args == (code,)
        assert re.fullmatch(r"[A-Z][A-Z0-9_]*", code)
    else:
        raise AssertionError("tampered stream state was accepted")


def _assert_properties_and_verifier_reject(stream: PreparedEventStreamV1) -> None:
    for read_property in (
        lambda: stream.stream_digest,
        lambda: stream.event_count,
        lambda: stream.cursor,
        lambda: stream.coverage,
    ):
        _assert_content_free_stream_error(read_property)
    _assert_content_free_stream_error(lambda: verify_prepared_stream(stream), StreamTamperedError)


def _assert_rejected_by_exhaustion(stream: PreparedEventStreamV1) -> None:
    try:
        while True:
            next(stream)
    except StopIteration:
        raise AssertionError("tampered stream reached normal exhaustion") from None
    except SealedStreamTamperedError as error:
        code = str(error)
        assert error.args == (code,)
        assert code == "SEALED_STREAM_TAMPERED"


def test_synthetic_stream_iteration_semantics_to_ten_thousand_events() -> None:
    stream_1k = _synthetic_stream(1_000, dataset_id="perf-1k")
    stream_10k = _synthetic_stream(10_000, dataset_id="perf-10k")

    output_1k = tuple(stream_1k)
    output_10k = tuple(stream_10k)

    assert len(output_1k) == stream_1k.event_count == 1_000
    assert len(output_10k) == stream_10k.event_count == 10_000
    assert stream_1k.complete
    assert stream_10k.complete


def _measure_iteration_min_of_n(event_count: int, rounds: int = 3) -> tuple[float, float]:
    cpu_samples: list[float] = []
    wall_samples: list[float] = []
    for round_index in range(rounds):
        stream = _synthetic_stream(
            event_count,
            dataset_id=f"perf-{event_count}-{round_index}",
        )
        wall_started = perf_counter()
        cpu_started = process_time()
        output = tuple(stream)
        cpu_samples.append(process_time() - cpu_started)
        wall_samples.append(perf_counter() - wall_started)
        assert len(output) == event_count
        assert stream.complete
    return min(cpu_samples), min(wall_samples)


@pytest.mark.skipif(
    os.environ.get("LEVIATHAN_RUN_PERF") != "1",
    reason="perf opt-in",
)
def test_synthetic_stream_iteration_scales_to_ten_thousand_events() -> None:
    cpu_1k, _ = _measure_iteration_min_of_n(1_000)
    cpu_10k, wall_10k = _measure_iteration_min_of_n(10_000)

    assert wall_10k < 2.0
    per_event_1k = cpu_1k / 1_000
    per_event_10k = cpu_10k / 10_000
    assert max(per_event_1k, per_event_10k) <= 3 * min(per_event_1k, per_event_10k)


def test_plan_tampering_after_iteration_start_fails_by_iteration_end() -> None:
    stream = _synthetic_stream(128, dataset_id="tamper-after-start")
    first = next(stream)
    assert first.raw.source_id == "tick-0"

    plan = stream._plan  # type: ignore[attr-defined]
    object.__setattr__(plan, "manifest_digest", "f" * 64)

    try:
        tuple(stream)
    except EventClockError as error:
        code = str(error)
        arguments = error.args
    else:
        raise AssertionError("tampered plan completed iteration without detection")

    assert arguments == (code,)
    assert re.fullmatch(r"[A-Z][A-Z0-9_]*", code)
    assert "tamper-after-start" not in code


def test_output_order_identity_and_digests_match_prechange_canonical() -> None:
    stream = _synthetic_stream(
        5,
        dataset_id="perf-golden-dataset",
        first_event_ns=100,
        event_step_ns=100,
        dataset_end_ns=1000,
    )
    prepared = tuple(stream)

    assert tuple(item.raw.source_id for item in prepared) == _GOLDEN_ORDER
    assert tuple(
        (item.raw.source_id, item.raw.correction_key, item.raw.stream_id) for item in prepared
    ) == tuple((source_id, "original", "ticks") for source_id in _GOLDEN_ORDER)
    assert tuple(digest(item) for item in prepared) == _GOLDEN_EVENT_DIGESTS
    assert stream.stream_digest == _GOLDEN_STREAM_DIGEST


def _resume_matrix_stream(kind: str) -> PreparedEventStreamV1:
    first = _matrix_stream(kind, limit=2)
    assert len(tuple(first)) == 2
    return _matrix_stream(kind, cursor=first.cursor)


def _at_position(stream: PreparedEventStreamV1, position: str) -> None:
    offset = stream._resume.event_count if stream._resume is not None else 0
    expected_ids = tuple(item.source_id for item in stream._projection)[offset:]
    if position == "mid":
        assert next(stream).raw.source_id == expected_ids[0]
        assert next(stream).raw.source_id == expected_ids[1]
    elif position == "done":
        assert len(tuple(stream)) == len(expected_ids)


def _mutate_matrix_stream(
    stream: PreparedEventStreamV1,
    mutation: str,
    position: str,
    kind: str,
) -> None:
    if mutation == "_iterator":
        object.__setattr__(stream, "_iterator", iter(()))
    elif mutation == "_limit":
        object.__setattr__(stream, "_limit", 2)
    elif mutation == "_prepared_outputs":
        other_stream = _matrix_stream(kind)
        object.__setattr__(stream, "_prepared_outputs", tuple(reversed(tuple(other_stream))))
    elif mutation == "_projection_order":
        object.__setattr__(stream, "_projection", tuple(reversed(stream._projection)))
    elif mutation == "_projection_price":
        index = 3 if position == "mid" else 1
        object.__setattr__(stream._projection[index], "price", Decimal("999"))
    elif mutation == "_resume":
        object.__setattr__(stream, "_resume", None)
    elif mutation == "_manifest":
        object.__setattr__(
            stream,
            "_manifest",
            replace(stream._manifest, calendar_version="forged"),
        )
    elif mutation == "_policy":
        object.__setattr__(stream, "_policy", replace(stream._policy, version="forged"))
    elif mutation == "_manifest_digest":
        object.__setattr__(stream, "_manifest_digest", "f" * 64)
    elif mutation == "_action_snapshot_digest":
        object.__setattr__(stream, "_action_snapshot_digest", "forged")
    elif mutation == "_correction_audit":
        object.__setattr__(stream, "_correction_audit", ())
    elif mutation == "_supersedes":
        object.__setattr__(stream, "_supersedes", {})
    elif mutation == "_skipped_unavailable":
        object.__setattr__(stream, "_skipped_unavailable", 7)
    elif mutation == "_plan":
        object.__setattr__(stream, "_plan", _matrix_stream(kind)._plan)
    else:
        raise AssertionError(f"unknown matrix mutation: {mutation}")


_MATRIX_MUTATIONS = (
    "_iterator",
    "_limit",
    "_prepared_outputs",
    "_projection_order",
    "_projection_price",
    "_resume",
    "_manifest",
    "_policy",
    "_manifest_digest",
    "_action_snapshot_digest",
    "_correction_audit",
    "_supersedes",
    "_skipped_unavailable",
    "_plan",
)


@pytest.mark.parametrize("kind", ("raw", "adjusted"))
@pytest.mark.parametrize("mutation", _MATRIX_MUTATIONS)
@pytest.mark.parametrize("position", ("start", "mid", "done"))
def test_published_tamper_matrix_fails_closed(kind: str, mutation: str, position: str) -> None:
    stream = _resume_matrix_stream(kind) if mutation == "_resume" else _matrix_stream(kind)
    _at_position(stream, position)
    _mutate_matrix_stream(stream, mutation, position, kind)

    if position == "done":
        _assert_properties_and_verifier_reject(stream)
    elif mutation in {"_iterator", "_limit", "_prepared_outputs"}:
        _assert_content_free_stream_error(lambda: next(stream))
    else:
        _assert_rejected_by_exhaustion(stream)


@pytest.mark.parametrize(
    ("field_name", "forged_value"),
    (
        ("manifest_digest", "f" * 64),
        ("projection_count", 99),
        ("limit", 3),
    ),
)
def test_plan_field_tampering_is_detected_before_output(
    field_name: str, forged_value: object
) -> None:
    for kind in ("raw", "adjusted"):
        stream = _matrix_stream(kind)
        object.__setattr__(stream._plan, field_name, forged_value)
        _assert_content_free_stream_error(lambda stream=stream: next(stream))


@pytest.mark.parametrize("kind", ("raw", "adjusted"))
def test_structural_tampering_before_first_output_is_detected_immediately(
    kind: str,
) -> None:
    for field_name, forged_value in (
        ("_limit", 2),
        ("_prepared_outputs", tuple(reversed(tuple(_matrix_stream(kind))))),
    ):
        stream = _matrix_stream(kind)
        object.__setattr__(stream, field_name, forged_value)
        _assert_content_free_stream_error(lambda stream=stream: next(stream))


@pytest.mark.parametrize("kind", ("raw", "adjusted"))
def test_structural_tampering_after_two_outputs_is_detected_immediately(
    kind: str,
) -> None:
    stream = _matrix_stream(kind)
    assert next(stream).raw.source_id == "e0"
    assert next(stream).raw.source_id == "e1"
    object.__setattr__(stream, "_iterator", iter(()))
    _assert_content_free_stream_error(lambda: next(stream))


@pytest.mark.parametrize("kind", ("raw", "adjusted"))
def test_completed_progress_digest_and_count_forgery_is_rejected(kind: str) -> None:
    stream = _matrix_stream(kind)
    assert len(tuple(stream)) == 6
    object.__setattr__(stream._progress, "stream_digest", "0" * 64)  # type: ignore[attr-defined]
    object.__setattr__(stream._progress, "event_count", 0)  # type: ignore[attr-defined]

    _assert_properties_and_verifier_reject(stream)


@pytest.mark.parametrize("kind", ("raw", "adjusted"))
def test_replacing_progress_and_complete_progress_with_forged_pair_is_rejected(
    kind: str,
) -> None:
    stream = _matrix_stream(kind)
    assert len(tuple(stream)) == 6
    forged_progress = replace(
        stream._complete_progress,
        stream_digest="1" * 64,
        event_count=3,
    )
    object.__setattr__(stream, "_progress", forged_progress)
    object.__setattr__(stream, "_complete_progress", forged_progress)

    _assert_properties_and_verifier_reject(stream)


def _measure_construct_and_iterate(event_count: int, adjustment_mode: str) -> tuple[float, float]:
    cpu_started = process_time()
    wall_started = perf_counter()
    stream = _synthetic_stream(
        event_count,
        dataset_id=f"construct-{adjustment_mode}-{event_count}",
        adjustment_mode=adjustment_mode,
    )
    output = tuple(stream)
    cpu_elapsed = process_time() - cpu_started
    wall_elapsed = perf_counter() - wall_started
    assert len(output) == event_count
    assert stream.event_count == event_count
    assert stream.complete
    return cpu_elapsed, wall_elapsed


@pytest.mark.parametrize("adjustment_mode", ("raw", "split_only"))
def test_construct_and_iterate_scaling_for_raw_and_adjusted_modes(
    adjustment_mode: str,
) -> None:
    cpu_1k, wall_1k = _measure_construct_and_iterate(1_000, adjustment_mode)
    cpu_10k, wall_10k = _measure_construct_and_iterate(10_000, adjustment_mode)

    assert cpu_10k <= 15.0
    per_event_1k = cpu_1k / 1_000
    per_event_10k = cpu_10k / 10_000
    assert max(per_event_1k, per_event_10k) <= 3 * min(per_event_1k, per_event_10k)
    # Wall samples are intentionally informational under host contention.
    assert wall_1k > 0
    assert wall_10k > 0
