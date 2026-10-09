"""Regression checks for bounded per-item prepared-stream iteration work."""

from dataclasses import replace
from decimal import Decimal
from time import process_time

from pytest import MonkeyPatch

from leviathan_core.backtest_lab.clock import (
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
    MarketEventV1,
    SealedStreamTamperedError,
    SessionWindowV1,
    StreamSpecV1,
    UniverseMemberV1,
)


def _stream(event_count: int) -> PreparedEventStreamV1:
    manifest = DatasetManifestV1(
        dataset_id="iteration-perf",
        dataset_version="v1",
        universe_version="u1",
        symbol_mapping_version="map1",
        calendar_id="calendar",
        calendar_version="cal1",
        adjustment_version="a1",
        as_of_ns=event_count + 1,
        start_ns=0,
        end_ns=event_count + 1,
        source_checksums=(("vendor", "a" * 64),),
        universe=(UniverseMemberV1("ABC", "X", 0, event_count + 1),),
        sessions=(SessionWindowV1("X", "1970-01-01", 0, event_count + 1),),
        streams=(StreamSpecV1("ticks", "vendor", "X", 0),),
        max_identity_cache=event_count + 1,
    )
    events = tuple(
        MarketEventV1(
            dataset_id="iteration-perf",
            dataset_version="v1",
            universe_version="u1",
            source="vendor",
            source_id=f"tick-{index}",
            correction_key="base",
            stream_id="ticks",
            event_ns=index + 1,
            available_ns=index + 1,
            instrument="ABC",
            venue="X",
            sequence=index + 1,
            kind="trade",
            price=Decimal("10"),
            size=Decimal("1"),
        )
        for index in range(event_count)
    )
    return prepare_events(manifest, events, AdjustmentPolicyV1("raw", "a1", view="PIT"))


def test_iteration_revalidates_at_boundaries_not_for_each_item(
    monkeypatch: MonkeyPatch,
) -> None:
    stream = _stream(64)
    original = PreparedEventStreamV1._require_seal
    calls = 0

    def count_boundary_checks(self: PreparedEventStreamV1) -> object:
        nonlocal calls
        calls += 1
        return original(self)

    monkeypatch.setattr(PreparedEventStreamV1, "_require_seal", count_boundary_checks)

    output = tuple(stream)

    assert len(output) == 64
    assert output[0].raw.source_id == "tick-0"
    assert output[-1].raw.source_id == "tick-63"
    assert calls == 2


def test_iterator_replacement_after_start_fails_closed() -> None:
    stream = _stream(6)
    assert [next(stream).raw.source_id for _ in range(2)] == ["tick-0", "tick-1"]

    object.__setattr__(stream, "_iterator", iter(()))

    try:
        next(stream)
    except SealedStreamTamperedError:
        pass
    else:
        raise AssertionError("replacing the bound iterator silently truncated the stream")


def test_pre_iteration_limit_tampering_fails_closed() -> None:
    stream = _stream(6)
    object.__setattr__(stream, "_limit", 2)

    try:
        next(stream)
    except SealedStreamTamperedError:
        pass
    else:
        raise AssertionError("a changed limit silently truncated the stream")


def test_pre_iteration_prepared_output_reordering_fails_closed() -> None:
    stream = _stream(6)
    object.__setattr__(
        stream,
        "_prepared_outputs",
        tuple(reversed(stream._prepared_outputs)),
    )

    try:
        next(stream)
    except SealedStreamTamperedError:
        pass
    else:
        raise AssertionError("reordered prepared outputs were emitted")


def test_projection_mutation_is_detected_by_exhaustion() -> None:
    stream = _stream(6)
    assert [next(stream).raw.source_id for _ in range(2)] == ["tick-0", "tick-1"]
    object.__setattr__(stream._projection[3], "price", Decimal("12"))

    try:
        tuple(stream)
    except SealedStreamTamperedError:
        pass
    else:
        raise AssertionError("projection mutation survived end-of-iteration verification")


def test_completed_progress_mutation_is_rejected_by_properties_and_verifier() -> None:
    stream = _stream(6)
    assert len(tuple(stream)) == 6
    object.__setattr__(stream._progress, "stream_digest", "0" * 64)
    object.__setattr__(stream._progress, "event_count", 0)

    for read in (lambda: stream.stream_digest, lambda: stream.event_count, lambda: stream.cursor):
        try:
            read()
        except SealedStreamTamperedError:
            pass
        else:
            raise AssertionError("forged final progress was exposed")
    try:
        verify_prepared_stream(stream)
    except StreamTamperedError:
        pass
    else:
        raise AssertionError("verifier accepted forged final progress")


def test_replacing_complete_progress_with_forged_copy_is_rejected() -> None:
    stream = _stream(6)
    assert len(tuple(stream)) == 6
    complete_progress = stream._complete_progress
    assert complete_progress is not None
    forged = replace(complete_progress, stream_digest="1" * 64, event_count=3)
    object.__setattr__(stream, "_complete_progress", forged)
    object.__setattr__(stream, "_progress", forged)

    try:
        verify_prepared_stream(stream)
    except StreamTamperedError:
        pass
    else:
        raise AssertionError("verifier accepted a replaced forged completion record")


def test_post_completion_structural_tampering_is_rejected_on_next() -> None:
    for attribute, forged_value in (
        ("_iterator", iter(())),
        ("_limit", 2),
    ):
        stream = _stream(6)
        assert len(tuple(stream)) == 6
        object.__setattr__(stream, attribute, forged_value)
        try:
            next(stream)
        except SealedStreamTamperedError:
            pass
        else:
            raise AssertionError(f"post-completion {attribute} tampering was accepted")

    stream = _stream(6)
    assert len(tuple(stream)) == 6
    object.__setattr__(stream, "_prepared_outputs", tuple(reversed(stream._prepared_outputs)))
    try:
        next(stream)
    except SealedStreamTamperedError:
        pass
    else:
        raise AssertionError("post-completion output tampering was accepted")


def _timed_construct_and_iterate(event_count: int, *, adjusted: bool) -> float:
    started = process_time()
    events = tuple(
        MarketEventV1(
            dataset_id="iteration-perf",
            dataset_version="v1",
            universe_version="u1",
            source="vendor",
            source_id=f"tick-{index}",
            correction_key="base",
            stream_id="ticks",
            event_ns=index + 1,
            available_ns=index + 1,
            instrument="ABC",
            venue="X",
            sequence=index + 1,
            kind="trade",
            price=Decimal("10"),
            size=Decimal("1"),
        )
        for index in range(event_count)
    )
    manifest = DatasetManifestV1(
        dataset_id="iteration-perf",
        dataset_version="v1",
        universe_version="u1",
        symbol_mapping_version="map1",
        calendar_id="calendar",
        calendar_version="cal1",
        adjustment_version="a1",
        as_of_ns=event_count + 1,
        start_ns=0,
        end_ns=event_count + 1,
        source_checksums=(("vendor", "a" * 64),),
        universe=(UniverseMemberV1("ABC", "X", 0, event_count + 1),),
        sessions=(SessionWindowV1("X", "1970-01-01", 0, event_count + 1),),
        streams=(StreamSpecV1("ticks", "vendor", "X", 0),),
        max_identity_cache=event_count + 1,
    )
    if adjusted:
        manifest = replace(manifest, as_of_ns=event_count + 2, end_ns=event_count + 2)
    policy = AdjustmentPolicyV1(
        "split_only" if adjusted else "raw",
        "a1",
        view="BACK_ADJUSTED" if adjusted else "PIT",
    )
    snapshot = None
    if adjusted:
        effective_ns = event_count + 2
        action_event = MarketEventV1(
            dataset_id="iteration-perf",
            dataset_version="v1",
            universe_version="u1",
            source="vendor",
            source_id="split-action",
            correction_key="action-v1",
            stream_id="ticks",
            event_ns=effective_ns,
            available_ns=1,
            instrument="ABC",
            venue="X",
            sequence=None,
            kind="corporate_action",
            price=None,
            size=None,
            action=CorporateActionV1(
                "split",
                effective_ns,
                1,
                1,
                split_ratio=Decimal("2"),
            ),
        )
        snapshot = CorporateActionSnapshotV1(
            "iteration-actions",
            event_count + 2,
            "a1",
            (action_event,),
        )
    stream = prepare_events(manifest, events, policy, action_snapshot=snapshot)
    assert len(tuple(stream)) == event_count
    return process_time() - started


def test_end_to_end_construction_and_iteration_scale_linearly() -> None:
    for adjusted in (False, True):
        small = _timed_construct_and_iterate(1_000, adjusted=adjusted)
        large = _timed_construct_and_iterate(10_000, adjusted=adjusted)

        assert large < 15.0
        assert (large / 10_000) <= 3 * (small / 1_000)
