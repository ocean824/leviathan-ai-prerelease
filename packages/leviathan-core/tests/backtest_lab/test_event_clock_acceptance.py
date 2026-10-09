"""Contract-level adversarial tests for BT-002's pure event clock."""

import gc
import json
import pickle
from collections.abc import Iterable, Mapping
from copy import copy, deepcopy
from dataclasses import dataclass, field, fields, replace
from datetime import datetime
from decimal import Decimal, localcontext
from hashlib import sha256

import pytest

from leviathan_core.backtest_lab import (
    AdjustmentError,
    AdjustmentPolicyV1,
    BookLevelV1,
    BookStateError,
    CapacityError,
    CheckpointError,
    CorporateActionSnapshotV1,
    CorporateActionV1,
    DatasetManifestV1,
    DuplicateSourceError,
    EventClockError,
    EventValidationError,
    ManifestError,
    MarketEventV1,
    OutOfOrderError,
    PolicyOutOfBoundsError,
    PrecisionExceededError,
    SequenceGapError,
    SequenceGapV1,
    SessionWindowV1,
    StreamSpecV1,
    UniverseMemberV1,
    prepare_events,
)
from leviathan_core.backtest_lab.adjustments import AdjustmentEngine


def manifest(
    *,
    streams: tuple[StreamSpecV1, ...] | None = None,
    as_of_ns: int = 100,
    universe: tuple[UniverseMemberV1, ...] | None = None,
    max_retained_book_levels: int = 50_000,
    max_identity_cache: int = 100_000,
    end_ns: int = 100,
) -> DatasetManifestV1:
    declared_streams = streams or (StreamSpecV1("a", "feed-a", "XNYS", priority=0),)
    return DatasetManifestV1(
        dataset_id="fixture-dataset",
        dataset_version="dataset-v1",
        universe_version="universe-v1",
        symbol_mapping_version="symbols-v1",
        calendar_id="fixture-calendar",
        calendar_version="calendar-v1",
        adjustment_version="adjustment-v1",
        as_of_ns=as_of_ns,
        start_ns=0,
        end_ns=end_ns,
        source_checksums=tuple(
            (stream.source, "a" * 64 if stream.source == "feed-a" else "b" * 64)
            for stream in declared_streams
        ),
        universe=universe or (UniverseMemberV1("XYZ", "XNYS", listed_ns=0),),
        sessions=(SessionWindowV1("XNYS", "1970-01-01", 0, end_ns),),
        streams=declared_streams,
        max_identity_cache=max_identity_cache,
        max_retained_book_levels=max_retained_book_levels,
    )


def event(
    source_id: str,
    *,
    stream_id: str = "a",
    source: str | None = None,
    sequence: int | None = 1,
    event_ns: int = 10,
    available_ns: int | None = None,
    instrument: str = "XYZ",
    venue: str = "XNYS",
    kind: str = "trade",
    price: Decimal | None = Decimal("10"),
    size: Decimal | None = Decimal("2"),
    levels: tuple[BookLevelV1, ...] = (),
    action: CorporateActionV1 | None = None,
    correction_key: str = "original",
) -> MarketEventV1:
    stream_source = source or ("feed-a" if stream_id == "a" else "feed-b")
    return MarketEventV1(
        dataset_id="fixture-dataset",
        dataset_version="dataset-v1",
        universe_version="universe-v1",
        source=stream_source,
        source_id=source_id,
        correction_key=correction_key,
        stream_id=stream_id,
        event_ns=event_ns,
        available_ns=event_ns if available_ns is None else available_ns,
        instrument=instrument,
        venue=venue,
        sequence=sequence,
        kind=kind,  # type: ignore[arg-type]
        price=price,
        size=size,
        levels=levels,
        action=action,
    )


def consume(
    events: Mapping[str, Iterable[MarketEventV1]] | Iterable[MarketEventV1],
    *,
    data: DatasetManifestV1 | None = None,
    policy: AdjustmentPolicyV1 | None = None,
    action_snapshot: CorporateActionSnapshotV1 | None = None,
):
    stream = prepare_events(
        data or manifest(),
        events,
        policy or AdjustmentPolicyV1(mode="raw", version="adjustment-v1"),
        action_snapshot=action_snapshot,
    )
    prepared = tuple(stream)
    return stream, prepared


def test_nanosecond_separation_is_not_rounded_or_reordered() -> None:
    _, prepared = consume(
        (event("earlier", event_ns=1, sequence=1), event("later", event_ns=2, sequence=2))
    )

    assert [item.raw.source_id for item in prepared] == ["earlier", "later"]
    assert prepared[0].raw.event_ns + 1 == prepared[1].raw.event_ns


def test_source_availability_is_visible_without_reordering_event_time() -> None:
    _, prepared = consume(
        (event("available-later", event_ns=1, available_ns=2, sequence=1),)
    )

    assert prepared[0].raw.event_ns == 1
    assert prepared[0].visible_ns == 2


def test_equal_time_ties_follow_manifest_priority_not_input_order() -> None:
    low_priority = event("low", stream_id="b", event_ns=10, sequence=1)
    high_priority = event("high", stream_id="a", event_ns=10, sequence=99)

    two_streams = manifest(
        streams=(
            StreamSpecV1("a", "feed-a", "XNYS", priority=0),
            StreamSpecV1("b", "feed-b", "XNYS", priority=1),
        )
    )
    _, first = consume({"a": (high_priority,), "b": (low_priority,)}, data=two_streams)
    second_stream, second = consume(
        {"b": (low_priority,), "a": (high_priority,)}, data=two_streams
    )

    assert [item.raw.source_id for item in first] == ["high", "low"]
    assert [item.raw.source_id for item in second] == ["high", "low"]
    assert second_stream.stream_digest


def test_repeated_identical_source_identity_collapses_but_divergence_fails() -> None:
    original = event("same-id")
    _, prepared = consume((original, original))
    assert len(prepared) == 1

    divergent = event("same-id", price=Decimal("11"))
    with pytest.raises(DuplicateSourceError):
        consume((original, divergent))


def test_point_in_time_universe_rejects_late_or_unknown_members() -> None:
    late_member = event("late", event_ns=10, instrument="LATE")
    with pytest.raises(EventClockError):
        consume((late_member,))

    delisted_manifest = replace(
        manifest(), universe=(UniverseMemberV1("XYZ", "XNYS", 0, delisted_ns=10),)
    )
    with pytest.raises(EventClockError):
        consume((event("delisted", event_ns=11),), data=delisted_manifest)


def test_unexplained_sequence_gap_fails_and_declared_gap_is_reported() -> None:
    events = (event("seq-1", sequence=1), event("seq-3", sequence=3, event_ns=11))

    with pytest.raises(SequenceGapError):
        consume(events)

    declared = replace(manifest(), declared_gaps=(SequenceGapV1("a", 1, 3),))
    stream, _ = consume(events, data=declared)
    assert stream.coverage.observed_gaps


def test_l2_delta_requires_snapshot_and_nonnegative_depth() -> None:
    delta = event(
        "delta",
        sequence=1,
        kind="book_delta",
        levels=(BookLevelV1("bid", Decimal("9"), Decimal("1")),),
    )
    with pytest.raises(BookStateError):
        consume((delta,))

    snapshot = event(
        "snapshot",
        sequence=1,
        kind="book_snapshot",
        levels=(BookLevelV1("bid", Decimal("9"), Decimal("-1")),),
    )
    with pytest.raises(EventClockError):
        consume((snapshot,))


def test_late_unavailable_split_does_not_rewrite_earlier_as_of_output() -> None:
    tick = event("tick", event_ns=5, sequence=1, price=Decimal("100"))
    future_action = CorporateActionV1(
        action="split",
        effective_ns=10,
        announced_ns=101,
        available_ns=102,
        split_ratio=Decimal("2"),
    )
    action_event = event(
        "late-split",
        sequence=2,
        event_ns=10,
        available_ns=102,
        kind="corporate_action",
        price=None,
        size=None,
        action=future_action,
    )
    policy = AdjustmentPolicyV1(mode="split_only", version="adjustment-v1")
    at_early_t = manifest(as_of_ns=100)
    early_snapshot = CorporateActionSnapshotV1(
        "actions-at-early-t", 100, "adjustment-v1", ()
    )
    early_stream, early = consume(
        (tick,), data=at_early_t, policy=policy, action_snapshot=early_snapshot
    )
    later_t = manifest(as_of_ns=200)
    later_snapshot = CorporateActionSnapshotV1(
        "actions-at-later-t", 200, "adjustment-v1", (action_event,)
    )
    later_stream, later = consume(
        (tick,), data=later_t, policy=policy, action_snapshot=later_snapshot
    )

    assert early[0].adjusted_price == Decimal("100")
    assert early[0].applied_action_ids == ()
    assert early_stream.adjustment_journal == ()
    assert later[0].adjusted_price == Decimal("50")
    assert later[0].applied_action_ids
    assert later_stream.adjustment_journal


def test_split_adjustment_is_back_adjusted_and_preserves_raw_source() -> None:
    tick = event("tick-pre", event_ns=5, sequence=1, price=Decimal("100"), size=Decimal("2"))
    book = event(
        "book",
        event_ns=5,
        sequence=2,
        kind="book_snapshot",
        price=None,
        size=None,
        levels=(BookLevelV1("bid", Decimal("100"), Decimal("4")),),
    )
    post_tick = event(
        "tick-post", event_ns=20, sequence=3, price=Decimal("50"), size=Decimal("4")
    )
    split = CorporateActionV1(
        action="split",
        effective_ns=10,
        announced_ns=1,
        available_ns=1,
        split_ratio=Decimal("2"),
    )
    action_event = event(
        "split",
        sequence=None,
        event_ns=10,
        available_ns=1,
        kind="corporate_action",
        price=None,
        size=None,
        action=split,
    )
    action_snapshot = CorporateActionSnapshotV1(
        "split-snapshot", 100, "adjustment-v1", (action_event,)
    )
    stream, prepared = consume(
        (tick, book, post_tick),
        policy=AdjustmentPolicyV1(mode="split_only", version="adjustment-v1"),
        action_snapshot=action_snapshot,
    )

    adjusted_tick = next(item for item in prepared if item.raw.source_id == "tick-pre")
    assert adjusted_tick.raw.price == Decimal("100")
    assert adjusted_tick.adjusted_price == Decimal("50")
    assert adjusted_tick.adjusted_size == Decimal("4")
    assert adjusted_tick.adjustment_version == "adjustment-v1"
    assert adjusted_tick.applied_action_ids
    adjusted_post = next(item for item in prepared if item.raw.source_id == "tick-post")
    assert adjusted_post.raw.price == Decimal("50")
    assert adjusted_post.adjusted_price == Decimal("50")
    adjusted_book = next(item for item in prepared if item.raw.source_id == "book")
    assert adjusted_book.raw.levels == (BookLevelV1("bid", Decimal("100"), Decimal("4")),)
    assert adjusted_book.adjusted_levels == (BookLevelV1("bid", Decimal("50"), Decimal("8")),)
    assert stream.adjustment_journal
    assert stream.adjustment_journal[0].action_source_id == "split"
    assert stream.adjustment_journal_digest


def test_pit_action_visibility_is_checked_at_each_tick_observation_time() -> None:
    tick = event("pre-split", event_ns=5, available_ns=5, price=Decimal("100"))
    split = CorporateActionV1(
        action="split",
        effective_ns=10,
        announced_ns=9,
        available_ns=9,
        split_ratio=Decimal("2"),
    )
    action = event(
        "known-split",
        event_ns=10,
        available_ns=9,
        kind="corporate_action",
        price=None,
        size=None,
        action=split,
    )
    data = manifest(as_of_ns=100)
    snapshot = CorporateActionSnapshotV1("pit-actions", 100, "adjustment-v1", (action,))

    pit_stream, pit = consume(
        (tick,),
        data=data,
        policy=AdjustmentPolicyV1(
            mode="split_only", version="adjustment-v1", view="PIT"
        ),
        action_snapshot=snapshot,
    )
    research_stream, research = consume(
        (tick,),
        data=data,
        policy=AdjustmentPolicyV1(
            mode="split_only", version="adjustment-v1", view="BACK_ADJUSTED"
        ),
        action_snapshot=snapshot,
    )

    assert pit[0].adjusted_price == Decimal("100")
    assert pit[0].applied_action_ids == ()
    assert pit[0].view == "PIT"
    assert pit[0].view_as_of_ns is None
    assert pit[0].simulator_eligible is True
    assert research[0].adjusted_price == Decimal("50")
    assert research[0].view == "BACK_ADJUSTED"
    assert research[0].view_as_of_ns == 100
    assert research[0].simulator_eligible is False
    assert pit_stream.coverage.complete and research_stream.coverage.complete


def test_back_adjusted_view_accepts_known_action_outside_tick_interval() -> None:
    tick = event("pre-future-split", event_ns=2, available_ns=2, price=Decimal("100"))
    future_split = CorporateActionV1(
        action="split",
        effective_ns=150,
        announced_ns=5,
        available_ns=5,
        split_ratio=Decimal("2"),
    )
    future_action = event(
        "future-known-split",
        event_ns=150,
        available_ns=5,
        kind="corporate_action",
        price=None,
        size=None,
        action=future_split,
    )

    before_effective, early = consume(
        (tick,),
        data=manifest(as_of_ns=5, end_ns=100),
        policy=AdjustmentPolicyV1(
            mode="split_only", version="adjustment-v1", view="BACK_ADJUSTED"
        ),
        action_snapshot=CorporateActionSnapshotV1(
            "known-before-effective", 5, "adjustment-v1", (future_action,)
        ),
    )
    after_effective, research = consume(
        (tick,),
        data=manifest(as_of_ns=200, end_ns=100),
        policy=AdjustmentPolicyV1(
            mode="split_only", version="adjustment-v1", view="BACK_ADJUSTED"
        ),
        action_snapshot=CorporateActionSnapshotV1(
            "known-after-effective", 200, "adjustment-v1", (future_action,)
        ),
    )
    pit_stream, pit = consume(
        (tick,),
        data=manifest(as_of_ns=200, end_ns=100),
        policy=AdjustmentPolicyV1(
            mode="split_only", version="adjustment-v1", view="PIT"
        ),
        action_snapshot=CorporateActionSnapshotV1(
            "pit-future-action", 200, "adjustment-v1", (future_action,)
        ),
    )

    assert early[0].adjusted_price == Decimal("100")
    assert early[0].applied_action_ids == ()
    assert early[0].view_as_of_ns == 5
    assert research[0].adjusted_price == Decimal("50")
    assert research[0].applied_action_ids
    assert research[0].view_as_of_ns == 200
    assert research[0].simulator_eligible is False
    assert pit[0].adjusted_price == Decimal("100")
    assert pit[0].applied_action_ids == ()
    assert pit[0].simulator_eligible is True
    assert before_effective.coverage.complete
    assert after_effective.coverage.complete
    assert pit_stream.coverage.complete


def test_correction_references_use_collision_free_canonical_json() -> None:
    streams = (
        StreamSpecV1("a", "a:b", "XNYS", priority=0),
        StreamSpecV1("b", "a", "XNYS", priority=1),
    )
    data = manifest(streams=streams, as_of_ns=30)
    stream_a = (
        event("c", stream_id="a", source="a:b", sequence=1, correction_key="d"),
        event(
            "c", stream_id="a", source="a:b", sequence=2, event_ns=10,
            available_ns=20, correction_key="e",
        ),
    )
    stream_b = (
        event("b:c", stream_id="b", source="a", sequence=1, correction_key="d"),
        event(
            "b:c", stream_id="b", source="a", sequence=2, event_ns=10,
            available_ns=20, correction_key="e",
        ),
    )

    stream, prepared = consume({"a": stream_a, "b": stream_b}, data=data)
    references = {
        item.raw.source: item.supersedes
        for item in prepared
        if item.supersedes is not None
    }

    assert references == {
        "a:b": json.dumps(["a:b", "c", "d"], separators=(",", ":")),
        "a": json.dumps(["a", "b:c", "d"], separators=(",", ":")),
    }
    assert len(set(references.values())) == 2
    for item in stream.correction_audit:
        if item.raw.correction_key == "d":
            expected = json.dumps(
                [item.raw.source, item.raw.source_id, "e"], separators=(",", ":")
            )
            assert item.superseded_by == expected


def test_adjustment_version_must_match_manifest_and_total_return_needs_declared_fx() -> None:
    with pytest.raises(AdjustmentError):
        consume((), policy=AdjustmentPolicyV1(mode="raw", version="other-version"))

    dividend = CorporateActionV1(
        action="dividend",
        effective_ns=1,
        announced_ns=1,
        available_ns=1,
        cash_amount=Decimal("1"),
        reference_price=Decimal("10"),
    )
    action_event = event(
        "dividend",
        event_ns=1,
        available_ns=1,
        kind="corporate_action",
        price=None,
        size=None,
        action=dividend,
    )
    dividend_snapshot = CorporateActionSnapshotV1(
        "dividend-snapshot", 100, "adjustment-v1", (action_event,)
    )
    with pytest.raises(AdjustmentError):
        consume(
            (event("tick", event_ns=2),),
            policy=AdjustmentPolicyV1(mode="split_plus_dividend", version="adjustment-v1"),
            action_snapshot=dividend_snapshot,
        )


def test_checkpoint_cannot_resume_under_a_different_manifest() -> None:
    all_events = (event("first", event_ns=1), event("second", event_ns=2, sequence=2))
    full_stream, uninterrupted = consume(all_events)
    first = prepare_events(
        manifest(),
        all_events,
        AdjustmentPolicyV1(mode="raw", version="adjustment-v1"),
        limit=1,
    )
    first_items = tuple(first)
    cursor = first.cursor
    changed_manifest = replace(manifest(), dataset_version="dataset-v2")

    resumed_stream = prepare_events(
        manifest(),
        all_events,
        AdjustmentPolicyV1(mode="raw", version="adjustment-v1"),
        cursor=cursor,
    )
    resumed = tuple(resumed_stream)
    assert len(uninterrupted) == 2
    assert len(resumed) == 1
    assert (*first_items, *resumed) == uninterrupted
    assert full_stream.stream_digest == resumed_stream.stream_digest

    with pytest.raises(CheckpointError):
        prepare_events(
            changed_manifest,
            (event("first", event_ns=1), event("second", event_ns=2)),
            AdjustmentPolicyV1(mode="raw", version="adjustment-v1"),
            cursor=cursor,
        )


def test_out_of_bound_lateness_fails_instead_of_using_arrival_order() -> None:
    events = (event("new", sequence=1, event_ns=10), event("too-late", sequence=2, event_ns=1))
    with pytest.raises(OutOfOrderError):
        consume(events)


def test_copy_pickle_reject_and_replace_validates_and_freezes_exact_record_types() -> None:
    mutable_members = [UniverseMemberV1("XYZ", "XNYS", 0)]
    pinned = replace(manifest(), universe=mutable_members)

    for clone in (lambda: copy(pinned), lambda: deepcopy(pinned), lambda: pickle.dumps(pinned)):
        with pytest.raises(TypeError):
            clone()

    pinned_stream, _ = consume((event("pinned"),), data=pinned)
    pinned_digest = pinned_stream.stream_digest
    mutable_members.append(UniverseMemberV1("Y", "XNYS", 0))

    assert pinned_stream.stream_digest == pinned_digest
    with pytest.raises(EventClockError):
        consume((event("outside", instrument="Y"),), data=pinned)

    @dataclass(frozen=True, slots=True)
    class ExtendedUniverseMember(UniverseMemberV1):
        notes: list[str] = field(kw_only=True)

    with pytest.raises(ManifestError):
        replace(
            manifest(),
            universe=(
                ExtendedUniverseMember("XYZ", "XNYS", 0, None, notes=["mutable"]),
            ),
        )
    with pytest.raises(ManifestError):
        replace(manifest(), max_identity_cache=0)
    with pytest.raises(EventValidationError):
        replace(event("invalid-replacement"), event_ns=True)

    mutable_levels = [BookLevelV1("bid", Decimal("9"), Decimal("1"))]
    raw = replace(
        event("snapshot", kind="book_snapshot", price=None, size=None),
        levels=mutable_levels,
    )
    for clone in (lambda: copy(raw), lambda: deepcopy(raw), lambda: pickle.dumps(raw)):
        with pytest.raises(TypeError):
            clone()
    assert isinstance(raw.levels, tuple)
    stream, prepared = consume((raw,))
    digest = stream.stream_digest
    mutable_levels.append(BookLevelV1("ask", Decimal("11"), Decimal("1")))

    assert stream.stream_digest == digest
    assert prepared[0].raw.levels == (BookLevelV1("bid", Decimal("9"), Decimal("1")),)


def test_as_of_rejects_early_available_future_event_and_filters_future_visible_tick() -> None:
    data = manifest(as_of_ns=50)
    impossible = event("future-event", event_ns=70, available_ns=30)
    with pytest.raises(EventClockError):
        consume((impossible,), data=data)

    not_yet_visible = event("future-visible", event_ns=30, available_ns=70)
    stream, prepared = consume((not_yet_visible,), data=data)
    assert prepared == ()
    assert stream.coverage.skipped_unavailable == 1


def test_correction_market_view_has_one_version_at_each_as_of_time() -> None:
    first = event(
        "same", event_ns=10, available_ns=10, sequence=1, correction_key="c1"
    )
    second = event(
        "same", event_ns=10, available_ns=20, sequence=2,
        correction_key="c2", price=Decimal("12"),
    )
    early_stream, early = consume(
        (first, second), data=manifest(as_of_ns=15)
    )
    late_stream, late = consume(
        (first, second), data=manifest(as_of_ns=25)
    )

    assert len(early) == len(late) == 1
    assert early[0].raw.correction_key == "c1"
    assert late[0].raw.correction_key == "c2"
    assert late[0].supersedes
    assert len(early_stream.correction_audit) == 1
    assert len(late_stream.correction_audit) == 2
    assert all(item.effective for item in early_stream.correction_audit)
    assert sum(item.effective for item in early_stream.correction_audit) == 1
    assert sum(item.effective for item in late_stream.correction_audit) == 1
    superseded = next(
        item for item in late_stream.correction_audit if item.raw.correction_key == "c1"
    )
    assert superseded.superseded_by


def test_decimal_digest_is_canonical_and_arithmetic_ignores_ambient_context() -> None:
    _, one_decimal = consume((event("canonical", price=Decimal("10.0")),))
    stream, two_decimals = consume((event("canonical", price=Decimal("10.00")),))
    assert one_decimal[0].raw.price == two_decimals[0].raw.price
    assert one_decimal[0].adjusted_price == two_decimals[0].adjusted_price
    first_stream, _ = consume((event("canonical", price=Decimal("10.0")),))
    assert stream.stream_digest == first_stream.stream_digest

    with localcontext() as context:
        context.Emax = 9
        context.Emin = -9
        _, large_value = consume((event("large-decimal", price=Decimal("1E+10")),))
    assert large_value[0].adjusted_price == Decimal("1E+10")

    precise = Decimal("1.2345678901234567890123456789")
    with localcontext() as context:
        context.prec = 6
        context.Emax = 9
        _, low_ambient_precision = consume((event("low-ambient", price=precise),))
    assert low_ambient_precision[0].adjusted_price == precise


def test_decimal_precision_excess_fails_and_final_quotient_rounds_once() -> None:
    over_precision = Decimal("12345678901234567890123456789012345")
    with pytest.raises(PrecisionExceededError, match="PRECISION_EXCEEDED"):
        consume((event("precision-overflow", price=over_precision),))

    tick = event("inexact-tick", event_ns=5, price=Decimal("10"))
    split = CorporateActionV1(
        action="split",
        effective_ns=10,
        announced_ns=1,
        available_ns=1,
        split_ratio=Decimal("3"),
    )
    action_event = event(
        "inexact-split",
        event_ns=10,
        available_ns=1,
        kind="corporate_action",
        price=None,
        size=None,
        action=split,
    )
    action_snapshot = CorporateActionSnapshotV1(
        "inexact-snapshot", 100, "adjustment-v1", (action_event,)
    )
    _, adjusted = consume(
        (tick,),
        policy=AdjustmentPolicyV1(mode="split_only", version="adjustment-v1"),
        action_snapshot=action_snapshot,
    )
    assert adjusted[0].adjusted_price == Decimal(
        "3.333333333333333333333333333333333"
    )


def test_integer_fields_reject_bool_through_constructor_and_replace() -> None:
    with pytest.raises(EventValidationError):
        replace(event("bool-event-time"), event_ns=True)
    with pytest.raises(ManifestError):
        replace(manifest(), as_of_ns=True)
    with pytest.raises(ManifestError):
        replace(manifest(), max_identity_cache=True)


def test_ascii_grammars_and_governed_capacity_bounds_are_enforced() -> None:
    with pytest.raises(ManifestError):
        replace(
            manifest(),
            source_checksums=(("feed-a", "a" * 63 + "\u00e9"),),
        )
    with pytest.raises(EventClockError):
        SessionWindowV1("XNYS", "\uff12\uff10\uff12\uff14-\uff10\uff11-\uff10\uff11", 0, 100)
    with pytest.raises(ManifestError):
        replace(manifest(), max_retained_book_levels=0)
    with pytest.raises(PolicyOutOfBoundsError, match="POLICY_OUT_OF_BOUNDS"):
        AdjustmentPolicyV1(
            mode="split_only", version="adjustment-v1", view="PIT_SIMULATION"
        )


def test_far_timestamp_and_lone_surrogate_fail_as_typed_event_errors() -> None:
    far_ns = 10**22
    with pytest.raises(EventClockError):
        far_data = manifest(as_of_ns=far_ns, end_ns=far_ns + 1)
        far_action = CorporateActionV1(
            action="split",
            effective_ns=far_ns,
            announced_ns=far_ns,
            available_ns=far_ns,
            split_ratio=Decimal("2"),
        )
        far_event = event(
            "far-action",
            event_ns=far_ns,
            available_ns=far_ns,
            kind="corporate_action",
            price=None,
            size=None,
            action=far_action,
        )
        far_snapshot = CorporateActionSnapshotV1(
            "far-actions", far_ns, "adjustment-v1", (far_event,)
        )
        consume(
            (),
            data=far_data,
            policy=AdjustmentPolicyV1(mode="split_only", version="adjustment-v1"),
            action_snapshot=far_snapshot,
        )

    secret = "SYNTHETIC_SECRET_SOURCE_ID"
    with pytest.raises(EventClockError) as failure:
        malformed = replace(event(secret), source_id=secret + "\ud800")
        consume((malformed,))
    assert secret not in str(failure.value)


@pytest.mark.parametrize(
    "wall_clock",
    (
        datetime(2024, 1, 2, 9, 30),
        datetime(2024, 11, 3, 1, 30),
    ),
    ids=("ordinary-eastern", "ambiguous-dst-fold"),
)
def test_naive_eastern_wall_clock_timestamp_is_not_silently_treated_as_utc(
    wall_clock: datetime,
) -> None:
    with pytest.raises(EventClockError):
        naive = replace(event("naive-wall-clock"), event_ns=wall_clock)
        consume((naive,))


def test_unavailable_sequence_is_recorded_as_gap_and_incomplete_coverage() -> None:
    events = (
        event("seq-1", sequence=1, event_ns=10, available_ns=10),
        event("seq-2", sequence=2, event_ns=11, available_ns=20),
        event("seq-3", sequence=3, event_ns=12, available_ns=12),
    )
    stream, prepared = consume(events, data=manifest(as_of_ns=15))

    assert [item.raw.sequence for item in prepared] == [1, 3]
    assert not stream.coverage.complete
    assert stream.coverage.gaps
    gap, = stream.coverage.gaps
    assert gap.kind == "GAP"
    assert gap.stream_id == "a"
    assert (gap.start_sequence, gap.end_sequence) == (2, 2)


def test_empty_quote_is_rejected_as_typed_invalid_market_data() -> None:
    empty = event(
        "empty-quote", kind="quote", price=None, size=None, levels=()
    )

    with pytest.raises(EventClockError):
        consume((empty,))


def test_aggregate_retained_book_budget_is_enforced_across_instruments() -> None:
    data = manifest(
        universe=(
            UniverseMemberV1("XYZ", "XNYS", 0),
            UniverseMemberV1("ABC", "XNYS", 0),
        ),
        max_retained_book_levels=1,
    )
    events = (
        event(
            "book-xyz",
            sequence=1,
            kind="book_snapshot",
            price=None,
            size=None,
            levels=(BookLevelV1("bid", Decimal("9"), Decimal("1")),),
        ),
        event(
            "book-abc",
            sequence=2,
            event_ns=11,
            instrument="ABC",
            kind="book_snapshot",
            price=None,
            size=None,
            levels=(BookLevelV1("ask", Decimal("11"), Decimal("1")),),
        ),
    )

    with pytest.raises(CapacityError, match="BOOK_BUDGET_EXCEEDED"):
        consume(events, data=data)


def test_identity_cache_budget_preflights_input_before_output() -> None:
    data = manifest(max_identity_cache=1)
    events = (event("first", sequence=1), event("second", sequence=2, event_ns=11))

    with pytest.raises(CapacityError):
        consume(events, data=data)


def test_future_correction_is_absent_from_earlier_audit_projection_and_gaps() -> None:
    original = event(
        "future-correction-target",
        event_ns=5,
        available_ns=5,
        sequence=1,
        correction_key="original",
    )
    later_correction = event(
        "future-correction-target",
        event_ns=5,
        available_ns=20,
        sequence=3,
        correction_key="corrected",
        price=Decimal("12"),
    )
    stream, prepared = consume(
        (original, later_correction), data=manifest(as_of_ns=10)
    )

    assert len(prepared) == 1
    assert prepared[0].raw.correction_key == "original"
    assert [item.raw.correction_key for item in stream.correction_audit] == [
        "original"
    ]
    assert all(item.effective for item in stream.correction_audit)
    assert stream.coverage.observed_gaps == ()
    assert stream.coverage.gaps == ()
    assert stream.coverage.complete


def test_pit_projection_orders_events_by_monotonic_visible_time() -> None:
    late_visible = event(
        "event-time-first",
        event_ns=5,
        available_ns=20,
        sequence=1,
    )
    visible_first = event(
        "available-first",
        event_ns=10,
        available_ns=10,
        sequence=2,
    )

    _, prepared = consume(
        (late_visible, visible_first),
        data=manifest(as_of_ns=25),
        policy=AdjustmentPolicyV1(
            mode="raw", version="adjustment-v1", view="PIT"
        ),
    )

    assert [item.raw.source_id for item in prepared] == [
        "available-first",
        "event-time-first",
    ]
    assert [item.visible_ns for item in prepared] == [10, 20]
    assert all(item.simulator_eligible for item in prepared)
    assert [item.raw.event_ns for item in prepared] == [10, 5]


def test_pit_correction_versions_are_observed_causally() -> None:
    original = event(
        "pit-correction",
        event_ns=5,
        available_ns=5,
        sequence=1,
        correction_key="original",
        price=Decimal("10"),
    )
    corrected = event(
        "pit-correction",
        event_ns=5,
        available_ns=20,
        sequence=2,
        correction_key="corrected",
        price=Decimal("12"),
    )

    stream, prepared = consume(
        (original, corrected),
        data=manifest(as_of_ns=25),
        policy=AdjustmentPolicyV1(
            mode="raw", version="adjustment-v1", view="PIT"
        ),
    )

    assert [item.raw.correction_key for item in prepared] == [
        "original",
        "corrected",
    ]
    assert [item.visible_ns for item in prepared] == [5, 20]
    assert [item.raw.price for item in prepared] == [Decimal("10"), Decimal("12")]
    assert len(stream.correction_audit) == 2
    assert sum(item.effective for item in stream.correction_audit) == 1


def test_prepared_research_result_cannot_be_relabelled_as_pit() -> None:
    tick = event("relabel-tick", event_ns=5, price=Decimal("100"))
    split = CorporateActionV1(
        action="split",
        effective_ns=10,
        announced_ns=1,
        available_ns=1,
        split_ratio=Decimal("2"),
    )
    action = event(
        "relabel-split",
        sequence=None,
        event_ns=10,
        available_ns=1,
        kind="corporate_action",
        price=None,
        size=None,
        action=split,
    )
    _, research = consume(
        (tick,),
        policy=AdjustmentPolicyV1(
            mode="split_only", version="adjustment-v1", view="BACK_ADJUSTED"
        ),
        action_snapshot=CorporateActionSnapshotV1(
            "relabel-actions", 100, "adjustment-v1", (action,)
        ),
    )
    assert research[0].adjusted_price == Decimal("50")
    assert not research[0].simulator_eligible

    with pytest.raises(EventClockError):
        replace(research[0], view="PIT", view_as_of_ns=None)

    class ViewRelabel(str):
        def __eq__(self, other: object) -> bool:
            return other in ("PIT", "BACK_ADJUSTED")

        __hash__ = str.__hash__

    forged_view = ViewRelabel("BACK_ADJUSTED")
    assert str(forged_view) == "BACK_ADJUSTED"
    with pytest.raises(PolicyOutOfBoundsError):
        AdjustmentPolicyV1(
            mode="raw", version="adjustment-v1", view=forged_view
        )


def test_exact_rational_split_and_dividend_factors_succeed() -> None:
    tick = event("exact-rational-tick", event_ns=5, price=Decimal("3"))
    split = CorporateActionV1(
        action="split",
        effective_ns=10,
        announced_ns=1,
        available_ns=1,
        split_ratio=Decimal("3"),
    )
    split_event = event(
        "exact-three-for-one",
        sequence=None,
        event_ns=10,
        available_ns=1,
        kind="corporate_action",
        price=None,
        size=None,
        action=split,
    )
    _, split_result = consume(
        (tick,),
        policy=AdjustmentPolicyV1(
            mode="split_only", version="adjustment-v1"
        ),
        action_snapshot=CorporateActionSnapshotV1(
            "exact-split-actions", 100, "adjustment-v1", (split_event,)
        ),
    )
    assert split_result[0].adjusted_price == Decimal("1")

    dividend = CorporateActionV1(
        action="dividend",
        effective_ns=10,
        announced_ns=1,
        available_ns=1,
        cash_amount=Decimal("1"),
        cash_currency="USD",
        fx_rate=Decimal("1"),
        fx_pair="USD/USD",
        reference_price=Decimal("3"),
        price_currency="USD",
    )
    dividend_event = event(
        "exact-two-thirds-dividend",
        sequence=None,
        event_ns=10,
        available_ns=1,
        kind="corporate_action",
        price=None,
        size=None,
        action=dividend,
    )
    _, dividend_result = consume(
        (tick,),
        policy=AdjustmentPolicyV1(
            mode="split_plus_dividend", version="adjustment-v1"
        ),
        action_snapshot=CorporateActionSnapshotV1(
            "exact-dividend-actions", 100, "adjustment-v1", (dividend_event,)
        ),
    )
    assert dividend_result[0].adjusted_price == Decimal("2")


def test_distinct_actions_keep_canonical_ids_and_journal_entries() -> None:
    def action_record(
        stream_id: str, source: str, source_id: str, correction_key: str
    ) -> MarketEventV1:
        split = CorporateActionV1(
            action="split",
            effective_ns=10,
            announced_ns=1,
            available_ns=1,
            split_ratio=Decimal("2"),
        )
        return event(
            source_id,
            stream_id=stream_id,
            source=source,
            correction_key=correction_key,
            sequence=None,
            event_ns=10,
            available_ns=1,
            kind="corporate_action",
            price=None,
            size=None,
            action=split,
        )

    actions = (
        action_record("a", "feed-a", "b", "c:d"),
        action_record("a", "feed-a", "b:c", "d"),
        action_record("a", "feed-a", "shared", "first"),
        action_record("b", "feed-b", "shared", "second"),
    )
    data = manifest(
        streams=(
            StreamSpecV1("a", "feed-a", "XNYS", priority=0),
            StreamSpecV1("b", "feed-b", "XNYS", priority=1),
        )
    )
    stream, prepared = consume(
        {
            "a": (event("multi-action-tick", event_ns=5, price=Decimal("100")),),
            "b": (),
        },
        data=data,
        policy=AdjustmentPolicyV1(
            mode="split_only", version="adjustment-v1"
        ),
        action_snapshot=CorporateActionSnapshotV1(
            "distinct-actions", 100, "adjustment-v1", actions
        ),
    )

    expected_ids = {
        json.dumps([source, source_id, key], separators=(",", ":"))
        for source, source_id, key in (
            ("feed-a", "b", "c:d"),
            ("feed-a", "b:c", "d"),
            ("feed-a", "shared", "first"),
            ("feed-b", "shared", "second"),
        )
    }
    assert prepared[0].adjusted_price == Decimal("6.25")
    assert len(prepared[0].applied_action_ids) == 4
    assert set(prepared[0].applied_action_ids) == expected_ids
    assert len(stream.adjustment_journal) == 4


def test_checkpoint_version_rejects_bool() -> None:
    all_events = (event("cursor-one", sequence=1), event("cursor-two", sequence=2, event_ns=11))
    partial = prepare_events(
        manifest(),
        all_events,
        AdjustmentPolicyV1(mode="raw", version="adjustment-v1"),
        limit=1,
    )
    tuple(partial)
    cursor = partial.cursor
    assert cursor is not None

    with pytest.raises(CheckpointError):
        invalid_cursor = replace(cursor, version=True)
        prepare_events(
            manifest(),
            all_events,
            AdjustmentPolicyV1(mode="raw", version="adjustment-v1"),
            cursor=invalid_cursor,
        )


def test_typed_unicode_validation_error_has_no_raw_input_in_exception_chain() -> None:
    canary = "SECRET_CANARY_42"
    invalid_checksum = canary + "\ud800" + "a" * 48

    with pytest.raises(ManifestError) as failure:
        replace(
            manifest(),
            source_checksums=(("feed-a", invalid_checksum),),
        )

    error = failure.value
    assert error.__cause__ is None
    for chained in (error.__cause__, error.__context__):
        if chained is not None:
            assert canary not in str(chained)
            assert canary not in repr(chained)
            chained_object = getattr(chained, "object", None)
            assert not isinstance(chained_object, str) or canary not in chained_object


def test_equal_pit_events_keep_identity_issuance_after_peer_is_collected() -> None:
    tick = event("equal-pit-issuance", event_ns=5, available_ns=5)
    pit = AdjustmentPolicyV1(mode="raw", version="adjustment-v1", view="PIT")
    _, first_result = consume((tick,), policy=pit)
    _, second_result = consume((tick,), policy=pit)
    first = first_result[0]
    second = second_result[0]

    assert first is not second
    assert first == second
    assert first.simulator_eligible
    assert second.simulator_eligible

    same_event_values = {
        item.name: getattr(first, item.name) for item in fields(first) if item.init
    }
    with pytest.raises(EventValidationError):
        type(first).__init__(first, **same_event_values)
    assert first.simulator_eligible

    research_policy = AdjustmentPolicyV1(
        mode="raw", version="adjustment-v1", view="BACK_ADJUSTED"
    )
    _, research_result = consume((tick,), policy=research_policy)
    relabelled_research = research_result[0]
    object.__setattr__(relabelled_research, "view", "PIT")
    object.__setattr__(relabelled_research, "view_as_of_ns", None)

    assert relabelled_research == second
    assert not relabelled_research.simulator_eligible

    _, tampered_result = consume((tick,), policy=pit)
    tampered_pit = tampered_result[0]
    assert tampered_pit.simulator_eligible
    object.__setattr__(tampered_pit, "visible_ns", tampered_pit.visible_ns + 1)
    assert not tampered_pit.simulator_eligible

    del first
    del first_result
    gc.collect()

    assert second.simulator_eligible


def test_same_visible_correction_chronology_agrees_across_views() -> None:
    original = event(
        "same-visible-correction",
        event_ns=5,
        available_ns=5,
        sequence=1,
        correction_key="z",
        price=Decimal("10"),
    )
    correction = event(
        "same-visible-correction",
        event_ns=5,
        available_ns=5,
        sequence=2,
        correction_key="a",
        price=Decimal("12"),
    )
    input_events = (original, correction)
    pit_policy = AdjustmentPolicyV1(
        mode="raw", version="adjustment-v1", view="PIT"
    )
    pit_stream, pit_events = consume(input_events, policy=pit_policy)

    assert [item.raw.price for item in pit_events] == [Decimal("10"), Decimal("12")]
    effective_rows = [row for row in pit_stream.correction_audit if row.effective]
    assert len(effective_rows) == 1
    assert effective_rows[0].raw.sequence == 2
    assert effective_rows[0].raw.correction_key == "a"
    assert effective_rows[0].raw.price == Decimal("12")

    research_policy = AdjustmentPolicyV1(
        mode="raw", version="adjustment-v1", view="BACK_ADJUSTED"
    )
    _, research_events = consume(input_events, policy=research_policy)
    assert len(research_events) == 1
    assert research_events[0].raw.price == Decimal("12")
    assert research_events[0].raw.sequence == 2
    assert research_events[0].raw.correction_key == "a"


def test_raw_pit_stream_rejects_external_adjustment_engine_replacement() -> None:
    data = manifest()
    tick = event("b24-raw-tick", event_ns=5, available_ns=20, price=Decimal("10"))
    split = CorporateActionV1(
        action="split",
        effective_ns=10,
        announced_ns=10,
        available_ns=10,
        split_ratio=Decimal("2"),
    )
    action = event(
        "b24-external-split",
        sequence=None,
        event_ns=10,
        available_ns=10,
        kind="corporate_action",
        price=None,
        size=None,
        action=split,
    )
    external_snapshot = CorporateActionSnapshotV1(
        "b24-external-actions", data.as_of_ns, "adjustment-v1", (action,)
    )
    raw_pit_policy = AdjustmentPolicyV1(
        "raw", "adjustment-v1", view="PIT"
    )
    stream = prepare_events(data, (tick,), raw_pit_policy)

    assert stream.simulator_eligible
    with pytest.raises(EventValidationError):
        type(stream).__init__(stream, data, (tick,), raw_pit_policy, None, None, None)
    assert stream.simulator_eligible
    assert stream.action_snapshot_digest == sha256(b"").hexdigest()
    with pytest.raises((AttributeError, EventClockError)) as replacement:
        stream._adjustments = AdjustmentEngine(
            AdjustmentPolicyV1(
                "split_only", "adjustment-v1", view="PIT"
            ),
            external_snapshot,
            data.as_of_ns,
        )
    if isinstance(replacement.value, EventClockError):
        assert str(replacement.value) == "SEALED_STREAM_TAMPERED"

    prepared = next(stream)
    assert prepared.simulator_eligible
    assert prepared.raw.price == Decimal("10")
    assert prepared.adjusted_price == Decimal("10")
    assert prepared.applied_action_ids == ()
    assert prepared.action_snapshot_id == ""


def test_sealed_stream_checks_inputs_before_each_next_emission() -> None:
    ticks = (
        event("b24-first", sequence=1, event_ns=5),
        event("b24-second", sequence=2, event_ns=6),
    )
    stream = prepare_events(
        manifest(),
        ticks,
        AdjustmentPolicyV1("raw", "adjustment-v1", view="PIT"),
    )

    first = next(stream)
    assert first.raw.source_id == "b24-first"
    assert stream.event_count == 1
    object.__setattr__(stream, "_projection", ())

    with pytest.raises(EventClockError, match="SEALED_STREAM_TAMPERED"):
        next(stream)
    with pytest.raises(EventClockError, match="SEALED_STREAM_TAMPERED"):
        _ = stream.event_count

@pytest.mark.parametrize("tamper_pinned_action", (False, True))
def test_split_action_snapshot_tampering_cannot_change_pit_adjustment(
    tamper_pinned_action: bool,
) -> None:
    data = manifest()
    tick = event(
        f"b25-tick-{tamper_pinned_action}",
        event_ns=5,
        available_ns=20,
        price=Decimal("10"),
    )
    split = CorporateActionV1(
        action="split",
        effective_ns=10,
        announced_ns=10,
        available_ns=10,
        split_ratio=Decimal("2"),
    )
    split_event = event(
        f"b25-split-{tamper_pinned_action}",
        sequence=None,
        event_ns=10,
        available_ns=10,
        kind="corporate_action",
        price=None,
        size=None,
        action=split,
    )
    snapshot = CorporateActionSnapshotV1(
        f"b25-snapshot-{tamper_pinned_action}",
        data.as_of_ns,
        "adjustment-v1",
        (split_event,),
    )
    policy = AdjustmentPolicyV1("split_only", "adjustment-v1", view="PIT")
    stream = prepare_events(data, (tick,), policy, action_snapshot=snapshot)

    if tamper_pinned_action:
        pinned_action = stream._action_snapshot.actions[0].action
        assert pinned_action is not None
        object.__setattr__(pinned_action, "split_ratio", Decimal("4"))
        with pytest.raises(EventClockError, match="SEALED_STREAM_TAMPERED") as failure:
            next(stream)
        assert failure.value.args == ("SEALED_STREAM_TAMPERED",)
        assert failure.value.__cause__ is None
        assert failure.value.__context__ is None
        with pytest.raises(EventClockError, match="SEALED_STREAM_TAMPERED") as count_failure:
            _ = stream.event_count
        assert count_failure.value.__context__ is None
        assert not stream.simulator_eligible
    else:
        assert snapshot.actions[0].action is not None
        object.__setattr__(snapshot.actions[0].action, "split_ratio", Decimal("4"))
        assert split_event.action is not None
        object.__setattr__(split_event.action, "split_ratio", Decimal("4"))
        prepared = next(stream)
        assert prepared.simulator_eligible
        assert prepared.raw.price == Decimal("10")
        assert prepared.adjusted_price == Decimal("5")
        assert prepared.adjusted_price != Decimal("2.5")




