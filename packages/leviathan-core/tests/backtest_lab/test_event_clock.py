"""BT-002 unit proofs for ordering, bounded replay and remediation regressions."""

import gc
import pickle
import weakref
from copy import copy, deepcopy
from dataclasses import dataclass, field, replace
from datetime import datetime
from decimal import Decimal, Overflow, localcontext

import pytest

from leviathan_core.backtest_lab import (
    AdjustmentPolicyV1,
    BookBudgetExceeded,
    BookLevelV1,
    BookStateError,
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
    SealedStreamTamperedError,
    SequenceGapError,
    SessionWindowV1,
    StreamSpecV1,
    UniverseMemberV1,
    prepare_events,
)
from leviathan_core.backtest_lab.adjustments import AdjustmentEngine
from leviathan_core.numeric import Ratio


def manifest(*, streams: tuple[StreamSpecV1, ...] | None = None) -> DatasetManifestV1:
    if streams is None:
        streams = (StreamSpecV1("s", "vendor", "X", 0),)
    return DatasetManifestV1(
        "dataset", "v1", "u1", "map1", "calendar", "cal1", "a1",
        1000, 0, 1000, (("vendor", "a" * 64),),
        (UniverseMemberV1("ABC", "X", 0, 1000),),
        (SessionWindowV1("X", "1970-01-01", 0, 1000),),
        streams, 1000,
    )


def event(timestamp: int, source_id: str, **changes: object) -> MarketEventV1:
    result = MarketEventV1(
        "dataset", "v1", "u1", "vendor", source_id, "base", "s",
        timestamp, timestamp, "ABC", "X", None, "trade", Decimal("10"), Decimal("2"),
    )
    return replace(result, **changes)


def test_nanosecond_order_and_tie_permutations() -> None:
    spec = StreamSpecV1("s", "vendor", "X", 0)
    source = [event(101, "b"), event(100, "z"), event(100, "a")]
    with pytest.raises(OutOfOrderError, match=r"^OUT_OF_ORDER$") as failure:
        list(prepare_events(manifest(), source, AdjustmentPolicyV1("raw", "a1")))
    assert failure.value.stream_id == "s" and failure.value.sequence is None
    a, z, b = event(100, "a"), event(100, "z"), event(101, "b")
    first = prepare_events(manifest(streams=(spec,)), [z, a, b], AdjustmentPolicyV1("raw", "a1"))
    second = prepare_events(manifest(streams=(spec,)), [a, z, b], AdjustmentPolicyV1("raw", "a1"))
    assert [item.raw.source_id for item in first] == ["a", "z", "b"]
    assert [item.raw.source_id for item in second] == ["a", "z", "b"]
    assert first.stream_digest == second.stream_digest


def test_bounded_reorder_and_out_of_bound_rejection() -> None:
    delayed = replace(manifest(), streams=(StreamSpecV1("s", "vendor", "X", 0, 2),))
    result = prepare_events(
        delayed, [event(101, "b"), event(100, "a"), event(103, "c")],
        AdjustmentPolicyV1("raw", "a1"),
    )
    assert [item.raw.event_ns for item in result] == [100, 101, 103]
    with pytest.raises(OutOfOrderError, match=r"^OUT_OF_ORDER$") as failure:
        list(prepare_events(
            delayed, [event(104, "b"), event(100, "a")], AdjustmentPolicyV1("raw", "a1")
        ))
    assert failure.value.stream_id == "s" and failure.value.sequence is None


def test_sequence_gap_and_book_snapshot_validation() -> None:
    e1 = event(100, "snapshot", sequence=1, kind="book_snapshot", price=None, size=None, levels=(
        BookLevelV1("bid", Decimal("9"), Decimal("1")),
        BookLevelV1("ask", Decimal("11"), Decimal("1")),
    ))
    e2 = event(101, "delta", sequence=3, kind="book_delta", price=None, size=None, levels=(
        BookLevelV1("bid", Decimal("10"), Decimal("1")),
    ))
    with pytest.raises(SequenceGapError):
        list(prepare_events(manifest(), [e1, e2], AdjustmentPolicyV1("raw", "a1")))
    with pytest.raises(BookStateError):
        list(prepare_events(manifest(), [replace(e2, sequence=1)], AdjustmentPolicyV1("raw", "a1")))
    with pytest.raises(BookStateError, match="crossed"):
        list(prepare_events(manifest(), [replace(e1, levels=(
            BookLevelV1("bid", Decimal("12"), Decimal("1")),
            BookLevelV1("ask", Decimal("11"), Decimal("1")),
        ))], AdjustmentPolicyV1("raw", "a1")))


def test_adjustments_are_causal_and_raw_is_auditable() -> None:
    action = CorporateActionV1("split", 200, 190, 190, split_ratio=Decimal("2"))
    action_event = event(
        200, "action", kind="corporate_action", available_ns=190,
        price=None, size=None, action=action,
    )
    snapshot = CorporateActionSnapshotV1("actions-1", 1000, "a1", (action_event,))
    events = [event(100, "before", price=Decimal("100")),
              event(201, "after", price=Decimal("50"), size=Decimal("4"))]
    result = prepare_events(
        manifest(), events, AdjustmentPolicyV1("split_only", "a1"), action_snapshot=snapshot
    )
    prepared = list(result)
    assert [item.adjusted_price for item in prepared] == [Decimal("50"), Decimal("50")]
    assert prepared[0].raw.price == Decimal("100")
    assert prepared[0].adjusted_size == Decimal("4")
    assert prepared[0].applied_action_ids == ('["vendor","action","base"]',)
    assert prepared[0].action_snapshot_id == "actions-1"
    assert prepared[1].applied_action_ids == ()
    assert len(result.adjustment_journal) == 1
    assert result.adjustment_journal[0].action_source_id == "action"
    too_early = replace(manifest(), as_of_ns=199)
    early_snapshot = CorporateActionSnapshotV1("actions-early", 199, "a1", ())
    earlier = prepare_events(
        too_early, events, AdjustmentPolicyV1("split_only", "a1"),
        action_snapshot=early_snapshot,
    )
    assert [item.raw.source_id for item in earlier] == ["before"]
    assert earlier.adjustment_journal == ()
    assert earlier.coverage.skipped_unavailable == 1


def test_checkpoint_replays_prefix_and_rejects_wrong_input() -> None:
    events = [event(100 + n, str(n)) for n in range(5)]
    policy = AdjustmentPolicyV1("raw", "a1")
    first = prepare_events(manifest(), events, policy, limit=2)
    prefix = list(first)
    assert len(prefix) == 2
    continuation = prepare_events(manifest(), events, policy, first.cursor)
    suffix = list(continuation)
    whole = prepare_events(manifest(), events, policy)
    assert [item.raw.source_id for item in prefix + suffix] == [
        item.raw.source_id for item in whole
    ]
    assert continuation.stream_digest == whole.stream_digest
    with pytest.raises(CheckpointError, match="prior digest"):
        list(prepare_events(manifest(), [event(100, "changed"), *events[1:]], policy, first.cursor))


def test_point_in_time_membership_rejects_delisted_symbol() -> None:
    data = replace(manifest(), universe=(UniverseMemberV1("ABC", "X", 0, 150),))
    with pytest.raises(EventValidationError, match="point-in-time"):
        list(prepare_events(data, [event(151, "late")], AdjustmentPolicyV1("raw", "a1")))


def test_k_way_merge_is_independent_of_mapping_order_and_exposes_visibility() -> None:
    data = replace(
        manifest(),
        source_checksums=(("vendor", "a" * 64), ("other", "b" * 64)),
        streams=(StreamSpecV1("s", "vendor", "X", 1), StreamSpecV1("other", "other", "X", 0)),
    )
    first = event(10, "first", available_ns=12)
    second = replace(event(10, "second"), source="other", stream_id="other")
    a = prepare_events(data, {"s": [first], "other": [second]}, AdjustmentPolicyV1("raw", "a1"))
    b = prepare_events(data, {"other": [second], "s": [first]}, AdjustmentPolicyV1("raw", "a1"))
    left, right = list(a), list(b)
    assert [item.raw.source_id for item in left] == ["second", "first"]
    assert left == right
    assert a.stream_digest == b.stream_digest
    assert left[-1].visible_ns == 12


def test_split_adjusts_l2_levels_and_declared_dividend_fx() -> None:
    split = CorporateActionV1("split", 200, 90, 90, split_ratio=Decimal("2"))
    book = event(
        101, "book", kind="book_snapshot", price=None, size=None,
        levels=(
            BookLevelV1("bid", Decimal("5"), Decimal("4")),
            BookLevelV1("ask", Decimal("6"), Decimal("4")),
        ),
    )
    split_event = event(
        200, "split", kind="corporate_action", available_ns=90,
        price=None, size=None, action=split,
    )
    split_snapshot = CorporateActionSnapshotV1("split-snapshot", 1000, "a1", (split_event,))
    prepared = list(prepare_events(
        manifest(), [book], AdjustmentPolicyV1("split_only", "a1"),
        action_snapshot=split_snapshot,
    ))
    assert prepared[0].raw.levels[0].price == Decimal("5")
    assert prepared[0].adjusted_levels[0].price == Decimal("2.5")
    assert prepared[0].adjusted_levels[0].size == Decimal("8")

    dividend = CorporateActionV1(
        "dividend", 200, 90, 90,
        cash_amount=Decimal("2"), cash_currency="USD", fx_rate=Decimal("1"),
        fx_pair="USD/USD", reference_price=Decimal("10"), price_currency="USD",
    )
    dividend_event = event(
        200, "div", kind="corporate_action", available_ns=90,
        price=None, size=None, action=dividend,
    )
    tick = event(101, "tick", price=Decimal("8"))
    dividend_snapshot = CorporateActionSnapshotV1("div-snapshot", 1000, "a1", (dividend_event,))
    adjusted = list(prepare_events(
        manifest(), [tick], AdjustmentPolicyV1("split_plus_dividend", "a1"),
        action_snapshot=dividend_snapshot,
    ))
    assert adjusted[-1].adjusted_price == Decimal("6.4")

    raw_dividend = replace(
        dividend, fx_rate=None, fx_pair=None, reference_price=None, price_currency=None
    )
    raw_event = replace(dividend_event, action=raw_dividend)
    raw_snapshot = CorporateActionSnapshotV1("raw-div", 1000, "a1", (raw_event,))
    raw = list(prepare_events(
        manifest(), [tick], AdjustmentPolicyV1("raw", "a1"), action_snapshot=raw_snapshot
    ))
    assert raw[-1].adjusted_price == tick.price


def test_nested_inputs_are_frozen_before_digest_and_after_copy() -> None:
    members = [UniverseMemberV1("ABC", "X", 0, 1000)]
    data = replace(manifest(), universe=members)
    levels = [BookLevelV1("bid", Decimal("9"), Decimal("1"))]
    record = event(10, "book", kind="book_snapshot", price=None, size=None, levels=levels)
    prepared = prepare_events(data, [record], AdjustmentPolicyV1("raw", "a1"))
    pinned_digest = prepared.manifest_digest
    members.append(UniverseMemberV1("OTHER", "X", 0, 1000))
    levels[0] = BookLevelV1("bid", Decimal("8"), Decimal("1"))
    assert len(data.universe) == 1
    assert next(iter(prepared)).raw.levels[0].price == Decimal("9")
    assert prepared.manifest_digest == pinned_digest
    for clone in (lambda: copy(data), lambda: deepcopy(data), lambda: pickle.dumps(data)):
        with pytest.raises(TypeError):
            clone()
    changed = replace(data, universe=(UniverseMemberV1("OTHER", "X", 0, 1000),))
    assert changed != data and prepared.manifest_digest == pinned_digest


def test_as_of_bounds_event_and_visibility_and_rejects_early_market_data() -> None:
    data = replace(manifest(), as_of_ns=50)
    future = prepare_events(data, [event(70, "future")], AdjustmentPolicyV1("raw", "a1"))
    assert list(future) == []
    assert not future.coverage.complete
    with pytest.raises(EventValidationError, match="before source event time"):
        prepare_events(
            data, [event(70, "impossible", available_ns=30)], AdjustmentPolicyV1("raw", "a1")
        )


def test_one_effective_correction_and_explicit_audit_links() -> None:
    original = event(10, "same", correction_key="orig", sequence=1, price=Decimal("10"))
    corrected = event(
        10, "same", correction_key="fix", sequence=1, available_ns=20,
        price=Decimal("12"),
    )
    later = prepare_events(manifest(), [original, corrected], AdjustmentPolicyV1("raw", "a1"))
    selected = list(later)
    assert len(selected) == 1 and selected[0].raw.price == Decimal("12")
    assert selected[0].supersedes == '["vendor","same","orig"]'
    assert len(later.correction_audit) == 2
    assert later.correction_audit[0].superseded_by == '["vendor","same","fix"]'
    assert later.correction_audit[1].effective
    earlier = prepare_events(
        replace(manifest(), as_of_ns=15), [original, corrected],
        AdjustmentPolicyV1("raw", "a1"),
    )
    assert [item.raw.price for item in earlier] == [Decimal("10")]


def test_decimal_digest_and_arithmetic_ignore_ambient_context() -> None:
    policy = AdjustmentPolicyV1("raw", "a1")
    a = prepare_events(manifest(), [event(10, "id", price=Decimal("10.0"))], policy)
    b = prepare_events(manifest(), [event(10, "id", price=Decimal("10.00"))], policy)
    list(a)
    list(b)
    assert a.stream_digest == b.stream_digest
    with localcontext() as context:
        context.Emax = 9
        context.traps[Overflow] = True
        result = prepare_events(
            manifest(), [event(10, "big", price=Decimal("1E+10"))], policy
        )
        assert next(iter(result)).adjusted_price == Decimal("1E+10")
    with pytest.raises(EventValidationError, match="exponent"):
        prepare_events(manifest(), [event(10, "too-big", price=Decimal("1E+50"))], policy)


def test_far_time_naive_local_time_and_surrogate_raise_typed_errors() -> None:
    with pytest.raises(EventClockError, match="UTC nanosecond"):
        prepare_events(
            replace(manifest(), as_of_ns=10**22), [], AdjustmentPolicyV1("raw", "a1")
        )
    with pytest.raises(EventValidationError, match="UTC nanosecond"):
        prepare_events(
            manifest(), [event(10, "local", event_ns=datetime(2026, 9, 30, 9))],
            AdjustmentPolicyV1("raw", "a1"),
        )
    with pytest.raises(EventValidationError):
        prepare_events(
            manifest(), [event(10, "\ud800")], AdjustmentPolicyV1("raw", "a1")
        )


def test_filtered_sequence_creates_gap_and_blocks_complete_coverage() -> None:
    data = replace(manifest(), as_of_ns=3)
    records = [
        event(1, "one", sequence=1),
        event(2, "two", sequence=2, available_ns=4),
        event(3, "three", sequence=3),
    ]
    result = prepare_events(data, records, AdjustmentPolicyV1("raw", "a1"))
    assert [item.raw.sequence for item in result] == [1, 3]
    assert result.coverage.gaps[0].kind == "GAP"
    assert result.coverage.gaps[0].start_sequence == 2
    assert result.coverage.gaps[0].reason == "UNAVAILABLE_AS_OF"
    assert not result.coverage.complete


def test_quote_requires_typed_side() -> None:
    with pytest.raises(EventValidationError, match="empty quote"):
        prepare_events(
            manifest(), [event(10, "empty", kind="quote", price=None, size=None)],
            AdjustmentPolicyV1("raw", "a1"),
        )
    quote = event(
        10, "bid", kind="quote", price=None, size=None,
        bid_price=Decimal("9"), bid_size=Decimal("2"),
    )
    result = prepare_events(manifest(), [quote], AdjustmentPolicyV1("raw", "a1"))
    assert next(iter(result)).raw == quote


def test_aggregate_l2_budget_fails_before_retaining_second_book() -> None:
    data = replace(
        manifest(), universe=(
            UniverseMemberV1("ABC", "X", 0, 1000),
            UniverseMemberV1("DEF", "X", 0, 1000),
        ), max_retained_book_levels=1,
    )
    first = event(
        10, "first", kind="book_snapshot", price=None, size=None,
        levels=(BookLevelV1("bid", Decimal("9"), Decimal("1")),),
    )
    second = event(
        11, "second", instrument="DEF", kind="book_snapshot", price=None, size=None,
        levels=(BookLevelV1("bid", Decimal("8"), Decimal("1")),),
    )
    with pytest.raises(BookBudgetExceeded, match="BOOK_BUDGET_EXCEEDED"):
        list(prepare_events(data, [first, second], AdjustmentPolicyV1("raw", "a1")))


def test_cycle2_exact_nested_records_and_reconstruction_validation() -> None:
    @dataclass(frozen=True, slots=True)
    class ExtendedMember(UniverseMemberV1):
        notes: list[str] = field(default_factory=list)

    with pytest.raises(ManifestError):
        replace(manifest(), universe=(ExtendedMember("ABC", "X", 0),))
    with pytest.raises(ManifestError):
        replace(manifest(), max_identity_cache=0)
    with pytest.raises(EventValidationError):
        replace(event(5, "bool"), event_ns=True)
    with pytest.raises(PolicyOutOfBoundsError, match="POLICY_OUT_OF_BOUNDS"):
        replace(AdjustmentPolicyV1("raw", "a1"), view="UNKNOWN")


def test_cycle2_pit_observation_and_labelled_research_view() -> None:
    tick = event(5, "tick", price=Decimal("100"))
    split = CorporateActionV1("split", 10, 9, 9, split_ratio=Decimal("2"))
    action = event(
        10, "split", kind="corporate_action", available_ns=9,
        price=None, size=None, action=split,
    )
    snapshot = CorporateActionSnapshotV1("actions", 1000, "a1", (action,))
    pit = prepare_events(
        manifest(), (tick,), AdjustmentPolicyV1("split_only", "a1", "PIT"),
        action_snapshot=snapshot,
    )
    research = prepare_events(
        manifest(), (tick,), AdjustmentPolicyV1("split_only", "a1"),
        action_snapshot=snapshot,
    )
    pit_tick, research_tick = next(pit), next(research)
    assert pit_tick.adjusted_price == Decimal("100")
    assert pit_tick.view == "PIT" and pit_tick.view_as_of_ns is None
    assert pit_tick.simulator_eligible and pit.simulator_eligible
    assert research_tick.adjusted_price == Decimal("50")
    assert research_tick.view == "BACK_ADJUSTED" and research_tick.view_as_of_ns == 1000
    assert not research_tick.simulator_eligible and not research.simulator_eligible


def test_cycle2_precision_and_inexact_arithmetic_are_typed() -> None:
    with pytest.raises(PrecisionExceededError, match="PRECISION_EXCEEDED"):
        prepare_events(
            manifest(),
            (event(5, "precise", price=Decimal("1.2345678901234567890123456789012345")),),
            AdjustmentPolicyV1("raw", "a1"),
        )
    split = CorporateActionV1("split", 10, 1, 1, split_ratio=Decimal("3"))
    action = event(
        10, "split", kind="corporate_action", available_ns=1,
        price=None, size=None, action=split,
    )
    snapshot = CorporateActionSnapshotV1("actions", 1000, "a1", (action,))
    adjusted = list(prepare_events(
        manifest(), (event(5, "tick"),), AdjustmentPolicyV1("split_only", "a1"),
        action_snapshot=snapshot,
    ))
    assert adjusted[0].adjusted_price == Decimal("3.333333333333333333333333333333333")


def test_cycle2_action_snapshot_outside_tick_interval_and_future_effective() -> None:
    data = replace(manifest(), end_ns=100, as_of_ns=200, sessions=(
        SessionWindowV1("X", "1970-01-01", 0, 100),
    ))
    tick = event(2, "tick", price=Decimal("100"))
    split = CorporateActionV1("split", 150, 50, 50, split_ratio=Decimal("2"))
    action = event(
        150, "split", kind="corporate_action", available_ns=50,
        price=None, size=None, action=split,
    )
    snapshot = CorporateActionSnapshotV1("later", 200, "a1", (action,))
    research = prepare_events(
        data, (tick,), AdjustmentPolicyV1("split_only", "a1"), action_snapshot=snapshot,
    )
    assert next(research).adjusted_price == Decimal("50")
    before_effective = replace(data, as_of_ns=60)
    known = CorporateActionSnapshotV1("known-future", 60, "a1", (action,))
    early = prepare_events(
        before_effective, (tick,), AdjustmentPolicyV1("split_only", "a1"),
        action_snapshot=known,
    )
    assert next(early).adjusted_price == Decimal("100")


def test_cycle2_correction_refs_are_collision_free_canonical_json() -> None:
    data = replace(
        manifest(),
        streams=(StreamSpecV1("one", "a:b", "X", 0), StreamSpecV1("two", "a", "X", 1)),
        source_checksums=(("a:b", "a" * 64), ("a", "b" * 64)),
    )
    first = event(10, "c", source="a:b", stream_id="one", sequence=1, correction_key="d")
    first_fix = replace(first, correction_key="e", available_ns=20, sequence=2)
    second = event(10, "b:c", source="a", stream_id="two", sequence=1, correction_key="d")
    second_fix = replace(second, correction_key="e", available_ns=20, sequence=2)
    stream = prepare_events(
        data, {"one": (first, first_fix), "two": (second, second_fix)},
        AdjustmentPolicyV1("raw", "a1"),
    )
    references = {item.supersedes for item in stream}
    assert references == {'["a:b","c","d"]', '["a","b:c","d"]'}


def test_cycle2_ascii_and_error_message_boundaries() -> None:
    with pytest.raises(EventValidationError):
        replace(event(5, "id"), source_id="bad\nheader")
    with pytest.raises(ManifestError):
        replace(manifest(), as_of_ns=True)
    with pytest.raises(OutOfOrderError) as failure:
        list(prepare_events(
            manifest(), (event(10, "first"), event(9, "second")),
            AdjustmentPolicyV1("raw", "a1"),
        ))
    assert str(failure.value) == "OUT_OF_ORDER"
    assert failure.value.stream_id == "s" and failure.value.sequence is None


def test_cycle3_as_of_filters_corrections_before_reconciliation() -> None:
    original = event(5, "same", sequence=1)
    correction = replace(original, correction_key="fix", available_ns=20)
    early = prepare_events(
        replace(manifest(), as_of_ns=10), (original, correction),
        AdjustmentPolicyV1("raw", "a1", view="PIT"),
    )
    assert [item.raw.correction_key for item in early] == ["base"]
    assert [item.raw.correction_key for item in early.correction_audit] == ["base"]
    assert early.coverage.gaps == () and early.coverage.complete
    late = prepare_events(
        replace(manifest(), as_of_ns=30), (original, correction),
        AdjustmentPolicyV1("raw", "a1", view="PIT"),
    )
    assert [item.visible_ns for item in late] == [5, 20]
    assert [item.effective for item in late.correction_audit] == [False, True]


def test_cycle3_pit_visibility_order_is_nondecreasing() -> None:
    delayed = event(5, "delayed", available_ns=20)
    immediate = event(10, "immediate")
    prepared = list(prepare_events(
        manifest(), (delayed, immediate), AdjustmentPolicyV1("raw", "a1", view="PIT")
    ))
    assert [(item.raw.source_id, item.visible_ns) for item in prepared] == [
        ("immediate", 10), ("delayed", 20),
    ]


def test_cycle3_pit_issuance_and_exact_policy_labels() -> None:
    class Deceptive(str):
        def __eq__(self, other: object) -> bool:
            return other == "PIT"

    with pytest.raises(PolicyOutOfBoundsError):
        AdjustmentPolicyV1("raw", "a1", view=Deceptive("BACK_ADJUSTED"))
    pit = next(prepare_events(
        manifest(), (event(5, "tick"),), AdjustmentPolicyV1("raw", "a1", view="PIT")
    ))
    assert pit.simulator_eligible
    with pytest.raises(EventValidationError):
        replace(pit)
    pit_fields = {
        name: getattr(pit, name)
        for name in pit.__dataclass_fields__ if name != "_issuer"
    }
    with pytest.raises(EventValidationError):
        type(pit)(**pit_fields)
    research = next(prepare_events(
        manifest(), (event(5, "tick"),), AdjustmentPolicyV1("raw", "a1")
    ))
    with pytest.raises(EventValidationError):
        replace(research, view="PIT", view_as_of_ns=None)


def test_cycle3_exact_rational_adjustments_round_only_final_value() -> None:
    split = CorporateActionV1("split", 20, 1, 1, split_ratio=Decimal(3))
    split_event = event(
        20, "split", kind="corporate_action", available_ns=1,
        price=None, size=None, action=split,
    )
    split_snapshot = CorporateActionSnapshotV1("split-snapshot", 1000, "a1", (split_event,))
    tick = event(5, "tick", price=Decimal(3))
    result = next(prepare_events(
        manifest(), (tick,), AdjustmentPolicyV1("split_only", "a1"),
        action_snapshot=split_snapshot,
    ))
    assert result.adjusted_price == Decimal(1)
    dividend = CorporateActionV1(
        "dividend", 20, 1, 1, cash_amount=Decimal(1), cash_currency="USD",
        fx_rate=Decimal(1), fx_pair="USD/USD", reference_price=Decimal(3),
        price_currency="USD",
    )
    dividend_event = event(
        20, "dividend", kind="corporate_action", available_ns=1,
        price=None, size=None, action=dividend,
    )
    dividend_snapshot = CorporateActionSnapshotV1(
        "dividend-snapshot", 1000, "a1", (dividend_event,)
    )
    dividend_result = next(prepare_events(
        manifest(), (tick,), AdjustmentPolicyV1("split_plus_dividend", "a1"),
        action_snapshot=dividend_snapshot,
    ))
    assert dividend_result.adjusted_price == Decimal(2)


def test_cycle3_composed_factor_can_exceed_decimal_bounds_when_final_price_fits() -> None:
    actions = tuple(
        event(
            timestamp, source_id, kind="corporate_action", available_ns=1,
            price=None, size=None,
            action=CorporateActionV1(
                "split", timestamp, 1, 1, split_ratio=Decimal("1E+38")
            ),
        )
        for timestamp, source_id in ((20, "first"), (21, "second"))
    )
    snapshot = CorporateActionSnapshotV1("large-factors", 1000, "a1", actions)
    tick = event(5, "tick", price=Decimal("1E+38"), size=Decimal("1E-38"))
    prepared = next(prepare_events(
        manifest(), (tick,), AdjustmentPolicyV1("split_only", "a1"),
        action_snapshot=snapshot,
    ))
    assert prepared.adjusted_price == Decimal("1E-38")
    assert prepared.adjusted_size == Decimal("1E+38")
    assert prepared.adjustment_factor == Ratio(1, 10**76)


def test_cycle3_action_journal_uses_canonical_json_identity() -> None:
    first = event(
        20, "a:b", kind="corporate_action", available_ns=1, correction_key="c",
        price=None, size=None,
        action=CorporateActionV1("split", 20, 1, 1, split_ratio=Decimal(2)),
    )
    second = event(
        21, "a", kind="corporate_action", available_ns=1, correction_key="b:c",
        price=None, size=None,
        action=CorporateActionV1("split", 21, 1, 1, split_ratio=Decimal(2)),
    )
    snapshot = CorporateActionSnapshotV1("both", 1000, "a1", (first, second))
    prepared = prepare_events(
        manifest(), (event(5, "tick"),), AdjustmentPolicyV1("split_only", "a1"),
        action_snapshot=snapshot,
    )
    assert len(next(prepared).applied_action_ids) == 2
    assert {entry.action_identity for entry in prepared.adjustment_journal} == {
        '["vendor","a:b","c"]', '["vendor","a","b:c"]',
    }


def test_cycle3_bool_cursor_version_and_sanitized_unicode_error() -> None:
    prepared = prepare_events(
        manifest(), (event(5, "tick"),), AdjustmentPolicyV1("raw", "a1")
    )
    with pytest.raises(CheckpointError):
        replace(prepared.cursor, version=True)
    with pytest.raises(EventValidationError) as failure:
        malformed = event(
            5, "book", kind="book_snapshot", price=None, size=None,
            levels=(BookLevelV1("\ud800", Decimal(1), Decimal(1)),),
        )
        prepare_events(manifest(), (malformed,), AdjustmentPolicyV1("raw", "a1"))
    assert failure.value.__cause__ is None and failure.value.__context__ is None
    with pytest.raises(ManifestError) as manifest_failure:
        replace(manifest(), source_checksums=(("vendor", "SECRET\ud800"),))
    assert manifest_failure.value.__cause__ is None
    assert manifest_failure.value.__context__ is None


def test_adjudicated_pit_issuance_is_identity_bound_and_value_sealed() -> None:
    raw = event(5, "same")
    pit_policy = AdjustmentPolicyV1("raw", "a1", view="PIT")
    first_stream = prepare_events(manifest(), (raw,), pit_policy)
    first = next(first_stream)
    list(first_stream)
    second_stream = prepare_events(manifest(), (raw,), pit_policy)
    second = next(second_stream)
    assert first is not second and first == second
    assert first.simulator_eligible and second.simulator_eligible
    first_ref = weakref.ref(first)
    del first, first_stream
    gc.collect()
    assert first_ref() is None
    assert second.simulator_eligible

    research = next(prepare_events(
        manifest(), (raw,), AdjustmentPolicyV1("raw", "a1")
    ))
    object.__setattr__(research, "view", "PIT")
    object.__setattr__(research, "view_as_of_ns", None)
    assert research == second
    assert not research.simulator_eligible
    object.__setattr__(second, "adjusted_price", Decimal("11"))
    assert not second.simulator_eligible

    third = next(prepare_events(manifest(), (raw,), pit_policy))
    values = {field: getattr(third, field) for field in third.__dataclass_fields__
              if field != "_issuer"}
    with pytest.raises(EventValidationError):
        third.__init__(**values)
    assert third.simulator_eligible

    changed_stream = prepare_events(manifest(), (raw,), pit_policy)
    assert changed_stream.simulator_eligible
    object.__setattr__(changed_stream, "_projection", ())
    assert not changed_stream.simulator_eligible
    reinitialized_stream = prepare_events(manifest(), (raw,), pit_policy)
    with pytest.raises(EventValidationError):
        reinitialized_stream.__init__(manifest(), (raw,), pit_policy, None, None, None)
    assert reinitialized_stream.simulator_eligible


def test_adjudicated_correction_order_uses_visible_time_then_sequence() -> None:
    original = event(5, "same", sequence=1, correction_key="z", price=Decimal("10"))
    corrected = replace(
        original, sequence=2, correction_key="a", price=Decimal("12")
    )
    pit = prepare_events(
        manifest(), (original, corrected), AdjustmentPolicyV1("raw", "a1", view="PIT")
    )
    assert [item.raw.price for item in pit] == [Decimal("10"), Decimal("12")]
    assert [item.effective for item in pit.correction_audit] == [False, True]
    assert pit.correction_audit[1].supersedes == '["vendor","same","z"]'
    research = prepare_events(
        manifest(), (original, corrected), AdjustmentPolicyV1("raw", "a1")
    )
    assert [item.raw.price for item in research] == [Decimal("12")]
    with pytest.raises(DuplicateSourceError, match="ambiguous correction chronology"):
        prepare_events(
            manifest(), (original, replace(corrected, sequence=1)),
            AdjustmentPolicyV1("raw", "a1"),
        )


def test_b24_raw_pit_stream_rejects_external_adjustment_engine() -> None:
    tick = event(5, "tick", available_ns=20)
    split = event(
        10, "external", kind="corporate_action", price=None, size=None,
        action=CorporateActionV1("split", 10, 10, 10, split_ratio=Decimal(2)),
    )
    snapshot = CorporateActionSnapshotV1("external", 1000, "a1", (split,))
    stream = prepare_events(manifest(), (tick,), AdjustmentPolicyV1("raw", "a1", "PIT"))
    with pytest.raises(SealedStreamTamperedError, match=r"^SEALED_STREAM_TAMPERED$"):
        stream._adjustments = AdjustmentEngine(  # type: ignore[attr-defined]
            AdjustmentPolicyV1("split_only", "a1", "PIT"), snapshot, 1000
        )
    prepared = next(stream)
    assert prepared.simulator_eligible
    assert prepared.raw.price == prepared.adjusted_price == Decimal(10)
    assert prepared.applied_action_ids == () and prepared.action_snapshot_id == ""


def test_b24_stream_rechecks_sealed_inputs_before_next_output() -> None:
    stream = prepare_events(
        manifest(), (event(5, "first", sequence=1), event(6, "second", sequence=2)),
        AdjustmentPolicyV1("raw", "a1", "PIT"),
    )
    next(stream)
    object.__setattr__(stream, "_action_snapshot_digest", "forged")
    with pytest.raises(SealedStreamTamperedError, match=r"^SEALED_STREAM_TAMPERED$"):
        next(stream)
    with pytest.raises(SealedStreamTamperedError):
        _ = stream.event_count
    assert not stream.simulator_eligible


def test_seal_migrate_b25_pinned_adjustment_factor_cannot_change_eligible_price() -> None:
    split = event(
        10, "action", kind="corporate_action", price=None, size=None,
        action=CorporateActionV1("split", 10, 10, 10, split_ratio=Decimal(2)),
    )
    snapshot = CorporateActionSnapshotV1("actions", 1000, "a1", (split,))
    tick = event(5, "tick", available_ns=20)
    policy = AdjustmentPolicyV1("split_only", "a1", "PIT")
    stable = prepare_events(manifest(), (tick,), policy, action_snapshot=snapshot)
    object.__setattr__(snapshot.actions[0].action, "split_ratio", Decimal(4))
    result = next(stable)
    assert result.simulator_eligible and result.adjusted_price == Decimal(5)

    tampered = prepare_events(manifest(), (tick,), policy, action_snapshot=(
        CorporateActionSnapshotV1("actions", 1000, "a1", (split,))
    ))
    assert tampered._action_snapshot is not None
    object.__setattr__(tampered._action_snapshot.actions[0].action, "split_ratio", Decimal(4))
    with pytest.raises(SealedStreamTamperedError, match=r"^SEALED_STREAM_TAMPERED$"):
        next(tampered)
    assert not tampered.simulator_eligible


def test_seal_migrate_stream_copy_and_pickle_are_rejected() -> None:
    stream = prepare_events(
        manifest(), (event(5, "tick"),), AdjustmentPolicyV1("raw", "a1", "PIT")
    )
    for clone in (lambda: copy(stream), lambda: deepcopy(stream), lambda: pickle.dumps(stream)):
        with pytest.raises(SealedStreamTamperedError, match=r"^SEALED_STREAM_TAMPERED$"):
            clone()
    assert stream.simulator_eligible


def test_seal_migrate_replayed_old_issued_progress_fails_closed() -> None:
    stream = prepare_events(
        manifest(), (event(5, "first", sequence=1), event(6, "second", sequence=2)),
        AdjustmentPolicyV1("raw", "a1", "PIT"),
    )
    next(stream)
    old_progress = stream._progress
    next(stream)
    object.__setattr__(stream, "_progress", old_progress)
    assert not stream.simulator_eligible
    with pytest.raises(SealedStreamTamperedError, match=r"^SEALED_STREAM_TAMPERED$"):
        _ = stream.cursor
