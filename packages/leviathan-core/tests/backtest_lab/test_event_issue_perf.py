"""Focused correctness checks for the prepared-event issuance fast path."""

from __future__ import annotations

from dataclasses import replace
from decimal import Decimal

import pytest

from leviathan_core.backtest_lab import (
    AdjustmentPolicyV1,
    DatasetManifestV1,
    EventValidationError,
    MarketEventV1,
    SessionWindowV1,
    StreamSpecV1,
    UniverseMemberV1,
    prepare_events,
)
from leviathan_core.backtest_lab.events import _issue_prepared_event
from leviathan_core.seal import SealError, require

_EVENT_SEAL = "bt002.event.v1"


def _input_events() -> tuple[DatasetManifestV1, tuple[MarketEventV1, ...]]:
    manifest = DatasetManifestV1(
        dataset_id="issue-fast-path",
        dataset_version="v1",
        universe_version="u1",
        symbol_mapping_version="map1",
        calendar_id="calendar",
        calendar_version="v1",
        adjustment_version="adj1",
        as_of_ns=100,
        start_ns=0,
        end_ns=100,
        source_checksums=(("feed", "a" * 64),),
        universe=(UniverseMemberV1("ABC", "X", 0, 100),),
        sessions=(SessionWindowV1("X", "1970-01-01", 0, 100),),
        streams=(StreamSpecV1("ticks", "feed", "X", 0),),
        max_identity_cache=16,
    )
    events = tuple(
        MarketEventV1(
            dataset_id="issue-fast-path",
            dataset_version="v1",
            universe_version="u1",
            source="feed",
            source_id=f"tick-{index}",
            correction_key="original",
            stream_id="ticks",
            event_ns=index + 1,
            available_ns=index + 1,
            instrument="ABC",
            venue="X",
            sequence=index + 1,
            kind="trade",
            price=Decimal("10"),
            size=Decimal("2"),
        )
        for index in range(4)
    )
    return manifest, events


def test_internal_issue_detaches_inputs_and_preserves_seal_eligibility() -> None:
    manifest, events = _input_events()
    stream = prepare_events(manifest, events, AdjustmentPolicyV1("raw", "adj1", view="PIT"))

    # The prepared plan owns its frozen inputs before any prepared event is issued.
    object.__setattr__(events[0], "price", Decimal("99"))
    output = tuple(stream)

    assert len(output) == len(events)
    assert output[0].raw is not events[0]
    assert output[0].raw.price == Decimal("10")
    assert all(item.simulator_eligible for item in output)
    assert all(require(item, _EVENT_SEAL) is item for item in output)


def test_internal_issue_seal_still_detects_prepared_event_tampering() -> None:
    manifest, events = _input_events()
    stream = prepare_events(manifest, events, AdjustmentPolicyV1("raw", "adj1", view="PIT"))
    prepared = next(iter(stream))

    object.__setattr__(prepared, "adjusted_price", Decimal("99"))

    try:
        require(prepared, _EVENT_SEAL)
    except SealError as error:
        assert error.code == "SEAL_TAMPERED"
    else:
        raise AssertionError("tampered prepared event remained accepted")


def _internal_issue_kwargs(raw: MarketEventV1) -> dict[str, object]:
    return {
        "raw": raw,
        "adjusted_price": Decimal("10"),
        "adjusted_size": Decimal("2"),
        "adjustment_factor": Decimal("1"),
        "visible_ns": raw.available_ns,
        "adjusted_levels": (),
        "adjustment_version": "adj1",
        "action_snapshot_id": "",
        "applied_action_ids": (),
        "supersedes": None,
        "adjusted_bid_price": None,
        "adjusted_bid_size": None,
        "adjusted_ask_price": None,
        "adjusted_ask_size": None,
        "view": "PIT",
        "view_as_of_ns": None,
        "_allowed_action_ids": frozenset(),
        "_issued_policy_mode": "raw",
        "_pinned_snapshot_id": "",
    }


def test_internal_issue_preserves_canonical_decimal_representations() -> None:
    from leviathan_core.backtest_lab.adjustments import canonical_decimal

    _, events = _input_events()
    raw = replace(events[0], price=Decimal("30.00"), size=Decimal("3.000"))
    values = _internal_issue_kwargs(raw)
    values.update(
        adjusted_price=Decimal("30.00"),
        adjusted_size=Decimal("3.000"),
        adjustment_factor=Decimal("1.000"),
        adjusted_bid_price=Decimal("29.00"),
        adjusted_bid_size=Decimal("2.000"),
        adjusted_ask_price=Decimal("31.00"),
        adjusted_ask_size=Decimal("4.000"),
    )

    prepared = _issue_prepared_event(**values)

    inputs = {
        "adjusted_price": Decimal("30.00"),
        "adjusted_size": Decimal("3.000"),
        "adjustment_factor": Decimal("1.000"),
        "adjusted_bid_price": Decimal("29.00"),
        "adjusted_bid_size": Decimal("2.000"),
        "adjusted_ask_price": Decimal("31.00"),
        "adjusted_ask_size": Decimal("4.000"),
    }
    for field, raw_value in inputs.items():
        value = getattr(prepared, field)
        assert isinstance(value, Decimal)
        expected = canonical_decimal(raw_value, field)
        assert value.as_tuple() == expected.as_tuple()


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("adjusted_price", "x"),
        ("adjusted_size", "x"),
        ("adjustment_version", " bad "),
        ("adjustment_version", ""),
        ("adjustment_version", "v\u00e9"),
        ("adjusted_levels", []),
        ("supersedes", 5),
    ),
)
def test_internal_issue_revalidates_fields_before_issuing(field: str, value: object) -> None:
    _, events = _input_events()
    values = _internal_issue_kwargs(events[0])
    values[field] = value

    with pytest.raises(EventValidationError):
        _issue_prepared_event(**values)


def test_issued_event_is_detached_from_the_stream_projection() -> None:
    manifest, events = _input_events()
    stream = prepare_events(manifest, events, AdjustmentPolicyV1("raw", "adj1", view="PIT"))
    prepared = next(iter(stream))
    projection_event = stream._projection[0]

    assert prepared.raw is not projection_event
    object.__setattr__(projection_event, "price", Decimal("99"))

    assert require(prepared, _EVENT_SEAL) is prepared
    assert prepared.raw.price == Decimal("10")
