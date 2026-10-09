"""Independent acceptance for BT-002 prepared-event issuance performance."""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import replace
from decimal import Decimal
from time import process_time
from typing import Literal

import pytest

from leviathan_core.backtest_lab.clock import PreparedEventStreamV1, prepare_events
from leviathan_core.backtest_lab.events import (
    AdjustmentPolicyV1,
    CorporateActionSnapshotV1,
    CorporateActionV1,
    DatasetManifestV1,
    EventValidationError,
    MarketEventV1,
    PreparedEventV1,
    SessionWindowV1,
    StreamSpecV1,
    UniverseMemberV1,
    _issue_prepared_event,
)
from leviathan_core.seal import SealError, digest, require

_EVENT_SEAL = "bt002.event.v1"
IssueMode = Literal["raw", "split_only"]
_GOLDEN_RAW_EVENT_DIGESTS = (
    "f3a5fefb19250f5947e8cd9b6e66d9752b036d4393dd161baaec84a88276d072",
    "01af805f0dc307239a67e3dc7855136861a3d317e5d21d06113a8b34d95d80aa",
    "9506171d82e53637da0c4451a54c40d68c3f9d25d1d49510185721a5b5660263",
    "f56ab827998a3c0903b0ff60cc043856355e2cf6127023ae8ec2c9726122e758",
    "963a714c07a719c2cfca52a64b5f0815079829a40c8df9515715cc327c880fd8",
)
_GOLDEN_RAW_PREPARED_DIGESTS = (
    "693e6b2c050afea0f0fe15239fa7935f7326e994b926779833901aa1d80bafb9",
    "454fe519810cefedb312c4e828dd5a48a9562c2e75584c076461b04d982aeec5",
    "5ff7a1e71becb9e7e212b56c04cd940f673c7f8b1c3ef24618ca4628c503814a",
    "723ab0dbc1f36697c0164ce781a9fe9c64f1ea8a3cd94a4c20b5b82fc3614393",
    "ed1c1e55754188c55524fc2b677edf7d03089d646000d4a048025ab8203f15ce",
)
_GOLDEN_RAW_STREAM_DIGEST = "2172377ece5033726a3f7f33dbbb73896b66b330cdfd30d3b343d9c984cd0b2a"

_GOLDEN_ADJUSTED_RAW_EVENT_DIGESTS = (
    "cbfb6572092ad6579c49fee0fae38ce08fa2d58de3a517721fa2be180ee6a5df",
    "019ecd6c101bf87547ba6dca819c5c3f844d0c8720a918300473444c4eddcc38",
    "e4229b303d6405cf7cdfabd25b886f1c1fd56c990173835f9ebc4127151e77ed",
    "b207fdd144f92a96946b544a225f70f75b77e6551a1ff49978dd1edcd1bfeb57",
    "fef1a14d4b9479ae88d0eebe9515b77baf43be9eac34076cbdfb73bcc90f93f3",
)
_GOLDEN_ADJUSTED_PREPARED_DIGESTS = (
    "430fa8b9f698cd717e00d397c1c4f99a884f4bc2bfb2664ae2cdf192d309182a",
    "ca121df823e9c134ae412d88c5d07c0593dab94fcc2b8d5303e98a591af13000",
    "ec19bddee08304b2ea7b5171981feac5d08e8c89c35310c5f7a1d3097960161b",
    "126b732ecd14c3aefae00ecd4af5164bbad4ca3395e8cd156ce5fc2c5c67bfc0",
    "97568cad1ee542f33f8be220deb91c7701fb6e5e9906e44e346832fd6209e179",
)
_GOLDEN_ADJUSTED_STREAM_DIGEST = "a999ce5deac2b3457d88210591259efd9fb8d5a659964932fbe128a9ab6abaa8"


def _input_case(
    event_count: int,
    *,
    dataset_id: str,
    mode: IssueMode,
    first_event_ns: int = 1,
    event_step_ns: int = 1,
    dataset_end_ns: int | None = None,
) -> tuple[
    DatasetManifestV1,
    tuple[MarketEventV1, ...],
    AdjustmentPolicyV1,
    CorporateActionSnapshotV1 | None,
]:
    inferred_end = first_event_ns + (event_count - 1) * event_step_ns + 1
    end_ns = inferred_end if dataset_end_ns is None else dataset_end_ns
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
        sessions=(SessionWindowV1("XPERF", "1970-01-01", 0, end_ns),),
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
    snapshot: CorporateActionSnapshotV1 | None = None
    view: Literal["PIT", "BACK_ADJUSTED"] = "PIT"
    if mode == "split_only":
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
        snapshot = CorporateActionSnapshotV1(
            snapshot_id=f"actions-{dataset_id}",
            as_of_ns=end_ns,
            adjustment_version="raw-v1",
            actions=(action_event,),
        )
        view = "BACK_ADJUSTED"
    policy = AdjustmentPolicyV1(mode=mode, version="raw-v1", view=view)
    return manifest, events, policy, snapshot


def _prepare_case(
    case: tuple[
        DatasetManifestV1,
        tuple[MarketEventV1, ...],
        AdjustmentPolicyV1,
        CorporateActionSnapshotV1 | None,
    ],
) -> PreparedEventStreamV1:
    manifest, events, policy, snapshot = case
    return prepare_events(
        manifest,
        events,
        policy,
        action_snapshot=snapshot,
    )


def _issue_and_consume(
    case: tuple[
        DatasetManifestV1,
        tuple[MarketEventV1, ...],
        AdjustmentPolicyV1,
        CorporateActionSnapshotV1 | None,
    ],
) -> tuple[float, PreparedEventStreamV1, tuple[PreparedEventV1, ...]]:
    started = process_time()
    stream = _prepare_case(case)
    output = tuple(stream)
    elapsed = process_time() - started
    return elapsed, stream, output


def _assert_seal_code(call: Callable[[], object], expected: str) -> None:
    try:
        call()
    except SealError as error:
        assert error.code == expected
        assert error.args == (expected,)
        assert str(error) == expected
    else:
        raise AssertionError(f"SEAL require accepted expected {expected}")


def test_prepared_event_bytes_and_digests_match_prechange_canonical() -> None:
    fixtures = (
        (
            "raw",
            _GOLDEN_RAW_EVENT_DIGESTS,
            _GOLDEN_RAW_PREPARED_DIGESTS,
            _GOLDEN_RAW_STREAM_DIGEST,
        ),
        (
            "split_only",
            _GOLDEN_ADJUSTED_RAW_EVENT_DIGESTS,
            _GOLDEN_ADJUSTED_PREPARED_DIGESTS,
            _GOLDEN_ADJUSTED_STREAM_DIGEST,
        ),
    )
    for mode, raw_digests, prepared_digests, stream_digest in fixtures:
        case = _input_case(
            5,
            dataset_id=f"issue-perf-golden-{mode}",
            mode=mode,
            first_event_ns=100,
            event_step_ns=100,
            dataset_end_ns=1000,
        )
        stream = _prepare_case(case)
        output = tuple(stream)

        assert tuple(item.raw.source_id for item in output) == tuple(
            f"tick-{index}" for index in range(5)
        )
        assert tuple(digest(item.raw) for item in output) == raw_digests
        assert tuple(digest(item) for item in output) == prepared_digests
        assert stream.stream_digest == stream_digest
        if mode == "split_only":
            assert all(not item.simulator_eligible for item in output)
            for item in output:
                _assert_seal_code(
                    lambda item=item: require(item, _EVENT_SEAL),
                    "SEAL_NOT_ISSUED",
                )


def test_pit_event_issuance_and_seal_require_semantics_are_preserved() -> None:
    stream = _prepare_case(_input_case(5, dataset_id="issue-perf-seal", mode="raw"))
    output = tuple(stream)
    assert output
    for item in output:
        assert require(item, _EVENT_SEAL) is item
        assert item.simulator_eligible
        _assert_seal_code(
            lambda item=item: require(item, "bt002.other_event.v1"),
            "SEAL_WRONG_ISSUER",
        )


def test_unissued_prepared_event_forgery_is_rejected_by_seal_require() -> None:
    issued = next(iter(_prepare_case(_input_case(1, dataset_id="issue-perf-forgery", mode="raw"))))
    forged = replace(
        issued,
        view="BACK_ADJUSTED",
        view_as_of_ns=issued.visible_ns + 1,
    )

    assert not forged.simulator_eligible
    _assert_seal_code(
        lambda: require(forged, _EVENT_SEAL),
        "SEAL_NOT_ISSUED",
    )


def test_issued_prepared_event_tampering_is_rejected_by_seal_require() -> None:
    issued = next(iter(_prepare_case(_input_case(1, dataset_id="issue-perf-tamper", mode="raw"))))
    original = issued.adjusted_price
    assert original is not None
    object.__setattr__(issued, "adjusted_price", original + Decimal("1"))

    _assert_seal_code(
        lambda: require(issued, _EVENT_SEAL),
        "SEAL_TAMPERED",
    )


def _private_pit_issue_values(raw: MarketEventV1) -> dict[str, object]:
    return {
        "raw": raw,
        "adjusted_price": Decimal("10"),
        "adjusted_size": Decimal("2"),
        "adjustment_factor": Decimal("1"),
        "visible_ns": max(raw.event_ns, raw.available_ns),
        "adjusted_levels": (),
        "adjustment_version": "raw-v1",
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


def test_stream_owned_pit_decimal_fields_use_canonical_representations() -> None:
    from leviathan_core.backtest_lab.adjustments import canonical_decimal

    _, events, _, _ = _input_case(
        1,
        dataset_id="issue-perf-decimal-representation",
        mode="raw",
    )
    raw = events[0]
    values = _private_pit_issue_values(raw)
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
    assert prepared.view == "PIT"
    assert require(prepared, _EVENT_SEAL) is prepared
    for field, original in inputs.items():
        actual = getattr(prepared, field)
        expected_value = canonical_decimal(original, field)
        assert type(actual) is Decimal
        assert actual.as_tuple() == expected_value.as_tuple()


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("adjusted_price", "30.00"),
        ("adjusted_size", "3.000"),
        ("adjustment_version", " bad "),
        ("adjustment_version", ""),
        ("adjustment_version", "v\u00e9"),
        ("adjusted_levels", []),
        ("supersedes", 5),
    ),
)
def test_private_issue_rejects_malformed_stream_owned_values(field: str, value: object) -> None:
    _, events, _, _ = _input_case(
        1,
        dataset_id=f"issue-perf-invalid-{field}",
        mode="raw",
    )
    values = _private_pit_issue_values(events[0])
    values[field] = value

    with pytest.raises(EventValidationError):
        _issue_prepared_event(**values)


def _timed_case(event_count: int, mode: IssueMode, *, dataset_id: str) -> float:
    case = _input_case(
        event_count,
        dataset_id=dataset_id,
        mode=mode,
    )
    elapsed, stream, output = _issue_and_consume(case)
    assert len(output) == event_count
    assert stream.complete
    return elapsed


@pytest.mark.parametrize("mode", ("raw", "split_only"))
@pytest.mark.skipif(
    os.environ.get("LEVIATHAN_RUN_PERF") != "1",
    reason="perf opt-in",
)
def test_issuance_construction_scales_to_fifty_thousand(mode: str) -> None:
    seconds_10k = _timed_case(
        10_000,
        mode,
        dataset_id=f"issue-perf-{mode}-10k",
    )
    seconds_50k = _timed_case(
        50_000,
        mode,
        dataset_id=f"issue-perf-{mode}-50k",
    )

    per_event_10k = seconds_10k / 10_000
    per_event_50k = seconds_50k / 50_000
    if mode == "split_only":
        assert per_event_50k <= 1.5 * per_event_10k
    else:
        # Coordinator ruling: raw PIT scaling is recorded, not a failure gate.
        assert per_event_10k > 0
