"""Independent acceptance for BT-003's binding to the verified stream calendar."""

from __future__ import annotations

from collections.abc import Iterable
from decimal import Decimal
from typing import Any, cast

import pytest

from leviathan_core.backtest_lab import (
    AdjustmentPolicyV1,
    DatasetManifestV1,
    MarketEventV1,
    PreparedEventStreamV1,
    SessionWindowV1,
    StreamSpecV1,
    UniverseMemberV1,
    prepare_events,
)
from leviathan_core.backtest_lab import fills as fills_module
from leviathan_core.backtest_lab.clock import StreamTamperedError
from leviathan_core.backtest_lab.costs import FeeModelV1
from leviathan_core.backtest_lab.fills import FillPolicyV1, match
from leviathan_core.backtest_lab.latency import FixedLatencyV1, LatencyModelV1
from leviathan_core.backtest_lab.orders import FillPolicyError, FillRequestV1

CALENDAR_ID = "synthetic-xnys"
CALENDAR_VERSION = "2026a"
INSTRUMENT = "SYNTH"
VENUE = "XTEST"
SOURCE = "synthetic-feed"
STREAM_ID = "quotes"
RAW_POLICY = AdjustmentPolicyV1(mode="raw", version="raw-v1", view="PIT")


def _calendar(
    *,
    calendar_id: str = CALENDAR_ID,
    calendar_version: str = CALENDAR_VERSION,
    sessions: tuple[SessionWindowV1, ...] | None = None,
) -> DatasetManifestV1:
    windows = sessions or (SessionWindowV1(VENUE, "2026-01-02", 0, 100),)
    return DatasetManifestV1(
        dataset_id="calendar-binding-dataset",
        dataset_version="dataset-v1",
        universe_version="universe-v1",
        symbol_mapping_version="mapping-v1",
        calendar_id=calendar_id,
        calendar_version=calendar_version,
        adjustment_version="raw-v1",
        as_of_ns=max(window.close_ns for window in windows),
        start_ns=min(window.open_ns for window in windows),
        end_ns=max(window.close_ns for window in windows),
        source_checksums=((SOURCE, "a" * 64),),
        universe=(UniverseMemberV1(INSTRUMENT, VENUE, 0),),
        sessions=windows,
        streams=(StreamSpecV1(STREAM_ID, SOURCE, VENUE, priority=0),),
        max_identity_cache=32,
    )


def _quote(event_ns: int, sequence: int) -> MarketEventV1:
    return MarketEventV1(
        dataset_id="calendar-binding-dataset",
        dataset_version="dataset-v1",
        universe_version="universe-v1",
        source=SOURCE,
        source_id=f"quote-{sequence}",
        correction_key="original",
        stream_id=STREAM_ID,
        event_ns=event_ns,
        available_ns=event_ns,
        instrument=INSTRUMENT,
        venue=VENUE,
        sequence=sequence,
        kind="quote",
        bid_price=Decimal("99"),
        bid_size=Decimal("5"),
        ask_price=Decimal("100"),
        ask_size=Decimal("5"),
    )


def _stream(
    *event_times: int,
    calendar_id: str = CALENDAR_ID,
    calendar_version: str = CALENDAR_VERSION,
    sessions: tuple[SessionWindowV1, ...] | None = None,
) -> PreparedEventStreamV1:
    manifest = _calendar(
        calendar_id=calendar_id,
        calendar_version=calendar_version,
        sessions=sessions,
    )
    events: Iterable[MarketEventV1] = tuple(
        _quote(event_ns, sequence) for sequence, event_ns in enumerate(event_times, start=1)
    )
    return prepare_events(manifest, events, RAW_POLICY)


def _policy(
    *, calendar_id: str = CALENDAR_ID, calendar_version: str = CALENDAR_VERSION
) -> FillPolicyV1:
    return FillPolicyV1(
        version="fill-policy-v1",
        calendar_id=calendar_id,
        calendar_version=calendar_version,
        execution_mode="L1_TOP_OF_BOOK",
        queue_model="PRICE_TIME_BOOK_SHARE",
        latency=LatencyModelV1(
            strategy=FixedLatencyV1(0, "latency-v1"),
            network=FixedLatencyV1(0, "latency-v1"),
            venue=FixedLatencyV1(0, "latency-v1"),
            version="latency-v1",
        ),
        fees=FeeModelV1(
            version="fees-v1",
            currency="USD",
            minor_units=2,
            fee_per_share=Decimal(0),
            fee_bps=Decimal(0),
            rebate_per_share=Decimal(0),
            rebate_bps=Decimal(0),
        ),
        max_book_age_ns=50,
    )


def _request(
    *,
    session: SessionWindowV1 | None = None,
    sessions: tuple[SessionWindowV1, ...] | None = None,
    calendar_id: str = CALENDAR_ID,
    calendar_version: str = CALENDAR_VERSION,
    time_in_force: str = "DAY",
    submit_ns: int = 0,
    expires_ns: int | None = None,
) -> FillRequestV1:
    primary = session or SessionWindowV1(VENUE, "2026-01-02", 0, 100)
    return FillRequestV1(
        request_id="calendar-binding-order",
        instrument=INSTRUMENT,
        venue=VENUE,
        side="BUY",
        order_type="MARKET",
        time_in_force=cast(Any, time_in_force),
        quantity=Decimal(1),
        submit_ns=submit_ns,
        submit_sequence=0,
        currency="USD",
        calendar_id=calendar_id,
        calendar_version=calendar_version,
        session=primary,
        sessions=sessions or (primary,),
        expires_ns=expires_ns,
    )


def test_matching_calendar_preserves_the_existing_fill_result_and_verifies_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stream = _stream(10)
    calls = 0
    verifier = fills_module.verify_prepared_stream

    def counted(value: object) -> object:
        nonlocal calls
        calls += 1
        return verifier(value)

    monkeypatch.setattr(fills_module, "verify_prepared_stream", counted)
    trace = match(_request(), _policy(), stream)

    assert calls == 1
    assert trace.status == "FILLED"
    assert trace.filled_quantity == Decimal(1)
    assert trace.remaining_quantity == Decimal(0)
    assert len(trace.fills) == 1
    assert trace.fills[0].visible_ns == 10
    assert trace.fills[0].price == Decimal(100)
    assert trace.fills[0].quantity == Decimal(1)
    assert trace.total_fee == Decimal(0)


@pytest.mark.parametrize(
    ("request_id", "request_version", "policy_id", "policy_version", "session"),
    [
        ("other-calendar", CALENDAR_VERSION, "other-calendar", CALENDAR_VERSION, None),
        (CALENDAR_ID, "other-version", CALENDAR_ID, "other-version", None),
        (
            CALENDAR_ID,
            CALENDAR_VERSION,
            CALENDAR_ID,
            CALENDAR_VERSION,
            SessionWindowV1(VENUE, "2026-01-02", 0, 101),
        ),
    ],
)
def test_manifest_calendar_or_window_mismatch_denies_before_any_fill(
    request_id: str,
    request_version: str,
    policy_id: str,
    policy_version: str,
    session: SessionWindowV1 | None,
) -> None:
    with pytest.raises(FillPolicyError) as mismatch:
        match(
            _request(
                calendar_id=request_id,
                calendar_version=request_version,
                session=session,
            ),
            _policy(calendar_id=policy_id, calendar_version=policy_version),
            _stream(10),
        )

    assert mismatch.value.code == "CALENDAR_MISMATCH"
    assert str(mismatch.value) == "CALENDAR_MISMATCH"
    assert mismatch.value.args == ("CALENDAR_MISMATCH",)


def test_tampered_prepared_stream_propagates_stream_tampered_before_filling() -> None:
    stream = _stream(10)
    tuple(stream)
    object.__setattr__(
        stream,
        "_manifest",
        _calendar(calendar_id="tampered-calendar"),
    )

    with pytest.raises(StreamTamperedError) as tampered:
        match(_request(), _policy(), stream)

    assert type(tampered.value) is StreamTamperedError
    assert str(tampered.value) == "STREAM_TAMPERED"
    assert tampered.value.args == ("STREAM_TAMPERED",)


def test_fills_obey_manifest_session_open_and_close_boundaries() -> None:
    first = SessionWindowV1(VENUE, "2026-01-02", 0, 30)
    second = SessionWindowV1(VENUE, "2026-01-02", 40, 80)
    windows = (first, second)
    policy = _policy()
    narrowed_first = SessionWindowV1(VENUE, "2026-01-02", 0, 20)
    request_windows = (narrowed_first, second)

    at_request_close = match(
        _request(
            session=narrowed_first,
            sessions=request_windows,
            time_in_force="GTC",
            expires_ns=80,
        ),
        policy,
        # 20 is the request's exclusive close but remains inside the manifest session.
        _stream(20, sessions=windows),
    )
    assert at_request_close.status == "UNFILLED"
    assert not at_request_close.fills

    last_manifest_tick = match(
        _request(session=first, sessions=windows, time_in_force="GTC", expires_ns=80),
        policy,
        _stream(29, sessions=windows),
    )
    assert last_manifest_tick.status == "FILLED"
    assert last_manifest_tick.fills[0].visible_ns == 29

    at_second_open = match(
        _request(session=first, sessions=windows, time_in_force="GTC", expires_ns=80),
        policy,
        _stream(40, sessions=windows),
    )
    assert at_second_open.status == "FILLED"
    assert at_second_open.fills[0].visible_ns == 40

    at_second_final_tick = match(
        _request(session=first, sessions=windows, time_in_force="GTC", expires_ns=80),
        policy,
        _stream(79, sessions=windows),
    )
    assert at_second_final_tick.status == "FILLED"
    assert at_second_final_tick.fills[0].visible_ns == 79
