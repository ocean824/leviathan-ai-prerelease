"""Calendar binding between BT-003 fill inputs and the verified BT-002 plan."""

from collections.abc import Callable
from dataclasses import replace
from decimal import Decimal

import pytest

import leviathan_core.backtest_lab.fills as fills_module
from leviathan_core.backtest_lab import (
    AdjustmentPolicyV1,
    DatasetManifestV1,
    PreparedEventStreamV1,
    SessionWindowV1,
    StreamSpecV1,
    UniverseMemberV1,
    prepare_events,
)
from leviathan_core.backtest_lab.clock import StreamTamperedError
from leviathan_core.backtest_lab.costs import FeeModelV1
from leviathan_core.backtest_lab.fills import FillPolicyV1, match
from leviathan_core.backtest_lab.latency import FixedLatencyV1, LatencyModelV1
from leviathan_core.backtest_lab.orders import FillPolicyError, FillRequestV1

SESSION = SessionWindowV1("XNYS", "2026-01-02", 0, 100)


def _policy(
    *, calendar_id: str = "xnys-calendar", calendar_version: str = "2026-v1"
) -> FillPolicyV1:
    fixed = FixedLatencyV1(0, "fixed-v1")
    return FillPolicyV1(
        version="fill-policy-v1",
        calendar_id=calendar_id,
        calendar_version=calendar_version,
        execution_mode="L1_TOP_OF_BOOK",
        queue_model="PRICE_TIME_BOOK_SHARE",
        latency=LatencyModelV1(fixed, fixed, fixed, "latency-v1"),
        fees=FeeModelV1(
            version="fees-v1",
            currency="USD",
            minor_units=2,
            fee_per_share=Decimal("0"),
            fee_bps=Decimal("0"),
            rebate_per_share=Decimal("0"),
            rebate_bps=Decimal("0"),
        ),
        max_book_age_ns=50,
    )


def _request(
    *,
    session: SessionWindowV1 = SESSION,
    sessions: tuple[SessionWindowV1, ...] | None = None,
    calendar_id: str = "xnys-calendar",
    calendar_version: str = "2026-v1",
) -> FillRequestV1:
    return FillRequestV1(
        request_id="calendar-binding-request",
        instrument="XYZ",
        venue="XNYS",
        side="BUY",
        order_type="MARKET",
        time_in_force="DAY",
        quantity=Decimal("1"),
        submit_ns=session.open_ns,
        submit_sequence=0,
        currency="USD",
        calendar_id=calendar_id,
        calendar_version=calendar_version,
        session=session,
        sessions=sessions if sessions is not None else (session,),
    )


def _prepared(
    *,
    calendar_id: str = "xnys-calendar",
    calendar_version: str = "2026-v1",
    sessions: tuple[SessionWindowV1, ...] = (SESSION,),
) -> PreparedEventStreamV1:
    start_ns = min(session.open_ns for session in sessions)
    end_ns = max(session.close_ns for session in sessions)
    dataset = DatasetManifestV1(
        dataset_id="calendar-binding-dataset",
        dataset_version="dataset-v1",
        universe_version="universe-v1",
        symbol_mapping_version="symbols-v1",
        calendar_id=calendar_id,
        calendar_version=calendar_version,
        adjustment_version="raw-v1",
        as_of_ns=end_ns,
        start_ns=start_ns,
        end_ns=end_ns,
        source_checksums=(("synthetic-feed", "a" * 64),),
        universe=(UniverseMemberV1("XYZ", "XNYS", start_ns),),
        sessions=sessions,
        streams=(StreamSpecV1("ticks", "synthetic-feed", "XNYS", 0),),
        max_identity_cache=100,
    )
    return prepare_events(
        dataset,
        (),
        AdjustmentPolicyV1("raw", "raw-v1", view="PIT"),
    )


def _assert_calendar_mismatch(call: Callable[[], object]) -> None:
    with pytest.raises(FillPolicyError) as caught:
        call()
    assert caught.value.code == "CALENDAR_MISMATCH"
    assert str(caught.value) == "CALENDAR_MISMATCH"
    assert caught.value.args == ("CALENDAR_MISMATCH",)


def test_match_verifies_the_prepared_stream_once_before_iteration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events = _prepared()
    verifier = fills_module.__dict__["verify_prepared_stream"]
    calls = 0

    def counted(stream: object) -> object:
        nonlocal calls
        calls += 1
        return verifier(stream)

    monkeypatch.setitem(fills_module.__dict__, "verify_prepared_stream", counted)

    trace = match(_request(), _policy(), events)

    assert calls == 1
    assert trace.status == "UNFILLED"


@pytest.mark.parametrize(
    ("request_calendar_id", "request_calendar_version", "policy_calendar_id", "policy_version"),
    [
        ("other-calendar", "2026-v1", "xnys-calendar", "2026-v1"),
        ("xnys-calendar", "other-version", "xnys-calendar", "2026-v1"),
        ("xnys-calendar", "2026-v1", "other-calendar", "2026-v1"),
        ("xnys-calendar", "2026-v1", "xnys-calendar", "other-version"),
    ],
)
def test_request_and_policy_calendar_must_match_verified_manifest(
    request_calendar_id: str,
    request_calendar_version: str,
    policy_calendar_id: str,
    policy_version: str,
) -> None:
    _assert_calendar_mismatch(
        lambda: match(
            _request(
                calendar_id=request_calendar_id,
                calendar_version=request_calendar_version,
            ),
            _policy(calendar_id=policy_calendar_id, calendar_version=policy_version),
            _prepared(),
        )
    )


def test_request_session_windows_must_be_contained_in_verified_manifest() -> None:
    narrower = SessionWindowV1("XNYS", "2026-01-02", 10, 90)
    wider_manifest = SessionWindowV1("XNYS", "2026-01-02", 0, 120)
    trace = match(
        _request(session=narrower),
        _policy(),
        _prepared(sessions=(wider_manifest,)),
    )
    assert trace.status == "UNFILLED"

    outside_manifest = SessionWindowV1("XNYS", "2026-01-02", 0, 120)
    _assert_calendar_mismatch(
        lambda: match(
            _request(session=outside_manifest),
            _policy(),
            _prepared(sessions=(SESSION,)),
        )
    )


def test_every_order_pinned_session_must_be_in_the_verified_manifest() -> None:
    first = SessionWindowV1("XNYS", "2026-01-02", 0, 100)
    second = SessionWindowV1("XNYS", "2026-01-05", 200, 300)
    missing = SessionWindowV1("XNYS", "2026-01-06", 400, 500)
    _assert_calendar_mismatch(
        lambda: match(
            _request(session=first, sessions=(first, missing)),
            _policy(),
            _prepared(sessions=(first, second)),
        )
    )


def test_stream_tampering_propagates_as_stream_tampered() -> None:
    events = _prepared()
    object.__setattr__(events, "_manifest", replace(events._manifest, calendar_id="tampered"))

    with pytest.raises(StreamTamperedError) as caught:
        match(_request(), _policy(), events)

    assert str(caught.value) == "STREAM_TAMPERED"
    assert caught.value.args == ("STREAM_TAMPERED",)
