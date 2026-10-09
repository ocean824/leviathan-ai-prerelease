"""Independent contract acceptance for the BT-003 fill and cost kernel."""

from __future__ import annotations

import copy
import http.client
import json
import pickle
import random
import socket
import urllib.request
from collections.abc import Iterable, Iterator
from decimal import Decimal, localcontext
from fractions import Fraction
from hashlib import sha256
from pathlib import Path
from typing import Any, cast

import pytest

from leviathan_core.backtest_lab import (
    AdjustmentPolicyV1,
    BookLevelV1,
    DatasetManifestV1,
    EventValidationError,
    MarketEventV1,
    PreparedEventStreamV1,
    SessionWindowV1,
    StreamSpecV1,
    UniverseMemberV1,
    prepare_events,
)
from leviathan_core.backtest_lab.costs import (
    FeeModelV1,
    FinancingRatesV1,
    accrue_financing,
)
from leviathan_core.backtest_lab.fills import (
    FillPolicyV1,
    FillTraceV1,
    match,
)
from leviathan_core.backtest_lab.latency import (
    EmpiricalLatencyV1,
    FixedLatencyV1,
    LatencyDistributionV1,
    LatencyModelV1,
    LognormalLatencyV1,
    NormalLatencyV1,
    sample_total_latency,
)
from leviathan_core.backtest_lab.orders import (
    FillKernelError,
    FillPolicyError,
    FillRequestV1,
    FillValidationError,
    OrderRejectedError,
)
from leviathan_core.numeric import Ratio, canonical_json

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "fills"
SESSION = SessionWindowV1("XNYS", "2026-01-02", 0, 100)
ZERO = Decimal("0")


def _fixture(name: str) -> dict[str, Any]:
    return cast(
        dict[str, Any],
        json.loads((FIXTURE_DIR / name).read_text(encoding="utf-8")),
    )


def _latency(
    strategy: LatencyDistributionV1 | None = None,
    network: LatencyDistributionV1 | None = None,
    venue: LatencyDistributionV1 | None = None,
) -> LatencyModelV1:
    return LatencyModelV1(
        strategy=strategy or FixedLatencyV1(0, "fixed-v1"),
        network=network or FixedLatencyV1(0, "fixed-v1"),
        venue=venue or FixedLatencyV1(0, "fixed-v1"),
        version="latency-v1",
    )


def _fees(
    *,
    fee_per_share: Decimal = ZERO,
    fee_bps: Decimal = ZERO,
    rebate_per_share: Decimal = ZERO,
    rebate_bps: Decimal = ZERO,
    minimum_order_fee: Decimal | None = None,
    maximum_order_fee: Decimal | None = None,
    currency: str = "USD",
    minor_units: int = 2,
) -> FeeModelV1:
    return FeeModelV1(
        version="fees-v1",
        currency=currency,
        minor_units=minor_units,
        fee_per_share=fee_per_share,
        fee_bps=fee_bps,
        rebate_per_share=rebate_per_share,
        rebate_bps=rebate_bps,
        minimum_order_fee=minimum_order_fee,
        maximum_order_fee=maximum_order_fee,
    )


def _policy(
    *,
    mode: str = "L1_TOP_OF_BOOK",
    latency: LatencyModelV1 | None = None,
    fees: FeeModelV1 | None = None,
    book_share: Decimal = Decimal(1),
    max_book_age_ns: int = 50,
    calendar_id: str = "xnys-calendar",
    calendar_version: str = "2026-v1",
) -> FillPolicyV1:
    return FillPolicyV1(
        version="fill-policy-v1",
        calendar_id=calendar_id,
        calendar_version=calendar_version,
        execution_mode=mode,  # type: ignore[arg-type]
        queue_model="PRICE_TIME_BOOK_SHARE",
        latency=latency or _latency(),
        fees=fees or _fees(),
        max_book_age_ns=max_book_age_ns,
        book_share=book_share,
    )


def _request(
    *,
    request_id: str = "acceptance-order",
    side: str = "BUY",
    order_type: str = "MARKET",
    time_in_force: str = "DAY",
    quantity: Decimal = Decimal("1"),
    submit_ns: int = 0,
    submit_sequence: int = 0,
    limit_price: Decimal | None = None,
    stop_price: Decimal | None = None,
    expires_ns: int | None = None,
    cancel_ns: int | None = None,
    cancel_sequence: int | None = None,
    session: SessionWindowV1 = SESSION,
    sessions: tuple[SessionWindowV1, ...] | None = None,
    venue: str = "XNYS",
    calendar_id: str = "xnys-calendar",
    calendar_version: str = "2026-v1",
    currency: str = "USD",
) -> FillRequestV1:
    return FillRequestV1(
        request_id=request_id,
        instrument="XYZ",
        venue=venue,
        side=side,  # type: ignore[arg-type]
        order_type=order_type,  # type: ignore[arg-type]
        time_in_force=time_in_force,  # type: ignore[arg-type]
        quantity=quantity,
        submit_ns=submit_ns,
        submit_sequence=submit_sequence,
        currency=currency,
        calendar_id=calendar_id,
        calendar_version=calendar_version,
        session=session,
        limit_price=limit_price,
        stop_price=stop_price,
        expires_ns=expires_ns,
        cancel_ns=cancel_ns,
        cancel_sequence=cancel_sequence,
        sessions=sessions if sessions is not None else (session,),
    )


def _event_rows(*rows: dict[str, Any]) -> list[MarketEventV1]:
    events: list[MarketEventV1] = []
    for index, row in enumerate(rows, start=1):
        sequence = int(row.get("sequence", index))
        levels = tuple(
            BookLevelV1(
                side=level["side"],
                price=Decimal(level["price"]),
                size=Decimal(level["size"]),
            )
            for level in row.get("levels", ())
        )

        def decimal(name: str, source_row: dict[str, Any] = row) -> Decimal | None:
            value = source_row.get(name)
            return Decimal(value) if value is not None else None

        event_ns = int(row["event_ns"])
        events.append(
            MarketEventV1(
                dataset_id="bt003-fixture-dataset",
                dataset_version="dataset-v1",
                universe_version="universe-v1",
                source="synthetic-feed",
                source_id=str(row.get("source_id", f"event-{sequence}")),
                correction_key="original",
                stream_id="ticks",
                event_ns=event_ns,
                available_ns=int(row.get("available_ns", event_ns)),
                instrument="XYZ",
                venue="XNYS",
                sequence=sequence,
                kind=row["kind"],
                price=decimal("price"),
                size=decimal("size"),
                levels=levels,
                bid_price=decimal("bid_price"),
                bid_size=decimal("bid_size"),
                ask_price=decimal("ask_price"),
                ask_size=decimal("ask_size"),
            )
        )
    return events


def _prepared(
    rows: list[dict[str, Any]],
    *,
    session: SessionWindowV1 = SESSION,
    sessions: tuple[SessionWindowV1, ...] = (),
    chunk_size: int | None = None,
    view: str = "PIT",
) -> PreparedEventStreamV1:
    events = _event_rows(*rows)
    manifest_sessions = sessions or (session,)
    manifest = DatasetManifestV1(
        dataset_id="bt003-fixture-dataset",
        dataset_version="dataset-v1",
        universe_version="universe-v1",
        symbol_mapping_version="symbols-v1",
        calendar_id="xnys-calendar",
        calendar_version="2026-v1",
        adjustment_version="raw-v1",
        as_of_ns=max(item.close_ns for item in manifest_sessions),
        start_ns=min(item.open_ns for item in manifest_sessions),
        end_ns=max(item.close_ns for item in manifest_sessions),
        source_checksums=(("synthetic-feed", "a" * 64),),
        universe=(UniverseMemberV1("XYZ", "XNYS", 0),),
        sessions=manifest_sessions,
        streams=(StreamSpecV1("ticks", "synthetic-feed", "XNYS", priority=0),),
        max_identity_cache=1000,
    )
    policy = AdjustmentPolicyV1("raw", "raw-v1", view=cast(Any, view))
    if chunk_size is None:
        source: Iterable[MarketEventV1] = events
    else:

        def chunks() -> Iterator[MarketEventV1]:
            for offset in range(0, len(events), chunk_size):
                yield from events[offset : offset + chunk_size]

        source = chunks()
    return prepare_events(manifest, source, policy)


def _scenario_rows(scenario: dict[str, Any]) -> list[dict[str, Any]]:
    return [dict(row) for row in scenario["events"]]


def _midpoint(bid: str, ask: str) -> Decimal:
    return (Decimal(bid) + Decimal(ask)) / Decimal(2)


@pytest.mark.parametrize("order_type", ["MARKET", "LIMIT", "STOP", "STOP_LIMIT"])
@pytest.mark.parametrize("time_in_force", ["DAY", "GTC", "IOC", "FOK"])
def test_closed_order_type_and_tif_values_are_accepted(order_type: str, time_in_force: str) -> None:
    kwargs: dict[str, Any] = {}
    if order_type in ("LIMIT", "STOP_LIMIT"):
        kwargs["limit_price"] = Decimal("101")
    if order_type in ("STOP", "STOP_LIMIT"):
        kwargs["stop_price"] = Decimal("100")
    if time_in_force == "GTC":
        kwargs["expires_ns"] = 90
    request = _request(order_type=order_type, time_in_force=time_in_force, **kwargs)
    assert request.order_type == order_type
    assert request.time_in_force == time_in_force


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("side", "SHORT", "INVALID_SIDE"),
        ("order_type", "TRAILING_STOP", "INVALID_ORDER_TYPE"),
        ("time_in_force", "GTD", "INVALID_TIME_IN_FORCE"),
        ("quantity", Decimal("0"), "OUT_OF_RANGE"),
        ("quantity", Decimal("NaN"), "INVALID_DECIMAL"),
        ("submit_ns", True, "INVALID_UTC_NS"),
        ("submit_ns", -1, "INVALID_UTC_NS"),
        ("currency", "usd", "INVALID_CURRENCY"),
    ],
)
def test_request_rejects_invalid_order_values_with_closed_codes(
    field: str, value: object, code: str
) -> None:
    with pytest.raises(FillValidationError) as invalid:
        _request(**cast(Any, {field: value}))
    assert invalid.value.code == code
    assert str(invalid.value) == code


def test_calendar_identity_venue_and_submit_window_fail_closed() -> None:
    with pytest.raises(FillValidationError) as bad_venue:
        _request(venue="XNAS")
    assert bad_venue.value.code == "INVALID_SESSION"

    with pytest.raises(FillValidationError) as at_close:
        _request(submit_ns=SESSION.close_ns)
    assert at_close.value.code == "INVALID_SESSION"

    rows = [
        {
            "kind": "quote",
            "event_ns": 10,
            "bid_price": "99.5",
            "bid_size": "5",
            "ask_price": "100",
            "ask_size": "5",
        }
    ]
    with pytest.raises(FillPolicyError) as mismatch:
        match(_request(), _policy(calendar_version="wrong-version"), _prepared(rows))
    assert mismatch.value.code == "CALENDAR_MISMATCH"
    assert str(mismatch.value) == "CALENDAR_MISMATCH"

    wider_calendar = SessionWindowV1("XNYS", "2026-01-02", 0, 200)
    outside_request_window = [
        {
            "kind": "quote",
            "event_ns": 100,
            "bid_price": "99",
            "bid_size": "1",
            "ask_price": "100",
            "ask_size": "1",
        }
    ]
    outside = match(
        _request(),
        _policy(),
        _prepared(outside_request_window, session=wider_calendar),
    )
    assert outside.status == "UNFILLED"
    assert not outside.fills


def test_policy_rejects_unsupported_mode_queue_and_book_share() -> None:
    with pytest.raises(FillPolicyError) as mode:
        _policy(mode="MIDPOINT")
    assert mode.value.code == "INVALID_EXECUTION_MODE"

    with pytest.raises(FillPolicyError) as queue:
        FillPolicyV1(
            version="policy-v1",
            calendar_id="xnys-calendar",
            calendar_version="2026-v1",
            execution_mode="L1_TOP_OF_BOOK",
            queue_model=cast(Any, "CANCEL_AWARE"),
            latency=_latency(),
            fees=_fees(),
            max_book_age_ns=10,
        )
    assert queue.value.code == "INVALID_QUEUE_MODEL"

    with pytest.raises(FillPolicyError) as share:
        _policy(book_share=Decimal("1.01"))
    assert share.value.code == "BOOK_SHARE_OUT_OF_BOUNDS"


def test_fee_and_latency_reject_nonfinite_or_invalid_parameters() -> None:
    with pytest.raises(FillValidationError) as fee:
        _fees(fee_bps=Decimal("Infinity"))
    assert fee.value.code == "INVALID_DECIMAL"

    with pytest.raises(FillValidationError) as lognormal:
        LognormalLatencyV1(Decimal("NaN"), Decimal("0.1"), 1, "lognormal-v1")
    assert lognormal.value.code == "INVALID_DECIMAL"

    with pytest.raises(FillValidationError) as seed:
        NormalLatencyV1(1, 1, -1, "normal-v1")
    assert seed.value.code == "INVALID_SEED"


@pytest.mark.parametrize(
    "mode", ["L1_TOP_OF_BOOK", "L1_DEPTH_PROXY", "SYNTHETIC_L2", "RECORDED_L2"]
)
def test_supported_execution_modes_are_closed_and_recorded(mode: str) -> None:
    if mode in ("L1_TOP_OF_BOOK", "L1_DEPTH_PROXY"):
        rows = [
            {
                "kind": "quote",
                "event_ns": 10,
                "bid_price": "99.5",
                "bid_size": "2",
                "ask_price": "100",
                "ask_size": "2",
            }
        ]
    else:
        rows = [
            {
                "kind": "book_snapshot",
                "event_ns": 10,
                "levels": [
                    {"side": "bid", "price": "99.5", "size": "2"},
                    {"side": "ask", "price": "100", "size": "2"},
                ],
            }
        ]
    trace = match(_request(), _policy(mode=mode), _prepared(rows))
    assert trace.execution_mode == mode
    assert trace.fills[0].price == Decimal("100")


def test_midpoint_is_benchmark_only_and_fill_uses_executable_quote() -> None:
    rows = [
        {
            "kind": "quote",
            "event_ns": 10,
            "bid_price": "100",
            "bid_size": "5",
            "ask_price": "102",
            "ask_size": "5",
        }
    ]
    trace = match(_request(), _policy(mode="L1_MIDPOINT_BENCHMARK"), _prepared(rows))
    assert trace.execution_mode == "L1_MIDPOINT_BENCHMARK"
    assert trace.benchmark_midpoint == Decimal("101")
    assert trace.fills[0].price == Decimal("102")
    assert trace.fills[0].reference_price == Decimal("101")
    assert trace.implementation_shortfall == Decimal("1.00")


def test_limit_uses_only_opposite_executable_quote_at_limit_or_better() -> None:
    rows = [
        {
            "kind": "quote",
            "event_ns": 10,
            "bid_price": "99",
            "bid_size": "5",
            "ask_price": "100.5",
            "ask_size": "5",
        },
        {
            "kind": "quote",
            "event_ns": 11,
            "bid_price": "99.5",
            "bid_size": "5",
            "ask_price": "100",
            "ask_size": "5",
        },
    ]
    trace = match(
        _request(order_type="LIMIT", limit_price=Decimal("100")),
        _policy(),
        _prepared(rows),
    )
    assert trace.status == "FILLED"
    assert [fill.price for fill in trace.fills] == [Decimal("100")]
    assert trace.fills[0].visible_ns == 11


@pytest.mark.parametrize(
    ("side", "limit_price", "trade_price"),
    [
        ("BUY", Decimal("99.5"), Decimal("99.5")),
        ("SELL", Decimal("100.5"), Decimal("100.5")),
    ],
)
def test_l1_passive_orders_fill_at_improved_inside_prices(
    side: str, limit_price: Decimal, trade_price: Decimal
) -> None:
    rows = [
        {
            "kind": "quote",
            "event_ns": 10,
            "bid_price": "99",
            "bid_size": "10",
            "ask_price": "101",
            "ask_size": "10",
        },
        {
            "kind": "trade",
            "event_ns": 11,
            "price": str(trade_price),
            "size": "5",
        },
    ]
    trace = match(
        _request(
            side=side,
            order_type="LIMIT",
            quantity=Decimal("3"),
            limit_price=limit_price,
        ),
        _policy(mode="L1_TOP_OF_BOOK"),
        _prepared(rows),
    )

    assert trace.status == "FILLED"
    assert trace.filled_quantity == Decimal("3")
    assert trace.fills[0].price == limit_price
    assert trace.fills[0].visible_ns == 11


def test_market_walks_only_the_current_visible_depth_and_cancels_remainder() -> None:
    rows = [
        {
            "kind": "quote",
            "event_ns": 10,
            "bid_price": "99",
            "bid_size": "10",
            "ask_price": "100",
            "ask_size": "1",
        },
        {
            "kind": "quote",
            "event_ns": 11,
            "bid_price": "99",
            "bid_size": "10",
            "ask_price": "100.1",
            "ask_size": "10",
        },
    ]
    trace = match(_request(quantity=Decimal("2")), _policy(), _prepared(rows))
    assert trace.status == "PARTIALLY_FILLED"
    assert trace.filled_quantity == Decimal("1")
    assert trace.remaining_quantity == Decimal("1")
    assert trace.transitions[-1].state_after == "CANCELLED"
    assert trace.transitions[-1].reason == "UNFILLED_NO_LIQUIDITY"


def test_l2_walks_best_price_first_and_never_invents_depth() -> None:
    rows = [
        {
            "kind": "book_snapshot",
            "event_ns": 10,
            "levels": [
                {"side": "bid", "price": "99.5", "size": "4"},
                {"side": "ask", "price": "100.1", "size": "1"},
                {"side": "ask", "price": "100.2", "size": "2"},
            ],
        }
    ]
    trace = match(
        _request(quantity=Decimal("5")),
        _policy(mode="SYNTHETIC_L2"),
        _prepared(rows),
    )
    assert [fill.price for fill in trace.fills] == [Decimal("100.1"), Decimal("100.2")]
    assert [fill.quantity for fill in trace.fills] == [Decimal("1"), Decimal("2")]
    assert trace.filled_quantity == Decimal("3")
    assert trace.remaining_quantity == Decimal("2")
    assert trace.transitions[-1].reason == "UNFILLED_NO_LIQUIDITY"


@pytest.mark.parametrize("mode", ["L1_TOP_OF_BOOK", "SYNTHETIC_L2"])
def test_own_fills_consume_a_persistent_ten_share_level(mode: str) -> None:
    if mode == "L1_TOP_OF_BOOK":
        rows: list[dict[str, Any]] = [{
            "kind": "quote",
            "event_ns": 10,
            "bid_price": "99.5",
            "bid_size": "10",
            "ask_price": "100",
            "ask_size": "10",
        }]
    else:
        rows = [{
            "kind": "book_snapshot",
            "event_ns": 10,
            "levels": [
                {"side": "bid", "price": "99.5", "size": "10"},
                {"side": "ask", "price": "100", "size": "10"},
            ],
        }]
    rows.extend(
        {"kind": "trade", "event_ns": ns, "price": "99.5", "size": "1"}
        for ns in range(11, 46)
    )

    trace = match(
        _request(order_type="LIMIT", quantity=Decimal("35"), limit_price=Decimal("100")),
        _policy(mode=mode),
        _prepared(rows),
    )

    assert trace.status == "PARTIALLY_FILLED"
    assert trace.filled_quantity == Decimal("10")
    assert trace.remaining_quantity == Decimal("25")
    assert sum((fill.quantity for fill in trace.fills), ZERO) == Decimal("10")


def test_l2_consumed_depth_survives_unrelated_l1_quote_events() -> None:
    rows = [
        {
            "kind": "book_snapshot",
            "event_ns": 10,
            "levels": [
                {"side": "bid", "price": "100", "size": "10"},
                {"side": "ask", "price": "101", "size": "10"},
            ],
        },
        {"kind": "trade", "event_ns": 11, "price": "100", "size": "1"},
        {
            "kind": "quote",
            "event_ns": 12,
            "bid_price": "99.5",
            "bid_size": "10",
            "ask_price": "100.5",
            "ask_size": "10",
        },
        {"kind": "trade", "event_ns": 13, "price": "100", "size": "1"},
        {"kind": "trade", "event_ns": 14, "price": "100", "size": "1"},
    ]
    trace = match(
        _request(
            order_type="LIMIT",
            quantity=Decimal("35"),
            submit_ns=10,
            submit_sequence=2,
            limit_price=Decimal("101"),
        ),
        _policy(mode="SYNTHETIC_L2"),
        _prepared(rows),
    )

    assert trace.status == "PARTIALLY_FILLED"
    assert trace.filled_quantity == Decimal("10")
    assert trace.remaining_quantity == Decimal("25")


def test_l1_consumed_depth_survives_unrelated_l2_book_snapshots() -> None:
    rows = [
        {
            "kind": "quote",
            "event_ns": 10,
            "bid_price": "100",
            "bid_size": "10",
            "ask_price": "101",
            "ask_size": "10",
        },
        {"kind": "trade", "event_ns": 11, "price": "100", "size": "1"},
        {
            "kind": "book_snapshot",
            "event_ns": 12,
            "levels": [
                {"side": "bid", "price": "100", "size": "20"},
                {"side": "ask", "price": "101", "size": "20"},
            ],
        },
        {"kind": "trade", "event_ns": 13, "price": "100", "size": "1"},
        {"kind": "trade", "event_ns": 14, "price": "100", "size": "1"},
    ]
    trace = match(
        _request(
            order_type="LIMIT",
            quantity=Decimal("35"),
            submit_ns=10,
            submit_sequence=2,
            limit_price=Decimal("101"),
        ),
        _policy(mode="L1_TOP_OF_BOOK"),
        _prepared(rows),
    )

    assert trace.status == "PARTIALLY_FILLED"
    assert trace.filled_quantity == Decimal("10")
    assert trace.remaining_quantity == Decimal("25")


@pytest.mark.parametrize("mode", ["SYNTHETIC_L2", "RECORDED_L2"])
def test_l2_missing_or_stale_book_fails_before_fill(mode: str) -> None:
    no_book = [
        {
            "kind": "quote",
            "event_ns": 10,
            "bid_price": "99",
            "bid_size": "1",
            "ask_price": "100",
            "ask_size": "1",
        }
    ]
    with pytest.raises(FillKernelError) as missing:
        match(_request(), _policy(mode=mode), _prepared(no_book))
    assert missing.value.code == "DEPTH_UNAVAILABLE"

    stale = [
        {
            "kind": "book_snapshot",
            "event_ns": 10,
            "levels": [
                {"side": "bid", "price": "99", "size": "1"},
                {"side": "ask", "price": "100", "size": "1"},
            ],
        },
        {
            "kind": "quote",
            "event_ns": 13,
            "bid_price": "99.5",
            "bid_size": "1",
            "ask_price": "100",
            "ask_size": "1",
        },
    ]
    with pytest.raises(FillKernelError) as old:
        match(
            _request(order_type="LIMIT", limit_price=Decimal("98"), submit_ns=10),
            _policy(mode=mode, max_book_age_ns=2),
            _prepared(stale),
        )
    assert old.value.code == "BOOK_STALE"


def test_latency_components_apply_before_matching_at_exact_boundary() -> None:
    latency = _latency(
        FixedLatencyV1(2, "strategy-v1"),
        FixedLatencyV1(3, "network-v1"),
        FixedLatencyV1(4, "venue-v1"),
    )
    rows = [
        {
            "kind": "quote",
            "event_ns": 8,
            "bid_price": "99",
            "bid_size": "2",
            "ask_price": "100",
            "ask_size": "2",
        },
        {
            "kind": "quote",
            "event_ns": 9,
            "bid_price": "99.5",
            "bid_size": "2",
            "ask_price": "101",
            "ask_size": "2",
        },
    ]
    trace = match(_request(submit_ns=0), _policy(latency=latency), _prepared(rows))
    assert (trace.latency_strategy_ns, trace.latency_network_ns, trace.latency_venue_ns) == (
        2,
        3,
        4,
    )
    assert trace.eligible_from_ns == 9
    assert trace.fills[0].visible_ns == 9
    assert trace.fills[0].price == Decimal("101")


def test_pre_eligibility_l2_snapshot_and_delta_supply_current_depth() -> None:
    rows = [
        {
            "kind": "book_snapshot",
            "event_ns": 5,
            "levels": [
                {"side": "bid", "price": "99", "size": "2"},
                {"side": "ask", "price": "100", "size": "1"},
            ],
        },
        {
            "kind": "book_delta",
            "event_ns": 9,
            "levels": [{"side": "ask", "price": "100", "size": "2"}],
        },
        {"kind": "trade", "event_ns": 11, "price": "99.5", "size": "1"},
    ]
    trace = match(
        _request(submit_ns=10, quantity=Decimal("2")),
        _policy(mode="SYNTHETIC_L2"),
        _prepared(rows),
    )

    assert trace.status == "FILLED"
    assert trace.filled_quantity == Decimal("2")
    assert trace.fills[0].visible_ns == 11


def test_pre_eligibility_l1_quote_persists_and_quote_age_is_enforced() -> None:
    rows = [
        {
            "kind": "quote",
            "event_ns": 5,
            "bid_price": "99",
            "bid_size": "2",
            "ask_price": "100",
            "ask_size": "2",
        },
        {"kind": "trade", "event_ns": 11, "price": "99.5", "size": "1"},
    ]
    trace = match(
        _request(submit_ns=10),
        _policy(max_book_age_ns=10),
        _prepared(rows),
    )
    assert trace.status == "FILLED"
    assert trace.fills[0].visible_ns == 11
    assert trace.fills[0].price == Decimal("100")

    stale_rows = [rows[0], {**rows[1], "event_ns": 16}]
    with pytest.raises(FillKernelError) as stale:
        match(
            _request(submit_ns=10),
            _policy(max_book_age_ns=10),
            _prepared(stale_rows),
        )
    assert stale.value.code == "BOOK_STALE"


def test_seeded_latency_distributions_are_stable_and_not_global_rng(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise AssertionError("fill kernel used process-global random state")

    for name in (
        "random",
        "randint",
        "randrange",
        "normalvariate",
        "gauss",
        "lognormvariate",
    ):
        monkeypatch.setattr(random, name, forbidden)

    models = (
        NormalLatencyV1(100, 10, 1234, "normal-v1"),
        LognormalLatencyV1(Decimal("2"), Decimal("0.2"), 1234, "lognormal-v1"),
    )
    for distribution in models:
        model = _latency(strategy=distribution)
        first = sample_total_latency(model, "stable-request")
        second = sample_total_latency(model, "stable-request")
        assert first == second
        assert first[3] == first[0] + first[1] + first[2]

    empirical_samples = (2, 7, 11)
    empirical_digest = sha256(
        canonical_json(
            {
                "snapshot_id": "latency-snapshot-v1",
                "samples_ns": empirical_samples,
            }
        )
    ).hexdigest()
    empirical = EmpiricalLatencyV1(
        empirical_samples, 4, "latency-snapshot-v1", empirical_digest, "empirical-v1"
    )
    model = _latency(strategy=empirical)
    assert sample_total_latency(model, "stable-request") == sample_total_latency(
        model, "stable-request"
    )


def test_latency_inputs_require_each_component_and_pinned_empirical_digest() -> None:
    with pytest.raises(FillValidationError) as missing:
        LatencyModelV1(
            cast(Any, None),
            FixedLatencyV1(0, "fixed-v1"),
            FixedLatencyV1(0, "fixed-v1"),
            "latency-v1",
        )
    assert missing.value.code == "INVALID_LATENCY_COMPONENT"

    with pytest.raises(FillValidationError) as digest:
        EmpiricalLatencyV1((2, 7), 1, "snapshot-v1", "0" * 64, "empirical-v1")
    assert digest.value.code == "EMPIRICAL_SNAPSHOT_MISMATCH"


def test_stop_triggers_only_on_eligible_trade_and_becomes_market() -> None:
    rows = [
        {
            "kind": "quote",
            "event_ns": 10,
            "bid_price": "99",
            "bid_size": "2",
            "ask_price": "100",
            "ask_size": "2",
        },
        {"kind": "trade", "event_ns": 11, "price": "99.5", "size": "1"},
        {"kind": "trade", "event_ns": 12, "price": "100", "size": "1"},
        {
            "kind": "quote",
            "event_ns": 13,
            "bid_price": "100",
            "bid_size": "2",
            "ask_price": "100.5",
            "ask_size": "2",
        },
    ]
    trace = match(
        _request(order_type="STOP", stop_price=Decimal("100")),
        _policy(),
        _prepared(rows),
    )
    assert trace.status == "FILLED"
    assert trace.fills[0].visible_ns == 12
    assert trace.fills[0].price == Decimal("100")
    assert any(
        row.visible_ns == 12
        and row.state_before == "PENDING_TRIGGER"
        and row.state_after == "FILLED"
        for row in trace.transitions
    )


def test_quote_alone_does_not_trigger_stop_or_stop_limit() -> None:
    rows = [
        {
            "kind": "quote",
            "event_ns": 10,
            "bid_price": "101",
            "bid_size": "4",
            "ask_price": "102",
            "ask_size": "4",
        }
    ]
    for order_type, extra in (
        ("STOP", {"stop_price": Decimal("100")}),
        ("STOP_LIMIT", {"stop_price": Decimal("100"), "limit_price": Decimal("103")}),
    ):
        trace = match(
            _request(order_type=order_type, **extra),  # type: ignore[arg-type]
            _policy(),
            _prepared(rows),
        )
        assert trace.status == "UNFILLED"
        assert not trace.fills
        assert trace.transitions[0].state_before == "PENDING_TRIGGER"


def test_stop_limit_converts_to_limit_after_trade_trigger() -> None:
    rows = [
        {"kind": "trade", "event_ns": 10, "price": "101", "size": "1"},
        {
            "kind": "quote",
            "event_ns": 11,
            "bid_price": "100.5",
            "bid_size": "2",
            "ask_price": "101.5",
            "ask_size": "2",
        },
    ]
    trace = match(
        _request(order_type="STOP_LIMIT", stop_price=Decimal("100"), limit_price=Decimal("102")),
        _policy(),
        _prepared(rows),
    )
    assert trace.status == "FILLED"
    assert trace.fills[0].price == Decimal("101.5")


def test_ioc_attempts_only_first_eligible_event_and_cancels_remainder() -> None:
    rows = [
        {
            "kind": "quote",
            "event_ns": 10,
            "bid_price": "99",
            "bid_size": "2",
            "ask_price": "100.5",
            "ask_size": "2",
        },
        {
            "kind": "quote",
            "event_ns": 11,
            "bid_price": "99",
            "bid_size": "2",
            "ask_price": "100",
            "ask_size": "2",
        },
    ]
    trace = match(
        _request(order_type="LIMIT", time_in_force="IOC", limit_price=Decimal("100")),
        _policy(),
        _prepared(rows),
    )
    assert trace.status == "CANCELLED"
    assert not trace.fills
    assert trace.transitions[-1].reason == "IOC_REMAINDER_CANCELLED"


@pytest.mark.parametrize(
    "quantity,expected_status,expected_fills",
    [
        (Decimal("2"), "FILLED", Decimal("2")),
        (Decimal("3"), "CANCELLED", Decimal("0")),
    ],
)
def test_fok_is_all_or_none_across_levels_at_one_event(
    quantity: Decimal, expected_status: str, expected_fills: Decimal
) -> None:
    rows = [
        {
            "kind": "book_snapshot",
            "event_ns": 10,
            "levels": [
                {"side": "bid", "price": "99", "size": "10"},
                {"side": "ask", "price": "100", "size": "1"},
                {"side": "ask", "price": "101", "size": "1"},
            ],
        }
    ]
    trace = match(
        _request(time_in_force="FOK", quantity=quantity),
        _policy(mode="RECORDED_L2"),
        _prepared(rows),
    )
    assert trace.status == expected_status
    assert trace.filled_quantity == expected_fills
    if expected_fills == 0:
        assert trace.remaining_quantity == quantity
        assert trace.transitions[-1].reason == "FOK_NOT_FILLED"


def test_day_expires_at_pinned_session_boundary_and_gtc_honors_expiry() -> None:
    rows = [
        {
            "kind": "quote",
            "event_ns": 10,
            "bid_price": "99",
            "bid_size": "2",
            "ask_price": "101",
            "ask_size": "2",
        }
    ]
    day = match(
        _request(order_type="LIMIT", time_in_force="DAY", limit_price=Decimal("100")),
        _policy(),
        _prepared(rows),
    )
    assert day.status == "UNFILLED"
    assert day.remaining_quantity == Decimal("1")

    later = [
        rows[0],
        {
            "kind": "quote",
            "event_ns": 20,
            "bid_price": "100",
            "bid_size": "2",
            "ask_price": "100.5",
            "ask_size": "2",
        },
    ]
    gtc = match(
        _request(
            order_type="LIMIT", time_in_force="GTC", limit_price=Decimal("100"), expires_ns=15
        ),
        _policy(),
        _prepared(later),
    )
    assert gtc.status == "UNFILLED"
    assert not gtc.fills


def test_day_limit_can_partially_fill_then_finish_across_events() -> None:
    rows = [
        {
            "kind": "book_snapshot",
            "event_ns": 10,
            "levels": [
                {"side": "bid", "price": "100", "size": "1"},
                {"side": "ask", "price": "100.5", "size": "1"},
            ],
        },
        {"kind": "trade", "event_ns": 11, "price": "100", "size": "2"},
        {"kind": "trade", "event_ns": 12, "price": "100", "size": "2"},
    ]
    trace = match(
        _request(order_type="LIMIT", quantity=Decimal("2"), limit_price=Decimal("100")),
        _policy(mode="SYNTHETIC_L2"),
        _prepared(rows),
    )
    assert trace.status == "FILLED"
    assert [fill.visible_ns for fill in trace.fills] == [11, 12]
    assert [fill.quantity for fill in trace.fills] == [Decimal("1"), Decimal("1")]
    assert trace.filled_quantity == Decimal("2")
    assert trace.remaining_quantity == Decimal("0")


def test_passive_fill_consumes_displayed_same_price_liquidity() -> None:
    rows = [
        {
            "kind": "book_snapshot",
            "event_ns": 10,
            "levels": [
                {"side": "bid", "price": "100", "size": "1"},
                {"side": "ask", "price": "100.5", "size": "1"},
            ],
        },
        {"kind": "trade", "event_ns": 11, "price": "100", "size": "2"},
        {"kind": "trade", "event_ns": 12, "price": "100", "size": "2"},
    ]
    trace = match(
        _request(order_type="LIMIT", quantity=Decimal("2"), limit_price=Decimal("100")),
        _policy(mode="SYNTHETIC_L2"),
        _prepared(rows),
    )

    assert trace.status == "FILLED"
    assert trace.filled_quantity == Decimal("2")
    assert trace.remaining_quantity == Decimal("0")
    assert [fill.visible_ns for fill in trace.fills] == [11, 12]


def test_cancel_race_uses_stable_same_timestamp_sequence() -> None:
    rows = [
        {
            "kind": "quote",
            "event_ns": 10,
            "sequence": 1,
            "bid_price": "100",
            "bid_size": "1",
            "ask_price": "100.5",
            "ask_size": "1",
        },
        {"kind": "trade", "event_ns": 11, "sequence": 2, "price": "100", "size": "2"},
        {"kind": "trade", "event_ns": 11, "sequence": 3, "price": "100", "size": "10"},
    ]
    trace = match(
        _request(
            order_type="LIMIT",
            quantity=Decimal("2"),
            limit_price=Decimal("100"),
            cancel_ns=11,
            cancel_sequence=3,
        ),
        _policy(mode="L1_TOP_OF_BOOK"),
        _prepared(rows),
    )
    assert trace.status == "PARTIALLY_FILLED"
    assert trace.filled_quantity == Decimal("1")
    assert trace.remaining_quantity == Decimal("1")
    assert trace.fills[0].visible_ns == 11


def test_cancel_effective_time_includes_declared_latency() -> None:
    latency = _latency(
        FixedLatencyV1(2, "cancel-strategy-v1"),
        FixedLatencyV1(1, "cancel-network-v1"),
        FixedLatencyV1(1, "cancel-venue-v1"),
    )
    rows = [
        {
            "kind": "book_snapshot",
            "event_ns": 5,
            "levels": [
                {"side": "bid", "price": "100", "size": "2"},
                {"side": "ask", "price": "101", "size": "5"},
            ],
        },
        {"kind": "trade", "event_ns": 11, "price": "100", "size": "1"},
        {"kind": "trade", "event_ns": 13, "price": "100", "size": "1"},
        {"kind": "trade", "event_ns": 14, "price": "100", "size": "1"},
    ]
    trace = match(
        _request(
            order_type="LIMIT",
            quantity=Decimal("3"),
            limit_price=Decimal("100"),
            cancel_ns=10,
            cancel_sequence=1,
        ),
        _policy(mode="SYNTHETIC_L2", latency=latency, book_share=ZERO),
        _prepared(rows),
    )
    assert trace.status == "PARTIALLY_FILLED"
    assert trace.filled_quantity == Decimal("2")
    assert [fill.visible_ns for fill in trace.fills] == [11, 13]


def test_cancel_submitted_before_order_eligibility_still_has_latency() -> None:
    latency = _latency(
        FixedLatencyV1(1, "preeligible-cancel-strategy-v1"),
        FixedLatencyV1(2, "preeligible-cancel-network-v1"),
        FixedLatencyV1(2, "preeligible-cancel-venue-v1"),
    )
    rows = [
        {
            "kind": "book_snapshot",
            "event_ns": 5,
            "levels": [
                {"side": "bid", "price": "100", "size": "1"},
                {"side": "ask", "price": "101", "size": "5"},
            ],
        },
        {"kind": "trade", "event_ns": 15, "price": "100", "size": "1"},
        {"kind": "trade", "event_ns": 16, "price": "100", "size": "1"},
    ]
    trace = match(
        _request(
            order_type="LIMIT",
            quantity=Decimal("2"),
            submit_ns=10,
            limit_price=Decimal("100"),
            cancel_ns=11,
            cancel_sequence=1,
        ),
        _policy(mode="SYNTHETIC_L2", latency=latency, book_share=ZERO),
        _prepared(rows),
    )
    assert trace.eligible_from_ns == 15
    assert trace.status == "PARTIALLY_FILLED"
    assert trace.filled_quantity == Decimal("1")
    assert trace.fills[0].visible_ns == 15


def test_eligibility_boundary_uses_sequence_after_submit_sequence() -> None:
    before_submit = [{
        "kind": "quote",
        "event_ns": 10,
        "sequence": 4,
        "bid_price": "99",
        "bid_size": "1",
        "ask_price": "100",
        "ask_size": "1",
    }]
    not_yet_eligible = match(
        _request(submit_ns=10, submit_sequence=5),
        _policy(),
        _prepared(before_submit),
    )
    assert not not_yet_eligible.fills

    at_submit_sequence = match(
        _request(submit_ns=10, submit_sequence=5),
        _policy(),
        _prepared([
            *before_submit,
            {"kind": "trade", "event_ns": 10, "sequence": 5, "price": "99.5", "size": "1"},
        ]),
    )
    assert at_submit_sequence.status == "FILLED"
    assert at_submit_sequence.fills[0].visible_ns == 10
    assert len(at_submit_sequence.transitions) == 1
    assert at_submit_sequence.fills[0].event_id == at_submit_sequence.transitions[0].event_id


@pytest.mark.parametrize("mode", ["SYNTHETIC_L2", "RECORDED_L2"])
def test_queue_ahead_defaults_to_full_displayed_size_and_cancels_do_not_reduce_it(
    mode: str,
) -> None:
    rows = [
        {
            "kind": "book_snapshot",
            "event_ns": 10,
            "levels": [
                {"side": "bid", "price": "100", "size": "5"},
                {"side": "ask", "price": "100.5", "size": "1"},
            ],
        },
        {"kind": "trade", "event_ns": 11, "price": "100", "size": "2"},
        {
            "kind": "book_delta",
            "event_ns": 12,
            "levels": [
                {"side": "bid", "price": "100", "size": "0"},
            ],
        },
        {"kind": "trade", "event_ns": 13, "price": "100", "size": "2"},
        {
            "kind": "book_delta",
            "event_ns": 14,
            "levels": [{"side": "bid", "price": "100", "size": "5"}],
        },
        {"kind": "trade", "event_ns": 14, "price": "100", "size": "2"},
    ]
    trace = match(
        _request(order_type="LIMIT", limit_price=Decimal("100")),
        _policy(mode=mode),
        _prepared(rows),
    )
    assert trace.status == "FILLED"
    assert trace.fills[0].visible_ns == 14
    assert trace.fills[0].quantity == Decimal("1")

    half_queue = match(
        _request(request_id="half-queue", order_type="LIMIT", limit_price=Decimal("100")),
        _policy(mode=mode, book_share=Decimal("0.5")),
        _prepared([rows[0], {**rows[1], "size": "3"}]),
    )
    assert half_queue.status == "PARTIALLY_FILLED"
    assert half_queue.fills[0].visible_ns == 11
    assert half_queue.filled_quantity == Decimal("0.5")


def test_queue_ahead_is_captured_from_displayed_depth_when_order_joins() -> None:
    latency = _latency(FixedLatencyV1(2, "queue-join-v1"))
    rows = [
        {
            "kind": "book_snapshot",
            "event_ns": 5,
            "levels": [
                {"side": "bid", "price": "100", "size": "5"},
                {"side": "ask", "price": "100.5", "size": "1"},
            ],
        },
        {"kind": "trade", "event_ns": 10, "price": "100", "size": "20"},
        {
            "kind": "book_delta",
            "event_ns": 11,
            "levels": [{"side": "bid", "price": "100", "size": "2"}],
        },
        {"kind": "trade", "event_ns": 12, "price": "100", "size": "1"},
        {"kind": "trade", "event_ns": 13, "price": "100", "size": "2"},
    ]
    trace = match(
        _request(
            order_type="LIMIT",
            limit_price=Decimal("100"),
            submit_ns=10,
        ),
        _policy(mode="SYNTHETIC_L2", latency=latency),
        _prepared(rows),
    )

    assert trace.eligible_from_ns == 12
    assert trace.status == "FILLED"
    assert trace.filled_quantity == Decimal("1")
    assert trace.fills[0].visible_ns == 13


def test_day_and_gtc_obey_order_pinned_session_windows() -> None:
    first = SessionWindowV1("XNYS", "2026-01-02", 0, 20)
    intervening = SessionWindowV1("XNYS", "2026-01-03", 25, 35)
    second = SessionWindowV1("XNYS", "2026-01-05", 40, 60)
    manifest_sessions = (first, intervening, second)
    request_sessions = (first, second)
    with pytest.raises(EventValidationError):
        list(_prepared(
            [{
                "kind": "quote",
                "event_ns": 30,
                "bid_price": "99",
                "bid_size": "1",
                "ask_price": "100",
                "ask_size": "1",
            }],
            session=first,
            sessions=request_sessions,
        ))

    rows = [
        {
            "kind": "quote",
            "event_ns": 15,
            "bid_price": "99",
            "bid_size": "1",
            "ask_price": "101",
            "ask_size": "1",
        },
        {
            "kind": "quote",
            "event_ns": 30,
            "bid_price": "99",
            "bid_size": "1",
            "ask_price": "100",
            "ask_size": "1",
        },
        {
            "kind": "quote",
            "event_ns": 45,
            "bid_price": "99",
            "bid_size": "1",
            "ask_price": "100",
            "ask_size": "1",
        },
    ]
    events = _prepared(rows, session=first, sessions=manifest_sessions)

    day = match(
        _request(
            order_type="LIMIT",
            limit_price=Decimal("100"),
            submit_ns=10,
            session=first,
            sessions=request_sessions,
        ),
        _policy(),
        events,
    )
    assert day.status == "UNFILLED"
    assert not day.fills

    gtc = match(
        _request(
            request_id="multi-session-gtc",
            order_type="LIMIT",
            time_in_force="GTC",
            limit_price=Decimal("100"),
            submit_ns=10,
            expires_ns=50,
            session=first,
            sessions=request_sessions,
        ),
        _policy(),
        _prepared(rows, session=first, sessions=manifest_sessions),
    )
    assert gtc.status == "FILLED"
    assert gtc.fills[0].visible_ns == 45

    expired = match(
        _request(
            request_id="multi-session-gtc-expired",
            order_type="LIMIT",
            time_in_force="GTC",
            limit_price=Decimal("100"),
            submit_ns=10,
            expires_ns=44,
            session=first,
            sessions=request_sessions,
        ),
        _policy(),
        _prepared(rows, session=first, sessions=manifest_sessions),
    )
    assert expired.status == "UNFILLED"
    assert not expired.fills


def test_fee_rebate_components_and_order_bounds_are_exact_and_separate() -> None:
    fee_model = _fees(
        fee_per_share=Decimal("0.10"),
        fee_bps=Decimal("10"),
        rebate_per_share=Decimal("0.02"),
        rebate_bps=Decimal("1"),
        minimum_order_fee=Decimal("1.00"),
        maximum_order_fee=Decimal("1.50"),
    )
    rows = [
        {
            "kind": "quote",
            "event_ns": 10,
            "bid_price": "99",
            "bid_size": "4",
            "ask_price": "100",
            "ask_size": "4",
        }
    ]
    trace = match(
        _request(quantity=Decimal("2")),
        _policy(fees=fee_model),
        _prepared(rows),
    )
    expected_fee = Fraction(2) * Fraction(10, 100) + Fraction(200) * Fraction(10, 10_000)
    expected_rebate = -(Fraction(2) * Fraction(2, 100) + Fraction(200) * Fraction(1, 10_000))
    assert trace.fills[0].fee_exact == Ratio(expected_fee.numerator, expected_fee.denominator)
    assert trace.fills[0].rebate_exact == Ratio(
        expected_rebate.numerator, expected_rebate.denominator
    )
    assert trace.total_fee == Decimal("1.00")
    assert trace.total_rebate == Decimal("-0.06")

    capped = match(
        _request(request_id="fee-cap", quantity=Decimal("2")),
        _policy(fees=_fees(fee_per_share=Decimal("1"), maximum_order_fee=Decimal("1.50"))),
        _prepared(rows),
    )
    assert capped.total_fee == Decimal("1.50")


@pytest.mark.parametrize(
    ("raw_fee", "expected"),
    [
        (Decimal("0.005"), Decimal("0.00")),
        (Decimal("0.015"), Decimal("0.02")),
    ],
)
def test_fee_rounding_is_half_even_only_at_report_boundary(
    raw_fee: Decimal, expected: Decimal
) -> None:
    rows = [
        {
            "kind": "quote",
            "event_ns": 10,
            "bid_price": "99",
            "bid_size": "1",
            "ask_price": "100",
            "ask_size": "1",
        }
    ]
    trace = match(
        _request(request_id=f"fee-rounding-{raw_fee}"),
        _policy(fees=_fees(fee_per_share=raw_fee)),
        _prepared(rows),
    )
    assert trace.fills[0].fee_exact == Ratio(
        Fraction(raw_fee).numerator, Fraction(raw_fee).denominator
    )
    assert trace.total_fee == expected

    with localcontext() as context:
        context.prec = 2
        constrained = match(
            _request(request_id=f"fee-rounding-{raw_fee}"),
            _policy(fees=_fees(fee_per_share=raw_fee)),
            _prepared(rows),
        )
    assert constrained.canonical_bytes() == trace.canonical_bytes()


def test_financing_requires_explicit_horizon_and_retains_exact_ratio() -> None:
    rates = FinancingRatesV1(
        version="financing-v1",
        currency="USD",
        minor_units=2,
        reference_price=Decimal("100"),
        period_ns=100,
        borrow_apr=Decimal("0.10"),
        long_financing_apr=Decimal("0.10"),
    )
    accrual = accrue_financing("SHORT", Decimal("2"), 0, 50, rates)
    assert accrual.elapsed_ns == 50
    assert accrual.amount_exact == Ratio(10, 1)
    assert accrual.amount == Decimal("10.00")
    assert accrual.status == "ACCRUED"
    accrual.require_integrity()

    no_long_rate = FinancingRatesV1(
        version="financing-v1",
        currency="USD",
        minor_units=2,
        reference_price=Decimal("100"),
        period_ns=100,
        borrow_apr=None,
        long_financing_apr=None,
    )
    long = accrue_financing("LONG", Decimal("2"), 0, 50, no_long_rate)
    assert long.amount == Decimal("0.00")
    assert long.status == "NOT_DECLARED"
    with pytest.raises(FillKernelError):
        copy.deepcopy(long)
    with pytest.raises(FillKernelError):
        pickle.dumps(long)
    with pytest.raises(FillPolicyError) as no_borrow:
        accrue_financing("SHORT", Decimal("1"), 0, 50, no_long_rate)
    assert no_borrow.value.code == "BORROW_RATE_REQUIRED"
    with pytest.raises(FillValidationError) as reversed_horizon:
        accrue_financing("LONG", Decimal("1"), 51, 50, rates)
    assert reversed_horizon.value.code == "INVALID_FINANCING_HORIZON"


def test_currency_mismatch_fails_closed_without_implicit_fx() -> None:
    rows = [
        {
            "kind": "quote",
            "event_ns": 10,
            "bid_price": "99",
            "bid_size": "2",
            "ask_price": "100",
            "ask_size": "2",
        }
    ]
    with pytest.raises(FillPolicyError) as mismatch:
        match(
            _request(currency="EUR"),
            _policy(fees=_fees(currency="USD")),
            _prepared(rows),
        )
    assert mismatch.value.code == "CURRENCY_MISMATCH"


def test_result_is_sealed_and_canonical_bytes_are_deterministic() -> None:
    rows = [
        {
            "kind": "quote",
            "event_ns": 10,
            "sequence": 1,
            "bid_price": "99",
            "bid_size": "2",
            "ask_price": "100",
            "ask_size": "2",
        },
        {
            "kind": "quote",
            "event_ns": 10,
            "sequence": 2,
            "bid_price": "99.5",
            "bid_size": "2",
            "ask_price": "101",
            "ask_size": "2",
        },
    ]
    request = _request()
    policy = _policy()
    first = match(request, policy, _prepared(rows))
    shuffled = match(request, policy, _prepared(list(reversed(rows))))
    assert isinstance(first, FillTraceV1)
    assert first.order_id == shuffled.order_id
    assert first.canonical_bytes() == shuffled.canonical_bytes()
    assert first.fills[0].event_id == first.transitions[0].event_id
    assert first.policy_digest
    assert first.fills[0].visible_ns == 10
    assert first.transitions[0].reason == "FILLED"
    assert first.transitions[0].state_before == "TRIGGERED"
    assert first.transitions[0].state_after == "FILLED"
    assert first.transitions[0].fills == first.fills
    changed_request = _request(quantity=Decimal("2"))
    changed = match(changed_request, policy, _prepared(rows))
    assert changed.order_id != first.order_id
    with pytest.raises(FillKernelError) as direct:
        FillTraceV1(
            order_id="not-issued",
            request_id="x",
            policy_version="v1",
            policy_digest="a" * 64,
            execution_mode="L1_TOP_OF_BOOK",
            benchmark_midpoint=None,
            latency_strategy_ns=0,
            latency_network_ns=0,
            latency_venue_ns=0,
            eligible_from_ns=0,
            fills=(),
            transitions=(),
            status="UNFILLED",
            filled_quantity=ZERO,
            remaining_quantity=Decimal("1"),
            total_fee=ZERO,
            total_rebate=ZERO,
            implementation_shortfall=ZERO,
            currency="USD",
            minor_units=2,
        )
    assert direct.value.code == "FILL_TRACE_UNISSUED"


def test_inputs_and_outputs_reject_copy_pickle_and_post_issue_tampering() -> None:
    request = _request()
    policy = _policy()
    for value in (request, policy):
        with pytest.raises(FillKernelError):
            copy.copy(value)
        with pytest.raises(FillKernelError):
            pickle.dumps(value)

    rows = [
        {
            "kind": "quote",
            "event_ns": 10,
            "bid_price": "99",
            "bid_size": "1",
            "ask_price": "100",
            "ask_size": "1",
        }
    ]
    trace = match(request, policy, _prepared(rows))
    with pytest.raises(FillKernelError):
        copy.deepcopy(trace)
    with pytest.raises(FillKernelError):
        pickle.dumps(trace)
    object.__setattr__(trace, "total_fee", Decimal("99"))
    with pytest.raises(FillKernelError) as trace_tampered:
        trace.canonical_bytes()
    assert trace_tampered.value.code == "FILL_TRACE_TAMPERED"

    compromised = _request(request_id="tamper-input")
    object.__setattr__(compromised, "quantity", Decimal("100"))
    with pytest.raises(FillKernelError) as input_tampered:
        match(compromised, policy, _prepared(rows))
    assert input_tampered.value.code == "MATCH_INPUT_TAMPERED"


def test_property_bounds_never_overfill_or_report_negative_remaining() -> None:
    rows = [
        {
            "kind": "book_snapshot",
            "event_ns": 10,
            "levels": [
                {"side": "bid", "price": "99", "size": "0.7"},
                {"side": "ask", "price": "100", "size": "0.7"},
            ],
        }
    ]
    for quantity in (Decimal("0.1"), Decimal("0.7"), Decimal("1"), Decimal("3.25")):
        trace = match(
            _request(request_id=f"property-{quantity}", quantity=quantity),
            _policy(mode="RECORDED_L2"),
            _prepared(rows),
        )
        assert ZERO <= trace.filled_quantity <= quantity
        assert ZERO <= trace.remaining_quantity <= quantity
        assert trace.filled_quantity + trace.remaining_quantity == quantity


def test_back_adjusted_research_events_are_not_simulator_authority() -> None:
    row = {
        "kind": "quote",
        "event_ns": 10,
        "bid_price": "99",
        "bid_size": "1",
        "ask_price": "100",
        "ask_size": "1",
    }
    with pytest.raises(OrderRejectedError) as untrusted:
        match(
            _request(),
            _policy(),
            _prepared([row], view="BACK_ADJUSTED"),
        )
    assert untrusted.value.code == "UNTRUSTED_EVENT"


def test_generator_chunk_sizes_preserve_canonical_fill_trace() -> None:
    rows = [
        {
            "kind": "quote",
            "event_ns": 10,
            "sequence": 1,
            "bid_price": "99",
            "bid_size": "2",
            "ask_price": "100",
            "ask_size": "2",
        },
        {
            "kind": "quote",
            "event_ns": 11,
            "sequence": 2,
            "bid_price": "99.5",
            "bid_size": "2",
            "ask_price": "100.5",
            "ask_size": "2",
        },
        {
            "kind": "quote",
            "event_ns": 12,
            "sequence": 3,
            "bid_price": "100",
            "bid_size": "2",
            "ask_price": "101",
            "ask_size": "2",
        },
    ]
    request = _request(order_type="LIMIT", quantity=Decimal("2"), limit_price=Decimal("101"))
    policy = _policy()
    whole = match(request, policy, _prepared(rows))
    chunked = match(request, policy, _prepared(rows, chunk_size=1))
    assert whole.canonical_bytes() == chunked.canonical_bytes()


def test_offline_match_performs_no_network_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise AssertionError("offline fill kernel attempted network access")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(http.client.HTTPConnection, "connect", forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    rows = [
        {
            "kind": "quote",
            "event_ns": 10,
            "bid_price": "99",
            "bid_size": "1",
            "ask_price": "100",
            "ask_size": "1",
        }
    ]
    trace = match(_request(), _policy(), _prepared(rows))
    assert trace.status == "FILLED"


def test_synthetic_latency_proxy_reverses_zero_delay_gross_result() -> None:
    scenario = _fixture("latency_proxy_gross_reversal.json")
    rows = _scenario_rows(scenario)
    session = SessionWindowV1(**scenario["session"])
    quantity = Decimal(scenario["quantity"])

    def round_trip(delay_ns: int, suffix: str) -> Decimal:
        latency = _latency(strategy=FixedLatencyV1(delay_ns, f"latency-{suffix}"))
        buy = match(
            _request(
                request_id=f"latency-buy-{suffix}",
                quantity=quantity,
                submit_ns=int(scenario["entry_submit_ns"]),
                session=session,
            ),
            _policy(latency=latency),
            _prepared(rows, session=session),
        )
        sell = match(
            _request(
                request_id=f"latency-sell-{suffix}",
                side="SELL",
                quantity=quantity,
                submit_ns=int(scenario["exit_submit_ns"]),
                session=session,
            ),
            _policy(),
            _prepared(rows, session=session),
        )
        assert len(buy.fills) == len(sell.fills) == 1
        return (sell.fills[0].price - buy.fills[0].price) * quantity

    zero_delay = round_trip(0, "zero")
    latency_proxy = round_trip(int(scenario["latency_proxy_ns"]), "proxy")
    assert zero_delay == Decimal("0.50")
    assert latency_proxy == Decimal("-0.50")


def test_synthetic_partial_book_market_making_gross_gain_turns_net_loss() -> None:
    scenario = _fixture("stale_partial_book_market_making.json")
    rows = _scenario_rows(scenario)
    session = SessionWindowV1(**scenario["session"])
    maker = match(
        _request(
            request_id="mm-maker",
            order_type="LIMIT",
            limit_price=Decimal("100.00"),
            quantity=Decimal(scenario["maker_quantity"]),
        ),
        _policy(
            mode="SYNTHETIC_L2",
            latency=_latency(strategy=FixedLatencyV1(10, "mm-latency-v1")),
            book_share=Decimal(scenario["queue_share"]),
            fees=_fees(fee_per_share=Decimal(scenario["fee_per_share"])),
            max_book_age_ns=int(scenario["max_book_age_ns"]),
        ),
        _prepared(rows, session=session),
    )
    assert maker.status == "FILLED"
    assert maker.fills[0].visible_ns == 12
    assert maker.fills[0].price == Decimal("100.00")

    exit_order = match(
        _request(
            request_id="mm-taker-exit",
            side="SELL",
            quantity=Decimal(scenario["exit_quantity"]),
            submit_ns=13,
            session=session,
        ),
        _policy(
            mode="SYNTHETIC_L2",
            fees=_fees(fee_per_share=Decimal(scenario["fee_per_share"])),
            max_book_age_ns=int(scenario["max_book_age_ns"]),
        ),
        _prepared(rows, session=session),
    )
    assert exit_order.status == "PARTIALLY_FILLED"
    assert exit_order.filled_quantity == Decimal("1")
    assert exit_order.remaining_quantity == Decimal("1")
    gross = (exit_order.fills[0].price - maker.fills[0].price) * maker.filled_quantity
    total_cost = maker.total_fee + exit_order.total_fee
    assert gross == Decimal("0.10")
    assert total_cost == Decimal("0.12")
    assert gross - total_cost == Decimal("-0.02")

    # Reducing the declared queue share changes when the passive fill occurs.
    half_queue = match(
        _request(request_id="mm-half-queue", order_type="LIMIT", limit_price=Decimal("100.00")),
        _policy(mode="SYNTHETIC_L2", book_share=Decimal(scenario["half_queue_share"])),
        _prepared(rows[:2], session=session),
    )
    assert half_queue.fills[0].visible_ns == 11


def test_stale_partial_book_fixture_fails_closed_before_fill() -> None:
    scenario = _fixture("stale_partial_book_market_making.json")
    rows = _scenario_rows(scenario)
    session = SessionWindowV1(**scenario["session"])
    with pytest.raises(FillKernelError) as stale:
        match(
            _request(
                request_id="mm-stale",
                order_type="LIMIT",
                limit_price=Decimal("99"),
                submit_ns=13,
                session=session,
            ),
            _policy(mode="RECORDED_L2", max_book_age_ns=int(scenario["max_book_age_ns"])),
            _prepared(rows, session=session),
        )
    assert stale.value.code == "BOOK_STALE"
    assert "mm-stale" not in str(stale.value)
