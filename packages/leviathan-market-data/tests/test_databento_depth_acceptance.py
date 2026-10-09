from __future__ import annotations

import json
from datetime import UTC, datetime
from decimal import Decimal

import pytest

from leviathan_market_data.ingress import SinkAck
from leviathan_market_data.live.book_cache import BookCache, BookKeyV1
from leviathan_market_data.normalization import Normalizer
from leviathan_market_data.providers.databento import (
    CAPABILITIES,
    CREDENTIAL_NAMES,
    PROVIDER_ID,
    DatabentoAdapterError,
    DatabentoReadSpec,
    DatabentoRuntimePortsV1,
    HttpRequest,
    HttpResponse,
    InstrumentBindingV1,
    build_adapter,
)
from leviathan_market_data.schema import NormalizedMarketEventV1
from leviathan_market_data.symbology import InstrumentMapping, MappingRegistry

DATASET = "GLBX.MDP3"
MAPPING_VERSION = "acceptance-map-v1"
NATIVE_ID = 7001
BASE_NS = 1_767_225_600_000_000_000
UNDEF_PRICE = 9_223_372_036_854_775_807
SYNTHETIC_KEY = "synthetic-databento-key-must-not-leak"
BOOK_KEY = BookKeyV1(
    provider="databento",
    dataset=DATASET,
    venue="XTEST",
    instrument_id="SYN-0001",
)


class FakeTransport:
    def __init__(self, *responses: HttpResponse) -> None:
        self.responses = list(responses)
        self.requests: list[HttpRequest] = []

    def request(self, request: HttpRequest) -> HttpResponse:
        self.requests.append(request)
        if not self.responses:
            raise AssertionError("unexpected provider request")
        return self.responses.pop(0)


class FakeSink:
    def __init__(self, *acks: SinkAck) -> None:
        self.acks = list(acks)
        self.events: list[NormalizedMarketEventV1] = []

    def accept(self, event: NormalizedMarketEventV1) -> SinkAck:
        self.events.append(event)
        return self.acks.pop(0) if self.acks else SinkAck(accepted=True)


def _spec(
    schema: str = "mbo",
    *,
    cap: Decimal = Decimal("0.05"),
) -> DatabentoReadSpec:
    return DatabentoReadSpec(
        dataset=DATASET,
        schema=schema,
        mapping_version=MAPPING_VERSION,
        listing_venue="XTEST",
        instrument_binding=InstrumentBindingV1(
            provider_instrument_id=NATIVE_ID,
            valid_from_ns=1,
            valid_to_ns=(1 << 63) - 1,
        ),
        symbols=("SYN",),
        start=datetime(2025, 1, 1, tzinfo=UTC),
        end=datetime(2027, 1, 1, tzinfo=UTC),
        stype_in="raw_symbol",
        limit=100,
        max_estimated_usd=cap,
        max_requests=2,
    )


def _harness(
    *responses: HttpResponse,
    sink: FakeSink | None = None,
) -> tuple[object, FakeTransport, FakeSink, BookCache, list[str]]:
    mapping = InstrumentMapping(
        provider="databento",
        dataset=DATASET,
        venue="XTEST",
        native_symbol="SYN",
        instrument_id="SYN-0001",
        leviathan_symbol="SYN",
        instrument_type="equity",
        mapping_version=MAPPING_VERSION,
        tick_size="0.01",
    )
    registry = MappingRegistry((mapping,))
    cache = BookCache(depth=10)
    active_sink = sink or FakeSink()
    transport = FakeTransport(*responses)
    resolved: list[str] = []

    def resolve_secret(name: str) -> str:
        resolved.append(name)
        return SYNTHETIC_KEY

    runtime = DatabentoRuntimePortsV1(
        http_transport=transport,
        mapping_registry=registry,
        instrument_locator=lambda _dataset, _publisher, native_id, _day: (
            native_id,
            "SYN",
        ),
        session_resolver=lambda _dataset, _publisher, _native_id, _event: "synthetic-session",
        normalizer=Normalizer(registry),
        ingress=active_sink,
        book_cache=cache,
    )
    adapter = build_adapter(resolve_secret=resolve_secret, transport=runtime)
    return adapter, transport, active_sink, cache, resolved


def _response(body: bytes, status: int = 200) -> HttpResponse:
    return HttpResponse(status, {}, body)


def _pair(body: bytes, cost: bytes = b'{"cost":0.01}') -> tuple[HttpResponse, HttpResponse]:
    return _response(cost), _response(body)


def _jsonl(*rows: dict[str, object]) -> bytes:
    return b"\n".join(
        json.dumps(row, sort_keys=True, separators=(",", ":")).encode("ascii")
        for row in rows
    ) + b"\n"


def _mbo(
    action: str,
    sequence: int,
    *,
    event_ns: int | None = None,
    flags: int = 128,
    order_id: int = 0,
    side: str = "N",
    price: int = UNDEF_PRICE,
    size: int = 0,
) -> dict[str, object]:
    event_time = BASE_NS + sequence * 1_000 if event_ns is None else event_ns
    return {
        "publisher_id": 42,
        "instrument_id": NATIVE_ID,
        "rtype": 160,
        "ts_event": event_time,
        "ts_recv": event_time + 100,
        "sequence": sequence,
        "flags": flags,
        "action": action,
        "order_id": order_id,
        "side": side,
        "price": price,
        "size": size,
    }


def _base_snapshot() -> dict[str, object]:
    return _mbo("R", 100, flags=160)


def _book_levels(cache: BookCache) -> tuple[tuple[str, str, str, str | None, int | None], ...]:
    receipt = cache.snapshot(BOOK_KEY, now_ns=BASE_NS + 2_000_000_000)
    assert receipt.coherent and receipt.snapshot is not None
    return tuple(
        (level.side, level.price.value, level.size, level.order_id, level.level)
        for level in receipt.snapshot.levels
    )


def _assert_cost_then_data(transport: FakeTransport, *, pairs: int = 1) -> None:
    assert len(transport.requests) == pairs * 2
    for index in range(pairs):
        cost, data = transport.requests[index * 2 : index * 2 + 2]
        assert cost.method == "GET"
        assert cost.url.split("?", 1)[0].endswith("/metadata.get_cost")
        assert data.method == "POST"
        assert data.url.split("?", 1)[0].endswith("/timeseries.get_range")


def test_public_factory_metadata_and_injected_ports_are_offline() -> None:
    adapter, transport, _sink, _cache, resolved = _harness()

    assert PROVIDER_ID == "databento"
    assert CREDENTIAL_NAMES == ("databento_api_key",)
    assert {"L3_MBO", "L2_MBP10", "TRADES", "L1_MBP1", "OHLCV_1M"} <= CAPABILITIES
    assert adapter.metadata.gap_detection == "PARTIAL"
    assert "filtered_channel_record_omission_is_not_observable" in adapter.metadata.limitations
    assert transport.requests == []
    assert resolved == []


def test_mbo_add_modify_fill_cancel_rebuild_full_book_then_reset_clears_it() -> None:
    rows = (
        _base_snapshot(),
        _mbo("A", 119, order_id=11, side="B", price=100_000_000_000, size=5),
        _mbo("A", 128, order_id=21, side="A", price=101_000_000_000, size=7),
        _mbo("M", 140, order_id=11, side="B", price=100_500_000_000, size=4),
        _mbo("F", 150, order_id=11, side="B", price=100_500_000_000, size=1),
        _mbo("C", 160, order_id=21, side="A", price=101_000_000_000, size=7),
        _mbo("A", 170, order_id=22, side="A", price=102_000_000_000, size=3),
    )
    reset = _mbo("R", 180)
    transport_responses = (*_pair(_jsonl(*rows)), *_pair(_jsonl(reset)))
    adapter, transport, sink, cache, resolved = _harness(*transport_responses)

    result = adapter.read(_spec())

    assert result.book_watermark_sequence == 170
    assert [event.native_sequence for event in sink.events] == [100, 119, 128, 140, 150, 160, 170]
    assert all(event.event_type == "book_snapshot" for event in sink.events)
    assert all(event.channel == "mbo" for event in sink.events)
    assert all(event.event_time_ns != event.ingest_time_ns for event in sink.events)
    assert _book_levels(cache) == (
        ("bid", "100.5", "3", "11", None),
        ("ask", "102", "3", "22", None),
    )
    observed = (result, sink.events, cache.snapshot(BOOK_KEY, now_ns=BASE_NS + 2_000_000_000))
    assert SYNTHETIC_KEY not in repr(observed)
    assert resolved == ["databento_api_key"]

    reset_result = adapter.read(_spec())
    assert reset_result.book_watermark_sequence == 180
    assert sink.events[-1].native_sequence == 180
    assert sink.events[-1].event_type == "book_snapshot"
    assert _book_levels(cache) == ()
    _assert_cost_then_data(transport, pairs=2)


def test_mbp10_emits_full_l2_levels_and_preserves_native_sequences() -> None:
    def mbp_row(sequence: int, price_offset: int) -> dict[str, object]:
        row: dict[str, object] = {
            "publisher_id": 42,
            "instrument_id": NATIVE_ID,
            "rtype": 10,
            "ts_event": BASE_NS + sequence * 1_000,
            "ts_recv": BASE_NS + sequence * 1_000 + 100,
            "sequence": sequence,
            "flags": 0,
        }
        for level in range(10):
            row[f"bid_px_{level:02d}"] = (100 - level + price_offset) * 1_000_000_000
            row[f"bid_sz_{level:02d}"] = level + 1
            row[f"ask_px_{level:02d}"] = (101 + level + price_offset) * 1_000_000_000
            row[f"ask_sz_{level:02d}"] = level + 11
        return row

    rows = (mbp_row(4000, 0), mbp_row(9021, 1))
    adapter, transport, sink, cache, _resolved = _harness(*_pair(_jsonl(*rows)))

    result = adapter.read(_spec("mbp-10"))

    assert result.book_watermark_sequence == 9021
    assert [event.native_sequence for event in sink.events] == [4000, 9021]
    assert all(event.event_type == "book_snapshot" for event in sink.events)
    assert all(event.channel == "mbp-10" for event in sink.events)
    expected = tuple(
        [
            ("bid", str(price), str(size), None, level)
            for level, (price, size) in enumerate(
                [(100 - level + 1, level + 1) for level in range(10)]
            )
        ]
        + [
            ("ask", str(price), str(size), None, level)
            for level, (price, size) in enumerate(
                [(101 + level + 1, level + 11) for level in range(10)]
            )
        ]
    )
    assert _book_levels(cache) == expected
    assert all(event.channel != "mbo" for event in sink.events)
    _assert_cost_then_data(transport)


def test_exact_duplicate_mbo_record_is_idempotent() -> None:
    snapshot = _base_snapshot()
    add = _mbo("A", 119, order_id=11, side="B", price=100_000_000_000, size=5)
    adapter, _transport, sink, cache, _resolved = _harness(*_pair(_jsonl(snapshot, add, add)))

    result = adapter.read(_spec())

    assert result.record_count == 3
    assert result.normalized_count == 2
    assert result.book_watermark_sequence == 119
    assert [event.native_sequence for event in sink.events] == [100, 119]
    assert _book_levels(cache) == (("bid", "100", "5", "11", None),)


@pytest.mark.parametrize(
    ("bad_row", "reason"),
    [
        (
            _mbo("A", 130, flags=132, order_id=12, side="B", price=99_000_000_000, size=1),
            "MAYBE_BAD_BOOK",
        ),
        (
            _mbo(
                "A", 118, event_ns=BASE_NS + 130_000, order_id=12,
                side="B", price=99_000_000_000, size=1,
            ),
            "NON_INCREASING_SEQUENCE",
        ),
        (
            _mbo(
                "A", 130, event_ns=BASE_NS + 1_000, order_id=12,
                side="B", price=99_000_000_000, size=1,
            ),
            "EVENT_TIME_REGRESSION",
        ),
    ],
)
def test_detected_depth_gap_fails_closed_and_invalidates_prior_book(
    bad_row: dict[str, object],
    reason: str,
) -> None:
    base = _jsonl(
        _base_snapshot(),
        _mbo("A", 119, order_id=11, side="B", price=100_000_000_000, size=5),
    )
    responses = (*_pair(base), *_pair(_jsonl(bad_row)))
    adapter, _transport, _sink, cache, _resolved = _harness(*responses)
    adapter.read(_spec())

    with pytest.raises(DatabentoAdapterError) as caught:
        adapter.read(_spec())

    assert caught.value.code == "GAP_DETECTED"
    assert caught.value.gap_event is not None
    assert caught.value.gap_event.code == "GAP_DETECTED"
    assert caught.value.gap_event.reason.value == reason
    receipt = cache.snapshot(BOOK_KEY, now_ns=BASE_NS + 2_000_000_000)
    assert not receipt.coherent
    assert receipt.snapshot is None


@pytest.mark.parametrize(
    ("cost_body", "error_code"),
    [(b"{}", "EXTERNAL_GATE"), (b'{"cost":0.06}', "COST_CAP")],
)
def test_unknown_or_over_cap_cost_never_makes_a_data_call(
    cost_body: bytes,
    error_code: str,
) -> None:
    adapter, transport, _sink, _cache, resolved = _harness(_response(cost_body))

    with pytest.raises(DatabentoAdapterError) as caught:
        adapter.read(_spec(cap=Decimal("0.05")))

    assert caught.value.code == error_code
    assert len(transport.requests) == 1
    assert transport.requests[0].method == "GET"
    assert all(request.method != "POST" for request in transport.requests)
    assert resolved == ["databento_api_key"]
    assert SYNTHETIC_KEY not in str(caught.value)


def test_sink_backpressure_does_not_advance_cache_until_ack_retry() -> None:
    snapshot = _base_snapshot()
    rows = _jsonl(snapshot, _mbo("A", 119, order_id=11, side="B", price=100_000_000_000, size=5))
    sink = FakeSink(SinkAck(backpressure=True), SinkAck(accepted=True))
    adapter, _transport, _sink, cache, _resolved = _harness(*_pair(rows), sink=sink)

    result = adapter.read(_spec())

    assert result.book_watermark_sequence is None
    assert len(result.pending_record_keys) == 2
    assert not cache.snapshot(BOOK_KEY, now_ns=BASE_NS + 2_000_000_000).coherent
    snapshot_ack = adapter.resubmit(result.pending_record_keys[0])
    assert snapshot_ack.accepted
    # The SinkAck for the snapshot commits only that watermark; the later
    # update remains retry-owned until its own acknowledgement.
    assert _book_levels(cache) == ()
    update_ack = adapter.resubmit(result.pending_record_keys[1])
    assert update_ack.accepted
    assert _book_levels(cache) == (("bid", "100", "5", "11", None),)


def test_gateway_error_invalidates_book_without_echoing_provider_or_key() -> None:
    base = _jsonl(
        _base_snapshot(),
        _mbo("A", 119, order_id=11, side="B", price=100_000_000_000, size=5),
    )
    adapter, _transport, _sink, cache, _resolved = _harness(
        *_pair(base),
        _response(b'{"cost":0.01}'),
        _response(b"synthetic-provider-error-canary", status=503),
    )
    adapter.read(_spec())

    with pytest.raises(DatabentoAdapterError) as caught:
        adapter.read(_spec())

    assert caught.value.code == "GAP_DETECTED"
    assert "synthetic-provider-error-canary" not in str(caught.value)
    assert SYNTHETIC_KEY not in repr(caught.value)
    assert not cache.snapshot(BOOK_KEY, now_ns=BASE_NS + 2_000_000_000).coherent
