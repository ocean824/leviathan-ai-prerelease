from __future__ import annotations

import json
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest

from leviathan_market_data.ingress import SinkAck
from leviathan_market_data.live.book_cache import BookCache, BookKeyV1
from leviathan_market_data.normalization import Normalizer
from leviathan_market_data.providers.databento import (
    CAPABILITIES,
    CREDENTIAL_NAMES,
    GAP_DETECTABLE_SET,
    GAP_DETECTION,
    GAP_DETECTION_LIMITATIONS,
    PROVIDER_ID,
    DatabentoAdapterError,
    DatabentoHistoricalAdapter,
    DatabentoReadSpec,
    HttpResponse,
    InstrumentBindingV1,
)
from leviathan_market_data.symbology import InstrumentMapping, MappingRegistry

DATASET = "GLBX.MDP3"
MAPPING_VERSION = "synthetic-map-v1"
INSTRUMENT_ID = 7001
EVENT_NS = 1_767_225_600_000_000_000
FIXTURES = Path(__file__).parent / "fixtures" / "databento_depth"
BOOK_KEY = BookKeyV1(
    provider="databento",
    dataset=DATASET,
    venue="XTEST",
    instrument_id="SYN-0001",
)


class FakeTransport:
    def __init__(self, *responses: HttpResponse) -> None:
        self.responses = list(responses)
        self.calls = 0

    def request(self, _request: object) -> HttpResponse:
        self.calls += 1
        if not self.responses:
            raise AssertionError("fake transport exhausted")
        return self.responses.pop(0)


class FakeSink:
    def __init__(self, *acks: SinkAck) -> None:
        self.acks = list(acks)
        self.events = []

    def accept(self, event):
        self.events.append(event)
        return self.acks.pop(0) if self.acks else SinkAck(accepted=True)


def spec(schema: str = "mbo") -> DatabentoReadSpec:
    return DatabentoReadSpec(
        dataset=DATASET,
        schema=schema,
        mapping_version=MAPPING_VERSION,
        listing_venue="XTEST",
        instrument_binding=InstrumentBindingV1(
            provider_instrument_id=INSTRUMENT_ID,
            valid_from_ns=1,
            valid_to_ns=(1 << 63) - 1,
        ),
        symbols=("SYN",),
        start=datetime(2025, 1, 1, tzinfo=UTC),
        end=datetime(2027, 1, 1, tzinfo=UTC),
        stype_in="raw_symbol",
        limit=100,
        max_estimated_usd=Decimal("0.05"),
        max_requests=2,
    )


def adapter(
    body: bytes,
    *,
    cache: BookCache | None = None,
    sink: FakeSink | None = None,
    data_response: HttpResponse | None = None,
) -> tuple[DatabentoHistoricalAdapter, FakeSink, FakeTransport, BookCache]:
    active_cache = cache or BookCache(depth=20)
    active_sink = sink or FakeSink()
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
    transport = FakeTransport(
        HttpResponse(200, {}, b'{"cost":0.01}'),
        data_response or HttpResponse(200, {}, body),
    )
    instance = DatabentoHistoricalAdapter(
        transport=transport,
        credential_resolver=lambda _ref: "synthetic-key",
        mapping_registry=registry,
        instrument_locator=lambda _ds, _pub, native, _day: (native, "SYN"),
        session_resolver=lambda _ds, _pub, _native, _event: "synthetic-session",
        normalizer=Normalizer(registry),
        ingress=active_sink,
        book_cache=active_cache,
    )
    return instance, active_sink, transport, active_cache


def _event(cache: BookCache):
    return cache.snapshot(BOOK_KEY, now_ns=EVENT_NS + 1_000_000_000)


def test_provider_registration_and_partial_gap_metadata_are_explicit() -> None:
    assert PROVIDER_ID == "databento"
    assert frozenset({"L3_MBO", "L2_MBP10", "TRADES", "L1_MBP1", "OHLCV_1M"}) == CAPABILITIES
    assert CREDENTIAL_NAMES == ("databento_api_key",)
    instance, _sink, _transport, _cache = adapter(b"\n")
    assert GAP_DETECTION == "PARTIAL"
    assert instance.metadata.gap_detection == "PARTIAL"
    assert instance.metadata.detectable == GAP_DETECTABLE_SET
    assert instance.metadata.limitations == GAP_DETECTION_LIMITATIONS
    assert GAP_DETECTION_LIMITATIONS == ("filtered_channel_record_omission_is_not_observable",)


def test_snapshot_and_native_sequence_jumps_rebuild_full_book_without_fake_contiguity() -> None:
    rows = (FIXTURES / "snapshot_then_sequence_jump.jsonl").read_bytes()
    instance, sink, _transport, cache = adapter(rows)

    result = instance.read(spec())

    assert [event.event_type for event in sink.events] == ["book_snapshot", "book_snapshot"]
    assert [event.native_sequence for event in sink.events] == [100, 119]
    assert result.book_watermark_sequence == 119
    assert all(event.event_time_ns != event.ingest_time_ns for event in sink.events)
    receipt = _event(cache)
    assert receipt.coherent
    assert receipt.snapshot is not None
    assert len(receipt.snapshot.levels) == 1
    assert receipt.snapshot.levels[0].price.value == "100"


@pytest.mark.parametrize(
    ("body", "reason"),
    [
        ((FIXTURES / "maybe_bad_book.jsonl").read_bytes(), "MAYBE_BAD_BOOK"),
        ((FIXTURES / "gateway_error.jsonl").read_bytes(), "GATEWAY_DATA_LOSS"),
        ((FIXTURES / "slow_reader_warning.jsonl").read_bytes(), "GATEWAY_DATA_LOSS"),
        ((FIXTURES / "event_time_regression.jsonl").read_bytes(), "EVENT_TIME_REGRESSION"),
        ((FIXTURES / "sequence_reversal.jsonl").read_bytes(), "NON_INCREASING_SEQUENCE"),
    ],
)
def test_detected_gap_is_typed_and_invalidates_the_cached_book(
    body: bytes,
    reason: str,
) -> None:
    initial = (FIXTURES / "snapshot_then_sequence_jump.jsonl").read_bytes()
    instance, _sink, _transport, cache = adapter(initial)
    instance.read(spec())
    instance.transport = FakeTransport(
        HttpResponse(200, {}, b'{"cost":0.01}'),
        HttpResponse(200, {}, body),
    )

    with pytest.raises(DatabentoAdapterError) as caught:
        instance.read(spec())

    assert caught.value.code == "GAP_DETECTED"
    assert caught.value.gap_event is not None
    assert caught.value.gap_event.code == "GAP_DETECTED"
    assert caught.value.gap_event.reason.value == reason
    assert not _event(cache).coherent


def test_snapshot_replay_after_reconnect_rebuilds_with_a_new_native_epoch() -> None:
    initial = (FIXTURES / "snapshot_then_sequence_jump.jsonl").read_bytes().splitlines()[0]
    replay = json.loads(initial)
    replay["sequence"] = 2
    replay["ts_event"] = EVENT_NS + 1_000
    replay["ts_recv"] = EVENT_NS + 20_000
    replay["flags"] = 160
    replay["action"] = "R"
    replay["order_id"] = 0
    replay["size"] = 0
    replay["side"] = "N"
    replay["price"] = 9_223_372_036_854_775_807
    original = json.loads(initial)
    original["sequence"] = 7
    original["ts_event"] = EVENT_NS + 2_000
    original["ts_recv"] = EVENT_NS + 20_000
    original["flags"] = 160
    body = (json.dumps(replay) + "\n" + json.dumps(original) + "\n").encode()
    instance, sink, _transport, cache = adapter(
        (FIXTURES / "snapshot_then_sequence_jump.jsonl").read_bytes(),
    )
    first = instance.read(spec())
    assert first.book_watermark_sequence == 119
    instance.transport = FakeTransport(
        HttpResponse(200, {}, b'{"cost":0.01}'),
        HttpResponse(200, {}, body),
    )

    result = instance.read(spec())

    assert result.book_watermark_sequence == 7
    assert sink.events[-1].session_transition_confirmed
    assert sink.events[-1].native_sequence == 7
    assert _event(cache).coherent


def test_sink_ack_precedes_cache_watermark_and_retry_applies_snapshot() -> None:
    body = (FIXTURES / "snapshot_then_sequence_jump.jsonl").read_bytes().splitlines()[0]
    sink = FakeSink(SinkAck(backpressure=True), SinkAck(accepted=True))
    instance, _sink, _transport, cache = adapter(body + b"\n", sink=sink)

    result = instance.read(spec())

    assert result.book_watermark_sequence is None
    assert result.pending_record_keys
    assert not _event(cache).coherent
    assert instance.resubmit(result.pending_record_keys[0]).accepted
    assert _event(cache).coherent


def test_gateway_server_failure_invalidates_prior_book_with_content_free_gap() -> None:
    body = (FIXTURES / "snapshot_then_sequence_jump.jsonl").read_bytes()
    instance, _sink, _transport, cache = adapter(body)
    instance.read(spec())
    instance.transport = FakeTransport(
        HttpResponse(200, {}, b'{"cost":0.01}'),
        HttpResponse(503, {}, b"private gateway detail"),
    )

    with pytest.raises(DatabentoAdapterError) as caught:
        instance.read(spec())

    assert caught.value.code == "GAP_DETECTED"
    assert "private gateway detail" not in str(caught.value)
    assert not _event(cache).coherent


def test_mbo_modify_cancel_and_clear_emit_full_native_snapshots() -> None:
    snapshot = json.loads(
        (FIXTURES / "snapshot_then_sequence_jump.jsonl").read_text().splitlines()[0]
    )
    add = json.loads((FIXTURES / "snapshot_then_sequence_jump.jsonl").read_text().splitlines()[1])
    modify = dict(
        add,
        action="M",
        sequence=128,
        price=102_000_000_000,
        size=7,
        ts_event=EVENT_NS + 300,
        ts_recv=EVENT_NS + 310,
    )
    fill = dict(
        add, action="F", sequence=150, size=3, ts_event=EVENT_NS + 400, ts_recv=EVENT_NS + 410
    )
    cancel = dict(
        add, action="C", sequence=160, size=2, ts_event=EVENT_NS + 500, ts_recv=EVENT_NS + 510
    )
    clear = dict(snapshot, sequence=170, ts_event=EVENT_NS + 600, ts_recv=EVENT_NS + 610)
    body = (
        "\n".join(json.dumps(item) for item in (snapshot, add, modify, fill, cancel, clear)) + "\n"
    ).encode()
    instance, sink, _transport, cache = adapter(body)

    result = instance.read(spec())

    assert result.book_watermark_sequence == 170
    assert [event.native_sequence for event in sink.events] == [100, 119, 128, 150, 160, 170]
    fill_snapshot = next(event for event in sink.events if event.native_sequence == 150)
    assert fill_snapshot.payload.levels[0].size == "4"
    assert all(event.event_type == "book_snapshot" for event in sink.events)
    assert _event(cache).coherent
    assert _event(cache).snapshot is not None
    assert _event(cache).snapshot.levels == ()


def test_mbp10_is_a_full_l2_snapshot_with_native_sequence() -> None:
    row = {
        "publisher_id": 42,
        "instrument_id": INSTRUMENT_ID,
        "rtype": 10,
        "ts_event": EVENT_NS + 100,
        "sequence": 4000,
        "flags": 0,
        "bid_px_00": 100_000_000_000,
        "bid_sz_00": 4,
        "ask_px_00": 101_000_000_000,
        "ask_sz_00": 6,
    }
    body = (json.dumps(row) + "\n").encode()
    instance, sink, _transport, cache = adapter(body)

    result = instance.read(spec("mbp-10"))

    assert result.book_watermark_sequence == 4000
    assert len(sink.events) == 1
    assert sink.events[0].native_sequence == 4000
    assert sink.events[0].channel == "mbp-10"
    receipt = _event(cache)
    assert receipt.coherent and receipt.snapshot is not None
    assert [(level.side, level.price.value) for level in receipt.snapshot.levels] == [
        ("bid", "100"),
        ("ask", "101"),
    ]


def test_mbo_without_base_fails_closed() -> None:
    row = {
        "publisher_id": 42,
        "instrument_id": INSTRUMENT_ID,
        "rtype": 160,
        "ts_event": EVENT_NS + 100,
        "ts_recv": EVENT_NS + 110,
        "sequence": 20,
        "flags": 128,
        "action": "A",
        "side": "B",
        "price": 100_000_000_000,
        "size": 1,
        "order_id": 1,
    }
    instance, sink, _transport, cache = adapter((json.dumps(row) + "\n").encode())

    with pytest.raises(DatabentoAdapterError) as caught:
        instance.read(spec())

    assert caught.value.code == "MISSING_BASE"
    assert sink.events == []
    assert not _event(cache).coherent
