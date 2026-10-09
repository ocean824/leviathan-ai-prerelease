from __future__ import annotations

import copy
import json
import pickle
from dataclasses import replace
from datetime import UTC, date, datetime
from decimal import Decimal
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest
from pydantic import SecretStr

from leviathan_core.seal import verify
from leviathan_market_data.ingress import SinkAck
from leviathan_market_data.live.book_cache import BookCache
from leviathan_market_data.normalization import Normalizer
from leviathan_market_data.providers.databento import (
    CanonicalQuery,
    DatabentoAdapterError,
    DatabentoHistoricalAdapter,
    DatabentoReadSpec,
    HttpRequest,
    HttpResponse,
    InstrumentBindingV1,
)
from leviathan_market_data.schema import NormalizedMarketEventV1
from leviathan_market_data.symbology import InstrumentMapping, MappingRegistry
from leviathan_vault.client import CredentialRef

FIXTURES = Path(__file__).parent / "fixtures" / "databento"
DATASET = "GLBX.MDP3"
MAPPING_VERSION = "synthetic-map-v1"
PUBLISHER_ID = 42
NATIVE_INSTRUMENT_ID = 7001
EVENT_NS = 1_770_000_000_000_000_000
SYNTHETIC_KEY = "synthetic-key-for-tests-only"
SYNTHETIC_SECRET = "synthetic-vendor-body-secret"


def make_spec(
    schema: str = "trades",
    *,
    end: datetime = datetime(2027, 1, 1, tzinfo=UTC),
    limit: int = 10,
    cap: Decimal = Decimal("0.05"),
    max_requests: int = 2,
    mapping_version: str = MAPPING_VERSION,
    listing_venue: str = "XTEST",
    instrument_binding: InstrumentBindingV1 | None = None,
) -> DatabentoReadSpec:
    return DatabentoReadSpec(
        dataset=DATASET,
        schema=schema,
        mapping_version=mapping_version,
        listing_venue=listing_venue,
        instrument_binding=instrument_binding
        or InstrumentBindingV1(
            provider_instrument_id=NATIVE_INSTRUMENT_ID,
            valid_from_ns=1,
            valid_to_ns=2**63 - 1,
        ),
        symbols=("SYN",),
        start=datetime(2025, 1, 1, tzinfo=UTC),
        end=end,
        stype_in="raw_symbol",
        limit=limit,
        max_estimated_usd=cap,
        max_requests=max_requests,
    )


def read_fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def first_json_line(body: bytes | None = None) -> dict[str, object]:
    raw = body if body is not None else read_fixture("trades.jsonl")
    return json.loads(raw.splitlines()[0])


def jsonl(*records: dict[str, object]) -> bytes:
    return (
        b"\n".join(
            json.dumps(record, sort_keys=True, separators=(",", ":")).encode("ascii")
            for record in records
        )
        + b"\n"
    )


class FakeTransport:
    def __init__(self, *responses: HttpResponse | Exception | object) -> None:
        self.responses = list(responses)
        self.calls: list[HttpRequest] = []

    def request(self, request: HttpRequest) -> HttpResponse:
        self.calls.append(request)
        if not self.responses:
            raise AssertionError("fake response queue exhausted")
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response  # type: ignore[return-value]


class RecordingSink:
    def __init__(self, *acks: SinkAck) -> None:
        self.acks = list(acks)
        self.attempts: list[NormalizedMarketEventV1] = []
        self.accepted: dict[str, NormalizedMarketEventV1] = {}

    def accept(self, event: NormalizedMarketEventV1) -> SinkAck:
        self.attempts.append(event)
        ack = self.acks.pop(0) if self.acks else SinkAck(accepted=True)
        if ack.accepted:
            self.accepted.setdefault(event.idempotency_key, event)
        return ack


class IdempotentSink(RecordingSink):
    def accept(self, event: NormalizedMarketEventV1) -> SinkAck:
        self.attempts.append(event)
        if event.idempotency_key in self.accepted:
            return SinkAck(accepted=True)
        self.accepted[event.idempotency_key] = event
        return SinkAck(accepted=True)


def mapping(version: str = MAPPING_VERSION) -> InstrumentMapping:
    return InstrumentMapping(
        provider="databento",
        dataset=DATASET,
        venue="XTEST",
        native_symbol="SYN",
        instrument_id="SYN-0001",
        leviathan_symbol="SYN",
        instrument_type="equity",
        mapping_version=version,
        tick_size="0.01",
    )


def cost_response(body: bytes = b'{"cost":0.01}') -> HttpResponse:
    return HttpResponse(200, {}, body)


def data_response(body: bytes | None = None) -> HttpResponse:
    return HttpResponse(200, {}, body if body is not None else read_fixture("trades.jsonl"))


def build_adapter(
    transport: FakeTransport,
    *,
    sink: RecordingSink | None = None,
    credential_resolver=None,
    locator_result: tuple[int, str] | None = (NATIVE_INSTRUMENT_ID, "SYN"),
    registry: MappingRegistry | None = None,
    mapping_version: str = MAPPING_VERSION,
    session_resolver=None,
    book_cache: BookCache | None = None,
    seen_locator: list[tuple[str, int, int, date]] | None = None,
) -> tuple[DatabentoHistoricalAdapter, RecordingSink, list[CredentialRef]]:
    active_sink = sink or RecordingSink()
    refs: list[CredentialRef] = []
    active_registry = registry or MappingRegistry((mapping(mapping_version),))

    def resolve_credential(ref: CredentialRef) -> SecretStr:
        refs.append(ref)
        return SecretStr(SYNTHETIC_KEY)

    def locate(
        dataset: str, publisher_id: int, instrument_id: int, event_date: date
    ) -> tuple[int, str] | None:
        if seen_locator is not None:
            seen_locator.append((dataset, publisher_id, instrument_id, event_date))
        return locator_result

    def resolve_session(
        dataset: str, publisher_id: int, instrument_id: int, event_time_ns: int
    ) -> str | None:
        if session_resolver is not None:
            return session_resolver(dataset, publisher_id, instrument_id, event_time_ns)
        event_day = datetime.fromtimestamp(event_time_ns // 1_000_000_000, UTC).date()
        return f"synthetic-session:{event_day.isoformat()}"

    adapter = DatabentoHistoricalAdapter(
        transport=transport,
        credential_resolver=credential_resolver or resolve_credential,
        mapping_registry=active_registry,
        instrument_locator=locate,
        session_resolver=resolve_session,
        normalizer=Normalizer(active_registry),
        ingress=active_sink,
        book_cache=book_cache,
    )
    return adapter, active_sink, refs


def data_call_count(transport: FakeTransport) -> int:
    return sum("timeseries.get_range" in request.url for request in transport.calls)


def test_trade_query_is_shared_exactly_and_normalizes_native_integer_provenance() -> None:
    transport = FakeTransport(cost_response(), data_response())
    seen_locator: list[tuple[str, int, int, date]] = []
    adapter, sink, refs = build_adapter(transport, seen_locator=seen_locator)
    query = CanonicalQuery.from_spec(make_spec())

    result = adapter.read(make_spec())

    assert result.request_count == 2
    assert result.record_count == 2
    assert result.normalized_count == 2
    assert result.mapping_version == MAPPING_VERSION
    assert result.receipts == (SinkAck(accepted=True), SinkAck(accepted=True))
    assert verify(result, "md002.read_result.v1")
    assert [item.event_type for item in sink.accepted.values()] == ["trade", "trade"]
    assert [event.native_sequence for event in sink.accepted.values()] == [17, 24]
    first = next(iter(sink.accepted.values()))
    assert first.source_mode == "historical"
    assert first.native_trade_id is None
    assert first.native_provenance.publisher_id == PUBLISHER_ID
    assert first.native_provenance.native_instrument_id == NATIVE_INSTRUMENT_ID
    assert first.event_time_ns == EVENT_NS
    assert first.exchange_time_ns == EVENT_NS
    assert first.source_time_ns == EVENT_NS + 100
    assert first.provenance_timestamps.exchange == EVENT_NS
    assert first.provenance_timestamps.provider == EVENT_NS + 100
    assert first.provider_session_id.startswith("synthetic-session:")
    assert first.payload.price.value == "101.25"
    assert first.payload.size == "2"
    assert first.payload.side == "buy"
    assert first.native_provenance.flags == 0
    assert first.native_provenance.action == "trade"
    assert first.source_attributes["databento:raw_rtype_code"] == "0"

    assert len(transport.calls) == 2
    cost_request, data_request = transport.calls
    canonical = query.values()
    assert {key: cost_request.query_params[key] for key in canonical} == canonical
    assert {key: data_request.form_data[key] for key in canonical} == canonical
    for key, value in canonical.items():
        assert cost_request.query_params[key] == value
        assert data_request.form_data[key] == value
    assert data_request.form_data["encoding"] == "json"
    assert data_request.form_data["pretty_px"] == "false"
    assert data_request.form_data["pretty_ts"] == "false"
    assert data_request.form_data["map_symbols"] == "false"
    assert [request.method for request in transport.calls] == ["GET", "POST"]
    assert cost_request.url.startswith("https://hist.databento.com/v0/metadata.get_cost?")
    assert data_request.url == "https://hist.databento.com/v0/timeseries.get_range"
    assert all(request.allow_redirects is False for request in transport.calls)
    assert all(request.connect_timeout_s == 3 for request in transport.calls)
    assert all(request.read_timeout_s == 5 for request in transport.calls)
    assert all(request.total_timeout_s == 10 for request in transport.calls)
    assert parse_qs(urlsplit(cost_request.url).query)["limit"] == ["10"]
    assert data_request.form_data["limit"] == "10"
    assert refs == [
        CredentialRef(
            provider="databento",
            name="DATABENTO_API_KEY",
            scope="leviathan-ai",
            environment="development",
        )
    ]
    expected_day = datetime.fromtimestamp(EVENT_NS // 1_000_000_000, UTC).date()
    assert seen_locator == [
        (DATASET, PUBLISHER_ID, NATIVE_INSTRUMENT_ID, expected_day),
        (DATASET, PUBLISHER_ID, NATIVE_INSTRUMENT_ID, expected_day),
    ]


@pytest.mark.parametrize(
    ("schema", "fixture_name", "event_type", "channel"),
    [
        ("trades", "trades.jsonl", "trade", "trades"),
        ("mbp-1", "mbp-1.jsonl", "quote", "mbp-1"),
        ("ohlcv-1m", "ohlcv-1m.jsonl", "bar", "ohlcv-1m"),
    ],
)
def test_supported_schemas_use_exact_payload_and_preserve_absent_quote_side(
    schema: str, fixture_name: str, event_type: str, channel: str
) -> None:
    transport = FakeTransport(cost_response(), data_response(read_fixture(fixture_name)))
    adapter, sink, _refs = build_adapter(transport)

    result = adapter.read(make_spec(schema))

    assert result.normalized_count == (2 if schema == "trades" else 1)
    event = sink.attempts[0]
    assert event.event_type == event_type
    assert event.channel == channel
    if schema == "mbp-1":
        assert event.payload.bid_present is True
        assert event.payload.bid_price.value == "101.24"
        assert event.payload.bid_size == "8"
        assert event.payload.ask_present is False
        assert event.payload.ask_price is None
        assert event.payload.ask_size is None
        assert event.payload.ask_time_ns is None
    elif schema == "ohlcv-1m":
        assert event.payload.open.value == "101"
        assert event.payload.high.value == "102"
        assert event.payload.low.value == "100.5"
        assert event.payload.close.value == "101.5"
        assert event.payload.volume == "1250"
        assert event.native_trade_id is None
    else:
        assert event.payload.price.value == "101.25"
        assert event.native_trade_id is None
        assert event.native_sequence == 17
    assert event.source_mode == "historical"
    if hasattr(event, "execution_eligible"):
        assert event.execution_eligible is False


def test_unknown_and_over_cap_estimates_never_issue_a_data_request() -> None:
    for body, cap, expected_code in (
        (b'{"cost":0.06}', Decimal("0.05"), "COST_CAP"),
        (b'{"cost":"not-a-number"}', Decimal("0.05"), "EXTERNAL_GATE"),
    ):
        transport = FakeTransport(cost_response(body), data_response())
        adapter, sink, _refs = build_adapter(transport)
        with pytest.raises(DatabentoAdapterError) as caught:
            adapter.read(make_spec(cap=cap))
        assert caught.value.code == expected_code
        assert len(transport.calls) == 1
        assert data_call_count(transport) == 0
        assert sink.attempts == []

    transport = FakeTransport(cost_response())
    adapter, _sink, _refs = build_adapter(transport)
    with pytest.raises(DatabentoAdapterError) as caught:
        adapter.read(make_spec(max_requests=1))
    assert caught.value.code == "EXTERNAL_GATE"
    assert len(transport.calls) == 1
    assert data_call_count(transport) == 0


@pytest.mark.parametrize(
    ("schema", "expected"),
    [
        ("definition", "UNSUPPORTED_SCHEMA"),
        ("status", "UNSUPPORTED_SCHEMA"),
    ],
)
def test_known_unimplemented_schemas_fail_closed_before_transport(
    schema: str, expected: str
) -> None:
    with pytest.raises(DatabentoAdapterError) as caught:
        make_spec(schema)
    assert caught.value.code == expected
    assert str(caught.value) == expected


@pytest.mark.parametrize(
    "invalid",
    [
        {"dataset": "BAD/host"},
        {"mapping_version": "bad version"},
        {"symbols": ("SYN", "SYN")},
        {"symbols": ("SYN?x",)},
        {"limit": True},
        {"start": datetime(2025, 1, 1)},
        {"end": datetime(2024, 1, 1, tzinfo=UTC)},
    ],
)
def test_invalid_query_never_reaches_transport(invalid: dict[str, object]) -> None:
    args: dict[str, object] = {
        "dataset": DATASET,
        "schema": "trades",
        "mapping_version": MAPPING_VERSION,
        "listing_venue": "XTEST",
        "instrument_binding": InstrumentBindingV1(
            provider_instrument_id=NATIVE_INSTRUMENT_ID,
            valid_from_ns=1,
            valid_to_ns=2**63 - 1,
        ),
        "symbols": ("SYN",),
        "start": datetime(2025, 1, 1, tzinfo=UTC),
        "end": datetime(2027, 1, 1, tzinfo=UTC),
        "stype_in": "raw_symbol",
        "limit": 10,
        "max_estimated_usd": Decimal("0.05"),
    }
    args.update(invalid)
    transport = FakeTransport()
    with pytest.raises(DatabentoAdapterError) as caught:
        spec = DatabentoReadSpec(**args)  # type: ignore[arg-type]
        adapter, _sink, _refs = build_adapter(transport)
        adapter.read(spec)
    assert caught.value.code == "INVALID_QUERY"
    assert len(transport.calls) == 0
    assert str(caught.value) == caught.value.args[0]


def test_locator_and_pinned_registry_mapping_version_are_required() -> None:
    cases = (
        ((NATIVE_INSTRUMENT_ID, "SYN"), MappingRegistry(), MAPPING_VERSION),
        ((NATIVE_INSTRUMENT_ID, "SYN"), MappingRegistry((mapping("other-v"),)), MAPPING_VERSION),
        (None, MappingRegistry((mapping(),)), MAPPING_VERSION),
    )
    for locator, registry, version in cases:
        transport = FakeTransport(cost_response(), data_response())
        adapter, sink, _refs = build_adapter(transport, locator_result=locator, registry=registry)
        with pytest.raises(DatabentoAdapterError) as caught:
            adapter.read(make_spec(mapping_version=version))
        assert caught.value.code == "UNMAPPED_INSTRUMENT"
        assert str(caught.value) == "UNMAPPED_INSTRUMENT"
        assert sink.attempts == []

    transport = FakeTransport(cost_response(), data_response())
    adapter, sink, _refs = build_adapter(transport)
    with pytest.raises(DatabentoAdapterError) as caught:
        adapter.read(make_spec(listing_venue="XOTHER"))
    assert caught.value.code == "UNMAPPED_INSTRUMENT"
    assert sink.attempts == []


@pytest.mark.parametrize(
    ("raw_instrument_id", "located_instrument_id"),
    [(7002, 7002), (7001, 7002)],
)
def test_instrument_binding_quarantines_reused_symbol_with_wrong_provider_id(
    raw_instrument_id: int, located_instrument_id: int
) -> None:
    raw = first_json_line()
    raw["instrument_id"] = raw_instrument_id
    transport = FakeTransport(cost_response(), data_response(jsonl(raw)))
    adapter, sink, _refs = build_adapter(transport, locator_result=(located_instrument_id, "SYN"))

    result = adapter.read(make_spec())

    assert result.record_count == 1
    assert result.quarantined_count == 1
    assert result.normalized_count == 0
    assert sink.attempts == []


@pytest.mark.parametrize(
    ("event_time_ns", "expected_reason"),
    [
        (EVENT_NS - 1, "OUTSIDE_MAPPING_VALIDITY"),
        (EVENT_NS + 10, "OUTSIDE_MAPPING_VALIDITY"),
    ],
)
def test_binding_validity_is_half_open_and_out_of_range_events_are_quarantined(
    event_time_ns: int, expected_reason: str
) -> None:
    raw = first_json_line()
    raw["ts_event"] = event_time_ns
    binding = InstrumentBindingV1(
        provider_instrument_id=NATIVE_INSTRUMENT_ID,
        valid_from_ns=EVENT_NS,
        valid_to_ns=EVENT_NS + 10,
    )
    transport = FakeTransport(cost_response(), data_response(jsonl(raw)))
    adapter, sink, _refs = build_adapter(transport)

    result = adapter.read(make_spec(instrument_binding=binding))

    assert result.record_count == 1
    assert result.quarantined_count == 1
    assert result.normalized_count == 0
    assert sink.attempts == []


def test_binding_valid_from_is_inclusive_and_valid_event_normalizes() -> None:
    raw = first_json_line()
    raw["ts_event"] = EVENT_NS
    binding = InstrumentBindingV1(
        provider_instrument_id=NATIVE_INSTRUMENT_ID,
        valid_from_ns=EVENT_NS,
        valid_to_ns=EVENT_NS + 10,
    )
    transport = FakeTransport(cost_response(), data_response(jsonl(raw)))
    adapter, sink, _refs = build_adapter(transport)

    result = adapter.read(make_spec(instrument_binding=binding))

    assert result.quarantined_count == 0
    assert result.normalized_count == 1
    assert len(sink.attempts) == 1
    assert sink.attempts[0].native_provenance.native_instrument_id == NATIVE_INSTRUMENT_ID


def test_dated_locator_receives_provider_ids_and_event_date_and_version_is_pinned() -> None:
    seen: list[tuple[str, int, int, date]] = []
    transport = FakeTransport(cost_response(), data_response(read_fixture("ohlcv-1m.jsonl")))
    adapter, sink, _refs = build_adapter(transport, seen_locator=seen)

    result = adapter.read(make_spec("ohlcv-1m"))

    event_date = datetime.fromtimestamp(EVENT_NS / 1_000_000_000, UTC).date()
    assert seen == [(DATASET, PUBLISHER_ID, NATIVE_INSTRUMENT_ID, event_date)]
    assert result.mapping_version == MAPPING_VERSION
    assert sink.attempts[0].mapping_version == MAPPING_VERSION


def test_sentinels_bool_integers_and_missing_native_fields_are_quarantined() -> None:
    source = first_json_line()
    cases: list[dict[str, object]] = []
    for field, value in (
        ("price", 9_223_372_036_854_775_807),
        ("ts_event", 18_446_744_073_709_551_615),
        ("ts_recv", 18_446_744_073_709_551_615),
        ("sequence", True),
        ("publisher_id", True),
    ):
        invalid = dict(source)
        invalid[field] = value
        cases.append(invalid)
    missing = dict(source)
    del missing["ts_recv"]
    cases.append(missing)

    for raw in cases:
        transport = FakeTransport(cost_response(), data_response(jsonl(raw)))
        adapter, sink, _refs = build_adapter(transport)
        result = adapter.read(make_spec())
        assert result.record_count == 1
        assert result.quarantined_count == 1
        assert result.normalized_count == 0
        assert sink.attempts == []


def test_exact_duplicate_is_skipped_and_semantic_key_conflict_is_quarantined() -> None:
    record = first_json_line()
    exact_transport = FakeTransport(cost_response(), data_response(jsonl(record, record)))
    exact_adapter, exact_sink, _refs = build_adapter(exact_transport)
    exact_result = exact_adapter.read(make_spec())
    assert exact_result.normalized_count == 1
    assert exact_result.quarantined_count == 0
    assert len(exact_sink.attempts) == 1

    conflicting = dict(record)
    conflicting["price"] = 101_260_000_000
    conflict_transport = FakeTransport(cost_response(), data_response(jsonl(record, conflicting)))
    conflict_adapter, conflict_sink, _refs = build_adapter(conflict_transport)
    conflict_result = conflict_adapter.read(make_spec())
    assert conflict_result.normalized_count == 1
    assert conflict_result.quarantined_count == 1
    assert len(conflict_sink.attempts) == 1


def test_refetch_with_different_query_end_keeps_native_identity_stable() -> None:
    record_body = jsonl(first_json_line())
    sink = IdempotentSink()
    first_transport = FakeTransport(cost_response(), data_response(record_body))
    first_adapter, _sink, _refs = build_adapter(first_transport, sink=sink)
    first_result = first_adapter.read(make_spec(end=datetime(2027, 1, 1, tzinfo=UTC)))
    first_event = sink.attempts[0]

    second_transport = FakeTransport(cost_response(), data_response(record_body))
    second_adapter, _sink, _refs = build_adapter(second_transport, sink=sink)
    second_result = second_adapter.read(make_spec(end=datetime(2027, 1, 2, tzinfo=UTC)))
    second_event = sink.attempts[1]

    assert first_result.normalized_count == second_result.normalized_count == 1
    assert first_event.source_record_key == second_event.source_record_key
    assert first_event.idempotency_key == second_event.idempotency_key
    assert first_event.event_id == second_event.event_id
    assert len(sink.accepted) == 1
    assert first_event.ingest_time_ns != second_event.ingest_time_ns


def test_backpressure_returns_sealed_pending_key_and_resubmit_retries_same_event() -> None:
    sink = RecordingSink(SinkAck(backpressure=True), SinkAck(accepted=True))
    transport = FakeTransport(cost_response(), data_response())
    adapter, _sink, _refs = build_adapter(transport, sink=sink)

    result = adapter.read(make_spec())

    assert verify(result, "md002.read_result.v1")
    assert result.normalized_count == 0
    assert result.pending_record_keys
    assert result.receipts == ()
    assert len(sink.attempts) == 1
    pending_key = result.pending_record_keys[0]
    pending_event = sink.attempts[0]
    ack = adapter.resubmit(pending_key)
    assert ack.accepted
    assert not ack.backpressure
    assert sink.attempts[1] is pending_event
    assert sink.accepted[pending_event.idempotency_key] is pending_event
    with pytest.raises(DatabentoAdapterError) as caught:
        adapter.resubmit(pending_key)
    assert caught.value.code == "INVALID_QUERY"


@pytest.mark.parametrize(
    ("response", "code"),
    [
        (HttpResponse(401, {}, b"private body"), "AUTH_DENIED"),
        (HttpResponse(403, {}, b"private body"), "ENTITLEMENT_DENIED"),
        (HttpResponse(302, {"Location": "https://evil.invalid/"}, b"secret"), "REDIRECT_DENIED"),
        (HttpResponse(500, {}, SYNTHETIC_SECRET.encode()), "HTTP_STATUS"),
        (TimeoutError(SYNTHETIC_SECRET), "TIMEOUT"),
        (RuntimeError(SYNTHETIC_SECRET), "HTTP_STATUS"),
    ],
)
def test_transport_errors_are_typed_redacted_and_never_retried(
    response: HttpResponse | Exception, code: str
) -> None:
    transport = FakeTransport(response)
    adapter, sink, _refs = build_adapter(transport)
    with pytest.raises(DatabentoAdapterError) as caught:
        adapter.read(make_spec())
    assert caught.value.code == code
    assert str(caught.value) == code
    assert caught.value.args == (code,)
    assert SYNTHETIC_SECRET not in str(caught.value)
    assert len(transport.calls) == 1
    assert data_call_count(transport) == 0
    assert sink.attempts == []


@pytest.mark.parametrize("which", ["cost", "data"])
def test_response_byte_caps_are_enforced_before_parsing(which: str) -> None:
    body = b"x" * (65_536 + 1 if which == "cost" else 1_048_576 + 1)
    responses = (
        (cost_response(body),) if which == "cost" else (cost_response(), data_response(body))
    )
    transport = FakeTransport(*responses)
    adapter, _sink, _refs = build_adapter(transport)
    with pytest.raises(DatabentoAdapterError) as caught:
        adapter.read(make_spec())
    assert caught.value.code == "OVERSIZE"
    assert len(transport.calls) == len(responses)


def test_line_and_record_caps_and_malformed_json_are_bounded() -> None:
    oversized_line = jsonl(first_json_line()) + b"x" * 10_241 + b"\n"
    transport = FakeTransport(cost_response(), data_response(oversized_line))
    adapter, _sink, _refs = build_adapter(transport)
    with pytest.raises(DatabentoAdapterError) as caught:
        adapter.read(make_spec())
    assert caught.value.code == "OVERSIZE"

    eleven = jsonl(*(first_json_line() for _ in range(11)))
    transport = FakeTransport(cost_response(), data_response(eleven))
    adapter, _sink, _refs = build_adapter(transport)
    with pytest.raises(DatabentoAdapterError) as caught:
        adapter.read(make_spec())
    assert caught.value.code == "OVERSIZE"

    transport = FakeTransport(cost_response(), data_response(b"{bad json}\n"))
    adapter, sink, _refs = build_adapter(transport)
    result = adapter.read(make_spec())
    assert result.record_count == 1
    assert result.quarantined_count == 1
    assert result.normalized_count == 0
    assert sink.attempts == []


def test_credential_resolution_is_injected_per_read_and_vendor_errors_do_not_escape() -> None:
    def denied(_ref: CredentialRef) -> SecretStr:
        raise RuntimeError(SYNTHETIC_SECRET)

    transport = FakeTransport()
    adapter, _sink, refs = build_adapter(transport, credential_resolver=denied)
    with pytest.raises(DatabentoAdapterError) as caught:
        adapter.read(make_spec())
    assert caught.value.code == "AUTH_DENIED"
    assert str(caught.value) == "AUTH_DENIED"
    assert SYNTHETIC_SECRET not in repr(caught.value)
    assert caught.value.__cause__ is None
    assert len(transport.calls) == 0
    assert refs == []


def test_result_is_sealed_immutable_and_noncopyable() -> None:
    transport = FakeTransport(cost_response(), data_response(read_fixture("ohlcv-1m.jsonl")))
    adapter, _sink, _refs = build_adapter(transport)
    result = adapter.read(make_spec("ohlcv-1m"))
    assert verify(result, "md002.read_result.v1")
    with pytest.raises((AttributeError, TypeError)):
        result.record_count = 99  # type: ignore[misc]
    assert not verify(replace(result, normalized_count=99), "md002.read_result.v1")
    with pytest.raises(TypeError, match="COPY_FORBIDDEN"):
        copy.copy(result)
    with pytest.raises(TypeError, match="COPY_FORBIDDEN"):
        copy.deepcopy(result)
    with pytest.raises(TypeError, match="COPY_FORBIDDEN"):
        pickle.dumps(result)
