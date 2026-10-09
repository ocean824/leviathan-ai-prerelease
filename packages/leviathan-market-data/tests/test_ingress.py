from __future__ import annotations

import copy
import json
import pickle
import random
from collections.abc import Mapping
from dataclasses import replace
from decimal import ROUND_DOWN, Inexact, Overflow, localcontext
from operator import setitem
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from pydantic import BaseModel

from leviathan_market_data import is_issued_receipt
from leviathan_market_data.health import SourceHealthSnapshot
from leviathan_market_data.ingress import (
    IngestReceipt,
    IngestStatus,
    NormalizedIngress,
    SinkAck,
)
from leviathan_market_data.normalization import NormalizationError, Normalizer, VendorRecord
from leviathan_market_data.schema import (
    BarPayload,
    BookDeltaPayload,
    BookLevel,
    BookSnapshotPayload,
    CorporateActionPayload,
    MarketDataValidationError,
    MarketDataValueError,
    NativeProvenance,
    NewsPayload,
    NormalizedMarketEventV1,
    PriceValue,
    ProvenanceTimestamps,
    QuotePayload,
    ReferencePayload,
    StatusPayload,
    TradePayload,
)
from leviathan_market_data.symbology import InstrumentMapping, MappingRegistry

ROOT = Path(__file__).parent
FIXTURE = ROOT / "fixtures" / "ingress" / "trade-quote-book.jsonl"
NOW_NS = 2_000_000_000_000_000_000
EVENT_NS = 1_770_000_000_000_000_000


MAPPING = InstrumentMapping(
    provider="synthetic-feed",
    dataset="synthetic-v1",
    venue="XTEST",
    native_symbol="SYNTH",
    instrument_id="SYNTH-001",
    leviathan_symbol="SYNTH",
    instrument_type="equity",
    mapping_version="test-v1",
    tick_size="0.01",
)


class RecordingSink:
    def __init__(self, *, backpressure_count: int = 0) -> None:
        self.attempts: list[Any] = []
        self.accepted: list[Any] = []
        self.backpressure_count = backpressure_count

    def accept(self, event: Any) -> SinkAck:
        self.attempts.append(event)
        if self.backpressure_count:
            self.backpressure_count -= 1
            return SinkAck(accepted=False, backpressure=True)
        self.accepted.append(event)
        return SinkAck(accepted=True)


class SideEffectThenRaiseSink:
    """Demonstrate why explicit recovery requires sink idempotency by event identity."""

    def __init__(self, *, idempotent: bool) -> None:
        self.idempotent = idempotent
        self.calls = 0
        self.side_effects: list[str] = []
        self.seen: set[str] = set()

    def accept(self, event: Any) -> SinkAck:
        self.calls += 1
        key = event.idempotency_key
        if not self.idempotent or key not in self.seen:
            self.side_effects.append(key)
            self.seen.add(key)
        if self.calls == 1:
            raise RuntimeError("synthetic post-side-effect sink fault")
        return SinkAck(accepted=True)


def make_record(
    event_type: str = "trade",
    *,
    payload: Mapping[str, object] | None = None,
    event_time_ns: int = EVENT_NS,
    source_mode: str = "historical",
    source_record_ref: str = "synthetic://test/record-1",
    source_record_key: str | None = None,
    native_trade_id: str | None = "trade-1",
    native_sequence: int | None = 1,
    source_time_ns: int | None = EVENT_NS - 5,
    exchange_time_ns: int | None = EVENT_NS - 4,
    event_id: UUID | None = None,
    ingest_time_ns: int | None = None,
    received_time_ns: int | None = None,
    processing_time_ns: int | None = None,
    transport_request_id: str | None = None,
    quality_flags: tuple[str, ...] = (),
    correction_fields: Mapping[str, object] | None = None,
    provenance_timestamps: Mapping[str, int | None] | None = None,
    native_provenance: Mapping[str, object] | None = None,
    source_attributes: Mapping[str, str] | None = None,
    provider_session_id: str | None = None,
    session_transition_confirmed: bool = False,
    provider: str = "synthetic-feed",
    dataset: str = "synthetic-v1",
    venue: str = "XTEST",
    native_symbol: str = "SYNTH",
    channel: str = "trades",
) -> VendorRecord:
    payloads: dict[str, Mapping[str, object]] = {
        "trade": {"price": "101.25", "size": "3.000", "side": "buy"},
        "quote": {
            "bid_price": "101.24", "ask_price": "101.26",
            "bid_size": "8.00", "ask_size": "7.0",
            "bid_exchange": "XBid", "ask_exchange": "XAsk",
            "bid_time_ns": EVENT_NS - 5, "ask_time_ns": EVENT_NS - 4,
        },
        "book_delta": {
            "action": "update", "side": "bid", "price": "101.24",
            "size": "5.000", "level": 1, "order_id": "order-1",
        },
        "book_snapshot": {"levels": [
            {"side": "bid", "price": "101.24", "size": "5.000", "level": 1},
            {"side": "ask", "price": "101.26", "size": "6.000", "level": 1},
        ]},
        "bar": {
            "interval": "1m", "open_time_ns": EVENT_NS - 60_000_000_000,
            "open": "101.00", "high": "102.00", "low": "100.50",
            "close": "101.50", "volume": "10.125",
        },
        "status": {"status": "halted", "reason": "synthetic maintenance"},
        "reference": {"attributes": {"currency": "USD", "class": "synthetic"}},
        "corporate_action": {
            "action": "split", "effective_time_ns": EVENT_NS + 100,
            "details": {"ratio": "2:1"},
        },
        "news": {
            "headline": "Synthetic fixture headline", "story_ref": "fixture://story/1",
            "publisher": "Synthetic Publisher",
        },
    }
    effective_payload = dict(payload if payload is not None else payloads[event_type])
    if source_record_key is None and event_type in {
        "book_snapshot", "status", "reference", "corporate_action", "news",
    }:
        source_record_key = f"synthetic-{event_type}-identity"
    return VendorRecord(
        provider=provider,
        dataset=dataset,
        venue=venue,
        native_symbol=native_symbol,
        channel=channel,
        event_type=event_type,
        event_time_ns=event_time_ns,
        source_record_ref=source_record_ref,
        payload=effective_payload,
        source_mode=source_mode,  # type: ignore[arg-type]
        source_time_ns=source_time_ns,
        exchange_time_ns=exchange_time_ns,
        native_sequence=native_sequence,
        native_trade_id=native_trade_id if event_type == "trade" else None,
        source_record_key=source_record_key,
        event_id=event_id,
        ingest_time_ns=ingest_time_ns,
        received_time_ns=received_time_ns,
        processing_time_ns=processing_time_ns,
        quality_flags=quality_flags,
        correction_fields=dict(correction_fields or {}),
        provenance_timestamps=dict(provenance_timestamps or {}),
        native_provenance=dict(native_provenance or {}),
        source_attributes=dict(source_attributes or {}),
        provider_session_id=provider_session_id,
        session_transition_confirmed=session_transition_confirmed,
        transport_request_id=transport_request_id,
    )


def make_ingress(
    *,
    sink: RecordingSink | None = None,
    now: int = NOW_NS,
    arrival: int = 0,
    future_tolerance_ms: int = 1_000,
    **kwargs: Any,
) -> tuple[NormalizedIngress, RecordingSink, dict[str, int]]:
    sink = sink or RecordingSink()
    clocks = {"wall": now, "arrival": arrival}
    normalizer = Normalizer(
        MappingRegistry((MAPPING,)), future_tolerance_ms=future_tolerance_ms,
    )
    ingress = NormalizedIngress(
        normalizer,
        sink,
        clock_ns=lambda: clocks["wall"],
        arrival_clock_ns=lambda: clocks["arrival"],
        **kwargs,
    )
    return ingress, sink, clocks


def stream_key(record: VendorRecord) -> tuple[str, str, str, str, str]:
    return (record.provider, record.dataset, record.venue, "SYNTH-001", record.channel)


def fixture_pairs(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def schema_model_samples() -> dict[type[BaseModel], BaseModel]:
    normalizer = Normalizer(MappingRegistry((MAPPING,)))
    event_types = (
        "trade", "quote", "book_delta", "book_snapshot", "bar", "status",
        "reference", "corporate_action", "news",
    )
    events = [
        normalizer.normalize(make_record(event_type), now_ns=NOW_NS)
        for event_type in event_types
    ]
    samples: dict[type[BaseModel], BaseModel] = {}

    def collect(value: object) -> None:
        if isinstance(value, BaseModel):
            samples[type(value)] = value
            for field_name in type(value).model_fields:
                collect(getattr(value, field_name))
        elif isinstance(value, Mapping):
            for item in value.values():
                collect(item)
        elif isinstance(value, (list, tuple)):
            for item in value:
                collect(item)

    for event in events:
        collect(event)
    return samples


def test_fixture_is_synthetic_trade_quote_and_book_jsonl() -> None:
    lines = [json.loads(line) for line in FIXTURE.read_text(encoding="utf-8").splitlines()]
    assert len(lines) == 3
    assert {line["record"]["event_type"] for line in lines} == {
        "trade", "quote", "book_delta",
    }
    assert all(line["mapping"]["provider"] == "synthetic-feed" for line in lines)
    assert all(line["record"]["source_record_ref"].startswith("synthetic://") for line in lines)
    assert all("source_record_key" in line["record"] for line in lines)


@pytest.mark.parametrize(
    ("event_type", "payload_type"),
    [
        ("trade", TradePayload),
        ("quote", QuotePayload),
        ("book_delta", BookDeltaPayload),
        ("book_snapshot", BookSnapshotPayload),
        ("bar", BarPayload),
        ("status", StatusPayload),
        ("reference", ReferencePayload),
        ("corporate_action", CorporateActionPayload),
        ("news", NewsPayload),
    ],
)
def test_every_supported_event_type_normalizes_to_its_typed_payload(
    event_type: str, payload_type: type[Any],
) -> None:
    ingress, sink, _ = make_ingress()
    record = make_record(event_type)

    receipt = ingress.ingest(record)

    assert receipt.status is IngestStatus.ACCEPTED
    assert isinstance(receipt.event.payload, payload_type)
    assert receipt.event.event_type == event_type
    assert receipt.execution_eligible is False
    assert len(sink.accepted) == 1


def test_normalized_schema_is_frozen_and_forbids_unrecognized_fields() -> None:
    ingress, _, _ = make_ingress()
    event = ingress.ingest(make_record()).event
    serialized = event.model_dump(mode="python")
    serialized["unexpected_source_field"] = "not permitted"

    with pytest.raises(MarketDataValidationError) as invalid_event:
        NormalizedMarketEventV1.model_validate(serialized)
    assert invalid_event.value.code == "INVALID_PAYLOAD"
    assert "unexpected_source_field" not in str(invalid_event.value)
    assert "not permitted" not in str(invalid_event.value.args)

    canary = "MUTATION-CANARY-MUST-NOT-LEAK"
    with pytest.raises(MarketDataValidationError) as assignment:
        event.provider = canary
    with pytest.raises(MarketDataValidationError) as setattr_error:
        event.provider = canary
    with pytest.raises(MarketDataValidationError) as deletion:
        del event.provider
    for error in (assignment.value, setattr_error.value, deletion.value):
        assert error.code == "FROZEN_RECORD"
        assert canary not in str(error)
        assert canary not in str(error.args)
        assert canary not in str(error.errors())
        assert canary not in error.json()


def test_pydantic_copy_construct_and_serialization_bypasses_are_blocked() -> None:
    samples = schema_model_samples()
    expected_models = {
        PriceValue, TradePayload, QuotePayload, BookLevel, BookDeltaPayload,
        BookSnapshotPayload, BarPayload, StatusPayload, ReferencePayload,
        CorporateActionPayload, NewsPayload, ProvenanceTimestamps,
        NativeProvenance, NormalizedMarketEventV1,
    }
    assert set(samples) == expected_models

    invalid_updates: dict[type[BaseModel], dict[str, object]] = {
        PriceValue: {"value": "SYNTHETIC_INVALID_DECIMAL"},
        TradePayload: {"size": "-1"},
        QuotePayload: {"bid_present": False, "ask_present": False},
        BookLevel: {"side": "neither"},
        BookDeltaPayload: {"action": "neither"},
        BookSnapshotPayload: {"levels": ("not-a-level",)},
        BarPayload: {"open_time_ns": True},
        StatusPayload: {"status": None},
        ReferencePayload: {"attributes": {"currency": 7}},
        CorporateActionPayload: {"effective_time_ns": True},
        NewsPayload: {"headline": None},
        ProvenanceTimestamps: {"provider": True},
        NativeProvenance: {"flags": True},
        NormalizedMarketEventV1: {"event_time_ns": True},
    }
    for model_type, instance in samples.items():
        updates = invalid_updates[model_type]
        with pytest.raises(TypeError, match="MODEL_BYPASS_FORBIDDEN"):
            instance.model_copy(update=updates)
        values = instance.model_dump(mode="python")
        values.update(updates)
        with pytest.raises(TypeError, match="MODEL_BYPASS_FORBIDDEN"):
            model_type.model_construct(**values)
        for operation in (copy.copy, copy.deepcopy):
            with pytest.raises(TypeError, match="COPY_FORBIDDEN"):
                operation(instance)
        with pytest.raises(TypeError, match="COPY_FORBIDDEN"):
            pickle.dumps(instance)
        first_field = next(iter(model_type.model_fields))
        canary = "MUTATION-CANARY-MUST-NOT-LEAK"
        with pytest.raises(MarketDataValidationError) as assignment:
            setattr(instance, first_field, canary)
        with pytest.raises(MarketDataValidationError) as deletion:
            delattr(instance, first_field)
        for error in (assignment.value, deletion.value):
            assert error.code == "FROZEN_RECORD"
            assert canary not in str(error)
            assert canary not in str(error.args)
            assert canary not in str(error.errors())
            assert canary not in error.json()


def test_model_bypass_cannot_inject_mutable_nested_mappings() -> None:
    samples = schema_model_samples()
    reference = samples[ReferencePayload]
    event = samples[NormalizedMarketEventV1]
    mutable_attributes = {"currency": "USD"}

    with pytest.raises(TypeError, match="MODEL_BYPASS_FORBIDDEN"):
        reference.model_copy(update={"attributes": mutable_attributes})
    with pytest.raises(TypeError, match="MODEL_BYPASS_FORBIDDEN"):
        ReferencePayload.model_construct(attributes=mutable_attributes)

    with pytest.raises(TypeError, match="MODEL_BYPASS_FORBIDDEN"):
        event.model_copy(update={"source_attributes": mutable_attributes})
    values = event.model_dump(mode="python")
    values["source_attributes"] = mutable_attributes
    with pytest.raises(TypeError, match="MODEL_BYPASS_FORBIDDEN"):
        NormalizedMarketEventV1.model_construct(**values)

    mutable_attributes["currency"] = "EUR"


def test_all_schema_integer_and_timestamp_fields_reject_bool() -> None:
    samples = schema_model_samples()
    integer_fields = {
        PriceValue: ("price_ticks",),
        QuotePayload: ("bid_time_ns", "ask_time_ns"),
        BookLevel: ("level",),
        BookDeltaPayload: ("level",),
        BarPayload: ("open_time_ns",),
        CorporateActionPayload: ("effective_time_ns",),
        ProvenanceTimestamps: ("exchange", "sip", "trf", "participant", "provider"),
        NativeProvenance: (
            "publisher_id", "native_instrument_id", "native_exchange_id",
            "rtype", "flags", "ts_in_delta_ns",
        ),
        NormalizedMarketEventV1: (
            "event_time_ns", "source_time_ns", "exchange_time_ns", "ingest_time_ns",
            "processing_time_ns", "received_time_ns", "native_sequence",
        ),
    }
    for model_type, fields in integer_fields.items():
        instance = samples[model_type]
        for field_name in fields:
            values = instance.model_dump(mode="python")
            values[field_name] = True
            with pytest.raises(MarketDataValidationError) as caught:
                model_type.model_validate(values)
            assert caught.value.code == "INVALID_INTEGER"
            assert "True" not in str(caught.value)
            assert "True" not in str(caught.value.args)
            assert "True" not in str(caught.value.errors())
            assert "True" not in caught.value.json()


def test_vendor_record_integer_and_timestamp_fields_reject_bool_with_redacted_codes() -> None:
    record = make_record()
    direct_integer_fields = (
        "event_time_ns", "source_time_ns", "exchange_time_ns", "ingest_time_ns",
        "received_time_ns", "processing_time_ns", "native_sequence",
    )
    invalid_factories = [
        lambda field_name=field_name: replace(record, **{field_name: True})
        for field_name in direct_integer_fields
    ]
    invalid_factories.extend((
        lambda: replace(record, provenance_timestamps={"sip": True}),
        lambda: replace(record, native_provenance={"flags": True}),
    ))
    for build_invalid_record in invalid_factories:
        with pytest.raises(ValueError) as caught:
            build_invalid_record()
        assert getattr(caught.value, "code", None) == "INVALID_INTEGER"
        assert "input_value=" not in str(caught.value)

    integer_payloads = (
        ("quote", "bid_time_ns"),
        ("quote", "ask_time_ns"),
        ("book_delta", "level"),
        ("book_snapshot", "levels"),
        ("bar", "open_time_ns"),
        ("corporate_action", "effective_time_ns"),
    )
    for event_type, field_name in integer_payloads:
        source = make_record(event_type)
        payload = dict(source.payload)
        if field_name == "levels":
            level = dict(payload["levels"][0])
            level["level"] = True
            payload["levels"] = [level]
        else:
            payload[field_name] = True
        bad_record = replace(source, payload=payload)
        with pytest.raises(NormalizationError) as caught:
            Normalizer(MappingRegistry((MAPPING,))).normalize(bad_record, now_ns=NOW_NS)
        assert caught.value.reason == "INVALID_INTEGER"
        assert "input_value=" not in str(caught.value)


def test_health_snapshot_integer_fields_reject_bool_with_typed_redacted_error() -> None:
    ingress, _, _ = make_ingress()
    snapshot = ingress.health(stream_key(make_record()))
    integer_fields = (
        "last_received_time_ns", "last_processed_time_ns", "last_provider_time_ns",
        "last_exchange_time_ns", "gap_count", "late_count", "queued_count",
        "fault_count", "sequence_regression_count",
    )

    for field_name in integer_fields:
        with pytest.raises(ValueError) as caught:
            replace(snapshot, **{field_name: True})
        assert type(caught.value).__name__ == "MarketDataValueError"
        assert getattr(caught.value, "code", None) == "INVALID_INTEGER"
        assert "input_value=" not in str(caught.value)


def test_policy_and_injected_clock_integer_inputs_reject_bool() -> None:
    integer_policies = (
        "max_committed_keys", "dedupe_window_ns", "hot_window_ns",
        "hot_max_messages", "correction_window_ns",
    )
    for policy_name in integer_policies:
        with pytest.raises(ValueError) as caught:
            make_ingress(**{policy_name: True})
        assert type(caught.value).__name__ == "MarketDataValueError"
        assert getattr(caught.value, "code", None) == "INVALID_INTEGER"
        assert "input_value=" not in str(caught.value)

    with pytest.raises(ValueError) as caught_tolerance:
        make_ingress(future_tolerance_ms=True)
    assert type(caught_tolerance.value).__name__ == "MarketDataValueError"
    assert getattr(caught_tolerance.value, "code", None) == "INVALID_INTEGER"

    normalizer = Normalizer(MappingRegistry((MAPPING,)))
    with pytest.raises(NormalizationError) as caught_clock:
        normalizer.normalize(make_record(), now_ns=True)
    assert caught_clock.value.reason == "INVALID_INTEGER"
    assert "input_value=" not in str(caught_clock.value)


def test_error_codes_are_typed_and_do_not_echo_invalid_decimal_input() -> None:
    secret_marker = "SYNTHETIC_INVALID_DECIMAL_SHOULD_NOT_LEAK"
    ingress, sink, _ = make_ingress()
    receipt = ingress.ingest(make_record(payload={
        "price": secret_marker, "size": "1", "side": "buy",
    }))

    assert receipt.status is IngestStatus.QUARANTINED
    assert receipt.reason == "INVALID_DECIMAL"
    assert secret_marker not in str(receipt)
    assert not sink.attempts


def test_quote_preserves_each_publishing_exchange_independently() -> None:
    ingress, _, _ = make_ingress()
    receipt = ingress.ingest(make_record("quote"))

    assert isinstance(receipt.event.payload, QuotePayload)
    assert receipt.event.payload.bid_exchange == "XBid"
    assert receipt.event.payload.ask_exchange == "XAsk"
    assert receipt.event.venue == "XTEST"


@pytest.mark.parametrize(("record_index", "missing_side"), [(0, "bid"), (1, "ask")])
def test_one_sided_massive_quote_fixture_preserves_only_present_side(
    record_index: int, missing_side: str,
) -> None:
    pair = fixture_pairs(ROOT / "fixtures" / "ingress" / "one-sided-quotes.jsonl")[record_index]
    mapping = InstrumentMapping(**pair["mapping"])
    record = VendorRecord(**pair["record"])
    normalizer = Normalizer(MappingRegistry((mapping,)))

    event = normalizer.normalize(record, now_ns=NOW_NS)

    assert isinstance(event.payload, QuotePayload)
    if missing_side == "bid":
        assert event.payload.bid_present is False
        assert event.payload.bid_price is None
        assert event.payload.bid_size is None
        assert event.payload.bid_exchange is None
        assert event.payload.bid_time_ns is None
        assert event.payload.ask_present is True
        assert event.payload.ask_price.value == "101.26"
        assert event.payload.ask_size == "2"
        assert event.payload.ask_time_ns == 1_770_000_000_000_000_009
        assert "missing_bid" in event.quality_flags
    else:
        assert event.payload.ask_present is False
        assert event.payload.ask_price is None
        assert event.payload.ask_size is None
        assert event.payload.ask_exchange is None
        assert event.payload.ask_time_ns is None
        assert event.payload.bid_present is True
        assert event.payload.bid_price.value == "101.24"
        assert event.payload.bid_size == "7"
        assert event.payload.bid_time_ns == 1_770_000_000_000_000_019
        assert "missing_ask" in event.quality_flags


def test_reviewer_ask_only_quote_with_zero_missing_bid_size_is_not_treated_as_a_bid() -> None:
    ingress, sink, _ = make_ingress()
    record = make_record(
        "quote",
        source_record_key="reviewer-ask-only-quote",
        payload={
            "bid_price": None,
            "bid_size": "0",
            "ask_price": "101.26",
            "ask_size": "2.00",
        },
    )

    receipt = ingress.ingest(record)

    assert receipt.status is IngestStatus.QUARANTINED
    assert not sink.attempts


def test_md002_md003_timestamp_fixtures_are_visible_as_typed_provenance() -> None:
    pairs = fixture_pairs(ROOT / "fixtures" / "ingress" / "native-timestamp-provenance.jsonl")
    events = []
    for pair in pairs:
        mapping = InstrumentMapping(**pair["mapping"])
        record = VendorRecord(**pair["record"])
        events.append(
            Normalizer(MappingRegistry((mapping,))).normalize(record, now_ns=NOW_NS)
        )

    massive_quote, databento_trade, massive_trade = events
    assert massive_quote.provenance_timestamps.participant == 1_770_000_000_000_000_008
    assert massive_quote.provenance_timestamps.sip == 1_770_000_000_000_000_009
    assert massive_quote.provenance_timestamps.trf == 1_770_000_000_000_000_007
    assert massive_quote.native_provenance.trf_id == "synthetic-trf-id"
    assert databento_trade.provenance_timestamps.exchange == 1_770_000_000_000_000_100
    assert databento_trade.provenance_timestamps.provider == 1_770_000_000_000_000_101
    assert massive_quote.native_provenance.trade_conditions == (
        "massive:SYNTHETIC_CONDITION",
    )
    assert databento_trade.native_provenance.publisher_id == 1
    assert databento_trade.native_provenance.native_instrument_id == 42
    assert databento_trade.native_provenance.rtype == 0
    assert databento_trade.native_provenance.flags == 4
    assert databento_trade.native_provenance.ts_in_delta_ns == -100
    assert databento_trade.native_provenance.action == "trade"
    assert databento_trade.native_provenance.side == "buy"
    assert databento_trade.native_provenance.correction == "none"
    assert databento_trade.native_provenance.trade_conditions == (
        "databento:SYNTHETIC_CONDITION",
    )
    assert databento_trade.source_attributes["databento:raw_action_code"] == "T"
    assert databento_trade.native_trade_id is None
    assert databento_trade.provider_session_id == "synthetic-session-2026-09-29"
    assert databento_trade.source_record_key.startswith("databento-trades-v1|")
    assert massive_trade.native_provenance.native_exchange_id == "SYNTH-EXCHANGE"
    assert massive_trade.native_provenance.trf_id == "synthetic-trf-id-3"
    assert massive_trade.native_provenance.correction == "correction"
    assert massive_trade.native_provenance.referenced_native_id == "synthetic-trade-id-1"
    assert massive_trade.native_provenance.side == "buy"
    assert massive_trade.source_attributes["massive:raw_exchange_code"] == "SYNTH-EXCHANGE"


def test_reference_payload_is_immutable_after_ack_and_input_mutation_cannot_change_it() -> None:
    ingress, sink, _ = make_ingress()
    source_attributes = {"currency": "USD", "class": "synthetic"}
    record = make_record("reference", payload={"attributes": source_attributes})

    accepted = ingress.ingest(record)
    source_attributes["currency"] = "EUR"

    assert accepted.status is IngestStatus.ACCEPTED
    assert accepted.event.payload.attributes["currency"] == "USD"
    with pytest.raises(TypeError):
        setitem(accepted.event.payload.attributes, "currency", "GBP")
    replay = ingress.ingest(record)
    assert replay.status is IngestStatus.DUPLICATE
    assert sink.accepted[0].payload.attributes["currency"] == "USD"


def test_corporate_action_details_are_immutable_after_ack_and_replay() -> None:
    ingress, sink, _ = make_ingress()
    details = {"ratio": "2:1"}
    record = make_record("corporate_action", payload={
        "action": "split", "effective_time_ns": EVENT_NS + 100, "details": details,
    })

    accepted = ingress.ingest(record)
    details["ratio"] = "3:1"
    replay = ingress.ingest(record)

    assert accepted.status is IngestStatus.ACCEPTED
    assert replay.status is IngestStatus.DUPLICATE
    assert accepted.event.payload.details["ratio"] == "2:1"
    assert sink.accepted[0].payload.details["ratio"] == "2:1"
    with pytest.raises(TypeError):
        setitem(accepted.event.payload.details, "ratio", "4:1")


def test_buffered_reference_payload_is_immutable_before_drain() -> None:
    ingress, sink, _ = make_ingress()
    source_attributes = {"currency": "USD"}
    record = make_record(
        "reference", source_mode="live", payload={"attributes": source_attributes},
    )

    buffered = ingress.ingest(record)
    source_attributes["currency"] = "EUR"
    with pytest.raises(TypeError):
        setitem(buffered.event.payload.attributes, "currency", "GBP")

    delivered = ingress.flush(force=True)

    assert buffered.status is IngestStatus.BUFFERED
    assert delivered[0].status is IngestStatus.ACCEPTED
    assert delivered[0].event.payload.attributes["currency"] == "USD"
    assert sink.accepted[0].payload.attributes["currency"] == "USD"


@pytest.mark.parametrize(
    ("idempotent", "expected_side_effects"),
    [(True, 1), (False, 2)],
)
def test_sink_fault_requires_explicit_recovery_with_same_identity(
    idempotent: bool, expected_side_effects: int,
) -> None:
    sink = SideEffectThenRaiseSink(idempotent=idempotent)
    ingress, _, _ = make_ingress(sink=sink)  # type: ignore[arg-type]
    record = make_record()
    key = stream_key(record)

    fault = ingress.ingest(record)
    assert fault.status is IngestStatus.SINK_FAULT
    assert fault.reason == "SINK_FAULT"
    assert ingress.committed_count(key) == 0
    assert ingress.health(key).faulted is True
    assert sink.calls == 1

    blocked = ingress.ingest(make_record(
        native_trade_id="other-while-faulted", event_time_ns=EVENT_NS + 1,
    ))
    assert blocked.status is IngestStatus.SINK_FAULT
    assert sink.calls == 1

    recovered = ingress.recover(key)

    assert recovered.status is IngestStatus.ACCEPTED
    assert recovered.event.idempotency_key == fault.event.idempotency_key
    assert ingress.committed_count(key) == 1
    assert sink.calls == 2
    assert sink.side_effects == [fault.event.idempotency_key] * expected_side_effects


def test_faulted_stream_does_not_release_other_queued_records() -> None:
    sink = SideEffectThenRaiseSink(idempotent=True)
    ingress, _, _ = make_ingress(
        sink=sink,  # type: ignore[arg-type]
        hot_window_ns=10_000,
        hot_max_messages=10,
    )
    records = [
        make_record(
            source_mode="live", event_time_ns=EVENT_NS + offset,
            source_time_ns=EVENT_NS + offset, exchange_time_ns=EVENT_NS + offset,
            ingest_time_ns=EVENT_NS + offset, native_trade_id=f"fault-queue-{offset}",
        )
        for offset in (1, 2)
    ]
    key = stream_key(records[0])
    assert all(ingress.ingest(record).status is IngestStatus.BUFFERED for record in records)

    first_drain = ingress.drain(stream=key, force=True)
    second_drain = ingress.drain(stream=key, force=True)

    assert [receipt.status for receipt in first_drain] == [IngestStatus.SINK_FAULT]
    assert second_drain == ()
    assert ingress.health(key).faulted is True
    assert ingress.committed_count(key) == 0
    assert ingress.queued_count(key) == 1
    assert sink.calls == 1


def test_exact_nanosecond_and_decimal_values_survive_without_float_rounding() -> None:
    ingress, _, _ = make_ingress()
    event_ns = 1_765_432_109_123_456_789
    record = make_record(
        event_time_ns=event_ns,
        source_time_ns=event_ns - 1,
        exchange_time_ns=event_ns - 2,
        payload={"price": "123.45", "size": "0.000000000000000001", "side": "sell"},
    )

    event = ingress.ingest(record).event

    assert event.event_time_ns == event_ns
    assert event.source_time_ns == event_ns - 1
    assert event.exchange_time_ns == event_ns - 2
    assert isinstance(event.payload, TradePayload)
    assert event.payload.price.value == "123.45"
    assert event.payload.price.price_ticks == 12_345
    assert event.payload.size == "0.000000000000000001"


def test_decimal_results_and_semantic_digest_ignore_ambient_context() -> None:
    normalizer = Normalizer(MappingRegistry((MAPPING,)))
    records = (
        make_record(payload={
            "price": "101.2500", "size": "1.2345678901234567890123456789012340",
            "side": "buy",
        }),
        make_record(payload={
            "price": "101.25", "size": "1.234567890123456789012345678901234",
            "side": "buy",
        }),
    )
    normalized = []
    digests = []
    for record in records:
        with localcontext() as context:
            context.prec = 2
            context.Emax = 9
            context.Emin = -9
            context.rounding = ROUND_DOWN
            context.traps[Inexact] = True
            context.traps[Overflow] = True
            event = normalizer.normalize(record, now_ns=NOW_NS)
            normalized.append(event)
            digests.append(normalizer.semantic_digest(record, event))

    first, equivalent = normalized
    assert first.payload.price.value == equivalent.payload.price.value == "101.25"
    assert first.payload.size == equivalent.payload.size == (
        "1.234567890123456789012345678901234"
    )
    assert first.idempotency_key == equivalent.idempotency_key
    assert digests[0] == digests[1]


def test_decimal_precision_boundary_rejects_extra_significant_digit_without_echo() -> None:
    ingress, _, _ = make_ingress()
    accepted_size = "1234567890123456789012345678901234"
    rejected_size = "12345678901234567890123456789012345"

    accepted = ingress.ingest(make_record(payload={
        "price": "101.25", "size": accepted_size, "side": "buy",
    }))
    rejected = ingress.ingest(make_record(
        native_trade_id="over-precision",
        payload={"price": "101.25", "size": rejected_size, "side": "buy"},
    ))

    assert accepted.status is IngestStatus.ACCEPTED
    assert accepted.event.payload.size == accepted_size
    assert rejected.status is IngestStatus.QUARANTINED
    assert rejected.reason == "PRECISION_EXCEEDED"
    assert rejected_size not in str(rejected)


def test_decimal_magnitude_is_rejected_before_expanding_large_exponent() -> None:
    ingress, sink, _ = make_ingress()
    compact_huge = "1E+100000"

    rejected = ingress.ingest(make_record(payload={
        "price": "101.25", "size": compact_huge, "side": "buy",
    }))

    assert rejected.status is IngestStatus.QUARANTINED
    assert rejected.reason == "DECIMAL_OUT_OF_BOUNDS"
    assert compact_huge not in str(rejected)
    assert not sink.attempts

    representable_exponent = ingress.ingest(make_record(
        native_trade_id="one-times-ten-to-thirty-four",
        payload={"price": "101.25", "size": "1E+34", "side": "buy"},
    ))
    assert representable_exponent.status is IngestStatus.ACCEPTED
    assert representable_exponent.event.payload.size == "1" + "0" * 34


def test_prices_omit_ticks_when_mapping_has_no_versioned_tick_size() -> None:
    mapping_without_tick = InstrumentMapping(
        provider="synthetic-feed", dataset="synthetic-v1", venue="XTEST",
        native_symbol="SYNTH", instrument_id="SYNTH-001", leviathan_symbol="SYNTH",
        instrument_type="equity", mapping_version="no-tick-v1", tick_size=None,
    )
    normalizer = Normalizer(MappingRegistry((mapping_without_tick,)))

    event = normalizer.normalize(make_record(), now_ns=NOW_NS)

    assert isinstance(event.payload, TradePayload)
    assert event.payload.price.value == "101.25"
    assert event.payload.price.price_ticks is None


def test_unrepresentable_tick_precision_is_quarantined() -> None:
    ingress, sink, _ = make_ingress()

    receipt = ingress.ingest(make_record(payload={
        "price": "123.456", "size": "1", "side": "buy",
    }))

    assert receipt.status is IngestStatus.QUARANTINED
    assert "INVALID_TICK_PRECISION" in (receipt.reason or "")
    assert not sink.attempts


@pytest.mark.parametrize("bad_time", [0, -1, 1 << 63])
def test_impossible_event_time_is_quarantined(bad_time: int) -> None:
    ingress, sink, _ = make_ingress()

    receipt = ingress.ingest(make_record(event_time_ns=bad_time))

    assert receipt.status is IngestStatus.QUARANTINED
    assert receipt.reason == "INVALID_TIME"
    assert not sink.attempts


def test_bool_event_time_is_rejected_at_vendor_record_creation() -> None:
    with pytest.raises(MarketDataValueError) as caught:
        make_record(event_time_ns=True)

    assert caught.value.code == "INVALID_INTEGER"
    assert "True" not in str(caught.value)
    assert "True" not in str(caught.value.args)


def test_unknown_mapping_and_unsupported_payload_are_quarantined() -> None:
    ingress, sink, _ = make_ingress()
    unknown = make_record(native_symbol="UNMAPPED")
    unsupported = make_record(event_type="not_a_market_event", payload={})

    unknown_result = ingress.ingest(unknown)
    unsupported_result = ingress.ingest(unsupported)

    assert unknown_result.status is IngestStatus.QUARANTINED
    assert unknown_result.reason == "UNKNOWN_MAPPING"
    assert unsupported_result.status is IngestStatus.QUARANTINED
    assert unsupported_result.reason == "QUARANTINED_UNSUPPORTED"
    assert not sink.attempts


def test_native_semantic_duplicate_ignores_local_ids_times_and_json_formatting() -> None:
    ingress, sink, _ = make_ingress()
    first = make_record(
        payload={"price": "101.2500", "size": "3.000", "side": "buy"},
        event_id=UUID("00000000-0000-7000-8000-000000000001"),
        ingest_time_ns=NOW_NS - 100,
        received_time_ns=NOW_NS - 90,
        processing_time_ns=NOW_NS - 80,
        transport_request_id="synthetic-request-a",
    )
    replay = make_record(
        payload={"price": "101.25", "size": "3", "side": "buy"},
        event_id=UUID("00000000-0000-7000-8000-000000000002"),
        ingest_time_ns=NOW_NS - 5,
        received_time_ns=NOW_NS - 4,
        processing_time_ns=NOW_NS - 3,
        transport_request_id="synthetic-request-b",
    )

    first_result = ingress.ingest(first)
    replay_result = ingress.ingest(replay)

    assert first_result.status is IngestStatus.ACCEPTED
    assert replay_result.status is IngestStatus.DUPLICATE
    assert replay_result.event.event_id != first_result.event.event_id
    assert replay_result.event.idempotency_key == first_result.event.idempotency_key
    assert first_result.event.payload.price.value == "101.25"
    assert first_result.event.payload.size == "3"
    assert len(sink.accepted) == 1


def test_native_replay_across_local_clock_fallback_threshold_is_duplicate() -> None:
    ingress, sink, _ = make_ingress()
    original = make_record(
        source_mode="live", event_time_ns=EVENT_NS,
        source_time_ns=EVENT_NS, exchange_time_ns=EVENT_NS,
        ingest_time_ns=EVENT_NS + 250_000_000,
        native_trade_id="threshold-replay", native_sequence=1,
    )
    replay = make_record(
        source_mode="live", event_time_ns=EVENT_NS,
        source_time_ns=EVENT_NS, exchange_time_ns=EVENT_NS,
        ingest_time_ns=EVENT_NS + 250_000_001,
        native_trade_id="threshold-replay", native_sequence=1,
    )

    first = ingress.ingest(original)
    assert first.status is IngestStatus.BUFFERED
    released = ingress.drain(now_ns=0, force=True)
    assert released[0].status is IngestStatus.ACCEPTED

    duplicate = ingress.ingest(replay)

    assert duplicate.status is IngestStatus.DUPLICATE
    assert duplicate.reason == "DUPLICATE"
    assert duplicate.status is not IngestStatus.QUARANTINED
    assert len(sink.accepted) == 1


def test_same_identity_with_changed_semantic_source_content_is_conflict() -> None:
    ingress, sink, _ = make_ingress()
    ingress.ingest(make_record())

    conflict = ingress.ingest(make_record(payload={
        "price": "101.26", "size": "3", "side": "buy",
    }))

    assert conflict.status is IngestStatus.QUARANTINED
    assert conflict.reason == "QUARANTINED_CONFLICT"
    assert len(sink.accepted) == 1


def test_source_attributes_are_digest_included_and_frozen_after_ack() -> None:
    mapping = InstrumentMapping(
        provider="massive", dataset="stocks-synthetic", venue="XTEST",
        native_symbol="SYNTH", instrument_id="SYNTH-001",
        leviathan_symbol="SYNTH", instrument_type="equity",
        mapping_version="test-v1", tick_size="0.01",
    )
    sink = RecordingSink()
    ingress = NormalizedIngress(
        Normalizer(MappingRegistry((mapping,))), sink,
        clock_ns=lambda: NOW_NS,
        arrival_clock_ns=lambda: 0,
    )
    record = make_record(
        "news", source_record_key="source-attribute-key", native_trade_id=None,
        provider="massive", dataset="stocks-synthetic", venue="XTEST",
        source_attributes={"massive:raw_condition_codes": "synthetic:1,2"},
    )
    changed = replace(
        record,
        source_attributes={"massive:raw_condition_codes": "synthetic:1,3"},
    )

    accepted = ingress.ingest(record)
    conflict = ingress.ingest(changed)

    assert accepted.status is IngestStatus.ACCEPTED
    assert accepted.event.source_attributes["massive:raw_condition_codes"] == "synthetic:1,2"
    assert conflict.status is IngestStatus.QUARANTINED
    assert conflict.reason == "QUARANTINED_CONFLICT"
    with pytest.raises(TypeError):
        setitem(accepted.event.source_attributes, "massive:raw_condition_codes", "changed")


@pytest.mark.parametrize(
    "event_type,overrides",
    [
        ("trade", {"native_trade_id": None}),
        ("book_delta", {"native_sequence": None}),
    ],
)
def test_missing_natural_identity_requires_provider_source_key(
    event_type: str, overrides: dict[str, object],
) -> None:
    ingress, sink, _ = make_ingress()
    record = replace(make_record(event_type), source_record_key=None, **overrides)

    receipt = ingress.ingest(record)

    assert receipt.status is IngestStatus.QUARANTINED
    assert receipt.reason == "NATIVE_RECORD_KEY_REQUIRED"
    assert not sink.attempts


def test_provider_dataset_and_identity_policy_are_namespaced_in_key() -> None:
    other_mapping = InstrumentMapping(
        provider="other-synthetic-feed", dataset="other-synthetic-v1", venue="XTEST",
        native_symbol="SYNTH", instrument_id="SYNTH-001", leviathan_symbol="SYNTH",
        instrument_type="equity", mapping_version="test-v1", tick_size="0.01",
    )
    registry = MappingRegistry((MAPPING, other_mapping))
    normalizer_v1 = Normalizer(registry, identity_policy_version="identity-v1")
    normalizer_v2 = Normalizer(registry, identity_policy_version="identity-v2")
    record = make_record("news", source_record_key="same-native-key", native_trade_id=None)
    other_provider = make_record(
        "news", source_record_key="same-native-key", native_trade_id=None,
        provider="other-synthetic-feed", dataset="other-synthetic-v1",
    )

    first = normalizer_v1.normalize(record, now_ns=NOW_NS)
    policy_variant = normalizer_v2.normalize(record, now_ns=NOW_NS)
    provider_variant = normalizer_v1.normalize(other_provider, now_ns=NOW_NS)

    assert first.idempotency_key != policy_variant.idempotency_key
    assert first.idempotency_key != provider_variant.idempotency_key


@pytest.mark.parametrize(
    "event_type",
    ["book_snapshot", "status", "reference", "corporate_action", "news"],
)
def test_source_record_ref_is_not_a_substitute_for_required_native_identity(
    event_type: str,
) -> None:
    ingress, sink, _ = make_ingress()
    record = replace(make_record(event_type), source_record_key=None)

    receipt = ingress.ingest(record)

    assert receipt.status is IngestStatus.QUARANTINED
    assert receipt.reason == "NATIVE_RECORD_KEY_REQUIRED"
    assert not sink.attempts


def test_massive_quote_requires_provider_native_key() -> None:
    mapping = InstrumentMapping(
        provider="massive", dataset="synthetic", venue="XTEST", native_symbol="SYNTH",
        instrument_id="SYNTH-001", leviathan_symbol="SYNTH", instrument_type="equity",
        mapping_version="test-v1", tick_size="0.01",
    )
    normalizer = Normalizer(MappingRegistry((mapping,)))
    record = make_record(
        "quote", provider="massive", dataset="synthetic", source_record_key=None,
    )

    with pytest.raises(NormalizationError, match="NATIVE_RECORD_KEY_REQUIRED"):
        normalizer.normalize(record, now_ns=NOW_NS)


def test_backpressure_does_not_commit_identity_and_identical_resubmit_reaches_sink() -> None:
    sink = RecordingSink(backpressure_count=1)
    ingress, _, _ = make_ingress(sink=sink)
    record = make_record()
    key = stream_key(record)

    first = ingress.ingest(record)
    assert first.status is IngestStatus.BACKPRESSURE
    assert ingress.committed_count(key) == 0

    retry = ingress.ingest(record)

    assert retry.status is IngestStatus.ACCEPTED
    assert len(sink.attempts) == 2
    assert len(sink.accepted) == 1
    assert ingress.committed_count(key) == 1


def test_backpressure_during_live_drain_returns_retry_ownership_without_redelivery() -> None:
    sink = RecordingSink(backpressure_count=1)
    ingress, _, clocks = make_ingress(
        sink=sink, hot_window_ns=10, hot_max_messages=10,
    )
    record = make_record("trade", source_mode="live")
    key = stream_key(record)

    queued = ingress.ingest(record)
    assert queued.status is IngestStatus.BUFFERED
    clocks["arrival"] = 10
    terminal = ingress.drain(now_ns=10, force=False)
    assert [receipt.status for receipt in terminal] == [IngestStatus.BACKPRESSURE]
    assert ingress.queued_count(key) == 0

    retried = ingress.ingest(record)
    assert retried.status is IngestStatus.ACCEPTED
    assert len(sink.attempts) == 2
    assert len(sink.accepted) == 1


def test_sink_backpressure_holds_head_until_retry_without_duplicate_delivery() -> None:
    sink = RecordingSink(backpressure_count=1)
    ingress, _, clocks = make_ingress(
        sink=sink, hot_window_ns=10, hot_max_messages=10,
    )
    first = make_record(
        source_mode="live", event_time_ns=EVENT_NS + 1,
        source_time_ns=EVENT_NS + 1, exchange_time_ns=EVENT_NS + 1,
        ingest_time_ns=EVENT_NS + 1, native_trade_id="retry-head",
    )
    second = make_record(
        source_mode="live", event_time_ns=EVENT_NS + 2,
        source_time_ns=EVENT_NS + 2, exchange_time_ns=EVENT_NS + 2,
        ingest_time_ns=EVENT_NS + 2, native_trade_id="retry-tail",
    )
    key = stream_key(first)
    assert ingress.ingest(first).status is IngestStatus.BUFFERED
    assert ingress.ingest(second).status is IngestStatus.BUFFERED
    clocks["arrival"] = 10

    blocked = ingress.drain(stream=key, now_ns=10)

    assert len(blocked) == 1
    assert blocked[0].status is IngestStatus.BACKPRESSURE
    assert blocked[0].source == "SINK"
    assert ingress.queued_count(key) == 1
    assert len(sink.attempts) == 1
    assert ingress.drain(stream=key, now_ns=20, force=True) == ()
    assert len(sink.attempts) == 1

    retry = ingress.retry(key)

    assert retry.status is IngestStatus.ACCEPTED
    assert len(sink.attempts) == 2
    assert len(sink.accepted) == 1
    assert sink.accepted[0].idempotency_key == retry.event.idempotency_key
    assert ingress.queued_count(key) == 1
    drained_tail = ingress.drain(stream=key, now_ns=20, force=True)
    assert [receipt.status for receipt in drained_tail] == [IngestStatus.ACCEPTED]
    assert len(sink.attempts) == 3
    assert len(sink.accepted) == 2
    assert [event.idempotency_key for event in sink.accepted] == [
        receipt.event.idempotency_key for receipt in (retry, drained_tail[0])
    ]


def test_repeated_live_submission_while_buffered_does_not_queue_or_deliver_twice() -> None:
    ingress, sink, _ = make_ingress(hot_window_ns=10_000, hot_max_messages=10)
    record = make_record("trade", source_mode="live")
    key = stream_key(record)

    initial = ingress.ingest(record)
    repeated = ingress.ingest(record)

    assert initial.status is IngestStatus.BUFFERED
    assert repeated.status is IngestStatus.BUFFERED
    assert repeated.reason == "ALREADY_BUFFERED"
    assert ingress.queued_count(key) == 1
    assert sink.attempts == []
    delivered = ingress.flush(stream=key)
    assert [receipt.status for receipt in delivered] == [IngestStatus.ACCEPTED]
    assert len(sink.attempts) == len(sink.accepted) == 1


def test_ingest_receipt_cannot_be_forged_by_construction_or_replace() -> None:
    ingress, _, _ = make_ingress()
    buffered = ingress.ingest(make_record(source_mode="live"))
    assert buffered.status is IngestStatus.BUFFERED
    assert is_issued_receipt(buffered) is True
    assert is_issued_receipt(object()) is False

    with pytest.raises(MarketDataValueError) as replaced:
        replace(
            buffered, status=IngestStatus.ACCEPTED,
            reason="SINK_ACK", execution_eligible=True,
        )
    assert replaced.value.code == "UNAUTHORIZED_RECEIPT"

    with pytest.raises(MarketDataValueError) as constructed:
        IngestReceipt(
            status=IngestStatus.ACCEPTED,
            reason="SINK_ACK",
            event=None,
            execution_eligible=True,
        )
    assert constructed.value.code == "UNAUTHORIZED_RECEIPT"

    assert not hasattr(buffered, "_seal")
    captured_receipt_attribute = buffered.status
    with pytest.raises(MarketDataValueError) as copied_seal_replace:
        replace(
            buffered, _issuer=captured_receipt_attribute,
            status=IngestStatus.ACCEPTED, reason="SINK_ACK", sink_count=1,
            execution_eligible=True,
        )
    assert copied_seal_replace.value.code == "UNAUTHORIZED_RECEIPT"

    with pytest.raises(MarketDataValueError) as copied_seal_construct:
        IngestReceipt(
            status=IngestStatus.ACCEPTED,
            reason="SINK_ACK",
            event=buffered.event,
            sink_count=1,
            execution_eligible=True,
            _issuer=captured_receipt_attribute,
        )
    assert copied_seal_construct.value.code == "UNAUTHORIZED_RECEIPT"

    accepted_ingress, _, _ = make_ingress()
    accepted = accepted_ingress.ingest(make_record(native_trade_id="receipt-ack"))
    assert accepted.status is IngestStatus.ACCEPTED
    assert accepted.reason == "SINK_ACK"
    assert accepted.event is not None
    assert accepted.sink_count >= 1
    assert is_issued_receipt(accepted) is True


def test_committed_key_capacity_backpressures_instead_of_silently_evicting() -> None:
    ingress, sink, _ = make_ingress(max_committed_keys=2)
    records = [
        make_record(event_time_ns=EVENT_NS + index, native_trade_id=f"trade-{index}",
                    source_record_ref=f"synthetic://capacity/{index}")
        for index in range(3)
    ]
    key = stream_key(records[0])

    accepted = [ingress.ingest(record) for record in records[:2]]
    exhausted = ingress.ingest(records[2])

    assert [receipt.status for receipt in accepted] == [IngestStatus.ACCEPTED] * 2
    assert exhausted.status is IngestStatus.BACKPRESSURE
    assert exhausted.reason == "DEDUPE_CAPACITY_EXHAUSTED"
    assert exhausted.source == "INGRESS_CAPACITY"
    assert ingress.committed_count(key) == 2
    assert ingress.health(key).unhealthy is True
    assert len(sink.accepted) == 2

    resubmitted = ingress.ingest(records[2])
    assert resubmitted.status is IngestStatus.BACKPRESSURE
    assert resubmitted.source == "INGRESS_CAPACITY"
    assert resubmitted.reason == "DEDUPE_CAPACITY_EXHAUSTED"
    assert len(sink.attempts) == 2
    assert ingress.queued_count(key) == 0


def test_dedupe_window_policy_cannot_be_relaxed_below_24_hours() -> None:
    minimum_window_ns = 24 * 60 * 60 * 1_000_000_000

    with pytest.raises(ValueError) as caught:
        make_ingress(dedupe_window_ns=minimum_window_ns - 1)

    assert type(caught.value).__name__ == "MarketDataValueError"
    assert getattr(caught.value, "code", None) == "POLICY_OUT_OF_BOUNDS"
    assert str(caught.value) == "POLICY_OUT_OF_BOUNDS"


def test_ingress_policy_objects_reject_looser_bounds_and_post_construction_changes() -> None:
    invalid_policies = (
        {"future_tolerance_ms": 1_001},
        {"hot_window_ns": 150_000_001},
        {"hot_max_messages": 501},
        {"correction_window_ns": 2_000_000_001},
        {"max_committed_keys": 50_001},
    )
    for policy in invalid_policies:
        with pytest.raises(MarketDataValueError) as caught:
            make_ingress(**policy)
        assert caught.value.code == "POLICY_OUT_OF_BOUNDS"
        assert str(caught.value) == "POLICY_OUT_OF_BOUNDS"

    normalizer = Normalizer(MappingRegistry((MAPPING,)))
    ingress, _, _ = make_ingress()
    with pytest.raises(MarketDataValueError) as normalizer_mutation:
        normalizer.future_tolerance_ns = 1_001_000_000
    with pytest.raises(MarketDataValueError) as ingress_mutation:
        ingress.dedupe_window_ns = 1
    assert normalizer_mutation.value.code == "POLICY_IMMUTABLE"
    assert ingress_mutation.value.code == "POLICY_IMMUTABLE"


def test_dedupe_window_eviction_is_event_time_bounded_and_restart_is_unproven() -> None:
    day_ns = 24 * 60 * 60 * 1_000_000_000
    ingress, _, _ = make_ingress(max_committed_keys=4)
    records = [
        make_record(event_time_ns=EVENT_NS - day_ns - 1, native_trade_id="old",
                    source_record_ref="synthetic://old"),
        make_record(event_time_ns=EVENT_NS - day_ns, native_trade_id="middle",
                    source_record_ref="synthetic://middle"),
        make_record(event_time_ns=EVENT_NS, native_trade_id="new",
                    source_record_ref="synthetic://new"),
    ]
    key = stream_key(records[0])

    receipts = [ingress.ingest(record) for record in records]
    health = ingress.health(key)

    assert [receipt.status for receipt in receipts] == [IngestStatus.ACCEPTED] * 3
    assert ingress.committed_count(key) == 2
    assert health.dedupe_restart_unproven is True


def test_live_record_beyond_correction_and_dedupe_windows_is_too_late() -> None:
    day_ns = 24 * 60 * 60 * 1_000_000_000
    ingress, sink, _ = make_ingress(correction_window_ns=2)
    recent = make_record(
        source_mode="live", event_time_ns=EVENT_NS + day_ns + 2,
        source_time_ns=EVENT_NS + day_ns + 2,
        exchange_time_ns=EVENT_NS + day_ns + 2,
        ingest_time_ns=EVENT_NS + day_ns + 2, native_trade_id="recent",
    )
    too_old = make_record(
        source_mode="live", event_time_ns=EVENT_NS, source_time_ns=EVENT_NS,
        exchange_time_ns=EVENT_NS, ingest_time_ns=EVENT_NS, native_trade_id="too-old",
    )
    queued = ingress.ingest(recent)
    assert queued.status is IngestStatus.BUFFERED
    ingress.flush(force=True)

    receipt = ingress.ingest(too_old)

    assert receipt.status is IngestStatus.QUARANTINED
    assert receipt.reason == "TOO_LATE"
    assert len(sink.accepted) == 1
    assert ingress.health(stream_key(recent)).late_count == 1


def test_historical_order_uses_declared_event_time_range_not_current_wall_clock() -> None:
    ingress, sink, _ = make_ingress(
        historical_range_ns=(EVENT_NS - 100, EVENT_NS + 100),
    )
    newer = make_record(event_time_ns=EVENT_NS + 50, native_trade_id="newer")
    older = make_record(event_time_ns=EVENT_NS - 50, native_trade_id="older")

    first = ingress.ingest(newer)
    second = ingress.ingest(older)

    assert first.status is IngestStatus.ACCEPTED
    assert second.status is IngestStatus.ACCEPTED
    assert second.correction is True
    assert second.event.event_time_ns == EVENT_NS - 50
    assert second.event.exchange_time_ns == EVENT_NS - 4
    assert second.execution_eligible is False
    assert len(sink.accepted) == 2


def test_historical_record_outside_declared_range_is_quarantined() -> None:
    ingress, sink, _ = make_ingress(
        historical_range_ns=(EVENT_NS - 10, EVENT_NS + 10),
    )

    receipt = ingress.ingest(make_record(event_time_ns=EVENT_NS - 11))

    assert receipt.status is IngestStatus.QUARANTINED
    assert receipt.reason == "OUTSIDE_HISTORICAL_RANGE"
    assert not sink.attempts


def test_sequence_policy_reports_only_proven_contiguous_gaps() -> None:
    contiguous, gap_sink, _ = make_ingress(sequence_policy="contiguous")
    first = contiguous.ingest(make_record(
        native_sequence=10, native_trade_id="seq-10", provider_session_id="session-a",
    ))
    second = contiguous.ingest(make_record(
        native_sequence=13, native_trade_id="seq-13", event_time_ns=EVENT_NS + 1,
        provider_session_id="session-a",
    ))
    gap_key = stream_key(make_record())
    assert first.status is IngestStatus.ACCEPTED
    assert second.event.quality_flags.count("gap_detected") == 1
    assert contiguous.health(gap_key).gap_count == 1
    assert gap_sink.accepted[-1].quality_flags.count("gap_detected") == 1

    noncontiguous, _, _ = make_ingress(
        sequence_policy="monotonic_noncontiguous_session_reset",
    )
    noncontiguous.ingest(make_record(native_sequence=10, native_trade_id="nseq-10"))
    jump = noncontiguous.ingest(make_record(
        native_sequence=13, native_trade_id="nseq-13", event_time_ns=EVENT_NS + 1,
    ))
    assert "gap_detected" not in jump.event.quality_flags


def test_sequence_regression_requires_evidence_for_confirmed_reset() -> None:
    ingress, _, _ = make_ingress(
        sequence_policy="monotonic_noncontiguous_session_reset",
    )
    key = stream_key(make_record())
    accepted = ingress.ingest(make_record(
        native_sequence=10, native_trade_id="session-a-10",
        provider_session_id="session-a",
    ))
    regression = ingress.ingest(make_record(
        native_sequence=9, native_trade_id="session-a-9", event_time_ns=EVENT_NS + 1,
        provider_session_id="session-a",
    ))

    assert accepted.status is IngestStatus.ACCEPTED
    assert regression.status is IngestStatus.QUARANTINED
    assert regression.reason == "SEQUENCE_REGRESSION"
    assert ingress.health(key).sequence_regression_count == 1

    unknown_boundary, _, _ = make_ingress(
        sequence_policy="monotonic_noncontiguous_session_reset",
    )
    unknown_boundary.ingest(make_record(
        native_sequence=10, native_trade_id="unknown-10", provider_session_id=None,
    ))
    unknown = unknown_boundary.ingest(make_record(
        native_sequence=1, native_trade_id="unknown-1", event_time_ns=EVENT_NS + 1,
        provider_session_id="session-b", session_transition_confirmed=False,
    ))
    assert unknown.status is IngestStatus.QUARANTINED
    assert unknown.reason == "SEQUENCE_REGRESSION"

    evidenced, _, _ = make_ingress(
        sequence_policy="monotonic_noncontiguous_session_reset",
    )
    evidenced.ingest(make_record(
        native_sequence=10, native_trade_id="old-session-10",
        provider_session_id="session-a",
    ))
    reset = evidenced.ingest(make_record(
        native_sequence=1, native_trade_id="new-session-1", event_time_ns=EVENT_NS + 1,
        provider_session_id="session-b", session_transition_confirmed=True,
    ))
    assert reset.status is IngestStatus.ACCEPTED
    assert "RESET" in reset.event.quality_flags


def test_missing_native_sequence_is_synthetic_and_cannot_prove_gap_free_delivery() -> None:
    ingress, _, _ = make_ingress(sequence_policy="contiguous")

    receipt = ingress.ingest(make_record(native_sequence=None))

    assert receipt.status is IngestStatus.ACCEPTED
    assert receipt.event.sequence_synthetic is True
    assert "sequence_synthetic" in receipt.event.quality_flags
    assert "gap_detected" not in receipt.event.quality_flags


def test_unknown_sequence_and_confirmed_new_session_do_not_claim_a_gap() -> None:
    ingress, _, _ = make_ingress(sequence_policy="contiguous")
    first = ingress.ingest(make_record(
        native_sequence=10, native_trade_id="known-before-gap",
        provider_session_id="session-a",
    ))
    unknown = ingress.ingest(make_record(
        native_sequence=None, native_trade_id=None,
        source_record_key="missing-sequence-record",
        event_time_ns=EVENT_NS + 1, provider_session_id="session-a",
    ))
    after_unknown = ingress.ingest(make_record(
        native_sequence=13, native_trade_id="known-after-gap",
        event_time_ns=EVENT_NS + 2, provider_session_id="session-a",
    ))
    new_session = ingress.ingest(make_record(
        native_sequence=1, native_trade_id="new-session-first",
        event_time_ns=EVENT_NS + 3, provider_session_id="session-b",
        session_transition_confirmed=True,
    ))

    assert first.status is IngestStatus.ACCEPTED
    assert unknown.status is IngestStatus.ACCEPTED
    assert "UNKNOWN_CONTINUITY" in unknown.event.quality_flags
    assert "gap_detected" not in unknown.event.quality_flags
    assert after_unknown.status is IngestStatus.ACCEPTED
    assert "UNKNOWN_CONTINUITY" in after_unknown.event.quality_flags
    assert "gap_detected" not in after_unknown.event.quality_flags
    assert new_session.status is IngestStatus.ACCEPTED
    assert "RESET" in new_session.event.quality_flags
    assert "UNKNOWN_CONTINUITY" in new_session.event.quality_flags
    assert "gap_detected" not in new_session.event.quality_flags


def test_acked_late_confirmed_session_reset_rebases_next_sequence() -> None:
    ingress, _, clocks = make_ingress(
        hot_window_ns=10,
        sequence_policy="monotonic_noncontiguous_session_reset",
    )
    old_session = make_record(
        source_mode="live", event_time_ns=EVENT_NS + 10,
        source_time_ns=EVENT_NS + 10, exchange_time_ns=EVENT_NS + 10,
        ingest_time_ns=EVENT_NS + 10,
        native_trade_id="reset-base", native_sequence=10,
        provider_session_id="session-a",
    )
    assert ingress.ingest(old_session).status is IngestStatus.BUFFERED
    clocks["arrival"] = 10
    assert ingress.drain(now_ns=10, force=False)[0].status is IngestStatus.ACCEPTED

    reset = ingress.ingest(make_record(
        source_mode="live", event_time_ns=EVENT_NS + 9,
        source_time_ns=EVENT_NS + 10, exchange_time_ns=EVENT_NS + 10,
        ingest_time_ns=EVENT_NS + 10,
        native_trade_id="reset-session-first", native_sequence=1,
        provider_session_id="session-b", session_transition_confirmed=True,
    ))
    following = ingress.ingest(make_record(
        source_mode="live", event_time_ns=EVENT_NS + 11,
        source_time_ns=EVENT_NS + 11, exchange_time_ns=EVENT_NS + 11,
        ingest_time_ns=EVENT_NS + 11,
        native_trade_id="reset-session-second", native_sequence=2,
        provider_session_id="session-b",
    ))
    following_terminal = ingress.flush(stream=stream_key(old_session))

    assert reset.status is IngestStatus.ACCEPTED
    assert reset.correction is True
    assert "RESET" in reset.event.quality_flags
    assert following.status is IngestStatus.BUFFERED
    assert [receipt.status for receipt in following_terminal] == [IngestStatus.ACCEPTED]
    assert following_terminal[0].reason != "SEQUENCE_REGRESSION"
    assert "gap_detected" not in following_terminal[0].event.quality_flags


def test_acked_late_sequence_two_then_three_does_not_claim_gap() -> None:
    ingress, _, clocks = make_ingress(
        hot_window_ns=10, sequence_policy="contiguous",
    )
    first = make_record(
        source_mode="live", event_time_ns=EVENT_NS + 10,
        source_time_ns=EVENT_NS + 10, exchange_time_ns=EVENT_NS + 10,
        ingest_time_ns=EVENT_NS + 10, native_trade_id="session-seq-1",
        native_sequence=1, provider_session_id="session-a",
    )
    assert ingress.ingest(first).status is IngestStatus.BUFFERED
    clocks["arrival"] = 10
    assert ingress.drain(now_ns=10, force=False)[0].status is IngestStatus.ACCEPTED

    late_two = ingress.ingest(make_record(
        source_mode="live", event_time_ns=EVENT_NS + 9,
        source_time_ns=EVENT_NS + 10, exchange_time_ns=EVENT_NS + 10,
        ingest_time_ns=EVENT_NS + 10, native_trade_id="session-seq-2",
        native_sequence=2, provider_session_id="session-a",
        native_provenance={
            "correction": "correction",
            "referenced_native_id": "session-seq-1",
        },
    ))
    three = ingress.ingest(make_record(
        source_mode="live", event_time_ns=EVENT_NS + 11,
        source_time_ns=EVENT_NS + 11, exchange_time_ns=EVENT_NS + 11,
        ingest_time_ns=EVENT_NS + 11, native_trade_id="session-seq-3",
        native_sequence=3, provider_session_id="session-a",
    ))
    three_terminal = ingress.flush(stream=stream_key(first))

    assert late_two.status is IngestStatus.ACCEPTED
    assert late_two.correction is True
    assert "gap_detected" not in late_two.event.quality_flags
    assert three.status is IngestStatus.BUFFERED
    assert [receipt.status for receipt in three_terminal] == [IngestStatus.ACCEPTED]
    assert "gap_detected" not in three_terminal[0].event.quality_flags


def test_old_session_late_correction_does_not_replace_confirmed_active_baseline() -> None:
    ingress, sink, _ = make_ingress(
        sequence_policy="contiguous", hot_window_ns=150_000_000,
    )

    def ack_live(record: VendorRecord) -> IngestReceipt:
        receipt = ingress.ingest(record)
        if receipt.status is IngestStatus.BUFFERED:
            terminal = ingress.flush(stream=stream_key(record))
            assert len(terminal) == 1
            return terminal[0]
        return receipt

    s1_original = make_record(
        source_mode="live", event_time_ns=EVENT_NS + 10,
        source_time_ns=EVENT_NS + 10, exchange_time_ns=EVENT_NS + 10,
        ingest_time_ns=EVENT_NS + 10, native_trade_id="s1-original-10",
        native_sequence=10, provider_session_id="s1",
    )
    s2_reset = make_record(
        source_mode="live", event_time_ns=EVENT_NS + 11,
        source_time_ns=EVENT_NS + 11, exchange_time_ns=EVENT_NS + 11,
        ingest_time_ns=EVENT_NS + 11, native_trade_id="s2-reset-1",
        native_sequence=1, provider_session_id="s2",
        session_transition_confirmed=True,
    )
    s1_late_correction = make_record(
        source_mode="live", event_time_ns=EVENT_NS + 9,
        source_time_ns=EVENT_NS + 12, exchange_time_ns=EVENT_NS + 12,
        ingest_time_ns=EVENT_NS + 12, native_trade_id="s1-correction-9",
        native_sequence=9, provider_session_id="s1",
        native_provenance={
            "correction": "correction",
            "referenced_native_id": "s1-original-10",
            "referenced_native_sequence": 10,
        },
    )
    s2_next = make_record(
        source_mode="live", event_time_ns=EVENT_NS + 12,
        source_time_ns=EVENT_NS + 12, exchange_time_ns=EVENT_NS + 12,
        ingest_time_ns=EVENT_NS + 12, native_trade_id="s2-next-2",
        native_sequence=2, provider_session_id="s2",
    )

    acknowledged = [
        ack_live(s1_original),
        ack_live(s2_reset),
        ack_live(s1_late_correction),
        ack_live(s2_next),
    ]

    assert [receipt.status for receipt in acknowledged] == [
        IngestStatus.ACCEPTED,
        IngestStatus.ACCEPTED,
        IngestStatus.ACCEPTED,
        IngestStatus.ACCEPTED,
    ]
    assert [receipt.reason for receipt in acknowledged] == ["SINK_ACK"] * 4
    assert len(sink.accepted) == 4
    assert [event.native_sequence for event in sink.accepted] == [10, 1, 9, 2]
    assert [event.provider_session_id for event in sink.accepted] == ["s1", "s2", "s1", "s2"]
    assert acknowledged[2].correction is True
    assert acknowledged[2].event.native_provenance.correction == "correction"
    assert acknowledged[2].event.native_provenance.referenced_native_sequence == 10
    assert acknowledged[3].reason == "SINK_ACK"
    assert "gap_detected" not in acknowledged[3].event.quality_flags


def test_late_old_session_correction_is_checked_against_its_own_sequence_max() -> None:
    ingress, sink, _ = make_ingress(
        sequence_policy="contiguous", hot_window_ns=150_000_000,
    )

    def ack_live(record: VendorRecord) -> IngestReceipt:
        receipt = ingress.ingest(record)
        if receipt.status is IngestStatus.BUFFERED:
            terminal = ingress.flush(stream=stream_key(record))
            assert len(terminal) == 1
            return terminal[0]
        return receipt

    assert ack_live(make_record(
        source_mode="live", event_time_ns=EVENT_NS + 10,
        source_time_ns=EVENT_NS + 10, exchange_time_ns=EVENT_NS + 10,
        ingest_time_ns=EVENT_NS + 10, native_trade_id="s1-max-10",
        native_sequence=10, provider_session_id="s1",
    )).status is IngestStatus.ACCEPTED
    assert ack_live(make_record(
        source_mode="live", event_time_ns=EVENT_NS + 11,
        source_time_ns=EVENT_NS + 11, exchange_time_ns=EVENT_NS + 11,
        ingest_time_ns=EVENT_NS + 11, native_trade_id="s2-max-1",
        native_sequence=1, provider_session_id="s2",
        session_transition_confirmed=True,
    )).status is IngestStatus.ACCEPTED
    correction = ack_live(make_record(
        source_mode="live", event_time_ns=EVENT_NS + 9,
        source_time_ns=EVENT_NS + 12, exchange_time_ns=EVENT_NS + 12,
        ingest_time_ns=EVENT_NS + 12, native_trade_id="s1-valid-correction-9",
        native_sequence=9, provider_session_id="s1",
        native_provenance={
            "correction": "correction",
            "referenced_native_id": "s1-max-10",
            "referenced_native_sequence": 10,
        },
    ))

    assert correction.status is IngestStatus.ACCEPTED
    assert correction.correction is True
    unlinked_old_session_regression = ingress.ingest(make_record(
        source_mode="live", event_time_ns=EVENT_NS + 10,
        source_time_ns=EVENT_NS + 12, exchange_time_ns=EVENT_NS + 12,
        ingest_time_ns=EVENT_NS + 12, native_trade_id="s1-unlinked-9",
        native_sequence=9, provider_session_id="s1",
    ))
    next_active_session = ack_live(make_record(
        source_mode="live", event_time_ns=EVENT_NS + 12,
        source_time_ns=EVENT_NS + 12, exchange_time_ns=EVENT_NS + 12,
        ingest_time_ns=EVENT_NS + 12, native_trade_id="s2-next-after-reject-2",
        native_sequence=2, provider_session_id="s2",
    ))

    assert unlinked_old_session_regression.status is IngestStatus.QUARANTINED
    assert unlinked_old_session_regression.reason == "SEQUENCE_REGRESSION"
    assert next_active_session.status is IngestStatus.ACCEPTED
    assert next_active_session.reason == "SINK_ACK"
    assert "gap_detected" not in next_active_session.event.quality_flags
    assert sink.accepted[-1].native_trade_id == "s2-next-after-reject-2"


def test_seeded_late_corrections_and_resets_preserve_sequence_continuity() -> None:
    rng = random.Random(0x4D443031)

    for case in range(12):
        ingress, _, clocks = make_ingress(
            hot_window_ns=10,
            sequence_policy="monotonic_noncontiguous_session_reset",
        )
        base_time = EVENT_NS + 1_000 + case * 10
        old_sequence = rng.randint(20, 200)
        reset_sequence = rng.randint(4, 10)
        original_id = f"property-original-{case}"
        reset_id = f"property-reset-{case}"

        original = make_record(
            source_mode="live", event_time_ns=base_time,
            source_time_ns=base_time, exchange_time_ns=base_time,
            ingest_time_ns=base_time, native_trade_id=original_id,
            native_sequence=old_sequence, provider_session_id=f"old-{case}",
        )
        assert ingress.ingest(original).status is IngestStatus.BUFFERED
        clocks["arrival"] = 10
        assert ingress.drain(now_ns=10, force=False)[0].status is IngestStatus.ACCEPTED

        reset = ingress.ingest(make_record(
            source_mode="live", event_time_ns=base_time - 1,
            source_time_ns=base_time, exchange_time_ns=base_time,
            ingest_time_ns=base_time, native_trade_id=reset_id,
            native_sequence=reset_sequence, provider_session_id=f"new-{case}",
            session_transition_confirmed=True,
        ))
        late_correction = ingress.ingest(make_record(
            source_mode="live", event_time_ns=base_time - 2,
            source_time_ns=base_time, exchange_time_ns=base_time,
            ingest_time_ns=base_time,
            native_trade_id=f"property-correction-{case}",
            native_sequence=reset_sequence - 1,
            provider_session_id=f"new-{case}",
            native_provenance={
                "correction": "correction",
                "referenced_native_id": reset_id,
            },
        ))
        next_sequence = ingress.ingest(make_record(
            source_mode="live", event_time_ns=base_time + 1,
            source_time_ns=base_time + 1, exchange_time_ns=base_time + 1,
            ingest_time_ns=base_time + 1,
            native_trade_id=f"property-next-{case}",
            native_sequence=reset_sequence + 1,
            provider_session_id=f"new-{case}",
        ))
        next_sequence_terminal = ingress.flush(stream=stream_key(original))

        assert reset.status is IngestStatus.ACCEPTED
        assert reset.correction is True
        assert late_correction.status is IngestStatus.ACCEPTED
        assert late_correction.correction is True
        assert next_sequence.status is IngestStatus.BUFFERED
        assert [receipt.status for receipt in next_sequence_terminal] == [
            IngestStatus.ACCEPTED,
        ]
        for receipt in (reset, late_correction, next_sequence_terminal[0]):
            assert "gap_detected" not in receipt.event.quality_flags
            assert receipt.reason != "SEQUENCE_REGRESSION"

        unknown = ingress.ingest(make_record(
            source_mode="live", event_time_ns=base_time + 2,
            source_time_ns=base_time + 2, exchange_time_ns=base_time + 2,
            ingest_time_ns=base_time + 2, native_trade_id=None,
            source_record_key=f"property-unknown-{case}", native_sequence=None,
            provider_session_id=f"new-{case}",
        ))
        after_unknown = ingress.ingest(make_record(
            source_mode="live", event_time_ns=base_time + 3,
            source_time_ns=base_time + 3, exchange_time_ns=base_time + 3,
            ingest_time_ns=base_time + 3,
            native_trade_id=f"property-after-unknown-{case}",
            native_sequence=reset_sequence + 2,
            provider_session_id=f"new-{case}",
        ))
        after_unknown_terminal = ingress.flush(stream=stream_key(original))
        assert unknown.status is IngestStatus.BUFFERED
        assert after_unknown.status is IngestStatus.BUFFERED
        assert [receipt.status for receipt in after_unknown_terminal] == [
            IngestStatus.ACCEPTED, IngestStatus.ACCEPTED,
        ]
        assert "UNKNOWN_CONTINUITY" in after_unknown_terminal[0].event.quality_flags
        assert "gap_detected" not in after_unknown_terminal[1].event.quality_flags


def test_injected_clock_accepts_future_tolerance_boundary_and_rejects_beyond() -> None:
    ingress, sink, _ = make_ingress(future_tolerance_ms=1_000)
    edge = ingress.ingest(make_record(event_time_ns=NOW_NS + 1_000_000_000))
    beyond = ingress.ingest(make_record(
        event_time_ns=NOW_NS + 1_000_000_001, native_trade_id="future-beyond",
    ))

    assert edge.status is IngestStatus.ACCEPTED
    assert beyond.status is IngestStatus.QUARANTINED
    assert beyond.reason == "FUTURE_EVENT_TIME"
    assert len(sink.accepted) == 1


def test_future_skew_ceiling_does_not_ratchet_from_prior_future_event() -> None:
    ingress, sink, _ = make_ingress(future_tolerance_ms=1_000)
    edge = ingress.ingest(make_record(
        event_time_ns=NOW_NS + 1_000_000_000,
        source_time_ns=NOW_NS + 1_000_000_000,
        exchange_time_ns=NOW_NS + 1_000_000_000,
        native_trade_id="absolute-future-edge",
    ))
    chained = ingress.ingest(make_record(
        event_time_ns=NOW_NS + 2_000_000_000,
        source_time_ns=NOW_NS + 2_000_000_000,
        exchange_time_ns=NOW_NS + 2_000_000_000,
        native_trade_id="absolute-future-chained",
    ))

    assert edge.status is IngestStatus.ACCEPTED
    assert chained.status is IngestStatus.QUARANTINED
    assert chained.reason == "FUTURE_EVENT_TIME"
    assert len(sink.accepted) == 1


def test_bar_open_time_beyond_future_skew_is_quarantined() -> None:
    ingress, sink, _ = make_ingress(future_tolerance_ms=1_000)
    record = make_record("bar", payload={
        "interval": "1m", "open_time_ns": NOW_NS + 2_000_000_000,
        "open": "101.00", "high": "102.00", "low": "100.50",
        "close": "101.50", "volume": "10.125",
    })

    receipt = ingress.ingest(record)

    assert receipt.status is IngestStatus.QUARANTINED
    assert receipt.reason == "FUTURE_EVENT_TIME"
    assert not sink.attempts


@pytest.mark.parametrize(
    ("offset", "alert", "blocked"),
    [(2.0, False, False), (2.001, True, False), (10.0, True, False), (10.001, True, True)],
)
def test_node_clock_alert_and_publish_block_thresholds(
    offset: float, alert: bool, blocked: bool,
) -> None:
    ingress, sink, _ = make_ingress()
    ingress.set_trusted_node_clock_offset_ms(offset)

    assert ingress.node_drift_alert is alert
    assert ingress.node_publish_blocked is blocked
    receipt = ingress.ingest(make_record(source_mode="live"))
    if blocked:
        assert receipt.status is IngestStatus.BACKPRESSURE
        assert receipt.reason == "NODE_CLOCK_BLOCK"
        assert not sink.attempts
    else:
        assert receipt.status is IngestStatus.BUFFERED


def test_rising_node_drift_holds_buffered_and_sink_retry_handoffs() -> None:
    buffered_ingress, buffered_sink, _ = make_ingress(hot_window_ns=1_000)
    queued_record = make_record(
        source_mode="live", event_time_ns=EVENT_NS,
        source_time_ns=EVENT_NS, exchange_time_ns=EVENT_NS,
        ingest_time_ns=EVENT_NS, native_trade_id="drift-buffered",
    )
    buffered = buffered_ingress.ingest(queued_record)
    assert buffered.status is IngestStatus.BUFFERED

    buffered_ingress.set_trusted_node_clock_offset_ms(10.001)
    buffered_ingress.drain(now_ns=1_000, stream=stream_key(queued_record), force=True)

    assert not buffered_sink.attempts
    assert not buffered_sink.accepted
    assert buffered_ingress.health(stream_key(queued_record)).queued_count == 1

    retry_sink = RecordingSink(backpressure_count=1)
    retry_ingress, _, _ = make_ingress(sink=retry_sink, hot_window_ns=1_000)
    retry_record = make_record(
        source_mode="live", event_time_ns=EVENT_NS,
        source_time_ns=EVENT_NS, exchange_time_ns=EVENT_NS,
        ingest_time_ns=EVENT_NS, native_trade_id="drift-retry",
    )
    assert retry_ingress.ingest(retry_record).status is IngestStatus.BUFFERED
    blocked_ack = retry_ingress.drain(
        now_ns=1_000, stream=stream_key(retry_record), force=True,
    )
    assert blocked_ack[0].status is IngestStatus.BACKPRESSURE
    assert blocked_ack[0].source == "SINK"
    assert len(retry_sink.attempts) == 1

    retry_ingress.set_trusted_node_clock_offset_ms(10.001)
    held_retry = retry_ingress.retry(stream_key(retry_record))

    assert held_retry.status is IngestStatus.BACKPRESSURE
    assert held_retry.reason == "NODE_CLOCK_BLOCK"
    assert held_retry.source == "INGRESS_CLOCK"
    assert len(retry_sink.attempts) == 1
    assert not retry_sink.accepted


def test_per_event_clock_fallback_preserves_raw_timestamps_and_is_health_visible() -> None:
    ingress, _, _ = make_ingress()
    record = make_record(
        source_mode="live",
        event_time_ns=EVENT_NS,
        source_time_ns=EVENT_NS - 10,
        exchange_time_ns=EVENT_NS + 250_000_001,
        ingest_time_ns=EVENT_NS,
        native_sequence=7,
    )

    receipt = ingress.ingest(record)
    event = receipt.event
    health = ingress.health(stream_key(record))

    assert receipt.status is IngestStatus.BUFFERED
    assert event.event_time_ns == record.source_time_ns
    assert event.source_time_ns == record.source_time_ns
    assert event.exchange_time_ns == record.exchange_time_ns
    assert "clock_adjusted" in event.quality_flags
    assert health.last_event_clock_adjusted is True
    assert receipt.execution_eligible is False


def test_live_event_delta_at_or_below_250ms_does_not_select_clock_fallback() -> None:
    ingress, _, _ = make_ingress()
    record = make_record(
        source_mode="live", event_time_ns=EVENT_NS,
        source_time_ns=EVENT_NS, exchange_time_ns=EVENT_NS + 250_000_000,
        ingest_time_ns=EVENT_NS + 500_000_000,
    )

    receipt = ingress.ingest(record)

    assert receipt.status is IngestStatus.BUFFERED
    assert receipt.event.event_time_ns == EVENT_NS
    assert "clock_adjusted" not in receipt.event.quality_flags


def test_historical_exchange_delta_never_refreshes_or_rewrites_event_time() -> None:
    ingress, _, _ = make_ingress()
    record = make_record(
        source_mode="historical", event_time_ns=EVENT_NS - 10_000_000_000,
        source_time_ns=EVENT_NS - 10_000_000_001,
        exchange_time_ns=EVENT_NS, ingest_time_ns=EVENT_NS + 300_000_000,
    )

    receipt = ingress.ingest(record)

    assert receipt.status is IngestStatus.ACCEPTED
    assert receipt.event.event_time_ns == EVENT_NS - 10_000_000_000
    assert receipt.event.source_time_ns == EVENT_NS - 10_000_000_001
    assert receipt.event.exchange_time_ns == EVENT_NS
    assert "clock_adjusted" not in receipt.event.quality_flags
    assert receipt.execution_eligible is False


def test_live_reorder_waits_until_150ms_then_releases_by_event_time() -> None:
    ingress, sink, clocks = make_ingress(hot_window_ns=150, hot_max_messages=500)
    late_arriving_earlier_event = make_record(
        source_mode="live", event_time_ns=EVENT_NS + 30,
        source_time_ns=EVENT_NS + 30, exchange_time_ns=EVENT_NS + 30,
        ingest_time_ns=EVENT_NS + 30,
        source_record_key="live-30", native_sequence=30,
    )
    earlier_arriving_later_event = make_record(
        source_mode="live", event_time_ns=EVENT_NS + 20,
        source_time_ns=EVENT_NS + 20, exchange_time_ns=EVENT_NS + 20,
        ingest_time_ns=EVENT_NS + 20,
        source_record_key="live-20", native_sequence=20,
    )
    first = ingress.ingest(late_arriving_earlier_event)
    clocks["arrival"] = 149
    second = ingress.ingest(earlier_arriving_later_event)

    assert first.status is IngestStatus.BUFFERED
    assert second.status is IngestStatus.BUFFERED
    assert not sink.accepted
    assert ingress.drain(now_ns=149, force=False) == ()
    released = ingress.drain(now_ns=150, force=False)

    assert [receipt.status for receipt in released] == [
        IngestStatus.ACCEPTED, IngestStatus.ACCEPTED,
    ]
    assert [event.event_time_ns for event in sink.accepted] == [
        EVENT_NS + 20, EVENT_NS + 30,
    ]


def test_500_queued_messages_trigger_reorder_release_before_timer() -> None:
    ingress, sink, _ = make_ingress(hot_window_ns=10_000, hot_max_messages=500)
    records = [
        make_record(
            source_mode="live", event_time_ns=EVENT_NS + event_offset,
            source_time_ns=EVENT_NS + event_offset,
            exchange_time_ns=EVENT_NS + event_offset,
            ingest_time_ns=EVENT_NS + event_offset,
            source_record_key=f"count-{event_offset}",
            native_trade_id=f"count-trade-{event_offset}", native_sequence=event_offset,
            source_record_ref=f"synthetic://count/{event_offset}",
        )
        for event_offset in range(500, 0, -1)
    ]

    initial = [ingress.ingest(record) for record in records[:-1]]
    cap_trigger = ingress.ingest(records[-1])

    assert all(receipt.status is IngestStatus.BUFFERED for receipt in initial)
    assert cap_trigger.status is IngestStatus.BUFFERED
    assert len(cap_trigger.drained_receipts) == 500
    assert all(receipt.status is IngestStatus.ACCEPTED
               for receipt in cap_trigger.drained_receipts)
    assert [event.event_time_ns for event in sink.accepted] == [
        EVENT_NS + event_offset for event_offset in range(1, 501)
    ]


def test_live_late_correction_window_is_distinct_from_too_late_quarantine() -> None:
    ingress, _, clocks = make_ingress(
        correction_window_ns=2_000_000_000, hot_window_ns=10,
        sequence_policy="monotonic_noncontiguous_session_reset",
    )
    newest = make_record(
        source_mode="live", event_time_ns=EVENT_NS + 10,
        source_time_ns=EVENT_NS + 10, exchange_time_ns=EVENT_NS + 10,
        ingest_time_ns=EVENT_NS + 10,
        native_trade_id="original-trade", source_record_key="live-newest",
        native_sequence=10, provider_session_id="session-a",
    )
    assert ingress.ingest(newest).status is IngestStatus.BUFFERED
    clocks["arrival"] = 10
    assert ingress.drain(now_ns=10, force=False)[0].status is IngestStatus.ACCEPTED

    within = ingress.ingest(make_record(
        source_mode="live", event_time_ns=EVENT_NS + 8,
        source_time_ns=EVENT_NS + 10, exchange_time_ns=EVENT_NS + 10,
        ingest_time_ns=EVENT_NS + 10,
        native_trade_id="correction-trade", source_record_key="live-correction",
        native_sequence=8, provider_session_id="session-a",
        native_provenance={
            "correction": "correction",
            "referenced_native_id": "original-trade",
            "referenced_native_sequence": 10,
        },
    ))
    too_late = ingress.ingest(make_record(
        source_mode="live", event_time_ns=EVENT_NS + 10 - 2_000_000_001,
        source_time_ns=EVENT_NS + 10, exchange_time_ns=EVENT_NS + 10,
        ingest_time_ns=EVENT_NS + 10,
        source_record_key="live-too-late", native_trade_id=None,
        native_sequence=None, provider_session_id="session-a",
    ))

    assert within.status is IngestStatus.ACCEPTED
    assert within.correction is True
    assert "late_correction" in within.event.quality_flags
    assert too_late.status is IngestStatus.QUARANTINED
    assert too_late.reason == "TOO_LATE"
    assert ingress.health(stream_key(newest)).late_count == 2


@pytest.mark.parametrize("reference_kind", ["native_id", "sequence"])
def test_late_lower_sequence_requires_matching_acknowledged_correction_lineage(
    reference_kind: str,
) -> None:
    ingress, _, clocks = make_ingress(
        correction_window_ns=2_000_000_000, hot_window_ns=10,
        sequence_policy="monotonic_noncontiguous_session_reset",
    )
    original = make_record(
        source_mode="live", event_time_ns=EVENT_NS + 10,
        source_time_ns=EVENT_NS + 10, exchange_time_ns=EVENT_NS + 10,
        ingest_time_ns=EVENT_NS + 10,
        native_trade_id="lineage-original", native_sequence=10,
        provider_session_id="session-a",
    )
    assert ingress.ingest(original).status is IngestStatus.BUFFERED
    clocks["arrival"] = 10
    assert ingress.drain(now_ns=10, force=False)[0].status is IngestStatus.ACCEPTED

    lineage: dict[str, object] = {"correction": "correction"}
    if reference_kind == "native_id":
        lineage["referenced_native_id"] = "lineage-original"
    else:
        lineage["referenced_native_sequence"] = 10
    correction = ingress.ingest(make_record(
        source_mode="live", event_time_ns=EVENT_NS + 8,
        source_time_ns=EVENT_NS + 10, exchange_time_ns=EVENT_NS + 10,
        ingest_time_ns=EVENT_NS + 10,
        native_trade_id=f"lineage-correction-{reference_kind}",
        native_sequence=8, provider_session_id="session-a",
        native_provenance=lineage,
    ))

    assert correction.status is IngestStatus.ACCEPTED
    assert correction.correction is True
    assert correction.event.native_provenance.correction == "correction"
    assert "late_correction" in correction.event.quality_flags


def test_late_lower_sequence_without_lineage_is_sequence_regression() -> None:
    ingress, _, clocks = make_ingress(
        correction_window_ns=2_000_000_000, hot_window_ns=10,
        sequence_policy="monotonic_noncontiguous_session_reset",
    )
    original = make_record(
        source_mode="live", event_time_ns=EVENT_NS + 10,
        source_time_ns=EVENT_NS + 10, exchange_time_ns=EVENT_NS + 10,
        ingest_time_ns=EVENT_NS + 10, native_trade_id="unlinked-original",
        native_sequence=10, provider_session_id="session-a",
    )
    assert ingress.ingest(original).status is IngestStatus.BUFFERED
    clocks["arrival"] = 10
    assert ingress.drain(now_ns=10, force=False)[0].status is IngestStatus.ACCEPTED

    regression = ingress.ingest(make_record(
        source_mode="live", event_time_ns=EVENT_NS + 8,
        source_time_ns=EVENT_NS + 10, exchange_time_ns=EVENT_NS + 10,
        ingest_time_ns=EVENT_NS + 10, native_trade_id="unlinked-regression",
        native_sequence=8, provider_session_id="session-a",
    ))

    assert regression.status is IngestStatus.QUARANTINED
    assert regression.reason == "SEQUENCE_REGRESSION"
    assert regression.correction is False


def test_correction_lineage_must_resolve_id_and_sequence_to_same_original() -> None:
    ingress, _, clocks = make_ingress(
        correction_window_ns=2_000_000_000, hot_window_ns=10,
        sequence_policy="monotonic_noncontiguous_session_reset",
    )
    original = make_record(
        source_mode="live", event_time_ns=EVENT_NS + 10,
        source_time_ns=EVENT_NS + 10, exchange_time_ns=EVENT_NS + 10,
        ingest_time_ns=EVENT_NS + 10, native_trade_id="lineage-conflict-original",
        native_sequence=10, provider_session_id="session-a",
    )
    assert ingress.ingest(original).status is IngestStatus.BUFFERED
    clocks["arrival"] = 10
    assert ingress.drain(now_ns=10, force=False)[0].status is IngestStatus.ACCEPTED

    conflict = ingress.ingest(make_record(
        source_mode="live", event_time_ns=EVENT_NS + 8,
        source_time_ns=EVENT_NS + 10, exchange_time_ns=EVENT_NS + 10,
        ingest_time_ns=EVENT_NS + 10, native_trade_id="lineage-conflict-record",
        native_sequence=8, provider_session_id="session-a",
        native_provenance={
            "correction": "correction",
            "referenced_native_id": "lineage-conflict-original",
            "referenced_native_sequence": 9,
        },
    ))

    assert conflict.status is IngestStatus.QUARANTINED
    assert conflict.reason == "CORRECTION_LINEAGE_CONFLICT"


def test_matched_late_correction_beyond_window_is_late_correction_quarantine() -> None:
    ingress, _, clocks = make_ingress(
        correction_window_ns=2_000_000_000, hot_window_ns=10,
        sequence_policy="monotonic_noncontiguous_session_reset",
    )
    original = make_record(
        source_mode="live", event_time_ns=EVENT_NS + 10,
        source_time_ns=EVENT_NS + 10, exchange_time_ns=EVENT_NS + 10,
        ingest_time_ns=EVENT_NS + 10, native_trade_id="too-late-original",
        native_sequence=10, provider_session_id="session-a",
    )
    assert ingress.ingest(original).status is IngestStatus.BUFFERED
    clocks["arrival"] = 10
    assert ingress.drain(now_ns=10, force=False)[0].status is IngestStatus.ACCEPTED

    too_late = ingress.ingest(make_record(
        source_mode="live", event_time_ns=EVENT_NS + 7,
        source_time_ns=EVENT_NS + 10 + 2_000_000_001,
        exchange_time_ns=EVENT_NS + 10 + 2_000_000_001,
        ingest_time_ns=EVENT_NS + 10 + 2_000_000_001,
        native_trade_id="too-late-correction",
        native_sequence=7, provider_session_id="session-a",
        native_provenance={
            "correction": "correction",
            "referenced_native_id": "too-late-original",
        },
    ))

    assert too_late.status is IngestStatus.QUARANTINED
    assert too_late.reason == "LATE_CORRECTION"


def test_health_exposes_queue_pressure_gaps_late_count_and_restart_limit() -> None:
    ingress, _, clocks = make_ingress(
        sequence_policy="contiguous", hot_window_ns=1_000, hot_max_messages=10,
    )
    record = make_record(source_mode="live", native_sequence=1)
    ingress.ingest(record)
    queued = ingress.health(stream_key(record))
    assert queued.queued_count == 1
    assert queued.queue_pressure == pytest.approx(0.1)
    clocks["arrival"] = 1_000
    ingress.drain(now_ns=1_000, force=False)
    assert isinstance(ingress.health(stream_key(record)), SourceHealthSnapshot)
    assert ingress.health(stream_key(record)).dedupe_restart_unproven is True
