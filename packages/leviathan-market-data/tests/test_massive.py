"""Independent contract acceptance for the offline Massive historical adapter.

Requirement-to-case matrix (the contract, not adapter internals, is the oracle):
* Request boundary: exact HTTPS route, ASCII ticker/range/limit validation, one GET,
  ascending bounded query, no redirect, retry, pagination, or credential query key.
* Credential/error boundary: exact development CredentialRef, Bearer-only auth,
  external quote entitlement gate, allowlisted failures, no body/secret/traceback echo.
* Trade semantics: exact Decimal and tick conversion, UTC timestamp provenance,
  decimal_size, caller-pinned listing venue, ticker/exchange/TRF/id/correction
  identity, conditions, conflicts.
* Quote semantics: participant/SIP/TRF provenance, distinct bid/ask fields, nullable
  absent side, session/ticker/sequence identity, noncontiguous sequence, confirmed reset,
  regression and unknown session quarantine, secondary quote-tuple checks.
* Operational bounds: response/line/record caps, historical noneligibility, and
  backpressure followed by resubmission of the same immutable VendorRecord.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from leviathan_market_data.ingress import IngestStatus, NormalizedIngress, SinkAck
from leviathan_market_data.normalization import Normalizer
from leviathan_market_data.providers.massive import (
    InstrumentBindingV1,
    MassiveAdapterError,
    MassiveHTTPResponse,
    MassiveReadSpec,
    MassiveStocksHistoricalAdapter,
    SessionResolution,
)
from leviathan_market_data.schema import QuotePayload, TradePayload
from leviathan_market_data.symbology import InstrumentMapping, MappingRegistry
from leviathan_vault.client import CredentialRef

_FIXTURES = Path(__file__).parent / "fixtures" / "massive"
_START = datetime(2026, 10, 6, 14, 30, tzinfo=UTC)
_END = _START + timedelta(minutes=1)
_NOW_NS = 1_791_297_000_000_000_000
_SECRET = "q7!Xm2@Vr9#Lp4$Kz8^Bw5&"
_BODY_MARKER = "synthetic-vendor-error-body-marker-71c2"
_ERROR_CODES = {
    "AUTH_DENIED",
    "ENTITLEMENT_DENIED",
    "HTTP_STATUS",
    "INSTRUMENT_BINDING_MISMATCH",
    "TIMEOUT",
    "OVERSIZE",
    "OUTSIDE_MAPPING_VALIDITY",
    "PROVIDER_ORDER_VIOLATION",
    "REDIRECT_DENIED",
    "MALFORMED_RECORD",
}


def _spec(
    channel: str = "trades",
    *,
    ticker: str = "AAPL",
    start: datetime = _START,
    end: datetime = _END,
    limit: int = 10,
    mapping_version: str = "synthetic-map-v1",
    listing_venue: str = "XNAS",
    binding_valid_from_ns: int = _NOW_NS - 1_000,
    binding_valid_to_ns: int = _NOW_NS + 1_000_000,
    stable_instrument_id: str | None = None,
    quote_entitlement_expected: bool = True,
) -> MassiveReadSpec:
    return MassiveReadSpec(
        ticker=ticker,
        channel=channel,  # type: ignore[arg-type]
        start=start,
        end=end,
        limit=limit,
        mapping_version=mapping_version,
        listing_venue=listing_venue,
        instrument_binding=InstrumentBindingV1(
            listing_venue=listing_venue,
            ticker=ticker,
            valid_from_ns=binding_valid_from_ns,
            valid_to_ns=binding_valid_to_ns,
            stable_instrument_id=stable_instrument_id,
        ),
        quote_entitlement_expected=quote_entitlement_expected,
    )


def _response(body: bytes, *, status: int = 200, headers: Mapping[str, str] | None = None):
    return MassiveHTTPResponse(
        status_code=status,
        headers=headers or {"content-type": "application/json"},
        body=body,
    )


class _Transport:
    def __init__(self, *responses: MassiveHTTPResponse | Exception) -> None:
        self.responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    def get(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        params: Mapping[str, object],
        connect_timeout_s: float,
        read_timeout_s: float,
        total_timeout_s: float,
        allow_redirects: bool,
    ) -> MassiveHTTPResponse:
        self.calls.append(
            {
                "url": url,
                "headers": dict(headers),
                "params": dict(params),
                "connect_timeout_s": connect_timeout_s,
                "read_timeout_s": read_timeout_s,
                "total_timeout_s": total_timeout_s,
                "allow_redirects": allow_redirects,
            }
        )
        if not self.responses:
            raise AssertionError("unexpected additional transport request")
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class _Credentials:
    def __init__(self, secret: str = _SECRET) -> None:
        self.references: list[CredentialRef] = []
        self.secret = secret

    def __call__(self, reference: CredentialRef) -> str:
        self.references.append(reference)
        return self.secret


class _Sessions:
    def __init__(self, *resolutions: SessionResolution | None) -> None:
        self.resolutions = list(resolutions)
        self.calls: list[dict[str, object]] = []

    def resolve(
        self,
        *,
        ticker: str,
        venue: str,
        event_time_ns: int,
        sequence_number: int,
        previous_session_id: str | None,
    ) -> SessionResolution | None:
        self.calls.append(
            {
                "ticker": ticker,
                "venue": venue,
                "event_time_ns": event_time_ns,
                "sequence_number": sequence_number,
                "previous_session_id": previous_session_id,
            }
        )
        if self.resolutions:
            return self.resolutions.pop(0)
        return SessionResolution(
            provider_session_id="synthetic-session-2026-10-06",
            transition_confirmed=False,
            venue=venue,
        )


def _mapping_registry() -> MappingRegistry:
    return MappingRegistry(
        (
            InstrumentMapping(
                provider="massive",
                dataset="stocks-trades-v1",
                venue="XNAS",
                native_symbol="AAPL",
                instrument_id="synthetic-instrument-aapl",
                leviathan_symbol="NASDAQ:AAPL:STOCK",
                instrument_type="equity",
                mapping_version="synthetic-map-v1",
                tick_size="0.05",
            ),
            InstrumentMapping(
                provider="massive",
                dataset="stocks-quotes-v1",
                venue="XNAS",
                native_symbol="AAPL",
                instrument_id="synthetic-instrument-aapl",
                leviathan_symbol="NASDAQ:AAPL:STOCK",
                instrument_type="equity",
                mapping_version="synthetic-map-v1",
                tick_size="0.01",
            ),
        )
    )


def _adapter(
    *responses: MassiveHTTPResponse | Exception,
    sessions: _Sessions | None = None,
    clock_ns=lambda: _NOW_NS,
    mapping_registry: MappingRegistry | None = None,
    credential_secret: str = _SECRET,
) -> tuple[MassiveStocksHistoricalAdapter, _Transport, _Credentials, _Sessions]:
    transport = _Transport(*responses)
    credentials = _Credentials(secret=credential_secret)
    session_resolver = sessions or _Sessions()
    adapter = MassiveStocksHistoricalAdapter(
        transport=transport,
        credential_resolver=credentials,
        mapping_registry=mapping_registry or _mapping_registry(),
        session_resolver=session_resolver,
        clock_ns=clock_ns,
    )
    return adapter, transport, credentials, session_resolver


def _fixture(name: str) -> bytes:
    return (_FIXTURES / name).read_bytes()


def _body(results: list[dict[str, object]], **extra: object) -> bytes:
    return json.dumps({"status": "OK", "results": results, **extra}, separators=(",", ":")).encode()


def _trade(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "ticker": "AAPL",
        "sip_timestamp": _NOW_NS + 123,
        "participant_timestamp": _NOW_NS,
        "price": 123.4500,
        "size": 2,
        "decimal_size": 2.500,
        "exchange": 4,
        "conditions": [1],
        "id": "synthetic-native-trade-1",
        "correction": 0,
        "trf_id": None,
    }
    value.update(overrides)
    return value


def _quote(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "ticker": "AAPL",
        "sip_timestamp": _NOW_NS + 123,
        "participant_timestamp": _NOW_NS,
        "sequence_number": 1,
        "bid_exchange": 4,
        "ask_exchange": 7,
        "bid_price": 123.45,
        "ask_price": 123.50,
        "bid_size": 10.0,
        "ask_size": 11.0,
        "trf_timestamp": None,
    }
    value.update(overrides)
    return value


def _assert_failure_is_content_free(result: object, *forbidden: str) -> None:
    code = result.error_code
    assert code is None or code in _ERROR_CODES
    rendered = f"{result!s} {result!r}"
    for value in forbidden:
        assert value not in rendered


def test_trade_request_uses_allowlisted_route_bearer_and_explicit_bounds() -> None:
    adapter, transport, credentials, _ = _adapter(_response(_fixture("synthetic-trades.json")))

    result = adapter.read(_spec())

    assert result.error_code is None
    assert len(transport.calls) == 1
    call = transport.calls[0]
    assert call["url"] == "https://api.massive.com/v3/trades/AAPL"
    assert call["headers"]["Authorization"] == f"Bearer {_SECRET}"
    assert call["allow_redirects"] is False
    assert call["connect_timeout_s"] == 3
    assert call["read_timeout_s"] == 5
    assert call["total_timeout_s"] == 10
    params = call["params"]
    assert "limit" in params and int(params["limit"]) == 10
    assert "apiKey" not in params and "apikey" not in params
    assert "api_key" not in params
    assert all(_SECRET not in str(value) for value in params.values())
    assert credentials.references == [
        CredentialRef(
            provider="massive",
            name="MASSIVE_API_KEY",
            scope="leviathan-ai",
            environment="development",
        )
    ]


def test_minimal_contract_shaped_trade_response_is_accepted() -> None:
    body = _body(
        [
            {
                "id": "t1",
                "ticker": "AAPL",
                "exchange": 1,
                "participant_timestamp": _NOW_NS,
                "sip_timestamp": _NOW_NS + 100,
                "price": 12.35,
                "size": 2,
                "decimal_size": 2.5,
                "conditions": [1],
                "correction": 0,
            }
        ],
        request_id="req-1",
    )
    adapter, _, _, _ = _adapter(_response(body))

    result = adapter.read(_spec())

    assert result.error_code is None
    assert result.request_id == "req-1"
    assert len(result.records) == len(result.events) == 1
    assert result.quarantined_count == 0


def test_parsed_vendor_record_cannot_echo_the_credential() -> None:
    adapter, _, _, _ = _adapter(
        _response(
            _body(
                [_trade(id=_SECRET)],
                request_id="safe-request-id",
            )
        )
    )

    result = adapter.read(_spec())

    assert result.records == () and result.events == ()
    assert result.error_code is None or result.error_code in _ERROR_CODES
    assert _SECRET not in str(result)
    assert _SECRET not in repr(result)


@pytest.mark.parametrize(
    ("secret", "request_id"),
    [
        ("AbcdefghijklmnopXYZ123", "Abcdef"),
        ("prefix-provider-suffixXYZ123456", "provider"),
    ],
)
def test_request_id_credential_fragments_are_rejected_without_echo(
    secret: str, request_id: str
) -> None:
    adapter, _, _, _ = _adapter(
        _response(_body([_trade()], request_id=request_id)),
        credential_secret=secret,
    )

    result = adapter.read(_spec())

    assert result.error_code == "MALFORMED_RECORD"
    assert result.records == () and result.events == ()
    assert result.request_id is None
    _assert_failure_is_content_free(result, secret, request_id)


def test_descending_provider_page_fails_closed_after_ascending_request() -> None:
    response = _body(
        [
            _trade(id="later", participant_timestamp=_NOW_NS + 2),
            _trade(id="earlier", participant_timestamp=_NOW_NS + 1),
        ]
    )
    adapter, transport, _, _ = _adapter(_response(response))

    result = adapter.read(_spec(limit=2))

    assert len(transport.calls) == 1
    params = transport.calls[0]["params"]
    assert int(params["limit"]) == 2
    assert params["sort"] == "timestamp"
    assert params["order"] == "asc"
    assert any("start" in str(value) or "gte" in str(key) for key, value in params.items())
    assert any("end" in str(value) or "lt" in str(key) for key, value in params.items())
    assert result.error_code == "PROVIDER_ORDER_VIOLATION"
    assert result.records == () and result.events == ()
    assert result.quarantined_count >= 1


def test_ascending_provider_page_produces_ascending_normalized_output() -> None:
    response = _body(
        [
            _trade(id="earlier", participant_timestamp=_NOW_NS + 1),
            _trade(id="later", participant_timestamp=_NOW_NS + 2),
        ]
    )
    adapter, transport, _, _ = _adapter(_response(response))

    result = adapter.read(_spec(limit=2))

    assert len(transport.calls) == 1
    assert result.error_code is None
    event_times = [event.event_time_ns for event in result.events]
    assert event_times == sorted(event_times)
    assert len(event_times) == 2


@pytest.mark.parametrize(
    "overrides",
    [
        {"ticker": "AAPL/../../outside"},
        {"start": datetime(2026, 10, 6, 14, 30)},
        {"start": _END, "end": _START},
        {"limit": 0},
        {"limit": 11},
        {"limit": True},
    ],
)
def test_invalid_spec_fails_before_credentials_or_transport(overrides: dict[str, object]) -> None:
    adapter, transport, credentials, sessions = _adapter()
    options: dict[str, object] = dict(overrides)
    with pytest.raises(MassiveAdapterError) as caught:
        adapter.read(_spec(**options))

    assert caught.value.code
    assert transport.calls == []
    assert credentials.references == []
    assert sessions.calls == []
    assert "AAPL/../../outside" not in str(caught.value)


def test_mapping_version_is_required_at_spec_construction() -> None:
    with pytest.raises(TypeError):
        MassiveReadSpec(
            ticker="AAPL",
            channel="trades",
            start=_START,
            end=_END,
            limit=10,
            listing_venue="XNAS",
            quote_entitlement_expected=True,
        )


def test_listing_venue_is_required_at_spec_construction() -> None:
    with pytest.raises(TypeError):
        MassiveReadSpec(
            ticker="AAPL",
            channel="trades",
            start=_START,
            end=_END,
            limit=10,
            mapping_version="synthetic-map-v1",
            instrument_binding=InstrumentBindingV1(
                listing_venue="XNAS",
                ticker="AAPL",
                valid_from_ns=_NOW_NS - 1_000,
                valid_to_ns=_NOW_NS + 1_000_000,
            ),
            quote_entitlement_expected=True,
        )


def test_instrument_binding_is_required_at_spec_construction() -> None:
    with pytest.raises(TypeError):
        MassiveReadSpec(
            ticker="AAPL",
            channel="trades",
            start=_START,
            end=_END,
            limit=10,
            mapping_version="synthetic-map-v1",
            listing_venue="XNAS",
            quote_entitlement_expected=True,
        )


def test_record_before_binding_valid_from_is_quarantined() -> None:
    adapter, _, _, _ = _adapter(_response(_body([_trade()])))

    result = adapter.read(
        _spec(binding_valid_from_ns=_NOW_NS + 1, binding_valid_to_ns=_NOW_NS + 100)
    )

    assert result.error_code == "OUTSIDE_MAPPING_VALIDITY"
    assert result.quarantined_count == 1
    assert result.records == () and result.events == ()


def test_record_at_binding_valid_to_is_outside_exclusive_window() -> None:
    adapter, _, _, _ = _adapter(_response(_body([_trade()])))

    result = adapter.read(_spec(binding_valid_from_ns=_NOW_NS - 100, binding_valid_to_ns=_NOW_NS))

    assert result.error_code == "OUTSIDE_MAPPING_VALIDITY"
    assert result.quarantined_count == 1
    assert result.records == () and result.events == ()


def test_record_at_binding_valid_from_is_inside_inclusive_window() -> None:
    adapter, _, _, _ = _adapter(_response(_body([_trade()])))

    result = adapter.read(_spec(binding_valid_from_ns=_NOW_NS, binding_valid_to_ns=_NOW_NS + 1))

    assert result.error_code is None
    assert result.quarantined_count == 0
    assert len(result.records) == len(result.events) == 1


def test_stable_identifier_mismatch_is_quarantined() -> None:
    adapter, _, _, _ = _adapter(
        _response(_body([_trade(composite_figi="SYNTHETIC-FIGI-OTHER")])),
    )

    result = adapter.read(_spec(stable_instrument_id="SYNTHETIC-FIGI-EXPECTED"))

    assert result.error_code == "INSTRUMENT_BINDING_MISMATCH"
    assert result.quarantined_count == 1
    assert result.records == () and result.events == ()
    assert "SYNTHETIC-FIGI-OTHER" not in repr(result)


def test_listing_venue_pins_mapping_while_provider_exchange_stays_native() -> None:
    venue_mapping = InstrumentMapping(
        provider="massive",
        dataset="stocks-trades-v1",
        venue="XNYS",
        native_symbol="AAPL",
        instrument_id="synthetic-instrument-xnys",
        leviathan_symbol="NYSE:AAPL:STOCK",
        instrument_type="equity",
        mapping_version="synthetic-map-v1",
        tick_size="0.01",
    )
    adapter, _, _, resolver = _adapter(
        _response(_body([_trade(exchange=1)])),
        mapping_registry=MappingRegistry((venue_mapping,)),
    )

    result = adapter.read(_spec(listing_venue="XNYS"))

    assert result.error_code is None
    assert len(result.records) == len(result.events) == 1
    assert resolver.calls[0]["venue"] == "XNYS"
    assert result.records[0].native_provenance["native_exchange_id"] == 1


def test_missing_versioned_instrument_mapping_returns_content_free_gate() -> None:
    transport = _Transport(_response(_fixture("synthetic-trades.json")))
    credentials = _Credentials()
    adapter = MassiveStocksHistoricalAdapter(
        transport=transport,
        credential_resolver=credentials,
        mapping_registry=MappingRegistry(()),
        session_resolver=_Sessions(),
        clock_ns=lambda: _NOW_NS,
    )

    result = adapter.read(_spec())

    assert result.error_code == "UNMAPPED_INSTRUMENT"
    assert result.records == () and result.events == ()
    assert result.external_gate is False
    assert len(transport.calls) == 1
    assert len(credentials.references) == 1


def test_mapping_version_mismatch_does_not_select_another_mapping_revision() -> None:
    adapter, transport, credentials, _ = _adapter(
        _response(_fixture("synthetic-trades.json")),
    )

    result = adapter.read(_spec(mapping_version="stale-map-v0"))

    assert result.error_code == "UNMAPPED_INSTRUMENT"
    assert result.records == () and result.events == ()
    assert result.external_gate is False
    assert len(transport.calls) == 1
    assert len(credentials.references) == 1


def test_response_request_id_is_transport_only_for_semantic_identity() -> None:
    body_a = _body([_trade()], request_id="synthetic-request-A")
    body_b = _body([_trade()], request_id="synthetic-request-B")
    first, _, _, _ = _adapter(_response(body_a))
    second, _, _, _ = _adapter(_response(body_b))

    result_a = first.read(_spec())
    result_b = second.read(_spec())

    assert result_a.request_id == "synthetic-request-A"
    assert result_b.request_id == "synthetic-request-B"
    assert result_a.records[0].source_record_key == result_b.records[0].source_record_key
    assert result_a.events[0].idempotency_key == result_b.events[0].idempotency_key


def test_request_id_containing_actual_credential_fragment_is_rejected_without_echo() -> None:
    credential = "AbcdefghijklmnopXYZ123"
    adapter, transport, credentials, _ = _adapter(
        _response(_body([_trade()], request_id="Abcdefgh")),
        credential_secret=credential,
    )

    result = adapter.read(_spec())

    assert result.records == () and result.events == ()
    assert result.request_id != "Abcdefgh"
    assert result.error_code is None or result.error_code in _ERROR_CODES
    assert len(transport.calls) == 1
    assert len(credentials.references) == 1
    _assert_failure_is_content_free(result, credential, "Abcdefgh")


def test_trade_decimal_timestamp_and_native_provenance_are_exact() -> None:
    adapter, _, _, _ = _adapter(_response(_fixture("synthetic-trades.json")))

    result = adapter.read(_spec())

    assert len(result.records) == len(result.events) == 1
    record = result.records[0]
    event = result.events[0]
    assert event.source_mode == "historical"
    assert event.event_time_ns == _NOW_NS
    assert event.source_time_ns == _NOW_NS + 123
    assert event.exchange_time_ns == _NOW_NS
    assert event.ingest_time_ns == _NOW_NS
    assert record.provenance_timestamps["participant"] == _NOW_NS
    assert record.provenance_timestamps["sip"] == _NOW_NS + 123
    assert record.provenance_timestamps["trf"] is None
    assert isinstance(event.payload, TradePayload)
    assert event.payload.price.value == "123.45"
    assert event.payload.price.price_ticks == 2469
    assert event.payload.size == "2.5"
    assert event.native_trade_id == "synthetic-trade-001"
    assert record.native_provenance["trf_id"] is None
    assert record.native_provenance["trade_conditions"] == ("massive:1",)
    assert event.idempotency_key
    assert result.quarantined_count == 0


def test_trade_identity_separates_exchange_trf_and_correction_namespaces() -> None:
    records = [
        _trade(exchange=4, trf_id=None, correction=0),
        _trade(exchange=7, trf_id=None, correction=0),
        _trade(exchange=4, trf_id="synthetic-trf-9", correction=0),
        _trade(exchange=4, trf_id=None, correction=1),
    ]
    adapter, _, _, _ = _adapter(_response(_body(records)))

    result = adapter.read(_spec())

    assert len(result.records) == 4
    keys = {record.source_record_key for record in result.records}
    assert len(keys) == 4
    assert {record.native_trade_id for record in result.records} == {"synthetic-native-trade-1"}
    assert {record.native_provenance["native_exchange_id"] for record in result.records} == {4, 7}
    assert {record.native_provenance["trf_id"] for record in result.records} == {
        None,
        "synthetic-trf-9",
    }
    assert {record.native_provenance["correction"] for record in result.records} >= {
        "none",
        "correction",
    }


def test_conflicting_trade_content_under_one_revision_is_quarantined() -> None:
    adapter, _, _, _ = _adapter(
        _response(
            _body(
                [
                    _trade(price=123.45),
                    _trade(price=123.46),
                ]
            )
        )
    )

    result = adapter.read(_spec())

    assert result.quarantined_count == 1
    assert len(result.records) == 1
    assert len(result.events) == 1


def test_decimal_price_and_ticks_follow_exact_versioned_tick_conversion() -> None:
    mapping = InstrumentMapping(
        provider="massive",
        dataset="stocks-trades-v1",
        venue="XNAS",
        native_symbol="AAPL",
        instrument_id="synthetic-instrument-aapl",
        leviathan_symbol="NASDAQ:AAPL:STOCK",
        instrument_type="equity",
        mapping_version="synthetic-map-v1",
        tick_size="0.01",
    )
    adapter, _, _, _ = _adapter(
        _response(_body([_trade(price=123.46)])),
        mapping_registry=MappingRegistry((mapping,)),
    )

    result = adapter.read(_spec())

    assert result.quarantined_count == 0
    assert result.events[0].payload.price.value == "123.46"
    assert result.events[0].payload.price.price_ticks == 12346


def test_quotes_keep_side_exchange_and_all_native_timestamp_roles() -> None:
    adapter, _, _, resolver = _adapter(
        _response(_fixture("synthetic-quotes.json")),
    )

    result = adapter.read(_spec("quotes"))

    assert len(result.events) == 3
    first = result.events[0]
    assert isinstance(first.payload, QuotePayload)
    assert first.payload.bid_exchange == "4"
    assert first.payload.ask_exchange == "7"
    assert first.payload.bid_price is not None and first.payload.ask_price is not None
    assert first.payload.bid_price.value == "123.45"
    assert first.payload.ask_price.value == "123.46"
    assert first.provenance_timestamps.participant == _NOW_NS
    assert first.provenance_timestamps.sip == _NOW_NS + 1_000
    assert first.provenance_timestamps.trf is None
    assert first.provider_session_id == "synthetic-session-2026-10-06"
    assert len(resolver.calls) == 3
    assert all(call["venue"] == "XNAS" for call in resolver.calls)


def test_quote_sequence_jump_1_2_6_is_not_a_gap() -> None:
    adapter, _, _, _ = _adapter(_response(_fixture("synthetic-quotes.json")))

    result = adapter.read(_spec("quotes"))

    assert [record.native_sequence for record in result.records] == [1, 2, 6]
    assert result.quarantined_count == 0
    assert all("gap_detected" not in event.quality_flags for event in result.events)


def test_quote_native_identity_keeps_same_secondary_tuple_at_distinct_sequences() -> None:
    duplicate_tuple = _quote(sequence_number=2)
    first_tuple = _quote(sequence_number=1)
    adapter, _, _, _ = _adapter(_response(_body([first_tuple, duplicate_tuple])))

    result = adapter.read(_spec("quotes"))

    assert len(result.records) == 2
    assert result.records[0].source_record_key != result.records[1].source_record_key
    assert result.events[0].idempotency_key != result.events[1].idempotency_key


def test_quote_sequence_regression_within_confirmed_session_is_quarantined() -> None:
    same_session = SessionResolution(
        provider_session_id="synthetic-session-a",
        transition_confirmed=False,
        venue="XNAS",
    )
    adapter, _, _, _ = _adapter(
        _response(
            _body(
                [
                    _quote(sequence_number=6, participant_timestamp=_NOW_NS),
                    _quote(sequence_number=5, participant_timestamp=_NOW_NS + 1),
                ]
            )
        ),
        sessions=_Sessions(same_session, same_session),
    )

    result = adapter.read(_spec("quotes"))

    assert result.quarantined_count == 1
    assert len(result.records) == 1


def test_quote_reset_requires_resolver_confirmed_session_transition() -> None:
    adapter, _, _, _ = _adapter(
        _response(
            _body(
                [
                    _quote(sequence_number=6),
                    _quote(sequence_number=1, participant_timestamp=_NOW_NS + 1),
                ]
            )
        ),
        sessions=_Sessions(
            SessionResolution("synthetic-session-old", False, "XNAS"),
            SessionResolution("synthetic-session-new", True, "XNAS"),
        ),
    )

    result = adapter.read(_spec("quotes"))

    assert result.quarantined_count == 0
    assert [record.provider_session_id for record in result.records] == [
        "synthetic-session-old",
        "synthetic-session-new",
    ]
    assert result.records[1].session_transition_confirmed is True


def test_unknown_quote_session_boundary_is_quarantined() -> None:
    adapter, _, _, _ = _adapter(
        _response(_body([_quote()])),
        sessions=_Sessions(None),
    )

    result = adapter.read(_spec("quotes"))

    assert result.quarantined_count == 1
    assert result.records == ()
    assert result.events == ()


def test_absent_quote_side_is_null_with_no_cross_side_fill() -> None:
    adapter, _, _, _ = _adapter(
        _response(
            _body(
                [
                    _quote(
                        ask_exchange=None,
                        ask_price=None,
                        ask_size=None,
                    )
                ]
            )
        )
    )

    result = adapter.read(_spec("quotes"))

    quote = result.events[0].payload
    assert isinstance(quote, QuotePayload)
    assert quote.bid_present is True
    assert quote.ask_present is False
    assert quote.ask_exchange is None
    assert quote.ask_price is None
    assert quote.ask_size is None
    assert quote.bid_price is not None and quote.bid_price.value == "123.45"
    assert quote.bid_size == "10"


def test_missing_participant_timestamp_is_unknown_not_local_receipt_time() -> None:
    adapter, _, _, _ = _adapter(_response(_body([_quote(participant_timestamp=None)])))

    result = adapter.read(_spec("quotes"))

    record = result.records[0]
    event = result.events[0]
    assert record.provenance_timestamps["participant"] is None
    assert event.exchange_time_ns is None
    assert event.received_time_ns == _NOW_NS
    assert event.exchange_time_ns != event.received_time_ns
    assert record.quality_flags


def test_quote_trf_timestamp_is_retained_as_source_provenance() -> None:
    adapter, _, _, _ = _adapter(_response(_body([_quote(trf_timestamp=_NOW_NS + 77)])))

    result = adapter.read(_spec("quotes"))

    assert result.records[0].provenance_timestamps["trf"] == _NOW_NS + 77


def test_quote_entitlement_denial_is_external_gate_not_empty_success() -> None:
    body = json.dumps({"error": _BODY_MARKER, "detail": _SECRET}).encode()
    adapter, transport, _, _ = _adapter(_response(body, status=403))

    result = adapter.read(_spec("quotes", quote_entitlement_expected=True))

    assert result.external_gate is True
    assert result.error_code == "ENTITLEMENT_DENIED"
    assert result.records == () and result.events == ()
    assert len(transport.calls) == 1
    _assert_failure_is_content_free(result, _SECRET, _BODY_MARKER)


def test_quote_gate_without_expected_entitlement_precedes_credentials_and_transport() -> None:
    adapter, transport, credentials, _ = _adapter()

    result = adapter.read(_spec("quotes", quote_entitlement_expected=False))

    assert result.external_gate is True
    assert result.error_code == "ENTITLEMENT_DENIED"
    assert result.records == () and result.events == ()
    assert credentials.references == []
    assert transport.calls == []


@pytest.mark.parametrize(
    ("status", "expected"),
    [(401, "AUTH_DENIED"), (429, "HTTP_STATUS"), (500, "HTTP_STATUS")],
)
def test_http_failures_are_allowlisted_and_do_not_echo_vendor_body(
    status: int,
    expected: str,
) -> None:
    body = json.dumps({"message": _BODY_MARKER, "token": _SECRET}).encode()
    adapter, _, _, _ = _adapter(_response(body, status=status))

    result = adapter.read(_spec())

    assert result.error_code == expected
    assert result.external_gate is (status == 401)
    _assert_failure_is_content_free(result, _SECRET, _BODY_MARKER)


def test_redirect_is_denied_without_following_or_forwarding_credentials() -> None:
    adapter, transport, _, _ = _adapter(
        _response(
            b"synthetic redirect body",
            status=302,
            headers={"location": "https://untrusted.invalid/leak"},
        )
    )

    result = adapter.read(_spec())

    assert result.error_code == "REDIRECT_DENIED"
    assert len(transport.calls) == 1
    assert transport.calls[0]["allow_redirects"] is False
    assert transport.calls[0]["url"] == "https://api.massive.com/v3/trades/AAPL"
    assert "untrusted.invalid" not in repr(result)
    assert _SECRET not in repr(result)


def test_transport_exception_is_not_retried_or_echoed() -> None:
    adapter, transport, _, _ = _adapter(TimeoutError(f"{_SECRET} {_BODY_MARKER}"))

    result = adapter.read(_spec())

    assert result.error_code == "TIMEOUT"
    assert len(transport.calls) == 1
    _assert_failure_is_content_free(result, _SECRET, _BODY_MARKER)


@pytest.mark.parametrize(
    "body",
    [
        b"not-json " + _BODY_MARKER.encode(),
        _body([_trade(price="not-a-decimal")]),
    ],
)
def test_malformed_vendor_data_is_quarantined_without_content_echo(body: bytes) -> None:
    adapter, _, _, _ = _adapter(_response(body))

    result = adapter.read(_spec())

    assert result.error_code in {None, "MALFORMED_RECORD"}
    if result.error_code == "MALFORMED_RECORD":
        assert result.records == () and result.events == ()
    else:
        assert result.quarantined_count >= 1
    if result.error_code is not None:
        _assert_failure_is_content_free(result, _BODY_MARKER)


def test_provider_ticker_mismatch_is_a_binding_error() -> None:
    adapter, _, _, _ = _adapter(_response(_body([_trade(ticker="MSFT")])))

    result = adapter.read(_spec())

    assert result.error_code == "INSTRUMENT_BINDING_MISMATCH"
    assert result.quarantined_count == 1
    assert result.records == () and result.events == ()


def test_oversized_response_is_rejected_before_json_parse() -> None:
    body = b"{" + b" " * (1024 * 1024) + _SECRET.encode()
    adapter, transport, _, _ = _adapter(_response(body))

    result = adapter.read(_spec())

    assert result.error_code == "OVERSIZE"
    assert len(transport.calls) == 1
    _assert_failure_is_content_free(result, _SECRET)


def test_oversized_line_is_rejected() -> None:
    body = _body([_trade(conditions=[1], note="x" * (10 * 1024))])
    adapter, _, _, _ = _adapter(_response(body))

    result = adapter.read(_spec())

    assert result.error_code == "OVERSIZE"
    assert result.records == ()


def test_more_than_ten_records_is_rejected_even_if_provider_returns_them() -> None:
    body = _body([_trade(id=f"synthetic-{index}") for index in range(11)])
    adapter, _, _, _ = _adapter(_response(body))

    result = adapter.read(_spec(limit=10))

    assert result.error_code == "OVERSIZE"
    assert result.records == ()


def test_next_url_is_never_followed_and_one_page_budget_is_enforced() -> None:
    adapter, transport, _, _ = _adapter(_response(_fixture("synthetic-trades.json")))

    result = adapter.read(_spec())

    assert len(transport.calls) == 1
    assert len(result.records) == 1
    assert result.request_id == "synthetic-request-001"
    assert all(
        "untrusted.invalid" not in str(value) for call in transport.calls for value in call.values()
    )


def test_historical_records_and_events_are_never_execution_eligible() -> None:
    adapter, _, _, _ = _adapter(_response(_fixture("synthetic-trades.json")))

    result = adapter.read(_spec())

    assert all(record.source_mode == "historical" for record in result.records)
    assert all(event.source_mode == "historical" for event in result.events)
    assert all(not getattr(event, "execution_eligible", False) for event in result.events)


def test_vendor_record_can_be_resubmitted_after_public_ingress_backpressure() -> None:
    adapter, _, _, _ = _adapter(_response(_fixture("synthetic-trades.json")))
    record = adapter.read(_spec()).records[0]
    mapping = InstrumentMapping(
        provider="massive",
        dataset="stocks-trades-v1",
        venue="XNAS",
        native_symbol="AAPL",
        instrument_id="synthetic-instrument-aapl",
        leviathan_symbol="NASDAQ:AAPL:STOCK",
        instrument_type="equity",
        mapping_version="synthetic-map-v1",
        tick_size="0.05",
    )

    class _BackpressureOnce:
        def __init__(self) -> None:
            self.calls = 0

        def accept(self, _event: object) -> SinkAck:
            self.calls += 1
            return SinkAck(accepted=self.calls > 1, backpressure=self.calls == 1)

    sink = _BackpressureOnce()
    ingress = NormalizedIngress(
        Normalizer(MappingRegistry((mapping,))),
        sink,
        clock_ns=lambda: _NOW_NS,
        arrival_clock_ns=lambda: 1,
    )

    first = ingress.ingest(record)
    second = ingress.ingest(record)

    assert first.status is IngestStatus.BACKPRESSURE
    assert second.status is IngestStatus.ACCEPTED
    assert sink.calls == 2
