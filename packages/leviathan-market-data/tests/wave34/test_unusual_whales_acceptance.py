"""Independent acceptance for DATA-004 (Unusual Whales options-flow and GEX adapter).

Written from the Wave 34 contract (row 4), the global data-adapter rules and the coordinator's
rulings, not from the writer's unit tests. Everything is offline: a fake single-request
transport with an injected clock, a fake secret resolver and a synthetic key. Requirement matrix:

* Registration surface: PROVIDER_ID, CAPABILITIES, CREDENTIAL_NAMES, keyword-only
  build_adapter(resolve_secret=..., transport=...), no registry import, no environment, file,
  network or logging access of its own.
* Options flow and GEX are distinct record types; contract, expiry, strike, side, venue and
  units are preserved verbatim; event time is distinct from ingest time; nothing is inferred
  (multiplier only from a caller binding, side only from exactly one documented tag).
* Quota and failure handling: 429 with a bounded Retry-After, 503, auth, redirect, timeout,
  size and malformed-body cases, with exactly one request and no retry or pagination.
* Missing values, as-of handling and the redaction of the key from repr, errors, logs and records.
* An unconfigured credential makes zero requests.
"""
# ruff: noqa: E501

from __future__ import annotations

import dataclasses
import importlib
import inspect
import json
import logging
import random
import re
import traceback
from collections.abc import Callable, Mapping
from datetime import UTC, date, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from leviathan_core.flow_radar import Entitlement, OptionPrint, OptionSide, SourceStamp, TradeSide
from leviathan_market_data.providers.wave34 import unusual_whales as uw
from leviathan_market_data.providers.wave34.unusual_whales import (
    CAPABILITIES,
    CREDENTIAL_NAMES,
    PROVIDER_ID,
    ContractBindingV1,
    FlowReadSpecV1,
    GexLevelsV1,
    GexReadSpecV1,
    MappedOptionPrintV1,
    UnusualWhalesAdapter,
    UnusualWhalesAdapterError,
    UnusualWhalesGexRowV1,
    UnusualWhalesHTTPResponse,
    UnusualWhalesOptionTradeV1,
    build_adapter,
    gex_levels,
    to_option_print,
)

KEY = "SyntheticUwKey0123456789abcdefABCDEF"
CHAIN = "SPY261218C00600000"
PUT_CHAIN = "SPY261218P00590000"
EXPIRY = date(2026, 12, 18)
MARKET_DATE = date(2026, 10, 7)
EVENT_TIME = "2026-10-07T14:30:00.123456789Z"
EVENT_NS = int(datetime(2026, 10, 7, 14, 30, tzinfo=UTC).timestamp()) * 1_000_000_000 + 123_456_789
INGEST_NS = EVENT_NS + 2_000_000_000
AS_OF_NS = EVENT_NS + 60_000_000_000
CANARY = "SYNTHETIC_UW_RESPONSE_CANARY_DO_NOT_ECHO"
ERROR_CODES = {
    "NOT_CONFIGURED", "AUTH_DENIED", "RATE_LIMITED", "SOURCE_NOT_READY", "HTTP_STATUS", "TIMEOUT",
    "REDIRECT_DENIED", "RESPONSE_TOO_LARGE", "MALFORMED_RESPONSE", "MISSING_REQUIRED_FIELD",
    "MISSING_MULTIPLIER", "SIDE_UNDETERMINED", "INSTRUMENT_BINDING_MISMATCH", "QUERY_ROW_MISMATCH",
    "INVALID_RECORD", "INVALID_SPEC", "INVALID_GEX_SET",
}
FLOW_URL = "https://api.unusualwhales.com/api/option-trades"
GEX_URL = "https://api.unusualwhales.com/api/stock/SPY/spot-exposures/expiry-strike"


# ------------------------------------------------------------------------------- fakes


class FakeTransport:
    """One scripted response per request; any extra request is a test failure."""

    def __init__(
        self,
        responses: list[UnusualWhalesHTTPResponse | BaseException] | None = None,
        *,
        clock_ns: int = INGEST_NS,
    ) -> None:
        self.responses: list[UnusualWhalesHTTPResponse | BaseException] = list(responses or [])
        self.calls: list[dict[str, Any]] = []
        self.clock_value = clock_ns
        self.clock_calls = 0

    def get(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        params: Mapping[str, str],
        connect_timeout_s: float,
        read_timeout_s: float,
        total_timeout_s: float,
        allow_redirects: bool,
    ) -> UnusualWhalesHTTPResponse:
        self.calls.append({
            "url": url,
            "headers": dict(headers),
            "params": dict(params),
            "connect_timeout_s": connect_timeout_s,
            "read_timeout_s": read_timeout_s,
            "total_timeout_s": total_timeout_s,
            "allow_redirects": allow_redirects,
        })
        if not self.responses:
            raise AssertionError("an unscripted extra request was made")
        item = self.responses.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item

    def clock_ns(self) -> int:
        self.clock_calls += 1
        return self.clock_value


class FakeResolver:
    def __init__(self, secret: object = KEY, *, error: BaseException | None = None) -> None:
        self.secret = secret
        self.error = error
        self.names: list[str] = []

    def __call__(self, name: str) -> str:
        self.names.append(name)
        if self.error is not None:
            raise self.error
        return self.secret  # type: ignore[return-value]


def response(
    body: object,
    *,
    status: int = 200,
    headers: Mapping[str, str] | None = None,
) -> UnusualWhalesHTTPResponse:
    raw = body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")
    return UnusualWhalesHTTPResponse(status, dict(headers or {}), raw)


def trade(**changes: object) -> dict[str, object]:
    row: dict[str, object] = {
        "id": "trade-0001",
        "underlying_symbol": "SPY",
        "option_chain_id": CHAIN,
        "exchange": "CBOE",
        "executed_at": EVENT_TIME,
        "expiry": "2026-12-18",
        "strike": "600",
        "option_type": "call",
        "price": "4.25",
        "size": 10,
        "tags": ["ask_side"],
    }
    row.update(changes)
    return {key: value for key, value in row.items() if value is not _ABSENT}


_ABSENT = object()


def gex(**changes: object) -> dict[str, object]:
    row: dict[str, object] = {
        "strike": "600",
        "time": "2026-10-07T14:30:00Z",
        "call_gamma_oi": "1500.5",
        "put_gamma_oi": "-900.25",
        "call_gamma_vol": "300.1",
        "put_gamma_vol": "-120.9",
        "price": "598.4",
    }
    row.update(changes)
    return {key: value for key, value in row.items() if value is not _ABSENT}


def flow_spec(**changes: object) -> FlowReadSpecV1:
    values: dict[str, Any] = {
        "ticker": "SPY",
        "as_of_ns": AS_OF_NS,
        "limit": 100,
        "session_id": "session-2026-10-07",
        "entitlement": Entitlement.SYNTHETIC,
    }
    values.update(changes)
    return FlowReadSpecV1(**values)


SIDE_TABLE = {"ask_side": TradeSide.BUY, "bid_side": TradeSide.SELL}


def binding(**changes: object) -> ContractBindingV1:
    values: dict[str, Any] = {
        "option_chain_id": CHAIN,
        "underlying": "SPY",
        "multiplier": Decimal("100"),
        "currency": "USD",
    }
    values.update(changes)
    return ContractBindingV1(**values)


def mapped(
    row: dict[str, object], contract: ContractBindingV1 | None = None,
) -> MappedOptionPrintV1:
    dto = flow(row)[0]
    return to_option_print(dto, contract or binding(), SIDE_TABLE)


def gex_spec(**changes: object) -> GexReadSpecV1:
    values: dict[str, Any] = {
        "ticker": "SPY",
        "expiry": EXPIRY,
        "market_date": MARKET_DATE,
        "as_of_ns": AS_OF_NS,
        "limit": 100,
        "page": 0,
    }
    values.update(changes)
    return GexReadSpecV1(**values)


def adapter_for(
    *responses: UnusualWhalesHTTPResponse | BaseException,
    resolver: FakeResolver | None = None,
    clock_ns: int = INGEST_NS,
) -> tuple[UnusualWhalesAdapter, FakeTransport, FakeResolver]:
    transport = FakeTransport(list(responses), clock_ns=clock_ns)
    resolver = resolver or FakeResolver()
    return build_adapter(resolve_secret=resolver, transport=transport), transport, resolver


def flow(*rows: dict[str, object], **headers: str) -> tuple[UnusualWhalesOptionTradeV1, ...]:
    adapter, _, _ = adapter_for(response({"data": list(rows)}, headers=headers))
    return adapter.fetch_options_flow(flow_spec())


def flow_error(*rows: dict[str, object], spec: FlowReadSpecV1 | None = None) -> UnusualWhalesAdapterError:
    adapter, transport, _ = adapter_for(response({"data": list(rows)}))
    with pytest.raises(UnusualWhalesAdapterError) as raised:
        adapter.fetch_options_flow(spec or flow_spec())
    assert len(transport.calls) == 1
    return raised.value


# ------------------------------------------------------------------ registration surface


def test_the_registration_constants_are_exact() -> None:
    assert PROVIDER_ID == "unusual_whales"
    assert re.fullmatch(r"[a-z][a-z0-9._-]{0,63}", PROVIDER_ID)
    assert isinstance(CAPABILITIES, frozenset)
    assert frozenset({"OPTIONS_FLOW", "GEX"}) == CAPABILITIES
    assert all(type(item) is str and item == item.upper() for item in CAPABILITIES)
    assert isinstance(CREDENTIAL_NAMES, tuple)
    assert CREDENTIAL_NAMES == ("unusual_whales_api_key",)
    assert all(re.fullmatch(r"[a-z][a-z0-9_]*", name) for name in CREDENTIAL_NAMES)


def test_build_adapter_is_keyword_only_with_an_injected_resolver_and_transport() -> None:
    parameters = inspect.signature(build_adapter).parameters
    assert list(parameters) == ["resolve_secret", "transport"]
    assert all(p.kind is inspect.Parameter.KEYWORD_ONLY for p in parameters.values())
    transport = FakeTransport()
    with pytest.raises(TypeError):
        build_adapter(FakeResolver(), transport)  # type: ignore[misc]
    adapter = build_adapter(resolve_secret=FakeResolver(), transport=transport)
    assert type(adapter) is UnusualWhalesAdapter


def test_building_an_adapter_reads_no_secret_and_makes_no_request() -> None:
    resolver = FakeResolver()
    transport = FakeTransport()
    build_adapter(resolve_secret=resolver, transport=transport)
    assert resolver.names == [] and transport.calls == [] and transport.clock_calls == 0


@pytest.mark.parametrize("bad", [None, "not callable", 7, object()])
def test_build_adapter_rejects_a_non_callable_resolver(bad: object) -> None:
    with pytest.raises(UnusualWhalesAdapterError) as raised:
        build_adapter(resolve_secret=bad, transport=FakeTransport())  # type: ignore[arg-type]
    assert raised.value.code == "INVALID_SPEC"


@pytest.mark.parametrize("bad", [None, object(), "transport", 3])
def test_build_adapter_rejects_a_transport_without_get_and_clock(bad: object) -> None:
    with pytest.raises(UnusualWhalesAdapterError) as raised:
        build_adapter(resolve_secret=FakeResolver(), transport=bad)  # type: ignore[arg-type]
    assert raised.value.code == "INVALID_SPEC"


def test_the_module_exports_its_surface() -> None:
    exported = set(uw.__all__)
    assert {
        "PROVIDER_ID", "CAPABILITIES", "CREDENTIAL_NAMES", "build_adapter", "FlowReadSpecV1",
        "GexReadSpecV1", "UnusualWhalesAdapter", "UnusualWhalesAdapterError",
        "UnusualWhalesGexRowV1", "GexLevelsV1", "gex_levels", "ContractBindingV1",
        "MappedOptionPrintV1", "UnusualWhalesOptionTradeV1", "to_option_print",
    } <= exported
    for name in exported:
        assert hasattr(uw, name), name


def test_the_module_has_no_registry_environment_file_network_or_logging_access() -> None:
    source = Path(inspect.getsourcefile(uw) or "").read_text(encoding="utf-8")
    assert not re.search(r"providers\.registry|import registry|from .*registry import", source)
    assert not re.search(r"^\s*(import|from)\s+(os|sys|socket|ssl|http|urllib\.request|requests|httpx|aiohttp|subprocess|logging|pathlib|shutil|tempfile)\b", source, re.M)
    assert not re.search(r"os\.environ|getenv|\bopen\(|read_text|read_bytes|(?<![\w.])print\(|\blogger\b|\.warn(ing)?\(", source)
    assert "vault://" not in source and KEY not in source


# ------------------------------------------------------------- an unconfigured credential


UNCONFIGURED: list[tuple[str, Callable[[], FakeResolver]]] = [
    ("resolver raises KeyError", lambda: FakeResolver(error=KeyError("unusual_whales_api_key"))),
    ("resolver raises with the key text", lambda: FakeResolver(error=RuntimeError(f"boom {KEY}"))),
    ("resolver raises LookupError", lambda: FakeResolver(error=LookupError(CANARY))),
    ("empty string", lambda: FakeResolver("")),
    ("None", lambda: FakeResolver(None)),
    ("bytes", lambda: FakeResolver(b"key")),
    ("integer", lambda: FakeResolver(12345)),
    ("whitespace only", lambda: FakeResolver("   ")),
    ("leading space", lambda: FakeResolver(f" {KEY}")),
    ("trailing newline", lambda: FakeResolver(f"{KEY}\n")),
    ("embedded CR", lambda: FakeResolver(f"{KEY}\rX")),
    ("embedded LF header injection", lambda: FakeResolver(f"{KEY}\nX-Evil: 1")),
]


@pytest.mark.parametrize(("name", "make_resolver"), UNCONFIGURED, ids=[n for n, _ in UNCONFIGURED])
@pytest.mark.parametrize("method", ["flow", "gex"])
def test_an_unconfigured_credential_makes_zero_requests(
    name: str, make_resolver: Callable[[], FakeResolver], method: str,
) -> None:
    resolver = make_resolver()
    transport = FakeTransport([response({"data": [trade()]})])
    adapter = build_adapter(resolve_secret=resolver, transport=transport)
    with pytest.raises(UnusualWhalesAdapterError) as raised:
        if method == "flow":
            adapter.fetch_options_flow(flow_spec())
        else:
            adapter.fetch_gex(gex_spec())
    assert raised.value.code == "NOT_CONFIGURED"
    assert transport.calls == []
    assert resolver.names == ["unusual_whales_api_key"]
    for text in (str(raised.value), repr(raised.value), repr(raised.value.args)):
        assert KEY not in text and CANARY not in text


@pytest.mark.parametrize("secret", [f"{KEY}\x00", f"{KEY}\tx", f"{KEY}\x07", "key with\x7fdelete"])
def test_a_secret_with_control_characters_is_not_sent(secret: str) -> None:
    adapter, transport, _ = adapter_for(response({"data": []}), resolver=FakeResolver(secret))
    with pytest.raises(UnusualWhalesAdapterError) as raised:
        adapter.fetch_options_flow(flow_spec())
    assert raised.value.code == "NOT_CONFIGURED"
    assert transport.calls == []


def test_the_secret_is_resolved_on_every_read_and_never_cached() -> None:
    resolver = FakeResolver()
    adapter, transport, _ = adapter_for(
        response({"data": []}), response({"data": []}), resolver=resolver,
    )
    adapter.fetch_options_flow(flow_spec())
    resolver.secret = "SecondSyntheticKeyValueAAAAAAAAAAAA"
    adapter.fetch_gex(gex_spec())
    assert resolver.names == ["unusual_whales_api_key", "unusual_whales_api_key"]
    assert transport.calls[0]["headers"]["Authorization"] == f"Bearer {KEY}"
    assert transport.calls[1]["headers"]["Authorization"] == "Bearer SecondSyntheticKeyValueAAAAAAAAAAAA"


def test_an_invalid_spec_is_refused_before_any_secret_or_request() -> None:
    resolver = FakeResolver()
    adapter, transport, _ = adapter_for(resolver=resolver)
    for bad in (None, {}, "spec", flow_spec()):
        with pytest.raises(UnusualWhalesAdapterError) as raised:
            adapter.fetch_gex(bad)  # type: ignore[arg-type]
        assert raised.value.code == "INVALID_SPEC"
    for bad in (None, {}, "spec", gex_spec()):
        with pytest.raises(UnusualWhalesAdapterError) as raised:
            adapter.fetch_options_flow(bad)  # type: ignore[arg-type]
        assert raised.value.code == "INVALID_SPEC"
    assert resolver.names == [] and transport.calls == []


# --------------------------------------------------------------------------- the request


def test_the_flow_request_is_one_bounded_get_with_the_key_only_in_the_header() -> None:
    adapter, transport, _ = adapter_for(response({"data": [trade()]}))
    adapter.fetch_options_flow(flow_spec(limit=50))
    assert len(transport.calls) == 1
    call = transport.calls[0]
    assert call["url"] == FLOW_URL
    assert call["headers"] == {"Authorization": f"Bearer {KEY}"}
    assert call["params"]["ticker"] == "SPY"
    assert call["params"]["limit"] == "50"
    assert call["allow_redirects"] is False
    for name in ("connect_timeout_s", "read_timeout_s", "total_timeout_s"):
        assert 0 < call[name] <= 60
    assert KEY not in json.dumps({"url": call["url"], "params": call["params"]})


def test_the_flow_request_pushes_the_as_of_instant_to_the_source() -> None:
    adapter, transport, _ = adapter_for(response({"data": []}))
    adapter.fetch_options_flow(flow_spec(as_of_ns=EVENT_NS))
    stamp = transport.calls[0]["params"]["older_than"]
    assert stamp.startswith("2026-10-07T14:30:00.123456789") and stamp.endswith("Z")


def test_the_gex_request_binds_one_expiry_one_market_date_and_one_page() -> None:
    adapter, transport, _ = adapter_for(response({"data": [gex()]}))
    adapter.fetch_gex(gex_spec(page=2, limit=25))
    assert len(transport.calls) == 1
    call = transport.calls[0]
    assert call["url"] == GEX_URL
    assert call["headers"] == {"Authorization": f"Bearer {KEY}"}
    assert call["params"] == {
        "expirations[]": "2026-12-18",
        "date": "2026-10-07",
        "limit": "25",
        "page": "2",
    }
    assert call["allow_redirects"] is False


def test_a_ticker_with_url_significant_characters_cannot_change_the_path() -> None:
    for bad in ("../ADMIN", "SPY/../X", "SPY?x=1", "SPY#f", "spy", "SPY ", ""):
        with pytest.raises(UnusualWhalesAdapterError) as raised:
            gex_spec(ticker=bad)
        assert raised.value.code == "INVALID_SPEC"


# ------------------------------------------------- fetch returns raw documented trade records


def test_fetch_returns_raw_immutable_trade_records_with_every_documented_value() -> None:
    (record,) = flow(trade(), **{"x-request-id": "req-abc-123"})
    assert type(record) is UnusualWhalesOptionTradeV1
    assert not isinstance(record, OptionPrint)
    assert record.trade_id == "trade-0001" and record.option_chain_id == CHAIN
    assert (record.expiry, record.strike, record.option_type) == (EXPIRY, Decimal("600"), "call")
    assert record.exchange == "CBOE" and record.underlying_symbol == "SPY"
    assert (record.price, record.size) == (Decimal("4.25"), Decimal(10))
    assert record.executed_at == EVENT_TIME
    assert record.tags == ("ask_side",)
    assert record.session_id == "session-2026-10-07" and record.entitlement is Entitlement.SYNTHETIC
    assert (record.query_ticker, record.query_as_of_ns, record.query_expiry) == ("SPY", AS_OF_NS, None)
    assert record.request_id == "req-abc-123"
    with pytest.raises(dataclasses.FrozenInstanceError):
        record.price = Decimal("1")  # type: ignore[misc]


def test_a_trade_record_carries_no_mapping_decision() -> None:
    names = {field.name for field in dataclasses.fields(UnusualWhalesOptionTradeV1)}
    assert not names & {"multiplier", "trade_side", "side", "cp", "currency", "flags", "notional", "premium"}
    assert all(not isinstance(item, OptionPrint) for item in flow(trade(), trade(id="t2")))


def test_the_wire_tag_sequence_and_time_text_are_retained_verbatim() -> None:
    for tags in (["sweep", "ask_side", "floor"], ["bid_side"], ["ask_side", "bid_side"], []):
        (record,) = flow(trade(tags=tags))
        assert record.tags == tuple(tags)
    (record,) = flow(trade(executed_at="2026-10-07T14:30:00.5Z"))
    assert record.executed_at == "2026-10-07T14:30:00.5Z"


def test_an_ambiguous_side_is_not_rejected_at_fetch_because_no_side_is_chosen_there() -> None:
    for tags in (["ask_side", "bid_side"], ["sweep"], ["ASK_SIDE"]):
        assert len(flow(trade(tags=tags))) == 1


def test_contract_expiry_strike_venue_and_size_are_preserved_per_row() -> None:
    rows = [
        trade(id="a1", exchange="CBOE", strike="600", size=3),
        trade(id="a2", exchange="ISE", strike="600.5", option_chain_id=PUT_CHAIN, option_type="put", size=7),
    ]
    first, second = flow(*rows)
    assert (first.trade_id, first.exchange, first.strike, first.size) == ("a1", "CBOE", Decimal("600"), Decimal(3))
    assert (second.trade_id, second.exchange, second.strike, second.size) == ("a2", "ISE", Decimal("600.5"), Decimal(7))
    assert (second.option_chain_id, second.option_type) == (PUT_CHAIN, "put")


def test_numeric_values_keep_their_exact_decimal_text_and_are_never_scaled() -> None:
    adapter, _, _ = adapter_for(response(
        b'{"data":[{"id":"x1","underlying_symbol":"SPY","option_chain_id":"%s","exchange":"CBOE",'
        b'"executed_at":"%s","expiry":"2026-12-18","strike":600.10,"option_type":"call",'
        b'"price":4.1,"size":25,"tags":["ask_side"]}]}' % (CHAIN.encode(), EVENT_TIME.encode())
    ))
    (record,) = adapter.fetch_options_flow(flow_spec())
    assert record.price == Decimal("4.1") and record.strike == Decimal("600.10")
    assert record.size == Decimal(25)


def test_event_time_is_distinct_from_ingest_time_and_keeps_nanosecond_precision() -> None:
    (record,) = flow(trade())
    assert record.event_time_ns == EVENT_NS
    assert record.ingest_time_ns == INGEST_NS
    assert record.event_time_ns != record.ingest_time_ns


def test_changing_the_receipt_clock_changes_ingest_and_never_the_event_time() -> None:
    first = adapter_for(response({"data": [trade()]}), clock_ns=INGEST_NS)[0].fetch_options_flow(flow_spec())
    second = adapter_for(response({"data": [trade()]}), clock_ns=INGEST_NS + 9_000_000_000)[0].fetch_options_flow(
        flow_spec()
    )
    assert first[0].event_time_ns == second[0].event_time_ns == EVENT_NS
    assert second[0].ingest_time_ns == INGEST_NS + 9_000_000_000


@pytest.mark.parametrize(("text", "expected_fraction_ns"), [
    ("2026-10-07T14:30:00Z", 0),
    ("2026-10-07T14:30:00.5Z", 500_000_000),
    ("2026-10-07T14:30:00.123Z", 123_000_000),
    ("2026-10-07T14:30:00.000001Z", 1_000),
    ("2026-10-07T14:30:00.123456789Z", 123_456_789),
])
def test_event_time_parses_every_documented_fraction_exactly(text: str, expected_fraction_ns: int) -> None:
    (record,) = flow(trade(executed_at=text))
    base = int(datetime(2026, 10, 7, 14, 30, tzinfo=UTC).timestamp()) * 1_000_000_000
    assert record.event_time_ns == base + expected_fraction_ns


@pytest.mark.parametrize("text", [
    "2026-10-07T14:30:00", "2026-10-07T14:30:00+00:00", "2026-10-07T10:30:00-04:00",
    "2026-10-07", "2026-10-07 14:30:00Z", "2026-10-07T14:30:00z", "2026-13-07T14:30:00Z",
    "2026-10-07T25:30:00Z", "2026-10-07T14:30:60Z", "2026-10-07T14:30:00.1234567891Z",
    "1791316800", "", "not a time", None, 1791316800, 1.79e9, True,
])
def test_an_event_time_that_is_not_explicit_utc_is_rejected(text: object) -> None:
    assert flow_error(trade(executed_at=text)).code == "MISSING_REQUIRED_FIELD"


# ------------------------------------------ missing, malformed and bad values at fetch


REQUIRED = ["id", "underlying_symbol", "option_chain_id", "exchange", "executed_at", "expiry",
            "strike", "price", "size", "option_type"]


@pytest.mark.parametrize("field", REQUIRED)
@pytest.mark.parametrize("how", ["absent", "none", "empty", "wrong_type"])
def test_every_required_trade_field_fails_closed_when_missing_or_malformed(field: str, how: str) -> None:
    value: object = {"absent": _ABSENT, "none": None, "empty": "", "wrong_type": ["x"]}[how]
    error = flow_error(trade(**{field: value}))
    assert error.code in {"MISSING_REQUIRED_FIELD", "INVALID_RECORD"}, (field, how, error.code)


@pytest.mark.parametrize("field", ["strike", "price", "size"])
@pytest.mark.parametrize("value", ["0", "-1", "NaN", "Infinity", "-Infinity", "1e999999", "abc", "1,5", " 5", "5 ", True, [], {}])
def test_a_numeric_trade_field_that_is_not_a_positive_finite_number_is_rejected(field: str, value: object) -> None:
    assert flow_error(trade(**{field: value})).code in {"MISSING_REQUIRED_FIELD", "INVALID_RECORD"}


@pytest.mark.parametrize("value", ["c", "p", "straddle", "", None, 1, True])
def test_an_option_type_other_than_the_documented_spelling_is_rejected_not_guessed(value: object) -> None:
    assert flow_error(trade(option_type=value)).code in {"MISSING_REQUIRED_FIELD", "INVALID_RECORD"}


def test_nothing_about_the_contract_is_inferred_from_the_chain_identifier() -> None:
    for missing in ("option_type", "expiry", "strike"):
        assert flow_error(trade(**{missing: _ABSENT})).code == "MISSING_REQUIRED_FIELD", missing


@pytest.mark.parametrize("constant", [b"NaN", b"Infinity", b"-Infinity"])
def test_non_finite_json_constants_make_the_body_malformed(constant: bytes) -> None:
    adapter, transport, _ = adapter_for(response(b'{"data":[{"id":"x","price":' + constant + b"}]}"))
    with pytest.raises(UnusualWhalesAdapterError) as raised:
        adapter.fetch_options_flow(flow_spec())
    assert raised.value.code == "MALFORMED_RESPONSE" and len(transport.calls) == 1


def test_one_bad_row_rejects_the_whole_batch_and_no_partial_result_escapes() -> None:
    good = [trade(id=f"g{i}") for i in range(3)]
    for bad in (trade(id="b", price="0"), trade(id="b", strike=_ABSENT), trade(id="b", executed_at="soon")):
        adapter, transport, _ = adapter_for(response({"data": [*good, bad]}))
        result: object = None
        with pytest.raises(UnusualWhalesAdapterError):
            result = adapter.fetch_options_flow(flow_spec())
        assert result is None and len(transport.calls) == 1


def test_a_row_for_another_underlying_is_rejected_not_relabelled() -> None:
    assert flow_error(trade(underlying_symbol="QQQ")).code in {"QUERY_ROW_MISMATCH", "MISSING_REQUIRED_FIELD"}


def test_a_pinned_expiry_filters_the_request_and_a_conflicting_row_is_rejected() -> None:
    adapter, transport, _ = adapter_for(response({"data": [trade()]}))
    (record,) = adapter.fetch_options_flow(flow_spec(expiry=EXPIRY))
    assert transport.calls[0]["params"]["expirations[]"] == "2026-12-18"
    assert record.query_expiry == EXPIRY and record.expiry == EXPIRY
    assert flow_error(trade(expiry="2026-12-19"), spec=flow_spec(expiry=EXPIRY)).code == "QUERY_ROW_MISMATCH"
    adapter, transport, _ = adapter_for(response({"data": [trade()]}))
    adapter.fetch_options_flow(flow_spec())
    assert "expirations[]" not in transport.calls[0]["params"]


@pytest.mark.parametrize("body", [
    b"", b"not json", b"[]", b'"text"', b"null", b"123", b'{"data": null}', b'{"data": {}}',
    b'{"data": "x"}', b'{"data": [1]}', b'{"data": [null]}', b'{"data": [[]]}', b'{"other": []}', b"\xff\xfe",
])
def test_a_malformed_body_is_rejected_with_one_request(body: bytes) -> None:
    adapter, transport, _ = adapter_for(response(body))
    with pytest.raises(UnusualWhalesAdapterError) as raised:
        adapter.fetch_options_flow(flow_spec())
    assert raised.value.code == "MALFORMED_RESPONSE" and len(transport.calls) == 1


def test_a_page_larger_than_the_requested_limit_is_malformed_and_never_paginated() -> None:
    rows = [trade(id=f"r{i}") for i in range(3)]
    adapter, transport, _ = adapter_for(response({"data": rows}), response({"data": []}))
    with pytest.raises(UnusualWhalesAdapterError) as raised:
        adapter.fetch_options_flow(flow_spec(limit=2))
    assert raised.value.code == "MALFORMED_RESPONSE" and len(transport.calls) == 1


@pytest.mark.parametrize("limit", [0, -1, 501, 10**6, True, 1.5, "10", None])
def test_the_read_limit_is_bounded(limit: object) -> None:
    with pytest.raises(UnusualWhalesAdapterError) as raised:
        flow_spec(limit=limit)
    assert raised.value.code == "INVALID_SPEC"
    with pytest.raises(UnusualWhalesAdapterError):
        gex_spec(limit=limit)


def test_a_response_does_not_trigger_automatic_pagination_or_retry() -> None:
    adapter, transport, _ = adapter_for(
        response({"data": [trade(id="p1")], "next_page": "https://example.invalid/next"}),
        response({"data": [trade(id="p2")]}),
    )
    assert [r.trade_id for r in adapter.fetch_options_flow(flow_spec())] == ["p1"]
    assert len(transport.calls) == 1


# -------------------------------------------------------------------------- as-of handling


def test_rows_executed_after_the_as_of_instant_are_excluded_and_the_boundary_is_inclusive() -> None:
    rows = [
        trade(id="before", executed_at="2026-10-07T14:29:59Z"),
        trade(id="at", executed_at="2026-10-07T14:30:00.123456789Z"),
        trade(id="after", executed_at="2026-10-07T14:30:00.123456790Z"),
    ]
    adapter, _, _ = adapter_for(response({"data": rows}))
    assert [r.trade_id for r in adapter.fetch_options_flow(flow_spec(as_of_ns=EVENT_NS))] == ["before", "at"]


def test_an_as_of_instant_before_every_row_returns_an_empty_result_not_an_error() -> None:
    adapter, _, _ = adapter_for(response({"data": [trade()]}))
    assert adapter.fetch_options_flow(flow_spec(as_of_ns=EVENT_NS - 1)) == ()
    assert flow() == ()


def test_the_flow_request_as_of_instant_is_also_the_older_than_filter() -> None:
    adapter, transport, _ = adapter_for(response({"data": []}))
    adapter.fetch_options_flow(flow_spec(as_of_ns=EVENT_NS))
    stamp = transport.calls[0]["params"]["older_than"]
    assert stamp.startswith("2026-10-07T14:30:00.123456789") and stamp.endswith("Z")


def test_a_row_dated_after_the_receipt_clock_is_never_returned_as_if_already_received() -> None:
    future = "2026-10-07T14:30:30Z"  # after INGEST_NS, before the as-of instant
    adapter, _, _ = adapter_for(response({"data": [trade(executed_at=future)]}))
    try:
        records = adapter.fetch_options_flow(flow_spec())
    except UnusualWhalesAdapterError:
        return
    for record in records:
        assert record.ingest_time_ns >= record.event_time_ns


def test_ingest_time_is_never_before_the_event_time_of_a_returned_row() -> None:
    for record in flow(trade(id="a"), trade(id="b", executed_at="2026-10-07T14:29:00Z")):
        assert record.ingest_time_ns >= record.event_time_ns


@pytest.mark.parametrize("bad", [0, -5, True, 1.5, "1", None])
def test_a_receipt_clock_that_is_not_a_positive_integer_is_rejected(bad: object) -> None:
    adapter, _, _ = adapter_for(response({"data": [trade()]}), clock_ns=bad)  # type: ignore[arg-type]
    with pytest.raises(UnusualWhalesAdapterError):
        adapter.fetch_options_flow(flow_spec())


@pytest.mark.parametrize(("field", "bad"), [
    ("ticker", "spy"), ("ticker", ""), ("ticker", "TOOLONGTICKERSYMBOLXXXXXXXX"), ("ticker", None),
    ("as_of_ns", 0), ("as_of_ns", -1), ("as_of_ns", True), ("as_of_ns", 1.5), ("as_of_ns", None),
    ("session_id", ""), ("session_id", "has space"), ("session_id", "../x"), ("session_id", None),
    ("entitlement", "SYNTHETIC"), ("entitlement", None), ("entitlement", 1),
    ("expiry", "2026-12-18"), ("expiry", 20261218), ("expiry", True),
])
def test_an_invalid_flow_spec_is_refused(field: str, bad: object) -> None:
    with pytest.raises(UnusualWhalesAdapterError) as raised:
        flow_spec(**{field: bad})
    assert raised.value.code == "INVALID_SPEC"


@pytest.mark.parametrize(("field", "bad"), [
    ("expiry", "2026-12-18"), ("expiry", None), ("market_date", "2026-10-07"), ("page", -1),
    ("page", True), ("page", 1.5), ("as_of_ns", 0), ("as_of_ns", True), ("ticker", "spy"),
])
def test_an_invalid_gex_spec_is_refused(field: str, bad: object) -> None:
    with pytest.raises(UnusualWhalesAdapterError) as raised:
        gex_spec(**{field: bad})
    assert raised.value.code == "INVALID_SPEC"


# ---------------------------------------------- mapping to a FLOW OptionPrint (pure, bound)


def test_the_mapping_produces_the_exact_flow_record_inside_a_provenance_wrapper() -> None:
    result = mapped(trade())
    assert type(result) is MappedOptionPrintV1
    printed = result.option_print
    assert type(printed) is OptionPrint
    assert (printed.ticker, printed.expiry, printed.strike) == ("SPY", EXPIRY, Decimal("600"))
    assert (printed.cp, printed.trade_side) == (OptionSide.CALL, TradeSide.BUY)
    assert (printed.size, printed.price, printed.multiplier) == (Decimal(10), Decimal("4.25"), Decimal("100"))
    assert result.currency == "USD" and result.multiplier_source == "contract_binding"
    assert result.expiry_source == "provider_row"
    assert result.source_trade == flow(trade())[0]
    stamp = printed.stamp
    assert type(stamp) is SourceStamp
    assert stamp.provider == PROVIDER_ID and stamp.dataset
    assert stamp.session == "session-2026-10-07" and stamp.venue == "CBOE"
    assert stamp.native_record_key == "trade-0001" and stamp.entitlement is Entitlement.SYNTHETIC
    assert stamp.event_ns == EVENT_NS
    assert stamp.ingest_ns == INGEST_NS and stamp.available_ns >= stamp.event_ns


def test_a_put_hit_at_the_bid_maps_to_put_and_sell_and_keeps_its_venue() -> None:
    result = mapped(
        trade(id="t-put", option_chain_id=PUT_CHAIN, option_type="put", strike="590", tags=["bid_side"], exchange="XNAS"),
        binding(option_chain_id=PUT_CHAIN),
    )
    printed = result.option_print
    assert (printed.cp, printed.trade_side) == (OptionSide.PUT, TradeSide.SELL)
    assert printed.strike == Decimal("590") and printed.stamp.venue == "XNAS"


def test_a_pinned_query_expiry_is_reported_as_a_request_filter_not_a_provider_value() -> None:
    adapter, _, _ = adapter_for(response({"data": [trade()]}))
    (record,) = adapter.fetch_options_flow(flow_spec(expiry=EXPIRY))
    assert to_option_print(record, binding(), SIDE_TABLE).expiry_source == "request_filter"


def test_the_multiplier_and_currency_come_only_from_the_binding_and_are_never_defaulted() -> None:
    result = mapped(trade(), binding(multiplier=Decimal("10"), currency="EUR"))
    assert result.option_print.multiplier == Decimal("10") and result.currency == "EUR"
    result = mapped(trade(), binding(multiplier=Decimal("1.5")))
    assert result.option_print.multiplier == Decimal("1.5")
    with pytest.raises(UnusualWhalesAdapterError) as raised:
        to_option_print(flow(trade())[0], None, SIDE_TABLE)  # type: ignore[arg-type]
    assert raised.value.code == "MISSING_MULTIPLIER"


@pytest.mark.parametrize(("changes", "codes"), [
    ({"option_chain_id": PUT_CHAIN}, {"INSTRUMENT_BINDING_MISMATCH"}),
    ({"option_chain_id": CHAIN.lower()}, {"INSTRUMENT_BINDING_MISMATCH"}),
    ({"option_chain_id": "SPY"}, {"INSTRUMENT_BINDING_MISMATCH"}),
    ({"underlying": "QQQ"}, {"INSTRUMENT_BINDING_MISMATCH"}),
    ({"underlying": "spy"}, {"INSTRUMENT_BINDING_MISMATCH", "INVALID_SPEC"}),
    ({"underlying": "SPY "}, {"INSTRUMENT_BINDING_MISMATCH", "INVALID_SPEC"}),
])
def test_a_binding_for_another_contract_or_underlying_is_a_mismatch_never_a_guess(
    changes: dict[str, object], codes: set[str],
) -> None:
    with pytest.raises(UnusualWhalesAdapterError) as raised:
        to_option_print(flow(trade())[0], binding(**changes), SIDE_TABLE)
    assert raised.value.code in codes


@pytest.mark.parametrize("changes", [
    {"multiplier": Decimal("0")}, {"multiplier": Decimal("-1")}, {"multiplier": Decimal("NaN")},
    {"multiplier": Decimal("Infinity")}, {"multiplier": 100}, {"multiplier": 100.0}, {"multiplier": "100"},
    {"multiplier": None}, {"currency": "usd"}, {"currency": "US"}, {"currency": "USDX"},
    {"currency": "U1D"}, {"currency": ""}, {"currency": None}, {"currency": 840},
    {"option_chain_id": ""}, {"option_chain_id": "has space"}, {"underlying": ""}, {"underlying": None},
])
def test_an_invalid_contract_binding_is_refused(changes: dict[str, object]) -> None:
    with pytest.raises(UnusualWhalesAdapterError) as raised:
        binding(**changes)
    assert raised.value.code in {"INVALID_SPEC", "MISSING_MULTIPLIER"}


@pytest.mark.parametrize("tags", [
    (), ("sweep",), ("ask_side", "bid_side"), ("ask_side", "ask_side"), ("bid_side", "bid_side"),
    ("ASK_SIDE",), ("Ask_Side",), ("ask",), ("bid",), ("no_side",), ("ask_side ",), ("ask_side", "ask_side", "bid_side"),
])
def test_a_side_that_is_not_exactly_one_documented_tag_is_undetermined_not_guessed(tags: tuple[str, ...]) -> None:
    dto = flow(trade(tags=list(tags)))[0]
    with pytest.raises(UnusualWhalesAdapterError) as raised:
        to_option_print(dto, binding(), SIDE_TABLE)
    assert raised.value.code == "SIDE_UNDETERMINED"


def test_the_side_is_never_inferred_from_the_price_or_the_quote() -> None:
    for row in (
        trade(tags=_ABSENT, nbbo_ask="4.25", nbbo_bid="4.00", price="4.25"),
        trade(tags=["sweep"], nbbo_ask="4.25", nbbo_bid="4.00", price="4.00"),
    ):
        try:
            dto = flow(row)[0]
        except UnusualWhalesAdapterError:
            continue
        with pytest.raises(UnusualWhalesAdapterError) as raised:
            to_option_print(dto, binding(), SIDE_TABLE)
        assert raised.value.code == "SIDE_UNDETERMINED"


def test_extra_tags_alongside_exactly_one_side_do_not_change_the_mapping() -> None:
    buy = mapped(trade(tags=["sweep", "ask_side", "floor"]))
    sell = mapped(trade(tags=["bid_side", "sweep"]))
    assert buy.option_print.trade_side is TradeSide.BUY and sell.option_print.trade_side is TradeSide.SELL


@pytest.mark.parametrize("table", [
    {"ask_side": TradeSide.SELL, "bid_side": TradeSide.BUY},
    {"ask_side": TradeSide.BUY},
    {"bid_side": TradeSide.SELL},
    {},
    {"ask_side": TradeSide.BUY, "bid_side": TradeSide.SELL, "mid_side": TradeSide.BUY},
    {"ask_side": "BUY", "bid_side": "SELL"},
    {"ask_side": TradeSide.BUY, "bid_side": TradeSide.BUY},
    None,
    [("ask_side", TradeSide.BUY)],
])
def test_only_the_documented_side_table_is_accepted(table: object) -> None:
    with pytest.raises(UnusualWhalesAdapterError) as raised:
        to_option_print(flow(trade())[0], binding(), table)  # type: ignore[arg-type]
    assert raised.value.code in {"SIDE_UNDETERMINED", "INVALID_SPEC"}


def test_no_optional_flow_field_is_invented_and_units_are_never_scaled() -> None:
    printed = mapped(trade(tags=["ask_side", "sweep", "floor"]), binding(multiplier=Decimal("100"))).option_print
    assert printed.flags == () and printed.common_order_id is None and printed.aggression_score is None
    assert printed.original_strike is None and printed.original_size is None
    assert printed.adjustment_version is None and printed.stamp.correction_of is None
    assert printed.price == Decimal("4.25") and printed.size == Decimal(10) and printed.strike == Decimal("600")


def test_the_mapping_is_pure_deterministic_and_needs_no_adapter_secret_or_transport() -> None:
    dto = flow(trade())[0]
    first = to_option_print(dto, binding(), SIDE_TABLE)
    second = to_option_print(dto, binding(), SIDE_TABLE)
    assert first.option_print.record_id == second.option_print.record_id
    assert first.option_print == second.option_print and first.currency == second.currency


def test_the_mapping_refuses_a_foreign_trade_object() -> None:
    for bad in (None, {}, "trade", trade(), flow(trade())[0].__class__):
        with pytest.raises(UnusualWhalesAdapterError) as raised:
            to_option_print(bad, binding(), SIDE_TABLE)  # type: ignore[arg-type]
        assert raised.value.code in {"INVALID_RECORD", "INVALID_SPEC"}


def test_the_mapped_wrapper_is_immutable_and_never_carries_the_key() -> None:
    result = mapped(trade())
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.currency = "EUR"  # type: ignore[misc]
    assert KEY not in repr(result)


def test_a_binding_mismatch_never_returns_a_partial_record() -> None:
    dtos = flow(trade(id="a"), trade(id="b", option_chain_id=PUT_CHAIN, option_type="put", strike="590"))
    results: list[object] = []
    with pytest.raises(UnusualWhalesAdapterError):
        for dto in dtos:
            results.append(to_option_print(dto, binding(), SIDE_TABLE))
    assert len(results) == 1
    assert results[0].option_print.stamp.native_record_key == "a"  # type: ignore[attr-defined]


# ------------------------------------------------------------------- GEX is its own record


def gex_rows(*rows: dict[str, object], spec: GexReadSpecV1 | None = None) -> tuple[UnusualWhalesGexRowV1, ...]:
    adapter, _, _ = adapter_for(response({"data": list(rows)}))
    return adapter.fetch_gex(spec or gex_spec())


def gex_error(*rows: dict[str, object]) -> UnusualWhalesAdapterError:
    adapter, transport, _ = adapter_for(response({"data": list(rows)}))
    with pytest.raises(UnusualWhalesAdapterError) as raised:
        adapter.fetch_gex(gex_spec())
    assert len(transport.calls) == 1
    return raised.value


def test_a_gex_row_is_a_distinct_record_type_with_only_the_documented_aggregate_fields() -> None:
    (row,) = gex_rows(gex())
    assert type(row) is UnusualWhalesGexRowV1
    assert not isinstance(row, OptionPrint)
    assert (row.ticker, row.strike, row.expiry) == ("SPY", Decimal("600"), EXPIRY)
    assert (row.call_gamma_oi, row.put_gamma_oi) == (Decimal("1500.5"), Decimal("-900.25"))
    assert (row.call_gamma_vol, row.put_gamma_vol) == (Decimal("300.1"), Decimal("-120.9"))
    assert row.price == Decimal("598.4")
    assert row.gex001_chain_evidence is False


def test_a_gex_row_never_pretends_to_carry_contract_venue_or_units() -> None:
    (row,) = gex_rows(gex())
    assert row.contract is None and row.venue is None and row.exposure_units is None
    assert set(row.missing_fields) == {"contract", "venue", "exposure_units"}
    names = {field.name for field in dataclasses.fields(row)}
    assert not names & {"open_interest", "iv", "implied_vol", "delta", "bid", "ask", "multiplier", "side"}


def test_flow_and_gex_results_are_different_types_and_never_mix() -> None:
    adapter, _, _ = adapter_for(response({"data": [trade()]}), response({"data": [gex()]}))
    flow_result = adapter.fetch_options_flow(flow_spec())
    gex_result = adapter.fetch_gex(gex_spec())
    assert all(type(item) is UnusualWhalesOptionTradeV1 for item in flow_result)
    assert not any(isinstance(item, OptionPrint) for item in flow_result)
    assert all(type(item) is UnusualWhalesGexRowV1 for item in gex_result)
    assert type(flow_result[0]) is not type(gex_result[0])
    assert {"OPTIONS_FLOW", "GEX"} == CAPABILITIES


def test_a_gex_record_is_not_an_option_series_evidence_record() -> None:
    (row,) = gex_rows(gex())
    chain_evidence = importlib.import_module("leviathan_core.dealer_gamma.models")
    evidence_type = getattr(chain_evidence, "OptionSeriesEvidenceV1", None)
    if evidence_type is not None:
        assert not isinstance(row, evidence_type)
    levels = gex_levels((row,), basis="oi")
    assert levels.gex001_chain_evidence is False and levels.exposure_units is None


def test_gex_event_time_comes_from_the_row_and_ingest_time_from_the_clock() -> None:
    (row,) = gex_rows(gex(time="2026-10-07T14:30:00.5Z"))
    assert row.event_time_ns == EVENT_NS - 123_456_789 + 500_000_000
    assert row.ingest_time_ns == INGEST_NS
    assert row.event_time_ns != row.ingest_time_ns and row.event_time_ns <= row.ingest_time_ns


def test_an_absent_gex_value_is_none_never_zero() -> None:
    (row,) = gex_rows(gex(call_gamma_vol=_ABSENT, put_gamma_vol=None, price=_ABSENT))
    assert row.call_gamma_vol is None and row.put_gamma_vol is None and row.price is None
    assert row.call_gamma_oi == Decimal("1500.5")


def test_a_gex_row_without_a_strike_or_time_is_rejected() -> None:
    assert gex_error(gex(strike=_ABSENT)).code == "MISSING_REQUIRED_FIELD"
    assert gex_error(gex(time=_ABSENT)).code == "MISSING_REQUIRED_FIELD"
    assert gex_error(gex(time="2026-10-07T14:30:00")).code == "MISSING_REQUIRED_FIELD"
    assert gex_error(gex(strike="0")).code in {"INVALID_RECORD", "MISSING_REQUIRED_FIELD"}


@pytest.mark.parametrize("field", ["call_gamma_oi", "put_gamma_oi", "call_gamma_vol", "put_gamma_vol", "price"])
@pytest.mark.parametrize("value", ["not-a-number", "NaN", "Infinity", True, ["1"], {"a": 1}, "1,5", " 7"])
def test_a_present_but_invalid_gex_value_is_rejected_not_silently_turned_into_missing(
    field: str, value: object,
) -> None:
    error = gex_error(gex(**{field: value}))
    assert error.code in {"INVALID_RECORD", "MALFORMED_RESPONSE", "MISSING_REQUIRED_FIELD"}


def test_a_gex_row_states_that_its_expiry_and_ticker_come_from_the_request() -> None:
    (row,) = gex_rows(gex())
    assert row.expiry_source == "request_filter" and row.ticker_source == "request_path"
    assert (row.expiry, row.ticker) == (EXPIRY, "SPY")


def test_a_gex_row_that_carries_its_own_identity_must_match_the_request() -> None:
    (row,) = gex_rows(gex(expiry="2026-12-18", ticker="SPY"))
    assert row.expiry == EXPIRY and row.ticker == "SPY"
    assert row.expiry_source == "provider_row" and row.ticker_source == "provider_row"
    for conflicting in ({"expiry": "2026-12-19"}, {"ticker": "QQQ"}, {"symbol": "QQQ"}):
        assert gex_error(gex(**conflicting)).code == "QUERY_ROW_MISMATCH", conflicting


def test_gex_rows_after_the_as_of_instant_are_excluded_and_the_boundary_is_inclusive() -> None:
    rows = [
        gex(strike="590", time="2026-10-07T14:29:59Z"),
        gex(strike="600", time="2026-10-07T14:30:00.123456789Z"),
        gex(strike="610", time="2026-10-07T14:30:00.123456790Z"),
    ]
    result = gex_rows(*rows, spec=gex_spec(as_of_ns=EVENT_NS))
    assert [row.strike for row in result] == [Decimal("590"), Decimal("600")]


def test_gex_rows_dated_after_the_receipt_clock_are_never_returned() -> None:
    rows = [gex(strike="590", time="2026-10-07T14:30:30Z")]
    try:
        result = gex_rows(*rows)
    except UnusualWhalesAdapterError:
        return
    for row in result:
        assert row.event_time_ns <= row.ingest_time_ns


def test_a_gex_record_is_immutable() -> None:
    (row,) = gex_rows(gex())
    with pytest.raises(dataclasses.FrozenInstanceError):
        row.strike = Decimal("1")  # type: ignore[misc]
    with pytest.raises(UnusualWhalesAdapterError) as raised:
        dataclasses.replace(row, contract="SPY261218C00600000")  # type: ignore[arg-type]
    assert raised.value.code == "INVALID_RECORD"
    with pytest.raises(UnusualWhalesAdapterError):
        dataclasses.replace(row, exposure_units="USD")  # type: ignore[arg-type]
    with pytest.raises(UnusualWhalesAdapterError):
        dataclasses.replace(row, gex001_chain_evidence=True)  # type: ignore[arg-type]
    with pytest.raises(UnusualWhalesAdapterError):
        dataclasses.replace(row, ingest_time_ns=row.event_time_ns - 1)


# ----------------------------------------------------------------------- gex_levels (pure)


def level_rows() -> tuple[UnusualWhalesGexRowV1, ...]:
    return gex_rows(
        gex(strike="590", call_gamma_oi="100", put_gamma_oi="-900", call_gamma_vol="10", put_gamma_vol="-90"),
        gex(strike="595", call_gamma_oi="300", put_gamma_oi="-400", call_gamma_vol="30", put_gamma_vol="-40"),
        gex(strike="600", call_gamma_oi="1500", put_gamma_oi="-200", call_gamma_vol="150", put_gamma_vol="-20"),
        gex(strike="605", call_gamma_oi="700", put_gamma_oi="-50", call_gamma_vol="70", put_gamma_vol="-5"),
    )


def test_gex_levels_are_deterministic_provider_aggregates() -> None:
    rows = level_rows()
    levels = gex_levels(rows, basis="oi")
    assert type(levels) is GexLevelsV1
    assert (levels.ticker, levels.expiry, levels.basis) == ("SPY", EXPIRY, "oi")
    assert levels.call_wall == Decimal("600") and levels.put_wall == Decimal("590")
    assert levels.zero_gamma_flips == ((Decimal("595"), Decimal("600")),)
    assert levels.top_strikes[0] == Decimal("600") and len(levels.top_strikes) == 4
    assert levels.source == "unusual_whales_aggregate"
    assert levels.gex001_chain_evidence is False and levels.exposure_units is None
    assert gex_levels(rows, basis="oi") == levels


def test_gex_levels_do_not_depend_on_input_order() -> None:
    rows = list(level_rows())
    expected = gex_levels(tuple(rows), basis="volume")
    for seed in range(5):
        shuffled = rows[:]
        random.Random(seed).shuffle(shuffled)
        assert gex_levels(tuple(shuffled), basis="volume") == expected


def test_gex_levels_use_the_requested_basis_and_bound_the_top_list() -> None:
    rows = level_rows()
    assert gex_levels(rows, basis="volume").call_wall == Decimal("600")
    assert len(gex_levels(rows, basis="oi", top_n=2).top_strikes) == 2
    assert len(gex_levels(rows, basis="oi", top_n=100).top_strikes) == len(rows)


@pytest.mark.parametrize("bad", [0, -1, 101, True, 1.5, None, "5"])
def test_gex_levels_reject_an_unbounded_or_invalid_top_n(bad: object) -> None:
    with pytest.raises(UnusualWhalesAdapterError) as raised:
        gex_levels(level_rows(), basis="oi", top_n=bad)  # type: ignore[arg-type]
    assert raised.value.code == "INVALID_GEX_SET"


@pytest.mark.parametrize("basis", ["OI", "gamma", "", None, 1])
def test_gex_levels_reject_an_unknown_basis(basis: object) -> None:
    with pytest.raises(UnusualWhalesAdapterError) as raised:
        gex_levels(level_rows(), basis=basis)  # type: ignore[arg-type]
    assert raised.value.code == "INVALID_GEX_SET"


def test_gex_levels_reject_empty_foreign_duplicate_or_mixed_sets() -> None:
    rows = level_rows()
    for bad in ((), [], None, "rows", (rows[0], "x"), (rows[0], rows[0])):
        with pytest.raises(UnusualWhalesAdapterError) as raised:
            gex_levels(bad, basis="oi")  # type: ignore[arg-type]
        assert raised.value.code == "INVALID_GEX_SET"
    other_expiry = gex_rows(gex(strike="610"), spec=gex_spec(expiry=date(2026, 12, 19)))
    other_time = gex_rows(gex(strike="615", time="2026-10-07T14:29:00Z"))
    for mixed in ((rows[0], other_expiry[0]), (rows[0], other_time[0])):
        with pytest.raises(UnusualWhalesAdapterError) as raised:
            gex_levels(mixed, basis="oi")
        assert raised.value.code == "INVALID_GEX_SET"


def test_gex_levels_never_fill_a_missing_value_with_zero() -> None:
    rows = gex_rows(gex(strike="590"), gex(strike="595", call_gamma_oi=_ABSENT))
    with pytest.raises(UnusualWhalesAdapterError) as raised:
        gex_levels(rows, basis="oi")
    assert raised.value.code == "MISSING_REQUIRED_FIELD"


# ------------------------------------------------------------------ quota and the failures


@pytest.mark.parametrize("method", ["flow", "gex"])
def test_a_429_is_a_rate_limit_with_one_request_and_a_parsed_retry_after(method: str) -> None:
    adapter, transport, _ = adapter_for(
        response({"error": CANARY}, status=429, headers={"Retry-After": "30"}),
        response({"data": []}),
    )
    with pytest.raises(UnusualWhalesAdapterError) as raised:
        adapter.fetch_options_flow(flow_spec()) if method == "flow" else adapter.fetch_gex(gex_spec())
    assert raised.value.code == "RATE_LIMITED"
    assert raised.value.retry_after_seconds == 30
    assert len(transport.calls) == 1
    for text in (str(raised.value), repr(raised.value), repr(raised.value.args)):
        assert CANARY not in text and KEY not in text


@pytest.mark.parametrize("header", ["abc", "-5", "1.5", "99999999", "30 s", "", " 30", "0x10", "1e3", "٣٠"])
def test_an_untrustworthy_retry_after_is_ignored_not_obeyed(header: str) -> None:
    adapter, _, _ = adapter_for(response({}, status=429, headers={"Retry-After": header}))
    with pytest.raises(UnusualWhalesAdapterError) as raised:
        adapter.fetch_options_flow(flow_spec())
    assert raised.value.code == "RATE_LIMITED"
    assert raised.value.retry_after_seconds is None


def test_retry_after_is_found_case_insensitively_and_bounded_to_one_day() -> None:
    adapter, _, _ = adapter_for(response({}, status=429, headers={"retry-after": "86400"}))
    with pytest.raises(UnusualWhalesAdapterError) as raised:
        adapter.fetch_options_flow(flow_spec())
    assert raised.value.retry_after_seconds == 86_400


def test_a_429_without_retry_after_has_no_delay_and_still_one_request() -> None:
    adapter, transport, _ = adapter_for(response({}, status=429), response({"data": []}))
    with pytest.raises(UnusualWhalesAdapterError) as raised:
        adapter.fetch_options_flow(flow_spec())
    assert raised.value.code == "RATE_LIMITED" and raised.value.retry_after_seconds is None
    assert len(transport.calls) == 1


@pytest.mark.parametrize(("status", "code"), [
    (503, "SOURCE_NOT_READY"), (401, "AUTH_DENIED"), (403, "AUTH_DENIED"), (400, "HTTP_STATUS"),
    (404, "HTTP_STATUS"), (418, "HTTP_STATUS"), (500, "HTTP_STATUS"), (502, "HTTP_STATUS"),
    (504, "HTTP_STATUS"), (301, "REDIRECT_DENIED"), (302, "REDIRECT_DENIED"),
    (307, "REDIRECT_DENIED"), (308, "REDIRECT_DENIED"), (199, "HTTP_STATUS"), (600, "HTTP_STATUS"),
])
@pytest.mark.parametrize("method", ["flow", "gex"])
def test_every_status_maps_to_a_closed_code_with_one_request_and_no_body_echo(
    status: int, code: str, method: str,
) -> None:
    adapter, transport, _ = adapter_for(
        response({"detail": CANARY, "key": KEY}, status=status, headers={"Location": f"https://x.invalid/{CANARY}"}),
        response({"data": []}),
    )
    with pytest.raises(UnusualWhalesAdapterError) as raised:
        adapter.fetch_options_flow(flow_spec()) if method == "flow" else adapter.fetch_gex(gex_spec())
    assert raised.value.code == code
    assert len(transport.calls) == 1 and transport.calls[0]["allow_redirects"] is False
    for text in (str(raised.value), repr(raised.value), repr(raised.value.args)):
        assert CANARY not in text and KEY not in text


def test_a_503_carries_a_parsed_retry_after_but_never_retries() -> None:
    adapter, transport, _ = adapter_for(
        response({}, status=503, headers={"Retry-After": "12"}), response({"data": []}),
    )
    with pytest.raises(UnusualWhalesAdapterError) as raised:
        adapter.fetch_gex(gex_spec())
    assert raised.value.code == "SOURCE_NOT_READY" and raised.value.retry_after_seconds == 12
    assert len(transport.calls) == 1


@pytest.mark.parametrize(("exc", "code"), [
    (TimeoutError("slow"), "TIMEOUT"),
    (OSError(f"connection reset {KEY}"), "HTTP_STATUS"),
    (RuntimeError(f"boom {KEY} {CANARY}"), "HTTP_STATUS"),
    (ConnectionError(CANARY), "HTTP_STATUS"),
    (ValueError(KEY), "HTTP_STATUS"),
])
def test_a_transport_failure_maps_to_a_closed_code_and_never_carries_the_key(
    exc: BaseException, code: str,
) -> None:
    adapter, transport, _ = adapter_for(exc, response({"data": []}))
    with pytest.raises(UnusualWhalesAdapterError) as raised:
        adapter.fetch_options_flow(flow_spec())
    err = raised.value
    assert err.code == code and len(transport.calls) == 1
    assert err.__cause__ is None
    rendered = "".join(traceback.format_exception(type(err), err, err.__traceback__))
    for text in (str(err), repr(err), repr(err.args), rendered):
        assert KEY not in text and CANARY not in text


def test_a_response_larger_than_the_cap_is_rejected_without_parsing() -> None:
    big = b'{"data":[],"pad":"' + b"x" * 2_200_000 + b'"}'
    adapter, transport, _ = adapter_for(response(big))
    with pytest.raises(UnusualWhalesAdapterError) as raised:
        adapter.fetch_options_flow(flow_spec())
    assert raised.value.code == "RESPONSE_TOO_LARGE" and len(transport.calls) == 1


def test_a_response_with_a_non_integer_status_or_non_bytes_body_is_malformed() -> None:
    for bad in (
        UnusualWhalesHTTPResponse(True, {}, b"{}"),  # type: ignore[arg-type]
        UnusualWhalesHTTPResponse(200, {}, "text"),  # type: ignore[arg-type]
        UnusualWhalesHTTPResponse("200", {}, b"{}"),  # type: ignore[arg-type]
    ):
        adapter, _, _ = adapter_for(bad)
        with pytest.raises(UnusualWhalesAdapterError) as raised:
            adapter.fetch_options_flow(flow_spec())
        assert raised.value.code == "MALFORMED_RESPONSE"


def test_no_error_code_outside_the_closed_vocabulary_can_be_constructed() -> None:
    assert UnusualWhalesAdapterError("NOT_A_CODE").code in ERROR_CODES
    for code in ERROR_CODES:
        assert UnusualWhalesAdapterError(code).code == code
        assert str(UnusualWhalesAdapterError(code)) == code


# ---------------------------------------------------------------------- redaction of the key


def test_the_adapter_repr_and_str_never_contain_the_key() -> None:
    adapter, _, _ = adapter_for()
    for text in (repr(adapter), str(adapter), f"{adapter}", format(adapter)):
        assert KEY not in text and "REDACTED" in text.upper()
    assert not hasattr(adapter, "__dict__")
    assert not any(KEY in repr(getattr(adapter, name, "")) for name in dir(adapter) if not name.startswith("__"))


def test_the_key_is_in_the_request_header_and_nowhere_else() -> None:
    adapter, transport, _ = adapter_for(response({"data": [trade()]}), response({"data": [gex()]}))
    adapter.fetch_options_flow(flow_spec())
    adapter.fetch_gex(gex_spec())
    for call in transport.calls:
        assert call["headers"] == {"Authorization": f"Bearer {KEY}"}
        assert KEY not in call["url"]
        assert KEY not in json.dumps(call["params"])


def test_the_key_never_reaches_a_log_stdout_stderr_or_a_returned_record(
    caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture[str],
) -> None:
    caplog.set_level(logging.DEBUG)
    adapter, _, _ = adapter_for(
        response({"data": [trade()]}), response({"data": [gex()]}), response({}, status=401),
    )
    records = adapter.fetch_options_flow(flow_spec())
    rows = adapter.fetch_gex(gex_spec())
    with pytest.raises(UnusualWhalesAdapterError):
        adapter.fetch_options_flow(flow_spec())
    captured = capsys.readouterr()
    assert caplog.records == []
    assert KEY not in captured.out + captured.err + caplog.text
    assert KEY not in repr(records) and KEY not in repr(rows) and KEY not in repr(flow_spec())


def test_a_server_that_reflects_the_key_cannot_put_it_into_a_returned_record() -> None:
    # A misbehaving or intercepting server can echo the Authorization value in a response header.
    adapter, _, _ = adapter_for(response({"data": [trade()]}, headers={"x-request-id": KEY}))
    for record in adapter.fetch_options_flow(flow_spec()):
        assert KEY not in repr(record)
        assert record.request_id != KEY
        assert KEY not in repr(to_option_print(record, binding(), SIDE_TABLE))


def test_a_reflected_key_in_an_error_response_is_never_echoed() -> None:
    adapter, _, _ = adapter_for(response(
        {"error": f"invalid token {KEY}", "authorization": f"Bearer {KEY}"}, status=401,
        headers={"WWW-Authenticate": f'Bearer realm="{KEY}"'},
    ))
    with pytest.raises(UnusualWhalesAdapterError) as raised:
        adapter.fetch_options_flow(flow_spec())
    err = raised.value
    rendered = "".join(traceback.format_exception(type(err), err, err.__traceback__))
    assert KEY not in rendered + repr(err) + str(err) + repr(err.args)


def test_the_key_never_appears_in_an_exception_raised_by_the_resolver() -> None:
    secret_text = f"vault backend failed for {KEY}"
    adapter, transport, _ = adapter_for(resolver=FakeResolver(error=RuntimeError(secret_text)))
    with pytest.raises(UnusualWhalesAdapterError) as raised:
        adapter.fetch_gex(gex_spec())
    err = raised.value
    rendered = "".join(traceback.format_exception(type(err), err, err.__traceback__))
    assert KEY not in rendered + repr(err) + str(err) + repr(err.args)
    assert err.__cause__ is None and transport.calls == []


# ------------------------------------------------------------------------ immutability


def test_flow_records_cannot_be_mutated_and_mapped_flow_values_cannot_be_copied_or_pickled() -> None:
    record = flow(trade())[0]
    with pytest.raises(dataclasses.FrozenInstanceError):
        record.price = Decimal("1")  # type: ignore[misc]
    import copy
    import pickle

    printed = to_option_print(record, binding(), SIDE_TABLE).option_print
    with pytest.raises(Exception):  # noqa: B017 - FLOW values forbid copies by design
        copy.copy(printed)
    with pytest.raises(Exception):  # noqa: B017
        pickle.dumps(printed)


def test_the_adapter_returns_tuples_not_lists_or_generators() -> None:
    adapter, _, _ = adapter_for(response({"data": [trade()]}), response({"data": [gex()]}))
    assert type(adapter.fetch_options_flow(flow_spec())) is tuple
    assert type(adapter.fetch_gex(gex_spec())) is tuple


def test_a_callable_that_is_not_a_function_still_works_as_the_resolver() -> None:
    resolver: Callable[[str], str] = FakeResolver()
    adapter = build_adapter(resolve_secret=resolver, transport=FakeTransport([response({"data": []})]))
    assert adapter.fetch_options_flow(flow_spec()) == ()


# --------------------------------------------- added after the mutation run on the frozen module


class OrderedTransport(FakeTransport):
    """Records whether the receipt clock is read before or after the response and how often."""

    def __init__(self, responses: list[UnusualWhalesHTTPResponse | BaseException]) -> None:
        super().__init__(responses)
        self.events: list[str] = []

    def get(self, url: str, **kwargs: Any) -> UnusualWhalesHTTPResponse:
        self.events.append("get")
        return super().get(url, **kwargs)

    def clock_ns(self) -> int:
        self.events.append("clock")
        self.clock_calls += 1
        return INGEST_NS + self.clock_calls * 1_000_000_000


@pytest.mark.parametrize("secret", ["key\x7f", "kéy", "key​", "密钥", "key\x80", "key\xa0"])
def test_a_secret_with_del_or_non_ascii_characters_is_not_sent(secret: str) -> None:
    resolver = FakeResolver(secret)
    transport = FakeTransport([response({"data": []})])
    adapter = build_adapter(resolve_secret=resolver, transport=transport)
    for call in (lambda: adapter.fetch_options_flow(flow_spec()), lambda: adapter.fetch_gex(gex_spec())):
        with pytest.raises(UnusualWhalesAdapterError) as raised:
            call()
        assert raised.value.code == "NOT_CONFIGURED"
    assert transport.calls == []


@pytest.mark.parametrize("resolved", ["", None, "raises"])
def test_the_environment_is_never_a_fallback_for_a_missing_key(
    monkeypatch: pytest.MonkeyPatch, resolved: object,
) -> None:
    for name in (
        "UW_KEY", "UW_API_KEY", "UW_TOKEN", "UNUSUAL_WHALES_KEY", "UNUSUAL_WHALES_API_KEY",
        "UNUSUAL_WHALES_TOKEN", "unusual_whales_api_key",
    ):
        monkeypatch.setenv(name, KEY)
    resolver = FakeResolver(error=KeyError("unusual_whales_api_key")) if resolved == "raises" else FakeResolver(resolved)
    transport = FakeTransport([response({"data": []})])
    adapter = build_adapter(resolve_secret=resolver, transport=transport)
    with pytest.raises(UnusualWhalesAdapterError) as raised:
        adapter.fetch_options_flow(flow_spec())
    assert raised.value.code == "NOT_CONFIGURED"
    assert transport.calls == []


@pytest.mark.parametrize("field", ["id", "exchange", "option_chain_id", "underlying_symbol"])
def test_a_server_that_reflects_the_key_into_a_trade_field_never_yields_a_record_holding_it(field: str) -> None:
    row = trade(**{field: KEY})
    adapter, transport, _ = adapter_for(response({"data": [row]}))
    try:
        records = adapter.fetch_options_flow(flow_spec())
    except UnusualWhalesAdapterError as error:
        assert KEY not in repr(error) + str(error) + repr(error.args)
    else:
        assert KEY not in repr(records)
    assert len(transport.calls) == 1


def test_an_oversized_body_is_refused_for_its_size_before_any_attempt_to_parse_it() -> None:
    adapter, transport, _ = adapter_for(response(b"x" * 2_200_000))
    with pytest.raises(UnusualWhalesAdapterError) as raised:
        adapter.fetch_options_flow(flow_spec())
    assert raised.value.code == "RESPONSE_TOO_LARGE" and len(transport.calls) == 1
    adapter, transport, _ = adapter_for(response(b"x" * 2_200_000))
    with pytest.raises(UnusualWhalesAdapterError) as raised:
        adapter.fetch_gex(gex_spec())
    assert raised.value.code == "RESPONSE_TOO_LARGE" and len(transport.calls) == 1


def test_a_page_that_is_exactly_full_is_one_request_never_a_follow_up_page() -> None:
    adapter, transport, _ = adapter_for(
        response({"data": [trade(id="f1"), trade(id="f2")]}), response({"data": [trade(id="f3")]}),
    )
    assert [r.trade_id for r in adapter.fetch_options_flow(flow_spec(limit=2))] == ["f1", "f2"]
    assert len(transport.calls) == 1
    adapter, transport, _ = adapter_for(
        response({"data": [gex(strike="590"), gex(strike="600")]}), response({"data": [gex(strike="610")]}),
    )
    assert len(adapter.fetch_gex(gex_spec(limit=2))) == 2
    assert len(transport.calls) == 1


def test_a_retry_after_of_zero_is_a_real_zero_not_an_absent_value() -> None:
    adapter, _, _ = adapter_for(response({}, status=429, headers={"Retry-After": "0"}))
    with pytest.raises(UnusualWhalesAdapterError) as raised:
        adapter.fetch_options_flow(flow_spec())
    assert raised.value.code == "RATE_LIMITED" and raised.value.retry_after_seconds == 0


def test_the_receipt_clock_is_read_once_after_the_response_and_shared_by_every_row() -> None:
    transport = OrderedTransport([response({"data": [trade(id="o1"), trade(id="o2"), trade(id="o3")]})])
    adapter = build_adapter(resolve_secret=FakeResolver(), transport=transport)
    records = adapter.fetch_options_flow(flow_spec())
    assert transport.events == ["get", "clock"]
    assert {r.ingest_time_ns for r in records} == {INGEST_NS + 1_000_000_000}
    transport = OrderedTransport([response({"data": [gex(strike="590"), gex(strike="600")]})])
    adapter = build_adapter(resolve_secret=FakeResolver(), transport=transport)
    rows = adapter.fetch_gex(gex_spec())
    assert transport.events == ["get", "clock"]
    assert {r.ingest_time_ns for r in rows} == {INGEST_NS + 1_000_000_000}


@pytest.mark.parametrize("text", [
    "2026-10-07T14:30:00Z", "2026-10-07T14:30:00.500000Z", "2026-10-07T14:30:00.120000000Z",
    "2026-10-07T14:30:00.10Z", "2026-10-07T14:30:00.000Z",
])
def test_the_executed_at_text_is_retained_exactly_as_the_provider_wrote_it(text: str) -> None:
    (record,) = flow(trade(executed_at=text))
    assert record.executed_at == text


@pytest.mark.parametrize("key", ["ticker", "symbol"])
def test_a_flow_row_that_names_another_underlying_in_any_identity_field_is_a_mismatch(key: str) -> None:
    assert flow_error(trade(**{key: "QQQ"})).code == "QUERY_ROW_MISMATCH"
    (record,) = flow(trade(**{key: "SPY"}))
    assert record.underlying_symbol == "SPY"


def test_a_flow_row_without_an_expiry_is_never_given_the_requested_one() -> None:
    row = trade(expiry=_ABSENT)
    for spec in (flow_spec(), flow_spec(expiry=EXPIRY)):
        assert flow_error(row, spec=spec).code == "MISSING_REQUIRED_FIELD"


@pytest.mark.parametrize("value", ["garbage", "2026-13-45", "", 20261218, ["2026-12-18"], {"d": 1}, True])
def test_a_gex_row_with_an_unreadable_expiry_is_invalid_not_treated_as_absent(value: object) -> None:
    assert gex_error(gex(expiry=value)).code == "INVALID_RECORD"


def test_a_gex_row_whose_identity_fields_disagree_with_each_other_is_a_mismatch() -> None:
    assert gex_error(gex(ticker="SPY", symbol="QQQ")).code == "QUERY_ROW_MISMATCH"
    assert gex_error(gex(symbol="QQQ", underlying_symbol="SPY")).code == "QUERY_ROW_MISMATCH"


@pytest.mark.parametrize("value", [123, ["SPY"], {"a": 1}, True])
def test_a_gex_row_with_a_non_text_ticker_is_invalid(value: object) -> None:
    assert gex_error(gex(ticker=value)).code == "INVALID_RECORD"


def test_a_gex_page_with_a_non_object_row_or_too_many_rows_is_malformed_and_never_partial() -> None:
    adapter, transport, _ = adapter_for(response({"data": [gex(strike="590"), "not a row"]}))
    with pytest.raises(UnusualWhalesAdapterError) as raised:
        adapter.fetch_gex(gex_spec())
    assert raised.value.code == "MALFORMED_RESPONSE" and len(transport.calls) == 1
    adapter, transport, _ = adapter_for(response({"data": [gex(strike="590"), gex(strike="600"), gex(strike="610")]}))
    with pytest.raises(UnusualWhalesAdapterError) as raised:
        adapter.fetch_gex(gex_spec(limit=2))
    assert raised.value.code == "MALFORMED_RESPONSE" and len(transport.calls) == 1


def test_a_flow_page_with_a_non_object_row_is_malformed_and_never_partial() -> None:
    adapter, transport, _ = adapter_for(response({"data": [trade(id="n1"), 7]}))
    with pytest.raises(UnusualWhalesAdapterError) as raised:
        adapter.fetch_options_flow(flow_spec())
    assert raised.value.code == "MALFORMED_RESPONSE" and len(transport.calls) == 1


def test_exact_decimal_text_survives_for_price_strike_and_a_fractional_size() -> None:
    adapter, _, _ = adapter_for(response(
        b'{"data":[{"id":"d1","underlying_symbol":"SPY","option_chain_id":"%s","exchange":"CBOE",'
        b'"executed_at":"%s","expiry":"2026-12-18","strike":"452.5","option_type":"put",'
        b'"price":"1.2345678","size":2.5,"tags":["bid_side"]}]}' % (CHAIN.encode(), EVENT_TIME.encode())
    ))
    (record,) = adapter.fetch_options_flow(flow_spec())
    assert (str(record.price), str(record.strike), str(record.size)) == ("1.2345678", "452.5", "2.5")


def test_a_number_with_an_absurd_number_of_significant_digits_is_refused() -> None:
    for field in ("price", "strike", "size"):
        with pytest.raises(UnusualWhalesAdapterError):
            flow(trade(**{field: "1." + "2" * 48}))


@pytest.mark.parametrize("entitlement", list(Entitlement))
def test_the_caller_pinned_entitlement_is_carried_unchanged_to_the_record_and_the_stamp(
    entitlement: Entitlement,
) -> None:
    adapter, _, _ = adapter_for(response({"data": [trade()]}))
    (record,) = adapter.fetch_options_flow(flow_spec(entitlement=entitlement))
    assert record.entitlement is entitlement
    assert to_option_print(record, binding(), SIDE_TABLE).option_print.stamp.entitlement is entitlement


@pytest.mark.parametrize("header", ["X-Request-Id", "x-request-id", "X-REQUEST-ID"])
def test_the_request_id_header_is_found_case_insensitively(header: str) -> None:
    (record,) = flow(trade(), **{header: "req_1234-AB"})
    assert record.request_id == "req_1234-AB"
    assert to_option_print(record, binding(), SIDE_TABLE).option_print.stamp.request_id == "req_1234-AB"


@pytest.mark.parametrize("header", ["x-trace-id", "x-trace", "request-id", "x-amzn-requestid", "traceparent", "x-correlation-id", "x-requestid"])
def test_no_other_header_is_taken_as_the_request_id(header: str) -> None:
    (record,) = flow(trade(), **{header: "req_1234-AB"})
    assert record.request_id is None


@pytest.mark.parametrize("value", ["has space", "a" * 65, "café", "", "x\ny", "../etc", "id;drop"])
def test_an_unsafe_request_id_is_dropped_not_stored(value: str) -> None:
    (record,) = flow(trade(), **{"x-request-id": value})
    assert record.request_id is None


def test_a_trade_record_cannot_be_rebuilt_with_ingest_or_as_of_before_its_event_time() -> None:
    (record,) = flow(trade())
    with pytest.raises(UnusualWhalesAdapterError) as raised:
        dataclasses.replace(record, ingest_time_ns=record.event_time_ns - 1)
    assert raised.value.code == "INVALID_RECORD"
    with pytest.raises(UnusualWhalesAdapterError) as raised:
        dataclasses.replace(record, query_as_of_ns=record.event_time_ns - 1)
    assert raised.value.code == "INVALID_RECORD"


# ----------------------------------- second round: mapping provenance, errors and gex_levels oracle


class ClockFailsTransport(FakeTransport):
    def __init__(self, responses: list[UnusualWhalesHTTPResponse | BaseException], value: object) -> None:
        super().__init__(responses)
        self.value = value

    def clock_ns(self) -> int:
        self.clock_calls += 1
        if isinstance(self.value, BaseException):
            raise self.value
        return self.value  # type: ignore[return-value]


def test_a_flow_spec_refuses_a_datetime_where_a_date_is_required() -> None:
    with pytest.raises(UnusualWhalesAdapterError) as raised:
        flow_spec(expiry=datetime(2026, 12, 18, tzinfo=UTC))
    assert raised.value.code == "INVALID_SPEC"


@pytest.mark.parametrize("bad", ["binding", object(), {"multiplier": Decimal(100)}, 100, ("SPY", Decimal(100))])
def test_the_mapping_refuses_a_binding_that_is_not_a_contract_binding(bad: object) -> None:
    with pytest.raises(UnusualWhalesAdapterError) as raised:
        to_option_print(flow(trade())[0], bad, SIDE_TABLE)  # type: ignore[arg-type]
    assert raised.value.code == "INVALID_SPEC"


@pytest.mark.parametrize("table", [
    {"ask_side": TradeSide.SELL, "bid_side": TradeSide.SELL},
    {"ask_side": TradeSide.SELL, "bid_side": TradeSide.BUY},
    {"ask_side": TradeSide.BUY, "bid_side": TradeSide.BUY},
    {"ask_side": TradeSide.BUY, "bid_side": None},
    {"ask_side": None, "bid_side": TradeSide.SELL},
])
def test_both_entries_of_the_side_table_must_be_the_documented_aggressor_mapping(table: object) -> None:
    for tags in (["ask_side"], ["bid_side"]):
        with pytest.raises(UnusualWhalesAdapterError) as raised:
            to_option_print(flow(trade(tags=tags))[0], binding(), table)  # type: ignore[arg-type]
        assert raised.value.code == "INVALID_SPEC"


def test_a_mapped_print_is_available_only_from_the_moment_it_was_received() -> None:
    stamp = mapped(trade()).option_print.stamp
    assert stamp.event_ns == EVENT_NS and stamp.ingest_ns == INGEST_NS
    assert stamp.available_ns == INGEST_NS > stamp.event_ns


@pytest.mark.parametrize("changes", [
    {"currency": "usd"}, {"currency": ""}, {"currency": None}, {"currency": "USDX"},
    {"source_trade": "x"}, {"source_trade": None}, {"option_print": "x"}, {"option_print": None},
    {"multiplier_source": "default"}, {"multiplier_source": "exchange"}, {"expiry_source": "inferred"},
    {"expiry_source": None},
])
def test_the_mapped_wrapper_refuses_provenance_it_cannot_vouch_for(changes: dict[str, object]) -> None:
    good = mapped(trade())
    with pytest.raises(UnusualWhalesAdapterError) as raised:
        dataclasses.replace(good, **changes)
    assert raised.value.code == "INVALID_RECORD"


@pytest.mark.parametrize("code", ["OTHER", "", "not_configured", "RATE_LIMITED ", "HTTP", "UNKNOWN", "ERROR"])
def test_any_code_outside_the_closed_vocabulary_becomes_a_plain_http_status_failure(code: str) -> None:
    assert UnusualWhalesAdapterError(code).code == "HTTP_STATUS"


@pytest.mark.parametrize("value", [True, False, 1.0, "1", None, 0, -1])
def test_a_receipt_clock_that_is_not_a_genuine_positive_int_is_rejected(value: object) -> None:
    transport = ClockFailsTransport([response({"data": [trade()]})], value)
    adapter = build_adapter(resolve_secret=FakeResolver(), transport=transport)
    with pytest.raises(UnusualWhalesAdapterError):
        adapter.fetch_options_flow(flow_spec())


def test_a_receipt_clock_that_raises_becomes_a_content_free_adapter_error() -> None:
    transport = ClockFailsTransport([response({"data": [trade()]})], RuntimeError(f"clock {KEY} {CANARY}"))
    adapter = build_adapter(resolve_secret=FakeResolver(), transport=transport)
    with pytest.raises(UnusualWhalesAdapterError) as raised:
        adapter.fetch_options_flow(flow_spec())
    err = raised.value
    assert err.code in ERROR_CODES and err.__cause__ is None
    rendered = "".join(traceback.format_exception(type(err), err, err.__traceback__))
    assert KEY not in rendered and CANARY not in rendered


def _failure_cases() -> list[tuple[str, Callable[[], UnusualWhalesAdapterError]]]:
    def captured(build: Callable[[], Any]) -> UnusualWhalesAdapterError:
        with pytest.raises(UnusualWhalesAdapterError) as raised:
            build()
        return raised.value

    def run(*scripted: UnusualWhalesHTTPResponse | BaseException, resolver: FakeResolver | None = None) -> Any:
        adapter, _, _ = adapter_for(*scripted, resolver=resolver)
        return adapter.fetch_options_flow(flow_spec())

    return [
        ("transport error", lambda: captured(lambda: run(RuntimeError(f"boom {KEY} {CANARY}")))),
        ("timeout", lambda: captured(lambda: run(TimeoutError(f"slow {KEY} {CANARY}")))),
        ("resolver error", lambda: captured(lambda: run(response({"data": []}), resolver=FakeResolver(error=RuntimeError(f"{KEY} {CANARY}"))))),
        ("undecodable body", lambda: captured(lambda: run(response(b'{"data": [' + CANARY.encode())))),
        ("non-utf8 body", lambda: captured(lambda: run(response(b"\xff\xfe" + CANARY.encode())))),
        ("record refused by its own invariants", lambda: captured(lambda: run(response({"data": [trade(price="0", note=CANARY)]})))),
        ("negative strike", lambda: captured(lambda: run(response({"data": [trade(strike="-5", note=CANARY)]})))),
        ("http status", lambda: captured(lambda: run(response({"error": CANARY}, status=500)))),
    ]


@pytest.mark.parametrize(("name", "make_error"), _failure_cases(), ids=[n for n, _ in _failure_cases()])
def test_every_failure_is_content_free_and_carries_no_chained_cause(
    name: str, make_error: Callable[[], UnusualWhalesAdapterError],
) -> None:
    err = make_error()
    assert err.code in ERROR_CODES
    assert err.__cause__ is None and (err.__context__ is None or err.__suppress_context__)
    rendered = "".join(traceback.format_exception(type(err), err, err.__traceback__))
    assert KEY not in rendered and CANARY not in rendered


# ---- gex_levels checked against an independent reference implementation


def _gex_row(
    strike: int, oi: tuple[int, int], vol: tuple[int, int], *, ticker: str = "SPY", event_ns: int = EVENT_NS,
    expiry: date = EXPIRY,
) -> UnusualWhalesGexRowV1:
    return UnusualWhalesGexRowV1(
        ticker=ticker, strike=Decimal(strike), expiry=expiry,
        call_gamma_oi=Decimal(oi[0]), put_gamma_oi=Decimal(oi[1]),
        call_gamma_vol=Decimal(vol[0]), put_gamma_vol=Decimal(vol[1]),
        price=None, event_time_ns=event_ns, ingest_time_ns=INGEST_NS,
    )


def _reference(rows: list[tuple[int, int, int]]) -> dict[str, Any]:
    rows = sorted(rows)
    nets = [call + put for _, call, put in rows]
    flips: list[tuple[int, int]] = []
    for index in range(len(rows) - 1):
        left, right = nets[index], nets[index + 1]
        if left == 0:
            flips.append((rows[index][0], rows[index][0]))
        elif left * right < 0:
            flips.append((rows[index][0], rows[index + 1][0]))
    if nets[-1] == 0:
        flips.append((rows[-1][0], rows[-1][0]))
    calls = [call for _, call, _ in rows if call > 0]
    puts = [put for _, _, put in rows if put < 0]
    return {
        "flips": flips,
        "best_call": max(calls) if calls else None,
        "best_put": min(puts) if puts else None,
        "magnitudes": sorted((abs(n) for n in nets), reverse=True),
        "by_strike": {strike: (call, put, call + put) for strike, call, put in rows},
    }


@pytest.mark.parametrize("seed", range(60))
def test_gex_levels_agree_with_an_independent_reference_on_random_sets(seed: int) -> None:
    rng = random.Random(seed)
    strikes = sorted(rng.sample(range(500, 700, 5), rng.randint(1, 7)))
    values = list(range(-6, 7))
    oi = {s: (rng.choice(values), rng.choice(values)) for s in strikes}
    vol = {s: (rng.choice(values) * 3, rng.choice(values) * 7) for s in strikes}
    rows = [_gex_row(s, oi[s], vol[s]) for s in strikes]
    rng.shuffle(rows)
    for basis, table in (("oi", oi), ("volume", vol)):
        ref = _reference([(s, table[s][0], table[s][1]) for s in strikes])
        top_n = rng.randint(1, 9)
        levels = gex_levels(tuple(rows), basis=basis, top_n=top_n)  # type: ignore[arg-type]
        assert levels.basis == basis and levels.ticker == "SPY" and levels.expiry == EXPIRY
        assert levels.as_of_ns == EVENT_NS and levels.source == "unusual_whales_aggregate"
        assert list(levels.zero_gamma_flips) == [(Decimal(a), Decimal(b)) for a, b in ref["flips"]]
        if ref["best_call"] is None:
            assert levels.call_wall is None
        else:
            assert levels.call_wall is not None and ref["by_strike"][int(levels.call_wall)][0] == ref["best_call"]
        if ref["best_put"] is None:
            assert levels.put_wall is None
        else:
            assert levels.put_wall is not None and ref["by_strike"][int(levels.put_wall)][1] == ref["best_put"]
        assert len(levels.top_strikes) == min(top_n, len(strikes)) == len(set(levels.top_strikes))
        assert all(int(s) in strikes for s in levels.top_strikes)
        assert [abs(ref["by_strike"][int(s)][2]) for s in levels.top_strikes] == ref["magnitudes"][: len(levels.top_strikes)]


def test_gex_levels_uses_the_event_time_of_the_data_not_the_receipt_time() -> None:
    rows = (_gex_row(590, (1, -2), (1, -2)), _gex_row(600, (3, -1), (3, -1)))
    levels = gex_levels(rows, basis="oi")
    assert levels.as_of_ns == EVENT_NS != INGEST_NS


def test_gex_levels_sums_exactly_even_beyond_the_default_decimal_precision() -> None:
    low = Decimal("1.000000000000000000000000000001")
    high = Decimal("1.000000000000000000000000000002")
    rows = (
        UnusualWhalesGexRowV1(
            ticker="SPY", strike=Decimal(590), expiry=EXPIRY, call_gamma_oi=low, put_gamma_oi=Decimal(0),
            call_gamma_vol=low, put_gamma_vol=Decimal(0), price=None, event_time_ns=EVENT_NS, ingest_time_ns=INGEST_NS,
        ),
        UnusualWhalesGexRowV1(
            ticker="SPY", strike=Decimal(600), expiry=EXPIRY, call_gamma_oi=high, put_gamma_oi=Decimal(0),
            call_gamma_vol=high, put_gamma_vol=Decimal(0), price=None, event_time_ns=EVENT_NS, ingest_time_ns=INGEST_NS,
        ),
    )
    assert gex_levels(rows, basis="oi").top_strikes == (Decimal(600), Decimal(590))
    assert gex_levels(rows, basis="oi").call_wall == Decimal(600)


def test_gex_levels_refuse_a_list_and_rows_of_different_tickers_or_times() -> None:
    rows = (_gex_row(590, (1, -2), (1, -2)), _gex_row(600, (3, -1), (3, -1)))
    with pytest.raises(UnusualWhalesAdapterError) as raised:
        gex_levels(list(rows), basis="oi")  # type: ignore[arg-type]
    assert raised.value.code == "INVALID_GEX_SET"
    for mixed in (
        (_gex_row(590, (1, -2), (1, -2)), _gex_row(600, (3, -1), (3, -1), ticker="QQQ")),
        (_gex_row(590, (1, -2), (1, -2)), _gex_row(600, (3, -1), (3, -1), event_ns=EVENT_NS - 1)),
    ):
        with pytest.raises(UnusualWhalesAdapterError) as raised:
            gex_levels(mixed, basis="oi")
        assert raised.value.code == "INVALID_GEX_SET"


def test_gex_levels_top_n_larger_than_the_set_returns_the_whole_set() -> None:
    rows = level_rows()
    full = gex_levels(rows, basis="oi", top_n=100).top_strikes
    assert len(full) == 4 and set(full) == {Decimal(s) for s in (590, 595, 600, 605)}
    assert gex_levels(rows, basis="oi", top_n=2).top_strikes == full[:2]


def test_gex_levels_report_the_ticker_and_expiry_of_the_rows_they_were_given() -> None:
    other = date(2026, 12, 19)
    rows = (
        _gex_row(390, (1, -2), (1, -2), ticker="QQQ", expiry=other),
        _gex_row(400, (3, -1), (3, -1), ticker="QQQ", expiry=other),
    )
    levels = gex_levels(rows, basis="volume")
    assert (levels.ticker, levels.expiry, levels.basis) == ("QQQ", other, "volume")
