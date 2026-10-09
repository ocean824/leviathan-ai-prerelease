from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import date
from decimal import Decimal

import pytest

from leviathan_core.flow_radar import Entitlement, TradeSide
from leviathan_market_data.providers.wave34.unusual_whales import (
    CAPABILITIES,
    CREDENTIAL_NAMES,
    PROVIDER_ID,
    ContractBindingV1,
    FlowReadSpecV1,
    GexReadSpecV1,
    MappedOptionPrintV1,
    UnusualWhalesAdapterError,
    UnusualWhalesGexRowV1,
    UnusualWhalesHTTPResponse,
    UnusualWhalesOptionTradeV1,
    build_adapter,
    gex_levels,
    to_option_print,
)

TOKEN = "synthetic-unusual-whales-token"
INGEST_NS = 1_791_316_801_000_000_000
AS_OF_NS = 1_791_316_800_000_000_000


class FakeTransport:
    def __init__(
        self, body: object, *, status: int = 200, headers: Mapping[str, str] | None = None
    ):
        self.body = body
        self.status = status
        self.headers = dict(headers or {})
        self.requests: list[dict[str, object]] = []

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
        self.requests.append(
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
        body = self.body if isinstance(self.body, bytes) else json.dumps(self.body).encode()
        return UnusualWhalesHTTPResponse(self.status, self.headers, body)

    def clock_ns(self) -> int:
        return INGEST_NS


def _adapter(transport: FakeTransport, *, key: str = TOKEN):
    names: list[str] = []

    def resolve(name: str) -> str:
        names.append(name)
        return key

    return build_adapter(resolve_secret=resolve, transport=transport), names


def _flow_item(**changes: object) -> dict[str, object]:
    row: dict[str, object] = {
        "id": "trade-123",
        "option_chain_id": "NVDA261016C00150000",
        "underlying_symbol": "NVDA",
        "expiry": "2026-10-16T00:00:00.000Z",
        "strike": "150.000",
        "option_type": "call",
        "exchange": "MXOP",
        "executed_at": "2026-10-06T19:59:59.123456789Z",
        "price": "2.75",
        "size": 3,
        "tags": ["ask_side", "bullish"],
        "premium": "825.00",
        "theo": "2.70",
    }
    row.update(changes)
    return row


def _flow_spec(*, as_of: int = AS_OF_NS):
    return FlowReadSpecV1(
        ticker="NVDA",
        as_of_ns=as_of,
        limit=10,
        session_id="2026-10-06-RTH",
        entitlement=Entitlement.ENTITLED,
    )


def _flow_spec_for_expiry():
    return FlowReadSpecV1(
        ticker="NVDA",
        as_of_ns=AS_OF_NS,
        limit=10,
        session_id="2026-10-06-RTH",
        entitlement=Entitlement.ENTITLED,
        expiry=date(2026, 10, 16),
    )


def _binding(
    *, contract: str = "NVDA261016C00150000", underlying: str = "NVDA"
) -> ContractBindingV1:
    return ContractBindingV1(
        option_chain_id=contract,
        underlying=underlying,
        multiplier=Decimal("100"),
        currency="USD",
    )


def _gex_item(strike: str, call_oi: str, put_oi: str, call_vol: str, put_vol: str):
    return {
        "strike": strike,
        "call_gamma_oi": call_oi,
        "put_gamma_oi": put_oi,
        "call_gamma_vol": call_vol,
        "put_gamma_vol": put_vol,
        "price": "150.25",
        "time": "2026-10-06T19:59:00.123456789Z",
    }


def test_registration_and_injected_secret_header_are_exact() -> None:
    transport = FakeTransport({"data": []})
    adapter, names = _adapter(transport)
    spec = _flow_spec()

    assert PROVIDER_ID == "unusual_whales"
    assert frozenset({"OPTIONS_FLOW", "GEX"}) == CAPABILITIES
    assert CREDENTIAL_NAMES == ("unusual_whales_api_key",)
    assert adapter.fetch_options_flow(spec) == ()
    assert names == [CREDENTIAL_NAMES[0]]
    assert transport.requests[0]["headers"] == {"Authorization": f"Bearer {TOKEN}"}
    assert transport.requests[0]["allow_redirects"] is False
    assert "older_than" in transport.requests[0]["params"]
    assert TOKEN not in repr(adapter)


def test_flow_fetch_preserves_wire_fields_and_separate_times() -> None:
    transport = FakeTransport({"data": [_flow_item()]}, headers={"x-request-id": "req-01"})
    adapter, _ = _adapter(transport)

    trades = adapter.fetch_options_flow(_flow_spec())

    assert len(trades) == 1
    trade = trades[0]
    assert type(trade) is UnusualWhalesOptionTradeV1
    assert trade.trade_id == "trade-123"
    assert trade.option_chain_id == "NVDA261016C00150000"
    assert trade.expiry == date(2026, 10, 16)
    assert trade.strike == Decimal("150.000")
    assert trade.option_type == "call"
    assert trade.exchange == "MXOP"
    assert trade.executed_at == "2026-10-06T19:59:59.123456789Z"
    assert trade.price == Decimal("2.75")
    assert trade.size == Decimal(3)
    assert trade.tags == ("ask_side", "bullish")
    assert trade.event_time_ns == 1_791_316_799_123_456_789
    assert trade.ingest_time_ns == INGEST_NS
    assert trade.request_id == "req-01"
    assert trade.query_ticker == "NVDA"
    assert trade.query_as_of_ns == AS_OF_NS
    assert trade.query_expiry is None


def test_flow_expiry_filter_is_explicit_and_recorded_as_mapping_provenance() -> None:
    transport = FakeTransport({"data": [_flow_item()]})
    adapter, _ = _adapter(transport)

    trade = adapter.fetch_options_flow(_flow_spec_for_expiry())[0]
    mapped = to_option_print(
        trade,
        _binding(),
        {"ask_side": TradeSide.BUY, "bid_side": TradeSide.SELL},
    )

    assert transport.requests[0]["params"]["expirations[]"] == "2026-10-16"
    assert trade.query_expiry == date(2026, 10, 16)
    assert mapped.expiry_source == "request_filter"


@pytest.mark.parametrize(
    "identity", [{"expiry": "2026-10-23T00:00:00.000Z"}, {"ticker": "AMD"}, {"symbol": "AMD"}]
)
def test_flow_rejects_response_identity_that_conflicts_with_request(
    identity: dict[str, str],
) -> None:
    transport = FakeTransport({"data": [_flow_item() | identity]})
    adapter, _ = _adapter(transport)

    with pytest.raises(UnusualWhalesAdapterError) as exc:
        adapter.fetch_options_flow(_flow_spec_for_expiry())

    assert exc.value.code == "QUERY_ROW_MISMATCH"


def test_to_option_print_uses_exact_binding_side_table_and_provenance() -> None:
    transport = FakeTransport({"data": [_flow_item()]})
    adapter, _ = _adapter(transport)
    trade = adapter.fetch_options_flow(_flow_spec())[0]

    mapped = to_option_print(
        trade,
        _binding(),
        {"ask_side": TradeSide.BUY, "bid_side": TradeSide.SELL},
    )

    assert type(mapped) is MappedOptionPrintV1
    assert mapped.option_print.ticker == "NVDA"
    assert mapped.option_print.expiry == date(2026, 10, 16)
    assert mapped.option_print.strike == Decimal("150.000")
    assert mapped.option_print.trade_side is TradeSide.BUY
    assert mapped.option_print.price == Decimal("2.75")
    assert mapped.option_print.size == Decimal(3)
    assert mapped.option_print.multiplier == Decimal("100")
    assert mapped.option_print.stamp.venue == "MXOP"
    assert mapped.option_print.stamp.native_record_key == "trade-123"
    assert mapped.option_print.stamp.event_ns == trade.event_time_ns
    assert mapped.option_print.stamp.available_ns == INGEST_NS
    assert mapped.option_print.stamp.ingest_ns == INGEST_NS
    assert mapped.option_print.stamp.entitlement is Entitlement.ENTITLED
    assert mapped.currency == "USD"
    assert mapped.multiplier_source == "contract_binding"
    assert mapped.expiry_source == "provider_row"
    assert mapped.source_trade.option_chain_id == trade.option_chain_id


def test_mapped_wrapper_rejects_non_string_currency_as_typed_error() -> None:
    transport = FakeTransport({"data": [_flow_item()]})
    adapter, _ = _adapter(transport)
    trade = adapter.fetch_options_flow(_flow_spec())[0]
    mapped = to_option_print(
        trade,
        _binding(),
        {"ask_side": TradeSide.BUY, "bid_side": TradeSide.SELL},
    )

    with pytest.raises(UnusualWhalesAdapterError) as exc:
        MappedOptionPrintV1(
            option_print=mapped.option_print,
            source_trade=mapped.source_trade,
            currency=None,  # type: ignore[arg-type]
        )

    assert exc.value.code == "INVALID_RECORD"


def test_bid_side_tag_maps_to_sell() -> None:
    transport = FakeTransport({"data": [_flow_item(tags=["bid_side"])]})
    adapter, _ = _adapter(transport)
    trade = adapter.fetch_options_flow(_flow_spec())[0]

    mapped = to_option_print(
        trade,
        _binding(),
        {"ask_side": TradeSide.BUY, "bid_side": TradeSide.SELL},
    )

    assert mapped.option_print.trade_side is TradeSide.SELL


@pytest.mark.parametrize(
    "tags",
    [[], ["bullish"], ["ask_side", "bid_side"], ["ask_side", "ask_side"], ["unknown_side"]],
)
def test_to_option_print_rejects_absent_ambiguous_or_unknown_side(tags: object) -> None:
    transport = FakeTransport({"data": [_flow_item(tags=tags)]})
    adapter, _ = _adapter(transport)
    trade = adapter.fetch_options_flow(_flow_spec())[0]

    with pytest.raises(UnusualWhalesAdapterError) as exc:
        to_option_print(
            trade,
            _binding(),
            {"ask_side": TradeSide.BUY, "bid_side": TradeSide.SELL},
        )

    assert exc.value.code == "SIDE_UNDETERMINED"
    assert exc.value.args == ("SIDE_UNDETERMINED",)


def test_to_option_print_rejects_wrong_contract_or_underlying_binding() -> None:
    transport = FakeTransport({"data": [_flow_item()]})
    adapter, _ = _adapter(transport)
    trade = adapter.fetch_options_flow(_flow_spec())[0]

    for binding in (
        _binding(contract="OTHER261016C00150000"),
        _binding(underlying="AMD"),
    ):
        with pytest.raises(UnusualWhalesAdapterError) as exc:
            to_option_print(
                trade,
                binding,
                {"ask_side": TradeSide.BUY, "bid_side": TradeSide.SELL},
            )
        assert exc.value.code == "INSTRUMENT_BINDING_MISMATCH"


def test_to_option_print_never_defaults_a_missing_multiplier_binding() -> None:
    transport = FakeTransport({"data": [_flow_item()]})
    adapter, _ = _adapter(transport)
    trade = adapter.fetch_options_flow(_flow_spec())[0]

    with pytest.raises(UnusualWhalesAdapterError) as exc:
        to_option_print(
            trade,
            None,
            {"ask_side": TradeSide.BUY, "bid_side": TradeSide.SELL},
        )

    assert exc.value.code == "MISSING_MULTIPLIER"


def test_missing_required_wire_row_aborts_whole_batch_without_partial_tuple() -> None:
    transport = FakeTransport(
        {"data": [_flow_item(id="trade-a"), _flow_item(id="trade-b", exchange=None)]}
    )
    adapter, _ = _adapter(transport)

    with pytest.raises(UnusualWhalesAdapterError) as exc:
        adapter.fetch_options_flow(_flow_spec())

    assert exc.value.code == "MISSING_REQUIRED_FIELD"


def test_event_after_as_of_is_not_returned() -> None:
    transport = FakeTransport({"data": [_flow_item(executed_at="2026-10-06T20:00:01Z")]})
    adapter, _ = _adapter(transport)

    assert adapter.fetch_options_flow(_flow_spec()) == ()


def test_gex_returns_distinct_aggregate_rows_with_explicit_missing_fields() -> None:
    transport = FakeTransport({"data": [_gex_item("148", "12.5", "-3", "8", "-2")]})
    adapter, _ = _adapter(transport)
    spec = GexReadSpecV1(
        ticker="NVDA",
        expiry=date(2026, 10, 16),
        market_date=date(2026, 10, 6),
        as_of_ns=AS_OF_NS,
        limit=10,
        page=0,
    )

    rows = adapter.fetch_gex(spec)

    assert len(rows) == 1
    row = rows[0]
    assert type(row) is UnusualWhalesGexRowV1
    assert row.strike == Decimal(148)
    assert row.expiry == date(2026, 10, 16)
    assert row.call_gamma_oi == Decimal("12.5")
    assert row.put_gamma_oi == Decimal("-3")
    assert row.call_gamma_vol == Decimal(8)
    assert row.put_gamma_vol == Decimal(-2)
    assert row.event_time_ns == 1_791_316_740_123_456_789
    assert row.ingest_time_ns == INGEST_NS
    assert row.expiry_source == "request_filter"
    assert row.ticker_source == "request_path"
    assert row.missing_fields == ("contract", "venue", "exposure_units")
    assert row.gex001_chain_evidence is False
    assert transport.requests[0]["params"] == {
        "expirations[]": "2026-10-16",
        "date": "2026-10-06",
        "limit": "10",
        "page": "0",
    }


def test_gex_levels_are_provider_aggregate_and_deterministic() -> None:
    rows = (
        UnusualWhalesGexRowV1(
            "NVDA",
            Decimal(100),
            date(2026, 10, 16),
            Decimal(4),
            Decimal(-1),
            Decimal(1),
            Decimal(-4),
            None,
            10,
            11,
        ),
        UnusualWhalesGexRowV1(
            "NVDA",
            Decimal(110),
            date(2026, 10, 16),
            Decimal(9),
            Decimal(-2),
            Decimal(5),
            Decimal(-1),
            None,
            10,
            11,
        ),
        UnusualWhalesGexRowV1(
            "NVDA",
            Decimal(120),
            date(2026, 10, 16),
            Decimal(2),
            Decimal(-8),
            Decimal(2),
            Decimal(-5),
            None,
            10,
            11,
        ),
    )

    result = gex_levels(rows, basis="oi", top_n=2)
    permuted = gex_levels((rows[2], rows[0], rows[1]), basis="oi", top_n=2)

    assert result == permuted
    assert result.source == "unusual_whales_aggregate"
    assert result.exposure_units is None
    assert result.gex001_chain_evidence is False
    assert result.call_wall == Decimal(110)
    assert result.put_wall == Decimal(120)
    assert result.zero_gamma_flips == ((Decimal(110), Decimal(120)),)
    assert result.top_strikes == (Decimal(110), Decimal(120))


def test_gex_level_ranking_preserves_decimal_digits_beyond_default_precision() -> None:
    rows = (
        UnusualWhalesGexRowV1(
            "NVDA",
            Decimal(590),
            date(2026, 10, 16),
            Decimal("1.000000000000000000000000000001"),
            Decimal(0),
            Decimal(0),
            Decimal(0),
            None,
            10,
            11,
        ),
        UnusualWhalesGexRowV1(
            "NVDA",
            Decimal(600),
            date(2026, 10, 16),
            Decimal("1.000000000000000000000000000002"),
            Decimal(0),
            Decimal(0),
            Decimal(0),
            None,
            10,
            11,
        ),
    )

    result = gex_levels(rows, basis="oi", top_n=2)

    assert result.top_strikes == (Decimal(600), Decimal(590))
    assert result.call_wall == Decimal(600)


def test_429_is_content_free_and_not_retried() -> None:
    transport = FakeTransport({"error": TOKEN}, status=429, headers={"Retry-After": "7"})
    adapter, _ = _adapter(transport)

    with pytest.raises(UnusualWhalesAdapterError) as exc:
        adapter.fetch_options_flow(_flow_spec())

    assert exc.value.code == "RATE_LIMITED"
    assert exc.value.retry_after_seconds == 7
    assert TOKEN not in str(exc.value)
    assert TOKEN not in repr(exc.value)
    assert all(TOKEN not in str(arg) for arg in exc.value.args)
    assert len(transport.requests) == 1


def test_unconfigured_secret_performs_no_transport_call() -> None:
    transport = FakeTransport({"data": []})
    adapter = build_adapter(resolve_secret=lambda _name: "", transport=transport)

    with pytest.raises(UnusualWhalesAdapterError) as exc:
        adapter.fetch_options_flow(_flow_spec())

    assert exc.value.code == "NOT_CONFIGURED"
    assert transport.requests == []


@pytest.mark.parametrize("key", [f"{TOKEN}\x00", f"{TOKEN}\t", f"{TOKEN}\x07", f"{TOKEN}\x7f"])
def test_credentials_with_control_characters_never_reach_transport(key: str) -> None:
    transport = FakeTransport({"data": []})
    adapter, _ = _adapter(transport, key=key)

    with pytest.raises(UnusualWhalesAdapterError) as exc:
        adapter.fetch_options_flow(_flow_spec())

    assert exc.value.code == "NOT_CONFIGURED"
    assert transport.requests == []


def test_transport_exception_text_never_escapes() -> None:
    class RaisingTransport(FakeTransport):
        def get(self, *_args: object, **_kwargs: object) -> UnusualWhalesHTTPResponse:
            raise RuntimeError(f"{TOKEN} https://example.test/?token={TOKEN}")

    adapter, _ = _adapter(RaisingTransport({}))

    with pytest.raises(UnusualWhalesAdapterError) as exc:
        adapter.fetch_options_flow(_flow_spec())

    assert exc.value.code == "HTTP_STATUS"
    assert TOKEN not in str(exc.value)
    assert TOKEN not in repr(exc.value)
    assert all(TOKEN not in str(arg) for arg in exc.value.args)


def test_invalid_json_and_oversize_responses_fail_closed() -> None:
    for response_body, code in (
        (b"not json", "MALFORMED_RESPONSE"),
        (b"x" * 2_097_153, "RESPONSE_TOO_LARGE"),
    ):
        adapter, _ = _adapter(FakeTransport(response_body))
        with pytest.raises(UnusualWhalesAdapterError) as exc:
            adapter.fetch_options_flow(_flow_spec())
        assert exc.value.code == code


@pytest.mark.parametrize(
    "status,code",
    [
        (301, "REDIRECT_DENIED"),
        (401, "AUTH_DENIED"),
        (500, "HTTP_STATUS"),
        (503, "SOURCE_NOT_READY"),
    ],
)
def test_status_errors_are_sanitized(status: int, code: str) -> None:
    adapter, _ = _adapter(FakeTransport({"secret": TOKEN}, status=status))

    with pytest.raises(UnusualWhalesAdapterError) as exc:
        adapter.fetch_options_flow(_flow_spec())

    assert exc.value.code == code
    assert TOKEN not in str(exc.value)


def test_gex_as_of_filters_future_calculations_and_does_not_auto_page() -> None:
    transport = FakeTransport(
        {"data": [_gex_item("148", "12", "-3", "8", "-2"), _gex_item("150", "2", "-1", "1", "-1")]}
    )
    adapter, _ = _adapter(transport)
    spec = GexReadSpecV1(
        ticker="NVDA",
        expiry=date(2026, 10, 16),
        market_date=date(2026, 10, 6),
        as_of_ns=1_791_316_000_000_000_000,
        limit=10,
        page=2,
    )

    assert adapter.fetch_gex(spec) == ()
    assert len(transport.requests) == 1


@pytest.mark.parametrize(
    "identity", [{"expiry": "2026-10-23"}, {"ticker": "AMD"}, {"symbol": "AMD"}]
)
def test_gex_rejects_identity_that_conflicts_with_request_binding(identity: dict[str, str]) -> None:
    transport = FakeTransport({"data": [_gex_item("148", "12", "-3", "8", "-2") | identity]})
    adapter, _ = _adapter(transport)
    spec = GexReadSpecV1(
        ticker="NVDA",
        expiry=date(2026, 10, 16),
        market_date=date(2026, 10, 6),
        as_of_ns=AS_OF_NS,
        limit=10,
    )

    with pytest.raises(UnusualWhalesAdapterError) as exc:
        adapter.fetch_gex(spec)

    assert exc.value.code == "QUERY_ROW_MISMATCH"


def test_reflected_secret_is_not_exposed_as_request_id_or_record() -> None:
    transport = FakeTransport({"data": [_flow_item()]}, headers={"x-request-id": TOKEN})
    adapter, _ = _adapter(transport)
    trade = adapter.fetch_options_flow(_flow_spec())[0]

    assert trade.request_id is None
    assert TOKEN not in repr(trade)
