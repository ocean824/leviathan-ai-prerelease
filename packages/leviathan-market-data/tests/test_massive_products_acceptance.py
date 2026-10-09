"""Independent offline acceptance for DATA-003 Massive products."""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from leviathan_market_data.providers.massive import (
    CAPABILITIES,
    CREDENTIAL_NAMES,
    MASSIVE_AGGREGATES_ADJUSTED_DATASET,
    MASSIVE_AGGREGATES_UNADJUSTED_DATASET,
    MASSIVE_BENZINGA_NEWS_DATASET,
    MASSIVE_QUOTES_DATASET,
    MASSIVE_TRADES_DATASET,
    PROVIDER_ID,
    InstrumentBindingV1,
    MassiveAdapterError,
    MassiveAggregateReadSpec,
    MassiveHTTPResponse,
    MassiveNewsReadSpec,
    MassiveReadSpec,
    MassiveStocksHistoricalAdapter,
    SessionResolution,
)
from leviathan_market_data.schema import BarPayload, NewsPayload, QuotePayload, TradePayload
from leviathan_market_data.symbology import InstrumentMapping, MappingRegistry
from leviathan_vault.client import CredentialRef

_KEY = "Q7!xm2V@r9Lp4Kz8BW5&"
_START = datetime(2026, 10, 6, 14, 30, tzinfo=UTC)
_END = _START + timedelta(minutes=5)
_START_NS = 1_791_297_000_000_000_000
_NOW_NS = _START_NS + 5_000_000_000
_VERSION = "acceptance-map-v1"
_BINDING = InstrumentBindingV1(
    listing_venue="XNAS",
    ticker="AAPL",
    valid_from_ns=_START_NS - 10_000_000_000,
    valid_to_ns=_NOW_NS + 10_000_000_000,
    stable_instrument_id="acceptance-aapl",
)


def _registry() -> MappingRegistry:
    datasets = (
        MASSIVE_TRADES_DATASET,
        MASSIVE_QUOTES_DATASET,
        MASSIVE_AGGREGATES_ADJUSTED_DATASET,
        MASSIVE_AGGREGATES_UNADJUSTED_DATASET,
        MASSIVE_BENZINGA_NEWS_DATASET,
    )
    return MappingRegistry(
        tuple(
            InstrumentMapping(
                provider="massive",
                dataset=dataset,
                venue="XNAS",
                native_symbol="AAPL",
                instrument_id="acceptance-aapl",
                leviathan_symbol="NASDAQ:AAPL:STOCK",
                instrument_type="equity",
                mapping_version=_VERSION,
                tick_size="0.01",
            )
            for dataset in datasets
        )
    )


class _Transport:
    def __init__(self, *responses: MassiveHTTPResponse | Exception) -> None:
        self._responses = list(responses)
        self.calls: list[dict[str, Any]] = []

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
        if not self._responses:
            raise AssertionError("unexpected second request, retry, or pagination")
        response = self._responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class _Credentials:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.references: list[CredentialRef] = []

    def __call__(self, reference: CredentialRef) -> str:
        self.references.append(reference)
        if self.fail:
            raise RuntimeError(f"resolver detail includes {_KEY}")
        return _KEY


class _Sessions:
    def resolve(self, *, venue: str, **kwargs: object) -> SessionResolution:
        del kwargs
        return SessionResolution("acceptance-session", False, venue)


def _response(
    payload: object,
    *,
    status: int = 200,
    headers: Mapping[str, str] | None = None,
) -> MassiveHTTPResponse:
    body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    return MassiveHTTPResponse(status, headers or {"content-type": "application/json"}, body)


def _adapter(
    *responses: MassiveHTTPResponse | Exception,
) -> tuple[MassiveStocksHistoricalAdapter, _Transport, _Credentials]:
    transport = _Transport(*responses)
    credentials = _Credentials()
    adapter = MassiveStocksHistoricalAdapter(
        transport=transport,
        credential_resolver=credentials,
        mapping_registry=_registry(),
        session_resolver=_Sessions(),
        clock_ns=lambda: _NOW_NS,
    )
    return adapter, transport, credentials


def _trade(**overrides: object) -> dict[str, object]:
    row: dict[str, object] = {
        "ticker": "AAPL",
        "sip_timestamp": _START_NS + 123,
        "participant_timestamp": _START_NS,
        "price": "123.4500",
        "size": 2,
        "decimal_size": "0.1234567890123456789012345678901234",
        "exchange": 4,
        "conditions": [1],
        "id": "trade-1",
        "correction": 0,
        "trf_id": None,
    }
    row.update(overrides)
    return row


def _quote(**overrides: object) -> dict[str, object]:
    row: dict[str, object] = {
        "ticker": "AAPL",
        "sip_timestamp": _START_NS + 123,
        "participant_timestamp": _START_NS,
        "sequence_number": 101,
        "bid_exchange": 4,
        "ask_exchange": 7,
        "bid_price": "123.4500",
        "ask_price": "123.5000",
        "bid_size": "10.00",
        "ask_size": "11.00",
        "trf_timestamp": None,
    }
    row.update(overrides)
    return row


def _aggregate(**overrides: object) -> dict[str, object]:
    row: dict[str, object] = {
        "T": "AAPL",
        "o": "123.4500",
        "h": "124.0000",
        "l": "122.5000",
        "c": "123.7500",
        "v": "1000.500",
        "t": _START_NS // 1_000_000,
        "n": 12,
        "vw": "123.6250",
    }
    row.update(overrides)
    return row


def _news(**overrides: object) -> dict[str, object]:
    row: dict[str, object] = {
        "benzinga_id": 7001001,
        "title": "Synthetic AAPL headline",
        "published": "2026-10-06T14:30:00.000000123Z",
        "last_updated": "2026-10-06T14:30:01.000000456Z",
        "tickers": ["AAPL"],
        "author": "Synthetic Author",
        "body": "Synthetic body must not be exposed.",
    }
    row.update(overrides)
    return row


def _read_spec(channel: str, *, limit: int = 10) -> MassiveReadSpec:
    return MassiveReadSpec(
        ticker="AAPL",
        listing_venue="XNAS",
        channel=channel,  # type: ignore[arg-type]
        start=_START,
        end=_END,
        limit=limit,
        mapping_version=_VERSION,
        instrument_binding=_BINDING,
        quote_entitlement_expected=True,
    )


def _aggregate_spec(*, limit: int = 10, entitled: bool = True) -> MassiveAggregateReadSpec:
    return MassiveAggregateReadSpec(
        ticker="AAPL",
        listing_venue="XNAS",
        start=_START,
        end=_END,
        multiplier=1,
        timespan="minute",
        limit=limit,
        mapping_version=_VERSION,
        instrument_binding=_BINDING,
        adjusted=True,
        stocks_entitlement_expected=entitled,
    )


def _news_spec(*, entitled: bool = True, limit: int = 10) -> MassiveNewsReadSpec:
    return MassiveNewsReadSpec(
        ticker="AAPL",
        listing_venue="XNAS",
        start=_START,
        end=_END,
        limit=limit,
        mapping_version=_VERSION,
        instrument_binding=_BINDING,
        benzinga_entitlement_expected=entitled,
    )


def _dump(result: object) -> str:
    parts = [repr(result)]
    for name in ("error_code", "request_id", "records", "events"):
        value = getattr(result, name, None)
        if name == "events" and isinstance(value, tuple):
            parts.extend(event.model_dump_json() for event in value)
        else:
            parts.append(repr(value))
    return "\n".join(parts)


def test_products_keep_distinct_identity_and_decimal_payloads() -> None:
    trade_body = {
        "status": "OK",
        "request_id": "synthetic-trades",
        "next_url": "https://api.massive.com/v3/trades/AAPL?cursor=ignored",
        "results": [_trade(), _trade(correction=1, price="123.4600")],
    }
    adapter, transport, _ = _adapter(_response(trade_body))
    trades = adapter.read(_read_spec("trades"))
    assert len(trades.events) == 2
    first_trade, corrected_trade = trades.events
    assert first_trade.event_type == "trade"
    assert first_trade.dataset == MASSIVE_TRADES_DATASET
    assert first_trade.instrument_id == "acceptance-aapl"
    assert first_trade.venue == "XNAS"
    assert first_trade.native_symbol == "AAPL"
    assert isinstance(first_trade.payload, TradePayload)
    assert isinstance(corrected_trade.payload, TradePayload)
    assert first_trade.payload.price.value == "123.45"
    assert first_trade.payload.size == "0.1234567890123456789012345678901234"
    assert first_trade.native_provenance.correction == "none"
    assert corrected_trade.native_provenance.correction == "correction"
    assert first_trade.source_record_key != corrected_trade.source_record_key
    assert len(transport.calls) == 1

    direct_adapter, _, direct_credentials = _adapter(
        _response({"status": "OK", "results": [_trade()]})
    )
    assert direct_adapter.read(_read_spec("trades")).error_code is None
    assert len(direct_credentials.references) == 1
    assert direct_credentials.references[0].name == "MASSIVE_API_KEY"

    quote_adapter, quote_transport, _ = _adapter(
        _response(
            {
                "status": "OK",
                "next_url": "https://api.massive.com/v3/quotes/AAPL?cursor=ignored",
                "results": [_quote(bid_exchange=None, bid_price=None, bid_size=None)],
            }
        )
    )
    quotes = quote_adapter.read(_read_spec("quotes"))
    assert len(quotes.events) == 1
    quote = quotes.events[0]
    assert quote.event_type == "quote"
    assert quote.dataset == MASSIVE_QUOTES_DATASET
    assert isinstance(quote.payload, QuotePayload)
    assert quote.payload.kind == "quote"
    assert quote.payload.bid_present is False
    assert quote.payload.ask_price is not None
    assert quote.payload.ask_price.value == "123.5"
    assert quote.payload.ask_size == "11"
    assert len(quote_transport.calls) == 1

    bar_adapter, bar_transport, _ = _adapter(
        _response(
            {
                "status": "OK",
                "next_url": "https://api.massive.com/v2/aggs/next?cursor=ignored",
                "results": [_aggregate()],
            }
        )
    )
    bars = bar_adapter.read_aggregates(_aggregate_spec())
    assert len(bars.events) == 1
    bar = bars.events[0]
    assert bar.event_type == "bar"
    assert bar.dataset == MASSIVE_AGGREGATES_ADJUSTED_DATASET
    assert isinstance(bar.payload, BarPayload)
    assert bar.payload.open.value == "123.45"
    assert bar.payload.high.value == "124"
    assert bar.payload.volume == "1000.5"
    assert len(bar_transport.calls) == 1
    same_bar_adapter, _, _ = _adapter(_response({"status": "OK", "results": [_aggregate()]}))
    same_bar = same_bar_adapter.read_aggregates(_aggregate_spec())
    assert same_bar.events[0].source_record_key == bar.source_record_key

    news_adapter, news_transport, _ = _adapter(
        _response(
            {
                "status": "OK",
                "next_url": "https://api.massive.com/benzinga/v2/news?cursor=ignored",
                "results": [_news()],
            }
        )
    )
    news_result = news_adapter.read_benzinga_news(_news_spec())
    assert len(news_result.events) == 1
    news = news_result.events[0]
    assert news.event_type == "news"
    assert news.dataset == MASSIVE_BENZINGA_NEWS_DATASET
    assert isinstance(news.payload, NewsPayload)
    assert news.source_record_key == "massive:benzinga:7001001"
    assert news.event_time_ns == _START_NS + 123
    assert news.source_time_ns == _START_NS + 1_000_000_456
    assert news.native_provenance.correction == "correction"
    assert news.payload.headline == "Synthetic AAPL headline"
    assert "body" not in news.model_dump(mode="json")["payload"]
    assert len(news_transport.calls) == 1


def test_trade_and_news_corrections_are_identity_safe_and_conflicts_quarantined() -> None:
    exact_trade = _trade()
    adapter, _, _ = _adapter(
        _response({"status": "OK", "results": [exact_trade, exact_trade.copy()]})
    )
    duplicate = adapter.read(_read_spec("trades"))
    assert len(duplicate.events) == 1
    assert duplicate.quarantined_count == 0

    conflicting = _trade(price="999.99")
    adapter2, _, _ = _adapter(
        _response({"status": "OK", "results": [exact_trade, conflicting]})
    )
    conflict = adapter2.read(_read_spec("trades"))
    assert len(conflict.events) == 1
    assert conflict.quarantined_count == 1

    same_bar = _aggregate()
    changed_bar = _aggregate(c="999.99")
    adapter3, _, _ = _adapter(
        _response({"status": "OK", "results": [same_bar, changed_bar]})
    )
    bar_conflict = adapter3.read_aggregates(_aggregate_spec())
    assert len(bar_conflict.events) == 1
    assert bar_conflict.quarantined_count == 1

    original_news = _news()
    revised_news = _news(last_updated="2026-10-06T14:30:02.000000000Z", title="Revised")
    adapter4, _, _ = _adapter(
        _response({"status": "OK", "results": [original_news, revised_news]})
    )
    news_conflict = adapter4.read_benzinga_news(_news_spec())
    assert len(news_conflict.events) == 1
    assert news_conflict.quarantined_count == 1
    assert news_conflict.events[0].source_record_key == "massive:benzinga:7001001"


def test_depth_is_external_gate_and_quotes_are_not_depth() -> None:
    adapter, transport, _ = _adapter()
    result = adapter.read_depth()
    assert result.external_gate is True
    assert result.error_code == "EXTERNAL_GATE"
    assert result.events == ()
    assert "DEPTH" not in CAPABILITIES
    assert "L2" not in CAPABILITIES
    assert transport.calls == []


def test_entitlement_caps_and_invalid_ranges_fail_before_extra_io() -> None:
    adapter, transport, credentials = _adapter()
    aggregate = adapter.read_aggregates(_aggregate_spec(entitled=False))
    news = adapter.read_benzinga_news(_news_spec(entitled=False))
    assert aggregate.error_code == news.error_code == "ENTITLEMENT_DENIED"
    assert aggregate.external_gate is news.external_gate is True
    assert transport.calls == []
    assert credentials.references == []

    for invalid_spec in (
        lambda: _aggregate_spec(limit=11),
        lambda: _news_spec(limit=11),
        lambda: _read_spec("trades", limit=11),
        lambda: _read_spec("quotes", limit=11),
    ):
        with pytest.raises(MassiveAdapterError) as too_many:
            invalid_spec()
        assert str(too_many.value) == "MALFORMED_RECORD"

    oversized_body = json.dumps(
        {"status": "OK", "results": [_aggregate() for _ in range(11)]}
    ).encode()
    capped_adapter, capped_transport, _ = _adapter(_response(oversized_body))
    capped = capped_adapter.read_aggregates(_aggregate_spec())
    assert capped.error_code == "OVERSIZE"
    assert capped.events == ()
    assert len(capped_transport.calls) == 1

    response_too_large_adapter, too_large_transport, _ = _adapter(_response(b"x" * 1_048_577))
    response_too_large = response_too_large_adapter.read_aggregates(_aggregate_spec())
    assert response_too_large.error_code == "OVERSIZE"
    assert response_too_large.events == ()
    assert len(too_large_transport.calls) == 1


def test_missing_event_time_is_quarantined_and_never_inferred() -> None:
    adapter, _, _ = _adapter(
        _response(
            {
                "status": "OK",
                "results": [_trade(sip_timestamp=None, participant_timestamp=None)],
            }
        )
    )
    result = adapter.read(_read_spec("trades"))
    assert result.events == ()
    assert result.quarantined_count == 1

    adapter2, _, _ = _adapter(
        _response(
            {
                "status": "OK",
                "results": [
                    _news(published=None, last_updated="2026-10-06T14:30:01Z"),
                ],
            }
        )
    )
    news_result = adapter2.read_benzinga_news(_news_spec())
    assert news_result.events == ()
    assert news_result.quarantined_count == 1


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        (
            _response(
                {"status": "ERROR", "message": f"private body {_KEY}"},
                status=401,
            ),
            "AUTH_DENIED",
        ),
        (
            _response(
                {"status": "ERROR", "message": "redirect"},
                status=302,
                headers={"location": f"https://evil.invalid/{_KEY}"},
            ),
            "REDIRECT_DENIED",
        ),
    ],
)
def test_auth_and_redirects_are_bounded_redacted_and_not_retried(
    response: MassiveHTTPResponse, expected: str
) -> None:
    adapter, transport, _ = _adapter(response)
    result = adapter.read_aggregates(_aggregate_spec())
    assert result.error_code == expected
    assert len(transport.calls) == 1
    assert transport.calls[0]["allow_redirects"] is False
    assert _KEY not in _dump(result)


def test_provider_next_urls_are_ignored_and_timeout_is_not_retried() -> None:
    body = {
        "status": "OK",
        "next_url": "https://api.massive.com/next?cursor=synthetic-next",
        "results": [_aggregate()],
    }
    adapter, transport, _ = _adapter(_response(body))
    result = adapter.read_aggregates(_aggregate_spec())
    assert len(result.events) == 1
    assert len(transport.calls) == 1
    assert "apiKey" not in transport.calls[0]["params"]
    assert _KEY not in _dump(result)

    timeout_adapter, timeout_transport, _ = _adapter(TimeoutError(f"{_KEY} timeout detail"))
    timeout = timeout_adapter.read_aggregates(_aggregate_spec())
    assert timeout.error_code == "TIMEOUT"
    assert len(timeout_transport.calls) == 1
    assert _KEY not in _dump(timeout)


def test_secret_resolution_is_lazy_and_never_echoed() -> None:
    transport = _Transport(_response({"status": "OK", "results": [_aggregate()]}))
    resolved: list[str] = []

    def resolver(uri: str) -> str:
        resolved.append(uri)
        return _KEY

    from leviathan_market_data.providers.massive import build_adapter

    adapter = build_adapter(
        resolve_secret=resolver,
        transport=transport,
        mapping_registry=_registry(),
        session_resolver=_Sessions(),
        clock=lambda: _NOW_NS,
    )
    assert resolved == []
    result = adapter.read_aggregates(_aggregate_spec())
    assert len(resolved) == 1
    assert resolved[0] == "massive_api_key"
    assert PROVIDER_ID == "massive"
    assert CREDENTIAL_NAMES == ("massive_api_key",)
    assert _KEY not in _dump(result)
    assert len(transport.calls) == 1

    failed_transport = _Transport()
    failed_adapter = MassiveStocksHistoricalAdapter(
        transport=failed_transport,
        credential_resolver=_Credentials(fail=True),
        mapping_registry=_registry(),
        session_resolver=_Sessions(),
        clock_ns=lambda: _NOW_NS,
    )
    failed = failed_adapter.read_aggregates(_aggregate_spec())
    assert failed.error_code == "AUTH_DENIED"
    assert failed_transport.calls == []
    assert _KEY not in _dump(failed)


def test_registry_two_argument_factory_fails_closed_without_dependencies() -> None:
    transport = _Transport()
    resolved: list[str] = []

    def resolver(uri: str) -> str:
        resolved.append(uri)
        return _KEY

    from leviathan_market_data.providers.massive import build_adapter

    adapter = build_adapter(resolve_secret=resolver, transport=transport)
    result = adapter.read_aggregates(_aggregate_spec())
    assert result.error_code == "NOT_CONFIGURED"
    assert result.external_gate is True
    assert result.events == ()
    assert resolved == []
    assert transport.calls == []
    assert _KEY not in _dump(result)
