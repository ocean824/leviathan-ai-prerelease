"""Offline DATA-003 contract tests for Massive stock products."""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
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
    build_adapter,
)
from leviathan_market_data.symbology import InstrumentMapping, MappingRegistry
from leviathan_vault.client import CredentialRef

_FIXTURES = Path(__file__).parent / "fixtures" / "massive_products"
_START = datetime(2026, 10, 6, 14, 30, tzinfo=UTC)
_END = _START + timedelta(minutes=5)
_NOW_NS = 1_791_297_000_000_000_000
_SECRET = "Q7!xm2V@r9Lp4Kz8BW5&"
_VERSION = "massive-map-v1"
_BINDING = InstrumentBindingV1(
    listing_venue="XNAS",
    ticker="AAPL",
    valid_from_ns=_NOW_NS - 10_000_000_000,
    valid_to_ns=_NOW_NS + 10_000_000_000,
    stable_instrument_id="synthetic-aapl-id",
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
                instrument_id="synthetic-aapl-id",
                leviathan_symbol="NASDAQ:AAPL:STOCK",
                instrument_type="equity",
                mapping_version=_VERSION,
                tick_size="0.01",
            )
            for dataset in datasets
        )
    )


def _fixture(name: str) -> bytes:
    return (_FIXTURES / name).read_bytes()


def _response(body: bytes, status: int = 200, headers: Mapping[str, str] | None = None):
    return MassiveHTTPResponse(status, headers or {"content-type": "application/json"}, body)


class _Transport:
    def __init__(self, *responses: MassiveHTTPResponse | Exception) -> None:
        self.responses = list(responses)
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
        if not self.responses:
            raise AssertionError("unexpected retry or pagination request")
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class _Credentials:
    def __init__(self, *, secret: str = _SECRET, fail: bool = False) -> None:
        self.secret = secret
        self.fail = fail
        self.refs: list[CredentialRef] = []

    def __call__(self, reference: CredentialRef) -> str:
        self.refs.append(reference)
        if self.fail:
            raise RuntimeError("private resolver detail must not escape")
        return self.secret


class _Sessions:
    def resolve(self, **kwargs: object) -> SessionResolution:
        del kwargs
        return SessionResolution("synthetic-session", False, "XNAS")


def _adapter(*responses: MassiveHTTPResponse | Exception):
    transport = _Transport(*responses)
    credentials = _Credentials()
    adapter = MassiveStocksHistoricalAdapter(
        transport=transport,
        credential_resolver=credentials,
        mapping_registry=_registry(),
        session_resolver=_Sessions(),
        clock_ns=lambda: _NOW_NS + 5_000_000_000,
    )
    return adapter, transport, credentials


def _read_spec(channel: str) -> MassiveReadSpec:
    return MassiveReadSpec(
        ticker="AAPL",
        listing_venue="XNAS",
        channel=channel,
        start=_START,
        end=_END,
        limit=10,
        mapping_version=_VERSION,
        instrument_binding=_BINDING,
        quote_entitlement_expected=True,
    )  # type: ignore[arg-type]


def _aggregate_spec(*, adjusted: bool = True) -> MassiveAggregateReadSpec:
    return MassiveAggregateReadSpec(
        ticker="AAPL",
        listing_venue="XNAS",
        start=_START,
        end=_END,
        multiplier=1,
        timespan="minute",
        limit=10,
        mapping_version=_VERSION,
        instrument_binding=_BINDING,
        adjusted=adjusted,
        stocks_entitlement_expected=True,
    )


def _news_spec(*, entitled: bool = True) -> MassiveNewsReadSpec:
    return MassiveNewsReadSpec(
        ticker="AAPL",
        listing_venue="XNAS",
        start=_START,
        end=_END,
        limit=10,
        mapping_version=_VERSION,
        instrument_binding=_BINDING,
        benzinga_entitlement_expected=entitled,
    )


def test_trade_decimal_identity_and_native_correction_codes() -> None:
    adapter, transport, credentials = _adapter(_response(_fixture("trades.json")))
    result = adapter.read(_read_spec("trades"))

    assert result.error_code is None
    assert result.quarantined_count == 0
    assert len(result.events) == 2
    assert result.events[0].payload.price.value == "123.45"
    assert result.events[0].payload.size == "2.5"
    assert result.events[0].native_provenance.correction == "none"
    assert result.events[1].native_provenance.correction == "correction"
    assert result.events[0].source_record_key != result.events[1].source_record_key
    assert credentials.refs[0].provider == "massive"
    assert credentials.refs[0].name == "MASSIVE_API_KEY"
    assert credentials.refs[0].scope == "leviathan-ai"
    assert credentials.refs[0].environment == "development"
    assert len(transport.calls) == 1
    assert transport.calls[0]["headers"] == {"Authorization": f"Bearer {_SECRET}"}
    assert "apiKey" not in transport.calls[0]["params"]
    assert transport.calls[0]["allow_redirects"] is False


def test_quote_is_nbbo_with_missing_side_and_never_l2() -> None:
    adapter, transport, _ = _adapter(_response(_fixture("quotes.json")))
    quote_result = adapter.read(_read_spec("quotes"))

    assert quote_result.error_code is None
    assert len(quote_result.events) == 1
    quote = quote_result.events[0]
    assert quote.payload.kind == "quote"
    assert quote.payload.bid_present is False
    assert quote.payload.ask_present is True
    assert quote.payload.ask_price is not None
    assert quote.payload.ask_price.value == "123.5"
    assert "missing_bid" in quote.quality_flags
    depth = adapter.read_depth()
    assert depth.external_gate is True
    assert depth.error_code == "EXTERNAL_GATE"
    assert depth.events == ()
    assert len(transport.calls) == 1


def test_aggregate_bar_preserves_decimal_values_and_uses_one_page() -> None:
    adapter, transport, _ = _adapter(_response(_fixture("aggregates.json")))
    result = adapter.read_aggregates(_aggregate_spec())

    assert result.error_code is None
    assert len(result.events) == 1
    bar = result.events[0]
    assert bar.event_type == "bar"
    assert bar.payload.open.value == "123.45"
    assert bar.payload.high.value == "124"
    assert bar.payload.volume == "1000.5"
    assert bar.payload.open_time_ns == _NOW_NS
    assert transport.calls[0]["url"].endswith("/range/1/minute/1791297000000/1791297300000")
    assert transport.calls[0]["params"] == {
        "adjusted": "true",
        "sort": "asc",
        "limit": "10",
    }
    assert len(transport.calls) == 1


def test_benzinga_news_timestamp_precision_and_revision_provenance() -> None:
    adapter, transport, _ = _adapter(_response(_fixture("benzinga_news.json")))
    result = adapter.read_benzinga_news(_news_spec())

    assert result.error_code is None
    assert len(result.events) == 1
    news = result.events[0]
    assert news.event_type == "news"
    assert news.payload.headline == "Synthetic AAPL market headline"
    assert news.payload.publisher == "Benzinga"
    assert news.event_time_ns == _NOW_NS + 123
    assert news.source_time_ns == _NOW_NS + 1_000_000_456
    assert news.native_provenance.correction == "correction"
    assert "body" not in news.model_dump(mode="json")["payload"]
    assert transport.calls[0]["url"] == "https://api.massive.com/benzinga/v2/news"
    assert transport.calls[0]["params"]["tickers"] == "AAPL"
    assert transport.calls[0]["params"]["sort"] == "published.asc"
    assert len(transport.calls) == 1


def test_no_benzinga_entitlement_fails_before_secret_resolution_or_request() -> None:
    adapter, transport, credentials = _adapter()
    result = adapter.read_benzinga_news(_news_spec(entitled=False))
    assert result.external_gate is True
    assert result.error_code == "ENTITLEMENT_DENIED"
    assert credentials.refs == []
    assert transport.calls == []


def test_no_stock_entitlement_fails_before_secret_resolution_or_request() -> None:
    adapter, transport, credentials = _adapter()
    spec = _aggregate_spec()
    unentitled = MassiveAggregateReadSpec(
        ticker=spec.ticker,
        listing_venue=spec.listing_venue,
        start=spec.start,
        end=spec.end,
        multiplier=spec.multiplier,
        timespan=spec.timespan,
        limit=spec.limit,
        mapping_version=spec.mapping_version,
        instrument_binding=spec.instrument_binding,
        adjusted=spec.adjusted,
        stocks_entitlement_expected=False,
    )
    result = adapter.read_aggregates(unentitled)
    assert result.external_gate is True
    assert result.error_code == "ENTITLEMENT_DENIED"
    assert credentials.refs == []
    assert transport.calls == []


def test_registration_surface_factory_resolves_the_vault_uri_only_at_read_time() -> None:
    transport = _Transport(_response(_fixture("aggregates.json")))
    secret_lookups: list[str] = []

    def resolve_secret(uri: str) -> str:
        secret_lookups.append(uri)
        return _SECRET

    adapter = build_adapter(
        resolve_secret=resolve_secret,
        transport=transport,
        mapping_registry=_registry(),
        session_resolver=_Sessions(),
        clock=lambda: _NOW_NS + 5_000_000_000,
    )
    assert secret_lookups == []
    result = adapter.read_aggregates(_aggregate_spec())
    assert result.error_code is None
    assert secret_lookups == ["massive_api_key"]
    assert CREDENTIAL_NAMES == ("massive_api_key",)
    assert PROVIDER_ID == "massive"
    assert frozenset({"TRADES", "QUOTES", "NBBO", "AGGREGATES"}) == CAPABILITIES


def test_registry_factory_defaults_fail_closed_without_symbol_configuration() -> None:
    transport = _Transport(_response(_fixture("aggregates.json")))
    secret_lookups: list[str] = []
    adapter = build_adapter(
        resolve_secret=lambda uri: secret_lookups.append(uri) or _SECRET,
        transport=transport,
    )

    assert adapter.health().status == "NOT_CONFIGURED"
    assert adapter.health().error_code == "NOT_CONFIGURED"
    result = adapter.read_aggregates(_aggregate_spec())
    assert result.error_code == "NOT_CONFIGURED"
    assert result.external_gate is True
    assert secret_lookups == []
    assert transport.calls == []


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        (_response(b'{"status":"ERROR","message":"private body"}', 401), "AUTH_DENIED"),
        (
            _response(b'{"status":"OK"}', 302, {"location": f"https://evil.invalid/{_SECRET}"}),
            "REDIRECT_DENIED",
        ),
    ],
)
def test_auth_and_redirect_fail_closed_without_echo_or_retry(
    response: MassiveHTTPResponse,
    expected: str,
) -> None:
    adapter, transport, _ = _adapter(response)
    result = adapter.read_aggregates(_aggregate_spec())
    assert result.error_code == expected
    assert _SECRET not in repr(result)
    assert len(transport.calls) == 1
    assert transport.calls[0]["allow_redirects"] is False


def test_transport_failure_is_not_retried_and_resolver_errors_are_redacted() -> None:
    adapter, transport, _ = _adapter(TimeoutError("private transport detail"))
    result = adapter.read_aggregates(_aggregate_spec())
    assert result.error_code == "TIMEOUT"
    assert "private transport detail" not in repr(result)
    assert len(transport.calls) == 1

    transport2 = _Transport(_response(_fixture("aggregates.json")))
    credentials = _Credentials(fail=True)
    adapter2 = MassiveStocksHistoricalAdapter(
        transport=transport2,
        credential_resolver=credentials,
        mapping_registry=_registry(),
        session_resolver=_Sessions(),
        clock_ns=lambda: _NOW_NS,
    )
    result2 = adapter2.read_aggregates(_aggregate_spec())
    assert result2.error_code == "AUTH_DENIED"
    assert "private resolver detail" not in repr(result2)
    assert transport2.calls == []


def test_invalid_news_timestamp_is_quarantined_not_fabricated() -> None:
    body = json.dumps(
        {
            "status": "OK",
            "results": [
                {
                    "benzinga_id": 5,
                    "title": "Synthetic",
                    "published": "2026-10-06T14:30:00",
                    "tickers": ["AAPL"],
                }
            ],
        }
    ).encode()
    adapter, _, _ = _adapter(_response(body))
    result = adapter.read_benzinga_news(_news_spec())
    assert result.events == ()
    assert result.quarantined_count == 1


def test_response_record_cap_is_content_free() -> None:
    body = json.dumps({"status": "OK", "results": [{"t": _NOW_NS // 1_000_000}] * 11}).encode()
    adapter, transport, _ = _adapter(_response(body))
    result = adapter.read_aggregates(_aggregate_spec())
    assert result.error_code == "OVERSIZE"
    assert result.events == ()
    assert len(transport.calls) == 1


def test_invalid_product_spec_is_rejected_content_free() -> None:
    with pytest.raises(MassiveAdapterError) as caught:
        MassiveAggregateReadSpec(
            ticker="AAPL",
            listing_venue="XNAS",
            start=_START.replace(tzinfo=None),
            end=_END,
            multiplier=1,
            timespan="minute",
            limit=10,
            mapping_version=_VERSION,
            instrument_binding=_BINDING,
        )
    assert str(caught.value) == "MALFORMED_RECORD"
    assert _SECRET not in str(caught.value)
