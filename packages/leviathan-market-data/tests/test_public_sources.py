from __future__ import annotations

from datetime import UTC, date, datetime
from email.message import Message
from pathlib import Path
from threading import Event, Thread
from time import perf_counter
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlparse

import pytest

from leviathan_market_data.public_sources import (
    PUBLIC_SOURCES,
    PublicEvidenceV1,
    PublicSourceError,
    PublicSourcesClient,
    parse_cftc_cot,
    parse_coinbase_derivatives_open_interest,
    parse_finra_regsho,
    parse_finra_weekly,
    parse_sec_form4,
    parse_treasury_curve,
)
from leviathan_market_data.public_sources import sources as public_sources_module

FIXTURES = Path(__file__).parent / "fixtures" / "public_sources"
NOW = datetime(2026, 10, 9, 12, tzinfo=UTC)


def fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def test_source_registry_has_tiers_and_point_in_time_rules() -> None:
    assert {source.source_id for source in PUBLIC_SOURCES} >= {
        "sec.edgar.form4",
        "finra.regsho.daily",
        "finra.otc.weekly",
        "cftc.cot.legacy",
        "treasury.yield_curve",
        "treasury.fiscal_data",
        "api_anything.calendar.fed",
        "api_anything.cnn.fear_greed",
    }
    assert all(source.tier in {1, 2, 3} and source.point_in_time_rule for source in PUBLIC_SOURCES)
    assert all(
        source.schema_version == 1 and source.redistribution is False for source in PUBLIC_SOURCES
    )
    crypto_sources = [source for source in PUBLIC_SOURCES if "crypto_market" in source.factor_tags]
    coinbase = next(
        source for source in PUBLIC_SOURCES if source.source_id == "coinbase.derivatives_us"
    )
    coinbase_exchange = next(
        source for source in PUBLIC_SOURCES if source.source_id == "coinbase.exchange"
    )
    binance = next(source for source in crypto_sources if source.source_id == "crypto.binance_usdm")
    assert coinbase.us_eligibility == "eligible" and coinbase.us_eligibility_note
    assert coinbase.tos_url == "https://www.coinbase.com/legal/futures-account-agreement"
    assert "open_interest" in coinbase.capabilities
    assert hasattr(PublicSourcesClient, "fetch_coinbase_derivatives_open_interest")
    assert coinbase_exchange.us_eligibility == "eligible" and coinbase_exchange.us_eligibility_note
    assert coinbase_exchange.tos_url == "https://www.coinbase.com/legal/user_agreement/united_states"
    assert binance.us_eligibility == "ineligible" and binance.us_eligibility_note
    assert all(
        source.us_eligibility is not None and source.us_eligibility_note
        for source in crypto_sources
    )
    assert binance.tos_classification == "EXCLUDED"
    assert not hasattr(PublicSourcesClient, "fetch_crypto_funding")
    assert not hasattr(PublicSourcesClient, "fetch_crypto_open_interest")


def test_sec_form4_uses_filing_time_as_knowable_time() -> None:
    evidence = parse_sec_form4(
        fixture("sec-form4.xml"),
        cik="0000000001",
        accession="0000000001-26-000001",
        filed_at=datetime(2026, 10, 9, 10, tzinfo=UTC),
        fetched_at=NOW,
    )
    assert len(evidence) == 1
    assert evidence[0].source_id == "sec.edgar.form4"
    assert evidence[0].as_of.date() == date(2026, 10, 8)
    assert evidence[0].knowable_at.hour == 10
    assert dict(evidence[0].values)["transaction_code"] == "P"


def test_finra_daily_and_weekly_fixtures_keep_availability_times() -> None:
    daily = parse_finra_regsho(
        fixture("finra-regsho.txt"), trade_date=date(2026, 10, 8), fetched_at=NOW
    )
    weekly = parse_finra_weekly(fixture("finra-weekly.json"), fetched_at=NOW)
    assert dict(daily[0].values)["short_volume"] == "100"
    assert weekly[0].knowable_at.date() == date(2026, 10, 5)
    assert weekly[0].as_of.date() == date(2026, 9, 21)
    assert all(item.redistribution is False for item in (*daily, *weekly))


def test_finra_weekly_revisions_have_distinct_versioned_records() -> None:
    payload = b"""[
      {"issueSymbolIdentifier":"XYZ","weekStartDate":"2026-09-21","initialPublishedDate":"2026-10-05","lastUpdateDate":"2026-10-06","totalWeeklyShareQuantity":50,"summaryTypeCode":"ATS_W_SMBL"},
      {"issueSymbolIdentifier":"XYZ","weekStartDate":"2026-09-21","initialPublishedDate":"2026-10-05","lastUpdateDate":"2026-10-08","totalWeeklyShareQuantity":55,"summaryTypeCode":"ATS_W_SMBL"}
    ]"""
    revisions = parse_finra_weekly(payload, fetched_at=NOW)
    assert len(revisions) == 2
    assert revisions[0].record_id != revisions[1].record_id
    assert revisions[0].knowable_at.date() == date(2026, 10, 6)
    assert revisions[1].knowable_at.date() == date(2026, 10, 8)
    assert dict(revisions[0].values)["initial_published_date"].startswith("2026-10-05")
    assert dict(revisions[1].values)["last_update_date"].startswith("2026-10-08")


def test_public_source_digest_binds_nonredistribution_and_event_at() -> None:
    record = PublicEvidenceV1(
        2,
        "fed.fomc",
        "meeting-2026-11-03",
        NOW,
        NOW,
        NOW,
        ("event_risk",),
        (("event", "FOMC"),),
        event_at=datetime(2026, 11, 3, 19, tzinfo=UTC),
    )
    assert record.redistribution is False
    assert record.event_at is not None and record.event_at > record.fetched_at
    assert len(record.record_digest) == 64


def test_cftc_and_treasury_fixtures_are_point_in_time() -> None:
    cot = parse_cftc_cot(fixture("cftc-cot.json"), fetched_at=NOW)
    curve = parse_treasury_curve(fixture("treasury-curve.xml"), fetched_at=NOW)
    assert dict(cot[0].values)["commercial_long"] == "400"
    assert cot[0].knowable_at == NOW
    assert dict(curve[0].values)["BC_10YEAR"] == "4.10"


def test_coinbase_derivatives_funding_uses_unauthenticated_us_endpoint() -> None:
    transport = RecordingTransport(
        b'[{"symbol":"BIPZ30","funding_rate":"0.0001","event_time":"2026-10-09T11:00:00Z"}]'
    )
    client = PublicSourcesClient(
        transport=transport,
        sec_user_agent="Leviathan contact@example.test",
        coinbase_derivatives_enabled=True,
        now=lambda: NOW,
    )
    evidence = client.fetch_coinbase_derivatives_funding(
        symbol="BIPZ30", trading_session_date=date(2026, 10, 9)
    )
    assert evidence[0].source_id == "coinbase.derivatives_us"
    assert evidence[0].as_of == datetime(2026, 10, 9, 11, tzinfo=UTC)
    assert evidence[0].knowable_at == NOW
    assert "api.exchange.fairx.net/rest/funding-rate" in transport.calls[0][1]
    assert "Authorization" not in transport.calls[0][2]


def test_coinbase_derivatives_instruments_use_bounded_public_filter() -> None:
    transport = RecordingTransport(b'[{"symbol":"BIPZ30","product_code":"BIP"}]')
    client = PublicSourcesClient(
        transport=transport,
        sec_user_agent="Leviathan contact@example.test",
        coinbase_derivatives_enabled=True,
        now=lambda: NOW,
    )
    evidence = client.fetch_coinbase_derivatives_instruments(product_codes=("BIP",))
    assert evidence[0].source_id == "coinbase.derivatives_us"
    assert evidence[0].as_of == NOW
    assert transport.calls[0][0] == "POST"
    assert transport.calls[0][3] == b'{"product_codes":["BIP"]}'
    assert "Authorization" not in transport.calls[0][2]


def test_coinbase_derivatives_methods_fail_closed_when_disabled() -> None:
    transport = RecordingTransport()
    client = PublicSourcesClient(
        transport=transport,
        sec_user_agent="Leviathan contact@example.test",
        now=lambda: NOW,
    )
    with pytest.raises(PublicSourceError, match="COINBASE_DERIVATIVES_DISABLED"):
        client.fetch_coinbase_derivatives_funding(
            symbol="BIPZ30", trading_session_date=date(2026, 10, 9)
        )
    with pytest.raises(PublicSourceError, match="COINBASE_DERIVATIVES_DISABLED"):
        client.fetch_coinbase_derivatives_instruments(product_codes=("BIP",))
    with pytest.raises(PublicSourceError, match="COINBASE_DERIVATIVES_DISABLED"):
        client.fetch_coinbase_derivatives_open_interest()
    assert transport.calls == []


def test_coinbase_public_us_futures_open_interest_has_provenance() -> None:
    transport = RecordingTransport(fixture("coinbase-futures-open-interest.json"))
    client = PublicSourcesClient(
        transport=transport,
        sec_user_agent="Leviathan contact@example.test",
        coinbase_derivatives_enabled=True,
        now=lambda: NOW,
    )

    evidence = client.fetch_coinbase_derivatives_open_interest()

    assert [record.record_id.split(":", 1)[0] for record in evidence] == [
        "BIP-USD",
        "BTC-DEC26-CDE",
    ]
    assert [dict(record.values)["open_interest"] for record in evidence] == ["179300", "121786"]
    assert all(record.source_id == "coinbase.derivatives_us" for record in evidence)
    assert all(record.as_of == NOW and record.knowable_at == NOW for record in evidence)
    assert all(record.fetched_at == NOW and record.redistribution is False for record in evidence)
    assert all(len(record.record_digest) == 64 for record in evidence)
    method, url, headers, body, _, _ = transport.calls[0]
    assert method == "GET" and body is None
    assert url.startswith("https://api.coinbase.com/api/v3/brokerage/market/products?")
    assert parse_qs(urlparse(url).query) == {
        "product_type": ["FUTURE"],
        "user_country_code": ["US"],
        "get_all_products": ["true"],
        "limit": ["100"],
    }
    assert "Authorization" not in headers


def test_coinbase_zero_perpetual_open_interest_is_preserved() -> None:
    evidence = parse_coinbase_derivatives_open_interest(
        b'{"products":[{"product_id":"BIP-USD","product_type":"FUTURE","future_product_details":{"perpetual_details":{"open_interest":0}}}],"pagination":{"has_next":false}}',
        fetched_at=NOW,
    )
    assert dict(evidence[0].values)["open_interest"] == "0"


def test_coinbase_perpetual_open_interest_takes_precedence_over_top_level() -> None:
    evidence = parse_coinbase_derivatives_open_interest(
        b'{"products":[{"product_id":"BIP-USD","product_type":"FUTURE","future_product_details":{"open_interest":"9","perpetual_details":{"open_interest":"7"}}}],"pagination":{"has_next":false}}',
        fetched_at=NOW,
    )
    assert dict(evidence[0].values)["open_interest"] == "7"


def test_coinbase_open_interest_absent_from_both_fields_fails_closed() -> None:
    with pytest.raises(PublicSourceError, match="SCHEMA_MISSING_COLUMN"):
        parse_coinbase_derivatives_open_interest(
            b'{"products":[{"product_id":"BIP-USD","product_type":"FUTURE","future_product_details":{"perpetual_details":{}}}],"pagination":{"has_next":false}}',
            fetched_at=NOW,
        )


def test_treasury_curve_rejects_entry_without_observation_date() -> None:
    with pytest.raises(PublicSourceError, match="SCHEMA_MISSING_COLUMN"):
        parse_treasury_curve(
            b"<feed><entry><content><properties><BC_10YEAR>4.10</BC_10YEAR></properties></content></entry></feed>",
            fetched_at=NOW,
        )


def test_future_dated_records_fail_closed() -> None:
    with pytest.raises(PublicSourceError, match="FUTURE_DATED_EVIDENCE"):
        PublicEvidenceV1(
            1, "treasury.yield_curve", "x", NOW, NOW.replace(day=10), NOW, ("rates",), ()
        )


class RecordingTransport:
    def __init__(self, body: bytes = b"[]") -> None:
        self.body = body
        self.calls: list[tuple[str, str, dict[str, str], bytes | None, float, int]] = []

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        body: bytes | None,
        timeout_s: float,
        max_bytes: int,
    ):
        self.calls.append((method, url, headers, body, timeout_s, max_bytes))
        return type("Response", (), {"status": 200, "body": self.body, "headers": {}})()


def test_client_requires_sec_ua_and_finra_vault_token() -> None:
    with pytest.raises(PublicSourceError, match="SEC_USER_AGENT_REQUIRED"):
        PublicSourcesClient(sec_user_agent="")
    client = PublicSourcesClient(
        transport=RecordingTransport(),
        sec_user_agent="Leviathan contact@example.test",
        now=lambda: NOW,
    )
    with pytest.raises(PublicSourceError, match="FINRA_CREDENTIAL_REQUIRED"):
        client.fetch_finra_weekly(report_type="ATS_W_SMBL", week_start=date(2026, 9, 21))


def test_finra_credentials_resolve_through_project_vault_refs() -> None:
    resolved: list[tuple[str, str]] = []

    def vault(reference: str, name: str) -> str:
        resolved.append((reference, name))
        return "fixture-value"

    client = PublicSourcesClient.from_vault(
        sec_user_agent="Leviathan contact@example.test",
        vault_ref_resolver=vault,
        finra_enabled=True,
        transport=RecordingTransport(),
        now=lambda: NOW,
    )
    assert isinstance(client, PublicSourcesClient)
    assert resolved == [
        ("vault://leviathan-ai/development/FINRA/FINRA_CLIENT_ID", "FINRA_CLIENT_ID"),
        ("vault://leviathan-ai/development/FINRA/FINRA_CLIENT_SECRET", "FINRA_CLIENT_SECRET"),
    ]
    with pytest.raises(PublicSourceError, match="FINRA_CREDENTIAL_REQUIRED"):
        PublicSourcesClient.from_vault(
            sec_user_agent="Leviathan contact@example.test",
            vault_ref_resolver=None,
            finra_enabled=True,
        )


def test_sec_client_is_host_allowlisted_and_sets_declared_user_agent() -> None:
    transport = RecordingTransport(fixture("sec-form4.xml"))
    client = PublicSourcesClient(
        transport=transport, sec_user_agent="Leviathan contact@example.test", now=lambda: NOW
    )
    with pytest.raises(PublicSourceError, match="URL_NOT_ALLOWLISTED"):
        client.fetch_sec_form4(
            xml_url="https://evil.test/form4.xml", cik="1", accession="x", filed_at=NOW
        )
    client.fetch_sec_form4(
        xml_url="https://www.sec.gov/Archives/edgar/data/1/x/form4.xml",
        cik="1",
        accession="x",
        filed_at=NOW,
    )
    assert transport.calls[0][2]["User-Agent"] == "Leviathan contact@example.test"
    assert transport.calls[0][4:] == (8.0, 8_000_000)


def test_sec_throttle_is_shared_across_client_instances(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = [1.0]
    sleeps: list[float] = []
    monkeypatch.setattr(public_sources_module, "_SEC_LAST_REQUEST", 0.0)
    monkeypatch.setattr(public_sources_module.time, "monotonic", lambda: clock[0])

    def advance(seconds: float) -> None:
        sleeps.append(seconds)
        clock[0] += seconds

    monkeypatch.setattr(public_sources_module.time, "sleep", advance)
    for _ in range(2):
        client = PublicSourcesClient(
            transport=RecordingTransport(fixture("sec-form4.xml")),
            sec_user_agent="Leviathan contact@example.test",
            sec_rate_per_second=5,
            now=lambda: NOW,
        )
        client.fetch_sec_form4(
            xml_url="https://www.sec.gov/Archives/edgar/data/1/x/form4.xml",
            cik="1",
            accession="x",
            filed_at=NOW,
        )
    assert sleeps == [0.2]


def test_sec_requests_are_serialized_across_client_instances(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    active = 0
    max_active = 0
    guard = Event()

    class ConcurrentTransport(RecordingTransport):
        def request(self, *args: object, **kwargs: object):
            nonlocal active, max_active
            active += 1
            max_active = max(max_active, active)
            guard.wait(0.03)
            active -= 1
            return type(
                "Response",
                (),
                {"status": 200, "body": fixture("sec-form4.xml"), "headers": {}},
            )()

    monkeypatch.setattr(public_sources_module, "_SEC_LAST_REQUEST", 0.0)
    clients = [
        PublicSourcesClient(
            transport=ConcurrentTransport(),
            sec_user_agent="Leviathan contact@example.test",
            sec_rate_per_second=10,
            now=lambda: NOW,
        )
        for _ in range(2)
    ]
    errors: list[BaseException] = []

    def fetch(client: PublicSourcesClient) -> None:
        try:
            client.fetch_sec_form4(
                xml_url="https://www.sec.gov/Archives/edgar/data/1/x/form4.xml",
                cik="1",
                accession="x",
                filed_at=NOW,
            )
        except BaseException as exc:  # pragma: no cover - surfaced in assertion below
            errors.append(exc)

    first = Thread(target=fetch, args=(clients[0],))
    second = Thread(target=fetch, args=(clients[1],))
    first.start()
    second.start()
    first.join(timeout=1)
    second.join(timeout=1)
    assert not first.is_alive() and not second.is_alive()
    assert errors == []
    assert max_active == 1


def test_http_timeout_is_a_wall_clock_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    def stalled_open(*_args: object, **_kwargs: object) -> object:
        Event().wait(0.2)
        raise OSError("fixture timeout")

    monkeypatch.setattr(public_sources_module.urllib.request, "urlopen", stalled_open)
    started = perf_counter()
    with pytest.raises(PublicSourceError, match="HTTP_DEADLINE_EXCEEDED"):
        public_sources_module.BoundedHTTPTransport(max_retries=0).request(
            "GET",
            "https://example.test/resource",
            headers={},
            body=None,
            timeout_s=0.03,
            max_bytes=1024,
        )
    assert perf_counter() - started < 0.15


@pytest.mark.parametrize("status", [403, 429])
def test_http_retries_sec_rate_limit_status_and_honors_retry_after(
    monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    attempts = 0
    sleeps: list[float] = []

    class Response:
        status = 200
        headers = Message()

        def __enter__(self) -> Response:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, _limit: int) -> bytes:
            return b"ok"

    def request(*_args: object, **_kwargs: object) -> Response:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise HTTPError(
                "https://example.test", status, "rate limited", {"Retry-After": "0.7"}, None
            )
        return Response()

    monkeypatch.setattr(public_sources_module.urllib.request, "urlopen", request)
    monkeypatch.setattr(public_sources_module.time, "sleep", sleeps.append)
    body = public_sources_module.BoundedHTTPTransport(max_retries=1).request(
        "GET",
        "https://example.test/resource",
        headers={},
        body=None,
        timeout_s=3,
        max_bytes=100,
    )
    assert body.body == b"ok"
    assert attempts == 2
    assert sleeps == [0.7]


def test_http_deadline_covers_response_body_read(monkeypatch: pytest.MonkeyPatch) -> None:
    class StalledResponse:
        status = 200
        headers = Message()

        def __enter__(self) -> StalledResponse:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, _limit: int) -> bytes:
            Event().wait(0.2)
            return b"late"

    monkeypatch.setattr(
        public_sources_module.urllib.request, "urlopen", lambda *_args, **_kwargs: StalledResponse()
    )
    started = perf_counter()
    with pytest.raises(PublicSourceError, match="HTTP_DEADLINE_EXCEEDED"):
        public_sources_module.BoundedHTTPTransport(max_retries=0).request(
            "GET",
            "https://example.test/resource",
            headers={},
            body=None,
            timeout_s=0.03,
            max_bytes=1024,
        )
    assert perf_counter() - started < 0.15


def test_http_response_body_limit_is_enforced(monkeypatch: pytest.MonkeyPatch) -> None:
    class Response:
        status = 200
        headers = Message()

        def __enter__(self) -> Response:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, limit: int) -> bytes:
            return b"x" * limit

    monkeypatch.setattr(
        public_sources_module.urllib.request, "urlopen", lambda *_args, **_kwargs: Response()
    )
    with pytest.raises(PublicSourceError, match="RESPONSE_TOO_LARGE"):
        public_sources_module.BoundedHTTPTransport(max_retries=0).request(
            "GET",
            "https://example.test/resource",
            headers={},
            body=None,
            timeout_s=1,
            max_bytes=10,
        )
