from __future__ import annotations

from datetime import UTC, date, datetime
from email.message import Message
from pathlib import Path
from threading import Event, Lock, Thread
from time import perf_counter
from urllib.error import HTTPError

import pytest

from leviathan_market_data.public_sources import (
    PublicEvidenceV1,
    PublicSourceError,
    PublicSourcesClient,
    parse_cftc_cot,
    parse_finra_regsho,
    parse_finra_weekly,
    parse_sec_form4,
    parse_treasury_curve,
)
from leviathan_market_data.public_sources import sources as source_module
from leviathan_market_data.public_sources.registry import PUBLIC_SOURCES

ROOT = Path(__file__).resolve().parents[3]
FIXTURES = ROOT / "packages" / "leviathan-market-data" / "tests" / "fixtures" / "public_sources"
NOW = datetime(2026, 10, 9, 12, tzinfo=UTC)
SEC_URL = "https://www.sec.gov/Archives/edgar/data/1/x/form4.xml"


def _fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def _records() -> tuple[PublicEvidenceV1, ...]:
    return (
        *parse_sec_form4(
            _fixture("sec-form4.xml"),
            cik="0000000001",
            accession="0000000001-26-000001",
            filed_at=datetime(2026, 10, 9, 10, tzinfo=UTC),
            fetched_at=NOW,
        ),
        *parse_finra_regsho(
            _fixture("finra-regsho.txt"), trade_date=date(2026, 10, 8), fetched_at=NOW
        ),
        *parse_finra_weekly(_fixture("finra-weekly.json"), fetched_at=NOW),
        *parse_cftc_cot(_fixture("cftc-cot.json"), fetched_at=NOW),
        *parse_treasury_curve(_fixture("treasury-curve.xml"), fetched_at=NOW),
    )


class _Response:
    def __init__(self) -> None:
        self.status = 200
        self.body = _fixture("sec-form4.xml")
        self.headers: dict[str, str] = {}


def test_sec_default_five_rps_hard_cap_ten_and_global_serialization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(source_module, "_SEC_LAST_REQUEST", -1.0)
    clock = [0.0]
    sleeps: list[float] = []
    monkeypatch.setattr(source_module.time, "monotonic", lambda: clock[0])

    def sleep(seconds: float) -> None:
        sleeps.append(seconds)
        clock[0] += seconds

    monkeypatch.setattr(source_module.time, "sleep", sleep)

    class RecordingTransport:
        def request(self, *_args: object, **_kwargs: object) -> _Response:
            return _Response()

    default_client = PublicSourcesClient(
        transport=RecordingTransport(), sec_user_agent="Example contact@example.test"
    )
    for index in range(2):
        default_client.fetch_sec_form4(
            xml_url=SEC_URL, cik="1", accession=f"x-{index}", filed_at=NOW
        )
    assert sleeps == [pytest.approx(0.2)]

    capped = PublicSourcesClient(
        transport=RecordingTransport(),
        sec_user_agent="Example contact@example.test",
        sec_rate_per_second=10,
    )
    capped.fetch_sec_form4(xml_url=SEC_URL, cik="1", accession="cap", filed_at=NOW)
    with pytest.raises(PublicSourceError, match="SEC_RATE_MUST_BE_TEN_PER_SECOND"):
        PublicSourcesClient(sec_user_agent="Example contact@example.test", sec_rate_per_second=11)

    monkeypatch.undo()

    active = 0
    peak = 0
    guard = Lock()
    started = Event()

    class ConcurrentTransport:
        def request(self, *_args: object, **_kwargs: object) -> _Response:
            nonlocal active, peak
            with guard:
                active += 1
                peak = max(peak, active)
            started.set()
            Event().wait(0.03)
            with guard:
                active -= 1
            return _Response()

    concurrent_clients = [
        PublicSourcesClient(
            transport=ConcurrentTransport(),
            sec_user_agent="Example contact@example.test",
            sec_rate_per_second=10,
        )
        for _ in range(2)
    ]
    failures: list[BaseException] = []

    def fetch(client: PublicSourcesClient, suffix: str) -> None:
        try:
            client.fetch_sec_form4(xml_url=SEC_URL, cik="1", accession=suffix, filed_at=NOW)
        except BaseException as exc:  # surfaced by the assertion below
            failures.append(exc)

    first = Thread(target=fetch, args=(concurrent_clients[0], "first"))
    second = Thread(target=fetch, args=(concurrent_clients[1], "second"))
    first.start()
    assert started.wait(1)
    second.start()
    first.join(2)
    second.join(2)
    assert not first.is_alive() and not second.is_alive()
    assert failures == []
    assert peak == 1


@pytest.mark.parametrize("status", [403, 429])
def test_http_backoff_honors_retry_after_for_sec_rate_statuses(
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

    def fake_urlopen(*_args: object, **_kwargs: object) -> Response:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise HTTPError(
                "https://example.test", status, "rate limited", {"Retry-After": "0.7"}, None
            )
        return Response()

    monkeypatch.setattr(source_module.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(source_module.time, "sleep", sleeps.append)
    response = source_module.BoundedHTTPTransport(max_retries=1).request(
        "GET",
        "https://example.test/resource",
        headers={},
        body=None,
        timeout_s=3,
        max_bytes=100,
    )
    assert response.body == b"ok"
    assert attempts == 2
    assert sleeps == [0.7]


def test_http_deadline_covers_body_read_and_response_size_is_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class SlowBody:
        status = 200
        headers = Message()

        def __enter__(self) -> SlowBody:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, _limit: int) -> bytes:
            Event().wait(0.12)
            return b"late"

    monkeypatch.setattr(
        source_module.urllib.request, "urlopen", lambda *_args, **_kwargs: SlowBody()
    )
    start = perf_counter()
    with pytest.raises(PublicSourceError, match="HTTP_DEADLINE_EXCEEDED"):
        source_module.BoundedHTTPTransport(max_retries=0).request(
            "GET",
            "https://example.test/resource",
            headers={},
            body=None,
            timeout_s=0.02,
            max_bytes=100,
        )
    assert perf_counter() - start < 0.09

    class OversizedBody:
        status = 200
        headers = Message()

        def __enter__(self) -> OversizedBody:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, limit: int) -> bytes:
            return b"x" * limit

    monkeypatch.setattr(
        source_module.urllib.request, "urlopen", lambda *_args, **_kwargs: OversizedBody()
    )
    with pytest.raises(PublicSourceError, match="RESPONSE_TOO_LARGE"):
        source_module.BoundedHTTPTransport(max_retries=0).request(
            "GET",
            "https://example.test/resource",
            headers={},
            body=None,
            timeout_s=1,
            max_bytes=10,
        )


def test_every_normalized_record_forbids_redistribution_and_registry_is_versioned() -> None:
    records = _records()
    assert len(records) == 5
    assert all(record.redistribution is False for record in records)
    assert all(source.redistribution is False for source in PUBLIC_SOURCES)
    assert PUBLIC_SOURCES
    assert all(source.schema_version == 1 for source in PUBLIC_SOURCES)
    assert all(source.schema_version == 1 for source in source_module.PUBLIC_SOURCES)
