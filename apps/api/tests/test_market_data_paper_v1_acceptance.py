"""Independent black-box acceptance for the injected paper market-data API."""

from __future__ import annotations

import socket
from dataclasses import dataclass, field
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from leviathan_api.routers.market_data_paper_v1 import (
    BackfillJobStatusV1,
    BackfillPreviewV1,
    BackfillRequestV1,
    create_paper_market_data_router,
)
from leviathan_market_data.health import SourceHealthSnapshot
from leviathan_market_data.schema import NormalizedMarketEventV1, PriceValue, TradePayload

SCHEMA_VERSION = "leviathan.market-data-paper/1"
_PRIVATE_CANARY = "synthetic-provider-error-canary"


def _health(*, gap_count: int = 0) -> SourceHealthSnapshot:
    return SourceHealthSnapshot(
        provider="synthetic-provider",
        dataset="synthetic-dataset",
        venue="XTS1",
        instrument_id="SYNTH",
        channel="trades",
        last_received_time_ns=1_700_000_000_000_000_222,
        last_processed_time_ns=1_700_000_000_000_000_223,
        last_provider_time_ns=1_700_000_000_000_000_111,
        last_exchange_time_ns=1_700_000_000_000_000_112,
        gap_count=gap_count,
        late_count=0,
        node_clock_offset_ms=0.0,
        node_drift_alert=False,
        node_publish_blocked=False,
        last_event_clock_adjusted=False,
        queued_count=0,
        queue_pressure=0.0,
        unhealthy=False,
    )


def _event() -> NormalizedMarketEventV1:
    base = 1_700_000_000_000_000_000
    return NormalizedMarketEventV1(
        event_id="00000000-0000-0000-0000-000000000001",
        provider="synthetic-provider",
        dataset="synthetic-dataset",
        venue="XTS1",
        native_symbol="SYN-1",
        leviathan_symbol="SYNTH1",
        instrument_id="SYNTH",
        instrument_type="equity",
        channel="trades",
        event_type="trade",
        source_mode="live",
        event_time_ns=base + 100,
        source_time_ns=base + 90,
        exchange_time_ns=base + 95,
        ingest_time_ns=base + 200,
        processing_time_ns=base + 201,
        received_time_ns=base + 199,
        native_sequence=1,
        sequence_synthetic=False,
        native_trade_id="synthetic-trade-1",
        source_record_key="synthetic-key-1",
        source_record_ref="synthetic-ref-1",
        source_payload_sha256="a" * 64,
        mapping_version="mapping/1",
        identity_policy_version="identity/1",
        quality_flags=(),
        reconstructed=False,
        idempotency_key="synthetic-idempotency-1",
        payload=TradePayload(price=PriceValue(value="12.34"), size="2", side="buy"),
    )


def _request(*, dry_run: bool) -> dict[str, object]:
    return {
        "venue": "XTS1",
        "instruments": ["SYNTH"],
        "types": ["trades"],
        "t0_ns": 1_700_000_000_000_000_000,
        "t1_ns": 1_700_000_060_000_000_000,
        "max_records": 100,
        "dry_run": dry_run,
    }


@dataclass
class _SyntheticPorts:
    venue_rows: tuple[SourceHealthSnapshot, ...] | None = field(
        default_factory=lambda: (_health(),)
    )
    latest: tuple[NormalizedMarketEventV1 | None, SourceHealthSnapshot | None] | None = field(
        default_factory=lambda: (_event(), _health())
    )
    enqueued_id: str = "job_opaque-7f3a"
    calls: list[tuple[str, object]] = field(default_factory=list)
    fail_with_canary: bool = False

    def read_venue_health(self, *, venue: str | None, limit: int):
        self.calls.append(("venues", (venue, limit)))
        if self.fail_with_canary:
            raise RuntimeError(_PRIVATE_CANARY)
        if self.venue_rows is None:
            return None
        return self.venue_rows[:limit]

    def read_latest(self, *, venue: str, instrument: str, data_type: str):
        self.calls.append(("latest", (venue, instrument, data_type)))
        if self.fail_with_canary:
            raise RuntimeError(_PRIVATE_CANARY)
        return self.latest

    def preview_backfill(self, request: BackfillRequestV1) -> BackfillPreviewV1:
        self.calls.append(("preview", request))
        if self.fail_with_canary:
            raise RuntimeError(_PRIVATE_CANARY)
        return BackfillPreviewV1(estimated_event_count=7)

    def enqueue_backfill(self, request: BackfillRequestV1) -> str:
        self.calls.append(("enqueue", request))
        if self.fail_with_canary:
            raise RuntimeError(_PRIVATE_CANARY)
        return self.enqueued_id

    def read_backfill_job(self, job_id: str) -> BackfillJobStatusV1 | None:
        self.calls.append(("job", job_id))
        if job_id != self.enqueued_id:
            return None
        return BackfillJobStatusV1(
            status="QUEUED",
            completed_count=0,
            remaining_count=100,
            source_state="AVAILABLE",
            gap_state="DETECTED",
            last_event_time_ns=1_700_000_000_000_000_111,
            last_ingest_time_ns=1_700_000_000_000_000_222,
        )


def _client(ports: _SyntheticPorts, *, enabled: bool = True) -> TestClient:
    app = FastAPI()
    app.include_router(
        create_paper_market_data_router(
            enabled=enabled,
            venue_port=ports,
            latest_port=ports,
            backfill_port=ports,
        )
    )
    return TestClient(app)


def _assert_no_store(response: Any) -> None:
    assert response.headers.get("cache-control") == "no-store"


def _assert_error(response: Any, status: int, code: str) -> None:
    assert response.status_code == status
    body = response.json()
    assert body.get("schema_version") == SCHEMA_VERSION
    assert body.get("error") == {"code": code}
    _assert_no_store(response)


def test_venue_query_is_bounded_and_validated() -> None:
    ports = _SyntheticPorts()
    with _client(ports) as client:
        response = client.get("/ingest/venues?venue=XTS1&limit=1")
        assert response.status_code == 200
        assert response.json()["source_state"] == "AVAILABLE"
        assert ports.calls[-1] == ("venues", ("XTS1", 1))
        for query in (
            "limit=0",
            "limit=101",
            "limit=1&limit=2",
            "unexpected=1",
            "venue=ABCDX",
            "x=" + "z" * 2_100,
        ):
            invalid = client.get("/ingest/venues?" + query)
            _assert_error(invalid, 400, "INVALID_REQUEST")


def test_latest_requires_valid_complete_query_and_preserves_both_times() -> None:
    ports = _SyntheticPorts()
    with _client(ports) as client:
        response = client.get(
            "/md/latest?venue=XTS1&instrument=SYNTH&type=trades"
        )
        assert response.status_code == 200
        body = response.json()
        assert body["schema_version"] == SCHEMA_VERSION
        assert body["source_state"] == "AVAILABLE"
        assert body["event"]["event_time_ns"] != body["event"]["ingest_time_ns"]
        assert body["event"]["event_time_ns"] == _event().event_time_ns
        assert body["event"]["ingest_time_ns"] == _event().ingest_time_ns
        assert body["gap_state"] == "NONE"
        _assert_no_store(response)

        for query in (
            "venue=XTS1&instrument=SYNTH&type=trades&extra=1",
            "venue=XTS1&instrument=SYNTH&instrument=OTHER&type=trades",
            "venue=XTS1&instrument=bad%20instrument&type=trades",
            "venue=XTS1&instrument=SYNTH&type=unsupported",
        ):
            _assert_error(client.get("/md/latest?" + query), 400, "INVALID_REQUEST")


def test_absent_source_and_detected_gap_are_explicit() -> None:
    ports = _SyntheticPorts(venue_rows=None, latest=None)
    with _client(ports) as client:
        venues = client.get("/ingest/venues")
        assert venues.status_code == 200
        assert venues.json()["source_state"] == "ABSENT"
        assert venues.json()["venues"] == []
        _assert_no_store(venues)

        latest_absent = client.get(
            "/md/latest?venue=XTS1&instrument=SYNTH&type=trades"
        )
        assert latest_absent.status_code == 200
        assert latest_absent.json()["source_state"] == "ABSENT"
        assert latest_absent.json()["gap_state"] == "UNKNOWN"
        assert latest_absent.json()["event"] is None

        ports.latest = (_event(), _health(gap_count=2))
        latest_gap = client.get(
            "/md/latest?venue=XTS1&instrument=SYNTH&type=trades"
        )
        assert latest_gap.status_code == 200
        assert latest_gap.json()["gap_state"] == "DETECTED"


def test_dry_run_previews_without_enqueue_or_other_writes() -> None:
    ports = _SyntheticPorts()
    with _client(ports) as client:
        response = client.post("/ingest/backfill", json=_request(dry_run=True))
        assert response.status_code == 200
        body = response.json()
        assert body["schema_version"] == SCHEMA_VERSION
        assert body["status"] == "PREVIEW"
        assert body["writes_performed"] is False
        assert body["estimated_event_count"] == 7
        assert [name for name, _ in ports.calls] == ["preview"]
        _assert_no_store(response)


def test_queued_job_returns_opaque_id_and_status_keeps_event_and_ingest_time() -> None:
    ports = _SyntheticPorts()
    with _client(ports) as client:
        response = client.post("/ingest/backfill", json=_request(dry_run=False))
        assert response.status_code == 202
        queued = response.json()
        assert queued["schema_version"] == SCHEMA_VERSION
        assert queued["status"] == "QUEUED"
        assert queued["job_id"] == ports.enqueued_id
        assert queued["job_id"] not in str(_request(dry_run=False))
        assert set(queued) == {"schema_version", "job_id", "status"}
        _assert_no_store(response)

        status = client.get(f"/ingest/backfill/{queued['job_id']}")
        assert status.status_code == 200
        body = status.json()
        assert body["source_state"] == "AVAILABLE"
        assert body["gap_state"] == "DETECTED"
        assert body["last_event_time_ns"] == 1_700_000_000_000_000_111
        assert body["last_ingest_time_ns"] == 1_700_000_000_000_000_222
        assert body["last_event_time_ns"] != body["last_ingest_time_ns"]
        _assert_no_store(status)


@pytest.mark.parametrize(
    "body",
    [
        {**_request(dry_run=True), "unexpected": "request-canary"},
        {**_request(dry_run=True), "max_records": True},
        {**_request(dry_run=True), "instruments": []},
        {**_request(dry_run=True), "types": ["trades", "unsupported"]},
            {
                **_request(dry_run=True),
                "t1_ns": 1_700_000_000_000_000_000 + 31 * 24 * 60 * 60 * 1_000_000_000 + 1,
            },
        {**_request(dry_run=True), "dry_run": "true"},
    ],
)
def test_backfill_rejects_unbounded_or_non_strict_requests(body: dict[str, object]) -> None:
    ports = _SyntheticPorts()
    with _client(ports) as client:
        response = client.post("/ingest/backfill", json=body)
        _assert_error(response, 400, "INVALID_REQUEST")
        assert ports.calls == []


def test_backfill_rejects_oversized_body_and_unknown_operations() -> None:
    ports = _SyntheticPorts()
    with _client(ports) as client:
        oversized = client.post(
            "/ingest/backfill",
            content=b"{" + b" " * 8_200 + b"}",
            headers={"content-type": "application/json"},
        )
        _assert_error(oversized, 400, "INVALID_REQUEST")
        _assert_error(client.delete("/md/latest"), 405, "METHOD_NOT_ALLOWED")
        _assert_error(client.get("/ingest/backfill/job-canary?x=1"), 400, "INVALID_REQUEST")
        assert ports.calls == []


def test_fixed_errors_do_not_echo_port_exceptions_or_request_values() -> None:
    ports = _SyntheticPorts(fail_with_canary=True)
    with _client(ports) as client:
        response = client.get(
            "/md/latest?venue=XTS1&instrument=SYNTH&type=trades"
        )
        _assert_error(response, 503, "MARKET_DATA_UNAVAILABLE")
        assert _PRIVATE_CANARY not in response.text
        assert "SYNTH" not in response.text

        response = client.post("/ingest/backfill", json=_request(dry_run=False))
        _assert_error(response, 503, "BACKFILL_UNAVAILABLE")
        assert _PRIVATE_CANARY not in response.text


def test_disabled_router_fails_closed_with_fixed_no_store_error() -> None:
    ports = _SyntheticPorts()
    with _client(ports, enabled=False) as client:
        response = client.get(
            "/md/latest?venue=XTS1&instrument=SYNTH&type=trades"
        )
        _assert_error(response, 503, "SERVICE_UNAVAILABLE")
        assert ports.calls == []


def test_injected_ports_are_synthetic_and_router_attempts_no_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def blocked(*args: object, **kwargs: object) -> Any:
        raise AssertionError("NETWORK_ACCESS_FORBIDDEN")

    ports = _SyntheticPorts()
    with _client(ports) as client:
        monkeypatch.setattr(socket, "create_connection", blocked)
        monkeypatch.setattr(socket.socket, "connect", blocked)
        monkeypatch.setattr(socket.socket, "connect_ex", blocked)
        assert client.get("/ingest/venues").status_code == 200
        assert client.get(
            "/md/latest?venue=XTS1&instrument=SYNTH&type=trades"
        ).status_code == 200
        assert client.post("/ingest/backfill", json=_request(dry_run=True)).status_code == 200
        assert all(name in {"venues", "latest", "preview"} for name, _ in ports.calls)
