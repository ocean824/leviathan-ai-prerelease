from __future__ import annotations

from collections.abc import AsyncIterator
from uuid import UUID

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from leviathan_api.auth import OperatorPrincipalMiddleware, make_local_operator_profile
from leviathan_api.main import create_app
from leviathan_api.paper_mounts_runtime import PaperMarketDataPortsV1
from leviathan_api.routers.market_data_paper_v1 import (
    BackfillJobStatusV1,
    BackfillPreviewV1,
    create_paper_market_data_router,
)
from leviathan_api.wave35_mounts import Wave35MountDependenciesV1
from leviathan_core.security.authz_models import (
    _VERIFIER_MARKER,
    PrincipalV1,
    TrustedPrincipalAdapterV1,
    TrustedPrincipalV1,
)
from leviathan_market_data.health import SourceHealthSnapshot
from leviathan_market_data.schema import NormalizedMarketEventV1, PriceValue, TradePayload

BASE = "/"
SCHEMA = "leviathan.market-data-paper/1"
OPERATOR_PORT = 49321
OPERATOR_CAPABILITY = "ab" * 32
OPERATOR_ORIGIN = f"http://127.0.0.1:{OPERATOR_PORT}"


def _health(**changes: object) -> SourceHealthSnapshot:
    values: dict[str, object] = {
        "provider": "synthetic-provider",
        "dataset": "synthetic-dataset",
        "venue": "XNAS",
        "instrument_id": "instrument-1",
        "channel": "trades",
        "last_received_time_ns": 2_000,
        "last_processed_time_ns": 2_001,
        "last_provider_time_ns": 1_900,
        "last_exchange_time_ns": 1_800,
        "gap_count": 0,
        "late_count": 0,
        "node_clock_offset_ms": 0.0,
        "node_drift_alert": False,
        "node_publish_blocked": False,
        "last_event_clock_adjusted": False,
        "queued_count": 0,
        "queue_pressure": 0.0,
        "unhealthy": False,
        "freshness": "UNKNOWN",
    }
    values.update(changes)
    return SourceHealthSnapshot(**values)  # type: ignore[arg-type]


def _event(**changes: object) -> NormalizedMarketEventV1:
    values: dict[str, object] = {
        "event_id": UUID("00000000-0000-0000-0000-000000000001"),
        "provider": "synthetic-provider",
        "dataset": "synthetic-dataset",
        "venue": "XNAS",
        "native_symbol": "SYN1",
        "leviathan_symbol": "SYN1",
        "instrument_id": "instrument-1",
        "instrument_type": "equity",
        "channel": "trades",
        "event_type": "trade",
        "source_mode": "historical",
        "event_time_ns": 1_000,
        "source_time_ns": 1_100,
        "exchange_time_ns": 1_050,
        "ingest_time_ns": 2_000,
        "processing_time_ns": 2_001,
        "received_time_ns": 2_002,
        "native_sequence": 1,
        "sequence_synthetic": False,
        "native_trade_id": "trade-1",
        "source_record_key": "source-row-1",
        "source_record_ref": "source-ref-1",
        "source_payload_sha256": "a" * 64,
        "mapping_version": "mapping-1",
        "identity_policy_version": "identity-1",
        "quality_flags": (),
        "reconstructed": False,
        "idempotency_key": "event-1",
        "payload": TradePayload(price=PriceValue(value="10.25"), size="2"),
    }
    values.update(changes)
    return NormalizedMarketEventV1(**values)


class _VenuePort:
    def __init__(self, rows: object = ()) -> None:
        self.rows = rows
        self.calls: list[tuple[str | None, int]] = []

    def read_venue_health(
        self, *, venue: str | None, limit: int
    ) -> tuple[SourceHealthSnapshot, ...] | None:
        self.calls.append((venue, limit))
        if isinstance(self.rows, Exception):
            raise self.rows
        return self.rows  # type: ignore[return-value]


class _LatestPort:
    def __init__(self, result: object) -> None:
        self.result = result
        self.calls: list[tuple[str, str, str]] = []

    def read_latest(
        self, *, venue: str, instrument: str, data_type: str
    ) -> tuple[NormalizedMarketEventV1 | None, SourceHealthSnapshot | None] | None:
        self.calls.append((venue, instrument, data_type))
        if isinstance(self.result, Exception):
            raise self.result
        return self.result  # type: ignore[return-value]


class _BackfillPort:
    def __init__(self) -> None:
        self.previews: list[object] = []
        self.enqueued: list[object] = []
        self.jobs: dict[str, BackfillJobStatusV1 | None] = {}

    def preview_backfill(self, request: object) -> BackfillPreviewV1:
        self.previews.append(request)
        return BackfillPreviewV1(estimated_event_count=12)

    def enqueue_backfill(self, request: object) -> str:
        self.enqueued.append(request)
        return "job-001"

    def read_backfill_job(self, job_id: str) -> BackfillJobStatusV1 | None:
        return self.jobs.get(job_id)


class _ChartStreamPort:
    def __init__(self) -> None:
        self.principals: list[TrustedPrincipalV1] = []

    async def open_chart_stream(
        self,
        *,
        principal: TrustedPrincipalV1,
        venue: str,
        instrument: str,
        data_type: str,
    ) -> AsyncIterator[dict[str, object]]:
        self.principals.append(principal)
        snapshot = {
            "instrument": instrument,
            "venue": venue,
            "source": "none",
            "eventTimeNs": None,
            "candles": [],
            "depth": None,
            "footprint": None,
            "gex": None,
            "indicators": None,
        }
        yield {
            "schema_version": 1,
            "state": "UNKNOWN",
            "snapshot": snapshot,
            "received_time_ns": "1000",
            "code": "NOT_CONFIGURED",
        }
        yield {
            "schema_version": 1,
            "state": "HEALTHY",
            "snapshot": {**snapshot, "eventTimeNs": "2000"},
            "received_time_ns": "2001",
            "code": None,
        }


def _client(
    *,
    enabled: bool = True,
    venue_port: object | None = None,
    latest_port: object | None = None,
    backfill_port: object | None = None,
    chart_stream_port: object | None = None,
    chart_principal_resolver: object | None = None,
) -> TestClient:
    app = FastAPI()
    app.include_router(
        create_paper_market_data_router(
            enabled=enabled,
            venue_port=venue_port,  # type: ignore[arg-type]
            latest_port=latest_port,  # type: ignore[arg-type]
            backfill_port=backfill_port,  # type: ignore[arg-type]
            chart_stream_port=chart_stream_port,  # type: ignore[arg-type]
            chart_principal_resolver=chart_principal_resolver,  # type: ignore[arg-type]
        )
    )
    return TestClient(app, client=("127.0.0.1", 54_321))


def test_authorized_loopback_chart_websocket_receives_snapshot_then_live_delta() -> None:
    principal = TrustedPrincipalAdapterV1.from_verified_claims(
        PrincipalV1(
            principal_id="chart-operator",
            project_id="leviathan-ai",
            roles=("operator",),
            env="PAPER",
        ),
        verifier_marker=_VERIFIER_MARKER,
    )
    port = _ChartStreamPort()
    client = _client(
        chart_stream_port=port,
        chart_principal_resolver=lambda _connection: principal,
    )

    with client.websocket_connect(
        "/md/chart?venue=XNAS&instrument=instrument-1&type=trades"
    ) as websocket:
        snapshot = websocket.receive_json()
        delta = websocket.receive_json()

    assert snapshot["snapshot"]["instrument"] == "instrument-1"
    assert snapshot["snapshot"]["eventTimeNs"] is None
    assert snapshot["state"] == "UNKNOWN"
    assert delta["snapshot"]["eventTimeNs"] == "2000"
    assert delta["state"] == "HEALTHY"
    assert port.principals == [principal]


def _create_app_operator_websocket_app(port: _ChartStreamPort) -> FastAPI:
    dependencies = Wave35MountDependenciesV1(
        paper_market_data_ports=PaperMarketDataPortsV1(
            venue_port=_VenuePort(),
            latest_port=_LatestPort(None),
            backfill_port=_BackfillPort(),
            chart_stream_port=port,
        )
    )
    app = create_app(wave35_mount_dependencies=dependencies)
    # This is the real create_app/W35 stack. Only the local launch evidence is
    # supplied here; the W35 principal resolver remains its production default.
    assert dependencies.principal_resolver is None
    app.add_middleware(
        OperatorPrincipalMiddleware,
        capability=OPERATOR_CAPABILITY,
        port=OPERATOR_PORT,
        profile=make_local_operator_profile(
            principal_id="chart-operator", project_id="leviathan-ai", env="paper"
        ),
    )
    return app


def test_create_app_default_resolver_authorizes_websocket_snapshot_then_delta(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("LEVIATHAN_LICENSE_STATE", raising=False)
    monkeypatch.delenv("LEVIATHAN_LICENSE_FEATURES", raising=False)
    port = _ChartStreamPort()
    app = _create_app_operator_websocket_app(port)
    with (
        TestClient(app, base_url=OPERATOR_ORIGIN, client=("127.0.0.1", 54_321)) as client,
        client.websocket_connect(
            "/api/md/chart?venue=XNAS&instrument=instrument-1&type=trades",
            headers={
                "x-leviathan-capability": OPERATOR_CAPABILITY,
                "origin": OPERATOR_ORIGIN,
                "host": f"127.0.0.1:{OPERATOR_PORT}",
            },
        ) as websocket,
    ):
        snapshot = websocket.receive_json()
        delta = websocket.receive_json()

    assert snapshot["snapshot"]["instrument"] == "instrument-1"
    assert snapshot["state"] == "UNKNOWN"
    assert delta["snapshot"]["eventTimeNs"] == "2000"
    assert delta["state"] == "HEALTHY"
    assert len(port.principals) == 1
    principal = port.principals[0]
    assert principal.principal_id == "chart-operator"
    assert principal.project_id == "leviathan-ai"


@pytest.mark.parametrize(
    ("headers", "close_code"),
    [
        ({"origin": OPERATOR_ORIGIN}, 4401),
        (
            {
                "x-leviathan-capability": "cd" * 32,
                "origin": OPERATOR_ORIGIN,
                "host": f"127.0.0.1:{OPERATOR_PORT}",
            },
            4401,
        ),
        (
            {
                "x-leviathan-capability": OPERATOR_CAPABILITY,
                "origin": "http://evil.invalid",
                "host": f"127.0.0.1:{OPERATOR_PORT}",
            },
            4403,
        ),
    ],
)
def test_create_app_default_resolver_refuses_websocket_before_accept(
    monkeypatch: pytest.MonkeyPatch,
    headers: dict[str, str],
    close_code: int,
) -> None:
    monkeypatch.delenv("LEVIATHAN_LICENSE_STATE", raising=False)
    monkeypatch.delenv("LEVIATHAN_LICENSE_FEATURES", raising=False)
    port = _ChartStreamPort()
    app = _create_app_operator_websocket_app(port)
    with (
        TestClient(app, base_url=OPERATOR_ORIGIN, client=("127.0.0.1", 54_321)) as client,
        pytest.raises(WebSocketDisconnect) as raised,
        client.websocket_connect(
            "/api/md/chart?venue=XNAS&instrument=instrument-1&type=trades",
            headers={"host": f"127.0.0.1:{OPERATOR_PORT}", **headers},
        ),
    ):
        pytest.fail("unauthorized websocket unexpectedly accepted")

    assert raised.value.code == close_code
    assert port.principals == []


def _backfill_body(**changes: object) -> dict[str, object]:
    values: dict[str, object] = {
        "venue": "XNAS",
        "instruments": ["instrument-1"],
        "types": ["trades"],
        "t0_ns": 1_000,
        "t1_ns": 2_000,
        "max_records": 100,
        "dry_run": True,
    }
    values.update(changes)
    return values


def test_factory_default_is_disabled() -> None:
    app = FastAPI()
    app.include_router(create_paper_market_data_router())
    response = TestClient(app).get("/ingest/venues")
    assert response.status_code == 503
    assert response.json() == {
        "schema_version": SCHEMA,
        "error": {"code": "SERVICE_UNAVAILABLE"},
    }


def test_router_is_disabled_by_default_and_no_ports_are_touched() -> None:
    venue = _VenuePort((_health(),))
    latest = _LatestPort((_event(), _health()))
    backfill = _BackfillPort()
    client = _client(enabled=False, venue_port=venue, latest_port=latest, backfill_port=backfill)

    responses = (
        client.get("/ingest/venues"),
        client.get(
            "/md/latest",
            params={"venue": "XNAS", "instrument": "instrument-1", "type": "trades"},
        ),
        client.post("/ingest/backfill", json=_backfill_body()),
    )
    assert all(response.status_code == 503 for response in responses)
    unavailable = {"schema_version": SCHEMA, "error": {"code": "SERVICE_UNAVAILABLE"}}
    assert all(response.json() == unavailable for response in responses)
    assert all(response.headers["cache-control"] == "no-store" for response in responses)
    assert venue.calls == []
    assert latest.calls == []
    assert backfill.previews == []
    assert backfill.enqueued == []


def test_venues_are_bounded_sorted_and_do_not_echo_provider_details() -> None:
    rows = (_health(channel="quotes", last_provider_time_ns=1_500), _health())
    port = _VenuePort(rows)
    response = _client(venue_port=port).get("/ingest/venues?venue=XNAS&limit=2")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    body = response.json()
    assert body == {
        "schema_version": SCHEMA,
        "source_state": "AVAILABLE",
        "venues": [
            {
                "venue": "XNAS",
                "type": "quotes",
                "freshness": "UNKNOWN",
                "unhealthy": False,
                "gap_count": 0,
                "last_event_time_ns": 1_500,
                "last_ingest_time_ns": 2_000,
            },
            {
                "venue": "XNAS",
                "type": "trades",
                "freshness": "UNKNOWN",
                "unhealthy": False,
                "gap_count": 0,
                "last_event_time_ns": 1_900,
                "last_ingest_time_ns": 2_000,
            },
        ],
    }
    assert port.calls == [("XNAS", 2)]
    assert "synthetic-provider" not in response.text
    assert "synthetic-dataset" not in response.text


def test_venues_explicitly_report_absent_source_and_invalid_queries_do_not_read() -> None:
    port = _VenuePort(None)
    client = _client(venue_port=port)
    absent = client.get("/ingest/venues")
    assert absent.json() == {"schema_version": SCHEMA, "source_state": "ABSENT", "venues": []}
    assert client.get("/ingest/venues?limit=101").status_code == 400
    assert client.get("/ingest/venues?limit=1&limit=2").status_code == 400
    assert client.get("/ingest/venues?other=canary").status_code == 400
    assert port.calls == [(None, 50)]


def test_latest_keeps_event_source_and_ingest_times_separate_and_explicit_gap() -> None:
    port = _LatestPort((_event(), _health(gap_count=2)))
    response = _client(latest_port=port).get(
        "/md/latest?venue=XNAS&instrument=instrument-1&type=trades"
    )
    assert response.status_code == 200
    body = response.json()
    assert body["source_state"] == "AVAILABLE"
    assert body["gap_state"] == "DETECTED"
    assert body["event"] == {
        "event_id": "00000000-0000-0000-0000-000000000001",
        "event_type": "trade",
        "event_time_ns": 1_000,
        "source_time_ns": 1_100,
        "ingest_time_ns": 2_000,
    }
    assert "synthetic-provider" not in response.text
    assert "synthetic-dataset" not in response.text
    assert "source-row-1" not in response.text
    assert port.calls == [("XNAS", "instrument-1", "trades")]


def test_latest_absent_event_and_health_are_both_explicit() -> None:
    port = _LatestPort((None, None))
    body = (
        _client(latest_port=port)
        .get("/md/latest?venue=XNAS&instrument=instrument-1&type=trades")
        .json()
    )
    assert body == {
        "schema_version": SCHEMA,
        "source_state": "ABSENT",
        "gap_state": "UNKNOWN",
        "event": None,
    }


@pytest.mark.parametrize(
    "query",
    [
        "venue=xnas&instrument=instrument-1&type=trades",
        "venue=XNAS&instrument=instrument-1&type=unsupported",
        "venue=XNAS&instrument=api_key&type=trades",
        "venue=XNAS&instrument=instrument-1&type=trades&extra=x",
    ],
)
def test_latest_rejects_unsupported_or_unsafe_query_without_read(query: str) -> None:
    port = _LatestPort((_event(), _health()))
    response = _client(latest_port=port).get("/md/latest?" + query)
    assert response.status_code == 400
    assert response.json()["schema_version"] == SCHEMA
    assert "api_key" not in response.text
    assert port.calls == []


def test_latest_rejects_mismatched_port_event_and_hides_port_exception() -> None:
    mismatched = _LatestPort((_event(instrument_id="other"), _health()))
    response = _client(latest_port=mismatched).get(
        "/md/latest?venue=XNAS&instrument=instrument-1&type=trades"
    )
    assert response.status_code == 503
    assert response.json() == {
        "schema_version": SCHEMA,
        "error": {"code": "MARKET_DATA_UNAVAILABLE"},
    }

    raising = _LatestPort(RuntimeError("private-provider-secret"))
    error = _client(latest_port=raising).get(
        "/md/latest?venue=XNAS&instrument=instrument-1&type=trades"
    )
    assert error.status_code == 503
    assert "private-provider-secret" not in error.text


def test_dry_run_only_previews_and_returns_no_write_claim() -> None:
    port = _BackfillPort()
    response = _client(backfill_port=port).post("/ingest/backfill", json=_backfill_body())
    assert response.status_code == 200
    assert response.json() == {
        "schema_version": SCHEMA,
        "status": "PREVIEW",
        "instrument_count": 1,
        "type_count": 1,
        "max_records": 100,
        "estimated_event_count": 12,
        "writes_performed": False,
    }
    assert len(port.previews) == 1
    assert port.enqueued == []


def test_non_dry_run_queues_opaque_job_and_status_is_allowlisted() -> None:
    port = _BackfillPort()
    client = _client(backfill_port=port)
    created = client.post("/ingest/backfill", json=_backfill_body(dry_run=False))
    assert created.status_code == 202
    assert created.json() == {"schema_version": SCHEMA, "job_id": "job-001", "status": "QUEUED"}
    assert port.previews == []
    assert len(port.enqueued) == 1

    port.jobs["job-001"] = BackfillJobStatusV1(
        status="RUNNING",
        completed_count=3,
        remaining_count=7,
        source_state="AVAILABLE",
        gap_state="DETECTED",
        last_event_time_ns=1_500,
        last_ingest_time_ns=1_700,
    )
    status = client.get("/ingest/backfill/job-001")
    assert status.status_code == 200
    assert status.json() == {
        "schema_version": SCHEMA,
        "job_id": "job-001",
        "status": "RUNNING",
        "completed_count": 3,
        "remaining_count": 7,
        "source_state": "AVAILABLE",
        "gap_state": "DETECTED",
        "last_event_time_ns": 1_500,
        "last_ingest_time_ns": 1_700,
    }


def test_backfill_validates_before_port_and_errors_are_content_free() -> None:
    port = _BackfillPort()
    client = _client(backfill_port=port)
    invalid = (
        _backfill_body(dry_run="true"),
        _backfill_body(venue="bad!"),
        _backfill_body(instruments=["api_key"]),
        _backfill_body(instruments=["i" for _ in range(11)]),
        _backfill_body(types=["trades", "trades"]),
        _backfill_body(t1_ns=1_000 + 31 * 24 * 60 * 60 * 1_000_000_000 + 1),
        _backfill_body(unexpected="private-canary"),
    )
    for body in invalid:
        response = client.post("/ingest/backfill", json=body)
        assert response.status_code == 400
        assert response.json() == {"schema_version": SCHEMA, "error": {"code": "INVALID_REQUEST"}}
        assert "private-canary" not in response.text
    assert port.previews == []
    assert port.enqueued == []


def test_empty_query_and_body_are_rejected_and_method_errors_are_no_store() -> None:
    client = _client(backfill_port=_BackfillPort())
    response = client.post("/ingest/backfill?unexpected=1", json=_backfill_body())
    assert response.status_code == 400
    assert response.headers["cache-control"] == "no-store"
    for method in ("PUT", "DELETE", "PATCH", "OPTIONS"):
        response = client.request(method, "/ingest/venues")
        assert response.status_code == 405
        assert response.headers["cache-control"] == "no-store"
        assert response.json() == {
            "schema_version": SCHEMA,
            "error": {"code": "METHOD_NOT_ALLOWED"},
        }


def test_body_requires_application_json_and_duplicate_keys_are_rejected() -> None:
    port = _BackfillPort()
    client = _client(backfill_port=port)
    plain = client.post(
        "/ingest/backfill",
        content='{"bad": true}',
        headers={"content-type": "text/plain"},
    )
    duplicate = client.post(
        "/ingest/backfill",
        content='{"venue":"XNAS","venue":"XNYS"}',
        headers={"content-type": "application/json"},
    )
    assert plain.status_code == duplicate.status_code == 400
    assert port.previews == []
    assert port.enqueued == []
