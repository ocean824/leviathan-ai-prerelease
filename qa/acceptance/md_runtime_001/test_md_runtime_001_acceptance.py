# ruff: noqa: SLF001
from __future__ import annotations

import asyncio
import hashlib
import logging
import urllib.error
from collections.abc import Mapping
from pathlib import Path
from typing import ClassVar
from uuid import UUID

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from httpx import ASGITransport, AsyncClient
from starlette.websockets import WebSocketDisconnect

from leviathan_api import main as api_main
from leviathan_api.auth import OperatorPrincipalMiddleware, make_local_operator_profile
from leviathan_api.auth.chart_stream_tickets import ChartStreamTicketStore
from leviathan_api.main import create_app
from leviathan_api.market_data_runtime import MarketDataRuntime
from leviathan_api.market_data_runtime_config import (
    CONFIG_RELATIVE_PATH,
    MAX_CONFIG_BYTES,
    BackfillConfigV1,
    MarketDataConfigError,
    MarketDataRuntimeConfigV1,
    load_market_data_runtime_config,
    resolve_market_data_runtime_config,
)
from leviathan_api.paper_mounts_runtime import PaperMarketDataPortsV1
from leviathan_api.routers.market_data_paper_v1 import (
    BackfillJobStatusV1,
    BackfillPreviewV1,
    create_paper_market_data_router,
)
from leviathan_api.settings import get_settings
from leviathan_api.state import build_app_state
from leviathan_api.wave35_mounts import Wave35MountDependenciesV1
from leviathan_core.risk.halt_store import HaltStore, ProfileClassification, ProfileEvidence
from leviathan_core.security.authz_models import (
    PrincipalV1,
    TrustedPrincipalAdapterV1,
    TrustedPrincipalV1,
)
from leviathan_market_data.live import backfill_jobs as backfill_jobs_module
from leviathan_market_data.live.backfill_jobs import (
    MAX_BACKFILL_JOBS,
    BackfillJobQueue,
    BackfillJobsError,
    BackfillPreview,
)
from leviathan_market_data.providers.databento_live import (
    DatabentoLiveAdapter,
    DatabentoLiveError,
    DatabentoLiveSubscriptionV1,
)
from leviathan_market_data.providers.databento_mapping import DatabentoSessionMappingRegistry
from leviathan_market_data.providers.massive import MAX_RESPONSE_BYTES, MassiveAdapterError
from leviathan_market_data.providers.massive_transport import UrllibMassiveTransport
from leviathan_market_data.schema import NormalizedMarketEventV1, PriceValue, TradePayload

_KEY = "0123456789abcdef0123456789abcdef"
_CHALLENGE = "acceptance-challenge"
_OPERATOR_CAPABILITY = "ab" * 32
_OPERATOR_PORT = 49_137
_TOML = """\
schema_version = 1
project_id = "acceptance-project"
environment = "PAPER"

[databento]
enabled = false
dataset = "synthetic-dataset"
stype_in = "raw_symbol"
schemas = ["trades"]
instruments = ["SYNTH"]

[massive]
enabled = false
dataset = "synthetic-dataset"
stype_in = "raw_symbol"
schemas = ["trades"]
instruments = ["SYNTH"]

[backfill]
max_jobs = 16
max_records = 1000
max_window_ns = 86400000000000
max_estimated_usd = "3.50"

[reconnect]
min_delay_ms = 200
max_delay_ms = 5000
max_attempts = 2
"""


class _GatewaySocket:
    def __init__(self, auth_line: bytes = b"success=1|session_id=fake-session\n") -> None:
        self.lines = [b"lsg_version=1.0\n", f"cram={_CHALLENGE}\n".encode(), auth_line]
        self.writes: list[bytes] = []
        self.closed = False

    async def read_line(self, _maximum: int) -> bytes:
        return self.lines.pop(0)

    async def write(self, data: bytes) -> None:
        self.writes.append(data)

    async def read_chunk(self, _maximum: int) -> bytes:
        return b""

    async def close(self) -> None:
        self.closed = True


class _GatewayTransport:
    def __init__(self, socket: _GatewaySocket) -> None:
        self.socket = socket
        self.opened: list[tuple[str, int, float]] = []

    async def open(self, host: str, port: int, timeout_s: float) -> _GatewaySocket:
        self.opened.append((host, port, timeout_s))
        return self.socket


@pytest.mark.asyncio
async def test_databento_cram_handshake_frames_and_chunks_symbols(
    caplog: pytest.LogCaptureFixture,
) -> None:
    socket = _GatewaySocket()
    transport = _GatewayTransport(socket)
    symbols = tuple(f"SYN{i:03d}" for i in range(501))
    subscription = DatabentoLiveSubscriptionV1("GLBX.MDP3", "trades", "raw_symbol", symbols)
    caplog.set_level(logging.DEBUG)

    session = await DatabentoLiveAdapter(transport).connect(subscription, api_key=_KEY)

    assert transport.opened == [("glbx-mdp3.lsg.databento.com", 13_000, 5.0)]
    auth = socket.writes[0].decode("ascii")
    expected = hashlib.sha256(f"{_CHALLENGE}|{_KEY}".encode("ascii")).hexdigest()
    assert auth.startswith(f"auth={expected}-{_KEY[-5:]}|dataset=GLBX.MDP3|encoding=dbn|")
    chunks = [item.decode("ascii") for item in socket.writes if item.startswith(b"schema=")]
    assert len(chunks) == 2
    assert "is_last=0" in chunks[0] and "is_last=1" in chunks[1]
    assert len(chunks[0].split("symbols=", 1)[1].split("|", 1)[0].split(",")) == 500
    assert len(chunks[1].split("symbols=", 1)[1].split("|", 1)[0].split(",")) == 1
    assert socket.writes[-1] == b"start_session\n"
    assert _KEY not in caplog.text and expected not in caplog.text
    assert _KEY not in repr(session) and expected not in repr(session)
    await session.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("challenge_line", "auth_line", "expected_code"),
    [
        (b"cram=invalid challenge\n", b"success=1|session_id=x\n", "PROTOCOL_ERROR"),
        (f"cram={_CHALLENGE}\n".encode(), b"success=0|error={_KEY}\n", "AUTH_REJECTED"),
    ],
)
async def test_databento_auth_failures_are_content_free(
    challenge_line: bytes,
    auth_line: bytes,
    expected_code: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    socket = _GatewaySocket(auth_line)
    socket.lines[1] = challenge_line
    caplog.set_level(logging.DEBUG)
    subscription = DatabentoLiveSubscriptionV1("GLBX.MDP3", "trades", "raw_symbol", ("SYN",))

    with pytest.raises(DatabentoLiveError) as caught:
        await DatabentoLiveAdapter(_GatewayTransport(socket)).connect(subscription, api_key=_KEY)

    assert caught.value.code == expected_code
    assert str(caught.value) == expected_code
    assert _KEY not in repr(caught.value) + str(caught.value) + caplog.text
    assert _CHALLENGE not in repr(caught.value) + str(caught.value) + caplog.text
    assert socket.closed


def _mapping(*, raw_symbol: str, start_ns: int, end_ns: int, instrument_id: int = 42) -> object:
    from databento_dbn import SType, SymbolMappingMsg

    return SymbolMappingMsg(
        publisher_id=1,
        instrument_id=instrument_id,
        ts_event=start_ns,
        stype_in=SType.CONTINUOUS,
        stype_in_symbol="SYN.CONT",
        stype_out=SType.RAW_SYMBOL,
        stype_out_symbol=raw_symbol,
        start_ts=start_ns,
        end_ts=end_ns,
    )


def _registry(session: str) -> DatabentoSessionMappingRegistry:
    return DatabentoSessionMappingRegistry(
        session_id=session,
        dataset="GLBX.MDP3",
        stype_in="continuous",
        configured_symbols=("SYN.CONT",),
    )


def test_symbol_mapping_remap_is_half_open_and_reconnect_starts_empty() -> None:
    registry = _registry("session-one")
    first = registry.ingest(_mapping(raw_symbol="SYNM7", start_ns=100, end_ns=150))
    second = registry.ingest(_mapping(raw_symbol="SYNZ7", start_ns=150, end_ns=200))

    assert registry.resolve(publisher_id=1, instrument_id=42, event_time_ns=149) == first
    assert registry.resolve(publisher_id=1, instrument_id=42, event_time_ns=150) == second
    assert registry.resolve(publisher_id=1, instrument_id=42, event_time_ns=200) is None

    replacement = _registry("session-two")
    assert replacement.mapping_count == 0
    assert replacement.resolve(publisher_id=1, instrument_id=42, event_time_ns=150) is None


def test_pre_mapping_record_is_dropped_and_degrades_databento_session() -> None:
    from databento_dbn import Action, Side, TradeMsg

    from leviathan_market_data.providers.databento_live import DatabentoLiveSession

    class Socket:
        def __init__(self) -> None:
            self.chunks = [b"frame-1", b"frame-2", b""]

        async def read_line(self, _maximum: int) -> bytes:
            raise AssertionError("established session has no control reads")

        async def write(self, _data: bytes) -> None:
            raise AssertionError("established session has no control writes")

        async def read_chunk(self, _maximum: int) -> bytes:
            return self.chunks.pop(0)

        async def close(self) -> None:
            return None

    unmapped = TradeMsg(
        publisher_id=1,
        instrument_id=99,
        ts_event=120,
        price=1_000_000_000,
        size=1,
        action=Action.TRADE,
        side=Side.BID,
        depth=0,
        ts_recv=121,
    )
    mapped = TradeMsg(
        publisher_id=1,
        instrument_id=42,
        ts_event=120,
        price=1_000_000_000,
        size=1,
        action=Action.TRADE,
        side=Side.BID,
        depth=0,
        ts_recv=121,
    )

    class Decoder:
        rows: ClassVar[list[list[object]]] = [
            [unmapped],
            [_mapping(raw_symbol="SYNM7", start_ns=100, end_ns=200), mapped],
        ]

        def write_and_decode(self, _chunk: bytes) -> list[object]:
            return self.rows.pop(0)

    session = DatabentoLiveSession(
        socket=Socket(),
        decoder=Decoder(),
        session_id="session-one",
        mapping_registry=_registry("session-one"),
    )
    yielded: list[object] = []

    async def collect() -> None:
        with pytest.raises(DatabentoLiveError) as caught:
            async for record in session.records():
                yielded.append(record)
        assert caught.value.code == "SESSION_CLOSED"

    asyncio.run(collect())
    assert unmapped not in yielded
    assert mapped in yielded
    assert session.unmapped_record_count == 1
    assert session.mapping_degraded is True


def _runtime_config(
    *, cap: str = "3.50", massive_enabled: bool = False
) -> MarketDataRuntimeConfigV1:
    payload: dict[str, object] = {
        "schema_version": 1,
        "project_id": "acceptance-project",
        "environment": "PAPER",
        "databento": {
            "enabled": True,
            "dataset": "GLBX.MDP3",
            "stype_in": "continuous",
            "schemas": ("trades",),
            "instruments": ("SYN.CONT",),
        },
        "massive": {
            "enabled": massive_enabled,
            "dataset": "stocks",
            "stype_in": "raw_symbol",
            "schemas": ("trades",),
            "instruments": ("SYN",),
        },
        "backfill": {
            "max_jobs": 16,
            "max_records": 1000,
            "max_window_ns": 86_400_000_000_000,
        },
        "reconnect": {"min_delay_ms": 200, "max_delay_ms": 5000, "max_attempts": 2},
    }
    payload["backfill"]["max_estimated_usd"] = cap  # type: ignore[index]
    return MarketDataRuntimeConfigV1.model_validate(payload, strict=True)


def _runtime_config_without_cost_cap() -> MarketDataRuntimeConfigV1:
    config = _runtime_config()
    uncapped_backfill = BackfillConfigV1.model_construct(
        max_jobs=config.backfill.max_jobs,
        max_records=config.backfill.max_records,
        max_window_ns=config.backfill.max_window_ns,
        max_estimated_usd=None,
    )
    return MarketDataRuntimeConfigV1.model_construct(
        schema_version=config.schema_version,
        project_id=config.project_id,
        environment=config.environment,
        databento=config.databento,
        massive=config.massive,
        backfill=uncapped_backfill,
        reconnect=config.reconnect,
    )


def test_databento_missing_cap_and_over_cap_fail_before_data_transport() -> None:
    from leviathan_api.market_data_backfill import BackfillBridgeError, HistoricalBackfillExecutor
    from leviathan_api.routers.market_data_paper_v1 import BackfillRequestV1
    from leviathan_market_data.providers.databento import HttpResponse
    from leviathan_market_data.providers.databento_mapping import DatabentoResolvedMappingV1
    from leviathan_market_data.symbology import InstrumentMapping, MappingRegistry

    class Transport:
        def __init__(self, result: bytes) -> None:
            self.result = result
            self.requests: list[object] = []

        def request(self, request: object) -> HttpResponse:
            self.requests.append(request)
            return HttpResponse(200, {}, self.result)

    request = BackfillRequestV1(
        venue="DBN-PUB-123",
        instruments=("SYN.CONT",),
        types=("trades",),
        t0_ns=1_000_000_000,
        t1_ns=2_000_000_000,
        max_records=100,
        dry_run=False,
    )
    mapping = InstrumentMapping(
        provider="databento",
        dataset="GLBX.MDP3",
        venue="DBN-PUB-123",
        native_symbol="SYNM7",
        instrument_id="SYN.CONT",
        leviathan_symbol="SYN.CONT",
        instrument_type="equity",
        mapping_version="acceptance-v1",
    )
    resolved = DatabentoResolvedMappingV1(
        provider_id=123,
        native_instrument_id=42,
        configured_symbol="SYN.CONT",
        raw_symbol="SYNM7",
        valid_from_ns=1,
        valid_to_ns=3_000_000_000,
        mapping=mapping,
        registry=MappingRegistry((mapping,)),
    )

    missing_transport = Transport(b'{"cost":"0.01"}')
    missing = MarketDataRuntime(
        config=_runtime_config_without_cost_cap(),
        vault_ref_resolver=lambda _ref, _name: "synthetic-resolved-key",
        historical_transports={"databento": missing_transport},
    )
    missing._dbn_mapping_slots["trades"] = {(123, 42, 1): resolved}
    missing._dbn_mapping_count = 1
    with pytest.raises(BackfillBridgeError) as no_cap:
        asyncio.run(
            HistoricalBackfillExecutor(
                config=missing.config,
                resolve_key=missing._resolve_key,
                commit_event=missing._commit_historical_event,
                mapping_snapshot=missing._snapshot_databento_mappings,
                clock_ns=missing.clock_ns,
                historical_transports={"databento": missing_transport},
            ).execute(request)
        )
    assert no_cap.value.code == "NOT_CONFIGURED"
    assert missing_transport.requests == []

    capped_transport = Transport(b'{"cost":"1.01"}')
    capped = MarketDataRuntime(
        config=_runtime_config(cap="1.00"),
        vault_ref_resolver=lambda _ref, _name: "synthetic-resolved-key",
        historical_transports={"databento": capped_transport},
    )
    capped._dbn_mapping_slots["trades"] = {(123, 42, 1): resolved}
    capped._dbn_mapping_count = 1
    executor = HistoricalBackfillExecutor(
        config=capped.config,
        resolve_key=capped._resolve_key,
        commit_event=capped._commit_historical_event,
        mapping_snapshot=capped._snapshot_databento_mappings,
        clock_ns=capped.clock_ns,
        historical_transports={"databento": capped_transport},
    )
    with pytest.raises(BackfillBridgeError) as over_cap:
        asyncio.run(executor.execute(request))
    assert over_cap.value.code == "COST_CAP"
    assert len(capped_transport.requests) == 1
    assert "metadata.get_cost" in getattr(capped_transport.requests[0], "url", "")


@pytest.mark.asyncio
async def test_backfill_seventeenth_job_rejected_and_shutdown_cancels_and_drains() -> None:
    started = asyncio.Event()
    cancelled = asyncio.Event()

    class Executor:
        def preview(self, _request: object) -> BackfillPreview:
            return BackfillPreview(estimated_event_count=1)

        async def execute(self, _request: object) -> tuple[int, int | None, int | None]:
            started.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                cancelled.set()
                raise

    queue = BackfillJobQueue(Executor(), max_jobs=MAX_BACKFILL_JOBS)
    job_ids = [queue.enqueue(object())]
    for _ in range(MAX_BACKFILL_JOBS - 1):
        job_ids.append(queue.enqueue(object()))
    with pytest.raises(BackfillJobsError) as full:
        queue.enqueue(object())
    assert full.value.code == "QUEUE_FULL"
    await asyncio.wait_for(started.wait(), timeout=1)
    await queue.close()
    assert cancelled.is_set()
    assert all(queue.read(job_id) is not None for job_id in job_ids)
    assert all(queue.read(job_id).status == "CANCELLED" for job_id in job_ids if queue.read(job_id))
    with pytest.raises(BackfillJobsError):
        queue.enqueue(object())


@pytest.mark.asyncio
async def test_backfill_reuses_capacity_and_evicts_terminal_status_through_route(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Executor:
        def __init__(self, gate: asyncio.Event | None = None) -> None:
            self.gate = gate
            self.started = asyncio.Event()

        def preview(self, _request: object) -> BackfillPreview:
            return BackfillPreview(estimated_event_count=1)

        async def execute(self, _request: object) -> tuple[int, int | None, int | None]:
            self.started.set()
            if self.gate is not None:
                await self.gate.wait()
            return (1, 1_000, 1_001)

    class QueuePort:
        def __init__(self, queue: BackfillJobQueue) -> None:
            self.queue = queue

        def preview_backfill(self, request: object) -> BackfillPreviewV1:
            del request
            return BackfillPreviewV1(estimated_event_count=1)

        def enqueue_backfill(self, request: object) -> str:
            return self.queue.enqueue(request)

        def read_backfill_job(self, job_id: str) -> BackfillJobStatusV1 | None:
            job = self.queue.read(job_id)
            if job is None:
                return None
            return BackfillJobStatusV1(
                status=job.status,
                completed_count=job.completed_count,
                remaining_count=job.remaining_count,
                source_state=job.source_state,
                gap_state=job.gap_state,
                last_event_time_ns=job.last_event_time_ns,
                last_ingest_time_ns=job.last_ingest_time_ns,
            )

    def make_app(port: QueuePort) -> FastAPI:
        app = FastAPI()
        app.include_router(create_paper_market_data_router(enabled=True, backfill_port=port))
        return app

    body = {
        "venue": "XNAS",
        "instruments": ["SYN"],
        "types": ["trades"],
        "t0_ns": 1_000,
        "t1_ns": 2_000,
        "max_records": 10,
        "dry_run": False,
    }
    safe_ids = iter(f"a1b2c3d4e5f6g7h{value:x}" for value in range(64))

    class SafeJobId:
        def __init__(self) -> None:
            self.hex = next(safe_ids)

    monkeypatch.setattr(backfill_jobs_module, "uuid4", SafeJobId)
    executor = Executor()
    queue = BackfillJobQueue(executor)
    app = make_app(QueuePort(queue))
    job_ids: list[str] = []
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        for _ in range(MAX_BACKFILL_JOBS + 8):
            created = await client.post("/ingest/backfill", json=body)
            assert created.status_code == 202, created.text
            job_id = created.json()["job_id"]
            job_ids.append(job_id)

            async def wait_for_terminal(target_id: str) -> None:
                while queue.read(target_id) is None or queue.read(target_id).status not in {
                    "COMPLETED",
                    "FAILED",
                }:
                    await asyncio.sleep(0.001)

            await asyncio.wait_for(wait_for_terminal(job_id), timeout=2.0)
            status = await client.get(f"/ingest/backfill/{job_id}")
            assert status.status_code == 200
            assert status.json()["status"] == "COMPLETED"

        retained = await client.get(f"/ingest/backfill/{job_ids[8]}")
        evicted = await client.get(f"/ingest/backfill/{job_ids[7]}")
        assert retained.status_code == 200
        assert retained.json()["status"] == "COMPLETED"
        assert evicted.status_code == 404
        assert evicted.json()["error"]["code"] == "BACKFILL_NOT_FOUND"
    await queue.close()

    gate = asyncio.Event()
    concurrent_executor = Executor(gate)
    concurrent_queue = BackfillJobQueue(concurrent_executor)
    concurrent_app = make_app(QueuePort(concurrent_queue))
    async with AsyncClient(
        transport=ASGITransport(app=concurrent_app), base_url="http://testserver"
    ) as client:
        created = [
            await client.post("/ingest/backfill", json=body) for _ in range(MAX_BACKFILL_JOBS)
        ]
        assert all(response.status_code == 202 for response in created)
        await asyncio.wait_for(concurrent_executor.started.wait(), timeout=2.0)
        with pytest.raises(BackfillJobsError) as full:
            concurrent_queue.enqueue(object())
        assert full.value.code == "QUEUE_FULL"
        rejected = await client.post("/ingest/backfill", json=body)
        assert rejected.status_code == 503
        assert rejected.json()["error"]["code"] == "BACKFILL_UNAVAILABLE"
    gate.set()
    await concurrent_queue._queue.join()
    assert all(
        concurrent_queue.read(response.json()["job_id"]).status == "COMPLETED"
        for response in created
    )
    await concurrent_queue.close()


@pytest.mark.asyncio
async def test_missing_provider_key_reports_not_configured_without_transport_call() -> None:
    calls: list[str] = []

    class Transport:
        async def connect(self, *_args: object, **_kwargs: object) -> object:
            calls.append("connect")
            raise AssertionError("fake transport must remain unopened")

    runtime = MarketDataRuntime(
        config=_runtime_config(massive_enabled=True), transports={"massive": Transport()}
    )
    runtime.start()
    try:
        expected_status = {"databento": "NOT_CONFIGURED", "massive": "NOT_CONFIGURED"}

        async def wait_until_configured_status() -> None:
            while runtime.feed_status != expected_status:
                await asyncio.sleep(0.01)

        await asyncio.wait_for(wait_until_configured_status(), timeout=2.0)
        assert runtime.feed_status == {"databento": "NOT_CONFIGURED", "massive": "NOT_CONFIGURED"}
        assert calls == []
    finally:
        await runtime.close()


class _FakeResponse:
    status = 200
    headers: Mapping[str, str] = {"Content-Type": "application/json"}

    def __init__(self, body: bytes) -> None:
        self.body = body
        self.read_size: int | None = None
        self.closed = False

    def read(self, size: int) -> bytes:
        self.read_size = size
        return self.body[:size]

    def close(self) -> None:
        self.closed = True


class _FakeOpener:
    def __init__(self, response: object) -> None:
        self.response = response
        self.calls: list[object] = []

    def open(self, request: object, *, timeout: float) -> object:
        self.calls.append((request, timeout))
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def _massive_get(
    transport: UrllibMassiveTransport, url: str = "https://api.massive.com/v3/trades/AAPL"
):
    return transport.get(
        url,
        headers={"Authorization": f"Bearer {_KEY}"},
        params={},
        connect_timeout_s=3.0,
        read_timeout_s=5.0,
        total_timeout_s=10.0,
        allow_redirects=False,
    )


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.example/v3/trades/AAPL",
        "https://api.massive.com/v1/private",
    ],
)
def test_massive_transport_pins_host_and_path_before_open(
    url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    opener = _FakeOpener(_FakeResponse(b"{}"))
    monkeypatch.setattr("urllib.request.build_opener", lambda *_args: opener)
    with pytest.raises(MassiveAdapterError):
        _massive_get(UrllibMassiveTransport(), url)
    assert opener.calls == []


def test_massive_transport_refuses_redirect_and_caps_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    url = "https://api.massive.com/v3/trades/AAPL"
    redirect = urllib.error.HTTPError(url, 302, "redirect", {}, None)
    redirect_opener = _FakeOpener(redirect)
    monkeypatch.setattr("urllib.request.build_opener", lambda *_args: redirect_opener)
    redirected = _massive_get(UrllibMassiveTransport())
    assert redirected.status_code == 302 and redirected.body == b""
    assert len(redirect_opener.calls) == 1

    response = _FakeResponse(b"x" * (MAX_RESPONSE_BYTES + 1))
    opener = _FakeOpener(response)
    monkeypatch.setattr("urllib.request.build_opener", lambda *_args: opener)
    with pytest.raises(MassiveAdapterError) as oversized:
        _massive_get(UrllibMassiveTransport())
    assert oversized.value.code == "OVERSIZE"
    assert response.read_size == MAX_RESPONSE_BYTES + 1 and response.closed

    error_opener = _FakeOpener(OSError(f"failure {_KEY}"))
    monkeypatch.setattr("urllib.request.build_opener", lambda *_args: error_opener)
    with pytest.raises(MassiveAdapterError) as failed:
        _massive_get(UrllibMassiveTransport())
    assert _KEY not in str(failed.value) and _KEY not in repr(failed.value)


def _valid_config() -> MarketDataRuntimeConfigV1:
    payload = {
        "schema_version": 1,
        "project_id": "acceptance-project",
        "environment": "PAPER",
        "databento": {
            "enabled": False,
            "dataset": "GLBX.MDP3",
            "stype_in": "raw_symbol",
            "schemas": ("trades",),
            "instruments": ("SYN",),
        },
        "massive": {
            "enabled": False,
            "dataset": "stocks",
            "stype_in": "raw_symbol",
            "schemas": ("trades",),
            "instruments": ("SYN",),
        },
        "backfill": {
            "max_jobs": 16,
            "max_records": 1000,
            "max_window_ns": 86400000000000,
            "max_estimated_usd": "3.50",
        },
        "reconnect": {"min_delay_ms": 200, "max_delay_ms": 5000, "max_attempts": 2},
    }
    return MarketDataRuntimeConfigV1.model_validate(payload, strict=True)


def test_startup_config_precedence_and_fail_closed_file_validation(tmp_path: Path) -> None:
    config_path = tmp_path / CONFIG_RELATIVE_PATH
    config_path.parent.mkdir(parents=True)
    config_path.write_text(
        _TOML.replace('project_id = "acceptance-project"', 'project_id = "file-project"'),
        encoding="utf-8",
    )

    injected = resolve_market_data_runtime_config(
        injected=_valid_config(), app_data_dir=tmp_path, environ={}
    )
    assert injected.status == "CONFIGURED" and injected.source == "INJECTED"
    assert injected.config is not None and injected.config.project_id == "acceptance-project"
    from_file = resolve_market_data_runtime_config(injected=None, app_data_dir=tmp_path, environ={})
    assert from_file.status == "CONFIGURED" and from_file.source == "FILE"
    assert from_file.config is not None and from_file.config.project_id == "file-project"
    absent = resolve_market_data_runtime_config(
        injected=None, app_data_dir=tmp_path / "absent", environ={}
    )
    assert absent.status == "NOT_CONFIGURED"

    for text in (
        _TOML.replace("[reconnect]", "[unknown]\nvalue=1\n\n[reconnect]"),
        _TOML.replace(
            "[reconnect]", '[credentials]\napi_key="synthetic-secret-value"\n\n[reconnect]'
        ),
    ):
        bad = tmp_path / "bad-runtime.toml"
        bad.write_text(text, encoding="utf-8")
        with pytest.raises(MarketDataConfigError) as caught:
            load_market_data_runtime_config(bad)
        assert caught.value.code == "INVALID_CONFIG"
        assert "synthetic-secret-value" not in str(caught.value)

    oversized = tmp_path / "oversized.toml"
    oversized.write_bytes(b"#" * (MAX_CONFIG_BYTES + 1))
    with pytest.raises(MarketDataConfigError) as too_large:
        load_market_data_runtime_config(oversized)
    assert too_large.value.code == "CONFIG_TOO_LARGE"

    import _winapi

    target_root = tmp_path / "junction-target"
    target_file = target_root / CONFIG_RELATIVE_PATH
    target_file.parent.mkdir(parents=True)
    target_file.write_text(_TOML, encoding="utf-8")
    junction = tmp_path / "junction-root"
    try:
        _winapi.CreateJunction(str(target_root), str(junction))
    except (OSError, NotImplementedError) as error:
        pytest.skip(f"host does not permit junction creation: {type(error).__name__}")
    with pytest.raises(MarketDataConfigError) as unsafe:
        load_market_data_runtime_config(junction / CONFIG_RELATIVE_PATH)
    assert unsafe.value.code == "CONFIG_UNSAFE_PATH"
    junction.rmdir()


def _issued_principal() -> TrustedPrincipalV1:
    from leviathan_core.security.authz_models import _VERIFIER_MARKER

    claims = PrincipalV1(
        principal_id="synthetic-chart-principal",
        project_id="acceptance-project",
        roles=("operator",),
        env="PAPER",
    )
    return TrustedPrincipalAdapterV1.from_verified_claims(claims, verifier_marker=_VERIFIER_MARKER)


def test_chart_websocket_refuses_non_loopback_and_wrong_principal() -> None:
    class StreamPort:
        async def open_chart_stream(self, **_kwargs: object):
            async def no_events():
                if False:
                    yield {}

            return no_events()

    router = create_paper_market_data_router(
        enabled=True,
        chart_stream_port=StreamPort(),  # type: ignore[arg-type]
        chart_principal_resolver=lambda _request: object(),  # type: ignore[return-value]
    )
    app = FastAPI()
    app.include_router(router)
    with TestClient(app, client=("203.0.113.8", 7000)) as client:
        connection = client.websocket_connect("/md/chart?venue=XNAS&instrument=SYN&type=trades")
        with pytest.raises(WebSocketDisconnect) as non_loopback:
            connection.__enter__()
        assert non_loopback.value.code == 4403
    with TestClient(app, client=("127.0.0.1", 7000)) as client:
        connection = client.websocket_connect("/md/chart?venue=XNAS&instrument=SYN&type=trades")
        with pytest.raises(WebSocketDisconnect) as wrong_principal:
            connection.__enter__()
        assert wrong_principal.value.code == 4401


class _ChartTicketClock:
    def __init__(self) -> None:
        self.now_ns = 1_000_000

    def __call__(self) -> int:
        return self.now_ns


class _FakeChartFeed:
    def __init__(self) -> None:
        self.principals: list[TrustedPrincipalV1] = []
        self.scopes: list[tuple[str, str, str]] = []

    async def open_chart_stream(
        self,
        *,
        principal: TrustedPrincipalV1,
        venue: str,
        instrument: str,
        data_type: str,
    ):
        self.principals.append(principal)
        self.scopes.append((venue, instrument, data_type))
        yield {
            "schema_version": 1,
            "state": "UNKNOWN",
            "snapshot": {"instrument": instrument, "eventTimeNs": None},
            "received_time_ns": "1000",
            "code": "SNAPSHOT",
        }
        await asyncio.sleep(0)
        yield {
            "schema_version": 1,
            "state": "HEALTHY",
            "snapshot": {"instrument": instrument, "eventTimeNs": "2000"},
            "received_time_ns": "2001",
            "code": "DELTA",
        }


class _ChartVenuePort:
    def read_venue_health(self, *, venue: str | None, limit: int):
        del venue, limit
        return ()


class _ChartLatestPort:
    def read_latest(self, *, venue: str, instrument: str, data_type: str):
        del venue, instrument, data_type
        return None


class _ChartBackfillPort:
    def preview_backfill(self, _request: object) -> BackfillPreviewV1:
        return BackfillPreviewV1(estimated_event_count=0)

    def enqueue_backfill(self, _request: object) -> str:
        return "unused-job"

    def read_backfill_job(self, _job_id: str) -> BackfillJobStatusV1 | None:
        return None


def _build_ticketed_chart_app(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    clock: _ChartTicketClock,
) -> tuple[FastAPI, _FakeChartFeed, ChartStreamTicketStore]:
    feed = _FakeChartFeed()
    ticket_store = ChartStreamTicketStore(clock_ns=clock, ttl_ns=2_000_000_000)
    repo_root = Path(__file__).resolve().parents[3]
    risk_lock = repo_root / "tests/fixtures/risk_lock/risk_governance.lock.yaml"
    halt_path = tmp_path / "halt-state.sqlite3"
    HaltStore.provision_new(
        halt_path,
        tmp_path,
        ProfileEvidence(
            ProfileClassification.NEVER_PROVISIONED,
            verified=True,
            references=("pytest:md-runtime-acceptance",),
        ),
    )
    monkeypatch.setenv("LEVIATHAN_HALT_STORE_PATH", str(halt_path))
    monkeypatch.setenv(
        "LEVIATHAN_DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path.as_posix()}/api.db"
    )
    monkeypatch.setenv(
        "LEVIATHAN_RISK_LOCK_SHA256",
        "46a03497679f8a59c82229ba28cef4bf56b7c1d7c30ae936016f876c9eaf3c51",
    )
    monkeypatch.setattr(
        api_main,
        "build_app_state",
        lambda: build_app_state(lock_path=risk_lock),
    )
    get_settings.cache_clear()
    dependencies = Wave35MountDependenciesV1(
        app_data_dir=tmp_path / "app-data",
        chart_stream_ticket_store=ticket_store,
        paper_market_data_ports=PaperMarketDataPortsV1(
            venue_port=_ChartVenuePort(),  # type: ignore[arg-type]
            latest_port=_ChartLatestPort(),  # type: ignore[arg-type]
            backfill_port=_ChartBackfillPort(),  # type: ignore[arg-type]
            chart_stream_port=feed,  # type: ignore[arg-type]
        ),
    )
    app = create_app(wave35_mount_dependencies=dependencies)
    app.add_middleware(
        OperatorPrincipalMiddleware,
        capability=_OPERATOR_CAPABILITY,
        port=_OPERATOR_PORT,
        profile=make_local_operator_profile(
            principal_id="md-runtime-operator",
            project_id="acceptance-project",
            env="development",
            roles=("operator",),
        ),
    )
    return app, feed, ticket_store


def _chart_ticket_headers(*, origin: str | None = None) -> dict[str, str]:
    return {
        "X-Leviathan-Capability": _OPERATOR_CAPABILITY,
        "Origin": origin or f"http://127.0.0.1:{_OPERATOR_PORT}",
        "Host": f"127.0.0.1:{_OPERATOR_PORT}",
    }


def _mint_chart_ticket(client: TestClient, *, instrument: str = "SYN") -> str:
    response = client.post(
        "/api/md/chart/ticket",
        json={"venue": "XNAS", "instrument": instrument, "type": "trades"},
        headers=_chart_ticket_headers(),
    )
    assert response.status_code == 201
    body = response.json()
    assert body["schema_version"] == 1
    assert isinstance(body["ticket"], str)
    return body["ticket"]


def _connect_with_chart_ticket(
    client: TestClient,
    ticket: str,
    *,
    instrument: str = "SYN",
    origin: str | None = None,
):
    path = f"/api/md/chart?venue=XNAS&instrument={instrument}&type=trades"
    assert ticket not in path
    return client.websocket_connect(
        path,
        subprotocols=["leviathan.chart.v1", f"ticket.{ticket}"],
        headers={
            "Origin": origin or f"http://127.0.0.1:{_OPERATOR_PORT}",
            "Host": f"127.0.0.1:{_OPERATOR_PORT}",
        },
    )


def _expect_chart_ticket_denied(connection, *, code: int = 4401, ticket: str | None = None) -> None:
    try:
        connection.__enter__()
    except WebSocketDisconnect as denied:
        assert denied.code == code
        if ticket is not None:
            assert ticket not in getattr(denied, "reason", "")
        return
    connection.close()
    connection.__exit__(None, None, None)
    pytest.fail(f"websocket unexpectedly accepted; expected close code {code}")


def _find_operator_middleware(app: FastAPI) -> OperatorPrincipalMiddleware:
    layer = app.middleware_stack
    while layer is not None:
        if isinstance(layer, OperatorPrincipalMiddleware):
            return layer
        layer = getattr(layer, "app", None)
    raise AssertionError("operator principal middleware is not installed")


def test_real_app_chart_websocket_ticket_browser_flow_is_scoped_single_use_and_secret_safe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    clock = _ChartTicketClock()
    app, feed, ticket_store = _build_ticketed_chart_app(tmp_path, monkeypatch, clock=clock)
    ws_path = "/api/md/chart?venue=XNAS&instrument=SYN&type=trades"
    alternate_origin = f"http://127.0.0.1:{_OPERATOR_PORT + 1}"
    try:
        with TestClient(
            app,
            base_url=f"http://127.0.0.1:{_OPERATOR_PORT}",
            client=("127.0.0.1", _OPERATOR_PORT),
        ) as client:
            first_ticket = _mint_chart_ticket(client)
            assert first_ticket not in ws_path
            with _connect_with_chart_ticket(client, first_ticket) as websocket:
                assert websocket.accepted_subprotocol == "leviathan.chart.v1"
                snapshot = websocket.receive_json()
                delta = websocket.receive_json()
            assert snapshot["code"] == "SNAPSHOT"
            assert snapshot["state"] == "UNKNOWN"
            assert delta["code"] == "DELTA"
            assert delta["snapshot"]["eventTimeNs"] == "2000"

            # First consumption is one-shot; the same protocol ticket cannot reconnect.
            _expect_chart_ticket_denied(
                _connect_with_chart_ticket(client, first_ticket), ticket=first_ticket
            )

            expired_ticket = _mint_chart_ticket(client)
            clock.now_ns += ticket_store.ttl_ns + 1
            _expect_chart_ticket_denied(
                _connect_with_chart_ticket(client, expired_ticket), ticket=expired_ticket
            )

            wrong_origin_ticket = _mint_chart_ticket(client)
            wrong_origin = client.websocket_connect(
                ws_path,
                subprotocols=["leviathan.chart.v1", f"ticket.{wrong_origin_ticket}"],
                headers={
                    "Host": f"127.0.0.1:{_OPERATOR_PORT}",
                    "Origin": "https://attacker.example",
                },
            )
            _expect_chart_ticket_denied(wrong_origin, code=4403, ticket=wrong_origin_ticket)

            wrong_host_ticket = _mint_chart_ticket(client)
            wrong_host = client.websocket_connect(
                ws_path,
                subprotocols=["leviathan.chart.v1", f"ticket.{wrong_host_ticket}"],
                headers={
                    "Host": "attacker.example",
                    "Origin": f"http://127.0.0.1:{_OPERATOR_PORT}",
                },
            )
            _expect_chart_ticket_denied(wrong_host, code=4403, ticket=wrong_host_ticket)
            missing_host = client.websocket_connect(
                ws_path,
                subprotocols=["leviathan.chart.v1", f"ticket.{wrong_host_ticket}"],
                headers={
                    "Host": "",
                    "Origin": f"http://127.0.0.1:{_OPERATOR_PORT}",
                },
            )
            _expect_chart_ticket_denied(missing_host, code=4403, ticket=wrong_host_ticket)
            # Wrong/missing Host must be rejected before consuming the ticket.
            with _connect_with_chart_ticket(client, wrong_host_ticket) as websocket:
                assert websocket.accepted_subprotocol == "leviathan.chart.v1"
                assert websocket.receive_json()["code"] == "SNAPSHOT"
                assert websocket.receive_json()["code"] == "DELTA"

            # Change only the middleware's expected Origin after issuance. The new
            # request passes middleware evidence but must fail the ticket's stored
            # origin binding.
            bound_origin_ticket = _mint_chart_ticket(client)
            middleware = _find_operator_middleware(app)
            original_origin = middleware._origin
            middleware._origin = alternate_origin.encode("ascii")
            try:
                _expect_chart_ticket_denied(
                    _connect_with_chart_ticket(
                        client, bound_origin_ticket, origin=alternate_origin
                    ),
                    ticket=bound_origin_ticket,
                )
            finally:
                middleware._origin = original_origin

            out_of_scope_ticket = _mint_chart_ticket(client)
            _expect_chart_ticket_denied(
                _connect_with_chart_ticket(client, out_of_scope_ticket, instrument="OTHER"),
                ticket=out_of_scope_ticket,
            )

            missing_ticket = client.websocket_connect(
                ws_path,
                headers={
                    "Host": f"127.0.0.1:{_OPERATOR_PORT}",
                    "Origin": _chart_ticket_headers()["Origin"],
                },
            )
            _expect_chart_ticket_denied(missing_ticket)

            # Reconnect uses a newly minted ticket; the browser protocol contains
            # the credential while the URL remains ticket-free.
            clock.now_ns += 1
            reconnect_ticket = _mint_chart_ticket(client)
            assert reconnect_ticket != first_ticket
            with _connect_with_chart_ticket(client, reconnect_ticket) as websocket:
                assert websocket.accepted_subprotocol == "leviathan.chart.v1"
                assert websocket.receive_json()["code"] == "SNAPSHOT"
                assert websocket.receive_json()["code"] == "DELTA"
    finally:
        get_settings.cache_clear()

    assert [principal.principal_id for principal in feed.principals] == [
        "md-runtime-operator",
        "md-runtime-operator",
        "md-runtime-operator",
    ]
    assert feed.scopes == [
        ("XNAS", "SYN", "trades"),
        ("XNAS", "SYN", "trades"),
        ("XNAS", "SYN", "trades"),
    ]
    assert ticket_store.size == 1  # Wrong Origin is unconsumed; wrong Host ticket was retried.
    logged_text = "\n".join(f"{record.msg} {record.args}" for record in caplog.records)
    for token in (
        first_ticket,
        expired_ticket,
        wrong_origin_ticket,
        wrong_host_ticket,
        bound_origin_ticket,
        out_of_scope_ticket,
        reconnect_ticket,
    ):
        assert token not in logged_text
        assert token not in ws_path


def _event(index: int) -> NormalizedMarketEventV1:
    source_time = 1_700_000_000_000_000_000 + index
    return NormalizedMarketEventV1(
        event_id=UUID(int=index + 1),
        provider="massive",
        dataset="stocks",
        venue="MASS",
        native_symbol="SYN",
        leviathan_symbol="SYN",
        instrument_id="SYN",
        instrument_type="equity",
        channel="trades",
        event_type="trade",
        source_mode="live",
        event_time_ns=source_time,
        source_time_ns=source_time,
        exchange_time_ns=source_time,
        ingest_time_ns=source_time,
        processing_time_ns=source_time,
        received_time_ns=source_time,
        native_sequence=index + 1,
        sequence_synthetic=False,
        native_trade_id=f"trade-{index}",
        source_record_key=f"record-{index}",
        source_record_ref=f"ref-{index}",
        source_payload_sha256="a" * 64,
        mapping_version="mapping-v1",
        identity_policy_version="identity-v1",
        quality_flags=(),
        reconstructed=False,
        idempotency_key=f"event-{index}",
        payload=TradePayload(price=PriceValue(value="10.25"), size="1"),
    )


@pytest.mark.asyncio
async def test_chart_overflow_resyncs_to_fresh_snapshot_and_disconnect_is_visible() -> None:
    runtime = MarketDataRuntime(
        config=_runtime_config(massive_enabled=True),
        clock_ns=lambda: 1_800_000_000_000_000_000,
        monotonic_ns=lambda: 1,
    )
    principal = _issued_principal()
    stream = runtime.open_chart_stream(
        principal=principal, venue="MASS", instrument="SYN", data_type="trades"
    )
    initial = await anext(stream)
    assert initial["state"] in {"UNKNOWN", "DISCONNECTED"}
    client = next(iter(runtime._chart_clients.values()))
    runtime._set_feed_status("massive", "ACTIVE")
    for index in range(20):
        event = _event(index)
        runtime.latest_store.record(event, runtime.health_snapshot_for(event))
        runtime._publish_ack(event)
    assert client.queue.qsize() <= client.queue.maxsize == 16
    queued = [client.queue.get_nowait() for _ in range(client.queue.qsize())]
    resyncs = [envelope for envelope in queued if envelope["code"] == "RESYNC"]
    assert resyncs
    resync_time = int(resyncs[0]["snapshot"]["footprint"][-1]["eventTimeNs"])
    assert _event(0).event_time_ns < resync_time < _event(19).event_time_ns
    assert queued[-1]["snapshot"]["footprint"][-1]["eventTimeNs"] == str(_event(19).event_time_ns)

    runtime._set_feed_status("massive", "DISCONNECTED")
    disconnected = runtime._current_envelope(client)
    assert disconnected["state"] == "DISCONNECTED"
    await stream.aclose()
    await runtime.close()
