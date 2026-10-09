"""Injection-only HTTP seam for bounded paper market-data reads and backfill jobs.

This router does not mount itself, access credentials, construct vendor SDKs, or
perform provider I/O. The injected ports expose only normalized records and
bounded job operations. Error responses are fixed and content-free.
"""

from __future__ import annotations

import asyncio
import inspect
import ipaddress
import json
import re
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import suppress
from dataclasses import dataclass
from typing import Protocol
from uuid import UUID

from fastapi import APIRouter, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict, model_validator
from starlette.requests import HTTPConnection
from starlette.routing import Match
from starlette.types import Receive, Scope, Send

from leviathan_api.auth.chart_stream_tickets import (
    ChartStreamScopeV1,
    ChartStreamTicketError,
    ChartStreamTicketStore,
    principal_binding,
)
from leviathan_api.auth.operator_principal import (
    LocalOperatorProfileV1,
    require_local_operator_profile,
)
from leviathan_core.security.authz_models import TrustedPrincipalV1
from leviathan_core.text.safe_label import contains_deny_word, is_safe_identifier
from leviathan_market_data.health import SourceHealthSnapshot
from leviathan_market_data.schema import NormalizedMarketEventV1

_SCHEMA_VERSION = "leviathan.market-data-paper/1"
_MAX_QUERY_BYTES = 2_048
_MAX_BODY_BYTES = 8_192
_MAX_VENUE_ROWS = 100
_MAX_INSTRUMENTS = 10
_MAX_DATA_TYPES = 6
_MAX_RECORDS = 50_000
_MAX_WINDOW_NS = 31 * 24 * 60 * 60 * 1_000_000_000
_INT64_MAX = (1 << 63) - 1
_VENUE = re.compile(r"(?:[A-Z0-9]{4}|DBN-PUB-[0-9]{1,19})\Z", re.ASCII)
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)
_DATA_TYPES = frozenset({"trades", "quotes", "mbp-1", "mbo", "mbp-10", "ohlcv-1m"})
_JOB_STATUSES = frozenset({"QUEUED", "RUNNING", "COMPLETED", "FAILED", "CANCELLED"})
_SOURCE_STATES = frozenset({"AVAILABLE", "ABSENT", "UNKNOWN"})
_GAP_STATES = frozenset({"DETECTED", "NONE", "UNKNOWN"})


class MarketDataPaperRouteError(ValueError):
    """Content-free router construction failure."""

    def __init__(self, code: str = "INVALID_CONFIGURATION") -> None:
        self.code = code if code == "INVALID_CONFIGURATION" else "INVALID_CONFIGURATION"
        super().__init__(self.code)


@dataclass(frozen=True, slots=True)
class BackfillPreviewV1:
    """Bounded, read-only preview returned by the injected planner port."""

    estimated_event_count: int | None

    def __post_init__(self) -> None:
        if self.estimated_event_count is not None and (
            type(self.estimated_event_count) is not int
            or not 0 <= self.estimated_event_count <= _MAX_RECORDS
        ):
            raise ValueError("INVALID_PREVIEW")


@dataclass(frozen=True, slots=True)
class BackfillJobStatusV1:
    """Allowlisted job status; never carries a raw provider error or request."""

    status: str
    completed_count: int
    remaining_count: int
    source_state: str
    gap_state: str
    last_event_time_ns: int | None = None
    last_ingest_time_ns: int | None = None

    def __post_init__(self) -> None:
        if (
            type(self.status) is not str
            or self.status not in _JOB_STATUSES
            or type(self.completed_count) is not int
            or type(self.remaining_count) is not int
            or not 0 <= self.completed_count <= _MAX_RECORDS
            or not 0 <= self.remaining_count <= _MAX_RECORDS
            or type(self.source_state) is not str
            or self.source_state not in _SOURCE_STATES
            or type(self.gap_state) is not str
            or self.gap_state not in _GAP_STATES
            or not _valid_optional_ns(self.last_event_time_ns)
            or not _valid_optional_ns(self.last_ingest_time_ns)
        ):
            raise ValueError("INVALID_JOB_STATUS")


class BackfillRequestV1(BaseModel):
    """Strict bounded backfill request. Times are UTC nanoseconds, range [t0,t1)."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    venue: str
    instruments: tuple[str, ...]
    types: tuple[str, ...]
    t0_ns: int
    t1_ns: int
    max_records: int
    dry_run: bool

    @model_validator(mode="after")
    def _bounded(self) -> BackfillRequestV1:
        if type(self.venue) is not str or _VENUE.fullmatch(self.venue) is None:
            raise ValueError("INVALID_REQUEST")
        if (
            type(self.instruments) is not tuple
            or not 1 <= len(self.instruments) <= _MAX_INSTRUMENTS
            or any(not _safe_identifier(item) for item in self.instruments)
            or len(set(self.instruments)) != len(self.instruments)
        ):
            raise ValueError("INVALID_REQUEST")
        if (
            type(self.types) is not tuple
            or not 1 <= len(self.types) <= _MAX_DATA_TYPES
            or any(type(item) is not str or item not in _DATA_TYPES for item in self.types)
            or len(set(self.types)) != len(self.types)
        ):
            raise ValueError("INVALID_REQUEST")
        if (
            type(self.t0_ns) is not int
            or type(self.t1_ns) is not int
            or not 0 < self.t0_ns < self.t1_ns <= _INT64_MAX
            or self.t1_ns - self.t0_ns > _MAX_WINDOW_NS
            or type(self.max_records) is not int
            or not 1 <= self.max_records <= _MAX_RECORDS
            or type(self.dry_run) is not bool
        ):
            raise ValueError("INVALID_REQUEST")
        return self


class ChartStreamTicketRequestV1(BaseModel):
    """Exact one-stream scope for a short-lived browser ticket."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    venue: str
    instrument: str
    type: str

    @model_validator(mode="after")
    def _bounded(self) -> ChartStreamTicketRequestV1:
        ChartStreamScopeV1(self.venue, self.instrument, self.type)
        return self


def _valid_optional_ns(value: object) -> bool:
    return value is None or (type(value) is int and 0 < value <= _INT64_MAX)


def _safe_identifier(value: object) -> bool:
    return (
        type(value) is str
        and _IDENTIFIER.fullmatch(value) is not None
        and is_safe_identifier(value)
        and not contains_deny_word(value)
    )


class VenueStatusReadPortV1(Protocol):
    """Bounded venue-health snapshots from normalized market-data ingress."""

    def read_venue_health(
        self, *, venue: str | None, limit: int
    ) -> tuple[SourceHealthSnapshot, ...] | None: ...


class LatestMarketDataReadPortV1(Protocol):
    """One latest normalized event and its separate source-health evidence."""

    def read_latest(
        self, *, venue: str, instrument: str, data_type: str
    ) -> tuple[NormalizedMarketEventV1 | None, SourceHealthSnapshot | None] | None: ...


class BackfillJobPortV1(Protocol):
    """Preview, enqueue and inspect a bounded historical-data job."""

    def preview_backfill(self, request: BackfillRequestV1) -> BackfillPreviewV1: ...

    def enqueue_backfill(self, request: BackfillRequestV1) -> str | Awaitable[str]: ...

    def read_backfill_job(self, job_id: str) -> BackfillJobStatusV1 | None: ...


class ChartStreamReadPortV1(Protocol):
    def open_chart_stream(
        self, *, principal: TrustedPrincipalV1, venue: str, instrument: str, data_type: str
    ) -> AsyncIterator[dict[str, object]]: ...


class _NoStoreRoute(APIRoute):
    """Use fixed 405 responses and prevent caches retaining paper data."""

    def matches(self, scope: Scope) -> tuple[Match, Scope]:
        match, child_scope = super().matches(scope)
        path = scope.get("path")
        if (
            match is Match.PARTIAL
            and scope.get("type") == "http"
            and isinstance(path, str)
            and self.path_regex.match(path) is not None
        ):
            return Match.FULL, child_scope
        return match, child_scope

    async def handle(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("method") not in (self.methods or set()):
            await _error(405, "METHOD_NOT_ALLOWED")(scope, receive, send)
            return
        await super().handle(scope, receive, send)


def _error(status_code: int, code: str) -> JSONResponse:
    return JSONResponse(
        {"schema_version": _SCHEMA_VERSION, "error": {"code": code}},
        status_code=status_code,
        headers={"Cache-Control": "no-store"},
    )


def _ok(status_code: int, content: dict[str, object]) -> JSONResponse:
    return JSONResponse(
        content,
        status_code=status_code,
        headers={"Cache-Control": "no-store"},
    )


def _query(request: Request, allowed: frozenset[str]) -> dict[str, str] | None:
    raw = request.scope.get("query_string", b"")
    if not isinstance(raw, bytes) or len(raw) > _MAX_QUERY_BYTES:
        return None
    pairs = request.query_params.multi_items()
    if any(key not in allowed for key, _ in pairs):
        return None
    result: dict[str, str] = {}
    for key, value in pairs:
        if key in result or not value.isascii() or len(value) > 128:
            return None
        result[key] = value
    return result


def _query_limit(value: str | None, *, default: int, maximum: int) -> int | None:
    if value is None:
        return default
    if not value.isascii() or not value.isdigit() or len(value) > 6:
        return None
    number = int(value)
    return number if 1 <= number <= maximum else None


def _health_matches(
    snapshot: SourceHealthSnapshot,
    *,
    venue: str,
    instrument: str | None = None,
    data_type: str | None = None,
) -> bool:
    return (
        type(snapshot) is SourceHealthSnapshot
        and _VENUE.fullmatch(snapshot.venue) is not None
        and snapshot.venue == venue
        and type(snapshot.channel) is str
        and snapshot.channel in _DATA_TYPES
        and (instrument is None or snapshot.instrument_id == instrument)
        and (data_type is None or snapshot.channel == data_type)
        and type(snapshot.gap_count) is int
        and snapshot.gap_count >= 0
        and type(snapshot.unhealthy) is bool
        and type(snapshot.freshness) is str
        and snapshot.freshness
        in {
            "UNKNOWN",
            "DEGRADED",
            "HEALTHY",
            "STALE",
            "DISCONNECTED",
            "HALTED",
            "UNENTITLED",
        }
        and _valid_optional_ns(snapshot.last_provider_time_ns)
        and _valid_optional_ns(snapshot.last_received_time_ns)
    )


def _venue_row(snapshot: SourceHealthSnapshot) -> dict[str, object]:
    return {
        "venue": snapshot.venue,
        "type": snapshot.channel,
        "freshness": snapshot.freshness,
        "unhealthy": snapshot.unhealthy,
        "gap_count": snapshot.gap_count,
        "last_event_time_ns": snapshot.last_provider_time_ns,
        "last_ingest_time_ns": snapshot.last_received_time_ns,
    }


def _gap_state(snapshot: SourceHealthSnapshot | None) -> str:
    if snapshot is None:
        return "UNKNOWN"
    if type(snapshot) is not SourceHealthSnapshot or type(snapshot.gap_count) is not int:
        raise ValueError("INVALID_HEALTH")
    return "DETECTED" if snapshot.gap_count > 0 else "NONE"


def _event_row(event: NormalizedMarketEventV1) -> dict[str, object]:
    if (
        type(event) is not NormalizedMarketEventV1
        or type(event.event_id) is not UUID
        or type(event.event_type) is not str
        or event.event_type
        not in {
            "trade",
            "quote",
            "book_delta",
            "book_snapshot",
            "bar",
            "status",
            "reference",
            "corporate_action",
            "news",
        }
        or not all(
            type(value) is int and 0 < value <= _INT64_MAX
            for value in (
                event.event_time_ns,
                event.ingest_time_ns,
            )
        )
        or not _valid_optional_ns(event.source_time_ns)
    ):
        raise ValueError("INVALID_EVENT")
    return {
        "event_id": str(event.event_id),
        "event_type": event.event_type,
        "event_time_ns": event.event_time_ns,
        "source_time_ns": event.source_time_ns,
        "ingest_time_ns": event.ingest_time_ns,
    }


def _job_status_body(job_id: str, status: BackfillJobStatusV1) -> dict[str, object]:
    if type(status) is not BackfillJobStatusV1 or not _safe_identifier(job_id):
        raise ValueError("INVALID_JOB_STATUS")
    # Re-run frozen-record invariants in case a port forged its instance.
    status.__post_init__()
    return {
        "schema_version": _SCHEMA_VERSION,
        "job_id": job_id,
        "status": status.status,
        "completed_count": status.completed_count,
        "remaining_count": status.remaining_count,
        "source_state": status.source_state,
        "gap_state": status.gap_state,
        "last_event_time_ns": status.last_event_time_ns,
        "last_ingest_time_ns": status.last_ingest_time_ns,
    }


def _json_object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("DUPLICATE_KEY")
        result[key] = value
    return result


async def _backfill_body(request: Request) -> BackfillRequestV1 | None:
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != "application/json":
        return None
    content_length = request.headers.get("content-length")
    if content_length is not None and (
        not content_length.isascii()
        or not content_length.isdigit()
        or int(content_length) > _MAX_BODY_BYTES
    ):
        return None
    chunks: list[bytes] = []
    size = 0
    try:
        async for chunk in request.stream():
            size += len(chunk)
            if size > _MAX_BODY_BYTES:
                return None
            chunks.append(chunk)
        decoded = json.loads(b"".join(chunks), object_pairs_hook=_json_object_pairs)
        if type(decoded) is not dict:
            return None
        # JSON arrays are converted only for the two tuple-typed request fields;
        # Pydantic strict mode then validates all values without coercion.
        for field in ("instruments", "types"):
            value = decoded.get(field)
            if type(value) is list and all(type(item) is str for item in value):
                decoded[field] = tuple(value)
        return BackfillRequestV1.model_validate(decoded, strict=True)
    except Exception:
        return None


async def _chart_ticket_body(request: Request) -> ChartStreamTicketRequestV1 | None:
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != "application/json":
        return None
    content_length = request.headers.get("content-length")
    if content_length is not None and (
        not content_length.isascii() or not content_length.isdigit() or int(content_length) > 2048
    ):
        return None
    chunks: list[bytes] = []
    size = 0
    try:
        async for chunk in request.stream():
            size += len(chunk)
            if size > 2048:
                return None
            chunks.append(chunk)
        decoded = json.loads(b"".join(chunks), object_pairs_hook=_json_object_pairs)
        if type(decoded) is not dict:
            return None
        return ChartStreamTicketRequestV1.model_validate(decoded, strict=True)
    except Exception:
        return None


def create_paper_market_data_router(
    *,
    enabled: bool = False,
    venue_port: VenueStatusReadPortV1 | None = None,
    latest_port: LatestMarketDataReadPortV1 | None = None,
    backfill_port: BackfillJobPortV1 | None = None,
    chart_stream_port: ChartStreamReadPortV1 | None = None,
    chart_principal_resolver: Callable[[HTTPConnection], TrustedPrincipalV1 | None] | None = None,
) -> APIRouter:
    """Build an unmounted, disabled-by-default paper market-data router."""

    if type(enabled) is not bool:
        raise MarketDataPaperRouteError()
    if venue_port is not None and not callable(getattr(venue_port, "read_venue_health", None)):
        raise MarketDataPaperRouteError()
    if latest_port is not None and not callable(getattr(latest_port, "read_latest", None)):
        raise MarketDataPaperRouteError()
    if backfill_port is not None and (
        not callable(getattr(backfill_port, "preview_backfill", None))
        or not callable(getattr(backfill_port, "enqueue_backfill", None))
        or not callable(getattr(backfill_port, "read_backfill_job", None))
    ):
        raise MarketDataPaperRouteError()
    if chart_stream_port is not None and not callable(
        getattr(chart_stream_port, "open_chart_stream", None)
    ):
        raise MarketDataPaperRouteError()

    router = APIRouter(tags=["paper-market-data-v1"], route_class=_NoStoreRoute)

    @router.post("/md/chart/ticket")
    async def issue_chart_ticket(request: Request) -> JSONResponse:
        if not enabled or chart_stream_port is None or chart_principal_resolver is None:
            return _error(503, "SERVICE_UNAVAILABLE")
        if request.scope.get("query_string", b""):
            return _error(400, "INVALID_REQUEST")
        body = await _chart_ticket_body(request)
        if body is None:
            return _error(400, "INVALID_REQUEST")
        raw_origins = [value for key, value in request.scope.get("headers", ()) if key == b"origin"]
        if len(raw_origins) != 1:
            return _error(401, "UNAUTHORIZED")
        try:
            origin = raw_origins[0].decode("ascii")
            connection = HTTPConnection(request.scope)
            principal = chart_principal_resolver(connection)
            trusted_principal = getattr(request.state, "trusted_principal", None)
            profile = require_local_operator_profile(
                getattr(request.state, "trusted_operator_profile", None)
            )
            expected_origin = getattr(request.state, "trusted_operator_origin", None)
            store = getattr(request.app.state, "chart_stream_ticket_store", None)
            if (
                type(principal) is not TrustedPrincipalV1
                or type(trusted_principal) is not TrustedPrincipalV1
                or principal_binding(principal) != principal_binding(trusted_principal)
                or type(profile) is not LocalOperatorProfileV1
                or type(expected_origin) is not str
                or origin != expected_origin
                or type(store) is not ChartStreamTicketStore
            ):
                return _error(401, "UNAUTHORIZED")
            scope = ChartStreamScopeV1(body.venue, body.instrument, body.type)
            ticket = store.issue(
                principal=principal,
                profile=profile,
                origin=origin,
                stream_scope=scope,
            )
        except (ChartStreamTicketError, UnicodeDecodeError, ValueError):
            return _error(503, "SERVICE_UNAVAILABLE")
        return _ok(201, {"schema_version": 1, "ticket": ticket})

    @router.websocket("/md/chart")
    async def chart_stream(websocket: WebSocket) -> None:
        if not enabled or chart_stream_port is None or chart_principal_resolver is None:
            await websocket.close(code=1013)
            return
        client = websocket.client
        if client is None:
            await websocket.close(code=4403)
            return
        try:
            if not ipaddress.ip_address(client.host).is_loopback:
                await websocket.close(code=4403)
                return
        except ValueError:
            await websocket.close(code=4403)
            return
        try:
            connection = HTTPConnection(websocket.scope)
            principal = chart_principal_resolver(connection)
        except Exception:
            principal = None
        if type(principal) is not TrustedPrincipalV1:
            await websocket.close(code=4401)
            return
        query = dict(websocket.query_params)
        if set(query) != {"venue", "instrument", "type"}:
            await websocket.close(code=4400)
            return
        venue, instrument, data_type = query["venue"], query["instrument"], query["type"]
        if (
            _VENUE.fullmatch(venue) is None
            or not _safe_identifier(instrument)
            or data_type not in _DATA_TYPES
        ):
            await websocket.close(code=4400)
            return
        try:
            stream = chart_stream_port.open_chart_stream(
                principal=principal,
                venue=venue,
                instrument=instrument,
                data_type=data_type,
            )
            if not hasattr(stream, "__aiter__"):
                await websocket.close(code=1013)
                return
        except Exception:
            await websocket.close(code=1013)
            return
        if websocket.scope.get("state", {}).get("chart_ticket_authenticated") is True:
            await websocket.accept(
                subprotocol="leviathan.chart.v1",
                headers=[(b"cache-control", b"no-store")],
            )
        else:
            await websocket.accept(headers=[(b"cache-control", b"no-store")])
        try:
            async for envelope in stream:
                await websocket.send_json(envelope)
        except WebSocketDisconnect:
            return
        except Exception:
            # No provider or cache exception text crosses the websocket boundary.
            with suppress(Exception):
                await websocket.send_json(
                    {"schema_version": 1, "state": "DISCONNECTED", "code": "STREAM_UNAVAILABLE"}
                )
            await websocket.close(code=1011)

    @router.get("/ingest/venues")
    def read_venues(request: Request) -> JSONResponse:
        if not enabled or venue_port is None:
            return _error(503, "SERVICE_UNAVAILABLE")
        query = _query(request, frozenset({"venue", "limit"}))
        if query is None:
            return _error(400, "INVALID_REQUEST")
        venue = query.get("venue")
        if venue is not None and _VENUE.fullmatch(venue) is None:
            return _error(400, "INVALID_REQUEST")
        limit = _query_limit(query.get("limit"), default=50, maximum=_MAX_VENUE_ROWS)
        if limit is None:
            return _error(400, "INVALID_REQUEST")
        try:
            snapshots = venue_port.read_venue_health(venue=venue, limit=limit)
            if snapshots is None:
                return _ok(
                    200,
                    {
                        "schema_version": _SCHEMA_VERSION,
                        "source_state": "ABSENT",
                        "venues": [],
                    },
                )
            if type(snapshots) is not tuple or len(snapshots) > limit:
                return _error(503, "MARKET_DATA_UNAVAILABLE")
            if any(
                not _health_matches(item, venue=item.venue)
                or (venue is not None and item.venue != venue)
                for item in snapshots
            ):
                return _error(503, "MARKET_DATA_UNAVAILABLE")
            ordered = sorted(
                snapshots,
                key=lambda item: (
                    item.venue,
                    item.channel,
                    item.last_provider_time_ns or 0,
                    item.last_received_time_ns or 0,
                ),
            )
            rows = [_venue_row(item) for item in ordered]
        except Exception:
            return _error(503, "MARKET_DATA_UNAVAILABLE")
        return _ok(
            200,
            {
                "schema_version": _SCHEMA_VERSION,
                "source_state": "AVAILABLE",
                "venues": rows,
            },
        )

    @router.get("/md/latest")
    def read_latest(request: Request) -> JSONResponse:
        if not enabled or latest_port is None:
            return _error(503, "SERVICE_UNAVAILABLE")
        query = _query(request, frozenset({"venue", "instrument", "type"}))
        if query is None or set(query) != {"venue", "instrument", "type"}:
            return _error(400, "INVALID_REQUEST")
        venue = query["venue"]
        instrument = query["instrument"]
        data_type = query["type"]
        if (
            _VENUE.fullmatch(venue) is None
            or not _safe_identifier(instrument)
            or data_type not in _DATA_TYPES
        ):
            return _error(400, "INVALID_REQUEST")
        try:
            snapshot = latest_port.read_latest(
                venue=venue, instrument=instrument, data_type=data_type
            )
            if snapshot is None:
                return _ok(
                    200,
                    {
                        "schema_version": _SCHEMA_VERSION,
                        "source_state": "ABSENT",
                        "gap_state": "UNKNOWN",
                        "event": None,
                    },
                )
            if type(snapshot) is not tuple or len(snapshot) != 2:
                return _error(503, "MARKET_DATA_UNAVAILABLE")
            event, health = snapshot
            if event is not None and (
                type(event) is not NormalizedMarketEventV1
                or event.venue != venue
                or event.instrument_id != instrument
                or event.channel != data_type
            ):
                return _error(503, "MARKET_DATA_UNAVAILABLE")
            if health is not None and not _health_matches(
                health, venue=venue, instrument=instrument, data_type=data_type
            ):
                return _error(503, "MARKET_DATA_UNAVAILABLE")
            event_body = _event_row(event) if event is not None else None
            gap_state = _gap_state(health)
        except Exception:
            return _error(503, "MARKET_DATA_UNAVAILABLE")
        return _ok(
            200,
            {
                "schema_version": _SCHEMA_VERSION,
                "source_state": "AVAILABLE" if event_body is not None else "ABSENT",
                "gap_state": gap_state,
                "event": event_body,
            },
        )

    @router.post("/ingest/backfill")
    async def create_backfill(request: Request) -> JSONResponse:
        if not enabled or backfill_port is None:
            return _error(503, "SERVICE_UNAVAILABLE")
        if request.scope.get("query_string", b""):
            return _error(400, "INVALID_REQUEST")
        body = await _backfill_body(request)
        if body is None:
            return _error(400, "INVALID_REQUEST")
        if body.dry_run:
            try:
                preview = await asyncio.to_thread(backfill_port.preview_backfill, body)
                if type(preview) is not BackfillPreviewV1:
                    return _error(503, "BACKFILL_UNAVAILABLE")
                preview.__post_init__()
            except Exception:
                return _error(503, "BACKFILL_UNAVAILABLE")
            return _ok(
                200,
                {
                    "schema_version": _SCHEMA_VERSION,
                    "status": "PREVIEW",
                    "instrument_count": len(body.instruments),
                    "type_count": len(body.types),
                    "max_records": body.max_records,
                    "estimated_event_count": preview.estimated_event_count,
                    "writes_performed": False,
                },
            )
        try:
            job_id = backfill_port.enqueue_backfill(body)
            if inspect.isawaitable(job_id):
                job_id = await job_id
            if type(job_id) is not str or not _safe_identifier(job_id):
                return _error(503, "BACKFILL_UNAVAILABLE")
        except Exception:
            return _error(503, "BACKFILL_UNAVAILABLE")
        return _ok(
            202,
            {
                "schema_version": _SCHEMA_VERSION,
                "job_id": job_id,
                "status": "QUEUED",
            },
        )

    @router.get("/ingest/backfill/{job_id}")
    def read_backfill_status(job_id: str, request: Request) -> JSONResponse:
        if not enabled or backfill_port is None:
            return _error(503, "SERVICE_UNAVAILABLE")
        if request.scope.get("query_string", b"") or not _safe_identifier(job_id):
            return _error(400, "INVALID_REQUEST")
        try:
            status = backfill_port.read_backfill_job(job_id)
            if status is None:
                return _error(404, "BACKFILL_NOT_FOUND")
            body = _job_status_body(job_id, status)
        except Exception:
            return _error(503, "BACKFILL_UNAVAILABLE")
        return _ok(200, body)

    return router


__all__ = [
    "BackfillJobPortV1",
    "BackfillJobStatusV1",
    "BackfillPreviewV1",
    "BackfillRequestV1",
    "LatestMarketDataReadPortV1",
    "MarketDataPaperRouteError",
    "VenueStatusReadPortV1",
    "create_paper_market_data_router",
]
