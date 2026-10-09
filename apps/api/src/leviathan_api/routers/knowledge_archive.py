"""Read-only archived knowledge API over injected repository and telemetry ports."""

from __future__ import annotations

import inspect
import threading
from collections.abc import Callable, Mapping, MutableMapping
from datetime import UTC, datetime
from typing import Any, Protocol, cast

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response
from fastapi.routing import APIRoute
from pydantic import ValidationError
from starlette.routing import Match

from leviathan_core.knowledge_sync.archive_models import (
    ArchivedQueryV1,
    ArchivedReadDecisionV1,
    ArchivedRecordV1,
    ArchivedWriteDenialV1,
    ArchivePolicyError,
)
from leviathan_core.knowledge_sync.archive_policy import (
    deny_archived_write,
    parse_archived_query,
    read_archived_detail,
    read_archived_list,
)
from leviathan_core.seal import Issuer, SealedModel, SealError
from leviathan_core.security.authz_models import (
    AuthorizationModelError,
    TrustedPrincipalV1,
    require_trusted_principal,
)

router = APIRouter(prefix="/v1/knowledge/ingestions", tags=["archived-knowledge"])
_ISSUER = Issuer("know_legacy002.route.v1")
_FILTER_NAMES = frozenset(
    {"cursor", "limit", "source_type", "created_after", "created_before", "tag"}
)
_QUERY_ERROR_CODES = frozenset(
    {
        "INVALID_QUERY",
        "INVALID_CURSOR",
        "INVALID_LIMIT",
        "INVALID_TAG",
        "INVALID_TIME",
        "INVALID_TIME_RANGE",
    }
)
_METHOD_LABELS = frozenset(
    {
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "HEAD",
        "OPTIONS",
        "TRACE",
        "CONNECT",
        "COPY",
        "LINK",
        "UNLINK",
        "PURGE",
        "LOCK",
        "UNLOCK",
        "PROPFIND",
        "PROPPATCH",
        "MKCOL",
        "MOVE",
        "REPORT",
        "VIEW",
        "OTHER",
    }
)
_MAX_NS = 253402300799999999999


class _AnyVerbAPIRoute(APIRoute):
    """Match methods FastAPI does not enumerate so writes still receive 410."""

    def matches(self, scope: MutableMapping[str, Any]) -> tuple[Match, MutableMapping[str, Any]]:
        match, child_scope = super().matches(scope)
        if (
            match is Match.PARTIAL
            and scope.get("type") == "http"
            and self.path_regex.match(scope.get("path", "")) is not None
        ):
            return Match.FULL, child_scope
        return match, child_scope

    async def handle(
        self,
        scope: MutableMapping[str, Any],
        receive: Callable[..., Any],
        send: Callable[..., Any],
    ) -> None:
        if scope.get("method") not in (self.methods or set()):
            routed_scope = dict(scope)
            routed_scope["archive_original_method"] = scope.get("method", "")
            routed_scope["method"] = "GET"
            await super().handle(routed_scope, receive, send)
            return
        await super().handle(scope, receive, send)


def _raw_method(request: Request) -> str:
    original = request.scope.get("archive_original_method")
    value = original if type(original) is str and original else request.method
    return value.upper()


def _method_label(request: Request) -> str:
    method = _raw_method(request)
    return method if method in _METHOD_LABELS else "OTHER"


class ArchiveRouteError(ValueError):
    """Content-free route configuration or port failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class ArchiveAuditEventV1(SealedModel):
    schema_version: str
    actor_id: str
    method: str
    endpoint: str
    filters: tuple[str, ...]
    result_count: int
    status_code: int
    occurred_at_ns: int


class ArchiveThresholdAlertV1(SealedModel):
    schema_version: str
    day_utc: str
    observed_calls: int
    daily_threshold: int


class ArchiveRepositoryPort(Protocol):
    """Read-only, org-scoped snapshots; implementations must use a read-only role."""

    def list_archived_records(self, org_id: str) -> tuple[ArchivedRecordV1, ...]: ...

    def get_archived_record(self, org_id: str, ingestion_id: str) -> ArchivedRecordV1 | None: ...

    def list_archived_runs(
        self, org_id: str, ingestion_id: str
    ) -> tuple[ArchivedRecordV1, ...]: ...


class ArchiveAuditPort(Protocol):
    def record(self, event: ArchiveAuditEventV1) -> None: ...


class ArchiveMetricsPort(Protocol):
    def increment(self, name: str, *, labels: Mapping[str, str]) -> None: ...


class ArchiveAlertPort(Protocol):
    def emit(self, alert: ArchiveThresholdAlertV1) -> None: ...


class KnowledgeArchiveRuntime:
    """Explicit injected ports and UTC policy settings for the archived router."""

    def __init__(
        self,
        *,
        repository: ArchiveRepositoryPort,
        audit: ArchiveAuditPort,
        metrics: ArchiveMetricsPort,
        alerts: ArchiveAlertPort,
        clock: Callable[[], datetime],
        sunset_at_ns: int,
        daily_threshold: int,
    ) -> None:
        if (
            not callable(getattr(repository, "list_archived_records", None))
            or not callable(getattr(repository, "get_archived_record", None))
            or not callable(getattr(repository, "list_archived_runs", None))
            or not callable(getattr(audit, "record", None))
            or not callable(getattr(metrics, "increment", None))
            or not callable(getattr(alerts, "emit", None))
            or not callable(clock)
            or type(sunset_at_ns) is not int
            or not 0 <= sunset_at_ns <= _MAX_NS
            or type(daily_threshold) is not int
            or daily_threshold < 1
        ):
            raise ArchiveRouteError("INVALID_CONFIGURATION")
        self.repository = repository
        self.audit = audit
        self.metrics = metrics
        self.alerts = alerts
        self.clock = clock
        self.sunset_at_ns = sunset_at_ns
        self.daily_threshold = daily_threshold
        self._usage_lock = threading.Lock()
        self._usage_day: str | None = None
        self._usage_count = 0
        self._alerted_days: set[str] = set()

    def now_ns(self) -> tuple[datetime, int]:
        try:
            value = self.clock()
        except Exception:
            raise ArchiveRouteError("INVALID_CLOCK") from None
        if type(value) is not datetime or value.tzinfo is not UTC:
            raise ArchiveRouteError("INVALID_CLOCK")
        delta = value - datetime(1970, 1, 1, tzinfo=UTC)
        ns = ((delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds) * 1000
        if not 0 <= ns <= _MAX_NS:
            raise ArchiveRouteError("INVALID_CLOCK")
        return value, ns

    def observe(self, event: ArchiveAuditEventV1) -> None:
        self.audit.record(event)
        self.metrics.increment(
            "archived_knowledge.calls_total",
            labels={"method": event.method, "status": str(event.status_code)},
        )
        moment, _ = self.now_ns()
        day = moment.date().isoformat()
        alert_now = False
        count = 0
        with self._usage_lock:
            if self._usage_day != day:
                self._usage_day = day
                self._usage_count = 0
            self._usage_count += 1
            count = self._usage_count
            if count >= self.daily_threshold and day not in self._alerted_days:
                self._alerted_days.add(day)
                alert_now = True
        if alert_now:
            self.alerts.emit(
                _ISSUER.issue(
                    ArchiveThresholdAlertV1(
                        schema_version="1",
                        day_utc=day,
                        observed_calls=count,
                        daily_threshold=self.daily_threshold,
                    )
                )
            )


async def _maybe_await(value: object) -> object:
    if inspect.isawaitable(value):
        return await cast(Any, value)
    return value


def _runtime(request: Request) -> KnowledgeArchiveRuntime:
    value = getattr(request.app.state, "knowledge_archive", None)
    if type(value) is not KnowledgeArchiveRuntime:
        raise ArchiveRouteError("RUNTIME_UNAVAILABLE")
    return value


def _principal(request: Request) -> object:
    return getattr(request.state, "trusted_principal", None)


def _trusted(principal: object) -> TrustedPrincipalV1 | None:
    """The issued, unmodified principal, or None: forged ones look like a missing one."""
    try:
        return require_trusted_principal(principal)
    except AuthorizationModelError:
        return None


def _actor_id(principal: object) -> str:
    trusted = _trusted(principal)
    return "anonymous" if trusted is None else trusted.principal_id


def _principal_org(principal: object) -> str | None:
    trusted = _trusted(principal)
    if trusted is None:
        return None
    try:
        org_id = trusted.project_id
    except Exception:
        return None
    return org_id if type(org_id) is str else None


def _query_params(request: Request) -> dict[str, str]:
    params: dict[str, str] = {}
    for key, value in request.query_params.multi_items():
        if key in params:
            raise ArchivePolicyError("INVALID_QUERY")
        params[key] = value
    return params


def _query_error_code(error: ArchivePolicyError) -> str:
    code = error.code
    return code if code in _QUERY_ERROR_CODES else "INVALID_QUERY"


def _query_validation_error_code(params: Mapping[str, str]) -> str:
    """Map a sealed query validation failure to a fixed field error code."""
    if "limit" in params:
        return "INVALID_LIMIT"
    if "cursor" in params:
        return "INVALID_CURSOR"
    if "tag" in params:
        return "INVALID_TAG"
    if "created_after" in params or "created_before" in params:
        return "INVALID_TIME"
    return "INVALID_QUERY"


def _response_from_decision(
    decision: ArchivedReadDecisionV1 | ArchivedWriteDenialV1,
) -> Response:
    headers = dict(decision.headers)
    if isinstance(decision, ArchivedReadDecisionV1):
        if decision.etag is not None:
            headers["ETag"] = decision.etag
        if decision.next_cursor is not None:
            headers["X-Next-Cursor"] = decision.next_cursor
        if decision.status_code == 304:
            return Response(status_code=304, headers=headers)
        return Response(
            content=decision.body_json or "{}",
            status_code=decision.status_code,
            headers=headers,
            media_type="application/json",
        )
    return Response(
        content=decision.body_json,
        status_code=decision.status_code,
        headers=headers,
        media_type="application/json",
    )


async def _finish(
    request: Request,
    runtime: KnowledgeArchiveRuntime,
    *,
    decision: ArchivedReadDecisionV1 | ArchivedWriteDenialV1,
    endpoint: str,
    filter_names: tuple[str, ...] = (),
) -> Response:
    status = decision.status_code
    count = decision.record_count if isinstance(decision, ArchivedReadDecisionV1) else 0
    try:
        _, now_ns = runtime.now_ns()
        actor = _principal(request)
        actor_id = _actor_id(actor)
        if type(actor_id) is not str or not actor_id.isascii():
            actor_id = "unavailable"
        runtime.observe(
            _ISSUER.issue(
                ArchiveAuditEventV1(
                    schema_version="1",
                    actor_id=actor_id,
                    method=_method_label(request),
                    endpoint=endpoint,
                    filters=tuple(sorted(filter_names)),
                    result_count=count,
                    status_code=status,
                    occurred_at_ns=now_ns,
                )
            )
        )
    except Exception:
        return JSONResponse(
            {"error": {"code": "ARCHIVE_OBSERVABILITY_UNAVAILABLE"}}, status_code=503
        )
    return _response_from_decision(decision)


async def _finish_error(
    request: Request, runtime: KnowledgeArchiveRuntime, endpoint: str
) -> Response:
    try:
        _, now_ns = runtime.now_ns()
        actor = _principal(request)
        actor_id = _actor_id(actor)
        if type(actor_id) is not str or not actor_id.isascii():
            actor_id = "unavailable"
        runtime.observe(
            _ISSUER.issue(
                ArchiveAuditEventV1(
                    schema_version="1",
                    actor_id=actor_id,
                    method=_method_label(request),
                    endpoint=endpoint,
                    filters=(),
                    result_count=0,
                    status_code=503,
                    occurred_at_ns=now_ns,
                )
            )
        )
    except Exception:
        pass
    return JSONResponse({"error": {"code": "ARCHIVE_READ_FAILED"}}, status_code=503)


async def _finish_client_error(
    request: Request,
    runtime: KnowledgeArchiveRuntime,
    *,
    code: str,
    endpoint: str,
    filter_names: tuple[str, ...] = (),
) -> Response:
    try:
        now_ns, sunset = _policy_time(runtime)
        principal = _principal(request)
        org_id = _principal_org(principal) or "invalid"
        headers = dict(
            read_archived_detail(
                principal,
                org_id,
                None,
                now_ns=now_ns,
                sunset_at_ns=sunset,
            ).headers
        )
        _, audit_ns = runtime.now_ns()
        actor_id = _actor_id(principal)
        if type(actor_id) is not str or not actor_id.isascii():
            actor_id = "unavailable"
        runtime.observe(
            _ISSUER.issue(
                ArchiveAuditEventV1(
                    schema_version="1",
                    actor_id=actor_id,
                    method=_method_label(request),
                    endpoint=endpoint,
                    filters=tuple(sorted(filter_names)),
                    result_count=0,
                    status_code=400,
                    occurred_at_ns=audit_ns,
                )
            )
        )
    except Exception:
        return JSONResponse(
            {"error": {"code": "ARCHIVE_OBSERVABILITY_UNAVAILABLE"}}, status_code=503
        )
    return JSONResponse({"error": {"code": code}}, status_code=400, headers=headers)


def _policy_time(runtime: KnowledgeArchiveRuntime) -> tuple[int, int]:
    _, now_ns = runtime.now_ns()
    return now_ns, runtime.sunset_at_ns


async def _repository_call(call: Callable[..., object], *args: object) -> object:
    try:
        return await _maybe_await(call(*args))
    except Exception:
        raise ArchiveRouteError("ARCHIVE_READ_FAILED") from None


def _error_decision(
    principal: object, org_id: str, runtime: KnowledgeArchiveRuntime, etag: str | None = None
) -> ArchivedReadDecisionV1:
    now_ns, sunset = _policy_time(runtime)
    return read_archived_list(
        principal,
        org_id,
        (),
        ArchivedQueryV1(schema_version="1"),
        now_ns=now_ns,
        sunset_at_ns=sunset,
        if_none_match=etag,
    )


async def _fail_closed(request: Request, code: str, endpoint: str) -> Response:
    try:
        runtime = _runtime(request)
        response = await _finish_error(request, runtime, endpoint)
        return JSONResponse({"error": {"code": code}}, status_code=response.status_code)
    except Exception:
        return JSONResponse({"error": {"code": code}}, status_code=503)


@router.get("")
async def archived_ingestions(request: Request) -> Response:
    try:
        runtime = _runtime(request)
        principal = _principal(request)
        org_id = _principal_org(principal) or "invalid"
        now_ns, sunset = _policy_time(runtime)
        etag = request.headers.get("if-none-match")
        # Run authorization against an empty snapshot before repository access.
        auth = read_archived_list(
            principal,
            org_id,
            (),
            ArchivedQueryV1(schema_version="1"),
            now_ns=now_ns,
            sunset_at_ns=sunset,
            if_none_match=None,
        )
        if auth.status_code != 200:
            return await _finish(
                request,
                runtime,
                decision=auth,
                endpoint="GET /v1/knowledge/ingestions",
            )
        params: dict[str, str] = {}
        try:
            params = _query_params(request)
            query = parse_archived_query(params)
        except ArchivePolicyError as exc:
            return await _finish_client_error(
                request,
                runtime,
                code=_query_error_code(exc),
                endpoint="GET /v1/knowledge/ingestions",
                filter_names=tuple(key for key in params if key in _FILTER_NAMES),
            )
        except (ValidationError, SealError):
            return await _finish_client_error(
                request,
                runtime,
                code=_query_validation_error_code(params),
                endpoint="GET /v1/knowledge/ingestions",
                filter_names=tuple(key for key in params if key in _FILTER_NAMES),
            )
        records_obj = await _repository_call(runtime.repository.list_archived_records, org_id)
        if type(records_obj) is not tuple:
            raise ArchiveRouteError("ARCHIVE_READ_FAILED")
        decision = read_archived_list(
            principal,
            org_id,
            cast(tuple[ArchivedRecordV1, ...], records_obj),
            query,
            now_ns=now_ns,
            sunset_at_ns=sunset,
            if_none_match=etag,
        )
        return await _finish(
            request,
            runtime,
            decision=decision,
            endpoint="GET /v1/knowledge/ingestions",
            filter_names=tuple(key for key in params if key in _FILTER_NAMES),
        )
    except ArchivePolicyError:
        return await _fail_closed(request, "ARCHIVE_READ_FAILED", "GET /v1/knowledge/ingestions")
    except Exception:
        return await _fail_closed(request, "ARCHIVE_READ_FAILED", "GET /v1/knowledge/ingestions")


@router.get("/{ingestion_id}/runs")
async def archived_ingestion_runs(ingestion_id: str, request: Request) -> Response:
    endpoint = "GET /v1/knowledge/ingestions/{ingestion_id}/runs"
    try:
        runtime = _runtime(request)
        principal = _principal(request)
        org_id = _principal_org(principal) or "invalid"
        now_ns, sunset = _policy_time(runtime)
        etag = request.headers.get("if-none-match")
        auth = read_archived_list(
            principal,
            org_id,
            (),
            ArchivedQueryV1(schema_version="1"),
            now_ns=now_ns,
            sunset_at_ns=sunset,
            if_none_match=None,
        )
        if auth.status_code != 200:
            return await _finish(request, runtime, decision=auth, endpoint=endpoint)
        params: dict[str, str] = {}
        try:
            params = _query_params(request)
            query = parse_archived_query(params)
        except ArchivePolicyError as exc:
            return await _finish_client_error(
                request,
                runtime,
                code=_query_error_code(exc),
                endpoint=endpoint,
                filter_names=tuple(key for key in params if key in _FILTER_NAMES),
            )
        except (ValidationError, SealError):
            return await _finish_client_error(
                request,
                runtime,
                code=_query_validation_error_code(params),
                endpoint=endpoint,
                filter_names=tuple(key for key in params if key in _FILTER_NAMES),
            )
        parent = await _repository_call(
            runtime.repository.get_archived_record, org_id, ingestion_id
        )
        if parent is None:
            return await _finish(
                request,
                runtime,
                decision=read_archived_detail(
                    principal,
                    org_id,
                    None,
                    now_ns=now_ns,
                    sunset_at_ns=sunset,
                    if_none_match=etag,
                ),
                endpoint=endpoint,
            )
        if type(parent) is not ArchivedRecordV1:
            raise ArchiveRouteError("ARCHIVE_READ_FAILED")
        parent_visibility = read_archived_detail(
            principal,
            org_id,
            parent,
            now_ns=now_ns,
            sunset_at_ns=sunset,
            if_none_match=None,
        )
        if parent_visibility.status_code != 200:
            return await _finish(request, runtime, decision=parent_visibility, endpoint=endpoint)
        runs_obj = await _repository_call(
            runtime.repository.list_archived_runs, org_id, ingestion_id
        )
        if type(runs_obj) is not tuple:
            raise ArchiveRouteError("ARCHIVE_READ_FAILED")
        decision = read_archived_list(
            principal,
            org_id,
            cast(tuple[ArchivedRecordV1, ...], runs_obj),
            query,
            now_ns=now_ns,
            sunset_at_ns=sunset,
            if_none_match=etag,
        )
        return await _finish(
            request,
            runtime,
            decision=decision,
            endpoint=endpoint,
            filter_names=tuple(key for key in params if key in _FILTER_NAMES),
        )
    except Exception:
        return await _fail_closed(request, "ARCHIVE_READ_FAILED", endpoint)


@router.get("/{ingestion_id}")
async def archived_ingestion_detail(ingestion_id: str, request: Request) -> Response:
    endpoint = "GET /v1/knowledge/ingestions/{ingestion_id}"
    try:
        runtime = _runtime(request)
        principal = _principal(request)
        org_id = _principal_org(principal) or "invalid"
        now_ns, sunset = _policy_time(runtime)
        etag = request.headers.get("if-none-match")
        auth = _error_decision(principal, org_id, runtime)
        if auth.status_code != 200:
            return await _finish(request, runtime, decision=auth, endpoint=endpoint)
        record = await _repository_call(
            runtime.repository.get_archived_record, org_id, ingestion_id
        )
        if record is not None and type(record) is not ArchivedRecordV1:
            raise ArchiveRouteError("ARCHIVE_READ_FAILED")
        decision = read_archived_detail(
            principal,
            org_id,
            record,
            now_ns=now_ns,
            sunset_at_ns=sunset,
            if_none_match=etag,
        )
        return await _finish(request, runtime, decision=decision, endpoint=endpoint)
    except Exception:
        return await _fail_closed(request, "ARCHIVE_READ_FAILED", endpoint)


async def archived_write_denial(request: Request, resource_path: str = "") -> Response:
    raw_method = _raw_method(request)
    method_label = _method_label(request)
    endpoint = f"{method_label} /v1/knowledge/ingestions/{{path}}"
    try:
        runtime = _runtime(request)
        if len(raw_method) > 64:
            return await _finish_client_error(
                request,
                runtime,
                code="INVALID_METHOD",
                endpoint=endpoint,
            )
        if raw_method == "GET":
            principal = _principal(request)
            org_id = _principal_org(principal) or "invalid"
            now_ns, sunset = _policy_time(runtime)
            decision = read_archived_detail(
                principal,
                org_id,
                None,
                now_ns=now_ns,
                sunset_at_ns=sunset,
                if_none_match=request.headers.get("if-none-match"),
            )
            return await _finish(request, runtime, decision=decision, endpoint=endpoint)
        now_ns, sunset = _policy_time(runtime)
        denial = deny_archived_write(
            raw_method if raw_method in _METHOD_LABELS else "OTHER",
            now_ns=now_ns,
            sunset_at_ns=sunset,
        )
        return await _finish(request, runtime, decision=denial, endpoint=endpoint)
    except Exception:
        return await _fail_closed(request, "LEGACY_ARCHIVED", endpoint)


router.add_api_route(
    "", archived_write_denial, methods=["GET"], route_class_override=_AnyVerbAPIRoute
)
router.add_api_route(
    "/{resource_path:path}",
    archived_write_denial,
    methods=["GET"],
    route_class_override=_AnyVerbAPIRoute,
)
