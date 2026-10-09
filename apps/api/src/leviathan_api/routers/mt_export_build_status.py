"""Read-only, content-safe MT export build status API."""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Protocol

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from starlette.routing import Match
from starlette.types import Message, Receive, Scope, Send

from leviathan_core.mt_export_bridge_build_view import (
    BuildEventV1,
    project_build_events,
)
from leviathan_core.security.authz_models import (
    AuthorizationModelError,
    TrustedPrincipalV1,
    require_trusted_principal,
)


class _NoStoreAPIRoute(APIRoute):
    """Apply no-store to every route response, including arbitrary methods."""

    def matches(self, scope: Scope) -> tuple[Match, Scope]:
        match, child_scope = super().matches(scope)
        if (
            match is Match.PARTIAL
            and scope.get("type") == "http"
            and self.path_regex.match(scope.get("path", "")) is not None
        ):
            return Match.FULL, child_scope
        return match, child_scope

    async def handle(self, scope: Scope, receive: Receive, send: Send) -> None:
        if self.methods is not None and scope.get("method") not in self.methods:
            response = JSONResponse(
                status_code=405,
                content={"detail": "Method Not Allowed"},
                headers={"Allow": ", ".join(sorted(self.methods)), "Cache-Control": "no-store"},
            )
            await response(scope, receive, send)
            return

        async def send_no_store(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = [
                    (name, value)
                    for name, value in message.get("headers", [])
                    if name.lower() != b"cache-control"
                ]
                headers.append((b"cache-control", b"no-store"))
                message = {**message, "headers": headers}
            await send(message)

        await super().handle(scope, receive, send_no_store)


router = APIRouter(
    prefix="/v1/mt-export",
    tags=["mt-export-build-status"],
    route_class=_NoStoreAPIRoute,
)

DEFAULT_EVENT_LIMIT = 50
MAX_EVENT_LIMIT = 100
UNAVAILABLE_CODE = "BUILD_STATUS_UNAVAILABLE"
_LIMIT_GRAMMAR = re.compile(r"[0-9]{1,3}\Z", re.ASCII)
_EXPORT_JOB_ID_GRAMMAR = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z", re.ASCII)


class BuildEventReadPort(Protocol):
    """Read-only, project-scoped source of typed build events."""

    def read_build_events(
        self, project_id: str, export_job_id: str, *, limit: int
    ) -> Iterable[BuildEventV1]: ...


def _trusted_principal(request: Request) -> TrustedPrincipalV1 | None:
    try:
        return require_trusted_principal(getattr(request.state, "trusted_principal", None))
    except AuthorizationModelError:
        return None


def _parse_limit(request: Request) -> int | None:
    values = request.query_params.getlist("limit")
    if not values:
        return DEFAULT_EVENT_LIMIT
    if len(values) != 1 or _LIMIT_GRAMMAR.fullmatch(values[0]) is None:
        return None
    limit = int(values[0])
    return limit if 1 <= limit <= MAX_EVENT_LIMIT else None


def _unavailable() -> JSONResponse:
    return JSONResponse(status_code=503, content={"detail": UNAVAILABLE_CODE})


@router.get("/builds/{export_job_id:path}")
def read_build_status(export_job_id: str, request: Request) -> JSONResponse:
    """Return a bounded projection for the authenticated principal's project."""

    principal = _trusted_principal(request)
    if principal is None:
        return JSONResponse(status_code=401, content={"detail": "PRINCIPAL_REQUIRED"})

    if _EXPORT_JOB_ID_GRAMMAR.fullmatch(export_job_id) is None:
        return JSONResponse(status_code=400, content={"detail": "INVALID_EXPORT_JOB_ID"})

    if any(key != "limit" for key, _ in request.query_params.multi_items()):
        return JSONResponse(status_code=422, content={"detail": "INVALID_QUERY"})

    limit = _parse_limit(request)
    if limit is None:
        return JSONResponse(status_code=422, content={"detail": "INVALID_LIMIT"})

    try:
        port = getattr(request.app.state, "build_event_read_port", None)
        read_events = getattr(port, "read_build_events", None)
        if not callable(read_events):
            return _unavailable()
        source_events = read_events(principal.project_id, export_job_id, limit=limit)
        if isinstance(source_events, (str, bytes, bytearray)):
            return _unavailable()
        iterator = iter(source_events)
        events: list[BuildEventV1] = []
        for _ in range(limit + 1):
            try:
                event = next(iterator)
            except StopIteration:
                break
            if len(events) == limit:
                return _unavailable()
            events.append(event)
        view = project_build_events(tuple(events))
    except Exception:
        return _unavailable()

    return JSONResponse(
        status_code=200,
        content={
            "export_job_id": export_job_id,
            "status": view.status.value,
            "logs": [entry.model_dump(mode="json") for entry in view.logs],
            "live_enabled": False,
        },
    )


__all__ = ["BuildEventReadPort", "router"]
