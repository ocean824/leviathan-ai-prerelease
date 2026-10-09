"""Authenticated per-user preferences API adapter.

The router is intentionally exported as a factory and is not mounted here.
The trusted application composition root owns principal resolution and mounting.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Protocol

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response
from fastapi.routing import APIRoute
from leviathan_store.preferences import (
    MAX_DOCUMENT_BYTES,
    MAX_RAW_REQUEST_BYTES,
    PreferencesError,
    UserPreferencesV1,
    validate_document,
)
from starlette.concurrency import run_in_threadpool
from starlette.types import Receive, Scope, Send

from leviathan_core.security.authz_models import (
    TrustedPrincipalV1,
    require_trusted_principal,
)

PrincipalResolver = Callable[[Request], TrustedPrincipalV1 | None]


class PreferencesHttpPort(Protocol):
    def get(self, user_scope: str, namespace: str) -> UserPreferencesV1 | None: ...

    def put(
        self,
        user_scope: str,
        namespace: str,
        document: dict[str, object],
        *,
        if_match: str,
    ) -> UserPreferencesV1: ...

    def delete(self, user_scope: str, namespace: str) -> None: ...


_STATUS = {
    "UNAUTHENTICATED": 401,
    "PREFERENCES_SCOPE_DENIED": 403,
    "PREFERENCE_NOT_FOUND": 404,
    "REVISION_CONFLICT": 409,
    "PRECONDITION_REQUIRED": 412,
    "DOCUMENT_TOO_LARGE": 413,
    "PREFERENCES_INVALID": 422,
    "PREFERENCES_UNAVAILABLE": 503,
}


def _record_body(record: UserPreferencesV1) -> dict[str, object]:
    return {
        "schema_version": record.schema_version,
        "user_scope": record.user_scope,
        "namespace": record.namespace,
        "document": record.document,
        # int64 nanoseconds exceed JavaScript's exact-number range. Keep the
        # HTTP representation canonical and lossless; storage remains integer.
        "updated_at_ns": str(record.updated_at_ns),
        "revision": record.revision,
    }


def _error(status: int, code: str, *, current: UserPreferencesV1 | None = None) -> JSONResponse:
    body: dict[str, object] = {"error": {"code": code}}
    if current is not None:
        body["current"] = _record_body(current)
    return JSONResponse(body, status_code=status, headers={"Cache-Control": "no-store"})


class _NoStoreRoute(APIRoute):
    """Add no-store to the framework 405 for an unmatched route method."""

    async def handle(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("method") not in (self.methods or set()):
            response = _error(405, "METHOD_NOT_ALLOWED")
            await response(scope, receive, send)
            return
        await super().handle(scope, receive, send)


def _safe_principal(request: Request, resolver: PrincipalResolver) -> TrustedPrincipalV1 | None:
    try:
        principal = resolver(request)
        return require_trusted_principal(principal)
    except Exception:
        return None


async def _read_json(request: Request) -> object:
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().casefold()
    if content_type != "application/json":
        raise PreferencesError("PREFERENCES_INVALID")
    content_length = request.headers.get("content-length")
    if content_length is not None:
        if not content_length.isascii() or not content_length.isdecimal():
            raise PreferencesError("PREFERENCES_INVALID")
        if int(content_length) > MAX_RAW_REQUEST_BYTES:
            raise PreferencesError("DOCUMENT_TOO_LARGE")
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > MAX_RAW_REQUEST_BYTES:
            raise PreferencesError("DOCUMENT_TOO_LARGE")
        chunks.append(chunk)
    try:
        parsed = json.loads(b"".join(chunks).decode("utf-8", errors="strict"))
    except (UnicodeError, json.JSONDecodeError):
        raise PreferencesError("PREFERENCES_INVALID") from None
    return parsed


def build_preferences_router(
    store: PreferencesHttpPort,
    principal_resolver: PrincipalResolver,
) -> APIRouter:
    """Build an unmounted preferences router.

    Mount from the trusted app composition root at ``/api/preferences``. The
    principal resolver must return a SEAL-issued trusted principal.
    """
    router = APIRouter(prefix="/api/preferences", tags=["preferences"], route_class=_NoStoreRoute)

    def _authorized(request: Request) -> tuple[str | None, JSONResponse | None]:
        principal = _safe_principal(request, principal_resolver)
        if principal is None:
            return None, _error(401, "UNAUTHENTICATED")
        if principal.project_id != "leviathan-ai" or "operator" not in principal.roles:
            return None, _error(403, "PREFERENCES_SCOPE_DENIED")
        return principal.principal_id, None

    @router.get("/{namespace}")
    async def get_preferences(namespace: str, request: Request) -> JSONResponse:
        scope, denial = _authorized(request)
        if denial is not None:
            return denial
        assert scope is not None
        try:
            record = await run_in_threadpool(store.get, scope, namespace)
        except PreferencesError as exc:
            return _error(_STATUS.get(exc.code, 503), exc.code)
        except Exception:
            return _error(503, "PREFERENCES_UNAVAILABLE")
        if record is None:
            return _error(404, "PREFERENCE_NOT_FOUND")
        return JSONResponse(_record_body(record), headers={"Cache-Control": "no-store"})

    @router.put("/{namespace}")
    async def put_preferences(namespace: str, request: Request) -> JSONResponse:
        scope, denial = _authorized(request)
        if denial is not None:
            return denial
        assert scope is not None
        if_match = request.headers.get("if-match")
        if if_match is None:
            return _error(412, "PRECONDITION_REQUIRED")
        if_match = if_match.strip().strip('"')
        try:
            body = await _read_json(request)
            if type(body) is not dict or set(body) != {"document"}:
                raise PreferencesError("PREFERENCES_INVALID")
            document = validate_document(body["document"])
            if (
                len(
                    json.dumps(
                        document, sort_keys=True, separators=(",", ":"), ensure_ascii=False
                    ).encode("utf-8")
                )
                > MAX_DOCUMENT_BYTES
            ):
                raise PreferencesError("DOCUMENT_TOO_LARGE")
            record = await run_in_threadpool(
                lambda: store.put(scope, namespace, document, if_match=if_match)
            )
        except PreferencesError as exc:
            return _error(
                _STATUS.get(exc.code, 422),
                exc.code,
                current=exc.current if isinstance(exc.current, UserPreferencesV1) else None,
            )
        except Exception:
            return _error(503, "PREFERENCES_UNAVAILABLE")
        return JSONResponse(_record_body(record), headers={"Cache-Control": "no-store"})

    @router.delete("/{namespace}")
    async def delete_preferences(namespace: str, request: Request) -> Response:
        scope, denial = _authorized(request)
        if denial is not None:
            return denial
        assert scope is not None
        try:
            await run_in_threadpool(store.delete, scope, namespace)
        except PreferencesError as exc:
            return _error(_STATUS.get(exc.code, 422), exc.code)
        except Exception:
            return _error(503, "PREFERENCES_UNAVAILABLE")
        return Response(status_code=204, headers={"Cache-Control": "no-store"})

    return router


__all__ = ["PreferencesHttpPort", "PrincipalResolver", "build_preferences_router"]
