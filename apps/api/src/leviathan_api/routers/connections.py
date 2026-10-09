"""Fake-first local connection API. This router is intentionally unmounted."""

from __future__ import annotations

import re
from typing import TypeVar
from urllib.parse import parse_qsl, urlsplit

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from leviathan_api.connections_runtime import (
    ConnectInitiateV1,
    ConnectionActionResultV1,
    ConnectionActionV1,
    ConnectionCatalogEntryV1,
    ConnectionCatalogV1,
    ConnectionsRuntimeV1,
    ConnectionStatusV1,
    CredentialConnectInitiateV1,
    EnvironmentV1,
    ProviderV1,
)
from leviathan_core.security.authz_models import (
    AuthorizationModelError,
    TrustedPrincipalV1,
    require_trusted_principal,
)

_PROVIDER_TEXT = re.compile(r"[a-z][a-z0-9_]{0,63}\Z", re.ASCII)
_BAD_REQUEST = "INVALID_PROVIDER"
_UNSUPPORTED_BODY = "UNSUPPORTED_BODY"
_UNSUPPORTED_QUERY = "UNSUPPORTED_QUERY"
_AUTH_REQUIRED = "PRINCIPAL_UNTRUSTED"
_FORBIDDEN = "CONNECTION_FORBIDDEN"
_NOT_FOUND = "PROVIDER_NOT_FOUND"
_UNAVAILABLE = "CONNECTIONS_UNAVAILABLE"
_ModelT = TypeVar("_ModelT", bound=BaseModel)
_ALLOWED_OAUTH_QUERY_KEYS = frozenset(
    {
        "client_id",
        "response_type",
        "redirect_uri",
        "state",
        "scope",
        "code_challenge",
        "code_challenge_method",
        "nonce",
        "audience",
        "resource",
        "prompt",
        "access_type",
        "include_granted_scopes",
        "response_mode",
    }
)


def _error(status: int, code: str) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"error": {"code": code}},
        headers={"Cache-Control": "no-store"},
    )


def _ok(payload: dict[str, object], *, status: int = 200) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content=payload,
        headers={"Cache-Control": "no-store"},
    )


def _trusted_scope(
    request: Request,
) -> tuple[TrustedPrincipalV1, EnvironmentV1] | JSONResponse:
    try:
        principal = require_trusted_principal(getattr(request.state, "trusted_principal", None))
    except AuthorizationModelError:
        return _error(401, _AUTH_REQUIRED)
    if not ({"operator", "admin"} & set(principal.roles)):
        return _error(403, _FORBIDDEN)
    try:
        environment = EnvironmentV1(principal.env.upper())
    except (AttributeError, ValueError):
        return _error(403, _FORBIDDEN)
    return principal, environment


def _no_request_body(request: Request) -> bool:
    """Reject bodies before parsing; credential values have no route into this API."""

    headers = request.headers
    content_length = headers.get("content-length")
    if content_length is not None and content_length != "0":
        return False
    return headers.get("transfer-encoding") is None


def _read_catalog(runtime: ConnectionsRuntimeV1, project_id: str) -> ConnectionCatalogV1 | None:
    port = runtime.catalog_port
    if port is None:
        return None
    try:
        result = port.get_catalog(project_id)
    except Exception:
        return None
    if type(result) is not ConnectionCatalogV1:
        return None
    if any(type(row) is not ConnectionCatalogEntryV1 for row in result.providers):
        return None
    return result


def _catalog_entry(
    catalog: ConnectionCatalogV1, provider: ProviderV1
) -> ConnectionCatalogEntryV1 | None:
    return next((row for row in catalog.providers if row.provider_id is provider), None)


def _provider(value: str) -> ProviderV1 | None:
    if type(value) is not str or _PROVIDER_TEXT.fullmatch(value) is None:
        return None
    try:
        return ProviderV1(value)
    except ValueError:
        return None


def _valid_oauth_expiry(expires_at_ns: str, clock_ns: object) -> bool:
    if not callable(clock_ns):
        return False
    try:
        now = clock_ns()
        expiry = int(expires_at_ns)
    except (TypeError, ValueError, OverflowError):
        return False
    return type(now) is int and now < expiry <= now + 600_000_000_000


def _authorization_host_matches(result: ConnectInitiateV1, runtime: ConnectionsRuntimeV1) -> bool:
    try:
        parsed = urlsplit(result.authorization_url)
        query = parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=32)
    except (ValueError, TypeError):
        return False
    if parsed.netloc != result.authorization_host:
        return False
    if not any(
        provider is result.provider_id and host == result.authorization_host
        for provider, host in runtime.oauth_host_allowlist
    ):
        return False
    if any(key not in _ALLOWED_OAUTH_QUERY_KEYS for key, _value in query):
        return False
    if len({key for key, _value in query}) != len(query):
        return False
    query_values = dict(query)
    return (
        query_values.get("state") == result.state
        and query_values.get("redirect_uri") == result.redirect_uri
    )


def _dto_payload(value: object, expected: type[_ModelT]) -> dict[str, object] | None:
    if not isinstance(value, BaseModel) or type(value) is not expected:
        return None
    try:
        dumped = value.model_dump(mode="json")
    except Exception:
        return None
    return dumped if type(dumped) is dict else None


def create_connections_router(runtime: ConnectionsRuntimeV1) -> APIRouter:
    """Create the local API routes around injected ports; never discovers I/O."""

    if type(runtime) is not ConnectionsRuntimeV1:
        raise TypeError("INVALID_CONNECTION_RUNTIME")

    router = APIRouter(prefix="/connections", tags=["connections"])

    @router.get("/catalog")
    def get_catalog(request: Request) -> JSONResponse:
        scope = _trusted_scope(request)
        if isinstance(scope, JSONResponse):
            return scope
        if request.scope.get("query_string", b""):
            return _error(400, _UNSUPPORTED_QUERY)
        principal, _environment = scope
        catalog = _read_catalog(runtime, principal.project_id)
        if catalog is None:
            return _error(503, _UNAVAILABLE)
        providers = _dto_payload(catalog, ConnectionCatalogV1)
        if providers is None:
            return _error(503, _UNAVAILABLE)
        return _ok(providers)

    @router.get("/status")
    def get_status(request: Request) -> JSONResponse:
        scope = _trusted_scope(request)
        if isinstance(scope, JSONResponse):
            return scope
        if request.scope.get("query_string", b""):
            return _error(400, _UNSUPPORTED_QUERY)
        principal, environment = scope
        if runtime.status_port is None:
            return _error(503, _UNAVAILABLE)
        catalog = _read_catalog(runtime, principal.project_id)
        if catalog is None:
            return _error(503, _UNAVAILABLE)
        try:
            rows = runtime.status_port.get_status(principal.project_id, environment)
        except Exception:
            return _error(503, _UNAVAILABLE)
        if type(rows) is not tuple or len(rows) > 64:
            return _error(503, _UNAVAILABLE)
        safe_rows: list[dict[str, object]] = []
        for row in rows:
            payload = _dto_payload(row, ConnectionStatusV1)
            if (
                payload is None
                or row.environment is not environment
                or _catalog_entry(catalog, row.provider_id) is None
            ):
                return _error(503, _UNAVAILABLE)
            safe_rows.append(payload)
        return _ok({"connections": safe_rows})

    def action_context(
        request: Request, provider_text: str
    ) -> (
        tuple[TrustedPrincipalV1, EnvironmentV1, ProviderV1, ConnectionCatalogEntryV1]
        | JSONResponse
    ):
        scope = _trusted_scope(request)
        if isinstance(scope, JSONResponse):
            return scope
        principal, environment = scope
        if request.scope.get("query_string", b""):
            return _error(400, _UNSUPPORTED_QUERY)
        if not _no_request_body(request):
            return _error(400, _UNSUPPORTED_BODY)
        provider = _provider(provider_text)
        if provider is None:
            if type(provider_text) is str and _PROVIDER_TEXT.fullmatch(provider_text):
                return _error(404, _NOT_FOUND)
            return _error(400, _BAD_REQUEST)
        catalog = _read_catalog(runtime, principal.project_id)
        if catalog is None:
            return _error(503, _UNAVAILABLE)
        entry = _catalog_entry(catalog, provider)
        if entry is None:
            return _error(404, _NOT_FOUND)
        if environment not in entry.environments:
            return _error(403, _FORBIDDEN)
        return principal, environment, provider, entry

    @router.post("/{provider}/connect")
    async def connect(provider: str, request: Request) -> JSONResponse:
        context = action_context(request, provider)
        if isinstance(context, JSONResponse):
            return context
        principal, environment, provider_value, entry = context
        if environment is EnvironmentV1.LIVE:
            return _error(403, _FORBIDDEN)
        port = runtime.connect_port
        if port is None:
            return _error(503, _UNAVAILABLE)
        try:
            result = port.initiate_connect(principal.project_id, provider_value, environment)
        except Exception:
            return _error(503, _UNAVAILABLE)
        if type(result) is ConnectInitiateV1:
            if (
                entry.auth_method != "oauth"
                or result.provider_id is not provider_value
                or result.environment is not environment
                or result.single_use is not True
                or not _valid_oauth_expiry(result.expires_at_ns, runtime.clock_ns)
                or not _authorization_host_matches(result, runtime)
            ):
                return _error(503, _UNAVAILABLE)
            payload = _dto_payload(result, ConnectInitiateV1)
        elif type(result) is CredentialConnectInitiateV1:
            if (
                entry.auth_method != result.auth_method
                or result.provider_id is not provider_value
                or result.environment is not environment
            ):
                return _error(503, _UNAVAILABLE)
            payload = _dto_payload(result, CredentialConnectInitiateV1)
        else:
            payload = None
        if payload is None:
            return _error(503, _UNAVAILABLE)
        return _ok(payload, status=202)

    def finish_action(
        request: Request,
        provider_text: str,
        *,
        cancel: bool,
    ) -> JSONResponse:
        context = action_context(request, provider_text)
        if isinstance(context, JSONResponse):
            return context
        principal, environment, provider, _entry = context
        if cancel:
            cancel_port = runtime.cancel_port
            if cancel_port is None:
                return _error(503, _UNAVAILABLE)
            try:
                result = cancel_port.cancel_connect(principal.project_id, provider, environment)
            except Exception:
                return _error(503, _UNAVAILABLE)
        else:
            disconnect_port = runtime.disconnect_port
            if disconnect_port is None:
                return _error(503, _UNAVAILABLE)
            try:
                result = disconnect_port.disconnect(principal.project_id, provider, environment)
            except Exception:
                return _error(503, _UNAVAILABLE)
        payload = _dto_payload(result, ConnectionActionV1)
        expected_results = (
            {ConnectionActionResultV1.CANCELLED}
            if cancel
            else {
                ConnectionActionResultV1.DISCONNECTED,
                ConnectionActionResultV1.ALREADY_DISCONNECTED,
            }
        )
        if (
            payload is None
            or result.provider_id is not provider
            or result.environment is not environment
            or result.result not in expected_results
        ):
            return _error(503, _UNAVAILABLE)
        return _ok(payload)

    @router.post("/{provider}/cancel")
    def cancel(provider: str, request: Request) -> JSONResponse:
        return finish_action(request, provider, cancel=True)

    @router.post("/{provider}/disconnect")
    def disconnect(provider: str, request: Request) -> JSONResponse:
        return finish_action(request, provider, cancel=False)

    return router


__all__ = ["create_connections_router"]
