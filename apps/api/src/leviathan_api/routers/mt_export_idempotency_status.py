"""Read-only, principal-scoped status for duplicate-intent comparisons.

The router never accepts an idempotency key or payload. Its injected read port
owns principal-scoped request-reference lookup; no persistence implementation
or exactly-once behavior is implied here.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Protocol

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from starlette.types import Receive, Scope, Send

from leviathan_core.mt_export_idempotency import (
    DuplicateIntentDecisionV1,
    DuplicateIntentStatusV1,
    RequestBindingV1,
    decide_duplicate_intent,
)
from leviathan_core.seal import require
from leviathan_core.security.authz_models import (
    AuthorizationModelError,
    TrustedPrincipalV1,
    require_trusted_principal,
)

_ROUTE_PREFIX = "/mt-export/idempotency"
_REQUEST_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)
_DECISION_TAG = "mt_export_idemp_decision_v1"
_UNAVAILABLE = {"error": "unavailable"}
_UNAUTHENTICATED = {"error": "unauthenticated"}
_NOT_FOUND = {"error": "not_found"}
_INVALID_REQUEST = {"error": "invalid_request"}


class IdempotencyStatusRouteError(ValueError):
    """Content-free configuration failure for the router factory."""

    def __init__(self) -> None:
        self.code = "INVALID_CONFIGURATION"
        super().__init__(self.code)


class IdempotencyStatusReadPort(Protocol):
    """Read an issued prior/candidate pair scoped to this trusted principal."""

    def read_bindings(
        self, *, principal: TrustedPrincipalV1, request_ref: str
    ) -> tuple[RequestBindingV1 | None, RequestBindingV1] | None: ...


def _response(status_code: int, body: Mapping[str, object]) -> JSONResponse:
    return JSONResponse(
        dict(body),
        status_code=status_code,
        headers={"Cache-Control": "no-store"},
    )


class _NoStoreAPIRoute(APIRoute):
    """Give framework-generated method errors the same no-store response policy."""

    async def handle(self, scope: Scope, receive: Receive, send: Send) -> None:
        if self.methods is not None and scope.get("method") not in self.methods:
            await _response(405, {"error": "method_not_allowed"})(scope, receive, send)
            return
        await super().handle(scope, receive, send)


def build_idempotency_status_router(
    *,
    enabled: bool = False,
    read_port: IdempotencyStatusReadPort | None = None,
) -> APIRouter:
    """Build a GET-only status router, disabled unless explicitly enabled."""

    if type(enabled) is not bool:
        raise IdempotencyStatusRouteError()
    if read_port is not None and not callable(getattr(read_port, "read_bindings", None)):
        raise IdempotencyStatusRouteError()

    router = APIRouter(
        prefix=_ROUTE_PREFIX,
        tags=["mt-export-idempotency"],
        route_class=_NoStoreAPIRoute,
    )

    @router.get("/requests/{request_ref:path}")
    def read_status(request_ref: str, request: Request) -> JSONResponse:
        if not enabled or read_port is None:
            return _response(503, _UNAVAILABLE)

        if request.scope.get("query_string", b""):
            return _response(400, _INVALID_REQUEST)

        if (
            type(request_ref) is not str
            or len(request_ref) > 128
            or _REQUEST_REF.fullmatch(request_ref) is None
        ):
            return _response(404, _NOT_FOUND)

        try:
            principal = require_trusted_principal(getattr(request.state, "trusted_principal", None))
        except AuthorizationModelError:
            return _response(401, _UNAUTHENTICATED)

        try:
            pair = read_port.read_bindings(principal=principal, request_ref=request_ref)
            if pair is None:
                return _response(404, _NOT_FOUND)
            if type(pair) is not tuple or len(pair) != 2:
                return _response(503, _UNAVAILABLE)
            prior, candidate = pair
            decision = decide_duplicate_intent(prior, candidate)
            require(decision, _DECISION_TAG)
            if type(decision) is not DuplicateIntentDecisionV1:
                return _response(503, _UNAVAILABLE)
            if type(decision.status) is not DuplicateIntentStatusV1:
                return _response(503, _UNAVAILABLE)
            if decision.reason_code not in (None, "IDEMPOTENCY_CONFLICT"):
                return _response(503, _UNAVAILABLE)
        except Exception:
            return _response(503, _UNAVAILABLE)

        return _response(
            200,
            {
                "status": decision.status.value,
                "reason_code": decision.reason_code,
            },
        )

    return router


__all__ = [
    "IdempotencyStatusReadPort",
    "IdempotencyStatusRouteError",
    "build_idempotency_status_router",
]
