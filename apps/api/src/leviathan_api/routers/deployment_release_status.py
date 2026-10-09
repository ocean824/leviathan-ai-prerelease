"""Read-only, principal-scoped release readiness projection.

This router evaluates an already-issued evidence and policy bundle. It does not
approve, stage, apply, deploy, or roll back releases.
"""

from __future__ import annotations

import re
from typing import Protocol

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from starlette.types import Receive, Scope, Send

from leviathan_core.deployment_release_policy import (
    ReadinessBlocker,
    ReleaseEvidence,
    ReleasePolicy,
    evaluate_release_readiness,
)
from leviathan_core.security.authz_models import (
    AuthorizationModelError,
    TrustedPrincipalV1,
    require_trusted_principal,
)

_RELEASE_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z", re.ASCII)
_NO_STORE = {"Cache-Control": "no-store"}
_ERRORS = {
    "RELEASE_STATUS_UNAVAILABLE": 503,
    "UNAUTHENTICATED": 401,
    "RELEASE_STATUS_NOT_FOUND": 404,
}


class _NoStoreAPIRoute(APIRoute):
    """Attach no-store to framework method-mismatch responses as well."""

    async def handle(self, scope: Scope, receive: Receive, send: Send) -> None:
        method = scope.get("method")
        if method not in (self.methods or set()):
            response = JSONResponse(
                status_code=405,
                content={"error": {"code": "METHOD_NOT_ALLOWED"}},
                headers={"Allow": ", ".join(sorted(self.methods or set())), **_NO_STORE},
            )
            await response(scope, receive, send)
            return
        await super().handle(scope, receive, send)


class ReleaseStatusReadPortV1(Protocol):
    """Project-scoped read-only source for synthetic or future release records."""

    def read_release(
        self, *, project_id: str, release_ref: str
    ) -> tuple[ReleaseEvidence, ReleasePolicy] | None: ...


def _error(code: str) -> JSONResponse:
    return JSONResponse(
        status_code=_ERRORS[code],
        content={"error": {"code": code}},
        headers=_NO_STORE,
    )


def _principal(request: Request) -> TrustedPrincipalV1 | None:
    candidate = getattr(request.state, "trusted_principal", None)
    try:
        return require_trusted_principal(candidate)
    except AuthorizationModelError:
        return None


def create_deployment_release_status_router(
    *,
    enabled: bool = False,
    read_port: ReleaseStatusReadPortV1 | None = None,
) -> APIRouter:
    """Create an opt-in status router; absent configuration always fails closed."""
    router = APIRouter(
        prefix="/deployment/releases",
        tags=["deployment-release-status"],
        route_class=_NoStoreAPIRoute,
    )

    @router.get("/{release_ref}/readiness", response_model=None)
    def get_release_readiness(release_ref: str, request: Request) -> JSONResponse:
        if not enabled or read_port is None:
            return _error("RELEASE_STATUS_UNAVAILABLE")

        if request.method != "GET":
            return JSONResponse(
                status_code=405,
                content={"error": {"code": "METHOD_NOT_ALLOWED"}},
                headers={**_NO_STORE, "Allow": "GET"},
            )

        principal = _principal(request)
        if principal is None:
            return _error("UNAUTHENTICATED")

        if _RELEASE_REF.fullmatch(release_ref) is None:
            return _error("RELEASE_STATUS_NOT_FOUND")

        try:
            record = read_port.read_release(
                project_id=principal.project_id,
                release_ref=release_ref,
            )
        except Exception:
            return _error("RELEASE_STATUS_UNAVAILABLE")
        if record is None:
            return _error("RELEASE_STATUS_NOT_FOUND")
        if type(record) is not tuple or len(record) != 2:
            return _error("RELEASE_STATUS_UNAVAILABLE")

        evidence, policy = record
        try:
            result = evaluate_release_readiness(evidence, policy)
        except Exception:
            return _error("RELEASE_STATUS_UNAVAILABLE")
        blockers = tuple(ReadinessBlocker(item).value for item in result.blockers)
        return JSONResponse(
            status_code=200,
            content={"ready": result.ready, "blockers": list(blockers)},
            headers=_NO_STORE,
        )

    return router


__all__ = ["ReleaseStatusReadPortV1", "create_deployment_release_status_router"]
