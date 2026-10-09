"""Read-only, principal-scoped MT terminal-agent health status endpoint."""

from __future__ import annotations

import re
from collections.abc import MutableMapping
from typing import Any, Protocol

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from starlette.routing import Match
from starlette.types import Receive, Scope, Send

from leviathan_core.mt_export_agent_health import (
    AgentHealthPolicyV1,
    AgentHeartbeatV1,
    UtcNsClock,
    evaluate_agent_health,
    require_agent_health,
)
from leviathan_core.security.authz_models import (
    AuthorizationModelError,
    TrustedPrincipalV1,
    require_trusted_principal,
)

_AGENT_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z", re.ASCII)


class AgentHealthStatusReadPort(Protocol):
    """One principal-scoped snapshot read; implementations must not write."""

    def read_snapshot(
        self, *, principal_id: str, project_id: str, agent_ref: str
    ) -> tuple[AgentHeartbeatV1 | None, AgentHealthPolicyV1] | None: ...


def _error(status_code: int, code: str) -> JSONResponse:
    return JSONResponse(
        {"error": {"code": code}},
        status_code=status_code,
        headers={"Cache-Control": "no-store"},
    )


def _principal(request: Request) -> TrustedPrincipalV1 | None:
    try:
        return require_trusted_principal(getattr(request.state, "trusted_principal", None))
    except AuthorizationModelError:
        return None


class _NoStoreRoute(APIRoute):
    """Apply no-store to method rejections generated before endpoint dispatch."""

    def matches(self, scope: MutableMapping[str, Any]) -> tuple[Match, MutableMapping[str, Any]]:
        match, child_scope = super().matches(scope)
        if (
            match is Match.PARTIAL
            and scope.get("type") == "http"
            and self.path_regex.match(scope.get("path", "")) is not None
        ):
            return Match.FULL, child_scope
        return match, child_scope

    async def handle(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("method") not in (self.methods or set()):
            response = _error(405, "METHOD_NOT_ALLOWED")
            await response(scope, receive, send)
            return
        await super().handle(scope, receive, send)


def create_agent_health_status_router(
    *,
    enabled: bool = False,
    read_port: AgentHealthStatusReadPort | None = None,
    clock: UtcNsClock | None = None,
) -> APIRouter:
    """Create a disabled-by-default read-only health route.

    The caller supplies a trusted-clock implementation and a sealed-policy-backed
    read port. This module deliberately does not register the router with an app.
    """

    router = APIRouter(tags=["mt-export-agent-health"], route_class=_NoStoreRoute)

    @router.get("/mt-export/agents/{agent_ref}/health")
    def get_agent_health(agent_ref: str, request: Request) -> JSONResponse:
        if enabled is not True or read_port is None or clock is None:
            return _error(503, "SERVICE_UNAVAILABLE")
        if _AGENT_REF.fullmatch(agent_ref) is None or request.query_params:
            return _error(400, "INVALID_REQUEST")

        principal = _principal(request)
        if principal is None:
            return _error(401, "AUTH_REQUIRED")

        try:
            snapshot = read_port.read_snapshot(
                principal_id=principal.principal_id,
                project_id=principal.project_id,
                agent_ref=agent_ref,
            )
        except Exception:
            return _error(503, "HEALTH_STATUS_UNAVAILABLE")

        if snapshot is None:
            return _error(404, "HEALTH_SNAPSHOT_NOT_FOUND")
        if type(snapshot) is not tuple or len(snapshot) != 2:
            return _error(503, "HEALTH_STATUS_UNAVAILABLE")

        heartbeat, policy = snapshot
        if heartbeat is not None and type(heartbeat) is not AgentHeartbeatV1:
            return _error(503, "HEALTH_STATUS_UNAVAILABLE")
        if type(policy) is not AgentHealthPolicyV1:
            return _error(503, "HEALTH_STATUS_UNAVAILABLE")

        try:
            health = require_agent_health(evaluate_agent_health(heartbeat, policy, clock))
            body = {
                "state": health.state.value,
                "reason_codes": [reason.value for reason in health.reason_codes],
                "observed_at_utc_ns": health.observed_at_utc_ns,
                "heartbeat_age_ns": health.heartbeat_age_ns,
                "activation_permitted": False,
            }
        except Exception:
            return _error(503, "HEALTH_STATUS_UNAVAILABLE")

        return JSONResponse(body, headers={"Cache-Control": "no-store"})

    return router


__all__ = ["AgentHealthStatusReadPort", "create_agent_health_status_router"]
