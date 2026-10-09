"""Read-only router for bounded, fake-first MT deployment plan snapshots.

The route computes a sealed plan from one injected snapshot. It does not mount
itself, discover a store, perform I/O beyond that read port, or authorize action.
"""

from __future__ import annotations

import re
from typing import Protocol

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from starlette.datastructures import MutableHeaders
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import PlainTextResponse
from starlette.types import Message, Receive, Scope, Send

from leviathan_core.mt_export_deploy_plan import (
    DeploymentPlanError,
    DeploymentPlanRequestV1,
    DeploymentPlanV1,
    plan_deployment,
    require_deployment_plan,
)
from leviathan_core.security.authz_models import (
    AuthorizationModelError,
    require_trusted_principal,
)

_PLAN_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z", re.ASCII)
_STATUS_UNAVAILABLE = "DEPLOY_PLAN_STATUS_UNAVAILABLE"
_INVALID_PLAN_REF = "INVALID_PLAN_REF"
_PLAN_NOT_FOUND = "DEPLOY_PLAN_NOT_FOUND"
_PRINCIPAL_UNTRUSTED = "PRINCIPAL_UNTRUSTED"
_UNSUPPORTED_QUERY = "UNSUPPORTED_QUERY"


class _NoStoreRoute(APIRoute):
    """Apply no-store to route responses, including FastAPI's 405 response."""

    async def handle(self, scope: Scope, receive: Receive, send: Send) -> None:
        async def send_no_store(message: Message) -> None:
            if message["type"] == "http.response.start":
                MutableHeaders(scope=message)["Cache-Control"] = "no-store"
            await send(message)

        try:
            await super().handle(scope, receive, send_no_store)
        except StarletteHTTPException as exc:
            if exc.status_code != 405:
                raise
            headers = dict(exc.headers or {})
            headers["Cache-Control"] = "no-store"
            response = PlainTextResponse(
                "Method Not Allowed",
                status_code=405,
                headers=headers,
            )
            await response(scope, receive, send)


class DeploymentPlanReadPortV1(Protocol):
    """One bounded project-scoped snapshot lookup; never a list operation."""

    def read_plan_request(
        self, project_id: str, plan_ref: str
    ) -> DeploymentPlanRequestV1 | None: ...


def _error(status_code: int, code: str) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"error": {"code": code}})


def _unavailable() -> JSONResponse:
    return _error(503, _STATUS_UNAVAILABLE)


def _serialize(plan: DeploymentPlanV1) -> dict[str, object]:
    """Explicit response allowlist: never dump the plan model or source inputs."""

    return {
        "schema_version": plan.schema_version,
        "artifact_id": plan.artifact_id,
        "action": plan.action.value,
        "evaluated_at_ns": plan.evaluated_at_ns,
        "target_decisions": [
            {
                "target_id": item.target_id,
                "decision": item.decision,
                "block_code": item.block_code,
                "canary_partition": item.canary_partition,
                "operator_switch_required": item.operator_switch_required,
                "execution_permitted": False,
            }
            for item in plan.target_decisions
        ],
        "canary_target_ids": list(plan.canary_target_ids),
        "remainder_target_ids": list(plan.remainder_target_ids),
        "blocked_target_ids": list(plan.blocked_target_ids),
        "execution_permitted": False,
    }


def create_mt_export_deploy_status_router(
    *,
    read_port: DeploymentPlanReadPortV1 | None = None,
    enabled: bool = False,
) -> APIRouter:
    """Build a GET-only router; the status feature is disabled by default."""

    if type(enabled) is not bool:
        raise ValueError("INVALID_CONFIGURATION")

    router = APIRouter(
        tags=["mt-export-deployment-status"],
        route_class=_NoStoreRoute,
    )

    @router.get("/mt-export/deployment/plans/{plan_ref:path}", response_model=None)
    def read_deployment_plan(plan_ref: str, request: Request) -> JSONResponse:
        if not enabled or read_port is None:
            return _unavailable()

        try:
            principal = require_trusted_principal(getattr(request.state, "trusted_principal", None))
        except AuthorizationModelError:
            return _error(401, _PRINCIPAL_UNTRUSTED)

        if type(plan_ref) is not str or _PLAN_REF.fullmatch(plan_ref) is None:
            return _error(400, _INVALID_PLAN_REF)
        if request.scope.get("query_string", b""):
            return _error(400, _UNSUPPORTED_QUERY)

        try:
            snapshot = read_port.read_plan_request(principal.project_id, plan_ref)
        except Exception:
            return _unavailable()
        if snapshot is None:
            return _error(404, _PLAN_NOT_FOUND)

        try:
            plan = require_deployment_plan(plan_deployment(snapshot))
        except (DeploymentPlanError, TypeError, ValueError):
            return _unavailable()
        return JSONResponse(status_code=200, content=_serialize(plan))

    return router


__all__ = ["DeploymentPlanReadPortV1", "create_mt_export_deploy_status_router"]
