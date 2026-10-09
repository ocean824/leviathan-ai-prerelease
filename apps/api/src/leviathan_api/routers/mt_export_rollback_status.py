"""Disabled-by-default, read-only HTTP status for MT rollback proposals."""

from __future__ import annotations

import re
from collections.abc import MutableMapping
from typing import Any, Protocol

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from starlette.types import Receive, Scope, Send

from leviathan_core.mt_export_rollback_plan import (
    RollbackPlanError,
    RollbackPlanV1,
    RollbackProposalV1,
    validate_rollback_proposal,
)
from leviathan_core.security.authz_models import (
    AuthorizationModelError,
    TrustedPrincipalV1,
    require_trusted_principal,
)

_PROPOSAL_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z", re.ASCII)
_ROLLBACK_ERROR_CODES = frozenset(
    {
        "INVALID_INPUT",
        "PROVENANCE_INVALID",
        "PRIOR_NOT_EARLIER",
        "ARTIFACT_NOT_DISTINCT",
        "TARGET_MISMATCH",
        "PLATFORM_MISMATCH",
    }
)


class _NoStoreRoute(APIRoute):
    """Apply no-store to normal responses and method-not-allowed responses."""

    async def handle(self, scope: Scope, receive: Receive, send: Send) -> None:
        async def send_no_store(message: MutableMapping[str, Any]) -> None:
            if message.get("type") == "http.response.start":
                headers = [
                    (name, value)
                    for name, value in message.get("headers", [])
                    if name.lower() != b"cache-control"
                ]
                headers.append((b"cache-control", b"no-store"))
                message = {**message, "headers": headers}
            await send(message)

        if self.methods and scope["method"] not in self.methods:
            response = JSONResponse(
                status_code=405,
                content={"detail": "Method Not Allowed"},
                headers={"Allow": ", ".join(self.methods)},
            )
            await response(scope, receive, send_no_store)
            return

        await super().handle(scope, receive, send_no_store)


class RollbackProposalReadPortV1(Protocol):
    """Injected read-only lookup for one opaque proposal reference."""

    def get_proposal(self, project_id: str, proposal_ref: str) -> RollbackProposalV1 | None:
        """Return a proposal for this project; return None for absent or foreign refs."""


def _error(status_code: int, code: str) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"detail": code})


def _trusted_principal(request: Request) -> TrustedPrincipalV1 | None:
    try:
        return require_trusted_principal(getattr(request.state, "trusted_principal", None))
    except AuthorizationModelError:
        return None


def _plan_projection(plan: RollbackPlanV1) -> dict[str, Any]:
    """Serialize only the closed, non-executable plan status fields."""
    return {
        "status": plan.status.value,
        "target_id": plan.target_id,
        "platform": plan.platform.value,
        "mode": plan.mode.value,
        "current_artifact_id": plan.current_artifact_id,
        "prior_artifact_id": plan.prior_artifact_id,
        "forward_deployment_id": plan.forward_deployment_id,
        "block_code": plan.block_code,
        "executable": False,
    }


def create_router(
    *,
    read_port: RollbackProposalReadPortV1 | None = None,
    enabled: bool = False,
) -> APIRouter:
    """Create one GET-only router. It remains unavailable unless explicitly enabled."""
    router = APIRouter(tags=["mt-export-rollback-status"], route_class=_NoStoreRoute)

    @router.get("/mt-export/rollback/proposals/{proposal_ref:path}", response_model=None)
    def get_rollback_proposal_status(
        proposal_ref: str, request: Request
    ) -> dict[str, Any] | JSONResponse:
        principal = _trusted_principal(request)
        if principal is None:
            return _error(401, "AUTH_REQUIRED")
        if enabled is not True or read_port is None:
            return _error(503, "FEATURE_UNAVAILABLE")
        if request.query_params.multi_items():
            return _error(400, "INVALID_QUERY")
        if _PROPOSAL_REF.fullmatch(proposal_ref) is None:
            return _error(400, "INVALID_REFERENCE")

        try:
            proposal = read_port.get_proposal(principal.project_id, proposal_ref)
        except Exception:
            return _error(503, "PROPOSAL_UNAVAILABLE")
        if proposal is None:
            return _error(404, "PROPOSAL_NOT_FOUND")

        try:
            plan = validate_rollback_proposal(proposal)
            plan.assert_sealed()
            projection = _plan_projection(plan)
        except RollbackPlanError as exc:
            code = exc.code if exc.code in _ROLLBACK_ERROR_CODES else "INVALID_INPUT"
            return _error(422, code)
        except Exception:
            return _error(503, "PROPOSAL_UNAVAILABLE")

        return {"plan": projection}

    return router


__all__ = ["RollbackProposalReadPortV1", "create_router"]
