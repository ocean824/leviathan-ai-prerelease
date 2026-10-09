"""Injection-only, PAPER-scoped account snapshot API.

The router is intentionally not mounted by this module. It projects an
already-issued broker account view and never submits orders or computes PnL.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Protocol

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from starlette.types import Receive, Scope, Send

from leviathan_core.execution.broker_port_v1 import (
    AccountViewV1,
    BrokerEnvironment,
    EquityEvidenceV1,
    VenueIdentityV1,
    require_account_view,
    require_venue_identity,
)
from leviathan_core.numeric import canonical_str
from leviathan_core.security.authz_models import (
    AuthorizationModelError,
    TrustedPrincipalV1,
    require_trusted_principal,
)

_NO_STORE = {"Cache-Control": "no-store"}
_ERRORS = {
    "UNAUTHENTICATED": 401,
    "PAPER_SCOPE_REQUIRED": 403,
    "PAPER_ACCOUNT_SNAPSHOT_UNAVAILABLE": 503,
}


class _NoStoreRoute(APIRoute):
    """Keep framework-generated method errors out of intermediary caches."""

    async def handle(self, scope: Scope, receive: Receive, send: Send) -> None:
        method = scope.get("method")
        if method not in (self.methods or set()):
            response = JSONResponse(
                status_code=405,
                content={"error": {"code": "METHOD_NOT_ALLOWED"}},
                headers={**_NO_STORE, "Allow": ", ".join(sorted(self.methods or set()))},
            )
            await response(scope, receive, send)
            return
        await super().handle(scope, receive, send)


class PaperAccountSnapshotReadPortV1(Protocol):
    """Read one account snapshot from an injected, already PAPER-bound port."""

    def read_account_view(self, account_id: str) -> AccountViewV1: ...


def _error(code: str) -> JSONResponse:
    return JSONResponse(
        status_code=_ERRORS[code],
        content={"error": {"code": code}},
        headers=_NO_STORE,
    )


def _utc_text(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _serialize_equity(value: EquityEvidenceV1 | None) -> dict[str, object] | None:
    if value is None:
        return None
    value.assert_sealed()
    return {
        "currency": value.currency,
        "amount": canonical_str(value.amount),
        "kind": value.kind.value,
        "broker_observed_at_ns": value.broker_observed_at_ns,
    }


def _serialize_view(view: AccountViewV1) -> dict[str, object]:
    observed_at = view.broker_observed_at
    if observed_at is None:
        raise ValueError("MISSING_BROKER_TIMESTAMP")
    return {
        "account_id": view.account_id,
        "environment": "paper",
        "broker_revision": view.broker_revision,
        "broker_observed_at": _utc_text(observed_at),
        "balances": (
            None
            if view.balances is None
            else [
                {"currency": balance.currency, "amount": canonical_str(balance.amount)}
                for balance in view.balances
            ]
        ),
        "positions": [
            {"instrument_id": instrument_id, "quantity": canonical_str(quantity)}
            for instrument_id, quantity in view.positions
        ],
        "equity": _serialize_equity(view.equity),
    }


def _trusted_principal(request: Request) -> TrustedPrincipalV1 | None:
    try:
        return require_trusted_principal(getattr(request.state, "trusted_principal", None))
    except AuthorizationModelError:
        return None


def create_paper_account_snapshot_router(
    *,
    read_port: PaperAccountSnapshotReadPortV1 | None,
    venue_identity: VenueIdentityV1 | None,
    enabled: bool = False,
) -> APIRouter:
    """Build an unmounted PAPER snapshot router with explicit dependencies.

    An absent dependency or disabled switch leaves the endpoint unavailable.
    The supplied venue identity binds this read to one account and PAPER
    environment; callers cannot choose another account through the URL.
    """
    if type(enabled) is not bool:
        raise ValueError("INVALID_CONFIGURATION")

    router = APIRouter(tags=["paper-account-snapshot"], route_class=_NoStoreRoute)

    @router.get("/paper/accounts/{account_id}/snapshot", response_model=None)
    def read_paper_account_snapshot(account_id: str, request: Request) -> JSONResponse:
        if not enabled or read_port is None or venue_identity is None:
            return _error("PAPER_ACCOUNT_SNAPSHOT_UNAVAILABLE")

        principal = _trusted_principal(request)
        if principal is None:
            return _error("UNAUTHENTICATED")
        if principal.project_id != "leviathan-ai" or "operator" not in principal.roles:
            return _error("PAPER_SCOPE_REQUIRED")

        try:
            venue = require_venue_identity(venue_identity)
        except Exception:
            return _error("PAPER_ACCOUNT_SNAPSHOT_UNAVAILABLE")
        if venue.environment is not BrokerEnvironment.PAPER:
            return _error("PAPER_SCOPE_REQUIRED")
        if account_id != venue.account_id or (
            principal.venue is not None and principal.venue != venue.venue.value
        ):
            return _error("PAPER_SCOPE_REQUIRED")

        try:
            view = require_account_view(read_port.read_account_view(venue.account_id))
            if view.account_id != venue.account_id or view.broker_observed_at is None:
                return _error("PAPER_ACCOUNT_SNAPSHOT_UNAVAILABLE")
            return JSONResponse(
                status_code=200,
                content=_serialize_view(view),
                headers=_NO_STORE,
            )
        except Exception:
            return _error("PAPER_ACCOUNT_SNAPSHOT_UNAVAILABLE")

    return router


__all__ = ["PaperAccountSnapshotReadPortV1", "create_paper_account_snapshot_router"]
