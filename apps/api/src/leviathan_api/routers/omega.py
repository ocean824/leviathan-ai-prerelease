"""Authenticated OMEGA heartbeat, inquiry and kill routes.

The routes deliberately have no legacy seed behavior. Production wiring must
install a configured ``OmegaHeartbeatAdapterV1`` on ``app.state``; without it
the endpoints fail closed. Client certificate bytes come only from the
trusted ASGI TLS extension, never from a caller-controlled header.
"""

from __future__ import annotations

from contextlib import suppress
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Request

from leviathan_core.omega_link.heartbeat_adapter import (
    OmegaAdapterError,
    OmegaHeartbeatAdapterV1,
    OmegaPeerIdentityV1,
)

router = APIRouter(prefix="/omega", tags=["omega"])


def _adapter(request: Request) -> OmegaHeartbeatAdapterV1:
    adapter = getattr(request.app.state, "omega_adapter", None)
    if type(adapter) is not OmegaHeartbeatAdapterV1:
        raise HTTPException(status_code=503, detail="OMEGA_ADAPTER_UNAVAILABLE")
    return adapter


def _peer_certificate_der(request: Request) -> bytes | None:
    """Read only the proxy-authenticated client certificate extension."""
    extensions = request.scope.get("extensions")
    if not isinstance(extensions, dict):
        return None
    tls = extensions.get("tls")
    if not isinstance(tls, dict):
        return None
    certificate = tls.get("client_cert_der")
    return certificate if type(certificate) is bytes and certificate else None


def _authenticate(request: Request, *, scope: str) -> OmegaPeerIdentityV1:
    adapter = _adapter(request)
    try:
        return adapter.authenticate_request(
            authorization=request.headers.get("authorization"),
            peer_certificate_der=_peer_certificate_der(request),
            required_scope=scope,
        )
    except OmegaAdapterError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.code) from None


@router.get("/heartbeat")
def heartbeat(request: Request) -> dict[str, object]:
    _authenticate(request, scope="omega:heartbeat")
    state = getattr(request.app.state, "leviathan", None)
    if state is None:
        with suppress(OmegaAdapterError):
            _adapter(request).audit_denial("OMEGA_HEARTBEAT_UNAVAILABLE")
        raise HTTPException(status_code=503, detail="OMEGA_HEARTBEAT_UNAVAILABLE")
    adapter = _adapter(request)
    try:
        with state.halts.route_interlock():
            halted = state.halts.halted
            active_halts = state.halts.active
        return adapter.signed_heartbeat(
            halted=halted,
            active_halts=active_halts,
            trace_id=uuid4().hex,
        )
    except OmegaAdapterError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.code) from None
    except Exception:
        with suppress(OmegaAdapterError):
            adapter.audit_denial("OMEGA_HEARTBEAT_UNAVAILABLE")
        raise HTTPException(status_code=503, detail="OMEGA_HEARTBEAT_UNAVAILABLE") from None


@router.post("/inquiry")
def inquiry(request: Request) -> dict[str, str]:
    _authenticate(request, scope="omega:inquiry")
    # No reviewed live-data/risk path is wired in this slice. Never answer from
    # the demo replay context or imply that demo evidence is a live decision.
    try:
        _adapter(request).audit_denial("LIVE_EVIDENCE_UNAVAILABLE")
    except OmegaAdapterError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.code) from None
    return {
        "version": "1",
        "status": "unavailable",
        "permission": "deny",
        "reason_code": "LIVE_EVIDENCE_UNAVAILABLE",
    }


@router.post("/kill")
def kill_signal(request: Request) -> dict[str, object]:
    peer = _authenticate(request, scope="omega:kill")
    state = getattr(request.app.state, "leviathan", None)
    if state is None:
        with suppress(OmegaAdapterError):
            _adapter(request).audit_denial("OMEGA_KILL_DENIED")
        raise HTTPException(status_code=503, detail="OMEGA_KILL_DENIED")
    adapter = _adapter(request)
    try:
        reason = adapter.engage_kill(peer=peer, halt_authority=state.halts)
        return {"version": "1", "status": "halted", "reason": reason}
    except OmegaAdapterError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.code) from None
    except Exception:
        raise HTTPException(status_code=503, detail="OMEGA_KILL_DENIED") from None
