"""Bounded HTTP adapter for the local, DEMO-only MT5 EA hosting service.

The router is deliberately not mounted by ``main.py`` in this slice. A later
integration must provide the operator-selected local data root and reviewed
bridge/cap adapters before enabling it.
"""

from __future__ import annotations

import base64
import binascii
import json
from typing import NoReturn

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from leviathan_core.execution.mt5_ea_host import (
    MAX_HTTP_BODY_BYTES,
    EaHostingError,
    EaHostingServiceV1,
    EaInstallRequestV1,
    EaInstallResultV1,
    EaKillResultV1,
    EaMonitorResultV1,
)
from leviathan_core.security.authz_models import (
    AuthorizationModelError,
    TrustedPrincipalV1,
    require_trusted_principal,
)

_INSTALL_FIELDS = frozenset(
    {
        "ea_filename",
        "ea_base64",
        "set_filename",
        "set_base64",
        "terminal_family",
        "symbol",
        "timeframe",
    }
)
_ID_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:-")


def _error(status: int, code: str) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"error": {"code": code}},
        headers={"Cache-Control": "no-store"},
    )


def _deny(status: int, code: str) -> NoReturn:
    raise _RouteError(status, code)


class _RouteError(Exception):
    __slots__ = ("code", "status")

    def __init__(self, status: int, code: str) -> None:
        self.status = status
        self.code = code
        super().__init__(code)


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _deny(422, "INVALID_EA_REQUEST")
        result[key] = value
    return result


async def _json_body(request: Request) -> object:
    raw = bytearray()
    try:
        async for chunk in request.stream():
            if len(raw) + len(chunk) > MAX_HTTP_BODY_BYTES:
                _deny(413, "FILE_TOO_LARGE")
            raw.extend(chunk)
        return json.loads(bytes(raw), object_pairs_hook=_unique_pairs)
    except _RouteError:
        raise
    except Exception:
        _deny(422, "INVALID_EA_REQUEST")


def _principal(request: Request) -> TrustedPrincipalV1:
    try:
        principal = require_trusted_principal(getattr(request.state, "trusted_principal", None))
    except AuthorizationModelError:
        _deny(401, "PRINCIPAL_UNTRUSTED")
    if principal.project_id != "leviathan-ai" or principal.env != "development":
        _deny(403, "DEMO_SCOPE_REQUIRED")
    if not ({"operator", "admin"} & set(principal.roles)):
        _deny(403, "OPERATOR_REQUIRED")
    return principal


def _b64(value: object) -> bytes:
    if type(value) is not str or len(value) > MAX_HTTP_BODY_BYTES:
        _deny(422, "INVALID_EA_REQUEST")
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeError, binascii.Error, ValueError):
        _deny(422, "INVALID_EA_REQUEST")


def _install_json(result: EaInstallResultV1) -> dict[str, object]:
    return {
        "session_id": result.session_id,
        "account_id": result.account_id,
        "environment": "DEMO",
        "terminal_family": result.terminal_family,
        "expert_relative_path": result.expert_relative_path,
        "preset_relative_path": result.preset_relative_path,
        "ea_sha256": result.ea_sha256,
        "set_sha256": result.set_sha256,
        "provenance": {
            "ea_filename": result.provenance.ea_filename,
            "set_filename": result.provenance.set_filename,
            "ea_sha256": result.provenance.ea_sha256,
            "set_sha256": result.provenance.set_sha256,
            "ea_size_bytes": result.provenance.ea_size_bytes,
            "set_size_bytes": result.provenance.set_size_bytes,
            "installed_at_ns": str(result.provenance.installed_at_ns),
            "operator_id": result.provenance.operator_id,
        },
        "startup_config": {
            "terminal_family": result.startup_config.terminal_family,
            "expert_name": result.startup_config.expert_name,
            "set_file": result.startup_config.set_file,
            "symbol": result.startup_config.symbol,
            "timeframe": result.startup_config.timeframe,
            "environment": "DEMO",
            "execution_allowed": False,
        },
        "execution_allowed": False,
    }


def _monitor_json(result: EaMonitorResultV1) -> dict[str, object]:
    return {
        "session_id": result.session_id,
        "account_id": result.account_id,
        "environment": "DEMO",
        "observed_at_ns": str(result.observed_at_ns),
        "open_order_count": result.open_order_count,
        "open_orders": [
            {
                "client_order_id": order.client_order_id,
                "venue_order_id": order.venue_order_id,
                "venue": order.venue,
                "status": order.status,
                "observed_at_ns": str(order.observed_at_ns),
            }
            for order in result.open_orders
        ],
        "positions": [[instrument, quantity] for instrument, quantity in result.positions],
        "cap_status": result.cap_status,
        "state": result.state,
        "execution_allowed": False,
    }


def _kill_json(result: EaKillResultV1) -> dict[str, object]:
    return {
        "session_id": result.session_id,
        "environment": "DEMO",
        "state": result.state,
        "disabled": result.disabled,
        "close_attempted": result.close_attempted,
        "execution_allowed": False,
    }


def _status(error: EaHostingError) -> int:
    if error.code in {"INVALID_EA_REQUEST", "INVALID_EA_FILE", "INVALID_SET_FILE"}:
        return 422
    if error.code == "FILE_TOO_LARGE":
        return 413
    if error.code == "DEMO_IDENTITY_REQUIRED":
        return 403
    if error.code == "SESSION_NOT_FOUND":
        return 404
    return 503


def create_mt5_ea_host_router(*, service: EaHostingServiceV1, enabled: bool = False) -> APIRouter:
    if type(service) is not EaHostingServiceV1 or type(enabled) is not bool:
        raise ValueError("INVALID_EA_HOST_CONFIGURATION")
    router = APIRouter(tags=["mt5-ea-host"])

    @router.post("/mt5/ea-host/v1/install", response_model=None)
    async def install(request: Request) -> JSONResponse:
        if not enabled:
            return _error(503, "EA_HOST_DISABLED")
        try:
            principal = _principal(request)
            if request.query_params:
                _deny(400, "INVALID_EA_REQUEST")
            if principal.portfolio not in (None, service.account_id):
                _deny(403, "DEMO_SCOPE_REQUIRED")
            if principal.venue not in (None, "MT5"):
                _deny(403, "DEMO_SCOPE_REQUIRED")
            body = await _json_body(request)
            if type(body) is not dict or set(body) != _INSTALL_FIELDS:
                _deny(422, "INVALID_EA_REQUEST")
            result = service.install(
                EaInstallRequestV1(
                    ea_filename=body["ea_filename"],
                    ea_bytes=_b64(body["ea_base64"]),
                    set_filename=body["set_filename"],
                    set_bytes=_b64(body["set_base64"]),
                    terminal_family=body["terminal_family"],
                    symbol=body["symbol"],
                    timeframe=body["timeframe"],
                ),
                operator_id=principal.principal_id,
            )
            return JSONResponse(
                status_code=201,
                content=_install_json(result),
                headers={"Cache-Control": "no-store"},
            )
        except _RouteError as exc:
            return _error(exc.status, exc.code)
        except EaHostingError as exc:
            return _error(_status(exc), exc.code)
        except Exception:
            return _error(503, "EA_HOST_UNAVAILABLE")

    @router.get("/mt5/ea-host/v1/sessions/{session_id}", response_model=None)
    def monitor(session_id: str, request: Request) -> JSONResponse:
        if not enabled:
            return _error(503, "EA_HOST_DISABLED")
        try:
            principal = _principal(request)
            if not _id(session_id) or principal.venue not in (None, "MT5"):
                _deny(403, "DEMO_SCOPE_REQUIRED")
            if principal.portfolio not in (None, service.account_id):
                _deny(403, "DEMO_SCOPE_REQUIRED")
            result = service.monitor(session_id, operator_id=principal.principal_id)
            return JSONResponse(
                status_code=200,
                content=_monitor_json(result),
                headers={"Cache-Control": "no-store"},
            )
        except _RouteError as exc:
            return _error(exc.status, exc.code)
        except EaHostingError as exc:
            return _error(_status(exc), exc.code)
        except Exception:
            return _error(503, "EA_HOST_UNAVAILABLE")

    @router.post("/mt5/ea-host/v1/sessions/{session_id}/kill", response_model=None)
    def kill(session_id: str, request: Request) -> JSONResponse:
        if not enabled:
            return _error(503, "EA_HOST_DISABLED")
        try:
            principal = _principal(request)
            if not _id(session_id) or principal.venue not in (None, "MT5"):
                _deny(403, "DEMO_SCOPE_REQUIRED")
            if principal.portfolio not in (None, service.account_id):
                _deny(403, "DEMO_SCOPE_REQUIRED")
            result = service.kill(session_id, operator_id=principal.principal_id)
            if result.state != "STOPPED":
                _deny(503, "EA_KILL_OUTCOME_UNKNOWN")
            return JSONResponse(
                status_code=200,
                content=_kill_json(result),
                headers={"Cache-Control": "no-store"},
            )
        except _RouteError as exc:
            return _error(exc.status, exc.code)
        except EaHostingError as exc:
            return _error(_status(exc), exc.code)
        except Exception:
            return _error(503, "EA_HOST_UNAVAILABLE")

    return router


def _id(value: object) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= 128
        and value.isascii()
        and all(ch.isalnum() or ch in _ID_CHARS for ch in value)
        and value[0].isalnum()
    )


__all__ = ["create_mt5_ea_host_router"]
