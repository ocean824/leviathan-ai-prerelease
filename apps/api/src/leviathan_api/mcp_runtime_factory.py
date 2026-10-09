"""Fail-closed factory for the MCP control router.

The binding is an offline composition seam. Production mounting remains gated
on an independently supplied durable MCP audit store.
"""

from __future__ import annotations

import re
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol

from fastapi import APIRouter, HTTPException, Request

from leviathan_api.routers.mcp_control import McpControlRuntime, router
from leviathan_api.security.mcp_principal_resolver import (
    McpPrincipalResolutionCodeV1,
    McpPrincipalResolutionError,
)
from leviathan_core.mcp_control.state_models import AuditEventV1
from leviathan_core.risk.halt import HaltAuthority
from leviathan_core.security.principal_verifier import VerifiedPrincipalV1

_AUTHORIZATION_BEARER = re.compile(rb"Bearer ([A-Za-z0-9._~+/-]+=*)\Z", re.ASCII)
_MAX_AUTHORIZATION_BYTES = 16_400


class McpVerifiedResolverPort(Protocol):
    """SEC-003 resolver boundary consumed by MCP-003 routes."""

    def resolve_verified(
        self,
        token: object,
        *,
        peer_certificate_der: object | None = None,
    ) -> VerifiedPrincipalV1: ...


class McpAuditPort(Protocol):
    """Atomically append all events or persist none when append_batch raises."""

    def append_batch(self, events: tuple[AuditEventV1, ...]) -> None: ...


class McpRuntimeFactoryError(ValueError):
    """Fixed construction failure that contains no injected value."""

    code = "MCP_CONTROL_UNAVAILABLE"

    def __init__(self) -> None:
        super().__init__(self.code)


@dataclass(frozen=True, slots=True)
class McpRuntimeFactoryConfigV1:
    """Required runtime, SEC-003 resolver and append-only audit port."""

    runtime: McpControlRuntime
    resolver: McpVerifiedResolverPort = field(repr=False)
    audit: McpAuditPort = field(repr=False)


@dataclass(slots=True)
class _BindingState:
    lock: threading.Lock = field(default_factory=threading.Lock)
    closed: bool = False


@dataclass(frozen=True, slots=True)
class McpControlBinding:
    """Frozen router and injected ports with an idempotent fail-closed close."""

    router: APIRouter
    runtime: McpControlRuntime
    resolver: McpVerifiedResolverPort = field(repr=False)
    audit: McpAuditPort = field(repr=False)
    principal_resolver: Callable[[Request], VerifiedPrincipalV1]
    _state: _BindingState = field(repr=False, compare=False)

    def close(self) -> None:
        """Make future route authentication fail closed; safe to call repeatedly."""
        with self._state.lock:
            self._state.closed = True


def _peer_certificate_der(request: Request) -> object | None:
    """Read the transport-authenticated certificate from the ASGI TLS extension."""
    extensions = request.scope.get("extensions")
    if extensions is None:
        return None
    if type(extensions) is not dict:
        raise HTTPException(status_code=503, detail="MCP_CONTROL_UNAVAILABLE") from None
    tls = extensions.get("tls")
    if tls is None:
        return None
    if type(tls) is not dict:
        raise HTTPException(status_code=503, detail="MCP_CONTROL_UNAVAILABLE") from None
    certificate = tls.get("client_cert_der")
    if certificate is None:
        return None
    if type(certificate) is not bytes or not certificate:
        raise HTTPException(status_code=503, detail="MCP_CONTROL_UNAVAILABLE") from None
    return certificate


def _authorization_token(request: Request) -> str:
    values = [
        value for key, value in request.scope.get("headers", ()) if key.lower() == b"authorization"
    ]
    if len(values) != 1 or len(values[0]) > _MAX_AUTHORIZATION_BYTES:
        raise HTTPException(status_code=401, detail="UNAUTHENTICATED") from None
    match = _AUTHORIZATION_BEARER.fullmatch(values[0])
    if match is None:
        raise HTTPException(status_code=401, detail="UNAUTHENTICATED") from None
    try:
        return match.group(1).decode("ascii")
    except UnicodeDecodeError:
        raise HTTPException(status_code=401, detail="UNAUTHENTICATED") from None


def _request_principal_resolver(
    resolver: McpVerifiedResolverPort,
    state: _BindingState,
) -> Callable[[Request], VerifiedPrincipalV1]:
    def resolve_request(request: Request) -> VerifiedPrincipalV1:
        with state.lock:
            if state.closed:
                raise HTTPException(status_code=503, detail="MCP_CONTROL_UNAVAILABLE") from None
        token = _authorization_token(request)
        certificate = _peer_certificate_der(request)
        try:
            principal = resolver.resolve_verified(token, peer_certificate_der=certificate)
        except McpPrincipalResolutionError as exc:
            if exc.code is McpPrincipalResolutionCodeV1.VERIFIER_UNAVAILABLE:
                raise HTTPException(status_code=503, detail="MCP_CONTROL_UNAVAILABLE") from None
            raise HTTPException(status_code=401, detail="UNAUTHENTICATED") from None
        except Exception:
            raise HTTPException(status_code=503, detail="MCP_CONTROL_UNAVAILABLE") from None
        if type(principal) is not VerifiedPrincipalV1:
            raise HTTPException(status_code=401, detail="UNAUTHENTICATED") from None
        return principal

    return resolve_request


def build_mcp_control(config: McpRuntimeFactoryConfigV1) -> McpControlBinding:
    """Validate all ports, then return a router binding without mounting an app."""
    if (
        type(config) is not McpRuntimeFactoryConfigV1
        or type(config.runtime) is not McpControlRuntime
        or type(config.runtime.halt_authority) is not HaltAuthority
        or not callable(getattr(config.resolver, "resolve_verified", None))
        or not callable(getattr(config.audit, "append_batch", None))
        or config.runtime.audit_sink is not None
        or config.runtime.write_ahead_required
        or config.runtime.allow_unaudited_for_tests
    ):
        raise McpRuntimeFactoryError()

    state = _BindingState()
    principal_resolver = _request_principal_resolver(config.resolver, state)

    def append_events(events: tuple[AuditEventV1, ...]) -> None:
        if type(events) is not tuple or any(type(event) is not AuditEventV1 for event in events):
            raise RuntimeError("MCP audit append failed")
        config.audit.append_batch(events)

    binding = McpControlBinding(
        router=router,
        runtime=config.runtime,
        resolver=config.resolver,
        audit=config.audit,
        principal_resolver=principal_resolver,
        _state=state,
    )
    config.runtime.bind_write_ahead_audit_sink(append_events)
    return binding


__all__ = [
    "McpAuditPort",
    "McpControlBinding",
    "McpRuntimeFactoryConfigV1",
    "McpRuntimeFactoryError",
    "McpVerifiedResolverPort",
    "build_mcp_control",
]
