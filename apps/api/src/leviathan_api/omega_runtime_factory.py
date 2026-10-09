"""Instance-scoped construction for the production OMEGA task router."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass, field
from threading import Lock

from fastapi import APIRouter
from leviathan_store.omega_due_queue import OmegaDueQueueStore

from leviathan_api.routers.omega_tasks import build_router
from leviathan_core.omega_link.heartbeat_adapter import (
    OmegaHeartbeatAdapterV1,
    OmegaNonceStore,
)
from leviathan_core.omega_link.state_models import OmegaPolicyV1
from leviathan_core.omega_link.task_bridge import (
    AuditSinkPort,
    BridgeHealthPort,
    EventOutboxPort,
    ManifestPort,
    MCPAuthorizerPort,
    ModelPolicyPort,
    OmegaTaskRuntime,
    RateLimiterPort,
    SessionVerifierPort,
    TaskBridgeError,
)
from leviathan_core.security.principal_verifier import PrincipalVerifier


class _CloseOnce:
    """Run caller-owned resource cleanup once, even across concurrent closes."""

    __slots__ = ("_callback", "_closed", "_lock")

    def __init__(self, callback: Callable[[], None]) -> None:
        self._callback = callback
        self._closed = False
        self._lock = Lock()

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            try:
                self._callback()
            except Exception:
                raise TaskBridgeError("TASK_STORE_UNAVAILABLE", 503) from None


@dataclass(frozen=True, slots=True)
class OmegaTasksConfig:
    """All dependencies needed to construct a matched runtime and adapter.

    ``omega_policy`` is the sole policy input. The factory passes that exact
    object to both the runtime and the heartbeat adapter.
    """

    bridge_health_port: BridgeHealthPort
    session_verifier: SessionVerifierPort
    manifest_port: ManifestPort
    mcp_authorizer: MCPAuthorizerPort
    task_store: OmegaDueQueueStore
    audit_sink: AuditSinkPort
    event_outbox: EventOutboxPort
    rate_limiter: RateLimiterPort
    model_policy: ModelPolicyPort
    omega_policy: OmegaPolicyV1
    clock: Callable[[], int]
    adapter_verifier: PrincipalVerifier
    pinned_certificates: Mapping[str, str]
    nonce_store: OmegaNonceStore
    adapter_clock_ns: Callable[[], int]
    response_signer: Callable[[bytes], str]
    denial_auditor: Callable[[str], None]
    capability_manifest_hash: str
    close_resources: Callable[[], None]


@dataclass(frozen=True, slots=True)
class OmegaTasksBinding:
    """The router and constructed dependencies to mount together."""

    router: APIRouter
    runtime: OmegaTaskRuntime
    adapter: OmegaHeartbeatAdapterV1
    _closer: _CloseOnce = field(repr=False, compare=False)

    def close(self) -> None:
        """Close caller-owned resources once; repeated calls are harmless."""

        self._closer.close()


def _make_runtime(config: OmegaTasksConfig) -> OmegaTaskRuntime:
    return OmegaTaskRuntime(
        bridge_health_port=config.bridge_health_port,
        session_verifier=config.session_verifier,
        manifest_port=config.manifest_port,
        mcp_authorizer=config.mcp_authorizer,
        task_store=config.task_store,
        audit_sink=config.audit_sink,
        event_outbox=config.event_outbox,
        rate_limiter=config.rate_limiter,
        model_policy=config.model_policy,
        omega_policy=config.omega_policy,
        clock=config.clock,
    )


def build_omega_tasks(config: OmegaTasksConfig) -> OmegaTasksBinding:
    """Build a router binding only from a complete, validated configuration.

    The caller owns mounting: set ``app.state.omega_tasks`` to the returned
    runtime, set ``app.state.omega_adapter`` to its adapter, include its router,
    and register ``binding.close`` with application shutdown.
    """

    if type(config) is not OmegaTasksConfig:
        raise TaskBridgeError("NOT_CONFIGURED", 503) from None

    cleanup = config.close_resources
    if not callable(cleanup):
        raise TaskBridgeError("NOT_CONFIGURED", 503) from None

    try:
        if type(config.omega_policy) is not OmegaPolicyV1:
            raise TaskBridgeError("NOT_CONFIGURED", 503)
        if type(config.task_store) is not OmegaDueQueueStore:
            raise TaskBridgeError("NOT_CONFIGURED", 503)
        config.task_store.list_due(now_ns=0, limit=1)
        runtime = _make_runtime(config)
        adapter = OmegaHeartbeatAdapterV1(
            verifier=config.adapter_verifier,
            pinned_certificates=config.pinned_certificates,
            nonce_store=config.nonce_store,
            clock_ns=config.adapter_clock_ns,
            policy=config.omega_policy,
            response_signer=config.response_signer,
            denial_auditor=config.denial_auditor,
            capability_manifest_hash=config.capability_manifest_hash,
        )
        router = build_router(runtime)
        return OmegaTasksBinding(
            router=router,
            runtime=runtime,
            adapter=adapter,
            _closer=_CloseOnce(cleanup),
        )
    except Exception:
        with suppress(Exception):
            cleanup()
        raise TaskBridgeError("NOT_CONFIGURED", 503) from None


__all__ = ["OmegaTasksBinding", "OmegaTasksConfig", "build_omega_tasks"]
