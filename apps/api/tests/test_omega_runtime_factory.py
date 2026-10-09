"""Unit coverage for the injected OMEGA router factory."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from typing import cast

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from leviathan_store.engine import create_sync_engine_and_sessionmaker, init_sync_schema
from leviathan_store.omega_due_queue import OmegaDueQueueStore
from sqlalchemy.orm import Session, sessionmaker

import leviathan_api.omega_runtime_factory as omega_runtime_factory
from leviathan_api.routers import omega_tasks
from leviathan_core.execution.order_models import LedgerIntegrityKey
from leviathan_core.omega_link.heartbeat_adapter import (
    InMemoryOmegaNonceStore,
    OmegaHeartbeatAdapterV1,
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
from leviathan_core.security.principal_verifier import (
    PrincipalVerifier,
    RSAPublicKeyV1,
    TrustedIssuerV1,
)

_ROOT = Path(__file__).resolve().parents[3]
_NOW_NS = 1_800_000_000_000_000_000
_CERTIFICATE = b"synthetic omega certificate"
_PEER_SYSTEM = "peer-alpha"
_MISSING = object()
_RSA_FIXTURE = json.loads(
    (_ROOT / "packages/leviathan-core/tests/security/fixtures/sec003_synthetic_rsa.json").read_text(
        encoding="utf-8"
    )
)


class _KeySet:
    def get_key(self, issuer: str, kid: str) -> RSAPublicKeyV1 | None:
        if (issuer, kid) != ("omega-test-issuer", "omega-test-key"):
            return None
        return RSAPublicKeyV1(
            int(_RSA_FIXTURE["modulus_hex"], 16),
            int(_RSA_FIXTURE["public_exponent_hex"], 16),
        )


class _Revocations:
    def is_revoked(self, issuer: str, jti: str) -> bool:
        return False


class _Ports:
    def __init__(self) -> None:
        self.fail_due = False

    def snapshot(self, peer_system: str) -> object:
        return object()

    def verify(self, *args: object, **kwargs: object) -> object:
        return object()

    def get_manifest(self, peer_system: str) -> object:
        return object()

    def authorize_tool(self, **kwargs: object) -> object:
        return object()

    def create(self, **kwargs: object) -> object:
        return object()

    def get_task(self, peer_system: str, task_id: str) -> None:
        return None

    def replace_task(self, **kwargs: object) -> bool:
        return False

    def list_due(self, *, now_ns: int, limit: int) -> tuple[()]:
        return ()

    def list_due_for_peer(self, *, peer_system: str, now_ns: int, limit: int) -> tuple[()]:
        if self.fail_due:
            raise RuntimeError("synthetic store failure")
        return ()

    def append(self, entry: object) -> object:
        return object()

    def read(self, **kwargs: object) -> tuple[()]:
        return ()

    def enqueue(self, event: object) -> None:
        return None

    def consume(self, *args: object, **kwargs: object) -> object:
        return object()

    def route_task(self, **kwargs: object) -> object:
        return object()


class _RaisingSessionFactory:
    def __call__(self) -> Session:
        raise RuntimeError("synthetic session construction failure")

    @contextmanager
    def begin(self) -> Iterator[Session]:
        yield self()


def _verifier() -> PrincipalVerifier:
    return PrincipalVerifier(
        trusted_issuer=TrustedIssuerV1(
            issuer="omega-test-issuer",
            audience="leviathan-api",
            org_id="synthetic-org",
            project_id="synthetic-project",
            env="test",
            require_mtls=True,
        ),
        key_set=_KeySet(),
        revocations=_Revocations(),
        clock=lambda: datetime.fromtimestamp(_NOW_NS / 1_000_000_000, tz=UTC),
    )


def _config(
    ports: _Ports,
    *,
    omega_policy: object = _MISSING,
    adapter_verifier: object = _MISSING,
    pinned_certificates: object = _MISSING,
    capability_manifest_hash: object = _MISSING,
    task_store: object = _MISSING,
    close_resources: Callable[[], None] | None = None,
) -> omega_runtime_factory.OmegaTasksConfig:
    policy = cast(
        OmegaPolicyV1,
        OmegaPolicyV1(version="1", max_heartbeat_age_ns=10_000_000_000)
        if omega_policy is _MISSING
        else omega_policy,
    )
    cleanup = close_resources or (lambda: None)
    if task_store is _MISSING:
        temporary_directory = TemporaryDirectory()
        engine, sessions = create_sync_engine_and_sessionmaker(
            f"sqlite:///{Path(temporary_directory.name) / 'omega.db'}"
        )
        init_sync_schema(engine)
        task_store = OmegaDueQueueStore(
            sessions,
            key=LedgerIntegrityKey(b"omega-runtime-factory-synthetic-key-32bytes"),
        )

        def cleanup_store_and_resources(
            cleanup_callback: Callable[[], None] = cleanup,
        ) -> None:
            try:
                cleanup_callback()
            finally:
                engine.dispose()
                temporary_directory.cleanup()

        cleanup = cleanup_store_and_resources
    return omega_runtime_factory.OmegaTasksConfig(
        bridge_health_port=cast(BridgeHealthPort, ports),
        session_verifier=cast(SessionVerifierPort, ports),
        manifest_port=cast(ManifestPort, ports),
        mcp_authorizer=cast(MCPAuthorizerPort, ports),
        task_store=cast(OmegaDueQueueStore, task_store),
        audit_sink=cast(AuditSinkPort, ports),
        event_outbox=cast(EventOutboxPort, ports),
        rate_limiter=cast(RateLimiterPort, ports),
        model_policy=cast(ModelPolicyPort, ports),
        omega_policy=policy,
        clock=lambda: _NOW_NS,
        adapter_verifier=cast(
            PrincipalVerifier, _verifier() if adapter_verifier is _MISSING else adapter_verifier
        ),
        pinned_certificates=cast(
            dict[str, str],
            {hashlib.sha256(_CERTIFICATE).hexdigest(): _PEER_SYSTEM}
            if pinned_certificates is _MISSING
            else pinned_certificates,
        ),
        nonce_store=InMemoryOmegaNonceStore(),
        adapter_clock_ns=lambda: _NOW_NS,
        response_signer=lambda payload: hashlib.sha256(payload).hexdigest(),
        denial_auditor=lambda code: None,
        capability_manifest_hash=cast(
            str,
            "a" * 64 if capability_manifest_hash is _MISSING else capability_manifest_hash,
        ),
        close_resources=cleanup,
    )


def test_build_binding_uses_existing_router_and_closes_resources_once() -> None:
    ports = _Ports()
    policy = OmegaPolicyV1(version="1", max_heartbeat_age_ns=10_000_000_000)
    close_calls: list[str] = []
    config = _config(
        ports,
        omega_policy=policy,
        close_resources=lambda: close_calls.append("closed"),
    )
    binding = omega_runtime_factory.build_omega_tasks(config)

    assert binding.router is omega_tasks.router
    assert binding.runtime.omega_policy is policy
    assert binding.adapter.__class__ is OmegaHeartbeatAdapterV1
    assert binding.runtime.task_store is config.task_store
    assert type(binding.runtime.task_store) is OmegaDueQueueStore
    binding.close()
    binding.close()
    assert close_calls == ["closed"]


@pytest.mark.parametrize(
    ("adapter_verifier", "pinned_certificates", "capability_manifest_hash", "store_is_valid"),
    [
        (None, _MISSING, _MISSING, True),
        (_MISSING, {}, _MISSING, True),
        (_MISSING, _MISSING, "invalid", True),
        (_MISSING, _MISSING, _MISSING, False),
    ],
)
def test_invalid_configuration_fails_closed_and_releases_resources(
    adapter_verifier: object,
    pinned_certificates: object,
    capability_manifest_hash: object,
    store_is_valid: bool,
) -> None:
    ports = _Ports()
    close_calls: list[str] = []
    config = _config(
        ports,
        adapter_verifier=adapter_verifier,
        pinned_certificates=pinned_certificates,
        capability_manifest_hash=capability_manifest_hash,
        task_store=_MISSING if store_is_valid else ports,
        close_resources=lambda: close_calls.append("closed"),
    )

    with pytest.raises(TaskBridgeError) as caught:
        omega_runtime_factory.build_omega_tasks(config)

    assert caught.value.code == "NOT_CONFIGURED"
    assert str(caught.value) == "NOT_CONFIGURED"
    assert caught.value.status_code == 503
    assert close_calls == ["closed"]


def test_invalid_policy_fails_closed_and_releases_resources() -> None:
    ports = _Ports()
    close_calls: list[str] = []
    config = _config(
        ports,
        omega_policy=None,
        close_resources=lambda: close_calls.append("closed"),
    )

    with pytest.raises(TaskBridgeError) as caught:
        omega_runtime_factory.build_omega_tasks(config)

    assert caught.value.code == "NOT_CONFIGURED"
    assert caught.value.status_code == 503
    assert close_calls == ["closed"]


def test_uninitialized_concrete_store_fails_closed_before_binding() -> None:
    ports = _Ports()
    close_calls: list[str] = []
    uninitialized_store = object.__new__(OmegaDueQueueStore)
    config = _config(
        ports,
        task_store=uninitialized_store,
        close_resources=lambda: close_calls.append("closed"),
    )

    with pytest.raises(TaskBridgeError) as caught:
        omega_runtime_factory.build_omega_tasks(config)

    assert caught.value.code == "NOT_CONFIGURED"
    assert caught.value.status_code == 503
    assert caught.value.__suppress_context__ is True
    assert close_calls == ["closed"]


def test_store_session_factory_failure_fails_closed_before_binding() -> None:
    ports = _Ports()
    close_calls: list[str] = []
    failing_store = OmegaDueQueueStore(
        cast(sessionmaker[Session], _RaisingSessionFactory()),
        key=LedgerIntegrityKey(b"omega-runtime-factory-synthetic-key-32bytes"),
    )
    config = _config(
        ports,
        task_store=failing_store,
        close_resources=lambda: close_calls.append("closed"),
    )

    with pytest.raises(TaskBridgeError) as caught:
        omega_runtime_factory.build_omega_tasks(config)

    assert caught.value.code == "NOT_CONFIGURED"
    assert caught.value.status_code == 503
    assert caught.value.__suppress_context__ is True
    assert close_calls == ["closed"]


def test_no_store_is_set_on_success_client_error_service_error_and_method_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ports = _Ports()
    config = _config(ports)
    binding = omega_runtime_factory.build_omega_tasks(config)
    peer = SimpleNamespace(peer_system=_PEER_SYSTEM)
    session = SimpleNamespace(session_id="session-alpha", scopes=("task:audit.read",))
    manifest = SimpleNamespace(rate_limit_rps=10, rate_limit_burst=10)

    def authenticate(request: Request, runtime: OmegaTaskRuntime) -> tuple[object, ...]:
        request.state.omega_audit_context = (runtime, peer, session, "trace", _NOW_NS)
        request.state.omega_audit_task_id = None
        request.state.omega_audit_tool_id = None
        return peer, session, manifest, object(), _NOW_NS, "trace"

    monkeypatch.setattr(omega_tasks, "_authenticate", authenticate)
    monkeypatch.setattr(omega_tasks, "_require_bridge", lambda *args: None)
    monkeypatch.setattr(omega_tasks, "_rate", lambda *args: None)
    monkeypatch.setattr(omega_tasks, "_audit", lambda *args, **kwargs: "audit-id")

    original_list_due_for_peer = OmegaDueQueueStore.list_due_for_peer

    def list_due_for_peer(
        store: OmegaDueQueueStore,
        *,
        peer_system: str,
        now_ns: int,
        limit: int,
    ) -> tuple[object, ...]:
        if ports.fail_due:
            raise RuntimeError("synthetic store failure")
        return original_list_due_for_peer(
            store, peer_system=peer_system, now_ns=now_ns, limit=limit
        )

    monkeypatch.setattr(OmegaDueQueueStore, "list_due_for_peer", list_due_for_peer)

    app = FastAPI()
    app.state.omega_tasks = binding.runtime
    app.state.omega_adapter = binding.adapter
    app.include_router(binding.router)

    with TestClient(app) as client:
        success = client.get("/v1/omega/tasks/due")
        invalid = client.get("/v1/omega/tasks/due?limit=999999")
        ports.fail_due = True
        unavailable = client.get("/v1/omega/tasks/due")
        trace = client.request("TRACE", "/v1/omega/tasks/due")
        propfind = client.request("PROPFIND", "/v1/omega/tasks/due")

    assert success.status_code == 200
    assert invalid.status_code == 422
    assert unavailable.status_code == 503
    assert trace.status_code == 405
    assert propfind.status_code == 405
    assert all(
        response.headers.get("cache-control") == "no-store"
        for response in (success, invalid, unavailable, trace, propfind)
    )
    binding.close()
