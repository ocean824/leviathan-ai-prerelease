"""Independent acceptance for the instance-scoped OMEGA runtime factory."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from leviathan_store.engine import create_sync_engine_and_sessionmaker, init_sync_schema
from leviathan_store.omega_due_queue import OmegaDueQueueStore
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

import leviathan_api.omega_runtime_factory as runtime_factory
from leviathan_api.routers import omega_tasks
from leviathan_core.agent_council.model_policy import (
    AgentModelPolicyV1,
    AIRequestV1,
    RouteUsageV1,
    ScopePrivacyV1,
)
from leviathan_core.agent_council.model_registry import (
    ModelCapabilityV1,
    ModelRegistryEntryV1,
    ModelRegistryV1,
)
from leviathan_core.agent_council.model_router import route_model
from leviathan_core.execution.order_models import LedgerIntegrityKey
from leviathan_core.mcp_control.policy_models import PolicyDecisionV1
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
    TaskRecordV1,
    issue_task_create_result,
    require_task_record,
)
from leviathan_core.security.authz_models import AuthorizationDecisionV1
from leviathan_core.security.principal_verifier import (
    PrincipalVerifier,
    RSAPublicKeyV1,
    TrustedIssuerV1,
)

_ROOT = Path(__file__).resolve().parents[3]
_NOW_NS = 1_800_000_000_000_000_000
_CERTIFICATE = b"synthetic acceptance certificate"
_PEER = "peer.acceptance"
_MISSING = object()
_RSA_FIXTURE = json.loads(
    (_ROOT / "packages/leviathan-core/tests/security/fixtures/sec003_synthetic_rsa.json").read_text(
        encoding="utf-8"
    )
)


class _KeySet:
    def get_key(self, issuer: str, kid: str) -> RSAPublicKeyV1 | None:
        if (issuer, kid) != ("acceptance-issuer", "acceptance-key"):
            return None
        return RSAPublicKeyV1(
            int(_RSA_FIXTURE["modulus_hex"], 16),
            int(_RSA_FIXTURE["public_exponent_hex"], 16),
        )


class _Revocations:
    def is_revoked(self, _issuer: str, _jti: str) -> bool:
        return False


class _RaisingSessionFactory:
    def __call__(self) -> Session:
        raise RuntimeError("synthetic session construction failure")

    @contextmanager
    def begin(self) -> Iterator[Session]:
        yield self()


class _Ports:
    """Synthetic protocol ports; no provider or network operation exists."""

    def __init__(self) -> None:
        self.due_calls: list[dict[str, object]] = []
        self.fail_due = False
        self.records: dict[tuple[str, str], TaskRecordV1] = {}

    def snapshot(self, _peer_system: str) -> object:
        return object()

    def verify(self, *_args: object, **_kwargs: object) -> object:
        return object()

    def get_manifest(self, _peer_system: str) -> object:
        return object()

    def authorize_tool(self, **_kwargs: object) -> object:
        return object()

    def create(self, **_kwargs: object) -> object:
        peer_system = cast(str, _kwargs["peer_system"])
        record = require_task_record(_kwargs["record"])
        self.records[(peer_system, record.task.task_id)] = record
        return issue_task_create_result(disposition="created", record=record)

    def get_task(self, _peer_system: str, _task_id: str) -> None:
        return None

    def replace_task(self, **_kwargs: object) -> bool:
        return False

    def list_due(self, *, now_ns: int, limit: int) -> tuple[()]:
        del now_ns, limit
        return ()

    def list_due_for_peer(
        self, *, peer_system: str, now_ns: int, limit: int
    ) -> tuple[TaskRecordV1, ...]:
        self.due_calls.append({"peer_system": peer_system, "now_ns": now_ns, "limit": limit})
        if self.fail_due:
            raise RuntimeError("synthetic private store detail")
        records = tuple(
            record
            for (record_peer, _task_id), record in self.records.items()
            if record_peer == peer_system and record.task.expires_at_ns <= now_ns
        )
        ordered = sorted(
            records, key=lambda record: (record.task.expires_at_ns, record.task.task_id)
        )
        return tuple(ordered[:limit])

    def append(self, _entry: object) -> object:
        return object()

    def read(self, **_kwargs: object) -> tuple[()]:
        return ()

    def enqueue(self, _event: object) -> None:
        return None

    def consume(self, *_args: object, **_kwargs: object) -> object:
        return object()

    def route_task(self, **_kwargs: object) -> object:
        return _route_result(
            task_type=cast(str, _kwargs["task_type"]),
            agent_id=cast(str, _kwargs["agent_id"]),
            tools=cast(tuple[str, ...], _kwargs["tool_allowlist"]),
            now_ns=cast(int, _kwargs["now_ns"]),
        )


def _route_result(*, task_type: str, agent_id: str, tools: tuple[str, ...], now_ns: int) -> object:
    selected_tools = tuple(tools) or ("research.read",)
    request_value = AIRequestV1(
        request_id=f"route.{task_type}",
        agent_id=agent_id,
        project_id="leviathan-ai",
        environment="development",
        alias="analyst",
        task_type=task_type,
        data_scope="research",
        modality="text",
        output_schema="answer@v1",
        required_tools=selected_tools,
        input_tokens=4,
        output_tokens=8,
        min_quality_class="standard",
        privacy_class="internal",
        max_latency_class="low",
        prompt_version="v1",
        at_ns=now_ns,
        region="us-test",
    )
    policy = AgentModelPolicyV1(
        version="v1",
        agent_id=agent_id,
        project_id="leviathan-ai",
        environment="development",
        allowed_aliases=("analyst",),
        allowed_providers=("gpt",),
        allowed_tools=selected_tools,
        allowed_data_scopes=("research",),
        scope_privacy_classes=(ScopePrivacyV1(scope="research", min_privacy_class="internal"),),
        allowed_output_schemas=("answer@v1",),
        allowed_regions=("us-test",),
        fallback_aliases=(),
        min_quality_class="standard",
        min_privacy_class="internal",
        max_latency_class="medium",
        max_cost_class="medium",
        max_context_tokens=1_000,
        max_calls=2,
        max_tokens=100,
        max_elapsed_ns=10_000_000,
        max_cost_usd=Decimal("0.01"),
        max_attempts=1,
    )
    capability = ModelCapabilityV1(
        modalities=("text",),
        tools=selected_tools,
        output_schemas=("answer@v1",),
        structured_output=True,
        max_context_tokens=1_000,
        max_output_tokens=100,
        quality_class="advanced",
        privacy_class="restricted",
    )
    entry = ModelRegistryEntryV1(
        entry_id="entry.synthetic",
        alias="analyst",
        provider="gpt",
        model_id="gpt.synthetic",
        model_version="v1",
        registry_version="v1",
        capability=capability,
        supported_regions=("us-test",),
        approved=True,
        available=True,
        available_from_ns=1,
        available_until_ns=9_000_000_000_000_000_000,
        credential_name="SYNTHETIC_KEY",
        input_cost_per_million_tokens_usd=Decimal("1"),
        output_cost_per_million_tokens_usd=Decimal("1"),
        cost_class="low",
        latency_class="low",
        latency_reservation_ns=1_000,
    )
    registry = ModelRegistryV1(version="v1", entries=(entry,))

    class _Trust:
        def principal_decision(self, _request: AIRequestV1) -> AuthorizationDecisionV1:
            from leviathan_core.security.authz_models import (
                AuthorizationExplanationV1,
                EffectV1,
                ReasonCodeV1,
            )

            return AuthorizationDecisionV1(
                AuthorizationExplanationV1(
                    rule_id=None, decision=EffectV1.ALLOW, reason_code=ReasonCodeV1.AUTHORIZED
                )
            )

        def tool_decision(self, _request: AIRequestV1, _tool_name: str) -> PolicyDecisionV1:
            return PolicyDecisionV1(
                allowed=True, effect_allowed=False, status="approved", reason_codes=("ALLOW",)
            )

        def usage_is_verified(self, _request: AIRequestV1, _usage: RouteUsageV1) -> bool:
            return True

        def evaluation_time_ns(self, _request: AIRequestV1) -> int:
            return now_ns

        def credential_is_bound(self, _request: AIRequestV1, _credential_ref: str) -> bool:
            return True

    return route_model(
        request_value,
        policy,
        registry,
        RouteUsageV1(
            snapshot_revision=1,
            calls_used=0,
            tokens_used=0,
            elapsed_ns=0,
            cost_spent_usd=Decimal("0"),
        ),
        _Trust(),
    )


def _verifier() -> PrincipalVerifier:
    return PrincipalVerifier(
        trusted_issuer=TrustedIssuerV1(
            issuer="acceptance-issuer",
            audience="leviathan-api",
            org_id="synthetic-org",
            project_id="leviathan-ai",
            env="test",
            require_mtls=True,
        ),
        key_set=_KeySet(),
        revocations=_Revocations(),
        clock=lambda: datetime.fromtimestamp(_NOW_NS / 1_000_000_000, tz=UTC),
    )


def _real_store(tmp_path: Path) -> tuple[OmegaDueQueueStore, Engine]:
    engine, sessions = create_sync_engine_and_sessionmaker(
        f"sqlite:///{(tmp_path / 'omega-runtime-acceptance.sqlite3').as_posix()}"
    )
    init_sync_schema(engine)
    store = OmegaDueQueueStore(
        sessions, key=LedgerIntegrityKey(b"omega-runtime-acceptance-integrity-key-32")
    )
    return store, engine


def _config(
    ports: _Ports,
    *,
    task_store: object,
    policy: object = _MISSING,
    adapter_verifier: object = _MISSING,
    pinned_certificates: object = _MISSING,
    capability_manifest_hash: object = _MISSING,
    close_resources: Callable[[], None] | None = None,
) -> runtime_factory.OmegaTasksConfig:
    actual_policy = cast(
        OmegaPolicyV1,
        OmegaPolicyV1(version="1", max_heartbeat_age_ns=10_000_000_000)
        if policy is _MISSING
        else policy,
    )
    return runtime_factory.OmegaTasksConfig(
        bridge_health_port=cast(BridgeHealthPort, ports),
        session_verifier=cast(SessionVerifierPort, ports),
        manifest_port=cast(ManifestPort, ports),
        mcp_authorizer=cast(MCPAuthorizerPort, ports),
        task_store=cast(OmegaDueQueueStore, task_store),
        audit_sink=cast(AuditSinkPort, ports),
        event_outbox=cast(EventOutboxPort, ports),
        rate_limiter=cast(RateLimiterPort, ports),
        model_policy=cast(ModelPolicyPort, ports),
        omega_policy=actual_policy,
        clock=lambda: _NOW_NS,
        adapter_verifier=cast(
            PrincipalVerifier, _verifier() if adapter_verifier is _MISSING else adapter_verifier
        ),
        pinned_certificates=cast(
            dict[str, str],
            {hashlib.sha256(_CERTIFICATE).hexdigest(): _PEER}
            if pinned_certificates is _MISSING
            else pinned_certificates,
        ),
        nonce_store=InMemoryOmegaNonceStore(),
        adapter_clock_ns=lambda: _NOW_NS,
        response_signer=lambda payload: hashlib.sha256(payload).hexdigest(),
        denial_auditor=lambda _code: None,
        capability_manifest_hash=cast(
            str, "a" * 64 if capability_manifest_hash is _MISSING else capability_manifest_hash
        ),
        close_resources=close_resources or (lambda: None),
    )


def _assert_not_configured(error: TaskBridgeError) -> None:
    assert error.code == "NOT_CONFIGURED"
    assert str(error) == "NOT_CONFIGURED"
    assert error.args == ("NOT_CONFIGURED",)


def test_factory_returns_existing_router_and_closes_resources_once(tmp_path: Path) -> None:
    ports = _Ports()
    store, engine = _real_store(tmp_path)
    policy = OmegaPolicyV1(version="1", max_heartbeat_age_ns=10_000_000_000)
    closed: list[str] = []

    def close_resources() -> None:
        closed.append("close")
        engine.dispose()

    config = _config(
        ports,
        task_store=store,
        policy=policy,
        close_resources=close_resources,
    )
    binding = runtime_factory.build_omega_tasks(config)

    assert binding.router is omega_tasks.router
    assert binding.runtime.omega_policy is policy
    assert type(binding.adapter) is OmegaHeartbeatAdapterV1
    assert binding.runtime.task_store is store

    binding.close()
    binding.close()
    assert closed == ["close"]


@pytest.mark.parametrize(
    ("policy", "adapter_verifier", "pinned_certificates", "capability_manifest_hash"),
    [
        (None, _MISSING, _MISSING, _MISSING),
        (object(), _MISSING, _MISSING, _MISSING),
        (_MISSING, None, _MISSING, _MISSING),
        (_MISSING, _MISSING, {}, _MISSING),
        (_MISSING, _MISSING, _MISSING, "invalid"),
    ],
)
def test_invalid_adapter_dependencies_fail_before_binding_and_release_resources(
    tmp_path: Path,
    policy: object,
    adapter_verifier: object,
    pinned_certificates: object,
    capability_manifest_hash: object,
) -> None:
    ports = _Ports()
    store, engine = _real_store(tmp_path)
    closed: list[str] = []

    def close_resources() -> None:
        closed.append("close")
        engine.dispose()

    config = _config(
        ports,
        task_store=store,
        policy=policy,
        adapter_verifier=adapter_verifier,
        pinned_certificates=pinned_certificates,
        capability_manifest_hash=capability_manifest_hash,
        close_resources=close_resources,
    )

    with pytest.raises(TaskBridgeError) as rejected:
        runtime_factory.build_omega_tasks(config)

    _assert_not_configured(rejected.value)
    assert closed == ["close"]


def test_duck_typed_unkeyed_store_is_rejected_before_binding(tmp_path: Path) -> None:
    ports = _Ports()
    _store, engine = _real_store(tmp_path)
    closed: list[str] = []

    def close_resources() -> None:
        closed.append("close")
        engine.dispose()

    config = _config(
        ports,
        task_store=cast(OmegaDueQueueStore, ports),
        close_resources=close_resources,
    )

    with pytest.raises(TaskBridgeError) as rejected:
        runtime_factory.build_omega_tasks(config)

    _assert_not_configured(rejected.value)
    assert closed == ["close"]


def test_uninitialized_concrete_store_is_rejected_before_binding() -> None:
    ports = _Ports()
    closed: list[str] = []
    uninitialized_store = object.__new__(OmegaDueQueueStore)
    config = _config(
        ports,
        task_store=uninitialized_store,
        close_resources=lambda: closed.append("close"),
    )

    with pytest.raises(TaskBridgeError) as rejected:
        runtime_factory.build_omega_tasks(config)

    _assert_not_configured(rejected.value)
    assert closed == ["close"]


def test_store_session_factory_failure_is_rejected_before_binding() -> None:
    ports = _Ports()
    closed: list[str] = []
    store = OmegaDueQueueStore(
        cast(sessionmaker[Session], _RaisingSessionFactory()),
        key=LedgerIntegrityKey(b"omega-runtime-acceptance-integrity-key-32"),
    )
    config = _config(
        ports,
        task_store=store,
        close_resources=lambda: closed.append("close"),
    )

    with pytest.raises(TaskBridgeError) as rejected:
        runtime_factory.build_omega_tasks(config)

    _assert_not_configured(rejected.value)
    assert closed == ["close"]


def test_mounted_app_creates_and_reads_fake_task_with_peer_scope(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    ports = _Ports()
    store, engine = _real_store(tmp_path)
    policy = OmegaPolicyV1(version="1", max_heartbeat_age_ns=10_000_000_000)
    binding = runtime_factory.build_omega_tasks(
        _config(ports, task_store=store, policy=policy, close_resources=engine.dispose)
    )
    now_ns = [_NOW_NS]
    peer_system = [_PEER]
    due_queries: list[dict[str, object]] = []
    original_due_query = OmegaDueQueueStore.list_due_for_peer

    def trace_due_query(
        self: OmegaDueQueueStore, *, peer_system: str, now_ns: int, limit: int
    ) -> tuple[TaskRecordV1, ...]:
        due_queries.append({"peer_system": peer_system, "now_ns": now_ns, "limit": limit})
        return original_due_query(self, peer_system=peer_system, now_ns=now_ns, limit=limit)

    monkeypatch.setattr(OmegaDueQueueStore, "list_due_for_peer", trace_due_query)
    session = SimpleNamespace(
        session_id="session.synthetic",
        agent_id="agent.creator",
        scopes=("task:handoff", "task:audit.read", "tool:use.research.read"),
    )
    manifest = SimpleNamespace(tools=("research.read",))

    def authenticate(request: Request, runtime: OmegaTaskRuntime) -> tuple[object, ...]:
        active_peer = SimpleNamespace(peer_system=peer_system[0])
        request.state.omega_audit_context = (
            runtime,
            active_peer,
            session,
            "trace.synthetic",
            now_ns[0],
        )
        request.state.omega_audit_task_id = None
        request.state.omega_audit_tool_id = None
        request.state.omega_audit_body_hash = None
        return active_peer, session, manifest, object(), now_ns[0], "trace.synthetic"

    monkeypatch.setattr(omega_tasks, "_authenticate", authenticate)
    monkeypatch.setattr(omega_tasks, "_require_bridge", lambda *_args: None)
    monkeypatch.setattr(omega_tasks, "_rate", lambda *_args: None)
    monkeypatch.setattr(omega_tasks, "_audit", lambda *_args, **_kwargs: "audit.synthetic")

    app = FastAPI()
    app.state.omega_tasks = binding.runtime
    app.state.omega_adapter = binding.adapter
    app.include_router(binding.router)

    try:
        with TestClient(app) as client:
            created = client.post(
                "/v1/omega/tasks/handoff",
                headers={"idempotency-key": "acceptance-task-001"},
                json={
                    "type": "analysis",
                    "priority": "normal",
                    "assigned_to": "agent.worker",
                    "ttl_ms": 1_000,
                    "sla_ms": 1_000,
                    "context": {"question": "Synthetic question", "max_tokens": 8},
                    "tool_allowlist": ["research.read"],
                },
            )
            assert created.status_code == 202, created.text
            task_id = created.json()["task_id"]
            stored = store.get_task(_PEER, task_id)
            assert stored is not None
            assert stored.task.task_id == task_id

            # Advance only the synthetic request clock so this task is due.
            now_ns[0] += 1_000_000_001
            read_back = client.get("/v1/omega/tasks/due")
            assert read_back.status_code == 200
            assert read_back.json()["peer_system"] == _PEER
            assert [item["task_id"] for item in read_back.json()["items"]] == [task_id]

            # A different authenticated peer receives no records from the fake store.
            peer_system[0] = "peer.other"
            other_peer_read = client.get("/v1/omega/tasks/due")
            assert other_peer_read.status_code == 200
            assert other_peer_read.json()["items"] == []
            assert store.get_task("peer.other", task_id) is None
    finally:
        binding.close()

    assert [call["peer_system"] for call in due_queries] == [_PEER, "peer.other"]
    assert all(call["limit"] == 101 for call in due_queries)


def test_coordinator_mount_has_no_store_for_success_errors_and_method_mismatch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    ports = _Ports()
    store, engine = _real_store(tmp_path)
    binding = runtime_factory.build_omega_tasks(
        _config(ports, task_store=store, close_resources=engine.dispose)
    )
    peer = SimpleNamespace(peer_system=_PEER)
    session = SimpleNamespace(session_id="session.synthetic", scopes=("task:audit.read",))
    manifest = SimpleNamespace(rate_limit_rps=10, rate_limit_burst=10)

    def authenticate(request: Request, runtime: OmegaTaskRuntime) -> tuple[object, ...]:
        request.state.omega_audit_context = (runtime, peer, session, "trace.synthetic", _NOW_NS)
        request.state.omega_audit_task_id = None
        request.state.omega_audit_tool_id = None
        request.state.omega_audit_body_hash = None
        return peer, session, manifest, object(), _NOW_NS, "trace.synthetic"

    monkeypatch.setattr(omega_tasks, "_authenticate", authenticate)
    monkeypatch.setattr(omega_tasks, "_require_bridge", lambda *_args: None)
    monkeypatch.setattr(omega_tasks, "_rate", lambda *_args: None)
    monkeypatch.setattr(omega_tasks, "_audit", lambda *_args, **_kwargs: "audit.synthetic")
    fail_due = [False]
    due_queries: list[dict[str, object]] = []
    original_due_query = OmegaDueQueueStore.list_due_for_peer

    def maybe_fail_due(
        self: OmegaDueQueueStore, *, peer_system: str, now_ns: int, limit: int
    ) -> tuple[TaskRecordV1, ...]:
        due_queries.append({"peer_system": peer_system, "now_ns": now_ns, "limit": limit})
        if fail_due[0]:
            raise RuntimeError("synthetic store error")
        return original_due_query(self, peer_system=peer_system, now_ns=now_ns, limit=limit)

    monkeypatch.setattr(OmegaDueQueueStore, "list_due_for_peer", maybe_fail_due)

    app = FastAPI()
    # Use the same instance-scoped state seam the coordinator uses.
    app.state.omega_tasks = binding.runtime
    app.state.omega_adapter = binding.adapter
    app.include_router(binding.router)

    try:
        with TestClient(app) as client:
            success = client.get("/v1/omega/tasks/due")
            invalid = client.get("/v1/omega/tasks/due?limit=999999")
            fail_due[0] = True
            unavailable = client.get("/v1/omega/tasks/due")
            method_not_allowed = client.post("/v1/omega/tasks/due")
            trace = client.request("TRACE", "/v1/omega/tasks/due")
            propfind = client.request("PROPFIND", "/v1/omega/tasks/due")
    finally:
        binding.close()

    assert success.status_code == 200
    assert invalid.status_code == 422
    assert unavailable.status_code == 503
    assert method_not_allowed.status_code == 405
    assert trace.status_code == 405
    assert propfind.status_code == 405
    for response in (success, invalid, unavailable, method_not_allowed, trace, propfind):
        assert response.headers.get("cache-control") == "no-store"
        assert "synthetic private store detail" not in response.text
    assert [call["peer_system"] for call in due_queries] == [_PEER, _PEER]
    assert all(call["limit"] == 101 for call in due_queries)
