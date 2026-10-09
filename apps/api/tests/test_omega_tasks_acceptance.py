"""Independent OMEGA-003 acceptance using synthetic authority ports only.

Requirement-to-case matrix includes route authentication/authorization, bounded task
lifetime and UTF-8 context handling; closed analysis/research context schemas and all
reviewer credential shapes; content-free refusal audits with known task/tool IDs; distinct
idempotency-conflict events; and trusted-clock bounded, idempotent expiry emission.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from leviathan_api.routers.omega_tasks import router
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
from leviathan_core.mcp_control.policy_models import PolicyDecisionV1
from leviathan_core.omega_link.heartbeat_adapter import (
    InMemoryOmegaNonceStore,
    OmegaHeartbeatAdapterV1,
)
from leviathan_core.omega_link.state_models import (
    AgentSessionV1,
    BridgeHealthV1,
    CapabilityManifestV1,
    OmegaPolicyV1,
)
from leviathan_core.omega_link.state_models import (
    _from_trusted_adapter as issue_agent_session,
)
from leviathan_core.omega_link.task_bridge import (
    IDEMPOTENCY_RETENTION_NS,
    OMEGA_TASK_TYPES_V1,
    TaskAuditRecordV1,
    TaskCreateResultV1,
    TaskLifecycleEventV1,
    TaskRateDecisionV1,
    TaskRecordV1,
    issue_task_audit_entry,
    issue_task_audit_receipt,
    issue_task_audit_record,
    issue_task_create_result,
    issue_task_rate_decision,
    require_task_audit_entry,
    require_task_lifecycle_event,
    require_task_record,
)
from leviathan_core.security.principal_verifier import (
    PrincipalVerifier,
    RSAPublicKeyV1,
    TrustedIssuerV1,
)

ROOT = Path(__file__).resolve().parents[3]
_RSA_FIXTURE = json.loads(
    (ROOT / "packages/leviathan-core/tests/security/fixtures/sec003_synthetic_rsa.json").read_text(
        encoding="utf-8"
    )
)
_PUBLIC_N = int(_RSA_FIXTURE["modulus_hex"], 16)
_PUBLIC_E = int(_RSA_FIXTURE["public_exponent_hex"], 16)
_PRIVATE_D = int(_RSA_FIXTURE["private_exponent_hex"], 16)
_PUBLIC_KEY = RSAPublicKeyV1(_PUBLIC_N, _PUBLIC_E)
_ISSUER = "omega-idp"
_AUDIENCE = "leviathan-backend"
_ORG = "org-omega"
_PROJECT = "leviathan-ai"
_ENV = "test"
_KID = "omega-synthetic-key"
_PEER = "omega-peer-test"
_CERT = b"synthetic OMEGA task bridge TLS certificate DER"
_CERT_PIN = hashlib.sha256(_CERT).hexdigest()
_CREATOR_SESSION = "session-creator"
_WORKER_SESSION = "session-worker"
_CREATOR = "agent.creator"
_WORKER = "agent.worker"
_TASK_TOOL = "research.read"
_OTHER_TOOL = "risk.inspect"
_FINANCIAL_TOOL = "order.place.sim"


class _KeySet:
    def get_key(self, issuer: str, kid: str) -> RSAPublicKeyV1 | None:
        return _PUBLIC_KEY if (issuer, kid) == (_ISSUER, _KID) else None


class _Revocations:
    def is_revoked(self, issuer: str, jti: str) -> bool:
        return False


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _segment(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return _b64url(encoded)


def _signature(message: bytes) -> bytes:
    digest_info = (
        bytes.fromhex("3031300d060960864801650304020105000420") + hashlib.sha256(message).digest()
    )
    width = (_PUBLIC_N.bit_length() + 7) // 8
    padding_length = width - len(digest_info) - 3
    encoded = b"\x00\x01" + b"\xff" * padding_length + b"\x00" + digest_info
    return pow(int.from_bytes(encoded, "big"), _PRIVATE_D, _PUBLIC_N).to_bytes(width, "big")


def _token(now_ns: int, nonce: str, *, scope: str = "omega:task") -> str:
    now_seconds = now_ns // 1_000_000_000
    header = _segment({"alg": "RS256", "kid": _KID, "typ": "JWT"})
    claims = _segment(
        {
            "iss": _ISSUER,
            "aud": _AUDIENCE,
            "org": _ORG,
            "sub": _PEER,
            "role": "bridge-peer",
            "scope": [scope],
            "env": _ENV,
            "jti": nonce,
            "iat": now_seconds,
            "nbf": now_seconds,
            "exp": now_seconds + 240,
            "cnf": {"x5t#S256": _b64url(hashlib.sha256(_CERT).digest())},
        }
    )
    signing_input = f"{header}.{claims}".encode("ascii")
    return f"{signing_input.decode('ascii')}.{_b64url(_signature(signing_input))}"


def _verifier(now: list[int]) -> PrincipalVerifier:
    return PrincipalVerifier(
        trusted_issuer=TrustedIssuerV1(
            issuer=_ISSUER,
            audience=_AUDIENCE,
            org_id=_ORG,
            project_id=_PROJECT,
            env=_ENV,
            require_mtls=True,
        ),
        key_set=_KeySet(),
        revocations=_Revocations(),
        clock=lambda: datetime.fromtimestamp(now[0] / 1_000_000_000, tz=UTC),
    )


def _manifest() -> CapabilityManifestV1:
    return CapabilityManifestV1(
        version="1",
        tools=(_TASK_TOOL, _OTHER_TOOL, _FINANCIAL_TOOL),
        datasets=("market.synthetic", "private.dataset"),
        actions=("research", "orders"),
        limits=(("rate_burst", 100), ("rate_rps", 50)),
        financial_tools=(_FINANCIAL_TOOL,),
    )


def _session(
    *, session_id: str, agent_id: str, now_ns: int, manifest: CapabilityManifestV1
) -> AgentSessionV1:
    return issue_agent_session(
        session=AgentSessionV1(
            version="1",
            session_id=session_id,
            peer_system=_PEER,
            agent_id=agent_id,
            scopes=(
                "omega:task",
                "task:handoff",
                "task:accept",
                "task:update",
                "task:cancel",
                "task:manifest.read",
                "task:audit.read",
                f"tool:use.{_TASK_TOOL}",
                f"tool:use.{_OTHER_TOOL}",
            ),
            manifest_hash=manifest.manifest_hash,
            status="active",
            issued_at_ns=now_ns - 1_000_000,
            expires_at_ns=now_ns + 240_000_000_000,
            action_budget=100,
        )
    )


class _BridgeHealth:
    def __init__(self, clock: list[int], age_ns: int) -> None:
        self.clock = clock
        self.age_ns = age_ns
        self.offline = False
        self.halted = False
        self.peer_killed = False

    def snapshot(self, peer_system: str) -> BridgeHealthV1:
        now = self.clock[0]
        return BridgeHealthV1(
            version="1",
            peer_system=peer_system,
            transport_verified=True,
            heartbeat_at_ns=now - self.age_ns - 1 if self.offline else now,
            heartbeat_expires_ns=now + 240_000_000_000,
            degraded=self.offline,
            peer_kill_pending=False,
            peer_killed=self.peer_killed,
            halt_reasons=("risk_halt",) if self.halted else (),
            halt_version=1 if self.halted else 0,
        )


class _Sessions:
    def __init__(self, entries: dict[str, AgentSessionV1]) -> None:
        self.entries = entries
        self.calls: list[tuple[str, int]] = []

    def verify(self, peer: object, session_id: str, *, now_ns: int) -> AgentSessionV1 | None:
        self.calls.append((session_id, now_ns))
        return self.entries.get(session_id)


class _Manifest:
    def __init__(self, manifest: CapabilityManifestV1) -> None:
        self.value = manifest

    def get_manifest(self, peer_system: str) -> CapabilityManifestV1:
        return self.value


def _route_result(*, task_type: str, agent_id: str, tools: tuple[str, ...], now_ns: int):
    selected_tools = tuple(tools) or (_TASK_TOOL,)
    request_value = AIRequestV1(
        request_id=f"route.{task_type}",
        agent_id=agent_id,
        project_id=_PROJECT,
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
        project_id=_PROJECT,
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

    class Trust:
        def principal_decision(self, request: AIRequestV1):
            from leviathan_core.security.authz_models import (
                AuthorizationDecisionV1,
                AuthorizationExplanationV1,
                EffectV1,
                ReasonCodeV1,
            )

            return AuthorizationDecisionV1(
                AuthorizationExplanationV1(
                    rule_id=None, decision=EffectV1.ALLOW, reason_code=ReasonCodeV1.AUTHORIZED
                )
            )

        def tool_decision(self, request: AIRequestV1, tool_name: str):
            return PolicyDecisionV1(
                allowed=True,
                effect_allowed=False,
                status="approved",
                reason_codes=("SYNTHETIC_ALLOW",),
            )

        def usage_is_verified(self, request: AIRequestV1, usage: RouteUsageV1):
            return True

        def evaluation_time_ns(self, request: AIRequestV1):
            return now_ns

        def credential_is_bound(self, request: AIRequestV1, credential_ref: str):
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
        Trust(),
    )


class _ModelPolicy:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def route_task(self, **kwargs: Any):
        self.calls.append(kwargs)
        return _route_result(
            task_type=kwargs["task_type"],
            agent_id=kwargs["agent_id"],
            tools=kwargs["tool_allowlist"],
            now_ns=kwargs["now_ns"],
        )


class _TaskStore:
    def __init__(self, clock: list[int]) -> None:
        self.clock = clock
        self.records: dict[tuple[str, str], TaskRecordV1] = {}
        self.idempotency: dict[tuple[str, str], tuple[str, int, TaskRecordV1]] = {}
        self.create_calls: list[dict[str, Any]] = []

    def create(self, **kwargs: Any) -> TaskCreateResultV1:
        self.create_calls.append(kwargs)
        peer = kwargs["peer_system"]
        key = kwargs["idempotency_key"]
        digest = kwargs["request_digest"]
        idem_key = (peer, key)
        prior = self.idempotency.get(idem_key)
        if prior is not None and self.clock[0] < prior[1]:
            if prior[0] != digest:
                return issue_task_create_result(disposition="conflict", record=prior[2])
            return issue_task_create_result(disposition="duplicate", record=prior[2])
        record = kwargs["record"]
        require_task_record(record)
        task_key = (peer, record.task.task_id)
        self.records[task_key] = record
        self.idempotency[idem_key] = (digest, kwargs["idempotency_expires_at_ns"], record)
        return issue_task_create_result(disposition="created", record=record)

    def get_task(self, peer_system: str, task_id: str) -> TaskRecordV1 | None:
        return self.records.get((peer_system, task_id))

    def list_due(self, now_ns: int, limit: int) -> tuple[TaskRecordV1, ...]:
        due: list[TaskRecordV1] = []
        for record in self.records.values():
            task = record.task
            if (task.state == "pending" and task.expires_at_ns <= now_ns) or (
                task.state == "in_progress"
                and (
                    task.expires_at_ns <= now_ns
                    or task.created_at_ns + task.sla_ms * 1_000_000 <= now_ns
                )
            ):
                due.append(record)
        due.sort(key=lambda record: (record.task.expires_at_ns, record.task.task_id))
        return tuple(due[:limit])

    def replace_task(self, **kwargs: Any) -> bool:
        key = (kwargs["peer_system"], kwargs["task_id"])
        current = self.records.get(key)
        if current is None or current.revision != kwargs["expected_revision"]:
            return False
        require_task_record(kwargs["record"])
        self.records[key] = kwargs["record"]
        return True


class _Audit:
    def __init__(self) -> None:
        self.records: list[TaskAuditRecordV1] = []

    def append(self, entry: object):
        valid_entry = require_task_audit_entry(entry)
        previous = self.records[-1].receipt.event_hash if self.records else "0" * 64
        sequence = len(self.records)
        event_hash = hashlib.sha256(
            f"{previous}:{valid_entry.trace_id}:{valid_entry.payload_hash}:{sequence}".encode()
        ).hexdigest()
        receipt = issue_task_audit_receipt(
            event_id=f"audit-{sequence}",
            event_hash=event_hash,
            predecessor_hash=previous,
            sequence=sequence,
        )
        self.records.append(issue_task_audit_record(entry=valid_entry, receipt=receipt))
        return receipt

    def read(self, **filters: Any) -> tuple[TaskAuditRecordV1, ...]:
        rows = [
            record for record in self.records if record.entry.peer_system == filters["peer_system"]
        ]
        for key, field in (
            ("trace_id", "trace_id"),
            ("task_id", "task_id"),
            ("agent_session_id", "session_id"),
        ):
            value = filters[key]
            if value is not None:
                rows = [row for row in rows if getattr(row.entry, field) == value]
        if filters["since_ns"] is not None:
            rows = [row for row in rows if row.entry.occurred_at_ns >= filters["since_ns"]]
        if filters["until_ns"] is not None:
            rows = [row for row in rows if row.entry.occurred_at_ns <= filters["until_ns"]]
        return tuple(rows[: filters["limit"]])


class _Outbox:
    def __init__(self) -> None:
        self.events: dict[str, TaskLifecycleEventV1] = {}

    def enqueue(self, event: object) -> None:
        valid = require_task_lifecycle_event(event)
        self.events.setdefault(valid.event_id, valid)


class _RateLimiter:
    def __init__(self) -> None:
        self.calls = 0
        self.deny = False

    def consume(self, peer_system: str, **kwargs: Any) -> TaskRateDecisionV1:
        self.calls += 1
        return issue_task_rate_decision(allowed=not self.deny, retry_after_seconds=3)


class _MCP:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.deny = False

    def authorize_tool(self, **kwargs: Any) -> PolicyDecisionV1:
        self.calls.append(kwargs)
        allowed = not self.deny
        return PolicyDecisionV1(
            allowed=allowed,
            effect_allowed=allowed,
            status="approved" if allowed else "rejected",
            reason_codes=("MCP_SYNTHETIC_ALLOW" if allowed else "MCP_SYNTHETIC_DENY",),
        )


@pytest.fixture
def bridge() -> Any:
    now = [int(datetime(2026, 10, 6, 18, 0, tzinfo=UTC).timestamp()) * 1_000_000_000]
    clock_reads = [0]

    def trusted_clock() -> int:
        clock_reads[0] += 1
        return now[0]

    manifest = _manifest()
    sessions = {
        _CREATOR_SESSION: _session(
            session_id=_CREATOR_SESSION, agent_id=_CREATOR, now_ns=now[0], manifest=manifest
        ),
        _WORKER_SESSION: _session(
            session_id=_WORKER_SESSION, agent_id=_WORKER, now_ns=now[0], manifest=manifest
        ),
    }
    health = _BridgeHealth(now, age_ns=60_000_000_000)
    audit = _Audit()
    outbox = _Outbox()
    store = _TaskStore(now)
    rate = _RateLimiter()
    mcp = _MCP()
    model = _ModelPolicy()
    policy = OmegaPolicyV1(version="1", max_heartbeat_age_ns=60_000_000_000)
    app = FastAPI()
    app.include_router(router)
    certificate: list[bytes | None] = [_CERT]

    @app.middleware("http")
    async def inject_synthetic_tls(request: Request, call_next):
        extensions = dict(request.scope.get("extensions", {}))
        if certificate[0] is None:
            extensions.pop("tls", None)
        else:
            extensions["tls"] = {"client_cert_der": certificate[0]}
        request.scope["extensions"] = extensions
        return await call_next(request)

    def response_signer(payload: bytes) -> str:
        return hashlib.sha256(payload).hexdigest()

    def denial_auditor(code: str) -> None:
        audit.append(
            issue_task_audit_entry(
                trace_id="auth-denial",
                peer_system=_PEER,
                actor_id="bridge-peer",
                session_id=_CREATOR_SESSION,
                task_id=None,
                action="auth_denial",
                reason_code=code,
                payload_hash="0" * 64,
                occurred_at_ns=now[0],
            )
        )

    app.state.omega_adapter = OmegaHeartbeatAdapterV1(
        verifier=_verifier(now),
        pinned_certificates={_CERT_PIN: _PEER},
        nonce_store=InMemoryOmegaNonceStore(),
        clock_ns=lambda: now[0],
        policy=policy,
        response_signer=response_signer,
        capability_manifest_hash=manifest.manifest_hash,
        denial_auditor=denial_auditor,
    )
    from leviathan_core.omega_link.task_bridge import OmegaTaskRuntime

    app.state.omega_tasks = OmegaTaskRuntime(
        bridge_health_port=health,
        session_verifier=_Sessions(sessions),
        manifest_port=_Manifest(manifest),
        mcp_authorizer=mcp,
        task_store=store,
        audit_sink=audit,
        event_outbox=outbox,
        rate_limiter=rate,
        model_policy=model,
        omega_policy=policy,
        clock=trusted_clock,
    )
    with TestClient(app) as client:
        yield SimpleNamespace(
            app=app,
            client=client,
            now=now,
            clock_reads=clock_reads,
            certificate=certificate,
            manifest=manifest,
            health=health,
            audit=audit,
            outbox=outbox,
            store=store,
            rate=rate,
            mcp=mcp,
            model=model,
            sessions=sessions,
            nonce_counter=0,
            adapter=app.state.omega_adapter,
            runtime=app.state.omega_tasks,
        )


def _headers(
    bridge: Any,
    *,
    session_id: str = _CREATOR_SESSION,
    scope: str = "omega:task",
    nonce: str | None = None,
) -> dict[str, str]:
    if nonce is None:
        bridge.nonce_counter += 1
        nonce = f"nonce-{bridge.nonce_counter}-{bridge.now[0]}"
    return {
        "Authorization": f"Bearer {_token(bridge.now[0], nonce, scope=scope)}",
        "x-agent-session-id": session_id,
    }


def _handoff_body(**changes: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "type": "analysis",
        "priority": "normal",
        "assigned_to": _WORKER,
        "ttl_ms": 60_000,
        "sla_ms": 30_000,
        "context": {"question": "synthetic market summary"},
        "tool_allowlist": [_TASK_TOOL],
        "requires_risk_guard": False,
    }
    body.update(changes)
    return body


def _handoff(
    bridge: Any,
    *,
    key: str = "handoff-key-1",
    session_id: str = _CREATOR_SESSION,
    body: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
):
    auth = _headers(bridge, session_id=session_id)
    auth["Idempotency-Key"] = key
    if headers:
        auth.update(headers)
    return bridge.client.post(
        "/v1/omega/tasks/handoff", headers=auth, json=_handoff_body() if body is None else body
    )


def _task_id(response: Any) -> str:
    assert response.status_code in (200, 202), response.text
    return response.json()["task_id"]


def _audit_refusal(
    bridge: Any,
    *,
    since: int,
    reason_code: str,
    task_id: str | None,
    tool_id: str | None,
):
    entries = [record.entry for record in bridge.audit.records[since:]]
    matches = [entry for entry in entries if entry.reason_code == reason_code]
    assert len(matches) == 1
    entry = matches[0]
    assert entry.task_id == task_id
    assert entry.tool_id == tool_id
    return entry


def test_missing_runtime_and_untrusted_tls_header_fail_closed(bridge: Any) -> None:
    del bridge.app.state.omega_tasks
    missing = bridge.client.get("/v1/omega/tools/manifest", headers=_headers(bridge))
    assert missing.status_code == 503
    assert missing.json() == {"detail": "NOT_CONFIGURED"}

    bridge.app.state.omega_tasks = bridge.runtime
    bridge.certificate[0] = None
    forged = bridge.client.get(
        "/v1/omega/tools/manifest",
        headers={**_headers(bridge), "X-Client-Cert": _b64url(_CERT)},
    )
    assert forged.status_code == 401
    assert forged.json()["detail"] == "OMEGA_AUTH_DENIED"


def test_handoff_requires_task_scope_and_verified_session(bridge: Any) -> None:
    wrong_scope = _handoff(
        bridge,
        headers={
            "Authorization": (
                f"Bearer {_token(bridge.now[0], 'wrong-scope', scope='omega:heartbeat')}"
            )
        },
    )
    assert wrong_scope.status_code == 401
    assert wrong_scope.json()["detail"] == "OMEGA_AUTH_DENIED"

    denied_session = _handoff(bridge, headers={"x-agent-session-id": "session-unknown"})
    assert denied_session.status_code == 403
    assert denied_session.json()["detail"] == "SESSION_DENIED"
    assert bridge.store.records == {}

    base = bridge.sessions[_CREATOR_SESSION]
    no_handoff_scope = issue_agent_session(
        session=AgentSessionV1(
            **{
                **base.model_dump(),
                "session_id": "session-no-handoff",
                "scopes": ("omega:task",),
            }
        )
    )
    bridge.sessions[no_handoff_scope.session_id] = no_handoff_scope
    before_scope = len(bridge.audit.records)
    denied_scope = _handoff(
        bridge, key="session-scope-denied", session_id=no_handoff_scope.session_id
    )
    assert denied_scope.status_code == 403
    assert denied_scope.json()["detail"] == "SCOPE_DENIED"
    _audit_refusal(
        bridge,
        since=before_scope,
        reason_code="SCOPE_DENIED",
        task_id=None,
        tool_id=_TASK_TOOL,
    )
    assert bridge.store.records == {}


def test_handoff_duplicate_is_idempotent_and_changed_payload_conflicts(bridge: Any) -> None:
    first = _handoff(bridge, key="same-key")
    assert first.status_code == 202
    assert first.json()["state"] == "pending"
    assert first.json()["created_by"] == _CREATOR
    assert first.json()["assigned_to"] == _WORKER
    assert first.json()["expires_at_ns"] == bridge.now[0] + 60_000_000_000
    task_id = first.json()["task_id"]
    trace_id = first.json()["trace_id"]
    assert task_id and trace_id

    duplicate = _handoff(bridge, key="same-key")
    assert duplicate.status_code == 200
    assert duplicate.json()["task_id"] == task_id
    assert len(bridge.store.records) == 1
    assert len(bridge.outbox.events) == 1

    before_conflict = len(bridge.audit.records)
    conflict = _handoff(bridge, key="same-key", body=_handoff_body(priority="high"))
    assert conflict.status_code == 409
    assert conflict.json()["detail"] == "IDEMPOTENCY_CONFLICT"
    conflict_entry = _audit_refusal(
        bridge,
        since=before_conflict,
        reason_code="IDEMPOTENCY_CONFLICT",
        task_id=task_id,
        tool_id=_TASK_TOOL,
    )
    assert conflict_entry.action == "TASK_HANDOFF_CONFLICT"
    assert conflict_entry.action != "TASK_HANDOFF"
    create_call = bridge.store.create_calls[0]
    assert create_call["idempotency_expires_at_ns"] == bridge.now[0] + IDEMPOTENCY_RETENTION_NS


@pytest.mark.parametrize(
    ("changes", "status", "code"),
    [
        ({"ttl_ms": 999}, 422, "INVALID_TASK_LIFETIME"),
        ({"ttl_ms": 60_000, "sla_ms": 60_001}, 422, "INVALID_TASK_LIFETIME"),
        ({"context": None}, 422, "CONTEXT_REQUIRED"),
        ({"context": {"x": 1}, "blob_id": "blob.synthetic"}, 422, "CONTEXT_REQUIRED"),
        ({"requires_risk_guard": True}, 412, "RISK_GUARD_UNAVAILABLE"),
        ({"tool_allowlist": ["unlisted.tool"]}, 400, "TOOL_DENIED"),
    ],
)
def test_handoff_bounds_scope_and_risk_gate_fail_closed(
    bridge: Any, changes: dict[str, Any], status: int, code: str
) -> None:
    before_refusal = len(bridge.audit.records)
    response = _handoff(bridge, key=f"invalid-{code}", body=_handoff_body(**changes))
    assert response.status_code == status
    assert response.json() == {"detail": code}
    _audit_refusal(
        bridge,
        since=before_refusal,
        reason_code=code,
        task_id=None,
        tool_id=(changes.get("tool_allowlist") or [_TASK_TOOL])[0],
    )
    assert bridge.store.records == {}


def test_question_character_limit_is_content_free(bridge: Any) -> None:
    accepted_context = {"question": "a" * 2_000}
    accepted = _handoff(
        bridge, key="question-at-limit", body=_handoff_body(context=accepted_context)
    )
    assert accepted.status_code == 202

    records_before_refusal = dict(bridge.store.records)
    oversized_question = "b" * 2_001
    refused = _handoff(
        bridge,
        key="question-over-limit",
        body=_handoff_body(context={"question": oversized_question}),
    )
    assert refused.status_code == 422
    assert refused.json() == {"detail": "CONTEXT_SCHEMA_DENIED"}
    assert oversized_question not in refused.text
    assert bridge.store.records == records_before_refusal


@pytest.mark.parametrize(
    ("context", "marker"),
    [
        (
            {"connection": "postgresql://admin:CANARY_DBPASS@db.internal:5432/prod"},
            "CANARY_DBPASS",
        ),
        (
            {"url": "https://api.vendor.example/v1?api_key=CANARY_QS"},
            "CANARY_QS",
        ),
        ({"note": "use sk_live_CANARYKEY0000 for the call"}, "sk_live_CANARYKEY0000"),
        ({"jwt": "eyJhbGciOiJSUzI1NiJ9.CANARY.SIG"}, "CANARY.SIG"),
        ({"pw": "CANARY_PW"}, "CANARY_PW"),
        ({"passwd": "CANARY_PASSWD"}, "CANARY_PASSWD"),
        (
            {"headers": [["Cookie", "session=CANARY_COOKIE"], ["X-Auth", "CANARY_XAUTH"]]},
            "CANARY_COOKIE",
        ),
        ({"pair": {"name": "db_password", "value": "CANARY_PAIR"}}, "CANARY_PAIR"),
    ],
)
def test_reviewer_secret_context_shapes_reject_content_free(
    bridge: Any, context: dict[str, Any], marker: str
) -> None:
    before_refusal = len(bridge.audit.records)
    response = _handoff(bridge, body=_handoff_body(context=context))

    assert response.status_code == 422
    reason_code = response.json()["detail"]
    assert reason_code in {"CONTEXT_SECRET_DENIED", "CONTEXT_SCHEMA_DENIED"}
    assert marker not in response.text
    assert marker not in repr(bridge.audit.records[before_refusal:])
    _audit_refusal(
        bridge,
        since=before_refusal,
        reason_code=reason_code,
        task_id=None,
        tool_id=_TASK_TOOL,
    )
    assert bridge.store.records == {}


@pytest.mark.parametrize(
    ("question", "marker"),
    [
        (
            "postgresql://admin:CANARY_DBPASS@db.internal:5432/prod",
            "CANARY_DBPASS",
        ),
        ("https://api.vendor.example/v1?api_key=CANARY_QS", "CANARY_QS"),
        ("use sk_live_CANARYKEY0000 now", "sk_live_CANARYKEY0000"),
        ("password=CANARY_PASSWORD", "CANARY_PASSWORD"),
        ("passwd=CANARY_PASSWD", "CANARY_PASSWD"),
        ("Cookie: session=CANARY_COOKIE", "CANARY_COOKIE"),
        ("Set-Cookie: session=CANARY_COOKIE", "CANARY_COOKIE"),
        ("Authorization: Bearer CANARY_AUTH_VALUE", "CANARY_AUTH_VALUE"),
    ],
)
def test_free_text_question_scans_credential_patterns_without_echo(
    bridge: Any, question: str, marker: str
) -> None:
    before_refusal = len(bridge.audit.records)
    response = _handoff(
        bridge,
        body=_handoff_body(context={"question": question}),
    )

    assert response.status_code == 422
    assert response.json() == {"detail": "CONTEXT_SECRET_DENIED"}
    assert marker not in response.text
    assert marker not in repr(bridge.audit.records[before_refusal:])
    _audit_refusal(
        bridge,
        since=before_refusal,
        reason_code="CONTEXT_SECRET_DENIED",
        task_id=None,
        tool_id=_TASK_TOOL,
    )
    assert bridge.store.records == {}


@pytest.mark.parametrize(
    "question",
    [
        "matplotlib.pyplot.figure",
        "docs.example.invalid/pipeline.guide.page",
        "eyJhbGciOiJSUzI1NiJ9.CANARY.SIG",
    ],
)
def test_ordinary_three_dot_text_and_host_paths_are_accepted(bridge: Any, question: str) -> None:
    response = _handoff(
        bridge,
        key=f"ordinary-dotted-text-{question[:12]}",
        body=_handoff_body(context={"question": question}),
    )

    assert response.status_code == 202
    assert response.json()["task_id"]


@pytest.mark.parametrize(
    ("question", "marker"),
    [
        (
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.ABCDEFGHIJKLMNOPQRSTUV",
            "eyJhbGciOiJIUzI1NiJ9",
        ),
        (
            "eyJhbGciOi.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlMTIzNDU2Nzg",
            "eyJhbGciOi",
        ),
        (
            "eyJub3QtanNvbg.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlMTIzNDU2Nzg",
            "eyJub3QtanNvbg",
        ),
    ],
)
def test_jwt_shaped_three_segment_values_are_denied_without_echo(
    bridge: Any, question: str, marker: str
) -> None:
    before_refusal = len(bridge.audit.records)
    response = _handoff(
        bridge,
        body=_handoff_body(context={"question": question}),
    )

    assert response.status_code == 422
    assert response.json() == {"detail": "CONTEXT_SECRET_DENIED"}
    assert marker not in response.text
    assert question not in response.text
    assert marker not in repr(bridge.audit.records[before_refusal:])
    _audit_refusal(
        bridge,
        since=before_refusal,
        reason_code="CONTEXT_SECRET_DENIED",
        task_id=None,
        tool_id=_TASK_TOOL,
    )
    assert bridge.store.records == {}


def test_short_dotted_credential_lookalike_is_not_a_jwt(bridge: Any) -> None:
    response = _handoff(
        bridge,
        body=_handoff_body(context={"question": "eyJhbGciOiJSUzI1NiJ9.CANARY.SIG"}),
    )

    assert response.status_code == 202
    assert response.json()["task_id"]


@pytest.mark.parametrize(
    ("question", "marker"),
    [
        ("ghp_QA_CANARY_TOKEN_0123456789ABCDEFGH", "ghp_QA_CANARY_TOKEN_0123456789ABCDEFGH"),
        ("gho_QA_CANARY_TOKEN_0123456789ABCDEFGH", "gho_QA_CANARY_TOKEN_0123456789ABCDEFGH"),
        ("ghs_QA_CANARY_TOKEN_0123456789ABCDEFGH", "ghs_QA_CANARY_TOKEN_0123456789ABCDEFGH"),
        ("xoxb-1234567890-1234567890-QACANARYTOKEN", "xoxb-1234567890-1234567890-QACANARYTOKEN"),
        ("xoxa-1234567890-1234567890-QACANARYTOKEN", "xoxa-1234567890-1234567890-QACANARYTOKEN"),
        ("xoxp-1234567890-1234567890-QACANARYTOKEN", "xoxp-1234567890-1234567890-QACANARYTOKEN"),
        ("xoxr-1234567890-1234567890-QACANARYTOKEN", "xoxr-1234567890-1234567890-QACANARYTOKEN"),
        ("AKIA1234567890ABCDEF", "AKIA1234567890ABCDEF"),
        ("ASIA1234567890ABCDEF", "ASIA1234567890ABCDEF"),
        (
            "https://hooks.slack.com/services/T00000000/B00000000/QACANARYSLACKTOKEN0123456789",
            "QACANARYSLACKTOKEN0123456789",
        ),
        (
            "https://discord.com/api/webhooks/123456789012345678/QACANARYDISCORDTOKEN0123456789",
            "QACANARYDISCORDTOKEN0123456789",
        ),
    ],
)
def test_additional_provider_tokens_and_webhook_paths_are_denied_without_echo(
    bridge: Any, question: str, marker: str
) -> None:
    before_refusal = len(bridge.audit.records)
    response = _handoff(
        bridge,
        body=_handoff_body(context={"question": question}),
    )

    assert response.status_code == 422
    assert response.json() == {"detail": "CONTEXT_SECRET_DENIED"}
    assert marker not in response.text
    assert question not in response.text
    assert marker not in repr(bridge.audit.records[before_refusal:])
    _audit_refusal(
        bridge,
        since=before_refusal,
        reason_code="CONTEXT_SECRET_DENIED",
        task_id=None,
        tool_id=_TASK_TOOL,
    )
    assert bridge.store.records == {}


def test_task_context_schema_is_closed_versioned_and_accepts_max_tokens(bridge: Any) -> None:
    assert frozenset({"analysis", "research"}) == OMEGA_TASK_TYPES_V1

    analysis = _handoff(
        bridge,
        key="analysis-max-tokens",
        body=_handoff_body(context={"question": "synthetic summary", "max_tokens": 100}),
    )
    assert analysis.status_code == 202
    analysis_record = require_task_record(bridge.store.get_task(_PEER, analysis.json()["task_id"]))
    assert analysis_record.task.task_type == "analysis"
    assert b'"max_tokens":100' in analysis_record.context_payload

    research = _handoff(
        bridge,
        key="research-source-refs",
        body=_handoff_body(
            type="research",
            context={"question": "synthetic summary", "source_refs": ["source.synthetic"]},
        ),
    )
    assert research.status_code == 202
    research_record = require_task_record(bridge.store.get_task(_PEER, research.json()["task_id"]))
    assert research_record.task.task_type == "research"

    before_unknown_key = len(bridge.audit.records)
    unknown_key = _handoff(
        bridge,
        key="unknown-context-key",
        body=_handoff_body(
            context={"question": "synthetic summary", "unapproved_field": "do not echo"}
        ),
    )
    assert unknown_key.status_code == 422
    assert unknown_key.json() == {"detail": "CONTEXT_SCHEMA_DENIED"}
    assert "unapproved_field" not in unknown_key.text
    assert "do not echo" not in unknown_key.text
    assert "unapproved_field" not in repr(bridge.audit.records[before_unknown_key:])
    assert "do not echo" not in repr(bridge.audit.records[before_unknown_key:])
    _audit_refusal(
        bridge,
        since=before_unknown_key,
        reason_code="CONTEXT_SCHEMA_DENIED",
        task_id=None,
        tool_id=_TASK_TOOL,
    )

    before_unknown_type = len(bridge.audit.records)
    unknown_type = _handoff(
        bridge,
        key="unknown-task-type",
        body=_handoff_body(type="unapproved-type"),
    )
    assert unknown_type.status_code == 422
    assert unknown_type.json() == {"detail": "TASK_TYPE_DENIED"}
    assert "unapproved-type" not in unknown_type.text
    assert "unapproved-type" not in repr(bridge.audit.records[before_unknown_type:])
    _audit_refusal(
        bridge,
        since=before_unknown_type,
        reason_code="TASK_TYPE_DENIED",
        task_id=None,
        tool_id=_TASK_TOOL,
    )


def test_duplicate_json_keys_fail_content_free(bridge: Any) -> None:
    response = bridge.client.post(
        "/v1/omega/tasks/handoff",
        headers={
            **_headers(bridge),
            "Idempotency-Key": "duplicate-json-key",
            "Content-Type": "application/json",
        },
        content=(
            b'{"type":"analysis","type":"forged","priority":"normal",'
            b'"assigned_to":"agent.worker","ttl_ms":60000,"sla_ms":30000,'
            b'"context":{"secret":"duplicate-key-canary"}}'
        ),
    )
    assert response.status_code == 422
    assert response.json() == {"detail": "INVALID_REQUEST"}
    assert "duplicate-key-canary" not in response.text


def test_owner_accepts_and_updates_without_persisting_raw_output(bridge: Any) -> None:
    created = _handoff(bridge)
    task_id = _task_id(created)
    accepted = bridge.client.post(
        f"/v1/omega/tasks/{task_id}/accept",
        headers=_headers(bridge, session_id=_WORKER_SESSION),
        json={},
    )
    assert accepted.status_code == 200
    assert accepted.json()["state"] == "in_progress"

    secret = "private-output-canary"
    updated = bridge.client.post(
        f"/v1/omega/tasks/{task_id}/update",
        headers=_headers(bridge, session_id=_WORKER_SESSION),
        json={"state": "failed", "progress_pct": 100, "output": secret},
    )
    assert updated.status_code == 200
    assert updated.json()["state"] == "failed"
    assert secret not in updated.text
    record = require_task_record(bridge.store.get_task(_PEER, task_id))
    assert record.task.state == "failed"
    assert secret.encode() not in (record.context_payload or b"")
    assert all(secret not in entry.entry.reason_code for entry in bridge.audit.records)
    assert len(bridge.outbox.events) == 3


def test_success_state_requires_external_mcp_postcondition_receipt(bridge: Any) -> None:
    task_id = _task_id(_handoff(bridge))
    accepted = bridge.client.post(
        f"/v1/omega/tasks/{task_id}/accept",
        headers=_headers(bridge, session_id=_WORKER_SESSION),
        json={},
    )
    assert accepted.status_code == 200
    succeeded = bridge.client.post(
        f"/v1/omega/tasks/{task_id}/update",
        headers=_headers(bridge, session_id=_WORKER_SESSION),
        json={"state": "succeeded"},
    )
    assert succeeded.status_code == 412
    assert succeeded.json() == {"detail": "POSTCONDITION_RECEIPT_REQUIRED"}
    record = require_task_record(bridge.store.get_task(_PEER, task_id))
    assert record.task.state == "in_progress"


def test_non_owner_cannot_accept_or_update_and_creator_can_cancel(bridge: Any) -> None:
    created = _handoff(bridge)
    task_id = _task_id(created)
    creator_accept = bridge.client.post(
        f"/v1/omega/tasks/{task_id}/accept",
        headers=_headers(bridge),
        json={},
    )
    assert creator_accept.status_code == 403
    assert creator_accept.json()["detail"] == "OWNER_REQUIRED"

    created_again = _handoff(bridge, key="creator-cancel")
    cancel_id = _task_id(created_again)
    not_creator = bridge.client.post(
        f"/v1/omega/tasks/{cancel_id}/cancel",
        headers=_headers(bridge, session_id=_WORKER_SESSION),
        json={},
    )
    assert not_creator.status_code == 403
    assert not_creator.json()["detail"] == "CREATOR_REQUIRED"
    cancelled = bridge.client.post(
        f"/v1/omega/tasks/{cancel_id}/cancel", headers=_headers(bridge), json={}
    )
    assert cancelled.status_code == 200
    assert cancelled.json()["state"] == "cancelled"


def test_task_expiry_materializes_lifecycle_event_on_access(bridge: Any) -> None:
    response = _handoff(bridge, body=_handoff_body(ttl_ms=1_000, sla_ms=500))
    task_id = _task_id(response)
    bridge.now[0] += 1_000_000_000
    expired = bridge.client.post(
        f"/v1/omega/tasks/{task_id}/accept",
        headers=_headers(bridge, session_id=_WORKER_SESSION),
        json={},
    )
    assert expired.status_code == 410
    assert expired.json()["detail"] == "TASK_EXPIRED"
    record = require_task_record(bridge.store.get_task(_PEER, task_id))
    assert record.task.state == "expired"
    assert any(event.new_state == "expired" for event in bridge.outbox.events.values())


def test_expire_due_uses_runtime_clock_and_emits_expiry_once(bridge: Any) -> None:
    response = _handoff(bridge, body=_handoff_body(ttl_ms=1_000, sla_ms=500))
    task_id = _task_id(response)
    initial_events = len(bridge.outbox.events)

    # No task endpoint is touched after the trusted clock crosses expires_at_ns.
    bridge.now[0] += 1_000_000_000
    clock_reads_before = bridge.clock_reads[0]
    expired_count = bridge.runtime.expire_due(limit=10)

    assert expired_count == 1
    assert bridge.clock_reads[0] == clock_reads_before + 1
    record = require_task_record(bridge.store.get_task(_PEER, task_id))
    assert record.task.state == "expired"
    expiry_events = [
        event
        for event in bridge.outbox.events.values()
        if event.task_id == task_id and event.new_state == "expired"
    ]
    assert len(expiry_events) == 1
    assert len(bridge.outbox.events) == initial_events + 1

    assert bridge.runtime.expire_due(limit=10) == 0
    expiry_events = [
        event
        for event in bridge.outbox.events.values()
        if event.task_id == task_id and event.new_state == "expired"
    ]
    assert len(expiry_events) == 1
    assert len(bridge.outbox.events) == initial_events + 1


def test_expire_due_limit_bounds_work_and_drains_in_deterministic_order(bridge: Any) -> None:
    first_task = _task_id(
        _handoff(
            bridge,
            key="expire-first",
            body=_handoff_body(ttl_ms=1_000, sla_ms=500),
        )
    )
    bridge.now[0] += 1
    second_task = _task_id(
        _handoff(
            bridge,
            key="expire-second",
            body=_handoff_body(ttl_ms=1_000, sla_ms=500),
        )
    )
    bridge.now[0] += 1_000_000_000

    assert bridge.runtime.expire_due(limit=1) == 1
    first_record = require_task_record(bridge.store.get_task(_PEER, first_task))
    second_record = require_task_record(bridge.store.get_task(_PEER, second_task))
    assert first_record.task.state == "expired"
    assert second_record.task.state == "pending"

    assert bridge.runtime.expire_due(limit=1) == 1
    assert bridge.runtime.expire_due(limit=1) == 0
    for task_id in (first_task, second_task):
        events = [
            event
            for event in bridge.outbox.events.values()
            if event.task_id == task_id and event.new_state == "expired"
        ]
        assert len(events) == 1


def test_expire_due_materializes_untouched_stale_orphan_once(bridge: Any) -> None:
    task_id = _task_id(_handoff(bridge, body=_handoff_body(ttl_ms=60_000, sla_ms=2_000)))
    accepted = bridge.client.post(
        f"/v1/omega/tasks/{task_id}/accept",
        headers=_headers(bridge, session_id=_WORKER_SESSION),
        json={},
    )
    assert accepted.status_code == 200
    bridge.health.offline = True
    bridge.now[0] += 3_000_000_000

    assert bridge.runtime.expire_due(limit=10) == 1
    record = require_task_record(bridge.store.get_task(_PEER, task_id))
    assert record.task.state == "failed"
    orphan_events = [
        event
        for event in bridge.outbox.events.values()
        if event.task_id == task_id and event.reason_code == "ORPHANED_HEARTBEAT"
    ]
    assert len(orphan_events) == 1
    assert bridge.runtime.expire_due(limit=10) == 0
    assert (
        len(
            [
                event
                for event in bridge.outbox.events.values()
                if event.task_id == task_id and event.reason_code == "ORPHANED_HEARTBEAT"
            ]
        )
        == 1
    )


def test_stale_bridge_after_sla_materializes_orphan_failure(bridge: Any) -> None:
    created = _handoff(bridge, body=_handoff_body(ttl_ms=60_000, sla_ms=2_000))
    task_id = _task_id(created)
    accepted = bridge.client.post(
        f"/v1/omega/tasks/{task_id}/accept",
        headers=_headers(bridge, session_id=_WORKER_SESSION),
        json={},
    )
    assert accepted.status_code == 200
    bridge.now[0] += 3_000_000_000
    bridge.health.offline = True
    orphaned = bridge.client.post(
        f"/v1/omega/tasks/{task_id}/update",
        headers=_headers(bridge, session_id=_WORKER_SESSION),
        json={"state": "failed"},
    )
    assert orphaned.status_code == 410
    assert orphaned.json()["detail"] == "TASK_ORPHANED"
    record = require_task_record(bridge.store.get_task(_PEER, task_id))
    assert record.task.state == "failed"
    assert any(event.reason_code == "ORPHANED_HEARTBEAT" for event in bridge.outbox.events.values())


def test_manifest_is_session_scoped_and_tool_use_is_authorization_only(bridge: Any) -> None:
    base = bridge.sessions[_WORKER_SESSION]
    scoped_session = issue_agent_session(
        session=AgentSessionV1(
            **{
                **base.model_dump(),
                "session_id": "session-research-only",
                "scopes": tuple(
                    scope for scope in base.scopes if scope != f"tool:use.{_OTHER_TOOL}"
                ),
            }
        )
    )
    bridge.sessions[scoped_session.session_id] = scoped_session
    manifest = bridge.client.get(
        "/v1/omega/tools/manifest",
        headers=_headers(bridge, session_id=scoped_session.session_id),
    )
    assert manifest.status_code == 200
    assert _TASK_TOOL in manifest.json()["tools"]
    assert _OTHER_TOOL not in manifest.json()["tools"]

    created = _handoff(bridge)
    task_id = _task_id(created)
    accepted = bridge.client.post(
        f"/v1/omega/tasks/{task_id}/accept",
        headers=_headers(bridge, session_id=_WORKER_SESSION),
        json={},
    )
    assert accepted.status_code == 200

    used = bridge.client.post(
        "/v1/omega/tools/use",
        headers=_headers(bridge, session_id=_WORKER_SESSION),
        json={
            "task_id": task_id,
            "tool_id": _TASK_TOOL,
            "action": "read",
            "params": {"symbol": "SYNTH"},
        },
    )
    assert used.status_code == 200
    assert used.json()["status"] == "authorized_for_mcp"
    assert used.json()["effect_performed"] is False
    assert used.json()["trace_ids"]
    assert len(bridge.mcp.calls) == 1
    assert bridge.mcp.calls[0]["action"] == "read"
    assert len(bridge.outbox.events) == 2


def test_tool_allowlist_scope_financial_gate_and_mcp_refusal(bridge: Any) -> None:
    created = _handoff(bridge)
    task_id = _task_id(created)
    bridge.client.post(
        f"/v1/omega/tasks/{task_id}/accept",
        headers=_headers(bridge, session_id=_WORKER_SESSION),
        json={},
    )
    before_tool_denial = len(bridge.audit.records)
    disallowed = bridge.client.post(
        "/v1/omega/tools/use",
        headers=_headers(bridge, session_id=_WORKER_SESSION),
        json={"task_id": task_id, "tool_id": _OTHER_TOOL, "action": "read"},
    )
    assert disallowed.status_code == 403
    assert disallowed.json()["detail"] == "TOOL_DENIED"
    _audit_refusal(
        bridge,
        since=before_tool_denial,
        reason_code="TOOL_DENIED",
        task_id=task_id,
        tool_id=_OTHER_TOOL,
    )
    before_financial_denial = len(bridge.audit.records)
    financial = bridge.client.post(
        "/v1/omega/tools/use",
        headers=_headers(bridge, session_id=_WORKER_SESSION),
        json={"task_id": task_id, "tool_id": _FINANCIAL_TOOL, "action": "execute"},
    )
    assert financial.status_code == 403
    assert financial.json()["detail"] == "FINANCIAL_ROUTE_DENIED"
    _audit_refusal(
        bridge,
        since=before_financial_denial,
        reason_code="FINANCIAL_ROUTE_DENIED",
        task_id=task_id,
        tool_id=_FINANCIAL_TOOL,
    )
    assert bridge.mcp.calls == []

    bridge.mcp.deny = True
    before_mcp_denial = len(bridge.audit.records)
    denied = bridge.client.post(
        "/v1/omega/tools/use",
        headers=_headers(bridge, session_id=_WORKER_SESSION),
        json={"task_id": task_id, "tool_id": _TASK_TOOL, "action": "read"},
    )
    assert denied.status_code == 403
    assert denied.json()["detail"] == "MCP_POLICY_DENIED"
    assert denied.json().get("effect_performed") is not True
    _audit_refusal(
        bridge,
        since=before_mcp_denial,
        reason_code="MCP_POLICY_DENIED",
        task_id=task_id,
        tool_id=_TASK_TOOL,
    )


def test_active_halt_refuses_tool_use_without_mcp_authorization(bridge: Any) -> None:
    task_id = _task_id(_handoff(bridge))
    accepted = bridge.client.post(
        f"/v1/omega/tasks/{task_id}/accept",
        headers=_headers(bridge, session_id=_WORKER_SESSION),
        json={},
    )
    assert accepted.status_code == 200
    bridge.health.halted = True
    before_halt = len(bridge.audit.records)
    refused = bridge.client.post(
        "/v1/omega/tools/use",
        headers=_headers(bridge, session_id=_WORKER_SESSION),
        json={"task_id": task_id, "tool_id": _TASK_TOOL, "action": "read"},
    )
    assert refused.status_code == 403
    assert refused.json()["detail"] in {"BRIDGE_UNAVAILABLE", "HALT_ACTIVE"}
    _audit_refusal(
        bridge,
        since=before_halt,
        reason_code=refused.json()["detail"],
        task_id=task_id,
        tool_id=_TASK_TOOL,
    )
    assert bridge.mcp.calls == []
    record = require_task_record(bridge.store.get_task(_PEER, task_id))
    assert record.task.state == "in_progress"


def test_risk_required_task_is_refused_and_offline_handoff_denied(bridge: Any) -> None:
    before_risk_refusal = len(bridge.audit.records)
    risk_task = _handoff(
        bridge,
        key="risk-required",
        body=_handoff_body(requires_risk_guard=True),
    )
    assert risk_task.status_code == 412
    assert risk_task.json()["detail"] == "RISK_GUARD_UNAVAILABLE"
    _audit_refusal(
        bridge,
        since=before_risk_refusal,
        reason_code="RISK_GUARD_UNAVAILABLE",
        task_id=None,
        tool_id=_TASK_TOOL,
    )

    bridge.health.offline = True
    before_bridge_refusal = len(bridge.audit.records)
    offline = _handoff(bridge, key="offline-handoff")
    assert offline.status_code == 403
    assert offline.json()["detail"] == "BRIDGE_UNAVAILABLE"
    _audit_refusal(
        bridge,
        since=before_bridge_refusal,
        reason_code="BRIDGE_UNAVAILABLE",
        task_id=None,
        tool_id=_TASK_TOOL,
    )
    assert bridge.store.records == {}


def test_rate_limit_and_retry_after_are_enforced(bridge: Any) -> None:
    bridge.rate.deny = True
    before_rate_refusal = len(bridge.audit.records)
    response = _handoff(bridge, key="rate-limited")
    assert response.status_code == 429
    assert response.json()["detail"] == "RATE_LIMITED"
    assert response.headers["retry-after"] == "3"
    _audit_refusal(
        bridge,
        since=before_rate_refusal,
        reason_code="RATE_LIMITED",
        task_id=None,
        tool_id=_TASK_TOOL,
    )
    assert bridge.store.records == {}


def test_audit_filter_chain_and_trace_are_redacted(
    bridge: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "leviathan_api.routers.omega_tasks.uuid4",
        lambda: SimpleNamespace(hex="1234567890abcdef1234567890abcdef"),
    )
    handoff = _handoff(bridge)
    task_id = _task_id(handoff)
    trace_id = handoff.json()["trace_id"]
    response = bridge.client.get(
        "/v1/omega/audit",
        headers=_headers(bridge),
        params={"trace_id": trace_id, "task_id": task_id, "limit": 10},
    )
    assert response.status_code == 200
    events = response.json()
    assert len(events) == 2
    assert {event["action"] for event in events} == {
        "task_handoff_attempt",
        "task_handoff",
    }
    assert all(event["trace_id"] == trace_id for event in events)
    assert all(event["task_id"] == task_id for event in events)
    assert all(len(event["payload_hash"]) == 64 for event in events)
    assert "synthetic market summary" not in response.text
    assert "question" not in response.text

    invalid_range = bridge.client.get(
        "/v1/omega/audit",
        headers=_headers(bridge),
        params={"since_ns": bridge.now[0]},
    )
    assert invalid_range.status_code == 200
    assert all(event["ts"] >= bridge.now[0] for event in invalid_range.json())


def test_replayed_signed_nonce_is_rejected_before_store_access(bridge: Any) -> None:
    signed = _token(bridge.now[0], "nonce-replay")
    headers = {
        "Authorization": f"Bearer {signed}",
        "x-agent-session-id": _CREATOR_SESSION,
        "Idempotency-Key": "replay-key",
    }
    first = bridge.client.post("/v1/omega/tasks/handoff", headers=headers, json=_handoff_body())
    assert first.status_code == 202
    store_count = len(bridge.store.create_calls)
    replay = bridge.client.post("/v1/omega/tasks/handoff", headers=headers, json=_handoff_body())
    assert replay.status_code == 401
    assert replay.json()["detail"] == "OMEGA_REPLAY_OR_STORE_UNAVAILABLE"
    assert len(bridge.store.create_calls) == store_count
