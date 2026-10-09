"""Independent MCP-003 HTTP acceptance using synthetic principals and evidence."""

from __future__ import annotations

import base64
import hashlib
import json
from collections import deque
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from leviathan_api.routers import mcp_control as _mcp_control_router
from leviathan_api.routers.mcp_control import McpControlRuntime, router
from leviathan_core.mcp_control import state_models as _state_models
from leviathan_core.mcp_control.audit_chain import (
    GENESIS_HASH,
    _event_bytes,
    _event_hash,
    verify_audit_chain,
)
from leviathan_core.mcp_control.control_service import empty_control_snapshot
from leviathan_core.mcp_control.http_contract import AgentRegistrationRequestV1
from leviathan_core.mcp_control.policy_models import (
    ApprovalEvidenceV1 as PolicyApprovalEvidenceV1,
)
from leviathan_core.mcp_control.policy_models import (
    PolicyContextV1,
    ToolGrantV1,
    ToolRegistrationV1,
)
from leviathan_core.mcp_control.state_models import (
    CONTROL_VERSION,
    ApprovalEvidenceV1,
    AttestationEvidenceV1,
    ControlSnapshotV1,
)
from leviathan_core.risk.halt import HaltAuthority
from leviathan_core.security.authz_models import (
    _VERIFIER_MARKER,
    PrincipalV1,
    TrustedPrincipalAdapterV1,
    TrustedPrincipalV1,
)
from leviathan_core.security.principal_verifier import (
    PrincipalVerifier,
    RSAPublicKeyV1,
    TrustedIssuerV1,
    VerifiedPrincipalV1,
)
from leviathan_core.text.safe_label import is_safe_display_label

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
_NOW = datetime(2026, 10, 6, 18, 0, tzinfo=UTC)
_NOW_SECONDS = int(_NOW.timestamp())
_NOW_NS = _NOW_SECONDS * 1_000_000_000
_ISSUER = "mcp-synthetic-idp"
_AUDIENCE = "leviathan-backend"
_ORG = "org-fixture"
_DESK = "desk-fixture"
_ENV = "test"
_KID = "mcp-synthetic-key"
_AGENT = "agent-fixture"
_SESSION = "session-fixture"
_TOOL = "quotes.read"
_RESOURCE = f"{_ORG}:quotes:SYNTH"
_SCOPE = "market:read"
_CERT = b"synthetic MCP client certificate DER"


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


def _token(
    subject: str,
    role: str,
    scopes: tuple[str, ...],
    *,
    org_id: str = _ORG,
) -> str:
    header = _segment({"alg": "RS256", "kid": _KID, "typ": "JWT"})
    claims = _segment(
        {
            "iss": _ISSUER,
            "aud": _AUDIENCE,
            "org": org_id,
            "sub": subject,
            "role": role,
            "scope": list(scopes),
            "env": _ENV,
            "jti": f"jti-{subject}",
            "iat": _NOW_SECONDS,
            "nbf": _NOW_SECONDS,
            "exp": _NOW_SECONDS + 300,
            "cnf": {"x5t#S256": _b64url(hashlib.sha256(_CERT).digest())},
        }
    )
    signing_input = f"{header}.{claims}".encode("ascii")
    return f"{signing_input.decode('ascii')}.{_b64url(_signature(signing_input))}"


def _verifier(*, org_id: str = _ORG, project_id: str = _DESK) -> PrincipalVerifier:
    return PrincipalVerifier(
        trusted_issuer=TrustedIssuerV1(
            issuer=_ISSUER,
            audience=_AUDIENCE,
            org_id=org_id,
            project_id=project_id,
            env=_ENV,
        ),
        key_set=_KeySet(),
        revocations=_Revocations(),
        clock=lambda: _NOW,
    )


def _principal(
    verifier: PrincipalVerifier,
    *,
    subject: str = "operator-1",
    role: str = "Operator",
    scopes: tuple[str, ...] = ("mcp:read", "mcp:write", "mcp:approve", "mcp:audit"),
    org_id: str = _ORG,
) -> VerifiedPrincipalV1:
    return verifier.verify(_token(subject, role, scopes, org_id=org_id), peer_certificate_der=_CERT)


def _tool(**changes: Any) -> ToolRegistrationV1:
    fields: dict[str, Any] = {
        "org_id": _ORG,
        "tool_id": _TOOL,
        "resource_pattern": _RESOURCE,
        "tool_class": "data",
        "capabilities": frozenset({"read", "update"}),
        "environments": frozenset({"paper"}),
        "scope": _SCOPE,
        "bridge_required": False,
        "order_or_route": False,
        "financial": False,
        "config_change": True,
        "data_egress": False,
    }
    fields.update(changes)
    return ToolRegistrationV1(**fields)


def _grant(
    now_ns: int = _NOW_NS,
    *,
    agent_id: str = _AGENT,
    session_id: str = _SESSION,
) -> ToolGrantV1:
    return ToolGrantV1._from_trusted_adapter(
        version=CONTROL_VERSION,
        grant_id="grant-fixture",
        org_id=_ORG,
        desk_id=_DESK,
        agent_id=agent_id,
        session_id=session_id,
        tool_id=_TOOL,
        resource_pattern=_RESOURCE,
        scope=_SCOPE,
        capabilities=frozenset({"read", "update"}),
        environments=frozenset({"paper"}),
        expires_at_ns=now_ns + 100_000_000_000,
        issued_at_ns=now_ns - 1,
        max_notional=None,
        max_leverage=None,
        deny=False,
    )


def _context(
    now_ns: int = _NOW_NS,
    *,
    snapshot: ControlSnapshotV1 | None = None,
    bridge_online: bool = True,
    halt_clear: bool = True,
    agent_id: str = _AGENT,
    session_id: str = _SESSION,
    elevation_requires_approval: bool = False,
) -> PolicyContextV1:
    approvals: tuple[PolicyApprovalEvidenceV1, ...] = ()
    if snapshot is not None:
        approvals = tuple(
            PolicyApprovalEvidenceV1(approver_id=row.actor_id, role=row.actor_role)
            for row in snapshot.approvals
            if row.kind == "config_change"
        )
    registration = _tool()
    reserved_order_tool = _tool(
        tool_id="orders.place",
        resource_pattern=f"{_ORG}:orders:*",
        tool_class="order_route",
        capabilities=frozenset({"execute"}),
        scope="market:execute",
        order_or_route=True,
    )
    return PolicyContextV1._from_trusted_adapter(
        version=CONTROL_VERSION,
        org_id=_ORG,
        desk_id=_DESK,
        agent_id=agent_id,
        session_id=session_id,
        evaluation_time_ns=now_ns,
        principal_verified=True,
        attestation_verified=True,
        session_active=True,
        halt_clear=halt_clear,
        risk_snapshot_at_ns=now_ns,
        risk_snapshot_max_age_ns=10_000_000_000,
        bridge_online=bridge_online,
        tools=(registration, reserved_order_tool),
        global_max_notional=None,
        global_max_leverage=None,
        live_financial_enabled=False,
        market_open=True,
        liquidity_ok=True,
        egress_allowed=True,
        allowed_egress_domains=(),
        config_approvals=approvals,
        rate_remaining=100,
        max_session_quota=100,
        max_session_lifetime_ns=100_000_000_000,
        elevation_requires_approval=elevation_requires_approval,
        allowed_venues=(),
        blocked_symbols=(),
        allowed_order_types=(),
    )


def _attestation(
    origin: str, now_ns: int = _NOW_NS, agent_id: str = _AGENT
) -> AttestationEvidenceV1:
    return AttestationEvidenceV1._from_trusted_adapter(
        version=CONTROL_VERSION,
        attestation_id=f"attestation-{origin.lower()}",
        org_id=_ORG,
        desk_id=_DESK,
        agent_id=agent_id,
        origin=origin,
        signature_digest="a" * 64,
        issued_at_ns=now_ns,
        expires_at_ns=now_ns + 100_000_000_000,
    )


def _approval(principal: VerifiedPrincipalV1, body: dict[str, Any]) -> ApprovalEvidenceV1:
    return ApprovalEvidenceV1._from_trusted_adapter(
        version=CONTROL_VERSION,
        approval_id=body["approval_id"],
        org_id=_ORG,
        desk_id=_DESK,
        session_id=body["session_id"],
        action_key=body.get("action_key"),
        actor_id=principal.subject_id,
        actor_role=principal.role,
        kind=body["kind"],
        target_scope=body["target_scope"],
        issued_at_ns=_NOW_NS,
        expires_at_ns=body["expires_at_ns"],
    )


def _action(**changes: Any) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "version": "1",
        "org_id": _ORG,
        "desk_id": _DESK,
        "agent_id": _AGENT,
        "session_id": _SESSION,
        "environment": "paper",
        "action_idempotency_key": "action-fixture-1",
        "tool_id": _TOOL,
        "resource": _RESOURCE,
        "scope": _SCOPE,
        "capability": "read",
        "timestamp_ns": _NOW_NS,
    }
    fields.update(changes)
    return fields


@pytest.fixture
def control_app() -> Any:
    verifier = _verifier()
    current: list[VerifiedPrincipalV1 | None] = [
        _principal(verifier, subject="operator-1", role="Operator")
    ]
    context_flags = {"bridge_online": True, "halt_clear": True}
    executor_calls: list[object] = []
    snapshot = empty_control_snapshot()
    attestation_origins = {"origin": "LEVIATHAN"}
    runtime_box: dict[str, McpControlRuntime] = {}

    def context_resolver(principal: VerifiedPrincipalV1, *, now_ns: int, **selectors: object):
        runtime = runtime_box["runtime"]
        return _context(
            now_ns,
            snapshot=runtime.snapshot,
            bridge_online=context_flags["bridge_online"],
            halt_clear=context_flags["halt_clear"],
            agent_id=str(selectors.get("agent_id") or _AGENT),
            session_id=str(selectors.get("session_id") or _SESSION),
        )

    def grants_resolver(
        principal: VerifiedPrincipalV1, session_id: str, *, now_ns: int
    ) -> tuple[ToolGrantV1, ...]:
        return (_grant(now_ns),)

    def attestation_resolver(
        principal: VerifiedPrincipalV1, payload: Any, *, now_ns: int
    ) -> AttestationEvidenceV1:
        return _attestation(attestation_origins["origin"], now_ns, payload.agent_id)

    def approval_resolver(
        principal: VerifiedPrincipalV1, body: Any, *, now_ns: int
    ) -> ApprovalEvidenceV1:
        return _approval(principal, body.model_dump())

    halt = HaltAuthority(clock=lambda: _NOW)
    runtime = McpControlRuntime(
        context_resolver=context_resolver,
        grants_resolver=grants_resolver,
        attestation_resolver=attestation_resolver,
        approval_resolver=approval_resolver,
        halt_authority=halt,
        snapshot=snapshot,
        now_ns=lambda: _NOW_NS,
        allow_unaudited_for_tests=True,
    )
    runtime_box["runtime"] = runtime
    app = FastAPI()
    app.include_router(router)
    app.state.mcp_control_runtime = runtime
    app.state.mcp_control_principal_resolver = lambda request: current[0]
    app.state.mcp_control_now_ns = lambda: _NOW_NS
    # Deliberately supplied as a canary: the read-only route must never use it.
    app.state.mcp_executor = lambda *args, **kwargs: executor_calls.append((args, kwargs))
    with TestClient(app) as client:
        yield SimpleNamespace(
            app=app,
            client=client,
            runtime=runtime,
            halt=halt,
            current=current,
            verifier=verifier,
            context_flags=context_flags,
            attestation_origins=attestation_origins,
            executor_calls=executor_calls,
        )


def _create_world(world: Any) -> None:
    response = world.client.post(
        "/mcp/agents/register",
        json={
            "version": "1",
            "agent_id": _AGENT,
            "display_label": "Market-Reader",
            "origin": "LEVIATHAN",
            "attestation": "synthetic-signed-attestation",
        },
    )
    assert response.status_code == 201, response.text
    session = world.client.post(
        "/mcp/sessions",
        json={
            "version": "1",
            "agent_id": _AGENT,
            "session_id": _SESSION,
            "expires_at_ns": _NOW_NS + 100_000_000_000,
            "quota": 10,
        },
    )
    assert session.status_code == 201, session.text


def test_principal_scope_and_payload_role_are_not_authority(control_app: Any) -> None:
    world = control_app
    _create_world(world)
    world.current[0] = _principal(world.verifier, scopes=("mcp:read",))
    denied = world.client.post(
        "/mcp/sessions",
        json={
            "version": "1",
            "agent_id": _AGENT,
            "session_id": "session-forged",
            "expires_at_ns": _NOW_NS + 1000,
            "quota": 10,
            "role": "RiskOfficer",
        },
    )
    assert denied.status_code == 403
    assert denied.json()["detail"] == "SCOPE_DENIED"
    world.current[0] = None
    unauthenticated = world.client.get(
        "/mcp/tools", params={"agent_id": _AGENT, "session_id": _SESSION}
    )
    assert unauthenticated.status_code == 401
    assert len(world.runtime.snapshot.sessions) == 1
    assert world.runtime.snapshot.audit_events[-1].kind == "request_denied"
    assert world.runtime.snapshot.audit_events[-1].reason_codes == ("SCOPE_DENIED",)


def test_omega_origin_requires_bridge_and_matching_trusted_attestation(control_app: Any) -> None:
    world = control_app
    world.context_flags["bridge_online"] = False
    offline = world.client.post(
        "/mcp/agents/register",
        json={
            "version": "1",
            "agent_id": "agent-omega",
            "display_label": "Synthetic",
            "origin": "OMEGA",
            "attestation": "forged",
        },
    )
    assert offline.status_code == 403
    assert offline.json()["detail"] == "ORIGIN_DENIED"
    world.context_flags["bridge_online"] = True
    world.attestation_origins["origin"] = "LEVIATHAN"
    forged = world.client.post(
        "/mcp/agents/register",
        json={
            "version": "1",
            "agent_id": "agent-omega",
            "display_label": "Synthetic",
            "origin": "OMEGA",
            "attestation": "forged",
        },
    )
    assert forged.status_code == 409
    assert forged.json()["detail"] == "ATTESTATION_MISMATCH"
    assert world.runtime.snapshot.agents == ()
    world.attestation_origins["origin"] = "OMEGA"
    trusted = world.client.post(
        "/mcp/agents/register",
        json={
            "version": "1",
            "agent_id": "agent-omega",
            "display_label": "Synthetic",
            "origin": "OMEGA",
            "attestation": "synthetic-bridge-attestation",
        },
    )
    assert trusted.status_code == 201, trusted.text


@pytest.mark.parametrize(
    "label",
    (
        "free text!",
        "Market Data, Reader",
        "Aster--Node",
        "Aster_Node",
        "Aster1234",
        "Aster-Node-Desk-Extra",
        "A" * 41,
        "ApiKey7",
        "secret2",
        "my-token",
        "AKIA",
        "ghp123",
        "Sk2",
        "ghp_abcd1234",
        "xox-bad-token",
        "sk_live_abcdef",
    ),
)
def test_display_label_rejects_free_text_denied_words_and_credential_shapes(
    control_app: Any, label: str
) -> None:
    world = control_app
    prior_events = world.runtime.snapshot.audit_events
    response = world.client.post(
        "/mcp/agents/register",
        json={
            "version": "1",
            "agent_id": "agent-label-invalid",
            "display_label": label,
            "origin": "LEVIATHAN",
            "attestation": "synthetic-signed-attestation",
        },
    )

    assert response.status_code == 422
    assert response.json() == {"detail": "REQUEST_INVALID"}
    assert label not in response.text
    assert world.runtime.snapshot.agents == ()
    assert len(world.runtime.snapshot.audit_events) == len(prior_events) + 1
    denial = world.runtime.snapshot.audit_events[-1]
    assert denial.kind == "request_denied"
    assert denial.reason_codes == ("REQUEST_INVALID",)
    assert denial.agent_id == "UNKNOWN_SUBJECT"
    assert label not in repr(denial)


def test_display_label_is_not_persisted_logged_or_included_in_audit_digest(
    control_app: Any, caplog: pytest.LogCaptureFixture
) -> None:
    world = control_app
    labels = ("Aster123-Node7-Team", "Birch12-Node8-Team")
    event_hashes: list[str] = []
    observed_labels: list[str] = []
    original_attestation_resolver = world.runtime.attestation_resolver

    def observe_label(principal: VerifiedPrincipalV1, payload: Any, *, now_ns: int):
        observed_labels.append(payload.display_label)
        return original_attestation_resolver(principal, payload, now_ns=now_ns)

    world.runtime.attestation_resolver = observe_label
    for label in labels:
        # Reuse identical registration evidence in a fresh ledger so the audit
        # digest comparison isolates the label as the only changed input.
        prior_runtime = world.runtime
        world.runtime = McpControlRuntime(
            context_resolver=prior_runtime.context_resolver,
            grants_resolver=prior_runtime.grants_resolver,
            attestation_resolver=prior_runtime.attestation_resolver,
            approval_resolver=prior_runtime.approval_resolver,
            grant_resolver=prior_runtime.grant_resolver,
            halt_authority=prior_runtime.halt_authority,
            snapshot=empty_control_snapshot(),
            now_ns=prior_runtime.now_ns,
            allow_unaudited_for_tests=True,
        )
        world.app.state.mcp_control_runtime = world.runtime
        response = world.client.post(
            "/mcp/agents/register",
            json={
                "version": "1",
                "agent_id": "agent-label-canary",
                "display_label": label,
                "origin": "LEVIATHAN",
                "attestation": "synthetic-signed-attestation",
            },
        )
        assert response.status_code == 201, response.text
        assert label not in response.text
        snapshot = world.runtime.snapshot
        snapshot_json = snapshot.model_dump_json()
        audit_json = json.dumps(
            [event.model_dump(mode="json") for event in snapshot.audit_events],
            sort_keys=True,
        )
        assert label not in repr(snapshot)
        assert label not in snapshot_json
        assert label not in audit_json
        assert label not in caplog.text
        event_hashes.append(snapshot.audit_events[-1].event_hash)

    assert observed_labels == list(labels)
    assert event_hashes[0] == event_hashes[1]
    assert all(label not in digest for label in labels for digest in event_hashes)


@pytest.mark.parametrize(
    ("label", "expected"),
    (
        ("Aster-Node7-Team", True),
        ("Aster Node7 Team", True),
        ("A" * 16 + "-" + "B" * 16 + "-" + "C" * 6, True),
        ("A" * 41, False),
        ("Aster--Node", False),
        ("Aster-Node-Desk-Extra", False),
            ("Tokenish", True),
        ("Display-Password2", False),
            ("sketch", True),
        ("Safe-Apikey7", False),
    ),
)
def test_registration_uses_shared_lesson_19_display_label_policy(
    label: str, expected: bool
) -> None:
    safe = is_safe_display_label(label)
    try:
        AgentRegistrationRequestV1.model_validate(
            {
                "version": "1",
                "agent_id": "agent-label-policy",
                "display_label": label,
                "origin": "LEVIATHAN",
                "attestation": "synthetic-attestation",
            }
        )
    except Exception:
        contract_accepts = False
    else:
        contract_accepts = True
    assert safe is expected
    assert contract_accepts is safe


def test_desktop_trusted_principal_is_rejected_like_missing_verified_identity(
    control_app: Any,
) -> None:
    world = control_app
    path = "/mcp/tools"
    params = {"agent_id": _AGENT, "session_id": _SESSION}
    world.current[0] = None
    missing = world.client.get(path, params=params)
    assert missing.status_code == 401
    assert missing.json() == {"detail": "UNAUTHENTICATED"}

    resolver = world.app.state.mcp_control_principal_resolver
    world.app.state.mcp_control_principal_resolver = None
    no_verifier = world.client.get(path, params=params)
    assert no_verifier.status_code == 503
    assert no_verifier.json() == {"detail": "MCP_CONTROL_UNAVAILABLE"}
    world.app.state.mcp_control_principal_resolver = resolver

    claims = PrincipalV1(
        principal_id="desktop-user",
        project_id=_DESK,
        roles=("Operator",),
        env=_ENV,
    )
    desktop_principal = TrustedPrincipalAdapterV1.from_verified_claims(
        claims, verifier_marker=_VERIFIER_MARKER
    )
    assert type(desktop_principal) is TrustedPrincipalV1
    world.current[0] = desktop_principal
    refused = world.client.get(path, params=params)
    assert refused.status_code == 401
    assert refused.content == missing.content


def test_auth_clock_is_read_once_per_request(control_app: Any) -> None:
    world = control_app
    readings: list[int] = []

    def advancing_clock() -> int:
        readings.append(_NOW_NS + len(readings))
        return readings[-1]

    world.app.state.mcp_control_now_ns = advancing_clock
    world.runtime.now_ns = advancing_clock
    response = world.client.get("/mcp/tools", params={"agent_id": _AGENT, "session_id": _SESSION})
    assert response.status_code == 200, response.text
    assert len(readings) == 1


def test_duplicate_action_is_idempotent_and_conflicting_reuse_is_denied(control_app: Any) -> None:
    world = control_app
    _create_world(world)
    action = _action()
    missing_key = world.client.post("/mcp/actions", json=action)
    assert missing_key.status_code == 400
    assert missing_key.json()["detail"] == "IDEMPOTENCY_KEY_REQUIRED"
    assert world.runtime.snapshot.actions == ()
    first = world.client.post(
        "/mcp/actions", json=action, headers={"Idempotency-Key": action["action_idempotency_key"]}
    )
    second = world.client.post(
        "/mcp/actions", json=action, headers={"Idempotency-Key": action["action_idempotency_key"]}
    )
    assert first.status_code == second.status_code == 200
    assert first.json()["action_id"] == second.json()["action_id"]
    assert first.json()["effect_allowed"] is False
    assert len(world.runtime.snapshot.actions) == 1
    conflict = world.client.post(
        "/mcp/actions",
        json=_action(resource=f"{_ORG}:quotes:OTHER"),
        headers={"Idempotency-Key": "action-fixture-1"},
    )
    assert conflict.status_code == 409
    assert conflict.json()["detail"] == "IDEMPOTENCY_CONFLICT"
    assert len(world.runtime.snapshot.actions) == 1


def test_three_critical_denials_quarantine_and_future_action_stays_denied(control_app: Any) -> None:
    world = control_app
    _create_world(world)
    for index in range(3):
        result = world.client.post(
            "/mcp/actions",
            json=_action(
                action_idempotency_key=f"bad-resource-{index}",
                resource=f"{_ORG}:private:CANARY",
                timestamp_ns=_NOW_NS + index,
            ),
            headers={"Idempotency-Key": f"bad-resource-{index}"},
        )
        assert result.status_code == 200
        assert result.json()["allowed"] is False
        assert result.json()["effect_allowed"] is False
        assert "RESOURCE_MISMATCH" in result.json()["reason_codes"]
    assert world.runtime.snapshot.agents[0].status == "quarantined"
    next_action = world.client.post(
        "/mcp/actions",
        json=_action(action_idempotency_key="after-quarantine"),
        headers={"Idempotency-Key": "after-quarantine"},
    )
    assert next_action.status_code == 200
    assert next_action.json()["allowed"] is False
    assert "AGENT_UNAVAILABLE" in next_action.json()["reason_codes"]


def test_dry_run_reuses_policy_decision_without_snapshot_or_executor_effect(
    control_app: Any,
) -> None:
    world = control_app
    _create_world(world)
    before = world.runtime.snapshot
    quota_before = before.sessions[0].quota_remaining
    violations_before = before.violations
    key = "dry-run-does-not-consume-key"
    denied_probe = world.client.post(
        "/mcp/actions/dry-run",
        json={
            "version": "1",
            "action": _action(
                action_idempotency_key=key,
                resource=f"{_ORG}:private:DRY-RUN-CANARY",
            ),
        },
        headers={"Idempotency-Key": key},
    )
    assert denied_probe.status_code == 200
    assert denied_probe.json()["allowed"] is False
    assert denied_probe.json()["dry_run"] is True
    after_denial = world.runtime.snapshot
    assert len(after_denial.audit_events) == len(before.audit_events) + 1
    denial_event = after_denial.audit_events[-1]
    assert denial_event.kind == "action_denied"
    assert getattr(denial_event, "dry_run", None) is True
    assert after_denial.actions == before.actions
    assert after_denial.sessions == before.sessions
    assert after_denial.violations == violations_before
    assert world.runtime.snapshot.agents[0].status == "active"

    result = world.client.post(
        "/mcp/actions/dry-run",
        json={"version": "1", "action": _action(action_idempotency_key=key)},
        headers={"Idempotency-Key": key},
    )
    assert result.status_code == 200
    assert result.json()["allowed"] is True
    assert result.json()["dry_run"] is True
    assert result.json()["effect_allowed"] is False
    after_accepted_dry_run = world.runtime.snapshot
    assert after_accepted_dry_run is not after_denial
    assert len(after_accepted_dry_run.audit_events) == len(after_denial.audit_events) + 1
    assert after_accepted_dry_run.audit_events[-1].kind == "action_dry_run"
    assert world.runtime.snapshot.sessions[0].quota_remaining == quota_before
    assert world.runtime.snapshot.actions == before.actions
    assert world.runtime.snapshot.audit_events == after_accepted_dry_run.audit_events

    actual = world.client.post(
        "/mcp/actions",
        json=_action(action_idempotency_key=key),
        headers={"Idempotency-Key": key},
    )
    assert actual.status_code == 200, actual.text
    assert actual.json()["allowed"] is True
    assert actual.json()["effect_allowed"] is False
    assert world.runtime.snapshot.actions[-1].state == "approved"
    assert world.runtime.snapshot.sessions[0].quota_remaining == quota_before - 1
    assert world.runtime.snapshot.agents[0].status == "active"
    assert world.executor_calls == []


def test_dry_run_denials_are_attributed_audited_and_separately_rate_limited(
    control_app: Any,
) -> None:
    world = control_app
    _create_world(world)
    actor = "dry-run-denial-operator"
    world.current[0] = _principal(world.verifier, subject=actor)
    before_events = len(world.runtime.snapshot.audit_events)
    before_violations = world.runtime.snapshot.violations

    for index in range(100):
        response = world.client.post(
            "/mcp/actions/dry-run",
            json={
                "version": "1",
                "action": _action(
                    agent_id=f"unknown-dry-run-{index}",
                    action_idempotency_key=f"dry-denial-{index}",
                ),
            },
        )
        assert response.status_code == 200, response.text
        assert response.json()["allowed"] is False
        assert response.json()["reason_codes"] == ["UNKNOWN_SUBJECT"]
        assert response.json()["dry_run"] is True
        assert f"unknown-dry-run-{index}" not in response.text

    after_denials = world.runtime.snapshot.audit_events[before_events:]
    assert len(after_denials) == 100
    assert all(event.kind == "action_denied" for event in after_denials)
    assert all(event.actor_principal_id == actor for event in after_denials)
    assert all(event.subject_id == "UNKNOWN_SUBJECT" for event in after_denials)
    assert all(getattr(event, "dry_run", None) is True for event in after_denials)
    assert world.runtime.snapshot.violations == before_violations

    tenant_b_org = "org-independent-rate-bucket"
    tenant_b_desk = "desk-independent-rate-bucket"
    tenant_b_actor = "tenant-b-denial-operator"
    tenant_b_verifier = _verifier(org_id=tenant_b_org, project_id=tenant_b_desk)
    world.current[0] = _principal(
        tenant_b_verifier,
        subject=tenant_b_actor,
        org_id=tenant_b_org,
    )
    tenant_b = world.client.post(
        "/mcp/actions/dry-run",
        json={
            "version": "1",
            "action": _action(
                org_id=tenant_b_org,
                desk_id=tenant_b_desk,
                agent_id="tenant-b-unknown-agent",
                action_idempotency_key="tenant-b-dry-denial",
                resource=f"{tenant_b_org}:market:prices:EURUSD",
            ),
        },
    )
    assert tenant_b.status_code == 200, tenant_b.text
    assert tenant_b.json()["reason_codes"] == ["UNKNOWN_SUBJECT"]
    assert world.runtime.dry_run_denial_timestamps_ns[(tenant_b_org, tenant_b_actor)] == deque(
        [_NOW_NS]
    )
    assert len(world.runtime.dry_run_denial_timestamps_ns) == 2

    world.current[0] = _principal(world.verifier, subject=actor)
    limited = world.client.post(
        "/mcp/actions/dry-run",
        json={
            "version": "1",
            "action": _action(
                agent_id="unknown-dry-run-rate-limit",
                action_idempotency_key="dry-denial-rate-limit",
            ),
        },
    )
    assert limited.status_code == 429
    assert limited.json() == {"detail": "DRY_RUN_RATE_LIMIT"}
    assert len(world.runtime.snapshot.audit_events) == before_events + 101
    assert world.runtime.snapshot.violations == before_violations
    agent = next(row for row in world.runtime.snapshot.agents if row.agent_id == _AGENT)
    assert agent.status == "active"

    real_action = world.client.post(
        "/mcp/actions",
        json=_action(
            agent_id="unknown-real-after-dry-limit",
            action_idempotency_key="real-after-dry-limit",
        ),
        headers={"Idempotency-Key": "real-after-dry-limit"},
    )
    assert real_action.status_code == 200
    assert real_action.json()["reason_codes"] == ["UNKNOWN_SUBJECT"]
    assert world.runtime.dry_run_denial_timestamps_ns[(_ORG, actor)] == deque([_NOW_NS] * 100)
    assert len(world.runtime.snapshot.audit_events) == before_events + 102


def test_dry_run_distinct_key_cap_is_bounded_and_prunes_expired_buckets(
    control_app: Any,
) -> None:
    world = control_app
    _create_world(world)
    buckets = world.runtime.dry_run_denial_timestamps_ns
    buckets.update(
        {
            ("synthetic-capacity-org", f"principal-{index}"): deque((_NOW_NS,))
            for index in range(1_024)
        }
    )
    assert len(buckets) == 1_024
    before_events = len(world.runtime.snapshot.audit_events)

    overflow = world.client.post(
        "/mcp/actions/dry-run",
        json={
            "version": "1",
            "action": _action(
                agent_id="unknown-cap-overflow",
                action_idempotency_key="dry-overflow",
            ),
        },
    )
    assert overflow.status_code == 429
    assert overflow.json() == {"detail": "DRY_RUN_RATE_LIMIT"}
    assert len(buckets) == 1_024
    assert len(world.runtime.snapshot.audit_events) == before_events

    real_action = world.client.post(
        "/mcp/actions",
        json=_action(
            agent_id="unknown-real-overflow",
            action_idempotency_key="real-overflow",
        ),
        headers={"Idempotency-Key": "real-overflow"},
    )
    assert real_action.status_code == 200
    assert real_action.json()["reason_codes"] == ["UNKNOWN_SUBJECT"]
    assert len(buckets) == 1_024

    world.runtime.now_ns = lambda: _NOW_NS + 60_000_000_000
    after_expiry = world.client.post(
        "/mcp/actions/dry-run",
        json={
            "version": "1",
            "action": _action(
                agent_id="unknown-after-expiry",
                action_idempotency_key="dry-after-expiry",
            ),
        },
    )
    assert after_expiry.status_code == 200, after_expiry.text
    assert after_expiry.json()["reason_codes"] == ["UNKNOWN_SUBJECT"]
    assert len(buckets) == 1


def test_config_change_requires_operator_and_risk_officer_approvals(control_app: Any) -> None:
    world = control_app
    _create_world(world)
    action = _action(
        action_idempotency_key="config-change-1",
        capability="update",
        is_config_change=True,
    )
    # Unknown body authority fields are rejected without echoing their values.
    forged = world.client.post(
        "/mcp/actions",
        json={
            **action,
            "role": "RiskOfficer",
            "approval": True,
            "secret": "mcp-secret-canary-do-not-leak",
        },
        headers={"Idempotency-Key": "config-change-1"},
    )
    assert forged.status_code == 422
    assert forged.json()["detail"] == "REQUEST_INVALID"
    assert "RiskOfficer" not in forged.text
    assert "mcp-secret-canary-do-not-leak" not in forged.text

    def approve(subject: str, role: str, approval_id: str, action_key: str) -> Any:
        world.current[0] = _principal(
            world.verifier,
            subject=subject,
            role=role,
            scopes=("mcp:approve",),
        )
        return world.client.post(
            "/mcp/overrides",
            json={
                "version": "1",
                "approval_id": approval_id,
                "session_id": _SESSION,
                "action_key": action_key,
                "kind": "config_change",
                "target_scope": "session",
                "expires_at_ns": _NOW_NS + 10_000_000_000,
                "reason_code": "CONFIG_CHANGE_REVIEWED",
            },
        )

    first = approve("operator-1", "Operator", "approval-operator", "config-change-1")
    assert first.status_code == 200, first.text
    world.current[0] = _principal(world.verifier, subject="operator-1", role="Operator")
    one_approval = world.client.post(
        "/mcp/actions", json=action, headers={"Idempotency-Key": "config-change-1"}
    )
    assert one_approval.status_code == 200
    assert one_approval.json()["allowed"] is False
    approve2a = approve("operator-1", "Operator", "approval-operator-2", "config-change-2")
    assert approve2a.status_code == 200, approve2a.text
    approve2b = approve("risk-1", "RiskOfficer", "approval-risk-2", "config-change-2")
    assert approve2b.status_code == 200, approve2b.text
    world.current[0] = _principal(world.verifier, subject="operator-1", role="Operator")
    approved = world.client.post(
        "/mcp/actions",
        json={**action, "action_idempotency_key": "config-change-2"},
        headers={"Idempotency-Key": "config-change-2"},
    )
    assert approved.status_code == 200
    assert approved.json()["allowed"] is True
    assert approved.json()["effect_allowed"] is False
    assert world.executor_calls == []


def test_denied_approval_is_not_reported_as_applied_and_has_a_stable_code(
    control_app: Any,
) -> None:
    world = control_app
    _create_world(world)
    world.current[0] = _principal(world.verifier, scopes=("mcp:approve",))
    response = world.client.post(
        "/mcp/overrides",
        json={
            "version": "1",
            "approval_id": "approval-no-action",
            "session_id": _SESSION,
            "action_key": "missing-action",
            "kind": "approve",
            "target_scope": "session",
            "expires_at_ns": _NOW_NS + 10_000_000_000,
            "reason_code": "REVIEWED",
        },
    )
    assert response.status_code == 403, response.text
    body = response.json()
    assert body["applied"] is False
    assert body["code"] == "ACTION_NOT_APPROVABLE"
    denial = world.runtime.snapshot.audit_events[-1]
    assert denial.kind == "approval_denied"
    assert denial.reason_codes == ("ACTION_NOT_APPROVABLE",)


def test_patch_override_requires_approve_scope(control_app: Any) -> None:
    world = control_app
    _create_world(world)
    world.current[0] = _principal(world.verifier, scopes=("mcp:write",))
    response = world.client.patch(
        f"/mcp/sessions/{_SESSION}",
        json={
            "version": "1",
            "approval_id": "approval-patch-scope",
            "session_id": _SESSION,
            "kind": "revoke",
            "target_scope": "session",
            "expires_at_ns": _NOW_NS + 10_000_000_000,
            "reason_code": "REVIEWED",
        },
    )
    assert response.status_code == 403
    assert response.json() == {"detail": "SCOPE_DENIED"}
    assert world.runtime.snapshot.sessions[0].state == "running"


@pytest.mark.parametrize("method", ("post", "patch"))
def test_halt_kind_approval_never_applies_only_to_local_control_state(
    control_app: Any, method: str
) -> None:
    world = control_app
    _create_world(world)
    world.current[0] = _principal(
        world.verifier,
        subject="risk-halt-approver",
        role="RiskOfficer",
        scopes=("mcp:approve", "mcp:write", "mcp:halt"),
    )
    halt_reasons: list[str] = []
    original_engage = world.halt.engage

    def record_halt_reason(reason: str) -> None:
        halt_reasons.append(reason)
        original_engage(reason)

    world.halt.engage = record_halt_reason  # type: ignore[method-assign]
    body = {
        "version": "1",
        "approval_id": f"approval-halt-{method}",
        "session_id": _SESSION,
        "kind": "halt",
        "target_scope": "all",
        "expires_at_ns": _NOW_NS + 10_000_000_000,
        "reason_code": "CALLER_FORGED_REASON",
    }
    response = (
        world.client.post("/mcp/overrides", json=body)
        if method == "post"
        else world.client.patch(f"/mcp/sessions/{_SESSION}", json=body)
    )
    if response.status_code == 200 and response.json().get("applied") is True:
        assert world.halt.halted is True
        assert halt_reasons == ["operator_halt"]
    else:
        assert response.status_code in {403, 409, 422, 503}
        assert "CALLER_FORGED_REASON" not in response.text
        assert "approval-halt" not in response.text
        assert halt_reasons == []
    assert world.runtime.snapshot.halted_org_ids == ()


@pytest.mark.parametrize("method", ("post_halts", "post_override"))
def test_operator_with_halt_and_approve_scopes_cannot_engage_halt(
    control_app: Any, method: str
) -> None:
    world = control_app
    _create_world(world)
    world.current[0] = _principal(
        world.verifier,
        subject="operator-halt-canary",
        role="Operator",
        scopes=("mcp:approve", "mcp:halt"),
    )
    calls: list[str] = []
    original_engage = world.halt.engage

    def record_halt_reason(reason: str) -> None:
        calls.append(reason)
        original_engage(reason)

    world.halt.engage = record_halt_reason  # type: ignore[method-assign]
    if method == "post_halts":
        response = world.client.post(
            "/mcp/halts",
            json={"version": "1", "reason_code": "OPERATOR_CANARY", "scope": "all"},
        )
    else:
        response = world.client.post(
            "/mcp/overrides",
            json={
                "version": "1",
                "approval_id": "operator-halt-approval-canary",
                "session_id": _SESSION,
                "kind": "halt",
                "target_scope": "all",
                "expires_at_ns": _NOW_NS + 10_000_000_000,
                "reason_code": "OPERATOR_CANARY",
            },
        )
    assert response.status_code == 403, response.text
    assert calls == []
    assert world.halt.halted is False
    assert world.runtime.snapshot.halted_org_ids == ()
    assert "OPERATOR_CANARY" not in response.text
    assert "operator-halt-approval-canary" not in response.text


def test_approved_halt_is_attributed_audited_and_approval_cannot_replay(
    control_app: Any,
) -> None:
    world = control_app
    _create_world(world)
    actor = "risk-halt-auditor"
    world.current[0] = _principal(
        world.verifier,
        subject=actor,
        role="RiskOfficer",
        scopes=("mcp:approve", "mcp:halt"),
    )
    calls: list[str] = []
    original_engage = world.halt.engage

    def record_halt_reason(reason: str) -> None:
        calls.append(reason)
        original_engage(reason)

    world.halt.engage = record_halt_reason  # type: ignore[method-assign]
    body = {
        "version": "1",
        "approval_id": "one-use-halt-approval",
        "session_id": _SESSION,
        "action_key": None,
        "kind": "halt",
        "target_scope": "all",
        "expires_at_ns": _NOW_NS + 10_000_000_000,
        "reason_code": "CALLER_REASON_MUST_NOT_BE_AUDITED",
    }
    applied = world.client.post("/mcp/overrides", json=body)
    assert applied.status_code == 200, applied.text
    assert applied.json()["applied"] is True
    assert applied.json()["approval_id"] == body["approval_id"]
    assert calls == ["operator_halt"]
    event = world.runtime.snapshot.audit_events[-1]
    assert event.version == "2"
    assert event.kind == "halt_engaged"
    assert event.reason_codes == ("OPERATOR_HALT",)
    assert event.actor_principal_id == actor
    assert event.subject_id == _ORG
    assert "CALLER_REASON_MUST_NOT_BE_AUDITED" not in repr(event)

    halt_event_ids = tuple(
        item.event_id for item in world.runtime.snapshot.audit_events if item.kind == "halt_engaged"
    )
    replay = world.client.post("/mcp/overrides", json=body)
    assert replay.status_code in {403, 404, 409}
    assert replay.json().get("applied") is not True
    assert "one-use-halt-approval" not in replay.text
    assert calls == ["operator_halt"]
    assert (
        tuple(
            item.event_id
            for item in world.runtime.snapshot.audit_events
            if item.kind == "halt_engaged"
        )
        == halt_event_ids
    )
    assert world.halt.halted is True


def test_halt_audit_sink_failure_prevents_engagement(
    control_app: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    world = control_app
    _create_world(world)
    world.current[0] = _principal(
        world.verifier,
        subject="risk-halt-audit-failure",
        role="RiskOfficer",
        scopes=("mcp:approve", "mcp:halt"),
    )
    before = world.runtime.snapshot
    calls: list[str] = []
    original_engage = world.halt.engage

    def record_halt_reason(reason: str) -> None:
        calls.append(reason)
        original_engage(reason)

    world.halt.engage = record_halt_reason  # type: ignore[method-assign]

    def fail_audit(*args: Any, **kwargs: Any) -> ControlSnapshotV1:
        del args, kwargs
        raise RuntimeError("halt-audit-sink-canary")

    monkeypatch.setattr(_mcp_control_router, "record_halt_approval", fail_audit)
    response = world.client.post(
        "/mcp/overrides",
        json={
            "version": "1",
            "approval_id": "halt-audit-failure-approval",
            "session_id": _SESSION,
            "action_key": None,
            "kind": "halt",
            "target_scope": "all",
            "expires_at_ns": _NOW_NS + 10_000_000_000,
            "reason_code": "CALLER_REASON",
        },
    )
    assert response.status_code == 503
    assert "halt-audit-sink-canary" not in response.text
    assert response.json().get("applied") is not True
    assert world.runtime.snapshot is before
    assert calls == []
    assert world.halt.halted is False


def test_halt_uses_authority_and_blocks_actions_without_any_resume_path(control_app: Any) -> None:
    world = control_app
    _create_world(world)
    calls: list[str] = []
    original_engage = world.halt.engage

    def engage(reason: str) -> None:
        calls.append(reason)
        original_engage(reason)

    world.halt.engage = engage  # type: ignore[method-assign]
    world.current[0] = _principal(
        world.verifier,
        subject="risk-1",
        role="RiskOfficer",
        scopes=("mcp:halt",),
    )
    payload = {"version": "1", "reason_code": "MCP_POLICY_HALT", "scope": "all"}
    first = world.client.post("/mcp/halts", json=payload)
    second = world.client.post("/mcp/halts", json=payload)
    assert first.status_code == second.status_code == 202
    assert world.halt.halted is True
    assert calls == ["operator_halt", "operator_halt"]
    assert not any(getattr(route, "path", None) == "/mcp/resume" for route in world.app.routes)
    world.context_flags["halt_clear"] = False
    world.current[0] = _principal(world.verifier, subject="operator-1", role="Operator")
    denied = world.client.post(
        "/mcp/actions",
        json=_action(action_idempotency_key="while-halted"),
        headers={"Idempotency-Key": "while-halted"},
    )
    assert denied.status_code == 409
    assert denied.json()["detail"] == "HALTED"
    before_dry_run = world.runtime.snapshot
    quota_before_dry_run = before_dry_run.sessions[0].quota_remaining
    violations_before_dry_run = before_dry_run.violations
    dry_denied = world.client.post(
        "/mcp/actions/dry-run",
        json={
            "version": "1",
            "action": _action(action_idempotency_key="dry-while-halted"),
        },
        headers={"Idempotency-Key": "dry-while-halted"},
    )
    assert dry_denied.status_code == 200
    dry_preview = dry_denied.json()
    assert dry_preview["allowed"] is False
    assert dry_preview["effect_allowed"] is False
    assert dry_preview["reason_codes"] == ["HALTED"]
    assert dry_preview["dry_run"] is True
    after_dry_run = world.runtime.snapshot
    assert len(after_dry_run.audit_events) == len(before_dry_run.audit_events) + 1
    dry_run_event = after_dry_run.audit_events[-1]
    assert dry_run_event.kind == "action_denied"
    assert dry_run_event.reason_codes == ("HALTED",)
    assert getattr(dry_run_event, "dry_run", None) is True
    assert after_dry_run.actions == before_dry_run.actions
    assert after_dry_run.sessions == before_dry_run.sessions
    assert after_dry_run.sessions[0].quota_remaining == quota_before_dry_run
    assert after_dry_run.violations == violations_before_dry_run
    assert after_dry_run.agents[0].status == "active"
    assert world.executor_calls == []


def test_audit_export_is_tenant_scoped_redacted_and_detects_chain_corruption(
    control_app: Any,
) -> None:
    world = control_app
    _create_world(world)
    world.client.post(
        "/mcp/actions",
        json=_action(resource=f"{_ORG}:private:CANARY"),
        headers={"Idempotency-Key": "action-fixture-1"},
    )
    response = world.client.get("/mcp/audit", params={"cursor": 0, "limit": 1})
    assert response.status_code == 200
    assert response.json()["chain_valid"] is True
    assert len(response.json()["events"]) == 1
    assert response.json()["next_cursor"] == 1
    serialized = response.text
    assert "synthetic-signed-attestation" not in serialized
    assert "attestation-leviathan" not in serialized
    assert "authorization" not in serialized.lower()

    world.current[0] = _principal(
        _verifier(org_id="org-other", project_id="desk-other"),
        subject="other-tenant-reader",
        scopes=("mcp:audit",),
        org_id="org-other",
    )
    other_tenant = world.client.get("/mcp/audit")
    assert other_tenant.status_code == 200
    assert other_tenant.json()["events"] == []
    assert other_tenant.json()["chain_valid"] is False
    world.current[0] = _principal(world.verifier, scopes=("mcp:audit",))

    # Chain mutation is test-only and must make the route fail closed.
    payload_entry = _state_models._SNAPSHOT_PAYLOADS[id(world.runtime.snapshot)]
    first_event = payload_entry[1].audit_events[0]
    object.__setattr__(first_event, "kind", "tamper-canary")
    corrupt = world.client.get("/mcp/audit")
    assert corrupt.status_code == 503
    assert corrupt.json()["detail"] == "AUDIT_UNAVAILABLE"


def test_audit_export_includes_v2_attribution_for_chain_recomputation(control_app: Any) -> None:
    world = control_app
    _create_world(world)
    actor = "audit-v2-operator"
    world.current[0] = _principal(world.verifier, subject=actor)

    denied = world.client.get("/mcp/audit", params={"limit": 0})
    assert denied.status_code == 422
    assert denied.json() == {"detail": "QUERY_INVALID"}
    recorded = world.runtime.snapshot.audit_events[-1]
    assert recorded.version == "2"
    assert recorded.actor_principal_id == actor
    assert recorded.subject_id == "UNKNOWN_SUBJECT"

    exported = world.client.get("/mcp/audit")
    assert exported.status_code == 200, exported.text
    rows = exported.json()["events"]
    matching = next(row for row in rows if row["event_id"] == recorded.event_id)
    assert matching["version"] == "2"
    assert matching["actor_principal_id"] == actor
    assert matching["subject_id"] == "UNKNOWN_SUBJECT"
    predecessor = GENESIS_HASH
    for expected_sequence, row in enumerate(rows):
        assert row["sequence"] == expected_sequence
        encoded = _event_bytes(
            version=row["version"],
            sequence=row["sequence"],
            org_id=row["org_id"],
            agent_id=row["agent_id"],
            session_id=row["session_id"],
            action_id=row["action_id"],
            kind=row["kind"],
            reason_codes=tuple(row["reason_codes"]),
            recorded_at_ns=row["recorded_at_ns"],
            actor_principal_id=row["actor_principal_id"],
            subject_id=row["subject_id"],
        )
        assert _event_hash(predecessor, encoded) == row["event_hash"]
        predecessor = row["event_hash"]
    assert verify_audit_chain(world.runtime.snapshot.audit_events) is True
    assert exported.json()["chain_valid"] is True


def test_order_route_tool_and_unapproved_effects_never_reach_executor(control_app: Any) -> None:
    world = control_app
    _create_world(world)
    result = world.client.post(
        "/mcp/actions",
        json=_action(
            action_idempotency_key="order-reserved",
            tool_id="orders.place",
            resource=f"{_ORG}:orders:XYZ",
            scope="market:execute",
            capability="execute",
        ),
        headers={"Idempotency-Key": "order-reserved"},
    )
    assert result.status_code == 200
    assert result.json()["allowed"] is False
    assert "ORDER_AUTHORITY_RESERVED" in result.json()["reason_codes"]
    assert result.json()["effect_allowed"] is False
    assert world.executor_calls == []


def test_unknown_runtime_and_untrusted_context_fail_closed(control_app: Any) -> None:
    world = control_app
    world.app.state.mcp_control_runtime = None
    absent = world.client.get("/mcp/tools", params={"agent_id": _AGENT, "session_id": _SESSION})
    assert absent.status_code == 503
    assert absent.json()["detail"] == "MCP_CONTROL_UNAVAILABLE"

    world.app.state.mcp_control_runtime = world.runtime
    world.runtime.context_resolver = lambda *args, **kwargs: None
    unavailable = world.client.get(
        "/mcp/tools", params={"agent_id": _AGENT, "session_id": _SESSION}
    )
    assert unavailable.status_code == 503
    assert unavailable.json()["detail"] == "TRUSTED_CONTEXT_UNAVAILABLE"
    assert world.runtime.snapshot.audit_events[-1].kind == "request_denied"
    assert world.runtime.snapshot.audit_events[-1].reason_codes == ("TRUSTED_CONTEXT_UNAVAILABLE",)


def test_trusted_context_binds_desk_to_verified_principal(control_app: Any) -> None:
    world = control_app
    original = world.runtime.context_resolver

    def wrong_desk(principal: VerifiedPrincipalV1, *, now_ns: int, **selectors: object):
        context = original(principal, now_ns=now_ns, **selectors)
        assert type(context) is PolicyContextV1
        fields = context.model_dump(mode="python")
        fields["desk_id"] = "desk-other"
        return PolicyContextV1._from_trusted_adapter(**fields)

    world.runtime.context_resolver = wrong_desk
    response = world.client.get("/mcp/tools", params={"agent_id": _AGENT, "session_id": _SESSION})
    assert response.status_code == 403
    assert response.json() == {"detail": "PRINCIPAL_SCOPE_MISMATCH"}
    assert world.runtime.snapshot.audit_events[-1].kind == "request_denied"
    assert world.runtime.snapshot.audit_events[-1].reason_codes == ("PRINCIPAL_SCOPE_MISMATCH",)


def test_session_body_cannot_exceed_trusted_quota_lifetime_or_elevation(
    control_app: Any,
) -> None:
    world = control_app
    _create_world(world)
    world.runtime.context_resolver = lambda principal, *, now_ns, **selectors: _context(
        now_ns,
        snapshot=world.runtime.snapshot,
        agent_id=str(selectors.get("agent_id") or _AGENT),
        session_id=str(selectors.get("session_id") or _SESSION),
        elevation_requires_approval=True,
    )
    response = world.client.post(
        "/mcp/sessions",
        json={
            "version": "1",
            "agent_id": _AGENT,
            "session_id": "session-bounded-body",
            "expires_at_ns": _NOW_NS + 101_000_000_000,
            "quota": 101,
            "scope_elevated": True,
        },
    )
    if response.status_code == 201:
        session = next(
            row
            for row in world.runtime.snapshot.sessions
            if row.session_id == "session-bounded-body"
        )
        attestation_expiry = world.runtime.snapshot.agents[0].attestation_expires_at_ns
        violations = []
        if session.quota_remaining > 100:
            violations.append("quota exceeded trusted rate limit")
        if session.expires_at_ns > attestation_expiry:
            violations.append("lifetime exceeded attestation validity")
        if session.state != "pending_approval" or session.scope_elevated is not True:
            violations.append("elevated scope was not held for approval")
        assert not violations, "; ".join(violations)
    else:
        assert response.status_code in {403, 409, 422}
        assert "session-bounded-body" not in response.text
        assert "101000000000" not in response.text
        assert not any(
            row.session_id == "session-bounded-body" for row in world.runtime.snapshot.sessions
        )

    elevated = {
        "version": "1",
        "agent_id": _AGENT,
        "session_id": "session-elevation-review",
        "expires_at_ns": _NOW_NS + 80_000_000_000,
        "quota": 50,
        "scope_elevated": True,
    }
    accepted = world.client.post("/mcp/sessions", json=elevated)
    assert accepted.status_code == 201, accepted.text
    pending = next(
        row
        for row in world.runtime.snapshot.sessions
        if row.session_id == "session-elevation-review"
    )
    assert pending.state == "pending_approval"
    assert pending.scope_elevated is True
    underclaimed = world.client.post(
        "/mcp/sessions",
        json={**elevated, "session_id": "session-elevation-unapproved", "scope_elevated": False},
    )
    assert underclaimed.status_code == 201, underclaimed.text
    non_elevated = next(
        row
        for row in world.runtime.snapshot.sessions
        if row.session_id == "session-elevation-unapproved"
    )
    assert non_elevated.scope_elevated is False
    assert non_elevated.state == "running"

    world.runtime.context_resolver = lambda principal, *, now_ns, **selectors: _context(
        now_ns,
        snapshot=world.runtime.snapshot,
        agent_id=str(selectors.get("agent_id") or _AGENT),
        session_id=str(selectors.get("session_id") or _SESSION),
    )
    ignored_elevation = world.client.post(
        "/mcp/sessions",
        json={
            "version": "1",
            "agent_id": _AGENT,
            "session_id": "session-elevation-not-trusted",
            "expires_at_ns": _NOW_NS + 80_000_000_000,
            "quota": 50,
            "scope_elevated": True,
        },
    )
    assert ignored_elevation.status_code == 201, ignored_elevation.text
    clamped = next(
        row
        for row in world.runtime.snapshot.sessions
        if row.session_id == "session-elevation-not-trusted"
    )
    assert clamped.scope_elevated is False
    assert clamped.state == "running"


def test_unknown_subject_denial_is_stable_and_audited(control_app: Any) -> None:
    world = control_app
    _create_world(world)
    result = world.client.post(
        "/mcp/actions",
        json=_action(
            agent_id="agent-unknown-subject",
            session_id="session-unknown-subject",
            action_idempotency_key="unknown-subject-action",
        ),
        headers={"Idempotency-Key": "unknown-subject-action"},
    )
    assert result.status_code == 200
    assert result.json()["allowed"] is False
    assert result.json()["effect_allowed"] is False
    assert result.json()["reason_codes"] == ["UNKNOWN_SUBJECT"]
    assert "agent-unknown-subject" not in result.text
    assert "session-unknown-subject" not in result.text
    event = world.runtime.snapshot.audit_events[-1]
    assert event.kind == "action_denied"
    assert event.reason_codes == ("UNKNOWN_SUBJECT",)
    assert event.agent_id == "UNKNOWN_SUBJECT"
    assert event.session_id is None
    assert event.action_id is None
    assert "agent-unknown-subject" not in repr(event)
    assert "session-unknown-subject" not in repr(event)


def test_audit_sink_failure_fails_closed_without_echo_or_state_change(
    control_app: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    world = control_app
    _create_world(world)
    before_events = world.runtime.snapshot.audit_events
    original_transition = _mcp_control_router.record_request_denial
    calls = 0

    def fail_once(*args: Any, **kwargs: Any):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("sink-secret-canary")
        return original_transition(*args, **kwargs)

    monkeypatch.setattr(_mcp_control_router, "record_request_denial", fail_once)
    result = world.client.get("/mcp/audit", params={"limit": 0})
    assert result.status_code == 503
    assert result.json() == {"detail": "AUDIT_UNAVAILABLE"}
    assert "sink-secret-canary" not in result.text
    assert calls >= 2
    assert len(world.runtime.snapshot.audit_events) == len(before_events) + 1
    assert world.runtime.snapshot.audit_events[-1].kind == "request_denied"
    assert world.runtime.snapshot.audit_events[-1].reason_codes == ("AUDIT_UNAVAILABLE",)
    assert world.executor_calls == []


def test_audit_query_errors_are_content_free_and_ids_are_bounded(control_app: Any) -> None:
    world = control_app
    _create_world(world)
    violations = []
    for params, canary in (
        ({"cursor": -1}, "-1"),
        ({"limit": 501}, "501"),
        ({"entity_id": "x" * 129}, "x" * 129),
    ):
        response = world.client.get("/mcp/audit", params=params)
        if (
            response.status_code != 422
            or response.json() != {"detail": "QUERY_INVALID"}
            or canary in response.text
        ):
            violations.append(f"audit query {tuple(params)} was not bounded/content-free")

    long_agent_id = "a" * 129
    response = world.client.get(
        "/mcp/tools", params={"agent_id": long_agent_id, "session_id": _SESSION}
    )
    if (
        response.status_code != 422
        or response.json() != {"detail": "REQUEST_INVALID"}
        or long_agent_id in response.text
    ):
        violations.append("overlong agent selector was not rejected content-free")
    assert not violations, "; ".join(violations)


def test_approval_identifiers_do_not_reveal_other_tenant_state(control_app: Any) -> None:
    world = control_app
    _create_world(world)
    body = {
        "version": "1",
        "approval_id": "tenant-collision-canary",
        "session_id": _SESSION,
        "action_key": "tenant-action",
        "kind": "config_change",
        "target_scope": "session",
        "expires_at_ns": _NOW_NS + 10_000_000_000,
        "reason_code": "REVIEWED",
    }
    world.current[0] = _principal(world.verifier, scopes=("mcp:approve",))
    first = world.client.post("/mcp/overrides", json=body)
    assert first.status_code == 200

    world.current[0] = _principal(
        _verifier(org_id="org-other", project_id="desk-other"),
        subject="other-tenant-approver",
        scopes=("mcp:approve",),
        org_id="org-other",
    )
    duplicate = world.client.post("/mcp/overrides", json=body)
    unknown = world.client.post(
        "/mcp/overrides", json={**body, "approval_id": "tenant-unknown-canary"}
    )
    assert duplicate.status_code in {403, 404}
    assert duplicate.content == unknown.content
    assert "tenant-collision-canary" not in duplicate.text
    assert "tenant-unknown-canary" not in unknown.text


def test_grant_requires_matching_agent_binding_and_audits_denial(
    control_app: Any,
) -> None:
    world = control_app
    _create_world(world)
    before_count = len(world.runtime.snapshot.audit_events)
    world.runtime.grant_resolver = lambda principal, payload, context, *, now_ns: _grant(
        now_ns, agent_id="agent-other", session_id=payload.session_id
    )
    response = world.client.post(
        "/mcp/tools/grant",
        json={
            "version": "1",
            "session_id": _SESSION,
            "tool_id": _TOOL,
            "scope_subset": _SCOPE,
            "ttl_ns": 1_000_000_000,
        },
    )
    violations = []
    if response.status_code != 403:
        violations.append("mismatched agent grant was not denied")
    if "agent-other" in response.text:
        violations.append("grant denial echoed a foreign subject")
    if len(world.runtime.snapshot.audit_events) <= before_count:
        violations.append("grant denial was not audited")
    elif world.runtime.snapshot.audit_events[-1].kind != "grant_denied":
        violations.append("grant denial event kind was unstable")
    assert not violations, "; ".join(violations)
