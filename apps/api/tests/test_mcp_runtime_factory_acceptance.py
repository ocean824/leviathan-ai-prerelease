"""Independent acceptance for the fail-closed MCP runtime factory."""

from __future__ import annotations

import base64
import hashlib
import json
import math
import random
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from leviathan_api.mcp_runtime_factory import (
    McpRuntimeFactoryConfigV1,
    McpRuntimeFactoryError,
    build_mcp_control,
)
from leviathan_api.routers.mcp_control import McpControlRuntime, router
from leviathan_api.security.mcp_principal_resolver import McpPrincipalResolverV1
from leviathan_core.mcp_control.control_service import (
    empty_control_snapshot,
    record_request_denial,
    register_agent,
    start_session,
)
from leviathan_core.mcp_control.policy_models import (
    PolicyContextV1,
    ToolGrantV1,
    ToolRegistrationV1,
)
from leviathan_core.mcp_control.state_models import CONTROL_VERSION, AttestationEvidenceV1
from leviathan_core.risk.halt import HaltAuthority
from leviathan_core.security.principal_verifier import (
    PrincipalVerifier,
    RSAPublicKeyV1,
    TrustedIssuerV1,
    VerifiedPrincipalV1,
)

_NOW = datetime(2026, 10, 6, 18, 0, tzinfo=UTC)
_NOW_SECONDS = int(_NOW.timestamp())
_NOW_NS = _NOW_SECONDS * 1_000_000_000
_ISSUER = "factory.synthetic"
_AUDIENCE = "mcp.synthetic"
_ORG = "org.synthetic"
_PROJECT = "desk.synthetic"
_ENV = "test"
_KID = "factory-test-key"
_CERT = b"synthetic TLS client certificate"
_TOKEN_CANARY = "factory-token-secret-canary-5c2a"
_DER_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")
_NO_STORE = "no-store"


def _prime(rng: random.Random) -> int:
    """Generate an ephemeral test-only probable prime."""
    while True:
        candidate = rng.getrandbits(1024) | (3 << 1022) | 1
        if any(candidate % divisor == 0 for divisor in (3, 5, 7, 11, 13, 17, 19, 23, 29)):
            continue
        odd_part = candidate - 1
        powers_of_two = 0
        while odd_part % 2 == 0:
            powers_of_two += 1
            odd_part //= 2
        for base in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
            residue = pow(base, odd_part, candidate)
            if residue in (1, candidate - 1):
                continue
            for _ in range(powers_of_two - 1):
                residue = pow(residue, 2, candidate)
                if residue == candidate - 1:
                    break
            else:
                break
        else:
            return candidate


def _generate_rsa_key() -> tuple[RSAPublicKeyV1, int]:
    rng = random.Random(0x4D435046)
    p, q = _prime(rng), _prime(rng)
    while p == q or math.gcd(65537, (p - 1) * (q - 1)) != 1:
        q = _prime(rng)
    modulus = p * q
    return RSAPublicKeyV1(modulus, 65537), pow(65537, -1, (p - 1) * (q - 1))


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _segment(value: object) -> str:
    return _b64(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def _verifier(key: RSAPublicKeyV1) -> PrincipalVerifier:
    class _KeySet:
        def get_key(self, issuer: str, kid: str) -> RSAPublicKeyV1 | None:
            return key if (issuer, kid) == (_ISSUER, _KID) else None

    class _Revocations:
        def is_revoked(self, _issuer: str, _jti: str) -> bool:
            return False

    return PrincipalVerifier(
        trusted_issuer=TrustedIssuerV1(_ISSUER, _AUDIENCE, _ORG, _PROJECT, _ENV),
        key_set=_KeySet(),
        revocations=_Revocations(),
        clock=lambda: _NOW,
    )


def _token(
    key: tuple[RSAPublicKeyV1, int],
    *,
    subject: str = "operator.synthetic",
    scopes: tuple[str, ...] = ("mcp:read", "mcp:write", "mcp:audit"),
    role: str = "mcp.reader",
    jti: str = "synthetic-jti-1",
    invalid_signature: bool = False,
) -> str:
    public_key, private_exponent = key
    header = _segment({"alg": "RS256", "kid": _KID, "typ": "JWT"})
    payload = _segment(
        {
            "iss": _ISSUER,
            "aud": _AUDIENCE,
            "org": _ORG,
            "sub": subject,
            "role": role,
            "scope": list(scopes),
            "env": _ENV,
            "jti": jti,
            "iat": _NOW_SECONDS - 1,
            "nbf": _NOW_SECONDS - 1,
            "exp": _NOW_SECONDS + 300,
            "cnf": {"x5t#S256": _b64(hashlib.sha256(_CERT).digest())},
        }
    )
    signed = f"{header}.{payload}".encode("ascii")
    digest_info = _DER_PREFIX + hashlib.sha256(signed).digest()
    width = (public_key.modulus.bit_length() + 7) // 8
    padding = width - len(digest_info) - 3
    encoded = b"\x00\x01" + b"\xff" * padding + b"\x00" + digest_info
    signature = pow(int.from_bytes(encoded, "big"), private_exponent, public_key.modulus)
    signature_bytes = signature.to_bytes(width, "big")
    if invalid_signature:
        signature_bytes = bytes([signature_bytes[0] ^ 1]) + signature_bytes[1:]
    return f"{header}.{payload}.{_b64(signature_bytes)}"


def _context(*, agent_id: str, session_id: str) -> PolicyContextV1:
    tool = ToolRegistrationV1(
        org_id=_ORG,
        tool_id="quotes.read",
        resource_pattern=f"{_ORG}:quotes:*",
        tool_class="data",
        capabilities=frozenset({"read"}),
        environments=frozenset({"paper"}),
        scope="market:read",
        bridge_required=False,
        order_or_route=False,
        financial=False,
        config_change=False,
        data_egress=False,
    )
    return PolicyContextV1._from_trusted_adapter(
        version="1",
        org_id=_ORG,
        desk_id=_PROJECT,
        agent_id=agent_id,
        session_id=session_id,
        evaluation_time_ns=_NOW_NS,
        principal_verified=True,
        attestation_verified=True,
        session_active=True,
        halt_clear=True,
        risk_snapshot_at_ns=_NOW_NS,
        risk_snapshot_max_age_ns=10_000_000_000,
        bridge_online=True,
        tools=(tool,),
        global_max_notional=None,
        global_max_leverage=None,
        live_financial_enabled=False,
        market_open=True,
        liquidity_ok=True,
        egress_allowed=True,
        allowed_egress_domains=(),
        config_approvals=(),
        rate_remaining=100,
        max_session_quota=100,
        max_session_lifetime_ns=100_000_000_000,
        elevation_requires_approval=False,
        allowed_venues=(),
        blocked_symbols=(),
        allowed_order_types=(),
    )


class _AuditSink:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.events: list[object] = []
        self.batch_calls: list[tuple[object, ...]] = []
        self.runtime: McpControlRuntime | None = None
        self.snapshots_at_append: list[object] = []

    def append_batch(self, events: tuple[object, ...]) -> None:
        self.batch_calls.append(events)
        if self.runtime is not None:
            self.snapshots_at_append.append(self.runtime.snapshot)
        if self.fail:
            raise RuntimeError(_TOKEN_CANARY)
        self.events.extend(events)


def _runtime(
    *,
    context_resolver: Any,
    halt_authority: HaltAuthority | None = None,
    audit_sink: Any = None,
    grants_resolver: Any = None,
    snapshot: Any = None,
    allow_unaudited_for_tests: bool = False,
) -> McpControlRuntime:
    return McpControlRuntime(
        context_resolver=context_resolver,
        grants_resolver=grants_resolver or (lambda _principal, _session_id, *, now_ns: ()),
        attestation_resolver=lambda _principal, payload, *, now_ns: (
            AttestationEvidenceV1._from_trusted_adapter(
                version=CONTROL_VERSION,
                attestation_id=f"attestation-{payload.agent_id}",
                org_id=_ORG,
                desk_id=_PROJECT,
                agent_id=payload.agent_id,
                origin=payload.origin,
                signature_digest="a" * 64,
                issued_at_ns=now_ns,
                expires_at_ns=now_ns + 100_000_000_000,
            )
        ),
        approval_resolver=lambda *_args, **_kwargs: None,
        halt_authority=halt_authority or HaltAuthority(clock=lambda: _NOW),
        snapshot=snapshot or empty_control_snapshot(),
        now_ns=lambda: _NOW_NS,
        audit_sink=audit_sink,
        allow_unaudited_for_tests=allow_unaudited_for_tests,
    )


def _context_resolver(seen: list[str] | None = None, *, unavailable: bool = False):
    def resolve(principal: VerifiedPrincipalV1, *, now_ns: int, **selectors: object):
        if seen is not None:
            seen.append(principal.subject_id)
        if unavailable:
            return None
        return _context(
            agent_id=str(selectors.get("agent_id") or "agent.synthetic"),
            session_id=str(selectors.get("session_id") or "session.synthetic"),
        )

    return resolve


def _app(
    key: tuple[RSAPublicKeyV1, int],
    *,
    scopes: tuple[str, ...] = ("mcp:read", "mcp:write", "mcp:audit"),
    sink: _AuditSink | None = None,
    context_resolver: Any = None,
    resolver: Any = None,
    middleware_principal: VerifiedPrincipalV1 | None = None,
    token: str | None = None,
    grants_resolver: Any = None,
    snapshot: Any = None,
    allow_unaudited_for_tests: bool = False,
    halt_authority: HaltAuthority | None = None,
):
    seen: list[str] = []
    audit = sink if sink is not None else _AuditSink()
    selected_resolver = (
        resolver if resolver is not None else McpPrincipalResolverV1(_verifier(key[0]))
    )
    runtime = _runtime(
        context_resolver=context_resolver or _context_resolver(seen),
        grants_resolver=grants_resolver,
        snapshot=snapshot,
        allow_unaudited_for_tests=allow_unaudited_for_tests,
        halt_authority=halt_authority,
    )
    binding = build_mcp_control(
        McpRuntimeFactoryConfigV1(runtime=runtime, resolver=selected_resolver, audit=audit)
    )
    audit.runtime = runtime
    app = FastAPI()

    @app.middleware("http")
    async def inject_synthetic_transport(request, call_next):
        request.scope["extensions"] = {"tls": {"client_cert_der": _CERT}}
        if middleware_principal is not None:
            request.state.verified_principal = middleware_principal
        return await call_next(request)

    app.state.mcp_control_runtime = binding.runtime
    app.state.mcp_control_principal_resolver = binding.principal_resolver
    app.include_router(binding.router)
    return SimpleNamespace(
        app=app,
        binding=binding,
        runtime=runtime,
        sink=audit,
        seen=seen,
        token=token or _token(key, scopes=scopes),
    )


@pytest.fixture(scope="module")
def _key() -> tuple[RSAPublicKeyV1, int]:
    return _generate_rsa_key()


def _assert_no_store(response) -> None:
    assert response.headers.get("cache-control") == _NO_STORE


def _approved_action_world(
    key: tuple[RSAPublicKeyV1, int], *, sink: _AuditSink, subject: str
) -> tuple[Any, dict[str, object]]:
    agent_id, session_id = "agent.synthetic", "session.real-action"
    context = _context(agent_id=agent_id, session_id=session_id)
    attestation = AttestationEvidenceV1._from_trusted_adapter(
        version=CONTROL_VERSION,
        attestation_id="attestation-real-action",
        org_id=_ORG,
        desk_id=_PROJECT,
        agent_id=agent_id,
        origin="LEVIATHAN",
        signature_digest="a" * 64,
        issued_at_ns=_NOW_NS,
        expires_at_ns=_NOW_NS + 100_000_000_000,
    )
    snapshot = register_agent(
        empty_control_snapshot(), context=context, attestation=attestation, now_ns=_NOW_NS
    )
    snapshot = start_session(
        snapshot,
        context=context,
        expires_at_ns=_NOW_NS + 90_000_000_000,
        quota=5,
        scope_elevated=False,
        now_ns=_NOW_NS,
    )
    grant = ToolGrantV1._from_trusted_adapter(
        version=CONTROL_VERSION,
        grant_id="grant-real-action",
        org_id=_ORG,
        desk_id=_PROJECT,
        agent_id=agent_id,
        session_id=session_id,
        tool_id="quotes.read",
        resource_pattern=f"{_ORG}:quotes:*",
        scope="market:read",
        capabilities=frozenset({"read"}),
        environments=frozenset({"paper"}),
        expires_at_ns=_NOW_NS + 90_000_000_000,
        issued_at_ns=_NOW_NS - 1,
        max_notional=None,
        max_leverage=None,
        deny=False,
    )
    world = _app(
        key,
        sink=sink,
        context_resolver=lambda _principal, *, now_ns, **_selectors: context,
        grants_resolver=lambda _principal, _session_id, *, now_ns: (grant,),
        snapshot=snapshot,
        token=_token(key, subject=subject),
    )
    action: dict[str, object] = {
        "version": "1",
        "org_id": _ORG,
        "desk_id": _PROJECT,
        "agent_id": agent_id,
        "session_id": session_id,
        "environment": "paper",
        "action_idempotency_key": "approved-real-action",
        "tool_id": "quotes.read",
        "resource": f"{_ORG}:quotes:SYNTH",
        "scope": "market:read",
        "capability": "read",
        "timestamp_ns": _NOW_NS,
    }
    return world, action


def test_only_bearer_token_supplies_identity_not_headers_body_query_or_middleware(
    _key: tuple[RSAPublicKeyV1, int],
) -> None:
    verifier = _verifier(_key[0])
    middleware_principal = verifier.verify(
        _token(_key, subject="middleware.forged", scopes=("mcp:read",)),
        peer_certificate_der=_CERT,
    )
    world = _app(_key, middleware_principal=middleware_principal)
    request_token = _token(_key, subject="bearer.operator", scopes=("mcp:read",))

    with TestClient(world.app) as client:
        response = client.request(
            "GET",
            "/mcp/tools",
            params={
                "agent_id": "agent.synthetic",
                "session_id": "session.synthetic",
                "principal_id": "query.forgery",
                "role": "RiskOfficer",
                "org_id": "org.attacker",
            },
            json={
                "principal_id": "body.forgery",
                "role": "System",
                "org_id": "org.attacker",
                "approval": True,
                "entitlement": "admin",
            },
            headers={
                "Authorization": f"Bearer {request_token}",
                "X-Principal-ID": "header.forgery",
                "X-Role": "System",
                "X-Org-ID": "org.attacker",
            },
        )

    assert response.status_code == 200, response.text
    assert world.seen == ["bearer.operator"]
    assert world.seen[0] != middleware_principal.subject_id
    _assert_no_store(response)


def test_missing_or_malformed_bearer_fails_closed_with_no_store_and_no_canary(
    _key: tuple[RSAPublicKeyV1, int], caplog: pytest.LogCaptureFixture
) -> None:
    world = _app(_key)
    with TestClient(world.app) as client:
        missing = client.get(
            "/mcp/tools",
            params={"agent_id": "agent.synthetic", "session_id": "session.synthetic"},
            headers={"X-MCP-Token": _TOKEN_CANARY},
        )
        malformed = client.get(
            "/mcp/tools",
            params={"agent_id": "agent.synthetic", "session_id": "session.synthetic"},
            headers={"Authorization": f"Bearer {_TOKEN_CANARY}"},
        )
        basic = client.get(
            "/mcp/tools",
            params={"agent_id": "agent.synthetic", "session_id": "session.synthetic"},
            headers={"Authorization": f"Basic {_TOKEN_CANARY}"},
        )

    for response in (missing, malformed, basic):
        assert response.status_code == 401
        assert response.json() == {"detail": "UNAUTHENTICATED"}
        _assert_no_store(response)
    assert _TOKEN_CANARY not in caplog.text
    assert all(_TOKEN_CANARY not in response.text for response in (missing, malformed, basic))


def test_missing_factory_ports_have_fixed_error_and_no_binding(
    _key: tuple[RSAPublicKeyV1, int],
) -> None:
    runtime = _runtime(context_resolver=_context_resolver())
    verifier = McpPrincipalResolverV1(_verifier(_key[0]))

    for config in (
        McpRuntimeFactoryConfigV1(runtime=runtime, resolver=verifier, audit=None),
        McpRuntimeFactoryConfigV1(runtime=runtime, resolver=None, audit=_AuditSink()),
    ):
        with pytest.raises(McpRuntimeFactoryError) as raised:
            build_mcp_control(config)
        assert raised.value.code == "MCP_CONTROL_UNAVAILABLE"
        assert str(raised.value) == "MCP_CONTROL_UNAVAILABLE"

    app = FastAPI()
    app.include_router(router)
    with TestClient(app) as client:
        response = client.get("/mcp/tools")

    assert response.status_code == 503
    assert response.json() == {"detail": "MCP_CONTROL_UNAVAILABLE"}
    _assert_no_store(response)


def test_verifier_unavailable_and_verifier_exception_are_fixed_503s(
    _key: tuple[RSAPublicKeyV1, int], caplog: pytest.LogCaptureFixture
) -> None:
    unavailable = _app(_key, resolver=McpPrincipalResolverV1(None))
    broken_resolver = SimpleNamespace(
        resolve_verified=lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RuntimeError(_TOKEN_CANARY)
        )
    )
    broken = _app(_key, resolver=broken_resolver)

    responses = []
    for world in (unavailable, broken):
        with TestClient(world.app) as client:
            responses.append(
                client.get(
                    "/mcp/tools",
                    params={"agent_id": "agent.synthetic", "session_id": "session.synthetic"},
                    headers={"Authorization": f"Bearer {world.token}"},
                )
            )

    for response in responses:
        assert response.status_code == 503
        assert response.json() == {"detail": "MCP_CONTROL_UNAVAILABLE"}
        assert _TOKEN_CANARY not in response.text
        _assert_no_store(response)
    assert _TOKEN_CANARY not in caplog.text


def test_audit_append_precedes_snapshot_commit(
    _key: tuple[RSAPublicKeyV1, int],
) -> None:
    sink = _AuditSink()
    world = _app(_key, sink=sink)
    before = world.runtime.snapshot

    with TestClient(world.app) as client:
        response = client.post(
            "/mcp/agents/register",
            json={
                "version": "1",
                "agent_id": "agent.synthetic",
                "display_label": "Synthetic Agent",
                "origin": "LEVIATHAN",
                "attestation": "synthetic-attestation",
            },
            headers={"Authorization": f"Bearer {world.token}"},
        )

    assert response.status_code == 201, response.text
    assert sink.events
    assert sink.snapshots_at_append
    assert sink.batch_calls == [(world.runtime.snapshot.audit_events[-1],)]
    assert all(snapshot is before for snapshot in sink.snapshots_at_append)
    assert world.runtime.snapshot is not before
    assert len(world.runtime.snapshot.agents) == 1
    _assert_no_store(response)


def test_audit_only_accepted_dry_run_does_not_consume_later_real_submit(
    _key: tuple[RSAPublicKeyV1, int],
) -> None:
    agent_id, session_id = "agent.synthetic", "session.dry-run"
    context = _context(agent_id=agent_id, session_id=session_id)
    attestation = AttestationEvidenceV1._from_trusted_adapter(
        version=CONTROL_VERSION,
        attestation_id="attestation-dry-run",
        org_id=_ORG,
        desk_id=_PROJECT,
        agent_id=agent_id,
        origin="LEVIATHAN",
        signature_digest="a" * 64,
        issued_at_ns=_NOW_NS,
        expires_at_ns=_NOW_NS + 100_000_000_000,
    )
    snapshot = register_agent(
        empty_control_snapshot(),
        context=context,
        attestation=attestation,
        now_ns=_NOW_NS,
    )
    snapshot = start_session(
        snapshot,
        context=context,
        expires_at_ns=_NOW_NS + 90_000_000_000,
        quota=5,
        scope_elevated=False,
        now_ns=_NOW_NS,
    )
    grant = ToolGrantV1._from_trusted_adapter(
        version=CONTROL_VERSION,
        grant_id="grant-dry-run",
        org_id=_ORG,
        desk_id=_PROJECT,
        agent_id=agent_id,
        session_id=session_id,
        tool_id="quotes.read",
        resource_pattern=f"{_ORG}:quotes:*",
        scope="market:read",
        capabilities=frozenset({"read"}),
        environments=frozenset({"paper"}),
        expires_at_ns=_NOW_NS + 90_000_000_000,
        issued_at_ns=_NOW_NS - 1,
        max_notional=None,
        max_leverage=None,
        deny=False,
    )
    sink = _AuditSink()
    world = _app(
        _key,
        sink=sink,
        context_resolver=lambda _principal, *, now_ns, **_selectors: context,
        grants_resolver=lambda _principal, _session_id, *, now_ns: (grant,),
        snapshot=snapshot,
    )
    action = {
        "version": "1",
        "org_id": _ORG,
        "desk_id": _PROJECT,
        "agent_id": agent_id,
        "session_id": session_id,
        "environment": "paper",
        "action_idempotency_key": "dry-run-then-submit",
        "tool_id": "quotes.read",
        "resource": f"{_ORG}:quotes:SYNTH",
        "scope": "market:read",
        "capability": "read",
        "timestamp_ns": _NOW_NS,
    }
    headers = {"Authorization": f"Bearer {world.token}"}
    original = world.runtime.snapshot

    with TestClient(world.app) as client:
        dry_run = client.post(
            "/mcp/actions/dry-run",
            json={"version": "1", "action": action},
            headers={**headers, "Idempotency-Key": action["action_idempotency_key"]},
        )

    assert dry_run.status_code == 200, dry_run.text
    assert dry_run.json()["allowed"] is True
    after_dry_run = world.runtime.snapshot
    assert after_dry_run.actions == original.actions
    assert after_dry_run.sessions == original.sessions
    assert after_dry_run.outbox_event_ids == original.outbox_event_ids
    assert after_dry_run.audit_events[-1].kind == "action_dry_run"
    assert len(sink.events) == 1
    _assert_no_store(dry_run)

    with TestClient(world.app) as client:
        submitted = client.post(
            "/mcp/actions",
            json=action,
            headers={**headers, "Idempotency-Key": action["action_idempotency_key"]},
        )

    assert submitted.status_code == 200, submitted.text
    assert submitted.json()["allowed"] is True
    assert world.runtime.snapshot.actions[-1].state == "approved"
    assert world.runtime.snapshot.sessions[0].quota_remaining == 4
    _assert_no_store(submitted)


def test_real_approved_action_is_audited_before_commit_and_fails_closed(
    _key: tuple[RSAPublicKeyV1, int],
) -> None:
    class FailBeforeAppend(_AuditSink):
        def append_batch(self, events: tuple[object, ...]) -> None:
            self.batch_calls.append(events)
            if self.runtime is not None:
                self.snapshots_at_append.append(self.runtime.snapshot)
            raise RuntimeError(_TOKEN_CANARY)

    failing_sink = FailBeforeAppend()
    failing_world, action = _approved_action_world(_key, sink=failing_sink, subject="approved.fail")
    original = failing_world.runtime.snapshot
    original_outbox_event_ids = original.outbox_event_ids
    with TestClient(failing_world.app) as client:
        failed = client.post(
            "/mcp/actions",
            json=action,
            headers={
                "Authorization": f"Bearer {failing_world.token}",
                "Idempotency-Key": str(action["action_idempotency_key"]),
            },
        )

    assert failed.status_code == 503
    assert failed.json().get("allowed") is False
    assert failed.json().get("detail") == "AUDIT_UNAVAILABLE"
    assert failing_sink.events == []
    assert len(failing_sink.batch_calls) == 1
    assert tuple(event.kind for event in failing_sink.batch_calls[0]) == ("action_approved",)
    assert failing_sink.snapshots_at_append == [original]
    assert failing_world.runtime.snapshot is original
    assert original.actions == ()
    assert failing_world.runtime.snapshot.outbox_event_ids == original_outbox_event_ids
    _assert_no_store(failed)

    healthy_sink = _AuditSink()
    healthy_world, healthy_action = _approved_action_world(
        _key, sink=healthy_sink, subject="approved.ok"
    )
    healthy_original = healthy_world.runtime.snapshot
    with TestClient(healthy_world.app) as client:
        approved = client.post(
            "/mcp/actions",
            json=healthy_action,
            headers={
                "Authorization": f"Bearer {healthy_world.token}",
                "Idempotency-Key": str(healthy_action["action_idempotency_key"]),
            },
        )

    assert approved.status_code == 200, approved.text
    assert approved.json()["allowed"] is True
    assert [event.kind for event in healthy_sink.events] == ["action_approved"]
    assert len(healthy_sink.batch_calls) == 1
    assert healthy_sink.batch_calls[0] == (healthy_sink.events[0],)
    assert healthy_sink.snapshots_at_append == [healthy_original]
    assert healthy_world.runtime.snapshot is not healthy_original
    assert len(healthy_world.runtime.snapshot.actions) == 1
    _assert_no_store(approved)


def test_policy_rejected_real_submit_is_audited_and_sink_failure_preserves_state(
    _key: tuple[RSAPublicKeyV1, int],
) -> None:
    healthy_sink = _AuditSink()
    healthy_world, action = _approved_action_world(_key, sink=healthy_sink, subject="rejected.ok")
    action["scope"] = "market:write"
    original = healthy_world.runtime.snapshot

    with TestClient(healthy_world.app) as client:
        rejected = client.post(
            "/mcp/actions",
            json=action,
            headers={
                "Authorization": f"Bearer {healthy_world.token}",
                "Idempotency-Key": str(action["action_idempotency_key"]),
            },
        )

    assert rejected.status_code == 200, rejected.text
    assert rejected.json()["allowed"] is False
    assert [event.kind for event in healthy_sink.events] == ["action_denied"]
    assert healthy_sink.snapshots_at_append == [original]
    assert len(healthy_sink.batch_calls) == 1
    assert healthy_sink.batch_calls[0] == (healthy_sink.events[0],)
    assert healthy_world.runtime.snapshot is not original
    assert healthy_world.runtime.snapshot.actions[-1].state == "rejected"
    _assert_no_store(rejected)

    class FailBeforeAppend(_AuditSink):
        def append_batch(self, events: tuple[object, ...]) -> None:
            self.batch_calls.append(events)
            if self.runtime is not None:
                self.snapshots_at_append.append(self.runtime.snapshot)
            raise RuntimeError(_TOKEN_CANARY)

    failing_sink = FailBeforeAppend()
    failing_world, failing_action = _approved_action_world(
        _key, sink=failing_sink, subject="rejected.fail"
    )
    failing_action["scope"] = "market:write"
    failing_original = failing_world.runtime.snapshot

    with TestClient(failing_world.app) as client:
        failed = client.post(
            "/mcp/actions",
            json=failing_action,
            headers={
                "Authorization": f"Bearer {failing_world.token}",
                "Idempotency-Key": str(failing_action["action_idempotency_key"]),
            },
        )

    assert failed.status_code == 503
    assert failed.json().get("allowed") is False
    assert failing_sink.events == []
    assert len(failing_sink.batch_calls) == 1
    assert tuple(event.kind for event in failing_sink.batch_calls[0]) == ("action_denied",)
    assert failing_sink.snapshots_at_append == [failing_original]
    assert failing_world.runtime.snapshot is failing_original
    assert failing_original.actions == ()
    _assert_no_store(failed)


def test_snapshot_and_bound_audit_sink_cannot_be_replaced_or_disabled(
    _key: tuple[RSAPublicKeyV1, int],
) -> None:
    world = _app(_key)
    current = world.runtime.snapshot
    candidate = record_request_denial(
        current,
        org_id=_ORG,
        principal_id="operator.synthetic",
        reason_code="SCOPE_DENIED",
        now_ns=_NOW_NS,
    )
    with pytest.raises((AttributeError, RuntimeError, TypeError, HTTPException)):
        world.runtime.snapshot = candidate
    assert world.runtime.snapshot is current

    try:
        world.runtime.audit_sink = None
    except Exception:
        assert world.runtime.snapshot is current
    else:
        with pytest.raises(HTTPException) as raised:
            world.runtime.commit(candidate)
        assert raised.value.status_code == 503
        assert raised.value.detail == "AUDIT_UNAVAILABLE"
        assert world.runtime.snapshot is current

    unaudited_runtime = _runtime(context_resolver=_context_resolver())
    unaudited_snapshot = unaudited_runtime.snapshot
    unaudited_revision = record_request_denial(
        unaudited_snapshot,
        org_id=_ORG,
        principal_id="operator.synthetic",
        reason_code="SCOPE_DENIED",
        now_ns=_NOW_NS,
    )
    with pytest.raises(HTTPException) as unaudited_error:
        unaudited_runtime.commit(unaudited_revision)
    assert unaudited_error.value.status_code == 503
    assert unaudited_error.value.detail == "AUDIT_UNAVAILABLE"
    assert unaudited_runtime.snapshot is unaudited_snapshot


def test_factory_rejects_test_only_unaudited_runtime(
    _key: tuple[RSAPublicKeyV1, int],
) -> None:
    runtime = _runtime(context_resolver=_context_resolver(), allow_unaudited_for_tests=True)
    config = McpRuntimeFactoryConfigV1(
        runtime=runtime,
        resolver=McpPrincipalResolverV1(_verifier(_key[0])),
        audit=_AuditSink(),
    )
    with pytest.raises(McpRuntimeFactoryError) as raised:
        build_mcp_control(config)
    assert raised.value.code == "MCP_CONTROL_UNAVAILABLE"
    assert str(raised.value) == "MCP_CONTROL_UNAVAILABLE"
    assert runtime.audit_sink is None


def test_accepted_dry_run_rate_limit_is_separate_per_principal_bucket(
    _key: tuple[RSAPublicKeyV1, int],
) -> None:
    sink = _AuditSink()
    world, action = _approved_action_world(_key, sink=sink, subject="rate.first")
    headers = {
        "Authorization": f"Bearer {world.token}",
        "Idempotency-Key": str(action["action_idempotency_key"]),
    }
    request = {"version": "1", "action": action}
    with TestClient(world.app) as client:
        for _ in range(512):
            response = client.post("/mcp/actions/dry-run", json=request, headers=headers)
            if response.status_code == 429:
                break
            assert response.status_code == 200, response.text
            assert response.json()["allowed"] is True
        else:
            pytest.fail("accepted dry-run rate limit was never reached")

        assert response.json() == {"detail": "DRY_RUN_RATE_LIMIT"}
        _assert_no_store(response)
        audit_count_at_limit = len(sink.events)
        assert audit_count_at_limit > 0

        # The denied-preview bucket is independent from accepted previews.
        rejected_action = {**action, "scope": "market:write"}
        rejected = client.post(
            "/mcp/actions/dry-run",
            json={"version": "1", "action": rejected_action},
            headers=headers,
        )
        assert rejected.status_code == 200, rejected.text
        assert rejected.json()["allowed"] is False
        assert len(sink.events) == audit_count_at_limit + 1
        _assert_no_store(rejected)

        # A second principal receives an independent accepted-preview allowance.
        second_token = _token(_key, subject="rate.second")
        second = client.post(
            "/mcp/actions/dry-run",
            json=request,
            headers={
                "Authorization": f"Bearer {second_token}",
                "Idempotency-Key": str(action["action_idempotency_key"]),
            },
        )

    assert second.status_code == 200, second.text
    assert second.json()["allowed"] is True
    _assert_no_store(second)


def test_factory_config_and_binding_repr_redact_injected_ports(
    _key: tuple[RSAPublicKeyV1, int],
) -> None:
    marker = "PORT_REPR_SECRET_CANARY"

    class OpaqueResolver:
        def resolve_verified(self, *_args: object, **_kwargs: object) -> None:
            return None

        def __repr__(self) -> str:
            return marker

    class OpaqueAudit:
        def append_batch(self, _events: tuple[object, ...]) -> None:
            return None

        def __repr__(self) -> str:
            return marker

    runtime = _runtime(context_resolver=_context_resolver())
    config = McpRuntimeFactoryConfigV1(
        runtime=runtime,
        resolver=OpaqueResolver(),
        audit=OpaqueAudit(),
    )
    binding = build_mcp_control(config)
    assert marker not in repr(config)
    assert marker not in repr(binding)


def test_audit_failure_during_halt_reports_halt_and_retains_authority_state(
    _key: tuple[RSAPublicKeyV1, int],
) -> None:
    authority = HaltAuthority(clock=lambda: _NOW)
    sink = _AuditSink(fail=True)
    token = _token(
        _key,
        subject="risk.halt-operator",
        scopes=("mcp:halt",),
        role="RiskOfficer",
    )
    world = _app(_key, sink=sink, token=token, halt_authority=authority)
    original = world.runtime.snapshot

    with TestClient(world.app) as client:
        response = client.post(
            "/mcp/halts",
            json={"version": "1", "reason_code": "SYNTHETIC_TEST", "scope": "all"},
            headers={"Authorization": f"Bearer {world.token}"},
        )

    assert response.status_code == 503
    assert response.json()["halted"] is True
    assert response.json()["audit_error_code"] == "AUDIT_UNAVAILABLE"
    assert authority.halted is True
    assert world.runtime.snapshot is original
    _assert_no_store(response)


def test_audit_failure_denies_success_and_denial_paths_without_snapshot_change(
    _key: tuple[RSAPublicKeyV1, int],
) -> None:
    sink = _AuditSink(fail=True)
    world = _app(_key, sink=sink)
    original = world.runtime.snapshot
    body = {
        "version": "1",
        "agent_id": "agent.synthetic",
        "display_label": "Synthetic Agent",
        "origin": "LEVIATHAN",
        "attestation": "synthetic-attestation",
    }

    with TestClient(world.app) as client:
        failed_success = client.post(
            "/mcp/agents/register",
            json=body,
            headers={"Authorization": f"Bearer {world.token}"},
        )
    assert failed_success.status_code == 503
    assert failed_success.json() == {"detail": "AUDIT_UNAVAILABLE"}
    assert world.runtime.snapshot is original
    _assert_no_store(failed_success)

    deny_world = _app(_key, scopes=("mcp:read",), sink=_AuditSink(fail=True))
    deny_original = deny_world.runtime.snapshot
    with TestClient(deny_world.app) as client:
        failed_denial = client.post(
            "/mcp/sessions",
            json=body,
            headers={"Authorization": f"Bearer {deny_world.token}"},
        )
    assert failed_denial.status_code == 503
    assert failed_denial.json() == {"detail": "AUDIT_UNAVAILABLE"}
    assert deny_world.runtime.snapshot is deny_original
    assert deny_world.runtime.snapshot.sessions == ()
    _assert_no_store(failed_denial)


def test_non_prefix_audit_revision_is_rejected_without_replacing_snapshot(
    _key: tuple[RSAPublicKeyV1, int],
) -> None:
    sink = _AuditSink()
    world = _app(_key, sink=sink)
    base = world.runtime.snapshot
    first = record_request_denial(
        base,
        org_id=_ORG,
        principal_id="operator.synthetic",
        reason_code="SCOPE_DENIED",
        now_ns=_NOW_NS,
    )
    conflicting = record_request_denial(
        base,
        org_id=_ORG,
        principal_id="operator.synthetic",
        reason_code="ROLE_DENIED",
        now_ns=_NOW_NS,
    )
    world.runtime.commit(first)
    sink_calls_after_first = len(sink.events)

    with pytest.raises(HTTPException) as raised:
        world.runtime.commit(conflicting)

    assert raised.value.status_code == 503
    assert raised.value.detail == "AUDIT_UNAVAILABLE"
    assert world.runtime.snapshot is first
    assert len(sink.events) == sink_calls_after_first


def test_commit_sends_the_full_new_event_tuple_once_before_assignment(
    _key: tuple[RSAPublicKeyV1, int],
) -> None:
    sink = _AuditSink()
    world = _app(_key, sink=sink)
    before = world.runtime.snapshot
    first = record_request_denial(
        before,
        org_id=_ORG,
        principal_id="operator.synthetic",
        reason_code="SCOPE_DENIED",
        now_ns=_NOW_NS,
    )
    revised = record_request_denial(
        first,
        org_id=_ORG,
        principal_id="operator.synthetic",
        reason_code="ROLE_DENIED",
        now_ns=_NOW_NS,
    )
    expected_new_events = revised.audit_events[len(before.audit_events) :]

    world.runtime.commit(revised)

    assert len(expected_new_events) == 2
    assert sink.batch_calls == [expected_new_events]
    assert sink.events == list(expected_new_events)
    assert sink.snapshots_at_append == [before]
    assert world.runtime.snapshot is revised


def test_every_routed_and_method_mismatch_response_is_no_store(
    _key: tuple[RSAPublicKeyV1, int],
) -> None:
    world = _app(_key)
    with TestClient(world.app) as client:
        success = client.get(
            "/mcp/tools",
            params={"agent_id": "agent.synthetic", "session_id": "session.synthetic"},
            headers={"Authorization": f"Bearer {world.token}"},
        )
        unauthenticated = client.get(
            "/mcp/tools",
            params={"agent_id": "agent.synthetic", "session_id": "session.synthetic"},
        )
        method_mismatch = client.post(
            "/mcp/tools", headers={"Authorization": f"Bearer {world.token}"}
        )

    assert success.status_code == 200
    assert unauthenticated.status_code == 401
    assert method_mismatch.status_code == 405
    for response in (success, unauthenticated, method_mismatch):
        _assert_no_store(response)
