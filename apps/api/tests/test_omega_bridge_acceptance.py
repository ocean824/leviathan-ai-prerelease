"""Independent OMEGA-002 router acceptance using synthetic identity only."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from leviathan_api.routers.omega import router
from leviathan_core.omega_link.heartbeat_adapter import (
    InMemoryOmegaNonceStore,
    OmegaHeartbeatAdapterV1,
)
from leviathan_core.omega_link.state_models import OmegaPolicyV1
from leviathan_core.risk.halt import HaltAuthority
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
_NOW = datetime(2026, 10, 6, 18, 0, tzinfo=UTC)
_NOW_SECONDS = int(_NOW.timestamp())
_NOW_NS = _NOW_SECONDS * 1_000_000_000
_ISSUER = "omega-idp"
_AUDIENCE = "leviathan-backend"
_ORG = "org-omega"
_PROJECT = "leviathan-ai"
_ENV = "test"
_KID = "omega-synthetic-key"
_PEER = "omega-peer-test"
_CERT = b"synthetic OMEGA TLS certificate DER bytes"
_CERT_PIN = hashlib.sha256(_CERT).hexdigest()
_CAPABILITY_HASH = "a" * 64


class _KeySet:
    def get_key(self, issuer: str, kid: str) -> RSAPublicKeyV1 | None:
        if (issuer, kid) == (_ISSUER, _KID):
            return _PUBLIC_KEY
        return None


class _Revocations:
    def is_revoked(self, issuer: str, jti: str) -> bool:
        return False


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _segment(value: object) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return _b64url(payload)


def _signature(message: bytes) -> bytes:
    digest_info = (
        bytes.fromhex("3031300d060960864801650304020105000420") + hashlib.sha256(message).digest()
    )
    width = (_PUBLIC_N.bit_length() + 7) // 8
    padding_length = width - len(digest_info) - 3
    assert padding_length >= 8
    encoded = b"\x00\x01" + b"\xff" * padding_length + b"\x00" + digest_info
    return pow(int.from_bytes(encoded, "big"), _PRIVATE_D, _PUBLIC_N).to_bytes(width, "big")


def _token(
    nonce: str,
    *,
    scope: str = "omega:heartbeat",
    issued_offset_seconds: int = 0,
    claims: dict[str, object] | None = None,
) -> str:
    issued = _NOW_SECONDS + issued_offset_seconds
    token_claims: dict[str, object] = {
        "iss": _ISSUER,
        "aud": _AUDIENCE,
        "org": _ORG,
        "sub": _PEER,
        "role": "bridge-peer",
        "scope": [scope],
        "env": _ENV,
        "jti": nonce,
        "iat": issued,
        "nbf": issued,
        "exp": issued + 240,
        "cnf": {"x5t#S256": _b64url(hashlib.sha256(_CERT).digest())},
    }
    if claims:
        token_claims.update(claims)
    header = _segment({"alg": "RS256", "kid": _KID, "typ": "JWT"})
    payload = _segment(token_claims)
    signing_input = f"{header}.{payload}".encode("ascii")
    return f"{signing_input.decode('ascii')}.{_b64url(_signature(signing_input))}"


def _verifier() -> PrincipalVerifier:
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
        clock=lambda: _NOW,
    )


@pytest.fixture
def omega_client() -> Any:
    transport_certificate: list[bytes | None] = [_CERT]
    signed_payloads: list[bytes] = []
    denial_audit: list[str] = []

    def signer(payload: bytes) -> str:
        signed_payloads.append(payload)
        return hashlib.sha256(payload).hexdigest()

    halt = HaltAuthority(clock=lambda: _NOW)
    app = FastAPI()
    app.include_router(router)

    @app.middleware("http")
    async def inject_test_tls_extension(request: Request, call_next):
        # The test harness simulates trusted ASGI TLS metadata; request headers
        # never control this extension.
        extensions = dict(request.scope.get("extensions", {}))
        if transport_certificate[0] is None:
            extensions.pop("tls", None)
        else:
            extensions["tls"] = {"client_cert_der": transport_certificate[0]}
        request.scope["extensions"] = extensions
        return await call_next(request)

    app.state.leviathan = SimpleNamespace(halts=halt)
    app.state.omega_adapter = OmegaHeartbeatAdapterV1(
        verifier=_verifier(),
        pinned_certificates={_CERT_PIN: _PEER},
        nonce_store=InMemoryOmegaNonceStore(),
        clock_ns=lambda: _NOW_NS,
        policy=OmegaPolicyV1(version="1", max_heartbeat_age_ns=60_000_000_000),
        response_signer=signer,
        capability_manifest_hash=_CAPABILITY_HASH,
        denial_auditor=denial_audit.append,
    )
    with TestClient(app) as client:
        yield SimpleNamespace(
            client=client,
            app=app,
            halt=halt,
            signed_payloads=signed_payloads,
            denial_audit=denial_audit,
            transport_certificate=transport_certificate,
        )


def _auth(nonce: str, *, scope: str = "omega:heartbeat", **kwargs: Any) -> dict[str, str]:
    return {"Authorization": f"Bearer {_token(nonce, scope=scope, **kwargs)}"}


def test_missing_adapter_fails_closed_on_all_legacy_routes(omega_client: Any) -> None:
    del omega_client.app.state.omega_adapter
    routes = (
        omega_client.client.get("/omega/heartbeat"),
        omega_client.client.post("/omega/inquiry", json={"instrument": "EURUSD"}),
        omega_client.client.post("/omega/kill"),
    )

    assert [response.status_code for response in routes] == [503, 503, 503]
    assert all(response.json() == {"detail": "OMEGA_ADAPTER_UNAVAILABLE"} for response in routes)
    assert omega_client.halt.halted is False


def test_offline_local_control_plane_denies_kill(omega_client: Any) -> None:
    del omega_client.app.state.leviathan

    response = omega_client.client.post(
        "/omega/kill", headers=_auth("offline-kill", scope="omega:kill")
    )

    assert response.status_code == 503
    assert response.json() == {"detail": "OMEGA_KILL_DENIED"}
    assert omega_client.denial_audit == ["OMEGA_KILL_DENIED"]


@pytest.mark.parametrize(
    ("name", "nonce", "claims", "iat_offset", "scope", "cert", "headers"),
    [
        ("bad-issuer", "bad-issuer", {"iss": "attacker-idp"}, 0, "omega:heartbeat", _CERT, None),
        ("bad-audience", "bad-aud", {"aud": "other-api"}, 0, "omega:heartbeat", _CERT, None),
        (
            "wrong-peer",
            "wrong-peer",
            {"sub": "omega-peer-forged"},
            0,
            "omega:heartbeat",
            _CERT,
            None,
        ),
        ("wrong-scope", "wrong-scope", None, 0, "omega:kill", _CERT, None),
        (
            "wrong-certificate-binding",
            "wrong-binding",
            {"cnf": {"x5t#S256": _b64url(hashlib.sha256(b"other synthetic cert").digest())}},
            0,
            "omega:heartbeat",
            _CERT,
            None,
        ),
        (
            "stale-token",
            "stale-token",
            {"exp": _NOW_SECONDS + 120},
            -301,
            "omega:heartbeat",
            _CERT,
            None,
        ),
        ("stale-iat", "stale-iat", None, 3, "omega:heartbeat", _CERT, None),
        (
            "wrong-certificate",
            "wrong-cert",
            None,
            0,
            "omega:heartbeat",
            b"different synthetic certificate",
            None,
        ),
        (
            "forwarded-header-cannot-authenticate",
            "header-cert",
            None,
            0,
            "omega:heartbeat",
            None,
            {"X-Forwarded-Client-Cert": _CERT.hex()},
        ),
    ],
)
def test_forged_or_stale_identity_is_denied(
    omega_client: Any,
    name: str,
    nonce: str,
    claims: dict[str, object] | None,
    iat_offset: int,
    scope: str,
    cert: bytes | None,
    headers: dict[str, str] | None,
) -> None:
    del name  # pytest case label only
    omega_client.transport_certificate[0] = cert
    token = _token(
        nonce,
        scope=scope,
        issued_offset_seconds=iat_offset,
        claims=claims,
    )
    request_headers = {"Authorization": f"Bearer {token}", **(headers or {})}

    response = omega_client.client.get("/omega/heartbeat", headers=request_headers)

    assert response.status_code == 401
    assert response.json() == {"detail": "OMEGA_AUTH_DENIED"}
    assert omega_client.halt.halted is False
    assert omega_client.denial_audit == ["OMEGA_AUTH_DENIED"]


def test_malformed_or_forged_bearer_token_is_denied(omega_client: Any) -> None:
    canary = "OMEGA_SYNTHETIC_FORGED_TOKEN_CANARY"
    token = _token("forged-token", claims={"sub": canary})
    forged = token[:-1] + ("A" if token[-1] != "A" else "B")

    response = omega_client.client.get(
        "/omega/heartbeat", headers={"Authorization": f"Bearer {forged}"}
    )

    assert response.status_code == 401
    assert response.json() == {"detail": "OMEGA_AUTH_DENIED"}
    assert omega_client.denial_audit == ["OMEGA_AUTH_DENIED"]
    assert canary not in repr(omega_client.denial_audit)


def test_denial_audit_failure_returns_service_unavailable(
    omega_client: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unavailable(_code: str) -> None:
        raise RuntimeError("synthetic audit failure")

    monkeypatch.setattr(omega_client.app.state.omega_adapter, "_denial_auditor", unavailable)
    response = omega_client.client.get(
        "/omega/heartbeat", headers={"Authorization": "Bearer malformed"}
    )

    assert response.status_code == 503
    assert response.json() == {"detail": "OMEGA_AUDIT_UNAVAILABLE"}


def test_signed_request_timestamp_accepts_exact_two_second_window(omega_client: Any) -> None:
    for offset in (-2, 2):
        response = omega_client.client.get(
            "/omega/heartbeat", headers=_auth(f"boundary-{offset}", issued_offset_seconds=offset)
        )
        assert response.status_code == 200


def test_replayed_nonce_is_denied(omega_client: Any) -> None:
    headers = _auth("replay-once")

    first = omega_client.client.get("/omega/heartbeat", headers=headers)
    replay = omega_client.client.get("/omega/heartbeat", headers=headers)

    assert first.status_code == 200
    assert replay.status_code == 401
    assert replay.json() == {"detail": "OMEGA_REPLAY_OR_STORE_UNAVAILABLE"}
    assert omega_client.denial_audit == ["OMEGA_REPLAY_OR_STORE_UNAVAILABLE"]


def test_heartbeat_is_signed_versioned_and_contains_only_local_status(omega_client: Any) -> None:
    response = omega_client.client.get("/omega/heartbeat", headers=_auth("heartbeat-ok"))
    body = response.json()
    unsigned = {key: value for key, value in body.items() if key != "signature"}
    canonical = json.dumps(
        unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")

    assert response.status_code == 200
    assert body["version"] == "1"
    assert body["capability_manifest_hash"] == _CAPABILITY_HASH
    assert body["halted"] is False
    assert body["active_halts"] == []
    assert body["freshness_ns"] == 60_000_000_000
    assert body["timestamp_ns"] == _NOW_NS
    assert body["trace_id"]
    assert body["signature"] == hashlib.sha256(canonical).hexdigest()
    assert omega_client.signed_payloads == [canonical]


def test_inquiry_is_explicitly_unavailable_and_never_returns_a_demo_decision(
    omega_client: Any,
) -> None:
    response = omega_client.client.post(
        "/omega/inquiry",
        json={"instrument": "EURUSD"},
        headers=_auth("inquiry-deny", scope="omega:inquiry"),
    )

    assert response.status_code == 200
    assert response.json() == {
        "version": "1",
        "status": "unavailable",
        "permission": "deny",
        "reason_code": "LIVE_EVIDENCE_UNAVAILABLE",
    }
    assert omega_client.denial_audit == ["LIVE_EVIDENCE_UNAVAILABLE"]


def test_kill_uses_only_halt_authority_engage_and_is_idempotent(
    omega_client: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    authority = omega_client.halt
    original_engage = authority.engage
    engaged: list[str] = []

    def observed_engage(reason: str) -> None:
        engaged.append(reason)
        original_engage(reason)

    def forbidden_resume(*_args: object, **_kwargs: object) -> None:
        pytest.fail("OMEGA kill path attempted to clear HALT")

    monkeypatch.setattr(authority, "engage", observed_engage)
    monkeypatch.setattr(authority, "lift", forbidden_resume)
    monkeypatch.setattr(authority, "lift_committed", forbidden_resume)

    first = omega_client.client.post("/omega/kill", headers=_auth("kill-1", scope="omega:kill"))
    generation_after_first = authority.generation
    second = omega_client.client.post("/omega/kill", headers=_auth("kill-2", scope="omega:kill"))

    assert first.status_code == second.status_code == 200
    assert first.json()["status"] == second.json()["status"] == "halted"
    assert first.json()["reason"] == second.json()["reason"]
    assert engaged == [first.json()["reason"], first.json()["reason"]]
    assert generation_after_first == authority.generation == 1
    assert authority.halted is True
    assert authority.active == (first.json()["reason"],)


def test_failed_halt_engage_stays_denied(
    omega_client: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail_engage(_reason: str) -> None:
        raise RuntimeError("synthetic halt failure")

    monkeypatch.setattr(omega_client.halt, "engage", fail_engage)
    response = omega_client.client.post(
        "/omega/kill", headers=_auth("kill-fails", scope="omega:kill")
    )

    assert response.status_code == 503
    assert response.json() == {"detail": "OMEGA_KILL_ENGAGE_FAILED"}
    assert omega_client.halt.halted is False
    assert omega_client.denial_audit == ["OMEGA_KILL_ENGAGE_FAILED"]


def test_no_omega_resume_route_can_clear_an_existing_halt(omega_client: Any) -> None:
    killed = omega_client.client.post(
        "/omega/kill", headers=_auth("kill-before-resume", scope="omega:kill")
    )
    assert killed.status_code == 200
    active_before = omega_client.halt.active

    resume = omega_client.client.post(
        "/omega/resume", headers=_auth("resume-attempt", scope="omega:kill")
    )

    assert resume.status_code in (404, 405)
    assert omega_client.halt.halted is True
    assert omega_client.halt.active == active_before
