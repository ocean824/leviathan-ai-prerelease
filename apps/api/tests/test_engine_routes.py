"""Risk, pipeline, and ØMEGA surfaces over HTTP."""

import base64
import hashlib
import json
import re
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from threading import Event, Thread
from uuid import uuid4

import pytest
from fastapi import Request
from fastapi.testclient import TestClient

from leviathan_api.main import app
from leviathan_core.numeric import canonical_str, parse_decimal
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

_OMEGA_ISSUER = "omega-idp"
_OMEGA_AUDIENCE = "leviathan-backend"
_OMEGA_ORG = "org-omega-synthetic"
_OMEGA_PROJECT = "leviathan-synthetic"
_OMEGA_ENV = "test"
_OMEGA_KID = "omega-synthetic-key"
_OMEGA_PEER = "omega-peer-test"
_OMEGA_CERT = b"synthetic OMEGA TLS certificate DER bytes for legacy route tests"
_OMEGA_CERT_PIN = hashlib.sha256(_OMEGA_CERT).hexdigest()
_OMEGA_RSA = json.loads(
    (
        Path(__file__).resolve().parents[3]
        / "packages/leviathan-core/tests/security/fixtures/sec003_synthetic_rsa.json"
    ).read_text(encoding="utf-8")
)
_OMEGA_MODULUS = int(_OMEGA_RSA["modulus_hex"], 16)
_OMEGA_PRIVATE_EXPONENT = int(_OMEGA_RSA["private_exponent_hex"], 16)


@app.middleware("http")
async def _inject_synthetic_omega_tls(request: Request, call_next):
    """Model trusted TLS metadata in tests; caller certificate headers are ignored."""
    extensions = dict(request.scope.get("extensions", {}))
    headers = request.headers
    if headers.get("x-test-trusted-tls") == "synthetic":
        extensions["tls"] = {"client_cert_der": _OMEGA_CERT}
    else:
        extensions.pop("tls", None)
    request.scope["extensions"] = extensions
    return await call_next(request)


class _OmegaKeySet:
    def get_key(self, issuer: str, kid: str) -> RSAPublicKeyV1 | None:
        if (issuer, kid) == (_OMEGA_ISSUER, _OMEGA_KID):
            exponent = int(_OMEGA_RSA["public_exponent_hex"], 16)
            return RSAPublicKeyV1(_OMEGA_MODULUS, exponent)
        return None


class _OmegaRevocations:
    def is_revoked(self, issuer: str, jti: str) -> bool:
        return False


def _omega_b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _omega_jwt(scope: str) -> str:
    issued_at = int(datetime.now(UTC).timestamp())
    header = _omega_b64url(
        json.dumps(
            {"alg": "RS256", "kid": _OMEGA_KID, "typ": "JWT"},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )
    claims = _omega_b64url(
        json.dumps(
            {
                "iss": _OMEGA_ISSUER,
                "aud": _OMEGA_AUDIENCE,
                "org": _OMEGA_ORG,
                "project": _OMEGA_PROJECT,
                "sub": _OMEGA_PEER,
                "role": "bridge-peer",
                "scope": [scope],
                "env": _OMEGA_ENV,
                "jti": uuid4().hex,
                "iat": issued_at,
                "nbf": issued_at,
                "exp": issued_at + 240,
                "cnf": {"x5t#S256": _omega_b64url(hashlib.sha256(_OMEGA_CERT).digest())},
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )
    signing_input = f"{header}.{claims}".encode("ascii")
    digest_info = (
        bytes.fromhex("3031300d060960864801650304020105000420")
        + hashlib.sha256(signing_input).digest()
    )
    width = (_OMEGA_MODULUS.bit_length() + 7) // 8
    padding_length = width - len(digest_info) - 3
    encoded = b"\x00\x01" + b"\xff" * padding_length + b"\x00" + digest_info
    signature = pow(
        int.from_bytes(encoded, "big"), _OMEGA_PRIVATE_EXPONENT, _OMEGA_MODULUS
    ).to_bytes(width, "big")
    return f"{signing_input.decode('ascii')}.{_omega_b64url(signature)}"


def _configure_omega_test_adapter(target_app: object = app) -> None:
    def clock() -> datetime:
        return datetime.now(UTC)

    verifier = PrincipalVerifier(
        trusted_issuer=TrustedIssuerV1(
            issuer=_OMEGA_ISSUER,
            audience=_OMEGA_AUDIENCE,
            org_id=_OMEGA_ORG,
            project_id=_OMEGA_PROJECT,
            env=_OMEGA_ENV,
            require_mtls=True,
        ),
        key_set=_OmegaKeySet(),
        revocations=_OmegaRevocations(),
        clock=clock,
    )
    target_app.state.omega_adapter = OmegaHeartbeatAdapterV1(  # type: ignore[attr-defined]
        verifier=verifier,
        pinned_certificates={_OMEGA_CERT_PIN: _OMEGA_PEER},
        nonce_store=InMemoryOmegaNonceStore(),
        clock_ns=lambda: int(clock().timestamp() * 1_000_000_000),
        policy=OmegaPolicyV1(version="1", max_heartbeat_age_ns=60_000_000_000),
        response_signer=lambda payload: hashlib.sha256(payload).hexdigest(),
        denial_auditor=lambda _code: None,
        capability_manifest_hash="a" * 64,
    )


def _omega_request_kwargs(scope: str, *, include_tls_extension: bool = True) -> dict[str, object]:
    kwargs: dict[str, object] = {
        "headers": {"Authorization": f"Bearer {_omega_jwt(scope)}"},
    }
    if include_tls_extension:
        kwargs["headers"]["X-Test-Trusted-TLS"] = "synthetic"  # type: ignore[index]
    return kwargs


@pytest.fixture
def client() -> TestClient:
    _configure_omega_test_adapter()
    with TestClient(app) as c:  # context manager triggers lifespan
        yield c


def test_risk_status_reports_policy(client: TestClient) -> None:
    body = client.get("/risk/status").json()
    assert body["halted"] is False
    assert body["policy"]["max_daily_dd_pct"] == "3.0"
    assert body["policy"]["loss_streak_trigger"] == 3


def test_halt_engage_and_lift_roundtrip(entitled_desktop_lift_client) -> None:
    client, headers = entitled_desktop_lift_client
    assert client.post("/risk/halt", json={"reason": "operator_hold"}).json()["halted"] is True
    status = client.get("/risk/status").json()
    assert "operator_hold" in status["active_halts"]
    lifted = client.post(
        "/risk/halt/lift", json={"reason": "operator_hold"}, headers=headers
    ).json()
    assert lifted["halted"] is False


def test_pipeline_replay_end_to_end_over_http(client: TestClient) -> None:
    body = client.post("/pipeline/replay").json()
    assert body["decision"]["permission"] == "approve"
    assert body["verdict"]["action"] == "allow"
    assert body["journal_record"]["outcome"] == "win"
    assert body["session"]["label"] == "ny_overlap"
    assert body["intent"]["risk_session_id"]


def test_pipeline_replay_decimal_fields_use_canonical_decimal_strings(
    client: TestClient,
) -> None:
    body = client.post("/pipeline/replay").json()
    fields = (
        ("decision.confidence", body["decision"]["confidence"], "0", "1"),
        ("session.quality", body["session"]["quality"], "0", "1"),
        (
            "truth.sentiment_modifier",
            body["truth"]["sentiment_modifier"],
            "-0.25",
            "0.25",
        ),
    )
    grammar = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]*[1-9])?\Z", re.ASCII)
    for name, value, minimum, maximum in fields:
        assert type(value) is str, name
        assert grammar.fullmatch(value), name
        parsed = parse_decimal(
            value,
            field="pipeline_decimal",
            min_value=Decimal(minimum),
            max_value=Decimal(maximum),
        )
        assert canonical_str(parsed) == value, name


def test_omega_heartbeat_and_kill_sync(entitled_desktop_lift_client) -> None:
    client, lift_headers = entitled_desktop_lift_client
    _configure_omega_test_adapter(client.app)
    hb = client.get("/omega/heartbeat", **_omega_request_kwargs("omega:heartbeat")).json()
    assert hb["system"] == "leviathan"
    assert hb["halted"] is False

    client.post("/omega/kill", **_omega_request_kwargs("omega:kill"))
    hb2 = client.get("/omega/heartbeat", **_omega_request_kwargs("omega:heartbeat")).json()
    assert hb2["halted"] is True
    assert "omega_kill_signal" in hb2["active_halts"]

    # Halted system refuses live inquiry because no reviewed live data path exists.
    inq = client.post(
        "/omega/inquiry",
        json={"instrument": "NQ"},
        **_omega_request_kwargs("omega:inquiry"),
    ).json()
    assert inq["permission"] == "deny"
    lifted = client.post(
        "/risk/halt/lift",
        json={"reason": "omega_kill_signal"},
        headers=lift_headers,
    )
    assert lifted.status_code == 200


def test_omega_inquiry_returns_confidence(client: TestClient) -> None:
    response = client.post("/omega/inquiry", json={"instrument": "NQ"})
    assert response.status_code == 401
    assert response.json() == {"detail": "OMEGA_AUTH_DENIED"}


def test_omega_heartbeat_uses_one_atomic_halt_snapshot(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    halted_read = Event()
    halt_attempted = Event()
    original_halted = HaltAuthority.halted
    original_active = HaltAuthority.active
    halted_getter = original_halted.fget
    active_getter = original_active.fget
    assert halted_getter is not None
    assert active_getter is not None

    def halted_before_concurrent_halt(authority: HaltAuthority) -> bool:
        halted = halted_getter(authority)
        halted_read.set()
        assert halt_attempted.wait(timeout=2)
        return halted

    monkeypatch.setattr(HaltAuthority, "halted", property(halted_before_concurrent_halt))
    state = app.state.leviathan

    def engage_between_reads() -> None:
        assert halted_read.wait(timeout=2)
        halt_attempted.set()
        state.halts.engage("concurrent_test_halt")

    mutation = Thread(target=engage_between_reads)
    mutation.start()
    heartbeat = client.get("/omega/heartbeat", **_omega_request_kwargs("omega:heartbeat"))
    mutation.join(timeout=2)
    assert not mutation.is_alive()
    assert heartbeat.status_code == 200
    body = heartbeat.json()
    assert body["halted"] is False
    assert body["active_halts"] == []
    assert state.halts.halted is True
