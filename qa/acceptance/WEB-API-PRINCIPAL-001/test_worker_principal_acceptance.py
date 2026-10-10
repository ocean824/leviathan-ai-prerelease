"""Cold acceptance for the Worker assertion principal boundary."""

from __future__ import annotations

import asyncio
import base64
import json
import math
import os
import random
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.testclient import TestClient

from leviathan_api.auth import worker_assertion
from leviathan_api.auth.operator_principal import (
    OperatorPrincipalMiddleware,
    make_local_operator_profile,
)
from leviathan_api.auth.worker_assertion import (
    WORKER_ASSERTION_HEADER,
    InMemoryAssertionReplayStore,
    WorkerAssertionCode,
    WorkerAssertionError,
    WorkerAssertionVerifier,
    WorkerRequestPrincipalV1,
    require_worker_principal,
)
from leviathan_core.security.authz_models import require_trusted_principal
from leviathan_core.security.principal_verifier import RSAPublicKeyV1

ISSUER = "https://site.acceptance.invalid/worker"
AUDIENCE = "leviathan-web-api"
METHOD = "GET"
PATH = "/api/profile"
NOW = datetime(2026, 10, 9, 20, 0, 0, tzinfo=UTC)
NOW_S = int(NOW.timestamp())
_DER_SHA256 = bytes.fromhex("3031300d060960864801650304020105000420")


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _prime(rng: random.Random) -> int:
    while True:
        candidate = rng.getrandbits(1024) | (3 << 1022) | 1
        if any(candidate % divisor == 0 for divisor in (3, 5, 7, 11, 13, 17, 19, 23, 29)):
            continue
        s, d = 0, candidate - 1
        while d % 2 == 0:
            s, d = s + 1, d // 2
        for base in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
            x = pow(base, d, candidate)
            if x in (1, candidate - 1):
                continue
            for _ in range(s - 1):
                x = pow(x, 2, candidate)
                if x == candidate - 1:
                    break
            else:
                break
        else:
            return candidate


@pytest.fixture(scope="module")
def signing_key() -> tuple[RSAPublicKeyV1, int]:
    rng = random.Random(0xA551D)
    p, q = _prime(rng), _prime(rng)
    while q == p or math.gcd(65537, (p - 1) * (q - 1)) != 1:
        q = _prime(rng)
    modulus = p * q
    return RSAPublicKeyV1(modulus, 65537), pow(65537, -1, (p - 1) * (q - 1))


def _jwks(key: tuple[RSAPublicKeyV1, int], *, kid: str = "acceptance-key") -> str:
    public, _private = key
    modulus, exponent = public.modulus, public.exponent
    return json.dumps(
        {
            "keys": [
                {
                    "kty": "RSA",
                    "kid": kid,
                    "use": "sig",
                    "alg": "RS256",
                    "n": _b64(modulus.to_bytes((modulus.bit_length() + 7) // 8, "big")),
                    "e": _b64(exponent.to_bytes((exponent.bit_length() + 7) // 8, "big")),
                }
            ]
        },
        separators=(",", ":"),
    )


def _claims(**changes: object) -> dict[str, object]:
    return {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "org": "org.acceptance",
        "env": "test",
        "sub": "user.acceptance",
        "sid": "session.acceptance",
        "device_id": "device.from.signed.claim",
        "auth_time": NOW_S - 10,
        "entitlement_version": "entitlement-v1",
        "features": ["analysis.read"],
        "role": "user",
        "roles": ["user"],
        "scope": ["api:read"],
        "req_method": METHOD,
        "req_path": PATH,
        "jti": "jti.acceptance",
        "iat": NOW_S - 10,
        "nbf": NOW_S - 10,
        "exp": NOW_S + 90,
        **changes,
    }


def _signed_token(
    key: tuple[RSAPublicKeyV1, int],
    claims: dict[str, object] | None = None,
    *,
    kid: str = "acceptance-key",
    alg: str = "RS256",
    header: dict[str, str] | None = None,
) -> str:
    jose_header = header or {"alg": alg, "kid": kid, "typ": "JWT"}
    enc_header = _b64(json.dumps(jose_header, sort_keys=True, separators=(",", ":")).encode())
    enc_claims = _b64(
        json.dumps(
            claims if claims is not None else _claims(), sort_keys=True, separators=(",", ":")
        ).encode()
    )
    payload = f"{enc_header}.{enc_claims}"
    public, private = key
    digest = __import__("hashlib").sha256(payload.encode("ascii")).digest()
    digest_info = _DER_SHA256 + digest
    size = (public.modulus.bit_length() + 7) // 8
    block = b"\x00\x01" + b"\xff" * (size - len(digest_info) - 3) + b"\x00" + digest_info
    signature = pow(int.from_bytes(block, "big"), private, public.modulus).to_bytes(size, "big")
    return f"{payload}.{_b64(signature)}"


def _verifier(
    key: tuple[RSAPublicKeyV1, int],
    *,
    replay: InMemoryAssertionReplayStore | None = None,
    jwks: str | None = None,
) -> WorkerAssertionVerifier:
    return WorkerAssertionVerifier(
        issuer=ISSUER,
        audience=AUDIENCE,
        jwks_json=jwks or _jwks(key),
        replay_store=replay or InMemoryAssertionReplayStore(clock=lambda: NOW.timestamp()),
        env="test",
        clock=lambda: NOW,
    )


def _request(headers: list[tuple[bytes, bytes]], verifier: object) -> Request:
    return Request(
        {
            "type": "http",
            "method": METHOD,
            "scheme": "https",
            "path": PATH,
            "raw_path": PATH.encode(),
            "query_string": b"",
            "headers": headers,
            "server": ("api.acceptance.invalid", 443),
            "client": ("127.0.0.1", 12345),
            "app": SimpleNamespace(state=SimpleNamespace(worker_assertion_verifier=verifier)),
        }
    )


def _assert_content_free_rejection(
    verifier: WorkerAssertionVerifier, token: str | None, expected: WorkerAssertionCode
) -> None:
    with pytest.raises(WorkerAssertionError) as caught:
        verifier.verify(token, request_method=METHOD, request_path=PATH)
    assert caught.value.code == expected
    message = str(caught.value)
    assert message == expected
    assert "user.acceptance" not in message
    assert "device.from.signed.claim" not in message
    assert "eyJ" not in message


def test_valid_signed_worker_assertion_issues_a_request_scoped_principal(
    signing_key: tuple[RSAPublicKeyV1, int],
) -> None:
    principal = _verifier(signing_key).verify(
        _signed_token(signing_key), request_method=METHOD, request_path=PATH
    )
    assert type(principal) is WorkerRequestPrincipalV1
    assert principal.principal_id == "user.acceptance"
    assert principal.org_id == "org.acceptance"
    assert principal.session_id == "session.acceptance"
    assert principal.request_method == METHOD and principal.request_path == PATH


@pytest.mark.parametrize(
    ("claims", "expected"),
    [
        ({"exp": NOW_S - 1}, WorkerAssertionCode.EXPIRED_ASSERTION),
        ({"nbf": NOW_S + 1}, WorkerAssertionCode.NOT_YET_VALID),
        ({"aud": "wrong-audience"}, WorkerAssertionCode.WRONG_AUDIENCE),
        ({"iss": "https://wrong.invalid"}, WorkerAssertionCode.WRONG_ISSUER),
    ],
)
def test_invalid_time_and_identity_claims_fail_with_typed_content_free_errors(
    signing_key: tuple[RSAPublicKeyV1, int],
    claims: dict[str, object],
    expected: WorkerAssertionCode,
) -> None:
    token = _signed_token(signing_key, _claims(**claims))
    _assert_content_free_rejection(_verifier(signing_key), token, expected)


def test_missing_assertion_is_typed_and_content_free(
    signing_key: tuple[RSAPublicKeyV1, int],
) -> None:
    _assert_content_free_rejection(
        _verifier(signing_key), None, WorkerAssertionCode.MISSING_ASSERTION
    )


def test_bad_signature_and_unknown_key_id_are_rejected(
    signing_key: tuple[RSAPublicKeyV1, int],
) -> None:
    good = _signed_token(signing_key)
    parts = good.split(".")
    signature = bytearray(base64.urlsafe_b64decode(parts[2] + "=="))
    signature[-1] ^= 1
    bad_signature = f"{parts[0]}.{parts[1]}.{_b64(bytes(signature))}"
    verifier = _verifier(signing_key)
    _assert_content_free_rejection(verifier, bad_signature, WorkerAssertionCode.INVALID_ASSERTION)

    unknown_kid = _signed_token(signing_key, kid="not-in-jwks")
    _assert_content_free_rejection(
        _verifier(signing_key), unknown_kid, WorkerAssertionCode.INVALID_ASSERTION
    )


@pytest.mark.parametrize("algorithm", ["none", "HS256"])
def test_algorithm_none_and_downgrade_are_rejected(
    signing_key: tuple[RSAPublicKeyV1, int], algorithm: str
) -> None:
    token = _signed_token(signing_key, alg=algorithm)
    _assert_content_free_rejection(
        _verifier(signing_key), token, WorkerAssertionCode.INVALID_ASSERTION
    )


def test_replayed_jti_is_rejected_within_the_replay_window(
    signing_key: tuple[RSAPublicKeyV1, int],
) -> None:
    replay = InMemoryAssertionReplayStore(clock=lambda: NOW.timestamp())
    verifier = _verifier(signing_key, replay=replay)
    token = _signed_token(signing_key)
    verifier.verify(token, request_method=METHOD, request_path=PATH)
    _assert_content_free_rejection(verifier, token, WorkerAssertionCode.REPLAYED_ASSERTION)


def test_device_id_comes_from_signed_assertion_not_request_header(
    signing_key: tuple[RSAPublicKeyV1, int],
) -> None:
    token = _signed_token(signing_key, _claims(device_id="device.signed"))
    request = _request(
        [
            (WORKER_ASSERTION_HEADER, token.encode("ascii")),
            (b"x-device-id", b"device.forged.header"),
        ],
        _verifier(signing_key),
    )
    principal = asyncio.run(require_worker_principal(request))
    assert principal.device_id == "device.signed"
    assert request.state.trusted_principal.device_id == "device.signed"


def test_desktop_principal_path_does_not_call_worker_verifier(
    signing_key: tuple[RSAPublicKeyV1, int],
) -> None:
    verifier = _verifier(signing_key)
    verifier.verify = Mock(side_effect=AssertionError("Worker verifier must not run"))  # type: ignore[method-assign]
    capability = "ab" * 32
    profile = make_local_operator_profile(
        principal_id="desktop.operator",
        project_id="desktop-project",
        env="paper",
    )

    app = FastAPI()

    @app.get("/desktop-principal")
    async def desktop_principal(request: Request) -> JSONResponse:
        principal = require_trusted_principal(request.state.trusted_principal)
        return JSONResponse({"principal_id": principal.principal_id})

    app.add_middleware(
        OperatorPrincipalMiddleware,
        capability=capability,
        port=49321,
        profile=profile,
    )
    response = TestClient(app, base_url="http://127.0.0.1:49321").get(
        "/desktop-principal", headers={"x-leviathan-capability": capability}
    )
    assert response.status_code == 200
    assert response.json()["principal_id"] == "desktop.operator"
    verifier.verify.assert_not_called()


def _route_table(root: Path) -> list[list[str]]:
    roots = [
        root / "apps/api/src",
        root / "packages/leviathan-core/src",
        root / "packages/leviathan-store/src",
        root / "packages/leviathan-vault/src",
        root / "packages/leviathan-market-data/src",
    ]
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join(str(path) for path in roots)
    script = (
        "import json; from leviathan_api.main import app; "
        "print(json.dumps(sorted([ [method, route.path] "
        "for route in app.routes for method in getattr(route, 'methods', set()) ])))"
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=root,
        env=env,
        check=True,
        capture_output=True,
        text=True,
        timeout=90,
    )
    return json.loads(result.stdout.strip().splitlines()[-1])


def test_mounted_route_table_is_unchanged_from_canonical() -> None:
    worktree = Path(__file__).resolve().parents[3]
    configured_baseline = os.environ.get("LEVIATHAN_ACCEPTANCE_CANONICAL_ROOT")
    canonical = (
        Path(configured_baseline).resolve()
        if configured_baseline
        else worktree.parent.parent / "repo"
    )
    if not canonical.is_dir() or canonical.resolve() == worktree.resolve():
        pytest.skip("canonical route comparison root is unavailable or is this checkout")
    assert _route_table(worktree) == _route_table(canonical)


def test_import_origin_matches_requested_worktree_when_configured() -> None:
    expected = os.environ.get("LEVIATHAN_ACCEPTANCE_WORKTREE")
    if not expected:
        pytest.skip("set LEVIATHAN_ACCEPTANCE_WORKTREE to enforce the frozen source origin")
    origin = Path(worker_assertion.__file__).resolve()
    assert Path(expected).resolve() in origin.parents


def test_verifier_keeps_constant_time_comparisons_and_never_reads_device_header() -> None:
    source = Path(worker_assertion.__file__).read_text(encoding="utf-8")
    assert 'header.get("alg") != "RS256"' in source
    assert 'header.get("typ") != "JWT"' in source
    assert 'type(header.get("kid")) is not str' in source
    assert 'not hmac.compare_digest(\n            claims["iss"], self._issuer' in source
    assert 'not hmac.compare_digest(\n            claims["aud"], self._audience' in source
    assert 'device_id = claims.get("device_id")' in source
    assert "request.headers" not in source
    assert "x-device-id" not in source


@pytest.mark.parametrize(
    "header",
    [
        {"alg": "RS256", "kid": "acceptance-key"},
        {"alg": "RS256", "kid": "acceptance-key", "typ": "JOSE"},
    ],
    ids=["missing-typ", "wrong-typ"],
)
def test_signed_assertion_requires_exact_jose_typ_jwt(
    signing_key: tuple[RSAPublicKeyV1, int], header: dict[str, str]
) -> None:
    token = _signed_token(signing_key, header=header)
    _assert_content_free_rejection(
        _verifier(signing_key), token, WorkerAssertionCode.INVALID_ASSERTION
    )
