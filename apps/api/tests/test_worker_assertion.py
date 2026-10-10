"""Synthetic Worker-assertion verification tests; no session or signing secrets."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import math
import random
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest
from starlette.requests import Request

from leviathan_api.auth.worker_assertion import (
    WORKER_ASSERTION_HEADER,
    InMemoryAssertionReplayStore,
    WorkerAssertionCode,
    WorkerAssertionError,
    WorkerAssertionVerifier,
    WorkerRequestPrincipalV1,
    get_trusted_worker_principal,
    require_worker_principal,
    require_worker_request_principal,
)
from leviathan_core.security.authz_models import TrustedPrincipalV1
from leviathan_core.security.principal_verifier import RSAPublicKeyV1

ISSUER = "https://site.synthetic/worker"
AUDIENCE = "leviathan-api"
NOW = datetime(2026, 10, 9, 20, 0, 0, tzinfo=UTC)
NOW_SECONDS = int(NOW.timestamp())
_DER_SHA256 = bytes.fromhex("3031300d060960864801650304020105000420")


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
def synthetic_key() -> tuple[RSAPublicKeyV1, int]:
    rng = random.Random(0xA551D)
    p, q = _prime(rng), _prime(rng)
    while q == p or math.gcd(65537, (p - 1) * (q - 1)) != 1:
        q = _prime(rng)
    modulus = p * q
    return RSAPublicKeyV1(modulus, 65537), pow(65537, -1, (p - 1) * (q - 1))


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _jwks(key: RSAPublicKeyV1) -> str:
    width = (key.modulus.bit_length() + 7) // 8
    exponent = key.exponent.to_bytes((key.exponent.bit_length() + 7) // 8, "big")
    return json.dumps(
        {
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "worker-key-1",
                    "use": "sig",
                    "alg": "RS256",
                    "n": _b64(key.modulus.to_bytes(width, "big")),
                    "e": _b64(exponent),
                }
            ]
        },
        separators=(",", ":"),
    )


def _claims(**changes: Any) -> dict[str, Any]:
    return {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "org": "org.synthetic",
        "env": "test",
        "sub": "user.synthetic",
        "sid": "session.synthetic",
        "device_id": "device.synthetic",
        "auth_time": NOW_SECONDS - 120,
        "entitlement_version": "license-v1",
        "features": ["analysis.read", "live_trading"],
        "role": "user",
        "roles": ["user"],
        "scope": ["api:read", "license:read"],
        "req_method": "GET",
        "req_path": "/api/profile",
        "jti": "assertion.synthetic",
        "iat": NOW_SECONDS - 10,
        "nbf": NOW_SECONDS - 10,
        "exp": NOW_SECONDS + 90,
        **changes,
    }


def _token(
    key: tuple[RSAPublicKeyV1, int],
    claims: dict[str, Any] | None = None,
    *,
    header: dict[str, Any] | None = None,
    bad_signature: bool = False,
) -> str:
    public, private = key
    header_data = (
        header if header is not None else {"alg": "RS256", "kid": "worker-key-1", "typ": "JWT"}
    )
    claim_data = claims if claims is not None else _claims()
    encoded_header = _b64(json.dumps(header_data, sort_keys=True, separators=(",", ":")).encode())
    encoded_claims = _b64(json.dumps(claim_data, sort_keys=True, separators=(",", ":")).encode())
    signed = f"{encoded_header}.{encoded_claims}"
    digest_info = _DER_SHA256 + hashlib.sha256(signed.encode("ascii")).digest()
    size = (public.modulus.bit_length() + 7) // 8
    block = b"\x00\x01" + b"\xff" * (size - len(digest_info) - 3) + b"\x00" + digest_info
    signature = pow(int.from_bytes(block, "big"), private, public.modulus).to_bytes(size, "big")
    if bad_signature:
        signature = bytes([signature[0] ^ 1]) + signature[1:]
    return f"{signed}.{_b64(signature)}"


@pytest.fixture
def verifier(synthetic_key: tuple[RSAPublicKeyV1, int]) -> WorkerAssertionVerifier:
    return WorkerAssertionVerifier(
        issuer=ISSUER,
        audience=AUDIENCE,
        jwks_json=_jwks(synthetic_key[0]),
        replay_store=InMemoryAssertionReplayStore(clock=lambda: NOW.timestamp()),
        env="test",
        clock=lambda: NOW,
    )


def test_valid_assertion_issues_request_scoped_and_core_trusted_principals(
    synthetic_key: tuple[RSAPublicKeyV1, int], verifier: WorkerAssertionVerifier
) -> None:
    principal = verifier.verify(
        _token(synthetic_key), request_method="GET", request_path="/api/profile"
    )

    assert type(principal) is WorkerRequestPrincipalV1
    assert principal.principal_id == "user.synthetic"
    assert principal.org_id == "org.synthetic"
    assert principal.session_id == "session.synthetic"
    assert principal.device_id == "device.synthetic"
    assert principal.features == ("analysis.read", "live_trading")
    assert principal.request_method == "GET"
    assert principal.request_path == "/api/profile"
    trusted = get_trusted_worker_principal(principal)
    assert type(trusted) is TrustedPrincipalV1
    assert trusted.device_id == "device.synthetic"
    assert require_worker_request_principal(principal) is principal


@pytest.mark.parametrize(
    ("token_value", "expected"),
    [
        (None, WorkerAssertionCode.MISSING_ASSERTION),
        ("", WorkerAssertionCode.MISSING_ASSERTION),
    ],
)
def test_missing_assertion_is_a_typed_content_free_error(
    verifier: WorkerAssertionVerifier, token_value: str | None, expected: str
) -> None:
    with pytest.raises(WorkerAssertionError) as error:
        verifier.verify(token_value, request_method="GET", request_path="/api/profile")
    assert error.value.code == expected
    assert str(error.value) == expected


def test_signed_assertion_missing_typ_is_rejected(
    synthetic_key: tuple[RSAPublicKeyV1, int], verifier: WorkerAssertionVerifier
) -> None:
    token = _token(synthetic_key, header={"alg": "RS256", "kid": "worker-key-1"})

    with pytest.raises(WorkerAssertionError) as error:
        verifier.verify(token, request_method="GET", request_path="/api/profile")

    assert error.value.code == WorkerAssertionCode.INVALID_ASSERTION


def test_signed_assertion_wrong_typ_is_rejected(
    synthetic_key: tuple[RSAPublicKeyV1, int], verifier: WorkerAssertionVerifier
) -> None:
    token = _token(synthetic_key, header={"alg": "RS256", "kid": "worker-key-1", "typ": "JOSE"})

    with pytest.raises(WorkerAssertionError) as error:
        verifier.verify(token, request_method="GET", request_path="/api/profile")

    assert error.value.code == WorkerAssertionCode.INVALID_ASSERTION


@pytest.mark.parametrize(
    ("claim", "value", "expected"),
    [
        ("aud", "other-api", WorkerAssertionCode.WRONG_AUDIENCE),
        ("iss", "https://other.synthetic", WorkerAssertionCode.WRONG_ISSUER),
        ("exp", NOW_SECONDS - 1, WorkerAssertionCode.EXPIRED_ASSERTION),
        ("nbf", NOW_SECONDS + 1, WorkerAssertionCode.NOT_YET_VALID),
        ("device_id", {"untrusted": "shape"}, WorkerAssertionCode.INVALID_ASSERTION),
        ("aud", [AUDIENCE], WorkerAssertionCode.WRONG_AUDIENCE),
    ],
)
def test_invalid_claims_are_rejected_with_typed_errors(
    synthetic_key: tuple[RSAPublicKeyV1, int],
    verifier: WorkerAssertionVerifier,
    claim: str,
    value: Any,
    expected: str,
) -> None:
    with pytest.raises(WorkerAssertionError) as error:
        verifier.verify(
            _token(synthetic_key, _claims(**{claim: value})),
            request_method="GET",
            request_path="/api/profile",
        )
    assert error.value.code == expected


def test_replay_signature_and_request_binding_are_rejected(
    synthetic_key: tuple[RSAPublicKeyV1, int], verifier: WorkerAssertionVerifier
) -> None:
    assertion = _token(synthetic_key)
    verifier.verify(assertion, request_method="GET", request_path="/api/profile")
    with pytest.raises(WorkerAssertionError) as replay:
        verifier.verify(assertion, request_method="GET", request_path="/api/profile")
    assert replay.value.code == WorkerAssertionCode.REPLAYED_ASSERTION

    with pytest.raises(WorkerAssertionError) as signature:
        verifier.verify(
            _token(synthetic_key, bad_signature=True),
            request_method="GET",
            request_path="/api/profile",
        )
    assert signature.value.code == WorkerAssertionCode.INVALID_ASSERTION

    with pytest.raises(WorkerAssertionError) as binding:
        verifier.verify(assertion, request_method="POST", request_path="/api/profile")
    assert binding.value.code == WorkerAssertionCode.REQUEST_BINDING_MISMATCH


def test_optional_device_id_remains_none_for_non_live_compatibility(
    synthetic_key: tuple[RSAPublicKeyV1, int], verifier: WorkerAssertionVerifier
) -> None:
    claims = _claims()
    claims.pop("device_id")
    principal = verifier.verify(
        _token(synthetic_key, claims), request_method="GET", request_path="/api/profile"
    )
    assert principal.device_id is None


def test_invalid_jwks_fails_closed_without_echoing_key_material() -> None:
    private_jwks = json.dumps({"keys": [{"kty": "RSA", "kid": "worker-key-1", "d": "fake"}]})
    with pytest.raises(WorkerAssertionError) as error:
        WorkerAssertionVerifier(
            issuer=ISSUER,
            audience=AUDIENCE,
            jwks_json=private_jwks,
            replay_store=InMemoryAssertionReplayStore(clock=lambda: NOW.timestamp()),
            env="test",
            clock=lambda: NOW,
        )
    assert error.value.code == WorkerAssertionCode.CONFIG_NOT_READY
    assert "fake" not in str(error.value)


def _request(*, headers: list[tuple[bytes, bytes]], verifier: object | None) -> Request:
    app = SimpleNamespace(state=SimpleNamespace(worker_assertion_verifier=verifier))
    return Request(
        {
            "type": "http",
            "method": "GET",
            "scheme": "https",
            "path": "/api/profile",
            "raw_path": b"/api/profile",
            "query_string": b"",
            "headers": headers,
            "server": ("api.synthetic", 443),
            "client": ("127.0.0.1", 10000),
            "app": app,
        }
    )


def test_request_dependency_rejects_missing_duplicate_and_unconfigured_headers(
    verifier: WorkerAssertionVerifier,
) -> None:
    missing = _request(headers=[], verifier=verifier)
    with pytest.raises(WorkerAssertionError) as missing_error:
        asyncio.run(require_worker_principal(missing))
    assert missing_error.value.code == WorkerAssertionCode.MISSING_ASSERTION

    duplicate = _request(
        headers=[
            (WORKER_ASSERTION_HEADER, b"opaque-a"),
            (WORKER_ASSERTION_HEADER, b"opaque-b"),
        ],
        verifier=verifier,
    )
    with pytest.raises(WorkerAssertionError) as duplicate_error:
        asyncio.run(require_worker_principal(duplicate))
    assert duplicate_error.value.code == WorkerAssertionCode.INVALID_ASSERTION

    unconfigured = _request(headers=[(WORKER_ASSERTION_HEADER, b"opaque")], verifier=None)
    with pytest.raises(WorkerAssertionError) as config_error:
        asyncio.run(require_worker_principal(unconfigured))
    assert config_error.value.code == WorkerAssertionCode.CONFIG_NOT_READY
