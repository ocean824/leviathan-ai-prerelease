"""Synthetic-only tests for the SEC-003 to SEC-002 MCP principal adapter."""

from __future__ import annotations

import base64
import hashlib
import json
import math
import random
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import pytest

from leviathan_api.security.mcp_principal_resolver import (
    McpPrincipalResolutionCodeV1,
    McpPrincipalResolutionError,
    McpPrincipalResolverV1,
)
from leviathan_core.security.authz_models import TrustedPrincipalV1, is_trusted_principal
from leviathan_core.security.principal_verifier import (
    PrincipalVerifier,
    RSAPublicKeyV1,
    TrustedIssuerV1,
    VerifiedPrincipalV1,
)

_NOW = datetime(2026, 10, 6, 12, tzinfo=UTC)
_NOW_SECONDS = int(_NOW.timestamp())
_DIGEST_INFO_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")


def _prime(rng: random.Random) -> int:
    """Generate test-only RSA primes; no key material is used outside tests."""
    while True:
        candidate = rng.getrandbits(1024) | (3 << 1022) | 1
        if any(candidate % divisor == 0 for divisor in (3, 5, 7, 11, 13, 17, 19, 23, 29)):
            continue
        s, d = 0, candidate - 1
        while d % 2 == 0:
            s, d = s + 1, d // 2
        for base in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
            value = pow(base, d, candidate)
            if value in (1, candidate - 1):
                continue
            for _ in range(s - 1):
                value = pow(value, 2, candidate)
                if value == candidate - 1:
                    break
            else:
                break
        else:
            return candidate


@pytest.fixture(scope="module")
def synthetic_key() -> tuple[RSAPublicKeyV1, int]:
    rng = random.Random(0x4D435052)
    p, q = _prime(rng), _prime(rng)
    while q == p or math.gcd(65537, (p - 1) * (q - 1)) != 1:
        q = _prime(rng)
    modulus = p * q
    return RSAPublicKeyV1(modulus, 65537), pow(65537, -1, (p - 1) * (q - 1))


class _Keys:
    def __init__(self, public_key: RSAPublicKeyV1) -> None:
        self._public_key = public_key

    def get_key(self, issuer: str, kid: str) -> RSAPublicKeyV1 | None:
        if issuer == "issuer.synthetic" and kid == "kid.synthetic":
            return self._public_key
        return None


class _Revocations:
    def __init__(self, revoked: bool = False, failure: bool = False) -> None:
        self._revoked = revoked
        self._failure = failure

    def is_revoked(self, issuer: str, jti: str) -> bool:
        if self._failure:
            raise RuntimeError("synthetic revocation-port failure")
        return self._revoked


@pytest.fixture(scope="module")
def synthetic_material(
    synthetic_key: tuple[RSAPublicKeyV1, int],
) -> tuple[PrincipalVerifier, tuple[RSAPublicKeyV1, int]]:
    verifier = PrincipalVerifier(
        trusted_issuer=TrustedIssuerV1(
            "issuer.synthetic",
            "audience.synthetic",
            "org.synthetic",
            "project.synthetic",
            "test",
        ),
        key_set=_Keys(synthetic_key[0]),
        revocations=_Revocations(),
        clock=lambda: _NOW,
    )
    return verifier, synthetic_key


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _token(
    key: tuple[RSAPublicKeyV1, int],
    *,
    changes: dict[str, object] | None = None,
) -> str:
    header = {"alg": "RS256", "kid": "kid.synthetic"}
    claims: dict[str, Any] = {
        "iss": "issuer.synthetic",
        "aud": "audience.synthetic",
        "org": "org.synthetic",
        "env": "test",
        "sub": "mcp.client.synthetic",
        "role": "mcp.read",
        "scope": ["mcp.tool.read"],
        "jti": "jti.synthetic",
        "iat": _NOW_SECONDS - 10,
        "nbf": _NOW_SECONDS - 10,
        "exp": _NOW_SECONDS + 100,
    }
    claims.update(changes or {})
    encoded_header = _b64(json.dumps(header, sort_keys=True, separators=(",", ":")).encode())
    encoded_claims = _b64(json.dumps(claims, sort_keys=True, separators=(",", ":")).encode())
    unsigned = f"{encoded_header}.{encoded_claims}".encode("ascii")
    public_key, private_exponent = key
    info = _DIGEST_INFO_PREFIX + hashlib.sha256(unsigned).digest()
    block_size = (public_key.modulus.bit_length() + 7) // 8
    padding = b"\x00\x01" + b"\xff" * (block_size - len(info) - 3) + b"\x00" + info
    signature = pow(int.from_bytes(padding, "big"), private_exponent, public_key.modulus)
    return f"{unsigned.decode('ascii')}.{_b64(signature.to_bytes(block_size, 'big'))}"


def _replace_claim_without_resigning(token: str, name: str, value: object) -> str:
    header, claims, signature = token.split(".")
    padding = "=" * (-len(claims) % 4)
    decoded = json.loads(base64.urlsafe_b64decode(claims + padding))
    decoded[name] = value
    changed = _b64(json.dumps(decoded, sort_keys=True, separators=(",", ":")).encode())
    return f"{header}.{changed}.{signature}"


def test_resolves_only_an_issued_sec002_principal(
    synthetic_material: tuple[PrincipalVerifier, tuple[RSAPublicKeyV1, int]],
) -> None:
    verifier, key = synthetic_material
    principal = McpPrincipalResolverV1(verifier).resolve(_token(key))

    assert type(principal) is TrustedPrincipalV1
    assert is_trusted_principal(principal)
    assert principal.principal_id == "mcp.client.synthetic"
    assert principal.project_id == "project.synthetic"
    assert principal.roles == ("mcp.read",)
    assert principal.env == "test"
    assert principal.break_glass is False


def test_resolve_verified_returns_exact_verifier_output_without_reissue(
    synthetic_material: tuple[PrincipalVerifier, tuple[RSAPublicKeyV1, int]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verifier, key = synthetic_material
    token = _token(key)
    issued = verifier.verify(token)
    calls = 0

    def return_issued(
        incoming: str, *, peer_certificate_der: bytes | None = None
    ) -> VerifiedPrincipalV1:
        nonlocal calls
        calls += 1
        assert incoming == token
        assert peer_certificate_der is None
        return issued

    monkeypatch.setattr(verifier, "verify", return_issued)
    resolved = McpPrincipalResolverV1(verifier).resolve_verified(token)

    assert resolved is issued
    assert type(resolved) is VerifiedPrincipalV1
    assert calls == 1


def test_resolve_uses_one_verification_then_sec002_adaptation(
    synthetic_material: tuple[PrincipalVerifier, tuple[RSAPublicKeyV1, int]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verifier, key = synthetic_material
    original = verifier.verify
    calls = 0

    def count_verify(
        token: str, *, peer_certificate_der: bytes | None = None
    ) -> VerifiedPrincipalV1:
        nonlocal calls
        calls += 1
        return original(token, peer_certificate_der=peer_certificate_der)

    monkeypatch.setattr(verifier, "verify", count_verify)
    principal = McpPrincipalResolverV1(verifier).resolve(_token(key))

    assert is_trusted_principal(principal)
    assert calls == 1


@pytest.mark.parametrize("verifier", [None, object()])
def test_missing_or_wrong_verifier_fails_closed(verifier: object) -> None:
    resolver = McpPrincipalResolverV1(cast(PrincipalVerifier | None, verifier))

    with pytest.raises(McpPrincipalResolutionError) as failure:
        resolver.resolve("synthetic-token-secret-fragment")

    assert failure.value.code is McpPrincipalResolutionCodeV1.VERIFIER_UNAVAILABLE
    assert str(failure.value) == "VERIFIER_UNAVAILABLE"
    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None
    assert "synthetic-token-secret-fragment" not in repr(failure.value)


@pytest.mark.parametrize(
    ("token", "certificate"),
    [
        ("synthetic-secret-fragment", None),
        (None, None),
        ("token.synthetic", "not-certificate-bytes"),
    ],
)
def test_malformed_or_unverified_input_is_content_free(
    synthetic_material: tuple[PrincipalVerifier, tuple[RSAPublicKeyV1, int]],
    token: object,
    certificate: object | None,
) -> None:
    verifier, _ = synthetic_material
    resolver = McpPrincipalResolverV1(verifier)

    with pytest.raises(McpPrincipalResolutionError) as failure:
        resolver.resolve(token, peer_certificate_der=certificate)

    assert failure.value.code is McpPrincipalResolutionCodeV1.PRINCIPAL_REJECTED
    assert str(failure.value) == "PRINCIPAL_REJECTED"
    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None
    assert "synthetic-secret-fragment" not in repr(failure.value)


def test_resolve_verified_rejects_wrong_output_type_without_context(
    synthetic_material: tuple[PrincipalVerifier, tuple[RSAPublicKeyV1, int]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verifier, key = synthetic_material
    monkeypatch.setattr(verifier, "verify", lambda *args, **kwargs: object())

    with pytest.raises(McpPrincipalResolutionError) as failure:
        McpPrincipalResolverV1(verifier).resolve_verified(_token(key))

    assert failure.value.code is McpPrincipalResolutionCodeV1.PRINCIPAL_REJECTED
    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None


@pytest.mark.parametrize(
    "changes",
    [
        {"org": "org.attacker"},
        {"env": "production"},
        {"approval": "approved"},
        {"entitlement": "all"},
        {"break_glass": True},
        {"sub": "bad subject spaces"},
        {"iat": True},
    ],
)
def test_invalid_signed_claims_never_become_authority(
    synthetic_material: tuple[PrincipalVerifier, tuple[RSAPublicKeyV1, int]],
    changes: dict[str, object],
) -> None:
    verifier, key = synthetic_material
    with pytest.raises(McpPrincipalResolutionError) as failure:
        McpPrincipalResolverV1(verifier).resolve(_token(key, changes=changes))

    assert failure.value.code is McpPrincipalResolutionCodeV1.PRINCIPAL_REJECTED
    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None


@pytest.mark.parametrize(
    ("claim", "value"),
    [("role", "admin"), ("scope", ["admin.all"]), ("org", "org.attacker")],
)
def test_unsigned_client_claim_changes_are_rejected(
    synthetic_material: tuple[PrincipalVerifier, tuple[RSAPublicKeyV1, int]],
    claim: str,
    value: object,
) -> None:
    verifier, key = synthetic_material
    changed = _replace_claim_without_resigning(_token(key), claim, value)

    with pytest.raises(McpPrincipalResolutionError) as failure:
        McpPrincipalResolverV1(verifier).resolve(changed)

    assert failure.value.code is McpPrincipalResolutionCodeV1.PRINCIPAL_REJECTED
    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None


def test_no_client_supplied_authority_parameters_exist(
    synthetic_material: tuple[PrincipalVerifier, tuple[RSAPublicKeyV1, int]],
) -> None:
    verifier, key = synthetic_material
    resolver = McpPrincipalResolverV1(verifier)

    with pytest.raises(TypeError):
        resolver.resolve(_token(key), role="admin", org_id="org.attacker", scopes=("admin.all",))  # type: ignore[call-arg]


@pytest.mark.parametrize("failure_mode", ["expired", "revoked", "revocation-error"])
def test_expiry_and_revocation_failures_are_normalized(
    synthetic_key: tuple[RSAPublicKeyV1, int],
    failure_mode: str,
) -> None:
    public_key, _ = synthetic_key
    verifier = PrincipalVerifier(
        trusted_issuer=TrustedIssuerV1(
            "issuer.synthetic",
            "audience.synthetic",
            "org.synthetic",
            "project.synthetic",
            "test",
        ),
        key_set=_Keys(public_key),
        revocations=_Revocations(
            revoked=failure_mode == "revoked",
            failure=failure_mode == "revocation-error",
        ),
        clock=lambda: _NOW + (timedelta(seconds=161) if failure_mode == "expired" else timedelta()),
    )

    with pytest.raises(McpPrincipalResolutionError) as failure:
        McpPrincipalResolverV1(verifier).resolve(_token(synthetic_key))

    assert failure.value.code is McpPrincipalResolutionCodeV1.PRINCIPAL_REJECTED
    assert str(failure.value) == "PRINCIPAL_REJECTED"
    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None
