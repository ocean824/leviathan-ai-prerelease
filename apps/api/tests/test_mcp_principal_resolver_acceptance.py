"""Independent contract tests for the SEC-003 to SEC-002 MCP resolver."""

from __future__ import annotations

import base64
import hashlib
import json
import math
import random
from datetime import UTC, datetime
from typing import Any

import pytest

from leviathan_api.security.mcp_principal_resolver import (
    McpPrincipalResolutionError,
    McpPrincipalResolverV1,
)
from leviathan_core.security import (
    ActionV1,
    AuthorizationContextV1,
    AuthorizationPolicyV1,
    EffectV1,
    PolicyRuleV1,
    ResourceV1,
    TrustedPrincipalV1,
    authorize,
)
from leviathan_core.security.authz_models import require_trusted_principal
from leviathan_core.security.principal_verifier import (
    PrincipalVerifier,
    RSAPublicKeyV1,
    TrustedIssuerV1,
    VerifiedPrincipalV1,
)

_NOW = datetime(2026, 10, 6, 18, 0, tzinfo=UTC)
_NOW_SECONDS = int(_NOW.timestamp())
_ISSUER = "resolver.synthetic"
_AUDIENCE = "mcp.synthetic"
_ORG = "org.synthetic"
_PROJECT = "project.synthetic"
_ENV = "test"
_KID = "resolver-test-key"
_CERT = b"synthetic MCP peer certificate"
_TOKEN_CANARY = "token-secret-canary-resolver-7e4d"
_DER_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")


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


@pytest.fixture(scope="module")
def _rsa_key() -> tuple[RSAPublicKeyV1, int]:
    rng = random.Random(0x4D435052)
    p, q = _prime(rng), _prime(rng)
    while p == q or math.gcd(65537, (p - 1) * (q - 1)) != 1:
        q = _prime(rng)
    modulus = p * q
    return RSAPublicKeyV1(modulus, 65537), pow(65537, -1, (p - 1) * (q - 1))


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _segment(value: object) -> str:
    return _b64(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def _token(
    key: tuple[RSAPublicKeyV1, int],
    *,
    claims: dict[str, Any] | None = None,
    signature_canary: str | None = None,
) -> str:
    public_key, private_exponent = key
    token_claims = {
        "iss": _ISSUER,
        "aud": _AUDIENCE,
        "org": _ORG,
        "project": _PROJECT,
        "sub": "operator.synthetic",
        "role": "mcp.reader",
        "scope": ["mcp:read"],
        "env": _ENV,
        "jti": "jti-synthetic-1",
        "iat": _NOW_SECONDS - 1,
        "nbf": _NOW_SECONDS - 1,
        "exp": _NOW_SECONDS + 300,
    }
    if claims:
        token_claims.update(claims)
    header = _segment({"alg": "RS256", "kid": _KID, "typ": "JWT"})
    payload = _segment(token_claims)
    signed = f"{header}.{payload}".encode("ascii")
    digest_info = _DER_PREFIX + hashlib.sha256(signed).digest()
    width = (public_key.modulus.bit_length() + 7) // 8
    padding = width - len(digest_info) - 3
    encoded = b"\x00\x01" + b"\xff" * padding + b"\x00" + digest_info
    signature = pow(int.from_bytes(encoded, "big"), private_exponent, public_key.modulus)
    signature_bytes = signature.to_bytes(width, "big")
    if signature_canary:
        signature_bytes = bytes([signature_bytes[0] ^ 1]) + signature_bytes[1:]
    return f"{header}.{payload}.{_b64(signature_bytes)}"


class _KeySet:
    def __init__(self, key: RSAPublicKeyV1) -> None:
        self.key = key

    def get_key(self, issuer: str, kid: str) -> RSAPublicKeyV1 | None:
        return self.key if (issuer, kid) == (_ISSUER, _KID) else None


class _Revocations:
    def __init__(self, revoked: bool = False) -> None:
        self.revoked = revoked

    def is_revoked(self, _issuer: str, _jti: str) -> bool:
        return self.revoked


class _RaisingKeySet:
    def get_key(self, _issuer: str, _kid: str) -> RSAPublicKeyV1 | None:
        raise RuntimeError(_TOKEN_CANARY)


def _verifier(
    key: RSAPublicKeyV1,
    *,
    project_id: str = _PROJECT,
    env: str = _ENV,
    revoked: bool = False,
    key_set: object | None = None,
) -> PrincipalVerifier:
    return PrincipalVerifier(
        trusted_issuer=TrustedIssuerV1(_ISSUER, _AUDIENCE, _ORG, project_id, env),
        key_set=key_set if key_set is not None else _KeySet(key),
        revocations=_Revocations(revoked),
        clock=lambda: _NOW,
    )


def _rejected(resolver: McpPrincipalResolverV1, token: object) -> McpPrincipalResolutionError:
    with pytest.raises(McpPrincipalResolutionError) as raised:
        resolver.resolve(token, peer_certificate_der=_CERT)
    assert raised.value.code.value == "PRINCIPAL_REJECTED"
    return raised.value


def test_valid_verifier_result_is_adapted_to_an_issued_sec002_principal(
    _rsa_key: tuple[RSAPublicKeyV1, int],
) -> None:
    resolver = McpPrincipalResolverV1(_verifier(_rsa_key[0]))

    principal = resolver.resolve(
        _token(_rsa_key, claims={"project": "forged.project"}),
        peer_certificate_der=_CERT,
    )

    assert type(principal) is TrustedPrincipalV1
    assert require_trusted_principal(principal) is principal
    assert principal.principal_id == "operator.synthetic"
    assert principal.project_id == _PROJECT
    assert principal.env == _ENV
    assert principal.roles == ("mcp.reader",)


def test_resolve_verified_returns_the_exact_issued_sec003_result_once(
    _rsa_key: tuple[RSAPublicKeyV1, int],
) -> None:
    verifier = _verifier(_rsa_key[0])
    original_verify = verifier.verify
    issued: list[VerifiedPrincipalV1] = []
    calls = 0

    def capture(token: str, *, peer_certificate_der: bytes | None = None) -> VerifiedPrincipalV1:
        nonlocal calls
        calls += 1
        result = original_verify(token, peer_certificate_der=peer_certificate_der)
        issued.append(result)
        return result

    verifier.verify = capture  # type: ignore[method-assign]
    resolver = McpPrincipalResolverV1(verifier)

    result = resolver.resolve_verified(_token(_rsa_key), peer_certificate_der=_CERT)

    assert calls == 1
    assert type(result) is VerifiedPrincipalV1
    assert issued == [result]
    assert result is issued[0]
    assert result.subject_id == "operator.synthetic"


def test_sec002_denies_a_different_resource_project(
    _rsa_key: tuple[RSAPublicKeyV1, int],
) -> None:
    principal = McpPrincipalResolverV1(_verifier(_rsa_key[0])).resolve(
        _token(_rsa_key, claims={"project": "forged.project"}),
        peer_certificate_der=_CERT,
    )
    now = _NOW
    policy = AuthorizationPolicyV1(
        version="v1",
        project_id="other.project",
        expires_at=datetime(2026, 10, 7, tzinfo=UTC),
        rules=(
            PolicyRuleV1(
                rule_id="allow-read",
                effect=EffectV1.ALLOW,
                roles=("mcp.reader",),
                actions=("mcp.read",),
                resources=("synthetic-resource",),
                env=_ENV,
                not_before=datetime(2026, 10, 6, 17, 0, tzinfo=UTC),
                not_after=datetime(2026, 10, 7, tzinfo=UTC),
            ),
        ),
    )

    decision = authorize(
        principal,
        ActionV1("mcp.read"),
        ResourceV1("synthetic-resource", "other.project", _ENV),
        AuthorizationContextV1("other.project", _ENV, now),
        policy,
    )

    assert principal.project_id == _PROJECT
    assert not decision.allowed


def test_missing_verifier_fails_closed_with_fixed_error() -> None:
    resolver = McpPrincipalResolverV1(None)

    with pytest.raises(McpPrincipalResolutionError) as raised:
        resolver.resolve("opaque-synthetic-token")

    assert raised.value.code.value == "VERIFIER_UNAVAILABLE"
    assert str(raised.value) == raised.value.code.value


@pytest.mark.parametrize(
    "claims, verifier_changes",
    [
        ({"exp": _NOW_SECONDS - 1}, {}),
        ({"org": "other.org"}, {}),
        ({"env": "production"}, {}),
        ({}, {"revoked": True}),
    ],
)
def test_expired_revoked_wrong_project_and_wrong_env_are_rejected(
    _rsa_key: tuple[RSAPublicKeyV1, int],
    claims: dict[str, object],
    verifier_changes: dict[str, object],
) -> None:
    resolver = McpPrincipalResolverV1(_verifier(_rsa_key[0], **verifier_changes))

    _rejected(resolver, _token(_rsa_key, claims=claims))


def test_invalid_token_and_verifier_port_exception_are_content_free(
    _rsa_key: tuple[RSAPublicKeyV1, int], caplog: pytest.LogCaptureFixture
) -> None:
    bad_token = _token(
        _rsa_key,
        claims={"jti": _TOKEN_CANARY},
        signature_canary=_TOKEN_CANARY,
    )
    invalid_resolver = McpPrincipalResolverV1(_verifier(_rsa_key[0]))
    invalid_error = _rejected(invalid_resolver, bad_token)

    broken_verifier = _verifier(_rsa_key[0], key_set=_RaisingKeySet())
    broken_resolver = McpPrincipalResolverV1(broken_verifier)
    port_error = _rejected(broken_resolver, _token(_rsa_key))

    for error in (invalid_error, port_error):
        assert _TOKEN_CANARY not in str(error)
        assert _TOKEN_CANARY not in repr(error)
        assert error.__cause__ is None
        assert error.__context__ is None
    assert _TOKEN_CANARY not in caplog.text


def test_malformed_input_is_rejected_without_echoing_input(
    _rsa_key: tuple[RSAPublicKeyV1, int],
) -> None:
    resolver = McpPrincipalResolverV1(_verifier(_rsa_key[0]))
    marker = f"{_TOKEN_CANARY}.malformed"

    with pytest.raises(McpPrincipalResolutionError) as raised:
        resolver.resolve(marker)

    assert raised.value.code.value == "PRINCIPAL_REJECTED"
    assert marker not in str(raised.value)
    assert _TOKEN_CANARY not in repr(raised.value)
