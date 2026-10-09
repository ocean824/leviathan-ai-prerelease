"""SEC-003 pure verifier tests with deterministic, synthetic in-memory RSA keys."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import math
import pickle
import random
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest

from leviathan_core.seal import SealError, verify
from leviathan_core.security import TrustedPrincipalV1
from leviathan_core.security.principal_verifier import (
    PrincipalVerificationError,
    PrincipalVerifier,
    RSAPublicKeyV1,
    TrustedIssuerV1,
    VerificationCodeV1,
    VerifiedPrincipalV1,
)

NOW = datetime(2026, 10, 5, 12, tzinfo=UTC)
NOW_SECONDS = int(NOW.timestamp())
_DER_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")
_PEER = b"synthetic DER certificate bytes for tests only"


def _prime(rng: random.Random) -> int:
    # Test-only probable prime generation. No production signing key is issued.
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
    rng = random.Random(0x5EC003)
    p, q = _prime(rng), _prime(rng)
    while q == p or math.gcd(65537, (p - 1) * (q - 1)) != 1:
        q = _prime(rng)
    modulus = p * q
    return RSAPublicKeyV1(modulus, 65537), pow(65537, -1, (p - 1) * (q - 1))


class _Keys:
    def __init__(self, key: RSAPublicKeyV1) -> None:
        self.key = key

    def get_key(self, issuer: str, kid: str) -> RSAPublicKeyV1 | None:
        if issuer == "issuer.synthetic" and kid == "test.1":
            return self.key
        return None


class _Revocations:
    def __init__(self, revoked: bool = False) -> None:
        self.revoked = revoked

    def is_revoked(self, issuer: str, jti: str) -> bool:
        return self.revoked


def _verifier(
    key: RSAPublicKeyV1, *, now: datetime = NOW, mtls: bool = False,
    revoked: bool = False,
) -> PrincipalVerifier:
    return PrincipalVerifier(
        trusted_issuer=TrustedIssuerV1(
            "issuer.synthetic", "api.synthetic", "org.synthetic", "leviathan-ai", "test", mtls,
        ),
        key_set=_Keys(key), revocations=_Revocations(revoked), clock=lambda: now,
    )


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _claims() -> dict[str, Any]:
    return {
        "iss": "issuer.synthetic", "aud": "api.synthetic", "org": "org.synthetic",
        "sub": "service.alpha", "role": "risk.admin", "scope": ["research.read"],
        "env": "test", "venue": "XNYS", "portfolio": "book.1",
        "strategy": "alpha.1", "jti": "jti.1",
        "iat": NOW_SECONDS - 10, "nbf": NOW_SECONDS - 10, "exp": NOW_SECONDS + 100,
    }


def _token(
    key: tuple[RSAPublicKeyV1, int], *, claims: dict[str, Any] | None = None,
    header: dict[str, Any] | None = None, bad_signature: bool = False,
) -> str:
    header_data = header if header is not None else {"alg": "RS256", "kid": "test.1"}
    claim_data = claims if claims is not None else _claims()
    encoded = ".".join(
        _b64(json.dumps(part, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        for part in (header_data, claim_data)
    )
    encoded_header, encoded_claims = encoded.split(".")
    return _signed_token(key, encoded_header, encoded_claims, bad_signature=bad_signature)


def _signed_token(
    key: tuple[RSAPublicKeyV1, int], encoded_header: str, encoded_claims: str,
    *, bad_signature: bool = False,
) -> str:
    public, private = key
    encoded = f"{encoded_header}.{encoded_claims}"
    digest_info = _DER_PREFIX + hashlib.sha256(encoded.encode("ascii")).digest()
    size = (public.modulus.bit_length() + 7) // 8
    block = b"\x00\x01" + b"\xff" * (size - len(digest_info) - 3) + b"\x00" + digest_info
    signature = pow(int.from_bytes(block, "big"), private, public.modulus).to_bytes(size, "big")
    if bad_signature:
        signature = bytes([signature[0] ^ 1]) + signature[1:]
    return f"{encoded_header}.{encoded_claims}.{_b64(signature)}"


def _alternate_b64(segment: str) -> str:
    assert len(segment) % 4 in (2, 3)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    return segment[:-1] + alphabet[alphabet.index(segment[-1]) ^ 1]


def test_valid_token_issues_sealed_principal_and_sec002_identity(
    synthetic_key: tuple[RSAPublicKeyV1, int],
) -> None:
    verifier = _verifier(synthetic_key[0])
    verified = verifier.verify(_token(synthetic_key))
    with pytest.raises(PrincipalVerificationError) as direct:
        VerifiedPrincipalV1(**verified.model_dump())
    assert direct.value.code is VerificationCodeV1.PRINCIPAL_UNISSUED
    assert verify(verified, "sec003.verified_principal.v1")
    assert verified.verified_at_ns == NOW_SECONDS * 1_000_000_000
    assert verified.scopes == ("research.read",)
    assert verified.org_id == "org.synthetic"
    claims = verifier.to_sec002_claims(verified)
    assert claims.principal_id == "service.alpha"
    assert claims.roles == ("risk.admin",)
    trusted = verifier.to_trusted_principal(verified)
    assert type(trusted) is TrustedPrincipalV1
    assert trusted.project_id == "leviathan-ai"
    assert trusted.break_glass is False


@pytest.mark.parametrize("change", [
    {"iss": "issuer.other"}, {"aud": "api.other"}, {"org": "org.other"},
    {"env": "prod"}, {"role": "admin*"}, {"scope": ["research.read", "research.read"]},
    {"exp": NOW_SECONDS + 901}, {"exp": NOW_SECONDS - 61},
    {"iat": NOW_SECONDS + 61}, {"nbf": NOW_SECONDS + 61},
    {"iat": True}, {"sub": None}, {"approval": "approved"},
])
def test_invalid_claims_fail_closed_and_redacted(
    synthetic_key: tuple[RSAPublicKeyV1, int], change: dict[str, Any],
) -> None:
    claims = _claims() | change
    token = _token(synthetic_key, claims=claims)
    with pytest.raises(PrincipalVerificationError) as failure:
        _verifier(synthetic_key[0]).verify(token)
    assert failure.value.code is VerificationCodeV1.TOKEN_REJECTED
    assert str(failure.value) == "TOKEN_REJECTED"
    assert token not in str(failure.value)


def test_bad_algorithm_kid_signature_revocation_and_clock(
    synthetic_key: tuple[RSAPublicKeyV1, int],
) -> None:
    key = synthetic_key[0]
    tokens = [
        _token(synthetic_key, header={"alg": "none", "kid": "test.1"}),
        _token(synthetic_key, header={"alg": "HS256", "kid": "test.1"}),
        _token(synthetic_key, header={"alg": "RS256", "kid": "unknown"}),
        _token(synthetic_key, bad_signature=True),
    ]
    for token in tokens:
        with pytest.raises(PrincipalVerificationError, match=r"^TOKEN_REJECTED$"):
            _verifier(key).verify(token)
    with pytest.raises(PrincipalVerificationError, match=r"^TOKEN_REJECTED$"):
        _verifier(key, revoked=True).verify(_token(synthetic_key))
    with pytest.raises(PrincipalVerificationError, match=r"^TOKEN_REJECTED$"):
        _verifier(key, now=NOW.replace(tzinfo=timezone(timedelta(hours=1)))).verify(
            _token(synthetic_key)
        )


def test_skew_at_boundary_and_one_second_outside(
    synthetic_key: tuple[RSAPublicKeyV1, int],
) -> None:
    claims = _claims() | {"iat": NOW_SECONDS - 900, "nbf": NOW_SECONDS - 900, "exp": NOW_SECONDS}
    token = _token(synthetic_key, claims=claims)
    assert _verifier(synthetic_key[0], now=NOW + timedelta(seconds=60)).verify(token)
    with pytest.raises(PrincipalVerificationError):
        _verifier(synthetic_key[0], now=NOW + timedelta(seconds=61)).verify(token)


def test_conversion_rechecks_exact_expiry_and_revocation(
    synthetic_key: tuple[RSAPublicKeyV1, int],
) -> None:
    moment = [NOW]
    revocations = _Revocations()
    verifier = PrincipalVerifier(
        trusted_issuer=TrustedIssuerV1(
            "issuer.synthetic", "api.synthetic", "org.synthetic", "leviathan-ai", "test"
        ),
        key_set=_Keys(synthetic_key[0]), revocations=revocations,
        clock=lambda: moment[0],
    )
    token = _token(synthetic_key)
    verified = verifier.verify(token)
    moment[0] = NOW + timedelta(seconds=160)
    assert verifier.to_sec002_claims(verified).principal_id == "service.alpha"
    moment[0] += timedelta(microseconds=1)
    with pytest.raises(PrincipalVerificationError) as expired:
        verifier.to_trusted_principal(verified)
    assert expired.value.code is VerificationCodeV1.PRINCIPAL_UNISSUED
    with pytest.raises(PrincipalVerificationError):
        verifier.verify(token)
    moment[0] = NOW
    revocations.revoked = True
    with pytest.raises(PrincipalVerificationError) as revoked:
        verifier.to_sec002_claims(verified)
    assert revoked.value.code is VerificationCodeV1.PRINCIPAL_UNISSUED
    with pytest.raises(PrincipalVerificationError):
        verifier.to_trusted_principal(verified)


def test_conversion_rechecks_future_issue_skew_at_microsecond_boundary(
    synthetic_key: tuple[RSAPublicKeyV1, int],
) -> None:
    moment = [NOW]
    verifier = PrincipalVerifier(
        trusted_issuer=TrustedIssuerV1(
            "issuer.synthetic", "api.synthetic", "org.synthetic", "leviathan-ai", "test"
        ),
        key_set=_Keys(synthetic_key[0]), revocations=_Revocations(),
        clock=lambda: moment[0],
    )
    token = _token(
        synthetic_key,
        claims=_claims() | {"iat": NOW_SECONDS + 60, "exp": NOW_SECONDS + 120},
    )
    verified = verifier.verify(token)
    assert verifier.to_sec002_claims(verified).principal_id == "service.alpha"
    moment[0] -= timedelta(microseconds=1)
    with pytest.raises(PrincipalVerificationError) as too_early:
        verifier.to_sec002_claims(verified)
    assert too_early.value.code is VerificationCodeV1.PRINCIPAL_UNISSUED


def test_conversion_rejects_clock_and_revocation_port_failure(
    synthetic_key: tuple[RSAPublicKeyV1, int],
) -> None:
    verified = _verifier(synthetic_key[0]).verify(_token(synthetic_key))

    class FailingRevocations:
        def is_revoked(self, issuer: str, jti: str) -> bool:
            raise ValueError("secret_canary")

    policy = TrustedIssuerV1(
        "issuer.synthetic", "api.synthetic", "org.synthetic", "leviathan-ai", "test"
    )
    for clock, revocations in (
        (lambda: NOW, FailingRevocations()),
        (lambda: datetime(2026, 10, 5, 12), _Revocations()),
    ):
        verifier = PrincipalVerifier(
            trusted_issuer=policy, key_set=_Keys(synthetic_key[0]),
            revocations=revocations, clock=clock,
        )
        with pytest.raises(PrincipalVerificationError) as failure:
            verifier.to_trusted_principal(verified)
        assert failure.value.code is VerificationCodeV1.PRINCIPAL_UNISSUED
        assert failure.value.__context__ is None


def test_all_three_token_segments_require_canonical_base64url(
    synthetic_key: tuple[RSAPublicKeyV1, int],
) -> None:
    header = json.dumps({"alg": "RS256", "kid": "test.1"}, sort_keys=True).encode()
    claims = json.dumps(_claims(), sort_keys=True).encode()
    if len(header) % 3 == 0:
        header += b" "
    if len(claims) % 3 == 0:
        claims += b" "
    encoded_header, encoded_claims = _b64(header), _b64(claims)
    canonical = _signed_token(synthetic_key, encoded_header, encoded_claims)
    verifier = _verifier(synthetic_key[0])
    assert verifier.verify(canonical).subject_id == "service.alpha"
    for altered_header, altered_claims in (
        (_alternate_b64(encoded_header), encoded_claims),
        (encoded_header, _alternate_b64(encoded_claims)),
    ):
        alternate = _signed_token(synthetic_key, altered_header, altered_claims)
        with pytest.raises(PrincipalVerificationError) as rejected:
            verifier.verify(alternate)
        assert rejected.value.code is VerificationCodeV1.TOKEN_REJECTED
    encoded_signature = canonical.split(".")[2]
    alternate_signature = f"{encoded_header}.{encoded_claims}.{_alternate_b64(encoded_signature)}"
    with pytest.raises(PrincipalVerificationError):
        verifier.verify(alternate_signature)


def test_mtls_binding_requires_matching_peer_bytes(
    synthetic_key: tuple[RSAPublicKeyV1, int],
) -> None:
    thumbprint = _b64(hashlib.sha256(_PEER).digest())
    token = _token(synthetic_key, claims=_claims() | {"cnf": {"x5t#S256": thumbprint}})
    verifier = _verifier(synthetic_key[0], mtls=True)
    with pytest.raises(PrincipalVerificationError):
        verifier.verify(token)
    with pytest.raises(PrincipalVerificationError):
        verifier.verify(token, peer_certificate_der=b"different synthetic peer")
    assert verifier.verify(token, peer_certificate_der=_PEER).certificate_binding == thumbprint
    with pytest.raises(PrincipalVerificationError):
        verifier.verify(_token(synthetic_key), peer_certificate_der=_PEER)


def test_body_fields_cannot_override_signed_role_or_org(
    synthetic_key: tuple[RSAPublicKeyV1, int],
) -> None:
    body = {"role": "root.admin", "org": "org.other", "break_glass": True}
    verified = _verifier(synthetic_key[0]).verify(_token(synthetic_key))
    assert verified.role != body["role"]
    assert verified.org_id != body["org"]
    assert _verifier(synthetic_key[0]).to_trusted_principal(verified).break_glass is False


def test_unissued_copies_and_reconstruction_cannot_cross_adapter(
    synthetic_key: tuple[RSAPublicKeyV1, int],
) -> None:
    verifier = _verifier(synthetic_key[0])
    verified = verifier.verify(_token(synthetic_key))
    with pytest.raises((SealError, PrincipalVerificationError)):
        VerifiedPrincipalV1.model_validate(verified.model_dump())
    with pytest.raises((SealError, PrincipalVerificationError)):
        verified.model_copy(update={"role": "root.admin"})
    with pytest.raises(PrincipalVerificationError) as failure:
        verifier.to_trusted_principal(verified.model_dump())  # type: ignore[arg-type]
    assert failure.value.code is VerificationCodeV1.PRINCIPAL_UNISSUED
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(SealError):
            operation(verified)


def test_exact_project_binding_between_verifiers(
    synthetic_key: tuple[RSAPublicKeyV1, int],
) -> None:
    verified = _verifier(synthetic_key[0]).verify(_token(synthetic_key))
    other = PrincipalVerifier(
        trusted_issuer=TrustedIssuerV1(
            "issuer.synthetic", "api.synthetic", "org.synthetic", "project.other", "test"
        ),
        key_set=_Keys(synthetic_key[0]), revocations=_Revocations(), clock=lambda: NOW,
    )
    with pytest.raises(PrincipalVerificationError):
        other.to_trusted_principal(verified)


def test_parser_and_port_failures_do_not_chain_untrusted_data(
    synthetic_key: tuple[RSAPublicKeyV1, int],
) -> None:
    malformed_header = b'{"secret_canary":'
    malformed = f"{_b64(malformed_header)}.e30.eA"
    with pytest.raises(PrincipalVerificationError) as parser_failure:
        _verifier(synthetic_key[0]).verify(malformed)
    assert parser_failure.value.code is VerificationCodeV1.TOKEN_REJECTED
    assert parser_failure.value.__context__ is None

    class FailingKeys:
        def get_key(self, issuer: str, kid: str) -> RSAPublicKeyV1 | None:
            raise ValueError("secret_canary")

    verifier = PrincipalVerifier(
        trusted_issuer=TrustedIssuerV1(
            "issuer.synthetic", "api.synthetic", "org.synthetic", "leviathan-ai", "test"
        ),
        key_set=FailingKeys(), revocations=_Revocations(), clock=lambda: NOW,
    )
    with pytest.raises(PrincipalVerificationError) as port_failure:
        verifier.verify(_token(synthetic_key))
    assert port_failure.value.code is VerificationCodeV1.TOKEN_REJECTED
    assert port_failure.value.__context__ is None
