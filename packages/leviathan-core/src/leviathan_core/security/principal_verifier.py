"""Pure SEC-003 RS256 verification and sealed SEC-002 principal adaptation.

The key-set and revocation ports are trusted, pinned, in-process inputs. A
transport must supply the authenticated peer certificate bytes; this module
checks only the signed token's binding to those bytes. No key fetch or I/O is
performed here. Arbitrary in-process Python is outside this data-path threat
model, as in SEC-002.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, NoReturn, Protocol, cast

from leviathan_core.numeric import NumericError, parse_int
from leviathan_core.seal import Issuer, SealedModel, SealError, require
from leviathan_core.security.authz_models import (
    _VERIFIER_MARKER,
    AuthorizationModelError,
    PrincipalV1,
    TrustedPrincipalAdapterV1,
    TrustedPrincipalV1,
)

_SEALED = Issuer("sec003.verified_principal.v1")
_TAG = _SEALED.tag
_CONSTRUCTION_MARKER = object()
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z", re.ASCII)
_ISSUER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}\Z", re.ASCII)
_KID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z", re.ASCII)
_B64 = re.compile(r"[A-Za-z0-9_-]+\Z", re.ASCII)
_SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_MAX_SECONDS = 253402300799
_MAX_TOKEN_BYTES = 16384
_MAX_CERT_BYTES = 32768


class VerificationCodeV1(StrEnum):
    TOKEN_REJECTED = "TOKEN_REJECTED"
    CONFIG_INVALID = "CONFIG_INVALID"
    PRINCIPAL_UNISSUED = "PRINCIPAL_UNISSUED"


class PrincipalVerificationError(ValueError):
    """Allowlisted, content-free failure; no token or claim data is retained."""

    def __init__(self, code: VerificationCodeV1) -> None:
        self.code = code
        super().__init__(code.value)


def _reject() -> NoReturn:
    raise PrincipalVerificationError(VerificationCodeV1.TOKEN_REJECTED)


def _valid_id(value: object) -> bool:
    return type(value) is str and _ID.fullmatch(value) is not None


def _valid_issuer(value: object) -> bool:
    return type(value) is str and _ISSUER.fullmatch(value) is not None


@dataclass(frozen=True, slots=True)
class RSAPublicKeyV1:
    """Pinned RSA public numbers; no PEM parser or key discovery."""

    modulus: int
    exponent: int

    def __post_init__(self) -> None:
        if (
            type(self.modulus) is not int
            or not 2048 <= self.modulus.bit_length() <= 8192
            or self.modulus % 2 == 0
            or type(self.exponent) is not int
            or self.exponent != 65537
        ):
            raise PrincipalVerificationError(VerificationCodeV1.CONFIG_INVALID)


@dataclass(frozen=True, slots=True)
class TrustedIssuerV1:
    issuer: str
    audience: str
    org_id: str
    project_id: str
    env: str
    require_mtls: bool = False

    def __post_init__(self) -> None:
        if (
            not _valid_issuer(self.issuer)
            or not _valid_issuer(self.audience)
            or not all(_valid_id(x) for x in (self.org_id, self.project_id, self.env))
            or type(self.require_mtls) is not bool
        ):
            raise PrincipalVerificationError(VerificationCodeV1.CONFIG_INVALID)


class PinnedKeySetPort(Protocol):
    def get_key(self, issuer: str, kid: str) -> RSAPublicKeyV1 | None: ...


class RevocationPort(Protocol):
    def is_revoked(self, issuer: str, jti: str) -> bool: ...


class VerifiedPrincipalV1(SealedModel):
    issuer: str
    audience: str
    org_id: str
    project_id: str
    subject_id: str
    role: str
    scopes: tuple[str, ...]
    env: str
    venue: str | None
    portfolio: str | None
    strategy: str | None
    jti: str
    issued_at_ns: int
    expires_at_ns: int
    verified_at_ns: int
    certificate_binding: str | None

    def __init__(self, *, _construction_marker: object | None = None, **data: Any) -> None:
        if _construction_marker is not _CONSTRUCTION_MARKER:
            raise PrincipalVerificationError(VerificationCodeV1.PRINCIPAL_UNISSUED)
        super().__init__(**data)


def _decode_segment(segment: str) -> bytes:
    if not segment or len(segment) > _MAX_TOKEN_BYTES or _B64.fullmatch(segment) is None:
        _reject()
    try:
        decoded = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    except (binascii.Error, ValueError):
        decoded = None
    if decoded is None:
        _reject()
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    if not hmac.compare_digest(canonical, segment):
        _reject()
    return decoded


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _reject()
        result[key] = value
    return result


def _json_object(segment: str) -> dict[str, Any]:
    invalid = False
    try:
        value = json.loads(
            _decode_segment(segment), object_pairs_hook=_unique_pairs,
            parse_constant=lambda _: _reject(),
        )
    except Exception:
        invalid = True
        value = None
    if invalid:
        _reject()
    if type(value) is not dict:
        _reject()
    return cast(dict[str, Any], value)


def _seconds(value: object, field: str) -> int:
    try:
        parsed = parse_int(value, field=field, min_value=0, max_value=_MAX_SECONDS)
    except NumericError:
        parsed = None
    if parsed is None:
        _reject()
    return parsed


def _clock_ns(clock: Callable[[], datetime]) -> int:
    try:
        now = clock()
    except Exception:
        now = None
    if now is None:
        _reject()
    if type(now) is not datetime or now.tzinfo is not UTC:
        _reject()
    delta = now - _EPOCH
    return ((delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds) * 1000


def _verify_rs256(key: RSAPublicKeyV1, message: bytes, signature: bytes) -> bool:
    """Check the exact PKCS#1 v1.5 SHA-256 encoding, with no algorithm choice."""
    size = (key.modulus.bit_length() + 7) // 8
    if len(signature) != size:
        return False
    number = int.from_bytes(signature, "big")
    if number >= key.modulus:
        return False
    encoded = pow(number, key.exponent, key.modulus).to_bytes(size, "big")
    digest_info = _SHA256_DIGEST_INFO + hashlib.sha256(message).digest()
    padding_length = size - len(digest_info) - 3
    if padding_length < 8:
        return False
    expected = b"\x00\x01" + b"\xff" * padding_length + b"\x00" + digest_info
    return hmac.compare_digest(encoded, expected)


class PrincipalVerifier:
    """Verify one pinned issuer and adapt only this verifier's issued principals."""

    def __init__(
        self,
        *,
        trusted_issuer: TrustedIssuerV1,
        key_set: PinnedKeySetPort,
        revocations: RevocationPort,
        clock: Callable[[], datetime],
    ) -> None:
        if (
            type(trusted_issuer) is not TrustedIssuerV1
            or not callable(getattr(key_set, "get_key", None))
            or not callable(getattr(revocations, "is_revoked", None))
            or not callable(clock)
        ):
            raise PrincipalVerificationError(VerificationCodeV1.CONFIG_INVALID)
        self._trusted_issuer = trusted_issuer
        self._key_set = key_set
        self._revocations = revocations
        self._clock = clock

    def verify(
        self, token: str, *, peer_certificate_der: bytes | None = None
    ) -> VerifiedPrincipalV1:
        if type(token) is not str or len(token) > _MAX_TOKEN_BYTES or token.count(".") != 2:
            _reject()
        if peer_certificate_der is not None and (
            type(peer_certificate_der) is not bytes
            or not 0 < len(peer_certificate_der) <= _MAX_CERT_BYTES
        ):
            _reject()
        encoded_header, encoded_claims, encoded_signature = token.split(".")
        header = _json_object(encoded_header)
        claims = _json_object(encoded_claims)
        if header.get("alg") != "RS256" or type(header.get("alg")) is not str:
            _reject()
        if (
            not set(header).issubset({"alg", "kid", "typ"})
            or header.get("typ") not in (None, "JWT")
        ):
            _reject()
        kid = header.get("kid")
        if type(kid) is not str or _KID.fullmatch(kid) is None:
            _reject()
        policy = self._trusted_issuer
        if claims.get("iss") != policy.issuer or claims.get("aud") != policy.audience:
            _reject()
        try:
            key = self._key_set.get_key(policy.issuer, kid)
        except Exception:
            key = None
        if key is None:
            _reject()
        if type(key) is not RSAPublicKeyV1:
            _reject()
        signature = _decode_segment(encoded_signature)
        if not _verify_rs256(key, f"{encoded_header}.{encoded_claims}".encode("ascii"), signature):
            _reject()
        if claims.get("org") != policy.org_id or claims.get("env") != policy.env:
            _reject()
        if any(field in claims for field in ("approval", "entitlement", "break_glass")):
            _reject()
        subject = claims.get("sub")
        role = claims.get("role")
        jti = claims.get("jti")
        scope = claims.get("scope")
        if (
            not all(_valid_id(x) for x in (subject, role, jti))
            or type(scope) is not list
            or not scope
            or len(scope) > 64
            or not all(_valid_id(x) for x in scope)
            or len(scope) != len(set(scope))
        ):
            _reject()
        subject = cast(str, subject)
        role = cast(str, role)
        jti = cast(str, jti)
        scope = cast(list[str], scope)
        attrs = (claims.get("venue"), claims.get("portfolio"), claims.get("strategy"))
        if any(value is not None and not _valid_id(value) for value in attrs):
            _reject()
        issued = _seconds(claims.get("iat"), "iat")
        not_before = _seconds(claims.get("nbf"), "nbf")
        expires = _seconds(claims.get("exp"), "exp")
        now_ns = _clock_ns(self._clock)
        if (
            expires <= issued or expires - issued > 900
            or not_before > expires
            or issued * 1_000_000_000 > now_ns + 60_000_000_000
            or not_before * 1_000_000_000 > now_ns + 60_000_000_000
            or now_ns > expires * 1_000_000_000 + 60_000_000_000
        ):
            _reject()
        try:
            revoked = self._revocations.is_revoked(policy.issuer, jti)
        except Exception:
            revoked = None
        if revoked is None:
            _reject()
        if type(revoked) is not bool or revoked:
            _reject()
        cnf = claims.get("cnf")
        binding: str | None = None
        if cnf is not None:
            if type(cnf) is not dict or set(cnf) != {"x5t#S256"}:
                _reject()
            binding = cnf["x5t#S256"]
            if type(binding) is not str or len(binding) != 43 or _B64.fullmatch(binding) is None:
                _reject()
            if peer_certificate_der is None:
                _reject()
            actual = base64.urlsafe_b64encode(
                hashlib.sha256(peer_certificate_der).digest()
            ).rstrip(b"=").decode("ascii")
            if not hmac.compare_digest(binding, actual):
                _reject()
        elif policy.require_mtls:
            _reject()
        if policy.require_mtls and peer_certificate_der is None:
            _reject()
        try:
            verified = VerifiedPrincipalV1(
                _construction_marker=_CONSTRUCTION_MARKER,
                issuer=policy.issuer, audience=policy.audience, org_id=policy.org_id,
                project_id=policy.project_id, subject_id=subject, role=role,
                scopes=tuple(scope), env=policy.env, venue=attrs[0], portfolio=attrs[1],
                strategy=attrs[2], jti=jti, issued_at_ns=issued * 1_000_000_000,
                expires_at_ns=expires * 1_000_000_000, verified_at_ns=now_ns,
                certificate_binding=binding,
            )
            return _SEALED.issue(verified)
        except (SealError, AuthorizationModelError):
            pass
        _reject()

    def to_sec002_claims(self, verified: VerifiedPrincipalV1) -> PrincipalV1:
        if type(verified) is not VerifiedPrincipalV1:
            raise PrincipalVerificationError(VerificationCodeV1.PRINCIPAL_UNISSUED)
        try:
            require(verified, _TAG)
        except SealError:
            raise PrincipalVerificationError(VerificationCodeV1.PRINCIPAL_UNISSUED) from None
        policy = self._trusted_issuer
        if (
            verified.issuer != policy.issuer or verified.audience != policy.audience
            or verified.org_id != policy.org_id or verified.project_id != policy.project_id
            or verified.env != policy.env
        ):
            raise PrincipalVerificationError(VerificationCodeV1.PRINCIPAL_UNISSUED)
        try:
            now_ns = _clock_ns(self._clock)
        except PrincipalVerificationError:
            now_ns = None
        if (
            now_ns is None
            or now_ns > verified.expires_at_ns + 60_000_000_000
            or now_ns + 60_000_000_000 < verified.issued_at_ns
        ):
            raise PrincipalVerificationError(VerificationCodeV1.PRINCIPAL_UNISSUED)
        try:
            revoked = self._revocations.is_revoked(policy.issuer, verified.jti)
        except Exception:
            revoked = None
        if type(revoked) is not bool or revoked:
            raise PrincipalVerificationError(VerificationCodeV1.PRINCIPAL_UNISSUED)
        try:
            return PrincipalV1(
                principal_id=verified.subject_id, project_id=verified.project_id,
                roles=(verified.role,), env=verified.env, venue=verified.venue,
                portfolio=verified.portfolio, strategy=verified.strategy,
                break_glass=False,
            )
        except AuthorizationModelError:
            raise PrincipalVerificationError(VerificationCodeV1.PRINCIPAL_UNISSUED) from None

    def to_trusted_principal(self, verified: VerifiedPrincipalV1) -> TrustedPrincipalV1:
        return TrustedPrincipalAdapterV1.from_verified_claims(
            self.to_sec002_claims(verified), verifier_marker=_VERIFIER_MARKER
        )


__all__ = [
    "PinnedKeySetPort", "PrincipalVerificationError", "PrincipalVerifier",
    "RSAPublicKeyV1", "RevocationPort", "TrustedIssuerV1",
    "VerificationCodeV1", "VerifiedPrincipalV1",
]
