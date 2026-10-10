"""Verify one request-scoped assertion from the trusted site Worker.

The Worker assertion is distinct from the opaque Licensing Worker session token.
The site Worker resolves that session and signs a per-request RS256 assertion for
this API. This module verifies the assertion and adapts only verified claims.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import json
import re
import time
from collections.abc import Callable
from datetime import UTC, datetime
from enum import StrEnum
from threading import RLock
from typing import Annotated, Any, Protocol, cast

from fastapi import Request
from pydantic import StringConstraints

from leviathan_core.seal import Issuer, SealedModel, SealError, require
from leviathan_core.security.authz_models import (
    _VERIFIER_MARKER,
    AuthorizationModelError,
    PrincipalV1,
    TrustedPrincipalAdapterV1,
    TrustedPrincipalV1,
)
from leviathan_core.security.principal_verifier import (
    PrincipalVerificationError,
    PrincipalVerifier,
    RSAPublicKeyV1,
    TrustedIssuerV1,
)

WORKER_ASSERTION_HEADER = b"x-leviathan-worker-assertion"
WORKER_PRINCIPAL_TAG = "api.worker_request_principal.v1"
_MAX_TOKEN_BYTES = 16_384
_MAX_JWKS_BYTES = 131_072
_MAX_JWKS_KEYS = 64
_DEFAULT_MAX_TTL_SECONDS = 300
_B64URL = re.compile(r"[A-Za-z0-9_-]+\Z", re.ASCII)
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z", re.ASCII)
_FEATURE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z", re.ASCII)
_PATH = re.compile(r"/[A-Za-z0-9_./{}:%-]{0,1023}\Z", re.ASCII)
_METHOD = re.compile(r"[A-Z]{1,16}\Z", re.ASCII)
_ISSUER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}\Z", re.ASCII)
_PRINCIPAL_ISSUER = Issuer(WORKER_PRINCIPAL_TAG)

_Id = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")]
_Feature = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")]
_Method = Annotated[str, StringConstraints(pattern=r"^[A-Z]{1,16}$")]
_RequestPath = Annotated[str, StringConstraints(pattern=r"^/[A-Za-z0-9_./{}:%-]{0,1023}$")]


class WorkerAssertionCode(StrEnum):
    MISSING_ASSERTION = "WORKER_ASSERTION_MISSING"
    INVALID_ASSERTION = "WORKER_ASSERTION_INVALID"
    EXPIRED_ASSERTION = "WORKER_ASSERTION_EXPIRED"
    NOT_YET_VALID = "WORKER_ASSERTION_NOT_YET_VALID"
    WRONG_AUDIENCE = "WORKER_ASSERTION_WRONG_AUDIENCE"
    WRONG_ISSUER = "WORKER_ASSERTION_WRONG_ISSUER"
    REPLAYED_ASSERTION = "WORKER_ASSERTION_REPLAYED"
    REQUEST_BINDING_MISMATCH = "WORKER_ASSERTION_REQUEST_MISMATCH"
    CONFIG_NOT_READY = "WORKER_ASSERTION_NOT_CONFIGURED"
    REPLAY_STORE_UNAVAILABLE = "WORKER_ASSERTION_REPLAY_UNAVAILABLE"


class WorkerAssertionError(ValueError):
    """An allowlisted, content-free assertion failure."""

    def __init__(self, code: str) -> None:
        if code not in {
            WorkerAssertionCode.MISSING_ASSERTION,
            WorkerAssertionCode.INVALID_ASSERTION,
            WorkerAssertionCode.EXPIRED_ASSERTION,
            WorkerAssertionCode.NOT_YET_VALID,
            WorkerAssertionCode.WRONG_AUDIENCE,
            WorkerAssertionCode.WRONG_ISSUER,
            WorkerAssertionCode.REPLAYED_ASSERTION,
            WorkerAssertionCode.REQUEST_BINDING_MISMATCH,
            WorkerAssertionCode.CONFIG_NOT_READY,
            WorkerAssertionCode.REPLAY_STORE_UNAVAILABLE,
        }:
            code = WorkerAssertionCode.INVALID_ASSERTION
        self.code = code
        super().__init__(code)


class WorkerRequestPrincipalV1(SealedModel):
    """Sealed request identity derived only from a verified Worker assertion."""

    principal_id: _Id
    org_id: _Id
    session_id: _Id
    audience: _Id
    project_id: _Id
    env: _Id
    device_id: _Id | None = None
    auth_time_ns: int
    entitlement_version: _Id
    features: tuple[_Feature, ...]
    roles: tuple[_Id, ...]
    scopes: tuple[_Id, ...]
    request_method: _Method
    request_path: _RequestPath
    issued_at_ns: int
    expires_at_ns: int
    verified_at_ns: int


def require_worker_request_principal(obj: object) -> WorkerRequestPrincipalV1:
    if type(obj) is not WorkerRequestPrincipalV1:
        raise WorkerAssertionError(WorkerAssertionCode.INVALID_ASSERTION)
    try:
        return require(obj, WORKER_PRINCIPAL_TAG)
    except SealError:
        raise WorkerAssertionError(WorkerAssertionCode.INVALID_ASSERTION) from None


class AssertionReplayStore(Protocol):
    """Atomic, shared one-use jti store. ``True`` means the ID was already used."""

    def consume(self, issuer: str, assertion_id: str, expires_at_s: int) -> bool: ...


class InMemoryAssertionReplayStore:
    """Bounded local replay store for tests and single-process development only."""

    def __init__(self, *, capacity: int = 100_000, clock: Callable[[], float] = time.time) -> None:
        if type(capacity) is not int or not 1 <= capacity <= 1_000_000 or not callable(clock):
            raise WorkerAssertionError(WorkerAssertionCode.CONFIG_NOT_READY)
        self._capacity = capacity
        self._clock = clock
        self._entries: dict[tuple[str, str], int] = {}
        self._lock = RLock()

    def consume(self, issuer: str, assertion_id: str, expires_at_s: int) -> bool:
        now = int(self._clock())
        key = (issuer, assertion_id)
        with self._lock:
            expired = [entry for entry, expiry in self._entries.items() if expiry <= now]
            for entry in expired:
                del self._entries[entry]
            if key in self._entries:
                return True
            if len(self._entries) >= self._capacity:
                raise WorkerAssertionError(WorkerAssertionCode.REPLAY_STORE_UNAVAILABLE)
            self._entries[key] = min(expires_at_s, now + _DEFAULT_MAX_TTL_SECONDS + 60)
            return False


class _NoRevocations:
    """PrincipalVerifier port; replay is consumed only after signature validation."""

    @staticmethod
    def is_revoked(_issuer: str, _jti: str) -> bool:
        return False


class _JwksKeySet:
    def __init__(self, issuer: str, keys: dict[str, RSAPublicKeyV1]) -> None:
        self._issuer = issuer
        self._keys = keys

    def get_key(self, issuer: str, kid: str) -> RSAPublicKeyV1 | None:
        if not hmac.compare_digest(issuer, self._issuer):
            return None
        return self._keys.get(kid)


def _decode_b64url(value: object) -> bytes:
    if type(value) is not str or not value or _B64URL.fullmatch(value) is None:
        raise WorkerAssertionError(WorkerAssertionCode.CONFIG_NOT_READY)
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError):
        raise WorkerAssertionError(WorkerAssertionCode.CONFIG_NOT_READY) from None
    if not hmac.compare_digest(
        base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii"), value
    ):
        raise WorkerAssertionError(WorkerAssertionCode.CONFIG_NOT_READY)
    return decoded


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> None:
    raise ValueError("invalid JSON constant")


def _json_object(raw: bytes) -> dict[str, Any]:
    value = json.loads(raw, object_pairs_hook=_unique_pairs, parse_constant=_reject_json_constant)
    if type(value) is not dict:
        raise ValueError("JSON object required")
    return cast(dict[str, Any], value)


def _parse_jwks(issuer: str, raw_jwks: str) -> _JwksKeySet:
    if type(raw_jwks) is not str or not raw_jwks or len(raw_jwks.encode("utf-8")) > _MAX_JWKS_BYTES:
        raise WorkerAssertionError(WorkerAssertionCode.CONFIG_NOT_READY)
    try:
        document = _json_object(raw_jwks.encode("utf-8"))
        key_entries = document.get("keys")
        if type(key_entries) is not list or not key_entries or len(key_entries) > _MAX_JWKS_KEYS:
            raise ValueError("invalid key set")
        keys: dict[str, RSAPublicKeyV1] = {}
        for item in key_entries:
            if type(item) is not dict:
                raise ValueError("invalid key")
            if any(name in item for name in ("d", "p", "q", "dp", "dq", "qi", "oth")):
                raise ValueError("private key material is not accepted")
            kid = item.get("kid")
            if (
                type(kid) is not str
                or _ID.fullmatch(kid) is None
                or kid in keys
                or item.get("kty") != "RSA"
                or item.get("use", "sig") != "sig"
                or item.get("alg", "RS256") != "RS256"
            ):
                raise ValueError("invalid public key")
            modulus = int.from_bytes(_decode_b64url(item.get("n")), "big")
            exponent = int.from_bytes(_decode_b64url(item.get("e")), "big")
            keys[kid] = RSAPublicKeyV1(modulus=modulus, exponent=exponent)
        return _JwksKeySet(issuer, keys)
    except WorkerAssertionError:
        raise
    except Exception:
        raise WorkerAssertionError(WorkerAssertionCode.CONFIG_NOT_READY) from None


def _decode_token(token: str) -> tuple[dict[str, Any], dict[str, Any]]:
    if type(token) is not str or not 1 <= len(token.encode("utf-8")) <= _MAX_TOKEN_BYTES:
        raise WorkerAssertionError(WorkerAssertionCode.INVALID_ASSERTION)
    parts = token.split(".")
    if len(parts) != 3:
        raise WorkerAssertionError(WorkerAssertionCode.INVALID_ASSERTION)
    try:

        def decode(part: str) -> bytes:
            if not part or _B64URL.fullmatch(part) is None:
                raise ValueError("invalid segment")
            result = base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))
            if not hmac.compare_digest(
                base64.urlsafe_b64encode(result).rstrip(b"=").decode("ascii"), part
            ):
                raise ValueError("non-canonical segment")
            return result

        header = _json_object(decode(parts[0]))
        claims = _json_object(decode(parts[1]))
        return header, claims
    except Exception:
        raise WorkerAssertionError(WorkerAssertionCode.INVALID_ASSERTION) from None


def _seconds(claims: dict[str, Any], field: str) -> int:
    value = claims.get(field)
    if type(value) is not int or not 0 <= value <= 253_402_300_799:
        raise WorkerAssertionError(WorkerAssertionCode.INVALID_ASSERTION)
    return value


def _id(value: object) -> bool:
    return type(value) is str and _ID.fullmatch(value) is not None


class WorkerAssertionVerifier:
    """RS256 assertion verifier with config-pinned public keys and one-use IDs."""

    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        jwks_json: str,
        replay_store: AssertionReplayStore,
        env: str,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        max_ttl_seconds: int = _DEFAULT_MAX_TTL_SECONDS,
    ) -> None:
        if (
            type(issuer) is not str
            or _ISSUER.fullmatch(issuer) is None
            or type(audience) is not str
            or _ISSUER.fullmatch(audience) is None
            or not _id(env)
            or not callable(getattr(replay_store, "consume", None))
            or not callable(clock)
            or type(max_ttl_seconds) is not int
            or not 1 <= max_ttl_seconds <= _DEFAULT_MAX_TTL_SECONDS
        ):
            raise WorkerAssertionError(WorkerAssertionCode.CONFIG_NOT_READY)
        if (
            type(replay_store) is InMemoryAssertionReplayStore
            and env not in {"development", "test", "paper", "demo"}
        ):
            raise WorkerAssertionError(WorkerAssertionCode.CONFIG_NOT_READY)
        self._issuer = issuer
        self._audience = audience
        self._env = env
        self._clock = clock
        self._max_ttl_seconds = max_ttl_seconds
        self._key_set = _parse_jwks(issuer, jwks_json)
        self._replay_store = replay_store

    def verify(
        self,
        token: str | None,
        *,
        request_method: str,
        request_path: str,
    ) -> WorkerRequestPrincipalV1:
        if token is None or token == "":
            raise WorkerAssertionError(WorkerAssertionCode.MISSING_ASSERTION)
        if (
            type(request_method) is not str
            or _METHOD.fullmatch(request_method) is None
            or type(request_path) is not str
            or _PATH.fullmatch(request_path) is None
        ):
            raise WorkerAssertionError(WorkerAssertionCode.INVALID_ASSERTION)
        header, claims = _decode_token(token)
        if (
            header.get("alg") != "RS256"
            or header.get("typ") != "JWT"
            or type(header.get("kid")) is not str
        ):
            raise WorkerAssertionError(WorkerAssertionCode.INVALID_ASSERTION)
        if type(claims.get("iss")) is not str or not hmac.compare_digest(
            claims["iss"], self._issuer
        ):
            raise WorkerAssertionError(WorkerAssertionCode.WRONG_ISSUER)
        if type(claims.get("aud")) is not str or not hmac.compare_digest(
            claims["aud"], self._audience
        ):
            raise WorkerAssertionError(WorkerAssertionCode.WRONG_AUDIENCE)
        method = claims.get("req_method")
        path = claims.get("req_path")
        if (
            type(method) is not str
            or not hmac.compare_digest(method, request_method)
            or type(path) is not str
            or not hmac.compare_digest(path, request_path)
        ):
            raise WorkerAssertionError(WorkerAssertionCode.REQUEST_BINDING_MISMATCH)

        issued = _seconds(claims, "iat")
        not_before = _seconds(claims, "nbf")
        expires = _seconds(claims, "exp")
        now = self._clock()
        if type(now) is not datetime or now.tzinfo is not UTC:
            raise WorkerAssertionError(WorkerAssertionCode.CONFIG_NOT_READY)
        now_s = int(now.timestamp())
        if expires <= now_s:
            raise WorkerAssertionError(WorkerAssertionCode.EXPIRED_ASSERTION)
        if not_before > now_s or issued > now_s + 60:
            raise WorkerAssertionError(WorkerAssertionCode.NOT_YET_VALID)
        if expires <= issued or expires - issued > self._max_ttl_seconds:
            raise WorkerAssertionError(WorkerAssertionCode.INVALID_ASSERTION)

        required_ids = (
            claims.get("sub"),
            claims.get("org"),
            claims.get("sid"),
            claims.get("role"),
            claims.get("entitlement_version"),
            claims.get("jti"),
        )
        if not all(_id(value) for value in required_ids):
            raise WorkerAssertionError(WorkerAssertionCode.INVALID_ASSERTION)
        device_id = claims.get("device_id")
        if device_id is not None and not _id(device_id):
            raise WorkerAssertionError(WorkerAssertionCode.INVALID_ASSERTION)
        auth_time = _seconds(claims, "auth_time")
        if auth_time > now_s:
            raise WorkerAssertionError(WorkerAssertionCode.INVALID_ASSERTION)
        roles = claims.get("roles")
        scopes = claims.get("scope")
        features = claims.get("features")
        if (
            type(roles) is not list
            or not roles
            or len(roles) > 64
            or not all(_id(value) for value in roles)
            or len(roles) != len(set(roles))
            or not hmac.compare_digest(cast(str, claims["role"]), roles[0])
            or type(scopes) is not list
            or not scopes
            or len(scopes) > 64
            or not all(_id(value) for value in scopes)
            or len(scopes) != len(set(scopes))
            or type(features) is not list
            or len(features) > 128
            or not all(type(value) is str and _FEATURE.fullmatch(value) for value in features)
            or len(features) != len(set(features))
        ):
            raise WorkerAssertionError(WorkerAssertionCode.INVALID_ASSERTION)

        policy = TrustedIssuerV1(
            issuer=self._issuer,
            audience=self._audience,
            org_id=cast(str, claims["org"]),
            project_id="leviathan-web-api",
            env=self._env,
        )
        core_verifier = PrincipalVerifier(
            trusted_issuer=policy,
            key_set=self._key_set,
            revocations=_NoRevocations(),
            clock=lambda: now,
        )
        try:
            verified = core_verifier.verify(token)
            authz_claims_data: dict[str, object] = {
                "principal_id": verified.subject_id,
                "project_id": verified.project_id,
                "roles": tuple(cast(list[str], roles)),
                "env": verified.env,
                "break_glass": False,
                "device_id": verified.device_id,
            }
            PrincipalV1(**cast(Any, authz_claims_data))
        except (PrincipalVerificationError, AuthorizationModelError, ValueError, TypeError):
            raise WorkerAssertionError(WorkerAssertionCode.INVALID_ASSERTION) from None

        try:
            replayed = self._replay_store.consume(self._issuer, cast(str, claims["jti"]), expires)
        except Exception:
            raise WorkerAssertionError(WorkerAssertionCode.REPLAY_STORE_UNAVAILABLE) from None
        if replayed:
            raise WorkerAssertionError(WorkerAssertionCode.REPLAYED_ASSERTION)

        try:
            principal = _PRINCIPAL_ISSUER.issue(
                WorkerRequestPrincipalV1(
                    principal_id=verified.subject_id,
                    org_id=verified.org_id,
                    session_id=cast(str, claims["sid"]),
                    audience=verified.audience,
                    project_id=verified.project_id,
                    env=verified.env,
                    device_id=verified.device_id,
                    auth_time_ns=auth_time * 1_000_000_000,
                    entitlement_version=cast(str, claims["entitlement_version"]),
                    features=tuple(cast(list[str], features)),
                    roles=tuple(cast(list[str], roles)),
                    scopes=verified.scopes,
                    request_method=request_method,
                    request_path=request_path,
                    issued_at_ns=verified.issued_at_ns,
                    expires_at_ns=verified.expires_at_ns,
                    verified_at_ns=int(now.timestamp() * 1_000_000_000),
                )
            )
        except Exception:
            raise WorkerAssertionError(WorkerAssertionCode.INVALID_ASSERTION) from None
        return principal


def get_trusted_worker_principal(principal: WorkerRequestPrincipalV1) -> TrustedPrincipalV1:
    principal = require_worker_request_principal(principal)
    claims_data: dict[str, object] = {
        "principal_id": principal.principal_id,
        "project_id": principal.project_id,
        "roles": principal.roles,
        "env": principal.env,
        "break_glass": False,
        "device_id": principal.device_id,
    }
    try:
        claims = PrincipalV1(**cast(Any, claims_data))
        return TrustedPrincipalAdapterV1.from_verified_claims(
            claims, verifier_marker=_VERIFIER_MARKER
        )
    except (AuthorizationModelError, TypeError, ValueError):
        raise WorkerAssertionError(WorkerAssertionCode.INVALID_ASSERTION) from None


async def require_worker_principal(request: Request) -> WorkerRequestPrincipalV1:
    values = [
        value
        for key, value in request.scope.get("headers", ())
        if key.lower() == WORKER_ASSERTION_HEADER
    ]
    if not values:
        raise WorkerAssertionError(WorkerAssertionCode.MISSING_ASSERTION)
    if len(values) != 1:
        raise WorkerAssertionError(WorkerAssertionCode.INVALID_ASSERTION)
    try:
        token = values[0].decode("ascii")
    except UnicodeDecodeError:
        raise WorkerAssertionError(WorkerAssertionCode.INVALID_ASSERTION) from None
    verifier = getattr(request.app.state, "worker_assertion_verifier", None)
    if type(verifier) is not WorkerAssertionVerifier:
        raise WorkerAssertionError(WorkerAssertionCode.CONFIG_NOT_READY)
    principal = verifier.verify(
        token,
        request_method=request.method.upper(),
        request_path=request.url.path,
    )
    request.state.worker_principal = principal
    request.state.trusted_principal = get_trusted_worker_principal(principal)
    return principal


def worker_assertion_error_response(exc: WorkerAssertionError) -> tuple[int, dict[str, str]]:
    unavailable = {
        WorkerAssertionCode.CONFIG_NOT_READY,
        WorkerAssertionCode.REPLAY_STORE_UNAVAILABLE,
    }
    return (503 if exc.code in unavailable else 401, {"code": exc.code})


def build_worker_assertion_verifier(
    settings: object, *, replay_store: AssertionReplayStore
) -> WorkerAssertionVerifier:
    """Build from public JWKS configuration; the signing key never enters Python."""
    issuer = getattr(settings, "worker_assertion_issuer", None)
    audience = getattr(settings, "worker_assertion_audience", None)
    jwks_json = getattr(settings, "worker_assertion_jwks_json", None)
    env = getattr(settings, "env", None)
    if any(type(value) is not str or not value for value in (issuer, audience, jwks_json, env)):
        raise WorkerAssertionError(WorkerAssertionCode.CONFIG_NOT_READY)
    return WorkerAssertionVerifier(
        issuer=cast(str, issuer),
        audience=cast(str, audience),
        jwks_json=cast(str, jwks_json),
        replay_store=replay_store,
        env=cast(str, env),
    )


__all__ = [
    "WORKER_ASSERTION_HEADER",
    "WORKER_PRINCIPAL_TAG",
    "AssertionReplayStore",
    "InMemoryAssertionReplayStore",
    "WorkerAssertionCode",
    "WorkerAssertionError",
    "WorkerAssertionVerifier",
    "WorkerRequestPrincipalV1",
    "build_worker_assertion_verifier",
    "get_trusted_worker_principal",
    "require_worker_principal",
    "require_worker_request_principal",
    "worker_assertion_error_response",
]
