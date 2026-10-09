"""Authenticated OMEGA heartbeat and kill boundary.

This adapter accepts only verified JWTs bound to a pinned transport
certificate. It performs no network access and owns no HALT state. The API
router supplies the certificate bytes from its trusted TLS scope extension
and passes the single HALT authority only to :meth:`engage_kill`.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import threading
from collections.abc import Callable, Mapping
from typing import NoReturn, Protocol

from leviathan_core.omega_link.state_models import OmegaPolicyV1
from leviathan_core.risk.halt import HaltAuthority
from leviathan_core.risk.halt_reasons import HaltReasonV1
from leviathan_core.seal import Issuer, SealedModel, require
from leviathan_core.security.principal_verifier import (
    PrincipalVerifier,
    VerifiedPrincipalV1,
)

_FINGERPRINT = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_PEER = re.compile(r"[A-Za-z][A-Za-z0-9_.:-]{0,127}\Z", re.ASCII)
_TOKEN = re.compile(r"Bearer ([A-Za-z0-9._~-]{1,16384})\Z", re.ASCII)
_MAX_CLOCK_NS = (1 << 63) - 1
_MAX_REQUEST_SKEW_NS = 2_000_000_000
_MAX_TOKEN_AGE_NS = 300_000_000_000
_OMEGA_ISSUER = "omega-idp"
_OMEGA_AUDIENCE = "leviathan-backend"
_IDENTITY_ISSUER = Issuer("omega002.peer_identity.v1")
_SCOPES = frozenset({"omega:heartbeat", "omega:inquiry", "omega:kill", "omega:task"})
_DENIAL_CODES = frozenset(
    {
        "LIVE_EVIDENCE_UNAVAILABLE",
        "OMEGA_AUTH_DENIED",
        "OMEGA_HEARTBEAT_UNAVAILABLE",
        "OMEGA_KILL_DENIED",
        "OMEGA_KILL_ENGAGE_FAILED",
        "OMEGA_REPLAY_OR_STORE_UNAVAILABLE",
    }
)


class OmegaAdapterError(ValueError):
    """Content-free OMEGA adapter rejection."""

    __slots__ = ("code", "status_code")

    def __init__(self, code: str, status_code: int = 401) -> None:
        self.code = code
        self.status_code = status_code
        super().__init__(code)


class OmegaNonceStore(Protocol):
    """Atomic replay store. Production deployments must provide shared storage."""

    def claim(
        self, peer_system: str, nonce: str, *, now_ns: int, expires_at_ns: int
    ) -> bool: ...


class InMemoryOmegaNonceStore:
    """Thread-safe test/development replay guard; not a multi-process store."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._expires: dict[tuple[str, str], int] = {}

    def claim(
        self, peer_system: str, nonce: str, *, now_ns: int, expires_at_ns: int
    ) -> bool:
        if (
            not _PEER.fullmatch(peer_system)
            or type(nonce) is not str
            or not 1 <= len(nonce) <= 128
            or not nonce.isascii()
            or type(now_ns) is not int
            or type(expires_at_ns) is not int
            or now_ns < 0
            or expires_at_ns <= now_ns
        ):
            return False
        key = (peer_system, nonce)
        with self._lock:
            self._expires = {
                entry: expiry for entry, expiry in self._expires.items() if expiry > now_ns
            }
            if key in self._expires:
                return False
            self._expires[key] = expires_at_ns
            return True


class OmegaPeerIdentityV1(SealedModel):
    """Identity returned only after JWT, transport pin and replay checks."""

    peer_system: str
    nonce: str
    issued_at_ns: int
    expires_at_ns: int
    scopes: tuple[str, ...]


class OmegaHeartbeatAdapterV1:
    """Authenticate OMEGA requests and perform the one approved HALT effect."""

    def __init__(
        self,
        *,
        verifier: PrincipalVerifier,
        pinned_certificates: Mapping[str, str],
        nonce_store: OmegaNonceStore,
        clock_ns: Callable[[], int],
        policy: OmegaPolicyV1,
        response_signer: Callable[[bytes], str],
        denial_auditor: Callable[[str], None],
        capability_manifest_hash: str,
    ) -> None:
        if type(verifier) is not PrincipalVerifier or type(policy) is not OmegaPolicyV1:
            raise OmegaAdapterError("OMEGA_CONFIGURATION_INVALID", 503)
        if not callable(getattr(nonce_store, "claim", None)) or not callable(clock_ns):
            raise OmegaAdapterError("OMEGA_CONFIGURATION_INVALID", 503)
        if not callable(response_signer) or not callable(denial_auditor):
            raise OmegaAdapterError("OMEGA_CONFIGURATION_INVALID", 503)
        if (
            type(capability_manifest_hash) is not str
            or re.fullmatch(r"[0-9a-f]{64}", capability_manifest_hash, re.ASCII) is None
        ):
            raise OmegaAdapterError("OMEGA_CONFIGURATION_INVALID", 503)
        pins: dict[str, str] = {}
        for fingerprint, peer in pinned_certificates.items():
            if (
                type(fingerprint) is not str
                or _FINGERPRINT.fullmatch(fingerprint) is None
                or type(peer) is not str
                or _PEER.fullmatch(peer) is None
                or fingerprint in pins
            ):
                raise OmegaAdapterError("OMEGA_CONFIGURATION_INVALID", 503)
            pins[fingerprint] = peer
        if not pins:
            raise OmegaAdapterError("OMEGA_CONFIGURATION_INVALID", 503)
        self._verifier = verifier
        self._pins = pins
        self._nonce_store = nonce_store
        self._clock_ns = clock_ns
        self._policy = policy
        self._response_signer = response_signer
        self._denial_auditor = denial_auditor
        self._capability_manifest_hash = capability_manifest_hash

    def _reject(self, code: str, status_code: int = 401) -> NoReturn:
        """Audit a closed reason code only; never pass request content to audit."""
        self.audit_denial(code)
        raise OmegaAdapterError(code, status_code)

    def audit_denial(self, reason_code: str) -> None:
        """Record a closed reason code without accepting caller content."""
        if type(reason_code) is not str or reason_code not in _DENIAL_CODES:
            raise OmegaAdapterError("OMEGA_AUDIT_UNAVAILABLE", 503)
        try:
            self._denial_auditor(reason_code)
        except Exception:
            raise OmegaAdapterError("OMEGA_AUDIT_UNAVAILABLE", 503) from None

    def authenticate_request(
        self,
        *,
        authorization: str | None,
        peer_certificate_der: bytes | None,
        required_scope: str,
    ) -> OmegaPeerIdentityV1:
        """Validate pinned transport identity, signed request time, scope and nonce."""
        if required_scope not in _SCOPES:
            self._reject("OMEGA_AUTH_DENIED")
        match = _TOKEN.fullmatch(authorization) if type(authorization) is str else None
        if match is None or type(peer_certificate_der) is not bytes or not peer_certificate_der:
            self._reject("OMEGA_AUTH_DENIED")
        token = match.group(1)
        fingerprint = hashlib.sha256(peer_certificate_der).hexdigest()
        peer = self._pins.get(fingerprint)
        if peer is None:
            self._reject("OMEGA_AUTH_DENIED")
        try:
            verified = self._verifier.verify(token, peer_certificate_der=peer_certificate_der)
            now_ns = self._clock_ns()
        except Exception:
            self._reject("OMEGA_AUTH_DENIED")
        if (
            type(verified) is not VerifiedPrincipalV1
            or type(now_ns) is not int
            or not 0 <= now_ns <= _MAX_CLOCK_NS
        ):
            self._reject("OMEGA_AUTH_DENIED")
        issued_at_ns = verified.issued_at_ns
        expires_at_ns = verified.expires_at_ns
        cert_binding = _certificate_binding(peer_certificate_der)
        if (
            verified.issuer != _OMEGA_ISSUER
            or verified.audience != _OMEGA_AUDIENCE
            or verified.subject_id != peer
            or verified.certificate_binding is None
            or not hmac.compare_digest(verified.certificate_binding, cert_binding)
            or abs(now_ns - issued_at_ns) > _MAX_REQUEST_SKEW_NS
            or now_ns - issued_at_ns >= _MAX_TOKEN_AGE_NS
            or now_ns >= expires_at_ns
            or required_scope not in verified.scopes
        ):
            self._reject("OMEGA_AUTH_DENIED")
        try:
            claimed = self._nonce_store.claim(
                peer,
                verified.jti,
                now_ns=now_ns,
                expires_at_ns=min(expires_at_ns, now_ns + _MAX_TOKEN_AGE_NS),
            )
        except Exception:
            claimed = False
        if claimed is not True:
            self._reject("OMEGA_REPLAY_OR_STORE_UNAVAILABLE")
        try:
            identity = OmegaPeerIdentityV1(
                peer_system=peer,
                nonce=verified.jti,
                issued_at_ns=issued_at_ns,
                expires_at_ns=expires_at_ns,
                scopes=verified.scopes,
            )
            return _IDENTITY_ISSUER.issue(identity)
        except Exception:
            self._reject("OMEGA_AUTH_DENIED")

    def signed_heartbeat(
        self,
        *,
        halted: bool,
        active_halts: tuple[str, ...],
        trace_id: str,
    ) -> dict[str, object]:
        """Build the signed, versioned control-plane response; no market data."""
        if type(halted) is not bool or type(active_halts) is not tuple:
            self._reject("OMEGA_HEARTBEAT_UNAVAILABLE", 503)
        try:
            now_ns = self._clock_ns()
        except Exception:
            now_ns = None
        if type(now_ns) is not int or not 0 <= now_ns <= _MAX_CLOCK_NS:
            self._reject("OMEGA_HEARTBEAT_UNAVAILABLE", 503)
        unsigned: dict[str, object] = {
            "version": "1",
            "system": "leviathan",
            "capability_manifest_hash": self._capability_manifest_hash,
            "halted": halted,
            "active_halts": list(active_halts),
            "timestamp_ns": now_ns,
            "freshness_ns": self._policy.max_heartbeat_age_ns,
            "trace_id": trace_id,
        }
        payload = json.dumps(
            unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
        try:
            signature = self._response_signer(payload)
        except Exception:
            signature = None
        if type(signature) is not str or not signature or not signature.isascii():
            self._reject("OMEGA_HEARTBEAT_UNAVAILABLE", 503)
        return {**unsigned, "signature": signature}

    def engage_kill(self, *, peer: OmegaPeerIdentityV1, halt_authority: HaltAuthority) -> str:
        """Engage the sole HALT authority with a stable peer-specific reason."""
        if type(peer) is not OmegaPeerIdentityV1 or type(halt_authority) is not HaltAuthority:
            self._reject("OMEGA_KILL_DENIED", 503)
        try:
            require(peer, _IDENTITY_ISSUER.tag)
            now_ns = self._clock_ns()
        except Exception:
            self._reject("OMEGA_KILL_DENIED", 503)
        if (
            "omega:kill" not in peer.scopes
            or type(now_ns) is not int
            or now_ns >= peer.expires_at_ns
            or now_ns - peer.issued_at_ns >= _MAX_TOKEN_AGE_NS
        ):
            self._reject("OMEGA_KILL_DENIED", 503)
        reason = HaltReasonV1.OMEGA_KILL_SIGNAL
        try:
            halt_authority.engage(reason)
        except Exception:
            self._reject("OMEGA_KILL_ENGAGE_FAILED", 503)
        return reason


def _certificate_binding(certificate_der: bytes) -> str:
    """Return the JWT x5t#S256 binding for exact DER certificate bytes."""
    import base64

    return base64.urlsafe_b64encode(hashlib.sha256(certificate_der).digest()).rstrip(b"=").decode(
        "ascii"
    )


__all__ = [
    "InMemoryOmegaNonceStore",
    "OmegaAdapterError",
    "OmegaHeartbeatAdapterV1",
    "OmegaNonceStore",
    "OmegaPeerIdentityV1",
]
