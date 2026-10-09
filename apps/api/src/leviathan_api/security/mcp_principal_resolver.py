"""Resolve SEC-003 verified tokens into issued SEC-002 trusted principals.

This adapter accepts only a token and optional authenticated peer-certificate
bytes. Client-supplied role, organization, scope, approval, and entitlement
values are never accepted as authority. The resolver does not make an
action-specific authorization decision; callers must use SEC-002 ``authorize``.
Verifier ports are trusted construction-time dependencies. No network or vault
access occurs here.
"""

from __future__ import annotations

from enum import StrEnum

from leviathan_core.security.authz_models import (
    TrustedPrincipalV1,
    require_trusted_principal,
)
from leviathan_core.security.principal_verifier import PrincipalVerifier, VerifiedPrincipalV1


class McpPrincipalResolutionCodeV1(StrEnum):
    """Closed, content-free resolver outcomes."""

    VERIFIER_UNAVAILABLE = "VERIFIER_UNAVAILABLE"
    PRINCIPAL_REJECTED = "PRINCIPAL_REJECTED"


class McpPrincipalResolutionError(ValueError):
    """A stable resolver failure that retains no token or claim data."""

    def __init__(self, code: McpPrincipalResolutionCodeV1) -> None:
        self.code = code
        super().__init__(code.value)


class McpPrincipalResolverV1:
    """Adapt SEC-003 verifier output through the existing SEC-002 issuer."""

    __slots__ = ("_verifier",)

    def __init__(self, verifier: PrincipalVerifier | None) -> None:
        self._verifier = verifier if type(verifier) is PrincipalVerifier else None

    def resolve(
        self,
        token: object,
        *,
        peer_certificate_der: object | None = None,
    ) -> TrustedPrincipalV1:
        """Return an issued SEC-002 principal from the SEC-003 verified identity."""

        verified = self.resolve_verified(token, peer_certificate_der=peer_certificate_der)
        verifier = self._verifier
        if verifier is None:
            raise McpPrincipalResolutionError(McpPrincipalResolutionCodeV1.VERIFIER_UNAVAILABLE)
        try:
            trusted = verifier.to_trusted_principal(verified)
            return require_trusted_principal(trusted)
        except Exception:
            pass
        raise McpPrincipalResolutionError(McpPrincipalResolutionCodeV1.PRINCIPAL_REJECTED)

    def resolve_verified(
        self,
        token: object,
        *,
        peer_certificate_der: object | None = None,
    ) -> VerifiedPrincipalV1:
        """Return the exact SEC-003-issued verified principal, without re-issuing it."""

        verifier = self._verifier
        if verifier is None:
            raise McpPrincipalResolutionError(McpPrincipalResolutionCodeV1.VERIFIER_UNAVAILABLE)
        if type(token) is not str or (
            peer_certificate_der is not None and type(peer_certificate_der) is not bytes
        ):
            raise McpPrincipalResolutionError(McpPrincipalResolutionCodeV1.PRINCIPAL_REJECTED)
        try:
            verified = verifier.verify(token, peer_certificate_der=peer_certificate_der)
            if type(verified) is not VerifiedPrincipalV1:
                raise TypeError
            return verified
        except Exception:
            pass
        raise McpPrincipalResolutionError(McpPrincipalResolutionCodeV1.PRINCIPAL_REJECTED)


__all__ = [
    "McpPrincipalResolutionCodeV1",
    "McpPrincipalResolutionError",
    "McpPrincipalResolverV1",
]
