"""Authorized, org-scoped correlation over the OBS-002 read-only buffer."""

from __future__ import annotations

import re
from typing import Final, Protocol
from uuid import RFC_4122, UUID

from leviathan_core.observability.live_log import (
    LiveLogBufferV1,
    LiveLogEntryV1,
    LiveLogError,
)
from leviathan_core.seal import SealError, require
from leviathan_core.security.principal_verifier import VerifiedPrincipalV1

_PRINCIPAL_TAG: Final = "sec003.verified_principal.v1"
_CORRELATE_SCOPE: Final = "ops.observability.correlate"
_ALLOWED_ROLES: Final = frozenset({"operator", "devops"})
_UUID4: Final = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z",
    re.ASCII,
)
_MAX_READ_LIMIT: Final = 1000
_MAX_SCAN: Final = 100_000


class CorrelationError(ValueError):
    """Content-free correlation failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class CorrelationPolicy(Protocol):
    """Structural interface for the injected SEC-002 decision policy."""

    def allows(self, principal: VerifiedPrincipalV1, action: str) -> bool: ...


class CorrelationKernelV1:
    """Search only the verified principal's organization in the bounded log buffer."""

    def __init__(
        self,
        logs: LiveLogBufferV1,
        policy: CorrelationPolicy,
        *,
        max_scan_entries: int = _MAX_SCAN,
    ) -> None:
        if (
            type(logs) is not LiveLogBufferV1
            or not callable(getattr(policy, "allows", None))
            or type(max_scan_entries) is not int
            or not 1 <= max_scan_entries <= _MAX_SCAN
        ):
            raise CorrelationError("CORRELATION_CONFIG_INVALID")
        self._logs = logs
        self._policy = policy
        self._max_scan = max_scan_entries

    async def correlate(
        self,
        principal: VerifiedPrincipalV1,
        correlation_id: str,
    ) -> tuple[LiveLogEntryV1, ...]:
        self._authorize(principal)
        if type(correlation_id) is not str or _UUID4.fullmatch(correlation_id) is None:
            raise CorrelationError("CORRELATION_ID_INVALID")
        try:
            parsed = UUID(correlation_id)
        except ValueError:
            raise CorrelationError("CORRELATION_ID_INVALID") from None
        if parsed.variant != RFC_4122 or parsed.version != 4 or str(parsed) != correlation_id:
            raise CorrelationError("CORRELATION_ID_INVALID")
        cursor = 0
        scanned = 0
        matches: list[LiveLogEntryV1] = []
        while scanned < self._max_scan:
            limit = min(_MAX_READ_LIMIT, self._max_scan - scanned)
            try:
                page = await self._logs.read_live(
                    principal,
                    after_sequence=cursor,
                    limit=limit,
                )
            except LiveLogError:
                raise CorrelationError("CORRELATION_ACCESS_DENIED") from None
            except Exception:
                raise CorrelationError("CORRELATION_UNAVAILABLE") from None
            if not page:
                return tuple(matches)
            scanned += len(page)
            cursor = page[-1].sequence
            matches.extend(item for item in page if item.event.correlation_id == correlation_id)
            if len(page) < limit:
                return tuple(matches)
        raise CorrelationError("CORRELATION_SCAN_LIMIT")

    def _authorize(self, principal: VerifiedPrincipalV1) -> None:
        try:
            if type(principal) is not VerifiedPrincipalV1:
                raise SealError("principal rejected")
            require(principal, _PRINCIPAL_TAG)
            allowed = (
                principal.role.casefold() in _ALLOWED_ROLES
                and _CORRELATE_SCOPE in principal.scopes
                and self._policy.allows(principal, _CORRELATE_SCOPE) is True
            )
        except Exception:
            allowed = False
        if not allowed:
            raise CorrelationError("CORRELATION_ACCESS_DENIED") from None


__all__ = ["CorrelationError", "CorrelationKernelV1"]
