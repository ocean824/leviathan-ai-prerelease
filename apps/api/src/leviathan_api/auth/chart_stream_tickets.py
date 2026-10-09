"""Bounded, single-use browser tickets for the local chart WebSocket."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

_TOKEN = re.compile(r"[A-Za-z0-9_-]{43}\Z", re.ASCII)
_VENUE = re.compile(r"(?:[A-Z0-9]{4}|DBN-PUB-[0-9]{1,19})\Z", re.ASCII)
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)
_DATA_TYPES = frozenset({"trades", "quotes", "mbp-1", "mbo", "mbp-10", "ohlcv-1m"})
_MAX_TTL_NS = 30_000_000_000
_MAX_CAPACITY = 4096


class ChartStreamTicketError(ValueError):
    """Fixed, content-free ticket failure."""

    def __init__(self, code: str) -> None:
        self.code = (
            code
            if code in {"INVALID_TICKET", "TICKET_CAPACITY", "INVALID_BINDING"}
            else "INVALID_TICKET"
        )
        super().__init__(self.code)


@dataclass(frozen=True, slots=True)
class ChartStreamScopeV1:
    venue: str
    instrument: str
    data_type: str

    def __post_init__(self) -> None:
        if (
            type(self.venue) is not str
            or _VENUE.fullmatch(self.venue) is None
            or type(self.instrument) is not str
            or _IDENTIFIER.fullmatch(self.instrument) is None
            or type(self.data_type) is not str
            or self.data_type not in _DATA_TYPES
        ):
            raise ChartStreamTicketError("INVALID_BINDING")


class _PrincipalLike(Protocol):
    @property
    def principal_id(self) -> str: ...

    @property
    def project_id(self) -> str: ...

    @property
    def roles(self) -> tuple[str, ...]: ...

    @property
    def env(self) -> str: ...

    @property
    def venue(self) -> str | None: ...

    @property
    def portfolio(self) -> str | None: ...

    @property
    def strategy(self) -> str | None: ...

    @property
    def break_glass(self) -> bool: ...


class _ProfileLike(Protocol):
    @property
    def principal_id(self) -> str: ...

    @property
    def project_id(self) -> str: ...

    @property
    def env(self) -> str: ...

    @property
    def roles(self) -> tuple[str, ...]: ...

    @property
    def venue(self) -> str | None: ...

    @property
    def portfolio(self) -> str | None: ...

    @property
    def strategy(self) -> str | None: ...


def _digest(value: object) -> bytes:
    try:
        encoded = json.dumps(
            value, ensure_ascii=True, separators=(",", ":"), sort_keys=True
        ).encode("ascii")
    except (TypeError, ValueError):
        raise ChartStreamTicketError("INVALID_BINDING") from None
    return hashlib.sha256(encoded).digest()


def principal_binding(principal: _PrincipalLike) -> bytes:
    try:
        fields = (
            principal.principal_id,
            principal.project_id,
            principal.roles,
            principal.env,
            principal.venue,
            principal.portfolio,
            principal.strategy,
            principal.break_glass,
        )
    except Exception:
        raise ChartStreamTicketError("INVALID_BINDING") from None
    if any(type(item) not in (str, tuple, bool, type(None)) for item in fields):
        raise ChartStreamTicketError("INVALID_BINDING")
    return _digest(("principal-v1", fields))


def profile_binding(profile: _ProfileLike) -> bytes:
    try:
        fields = (
            profile.principal_id,
            profile.project_id,
            profile.env,
            profile.roles,
            profile.venue,
            profile.portfolio,
            profile.strategy,
        )
    except Exception:
        raise ChartStreamTicketError("INVALID_BINDING") from None
    if any(type(item) not in (str, tuple, type(None)) for item in fields):
        raise ChartStreamTicketError("INVALID_BINDING")
    return _digest(("operator-profile-v1", fields))


@dataclass(frozen=True, slots=True)
class _TicketBinding:
    principal_digest: bytes
    profile_digest: bytes
    origin: str
    stream_scope: ChartStreamScopeV1
    expires_at_ns: int


class ChartStreamTicketStore:
    """In-memory ticket store; only digests are retained and consumption is atomic."""

    __slots__ = ("_capacity", "_clock_ns", "_tickets", "_ttl_ns")

    def __init__(
        self,
        *,
        clock_ns: Callable[[], int] = time.monotonic_ns,
        ttl_ns: int = _MAX_TTL_NS,
        capacity: int = 1024,
    ) -> None:
        if (
            not callable(clock_ns)
            or type(ttl_ns) is not int
            or not 1 <= ttl_ns <= _MAX_TTL_NS
            or type(capacity) is not int
            or not 1 <= capacity <= _MAX_CAPACITY
        ):
            raise ChartStreamTicketError("INVALID_BINDING")
        self._clock_ns = clock_ns
        self._ttl_ns = ttl_ns
        self._capacity = capacity
        self._tickets: OrderedDict[bytes, _TicketBinding] = OrderedDict()

    @property
    def size(self) -> int:
        self._prune(self._now())
        return len(self._tickets)

    @property
    def ttl_ns(self) -> int:
        return self._ttl_ns

    def issue(
        self,
        *,
        principal: _PrincipalLike,
        profile: _ProfileLike,
        origin: str,
        stream_scope: ChartStreamScopeV1,
    ) -> str:
        now = self._now()
        self._prune(now)
        if (
            type(origin) is not str
            or not origin.isascii()
            or not 1 <= len(origin) <= 256
            or type(stream_scope) is not ChartStreamScopeV1
        ):
            raise ChartStreamTicketError("INVALID_BINDING")
        if len(self._tickets) >= self._capacity:
            # Keep memory bounded and favor current browser handshakes.
            self._tickets.popitem(last=False)
        token = secrets.token_urlsafe(32)
        token_digest = hashlib.sha256(token.encode("ascii")).digest()
        self._tickets[token_digest] = _TicketBinding(
            principal_digest=principal_binding(principal),
            profile_digest=profile_binding(profile),
            origin=origin,
            stream_scope=stream_scope,
            expires_at_ns=now + self._ttl_ns,
        )
        return token

    def consume(
        self,
        token: object,
        *,
        principal: _PrincipalLike,
        profile: _ProfileLike,
        origin: object,
        stream_scope: object,
    ) -> bool:
        now = self._now()
        self._prune(now)
        if type(token) is not str:
            token_bytes = b""
        else:
            try:
                token_bytes = token.encode("ascii")
            except UnicodeEncodeError:
                token_bytes = b""
        presented = hashlib.sha256(token_bytes).digest()
        matched: bytes | None = None
        # Compare every live digest so store position does not reveal the ticket.
        for candidate in self._tickets:
            if hmac.compare_digest(candidate, presented):
                matched = candidate
        if matched is None:
            return False
        binding = self._tickets.pop(matched)  # first presentation consumes it, even on mismatch
        try:
            return (
                binding.expires_at_ns > now
                and type(origin) is str
                and hmac.compare_digest(binding.origin.encode("ascii"), origin.encode("ascii"))
                and type(stream_scope) is ChartStreamScopeV1
                and binding.stream_scope == stream_scope
                and hmac.compare_digest(binding.principal_digest, principal_binding(principal))
                and hmac.compare_digest(binding.profile_digest, profile_binding(profile))
            )
        except (ChartStreamTicketError, UnicodeEncodeError):
            return False

    def _now(self) -> int:
        try:
            now = self._clock_ns()
        except Exception:
            raise ChartStreamTicketError("INVALID_TICKET") from None
        if type(now) is not int or not 0 <= now <= (1 << 63) - 1:
            raise ChartStreamTicketError("INVALID_TICKET")
        return now

    def _prune(self, now: int) -> None:
        expired = [key for key, binding in self._tickets.items() if binding.expires_at_ns <= now]
        for key in expired:
            self._tickets.pop(key, None)


__all__ = [
    "ChartStreamScopeV1",
    "ChartStreamTicketError",
    "ChartStreamTicketStore",
    "principal_binding",
    "profile_binding",
]
