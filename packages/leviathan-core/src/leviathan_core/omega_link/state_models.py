"""Immutable, local-only boundary records for the OMEGA bridge decision kernel."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any, Literal, NoReturn, Self, SupportsIndex

from pydantic import ConfigDict, PrivateAttr, ValidationError, field_validator, model_validator

from leviathan_core.schemas.base import LeviathanModel

BridgeState = Literal["connected", "degraded", "disconnected"]
SessionState = Literal["active", "paused", "revoked", "expired"]
TaskState = Literal[
    "pending", "in_progress", "waiting", "succeeded", "failed", "cancelled", "expired"
]
Action = Literal["task_accept", "task_update", "task_cancel", "tool_use"]
DecisionReason = Literal[
    "BRIDGE_DEGRADED",
    "BRIDGE_DISCONNECTED",
    "BRIDGE_READY",
    "HALT_ACTIVE",
    "PEER_KILLED",
    "UNKNOWN_ACTION",
    "TASK_EXPIRED",
    "SESSION_UNVERIFIED",
    "SESSION_INACTIVE",
    "ACTOR_MISMATCH",
    "MANIFEST_MISMATCH",
    "BUDGET_EXHAUSTED",
    "TASK_REQUIRED",
    "TASK_TERMINAL",
    "CREATOR_REQUIRED",
    "TASK_CANCELLED",
    "OWNER_REQUIRED",
    "INVALID_TRANSITION",
    "TASK_ACCEPTED",
    "TASK_UPDATED",
    "TOOL_REQUIRED",
    "TOOL_DENIED",
    "TOOL_KILLED",
    "FINANCIAL_ROUTE_DENIED",
    "SCOPE_DENIED",
    "TOOL_ALLOWED",
]

_IDENTIFIER = re.compile(r"[A-Za-z][A-Za-z0-9_.:-]{0,127}\Z", re.ASCII)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_MAX_NS = (1 << 63) - 1
DEFAULT_RATE_RPS = 50
DEFAULT_RATE_BURST = 100
MAX_SESSION_LIFETIME_NS = 300_000_000_000
MAX_HEARTBEAT_POLICY_AGE_NS = 1_800_000_000_000  # backend maximum handoff TTL: 30 minutes
_SESSION_ISSUER = object()
_ERROR_TYPE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z", re.ASCII)


class OmegaValidationError(Exception):
    """Public, input-free validation failure for OMEGA boundary records."""

    __slots__ = ("code", "error_type", "loc")

    def __init__(self, *, code: str, loc: tuple[str | int, ...], error_type: str) -> None:
        super().__init__(code)
        self.code = code
        self.loc = loc
        self.error_type = error_type

    def errors(self) -> list[dict[str, object]]:
        return [{"code": self.code, "loc": self.loc, "type": self.error_type}]

    def json(self) -> str:
        return json.dumps(self.errors(), sort_keys=True, separators=(",", ":"))


def _redacted_error(exc: ValidationError) -> OmegaValidationError:
    detail = exc.errors(include_url=False, include_context=False, include_input=False)[0]
    allowed_fields = {
        field
        for model in _BridgeModel.__subclasses__()
        for field in model.model_fields
    }
    loc = tuple(
        part
        if (type(part) is int and part >= 0)
        or (type(part) is str and part in allowed_fields)
        else "unknown_field"
        for part in detail["loc"]
    )
    raw_type = detail["type"]
    error_type = (
        raw_type
        if isinstance(raw_type, str) and _ERROR_TYPE.fullmatch(raw_type)
        else "validation_error"
    )
    code = "POLICY_OUT_OF_BOUNDS" if "max_heartbeat_age_ns" in loc else "OMEGA_INVALID_INPUT"
    return OmegaValidationError(code=code, loc=loc, error_type=error_type)


def _identifier(value: str) -> str:
    if _IDENTIFIER.fullmatch(value) is None:
        raise ValueError("invalid bridge identifier")
    return value


def _sha256(value: str) -> str:
    if _SHA256.fullmatch(value) is None:
        raise ValueError("invalid SHA-256 digest")
    return value


def _nonnegative_ns(value: int) -> int:
    if isinstance(value, bool) or value < 0 or value > _MAX_NS:
        raise ValueError("invalid UTC nanosecond timestamp")
    return value


def _identifiers(value: object) -> tuple[str, ...]:
    if not isinstance(value, (tuple, list)):
        raise ValueError("identifier collection must be a sequence")
    result = tuple(_identifier(item) for item in value if isinstance(item, str))
    if len(result) != len(value) or len(set(result)) != len(result):
        raise ValueError("invalid identifier collection")
    return tuple(sorted(result))


def _halt_reasons(value: object) -> tuple[str, ...]:
    if not isinstance(value, (tuple, list)):
        raise ValueError("halt snapshot must be a sequence")
    result: list[str] = []
    for item in value:
        if (
            not isinstance(item, str)
            or not 1 <= len(item) <= 256
            or any(ord(char) < 32 or ord(char) > 126 for char in item)
        ):
            raise ValueError("invalid halt snapshot reason")
        result.append(item)
    if len(set(result)) != len(result):
        raise ValueError("duplicate halt snapshot reason")
    return tuple(sorted(result))


class _BridgeModel(LeviathanModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True, hide_input_in_errors=True)

    def _frozen_error(self, name: str) -> OmegaValidationError:
        loc = (name,) if name in type(self).model_fields else ("unknown_field",)
        return OmegaValidationError(
            code="OMEGA_FROZEN_RECORD", loc=loc, error_type="frozen_instance"
        )

    def __setattr__(self, name: str, value: Any) -> NoReturn:
        raise self._frozen_error(name)

    def __delattr__(self, name: str) -> NoReturn:
        raise self._frozen_error(name)

    def __init__(self, **data: Any) -> None:
        safe_error: OmegaValidationError | None = None
        try:
            super().__init__(**data)
        except ValidationError as exc:
            safe_error = _redacted_error(exc)
        if safe_error is not None:
            raise safe_error

    @classmethod
    def model_validate(cls, obj: Any, **kwargs: Any) -> Self:
        safe_error: OmegaValidationError | None = None
        try:
            return super().model_validate(obj, **kwargs)
        except ValidationError as exc:
            safe_error = _redacted_error(exc)
        assert safe_error is not None
        raise safe_error

    @classmethod
    def model_validate_json(cls, json_data: Any, **kwargs: Any) -> Self:
        safe_error: OmegaValidationError | None = None
        try:
            return super().model_validate_json(json_data, **kwargs)
        except ValidationError as exc:
            safe_error = _redacted_error(exc)
        assert safe_error is not None
        raise safe_error

    @classmethod
    def model_validate_strings(cls, obj: Any, **kwargs: Any) -> Self:
        safe_error: OmegaValidationError | None = None
        try:
            return super().model_validate_strings(obj, **kwargs)
        except ValidationError as exc:
            safe_error = _redacted_error(exc)
        assert safe_error is not None
        raise safe_error

    @classmethod
    def model_construct(  # type: ignore[override]
        cls, _fields_set: set[str] | None = None, **values: Any
    ) -> Self:
        raise TypeError("unchecked bridge construction is forbidden")

    def model_copy(self, *, update: Mapping[str, Any] | None = None, deep: bool = False) -> Self:
        raise TypeError("unchecked bridge copying is forbidden")

    def copy(self, **kwargs: Any) -> Self:
        raise TypeError("unchecked bridge copying is forbidden")

    def __copy__(self) -> NoReturn:
        raise TypeError("bridge copying is forbidden")

    def __deepcopy__(self, memo: dict[int, Any] | None = None) -> NoReturn:
        raise TypeError("bridge copying is forbidden")

    def __reduce__(self) -> NoReturn:
        raise TypeError("bridge serialization is forbidden")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise TypeError("bridge serialization is forbidden")

    def __getstate__(self) -> NoReturn:
        raise TypeError("bridge serialization is forbidden")


class BridgeHealthV1(_BridgeModel):
    """Trusted adapter observations and HALT snapshot, never a second halt store."""

    version: Literal["1"]
    peer_system: str
    transport_verified: bool
    heartbeat_at_ns: int | None
    heartbeat_expires_ns: int | None
    previous_heartbeat_at_ns: int | None = None
    degraded: bool = False
    peer_kill_pending: bool = False
    peer_killed: bool = False
    tool_kill_pending: tuple[str, ...] = ()
    killed_tools: tuple[str, ...] = ()
    halt_reasons: tuple[str, ...] = ()
    halt_version: int = 0

    @field_validator("peer_system")
    @classmethod
    def _peer_id(cls, value: str) -> str:
        return _identifier(value)

    @field_validator("tool_kill_pending", "killed_tools", mode="before")
    @classmethod
    def _freeze_ids(cls, value: object) -> tuple[str, ...]:
        return _identifiers(value)

    @field_validator("halt_reasons", mode="before")
    @classmethod
    def _freeze_halts(cls, value: object) -> tuple[str, ...]:
        return _halt_reasons(value)

    @field_validator("heartbeat_at_ns", "heartbeat_expires_ns", "previous_heartbeat_at_ns")
    @classmethod
    def _clock(cls, value: int | None) -> int | None:
        return None if value is None else _nonnegative_ns(value)

    @field_validator("halt_version")
    @classmethod
    def _halt_version(cls, value: int) -> int:
        if type(value) is not int or value < 0:
            raise ValueError("halt version must be nonnegative")
        return value

    @model_validator(mode="after")
    def _heartbeat_shape(self) -> Self:
        if (self.heartbeat_at_ns is None) != (self.heartbeat_expires_ns is None):
            raise ValueError("heartbeat observation and expiry must both be present")
        if (
            self.heartbeat_at_ns is not None
            and self.heartbeat_expires_ns is not None
            and self.heartbeat_expires_ns <= self.heartbeat_at_ns
        ):
            raise ValueError("heartbeat expiry must follow observation")
        return self


class OmegaPolicyV1(_BridgeModel):
    """Injected heartbeat SLA; the value is an open OMEGA-002/operator policy item."""

    version: Literal["1"]
    max_heartbeat_age_ns: int

    @field_validator("max_heartbeat_age_ns")
    @classmethod
    def _bounded_age(cls, value: int) -> int:
        if type(value) is not int or not 0 < value <= MAX_HEARTBEAT_POLICY_AGE_NS:
            raise ValueError("POLICY_OUT_OF_BOUNDS")
        return value


class AgentSessionV1(_BridgeModel):
    version: Literal["1"]
    session_id: str
    peer_system: str
    agent_id: str
    scopes: tuple[str, ...] = ()
    manifest_hash: str
    status: SessionState = "active"
    issued_at_ns: int
    expires_at_ns: int
    action_budget: int
    _trusted_claims: tuple[object, int, tuple[object, ...]] | None = PrivateAttr(default=None)

    def _claims(self) -> tuple[object, ...]:
        return (
            self.version,
            self.session_id,
            self.peer_system,
            self.agent_id,
            self.scopes,
            self.manifest_hash,
            self.status,
            self.issued_at_ns,
            self.expires_at_ns,
            self.action_budget,
        )

    @property
    def verified(self) -> bool:
        claims = self._trusted_claims
        return (
            claims is not None
            and claims[0] is _SESSION_ISSUER
            and claims[1] == id(self)
            and claims[2] == self._claims()
        )

    @field_validator("session_id", "peer_system", "agent_id")
    @classmethod
    def _id(cls, value: str) -> str:
        return _identifier(value)

    @field_validator("scopes", mode="before")
    @classmethod
    def _scopes(cls, value: object) -> tuple[str, ...]:
        return _identifiers(value)

    @field_validator("manifest_hash")
    @classmethod
    def _manifest_digest(cls, value: str) -> str:
        return _sha256(value)

    @field_validator("issued_at_ns", "expires_at_ns")
    @classmethod
    def _clock(cls, value: int) -> int:
        return _nonnegative_ns(value)

    @field_validator("action_budget")
    @classmethod
    def _budget(cls, value: int) -> int:
        if type(value) is not int or value < 0:
            raise ValueError("action budget must be nonnegative")
        return value

    @model_validator(mode="after")
    def _short_lived(self) -> Self:
        if not 0 < self.expires_at_ns - self.issued_at_ns < MAX_SESSION_LIFETIME_NS:
            raise ValueError("session lifetime must be under five minutes")
        return self


def _from_trusted_adapter(*, session: AgentSessionV1) -> AgentSessionV1:
    """Internal OMEGA-002 seam: call only after authenticating the session claims."""
    if type(session) is not AgentSessionV1:
        raise TypeError("validated session required")
    issued = AgentSessionV1.model_validate(session.model_dump())
    assert issued.__pydantic_private__ is not None
    issued.__pydantic_private__["_trusted_claims"] = (
        _SESSION_ISSUER,
        id(issued),
        issued._claims(),  # noqa: SLF001 - same-module sealed issuance
    )
    return issued


class HandoffTaskV1(_BridgeModel):
    version: Literal["1"]
    task_id: str
    task_type: str
    created_by: str
    assigned_to: str
    state: TaskState = "pending"
    created_at_ns: int
    ttl_ms: int
    sla_ms: int
    context_hash: str
    tool_allowlist: tuple[str, ...] = ()
    audit_ref: str | None = None

    @field_validator("task_id", "task_type", "created_by", "assigned_to", "audit_ref")
    @classmethod
    def _id(cls, value: str | None) -> str | None:
        return None if value is None else _identifier(value)

    @field_validator("tool_allowlist", mode="before")
    @classmethod
    def _tools(cls, value: object) -> tuple[str, ...]:
        return _identifiers(value)

    @field_validator("context_hash")
    @classmethod
    def _context_digest(cls, value: str) -> str:
        return _sha256(value)

    @field_validator("created_at_ns")
    @classmethod
    def _clock(cls, value: int) -> int:
        return _nonnegative_ns(value)

    @model_validator(mode="after")
    def _lifetime(self) -> Self:
        if type(self.ttl_ms) is not int or not 1_000 <= self.ttl_ms <= 1_800_000:
            raise ValueError("task TTL must be 1s to 30m")
        if type(self.sla_ms) is not int or not 0 < self.sla_ms <= self.ttl_ms:
            raise ValueError("task SLA must be within TTL")
        if self.expires_at_ns > _MAX_NS:
            raise ValueError("task expiry exceeds UTC nanosecond range")
        return self

    @property
    def expires_at_ns(self) -> int:
        return self.created_at_ns + self.ttl_ms * 1_000_000


class CapabilityManifestV1(_BridgeModel):
    """Canonical capabilities; defaults describe policy, enforcement is OMEGA-002."""

    version: Literal["1"]
    tools: tuple[str, ...] = ()
    datasets: tuple[str, ...] = ()
    actions: tuple[str, ...] = ()
    limits: tuple[tuple[str, int], ...] = ()
    financial_tools: tuple[str, ...] = ()

    @field_validator("tools", "datasets", "actions", "financial_tools", mode="before")
    @classmethod
    def _freeze_ids(cls, value: object) -> tuple[str, ...]:
        return _identifiers(value)

    @field_validator("limits", mode="before")
    @classmethod
    def _freeze_limits(cls, value: object) -> tuple[tuple[str, int], ...]:
        if not isinstance(value, (tuple, list)):
            raise ValueError("manifest limits must be a sequence")
        result: list[tuple[str, int]] = []
        for item in value:
            if not isinstance(item, (tuple, list)) or len(item) != 2:
                raise ValueError("invalid manifest limit")
            name, amount = item
            if not isinstance(name, str) or type(amount) is not int or amount < 0:
                raise ValueError("invalid manifest limit")
            result.append((_identifier(name), amount))
        if len({name for name, _ in result}) != len(result):
            raise ValueError("duplicate manifest limit")
        return tuple(sorted(result))

    @model_validator(mode="after")
    def _financial_subset(self) -> Self:
        if not set(self.financial_tools).issubset(self.tools):
            raise ValueError("financial tools must be declared tools")
        return self

    @property
    def manifest_hash(self) -> str:
        payload = self.model_dump(mode="json")
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(encoded.encode("ascii")).hexdigest()

    @property
    def rate_limit_rps(self) -> int:
        return dict(self.limits).get("rate_rps", DEFAULT_RATE_RPS)

    @property
    def rate_limit_burst(self) -> int:
        return dict(self.limits).get("rate_burst", DEFAULT_RATE_BURST)


class KillSyncIntentV1(_BridgeModel):
    """A request for an adapter to call HaltAuthority.engage; no state mutation."""

    version: Literal["1"]
    request_id: str
    peer_system: str
    tool_id: str | None = None
    reason_code: str
    requested_at_ns: int
    halt_version: int
    halt_reason: str

    @field_validator("request_id", "peer_system", "tool_id", "reason_code", "halt_reason")
    @classmethod
    def _id(cls, value: str | None) -> str | None:
        return None if value is None else _identifier(value)

    @field_validator("requested_at_ns")
    @classmethod
    def _clock(cls, value: int) -> int:
        return _nonnegative_ns(value)

    @field_validator("halt_version")
    @classmethod
    def _version(cls, value: int) -> int:
        if type(value) is not int or value < 0:
            raise ValueError("halt version must be nonnegative")
        return value


class BridgeDecisionV1(_BridgeModel):
    version: Literal["1"]
    allowed: bool
    reason_code: DecisionReason
    bridge_state: BridgeState
    next_task: HandoffTaskV1 | None = None
    kill_intent: KillSyncIntentV1 | None = None
