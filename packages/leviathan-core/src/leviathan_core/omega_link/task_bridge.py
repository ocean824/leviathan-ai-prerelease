"""Typed, side-effect-free OMEGA task bridge records and injected ports.

This module defines the trusted runtime boundary for the HTTP adapter. It does
not provide local stores, audit sinks, event queues, executors, provider calls,
order effects, or HALT mutation paths.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping
from types import MappingProxyType
from typing import Any, Literal, Protocol

from pydantic import Field, StrictBool, StrictInt, field_validator

from leviathan_core.agent_council.model_registry import RouteModelError
from leviathan_core.agent_council.model_router import (
    RouteDecisionV1,
    RouteDenialV1,
    require_route_decision,
    verify_route_denial,
)
from leviathan_core.mcp_control.policy_models import PolicyDecisionV1
from leviathan_core.numeric import NumericError, canonical_json
from leviathan_core.omega_link.bridge_state import evaluate_bridge
from leviathan_core.omega_link.heartbeat_adapter import OmegaPeerIdentityV1
from leviathan_core.omega_link.state_models import (
    AgentSessionV1,
    BridgeHealthV1,
    CapabilityManifestV1,
    HandoffTaskV1,
    OmegaPolicyV1,
    _BridgeModel,
)
from leviathan_core.seal import Issuer, SealedModel, require
from leviathan_core.text.credential_patterns import contains_credential_value

_ID = re.compile(r"[A-Za-z][A-Za-z0-9_.:-]{0,127}\Z", re.ASCII)
_IDEMPOTENCY_KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._~-]{0,127}\Z", re.ASCII)
_BLOB_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_VAULT_REFERENCE = re.compile(
    r"vault://leviathan-ai/(development|live)/(claude|gemini|deepseek|gpt|ollama)/"
    r"([A-Z][A-Z0-9_]{0,63})\Z",
    re.ASCII,
)
OMEGA_TASK_TYPES_V1 = frozenset({"analysis", "research"})
MAX_CONTEXT_BYTES = 65_536
MAX_QUESTION_CHARS = 2_000
MAX_SOURCE_REF_COUNT = 16
MAX_SOURCE_REF_CHARS = 512
MAX_SOURCE_REFS_CHARS = 8_192
# These are the task types currently declared by the bridge API. Each schema is
# closed and bounded; larger or sensitive material must use blob_id/vault refs.
_TASK_CONTEXT_SCHEMAS_V1: Mapping[str, Mapping[str, tuple[str, int]]] = MappingProxyType(
    {
        "analysis": MappingProxyType(
            {"question": ("text", MAX_QUESTION_CHARS), "max_tokens": ("integer", 65_536)}
        ),
        "research": MappingProxyType(
            {
                "question": ("text", MAX_QUESTION_CHARS),
                "max_tokens": ("integer", 65_536),
                "source_refs": ("text_list", MAX_SOURCE_REF_COUNT),
            }
        ),
    }
)
IDEMPOTENCY_RETENTION_NS = 86_400_000_000_000
MAX_UTC_NS = (1 << 63) - 1

Priority = Literal["low", "normal", "high", "urgent"]
TaskCreateDisposition = Literal["created", "duplicate", "conflict"]
MCPAction = Literal["read", "create", "update", "delete", "publish", "execute"]

_RECORD_ISSUER = Issuer("omega003.task_record.v1")
_CREATE_RESULT_ISSUER = Issuer("omega003.task_create_result.v1")
_RATE_RESULT_ISSUER = Issuer("omega003.task_rate_decision.v1")
_AUDIT_ENTRY_ISSUER = Issuer("omega003.task_audit_entry.v1")
_AUDIT_RECEIPT_ISSUER = Issuer("omega003.task_audit_receipt.v1")
_AUDIT_RECORD_ISSUER = Issuer("omega003.task_audit_record.v1")
_LIFECYCLE_ISSUER = Issuer("omega003.task_lifecycle_event.v1")


class TaskBridgeError(ValueError):
    """Fixed-code task-bridge failure that never retains request content."""

    __slots__ = ("code", "status_code")

    def __init__(self, code: str, status_code: int = 503) -> None:
        self.code = code
        self.status_code = status_code
        super().__init__(code)


def _contains_credential_value(value: object) -> bool:
    """Defense-in-depth scan of values after closed-schema and size validation.

    Closed fields and bounds are the primary control. This scan catches common
    credential shapes in otherwise valid free-text values; field names alone
    never determine whether a value is secret.
    """
    if type(value) is dict:
        for key, child in value.items():
            if type(key) is str and _secret_header_pair(key, child):
                return True
            if _contains_credential_value(child):
                return True
        return False
    if isinstance(value, (list, tuple)):
        if len(value) == 2 and type(value[0]) is str and _secret_header_pair(value[0], value[1]):
            return True
        return any(_contains_credential_value(item) for item in value)
    if type(value) is str:
        return contains_credential_value(value)
    return False


def _secret_header_pair(name: str, value: object) -> bool:
    header = name.casefold()
    if header not in {"cookie", "set-cookie", "authorization"} or type(value) is not str:
        return False
    stripped = value.strip()
    if not stripped:
        return False
    if header in {"cookie", "set-cookie"}:
        return re.search(r"[^=;\s]+=[^;\s]+", stripped, re.ASCII) is not None
    return stripped.casefold() not in {"none", "anonymous", "public"}


def _validate_task_context(task_type: str, context: dict[str, Any]) -> None:
    schema = _TASK_CONTEXT_SCHEMAS_V1.get(task_type)
    if schema is None:
        raise TaskBridgeError("TASK_TYPE_DENIED", 422)
    if any(type(key) is not str or key not in schema for key in context):
        raise TaskBridgeError("CONTEXT_SCHEMA_DENIED", 422)
    if not context:
        raise TaskBridgeError("CONTEXT_SCHEMA_DENIED", 422)
    for key, value in context.items():
        value_type, bound = schema[key]
        if value_type == "text":
            if type(value) is not str or len(value) > bound:
                raise TaskBridgeError("CONTEXT_SCHEMA_DENIED", 422)
        elif value_type == "integer":
            if type(value) is not int or not 1 <= value <= bound:
                raise TaskBridgeError("CONTEXT_SCHEMA_DENIED", 422)
        elif value_type == "text_list":
            if (
                type(value) is not list
                or len(value) > bound
                or any(type(item) is not str or len(item) > MAX_SOURCE_REF_CHARS for item in value)
            ):
                raise TaskBridgeError("CONTEXT_SCHEMA_DENIED", 422)
            if sum(len(item) for item in value) > MAX_SOURCE_REFS_CHARS:
                raise TaskBridgeError("CONTEXT_SCHEMA_DENIED", 422)
        else:  # pragma: no cover - closed schema definition
            raise TaskBridgeError("CONTEXT_SCHEMA_DENIED", 422)


def _lifecycle_event_id(
    *,
    task_id: str,
    previous_state: str,
    new_state: str,
    occurred_at_ns: int,
    reason_code: str,
) -> str:
    raw = canonical_json(
        {
            "task_id": task_id,
            "previous_state": previous_state,
            "new_state": new_state,
            "occurred_at_ns": occurred_at_ns,
            "reason_code": reason_code,
        }
    )
    return "omega_task_" + hashlib.sha256(raw).hexdigest()


class HandoffRequestV1(_BridgeModel):
    """Untrusted request fields; context is canonicalized before persistence."""

    task_type: str = Field(alias="type")
    priority: Priority
    assigned_to: str
    ttl_ms: StrictInt
    sla_ms: StrictInt
    context: dict[str, Any] | None = None
    blob_id: str | None = None
    tool_allowlist: tuple[str, ...] = ()
    requires_risk_guard: StrictBool = False

    @field_validator("task_type", "assigned_to")
    @classmethod
    def _valid_ids(cls, value: str) -> str:
        if _ID.fullmatch(value) is None:
            raise ValueError("invalid identifier")
        return value

    @field_validator("tool_allowlist", mode="before")
    @classmethod
    def _valid_tools(cls, value: object) -> tuple[str, ...]:
        if not isinstance(value, (tuple, list)):
            raise ValueError("invalid tool list")
        if any(type(item) is not str or _ID.fullmatch(item) is None for item in value):
            raise ValueError("invalid tool list")
        tools = tuple(value)
        if len(set(tools)) != len(tools):
            raise ValueError("invalid tool list")
        return tuple(sorted(tools))

    @field_validator("blob_id")
    @classmethod
    def _valid_blob_id(cls, value: str | None) -> str | None:
        if value is not None and _BLOB_ID.fullmatch(value) is None:
            raise ValueError("invalid blob reference")
        return value

    def canonical_context(self) -> tuple[bytes | None, str]:
        if self.task_type not in OMEGA_TASK_TYPES_V1:
            raise TaskBridgeError("TASK_TYPE_DENIED", 422)
        if (self.context is None) == (self.blob_id is None):
            raise TaskBridgeError("CONTEXT_REQUIRED", 422)
        if self.blob_id is not None:
            raw = canonical_json({"blob_id": self.blob_id})
            return None, hashlib.sha256(raw).hexdigest()
        if self.context is None:
            raise TaskBridgeError("CONTEXT_REQUIRED", 422)
        _validate_task_context(self.task_type, self.context)
        try:
            raw = canonical_json(self.context)
        except (NumericError, TypeError, ValueError):
            raise TaskBridgeError("CONTEXT_INVALID", 422) from None
        if len(raw) > MAX_CONTEXT_BYTES:
            raise TaskBridgeError("CONTEXT_TOO_LARGE", 413)
        if _contains_credential_value(self.context):
            raise TaskBridgeError("CONTEXT_SECRET_DENIED", 422)
        return raw, hashlib.sha256(raw).hexdigest()


class TaskRecordV1(SealedModel):
    """Store-owned immutable task snapshot, including context only for delivery."""

    peer_system: str
    task: HandoffTaskV1
    priority: Priority
    requires_risk_guard: StrictBool
    context_payload_hex: str | None = None
    model_route_json: str
    revision: StrictInt = Field(ge=1, le=MAX_UTC_NS)

    @property
    def context_payload(self) -> bytes | None:
        """Return the exact payload while the sealed record binds its hex form."""
        encoded = self.context_payload_hex
        return None if encoded is None else bytes.fromhex(encoded)


class TaskCreateResultV1(SealedModel):
    disposition: TaskCreateDisposition
    record_peer_system: str | None = None
    record_task: HandoffTaskV1 | None = None
    record_priority: Priority | None = None
    record_requires_risk_guard: StrictBool | None = None
    record_context_payload_hex: str | None = None
    record_model_route_json: str | None = None
    record_revision: StrictInt | None = None

    @property
    def record(self) -> TaskRecordV1 | None:
        try:
            require(self, _CREATE_RESULT_ISSUER.tag)
        except Exception:
            raise TaskBridgeError("TASK_STORE_UNAVAILABLE", 503) from None
        if self.record_task is None:
            return None
        if (
            self.record_peer_system is None
            or self.record_priority is None
            or self.record_requires_risk_guard is None
            or self.record_model_route_json is None
            or self.record_revision is None
        ):
            raise TaskBridgeError("TASK_STORE_UNAVAILABLE", 503)
        return _issue_task_record_snapshot(
            peer_system=self.record_peer_system,
            task=self.record_task,
            priority=self.record_priority,
            requires_risk_guard=self.record_requires_risk_guard,
            context_payload_hex=self.record_context_payload_hex,
            model_route_json=self.record_model_route_json,
            revision=self.record_revision,
        )


class TaskRateDecisionV1(SealedModel):
    allowed: StrictBool
    retry_after_seconds: StrictInt = Field(ge=0, le=86_400)


class TaskAuditEntryV1(SealedModel):
    trace_id: str
    peer_system: str
    actor_id: str
    session_id: str
    task_id: str | None = None
    tool_id: str | None = None
    action: str
    reason_code: str
    payload_hash: str
    occurred_at_ns: StrictInt = Field(ge=0, le=MAX_UTC_NS)


class TaskAuditReceiptV1(SealedModel):
    event_id: str
    event_hash: str
    predecessor_hash: str
    sequence: StrictInt = Field(ge=0, le=MAX_UTC_NS)


class TaskAuditRecordV1(SealedModel):
    trace_id: str
    peer_system: str
    actor_id: str
    session_id: str
    task_id: str | None
    tool_id: str | None
    action: str
    reason_code: str
    payload_hash: str
    occurred_at_ns: StrictInt = Field(ge=0, le=MAX_UTC_NS)
    event_id: str
    event_hash: str
    predecessor_hash: str
    sequence: StrictInt = Field(ge=0, le=MAX_UTC_NS)

    @property
    def entry(self) -> TaskAuditEntryV1:
        try:
            require(self, _AUDIT_RECORD_ISSUER.tag)
        except Exception:
            raise TaskBridgeError("AUDIT_UNAVAILABLE", 503) from None
        return issue_task_audit_entry(
            trace_id=self.trace_id,
            peer_system=self.peer_system,
            actor_id=self.actor_id,
            session_id=self.session_id,
            task_id=self.task_id,
            tool_id=self.tool_id,
            action=self.action,
            reason_code=self.reason_code,
            payload_hash=self.payload_hash,
            occurred_at_ns=self.occurred_at_ns,
        )

    @property
    def receipt(self) -> TaskAuditReceiptV1:
        try:
            require(self, _AUDIT_RECORD_ISSUER.tag)
        except Exception:
            raise TaskBridgeError("AUDIT_UNAVAILABLE", 503) from None
        return issue_task_audit_receipt(
            event_id=self.event_id,
            event_hash=self.event_hash,
            predecessor_hash=self.predecessor_hash,
            sequence=self.sequence,
        )


class TaskLifecycleEventV1(SealedModel):
    task_id: str
    previous_state: str | None = None
    new_state: str
    occurred_at_ns: StrictInt = Field(ge=0, le=MAX_UTC_NS)
    agent_session_id: str
    reason_code: str
    trace_id: str
    event_id: str


def issue_task_record(
    *,
    peer_system: str,
    task: HandoffTaskV1,
    priority: Priority,
    requires_risk_guard: bool,
    context_payload: bytes | None,
    model_route: RouteDecisionV1,
    revision: int = 1,
) -> TaskRecordV1:
    if type(task) is not HandoffTaskV1 or type(model_route) is not RouteDecisionV1:
        raise TaskBridgeError("TASK_RECORD_INVALID", 503)
    if context_payload is not None and type(context_payload) is not bytes:
        raise TaskBridgeError("TASK_RECORD_INVALID", 503)
    try:
        require_route_decision(model_route)
    except RouteModelError:
        raise TaskBridgeError("MODEL_POLICY_UNAVAILABLE", 503) from None
    try:
        route_json = canonical_json(model_route.model_dump(mode="json")).decode("ascii")
    except Exception:
        raise TaskBridgeError("MODEL_POLICY_UNAVAILABLE", 503) from None
    return _issue_task_record_snapshot(
        peer_system=peer_system,
        task=task,
        priority=priority,
        requires_risk_guard=requires_risk_guard,
        context_payload_hex=None if context_payload is None else context_payload.hex(),
        model_route_json=route_json,
        revision=revision,
    )


def _issue_task_record_snapshot(
    *,
    peer_system: str,
    task: HandoffTaskV1,
    priority: Priority,
    requires_risk_guard: bool,
    context_payload_hex: str | None,
    model_route_json: str,
    revision: int,
) -> TaskRecordV1:
    if (
        type(peer_system) is not str
        or _ID.fullmatch(peer_system) is None
        or type(task) is not HandoffTaskV1
        or type(priority) is not str
        or type(requires_risk_guard) is not bool
        or (context_payload_hex is not None and type(context_payload_hex) is not str)
        or type(model_route_json) is not str
        or type(revision) is not int
    ):
        raise TaskBridgeError("TASK_RECORD_INVALID", 503)
    return _RECORD_ISSUER.issue(
        TaskRecordV1(
            peer_system=peer_system,
            task=task,
            priority=priority,
            requires_risk_guard=requires_risk_guard,
            context_payload_hex=context_payload_hex,
            model_route_json=model_route_json,
            revision=revision,
        )
    )


def restore_task_record(
    *,
    peer_system: str,
    task: HandoffTaskV1,
    priority: Priority,
    requires_risk_guard: bool,
    context_payload_hex: str | None,
    model_route_json: str,
    revision: int,
) -> TaskRecordV1:
    """Validate and reissue a record restored from an untrusted store boundary.

    Durable stores must authenticate their row before calling this function.
    This function independently validates every serialized field before it
    creates a fresh, process-local task-record seal.
    """
    try:
        if (
            type(peer_system) is not str
            or _ID.fullmatch(peer_system) is None
            or type(task) is not HandoffTaskV1
            or type(priority) is not str
            or priority not in {"low", "normal", "high", "urgent"}
            or type(requires_risk_guard) is not bool
            or type(revision) is not int
            or not 1 <= revision <= MAX_UTC_NS
            or type(model_route_json) is not str
            or not model_route_json.isascii()
        ):
            raise ValueError

        task_data = task.model_dump(mode="json")
        validated_task = HandoffTaskV1.model_validate(task_data)
        task_bytes = canonical_json(validated_task.model_dump(mode="json"))
        if task_bytes != canonical_json(task_data):
            raise ValueError

        if context_payload_hex is not None:
            if (
                type(context_payload_hex) is not str
                or len(context_payload_hex) > MAX_CONTEXT_BYTES * 2
                or len(context_payload_hex) % 2 != 0
                or re.fullmatch(r"[0-9a-f]*", context_payload_hex, re.ASCII) is None
            ):
                raise ValueError
            payload_bytes = bytes.fromhex(context_payload_hex)

            def unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
                result: dict[str, object] = {}
                for key, value in pairs:
                    if key in result:
                        raise ValueError
                    result[key] = value
                return result

            payload = json.loads(
                payload_bytes.decode("ascii"), object_pairs_hook=unique_pairs
            )
            if type(payload) is not dict:
                raise ValueError
            if canonical_json(payload) != payload_bytes or len(payload_bytes) > MAX_CONTEXT_BYTES:
                raise ValueError
            _validate_task_context(validated_task.task_type, payload)
            if _contains_credential_value(payload):
                raise ValueError
            if hashlib.sha256(payload_bytes).hexdigest() != validated_task.context_hash:
                raise ValueError

        route_data = json.loads(model_route_json)
        if type(route_data) is not dict:
            raise ValueError
        for field_name in ("checked_tools", "checked_scopes", "trace_codes"):
            values = route_data.get(field_name)
            if type(values) is not list:
                raise ValueError
            route_data[field_name] = tuple(values)
        route = RouteDecisionV1.model_validate(route_data)
        route_bytes = canonical_json(route.model_dump(mode="json"))
        if route_bytes.decode("ascii") != model_route_json:
            raise ValueError
        if (
            route.agent_id != validated_task.created_by
            or route.task_type != validated_task.task_type
        ):
            raise ValueError

        return _issue_task_record_snapshot(
            peer_system=peer_system,
            task=validated_task,
            priority=priority,
            requires_risk_guard=requires_risk_guard,
            context_payload_hex=context_payload_hex,
            model_route_json=model_route_json,
            revision=revision,
        )
    except Exception:
        raise TaskBridgeError("TASK_STORE_UNAVAILABLE", 503) from None


def revise_task_record(*, prior: TaskRecordV1, task: HandoffTaskV1) -> TaskRecordV1:
    prior = require_task_record(prior)
    if type(task) is not HandoffTaskV1:
        raise TaskBridgeError("TASK_RECORD_INVALID", 503)
    return _issue_task_record_snapshot(
        peer_system=prior.peer_system,
        task=task,
        priority=prior.priority,
        requires_risk_guard=prior.requires_risk_guard,
        context_payload_hex=prior.context_payload_hex,
        model_route_json=prior.model_route_json,
        revision=prior.revision + 1,
    )


def require_task_record(value: object) -> TaskRecordV1:
    if type(value) is not TaskRecordV1:
        raise TaskBridgeError("TASK_STORE_UNAVAILABLE", 503)
    try:
        return require(value, _RECORD_ISSUER.tag)
    except Exception:
        raise TaskBridgeError("TASK_STORE_UNAVAILABLE", 503) from None


def issue_task_create_result(
    *, disposition: TaskCreateDisposition, record: TaskRecordV1 | None
) -> TaskCreateResultV1:
    if disposition not in ("created", "duplicate", "conflict"):
        raise TaskBridgeError("TASK_STORE_UNAVAILABLE", 503)
    if record is not None:
        record = require_task_record(record)
    elif disposition in ("created", "duplicate"):
        raise TaskBridgeError("TASK_STORE_UNAVAILABLE", 503)
    return _CREATE_RESULT_ISSUER.issue(
        TaskCreateResultV1(
            disposition=disposition,
            record_peer_system=None if record is None else record.peer_system,
            record_task=None if record is None else record.task,
            record_priority=None if record is None else record.priority,
            record_requires_risk_guard=None if record is None else record.requires_risk_guard,
            record_context_payload_hex=None if record is None else record.context_payload_hex,
            record_model_route_json=None if record is None else record.model_route_json,
            record_revision=None if record is None else record.revision,
        )
    )


def require_task_create_result(value: object) -> TaskCreateResultV1:
    if type(value) is not TaskCreateResultV1:
        raise TaskBridgeError("TASK_STORE_UNAVAILABLE", 503)
    try:
        result = require(value, _CREATE_RESULT_ISSUER.tag)
        record = result.record
        if result.disposition in ("created", "duplicate") and record is None:
            raise TaskBridgeError("TASK_STORE_UNAVAILABLE", 503)
        if record is not None:
            require_task_record(record)
        return result
    except Exception:
        raise TaskBridgeError("TASK_STORE_UNAVAILABLE", 503) from None


def issue_task_rate_decision(*, allowed: bool, retry_after_seconds: int = 0) -> TaskRateDecisionV1:
    return _RATE_RESULT_ISSUER.issue(
        TaskRateDecisionV1(allowed=allowed, retry_after_seconds=retry_after_seconds)
    )


def require_task_rate_decision(value: object) -> TaskRateDecisionV1:
    if type(value) is not TaskRateDecisionV1:
        raise TaskBridgeError("RATE_LIMITER_UNAVAILABLE", 503)
    try:
        return require(value, _RATE_RESULT_ISSUER.tag)
    except Exception:
        raise TaskBridgeError("RATE_LIMITER_UNAVAILABLE", 503) from None


def issue_task_audit_entry(
    *,
    trace_id: str,
    peer_system: str,
    actor_id: str,
    session_id: str,
    task_id: str | None,
    tool_id: str | None = None,
    action: str,
    reason_code: str,
    payload_hash: str,
    occurred_at_ns: int,
) -> TaskAuditEntryV1:
    return _AUDIT_ENTRY_ISSUER.issue(
        TaskAuditEntryV1(
            trace_id=trace_id,
            peer_system=peer_system,
            actor_id=actor_id,
            session_id=session_id,
            task_id=task_id,
            tool_id=tool_id,
            action=action,
            reason_code=reason_code,
            payload_hash=payload_hash,
            occurred_at_ns=occurred_at_ns,
        )
    )


def require_task_audit_entry(value: object) -> TaskAuditEntryV1:
    if type(value) is not TaskAuditEntryV1:
        raise TaskBridgeError("AUDIT_UNAVAILABLE", 503)
    try:
        return require(value, _AUDIT_ENTRY_ISSUER.tag)
    except Exception:
        raise TaskBridgeError("AUDIT_UNAVAILABLE", 503) from None


def issue_task_audit_receipt(
    *, event_id: str, event_hash: str, predecessor_hash: str, sequence: int
) -> TaskAuditReceiptV1:
    return _AUDIT_RECEIPT_ISSUER.issue(
        TaskAuditReceiptV1(
            event_id=event_id,
            event_hash=event_hash,
            predecessor_hash=predecessor_hash,
            sequence=sequence,
        )
    )


def require_task_audit_receipt(value: object) -> TaskAuditReceiptV1:
    if type(value) is not TaskAuditReceiptV1:
        raise TaskBridgeError("AUDIT_UNAVAILABLE", 503)
    try:
        return require(value, _AUDIT_RECEIPT_ISSUER.tag)
    except Exception:
        raise TaskBridgeError("AUDIT_UNAVAILABLE", 503) from None


def issue_task_audit_record(
    *, entry: TaskAuditEntryV1, receipt: TaskAuditReceiptV1
) -> TaskAuditRecordV1:
    require_task_audit_entry(entry)
    require_task_audit_receipt(receipt)
    return _AUDIT_RECORD_ISSUER.issue(
        TaskAuditRecordV1(
            trace_id=entry.trace_id,
            peer_system=entry.peer_system,
            actor_id=entry.actor_id,
            session_id=entry.session_id,
            task_id=entry.task_id,
            tool_id=entry.tool_id,
            action=entry.action,
            reason_code=entry.reason_code,
            payload_hash=entry.payload_hash,
            occurred_at_ns=entry.occurred_at_ns,
            event_id=receipt.event_id,
            event_hash=receipt.event_hash,
            predecessor_hash=receipt.predecessor_hash,
            sequence=receipt.sequence,
        )
    )


def require_task_audit_record(value: object) -> TaskAuditRecordV1:
    if type(value) is not TaskAuditRecordV1:
        raise TaskBridgeError("AUDIT_UNAVAILABLE", 503)
    try:
        record = require(value, _AUDIT_RECORD_ISSUER.tag)
        require_task_audit_entry(record.entry)
        require_task_audit_receipt(record.receipt)
        return record
    except Exception:
        raise TaskBridgeError("AUDIT_UNAVAILABLE", 503) from None


def issue_task_lifecycle_event(
    *,
    task_id: str,
    previous_state: str | None,
    new_state: str,
    occurred_at_ns: int,
    agent_session_id: str,
    reason_code: str,
    trace_id: str,
    event_id: str,
) -> TaskLifecycleEventV1:
    return _LIFECYCLE_ISSUER.issue(
        TaskLifecycleEventV1(
            task_id=task_id,
            previous_state=previous_state,
            new_state=new_state,
            occurred_at_ns=occurred_at_ns,
            agent_session_id=agent_session_id,
            reason_code=reason_code,
            trace_id=trace_id,
            event_id=event_id,
        )
    )


def require_task_lifecycle_event(value: object) -> TaskLifecycleEventV1:
    if type(value) is not TaskLifecycleEventV1:
        raise TaskBridgeError("EVENT_OUTBOX_UNAVAILABLE", 503)
    try:
        return require(value, _LIFECYCLE_ISSUER.tag)
    except Exception:
        raise TaskBridgeError("EVENT_OUTBOX_UNAVAILABLE", 503) from None


class BridgeHealthPort(Protocol):
    def snapshot(self, peer_system: str) -> BridgeHealthV1: ...


class SessionVerifierPort(Protocol):
    def verify(
        self, peer: OmegaPeerIdentityV1, session_id: str, *, now_ns: int
    ) -> AgentSessionV1 | None: ...


class ManifestPort(Protocol):
    def get_manifest(self, peer_system: str) -> CapabilityManifestV1: ...


class MCPAuthorizerPort(Protocol):
    def authorize_tool(
        self,
        *,
        peer: OmegaPeerIdentityV1,
        session: AgentSessionV1,
        manifest: CapabilityManifestV1,
        task: HandoffTaskV1,
        tool_id: str,
        action: MCPAction,
        params_hash: str,
        now_ns: int,
    ) -> PolicyDecisionV1: ...


class TaskStorePort(Protocol):
    def create(
        self,
        *,
        peer_system: str,
        record: TaskRecordV1,
        idempotency_key: str,
        request_digest: str,
        idempotency_expires_at_ns: int,
    ) -> TaskCreateResultV1: ...

    def get_task(self, peer_system: str, task_id: str) -> TaskRecordV1 | None: ...

    def replace_task(
        self,
        *,
        peer_system: str,
        task_id: str,
        expected_revision: int,
        record: TaskRecordV1,
    ) -> bool: ...

    def list_due(self, *, now_ns: int, limit: int) -> tuple[TaskRecordV1, ...]: ...


class AuditSinkPort(Protocol):
    def append(self, entry: TaskAuditEntryV1) -> TaskAuditReceiptV1: ...

    def read(
        self,
        *,
        peer_system: str,
        trace_id: str | None,
        task_id: str | None,
        agent_session_id: str | None,
        since_ns: int | None,
        until_ns: int | None,
        limit: int,
    ) -> tuple[TaskAuditRecordV1, ...]: ...


class EventOutboxPort(Protocol):
    def enqueue(self, event: TaskLifecycleEventV1) -> None: ...


class RateLimiterPort(Protocol):
    def consume(
        self, peer_system: str, *, now_ns: int, requests_per_second: int, burst: int
    ) -> TaskRateDecisionV1: ...


class ModelPolicyPort(Protocol):
    def route_task(
        self,
        *,
        task_type: str,
        agent_id: str,
        session_id: str,
        tool_allowlist: tuple[str, ...],
        context_hash: str,
        now_ns: int,
    ) -> RouteDecisionV1 | RouteDenialV1: ...


class OmegaTaskRuntime:
    """Required, fail-closed ports for the task router; never a local fake."""

    def __init__(
        self,
        *,
        bridge_health_port: BridgeHealthPort,
        session_verifier: SessionVerifierPort,
        manifest_port: ManifestPort,
        mcp_authorizer: MCPAuthorizerPort,
        task_store: TaskStorePort,
        audit_sink: AuditSinkPort,
        event_outbox: EventOutboxPort,
        rate_limiter: RateLimiterPort,
        model_policy: ModelPolicyPort,
        omega_policy: OmegaPolicyV1,
        clock: Callable[[], int],
    ) -> None:
        required_methods = (
            (bridge_health_port, "snapshot"),
            (session_verifier, "verify"),
            (manifest_port, "get_manifest"),
            (mcp_authorizer, "authorize_tool"),
            (task_store, "create"),
            (task_store, "get_task"),
            (task_store, "replace_task"),
            (task_store, "list_due"),
            (audit_sink, "append"),
            (audit_sink, "read"),
            (event_outbox, "enqueue"),
            (rate_limiter, "consume"),
            (model_policy, "route_task"),
        )
        if (
            type(omega_policy) is not OmegaPolicyV1
            or not callable(clock)
            or any(not callable(getattr(port, method, None)) for port, method in required_methods)
        ):
            raise TaskBridgeError("NOT_CONFIGURED", 503)
        self.bridge_health_port = bridge_health_port
        self.session_verifier = session_verifier
        self.manifest_port = manifest_port
        self.mcp_authorizer = mcp_authorizer
        self.task_store = task_store
        self.audit_sink = audit_sink
        self.event_outbox = event_outbox
        self.rate_limiter = rate_limiter
        self.model_policy = model_policy
        self.omega_policy = omega_policy
        self.clock = clock

    def now_ns(self) -> int:
        try:
            value = self.clock()
        except Exception:
            raise TaskBridgeError("CLOCK_UNAVAILABLE", 503) from None
        if type(value) is not int or not 0 <= value <= MAX_UTC_NS:
            raise TaskBridgeError("CLOCK_UNAVAILABLE", 503)
        return value

    def expire_due(self, limit: int) -> int:
        """Materialize due expiry/orphan transitions using one trusted clock read."""
        if type(limit) is not int or not 1 <= limit <= 500:
            raise TaskBridgeError("INVALID_SWEEP_LIMIT", 422)
        now_ns = self.now_ns()
        try:
            values = self.task_store.list_due(now_ns=now_ns, limit=limit)
        except Exception:
            raise TaskBridgeError("TASK_STORE_UNAVAILABLE", 503) from None
        if type(values) is not tuple or len(values) > limit:
            raise TaskBridgeError("TASK_STORE_UNAVAILABLE", 503)
        records: list[TaskRecordV1] = []
        keys: list[tuple[int, str]] = []
        seen: set[tuple[str, str]] = set()
        for value in values:
            record = require_task_record(value)
            if _ID.fullmatch(record.peer_system) is None:
                raise TaskBridgeError("TASK_STORE_UNAVAILABLE", 503)
            key = (record.peer_system, record.task.task_id)
            if key in seen:
                raise TaskBridgeError("TASK_STORE_UNAVAILABLE", 503)
            seen.add(key)
            records.append(record)
            keys.append((record.task.expires_at_ns, record.task.task_id))
        if keys != sorted(keys):
            raise TaskBridgeError("TASK_STORE_UNAVAILABLE", 503)

        changed_count = 0
        for record in records:
            task = record.task
            if task.state in ("succeeded", "failed", "cancelled", "expired"):
                continue
            if task.expires_at_ns <= now_ns:
                reason_code = "TASK_EXPIRED"
                next_state = "expired"
            else:
                if now_ns < task.created_at_ns + task.sla_ms * 1_000_000:
                    continue
                try:
                    health = self.bridge_health_port.snapshot(record.peer_system)
                except Exception:
                    continue
                if type(health) is not BridgeHealthV1 or health.peer_system != record.peer_system:
                    continue
                try:
                    bridge_decision = evaluate_bridge(
                        health, now_ns=now_ns, policy=self.omega_policy
                    )
                except Exception:
                    continue
                heartbeat_at = health.heartbeat_at_ns
                stale_after_sla = (
                    now_ns - heartbeat_at >= task.sla_ms * 1_000_000
                    if heartbeat_at is not None and heartbeat_at <= now_ns
                    else now_ns - task.created_at_ns >= task.sla_ms * 1_000_000
                )
                if bridge_decision.reason_code != "BRIDGE_DISCONNECTED" or not stale_after_sla:
                    continue
                reason_code = "ORPHANED_HEARTBEAT"
                next_state = "failed"

            next_task = HandoffTaskV1.model_validate({**task.model_dump(), "state": next_state})
            event_id = _lifecycle_event_id(
                task_id=task.task_id,
                previous_state=task.state,
                new_state=next_state,
                occurred_at_ns=now_ns,
                reason_code=reason_code,
            )
            trace_id = "trace_" + hashlib.sha256(event_id.encode("ascii")).hexdigest()
            attempt_ref = self._audit_sweep(
                record=record,
                trace_id=trace_id,
                action="task_lifecycle_attempt",
                reason_code=reason_code + "_ATTEMPT",
                now_ns=now_ns,
            )
            audited_task = HandoffTaskV1.model_validate(
                {**next_task.model_dump(), "audit_ref": attempt_ref}
            )
            updated = revise_task_record(prior=record, task=audited_task)
            try:
                did_change = self.task_store.replace_task(
                    peer_system=record.peer_system,
                    task_id=task.task_id,
                    expected_revision=record.revision,
                    record=updated,
                )
            except Exception:
                raise TaskBridgeError("TASK_STORE_UNAVAILABLE", 503) from None
            if did_change is not True:
                continue
            self._audit_sweep(
                record=updated,
                trace_id=trace_id,
                action="task_lifecycle",
                reason_code=reason_code,
                now_ns=now_ns,
            )
            event = issue_task_lifecycle_event(
                task_id=task.task_id,
                previous_state=task.state,
                new_state=next_state,
                occurred_at_ns=now_ns,
                agent_session_id="omega.sweeper",
                reason_code=reason_code,
                trace_id=trace_id,
                event_id=event_id,
            )
            try:
                self.event_outbox.enqueue(require_task_lifecycle_event(event))
            except Exception:
                raise TaskBridgeError("EVENT_OUTBOX_UNAVAILABLE", 503) from None
            changed_count += 1
        return changed_count

    def _audit_sweep(
        self,
        *,
        record: TaskRecordV1,
        trace_id: str,
        action: str,
        reason_code: str,
        now_ns: int,
    ) -> str:
        try:
            entry = issue_task_audit_entry(
                trace_id=trace_id,
                peer_system=record.peer_system,
                actor_id="omega.sweeper",
                session_id="omega.sweeper",
                task_id=record.task.task_id,
                action=action,
                reason_code=reason_code,
                payload_hash=hashlib.sha256(
                    canonical_json(
                        {
                            "task_id": record.task.task_id,
                            "revision": record.revision,
                            "state": record.task.state,
                        }
                    )
                ).hexdigest(),
                occurred_at_ns=now_ns,
            )
            receipt = require_task_audit_receipt(self.audit_sink.append(entry))
        except Exception:
            raise TaskBridgeError("AUDIT_UNAVAILABLE", 503) from None
        return receipt.event_id


def verify_route_result(value: object) -> RouteDecisionV1:
    """Require an AGENT-003 issued route; denial stays content-free."""
    if type(value) is RouteDecisionV1:
        try:
            return require_route_decision(value)
        except Exception:
            raise TaskBridgeError("MODEL_POLICY_DENIED", 403) from None
    if type(value) is RouteDenialV1 and verify_route_denial(value):
        raise TaskBridgeError("MODEL_POLICY_DENIED", 403)
    raise TaskBridgeError("MODEL_POLICY_UNAVAILABLE", 503)


__all__ = [
    "IDEMPOTENCY_RETENTION_NS",
    "MAX_CONTEXT_BYTES",
    "MAX_QUESTION_CHARS",
    "MAX_SOURCE_REFS_CHARS",
    "MAX_SOURCE_REF_CHARS",
    "MAX_SOURCE_REF_COUNT",
    "OMEGA_TASK_TYPES_V1",
    "AuditSinkPort",
    "BridgeHealthPort",
    "EventOutboxPort",
    "HandoffRequestV1",
    "MCPAction",
    "MCPAuthorizerPort",
    "ManifestPort",
    "ModelPolicyPort",
    "OmegaTaskRuntime",
    "RateLimiterPort",
    "SessionVerifierPort",
    "TaskAuditEntryV1",
    "TaskAuditReceiptV1",
    "TaskAuditRecordV1",
    "TaskBridgeError",
    "TaskCreateResultV1",
    "TaskLifecycleEventV1",
    "TaskRateDecisionV1",
    "TaskRecordV1",
    "TaskStorePort",
    "issue_task_audit_entry",
    "issue_task_audit_receipt",
    "issue_task_audit_record",
    "issue_task_create_result",
    "issue_task_lifecycle_event",
    "issue_task_rate_decision",
    "issue_task_record",
    "require_task_audit_entry",
    "require_task_audit_receipt",
    "require_task_audit_record",
    "require_task_create_result",
    "require_task_lifecycle_event",
    "require_task_rate_decision",
    "require_task_record",
    "restore_task_record",
    "revise_task_record",
]
