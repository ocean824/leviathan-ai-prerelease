"""Pure MCP-002 control records. Issuance is bound to exact object identity.

The records model a transaction's contents; storage and transport belong to
later contracts. No caller-provided flag is itself an attestation or approval.
"""

from __future__ import annotations

import re
import weakref
from dataclasses import dataclass
from typing import Any, Final, Literal, Self, TypeVar

from pydantic import Field, field_validator, model_validator

from leviathan_core.seal import Issuer, SealedModel

CONTROL_VERSION: Final[Literal["1"]] = "1"
UNKNOWN_SUBJECT: Final[Literal["UNKNOWN_SUBJECT"]] = "UNKNOWN_SUBJECT"
MAX_UTC_NS = 253_402_300_799_999_999_999
QUARANTINE_WINDOW_NS = 600_000_000_000
EFFECT_GATE_TTL_NS = 30_000_000_000

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)
_HEX = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_APPROVAL_ISSUER = Issuer("mcp002.approval.v1")
_ATTESTATION_ISSUER = Issuer("mcp002.attestation.v1")
_SNAPSHOT_ISSUER = Issuer("mcp002.snapshot.v1")
_GATE_ISSUER = Issuer("mcp002.effect_gate.v1")
_RECEIPT_ISSUER = Issuer("mcp002.execution_receipt.v1")
_NO_EFFECT_ISSUER = Issuer("mcp002.no_effect.v1")
_RecordT = TypeVar("_RecordT", bound="_ControlModel")


class ControlError(ValueError):
    """Content-free service failure with a stable code."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _id(value: str) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise ControlError("ID_INVALID")
    return value


def _hex(value: str) -> str:
    if _HEX.fullmatch(value) is None:
        raise ControlError("DIGEST_INVALID")
    return value


class _ControlModel(SealedModel):
    """Strict, frozen, extra-forbid, content-free validation base."""


class AgentRegistrationV1(_ControlModel):
    version: Literal["1"]
    org_id: str
    desk_id: str
    agent_id: str
    origin: Literal["LEVIATHAN", "OMEGA"]
    status: Literal["active", "quarantined", "blocked"]
    attestation_id: str
    attestation_expires_at_ns: int = Field(ge=0, le=MAX_UTC_NS, strict=True)
    registered_at_ns: int = Field(ge=0, le=MAX_UTC_NS, strict=True)

    _ids = field_validator("org_id", "desk_id", "agent_id", "attestation_id")(_id)


class AttestationEvidenceV1(_ControlModel):
    """Signature verification result issued by a trusted attestation adapter."""

    version: Literal["1"]
    attestation_id: str
    org_id: str
    desk_id: str
    agent_id: str
    origin: Literal["LEVIATHAN", "OMEGA"]
    signature_digest: str
    issued_at_ns: int = Field(ge=0, le=MAX_UTC_NS, strict=True)
    expires_at_ns: int = Field(ge=0, le=MAX_UTC_NS, strict=True)

    _ids = field_validator("attestation_id", "org_id", "desk_id", "agent_id")(_id)
    _signature = field_validator("signature_digest")(_hex)

    @classmethod
    def _from_trusted_adapter(cls, **fields: Any) -> Self:
        evidence = cls.model_validate(fields)
        return _ATTESTATION_ISSUER.issue(evidence)

    @property
    def trusted_by_adapter(self) -> bool:
        return type(self) is AttestationEvidenceV1 and _ATTESTATION_ISSUER.issued_here(self)


class ToolSessionV1(_ControlModel):
    version: Literal["1"]
    org_id: str
    desk_id: str
    agent_id: str
    session_id: str
    state: Literal["pending_approval", "running", "paused", "revoked", "completed"]
    scope_elevated: bool = Field(strict=True)
    expires_at_ns: int = Field(ge=0, le=MAX_UTC_NS, strict=True)
    created_at_ns: int = Field(ge=0, le=MAX_UTC_NS, strict=True)
    quota_remaining: int = Field(ge=0, strict=True)

    _ids = field_validator("org_id", "desk_id", "agent_id", "session_id")(_id)


class ActionStateV1(_ControlModel):
    version: Literal["1"]
    action_id: str
    org_id: str
    agent_id: str
    session_id: str
    tool_id: str
    idempotency_key: str
    payload_digest: str
    state: Literal[
        "approved",
        "rejected",
        "dry_run",
        "revoked",
        "effect_authorized",
        "effect_unknown",
        "executed",
        "failed",
    ]
    reason_codes: tuple[str, ...]
    created_at_ns: int = Field(ge=0, le=MAX_UTC_NS, strict=True)
    decision_event_id: str
    effect_id: str | None = None
    postcondition_digest: str | None = None
    gate_event_id: str | None = None
    gate_expires_at_ns: int | None = Field(default=None, ge=0, le=MAX_UTC_NS, strict=True)
    human_approved: bool = Field(default=False, strict=True)

    _ids = field_validator(
        "action_id", "org_id", "agent_id", "session_id", "tool_id", "idempotency_key"
    )(_id)
    _digests = field_validator("payload_digest", "decision_event_id")(_hex)

    @field_validator("effect_id", "postcondition_digest", "gate_event_id")
    @classmethod
    def optional_digest(cls, value: str | None) -> str | None:
        return None if value is None else _hex(value)


class EffectGateV1(_ControlModel):
    """A pre-effect decision; it is never an execution or order permit."""

    version: Literal["1"]
    action_id: str
    effect_allowed: bool = Field(strict=True)
    reason_codes: tuple[str, ...]
    evaluated_at_ns: int = Field(ge=0, le=MAX_UTC_NS, strict=True)
    expires_at_ns: int = Field(ge=0, le=MAX_UTC_NS, strict=True)
    audit_event_id: str

    _action_id = field_validator("action_id")(_id)
    _audit_id = field_validator("audit_event_id")(_hex)

    @property
    def issued_by_control(self) -> bool:
        return type(self) is EffectGateV1 and _GATE_ISSUER.issued_here(self)


class ExecutionReceiptV1(_ControlModel):
    """Postcondition report issued by a trusted external executor adapter."""

    version: Literal["1"]
    effect_id: str
    action_id: str
    gate_event_id: str
    executor_id: str
    postcondition_ok: bool = Field(strict=True)
    postcondition_digest: str
    executed_at_ns: int = Field(ge=0, le=MAX_UTC_NS, strict=True)

    _ids = field_validator("action_id", "executor_id")(_id)
    _digests = field_validator("effect_id", "gate_event_id", "postcondition_digest")(_hex)

    @classmethod
    def _from_trusted_adapter(cls, **fields: Any) -> Self:
        receipt = cls.model_validate(fields)
        return _RECEIPT_ISSUER.issue(receipt)

    @property
    def trusted_by_adapter(self) -> bool:
        return type(self) is ExecutionReceiptV1 and _RECEIPT_ISSUER.issued_here(self)


class NoEffectEvidenceV1(_ControlModel):
    """Executor attestation that a specific expired gate never started an effect."""

    version: Literal["1"]
    action_id: str
    gate_event_id: str
    executor_id: str
    executor_state_digest: str
    observed_at_ns: int = Field(ge=0, le=MAX_UTC_NS, strict=True)

    _ids = field_validator("action_id", "executor_id")(_id)
    _digests = field_validator("gate_event_id", "executor_state_digest")(_hex)

    @classmethod
    def _from_trusted_adapter(cls, **fields: Any) -> Self:
        evidence = cls.model_validate(fields)
        return _NO_EFFECT_ISSUER.issue(evidence)

    @property
    def trusted_by_adapter(self) -> bool:
        return type(self) is NoEffectEvidenceV1 and _NO_EFFECT_ISSUER.issued_here(self)


class ApprovalEvidenceV1(_ControlModel):
    """Verified human instruction. Only the trusted adapter issues this value."""

    version: Literal["1"]
    approval_id: str
    org_id: str
    desk_id: str
    session_id: str
    action_key: str | None
    actor_id: str
    actor_role: Literal["Operator", "RiskOfficer"]
    kind: Literal["approve", "reject", "scope_update", "config_change", "halt", "revoke"]
    target_scope: Literal["session", "all"]
    issued_at_ns: int = Field(ge=0, le=MAX_UTC_NS, strict=True)
    expires_at_ns: int = Field(ge=0, le=MAX_UTC_NS, strict=True)

    _ids = field_validator("approval_id", "org_id", "desk_id", "session_id", "actor_id")(_id)

    @field_validator("action_key")
    @classmethod
    def valid_action_key(cls, value: str | None) -> str | None:
        return None if value is None else _id(value)

    @classmethod
    def _from_trusted_adapter(cls, **fields: Any) -> Self:
        evidence = cls.model_validate(fields)
        return _APPROVAL_ISSUER.issue(evidence)

    @property
    def trusted_by_adapter(self) -> bool:
        return type(self) is ApprovalEvidenceV1 and _APPROVAL_ISSUER.issued_here(self)


class ApprovalRecordV1(_ControlModel):
    version: Literal["1"]
    approval_id: str
    org_id: str
    desk_id: str
    session_id: str
    action_key: str | None
    actor_id: str
    actor_role: Literal["Operator", "RiskOfficer"]
    kind: Literal["approve", "reject", "scope_update", "config_change", "halt", "revoke"]
    target_scope: Literal["session", "all"]
    expires_at_ns: int = Field(ge=0, le=MAX_UTC_NS, strict=True)

    _ids = field_validator("approval_id", "org_id", "desk_id", "session_id", "actor_id")(_id)


class ViolationRecordV1(_ControlModel):
    version: Literal["1"]
    org_id: str
    agent_id: str
    reason_code: str
    recorded_at_ns: int = Field(ge=0, le=MAX_UTC_NS, strict=True)

    _ids = field_validator("org_id", "agent_id", "reason_code")(_id)


class AuditEventV1(_ControlModel):
    version: Literal["1", "2"]
    event_id: str
    sequence: int = Field(ge=0, strict=True)
    org_id: str
    agent_id: str
    session_id: str | None
    action_id: str | None
    kind: str
    reason_codes: tuple[str, ...]
    recorded_at_ns: int = Field(ge=0, le=MAX_UTC_NS, strict=True)
    predecessor_hash: str
    event_hash: str
    actor_principal_id: str | None = None
    subject_id: str | None = None
    dry_run: bool | None = Field(default=None, strict=True)

    _ids = field_validator("org_id", "agent_id", "kind")(_id)
    _digests = field_validator("event_id", "predecessor_hash", "event_hash")(_hex)

    @field_validator("actor_principal_id", "subject_id")
    @classmethod
    def valid_optional_audit_ids(cls, value: str | None) -> str | None:
        return None if value is None else _id(value)

    @model_validator(mode="after")
    def versioned_actor_fields(self) -> AuditEventV1:
        if self.version == "1" and (
            self.actor_principal_id is not None
            or self.subject_id is not None
            or self.dry_run is not None
        ):
            raise ControlError("AUDIT_INPUT_INVALID")
        if self.version == "2" and (self.actor_principal_id is None or self.subject_id is None):
            raise ControlError("AUDIT_INPUT_INVALID")
        return self


class ControlSnapshotV1(_ControlModel):
    """Small sealed root; immutable control rows live in an identity-bound registry."""

    version: Literal["1"]
    revision: int = Field(ge=0, strict=True)
    head_event_id: str
    halted_org_ids: tuple[str, ...]
    global_halt: bool = Field(strict=True)

    _head_digest = field_validator("head_event_id")(_hex)
    _halted_orgs = field_validator("halted_org_ids")(
        lambda value: tuple(_id(item) for item in value)
    )

    @property
    def agents(self) -> tuple[AgentRegistrationV1, ...]:
        return _public_rows(_require_payload(self).agents)

    @property
    def sessions(self) -> tuple[ToolSessionV1, ...]:
        return _public_rows(_require_payload(self).sessions)

    @property
    def actions(self) -> tuple[ActionStateV1, ...]:
        return _public_rows(_require_payload(self).actions)

    @property
    def approvals(self) -> tuple[ApprovalRecordV1, ...]:
        return _public_rows(_require_payload(self).approvals)

    @property
    def violations(self) -> tuple[ViolationRecordV1, ...]:
        return _public_rows(_require_payload(self).violations)

    @property
    def audit_events(self) -> tuple[AuditEventV1, ...]:
        return _public_rows(_require_payload(self).audit_events)

    @property
    def outbox_event_ids(self) -> tuple[str, ...]:
        return _require_payload(self).outbox_event_ids

    @property
    def delivered_event_ids(self) -> tuple[str, ...]:
        return _require_payload(self).delivered_event_ids


@dataclass(frozen=True, slots=True)
class _SnapshotPayload:
    agents: tuple[AgentRegistrationV1, ...] = ()
    sessions: tuple[ToolSessionV1, ...] = ()
    actions: tuple[ActionStateV1, ...] = ()
    approvals: tuple[ApprovalRecordV1, ...] = ()
    violations: tuple[ViolationRecordV1, ...] = ()
    audit_events: tuple[AuditEventV1, ...] = ()
    outbox_event_ids: tuple[str, ...] = ()
    delivered_event_ids: tuple[str, ...] = ()


_SNAPSHOT_PAYLOADS: dict[
    int, tuple[weakref.ReferenceType[ControlSnapshotV1], _SnapshotPayload]
] = {}


def _public_rows(rows: tuple[_RecordT, ...]) -> tuple[_RecordT, ...]:
    # A caller can force-mutate a frozen model. Never hand out registry rows.
    return tuple(type(row).model_validate(row.model_dump(mode="python")) for row in rows)


def _issue_snapshot(
    payload: _SnapshotPayload, *, halted_org_ids: tuple[str, ...] = ()
) -> ControlSnapshotV1:
    from .audit_chain import GENESIS_HASH

    head = payload.audit_events[-1].event_hash if payload.audit_events else GENESIS_HASH
    snapshot = _SNAPSHOT_ISSUER.issue(
        ControlSnapshotV1(
            version=CONTROL_VERSION,
            revision=len(payload.audit_events),
            head_event_id=head,
            halted_org_ids=halted_org_ids,
            global_halt=False,
        )
    )
    identity = id(snapshot)

    def _retire(ref: weakref.ReferenceType[ControlSnapshotV1]) -> None:
        entry = _SNAPSHOT_PAYLOADS.get(identity)
        if entry is not None and entry[0] is ref:
            del _SNAPSHOT_PAYLOADS[identity]

    owner_ref = weakref.ref(snapshot, _retire)
    _SNAPSHOT_PAYLOADS[identity] = (owner_ref, payload)
    return snapshot


def _issue_gate(gate: EffectGateV1) -> EffectGateV1:
    return _GATE_ISSUER.issue(gate)


def _require_snapshot(snapshot: object) -> ControlSnapshotV1:
    if type(snapshot) is not ControlSnapshotV1 or not _SNAPSHOT_ISSUER.issued_here(snapshot):
        raise ControlError("STATE_UNTRUSTED")
    return snapshot


def _require_payload(snapshot: object) -> _SnapshotPayload:
    issued = _require_snapshot(snapshot)
    entry = _SNAPSHOT_PAYLOADS.get(id(issued))
    if entry is None or entry[0]() is not issued:
        raise ControlError("STATE_UNTRUSTED")
    payload = entry[1]
    from .audit_chain import GENESIS_HASH

    head = payload.audit_events[-1].event_hash if payload.audit_events else GENESIS_HASH
    if issued.revision != len(payload.audit_events) or issued.head_event_id != head:
        raise ControlError("STATE_UNTRUSTED")
    return payload
