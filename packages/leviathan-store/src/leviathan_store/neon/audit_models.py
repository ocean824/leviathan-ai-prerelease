"""Immutable, redacted audit values for the fake-Neon boundary."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from leviathan_core.seal import SealedModel


class AuditActionV1(StrEnum):
    AUTHN_DECISION = "AUTHN_DECISION"
    AUTHZ_DECISION = "AUTHZ_DECISION"
    SECRET_ACCESS = "SECRET_ACCESS"
    KEY_ROTATION = "KEY_ROTATION"
    POLICY_EVALUATION = "POLICY_EVALUATION"
    RISK_LOCK = "RISK_LOCK"
    CONFIG_CHANGE = "CONFIG_CHANGE"
    ORDER_RISK = "ORDER_RISK"


class AuditDecisionV1(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    RECORDED = "RECORDED"


class AuditReasonCodeV1(StrEnum):
    AUTHORIZED = "AUTHORIZED"
    NOT_AUTHORIZED = "NOT_AUTHORIZED"
    ROTATED = "ROTATED"
    REVOKED = "REVOKED"
    UPDATED = "UPDATED"
    LOCKED = "LOCKED"
    UNLOCKED = "UNLOCKED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"


class AuditDiffFieldV1(StrEnum):
    ROLE = "role"
    LICENSE_STATUS = "license_status"
    SEAT_COUNT = "seat_count"
    POLICY_VERSION = "policy_version"
    RISK_LOCK_STATE = "risk_lock_state"
    CONFIG_VERSION = "config_version"


class _InputModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True, hide_input_in_errors=True)


class AuditDiffV1(_InputModel):
    """A change summary containing hashes only, never before/after values."""

    field: AuditDiffFieldV1
    before_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    after_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class AuditEventV1(_InputModel):
    """Validated append input; tenant and actor identity come from trusted context."""

    action: AuditActionV1
    decision: AuditDecisionV1
    reason_code: AuditReasonCodeV1
    target_ref: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    diff: tuple[AuditDiffV1, ...] = ()
    correlation_id: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    trace_id: str | None = Field(default=None, pattern=r"^[A-Fa-f0-9]{32}$")

    @field_validator("diff")
    @classmethod
    def _unique_diff_fields(cls, value: tuple[AuditDiffV1, ...]) -> tuple[AuditDiffV1, ...]:
        if len({item.field for item in value}) != len(value):
            raise ValueError("invalid audit diff")
        return value


class AuditEntryV1(SealedModel):
    """Issued immutable chain entry. Actor and target identities are references."""

    schema_version: Literal[1] = 1
    entry_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    org_id: str
    env: str
    sequence: int = Field(ge=1)
    recorded_at: datetime
    recorded_at_ns: int = Field(ge=0)
    actor_ref: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    actor_project_id: str
    actor_roles: tuple[str, ...]
    action: AuditActionV1
    decision: AuditDecisionV1
    reason_code: AuditReasonCodeV1
    target_ref: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    diff: tuple[AuditDiffV1, ...]
    correlation_id: str | None
    trace_id: str | None
    previous_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    entry_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class AuditPageV1:
    """A tenant-scoped page; each included entry keeps its own seal."""

    org_id: str
    entries: tuple[AuditEntryV1, ...]
    next_cursor: str | None
    chain_tip: str


class AuditChainVerificationV1(SealedModel):
    """Content-free result of verifying a complete fake chain and checkpoint."""

    org_id: str
    valid: bool
    entries_checked: int = Field(ge=0)
    chain_tip: str
    failure_code: Literal["CHAIN_INVALID"] | None


__all__ = [
    "AuditActionV1",
    "AuditChainVerificationV1",
    "AuditDecisionV1",
    "AuditDiffFieldV1",
    "AuditDiffV1",
    "AuditEntryV1",
    "AuditEventV1",
    "AuditPageV1",
    "AuditReasonCodeV1",
]
