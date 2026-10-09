"""Strict, content-safe HTTP request and response records for MCP-003."""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from leviathan_core.text.safe_label import is_safe_display_label


class MCPHTTPModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class AgentRegistrationRequestV1(MCPHTTPModel):
    version: Literal["1"]
    agent_id: str = Field(min_length=1, max_length=128)
    display_label: str = Field(min_length=1, max_length=40)
    origin: Literal["LEVIATHAN", "OMEGA"]
    attestation: str = Field(min_length=1, max_length=8192)

    @field_validator("display_label")
    @classmethod
    def safe_display_label(cls, value: str) -> str:
        if not is_safe_display_label(value):
            raise ValueError("display label invalid")
        return value


class SessionCreateRequestV1(MCPHTTPModel):
    version: Literal["1"]
    agent_id: str = Field(min_length=1, max_length=128)
    session_id: str = Field(min_length=1, max_length=128)
    expires_at_ns: int = Field(ge=0)
    quota: int = Field(ge=0, le=1_000_000)
    scope_elevated: bool = False


class ActionRequestHTTPV1(MCPHTTPModel):
    version: Literal["1"]
    org_id: str = Field(min_length=1, max_length=128)
    desk_id: str = Field(min_length=1, max_length=128)
    agent_id: str = Field(min_length=1, max_length=128)
    session_id: str = Field(min_length=1, max_length=128)
    environment: Literal["paper", "demo", "live"]
    action_idempotency_key: str = Field(min_length=1, max_length=128)
    tool_id: str = Field(min_length=1, max_length=128)
    resource: str = Field(min_length=1, max_length=256)
    scope: str = Field(min_length=1, max_length=128)
    capability: Literal["read", "create", "update", "delete", "publish", "execute"]
    timestamp_ns: int = Field(ge=0)
    notional: str | None = None
    leverage: str | None = None
    venue: str | None = None
    symbol: str | None = None
    order_type: str | None = None
    egress_domain: str | None = None
    is_config_change: bool = False


class DryRunRequestV1(MCPHTTPModel):
    version: Literal["1"]
    action: ActionRequestHTTPV1


class OverrideRequestV1(MCPHTTPModel):
    version: Literal["1"]
    approval_id: str = Field(min_length=1, max_length=128)
    session_id: str = Field(min_length=1, max_length=128)
    action_key: str | None = Field(default=None, max_length=128)
    kind: Literal["approve", "reject", "scope_update", "config_change", "halt", "revoke"]
    target_scope: Literal["session", "all"] = "session"
    expires_at_ns: int = Field(ge=0)
    reason_code: str = Field(min_length=1, max_length=64)

    @field_validator("reason_code")
    @classmethod
    def safe_reason_code(cls, value: str) -> str:
        if re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", value, re.ASCII) is None:
            raise ValueError("reason code invalid")
        return value


class HaltRequestV1(MCPHTTPModel):
    version: Literal["1"]
    reason_code: str = Field(min_length=1, max_length=64)
    scope: Literal["all", "session"]
    session_id: str | None = Field(default=None, max_length=128)

    @field_validator("reason_code")
    @classmethod
    def safe_reason_code(cls, value: str) -> str:
        if re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", value, re.ASCII) is None:
            raise ValueError("reason code invalid")
        return value


class ToolGrantRequestV1(MCPHTTPModel):
    version: Literal["1"]
    session_id: str = Field(min_length=1, max_length=128)
    tool_id: str = Field(min_length=1, max_length=128)
    scope_subset: str = Field(min_length=1, max_length=128)
    ttl_ns: int = Field(gt=0)


class ErrorResponseV1(MCPHTTPModel):
    version: Literal["1"] = "1"
    code: str


class DecisionResponseV1(MCPHTTPModel):
    version: Literal["1"] = "1"
    allowed: bool
    effect_allowed: bool
    dry_run: bool = False
    reason_codes: tuple[str, ...]
    action_id: str | None = None
    state: str | None = None


class AuditPageV1(MCPHTTPModel):
    version: Literal["1"] = "1"
    events: tuple[dict[str, object], ...]
    next_cursor: int | None
    chain_valid: bool
