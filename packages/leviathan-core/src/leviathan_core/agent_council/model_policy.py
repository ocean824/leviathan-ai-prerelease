"""Versioned agent routing policies, requests and trusted budget snapshots."""

from __future__ import annotations

from decimal import Decimal
from typing import ClassVar, Literal, Protocol

from pydantic import Field, StrictInt, field_validator, model_validator

from leviathan_core.mcp_control.policy_models import PolicyDecisionV1
from leviathan_core.numeric import parse_decimal
from leviathan_core.security.authz_models import AuthorizationDecisionV1

from .model_registry import (
    MAX_COST_USD,
    MAX_ELAPSED_NS,
    MAX_NS,
    MAX_TOKENS,
    BudgetClass,
    Modality,
    PrivacyClass,
    Provider,
    QualityClass,
    _identifier,
    _RouteModel,
    _schema,
    _unique,
    _version,
)

Environment = Literal["development", "live"]
PriorOutcome = Literal["provider_failure", "invalid_response"]


class ScopePrivacyV1(_RouteModel):
    scope: str
    min_privacy_class: PrivacyClass

    @field_validator("scope")
    @classmethod
    def valid_scope(cls, value: str) -> str:
        return _identifier(value)


class AgentModelPolicyV1(_RouteModel):
    """One agent's allowed routes and non-loosenable bounded spend."""

    _error_code: ClassVar[str] = "POLICY_OUT_OF_BOUNDS"

    version: str
    agent_id: str
    project_id: Literal["leviathan-ai"]
    environment: Environment
    allowed_aliases: tuple[str, ...] = Field(min_length=1, max_length=64)
    allowed_providers: tuple[Provider, ...] = Field(min_length=1, max_length=5)
    allowed_tools: tuple[str, ...] = Field(default=(), max_length=64)
    allowed_data_scopes: tuple[str, ...] = Field(min_length=1, max_length=64)
    scope_privacy_classes: tuple[ScopePrivacyV1, ...] = Field(min_length=1, max_length=64)
    allowed_output_schemas: tuple[str, ...] = Field(min_length=1, max_length=64)
    allowed_regions: tuple[str, ...] = Field(min_length=1, max_length=32)
    fallback_aliases: tuple[str, ...] = Field(default=(), max_length=64)
    min_quality_class: QualityClass
    min_privacy_class: PrivacyClass
    max_latency_class: BudgetClass
    max_cost_class: BudgetClass
    max_context_tokens: StrictInt = Field(gt=0, le=MAX_TOKENS)
    max_calls: StrictInt = Field(gt=0, le=1000)
    max_tokens: StrictInt = Field(gt=0, le=MAX_TOKENS)
    max_elapsed_ns: StrictInt = Field(gt=0, le=MAX_ELAPSED_NS)
    max_cost_usd: Decimal
    max_attempts: StrictInt = Field(gt=0, le=16)

    @field_validator("version")
    @classmethod
    def valid_version(cls, value: str) -> str:
        return _version(value)

    @field_validator("agent_id")
    @classmethod
    def valid_agent(cls, value: str) -> str:
        return _identifier(value)

    @field_validator(
        "allowed_aliases", "allowed_tools", "allowed_data_scopes", "allowed_regions",
        "fallback_aliases",
    )
    @classmethod
    def valid_identifiers(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        for value in values:
            _identifier(value)
        _unique(values)
        return values

    @field_validator("allowed_output_schemas")
    @classmethod
    def valid_schemas(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        for value in values:
            _schema(value)
        _unique(values)
        return values

    @field_validator("max_cost_usd", mode="before")
    @classmethod
    def valid_cost(cls, value: object) -> Decimal:
        return parse_decimal(value, field="max_cost_usd", min_value="0", max_value=MAX_COST_USD)

    @model_validator(mode="after")
    def coherent(self) -> AgentModelPolicyV1:
        _unique(self.allowed_providers)
        if not set(self.fallback_aliases).issubset(self.allowed_aliases):
            raise ValueError("fallback aliases exceed policy")
        scope_names = tuple(item.scope for item in self.scope_privacy_classes)
        _unique(scope_names)
        if set(scope_names) != set(self.allowed_data_scopes):
            raise ValueError("privacy classification must cover each scope")
        if self.max_attempts > self.max_calls:
            raise ValueError("attempt limit exceeds call budget")
        return self


class AIRequestV1(_RouteModel):
    """Untrusted task requirements; no authority or credential claim fields."""

    _error_code: ClassVar[str] = "REQUEST_INVALID"

    request_id: str
    agent_id: str
    project_id: Literal["leviathan-ai"]
    environment: Environment
    alias: str
    task_type: str
    data_scope: str
    modality: Modality
    output_schema: str
    required_tools: tuple[str, ...] = Field(default=(), max_length=64)
    input_tokens: StrictInt = Field(gt=0, le=MAX_TOKENS)
    output_tokens: StrictInt = Field(gt=0, le=MAX_TOKENS)
    min_quality_class: QualityClass
    privacy_class: PrivacyClass
    max_latency_class: BudgetClass
    prompt_version: str
    at_ns: StrictInt = Field(gt=0, le=MAX_NS)
    region: str

    @field_validator(
        "request_id", "agent_id", "alias", "task_type", "data_scope", "region",
    )
    @classmethod
    def valid_ids(cls, value: str) -> str:
        return _identifier(value)

    @field_validator("output_schema")
    @classmethod
    def valid_schema(cls, value: str) -> str:
        return _schema(value)

    @field_validator("prompt_version")
    @classmethod
    def valid_prompt(cls, value: str) -> str:
        return _version(value)

    @field_validator("required_tools")
    @classmethod
    def valid_tools(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        for value in values:
            _identifier(value)
        _unique(values)
        return values


class RouteUsageV1(_RouteModel):
    """Injected usage snapshot; the trust port must verify its provenance."""

    _error_code: ClassVar[str] = "USAGE_INVALID"

    snapshot_revision: StrictInt = Field(gt=0, le=MAX_NS)
    calls_used: StrictInt = Field(ge=0, le=1000)
    tokens_used: StrictInt = Field(ge=0, le=MAX_TOKENS)
    elapsed_ns: StrictInt = Field(ge=0, le=MAX_ELAPSED_NS)
    cost_spent_usd: Decimal
    attempted_entry_ids: tuple[str, ...] = Field(default=(), max_length=16)
    prior_outcome: PriorOutcome | None = None

    @field_validator("cost_spent_usd", mode="before")
    @classmethod
    def valid_cost(cls, value: object) -> Decimal:
        return parse_decimal(value, field="cost_spent_usd", min_value="0", max_value=MAX_COST_USD)

    @field_validator("attempted_entry_ids")
    @classmethod
    def valid_attempts(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        for value in values:
            _identifier(value)
        _unique(values)
        return values

    @model_validator(mode="after")
    def coherent(self) -> RouteUsageV1:
        if bool(self.attempted_entry_ids) != (self.prior_outcome is not None):
            raise ValueError("prior failure evidence invalid")
        if self.calls_used < len(self.attempted_entry_ids):
            raise ValueError("attempt count exceeds calls")
        return self


class RouteTrustPort(Protocol):
    """Injected SEC-002/MCP/binding facts; no secret resolution or provider call."""

    def principal_decision(self, request: AIRequestV1) -> AuthorizationDecisionV1: ...

    def tool_decision(self, request: AIRequestV1, tool_name: str) -> PolicyDecisionV1: ...

    def evaluation_time_ns(self, request: AIRequestV1) -> int: ...

    def usage_is_verified(self, request: AIRequestV1, usage: RouteUsageV1) -> bool: ...

    def credential_is_bound(self, request: AIRequestV1, credential_ref: str) -> bool: ...


__all__ = [
    "AIRequestV1",
    "AgentModelPolicyV1",
    "Environment",
    "PriorOutcome",
    "RouteTrustPort",
    "RouteUsageV1",
    "ScopePrivacyV1",
]
