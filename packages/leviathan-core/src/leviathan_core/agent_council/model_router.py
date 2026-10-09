"""Side-effect-free BYO model selection with fail-closed budgets and gates."""

from __future__ import annotations

import re
from decimal import Decimal
from hashlib import sha256
from typing import Literal

from pydantic import Field, StrictInt, field_validator, model_validator

from leviathan_core.mcp_control.policy_models import PolicyDecisionV1
from leviathan_core.numeric import NumericError, canonical_json, exact_add, exact_mul, parse_decimal
from leviathan_core.seal import Issuer, require, verify
from leviathan_core.security.authz_models import AuthorizationDecisionV1

from .model_policy import (
    AgentModelPolicyV1,
    AIRequestV1,
    Environment,
    RouteTrustPort,
    RouteUsageV1,
)
from .model_registry import (
    MAX_COST_USD,
    MAX_NS,
    Modality,
    ModelRegistryEntryV1,
    ModelRegistryV1,
    Provider,
    RouteModelError,
    _identifier,
    _RouteModel,
    _version,
)

DenialCode = Literal[
    "POLICY_DENIED",
    "AUTHORIZATION_DENIED",
    "BUDGET_EXCEEDED",
    "ATTEMPTS_EXHAUSTED",
    "NO_ELIGIBLE_MODEL",
    "MODEL_UNAPPROVED",
    "MODEL_UNAVAILABLE",
    "CAPABILITY_UNMET",
    "QUALITY_FLOOR_UNMET",
    "PRIVACY_FLOOR_UNMET",
    "CREDENTIAL_UNBOUND",
    "TRUST_TIME_INVALID",
]
TraceCode = DenialCode | Literal[
    "PRIMARY_SELECTED", "FALLBACK_SELECTED",
    "PRIOR_PROVIDER_FAILURE", "PRIOR_INVALID_RESPONSE",
]
_QUALITY = {"basic": 0, "standard": 1, "advanced": 2}
_PRIVACY = {"public": 0, "internal": 1, "restricted": 2}
_BUDGET_CLASS = {"low": 0, "medium": 1, "high": 2}
_MILLIONTH = Decimal("0.000001")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_VAULT_REF = re.compile(
    r"vault://leviathan-ai/(development|live)/(claude|gemini|deepseek|gpt|ollama)/"
    r"([A-Z][A-Z0-9_]{0,63})\Z",
    re.ASCII,
)
_DECISION_ISSUER = Issuer("agent003.route_decision.v1")
_DENIAL_ISSUER = Issuer("agent003.route_denial.v1")


class RouteDecisionV1(_RouteModel):
    """Issued selection proposal; it grants no model or tool execution."""

    status: Literal["selected"] = "selected"
    proposal_only: Literal[True] = True
    request_id: str
    agent_id: str
    environment: Environment
    alias: str
    entry_id: str
    provider: Provider
    model_id: str
    model_version: str
    credential_ref: str
    task_type: str
    data_scope: str
    modality: Modality
    region: str
    evaluated_at_ns: StrictInt = Field(gt=0, le=MAX_NS)
    usage_snapshot_revision: StrictInt = Field(ge=0, le=MAX_NS)
    policy_version: str
    registry_version: str
    prompt_version: str
    policy_digest: str
    registry_digest: str
    request_digest: str
    usage_digest: str
    output_schema: str
    reason_code: Literal["PRIMARY_SELECTED", "FALLBACK_SELECTED"]
    authorization_basis: Literal["PORT_ATTESTED"] = "PORT_ATTESTED"
    checked_tools: tuple[str, ...] = Field(min_length=1, max_length=65)
    checked_scopes: tuple[str, ...] = Field(min_length=1, max_length=64)
    reserved_calls: Literal[1] = 1
    reserved_tokens: StrictInt = Field(gt=0, le=2_000_000_000)
    reserved_elapsed_ns: StrictInt = Field(gt=0, le=MAX_NS)
    reserved_cost_usd: Decimal
    trace_codes: tuple[TraceCode, ...] = Field(max_length=256)

    @field_validator(
        "request_id", "agent_id", "alias", "entry_id", "model_id", "model_version",
        "task_type", "data_scope", "region",
    )
    @classmethod
    def valid_ids(cls, value: str) -> str:
        return _identifier(value)

    @field_validator("policy_version", "registry_version", "prompt_version")
    @classmethod
    def valid_version(cls, value: str) -> str:
        return _version(value)

    @field_validator("checked_tools")
    @classmethod
    def valid_tools(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        for value in values:
            _identifier(value)
        return values

    @field_validator("checked_scopes")
    @classmethod
    def valid_scopes(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        for value in values:
            _identifier(value)
        return values

    @field_validator("policy_digest", "registry_digest", "request_digest", "usage_digest")
    @classmethod
    def valid_digest(cls, value: str) -> str:
        if _DIGEST.fullmatch(value) is None:
            raise ValueError("digest invalid")
        return value

    @model_validator(mode="after")
    def coherent(self) -> RouteDecisionV1:
        match = _VAULT_REF.fullmatch(self.credential_ref)
        if match is None or match.group(1) != self.environment or match.group(2) != self.provider:
            raise ValueError("credential reference invalid")
        if self.checked_tools != tuple(dict.fromkeys(self.checked_tools)):
            raise ValueError("checked tools invalid")
        if self.checked_scopes != (self.data_scope,):
            raise ValueError("checked scopes invalid")
        return self

    @field_validator("reserved_cost_usd", mode="before")
    @classmethod
    def valid_cost(cls, value: object) -> Decimal:
        return parse_decimal(
            value, field="reserved_cost_usd", min_value="0", max_value=MAX_COST_USD
        )


class RouteDenialV1(_RouteModel):
    """Issued explicit denial with only fixed redacted reason codes."""

    status: Literal["denied"] = "denied"
    proposal_only: Literal[True] = True
    request_id: str
    agent_id: str
    policy_version: str
    registry_version: str
    prompt_version: str
    policy_digest: str
    registry_digest: str
    request_digest: str
    usage_digest: str
    evaluated_at_ns: StrictInt | None = Field(default=None, gt=0, le=MAX_NS)
    reason_code: DenialCode
    trace_codes: tuple[TraceCode, ...] = Field(max_length=256)

    @field_validator("request_id", "agent_id")
    @classmethod
    def valid_ids(cls, value: str) -> str:
        return _identifier(value)

    @field_validator("policy_version", "registry_version", "prompt_version")
    @classmethod
    def valid_version(cls, value: str) -> str:
        return _version(value)

    @field_validator("policy_digest", "registry_digest", "request_digest", "usage_digest")
    @classmethod
    def valid_digest(cls, value: str) -> str:
        if _DIGEST.fullmatch(value) is None:
            raise ValueError("digest invalid")
        return value


def _content_digest(
    value: AIRequestV1 | AgentModelPolicyV1 | ModelRegistryV1 | RouteUsageV1,
) -> str:
    return sha256(canonical_json(value.model_dump(mode="python"))).hexdigest()


def _deny(
    request: AIRequestV1,
    policy: AgentModelPolicyV1,
    registry: ModelRegistryV1,
    usage: RouteUsageV1,
    reason: DenialCode,
    trace: tuple[TraceCode, ...] = (),
    evaluated_at_ns: int | None = None,
) -> RouteDenialV1:
    return _DENIAL_ISSUER.issue(RouteDenialV1(
        request_id=request.request_id,
        agent_id=request.agent_id,
        policy_version=policy.version,
        registry_version=registry.version,
        prompt_version=request.prompt_version,
        policy_digest=_content_digest(policy),
        registry_digest=_content_digest(registry),
        request_digest=_content_digest(request),
        usage_digest=_content_digest(usage),
        evaluated_at_ns=evaluated_at_ns,
        reason_code=reason,
        trace_codes=trace or (reason,),
    ))


def _authorized(request: AIRequestV1, usage: RouteUsageV1, trust: RouteTrustPort) -> bool:
    """Only injected decisions count; request/model data never grants authority."""

    try:
        if trust.usage_is_verified(request, usage) is not True:
            return False
        principal = trust.principal_decision(request)
        if type(principal) is not AuthorizationDecisionV1 or principal.allowed is not True:
            return False
        for tool_name in dict.fromkeys(("model_route", *request.required_tools)):
            tool = trust.tool_decision(request, tool_name)
            if (
                type(tool) is not PolicyDecisionV1
                or tool.allowed is not True
                or tool.status != "approved"
            ):
                return False
    except Exception:
        return False
    return True


def _estimated_cost(entry: ModelRegistryEntryV1, request: AIRequestV1) -> Decimal:
    input_cost = exact_mul(
        exact_mul(entry.input_cost_per_million_tokens_usd, request.input_tokens),
        _MILLIONTH,
    )
    output_cost = exact_mul(
        exact_mul(entry.output_cost_per_million_tokens_usd, request.output_tokens),
        _MILLIONTH,
    )
    return exact_add(input_cost, output_cost)


def _candidate_reason(
    entry: ModelRegistryEntryV1,
    request: AIRequestV1,
    policy: AgentModelPolicyV1,
    usage: RouteUsageV1,
    evaluated_at_ns: int,
) -> tuple[DenialCode | None, Decimal | None]:
    if not entry.approved:
        return "MODEL_UNAPPROVED", None
    if (
        not entry.available
        or not entry.available_from_ns <= evaluated_at_ns < entry.available_until_ns
    ):
        return "MODEL_UNAVAILABLE", None
    if (
        request.region not in entry.supported_regions
        or request.modality not in entry.capability.modalities
        or not entry.capability.structured_output
        or request.output_schema not in entry.capability.output_schemas
        or not set(request.required_tools).issubset(entry.capability.tools)
        or request.input_tokens > entry.capability.max_context_tokens
        or request.output_tokens > entry.capability.max_output_tokens
        or _BUDGET_CLASS[entry.latency_class] > _BUDGET_CLASS[request.max_latency_class]
        or _BUDGET_CLASS[entry.latency_class] > _BUDGET_CLASS[policy.max_latency_class]
        or _BUDGET_CLASS[entry.cost_class] > _BUDGET_CLASS[policy.max_cost_class]
    ):
        return "CAPABILITY_UNMET", None
    if _QUALITY[entry.capability.quality_class] < max(
        _QUALITY[policy.min_quality_class], _QUALITY[request.min_quality_class]
    ):
        return "QUALITY_FLOOR_UNMET", None
    scope_floor = next(
        item.min_privacy_class for item in policy.scope_privacy_classes
        if item.scope == request.data_scope
    )
    if _PRIVACY[entry.capability.privacy_class] < max(
        _PRIVACY[policy.min_privacy_class], _PRIVACY[scope_floor],
        _PRIVACY[request.privacy_class],
    ):
        return "PRIVACY_FLOOR_UNMET", None
    if usage.elapsed_ns + entry.latency_reservation_ns > policy.max_elapsed_ns:
        return "BUDGET_EXCEEDED", None
    try:
        cost = _estimated_cost(entry, request)
        total = exact_add(usage.cost_spent_usd, cost)
    except NumericError:
        return "BUDGET_EXCEEDED", None
    if total > policy.max_cost_usd:
        return "BUDGET_EXCEEDED", None
    return None, cost


def route_model(
    request: AIRequestV1,
    policy: AgentModelPolicyV1,
    registry: ModelRegistryV1,
    usage: RouteUsageV1,
    trust: RouteTrustPort,
) -> RouteDecisionV1 | RouteDenialV1:
    """Propose one authorized route, or return a sealed denial without effects."""

    if (
        type(request) is not AIRequestV1
        or type(policy) is not AgentModelPolicyV1
        or type(registry) is not ModelRegistryV1
        or type(usage) is not RouteUsageV1
    ):
        raise RouteModelError("ROUTE_INPUT_INVALID")
    request = AIRequestV1.model_validate(request)
    policy = AgentModelPolicyV1.model_validate(policy)
    registry = ModelRegistryV1.model_validate(registry)
    usage = RouteUsageV1.model_validate(usage)
    if (
        request.agent_id != policy.agent_id
        or request.project_id != policy.project_id
        or request.environment != policy.environment
        or request.alias not in policy.allowed_aliases
        or request.data_scope not in policy.allowed_data_scopes
        or request.output_schema not in policy.allowed_output_schemas
        or request.region not in policy.allowed_regions
        or not set(request.required_tools).issubset(policy.allowed_tools)
        or request.input_tokens > policy.max_context_tokens
    ):
        return _deny(request, policy, registry, usage, "POLICY_DENIED")
    if not _authorized(request, usage, trust):
        return _deny(request, policy, registry, usage, "AUTHORIZATION_DENIED")
    try:
        evaluated_at_ns = trust.evaluation_time_ns(request)
    except Exception:
        return _deny(request, policy, registry, usage, "TRUST_TIME_INVALID")
    if (
        type(evaluated_at_ns) is not int
        or not 0 < evaluated_at_ns <= MAX_NS
        or evaluated_at_ns != request.at_ns
    ):
        return _deny(request, policy, registry, usage, "TRUST_TIME_INVALID")
    if len(usage.attempted_entry_ids) >= policy.max_attempts:
        return _deny(
            request, policy, registry, usage, "ATTEMPTS_EXHAUSTED",
            evaluated_at_ns=evaluated_at_ns,
        )
    reserved_tokens = request.input_tokens + request.output_tokens
    if (
        usage.calls_used + 1 > policy.max_calls
        or usage.tokens_used + reserved_tokens > policy.max_tokens
    ):
        return _deny(
            request, policy, registry, usage, "BUDGET_EXCEEDED",
            evaluated_at_ns=evaluated_at_ns,
        )
    aliases = tuple(dict.fromkeys((request.alias, *policy.fallback_aliases)))
    providers = {provider: index for index, provider in enumerate(policy.allowed_providers)}
    order = {alias: index for index, alias in enumerate(aliases)}
    candidates = sorted(
        (
            entry for entry in registry.entries
            if entry.alias in order
            and entry.provider in providers
            and entry.entry_id not in usage.attempted_entry_ids
        ),
        key=lambda entry: (order[entry.alias], providers[entry.provider], entry.entry_id),
    )
    if not candidates:
        return _deny(
            request, policy, registry, usage, "NO_ELIGIBLE_MODEL",
            evaluated_at_ns=evaluated_at_ns,
        )
    reasons: list[DenialCode] = []
    for entry in candidates:
        reason, estimated_cost = _candidate_reason(
            entry, request, policy, usage, evaluated_at_ns
        )
        if reason is not None or estimated_cost is None:
            reasons.append(reason or "BUDGET_EXCEEDED")
            continue
        credential_ref = (
            f"vault://leviathan-ai/{request.environment}/{entry.provider}/"
            f"{entry.credential_name}"
        )
        try:
            bound = trust.credential_is_bound(request, credential_ref)
        except Exception:
            bound = False
        if bound is not True:
            reasons.append("CREDENTIAL_UNBOUND")
            continue
        fallback = bool(usage.attempted_entry_ids or reasons or entry.alias != request.alias)
        reason_code: Literal["PRIMARY_SELECTED", "FALLBACK_SELECTED"] = (
            "FALLBACK_SELECTED" if fallback else "PRIMARY_SELECTED"
        )
        prior_trace: tuple[TraceCode, ...] = ()
        if usage.prior_outcome == "provider_failure":
            prior_trace = ("PRIOR_PROVIDER_FAILURE",)
        elif usage.prior_outcome == "invalid_response":
            prior_trace = ("PRIOR_INVALID_RESPONSE",)
        trace = (*prior_trace, *tuple(dict.fromkeys(reasons)), reason_code)
        return _DECISION_ISSUER.issue(RouteDecisionV1(
            request_id=request.request_id,
            agent_id=request.agent_id,
            environment=request.environment,
            alias=entry.alias,
            entry_id=entry.entry_id,
            provider=entry.provider,
            model_id=entry.model_id,
            model_version=entry.model_version,
            credential_ref=credential_ref,
            task_type=request.task_type,
            data_scope=request.data_scope,
            modality=request.modality,
            region=request.region,
            evaluated_at_ns=evaluated_at_ns,
            usage_snapshot_revision=usage.snapshot_revision,
            policy_version=policy.version,
            registry_version=registry.version,
            prompt_version=request.prompt_version,
            policy_digest=_content_digest(policy),
            registry_digest=_content_digest(registry),
            request_digest=_content_digest(request),
            usage_digest=_content_digest(usage),
            output_schema=request.output_schema,
            reason_code=reason_code,
            checked_tools=tuple(dict.fromkeys(("model_route", *request.required_tools))),
            checked_scopes=(request.data_scope,),
            reserved_tokens=reserved_tokens,
            reserved_elapsed_ns=entry.latency_reservation_ns,
            reserved_cost_usd=estimated_cost,
            trace_codes=trace,
        ))
    redacted = tuple(dict.fromkeys(reasons))
    return _deny(
        request, policy, registry, usage, reasons[0], redacted,
        evaluated_at_ns=evaluated_at_ns,
    )


def verify_route_decision(value: object) -> bool:
    return type(value) is RouteDecisionV1 and verify(value, _DECISION_ISSUER.tag)


def require_route_decision(value: RouteDecisionV1) -> RouteDecisionV1:
    if type(value) is not RouteDecisionV1:
        raise RouteModelError("ROUTE_INPUT_INVALID")
    return require(value, _DECISION_ISSUER.tag)


def verify_route_denial(value: object) -> bool:
    return type(value) is RouteDenialV1 and verify(value, _DENIAL_ISSUER.tag)


__all__ = [
    "RouteDecisionV1",
    "RouteDenialV1",
    "require_route_decision",
    "route_model",
    "verify_route_decision",
    "verify_route_denial",
]
