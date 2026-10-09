"""Focused, synthetic tests for the pure AGENT-003 route kernel."""

from __future__ import annotations

from decimal import Decimal

import pytest

from leviathan_core.agent_council.model_policy import (
    AgentModelPolicyV1,
    AIRequestV1,
    RouteUsageV1,
    ScopePrivacyV1,
)
from leviathan_core.agent_council.model_registry import (
    ModelCapabilityV1,
    ModelRegistryEntryV1,
    ModelRegistryV1,
)
from leviathan_core.agent_council.model_router import (
    RouteDecisionV1,
    RouteDenialV1,
    require_route_decision,
    route_model,
    verify_route_decision,
    verify_route_denial,
)
from leviathan_core.mcp_control.policy_models import PolicyDecisionV1
from leviathan_core.security.authz_models import (
    AuthorizationDecisionV1,
    AuthorizationExplanationV1,
    EffectV1,
    ReasonCodeV1,
)


class FakeTrust:
    def __init__(
        self, *, bound: bool = True, usage_verified: bool = True,
        now_ns: int | None = None,
    ) -> None:
        self.bound = bound
        self.usage_verified = usage_verified
        self.now_ns = now_ns
        self.tool_checks: list[str] = []
        self.credential_checks: list[str] = []

    def principal_decision(self, request: AIRequestV1) -> AuthorizationDecisionV1:
        return AuthorizationDecisionV1(
            AuthorizationExplanationV1(
                rule_id=None, decision=EffectV1.ALLOW,
                reason_code=ReasonCodeV1.AUTHORIZED,
            )
        )

    def tool_decision(self, request: AIRequestV1, tool_name: str) -> PolicyDecisionV1:
        self.tool_checks.append(tool_name)
        return PolicyDecisionV1(
            allowed=True, effect_allowed=False, status="approved", reason_codes=("ALLOW",)
        )

    def evaluation_time_ns(self, request: AIRequestV1) -> int:
        return request.at_ns if self.now_ns is None else self.now_ns

    def usage_is_verified(self, request: AIRequestV1, usage: RouteUsageV1) -> bool:
        return self.usage_verified

    def credential_is_bound(self, request: AIRequestV1, credential_ref: str) -> bool:
        self.credential_checks.append(credential_ref)
        return self.bound


def _scenario() -> tuple[AIRequestV1, AgentModelPolicyV1, ModelRegistryV1, RouteUsageV1]:
    capability = ModelCapabilityV1(
        modalities=("text",), tools=("tool.read",), output_schemas=("answer@v1",),
        structured_output=True, max_context_tokens=1000, max_output_tokens=100,
        quality_class="advanced", privacy_class="restricted",
    )
    entry = ModelRegistryEntryV1(
        entry_id="entry.primary", alias="analyst", provider="gpt", model_id="gpt.fixture",
        model_version="v1", registry_version="v1", capability=capability,
        supported_regions=("us",), approved=True, available=True,
        available_from_ns=1, available_until_ns=1000,
        credential_name="MODEL_KEY", input_cost_per_million_tokens_usd=Decimal("1"),
        output_cost_per_million_tokens_usd=Decimal("2"), cost_class="low",
        latency_class="low", latency_reservation_ns=10,
    )
    request = AIRequestV1(
        request_id="request.1", agent_id="agent.alpha", project_id="leviathan-ai",
        environment="development", alias="analyst", task_type="analysis",
        data_scope="research", modality="text", output_schema="answer@v1",
        required_tools=("tool.read",), input_tokens=3, output_tokens=2,
        min_quality_class="standard", privacy_class="internal", max_latency_class="low",
        prompt_version="v1", at_ns=10, region="us",
    )
    policy = AgentModelPolicyV1(
        version="v1", agent_id="agent.alpha", project_id="leviathan-ai",
        environment="development", allowed_aliases=("analyst", "backup"),
        allowed_providers=("gpt",), allowed_tools=("tool.read",),
        allowed_data_scopes=("research",), allowed_output_schemas=("answer@v1",),
        scope_privacy_classes=(
            ScopePrivacyV1(scope="research", min_privacy_class="internal"),
        ),
        allowed_regions=("us",), fallback_aliases=("backup",),
        min_quality_class="standard", min_privacy_class="internal",
        max_latency_class="low", max_cost_class="low", max_context_tokens=1000,
        max_calls=2, max_tokens=100, max_elapsed_ns=100,
        max_cost_usd=Decimal("0.000007"), max_attempts=2,
    )
    registry = ModelRegistryV1(version="v1", entries=(entry,))
    usage = RouteUsageV1(snapshot_revision=1, calls_used=0, tokens_used=0, elapsed_ns=0,
                         cost_spent_usd=Decimal("0"))
    return request, policy, registry, usage


def test_selects_sealed_proposal_with_exact_cost_and_vault_reference() -> None:
    request, policy, registry, usage = _scenario()
    trust = FakeTrust()
    result = route_model(request, policy, registry, usage, trust)
    assert isinstance(result, RouteDecisionV1)
    assert verify_route_decision(result)
    assert result.proposal_only is True
    assert result.reserved_cost_usd == Decimal("0.000007")
    assert result.reserved_tokens == 5
    assert result.credential_ref == "vault://leviathan-ai/development/gpt/MODEL_KEY"
    assert result.policy_version == result.registry_version == result.prompt_version == "v1"
    assert result.authorization_basis == "PORT_ATTESTED"
    assert result.checked_tools == ("model_route", "tool.read")
    assert result.checked_scopes == ("research",)
    assert result.evaluated_at_ns == request.at_ns
    assert result.usage_snapshot_revision == usage.snapshot_revision
    assert trust.tool_checks == ["model_route", "tool.read"]
    assert trust.credential_checks == [result.credential_ref]
    forged = RouteDecisionV1.model_validate(result.model_dump())
    assert not verify_route_decision(forged)
    with pytest.raises(ValueError):
        require_route_decision(forged)


def test_budget_and_binding_fail_closed() -> None:
    request, policy, registry, usage = _scenario()
    at_limit = RouteUsageV1(snapshot_revision=1, calls_used=0, tokens_used=0, elapsed_ns=0,
                            cost_spent_usd=Decimal("0.000001"))
    budget = route_model(request, policy, registry, at_limit, FakeTrust())
    assert isinstance(budget, RouteDenialV1)
    assert budget.reason_code == "BUDGET_EXCEEDED"
    assert verify_route_denial(budget)
    unbound = route_model(request, policy, registry, usage, FakeTrust(bound=False))
    assert isinstance(unbound, RouteDenialV1)
    assert unbound.reason_code == "CREDENTIAL_UNBOUND"
    unverified = route_model(request, policy, registry, usage,
                             FakeTrust(usage_verified=False))
    assert isinstance(unverified, RouteDenialV1)
    assert unverified.reason_code == "AUTHORIZATION_DENIED"


def test_declared_fallback_is_bounded_and_keeps_capabilities() -> None:
    request, policy, registry, usage = _scenario()
    backup = ModelRegistryEntryV1.model_validate({
        **registry.entries[0].model_dump(), "entry_id": "entry.backup", "alias": "backup",
    })
    registry = ModelRegistryV1(version="v1", entries=(*registry.entries, backup))
    usage = RouteUsageV1(snapshot_revision=2, calls_used=1, tokens_used=5, elapsed_ns=10,
                         cost_spent_usd=Decimal("0"),
                         attempted_entry_ids=("entry.primary",),
                         prior_outcome="provider_failure")
    result = route_model(request, policy, registry, usage, FakeTrust())
    assert isinstance(result, RouteDecisionV1)
    assert result.entry_id == "entry.backup"
    assert result.reason_code == "FALLBACK_SELECTED"
    exhausted = RouteUsageV1(snapshot_revision=3, calls_used=2, tokens_used=5, elapsed_ns=10,
                             cost_spent_usd=Decimal("0"),
                             attempted_entry_ids=("entry.primary", "entry.backup"),
                             prior_outcome="invalid_response")
    denial = route_model(request, policy, registry, exhausted, FakeTrust())
    assert isinstance(denial, RouteDenialV1)
    assert denial.reason_code == "ATTEMPTS_EXHAUSTED"


def test_backdated_request_cannot_select_retired_model() -> None:
    request, policy, registry, usage = _scenario()
    denial = route_model(request, policy, registry, usage, FakeTrust(now_ns=1000))
    assert isinstance(denial, RouteDenialV1)
    assert denial.reason_code == "TRUST_TIME_INVALID"
    assert denial.evaluated_at_ns is None


def test_scope_classification_overrides_public_request_claim() -> None:
    request, policy, registry, usage = _scenario()
    request = AIRequestV1.model_validate({
        **request.model_dump(), "privacy_class": "public",
    })
    policy = AgentModelPolicyV1.model_validate({
        **policy.model_dump(), "min_privacy_class": "public",
        "scope_privacy_classes": (
            ScopePrivacyV1(scope="research", min_privacy_class="restricted"),
        ),
    })
    low_capability = ModelCapabilityV1.model_validate({
        **registry.entries[0].capability.model_dump(), "privacy_class": "public",
    })
    low_entry = ModelRegistryEntryV1.model_validate({
        **registry.entries[0].model_dump(), "capability": low_capability,
    })
    denial = route_model(
        request, policy, ModelRegistryV1(version="v1", entries=(low_entry,)),
        usage, FakeTrust(),
    )
    assert isinstance(denial, RouteDenialV1)
    assert denial.reason_code == "PRIVACY_FLOOR_UNMET"


def test_same_alias_provider_switch_records_fallback_and_prior_outcome() -> None:
    request, policy, registry, _ = _scenario()
    policy = AgentModelPolicyV1.model_validate({
        **policy.model_dump(), "allowed_providers": ("gpt", "claude"),
    })
    second = ModelRegistryEntryV1.model_validate({
        **registry.entries[0].model_dump(), "entry_id": "entry.second",
        "provider": "claude", "credential_name": "CLAUDE_KEY",
    })
    registry = ModelRegistryV1(version="v1", entries=(*registry.entries, second))
    usage = RouteUsageV1(
        calls_used=1, tokens_used=5, elapsed_ns=10, cost_spent_usd=Decimal("0"),
        attempted_entry_ids=("entry.primary",), prior_outcome="provider_failure",
        snapshot_revision=7,
    )
    result = route_model(request, policy, registry, usage, FakeTrust())
    assert isinstance(result, RouteDecisionV1)
    assert result.reason_code == "FALLBACK_SELECTED"
    assert result.trace_codes == ("PRIOR_PROVIDER_FAILURE", "FALLBACK_SELECTED")
    assert result.usage_snapshot_revision == 7
