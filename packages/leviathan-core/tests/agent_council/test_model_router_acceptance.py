"""Independent synthetic acceptance tests for the AGENT-003 route contract."""

from __future__ import annotations

import copy
import gc
import pickle
from decimal import Decimal, Inexact, localcontext
from typing import Any

import pytest
from pydantic import BaseModel

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
    RouteModelError,
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
from leviathan_core.seal import SealError
from leviathan_core.security.authz_models import (
    AuthorizationDecisionV1,
    AuthorizationExplanationV1,
    EffectV1,
    ReasonCodeV1,
)

NOW = 1_000


class SyntheticTrust:
    """A local fake for trust and logical-vault bindings; no external calls."""

    def __init__(
        self,
        *,
        usage_result: object = True,
        principal: object | None = None,
        tool_result: object | None = None,
        credential_result: object = True,
        evaluation_time: object = NOW,
    ) -> None:
        self.usage_result = usage_result
        self.principal = principal or AuthorizationDecisionV1(
            AuthorizationExplanationV1(
                rule_id=None,
                decision=EffectV1.ALLOW,
                reason_code=ReasonCodeV1.AUTHORIZED,
            )
        )
        self.tool_result = tool_result or PolicyDecisionV1(
            allowed=True,
            effect_allowed=False,
            status="approved",
            reason_codes=("FIXTURE_ALLOW",),
        )
        self.credential_result = credential_result
        self.evaluation_time = evaluation_time
        self.calls: list[tuple[str, str | None]] = []

    def principal_decision(self, request: AIRequestV1) -> object:
        self.calls.append(("principal", request.request_id))
        return self.principal

    def tool_decision(self, request: AIRequestV1, tool_name: str) -> object:
        self.calls.append(("tool", tool_name))
        return self.tool_result

    def usage_is_verified(self, request: AIRequestV1, usage: RouteUsageV1) -> object:
        self.calls.append(("usage", None))
        return self.usage_result

    def evaluation_time_ns(self, request: AIRequestV1) -> object:
        self.calls.append(("evaluation_time", None))
        return self.evaluation_time

    def credential_is_bound(self, request: AIRequestV1, credential_ref: str) -> object:
        self.calls.append(("credential", credential_ref))
        return self.credential_result


def capability(**changes: Any) -> ModelCapabilityV1:
    fields: dict[str, Any] = {
        "modalities": ("text",),
        "tools": ("tool.read",),
        "output_schemas": ("answer@v1",),
        "structured_output": True,
        "max_context_tokens": 1_000,
        "max_output_tokens": 100,
        "quality_class": "advanced",
        "privacy_class": "restricted",
    }
    fields.update(changes)
    return ModelCapabilityV1(**fields)


def entry(
    *,
    entry_id: str = "entry.primary",
    alias: str = "analyst",
    provider: str = "gpt",
    **changes: Any,
) -> ModelRegistryEntryV1:
    fields: dict[str, Any] = {
        "entry_id": entry_id,
        "alias": alias,
        "provider": provider,
        "model_id": f"{provider}.synthetic",
        "model_version": "v3",
        "registry_version": "v1",
        "capability": capability(),
        "supported_regions": ("us-test",),
        "approved": True,
        "available": True,
        "available_from_ns": 1,
        "available_until_ns": 10_000,
        "credential_name": f"{provider.upper()}_FIXTURE_KEY",
        "input_cost_per_million_tokens_usd": Decimal("1"),
        "output_cost_per_million_tokens_usd": Decimal("2"),
        "cost_class": "low",
        "latency_class": "low",
        "latency_reservation_ns": 10,
    }
    fields.update(changes)
    return ModelRegistryEntryV1(**fields)


def request(**changes: Any) -> AIRequestV1:
    fields: dict[str, Any] = {
        "request_id": "request.fixture",
        "agent_id": "agent.alpha",
        "project_id": "leviathan-ai",
        "environment": "development",
        "alias": "analyst",
        "task_type": "analysis",
        "data_scope": "research",
        "modality": "text",
        "output_schema": "answer@v1",
        "required_tools": ("tool.read",),
        "input_tokens": 3,
        "output_tokens": 2,
        "min_quality_class": "standard",
        "privacy_class": "internal",
        "max_latency_class": "low",
        "prompt_version": "v7",
        "at_ns": NOW,
        "region": "us-test",
    }
    fields.update(changes)
    return AIRequestV1(**fields)


def policy(**changes: Any) -> AgentModelPolicyV1:
    fields: dict[str, Any] = {
        "version": "v2",
        "agent_id": "agent.alpha",
        "project_id": "leviathan-ai",
        "environment": "development",
        "allowed_aliases": ("analyst", "backup"),
        "allowed_providers": ("gpt", "claude", "gemini", "deepseek", "ollama"),
        "allowed_tools": ("tool.read",),
        "allowed_data_scopes": ("research",),
        "scope_privacy_classes": (
            ScopePrivacyV1(scope="research", min_privacy_class="internal"),
        ),
        "allowed_output_schemas": ("answer@v1",),
        "allowed_regions": ("us-test",),
        "fallback_aliases": ("backup",),
        "min_quality_class": "standard",
        "min_privacy_class": "internal",
        "max_latency_class": "medium",
        "max_cost_class": "medium",
        "max_context_tokens": 1_000,
        "max_calls": 3,
        "max_tokens": 100,
        "max_elapsed_ns": 100,
        "max_cost_usd": Decimal("0.000010"),
        "max_attempts": 2,
    }
    scopes = changes.get("allowed_data_scopes", fields["allowed_data_scopes"])
    fields["scope_privacy_classes"] = tuple(
        ScopePrivacyV1(scope=scope, min_privacy_class="internal") for scope in scopes
    )
    fields.update(changes)
    return AgentModelPolicyV1(**fields)


def usage(**changes: Any) -> RouteUsageV1:
    fields: dict[str, Any] = {
        "snapshot_revision": 1,
        "calls_used": 0,
        "tokens_used": 0,
        "elapsed_ns": 0,
        "cost_spent_usd": Decimal("0"),
    }
    fields.update(changes)
    return RouteUsageV1(**fields)


def route(
    *,
    req: AIRequestV1 | None = None,
    pol: AgentModelPolicyV1 | None = None,
    entries: tuple[ModelRegistryEntryV1, ...] | None = None,
    used: RouteUsageV1 | None = None,
    trust: SyntheticTrust | None = None,
) -> tuple[RouteDecisionV1 | RouteDenialV1, SyntheticTrust]:
    request_value = req or request()
    policy_value = pol or policy()
    registry = ModelRegistryV1(
        version="v1", entries=entries if entries is not None else (entry(),)
    )
    trust_value = trust or SyntheticTrust()
    return (
        route_model(request_value, policy_value, registry, used or usage(), trust_value),
        trust_value,
    )


def test_named_provider_registry_entries_are_proposals_without_provider_calls() -> None:
    for provider in ("claude", "gemini", "deepseek", "gpt", "ollama"):
        selected, trust = route(entries=(entry(provider=provider),))
        assert isinstance(selected, RouteDecisionV1)
        assert selected.provider == provider
        assert selected.model_id == f"{provider}.synthetic"
        assert selected.proposal_only is True
        assert selected.credential_ref.endswith(f"/{provider.upper()}_FIXTURE_KEY")
        assert selected.evaluated_at_ns == NOW
        assert selected.environment == "development"
        assert selected.task_type == "analysis"
        assert selected.data_scope == "research"
        assert selected.modality == "text"
        assert selected.region == "us-test"
        assert selected.usage_snapshot_revision == 1
        assert selected.authorization_basis == "PORT_ATTESTED"
        assert selected.checked_tools == ("model_route", "tool.read")
        assert selected.checked_scopes == ("research",)
        for digest in (
            selected.policy_digest,
            selected.registry_digest,
            selected.request_digest,
            selected.usage_digest,
        ):
            assert len(digest) == 64
        assert verify_route_decision(selected)
        assert [kind for kind, _ in trust.calls].count("credential") == 1


def test_policy_is_bound_to_agent_project_environment_and_scope() -> None:
    cases = (
        (request(agent_id="agent.beta"), "POLICY_DENIED"),
        (request(environment="live"), "POLICY_DENIED"),
        (request(data_scope="private-vault"), "POLICY_DENIED"),
        (request(alias="unlisted"), "POLICY_DENIED"),
        (request(region="eu-test"), "POLICY_DENIED"),
        (request(required_tools=("tool.write",)), "POLICY_DENIED"),
    )
    for req, expected in cases:
        denied, trust = route(req=req)
        assert isinstance(denied, RouteDenialV1)
        assert denied.reason_code == expected
        assert verify_route_denial(denied)
        assert trust.calls == []

    denied, trust = route(pol=policy(agent_id="agent.beta"))
    assert isinstance(denied, RouteDenialV1)
    assert denied.reason_code == "POLICY_DENIED"
    assert trust.calls == []


@pytest.mark.parametrize(
    "capability_change",
    (
        {"modalities": ("vision",)},
        {"structured_output": False, "output_schemas": ()},
        {"output_schemas": ("other@v1",)},
        {"tools": ()},
        {"max_context_tokens": 2},
        {"max_output_tokens": 1},
    ),
)
def test_every_requested_capability_must_be_supported(
    capability_change: dict[str, object],
) -> None:
    model_capability = capability(**capability_change)
    denied, _ = route(entries=(entry(capability=model_capability),))
    assert isinstance(denied, RouteDenialV1)
    assert denied.reason_code == "CAPABILITY_UNMET"


@pytest.mark.parametrize(
    ("changes", "expected"),
    (
        ({"approved": False}, "MODEL_UNAPPROVED"),
        ({"available": False}, "MODEL_UNAVAILABLE"),
        ({"available_from_ns": NOW + 1}, "MODEL_UNAVAILABLE"),
        ({"available_until_ns": NOW}, "MODEL_UNAVAILABLE"),
        ({"supported_regions": ("eu-test",)}, "CAPABILITY_UNMET"),
        ({"latency_class": "high"}, "CAPABILITY_UNMET"),
        ({"cost_class": "high"}, "CAPABILITY_UNMET"),
    ),
)
def test_registry_approval_availability_and_classes_are_enforced(
    changes: dict[str, object], expected: str
) -> None:
    denied, _ = route(entries=(entry(**changes),))
    assert isinstance(denied, RouteDenialV1)
    assert denied.reason_code == expected


@pytest.mark.parametrize(
    ("quality", "privacy", "expected"),
    (
        ("basic", "restricted", "QUALITY_FLOOR_UNMET"),
        ("advanced", "public", "PRIVACY_FLOOR_UNMET"),
    ),
)
def test_quality_and_privacy_floors_cannot_be_downgraded(
    quality: str, privacy: str, expected: str
) -> None:
    denied, _ = route(
        entries=(entry(capability=capability(quality_class=quality, privacy_class=privacy)),)
    )
    assert isinstance(denied, RouteDenialV1)
    assert denied.reason_code == expected


def test_scope_privacy_floor_is_required_and_cannot_be_weakened() -> None:
    strict_scope = policy(
        scope_privacy_classes=(
            ScopePrivacyV1(scope="research", min_privacy_class="restricted"),
        )
    )
    denied, _ = route(
        pol=strict_scope,
        entries=(entry(capability=capability(privacy_class="internal")),),
    )
    assert isinstance(denied, RouteDenialV1)
    assert denied.reason_code == "PRIVACY_FLOOR_UNMET"

    with pytest.raises(RouteModelError) as incomplete:
        policy(scope_privacy_classes=())
    assert incomplete.value.code == "POLICY_OUT_OF_BOUNDS"


def test_authority_usage_and_tool_policy_fail_closed_on_nonliteral_true() -> None:
    bad_policy = PolicyDecisionV1(
        allowed=False,
        effect_allowed=False,
        status="rejected",
        reason_codes=("CANARY",),
    )
    wrong_principal = object()
    for trust in (
        SyntheticTrust(usage_result=1),
        SyntheticTrust(usage_result=False),
        SyntheticTrust(principal=wrong_principal),
        SyntheticTrust(
            principal=AuthorizationDecisionV1(
                AuthorizationExplanationV1(
                    rule_id=None,
                    decision=EffectV1.DENY,
                    reason_code=ReasonCodeV1.NOT_AUTHORIZED,
                )
            )
        ),
        SyntheticTrust(tool_result=bad_policy),
        SyntheticTrust(credential_result=1),
        SyntheticTrust(credential_result=False),
    ):
        denied, _ = route(trust=trust)
        assert isinstance(denied, RouteDenialV1)
        assert denied.reason_code in {
            "AUTHORIZATION_DENIED",
            "CREDENTIAL_UNBOUND",
        }
        assert verify_route_denial(denied)


def test_all_trust_checks_are_required_for_every_tool_and_logical_credential() -> None:
    selected, trust = route()
    assert isinstance(selected, RouteDecisionV1)
    assert trust.calls == [
        ("usage", None),
        ("principal", "request.fixture"),
        ("tool", "model_route"),
        ("tool", "tool.read"),
        ("evaluation_time", None),
        ("credential", selected.credential_ref),
    ]
    assert selected.credential_ref == (
        "vault://leviathan-ai/development/gpt/GPT_FIXTURE_KEY"
    )


def test_decimal_cost_and_each_budget_boundary_are_exact() -> None:
    selected, _ = route()
    assert isinstance(selected, RouteDecisionV1)
    assert selected.reserved_cost_usd == Decimal("0.000007")
    exact_limit, _ = route(pol=policy(max_cost_usd=Decimal("0.000007")))
    assert isinstance(exact_limit, RouteDecisionV1)

    over_cost, _ = route(
        pol=policy(max_cost_usd=Decimal("0.000007")),
        used=usage(cost_spent_usd=Decimal("0.0000001")),
    )
    assert isinstance(over_cost, RouteDenialV1)
    assert over_cost.reason_code == "BUDGET_EXCEEDED"
    for pol, used in (
        (policy(max_calls=1, max_attempts=1), usage(calls_used=1)),
        (policy(max_tokens=5), usage(tokens_used=1)),
        (policy(max_elapsed_ns=10), usage(elapsed_ns=1)),
    ):
        denied, _ = route(pol=pol, used=used)
        assert isinstance(denied, RouteDenialV1)
        assert denied.reason_code == "BUDGET_EXCEEDED"


def test_fallback_is_declared_ordered_bounded_and_never_downgrades() -> None:
    req = request()
    high = entry(entry_id="primary", alias="analyst", approved=False)
    backup_first = entry(entry_id="backup.a", alias="backup", provider="claude")
    backup_second = entry(entry_id="backup.b", alias="backup", provider="gpt")
    selected, _ = route(
        entries=(backup_second, high, backup_first),
        pol=policy(allowed_providers=("claude", "gpt", "gemini", "deepseek", "ollama")),
        used=usage(
            calls_used=1,
            tokens_used=5,
            elapsed_ns=10,
            attempted_entry_ids=("already-tried",),
            prior_outcome="provider_failure",
        ),
    )
    assert isinstance(selected, RouteDecisionV1)
    assert selected.entry_id == "backup.a"
    assert selected.reason_code == "FALLBACK_SELECTED"
    assert "PRIOR_PROVIDER_FAILURE" in selected.trace_codes
    assert "MODEL_UNAPPROVED" in selected.trace_codes
    assert selected.output_schema == req.output_schema

    low_privacy = entry(
        entry_id="backup.low", alias="backup", provider="claude",
        capability=capability(privacy_class="public"),
    )
    denied, _ = route(entries=(high, low_privacy))
    assert isinstance(denied, RouteDenialV1)
    assert denied.reason_code == "MODEL_UNAPPROVED"
    assert "PRIVACY_FLOOR_UNMET" in denied.trace_codes


def test_attempted_entry_is_not_retried_and_attempt_limit_is_terminal() -> None:
    candidate = entry()
    exhausted, _ = route(
        entries=(candidate,),
        used=usage(
            calls_used=2,
            attempted_entry_ids=(candidate.entry_id, "prior.entry"),
            prior_outcome="invalid_response",
        ),
    )
    assert isinstance(exhausted, RouteDenialV1)
    assert exhausted.reason_code == "ATTEMPTS_EXHAUSTED"

    no_retry, _ = route(
        entries=(candidate,),
        used=usage(
            calls_used=1,
            attempted_entry_ids=(candidate.entry_id,),
            prior_outcome="provider_failure",
        ),
    )
    assert isinstance(no_retry, RouteDenialV1)
    assert no_retry.reason_code == "NO_ELIGIBLE_MODEL"


def test_prior_same_alias_candidate_can_fallback_with_invalid_response_trace() -> None:
    primary = entry(entry_id="entry.first")
    sibling = entry(entry_id="entry.second", provider="claude")
    selected, _ = route(
        entries=(primary, sibling),
        used=usage(
            snapshot_revision=3,
            calls_used=1,
            tokens_used=5,
            attempted_entry_ids=(primary.entry_id,),
            prior_outcome="invalid_response",
        ),
    )
    assert isinstance(selected, RouteDecisionV1)
    assert selected.entry_id == "entry.second"
    assert selected.alias == "analyst"
    assert selected.reason_code == "FALLBACK_SELECTED"
    assert "PRIOR_INVALID_RESPONSE" in selected.trace_codes


@pytest.mark.parametrize("evaluation_time", (True, 0, NOW + 1, "1000"))
def test_evaluation_time_must_be_trusted_bounded_exact_int_and_match_request(
    evaluation_time: object,
) -> None:
    denied, _ = route(trust=SyntheticTrust(evaluation_time=evaluation_time))
    assert isinstance(denied, RouteDenialV1)
    assert denied.reason_code == "TRUST_TIME_INVALID"
    assert denied.evaluated_at_ns is None


def test_denials_and_decisions_bind_request_and_usage_snapshots() -> None:
    selected_one, _ = route(req=request(request_id="request.one"), used=usage(snapshot_revision=1))
    selected_two, _ = route(req=request(request_id="request.two"), used=usage(snapshot_revision=2))
    assert isinstance(selected_one, RouteDecisionV1)
    assert isinstance(selected_two, RouteDecisionV1)
    assert selected_one.request_digest != selected_two.request_digest
    assert selected_one.usage_digest != selected_two.usage_digest
    assert selected_one.usage_snapshot_revision == 1
    assert selected_two.usage_snapshot_revision == 2


def test_versions_and_prompt_trace_are_pinned_and_redacted() -> None:
    selected, _ = route(req=request(prompt_version="v19"))
    assert isinstance(selected, RouteDecisionV1)
    assert selected.policy_version == "v2"
    assert selected.registry_version == "v1"
    assert selected.prompt_version == "v19"
    assert selected.reason_code == "PRIMARY_SELECTED"
    assert selected.trace_codes == ("PRIMARY_SELECTED",)
    assert "credential" not in repr(selected.trace_codes).lower()

    denied, _ = route(req=request(alias="secret-canary"))
    assert isinstance(denied, RouteDenialV1)
    assert denied.reason_code == "POLICY_DENIED"
    assert "secret-canary" not in str(denied)
    assert "vault://" not in str(denied)


def test_issued_proposals_cannot_be_forged_by_validated_copy_or_relabel() -> None:
    selected, _ = route()
    assert isinstance(selected, RouteDecisionV1)
    assert verify_route_decision(selected)
    cloned = RouteDecisionV1.model_validate(selected.model_dump())
    assert not verify_route_decision(cloned)
    assert not verify_route_decision(selected.model_copy())
    with pytest.raises((ValueError, RouteModelError)):
        require_route_decision(cloned)

    denied, _ = route(req=request(alias="forbidden"))
    assert isinstance(denied, RouteDenialV1)
    assert verify_route_denial(denied)
    assert not verify_route_denial(RouteDenialV1.model_validate(denied.model_dump()))


def test_strict_input_validation_and_errors_do_not_echo_canaries() -> None:
    with pytest.raises(RouteModelError) as invalid_tokens:
        request(input_tokens=True)
    assert "CANARY" not in str(invalid_tokens.value)
    with pytest.raises(RouteModelError):
        request(project_id="other-project")
    with pytest.raises(RouteModelError) as huge_integer:
        request(input_tokens=10**5000)
    assert huge_integer.value.code == "REQUEST_INVALID"
    assert "10" not in str(huge_integer.value)
    assert huge_integer.value.__cause__ is None

    with pytest.raises(RouteModelError) as invalid_cost:
        policy(max_cost_usd=Decimal("NaN"))
    assert invalid_cost.value.code == "POLICY_OUT_OF_BOUNDS"
    assert "NaN" not in str(invalid_cost.value)
    assert invalid_cost.value.__cause__ is None


def test_numeric_policy_is_independent_of_ambient_decimal_context() -> None:
    with localcontext() as ambient:
        ambient.prec = 2
        ambient.Emax = 9
        ambient.traps[Inexact] = True
        selected, _ = route()
        assert isinstance(selected, RouteDecisionV1)
        assert selected.reserved_cost_usd == Decimal("0.000007")


@pytest.mark.parametrize(
    ("factory", "field"),
    (
        (request, "input_tokens"),
        (request, "output_tokens"),
        (request, "at_ns"),
        (policy, "max_context_tokens"),
        (policy, "max_calls"),
        (policy, "max_tokens"),
        (policy, "max_elapsed_ns"),
        (policy, "max_attempts"),
        (usage, "calls_used"),
        (usage, "tokens_used"),
        (usage, "elapsed_ns"),
        (lambda **changes: capability(**changes), "max_context_tokens"),
        (lambda **changes: entry(**changes), "available_from_ns"),
        (lambda **changes: entry(**changes), "available_until_ns"),
        (lambda **changes: entry(**changes), "latency_reservation_ns"),
    ),
)
def test_bool_is_not_accepted_for_integer_limits_or_timestamps(
    factory: Any, field: str
) -> None:
    with pytest.raises(RouteModelError):
        factory(**{field: True})


@pytest.mark.parametrize(
    ("factory", "field", "value"),
    (
        (entry, "approved", 1),
        (entry, "available", "false"),
        (lambda **changes: capability(**changes), "structured_output", 1),
    ),
)
def test_boolean_fields_do_not_coerce_integers_or_text(
    factory: Any, field: str, value: object
) -> None:
    with pytest.raises(RouteModelError):
        factory(**{field: value})


@pytest.mark.parametrize(
    ("factory", "field", "value"),
    (
        (request, "request_id", "request-κ-canary"),
        (request, "alias", "alias-\u00e9-canary"),
        (request, "prompt_version", "v1-canary-\u00e9"),
        (policy, "agent_id", "agent-\u00e9-canary"),
        (entry, "entry_id", "entry-\u03b1-canary"),
    ),
)
def test_boundary_identifier_failures_are_typed_and_content_free(
    factory: Any, field: str, value: str
) -> None:
    with pytest.raises(RouteModelError) as failure:
        factory(**{field: value})
    assert failure.value.code in {
        "REQUEST_INVALID",
        "POLICY_OUT_OF_BOUNDS",
        "ROUTE_MODEL_INVALID",
    }
    assert value not in str(failure.value)
    assert value not in repr(failure.value.args)
    assert failure.value.__cause__ is None


def test_duplicate_and_excessive_registry_or_policy_bounds_fail_closed() -> None:
    with pytest.raises(RouteModelError):
        policy(max_attempts=4, max_calls=3)
    with pytest.raises(RouteModelError):
        ModelRegistryV1(version="v1", entries=(entry(), entry()))
    with pytest.raises(RouteModelError):
        entry(available_until_ns=1, available_from_ns=1)
    with pytest.raises(RouteModelError):
        entry(input_cost_per_million_tokens_usd=Decimal("1e999999"))


def test_public_decision_freeze_copy_pickle_and_digest_issuance() -> None:
    first, _ = route()
    second, _ = route()
    assert isinstance(first, RouteDecisionV1)
    assert isinstance(second, RouteDecisionV1)
    assert first == second and first is not second
    assert verify_route_decision(first) and verify_route_decision(second)

    del first
    gc.collect()
    assert verify_route_decision(second)

    with pytest.raises(SealError):
        second.prompt_version = "v99"
    with pytest.raises(SealError):
        del second.prompt_version
    for clone in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(SealError):
            clone(second)

    assert not any("issuer" in name.lower() or "seal" in name.lower() for name in vars(second))
    original_data = second.model_dump()
    with pytest.raises((RouteModelError, SealError)):
        BaseModel.__init__(second, **original_data)
    assert verify_route_decision(second)

    direct = RouteDecisionV1(**original_data)
    assert not verify_route_decision(direct)
    with pytest.raises((RouteModelError, SealError, TypeError)):
        RouteDecisionV1.model_construct(**original_data)

    validated = RouteDecisionV1.model_validate(second)
    assert validated is not second
    assert not verify_route_decision(validated)
    with pytest.raises(RouteModelError) as json_forge:
        RouteDecisionV1.model_validate_json(second.model_dump_json())
    assert json_forge.value.code == "ROUTE_MODEL_INVALID"
    assert json_forge.value.__cause__ is None

    object.__setattr__(second, "prompt_version", "v99")
    assert not verify_route_decision(second)
    with pytest.raises(SealError):
        require_route_decision(second)


def test_selection_does_not_trust_model_or_request_claims_as_authority() -> None:
    # Neither a proposed model ID nor an extra authority-shaped field is accepted
    # as a source of tool permission; the injected trust port remains mandatory.
    req = request()
    object.__setattr__(req, "credential_ref", "vault://forged/canary")
    denied, trust = route(req=req, trust=SyntheticTrust(usage_result=False))
    assert isinstance(denied, RouteDenialV1)
    assert denied.reason_code == "AUTHORIZATION_DENIED"
    assert all(value != "vault://forged/canary" for _, value in trust.calls)
