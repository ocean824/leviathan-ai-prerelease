"""Independent adversarial acceptance for SEC-002 default-deny authorization."""

from __future__ import annotations

import copy
import json
import pickle
from dataclasses import fields, replace
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import BaseModel

import leviathan_core.security as public_security
import leviathan_core.security.authz_models as authz_models
import leviathan_core.security.authz_policy as authz_policy
from leviathan_core.security.authz_models import (
    ActionV1,
    AuthorizationContextV1,
    AuthorizationModelError,
    AuthorizationPolicyV1,
    BreakGlassEvidenceV1,
    EffectV1,
    PolicyRuleV1,
    PrincipalV1,
    ReasonCodeV1,
    ResourceV1,
    TrustedPrincipalAdapterV1,
    TrustedPrincipalV1,
)
from leviathan_core.security.authz_policy import authorize

AT = datetime(2026, 9, 30, 12, 0, tzinfo=UTC)
PROJECT = "leviathan-ai"
HIDDEN_RESOURCE = "restricted-resource-7f3a"
PRIVATE_VENUE = "MIC-HIDDEN-83"


def _claims(
    *,
    principal_id: str = "requester-1",
    roles: tuple[str, ...] = ("operator.read",),
    env: str = "development",
    venue: str | None = None,
    portfolio: str | None = None,
    strategy: str | None = None,
    break_glass: bool = False,
) -> PrincipalV1:
    return PrincipalV1(
        principal_id=principal_id,
        project_id=PROJECT,
        roles=roles,
        env=env,
        venue=venue,
        portfolio=portfolio,
        strategy=strategy,
        break_glass=break_glass,
    )


def _trusted(**kwargs: object) -> TrustedPrincipalV1:
    claims = _claims(**kwargs)
    return TrustedPrincipalAdapterV1.from_verified_claims(
        claims, verifier_marker=authz_models._VERIFIER_MARKER
    )


def _action(name: str = "read") -> ActionV1:
    return ActionV1(name=name)


def _resource(
    *,
    resource_id: str = HIDDEN_RESOURCE,
    env: str = "development",
    venue: str | None = None,
    portfolio: str | None = None,
    strategy: str | None = None,
) -> ResourceV1:
    return ResourceV1(
        resource_id=resource_id,
        project_id=PROJECT,
        env=env,
        venue=venue,
        portfolio=portfolio,
        strategy=strategy,
    )


def _context(
    *,
    at: datetime = AT,
    env: str = "development",
    venue: str | None = None,
    portfolio: str | None = None,
    strategy: str | None = None,
) -> AuthorizationContextV1:
    return AuthorizationContextV1(
        project_id=PROJECT,
        env=env,
        at=at,
        venue=venue,
        portfolio=portfolio,
        strategy=strategy,
    )


def _rule(
    *,
    rule_id: str = "rule-read",
    effect: EffectV1 = EffectV1.ALLOW,
    roles: tuple[str, ...] = ("operator.read",),
    actions: tuple[str, ...] = ("read",),
    resources: tuple[str, ...] = (HIDDEN_RESOURCE,),
    env: str = "development",
    not_before: datetime = AT - timedelta(minutes=1),
    not_after: datetime = AT + timedelta(hours=1),
    venue: str | None = None,
    portfolio: str | None = None,
    strategy: str | None = None,
) -> PolicyRuleV1:
    return PolicyRuleV1(
        rule_id=rule_id,
        effect=effect,
        roles=roles,
        actions=actions,
        resources=resources,
        env=env,
        not_before=not_before,
        not_after=not_after,
        venue=venue,
        portfolio=portfolio,
        strategy=strategy,
    )


def _policy(
    *rules: PolicyRuleV1,
    expires_at: datetime = AT + timedelta(days=1),
    conflict_precedence: str | None = None,
) -> AuthorizationPolicyV1:
    return AuthorizationPolicyV1(
        version="v1",
        project_id=PROJECT,
        expires_at=expires_at,
        rules=tuple(rules) or (_rule(),),
        conflict_precedence=conflict_precedence,
    )


def _decision(
    principal: object | None = None,
    *,
    action: object | None = None,
    resource: object | None = None,
    context: object | None = None,
    policy: object | None = None,
    evidence: object | None = None,
):
    return authorize(
        principal if principal is not None else _trusted(),
        action if action is not None else _action(),
        resource if resource is not None else _resource(),
        context if context is not None else _context(),
        policy if policy is not None else _policy(),
        break_glass_evidence=evidence,
    )


def _assert_public_denial(decision: object) -> None:
    assert decision.decision is EffectV1.DENY
    assert decision.reason_code is ReasonCodeV1.NOT_AUTHORIZED
    assert decision.explanation.rule_id is None


def _assert_public_allow(decision: object) -> None:
    assert decision.decision is EffectV1.ALLOW
    assert decision.reason_code.value == "AUTHORIZED"
    assert decision.explanation.rule_id is None


def test_default_deny_when_policy_is_missing_or_has_no_matching_allow() -> None:
    missing = authorize(_trusted(), _action(), _resource(), _context(), None)
    _assert_public_denial(missing)

    unmatched = _policy(_rule(roles=("risk.admin",)))
    denied = _decision(policy=unmatched)
    _assert_public_denial(denied)


def test_evaluation_validates_policy_then_attributes_then_denies_before_allow() -> None:
    allow = _rule(rule_id="allow-read")
    deny = _rule(rule_id="deny-read", effect=EffectV1.DENY)
    policy = _policy(allow, deny, conflict_precedence="DENY_OVERRIDES")
    decision = _decision(policy=policy)
    _assert_public_denial(decision)

    mismatched = _decision(
        principal=_trusted(venue=PRIVATE_VENUE),
        resource=_resource(venue="MIC-OTHER"),
        context=_context(venue="MIC-OTHER"),
        policy=policy,
    )
    _assert_public_denial(mismatched)

    invalid_policy_result = authorize(_trusted(), {}, {}, {}, {"rules": []})
    _assert_public_denial(invalid_policy_result)


def test_overlapping_allow_and_deny_require_explicit_conflict_precedence_and_deny_wins() -> None:
    allow = _rule(rule_id="allow")
    deny = _rule(rule_id="deny", effect=EffectV1.DENY)
    with pytest.raises(AuthorizationModelError) as conflict:
        _policy(allow, deny)
    assert conflict.value.reason_code is ReasonCodeV1.POLICY_CONFLICT

    resolved = _policy(allow, deny, conflict_precedence="DENY_OVERRIDES")
    decision = _decision(policy=resolved)
    _assert_public_denial(decision)


def test_policy_construction_replace_and_authorize_revalidate_malformed_or_duplicate_policy() -> (
    None
):
    rule = _rule()
    with pytest.raises(AuthorizationModelError):
        _policy(rule, replace(rule, rule_id=rule.rule_id))

    valid = _policy(rule)
    with pytest.raises(AuthorizationModelError):
        replace(valid, rules=(rule, replace(rule, rule_id=rule.rule_id)))

    corrupted = object.__new__(AuthorizationPolicyV1)
    for field in fields(AuthorizationPolicyV1):
        object.__setattr__(corrupted, field.name, getattr(valid, field.name))
    object.__setattr__(corrupted, "rules", (rule, replace(rule, rule_id=rule.rule_id)))
    denied = authorize(_trusted(), _action(), _resource(), _context(), corrupted)
    _assert_public_denial(denied)


def test_expired_policy_is_rechecked_against_injected_utc_time() -> None:
    expired = _policy(expires_at=AT)
    decision = _decision(policy=expired)
    _assert_public_denial(decision)


def test_policy_rule_environment_never_accepts_wildcard() -> None:
    with pytest.raises(AuthorizationModelError):
        _rule(env="*")
    with pytest.raises(AuthorizationModelError):
        _rule(effect=EffectV1.DENY, roles=("*",))


def test_cross_environment_admin_is_denied_even_with_an_allow_rule() -> None:
    admin = _trusted(roles=("admin",), env="development")
    live_resource = _resource(env="live")
    live_context = _context(env="live")
    live_allow = _policy(_rule(roles=("*",), env="live"))

    decision = _decision(
        principal=admin,
        resource=live_resource,
        context=live_context,
        policy=live_allow,
    )

    _assert_public_denial(decision)


@pytest.mark.parametrize("attribute", ["venue", "portfolio", "strategy"])
def test_attribute_scopes_must_match_principal_resource_context_and_rule(attribute: str) -> None:
    principal = _trusted(**{attribute: "scope-a"})
    resource = _resource(**{attribute: "scope-a"})
    context = _context(**{attribute: "scope-a"})
    mismatched = _context(**{attribute: "scope-b"})

    decision = _decision(
        principal=principal,
        resource=resource,
        context=mismatched,
        policy=_policy(_rule(**{attribute: "scope-a"})),
    )

    _assert_public_denial(decision)

    wrong_rule_scope = _decision(
        principal=principal,
        resource=resource,
        context=context,
        policy=_policy(_rule(**{attribute: "scope-b"})),
    )
    _assert_public_denial(wrong_rule_scope)


def test_policy_time_window_is_half_open_and_uses_utc() -> None:
    opens_at = AT
    closes_at = AT + timedelta(minutes=1)
    rule = _rule(not_before=opens_at, not_after=closes_at)
    policy = _policy(rule)

    at_start = _decision(context=_context(at=opens_at), policy=policy)
    _assert_public_allow(at_start)
    at_end = _decision(context=_context(at=closes_at), policy=policy)
    _assert_public_denial(at_end)

    with pytest.raises(AuthorizationModelError):
        _context(at=AT.replace(tzinfo=None))


def test_trusted_principal_cannot_be_constructed_from_dict_json_or_request_body() -> None:
    claim_data = {
        "principal_id": "attacker",
        "project_id": PROJECT,
        "roles": ["admin"],
        "env": "live",
    }
    decoded = json.loads(json.dumps(claim_data))
    with pytest.raises((TypeError, ValueError, AuthorizationModelError)):
        TrustedPrincipalAdapterV1.from_verified_claims(
            decoded, verifier_marker=authz_models._VERIFIER_MARKER
        )
    with pytest.raises(TypeError):
        TrustedPrincipalV1(**claim_data)
    _assert_public_denial(_decision(principal=claim_data))

    class RequestBody(BaseModel):
        principal_id: str
        project_id: str
        roles: list[str]
        env: str

    body = RequestBody.model_construct(**claim_data)
    with pytest.raises(ValueError):
        TrustedPrincipalAdapterV1.from_verified_claims(
            body, verifier_marker=authz_models._VERIFIER_MARKER
        )
    _assert_public_denial(_decision(principal=body))


def test_trusted_principal_cannot_be_reissued_through_copy_deepcopy_pickle_or_replace() -> None:
    principal = _trusted()
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(TypeError):
            operation(principal)
    with pytest.raises(TypeError):
        replace(principal, env="live")
    with pytest.raises(ValueError):
        TrustedPrincipalAdapterV1.from_verified_claims(_claims(), verifier_marker=object())


def test_claim_principal_and_pydantic_construct_bypass_remain_untrusted() -> None:
    claim = _claims(roles=("admin",), env="live")
    _assert_public_denial(_decision(principal=claim))

    class Claims(BaseModel):
        principal_id: str
        project_id: str
        roles: tuple[str, ...]
        env: str

    forged = Claims.model_construct(
        principal_id="attacker", project_id=PROJECT, roles=("admin",), env="live"
    )
    _assert_public_denial(_decision(principal=forged))
    with pytest.raises(AuthorizationModelError):
        PrincipalV1(principal_id="attacker", project_id=PROJECT, roles=["admin"], env="live")


def test_break_glass_claim_and_unverified_evidence_grant_nothing() -> None:
    principal = _trusted(break_glass=True)
    decision = _decision(principal=principal)
    _assert_public_denial(decision)

    ordinary_evidence = BreakGlassEvidenceV1(
        requester_id="requester-1",
        approver_ids=("approver-1", "approver-2"),
        scope=("read",),
        issued_at=AT - timedelta(minutes=1),
        expires_at=AT + timedelta(minutes=29),
    )
    assert ordinary_evidence.verified is False
    denied = _decision(principal=principal, evidence=ordinary_evidence)
    _assert_public_denial(denied)


def test_break_glass_requires_two_distinct_nonrequester_approvers_and_at_most_thirty_minutes() -> (
    None
):
    for approvers, end in (
        (("approver-1",), AT + timedelta(minutes=5)),
        (("requester-1", "approver-2"), AT + timedelta(minutes=5)),
        (("approver-1", "approver-1"), AT + timedelta(minutes=5)),
        (("approver-1", "approver-2"), AT + timedelta(minutes=31)),
    ):
        with pytest.raises(AuthorizationModelError) as invalid:
            BreakGlassEvidenceV1(
                requester_id="requester-1",
                approver_ids=approvers,
                scope=("read",),
                issued_at=AT,
                expires_at=end,
            )
        assert invalid.value.reason_code is ReasonCodeV1.BREAK_GLASS_UNVERIFIED

    evidence = BreakGlassEvidenceV1._from_verified_adapter(
        requester_id="requester-1",
        approver_ids=("approver-1", "approver-2"),
        scope=("read",),
        issued_at=AT,
        expires_at=AT + timedelta(minutes=30),
        verifier_marker=authz_models._VERIFIER_MARKER,
    )
    allowed = _decision(principal=_trusted(break_glass=True), evidence=evidence)
    _assert_public_allow(allowed)
    assert evidence.verified

    outside_scope = BreakGlassEvidenceV1._from_verified_adapter(
        requester_id="requester-1",
        approver_ids=("approver-1", "approver-2"),
        scope=("write",),
        issued_at=AT,
        expires_at=AT + timedelta(minutes=30),
        verifier_marker=authz_models._VERIFIER_MARKER,
    )
    denied = _decision(principal=_trusted(break_glass=True), evidence=outside_scope)
    _assert_public_denial(denied)


def test_explanation_exposes_only_allowlisted_reason_and_never_attributes_or_hidden_resource() -> (
    None
):
    decision = _decision(
        principal=_trusted(venue=PRIVATE_VENUE),
        resource=_resource(resource_id=HIDDEN_RESOURCE, venue="MIC-OTHER"),
        context=_context(venue="MIC-OTHER"),
    )
    rendered = repr(decision)
    assert PRIVATE_VENUE not in rendered
    assert HIDDEN_RESOURCE not in rendered
    _assert_public_denial(decision)
    assert {field.name for field in fields(decision.explanation)} == {
        "rule_id",
        "decision",
        "reason_code",
    }
    assert not hasattr(decision, "route_permit")


def test_rule_deny_default_deny_and_unknown_resource_public_explanations_are_identical() -> None:
    principal = _trusted()
    context = _context()
    action = _action()
    hidden_id = "hidden-book"
    hidden_deny_policy = _policy(
        _rule(rule_id="deny-hidden-book", effect=EffectV1.DENY, resources=(hidden_id,))
    )
    default_deny_policy = _policy(
        _rule(rule_id="allow-known-book", resources=("known-book",))
    )

    rule_deny = authorize(
        principal, action, _resource(resource_id=hidden_id), context, hidden_deny_policy
    )
    default_deny = authorize(
        principal, action, _resource(resource_id=hidden_id), context, default_deny_policy
    )
    unknown_resource = authorize(
        principal, action, _resource(resource_id="unknown-book"), context, default_deny_policy
    )

    explanations = (rule_deny.explanation, default_deny.explanation, unknown_resource.explanation)
    encoded = tuple(repr(item).encode("utf-8") for item in explanations)
    assert encoded[0] == encoded[1] == encoded[2]
    for decision in (rule_deny, default_deny, unknown_resource):
        _assert_public_denial(decision)
        assert "hidden-book" not in repr(decision.explanation)
        assert "unknown-book" not in repr(decision.explanation)


def test_secret_shaped_policy_rule_id_is_rejected_by_closed_grammar() -> None:
    with pytest.raises(AuthorizationModelError):
        _rule(
            rule_id="sk_TEST_SYNTHETIC_NOT_A_REAL_KEY_ABCDEF1234567890",
            effect=EffectV1.DENY,
        )


def test_detailed_audit_record_is_not_reachable_from_public_authorize_result() -> None:
    public_deny = _decision(policy=_policy(_rule(effect=EffectV1.DENY)))

    _assert_public_denial(public_deny)
    assert {field.name for field in fields(public_deny)} == {"explanation"}
    assert not hasattr(public_deny, "audit")
    assert not hasattr(public_deny, "audit_record")
    assert not hasattr(public_deny, "policy_version")
    assert "AuthzAuditRecordV1" not in public_security.__all__
    assert not hasattr(public_security, "AuthzAuditRecordV1")
    assert "_authorize_with_audit" not in public_security.__all__


def test_public_allow_redacts_secret_shaped_rule_id_while_private_audit_retains_it() -> None:
    rule_id = "sk_test_synthetic_canary"
    policy = _policy(_rule(rule_id=rule_id))
    principal = _trusted()
    action = _action()
    resource = _resource()
    context = _context()

    public = authorize(principal, action, resource, context, policy)
    _assert_public_allow(public)
    public_bytes = repr(public.explanation).encode("utf-8")
    assert rule_id.encode("ascii") not in public_bytes

    with pytest.raises(PermissionError):
        authz_policy._authorize_with_audit(
            principal,
            action,
            resource,
            context,
            policy,
            audit_marker=object(),
        )

    private_decision, audit = authz_policy._authorize_with_audit(
        principal,
        action,
        resource,
        context,
        policy,
        audit_marker=authz_policy._AUDIT_MARKER,
    )
    assert private_decision == public
    assert audit.decision is EffectV1.ALLOW
    assert audit.reason_code is ReasonCodeV1.ALLOW_RULE
    assert audit.rule_id == rule_id
    assert audit.policy_version == "v1"
