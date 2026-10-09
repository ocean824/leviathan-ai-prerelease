"""SEC-002 bounded authorization kernel tests (LEV-REQ-032)."""

import copy
import json
import pickle
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from leviathan_core import security
from leviathan_core.security import (
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
    authorize,
)
from leviathan_core.security.authz_models import _VERIFIER_MARKER
from leviathan_core.security.authz_policy import _AUDIT_MARKER, _authorize_with_audit

AT = datetime(2026, 9, 30, 12, tzinfo=UTC)


def _principal(**changes: object) -> TrustedPrincipalV1:
    claims = PrincipalV1(
        principal_id="operator.1", project_id="leviathan-ai", roles=("risk.admin",),
        env="test", venue="XNYS", portfolio="book.1", strategy="alpha.1",
    )
    claims = replace(claims, **changes)
    return TrustedPrincipalAdapterV1.from_verified_claims(
        claims, verifier_marker=_VERIFIER_MARKER
    )


def _rule(effect: EffectV1 = EffectV1.ALLOW, **changes: object) -> PolicyRuleV1:
    rule = PolicyRuleV1(
        rule_id="allow.1" if effect is EffectV1.ALLOW else "deny.1",
        effect=effect, roles=("risk.admin",), actions=("research.read",),
        resources=("research.private",), env="test", venue="XNYS",
        portfolio="book.1", strategy="alpha.1",
        not_before=AT - timedelta(minutes=1), not_after=AT + timedelta(minutes=1),
    )
    return replace(rule, **changes)


def _inputs() -> tuple[TrustedPrincipalV1, ActionV1, ResourceV1, AuthorizationContextV1]:
    return (
        _principal(), ActionV1("research.read"),
        ResourceV1("research.private", "leviathan-ai", "test", "XNYS", "book.1", "alpha.1"),
        AuthorizationContextV1("leviathan-ai", "test", AT, "XNYS", "book.1", "alpha.1"),
    )


def _policy(
    *rules: PolicyRuleV1, conflict_precedence: str | None = None, **changes: object
) -> AuthorizationPolicyV1:
    policy = AuthorizationPolicyV1(
        "v1", "leviathan-ai", AT + timedelta(hours=1), rules or (_rule(),),
        conflict_precedence=conflict_precedence,
    )
    return replace(policy, **changes)


def test_matching_allow_and_default_deny() -> None:
    principal, action, resource, context = _inputs()
    allowed = authorize(principal, action, resource, context, _policy())
    assert allowed.allowed
    assert allowed.reason_code is ReasonCodeV1.AUTHORIZED
    assert allowed.explanation.rule_id is None
    missing_action = authorize(principal, ActionV1("admin.write"), resource, context, _policy())
    assert missing_action.decision is EffectV1.DENY
    assert missing_action.reason_code is ReasonCodeV1.NOT_AUTHORIZED


def test_missing_expired_conflicting_and_invalid_policy_fail_closed() -> None:
    inputs = _inputs()
    assert authorize(*inputs, None).reason_code is ReasonCodeV1.NOT_AUTHORIZED
    assert authorize(*inputs, {"version": "v1"}).reason_code is ReasonCodeV1.NOT_AUTHORIZED
    assert authorize(*inputs, _policy(expires_at=AT)).reason_code is ReasonCodeV1.NOT_AUTHORIZED
    with pytest.raises(AuthorizationModelError) as duplicate:
        _policy(_rule(), _rule())
    assert duplicate.value.reason_code is ReasonCodeV1.POLICY_INVALID
    with pytest.raises(AuthorizationModelError) as conflict:
        _policy(_rule(), _rule(EffectV1.DENY))
    assert conflict.value.reason_code is ReasonCodeV1.POLICY_CONFLICT
    assert authorize(
        *inputs, _policy(_rule(), _rule(EffectV1.DENY), conflict_precedence="DENY_OVERRIDES")
    ).reason_code is ReasonCodeV1.NOT_AUTHORIZED


@pytest.mark.parametrize("field,value", [
    ("env", "production"), ("venue", "XNAS"), ("portfolio", "book.2"),
    ("strategy", "alpha.2"), ("project_id", "other-project"),
])
def test_principal_attribute_mismatch_denies_even_admin(field: str, value: str) -> None:
    _, action, resource, context = _inputs()
    principal = _principal(**{field: value})
    decision = authorize(principal, action, resource, context, _policy())
    assert decision.reason_code is ReasonCodeV1.NOT_AUTHORIZED


def test_context_and_resource_mismatch_denies_before_rules() -> None:
    principal, action, resource, context = _inputs()
    assert authorize(
        principal, action, replace(resource, venue="XNAS"), context, _policy()
    ).reason_code is ReasonCodeV1.NOT_AUTHORIZED
    assert authorize(
        principal, action, resource, replace(context, at=AT + timedelta(minutes=2)), _policy()
    ).reason_code is ReasonCodeV1.NOT_AUTHORIZED


def test_wildcards_are_explicit_allow_only_and_never_environment() -> None:
    principal, action, resource, context = _inputs()
    broad = _rule(roles=("*",), actions=("*",), resources=("*",), venue="*",
                  portfolio="*", strategy="*")
    assert authorize(principal, action, resource, context, _policy(broad)).allowed
    with pytest.raises(AuthorizationModelError):
        replace(broad, env="*")
    with pytest.raises(AuthorizationModelError):
        _rule(EffectV1.DENY, resources=("*",))
    with pytest.raises(AuthorizationModelError):
        replace(broad, venue="X*")


def test_trusted_principal_rejects_untrusted_data_and_copy_paths() -> None:
    inputs = _inputs()
    trusted = inputs[0]
    raw = {"principal_id": "operator.1", "project_id": "leviathan-ai",
           "roles": ("risk.admin",), "env": "test"}
    with pytest.raises(TypeError):
        TrustedPrincipalV1(**raw)
    with pytest.raises(TypeError):
        TrustedPrincipalV1()
    with pytest.raises(ValueError):
        TrustedPrincipalAdapterV1.from_verified_claims(raw, verifier_marker=_VERIFIER_MARKER)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        TrustedPrincipalAdapterV1.from_verified_claims(PrincipalV1(**raw), verifier_marker=None)
    decoded = json.loads(json.dumps({**raw, "roles": list(raw["roles"])}))
    assert authorize(decoded, *inputs[1:], _policy()).reason_code is (
        ReasonCodeV1.NOT_AUTHORIZED
    )
    assert authorize(PrincipalV1(**raw), *inputs[1:], _policy()).reason_code is (
        ReasonCodeV1.NOT_AUTHORIZED
    )
    for attempt in (
        lambda: replace(trusted, env="production"),
        lambda: copy.copy(trusted),
        lambda: copy.deepcopy(trusted),
        lambda: pickle.loads(pickle.dumps(trusted)),
        lambda: TrustedPrincipalV1.model_validate(raw),  # type: ignore[attr-defined]
        lambda: trusted.model_copy(update={"env": "production"}),  # type: ignore[attr-defined]
        lambda: TrustedPrincipalV1.model_construct(**raw),  # type: ignore[attr-defined]
    ):
        with pytest.raises((TypeError, ValueError, AttributeError)):
            attempt()
    assert "_VERIFIER_MARKER" not in security.__all__
    assert not hasattr(security, "_VERIFIER_MARKER")


def test_policy_replace_validates_and_no_public_value_copies() -> None:
    policy = _policy()
    for attempt in (lambda: copy.copy(policy), lambda: copy.deepcopy(policy),
                    lambda: pickle.loads(pickle.dumps(policy))):
        with pytest.raises(TypeError):
            attempt()
    with pytest.raises(AuthorizationModelError):
        replace(policy, version="v2")
    with pytest.raises(AuthorizationModelError):
        replace(policy, rules=(_rule(), _rule()))


def test_break_glass_requires_verified_bounded_evidence() -> None:
    _, action, resource, context = _inputs()
    principal = _principal(break_glass=True)
    policy = _policy()
    assert authorize(principal, action, resource, context, policy).reason_code is (
        ReasonCodeV1.NOT_AUTHORIZED
    )
    evidence = BreakGlassEvidenceV1(
        "operator.1", ("approver.1", "approver.2"), ("research.read",),
        AT - timedelta(minutes=1), AT + timedelta(minutes=29),
    )
    assert authorize(
        principal, action, resource, context, policy, break_glass_evidence=evidence
    ).reason_code is ReasonCodeV1.NOT_AUTHORIZED
    with pytest.raises(AuthorizationModelError):
        replace(evidence, approver_ids=("approver.1", "approver.1"))
    with pytest.raises(AuthorizationModelError):
        replace(evidence, expires_at=AT + timedelta(minutes=31))
    with pytest.raises(ValueError):
        BreakGlassEvidenceV1._from_verified_adapter(
            requester_id="operator.1", approver_ids=("approver.1", "approver.2"),
            scope=("research.read",), issued_at=AT, expires_at=AT + timedelta(minutes=1),
            verifier_marker=None,
        )
    verified = BreakGlassEvidenceV1._from_verified_adapter(
        requester_id="operator.1", approver_ids=("approver.1", "approver.2"),
        scope=("research.read",), issued_at=AT, expires_at=AT + timedelta(minutes=1),
        verifier_marker=_VERIFIER_MARKER,
    )
    assert authorize(
        principal, action, resource, context, policy, break_glass_evidence=verified
    ).reason_code is ReasonCodeV1.AUTHORIZED
    assert authorize(
        principal, ActionV1("admin.write"), resource, context, policy,
        break_glass_evidence=verified,
    ).reason_code is ReasonCodeV1.NOT_AUTHORIZED


def test_denial_oracle_closed_and_detail_restricted_to_private_audit() -> None:
    principal, action, hidden, context = _inputs()
    unknown = replace(hidden, resource_id="unknown.book")
    policy = _policy(_rule(EffectV1.DENY))
    hidden_public = authorize(principal, action, hidden, context, policy)
    unknown_public = authorize(principal, action, unknown, context, policy)
    assert hidden_public.explanation == unknown_public.explanation
    assert hidden_public.explanation.rule_id is None
    assert hidden_public.reason_code is ReasonCodeV1.NOT_AUTHORIZED
    with pytest.raises(AuthorizationModelError):
        replace(hidden_public.explanation, rule_id="deny.1")
    with pytest.raises(AuthorizationModelError):
        replace(hidden_public.explanation, reason_code=ReasonCodeV1.DENY_RULE)
    with pytest.raises(PermissionError):
        _authorize_with_audit(
            principal, action, hidden, context, policy, audit_marker=None,
        )
    _, hidden_audit = _authorize_with_audit(
        principal, action, hidden, context, policy, audit_marker=_AUDIT_MARKER,
    )
    _, unknown_audit = _authorize_with_audit(
        principal, action, unknown, context, policy, audit_marker=_AUDIT_MARKER,
    )
    assert (hidden_audit.reason_code, hidden_audit.rule_id, hidden_audit.policy_version) == (
        ReasonCodeV1.DENY_RULE, "deny.1", "v1",
    )
    assert (unknown_audit.reason_code, unknown_audit.rule_id) == (
        ReasonCodeV1.DEFAULT_DENY, None,
    )
    with pytest.raises(AuthorizationModelError):
        _rule(rule_id="sk_TEST_SYNTHETIC_NOT_A_REAL_KEY_ABCDEF1234567890")
    assert not hasattr(security, "_authorize_with_audit")


@pytest.mark.parametrize("canary", ["sk_test_synthetic_canary", "test_user.ssn.0000"])
def test_public_allow_does_not_echo_sensitive_rule_id(canary: str) -> None:
    principal, action, resource, context = _inputs()
    policy = _policy(_rule(rule_id=canary))
    public = authorize(principal, action, resource, context, policy)
    assert public.allowed
    assert public.explanation.rule_id is None
    assert canary not in str(public)
    _, audit = _authorize_with_audit(
        principal, action, resource, context, policy, audit_marker=_AUDIT_MARKER,
    )
    assert audit.rule_id == canary
    with pytest.raises(AuthorizationModelError):
        replace(public.explanation, rule_id=canary)


def test_explanation_is_redacted() -> None:
    principal, action, resource, context = _inputs()
    decision = authorize(principal, action, resource, context, _policy())
    assert set(vars(type(decision.explanation))) >= {"rule_id", "decision", "reason_code"}
    rendered = str(decision)
    for hidden in ("research.private", "leviathan-ai", "XNYS", "book.1", "alpha.1"):
        assert hidden not in rendered
