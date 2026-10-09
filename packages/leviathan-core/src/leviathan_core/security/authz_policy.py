"""Pure, default-deny SEC-002 RBAC/ABAC policy evaluation.

This decision is neither a route permit nor an audit commit. The caller must
journal the result and independently pass C-101/HALT/OMS before any effect.
"""

from __future__ import annotations

from datetime import datetime
from typing import Final

from leviathan_core.seal import Issuer, verify

from .authz_models import (
    AUTHORIZATION_DECISION_TAG,
    TRUSTED_PRINCIPAL_TAG,
    ActionV1,
    AuthorizationContextV1,
    AuthorizationDecisionV1,
    AuthorizationExplanationV1,
    AuthorizationPolicyV1,
    AuthzAuditRecordV1,
    BreakGlassEvidenceV1,
    EffectV1,
    PolicyRuleV1,
    ReasonCodeV1,
    ResourceV1,
    TrustedPrincipalV1,
)

_AUDIT_MARKER: Final[object] = object()
# Module-private SEAL-001 capability: only ``authorize()`` can issue a decision.
_DECISION_ISSUER: Final = Issuer(AUTHORIZATION_DECISION_TAG)


def _outcome(
    effect: EffectV1,
    detail: ReasonCodeV1,
    rule_id: str | None = None,
    policy_version: str | None = None,
) -> tuple[AuthorizationDecisionV1, AuthzAuditRecordV1]:
    """Keep policy detail in the restricted audit record only."""

    public_reason = (
        ReasonCodeV1.NOT_AUTHORIZED if effect is EffectV1.DENY else ReasonCodeV1.AUTHORIZED
    )
    public = _DECISION_ISSUER.issue(
        AuthorizationDecisionV1(AuthorizationExplanationV1(None, effect, public_reason))
    )
    audit = AuthzAuditRecordV1(effect, detail, rule_id, policy_version)
    return public, audit


def _match_token(value: str, options: tuple[str, ...], *, allow_wildcard: bool) -> bool:
    return value in options or (allow_wildcard and "*" in options)


def _match_attr(value: str | None, rule_value: str | None, *, allow_wildcard: bool) -> bool:
    return value == rule_value or (allow_wildcard and rule_value == "*")


def _matches(
    rule: PolicyRuleV1,
    principal: TrustedPrincipalV1,
    action: ActionV1,
    resource: ResourceV1,
    context: AuthorizationContextV1,
) -> bool:
    wildcard = rule.effect is EffectV1.ALLOW
    return (
        ("*" in rule.roles if wildcard else False)
        or any(role in rule.roles for role in principal.roles)
    ) and all(
        (
            _match_token(action.name, rule.actions, allow_wildcard=wildcard),
            _match_token(resource.resource_id, rule.resources, allow_wildcard=wildcard),
            rule.env == context.env,
            _match_attr(context.venue, rule.venue, allow_wildcard=wildcard),
            _match_attr(context.portfolio, rule.portfolio, allow_wildcard=wildcard),
            _match_attr(context.strategy, rule.strategy, allow_wildcard=wildcard),
            rule.not_before <= context.at < rule.not_after,
        )
    )


def _attributes_match(
    principal: TrustedPrincipalV1,
    resource: ResourceV1,
    context: AuthorizationContextV1,
    policy: AuthorizationPolicyV1,
) -> bool:
    if not (
        principal.project_id == resource.project_id == context.project_id == policy.project_id
        and principal.env == resource.env == context.env
    ):
        return False
    return all(
        getattr(principal, name) == getattr(resource, name) == getattr(context, name)
        for name in ("venue", "portfolio", "strategy")
    )


def _break_glass_valid(
    evidence: object, principal: TrustedPrincipalV1, action: ActionV1, at: datetime
) -> bool:
    if type(evidence) is not BreakGlassEvidenceV1:
        return False
    return (
        evidence.verified is True
        and evidence.requester_id == principal.principal_id
        and action.name in evidence.scope
        and evidence.issued_at <= at < evidence.expires_at
    )


def _authorize_validated(
    principal: object,
    action: object,
    resource: object,
    context: object,
    policy: object | None,
    *,
    break_glass_evidence: object | None = None,
) -> tuple[AuthorizationDecisionV1, AuthzAuditRecordV1]:
    """Evaluate a policy using the context's injected UTC clock; never allow on error.

    Validation precedes attributes, then all deny rules, then allow rules. The
    public explanation is closed; detailed causes stay in a private audit record.
    """

    if policy is None:
        return _outcome(EffectV1.DENY, ReasonCodeV1.POLICY_MISSING)
    if type(policy) is not AuthorizationPolicyV1:
        return _outcome(EffectV1.DENY, ReasonCodeV1.POLICY_INVALID)
    try:
        policy.__post_init__()
    except Exception:
        return _outcome(EffectV1.DENY, ReasonCodeV1.POLICY_INVALID)
    version = policy.version
    if type(context) is not AuthorizationContextV1:
        return _outcome(EffectV1.DENY, ReasonCodeV1.CONTEXT_INVALID, policy_version=version)
    try:
        context.__post_init__()
    except Exception:
        return _outcome(EffectV1.DENY, ReasonCodeV1.CONTEXT_INVALID, policy_version=version)
    if policy.expires_at <= context.at:
        return _outcome(EffectV1.DENY, ReasonCodeV1.POLICY_EXPIRED, policy_version=version)
    # An unissued or altered principal is the same uniform DENY as any untrusted one.
    if type(principal) is not TrustedPrincipalV1 or not verify(principal, TRUSTED_PRINCIPAL_TAG):
        return _outcome(EffectV1.DENY, ReasonCodeV1.PRINCIPAL_UNTRUSTED, policy_version=version)
    if type(action) is not ActionV1 or type(resource) is not ResourceV1:
        return _outcome(EffectV1.DENY, ReasonCodeV1.CONTEXT_INVALID, policy_version=version)
    try:
        action.__post_init__()
        resource.__post_init__()
    except Exception:
        return _outcome(EffectV1.DENY, ReasonCodeV1.CONTEXT_INVALID, policy_version=version)
    if not _attributes_match(principal, resource, context, policy):
        return _outcome(EffectV1.DENY, ReasonCodeV1.ATTRIBUTE_MISMATCH, policy_version=version)
    if principal.break_glass and not _break_glass_valid(
        break_glass_evidence, principal, action, context.at
    ):
        return _outcome(EffectV1.DENY, ReasonCodeV1.BREAK_GLASS_UNVERIFIED,
                        policy_version=version)
    for rule in policy.rules:
        if rule.effect is EffectV1.DENY and _matches(rule, principal, action, resource, context):
            return _outcome(EffectV1.DENY, ReasonCodeV1.DENY_RULE, rule.rule_id, version)
    for rule in policy.rules:
        if rule.effect is EffectV1.ALLOW and _matches(rule, principal, action, resource, context):
            return _outcome(EffectV1.ALLOW, ReasonCodeV1.ALLOW_RULE, rule.rule_id, version)
    return _outcome(EffectV1.DENY, ReasonCodeV1.DEFAULT_DENY, policy_version=version)


def _authorize_with_audit(
    principal: object,
    action: object,
    resource: object,
    context: object,
    policy: object | None,
    *,
    audit_marker: object,
    break_glass_evidence: object | None = None,
) -> tuple[AuthorizationDecisionV1, AuthzAuditRecordV1]:
    """Internal audit-writer API; never import this in a public adapter.

    The leading underscore and absence from the package exports mark the
    boundary. A module-private identity marker is required as well. A future
    restricted audit writer must be explicitly granted both private imports;
    public adapters use only ``authorize``. In-process code is trusted.
    """

    if audit_marker is not _AUDIT_MARKER:
        raise PermissionError("restricted authorization audit access required")

    try:
        return _authorize_validated(
            principal, action, resource, context, policy,
            break_glass_evidence=break_glass_evidence,
        )
    except Exception:
        return _outcome(EffectV1.DENY, ReasonCodeV1.POLICY_INVALID)


def authorize(
    principal: object,
    action: object,
    resource: object,
    context: object,
    policy: object | None,
    *,
    break_glass_evidence: object | None = None,
) -> AuthorizationDecisionV1:
    """Public decision API; never returns restricted audit detail."""

    public, _audit = _authorize_with_audit(
        principal, action, resource, context, policy,
        audit_marker=_AUDIT_MARKER,
        break_glass_evidence=break_glass_evidence,
    )
    return public
