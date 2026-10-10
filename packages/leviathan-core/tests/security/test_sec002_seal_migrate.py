"""CL-SEC002-SEAL: SEAL-001 issuance of the SEC-002 trust types.

A principal is issued only by the verified adapter (and the verifier through it);
a decision only by ``authorize()``. Everything built any other way is unissued.
"""

from __future__ import annotations

import types
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from leviathan_core.seal import Issuer, SealError, verify
from leviathan_core.security import (
    ActionV1,
    AuthorizationContextV1,
    AuthorizationDecisionV1,
    AuthorizationExplanationV1,
    AuthorizationModelError,
    AuthorizationPolicyV1,
    EffectV1,
    PolicyRuleV1,
    PrincipalV1,
    ReasonCodeV1,
    ResourceV1,
    TrustedPrincipalAdapterV1,
    TrustedPrincipalV1,
    authorize,
)
from leviathan_core.security.authz_models import (
    _VERIFIER_MARKER,
    AUTHORIZATION_DECISION_TAG,
    TRUSTED_PRINCIPAL_TAG,
    is_authorization_decision,
    is_trusted_principal,
    require_authorization_decision,
    require_trusted_principal,
)
from leviathan_core.security.principal_verifier import PrincipalVerifier

AT = datetime(2026, 9, 30, 12, tzinfo=UTC)
_FIELDS = (
    "principal_id",
    "project_id",
    "roles",
    "env",
    "venue",
    "portfolio",
    "strategy",
    "break_glass",
    "device_id",
)
_UNIFORM_DENY = AuthorizationExplanationV1(None, EffectV1.DENY, ReasonCodeV1.NOT_AUTHORIZED)


def _claims(**changes: object) -> PrincipalV1:
    claims = PrincipalV1(
        principal_id="operator.1",
        project_id="leviathan-ai",
        roles=("risk.admin",),
        env="test",
        venue="XNYS",
        portfolio="book.1",
        strategy="alpha.1",
    )
    return replace(claims, **changes)


def _issued(**changes: object) -> TrustedPrincipalV1:
    return TrustedPrincipalAdapterV1.from_verified_claims(
        _claims(**changes), verifier_marker=_VERIFIER_MARKER
    )


def _hand_built(**changes: object) -> TrustedPrincipalV1:
    """The only way to get a TrustedPrincipalV1 without the adapter: bypass __new__."""
    claims = _claims(**changes)
    principal = object.__new__(TrustedPrincipalV1)
    for name in _FIELDS:
        object.__setattr__(principal, name, getattr(claims, name))
    return principal


def _inputs() -> tuple[ActionV1, ResourceV1, AuthorizationContextV1, AuthorizationPolicyV1]:
    rule = PolicyRuleV1(
        rule_id="allow.1",
        effect=EffectV1.ALLOW,
        roles=("risk.admin",),
        actions=("research.read",),
        resources=("research.private",),
        env="test",
        not_before=AT - timedelta(minutes=1),
        not_after=AT + timedelta(minutes=1),
        venue="XNYS",
        portfolio="book.1",
        strategy="alpha.1",
    )
    return (
        ActionV1("research.read"),
        ResourceV1("research.private", "leviathan-ai", "test", "XNYS", "book.1", "alpha.1"),
        AuthorizationContextV1("leviathan-ai", "test", AT, "XNYS", "book.1", "alpha.1"),
        AuthorizationPolicyV1("v1", "leviathan-ai", AT + timedelta(hours=1), (rule,)),
    )


def test_adapter_issues_the_principal_and_require_returns_it() -> None:
    principal = _issued()
    assert type(principal) is TrustedPrincipalV1
    assert verify(principal, TRUSTED_PRINCIPAL_TAG)
    assert is_trusted_principal(principal)
    assert require_trusted_principal(principal) is principal
    action, resource, context, policy = _inputs()
    assert authorize(principal, action, resource, context, policy).allowed


def test_verifier_path_goes_through_the_issuing_adapter() -> None:
    claims = _claims()
    stub = types.SimpleNamespace(to_sec002_claims=lambda verified: claims)
    principal = PrincipalVerifier.to_trusted_principal(stub, object())  # type: ignore[arg-type]
    assert is_trusted_principal(principal) and require_trusted_principal(principal) is principal


def test_hand_built_principal_is_unissued_and_denied_uniformly() -> None:
    forged = _hand_built()
    assert type(forged) is TrustedPrincipalV1
    assert not verify(forged, TRUSTED_PRINCIPAL_TAG) and not is_trusted_principal(forged)
    with pytest.raises(AuthorizationModelError) as raised:
        require_trusted_principal(forged)
    assert raised.value.reason_code is ReasonCodeV1.PRINCIPAL_UNTRUSTED
    action, resource, context, policy = _inputs()
    assert authorize(_issued(), action, resource, context, policy).allowed  # twin is allowed
    decision = authorize(forged, action, resource, context, policy)
    assert not decision.allowed and decision.explanation == _UNIFORM_DENY
    # Indistinguishable from any other denial at the public boundary.
    other = authorize(_issued(), ActionV1("admin.write"), resource, context, policy)
    assert other.explanation == decision.explanation


def test_public_construction_is_still_blocked() -> None:
    with pytest.raises(TypeError):
        TrustedPrincipalV1(**{name: "x" for name in _FIELDS})  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        TrustedPrincipalV1()  # type: ignore[call-arg]


def test_altering_an_issued_principal_revokes_its_standing() -> None:
    principal = _issued()
    object.__setattr__(principal, "roles", ("risk.admin", "extra.role"))
    assert not is_trusted_principal(principal)
    with pytest.raises(AuthorizationModelError):
        require_trusted_principal(principal)
    action, resource, context, policy = _inputs()
    assert authorize(principal, action, resource, context, policy).explanation == _UNIFORM_DENY


def test_other_types_and_wrong_issuers_are_rejected() -> None:
    for value in (None, "operator.1", _claims(), types.SimpleNamespace(), object()):
        assert not is_trusted_principal(value)
        with pytest.raises(AuthorizationModelError):
            require_trusted_principal(value)
    decision = authorize(_issued(), *_inputs()[:3], _inputs()[3])
    # A decision is not a principal, and a principal is not a decision.
    assert not is_trusted_principal(decision) and not is_authorization_decision(_issued())
    with pytest.raises(AuthorizationModelError):
        require_authorization_decision(_issued())
    # Another kernel's issuer cannot stand in for SEC-002's capability.
    foreign = Issuer("cl.sec002.test.foreign")
    borrowed = foreign.issue(_hand_built())
    assert not is_trusted_principal(borrowed)


def test_authorize_issues_its_decision_and_require_returns_it() -> None:
    action, resource, context, policy = _inputs()
    for principal, expected in ((_issued(), EffectV1.ALLOW), (_hand_built(), EffectV1.DENY)):
        decision = authorize(principal, action, resource, context, policy)
        assert decision.decision is expected
        assert verify(decision, AUTHORIZATION_DECISION_TAG) and is_authorization_decision(decision)
        assert require_authorization_decision(decision) is decision
    # Every call yields a distinct issued object.
    first = authorize(_issued(), action, resource, context, policy)
    second = authorize(_issued(), action, resource, context, policy)
    assert first is not second and first == second


def test_hand_built_decision_is_unissued() -> None:
    explanation = AuthorizationExplanationV1(None, EffectV1.ALLOW, ReasonCodeV1.AUTHORIZED)
    forged = AuthorizationDecisionV1(explanation)
    assert forged.allowed  # a plain value still behaves, but carries no standing
    assert not verify(forged, AUTHORIZATION_DECISION_TAG)
    assert not is_authorization_decision(forged)
    with pytest.raises(AuthorizationModelError) as raised:
        require_authorization_decision(forged)
    assert raised.value.reason_code is ReasonCodeV1.NOT_AUTHORIZED
    for value in (None, explanation, True, object()):
        assert not is_authorization_decision(value)
        with pytest.raises(AuthorizationModelError):
            require_authorization_decision(value)


def test_altering_an_issued_decision_revokes_its_standing() -> None:
    action, resource, context, policy = _inputs()
    decision = authorize(_hand_built(), action, resource, context, policy)
    assert decision.decision is EffectV1.DENY and is_authorization_decision(decision)
    object.__setattr__(decision.explanation, "decision", EffectV1.ALLOW)
    object.__setattr__(decision.explanation, "reason_code", ReasonCodeV1.AUTHORIZED)
    assert decision.allowed  # the value now lies ...
    assert not is_authorization_decision(decision)  # ... but is no longer issued
    with pytest.raises(AuthorizationModelError):
        require_authorization_decision(decision)


def test_issuers_are_module_private_and_unforgeable() -> None:
    for tag in (TRUSTED_PRINCIPAL_TAG, AUTHORIZATION_DECISION_TAG):
        with pytest.raises(SealError) as duplicate:
            Issuer(tag)
        assert duplicate.value.code == "SEAL_DUPLICATE_TAG"
        forged = (
            _hand_built()
            if tag == TRUSTED_PRINCIPAL_TAG
            else AuthorizationDecisionV1(
                AuthorizationExplanationV1(None, EffectV1.ALLOW, ReasonCodeV1.AUTHORIZED)
            )
        )
        with pytest.raises(SealError) as impostor:
            Issuer.issue(types.SimpleNamespace(tag=tag), forged)  # type: ignore[arg-type]
        assert impostor.value.code == "SEAL_FORBIDDEN_OPERATION"
        assert not verify(forged, tag)
    # No public name exposes either issuer.
    import leviathan_core.security.authz_models as models
    import leviathan_core.security.authz_policy as policy_module

    public = [name for name in dir(models) + dir(policy_module) if not name.startswith("_")]
    assert not any(isinstance(getattr(models, name, None), Issuer) for name in public)
    assert not any(isinstance(getattr(policy_module, name, None), Issuer) for name in public)
