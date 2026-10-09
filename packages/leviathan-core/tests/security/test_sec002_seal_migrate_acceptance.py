"""Independent acceptance for CL-SEC002-SEAL issued authorization values."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from leviathan_core.security.authz_models import (
    _VERIFIER_MARKER,
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
    is_authorization_decision,
    is_trusted_principal,
    require_authorization_decision,
    require_trusted_principal,
)
from leviathan_core.security.authz_policy import authorize

_AT = datetime(2026, 10, 6, 12, tzinfo=UTC)
_UNIFORM_DENY = AuthorizationExplanationV1(
    None, EffectV1.DENY, ReasonCodeV1.NOT_AUTHORIZED
)
_PRINCIPAL_FIELDS = (
    "principal_id",
    "project_id",
    "roles",
    "env",
    "venue",
    "portfolio",
    "strategy",
    "break_glass",
)


def _claims() -> PrincipalV1:
    return PrincipalV1(
        principal_id="operator.acceptance",
        project_id="project.acceptance",
        roles=("security.reader",),
        env="development",
    )


def _issued_principal() -> TrustedPrincipalV1:
    return TrustedPrincipalAdapterV1.from_verified_claims(
        _claims(), verifier_marker=_VERIFIER_MARKER
    )


def _hand_built_principal() -> TrustedPrincipalV1:
    claims = _claims()
    value = object.__new__(TrustedPrincipalV1)
    for name in _PRINCIPAL_FIELDS:
        object.__setattr__(value, name, getattr(claims, name))
    return value


def _authorization_inputs() -> tuple[
    ActionV1, ResourceV1, AuthorizationContextV1, AuthorizationPolicyV1
]:
    action = ActionV1("report.read")
    resource = ResourceV1("report.acceptance", "project.acceptance", "development")
    context = AuthorizationContextV1("project.acceptance", "development", _AT)
    rule = PolicyRuleV1(
        rule_id="acceptance.allow",
        effect=EffectV1.ALLOW,
        roles=("security.reader",),
        actions=(action.name,),
        resources=(resource.resource_id,),
        env="development",
        not_before=_AT - timedelta(minutes=1),
        not_after=_AT + timedelta(minutes=1),
    )
    policy = AuthorizationPolicyV1(
        "v1", "project.acceptance", _AT + timedelta(hours=1), (rule,)
    )
    return action, resource, context, policy


def test_hand_built_principal_is_unissued_and_authorize_denies_uniformly() -> None:
    forged = _hand_built_principal()

    assert not is_trusted_principal(forged)
    with pytest.raises(AuthorizationModelError) as raised:
        require_trusted_principal(forged)
    assert raised.value.reason_code is ReasonCodeV1.PRINCIPAL_UNTRUSTED

    action, resource, context, policy = _authorization_inputs()
    decision = authorize(forged, action, resource, context, policy)
    assert decision.explanation == _UNIFORM_DENY
    assert is_authorization_decision(decision)
    assert require_authorization_decision(decision) is decision


def test_hand_built_allow_decision_is_unissued_and_cannot_pass_require() -> None:
    forged = AuthorizationDecisionV1(
        AuthorizationExplanationV1(
            None, EffectV1.ALLOW, ReasonCodeV1.AUTHORIZED
        )
    )

    assert forged.allowed
    assert not is_authorization_decision(forged)
    with pytest.raises(AuthorizationModelError) as raised:
        require_authorization_decision(forged)
    assert raised.value.reason_code is ReasonCodeV1.NOT_AUTHORIZED


def test_adapter_issued_principal_passes_public_require() -> None:
    principal = _issued_principal()

    assert is_trusted_principal(principal)
    assert require_trusted_principal(principal) is principal


def test_authorize_issued_decision_passes_public_require() -> None:
    action, resource, context, policy = _authorization_inputs()
    decision = authorize(_issued_principal(), action, resource, context, policy)

    assert decision.decision is EffectV1.ALLOW
    assert is_authorization_decision(decision)
    assert require_authorization_decision(decision) is decision


@pytest.mark.parametrize("forged", [None, object(), True])
def test_non_decision_values_are_not_issued(forged: object) -> None:
    assert not is_authorization_decision(forged)
    with pytest.raises(AuthorizationModelError):
        require_authorization_decision(forged)

