from __future__ import annotations

import pytest
from pydantic import ValidationError

from leviathan_api.chat.capabilities_v1 import (
    ACTION_POLICIES,
    ACTION_POLICY_BY_ID,
    CAPABILITY_BY_ID,
    CAPABILITY_POLICIES,
    PROTECTED_O2_ACTIONS,
    ActionPolicyV1,
    CapabilityInputFieldV1,
    CapabilityLifecycleV1,
    CapabilityPolicyV1,
    ConfirmationClassV1,
    DelegationActionTypeV1,
    DelegationGrantV1,
    EnvironmentV1,
    FreshnessRequirementV1,
    InputKindV1,
    ModeAdmissionCodeV1,
    ModeAdmissionRequestV1,
    O2AuthorizationCodeV1,
    OperatingModeV1,
    assess_mode_admission,
    authorize_o2_action,
    create_delegation_grant,
    default_mode_assignment,
    mode_allows_effect,
    revoke_delegation_grant,
    validate_contract_tables,
)
from leviathan_api.chat.tool_bridge import _REGISTRY


def test_all_policy_rows_are_typed_unique_and_have_reviewable_audit_shape() -> None:
    validate_contract_tables()
    assert len(CAPABILITY_POLICIES) == len(CAPABILITY_BY_ID)
    assert len(ACTION_POLICIES) == len(ACTION_POLICY_BY_ID)
    assert {row.capability_id for row in CAPABILITY_POLICIES} == {
        row.capability_id for row in ACTION_POLICIES
    }
    for row in CAPABILITY_POLICIES:
        assert row.domain
        assert row.input_model and row.output_model
        assert row.scope
        assert row.audit_event.required_fields
        assert {"capability_id", "principal_id", "occurred_at_ns", "input_digest"}.issubset(
            row.audit_event.required_fields
        )
        assert row.lifecycle in {CapabilityLifecycleV1.CURRENT, CapabilityLifecycleV1.PLANNED}


def test_permission_table_covers_each_discovery_action_family() -> None:
    required = {
        "paper.orders.create_submit",
        "orders.activity.read",
        "orders.cancel",
        "paper.mass_cancel",
        "paper.activation.status.read",
        "paper.activation.activate",
        "paper.activation.revoke",
        "paper.session.pause_resume",
        "paper.account.read",
        "halt.status.read",
        "halt.engage",
        "halt.lift",
        "live.status.read",
        "live.enable",
        "live.disable",
        "mcp.policy.tools",
        "risk.policy.read",
        "risk.status.read",
        "risk.assess",
        "risk.limits.tighten",
        "risk.limits.relax",
        "connections.status.read",
        "connections.credentials.status.read",
        "connections.credentials.test",
        "connections.connect",
        "connections.test",
        "connections.cancel_connect",
        "connections.disconnect",
        "data_sources.status.read",
        "credentials.status.read",
        "credentials.change",
        "credentials.put",
        "credentials.delete",
        "genomes.list",
        "knowledge.archive.search",
        "strategy.inspect",
        "strategy.create",
        "strategy.update",
        "strategy.build",
        "strategy.paper_promote",
        "ea.templates.list",
        "ea.template.install",
        "ea.host.status.read",
        "ea.create",
        "ea.compile_sandbox",
        "ea.deploy",
        "presets.inspect",
        "presets.import",
        "presets.apply",
        "indicators.define",
        "indicators.calculate",
        "charts.snapshot.read",
        "charts.plot",
        "charts.annotate",
        "backtest.run",
        "backtest.result.read",
        "pipeline.attempt.read",
        "pipeline.replay.run",
        "pipeline.replay.general",
        "journal.records.read",
        "journal.records.search",
        "journal.audit.append",
        "preferences.put",
        "settings.write",
        "theme.apply",
        "market.snapshot.read",
        "market.morning_brief",
        "market.tape.read",
        "market.backfill",
        "mode.select.analysis",
        "mode.select.semi_auto",
        "trade_card.generate",
        "trade_card.approve",
        "trade_card.reject",
        "mode.full_auto.enroll",
        "full_auto.order.submit",
        "full_auto.disengage",
    }
    assert required == set(ACTION_POLICY_BY_ID)
    assert all(
        row.lifecycle is CapabilityLifecycleV1.PLANNED
        for action_id, row in ACTION_POLICY_BY_ID.items()
        if action_id not in {entry.tool_id for entry in _REGISTRY} | {"halt.engage"}
    )


def test_freshness_can_bind_a_source_policy_or_an_explicit_bound() -> None:
    assert FreshnessRequirementV1(source="risk_status", policy_ref="risk.status.freshness").required
    assert FreshnessRequirementV1(source="market_data", max_age_ns=5_000_000_000).required
    with pytest.raises(ValidationError, match="CAPABILITY_SCHEMA_INVALID"):
        FreshnessRequirementV1(source="market_data")
    with pytest.raises(ValidationError, match="CAPABILITY_SCHEMA_INVALID"):
        FreshnessRequirementV1(
            source="market_data", max_age_ns=5_000_000_000, policy_ref="market.live"
        )


def test_current_contract_rows_match_the_closed_chat_registry_and_effect_class() -> None:
    current = {
        row.capability_id: row
        for row in CAPABILITY_POLICIES
        if row.lifecycle is CapabilityLifecycleV1.CURRENT
    }
    # HALT engage is contract-current and always chat-available; registry
    # wiring is intentionally sequenced in a later adoption lane.
    assert set(current) == {row.tool_id for row in _REGISTRY} | {"halt.engage"}
    for entry in _REGISTRY:
        row = current[entry.tool_id]
        if entry.capability == "read":
            assert row.confirmation_class is ConfirmationClassV1.R0
            assert entry.confirmation_parity == "none"
        else:
            assert row.confirmation_class is ConfirmationClassV1.E1
            assert entry.confirmation_parity == "typed_confirmation"


@pytest.mark.parametrize("action_id", sorted(PROTECTED_O2_ACTIONS))
def test_privileged_actions_are_never_classified_below_o2(action_id: str) -> None:
    assert ACTION_POLICY_BY_ID[action_id].confirmation_class is ConfirmationClassV1.O2


def test_secret_typed_inputs_are_rejected_by_capability_schema() -> None:
    assert all(
        field.kind is not InputKindV1.SECRET
        for row in CAPABILITY_POLICIES
        for field in row.input_fields
    )
    with pytest.raises(ValidationError, match="SECRET_INPUT_FORBIDDEN"):
        CapabilityInputFieldV1(name="api_key", kind=InputKindV1.SECRET)


def test_default_mode_is_analysis_scoped_to_account_and_venue() -> None:
    mode = default_mode_assignment("acct-01", "venue-01")
    assert mode.account_id == "acct-01"
    assert mode.venue == "venue-01"
    assert mode.mode is OperatingModeV1.ANALYSIS
    assert mode.revision == 0


def test_mode_effects_are_narrower_than_the_confirmation_class() -> None:
    assert not mode_allows_effect("paper.orders.create_submit", OperatingModeV1.ANALYSIS)
    assert not mode_allows_effect("paper.orders.create_submit", OperatingModeV1.SEMI_AUTO)
    assert mode_allows_effect("trade_card.approve", OperatingModeV1.SEMI_AUTO)
    assert not mode_allows_effect("trade_card.approve", OperatingModeV1.FULL_AUTO)
    assert mode_allows_effect("full_auto.order.submit", OperatingModeV1.FULL_AUTO)
    assert not mode_allows_effect("paper.mass_cancel", OperatingModeV1.FULL_AUTO)
    assert not mode_allows_effect("live.enable", OperatingModeV1.FULL_AUTO)


@pytest.mark.parametrize("mode", tuple(OperatingModeV1))
def test_halt_engage_is_an_always_available_protective_effect(mode: OperatingModeV1) -> None:
    row = CAPABILITY_BY_ID["halt.engage"]
    assert row.confirmation_class is ConfirmationClassV1.E1
    assert row.requires_per_action_confirmation is False
    assert row.lifecycle is CapabilityLifecycleV1.CURRENT
    assert row.chat_surface.value == "tool"
    assert mode_allows_effect("halt.engage", mode)
    assert not mode_allows_effect("halt.lift", mode)
    assert not mode_allows_effect("halt.engage", "unknown")  # type: ignore[arg-type]


def test_each_mode_effect_allowlist_is_a_strict_subset_of_its_class() -> None:
    mode_classes = {
        OperatingModeV1.ANALYSIS: {ConfirmationClassV1.E1},
        OperatingModeV1.SEMI_AUTO: {ConfirmationClassV1.E1, ConfirmationClassV1.A3},
        OperatingModeV1.FULL_AUTO: {ConfirmationClassV1.E1, ConfirmationClassV1.F4},
    }
    for mode, eligible_classes in mode_classes.items():
        class_effects = {
            row.capability_id
            for row in CAPABILITY_POLICIES
            if row.confirmation_class in eligible_classes
        }
        mode_effects = {
            row.capability_id
            for row in CAPABILITY_POLICIES
            if mode_allows_effect(row.capability_id, mode)
        }
        assert mode_effects < class_effects
        assert all(
            ACTION_POLICY_BY_ID[action_id].confirmation_class is not ConfirmationClassV1.R0
            for action_id in mode_effects
        )


class _LiveGate:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def live_account_enabled(self, account_id: str) -> bool:
        assert account_id == "acct-01"
        return self.enabled


class _BrokenLiveGate:
    def live_account_enabled(self, account_id: str) -> bool:
        del account_id
        raise RuntimeError("must be content-free")


def _full_auto_request(
    *, environment: EnvironmentV1, first: bool = False
) -> ModeAdmissionRequestV1:
    return ModeAdmissionRequestV1(
        account_id="acct-01",
        venue="venue-01",
        mode=OperatingModeV1.FULL_AUTO,
        environment=environment,
        first_full_auto_enrollment=first,
    )


def test_full_auto_live_requires_the_live_gate_and_fails_closed() -> None:
    request = _full_auto_request(environment=EnvironmentV1.LIVE)
    assert assess_mode_admission(request).code is ModeAdmissionCodeV1.LIVE_GATE_REQUIRED
    assert (
        assess_mode_admission(request, _LiveGate(False)).code
        is ModeAdmissionCodeV1.LIVE_GATE_REQUIRED
    )
    assert (
        assess_mode_admission(request, _BrokenLiveGate()).code
        is ModeAdmissionCodeV1.LIVE_GATE_REQUIRED
    )
    assert assess_mode_admission(request, _LiveGate(True)).allowed is True


def test_first_full_auto_enrollment_is_paper_only_even_with_live_gate() -> None:
    request = _full_auto_request(environment=EnvironmentV1.LIVE, first=True)
    result = assess_mode_admission(request, _LiveGate(True))
    assert result.allowed is False
    assert result.code is ModeAdmissionCodeV1.PAPER_FIRST_REQUIRED
    paper = assess_mode_admission(_full_auto_request(environment=EnvironmentV1.PAPER, first=True))
    assert paper.allowed is True


def test_action_policy_rows_are_strictly_typed_and_not_secret_bearing() -> None:
    assert all(type(row) is ActionPolicyV1 for row in ACTION_POLICIES)
    assert all(row.action_id == row.capability_id for row in ACTION_POLICIES)
    assert all(
        field.kind is not InputKindV1.SECRET
        for row in CAPABILITY_POLICIES
        for field in row.input_fields
    )


def test_policy_models_reject_o2_downgrade_and_secret_bypasses() -> None:
    capability = CAPABILITY_BY_ID["live.enable"]
    with pytest.raises(ValidationError, match="PROTECTED_ACTION_CLASS_INVALID"):
        CapabilityPolicyV1(
            **{
                **capability.model_dump(mode="python"),
                "confirmation_class": ConfirmationClassV1.E1,
            }
        )
    with pytest.raises(ValidationError, match="PROTECTED_ACTION_CLASS_INVALID"):
        capability.model_copy(update={"confirmation_class": ConfirmationClassV1.E1})

    action = ACTION_POLICY_BY_ID["live.enable"]
    with pytest.raises(ValidationError, match="PROTECTED_ACTION_CLASS_INVALID"):
        ActionPolicyV1(
            **{
                **action.model_dump(mode="python"),
                "confirmation_class": ConfirmationClassV1.E1,
            }
        )
    with pytest.raises(ValidationError, match="PROTECTED_ACTION_CLASS_INVALID"):
        action.model_copy(update={"confirmation_class": ConfirmationClassV1.E1})

    secret = CapabilityInputFieldV1.model_construct(name="api_key", kind=InputKindV1.SECRET)
    with pytest.raises(ValidationError, match="SECRET_INPUT_FORBIDDEN"):
        CapabilityInputFieldV1(name="api_key", kind=InputKindV1.SECRET)
    with pytest.raises(ValidationError, match="SECRET_INPUT_FORBIDDEN"):
        CapabilityInputFieldV1(name="api_key", kind=InputKindV1.IDENTIFIER).model_copy(
            update={"kind": InputKindV1.SECRET}
        )
    with pytest.raises(ValidationError, match="SECRET_INPUT_FORBIDDEN"):
        CapabilityPolicyV1(
            **{
                **capability.model_dump(mode="python"),
                "input_fields": (*capability.input_fields, secret),
            }
        )
    with pytest.raises(ValidationError, match="SECRET_INPUT_FORBIDDEN"):
        ActionPolicyV1(
            **{
                **action.model_dump(mode="python"),
                "input_fields": (secret,),
            }
        )
    with pytest.raises(ValidationError, match="SECRET_INPUT_FORBIDDEN"):
        capability.model_copy(update={"input_fields": (*capability.input_fields, secret)})
    with pytest.raises(ValidationError, match="SECRET_INPUT_FORBIDDEN"):
        action.model_copy(update={"input_fields": (secret,)})


def test_policy_models_reject_modes_ineligible_for_confirmation_class() -> None:
    all_modes = tuple(OperatingModeV1)
    trade_card = CAPABILITY_BY_ID["trade_card.approve"]
    with pytest.raises(ValidationError, match="CAPABILITY_MODE_CLASS_INVALID"):
        CapabilityPolicyV1(**{**trade_card.model_dump(mode="python"), "allowed_modes": all_modes})
    with pytest.raises(ValidationError, match="CAPABILITY_MODE_CLASS_INVALID"):
        trade_card.model_copy(update={"allowed_modes": all_modes})

    trade_action = ACTION_POLICY_BY_ID["trade_card.approve"]
    with pytest.raises(ValidationError, match="ACTION_MODE_CLASS_INVALID"):
        ActionPolicyV1(**{**trade_action.model_dump(mode="python"), "allowed_modes": all_modes})
    with pytest.raises(ValidationError, match="ACTION_MODE_CLASS_INVALID"):
        trade_action.model_copy(update={"allowed_modes": all_modes})

    full_auto = CAPABILITY_BY_ID["full_auto.order.submit"]
    with pytest.raises(ValidationError, match="CAPABILITY_MODE_CLASS_INVALID"):
        full_auto.model_copy(
            update={"allowed_modes": (OperatingModeV1.ANALYSIS, OperatingModeV1.FULL_AUTO)}
        )

    assert CAPABILITY_BY_ID["halt.engage"].allowed_modes == all_modes


def _grant(
    action_type: DelegationActionTypeV1,
    *,
    expires_at_ns: int | None = None,
) -> DelegationGrantV1:
    return create_delegation_grant(
        grant_id="grant-01",
        principal_id="user-01",
        account_id="acct-01",
        action_type=action_type,
        created_at_ns=100,
        grant_event_id="event-grant-01",
        expires_at_ns=expires_at_ns,
    )


@pytest.mark.parametrize(
    ("action_id", "action_type"),
    [
        ("live.enable", DelegationActionTypeV1.LIVE_TOGGLE),
        ("halt.lift", DelegationActionTypeV1.HALT_LIFT),
        ("risk.limits.relax", DelegationActionTypeV1.RISK_LIMIT_CHANGE),
    ],
)
def test_o2_requires_current_user_confirmation_or_matching_delegation(
    action_id: str, action_type: DelegationActionTypeV1
) -> None:
    assert CAPABILITY_BY_ID[action_id].chat_surface.value == "tool"
    without_grant = authorize_o2_action(
        action_id,
        principal_id="user-01",
        account_id="acct-01",
        now_ns=200,
    )
    assert without_grant.allowed is False
    assert without_grant.code is O2AuthorizationCodeV1.CONFIRMATION_REQUIRED

    confirmed = authorize_o2_action(
        action_id,
        principal_id="user-01",
        account_id="acct-01",
        now_ns=200,
        in_app_confirmed=True,
    )
    assert confirmed.allowed is True
    assert confirmed.code is O2AuthorizationCodeV1.CONFIRMED

    delegated = authorize_o2_action(
        action_id,
        principal_id="user-01",
        account_id="acct-01",
        now_ns=200,
        delegations=(_grant(action_type),),
    )
    assert delegated.allowed is True
    assert delegated.code is O2AuthorizationCodeV1.DELEGATED


def test_delegation_is_audited_scoped_revocable_and_expires() -> None:
    grant = _grant(DelegationActionTypeV1.LIVE_TOGGLE, expires_at_ns=300)
    assert grant.grant_event.event_kind.value == "granted"
    assert grant.grant_event.principal_id == grant.principal_id
    assert grant.grant_event.account_id == grant.account_id

    for principal_id, account_id, now_ns, candidate in (
        ("other-user", "acct-01", 200, grant),
        ("user-01", "other-account", 200, grant),
        ("user-01", "acct-01", 300, grant),
    ):
        result = authorize_o2_action(
            "live.enable",
            principal_id=principal_id,
            account_id=account_id,
            now_ns=now_ns,
            delegations=(candidate,),
        )
        assert result.code is O2AuthorizationCodeV1.CONFIRMATION_REQUIRED

    revoked = revoke_delegation_grant(grant, revoked_at_ns=250, event_id="event-revoke-01")
    assert revoked.revocation_event is not None
    assert revoked.revocation_event.event_kind.value == "revoked"
    after_revoke = authorize_o2_action(
        "live.enable",
        principal_id="user-01",
        account_id="acct-01",
        now_ns=260,
        delegations=(revoked,),
    )
    assert after_revoke.code is O2AuthorizationCodeV1.CONFIRMATION_REQUIRED


def test_credentials_are_never_chat_delegable_or_chat_writable() -> None:
    for action_id in ("credentials.put", "credentials.delete", "credentials.change"):
        assert CAPABILITY_BY_ID[action_id].chat_surface.value == "ui_only"
        result = authorize_o2_action(
            action_id,
            principal_id="user-01",
            account_id="acct-01",
            now_ns=200,
            in_app_confirmed=True,
        )
        assert result.allowed is False
        assert result.code is O2AuthorizationCodeV1.CHAT_ACTION_FORBIDDEN

    with pytest.raises(ValidationError):
        create_delegation_grant(
            grant_id="grant-bad",
            principal_id="user-01",
            account_id="acct-01",
            action_type="credentials.put",  # type: ignore[arg-type]
            created_at_ns=100,
            grant_event_id="event-bad",
        )
