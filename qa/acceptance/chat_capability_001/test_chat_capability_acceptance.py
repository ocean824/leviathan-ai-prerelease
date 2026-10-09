from __future__ import annotations

import importlib.util
import inspect
import re
import sys
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType

import pytest
from pydantic import ValidationError

from leviathan_api.chat import capabilities_v1 as contract

_OWNER_CONTROL_IDS = {
    "live.enable",
    "halt.lift",
    "risk.limits.relax",
    "credentials.change",
    "credentials.put",
    "credentials.delete",
}
_ORDER_PLACEMENT_EFFECTS = {
    "paper.orders.create_submit",
    "trade_card.approve",
    "full_auto.order.submit",
}
_SECRET_VALUE_FIELD = re.compile(
    r"(?:credential|secret|password|token|api[_-]?key|private[_-]?key)", re.IGNORECASE
)
_CLASS_RANK = {"R0": 0, "E1": 1, "O2": 2, "A3": 3, "F4": 4}


def _assert_owner_controls_are_o2_or_higher(module: ModuleType) -> None:
    for action_id in _OWNER_CONTROL_IDS:
        row = module.ACTION_POLICY_BY_ID[action_id]
        assert _CLASS_RANK[row.confirmation_class.value] >= _CLASS_RANK["O2"]


def _assert_no_credential_value_fields(module: ModuleType) -> None:
    for policy in module.CAPABILITY_POLICIES:
        for field in policy.input_fields:
            assert field.kind is not module.InputKindV1.SECRET
            assert _SECRET_VALUE_FIELD.search(field.name) is None


def _assert_full_auto_live_requires_gate(module: ModuleType) -> None:
    request = module.ModeAdmissionRequestV1(
        account_id="acct-acceptance",
        venue="venue-acceptance",
        mode=module.OperatingModeV1.FULL_AUTO,
        environment=module.EnvironmentV1.LIVE,
        first_full_auto_enrollment=False,
    )
    result = module.assess_mode_admission(request)
    assert result.allowed is False
    assert result.code is module.ModeAdmissionCodeV1.LIVE_GATE_REQUIRED


def _assert_analysis_has_no_order_placement(module: ModuleType) -> None:
    assert not any(
        module.mode_allows_effect(action_id, module.OperatingModeV1.ANALYSIS)
        for action_id in _ORDER_PLACEMENT_EFFECTS
    )


def _assert_o2_copy_cannot_be_downgraded(module: ModuleType) -> None:
    capability = module.CAPABILITY_BY_ID["live.enable"]
    try:
        downgraded = capability.model_copy(
            update={"confirmation_class": module.ConfirmationClassV1.E1}
        )
    except ValidationError as exc:
        assert "PROTECTED_ACTION_CLASS_INVALID" in str(exc)
        return
    assert downgraded.confirmation_class is module.ConfirmationClassV1.O2


def _assert_halt_engage_is_allowed_in_every_mode(module: ModuleType) -> None:
    row = module.ACTION_POLICY_BY_ID["halt.engage"]
    capability = module.CAPABILITY_BY_ID["halt.engage"]
    assert row.confirmation_class is module.ConfirmationClassV1.E1
    assert row.requires_per_action_confirmation is False
    assert capability.audit_event.event_type
    assert capability.audit_event.required_fields
    for mode in module.OperatingModeV1:
        assert module.mode_allows_effect("halt.engage", mode)


def _assert_expired_grant_requires_confirmation(module: ModuleType) -> None:
    grant = module.create_delegation_grant(
        grant_id="expired-acceptance-grant",
        principal_id="account-owner",
        account_id="account-01",
        action_type=module.DelegationActionTypeV1.LIVE_TOGGLE,
        created_at_ns=100,
        grant_event_id="expired-acceptance-event",
        expires_at_ns=200,
    )
    result = module.authorize_o2_action(
        "live.enable",
        principal_id="account-owner",
        account_id="account-01",
        now_ns=200,
        delegations=(grant,),
    )
    assert result.allowed is False
    assert result.code is module.O2AuthorizationCodeV1.CONFIRMATION_REQUIRED


def _assert_credentials_cannot_be_delegated(module: ModuleType) -> None:
    grant = module.create_delegation_grant(
        grant_id="credential-acceptance-grant",
        principal_id="account-owner",
        account_id="account-01",
        action_type=module.DelegationActionTypeV1.LIVE_TOGGLE,
        created_at_ns=100,
        grant_event_id="credential-acceptance-event",
    )
    result = module.authorize_o2_action(
        "credentials.delete",
        principal_id="account-owner",
        account_id="account-01",
        now_ns=200,
        delegations=(grant,),
    )
    assert result.allowed is False
    assert result.code is module.O2AuthorizationCodeV1.CHAT_ACTION_FORBIDDEN


def _assert_validation_rejected(factory: Callable[[], object], code: str) -> None:
    try:
        factory()
    except ValidationError as exc:
        assert code in str(exc)
        return
    raise AssertionError(f"invalid policy was accepted: {code}")


def _assert_class_mode_restrictions(module: ModuleType) -> None:
    a3_capability = module.CAPABILITY_BY_ID["trade_card.approve"]
    assert a3_capability.confirmation_class is module.ConfirmationClassV1.A3
    a3_capability_values = a3_capability.model_dump(mode="python")
    a3_capability_values["allowed_modes"] = (module.OperatingModeV1.ANALYSIS,)
    _assert_validation_rejected(
        lambda: module.CapabilityPolicyV1(**a3_capability_values),
        "CAPABILITY_MODE_CLASS_INVALID",
    )
    _assert_validation_rejected(
        lambda: a3_capability.model_copy(
            update={"allowed_modes": (module.OperatingModeV1.ANALYSIS,)}
        ),
        "CAPABILITY_MODE_CLASS_INVALID",
    )

    a3_action = module.ACTION_POLICY_BY_ID["trade_card.approve"]
    a3_action_values = a3_action.model_dump(mode="python")
    a3_action_values["allowed_modes"] = (module.OperatingModeV1.ANALYSIS,)
    _assert_validation_rejected(
        lambda: module.ActionPolicyV1(**a3_action_values), "ACTION_MODE_CLASS_INVALID"
    )
    _assert_validation_rejected(
        lambda: a3_action.model_copy(update={"allowed_modes": (module.OperatingModeV1.ANALYSIS,)}),
        "ACTION_MODE_CLASS_INVALID",
    )

    f4_capability = module.CAPABILITY_BY_ID["full_auto.order.submit"]
    assert f4_capability.confirmation_class is module.ConfirmationClassV1.F4
    f4_capability_values = f4_capability.model_dump(mode="python")
    f4_capability_values["allowed_modes"] = (module.OperatingModeV1.SEMI_AUTO,)
    _assert_validation_rejected(
        lambda: module.CapabilityPolicyV1(**f4_capability_values),
        "CAPABILITY_MODE_CLASS_INVALID",
    )
    _assert_validation_rejected(
        lambda: f4_capability.model_copy(
            update={"allowed_modes": (module.OperatingModeV1.SEMI_AUTO,)}
        ),
        "CAPABILITY_MODE_CLASS_INVALID",
    )

    f4_action = module.ACTION_POLICY_BY_ID["full_auto.order.submit"]
    f4_action_values = f4_action.model_dump(mode="python")
    f4_action_values["allowed_modes"] = (module.OperatingModeV1.SEMI_AUTO,)
    _assert_validation_rejected(
        lambda: module.ActionPolicyV1(**f4_action_values), "ACTION_MODE_CLASS_INVALID"
    )
    _assert_validation_rejected(
        lambda: f4_action.model_copy(update={"allowed_modes": (module.OperatingModeV1.SEMI_AUTO,)}),
        "ACTION_MODE_CLASS_INVALID",
    )


@contextmanager
def _scratch_module(
    tmp_path: Path,
    name: str,
    replacements: tuple[tuple[str, str], ...],
) -> Iterator[ModuleType]:
    source_path = Path(contract.__file__)
    source = source_path.read_text(encoding="utf-8")
    for old, new in replacements:
        assert old in source, f"mutation anchor missing: {old!r}"
        source = source.replace(old, new, 1)

    mutant_path = tmp_path / f"{name}.py"
    mutant_path.write_text(source, encoding="utf-8")
    module_name = f"chat_capability_mutant_{name}"
    spec = importlib.util.spec_from_file_location(module_name, mutant_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
        yield module
    finally:
        sys.modules.pop(module_name, None)


def test_protected_owner_controls_and_emergency_halt_classification() -> None:
    _assert_owner_controls_are_o2_or_higher(contract)

    halt_engage = contract.ACTION_POLICY_BY_ID["halt.engage"]
    assert halt_engage.confirmation_class is contract.ConfirmationClassV1.E1
    assert halt_engage.requires_per_action_confirmation is False
    audit = contract.CAPABILITY_BY_ID["halt.engage"].audit_event
    assert audit.event_type
    assert {
        "capability_id",
        "principal_id",
        "occurred_at_ns",
        "input_digest",
    }.issubset(audit.required_fields)
    for mode in contract.OperatingModeV1:
        assert contract.mode_allows_effect("halt.engage", mode)


def _grant(
    action_type: contract.DelegationActionTypeV1,
    *,
    expires_at_ns: int | None = None,
) -> contract.DelegationGrantV1:
    return contract.create_delegation_grant(
        grant_id="acceptance-grant",
        principal_id="account-owner",
        account_id="account-01",
        action_type=action_type,
        created_at_ns=100,
        grant_event_id="acceptance-granted-event",
        expires_at_ns=expires_at_ns,
    )


def test_o2_uses_owner_confirmation_or_scoped_grant_without_admin_role() -> None:
    authorize = contract.authorize_o2_action
    params = inspect.signature(authorize).parameters
    assert "role" not in params
    assert "admin" not in params

    for action_id, action_type in (
        ("live.enable", contract.DelegationActionTypeV1.LIVE_TOGGLE),
        ("halt.lift", contract.DelegationActionTypeV1.HALT_LIFT),
        ("risk.limits.relax", contract.DelegationActionTypeV1.RISK_LIMIT_CHANGE),
    ):
        request = {
            "principal_id": "account-owner",
            "account_id": "account-01",
            "now_ns": 200,
        }
        missing = authorize(action_id, **request)
        assert missing.allowed is False
        assert missing.code is contract.O2AuthorizationCodeV1.CONFIRMATION_REQUIRED

        confirmed = authorize(action_id, **request, in_app_confirmed=True)
        assert confirmed.allowed is True
        assert confirmed.code is contract.O2AuthorizationCodeV1.CONFIRMED

        granted = authorize(
            action_id,
            **request,
            delegations=(_grant(action_type, expires_at_ns=300),),
        )
        assert granted.allowed is True
        assert granted.code is contract.O2AuthorizationCodeV1.DELEGATED

        revoked = contract.revoke_delegation_grant(
            _grant(action_type, expires_at_ns=300),
            revoked_at_ns=150,
            event_id="acceptance-revoked-event",
        )
        after_revoke = authorize(action_id, **request, delegations=(revoked,))
        assert after_revoke.allowed is False
        assert after_revoke.code is contract.O2AuthorizationCodeV1.CONFIRMATION_REQUIRED

        expired_grant = contract.create_delegation_grant(
            grant_id=f"expired-{action_id}",
            principal_id="account-owner",
            account_id="account-01",
            action_type=action_type,
            created_at_ns=100,
            grant_event_id=f"expired-event-{action_id}",
            expires_at_ns=200,
        )
        expired = authorize(
            action_id,
            **{**request, "now_ns": 200},
            delegations=(expired_grant,),
        )
        assert expired.allowed is False
        assert expired.code is contract.O2AuthorizationCodeV1.CONFIRMATION_REQUIRED


def test_credential_actions_cannot_use_confirmation_or_delegation() -> None:
    with pytest.raises(ValueError):
        contract.DelegationActionTypeV1("credentials.delete")

    result = contract.authorize_o2_action(
        "credentials.delete",
        principal_id="account-owner",
        account_id="account-01",
        now_ns=200,
        in_app_confirmed=True,
    )
    assert result.allowed is False
    assert result.code is contract.O2AuthorizationCodeV1.CHAT_ACTION_FORBIDDEN

    _assert_credentials_cannot_be_delegated(contract)

    # Even a valid grant for another allowed action cannot be repurposed for
    # credential removal.
    result = contract.authorize_o2_action(
        "credentials.delete",
        principal_id="account-owner",
        account_id="account-01",
        now_ns=200,
        delegations=(_grant(contract.DelegationActionTypeV1.LIVE_TOGGLE),),
    )
    assert result.allowed is False
    assert result.code is contract.O2AuthorizationCodeV1.CHAT_ACTION_FORBIDDEN


def test_all_capability_input_schemas_exclude_secret_and_credential_values() -> None:
    _assert_no_credential_value_fields(contract)


def test_analysis_default_and_mode_specific_order_effect_boundaries() -> None:
    assignment = contract.default_mode_assignment("acct-acceptance", "venue-acceptance")
    assert assignment.mode is contract.OperatingModeV1.ANALYSIS

    for action_id in _ORDER_PLACEMENT_EFFECTS:
        assert not contract.mode_allows_effect(action_id, contract.OperatingModeV1.ANALYSIS)

    assert contract.ACTION_POLICY_BY_ID["trade_card.approve"].confirmation_class is (
        contract.ConfirmationClassV1.A3
    )
    assert contract.mode_allows_effect("trade_card.approve", contract.OperatingModeV1.SEMI_AUTO)
    assert not contract.mode_allows_effect(
        "paper.orders.create_submit", contract.OperatingModeV1.SEMI_AUTO
    )
    assert not contract.mode_allows_effect(
        "full_auto.order.submit", contract.OperatingModeV1.SEMI_AUTO
    )


def test_full_auto_is_f4_paper_first_and_live_gate_protected() -> None:
    assert (
        contract.ACTION_POLICY_BY_ID["mode.full_auto.enroll"].confirmation_class
        is contract.ConfirmationClassV1.F4
    )
    assert (
        contract.ACTION_POLICY_BY_ID["full_auto.order.submit"].confirmation_class
        is contract.ConfirmationClassV1.F4
    )

    first_live = contract.ModeAdmissionRequestV1(
        account_id="acct-acceptance",
        venue="venue-acceptance",
        mode=contract.OperatingModeV1.FULL_AUTO,
        environment=contract.EnvironmentV1.LIVE,
        first_full_auto_enrollment=True,
    )
    assert contract.assess_mode_admission(first_live, _EnabledGate()).code is (
        contract.ModeAdmissionCodeV1.PAPER_FIRST_REQUIRED
    )

    first_paper = first_live.model_copy(update={"environment": contract.EnvironmentV1.PAPER})
    assert contract.assess_mode_admission(first_paper).allowed is True
    _assert_full_auto_live_requires_gate(contract)
    live = first_live.model_copy(update={"first_full_auto_enrollment": False})
    assert contract.assess_mode_admission(live, _EnabledGate()).allowed is True


class _EnabledGate:
    def live_account_enabled(self, account_id: str) -> bool:
        assert account_id == "acct-acceptance"
        return True


def test_each_action_has_one_unique_class_and_no_duplicate_rows() -> None:
    capability_ids = [row.capability_id for row in contract.CAPABILITY_POLICIES]
    action_ids = [row.action_id for row in contract.ACTION_POLICIES]
    assert len(capability_ids) == len(set(capability_ids))
    assert len(action_ids) == len(set(action_ids))
    assert set(capability_ids) == set(action_ids)

    for action in contract.ACTION_POLICIES:
        capability = contract.CAPABILITY_BY_ID[action.capability_id]
        assert action.confirmation_class is capability.confirmation_class
        assert action.action_id == action.capability_id


def test_confirmation_classes_constrain_modes_on_construction_and_copy() -> None:
    _assert_class_mode_restrictions(contract)


def test_mutant_live_enable_downgraded_to_e1_is_killed(tmp_path: Path) -> None:
    with (
        pytest.raises(ValueError, match="PROTECTED_ACTION_CLASS_INVALID"),
        _scratch_module(
            tmp_path,
            "live_enable_e1",
            (
                (
                    '_policy("live.enable", "Enable LIVE", CapabilityDomainV1.LIVE, '
                    "_O2, surface=_TOOL),",
                    '_policy("live.enable", "Enable LIVE", CapabilityDomainV1.LIVE, '
                    "_E1, surface=_TOOL),",
                ),
            ),
        ) as mutant,
    ):
        _assert_owner_controls_are_o2_or_higher(mutant)


def test_mutant_credential_value_field_is_killed(tmp_path: Path) -> None:
    with (
        _scratch_module(
            tmp_path,
            "credential_value_field",
            (
                (
                    'fields=(_field("provider", InputKindV1.ENUM), _field("profile_id")),',
                    'fields=(_field("provider", InputKindV1.ENUM), _field("profile_id"), '
                    '_field("credential_value", InputKindV1.TEXT)),',
                ),
            ),
        ) as mutant,
        pytest.raises(AssertionError),
    ):
        _assert_no_credential_value_fields(mutant)


def test_mutant_full_auto_live_without_gate_is_killed(tmp_path: Path) -> None:
    with (
        _scratch_module(
            tmp_path,
            "full_auto_live_gate_bypass",
            (
                (
                    "if request.mode is OperatingModeV1.FULL_AUTO "
                    "and request.environment is EnvironmentV1.LIVE:",
                    "if False:  # mutant bypasses the LIVE gate",
                ),
            ),
        ) as mutant,
        pytest.raises(AssertionError),
    ):
        _assert_full_auto_live_requires_gate(mutant)


def test_mutant_analysis_order_placement_is_killed(tmp_path: Path) -> None:
    with (
        _scratch_module(
            tmp_path,
            "analysis_order_placement",
            (
                (
                    "if mode not in policy.allowed_modes:\n        return False",
                    "if mode not in policy.allowed_modes and not (\n"
                    "        mode is OperatingModeV1.ANALYSIS\n"
                    '        and capability_id == "paper.orders.create_submit"\n'
                    "    ):\n        return False",
                ),
                (
                    'return capability_id in {"mode.select.analysis", "full_auto.disengage"}',
                    'return capability_id in {"mode.select.analysis", "full_auto.disengage", '
                    '"paper.orders.create_submit"}',
                ),
            ),
        ) as mutant,
        pytest.raises(AssertionError),
    ):
        _assert_analysis_has_no_order_placement(mutant)


def test_mutant_model_copy_o2_downgrade_is_killed(tmp_path: Path) -> None:
    with (
        _scratch_module(
            tmp_path,
            "model_copy_o2_downgrade",
            (
                (
                    "return type(self).model_validate(values)",
                    "return type(self).model_construct(**values)",
                ),
            ),
        ) as mutant,
        pytest.raises(AssertionError),
    ):
        _assert_o2_copy_cannot_be_downgraded(mutant)


def test_mutant_credential_remove_delegation_is_killed(tmp_path: Path) -> None:
    with (
        _scratch_module(
            tmp_path,
            "credential_remove_delegation",
            (
                (
                    "if action_id in _CREDENTIAL_VALUE_ACTION_IDS:",
                    "if False and action_id in _CREDENTIAL_VALUE_ACTION_IDS:",
                ),
                (
                    '"risk.limits.relax": DelegationActionTypeV1.RISK_LIMIT_CHANGE,',
                    '"risk.limits.relax": DelegationActionTypeV1.RISK_LIMIT_CHANGE,\n'
                    '        "credentials.delete": DelegationActionTypeV1.LIVE_TOGGLE,',
                ),
            ),
        ) as mutant,
        pytest.raises(AssertionError),
    ):
        _assert_credentials_cannot_be_delegated(mutant)


def test_mutant_halt_engage_denied_in_analysis_is_killed(tmp_path: Path) -> None:
    with (
        _scratch_module(
            tmp_path,
            "halt_engage_analysis_denied",
            (
                (
                    'if capability_id == "halt.engage":\n'
                    "        return (\n"
                    "            policy.domain is CapabilityDomainV1.HALT",
                    'if capability_id == "halt.engage" and mode is not OperatingModeV1.ANALYSIS:\n'
                    "        return (\n"
                    "            policy.domain is CapabilityDomainV1.HALT",
                ),
            ),
        ) as mutant,
        pytest.raises(AssertionError),
    ):
        _assert_halt_engage_is_allowed_in_every_mode(mutant)


def test_mutant_expired_grant_is_honoured_and_killed(tmp_path: Path) -> None:
    with (
        _scratch_module(
            tmp_path,
            "expired_delegation_honoured",
            (
                (
                    "(grant.expires_at_ns is None or now_ns < grant.expires_at_ns)",
                    "True  # mutant accepts an expired grant",
                ),
            ),
        ) as mutant,
        pytest.raises(AssertionError),
    ):
        _assert_expired_grant_requires_confirmation(mutant)


def test_mutant_a3_allowed_in_analysis_is_killed(tmp_path: Path) -> None:
    with (
        _scratch_module(
            tmp_path,
            "a3_analysis_eligibility",
            (
                (
                    "{OperatingModeV1.SEMI_AUTO, OperatingModeV1.FULL_AUTO}",
                    "{\n"
                    "                    OperatingModeV1.ANALYSIS,\n"
                    "                    OperatingModeV1.SEMI_AUTO,\n"
                    "                    OperatingModeV1.FULL_AUTO,\n"
                    "                }",
                ),
            ),
        ) as mutant,
        pytest.raises(AssertionError),
    ):
        _assert_class_mode_restrictions(mutant)
