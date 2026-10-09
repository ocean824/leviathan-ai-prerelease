"""Independent, synthetic acceptance tests for trading binding metadata."""

from __future__ import annotations

import copy
import json
import pickle
from dataclasses import replace
from datetime import date, datetime
from pathlib import Path
from typing import Any

import pytest

from leviathan_vault import VaultStatus
from leviathan_vault.trading_bindings import (
    BindingRequestV1,
    BindingValidationV1,
    TradingAccountBindingV1,
    TradingBindingError,
    parse_credential_ref,
    validate_binding,
    validate_binding_set,
)

_FIXTURES = Path(__file__).parent / "fixtures" / "trading_bindings"
_CANARY = "SYNTHETIC_NO_ECHO_CANARY_7f40"


def _binding(**changes: Any) -> TradingAccountBindingV1:
    fields = json.loads((_FIXTURES / "base_binding.json").read_text(encoding="utf-8"))
    fields["instrument_mapping_date"] = date.fromisoformat(fields["instrument_mapping_date"])
    for key in ("venue_allowlist", "instrument_allowlist", "strategy_allowlist"):
        fields[key] = tuple(fields[key])
    fields["activation_evidence_refs"] = tuple(fields["activation_evidence_refs"])
    if fields["expires_at"] is not None:
        fields["expires_at"] = datetime.fromisoformat(fields["expires_at"])
    if fields["activation_at"] is not None:
        fields["activation_at"] = datetime.fromisoformat(fields["activation_at"])
    if fields["last_provider_auth_verified_at"] is not None:
        fields["last_provider_auth_verified_at"] = datetime.fromisoformat(
            fields["last_provider_auth_verified_at"]
        )
    if fields["last_account_permission_verified_at"] is not None:
        fields["last_account_permission_verified_at"] = datetime.fromisoformat(
            fields["last_account_permission_verified_at"]
        )
    fields.update(changes)
    return TradingAccountBindingV1(**fields)


def _request(**changes: Any) -> BindingRequestV1:
    fields = json.loads((_FIXTURES / "base_request.json").read_text(encoding="utf-8"))
    fields["checked_at"] = datetime.fromisoformat(fields["checked_at"])
    fields.update(changes)
    return BindingRequestV1(**fields)


def _status(
    *, name: str = "IBKR_PAPER_TEST", scope: str = "leviathan-ai", environment: str = "development",
    status: str = "ENCRYPTED_ROUNDTRIP_VERIFIED",
    provider_authentication: str = "NOT_TESTED",
) -> VaultStatus:
    return VaultStatus(
        name=name,
        scope=scope,
        environment=environment,
        status=status,
        provider_authentication=provider_authentication,
    )


def _validate(
    binding: TradingAccountBindingV1 | None = None,
    request: BindingRequestV1 | None = None,
    *,
    credential_status: VaultStatus | None = None,
):
    selected_binding = binding or _binding()
    selected_request = request or _request()
    selected_status = credential_status
    if selected_status is None and selected_binding.credential_ref is not None:
        parsed = parse_credential_ref(selected_binding.credential_ref, selected_binding.broker)
        selected_status = _status(
            name=parsed.name,
            scope=parsed.scope,
            environment=parsed.environment,
        )
    return validate_binding(
        selected_binding,
        selected_request,
        credential_status=selected_status,
    )


def test_exact_synthetic_development_and_live_refs_resolve_only_to_their_scope() -> None:
    for environment in ("development", "live"):
        uri = f"vault://leviathan-ai/{environment}/IBKR_{environment.upper()}_TEST"
        resolved = parse_credential_ref(uri, "IBKR")

        assert resolved.provider == "IBKR"
        assert resolved.scope == "leviathan-ai"
        assert resolved.environment == environment
        assert resolved.name == f"IBKR_{environment.upper()}_TEST"


@pytest.mark.parametrize(
    "uri",
    [
        "vault://other-project/development/IBKR_PAPER_TEST",
        "vault://factory-admin/development/IBKR_PAPER_TEST",
        "vault://leviathan-ai/factory-admin/IBKR_PAPER_TEST",
        "vault://leviathan-ai/development/../IBKR_PAPER_TEST",
        "vault://leviathan-ai/development/IBKR_PAPER_TEST/..",
        "vault://leviathan-ai/development/%2e%2e/IBKR_PAPER_TEST",
        "Vault://leviathan-ai/development/IBKR_PAPER_TEST",
        "vault://Leviathan-ai/development/IBKR_PAPER_TEST",
        "vault://leviathan-ai/Development/IBKR_PAPER_TEST",
        "vault://leviathan-ai/development/ibkr_paper_test",
        "vault://leviathan-ai/development/IBKR_P\u0410PER_TEST",
        "vault://leviathan-\u0430i/development/IBKR_PAPER_TEST",
    ],
)
def test_every_nonexact_project_environment_or_alias_ref_is_rejected(uri: str) -> None:
    with pytest.raises(TradingBindingError) as error:
        parse_credential_ref(uri, "IBKR")

    assert error.value.code == "CREDENTIAL_REF_DENIED"
    assert uri not in str(error.value)
    assert uri not in repr(error.value.args)


def test_valid_binding_is_metadata_only_and_provider_auth_remains_unverified() -> None:
    result = _validate()

    assert result.metadata_valid is True
    assert result.submit_capable is False
    assert result.provider_authentication == "NOT_TESTED"


def test_validation_result_capability_cannot_be_forged_by_construction_or_replace() -> None:
    result = _validate()
    forged_fields = dict(
        binding_revision=1,
        credential_revision=1,
    )

    with pytest.raises(TradingBindingError) as direct:
        BindingValidationV1(**forged_fields)
    assert direct.value.code == "UNISSUED_VALIDATION"
    with pytest.raises(TradingBindingError) as copied:
        replace(result, binding_revision=2)
    assert copied.value.code == "UNISSUED_VALIDATION"
    assert result.metadata_valid is True
    assert result.submit_capable is False
    assert result.provider_authentication == "NOT_TESTED"
    assert "_issuer" not in BindingValidationV1.__slots__


def test_request_for_submit_is_denied_while_provider_authentication_is_not_tested() -> None:
    with pytest.raises(TradingBindingError) as error:
        _validate(request=_request(want_submit=True))

    assert error.value.code == "PROVIDER_VERIFICATION_REQUIRED"


def test_operator_session_requirement_never_falls_back_to_a_credential_ref() -> None:
    operator_binding = _binding(credential_ref=None, operator_session_required=True)
    metadata = _validate(operator_binding, _request(want_submit=False))

    assert metadata.metadata_valid is True
    assert metadata.submit_capable is False
    assert metadata.provider_authentication == "NOT_TESTED"

    with pytest.raises(TradingBindingError):
        _validate(_binding(operator_session_required=True), _request(want_submit=False))


def test_cross_environment_reference_is_denied_without_fallback() -> None:
    with pytest.raises(TradingBindingError) as error:
        _binding(credential_ref="vault://leviathan-ai/live/IBKR_LIVE_TEST")

    assert error.value.code == "CREDENTIAL_ENVIRONMENT_DENIED"


def test_wrong_project_broker_or_status_scope_is_denied() -> None:
    with pytest.raises(TradingBindingError) as wrong_project:
        _validate(_binding(project_id="other-project"), _request())
    assert wrong_project.value.code == "BINDING_SCOPE_DENIED"

    with pytest.raises(TradingBindingError) as wrong_broker:
        _validate(_binding(broker="MT5"), _request())
    assert wrong_broker.value.code == "BROKER_MISMATCH"

    with pytest.raises(TradingBindingError) as wrong_status:
        _validate(credential_status=_status(name="OTHER_SYNTHETIC_REF"))
    assert wrong_status.value.code == "CREDENTIAL_STATUS_DENIED"


@pytest.mark.parametrize(
    ("request_field", "value", "expected_code"),
    [
        ("account_ref", "synthetic-other-account", "ACCOUNT_MISMATCH"),
        ("session_ref", "synthetic-other-session", "SESSION_MISMATCH"),
        ("venue", "OTHER-VENUE", "VENUE_DENIED"),
        ("instrument", "NQ-202612", "INSTRUMENT_DENIED"),
        ("strategy_id", "other-strategy", "STRATEGY_DENIED"),
        ("hard_risk_limit_revision", "risk-v2", "RISK_REVISION_MISMATCH"),
        ("instrument_mapping_revision", "mapping-v2", "MAPPING_REVISION_MISMATCH"),
        ("binding_revision", 2, None),
        ("credential_revision", 2, "CREDENTIAL_ROTATED"),
    ],
)
def test_binding_must_match_every_requested_account_and_policy_dimension(
    request_field: str, value: object, expected_code: str | None
) -> None:
    with pytest.raises(TradingBindingError) as error:
        _validate(request=_request(**{request_field: value}))

    if expected_code is not None:
        assert error.value.code == expected_code


@pytest.mark.parametrize(
    ("changes", "expected_code"),
    [
        ({"revoked": True}, "BINDING_REVOKED"),
        ({"expires_at": datetime.fromisoformat("2026-10-05T12:00:00+00:00")}, "BINDING_EXPIRED"),
        ({"credential_revision": 2}, "CREDENTIAL_ROTATED"),
    ],
)
def test_revoked_expired_or_rotated_bindings_are_denied(
    changes: dict[str, Any], expected_code: str
) -> None:
    with pytest.raises(TradingBindingError) as error:
        _validate(_binding(**changes))

    assert error.value.code == expected_code


@pytest.mark.parametrize(
    "changes",
    [
        {"provider_authentication": "VERIFIED"},
        {"can_cancel": True},
        {"can_submit": True},
        {
            "activation_actor": "synthetic-actor",
            "activation_at": datetime.fromisoformat("2026-10-05T11:00:00+00:00"),
            "activation_evidence_refs": ("synthetic-evidence-001",),
        },
    ],
)
def test_offline_validation_cannot_forge_auth_capability_or_activation(
    changes: dict[str, Any]
) -> None:
    with pytest.raises(TradingBindingError) as error:
        _validate(_binding(**changes), _request(want_submit=False))

    assert error.value.code == "PROVIDER_VERIFICATION_REQUIRED"


def test_duplicate_credential_refs_and_duplicate_binding_scopes_are_rejected() -> None:
    other_account = _binding(
        account_ref="synthetic-paper-account-002",
        session_ref="synthetic-gateway-101",
    )
    with pytest.raises(TradingBindingError) as duplicate_ref:
        validate_binding_set((_binding(), other_account))
    assert duplicate_ref.value.code == "DUPLICATE_CREDENTIAL_REF"

    with pytest.raises(TradingBindingError) as duplicate_scope:
        validate_binding_set((_binding(), _binding()))
    assert duplicate_scope.value.code == "DUPLICATE_BINDING_SCOPE"


def test_integer_boolean_and_replace_inputs_are_validated_on_construction() -> None:
    binding = _binding()
    with pytest.raises(TradingBindingError):
        replace(binding, binding_revision=True)
    with pytest.raises(TradingBindingError):
        replace(binding, binding_revision=2**63)
    with pytest.raises(TradingBindingError):
        replace(binding, credential_revision=True)
    with pytest.raises(TradingBindingError):
        replace(binding, venue_allowlist=["IBKR-PAPER"])
    with pytest.raises(TradingBindingError):
        replace(binding, project_id=_CANARY)

    with pytest.raises(TradingBindingError) as error:
        _validate(_binding(project_id=_CANARY), _request())
    assert _CANARY not in str(error.value)
    assert _CANARY not in repr(error.value.args)


def test_binding_records_are_frozen_and_copy_pickle_are_rejected() -> None:
    binding = _binding()
    result = _validate(binding, _request())

    for record in (binding, _request(), result):
        with pytest.raises((TypeError, ValueError)):
            copy.copy(record)
        with pytest.raises((TypeError, ValueError)):
            copy.deepcopy(record)
        with pytest.raises((TypeError, ValueError)):
            pickle.dumps(record)

    with pytest.raises((AttributeError, TypeError, ValueError)) as error:
        binding.account_ref = _CANARY
    assert _CANARY not in str(error.value)
    with pytest.raises((AttributeError, TypeError, ValueError)) as error:
        del binding.account_ref
    assert _CANARY not in str(error.value)


@pytest.mark.parametrize(
    ("field", "value", "expected_code"),
    [
        (
            "credential_ref",
            "vault://leviathan-ai/live/IBKR_LIVE_MUTATED",
            "CREDENTIAL_ENVIRONMENT_DENIED",
        ),
        ("can_submit", True, "PROVIDER_VERIFICATION_REQUIRED"),
        ("provider_authentication", "VERIFIED", "PROVIDER_VERIFICATION_REQUIRED"),
    ],
)
def test_trust_boundaries_revalidate_bindings_mutated_after_construction(
    field: str, value: object, expected_code: str
) -> None:
    binding = _binding()
    object.__setattr__(binding, field, value)
    request = _request()
    live_status = _status(
        name="IBKR_LIVE_MUTATED",
        environment="live",
    )

    with pytest.raises(TradingBindingError) as single:
        validate_binding(binding, request, credential_status=live_status)
    assert single.value.code == expected_code

    with pytest.raises(TradingBindingError) as binding_set:
        validate_binding_set((binding,))
    assert binding_set.value.code == expected_code


def test_mapping_effective_date_uses_utc_date_for_equivalent_instants() -> None:
    binding = _binding(instrument_mapping_date=date(2026, 10, 2))
    offset_request = _request(
        checked_at=datetime.fromisoformat("2026-10-02T03:00:00+14:00")
    )
    utc_request = _request(
        checked_at=datetime.fromisoformat("2026-10-01T13:00:00+00:00")
    )

    for request in (offset_request, utc_request):
        with pytest.raises(TradingBindingError) as error:
            _validate(binding, request)
        assert error.value.code == "MAPPING_NOT_EFFECTIVE"
