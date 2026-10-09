"""Synthetic checks for offline trading binding metadata."""

from __future__ import annotations

import copy
import pickle
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, date, datetime, timedelta, timezone

import pytest

from leviathan_vault.client import VaultStatus
from leviathan_vault.trading_bindings import (
    BindingRequestV1,
    BindingValidationV1,
    TradingAccountBindingV1,
    TradingBindingError,
    parse_credential_ref,
    validate_binding,
    validate_binding_set,
)

NOW = datetime(2026, 10, 5, 12, tzinfo=UTC)
REF = "vault://leviathan-ai/development/IBKR_PAPER"


def _binding(**changes: object) -> TradingAccountBindingV1:
    fields: dict[str, object] = {
        "project_id": "leviathan-ai",
        "environment": "development",
        "broker": "IBKR",
        "adapter_protocol": "tws-gateway",
        "adapter_version": "1.0",
        "account_ref": "synthetic-paper-100",
        "session_ref": "synthetic-gateway-100",
        "credential_ref": REF,
        "operator_session_required": False,
        "venue_allowlist": ("XNAS",),
        "instrument_allowlist": ("AAPL",),
        "instrument_mapping_revision": "contracts-2026-10-01",
        "instrument_mapping_date": date(2026, 10, 1),
        "strategy_allowlist": ("paper-strategy-1",),
        "hard_risk_limit_revision": "risk-7",
        "can_read": True,
        "session_mode": "paper",
    }
    fields.update(changes)
    return TradingAccountBindingV1(**fields)  # type: ignore[arg-type]


def _request(**changes: object) -> BindingRequestV1:
    fields: dict[str, object] = {
        "environment": "development",
        "broker": "IBKR",
        "account_ref": "synthetic-paper-100",
        "session_ref": "synthetic-gateway-100",
        "venue": "XNAS",
        "instrument": "AAPL",
        "instrument_mapping_revision": "contracts-2026-10-01",
        "strategy_id": "paper-strategy-1",
        "hard_risk_limit_revision": "risk-7",
        "session_mode": "paper",
        "binding_revision": 1,
        "credential_revision": 1,
        "checked_at": NOW,
    }
    fields.update(changes)
    return BindingRequestV1(**fields)  # type: ignore[arg-type]


def _status(**changes: object) -> VaultStatus:
    fields: dict[str, object] = {
        "name": "IBKR_PAPER",
        "scope": "leviathan-ai",
        "environment": "development",
    }
    fields.update(changes)
    return VaultStatus(**fields)  # type: ignore[arg-type]


def test_exact_credential_ref_and_no_inheritance() -> None:
    parsed = parse_credential_ref(REF, "IBKR")
    assert (parsed.provider, parsed.name, parsed.scope, parsed.environment) == (
        "IBKR", "IBKR_PAPER", "leviathan-ai", "development"
    )
    for bad in (
        "vault://factory-admin/development/IBKR_PAPER",
        "vault://leviathan-ai/live/IBKR_PAPER/",
        "vault://leviathan-ai/development/ibkr_paper",
        "vault://leviathan-ai/development/IBKR_PAPER?inherit=true",
        "dpapi-current-user://leviathan-ai--development--IBKR_PAPER.dpapi",
    ):
        with pytest.raises(TradingBindingError, match=r"^CREDENTIAL_REF_DENIED$"):
            parse_credential_ref(bad, "IBKR")
    with pytest.raises(TradingBindingError, match=r"^CREDENTIAL_ENVIRONMENT_DENIED$"):
        _binding(credential_ref="vault://leviathan-ai/live/IBKR_PAPER")


def test_matching_metadata_stays_non_submit_capable() -> None:
    binding = _binding()
    verdict = validate_binding(binding, _request(), credential_status=_status())
    assert verdict.metadata_valid
    assert not verdict.submit_capable
    assert verdict.provider_authentication == "NOT_TESTED"
    assert verdict.binding_revision == 1
    with pytest.raises(TradingBindingError, match=r"^PROVIDER_VERIFICATION_REQUIRED$"):
        validate_binding(binding, _request(want_submit=True), credential_status=_status())
    with pytest.raises(TradingBindingError, match=r"^PROVIDER_VERIFICATION_REQUIRED$"):
        _binding(can_submit=True)
    with pytest.raises(TradingBindingError, match=r"^PROVIDER_VERIFICATION_REQUIRED$"):
        _binding(can_cancel=True)
    with pytest.raises(TradingBindingError, match=r"^PROVIDER_VERIFICATION_REQUIRED$"):
        _binding(provider_authentication="VERIFIED")
    with pytest.raises(TradingBindingError, match=r"^PROVIDER_VERIFICATION_REQUIRED$"):
        _binding(activation_actor="synthetic-operator", activation_at=NOW)
    with pytest.raises(TradingBindingError, match=r"^PROVIDER_VERIFICATION_REQUIRED$"):
        _binding(last_account_permission_verified_at=NOW)


@pytest.mark.parametrize(
    ("change", "code"),
    [
        ({"environment": "live"}, "BINDING_SCOPE_DENIED"),
        ({"broker": "MT5"}, "BROKER_MISMATCH"),
        ({"account_ref": "synthetic-other"}, "ACCOUNT_MISMATCH"),
        ({"session_ref": "synthetic-other"}, "SESSION_MISMATCH"),
        ({"session_mode": "demo"}, "SESSION_MISMATCH"),
        ({"venue": "XNYS"}, "VENUE_DENIED"),
        ({"instrument": "MSFT"}, "INSTRUMENT_DENIED"),
        ({"instrument_mapping_revision": "contracts-older"}, "MAPPING_REVISION_MISMATCH"),
        ({"strategy_id": "other-strategy"}, "STRATEGY_DENIED"),
        ({"hard_risk_limit_revision": "risk-older"}, "RISK_REVISION_MISMATCH"),
        ({"binding_revision": 2}, "BINDING_REVISION_MISMATCH"),
        ({"credential_revision": 2}, "CREDENTIAL_ROTATED"),
    ],
)
def test_request_mismatches_are_denied(change: dict[str, object], code: str) -> None:
    with pytest.raises(TradingBindingError, match=f"^{code}$"):
        validate_binding(_binding(), _request(**change), credential_status=_status())


def test_missing_cross_environment_or_forged_status_denied() -> None:
    for status in (None, _status(environment="live"), _status(scope="factory-admin"),
                   _status(status="REVOKED"), _status(provider_authentication="VERIFIED")):
        with pytest.raises(TradingBindingError, match=r"^CREDENTIAL_STATUS_DENIED$"):
            validate_binding(_binding(), _request(), credential_status=status)


def test_revocation_expiry_and_rotation_deny_without_fallback() -> None:
    with pytest.raises(TradingBindingError, match=r"^BINDING_REVOKED$"):
        validate_binding(_binding(revoked=True), _request(), credential_status=_status())
    with pytest.raises(TradingBindingError, match=r"^BINDING_EXPIRED$"):
        validate_binding(_binding(expires_at=NOW), _request(), credential_status=_status())
    with pytest.raises(TradingBindingError, match=r"^CREDENTIAL_ROTATED$"):
        validate_binding(_binding(credential_revision=2), _request(), credential_status=_status())
    with pytest.raises(TradingBindingError, match=r"^MAPPING_NOT_EFFECTIVE$"):
        validate_binding(
            _binding(instrument_mapping_date=(NOW + timedelta(days=1)).date()),
            _request(), credential_status=_status()
        )


def test_operator_session_is_distinct_and_still_unverified() -> None:
    binding = _binding(credential_ref=None, operator_session_required=True)
    verdict = validate_binding(binding, _request())
    assert verdict.metadata_valid and not verdict.submit_capable
    with pytest.raises(TradingBindingError, match=r"^CREDENTIAL_REF_AMBIGUOUS$"):
        validate_binding(binding, _request(), credential_status=_status())
    with pytest.raises(TradingBindingError, match=r"^CREDENTIAL_REF_AMBIGUOUS$"):
        _binding(operator_session_required=True)


def test_live_metadata_has_its_own_reference_and_session() -> None:
    live = _binding(
        environment="live",
        session_mode="live",
        credential_ref="vault://leviathan-ai/live/IBKR_LIVE",
        account_ref="synthetic-live-200",
        session_ref="synthetic-live-gateway-200",
    )
    request = _request(
        environment="live",
        session_mode="live",
        account_ref="synthetic-live-200",
        session_ref="synthetic-live-gateway-200",
    )
    verdict = validate_binding(live, request, credential_status=_status(
        name="IBKR_LIVE", environment="live"
    ))
    assert verdict.metadata_valid and not verdict.submit_capable
    with pytest.raises(TradingBindingError, match=r"^CREDENTIAL_STATUS_DENIED$"):
        validate_binding(live, request, credential_status=_status())


def test_duplicate_accounts_sessions_and_credential_refs_denied() -> None:
    base = _binding()
    assert validate_binding_set([base]) == (base,)
    with pytest.raises(TradingBindingError, match=r"^DUPLICATE_BINDING_SCOPE$"):
        validate_binding_set([base, base])
    with pytest.raises(TradingBindingError, match=r"^DUPLICATE_CREDENTIAL_REF$"):
        validate_binding_set([
            base, _binding(account_ref="synthetic-paper-200", session_ref="synthetic-gateway-200")
        ])
    with pytest.raises(TradingBindingError, match=r"^DUPLICATE_BINDING_SCOPE$"):
        validate_binding_set([
            base,
            _binding(
                environment="live",
                session_mode="live",
                credential_ref="vault://leviathan-ai/live/IBKR_LIVE",
                account_ref="synthetic-live-200",
            ),
        ])


def test_frozen_redacted_and_unissued_result() -> None:
    canary = "synthetic-sensitive-account-773"
    binding = _binding(account_ref=canary, session_ref="synthetic-session-773")
    request = _request(account_ref=canary, session_ref="synthetic-session-773")
    for obj in (binding, request):
        assert canary not in repr(obj)
        for operation in (copy.copy, copy.deepcopy, pickle.dumps):
            with pytest.raises(TradingBindingError, match=r"^FROZEN_BINDING$"):
                operation(obj)
        with pytest.raises(FrozenInstanceError) as exc:
            obj.account_ref = canary
        assert canary not in str(exc.value)
        with pytest.raises(FrozenInstanceError) as exc:
            del obj.account_ref
        assert canary not in str(exc.value)
    with pytest.raises(TradingBindingError, match=r"^PROVIDER_VERIFICATION_REQUIRED$"):
        replace(binding, can_submit=True)
    with pytest.raises(TradingBindingError, match=r"^BINDING_REVISION_INVALID$"):
        _binding(binding_revision=True)
    with pytest.raises(TradingBindingError, match=r"^BINDING_REVISION_INVALID$"):
        _binding(binding_revision=1 << 63)
    with pytest.raises(TradingBindingError, match=r"^BOOLEAN_INVALID$"):
        _request(want_submit="false")
    with pytest.raises(TradingBindingError) as invalid:
        _binding(account_ref=canary + "\n")
    assert canary not in str(invalid.value)
    assert canary not in repr(invalid.value.args)
    with pytest.raises(TradingBindingError, match=r"^UNISSUED_VALIDATION$"):
        BindingValidationV1(binding_revision=1, credential_revision=1)
    result = validate_binding(binding, request, credential_status=_status())
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(TradingBindingError, match=r"^FROZEN_BINDING$"):
            operation(result)
    with pytest.raises(TradingBindingError, match=r"^UNISSUED_VALIDATION$"):
        replace(result, binding_revision=2)
    with pytest.raises(TradingBindingError, match=r"^UNISSUED_VALIDATION$"):
        replace(result, _issuer=object())


def test_issued_result_reinitialization_and_field_tampering_fail_closed() -> None:
    result = validate_binding(_binding(), _request(), credential_status=_status())
    with pytest.raises(TradingBindingError, match=r"^FROZEN_BINDING$"):
        result.__init__(binding_revision=2, credential_revision=2)
    assert result.metadata_valid
    assert result.binding_revision == 1
    object.__setattr__(result, "binding_revision", 2)
    assert not result.metadata_valid
    assert not result.submit_capable


@pytest.mark.parametrize(
    ("field_name", "value", "code"),
    [
        (
            "credential_ref",
            "vault://leviathan-ai/live/IBKR_LIVE",
            "CREDENTIAL_ENVIRONMENT_DENIED",
        ),
        ("can_submit", True, "PROVIDER_VERIFICATION_REQUIRED"),
        ("provider_authentication", "VERIFIED", "PROVIDER_VERIFICATION_REQUIRED"),
    ],
)
def test_changed_binding_is_revalidated_at_use(
    field_name: str, value: object, code: str
) -> None:
    binding = _binding()
    object.__setattr__(binding, field_name, value)
    with pytest.raises(TradingBindingError, match=f"^{code}$"):
        validate_binding(
            binding,
            _request(),
            credential_status=_status(name="IBKR_LIVE", environment="live"),
        )
    with pytest.raises(TradingBindingError, match=f"^{code}$"):
        validate_binding_set((binding,))


def test_changed_request_is_revalidated_at_use() -> None:
    request = _request()
    object.__setattr__(request, "want_submit", "false")
    with pytest.raises(TradingBindingError, match=r"^BOOLEAN_INVALID$"):
        validate_binding(_binding(), request, credential_status=_status())


def test_mapping_effective_date_uses_the_utc_calendar() -> None:
    mapping = _binding(instrument_mapping_date=date(2026, 10, 6))
    same_instant = (
        datetime(2026, 10, 5, 10, 30, tzinfo=UTC),
        datetime(2026, 10, 6, 0, 30, tzinfo=timezone(timedelta(hours=14))),
    )
    for checked_at in same_instant:
        with pytest.raises(TradingBindingError, match=r"^MAPPING_NOT_EFFECTIVE$"):
            validate_binding(
                mapping, _request(checked_at=checked_at), credential_status=_status()
            )
