from __future__ import annotations

from typing import cast

import pytest

from leviathan_core.deployment_secret_refs import (
    AllowedSecretBindingsV1,
    ProviderAliasMapV1,
    SecretReferenceCode,
    SecretReferenceError,
    issue_allowed_secret_bindings,
    issue_provider_alias_map,
    validate_secret_reference,
)
from leviathan_core.seal import require


def _tables() -> tuple[AllowedSecretBindingsV1, ProviderAliasMapV1]:
    bindings = issue_allowed_secret_bindings(
        (
            (
                "market-data",
                "development",
                "vault://leviathan-ai/development/massive/MASSIVE_API_KEY",
            ),
            ("execution-gateway", "live", "vault://leviathan-ai/live/ibkr/IBKR_CREDENTIAL"),
        )
    )
    aliases = issue_provider_alias_map((("polygon", "massive", "development"),))
    return bindings, aliases


def test_canonical_reference_is_sealed_and_bound_to_service_environment() -> None:
    bindings, aliases = _tables()
    result = validate_secret_reference(
        "vault://leviathan-ai/development/massive/MASSIVE_API_KEY",
        service_id="market-data",
        environment="development",
        allowed_bindings=bindings,
        provider_aliases=aliases,
    )
    assert result.canonical_ref == "vault://leviathan-ai/development/massive/MASSIVE_API_KEY"
    assert result.provider == "massive"
    assert result.name == "MASSIVE_API_KEY"
    assert result.alias_applied is False
    assert require(result, "deployment.secret_refs.reference.v1") is result


def test_provider_alias_preserves_explicit_name_and_canonicalizes_before_membership() -> None:
    bindings, aliases = _tables()
    result = validate_secret_reference(
        "vault://leviathan-ai/development/polygon/MASSIVE_API_KEY",
        service_id="market-data",
        environment="development",
        allowed_bindings=bindings,
        provider_aliases=aliases,
    )
    assert result.canonical_ref == "vault://leviathan-ai/development/massive/MASSIVE_API_KEY"
    assert result.alias_applied is True


def test_other_service_and_environment_cannot_reuse_a_binding() -> None:
    bindings, aliases = _tables()
    cases = (
        (
            "execution-gateway",
            "development",
            "vault://leviathan-ai/development/massive/MASSIVE_API_KEY",
            SecretReferenceCode.SECRET_REF_NOT_BOUND,
        ),
        (
            "market-data",
            "development",
            "vault://leviathan-ai/live/ibkr/IBKR_CREDENTIAL",
            SecretReferenceCode.SECRET_ENVIRONMENT_MISMATCH,
        ),
    )
    for service_id, environment, ref, code in cases:
        with pytest.raises(SecretReferenceError) as raised:
            validate_secret_reference(
                ref,
                service_id=service_id,
                environment=environment,  # type: ignore[arg-type]
                allowed_bindings=bindings,
                provider_aliases=aliases,
            )
        assert raised.value.code is code
        assert str(raised.value) == code.value


def test_material_malformed_refs_and_unknown_paths_fail_content_free() -> None:
    bindings, aliases = _tables()
    cases = (
        ("api_key=do-not-echo-this-value", SecretReferenceCode.INVALID_SECRET_REFERENCE),
        ("sk_live_abcdefghijklmnopqrstuvwx", SecretReferenceCode.INVALID_SECRET_REFERENCE),
        ("postgresql://user:password@host/db", SecretReferenceCode.INVALID_SECRET_REFERENCE),
        (
            "vault://leviathan-ai/development/massive/MASSIVE_API_KEY?token=hidden",
            SecretReferenceCode.INVALID_SECRET_REFERENCE,
        ),
        (
            "vault://unknown-project/development/massive/MASSIVE_API_KEY",
            SecretReferenceCode.SECRET_SCOPE_MISMATCH,
        ),
        (
            "vault://leviathan-ai/development/unknown/UNKNOWN_API_KEY",
            SecretReferenceCode.SECRET_REF_NOT_BOUND,
        ),
    )
    for value, code in cases:
        with pytest.raises(SecretReferenceError) as raised:
            validate_secret_reference(
                value,
                service_id="market-data",
                environment="development",
                allowed_bindings=bindings,
                provider_aliases=aliases,
            )
        assert raised.value.code is code
        assert value not in str(raised.value)


def test_alias_must_be_explicit_for_environment_and_name() -> None:
    bindings, aliases = _tables()
    cases = (
        (
            "vault://leviathan-ai/development/polygon/POLYGON_API_KEY",
            "development",
            SecretReferenceCode.SECRET_REF_NOT_BOUND,
        ),
        (
            "vault://leviathan-ai/live/polygon/MASSIVE_API_KEY",
            "live",
            SecretReferenceCode.SECRET_REF_ALIAS_UNMAPPED,
        ),
    )
    for ref, environment, code in cases:
        with pytest.raises(SecretReferenceError) as raised:
            validate_secret_reference(
                ref,
                service_id="market-data",
                environment=environment,  # type: ignore[arg-type]
                allowed_bindings=bindings,
                provider_aliases=aliases,
            )
        assert raised.value.code is code


def test_unissued_or_invalid_tables_are_rejected_without_echo() -> None:
    _bindings, aliases = _tables()
    forged_bindings = cast(
        AllowedSecretBindingsV1,
        AllowedSecretBindingsV1.model_validate(
            {
                "schema_version": "1",
                "bindings": (
                    (
                        "market-data",
                        "development",
                        "vault://leviathan-ai/development/massive/MASSIVE_API_KEY",
                    ),
                ),
            }
        ),
    )
    with pytest.raises(SecretReferenceError) as raised:
        validate_secret_reference(
            "vault://leviathan-ai/development/massive/MASSIVE_API_KEY",
            service_id="market-data",
            environment="development",
            allowed_bindings=forged_bindings,
            provider_aliases=aliases,
        )
    assert raised.value.code is SecretReferenceCode.INVALID_BINDING_TABLE
    with pytest.raises(SecretReferenceError) as raised:
        issue_allowed_secret_bindings(
            (("market-data", "development", "api_key=must-not-echo-this"),)  # type: ignore[arg-type]
        )
    assert raised.value.code is SecretReferenceCode.INVALID_BINDING_TABLE
    assert "must-not-echo-this" not in str(raised.value)


def test_ambiguous_alias_table_is_denied() -> None:
    with pytest.raises(SecretReferenceError) as raised:
        issue_provider_alias_map(
            (
                ("polygon", "massive", "development"),
                ("polygon", "massive-alt", "development"),
            )  # type: ignore[arg-type]
        )
    assert raised.value.code is SecretReferenceCode.INVALID_ALIAS_MAP


def test_wrong_types_are_typed_without_echo() -> None:
    bindings, aliases = _tables()
    with pytest.raises(SecretReferenceError) as raised:
        validate_secret_reference(
            cast(str, object()),
            service_id="market-data",
            environment="development",
            allowed_bindings=bindings,
            provider_aliases=aliases,
        )
    assert raised.value.code is SecretReferenceCode.INVALID_SECRET_REFERENCE
