"""Independent acceptance probes for DEP-SECRET-REF-001."""

from __future__ import annotations

from typing import cast

import pytest

from leviathan_core.deployment_secret_refs import (
    AllowedSecretBindingsV1,
    EnvironmentV1,
    ProviderAliasMapV1,
    SecretReferenceCode,
    SecretReferenceError,
    issue_allowed_secret_bindings,
    issue_provider_alias_map,
    validate_secret_reference,
)
from leviathan_core.seal import require

CANONICAL_REF = "vault://leviathan-ai/development/massive/MASSIVE_API_KEY"
ALIAS_REF = "vault://leviathan-ai/development/polygon/MASSIVE_API_KEY"
OTHER_SERVICE_REF = "vault://leviathan-ai/live/ibkr/IBKR_CREDENTIAL"


def _tables() -> tuple[AllowedSecretBindingsV1, ProviderAliasMapV1]:
    bindings = issue_allowed_secret_bindings(
        (
            ("market-data", "development", CANONICAL_REF),
            ("execution-gateway", "live", OTHER_SERVICE_REF),
        )
    )
    aliases = issue_provider_alias_map((("polygon", "massive", "development"),))
    return bindings, aliases


def _assert_content_free(
    failure: SecretReferenceError,
    code: SecretReferenceCode,
    *rejected_values: str,
) -> None:
    assert failure.code is code
    assert str(failure) == code.value
    assert failure.args == (code.value,)
    for value in rejected_values:
        assert value not in str(failure)
        assert value not in repr(failure)


def test_canonical_reference_requires_exact_service_and_environment_binding() -> None:
    bindings, aliases = _tables()
    result = validate_secret_reference(
        CANONICAL_REF,
        service_id="market-data",
        environment="development",
        allowed_bindings=bindings,
        provider_aliases=aliases,
    )

    assert require(result, "deployment.secret_refs.reference.v1") is result
    assert result.canonical_ref == CANONICAL_REF
    assert result.service_id == "market-data"
    assert result.environment == "development"
    assert result.provider == "massive"
    assert result.name == "MASSIVE_API_KEY"
    assert result.alias_applied is False
    assert set(result.model_dump(mode="python")) == {
        "schema_version",
        "service_id",
        "environment",
        "canonical_ref",
        "provider",
        "name",
        "alias_applied",
    }


def test_polygon_alias_is_development_only_and_preserves_the_key_name() -> None:
    bindings, aliases = _tables()
    result = validate_secret_reference(
        ALIAS_REF,
        service_id="market-data",
        environment="development",
        allowed_bindings=bindings,
        provider_aliases=aliases,
    )
    assert result.provider == "massive"
    assert result.name == "MASSIVE_API_KEY"
    assert result.canonical_ref == CANONICAL_REF
    assert result.alias_applied is True

    with pytest.raises(SecretReferenceError) as failure:
        validate_secret_reference(
            "vault://leviathan-ai/live/polygon/MASSIVE_API_KEY",
            service_id="execution-gateway",
            environment="live",
            allowed_bindings=bindings,
            provider_aliases=aliases,
        )
    _assert_content_free(failure.value, SecretReferenceCode.SECRET_REF_ALIAS_UNMAPPED)


def test_no_global_or_cross_service_fallback_exists() -> None:
    bindings, aliases = _tables()
    with pytest.raises(SecretReferenceError) as service_failure:
        validate_secret_reference(
            CANONICAL_REF,
            service_id="execution-gateway",
            environment="development",
            allowed_bindings=bindings,
            provider_aliases=aliases,
        )
    _assert_content_free(service_failure.value, SecretReferenceCode.SECRET_REF_NOT_BOUND)

    empty_bindings = issue_allowed_secret_bindings(())
    empty_aliases = issue_provider_alias_map(())
    with pytest.raises(SecretReferenceError) as empty_failure:
        validate_secret_reference(
            CANONICAL_REF,
            service_id="market-data",
            environment="development",
            allowed_bindings=empty_bindings,
            provider_aliases=empty_aliases,
        )
    _assert_content_free(empty_failure.value, SecretReferenceCode.SECRET_REF_NOT_BOUND)


def test_scope_environment_provider_and_name_mismatches_fail_closed() -> None:
    bindings, aliases = _tables()
    cases = (
        (
            "vault://other-project/development/massive/MASSIVE_API_KEY",
            "market-data",
            "development",
            SecretReferenceCode.SECRET_SCOPE_MISMATCH,
        ),
        (
            CANONICAL_REF,
            "market-data",
            "live",
            SecretReferenceCode.SECRET_ENVIRONMENT_MISMATCH,
        ),
        (
            "vault://leviathan-ai/development/unknown/UNKNOWN_API_KEY",
            "market-data",
            "development",
            SecretReferenceCode.SECRET_REF_NOT_BOUND,
        ),
        (
            "vault://leviathan-ai/development/polygon/DIFFERENT_API_KEY",
            "market-data",
            "development",
            SecretReferenceCode.SECRET_REF_NOT_BOUND,
        ),
    )
    for reference, service, environment, code in cases:
        with pytest.raises(SecretReferenceError) as failure:
            validate_secret_reference(
                reference,
                service_id=service,
                environment=cast(EnvironmentV1, environment),
                allowed_bindings=bindings,
                provider_aliases=aliases,
            )
        _assert_content_free(failure.value, code, reference)


def test_raw_material_and_secret_shaped_references_are_rejected_without_echo() -> None:
    bindings, aliases = _tables()
    cases = (
        "sk_live_ACCEPTANCE_SECRET_CANARY",
        "api_key=ACCEPTANCE_SECRET_CANARY",
        "https://user:password@host.example/ACCEPTANCE_SECRET_CANARY",
        "vault://leviathan-ai/development/massive/MASSIVE_API_KEY?token=ACCEPTANCE_SECRET_CANARY",
    )
    for value in cases:
        with pytest.raises(SecretReferenceError) as failure:
            validate_secret_reference(
                value,
                service_id="market-data",
                environment="development",
                allowed_bindings=bindings,
                provider_aliases=aliases,
            )
        _assert_content_free(
            failure.value,
            SecretReferenceCode.INVALID_SECRET_REFERENCE,
            value,
            "ACCEPTANCE_SECRET_CANARY",
        )


def test_scope_fields_and_sealed_allowlists_are_validated() -> None:
    bindings, aliases = _tables()
    with pytest.raises(SecretReferenceError) as service_failure:
        validate_secret_reference(
            CANONICAL_REF,
            service_id="api-token",
            environment="development",
            allowed_bindings=bindings,
            provider_aliases=aliases,
        )
    _assert_content_free(service_failure.value, SecretReferenceCode.INVALID_SERVICE_SCOPE)

    with pytest.raises(SecretReferenceError) as environment_failure:
        validate_secret_reference(
            CANONICAL_REF,
            service_id="market-data",
            environment=cast(EnvironmentV1, "staging"),
            allowed_bindings=bindings,
            provider_aliases=aliases,
        )
    _assert_content_free(environment_failure.value, SecretReferenceCode.INVALID_ENVIRONMENT_SCOPE)

    forged_bindings = AllowedSecretBindingsV1.model_validate(
        {"schema_version": "1", "bindings": (("market-data", "development", CANONICAL_REF),)}
    )
    with pytest.raises(SecretReferenceError) as binding_failure:
        validate_secret_reference(
            CANONICAL_REF,
            service_id="market-data",
            environment="development",
            allowed_bindings=forged_bindings,
            provider_aliases=aliases,
        )
    _assert_content_free(binding_failure.value, SecretReferenceCode.INVALID_BINDING_TABLE)

    forged_aliases = ProviderAliasMapV1.model_validate(
        {"schema_version": "1", "aliases": (("polygon", "massive", "development"),)}
    )
    with pytest.raises(SecretReferenceError) as alias_failure:
        validate_secret_reference(
            ALIAS_REF,
            service_id="market-data",
            environment="development",
            allowed_bindings=bindings,
            provider_aliases=forged_aliases,
        )
    _assert_content_free(alias_failure.value, SecretReferenceCode.INVALID_ALIAS_MAP)


def test_alias_rows_are_closed_unique_and_one_hop() -> None:
    with pytest.raises(SecretReferenceError) as duplicate:
        issue_provider_alias_map(
            (
                ("polygon", "massive", "development"),
                ("polygon", "massive-alt", "development"),
            )
        )
    _assert_content_free(duplicate.value, SecretReferenceCode.INVALID_ALIAS_MAP)

    with pytest.raises(SecretReferenceError) as chained:
        issue_provider_alias_map(
            (
                ("polygon", "massive", "development"),
                ("massive", "massive-alt", "development"),
            )
        )
    _assert_content_free(chained.value, SecretReferenceCode.INVALID_ALIAS_MAP)
