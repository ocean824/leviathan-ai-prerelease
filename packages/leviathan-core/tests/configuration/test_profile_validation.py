"""CFG-001 writer tests for bounded, inert configuration validation."""

from __future__ import annotations

import builtins
import json
import pickle
from collections.abc import Callable
from copy import copy, deepcopy
from dataclasses import FrozenInstanceError, replace
from decimal import Decimal
from types import MappingProxyType

import pytest

from leviathan_core.configuration import (
    EndpointRegistryV1,
    ParameterRuleV1,
    ProfileValidationError,
    ReferenceCatalogV1,
    StrategyProfileV1,
    enforce_immutable_version,
    load_parameter_set,
    load_strategy_profile,
)

REFERENCES = {
    "connectors": ("paper-broker",),
    "data_feeds": ("bars",),
    "risk_guards": ("sovereign",),
}


def profile(**changes: object) -> dict[str, object]:
    result: dict[str, object] = {
        "schema_version": 1,
        "name": "momentum-paper",
        "version": 1,
        "strategy_id": "momentum",
        "strategy_version": "1.0.0",
        "mode": "paper",
        "environment": "staging",
        "connectors": ["paper-broker"],
        "data_feeds": ["bars"],
        "risk_guard": "sovereign",
        "parameter_schema": {"alpha": {"type": "number", "minimum": 0, "maximum": 1}},
        "parameters": {"alpha": 0.5},
        "secret_refs": {
            "data": "vault://leviathan-ai/development/fred/FRED_API_KEY",
        },
        "published": True,
    }
    result.update(changes)
    return result


def load_profile(
    data: dict[str, object], *, endpoint_registry: EndpointRegistryV1 | None = None,
) -> StrategyProfileV1:
    return load_strategy_profile(json.dumps(data), format="json", available_references=REFERENCES,
                                 endpoint_registry=endpoint_registry)


def assert_issue(document: str, code: str, path: str, *, format: str = "json") -> None:
    with pytest.raises(ProfileValidationError) as caught:
        load_strategy_profile(
            document, format=format, available_references=REFERENCES  # type: ignore[arg-type]
        )
    assert (caught.value.code, caught.value.path) == (code, path)


def test_yaml_json_semantic_equivalence_and_deep_immutability() -> None:
    json_profile = load_profile(profile())
    yaml_profile = load_strategy_profile(
        """schema_version: 1
name: momentum-paper
version: 1
strategy_id: momentum
strategy_version: 1.0.0
mode: paper
environment: staging
connectors: [paper-broker]
data_feeds: [bars]
risk_guard: sovereign
parameter_schema:
  alpha: {type: number, minimum: 0, maximum: 1}
parameters: {alpha: 0.5}
secret_refs:
  data: vault://leviathan-ai/development/fred/FRED_API_KEY
published: true
""",
        format="yaml",
        available_references=REFERENCES,
    )
    assert json_profile.content_hash == yaml_profile.content_hash
    assert json_profile == yaml_profile
    with pytest.raises(FrozenInstanceError):
        json_profile.version = 2  # type: ignore[misc]


@pytest.mark.parametrize(
    ("document", "code"),
    [
        ('{"x":1,"x":2}', "DUPLICATE_KEY"),
        ("x: 1\nx: 2", "DUPLICATE_KEY"),
        ("x: &a test\ny: *a", "YAML_FEATURE_FORBIDDEN"),
        ("x: !python/object:builtins.object {}", "YAML_FEATURE_FORBIDDEN"),
        ("? [bad, key]\n: value", "INVALID_TYPE"),
    ],
)
def test_parser_rejects_ambiguous_or_executable_yaml(document: str, code: str) -> None:
    format = "json" if document.startswith("{") else "yaml"
    assert_issue(document, code, "", format=format)


def test_size_and_depth_caps() -> None:
    assert_issue(" " * (256 * 1024 + 1), "DOCUMENT_TOO_LARGE", "")
    assert_issue("[" * 25 + "0" + "]" * 25, "DOCUMENT_LIMIT_EXCEEDED", "")


def test_secret_field_rejection_is_redacted() -> None:
    marker = "VERY_PRIVATE_CREDENTIAL_VALUE"
    data = profile(api_key=marker)
    with pytest.raises(ProfileValidationError) as caught:
        load_profile(data)
    assert (caught.value.code, caught.value.path) == ("SECRET_PLAINTEXT", "")
    assert marker not in str(caught.value)
    assert marker not in repr(caught.value.issues)


@pytest.mark.parametrize(
    ("uri", "code"),
    [
        ("vault://other/development/fred/FRED_API_KEY", "SECRET_SCOPE_MISMATCH"),
        ("vault://leviathan-ai/live/fred/FRED_API_KEY", "SECRET_ENVIRONMENT_MISMATCH"),
        ("vault://leviathan-ai/development/fred/FRED_API_KEY#key", "INVALID_SECRET_REFERENCE"),
        ("dpapi-current-user://leviathan-ai--development--FRED_API_KEY.dpapi",
         "INVALID_SECRET_REFERENCE"),
    ],
)
def test_secret_binding_exact_shape(uri: str, code: str) -> None:
    with pytest.raises(ProfileValidationError) as caught:
        load_profile(profile(secret_refs={"data": uri}))
    assert caught.value.code == code
    assert caught.value.path == "/secret_refs"


def test_vault_identity_grammar_parity_is_test_only() -> None:
    from leviathan_vault.client import NAME_RE, PROJECT_ENVIRONMENTS, PROJECT_SCOPE
    from leviathan_vault.import_keys import _provider

    assert PROJECT_SCOPE == "leviathan-ai"
    assert {"development", "live"} == PROJECT_ENVIRONMENTS
    assert NAME_RE.fullmatch("FRED_API_KEY")
    assert not NAME_RE.fullmatch("fred-api-key")
    assert _provider("MASSIVE_DATA").lower().replace("_", "-") == "massive-data"


def test_missing_reference_and_live_environment() -> None:
    with pytest.raises(ProfileValidationError) as caught:
        load_profile(profile(connectors=["unknown"]))
    assert (caught.value.code, caught.value.path) == ("UNRESOLVED_REFERENCE", "/connectors/0")
    with pytest.raises(ProfileValidationError) as caught:
        load_profile(profile(mode="live", environment="staging"))
    assert (caught.value.code, caught.value.path) == ("INVALID_VALUE", "/environment")


def test_parameter_values_cannot_smuggle_credential_fields() -> None:
    with pytest.raises(ProfileValidationError) as caught:
        load_profile(profile(parameters={"api_key": "plaintext-secret"}))
    assert (caught.value.code, caught.value.path) == ("SECRET_PLAINTEXT", "/parameters")


def test_parameter_set_version_is_immutable_and_typed() -> None:
    base: dict[str, object] = {
        "schema_version": 1, "name": "alpha-set", "version": 1,
        "strategy_id": "momentum", "strategy_version": "1.0.0",
        "schema": {"alpha": {"type": "number", "minimum": 0, "maximum": 1}},
        "values": {"alpha": 0.5}, "locked": True,
    }
    first = load_parameter_set(json.dumps(base), format="json")
    revised = load_parameter_set(json.dumps({**base, "values": {"alpha": 0.7}}), format="json")
    with pytest.raises(ProfileValidationError) as caught:
        enforce_immutable_version(first, revised)
    assert (caught.value.code, caught.value.path) == ("IMMUTABLE_VERSION_CONFLICT", "/version")
    successor = load_parameter_set(json.dumps({**base, "version": 2}), format="json")
    enforce_immutable_version(first, successor)


def test_replace_cannot_reuse_stale_hash_or_mutable_nested_mapping() -> None:
    original = load_profile(profile())
    replacement = replace(original, parameters=MappingProxyType({"alpha": Decimal("0.9")}))
    assert replacement.content_hash != original.content_hash
    with pytest.raises(ProfileValidationError) as caught:
        enforce_immutable_version(original, replacement)
    assert (caught.value.code, caught.value.path) == ("IMMUTABLE_VERSION_CONFLICT", "/version")
    changed_mode = replace(
        original, mode="live", environment="production",
        secret_refs={"data": "vault://leviathan-ai/live/fred/FRED_API_KEY"},
    )
    assert changed_mode.content_hash != original.content_hash
    with pytest.raises(ProfileValidationError):
        enforce_immutable_version(original, changed_mode)
    external = {"alpha": Decimal("0.8")}
    frozen = replace(original, parameters=external)
    external["alpha"] = Decimal("0.1")
    assert frozen.parameters["alpha"] == Decimal("0.8")
    with pytest.raises(TypeError):
        frozen.parameters["alpha"] = Decimal("0.2")  # type: ignore[index]


@pytest.mark.parametrize("credential", [
    "api_key=dummy_secret_123",
    "Bearer abc.def.ghi",
    '{"api_key":"dummy_secret_123"}',
    "{'password': 'dummy_secret_123'}",
    "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----",
    "uDf9xN3pQ7vLm2Rk8TzA4B",
])
def test_plaintext_credential_values_under_benign_name_are_redacted(credential: str) -> None:
    data = profile(parameter_schema={"endpoint": {"type": "string", "kind": "enum",
                                                   "choices": [credential]}},
                   parameters={"endpoint": credential})
    with pytest.raises(ProfileValidationError) as caught:
        load_profile(data)
    assert (caught.value.code, caught.value.path) == ("SECRET_PLAINTEXT", "/parameters")
    assert credential not in str(caught.value)
    assert credential not in repr(caught.value.issues)


def test_parameter_set_string_value_gets_same_credential_check() -> None:
    data = {
        "schema_version": 1, "name": "string-set", "version": 1,
        "strategy_id": "momentum", "strategy_version": "1.0.0",
        "schema": {"endpoint": {"type": "string", "kind": "enum",
                                "choices": ["token=dummy_secret_123"]}},
        "values": {"endpoint": "token=dummy_secret_123"},
    }
    with pytest.raises(ProfileValidationError) as caught:
        load_parameter_set(json.dumps(data), format="json")
    assert (caught.value.code, caught.value.path) == ("SECRET_PLAINTEXT", "/values")


@pytest.mark.parametrize("credential", ["api key=abc123", "access_token=abc123"])
def test_r6_plaintext_reproductions_are_redacted(credential: str) -> None:
    data = profile(
        parameter_schema={"endpoint": {"type": "string", "kind": "enum",
                                       "choices": [credential]}},
        parameters={"endpoint": credential},
    )
    with pytest.raises(ProfileValidationError) as caught:
        load_profile(data)
    assert (caught.value.code, caught.value.path) == ("SECRET_PLAINTEXT", "/parameters")
    assert credential not in str(caught.value)


def test_replace_cannot_store_an_undeclared_or_plaintext_string() -> None:
    original = load_profile(profile())
    with pytest.raises(ProfileValidationError) as caught:
        replace(original, parameters={"alpha": "api key=abc123"})
    assert (caught.value.code, caught.value.path) == ("INVALID_TYPE", "/parameters")
    with pytest.raises(ProfileValidationError) as caught:
        replace(original, parameter_schema={"endpoint": ParameterRuleV1(
            "endpoint", "string", kind="enum", choices=("safe",)
        )},
                parameters={"endpoint": "access_token=abc123"})
    assert (caught.value.code, caught.value.path) == ("SECRET_PLAINTEXT", "/parameters")


@pytest.mark.parametrize("endpoint", [
    "https://example.com/path?", "https://example.com/path#",
    "https://example.com/pa\nth", "https://user@example.com/path",
])
def test_url_kind_rejects_delimiters_controls_and_userinfo(endpoint: str) -> None:
    data = profile(
        parameter_schema={"endpoint": {"type": "string", "kind": "url",
                                       "hosts": ["example.com"]}},
        parameters={"endpoint": endpoint},
    )
    with pytest.raises(ProfileValidationError) as caught:
        load_profile(data)
    assert (caught.value.code, caught.value.path) == ("INVALID_VALUE", "/parameters")


def test_replace_revalidates_secret_refs_mode_and_schema_version() -> None:
    original = load_profile(profile())
    for changes, code, path in (
        ({"version": 2, "secret_refs": {"data": "api key=abc123"}},
         "INVALID_SECRET_REFERENCE", "/secret_refs"),
        ({"version": 2, "mode": "live", "environment": "test"},
         "INVALID_VALUE", "/environment"),
        ({"version": 2, "schema_version": True},
         "INVALID_TYPE", "/schema_version"),
    ):
        with pytest.raises(ProfileValidationError) as caught:
            replace(original, **changes)
        assert (caught.value.code, caught.value.path) == (code, path)


def test_endpoint_ids_and_urls_require_exact_immutable_registry_membership() -> None:
    registry = EndpointRegistryV1(
        "snapshot-1", {"prices-primary": "https://example.com/v1/quotes"}
    )
    with pytest.raises(TypeError):
        registry.entries["prices-primary"] = "https://example.com/other"  # type: ignore[index]
    endpoint_id = profile(
        parameter_schema={"endpoint": {"type": "string", "kind": "endpoint_id"}},
        parameters={"endpoint": "prices-primary"},
    )
    with pytest.raises(ProfileValidationError) as missing:
        load_profile(endpoint_id)
    assert (missing.value.code, missing.value.path) == ("REQUIRED_FIELD", "/endpoint_registry")
    loaded = load_profile(endpoint_id, endpoint_registry=registry)
    assert loaded.parameters["endpoint"] == "prices-primary"
    with pytest.raises(ProfileValidationError) as nonmember:
        load_profile(profile(parameter_schema=endpoint_id["parameter_schema"],
                             parameters={"endpoint": "other-endpoint"}),
                     endpoint_registry=registry)
    assert (nonmember.value.code, nonmember.value.path) == (
        "UNRESOLVED_REFERENCE", "/parameters"
    )
    url_schema = {"endpoint": {"type": "string", "kind": "url", "hosts": ["example.com"]}}
    exact = load_profile(profile(parameter_schema=url_schema,
                                 parameters={"endpoint": "https://example.com/v1/quotes"}),
                         endpoint_registry=registry)
    assert exact.parameters["endpoint"] == registry.entries["prices-primary"]
    token_url = "https://example.com/auth/D4v8F2q7M1r9L3s6T0u5W8x2Y7z4A1b6"
    with pytest.raises(ProfileValidationError) as token:
        load_profile(profile(parameter_schema=url_schema, parameters={"endpoint": token_url}),
                     endpoint_registry=registry)
    assert (token.value.code, token.value.path) == ("UNRESOLVED_REFERENCE", "/parameters")


@pytest.mark.parametrize("format", ["json", "yaml"])
def test_escaped_lone_surrogate_is_typed_and_unretained(format: str) -> None:
    document = (
        '{"schema_version":1,"name":"alpha-set","version":1,"strategy_id":"momentum",'
        '"strategy_version":"1.0.0","schema":{"note":{"type":"string"}},'
        '"values":{"note":"dummy_secret_value_123\\uD800"}}'
        if format == "json" else
        """schema_version: 1
name: alpha-set
version: 1
strategy_id: momentum
strategy_version: 1.0.0
schema: {note: {type: string}}
values: {note: "dummy_secret_value_123\\uD800"}
"""
    )
    with pytest.raises(ProfileValidationError) as caught:
        load_parameter_set(document, format=format)  # type: ignore[arg-type]
    assert (caught.value.code, caught.value.path) == ("DOCUMENT_SYNTAX", "")
    assert caught.value.__context__ is None
    assert "dummy_secret_value_123" not in str(caught.value)
    with pytest.raises(ProfileValidationError) as raw_caught:
        load_parameter_set(document.replace("\\uD800", "\ud800"), format=format)  # type: ignore[arg-type]
    assert (raw_caught.value.code, raw_caught.value.path) == ("DOCUMENT_SYNTAX", "")
    assert raw_caught.value.__context__ is None


def test_reference_catalog_is_frozen_and_uses_exact_ids() -> None:
    catalog = ReferenceCatalogV1(
        frozenset({"paper-broker"}), frozenset({"bars"}), frozenset({"sovereign"})
    )
    assert isinstance(catalog.connectors, frozenset)
    with pytest.raises(ProfileValidationError) as caught:
        load_strategy_profile(
            json.dumps(profile(connectors=["paper"])), format="json",
            available_references=catalog,
        )
    assert (caught.value.code, caught.value.path) == ("UNRESOLVED_REFERENCE", "/connectors/0")
    with pytest.raises(ProfileValidationError) as caught:
        load_strategy_profile(json.dumps(profile()), format="json", available_references={
            "connectors": "paper-broker", "data_feeds": "bars", "risk_guards": "sovereign"
        })
    assert (caught.value.code, caught.value.path) == (
        "INVALID_TYPE", "/available_references/connectors"
    )


@pytest.mark.parametrize("operation", [copy, deepcopy, pickle.dumps])
def test_configuration_values_cannot_be_copied_or_pickled(
    operation: Callable[[object], object],
) -> None:
    profile_value = load_profile(profile())
    parameter_value = load_parameter_set(json.dumps({
        "schema_version": 1, "name": "alpha-set", "version": 1,
        "strategy_id": "momentum", "strategy_version": "1.0.0",
        "schema": {"alpha": {"type": "number"}}, "values": {"alpha": 0.5},
    }), format="json")
    for value in (profile_value, parameter_value):
        with pytest.raises(TypeError):
            operation(value)


def test_decimal_inputs_over_34_digits_are_typed_and_never_rounded() -> None:
    digits = "1234567890123456789012345678901234"
    base = {
        "schema_version": 1, "name": "precision-set", "version": 1,
        "strategy_id": "momentum", "strategy_version": "1.0.0",
        "schema": {"alpha": {"type": "number"}},
    }

    def document(lexeme: str) -> str:
        return json.dumps(base)[:-1] + ',"values":{"alpha":0.' + lexeme + "}}"

    accepted = load_parameter_set(document(digits), format="json")
    assert accepted.values["alpha"] == Decimal("0." + digits)
    over_limit = "0." + digits + "5"
    with pytest.raises(ProfileValidationError) as caught:
        load_parameter_set(document(digits + "5"), format="json")
    assert caught.value.code == "PRECISION_EXCEEDED"
    assert over_limit not in str(caught.value)
    with pytest.raises(ProfileValidationError) as caught:
        replace(accepted, values={"alpha": Decimal(over_limit)})
    assert (caught.value.code, caught.value.path) == ("PRECISION_EXCEEDED", "/values")
    with pytest.raises(ProfileValidationError) as huge_integer:
        replace(accepted, values={"alpha": 10**10000})
    assert (huge_integer.value.code, huge_integer.value.path) == ("INVALID_VALUE", "/values")


def test_decimal_numeric_hash_normalization_and_precision() -> None:
    base = {
        "schema_version": 1, "name": "decimal-set", "version": 1,
        "strategy_id": "momentum", "strategy_version": "1.0.0",
        "schema": {"alpha": {"type": "number"}},
    }

    def load(value: str, *, format: str = "json") -> str:
        if format == "json":
            document = json.dumps(base)[:-1] + ',"values":{"alpha":' + value + "}}"
        else:
            document = (
                "schema_version: 1\nname: decimal-set\nversion: 1\nstrategy_id: momentum\n"
                "strategy_version: 1.0.0\nschema: {alpha: {type: number}}\n"
                f"values: {{alpha: {value}}}\n"
            )
        return load_parameter_set(document, format=format).content_hash  # type: ignore[arg-type]

    assert load("1") == load("1.0") == load("1.00") == load("1.00", format="yaml")
    assert load("1.1") != load("1.10000001")
    with pytest.raises(ProfileValidationError) as caught:
        load('"1"')
    assert (caught.value.code, caught.value.path) == ("INVALID_TYPE", "/values")
    with pytest.raises(ProfileValidationError) as caught:
        load("NaN")
    assert caught.value.code == "INVALID_VALUE"
    numeric = load_parameter_set(
        json.dumps({**base, "values": {"alpha": 1.5}}), format="json"
    )
    assert numeric.values["alpha"] == Decimal("1.5")
    with pytest.raises(ProfileValidationError) as caught:
        replace(numeric, values={"alpha": 0.1})
    assert (caught.value.code, caught.value.path) == ("INVALID_VALUE", "/values")


def test_compact_decimal_bounds_precede_expansion_and_strip_coefficient_zeroes() -> None:
    base = {
        "schema_version": 1, "name": "bounded-set", "version": 1,
        "strategy_id": "momentum", "strategy_version": "1.0.0",
        "schema": {"alpha": {"type": "number"}},
    }

    def load_lexeme(lexeme: str) -> object:
        document = json.dumps(base)[:-1] + ',"values":{"alpha":' + lexeme + "}}"
        return load_parameter_set(document, format="json")

    digits = "1234567890123456789012345678901234"
    exact = load_lexeme("0." + digits)
    with_zeroes = load_lexeme("0." + digits + "0000")
    assert exact.content_hash == with_zeroes.content_hash  # type: ignore[attr-defined]
    with pytest.raises(ProfileValidationError) as precision:
        load_lexeme("0." + digits + "5")
    assert precision.value.code == "PRECISION_EXCEEDED"
    for lexeme in ("1E+34", "1E+100000", "12345678901234567890123456789012345"):
        with pytest.raises(ProfileValidationError) as out_of_bounds:
            load_lexeme(lexeme)
        assert out_of_bounds.value.code == "INVALID_VALUE"


def test_live_validation_does_not_import_or_call_execution_modules(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_import = builtins.__import__

    def guarded_import(name: str, *args: object, **kwargs: object) -> object:
        if any(part in name for part in (".risk", ".route", ".execution", ".oms")):
            raise AssertionError("validation crossed into execution")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    result = load_profile(profile(
        mode="live", environment="production",
        secret_refs={"data": "vault://leviathan-ai/live/fred/FRED_API_KEY"},
    ))
    assert result.mode == "live"
