"""Independent requirement-level acceptance cases for CFG-001."""

import json
import pickle
import sys
from collections.abc import Mapping
from copy import copy, deepcopy
from dataclasses import replace
from decimal import Decimal
from types import MappingProxyType

import pytest

from leviathan_core.configuration import (
    EndpointRegistryV1,
    ParameterSetV1,
    ProfileValidationError,
    ReferenceCatalogV1,
    StrategyProfileV1,
    enforce_immutable_version,
    load_parameter_set,
    load_strategy_profile,
)

REFERENCES = {
    "connectors": {"paper-feed"},
    "data_feeds": {"bars"},
    "risk_guards": {"standard"},
}


def endpoint_registry(entries=None) -> EndpointRegistryV1:
    return EndpointRegistryV1(
        snapshot_id="network-endpoints-v1",
        entries=(
            {"market-data-primary": "https://example.com/v1/quotes"}
            if entries is None
            else entries
        ),
    )


def profile_document(**overrides) -> dict:
    profile = {
        "schema_version": 1,
        "name": "momentum-paper",
        "version": 1,
        "strategy_id": "momentum",
        "strategy_version": "1.2.3",
        "mode": "paper",
        "environment": "test",
        "connectors": ["paper-feed"],
        "data_feeds": ["bars"],
        "risk_guard": "standard",
        "parameter_schema": {
            "lookback": {"type": "integer", "minimum": 1, "maximum": 100},
            "threshold": {"type": "number", "minimum": 0, "maximum": 1},
        },
        "parameters": {"lookback": 20, "threshold": 0.25},
        "secret_refs": {
            "market_data": "vault://leviathan-ai/development/massive/MASSIVE_API_KEY"
        },
        "published": True,
    }
    profile.update(overrides)
    return profile


def valid_profile(**overrides) -> StrategyProfileV1:
    return load_strategy_profile(
        json.dumps(profile_document(**overrides)),
        format="json",
        available_references=REFERENCES,
    )


def parameter_set(*, version=1, locked=False, values=None) -> ParameterSetV1:
    document = {
        "schema_version": 1,
        "name": "momentum-parameters",
        "version": version,
        "strategy_id": "momentum",
        "strategy_version": "1.2.3",
        "schema": {"lookback": {"type": "integer", "minimum": 1, "maximum": 100}},
        "values": values or {"lookback": 20},
        "locked": locked,
    }
    return load_parameter_set(json.dumps(document), format="json")


def number_parameter_set(value_token: str, *, format="json") -> ParameterSetV1:
    if format == "json":
        document = (
            '{"schema_version":1,"name":"numeric-parameters","version":1,'
            '"strategy_id":"momentum","strategy_version":"1.2.3",'
            '"schema":{"alpha":{"type":"number"}},'
            f'"values":{{"alpha":{value_token}}},"locked":true}}'
        )
    else:
        document = (
            "schema_version: 1\nname: numeric-parameters\nversion: 1\n"
            "strategy_id: momentum\nstrategy_version: 1.2.3\n"
            "schema:\n  alpha: {type: number}\n"
            f"values:\n  alpha: {value_token}\nlocked: true\n"
        )
    return load_parameter_set(document, format=format)


def expect_code(code: str, call) -> ProfileValidationError:
    with pytest.raises(ProfileValidationError) as caught:
        call()
    assert code in {issue.code for issue in caught.value.issues}
    assert all(issue.path.startswith("/") or issue.path == "" for issue in caught.value.issues)
    return caught.value


def test_yaml_and_json_equivalent_profiles_have_same_canonical_semantic_hash() -> None:
    profile_json = json.dumps(profile_document(), separators=(",", ":"))
    profile_yaml = """schema_version: 1
name: momentum-paper
version: 1
strategy_id: momentum
strategy_version: 1.2.3
mode: paper
environment: test
connectors: [paper-feed]
data_feeds: [bars]
risk_guard: standard
parameter_schema:
  lookback: {type: integer, minimum: 1, maximum: 100}
  threshold: {type: number, minimum: 0, maximum: 1}
parameters: {lookback: 20, threshold: 0.25}
secret_refs:
  market_data: vault://leviathan-ai/development/massive/MASSIVE_API_KEY
published: true
"""

    from_json = load_strategy_profile(profile_json, format="json", available_references=REFERENCES)
    from_yaml = load_strategy_profile(profile_yaml, format="yaml", available_references=REFERENCES)

    assert from_json.content_hash == from_yaml.content_hash


def test_hash_ignores_input_whitespace_and_mapping_order_but_tracks_semantic_changes() -> None:
    first = profile_document()
    reordered = dict(reversed(list(first.items())))
    changed = profile_document(parameters={"lookback": 21, "threshold": 0.25})
    hashes = [
        valid_profile().content_hash,
        load_strategy_profile(
            json.dumps(reordered, indent=4),
            format="json",
            available_references=REFERENCES,
        ).content_hash,
        valid_profile(**{"parameters": changed["parameters"]}).content_hash,
    ]

    assert hashes[0] == hashes[1]
    assert hashes[0] != hashes[2]
    assert len(hashes[0]) == 64
    int(hashes[0], 16)


@pytest.mark.parametrize(
    "document",
    [
        '{"schema_version":1,"schema_version":1}',
        '{"schema_version":1,"name":"first","name":"second"}',
    ],
)
def test_json_duplicate_keys_are_rejected(document: str) -> None:
    expect_code("DUPLICATE_KEY", lambda: load_strategy_profile(document, format="json"))


def test_yaml_duplicate_keys_are_rejected() -> None:
    expect_code(
        "DUPLICATE_KEY",
        lambda: load_strategy_profile(
            "schema_version: 1\nschema_version: 1\n", format="yaml"
        ),
    )


@pytest.mark.parametrize(
    "document",
    [
        "base: &base {schema_version: 1}\ncopy: *base\n",
        "!dangerous/object {schema_version: 1}\n",
        "schema_version: 1\nname: !ruby/object:Kernel {}\n",
    ],
)
def test_yaml_tags_anchors_and_aliases_are_rejected(document: str) -> None:
    expect_code("YAML_FEATURE_FORBIDDEN", lambda: load_strategy_profile(document, format="yaml"))


def test_non_string_yaml_mapping_keys_are_rejected() -> None:
    document = """schema_version: 1
name: example
version: 1
strategy_id: s
strategy_version: 1.0.0
mode: paper
environment: test
risk_guard: standard
parameters: {1: invalid}
"""

    error = expect_code("INVALID_TYPE", lambda: load_strategy_profile(document, format="yaml"))
    assert all(isinstance(issue.path, str) for issue in error.issues)


def test_256_kibibyte_input_boundary_is_enforced_in_bytes() -> None:
    too_large = " " * (256 * 1024 + 1)

    expect_code("DOCUMENT_TOO_LARGE", lambda: load_strategy_profile(too_large, format="json"))


def test_deeply_nested_document_is_rejected_with_typed_validation_error() -> None:
    nested = "[" * 300 + "0" + "]" * 300
    document = '{"schema_version":1,"extension":' + nested + "}"

    error = expect_code(
        "DOCUMENT_LIMIT_EXCEEDED",
        lambda: load_strategy_profile(document, format="json"),
    )
    assert any(issue.path == "" for issue in error.issues)


def test_document_with_excessive_item_count_is_rejected_at_document_boundary() -> None:
    document = json.dumps({"schema_version": 1, "extension": [0] * 12_000})

    error = expect_code(
        "DOCUMENT_LIMIT_EXCEEDED",
        lambda: load_strategy_profile(document, format="json"),
    )
    assert any(issue.path == "" for issue in error.issues)


def test_forbidden_plaintext_credential_is_rejected_without_echoing_value() -> None:
    secret_marker = "plaintext-credential-secret-marker"
    document = profile_document(password=secret_marker)

    error = expect_code(
        "SECRET_PLAINTEXT",
        lambda: load_strategy_profile(
            json.dumps(document), format="json", available_references=REFERENCES
        ),
    )

    assert secret_marker not in str(error)
    assert all(issue.code.isupper() for issue in error.issues)


@pytest.mark.parametrize(
    "reference",
    [
        "vault://factory-admin/development/massive/MASSIVE_API_KEY",
        "vault://leviathan-ai/test/massive/MASSIVE_API_KEY",
        "vault://leviathan-ai/development/Massive Data/MASSIVE_API_KEY",
        "vault://leviathan-ai/development/massive/bad-name",
        "vault://leviathan-ai/development/massive/MASSIVE_API_KEY?raw=1",
        "vault://leviathan-ai/development/massive/MASSIVE_API_KEY#fragment",
        "vault://leviathan-ai/development/massive/%4DASSIVE_API_KEY",
        "vault://user@leviathan-ai/development/massive/MASSIVE_API_KEY",
        "vault://leviathan-ai/development/massive/MASSIVE_API_KEY/extra",
        "vault://leviathan-ai//massive/MASSIVE_API_KEY",
    ],
)
def test_malformed_or_unapproved_vault_reference_shape_is_rejected(reference: str) -> None:
    document = profile_document(secret_refs={"market_data": reference})
    error = expect_code(
        "INVALID_SECRET_REFERENCE",
        lambda: load_strategy_profile(
            json.dumps(document), format="json", available_references=REFERENCES
        ),
    )
    assert reference not in str(error)


def test_vault_reference_scope_must_be_project_scoped() -> None:
    document = profile_document(
        secret_refs={"market_data": "vault://factory-admin/development/massive/MASSIVE_API_KEY"}
    )

    expect_code(
        "SECRET_SCOPE_MISMATCH",
        lambda: load_strategy_profile(
            json.dumps(document), format="json", available_references=REFERENCES
        ),
    )


def test_live_vault_reference_requires_live_mode_and_production_environment() -> None:
    document = profile_document(
        mode="live",
        environment="production",
        secret_refs={"market_data": "vault://leviathan-ai/development/massive/MASSIVE_API_KEY"},
    )

    expect_code(
        "SECRET_ENVIRONMENT_MISMATCH",
        lambda: load_strategy_profile(
            json.dumps(document), format="json", available_references=REFERENCES
        ),
    )


def test_valid_live_profile_remains_inert_data() -> None:
    live_references = {
        "connectors": {"paper-feed"},
        "data_feeds": {"bars"},
        "risk_guards": {"standard"},
    }
    document = profile_document(
        mode="live",
        environment="production",
        secret_refs={"market_data": "vault://leviathan-ai/live/massive/MASSIVE_API_KEY"},
    )

    result = load_strategy_profile(
        json.dumps(document), format="json", available_references=live_references
    )

    assert result.mode == "live"
    assert result.environment == "production"
    assert result.secret_refs["market_data"].startswith("vault://")


def test_unknown_declared_references_are_reported_as_unresolved() -> None:
    document = profile_document(connectors=["not-approved"])

    expect_code(
        "UNRESOLVED_REFERENCE",
        lambda: load_strategy_profile(
            json.dumps(document), format="json", available_references=REFERENCES
        ),
    )


def test_parameter_values_are_checked_against_declared_types_and_bounds() -> None:
    document = profile_document(parameters={"lookback": 0, "threshold": 0.25})

    error = expect_code(
        "INVALID_VALUE",
        lambda: load_strategy_profile(
            json.dumps(document), format="json", available_references=REFERENCES
        ),
    )
    assert all(issue.path.startswith("/") for issue in error.issues)


def test_validated_profile_and_nested_parameter_data_are_immutable() -> None:
    result = valid_profile()

    with pytest.raises((TypeError, AttributeError)):
        result.name = "mutated"  # type: ignore[misc]
    with pytest.raises(TypeError):
        result.parameters["lookback"] = 99  # type: ignore[index]
    with pytest.raises(TypeError):
        result.parameter_schema["lookback"]["minimum"] = 0  # type: ignore[index]


def test_parameter_set_locked_values_are_deeply_immutable() -> None:
    result = parameter_set(locked=True)

    with pytest.raises((TypeError, AttributeError)):
        result.locked = False  # type: ignore[misc]
    with pytest.raises(TypeError):
        result.values["lookback"] = 50  # type: ignore[index]


@pytest.mark.parametrize("operation", [copy, deepcopy, pickle.dumps])
def test_validated_profiles_and_parameter_sets_cannot_be_copied_or_pickled(
    operation,
) -> None:
    values = (valid_profile(), parameter_set(locked=True))

    for value in values:
        with pytest.raises(TypeError):
            operation(value)


def test_same_profile_version_cannot_be_mutated_in_place() -> None:
    original = valid_profile()
    changed = valid_profile(parameters={"lookback": 21, "threshold": 0.25})

    error = expect_code(
        "IMMUTABLE_VERSION_CONFLICT",
        lambda: enforce_immutable_version(original, changed),
    )
    assert all(issue.path.startswith("/") or issue.path == "" for issue in error.issues)


def test_parameter_set_version_cannot_be_mutated_in_place_but_new_version_is_allowed() -> None:
    original = parameter_set(locked=True)
    changed_same_version = parameter_set(locked=True, values={"lookback": 21})
    new_version = parameter_set(version=2, locked=True, values={"lookback": 21})

    expect_code(
        "IMMUTABLE_VERSION_CONFLICT",
        lambda: enforce_immutable_version(original, changed_same_version),
    )
    assert enforce_immutable_version(original, new_version) is None


def test_validation_error_paths_are_json_pointers_and_values_never_appear() -> None:
    marker = "sensitive-profile-content-marker"
    document = profile_document(password=marker)

    error = expect_code(
        "SECRET_PLAINTEXT",
        lambda: load_strategy_profile(
            json.dumps(document), format="json", available_references=REFERENCES
        ),
    )

    assert marker not in str(error)
    assert all(isinstance(issue.path, str) for issue in error.issues)
    assert all(isinstance(issue.code, str) and issue.code.isupper() for issue in error.issues)


def test_live_profile_parsing_does_not_mutate_reference_catalog() -> None:
    references = {
        "connectors": {"paper-feed"},
        "data_feeds": {"bars"},
        "risk_guards": {"standard"},
    }
    before = {key: set(value) for key, value in references.items()}
    governed_modules = {
        name
        for name in sys.modules
        if name.startswith("leviathan_core.")
        and name.rsplit(".", 1)[-1] in {"risk", "route", "oms", "execution"}
    }
    document = profile_document(
        mode="live",
        environment="production",
        secret_refs={"market_data": "vault://leviathan-ai/live/massive/MASSIVE_API_KEY"},
    )

    load_strategy_profile(json.dumps(document), format="json", available_references=references)

    assert references == before
    assert isinstance(references, Mapping)
    newly_loaded = {
        name
        for name in sys.modules
        if name.startswith("leviathan_core.")
        and name.rsplit(".", 1)[-1] in {"risk", "route", "oms", "execution"}
    } - governed_modules
    assert newly_loaded == set()


def test_stale_hash_dataclass_replacements_cannot_bypass_same_version_immutability() -> None:
    original = valid_profile()
    changed_parameters = replace(
        original,
        parameters=MappingProxyType({**original.parameters, "lookback": 21}),
    )
    changed_mode = replace(
        original,
        mode="live",
        environment="production",
        secret_refs=MappingProxyType(
            {"market_data": "vault://leviathan-ai/live/massive/MASSIVE_API_KEY"}
        ),
    )

    assert changed_parameters.content_hash != original.content_hash
    assert changed_mode.content_hash != original.content_hash
    expect_code(
        "IMMUTABLE_VERSION_CONFLICT",
        lambda: enforce_immutable_version(original, changed_parameters),
    )
    expect_code(
        "IMMUTABLE_VERSION_CONFLICT",
        lambda: enforce_immutable_version(original, changed_mode),
    )


def test_replace_revalidates_secret_refs_environment_and_boolean_schema_version() -> None:
    original = valid_profile()

    secret_error = expect_code(
        "INVALID_SECRET_REFERENCE",
        lambda: replace(
            original,
            secret_refs=MappingProxyType({"market_data": "plaintext-secret-marker"}),
        ),
    )
    assert any(issue.path == "/secret_refs" for issue in secret_error.issues)
    assert "plaintext-secret-marker" not in str(secret_error)

    environment_error = expect_code(
        "INVALID_VALUE",
        lambda: replace(original, mode="live", environment="test"),
    )
    assert any(issue.path == "/environment" for issue in environment_error.issues)

    schema_version_error = expect_code(
        "INVALID_TYPE",
        lambda: replace(original, schema_version=True),
    )
    assert any(issue.path == "/schema_version" for issue in schema_version_error.issues)


@pytest.mark.parametrize(
    "credential",
    [
        "api key=abc123",
        "access_token=abc123",
        "api_key=dummy_secret_123",
        "x-api-key=abc123",
        "client_secret=abc123",
        "Authorization: Bearer abc123",
        "user:pass@example.test",
        "prefix api key=abc123 suffix",
        "Bearer dummycredentialtoken1234567890",
        "token=dummy_secret_456",
        "password=dummy_secret_789",
        '{"password":"dummy_secret_json"}',
        "ValueError('password', 'dummy_secret_repr')",
        "-----BEGIN PRIVATE KEY-----\\nFAKEKEYMATERIAL\\n-----END PRIVATE KEY-----",
        "D4v8F2q7M1r9L3s6T0u5W8x2Y7z4A1b6",
    ],
)
def test_benign_string_parameter_names_cannot_carry_credentials(credential: str) -> None:
    profile = profile_document(
        parameter_schema={
            "endpoint": {"type": "string", "kind": "enum", "choices": ["endpoint"]}
        },
        parameters={"endpoint": credential},
    )
    profile_error = expect_code(
        "SECRET_PLAINTEXT",
        lambda: load_strategy_profile(
            json.dumps(profile), format="json", available_references=REFERENCES
        ),
    )
    parameter_set_doc = {
        "schema_version": 1,
        "name": "credential-shaped-parameter",
        "version": 1,
        "strategy_id": "momentum",
        "strategy_version": "1.2.3",
        "schema": {
            "endpoint": {"type": "string", "kind": "enum", "choices": ["endpoint"]}
        },
        "values": {"endpoint": credential},
        "locked": False,
    }
    value_error = expect_code(
        "SECRET_PLAINTEXT",
        lambda: load_parameter_set(json.dumps(parameter_set_doc), format="json"),
    )

    assert credential not in str(profile_error)
    assert credential not in repr(profile_error.issues)
    assert credential not in repr(profile_error.__dict__)
    assert credential not in str(value_error)
    assert credential not in repr(value_error.issues)
    assert credential not in repr(value_error.__dict__)


@pytest.mark.parametrize("format", ["json", "yaml"])
def test_lone_surrogate_is_a_safe_typed_error_without_retained_input(format: str) -> None:
    marker = "dummy_secret_surrogate"
    if format == "json":
        document = json.dumps(
            {
                "schema_version": 1,
                "name": "surrogate-parameter",
                "version": 1,
                "strategy_id": "momentum",
                "strategy_version": "1.2.3",
                "schema": {"note": {"type": "string", "kind": "identifier"}},
                "values": {"note": marker + "\ud800"},
                "locked": False,
            }
        )
    else:
        document = (
            "schema_version: 1\nname: surrogate-parameter\nversion: 1\n"
            "strategy_id: momentum\nstrategy_version: 1.2.3\n"
            "schema:\n  note: {type: string, kind: identifier}\n"
            f'values:\n  note: "{marker}\\uD800"\nlocked: false\n'
        )

    error = expect_code("DOCUMENT_SYNTAX", lambda: load_parameter_set(document, format=format))

    exception_chain = (error.__cause__, error.__context__)
    assert marker not in str(error)
    assert marker not in repr(error.issues)
    assert marker not in repr(error.__dict__)
    assert all(marker not in repr(chained) for chained in exception_chain)
    assert any(issue.path == "" for issue in error.issues)


@pytest.mark.parametrize("container", ["profile", "parameter_set"])
def test_string_parameters_require_a_declared_kind(container: str) -> None:
    if container == "profile":
        def load_undeclared():
            return load_strategy_profile(
                json.dumps(
                    profile_document(
                        parameter_schema={"endpoint": {"type": "string"}},
                        parameters={"endpoint": "endpoint"},
                    )
                ),
                format="json",
                available_references=REFERENCES,
            )

        expected_path = "/parameter_schema"
    else:
        document = {
            "schema_version": 1,
            "name": "undeclared-string-kind",
            "version": 1,
            "strategy_id": "momentum",
            "strategy_version": "1.2.3",
            "schema": {"endpoint": {"type": "string"}},
            "values": {"endpoint": "endpoint"},
            "locked": False,
        }

        def load_undeclared():
            return load_parameter_set(json.dumps(document), format="json")

        expected_path = "/schema"

    error = expect_code("PARAMETER_KIND_UNDECLARED", load_undeclared)
    assert any(issue.path == expected_path for issue in error.issues)


@pytest.mark.parametrize("container", ["profile", "parameter_set"])
def test_unknown_string_kind_is_rejected(container: str) -> None:
    schema_entry = {"type": "string", "kind": "free_text"}
    if container == "profile":
        def call():
            return load_strategy_profile(
                json.dumps(
                    profile_document(
                        parameter_schema={"endpoint": schema_entry},
                        parameters={"endpoint": "endpoint"},
                    )
                ),
                format="json",
                available_references=REFERENCES,
            )

        expected_path = "/parameter_schema"
    else:
        document = {
            "schema_version": 1,
            "name": "unknown-string-kind",
            "version": 1,
            "strategy_id": "momentum",
            "strategy_version": "1.2.3",
            "schema": {"endpoint": schema_entry},
            "values": {"endpoint": "endpoint"},
            "locked": False,
        }

        def call():
            return load_parameter_set(json.dumps(document), format="json")

        expected_path = "/schema"

    error = expect_code("PARAMETER_KIND_UNDECLARED", call)
    assert any(issue.path == expected_path for issue in error.issues)


def test_supported_string_kinds_validate_against_their_declared_shapes() -> None:
    document = {
        "schema_version": 1,
        "name": "typed-string-kinds",
        "version": 1,
        "strategy_id": "momentum",
        "strategy_version": "1.2.3",
        "schema": {
            "speed": {"type": "string", "kind": "enum", "choices": ["fast", "slow"]},
            "account": {"type": "string", "kind": "identifier"},
            "symbol": {"type": "string", "kind": "symbol", "provider": "nasdaq"},
            "threshold": {"type": "string", "kind": "decimal_text"},
            "timeout": {"type": "string", "kind": "duration"},
            "endpoint_id": {"type": "string", "kind": "endpoint_id"},
            "endpoint_url": {"type": "string", "kind": "url", "hosts": ["example.com"]},
            "credential": {"type": "string", "kind": "vault_ref"},
        },
        "values": {
            "speed": "fast",
            "account": "market.account-1",
            "symbol": "nasdaq:AAPL",
            "threshold": "1.25",
            "timeout": "PT5M",
            "endpoint_id": "market-data-primary",
            "endpoint_url": "https://example.com/v1/quotes",
            "credential": "vault://leviathan-ai/development/massive/MASSIVE_API_KEY",
        },
        "locked": False,
    }

    result = load_parameter_set(
        json.dumps(document), format="json", endpoint_registry=endpoint_registry()
    )

    assert result.values["speed"] == "fast"
    assert result.values["account"] == "market.account-1"
    assert result.values["symbol"] == "nasdaq:AAPL"
    assert result.values["threshold"] == "1.25"
    assert result.values["timeout"] == "PT5M"
    assert result.values["endpoint_id"] == "market-data-primary"
    assert result.values["endpoint_url"] == "https://example.com/v1/quotes"
    assert result.values["credential"] == (
        "vault://leviathan-ai/development/massive/MASSIVE_API_KEY"
    )


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/path",
        "https://user@example.com/path",
        "https://example.com/path?page=1",
        "https://example.com/path#fragment",
        "https://example.com:8443/path",
        "https://example.com/path with spaces",
        "https://not-allowed.example/path",
    ],
)
def test_url_kind_rejects_userinfo_query_and_unapproved_host(url: str) -> None:
    profile = profile_document(
        parameter_schema={
            "endpoint": {"type": "string", "kind": "url", "hosts": ["example.com"]}
        },
        parameters={"endpoint": url},
    )
    error = expect_code(
        "INVALID_VALUE",
        lambda: load_strategy_profile(
            json.dumps(profile),
            format="json",
            available_references=REFERENCES,
            endpoint_registry=endpoint_registry(),
        ),
    )

    assert url not in str(error)
    assert any(issue.path in {"/parameters", "/parameters/endpoint"} for issue in error.issues)


def test_https_path_credential_is_rejected_as_unregistered_url() -> None:
    credential = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"
    profile = profile_document(
        parameter_schema={
            "endpoint": {"type": "string", "kind": "url", "hosts": ["example.com"]}
        },
        parameters={"endpoint": f"https://example.com/v1/{credential}"},
    )

    error = expect_code(
        "UNRESOLVED_REFERENCE",
        lambda: load_strategy_profile(
            json.dumps(profile),
            format="json",
            available_references=REFERENCES,
            endpoint_registry=endpoint_registry(),
        ),
    )

    assert credential not in str(error)


@pytest.mark.parametrize(
    "url",
    [
        "https://user@example.com/v1/quotes",
        "https://example.com/v1/quotes?mode=private",
        "https://example.com/v1/quotes#private",
    ],
)
def test_endpoint_registry_rejects_userinfo_query_and_fragment(url: str) -> None:
    with pytest.raises(ProfileValidationError) as caught:
        endpoint_registry({"market-data-primary": url})

    assert url not in str(caught.value)


def test_endpoint_id_requires_an_injected_registry() -> None:
    profile = profile_document(
        parameter_schema={"endpoint": {"type": "string", "kind": "endpoint_id"}},
        parameters={"endpoint": "market-data-primary"},
    )

    error = expect_code(
        "REQUIRED_FIELD",
        lambda: load_strategy_profile(
            json.dumps(profile), format="json", available_references=REFERENCES
        ),
    )

    assert any(issue.path == "/endpoint_registry" for issue in error.issues)


def test_nonmember_endpoint_id_is_rejected_by_registry_membership() -> None:
    profile = profile_document(
        parameter_schema={"endpoint": {"type": "string", "kind": "endpoint_id"}},
        parameters={"endpoint": "unregistered-endpoint"},
    )

    error = expect_code(
        "UNRESOLVED_REFERENCE",
        lambda: load_strategy_profile(
            json.dumps(profile),
            format="json",
            available_references=REFERENCES,
            endpoint_registry=endpoint_registry(),
        ),
    )

    assert any(issue.path in {"/parameters", "/parameters/endpoint"} for issue in error.issues)


def test_url_kind_accepts_https_allowlisted_host() -> None:
    profile = profile_document(
        parameter_schema={
            "endpoint": {"type": "string", "kind": "url", "hosts": ["example.com"]}
        },
        parameters={"endpoint": "https://example.com/v1/quotes"},
    )

    result = load_strategy_profile(
        json.dumps(profile),
        format="json",
        available_references=REFERENCES,
        endpoint_registry=endpoint_registry(),
    )

    assert result.parameters["endpoint"] == "https://example.com/v1/quotes"


def test_reference_catalog_uses_immutable_exact_id_sets() -> None:
    catalog = ReferenceCatalogV1(
        connectors={"paper-feed"},
        data_feeds={"bars"},
        risk_guards={"standard"},
    )
    document = json.dumps(profile_document())

    result = load_strategy_profile(
        document, format="json", available_references=catalog
    )

    assert result.connectors == ("paper-feed",)
    with pytest.raises(AttributeError):
        catalog.connectors.add("new-connector")  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    "references",
    [
        {"connectors": "paper-feed", "data_feeds": {"bars"}, "risk_guards": {"standard"}},
        {"connectors": b"paper-feed", "data_feeds": {"bars"}, "risk_guards": {"standard"}},
        {"connectors": {"paper-feed"}, "data_feeds": "bars", "risk_guards": {"standard"}},
    ],
)
def test_scalar_string_or_bytes_reference_catalogs_are_rejected(references) -> None:
    error = expect_code(
        "INVALID_TYPE",
        lambda: load_strategy_profile(
            json.dumps(profile_document()),
            format="json",
            available_references=references,
        ),
    )
    assert any(issue.path.startswith("/available_references/") for issue in error.issues)


@pytest.mark.parametrize(
    "group,partial",
    [("connectors", "paper"), ("data_feeds", "bar"), ("risk_guards", "stand")],
)
def test_reference_resolution_never_accepts_a_catalog_substring(group: str, partial: str) -> None:
    catalog = ReferenceCatalogV1(
        connectors={"paper-feed"}, data_feeds={"bars"}, risk_guards={"standard"}
    )
    changes = {"connectors": ["paper-feed"], "data_feeds": ["bars"], "risk_guard": "standard"}
    if group == "connectors":
        changes["connectors"] = [partial]
    elif group == "data_feeds":
        changes["data_feeds"] = [partial]
    else:
        changes["risk_guard"] = partial

    error = expect_code(
        "UNRESOLVED_REFERENCE",
        lambda: load_strategy_profile(
            json.dumps(profile_document(**changes)),
            format="json",
            available_references=catalog,
        ),
    )
    assert all(issue.path.startswith("/") for issue in error.issues)


def test_numeric_values_use_normalized_decimal_hash_semantics_and_keep_precision() -> None:
    integer = number_parameter_set("1")
    decimal_one = number_parameter_set("1.0")
    decimal_two = number_parameter_set("1.00")
    yaml_decimal = number_parameter_set("1.000", format="yaml")
    precise = number_parameter_set("1.10000001")
    rounded_lookalike = number_parameter_set("1.1")

    assert integer.values["alpha"] == Decimal("1")
    assert isinstance(integer.values["alpha"], Decimal)
    assert integer.content_hash == decimal_one.content_hash
    assert integer.content_hash == decimal_two.content_hash
    assert integer.content_hash == yaml_decimal.content_hash
    assert precise.content_hash != rounded_lookalike.content_hash
    assert precise.values["alpha"] == Decimal("1.10000001")


@pytest.mark.parametrize("token", ["NaN", "Infinity", "-Infinity"])
def test_non_finite_numeric_lexemes_are_rejected(token: str) -> None:
    expect_code("INVALID_VALUE", lambda: number_parameter_set(token))


def test_numeric_string_is_not_coerced_to_a_number() -> None:
    error = expect_code(
        "INVALID_TYPE",
        lambda: number_parameter_set('"1"'),
    )
    assert any(issue.path in {"/values", "/values/alpha"} for issue in error.issues)


def test_exact_float_is_accepted_but_binary_approximation_is_rejected() -> None:
    original = number_parameter_set("1.5")
    exact_float = replace(original, values=MappingProxyType({"alpha": 1.5}))

    assert exact_float.content_hash == original.content_hash
    error = expect_code(
        "INVALID_VALUE",
        lambda: replace(
            original,
            values=MappingProxyType({"alpha": 0.1}),
        ).content_hash,
    )
    assert any(issue.path in {"/values", "/values/alpha"} for issue in error.issues)
    assert "0.1" not in str(error)


def test_number_hash_equivalence_does_not_hide_actual_decimal_precision() -> None:
    first = number_parameter_set("1.0")
    same_number = number_parameter_set("1.00")
    distinct_precision = number_parameter_set("1.000000000000000001")

    assert first.content_hash == same_number.content_hash
    assert first.content_hash != distinct_precision.content_hash


def test_numeric_inputs_over_working_precision_are_rejected_without_rounding() -> None:
    significant_digits = "1234567890123456789012345678901234"
    exact_34_digits = f"0.{significant_digits}"
    over_34_digits = f"0.{significant_digits}5"

    accepted = number_parameter_set(exact_34_digits)
    assert accepted.values["alpha"] == Decimal(exact_34_digits)

    error = expect_code(
        "PRECISION_EXCEEDED",
        lambda: number_parameter_set(over_34_digits),
    )
    assert all(over_34_digits not in str(issue) for issue in error.issues)
    assert over_34_digits not in str(error)


def test_34_digit_coefficient_with_trailing_zeroes_is_exact_and_canonical() -> None:
    significant_digits = "1234567890123456789012345678901234"
    canonical_token = f"0.{significant_digits}"
    padded_token = f"0.{significant_digits}000000"

    canonical = number_parameter_set(canonical_token)
    padded = number_parameter_set(padded_token)

    assert padded.values["alpha"] == Decimal(canonical_token)
    assert padded.content_hash == canonical.content_hash


def test_35_nonzero_significant_digits_raise_precision_exceeded() -> None:
    token = "1.1234567890123456789012345678901234"
    assert len(Decimal(token).as_tuple().digits) == 35

    error = expect_code("PRECISION_EXCEEDED", lambda: number_parameter_set(token))

    assert token not in str(error)


def test_compact_extreme_decimal_exponent_rejects_without_expansion() -> None:
    token = "1E+100000"

    error = expect_code("INVALID_VALUE", lambda: number_parameter_set(token))

    assert token not in str(error)
    assert all(issue.path == "" or issue.path.startswith("/") for issue in error.issues)


def test_cfg_absolute_numeric_cap_is_distinct_from_precision_limit() -> None:
    token = "1E+34"

    error = expect_code("INVALID_VALUE", lambda: number_parameter_set(token))

    assert "PRECISION_EXCEEDED" not in {issue.code for issue in error.issues}
    assert token not in str(error)


def test_oversized_json_integer_rejects_before_precision_stringification() -> None:
    token = "12345678901234567890123456789012345"

    error = expect_code("INVALID_VALUE", lambda: number_parameter_set(token))

    assert "PRECISION_EXCEEDED" not in {issue.code for issue in error.issues}
    assert token not in str(error)


def test_integer_fields_reject_booleans_in_profile_and_parameter_set() -> None:
    profile_cases = []
    for field in ("schema_version", "version"):
        profile_cases.append((profile_document(**{field: True}), f"/{field}"))

    minimum_true = profile_document()
    minimum_true["parameter_schema"]["lookback"]["minimum"] = True
    profile_cases.append((minimum_true, "/parameter_schema"))

    value_true = profile_document(parameters={"lookback": True, "threshold": 0.25})
    profile_cases.append((value_true, "/parameters"))

    for document, path_prefix in profile_cases:
        with pytest.raises(ProfileValidationError) as caught:
            load_strategy_profile(
                json.dumps(document), format="json", available_references=REFERENCES
            )
        assert caught.value.issues
        assert any(
            issue.path == "" or issue.path.startswith(path_prefix)
            for issue in caught.value.issues
        )

    parameter_cases = []
    for field in ("schema_version", "version"):
        document = {
            "schema_version": 1,
            "name": "momentum-parameters",
            "version": 1,
            "strategy_id": "momentum",
            "strategy_version": "1.2.3",
            "schema": {"lookback": {"type": "integer", "minimum": 1, "maximum": 100}},
            "values": {"lookback": 20},
            "locked": True,
        }
        document[field] = True
        parameter_cases.append((document, f"/{field}"))

    parameter_cases.extend(
        [
            (
                {
                    "schema_version": 1,
                    "name": "momentum-parameters",
                    "version": 1,
                    "strategy_id": "momentum",
                    "strategy_version": "1.2.3",
                    "schema": {
                        "lookback": {
                            "type": "integer",
                            "minimum": True,
                            "maximum": 100,
                        }
                    },
                    "values": {"lookback": 20},
                    "locked": True,
                },
                "/schema",
            ),
            (
                {
                    "schema_version": 1,
                    "name": "momentum-parameters",
                    "version": 1,
                    "strategy_id": "momentum",
                    "strategy_version": "1.2.3",
                    "schema": {"lookback": {"type": "integer", "minimum": 1, "maximum": 100}},
                    "values": {"lookback": True},
                    "locked": True,
                },
                "/values",
            ),
        ]
    )

    for document, path_prefix in parameter_cases:
        with pytest.raises(ProfileValidationError) as caught:
            load_parameter_set(
                json.dumps(document), format="json"
            )
        assert caught.value.issues
        assert any(
            issue.path == "" or issue.path.startswith(path_prefix)
            for issue in caught.value.issues
        )

    profile = valid_profile()
    parameters = parameter_set()
    with pytest.raises(ProfileValidationError) as profile_error:
        replace(profile, version=True)
    assert profile_error.value.issues
    with pytest.raises(ProfileValidationError) as parameter_error:
        replace(parameters, version=True)
    assert parameter_error.value.issues
