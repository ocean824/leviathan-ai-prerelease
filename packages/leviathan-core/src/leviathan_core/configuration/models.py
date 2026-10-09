"""Immutable, inert configuration value objects.

These objects carry validated data only. They have no activation or secret-read API.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from decimal import Decimal
from types import MappingProxyType
from typing import Literal, NoReturn, SupportsIndex, TypeAlias

ParameterValue: TypeAlias = str | int | Decimal | bool
ParameterType: TypeAlias = Literal["string", "integer", "number", "boolean"]
StringParameterKind: TypeAlias = Literal[
    "enum", "identifier", "symbol", "decimal_text", "duration", "url", "endpoint_id",
    "vault_ref",
]
ProfileMode: TypeAlias = Literal["backtest", "paper", "live"]
ProfileEnvironment: TypeAlias = Literal["test", "staging", "production"]
_REFERENCE_ID = re.compile(r"[a-z][a-z0-9_-]{1,63}\Z", re.ASCII)
_CODES = frozenset({
    "DOCUMENT_TOO_LARGE", "DOCUMENT_SYNTAX", "DOCUMENT_LIMIT_EXCEEDED", "DUPLICATE_KEY",
    "YAML_FEATURE_FORBIDDEN", "INVALID_TYPE", "REQUIRED_FIELD", "FORBIDDEN_FIELD",
    "INVALID_VALUE", "PRECISION_EXCEEDED", "PARAMETER_KIND_UNDECLARED",
    "UNRESOLVED_REFERENCE", "SECRET_PLAINTEXT",
    "INVALID_SECRET_REFERENCE", "SECRET_SCOPE_MISMATCH", "SECRET_ENVIRONMENT_MISMATCH",
    "IMMUTABLE_VERSION_CONFLICT",
})


@dataclass(frozen=True, slots=True)
class ValidationIssue:
    code: str
    path: str

    def __post_init__(self) -> None:
        if self.code not in _CODES or (not self.path.startswith("/") and self.path != ""):
            raise ValueError("INVALID_VALUE")


class ProfileValidationError(ValueError):
    """Allowlisted issues with JSON-pointer paths and no source values."""

    def __init__(self, issues: tuple[ValidationIssue, ...]) -> None:
        self.issues = issues
        super().__init__("; ".join(f"{issue.code} {issue.path}" for issue in issues))

    @property
    def code(self) -> str:
        return self.issues[0].code

    @property
    def path(self) -> str:
        return self.issues[0].path


def _model_fail(code: str, path: str) -> NoReturn:
    raise ProfileValidationError((ValidationIssue(code, path),))


def _check_identity(name: object, version: object, strategy_id: object,
                    strategy_version: object) -> None:
    for path, value in (("/name", name), ("/strategy_id", strategy_id),
                        ("/strategy_version", strategy_version)):
        if not isinstance(value, str):
            _model_fail("INVALID_TYPE", path)
    if type(version) is not int:
        _model_fail("INVALID_TYPE", "/version")


def _freeze_names(value: Collection[str], path: str) -> tuple[str, ...]:
    if not isinstance(value, (tuple, list)) or any(not isinstance(item, str) for item in value):
        _model_fail("INVALID_TYPE", path)
    if any(not _REFERENCE_ID.fullmatch(item) for item in value) or len(value) != len(set(value)):
        _model_fail("INVALID_VALUE", path)
    return tuple(value)


def _freeze_secret_refs(value: Mapping[str, str]) -> Mapping[str, str]:
    if not isinstance(value, Mapping):
        _model_fail("INVALID_TYPE", "/secret_refs")
    result = dict(value)
    if any(not isinstance(key, str) or not isinstance(uri, str)
           for key, uri in result.items()):
        _model_fail("INVALID_TYPE", "/secret_refs")
    return MappingProxyType(result)


def _decimal(value: int | float | Decimal) -> Decimal:
    if isinstance(value, bool):
        raise TypeError("INVALID_TYPE")
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("INVALID_VALUE")
        decimal = Decimal(str(value))
        if Decimal.from_float(value) != decimal:
            raise ValueError("INVALID_VALUE")
    elif type(value) is int:
        if value.bit_length() > 64:
            raise ValueError("INVALID_VALUE")
        decimal = Decimal(value)
    elif isinstance(value, Decimal):
        decimal = Decimal(value)
    else:
        raise TypeError("INVALID_TYPE")
    parts = decimal.as_tuple()
    exponent = parts.exponent
    significant = len(parts.digits)
    while significant > 1 and parts.digits[significant - 1] == 0:
        significant -= 1
    if significant > 34:
        raise ValueError("PRECISION_EXCEEDED")
    if (not decimal.is_finite()
            or not isinstance(exponent, int) or not -128 <= exponent <= 128
            or (not decimal.is_zero() and abs(decimal.adjusted()) > 38)
            or decimal.copy_abs() > Decimal("1000000000000000000")):
        raise ValueError("INVALID_VALUE")
    return decimal


def _canonical_number(value: int | Decimal) -> str:
    decimal = _decimal(value)
    if decimal.is_zero():
        return "0"
    text = format(decimal, "f")
    return text.rstrip("0").rstrip(".") if "." in text else text


def _checked_decimal(value: int | float | Decimal, path: str) -> Decimal:
    failure: str | None = None
    try:
        result = _decimal(value)
    except TypeError:
        failure = "INVALID_TYPE"
    except ValueError as exc:
        failure = str(exc)
    if failure is not None:
        _model_fail(failure, path)
    return result


def _freeze_rules(
    value: Mapping[str, ParameterRuleV1], path: str
) -> Mapping[str, ParameterRuleV1]:
    if not isinstance(value, Mapping):
        _model_fail("INVALID_TYPE", path)
    result = dict(value)
    if any(not isinstance(key, str) or not isinstance(rule, ParameterRuleV1)
           or key != rule.name
           for key, rule in result.items()):
        _model_fail("INVALID_TYPE", path)
    return MappingProxyType(result)


def _freeze_values(
    value: Mapping[str, ParameterValue], path: str
) -> Mapping[str, ParameterValue]:
    result: dict[str, ParameterValue] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise ProfileValidationError((ValidationIssue("INVALID_TYPE", path),))
        if isinstance(item, (int, float, Decimal)) and not isinstance(item, bool):
            failure: str | None = None
            try:
                result[key] = _decimal(item)
            except (TypeError, ValueError) as exc:
                failure = str(exc)
            if failure is not None:
                raise ProfileValidationError((ValidationIssue(failure, path),))
        elif isinstance(item, (str, bool)):
            result[key] = item
        else:
            raise ProfileValidationError((ValidationIssue("INVALID_TYPE", path),))
    return MappingProxyType(result)


def _hash(content: dict[str, object]) -> str:
    canonical = json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


class _NoCopy:
    __slots__ = ()

    def __copy__(self) -> NoReturn:
        raise TypeError("COPY_FORBIDDEN")

    def __deepcopy__(self, memo: dict[int, object]) -> NoReturn:
        raise TypeError("COPY_FORBIDDEN")

    def __reduce__(self) -> NoReturn:
        raise TypeError("COPY_FORBIDDEN")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise TypeError("COPY_FORBIDDEN")


@dataclass(frozen=True, slots=True)
class ReferenceCatalogV1(_NoCopy):
    """An immutable snapshot of exact, structurally valid reference IDs."""

    connectors: frozenset[str]
    data_feeds: frozenset[str]
    risk_guards: frozenset[str]

    def __post_init__(self) -> None:
        for field in ("connectors", "data_feeds", "risk_guards"):
            value: Collection[str] = getattr(self, field)
            if not isinstance(value, (tuple, list, set, frozenset)):
                raise TypeError("INVALID_TYPE")
            if any(not isinstance(item, str) or not _REFERENCE_ID.fullmatch(item)
                   for item in value):
                raise ValueError("INVALID_VALUE")
            object.__setattr__(self, field, frozenset(value))

    @classmethod
    def from_mapping(cls, value: Mapping[str, Collection[str]]) -> ReferenceCatalogV1:
        if set(value) != {"connectors", "data_feeds", "risk_guards"}:
            raise ValueError("INVALID_VALUE")
        entries = (value["connectors"], value["data_feeds"], value["risk_guards"])
        if any(not isinstance(item, (tuple, list, set, frozenset)) for item in entries):
            raise TypeError("INVALID_TYPE")
        return cls(*(frozenset(item) for item in entries))


@dataclass(frozen=True, slots=True)
class EndpointRegistryV1(_NoCopy):
    """Injected immutable endpoint IDs bound to one reviewed snapshot."""

    snapshot_id: str
    entries: Mapping[str, str]

    def __post_init__(self) -> None:
        from leviathan_core.configuration.validation import _valid_endpoint_url

        if not isinstance(self.snapshot_id, str) or not _REFERENCE_ID.fullmatch(
            self.snapshot_id
        ):
            _model_fail("INVALID_VALUE", "/endpoint_registry/snapshot_id")
        if not isinstance(self.entries, Mapping):
            _model_fail("INVALID_TYPE", "/endpoint_registry/entries")
        entries = dict(self.entries)
        if any(not isinstance(key, str) or not _REFERENCE_ID.fullmatch(key)
               or not isinstance(url, str) or not _valid_endpoint_url(url)
               for key, url in entries.items()):
            _model_fail("INVALID_VALUE", "/endpoint_registry/entries")
        object.__setattr__(self, "entries", MappingProxyType(entries))


@dataclass(frozen=True, slots=True)
class ParameterRuleV1(_NoCopy):
    name: str
    type: ParameterType
    minimum: Decimal | None = None
    maximum: Decimal | None = None
    kind: StringParameterKind | None = None
    choices: tuple[str, ...] = ()
    provider: str | None = None
    hosts: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not isinstance(self.type, str):
            _model_fail("INVALID_TYPE", "/parameter_schema")
        if self.type not in ("string", "integer", "number", "boolean"):
            _model_fail("INVALID_VALUE", "/parameter_schema")
        if self.type == "string" and self.kind not in (
            "enum", "identifier", "symbol", "decimal_text", "duration", "url",
            "endpoint_id", "vault_ref"
        ):
            _model_fail("PARAMETER_KIND_UNDECLARED", "/parameter_schema")
        if self.type != "string" and self.kind is not None:
            _model_fail("INVALID_VALUE", "/parameter_schema")
        if not isinstance(self.choices, (list, tuple)) or any(
            not isinstance(item, str) for item in self.choices
        ):
            _model_fail("INVALID_TYPE", "/parameter_schema")
        if not isinstance(self.hosts, (list, tuple)) or any(
            not isinstance(item, str) for item in self.hosts
        ):
            _model_fail("INVALID_TYPE", "/parameter_schema")
        object.__setattr__(self, "choices", tuple(self.choices))
        object.__setattr__(self, "hosts", tuple(self.hosts))
        if self.minimum is not None:
            object.__setattr__(self, "minimum", _checked_decimal(self.minimum, "/parameter_schema"))
        if self.maximum is not None:
            object.__setattr__(self, "maximum", _checked_decimal(self.maximum, "/parameter_schema"))


@dataclass(frozen=True, slots=True)
class SecretReferenceV1(_NoCopy):
    alias: str
    scope: str
    environment: str
    provider: str
    name: str

    def __post_init__(self) -> None:
        if any(not isinstance(value, str) for value in
               (self.alias, self.scope, self.environment, self.provider, self.name)):
            _model_fail("INVALID_TYPE", "/secret_refs")

    @property
    def uri(self) -> str:
        return f"vault://{self.scope}/{self.environment}/{self.provider}/{self.name}"


def _check_model_parameters(
    schema: Mapping[str, ParameterRuleV1], values: Mapping[str, ParameterValue],
    schema_path: str, values_path: str, mode: ProfileMode | None,
    endpoint_registry: EndpointRegistryV1 | None,
) -> None:
    # Constructors and dataclasses.replace use the same typed boundary as document loading.
    from leviathan_core.configuration.validation import (
        _looks_like_credential,
        _rules,
        _validate_string_kind,
        _values,
    )

    raw_schema: dict[str, dict[str, object]] = {}
    for name, rule in schema.items():
        fields: dict[str, object] = {"type": rule.type}
        if rule.minimum is not None:
            fields["minimum"] = rule.minimum
        if rule.maximum is not None:
            fields["maximum"] = rule.maximum
        if rule.kind is not None:
            fields["kind"] = rule.kind
        if rule.choices:
            fields["choices"] = list(rule.choices)
        if rule.provider is not None:
            fields["provider"] = rule.provider
        if rule.hosts:
            fields["hosts"] = list(rule.hosts)
        raw_schema[name] = fields
    _rules(raw_schema, schema_path)
    for rule in schema.values():
        if rule.type == "string":
            if rule.kind is None:
                _model_fail("PARAMETER_KIND_UNDECLARED", schema_path)
            for choice in rule.choices:
                if _looks_like_credential(choice):
                    _model_fail("SECRET_PLAINTEXT", schema_path)
                if "://" in choice:
                    _model_fail("INVALID_VALUE", schema_path)
    for name, value in values.items():
        value_rule = schema.get(name)
        if isinstance(value, str) and value_rule is not None and value_rule.type == "string":
            if not value.startswith(("https://", "vault://")) and _looks_like_credential(value):
                _model_fail("SECRET_PLAINTEXT", values_path)
            _validate_string_kind(value_rule, value, values_path, mode, endpoint_registry)
    _values(dict(values), tuple(schema.values()), values_path, mode,
            endpoint_registry=endpoint_registry, frozen=True)


def _registry_content(registry: EndpointRegistryV1 | None) -> object:
    if registry is None:
        return None
    return {"snapshot_id": registry.snapshot_id, "entries": dict(registry.entries)}


@dataclass(frozen=True, slots=True)
class StrategyProfileV1(_NoCopy):
    schema_version: int
    name: str
    version: int
    strategy_id: str
    strategy_version: str
    mode: ProfileMode
    environment: ProfileEnvironment
    connectors: tuple[str, ...]
    data_feeds: tuple[str, ...]
    risk_guard: str
    parameter_schema: Mapping[str, ParameterRuleV1]
    parameters: Mapping[str, ParameterValue]
    secret_refs: Mapping[str, str]
    published: bool
    endpoint_registry: EndpointRegistryV1 | None = None

    def __post_init__(self) -> None:
        from leviathan_core.configuration.validation import _identity, _secret_refs

        _check_identity(self.name, self.version, self.strategy_id, self.strategy_version)
        if type(self.schema_version) is not int:
            _model_fail("INVALID_TYPE", "/schema_version")
        _identity({"schema_version": self.schema_version, "name": self.name,
                   "version": self.version, "strategy_id": self.strategy_id,
                   "strategy_version": self.strategy_version})
        for path, value in (("/mode", self.mode), ("/environment", self.environment),
                            ("/risk_guard", self.risk_guard)):
            if not isinstance(value, str):
                _model_fail("INVALID_TYPE", path)
        if self.mode not in ("backtest", "paper", "live"):
            _model_fail("INVALID_VALUE", "/mode")
        if self.environment not in ("test", "staging", "production"):
            _model_fail("INVALID_VALUE", "/environment")
        if self.mode == "live" and self.environment != "production":
            _model_fail("INVALID_VALUE", "/environment")
        if not _REFERENCE_ID.fullmatch(self.risk_guard):
            _model_fail("INVALID_VALUE", "/risk_guard")
        if self.endpoint_registry is not None and not isinstance(
            self.endpoint_registry, EndpointRegistryV1
        ):
            _model_fail("INVALID_TYPE", "/endpoint_registry")
        if not isinstance(self.published, bool):
            _model_fail("INVALID_TYPE", "/published")
        object.__setattr__(self, "connectors", _freeze_names(self.connectors, "/connectors"))
        object.__setattr__(self, "data_feeds", _freeze_names(self.data_feeds, "/data_feeds"))
        object.__setattr__(self, "parameter_schema", _freeze_rules(
            self.parameter_schema, "/parameter_schema"
        ))
        object.__setattr__(self, "parameters", _freeze_values(self.parameters, "/parameters"))
        object.__setattr__(self, "secret_refs", _freeze_secret_refs(self.secret_refs))
        _secret_refs(dict(self.secret_refs), self.mode, "/secret_refs")
        _check_model_parameters(
            self.parameter_schema, self.parameters, "/parameter_schema", "/parameters",
            self.mode, self.endpoint_registry,
        )

    @property
    def content_hash(self) -> str:
        """Hash the current semantic fields; no cached hash can become stale."""
        content: dict[str, object] = {
            "schema_version": self.schema_version,
            "name": self.name,
            "version": self.version,
            "strategy_id": self.strategy_id,
            "strategy_version": self.strategy_version,
            "mode": self.mode,
            "environment": self.environment,
            "connectors": self.connectors,
            "data_feeds": self.data_feeds,
            "risk_guard": self.risk_guard,
            "parameter_schema": {
                name: {"type": rule.type,
                       "minimum": (_canonical_number(rule.minimum)
                                   if rule.minimum is not None else None),
                       "maximum": (_canonical_number(rule.maximum)
                                   if rule.maximum is not None else None),
                       "kind": rule.kind, "choices": rule.choices,
                       "provider": rule.provider, "hosts": rule.hosts}
                for name, rule in self.parameter_schema.items()
            },
            "parameters": {
                name: (_canonical_number(value) if isinstance(value, (int, Decimal))
                       and not isinstance(value, bool) else value)
                for name, value in self.parameters.items()
            },
            "secret_refs": dict(self.secret_refs),
            "published": self.published,
            "endpoint_registry": _registry_content(self.endpoint_registry),
        }
        return _hash(content)


@dataclass(frozen=True, slots=True)
class ParameterSetV1(_NoCopy):
    schema_version: int
    name: str
    version: int
    strategy_id: str
    strategy_version: str
    schema: Mapping[str, ParameterRuleV1]
    values: Mapping[str, ParameterValue]
    locked: bool
    endpoint_registry: EndpointRegistryV1 | None = None

    def __post_init__(self) -> None:
        from leviathan_core.configuration.validation import _identity

        _check_identity(self.name, self.version, self.strategy_id, self.strategy_version)
        if type(self.schema_version) is not int:
            _model_fail("INVALID_TYPE", "/schema_version")
        _identity({"schema_version": self.schema_version, "name": self.name,
                   "version": self.version, "strategy_id": self.strategy_id,
                   "strategy_version": self.strategy_version})
        if self.endpoint_registry is not None and not isinstance(
            self.endpoint_registry, EndpointRegistryV1
        ):
            _model_fail("INVALID_TYPE", "/endpoint_registry")
        if not isinstance(self.locked, bool):
            _model_fail("INVALID_TYPE", "/locked")
        object.__setattr__(self, "schema", _freeze_rules(self.schema, "/schema"))
        object.__setattr__(self, "values", _freeze_values(self.values, "/values"))
        _check_model_parameters(self.schema, self.values, "/schema", "/values", None,
                                self.endpoint_registry)

    @property
    def content_hash(self) -> str:
        content: dict[str, object] = {
            "schema_version": self.schema_version,
            "name": self.name,
            "version": self.version,
            "strategy_id": self.strategy_id,
            "strategy_version": self.strategy_version,
            "schema": {
                name: {"type": rule.type,
                       "minimum": (_canonical_number(rule.minimum)
                                   if rule.minimum is not None else None),
                       "maximum": (_canonical_number(rule.maximum)
                                   if rule.maximum is not None else None),
                       "kind": rule.kind, "choices": rule.choices,
                       "provider": rule.provider, "hosts": rule.hosts}
                for name, rule in self.schema.items()
            },
            "values": {
                name: (_canonical_number(value) if isinstance(value, (int, Decimal))
                       and not isinstance(value, bool) else value)
                for name, value in self.values.items()
            },
            "locked": self.locked,
            "endpoint_registry": _registry_content(self.endpoint_registry),
        }
        return _hash(content)
