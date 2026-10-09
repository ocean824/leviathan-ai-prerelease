"""Validate deployment secret references without resolving or storing values."""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Literal, NoReturn, cast

from pydantic import field_validator

from leviathan_core.seal import Issuer, SealedModel, SealError, require

EnvironmentV1 = Literal["development", "live"]

_SERVICE_ID = re.compile(r"[a-z][a-z0-9-]{1,63}\Z", re.ASCII)
_PROVIDER = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z", re.ASCII)
_NAME = re.compile(r"[A-Z][A-Z0-9_]{2,79}\Z", re.ASCII)
_REFERENCE = re.compile(
    r"vault://(?P<scope>[a-z][a-z0-9-]{1,63})/"
    r"(?P<environment>development|live)/"
    r"(?P<provider>[a-z0-9]+(?:-[a-z0-9]+)*)/"
    r"(?P<name>[A-Z][A-Z0-9_]{2,79})\Z",
    re.ASCII,
)
_SECRET_LOOKING_ID = re.compile(
    r"(?:api[_-]?key|secret|password|passwd|token|credential|bearer|"
    r"sk[_-]?live|gh[pousr]_|xox[baprs]-|-----BEGIN)",
    re.IGNORECASE | re.ASCII,
)
_ALLOWED_BINDINGS_TAG = "deployment.secret_refs.allowed_bindings.v1"
_PROVIDER_ALIASES_TAG = "deployment.secret_refs.provider_aliases.v1"
_REFERENCE_TAG = "deployment.secret_refs.reference.v1"
_ALLOWED_BINDINGS_ISSUER = Issuer(_ALLOWED_BINDINGS_TAG)
_PROVIDER_ALIASES_ISSUER = Issuer(_PROVIDER_ALIASES_TAG)
_REFERENCE_ISSUER = Issuer(_REFERENCE_TAG)


class SecretReferenceCode(StrEnum):
    INVALID_INPUT = "INVALID_INPUT"
    INVALID_SECRET_REFERENCE = "INVALID_SECRET_REFERENCE"
    INVALID_SERVICE_SCOPE = "INVALID_SERVICE_SCOPE"
    INVALID_ENVIRONMENT_SCOPE = "INVALID_ENVIRONMENT_SCOPE"
    INVALID_BINDING_TABLE = "INVALID_BINDING_TABLE"
    INVALID_ALIAS_MAP = "INVALID_ALIAS_MAP"
    SECRET_SCOPE_MISMATCH = "SECRET_SCOPE_MISMATCH"
    SECRET_ENVIRONMENT_MISMATCH = "SECRET_ENVIRONMENT_MISMATCH"
    SECRET_REF_ALIAS_UNMAPPED = "SECRET_REF_ALIAS_UNMAPPED"
    SECRET_REF_NOT_BOUND = "SECRET_REF_NOT_BOUND"


class SecretReferenceError(ValueError):
    """Fixed-code failure that never includes the rejected input."""

    def __init__(self, code: SecretReferenceCode) -> None:
        if type(code) is not SecretReferenceCode:
            raise TypeError("INVALID_INPUT")
        self.code = code
        super().__init__(code.value)


class AllowedSecretBindingsV1(SealedModel):
    """Closed service/environment/canonical-reference allowlist."""

    schema_version: Literal["1"]
    bindings: tuple[tuple[str, EnvironmentV1, str], ...]

    @field_validator("bindings")
    @classmethod
    def _validate_bindings(
        cls, value: tuple[tuple[str, EnvironmentV1, str], ...]
    ) -> tuple[tuple[str, EnvironmentV1, str], ...]:
        if type(value) is not tuple:
            raise ValueError("INVALID_BINDING_TABLE")
        if any(
            type(row) is not tuple
            or len(row) != 3
            or type(row[0]) is not str
            or type(row[1]) is not str
            or type(row[2]) is not str
            for row in value
        ):
            raise ValueError("INVALID_BINDING_TABLE")
        checked: list[tuple[str, EnvironmentV1, str]] = []
        for service_id, environment, canonical_ref in value:
            _validate_service_id(service_id)
            _validate_environment(environment)
            parsed = _parse_reference(canonical_ref)
            if parsed["scope"] != "leviathan-ai":
                raise ValueError("SECRET_SCOPE_MISMATCH")
            if parsed["environment"] != environment:
                raise ValueError("SECRET_ENVIRONMENT_MISMATCH")
            checked.append((service_id, environment, canonical_ref))
        if len(set(checked)) != len(checked):
            raise ValueError("INVALID_BINDING_TABLE")
        return tuple(checked)


class ProviderAliasMapV1(SealedModel):
    """Closed provider alias map; aliases retain the canonical key name."""

    schema_version: Literal["1"]
    aliases: tuple[tuple[str, str, EnvironmentV1], ...]

    @field_validator("aliases")
    @classmethod
    def _validate_aliases(
        cls, value: tuple[tuple[str, str, EnvironmentV1], ...]
    ) -> tuple[tuple[str, str, EnvironmentV1], ...]:
        if type(value) is not tuple:
            raise ValueError("INVALID_ALIAS_MAP")
        checked: list[tuple[str, str, EnvironmentV1]] = []
        for row in value:
            if (
                type(row) is not tuple
                or len(row) != 3
                or type(row[0]) is not str
                or type(row[1]) is not str
                or type(row[2]) is not str
            ):
                raise ValueError("INVALID_ALIAS_MAP")
            source, canonical, environment = row
            if (
                _PROVIDER.fullmatch(source) is None
                or _PROVIDER.fullmatch(canonical) is None
                or source == canonical
            ):
                raise ValueError("INVALID_ALIAS_MAP")
            _validate_environment(environment)
            checked.append((source, canonical, environment))
        if len({(source, environment) for source, _, environment in checked}) != len(checked):
            raise ValueError("INVALID_ALIAS_MAP")
        sources = {(source, environment) for source, _, environment in checked}
        if any((canonical, environment) in sources for _, canonical, environment in checked):
            raise ValueError("INVALID_ALIAS_MAP")
        return tuple(sorted(checked))


class SecretReferenceV1(SealedModel):
    """Issued metadata for one allowlisted logical reference; never a credential."""

    schema_version: Literal["1"]
    service_id: str
    environment: EnvironmentV1
    canonical_ref: str
    provider: str
    name: str
    alias_applied: bool

    @field_validator("service_id")
    @classmethod
    def _service_id(cls, value: str) -> str:
        _validate_service_id(value)
        return value

    @field_validator("environment")
    @classmethod
    def _environment(cls, value: str) -> EnvironmentV1:
        _validate_environment(value)
        return cast(EnvironmentV1, value)

    @field_validator("canonical_ref")
    @classmethod
    def _canonical_ref(cls, value: str) -> str:
        parsed = _parse_reference(value)
        if parsed["scope"] != "leviathan-ai":
            raise ValueError("SECRET_SCOPE_MISMATCH")
        return value

    @field_validator("provider")
    @classmethod
    def _provider(cls, value: str) -> str:
        if type(value) is not str or _PROVIDER.fullmatch(value) is None:
            raise ValueError("INVALID_SECRET_REFERENCE")
        return value

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        if type(value) is not str or _NAME.fullmatch(value) is None:
            raise ValueError("INVALID_SECRET_REFERENCE")
        return value


def _raise(code: SecretReferenceCode) -> NoReturn:
    raise SecretReferenceError(code)


def _validate_environment(value: object) -> EnvironmentV1:
    if type(value) is not str or value not in ("development", "live"):
        _raise(SecretReferenceCode.INVALID_ENVIRONMENT_SCOPE)
    return cast(EnvironmentV1, value)


def _validate_service_id(value: object) -> str:
    if (
        type(value) is not str
        or _SERVICE_ID.fullmatch(value) is None
        or _SECRET_LOOKING_ID.search(value) is not None
    ):
        _raise(SecretReferenceCode.INVALID_SERVICE_SCOPE)
    return value


def _parse_reference(value: object) -> dict[str, str]:
    if type(value) is not str or not value.isascii():
        _raise(SecretReferenceCode.INVALID_SECRET_REFERENCE)
    match = _REFERENCE.fullmatch(value)
    if match is None:
        _raise(SecretReferenceCode.INVALID_SECRET_REFERENCE)
    return cast(dict[str, str], match.groupdict())


def issue_allowed_secret_bindings(
    bindings: tuple[tuple[str, EnvironmentV1, str], ...],
) -> AllowedSecretBindingsV1:
    """Validate and seal a closed table of service/environment/ref triples."""
    if type(bindings) is not tuple:
        _raise(SecretReferenceCode.INVALID_BINDING_TABLE)
    try:
        result = AllowedSecretBindingsV1(schema_version="1", bindings=bindings)
        return _ALLOWED_BINDINGS_ISSUER.issue(result)
    except SecretReferenceError:
        raise
    except Exception:
        _raise(SecretReferenceCode.INVALID_BINDING_TABLE)


def issue_provider_alias_map(
    aliases: tuple[tuple[str, str, EnvironmentV1], ...],
) -> ProviderAliasMapV1:
    """Validate and seal provider aliases (source, canonical, environment)."""
    if type(aliases) is not tuple:
        _raise(SecretReferenceCode.INVALID_ALIAS_MAP)
    try:
        result = ProviderAliasMapV1(schema_version="1", aliases=aliases)
        return _PROVIDER_ALIASES_ISSUER.issue(result)
    except SecretReferenceError:
        raise
    except Exception:
        _raise(SecretReferenceCode.INVALID_ALIAS_MAP)


def validate_secret_reference(
    reference: str,
    *,
    service_id: str,
    environment: EnvironmentV1,
    allowed_bindings: AllowedSecretBindingsV1,
    provider_aliases: ProviderAliasMapV1,
) -> SecretReferenceV1:
    """Resolve an exact logical ref into an issued record if the closed table binds it."""
    if type(allowed_bindings) is not AllowedSecretBindingsV1:
        _raise(SecretReferenceCode.INVALID_BINDING_TABLE)
    if type(provider_aliases) is not ProviderAliasMapV1:
        _raise(SecretReferenceCode.INVALID_ALIAS_MAP)
    try:
        require(allowed_bindings, _ALLOWED_BINDINGS_TAG)
    except SealError:
        _raise(SecretReferenceCode.INVALID_BINDING_TABLE)
    try:
        require(provider_aliases, _PROVIDER_ALIASES_TAG)
    except SealError:
        _raise(SecretReferenceCode.INVALID_ALIAS_MAP)
    _validate_service_id(service_id)
    expected_environment = _validate_environment(environment)
    parsed = _parse_reference(reference)
    if parsed["scope"] != "leviathan-ai":
        _raise(SecretReferenceCode.SECRET_SCOPE_MISMATCH)
    if parsed["environment"] != expected_environment:
        _raise(SecretReferenceCode.SECRET_ENVIRONMENT_MISMATCH)
    source_provider = parsed["provider"]
    known_aliases = tuple(row for row in provider_aliases.aliases if row[0] == source_provider)
    if len(known_aliases) > 1:
        _raise(SecretReferenceCode.SECRET_REF_ALIAS_UNMAPPED)
    alias_row = known_aliases[0] if known_aliases else None
    if alias_row is not None and alias_row[2] != expected_environment:
        _raise(SecretReferenceCode.SECRET_REF_ALIAS_UNMAPPED)
    alias_applied = alias_row is not None
    canonical_provider = alias_row[1] if alias_row is not None else source_provider
    canonical_ref = (
        f"vault://leviathan-ai/{expected_environment}/{canonical_provider}/{parsed['name']}"
    )
    binding = (service_id, expected_environment, canonical_ref)
    if binding not in allowed_bindings.bindings:
        _raise(SecretReferenceCode.SECRET_REF_NOT_BOUND)
    try:
        result = SecretReferenceV1(
            schema_version="1",
            service_id=service_id,
            environment=expected_environment,
            canonical_ref=canonical_ref,
            provider=canonical_provider,
            name=parsed["name"],
            alias_applied=alias_applied,
        )
        return _REFERENCE_ISSUER.issue(result)
    except Exception:
        _raise(SecretReferenceCode.INVALID_SECRET_REFERENCE)


__all__ = [
    "AllowedSecretBindingsV1",
    "EnvironmentV1",
    "ProviderAliasMapV1",
    "SecretReferenceCode",
    "SecretReferenceError",
    "SecretReferenceV1",
    "issue_allowed_secret_bindings",
    "issue_provider_alias_map",
    "validate_secret_reference",
]
