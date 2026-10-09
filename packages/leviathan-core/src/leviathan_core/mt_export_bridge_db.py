"""Pure MT4/MT5 export-definition validation.

This module models only the definition and reference invariants needed before
an export request is considered well-formed. It performs no persistence,
compilation, signing, terminal discovery, or bridge operation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from decimal import Decimal
from enum import StrEnum
from typing import NoReturn, SupportsIndex

from leviathan_core.numeric import NumericError, parse_decimal

_IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}\Z", re.ASCII)
_PARAMETER_KEY_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}\Z", re.ASCII)
_TEMPLATE_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._-]{0,127}\Z", re.ASCII)
_VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}\Z", re.ASCII)
_SYMBOL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:#/-]{0,127}\Z", re.ASCII)

DEFINITION_ERROR_CODES = frozenset(
    {
        "DUPLICATE_BROKER_SYMBOL",
        "DUPLICATE_EXPORT_JOB_ID",
        "DUPLICATE_LOGICAL_SYMBOL",
        "DUPLICATE_PARAMETER_DEFINITION",
        "DUPLICATE_RESOLVED_PARAMETER",
        "DUPLICATE_TEMPLATE",
        "DUPLICATE_TEMPLATE_ID",
        "INVALID_COLLECTION",
        "INVALID_IDENTIFIER",
        "INVALID_PARAMETER_DEFINITION",
        "INVALID_PARAMETER_VALUE",
        "MISSING_REQUIRED_PARAMETER",
        "PARAMETER_ENUM_INVALID",
        "PARAMETER_OUT_OF_RANGE",
        "PARAMETER_TYPE_MISMATCH",
        "UNKNOWN_PARAMETER",
        "UNKNOWN_TEMPLATE_REFERENCE",
    }
)


class PlatformV1(StrEnum):
    """Closed platform set used by the MT export definitions."""

    MT4 = "MT4"
    MT5 = "MT5"


class ArtifactTypeV1(StrEnum):
    """Artifact categories named by the database PRD."""

    EA = "EA"
    INDICATOR = "INDICATOR"
    BRIDGE_DLL = "BRIDGE_DLL"
    PACKAGE = "PACKAGE"


class ParameterTypeV1(StrEnum):
    """Closed value kinds for export parameters."""

    STRING = "STRING"
    INTEGER = "INTEGER"
    DECIMAL = "DECIMAL"
    BOOLEAN = "BOOLEAN"
    ENUM = "ENUM"


class _FrozenRecord:
    """Make records immutable across the supported Python copy mechanisms."""

    __slots__ = ()

    def __copy__(self) -> NoReturn:
        raise TypeError("definition records cannot be copied")

    def __deepcopy__(self, _memo: dict[int, object]) -> NoReturn:
        raise TypeError("definition records cannot be copied")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> NoReturn:
        raise TypeError("definition records cannot be serialized")


class DefinitionInvariantError(ValueError):
    """A deterministic failure exposing fixed codes only, never input values."""

    __slots__ = ("code", "codes")

    def __init__(self, code: str | tuple[str, ...]) -> None:
        codes = (code,) if type(code) is str else code
        if (
            type(codes) is not tuple
            or not codes
            or any(type(item) is not str or item not in DEFINITION_ERROR_CODES for item in codes)
        ):
            raise TypeError("invalid definition error code")
        normalized = tuple(sorted(set(codes)))
        self.codes = normalized
        self.code = normalized[0]
        super().__init__(self.code)

    def __str__(self) -> str:
        return self.code


def _identifier(value: object) -> bool:
    return type(value) is str and _IDENTIFIER_RE.fullmatch(value) is not None


def _parameter_key(value: object) -> bool:
    return type(value) is str and _PARAMETER_KEY_RE.fullmatch(value) is not None


def _template_name(value: object) -> bool:
    return (
        type(value) is str and _TEMPLATE_NAME_RE.fullmatch(value) is not None and value[-1] != " "
    )


def _version(value: object) -> bool:
    return type(value) is str and _VERSION_RE.fullmatch(value) is not None


def _symbol(value: object) -> bool:
    return type(value) is str and _SYMBOL_RE.fullmatch(value) is not None


@dataclass(frozen=True, slots=True)
class CodegenTemplateV1(_FrozenRecord):
    """A typed MT4/MT5 template identity."""

    template_id: str
    platform: PlatformV1
    name: str
    version: str
    artifact_type: ArtifactTypeV1

    def __post_init__(self) -> None:
        if (
            not _identifier(self.template_id)
            or not _template_name(self.name)
            or not _version(self.version)
        ):
            raise DefinitionInvariantError("INVALID_IDENTIFIER")
        if type(self.platform) is not PlatformV1 or type(self.artifact_type) is not ArtifactTypeV1:
            raise DefinitionInvariantError("INVALID_IDENTIFIER")


@dataclass(frozen=True, slots=True)
class ParameterDefinitionV1(_FrozenRecord):
    """One template-scoped parameter rule; absent values are never defaulted."""

    template_id: str
    key: str
    value_type: ParameterTypeV1
    required: bool
    minimum: Decimal | None
    maximum: Decimal | None
    enum_values: tuple[str, ...]

    def __post_init__(self) -> None:
        if not _identifier(self.template_id) or not _parameter_key(self.key):
            raise DefinitionInvariantError("INVALID_IDENTIFIER")
        if type(self.value_type) is not ParameterTypeV1 or type(self.required) is not bool:
            raise DefinitionInvariantError("INVALID_PARAMETER_DEFINITION")
        if type(self.enum_values) is not tuple or any(
            type(value) is not str for value in self.enum_values
        ):
            raise DefinitionInvariantError("INVALID_PARAMETER_DEFINITION")
        if len(set(self.enum_values)) != len(self.enum_values):
            raise DefinitionInvariantError("INVALID_PARAMETER_DEFINITION")

        lower = self.minimum
        upper = self.maximum
        try:
            if lower is not None:
                if type(lower) is not Decimal:
                    raise DefinitionInvariantError("INVALID_PARAMETER_DEFINITION")
                lower = parse_decimal(lower, field="parameter.minimum")
            if upper is not None:
                if type(upper) is not Decimal:
                    raise DefinitionInvariantError("INVALID_PARAMETER_DEFINITION")
                upper = parse_decimal(upper, field="parameter.maximum")
        except NumericError:
            raise DefinitionInvariantError("INVALID_PARAMETER_DEFINITION") from None
        if lower is not None and upper is not None and lower > upper:
            raise DefinitionInvariantError("INVALID_PARAMETER_DEFINITION")

        if self.value_type is ParameterTypeV1.ENUM:
            if not self.enum_values or lower is not None or upper is not None:
                raise DefinitionInvariantError("INVALID_PARAMETER_DEFINITION")
        elif self.enum_values:
            raise DefinitionInvariantError("INVALID_PARAMETER_DEFINITION")
        if self.value_type not in (ParameterTypeV1.INTEGER, ParameterTypeV1.DECIMAL) and (
            lower is not None or upper is not None
        ):
            raise DefinitionInvariantError("INVALID_PARAMETER_DEFINITION")
        object.__setattr__(self, "minimum", lower)
        object.__setattr__(self, "maximum", upper)


@dataclass(frozen=True, slots=True)
class ResolvedParameterV1(_FrozenRecord):
    """An explicit parameter value attached to an export job."""

    key: str
    value: str | int | Decimal | bool

    def __post_init__(self) -> None:
        if not _parameter_key(self.key):
            raise DefinitionInvariantError("INVALID_IDENTIFIER")
        if type(self.value) not in (str, int, Decimal, bool):
            raise DefinitionInvariantError("INVALID_PARAMETER_VALUE")


@dataclass(frozen=True, slots=True)
class ExportJobV1(_FrozenRecord):
    """A parameter resolution request referencing one template identity."""

    export_job_id: str
    template_id: str
    params_resolved: tuple[ResolvedParameterV1, ...]

    def __post_init__(self) -> None:
        if not _identifier(self.export_job_id) or not _identifier(self.template_id):
            raise DefinitionInvariantError("INVALID_IDENTIFIER")
        if type(self.params_resolved) is not tuple or any(
            type(item) is not ResolvedParameterV1 for item in self.params_resolved
        ):
            raise DefinitionInvariantError("INVALID_COLLECTION")


@dataclass(frozen=True, slots=True)
class SymbolMapEntryV1(_FrozenRecord):
    """One target-scoped logical-to-broker symbol mapping."""

    target_id: str
    logical_symbol: str
    broker_symbol: str

    def __post_init__(self) -> None:
        if (
            not _identifier(self.target_id)
            or not _symbol(self.logical_symbol)
            or not _symbol(self.broker_symbol)
        ):
            raise DefinitionInvariantError("INVALID_IDENTIFIER")


@dataclass(frozen=True, slots=True)
class DefinitionValidationV1(_FrozenRecord):
    """Counts of definitions validated successfully; this is not an issuance proof."""

    template_count: int
    parameter_definition_count: int
    export_job_count: int
    symbol_map_count: int

    def __post_init__(self) -> None:
        if any(
            type(value) is not int or value < 0
            for value in (
                self.template_count,
                self.parameter_definition_count,
                self.export_job_count,
                self.symbol_map_count,
            )
        ):
            raise DefinitionInvariantError("INVALID_COLLECTION")


def _check_parameter_value(
    definition: ParameterDefinitionV1, value: object, errors: set[str]
) -> None:
    kind = definition.value_type
    if kind is ParameterTypeV1.STRING:
        if type(value) is not str:
            errors.add("PARAMETER_TYPE_MISMATCH")
        return
    if kind is ParameterTypeV1.BOOLEAN:
        if type(value) is not bool:
            errors.add("PARAMETER_TYPE_MISMATCH")
        return
    if kind is ParameterTypeV1.ENUM:
        if type(value) is not str:
            errors.add("PARAMETER_TYPE_MISMATCH")
        elif value not in definition.enum_values:
            errors.add("PARAMETER_ENUM_INVALID")
        return
    if kind is ParameterTypeV1.INTEGER:
        if type(value) is not int:
            errors.add("PARAMETER_TYPE_MISMATCH")
            return
    elif kind is ParameterTypeV1.DECIMAL:
        if type(value) not in (Decimal, int, str):
            errors.add("PARAMETER_TYPE_MISMATCH")
            return
    else:  # Closed enum validation makes this unreachable for constructed values.
        errors.add("INVALID_PARAMETER_DEFINITION")
        return

    try:
        number = parse_decimal(value, field="parameter.value")
    except NumericError:
        errors.add("INVALID_PARAMETER_VALUE")
        return
    if (definition.minimum is not None and number < definition.minimum) or (
        definition.maximum is not None and number > definition.maximum
    ):
        errors.add("PARAMETER_OUT_OF_RANGE")


def validate_export_definitions(
    *,
    templates: tuple[CodegenTemplateV1, ...],
    parameter_definitions: tuple[ParameterDefinitionV1, ...],
    export_jobs: tuple[ExportJobV1, ...],
    symbol_maps: tuple[SymbolMapEntryV1, ...],
) -> DefinitionValidationV1:
    """Validate cross-record identity, reference, parameter and symbol invariants.

    All collections must be explicit tuples. Errors are collected into a sorted
    closed code set so results do not depend on caller input order.
    """

    collections: tuple[tuple[object, ...], ...] = (
        templates,
        parameter_definitions,
        export_jobs,
        symbol_maps,
    )
    expected_types = (
        CodegenTemplateV1,
        ParameterDefinitionV1,
        ExportJobV1,
        SymbolMapEntryV1,
    )
    if any(type(items) is not tuple for items in collections) or any(
        type(item) is not expected
        for items, expected in zip(collections, expected_types, strict=True)
        for item in items
    ):
        raise DefinitionInvariantError("INVALID_COLLECTION")

    # Reconstruct a validated immutable snapshot so dataclass re-init or
    # object.__setattr__ cannot smuggle unchecked fields into validation.
    templates = tuple(
        CodegenTemplateV1(
            template_id=item.template_id,
            platform=item.platform,
            name=item.name,
            version=item.version,
            artifact_type=item.artifact_type,
        )
        for item in templates
    )
    parameter_definitions = tuple(
        ParameterDefinitionV1(
            template_id=item.template_id,
            key=item.key,
            value_type=item.value_type,
            required=item.required,
            minimum=item.minimum,
            maximum=item.maximum,
            enum_values=item.enum_values,
        )
        for item in parameter_definitions
    )
    if any(
        type(item.params_resolved) is not tuple
        or any(type(parameter) is not ResolvedParameterV1 for parameter in item.params_resolved)
        for item in export_jobs
    ):
        raise DefinitionInvariantError("INVALID_COLLECTION")
    export_jobs = tuple(
        ExportJobV1(
            export_job_id=item.export_job_id,
            template_id=item.template_id,
            params_resolved=tuple(
                ResolvedParameterV1(key=parameter.key, value=parameter.value)
                for parameter in item.params_resolved
            ),
        )
        for item in export_jobs
    )
    symbol_maps = tuple(
        SymbolMapEntryV1(
            target_id=item.target_id,
            logical_symbol=item.logical_symbol,
            broker_symbol=item.broker_symbol,
        )
        for item in symbol_maps
    )

    errors: set[str] = set()
    template_by_id: dict[str, CodegenTemplateV1] = {}
    duplicate_template_ids: set[str] = set()
    template_identity: set[tuple[PlatformV1, str, str]] = set()
    for template in templates:
        template_key = (template.platform, template.name, template.version)
        if template_key in template_identity:
            errors.add("DUPLICATE_TEMPLATE")
        template_identity.add(template_key)
        if template.template_id in template_by_id:
            duplicate_template_ids.add(template.template_id)
            errors.add("DUPLICATE_TEMPLATE_ID")
        else:
            template_by_id[template.template_id] = template
    for duplicate_id in duplicate_template_ids:
        template_by_id.pop(duplicate_id, None)

    definitions_by_identity: dict[tuple[str, str], ParameterDefinitionV1] = {}
    duplicate_definition_ids: set[tuple[str, str]] = set()
    for definition in parameter_definitions:
        if definition.template_id not in template_by_id:
            errors.add("UNKNOWN_TEMPLATE_REFERENCE")
        definition_key = (definition.template_id, definition.key)
        if definition_key in definitions_by_identity:
            duplicate_definition_ids.add(definition_key)
            errors.add("DUPLICATE_PARAMETER_DEFINITION")
        else:
            definitions_by_identity[definition_key] = definition
    for definition_key in duplicate_definition_ids:
        definitions_by_identity.pop(definition_key, None)

    seen_job_ids: set[str] = set()
    for job in export_jobs:
        if job.export_job_id in seen_job_ids:
            errors.add("DUPLICATE_EXPORT_JOB_ID")
        seen_job_ids.add(job.export_job_id)

        if job.template_id not in template_by_id:
            errors.add("UNKNOWN_TEMPLATE_REFERENCE")
            continue

        applicable = {
            definition.key: definition
            for (template_id, _), definition in definitions_by_identity.items()
            if template_id == job.template_id
        }
        resolved: dict[str, object] = {}
        duplicate_keys: set[str] = set()
        for parameter in job.params_resolved:
            if parameter.key in resolved:
                duplicate_keys.add(parameter.key)
                errors.add("DUPLICATE_RESOLVED_PARAMETER")
            else:
                resolved[parameter.key] = parameter.value

        if any(key not in applicable for key in resolved):
            errors.add("UNKNOWN_PARAMETER")
        if any(
            definition.required and key not in resolved for key, definition in applicable.items()
        ):
            errors.add("MISSING_REQUIRED_PARAMETER")
        for key, value in resolved.items():
            parameter_definition = applicable.get(key)
            if parameter_definition is not None and key not in duplicate_keys:
                _check_parameter_value(parameter_definition, value, errors)

    seen_logical: set[tuple[str, str]] = set()
    seen_broker: set[tuple[str, str]] = set()
    for entry in symbol_maps:
        logical_key = (entry.target_id, entry.logical_symbol)
        broker_key = (entry.target_id, entry.broker_symbol)
        if logical_key in seen_logical:
            errors.add("DUPLICATE_LOGICAL_SYMBOL")
        if broker_key in seen_broker:
            errors.add("DUPLICATE_BROKER_SYMBOL")
        seen_logical.add(logical_key)
        seen_broker.add(broker_key)

    if errors:
        raise DefinitionInvariantError(tuple(sorted(errors)))
    return DefinitionValidationV1(
        template_count=len(templates),
        parameter_definition_count=len(parameter_definitions),
        export_job_count=len(export_jobs),
        symbol_map_count=len(symbol_maps),
    )


__all__ = [
    "DEFINITION_ERROR_CODES",
    "ArtifactTypeV1",
    "CodegenTemplateV1",
    "DefinitionInvariantError",
    "DefinitionValidationV1",
    "ExportJobV1",
    "ParameterDefinitionV1",
    "ParameterTypeV1",
    "PlatformV1",
    "ResolvedParameterV1",
    "SymbolMapEntryV1",
    "validate_export_definitions",
]
