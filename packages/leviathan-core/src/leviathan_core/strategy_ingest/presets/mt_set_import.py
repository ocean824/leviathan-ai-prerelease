"""Strict, text-only MT4/MT5 SET import with source-byte preservation.

Imported values are configuration evidence only. They do not recover an EA's
compiled logic, authorize execution, or supersede sovereign risk policy.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import Literal, TypeAlias

MAX_SET_BYTES = 1_048_576
MAX_SET_LINES = 4_096
MAX_SET_FIELDS = 512
MAX_FIELD_NAME_CHARS = 128
MAX_FIELD_VALUE_CHARS = 4_096

FieldTypeV1: TypeAlias = Literal["boolean", "integer", "decimal", "string"]
PlatformV1: TypeAlias = Literal["MT4", "MT5"]
SourceFamilyV1: TypeAlias = Literal["GENERIC", "KINNOBOT", "TITAN_X"]
ScalarV1: TypeAlias = bool | int | Decimal | str

_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_.\[\]-]{0,127}\Z", re.ASCII)
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z", re.ASCII)
_INTEGER = re.compile(r"[+-]?(?:0|[1-9][0-9]*)\Z", re.ASCII)
_DECIMAL = re.compile(
    r"[+-]?(?:(?:[0-9]+(?:\.[0-9]*)?)|(?:\.[0-9]+))(?:[eE][+-]?[0-9]+)?\Z",
    re.ASCII,
)
_HINT = re.compile(r"hint[0-9]+\Z", re.IGNORECASE | re.ASCII)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)


class MtSetImportError(ValueError):
    """Fixed-code error that never includes source text or parameter values."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True, kw_only=True)
class ParameterSpecV1:
    value_type: FieldTypeV1
    unit: str

    def __post_init__(self) -> None:
        if not isinstance(self.value_type, str) or self.value_type not in {
            "boolean",
            "integer",
            "decimal",
            "string",
        }:
            raise MtSetImportError("INVALID_SCHEMA")
        _require_text(self.unit, "INVALID_SCHEMA", max_length=64)


@dataclass(frozen=True, slots=True, kw_only=True)
class InstrumentMappingV1:
    source_symbol: str
    instrument_id: str
    mapping_version: str

    def __post_init__(self) -> None:
        _require_token(self.source_symbol, "INVALID_MAPPING", max_length=128)
        _require_token(self.instrument_id, "INVALID_MAPPING", max_length=128)
        _require_version(self.mapping_version)


@dataclass(frozen=True, slots=True, kw_only=True)
class TimezoneMappingV1:
    source_timezone: str | None
    iana_timezone: str | None
    mapping_version: str

    def __post_init__(self) -> None:
        if self.source_timezone is not None:
            _require_token(self.source_timezone, "INVALID_MAPPING", max_length=128)
        if self.iana_timezone is not None:
            _require_token(self.iana_timezone, "INVALID_MAPPING", max_length=128)
        if (self.source_timezone is None) != (self.iana_timezone is None):
            raise MtSetImportError("INVALID_MAPPING")
        _require_version(self.mapping_version)


@dataclass(frozen=True, slots=True, kw_only=True)
class SetImportMetadataV1:
    preset_id: str
    preset_version: str
    platform: PlatformV1
    source_family: SourceFamilyV1
    source_locator: str
    instrument_mapping: InstrumentMappingV1
    timezone_mapping: TimezoneMappingV1
    license_status: Literal["TASK_AUTHORIZED", "LICENSE_VERIFIED", "UNVERIFIED"]
    license_reference: str | None = None

    def __post_init__(self) -> None:
        _require_token(self.preset_id, "INVALID_METADATA", max_length=128)
        _require_version(self.preset_version)
        if not isinstance(self.platform, str) or self.platform not in {"MT4", "MT5"}:
            raise MtSetImportError("INVALID_METADATA")
        if not isinstance(self.source_family, str) or self.source_family not in {
            "GENERIC",
            "KINNOBOT",
            "TITAN_X",
        }:
            raise MtSetImportError("INVALID_METADATA")
        _require_token(self.source_locator, "INVALID_METADATA", max_length=512)
        if not isinstance(self.license_status, str) or self.license_status not in {
            "TASK_AUTHORIZED",
            "LICENSE_VERIFIED",
            "UNVERIFIED",
        }:
            raise MtSetImportError("INVALID_METADATA")
        if self.license_reference is not None:
            _require_token(self.license_reference, "INVALID_METADATA", max_length=512)


@dataclass(frozen=True, slots=True, kw_only=True)
class OptimizationBoundsV1:
    start: str
    step: str
    stop: str
    enabled: bool


@dataclass(frozen=True, slots=True, kw_only=True)
class SetParameterV1:
    name: str
    value_type: FieldTypeV1
    value: ScalarV1
    raw_value: str
    unit: str
    optimization: OptimizationBoundsV1 | None


@dataclass(frozen=True, slots=True, kw_only=True)
class SetPresetV1:
    schema_version: Literal["1"]
    preset_id: str
    preset_version: str
    platform: PlatformV1
    source_family: SourceFamilyV1
    source_locator: str
    original_set_bytes: bytes
    original_sha256: str
    parameters: Mapping[str, SetParameterV1]
    instrument_mapping: InstrumentMappingV1
    timezone_mapping: TimezoneMappingV1
    license_status: Literal["TASK_AUTHORIZED", "LICENSE_VERIFIED", "UNVERIFIED"]
    license_reference: str | None

    @property
    def units(self) -> Mapping[str, str]:
        return MappingProxyType(
            {name: parameter.unit for name, parameter in self.parameters.items()}
        )

    @property
    def values(self) -> Mapping[str, ScalarV1]:
        return MappingProxyType(
            {name: parameter.value for name, parameter in self.parameters.items()}
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class HostingSetMaterialV1:
    original_set_bytes: bytes
    original_sha256: str
    effective_values: Mapping[str, ScalarV1]
    sovereign_override_names: tuple[str, ...]


def _require_text(value: str, code: str, *, max_length: int) -> None:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > max_length
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise MtSetImportError(code)


def _require_token(value: str, code: str, *, max_length: int) -> None:
    _require_text(value, code, max_length=max_length)
    if value.strip() != value:
        raise MtSetImportError(code)


def _require_version(value: str) -> None:
    if not isinstance(value, str) or not _VERSION.fullmatch(value):
        raise MtSetImportError("INVALID_METADATA")


def _decode_set_bytes(raw_set: bytes) -> str:
    if type(raw_set) is not bytes or not raw_set:
        raise MtSetImportError("INVALID_SET_BYTES")
    if len(raw_set) > MAX_SET_BYTES:
        raise MtSetImportError("EXCESSIVE_SIZE")
    if raw_set.startswith((b"\x00\x00\xfe\xff", b"\xff\xfe\x00\x00")):
        raise MtSetImportError("UNSUPPORTED_ENCODING")
    try:
        if raw_set.startswith((b"\xff\xfe", b"\xfe\xff")):
            text = raw_set.decode("utf-16")
        elif raw_set.startswith(b"\xef\xbb\xbf"):
            text = raw_set.decode("utf-8-sig")
        elif len(raw_set) >= 4 and len(raw_set) % 2 == 0:
            even_zeroes = raw_set[0::2].count(0)
            odd_zeroes = raw_set[1::2].count(0)
            pairs = len(raw_set) // 2
            if odd_zeroes > pairs // 3 and even_zeroes < pairs // 10:
                text = raw_set.decode("utf-16-le")
            elif even_zeroes > pairs // 3 and odd_zeroes < pairs // 10:
                text = raw_set.decode("utf-16-be")
            else:
                text = raw_set.decode("utf-8")
        else:
            text = raw_set.decode("utf-8")
    except UnicodeDecodeError:
        raise MtSetImportError("INVALID_ENCODING") from None
    if "\x00" in text or any(ord(char) < 32 and char not in "\r\n\t" for char in text):
        raise MtSetImportError("INVALID_SET_TEXT")
    return text


def _typed_value(value: str, value_type: FieldTypeV1) -> ScalarV1:
    if len(value) > MAX_FIELD_VALUE_CHARS:
        raise MtSetImportError("EXCESSIVE_SIZE")
    if value_type == "boolean":
        lowered = value.casefold()
        if lowered in {"true", "1"}:
            return True
        if lowered in {"false", "0"}:
            return False
        raise MtSetImportError("INVALID_VALUE")
    if value_type == "integer":
        if not _INTEGER.fullmatch(value):
            raise MtSetImportError("INVALID_VALUE")
        try:
            return int(value)
        except ValueError:
            raise MtSetImportError("INVALID_VALUE") from None
    if value_type == "decimal":
        if not _DECIMAL.fullmatch(value):
            raise MtSetImportError("INVALID_VALUE")
        try:
            number = Decimal(value)
        except InvalidOperation:
            raise MtSetImportError("INVALID_VALUE") from None
        if not number.is_finite():
            raise MtSetImportError("INVALID_VALUE")
        return number
    if value_type == "string":
        if any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise MtSetImportError("INVALID_VALUE")
        return value
    raise MtSetImportError("INVALID_SCHEMA")


def _parse_value_cell(value_cell: str) -> tuple[str, OptimizationBoundsV1 | None]:
    parts = value_cell.split("||")
    if len(parts) == 1:
        return parts[0], None
    if len(parts) != 5 or parts[4] not in {"Y", "N"}:
        raise MtSetImportError("INVALID_OPTIMIZATION_SUFFIX")
    if any(len(part) > MAX_FIELD_VALUE_CHARS for part in parts):
        raise MtSetImportError("EXCESSIVE_SIZE")
    if any(any(ord(char) < 32 or ord(char) == 127 for char in part) for part in parts):
        raise MtSetImportError("INVALID_OPTIMIZATION_SUFFIX")
    return parts[0], OptimizationBoundsV1(
        start=parts[1], step=parts[2], stop=parts[3], enabled=parts[4] == "Y"
    )


def parse_mt_set(
    raw_set: bytes,
    *,
    schema: Mapping[str, ParameterSpecV1],
    metadata: SetImportMetadataV1,
) -> SetPresetV1:
    """Parse a bounded MT4/MT5 .set file against an explicit field schema.

    Supported encodings are BOM-marked UTF-16LE/BE and UTF-8, unmarked UTF-8,
    and unmarked UTF-16 when its NUL-byte distribution is unambiguous. The first
    optimization cell is the active value; start/step/stop/enable are preserved.
    """

    if not isinstance(metadata, SetImportMetadataV1):
        raise MtSetImportError("INVALID_METADATA")
    if not isinstance(schema, Mapping) or not schema or len(schema) > MAX_SET_FIELDS:
        raise MtSetImportError("INVALID_SCHEMA")
    normalized_schema: dict[str, tuple[str, ParameterSpecV1]] = {}
    for name, spec in schema.items():
        if not isinstance(name, str) or not _IDENTIFIER.fullmatch(name):
            raise MtSetImportError("INVALID_SCHEMA")
        if not isinstance(spec, ParameterSpecV1):
            raise MtSetImportError("INVALID_SCHEMA")
        normalized = name.casefold()
        if normalized in normalized_schema:
            raise MtSetImportError("INVALID_SCHEMA")
        normalized_schema[normalized] = (name, spec)

    text = _decode_set_bytes(raw_set)
    lines = text.splitlines()
    if len(lines) > MAX_SET_LINES:
        raise MtSetImportError("EXCESSIVE_SIZE")
    parameters: dict[str, SetParameterV1] = {}
    seen_names: set[str] = set()
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith(";"):
            continue
        if "=" not in stripped:
            raise MtSetImportError("INVALID_SET_TEXT")
        name, value_cell = stripped.split("=", 1)
        name = name.strip()
        if not _IDENTIFIER.fullmatch(name):
            raise MtSetImportError("INVALID_FIELD_NAME")
        normalized = name.casefold()
        if normalized in seen_names:
            raise MtSetImportError("DUPLICATE_FIELD")
        seen_names.add(normalized)
        # Titan X stores presentation-only separators as hintN=... lines.
        if _HINT.fullmatch(name):
            continue
        if len(parameters) >= MAX_SET_FIELDS:
            raise MtSetImportError("EXCESSIVE_SIZE")
        definition = normalized_schema.get(normalized)
        if definition is None:
            raise MtSetImportError("UNKNOWN_FIELD")
        schema_name, spec = definition
        raw_value, optimization = _parse_value_cell(value_cell.strip())
        value = _typed_value(raw_value, spec.value_type)
        parameters[schema_name] = SetParameterV1(
            name=schema_name,
            value_type=spec.value_type,
            value=value,
            raw_value=raw_value,
            unit=spec.unit,
            optimization=optimization,
        )
    if not parameters:
        raise MtSetImportError("EMPTY_SET")

    return SetPresetV1(
        schema_version="1",
        preset_id=metadata.preset_id,
        preset_version=metadata.preset_version,
        platform=metadata.platform,
        source_family=metadata.source_family,
        source_locator=metadata.source_locator,
        original_set_bytes=raw_set,
        original_sha256=hashlib.sha256(raw_set).hexdigest(),
        parameters=MappingProxyType(parameters),
        instrument_mapping=metadata.instrument_mapping,
        timezone_mapping=metadata.timezone_mapping,
        license_status=metadata.license_status,
        license_reference=metadata.license_reference,
    )


def validated_hosting_material(
    preset: SetPresetV1,
    *,
    sovereign_risk_overrides: Mapping[str, ScalarV1],
) -> HostingSetMaterialV1:
    """Return original bytes and hash plus effective values with risk last.

    The byte payload is never rewritten. The hosting adapter must apply the
    returned effective values as sovereign overrides when loading the SET.
    """

    if not isinstance(preset, SetPresetV1):
        raise MtSetImportError("INVALID_PRESET")
    if hashlib.sha256(preset.original_set_bytes).hexdigest() != preset.original_sha256:
        raise MtSetImportError("SOURCE_HASH_MISMATCH")
    if not isinstance(sovereign_risk_overrides, Mapping):
        raise MtSetImportError("INVALID_SOVEREIGN_OVERRIDES")
    effective = {name: parameter.value for name, parameter in preset.parameters.items()}
    overridden: list[str] = []
    for name, value in sovereign_risk_overrides.items():
        parameter = preset.parameters.get(name)
        if parameter is None:
            raise MtSetImportError("UNKNOWN_SOVEREIGN_OVERRIDE")
        if not _matches_type(value, parameter.value_type):
            raise MtSetImportError("INVALID_SOVEREIGN_OVERRIDE")
        effective[name] = value
        overridden.append(name)
    return HostingSetMaterialV1(
        original_set_bytes=preset.original_set_bytes,
        original_sha256=preset.original_sha256,
        effective_values=MappingProxyType(effective),
        sovereign_override_names=tuple(sorted(overridden, key=str.casefold)),
    )


def _matches_type(value: object, value_type: FieldTypeV1) -> bool:
    if value_type == "boolean":
        return type(value) is bool
    if value_type == "integer":
        return type(value) is int
    if value_type == "decimal":
        return isinstance(value, Decimal) and value.is_finite()
    if value_type == "string":
        return isinstance(value, str) and len(value) <= MAX_FIELD_VALUE_CHARS
    return False


def source_locator_path(value: str, *, family: SourceFamilyV1) -> str:
    """Normalize and bound a logical source locator without touching the FS."""

    normalized = value.replace("\\", "/") if isinstance(value, str) else ""
    if not normalized or len(normalized) > 512 or normalized.startswith("/"):
        raise MtSetImportError("INVALID_SOURCE_LOCATOR")
    path = PurePosixPath(normalized)
    if any(part in {"", ".", ".."} for part in path.parts) or path.suffix.casefold() != ".set":
        raise MtSetImportError("INVALID_SOURCE_LOCATOR")
    if family == "KINNOBOT":
        if normalized not in {
            "KINNOBOT/EURUSD Q3.set",
            "KINNOBOT/GBPUSD.set",
            "KINNOBOT/GOLD.set",
            "KINNOBOT/oil.set",
            "KINNOBOT/USDJPY.set",
        }:
            raise MtSetImportError("INVALID_SOURCE_LOCATOR")
    elif family == "TITAN_X":
        root_file = len(path.parts) == 2 and path.parts[0] == "TITAN X RESOURCES"
        setfiles_path = len(path.parts) >= 4 and path.parts[:3] == (
            "TITAN X RESOURCES",
            "EAS",
            "SETFILES",
        )
        if not (root_file or setfiles_path):
            raise MtSetImportError("INVALID_SOURCE_LOCATOR")
    return normalized
