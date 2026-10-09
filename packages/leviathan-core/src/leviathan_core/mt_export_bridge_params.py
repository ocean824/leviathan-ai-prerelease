"""Pure, deterministic MT4/MT5 parameter-mapping validation view state.

This module accepts definitions, values, and choice lists from its caller. It
does not inspect terminals or brokers, build MQL, deploy artifacts, or evaluate
lot-sizing formulas.
"""

from __future__ import annotations

from decimal import Decimal
from enum import StrEnum
from typing import TypeAlias

from pydantic import BaseModel, ConfigDict

from leviathan_core.numeric import NumericError, parse_decimal
from leviathan_core.seal import Issuer, SealedModel, SealError, require

JsonScalar: TypeAlias = str | int | Decimal | bool | None


class MappingFieldStatus(StrEnum):
    VALID = "VALID"
    INVALID = "INVALID"


class ParameterDefinitionV1(BaseModel):
    """Caller-supplied mapping constraints for one source parameter."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    parameter_id: str
    value_type: str
    required: bool = False
    default: JsonScalar = None
    minimum: object | None = None
    maximum: object | None = None
    step: object | None = None
    enum_values: tuple[str, ...] = ()


class ParameterValueV1(BaseModel):
    """One caller-supplied value for a source parameter."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    parameter_id: str
    value: object


class ParameterMappingRequestV1(BaseModel):
    """Synthetic input used to produce a parameter-mapping view."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    definitions: tuple[ParameterDefinitionV1, ...]
    values: tuple[ParameterValueV1, ...] = ()
    symbol_choices: tuple[str, ...] = ()
    selected_symbol: str | None = None
    timeframe_choices: tuple[str, ...] = ()
    selected_timeframe: str | None = None
    # Deliberately opaque. Formula text is displayed/passed through, never run.
    lot_sizing_binding: str | None = None


class FieldValidationV1(SealedModel):
    """Content-minimal validation result for a single displayed field."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    field_id: str
    status: MappingFieldStatus
    reason_code: str | None = None
    normalized_value: JsonScalar = None


class ParameterMappingViewStateV1(SealedModel):
    """Deterministic view state; it contains no build or deploy operation."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    fields: tuple[FieldValidationV1, ...]
    valid: bool
    can_request_codegen: bool
    lot_sizing_binding: str | None


class MappingValidationError(ValueError):
    """Content-free rejection of an unissued or invalid mapping view."""

    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        if code not in {"MAPPING_NOT_ISSUED", "MAPPING_INVALID"}:
            raise TypeError("unknown mapping validation error")
        self.code = code
        super().__init__(code)

    def __str__(self) -> str:
        return self.code


_VIEW_ISSUER = Issuer("mtbr.param_mapping_view_state.v1")


_SUPPORTED_TYPES = frozenset({"int", "long", "double", "bool", "string", "color", "enum"})
_INTEGER_TYPES = frozenset({"int", "long"})
_RESERVED_PARAMETER_IDS = frozenset({"symbol", "timeframe"})


def _result(
    field_id: str,
    reason_code: str | None = None,
    normalized_value: JsonScalar = None,
) -> FieldValidationV1:
    return FieldValidationV1(
        field_id=field_id,
        status=MappingFieldStatus.INVALID if reason_code else MappingFieldStatus.VALID,
        reason_code=reason_code,
        normalized_value=normalized_value,
    )


def _number(value: object, field: str) -> Decimal:
    return parse_decimal(value, field=field)


def _scaled_integer(value: Decimal, scale: int) -> int:
    parts = value.as_tuple()
    exponent = parts.exponent
    if not isinstance(exponent, int):
        raise NumericError("INVALID_DECIMAL", "value")
    coefficient: int = 0
    for digit in parts.digits:
        coefficient = coefficient * 10 + digit
    if exponent >= 0:
        coefficient *= 10**exponent
    else:
        coefficient *= 10 ** (scale + exponent)
    return -coefficient if parts.sign else coefficient


def _decimal_scale(value: Decimal) -> int:
    exponent = value.as_tuple().exponent
    if not isinstance(exponent, int):
        raise NumericError("INVALID_DECIMAL", "value")
    return max(0, -exponent)


def _step_aligned(value: Decimal, anchor: Decimal, step: Decimal) -> bool:
    scale = max(
        _decimal_scale(value),
        _decimal_scale(anchor),
        _decimal_scale(step),
    )
    difference = _scaled_integer(value, scale) - _scaled_integer(anchor, scale)
    return difference % _scaled_integer(step, scale) == 0


def _validate_numeric(
    definition: ParameterDefinitionV1, value: object
) -> tuple[str | None, JsonScalar]:
    numeric_id = f"{definition.parameter_id}.value"
    try:
        number = _number(value, numeric_id)
        minimum = (
            _number(definition.minimum, f"{definition.parameter_id}.minimum")
            if definition.minimum is not None
            else None
        )
        maximum = (
            _number(definition.maximum, f"{definition.parameter_id}.maximum")
            if definition.maximum is not None
            else None
        )
        step = (
            _number(definition.step, f"{definition.parameter_id}.step")
            if definition.step is not None
            else None
        )
    except (NumericError, TypeError, ValueError):
        return "INVALID_NUMERIC", None

    if minimum is not None and maximum is not None and minimum > maximum:
        return "INVALID_RANGE", None
    if step is not None and step <= 0:
        return "INVALID_STEP", None

    if definition.value_type in _INTEGER_TYPES and number != number.to_integral_value():
        return "INVALID_TYPE", None
    if definition.value_type == "long" and not -(2**63) <= int(number) <= 2**63 - 1:
        return "OUT_OF_RANGE", None
    if definition.value_type == "int" and not -(2**31) <= int(number) <= 2**31 - 1:
        return "OUT_OF_RANGE", None
    if (minimum is not None and number < minimum) or (maximum is not None and number > maximum):
        return "OUT_OF_RANGE", None
    anchor = minimum if minimum is not None else Decimal(0)
    if step is not None and not _step_aligned(number, anchor, step):
        return "INVALID_STEP", None
    normalized: JsonScalar = int(number) if definition.value_type in _INTEGER_TYPES else number
    return None, normalized


def _validate_value(
    definition: ParameterDefinitionV1, value: object
) -> tuple[str | None, JsonScalar]:
    kind = definition.value_type
    if kind not in _SUPPORTED_TYPES:
        return "UNSUPPORTED_TYPE", None
    if kind in _INTEGER_TYPES | {"double"}:
        return _validate_numeric(definition, value)
    if any(item is not None for item in (definition.minimum, definition.maximum, definition.step)):
        return "UNSUPPORTED_CONSTRAINT", None
    if kind == "bool":
        return (None, value) if type(value) is bool else ("INVALID_TYPE", None)
    if kind in {"string", "color"}:
        return (None, value) if isinstance(value, str) else ("INVALID_TYPE", None)
    if kind == "enum":
        if not definition.enum_values:
            return "INVALID_ENUM_OPTIONS", None
        return (
            (None, value)
            if isinstance(value, str) and value in definition.enum_values
            else ("INVALID_ENUM_VALUE", None)
        )
    return "UNSUPPORTED_TYPE", None


def validate_parameter_mapping(
    request: ParameterMappingRequestV1,
) -> ParameterMappingViewStateV1:
    """Validate injected mappings and choices without side effects."""
    fields: list[FieldValidationV1] = []
    definitions_by_id: dict[str, ParameterDefinitionV1] = {}
    definition_counts: dict[str, int] = {}
    for definition in request.definitions:
        definition_counts[definition.parameter_id] = (
            definition_counts.get(definition.parameter_id, 0) + 1
        )
        definitions_by_id[definition.parameter_id] = definition

    values_by_id: dict[str, object] = {}
    value_counts: dict[str, int] = {}
    for item in request.values:
        value_counts[item.parameter_id] = value_counts.get(item.parameter_id, 0) + 1
        values_by_id[item.parameter_id] = item.value

    seen_parameter_ids: set[str] = set()
    for definition in sorted(request.definitions, key=lambda item: item.parameter_id):
        parameter_id = definition.parameter_id
        if parameter_id in seen_parameter_ids:
            continue
        seen_parameter_ids.add(parameter_id)
        field_id = f"parameter:{parameter_id}"
        if definition_counts[parameter_id] > 1:
            fields.append(_result(field_id, "DUPLICATE_DEFINITION"))
            continue
        if parameter_id in _RESERVED_PARAMETER_IDS:
            fields.append(_result(field_id, "RESERVED_PARAMETER_ID"))
            continue
        if value_counts.get(parameter_id, 0) > 1:
            fields.append(_result(field_id, "DUPLICATE_VALUE"))
            continue
        value = values_by_id.get(parameter_id, definition.default)
        if value is None:
            fields.append(
                _result(field_id, "REQUIRED_VALUE_MISSING" if definition.required else None)
            )
            continue
        reason_code, normalized = _validate_value(definition, value)
        fields.append(_result(field_id, reason_code, normalized))

    for parameter_id in sorted(set(values_by_id) - set(definitions_by_id)):
        fields.append(_result(f"parameter:{parameter_id}", "UNKNOWN_PARAMETER_ID"))

    fields.append(
        _result(
            "binding:symbol",
            None
            if request.selected_symbol is None or request.selected_symbol in request.symbol_choices
            else "UNKNOWN_SYMBOL",
            request.selected_symbol,
        )
    )
    fields.append(
        _result(
            "binding:timeframe",
            None
            if request.selected_timeframe is None
            or request.selected_timeframe in request.timeframe_choices
            else "UNKNOWN_TIMEFRAME",
            request.selected_timeframe,
        )
    )

    frozen_fields = tuple(fields)
    valid = all(field.status is MappingFieldStatus.VALID for field in frozen_fields)
    return _VIEW_ISSUER.issue(
        ParameterMappingViewStateV1(
            fields=frozen_fields,
            valid=valid,
            can_request_codegen=valid,
            lot_sizing_binding=request.lot_sizing_binding,
        )
    )


def require_valid_mapping(obj: object) -> ParameterMappingViewStateV1:
    """Return only an issued, unchanged, valid mapping view state."""
    if type(obj) is not ParameterMappingViewStateV1:
        raise MappingValidationError("MAPPING_NOT_ISSUED")
    try:
        issued = require(obj, "mtbr.param_mapping_view_state.v1")
    except SealError:
        raise MappingValidationError("MAPPING_NOT_ISSUED") from None
    if not issued.valid:
        raise MappingValidationError("MAPPING_INVALID")
    return issued


__all__ = [
    "FieldValidationV1",
    "MappingFieldStatus",
    "MappingValidationError",
    "ParameterDefinitionV1",
    "ParameterMappingRequestV1",
    "ParameterMappingViewStateV1",
    "ParameterValueV1",
    "require_valid_mapping",
    "validate_parameter_mapping",
]
