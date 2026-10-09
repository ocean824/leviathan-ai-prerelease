"""Independent contract acceptance for the MT export parameter view model."""

from decimal import Decimal

import pytest

from leviathan_core.mt_export_bridge_params import (
    MappingFieldStatus,
    MappingValidationError,
    ParameterDefinitionV1,
    ParameterMappingRequestV1,
    ParameterValueV1,
    require_valid_mapping,
    validate_parameter_mapping,
)
from leviathan_core.seal import verify


def _definition(
    parameter_id: str = "period",
    value_type: str = "int",
    **constraints: object,
) -> ParameterDefinitionV1:
    return ParameterDefinitionV1(
        parameter_id=parameter_id,
        value_type=value_type,
        **constraints,
    )


def _request(
    definitions: tuple[ParameterDefinitionV1, ...],
    values: tuple[ParameterValueV1, ...] = (),
    **choices: object,
) -> ParameterMappingRequestV1:
    return ParameterMappingRequestV1(
        definitions=definitions,
        values=values,
        **choices,
    )


def _fields(state: object) -> dict[str, object]:
    return {field.field_id: field for field in state.fields}  # type: ignore[attr-defined]


def test_required_omission_is_reported_on_its_field_and_blocks_codegen() -> None:
    state = validate_parameter_mapping(_request((_definition(required=True),)))

    period = _fields(state)["parameter:period"]
    assert period.status is MappingFieldStatus.INVALID
    assert period.reason_code == "REQUIRED_VALUE_MISSING"
    assert state.valid is False
    assert state.can_request_codegen is False
    with pytest.raises(MappingValidationError) as error:
        require_valid_mapping(state)
    assert error.value.code == "MAPPING_INVALID"


@pytest.mark.parametrize("value_type", ["datetime", "object"])
def test_unsupported_parameter_type_fails_closed(value_type: str) -> None:
    state = validate_parameter_mapping(
        _request(
            (_definition(value_type=value_type),),
            (ParameterValueV1(parameter_id="period", value=1),),
        )
    )

    period = _fields(state)["parameter:period"]
    assert period.status is MappingFieldStatus.INVALID
    assert period.reason_code == "UNSUPPORTED_TYPE"
    assert state.can_request_codegen is False


@pytest.mark.parametrize("value", [Decimal("-0.01"), Decimal("1.01")])
def test_numeric_value_outside_declared_range_is_invalid(value: Decimal) -> None:
    state = validate_parameter_mapping(
        _request(
            (
                _definition(
                    value_type="double",
                    minimum=Decimal("0"),
                    maximum=Decimal("1"),
                ),
            ),
            (ParameterValueV1(parameter_id="period", value=value),),
        )
    )

    period = _fields(state)["parameter:period"]
    assert period.status is MappingFieldStatus.INVALID
    assert period.reason_code == "OUT_OF_RANGE"
    assert state.can_request_codegen is False


def test_value_not_aligned_to_positive_step_is_invalid() -> None:
    state = validate_parameter_mapping(
        _request(
            (
                _definition(
                    value_type="double",
                    minimum=Decimal("0.1"),
                    maximum=Decimal("0.5"),
                    step=Decimal("0.2"),
                ),
            ),
            (ParameterValueV1(parameter_id="period", value=Decimal("0.4")),),
        )
    )

    period = _fields(state)["parameter:period"]
    assert period.status is MappingFieldStatus.INVALID
    assert period.reason_code == "INVALID_STEP"
    assert state.can_request_codegen is False


@pytest.mark.parametrize("step", [Decimal("0"), Decimal("-0.1")])
def test_nonpositive_step_definition_is_invalid(step: Decimal) -> None:
    state = validate_parameter_mapping(
        _request(
            (_definition(value_type="double", step=step),),
            (ParameterValueV1(parameter_id="period", value=Decimal("1")),),
        )
    )

    assert _fields(state)["parameter:period"].reason_code == "INVALID_STEP"
    assert state.can_request_codegen is False


def test_unknown_symbol_and_timeframe_are_field_level_errors() -> None:
    state = validate_parameter_mapping(
        _request(
            (),
            symbol_choices=("EURUSD",),
            selected_symbol="GBPUSD",
            timeframe_choices=("M1", "H1"),
            selected_timeframe="D1",
        )
    )

    fields = _fields(state)
    assert fields["binding:symbol"].reason_code == "UNKNOWN_SYMBOL"
    assert fields["binding:timeframe"].reason_code == "UNKNOWN_TIMEFRAME"
    assert state.valid is False
    assert state.can_request_codegen is False


@pytest.mark.parametrize("reserved_id", ["symbol", "timeframe"])
def test_reserved_parameter_ids_are_invalid_and_cannot_enable_codegen(
    reserved_id: str,
) -> None:
    state = validate_parameter_mapping(
        _request(
            (_definition(reserved_id, "string"),),
            (ParameterValueV1(parameter_id=reserved_id, value="logical-parameter"),),
            symbol_choices=("EURUSD",),
            selected_symbol="EURUSD",
            timeframe_choices=("M15",),
            selected_timeframe="M15",
        )
    )

    field_ids = [field.field_id for field in state.fields]
    fields = _fields(state)
    assert len(field_ids) == len(set(field_ids))
    assert f"parameter:{reserved_id}" in fields
    assert fields[f"parameter:{reserved_id}"].reason_code == "RESERVED_PARAMETER_ID"
    assert fields["binding:symbol"].status is MappingFieldStatus.VALID
    assert fields["binding:timeframe"].status is MappingFieldStatus.VALID
    assert state.valid is False
    assert state.can_request_codegen is False
    with pytest.raises(MappingValidationError) as error:
        require_valid_mapping(state)
    assert error.value.code == "MAPPING_INVALID"


def test_parameter_namespace_cannot_collide_with_binding_field_ids() -> None:
    state = validate_parameter_mapping(
        _request(
            (_definition("binding:symbol", "string"),),
            (ParameterValueV1(parameter_id="binding:symbol", value="logical-parameter"),),
            symbol_choices=("EURUSD",),
            selected_symbol="EURUSD",
            timeframe_choices=("M15",),
            selected_timeframe="M15",
        )
    )

    field_ids = [field.field_id for field in state.fields]
    fields = _fields(state)
    assert len(field_ids) == len(set(field_ids))
    assert fields["parameter:binding:symbol"].normalized_value == "logical-parameter"
    assert fields["binding:symbol"].normalized_value == "EURUSD"
    assert fields["binding:timeframe"].normalized_value == "M15"
    assert state.valid is True
    assert state.can_request_codegen is True
    assert require_valid_mapping(state) is state


def test_valid_mapping_has_deterministic_normalized_field_results() -> None:
    request = _request(
        (
            _definition(
                "risk_mode",
                "enum",
                enum_values=("fixed", "formula"),
            ),
            _definition("enabled", "bool", default=True),
            _definition(
                "lots",
                "double",
                minimum=Decimal("0.01"),
                maximum=Decimal("2"),
                step=Decimal("0.01"),
            ),
            _definition("period", "int", minimum=1, maximum=100, step=1),
        ),
        (
            ParameterValueV1(parameter_id="period", value=20),
            ParameterValueV1(parameter_id="risk_mode", value="fixed"),
            ParameterValueV1(parameter_id="lots", value=Decimal("0.25")),
        ),
        symbol_choices=("EURUSD", "GBPUSD"),
        selected_symbol="EURUSD",
        timeframe_choices=("M15", "H1"),
        selected_timeframe="M15",
    )

    first = validate_parameter_mapping(request)
    second = validate_parameter_mapping(request)

    assert first == second
    assert first.valid is True
    assert first.can_request_codegen is True
    assert verify(first, "mtbr.param_mapping_view_state.v1")
    fields = _fields(first)
    assert list(fields) == [
        "parameter:enabled",
        "parameter:lots",
        "parameter:period",
        "parameter:risk_mode",
        "binding:symbol",
        "binding:timeframe",
    ]
    assert [
        (
            field.field_id,
            field.status,
            field.reason_code,
            field.normalized_value,
        )
        for field in first.fields
    ] == [
        ("parameter:enabled", MappingFieldStatus.VALID, None, True),
        ("parameter:lots", MappingFieldStatus.VALID, None, Decimal("0.25")),
        ("parameter:period", MappingFieldStatus.VALID, None, 20),
        ("parameter:risk_mode", MappingFieldStatus.VALID, None, "fixed"),
        ("binding:symbol", MappingFieldStatus.VALID, None, "EURUSD"),
        ("binding:timeframe", MappingFieldStatus.VALID, None, "M15"),
    ]
    assert require_valid_mapping(first) is first


def test_invalid_view_cannot_be_used_as_a_codegen_request() -> None:
    state = validate_parameter_mapping(_request((_definition(required=True),)))

    assert state.valid is False
    assert state.can_request_codegen is False
    with pytest.raises(MappingValidationError) as error:
        require_valid_mapping(state)
    assert error.value.code == "MAPPING_INVALID"


def test_caller_constructed_and_copied_views_are_not_issued() -> None:
    issued = validate_parameter_mapping(_request(()))
    caller_constructed = type(issued)(
        fields=issued.fields,
        valid=issued.valid,
        can_request_codegen=issued.can_request_codegen,
        lot_sizing_binding=issued.lot_sizing_binding,
    )

    for view in (caller_constructed, caller_constructed.model_copy()):
        with pytest.raises(MappingValidationError) as error:
            require_valid_mapping(view)
        assert error.value.code == "MAPPING_NOT_ISSUED"


def test_formula_binding_is_opaque_and_never_evaluated(tmp_path) -> None:
    sentinel = tmp_path / "formula-ran"
    formula = f"__import__('pathlib').Path({str(sentinel)!r}).write_text('executed')"
    state = validate_parameter_mapping(_request((), lot_sizing_binding=formula))

    assert state.valid is True
    assert state.can_request_codegen is True
    assert state.lot_sizing_binding == formula
    assert not sentinel.exists()
