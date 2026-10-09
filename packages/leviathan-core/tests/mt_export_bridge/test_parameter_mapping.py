"""Writer-owned checks for the pure MT export parameter view model."""

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

D = Decimal


def _definition(
    parameter_id: str = "period",
    value_type: str = "int",
    **kwargs: object,
) -> ParameterDefinitionV1:
    return ParameterDefinitionV1(parameter_id=parameter_id, value_type=value_type, **kwargs)


def _request(
    definitions: tuple[ParameterDefinitionV1, ...],
    values: tuple[ParameterValueV1, ...] = (),
    **kwargs: object,
) -> ParameterMappingRequestV1:
    return ParameterMappingRequestV1(definitions=definitions, values=values, **kwargs)


def _field_codes(state: object) -> dict[str, str | None]:
    return {field.field_id: field.reason_code for field in state.fields}  # type: ignore[attr-defined]


def test_required_omission_is_field_level_and_disables_codegen() -> None:
    state = validate_parameter_mapping(_request((_definition(required=True),)))

    assert state.valid is False
    assert state.can_request_codegen is False
    assert _field_codes(state)["parameter:period"] == "REQUIRED_VALUE_MISSING"
    with pytest.raises(MappingValidationError) as error:
        require_valid_mapping(state)
    assert error.value.code == "MAPPING_INVALID"


@pytest.mark.parametrize("value_type", ["unsupported", "datetime"])
def test_unsupported_parameter_type_is_invalid(value_type: str) -> None:
    state = validate_parameter_mapping(
        _request(
            (_definition(value_type=value_type),),
            (ParameterValueV1(parameter_id="period", value=1),),
        )
    )

    assert state.valid is False
    assert _field_codes(state)["parameter:period"] == "UNSUPPORTED_TYPE"


def test_decimal_range_and_step_are_exact_and_step_is_anchored_at_minimum() -> None:
    definition = _definition(value_type="double", minimum=D("0.1"), maximum=D("0.5"), step=D("0.2"))
    on_grid = validate_parameter_mapping(
        _request((definition,), (ParameterValueV1(parameter_id="period", value=D("0.3")),))
    )
    off_grid = validate_parameter_mapping(
        _request((definition,), (ParameterValueV1(parameter_id="period", value=D("0.4")),))
    )
    outside = validate_parameter_mapping(
        _request((definition,), (ParameterValueV1(parameter_id="period", value=D("0.7")),))
    )

    assert on_grid.valid is True
    assert on_grid.fields[0].normalized_value == D("0.3")
    assert _field_codes(off_grid)["parameter:period"] == "INVALID_STEP"
    assert _field_codes(outside)["parameter:period"] == "OUT_OF_RANGE"


@pytest.mark.parametrize("step", [D(0), D(-1)])
def test_nonpositive_step_is_invalid(step: Decimal) -> None:
    state = validate_parameter_mapping(
        _request(
            (_definition(value_type="double", step=step),),
            (ParameterValueV1(parameter_id="period", value=D("1")),),
        )
    )

    assert state.valid is False
    assert _field_codes(state)["parameter:period"] == "INVALID_STEP"


def test_symbol_and_timeframe_choices_are_caller_supplied() -> None:
    state = validate_parameter_mapping(
        _request(
            (),
            symbol_choices=("EURUSD",),
            selected_symbol="GBPUSD",
            timeframe_choices=("M1", "H1"),
            selected_timeframe="D1",
        )
    )

    assert state.can_request_codegen is False
    assert _field_codes(state)["binding:symbol"] == "UNKNOWN_SYMBOL"
    assert _field_codes(state)["binding:timeframe"] == "UNKNOWN_TIMEFRAME"


def test_valid_mapping_is_deterministic_and_preserves_opaque_formula_text() -> None:
    formula = "fixed_lot * balance / 10000"
    request = _request(
        (
            _definition("risk_mode", "enum", enum_values=("fixed", "formula")),
            _definition("enabled", "bool", default=True),
            _definition("lots", "double", minimum=D("0.01"), maximum=D("5"), step=D("0.01")),
        ),
        (
            ParameterValueV1(parameter_id="risk_mode", value="formula"),
            ParameterValueV1(parameter_id="lots", value=D("0.25")),
        ),
        symbol_choices=("EURUSD",),
        selected_symbol="EURUSD",
        timeframe_choices=("M15",),
        selected_timeframe="M15",
        lot_sizing_binding=formula,
    )

    first = validate_parameter_mapping(request)
    second = validate_parameter_mapping(request)

    assert first == second
    assert first.valid is True
    assert first.can_request_codegen is True
    assert first.lot_sizing_binding == formula
    assert verify(first, "mtbr.param_mapping_view_state.v1")
    assert [field.field_id for field in first.fields] == [
        "parameter:enabled",
        "parameter:lots",
        "parameter:risk_mode",
        "binding:symbol",
        "binding:timeframe",
    ]
    assert all(field.status is MappingFieldStatus.VALID for field in first.fields)
    assert require_valid_mapping(first) is first


def test_caller_constructed_or_copied_valid_state_is_not_trusted() -> None:
    caller_state = validate_parameter_mapping(_request(()))
    unissued_state = type(caller_state)(
        fields=caller_state.fields,
        valid=caller_state.valid,
        can_request_codegen=caller_state.can_request_codegen,
        lot_sizing_binding=caller_state.lot_sizing_binding,
    )
    copied_state = unissued_state.model_copy()

    for state in (unissued_state, copied_state):
        with pytest.raises(MappingValidationError) as error:
            require_valid_mapping(state)
        assert error.value.code == "MAPPING_NOT_ISSUED"


def test_boolean_cannot_be_used_as_a_number_and_duplicate_values_fail_closed() -> None:
    definition = _definition(value_type="double")
    boolean = validate_parameter_mapping(
        _request((definition,), (ParameterValueV1(parameter_id="period", value=True),))
    )
    duplicate = validate_parameter_mapping(
        _request(
            (definition,),
            (
                ParameterValueV1(parameter_id="period", value=D("1")),
                ParameterValueV1(parameter_id="period", value=D("2")),
            ),
        )
    )

    assert _field_codes(boolean)["parameter:period"] == "INVALID_NUMERIC"
    assert _field_codes(duplicate)["parameter:period"] == "DUPLICATE_VALUE"
    assert duplicate.can_request_codegen is False


@pytest.mark.parametrize("reserved_id", ["symbol", "timeframe"])
def test_reserved_parameter_ids_are_distinct_and_block_codegen(reserved_id: str) -> None:
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

    assert len(field_ids) == len(set(field_ids))
    assert _field_codes(state)[f"parameter:{reserved_id}"] == "RESERVED_PARAMETER_ID"
    assert _field_codes(state)[f"binding:{reserved_id}"] is None
    assert state.valid is False
    assert state.can_request_codegen is False
    with pytest.raises(MappingValidationError) as error:
        require_valid_mapping(state)
    assert error.value.code == "MAPPING_INVALID"


def test_parameter_id_namespace_cannot_collide_with_binding_namespace() -> None:
    state = validate_parameter_mapping(
        _request(
            (_definition("binding:symbol", "string"),),
            (ParameterValueV1(parameter_id="binding:symbol", value="custom"),),
            symbol_choices=("EURUSD",),
            selected_symbol="EURUSD",
        )
    )

    field_ids = [field.field_id for field in state.fields]
    assert field_ids == [
        "parameter:binding:symbol",
        "binding:symbol",
        "binding:timeframe",
    ]
    assert len(field_ids) == len(set(field_ids))
    assert state.can_request_codegen is True
