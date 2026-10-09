"""Unit coverage for pure MT4/MT5 export-definition invariants."""

from __future__ import annotations

import copy
import pickle
from dataclasses import replace
from decimal import Decimal

import pytest

from leviathan_core.mt_export_bridge_db import (
    ArtifactTypeV1,
    CodegenTemplateV1,
    DefinitionInvariantError,
    DefinitionValidationV1,
    ExportJobV1,
    ParameterDefinitionV1,
    ParameterTypeV1,
    PlatformV1,
    ResolvedParameterV1,
    SymbolMapEntryV1,
    validate_export_definitions,
)


def _template(
    template_id: str = "template-mt4",
    *,
    platform: PlatformV1 = PlatformV1.MT4,
    name: str = "Simple EMA",
    version: str = "1.0",
) -> CodegenTemplateV1:
    return CodegenTemplateV1(
        template_id=template_id,
        platform=platform,
        name=name,
        version=version,
        artifact_type=ArtifactTypeV1.EA,
    )


def _definition(
    key: str = "period",
    *,
    template_id: str = "template-mt4",
    value_type: ParameterTypeV1 = ParameterTypeV1.INTEGER,
    required: bool = True,
    minimum: Decimal | None = Decimal("1"),
    maximum: Decimal | None = Decimal("100"),
    enum_values: tuple[str, ...] = (),
) -> ParameterDefinitionV1:
    return ParameterDefinitionV1(
        template_id=template_id,
        key=key,
        value_type=value_type,
        required=required,
        minimum=minimum,
        maximum=maximum,
        enum_values=enum_values,
    )


def _job(
    params: tuple[ResolvedParameterV1, ...] = (ResolvedParameterV1("period", 14),),
    *,
    export_job_id: str = "job-1",
    template_id: str = "template-mt4",
) -> ExportJobV1:
    return ExportJobV1(
        export_job_id=export_job_id,
        template_id=template_id,
        params_resolved=params,
    )


def _validate(
    *,
    templates: tuple[CodegenTemplateV1, ...] = (_template(),),
    parameter_definitions: tuple[ParameterDefinitionV1, ...] = (_definition(),),
    export_jobs: tuple[ExportJobV1, ...] = (_job(),),
    symbol_maps: tuple[SymbolMapEntryV1, ...] = (),
) -> DefinitionValidationV1:
    return validate_export_definitions(
        templates=templates,
        parameter_definitions=parameter_definitions,
        export_jobs=export_jobs,
        symbol_maps=symbol_maps,
    )


def test_valid_mt4_and_mt5_definitions_return_deterministic_counts() -> None:
    templates = (
        _template(),
        _template("template-mt5", platform=PlatformV1.MT5),
    )
    definitions = (
        _definition(),
        _definition("period", template_id="template-mt5"),
    )
    jobs = (
        _job(export_job_id="job-mt4"),
        _job(export_job_id="job-mt5", template_id="template-mt5"),
    )
    result = _validate(
        templates=templates,
        parameter_definitions=definitions,
        export_jobs=jobs,
        symbol_maps=(SymbolMapEntryV1("target-1", "EURUSD", "EURUSD.a"),),
    )

    assert result.template_count == 2
    assert result.parameter_definition_count == 2
    assert result.export_job_count == 2
    assert result.symbol_map_count == 1


def test_template_name_and_version_are_unique_per_platform_only() -> None:
    _validate(
        templates=(_template(), _template("template-mt5", platform=PlatformV1.MT5)),
        parameter_definitions=(_definition(),),
        export_jobs=(_job(),),
    )

    with pytest.raises(DefinitionInvariantError) as caught:
        _validate(templates=(_template(), _template("template-2")))

    assert caught.value.code == "DUPLICATE_TEMPLATE"


def test_parameter_definition_identity_is_scoped_to_template() -> None:
    _validate(
        templates=(_template(), _template("template-2", name="Other")),
        parameter_definitions=(_definition(), _definition(template_id="template-2")),
        export_jobs=(_job(),),
    )

    with pytest.raises(DefinitionInvariantError) as caught:
        _validate(parameter_definitions=(_definition(), _definition()))

    assert caught.value.code == "DUPLICATE_PARAMETER_DEFINITION"


def test_orphan_parameter_definition_fails_template_reference() -> None:
    with pytest.raises(DefinitionInvariantError) as caught:
        _validate(parameter_definitions=(_definition(template_id="missing-template"),))

    assert "UNKNOWN_TEMPLATE_REFERENCE" in caught.value.codes


@pytest.mark.parametrize(
    ("params", "expected"),
    [
        ((), "MISSING_REQUIRED_PARAMETER"),
        ((ResolvedParameterV1("period", True),), "PARAMETER_TYPE_MISMATCH"),
        ((ResolvedParameterV1("period", 0),), "PARAMETER_OUT_OF_RANGE"),
        ((ResolvedParameterV1("period", 101),), "PARAMETER_OUT_OF_RANGE"),
        ((ResolvedParameterV1("unknown", 14),), "MISSING_REQUIRED_PARAMETER"),
    ],
)
def test_required_type_range_and_unknown_parameter_fail(
    params: tuple[ResolvedParameterV1, ...], expected: str
) -> None:
    with pytest.raises(DefinitionInvariantError) as caught:
        _validate(export_jobs=(_job(params),))

    assert expected in caught.value.codes


def test_unknown_parameter_is_rejected_without_echoing_the_key() -> None:
    marker = "private_field"
    with pytest.raises(DefinitionInvariantError) as caught:
        _validate(export_jobs=(_job((ResolvedParameterV1(marker, 14),)),))

    assert caught.value.code == "MISSING_REQUIRED_PARAMETER"
    assert "UNKNOWN_PARAMETER" in caught.value.codes
    assert marker not in str(caught.value)
    assert marker not in repr(caught.value)


def test_decimal_ranges_use_num001_and_reject_float_values() -> None:
    definition = _definition(
        "threshold",
        value_type=ParameterTypeV1.DECIMAL,
        minimum=Decimal("0.125"),
        maximum=Decimal("0.5"),
    )
    _validate(
        parameter_definitions=(definition,),
        export_jobs=(_job((ResolvedParameterV1("threshold", Decimal("0.25")),)),),
    )

    with pytest.raises(DefinitionInvariantError) as caught:
        _validate(
            parameter_definitions=(definition,),
            export_jobs=(_job((ResolvedParameterV1("threshold", "not-a-decimal"),)),),
        )
    assert caught.value.code == "INVALID_PARAMETER_VALUE"

    with pytest.raises(DefinitionInvariantError) as caught:
        ResolvedParameterV1("threshold", 0.25)  # type: ignore[arg-type]
    assert caught.value.code == "INVALID_PARAMETER_VALUE"


def test_decimal_input_is_parsed_exactly_and_range_checked() -> None:
    definition = _definition(
        "threshold",
        value_type=ParameterTypeV1.DECIMAL,
        minimum=Decimal("0.1"),
        maximum=Decimal("0.3"),
    )
    _validate(
        parameter_definitions=(definition,),
        export_jobs=(_job((ResolvedParameterV1("threshold", "0.30"),)),),
    )
    with pytest.raises(DefinitionInvariantError) as caught:
        _validate(
            parameter_definitions=(definition,),
            export_jobs=(_job((ResolvedParameterV1("threshold", "0.3001"),)),),
        )
    assert caught.value.code == "PARAMETER_OUT_OF_RANGE"


def test_enum_definitions_require_explicit_values_and_check_membership() -> None:
    definition = _definition(
        "mode",
        value_type=ParameterTypeV1.ENUM,
        minimum=None,
        maximum=None,
        enum_values=("FAST", "SLOW"),
    )
    _validate(
        parameter_definitions=(definition,),
        export_jobs=(_job((ResolvedParameterV1("mode", "FAST"),)),),
    )
    with pytest.raises(DefinitionInvariantError) as caught:
        _validate(
            parameter_definitions=(definition,),
            export_jobs=(_job((ResolvedParameterV1("mode", "MEDIUM"),)),),
        )
    assert caught.value.code == "PARAMETER_ENUM_INVALID"


def test_parameter_definition_rejects_ill_typed_or_reversed_bounds() -> None:
    with pytest.raises(DefinitionInvariantError) as caught:
        _definition(minimum=Decimal("10"), maximum=Decimal("1"))
    assert caught.value.code == "INVALID_PARAMETER_DEFINITION"

    with pytest.raises(DefinitionInvariantError) as caught:
        _definition(minimum=Decimal("NaN"))
    assert caught.value.code == "INVALID_PARAMETER_DEFINITION"

    with pytest.raises(DefinitionInvariantError) as caught:
        _definition(required="false")  # type: ignore[arg-type]
    assert caught.value.code == "INVALID_PARAMETER_DEFINITION"


def test_jobs_require_a_known_template_and_have_unique_ids() -> None:
    with pytest.raises(DefinitionInvariantError) as caught:
        _validate(export_jobs=(_job(template_id="missing"),))
    assert caught.value.code == "UNKNOWN_TEMPLATE_REFERENCE"

    with pytest.raises(DefinitionInvariantError) as caught:
        _validate(export_jobs=(_job(), _job()))
    assert caught.value.code == "DUPLICATE_EXPORT_JOB_ID"


def test_unknown_resolved_fields_fail_closed() -> None:
    with pytest.raises(DefinitionInvariantError) as caught:
        _validate(export_jobs=(_job((ResolvedParameterV1("other", 2),)),))

    assert "UNKNOWN_PARAMETER" in caught.value.codes


def test_symbol_map_uniqueness_is_scoped_by_target_and_checks_both_sides() -> None:
    _validate(
        symbol_maps=(
            SymbolMapEntryV1("target-1", "EURUSD", "EURUSD.a"),
            SymbolMapEntryV1("target-2", "EURUSD", "EURUSD.a"),
        )
    )

    with pytest.raises(DefinitionInvariantError) as caught:
        _validate(
            symbol_maps=(
                SymbolMapEntryV1("target-1", "EURUSD", "EURUSD.a"),
                SymbolMapEntryV1("target-1", "EURUSD", "EURUSD.b"),
            )
        )
    assert caught.value.code == "DUPLICATE_LOGICAL_SYMBOL"

    with pytest.raises(DefinitionInvariantError) as caught:
        _validate(
            symbol_maps=(
                SymbolMapEntryV1("target-1", "EURUSD", "EURUSD.a"),
                SymbolMapEntryV1("target-1", "GBPUSD", "EURUSD.a"),
            )
        )
    assert caught.value.code == "DUPLICATE_BROKER_SYMBOL"


def test_failure_codes_are_permutation_invariant() -> None:
    bad_templates = (_template(), _template("template-2"))
    bad_maps = (
        SymbolMapEntryV1("target-1", "EURUSD", "EURUSD.a"),
        SymbolMapEntryV1("target-1", "EURUSD", "EURUSD.b"),
        SymbolMapEntryV1("target-1", "GBPUSD", "EURUSD.a"),
    )
    with pytest.raises(DefinitionInvariantError) as first:
        _validate(templates=bad_templates, symbol_maps=bad_maps)
    with pytest.raises(DefinitionInvariantError) as second:
        _validate(templates=tuple(reversed(bad_templates)), symbol_maps=tuple(reversed(bad_maps)))

    assert first.value.codes == second.value.codes


def test_records_are_deeply_immutable_and_revalidate_replace() -> None:
    definition = _definition()
    with pytest.raises((AttributeError, TypeError)):
        definition.required = False  # type: ignore[misc]
    with pytest.raises(DefinitionInvariantError) as caught:
        replace(definition, required="false")  # type: ignore[arg-type]
    assert caught.value.code == "INVALID_PARAMETER_DEFINITION"
    with pytest.raises(TypeError):
        copy.copy(definition)
    with pytest.raises(TypeError):
        copy.deepcopy(definition)
    with pytest.raises(TypeError):
        pickle.dumps(definition)


def test_input_collections_must_be_explicit_immutable_tuples() -> None:
    with pytest.raises(DefinitionInvariantError) as caught:
        validate_export_definitions(
            templates=[_template()],  # type: ignore[arg-type]
            parameter_definitions=(_definition(),),
            export_jobs=(_job(),),
            symbol_maps=(),
        )
    assert caught.value.code == "INVALID_COLLECTION"


def test_validator_revalidates_records_after_low_level_mutation() -> None:
    template = _template()
    object.__setattr__(template, "platform", "MT4")

    with pytest.raises(DefinitionInvariantError) as caught:
        _validate(templates=(template,))

    assert caught.value.code == "INVALID_IDENTIFIER"
