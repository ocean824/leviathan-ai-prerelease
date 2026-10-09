"""Independent MTBR-DB-001 acceptance tests derived from wave24-refill §1."""

from decimal import Decimal

import pytest

from leviathan_core.mt_export_bridge_db import (
    ArtifactTypeV1,
    CodegenTemplateV1,
    DefinitionInvariantError,
    ExportJobV1,
    ParameterDefinitionV1,
    ParameterTypeV1,
    PlatformV1,
    ResolvedParameterV1,
    SymbolMapEntryV1,
    validate_export_definitions,
)


def template(
    template_id: str = "template_mt5_a",
    *,
    platform: PlatformV1 = PlatformV1.MT5,
    name: str = "SMA",
    version: str = "1",
) -> CodegenTemplateV1:
    return CodegenTemplateV1(
        template_id=template_id,
        platform=platform,
        name=name,
        version=version,
        artifact_type=ArtifactTypeV1.EA,
    )


def parameter(
    key: str = "period",
    *,
    template_id: str = "template_mt5_a",
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


def resolved(key: str = "period", value: object = 14) -> ResolvedParameterV1:
    return ResolvedParameterV1(key=key, value=value)


def job(
    params: tuple[ResolvedParameterV1, ...] = (resolved(),),
    *,
    template_id: str = "template_mt5_a",
    job_id: str = "job_a",
) -> ExportJobV1:
    return ExportJobV1(
        export_job_id=job_id,
        template_id=template_id,
        params_resolved=params,
    )


def symbol(
    target_id: str = "target_a",
    logical_symbol: str = "EURUSD",
    broker_symbol: str = "EURUSD.a",
) -> SymbolMapEntryV1:
    return SymbolMapEntryV1(
        target_id=target_id,
        logical_symbol=logical_symbol,
        broker_symbol=broker_symbol,
    )


def validate(
    *,
    templates: tuple[CodegenTemplateV1, ...] | None = None,
    parameter_definitions: tuple[ParameterDefinitionV1, ...] | None = None,
    export_jobs: tuple[ExportJobV1, ...] | None = None,
    symbol_maps: tuple[SymbolMapEntryV1, ...] | None = None,
):
    return validate_export_definitions(
        templates=(template(),) if templates is None else templates,
        parameter_definitions=(parameter(),)
        if parameter_definitions is None
        else parameter_definitions,
        export_jobs=(job(),) if export_jobs is None else export_jobs,
        symbol_maps=(symbol(),) if symbol_maps is None else symbol_maps,
    )


def assert_content_free_failure(call, canary: str | None = None) -> None:
    with pytest.raises(DefinitionInvariantError) as caught:
        call()
    error = caught.value
    assert error.code
    assert error.args == (error.code,)
    assert error.codes == tuple(sorted(set(error.codes)))
    assert all(isinstance(code, str) and code for code in error.codes)
    with pytest.raises(DefinitionInvariantError) as repeated:
        call()
    assert (repeated.value.code, repeated.value.codes) == (error.code, error.codes)
    rendered = f"{error!s} {error!r} {error.args!r} {error.codes!r}"
    assert canary is None or canary not in rendered


def test_valid_definitions_allow_cross_platform_template_identity_and_count_only_result():
    result = validate(
        templates=(
            template("template_mt4", platform=PlatformV1.MT4),
            template("template_mt5", platform=PlatformV1.MT5),
        ),
        parameter_definitions=(
            parameter(template_id="template_mt4"),
            parameter(template_id="template_mt5"),
        ),
        export_jobs=(
            job(template_id="template_mt4", job_id="job_mt4"),
            job(template_id="template_mt5", job_id="job_mt5"),
        ),
        symbol_maps=(
            symbol(target_id="target_a", logical_symbol="EURUSD", broker_symbol="EURUSD.a"),
            symbol(target_id="target_b", logical_symbol="EURUSD", broker_symbol="EURUSD"),
        ),
    )

    assert result
    assert (
        result.template_count,
        result.parameter_definition_count,
        result.export_job_count,
        result.symbol_map_count,
    ) == (2, 2, 2, 2)
    assert not any(hasattr(result, field) for field in ("params_resolved", "source", "sql"))


def test_template_name_version_is_unique_within_platform_only():
    assert validate(
        templates=(
            template("mt4", platform=PlatformV1.MT4),
            template("mt5", platform=PlatformV1.MT5),
        ),
        parameter_definitions=(
            parameter(template_id="mt4"),
            parameter(template_id="mt5"),
        ),
        export_jobs=(job(template_id="mt4", job_id="j4"), job(template_id="mt5", job_id="j5")),
    )

    assert_content_free_failure(
        lambda: validate(
            templates=(template("first"), template("second")),
            parameter_definitions=(parameter(template_id="first"),),
            export_jobs=(job(template_id="first"),),
        )
    )
    assert_content_free_failure(
        lambda: validate(
            templates=(template("same_id"), template("same_id", name="other")),
            parameter_definitions=(),
            export_jobs=(),
        )
    )


def test_parameter_definition_identity_is_template_and_key():
    assert validate(
        templates=(template(), template("template_mt4_b", platform=PlatformV1.MT4)),
        parameter_definitions=(
            parameter("period", template_id="template_mt5_a"),
            parameter("period", template_id="template_mt4_b"),
        ),
        export_jobs=(job(),),
    )

    assert_content_free_failure(
        lambda: validate(
            parameter_definitions=(parameter("period"), parameter("period")),
        )
    )
    assert_content_free_failure(
        lambda: validate(
            export_jobs=(job(job_id="duplicate_job"), job(job_id="duplicate_job")),
        )
    )
    assert_content_free_failure(
        lambda: validate(
            export_jobs=(job((resolved("period", 14), resolved("period", 15))),),
        )
    )


def test_export_jobs_must_reference_an_existing_template():
    assert_content_free_failure(
        lambda: validate(export_jobs=(job(template_id="missing_template"),))
    )
    assert_content_free_failure(
        lambda: validate(parameter_definitions=(parameter(template_id="missing_template"),))
    )


def test_definition_records_reject_unknown_fields_without_echoing_values():
    canary = "UNTRUSTED_EXTRA_VALUE_CANARY"
    with pytest.raises(TypeError) as caught:
        CodegenTemplateV1(
            template_id="template_extra",
            platform=PlatformV1.MT5,
            name="SMA",
            version="1",
            artifact_type=ArtifactTypeV1.EA,
            extra_field=canary,
        )
    assert canary not in str(caught.value)


def test_parameter_resolution_enforces_required_type_range_and_enum_rules():
    definitions = (
        parameter("period", minimum=Decimal("2"), maximum=Decimal("20")),
        parameter(
            "mode",
            value_type=ParameterTypeV1.ENUM,
            minimum=None,
            maximum=None,
            enum_values=("close", "typical"),
        ),
    )
    valid_job = job(
        (
            resolved("period", 14),
            resolved("mode", "close"),
        )
    )
    assert validate(parameter_definitions=definitions, export_jobs=(valid_job,))

    invalid_jobs = (
        job((), job_id="missing_required"),
        job((resolved("period", "14"),), job_id="wrong_type"),
        job((resolved("period", 1),), job_id="below_minimum"),
        job((resolved("period", 21),), job_id="above_maximum"),
        job((resolved("period", 14), resolved("mode", "open")), job_id="bad_enum"),
        job((resolved("period", 14), resolved("unknown", "x")), job_id="unknown_key"),
    )
    for invalid_job in invalid_jobs:
        assert_content_free_failure(
            lambda invalid_job=invalid_job: validate(
                parameter_definitions=definitions,
                export_jobs=(invalid_job,),
            )
        )

    typed_definitions = (
        parameter(
            "label",
            value_type=ParameterTypeV1.STRING,
            minimum=None,
            maximum=None,
        ),
        parameter(
            "threshold",
            value_type=ParameterTypeV1.DECIMAL,
            minimum=Decimal("0.1"),
            maximum=Decimal("0.5"),
        ),
        parameter(
            "enabled",
            value_type=ParameterTypeV1.BOOLEAN,
            minimum=None,
            maximum=None,
        ),
    )
    assert validate(
        parameter_definitions=typed_definitions,
        export_jobs=(
            job(
                (
                    resolved("label", "fast"),
                    resolved("threshold", Decimal("0.3000000000000000000001")),
                    resolved("enabled", True),
                )
            ),
        ),
    )
    assert_content_free_failure(
        lambda: validate(
            parameter_definitions=(parameter(),),
            export_jobs=(job((resolved("period", True),)),),
        )
    )
    assert_content_free_failure(
        lambda: validate(
            parameter_definitions=(
                parameter(
                    "threshold",
                    value_type=ParameterTypeV1.DECIMAL,
                    minimum=Decimal("0.1"),
                    maximum=Decimal("0.3"),
                ),
            ),
            export_jobs=(job((resolved("threshold", Decimal("0.3000000000000000000001")),)),),
        )
    )


def test_optional_parameter_may_be_omitted_but_required_parameter_may_not():
    optional_definition = parameter(required=False)
    assert validate(
        parameter_definitions=(optional_definition,),
        export_jobs=(job(()),),
    )
    assert_content_free_failure(lambda: validate(export_jobs=(job(()),)))
    with pytest.raises(DefinitionInvariantError):
        parameter(minimum=Decimal("10"), maximum=Decimal("2"))


@pytest.mark.parametrize(
    ("first", "second"),
    [
        (
            symbol(logical_symbol="EURUSD", broker_symbol="EURUSD.a"),
            symbol(logical_symbol="EURUSD", broker_symbol="EURUSD.x"),
        ),
        (
            symbol(logical_symbol="EURUSD", broker_symbol="EURUSD.a"),
            symbol(logical_symbol="GBPUSD", broker_symbol="EURUSD.a"),
        ),
    ],
)
def test_symbol_mappings_are_unique_for_each_target_by_both_symbol_columns(
    first: SymbolMapEntryV1, second: SymbolMapEntryV1
):
    assert validate(
        symbol_maps=(
            first,
            symbol(
                target_id="target_b",
                logical_symbol=first.logical_symbol,
                broker_symbol=first.broker_symbol,
            ),
        ),
    )
    assert_content_free_failure(lambda: validate(symbol_maps=(first, second)))


def test_symbol_uniqueness_errors_do_not_echo_supplied_canary():
    canary = "ACCOUNT_SYMBOL_CANARY"
    assert_content_free_failure(
        lambda: validate(
            symbol_maps=(
                symbol(logical_symbol=canary),
                symbol(logical_symbol=canary, broker_symbol="different"),
            )
        ),
        canary,
    )
