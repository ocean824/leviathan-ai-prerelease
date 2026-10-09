"""Independent contract acceptance for MT4/MT5 preset import.

Fixtures are short synthetic .set text bytes. The suite does not read, extract,
or execute source archives or binary assets.
"""

from __future__ import annotations

import hashlib
from decimal import Decimal

import pytest

from leviathan_core.strategy_ingest.presets.kinno_presets import import_kinno_preset
from leviathan_core.strategy_ingest.presets.mt_set_import import (
    InstrumentMappingV1,
    MtSetImportError,
    ParameterSpecV1,
    SetImportMetadataV1,
    TimezoneMappingV1,
    parse_mt_set,
    validated_hosting_material,
)
from leviathan_core.strategy_ingest.presets.titan_x_presets import import_titan_x_preset

SCHEMA = {
    "Lots": ParameterSpecV1(value_type="decimal", unit="lots"),
    "Enabled": ParameterSpecV1(value_type="boolean", unit="flag"),
    "Count": ParameterSpecV1(value_type="integer", unit="bars"),
    "Label": ParameterSpecV1(value_type="string", unit="label"),
    "RiskCap": ParameterSpecV1(value_type="decimal", unit="fraction"),
}

TEXT = (
    "; synthetic acceptance fixture\r\n"
    "Lots=1.25||0.25||0.25||5.00||Y\r\n"
    "Enabled=true||false||true||true||N\r\n"
    "Count=12||1||1||100||Y\n"
    "Label=sample preset||ignored||ignored||ignored||N\n"
    "RiskCap=0.075||0.01||0.005||0.25||Y\n"
    "hint1=Display section\n"
)
UTF8_SET = TEXT.encode("utf-8")
UTF16_SET = b"\xff\xfe" + TEXT.encode("utf-16-le")
UTF16_BE_SET = b"\xfe\xff" + TEXT.encode("utf-16-be")


def metadata(**overrides: object) -> SetImportMetadataV1:
    fields: dict[str, object] = {
        "preset_id": "synthetic-mt5-demo",
        "preset_version": "1.0.0",
        "platform": "MT5",
        "source_family": "GENERIC",
        "source_locator": "SYNTHETIC/acceptance.set",
        "instrument_mapping": InstrumentMappingV1(
            source_symbol="EURUSD",
            instrument_id="FX.EURUSD.SIM",
            mapping_version="map-v1",
        ),
        "timezone_mapping": TimezoneMappingV1(
            source_timezone="EET",
            iana_timezone="Europe/Helsinki",
            mapping_version="tz-v1",
        ),
        "license_status": "TASK_AUTHORIZED",
        "license_reference": "synthetic-license-ref",
    }
    fields.update(overrides)
    return SetImportMetadataV1(**fields)  # type: ignore[arg-type]


def parse(raw_set: bytes = UTF8_SET, *, schema=SCHEMA, source_metadata=None):
    return parse_mt_set(raw_set, schema=schema, metadata=source_metadata or metadata())


def assert_content_free(error: MtSetImportError, code: str, secret: str) -> None:
    assert error.code == code
    assert str(error) == code
    assert secret not in str(error)
    assert secret not in repr(error)


@pytest.mark.parametrize(
    "raw_set", [UTF8_SET, UTF16_SET, UTF16_BE_SET], ids=["utf8", "utf16le-bom", "utf16be-bom"]
)
def test_parses_utf8_and_utf16_with_typed_values_optimization_and_hint_lines(
    raw_set: bytes,
) -> None:
    preset = parse(raw_set)

    assert preset.values == {
        "Lots": Decimal("1.25"),
        "Enabled": True,
        "Count": 12,
        "Label": "sample preset",
        "RiskCap": Decimal("0.075"),
    }
    assert preset.units == {
        "Lots": "lots",
        "Enabled": "flag",
        "Count": "bars",
        "Label": "label",
        "RiskCap": "fraction",
    }
    bounds = preset.parameters["Lots"].optimization
    assert bounds is not None
    assert (bounds.start, bounds.step, bounds.stop, bounds.enabled) == (
        "0.25",
        "0.25",
        "5.00",
        True,
    )
    assert preset.parameters["Enabled"].optimization is not None
    assert preset.parameters["Enabled"].optimization.enabled is False
    assert "hint1" not in preset.parameters
    assert preset.timezone_mapping == metadata().timezone_mapping
    assert preset.instrument_mapping == metadata().instrument_mapping


def test_digest_and_hosting_material_preserve_exact_original_bytes_with_sovereign_values_last() -> (
    None
):
    preset = parse(UTF16_SET)
    expected_digest = hashlib.sha256(UTF16_SET).hexdigest()
    material = validated_hosting_material(
        preset,
        sovereign_risk_overrides={"Lots": Decimal("0.50"), "RiskCap": Decimal("0.02")},
    )

    assert preset.original_set_bytes == UTF16_SET
    assert preset.original_sha256 == expected_digest
    assert material.original_set_bytes == UTF16_SET
    assert material.original_sha256 == expected_digest
    assert material.effective_values["Lots"] == Decimal("0.50")
    assert material.effective_values["RiskCap"] == Decimal("0.02")
    assert material.effective_values["Enabled"] is True
    assert material.sovereign_override_names == ("Lots", "RiskCap")
    assert not hasattr(preset, "execute")
    assert not callable(material)


@pytest.mark.parametrize(
    ("raw_set", "code", "secret"),
    [
        (b"Lots=1\nlots=2\n", "DUPLICATE_FIELD", "2"),
        (b"Lots=1\nprivate_secret=canary\n", "UNKNOWN_FIELD", "canary"),
    ],
)
def test_duplicate_and_unknown_fields_reject_without_echo(
    raw_set: bytes, code: str, secret: str
) -> None:
    with pytest.raises(MtSetImportError) as caught:
        parse(raw_set)
    assert_content_free(caught.value, code, secret)


def test_excessive_declared_fields_reject_with_content_free_code() -> None:
    schema = {
        f"field_{index}": ParameterSpecV1(value_type="integer", unit="count")
        for index in range(513)
    }
    raw_set = "field_0=1\n".encode("ascii")

    with pytest.raises(MtSetImportError) as caught:
        parse(raw_set, schema=schema)
    assert caught.value.code == "INVALID_SCHEMA"
    assert str(caught.value) == "INVALID_SCHEMA"
    assert "field_512" not in repr(caught.value)


def test_unresolved_timezone_is_explicit_and_not_inferred() -> None:
    unresolved = TimezoneMappingV1(
        source_timezone=None,
        iana_timezone=None,
        mapping_version="tz-unresolved-v1",
    )
    preset = parse(source_metadata=metadata(timezone_mapping=unresolved))

    assert preset.timezone_mapping.source_timezone is None
    assert preset.timezone_mapping.iana_timezone is None
    assert preset.timezone_mapping.mapping_version == "tz-unresolved-v1"


@pytest.mark.parametrize(
    ("overrides", "code"),
    [
        ({"UnknownRiskField": 1}, "UNKNOWN_SOVEREIGN_OVERRIDE"),
        ({"Lots": 1}, "INVALID_SOVEREIGN_OVERRIDE"),
        ({"Enabled": 1}, "INVALID_SOVEREIGN_OVERRIDE"),
    ],
)
def test_invalid_sovereign_overrides_reject_without_returning_hosting_material(
    overrides: dict[str, object], code: str
) -> None:
    preset = parse()
    with pytest.raises(MtSetImportError) as caught:
        validated_hosting_material(preset, sovereign_risk_overrides=overrides)  # type: ignore[arg-type]
    assert caught.value.code == code
    assert str(caught.value) == code


def test_source_wrappers_bind_family_platform_locator_license_and_mappings() -> None:
    kinno = import_kinno_preset(
        UTF8_SET,
        member_path="KINNOBOT/EURUSD Q3.set",
        preset_version="2.1.0",
        schema=SCHEMA,
        instrument_mapping=metadata().instrument_mapping,
        timezone_mapping=metadata().timezone_mapping,
        license_reference="synthetic-authorized-source",
    )
    titan = import_titan_x_preset(
        UTF16_SET,
        source_path="TITAN X RESOURCES/EAS/SETFILES/synthetic.set",
        preset_id="synthetic-titan",
        preset_version="3.0.0",
        platform="MT4",
        schema=SCHEMA,
        instrument_mapping=metadata().instrument_mapping,
        timezone_mapping=metadata().timezone_mapping,
        license_reference="synthetic-authorized-source",
    )

    assert (kinno.preset_id, kinno.platform, kinno.source_family) == (
        "eurusd-q3",
        "MT5",
        "KINNOBOT",
    )
    assert kinno.source_locator == "KINNOBOT.zip!KINNOBOT/EURUSD Q3.set"
    assert kinno.license_status == "TASK_AUTHORIZED"
    assert kinno.license_reference == "synthetic-authorized-source"
    assert kinno.instrument_mapping.instrument_id == "FX.EURUSD.SIM"
    assert kinno.timezone_mapping.iana_timezone == "Europe/Helsinki"
    assert (titan.preset_id, titan.platform, titan.source_family) == (
        "synthetic-titan",
        "MT4",
        "TITAN_X",
    )
    assert titan.source_locator == "TITAN X RESOURCES/EAS/SETFILES/synthetic.set"
    assert titan.original_set_bytes == UTF16_SET
    assert titan.original_sha256 == hashlib.sha256(UTF16_SET).hexdigest()


@pytest.mark.parametrize(
    "kwargs",
    [
        {"member_path": "KINNOBOT/../secret.set"},
        {"member_path": "KINNOBOT/not-approved.set"},
    ],
)
def test_kinno_wrapper_rejects_unapproved_or_traversing_member_paths(
    kwargs: dict[str, str],
) -> None:
    with pytest.raises(MtSetImportError) as caught:
        import_kinno_preset(
            UTF8_SET,
            member_path=kwargs["member_path"],
            preset_version="1.0.0",
            schema=SCHEMA,
            instrument_mapping=metadata().instrument_mapping,
            timezone_mapping=metadata().timezone_mapping,
        )
    assert caught.value.code == "INVALID_SOURCE_LOCATOR"
    assert str(caught.value) == "INVALID_SOURCE_LOCATOR"
