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
    "Enabled": ParameterSpecV1(value_type="boolean", unit="flag"),
    "Lots": ParameterSpecV1(value_type="decimal", unit="lots"),
    "Count": ParameterSpecV1(value_type="integer", unit="trades"),
    "Label": ParameterSpecV1(value_type="string", unit="text"),
}
INSTRUMENT = InstrumentMappingV1(
    source_symbol="EURUSD", instrument_id="FX.EURUSD", mapping_version="map-v1"
)
TIMEZONE = TimezoneMappingV1(
    source_timezone="broker-server",
    iana_timezone="Etc/UTC",
    mapping_version="tz-v1",
)


def _metadata() -> SetImportMetadataV1:
    return SetImportMetadataV1(
        preset_id="sample",
        preset_version="1.0",
        platform="MT4",
        source_family="GENERIC",
        source_locator="fixture/sample.set",
        instrument_mapping=INSTRUMENT,
        timezone_mapping=TIMEZONE,
        license_status="UNVERIFIED",
    )


def _parse(text: str, *, encoding: str = "utf-8"):
    return parse_mt_set(text.encode(encoding), schema=SCHEMA, metadata=_metadata())


def test_utf8_and_optimization_suffix_preserve_original_bytes_and_units() -> None:
    raw = b"Enabled=true||false||0||true||N\r\nLots=0.25||0.1||0.05||1||Y\r\n"
    preset = parse_mt_set(raw, schema=SCHEMA, metadata=_metadata())

    assert preset.original_set_bytes is raw
    assert preset.original_sha256 == hashlib.sha256(raw).hexdigest()
    assert preset.values == {"Enabled": True, "Lots": Decimal("0.25")}
    assert preset.units == {"Enabled": "flag", "Lots": "lots"}
    assert preset.parameters["Lots"].optimization is not None
    assert preset.parameters["Lots"].optimization.start == "0.1"
    assert preset.parameters["Lots"].optimization.enabled is True


@pytest.mark.parametrize("encoding", ["utf-16", "utf-16-le", "utf-16-be"])
def test_utf16_encodings_parse(encoding: str) -> None:
    text = "Count=12\nLabel=alpha"
    if encoding == "utf-16-le":
        raw = b"\xff\xfe" + text.encode(encoding)
    elif encoding == "utf-16-be":
        raw = b"\xfe\xff" + text.encode(encoding)
    else:
        raw = text.encode(encoding)
    assert parse_mt_set(raw, schema=SCHEMA, metadata=_metadata()).values == {
        "Count": 12,
        "Label": "alpha",
    }


def test_titan_hint_rows_are_ignored_but_known_fields_are_typed() -> None:
    preset = import_titan_x_preset(
        b"hint1======BASIC SETTINGS=====\nEnabled=1\nCount=4",
        source_path="TITAN X RESOURCES/EAS/SETFILES/sample.set",
        preset_id="titan-sample",
        preset_version="1.0",
        platform="MT5",
        schema=SCHEMA,
        instrument_mapping=INSTRUMENT,
        timezone_mapping=TIMEZONE,
    )
    assert preset.source_family == "TITAN_X"
    assert preset.values == {"Enabled": True, "Count": 4}


def test_kinno_adapter_records_member_provenance() -> None:
    preset = import_kinno_preset(
        b"Lots=0.02",
        member_path="KINNOBOT/EURUSD Q3.set",
        preset_version="1.2",
        schema=SCHEMA,
        instrument_mapping=INSTRUMENT,
        timezone_mapping=TIMEZONE,
    )
    assert preset.preset_id == "eurusd-q3"
    assert preset.source_locator == "KINNOBOT.zip!KINNOBOT/EURUSD Q3.set"
    assert preset.original_sha256 == hashlib.sha256(b"Lots=0.02").hexdigest()


@pytest.mark.parametrize(
    ("raw", "code"),
    [
        (b"Enabled=true\nenabled=false", "DUPLICATE_FIELD"),
        (b"Unknown=1", "UNKNOWN_FIELD"),
        (b"Enabled=perhaps", "INVALID_VALUE"),
        (b"Lots=1||0||1", "INVALID_OPTIMIZATION_SUFFIX"),
        (b"Enabled=true\x00", "INVALID_SET_TEXT"),
        (b"\xff", "INVALID_ENCODING"),
        (b"", "INVALID_SET_BYTES"),
    ],
)
def test_invalid_text_fails_with_fixed_content_free_code(raw: bytes, code: str) -> None:
    with pytest.raises(MtSetImportError) as error:
        parse_mt_set(raw, schema=SCHEMA, metadata=_metadata())
    assert error.value.code == code
    assert str(error.value) == code
    assert error.value.__cause__ is None


def test_hosting_returns_original_bytes_and_applies_sovereign_risk_last() -> None:
    raw = b"Lots=0.25\nCount=3"
    preset = parse_mt_set(raw, schema=SCHEMA, metadata=_metadata())
    material = validated_hosting_material(
        preset,
        sovereign_risk_overrides={"Lots": Decimal("0.05")},
    )
    assert material.original_set_bytes == raw
    assert material.original_sha256 == hashlib.sha256(raw).hexdigest()
    assert material.effective_values["Lots"] == Decimal("0.05")
    assert material.effective_values["Count"] == 3
    assert material.sovereign_override_names == ("Lots",)
    with pytest.raises(TypeError):
        material.effective_values["Lots"] = Decimal("1")  # type: ignore[index]


@pytest.mark.parametrize(
    ("overrides", "code"),
    [
        ({"Unknown": 1}, "UNKNOWN_SOVEREIGN_OVERRIDE"),
        ({"Lots": 1}, "INVALID_SOVEREIGN_OVERRIDE"),
        ({"Count": True}, "INVALID_SOVEREIGN_OVERRIDE"),
    ],
)
def test_hosting_rejects_unknown_or_wrongly_typed_risk_overrides(
    overrides: dict[str, bool | int | Decimal], code: str
) -> None:
    preset = _parse("Lots=0.25\nCount=3")
    with pytest.raises(MtSetImportError) as error:
        validated_hosting_material(preset, sovereign_risk_overrides=overrides)
    assert error.value.code == code


@pytest.mark.parametrize(
    "path",
    [
        "../secret.set",
        "/absolute/sample.set",
        "TITAN X RESOURCES/../secret.set",
        "TITAN X RESOURCES/sample.exe",
    ],
)
def test_titan_adapter_rejects_out_of_scope_source_paths(path: str) -> None:
    with pytest.raises(MtSetImportError) as error:
        import_titan_x_preset(
            b"Count=1",
            source_path=path,
            preset_id="sample",
            preset_version="1.0",
            platform="MT4",
            schema=SCHEMA,
            instrument_mapping=INSTRUMENT,
            timezone_mapping=TIMEZONE,
        )
    assert error.value.code == "INVALID_SOURCE_LOCATOR"
