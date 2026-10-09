"""Approved text-only Titan X preset adapters."""

from __future__ import annotations

from collections.abc import Mapping

from .mt_set_import import (
    InstrumentMappingV1,
    ParameterSpecV1,
    PlatformV1,
    SetImportMetadataV1,
    SetPresetV1,
    TimezoneMappingV1,
    parse_mt_set,
    source_locator_path,
)


def import_titan_x_preset(
    raw_set: bytes,
    *,
    source_path: str,
    preset_id: str,
    preset_version: str,
    platform: PlatformV1,
    schema: Mapping[str, ParameterSpecV1],
    instrument_mapping: InstrumentMappingV1,
    timezone_mapping: TimezoneMappingV1,
    license_reference: str | None = None,
) -> SetPresetV1:
    """Parse one explicitly selected Titan X SET file's bytes."""

    locator = source_locator_path(source_path, family="TITAN_X")
    metadata = SetImportMetadataV1(
        preset_id=preset_id,
        preset_version=preset_version,
        platform=platform,
        source_family="TITAN_X",
        source_locator=locator,
        instrument_mapping=instrument_mapping,
        timezone_mapping=timezone_mapping,
        license_status="TASK_AUTHORIZED",
        license_reference=license_reference,
    )
    return parse_mt_set(raw_set, schema=schema, metadata=metadata)
