"""Approved text-only KINNOBOT preset adapters."""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import PurePosixPath

from .mt_set_import import (
    InstrumentMappingV1,
    ParameterSpecV1,
    SetImportMetadataV1,
    SetPresetV1,
    TimezoneMappingV1,
    parse_mt_set,
    source_locator_path,
)


def import_kinno_preset(
    raw_set: bytes,
    *,
    member_path: str,
    preset_version: str,
    schema: Mapping[str, ParameterSpecV1],
    instrument_mapping: InstrumentMappingV1,
    timezone_mapping: TimezoneMappingV1,
    license_reference: str | None = None,
) -> SetPresetV1:
    """Parse one explicitly selected KINNOBOT ZIP member's SET bytes."""

    member = source_locator_path(member_path, family="KINNOBOT")
    stem = PurePosixPath(member).stem.casefold()
    preset_id = re.sub(r"[^a-z0-9_.-]+", "-", stem).strip("-._")
    metadata = SetImportMetadataV1(
        preset_id=preset_id,
        preset_version=preset_version,
        platform="MT5",
        source_family="KINNOBOT",
        source_locator=f"KINNOBOT.zip!{member}",
        instrument_mapping=instrument_mapping,
        timezone_mapping=timezone_mapping,
        license_status="TASK_AUTHORIZED",
        license_reference=license_reference,
    )
    return parse_mt_set(raw_set, schema=schema, metadata=metadata)
