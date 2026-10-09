"""Versioned typed records for non-market alternative observations."""

from __future__ import annotations

import re
from typing import Final, Literal

from pydantic import field_validator

from leviathan_market_data.schema import INT64_MAX, MarketDataValueError, MarketModel

_IDENTIFIER: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_UNIT: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z][A-Za-z0-9_%./*-]{0,31}$")
_DIGEST: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")


class AlternativeObservationV1(MarketModel):
    """One alternative-data measurement with explicit timing and lineage."""

    schema_version: Literal["leviathan.alternative-observation/1"] = (
        "leviathan.alternative-observation/1"
    )
    source_id: str
    dataset_id: str
    observation_id: str
    event_time_ns: int
    ingest_time_ns: int
    value: str
    unit: str
    mapping_version: str
    provenance_digest: str
    source_revision: str | None = None

    @field_validator("source_id", "dataset_id", "observation_id")
    @classmethod
    def _identifier(cls, value: str) -> str:
        if not _IDENTIFIER.fullmatch(value):
            raise MarketDataValueError("INVALID_IDENTIFIER")
        return value

    @field_validator("event_time_ns", "ingest_time_ns", mode="before")
    @classmethod
    def _timestamp(cls, value: int) -> int:
        if type(value) is not int or not 0 < value <= INT64_MAX:
            raise MarketDataValueError("INVALID_TIME")
        return value

    @field_validator("value")
    @classmethod
    def _value(cls, value: str) -> str:
        if not value or len(value) > 4096:
            raise MarketDataValueError("INVALID_VALUE")
        return value

    @field_validator("unit")
    @classmethod
    def _unit(cls, value: str) -> str:
        if not _UNIT.fullmatch(value):
            raise MarketDataValueError("INVALID_UNIT")
        return value

    @field_validator("mapping_version")
    @classmethod
    def _mapping_version(cls, value: str) -> str:
        if not _IDENTIFIER.fullmatch(value):
            raise MarketDataValueError("INVALID_MAPPING_VERSION")
        return value

    @field_validator("provenance_digest")
    @classmethod
    def _provenance_digest(cls, value: str) -> str:
        if not _DIGEST.fullmatch(value):
            raise MarketDataValueError("INVALID_PROVENANCE_DIGEST")
        return value

    @field_validator("source_revision")
    @classmethod
    def _source_revision(cls, value: str | None) -> str | None:
        if value is not None and (not value or len(value) > 128):
            raise MarketDataValueError("INVALID_SOURCE_REVISION")
        return value


__all__ = ["AlternativeObservationV1"]
