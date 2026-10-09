"""Immutable inputs and issued response shapes for archived knowledge reads."""

from __future__ import annotations

import json
import re
from decimal import Decimal
from typing import Literal

from pydantic import field_validator, model_validator

from leviathan_core.numeric import NumericError, canonical_json
from leviathan_core.seal import SealedModel

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", re.ASCII)
_UUID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    re.ASCII,
)
_CURSOR = re.compile(r"(?:0|[1-9][0-9]{0,17})", re.ASCII)
_TAG = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}", re.ASCII)
_MAX_NS = 253402300799999999999
_MAX_PAYLOAD_BYTES = 65536


class ArchivePolicyError(ValueError):
    """Content-free public policy failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def valid_id(value: object, *, code: str = "INVALID_ID") -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise ArchivePolicyError(code)
    return value


def valid_ns(value: object) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_NS:
        raise ArchivePolicyError("INVALID_TIME")
    return value


def _reject_constant(value: str) -> None:
    raise ArchivePolicyError("INVALID_PAYLOAD")


def load_payload(value: object) -> dict[str, object]:
    """Parse a bounded JSON object without binary-float or nonfinite values."""
    if type(value) is not str:
        raise ArchivePolicyError("INVALID_PAYLOAD")
    try:
        if len(value.encode("utf-8")) > _MAX_PAYLOAD_BYTES:
            raise ArchivePolicyError("INVALID_PAYLOAD")
        parsed = json.loads(value, parse_float=Decimal, parse_constant=_reject_constant)
        if type(parsed) is not dict:
            raise ArchivePolicyError("INVALID_PAYLOAD")
        # NUM-001 checks numeric bounds and canonical serialization. No parsed
        # data is emitted here; policy applies recursive masking before output.
        canonical_json(parsed)
    except (ArchivePolicyError, NumericError):
        raise ArchivePolicyError("INVALID_PAYLOAD") from None
    except (ValueError, TypeError, RecursionError, UnicodeError, OverflowError):
        raise ArchivePolicyError("INVALID_PAYLOAD") from None
    return parsed


class ArchivedQueryV1(SealedModel):
    schema_version: Literal["1"]
    cursor: str | None = None
    limit: int = 50
    source_type: Literal["web", "file", "api", "custom"] | None = None
    created_after_ns: int | None = None
    created_before_ns: int | None = None
    tag: str | None = None
    warnings: tuple[Literal["IGNORED_UNKNOWN_FILTER"], ...] = ()

    @field_validator("cursor")
    @classmethod
    def _cursor(cls, value: str | None) -> str | None:
        if value is not None and _CURSOR.fullmatch(value) is None:
            raise ArchivePolicyError("INVALID_CURSOR")
        return value

    @field_validator("limit")
    @classmethod
    def _limit(cls, value: int) -> int:
        if type(value) is not int or not 1 <= value <= 200:
            raise ArchivePolicyError("INVALID_LIMIT")
        return value

    @field_validator("created_after_ns", "created_before_ns")
    @classmethod
    def _time(cls, value: int | None) -> int | None:
        return None if value is None else valid_ns(value)

    @field_validator("tag")
    @classmethod
    def _tag(cls, value: str | None) -> str | None:
        if value is not None and _TAG.fullmatch(value) is None:
            raise ArchivePolicyError("INVALID_TAG")
        return value

    @model_validator(mode="after")
    def _range(self) -> ArchivedQueryV1:
        if (
            self.created_after_ns is not None
            and self.created_before_ns is not None
            and self.created_after_ns > self.created_before_ns
        ):
            raise ArchivePolicyError("INVALID_TIME_RANGE")
        return self


class ArchivedRecordV1(SealedModel):
    schema_version: Literal["1"]
    org_id: str
    record_id: str
    source_type: Literal["web", "file", "api", "custom"]
    created_at_ns: int
    updated_at_ns: int
    tags: tuple[str, ...]
    payload_json: str
    status: Literal["archived"]

    @field_validator("org_id")
    @classmethod
    def _org(cls, value: str) -> str:
        return valid_id(value, code="INVALID_ORG_ID")

    @field_validator("record_id")
    @classmethod
    def _record_id(cls, value: str) -> str:
        if type(value) is not str or _UUID.fullmatch(value) is None:
            raise ArchivePolicyError("INVALID_RECORD_ID")
        return value

    @field_validator("created_at_ns", "updated_at_ns")
    @classmethod
    def _time(cls, value: int) -> int:
        return valid_ns(value)

    @field_validator("tags")
    @classmethod
    def _tags(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) > 100 or len(value) != len(set(value)):
            raise ArchivePolicyError("INVALID_TAG")
        for tag in value:
            if type(tag) is not str or _TAG.fullmatch(tag) is None:
                raise ArchivePolicyError("INVALID_TAG")
        return value

    @field_validator("payload_json")
    @classmethod
    def _payload(cls, value: str) -> str:
        load_payload(value)
        return value

    @model_validator(mode="after")
    def _ordered_time(self) -> ArchivedRecordV1:
        if self.created_at_ns > self.updated_at_ns:
            raise ArchivePolicyError("INVALID_TIME_RANGE")
        return self


class ArchivedReadDecisionV1(SealedModel):
    schema_version: Literal["1"]
    status_code: Literal[200, 304, 401, 403, 404]
    body_json: str | None
    etag: str | None
    next_cursor: str | None
    warnings: tuple[Literal["IGNORED_UNKNOWN_FILTER"], ...]
    headers: tuple[tuple[str, str], ...]
    record_count: int


class ArchivedWriteDenialV1(SealedModel):
    schema_version: Literal["1"]
    status_code: Literal[410]
    code: Literal["LEGACY_ARCHIVED"]
    body_json: str
    headers: tuple[tuple[str, str], ...]
