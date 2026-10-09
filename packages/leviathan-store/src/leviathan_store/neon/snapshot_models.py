"""Strict, sealed contracts for fake-Neon warm snapshots and replay."""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Iterable
from typing import Literal, Protocol, runtime_checkable

from pydantic import field_validator

from leviathan_core.seal import Issuer, SealedModel

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)
_SCHEMA = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z", re.ASCII)
_SEMANTIC_KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z", re.ASCII)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_INT64_MAX = (1 << 63) - 1

_MANIFEST_ISSUER = Issuer("stor003.snapshot_manifest.v1")
_RECORD_ISSUER = Issuer("stor003.committed_record.v1")
_RECOVERY_ISSUER = Issuer("stor003.recovery_result.v1")


class SnapshotRecoveryError(ValueError):
    """Content-free error raised at the snapshot/recovery boundary."""

    _CODES = frozenset(
        {
            "INVALID_IDENTITY",
            "INVALID_SCHEMA",
            "INVALID_BYTES",
            "INVALID_DIGEST",
            "INVALID_OFFSET",
            "INVALID_WATERMARK",
            "INVALID_LINEAGE",
            "INVALID_POLICY",
            "INVALID_FAILPOINT",
            "SNAPSHOT_NOT_FOUND",
            "SNAPSHOT_INTERRUPTED",
            "SNAPSHOT_CORRUPT",
            "SNAPSHOT_CONFLICT",
            "SNAPSHOT_STALE",
            "SNAPSHOT_SCHEMA_MISMATCH",
            "OFFSET_UNCOMMITTED",
            "OFFSET_MISMATCH",
            "WAL_GAP",
            "WAL_REORDERED",
            "WAL_SCOPE_MISMATCH",
            "WAL_CONFLICT",
            "WAL_LIMIT_EXCEEDED",
            "WATERMARK_MISMATCH",
            "FRESHNESS_BLOCKED",
            "REPLAY_PORT_FAILURE",
            "INVALID_REPLAY_RECORD",
            "INVALID_REPLAY_OUTPUT",
        }
    )

    def __init__(self, code: str) -> None:
        safe_code = code if type(code) is str and code in self._CODES else "INVALID_POLICY"
        self.code = safe_code
        super().__init__(safe_code)


def _identifier(value: object, code: str = "INVALID_IDENTITY") -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise SnapshotRecoveryError(code)
    return value


def _schema(value: object) -> str:
    if type(value) is not str or _SCHEMA.fullmatch(value) is None:
        raise SnapshotRecoveryError("INVALID_SCHEMA")
    return value


def _semantic_key(value: object) -> str:
    if type(value) is not str or _SEMANTIC_KEY.fullmatch(value) is None:
        raise SnapshotRecoveryError("INVALID_REPLAY_RECORD")
    return value


def _offset(value: object) -> int:
    if type(value) is not int or not 0 <= value <= _INT64_MAX:
        raise SnapshotRecoveryError("INVALID_OFFSET")
    return value


def _watermark(value: object) -> int:
    if type(value) is not int or not 0 <= value <= _INT64_MAX:
        raise SnapshotRecoveryError("INVALID_WATERMARK")
    return value


def _lineage(value: object) -> tuple[str, ...]:
    if type(value) is not tuple or not value or len(value) > 64:
        raise SnapshotRecoveryError("INVALID_LINEAGE")
    return tuple(_identifier(part, "INVALID_LINEAGE") for part in value)


def _encode_bytes(value: object, code: str) -> str:
    if type(value) is not bytes:
        raise SnapshotRecoveryError(code)
    return base64.b64encode(value).decode("ascii")


def _decode_bytes(value: object, code: str) -> bytes:
    if type(value) is not str:
        raise SnapshotRecoveryError(code)
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error):
        raise SnapshotRecoveryError(code) from None
    if base64.b64encode(raw).decode("ascii") != value:
        raise SnapshotRecoveryError(code)
    return raw


class SnapshotManifestV1(SealedModel):
    """Published snapshot identity; the manifest is issued only after read-back."""

    schema_version: Literal["leviathan.snapshot-manifest/1"] = "leviathan.snapshot-manifest/1"
    scope_id: str
    instrument_id: str
    state_schema: str
    source_event_offset: int
    committed_wal_offset: int
    watermark_utc_ns: int
    byte_length: int
    sha256_digest: str
    created_utc_ns: int
    lineage: tuple[str, ...]
    snapshot_id: str

    @field_validator("scope_id", "instrument_id", "snapshot_id", mode="before")
    @classmethod
    def _valid_identifier(cls, value: object) -> str:
        return _identifier(value)

    @field_validator("state_schema", mode="before")
    @classmethod
    def _valid_schema(cls, value: object) -> str:
        return _schema(value)

    @field_validator("source_event_offset", "committed_wal_offset", mode="before")
    @classmethod
    def _valid_offset(cls, value: object) -> int:
        return _offset(value)

    @field_validator("watermark_utc_ns", "created_utc_ns", mode="before")
    @classmethod
    def _valid_time(cls, value: object) -> int:
        return _watermark(value)

    @field_validator("byte_length", mode="before")
    @classmethod
    def _valid_length(cls, value: object) -> int:
        if type(value) is not int or not 0 <= value <= _INT64_MAX:
            raise ValueError("INVALID_BYTES")
        return value

    @field_validator("sha256_digest", mode="before")
    @classmethod
    def _valid_digest(cls, value: object) -> str:
        if type(value) is not str or _SHA256.fullmatch(value) is None:
            raise ValueError("INVALID_DIGEST")
        return value

    @field_validator("lineage", mode="before")
    @classmethod
    def _valid_lineage(cls, value: object) -> tuple[str, ...]:
        return _lineage(value)


class CommittedRecordV1(SealedModel):
    """One committed, scoped WAL record supplied by an injected replay port."""

    schema_version: Literal["leviathan.committed-record/1"] = "leviathan.committed-record/1"
    scope_id: str
    instrument_id: str
    committed_offset: int
    source_event_offset: int
    semantic_key: str
    payload_base64: str
    watermark_utc_ns: int

    @field_validator("scope_id", "instrument_id", mode="before")
    @classmethod
    def _valid_identifier(cls, value: object) -> str:
        return _identifier(value)

    @field_validator("semantic_key", mode="before")
    @classmethod
    def _valid_semantic_key(cls, value: object) -> str:
        return _semantic_key(value)

    @field_validator("source_event_offset", mode="before")
    @classmethod
    def _valid_offset(cls, value: object) -> int:
        return _offset(value)

    @field_validator("committed_offset", mode="before")
    @classmethod
    def _valid_committed_offset(cls, value: object) -> int:
        if type(value) is not int or not 1 <= value <= _INT64_MAX:
            raise ValueError("INVALID_OFFSET")
        return value

    @field_validator("watermark_utc_ns", mode="before")
    @classmethod
    def _valid_watermark(cls, value: object) -> int:
        return _watermark(value)

    @field_validator("payload_base64", mode="before")
    @classmethod
    def _valid_payload(cls, value: object) -> str:
        if type(value) is not str:
            raise ValueError("INVALID_BYTES")
        _decode_bytes(value, "INVALID_BYTES")
        return value

    @property
    def payload(self) -> bytes:
        return _decode_bytes(self.payload_base64, "INVALID_BYTES")


class SnapshotRecoveryResultV1(SealedModel):
    """Immutable recovered bytes and a fail-closed publication decision."""

    schema_version: Literal["leviathan.snapshot-recovery/1"] = "leviathan.snapshot-recovery/1"
    scope_id: str
    instrument_id: str
    status: Literal["HEALTHY", "DEGRADED"]
    traffic_allowed: bool
    snapshot_id: str | None
    state_schema: str
    state_bytes_base64: str
    source_event_offset: int
    committed_wal_offset: int
    watermark_utc_ns: int
    used_snapshot: bool
    used_warm_read: bool
    replayed_count: int
    duplicate_count: int
    reason_codes: tuple[str, ...]

    @field_validator("scope_id", "instrument_id", mode="before")
    @classmethod
    def _valid_identifier(cls, value: object) -> str:
        return _identifier(value)

    @field_validator("state_schema", mode="before")
    @classmethod
    def _valid_schema(cls, value: object) -> str:
        return _schema(value)

    @field_validator("snapshot_id", mode="before")
    @classmethod
    def _valid_snapshot_id(cls, value: object) -> str | None:
        return None if value is None else _identifier(value)

    @field_validator("state_bytes_base64", mode="before")
    @classmethod
    def _valid_state(cls, value: object) -> str:
        if type(value) is not str:
            raise ValueError("INVALID_BYTES")
        _decode_bytes(value, "INVALID_BYTES")
        return value

    @property
    def state_bytes(self) -> bytes:
        return _decode_bytes(self.state_bytes_base64, "INVALID_BYTES")

    @field_validator(
        "source_event_offset",
        "committed_wal_offset",
        "watermark_utc_ns",
        "replayed_count",
        "duplicate_count",
        mode="before",
    )
    @classmethod
    def _valid_nonnegative_int(cls, value: object) -> int:
        if type(value) is not int or not 0 <= value <= _INT64_MAX:
            raise ValueError("INVALID_OFFSET")
        return value

    @field_validator("traffic_allowed", "used_snapshot", "used_warm_read", mode="before")
    @classmethod
    def _valid_bool(cls, value: object) -> bool:
        if type(value) is not bool:
            raise ValueError("INVALID_POLICY")
        return value

    @field_validator("reason_codes", mode="before")
    @classmethod
    def _valid_reasons(cls, value: object) -> tuple[str, ...]:
        if type(value) is not tuple or len(value) > 8:
            raise ValueError("INVALID_POLICY")
        return tuple(_identifier(item, "INVALID_POLICY") for item in value)

    def model_post_init(self, __context: object) -> None:
        if self.status == "HEALTHY":
            if not self.traffic_allowed or self.used_warm_read or self.reason_codes:
                raise ValueError("INVALID_POLICY")
        elif self.traffic_allowed or not self.reason_codes:
            raise ValueError("INVALID_POLICY")


def make_committed_record(
    *,
    scope_id: str,
    instrument_id: str,
    committed_offset: int,
    source_event_offset: int,
    semantic_key: str,
    payload: bytes,
    watermark_utc_ns: int,
) -> CommittedRecordV1:
    """Issue a content-validated record for a CommittedReplayPort implementation."""
    try:
        record = CommittedRecordV1(
            scope_id=scope_id,
            instrument_id=instrument_id,
            committed_offset=committed_offset,
            source_event_offset=source_event_offset,
            semantic_key=semantic_key,
            payload_base64=_encode_bytes(payload, "INVALID_BYTES"),
            watermark_utc_ns=watermark_utc_ns,
        )
        return _RECORD_ISSUER.issue(record)
    except Exception:
        raise SnapshotRecoveryError("INVALID_REPLAY_RECORD") from None


def _issue_snapshot_manifest(**values: object) -> SnapshotManifestV1:
    try:
        return _MANIFEST_ISSUER.issue(SnapshotManifestV1(**values))  # type: ignore[arg-type]
    except Exception:
        raise SnapshotRecoveryError("SNAPSHOT_CORRUPT") from None


def _issue_recovery_result(**values: object) -> SnapshotRecoveryResultV1:
    try:
        return _RECOVERY_ISSUER.issue(SnapshotRecoveryResultV1(**values))  # type: ignore[arg-type]
    except Exception:
        raise SnapshotRecoveryError("INVALID_POLICY") from None


@runtime_checkable
class CommittedReplayPort(Protocol):
    """Local adapter boundary; implementations return committed rows only."""

    def committed_through(self, *, scope_id: str, instrument_id: str) -> int:
        """Return the highest committed offset for this exact scope and instrument."""

    def read_committed(
        self,
        *,
        scope_id: str,
        instrument_id: str,
        after_offset: int,
        through_offset: int,
    ) -> Iterable[CommittedRecordV1]:
        """Yield committed records in offset order, excluding after and including through."""


__all__ = [
    "CommittedRecordV1",
    "CommittedReplayPort",
    "SnapshotManifestV1",
    "SnapshotRecoveryError",
    "SnapshotRecoveryResultV1",
    "make_committed_record",
]
