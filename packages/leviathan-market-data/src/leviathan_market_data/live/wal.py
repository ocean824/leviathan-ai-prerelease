"""Bounded append-only raw market-data WAL with fsync-before-return semantics."""

from __future__ import annotations

import base64
import binascii
import errno
import hashlib
import json
import os
import struct
import threading
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path
from typing import Any, Literal, cast

from pydantic import field_validator, model_validator

from leviathan_core.numeric import canonical_json
from leviathan_core.seal import Issuer, SealedModel, SealError
from leviathan_core.seal import require as seal_require
from leviathan_market_data.schema import INT64_MAX

MAX_RAW_PAYLOAD_BYTES = 1_048_576
MAX_WAL_BYTES = 64 * 1024 * 1024
MAX_WAL_RECORDS = 100_000
MAX_WAL_FRAME_BYTES = 2 * 1024 * 1024
MAX_QUARANTINE_FILES = 128
_MAGIC = b"MDW1"
_TRAILER = b"END1"
_HEADER = struct.Struct(">4sI")
_DIGEST_BYTES = hashlib.sha256().digest_size
_WAL_ISSUER = Issuer("md005.raw_wal_record.v1")
_SESSION_TRANSITION_ISSUER = Issuer("md005.session_transition_evidence.v1")


class WalError(ValueError):
    """Content-free durability and replay boundary failure."""

    _CODES = frozenset(
        {
            "INVALID_POLICY",
            "INVALID_RECORD",
            "PAYLOAD_TOO_LARGE",
            "BACKPRESSURE",
            "DURABILITY_FAILURE",
            "WAL_TAIL_QUARANTINED",
            "WAL_QUARANTINED",
            "WAL_CORRUPT",
            "SOURCE_KEY_CONFLICT",
            "SEQUENCE_GAP",
            "SEQUENCE_REORDER",
            "SESSION_RESET_UNCONFIRMED",
            "SESSION_REORDER",
            "UNKNOWN_CONTINUITY",
            "QUARANTINE_CAPACITY",
            "UNISSUED_VALUE",
            "CHECKPOINT_CORRUPT",
            "CHECKPOINT_REGRESSION",
            "SINK_FAULT",
            "CHECKPOINT_FAILURE",
            "INVALID_RESUME_TOKEN",
        }
    )

    def __init__(self, code: str) -> None:
        self.code = code if type(code) is str and code in self._CODES else "INVALID_RECORD"
        self.acknowledged = False
        self.stop_intake = self.code in {
            "BACKPRESSURE",
            "DURABILITY_FAILURE",
            "WAL_TAIL_QUARANTINED",
            "WAL_QUARANTINED",
            "WAL_CORRUPT",
            "SOURCE_KEY_CONFLICT",
            "SEQUENCE_GAP",
            "SEQUENCE_REORDER",
            "SESSION_RESET_UNCONFIRMED",
            "SESSION_REORDER",
            "UNKNOWN_CONTINUITY",
            "QUARANTINE_CAPACITY",
        }
        super().__init__(self.code)


def _valid_text(value: object, maximum: int) -> bool:
    return (
        type(value) is str
        and 0 < len(value) <= maximum
        and value == value.strip()
        and "\x00" not in value
        and value.isascii()
    )


def _valid_sequence(value: object) -> bool:
    return type(value) is int and 0 <= value <= INT64_MAX


def _decode_payload(value: str) -> bytes:
    maximum_encoded = 4 * ((MAX_RAW_PAYLOAD_BYTES + 2) // 3)
    if type(value) is not str or len(value) > maximum_encoded:
        raise WalError("WAL_CORRUPT")
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError):
        raise WalError("WAL_CORRUPT") from None
    if len(raw) > MAX_RAW_PAYLOAD_BYTES:
        raise WalError("WAL_CORRUPT")
    return raw


class RawWalRecordV1(SealedModel):
    """Issued immutable description of one complete, fsynced raw WAL frame."""

    schema_version: Literal["leviathan.raw-wal-record/1"] = "leviathan.raw-wal-record/1"
    stream_identity: tuple[str, str, str, str, str]
    session_id: str
    source_record_key: str
    native_record_id: str | None
    native_sequence: int
    source_time_ns: int | None
    received_time_ns: int
    session_transition_from_session_id: str | None = None
    raw_payload_b64: str
    raw_payload_sha256: str
    byte_offset: int
    frame_size: int

    @field_validator("stream_identity", mode="before")
    @classmethod
    def _stream(cls, value: object) -> tuple[str, str, str, str, str]:
        if (
            type(value) is not tuple
            or len(value) != 5
            or any(not _valid_text(part, 128) for part in value)
        ):
            raise ValueError("INVALID_STREAM")
        return value

    @field_validator("session_id", mode="before")
    @classmethod
    def _session(cls, value: object) -> str:
        if not _valid_text(value, 128):
            raise ValueError("INVALID_SESSION")
        return cast(str, value)

    @field_validator("source_record_key", mode="before")
    @classmethod
    def _source_key(cls, value: object) -> str:
        if not _valid_text(value, 512):
            raise ValueError("INVALID_SOURCE_KEY")
        return cast(str, value)

    @field_validator("native_record_id", mode="before")
    @classmethod
    def _native_id(cls, value: object) -> str | None:
        if value is not None and not _valid_text(value, 256):
            raise ValueError("INVALID_NATIVE_ID")
        return cast(str | None, value)

    @field_validator("native_sequence", mode="before")
    @classmethod
    def _sequence(cls, value: object) -> int:
        if not _valid_sequence(value):
            raise ValueError("INVALID_SEQUENCE")
        return cast(int, value)

    @field_validator("source_time_ns", mode="before")
    @classmethod
    def _source_time(cls, value: object) -> int | None:
        if value is not None and (type(value) is not int or not 0 < value <= INT64_MAX):
            raise ValueError("INVALID_TIME")
        return value

    @field_validator("received_time_ns", mode="before")
    @classmethod
    def _received_time(cls, value: object) -> int:
        if type(value) is not int or not 0 < value <= INT64_MAX:
            raise ValueError("INVALID_TIME")
        return value

    @field_validator("session_transition_from_session_id", mode="before")
    @classmethod
    def _transition_from(cls, value: object) -> str | None:
        if value is not None and not _valid_text(value, 128):
            raise ValueError("INVALID_SESSION")
        return cast(str | None, value)

    @field_validator("raw_payload_b64", mode="before")
    @classmethod
    def _base64(cls, value: object) -> str:
        if type(value) is not str:
            raise ValueError("INVALID_PAYLOAD")
        payload = _decode_payload(value)
        if base64.b64encode(payload).decode("ascii") != value:
            raise ValueError("INVALID_PAYLOAD")
        return value

    @field_validator("raw_payload_sha256", mode="before")
    @classmethod
    def _payload_digest(cls, value: object) -> str:
        if (
            type(value) is not str
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
        ):
            raise ValueError("INVALID_DIGEST")
        return value

    @field_validator("byte_offset", mode="before")
    @classmethod
    def _offset(cls, value: object) -> int:
        if type(value) is not int or not 0 <= value <= MAX_WAL_BYTES:
            raise ValueError("INVALID_OFFSET")
        return value

    @field_validator("frame_size", mode="before")
    @classmethod
    def _frame_size(cls, value: object) -> int:
        if (
            type(value) is not int
            or not _HEADER.size + _DIGEST_BYTES + len(_TRAILER) <= value <= MAX_WAL_FRAME_BYTES
        ):
            raise ValueError("INVALID_FRAME_SIZE")
        return value

    @model_validator(mode="after")
    def _digest_matches(self) -> RawWalRecordV1:
        if hashlib.sha256(self.raw_payload).hexdigest() != self.raw_payload_sha256:
            raise ValueError("INVALID_PAYLOAD_DIGEST")
        return self

    @property
    def raw_payload(self) -> bytes:
        return _decode_payload(self.raw_payload_b64)


class SessionTransitionEvidenceV1(SealedModel):
    """Adapter-issued proof that a source confirmed a session transition."""

    schema_version: Literal["leviathan.session-transition-evidence/1"] = (
        "leviathan.session-transition-evidence/1"
    )
    provider_id: str
    from_session_id: str
    to_session_id: str

    @field_validator("provider_id", "from_session_id", "to_session_id", mode="before")
    @classmethod
    def _session(cls, value: object) -> str:
        if not _valid_text(value, 128):
            raise ValueError("INVALID_SESSION_OR_PROVIDER")
        return cast(str, value)

    @model_validator(mode="after")
    def _distinct_sessions(self) -> SessionTransitionEvidenceV1:
        if self.from_session_id == self.to_session_id:
            raise ValueError("INVALID_SESSION_TRANSITION")
        return self


def is_issued_session_transition_evidence(value: object) -> bool:
    return _SESSION_TRANSITION_ISSUER.issued_here(value)


def _issue_session_transition_evidence(
    provider_id: str, from_session_id: str, to_session_id: str
) -> SessionTransitionEvidenceV1:
    try:
        return _SESSION_TRANSITION_ISSUER.issue(
            SessionTransitionEvidenceV1(
                provider_id=provider_id,
                from_session_id=from_session_id, to_session_id=to_session_id
            )
        )
    except (SealError, ValueError, TypeError):
        raise WalError("UNKNOWN_CONTINUITY") from None


def is_issued_raw_wal_record(value: object) -> bool:
    return _WAL_ISSUER.issued_here(value)


def _issue_record(**fields: object) -> RawWalRecordV1:
    try:
        return _WAL_ISSUER.issue(RawWalRecordV1(**cast(Any, fields)))
    except (SealError, ValueError, TypeError):
        raise WalError("WAL_CORRUPT") from None


def _record_fields(record: RawWalRecordV1) -> dict[str, object]:
    seal_require(record, _WAL_ISSUER.tag)
    return {
        "schema_version": record.schema_version,
        "stream_identity": record.stream_identity,
        "session_id": record.session_id,
        "source_record_key": record.source_record_key,
        "native_record_id": record.native_record_id,
        "native_sequence": record.native_sequence,
        "source_time_ns": record.source_time_ns,
        "received_time_ns": record.received_time_ns,
        "session_transition_from_session_id": record.session_transition_from_session_id,
        "raw_payload_b64": record.raw_payload_b64,
        "raw_payload_sha256": record.raw_payload_sha256,
        "byte_offset": record.byte_offset,
        "frame_size": record.frame_size,
    }


def _frame_body(fields: dict[str, object]) -> bytes:
    return canonical_json(fields)


def _frame(fields: dict[str, object]) -> bytes:
    body = _frame_body(fields)
    if len(body) > MAX_WAL_FRAME_BYTES:
        raise WalError("PAYLOAD_TOO_LARGE")
    return _HEADER.pack(_MAGIC, len(body)) + body + hashlib.sha256(body).digest() + _TRAILER


class AppendOnlyWal:
    """Single-writer bounded WAL. A returned record means its frame was fsynced."""

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        max_bytes: int = MAX_WAL_BYTES,
        max_records: int = MAX_WAL_RECORDS,
        max_payload_bytes: int = MAX_RAW_PAYLOAD_BYTES,
        fsync_fn: Callable[[int], None] = os.fsync,
        fault_hook: Callable[[str], None] | None = None,
    ) -> None:
        if (
            not isinstance(path, (str, os.PathLike))
            or isinstance(path, bool)
            or type(max_bytes) is not int
            or not 1 <= max_bytes <= MAX_WAL_BYTES
            or type(max_records) is not int
            or not 1 <= max_records <= MAX_WAL_RECORDS
            or type(max_payload_bytes) is not int
            or not 1 <= max_payload_bytes <= MAX_RAW_PAYLOAD_BYTES
            or not callable(fsync_fn)
            or (fault_hook is not None and not callable(fault_hook))
        ):
            raise WalError("INVALID_POLICY")
        self.path = Path(path)
        self._max_bytes = max_bytes
        self._max_records = max_records
        self._max_payload_bytes = max_payload_bytes
        self._fsync = fsync_fn
        self._fault_hook = fault_hook
        self._lock = threading.RLock()
        self._intake_stopped = False
        self._records: list[RawWalRecordV1] = []
        self._keys: dict[tuple[tuple[str, ...], str], RawWalRecordV1] = {}
        self._active_session: str | None = None
        self._active_sequence: int | None = None
        self._sessions: set[str] = set()
        self._stream_identity: tuple[str, str, str, str, str] | None = None
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if not self.path.exists():
                with self.path.open("xb") as handle:
                    handle.flush()
                    os.fsync(handle.fileno())
                self._fsync_directory()
            self._records = list(self._scan())
            self._rebuild_state()
        except WalError as exc:
            if exc.code == "WAL_TAIL_QUARANTINED":
                # Evidence is durable; return a handle that exposes it while all
                # read/write paths remain blocked by the quarantine marker.
                self._intake_stopped = True
            else:
                raise
        except Exception:
            raise WalError("DURABILITY_FAILURE") from None

    @property
    def intake_stopped(self) -> bool:
        return self._intake_stopped

    @property
    def quarantine_paths(self) -> tuple[Path, ...]:
        prefix = f"{self.path.name}.quarantine-"
        return tuple(sorted(p for p in self.path.parent.glob(f"{prefix}*") if p.is_file()))

    def read_all(self) -> tuple[RawWalRecordV1, ...]:
        with self._lock:
            self._ensure_unquarantined()
            records = tuple(self._scan())
            self._validate_records(records, quarantine=True)
            return records

    def append(
        self,
        *,
        stream_identity: tuple[str, str, str, str, str],
        session_id: str,
        source_record_key: str,
        native_record_id: str | None,
        native_sequence: int,
        source_time_ns: int | None,
        received_time_ns: int,
        raw_payload: bytes,
        session_transition_evidence: SessionTransitionEvidenceV1 | None = None,
    ) -> RawWalRecordV1:
        with self._lock:
            if self._intake_stopped:
                raise WalError("BACKPRESSURE")
            self._ensure_unquarantined()
            if native_sequence is None:
                raise WalError("UNKNOWN_CONTINUITY")
            self._validate_input(
                stream_identity,
                session_id,
                source_record_key,
                native_record_id,
                native_sequence,
                source_time_ns,
                received_time_ns,
                raw_payload,
                session_transition_evidence,
            )
            raw_digest = hashlib.sha256(raw_payload).hexdigest()
            key = (stream_identity, source_record_key)
            prior = self._keys.get(key)
            if prior is not None:
                if (
                    prior.raw_payload_sha256 != raw_digest
                    or prior.native_record_id != native_record_id
                    or prior.session_id != session_id
                    or prior.native_sequence != native_sequence
                    or prior.source_time_ns != source_time_ns
                ):
                    self._quarantine_conflict(
                        stream_identity=stream_identity,
                        session_id=session_id,
                        source_record_key=source_record_key,
                        native_record_id=native_record_id,
                        native_sequence=native_sequence,
                        source_time_ns=source_time_ns,
                        received_time_ns=received_time_ns,
                        raw_payload=raw_payload,
                    )
                    raise WalError("SOURCE_KEY_CONFLICT")
                return prior
            if self._stream_identity is not None and stream_identity != self._stream_identity:
                raise WalError("INVALID_RECORD")
            self._validate_order(
                session_id=session_id,
                native_sequence=native_sequence,
                transition_from_session_id=(
                    session_transition_evidence.from_session_id
                    if session_transition_evidence is not None
                    else None
                ),
            )
            current_size = self.path.stat().st_size
            if current_size > self._max_bytes or len(self._records) >= self._max_records:
                self._intake_stopped = True
                raise WalError("BACKPRESSURE")
            fields: dict[str, object] = {
                "schema_version": "leviathan.raw-wal-record/1",
                "stream_identity": stream_identity,
                "session_id": session_id,
                "source_record_key": source_record_key,
                "native_record_id": native_record_id,
                "native_sequence": native_sequence,
                "source_time_ns": source_time_ns,
                "received_time_ns": received_time_ns,
                "session_transition_from_session_id": (
                    session_transition_evidence.from_session_id
                    if session_transition_evidence is not None
                    else None
                ),
                "raw_payload_b64": base64.b64encode(raw_payload).decode("ascii"),
                "raw_payload_sha256": raw_digest,
                "byte_offset": current_size,
                "frame_size": 0,
            }
            encoded = b""
            for _ in range(4):
                encoded = _frame(fields)
                if fields["frame_size"] == len(encoded):
                    break
                fields["frame_size"] = len(encoded)
            encoded = _frame(fields)
            if fields["frame_size"] != len(encoded):
                raise WalError("INVALID_RECORD")
            if len(raw_payload) > self._max_payload_bytes:
                raise WalError("PAYLOAD_TOO_LARGE")
            if current_size + len(encoded) > self._max_bytes:
                self._intake_stopped = True
                raise WalError("BACKPRESSURE")
            fd = -1
            try:
                fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | getattr(os, "O_BINARY", 0))
                view = memoryview(encoded)
                while view:
                    written = os.write(fd, view)
                    if written <= 0:
                        raise OSError(errno.EIO, "write failed")
                    view = view[written:]
                self._fault("wal.after_write_before_fsync")
                self._fsync(fd)
                self._fault("wal.after_fsync_before_ack")
            except OSError as exc:
                self._intake_stopped = True
                if exc.errno in (errno.ENOSPC, getattr(errno, "EDQUOT", -1)):
                    raise WalError("BACKPRESSURE") from None
                raise WalError("DURABILITY_FAILURE") from None
            except Exception:
                self._intake_stopped = True
                raise WalError("DURABILITY_FAILURE") from None
            finally:
                if fd >= 0:
                    os.close(fd)
            record = _issue_record(**fields)
            self._records.append(record)
            self._keys[key] = record
            if self._stream_identity is None:
                self._stream_identity = stream_identity
            self._active_session = session_id
            self._active_sequence = native_sequence
            self._sessions.add(session_id)
            return record

    def _validate_input(
        self,
        stream_identity: object,
        session_id: object,
        source_record_key: object,
        native_record_id: object,
        native_sequence: object,
        source_time_ns: object,
        received_time_ns: object,
        raw_payload: object,
        session_transition_evidence: object,
    ) -> None:
        if (
            type(stream_identity) is not tuple
            or len(stream_identity) != 5
            or any(not _valid_text(value, 128) for value in stream_identity)
            or not _valid_text(session_id, 128)
            or not _valid_text(source_record_key, 512)
            or (native_record_id is not None and not _valid_text(native_record_id, 256))
            or not _valid_sequence(native_sequence)
            or (
                source_time_ns is not None
                and (type(source_time_ns) is not int or not 0 < source_time_ns <= INT64_MAX)
            )
            or type(received_time_ns) is not int
            or not 0 < received_time_ns <= INT64_MAX
            or type(raw_payload) is not bytes
        ):
            raise WalError("INVALID_RECORD")
        if session_transition_evidence is not None:
            if (
                not isinstance(session_transition_evidence, SessionTransitionEvidenceV1)
                or not is_issued_session_transition_evidence(session_transition_evidence)
            ):
                raise WalError("UNKNOWN_CONTINUITY")
            try:
                seal_require(session_transition_evidence, _SESSION_TRANSITION_ISSUER.tag)
            except (SealError, TypeError):
                raise WalError("UNKNOWN_CONTINUITY") from None
            if session_transition_evidence.to_session_id != session_id:
                raise WalError("UNKNOWN_CONTINUITY")
            if session_transition_evidence.provider_id != stream_identity[0]:
                raise WalError("UNKNOWN_CONTINUITY")
        if len(raw_payload) > self._max_payload_bytes:
            raise WalError("PAYLOAD_TOO_LARGE")

    def _validate_order(
        self,
        *,
        session_id: str,
        native_sequence: int,
        transition_from_session_id: str | None,
    ) -> None:
        if self._active_session is None:
            if transition_from_session_id is not None:
                raise WalError("UNKNOWN_CONTINUITY")
            return
        if session_id == self._active_session:
            if transition_from_session_id is not None:
                raise WalError("UNKNOWN_CONTINUITY")
            expected = (self._active_sequence or 0) + 1
            if native_sequence < expected:
                raise WalError("SEQUENCE_REORDER")
            if native_sequence > expected:
                raise WalError("SEQUENCE_GAP")
            return
        if transition_from_session_id != self._active_session:
            raise WalError("SESSION_RESET_UNCONFIRMED")
        if session_id in self._sessions:
            raise WalError("SESSION_REORDER")

    def _rebuild_state(self) -> None:
        self._keys.clear()
        self._sessions.clear()
        self._active_session = None
        self._active_sequence = None
        self._stream_identity = None
        for record in self._records:
            if not is_issued_raw_wal_record(record):
                raise WalError("WAL_CORRUPT")
            key = (record.stream_identity, record.source_record_key)
            prior = self._keys.get(key)
            if prior is not None:
                if (
                    prior.raw_payload_sha256 != record.raw_payload_sha256
                    or prior.native_record_id != record.native_record_id
                    or prior.session_id != record.session_id
                    or prior.native_sequence != record.native_sequence
                    or prior.source_time_ns != record.source_time_ns
                ):
                    self._quarantine_from(record.byte_offset)
                    raise WalError("WAL_TAIL_QUARANTINED")
                continue
            if (
                self._stream_identity is not None
                and record.stream_identity != self._stream_identity
            ):
                self._quarantine_from(record.byte_offset)
                raise WalError("WAL_TAIL_QUARANTINED")
            try:
                self._validate_order(
                    session_id=record.session_id,
                    native_sequence=record.native_sequence,
                    transition_from_session_id=record.session_transition_from_session_id,
                )
            except WalError:
                self._quarantine_from(record.byte_offset)
                raise WalError("WAL_TAIL_QUARANTINED") from None
            self._keys[key] = record
            self._stream_identity = record.stream_identity
            self._active_session = record.session_id
            self._active_sequence = record.native_sequence
            self._sessions.add(record.session_id)
            if len(self._keys) > self._max_records:
                raise WalError("BACKPRESSURE")

    def _scan(self) -> tuple[RawWalRecordV1, ...]:
        self._ensure_unquarantined()
        try:
            if self.path.stat().st_size > self._max_bytes:
                self._intake_stopped = True
                raise WalError("BACKPRESSURE")
            # Read at most one byte beyond the policy cap. stat() alone is not
            # sufficient because another writer could grow the file after it.
            with self.path.open("rb") as handle:
                data = handle.read(self._max_bytes + 1)
        except FileNotFoundError:
            return ()
        except WalError:
            raise
        except Exception:
            raise WalError("DURABILITY_FAILURE") from None
        if len(data) > self._max_bytes:
            self._intake_stopped = True
            raise WalError("BACKPRESSURE")
        records: list[RawWalRecordV1] = []
        offset = 0
        while offset < len(data):
            start = offset
            try:
                if len(data) - offset < _HEADER.size:
                    raise ValueError
                magic, body_size = _HEADER.unpack_from(data, offset)
                offset += _HEADER.size
                if magic != _MAGIC or body_size <= 0 or body_size > MAX_WAL_FRAME_BYTES:
                    raise ValueError
                end_body = offset + body_size
                end_frame = end_body + _DIGEST_BYTES + len(_TRAILER)
                if end_frame > len(data):
                    raise ValueError
                body = data[offset:end_body]
                offset = end_body
                supplied_digest = data[offset : offset + _DIGEST_BYTES]
                offset += _DIGEST_BYTES
                trailer = data[offset : offset + len(_TRAILER)]
                offset += len(_TRAILER)
                if supplied_digest != hashlib.sha256(body).digest() or trailer != _TRAILER:
                    raise ValueError
                obj = json.loads(body.decode("ascii"))
                if type(obj) is not dict or canonical_json(obj) != body:
                    raise ValueError
                expected_fields = {
                    "schema_version",
                    "stream_identity",
                    "session_id",
                    "source_record_key",
                    "native_record_id",
                    "native_sequence",
                    "source_time_ns",
                    "received_time_ns",
                    "session_transition_from_session_id",
                    "raw_payload_b64",
                    "raw_payload_sha256",
                    "byte_offset",
                    "frame_size",
                }
                if (
                    set(obj) != expected_fields
                    or obj["byte_offset"] != start
                    or obj["frame_size"] != end_frame - start
                ):
                    raise ValueError
                stream_identity = obj["stream_identity"]
                if type(stream_identity) is not list:
                    raise ValueError
                obj["stream_identity"] = tuple(stream_identity)
                record = _issue_record(**obj)
                records.append(record)
            except Exception:
                self._quarantine_bytes(start, data[start:])
                raise WalError("WAL_TAIL_QUARANTINED") from None
        return tuple(records)

    def _validate_records(self, records: tuple[RawWalRecordV1, ...], *, quarantine: bool) -> None:
        try:
            self._validate_record_order(records)
        except WalError:
            if quarantine and records:
                bad_offset = records[-1].byte_offset
                self._quarantine_from(bad_offset)
                raise WalError("WAL_TAIL_QUARANTINED") from None
            raise

    def _validate_record_order(self, records: tuple[RawWalRecordV1, ...]) -> None:
        active_session: str | None = None
        active_sequence: int | None = None
        sessions: set[str] = set()
        identities: set[tuple[str, ...]] = set()
        keys: dict[tuple[tuple[str, ...], str], RawWalRecordV1] = {}
        for record in records:
            if not is_issued_raw_wal_record(record):
                raise WalError("WAL_CORRUPT")
            if identities and record.stream_identity not in identities:
                raise WalError("INVALID_RECORD")
            identities.add(record.stream_identity)
            key = (record.stream_identity, record.source_record_key)
            prior = keys.get(key)
            if prior is not None:
                if prior.raw_payload_sha256 != record.raw_payload_sha256:
                    raise WalError("SOURCE_KEY_CONFLICT")
                if (
                    prior.session_id == record.session_id
                    and prior.native_sequence == record.native_sequence
                    and prior.native_record_id == record.native_record_id
                    and prior.source_time_ns == record.source_time_ns
                ):
                    continue
            if active_session is None:
                pass
            elif record.session_id == active_session:
                if record.session_transition_from_session_id is not None:
                    raise WalError("UNKNOWN_CONTINUITY")
                expected = (active_sequence or 0) + 1
                if record.native_sequence < expected:
                    raise WalError("SEQUENCE_REORDER")
                if record.native_sequence > expected:
                    raise WalError("SEQUENCE_GAP")
            else:
                if record.session_transition_from_session_id != active_session:
                    raise WalError("SESSION_RESET_UNCONFIRMED")
                if record.session_id in sessions:
                    raise WalError("SESSION_REORDER")
            keys[key] = record
            active_session = record.session_id
            active_sequence = record.native_sequence
            sessions.add(record.session_id)

    def _quarantine_from(self, offset: int) -> None:
        try:
            with self.path.open("rb") as handle:
                data = handle.read(self._max_bytes + 1)
            if len(data) > self._max_bytes:
                raise WalError("BACKPRESSURE")
        except Exception:
            raise WalError("WAL_CORRUPT") from None
        self._quarantine_bytes(offset, data[offset:])

    def _quarantine_bytes(self, offset: int, suffix: bytes) -> Path:
        if not suffix:
            raise WalError("WAL_CORRUPT")
        digest = hashlib.sha256(suffix).hexdigest()
        target = self.path.with_name(f"{self.path.name}.quarantine-tail-{offset}-{digest}.bin")
        self._write_evidence(target, suffix)
        return target

    def _quarantine_conflict(self, **metadata: object) -> None:
        payload = metadata.get("raw_payload")
        if type(payload) is not bytes:
            raise WalError("INVALID_RECORD")
        key = metadata.get("source_record_key")
        if type(key) is not str:
            raise WalError("INVALID_RECORD")
        evidence = {key: value for key, value in metadata.items() if key != "raw_payload"}
        evidence["raw_payload_b64"] = base64.b64encode(payload).decode("ascii")
        encoded = canonical_json(evidence)
        name_digest = hashlib.sha256(
            key.encode("utf-8") + hashlib.sha256(payload).digest()
        ).hexdigest()
        target = self.path.with_name(f"{self.path.name}.quarantine-conflict-{name_digest}.json")
        self._write_evidence(target, encoded)

    def _write_evidence(self, target: Path, data: bytes) -> None:
        if len(self.quarantine_paths) >= MAX_QUARANTINE_FILES and not target.exists():
            raise WalError("QUARANTINE_CAPACITY")
        if target.exists():
            try:
                if target.stat().st_size <= len(data):
                    with target.open("rb") as handle:
                        if handle.read(len(data) + 1) == data:
                            return
            except Exception:
                pass
            raise WalError("WAL_QUARANTINED")
        temp = target.with_name(target.name + ".tmp")
        try:
            with temp.open("xb") as handle:
                handle.write(data)
                handle.flush()
                self._fsync(handle.fileno())
            os.replace(temp, target)
            self._fsync_directory()
        except FileExistsError:
            raise WalError("WAL_QUARANTINED") from None
        except Exception:
            with suppress(Exception):
                temp.unlink(missing_ok=True)
            raise WalError("DURABILITY_FAILURE") from None

    def _ensure_unquarantined(self) -> None:
        if self.quarantine_paths:
            self._intake_stopped = True
            raise WalError("WAL_QUARANTINED")

    def _fault(self, point: str) -> None:
        if self._fault_hook is not None:
            self._fault_hook(point)

    def _fsync_directory(self) -> None:
        if os.name == "nt":
            return
        fd = os.open(self.path.parent, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
