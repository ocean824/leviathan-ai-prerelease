"""Crash-safe atomic checkpoint and native resume continuity values."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import threading
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator, model_validator

from leviathan_core.numeric import canonical_json
from leviathan_core.seal import Issuer, SealedModel, SealError
from leviathan_core.seal import require as seal_require
from leviathan_market_data.live.wal import RawWalRecordV1, WalError, is_issued_raw_wal_record
from leviathan_market_data.schema import INT64_MAX

_CHECKPOINT_ISSUER = Issuer("md005.checkpoint.v1")
_SINK_COMMIT_ISSUER = Issuer("md005.sink_commit_receipt.v1")
_POSITION_ISSUER = Issuer("md005.native_resume_position.v1")
_GAP_ISSUER = Issuer("md005.gap_manifest.v1")
_VERDICT_ISSUER = Issuer("md005.continuity_verdict.v1")
_TOKEN = re.compile(r"[A-Za-z0-9._~-]{1,256}\Z", re.ASCII)
MAX_GAP_RANGES = 1024
MAX_CHECKPOINT_BYTES = 16_384


class CheckpointV1(SealedModel):
    """Checkpoint for the last semantic record committed by the sink."""

    schema_version: Literal["leviathan.wal-checkpoint/1"] = "leviathan.wal-checkpoint/1"
    stream_identity: tuple[str, str, str, str, str]
    session_id: str
    native_sequence: int
    source_record_key: str
    payload_sha256: str
    committed_byte_offset: int
    generation: int

    @field_validator("stream_identity", mode="before")
    @classmethod
    def _identity(cls, value: object) -> tuple[str, str, str, str, str]:
        if (
            type(value) is not tuple
            or len(value) != 5
            or any(
                type(item) is not str
                or not item
                or len(item) > 128
                or item != item.strip()
                or not item.isascii()
                for item in value
            )
        ):
            raise ValueError("INVALID_IDENTITY")
        return value

    @field_validator("session_id", mode="before")
    @classmethod
    def _session(cls, value: object) -> str:
        if (
            type(value) is not str
            or not value
            or len(value) > 128
            or value != value.strip()
            or not value.isascii()
        ):
            raise ValueError("INVALID_TEXT")
        return value

    @field_validator("source_record_key", mode="before")
    @classmethod
    def _source_key(cls, value: object) -> str:
        if (
            type(value) is not str
            or not value
            or len(value) > 512
            or value != value.strip()
            or not value.isascii()
        ):
            raise ValueError("INVALID_TEXT")
        return value

    @field_validator("native_sequence", mode="before")
    @classmethod
    def _sequence(cls, value: object) -> int:
        if type(value) is not int or not 0 <= value <= INT64_MAX:
            raise ValueError("INVALID_SEQUENCE")
        return value

    @field_validator("committed_byte_offset", "generation", mode="before")
    @classmethod
    def _positive_integer(cls, value: object) -> int:
        if type(value) is not int or value < 0 or value > INT64_MAX:
            raise ValueError("INVALID_INTEGER")
        return value

    @field_validator("payload_sha256", mode="before")
    @classmethod
    def _digest(cls, value: object) -> str:
        if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value, re.ASCII) is None:
            raise ValueError("INVALID_DIGEST")
        return value


class SinkCommitReceiptV1(SealedModel):
    """Non-forgeable proof that a downstream sink write completed for one WAL record."""

    schema_version: Literal["leviathan.sink-commit-receipt/1"] = (
        "leviathan.sink-commit-receipt/1"
    )
    record_sha256: str
    byte_offset: int
    frame_size: int
    stream_identity: tuple[str, str, str, str, str]

    @field_validator("record_sha256", mode="before")
    @classmethod
    def _digest(cls, value: object) -> str:
        if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value, re.ASCII) is None:
            raise ValueError("INVALID_DIGEST")
        return value

    @field_validator("byte_offset", "frame_size", mode="before")
    @classmethod
    def _integer(cls, value: object) -> int:
        if type(value) is not int or value < 0 or value > INT64_MAX:
            raise ValueError("INVALID_INTEGER")
        return value

    @field_validator("stream_identity", mode="before")
    @classmethod
    def _identity(cls, value: object) -> tuple[str, str, str, str, str]:
        if (
            type(value) is not tuple
            or len(value) != 5
            or any(type(part) is not str or not part.isascii() for part in value)
        ):
            raise ValueError("INVALID_IDENTITY")
        return value


class NativeResumePositionV1(SealedModel):
    schema_version: Literal["leviathan.native-resume-position/1"] = (
        "leviathan.native-resume-position/1"
    )
    provider_id: str
    session_id: str
    next_sequence: int
    resume_token: str | None = None

    @field_validator("session_id", mode="before")
    @classmethod
    def _session(cls, value: object) -> str:
        if (
            type(value) is not str
            or not value
            or len(value) > 128
            or value != value.strip()
            or not value.isascii()
        ):
            raise ValueError("INVALID_SESSION")
        return value

    @field_validator("provider_id", mode="before")
    @classmethod
    def _provider(cls, value: object) -> str:
        if (
            type(value) is not str
            or not value
            or len(value) > 128
            or value != value.strip()
            or not value.isascii()
        ):
            raise ValueError("INVALID_PROVIDER_ID")
        return value

    @field_validator("next_sequence", mode="before")
    @classmethod
    def _next(cls, value: object) -> int:
        if type(value) is not int or not 0 <= value <= INT64_MAX:
            raise ValueError("INVALID_SEQUENCE")
        return value

    @field_validator("resume_token", mode="before")
    @classmethod
    def _token(cls, value: object) -> str | None:
        if value is not None and (type(value) is not str or _TOKEN.fullmatch(value) is None):
            raise ValueError("INVALID_RESUME_TOKEN")
        return value


class GapManifestV1(SealedModel):
    schema_version: Literal["leviathan.gap-manifest/1"] = "leviathan.gap-manifest/1"
    provider_id: str
    session_id: str
    ranges: tuple[tuple[int, int], ...] = Field(default_factory=tuple)

    @field_validator("session_id", mode="before")
    @classmethod
    def _session(cls, value: object) -> str:
        if type(value) is not str or not value or len(value) > 128 or not value.isascii():
            raise ValueError("INVALID_SESSION")
        return value

    @field_validator("provider_id", mode="before")
    @classmethod
    def _provider(cls, value: object) -> str:
        if (
            type(value) is not str
            or not value
            or len(value) > 128
            or value != value.strip()
            or not value.isascii()
        ):
            raise ValueError("INVALID_PROVIDER_ID")
        return value

    @field_validator("ranges", mode="before")
    @classmethod
    def _ranges(cls, value: object) -> tuple[tuple[int, int], ...]:
        if type(value) is not tuple or len(value) > MAX_GAP_RANGES:
            raise ValueError("INVALID_GAP_MANIFEST")
        previous_end = -1
        result: list[tuple[int, int]] = []
        for pair in value:
            if (
                type(pair) is not tuple
                or len(pair) != 2
                or any(type(item) is not int or not 0 <= item <= INT64_MAX for item in pair)
                or pair[0] >= pair[1]
                or pair[0] < previous_end
            ):
                raise ValueError("INVALID_GAP_MANIFEST")
            result.append(pair)
            previous_end = pair[1]
        return tuple(result)


class ContinuityVerdictV1(SealedModel):
    schema_version: Literal["leviathan.continuity-verdict/1"] = "leviathan.continuity-verdict/1"
    status: Literal[
        "CONTINUOUS",
        "GAP_PRESENT",
        "SESSION_MISMATCH",
        "SEQUENCE_MISMATCH",
        "PROVIDER_MISMATCH",
        "UNKNOWN",
    ]
    live_ready: bool
    committed_sequence: int | None

    @model_validator(mode="after")
    def _ready(self) -> ContinuityVerdictV1:
        if self.live_ready != (self.status == "CONTINUOUS"):
            raise ValueError("INVALID_VERDICT")
        return self


def _issue_native_resume_position(
    *, provider_id: str, session_id: str, next_sequence: int, resume_token: str | None = None
) -> NativeResumePositionV1:
    if resume_token is not None and (
        type(resume_token) is not str or _TOKEN.fullmatch(resume_token) is None
    ):
        raise WalError("INVALID_RESUME_TOKEN")
    try:
        return _POSITION_ISSUER.issue(
            NativeResumePositionV1(
                provider_id=provider_id,
                session_id=session_id,
                next_sequence=next_sequence,
                resume_token=resume_token,
            )
        )
    except (SealError, ValueError, TypeError):
        raise WalError("INVALID_RECORD") from None


def _issue_gap_manifest(
    *, provider_id: str, session_id: str, ranges: tuple[tuple[int, int], ...] = ()
) -> GapManifestV1:
    try:
        return _GAP_ISSUER.issue(
            GapManifestV1(provider_id=provider_id, session_id=session_id, ranges=ranges)
        )
    except (SealError, ValueError, TypeError):
        raise WalError("INVALID_RECORD") from None


def _issue_checkpoint(record: RawWalRecordV1, generation: int) -> CheckpointV1:
    if not is_issued_raw_wal_record(record):
        raise WalError("UNISSUED_VALUE")
    try:
        result = CheckpointV1(
            stream_identity=record.stream_identity,
            session_id=record.session_id,
            native_sequence=record.native_sequence,
            source_record_key=record.source_record_key,
            payload_sha256=record.raw_payload_sha256,
            committed_byte_offset=record.byte_offset + record.frame_size,
            generation=generation,
        )
        return _CHECKPOINT_ISSUER.issue(result)
    except (SealError, ValueError, TypeError):
        raise WalError("INVALID_RECORD") from None


def _issue_sink_commit_receipt(record: RawWalRecordV1) -> SinkCommitReceiptV1:
    try:
        seal_require(record, "md005.raw_wal_record.v1")
    except (SealError, TypeError):
        raise WalError("UNISSUED_VALUE") from None
    try:
        digest = hashlib.sha256(canonical_json(record.model_dump(mode="json"))).hexdigest()
        return _SINK_COMMIT_ISSUER.issue(
            SinkCommitReceiptV1(
                record_sha256=digest,
                byte_offset=record.byte_offset,
                frame_size=record.frame_size,
                stream_identity=record.stream_identity,
            )
        )
    except (SealError, ValueError, TypeError):
        raise WalError("INVALID_RECORD") from None


def _require_sink_commit_receipt(
    record: RawWalRecordV1, receipt: object
) -> None:
    if not isinstance(receipt, SinkCommitReceiptV1):
        raise WalError("UNISSUED_VALUE")
    try:
        seal_require(receipt, _SINK_COMMIT_ISSUER.tag)
    except SealError:
        raise WalError("UNISSUED_VALUE") from None
    expected = hashlib.sha256(canonical_json(record.model_dump(mode="json"))).hexdigest()
    if (
        receipt.record_sha256 != expected
        or receipt.byte_offset != record.byte_offset
        or receipt.frame_size != record.frame_size
        or receipt.stream_identity != record.stream_identity
    ):
        raise WalError("UNISSUED_VALUE")


class AtomicCheckpoint:
    """Single-writer checkpoint persisted by fsync + atomic replace."""

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        fsync_fn: Callable[[int], None] = os.fsync,
        fault_hook: Callable[[str], None] | None = None,
    ) -> None:
        if (
            not isinstance(path, (str, os.PathLike))
            or isinstance(path, bool)
            or not callable(fsync_fn)
            or (fault_hook is not None and not callable(fault_hook))
        ):
            raise WalError("INVALID_POLICY")
        self.path = Path(path)
        self._fsync = fsync_fn
        self._fault_hook = fault_hook
        self._lock = threading.RLock()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def load(self) -> CheckpointV1 | None:
        with self._lock:
            try:
                if self.path.stat().st_size > MAX_CHECKPOINT_BYTES:
                    raise WalError("CHECKPOINT_CORRUPT")
                # The extra byte detects oversize input without allocating the
                # full file; metadata checks alone can race with file growth.
                with self.path.open("rb") as handle:
                    raw = handle.read(MAX_CHECKPOINT_BYTES + 1)
            except FileNotFoundError:
                return None
            except WalError:
                raise
            except Exception:
                raise WalError("DURABILITY_FAILURE") from None
            if len(raw) > MAX_CHECKPOINT_BYTES:
                raise WalError("CHECKPOINT_CORRUPT")
            try:
                envelope = json.loads(raw.decode("ascii"))
                if type(envelope) is not dict or set(envelope) != {"body", "sha256"}:
                    raise ValueError
                body = envelope["body"]
                encoded = canonical_json(body)
                if (
                    envelope["sha256"] != hashlib.sha256(encoded).hexdigest()
                    or canonical_json(envelope) != raw
                ):
                    raise ValueError
                identity = body["stream_identity"]
                if type(identity) is not list:
                    raise ValueError
                body["stream_identity"] = tuple(identity)
                value = CheckpointV1(**body)
                issued = _CHECKPOINT_ISSUER.issue(value)
                return seal_require(issued, _CHECKPOINT_ISSUER.tag)
            except Exception:
                raise WalError("CHECKPOINT_CORRUPT") from None

    def commit(
        self, record: RawWalRecordV1, sink_receipt: SinkCommitReceiptV1 | None = None
    ) -> CheckpointV1:
        with self._lock:
            if not is_issued_raw_wal_record(record):
                raise WalError("UNISSUED_VALUE")
            _require_sink_commit_receipt(record, sink_receipt)
            previous = self.load()
            generation = 1 if previous is None else previous.generation + 1
            candidate = _issue_checkpoint(record, generation)
            if previous is not None:
                seal_require(previous, _CHECKPOINT_ISSUER.tag)
                if previous.stream_identity != candidate.stream_identity:
                    raise WalError("CHECKPOINT_REGRESSION")
                if previous.session_id == candidate.session_id:
                    if (
                        candidate.native_sequence <= previous.native_sequence
                        or candidate.committed_byte_offset <= previous.committed_byte_offset
                    ):
                        raise WalError("CHECKPOINT_REGRESSION")
                elif record.session_transition_from_session_id != previous.session_id:
                    raise WalError("CHECKPOINT_REGRESSION")
            body = candidate.model_dump(mode="json")
            envelope = {"body": body, "sha256": hashlib.sha256(canonical_json(body)).hexdigest()}
            data = canonical_json(envelope)
            if len(data) > MAX_CHECKPOINT_BYTES:
                raise WalError("CHECKPOINT_FAILURE")
            temp_name: str | None = None
            try:
                with tempfile.NamedTemporaryFile(
                    mode="wb",
                    prefix=self.path.name + ".",
                    suffix=".tmp",
                    dir=self.path.parent,
                    delete=False,
                ) as handle:
                    temp_name = handle.name
                    handle.write(data)
                    handle.flush()
                    self._fault("checkpoint.after_temp_write_before_fsync")
                    self._fsync(handle.fileno())
                    self._fault("checkpoint.after_temp_fsync_before_replace")
                os.replace(temp_name, self.path)
                temp_name = None
                self._fault("checkpoint.after_replace_before_directory_fsync")
                self._fsync_directory()
                return candidate
            except Exception:
                if temp_name is not None:
                    with suppress(Exception):
                        Path(temp_name).unlink(missing_ok=True)
                raise WalError("CHECKPOINT_FAILURE") from None

    def _fsync_directory(self) -> None:
        if os.name == "nt":
            return
        fd = os.open(self.path.parent, os.O_RDONLY)
        try:
            self._fsync(fd)
        finally:
            os.close(fd)

    def _fault(self, point: str) -> None:
        if self._fault_hook is not None:
            self._fault_hook(point)


def _reconcile_native_position(
    position: NativeResumePositionV1 | None,
    gaps: GapManifestV1 | None,
    checkpoint: CheckpointV1 | None,
) -> ContinuityVerdictV1:
    """Prove native continuity from an issued position, manifest and committed cursor."""
    status: Literal[
        "UNKNOWN",
        "GAP_PRESENT",
        "SESSION_MISMATCH",
        "SEQUENCE_MISMATCH",
        "PROVIDER_MISMATCH",
        "CONTINUOUS",
    ] = "UNKNOWN"
    committed: int | None = checkpoint.native_sequence if checkpoint is not None else None
    try:
        if not isinstance(position, NativeResumePositionV1) or not isinstance(
            gaps, GapManifestV1
        ):
            raise SealError("SEAL_NOT_ISSUED")
        seal_require(position, _POSITION_ISSUER.tag)
        seal_require(gaps, _GAP_ISSUER.tag)
    except (SealError, TypeError):
        try:
            return _VERDICT_ISSUER.issue(
                ContinuityVerdictV1(
                    status=status,
                    live_ready=False,
                    committed_sequence=committed,
                )
            )
        except (SealError, ValueError, TypeError):
            raise WalError("INVALID_RECORD") from None
    if checkpoint is None:
        status = "UNKNOWN"
    else:
        seal_require(checkpoint, _CHECKPOINT_ISSUER.tag)
        committed = checkpoint.native_sequence
        if (
            position.provider_id != checkpoint.stream_identity[0]
            or gaps.provider_id != checkpoint.stream_identity[0]
        ):
            status = "PROVIDER_MISMATCH"
        elif gaps.ranges:
            status = "GAP_PRESENT"
        elif (
            position.session_id != checkpoint.session_id or gaps.session_id != checkpoint.session_id
        ):
            status = "SESSION_MISMATCH"
        elif position.next_sequence != checkpoint.native_sequence + 1:
            status = "SEQUENCE_MISMATCH"
        else:
            status = "CONTINUOUS"
    try:
        return _VERDICT_ISSUER.issue(
            ContinuityVerdictV1(
                status=status, live_ready=status == "CONTINUOUS", committed_sequence=committed
            )
        )
    except (SealError, ValueError, TypeError):
        raise WalError("INVALID_RECORD") from None


def is_issued_checkpoint(value: object) -> bool:
    return _CHECKPOINT_ISSUER.issued_here(value)


def is_issued_native_resume_position(value: object) -> bool:
    return _POSITION_ISSUER.issued_here(value)


def is_issued_gap_manifest(value: object) -> bool:
    return _GAP_ISSUER.issued_here(value)


def is_issued_continuity_verdict(value: object) -> bool:
    return _VERDICT_ISSUER.issued_here(value)
