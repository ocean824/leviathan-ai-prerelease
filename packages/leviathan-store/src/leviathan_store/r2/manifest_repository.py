"""In-memory manifest state machine and lock-gated range restore for fake R2."""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from hashlib import sha256
from typing import BinaryIO, Final, TypeAlias, cast

from pydantic import ConfigDict, field_validator, model_validator

from leviathan_core.numeric import canonical_json
from leviathan_core.seal import Issuer, SealedModel, require
from leviathan_core.seal import digest as seal_digest
from leviathan_core.seal.errors import SealError
from leviathan_store.archive.engine import ArchiveEngine, ArchiveError
from leviathan_store.archive.models import ArchiveManifestV1, ArchiveStatus
from leviathan_store.archive.port import NotFound, ObjectHead

from .archive_port import R2ArchiveError, R2ArchiveObjectPortV1
from .lock_evidence import R2LockEvidenceV1, require_lock_evidence

ManifestKeyV1: TypeAlias = tuple[str, str, str]
_TAG: Final = "stor002.r2_manifest.v1"
_RESTORE_TAG: Final = "stor002.r2_restore.v1"
_ISSUER: Final = Issuer(_TAG)
_RESTORE_ISSUER: Final = Issuer(_RESTORE_TAG)
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)
_UTC_NS_PER_SECOND = 1_000_000_000
_UTC_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_RETENTION_YEARS = 7


class R2ManifestStateV1(StrEnum):
    PENDING = "PENDING"
    COMPLETE = "COMPLETE"
    VERIFIED = "VERIFIED"


class R2ManifestRecordV1(SealedModel):
    """Issued durable-state projection for one ARCH-001 manifest."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    manifest_key: ManifestKeyV1
    manifest_digest: str
    state: R2ManifestStateV1
    created_at: datetime
    completed_at: datetime | None = None
    verified_at: datetime | None = None
    lock_evidence_digest: str | None = None

    @field_validator("manifest_key")
    @classmethod
    def _manifest_key(cls, value: ManifestKeyV1) -> ManifestKeyV1:
        if (
            type(value) is not tuple
            or len(value) != 3
            or any(not isinstance(part, str) or not part for part in value)
        ):
            raise ValueError("INVALID_MANIFEST_KEY")
        return value

    @field_validator("manifest_digest")
    @classmethod
    def _manifest_digest(cls, value: str) -> str:
        if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value, re.ASCII) is None:
            raise ValueError("INVALID_MANIFEST")
        return value

    @field_validator("lock_evidence_digest")
    @classmethod
    def _lock_evidence_digest(cls, value: str | None) -> str | None:
        if value is not None and re.fullmatch(r"[0-9a-f]{64}", value, re.ASCII) is None:
            raise ValueError("INVALID_LOCK_EVIDENCE")
        return value

    @field_validator("created_at", "completed_at", "verified_at")
    @classmethod
    def _utc_datetime(cls, value: datetime | None) -> datetime | None:
        if value is not None and (type(value) is not datetime or value.tzinfo is not UTC):
            raise ValueError("INVALID_UTC_DATETIME")
        return value

    @model_validator(mode="after")
    def _state_shape(self) -> R2ManifestRecordV1:
        if self.state is R2ManifestStateV1.PENDING:
            if any((self.completed_at, self.verified_at, self.lock_evidence_digest)):
                raise ValueError("INVALID_MANIFEST_STATE")
        elif (
            self.state is R2ManifestStateV1.COMPLETE
            and (
                self.completed_at is None
                or self.verified_at is not None
                or self.lock_evidence_digest is not None
            )
        ) or (
            self.state is R2ManifestStateV1.VERIFIED
            and (
                self.completed_at is None
                or self.verified_at is None
                or self.lock_evidence_digest is None
            )
        ):
            raise ValueError("INVALID_MANIFEST_STATE")
        return self


class R2RestoreResultV1(SealedModel):
    """Sealed evidence of one successful, validated range publication."""

    manifest_keys: tuple[ManifestKeyV1, ...]
    bytes_restored: int
    lineage_id: str
    audit_id: str
    committed: bool
    committed_at: datetime

    @field_validator("manifest_keys")
    @classmethod
    def _manifest_keys(cls, value: tuple[ManifestKeyV1, ...]) -> tuple[ManifestKeyV1, ...]:
        if type(value) is not tuple or not value:
            raise ValueError("INVALID_RESTORE_REQUEST")
        for key in value:
            if (
                type(key) is not tuple
                or len(key) != 3
                or any(not isinstance(part, str) or not part for part in key)
            ):
                raise ValueError("INVALID_RESTORE_REQUEST")
        if len(set(value)) != len(value):
            raise ValueError("INVALID_RESTORE_REQUEST")
        return value

    @field_validator("bytes_restored")
    @classmethod
    def _bytes(cls, value: int) -> int:
        if type(value) is not int or value <= 0:
            raise ValueError("INVALID_RESTORE_REQUEST")
        return value

    @field_validator("lineage_id", "audit_id")
    @classmethod
    def _ids(cls, value: str) -> str:
        if not isinstance(value, str) or _ID.fullmatch(value) is None:
            raise ValueError("INVALID_RESTORE_REQUEST")
        return value

    @field_validator("committed")
    @classmethod
    def _committed(cls, value: bool) -> bool:
        if type(value) is not bool:
            raise ValueError("INVALID_RESTORE_REQUEST")
        return value

    @field_validator("committed_at")
    @classmethod
    def _committed_at(cls, value: datetime) -> datetime:
        if type(value) is not datetime or value.tzinfo is not UTC:
            raise ValueError("INVALID_RESTORE_REQUEST")
        return value


def _issue_record(**values: object) -> R2ManifestRecordV1:
    try:
        record = R2ManifestRecordV1.model_validate(values)
        return _ISSUER.issue(record)
    except SealError:
        raise R2ArchiveError("INVALID_MANIFEST") from None


def _issue_restore_result(**values: object) -> R2RestoreResultV1:
    try:
        result = R2RestoreResultV1.model_validate(values)
        return _RESTORE_ISSUER.issue(result)
    except SealError:
        raise R2ArchiveError("INVALID_RESTORE_REQUEST") from None


def _manifest_key(manifest: ArchiveManifestV1) -> ManifestKeyV1:
    return (manifest.dataset_id, manifest.dataset_version, manifest.partition_key)


def _manifest_digest(manifest: ArchiveManifestV1) -> str:
    payload = {
        "dataset_id": manifest.dataset_id,
        "dataset_version": manifest.dataset_version,
        "partition_key": manifest.partition_key,
        "event_start_ns": manifest.event_start_ns,
        "event_end_ns": manifest.event_end_ns,
        "source_schema": manifest.source_schema,
        "byte_length": manifest.byte_length,
        "sha256_digest": manifest.sha256_digest,
        "chunks": [
            {
                "index": chunk.index,
                "object_key": chunk.object_key,
                "byte_length": chunk.byte_length,
                "sha256_digest": chunk.sha256_digest,
                "schema_version": chunk.schema_version,
            }
            for chunk in manifest.chunks
        ],
        "created_at": manifest.created_at.isoformat(),
        "creation_provenance": manifest.creation_provenance,
        "retention_policy_id": manifest.retention_policy_id,
        "status": manifest.status.value,
        "failure_reason": manifest.failure_reason,
        "schema_version": manifest.schema_version,
    }
    return sha256(canonical_json(payload)).hexdigest()


def _validate_key(value: object) -> ManifestKeyV1:
    if (
        type(value) is not tuple
        or len(value) != 3
        or any(not isinstance(part, str) or not part for part in value)
    ):
        raise R2ArchiveError("INVALID_MANIFEST_KEY")
    return value


def _seven_years_reached(start_ns: int, end_ns: int) -> bool:
    """Check a seven-calendar-year lock, including exact sub-microsecond ns."""
    try:
        start_us, start_remainder = divmod(start_ns, 1_000)
        start = _UTC_EPOCH + timedelta(microseconds=start_us)
        try:
            target = start.replace(year=start.year + _RETENTION_YEARS)
        except ValueError:  # Feb 29 clamps to Feb 28 in the target year.
            target = start.replace(year=start.year + _RETENTION_YEARS, day=28)
        delta = target - _UTC_EPOCH
        target_ns = (
            (delta.days * 86_400 + delta.seconds) * 1_000_000 + delta.microseconds
        ) * 1_000 + start_remainder
    except (OverflowError, ValueError):
        return False
    return end_ns >= target_ns


def _datetime_to_utc_ns(value: datetime) -> int:
    try:
        utc_value = value.astimezone(UTC)
    except (OverflowError, ValueError):
        raise R2ArchiveError("LOCK_INSUFFICIENT_RETENTION") from None
    delta = utc_value - _UTC_EPOCH
    return (
        (delta.days * 86_400 + delta.seconds) * _UTC_NS_PER_SECOND
        + delta.microseconds * 1_000
    )


def _retention_horizon_ns(archive_at: datetime) -> int:
    try:
        utc_value = archive_at.astimezone(UTC)
        try:
            target = utc_value.replace(year=utc_value.year + _RETENTION_YEARS)
        except ValueError:  # Clamp a leap-day archive to February 28.
            target = utc_value.replace(year=utc_value.year + _RETENTION_YEARS, day=28)
    except (OverflowError, ValueError):
        raise R2ArchiveError("LOCK_INSUFFICIENT_RETENTION") from None
    return _datetime_to_utc_ns(target)


def _manifest_archive_horizon_ns(
    record: R2ManifestRecordV1, manifest: ArchiveManifestV1
) -> tuple[int, int]:
    manifest_created_ns = _datetime_to_utc_ns(manifest.created_at)
    archive_registered_ns = _datetime_to_utc_ns(record.created_at)
    archive_at_ns = max(manifest_created_ns, archive_registered_ns)
    archive_at = (
        manifest.created_at.astimezone(UTC)
        if manifest_created_ns >= archive_registered_ns
        else record.created_at
    )
    return archive_at_ns, _retention_horizon_ns(archive_at)


def _same_lock(left: R2LockEvidenceV1, right: R2LockEvidenceV1) -> bool:
    return (
        left.bucket == right.bucket
        and left.prefix == right.prefix
        and left.policy_id == right.policy_id
        and left.manifest_digest == right.manifest_digest
        and left.retention_start_utc_ns == right.retention_start_utc_ns
        and left.retention_end_utc_ns == right.retention_end_utc_ns
        and left.provider_response_digest == right.provider_response_digest
        and left.lifecycle_expiration_utc_ns == right.lifecycle_expiration_utc_ns
        and left.legal_hold is right.legal_hold
    )


class R2ManifestRepositoryV1:
    """Fake repository enforcing PENDING -> COMPLETE -> VERIFIED transitions."""

    def __init__(
        self,
        object_port: R2ArchiveObjectPortV1,
        *,
        clock: Callable[[], datetime],
        clock_ns: Callable[[], int] | None = None,
    ) -> None:
        if (
            type(object_port) is not R2ArchiveObjectPortV1
            or not callable(clock)
            or (clock_ns is not None and not callable(clock_ns))
        ):
            raise R2ArchiveError("INVALID_RESTORE_REQUEST")
        self.object_port = object_port
        self.clock = clock
        self.clock_ns = clock_ns
        self._records: dict[ManifestKeyV1, R2ManifestRecordV1] = {}
        self._manifests: dict[ManifestKeyV1, ArchiveManifestV1] = {}
        self._lock_evidence: dict[ManifestKeyV1, R2LockEvidenceV1] = {}
        self._restore_audit: list[R2RestoreResultV1] = []

    @property
    def restore_audit(self) -> tuple[R2RestoreResultV1, ...]:
        result: list[R2RestoreResultV1] = []
        for item in self._restore_audit:
            try:
                result.append(require(item, _RESTORE_TAG))
            except SealError:
                raise R2ArchiveError("INVALID_RESTORE_RESULT") from None
        return tuple(result)

    def put_pending(self, manifest: ArchiveManifestV1) -> R2ManifestRecordV1:
        if type(manifest) is not ArchiveManifestV1 or manifest.status is not ArchiveStatus.PENDING:
            raise R2ArchiveError("INVALID_MANIFEST")
        key = _manifest_key(manifest)
        existing = self._records.get(key)
        if existing is not None:
            self._require_record(existing)
            if existing.manifest != manifest:
                raise R2ArchiveError("MANIFEST_CONFLICT")
            return existing
        record = _issue_record(
            manifest_key=key,
            manifest_digest=_manifest_digest(manifest),
            state=R2ManifestStateV1.PENDING,
            created_at=self._now(),
        )
        self._records[key] = record
        self._manifests[key] = manifest
        return record

    def mark_complete(self, manifest_key: ManifestKeyV1) -> R2ManifestRecordV1:
        key = _validate_key(manifest_key)
        record = self._get_record(key)
        if record.state is not R2ManifestStateV1.PENDING:
            raise R2ArchiveError("INVALID_STATE_TRANSITION")
        if self.object_port.transport.fail_before_verify:
            raise R2ArchiveError("VERIFY_INTERRUPTED")
        try:
            manifest = self._get_manifest(record)
            verified_manifest = ArchiveEngine(self.object_port, clock=self.clock).verify(manifest)
        except ArchiveError:
            raise R2ArchiveError("OBJECT_INTEGRITY_FAILED") from None
        if verified_manifest.status is not ArchiveStatus.VERIFIED:
            raise R2ArchiveError("OBJECT_INTEGRITY_FAILED")
        completed = _issue_record(
            manifest_key=key,
            manifest_digest=_manifest_digest(verified_manifest),
            state=R2ManifestStateV1.COMPLETE,
            created_at=record.created_at,
            completed_at=self._now(),
        )
        self._records[key] = completed
        self._manifests[key] = verified_manifest
        return completed

    def mark_verified(self, manifest_key: ManifestKeyV1) -> R2ManifestRecordV1:
        key = _validate_key(manifest_key)
        record = self._get_record(key)
        if record.state is not R2ManifestStateV1.COMPLETE:
            raise R2ArchiveError("INVALID_STATE_TRANSITION")
        manifest = self._get_manifest(record)
        if not self._objects_intact(manifest):
            raise R2ArchiveError("OBJECT_INTEGRITY_FAILED")
        evidence = self._read_valid_lock(record, manifest)
        verified = _issue_record(
            manifest_key=key,
            manifest_digest=record.manifest_digest,
            state=R2ManifestStateV1.VERIFIED,
            created_at=record.created_at,
            completed_at=record.completed_at,
            verified_at=self._now(),
            lock_evidence_digest=seal_digest(evidence),
        )
        self._records[key] = verified
        self._lock_evidence[key] = evidence
        return verified

    def get(self, manifest_key: ManifestKeyV1) -> R2ManifestRecordV1 | None:
        key = _validate_key(manifest_key)
        record = self._records.get(key)
        if record is None:
            return None
        return self._require_record(record)

    def prune_eligible(self, manifest_key: ManifestKeyV1) -> bool:
        """Return true only while object bytes and current R2 lock proof still match."""
        try:
            record = self._get_record(_validate_key(manifest_key))
            if record.state is not R2ManifestStateV1.VERIFIED:
                return False
            manifest = self._get_manifest(record)
            if not self._objects_intact(manifest):
                return False
            current = self._read_bound_lock(record, manifest)
            saved = self._get_saved_lock(record)
            _archive_at_ns, retention_end_ns = _manifest_archive_horizon_ns(
                record, manifest
            )
            now_ns = self._now_ns()
            return (
                now_ns > retention_end_ns
                and _same_lock(saved, current)
                and not current.legal_hold
            )
        except Exception:
            return False

    def restore_range(
        self,
        manifest_keys: Sequence[ManifestKeyV1],
        *,
        start_ns: int,
        end_ns: int,
        expected_source_schema: str,
        temporary_destination: BinaryIO,
        atomic_commit: Callable[[BinaryIO], None] | None = None,
        lineage_id: str,
        audit_id: str,
        commit: bool = False,
        overwrite_existing: bool = False,
    ) -> R2RestoreResultV1:
        if (
            not isinstance(manifest_keys, Sequence)
            or isinstance(manifest_keys, (str, bytes))
            or not manifest_keys
            or type(commit) is not bool
            or type(overwrite_existing) is not bool
            or not isinstance(lineage_id, str)
            or _ID.fullmatch(lineage_id) is None
            or not isinstance(audit_id, str)
            or _ID.fullmatch(audit_id) is None
            or (atomic_commit is not None and not callable(atomic_commit))
            or (commit and not callable(atomic_commit))
        ):
            raise R2ArchiveError("INVALID_RESTORE_REQUEST")
        keys = tuple(_validate_key(key) for key in manifest_keys)
        if len(set(keys)) != len(keys):
            raise R2ArchiveError("INVALID_RESTORE_REQUEST")
        records = tuple(self._get_record(key) for key in keys)
        for record in records:
            if record.state is not R2ManifestStateV1.VERIFIED:
                raise R2ArchiveError("MANIFEST_NOT_VERIFIED")
            manifest = self._get_manifest(record)
            if not self._objects_intact(manifest):
                raise R2ArchiveError("OBJECT_INTEGRITY_FAILED")
            current = self._read_bound_lock(record, manifest)
            if not _same_lock(self._get_saved_lock(record), current):
                raise R2ArchiveError("LOCK_EVIDENCE_MISMATCH")
            if commit and overwrite_existing and current.legal_hold:
                raise R2ArchiveError("LEGAL_HOLD")
        committed_at = self._now()

        def commit_if_requested(source: BinaryIO) -> None:
            nonlocal committed_at
            if commit:
                committed_at = self._now()
                if atomic_commit is None:  # guarded above; retain a runtime boundary.
                    raise R2ArchiveError("INVALID_RESTORE_REQUEST")
                atomic_commit(source)

        try:
            restored = ArchiveEngine(self.object_port, clock=self.clock).restore_range(
                tuple(self._get_manifest(record) for record in records),
                start_ns=start_ns,
                end_ns=end_ns,
                expected_source_schema=expected_source_schema,
                temporary_destination=temporary_destination,
                atomic_commit=commit_if_requested,
            )
        except ArchiveError as exc:
            code = "RESTORE_" + exc.code
            raise R2ArchiveError(code) from None
        result = _issue_restore_result(
            manifest_keys=keys,
            bytes_restored=restored,
            lineage_id=lineage_id,
            audit_id=audit_id,
            committed=commit,
            committed_at=committed_at,
        )
        self._restore_audit.append(result)
        return result

    def _get_record(self, key: ManifestKeyV1) -> R2ManifestRecordV1:
        record = self._records.get(key)
        if record is None:
            raise R2ArchiveError("MANIFEST_NOT_FOUND")
        return self._require_record(record)

    def _get_manifest(self, record: R2ManifestRecordV1) -> ArchiveManifestV1:
        manifest = self._manifests.get(record.manifest_key)
        if manifest is None or _manifest_digest(manifest) != record.manifest_digest:
            raise R2ArchiveError("INVALID_MANIFEST")
        return manifest

    def _get_saved_lock(self, record: R2ManifestRecordV1) -> R2LockEvidenceV1:
        evidence = self._lock_evidence.get(record.manifest_key)
        if evidence is None or seal_digest(evidence) != record.lock_evidence_digest:
            raise R2ArchiveError("LOCK_EVIDENCE_INVALID")
        try:
            return require_lock_evidence(evidence)
        except Exception:
            raise R2ArchiveError("LOCK_EVIDENCE_INVALID") from None

    @staticmethod
    def _require_record(record: object) -> R2ManifestRecordV1:
        try:
            return cast(R2ManifestRecordV1, require(record, _TAG))
        except SealError:
            raise R2ArchiveError("INVALID_MANIFEST") from None

    def _objects_intact(self, manifest: ArchiveManifestV1) -> bool:
        if type(manifest) is not ArchiveManifestV1 or not manifest.chunks:
            return False
        whole = sha256()
        total = 0
        try:
            for chunk in manifest.chunks:
                head = self.object_port.head(chunk.object_key)
                data = self.object_port.get(chunk.object_key)
                if (
                    isinstance(head, NotFound)
                    or isinstance(data, NotFound)
                    or type(head) is not ObjectHead
                    or type(data) is not bytes
                    or len(data) != chunk.byte_length
                    or head.byte_length != chunk.byte_length
                    or sha256(data).hexdigest() != chunk.sha256_digest
                    or head.sha256_digest != chunk.sha256_digest
                ):
                    return False
                whole.update(data)
                total += len(data)
        except Exception:
            return False
        return total == manifest.byte_length and whole.hexdigest() == manifest.sha256_digest

    def _read_bound_lock(
        self, record: R2ManifestRecordV1, manifest: ArchiveManifestV1
    ) -> R2LockEvidenceV1:
        evidence = self._read_lock_evidence(record, manifest)
        self._validate_retention_period(record, manifest, evidence)
        return evidence

    def _read_lock_evidence(
        self, record: R2ManifestRecordV1, manifest: ArchiveManifestV1
    ) -> R2LockEvidenceV1:
        evidence = self.object_port.read_lock_evidence(record.manifest_digest)
        if isinstance(evidence, NotFound):
            raise R2ArchiveError("LOCK_EVIDENCE_MISSING")
        try:
            evidence = require_lock_evidence(evidence)
        except Exception:
            raise R2ArchiveError("LOCK_EVIDENCE_INVALID") from None
        if evidence.bucket != self.object_port.bucket or evidence.prefix != self.object_port.prefix:
            raise R2ArchiveError("LOCK_IDENTITY_MISMATCH")
        if evidence.manifest_digest != record.manifest_digest:
            raise R2ArchiveError("LOCK_UNBOUND")
        if evidence.policy_id != manifest.retention_policy_id:
            raise R2ArchiveError("LOCK_POLICY_MISMATCH")
        return evidence

    def _validate_retention_period(
        self,
        record: R2ManifestRecordV1,
        manifest: ArchiveManifestV1,
        evidence: R2LockEvidenceV1,
    ) -> None:
        archive_at_ns, retention_end_ns = _manifest_archive_horizon_ns(record, manifest)
        if (
            evidence.retention_start_utc_ns > archive_at_ns
            or evidence.retention_end_utc_ns < retention_end_ns
        ):
            raise R2ArchiveError("LOCK_INSUFFICIENT_RETENTION")
        if not _seven_years_reached(evidence.retention_start_utc_ns, evidence.retention_end_utc_ns):
            raise R2ArchiveError("LOCK_INSUFFICIENT_RETENTION")
        if (
            evidence.lifecycle_expiration_utc_ns is not None
            and evidence.lifecycle_expiration_utc_ns < evidence.retention_end_utc_ns
        ):
            raise R2ArchiveError("LIFECYCLE_BEFORE_LOCK")

    def _read_valid_lock(
        self, record: R2ManifestRecordV1, manifest: ArchiveManifestV1
    ) -> R2LockEvidenceV1:
        evidence = self._read_lock_evidence(record, manifest)
        now_ns = self._now_ns()
        if evidence.retention_end_utc_ns <= now_ns:
            raise R2ArchiveError("LOCK_EXPIRED")
        if evidence.retention_start_utc_ns > now_ns:
            raise R2ArchiveError("LOCK_INSUFFICIENT_RETENTION")
        self._validate_retention_period(record, manifest, evidence)
        return evidence

    def _now(self) -> datetime:
        try:
            value = self.clock()
        except Exception:
            raise R2ArchiveError("INVALID_CLOCK") from None
        if type(value) is not datetime or value.tzinfo is not UTC:
            raise R2ArchiveError("INVALID_CLOCK")
        return value

    def _now_ns(self) -> int:
        if self.clock_ns is None:
            return _datetime_to_utc_ns(self._now())
        try:
            value = self.clock_ns()
        except Exception:
            raise R2ArchiveError("INVALID_CLOCK") from None
        if type(value) is not int or value < 0:
            raise R2ArchiveError("INVALID_CLOCK")
        return value


__all__ = [
    "ManifestKeyV1",
    "R2ManifestRecordV1",
    "R2ManifestRepositoryV1",
    "R2ManifestStateV1",
    "R2RestoreResultV1",
]
