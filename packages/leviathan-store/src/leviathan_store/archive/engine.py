"""Bounded, offline content-addressed export and atomic range restore."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import replace
from datetime import datetime
from hashlib import sha256
from typing import BinaryIO, TypedDict

from .models import (
    ArchiveChunkV1,
    ArchiveManifestV1,
    ArchiveModelError,
    ArchiveStatus,
    _mark_verified,
    object_key_for_digest,
)
from .port import ArchiveObjectPort, NotFound, ObjectHead, PutResult

DEFAULT_CHUNK_SIZE = 8 * 1024 * 1024
MAX_CHUNK_SIZE = 64 * 1024 * 1024


class _ManifestFields(TypedDict):
    dataset_id: str
    dataset_version: str
    partition_key: str
    event_start_ns: int
    event_end_ns: int
    source_schema: str
    created_at: datetime
    creation_provenance: str
    retention_policy_id: str


class ArchiveError(RuntimeError):
    """Typed operation failure with no caller input in its message."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class ArchiveEngine:
    def __init__(
        self,
        port: ArchiveObjectPort,
        *,
        clock: Callable[[], datetime],
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ) -> None:
        if type(chunk_size) is not int or not 1 <= chunk_size <= MAX_CHUNK_SIZE:
            raise ArchiveError("CHUNK_SIZE_OUT_OF_BOUNDS")
        if not callable(clock):
            raise ArchiveError("INVALID_CLOCK")
        self.port = port
        self.clock = clock
        self.chunk_size = chunk_size

    def prepare_export(
        self,
        source: BinaryIO,
        *,
        dataset_id: str,
        dataset_version: str,
        partition_key: str,
        event_start_ns: int,
        event_end_ns: int,
        source_schema: str,
        creation_provenance: str,
        retention_policy_id: str,
    ) -> ArchiveManifestV1:
        """Write bounded chunks and return PENDING before any read-back verification.

        A caller can durably save PENDING before calling :meth:`verify`. Failed
        writes return FAILED metadata; neither state is prune eligible.
        """
        # Validate metadata before writing any object.
        try:
            created_at = self.clock()
        except Exception:
            raise ArchiveError("CLOCK_FAILED") from None
        manifest_fields: _ManifestFields = {
            "dataset_id": dataset_id,
            "dataset_version": dataset_version,
            "partition_key": partition_key,
            "event_start_ns": event_start_ns,
            "event_end_ns": event_end_ns,
            "source_schema": source_schema,
            "created_at": created_at,
            "creation_provenance": creation_provenance,
            "retention_policy_id": retention_policy_id,
        }
        try:
            ArchiveManifestV1(
                **manifest_fields,
                byte_length=0,
                sha256_digest=sha256(b"").hexdigest(),
                chunks=(),
            )
        except ArchiveModelError as exc:
            raise ArchiveError(exc.code) from exc

        digest = sha256()
        chunks: list[ArchiveChunkV1] = []
        total = 0
        failure: str | None = None
        try:
            while True:
                data = source.read(self.chunk_size)
                if not isinstance(data, bytes) or len(data) > self.chunk_size:
                    raise ArchiveError("INVALID_SOURCE_READ")
                if not data:
                    break
                chunk_digest = sha256(data).hexdigest()
                key = object_key_for_digest(chunk_digest)
                result = self.port.put_if_absent(key, data)
                if result is PutResult.CONFLICT:
                    raise ArchiveError("OBJECT_CONFLICT")
                if result not in (PutResult.STORED, PutResult.ALREADY_PRESENT):
                    raise ArchiveError("INVALID_PUT_RESULT")
                chunks.append(
                    ArchiveChunkV1(
                        index=len(chunks),
                        object_key=key,
                        byte_length=len(data),
                        sha256_digest=chunk_digest,
                    )
                )
                digest.update(data)
                total += len(data)
        except ArchiveError as exc:
            failure = exc.code
        except Exception:
            failure = "WRITE_FAILED"
        if not chunks and failure is None:
            failure = "EMPTY_SOURCE"
        return ArchiveManifestV1(
            **manifest_fields,
            byte_length=total,
            sha256_digest=digest.hexdigest(),
            chunks=tuple(chunks),
            status=ArchiveStatus.FAILED if failure is not None else ArchiveStatus.PENDING,
            failure_reason=failure,
        )

    def verify(self, manifest: ArchiveManifestV1) -> ArchiveManifestV1:
        """Transition PENDING to VERIFIED only after full read-back validation."""
        if type(manifest) is not ArchiveManifestV1:
            raise ArchiveError("INVALID_MANIFEST")
        if manifest.status is not ArchiveStatus.PENDING:
            raise ArchiveError("INVALID_STATE_TRANSITION")
        try:
            self._read_verified_chunks(manifest, sink=None)
        except ArchiveError as exc:
            return replace(manifest, status=ArchiveStatus.FAILED, failure_reason=exc.code)
        except Exception:
            return replace(manifest, status=ArchiveStatus.FAILED, failure_reason="VERIFY_FAILED")
        return _mark_verified(manifest)

    def export(
        self,
        source: BinaryIO,
        *,
        dataset_id: str,
        dataset_version: str,
        partition_key: str,
        event_start_ns: int,
        event_end_ns: int,
        source_schema: str,
        creation_provenance: str,
        retention_policy_id: str,
    ) -> ArchiveManifestV1:
        manifest = self.prepare_export(
            source,
            dataset_id=dataset_id,
            dataset_version=dataset_version,
            partition_key=partition_key,
            event_start_ns=event_start_ns,
            event_end_ns=event_end_ns,
            source_schema=source_schema,
            creation_provenance=creation_provenance,
            retention_policy_id=retention_policy_id,
        )
        return self.verify(manifest) if manifest.status is ArchiveStatus.PENDING else manifest

    def restore_range(
        self,
        manifests: Sequence[ArchiveManifestV1],
        *,
        start_ns: int,
        end_ns: int,
        expected_source_schema: str,
        temporary_destination: BinaryIO,
        atomic_commit: Callable[[BinaryIO], None],
    ) -> int:
        """Validate a partition-aligned half-open range, then commit exactly once.

        The caller supplies a seekable temporary destination and an atomic commit
        callback. The callback is never invoked before all bytes and metadata pass.
        """
        if (
            type(start_ns) is not int
            or type(end_ns) is not int
            or start_ns < 0
            or end_ns <= start_ns
        ):
            raise ArchiveError("INVALID_EVENT_RANGE")
        if not isinstance(expected_source_schema, str) or not expected_source_schema:
            raise ArchiveError("INVALID_SOURCE_SCHEMA")
        if not callable(atomic_commit):
            raise ArchiveError("INVALID_ATOMIC_COMMIT")
        if not isinstance(manifests, Sequence):
            raise ArchiveError("INVALID_MANIFESTS")
        for manifest in manifests:
            if type(manifest) is not ArchiveManifestV1:
                raise ArchiveError("INVALID_MANIFEST")
        selected = sorted(
            (m for m in manifests if m.event_end_ns > start_ns and m.event_start_ns < end_ns),
            key=lambda m: m.event_start_ns,
        )
        if not selected:
            raise ArchiveError("RANGE_NOT_COVERED")
        cursor = start_ns
        first = selected[0]
        for manifest in selected:
            if manifest.status is not ArchiveStatus.VERIFIED:
                raise ArchiveError("MANIFEST_NOT_VERIFIED")
            if manifest.event_start_ns != cursor or manifest.event_end_ns > end_ns:
                raise ArchiveError("RANGE_NOT_COVERED")
            if (
                manifest.dataset_id != first.dataset_id
                or manifest.dataset_version != first.dataset_version
                or manifest.source_schema != expected_source_schema
            ):
                raise ArchiveError("SCHEMA_OR_DATASET_MISMATCH")
            cursor = manifest.event_end_ns
        if cursor != end_ns:
            raise ArchiveError("RANGE_NOT_COVERED")

        try:
            temporary_destination.seek(0)
            temporary_destination.truncate(0)
        except Exception:
            raise ArchiveError("INVALID_TEMPORARY_DESTINATION") from None
        total = 0
        for manifest in selected:
            total += self._read_verified_chunks(manifest, sink=temporary_destination)
        try:
            temporary_destination.flush()
            temporary_destination.seek(0)
        except Exception:
            raise ArchiveError("INVALID_TEMPORARY_DESTINATION") from None
        try:
            atomic_commit(temporary_destination)
        except Exception:
            raise ArchiveError("COMMIT_FAILED") from None
        return total

    def _read_verified_chunks(self, manifest: ArchiveManifestV1, sink: BinaryIO | None) -> int:
        digest = sha256()
        total = 0
        if not manifest.chunks:
            raise ArchiveError("EMPTY_MANIFEST")
        for chunk in manifest.chunks:
            if chunk.byte_length > MAX_CHUNK_SIZE:
                raise ArchiveError("CHUNK_SIZE_OUT_OF_BOUNDS")
            if chunk.object_key != object_key_for_digest(chunk.sha256_digest):
                raise ArchiveError("INVALID_OBJECT_KEY")
            if type(chunk) is not ArchiveChunkV1:
                raise ArchiveError("INVALID_CHUNK")
            try:
                head = self.port.head(chunk.object_key)
                data = self.port.get(chunk.object_key)
            except Exception:
                raise ArchiveError("OBJECT_READ_FAILED") from None
            if isinstance(head, NotFound) or isinstance(data, NotFound):
                raise ArchiveError("OBJECT_NOT_FOUND")
            if type(head) is not ObjectHead or not isinstance(data, bytes):
                raise ArchiveError("INVALID_OBJECT_RESPONSE")
            if (
                head.byte_length != chunk.byte_length
                or head.sha256_digest != chunk.sha256_digest
                or len(data) != chunk.byte_length
                or sha256(data).hexdigest() != chunk.sha256_digest
            ):
                raise ArchiveError("OBJECT_INTEGRITY_FAILED")
            digest.update(data)
            total += len(data)
            if sink is not None:
                try:
                    if sink.write(data) != len(data):
                        raise ArchiveError("TEMPORARY_WRITE_FAILED")
                except ArchiveError:
                    raise
                except Exception:
                    raise ArchiveError("TEMPORARY_WRITE_FAILED") from None
        if total != manifest.byte_length or digest.hexdigest() != manifest.sha256_digest:
            raise ArchiveError("MANIFEST_INTEGRITY_FAILED")
        return total
