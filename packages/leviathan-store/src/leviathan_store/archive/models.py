"""Immutable, versioned archive metadata for the offline integrity port."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Literal, Never, SupportsIndex

_DIGEST = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)


class ArchiveModelError(ValueError):
    """Invalid archive metadata. The code does not include caller input."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class ArchiveStatus(StrEnum):
    PENDING = "PENDING"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"


def object_key_for_digest(digest: str) -> str:
    if not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None:
        raise ArchiveModelError("INVALID_DIGEST")
    return f"sha256/{digest[:2]}/{digest}"


def _positive_int(value: object, code: str, *, allow_zero: bool = False) -> None:
    if type(value) is not int or value < (0 if allow_zero else 1):
        raise ArchiveModelError(code)


class _FrozenValue:
    def __copy__(self) -> None:
        raise ArchiveModelError("COPY_FORBIDDEN")

    def __deepcopy__(self, memo: object) -> None:
        raise ArchiveModelError("COPY_FORBIDDEN")

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        raise ArchiveModelError("PICKLE_FORBIDDEN")


@dataclass(frozen=True, slots=True)
class _VerificationProof(_FrozenValue):
    binding: tuple[object, ...]


@dataclass(frozen=True, slots=True)
class ArchiveChunkV1(_FrozenValue):
    index: int
    object_key: str
    byte_length: int
    sha256_digest: str
    schema_version: Literal[1] = 1

    def __post_init__(self) -> None:
        _positive_int(self.index, "INVALID_CHUNK_INDEX", allow_zero=True)
        _positive_int(self.byte_length, "INVALID_CHUNK_LENGTH")
        if self.schema_version != 1 or type(self.schema_version) is not int:
            raise ArchiveModelError("INVALID_SCHEMA_VERSION")
        if self.object_key != object_key_for_digest(self.sha256_digest):
            raise ArchiveModelError("INVALID_OBJECT_KEY")


@dataclass(frozen=True, slots=True)
class ArchiveManifestV1(_FrozenValue):
    dataset_id: str
    dataset_version: str
    partition_key: str
    event_start_ns: int
    event_end_ns: int
    source_schema: str
    byte_length: int
    sha256_digest: str
    chunks: tuple[ArchiveChunkV1, ...]
    created_at: datetime
    creation_provenance: str
    retention_policy_id: str
    status: ArchiveStatus = ArchiveStatus.PENDING
    failure_reason: str | None = None
    schema_version: Literal[1] = 1
    _verification_proof: _VerificationProof | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.schema_version != 1 or type(self.schema_version) is not int:
            raise ArchiveModelError("INVALID_SCHEMA_VERSION")
        for value in (
            self.dataset_id,
            self.dataset_version,
            self.partition_key,
            self.source_schema,
            self.creation_provenance,
            self.retention_policy_id,
        ):
            if not isinstance(value, str) or not value:
                raise ArchiveModelError("INVALID_METADATA")
        _positive_int(self.event_start_ns, "INVALID_EVENT_RANGE", allow_zero=True)
        _positive_int(self.event_end_ns, "INVALID_EVENT_RANGE")
        if self.event_end_ns <= self.event_start_ns:
            raise ArchiveModelError("INVALID_EVENT_RANGE")
        _positive_int(self.byte_length, "INVALID_MANIFEST_LENGTH", allow_zero=True)
        if not isinstance(self.created_at, datetime) or self.created_at.utcoffset() is None:
            raise ArchiveModelError("INVALID_CREATED_AT")
        if not isinstance(self.status, ArchiveStatus):
            raise ArchiveModelError("INVALID_STATUS")
        if not isinstance(self.chunks, tuple) or any(
            type(chunk) is not ArchiveChunkV1 for chunk in self.chunks
        ):
            raise ArchiveModelError("INVALID_CHUNKS")
        if any(chunk.index != index for index, chunk in enumerate(self.chunks)):
            raise ArchiveModelError("INVALID_CHUNK_ORDER")
        if sum(chunk.byte_length for chunk in self.chunks) != self.byte_length:
            raise ArchiveModelError("INVALID_MANIFEST_LENGTH")
        object_key_for_digest(self.sha256_digest)
        if self.status is ArchiveStatus.VERIFIED and not self.chunks:
            raise ArchiveModelError("EMPTY_VERIFIED_MANIFEST")
        if self.status is ArchiveStatus.VERIFIED:
            if (
                not isinstance(self._verification_proof, _VerificationProof)
                or self._verification_proof.binding != _manifest_binding(self)
            ):
                raise ArchiveModelError("MISSING_VERIFICATION_PROOF")
        elif self._verification_proof is not None:
            raise ArchiveModelError("UNEXPECTED_VERIFICATION_PROOF")
        if self.status is ArchiveStatus.FAILED:
            if not isinstance(self.failure_reason, str) or not self.failure_reason:
                raise ArchiveModelError("MISSING_FAILURE_REASON")
        elif self.failure_reason is not None:
            raise ArchiveModelError("UNEXPECTED_FAILURE_REASON")

    @property
    def prune_eligible(self) -> bool:
        return self.status is ArchiveStatus.VERIFIED


def _manifest_binding(manifest: ArchiveManifestV1) -> tuple[object, ...]:
    return (
        manifest.schema_version,
        manifest.dataset_id,
        manifest.dataset_version,
        manifest.partition_key,
        manifest.event_start_ns,
        manifest.event_end_ns,
        manifest.source_schema,
        manifest.byte_length,
        manifest.sha256_digest,
        manifest.chunks,
        manifest.created_at,
        manifest.creation_provenance,
        manifest.retention_policy_id,
    )


def _mark_verified(manifest: ArchiveManifestV1) -> ArchiveManifestV1:
    """Internal transition used only after the engine has verified read-back."""
    from dataclasses import replace

    return replace(
        manifest,
        status=ArchiveStatus.VERIFIED,
        _verification_proof=_VerificationProof(_manifest_binding(manifest)),
    )
