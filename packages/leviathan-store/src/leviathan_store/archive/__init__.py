"""Offline archive integrity primitives (LEV-REQ-006 bounded slice)."""

from .engine import DEFAULT_CHUNK_SIZE, MAX_CHUNK_SIZE, ArchiveEngine, ArchiveError
from .models import (
    ArchiveChunkV1,
    ArchiveManifestV1,
    ArchiveModelError,
    ArchiveStatus,
    object_key_for_digest,
)
from .port import (
    NOT_FOUND,
    ArchiveObjectPort,
    InMemoryArchiveObjectPort,
    NotFound,
    ObjectHead,
    PutResult,
)

__all__ = [
    "DEFAULT_CHUNK_SIZE",
    "MAX_CHUNK_SIZE",
    "NOT_FOUND",
    "ArchiveChunkV1",
    "ArchiveEngine",
    "ArchiveError",
    "ArchiveManifestV1",
    "ArchiveModelError",
    "ArchiveObjectPort",
    "ArchiveStatus",
    "InMemoryArchiveObjectPort",
    "NotFound",
    "ObjectHead",
    "PutResult",
    "object_key_for_digest",
]
