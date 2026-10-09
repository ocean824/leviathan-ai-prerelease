"""Fake-first Cloudflare R2 archive adapter surface."""

from .archive_port import FakeR2TransportV1, R2ArchiveError, R2ArchiveObjectPortV1
from .lock_evidence import (
    FakeR2LockResponseV1,
    R2LockEvidenceV1,
    make_fake_lock_response,
)
from .manifest_repository import (
    ManifestKeyV1,
    R2ManifestRecordV1,
    R2ManifestRepositoryV1,
    R2ManifestStateV1,
    R2RestoreResultV1,
)

__all__ = [
    "FakeR2LockResponseV1",
    "FakeR2TransportV1",
    "ManifestKeyV1",
    "R2ArchiveError",
    "R2ArchiveObjectPortV1",
    "R2LockEvidenceV1",
    "R2ManifestRecordV1",
    "R2ManifestRepositoryV1",
    "R2ManifestStateV1",
    "R2RestoreResultV1",
    "make_fake_lock_response",
]
