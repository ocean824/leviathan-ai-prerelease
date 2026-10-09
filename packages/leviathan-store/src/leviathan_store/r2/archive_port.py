"""ARCH-001-compatible R2 object port backed only by an injected fake transport."""

from __future__ import annotations

import re
from collections.abc import Callable
from datetime import UTC, datetime
from hashlib import sha256
from threading import RLock
from typing import Final

from leviathan_store.archive.models import ArchiveModelError, object_key_for_digest
from leviathan_store.archive.port import NOT_FOUND, NotFound, ObjectHead, PutResult

from .lock_evidence import (
    FakeR2LockResponseV1,
    R2LockError,
    R2LockEvidenceV1,
    issue_lock_evidence,
    require_fake_lock_response,
)

_BUCKET = re.compile(r"[a-z0-9][a-z0-9.-]{0,62}\Z", re.ASCII)
_PREFIX = re.compile(r"[A-Za-z0-9._/-]{1,256}\Z", re.ASCII)
_OBJECT_KEY = re.compile(r"sha256/[0-9a-f]{2}/[0-9a-f]{64}\Z", re.ASCII)


class R2ArchiveError(RuntimeError):
    """Content-free error at the R2 object port boundary."""

    CODES: Final = frozenset(
        {
            "INVALID_BUCKET",
            "INVALID_PREFIX",
            "INVALID_OBJECT_KEY",
            "INVALID_OBJECT_BYTES",
            "OBJECT_CONFLICT",
            "OBJECT_INTEGRITY_FAILED",
            "INVALID_OBJECT_RESPONSE",
            "INVALID_LOCK_RESPONSE",
            "INVALID_CLOCK",
            "TRANSPORT_FAILED",
            "MANIFEST_NOT_FOUND",
            "MANIFEST_CONFLICT",
            "INVALID_MANIFEST",
            "INVALID_MANIFEST_KEY",
            "INVALID_STATE_TRANSITION",
            "VERIFY_INTERRUPTED",
            "LOCK_EVIDENCE_MISSING",
            "LOCK_NOT_ACTIVE",
            "LOCK_EVIDENCE_INVALID",
            "LOCK_EVIDENCE_MISMATCH",
            "LOCK_IDENTITY_MISMATCH",
            "LOCK_POLICY_MISMATCH",
            "LOCK_RETENTION_SHORT",
            "LOCK_EXPIRED",
            "LOCK_INSUFFICIENT_RETENTION",
            "LOCK_UNBOUND",
            "LIFECYCLE_BEFORE_LOCK",
            "LEGAL_HOLD",
            "MANIFEST_NOT_VERIFIED",
            "INVALID_RESTORE_REQUEST",
            "INVALID_RESTORE_RESULT",
            "RESTORE_INVALID_EVENT_RANGE",
            "RESTORE_INVALID_SOURCE_SCHEMA",
            "RESTORE_INVALID_ATOMIC_COMMIT",
            "RESTORE_INVALID_MANIFESTS",
            "RESTORE_INVALID_MANIFEST",
            "RESTORE_MANIFEST_NOT_VERIFIED",
            "RESTORE_RANGE_NOT_COVERED",
            "RESTORE_SCHEMA_OR_DATASET_MISMATCH",
            "RESTORE_INVALID_TEMPORARY_DESTINATION",
            "RESTORE_OBJECT_READ_FAILED",
            "RESTORE_OBJECT_NOT_FOUND",
            "RESTORE_INVALID_OBJECT_RESPONSE",
            "RESTORE_OBJECT_INTEGRITY_FAILED",
            "RESTORE_MANIFEST_INTEGRITY_FAILED",
            "RESTORE_TEMPORARY_WRITE_FAILED",
            "RESTORE_COMMIT_FAILED",
            "RESTORE_FAILED",
        }
    )

    def __init__(self, code: str) -> None:
        if code not in self.CODES:
            code = "TRANSPORT_FAILED"
        self.code = code
        super().__init__(code)


class FakeR2TransportV1:
    """Synthetic, in-memory transport with explicit corruption/failure seams.

    ``objects`` and ``read_overrides`` are keyed by the exact object key. A
    configured override affects GET only, allowing HEAD/GET disagreement to be
    exercised. Lock responses must be installed separately from the deliberately
    ignored ``s3_object_lock_responses`` map.
    """

    def __init__(self, *, clock: Callable[[], datetime]) -> None:
        if not callable(clock):
            raise R2ArchiveError("INVALID_CLOCK")
        self.clock = clock
        self.objects: dict[str, bytes] = {}
        self.read_overrides: dict[str, bytes] = {}
        self.lock_responses: dict[tuple[str, str], FakeR2LockResponseV1 | None] = {}
        self.s3_object_lock_responses: dict[tuple[str, str], object] = {}
        self.fail_operations: set[str] = set()
        self.fail_before_verify = False
        self.calls: list[tuple[str, str, str]] = []
        self._object_lock = RLock()

    def put_if_absent(self, bucket: str, key: str, data: bytes) -> PutResult:
        self._record("put", bucket, key)
        self._maybe_fail("put")
        with self._object_lock:
            current = self.objects.get(key)
            if current is not None:
                return PutResult.ALREADY_PRESENT if current == data else PutResult.CONFLICT
            self.objects[key] = data
            return PutResult.STORED

    def get(self, bucket: str, key: str) -> bytes | NotFound:
        self._record("get", bucket, key)
        self._maybe_fail("get")
        if key in self.read_overrides:
            return self.read_overrides[key]
        return self.objects.get(key, NOT_FOUND)

    def head(self, bucket: str, key: str) -> ObjectHead | NotFound:
        self._record("head", bucket, key)
        self._maybe_fail("head")
        data = self.objects.get(key)
        if data is None:
            return NOT_FOUND
        if not isinstance(data, bytes):
            raise R2ArchiveError("INVALID_OBJECT_RESPONSE")
        return ObjectHead(byte_length=len(data), sha256_digest=sha256(data).hexdigest())

    def get_lock_response(self, bucket: str, prefix: str) -> FakeR2LockResponseV1 | None:
        self._record("lock", bucket, prefix)
        self._maybe_fail("lock")
        # S3 Object Lock-looking data intentionally has no effect here.
        response = self.lock_responses.get((bucket, prefix))
        if response is None:
            return None
        return require_fake_lock_response(response)

    def _record(self, operation: str, bucket: str, resource: str) -> None:
        self.calls.append((operation, bucket, resource))

    def _maybe_fail(self, operation: str) -> None:
        if operation in self.fail_operations:
            raise OSError("synthetic transport failure")


class R2ArchiveObjectPortV1:
    """Conditional-create content-addressed object port for fake R2."""

    def __init__(
        self,
        transport: FakeR2TransportV1,
        *,
        bucket: str,
        prefix: str = "sha256/",
    ) -> None:
        if type(transport) is not FakeR2TransportV1:
            raise R2ArchiveError("INVALID_OBJECT_RESPONSE")
        if not isinstance(bucket, str) or _BUCKET.fullmatch(bucket) is None:
            raise R2ArchiveError("INVALID_BUCKET")
        if (
            not isinstance(prefix, str)
            or _PREFIX.fullmatch(prefix) is None
            or prefix.startswith("/")
            or ".." in prefix.split("/")
        ):
            raise R2ArchiveError("INVALID_PREFIX")
        if not "sha256/".startswith(prefix) and not prefix.startswith("sha256/"):
            raise R2ArchiveError("INVALID_PREFIX")
        self.transport = transport
        self.bucket = bucket
        self.prefix = prefix

    def put_if_absent(self, key: str, data: bytes) -> PutResult:
        self._validate_key(key)
        if type(data) is not bytes:
            raise R2ArchiveError("INVALID_OBJECT_BYTES")
        digest = sha256(data).hexdigest()
        try:
            if key != object_key_for_digest(digest):
                raise R2ArchiveError("INVALID_OBJECT_KEY")
            result = self.transport.put_if_absent(self.bucket, key, data)
            if result is PutResult.CONFLICT:
                return PutResult.CONFLICT
            if result not in (PutResult.STORED, PutResult.ALREADY_PRESENT):
                raise R2ArchiveError("INVALID_OBJECT_RESPONSE")
            stored = self.transport.get(self.bucket, key)
            head = self.transport.head(self.bucket, key)
            if (
                isinstance(stored, NotFound)
                or isinstance(head, NotFound)
                or type(stored) is not bytes
                or type(head) is not ObjectHead
                or len(stored) != len(data)
                or sha256(stored).hexdigest() != digest
                or head.byte_length != len(data)
                or head.sha256_digest != digest
            ):
                raise R2ArchiveError("OBJECT_INTEGRITY_FAILED")
            return result
        except R2ArchiveError:
            raise
        except Exception:
            raise R2ArchiveError("TRANSPORT_FAILED") from None

    def get(self, key: str) -> bytes | NotFound:
        self._validate_key(key)
        try:
            result = self.transport.get(self.bucket, key)
        except Exception:
            raise R2ArchiveError("TRANSPORT_FAILED") from None
        if isinstance(result, NotFound):
            return NOT_FOUND
        if type(result) is not bytes:
            raise R2ArchiveError("INVALID_OBJECT_RESPONSE")
        return result

    def head(self, key: str) -> ObjectHead | NotFound:
        self._validate_key(key)
        try:
            result = self.transport.head(self.bucket, key)
        except R2ArchiveError:
            raise
        except Exception:
            raise R2ArchiveError("TRANSPORT_FAILED") from None
        if isinstance(result, NotFound):
            return NOT_FOUND
        if type(result) is not ObjectHead:
            raise R2ArchiveError("INVALID_OBJECT_RESPONSE")
        return result

    def read_lock_evidence(self, manifest_digest: str) -> R2LockEvidenceV1 | NotFound:
        if not isinstance(manifest_digest, str) or re.fullmatch(
            r"[0-9a-f]{64}", manifest_digest, re.ASCII
        ) is None:
            raise R2ArchiveError("INVALID_MANIFEST")
        try:
            response = self.transport.get_lock_response(self.bucket, self.prefix)
            if response is None:
                return NOT_FOUND
            try:
                response = require_fake_lock_response(response)
            except R2LockError:
                raise R2ArchiveError("INVALID_LOCK_RESPONSE") from None
            if response.manifest_digest != manifest_digest:
                raise R2ArchiveError("LOCK_UNBOUND")
            captured_at = self.transport.clock()
            if type(captured_at) is not datetime or captured_at.tzinfo is not UTC:
                raise R2ArchiveError("INVALID_CLOCK")
            return issue_lock_evidence(response, captured_at=captured_at)
        except R2ArchiveError:
            raise
        except R2LockError:
            raise R2ArchiveError("INVALID_LOCK_RESPONSE") from None
        except Exception:
            raise R2ArchiveError("TRANSPORT_FAILED") from None

    def _validate_key(self, key: str) -> None:
        if not isinstance(key, str) or _OBJECT_KEY.fullmatch(key) is None:
            raise R2ArchiveError("INVALID_OBJECT_KEY")
        if not key.startswith(self.prefix):
            raise R2ArchiveError("INVALID_OBJECT_KEY")
        try:
            digest = key.rsplit("/", maxsplit=1)[1]
            if key != object_key_for_digest(digest):
                raise R2ArchiveError("INVALID_OBJECT_KEY")
        except ArchiveModelError:
            raise R2ArchiveError("INVALID_OBJECT_KEY") from None


__all__ = [
    "FakeR2TransportV1",
    "R2ArchiveError",
    "R2ArchiveObjectPortV1",
]
