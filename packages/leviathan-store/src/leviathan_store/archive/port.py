"""Synchronous object port and a deterministic local fake."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256
from typing import Protocol

from .models import ArchiveModelError, _FrozenValue, object_key_for_digest


class PutResult(StrEnum):
    STORED = "STORED"
    ALREADY_PRESENT = "ALREADY_PRESENT"
    CONFLICT = "CONFLICT"


@dataclass(frozen=True, slots=True)
class NotFound(_FrozenValue):
    """Absence sentinel, distinct from an empty object."""


NOT_FOUND = NotFound()


@dataclass(frozen=True, slots=True)
class ObjectHead(_FrozenValue):
    byte_length: int
    sha256_digest: str

    def __post_init__(self) -> None:
        if type(self.byte_length) is not int or self.byte_length < 0:
            raise ArchiveModelError("INVALID_OBJECT_LENGTH")
        object_key_for_digest(self.sha256_digest)


class ArchiveObjectPort(Protocol):
    def put_if_absent(self, key: str, data: bytes) -> PutResult: ...

    def get(self, key: str) -> bytes | NotFound: ...

    def head(self, key: str) -> ObjectHead | NotFound: ...


class InMemoryArchiveObjectPort:
    """Local fake. ``objects`` may be altered by tests to simulate corruption."""

    def __init__(self, *, read_only: bool = False) -> None:
        if type(read_only) is not bool:
            raise ArchiveModelError("INVALID_READ_ONLY")
        self.read_only = read_only
        self.objects: dict[str, bytes] = {}

    def put_if_absent(self, key: str, data: bytes) -> PutResult:
        if not isinstance(data, bytes):
            raise ArchiveModelError("INVALID_OBJECT_BYTES")
        existing = self.objects.get(key)
        if existing is not None:
            return PutResult.ALREADY_PRESENT if existing == data else PutResult.CONFLICT
        if key != object_key_for_digest(sha256(data).hexdigest()):
            raise ArchiveModelError("INVALID_OBJECT_KEY")
        if self.read_only:
            raise PermissionError("READ_ONLY")
        self.objects[key] = data
        return PutResult.STORED

    def get(self, key: str) -> bytes | NotFound:
        return self.objects.get(key, NOT_FOUND)

    def head(self, key: str) -> ObjectHead | NotFound:
        data = self.objects.get(key)
        if data is None:
            return NOT_FOUND
        return ObjectHead(byte_length=len(data), sha256_digest=sha256(data).hexdigest())
