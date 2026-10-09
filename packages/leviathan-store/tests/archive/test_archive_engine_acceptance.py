"""Independent adversarial acceptance for ARCH-001 archive integrity."""

from __future__ import annotations

import copy
import hashlib
import io
import pickle
from datetime import UTC, datetime

import pytest
from leviathan_store.archive import (
    ArchiveEngine,
    ArchiveError,
    ArchiveModelError,
    ArchiveStatus,
    InMemoryArchiveObjectPort,
    ObjectHead,
    object_key_for_digest,
)

NOW = datetime(2026, 9, 30, 12, 0, tzinfo=UTC)


def _metadata(partition: str, start: int, end: int) -> dict[str, object]:
    return {
        "dataset_id": "market-bars",
        "dataset_version": "v3",
        "partition_key": partition,
        "event_start_ns": start,
        "event_end_ns": end,
        "source_schema": "bar-v1",
        "creation_provenance": "acceptance-fixture",
        "retention_policy_id": "cold-7y",
    }


def _prepare(
    engine: ArchiveEngine, data: bytes, partition: str = "p0", start: int = 0, end: int = 10
):
    return engine.prepare_export(io.BytesIO(data), **_metadata(partition, start, end))


def _verified(
    engine: ArchiveEngine, data: bytes, partition: str = "p0", start: int = 0, end: int = 10
):
    manifest = _prepare(engine, data, partition, start, end)
    assert manifest.status is ArchiveStatus.PENDING
    return engine.verify(manifest)


def test_export_chunks_are_bounded_content_addressed_and_verified() -> None:
    port = InMemoryArchiveObjectPort()
    engine = ArchiveEngine(port, clock=lambda: NOW, chunk_size=3)
    source = io.BytesIO(b"abcdefgh")

    manifest = engine.export(source, **_metadata("p0", 0, 10))

    assert manifest.status is ArchiveStatus.VERIFIED
    assert manifest.prune_eligible
    assert [chunk.byte_length for chunk in manifest.chunks] == [3, 3, 2]
    assert all(chunk.byte_length <= 3 for chunk in manifest.chunks)
    assert manifest.byte_length == 8
    assert manifest.sha256_digest == hashlib.sha256(b"abcdefgh").hexdigest()
    for chunk, expected in zip(manifest.chunks, (b"abc", b"def", b"gh"), strict=True):
        digest = hashlib.sha256(expected).hexdigest()
        assert chunk.sha256_digest == digest
        assert chunk.object_key == f"sha256/{digest[:2]}/{digest}"
        assert object_key_for_digest(digest) == chunk.object_key
        assert port.objects[chunk.object_key] == expected


def test_same_key_same_bytes_is_idempotent_but_conflicting_bytes_fail() -> None:
    port = InMemoryArchiveObjectPort()
    engine = ArchiveEngine(port, clock=lambda: NOW, chunk_size=8)
    first = _prepare(engine, b"same bytes")
    retry = _prepare(engine, b"same bytes")
    assert first.status is retry.status is ArchiveStatus.PENDING
    assert first.chunks == retry.chunks
    assert engine.verify(first).status is ArchiveStatus.VERIFIED

    key = first.chunks[0].object_key
    port.objects[key] = b"different bytes"
    conflict = _prepare(engine, b"same bytes")
    assert conflict.status is ArchiveStatus.FAILED
    assert conflict.failure_reason == "OBJECT_CONFLICT"
    assert not conflict.prune_eligible


def test_pending_and_failed_manifests_are_not_prune_eligible_and_state_cannot_be_reverified():
    port = InMemoryArchiveObjectPort()
    engine = ArchiveEngine(port, clock=lambda: NOW)
    pending = _prepare(engine, b"pending")
    assert pending.status is ArchiveStatus.PENDING
    assert not pending.prune_eligible

    verified = engine.verify(pending)
    assert verified.status is ArchiveStatus.VERIFIED
    assert verified.prune_eligible
    with pytest.raises(ArchiveError):
        engine.verify(verified)

    readonly = ArchiveEngine(InMemoryArchiveObjectPort(read_only=True), clock=lambda: NOW)
    failed = _prepare(readonly, b"cannot write")
    assert failed.status is ArchiveStatus.FAILED
    assert not failed.prune_eligible


def test_read_back_detects_truncated_corrupt_missing_and_false_head_objects() -> None:
    class FalseHeadPort(InMemoryArchiveObjectPort):
        def head(self, key: str):
            head = super().head(key)
            if hasattr(head, "byte_length"):
                return ObjectHead(head.byte_length + 1, head.sha256_digest)
            return head

    for port_kind in ("truncate", "corrupt", "missing", "head"):
        port = FalseHeadPort() if port_kind == "head" else InMemoryArchiveObjectPort()
        engine = ArchiveEngine(port, clock=lambda: NOW)
        pending = _prepare(engine, b"read back checks")
        key = pending.chunks[0].object_key
        if port_kind == "truncate":
            port.objects[key] = port.objects[key][:-1]
        elif port_kind == "corrupt":
            port.objects[key] = b"tampered payload"
        elif port_kind == "missing":
            del port.objects[key]
        verified = engine.verify(pending)
        assert verified.status is ArchiveStatus.FAILED, port_kind
        assert not verified.prune_eligible, port_kind


def test_restore_commits_only_after_all_verified_partitions_pass_validation() -> None:
    port = InMemoryArchiveObjectPort()
    engine = ArchiveEngine(port, clock=lambda: NOW, chunk_size=4)
    first = _verified(engine, b"alpha", "p0", 0, 10)
    second = _verified(engine, b"beta", "p1", 10, 20)
    destination = io.BytesIO(b"previous-good-range")
    commits: list[bytes] = []

    written = engine.restore_range(
        (second, first),
        start_ns=0,
        end_ns=20,
        expected_source_schema="bar-v1",
        temporary_destination=io.BytesIO(),
        atomic_commit=lambda stream: commits.append(stream.read()),
    )

    assert written == 9
    assert commits == [b"alphabeta"]
    assert destination.getvalue() == b"previous-good-range"


@pytest.mark.parametrize("failure", ["missing", "truncated", "corrupt"])
def test_restore_failure_never_invokes_commit_or_changes_prior_target(failure: str) -> None:
    port = InMemoryArchiveObjectPort()
    engine = ArchiveEngine(port, clock=lambda: NOW)
    verified = _verified(engine, b"complete-range")
    chunk = verified.chunks[0]
    if failure == "missing":
        del port.objects[chunk.object_key]
    elif failure == "truncated":
        port.objects[chunk.object_key] = b"x"
    else:
        port.objects[chunk.object_key] = b"corrupt-range"

    target = bytearray(b"old-good-target")
    calls = 0

    def commit(stream: io.BytesIO) -> None:
        nonlocal calls
        calls += 1
        target[:] = stream.read()

    with pytest.raises(ArchiveError):
        engine.restore_range(
            (verified,),
            start_ns=0,
            end_ns=10,
            expected_source_schema="bar-v1",
            temporary_destination=io.BytesIO(),
            atomic_commit=commit,
        )
    assert calls == 0
    assert target == b"old-good-target"


def test_restore_rejects_gap_schema_or_unverified_state_without_commit() -> None:
    port = InMemoryArchiveObjectPort()
    engine = ArchiveEngine(port, clock=lambda: NOW)
    verified = _verified(engine, b"part", "p0", 0, 10)
    pending = _prepare(engine, b"next", "p1", 10, 20)

    for manifests, start, end, schema in (
        ((verified,), 0, 20, "bar-v1"),
        ((verified,), 0, 10, "wrong-schema"),
        ((verified, pending), 0, 20, "bar-v1"),
    ):
        called = False

        def commit(_stream: io.BytesIO) -> None:
            nonlocal called
            called = True

        with pytest.raises(ArchiveError):
            engine.restore_range(
                manifests,
                start_ns=start,
                end_ns=end,
                expected_source_schema=schema,
                temporary_destination=io.BytesIO(),
                atomic_commit=commit,
            )
        assert not called


def test_short_temporary_write_aborts_before_atomic_commit() -> None:
    class ShortWriter(io.BytesIO):
        def write(self, data: bytes) -> int:
            super().write(data[:-1])
            return len(data) - 1

    port = InMemoryArchiveObjectPort()
    engine = ArchiveEngine(port, clock=lambda: NOW)
    verified = _verified(engine, b"must-not-commit")
    called = False

    def commit(_stream: io.BytesIO) -> None:
        nonlocal called
        called = True

    with pytest.raises(ArchiveError):
        engine.restore_range(
            (verified,),
            start_ns=0,
            end_ns=10,
            expected_source_schema="bar-v1",
            temporary_destination=ShortWriter(),
            atomic_commit=commit,
        )
    assert not called


def test_metadata_rejects_bool_integer_and_archive_values_cannot_be_copied_or_pickled() -> None:
    port = InMemoryArchiveObjectPort()
    engine = ArchiveEngine(port, clock=lambda: NOW)
    with pytest.raises(ArchiveError):
        _prepare(engine, b"invalid", start=True, end=10)
    chunk = _prepare(engine, b"valid").chunks[0]
    manifest = _verified(engine, b"valid")
    for value in (chunk, manifest):
        with pytest.raises(ArchiveModelError):
            copy.copy(value)
        with pytest.raises(ArchiveModelError):
            copy.deepcopy(value)
        with pytest.raises(ArchiveModelError):
            pickle.dumps(value)


def test_crash_before_verify_leaves_pending_manifest_unprunable() -> None:
    engine = ArchiveEngine(InMemoryArchiveObjectPort(), clock=lambda: NOW)
    persisted_pending = _prepare(engine, b"written-but-not-verified")

    assert persisted_pending.status is ArchiveStatus.PENDING
    assert not persisted_pending.prune_eligible
