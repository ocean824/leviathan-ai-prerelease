"""Offline archive integrity and failure invariants."""

from __future__ import annotations

import copy
import pickle
from dataclasses import replace
from datetime import UTC, datetime
from hashlib import sha256
from io import BytesIO
from traceback import format_exception

import pytest
from leviathan_store.archive import (
    ArchiveEngine,
    ArchiveError,
    ArchiveModelError,
    ArchiveStatus,
    InMemoryArchiveObjectPort,
    PutResult,
    object_key_for_digest,
)

NOW = datetime(2026, 9, 30, tzinfo=UTC)


def _engine(port: InMemoryArchiveObjectPort | None = None) -> ArchiveEngine:
    return ArchiveEngine(port or InMemoryArchiveObjectPort(), chunk_size=3, clock=lambda: NOW)


def _fields(start: int = 0, end: int = 10, partition: str = "p0") -> dict[str, object]:
    return dict(
        dataset_id="ticks",
        dataset_version="v1",
        partition_key=partition,
        event_start_ns=start,
        event_end_ns=end,
        source_schema='{"fields":["ts","price"],"version":1}',
        creation_provenance="test-run",
        retention_policy_id="cold-7y",
    )


def test_export_verifies_each_bounded_chunk_and_identical_retry() -> None:
    port = InMemoryArchiveObjectPort()
    engine = _engine(port)
    first = engine.export(BytesIO(b"abcdefgh"), **_fields())
    second = engine.export(BytesIO(b"abcdefgh"), **_fields())
    assert first == second
    assert first.status is ArchiveStatus.VERIFIED
    assert first.prune_eligible
    assert [chunk.byte_length for chunk in first.chunks] == [3, 3, 2]
    assert first.sha256_digest == sha256(b"abcdefgh").hexdigest()
    assert len(port.objects) == 3
    assert port.put_if_absent(first.chunks[0].object_key, b"abc") is PutResult.ALREADY_PRESENT


def test_pending_is_not_prune_eligible_and_only_one_transition() -> None:
    engine = _engine()
    pending = engine.prepare_export(BytesIO(b"abc"), **_fields())
    assert pending.status is ArchiveStatus.PENDING
    assert not pending.prune_eligible
    verified = engine.verify(pending)
    assert verified.prune_eligible
    with pytest.raises(ArchiveError, match="INVALID_STATE_TRANSITION"):
        engine.verify(verified)


def test_conflicting_object_blocks_export_without_prune_eligibility() -> None:
    port = InMemoryArchiveObjectPort()
    key = object_key_for_digest(sha256(b"abc").hexdigest())
    port.objects[key] = b"wrong"
    manifest = _engine(port).export(BytesIO(b"abc"), **_fields())
    assert manifest.status is ArchiveStatus.FAILED
    assert manifest.failure_reason == "OBJECT_CONFLICT"
    assert not manifest.prune_eligible
    assert port.objects[key] == b"wrong"


@pytest.mark.parametrize("corrupt", [b"ab", b"abd", None])
def test_bad_readback_never_verifies(corrupt: bytes | None) -> None:
    port = InMemoryArchiveObjectPort()
    engine = _engine(port)
    pending = engine.prepare_export(BytesIO(b"abc"), **_fields())
    key = pending.chunks[0].object_key
    if corrupt is None:
        del port.objects[key]
    else:
        port.objects[key] = corrupt
    failed = engine.verify(pending)
    assert failed.status is ArchiveStatus.FAILED
    assert not failed.prune_eligible


def test_read_only_port_returns_failed_manifest() -> None:
    port = InMemoryArchiveObjectPort(read_only=True)
    failed = _engine(port).export(BytesIO(b"abc"), **_fields())
    assert failed.status is ArchiveStatus.FAILED
    assert failed.failure_reason == "WRITE_FAILED"
    assert port.objects == {}

    key = object_key_for_digest(sha256(b"abc").hexdigest())
    port.objects[key] = b"abc"
    assert port.put_if_absent(key, b"abc") is PutResult.ALREADY_PRESENT
    assert port.put_if_absent(key, b"wrong") is PutResult.CONFLICT


def test_restore_only_commits_after_complete_validation() -> None:
    port = InMemoryArchiveObjectPort()
    engine = _engine(port)
    left = engine.export(BytesIO(b"abcdef"), **_fields(0, 10, "p0"))
    right = engine.export(BytesIO(b"ghijkl"), **_fields(10, 20, "p1"))
    target = bytearray(b"previous-good-range")
    temp = BytesIO()
    calls = 0

    def commit(source: BytesIO) -> None:
        nonlocal calls
        calls += 1
        target[:] = source.read()

    restored = engine.restore_range(
        [right, left],
        start_ns=0,
        end_ns=20,
        expected_source_schema=left.source_schema,
        temporary_destination=temp,
        atomic_commit=commit,
    )
    assert restored == 12
    assert target == b"abcdefghijkl"
    assert calls == 1

    target[:] = b"previous-good-range"
    port.objects[right.chunks[1].object_key] = b"bad"
    with pytest.raises(ArchiveError, match="OBJECT_INTEGRITY_FAILED"):
        engine.restore_range(
            [left, right],
            start_ns=0,
            end_ns=20,
            expected_source_schema=left.source_schema,
            temporary_destination=temp,
            atomic_commit=commit,
        )
    assert target == b"previous-good-range"
    assert calls == 1


def test_restore_rejects_gap_partial_partition_and_schema_mismatch() -> None:
    engine = _engine()
    manifest = engine.export(BytesIO(b"abc"), **_fields(0, 10))
    for start, end, schema, expected_code in (
        (0, 20, manifest.source_schema, "RANGE_NOT_COVERED"),
        (1, 10, manifest.source_schema, "RANGE_NOT_COVERED"),
        (0, 10, "wrong-schema", "SCHEMA_OR_DATASET_MISMATCH"),
    ):
        with pytest.raises(ArchiveError, match=expected_code):
            engine.restore_range(
                [manifest],
                start_ns=start,
                end_ns=end,
                expected_source_schema=schema,
                temporary_destination=BytesIO(),
                atomic_commit=lambda _: pytest.fail("commit before validation"),
            )


def test_empty_source_and_missing_manifest_cannot_restore() -> None:
    engine = _engine()
    failed = engine.export(BytesIO(), **_fields())
    assert failed.status is ArchiveStatus.FAILED
    assert failed.failure_reason == "EMPTY_SOURCE"
    with pytest.raises(ArchiveError, match="RANGE_NOT_COVERED"):
        engine.restore_range(
            [],
            start_ns=0,
            end_ns=10,
            expected_source_schema=failed.source_schema,
            temporary_destination=BytesIO(),
            atomic_commit=lambda _: pytest.fail("commit without manifest"),
        )


def test_metadata_is_frozen_and_integer_booleans_are_rejected() -> None:
    manifest = _engine().export(BytesIO(b"abc"), **_fields())
    for value in (manifest, manifest.chunks[0]):
        with pytest.raises(ArchiveModelError, match="COPY_FORBIDDEN"):
            copy.copy(value)
        with pytest.raises(ArchiveModelError, match="COPY_FORBIDDEN"):
            copy.deepcopy(value)
        with pytest.raises(ArchiveModelError, match="PICKLE_FORBIDDEN"):
            pickle.dumps(value)
    with pytest.raises(ArchiveModelError, match="INVALID_EVENT_RANGE"):
        replace(manifest, event_start_ns=True)
    with pytest.raises(ArchiveModelError, match="MISSING_VERIFICATION_PROOF"):
        replace(manifest, sha256_digest=sha256(b"wrong").hexdigest())
    with pytest.raises(ArchiveError, match="CHUNK_SIZE_OUT_OF_BOUNDS"):
        ArchiveEngine(InMemoryArchiveObjectPort(), clock=lambda: NOW, chunk_size=True)


def test_public_error_does_not_echo_port_exception_details() -> None:
    class LeakyPort(InMemoryArchiveObjectPort):
        leak = False

        def get(self, key: str):
            if self.leak:
                raise ValueError("sensitive-object-content")
            return super().get(key)

    port = LeakyPort()
    engine = _engine(port)
    verified = engine.export(BytesIO(b"abc"), **_fields())
    port.leak = True
    with pytest.raises(ArchiveError) as captured:
        engine.restore_range(
            [verified],
            start_ns=0,
            end_ns=10,
            expected_source_schema=verified.source_schema,
            temporary_destination=BytesIO(),
            atomic_commit=lambda _: None,
        )
    assert "sensitive-object-content" not in str(captured.value)
    assert "sensitive-object-content" not in "".join(format_exception(captured.value))
