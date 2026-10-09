"""Offline object integrity, R2 lock evidence and range-restore invariants."""

from __future__ import annotations

import copy
import pickle
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from hashlib import sha256
from io import BytesIO

import pytest
from leviathan_store.archive import ArchiveEngine, ArchiveStatus
from leviathan_store.archive.models import object_key_for_digest
from leviathan_store.archive.port import NotFound
from leviathan_store.r2.archive_port import (
    FakeR2TransportV1,
    R2ArchiveError,
    R2ArchiveObjectPortV1,
)
from leviathan_store.r2.lock_evidence import (
    R2LockError,
    make_fake_lock_response,
    require_lock_evidence,
)
from leviathan_store.r2.manifest_repository import (
    R2ManifestRepositoryV1,
    R2ManifestStateV1,
)

from leviathan_core.seal.errors import SealError

NOW = datetime(2026, 10, 6, 12, 0, tzinfo=UTC)
BUCKET = "leviathan-archive-test"
PREFIX = "sha256/"
START_NS = 1_791_244_800_000_000_000
ARCHIVE_NS = int(NOW.timestamp()) * 1_000_000_000
END_NS = int(datetime(2033, 10, 6, 12, 0, tzinfo=UTC).timestamp()) * 1_000_000_000


def _transport(clock: Callable[[], datetime] = lambda: NOW) -> FakeR2TransportV1:
    return FakeR2TransportV1(clock=clock)


def _port(transport: FakeR2TransportV1 | None = None) -> R2ArchiveObjectPortV1:
    return R2ArchiveObjectPortV1(transport or _transport(), bucket=BUCKET)


def _install_lock(
    transport: FakeR2TransportV1,
    *,
    manifest_digest: str,
    bucket: str = BUCKET,
    prefix: str = PREFIX,
    retention_start_utc_ns: int = START_NS,
    retention_end_utc_ns: int = END_NS,
    lifecycle_expiration_utc_ns: int | None = END_NS,
    policy_id: str = "retention-policy-v1",
    legal_hold: bool = False,
) -> None:
    transport.lock_responses[(BUCKET, PREFIX)] = make_fake_lock_response(
        bucket=bucket,
        prefix=prefix,
        policy_id=policy_id,
        manifest_digest=manifest_digest,
        retention_start_utc_ns=retention_start_utc_ns,
        retention_end_utc_ns=retention_end_utc_ns,
        lifecycle_expiration_utc_ns=lifecycle_expiration_utc_ns,
        legal_hold=legal_hold,
    )


def _repository(
    transport: FakeR2TransportV1 | None = None,
    *,
    clock: Callable[[], datetime] | None = None,
    clock_ns: Callable[[], int] | None = None,
) -> tuple[FakeR2TransportV1, R2ArchiveObjectPortV1, R2ManifestRepositoryV1]:
    r2_transport = transport or _transport()
    port = _port(r2_transport)
    repository = R2ManifestRepositoryV1(
        port, clock=clock or r2_transport.clock, clock_ns=clock_ns
    )
    return r2_transport, port, repository


def _pending(
    repository: R2ManifestRepositoryV1,
    port: R2ArchiveObjectPortV1,
    *,
    partition_key: str = "2026-10-06",
):
    manifest = ArchiveEngine(port, clock=port.transport.clock, chunk_size=3).prepare_export(
        BytesIO(b"abcdefgh"),
        dataset_id="ticks",
        dataset_version="v1",
        partition_key=partition_key,
        event_start_ns=0,
        event_end_ns=10,
        source_schema="ticks-v1",
        creation_provenance="synthetic-test",
        retention_policy_id="retention-policy-v1",
    )
    assert manifest.status is ArchiveStatus.PENDING
    return repository.put_pending(manifest), manifest


def _verified(
    repository: R2ManifestRepositoryV1,
    port: R2ArchiveObjectPortV1,
    **lock_kwargs: object,
):
    record, _manifest = _pending(repository, port)
    complete = repository.mark_complete(record.manifest_key)
    _install_lock(
        port.transport, manifest_digest=complete.manifest_digest, **lock_kwargs
    )
    return repository.mark_verified(complete.manifest_key), _manifest


def _commit_target(target: bytearray):
    def commit(source: BytesIO) -> None:
        target[:] = source.read()

    return commit


def test_r2_put_uses_arch_content_key_and_verifies_exact_readback() -> None:
    transport = _transport()
    port = _port(transport)
    data = b"R2 bytes"
    key = object_key_for_digest(sha256(data).hexdigest())

    assert port.put_if_absent(key, data).value == "STORED"
    assert port.put_if_absent(key, data).value == "ALREADY_PRESENT"
    assert transport.objects == {key: data}
    assert port.head(key).byte_length == len(data)
    assert port.head(key).sha256_digest == sha256(data).hexdigest()
    assert port.get(key) == data
    assert all("s3" not in request[0].lower() for request in transport.calls)


def test_conflicting_conditional_create_never_overwrites_existing_object() -> None:
    transport = _transport()
    port = _port(transport)
    data = b"wanted"
    key = object_key_for_digest(sha256(data).hexdigest())
    transport.objects[key] = b"different"

    assert port.put_if_absent(key, data).value == "CONFLICT"
    assert transport.objects[key] == b"different"


def test_upload_readback_length_or_digest_mismatch_fails_closed() -> None:
    transport = _transport()
    port = _port(transport)
    data = b"correct"
    key = object_key_for_digest(sha256(data).hexdigest())
    transport.read_overrides[key] = b"corrupt"

    with pytest.raises(R2ArchiveError) as captured:
        port.put_if_absent(key, data)
    assert captured.value.code == "OBJECT_INTEGRITY_FAILED"
    assert "corrupt" not in str(captured.value)


def test_manifest_requires_verified_objects_and_matching_seven_year_lock() -> None:
    transport, port, repository = _repository()
    record, _manifest = _pending(repository, port)
    assert record.state is R2ManifestStateV1.PENDING
    assert repository.get(record.manifest_key).state is R2ManifestStateV1.PENDING
    assert not repository.prune_eligible(record.manifest_key)

    complete = repository.mark_complete(record.manifest_key)
    assert complete.state is R2ManifestStateV1.COMPLETE
    with pytest.raises(R2ArchiveError) as missing:
        repository.mark_verified(record.manifest_key)
    assert missing.value.code == "LOCK_EVIDENCE_MISSING"
    assert repository.get(record.manifest_key).state is R2ManifestStateV1.COMPLETE

    _install_lock(transport, manifest_digest=complete.manifest_digest)
    verified = repository.mark_verified(record.manifest_key)
    assert verified.state is R2ManifestStateV1.VERIFIED
    assert verified.lock_evidence_digest
    assert not repository.prune_eligible(record.manifest_key)
    with pytest.raises(R2ArchiveError) as transition:
        repository.mark_verified(record.manifest_key)
    assert transition.value.code == "INVALID_STATE_TRANSITION"


@pytest.mark.parametrize(
    ("lock_kwargs", "expected_code"),
    [
        ({"bucket": "other-bucket"}, "LOCK_IDENTITY_MISMATCH"),
        ({"policy_id": "different-retention-policy"}, "LOCK_POLICY_MISMATCH"),
        (
            {"retention_end_utc_ns": END_NS - 1},
            "LOCK_INSUFFICIENT_RETENTION",
        ),
        ({"lifecycle_expiration_utc_ns": END_NS - 1}, "LIFECYCLE_BEFORE_LOCK"),
    ],
)
def test_wrong_short_or_early_expiration_lock_never_verifies(
    lock_kwargs: dict[str, object], expected_code: str
) -> None:
    transport, port, repository = _repository()
    pending, _manifest = _pending(repository, port)
    record = repository.mark_complete(pending.manifest_key)
    _install_lock(transport, manifest_digest=record.manifest_digest, **lock_kwargs)

    with pytest.raises(R2ArchiveError) as captured:
        repository.mark_verified(record.manifest_key)
    assert captured.value.code == expected_code
    assert repository.get(record.manifest_key).state is R2ManifestStateV1.COMPLETE
    assert not repository.prune_eligible(record.manifest_key)


def test_expired_lock_cannot_verify_new_archive_or_enable_pruning() -> None:
    transport, port, repository = _repository()
    pending, _manifest = _pending(repository, port)
    complete = repository.mark_complete(pending.manifest_key)
    _install_lock(
        transport,
        manifest_digest=complete.manifest_digest,
        retention_start_utc_ns=int(datetime(2010, 1, 1, tzinfo=UTC).timestamp())
        * 1_000_000_000,
        retention_end_utc_ns=int(datetime(2017, 1, 1, tzinfo=UTC).timestamp())
        * 1_000_000_000,
        lifecycle_expiration_utc_ns=None,
    )

    with pytest.raises(R2ArchiveError) as captured:
        repository.mark_verified(complete.manifest_key)
    assert captured.value.code == "LOCK_EXPIRED"
    assert repository.get(complete.manifest_key).state is R2ManifestStateV1.COMPLETE
    assert not repository.prune_eligible(complete.manifest_key)


def test_active_but_short_lock_cannot_verify_new_archive() -> None:
    transport, port, repository = _repository()
    pending, _manifest = _pending(repository, port)
    complete = repository.mark_complete(pending.manifest_key)
    _install_lock(
        transport,
        manifest_digest=complete.manifest_digest,
        retention_start_utc_ns=ARCHIVE_NS,
        retention_end_utc_ns=ARCHIVE_NS + 6 * 365 * 24 * 60 * 60 * 1_000_000_000,
        lifecycle_expiration_utc_ns=None,
    )

    with pytest.raises(R2ArchiveError) as captured:
        repository.mark_verified(complete.manifest_key)
    assert captured.value.code == "LOCK_INSUFFICIENT_RETENTION"
    assert repository.get(complete.manifest_key).state is R2ManifestStateV1.COMPLETE
    assert not repository.prune_eligible(complete.manifest_key)


def test_lock_evidence_bound_to_another_manifest_is_rejected() -> None:
    transport, port, repository = _repository()
    first, _first_manifest = _pending(repository, port, partition_key="2026-10-06-a")
    first_complete = repository.mark_complete(first.manifest_key)
    _install_lock(transport, manifest_digest=first_complete.manifest_digest)

    second, _second_manifest = _pending(repository, port, partition_key="2026-10-06-b")
    second_complete = repository.mark_complete(second.manifest_key)
    with pytest.raises(R2ArchiveError) as captured:
        repository.mark_verified(second_complete.manifest_key)
    assert captured.value.code == "LOCK_UNBOUND"
    assert repository.get(second_complete.manifest_key).state is R2ManifestStateV1.COMPLETE
    assert not repository.prune_eligible(second_complete.manifest_key)


def test_exact_retention_boundaries_verify_and_gate_pruning() -> None:
    now_ns = [ARCHIVE_NS]
    transport = _transport()
    port = _port(transport)
    repository = R2ManifestRepositoryV1(
        port,
        clock=lambda: NOW,
        clock_ns=lambda: now_ns[0],
    )
    pending, _manifest = _pending(repository, port)
    complete = repository.mark_complete(pending.manifest_key)
    _install_lock(
        transport,
        manifest_digest=complete.manifest_digest,
        retention_start_utc_ns=ARCHIVE_NS,
        retention_end_utc_ns=END_NS,
        lifecycle_expiration_utc_ns=END_NS,
    )

    verified = repository.mark_verified(complete.manifest_key)
    assert verified.state is R2ManifestStateV1.VERIFIED
    now_ns[0] = END_NS
    assert not repository.prune_eligible(complete.manifest_key)
    now_ns[0] = END_NS + 1
    assert repository.prune_eligible(complete.manifest_key)


def test_s3_object_lock_looking_response_is_not_bucket_lock_evidence() -> None:
    transport, port, repository = _repository()
    pending, _manifest = _pending(repository, port)
    record = repository.mark_complete(pending.manifest_key)
    transport.s3_object_lock_responses[(BUCKET, PREFIX)] = {"mode": "COMPLIANCE", "years": 7}

    with pytest.raises(R2ArchiveError) as captured:
        repository.mark_verified(record.manifest_key)
    assert captured.value.code == "LOCK_EVIDENCE_MISSING"


def test_legal_hold_blocks_prune_and_restore_overwrite_but_allows_read_restore() -> None:
    _transport_value, port, repository = _repository()
    record, _manifest = _verified(repository, port, legal_hold=True)
    assert not repository.prune_eligible(record.manifest_key)

    target = bytearray(b"previous")
    result = repository.restore_range(
        [record.manifest_key],
        start_ns=0,
        end_ns=10,
        expected_source_schema="ticks-v1",
        temporary_destination=BytesIO(),
        atomic_commit=_commit_target(target),
        lineage_id="restore-lineage-1",
        audit_id="audit-restore-1",
    )
    assert result.bytes_restored == 8
    assert not result.committed
    assert target == b"previous"
    assert repository.restore_audit == (result,)

    target[:] = b"keep-me"
    with pytest.raises(R2ArchiveError) as held:
        repository.restore_range(
            [record.manifest_key],
            start_ns=0,
            end_ns=10,
            expected_source_schema="ticks-v1",
            temporary_destination=BytesIO(),
            atomic_commit=_commit_target(target),
            lineage_id="restore-lineage-2",
            audit_id="audit-restore-2",
            commit=True,
            overwrite_existing=True,
        )
    assert held.value.code == "LEGAL_HOLD"
    assert target == b"keep-me"


def test_fake_transport_crash_missing_object_and_truncated_read_stay_nonprunable() -> None:
    transport, port, repository = _repository()
    pending, manifest = _pending(repository, port)
    transport.fail_before_verify = True
    with pytest.raises(R2ArchiveError) as crash:
        repository.mark_complete(pending.manifest_key)
    assert crash.value.code == "VERIFY_INTERRUPTED"
    assert repository.get(pending.manifest_key).state is R2ManifestStateV1.PENDING
    assert not repository.prune_eligible(pending.manifest_key)

    transport.fail_before_verify = False
    transport.objects.pop(manifest.chunks[0].object_key)
    with pytest.raises(R2ArchiveError) as missing:
        repository.mark_complete(pending.manifest_key)
    assert missing.value.code == "OBJECT_INTEGRITY_FAILED"
    assert repository.get(pending.manifest_key).state is R2ManifestStateV1.PENDING

    transport.objects[manifest.chunks[0].object_key] = b"abc"
    complete = repository.mark_complete(pending.manifest_key)
    _install_lock(transport, manifest_digest=complete.manifest_digest)
    verified = repository.mark_verified(complete.manifest_key)
    transport.read_overrides[manifest.chunks[1].object_key] = b"truncated"
    assert not repository.prune_eligible(verified.manifest_key)


def test_concurrent_identical_retry_is_idempotent() -> None:
    transport = _transport()
    port = _port(transport)
    data = b"same bytes"
    key = object_key_for_digest(sha256(data).hexdigest())

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: port.put_if_absent(key, data), range(8)))
    assert results[0].value == "STORED"
    assert all(result.value == "ALREADY_PRESENT" for result in results[1:])
    assert transport.objects == {key: data}


def test_range_restore_validates_all_chunks_before_atomic_commit() -> None:
    transport, port, repository = _repository()
    record, manifest = _verified(repository, port)
    target = bytearray(b"previous-good-range")
    original = bytes(target)
    temp = BytesIO()
    calls = 0

    def commit(source: BytesIO) -> None:
        nonlocal calls
        calls += 1
        target[:] = source.read()

    transport.read_overrides[manifest.chunks[1].object_key] = b"bad"
    with pytest.raises(R2ArchiveError) as corrupt:
        repository.restore_range(
            [record.manifest_key],
            start_ns=0,
            end_ns=10,
            expected_source_schema="ticks-v1",
            temporary_destination=temp,
            atomic_commit=commit,
            lineage_id="restore-lineage-3",
            audit_id="audit-restore-3",
            commit=True,
        )
    assert corrupt.value.code == "OBJECT_INTEGRITY_FAILED"
    assert target == original
    assert calls == 0
    assert repository.restore_audit == ()


def test_restore_publishes_once_only_when_commit_is_explicit() -> None:
    _transport_value, port, repository = _repository()
    record, _manifest = _verified(repository, port)
    target = bytearray()
    calls = 0

    def commit(source: BytesIO) -> None:
        nonlocal calls
        calls += 1
        target.extend(source.read())

    result = repository.restore_range(
        [record.manifest_key],
        start_ns=0,
        end_ns=10,
        expected_source_schema="ticks-v1",
        temporary_destination=BytesIO(),
        atomic_commit=commit,
        lineage_id="restore-lineage-4",
        audit_id="audit-restore-4",
        commit=True,
    )
    assert result.committed
    assert result.bytes_restored == 8
    assert target == b"abcdefgh"
    assert calls == 1


def test_restore_requires_lineage_and_audit_and_defaults_to_no_overwrite() -> None:
    _transport_value, port, repository = _repository()
    record, _manifest = _verified(repository, port)
    target = bytearray(b"prior")

    with pytest.raises(R2ArchiveError) as invalid:
        repository.restore_range(
            [record.manifest_key],
            start_ns=0,
            end_ns=10,
            expected_source_schema="ticks-v1",
            temporary_destination=BytesIO(),
            atomic_commit=_commit_target(target),
            lineage_id="",
            audit_id="audit-1",
            commit=True,
        )
    assert invalid.value.code == "INVALID_RESTORE_REQUEST"
    assert target == b"prior"


def test_issued_records_are_sealed_against_mutation_and_copy() -> None:
    _transport_value, port, repository = _repository()
    record, _manifest = _verified(repository, port)
    evidence = port.read_lock_evidence(record.manifest_digest)
    assert not isinstance(evidence, NotFound)
    target = BytesIO()
    result = repository.restore_range(
        [record.manifest_key],
        start_ns=0,
        end_ns=10,
        expected_source_schema="ticks-v1",
        temporary_destination=target,
        lineage_id="seal-lineage",
        audit_id="seal-audit",
    )
    for issued in (record, evidence, result):
        with pytest.raises(SealError):
            copy.copy(issued)
        with pytest.raises(SealError):
            copy.deepcopy(issued)
        with pytest.raises(SealError):
            pickle.dumps(issued)

    object.__setattr__(evidence, "policy_id", "tampered")
    with pytest.raises(R2LockError):
        require_lock_evidence(evidence)

    object.__setattr__(result, "audit_id", "tampered")
    with pytest.raises(R2ArchiveError) as tampered_result:
        _ = repository.restore_audit
    assert tampered_result.value.code == "INVALID_RESTORE_RESULT"

    object.__setattr__(record, "state", R2ManifestStateV1.PENDING)
    with pytest.raises(R2ArchiveError) as tampered:
        repository.get(record.manifest_key)
    assert tampered.value.code == "INVALID_MANIFEST"
