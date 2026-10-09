"""Independent contract acceptance for the fake-first STOR-002 R2 adapter."""

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from io import BytesIO

import pytest
from leviathan_store.archive import ArchiveEngine, ArchiveStatus, object_key_for_digest
from leviathan_store.archive.port import PutResult
from leviathan_store.r2 import (
    FakeR2TransportV1,
    R2ArchiveError,
    R2ArchiveObjectPortV1,
    R2ManifestRepositoryV1,
    R2ManifestStateV1,
    make_fake_lock_response,
)

NOW = datetime(2026, 10, 6, 12, 0, tzinfo=UTC)
BUCKET = "acceptance-archive"
PREFIX = "sha256/"
POLICY = "retention-policy-v1"


def _utc_ns(value: datetime) -> int:
    delta = value - datetime(1970, 1, 1, tzinfo=UTC)
    return ((delta.days * 86_400 + delta.seconds) * 1_000_000 + delta.microseconds) * 1_000


def _transport() -> FakeR2TransportV1:
    return FakeR2TransportV1(clock=lambda: NOW)


def _port(transport: FakeR2TransportV1) -> R2ArchiveObjectPortV1:
    return R2ArchiveObjectPortV1(transport, bucket=BUCKET, prefix=PREFIX)


def _install_lock(
    transport: FakeR2TransportV1,
    *,
    manifest_digest: str,
    bucket: str = BUCKET,
    prefix: str = PREFIX,
    policy_id: str = POLICY,
    retention_start_utc_ns: int | None = None,
    retention_end_utc_ns: int | None = None,
    lifecycle_expiration_utc_ns: int | None = None,
    legal_hold: bool = False,
) -> None:
    start = retention_start_utc_ns
    if start is None:
        start = _utc_ns(NOW - timedelta(days=1))
    end = retention_end_utc_ns
    if end is None:
        end = _utc_ns(NOW.replace(year=NOW.year + 8))
    transport.lock_responses[(BUCKET, PREFIX)] = make_fake_lock_response(
        bucket=bucket,
        prefix=prefix,
        policy_id=policy_id, manifest_digest=manifest_digest,
        retention_start_utc_ns=start,
        retention_end_utc_ns=end,
        lifecycle_expiration_utc_ns=lifecycle_expiration_utc_ns,
        legal_hold=legal_hold,
    )


def _repository(
    transport: FakeR2TransportV1 | None = None,
    *,
    clock_ns: Callable[[], int] | None = None,
) -> tuple[FakeR2TransportV1, R2ArchiveObjectPortV1, R2ManifestRepositoryV1]:
    fake = transport or _transport()
    port = _port(fake)
    return (
        fake,
        port,
        R2ManifestRepositoryV1(port, clock=lambda: NOW, clock_ns=clock_ns),
    )


def _pending(
    repository: R2ManifestRepositoryV1,
    port: R2ArchiveObjectPortV1,
    *,
    payload: bytes = b"archive-payload",
    dataset_id: str = "bars",
    dataset_version: str = "v1",
    partition_key: str = "2026-10-06",
    start_ns: int = 0,
    end_ns: int = 10,
    chunk_size: int = 4,
):
    manifest = ArchiveEngine(
        port, clock=lambda: NOW, chunk_size=chunk_size
    ).prepare_export(
        BytesIO(payload),
        dataset_id=dataset_id,
        dataset_version=dataset_version,
        partition_key=partition_key,
        event_start_ns=start_ns,
        event_end_ns=end_ns,
        source_schema="bars-v1",
        creation_provenance="synthetic-acceptance",
        retention_policy_id=POLICY,
    )
    assert manifest.status is ArchiveStatus.PENDING
    record = repository.put_pending(manifest)
    return record, manifest


def _verified(
    repository: R2ManifestRepositoryV1,
    port: R2ArchiveObjectPortV1,
    *,
    payload: bytes = b"archive-payload",
    legal_hold: bool = False,
):
    pending, manifest = _pending(repository, port, payload=payload)
    complete = repository.mark_complete(pending.manifest_key)
    _install_lock(
        port.transport,
        manifest_digest=complete.manifest_digest,
        legal_hold=legal_hold,
    )
    verified = repository.mark_verified(complete.manifest_key)
    return verified, manifest


def _commit_to(target: bytearray):
    def commit(source: BytesIO) -> None:
        target[:] = source.read()

    return commit


def test_content_addressed_conditional_create_is_idempotent_and_never_overwrites() -> None:
    transport = _transport()
    port = _port(transport)
    data = b"immutable synthetic object"
    key = object_key_for_digest(sha256(data).hexdigest())

    assert port.put_if_absent(key, data) is PutResult.STORED
    assert port.put_if_absent(key, data) is PutResult.ALREADY_PRESENT
    assert port.get(key) == data
    head = port.head(key)
    assert head.byte_length == len(data)
    assert head.sha256_digest == sha256(data).hexdigest()

    original = b"preexisting different object"
    transport.objects[key] = original
    assert port.put_if_absent(key, data) is PutResult.CONFLICT
    assert transport.objects[key] == original
    with pytest.raises(R2ArchiveError) as invalid_key:
        port.put_if_absent("sha256/00/not-the-digest", data)
    assert invalid_key.value.code == "INVALID_OBJECT_KEY"


def test_concurrent_same_digest_retries_have_one_create_and_no_conflict() -> None:
    transport = _transport()
    port = _port(transport)
    data = b"concurrent synthetic retry"
    key = object_key_for_digest(sha256(data).hexdigest())

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: port.put_if_absent(key, data), range(8)))

    assert results.count(PutResult.STORED) == 1
    assert results.count(PutResult.ALREADY_PRESENT) == 7
    assert transport.objects == {key: data}


def test_readback_corruption_and_transport_failure_do_not_claim_integrity() -> None:
    transport = _transport()
    port = _port(transport)
    payload = b"correct upload bytes"
    key = object_key_for_digest(sha256(payload).hexdigest())
    transport.read_overrides[key] = payload[:-1]

    with pytest.raises(R2ArchiveError) as mismatch:
        port.put_if_absent(key, payload)
    assert mismatch.value.code == "OBJECT_INTEGRITY_FAILED"
    assert key in transport.objects
    assert transport.objects[key] == payload

    transport.read_overrides.clear()
    transport.fail_operations.add("head")
    with pytest.raises(R2ArchiveError) as failed:
        port.put_if_absent(object_key_for_digest(sha256(b"another").hexdigest()), b"another")
    assert failed.value.code == "TRANSPORT_FAILED"


def test_repository_requires_ordered_verification_before_prune_eligibility() -> None:
    transport, port, repository = _repository()
    record, _manifest = _pending(repository, port)

    assert record.state is R2ManifestStateV1.PENDING
    assert not repository.prune_eligible(record.manifest_key)
    with pytest.raises(R2ArchiveError) as premature:
        repository.mark_verified(record.manifest_key)
    assert premature.value.code == "INVALID_STATE_TRANSITION"

    complete = repository.mark_complete(record.manifest_key)
    assert complete.state is R2ManifestStateV1.COMPLETE
    assert not repository.prune_eligible(record.manifest_key)
    with pytest.raises(R2ArchiveError) as missing_lock:
        repository.mark_verified(record.manifest_key)
    assert missing_lock.value.code == "LOCK_EVIDENCE_MISSING"
    assert repository.get(record.manifest_key).state is R2ManifestStateV1.COMPLETE

    _install_lock(transport, manifest_digest=complete.manifest_digest)
    verified = repository.mark_verified(record.manifest_key)
    assert verified.state is R2ManifestStateV1.VERIFIED
    assert verified.completed_at is not None
    assert verified.verified_at is not None
    assert verified.lock_evidence_digest
    assert not repository.prune_eligible(record.manifest_key)


@pytest.mark.parametrize(
    ("lock_fields", "expected_code"),
    [
        ({"bucket": "different-archive"}, "LOCK_IDENTITY_MISMATCH"),
        ({"prefix": "sha256/other/"}, "LOCK_IDENTITY_MISMATCH"),
        ({"policy_id": "different-policy"}, "LOCK_POLICY_MISMATCH"),
        (
            {
                "retention_end_utc_ns": _utc_ns(NOW.replace(year=NOW.year + 6)),
            },
            "LOCK_INSUFFICIENT_RETENTION",
        ),
        (
            {
                "retention_start_utc_ns": _utc_ns(NOW + timedelta(days=1)),
            },
            "LOCK_INSUFFICIENT_RETENTION",
        ),
        (
            {
                "lifecycle_expiration_utc_ns": _utc_ns(NOW.replace(year=NOW.year + 7))
                - 1,
            },
            "LIFECYCLE_BEFORE_LOCK",
        ),
    ],
)
def test_nonmatching_or_insufficient_r2_lock_cannot_verify_or_prune(
    lock_fields: dict[str, object], expected_code: str
) -> None:
    transport, port, repository = _repository()
    pending, _manifest = _pending(repository, port)
    complete = repository.mark_complete(pending.manifest_key)
    _install_lock(transport, manifest_digest=complete.manifest_digest, **lock_fields)

    with pytest.raises(R2ArchiveError) as rejected:
        repository.mark_verified(complete.manifest_key)

    assert rejected.value.code == expected_code
    assert repository.get(complete.manifest_key).state is R2ManifestStateV1.COMPLETE
    assert not repository.prune_eligible(complete.manifest_key)


def test_s3_object_lock_metadata_is_not_r2_lock_proof() -> None:
    transport, _port_value, repository = _repository()
    pending, _manifest = _pending(repository, _port_value)
    complete = repository.mark_complete(pending.manifest_key)
    transport.s3_object_lock_responses[(BUCKET, PREFIX)] = {
        "mode": "COMPLIANCE",
        "retention_years": 99,
    }

    with pytest.raises(R2ArchiveError) as missing:
        repository.mark_verified(complete.manifest_key)

    assert missing.value.code == "LOCK_EVIDENCE_MISSING"
    assert not repository.prune_eligible(complete.manifest_key)


def test_interrupted_or_damaged_archive_remains_nonprunable() -> None:
    transport, port, repository = _repository()
    pending, manifest = _pending(repository, port)
    transport.fail_before_verify = True

    with pytest.raises(R2ArchiveError) as interrupted:
        repository.mark_complete(pending.manifest_key)
    assert interrupted.value.code == "VERIFY_INTERRUPTED"
    assert repository.get(pending.manifest_key).state is R2ManifestStateV1.PENDING
    assert not repository.prune_eligible(pending.manifest_key)

    transport.fail_before_verify = False
    object_key = manifest.chunks[0].object_key
    transport.objects[object_key] = b"damaged"
    with pytest.raises(R2ArchiveError) as corrupt:
        repository.mark_complete(pending.manifest_key)
    assert corrupt.value.code == "OBJECT_INTEGRITY_FAILED"
    assert repository.get(pending.manifest_key).state is R2ManifestStateV1.PENDING
    assert not repository.prune_eligible(pending.manifest_key)


def test_verified_archive_is_not_prunable_after_bytes_or_lock_change() -> None:
    now_ns = [_utc_ns(NOW)]
    transport, port, repository = _repository(clock_ns=lambda: now_ns[0])
    verified, manifest = _verified(repository, port, payload=b"payload across chunks")
    now_ns[0] = _utc_ns(NOW.replace(year=NOW.year + 7)) + 1
    assert repository.prune_eligible(verified.manifest_key)

    transport.objects[manifest.chunks[0].object_key] = b"altered"
    assert not repository.prune_eligible(verified.manifest_key)

    transport.objects[manifest.chunks[0].object_key] = b"payl"
    _install_lock(
        transport,
        manifest_digest=verified.manifest_digest,
        policy_id="rotated-policy",
    )
    assert not repository.prune_eligible(verified.manifest_key)


def test_restore_validates_range_without_publishing_by_default() -> None:
    _transport_value, port, repository = _repository()
    verified, _manifest = _verified(repository, port, payload=b"restore-me")
    destination = BytesIO()
    target = bytearray(b"prior published bytes")
    commits = 0

    def commit(source: BytesIO) -> None:
        nonlocal commits
        commits += 1
        target[:] = source.read()

    result = repository.restore_range(
        [verified.manifest_key],
        start_ns=0,
        end_ns=10,
        expected_source_schema="bars-v1",
        temporary_destination=destination,
        atomic_commit=commit,
        lineage_id="lineage-synthetic-1",
        audit_id="audit-synthetic-1",
    )

    assert destination.getvalue() == b"restore-me"
    assert not result.committed
    assert result.committed_at == NOW
    assert result.lineage_id == "lineage-synthetic-1"
    assert result.audit_id == "audit-synthetic-1"
    assert commits == 0
    assert target == b"prior published bytes"


def test_corrupt_middle_chunk_never_calls_atomic_commit_or_changes_target() -> None:
    transport, port, repository = _repository()
    verified, manifest = _verified(
        repository, port, payload=b"first-second-third-fourth", legal_hold=False
    )
    assert len(manifest.chunks) >= 3
    transport.read_overrides[manifest.chunks[1].object_key] = b"corrupt-middle"
    target = bytearray(b"previous complete archive")
    previous = bytes(target)
    calls = 0

    def commit(source: BytesIO) -> None:
        nonlocal calls
        calls += 1
        target[:] = source.read()

    with pytest.raises(R2ArchiveError) as rejected:
        repository.restore_range(
            [verified.manifest_key],
            start_ns=0,
            end_ns=10,
            expected_source_schema="bars-v1",
            temporary_destination=BytesIO(),
            atomic_commit=commit,
            lineage_id="lineage-corruption-1",
            audit_id="audit-corruption-1",
            commit=True,
        )

    assert rejected.value.code == "OBJECT_INTEGRITY_FAILED"
    assert calls == 0
    assert target == previous
    assert repository.restore_audit == ()


def test_legal_hold_blocks_prune_and_restore_overwrite_but_allows_validation() -> None:
    now_ns = [_utc_ns(NOW)]
    _transport_value, port, repository = _repository(clock_ns=lambda: now_ns[0])
    verified, _manifest = _verified(repository, port, legal_hold=True)
    now_ns[0] = _utc_ns(NOW.replace(year=NOW.year + 7)) + 1
    assert not repository.prune_eligible(verified.manifest_key)

    target = bytearray(b"protected existing archive")
    validation = repository.restore_range(
        [verified.manifest_key],
        start_ns=0,
        end_ns=10,
        expected_source_schema="bars-v1",
        temporary_destination=BytesIO(),
        atomic_commit=_commit_to(target),
        lineage_id="lineage-hold-check",
        audit_id="audit-hold-check",
    )
    assert not validation.committed
    assert target == b"protected existing archive"

    with pytest.raises(R2ArchiveError) as held:
        repository.restore_range(
            [verified.manifest_key],
            start_ns=0,
            end_ns=10,
            expected_source_schema="bars-v1",
            temporary_destination=BytesIO(),
            atomic_commit=_commit_to(target),
            lineage_id="lineage-hold-overwrite",
            audit_id="audit-hold-overwrite",
            commit=True,
            overwrite_existing=True,
        )
    assert held.value.code == "LEGAL_HOLD"
    assert target == b"protected existing archive"


def test_exact_seven_year_horizon_and_pruning_boundaries() -> None:
    archive_ns = _utc_ns(NOW)
    horizon_ns = _utc_ns(NOW.replace(year=NOW.year + 7))
    now_ns = [archive_ns]
    transport, port, repository = _repository(clock_ns=lambda: now_ns[0])
    pending, _manifest = _pending(repository, port)
    complete = repository.mark_complete(pending.manifest_key)
    _install_lock(
        transport,
        manifest_digest=complete.manifest_digest,
        retention_start_utc_ns=archive_ns,
        retention_end_utc_ns=horizon_ns,
        lifecycle_expiration_utc_ns=horizon_ns,
    )

    # Matching proof alone cannot make a COMPLETE archive prune eligible.
    now_ns[0] = horizon_ns + 1
    assert not repository.prune_eligible(complete.manifest_key)

    now_ns[0] = archive_ns
    verified = repository.mark_verified(complete.manifest_key)
    assert verified.state is R2ManifestStateV1.VERIFIED

    # Start equality is active; pruning waits until strictly after the horizon.
    now_ns[0] = horizon_ns
    assert not repository.prune_eligible(verified.manifest_key)
    now_ns[0] = horizon_ns + 1
    assert repository.prune_eligible(verified.manifest_key)


def test_lock_expiring_at_now_is_expired_and_cannot_verify() -> None:
    archive_ns = _utc_ns(NOW)
    horizon_ns = _utc_ns(NOW.replace(year=NOW.year + 7))
    now_ns = [horizon_ns]
    transport, port, repository = _repository(clock_ns=lambda: now_ns[0])
    pending, _manifest = _pending(repository, port)
    complete = repository.mark_complete(pending.manifest_key)
    _install_lock(
        transport,
        manifest_digest=complete.manifest_digest,
        retention_start_utc_ns=archive_ns,
        retention_end_utc_ns=horizon_ns,
        lifecycle_expiration_utc_ns=horizon_ns,
    )

    with pytest.raises(R2ArchiveError) as expired:
        repository.mark_verified(complete.manifest_key)

    assert expired.value.code == "LOCK_EXPIRED"
    assert repository.get(complete.manifest_key).state is R2ManifestStateV1.COMPLETE
    assert not repository.prune_eligible(complete.manifest_key)


def test_active_lock_short_of_archive_horizon_cannot_verify() -> None:
    archive_ns = _utc_ns(NOW)
    now_ns = [archive_ns]
    transport, port, repository = _repository(clock_ns=lambda: now_ns[0])
    pending, _manifest = _pending(repository, port)
    complete = repository.mark_complete(pending.manifest_key)
    _install_lock(
        transport,
        manifest_digest=complete.manifest_digest,
        retention_start_utc_ns=archive_ns,
        retention_end_utc_ns=_utc_ns(NOW.replace(year=NOW.year + 6)),
        lifecycle_expiration_utc_ns=None,
    )

    with pytest.raises(R2ArchiveError) as insufficient:
        repository.mark_verified(complete.manifest_key)

    assert insufficient.value.code == "LOCK_INSUFFICIENT_RETENTION"
    assert repository.get(complete.manifest_key).state is R2ManifestStateV1.COMPLETE
    assert not repository.prune_eligible(complete.manifest_key)


def test_lock_bound_to_another_manifest_digest_is_unbound() -> None:
    transport, port, repository = _repository()
    first, _first_manifest = _pending(repository, port, partition_key="archive-one")
    first_complete = repository.mark_complete(first.manifest_key)
    _install_lock(transport, manifest_digest=first_complete.manifest_digest)

    second, _second_manifest = _pending(repository, port, partition_key="archive-two")
    second_complete = repository.mark_complete(second.manifest_key)
    with pytest.raises(R2ArchiveError) as unbound:
        repository.mark_verified(second_complete.manifest_key)

    assert unbound.value.code == "LOCK_UNBOUND"
    assert repository.get(second_complete.manifest_key).state is R2ManifestStateV1.COMPLETE
    assert not repository.prune_eligible(second_complete.manifest_key)


def test_range_gap_never_publishes_and_preserves_existing_target() -> None:
    _transport_value, port, repository = _repository()
    verified, _manifest = _verified(repository, port, payload=b"whole-range")
    target = bytearray(b"existing-published-range")
    commits = 0

    def commit(source: BytesIO) -> None:
        nonlocal commits
        commits += 1
        target[:] = source.read()

    with pytest.raises(R2ArchiveError) as uncovered:
        repository.restore_range(
            [verified.manifest_key],
            start_ns=0,
            end_ns=11,
            expected_source_schema="bars-v1",
            temporary_destination=BytesIO(),
            atomic_commit=commit,
            lineage_id="lineage-gap",
            audit_id="audit-gap",
            commit=True,
        )

    assert uncovered.value.code == "RESTORE_RANGE_NOT_COVERED"
    assert commits == 0
    assert target == b"existing-published-range"
    assert repository.restore_audit == ()


def test_commit_requires_a_callback_and_successful_publish_calls_it_once() -> None:
    _transport_value, port, repository = _repository()
    verified, _manifest = _verified(repository, port)

    with pytest.raises(R2ArchiveError) as no_callback:
        repository.restore_range(
            [verified.manifest_key],
            start_ns=0,
            end_ns=10,
            expected_source_schema="bars-v1",
            temporary_destination=BytesIO(),
            lineage_id="lineage-no-callback",
            audit_id="audit-no-callback",
            commit=True,
        )
    assert no_callback.value.code == "INVALID_RESTORE_REQUEST"

    published = bytearray()
    calls = 0

    def commit(source: BytesIO) -> None:
        nonlocal calls
        calls += 1
        published[:] = source.read()

    temp = BytesIO(b"stale temporary contents")
    result = repository.restore_range(
        [verified.manifest_key],
        start_ns=0,
        end_ns=10,
        expected_source_schema="bars-v1",
        temporary_destination=temp,
        atomic_commit=commit,
        lineage_id="lineage-publish-once",
        audit_id="audit-publish-once",
        commit=True,
    )

    assert result.committed
    assert calls == 1
    assert published == b"archive-payload"
    assert result.bytes_restored == len(published)
    assert repository.restore_audit == (result,)
