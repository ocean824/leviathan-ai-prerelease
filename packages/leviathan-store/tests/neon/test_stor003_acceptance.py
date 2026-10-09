from __future__ import annotations

import copy
import hashlib
import pickle
from collections.abc import Callable
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, cast

import pytest
from leviathan_store.neon.snapshot_models import (
    CommittedRecordV1,
    SnapshotManifestV1,
    SnapshotRecoveryError,
    SnapshotRecoveryResultV1,
    make_committed_record,
)
from leviathan_store.neon.snapshot_repository import SnapshotRepositoryV1

from leviathan_core.seal import SealError, require
from leviathan_market_data.live import (
    FreshnessVerdictV1,
    LiveSourcePort,
    LiveSubscriptionKernel,
    LiveSubscriptionV1,
    make_live_subscription,
)
from leviathan_market_data.schema import NormalizedMarketEventV1

BASE_NS = 1_800_000_000_000_000_000
SCOPE = "org-a"
INSTRUMENT = "ABC"
STREAM_KEY = ("fake", "trades", "XNAS", INSTRUMENT, "prints", "session-1")
MANIFEST_TAG = "stor003.snapshot_manifest.v1"
RECORD_TAG = "stor003.committed_record.v1"
RESULT_TAG = "stor003.recovery_result.v1"


@dataclass(slots=True)
class FakeClock:
    utc_ns: int = BASE_NS
    mono_ns: int = 10_000_000_000

    def utc_now_ns(self) -> int:
        return self.utc_ns

    def monotonic_ns(self) -> int:
        return self.mono_ns


class FakeLiveSource(LiveSourcePort):
    def subscribe(
        self, subscription: LiveSubscriptionV1, resume_token: str | None
    ) -> str | None:
        del subscription, resume_token
        return None

    def unsubscribe(self, subscription: LiveSubscriptionV1) -> None:
        del subscription

    def poll(
        self, subscription: LiveSubscriptionV1
    ) -> tuple[NormalizedMarketEventV1, ...]:
        del subscription
        return ()


class FakeCommittedReplayPort:
    """Synthetic committed log with an opt-in scope-filter violation seam."""

    def __init__(self) -> None:
        self.records: tuple[CommittedRecordV1, ...] = ()
        self.high_water: dict[tuple[str, str], int] = {}
        self.return_foreign_scope_rows = False

    def committed_through(self, *, scope_id: str, instrument_id: str) -> int:
        return self.high_water.get((scope_id, instrument_id), 0)

    def read_committed(
        self,
        *,
        scope_id: str,
        instrument_id: str,
        after_offset: int,
        through_offset: int,
    ) -> tuple[CommittedRecordV1, ...]:
        return tuple(
            row
            for row in self.records
            if after_offset < row.committed_offset <= through_offset
            and (
                self.return_foreign_scope_rows
                or (row.scope_id, row.instrument_id) == (scope_id, instrument_id)
            )
        )


def make_repo(
    replay: FakeCommittedReplayPort,
    clock: FakeClock,
    *,
    max_age_ns: int = 60,
    max_records: int = 100,
) -> SnapshotRepositoryV1:
    return SnapshotRepositoryV1(
        replay,
        clock_ns=lambda: clock.utc_ns,
        max_snapshot_age_ns=max_age_ns,
        max_replay_records=max_records,
    )


def make_record(
    offset: int,
    payload: bytes,
    *,
    scope: str = SCOPE,
    instrument: str = INSTRUMENT,
    semantic_key: str | None = None,
    source_event_offset: int | None = None,
    watermark_ns: int | None = None,
) -> CommittedRecordV1:
    return make_committed_record(
        scope_id=scope,
        instrument_id=instrument,
        committed_offset=offset,
        source_event_offset=offset if source_event_offset is None else source_event_offset,
        semantic_key=f"event-{offset}" if semantic_key is None else semantic_key,
        payload=payload,
        watermark_utc_ns=BASE_NS + offset if watermark_ns is None else watermark_ns,
    )


def publish_snapshot(
    repo: SnapshotRepositoryV1,
    *,
    scope: str = SCOPE,
    instrument: str = INSTRUMENT,
    payload: bytes = b"snapshot:",
    offset: int = 0,
    watermark_ns: int = BASE_NS,
    schema: str = "state-v1",
    lineage: tuple[str, ...] = ("market-data", "job-1"),
    fail_after_temp_write: bool = False,
) -> SnapshotManifestV1:
    return repo.create_snapshot(
        scope_id=scope,
        instrument_id=instrument,
        state_schema=schema,
        state_bytes=payload,
        source_event_offset=offset,
        committed_wal_offset=offset,
        watermark_utc_ns=watermark_ns,
        lineage=lineage,
        fail_after_temp_write=fail_after_temp_write,
    )


def ready_verdict(
    clock: FakeClock,
    *,
    instrument: str = INSTRUMENT,
    entitlement: str = "GRANTED",
) -> FreshnessVerdictV1:
    key = ("fake", "trades", "XNAS", instrument, "prints", "session-1")
    spec = make_live_subscription(
        provider=key[0],
        dataset=key[1],
        venue=key[2],
        instrument_id=key[3],
        channel=key[4],
        session_id=key[5],
        heartbeat_interval_ns=1_000_000_000,
        sequence_policy="unavailable",
        required_group="acceptance",
    )
    kernel = LiveSubscriptionKernel(
        clock=clock,
        source=FakeLiveSource(),
        max_streams=4,
    )
    kernel.subscribe(spec, entitlement=entitlement)  # type: ignore[arg-type]
    kernel.set_node_drift(key, Decimal(0))
    return kernel.on_heartbeat(
        key,
        session_id=key[5],
        provider_time_ns=clock.utc_ns,
    )


def append_record(state: bytes, record: CommittedRecordV1) -> bytes:
    return state + record.payload


def recover(
    repo: SnapshotRepositoryV1,
    clock: FakeClock,
    *,
    scope: str = SCOPE,
    instrument: str = INSTRUMENT,
    schema: str = "state-v1",
    committed_offset: int,
    watermark_ns: int,
    verdict: FreshnessVerdictV1 | None = None,
    stream_key: tuple[str, str, str, str, str, str] | None = None,
    apply_record: Callable[[bytes, CommittedRecordV1], bytes] = append_record,
) -> SnapshotRecoveryResultV1:
    return repo.recover(
        scope_id=scope,
        instrument_id=instrument,
        expected_state_schema=schema,
        expected_committed_wal_offset=committed_offset,
        expected_watermark_utc_ns=watermark_ns,
        freshness_verdict=verdict or ready_verdict(clock, instrument=instrument),
        expected_stream_key=STREAM_KEY if stream_key is None else stream_key,
        apply_record=apply_record,
    )


def test_manifest_binds_scope_schema_offsets_watermark_bytes_digest_and_lineage() -> None:
    clock = FakeClock()
    replay = FakeCommittedReplayPort()
    replay.high_water[(SCOPE, INSTRUMENT)] = 4
    repo = make_repo(replay, clock)
    payload = b"known-state\x00bytes"

    manifest = repo.create_snapshot(
        scope_id=SCOPE,
        instrument_id=INSTRUMENT,
        state_schema="order-book/v3",
        state_bytes=payload,
        source_event_offset=37,
        committed_wal_offset=4,
        watermark_utc_ns=BASE_NS - 1,
        lineage=("feed-1", "checkpoint-4"),
    )

    assert manifest.scope_id == SCOPE
    assert manifest.instrument_id == INSTRUMENT
    assert manifest.state_schema == "order-book/v3"
    assert manifest.source_event_offset == 37
    assert manifest.committed_wal_offset == 4
    assert manifest.watermark_utc_ns == BASE_NS - 1
    assert manifest.created_utc_ns == BASE_NS
    assert manifest.byte_length == len(payload)
    assert manifest.sha256_digest == hashlib.sha256(payload).hexdigest()
    assert manifest.lineage == ("feed-1", "checkpoint-4")
    require(manifest, MANIFEST_TAG)


def test_failed_temporary_publish_keeps_last_good_snapshot_and_recovery_visible() -> None:
    clock = FakeClock()
    replay = FakeCommittedReplayPort()
    replay.high_water[(SCOPE, INSTRUMENT)] = 0
    repo = make_repo(replay, clock)
    last_good = publish_snapshot(repo, payload=b"last-good")

    with pytest.raises(SnapshotRecoveryError) as raised:
        publish_snapshot(repo, payload=b"SECRET partial bytes", fail_after_temp_write=True)

    assert raised.value.code == "SNAPSHOT_INTERRUPTED"
    assert "SECRET" not in str(raised.value)
    assert repo.latest_manifest(scope_id=SCOPE, instrument_id=INSTRUMENT) == last_good
    result = recover(repo, clock, committed_offset=0, watermark_ns=BASE_NS)
    assert result.status == "HEALTHY"
    assert result.traffic_allowed is True
    assert result.state_bytes == b"last-good"


def test_identical_snapshot_retry_is_idempotent_and_conflict_preserves_last_good() -> None:
    clock = FakeClock()
    replay = FakeCommittedReplayPort()
    replay.high_water[(SCOPE, INSTRUMENT)] = 0
    repo = make_repo(replay, clock)
    original = publish_snapshot(repo, payload=b"same")
    repeated = publish_snapshot(repo, payload=b"same")

    assert repeated == original
    with pytest.raises(SnapshotRecoveryError) as raised:
        publish_snapshot(repo, payload=b"different")
    assert raised.value.code == "SNAPSHOT_CONFLICT"
    assert repo.latest_manifest(scope_id=SCOPE, instrument_id=INSTRUMENT) == original


@pytest.mark.parametrize("replacement", [b"tampered-length", b"evil"])
def test_corrupt_snapshot_degrades_to_warm_read_without_traffic(
    replacement: bytes,
) -> None:
    clock = FakeClock()
    replay = FakeCommittedReplayPort()
    replay.records = (make_record(1, b"committed"),)
    replay.high_water[(SCOPE, INSTRUMENT)] = 1
    repo = make_repo(replay, clock)
    manifest = publish_snapshot(repo, payload=b"base", offset=0)
    repo.inject_corruption_for_test(snapshot_id=manifest.snapshot_id, replacement=replacement)
    clock.utc_ns = BASE_NS + 1

    result = recover(repo, clock, committed_offset=1, watermark_ns=BASE_NS + 1)

    assert result.status == "DEGRADED"
    assert result.traffic_allowed is False
    assert result.used_snapshot is False
    assert result.used_warm_read is True
    assert result.state_bytes == b"committed"
    assert result.reason_codes == ("SNAPSHOT_CORRUPT",)


def test_corrupt_newest_snapshot_falls_back_to_older_valid_checkpoint() -> None:
    clock = FakeClock()
    replay = FakeCommittedReplayPort()
    replay.records = (
        make_record(
            2,
            b"tail",
            semantic_key="tail-event-2",
            source_event_offset=22,
            watermark_ns=BASE_NS + 2,
        ),
    )
    replay.high_water[(SCOPE, INSTRUMENT)] = 2
    repo = make_repo(replay, clock, max_records=1)
    older = publish_snapshot(
        repo,
        payload=b"checkpoint-1:",
        offset=1,
        watermark_ns=BASE_NS,
    )
    clock.utc_ns = BASE_NS + 1
    newer = publish_snapshot(
        repo,
        payload=b"checkpoint-2-corrupt-me",
        offset=2,
        watermark_ns=BASE_NS + 1,
    )
    repo.inject_corruption_for_test(snapshot_id=newer.snapshot_id, replacement=b"corrupt")
    clock.utc_ns = BASE_NS + 2
    applied_offsets: list[int] = []

    def apply_tail(state: bytes, row: CommittedRecordV1) -> bytes:
        applied_offsets.append(row.committed_offset)
        return state + row.payload

    result = recover(
        repo,
        clock,
        committed_offset=2,
        watermark_ns=BASE_NS + 2,
        apply_record=apply_tail,
    )

    assert older.committed_wal_offset == 1
    assert newer.committed_wal_offset == 2
    assert result.status == "HEALTHY"
    assert result.traffic_allowed is True
    assert result.used_snapshot is True
    assert result.used_warm_read is False
    assert result.snapshot_id == older.snapshot_id
    assert result.state_bytes == b"checkpoint-1:tail"
    assert result.committed_wal_offset == 2
    assert result.source_event_offset == 22
    assert result.replayed_count == 1
    assert result.duplicate_count == 0
    assert applied_offsets == [2]


def test_stale_snapshot_uses_only_bounded_warm_read_and_remains_degraded() -> None:
    clock = FakeClock()
    replay = FakeCommittedReplayPort()
    replay.records = (make_record(1, b"fresh-wal", watermark_ns=BASE_NS + 11),)
    replay.high_water[(SCOPE, INSTRUMENT)] = 1
    repo = make_repo(replay, clock, max_age_ns=10)
    publish_snapshot(repo, payload=b"old", offset=0)
    clock.utc_ns = BASE_NS + 11

    result = recover(repo, clock, committed_offset=1, watermark_ns=BASE_NS + 11)

    assert result.status == "DEGRADED"
    assert result.traffic_allowed is False
    assert result.used_warm_read is True
    assert result.state_bytes == b"fresh-wal"
    assert result.reason_codes == ("SNAPSHOT_STALE",)


def test_snapshot_age_is_inclusive_at_limit_and_stale_one_nanosecond_later() -> None:
    clock = FakeClock()
    replay = FakeCommittedReplayPort()
    replay.high_water[(SCOPE, INSTRUMENT)] = 0
    repo = make_repo(replay, clock, max_age_ns=10)
    publish_snapshot(repo, offset=0)
    clock.utc_ns = BASE_NS + 10

    boundary = recover(repo, clock, committed_offset=0, watermark_ns=BASE_NS)
    clock.utc_ns += 1
    expired = recover(repo, clock, committed_offset=0, watermark_ns=BASE_NS)

    assert boundary.status == "HEALTHY"
    assert boundary.traffic_allowed is True
    assert expired.status == "DEGRADED"
    assert expired.reason_codes == ("SNAPSHOT_STALE",)
    assert expired.traffic_allowed is False


def test_recovery_selects_latest_valid_snapshot_for_exact_scope_and_instrument() -> None:
    clock = FakeClock()
    replay = FakeCommittedReplayPort()
    replay.high_water[(SCOPE, INSTRUMENT)] = 2
    repo = make_repo(replay, clock)
    old = publish_snapshot(repo, payload=b"older", offset=1, watermark_ns=BASE_NS)
    clock.utc_ns = BASE_NS + 2
    latest = publish_snapshot(
        repo,
        payload=b"latest",
        offset=2,
        watermark_ns=BASE_NS + 2,
    )

    result = recover(repo, clock, committed_offset=2, watermark_ns=BASE_NS + 2)

    assert latest.created_utc_ns > old.created_utc_ns
    assert result.status == "HEALTHY"
    assert result.traffic_allowed is True
    assert result.snapshot_id == latest.snapshot_id
    assert result.state_bytes == b"latest"


@pytest.mark.parametrize(
    ("schema", "watermark"),
    [
        ("state-v2", BASE_NS + 1),
        ("state-v1", BASE_NS + 2),
    ],
)
def test_schema_or_watermark_mismatch_never_exposes_healthy_state(
    schema: str, watermark: int
) -> None:
    clock = FakeClock()
    replay = FakeCommittedReplayPort()
    replay.records = (make_record(1, b"tail", watermark_ns=BASE_NS + 1),)
    replay.high_water[(SCOPE, INSTRUMENT)] = 1
    repo = make_repo(replay, clock)
    publish_snapshot(repo, payload=b"base", offset=0)
    clock.utc_ns = max(BASE_NS + 1, watermark)

    result = recover(
        repo,
        clock,
        schema=schema,
        committed_offset=1,
        watermark_ns=watermark,
    )

    assert result.status == "DEGRADED"
    assert result.traffic_allowed is False
    assert result.reason_codes


def test_replay_starts_after_snapshot_offset_and_applies_semantic_key_once() -> None:
    clock = FakeClock()
    replay = FakeCommittedReplayPort()
    same_event = (
        make_record(2, b"delta", semantic_key="feed-seq-44", source_event_offset=44,
                    watermark_ns=BASE_NS + 9),
        make_record(3, b"delta", semantic_key="feed-seq-44", source_event_offset=44,
                    watermark_ns=BASE_NS + 9),
    )
    replay.records = same_event
    replay.high_water[(SCOPE, INSTRUMENT)] = 3
    repo = make_repo(replay, clock)
    manifest = publish_snapshot(repo, payload=b"base:", offset=1, watermark_ns=BASE_NS)
    clock.utc_ns = BASE_NS + 9
    applied: list[str] = []

    def apply_once(state: bytes, row: CommittedRecordV1) -> bytes:
        applied.append(row.semantic_key)
        return state + row.payload

    result = recover(
        repo,
        clock,
        committed_offset=3,
        watermark_ns=BASE_NS + 9,
        apply_record=apply_once,
    )

    assert manifest.committed_wal_offset == 1
    assert result.status == "HEALTHY"
    assert result.traffic_allowed is True
    assert result.state_bytes == b"base:delta"
    assert result.source_event_offset == 44
    assert result.committed_wal_offset == 3
    assert result.replayed_count == 1
    assert result.duplicate_count == 1
    assert applied == ["feed-seq-44"]


@pytest.mark.parametrize(
    ("records", "high_water", "expected_reason"),
    [
        ((make_record(2, b"gap", watermark_ns=BASE_NS + 2),), 2, "WAL_GAP"),
        (
            (
                make_record(1, b"first", watermark_ns=BASE_NS + 1),
                make_record(1, b"repeat-offset", watermark_ns=BASE_NS + 1),
            ),
            1,
            "WAL_REORDERED",
        ),
        (
            (make_record(1, b"foreign", scope="org-b", watermark_ns=BASE_NS + 1),),
            1,
            "WAL_SCOPE_MISMATCH",
        ),
        (
            (
                make_record(1, b"first", semantic_key="same-key", watermark_ns=BASE_NS + 1),
                make_record(2, b"conflict", semantic_key="same-key", watermark_ns=BASE_NS + 2),
            ),
            2,
            "WAL_CONFLICT",
        ),
    ],
)
def test_wal_gap_reordering_scope_leak_and_semantic_conflict_fail_closed(
    records: tuple[CommittedRecordV1, ...], high_water: int, expected_reason: str
) -> None:
    clock = FakeClock()
    replay = FakeCommittedReplayPort()
    replay.records = records
    replay.high_water[(SCOPE, INSTRUMENT)] = high_water
    replay.return_foreign_scope_rows = expected_reason == "WAL_SCOPE_MISMATCH"
    repo = make_repo(replay, clock)
    publish_snapshot(repo, payload=b"before:", offset=0)
    clock.utc_ns = BASE_NS + high_water

    result = recover(
        repo,
        clock,
        committed_offset=high_water,
        watermark_ns=BASE_NS + high_water,
    )

    assert result.status == "DEGRADED"
    assert result.traffic_allowed is False
    assert result.reason_codes == (expected_reason,)
    assert result.state_bytes == b""


def test_committed_high_water_mismatch_and_uncommitted_snapshot_offset_are_denied() -> None:
    clock = FakeClock()
    replay = FakeCommittedReplayPort()
    replay.high_water[(SCOPE, INSTRUMENT)] = 2
    repo = make_repo(replay, clock)

    with pytest.raises(SnapshotRecoveryError) as raised:
        publish_snapshot(repo, offset=3)
    assert raised.value.code == "OFFSET_UNCOMMITTED"

    publish_snapshot(repo, offset=1)
    result = recover(repo, clock, committed_offset=1, watermark_ns=BASE_NS)
    assert result.status == "DEGRADED"
    assert result.traffic_allowed is False
    assert result.reason_codes == ("OFFSET_MISMATCH",)


def test_missing_snapshot_warm_read_is_bounded_and_never_live_eligible() -> None:
    clock = FakeClock()
    replay = FakeCommittedReplayPort()
    replay.records = tuple(
        make_record(i, f"{i}".encode(), watermark_ns=BASE_NS + i) for i in range(1, 4)
    )
    replay.high_water[(SCOPE, INSTRUMENT)] = 3
    repo = make_repo(replay, clock, max_records=2)
    clock.utc_ns = BASE_NS + 3

    result = recover(repo, clock, committed_offset=3, watermark_ns=BASE_NS + 3)

    assert result.status == "DEGRADED"
    assert result.traffic_allowed is False
    assert result.used_snapshot is False
    assert result.used_warm_read is True
    assert result.reason_codes
    assert result.state_bytes == b""


def test_snapshot_and_replay_are_isolated_by_both_scope_and_instrument() -> None:
    clock = FakeClock()
    replay = FakeCommittedReplayPort()
    for scope, instrument in (("org-a", "ABC"), ("org-b", "ABC"), ("org-a", "XYZ")):
        replay.high_water[(scope, instrument)] = 0
    repo = make_repo(replay, clock)
    publish_snapshot(repo, scope="org-a", instrument="ABC", payload=b"tenant-a-symbol-a")
    publish_snapshot(repo, scope="org-b", instrument="ABC", payload=b"tenant-b-symbol-a")
    publish_snapshot(repo, scope="org-a", instrument="XYZ", payload=b"tenant-a-symbol-b")

    result = recover(repo, clock, scope="org-a", instrument="ABC", committed_offset=0,
                     watermark_ns=BASE_NS)

    assert result.status == "HEALTHY"
    assert result.state_bytes == b"tenant-a-symbol-a"
    assert result.snapshot_id == repo.latest_manifest(
        scope_id="org-a", instrument_id="ABC"
    ).snapshot_id
    assert result.state_bytes not in (b"tenant-b-symbol-a", b"tenant-a-symbol-b")


@pytest.mark.parametrize("failure", ["forged", "stale", "wrong-stream", "unentitled"])
def test_recovery_requires_current_sealed_healthy_publication_verdict(failure: str) -> None:
    clock = FakeClock()
    replay = FakeCommittedReplayPort()
    replay.high_water[(SCOPE, INSTRUMENT)] = 0
    repo = make_repo(replay, clock)
    publish_snapshot(repo, offset=0)
    if failure == "forged":
        verdict = FreshnessVerdictV1(
            stream_key=STREAM_KEY,
            state="HEALTHY",
            evaluated_utc_ns=clock.utc_ns,
            publication_allowed=True,
            execution_eligible=False,
            heartbeat_age_ns=0,
            node_drift_ms=Decimal(0),
            reason_codes=(),
        )
    elif failure == "wrong-stream":
        verdict = ready_verdict(clock, instrument="XYZ")
    elif failure == "unentitled":
        verdict = ready_verdict(clock, entitlement="UNKNOWN")
    else:
        verdict = ready_verdict(clock)
        clock.utc_ns += 1

    result = recover(
        repo,
        clock,
        committed_offset=0,
        watermark_ns=BASE_NS,
        verdict=verdict,
    )

    assert result.status == "DEGRADED"
    assert result.traffic_allowed is False
    assert result.reason_codes == ("FRESHNESS_BLOCKED",)


def test_public_snapshot_errors_are_typed_content_free_and_reject_bool_offsets() -> None:
    clock = FakeClock()
    replay = FakeCommittedReplayPort()
    repo = make_repo(replay, clock)

    with pytest.raises(SnapshotRecoveryError) as invalid_scope:
        publish_snapshot(repo, scope="SECRET bad\nidentity")
    assert invalid_scope.value.code == "INVALID_IDENTITY"
    assert "SECRET" not in str(invalid_scope.value)
    assert "SECRET" not in repr(invalid_scope.value.args)
    assert invalid_scope.value.__cause__ is None
    assert invalid_scope.value.__context__ is None

    with pytest.raises(SnapshotRecoveryError) as bool_offset:
        repo.create_snapshot(
            scope_id=SCOPE,
            instrument_id=INSTRUMENT,
            state_schema="state-v1",
            state_bytes=b"x",
            source_event_offset=True,
            committed_wal_offset=0,
            watermark_utc_ns=BASE_NS,
            lineage=("source",),
        )
    assert bool_offset.value.code == "INVALID_OFFSET"


def test_issued_models_reject_copy_pickle_reinitialization_and_forged_validation() -> None:
    clock = FakeClock()
    replay = FakeCommittedReplayPort()
    replay.high_water[(SCOPE, INSTRUMENT)] = 1
    replay.records = (make_record(1, b"tail", watermark_ns=BASE_NS + 1),)
    repo = make_repo(replay, clock)
    manifest = publish_snapshot(repo, payload=b"base", offset=0)
    record = replay.records[0]
    clock.utc_ns += 1
    result = recover(repo, clock, committed_offset=1, watermark_ns=BASE_NS + 1)

    issued = (
        (manifest, MANIFEST_TAG),
        (record, RECORD_TAG),
        (result, RESULT_TAG),
    )
    for value, tag in issued:
        require(value, tag)
        with pytest.raises(SealError):
            copy.copy(value)
        with pytest.raises(SealError):
            copy.deepcopy(value)
        with pytest.raises(SealError):
            pickle.dumps(value)
        model_construct = cast(Any, value).model_construct
        with pytest.raises(SealError):
            model_construct()
        with pytest.raises(SealError):
            value.__setstate__({"scope_id": "forged"})

    copied_manifest = manifest.model_copy(update={"scope_id": "org-b"})
    with pytest.raises(SealError):
        require(copied_manifest, MANIFEST_TAG)
    direct_manifest = SnapshotManifestV1(**manifest.model_dump())
    with pytest.raises(SealError):
        require(direct_manifest, MANIFEST_TAG)
    with pytest.raises(SealError):
        cast(Any, manifest).__init__(**manifest.model_dump())
    require(manifest, MANIFEST_TAG)


def test_invalid_public_model_input_does_not_echo_canary() -> None:
    with pytest.raises(SealError) as raised:
        SnapshotManifestV1(
            scope_id="SECRET bad id",
            instrument_id=INSTRUMENT,
            state_schema="state-v1",
            source_event_offset=0,
            committed_wal_offset=0,
            watermark_utc_ns=BASE_NS,
            byte_length=0,
            sha256_digest="0" * 64,
            created_utc_ns=BASE_NS,
            lineage=("source",),
            snapshot_id="snapshot-1",
        )
    assert raised.value.code == "SEAL_INVALID_MODEL"
    assert "SECRET" not in str(raised.value)
    assert "SECRET" not in repr(raised.value.args)
