from __future__ import annotations

import copy
import pickle
from dataclasses import dataclass
from decimal import Decimal

import pytest
from leviathan_store.neon.snapshot_models import (
    CommittedRecordV1,
    SnapshotRecoveryError,
    make_committed_record,
)
from leviathan_store.neon.snapshot_repository import SnapshotRepositoryV1

from leviathan_core.seal import SealError, require
from leviathan_market_data.live import (
    LiveSubscriptionKernel,
    LiveSubscriptionV1,
    make_live_subscription,
)

_UTC_BASE = 1_800_000_000_000_000_000
_STREAM = ("fake", "dataset", "XNAS", "ABC", "trades", "session-1")


@dataclass
class FakeClock:
    utc_ns: int = _UTC_BASE
    mono_ns: int = 10_000_000_000

    def utc_now_ns(self) -> int:
        return self.utc_ns

    def monotonic_ns(self) -> int:
        return self.mono_ns


class FakeLiveSource:
    def subscribe(
        self, subscription: LiveSubscriptionV1, resume_token: str | None
    ) -> str | None:
        del subscription, resume_token
        return "resume-token"

    def unsubscribe(self, subscription: LiveSubscriptionV1) -> None:
        del subscription

    def poll(self, subscription: LiveSubscriptionV1) -> tuple[object, ...]:
        del subscription
        return ()


class FakeCommittedReplayPort:
    def __init__(self, records: tuple[CommittedRecordV1, ...] = ()) -> None:
        self.records = records
        self.high_water: dict[tuple[str, str], int] = {}

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
            record
            for record in self.records
            if record.scope_id == scope_id
            and record.instrument_id == instrument_id
            and after_offset < record.committed_offset <= through_offset
        )


def record(
    offset: int,
    payload: bytes,
    *,
    key: str | None = None,
    scope: str = "org-1",
    instrument: str = "ABC",
    event_offset: int | None = None,
    watermark: int | None = None,
) -> CommittedRecordV1:
    return make_committed_record(
        scope_id=scope,
        instrument_id=instrument,
        committed_offset=offset,
        source_event_offset=offset if event_offset is None else event_offset,
        semantic_key=f"event-{offset}" if key is None else key,
        payload=payload,
        watermark_utc_ns=_UTC_BASE + offset if watermark is None else watermark,
    )


def ready_verdict(
    *, clock: FakeClock | None = None, instrument_id: str = "ABC"
):
    live_clock = clock or FakeClock()
    source = FakeLiveSource()
    subscription = make_live_subscription(
        provider="fake",
        dataset="dataset",
        venue="XNAS",
        instrument_id=instrument_id,
        channel="trades",
        session_id="session-1",
        heartbeat_interval_ns=1_000_000_000,
        sequence_policy="unavailable",
        required_group="test-streams",
    )
    kernel = LiveSubscriptionKernel(
        clock=live_clock,
        source=source,
        max_streams=16,
    )
    kernel.subscribe(subscription, entitlement="GRANTED")
    kernel.set_node_drift(subscription.stream_key, Decimal("0"))
    return kernel.on_heartbeat(
        subscription.stream_key,
        session_id="session-1",
        provider_time_ns=live_clock.utc_ns,
    )


def apply_payload(state: bytes, event: CommittedRecordV1) -> bytes:
    return state + event.payload


def make_repo(
    replay: FakeCommittedReplayPort,
    clock: FakeClock,
    *,
    max_age_ns: int = 1_000_000_000,
    max_records: int = 100,
) -> SnapshotRepositoryV1:
    return SnapshotRepositoryV1(
        replay,
        clock_ns=lambda: clock.utc_ns,
        max_snapshot_age_ns=max_age_ns,
        max_replay_records=max_records,
    )


def create_snapshot(
    repo: SnapshotRepositoryV1,
    *,
    scope: str = "org-1",
    instrument: str = "ABC",
    payload: bytes = b"base:",
    offset: int = 1,
    watermark: int = _UTC_BASE,
    schema: str = "state-v1",
):
    return repo.create_snapshot(
        scope_id=scope,
        instrument_id=instrument,
        state_schema=schema,
        state_bytes=payload,
        source_event_offset=offset,
        committed_wal_offset=offset,
        watermark_utc_ns=watermark,
        lineage=("source-1", "job-1"),
    )


def test_snapshot_replays_contiguous_offsets_once_by_semantic_key() -> None:
    clock = FakeClock()
    events = (
        record(2, b"a", key="same-event", event_offset=7, watermark=_UTC_BASE + 10),
        record(3, b"a", key="same-event", event_offset=7, watermark=_UTC_BASE + 10),
    )
    replay = FakeCommittedReplayPort(events)
    replay.high_water[("org-1", "ABC")] = 3
    repo = make_repo(replay, clock)
    manifest = create_snapshot(repo, offset=1)
    clock.utc_ns = _UTC_BASE + 10

    recovered = repo.recover(
        scope_id="org-1",
        instrument_id="ABC",
        expected_state_schema="state-v1",
        expected_committed_wal_offset=3,
        expected_watermark_utc_ns=_UTC_BASE + 10,
        freshness_verdict=ready_verdict(clock=clock),
        expected_stream_key=_STREAM,
        apply_record=apply_payload,
    )

    assert manifest.committed_wal_offset == 1
    assert recovered.state_bytes == b"base:a"
    assert recovered.status == "HEALTHY"
    assert recovered.traffic_allowed is True
    assert recovered.committed_wal_offset == 3
    assert recovered.replayed_count == 1
    assert recovered.duplicate_count == 1
    assert recovered.reason_codes == ()
    require(recovered, "stor003.recovery_result.v1")


def test_interrupted_staging_keeps_last_good_snapshot_visible() -> None:
    clock = FakeClock()
    replay = FakeCommittedReplayPort()
    replay.high_water[("org-1", "ABC")] = 1
    repo = make_repo(replay, clock)
    original = create_snapshot(repo)

    with pytest.raises(SnapshotRecoveryError) as raised:
        repo.create_snapshot(
            scope_id="org-1",
            instrument_id="ABC",
            state_schema="state-v1",
            state_bytes=b"partial",
            source_event_offset=1,
            committed_wal_offset=1,
            watermark_utc_ns=_UTC_BASE,
            lineage=("source-1", "job-1"),
            fail_after_temp_write=True,
        )

    assert raised.value.code == "SNAPSHOT_INTERRUPTED"
    assert repo.latest_manifest(scope_id="org-1", instrument_id="ABC").snapshot_id == (
        original.snapshot_id
    )
    recovered = repo.recover(
        scope_id="org-1",
        instrument_id="ABC",
        expected_state_schema="state-v1",
        expected_committed_wal_offset=1,
        expected_watermark_utc_ns=_UTC_BASE,
        freshness_verdict=ready_verdict(clock=clock),
        expected_stream_key=_STREAM,
        apply_record=apply_payload,
    )
    assert recovered.status == "HEALTHY"
    assert recovered.state_bytes == b"base:"


def test_same_capture_point_cannot_publish_conflicting_snapshot_bytes() -> None:
    clock = FakeClock()
    replay = FakeCommittedReplayPort()
    replay.high_water[("org-1", "ABC")] = 0
    repo = make_repo(replay, clock)
    original = create_snapshot(repo, payload=b"last-good", offset=0)

    with pytest.raises(SnapshotRecoveryError) as raised:
        create_snapshot(repo, payload=b"different", offset=0)

    assert raised.value.code == "SNAPSHOT_CONFLICT"
    assert repo.latest_manifest(scope_id="org-1", instrument_id="ABC").snapshot_id == (
        original.snapshot_id
    )


def test_corrupt_snapshot_uses_bounded_warm_read_and_never_allows_traffic() -> None:
    clock = FakeClock()
    events = (
        record(1, b"first", watermark=_UTC_BASE + 1),
        record(2, b"second", watermark=_UTC_BASE + 2),
    )
    replay = FakeCommittedReplayPort(events)
    replay.high_water[("org-1", "ABC")] = 2
    repo = make_repo(replay, clock)
    manifest = create_snapshot(repo, offset=1)
    repo.inject_corruption_for_test(snapshot_id=manifest.snapshot_id, replacement=b"corrupt")
    clock.utc_ns = _UTC_BASE + 2

    recovered = repo.recover(
        scope_id="org-1",
        instrument_id="ABC",
        expected_state_schema="state-v1",
        expected_committed_wal_offset=2,
        expected_watermark_utc_ns=_UTC_BASE + 2,
        freshness_verdict=ready_verdict(clock=clock),
        expected_stream_key=_STREAM,
        apply_record=apply_payload,
    )

    assert recovered.status == "DEGRADED"
    assert recovered.traffic_allowed is False
    assert recovered.used_snapshot is False
    assert recovered.used_warm_read is True
    assert recovered.state_bytes == b"firstsecond"
    assert recovered.reason_codes == ("SNAPSHOT_CORRUPT",)


def test_corrupt_newest_snapshot_falls_back_to_latest_valid_checkpoint() -> None:
    clock = FakeClock()
    events = (record(2, b"tail", watermark=_UTC_BASE + 2),)
    replay = FakeCommittedReplayPort(events)
    replay.high_water[("org-1", "ABC")] = 2
    repo = make_repo(replay, clock, max_records=1)
    clock.utc_ns = _UTC_BASE + 2
    older = create_snapshot(repo, payload=b"checkpoint:", offset=1, watermark=_UTC_BASE + 1)
    newer = create_snapshot(repo, payload=b"newer:", offset=2, watermark=_UTC_BASE + 2)
    repo.inject_corruption_for_test(snapshot_id=newer.snapshot_id, replacement=b"corrupt")

    recovered = repo.recover(
        scope_id="org-1",
        instrument_id="ABC",
        expected_state_schema="state-v1",
        expected_committed_wal_offset=2,
        expected_watermark_utc_ns=_UTC_BASE + 2,
        freshness_verdict=ready_verdict(clock=clock),
        expected_stream_key=_STREAM,
        apply_record=apply_payload,
    )

    assert recovered.status == "HEALTHY", recovered.reason_codes
    assert recovered.traffic_allowed is True
    assert recovered.used_snapshot is True
    assert recovered.used_warm_read is False
    assert recovered.snapshot_id == older.snapshot_id
    assert recovered.state_bytes == b"checkpoint:tail"
    assert recovered.committed_wal_offset == 2
    assert recovered.reason_codes == ()


def test_stale_snapshot_warm_read_is_bounded_and_health_remains_degraded() -> None:
    clock = FakeClock()
    events = (record(1, b"one", watermark=_UTC_BASE + 1),)
    replay = FakeCommittedReplayPort(events)
    replay.high_water[("org-1", "ABC")] = 1
    repo = make_repo(replay, clock, max_age_ns=10)
    manifest = create_snapshot(repo, offset=0, watermark=_UTC_BASE)
    clock.utc_ns += 11

    recovered = repo.recover(
        scope_id="org-1",
        instrument_id="ABC",
        expected_state_schema="state-v1",
        expected_committed_wal_offset=1,
        expected_watermark_utc_ns=_UTC_BASE + 1,
        freshness_verdict=ready_verdict(clock=clock),
        expected_stream_key=_STREAM,
        apply_record=apply_payload,
    )

    assert manifest.snapshot_id is not None
    assert recovered.status == "DEGRADED"
    assert recovered.traffic_allowed is False
    assert recovered.used_warm_read is True
    assert recovered.reason_codes == ("SNAPSHOT_STALE",)
    assert recovered.state_bytes == b"one"


@pytest.mark.parametrize(
    ("offsets", "error_code"),
    [((3,), "WAL_GAP"), ((1, 2, 2), "WAL_REORDERED")],
)
def test_gap_or_reordered_offsets_fail_closed(offsets: tuple[int, ...], error_code: str) -> None:
    clock = FakeClock()
    events = tuple(record(value, b"x") for value in offsets)
    replay = FakeCommittedReplayPort(events)
    replay.high_water[("org-1", "ABC")] = 3
    repo = make_repo(replay, clock)
    create_snapshot(repo, offset=0)
    clock.utc_ns = _UTC_BASE + offsets[-1]

    recovered = repo.recover(
        scope_id="org-1",
        instrument_id="ABC",
        expected_state_schema="state-v1",
        expected_committed_wal_offset=replay.committed_through(
            scope_id="org-1", instrument_id="ABC"
        ),
        expected_watermark_utc_ns=_UTC_BASE + offsets[-1],
        freshness_verdict=ready_verdict(clock=clock),
        expected_stream_key=_STREAM,
        apply_record=apply_payload,
    )

    assert recovered.status == "DEGRADED"
    assert recovered.traffic_allowed is False
    assert recovered.reason_codes == (error_code,)


def test_expected_commit_offset_must_match_port_high_water() -> None:
    clock = FakeClock()
    replay = FakeCommittedReplayPort()
    replay.high_water[("org-1", "ABC")] = 2
    repo = make_repo(replay, clock)
    create_snapshot(repo, offset=1)

    recovered = repo.recover(
        scope_id="org-1",
        instrument_id="ABC",
        expected_state_schema="state-v1",
        expected_committed_wal_offset=1,
        expected_watermark_utc_ns=_UTC_BASE,
        freshness_verdict=ready_verdict(clock=clock),
        expected_stream_key=_STREAM,
        apply_record=apply_payload,
    )

    assert recovered.status == "DEGRADED"
    assert recovered.reason_codes == ("OFFSET_MISMATCH",)
    assert recovered.traffic_allowed is False
    assert recovered.used_warm_read is False


def test_schema_and_watermark_mismatch_never_publish_healthy() -> None:
    clock = FakeClock()
    events = (record(1, b"x", watermark=_UTC_BASE + 5),)
    replay = FakeCommittedReplayPort(events)
    replay.high_water[("org-1", "ABC")] = 1
    repo = make_repo(replay, clock)
    create_snapshot(repo, offset=0)
    clock.utc_ns = _UTC_BASE + 5

    wrong_schema = repo.recover(
        scope_id="org-1",
        instrument_id="ABC",
        expected_state_schema="state-v2",
        expected_committed_wal_offset=1,
        expected_watermark_utc_ns=_UTC_BASE + 5,
        freshness_verdict=ready_verdict(clock=clock),
        expected_stream_key=_STREAM,
        apply_record=apply_payload,
    )
    wrong_watermark = repo.recover(
        scope_id="org-1",
        instrument_id="ABC",
        expected_state_schema="state-v1",
        expected_committed_wal_offset=1,
        expected_watermark_utc_ns=_UTC_BASE + 4,
        freshness_verdict=ready_verdict(clock=clock),
        expected_stream_key=_STREAM,
        apply_record=apply_payload,
    )

    assert wrong_schema.reason_codes == ("SNAPSHOT_SCHEMA_MISMATCH",)
    assert wrong_schema.used_warm_read is True
    assert wrong_schema.traffic_allowed is False
    assert wrong_watermark.reason_codes == ("WATERMARK_MISMATCH",)
    assert wrong_watermark.traffic_allowed is False


def test_md004_verdict_must_be_sealed_healthy_and_match_stream() -> None:
    clock = FakeClock()
    replay = FakeCommittedReplayPort()
    replay.high_water[("org-1", "ABC")] = 0
    repo = make_repo(replay, clock)
    create_snapshot(repo, offset=0)
    wrong_stream = ready_verdict(clock=clock, instrument_id="XYZ")

    recovered = repo.recover(
        scope_id="org-1",
        instrument_id="ABC",
        expected_state_schema="state-v1",
        expected_committed_wal_offset=0,
        expected_watermark_utc_ns=_UTC_BASE,
        freshness_verdict=wrong_stream,
        expected_stream_key=_STREAM,
        apply_record=apply_payload,
    )

    assert recovered.status == "DEGRADED"
    assert recovered.reason_codes == ("FRESHNESS_BLOCKED",)
    assert recovered.traffic_allowed is False

    with pytest.raises(SnapshotRecoveryError) as raised:
        repo.recover(
            scope_id="org-1",
            instrument_id="ABC",
            expected_state_schema="state-v1",
            expected_committed_wal_offset=0,
            expected_watermark_utc_ns=_UTC_BASE,
            freshness_verdict=wrong_stream,
            expected_stream_key=("fake", "dataset", "XNAS", "XYZ", "trades", "session-1"),
            apply_record=apply_payload,
        )
    assert raised.value.code == "FRESHNESS_BLOCKED"


def test_old_md004_verdict_cannot_publish_even_when_snapshot_is_valid() -> None:
    clock = FakeClock()
    replay = FakeCommittedReplayPort()
    replay.high_water[("org-1", "ABC")] = 0
    repo = make_repo(replay, clock)
    create_snapshot(repo, offset=0)
    verdict = ready_verdict(clock=clock)
    clock.utc_ns += 1

    recovered = repo.recover(
        scope_id="org-1",
        instrument_id="ABC",
        expected_state_schema="state-v1",
        expected_committed_wal_offset=0,
        expected_watermark_utc_ns=_UTC_BASE,
        freshness_verdict=verdict,
        expected_stream_key=_STREAM,
        apply_record=apply_payload,
    )

    assert recovered.status == "DEGRADED"
    assert recovered.reason_codes == ("FRESHNESS_BLOCKED",)
    assert recovered.traffic_allowed is False


def test_snapshot_age_bound_is_inclusive_and_one_nanosecond_over_degrades() -> None:
    clock = FakeClock()
    replay = FakeCommittedReplayPort()
    replay.high_water[("org-1", "ABC")] = 0
    repo = make_repo(replay, clock, max_age_ns=10)
    create_snapshot(repo, offset=0)
    clock.utc_ns += 10

    at_bound = repo.recover(
        scope_id="org-1",
        instrument_id="ABC",
        expected_state_schema="state-v1",
        expected_committed_wal_offset=0,
        expected_watermark_utc_ns=_UTC_BASE,
        freshness_verdict=ready_verdict(clock=clock),
        expected_stream_key=_STREAM,
        apply_record=apply_payload,
    )
    clock.utc_ns += 1
    past_bound = repo.recover(
        scope_id="org-1",
        instrument_id="ABC",
        expected_state_schema="state-v1",
        expected_committed_wal_offset=0,
        expected_watermark_utc_ns=_UTC_BASE,
        freshness_verdict=ready_verdict(clock=clock),
        expected_stream_key=_STREAM,
        apply_record=apply_payload,
    )

    assert at_bound.status == "HEALTHY"
    assert at_bound.traffic_allowed is True
    assert past_bound.status == "DEGRADED"
    assert past_bound.reason_codes == ("SNAPSHOT_STALE",)
    assert past_bound.traffic_allowed is False


def test_scope_and_instrument_snapshots_are_isolated() -> None:
    clock = FakeClock()
    replay = FakeCommittedReplayPort()
    replay.high_water[("org-1", "ABC")] = 0
    replay.high_water[("org-2", "ABC")] = 0
    repo = make_repo(replay, clock)
    create_snapshot(repo, scope="org-1", payload=b"one", offset=0)
    create_snapshot(repo, scope="org-2", payload=b"two", offset=0)

    result = repo.recover(
        scope_id="org-1",
        instrument_id="ABC",
        expected_state_schema="state-v1",
        expected_committed_wal_offset=0,
        expected_watermark_utc_ns=_UTC_BASE,
        freshness_verdict=ready_verdict(clock=clock),
        expected_stream_key=_STREAM,
        apply_record=apply_payload,
    )

    assert result.status == "HEALTHY"
    assert result.state_bytes == b"one"


def test_invalid_integer_boolean_and_sealed_record_fail_closed() -> None:
    with pytest.raises(SnapshotRecoveryError) as raised:
        make_committed_record(
            scope_id="org-1",
            instrument_id="ABC",
            committed_offset=True,
            source_event_offset=1,
            semantic_key="key-1",
            payload=b"x",
            watermark_utc_ns=_UTC_BASE,
        )
    assert raised.value.code == "INVALID_REPLAY_RECORD"

    issued = record(1, b"x")
    with pytest.raises(SealError):
        copy.copy(issued)
    with pytest.raises(SealError):
        copy.deepcopy(issued)
    with pytest.raises(SealError):
        pickle.dumps(issued)
    with pytest.raises(SealError):
        issued.__init__(
            scope_id="org-1",
            instrument_id="ABC",
            committed_offset=1,
            source_event_offset=1,
            semantic_key="key-2",
            payload=b"canary",
            watermark_utc_ns=_UTC_BASE,
        )
    require(issued, "stor003.committed_record.v1")


def test_bounded_warm_read_limit_degrades_without_partial_state() -> None:
    clock = FakeClock()
    events = tuple(
        record(offset, b"x", watermark=_UTC_BASE + offset) for offset in range(1, 4)
    )
    replay = FakeCommittedReplayPort(events)
    replay.high_water[("org-1", "ABC")] = 3
    repo = make_repo(replay, clock, max_records=2)
    clock.utc_ns = _UTC_BASE + 3

    recovered = repo.recover(
        scope_id="org-1",
        instrument_id="ABC",
        expected_state_schema="state-v1",
        expected_committed_wal_offset=3,
        expected_watermark_utc_ns=_UTC_BASE + 3,
        freshness_verdict=ready_verdict(clock=clock),
        expected_stream_key=_STREAM,
        apply_record=apply_payload,
    )

    assert recovered.status == "DEGRADED"
    assert recovered.traffic_allowed is False
    assert recovered.reason_codes == ("WAL_LIMIT_EXCEEDED",)
    assert recovered.state_bytes == b""
