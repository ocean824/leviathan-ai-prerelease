"""Focused tests for append durability, checkpointing and fail-closed replay."""

from __future__ import annotations

import errno
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from capability_support import issue_test_capability

from leviathan_market_data.ingress import SinkAck
from leviathan_market_data.live.checkpoint import (
    AtomicCheckpoint,
    GapManifestV1,
    NativeResumePositionV1,
    SinkCommitReceiptV1,
)
from leviathan_market_data.live.replay import (
    CommittingSink,
    DeterministicReplay,
    NativeContinuitySnapshotV1,
    SessionTransitionConfirmationV1,
    SourceAdapter,
    TrustedProviderCapabilityV1,
)
from leviathan_market_data.live.wal import (
    AppendOnlyWal,
    RawWalRecordV1,
    SessionTransitionEvidenceV1,
    WalError,
)

IDENTITY = ("provider", "dataset", "venue", "instrument", "trades")


class _SourcePort:
    provider_id = "provider"

    def __init__(
        self,
        *,
        session: str = "s1",
        next_sequence: int = 1,
        gaps: tuple[tuple[int, int], ...] = (),
        transition_confirmed: bool = True,
    ) -> None:
        self.session = session
        self.next_sequence = next_sequence
        self.gaps = gaps
        self.transition_confirmed = transition_confirmed

    def continuity_snapshot(self) -> NativeContinuitySnapshotV1:
        return NativeContinuitySnapshotV1(
            session_id=self.session,
            next_sequence=self.next_sequence,
            resume_token="resume-1",
            gap_ranges=self.gaps,
        )

    def confirm_session_transition(
        self, old_session_id: str, new_session_id: str
    ) -> SessionTransitionConfirmationV1:
        return SessionTransitionConfirmationV1(
            from_session_id=old_session_id,
            to_session_id=new_session_id,
            status="CONFIRMED" if self.transition_confirmed else "UNCONFIRMED",
        )


def _append(
    wal: AppendOnlyWal, sequence: int = 1, session: str = "s1"
) -> RawWalRecordV1:
    source = _SourcePort()
    evidence = (
        _trusted_adapter(source).confirm_session_transition("s1", session)
        if session != "s1"
        else None
    )
    return wal.append(
        stream_identity=IDENTITY,
        session_id=session,
        source_record_key=f"key-{session}-{sequence}",
        native_record_id=f"id-{session}-{sequence}",
        native_sequence=sequence,
        source_time_ns=1_000 + sequence,
        received_time_ns=2_000 + sequence,
        raw_payload=f"record-{session}-{sequence}".encode(),
        session_transition_evidence=evidence,
    )


def _trusted_adapter(source: _SourcePort) -> SourceAdapter:
    """Test-only issuance for the future reviewed-provider registration gate."""
    capability = issue_test_capability(source, source.provider_id)
    return SourceAdapter(source, capability)


class _Sink:
    def __init__(self, *acks: SinkAck) -> None:
        self.acks = list(acks)
        self.accepted: list[object] = []

    def write(self, record: object) -> SinkAck:
        self.accepted.append(record)
        return self.acks.pop(0) if self.acks else SinkAck(accepted=True)


def _proof(record: RawWalRecordV1) -> SinkCommitReceiptV1:
    result = CommittingSink(_Sink()).write(record)
    if not isinstance(result, SinkCommitReceiptV1):
        pytest.fail("synthetic sink did not commit the record")
    return result


def test_append_is_fsynced_before_return_and_reopens(tmp_path: Path) -> None:
    points: list[str] = []
    wal = AppendOnlyWal(tmp_path / "feed.wal", fault_hook=points.append)
    record = _append(wal)

    assert points == ["wal.after_write_before_fsync", "wal.after_fsync_before_ack"]
    assert record.raw_payload == b"record-s1-1"
    assert (
        AppendOnlyWal(tmp_path / "feed.wal").read_all()[0].source_record_key
        == record.source_record_key
    )


def test_duplicate_is_idempotent_and_conflict_quarantines(tmp_path: Path) -> None:
    wal = AppendOnlyWal(tmp_path / "feed.wal")
    record = _append(wal)
    duplicate = wal.append(
        stream_identity=IDENTITY,
        session_id="s1",
        source_record_key="key-s1-1",
        native_record_id="id-s1-1",
        native_sequence=1,
        source_time_ns=1_001,
        received_time_ns=3_000,
        raw_payload=b"record-s1-1",
    )
    assert duplicate is record
    with pytest.raises(WalError) as caught:
        wal.append(
            stream_identity=IDENTITY,
            session_id="s1",
            source_record_key="key-s1-1",
            native_record_id="id-s1-1",
            native_sequence=1,
            source_time_ns=1_001,
            received_time_ns=3_001,
            raw_payload=b"conflicting",
        )
    assert caught.value.code == "SOURCE_KEY_CONFLICT"
    assert wal.quarantine_paths


def test_gap_and_unconfirmed_session_change_fail_closed(tmp_path: Path) -> None:
    wal = AppendOnlyWal(tmp_path / "feed.wal")
    _append(wal)
    with pytest.raises(WalError) as gap:
        _append(wal, 3)
    assert gap.value.code == "SEQUENCE_GAP"
    with pytest.raises(WalError) as transition:
        wal.append(
            stream_identity=IDENTITY,
            session_id="s2",
            source_record_key="new-session",
            native_record_id="n2",
            native_sequence=1,
            source_time_ns=3,
            received_time_ns=4,
            raw_payload=b"next",
        )
    assert transition.value.code == "SESSION_RESET_UNCONFIRMED"


def test_torn_tail_is_quarantined_with_evidence_and_not_skipped(tmp_path: Path) -> None:
    path = tmp_path / "feed.wal"
    wal = AppendOnlyWal(path)
    _append(wal)
    with path.open("ab") as stream:
        stream.write(b"torn")
    reopened = AppendOnlyWal(path)
    assert len(reopened.quarantine_paths) == 1
    assert reopened.quarantine_paths[0].read_bytes() == b"torn"
    with pytest.raises(WalError) as caught:
        reopened.read_all()
    assert caught.value.code == "WAL_QUARANTINED"


def test_disk_full_is_non_ack_and_stops_intake(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    wal = AppendOnlyWal(tmp_path / "feed.wal")
    real_write = os.write

    def full(_fd: int, _data: object) -> int:
        raise OSError(errno.ENOSPC, "synthetic")

    monkeypatch.setattr("leviathan_market_data.live.wal.os.write", full)
    with pytest.raises(WalError) as caught:
        _append(wal)
    assert caught.value.code == "BACKPRESSURE"
    assert caught.value.acknowledged is False
    assert caught.value.stop_intake is True
    monkeypatch.setattr("leviathan_market_data.live.wal.os.write", real_write)
    with pytest.raises(WalError):
        _append(wal)


@pytest.mark.parametrize(
    ("stream_identity", "session_id", "source_record_key"),
    [
        (("prøvider", "dataset", "venue", "instrument", "trades"), "s1", "k1"),
        (("provider", "dataset", "venue", "instrument", "trades"), "sés-session", "k1"),
        (("provider", "dataset", "venue", "instrument", "trades"), "s1", "clé-1"),
    ],
)
def test_wal_rejects_non_ascii_identity_and_session_fields(
    tmp_path: Path,
    stream_identity: tuple[str, str, str, str, str],
    session_id: str,
    source_record_key: str,
) -> None:
    wal = AppendOnlyWal(tmp_path / "feed.wal")
    with pytest.raises(WalError) as caught:
        wal.append(
            stream_identity=stream_identity,
            session_id=session_id,
            source_record_key=source_record_key,
            native_record_id="native-1",
            native_sequence=1,
            source_time_ns=1,
            received_time_ns=2,
            raw_payload=b"record",
        )
    assert caught.value.code == "INVALID_RECORD"


def test_wal_and_checkpoint_size_limits_precede_unbounded_reads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    wal_path = tmp_path / "oversized.wal"
    wal_path.write_bytes(b"x" * 65)
    checkpoint_path = tmp_path / "oversized.checkpoint"
    checkpoint_path.write_bytes(b"x" * 16_385)

    def forbidden_read_bytes(_path: Path) -> bytes:
        raise AssertionError("whole-file read_bytes must not be used")

    monkeypatch.setattr(Path, "read_bytes", forbidden_read_bytes)
    with pytest.raises(WalError) as wal_error:
        AppendOnlyWal(wal_path, max_bytes=64)
    assert wal_error.value.code == "BACKPRESSURE"
    with pytest.raises(WalError) as checkpoint_error:
        AtomicCheckpoint(checkpoint_path).load()
    assert checkpoint_error.value.code == "CHECKPOINT_CORRUPT"


def test_wal_capped_read_detects_growth_after_stat(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "growing.wal"
    path.write_bytes(b"")
    original_stat = Path.stat
    original_open = Path.open
    path_stat_calls = 0

    def stat(candidate: Path, *args: Any, **kwargs: Any) -> os.stat_result:
        nonlocal path_stat_calls
        result = original_stat(candidate, *args, **kwargs)
        if candidate == path:
            path_stat_calls += 1
            if path_stat_calls == 2:
                return cast(os.stat_result, SimpleNamespace(st_size=0))
        return result

    def open_file(
        candidate: Path, mode: str = "r", *args: Any, **kwargs: Any
    ) -> Any:
        if candidate == path and mode == "rb":
            with original_open(candidate, "wb") as handle:
                handle.write(b"x" * 65)
        return original_open(candidate, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", cast(Any, stat))
    monkeypatch.setattr(Path, "open", cast(Any, open_file))
    with pytest.raises(WalError) as caught:
        AppendOnlyWal(path, max_bytes=64)
    assert caught.value.code == "BACKPRESSURE"


def test_checkpoint_capped_read_detects_growth_after_stat(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "growing.checkpoint"
    path.write_bytes(b"")
    original_open = Path.open

    def stat(candidate: Path, *args: Any, **kwargs: Any) -> os.stat_result:
        result = os.stat(candidate, *args, **kwargs)
        return cast(os.stat_result, SimpleNamespace(st_size=0)) if candidate == path else result

    def open_file(
        candidate: Path, mode: str = "r", *args: Any, **kwargs: Any
    ) -> Any:
        if candidate == path and mode == "rb":
            with original_open(candidate, "wb") as handle:
                handle.write(b"x" * 16_385)
        return original_open(candidate, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", cast(Any, stat))
    monkeypatch.setattr(Path, "open", cast(Any, open_file))
    with pytest.raises(WalError) as caught:
        AtomicCheckpoint(path).load()
    assert caught.value.code == "CHECKPOINT_CORRUPT"


def test_replay_checkpoint_and_native_continuity_use_sequence_cursor(tmp_path: Path) -> None:
    wal = AppendOnlyWal(tmp_path / "feed.wal")
    first = _append(wal)
    checkpoint = AtomicCheckpoint(tmp_path / "feed.checkpoint")
    sink = _Sink()
    replay = DeterministicReplay(wal, checkpoint, sink)
    receipts = replay.replay()

    assert [receipt.status for receipt in receipts] == ["COMMITTED"]
    saved = checkpoint.load()
    assert saved is not None
    assert saved.committed_byte_offset == first.byte_offset + first.frame_size
    assert not replay.live_ready
    position, gaps = _trusted_adapter(
        _SourcePort(session="s1", next_sequence=2)
    ).continuity()
    verdict = replay.reconcile_native_position(position, gaps)
    assert verdict.status == "CONTINUOUS"
    assert verdict.committed_sequence == 1
    assert replay.live_ready


def test_checkpoint_cannot_advance_without_sink_commit_receipt(tmp_path: Path) -> None:
    wal = AppendOnlyWal(tmp_path / "feed.wal")
    record = _append(wal)
    checkpoint = AtomicCheckpoint(tmp_path / "feed.checkpoint")
    with pytest.raises(WalError) as caught:
        checkpoint.commit(record)
    assert caught.value.code == "UNISSUED_VALUE"
    assert checkpoint.load() is None

    sink = _Sink()
    receipts = DeterministicReplay(wal, checkpoint, sink).replay()
    assert [receipt.status for receipt in receipts] == ["COMMITTED"]
    assert len(sink.accepted) == 1
    assert checkpoint.load() is not None


def test_sink_commit_receipt_cannot_be_reused_for_another_record(tmp_path: Path) -> None:
    wal = AppendOnlyWal(tmp_path / "feed.wal")
    first = _append(wal, 1)
    second = _append(wal, 2)
    checkpoint = AtomicCheckpoint(tmp_path / "feed.checkpoint")
    proof = _proof(first)
    with pytest.raises(WalError) as caught:
        checkpoint.commit(second, proof)
    assert caught.value.code == "UNISSUED_VALUE"
    assert checkpoint.load() is None


def test_caller_minted_continuity_values_are_unknown(tmp_path: Path) -> None:
    wal = AppendOnlyWal(tmp_path / "feed.wal")
    _append(wal)
    replay = DeterministicReplay(wal, AtomicCheckpoint(tmp_path / "cp"), _Sink())
    replay.replay()
    verdict = replay.reconcile_native_position(
        NativeResumePositionV1(provider_id="provider", session_id="s1", next_sequence=2),
        GapManifestV1(provider_id="provider", session_id="s1"),
    )
    assert verdict.status == "UNKNOWN"
    assert verdict.live_ready is False
    assert replay.live_ready is False


def test_source_without_continuity_protocol_remains_unknown(tmp_path: Path) -> None:
    wal = AppendOnlyWal(tmp_path / "feed.wal")
    _append(wal)
    replay = DeterministicReplay(wal, AtomicCheckpoint(tmp_path / "cp"), _Sink())
    replay.replay()
    untrusted_source = _SourcePort(session="s1", next_sequence=2)
    untrusted = SourceAdapter(untrusted_source)
    position, gaps = untrusted.continuity()
    assert untrusted.confirm_session_transition("s1", "s2") is None
    verdict = replay.reconcile_native_position(position, gaps)
    assert verdict.status == "UNKNOWN"
    assert verdict.live_ready is False
    assert replay.live_ready is False


def test_trusted_provider_capability_is_issued_bound_and_provider_scoped() -> None:
    source = _SourcePort(session="s1", next_sequence=2)
    capability = issue_test_capability(source, "provider")
    assert _trusted_adapter(source).continuity()[0] is not None
    assert SourceAdapter(source).continuity() == (None, None)
    forged = TrustedProviderCapabilityV1(provider_id="provider")
    assert SourceAdapter(source, forged).continuity() == (None, None)

    other = _SourcePort(session="s1", next_sequence=2)
    assert SourceAdapter(other, capability).continuity() == (None, None)
    source.provider_id = "other-provider"
    assert SourceAdapter(source, capability).continuity() == (None, None)


def test_valid_provider_capability_cannot_reconcile_another_wal_provider(
    tmp_path: Path,
) -> None:
    wal = AppendOnlyWal(tmp_path / "other-provider.wal")
    wal.append(
        stream_identity=("provider-b", "dataset", "venue", "instrument", "trades"),
        session_id="s1",
        source_record_key="key-s1-1",
        native_record_id="id-s1-1",
        native_sequence=1,
        source_time_ns=1_001,
        received_time_ns=2_001,
        raw_payload=b"record-s1-1",
    )
    replay = DeterministicReplay(wal, AtomicCheckpoint(tmp_path / "other-provider.cp"), _Sink())
    assert [receipt.status for receipt in replay.replay()] == ["COMMITTED"]

    source = _SourcePort(session="s1", next_sequence=2)
    source.provider_id = "provider-a"
    position, gaps = _trusted_adapter(source).continuity()
    verdict = replay.reconcile_native_position(position, gaps)

    assert verdict.status == "PROVIDER_MISMATCH"
    assert verdict.live_ready is False
    assert replay.live_ready is False


def test_caller_minted_transition_evidence_cannot_reset_wal(tmp_path: Path) -> None:
    wal = AppendOnlyWal(tmp_path / "feed.wal")
    _append(wal)
    with pytest.raises(WalError) as caught:
        wal.append(
            stream_identity=IDENTITY,
            session_id="s2",
            source_record_key="key-s2-1",
            native_record_id="id-s2-1",
            native_sequence=1,
            source_time_ns=1_001,
            received_time_ns=2_001,
            raw_payload=b"record-s2-1",
            session_transition_evidence=SessionTransitionEvidenceV1(
                provider_id="provider",
                from_session_id="s1", to_session_id="s2"
            ),
        )
    assert caught.value.code == "UNKNOWN_CONTINUITY"


def test_session_transition_capability_cannot_cross_provider_boundaries(
    tmp_path: Path,
) -> None:
    wal = AppendOnlyWal(tmp_path / "provider-boundary.wal")
    other_identity = ("provider-b", "dataset", "venue", "instrument", "trades")
    wal.append(
        stream_identity=other_identity,
        session_id="s1",
        source_record_key="key-s1-1",
        native_record_id="id-s1-1",
        native_sequence=1,
        source_time_ns=1_001,
        received_time_ns=2_001,
        raw_payload=b"record-s1-1",
    )
    source = _SourcePort(session="s1")
    source.provider_id = "provider-a"
    evidence = _trusted_adapter(source).confirm_session_transition("s1", "s2")
    assert evidence is not None

    with pytest.raises(WalError) as caught:
        wal.append(
            stream_identity=other_identity,
            session_id="s2",
            source_record_key="key-s2-1",
            native_record_id="id-s2-1",
            native_sequence=1,
            source_time_ns=1_002,
            received_time_ns=2_002,
            raw_payload=b"record-s2-1",
            session_transition_evidence=evidence,
        )
    assert caught.value.code == "UNKNOWN_CONTINUITY"
    assert len(wal.read_all()) == 1


def test_gap_manifest_and_mismatched_native_position_fail_closed(tmp_path: Path) -> None:
    wal = AppendOnlyWal(tmp_path / "feed.wal")
    _append(wal)
    replay = DeterministicReplay(wal, AtomicCheckpoint(tmp_path / "cp"), _Sink())
    replay.replay()

    with_gap = replay.reconcile_native_position(
        *_trusted_adapter(
            _SourcePort(session="s1", next_sequence=2, gaps=((2, 4),))
        ).continuity(),
    )
    assert with_gap.status == "GAP_PRESENT"
    assert not with_gap.live_ready
    wrong_sequence = replay.reconcile_native_position(
        *_trusted_adapter(_SourcePort(session="s1", next_sequence=3)).continuity(),
    )
    assert wrong_sequence.status == "SEQUENCE_MISMATCH"
    assert not replay.live_ready


def test_backpressure_does_not_advance_checkpoint(tmp_path: Path) -> None:
    wal = AppendOnlyWal(tmp_path / "feed.wal")
    _append(wal)
    checkpoint = AtomicCheckpoint(tmp_path / "cp")
    receipts = DeterministicReplay(wal, checkpoint, _Sink(SinkAck(backpressure=True))).replay()
    assert [receipt.status for receipt in receipts] == ["BACKPRESSURE"]
    assert checkpoint.load() is None


def test_checkpoint_fault_after_sink_commit_is_reported_without_advancing_cursor(
    tmp_path: Path,
) -> None:
    wal = AppendOnlyWal(tmp_path / "feed.wal")
    _append(wal)
    checkpoint = AtomicCheckpoint(tmp_path / "cp")

    def fault(point: str) -> None:
        if point == "replay.after_sink_commit_before_checkpoint":
            raise RuntimeError("private sink detail")

    receipts = DeterministicReplay(wal, checkpoint, _Sink(), fault_hook=fault).replay()
    assert receipts[0].status == "CHECKPOINT_FAILURE"
    assert receipts[0].sink_committed
    assert receipts[0].reason == "CHECKPOINT_FAILURE"
    assert checkpoint.load() is None


@pytest.mark.parametrize(
    ("fault_point", "expected_sequence"),
    [
        ("checkpoint.after_temp_write_before_fsync", 1),
        ("checkpoint.after_temp_fsync_before_replace", 1),
        ("checkpoint.after_replace_before_directory_fsync", 2),
    ],
)
def test_checkpoint_replace_fault_boundaries_are_atomic_or_indeterminate(
    tmp_path: Path, fault_point: str, expected_sequence: int
) -> None:
    wal = AppendOnlyWal(tmp_path / "feed.wal")
    first = _append(wal, 1)
    second = _append(wal, 2)
    records = wal.read_all()
    path = tmp_path / f"{fault_point}.checkpoint"
    first_proof = _proof(first)
    AtomicCheckpoint(path).commit(first, first_proof)

    def fault(point: str) -> None:
        if point == fault_point:
            raise RuntimeError("injected")

    checkpoint = AtomicCheckpoint(path, fault_hook=fault)
    with pytest.raises(WalError) as caught:
        second_proof = _proof(second)
        checkpoint.commit(second, second_proof)
    assert caught.value.code == "CHECKPOINT_FAILURE"
    reloaded = AtomicCheckpoint(path).load()
    assert reloaded is not None
    assert reloaded.native_sequence == expected_sequence
    assert records[-1].native_sequence == 2


def test_confirmed_session_reset_replays_and_rebases_checkpoint(tmp_path: Path) -> None:
    wal_path = tmp_path / "feed.wal"
    wal = AppendOnlyWal(wal_path)
    _append(wal, 1, "s1")
    _append(wal, 1, "s2")
    wal = AppendOnlyWal(wal_path)
    checkpoint = AtomicCheckpoint(tmp_path / "cp")
    replay = DeterministicReplay(wal, checkpoint, _Sink())

    assert [receipt.status for receipt in replay.replay()] == ["COMMITTED", "COMMITTED"]
    position, gaps = _trusted_adapter(
        _SourcePort(session="s2", next_sequence=2)
    ).continuity()
    verdict = replay.reconcile_native_position(position, gaps)
    assert verdict.status == "CONTINUOUS"
    assert verdict.committed_sequence == 1


def test_subprocess_crash_after_fsync_replays_durably_appended_record(tmp_path: Path) -> None:
    path = tmp_path / "crash.wal"
    program = """
import os
import sys
from leviathan_market_data.live.wal import AppendOnlyWal
def crash(point):
    if point == "wal.after_fsync_before_ack":
        os._exit(77)
wal = AppendOnlyWal(sys.argv[1], fault_hook=crash)
wal.append(
    stream_identity=("provider", "dataset", "venue", "instrument", "trades"),
    session_id="s1",
    source_record_key="k1",
    native_record_id="n1",
    native_sequence=1,
    source_time_ns=10,
    received_time_ns=20,
    raw_payload=b"one",
)
"""
    crashed = subprocess.run([sys.executable, "-c", program, str(path)], check=False, timeout=10)
    assert crashed.returncode == 77
    assert len(AppendOnlyWal(path).read_all()) == 1


def test_subprocess_crash_after_sink_commit_retries_idempotently(tmp_path: Path) -> None:
    wal_path = tmp_path / "replay.wal"
    checkpoint_path = tmp_path / "replay.cp"
    marker_path = tmp_path / "sink.marker"
    wal = AppendOnlyWal(wal_path)
    _append(wal)
    program = """
import os
import sys
from pathlib import Path
from leviathan_market_data.ingress import SinkAck
from leviathan_market_data.live.checkpoint import AtomicCheckpoint
from leviathan_market_data.live.replay import DeterministicReplay
from leviathan_market_data.live.wal import AppendOnlyWal
class Sink:
    def write(self, record):
        Path(sys.argv[3]).write_text(record.source_record_key)
        return SinkAck(accepted=True)
def crash(point):
    if point == "replay.after_sink_commit_before_checkpoint":
        os._exit(78)
wal = AppendOnlyWal(sys.argv[1])
cp = AtomicCheckpoint(sys.argv[2])
DeterministicReplay(wal, cp, Sink(), fault_hook=crash).replay()
"""
    crashed = subprocess.run(
        [sys.executable, "-c", program, str(wal_path), str(checkpoint_path), str(marker_path)],
        check=False,
        timeout=10,
    )
    assert crashed.returncode == 78
    assert marker_path.read_text() == "key-s1-1"
    checkpoint = AtomicCheckpoint(checkpoint_path)
    assert checkpoint.load() is None

    class IdempotentSink(_Sink):
        def write(self, record: object) -> SinkAck:
            if marker_path.exists():
                return SinkAck(accepted=True)
            return super().write(record)

    resumed = DeterministicReplay(AppendOnlyWal(wal_path), checkpoint, IdempotentSink())
    result = resumed.replay()
    assert [item.status for item in result] == ["COMMITTED"]
    assert checkpoint.load() is not None
