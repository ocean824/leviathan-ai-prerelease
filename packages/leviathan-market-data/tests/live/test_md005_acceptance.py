from __future__ import annotations

import errno
import hashlib
import os
import subprocess
import sys
import textwrap
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace

import pytest
from capability_support import issue_test_capability

from leviathan_core.seal import SealError
from leviathan_market_data.ingress import SinkAck
from leviathan_market_data.live.checkpoint import (
    AtomicCheckpoint,
    CheckpointV1,
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
    SessionTransitionEvidenceV1,
    WalError,
)

STREAM_IDENTITY = ("synthetic-provider", "synthetic-dataset", "XTEST", "SYN-1", "trades")
SESSION = "synthetic-session-1"
BASE_TIME_NS = 1_770_000_000_000_000_000
PAYLOAD_1 = b'{"price":"101.25","size":"2"}'
PAYLOAD_2 = b'{"price":"101.50","size":"3"}'


def append_record(
    wal: AppendOnlyWal,
    *,
    sequence: int = 1,
    key: str | None = None,
    payload: bytes | None = None,
    session_id: str = SESSION,
    session_transition_evidence: SessionTransitionEvidenceV1 | None = None,
) -> object:
    return wal.append(
        stream_identity=STREAM_IDENTITY,
        session_id=session_id,
        source_record_key=key or f"synthetic-key-{session_id}-{sequence}",
        native_record_id=f"synthetic-native-{session_id}-{sequence}",
        native_sequence=sequence,
        source_time_ns=BASE_TIME_NS + sequence,
        received_time_ns=BASE_TIME_NS + sequence + 1,
        raw_payload=payload if payload is not None else PAYLOAD_1,
        session_transition_evidence=session_transition_evidence,
    )


class IdempotentSink:
    def __init__(self, acknowledgements: tuple[SinkAck, ...] = ()) -> None:
        self.acknowledgements = list(acknowledgements)
        self.accepted: dict[str, object] = {}
        self.calls: list[object] = []
        self.during_write: Callable[[object], None] | None = None

    def write(self, record: object) -> SinkAck:
        self.calls.append(record)
        if self.during_write is not None:
            self.during_write(record)
        key = record.source_record_key  # type: ignore[attr-defined]
        if key in self.accepted:
            return SinkAck(accepted=True)
        ack = self.acknowledgements.pop(0) if self.acknowledgements else SinkAck(accepted=True)
        if ack.accepted:
            self.accepted[key] = record
        return ack


def make_replay(
    wal_path: Path,
    checkpoint_path: Path,
    sink: IdempotentSink,
    *,
    wal: AppendOnlyWal | None = None,
    checkpoint: AtomicCheckpoint | None = None,
    fault_hook: Callable[[str], None] | None = None,
) -> tuple[AppendOnlyWal, AtomicCheckpoint, DeterministicReplay]:
    active_wal = wal or AppendOnlyWal(wal_path)
    active_checkpoint = checkpoint or AtomicCheckpoint(checkpoint_path)
    replay = DeterministicReplay(active_wal, active_checkpoint, sink, fault_hook=fault_hook)
    return active_wal, active_checkpoint, replay


class FakeContinuityPort:
    provider_id = STREAM_IDENTITY[0]

    def __init__(
        self,
        *,
        session_id: str = SESSION,
        next_sequence: int = 2,
        gap_ranges: tuple[tuple[int, int], ...] = (),
        transition_status: str = "CONFIRMED",
        transition_from_override: str | None = None,
        transition_to_override: str | None = None,
        fail_snapshot: bool = False,
    ) -> None:
        self.snapshot = NativeContinuitySnapshotV1(
            session_id=session_id,
            next_sequence=next_sequence,
            resume_token="synthetic-resume-token",
            gap_ranges=gap_ranges,
        )
        self.transition_status = transition_status
        self.transition_from_override = transition_from_override
        self.transition_to_override = transition_to_override
        self.fail_snapshot = fail_snapshot

    def continuity_snapshot(self) -> NativeContinuitySnapshotV1:
        if self.fail_snapshot:
            raise RuntimeError("SYNTHETIC_SOURCE_CANARY")
        return self.snapshot

    def confirm_session_transition(
        self, old_session_id: str, new_session_id: str
    ) -> SessionTransitionConfirmationV1:
        return SessionTransitionConfirmationV1(
            from_session_id=self.transition_from_override or old_session_id,
            to_session_id=self.transition_to_override or new_session_id,
            status=self.transition_status,  # type: ignore[arg-type]
        )


def trusted_source_adapter(source: FakeContinuityPort) -> SourceAdapter:
    capability = issue_test_capability(source, source.provider_id)
    return SourceAdapter(source, capability)


def error_code(call: Callable[[], object], expected: str) -> WalError:
    with pytest.raises(WalError) as caught:
        call()
    assert caught.value.code == expected
    assert str(caught.value) == expected
    assert caught.value.args == (expected,)
    return caught.value


def test_append_fsyncs_before_return_and_duplicate_key_is_idempotent(tmp_path: Path) -> None:
    path = tmp_path / "events.wal"
    fsync_calls: list[int] = []

    def recording_fsync(fd: int) -> None:
        fsync_calls.append(fd)
        os.fsync(fd)

    wal = AppendOnlyWal(path, fsync_fn=recording_fsync)
    fsync_calls.clear()  # Ignore durable creation of the empty WAL file.
    record = append_record(wal)

    assert len(fsync_calls) == 1
    assert record.byte_offset == 0  # type: ignore[attr-defined]
    assert record.frame_size > 0  # type: ignore[attr-defined]
    assert record.raw_payload == PAYLOAD_1  # type: ignore[attr-defined]
    assert record.raw_payload_sha256 == hashlib.sha256(PAYLOAD_1).hexdigest()  # type: ignore[attr-defined]

    duplicate = append_record(wal)
    assert duplicate == record
    assert len(fsync_calls) == 1
    assert len(wal.read_all()) == 1

    def conflict() -> object:
        return append_record(wal, payload=PAYLOAD_2)

    original_bytes = path.read_bytes()
    error_code(conflict, "SOURCE_KEY_CONFLICT")
    assert path.read_bytes() == original_bytes
    assert wal.quarantine_paths
    error_code(wal.read_all, "WAL_QUARANTINED")


@pytest.mark.parametrize(
    ("fault_point", "expected_fsync_calls"),
    [("wal.after_write_before_fsync", 0), ("wal.after_fsync_before_ack", 1)],
)
def test_wal_fault_before_ack_never_returns_an_unacknowledged_record(
    tmp_path: Path, fault_point: str, expected_fsync_calls: int
) -> None:
    path = tmp_path / f"{fault_point.rsplit('.', 1)[-1]}.wal"
    fsync_calls: list[int] = []

    def fsync_fn(fd: int) -> None:
        fsync_calls.append(fd)
        os.fsync(fd)

    def fault_hook(point: str) -> None:
        if point == fault_point:
            raise RuntimeError("SYNTHETIC_CRASH_CANARY")

    wal = AppendOnlyWal(path, fsync_fn=fsync_fn, fault_hook=fault_hook)
    fsync_calls.clear()
    error = error_code(lambda: append_record(wal), "DURABILITY_FAILURE")

    assert len(fsync_calls) == expected_fsync_calls
    assert "SYNTHETIC_CRASH_CANARY" not in repr(error)


@pytest.mark.parametrize("tail_kind", ["torn", "corrupt"])
def test_torn_or_corrupt_tail_is_quarantined_with_evidence_and_original_preserved(
    tmp_path: Path, tail_kind: str
) -> None:
    path = tmp_path / "tail.wal"
    wal = AppendOnlyWal(path)
    append_record(wal, sequence=1)
    second = append_record(wal, sequence=2, payload=PAYLOAD_2)
    pristine = path.read_bytes()
    tail_offset = second.byte_offset  # type: ignore[attr-defined]

    if tail_kind == "torn":
        damaged = pristine[: tail_offset + max(1, second.frame_size // 2)]  # type: ignore[attr-defined]
    else:
        damaged_bytes = bytearray(pristine)
        damaged_bytes[-1] ^= 0x01
        damaged = bytes(damaged_bytes)
    path.write_bytes(damaged)

    reopened = AppendOnlyWal(path)
    error_code(reopened.read_all, "WAL_QUARANTINED")
    assert len(reopened.quarantine_paths) == 1
    evidence_path = Path(reopened.quarantine_paths[0])
    assert evidence_path.exists()
    assert evidence_path.read_bytes() == damaged[tail_offset:]
    assert path.read_bytes() == damaged
    assert str(tail_offset) in evidence_path.name
    assert hashlib.sha256(damaged[tail_offset:]).hexdigest() in evidence_path.name

    error_code(reopened.read_all, "WAL_QUARANTINED")
    blocked = error_code(lambda: append_record(reopened, sequence=3), "BACKPRESSURE")
    assert blocked.acknowledged is False
    assert blocked.stop_intake is True
    assert path.read_bytes() == damaged


def test_gaps_reorders_and_unknown_sequence_fail_closed_before_append(tmp_path: Path) -> None:
    gap_wal = AppendOnlyWal(tmp_path / "gap.wal")
    gap_first = append_record(gap_wal, sequence=1)
    gap_bytes = (tmp_path / "gap.wal").read_bytes()
    gap_error = error_code(lambda: append_record(gap_wal, sequence=3), "SEQUENCE_GAP")
    assert gap_error.stop_intake is True
    assert gap_wal.read_all() == (gap_first,)
    assert (tmp_path / "gap.wal").read_bytes() == gap_bytes
    gap_second = append_record(gap_wal, sequence=2, payload=PAYLOAD_2)
    assert gap_wal.read_all() == (gap_first, gap_second)

    reorder_wal = gap_wal
    reorder_bytes = (tmp_path / "gap.wal").read_bytes()
    error_code(
        lambda: append_record(reorder_wal, sequence=1, key="synthetic-reordered-key"),
        "SEQUENCE_REORDER",
    )
    assert reorder_wal.read_all() == (gap_first, gap_second)
    assert (tmp_path / "gap.wal").read_bytes() == reorder_bytes
    third = append_record(reorder_wal, sequence=3)
    assert reorder_wal.read_all() == (gap_first, gap_second, third)

    unknown_wal = AppendOnlyWal(tmp_path / "unknown.wal")
    error_code(
        lambda: unknown_wal.append(
            stream_identity=STREAM_IDENTITY,
            session_id=SESSION,
            source_record_key="synthetic-unknown-sequence",
            native_record_id=None,
            native_sequence=None,  # type: ignore[arg-type]
            source_time_ns=None,
            received_time_ns=BASE_TIME_NS + 4,
            raw_payload=PAYLOAD_2,
        ),
        "UNKNOWN_CONTINUITY",
    )
    assert unknown_wal.read_all() == ()


def test_replay_is_deterministic_and_checkpoints_only_follow_sink_commit(tmp_path: Path) -> None:
    wal_path = tmp_path / "deterministic.wal"
    checkpoint_path = tmp_path / "deterministic.checkpoint"
    wal = AppendOnlyWal(wal_path)
    records = (
        append_record(wal, sequence=1),
        append_record(wal, sequence=2, payload=PAYLOAD_2),
    )
    checkpoint = AtomicCheckpoint(checkpoint_path)
    sink = IdempotentSink()
    observed_before_commit: list[object | None] = []

    def inspect_checkpoint(_record: object) -> None:
        observed_before_commit.append(checkpoint.load())

    sink.during_write = inspect_checkpoint
    replay = DeterministicReplay(wal, checkpoint, sink)
    receipts = replay.replay()

    assert [receipt.status for receipt in receipts] == ["COMMITTED", "COMMITTED"]
    assert all(receipt.sink_committed for receipt in receipts)
    assert observed_before_commit[0] is None
    assert observed_before_commit[1].native_sequence == 1  # type: ignore[union-attr]

    saved = checkpoint.load()
    assert saved is not None
    assert saved.native_sequence == 2
    assert saved.source_record_key == records[1].source_record_key  # type: ignore[attr-defined]
    assert saved.payload_sha256 == records[1].raw_payload_sha256  # type: ignore[attr-defined]
    assert saved.committed_byte_offset == records[1].byte_offset + records[1].frame_size  # type: ignore[attr-defined]
    assert saved.generation >= 2
    assert saved.committed_byte_offset != saved.native_sequence

    sink_calls = len(sink.calls)
    again = replay.replay()
    assert len(sink.calls) == sink_calls
    assert checkpoint.load() == saved
    assert all(receipt.status in ("DUPLICATE", "COMMITTED") for receipt in again)


def test_checkpoint_cannot_skip_a_record_without_matching_sink_proof(tmp_path: Path) -> None:
    wal = AppendOnlyWal(tmp_path / "proof-required.wal")
    first = append_record(wal, sequence=1)
    second = append_record(wal, sequence=2, payload=PAYLOAD_2)
    checkpoint = AtomicCheckpoint(tmp_path / "proof-required.cp")

    error_code(lambda: checkpoint.commit(first), "UNISSUED_VALUE")
    assert checkpoint.load() is None

    class CountingSink:
        def __init__(self) -> None:
            self.records: list[object] = []

        def write(self, record: object) -> None:
            self.records.append(record)

    sink = CountingSink()
    receipts = DeterministicReplay(wal, checkpoint, sink).replay()
    assert [receipt.status for receipt in receipts] == ["COMMITTED", "COMMITTED"]
    assert sink.records == [first, second]
    assert checkpoint.load().native_sequence == 2  # type: ignore[union-attr]


def test_sink_receipt_is_issued_after_write_and_bound_to_exact_record(tmp_path: Path) -> None:
    wal = AppendOnlyWal(tmp_path / "receipt-binding.wal")
    first = append_record(wal, sequence=1)
    second = append_record(wal, sequence=2, payload=PAYLOAD_2)
    checkpoint = AtomicCheckpoint(tmp_path / "receipt-binding.cp")

    class SuccessfulPort:
        def write(self, _record: object) -> None:
            return None

    proof = CommittingSink(SuccessfulPort()).write(first)
    assert isinstance(proof, SinkCommitReceiptV1)
    error_code(lambda: checkpoint.commit(second, proof), "UNISSUED_VALUE")
    assert checkpoint.load() is None

    forged = SinkCommitReceiptV1(
        record_sha256="0" * 64,
        byte_offset=first.byte_offset,  # type: ignore[attr-defined]
        frame_size=first.frame_size,  # type: ignore[attr-defined]
        stream_identity=first.stream_identity,  # type: ignore[attr-defined]
    )
    error_code(lambda: checkpoint.commit(first, forged), "UNISSUED_VALUE")
    assert checkpoint.load() is None
    saved = checkpoint.commit(first, proof)
    assert saved.native_sequence == 1


def test_sink_failure_or_backpressure_never_issues_checkpoint_proof(tmp_path: Path) -> None:
    wal = AppendOnlyWal(tmp_path / "proof-failure.wal")
    record = append_record(wal)
    checkpoint = AtomicCheckpoint(tmp_path / "proof-failure.cp")

    class FailedPort:
        def write(self, _record: object) -> None:
            raise RuntimeError("SYNTHETIC_SINK_CANARY")

    class BackpressurePort:
        def write(self, _record: object) -> SinkAck:
            return SinkAck(accepted=False, backpressure=True)

    error_code(lambda: CommittingSink(FailedPort()).write(record), "SINK_FAULT")
    backpressure = CommittingSink(BackpressurePort()).write(record)
    assert isinstance(backpressure, SinkAck)
    assert backpressure.backpressure
    error_code(lambda: checkpoint.commit(record, backpressure), "UNISSUED_VALUE")
    assert checkpoint.load() is None


def test_identical_wal_bytes_replay_to_identical_receipts_and_checkpoint(tmp_path: Path) -> None:
    outputs: list[tuple[tuple[tuple[object, ...], ...], object]] = []
    for name in ("run-a", "run-b"):
        wal_path = tmp_path / f"{name}.wal"
        checkpoint_path = tmp_path / f"{name}.checkpoint"
        wal = AppendOnlyWal(wal_path)
        append_record(wal, sequence=1)
        append_record(wal, sequence=2, payload=PAYLOAD_2)
        sink = IdempotentSink()
        checkpoint = AtomicCheckpoint(checkpoint_path)
        receipts = DeterministicReplay(wal, checkpoint, sink).replay()
        outputs.append(
            (
                tuple(
                    (
                        receipt.status,
                        receipt.byte_offset,
                        receipt.source_record_key,
                        receipt.sink_committed,
                        receipt.checkpoint_offset,
                        receipt.live_ready,
                    )
                    for receipt in receipts
                ),
                checkpoint.load(),
            )
        )

    assert outputs[0] == outputs[1]


@pytest.mark.parametrize(
    ("sink_mode", "expected_status", "sink_committed"),
    [
        ("backpressure", "BACKPRESSURE", False),
        ("exception", "SINK_FAULT", False),
    ],
)
def test_noncommitted_sink_outcomes_never_advance_checkpoint(
    tmp_path: Path, sink_mode: str, expected_status: str, sink_committed: bool
) -> None:
    wal = AppendOnlyWal(tmp_path / f"{sink_mode}.wal")
    append_record(wal)
    checkpoint = AtomicCheckpoint(tmp_path / f"{sink_mode}.checkpoint")

    class OutcomeSink(IdempotentSink):
        def write(self, record: object) -> SinkAck:
            self.calls.append(record)
            if sink_mode == "exception":
                raise RuntimeError("SYNTHETIC_SINK_CANARY")
            return SinkAck(accepted=False, backpressure=True)

    replay = DeterministicReplay(wal, checkpoint, OutcomeSink())
    (receipt,) = replay.replay()
    assert receipt.status == expected_status
    assert receipt.sink_committed is sink_committed
    assert not receipt.live_ready
    assert checkpoint.load() is None


def test_sink_commit_before_checkpoint_failure_replays_idempotently(tmp_path: Path) -> None:
    wal_path = tmp_path / "sink-before-checkpoint.wal"
    checkpoint_path = tmp_path / "sink-before-checkpoint.cp"
    wal = AppendOnlyWal(wal_path)
    append_record(wal)
    checkpoint = AtomicCheckpoint(checkpoint_path)
    sink = IdempotentSink()

    def fail_after_sink(point: str) -> None:
        if point == "replay.after_sink_commit_before_checkpoint":
            raise RuntimeError("SYNTHETIC_CHECKPOINT_CANARY")

    first = DeterministicReplay(wal, checkpoint, sink, fault_hook=fail_after_sink).replay()
    assert len(first) == 1
    assert first[0].status == "CHECKPOINT_FAILURE"
    assert first[0].sink_committed
    assert checkpoint.load() is None
    assert len(sink.accepted) == 1

    retried = DeterministicReplay(wal, checkpoint, sink).replay()
    assert retried
    assert len(sink.accepted) == 1
    assert len(sink.calls) == 2
    assert checkpoint.load().native_sequence == 1  # type: ignore[union-attr]


@pytest.mark.parametrize(
    "fault_point",
    [
        "checkpoint.after_temp_write_before_fsync",
        "checkpoint.after_temp_fsync_before_replace",
        "checkpoint.after_replace_before_directory_fsync",
    ],
)
def test_checkpoint_fault_boundaries_are_atomic_monotone_and_retryable(
    tmp_path: Path, fault_point: str
) -> None:
    wal_path = tmp_path / f"{fault_point.rsplit('.', 1)[-1]}.wal"
    checkpoint_path = tmp_path / f"{fault_point.rsplit('.', 1)[-1]}.cp"
    wal = AppendOnlyWal(wal_path)
    append_record(wal)
    checkpoint = AtomicCheckpoint(checkpoint_path)
    sink = IdempotentSink()

    def fail_at(point: str) -> None:
        if point == fault_point:
            raise RuntimeError("SYNTHETIC_CHECKPOINT_CANARY")

    checkpoint = AtomicCheckpoint(checkpoint_path, fault_hook=fail_at)
    (failed,) = DeterministicReplay(wal, checkpoint, sink).replay()
    assert failed.status == "CHECKPOINT_FAILURE"
    assert failed.sink_committed
    observed = checkpoint.load()
    assert observed is None or observed.native_sequence == 1

    reopened = AtomicCheckpoint(checkpoint_path)
    retry = DeterministicReplay(wal, reopened, sink).replay()
    assert retry
    final = reopened.load()
    assert final is not None
    assert final.native_sequence == 1
    assert final.generation >= 1
    assert len(sink.accepted) == 1


def test_checkpoint_survives_hard_process_exit_after_commit(tmp_path: Path) -> None:
    wal_path = tmp_path / "crash.wal"
    checkpoint_path = tmp_path / "crash.cp"
    wal = AppendOnlyWal(wal_path)
    record = append_record(wal)
    script = textwrap.dedent(
        """
        import os
        import sys
        from leviathan_market_data.ingress import SinkAck
        from leviathan_market_data.live.checkpoint import AtomicCheckpoint
        from leviathan_market_data.live.replay import DeterministicReplay
        from leviathan_market_data.live.wal import AppendOnlyWal

        class Sink:
            def write(self, record):
                return SinkAck(accepted=True)

        wal = AppendOnlyWal(sys.argv[1])
        checkpoint = AtomicCheckpoint(sys.argv[2])
        receipts = DeterministicReplay(wal, checkpoint, Sink()).replay()
        if not receipts or not receipts[-1].sink_committed:
            os._exit(91)
        os._exit(73)
        """
    )
    child = subprocess.run(
        [sys.executable, "-c", script, str(wal_path), str(checkpoint_path)],
        cwd=Path.cwd(),
        capture_output=True,
        timeout=15,
        check=False,
    )
    assert child.returncode == 73, child.stderr.decode("utf-8", errors="replace")

    recovered = AtomicCheckpoint(checkpoint_path).load()
    assert recovered is not None
    assert recovered.native_sequence == record.native_sequence  # type: ignore[attr-defined]
    assert recovered.source_record_key == record.source_record_key  # type: ignore[attr-defined]
    assert recovered.committed_byte_offset == record.byte_offset + record.frame_size  # type: ignore[attr-defined]


def committed_replay(tmp_path: Path) -> tuple[AppendOnlyWal, AtomicCheckpoint, DeterministicReplay]:
    wal = AppendOnlyWal(tmp_path / "continuity.wal")
    append_record(wal, sequence=1)
    checkpoint = AtomicCheckpoint(tmp_path / "continuity.cp")
    replay = DeterministicReplay(wal, checkpoint, IdempotentSink())
    replay.replay()
    return wal, checkpoint, replay


def test_native_reconciliation_uses_sequence_cursor_not_physical_byte_offset(
    tmp_path: Path,
) -> None:
    _wal, checkpoint, replay = committed_replay(tmp_path)
    saved = checkpoint.load()
    assert saved is not None
    assert saved.native_sequence == 1
    assert saved.committed_byte_offset > saved.native_sequence

    continuous = replay.reconcile_native_position(
        *trusted_source_adapter(FakeContinuityPort(next_sequence=2)).continuity(),
    )
    assert continuous.status == "CONTINUOUS"
    assert continuous.live_ready

    byte_offset_is_not_sequence = replay.reconcile_native_position(
        *trusted_source_adapter(
            FakeContinuityPort(next_sequence=saved.committed_byte_offset + 1)
        ).continuity(),
    )
    assert byte_offset_is_not_sequence.status == "SEQUENCE_MISMATCH"
    assert not byte_offset_is_not_sequence.live_ready


@pytest.mark.parametrize(
    ("position_session", "next_sequence", "ranges", "expected_status"),
    [
        ("other-session", 2, (), "SESSION_MISMATCH"),
        (SESSION, 3, (), "SEQUENCE_MISMATCH"),
        (SESSION, 2, ((2, 4),), "GAP_PRESENT"),
    ],
)
def test_native_reconciliation_rejects_session_sequence_or_gap_disagreement(
    tmp_path: Path,
    position_session: str,
    next_sequence: int,
    ranges: tuple[tuple[int, int], ...],
    expected_status: str,
) -> None:
    _wal, _checkpoint, replay = committed_replay(tmp_path)
    verdict = replay.reconcile_native_position(
        *trusted_source_adapter(
            FakeContinuityPort(
                session_id=position_session,
                next_sequence=next_sequence,
                gap_ranges=ranges,
            )
        ).continuity(),
    )
    assert verdict.status == expected_status
    assert not verdict.live_ready


def test_caller_constructed_continuity_values_cannot_claim_live_readiness(
    tmp_path: Path,
) -> None:
    _wal, _checkpoint, replay = committed_replay(tmp_path)
    caller_position = NativeResumePositionV1(
        provider_id=STREAM_IDENTITY[0], session_id=SESSION, next_sequence=2
    )
    caller_gaps = GapManifestV1(
        provider_id=STREAM_IDENTITY[0], session_id=SESSION, ranges=()
    )

    verdict = replay.reconcile_native_position(caller_position, caller_gaps)
    assert verdict.status == "UNKNOWN"
    assert not verdict.live_ready

    missing_position, missing_gaps = SourceAdapter(
        FakeContinuityPort(fail_snapshot=True)
    ).continuity()
    unavailable = replay.reconcile_native_position(missing_position, missing_gaps)
    assert unavailable.status == "UNKNOWN"
    assert not unavailable.live_ready

    caller_port = FakeContinuityPort(next_sequence=2)
    no_capability = SourceAdapter(caller_port)
    assert no_capability.continuity() == (None, None)
    assert no_capability.confirm_session_transition(SESSION, "synthetic-session-2") is None
    no_capability_verdict = replay.reconcile_native_position(*no_capability.continuity())
    assert no_capability_verdict.status == "UNKNOWN"
    assert not no_capability_verdict.live_ready

    forged_capability = TrustedProviderCapabilityV1(provider_id=caller_port.provider_id)
    forged_adapter = SourceAdapter(caller_port, forged_capability)
    assert forged_adapter.continuity() == (None, None)
    assert forged_adapter.confirm_session_transition(SESSION, "synthetic-session-2") is None
    forged_verdict = replay.reconcile_native_position(*forged_adapter.continuity())
    assert forged_verdict.status == "UNKNOWN"
    assert not forged_verdict.live_ready


def test_trusted_source_capability_is_bound_to_port_and_checkpoint_provider(
    tmp_path: Path,
) -> None:
    _wal, _checkpoint, replay = committed_replay(tmp_path)
    original_source = FakeContinuityPort(next_sequence=2)
    capability = issue_test_capability(original_source, original_source.provider_id)

    other_instance = FakeContinuityPort(next_sequence=2)
    wrong_port = SourceAdapter(other_instance, capability)
    assert wrong_port.continuity() == (None, None)
    wrong_port_verdict = replay.reconcile_native_position(*wrong_port.continuity())
    assert wrong_port_verdict.status == "UNKNOWN"
    assert not wrong_port_verdict.live_ready

    other_provider_source = FakeContinuityPort(next_sequence=2)
    other_provider_source.provider_id = "synthetic-other-provider"
    other_provider_capability = issue_test_capability(
        other_provider_source, other_provider_source.provider_id
    )
    mismatched_position, mismatched_gaps = SourceAdapter(
        other_provider_source, other_provider_capability
    ).continuity()
    assert mismatched_position is not None
    assert mismatched_gaps is not None
    mismatch = replay.reconcile_native_position(mismatched_position, mismatched_gaps)
    assert mismatch.status == "PROVIDER_MISMATCH"
    assert not mismatch.live_ready


def test_session_reset_requires_source_issued_transition_evidence(tmp_path: Path) -> None:
    wal = AppendOnlyWal(tmp_path / "session-evidence.wal")
    append_record(wal, sequence=1)
    new_session = "synthetic-session-2"

    with pytest.raises(TypeError):
        wal.append(
            stream_identity=STREAM_IDENTITY,
            session_id=new_session,
            source_record_key="synthetic-key-legacy-bool",
            native_record_id="synthetic-native-legacy-bool",
            native_sequence=1,
            source_time_ns=BASE_TIME_NS + 2,
            received_time_ns=BASE_TIME_NS + 3,
            raw_payload=PAYLOAD_2,
            session_transition_confirmed=True,  # type: ignore[call-arg]
        )

    caller_evidence = SessionTransitionEvidenceV1(
        provider_id=STREAM_IDENTITY[0],
        from_session_id=SESSION,
        to_session_id=new_session,
    )
    error_code(
        lambda: append_record(
            wal,
            sequence=1,
            key="synthetic-key-caller-evidence",
            payload=PAYLOAD_2,
            session_id=new_session,
            session_transition_evidence=caller_evidence,
        ),
        "UNKNOWN_CONTINUITY",
    )

    unconfirmed = trusted_source_adapter(
        FakeContinuityPort(transition_status="UNCONFIRMED")
    ).confirm_session_transition(SESSION, new_session)
    assert unconfirmed is None
    error_code(
        lambda: append_record(
            wal,
            sequence=1,
            key="synthetic-key-unconfirmed",
            payload=PAYLOAD_2,
            session_id=new_session,
        ),
        "SESSION_RESET_UNCONFIRMED",
    )

    mismatched = trusted_source_adapter(
        FakeContinuityPort(transition_to_override="synthetic-other-session")
    ).confirm_session_transition(SESSION, new_session)
    assert mismatched is None
    error_code(
        lambda: append_record(
            wal,
            sequence=1,
            key="synthetic-key-mismatched-confirmation",
            payload=PAYLOAD_2,
            session_id=new_session,
        ),
        "SESSION_RESET_UNCONFIRMED",
    )

    evidence = trusted_source_adapter(FakeContinuityPort()).confirm_session_transition(
        SESSION, new_session
    )
    assert evidence is not None
    accepted = append_record(
        wal,
        sequence=1,
        key="synthetic-key-confirmed",
        payload=PAYLOAD_2,
        session_id=new_session,
        session_transition_evidence=evidence,
    )
    assert accepted.session_id == new_session  # type: ignore[attr-defined]


def test_transition_evidence_is_bound_to_its_provider(tmp_path: Path) -> None:
    provider_a = FakeContinuityPort()
    evidence = trusted_source_adapter(provider_a).confirm_session_transition(
        SESSION, "synthetic-session-2"
    )
    assert evidence is not None
    assert evidence.provider_id == STREAM_IDENTITY[0]

    provider_b_identity = (
        "synthetic-provider-b",
        *STREAM_IDENTITY[1:],
    )
    wal = AppendOnlyWal(tmp_path / "provider-b.wal")
    original = wal.append(
        stream_identity=provider_b_identity,
        session_id=SESSION,
        source_record_key="provider-b-original",
        native_record_id="provider-b-native-1",
        native_sequence=1,
        source_time_ns=BASE_TIME_NS + 1,
        received_time_ns=BASE_TIME_NS + 2,
        raw_payload=PAYLOAD_1,
    )

    with pytest.raises(WalError) as caught:
        wal.append(
            stream_identity=provider_b_identity,
            session_id="synthetic-session-2",
            source_record_key="provider-b-reset-attempt",
            native_record_id="provider-b-native-1-reset",
            native_sequence=1,
            source_time_ns=BASE_TIME_NS + 3,
            received_time_ns=BASE_TIME_NS + 4,
            raw_payload=PAYLOAD_2,
            session_transition_evidence=evidence,
        )
    assert caught.value.code == "UNKNOWN_CONTINUITY"
    assert str(caught.value) == caught.value.code
    assert caught.value.args == (caught.value.code,)
    assert wal.read_all() == (original,)


def test_missing_checkpoint_never_claims_continuity(tmp_path: Path) -> None:
    wal = AppendOnlyWal(tmp_path / "empty.wal")
    checkpoint = AtomicCheckpoint(tmp_path / "empty.cp")
    replay = DeterministicReplay(wal, checkpoint, IdempotentSink())
    verdict = replay.reconcile_native_position(
        *trusted_source_adapter(FakeContinuityPort(next_sequence=1)).continuity(),
    )
    assert verdict.status == "UNKNOWN"
    assert not verdict.live_ready


def test_disk_full_and_record_capacity_are_non_ack_and_stop_intake(tmp_path: Path) -> None:
    limited = AppendOnlyWal(tmp_path / "limited.wal", max_records=1)
    append_record(limited, sequence=1)
    existing = limited.read_all()
    error = error_code(lambda: append_record(limited, sequence=2), "BACKPRESSURE")
    assert error.acknowledged is False
    assert error.stop_intake is True
    assert limited.read_all() == existing

    fail_fsync = False

    def no_space(_fd: int) -> None:
        if fail_fsync:
            raise OSError(errno.ENOSPC, "SYNTHETIC_DISK_FULL_CANARY")
        os.fsync(_fd)

    full = AppendOnlyWal(tmp_path / "disk-full.wal", fsync_fn=no_space)
    fail_fsync = True
    disk_error = error_code(lambda: append_record(full), "BACKPRESSURE")
    assert disk_error.acknowledged is False
    assert disk_error.stop_intake is True
    assert "SYNTHETIC_DISK_FULL_CANARY" not in repr(disk_error)


def test_wal_identity_fields_require_bounded_ascii_grammar(tmp_path: Path) -> None:
    invalid_cases = (
        (
            "provider",
            {
                "stream_identity": ("prøvider-UNICODE_CANARY", *STREAM_IDENTITY[1:]),
            },
        ),
        ("session", {"session_id": "sés-session-UNICODE_CANARY"}),
        ("source-key", {"source_record_key": "clè-key-UNICODE_CANARY"}),
        ("native-id", {"native_record_id": "natïve-id-UNICODE_CANARY"}),
    )

    for name, overrides in invalid_cases:
        wal = AppendOnlyWal(tmp_path / f"unicode-{name}.wal")
        arguments: dict[str, object] = {
            "stream_identity": STREAM_IDENTITY,
            "session_id": SESSION,
            "source_record_key": f"synthetic-{name}",
            "native_record_id": "synthetic-native-id",
            "native_sequence": 1,
            "source_time_ns": BASE_TIME_NS + 1,
            "received_time_ns": BASE_TIME_NS + 2,
            "raw_payload": PAYLOAD_1,
        }
        arguments.update(overrides)
        error = error_code(
            lambda active_wal=wal, call_arguments=arguments: active_wal.append(
                **call_arguments
            ),
            "INVALID_RECORD",
        )  # type: ignore[arg-type]
        assert "UNICODE_CANARY" not in repr(error)
        assert wal.read_all() == ()

    checkpoint_base: dict[str, object] = {
        "stream_identity": STREAM_IDENTITY,
        "session_id": SESSION,
        "native_sequence": 1,
        "source_record_key": "synthetic-key",
        "payload_sha256": "0" * 64,
        "committed_byte_offset": 1,
        "generation": 1,
    }
    checkpoint_cases = (
        ("stream_identity", ("prøvider-UNICODE_CANARY", *STREAM_IDENTITY[1:])),
        ("session_id", "sés-session-UNICODE_CANARY"),
        ("source_record_key", "clè-key-UNICODE_CANARY"),
    )
    for field, invalid_value in checkpoint_cases:
        with pytest.raises(SealError) as caught:
            CheckpointV1(**(checkpoint_base | {field: invalid_value}))
        assert "UNICODE_CANARY" not in str(caught.value)

    with pytest.raises(SealError):
        GapManifestV1(
            provider_id=STREAM_IDENTITY[0],
            session_id="sés-session-UNICODE_CANARY",
            ranges=(),
        )
    with pytest.raises(SealError):
        NativeResumePositionV1(
            provider_id=STREAM_IDENTITY[0],
            session_id="sés-session-UNICODE_CANARY",
            next_sequence=1,
        )
    with pytest.raises(SealError):
        NativeContinuitySnapshotV1(
            session_id="sés-session-UNICODE_CANARY", next_sequence=1
        )


def test_wal_and_checkpoint_reads_remain_bounded_if_file_grows_after_stat(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def install_growth_probe(target: Path) -> list[int]:
        read_sizes: list[int] = []
        original_stat = Path.stat
        original_open = Path.open

        def underreport_size(self: Path, *args: object, **kwargs: object) -> object:
            result = original_stat(self, *args, **kwargs)  # type: ignore[arg-type]
            if self == target:
                return SimpleNamespace(st_size=0)
            return result

        class ReadSpy:
            def __init__(self, handle: object) -> None:
                self.handle = handle

            def __enter__(self) -> ReadSpy:
                self.handle.__enter__()  # type: ignore[attr-defined]
                return self

            def __exit__(self, *args: object) -> object:
                return self.handle.__exit__(*args)  # type: ignore[attr-defined]

            def read(self, size: int = -1) -> bytes:
                read_sizes.append(size)
                return self.handle.read(size)  # type: ignore[attr-defined]

        def tracked_open(
            self: Path, *args: object, **kwargs: object
        ) -> object:
            handle = original_open(self, *args, **kwargs)  # type: ignore[arg-type]
            mode = kwargs.get("mode", args[0] if args else "r")
            if self == target and mode == "rb":
                return ReadSpy(handle)
            return handle

        monkeypatch.setattr(Path, "stat", underreport_size)
        monkeypatch.setattr(Path, "open", tracked_open)
        return read_sizes

    wal_path = tmp_path / "grown.wal"
    wal = AppendOnlyWal(wal_path, max_bytes=64)
    wal_path.write_bytes(b"x" * 80)
    wal_reads = install_growth_probe(wal_path)
    error_code(wal.read_all, "BACKPRESSURE")
    assert wal_reads == [65]

    checkpoint_path = tmp_path / "grown.checkpoint"
    checkpoint = AtomicCheckpoint(checkpoint_path)
    checkpoint_path.write_bytes(b"x" * 16_400)
    checkpoint_reads = install_growth_probe(checkpoint_path)
    error_code(checkpoint.load, "CHECKPOINT_CORRUPT")
    assert checkpoint_reads == [16_385]
