from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from pathlib import Path

import pytest
from leviathan_store.neon.wal_replay_adapter import (
    WalReplayAdapterError,
    WalReplayAdapterV1,
)

from leviathan_market_data.live.checkpoint import SinkCommitReceiptV1
from leviathan_market_data.live.replay import CommittingSink
from leviathan_market_data.live.wal import AppendOnlyWal, RawWalRecordV1

_STREAM = ("synthetic-provider", "synthetic-dataset", "XTEST", "SYN-1", "trades")
_SESSION = "synthetic-session"
_BASE_NS = 1_770_000_000_000_000_000


class _Sink:
    def write(self, _record: RawWalRecordV1) -> None:
        return None


class _WalReadPort:
    def __init__(self, rows: Iterable[object]) -> None:
        self.rows = tuple(rows)

    def read_all(self) -> Iterable[object]:
        return self.rows


def _append(wal: AppendOnlyWal, sequence: int) -> RawWalRecordV1:
    return wal.append(
        stream_identity=_STREAM,
        session_id=_SESSION,
        source_record_key=f"synthetic-key-{sequence}",
        native_record_id=f"synthetic-native-{sequence}",
        native_sequence=sequence,
        source_time_ns=None if sequence == 2 else _BASE_NS + sequence,
        received_time_ns=_BASE_NS + sequence + 10,
        raw_payload=f'{{"sequence":{sequence}}}'.encode("ascii"),
    )


def _adapter(
    wal: _WalReadPort,
    receipts: Mapping[int, object],
) -> WalReplayAdapterV1:
    return WalReplayAdapterV1(
        wal=wal,
        scope_id="scope-test",
        instrument_id="instrument-test",
        stream_identity=_STREAM,
        receipt_for=lambda record: receipts.get(record.byte_offset),
    )


def _rows_with_receipts(tmp_path: Path, count: int = 2) -> tuple[
    tuple[RawWalRecordV1, ...], dict[int, SinkCommitReceiptV1]
]:
    wal = AppendOnlyWal(tmp_path / "adapter.wal")
    rows = tuple(_append(wal, sequence) for sequence in range(1, count + 1))
    sink = CommittingSink(_Sink())
    receipts: dict[int, SinkCommitReceiptV1] = {}
    for row in rows:
        receipt = sink.write(row)
        assert isinstance(receipt, SinkCommitReceiptV1)
        receipts[row.byte_offset] = receipt
    return rows, receipts


def test_adapter_emits_only_verified_rows_with_contiguous_committed_ordinals(
    tmp_path: Path,
) -> None:
    rows, receipts = _rows_with_receipts(tmp_path)
    adapter = _adapter(_WalReadPort(rows), receipts)

    assert adapter.committed_through(scope_id="scope-test", instrument_id="instrument-test") == 2
    output = adapter.read_committed(
        scope_id="scope-test",
        instrument_id="instrument-test",
        after_offset=1,
        through_offset=2,
    )
    assert len(output) == 1
    assert output[0].committed_offset == 2
    assert output[0].source_event_offset == rows[1].native_sequence
    assert output[0].semantic_key == rows[1].source_record_key
    assert output[0].payload == rows[1].raw_payload
    assert output[0].watermark_utc_ns == rows[1].received_time_ns


def test_missing_receipt_fails_the_entire_range_without_partial_rows(tmp_path: Path) -> None:
    rows, receipts = _rows_with_receipts(tmp_path)
    receipts.pop(rows[1].byte_offset)
    adapter = _adapter(_WalReadPort(rows), receipts)

    with pytest.raises(WalReplayAdapterError) as exc:
        adapter.read_committed(
            scope_id="scope-test",
            instrument_id="instrument-test",
            after_offset=0,
            through_offset=1,
        )
    assert exc.value.code == "UNVERIFIED_RECEIPT"


def test_receipt_from_a_different_record_is_rejected(tmp_path: Path) -> None:
    rows, receipts = _rows_with_receipts(tmp_path)
    receipts[rows[0].byte_offset] = receipts[rows[1].byte_offset]
    adapter = _adapter(_WalReadPort(rows), receipts)

    with pytest.raises(WalReplayAdapterError) as exc:
        adapter.committed_through(scope_id="scope-test", instrument_id="instrument-test")
    assert exc.value.code == "RECEIPT_MISMATCH"


def test_publicly_constructed_receipt_is_not_sink_commit_proof(tmp_path: Path) -> None:
    rows, receipts = _rows_with_receipts(tmp_path, count=1)
    original = receipts[rows[0].byte_offset]
    assert isinstance(original, SinkCommitReceiptV1)
    receipts[rows[0].byte_offset] = SinkCommitReceiptV1(
        record_sha256=original.record_sha256,
        byte_offset=original.byte_offset,
        frame_size=original.frame_size,
        stream_identity=original.stream_identity,
    )
    adapter = _adapter(_WalReadPort(rows), receipts)

    with pytest.raises(WalReplayAdapterError) as exc:
        adapter.committed_through(scope_id="scope-test", instrument_id="instrument-test")
    assert exc.value.code == "UNVERIFIED_RECEIPT"


@pytest.mark.parametrize(
    ("rows_factory", "code"),
    [
        (lambda rows: (rows[1],), "WAL_GAP"),
        (lambda rows: (rows[0], rows[0]), "WAL_REORDERED"),
    ],
)
def test_gap_or_reordered_wal_fails_closed(
    tmp_path: Path,
    rows_factory: Callable[[tuple[RawWalRecordV1, ...]], tuple[RawWalRecordV1, ...]],
    code: str,
) -> None:
    rows, receipts = _rows_with_receipts(tmp_path)
    selected = rows_factory(rows)
    selected_receipts = {row.byte_offset: receipts[row.byte_offset] for row in selected}
    adapter = _adapter(_WalReadPort(selected), selected_receipts)

    with pytest.raises(WalReplayAdapterError) as exc:
        adapter.committed_through(scope_id="scope-test", instrument_id="instrument-test")
    assert exc.value.code == code


def test_wrong_scope_and_invalid_ranges_are_rejected(tmp_path: Path) -> None:
    rows, receipts = _rows_with_receipts(tmp_path)
    adapter = _adapter(_WalReadPort(rows), receipts)

    with pytest.raises(WalReplayAdapterError, match="STREAM_MISMATCH"):
        adapter.committed_through(scope_id="other-scope", instrument_id="instrument-test")
    with pytest.raises(WalReplayAdapterError) as exc:
        adapter.read_committed(
            scope_id="scope-test",
            instrument_id="instrument-test",
            after_offset=True,
            through_offset=1,
        )
    assert exc.value.code == "INVALID_RANGE"


def test_unissued_raw_record_is_not_accepted(tmp_path: Path) -> None:
    rows, receipts = _rows_with_receipts(tmp_path, count=1)
    fields = rows[0].model_dump()
    candidate = RawWalRecordV1(**fields)
    adapter = _adapter(_WalReadPort((candidate,)), receipts)

    with pytest.raises(WalReplayAdapterError) as exc:
        adapter.committed_through(scope_id="scope-test", instrument_id="instrument-test")
    assert exc.value.code == "UNISSUED_RECORD"
