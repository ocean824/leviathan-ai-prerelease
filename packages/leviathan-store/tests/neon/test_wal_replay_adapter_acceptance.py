from __future__ import annotations

from collections.abc import Callable, Iterable
from pathlib import Path

import pytest
from leviathan_store.neon.snapshot_models import CommittedRecordV1
from leviathan_store.neon.wal_replay_adapter import (
    WalReplayAdapterError,
    WalReplayAdapterV1,
)

from leviathan_market_data.ingress import SinkAck
from leviathan_market_data.live.checkpoint import SinkCommitReceiptV1
from leviathan_market_data.live.replay import CommittingSink
from leviathan_market_data.live.wal import AppendOnlyWal

STREAM = (
    "synthetic-provider",
    "synthetic-dataset",
    "XTEST",
    "SYN-1",
    "trades",
)
SCOPE = "scope-synthetic"
INSTRUMENT = "instrument-synthetic-1"
BASE_TIME_NS = 1_780_000_000_000_000_000


class AcceptingSink:
    def write(self, _record: object) -> SinkAck:
        return SinkAck(accepted=True)


class FakeWalReadPort:
    def __init__(self, records: Iterable[object]) -> None:
        self.records = tuple(records)

    def read_all(self) -> tuple[object, ...]:
        return self.records


def append_records(
    path: Path, *, count: int = 3, missing_source_time_at: int | None = None
) -> tuple[AppendOnlyWal, tuple[object, ...]]:
    wal = AppendOnlyWal(path)
    records = tuple(
        wal.append(
            stream_identity=STREAM,
            session_id="synthetic-session",
            source_record_key=f"synthetic-source-key-{sequence}",
            native_record_id=f"synthetic-native-id-{sequence}",
            native_sequence=sequence,
            source_time_ns=(
                None
                if sequence == missing_source_time_at
                else BASE_TIME_NS + sequence
            ),
            received_time_ns=BASE_TIME_NS + sequence + 100,
            raw_payload=f'{{"sequence":{sequence},"synthetic":true}}'.encode(),
        )
        for sequence in range(1, count + 1)
    )
    return wal, records


def commit_receipts(records: Iterable[object]) -> dict[int, SinkCommitReceiptV1]:
    committing_sink = CommittingSink(AcceptingSink())
    receipts: dict[int, SinkCommitReceiptV1] = {}
    for record in records:
        receipt = committing_sink.write(record)  # type: ignore[arg-type]
        assert isinstance(receipt, SinkCommitReceiptV1)
        receipts[record.byte_offset] = receipt  # type: ignore[attr-defined]
    return receipts


def adapter_for(
    wal: object,
    receipt_lookup: Callable[[object], object | None],
) -> WalReplayAdapterV1:
    return WalReplayAdapterV1(
        wal=wal,  # type: ignore[arg-type]
        scope_id=SCOPE,
        instrument_id=INSTRUMENT,
        stream_identity=STREAM,
        receipt_for=receipt_lookup,  # type: ignore[arg-type]
    )


def assert_adapter_error(call: Callable[[], object], code: str) -> WalReplayAdapterError:
    with pytest.raises(WalReplayAdapterError) as caught:
        call()
    assert caught.value.code == code
    assert str(caught.value) == code
    assert caught.value.args == (code,)
    return caught.value


def test_only_proven_commits_are_projected_with_contiguous_store_offsets(
    tmp_path: Path,
) -> None:
    wal, source_records = append_records(
        tmp_path / "committed.wal", missing_source_time_at=2
    )
    receipts = commit_receipts(source_records)
    adapter = adapter_for(
        wal,
        lambda record: receipts.get(record.byte_offset),  # type: ignore[attr-defined]
    )

    assert adapter.committed_through(scope_id=SCOPE, instrument_id=INSTRUMENT) == 3
    rows = adapter.read_committed(
        scope_id=SCOPE,
        instrument_id=INSTRUMENT,
        after_offset=0,
        through_offset=3,
    )

    assert all(isinstance(row, CommittedRecordV1) for row in rows)
    assert [row.committed_offset for row in rows] == [1, 2, 3]
    assert [row.source_event_offset for row in rows] == [1, 2, 3]
    assert [row.semantic_key for row in rows] == [
        f"synthetic-source-key-{sequence}" for sequence in range(1, 4)
    ]
    assert [row.payload for row in rows] == [record.raw_payload for record in source_records]  # type: ignore[attr-defined]
    assert rows[0].watermark_utc_ns == BASE_TIME_NS + 1
    assert rows[1].watermark_utc_ns == BASE_TIME_NS + 102
    assert rows[2].watermark_utc_ns == BASE_TIME_NS + 3

    later = adapter.read_committed(
        scope_id=SCOPE,
        instrument_id=INSTRUMENT,
        after_offset=1,
        through_offset=3,
    )
    assert [row.committed_offset for row in later] == [2, 3]


def test_uncommitted_offset_and_wrong_scope_are_denied(tmp_path: Path) -> None:
    wal, records = append_records(tmp_path / "range.wal", count=1)
    receipts = commit_receipts(records)
    adapter = adapter_for(
        wal,
        lambda record: receipts.get(record.byte_offset),  # type: ignore[attr-defined]
    )

    assert_adapter_error(
        lambda: adapter.read_committed(
            scope_id=SCOPE,
            instrument_id=INSTRUMENT,
            after_offset=0,
            through_offset=2,
        ),
        "OFFSET_UNCOMMITTED",
    )
    assert_adapter_error(
        lambda: adapter.committed_through(
            scope_id=SCOPE,
            instrument_id="another-instrument",
        ),
        "STREAM_MISMATCH",
    )


@pytest.mark.parametrize("bad_receipt", ["missing", "forged", "mismatched", "raising"])
def test_unverified_or_mismatched_sink_proof_fails_closed(
    tmp_path: Path, bad_receipt: str
) -> None:
    wal, records = append_records(tmp_path / f"{bad_receipt}.wal", count=2)
    receipts = commit_receipts(records)

    def lookup(record: object) -> object | None:
        if bad_receipt == "missing":
            return None
        if bad_receipt == "forged":
            source = records[0]
            return SinkCommitReceiptV1(
                record_sha256=receipts[source.byte_offset].record_sha256,  # type: ignore[attr-defined]
                byte_offset=source.byte_offset,  # type: ignore[attr-defined]
                frame_size=source.frame_size,  # type: ignore[attr-defined]
                stream_identity=STREAM,
            )
        if bad_receipt == "mismatched":
            return receipts[records[0].byte_offset]  # type: ignore[attr-defined]
        raise RuntimeError("SYNTHETIC_RECEIPT_LOOKUP_CANARY")

    adapter = adapter_for(wal, lookup)
    expected = (
        "UNVERIFIED_RECEIPT"
        if bad_receipt in ("missing", "forged", "raising")
        else "RECEIPT_MISMATCH"
    )
    error = assert_adapter_error(
        lambda: adapter.read_committed(
            scope_id=SCOPE,
            instrument_id=INSTRUMENT,
            after_offset=0,
            through_offset=2,
        ),
        expected,
    )
    assert "SYNTHETIC_RECEIPT_LOOKUP_CANARY" not in repr(error)


@pytest.mark.parametrize(
    ("records_order", "expected_code"),
    [
        ("gap", "WAL_GAP"),
        ("reordered", "WAL_REORDERED"),
    ],
)
def test_gap_or_reordered_wal_fails_before_any_range_is_returned(
    tmp_path: Path, records_order: str, expected_code: str
) -> None:
    _wal, source_records = append_records(tmp_path / f"{records_order}.wal", count=3)
    receipts = commit_receipts(source_records)
    if records_order == "gap":
        presented = (source_records[0], source_records[2])
    else:
        presented = (source_records[0], source_records[0], source_records[1])
    adapter = adapter_for(
        FakeWalReadPort(presented),
        lambda record: receipts.get(record.byte_offset),  # type: ignore[attr-defined]
    )

    assert_adapter_error(
        lambda: adapter.read_committed(
            scope_id=SCOPE,
            instrument_id=INSTRUMENT,
            after_offset=0,
            through_offset=3,
        ),
        expected_code,
    )


def test_unissued_wal_records_are_not_adapted(tmp_path: Path) -> None:
    adapter = adapter_for(FakeWalReadPort((object(),)), lambda _record: None)

    assert_adapter_error(
        lambda: adapter.committed_through(scope_id=SCOPE, instrument_id=INSTRUMENT),
        "UNISSUED_RECORD",
    )
