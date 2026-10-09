"""Adapt MD-005 sink-proven WAL records to STOR-003's committed replay port.

The adapter deliberately depends on structural record/read protocols so the
store package does not acquire a runtime dependency on the market-data package.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Iterable
from typing import Protocol, cast

from leviathan_core.numeric import canonical_json
from leviathan_core.seal import SealError, require
from leviathan_store.neon.snapshot_models import (
    CommittedRecordV1,
    SnapshotRecoveryError,
    make_committed_record,
)

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)
_STREAM_PART = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)
_RECORD_TAG = "md005.raw_wal_record.v1"
_RECEIPT_TAG = "md005.sink_commit_receipt.v1"


class WalReplayAdapterError(ValueError):
    """Content-free, closed failure from the MD-005 to STOR-003 boundary."""

    _CODES = frozenset(
        {
            "INVALID_CONFIGURATION",
            "INVALID_RANGE",
            "INVALID_WAL",
            "UNISSUED_RECORD",
            "STREAM_MISMATCH",
            "WAL_GAP",
            "WAL_REORDERED",
            "UNVERIFIED_RECEIPT",
            "RECEIPT_MISMATCH",
            "INVALID_REPLAY_RECORD",
            "OFFSET_UNCOMMITTED",
        }
    )

    def __init__(self, code: str) -> None:
        if code not in self._CODES:
            code = "INVALID_WAL"
        self.code = code
        super().__init__(code)


class RawWalRecordPort(Protocol):
    """Structural surface used after MD-005 record seal verification."""

    stream_identity: tuple[str, str, str, str, str]
    source_record_key: str
    native_sequence: int
    source_time_ns: int | None
    received_time_ns: int
    byte_offset: int
    frame_size: int

    @property
    def raw_payload(self) -> bytes: ...

    def model_dump(self, *, mode: str) -> dict[str, object]: ...


class RawWalReadPort(Protocol):
    """Read-only injected view of the MD-005 append-only WAL."""

    def read_all(self) -> Iterable[object]: ...


class SinkCommitReceiptPort(Protocol):
    """Structural fields of an MD-005-issued sink commit receipt."""

    record_sha256: str
    byte_offset: int
    frame_size: int
    stream_identity: tuple[str, str, str, str, str]


class WalReplayAdapterV1:
    """Expose verified sink-committed WAL rows using STOR-003's local port.

    `receipt_for` is a lookup for receipts captured when `CommittingSink.write`
    succeeded. It should key by stable record content/offset, not object
    identity, because a WAL read can return a freshly reconstructed record.
    """

    def __init__(
        self,
        *,
        wal: RawWalReadPort,
        scope_id: str,
        instrument_id: str,
        stream_identity: tuple[str, str, str, str, str],
        receipt_for: Callable[[RawWalRecordPort], object | None],
    ) -> None:
        if (
            not callable(getattr(wal, "read_all", None))
            or not callable(receipt_for)
            or type(scope_id) is not str
            or _IDENTIFIER.fullmatch(scope_id) is None
            or type(instrument_id) is not str
            or _IDENTIFIER.fullmatch(instrument_id) is None
            or type(stream_identity) is not tuple
            or len(stream_identity) != 5
            or any(
                type(part) is not str or _STREAM_PART.fullmatch(part) is None
                for part in stream_identity
            )
        ):
            raise WalReplayAdapterError("INVALID_CONFIGURATION")
        self._wal = wal
        self._scope_id = scope_id
        self._instrument_id = instrument_id
        self._stream_identity = stream_identity
        self._receipt_for = receipt_for

    def committed_through(self, *, scope_id: str, instrument_id: str) -> int:
        """Return the 1-based contiguous sink-committed record high-water mark."""
        self._require_scope(scope_id, instrument_id)
        return len(self._read_verified())

    def read_committed(
        self,
        *,
        scope_id: str,
        instrument_id: str,
        after_offset: int,
        through_offset: int,
    ) -> tuple[CommittedRecordV1, ...]:
        """Read offsets in `(after_offset, through_offset]`, failing atomically."""
        self._require_scope(scope_id, instrument_id)
        if (
            type(after_offset) is not int
            or type(through_offset) is not int
            or after_offset < 0
            or through_offset < after_offset
        ):
            raise WalReplayAdapterError("INVALID_RANGE")
        rows = self._read_verified()
        if through_offset > len(rows):
            raise WalReplayAdapterError("OFFSET_UNCOMMITTED")
        return tuple(
            self._to_committed_record(index, row)
            for index, row in enumerate(rows, start=1)
            if after_offset < index <= through_offset
        )

    def _require_scope(self, scope_id: str, instrument_id: str) -> None:
        if scope_id != self._scope_id or instrument_id != self._instrument_id:
            raise WalReplayAdapterError("STREAM_MISMATCH")

    def _read_verified(self) -> tuple[RawWalRecordPort, ...]:
        try:
            source_rows = tuple(self._wal.read_all())
        except WalReplayAdapterError:
            raise
        except Exception:
            raise WalReplayAdapterError("INVALID_WAL") from None

        expected_offset = 0
        records: list[RawWalRecordPort] = []
        for candidate in source_rows:
            try:
                require(candidate, _RECORD_TAG)
            except (SealError, TypeError, ValueError):
                raise WalReplayAdapterError("UNISSUED_RECORD") from None
            record = cast(RawWalRecordPort, candidate)
            if record.stream_identity != self._stream_identity:
                raise WalReplayAdapterError("STREAM_MISMATCH")
            if type(record.byte_offset) is not int or type(record.frame_size) is not int:
                raise WalReplayAdapterError("INVALID_WAL")
            if record.byte_offset < expected_offset:
                raise WalReplayAdapterError("WAL_REORDERED")
            if record.byte_offset > expected_offset:
                raise WalReplayAdapterError("WAL_GAP")
            if record.frame_size <= 0:
                raise WalReplayAdapterError("INVALID_WAL")
            expected_offset = record.byte_offset + record.frame_size
            self._verify_receipt(record)
            records.append(record)
        return tuple(records)

    def _verify_receipt(self, record: RawWalRecordPort) -> None:
        try:
            receipt = self._receipt_for(record)
        except Exception:
            raise WalReplayAdapterError("UNVERIFIED_RECEIPT") from None
        if receipt is None:
            raise WalReplayAdapterError("UNVERIFIED_RECEIPT")
        try:
            require(receipt, _RECEIPT_TAG)
        except (SealError, TypeError, ValueError):
            raise WalReplayAdapterError("UNVERIFIED_RECEIPT") from None
        verified_receipt = cast(SinkCommitReceiptPort, receipt)
        try:
            digest = hashlib.sha256(canonical_json(record.model_dump(mode="json"))).hexdigest()
            matches = (
                verified_receipt.record_sha256 == digest
                and verified_receipt.byte_offset == record.byte_offset
                and verified_receipt.frame_size == record.frame_size
                and verified_receipt.stream_identity == record.stream_identity
            )
        except Exception:
            matches = False
        if not matches:
            raise WalReplayAdapterError("RECEIPT_MISMATCH")

    def _to_committed_record(
        self, committed_offset: int, record: RawWalRecordPort
    ) -> CommittedRecordV1:
        watermark = (
            record.source_time_ns
            if record.source_time_ns is not None
            else record.received_time_ns
        )
        try:
            return make_committed_record(
                scope_id=self._scope_id,
                instrument_id=self._instrument_id,
                committed_offset=committed_offset,
                source_event_offset=record.native_sequence,
                semantic_key=record.source_record_key,
                payload=record.raw_payload,
                watermark_utc_ns=watermark,
            )
        except (SnapshotRecoveryError, TypeError, ValueError):
            raise WalReplayAdapterError("INVALID_REPLAY_RECORD") from None


__all__ = [
    "RawWalReadPort",
    "SinkCommitReceiptPort",
    "WalReplayAdapterError",
    "WalReplayAdapterV1",
]
