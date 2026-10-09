"""Fake-Neon snapshot publication and bounded committed-record recovery."""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from threading import RLock
from typing import TYPE_CHECKING, cast

from leviathan_core.numeric import canonical_json
from leviathan_core.seal import SealError, require

from .snapshot_models import (
    CommittedRecordV1,
    CommittedReplayPort,
    SnapshotManifestV1,
    SnapshotRecoveryError,
    SnapshotRecoveryResultV1,
    _issue_recovery_result,
    _issue_snapshot_manifest,
    _schema,
)

if TYPE_CHECKING:
    from leviathan_market_data.live import FreshnessVerdictV1, StreamKey

_RECORD_TAG = "stor003.committed_record.v1"
_FRESHNESS_TAG = "md004.freshness_verdict.v1"
_INT64_MAX = (1 << 63) - 1
_MAX_REPLAY_CEILING = 1_000_000


@dataclass(frozen=True, slots=True)
class _PublishedSnapshot:
    manifest: SnapshotManifestV1
    payload: bytes


@dataclass(frozen=True, slots=True)
class _ReplayOutcome:
    state_bytes: bytes
    source_event_offset: int
    committed_wal_offset: int
    watermark_utc_ns: int
    replayed_count: int
    duplicate_count: int
    error_code: str | None


ReplayApply = Callable[[bytes, CommittedRecordV1], bytes]


def _identifier(value: object, code: str) -> str:
    if type(value) is not str or not value or value != value.strip():
        raise SnapshotRecoveryError(code)
    try:
        value.encode("ascii")
    except UnicodeEncodeError:
        raise SnapshotRecoveryError(code) from None
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-"
    if len(value) > 128 or any(char not in allowed for char in value):
        raise SnapshotRecoveryError(code)
    return value


def _integer(value: object, code: str, *, allow_zero: bool = True) -> int:
    if type(value) is not int or value < (0 if allow_zero else 1) or value > _INT64_MAX:
        raise SnapshotRecoveryError(code)
    return value


class SnapshotRepositoryV1:
    """In-memory fake-Neon store with atomic manifests and bounded warm replay.

    This models transaction and read-back behavior only. It makes no Neon
    durability, fsync, throughput, or restore-time claim.
    """

    backend = "FAKE_NEON"

    def __init__(
        self,
        replay_port: CommittedReplayPort,
        *,
        clock_ns: Callable[[], int],
        max_snapshot_age_ns: int = 60_000_000_000,
        max_replay_records: int = 10_000,
    ) -> None:
        if not isinstance(replay_port, CommittedReplayPort):
            raise SnapshotRecoveryError("REPLAY_PORT_FAILURE")
        if not callable(clock_ns):
            raise SnapshotRecoveryError("INVALID_POLICY")
        age = _integer(max_snapshot_age_ns, "INVALID_POLICY", allow_zero=False)
        count = _integer(max_replay_records, "INVALID_POLICY", allow_zero=False)
        if count > _MAX_REPLAY_CEILING:
            raise SnapshotRecoveryError("INVALID_POLICY")
        self._replay_port = replay_port
        self._clock_ns = clock_ns
        self._max_snapshot_age_ns = age
        self._max_replay_records = count
        self._lock = RLock()
        self._published: dict[tuple[str, str], list[_PublishedSnapshot]] = {}
        self._staging: dict[tuple[str, str], bytes] = {}

    def _now_ns(self) -> int:
        try:
            return _integer(self._clock_ns(), "INVALID_WATERMARK")
        except SnapshotRecoveryError:
            raise
        except Exception:
            raise SnapshotRecoveryError("INVALID_WATERMARK") from None

    def _committed_through(self, scope: str, instrument: str) -> int:
        try:
            return _integer(
                self._replay_port.committed_through(scope_id=scope, instrument_id=instrument),
                "OFFSET_MISMATCH",
            )
        except SnapshotRecoveryError:
            raise
        except Exception:
            raise SnapshotRecoveryError("REPLAY_PORT_FAILURE") from None

    def create_snapshot(
        self,
        *,
        scope_id: str,
        instrument_id: str,
        state_schema: str,
        state_bytes: bytes,
        source_event_offset: int,
        committed_wal_offset: int,
        watermark_utc_ns: int,
        lineage: tuple[str, ...],
        fail_after_temp_write: bool = False,
    ) -> SnapshotManifestV1:
        """Stage, read back, and atomically publish a snapshot manifest and bytes."""
        scope = _identifier(scope_id, "INVALID_IDENTITY")
        instrument = _identifier(instrument_id, "INVALID_IDENTITY")
        schema = _schema(state_schema)
        source_offset = _integer(source_event_offset, "INVALID_OFFSET")
        wal_offset = _integer(committed_wal_offset, "INVALID_OFFSET")
        watermark = _integer(watermark_utc_ns, "INVALID_WATERMARK")
        now = self._now_ns()
        if type(state_bytes) is not bytes:
            raise SnapshotRecoveryError("INVALID_BYTES")
        if type(fail_after_temp_write) is not bool:
            raise SnapshotRecoveryError("INVALID_FAILPOINT")
        if type(lineage) is not tuple or not lineage or len(lineage) > 64:
            raise SnapshotRecoveryError("INVALID_LINEAGE")
        checked_lineage = tuple(_identifier(item, "INVALID_LINEAGE") for item in lineage)
        committed = self._committed_through(scope, instrument)
        if wal_offset > committed:
            raise SnapshotRecoveryError("OFFSET_UNCOMMITTED")
        if watermark > now:
            raise SnapshotRecoveryError("INVALID_WATERMARK")

        payload_digest = hashlib.sha256(state_bytes).hexdigest()
        metadata = {
            "scope_id": scope,
            "instrument_id": instrument,
            "state_schema": schema,
            "source_event_offset": source_offset,
            "committed_wal_offset": wal_offset,
            "watermark_utc_ns": watermark,
            "byte_length": len(state_bytes),
            "sha256_digest": payload_digest,
            "created_utc_ns": now,
            "lineage": checked_lineage,
        }
        snapshot_id = hashlib.sha256(canonical_json(metadata)).hexdigest()
        manifest = _issue_snapshot_manifest(**metadata, snapshot_id=snapshot_id)
        key = (scope, instrument)
        with self._lock:
            self._staging[key] = state_bytes
            if fail_after_temp_write:
                raise SnapshotRecoveryError("SNAPSHOT_INTERRUPTED")
            readback = self._staging.get(key)
            if (
                type(readback) is not bytes
                or len(readback) != manifest.byte_length
                or hashlib.sha256(readback).hexdigest() != manifest.sha256_digest
            ):
                self._staging.pop(key, None)
                raise SnapshotRecoveryError("SNAPSHOT_CORRUPT")
            previous = self._published.get(key, [])
            latest = self._latest_row(previous)
            if latest is not None and now < latest.manifest.created_utc_ns:
                self._staging.pop(key, None)
                raise SnapshotRecoveryError("INVALID_WATERMARK")
            if any(item.manifest.snapshot_id == snapshot_id for item in previous):
                existing = next(
                    item for item in previous if item.manifest.snapshot_id == snapshot_id
                )
                if existing.payload != readback or existing.manifest != manifest:
                    raise SnapshotRecoveryError("SNAPSHOT_CORRUPT")
                self._staging.pop(key, None)
                return existing.manifest
            if any(
                item.manifest.created_utc_ns == now
                and item.manifest.committed_wal_offset == wal_offset
                for item in previous
            ):
                self._staging.pop(key, None)
                raise SnapshotRecoveryError("SNAPSHOT_CONFLICT")
            published = [*previous, _PublishedSnapshot(manifest, readback)]
            self._published[key] = published
            self._staging.pop(key, None)
            return manifest

    def latest_manifest(self, *, scope_id: str, instrument_id: str) -> SnapshotManifestV1:
        """Return the newest published manifest, never a staged partial snapshot."""
        key = (
            _identifier(scope_id, "INVALID_IDENTITY"),
            _identifier(instrument_id, "INVALID_IDENTITY"),
        )
        with self._lock:
            rows = self._published.get(key, [])
            if not rows:
                raise SnapshotRecoveryError("SNAPSHOT_NOT_FOUND")
            latest = self._latest_row(rows)
            if latest is None:
                raise SnapshotRecoveryError("SNAPSHOT_NOT_FOUND")
            manifest = latest.manifest
            try:
                require(manifest, "stor003.snapshot_manifest.v1")
            except SealError:
                raise SnapshotRecoveryError("SNAPSHOT_CORRUPT") from None
            return manifest

    @staticmethod
    def _latest_row(rows: Iterable[_PublishedSnapshot]) -> _PublishedSnapshot | None:
        return max(
            rows,
            key=lambda item: (
                item.manifest.created_utc_ns,
                item.manifest.committed_wal_offset,
                item.manifest.snapshot_id,
            ),
            default=None,
        )

    def inject_corruption_for_test(self, *, snapshot_id: str, replacement: bytes) -> None:
        """Mutate fake stored bytes to exercise read-back integrity failures."""
        snapshot = _identifier(snapshot_id, "INVALID_IDENTITY")
        if type(replacement) is not bytes:
            raise SnapshotRecoveryError("INVALID_BYTES")
        with self._lock:
            for _key, rows in self._published.items():
                for index, row in enumerate(rows):
                    if row.manifest.snapshot_id == snapshot:
                        rows[index] = _PublishedSnapshot(row.manifest, replacement)
                        return
        raise SnapshotRecoveryError("SNAPSHOT_NOT_FOUND")

    def _verify_candidate(
        self,
        row: _PublishedSnapshot,
        *,
        expected_schema: str,
        now: int,
    ) -> str | None:
        try:
            require(row.manifest, "stor003.snapshot_manifest.v1")
        except SealError:
            return "SNAPSHOT_CORRUPT"
        if row.manifest.state_schema != expected_schema:
            return "SNAPSHOT_SCHEMA_MISMATCH"
        if row.manifest.created_utc_ns > now:
            return "SNAPSHOT_STALE"
        if now - row.manifest.created_utc_ns > self._max_snapshot_age_ns:
            return "SNAPSHOT_STALE"
        if (
            type(row.payload) is not bytes
            or len(row.payload) != row.manifest.byte_length
            or hashlib.sha256(row.payload).hexdigest() != row.manifest.sha256_digest
        ):
            return "SNAPSHOT_CORRUPT"
        return None

    def _read_rows(
        self,
        *,
        scope: str,
        instrument: str,
        after_offset: int,
        through_offset: int,
        state_bytes: bytes,
        source_event_offset: int,
        watermark: int,
        apply_record: ReplayApply,
    ) -> _ReplayOutcome:
        current_offset = after_offset
        current_source_offset = source_event_offset
        current_watermark = watermark
        replayed = duplicates = 0
        seen: dict[str, tuple[int, int, str]] = {}
        if through_offset < after_offset:
            return _ReplayOutcome(
                state_bytes, source_event_offset, after_offset, watermark, 0, 0, "OFFSET_MISMATCH"
            )
        if through_offset == after_offset:
            return _ReplayOutcome(
                state_bytes, source_event_offset, current_offset, watermark, 0, 0, None
            )
        try:
            rows: Iterable[CommittedRecordV1] = self._replay_port.read_committed(
                scope_id=scope,
                instrument_id=instrument,
                after_offset=after_offset,
                through_offset=through_offset,
            )
            if isinstance(rows, (bytes, str)):
                return _ReplayOutcome(
                    state_bytes,
                    source_event_offset,
                    after_offset,
                    watermark,
                    0,
                    0,
                    "REPLAY_PORT_FAILURE",
                )
            for record in rows:
                if current_offset - after_offset >= self._max_replay_records:
                    raise SnapshotRecoveryError("WAL_LIMIT_EXCEEDED")
                try:
                    if type(record) is not CommittedRecordV1:
                        raise SealError("SEAL_NOT_ISSUED")
                    require(record, _RECORD_TAG)
                except SealError:
                    raise SnapshotRecoveryError("INVALID_REPLAY_RECORD") from None
                if (record.scope_id, record.instrument_id) != (scope, instrument):
                    raise SnapshotRecoveryError("WAL_SCOPE_MISMATCH")
                expected_offset = current_offset + 1
                if record.committed_offset < expected_offset:
                    raise SnapshotRecoveryError("WAL_REORDERED")
                if record.committed_offset > expected_offset:
                    raise SnapshotRecoveryError("WAL_GAP")
                if record.watermark_utc_ns < current_watermark:
                    raise SnapshotRecoveryError("WATERMARK_MISMATCH")
                payload_digest = hashlib.sha256(record.payload).hexdigest()
                signature = (
                    record.source_event_offset,
                    record.watermark_utc_ns,
                    payload_digest,
                )
                previous = seen.get(record.semantic_key)
                if previous is not None:
                    if previous != signature:
                        raise SnapshotRecoveryError("WAL_CONFLICT")
                    duplicates += 1
                else:
                    try:
                        new_state = apply_record(state_bytes, record)
                    except Exception:
                        raise SnapshotRecoveryError("REPLAY_PORT_FAILURE") from None
                    if type(new_state) is not bytes:
                        raise SnapshotRecoveryError("INVALID_REPLAY_OUTPUT")
                    state_bytes = new_state
                    seen[record.semantic_key] = signature
                    replayed += 1
                current_offset = record.committed_offset
                current_source_offset = record.source_event_offset
                current_watermark = record.watermark_utc_ns
        except SnapshotRecoveryError as exc:
            return _ReplayOutcome(
                b"", source_event_offset, after_offset, watermark, 0, 0, exc.code
            )
        except Exception:
            return _ReplayOutcome(
                b"", source_event_offset, after_offset, watermark, 0, 0, "REPLAY_PORT_FAILURE"
            )
        if current_offset != through_offset:
            return _ReplayOutcome(
                b"", source_event_offset, current_offset, current_watermark,
                replayed, duplicates, "WAL_GAP"
            )
        return _ReplayOutcome(
            state_bytes,
            current_source_offset,
            current_offset,
            current_watermark,
            replayed,
            duplicates,
            None,
        )

    @staticmethod
    def _stream_key(value: object) -> StreamKey:
        if type(value) is not tuple or len(value) != 6:
            raise SnapshotRecoveryError("FRESHNESS_BLOCKED")
        if any(type(item) is not str for item in value):
            raise SnapshotRecoveryError("FRESHNESS_BLOCKED")
        for item in value:
            _identifier(item, "FRESHNESS_BLOCKED")
        return cast(tuple[str, str, str, str, str, str], value)

    def recover(
        self,
        *,
        scope_id: str,
        instrument_id: str,
        expected_state_schema: str,
        expected_committed_wal_offset: int,
        expected_watermark_utc_ns: int,
        freshness_verdict: FreshnessVerdictV1,
        expected_stream_key: StreamKey,
        apply_record: ReplayApply,
    ) -> SnapshotRecoveryResultV1:
        """Recover from a verified snapshot or bounded full warm-read replay.

        A healthy result is issued only when the snapshot is fresh and intact,
        replay exactly reaches the committed offset and watermark, and MD-004's
        sealed verdict allows publication for the requested stream.
        """
        scope = _identifier(scope_id, "INVALID_IDENTITY")
        instrument = _identifier(instrument_id, "INVALID_IDENTITY")
        schema = _schema(expected_state_schema)
        expected_offset = _integer(expected_committed_wal_offset, "INVALID_OFFSET")
        expected_watermark = _integer(expected_watermark_utc_ns, "INVALID_WATERMARK")
        if not callable(apply_record):
            raise SnapshotRecoveryError("INVALID_POLICY")
        stream_key = self._stream_key(expected_stream_key)
        if stream_key[3] != instrument:
            raise SnapshotRecoveryError("FRESHNESS_BLOCKED")
        now = self._now_ns()
        if expected_watermark > now:
            raise SnapshotRecoveryError("INVALID_WATERMARK")
        port_error: str | None
        try:
            require(freshness_verdict, _FRESHNESS_TAG)
            freshness_ok = (
                freshness_verdict.stream_key == stream_key
                and freshness_verdict.evaluated_utc_ns == now
                and freshness_verdict.state == "HEALTHY"
                and freshness_verdict.publication_allowed is True
                and freshness_verdict.execution_eligible is False
            )
        except Exception:
            freshness_ok = False
        try:
            port_offset = self._committed_through(scope, instrument)
        except SnapshotRecoveryError as exc:
            port_offset = expected_offset
            port_error = exc.code
        else:
            port_error = None

        key = (scope, instrument)
        with self._lock:
            rows = tuple(self._published.get(key, ()))
        ordered_rows = sorted(
            rows,
            key=lambda item: (
                item.manifest.created_utc_ns,
                item.manifest.committed_wal_offset,
                item.manifest.snapshot_id,
            ),
            reverse=True,
        )
        candidate: _PublishedSnapshot | None = None
        issue: str | None = None
        for row in ordered_rows:
            candidate_issue = self._verify_candidate(
                row, expected_schema=schema, now=now
            )
            if (
                candidate_issue is None
                and row.manifest.committed_wal_offset > expected_offset
            ):
                candidate_issue = "OFFSET_MISMATCH"
            if candidate_issue is None:
                candidate = row
                issue = None
                break
            if issue is None:
                issue = candidate_issue
        if candidate is None and issue is None:
            issue = "SNAPSHOT_NOT_FOUND"

        reason: str | None = None
        if port_error is not None:
            outcome = _ReplayOutcome(b"", 0, 0, 0, 0, 0, port_error)
            used_snapshot = False
            used_warm = False
            snapshot_id = None
            result_schema = schema
            reason = port_error
        elif port_offset != expected_offset:
            outcome = _ReplayOutcome(b"", 0, 0, 0, 0, 0, "OFFSET_MISMATCH")
            used_snapshot = False
            used_warm = False
            snapshot_id = None
            result_schema = schema
            reason = "OFFSET_MISMATCH"
        elif candidate is not None and issue is None:
            manifest = candidate.manifest
            if expected_offset < manifest.committed_wal_offset:
                outcome = _ReplayOutcome(
                    candidate.payload,
                    manifest.source_event_offset,
                    manifest.committed_wal_offset,
                    manifest.watermark_utc_ns,
                    0,
                    0,
                    "OFFSET_MISMATCH",
                )
            else:
                outcome = self._read_rows(
                    scope=scope,
                    instrument=instrument,
                    after_offset=manifest.committed_wal_offset,
                    through_offset=expected_offset,
                    state_bytes=candidate.payload,
                    source_event_offset=manifest.source_event_offset,
                    watermark=manifest.watermark_utc_ns,
                    apply_record=apply_record,
                )
            used_snapshot = True
            used_warm = False
            snapshot_id = manifest.snapshot_id
            result_schema = manifest.state_schema
            reason = outcome.error_code
        else:
            outcome = self._read_rows(
                scope=scope,
                instrument=instrument,
                after_offset=0,
                through_offset=expected_offset,
                state_bytes=b"",
                source_event_offset=0,
                watermark=0,
                apply_record=apply_record,
            )
            used_snapshot = False
            used_warm = True
            snapshot_id = None
            result_schema = schema
            reason = issue or "SNAPSHOT_NOT_FOUND"
            if outcome.error_code is not None:
                reason = outcome.error_code

        if reason is None and outcome.watermark_utc_ns != expected_watermark:
            reason = "WATERMARK_MISMATCH"
        if reason is None and not freshness_ok:
            reason = "FRESHNESS_BLOCKED"
        healthy = reason is None and used_snapshot and not used_warm
        reasons = () if healthy else (reason or "FRESHNESS_BLOCKED",)
        final_state = outcome.state_bytes if outcome.error_code is None else b""
        final_source_offset = outcome.source_event_offset if outcome.error_code is None else 0
        final_offset = outcome.committed_wal_offset if outcome.error_code is None else 0
        final_watermark = outcome.watermark_utc_ns if outcome.error_code is None else 0
        return _issue_recovery_result(
            scope_id=scope,
            instrument_id=instrument,
            status="HEALTHY" if healthy else "DEGRADED",
            traffic_allowed=healthy,
            snapshot_id=snapshot_id,
            state_schema=result_schema,
            state_bytes_base64=base64.b64encode(final_state).decode("ascii"),
            source_event_offset=final_source_offset,
            committed_wal_offset=final_offset,
            watermark_utc_ns=final_watermark,
            used_snapshot=used_snapshot,
            used_warm_read=used_warm,
            replayed_count=outcome.replayed_count,
            duplicate_count=outcome.duplicate_count,
            reason_codes=reasons,
        )


__all__ = ["ReplayApply", "SnapshotRepositoryV1"]
