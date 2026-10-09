from __future__ import annotations

import hashlib
from decimal import Decimal
from pathlib import Path

import pytest
from capability_support import issue_test_capability

from leviathan_market_data.live.book_cache import (
    OBS004_PIPELINE_LAG,
    OBS004_STREAM_FRESHNESS_LAG,
    BackpressureController,
    BookCache,
    BookKeyV1,
    MarketCacheError,
    is_issued_book_snapshot_receipt,
    report_pipeline_lag,
    report_stream_freshness_lag,
    validate_control_envelope,
)
from leviathan_market_data.live.checkpoint import _issue_gap_manifest
from leviathan_market_data.live.gap_fill import (
    GapFillAdapter,
    GapFillBatchV1,
    GapFillError,
    GapFillRecordV1,
    is_issued_gap_fill_manifest,
    is_issued_gap_fill_result,
)
from leviathan_market_data.live.reference_cache import ReferenceCache
from leviathan_market_data.live.replay import (
    NativeContinuitySnapshotV1,
    SessionTransitionConfirmationV1,
)
from leviathan_market_data.live.wal import AppendOnlyWal
from leviathan_market_data.schema import (
    BookDeltaPayload,
    BookLevel,
    BookSnapshotPayload,
    CorporateActionPayload,
    NormalizedMarketEventV1,
    PriceValue,
    ReferencePayload,
)

PROVIDER = "synthetic-provider"
STREAM = (PROVIDER, "synthetic-dataset", "XTEST", "SYN-1", "trades")
SESSION = "synthetic-session"
BASE_NS = 1_780_000_000_000_000_000


class FakeFillSource:
    provider_id = PROVIDER

    def __init__(self, records: tuple[GapFillRecordV1, ...]) -> None:
        self.records = records
        self.calls = 0

    def continuity_snapshot(self) -> NativeContinuitySnapshotV1:
        return NativeContinuitySnapshotV1(
            session_id=SESSION,
            next_sequence=2,
            resume_token="synthetic-gap-resume",
            gap_ranges=(),
        )

    def confirm_session_transition(
        self, old_session_id: str, new_session_id: str
    ) -> SessionTransitionConfirmationV1:
        return SessionTransitionConfirmationV1(
            from_session_id=old_session_id,
            to_session_id=new_session_id,
            status="CONFIRMED",
        )

    def fetch_gap(
        self, *, session_id: str, start_sequence: int, end_sequence: int
    ) -> GapFillBatchV1:
        self.calls += 1
        return GapFillBatchV1(
            provider_id=self.provider_id,
            session_id=session_id,
            records=self.records,
        )


def record(sequence: int, *, provider_id: str = PROVIDER) -> GapFillRecordV1:
    return GapFillRecordV1(
        provider_id=provider_id,
        session_id=SESSION,
        source_record_key=f"synthetic-key-{sequence}",
        native_record_id=f"synthetic-id-{sequence}",
        native_sequence=sequence,
        source_time_ns=BASE_NS + sequence,
        received_time_ns=BASE_NS + sequence + 1,
        raw_payload=f'{{"sequence":{sequence}}}'.encode(),
    )


def append_seed(wal: AppendOnlyWal) -> None:
    wal.append(
        stream_identity=STREAM,
        session_id=SESSION,
        source_record_key="seed-key-1",
        native_record_id="seed-id-1",
        native_sequence=1,
        source_time_ns=BASE_NS,
        received_time_ns=BASE_NS + 1,
        raw_payload=b'{"sequence":1}',
    )


def event(
    event_type: str,
    sequence: int,
    payload: object,
    *,
    event_time_ns: int | None = None,
    instrument_id: str = "synthetic-instrument",
) -> NormalizedMarketEventV1:
    digest = hashlib.sha256(b"synthetic-payload").hexdigest()
    return NormalizedMarketEventV1(
        event_id=f"00000000-0000-0000-0000-{sequence:012d}",
        provider=PROVIDER,
        dataset="synthetic-dataset",
        venue="XTEST",
        native_symbol="SYN-1",
        leviathan_symbol="SYN1",
        instrument_id=instrument_id,
        instrument_type="equity",
        channel="synthetic-channel",
        event_type=event_type,
        source_mode="live",
        event_time_ns=event_time_ns or BASE_NS + sequence,
        source_time_ns=BASE_NS + sequence,
        exchange_time_ns=BASE_NS + sequence,
        ingest_time_ns=BASE_NS + sequence,
        processing_time_ns=BASE_NS + sequence,
        received_time_ns=BASE_NS + sequence,
        native_sequence=sequence,
        sequence_synthetic=False,
        native_trade_id=None,
        source_record_key=f"event-key-{sequence}",
        provider_session_id=SESSION,
        source_record_ref=f"synthetic-ref-{sequence}",
        source_payload_sha256=digest,
        mapping_version="mapping/1",
        identity_policy_version="identity/1",
        quality_flags=(),
        reconstructed=False,
        idempotency_key=f"event-idem-{sequence}",
        payload=payload,
    )


def test_gap_fill_requires_exact_range_and_appends_in_sequence(tmp_path: Path) -> None:
    wal = AppendOnlyWal(tmp_path / "events.wal")
    append_seed(wal)
    source = FakeFillSource((record(2), record(3)))
    capability = issue_test_capability(source, PROVIDER)
    adapter = GapFillAdapter(source, capability)
    gap = _issue_gap_manifest(
        provider_id=PROVIDER, session_id=SESSION, ranges=((2, 4),)
    )
    manifest = adapter.open_gap(gap)
    assert is_issued_gap_fill_manifest(manifest)

    result = adapter.fill(manifest, wal)

    assert result.continuity == "CONTINUOUS"
    assert is_issued_gap_fill_result(result)
    assert result.manifest.state == "FILLED"
    assert result.manifest.filled_count == 2
    assert tuple(item.reconstructed for item in result.reconstructed_records) == (True, True)
    assert tuple(row.native_sequence for row in wal.read_all()) == (1, 2, 3)
    with pytest.raises(GapFillError) as exc:
        adapter.fill(result.manifest, wal)
    assert exc.value.code == "GAP_ALREADY_CLOSED"


def test_partial_fill_stays_open_and_does_not_append(tmp_path: Path) -> None:
    wal = AppendOnlyWal(tmp_path / "events.wal")
    append_seed(wal)
    source = FakeFillSource((record(2),))
    adapter = GapFillAdapter(source, issue_test_capability(source, PROVIDER))
    gap = _issue_gap_manifest(
        provider_id=PROVIDER, session_id=SESSION, ranges=((2, 4),)
    )

    result = adapter.fill(adapter.open_gap(gap), wal)

    assert result.continuity == "UNKNOWN"
    assert result.error_code == "GAP_COVERAGE_INCOMPLETE"
    assert result.manifest.state == "OPEN"
    assert tuple(row.native_sequence for row in wal.read_all()) == (1,)


def test_multi_range_source_gap_is_not_partially_marked_continuous() -> None:
    source = FakeFillSource(())
    adapter = GapFillAdapter(source, issue_test_capability(source, PROVIDER))
    gap = _issue_gap_manifest(
        provider_id=PROVIDER, session_id=SESSION, ranges=((2, 4), (6, 7))
    )
    with pytest.raises(GapFillError) as exc:
        adapter.open_gap(gap)
    assert exc.value.code == "INVALID_GAP_MANIFEST"


def test_untrusted_or_cross_provider_fill_fails_closed(tmp_path: Path) -> None:
    wal = AppendOnlyWal(tmp_path / "events.wal")
    append_seed(wal)
    source = FakeFillSource((record(2, provider_id="other-provider"),))
    gap = _issue_gap_manifest(
        provider_id=PROVIDER, session_id=SESSION, ranges=((2, 3),)
    )
    untrusted = GapFillAdapter(source, object())  # type: ignore[arg-type]
    with pytest.raises(GapFillError) as exc:
        untrusted.open_gap(gap)
    assert exc.value.code == "UNTRUSTED_PROVIDER"

    adapter = GapFillAdapter(source, issue_test_capability(source, PROVIDER))
    result = adapter.fill(adapter.open_gap(gap), wal)
    assert result.continuity == "UNKNOWN"
    assert result.error_code == "PROVIDER_MISMATCH"
    assert tuple(row.native_sequence for row in wal.read_all()) == (1,)


def test_book_snapshot_and_delta_are_coherent_and_atomic() -> None:
    cache = BookCache(depth=1, ttl_ns=100)
    base = event(
        "book_snapshot",
        1,
        BookSnapshotPayload(
            levels=(
                BookLevel(side="bid", price=PriceValue(value="100"), size="2"),
                BookLevel(side="bid", price=PriceValue(value="99"), size="3"),
                BookLevel(side="ask", price=PriceValue(value="101"), size="4"),
            )
        ),
    )
    assert cache.apply(base).coherent
    key = BookKeyV1(
        provider=PROVIDER,
        dataset="synthetic-dataset",
        venue="XTEST",
        instrument_id="synthetic-instrument",
    )
    snapshot = cache.snapshot(key, now_ns=BASE_NS + 1)
    assert is_issued_book_snapshot_receipt(snapshot)
    assert snapshot.coherent
    assert snapshot.snapshot is not None
    assert len(snapshot.snapshot.levels) == 2

    bad = event(
        "book_delta",
        3,
        BookDeltaPayload(
            action="delete", side="bid", price=PriceValue(value="100")
        ),
    )
    receipt = cache.apply(bad)
    assert receipt.status == "SEQUENCE_GAP"
    assert not receipt.coherent
    assert cache.snapshot(key, now_ns=BASE_NS + 3).snapshot is None


def test_book_ttl_eviction_batch_dedupe_and_control_envelope_bounds() -> None:
    cache = BookCache(max_books=1, ttl_ns=10)
    first = event("book_snapshot", 1, BookSnapshotPayload(levels=()))
    cache.apply(first)
    key = BookKeyV1(
        provider=PROVIDER,
        dataset="synthetic-dataset",
        venue="XTEST",
        instrument_id="synthetic-instrument",
    )
    expired = cache.snapshot(key, now_ns=BASE_NS + 12)
    assert expired.reason == "STALE"
    assert cache.evictions
    second_book = event(
        "book_snapshot",
        2,
        BookSnapshotPayload(levels=()),
        instrument_id="synthetic-instrument-2",
    )
    cache.apply(second_book)
    capacity_cache = BookCache(max_books=1)
    capacity_cache.apply(first)
    capacity_cache.apply(second_book)
    assert len(capacity_cache.evictions) == 1
    window1 = cache.accept_batch_window(topic="trades", start_ns=1, end_ns=2)
    window2 = cache.accept_batch_window(topic="trades", start_ns=1, end_ns=2)
    assert window1.accepted and not window2.accepted
    assert cache.accept_batch_window(
        topic="trades", start_ns=1_000_000_003, end_ns=1_000_000_004
    ).accepted
    control = validate_control_envelope(
        event("news", 5, {"kind": "news", "headline": "synthetic"})
    )
    assert control.accepted
    assert control.size_bytes <= 65_536
    with pytest.raises(MarketCacheError) as exc:
        validate_control_envelope(
            event("news", 6, {"kind": "news", "headline": "x" * 70_000})
        )
    assert exc.value.code == "ENVELOPE_TOO_LARGE"


def test_reference_versions_and_corporate_actions_are_effective_time_filtered() -> None:
    cache = ReferenceCache(ttl_ns=10_000)
    reference = event(
        "reference", 1, ReferencePayload(attributes={"tick_size": "0.01", "name": "Synthetic"})
    )
    action = event(
        "corporate_action",
        2,
        CorporateActionPayload(
            action="split", effective_time_ns=BASE_NS + 20, details={"ratio": "2:1"}
        ),
    )
    assert cache.apply(reference).accepted
    assert cache.apply(action).accepted
    before = cache.get("synthetic-instrument", as_of_ns=BASE_NS + 15)
    after = cache.get("synthetic-instrument", as_of_ns=BASE_NS + 20)
    assert dict(before.attributes)["tick_size"] == "0.01"
    assert before.corporate_actions == ()
    assert len(after.corporate_actions) == 1
    assert not after.stale


def test_reference_capacity_eviction_is_recorded() -> None:
    cache = ReferenceCache(max_symbols=1)
    first = event("reference", 1, ReferencePayload(attributes={"name": "One"}))
    second = event(
        "reference",
        2,
        ReferencePayload(attributes={"name": "Two"}),
        instrument_id="synthetic-instrument-2",
    )
    assert cache.apply(first).accepted
    assert cache.apply(second).accepted
    assert len(cache.evictions) == 1


def test_backpressure_uses_strict_hysteresis_and_accounts_drops() -> None:
    guard = BackpressureController(max_quality_drops=2)
    assert not guard.observe_lag(1_000_000_000).active
    assert guard.observe_lag(1_000_000_001).active
    assert guard.observe_lag(250_000_000).active
    assert not guard.observe_lag(249_999_999).active
    assert guard.account_drop().quality_drop_count == 1
    with pytest.raises(MarketCacheError) as exc:
        guard.account_drop(critical=True)
    assert exc.value.code == "CRITICAL_STATE_PRESERVED"


def test_metrics_use_only_registered_obs004_names() -> None:
    sink = FakeMetricsSink()
    labels = {
        "service": "market-data",
        "component": "cache",
        "env": "test",
        "region": "local",
        "instance": "synthetic",
    }
    assert report_pipeline_lag(sink, labels, 1_234_567_890)
    assert report_stream_freshness_lag(sink, labels, 2_000_000_000)
    assert [item[0] for item in sink.values] == [
        OBS004_PIPELINE_LAG,
        OBS004_STREAM_FRESHNESS_LAG,
    ]
    assert sink.values[0][1] == Decimal("1.234567890")


class FakeMetricsSink:
    def __init__(self) -> None:
        self.values: list[tuple[str, Decimal, dict[str, str]]] = []

    def record_catalog_metric(
        self, name: str, value: Decimal, labels: dict[str, str]
    ) -> bool:
        self.values.append((name, value, labels))
        return True
