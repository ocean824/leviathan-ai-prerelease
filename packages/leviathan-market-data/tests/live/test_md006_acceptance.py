from __future__ import annotations

from collections.abc import Sequence
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
    report_pipeline_lag,
    report_stream_freshness_lag,
    validate_control_envelope,
)
from leviathan_market_data.live.gap_fill import (
    GapFillAdapter,
    GapFillBatchV1,
    GapFillError,
    GapFillManifestV1,
    GapFillRecordV1,
    is_issued_gap_fill_result,
    is_issued_reconstructed_wal_record,
)
from leviathan_market_data.live.reference_cache import ReferenceCache
from leviathan_market_data.live.replay import (
    GapManifestV1,
    NativeContinuitySnapshotV1,
    SessionTransitionConfirmationV1,
    SourceAdapter,
    TrustedProviderCapabilityV1,
)
from leviathan_market_data.live.wal import AppendOnlyWal
from leviathan_market_data.normalization import Normalizer, VendorRecord
from leviathan_market_data.symbology import InstrumentMapping, MappingRegistry

PROVIDER = "synthetic-gap-provider"
SESSION = "synthetic-gap-session"
STREAM = (PROVIDER, "synthetic-dataset", "XTEST", "SYN-1", "trades")
NOW_NS = 1_780_000_000_000_000_000
DATASET = "synthetic-dataset"
VENUE = "XTEST"
NATIVE_SYMBOL = "SYN-1"
INSTRUMENT_ID = "instrument-synthetic-1"


class FakeGapSource:
    provider_id = PROVIDER

    def __init__(
        self,
        records: Sequence[GapFillRecordV1] = (),
        *,
        session_id: str = SESSION,
        next_sequence: int = 4,
        ranges: tuple[tuple[int, int], ...] = ((2, 4),),
        batch_provider_id: str | None = None,
    ) -> None:
        self.records = tuple(records)
        self.session_id = session_id
        self.next_sequence = next_sequence
        self.ranges = ranges
        self.batch_provider_id = batch_provider_id or self.provider_id
        self.fetch_calls: list[tuple[str, int, int]] = []

    def continuity_snapshot(self) -> NativeContinuitySnapshotV1:
        return NativeContinuitySnapshotV1(
            session_id=self.session_id,
            next_sequence=self.next_sequence,
            resume_token="synthetic-resume",
            gap_ranges=self.ranges,
        )

    def confirm_session_transition(
        self, from_session_id: str, to_session_id: str
    ) -> SessionTransitionConfirmationV1:
        return SessionTransitionConfirmationV1(
            from_session_id=from_session_id,
            to_session_id=to_session_id,
            status="CONFIRMED",
        )

    def fetch_gap(
        self, *, session_id: str, start_sequence: int, end_sequence: int
    ) -> GapFillBatchV1:
        self.fetch_calls.append((session_id, start_sequence, end_sequence))
        return GapFillBatchV1(
            provider_id=self.batch_provider_id,
            session_id=session_id,
            records=self.records,
        )


def make_fill_record(sequence: int, *, provider: str = PROVIDER) -> GapFillRecordV1:
    return GapFillRecordV1(
        provider_id=provider,
        session_id=SESSION,
        source_record_key=f"synthetic-gap-key-{sequence}",
        native_record_id=f"synthetic-gap-native-{sequence}",
        native_sequence=sequence,
        source_time_ns=NOW_NS + sequence,
        received_time_ns=NOW_NS + sequence + 1,
        raw_payload=f'{{"sequence":{sequence},"synthetic":true}}'.encode(),
    )


def make_gap(source: FakeGapSource):
    capability = issue_test_capability(source, source.provider_id)
    position, gap = SourceAdapter(source, capability).continuity()
    assert position is not None
    assert gap is not None
    return capability, gap


def seed_wal(
    path: Path, *, max_records: int = 100, provider: str = PROVIDER
) -> AppendOnlyWal:
    wal = AppendOnlyWal(path, max_records=max_records)
    wal.append(
        stream_identity=(provider, *STREAM[1:]),
        session_id=SESSION,
        source_record_key="synthetic-gap-key-1",
        native_record_id="synthetic-gap-native-1",
        native_sequence=1,
        source_time_ns=NOW_NS + 1,
        received_time_ns=NOW_NS + 2,
        raw_payload=b'{"sequence":1,"synthetic":true}',
    )
    return wal


def normalized_event(
    event_type: str,
    payload: dict[str, object],
    *,
    sequence: int,
    channel: str,
    instrument_id: str = INSTRUMENT_ID,
):
    mapping = InstrumentMapping(
        provider=PROVIDER,
        dataset=DATASET,
        venue=VENUE,
        native_symbol=NATIVE_SYMBOL,
        instrument_id=instrument_id,
        leviathan_symbol="SYN",
        instrument_type="equity",
        mapping_version="synthetic-map-v1",
    )
    normalizer = Normalizer(MappingRegistry((mapping,)))
    event_time = NOW_NS + sequence * 10
    record = VendorRecord(
        provider=PROVIDER,
        dataset=DATASET,
        venue=VENUE,
        native_symbol=NATIVE_SYMBOL,
        channel=channel,
        event_type=event_type,
        event_time_ns=event_time,
        source_record_ref=f"synthetic-source-ref-{event_type}-{sequence}",
        payload=payload,
        source_mode="live",
        source_time_ns=event_time,
        exchange_time_ns=event_time,
        native_sequence=sequence,
        source_record_key=f"synthetic-event-key-{event_type}-{sequence}",
        ingest_time_ns=event_time + 1,
        received_time_ns=event_time + 1,
        processing_time_ns=event_time + 2,
        provider_session_id=SESSION,
    )
    return normalizer.normalize(record, now_ns=NOW_NS + 10_000)


def test_gap_fill_appends_exact_range_then_reports_continuity(tmp_path: Path) -> None:
    source = FakeGapSource((make_fill_record(2), make_fill_record(3)))
    capability, gap = make_gap(source)
    adapter = GapFillAdapter(source, capability)
    manifest = adapter.open_gap(gap)
    wal = seed_wal(tmp_path / "exact-fill.wal")

    result = adapter.fill(manifest, wal)

    assert result.continuity == "CONTINUOUS"
    assert result.error_code is None
    assert result.manifest.state == "FILLED"
    assert result.manifest.filled_count == 2
    assert result.manifest.source_gap_sha256
    assert result.appended_sequences == (2, 3)
    assert is_issued_gap_fill_result(result)
    assert all(is_issued_reconstructed_wal_record(item) for item in result.reconstructed_records)
    assert [item.record.native_sequence for item in result.reconstructed_records] == [2, 3]
    assert [record.native_sequence for record in wal.read_all()] == [1, 2, 3]
    assert source.fetch_calls == [(SESSION, 2, 4)]


def test_incomplete_fill_does_not_append_or_claim_continuity(tmp_path: Path) -> None:
    source = FakeGapSource((make_fill_record(2),))
    capability, gap = make_gap(source)
    adapter = GapFillAdapter(source, capability)
    manifest = adapter.open_gap(gap)
    wal = seed_wal(tmp_path / "incomplete-fill.wal")
    before = wal.read_all()

    result = adapter.fill(manifest, wal)

    assert result.continuity == "UNKNOWN"
    assert result.manifest.state in ("OPEN", "FAILED")
    assert result.manifest.filled_count == 0
    assert result.appended_sequences == ()
    assert result.error_code == "GAP_COVERAGE_INCOMPLETE"
    assert wal.read_all() == before


def test_gap_fill_requires_one_explicit_provider_reported_interval() -> None:
    source_without_gap = FakeGapSource(ranges=())
    capability_without_gap = issue_test_capability(source_without_gap, PROVIDER)
    _, no_gap = make_gap(source_without_gap)
    assert no_gap.ranges == ()
    with pytest.raises(GapFillError) as absent:
        GapFillAdapter(source_without_gap, capability_without_gap).open_gap(no_gap)
    assert absent.value.code == "INVALID_GAP_MANIFEST"

    multiple = FakeGapSource(ranges=((2, 3), (5, 6)))
    multiple_capability, multiple_gap = make_gap(multiple)
    with pytest.raises(GapFillError) as ambiguous:
        GapFillAdapter(multiple, multiple_capability).open_gap(multiple_gap)
    assert ambiguous.value.code == "INVALID_GAP_MANIFEST"


def test_partial_wal_append_failure_never_marks_gap_filled(tmp_path: Path) -> None:
    source = FakeGapSource((make_fill_record(2), make_fill_record(3)))
    capability, gap = make_gap(source)
    adapter = GapFillAdapter(source, capability)
    manifest = adapter.open_gap(gap)
    wal = seed_wal(tmp_path / "partial-fill.wal", max_records=2)

    result = adapter.fill(manifest, wal)

    assert result.continuity == "UNKNOWN"
    assert result.manifest.state == "FAILED"
    assert result.manifest.filled_count == 1
    assert result.appended_sequences == (2,)
    assert result.error_code == "WAL_APPEND_FAILED"
    assert [record.native_sequence for record in wal.read_all()] == [1, 2]


def test_fill_requires_issued_provider_capability_and_matching_gap(tmp_path: Path) -> None:
    source = FakeGapSource((make_fill_record(2), make_fill_record(3)))
    capability, gap = make_gap(source)
    forged = TrustedProviderCapabilityV1(provider_id=PROVIDER)
    forged_adapter = GapFillAdapter(source, forged)
    with pytest.raises(GapFillError) as caught:
        forged_adapter.open_gap(gap)
    assert caught.value.code == "UNTRUSTED_PROVIDER"
    assert str(caught.value) == caught.value.code
    assert caught.value.args == (caught.value.code,)

    other_source = FakeGapSource((make_fill_record(2), make_fill_record(3)))
    other_source.provider_id = "synthetic-other-provider"
    other_capability = issue_test_capability(other_source, other_source.provider_id)
    other_adapter = GapFillAdapter(other_source, other_capability)
    with pytest.raises(GapFillError) as mismatch:
        other_adapter.open_gap(gap)
    assert mismatch.value.code == "PROVIDER_MISMATCH"
    assert str(mismatch.value) == mismatch.value.code
    assert mismatch.value.args == (mismatch.value.code,)

    unissued_gap = GapManifestV1(
        provider_id=PROVIDER,
        session_id=SESSION,
        ranges=((2, 4),),
    )
    with pytest.raises(GapFillError) as unissued:
        GapFillAdapter(source, capability).open_gap(unissued_gap)
    assert unissued.value.code == "INVALID_GAP_MANIFEST"

    wal = seed_wal(tmp_path / "provider-mismatch.wal")
    assert capability.provider_id == PROVIDER
    assert len(wal.read_all()) == 1

    forged_manifest = GapFillManifestV1(
        source_gap_sha256="0" * 64,
        provider_id=PROVIDER,
        session_id=SESSION,
        start_sequence=2,
        end_sequence=4,
        state="OPEN",
    )
    with pytest.raises(GapFillError) as forged:
        GapFillAdapter(source, capability).fill(forged_manifest, wal)
    assert forged.value.code == "INVALID_GAP_MANIFEST"


def test_capability_cannot_be_reused_with_another_port_for_same_provider(
    tmp_path: Path,
) -> None:
    source_a = FakeGapSource((make_fill_record(2), make_fill_record(3)))
    capability_a, gap_from_a = make_gap(source_a)
    source_b = FakeGapSource((make_fill_record(2), make_fill_record(3)))
    assert source_a is not source_b
    assert source_a.provider_id == source_b.provider_id == PROVIDER
    wal = seed_wal(tmp_path / "same-provider-wrong-port.wal")
    before = wal.read_all()
    adapter_bound_to_other_source = GapFillAdapter(source_b, capability_a)

    with pytest.raises(GapFillError) as caught:
        adapter_bound_to_other_source.open_gap(gap_from_a)

    assert caught.value.code == "UNTRUSTED_PROVIDER"
    assert str(caught.value) == caught.value.code
    assert caught.value.args == (caught.value.code,)
    assert source_b.fetch_calls == []
    assert wal.read_all() == before


def test_fill_response_provider_must_match_capability(tmp_path: Path) -> None:
    source = FakeGapSource(
        (make_fill_record(2, provider="synthetic-provider-b"),
         make_fill_record(3, provider="synthetic-provider-b")),
        batch_provider_id=PROVIDER,
    )
    source.provider_id = "synthetic-provider-b"
    capability, gap = make_gap(source)
    adapter = GapFillAdapter(source, capability)
    manifest = adapter.open_gap(gap)
    wal = seed_wal(tmp_path / "response-provider-mismatch.wal", provider=source.provider_id)

    result = adapter.fill(manifest, wal)

    assert result.continuity == "UNKNOWN"
    assert result.error_code == "PROVIDER_MISMATCH"
    assert result.appended_sequences == ()
    assert [record.native_sequence for record in wal.read_all()] == [1]


def test_replaying_same_gap_is_idempotent_by_wal_identity(tmp_path: Path) -> None:
    source = FakeGapSource((make_fill_record(2), make_fill_record(3)))
    capability, gap = make_gap(source)
    adapter = GapFillAdapter(source, capability)
    wal = seed_wal(tmp_path / "duplicate-gap.wal")

    first = adapter.fill(adapter.open_gap(gap), wal)
    second = adapter.fill(adapter.open_gap(gap), wal)

    assert first.continuity == second.continuity == "CONTINUOUS"
    assert [record.native_sequence for record in wal.read_all()] == [1, 2, 3]
    assert len(wal.read_all()) == 3


@pytest.mark.parametrize("sequences", [(2, 2), (3, 2), (2, 5)])
def test_fill_preflights_provider_batch_before_any_append(
    tmp_path: Path, sequences: tuple[int, int]
) -> None:
    source = FakeGapSource(tuple(make_fill_record(seq) for seq in sequences))
    capability, gap = make_gap(source)
    adapter = GapFillAdapter(source, capability)
    manifest = adapter.open_gap(gap)
    wal = seed_wal(tmp_path / f"bad-batch-{sequences[0]}-{sequences[1]}.wal")
    before = wal.read_all()

    result = adapter.fill(manifest, wal)

    assert result.continuity == "UNKNOWN"
    assert result.manifest.state == "OPEN"
    assert result.appended_sequences == ()
    assert result.error_code == "GAP_COVERAGE_INCOMPLETE"
    assert wal.read_all() == before


def _book_key(instrument_id: str = INSTRUMENT_ID) -> BookKeyV1:
    return BookKeyV1(
        provider=PROVIDER,
        dataset=DATASET,
        venue=VENUE,
        instrument_id=instrument_id,
    )


def test_book_cache_capacity_evicts_oldest_bounded_state() -> None:
    cache = BookCache(max_books=1)
    levels = {"levels": [{"side": "bid", "price": "99", "size": "1", "level": 0}]}
    first = normalized_event(
        "book_snapshot", levels, sequence=1, channel="book",
        instrument_id="synthetic-instrument-a",
    )
    second = normalized_event(
        "book_snapshot", levels, sequence=1, channel="book",
        instrument_id="synthetic-instrument-b",
    )

    assert cache.apply(first).coherent
    assert cache.apply(second).coherent
    assert not cache.snapshot(
        _book_key("synthetic-instrument-a"), now_ns=NOW_NS + 10_000
    ).coherent
    assert cache.snapshot(
        _book_key("synthetic-instrument-b"), now_ns=NOW_NS + 10_000
    ).coherent
    assert len(cache.evictions) == 1
    assert cache.evictions[0].cache_name == "book"
    assert cache.evictions[0].reason == "CAPACITY"


def test_book_delta_without_base_and_sequence_gap_fail_closed() -> None:
    cache = BookCache(depth=2)
    delta = normalized_event(
        "book_delta",
        {"action": "add", "side": "bid", "price": "99", "size": "2", "level": 0},
        sequence=2,
        channel="book",
    )

    missing = cache.apply(delta)

    assert missing.status == "MISSING_BASE"
    assert not missing.coherent
    assert not cache.snapshot(_book_key(), now_ns=NOW_NS + 10_000).coherent

    base = normalized_event(
        "book_snapshot",
        {
            "levels": [
                {"side": "bid", "price": "99", "size": "2", "level": 0},
                {"side": "ask", "price": "101", "size": "3", "level": 0},
            ]
        },
        sequence=10,
        channel="book",
    )
    assert cache.apply(base).status == "APPLIED"
    gap = normalized_event(
        "book_delta",
        {"action": "update", "side": "bid", "price": "99", "size": "4", "level": 0},
        sequence=12,
        channel="book",
    )

    rejected = cache.apply(gap)

    assert rejected.status == "SEQUENCE_GAP"
    assert not rejected.coherent
    snapshot = cache.snapshot(_book_key(), now_ns=NOW_NS + 10_000)
    assert snapshot.reason == "MISSING_BASE"
    assert snapshot.snapshot is None


def test_book_depth_trimming_snapshot_atomicity_and_ttl_boundary() -> None:
    cache = BookCache(depth=1, ttl_ns=50)
    base_time = NOW_NS + 10
    base = normalized_event(
        "book_snapshot",
        {
            "levels": [
                {"side": "bid", "price": "99", "size": "2", "level": 0},
                {"side": "bid", "price": "100", "size": "1", "level": 1},
                {"side": "ask", "price": "101", "size": "3", "level": 0},
                {"side": "ask", "price": "102", "size": "2", "level": 1},
            ]
        },
        sequence=1,
        channel="book",
    )
    assert cache.apply(base).coherent

    at_boundary = cache.snapshot(_book_key(), now_ns=base_time + 50)

    assert at_boundary.reason == "HEALTHY"
    assert at_boundary.coherent
    assert at_boundary.snapshot is not None
    assert [(level.side, level.price.value) for level in at_boundary.snapshot.levels] == [
        ("bid", "100"),
        ("ask", "101"),
    ]
    after_boundary = cache.snapshot(_book_key(), now_ns=base_time + 51)
    assert after_boundary.reason == "STALE"
    assert not after_boundary.coherent
    assert any(item.reason == "TTL" for item in cache.evictions)


def test_book_batch_retry_is_idempotent_only_within_window() -> None:
    cache = BookCache(batch_window_ns=100)
    first = cache.accept_batch_window(topic="synthetic-book", start_ns=1000, end_ns=1100)
    retry = cache.accept_batch_window(topic="synthetic-book", start_ns=1000, end_ns=1100)
    later = cache.accept_batch_window(topic="synthetic-book", start_ns=1201, end_ns=1300)
    retried_after_expiry = cache.accept_batch_window(
        topic="synthetic-book", start_ns=1000, end_ns=1100
    )

    assert first.accepted
    assert not retry.accepted
    assert later.accepted
    assert retried_after_expiry.accepted


def test_reference_versions_and_corporate_actions_use_effective_time_without_mutation() -> None:
    cache = ReferenceCache(ttl_ns=10_000)
    reference = normalized_event(
        "reference",
        {"attributes": {"sector": "synthetic-technology", "currency": "USD"}},
        sequence=1,
        channel="reference",
    )
    action = normalized_event(
        "corporate_action",
        {
            "action": "synthetic-split",
            "effective_time_ns": NOW_NS + 500,
            "details": {"ratio": "2:1"},
        },
        sequence=2,
        channel="corporate_action",
    )
    original_payload = action.payload.model_dump(mode="python")

    assert cache.apply(reference).reason == "APPLIED"
    assert cache.apply(action).reason == "APPLIED"
    before_effective = cache.get(INSTRUMENT_ID, as_of_ns=NOW_NS + 499)
    at_effective = cache.get(INSTRUMENT_ID, as_of_ns=NOW_NS + 500)

    assert before_effective.attributes == (("currency", "USD"), ("sector", "synthetic-technology"))
    assert before_effective.corporate_actions == ()
    assert len(at_effective.corporate_actions) == 1
    assert at_effective.corporate_actions[0].effective_time_ns == NOW_NS + 500
    assert action.payload.model_dump(mode="python") == original_payload


def test_reference_cache_reports_duplicate_and_preserves_time_order() -> None:
    cache = ReferenceCache()
    first = normalized_event(
        "reference", {"attributes": {"status": "active"}}, sequence=10, channel="reference"
    )
    later = normalized_event(
        "reference", {"attributes": {"status": "halted"}}, sequence=12, channel="reference"
    )
    earlier = normalized_event(
        "reference", {"attributes": {"status": "pending"}}, sequence=11, channel="reference"
    )

    assert cache.apply(first).reason == "APPLIED"
    assert cache.apply(first).reason == "DUPLICATE"
    assert cache.apply(later).reason == "APPLIED"
    assert cache.apply(earlier).reason == "OUT_OF_ORDER"
    assert cache.get(INSTRUMENT_ID, as_of_ns=NOW_NS + 110).attributes == (
        ("status", "active"),
    )


def test_control_envelope_accepts_typed_status_and_news_and_rejects_oversize() -> None:
    status = normalized_event(
        "status", {"status": "halted", "reason": "synthetic test halt"},
        sequence=1, channel="status",
    )
    news = normalized_event(
        "news", {"headline": "synthetic bulletin", "publisher": "test-only"},
        sequence=2, channel="news",
    )
    oversized = normalized_event(
        "news", {"headline": "x" * 66_000, "publisher": "test-only"},
        sequence=3, channel="news",
    )

    status_receipt = validate_control_envelope(status)
    news_receipt = validate_control_envelope(news)
    assert status_receipt.accepted and status_receipt.event_type == "status"
    assert news_receipt.accepted and news_receipt.event_type == "news"
    assert 0 < status_receipt.size_bytes <= 65_536
    assert 0 < news_receipt.size_bytes <= 65_536
    with pytest.raises(MarketCacheError) as caught:
        validate_control_envelope(oversized)
    assert caught.value.code == "ENVELOPE_TOO_LARGE"
    assert str(caught.value) == caught.value.code
    assert caught.value.args == (caught.value.code,)

    unsupported = normalized_event(
        "trade",
        {"price": "10.5", "size": "1", "side": "buy"},
        sequence=4,
        channel="trades",
    )
    with pytest.raises(MarketCacheError) as invalid:
        validate_control_envelope(unsupported)
    assert invalid.value.code == "INVALID_ENVELOPE"
    assert str(invalid.value) == invalid.value.code


def test_backpressure_hysteresis_and_critical_drop_preservation() -> None:
    controller = BackpressureController(max_quality_drops=1)
    assert not controller.observe_lag(1_000_000_000).active
    assert controller.observe_lag(1_000_000_001).active
    assert controller.observe_lag(250_000_000).active
    assert not controller.observe_lag(249_999_999).active
    dropped = controller.account_drop()
    assert dropped.quality_drop_count == 1
    assert controller.observe_lag(1_500_000_000).active

    with pytest.raises(MarketCacheError) as critical:
        controller.account_drop(critical=True)
    assert critical.value.code == "CRITICAL_STATE_PRESERVED"
    assert controller.observe_lag(0).quality_drop_count == 1

    with pytest.raises(MarketCacheError) as bounded:
        controller.account_drop()
    assert bounded.value.code == "CAPACITY_EXCEEDED"
    assert controller.observe_lag(0).quality_drop_count == 1


class FakeMetrics:
    def __init__(self) -> None:
        self.samples: list[tuple[str, Decimal, dict[str, str]]] = []

    def record_catalog_metric(
        self, name: str, value: Decimal, labels: dict[str, str]
    ) -> bool:
        self.samples.append((name, value, dict(labels)))
        return True


def test_lag_reporting_uses_existing_catalog_names_and_exact_seconds() -> None:
    metrics = FakeMetrics()
    labels = {
        "service": "leviathan-market-data",
        "component": "synthetic-md006",
        "env": "test",
        "region": "local",
        "instance": "acceptance",
    }

    assert report_pipeline_lag(metrics, labels, 1_500_000_000)
    assert report_stream_freshness_lag(metrics, labels, 250_000_000)
    assert metrics.samples == [
        (OBS004_PIPELINE_LAG, Decimal("1.5"), labels),
        (OBS004_STREAM_FRESHNESS_LAG, Decimal("0.25"), labels),
    ]
