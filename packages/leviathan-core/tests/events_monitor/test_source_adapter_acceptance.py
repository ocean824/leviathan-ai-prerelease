from __future__ import annotations

import copy
import json
import pickle
import socket
import urllib.request
from datetime import UTC, date, datetime
from decimal import Decimal
from pathlib import Path

import pytest

from leviathan_core.events_monitor.models import ExchangeSessionV1
from leviathan_core.events_monitor.source_adapter import (
    US_IANA_RULES_VERSION,
    EventSourceEnvelopeV1,
    EventSourceManifestV1,
    EventSourcePortV1,
    MarketEvidenceEnvelopeV1,
    OverlaySourceEnvelopeV1,
    SourceAdapterError,
    TickerAliasV1,
)

FIXTURE = Path(__file__).parent / "fixtures" / "source" / "recorded_events.json"
DAY = date(2026, 9, 18)


def _ns(value: str | datetime) -> int:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00")) if isinstance(value, str) else value
    if dt.tzinfo is None:
        raise ValueError("fixture timestamps must be timezone-aware")
    delta = dt.astimezone(UTC) - datetime(1970, 1, 1, tzinfo=UTC)
    return ((delta.days * 86_400 + delta.seconds) * 1_000_000 + delta.microseconds) * 1000


def _fixture_records() -> list[dict[str, object]]:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert data["layout"] == "recorded-event-source-v1"
    rows = data["events"]
    for row in rows:
        for key in ("published", "received", "available"):
            row[f"{key}_ns"] = _ns(row.pop(key))
        row["event_date"] = date.fromisoformat(row["event_date"])
        row["related_tickers"] = tuple(row["related_tickers"])
    return rows


def _event(**updates: object) -> EventSourceEnvelopeV1:
    raw = _fixture_records()[0]
    raw.update(updates)
    return EventSourceEnvelopeV1(
        source_id=raw["source_id"],
        schema_version=raw["schema_version"],
        native_id=raw["native_id"],
        issuer_id=raw["issuer_id"],
        ticker=raw["ticker"],
        event_type=raw["event_type"],
        vendor_revision=raw["vendor_revision"],
        vendor_state=raw["vendor_state"],
        precision=raw["precision"],
        session=raw["session"],
        exchange_tz=raw["exchange_tz"],
        event_date=raw["event_date"],
        local_start=raw["local_start"],
        local_end=raw["local_end"],
        local_start_fold=raw.get("local_start_fold"),
        local_end_fold=raw.get("local_end_fold"),
        published_ns=raw["published_ns"],
        received_ns=raw["received_ns"],
        available_ns=raw["available_ns"],
        fiscal_year=raw.get("fiscal_year"),
        fiscal_quarter=raw.get("fiscal_quarter"),
        related_tickers=raw["related_tickers"],
        correction_of_revision=raw.get("correction_of_revision"),
        feed_state=raw.get("feed_state", "SYNTHETIC"),
    )


def _events() -> tuple[EventSourceEnvelopeV1, ...]:
    result = []
    for raw in _fixture_records():
        result.append(
            EventSourceEnvelopeV1(
                source_id=raw["source_id"],
                schema_version=raw["schema_version"],
                native_id=raw["native_id"],
                issuer_id=raw["issuer_id"],
                ticker=raw["ticker"],
                event_type=raw["event_type"],
                vendor_revision=raw["vendor_revision"],
                vendor_state=raw["vendor_state"],
                precision=raw["precision"],
                session=raw["session"],
                exchange_tz=raw["exchange_tz"],
                event_date=raw["event_date"],
                local_start=raw["local_start"],
                local_end=raw["local_end"],
                local_start_fold=raw.get("local_start_fold"),
                local_end_fold=raw.get("local_end_fold"),
                published_ns=raw["published_ns"],
                received_ns=raw["received_ns"],
                available_ns=raw["available_ns"],
                fiscal_year=raw.get("fiscal_year"),
                fiscal_quarter=raw.get("fiscal_quarter"),
                related_tickers=raw["related_tickers"],
                correction_of_revision=raw.get("correction_of_revision"),
                feed_state=raw.get("feed_state", "SYNTHETIC"),
            )
        )
    return tuple(result)


def _port(*, source_id: str = "provider-alpha", aliases=(), tzdata=None) -> EventSourcePortV1:
    open_ns = _ns("2026-09-18T13:30:00Z")
    close_ns = _ns("2026-09-18T20:00:00Z")
    manifest = EventSourceManifestV1(
        source_id=source_id,
        schema_version="schema-1",
        license_reference="fixture-license-1",
        state_map=(
            ("NEW", "scheduled"),
            ("CHANGE", "revised"),
            ("DELAY", "delayed"),
            ("CANCEL", "canceled"),
        ),
        market_source_ids=("market-recorded",),
        overlay_source_ids=("overlay-recorded",),
    )
    return EventSourcePortV1(
        manifest=manifest,
        sessions=(ExchangeSessionV1(DAY, open_ns, close_ns),),
        tzdata=tzdata or ("America/Chicago", "America/New_York"),
        aliases=tuple(aliases),
    )


def test_recorded_provider_neutral_event_mapping_and_revision_correction():
    rows = _events()
    cut = rows[0].available_ns
    before = _port().adapt(events=rows, asof_ns=cut)
    assert len(before.revisions) == 1
    assert before.revisions[0].state == "scheduled"
    assert before.revisions[0].event_id.startswith("evt1:")
    assert before.revisions[0].event_start_ns == _ns("2026-09-18T13:30:00Z")
    assert before.revisions[0].precision == "exact"
    assert before.activation_gates
    assert all(gate.endswith("_PENDING") for gate in before.activation_gates)
    assert len(before.result_version) == 64

    after = _port().adapt(events=rows, asof_ns=rows[1].available_ns)
    assert [row.vendor_revision for row in after.revisions] == [1, 2]
    assert len(after.latest_events) == 1
    assert after.latest_events[0].vendor_revision == 2
    assert len(after.visible_input_digest) == 64
    assert after.revisions[1].state == "revised"
    assert after.revisions[1].correction_of_revision == 1
    assert after.result_version != before.result_version

    other_provider = _port(source_id="provider-beta")
    beta_rows = tuple(_event(source_id="provider-beta", native_id=f"beta-{i}") for i in (1,))
    beta = other_provider.adapt(events=beta_rows, asof_ns=cut)
    assert beta.revisions[0].source == "provider-beta"
    assert beta.revisions[0].event_id == before.revisions[0].event_id


def test_future_available_revision_does_not_change_earlier_result():
    rows = _events()
    cut = rows[0].available_ns
    visible = _port().adapt(events=rows[:1], asof_ns=cut)
    with_future = _port().adapt(events=rows, asof_ns=cut)
    assert with_future == visible
    assert with_future.result_version == visible.result_version


def test_availability_boundary_is_inclusive_and_boolean_timestamp_is_rejected():
    row = _events()[0]
    before = _port().adapt(events=(row,), asof_ns=row.available_ns - 1)
    at_boundary = _port().adapt(events=(row,), asof_ns=row.available_ns)
    assert before.revisions == ()
    assert len(at_boundary.revisions) == 1
    with pytest.raises(SourceAdapterError):
        _port().adapt(events=(row,), asof_ns=True)
    with pytest.raises(SourceAdapterError):
        _event(published_ns=True)


def test_missing_stable_id_and_unknown_state_are_quarantined_without_echo():
    missing = _event(native_id=None)
    unknown = _event(native_id="secret-looking-vendor-row", vendor_state="RAW-STATE-DO-NOT-ECHO")
    result = _port().adapt(events=(missing, unknown), asof_ns=missing.available_ns)
    assert result.revisions == ()
    assert {row.reason for row in result.quarantined} == {
        "NATIVE_ID_MISSING",
        "UNKNOWN_VENDOR_STATE",
    }
    rendered = repr(result.quarantined)
    assert "RAW-STATE-DO-NOT-ECHO" not in rendered


def test_duplicate_source_revision_is_idempotent_and_conflicting_revision_quarantines():
    row = _events()[0]
    identical = _port().adapt(events=(row, row), asof_ns=row.available_ns)
    assert len(identical.revisions) == 1
    assert identical.quarantined == ()
    conflicting = _event(
        local_start="2026-09-18T08:45:00-05:00", local_end="2026-09-18T08:45:00-05:00"
    )
    result = _port().adapt(events=(row, conflicting), asof_ns=row.available_ns)
    assert result.revisions == ()
    assert any(item.reason == "EVENT_REVISION_CONFLICT" for item in result.quarantined)


def test_redated_earnings_with_new_native_id_remain_one_canonical_event():
    base = _events()[0]
    moved = _event(
        native_id="earnings-42-redated",
        vendor_revision=2,
        vendor_state="CHANGE",
        correction_of_revision=1,
        event_date=date(2026, 9, 21),
        local_start="2026-09-21T08:30:00-05:00",
        local_end="2026-09-21T08:30:00-05:00",
        published_ns=base.published_ns + 60_000_000_000,
        received_ns=base.received_ns + 60_000_000_000,
        available_ns=base.available_ns + 60_000_000_000,
    )
    batch = _port().adapt(events=(base, moved), asof_ns=moved.available_ns)
    assert len({row.event_id for row in batch.revisions}) == 1
    assert {row.native_id for row in batch.revisions} == {base.native_id, moved.native_id}


def test_linked_same_time_cross_native_correction_materializes_topologically():
    base = _event(native_id="earnings-42", vendor_revision=1, vendor_state="NEW")
    correction = _event(
        native_id="aaa-new-id",
        vendor_revision=2,
        vendor_state="CHANGE",
        correction_of_revision=1,
        published_ns=base.published_ns,
        received_ns=base.received_ns,
        available_ns=base.available_ns,
    )
    batch = _port().adapt(events=(correction, base), asof_ns=base.available_ns)
    assert [row.native_id for row in batch.revisions] == ["earnings-42", "aaa-new-id"]
    assert [row.vendor_revision for row in batch.revisions] == [1, 2]
    assert len(batch.latest_events) == 1
    assert batch.latest_events[0].native_id == "aaa-new-id"
    assert batch.latest_events[0].vendor_revision == 2


@pytest.mark.parametrize(
    ("native_ids", "reverse"),
    [
        (("aaa-new-id", "zzz-old-id"), False),
        (("aaa-new-id", "zzz-old-id"), True),
        (("zzz-new-id", "aaa-old-id"), False),
        (("zzz-new-id", "aaa-old-id"), True),
    ],
)
def test_unlinked_same_time_conflicting_content_is_ambiguous_independent_of_ids_and_order(
    native_ids, reverse
):
    first = _event(
        native_id=native_ids[0],
        vendor_revision=1,
        local_start="2026-09-18T08:30:00-05:00",
        local_end="2026-09-18T08:30:00-05:00",
    )
    second = _event(
        native_id=native_ids[1],
        vendor_revision=1,
        local_start="2026-09-18T09:00:00-05:00",
        local_end="2026-09-18T09:00:00-05:00",
    )
    rows = (second, first) if reverse else (first, second)
    batch = _port().adapt(events=rows, asof_ns=first.available_ns)
    assert batch.revisions == ()
    assert batch.latest_events == ()
    assert any(item.reason == "REVISION_AMBIGUOUS" for item in batch.quarantined)


def test_unlinked_same_time_identical_content_deduplicates_across_native_ids():
    first = _event(native_id="earnings-42", vendor_revision=1)
    second = _event(native_id="aaa-new-id", vendor_revision=1)
    batch = _port().adapt(events=(second, first), asof_ns=first.available_ns)
    assert len(batch.revisions) == 1
    assert len(batch.latest_events) == 1
    assert batch.latest_events[0].event_id == batch.revisions[0].event_id
    assert not any(item.reason == "REVISION_AMBIGUOUS" for item in batch.quarantined)


def test_correction_link_must_point_to_a_strictly_lower_revision():
    with pytest.raises(SourceAdapterError) as exc_info:
        _event(vendor_revision=2, correction_of_revision=2)
    assert exc_info.value.code == "OUT_OF_RANGE"


def test_correction_link_reconciliation_is_order_independent():
    base, correction = _events()
    forward = _port().adapt(events=(base, correction), asof_ns=correction.available_ns)
    reverse = _port().adapt(events=(correction, base), asof_ns=correction.available_ns)
    assert reverse == forward
    assert reverse.result_version == forward.result_version


def test_orphan_correction_does_not_remove_its_visible_base():
    base = _events()[0]
    orphan = _event(
        vendor_revision=3,
        vendor_state="CHANGE",
        correction_of_revision=2,
        published_ns=base.published_ns + 60_000_000_000,
        received_ns=base.received_ns + 60_000_000_000,
        available_ns=base.available_ns + 60_000_000_000,
    )
    batch = _port().adapt(events=(base, orphan), asof_ns=orphan.available_ns)
    assert any(row.vendor_revision == 1 for row in batch.revisions)
    assert not any(row.vendor_revision == 3 for row in batch.revisions)
    assert any(item.reason == "CORRECTION_TARGET_MISSING" for item in batch.quarantined)


def test_alias_applies_effective_ticker_and_merger_issuer_lineage():
    alias = TickerAliasV1(
        issuer_id="issuer-old",
        source_ticker="OLD",
        canonical_ticker="NEW",
        mapping_version="ticker-map-v3",
        valid_from_ns=0,
        canonical_issuer_id="issuer-successor",
    )
    result = _port(aliases=(alias,)).adapt(
        events=(_events()[0],), asof_ns=_events()[0].available_ns
    )
    assert result.revisions[0].issuer_id == "issuer-successor"
    assert result.revisions[0].ticker == "NEW"
    assert result.revisions[0].identity_mapping_version == "ticker-map-v3"
    assert "OLD" in result.revisions[0].related_tickers


def test_alias_is_applied_consistently_at_the_shared_asof_clock():
    base = _events()[0]
    alias_start = _ns("2026-09-18T13:30:00Z")
    alias = TickerAliasV1(
        issuer_id="issuer-old",
        source_ticker="OLD",
        canonical_ticker="NEW",
        mapping_version="pit-map",
        valid_from_ns=alias_start,
    )
    before_market = MarketEvidenceEnvelopeV1(
        kind="spot",
        ticker="OLD",
        observed_ns=base.available_ns,
        published_ns=base.published_ns,
        received_ns=base.received_ns,
        available_ns=base.available_ns,
        value="10",
        source_id="market-recorded",
        native_id="pit-before",
    )
    after_market = MarketEvidenceEnvelopeV1(
        kind="spot",
        ticker="OLD",
        observed_ns=base.available_ns,
        published_ns=base.published_ns,
        received_ns=base.received_ns,
        available_ns=base.available_ns,
        value="11",
        source_id="market-recorded",
        native_id="pit-after",
    )
    before = _port(aliases=(alias,)).adapt(
        events=(base,),
        market=(before_market, after_market),
        asof_ns=alias_start - 1,
    )
    after = _port(aliases=(alias,)).adapt(
        events=(base,), market=(before_market, after_market), asof_ns=alias_start + 1
    )
    assert before.revisions[0].ticker == "OLD"
    assert {row.ticker for row in before.market_evidence} == {"OLD"}
    assert after.revisions[0].ticker == "NEW"
    assert {row.ticker for row in after.market_evidence} == {"NEW"}


def test_session_precision_derives_calendar_range_instead_of_point_time():
    row = _event(precision="session", session="BMO", local_start=None, local_end=None)
    result = _port().adapt(events=(row,), asof_ns=row.available_ns)
    mapped = result.revisions[0]
    assert mapped.event_start_ns < mapped.event_end_ns
    assert mapped.event_start_ns < _ns("2026-09-18T13:30:00Z")
    assert mapped.event_end_ns == _ns("2026-09-18T13:30:00Z") - 1
    assert mapped.precision == "session"
    amc = _event(
        native_id="after-close",
        precision="session",
        session="AMC",
        local_start=None,
        local_end=None,
    )
    post = _port().adapt(events=(amc,), asof_ns=amc.available_ns).revisions[0]
    assert post.event_start_ns == _ns("2026-09-18T20:00:00Z") + 1
    assert post.event_end_ns > post.event_start_ns


def test_exact_event_at_session_open_is_regular_not_bmo():
    row = _event(
        session="BMO",
        local_start="2026-09-18T08:30:00-05:00",
        local_end="2026-09-18T08:30:00-05:00",
    )
    batch = _port().adapt(events=(row,), asof_ns=row.available_ns)
    assert batch.revisions[0].event_start_ns == _ns("2026-09-18T13:30:00Z")
    assert batch.revisions[0].session == "regular"


@pytest.mark.parametrize(
    ("local_time", "offset", "fold", "valid", "reason"),
    [
        ("2006-10-29T01:30:00", "-04:00", 0, True, None),
        ("2006-10-29T01:30:00", "-05:00", 1, True, None),
        ("2006-04-02T02:30:00", "-05:00", None, False, "DST_GAP_OR_OFFSET_MISMATCH"),
        ("2007-11-04T01:30:00", "-04:00", 0, True, None),
        ("2007-11-04T01:30:00", "-05:00", 1, True, None),
        ("2007-03-11T02:30:00", "-05:00", None, False, "DST_GAP_OR_OFFSET_MISMATCH"),
        ("2026-11-01T01:30:00", "-04:00", 0, True, None),
        ("2026-11-01T01:30:00", "-05:00", 1, True, None),
        ("2026-03-08T02:30:00", "-06:00", None, False, "DST_GAP_OR_OFFSET_MISMATCH"),
    ],
)
def test_versioned_dst_table_handles_historical_folds_and_gaps(
    local_time, offset, fold, valid, reason
):
    text = f"{local_time}{offset}"
    day = date.fromisoformat(local_time[:10])
    row = _event(
        event_date=day,
        exchange_tz="America/New_York",
        local_start=text,
        local_end=text,
        local_start_fold=fold,
        local_end_fold=fold,
    )
    result = _port().adapt(events=(row,), asof_ns=row.available_ns)
    if valid:
        assert len(result.revisions) == 1
        assert result.revisions[0].event_start_ns == _ns(datetime.fromisoformat(text))
        assert result.revisions[0].session == "unknown"
    else:
        assert result.revisions == ()
        assert result.quarantined[0].reason == reason


def test_ambiguous_local_time_requires_explicit_fold():
    row = _event(
        event_date=date(2026, 11, 1),
        exchange_tz="America/New_York",
        local_start="2026-11-01T01:30:00-05:00",
        local_end="2026-11-01T01:30:00-05:00",
    )
    result = _port().adapt(events=(row,), asof_ns=row.available_ns)
    assert result.revisions == ()
    assert result.quarantined[0].reason == "FOLD_REQUIRED"


def test_market_flow_dp_and_finra_mapping_are_typed_and_entitlement_gated():
    base = _ns("2026-09-18T19:59:30Z")
    market = MarketEvidenceEnvelopeV1(
        kind="adjusted_close",
        ticker="NEW",
        observed_ns=base,
        published_ns=base,
        received_ns=base,
        available_ns=base,
        value="123.45",
        source_id="market-recorded",
        native_id="close-1",
        adjustment_version="split-adjusted-v1",
    )
    flow = OverlaySourceEnvelopeV1(
        kind="flow",
        source_contract="FLOW-001",
        source_id="overlay-recorded",
        ticker="NEW",
        observed_ns=base,
        published_ns=base,
        received_ns=base,
        available_ns=base,
        metric_value="2500.00",
        native_id="flow-1",
        metric_name="notional",
    )
    dp = OverlaySourceEnvelopeV1(
        kind="dp",
        source_contract="DP-001",
        source_id="overlay-recorded",
        ticker="NEW",
        observed_ns=base,
        published_ns=base,
        received_ns=base,
        available_ns=base,
        metric_value="5000",
        native_id="dp-1",
        metric_name="cluster_notional",
        price_band_low="121",
        price_band_high="124",
    )
    finra = OverlaySourceEnvelopeV1(
        kind="finra_aggregate",
        source_contract="FINRA-AGG-001",
        source_id="overlay-recorded",
        ticker="NEW",
        observed_ns=base,
        published_ns=base,
        received_ns=base,
        available_ns=base,
        metric_value="100",
        native_id="aggregate-1",
    )
    result = _port().adapt(market=(market,), overlays=(flow, dp, finra), asof_ns=base)
    assert len(result.market_evidence) == 1
    assert result.market_evidence[0].value == Decimal("123.45")
    assert len(result.flow_evidence) == 1
    assert len(result.dp_evidence) == 1
    assert result.dp_evidence[0].price_band_low == 121
    assert any(item.reason == "FINRA_AGGREGATE_NOT_CLUSTER" for item in result.quarantined)


def test_caller_declared_entitlement_does_not_become_entitled():
    row = _event(feed_state="ENTITLED")
    batch = _port().adapt(events=(row,), asof_ns=row.available_ns)
    assert batch.revisions == ()
    assert any(item.reason == "CALLER_DECLARED" for item in batch.quarantined)


def test_future_observed_market_row_is_excluded_at_earlier_asof():
    cut = _ns("2026-09-18T14:00:00Z")
    observed_later = MarketEvidenceEnvelopeV1(
        kind="spot",
        ticker="NEW",
        observed_ns=cut + 1,
        published_ns=cut,
        received_ns=cut,
        available_ns=cut,
        value="99",
        source_id="market-recorded",
        native_id="future-observed",
    )
    batch = _port().adapt(market=(observed_later,), asof_ns=cut)
    assert batch.market_evidence == ()
    assert batch.quarantined


def test_flow_with_incompatible_units_is_rejected():
    cut = _ns("2026-09-18T14:00:00Z")
    flow = OverlaySourceEnvelopeV1(
        kind="flow",
        source_contract="FLOW-001",
        source_id="overlay-recorded",
        ticker="NEW",
        observed_ns=cut,
        published_ns=cut,
        received_ns=cut,
        available_ns=cut,
        metric_value="12",
        native_id="bad-units",
        metric_unit="shares",
    )
    batch = _port().adapt(overlays=(flow,), asof_ns=cut)
    assert batch.flow_evidence == ()
    assert batch.quarantined


def test_result_digest_changes_when_visible_envelope_changes():
    first = _event()
    altered = _event(event_type="dividend")
    batch_a = _port().adapt(events=(first,), asof_ns=first.available_ns)
    batch_b = _port().adapt(events=(altered,), asof_ns=altered.available_ns)
    assert batch_a.visible_event_envelopes != batch_b.visible_event_envelopes
    assert batch_a.visible_input_digest != batch_b.visible_input_digest
    assert batch_a.result_version != batch_b.result_version


def test_injected_tzinfo_objects_and_date_max_fail_with_typed_errors():
    with pytest.raises(SourceAdapterError) as invalid_tz:
        _port(tzdata=(UTC,))
    assert invalid_tz.value.code == "INVALID_TZDATA"
    assert US_IANA_RULES_VERSION == "us-iana-1987-2099-v1"

    unbounded = _event(
        event_date=date.max,
        precision="date",
        session="UNKNOWN",
        local_start=None,
        local_end=None,
    )
    batch = _port().adapt(events=(unbounded,), asof_ns=unbounded.available_ns)
    assert batch.revisions == ()
    assert batch.quarantined[0].reason == "DATE_RANGE_INVALID"


def test_unknown_schema_unmapped_sources_and_stale_chain_quarantine():
    unknown_schema = _event(schema_version="unknown-layout-with-private-marker")
    base = _ns("2026-09-18T19:00:00Z")
    unmapped = MarketEvidenceEnvelopeV1(
        kind="spot",
        ticker="NEW",
        observed_ns=base,
        published_ns=base,
        received_ns=base,
        available_ns=base,
        value="1",
        source_id="unknown-source",
        native_id="source-marker",
    )
    stale_chain = MarketEvidenceEnvelopeV1(
        kind="iv30d",
        ticker="NEW",
        observed_ns=base,
        published_ns=base,
        received_ns=base,
        available_ns=base,
        value="0.3",
        source_id="market-recorded",
        native_id="stale-chain",
        option_expiry_ns=_ns("2026-10-16T20:00:00Z"),
    )
    result = _port().adapt(
        events=(unknown_schema,),
        market=(unmapped, stale_chain),
        asof_ns=base + 120_000_000_000,
    )
    assert result.revisions == ()
    reasons = {row.reason for row in result.quarantined}
    assert "SOURCE_MANIFEST_MISMATCH" in reasons
    assert "MARKET_SOURCE_NOT_MAPPED" in reasons
    assert "STALE_CHAIN" in reasons
    rendered = repr(result.quarantined)
    assert "unknown-layout-with-private-marker" not in rendered


def test_adapter_has_no_network_transport():
    row = _events()[0]

    def forbidden(*args, **kwargs):
        raise AssertionError("network access attempted")

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(socket, "socket", forbidden)
        monkeypatch.setattr(socket, "create_connection", forbidden)
        monkeypatch.setattr(urllib.request, "urlopen", forbidden)
        result = _port().adapt(events=(row,), asof_ns=row.available_ns)
    assert len(result.revisions) == 1


def test_adapter_records_forbid_clone_and_pickle_reconstruction():
    row = _events()[0]
    result = _port().adapt(events=(row,), asof_ns=row.available_ns)
    for value in (row, result):
        for operation in (copy.copy, copy.deepcopy, pickle.dumps):
            with pytest.raises(SourceAdapterError):
                operation(value)
