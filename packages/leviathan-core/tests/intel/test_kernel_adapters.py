"""Fake-input checks for adapters over existing offline kernels."""

from __future__ import annotations

from datetime import date, timedelta
from decimal import Decimal

import pytest

from leviathan_core.dark_pool import (
    DarkLensPolicyV1,
    DarkLensSnapshotV1,
    DarkPrintV1,
    ExchangeSessionV1,
    LitTradeV1,
    VenueRuleV1,
)
from leviathan_core.dark_pool import (
    calculate as calculate_dark_pool,
)
from leviathan_core.feature_store.asof import FeatureKernelV1
from leviathan_core.feature_store.models import (
    FeatureDefinitionV1,
    FeatureObservationV1,
    FeatureQueryV1,
)
from leviathan_core.indicator_state import IndicatorDefinitionV1, batch
from leviathan_core.indicator_state.adapter import (
    NormalizedBarPortV1,
    issue_normalized_bar_port,
    to_final_bar,
)
from leviathan_core.intel import (
    COTFactorAdapter,
    DarkPoolFactorAdapter,
    FactorAbstentionV1,
    FactorAdapterInputError,
    FactorProjectionPolicyV1,
    FactorScoreV1,
    FeatureFactorAdapter,
    IndicatorFactorAdapter,
    MacroFeatureFactorAdapter,
    MarketBookFactorAdapter,
    RegimeFactorAdapter,
    issue_as_of_context,
)
from leviathan_core.intel.models import evidence_from_feature_result, evidence_from_payload
from leviathan_core.macro_cot import (
    COTMarketMapV1,
    COTPolicyV1,
    COTReportVintageV1,
    COTSnapshotV1,
)
from leviathan_core.macro_cot import (
    calculate as calculate_cot,
)
from leviathan_core.regime import (
    RegimeClockV1,
    RegimeFactorV1,
    RegimeSnapshotV1,
    RegimeSourceIdV1,
    RegimeSourceRecordV1,
    RegimeSourceRegistryV1,
    RegimeWeightPolicyV1,
)
from leviathan_core.regime import (
    score as score_regime,
)
from leviathan_market_data.live.book_cache import BookCache, BookKeyV1
from leviathan_market_data.schema import (
    BookLevel,
    BookSnapshotPayload,
    NormalizedMarketEventV1,
    PriceValue,
)

NOW = 1_800_000_000_000_000_000


def _feature(found: bool = True, *, source_dataset: str = "fixture-bars"):
    definition = FeatureDefinitionV1(
        feature_name="momentum.z",
        feature_version="v1",
        value_kind="decimal",
        published=True,
    )
    observations = (
        FeatureObservationV1(
            feature_name="momentum.z",
            feature_version="v1",
            instrument_id="XYZ",
            source_dataset=source_dataset,
            source_record_key="bar-1",
            event_time_ns=NOW - 10,
            availability_ns=NOW,
            value_decimal=Decimal("0.75"),
        ),
    )
    kernel = FeatureKernelV1((definition,), observations)
    if found:
        return kernel.query(
            FeatureQueryV1(
                feature_name="momentum.z",
                feature_version="v1",
                instrument_id="XYZ",
                asof_ns=NOW,
            )
        )
    return FeatureKernelV1((definition,), ()).query(
        FeatureQueryV1(
            feature_name="momentum.z",
            feature_version="v1",
            instrument_id="XYZ",
            asof_ns=NOW,
        )
    )


def _adapter() -> FeatureFactorAdapter:
    return FeatureFactorAdapter(
        FactorProjectionPolicyV1(
            factor_id="feat001.momentum.v1",
            family="momentum",
            method="feat001.z-score",
            method_version="1",
            scale=Decimal(1),
        )
    )


def _context(result, *, freshness: str = "fresh"):
    ref = evidence_from_feature_result(result)
    return issue_as_of_context(
        decision_as_of_ns=NOW,
        freshness=freshness,  # type: ignore[arg-type]
        evidence_refs=(ref,) if ref is not None else (),
    )


def test_feature_adapter_reuses_feat_issuance_and_maps_signed_strength() -> None:
    result = _feature()
    assert result.observation_hash
    outcome = _adapter().evaluate(result, _context(result))
    assert outcome.direction == "long"
    assert outcome.strength == "0.75"
    assert outcome.evidence_refs[0].issuer_tag == "feat001.feature_result.v1"
    assert outcome.evidence_refs[0].record_digest == result.observation_hash


def test_feature_adapter_abstains_for_stale_and_missing_values() -> None:
    result = _feature()
    stale = _adapter().evaluate(result, _context(result, freshness="stale"))
    assert isinstance(stale, FactorAbstentionV1)
    assert stale.reason == "STALE_EVIDENCE"
    missing = _feature(found=False)
    absent = _adapter().evaluate(missing, _context(missing))
    assert isinstance(absent, FactorAbstentionV1)
    assert absent.reason == "MISSING_EVIDENCE"


def test_feature_adapter_rejects_future_asof_evidence() -> None:
    from leviathan_core.intel import EvidenceRefV1

    result = _feature()
    ref = evidence_from_feature_result(result)
    assert ref is not None
    with pytest.raises(ValueError, match="FUTURE_EVIDENCE"):
        issue_as_of_context(
            decision_as_of_ns=NOW,
            freshness="fresh",
            evidence_refs=(
                EvidenceRefV1(
                    source=ref.source,
                    record_digest=ref.record_digest,
                    as_of_ns=ref.as_of_ns,
                    source_event_ns=NOW + 1,
                    issuer_tag=ref.issuer_tag,
                    seal_reference=ref.seal_reference,
                ),
            ),
        )


def test_market_book_adapter_uses_issued_snapshot_and_abstains_when_stale() -> None:
    event = NormalizedMarketEventV1(
        event_id="00000000-0000-0000-0000-000000000001",
        provider="fixture",
        dataset="fixture-l2",
        venue="XTEST",
        native_symbol="XYZ",
        leviathan_symbol="XYZ",
        instrument_id="XYZ",
        instrument_type="equity",
        channel="book",
        event_type="book_snapshot",
        source_mode="live",
        event_time_ns=NOW,
        source_time_ns=NOW,
        exchange_time_ns=NOW,
        ingest_time_ns=NOW,
        processing_time_ns=NOW,
        received_time_ns=NOW,
        native_sequence=1,
        sequence_synthetic=False,
        native_trade_id=None,
        source_record_key="book-1",
        provider_session_id="session-1",
        source_record_ref="fixture:book:1",
        source_payload_sha256="a" * 64,
        mapping_version="mapping/1",
        identity_policy_version="identity/1",
        quality_flags=(),
        reconstructed=False,
        idempotency_key="idem-book-1",
        payload=BookSnapshotPayload(
            levels=(
                BookLevel(side="bid", price=PriceValue(value="100"), size="30", level=0),
                BookLevel(side="ask", price=PriceValue(value="101"), size="10", level=0),
            )
        ),
    )
    key = BookKeyV1(provider="fixture", dataset="fixture-l2", venue="XTEST", instrument_id="XYZ")
    cache = BookCache(depth=10, ttl_ns=100)
    assert cache.apply(event).status == "APPLIED"
    receipt = cache.snapshot(key, now_ns=NOW)
    context = MarketBookFactorAdapter.context_for(key, receipt, event, decision_as_of_ns=NOW)
    adapter = MarketBookFactorAdapter()
    score = adapter.evaluate(key, receipt, event, context)
    assert score.direction == "long"
    assert score.strength == "0.5"
    assert score.evidence_refs[0].record_digest == event.source_payload_sha256

    stale_context = MarketBookFactorAdapter.context_for(
        key, receipt, event, decision_as_of_ns=NOW, freshness="stale"
    )
    stale = adapter.evaluate(key, receipt, event, stale_context)
    assert isinstance(stale, FactorAbstentionV1)
    assert stale.reason == "STALE_EVIDENCE"


def test_indicator_adapter_projects_issued_final_bar_with_lineage() -> None:
    port = issue_normalized_bar_port(
        NormalizedBarPortV1(
            provider="fixture",
            source_dataset="fixture-bars",
            source_record_key="bar-1",
            source_payload_sha256="b" * 64,
            instrument_id="XYZ",
            venue="XTEST",
            timeframe="1m",
            source_version="source/1",
            adjustment_basis="raw",
            adjustment_version="adjustment/1",
            calendar_version="calendar/1",
            calendar_session_id="session-1",
            auction_session_id="RTH",
            bar_start_ns=NOW - 60_000_000_000,
            bar_end_ns=NOW - 1,
            event_time_ns=NOW - 1,
            availability_ns=NOW,
            watermark_ns=NOW - 1,
            finalized_at_ns=NOW,
            open=Decimal("10"),
            high=Decimal("11"),
            low=Decimal("9"),
            close=Decimal("10"),
            volume=Decimal("100"),
            finalized=True,
            gap=False,
            quality_flags=(),
            revision=0,
            correction_id=None,
        )
    )
    definition = IndicatorDefinitionV1(
        kind="VWAP",
        period=None,
        formula_version="IND-FORMULA-v1",
        parameter_version="p1",
        instrument_id="XYZ",
        venue="XTEST",
        timeframe="1m",
        source_version="source/1",
        adjustment_version="raw:adjustment/1",
        calendar_version="calendar/1",
    )
    finalized = to_final_bar(port, definition, asof_ns=NOW)
    result = batch((finalized,), definition, NOW)[0]
    mapping = FactorProjectionPolicyV1(
        factor_id="ind001.vwap.v1",
        family="indicator",
        method="ind001.finalized-vwap",
        method_version="1",
        scale=Decimal(20),
    )
    adapter = IndicatorFactorAdapter(mapping)
    context = adapter.context_for(
        result,
        instrument="XYZ",
        venue="XTEST",
        available_ns=NOW,
        decision_as_of_ns=NOW,
    )
    score = adapter.evaluate(result, "XYZ", "XTEST", context)
    assert score.direction == "long"
    assert score.evidence_refs[0].record_digest
    stale_context = adapter.context_for(
        result,
        instrument="XYZ",
        venue="XTEST",
        available_ns=NOW,
        decision_as_of_ns=NOW,
        freshness="stale",
    )
    stale = adapter.evaluate(result, "XYZ", "XTEST", stale_context)
    assert isinstance(stale, FactorAbstentionV1)
    assert stale.reason == "STALE_EVIDENCE"


def test_macro_feature_adapter_preserves_point_in_time_lineage_and_abstains() -> None:
    result = _feature(source_dataset="FRED")
    adapter = MacroFeatureFactorAdapter(
        FactorProjectionPolicyV1(
            factor_id="feat001.macro-cpi.v1",
            family="macro",
            method="feat001.cpi-change",
            method_version="1",
            scale=Decimal(1),
        )
    )
    context = adapter.context_for(result, decision_as_of_ns=NOW)
    score = adapter.evaluate(result, context)
    assert isinstance(score, FactorScoreV1)
    assert score.family == "macro"
    assert score.direction == "long"
    assert Decimal(score.strength) <= 1
    assert score.evidence_refs[0].issuer_tag == "feat001.feature_result.v1"
    assert score.evidence_refs[0].record_digest == result.observation_hash
    assert score.evidence_refs[0].as_of_ns == result.asof_ns
    assert score.source_event_ns == result.event_time_ns
    stale = adapter.evaluate(
        result, adapter.context_for(result, decision_as_of_ns=NOW, freshness="stale")
    )
    assert isinstance(stale, FactorAbstentionV1)
    assert stale.reason == "STALE_EVIDENCE"
    missing = _feature(found=False)
    absent = adapter.evaluate(missing, adapter.context_for(missing, decision_as_of_ns=NOW))
    assert isinstance(absent, FactorAbstentionV1)
    assert absent.reason == "MISSING_EVIDENCE"
    with pytest.raises(FactorAdapterInputError):
        adapter.context_for(_feature(source_dataset="fixture-bars"), decision_as_of_ns=NOW)


def test_macro_feature_adapter_requires_macro_projection_family() -> None:
    with pytest.raises(FactorAdapterInputError):
        MacroFeatureFactorAdapter(
            FactorProjectionPolicyV1(
                factor_id="feat001.wrong-family.v1",
                family="indicator",
                method="feat001.invalid",
                method_version="1",
                scale=Decimal(1),
            )
        )


def test_dark_pool_adapter_projects_issued_result_with_source_lineage_and_latest_time() -> None:
    base = 100
    day = date(1970, 1, 1)
    calendar = (ExchangeSessionV1(day, 0, 1_000, "UTC", "cal-v1", "00:00", 0),)
    dark = DarkPrintV1(
        "XYZ",
        "finra",
        "ats-v1",
        "TRF-X",
        "dark-1",
        base + 50,
        base + 60,
        base + 70,
        "UTC",
        "cal-v1",
        Decimal("20"),
        Decimal("100"),
        fx_rate=Decimal(1),
        condition_codes=(),
        is_odd_lot=False,
        entitlement_status="SYNTHETIC",
        source_state="SYNTHETIC",
        side="B",
        reference_mid=Decimal("20"),
        correction_id="0",
        supersedes_id=None,
    )
    later_small_dark = DarkPrintV1(
        "XYZ",
        "finra",
        "ats-v1",
        "TRF-X",
        "dark-2",
        base + 80,
        base + 85,
        base + 86,
        "UTC",
        "cal-v1",
        Decimal("20"),
        Decimal("1"),
        fx_rate=Decimal(1),
        condition_codes=(),
        is_odd_lot=False,
        entitlement_status="SYNTHETIC",
        source_state="SYNTHETIC",
        side="S",
        reference_mid=Decimal("20"),
        correction_id="0",
        supersedes_id=None,
    )
    lit = LitTradeV1(
        "XYZ",
        "lit",
        "lit-v1",
        "XNYS",
        "lit-1",
        base + 40,
        base + 45,
        base + 50,
        "UTC",
        "cal-v1",
        Decimal("20"),
        Decimal("10"),
        is_off_exchange=False,
    )
    snapshot = calculate_dark_pool(
        DarkLensSnapshotV1(
            dark_prints=(dark, later_small_dark),
            lit_trades=(lit,),
            baseline_samples=(),
            aggregate_context=(),
            calendar=calendar,
            venue_registry=(VenueRuleV1("TRF-X", "OFF_EXCHANGE"), VenueRuleV1("XNYS", "LIT")),
        ),
        DarkLensPolicyV1(
            "XYZ",
            base,
            base + 90,
            "cal-v1",
            min_notional=Decimal("1000"),
            min_lit_volume=Decimal(0),
        ),
        base + 100,
    )
    assert snapshot.valid
    adapter = DarkPoolFactorAdapter()
    context = adapter.context_for(snapshot, venue="XNYS", decision_as_of_ns=base + 100)
    score = adapter.evaluate(snapshot, "XNYS", context)
    assert isinstance(score, FactorScoreV1)
    assert score.direction == "long"
    assert Decimal(score.strength) <= 1
    assert tuple(row.event_ns for row in snapshot.ranked_prints) == (base + 50,)
    assert score.source_event_ns == base + 80
    assert snapshot.latest_contributing_event_ns == base + 80
    assert score.evidence_refs[0].source == "dp001.dark-pool"
    assert score.evidence_refs[0].as_of_ns == snapshot.asof_ns
    assert (
        score.evidence_refs[0].record_digest
        == evidence_from_payload(
            source="dp001.dark-pool",
            payload={
                "digest": snapshot.digest,
                "window_id": snapshot.window_id,
                "source_ids": snapshot.source_ids,
                "source_event_ids": snapshot.source_event_ids,
                "aggregate_context_ids": snapshot.aggregate_context_ids,
                "adjustment_versions": snapshot.adjustment_versions,
            },
            source_event_ns=score.source_event_ns,
            as_of_ns=snapshot.asof_ns,
        ).record_digest
    )
    stale = adapter.evaluate(
        snapshot,
        "XNYS",
        adapter.context_for(
            snapshot, venue="XNYS", decision_as_of_ns=base + 100, freshness="stale"
        ),
    )
    assert isinstance(stale, FactorAbstentionV1)
    assert stale.reason == "STALE_EVIDENCE"
    with pytest.raises(ValueError, match="FUTURE_EVIDENCE"):
        adapter.context_for(snapshot, venue="XNYS", decision_as_of_ns=base + 60)

    empty = calculate_dark_pool(
        DarkLensSnapshotV1(
            dark_prints=(),
            lit_trades=(),
            baseline_samples=(),
            aggregate_context=(),
            calendar=calendar,
            venue_registry=(),
        ),
        DarkLensPolicyV1(
            "XYZ", base, base + 90, "cal-v1", min_notional=Decimal(0), min_lit_volume=Decimal(0)
        ),
        base + 100,
    )
    missing = adapter.evaluate(
        empty, "XNYS", adapter.context_for(empty, venue="XNYS", decision_as_of_ns=base + 100)
    )
    assert isinstance(missing, FactorAbstentionV1)
    assert missing.reason == "KERNEL_REJECTED"


def test_regime_adapter_uses_maximum_input_times_and_abstains_when_stale() -> None:
    source_registry = RegimeSourceRegistryV1(
        version="test-v1",
        records=(
            RegimeSourceRecordV1(
                source_id=RegimeSourceIdV1("source:test:v1"),
                trust_class="PIPELINE",
                entitlement="LICENSED",
                allowed_interface_ids=("FLOW-001:fixture",),
            ),
        ),
    )
    factors = tuple(
        RegimeFactorV1(
            kind=kind,
            value=Decimal("0.7"),
            source=RegimeSourceIdV1("source:test:v1"),
            source_version="fixture-v1",
            semantic_digest=f"digest:{kind}",
            event_ns=NOW - 100 + index,
            available_ns=NOW - 50 + index,
            baseline_available_ns=NOW - 40 + index,
            valid=True,
            fresh_until_ns=NOW + 1_000,
            scope="global",
            window_sec=60,
            horizon_sec=60,
            entitlement="LICENSED",
            release_lag="none",
            upstream_interface_id="FLOW-001:fixture" if kind == "flow" else None,
        )
        for index, kind in enumerate(("dealer", "flow", "dp", "macro"))
    )
    clock = RegimeClockV1(
        bar_id="bar:intel-test",
        bar_index=1,
        session_id="session:intel-test",
        symbol="XYZ",
        universe="equity",
        calendar_version="calendar-v1",
        asof_ns=NOW,
        window_sec=60,
        horizon_sec=60,
    )
    kernel_snapshot = RegimeSnapshotV1(
        clock=clock,
        factors=factors,
        record_available_ns=NOW,
        signal_status="FINALIZED",
        truth_status="PASS",
        flow_source="source:test:v1",
        flow_quality="GOOD",
    )
    snapshot = score_regime(kernel_snapshot, RegimeWeightPolicyV1(), (), NOW, source_registry)
    adapter = RegimeFactorAdapter()
    context = adapter.context_for(snapshot, instrument="XYZ", venue="XTEST", decision_as_of_ns=NOW)
    score = adapter.evaluate(snapshot, "XYZ", "XTEST", context)
    assert isinstance(score, FactorScoreV1)
    assert score.direction == "long"
    assert Decimal(score.strength) <= 1
    assert score.source_event_ns == NOW - 97
    assert score.evidence_refs == context.evidence_refs
    assert score.evidence_refs[0].as_of_ns == NOW - 37
    stale_context = adapter.context_for(
        snapshot, instrument="XYZ", venue="XTEST", decision_as_of_ns=NOW, freshness="stale"
    )
    stale = adapter.evaluate(snapshot, "XYZ", "XTEST", stale_context)
    assert isinstance(stale, FactorAbstentionV1)
    assert stale.reason == "STALE_EVIDENCE"
    with pytest.raises(ValueError, match="FUTURE_EVIDENCE"):
        adapter.context_for(snapshot, instrument="XYZ", venue="XTEST", decision_as_of_ns=NOW - 45)

    empty_snapshot = RegimeSnapshotV1(
        clock=clock,
        factors=(),
        record_available_ns=NOW,
        signal_status="UNKNOWN",
        truth_status="UNKNOWN",
        flow_source="source:test:v1",
        flow_quality="UNKNOWN",
    )
    empty = score_regime(empty_snapshot, RegimeWeightPolicyV1(), (), NOW, source_registry)
    missing = adapter.evaluate(
        empty,
        "XYZ",
        "XTEST",
        adapter.context_for(empty, instrument="XYZ", venue="XTEST", decision_as_of_ns=NOW),
    )
    assert isinstance(missing, FactorAbstentionV1)
    assert missing.reason == "MISSING_EVIDENCE"


def test_cot_adapter_preserves_vintage_provenance_max_times_and_abstains() -> None:
    epoch = date(1970, 1, 1)
    first = date(2022, 1, 4)

    def day_ns(value: date) -> int:
        return (value - epoch).days * 86_400_000_000_000

    rows = tuple(
        COTReportVintageV1(
            cftc_market_code="CFTC-CL",
            constituent_id="CL",
            report_date=first + timedelta(weeks=i),
            report_family="Disaggregated Futures",
            source="CFTC",
            revision=0,
            is_preliminary=False,
            published_ns=day_ns(first + timedelta(weeks=i, days=3)),
            received_ns=day_ns(first + timedelta(weeks=i, days=3, minutes=1)),
            available_ns=day_ns(first + timedelta(weeks=i, days=3, minutes=2)),
            mm_long=Decimal(200 if i == 103 else 20),
            mm_short=Decimal(0),
            open_interest=Decimal(100),
        )
        for i in range(104)
    )
    report_day = rows[-1].report_date
    map_value = COTMarketMapV1(
        "WTI", "map-v1", ("CL",), epoch, constituent_codes=(("CL", "CFTC-CL"),)
    )
    result = calculate_cot(
        COTSnapshotV1(map_value, rows),
        COTPolicyV1(min_lookback_samples=104),
        day_ns(report_day + timedelta(days=5)),
    )
    assert result.status == "OK"
    adapter = COTFactorAdapter()
    context = adapter.context_for(result, decision_as_of_ns=NOW)
    score = adapter.evaluate(result, "CL", "XTEST", context)
    assert isinstance(score, FactorScoreV1)
    assert score.direction == ("long" if result.contrarian_tag == "contrarian_long" else "short")
    assert Decimal(score.strength) <= 1
    assert score.evidence_refs == context.evidence_refs
    assert score.source_event_ns == day_ns(first + timedelta(weeks=103, days=3))
    assert score.evidence_refs[0].as_of_ns == day_ns(
        first + timedelta(weeks=103, days=3, minutes=2)
    )
    stale_context = adapter.context_for(result, decision_as_of_ns=NOW, freshness="stale")
    stale = adapter.evaluate(result, "CL", "XTEST", stale_context)
    assert isinstance(stale, FactorAbstentionV1)
    assert stale.reason == "STALE_EVIDENCE"
    with pytest.raises(ValueError, match="FUTURE_EVIDENCE"):
        adapter.context_for(result, decision_as_of_ns=score.evidence_refs[0].as_of_ns - 1)
    unavailable = calculate_cot(
        COTSnapshotV1(map_value, ()),
        COTPolicyV1(min_lookback_samples=104),
        day_ns(report_day + timedelta(days=5)),
    )
    missing = adapter.evaluate(
        unavailable,
        "CL",
        "XTEST",
        adapter.context_for(unavailable, decision_as_of_ns=NOW),
    )
    assert isinstance(missing, FactorAbstentionV1)
    assert missing.reason == "MISSING_EVIDENCE"
