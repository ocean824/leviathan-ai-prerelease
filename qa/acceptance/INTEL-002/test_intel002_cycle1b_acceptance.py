from __future__ import annotations

import sys
from datetime import date, timedelta
from decimal import Decimal
from pathlib import Path

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
from leviathan_core.dealer_delta import DexFactorAdapter, calculate_dex
from leviathan_core.dealer_delta.kernel import DexKernelError
from leviathan_core.intel import (
    COTFactorAdapter,
    DarkPoolFactorAdapter,
    FactorAbstentionV1,
    FactorProjectionPolicyV1,
    FactorScoreV1,
    MacroFeatureFactorAdapter,
    RegimeFactorAdapter,
    evidence_from_payload,
)
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

WORKTREE = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(WORKTREE / "packages/leviathan-core/tests/intel"))
sys.path.insert(0, str(WORKTREE / "packages/leviathan-core/tests/dealer_delta"))
sys.path.insert(0, str(WORKTREE / "qa/acceptance/INTEL-002"))

from test_dex_kernel import (  # noqa: E402
    _evidence as dex_evidence,
)
from test_dex_kernel import (  # noqa: E402
    _gamma as dex_gamma,
)
from test_dex_kernel import (  # noqa: E402
    _policy as dex_policy,
)
from test_dex_kernel import (  # noqa: E402
    _row as dex_row,
)
from test_intel002_cold_acceptance import EXPIRY, NOW  # noqa: E402
from test_kernel_adapters import _feature  # noqa: E402


def test_macro_feature_adapter_preserves_point_in_time_lineage_and_abstains() -> None:
    # Reviewer finding: macro projection accepts only allowlisted FRED/BEA/EIA inputs.
    result = _feature(source_dataset="FRED/observations")
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
    assert Decimal(score.strength) > 0
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
        Decimal("10"),
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
            dark_prints=(dark,),
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
            min_notional=Decimal(0),
            min_lit_volume=Decimal(0),
        ),
        base + 100,
    )
    assert snapshot.valid
    adapter = DarkPoolFactorAdapter()
    context = adapter.context_for(snapshot, venue="XNYS", decision_as_of_ns=base + 100)
    score = adapter.evaluate(snapshot, "XNYS", context)
    assert isinstance(score, FactorScoreV1)
    assert Decimal(score.strength) > 0
    assert score.direction == "long"
    assert Decimal(score.strength) <= 1
    assert score.source_event_ns == max(
        (p.event_ns for p in snapshot.ranked_prints), default=snapshot.window_end_ns
    )
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
    assert Decimal(score.strength) > 0
    assert score.direction == "long"
    assert Decimal(score.strength) <= 1
    assert score.source_event_ns == max(f.event_ns for f in factors)
    assert score.evidence_refs == context.evidence_refs
    assert score.evidence_refs[0].as_of_ns == max(
        [*(f.available_ns for f in factors), *(f.baseline_available_ns for f in factors)]
    )
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
    # Reviewer finding: missing regime availability no longer falls back to as_of.
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
    assert Decimal(score.strength) > 0
    assert score.direction == ("long" if result.contrarian_tag == "contrarian_long" else "short")
    assert Decimal(score.strength) <= 1
    assert score.evidence_refs == context.evidence_refs
    assert score.source_event_ns == max(
        v.published_ns for v in result.selected_vintages if v.published_ns is not None
    )
    assert score.evidence_refs[0].as_of_ns == max(
        v.available_ns for v in result.selected_vintages if v.available_ns is not None
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
    # Reviewer finding: missing COT availability no longer falls back to as_of.
    assert missing.reason == "MISSING_EVIDENCE"


def test_dex_uses_maximum_input_time_and_rejects_delta_after_cutoff() -> None:
    gamma = dex_gamma(available_ns=NOW + 2)
    later_delta = dex_row("acceptance-later", observed_ns=NOW + 1)
    estimate = calculate_dex(
        dex_evidence(gamma, rows=(later_delta,)), dex_policy(), decision_as_of_ns=NOW + 2
    )
    assert estimate.chain_observed_ns == NOW
    assert estimate.observed_ns == NOW + 1
    adapter = DexFactorAdapter(scale=Decimal("1000"))
    context = adapter.context_for(estimate, gamma, decision_as_of_ns=NOW + 2)
    score = adapter.evaluate(estimate, gamma, EXPIRY, context)
    assert isinstance(score, FactorScoreV1)
    assert score.source_event_ns == NOW + 1
    assert Decimal(score.strength) <= 1
    ref = next(ref for ref in score.evidence_refs if ref.source.startswith("dex001.estimate:"))
    assert ref.source_event_ns == NOW + 1
    assert ref.as_of_ns == NOW + 2

    future_gamma = dex_gamma(available_ns=NOW + 3)
    after_cutoff = dex_row("acceptance-future", observed_ns=NOW + 3)
    with pytest.raises(DexKernelError, match="FUTURE_EVIDENCE"):
        calculate_dex(
            dex_evidence(future_gamma, rows=(after_cutoff,)),
            dex_policy(),
            decision_as_of_ns=NOW + 2,
        )
