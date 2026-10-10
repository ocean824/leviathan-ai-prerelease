from __future__ import annotations

import os
import sys
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from pathlib import Path

import pytest
from pydantic import ValidationError

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
from leviathan_core.intel import (
    COTFactorAdapter,
    DarkPoolFactorAdapter,
    FactorAbstentionV1,
    FactorProjectionPolicyV1,
    FactorScoreV1,
    MacroFeatureFactorAdapter,
    RegimeFactorAdapter,
    build_trace,
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
sys.path.insert(0, str(WORKTREE / "packages/leviathan-core/tests/dealer_delta"))

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

from leviathan_core.dealer_delta import DexFactorAdapter, calculate_dex  # noqa: E402
from leviathan_core.dealer_delta.kernel import DexKernelError  # noqa: E402


def _assert_score_with_provenance(score: object) -> FactorScoreV1:
    assert isinstance(score, FactorScoreV1)
    strength = Decimal(score.strength)
    assert Decimal(0) < strength <= Decimal(1)
    assert score.evidence_refs
    assert all(ref.source and len(ref.record_digest) == 64 for ref in score.evidence_refs)
    assert score.source_event_ns is not None
    return score


def test_imports_resolve_to_the_requested_worktree_when_configured() -> None:
    expected_worktree = os.environ.get("LEVIATHAN_ACCEPTANCE_WORKTREE")
    if not expected_worktree:
        pytest.skip("set LEVIATHAN_ACCEPTANCE_WORKTREE to verify import origin")

    from leviathan_core.dark_pool import kernel as dark_kernel
    from leviathan_core.dealer_delta import kernel as dex_kernel
    from leviathan_core.intel import kernel_adapters
    from leviathan_core.intel import models as intel_models
    from leviathan_core.macro_cot import kernel as cot_kernel
    from leviathan_core.regime import kernel as regime_kernel

    expected_root = Path(expected_worktree).resolve()
    for module in (
        dark_kernel,
        dex_kernel,
        kernel_adapters,
        intel_models,
        cot_kernel,
        regime_kernel,
    ):
        assert Path(module.__file__).resolve().is_relative_to(expected_root), module.__file__


def test_macro_adapter_uses_allowlisted_observation_and_full_time_provenance() -> None:
    definition = FeatureDefinitionV1(
        feature_name="macro.cpi.change",
        feature_version="v1",
        value_kind="decimal",
        published=True,
    )
    observation = FeatureObservationV1(
        feature_name="macro.cpi.change",
        feature_version="v1",
        instrument_id="US",
        source_dataset="FRED/observations",
        source_record_key="cpi-2026-09",
        event_time_ns=NOW - 90,
        availability_ns=NOW - 30,
        value_decimal=Decimal("0.4"),
    )
    result = FeatureKernelV1((definition,), (observation,)).query(
        FeatureQueryV1(
            feature_name="macro.cpi.change",
            feature_version="v1",
            instrument_id="US",
            asof_ns=NOW,
        )
    )
    adapter = MacroFeatureFactorAdapter(
        FactorProjectionPolicyV1(
            factor_id="feat001.macro-cpi.v1",
            family="macro",
            method="feat001.cpi-change",
            method_version="1",
            scale=Decimal(1),
        )
    )
    context = adapter.context_for(result, decision_as_of_ns=NOW, freshness="fresh")
    score = _assert_score_with_provenance(adapter.evaluate(result, context))
    ref = score.evidence_refs[0]
    assert score.source_event_ns == observation.event_time_ns
    assert ref.source_event_ns == observation.event_time_ns
    assert ref.as_of_ns == observation.availability_ns
    assert ref.record_digest == result.observation_hash
    stale = adapter.evaluate(
        result,
        adapter.context_for(result, decision_as_of_ns=NOW, freshness="stale"),
    )
    assert isinstance(stale, FactorAbstentionV1)
    assert stale.reason == "STALE_EVIDENCE"


def test_dark_pool_max_time_includes_subthreshold_contributing_print() -> None:
    base = NOW
    day = datetime.fromtimestamp(base / 1_000_000_000, tz=UTC).date()
    calendar = (ExchangeSessionV1(day, base - 10, base + 300, "UTC", "cal-v1", "00:00", 0),)
    qualifying = DarkPrintV1(
        "XYZ",
        "finra",
        "ats-v1",
        "TRF-X",
        "dark-150",
        base + 150,
        base + 155,
        base + 160,
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
    subthreshold = DarkPrintV1(
        "XYZ",
        "finra",
        "ats-v1",
        "TRF-X",
        "dark-180",
        base + 180,
        base + 185,
        base + 190,
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
        base + 120,
        base + 125,
        base + 130,
        "UTC",
        "cal-v1",
        Decimal("20"),
        Decimal("10"),
        is_off_exchange=False,
    )
    snapshot = calculate_dark_pool(
        DarkLensSnapshotV1(
            dark_prints=(qualifying, subthreshold),
            lit_trades=(lit,),
            baseline_samples=(),
            aggregate_context=(),
            calendar=calendar,
            venue_registry=(VenueRuleV1("TRF-X", "OFF_EXCHANGE"), VenueRuleV1("XNYS", "LIT")),
        ),
        DarkLensPolicyV1(
            "XYZ",
            base,
            base + 200,
            "cal-v1",
            min_notional=Decimal("100"),
            min_lit_volume=Decimal(0),
        ),
        base + 210,
    )
    assert snapshot.valid
    assert tuple(print_.event_ns for print_ in snapshot.ranked_prints) == (base + 150,)
    assert snapshot.latest_contributing_event_ns == base + 180
    adapter = DarkPoolFactorAdapter()
    context = adapter.context_for(snapshot, venue="XNYS", decision_as_of_ns=base + 210)
    score = _assert_score_with_provenance(adapter.evaluate(snapshot, "XNYS", context))
    assert score.source_event_ns == base + 180
    assert score.evidence_refs[0].source_event_ns == base + 180
    assert score.evidence_refs[0].as_of_ns == snapshot.asof_ns


def test_regime_adapter_uses_maximum_event_and_availability_across_factors() -> None:
    registry = RegimeSourceRegistryV1(
        version="acceptance-v1",
        records=(
            RegimeSourceRecordV1(
                source_id=RegimeSourceIdV1("source:acceptance:v1"),
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
            source=RegimeSourceIdV1("source:acceptance:v1"),
            source_version="fixture-v1",
            semantic_digest=f"digest:{kind}",
            event_ns=NOW + index * 10,
            available_ns=NOW + 100 + index * 10,
            baseline_available_ns=NOW + 150 + index * 10,
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
        bar_id="acceptance-bar",
        bar_index=1,
        session_id="acceptance-session",
        symbol="XYZ",
        universe="equity",
        calendar_version="calendar-v1",
        asof_ns=NOW + 250,
        window_sec=60,
        horizon_sec=60,
    )
    source = RegimeSnapshotV1(
        clock=clock,
        factors=factors,
        record_available_ns=NOW + 250,
        signal_status="FINALIZED",
        truth_status="PASS",
        flow_source="source:acceptance:v1",
        flow_quality="GOOD",
    )
    snapshot = score_regime(source, RegimeWeightPolicyV1(), (), NOW + 250, registry)
    adapter = RegimeFactorAdapter()
    context = adapter.context_for(
        snapshot, instrument="XYZ", venue="XTEST", decision_as_of_ns=NOW + 250
    )
    score = _assert_score_with_provenance(adapter.evaluate(snapshot, "XYZ", "XTEST", context))
    assert score.source_event_ns == max(factor.event_ns for factor in factors)
    assert score.evidence_refs == context.evidence_refs
    assert score.evidence_refs[0].as_of_ns == max(
        max(factor.available_ns, factor.baseline_available_ns) for factor in factors
    )
    empty_snapshot = score_regime(
        RegimeSnapshotV1(
            clock=clock,
            factors=(),
            record_available_ns=NOW + 250,
            signal_status="UNKNOWN",
            truth_status="UNKNOWN",
            flow_source="source:acceptance:v1",
            flow_quality="UNKNOWN",
        ),
        RegimeWeightPolicyV1(),
        (),
        NOW + 250,
        registry,
    )
    empty_context = adapter.context_for(
        empty_snapshot, instrument="XYZ", venue="XTEST", decision_as_of_ns=NOW + 250
    )
    missing = adapter.evaluate(empty_snapshot, "XYZ", "XTEST", empty_context)
    assert isinstance(missing, FactorAbstentionV1)
    assert missing.reason == "MISSING_EVIDENCE"


def test_cot_adapter_uses_latest_selected_vintage_times_and_abstains_without_them() -> None:
    epoch = date(1970, 1, 1)
    first = date(2022, 1, 4)

    def day_ns(value: date) -> int:
        return (value - epoch).days * 86_400_000_000_000

    rows = tuple(
        COTReportVintageV1(
            cftc_market_code="CFTC-CL",
            constituent_id="CL",
            report_date=first + timedelta(weeks=index),
            report_family="Disaggregated Futures",
            source="CFTC",
            revision=0,
            is_preliminary=False,
            published_ns=day_ns(first + timedelta(weeks=index, days=3)),
            received_ns=day_ns(first + timedelta(weeks=index, days=3, minutes=1)),
            available_ns=day_ns(first + timedelta(weeks=index, days=3, minutes=2)),
            mm_long=Decimal("200") if index == 103 else Decimal("20"),
            mm_short=Decimal(0),
            open_interest=Decimal(100),
        )
        for index in range(104)
    )
    map_value = COTMarketMapV1(
        "WTI", "map-v1", ("CL",), epoch, constituent_codes=(("CL", "CFTC-CL"),)
    )
    policy = COTPolicyV1(min_lookback_samples=104)
    cutoff = day_ns(rows[-1].report_date + timedelta(days=5))
    result = calculate_cot(COTSnapshotV1(map_value, rows), policy, cutoff)
    adapter = COTFactorAdapter()
    context = adapter.context_for(result, decision_as_of_ns=NOW, freshness="fresh")
    score = _assert_score_with_provenance(adapter.evaluate(result, "CL", "XTEST", context))
    assert score.source_event_ns == max(
        row.published_ns for row in result.selected_vintages if row.published_ns is not None
    )
    assert score.evidence_refs == context.evidence_refs
    assert score.evidence_refs[0].as_of_ns == max(
        row.available_ns for row in result.selected_vintages if row.available_ns is not None
    )
    missing_result = calculate_cot(COTSnapshotV1(map_value, ()), policy, cutoff)
    missing_context = adapter.context_for(missing_result, decision_as_of_ns=NOW)
    missing = adapter.evaluate(missing_result, "CL", "XTEST", missing_context)
    assert isinstance(missing, FactorAbstentionV1)
    assert missing.reason == "MISSING_EVIDENCE"


def test_dex_maximum_time_permutation_digest_refs_trace_and_cutoff() -> None:
    gamma = dex_gamma(available_ns=NOW + 2)
    rows = (
        dex_row("call-a", observed_ns=NOW),
        dex_row("call-b", observed_ns=NOW + 1),
    )
    estimates = tuple(
        calculate_dex(dex_evidence(gamma, rows=ordered), dex_policy(), decision_as_of_ns=NOW + 2)
        for ordered in (rows, tuple(reversed(rows)))
    )
    assert estimates[0].observed_ns == NOW + 1
    assert estimates[0].semantic_digest == estimates[1].semantic_digest
    adapter = DexFactorAdapter(scale=Decimal("1000"))
    outcomes = tuple(
        adapter.evaluate(
            estimate,
            gamma,
            EXPIRY,
            adapter.context_for(estimate, gamma, decision_as_of_ns=NOW + 2),
        )
        for estimate in estimates
    )
    scores = tuple(_assert_score_with_provenance(outcome) for outcome in outcomes)
    assert scores[0].source_event_ns == NOW + 1
    assert scores[0].evidence_refs == scores[1].evidence_refs
    traces = tuple(
        build_trace(
            decision_as_of_ns=NOW + 2,
            evidence_refs=score.evidence_refs,
            normalized_event_refs=(),
            factor_outcomes=(score,),
        )
        for score in scores
    )
    assert traces[0].trace_sha256 == traces[1].trace_sha256

    future_gamma = dex_gamma(available_ns=NOW + 3)
    future = dex_row("after-cutoff", observed_ns=NOW + 3)
    with pytest.raises(DexKernelError) as error:
        calculate_dex(
            dex_evidence(future_gamma, rows=(future,)),
            dex_policy(),
            decision_as_of_ns=NOW + 2,
        )
    assert error.value.code == "FUTURE_EVIDENCE"


@pytest.mark.parametrize(
    ("option_type", "delta"),
    (("PUT", Decimal("0.25")), ("CALL", Decimal("-0.25"))),
)
def test_dex_rejects_delta_sign_outside_option_domain(option_type: str, delta: Decimal) -> None:
    with pytest.raises(ValidationError) as error:
        dex_row("wrong-sign", option_type=option_type, delta=delta)
    assert str(error.value) == "INVALID_FUSION_INPUT"


def test_tier_three_scheduled_event_scoring_is_deferred_to_intel003() -> None:
    ledger = (WORKTREE / "qa/handoffs/INTEL-002/cycle-2.md").read_text(encoding="utf-8")
    assert "tier-3 scheduled-event adapter remains deferred to INTEL-003" in ledger
    assert "ZQ/FOMC factor remains backlog-only" in ledger
