from __future__ import annotations

import hashlib
import json
import os
from datetime import date
from decimal import Decimal
from pathlib import Path

import pytest

from leviathan_core.dealer_delta import (
    DexChainEvidenceV1,
    DexFactorAdapter,
    DexOptionEvidenceV1,
    DexPolicyV1,
    calculate_dex,
)
from leviathan_core.dealer_gamma import (
    ChainSnapshotV1,
    DealerExposureAssumptionV1,
    DeliverableLegV1,
    ExchangeCalendarV1,
    GammaPolicyV1,
    GammaSnapshotV1,
    OptionSeriesEvidenceV1,
    evaluate,
)
from leviathan_core.intel import (
    FactorAbstentionV1,
    FactorAdapterInputError,
    FactorScoreV1,
    GammaFactorAdapter,
    build_trace,
    issue_as_of_context,
)
from leviathan_core.intel.models import EvidenceRefV1

WORKTREE = Path(__file__).resolve().parents[3]
CANONICAL = (
    Path(
        r"C:\Users\XYRASYSTEMS\TRAYCER MASTER TEMPLATE\XYRA-MASTER\projects\XYRASYSTEMS"
        r"\LEVIATHAN AI"
    )
    / "repo"
)
NOW = 1_800_000_000_000_000_000
DAY = 86_400_000_000_000
EXPIRY = date(2026, 10, 9)
D = Decimal
DEFAULT_DELTA = D("0.5")


def _gamma():
    calendar = ExchangeCalendarV1(
        "XNYS", "2026a", EXPIRY, NOW - DAY // 24, NOW + DAY // 24, early_close=False
    )
    series = OptionSeriesEvidenceV1(
        series_id="C100",
        underlier="XYZ",
        contract="XYZ-C100",
        venue="XOPT",
        option_type="CALL",
        strike=D("100"),
        expiry_date=EXPIRY,
        expiry_kind="WEEKLY",
        settlement="PM",
        expiry_cutoff_ns=calendar.session_close_ns,
        multiplier=D("100"),
        currency="USD",
        open_interest=D("100"),
        oi_asof_ns=NOW - DAY,
        spot=D("100"),
        spot_observed_ns=NOW,
        spot_available_ns=NOW,
        bid=D("2"),
        ask=D("2.10"),
        quote_observed_ns=NOW,
        quote_available_ns=NOW,
        implied_vol=D("0.20"),
        iv_observed_ns=NOW,
        iv_available_ns=NOW,
        gamma=D("0.02"),
        gamma_units="PER_UNDERLYING_UNIT",
        greek_observed_ns=NOW,
        greek_available_ns=NOW,
        source_id="fixture-options",
        dataset_id="fixture-chain-v1",
        entitlement_id="test-only",
        entitlement_status="ENTITLED",
        corporate_action_version="none-v1",
        multiplier_basis="PRE_ACTION",
        adjustment_version="adjust-v1",
        deliverable_units=(DeliverableLegV1("UNDERLIER", "XYZ", D("100"), "USD"),),
    )
    chain = ChainSnapshotV1(
        "snapshot-1",
        "LIVE",
        "XYZ",
        "XOPT",
        NOW,
        NOW,
        0,
        "fixture-options",
        "fixture-chain-v1",
        calendar,
        (EXPIRY,),
        D("100"),
        True,
        1,
        (series,),
    )
    policy = GammaPolicyV1(
        "fixture-gex",
        "1",
        "gex-calc-v1",
        "expiry-calendar-v1",
        (EXPIRY,),
        DealerExposureAssumptionV1("scenario-only", "1", "explicit test sign", -1, 1),
        (D("50"), D("75"), D("100"), D("125"), D("150")),
        D("0.0001"),
    )
    return evaluate(GammaSnapshotV1(chain), policy, NOW)


def _row(series: str, *, delta: Decimal | None = DEFAULT_DELTA, option_type: str = "CALL"):
    return DexOptionEvidenceV1(
        series_id=series,
        expiry=EXPIRY,
        option_type=option_type,
        delta=delta,
        open_interest=D("10"),
        multiplier=D("100"),
        delta_observed_ns=NOW,
        delta_available_ns=NOW,
        oi_asof_ns=NOW,
        source_record_digest=(series.encode("ascii").hex() * 64)[:64],
    )


def _evidence(gamma, *, chain_id: str = "snapshot-1", rows=None):
    horizon = gamma.live
    return DexChainEvidenceV1(
        chain_snapshot_id=chain_id,
        underlier="XYZ",
        venue="XOPT",
        provider="fixture-options",
        dataset="fixture-chain-v1",
        observed_ns=horizon.observed_ns,
        available_ns=horizon.available_ns,
        provenance_digest=gamma.semantic_digest,
        series=rows or (_row("call"), _row("put", delta=D("-0.25"), option_type="PUT")),
    )


def _policy():
    return DexPolicyV1(
        policy_id="declared-scenario", version="1", call_dealer_sign=-1, put_dealer_sign=1
    )


def test_imports_resolve_to_the_requested_worktree_when_configured() -> None:
    expected_worktree = os.environ.get("LEVIATHAN_ACCEPTANCE_WORKTREE")
    if not expected_worktree:
        pytest.skip("set LEVIATHAN_ACCEPTANCE_WORKTREE to verify import origin")

    import leviathan_core.dealer_delta as dex
    import leviathan_core.dealer_gamma as gex
    import leviathan_core.intel as intel
    import leviathan_market_data as market_data

    expected_root = Path(expected_worktree).resolve()
    for module in (dex, gex, intel, market_data):
        assert Path(module.__file__).resolve().is_relative_to(expected_root), module.__file__


def test_dex_and_gex_snapshot_mismatch_fails_closed() -> None:
    gamma = _gamma()
    dex = calculate_dex(
        _evidence(gamma, chain_id="another-snapshot"), _policy(), decision_as_of_ns=NOW
    )
    with pytest.raises(FactorAdapterInputError):
        DexFactorAdapter(scale=D("1000")).context_for(dex, gamma, decision_as_of_ns=NOW)


def test_missing_or_invalid_delta_is_not_zero_or_derived() -> None:
    gamma = _gamma()
    missing = calculate_dex(
        _evidence(gamma, rows=(_row("missing", delta=None),)), _policy(), decision_as_of_ns=NOW
    )
    assert missing.status == "MISSING_DELTA" and missing.reason == "MISSING_DELTA"
    assert missing.expiry_exposures == () and missing.missing_delta_count == 1
    adapter = DexFactorAdapter(scale=D("1000"))
    abstention = adapter.evaluate(
        missing, gamma, EXPIRY, adapter.context_for(missing, gamma, decision_as_of_ns=NOW)
    )
    assert isinstance(abstention, FactorAbstentionV1) and abstention.reason == "MISSING_DELTA"
    with pytest.raises(ValueError):
        _row("out-of-range", delta=D("1.01"))
    with pytest.raises(ValueError):
        DexOptionEvidenceV1(
            series_id="float-delta",
            expiry=EXPIRY,
            option_type="CALL",
            delta=0.5,
            open_interest=D("10"),
            multiplier=D("100"),
            delta_observed_ns=NOW,
            delta_available_ns=NOW,
            oi_asof_ns=NOW,
            source_record_digest="a" * 64,
        )


def test_gex_models_are_byte_identical_to_canonical_start() -> None:
    manifest_path = WORKTREE / "qa/handoffs/INTEL-002/canonical-start-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    recorded = {row["path"]: row["sha256"] for row in manifest["files"]}
    unchanged = (
        "packages/leviathan-core/src/leviathan_core/dealer_gamma/models.py",
        "packages/leviathan-core/src/leviathan_core/dealer_gamma/chain_adapter.py",
    )
    for rel in unchanged:
        worktree_bytes = (WORKTREE / rel).read_bytes()
        canonical_bytes = (CANONICAL / rel).read_bytes()
        assert worktree_bytes == canonical_bytes
        assert hashlib.sha256(worktree_bytes).hexdigest() == recorded[rel]
    gamma_source = (WORKTREE / unchanged[0]).read_text(encoding="utf-8")
    chain_source = (WORKTREE / unchanged[1]).read_text(encoding="utf-8")
    assert "class OptionSeriesEvidenceV1" in gamma_source
    assert "class ChainRowV1" in chain_source


def test_dex_and_gex_adapters_emit_valid_scores_with_provenance() -> None:
    gamma = _gamma()
    dex = calculate_dex(_evidence(gamma), _policy(), decision_as_of_ns=NOW)
    dex_adapter = DexFactorAdapter(scale=D("1000"))
    dex_score = dex_adapter.evaluate(
        dex, gamma, EXPIRY, dex_adapter.context_for(dex, gamma, decision_as_of_ns=NOW)
    )
    assert isinstance(dex_score, FactorScoreV1)
    assert dex_score.factor_id == f"{dex_adapter.factor_id}:{EXPIRY.isoformat()}"
    assert dex_score.evidence_refs and {ref.source for ref in dex_score.evidence_refs} == {
        "dex001.estimate:fixture-options:fixture-chain-v1",
        "gex001.gamma",
    }
    assert all(len(ref.record_digest) == 64 for ref in dex_score.evidence_refs)

    gex_adapter = GammaFactorAdapter()
    gex_score = gex_adapter.evaluate(
        gamma, "XOPT", gex_adapter.context_for(gamma, venue="XOPT", decision_as_of_ns=NOW)
    )
    assert isinstance(gex_score, FactorScoreV1) and gex_score.evidence_refs
    assert gex_score.evidence_refs[0].source == "gex001.gamma"


def test_future_evidence_hard_errors_and_stale_scheduled_factor_abstains() -> None:
    future_ref = EvidenceRefV1(
        source="tier3.calendar",
        record_digest="f" * 64,
        as_of_ns=NOW + 1,
        source_event_ns=NOW - 1,
    )
    with pytest.raises(ValueError, match="FUTURE_EVIDENCE"):
        issue_as_of_context(decision_as_of_ns=NOW, freshness="fresh", evidence_refs=(future_ref,))

    gamma = _gamma()
    dex = calculate_dex(_evidence(gamma), _policy(), decision_as_of_ns=NOW)
    adapter = DexFactorAdapter(scale=D("1000"))
    stale_context = adapter.context_for(dex, gamma, decision_as_of_ns=NOW, freshness="stale")
    outcome = adapter.evaluate(dex, gamma, EXPIRY, stale_context)
    assert isinstance(outcome, FactorAbstentionV1) and outcome.reason == "STALE_EVIDENCE"
    # Known-ahead event metadata is separate from publication/availability evidence.
    scheduled_event_at = NOW + DAY
    assert scheduled_event_at > NOW and future_ref.source_event_ns < NOW


def test_trace_digest_is_input_order_independent() -> None:
    gamma = _gamma()
    dex = calculate_dex(_evidence(gamma), _policy(), decision_as_of_ns=NOW)
    adapter = DexFactorAdapter(scale=D("1000"))
    score = adapter.evaluate(
        dex, gamma, EXPIRY, adapter.context_for(dex, gamma, decision_as_of_ns=NOW)
    )
    second = FactorScoreV1(**{**score.model_dump(), "factor_id": "dex001.other-factor.v1"})
    extra = EvidenceRefV1(
        source="fixture.extra", record_digest="e" * 64, as_of_ns=NOW, source_event_ns=NOW - 1
    )
    refs = (*score.evidence_refs, extra)
    first_trace = build_trace(
        decision_as_of_ns=NOW,
        evidence_refs=refs,
        normalized_event_refs=tuple(reversed(refs)),
        factor_outcomes=(score, second),
    )
    reordered = build_trace(
        decision_as_of_ns=NOW,
        evidence_refs=tuple(reversed(refs)),
        normalized_event_refs=refs,
        factor_outcomes=(second, score),
    )
    assert first_trace.trace_sha256 == reordered.trace_sha256
