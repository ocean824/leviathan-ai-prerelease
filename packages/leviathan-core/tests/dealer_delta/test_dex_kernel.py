"""DEX-001 exact scenario arithmetic and INTEL adapter lineage tests."""

from __future__ import annotations

from datetime import date
from decimal import Decimal

import pytest
from pydantic import ValidationError

from leviathan_core.dealer_delta import (
    DexChainEvidenceV1,
    DexFactorAdapter,
    DexOptionEvidenceV1,
    DexPolicyV1,
    calculate_dex,
)
from leviathan_core.dealer_delta.kernel import DexKernelError
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
    GammaFactorAdapter,
    build_trace,
)

D = Decimal
HALF = D("0.5")
TEN = D("10")
HUNDRED = D("100")
NOW = 1_800_000_000_000_000_000
DAY = 86_400_000_000_000
EXPIRY = date(2026, 10, 9)


def _gamma(*, available_ns: int = NOW) -> object:
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
        source_id="licensed-fixture",
        dataset_id="set-v1",
        entitlement_id="fixture-entitlement",
        entitlement_status="ENTITLED",
        corporate_action_version="no-action-v1",
        multiplier_basis="PRE_ACTION",
        adjustment_version="adjust-v1",
        deliverable_units=(DeliverableLegV1("UNDERLIER", "XYZ", D("100"), "USD"),),
    )
    chain = ChainSnapshotV1(
        "live-1",
        "LIVE",
        "XYZ",
        "XOPT",
        NOW,
        available_ns,
        0,
        "licensed-fixture",
        "set-v1",
        calendar,
        (EXPIRY,),
        D("100"),
        True,
        1,
        (series,),
    )
    policy = GammaPolicyV1(
        "offline-gex",
        "1",
        "gex-calc-1",
        "expiry-calendar-1",
        (EXPIRY,),
        DealerExposureAssumptionV1(
            "dealers-short-calls-long-puts", "1", "test-only declared scenario", -1, 1
        ),
        (D("50"), D("75"), D("100"), D("125"), D("150")),
        D("0.0001"),
    )
    return evaluate(GammaSnapshotV1(chain), policy, available_ns)


def _row(
    name: str,
    *,
    option_type: str = "CALL",
    delta: Decimal | None = HALF,
    oi: Decimal = TEN,
    multiplier: Decimal = HUNDRED,
    observed_ns: int = NOW,
    available_ns: int | None = None,
) -> DexOptionEvidenceV1:
    return DexOptionEvidenceV1(
        series_id=name,
        expiry=EXPIRY,
        option_type=option_type,  # type: ignore[arg-type]
        delta=delta,
        open_interest=oi,
        multiplier=multiplier,
        delta_observed_ns=observed_ns,
        delta_available_ns=available_ns if available_ns is not None else max(NOW, observed_ns),
        oi_asof_ns=NOW,
        source_record_digest=(name.encode("ascii").hex() * 64)[:64],
    )


def _evidence(
    gamma: object,
    *,
    rows: tuple[DexOptionEvidenceV1, ...] | None = None,
    chain_id: str = "live-1",
) -> DexChainEvidenceV1:
    horizon = gamma.live  # type: ignore[attr-defined]
    return DexChainEvidenceV1(
        chain_snapshot_id=chain_id,
        underlier="XYZ",
        venue="XOPT",
        provider="licensed-fixture",
        dataset="set-v1",
        observed_ns=horizon.observed_ns,
        available_ns=horizon.available_ns,
        provenance_digest=gamma.semantic_digest,  # type: ignore[attr-defined]
        series=rows or (_row("call"), _row("put", option_type="PUT", delta=D("-0.25"), oi=D("4"))),
    )


def _policy() -> DexPolicyV1:
    return DexPolicyV1(
        policy_id="dealer-side-scenario",
        version="1",
        call_dealer_sign=-1,
        put_dealer_sign=1,
    )


def test_dex_uses_delta_oi_multiplier_and_declared_side_by_expiry() -> None:
    gamma = _gamma()
    evidence = _evidence(gamma)
    result = calculate_dex(evidence, _policy(), decision_as_of_ns=NOW)
    assert result.status == "OK"
    assert result.expiry_exposures[0].signed_delta_contracts == D("-600")
    assert result.expiry_exposures[0].series_count == 2

    adapter = DexFactorAdapter(scale=D("1000"))
    context = adapter.context_for(result, gamma, decision_as_of_ns=NOW)
    score = adapter.evaluate(result, gamma, EXPIRY, context)
    assert score.direction == "short"
    assert score.strength == "0.6"
    assert {ref.source for ref in score.evidence_refs} == {
        "dex001.estimate:licensed-fixture:set-v1",
        "gex001.gamma",
    }

    gamma_adapter = GammaFactorAdapter()
    gamma_context = gamma_adapter.context_for(gamma, venue="XOPT", decision_as_of_ns=NOW)
    gamma_score = gamma_adapter.evaluate(gamma, "XOPT", gamma_context)
    assert gamma_score.direction == "neutral"
    assert gamma_score.evidence_refs[0].source == "gex001.gamma"


def test_missing_delta_is_a_typed_abstention_and_never_zero() -> None:
    gamma = _gamma()
    result = calculate_dex(
        _evidence(gamma, rows=(_row("missing", delta=None),)), _policy(), decision_as_of_ns=NOW
    )
    assert result.status == "MISSING_DELTA"
    assert result.expiry_exposures == ()
    adapter = DexFactorAdapter(scale=D("1000"))
    outcome = adapter.evaluate(
        result, gamma, EXPIRY, adapter.context_for(result, gamma, decision_as_of_ns=NOW)
    )
    assert isinstance(outcome, FactorAbstentionV1)
    assert outcome.reason == "MISSING_DELTA"


def test_dex_future_inputs_and_gex_snapshot_mismatch_fail_closed() -> None:
    gamma = _gamma()
    evidence = _evidence(gamma)
    with pytest.raises(DexKernelError) as future:
        calculate_dex(evidence, _policy(), decision_as_of_ns=NOW - 1)
    assert future.value.code == "FUTURE_EVIDENCE"

    mismatch = calculate_dex(
        _evidence(gamma, chain_id="other-chain"), _policy(), decision_as_of_ns=NOW
    )
    adapter = DexFactorAdapter(scale=D("1000"))
    with pytest.raises(FactorAdapterInputError):
        adapter.context_for(mismatch, gamma, decision_as_of_ns=NOW)


def test_dex_decimal_boundary_is_bounded_before_fraction_expansion() -> None:
    with pytest.raises(ValueError):
        _row("oversized", oi=D("1e1000000"))


def test_dex_propagates_latest_contributing_observation_time() -> None:
    gamma = _gamma(available_ns=NOW + 2)
    later_delta = _row("later", observed_ns=NOW + 1)
    evidence = _evidence(gamma, rows=(later_delta,))
    estimate = calculate_dex(evidence, _policy(), decision_as_of_ns=NOW + 2)
    assert estimate.chain_observed_ns == NOW
    assert estimate.observed_ns == NOW + 1

    adapter = DexFactorAdapter(scale=D("1000"))
    context = adapter.context_for(estimate, gamma, decision_as_of_ns=NOW + 2)
    score = adapter.evaluate(estimate, gamma, EXPIRY, context)
    dex_ref = next(ref for ref in score.evidence_refs if ref.source.startswith("dex001.estimate:"))
    assert dex_ref.source_event_ns == NOW + 1
    assert dex_ref.as_of_ns == NOW + 2
    assert score.source_event_ns == NOW + 1


def test_dex_delta_observation_after_cutoff_is_rejected() -> None:
    gamma = _gamma(available_ns=NOW + 3)
    evidence = _evidence(gamma, rows=(_row("future", observed_ns=NOW + 3),))
    with pytest.raises(DexKernelError) as future:
        calculate_dex(evidence, _policy(), decision_as_of_ns=NOW + 2)
    assert future.value.code == "FUTURE_EVIDENCE"


@pytest.mark.parametrize(
    ("option_type", "delta"),
    (("PUT", D("0.25")), ("CALL", D("-0.25"))),
)
def test_dex_rejects_delta_sign_inconsistent_with_option_type(
    option_type: str, delta: Decimal
) -> None:
    with pytest.raises(ValidationError) as error:
        _row("wrong-sign", option_type=option_type, delta=delta)
    assert str(error.value) == "INVALID_FUSION_INPUT"


def test_dex_series_permutation_preserves_digest_evidence_and_trace() -> None:
    gamma = _gamma()
    rows = (_row("call-a"), _row("put-b", option_type="PUT", delta=D("-0.25")))
    adapter = DexFactorAdapter(scale=D("1000"))
    estimates = tuple(
        calculate_dex(_evidence(gamma, rows=permutation), _policy(), decision_as_of_ns=NOW)
        for permutation in (rows, tuple(reversed(rows)))
    )
    assert estimates[0].semantic_digest == estimates[1].semantic_digest
    outcomes = []
    for estimate in estimates:
        context = adapter.context_for(estimate, gamma, decision_as_of_ns=NOW)
        outcome = adapter.evaluate(estimate, gamma, EXPIRY, context)
        outcomes.append(outcome)
    assert outcomes[0].evidence_refs == outcomes[1].evidence_refs
    traces = tuple(
        build_trace(
            decision_as_of_ns=NOW,
            evidence_refs=outcome.evidence_refs,
            normalized_event_refs=(),
            factor_outcomes=(outcome,),
        )
        for outcome in outcomes
    )
    assert traces[0].trace_sha256 == traces[1].trace_sha256
    opposite_policy = DexPolicyV1(
        policy_id="dealer-side-scenario",
        version="1",
        call_dealer_sign=1,
        put_dealer_sign=-1,
    )
    alternate = calculate_dex(_evidence(gamma, rows=rows), opposite_policy, decision_as_of_ns=NOW)
    assert alternate.semantic_digest != estimates[0].semantic_digest
