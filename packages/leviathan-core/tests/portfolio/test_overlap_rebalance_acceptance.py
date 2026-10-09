"""Independent contract probes for PORT-002 overlap and rebalance kernels."""

from __future__ import annotations

import copy
import pickle
import random
from dataclasses import replace
from decimal import Decimal, localcontext

import pytest

from leviathan_core.portfolio.models import (
    HardCapsV1,
    ObservationV1,
    PositionV1,
    ReturnPointV1,
    ReturnSeriesV1,
    SectorEntryV1,
    SizingMode,
    SizingPolicyV1,
    SizingRequestV1,
)
from leviathan_core.portfolio.overlap import (
    CorrelationSnapshotV1,
    ExposureComponentV1,
    ExposureSnapshotV1,
    MissingDataPolicy,
    OverlapPolicyV1,
    PortfolioAllocationV1,
    PortfolioInputError,
    PortfolioSpecV1,
    PortfolioStatus,
    SectorMappingV1,
    StrategyExposureV1,
    evaluate_portfolio,
)
from leviathan_core.portfolio.rebalance import (
    LotConsumptionV1,
    RebalanceAction,
    RebalanceInstrumentV1,
    RebalanceLotV1,
    RebalanceProposalV1,
    RebalanceRequestV1,
    RebalanceStatus,
    propose_rebalance,
)

D = Decimal
NOW = 10**12
WINDOW_START = NOW - 1_000
WINDOW_END = NOW - 100
WINDOW_NS = WINDOW_END - WINDOW_START


def caps(
    *,
    per_symbol: str = "1000",
    per_sector: str = "1000",
    gross: str = "1000",
    net: str = "1000",
    leverage: str = "1000",
    loss: str = "1000",
    heat: str = "1000",
) -> HardCapsV1:
    return HardCapsV1(
        *(D(value) for value in (per_symbol, per_sector, gross, net, leverage, loss, heat))
    )


def spec(
    allocations: tuple[tuple[str, str], ...] = (("rev-a", "1"),),
    *,
    nav: str = "100",
    evaluation_ns: int = NOW,
    revision: str = "portfolio-1",
) -> PortfolioSpecV1:
    return PortfolioSpecV1(
        revision,
        D(nav),
        evaluation_ns,
        tuple(PortfolioAllocationV1(key, D(weight)) for key, weight in allocations),
    )


def exposure(
    revision: str,
    symbols: tuple[tuple[str, str], ...] = (("SYM", "0.5"),),
    *,
    factors: tuple[tuple[str, str], ...] | None = (("value", "0.1"),),
    beta: str | None = "1",
    gamma: str | None = "0",
    heat: str = "0.1",
    event_ns: int = WINDOW_END,
    available_ns: int = WINDOW_END,
    source_version: str = "v1",
) -> StrategyExposureV1:
    return StrategyExposureV1(
        revision,
        tuple(ExposureComponentV1(key, D(value)) for key, value in symbols),
        None
        if factors is None
        else tuple(ExposureComponentV1(key, D(value)) for key, value in factors),
        None if beta is None else D(beta),
        None if gamma is None else D(gamma),
        D(heat),
        event_ns,
        available_ns,
        source_version,
    )


def policy(
    *,
    overlap: str = "1",
    correlation: str = "1",
    missing: MissingDataPolicy = MissingDataPolicy.BLOCK,
    caps_value: HardCapsV1 | None = None,
    gamma_cap: str = "1000",
    assumed_gamma: str = "1000",
    window_ns: int = WINDOW_NS,
    max_age_ns: int = 10_000,
) -> OverlapPolicyV1:
    return OverlapPolicyV1(
        "policy-v1",
        D(overlap),
        D(correlation),
        window_ns,
        max_age_ns,
        missing,
        D("1"),
        D("0.8"),
        D(assumed_gamma),
        caps_value or caps(),
        D(gamma_cap),
    )


def sector(
    symbol: str = "SYM",
    name: str = "TECH",
    *,
    event_ns: int = WINDOW_END,
    available_ns: int = WINDOW_END,
    source_version: str = "v1",
    remapped_from: str | None = None,
) -> SectorMappingV1:
    return SectorMappingV1(symbol, name, event_ns, available_ns, source_version, remapped_from)


def corr(
    left: str = "rev-a",
    right: str = "rev-b",
    value: str | None = "0.25",
    *,
    event_ns: int = WINDOW_END,
    available_ns: int = WINDOW_END,
    start_ns: int = WINDOW_START,
    end_ns: int = WINDOW_END,
    source_version: str = "v1",
) -> CorrelationSnapshotV1:
    return CorrelationSnapshotV1(
        left,
        right,
        None if value is None else D(value),
        start_ns,
        end_ns,
        event_ns,
        available_ns,
        source_version,
    )


def snapshot(
    strategies: tuple[StrategyExposureV1, ...] = (exposure("rev-a"),),
    *,
    correlations: tuple[CorrelationSnapshotV1, ...] = (),
    sectors: tuple[SectorMappingV1, ...] = (sector(),),
    start_ns: int = WINDOW_START,
    end_ns: int = WINDOW_END,
) -> ExposureSnapshotV1:
    return ExposureSnapshotV1(start_ns, end_ns, strategies, correlations, sectors)


def run(
    *,
    portfolio: PortfolioSpecV1 | None = None,
    evidence: ExposureSnapshotV1 | None = None,
    rules: OverlapPolicyV1 | None = None,
):
    return evaluate_portfolio(portfolio or spec(), evidence or snapshot(), rules or policy())


def sizing_inputs(
    current_quantity: str = "0",
    *,
    symbol: str = "SYM",
    risk_caps: HardCapsV1 | None = None,
    price_value: str = "1",
    lot_step: str = "1",
    fixed_quantity: str = "10",
    equity_value: str = "10000",
    side: str | None = None,
    position_quantities: tuple[tuple[str, str], ...] | None = None,
    sector_symbols: tuple[str, ...] | None = None,
) -> tuple[SizingRequestV1, SizingPolicyV1]:
    def observation(value: str, source: str) -> ObservationV1:
        return ObservationV1(D(value), WINDOW_END, WINDOW_END, source, "v1", "VALIDATED")

    instrument = symbol
    price = observation(price_value, "price")
    fx = observation("1", "fx")
    loss = observation("0.1", "loss")
    equity = observation(equity_value, "equity")
    position_rows = position_quantities
    if position_rows is None:
        position_rows = ((instrument, current_quantity),) if D(current_quantity) != 0 else ()
    positions = tuple(
        PositionV1(
            position_symbol,
            "USD",
            D(quantity),
            price,
            fx,
            loss,
            D("1"),
            WINDOW_END,
            WINDOW_END,
            f"position:{position_symbol}",
            "v1",
            "VALIDATED",
        )
        for position_symbol, quantity in position_rows
    )
    sector_rows = sector_symbols or (instrument,)
    sector_entries = tuple(
        SectorEntryV1(
            sector_symbol,
            "TECH",
            WINDOW_END,
            WINDOW_END,
            f"sector:{sector_symbol}",
            "v1",
            "VALIDATED",
        )
        for sector_symbol in sector_rows
    )
    series = ReturnSeriesV1(
        instrument,
        WINDOW_END,
        WINDOW_END,
        tuple(
            ReturnPointV1(WINDOW_START + index + 1, D("0.01") if index % 2 else D("-0.01"))
            for index in range(20)
        ),
        "returns",
        "v1",
        "VALIDATED",
    )
    risk_caps = risk_caps or caps(
        per_symbol="5",
        per_sector="10",
        gross="10",
        net="10",
        leverage="1",
        loss="10",
        heat="10",
    )
    request = SizingRequestV1(
        "tenant",
        "rev-a",
        "portfolio-1",
        instrument,
        side or ("BUY" if D(current_quantity) <= 0 else "SELL"),
        "USD",
        "USD",
        NOW,
        equity,
        positions,
        sector_entries,
        price,
        fx,
        (series,),
        None,
        loss,
        D("1"),
        D(lot_step),
        D("1"),
        20,
        D("1"),
        "risk-v1",
        None,
    )
    sizing_policy = SizingPolicyV1(
        SizingMode.FIXED,
        D(fixed_quantity),
        (),
        None,
        None,
        risk_caps,
        10_000,
        "risk-v1",
    )
    return request, sizing_policy


def test_weight_sum_accepts_exact_tolerance_edges_and_rejects_outside() -> None:
    assert spec((("rev-a", "0.5"), ("rev-b", "0.500001")))
    assert spec((("rev-a", "0.5"), ("rev-b", "0.499999")))
    with pytest.raises(PortfolioInputError) as error:
        spec((("rev-a", "0.5"), ("rev-b", "0.5000011")))
    assert error.value.code == "WEIGHTS_NOT_NORMALIZED"


def test_duplicate_revision_and_bad_identity_are_typed_and_do_not_echo_input() -> None:
    with pytest.raises(PortfolioInputError) as duplicate:
        spec((("rev-a", "0.5"), ("rev-a", "0.5")))
    assert duplicate.value.code == "DUPLICATE_STRATEGY_REVISION"
    secret = "SECRET bad id\n"
    with pytest.raises(PortfolioInputError) as invalid:
        PortfolioSpecV1(secret, D("100"), NOW, (PortfolioAllocationV1("rev-a", D("1")),))
    assert secret not in str(invalid.value)
    assert invalid.value.args == (invalid.value.code,)


def test_boolean_time_and_decimal_context_cannot_change_kernel_evaluation() -> None:
    with pytest.raises(PortfolioInputError):
        spec(evaluation_ns=True)  # type: ignore[arg-type]
    with localcontext() as context:
        context.prec = 2
        low_precision = run()
    with localcontext() as context:
        context.prec = 40
        high_precision = run()
    assert low_precision.canonical_bytes() == high_precision.canonical_bytes()


def test_decimal_bounds_reject_extreme_magnitude_without_echoing_it() -> None:
    with pytest.raises(PortfolioInputError) as error:
        ExposureComponentV1("wide", D("1e100000"))
    assert error.value.code in {
        "PRECISION_EXCEEDED",
        "INVALID_DECIMAL",
        "MAGNITUDE_OUT_OF_BOUNDS",
    }
    assert "100000" not in str(error.value)


def test_exact_derived_notional_can_be_smaller_than_input_exponent_floor() -> None:
    tiny = spec(nav="1E-38")
    check = run(
        portfolio=tiny,
        evidence=snapshot((exposure("rev-a", (("SYM", "0.1"),)),)),
    )
    assert check.status is PortfolioStatus.PASS
    assert check.gross_notional == D("1E-39")
    assert check.net_notional == D("1E-39")


def test_availability_is_filtered_before_selection_and_hashing() -> None:
    base_spec = spec()
    base_snapshot = snapshot()
    baseline = run(portfolio=base_spec, evidence=base_snapshot)
    late = exposure(
        "rev-a", (("SYM", "99"),), event_ns=NOW + 10, available_ns=NOW + 20, source_version="v2"
    )
    with_late_record = snapshot((exposure("rev-a"), late))
    result = run(portfolio=base_spec, evidence=with_late_record)
    assert result.canonical_bytes() == baseline.canonical_bytes()
    future_only = run(portfolio=base_spec, evidence=snapshot((late,)))
    assert future_only.status is PortfolioStatus.BLOCKED
    assert any(item.code == "MISSING_EXPOSURE" for item in future_only.breaches)


def test_missing_stale_and_wrong_window_evidence_fail_closed() -> None:
    missing = run(evidence=snapshot(strategies=()))
    assert missing.status is PortfolioStatus.BLOCKED
    assert "MISSING_EXPOSURE" in {item.code for item in missing.breaches}

    stale_record = exposure("rev-a", event_ns=NOW - 50_000, available_ns=NOW - 50_000)
    stale = run(evidence=snapshot((stale_record,)))
    assert stale.status is PortfolioStatus.BLOCKED
    assert "STALE_EXPOSURE" in {item.code for item in stale.breaches}

    pair_spec = spec((("rev-a", "0.5"), ("rev-b", "0.5")))
    pair_records = (exposure("rev-a"), exposure("rev-b", (("OTHER", "0.5"),)))
    wrong_window = corr(start_ns=WINDOW_START - 1)
    mismatch = run(
        portfolio=pair_spec,
        evidence=snapshot(
            pair_records, correlations=(wrong_window,), sectors=(sector(), sector("OTHER"))
        ),
    )
    assert mismatch.status is PortfolioStatus.BLOCKED
    assert "MISSING_OR_STALE_CORRELATION" in {item.code for item in mismatch.breaches}


def test_unknown_symbol_without_asof_sector_mapping_blocks() -> None:
    check = run(evidence=snapshot(sectors=()))
    assert check.status is PortfolioStatus.BLOCKED
    assert "UNKNOWN_SYMBOL" in {item.code for item in check.breaches}


def test_missing_factor_beta_gamma_are_blocked_or_visible_assumptions() -> None:
    incomplete = exposure("rev-a", factors=None, beta=None, gamma=None)
    blocked = run(evidence=snapshot((incomplete,)))
    assert blocked.status is PortfolioStatus.BLOCKED
    assert {item.code for item in blocked.breaches} >= {
        "MISSING_FACTOR",
        "MISSING_BETA",
        "MISSING_GAMMA",
    }

    conservative = run(
        evidence=snapshot((incomplete,)),
        rules=policy(missing=MissingDataPolicy.CONSERVATIVE),
    )
    assert conservative.status is PortfolioStatus.PASS
    assert conservative.assumptions == (
        "BETA_1:rev-a",
        "FACTOR_BETA_1:rev-a",
        "GAMMA_POLICY:rev-a",
    )


def test_conservative_missing_gamma_cannot_cancel_known_opposite_gamma() -> None:
    portfolio = spec((("rev-a", "0.5"), ("rev-b", "0.5")))
    records = (
        exposure("rev-a", (("SYM-A", "0.1"),), gamma="-0.4"),
        exposure("rev-b", (("SYM-B", "0.1"),), gamma=None),
    )
    evidence = snapshot(
        records,
        correlations=(corr(value="0.1"),),
        sectors=(sector("SYM-A"), sector("SYM-B")),
    )
    check = run(
        portfolio=portfolio,
        evidence=evidence,
        rules=policy(
            overlap="1",
            missing=MissingDataPolicy.CONSERVATIVE,
            gamma_cap="0.6",
            assumed_gamma="1",
        ),
    )
    assert check.status is PortfolioStatus.BLOCKED
    assert check.net_gamma == D("-0.7")
    assert "GAMMA_POLICY:rev-b" in check.assumptions
    assert "GAMMA_CAP" in {item.code for item in check.breaches}


def test_overlap_threshold_equality_blocks_and_exposes_shared_drivers() -> None:
    pair_spec = spec((("rev-a", "0.5"), ("rev-b", "0.5")))
    pair_snapshot = snapshot(
        (exposure("rev-a"), exposure("rev-b")),
        correlations=(corr(value="0.5"),),
    )
    result = run(portfolio=pair_spec, evidence=pair_snapshot, rules=policy(overlap="1"))
    assert result.status is PortfolioStatus.BLOCKED
    assert result.overlap_pairs[0].score == D("1")
    assert result.overlap_pairs[0].blocked is True
    assert {driver.kind for driver in result.overlap_pairs[0].drivers} >= {
        "symbol",
        "sector",
        "factor",
        "beta",
    }
    assert result.correlation_pairs[0].correlation == D("0.5")
    assert result.max_offdiag == D("0.5")


def test_zero_norm_overlap_vectors_block_without_division() -> None:
    portfolio = spec((("rev-a", "0.5"), ("rev-b", "0.5")))
    zero_vector = (
        exposure("rev-a", (("SYM-A", "0"),), factors=(), beta="0", gamma="0", heat="0"),
        exposure("rev-b", (("SYM-B", "0"),), factors=(), beta="0", gamma="0", heat="0"),
    )
    evidence = snapshot(
        zero_vector,
        correlations=(corr(value="0"),),
        sectors=(sector("SYM-A"), sector("SYM-B")),
    )
    check = run(portfolio=portfolio, evidence=evidence, rules=policy(overlap="1"))
    assert check.status is PortfolioStatus.BLOCKED
    assert "UNDEFINED_OVERLAP" in {breach.code for breach in check.breaches}
    assert len(check.overlap_pairs) == 1
    assert check.overlap_pairs[0].blocked is True
    assert check.overlap_pairs[0].score == D("0")


def test_correlation_limit_is_strict_and_pair_order_is_canonical() -> None:
    pair_spec = spec((("rev-b", "0.5"), ("rev-a", "0.5")))
    pair_snapshot = snapshot(
        (exposure("rev-b"), exposure("rev-a")),
        correlations=(corr("rev-b", "rev-a", "0.5"),),
    )
    at_limit = run(
        portfolio=pair_spec, evidence=pair_snapshot, rules=policy(overlap="1", correlation="0.5")
    )
    assert "CORRELATION_LIMIT" not in {item.code for item in at_limit.breaches}
    assert at_limit.correlation_pairs[0].left_revision_hash == "rev-a"
    assert at_limit.correlation_pairs[0].right_revision_hash == "rev-b"

    permuted = run(
        portfolio=spec((("rev-a", "0.5"), ("rev-b", "0.5"))),
        evidence=snapshot(
            (exposure("rev-a"), exposure("rev-b")), correlations=(corr(value="0.5"),)
        ),
        rules=policy(overlap="1", correlation="0.5"),
    )
    assert at_limit.canonical_bytes() == permuted.canonical_bytes()


@pytest.mark.parametrize(
    ("cap_field", "observed", "code"),
    [
        ("per_symbol", "50", ""),
        ("per_sector", "50", ""),
        ("gross", "50", ""),
        ("net", "50", ""),
        ("leverage", "0.5", ""),
    ],
)
def test_exact_cap_equality_passes(cap_field: str, observed: str, code: str) -> None:
    cap_values = {
        "per_symbol": "1000",
        "per_sector": "1000",
        "gross": "1000",
        "net": "1000",
        "leverage": "1000",
    }
    if cap_field == "per_symbol":
        cap_values["per_symbol"] = observed
    elif cap_field == "per_sector":
        cap_values.update(per_symbol=observed, per_sector=observed)
    elif cap_field == "gross":
        cap_values.update(per_symbol=observed, per_sector=observed, gross=observed, net=observed)
    else:
        cap_values[cap_field] = observed
    check = run(rules=policy(caps_value=caps(**cap_values)))
    assert check.status is PortfolioStatus.PASS
    assert code not in {item.code for item in check.breaches}


@pytest.mark.parametrize(
    ("cap_field", "observed", "code"),
    [
        ("per_symbol", "49.999", "SYMBOL_CAP"),
        ("per_sector", "49.999", "SECTOR_CAP"),
        ("gross", "49.999", "GROSS_CAP"),
        ("net", "49.999", "NET_CAP"),
        ("leverage", "0.49999", "LEVERAGE_CAP"),
    ],
)
def test_exact_cap_one_increment_over_blocks(cap_field: str, observed: str, code: str) -> None:
    cap_values = {
        "per_symbol": "1000",
        "per_sector": "1000",
        "gross": "1000",
        "net": "1000",
        "leverage": "1000",
    }
    if cap_field == "per_symbol":
        cap_values["per_symbol"] = observed
    elif cap_field == "per_sector":
        cap_values.update(per_symbol=observed, per_sector=observed)
    elif cap_field == "gross":
        cap_values.update(per_symbol=observed, per_sector=observed, gross=observed, net=observed)
    else:
        cap_values[cap_field] = observed
    check = run(rules=policy(caps_value=caps(**cap_values)))
    assert check.status is PortfolioStatus.BLOCKED
    assert code in {item.code for item in check.breaches}


def test_remapped_sector_breach_is_quarantined_for_new_entries() -> None:
    remapped = sector(name="NEW", remapped_from="OLD")
    check = run(
        evidence=snapshot(sectors=(remapped,)), rules=policy(caps_value=caps(per_symbol="49"))
    )
    assert check.status is PortfolioStatus.QUARANTINE
    assert "SYMBOL_CAP" in {item.code for item in check.breaches}


@pytest.mark.parametrize("auto_reweight", (False, True))
def test_quarantined_remap_allows_a_cap_restoring_close_but_no_increase(
    auto_reweight: bool,
) -> None:
    portfolio = spec((("rev-a", "0.5"), ("rev-b", "0.5")), nav="10000")
    strategies = (
        exposure("rev-a", (("SYM-A", "0.01"),)),
        exposure("rev-b", (("SYM-A", "0.01"),)),
    )
    evidence = snapshot(
        strategies,
        correlations=(corr(value="0.1"),),
        sectors=(sector("SYM-A", "TECH", remapped_from="OLD"), sector("SYM-B", "TECH")),
    )
    joint_caps = caps(
        per_symbol="100",
        per_sector="100",
        gross="100",
        net="100",
        leverage="0.01",
        loss="100",
        heat="100",
    )
    rules = policy(overlap="0.9", correlation="0.8", caps_value=joint_caps)
    check = run(portfolio=portfolio, evidence=evidence, rules=rules)
    assert check.status is PortfolioStatus.QUARANTINE
    assert "OVERLAP_THRESHOLD" in {item.code for item in check.breaches}

    positions = (("SYM-A", "60"), ("SYM-B", "60"))
    sector_symbols = ("SYM-A", "SYM-B")
    request_a, policy_a = sizing_inputs(
        "60",
        symbol="SYM-A",
        risk_caps=joint_caps,
        side="BUY",
        position_quantities=positions,
        sector_symbols=sector_symbols,
        fixed_quantity="100",
    )
    request_b, policy_b = sizing_inputs(
        "60",
        symbol="SYM-B",
        risk_caps=joint_caps,
        side="SELL",
        position_quantities=positions,
        sector_symbols=sector_symbols,
        fixed_quantity="100",
    )
    instruments = (
        RebalanceInstrumentV1(
            "SYM-A",
            D("60"),
            D("1"),
            request_a,
            policy_a,
            (RebalanceLotV1("a-lot", D("60"), 1),),
            0,
            False,
        ),
        RebalanceInstrumentV1(
            "SYM-B",
            D("60"),
            D("1"),
            request_b,
            policy_b,
            (RebalanceLotV1("b-lot", D("60"), 2),),
            0,
            False,
        ),
    )
    rebalance = RebalanceRequestV1(
        portfolio, evidence, rules, instruments, D("0"), True, auto_reweight, True, True, True
    )
    proposal = propose_rebalance(rebalance, check)

    assert proposal.status is RebalanceStatus.PROPOSED
    assert proposal.reasons == ("QUARANTINE_NEW_ENTRY:SYM-A",)
    assert len(proposal.candidates) == 1
    closing = proposal.candidates[0]
    assert closing.symbol == "SYM-B"
    assert closing.action is RebalanceAction.CLOSE
    assert closing.quantity == D("60")
    final_a = D("60")
    final_b = D("60") - closing.quantity
    final_gross = final_a + final_b
    final_net = abs(final_a + final_b)
    assert final_a <= joint_caps.per_symbol_notional
    assert final_b <= joint_caps.per_symbol_notional
    assert final_gross <= joint_caps.per_sector_notional
    assert final_gross <= joint_caps.gross_notional
    assert final_net <= joint_caps.net_notional
    assert final_gross / portfolio.nav <= joint_caps.max_leverage
    assert closing.quantity * D("0.1") <= joint_caps.per_trade_loss
    assert (final_a + final_b) * D("0.1") <= joint_caps.portfolio_heat


@pytest.mark.parametrize(
    ("availability", "event_ns", "available_ns", "max_age_ns"),
    (
        ("stale", WINDOW_END - 600, WINDOW_END - 600, 500),
        ("out_of_window", WINDOW_START - 1, WINDOW_START - 1, 10_000),
        ("future", NOW + 1, NOW + 1, 10_000),
    ),
)
def test_rebalance_never_targets_stale_out_of_window_or_future_exposure(
    availability: str, event_ns: int, available_ns: int, max_age_ns: int
) -> None:
    portfolio = spec((("rev-a", "0.5"), ("rev-b", "0.5")), nav="10000")
    rules = policy(
        overlap="1",
        correlation="1",
        max_age_ns=max_age_ns,
        caps_value=caps(
            per_symbol="1000",
            per_sector="1000",
            gross="1000",
            net="1000",
            leverage="1",
            loss="1000",
            heat="1000",
        ),
    )
    outcomes = []
    for excluded_value in ("0.004", "0.008"):
        valid = exposure("rev-a", (("SYM-A", "0.01"),))
        excluded = exposure(
            "rev-b",
            (("SYM-B", excluded_value),),
            event_ns=event_ns,
            available_ns=available_ns,
        )
        evidence = snapshot(
            (valid, excluded),
            correlations=(corr(value="0.1"),),
            sectors=(
                sector("SYM-A", "TECH", remapped_from="OLD"),
                sector("SYM-B", "TECH"),
            ),
        )
        check = run(portfolio=portfolio, evidence=evidence, rules=rules)
        assert check.status is PortfolioStatus.QUARANTINE, availability
        assert any(
            item.code
            in {"STALE_EXPOSURE", "OUT_OF_WINDOW_EXPOSURE", "MISSING_EXPOSURE"}
            for item in check.breaches
        ), availability

        positions = (("SYM-A", "50"), ("SYM-B", "40"))
        instruments = []
        for symbol, quantity, side in (
            ("SYM-A", "50", "BUY"),
            ("SYM-B", "40", "SELL"),
        ):
            sizing_request, sizing_policy = sizing_inputs(
                quantity,
                symbol=symbol,
                risk_caps=rules.caps,
                side=side,
                position_quantities=positions,
                sector_symbols=("SYM-A", "SYM-B"),
                fixed_quantity="100",
            )
            instruments.append(
                RebalanceInstrumentV1(
                    symbol,
                    D(quantity),
                    D("1"),
                    sizing_request,
                    sizing_policy,
                    (RebalanceLotV1(f"lot-{symbol}", D(quantity), 1),),
                    0,
                    False,
                )
            )
        request = RebalanceRequestV1(
            portfolio,
            evidence,
            rules,
            tuple(instruments),
            D("0"),
            True,
            False,
            True,
            True,
            True,
        )
        proposal = propose_rebalance(request, check)
        outcomes.append((proposal.status, proposal.candidates))

    assert outcomes[0] == outcomes[1], availability
    assert outcomes[0][0] is RebalanceStatus.BLOCKED, availability
    assert outcomes[0][1] == (), availability


def test_unattributed_close_cannot_claim_to_cure_gamma_cap_quarantine() -> None:
    portfolio = spec((("rev-a", "0.5"), ("rev-b", "0.5")), nav="10000")
    evidence = snapshot(
        (
            exposure("rev-a", (("SYM-A", "0.01"),), gamma="100"),
            exposure("rev-b", (("SYM-A", "0.01"),), gamma="100"),
        ),
        correlations=(corr(value="0.1"),),
        sectors=(
            sector("SYM-A", "TECH", remapped_from="OLD"),
            sector("SYM-B", "TECH"),
        ),
    )
    joint_caps = caps(
        per_symbol="1000",
        per_sector="1000",
        gross="1000",
        net="1000",
        leverage="1",
        loss="1000",
        heat="1000",
    )
    rules = policy(overlap="1", correlation="1", caps_value=joint_caps, gamma_cap="50")
    check = run(portfolio=portfolio, evidence=evidence, rules=rules)
    assert check.status is PortfolioStatus.QUARANTINE
    assert "GAMMA_CAP" in {item.code for item in check.breaches}

    positions = (("SYM-A", "100"), ("SYM-B", "60"))
    instruments = []
    for symbol, quantity, side in (
        ("SYM-A", "100", "BUY"),
        ("SYM-B", "60", "SELL"),
    ):
        sizing_request, sizing_policy = sizing_inputs(
            quantity,
            symbol=symbol,
            risk_caps=joint_caps,
            side=side,
            position_quantities=positions,
            sector_symbols=("SYM-A", "SYM-B"),
            fixed_quantity="100",
        )
        instruments.append(
            RebalanceInstrumentV1(
                symbol,
                D(quantity),
                D("1"),
                sizing_request,
                sizing_policy,
                (RebalanceLotV1(f"lot-{symbol}", D(quantity), 1),),
                0,
                False,
            )
        )
    request = RebalanceRequestV1(
        portfolio,
        evidence,
        rules,
        tuple(instruments),
        D("0"),
        True,
        False,
        True,
        True,
        True,
    )
    proposal = propose_rebalance(request, check)
    assert all(
        candidate.symbol != "SYM-B" or candidate.action is not RebalanceAction.CLOSE
        for candidate in proposal.candidates
    )


@pytest.mark.parametrize(
    ("gamma_value", "heat_value", "limit", "code", "expected_status"),
    [
        ("0.5", "0.1", "0.5", "", PortfolioStatus.PASS),
        ("0.5001", "0.1", "0.5", "GAMMA_CAP", PortfolioStatus.BLOCKED),
        ("0.5", "0.1001", "0.5", "HEAT_CAP", PortfolioStatus.BLOCKED),
    ],
)
def test_gamma_and_heat_caps_compare_exactly(
    gamma_value: str,
    heat_value: str,
    limit: str,
    code: str,
    expected_status: PortfolioStatus,
) -> None:
    check = run(
        evidence=snapshot((exposure("rev-a", gamma=gamma_value, heat=heat_value),)),
        rules=policy(
            caps_value=caps(heat="0.1"),
            gamma_cap=limit,
            assumed_gamma="1",
        ),
    )
    assert check.status is expected_status
    if code:
        assert code in {item.code for item in check.breaches}


def test_results_hash_canonicalize_decimal_spelling_and_input_permutations() -> None:
    first = run(
        portfolio=spec((("rev-b", "0.50"), ("rev-a", "0.5"))),
        evidence=snapshot(
            (exposure("rev-b", (("Z", "0.50"),)), exposure("rev-a", (("A", "0.50"),))),
            correlations=(corr(),),
            sectors=(sector("Z", "TECH"), sector("A", "TECH")),
        ),
    )
    second = run(
        portfolio=spec((("rev-a", "0.50"), ("rev-b", "0.5"))),
        evidence=snapshot(
            (exposure("rev-a", (("A", "0.5"),)), exposure("rev-b", (("Z", "0.5"),))),
            correlations=(corr("rev-b", "rev-a", "0.25"),),
            sectors=(sector("A", "TECH"), sector("Z", "TECH")),
        ),
    )
    assert first.input_hash == second.input_hash
    assert first.policy_hash == second.policy_hash
    assert first.canonical_bytes() == second.canonical_bytes()


def test_frozen_records_reject_copy_deepcopy_pickle_and_mutation() -> None:
    record = spec()
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(PortfolioInputError):
            operation(record)
    with pytest.raises(PortfolioInputError) as assignment_error:
        record.nav = D("1")  # type: ignore[misc]
    assert assignment_error.value.code == "FROZEN_RECORD"
    with pytest.raises(PortfolioInputError) as deletion_error:
        del record.nav  # type: ignore[misc]
    assert deletion_error.value.code == "FROZEN_RECORD"


def test_construction_and_dataclass_replace_revalidate_policy() -> None:
    valid = policy()
    with pytest.raises(PortfolioInputError):
        replace(valid, overlap_threshold=D("1.01"))
    with pytest.raises(PortfolioInputError):
        replace(valid, window_ns=True)  # type: ignore[arg-type]
    with pytest.raises(PortfolioInputError):
        policy(caps_value=caps(per_symbol="100", per_sector="50", gross="100"))


def test_advisory_api_has_no_order_route_and_blocked_check_cannot_rebalance() -> None:
    assert callable(evaluate_portfolio)
    assert callable(propose_rebalance)
    assert not hasattr(RebalanceProposalV1, "submit_order")
    assert not hasattr(RebalanceProposalV1, "route_order")
    blocked_check = run(evidence=snapshot(strategies=()))
    request = RebalanceRequestV1(
        spec(), snapshot(strategies=()), policy(), (), D("0"), True, True, True, True, True
    )
    proposal = propose_rebalance(request, blocked_check)
    assert proposal.status is RebalanceStatus.BLOCKED
    assert proposal.candidates == ()


def test_forged_pass_check_cannot_bypass_recomputed_portfolio_check() -> None:
    portfolio = spec()
    evidence = snapshot(strategies=())
    rules = policy()
    blocked_check = run(portfolio=portfolio, evidence=evidence, rules=rules)
    forged = replace(blocked_check, status=PortfolioStatus.PASS, breaches=())
    request = RebalanceRequestV1(
        portfolio, evidence, rules, (), D("0"), True, False, True, True, True
    )
    with pytest.raises(PortfolioInputError) as error:
        propose_rebalance(request, forged)
    assert error.value.code == "CHECK_MISMATCH"


def test_correlation_breach_never_auto_reweights_without_a_proven_safe_plan() -> None:
    portfolio = spec((("rev-a", "0.5"), ("rev-b", "0.5")))
    evidence = snapshot(
        (exposure("rev-a"), exposure("rev-b", (("OTHER", "0.5"),))),
        correlations=(corr(value="0.9"),),
        sectors=(sector(), sector("OTHER")),
    )
    rules = policy(overlap="1", correlation="0.8")
    check = run(portfolio=portfolio, evidence=evidence, rules=rules)
    assert check.status is PortfolioStatus.BLOCKED
    request = RebalanceRequestV1(
        portfolio, evidence, rules, (), D("0"), True, True, True, True, True
    )
    proposal = propose_rebalance(request, check)
    assert proposal.status is RebalanceStatus.BLOCKED
    assert proposal.candidates == ()
    assert proposal.reasons == ("AUTO_REWEIGHT_UNPROVEN",)


def test_rebalance_increase_is_port001_capped_and_lot_rounded() -> None:
    portfolio = spec(nav="10000")
    evidence = snapshot((exposure("rev-a", (("SYM", "0.1"),)),))
    rules = policy(caps_value=caps(per_symbol="2000", per_sector="2000", gross="2000", net="2000"))
    check = run(portfolio=portfolio, evidence=evidence, rules=rules)
    assert check.status is PortfolioStatus.PASS

    sizing_request, sizing_policy = sizing_inputs()
    instrument = RebalanceInstrumentV1(
        "SYM", D("0"), D("1"), sizing_request, sizing_policy, (), 0, False
    )
    request = RebalanceRequestV1(
        portfolio,
        evidence,
        rules,
        (instrument,),
        D("0"),
        True,
        False,
        True,
        True,
        True,
    )
    proposal = propose_rebalance(request, check)
    assert proposal.status is RebalanceStatus.PROPOSED
    assert len(proposal.candidates) == 1
    candidate = proposal.candidates[0]
    assert candidate.action is RebalanceAction.INCREASE
    assert candidate.quantity == D("5")
    assert candidate.notional == D("5")
    assert candidate.quantity % instrument.lot_step == 0
    assert candidate.notional <= sizing_policy.caps.per_symbol_notional


def test_cooldown_and_disabled_direction_suppress_increases() -> None:
    portfolio = spec(nav="10000")
    evidence = snapshot((exposure("rev-a", (("SYM", "0.1"),)),))
    rules = policy(caps_value=caps(per_symbol="2000", per_sector="2000", gross="2000", net="2000"))
    check = run(portfolio=portfolio, evidence=evidence, rules=rules)
    sizing_request, sizing_policy = sizing_inputs()
    ready = RebalanceInstrumentV1(
        "SYM", D("0"), D("1"), sizing_request, sizing_policy, (), 0, False
    )

    cooled = replace(ready, cooldown_until_ns=NOW + 1)
    cooled_request = RebalanceRequestV1(
        portfolio, evidence, rules, (cooled,), D("0"), True, False, True, True, True
    )
    cooled_result = propose_rebalance(cooled_request, check)
    assert cooled_result.status is RebalanceStatus.NO_PROPOSAL
    assert cooled_result.reasons == ("COOLDOWN_OR_STOP:SYM",)

    long_disabled = RebalanceRequestV1(
        portfolio, evidence, rules, (ready,), D("0"), True, False, False, True, True
    )
    disabled_result = propose_rebalance(long_disabled, check)
    assert disabled_result.status is RebalanceStatus.NO_PROPOSAL
    assert disabled_result.reasons == ("SIDE_DISABLED:SYM",)

    stopped = replace(ready, stop_breach=True)
    stopped_request = RebalanceRequestV1(
        portfolio, evidence, rules, (stopped,), D("0"), True, False, True, True, True
    )
    stopped_result = propose_rebalance(stopped_request, check)
    assert stopped_result.status is RebalanceStatus.NO_PROPOSAL
    assert stopped_result.reasons == ("COOLDOWN_OR_STOP:SYM",)

    below_drift = RebalanceRequestV1(
        portfolio, evidence, rules, (ready,), D("0.2"), False, False, True, True, True
    )
    drift_result = propose_rebalance(below_drift, check)
    assert drift_result.status is RebalanceStatus.NO_PROPOSAL
    assert drift_result.reasons == ("BELOW_DRIFT_THRESHOLD:SYM",)


def test_disabled_short_side_does_not_propose_an_increase() -> None:
    portfolio = spec(nav="10000")
    evidence = snapshot((exposure("rev-a", (("SYM", "-0.1"),)),))
    rules = policy(caps_value=caps(per_symbol="2000", per_sector="2000", gross="2000", net="2000"))
    check = run(portfolio=portfolio, evidence=evidence, rules=rules)
    assert check.status is PortfolioStatus.PASS
    sizing_request, sizing_policy = sizing_inputs()
    instrument = RebalanceInstrumentV1(
        "SYM", D("0"), D("1"), sizing_request, sizing_policy, (), 0, False
    )
    request = RebalanceRequestV1(
        portfolio, evidence, rules, (instrument,), D("0"), True, False, True, False, True
    )
    proposal = propose_rebalance(request, check)
    assert proposal.status is RebalanceStatus.NO_PROPOSAL
    assert proposal.reasons == ("SIDE_DISABLED:SYM",)


def test_rebalance_reduce_consumes_fifo_and_never_flips_position() -> None:
    portfolio = spec(nav="10000")
    evidence = snapshot((exposure("rev-a", (("SYM", "0.0005"),)),))
    rules = policy(caps_value=caps(per_symbol="2000", per_sector="2000", gross="2000", net="2000"))
    check = run(portfolio=portfolio, evidence=evidence, rules=rules)
    assert check.status is PortfolioStatus.PASS

    sizing_request, sizing_policy = sizing_inputs(
        "8",
        risk_caps=caps(
            per_symbol="10",
            per_sector="10",
            gross="10",
            net="10",
            leverage="1",
            loss="10",
            heat="10",
        ),
    )
    instrument = RebalanceInstrumentV1(
        "SYM",
        D("8"),
        D("1"),
        sizing_request,
        sizing_policy,
        (RebalanceLotV1("lot-old", D("5"), 1), RebalanceLotV1("lot-new", D("3"), 2)),
        0,
        False,
    )
    request = RebalanceRequestV1(
        portfolio,
        evidence,
        rules,
        (instrument,),
        D("0"),
        True,
        False,
        True,
        True,
        True,
    )
    proposal = propose_rebalance(request, check)
    assert proposal.status is RebalanceStatus.PROPOSED
    candidate = proposal.candidates[0]
    assert candidate.action is RebalanceAction.REDUCE
    assert candidate.quantity == D("3")
    assert candidate.current_quantity - candidate.quantity == D("5")
    assert candidate.fifo_consumed == (LotConsumptionV1("lot-old", D("3")),)

    no_netting_request = replace(request, fifo_netting=False)
    no_netting = propose_rebalance(no_netting_request, check)
    assert no_netting.status is RebalanceStatus.NO_PROPOSAL
    assert no_netting.reasons == ("FIFO_REQUIRED:SYM",)


def test_rebalance_close_consumes_the_full_position_fifo() -> None:
    portfolio = spec(nav="10000")
    evidence = snapshot((exposure("rev-a", (("SYM", "0"),)),))
    rules = policy(caps_value=caps(per_symbol="2000", per_sector="2000", gross="2000", net="2000"))
    check = run(portfolio=portfolio, evidence=evidence, rules=rules)
    assert check.status is PortfolioStatus.PASS

    sizing_request, sizing_policy = sizing_inputs(
        "8",
        risk_caps=caps(
            per_symbol="10",
            per_sector="10",
            gross="10",
            net="10",
            leverage="1",
            loss="10",
            heat="10",
        ),
    )
    instrument = RebalanceInstrumentV1(
        "SYM",
        D("8"),
        D("1"),
        sizing_request,
        sizing_policy,
        (RebalanceLotV1("lot-old", D("5"), 1), RebalanceLotV1("lot-new", D("3"), 2)),
        0,
        False,
    )
    request = RebalanceRequestV1(
        portfolio, evidence, rules, (instrument,), D("0"), True, False, True, True, True
    )
    proposal = propose_rebalance(request, check)
    assert proposal.status is RebalanceStatus.PROPOSED
    candidate = proposal.candidates[0]
    assert candidate.action is RebalanceAction.CLOSE
    assert candidate.quantity == D("8")
    assert candidate.target_quantity == D("0")
    assert candidate.fifo_consumed == (
        LotConsumptionV1("lot-old", D("5")),
        LotConsumptionV1("lot-new", D("3")),
    )


def test_simultaneous_increases_respect_aggregate_hard_caps() -> None:
    portfolio = spec(nav="10000")
    evidence = snapshot(
        (exposure("rev-a", (("SYM-A", "0.0005"), ("SYM-B", "0.0005"))),),
        sectors=(sector("SYM-A"), sector("SYM-B")),
    )
    global_caps = caps(
        per_symbol="5",
        per_sector="10",
        gross="10",
        net="10",
        leverage="0.001",
        loss="10",
        heat="10",
    )
    rules = policy(caps_value=global_caps)
    check = run(portfolio=portfolio, evidence=evidence, rules=rules)
    assert check.status is PortfolioStatus.PASS

    instruments = []
    for symbol in ("SYM-A", "SYM-B"):
        sizing_request, sizing_policy = sizing_inputs(symbol=symbol, risk_caps=global_caps)
        instruments.append(
            RebalanceInstrumentV1(
                symbol, D("0"), D("1"), sizing_request, sizing_policy, (), 0, False
            )
        )
    request = RebalanceRequestV1(
        portfolio,
        evidence,
        rules,
        tuple(instruments),
        D("0"),
        True,
        False,
        True,
        True,
        True,
    )
    proposal = propose_rebalance(request, check)
    assert proposal.status is RebalanceStatus.PROPOSED
    assert {candidate.symbol for candidate in proposal.candidates} == {"SYM-A", "SYM-B"}
    total = sum((candidate.notional for candidate in proposal.candidates), D("0"))
    assert total == D("10")
    assert total <= global_caps.gross_notional
    assert total <= global_caps.net_notional
    assert total <= global_caps.per_sector_notional
    assert (
        max(candidate.notional for candidate in proposal.candidates)
        <= global_caps.per_symbol_notional
    )
    assert total <= portfolio.nav * global_caps.max_leverage
    assert sum((candidate.quantity for candidate in proposal.candidates), D("0")) == D("10")
    estimated_losses = sum(
        (candidate.quantity * D("0.1") for candidate in proposal.candidates), D("0")
    )
    assert estimated_losses <= global_caps.per_trade_loss
    assert estimated_losses <= global_caps.portfolio_heat


def test_seeded_rebalance_lots_and_all_simulated_caps_stay_within_bounds() -> None:
    rng = random.Random(17002)
    nav = D("10000")
    for _ in range(6):
        prices = (D(rng.choice(("1.25", "2", "4"))), D(rng.choice(("1.5", "2.5", "5"))))
        lots = (D(rng.choice(("0.5", "1", "2"))), D(rng.choice(("0.5", "1", "2"))))
        weights = (
            D(rng.choice(("0.002", "0.003", "0.004"))),
            D(rng.choice(("0.002", "0.003", "0.004"))),
        )
        targets = tuple(nav * weight for weight in weights)
        gross_target = sum(targets, D("0"))
        symbol_cap = max(targets)
        max_leverage = gross_target / nav
        policy_caps = caps(
            per_symbol=str(symbol_cap),
            per_sector=str(gross_target),
            gross=str(gross_target),
            net=str(gross_target),
            leverage=str(max_leverage),
            loss="10",
            heat="10",
        )
        portfolio = spec(
            nav=str(nav),
        )
        evidence = snapshot(
            (
                exposure(
                    "rev-a",
                    (("SYM-A", str(weights[0])), ("SYM-B", str(weights[1]))),
                ),
            ),
            sectors=(sector("SYM-A"), sector("SYM-B")),
        )
        rules = policy(caps_value=policy_caps)
        check = run(portfolio=portfolio, evidence=evidence, rules=rules)
        assert check.status is PortfolioStatus.PASS

        instruments = []
        for index, symbol in enumerate(("SYM-A", "SYM-B")):
            sizing_request, sizing_policy = sizing_inputs(
                symbol=symbol,
                risk_caps=policy_caps,
                price_value=str(prices[index]),
                lot_step=str(lots[index]),
                fixed_quantity="100",
                equity_value=str(nav),
            )
            instruments.append(
                RebalanceInstrumentV1(
                    symbol,
                    D("0"),
                    lots[index],
                    sizing_request,
                    sizing_policy,
                    (),
                    0,
                    False,
                )
            )
        request = RebalanceRequestV1(
            portfolio,
            evidence,
            rules,
            tuple(instruments),
            D("0"),
            True,
            False,
            True,
            True,
            True,
        )
        proposal = propose_rebalance(request, check)
        assert proposal.status is RebalanceStatus.PROPOSED
        assert portfolio.allocations == (PortfolioAllocationV1("rev-a", D("1")),)
        assert {candidate.symbol for candidate in proposal.candidates} == {"SYM-A", "SYM-B"}

        total_gross = D("0")
        total_net = D("0")
        sector_gross = D("0")
        total_loss = D("0")
        for index, candidate in enumerate(proposal.candidates):
            assert candidate.quantity % lots[index] == 0
            assert candidate.action is RebalanceAction.INCREASE
            assert candidate.notional == candidate.quantity * prices[index]
            assert candidate.notional <= policy_caps.per_symbol_notional
            total_gross += abs(candidate.notional)
            total_net += candidate.notional
            sector_gross += abs(candidate.notional)
            loss = candidate.quantity * D("0.1")
            assert loss <= policy_caps.per_trade_loss
            total_loss += loss
        assert total_gross <= policy_caps.gross_notional
        assert total_net <= policy_caps.net_notional
        assert sector_gross <= policy_caps.per_sector_notional
        assert total_gross / nav <= policy_caps.max_leverage
        assert total_loss <= policy_caps.portfolio_heat
