"""Independent adversarial acceptance tests for the PORT-001 sizing kernel."""

from __future__ import annotations

import copy
import json
import pickle
import random
from dataclasses import replace
from decimal import Decimal
from fractions import Fraction
from pathlib import Path

import pytest

from leviathan_core.portfolio import (
    AssetProvenanceV1,
    HardCapsV1,
    KellyEstimateV1,
    ObservationV1,
    PositionV1,
    ReturnPointV1,
    ReturnSeriesV1,
    RiskBudgetV1,
    SectorEntryV1,
    SizingMode,
    SizingPolicyV1,
    SizingRequestV1,
    SizingResultV1,
    SizingStatus,
    size,
)
from leviathan_core.portfolio.models import SizingInputError, canonical_hash

D = Decimal
ONE = D("1")
NOW_NS = 20_000_000_000
BASE_RETURN = (D("-3"), D("3"), D("-0.5"), D("0.5"), D("-0.5"), D("0.5")) + (
    D("0"),
) * 14


def observation(
    value: str | Decimal,
    *,
    event_ns: int = NOW_NS - 1_000,
    available_ns: int = NOW_NS - 500,
) -> ObservationV1:
    return ObservationV1(
        value=value if isinstance(value, Decimal) else D(value),
        event_ns=event_ns,
        available_ns=available_ns,
        source_id="synthetic-feed",
        source_version="fixture-v1",
        validation_status="VALIDATED",
    )


def series(
    instrument: str,
    returns: tuple[Decimal, ...],
    *,
    timestamps: tuple[int, ...] | None = None,
    available_ns: int = NOW_NS - 100,
) -> ReturnSeriesV1:
    # Pin each fixture's final observation before evaluation time for any N.
    point_times = timestamps or tuple(
        NOW_NS - len(returns) * 1_000 + i * 1_000 for i in range(len(returns))
    )
    assert len(point_times) == len(returns)
    return ReturnSeriesV1(
        instrument=instrument,
        as_of_ns=point_times[-1],
        available_ns=available_ns,
        points=tuple(
            ReturnPointV1(timestamp_ns=timestamp, value=value)
            for timestamp, value in zip(point_times, returns, strict=True)
        ),
        source_id="synthetic-returns",
        source_version="fixture-v1",
        validation_status="VALIDATED",
    )


def orthogonal_series() -> tuple[ReturnSeriesV1, ReturnSeriesV1]:
    a = BASE_RETURN
    b = (D("0"),) * 6 + tuple(value * 2 for value in BASE_RETURN[:6]) + (D("0"),) * 8
    return series("A", a), series("B", b)


def correlated_series() -> tuple[ReturnSeriesV1, ReturnSeriesV1]:
    low = BASE_RETURN
    independent_component = (D("0"),) * 6 + (
        D("-4"),
        D("4"),
        D("-3"),
        D("3"),
        D("-1"),
        D("1"),
        D("-1"),
        D("1"),
        D("-1"),
        D("1"),
        D("-0.5"),
        D("0.5"),
        D("-0.5"),
        D("0.5"),
    )
    high = tuple(left + right for left, right in zip(low, independent_component, strict=True))
    # By direct sums: Var(high)=4, Var(low)=1, Cov(high, low)=1.
    return series("A", high), series("B", low)


def three_diagonal_series() -> tuple[ReturnSeriesV1, ...]:
    block = BASE_RETURN[:6]
    a = BASE_RETURN
    b = (D("0"),) * 6 + tuple(value * 2 for value in block) + (D("0"),) * 8
    c = (D("0"),) * 12 + tuple(value * 3 for value in block) + (D("0"),) * 2
    return series("A", a), series("B", b), series("C", c)


def reference_erc_series_3() -> tuple[ReturnSeriesV1, ...]:
    u = tuple(D("-1") if index % 2 == 0 else D("1") for index in range(24))
    v = tuple(D("1") if index % 4 < 2 else D("-1") for index in range(24))
    w = tuple(D("1") if index % 8 < 4 else D("-1") for index in range(24))
    return (
        series("A", u),
        series("B", tuple(left + right for left, right in zip(u, v, strict=True))),
        series(
            "C",
            tuple(
                left + middle + right
                for left, middle, right in zip(u, v, w, strict=True)
            ),
        ),
    )


def nonconverging_erc_series() -> tuple[ReturnSeriesV1, ...]:
    u = tuple(D("-1") if index % 2 == 0 else D("1") for index in range(24))
    v = tuple(D("1") if index % 4 < 2 else D("-1") for index in range(24))
    w = tuple(D("1") if index % 8 < 4 else D("-1") for index in range(24))
    return (
        series("A", u),
        series(
            "B",
            tuple(-left + D("0.1") * right for left, right in zip(u, v, strict=True)),
        ),
        series(
            "C",
            tuple(left + D("0.1") * right for left, right in zip(v, w, strict=True)),
        ),
    )


def caps(**overrides: Decimal) -> HardCapsV1:
    values = {
        "per_symbol_notional": D("1000000"),
        "per_sector_notional": D("1000000"),
        "gross_notional": D("1000000"),
        "net_notional": D("1000000"),
        "max_leverage": D("100"),
        "per_trade_loss": D("1000000"),
        "portfolio_heat": D("1000000"),
    }
    values.update(overrides)
    return HardCapsV1(**values)


def make_request(
    *,
    instrument: str = "A",
    return_series: tuple[ReturnSeriesV1, ...] | None = None,
    price: str = "10",
    equity: str = "10000",
    multiplier: str = "1",
    lot_step: str = "0.1",
    min_notional: str = "0",
    loss_per_unit: str = "1",
    lookback_count: int | None = 20,
    annualization_factor: str | None = "4",
    positions: tuple[PositionV1, ...] = (),
    sector_map: tuple[SectorEntryV1, ...] | None = None,
    kelly_estimate: KellyEstimateV1 | None = None,
    candidate_provenance: AssetProvenanceV1 | None = None,
) -> SizingRequestV1:
    active_series = return_series if return_series is not None else orthogonal_series()
    instruments = tuple(item.instrument for item in active_series)
    sectors = (
        sector_map
        if sector_map is not None
        else tuple(
            SectorEntryV1(
                instrument=symbol,
                sector="synthetic-sector",
                event_ns=NOW_NS - 1_000,
                available_ns=NOW_NS - 500,
                source_id="synthetic-sector-map",
                source_version="fixture-v1",
                validation_status="VALIDATED",
            )
            for symbol in instruments
        )
    )
    return SizingRequestV1(
        tenant_id="synthetic-tenant",
        strategy_revision_hash="a" * 64,
        portfolio_revision_hash="b" * 64,
        instrument=instrument,
        side="BUY",
        instrument_currency="USD",
        account_currency="USD",
        evaluation_ns=NOW_NS,
        equity=observation(equity),
        positions=positions,
        sector_map=sectors,
        price=observation(price),
        fx_to_account=observation("1"),
        return_series=active_series,
        kelly_estimate=kelly_estimate,
        worst_case_loss_per_unit=observation(loss_per_unit),
        contract_multiplier=D(multiplier),
        lot_step=D(lot_step),
        min_notional=D(min_notional),
        lookback_count=lookback_count,
        annualization_factor=None if annualization_factor is None else D(annualization_factor),
        risk_rail_policy_digest="c" * 64,
        candidate_provenance=candidate_provenance,
    )


def make_policy(
    mode: SizingMode | str = SizingMode.FIXED,
    *,
    fixed_quantity: Decimal | None = ONE,
    risk_budgets: tuple[RiskBudgetV1, ...] = (),
    fractional_kelly_factor: Decimal | None = None,
    gross_exposure_target: Decimal | None = None,
    hard_caps: HardCapsV1 | None = None,
) -> SizingPolicyV1:
    return SizingPolicyV1(
        mode=SizingMode(mode),
        fixed_quantity=fixed_quantity,
        risk_budget_fractions=risk_budgets,
        fractional_kelly_factor=fractional_kelly_factor,
        gross_exposure_target=gross_exposure_target,
        caps=hard_caps or caps(),
        max_age_ns=5_000_000,
        policy_digest="c" * 64,
    )


def inverse_volatility_pair(
    gross_target: Decimal,
) -> tuple[SizingResultV1, SizingResultV1]:
    equal_returns = orthogonal_series()[0].points
    aligned_equal_sigma = (
        series("A", tuple(point.value for point in equal_returns)),
        series("B", tuple(point.value for point in equal_returns)),
    )
    policy = make_policy(
        SizingMode.INVERSE_VOLATILITY,
        fixed_quantity=None,
        gross_exposure_target=gross_target,
    )
    return tuple(
        size(
            make_request(
                instrument=symbol,
                return_series=aligned_equal_sigma,
                price="1",
                multiplier="1",
                lot_step="1",
                annualization_factor="1",
            ),
            policy,
        )
        for symbol in ("A", "B")
    )


def assert_within_caps(result, cap: HardCapsV1) -> None:
    assert result.status is SizingStatus.SIZE
    assert result.exposures is not None
    assert result.exposures.symbol_notional <= cap.per_symbol_notional
    assert result.exposures.sector_notional <= cap.per_sector_notional
    assert result.exposures.gross_notional <= cap.gross_notional
    assert abs(result.exposures.net_notional) <= cap.net_notional
    assert result.exposures.leverage <= cap.max_leverage
    assert result.exposures.projected_worst_case_loss <= cap.per_trade_loss
    assert result.exposures.portfolio_heat <= cap.portfolio_heat
    assert result.proposed_quantity >= D("0")


def test_fixed_sizing_is_a_proposal_not_an_execution_authorization() -> None:
    request = make_request()
    policy = make_policy(fixed_quantity=D("2.5"))

    result = size(request, policy)

    assert result.status is SizingStatus.SIZE
    assert result.proposed_quantity == D("2.5")
    assert result.unclamped_quantity == D("2.5")
    assert result.formula_version == "PORT-FORMULA-v1"
    assert not hasattr(result, "permit")
    assert not hasattr(result, "route")
    assert_within_caps(result, policy.caps)


def test_volatility_scaled_uses_independently_derived_sample_sigma_and_annualization() -> None:
    # A has 20 centered returns with sum(x^2)=19: sample sigma is exactly 1.
    # Annualization factor 4 makes sigma exactly 2. Target notional=10000*0.2/2=1000.
    request = make_request(price="10", equity="10000", annualization_factor="4")
    policy = make_policy(
        SizingMode.VOLATILITY_SCALED,
        fixed_quantity=None,
        risk_budgets=(RiskBudgetV1("A", D("0.2")), RiskBudgetV1("B", D("0.3"))),
    )

    result = size(request, policy)

    assert result.status is SizingStatus.SIZE
    assert result.unclamped_quantity == D("100")
    assert result.proposed_quantity == D("100")
    assert result.formula_version == "PORT-FORMULA-v1"
    assert_within_caps(result, policy.caps)


def test_volatility_scaled_accepts_valid_mixed_scale_psd_returns() -> None:
    tiny = tuple(
        D("1e-20") if index % 2 == 0 else D("-1e-20") for index in range(20)
    )
    unit = tuple(D("1") if index % 2 == 0 else D("-1") for index in range(20))
    request = make_request(
        instrument="A",
        return_series=(series("A", tiny), series("B", unit)),
        annualization_factor="1",
    )
    policy = make_policy(
        SizingMode.VOLATILITY_SCALED,
        fixed_quantity=None,
        risk_budgets=(RiskBudgetV1("A", D("0.1")), RiskBudgetV1("B", D("0.1"))),
    )

    result = size(request, policy)

    assert result.status is SizingStatus.SIZE
    assert result.proposed_quantity > D("0")
    assert "NUMERICAL_INSTABILITY" not in result.reasons
    assert_within_caps(result, policy.caps)


@pytest.mark.parametrize(
    ("lookback_count", "annualization_factor"),
    [(19, "4"), (20, None)],
    ids=["too-short-lookback", "missing-annualization"],
)
def test_volatility_scaled_requires_explicit_valid_window_inputs(
    lookback_count: int, annualization_factor: str | None
) -> None:
    request = make_request(
        lookback_count=lookback_count,
        annualization_factor=annualization_factor,
    )
    policy = make_policy(
        SizingMode.VOLATILITY_SCALED,
        fixed_quantity=None,
        risk_budgets=(RiskBudgetV1("A", D("0.2")), RiskBudgetV1("B", D("0.3"))),
    )

    result = size(request, policy)

    assert result.status is SizingStatus.NO_SIZE
    assert result.proposed_quantity == D("0")


def test_volatility_scaled_rejects_misaligned_and_wrong_length_series() -> None:
    a, b = orthogonal_series()
    misaligned_points = (
        ReturnPointV1(timestamp_ns=b.points[0].timestamp_ns + 1, value=b.points[0].value),
        *b.points[1:],
    )
    misaligned = ReturnSeriesV1(
        instrument=b.instrument,
        as_of_ns=b.as_of_ns,
        available_ns=b.available_ns,
        points=misaligned_points,
        source_id=b.source_id,
        source_version=b.source_version,
        validation_status=b.validation_status,
    )
    short = ReturnSeriesV1(
        instrument=b.instrument,
        as_of_ns=b.as_of_ns,
        available_ns=b.available_ns,
        points=b.points[:-1],
        source_id=b.source_id,
        source_version=b.source_version,
        validation_status=b.validation_status,
    )
    policy = make_policy(
        SizingMode.VOLATILITY_SCALED,
        fixed_quantity=None,
        risk_budgets=(RiskBudgetV1("A", D("0.2")), RiskBudgetV1("B", D("0.3"))),
    )

    for candidate in (misaligned, short):
        result = size(make_request(return_series=(a, candidate)), policy)
        assert result.status is SizingStatus.NO_SIZE
        assert result.proposed_quantity == D("0")
        assert "RETURNS_MISALIGNED" in result.reasons


def test_zero_variance_series_fails_closed_for_nonpositive_sigma() -> None:
    zero = series("A", (D("0"),) * 20)
    request = make_request(return_series=(zero, orthogonal_series()[1]))
    policy = make_policy(
        SizingMode.VOLATILITY_SCALED,
        fixed_quantity=None,
        risk_budgets=(RiskBudgetV1("A", D("0.2")), RiskBudgetV1("B", D("0.3"))),
    )

    result = size(request, policy)

    assert result.status is SizingStatus.NO_SIZE
    assert result.proposed_quantity == D("0")
    assert "NONPOSITIVE_VOLATILITY" in result.reasons


def test_perfectly_collinear_returns_deny_erc_but_volatility_scaled_works() -> None:
    a = tuple(D("-1") if index % 2 == 0 else D("1") for index in range(20))
    collinear = (series("A", a), series("B", tuple(value * 2 for value in a)))
    request = make_request(
        instrument="A",
        return_series=collinear,
        price="100",
        lot_step="0.1",
        annualization_factor="1",
    )
    erc_policy = make_policy(
        SizingMode.RISK_PARITY,
        fixed_quantity=None,
        gross_exposure_target=D("9000"),
    )
    volatility_policy = make_policy(
        SizingMode.VOLATILITY_SCALED,
        fixed_quantity=None,
        risk_budgets=(RiskBudgetV1("A", D("0.2")), RiskBudgetV1("B", D("0.3"))),
    )

    erc = size(request, erc_policy)
    volatility_scaled = size(request, volatility_policy)

    assert erc.status is SizingStatus.NO_SIZE
    assert "COVARIANCE_SINGULAR" in erc.reasons
    assert volatility_scaled.status is SizingStatus.SIZE
    assert volatility_scaled.proposed_quantity > D("0")
    assert_within_caps(volatility_scaled, volatility_policy.caps)


@pytest.mark.parametrize(
    ("fractions", "valid"),
    [
        ((D("0.2"), D("0.3")), True),
        ((D("0.7"), D("0.4")), False),
        ((D("0"), D("0.3")), False),
        ((D("0.2"), D("1.01")), False),
    ],
)
def test_risk_budget_fractions_are_explicit_positive_and_sum_to_at_most_one(
    fractions: tuple[Decimal, Decimal], valid: bool
) -> None:
    request = make_request()
    risk_budgets = (
        RiskBudgetV1("A", fractions[0]),
        RiskBudgetV1("B", fractions[1]),
    )
    if not valid:
        with pytest.raises(SizingInputError, match="INVALID_RISK_BUDGET"):
            make_policy(
                SizingMode.VOLATILITY_SCALED,
                fixed_quantity=None,
                risk_budgets=risk_budgets,
            )
        return

    policy = make_policy(
        SizingMode.VOLATILITY_SCALED,
        fixed_quantity=None,
        risk_budgets=risk_budgets,
    )

    result = size(request, policy)

    assert result.status is SizingStatus.SIZE


@pytest.mark.parametrize(
    ("instrument", "expected_quantity"),
    [("A", D("2000")), ("B", D("1000"))],
)
def test_diagonal_risk_parity_matches_exact_inverse_volatility_erc_weights(
    instrument: str, expected_quantity: Decimal
) -> None:
    request = make_request(
        instrument=instrument,
        return_series=orthogonal_series(),
        price="1",
        annualization_factor="1",
        lot_step="1",
    )
    policy = make_policy(
        SizingMode.RISK_PARITY,
        fixed_quantity=None,
        gross_exposure_target=D("3000"),
    )

    result = size(request, policy)

    assert result.status is SizingStatus.SIZE
    assert result.unclamped_quantity == expected_quantity
    assert result.proposed_quantity == expected_quantity
    assert_within_caps(result, policy.caps)


@pytest.mark.parametrize(
    ("instrument", "expected_quantity"),
    [("A", D("10")), ("B", D("20"))],
)
def test_correlated_risk_parity_matches_independent_erc_reference(
    instrument: str, expected_quantity: Decimal
) -> None:
    # The independent return construction yields annual covariance [[4,1],[1,1]].
    # Equal-risk contributions solve w_A/w_B=1/2, hence weights 1/3 and 2/3.
    request = make_request(
        instrument=instrument,
        return_series=correlated_series(),
        price="1",
        annualization_factor="1",
        lot_step="0.001",
    )
    policy = make_policy(
        SizingMode.RISK_PARITY,
        fixed_quantity=None,
        gross_exposure_target=D("30"),
    )

    result = size(request, policy)

    assert result.status is SizingStatus.SIZE
    assert result.proposed_quantity == expected_quantity
    assert abs(result.unclamped_quantity - (D("10") if instrument == "A" else D("20"))) < D(
        "1e-10"
    )
    assert_within_caps(result, policy.caps)


@pytest.mark.parametrize(
    ("instrument", "expected_quantity"),
    [("A", D("60")), ("B", D("30"))],
)
def test_twenty_return_reference_vector_has_exact_erc_quantity(
    instrument: str, expected_quantity: Decimal
) -> None:
    u = tuple(D("-1") if index % 2 == 0 else D("1") for index in range(20))
    v = tuple(
        D("2") if index % 4 < 2 else D("-2")
        for index in range(20)
    )
    request = make_request(
        instrument=instrument,
        return_series=(series("A", u), series("B", v)),
        lookback_count=20,
        annualization_factor="1",
        price="100",
        lot_step="1",
    )
    policy = make_policy(
        SizingMode.RISK_PARITY,
        fixed_quantity=None,
        gross_exposure_target=D("9000"),
    )

    result = size(request, policy)

    # Sample variances are 20/19 and 80/19; inverse-volatility weights are 2/3 and 1/3.
    assert result.status is SizingStatus.SIZE
    assert result.proposed_quantity == expected_quantity
    assert_within_caps(result, policy.caps)


@pytest.mark.parametrize(
    ("instrument", "expected_quantity", "expected_weight"),
    [
        ("A", D("40"), D("0.4539583475988188007148733")),
        ("B", D("26"), D("0.2936262078668896602931178")),
        ("C", D("22"), D("0.2524154445342915389920089")),
    ],
)
def test_twenty_four_return_reference_vector_has_expected_three_asset_erc(
    instrument: str, expected_quantity: Decimal, expected_weight: Decimal
) -> None:
    request = make_request(
        instrument=instrument,
        return_series=reference_erc_series_3(),
        lookback_count=24,
        annualization_factor="1",
        price="100",
        lot_step="1",
    )
    policy = make_policy(
        SizingMode.RISK_PARITY,
        fixed_quantity=None,
        gross_exposure_target=D("9000"),
    )

    result = size(request, policy)

    # For M=[[1,1,1],[1,2,2],[1,2,3]], sum(w)=1 and equal risk
    # contributions reduce to a=b*(1+b+c)=c*(1+b+2*c). Solving those
    # equations independently gives these weights; tolerance follows the
    # contract's 1e-12 * total-risk solver criterion.
    assert result.status is SizingStatus.SIZE
    actual_weight = D(
        next(
            item.removeprefix("target_weight=")
            for item in result.calculation_trace
            if item.startswith("target_weight=")
        )
    )
    assert abs(actual_weight - expected_weight) <= D("2e-12")
    assert result.proposed_quantity == expected_quantity
    assert_within_caps(result, policy.caps)


def test_risk_parity_nonconvergence_fails_closed_at_solver_limit() -> None:
    request = make_request(
        return_series=nonconverging_erc_series(),
        lookback_count=24,
        annualization_factor="1",
        price="100",
        lot_step="1",
    )
    policy = make_policy(
        SizingMode.RISK_PARITY,
        fixed_quantity=None,
        gross_exposure_target=D("9000"),
    )

    result = size(request, policy)

    assert result.status is SizingStatus.NO_SIZE
    assert result.proposed_quantity == D("0")
    assert "SOLVER_NOT_CONVERGED" in result.reasons


@pytest.mark.parametrize(
    ("instrument", "expected_quantity"),
    [("A", D("6000")), ("B", D("3000")), ("C", D("2000"))],
)
def test_three_instrument_diagonal_risk_parity_has_exact_reference_values(
    instrument: str, expected_quantity: Decimal
) -> None:
    request = make_request(
        instrument=instrument,
        return_series=three_diagonal_series(),
        price="1",
        annualization_factor="1",
        lot_step="1",
    )
    policy = make_policy(
        SizingMode.RISK_PARITY,
        fixed_quantity=None,
        gross_exposure_target=D("11000"),
    )

    result = size(request, policy)

    assert result.status is SizingStatus.SIZE
    assert result.proposed_quantity == expected_quantity
    assert result.unclamped_quantity == expected_quantity
    assert_within_caps(result, policy.caps)


def test_risk_parity_is_permutation_invariant() -> None:
    original = three_diagonal_series()
    request_a = make_request(
        instrument="A",
        return_series=original,
        price="1",
        annualization_factor="1",
        lot_step="1",
    )
    request_b = make_request(
        instrument="A",
        return_series=tuple(reversed(original)),
        price="1",
        annualization_factor="1",
        lot_step="1",
        sector_map=tuple(
            SectorEntryV1(
                instrument=item.instrument,
                sector="synthetic-sector",
                event_ns=NOW_NS - 1_000,
                available_ns=NOW_NS - 500,
                source_id="synthetic-sector-map",
                source_version="fixture-v1",
                validation_status="VALIDATED",
            )
            for item in reversed(original)
        ),
    )
    policy_a = make_policy(
        SizingMode.RISK_PARITY,
        fixed_quantity=None,
        gross_exposure_target=D("11000"),
    )
    policy_b = make_policy(
        SizingMode.RISK_PARITY,
        fixed_quantity=None,
        gross_exposure_target=D("11000"),
    )

    result_a = size(request_a, policy_a)
    result_b = size(request_b, policy_b)

    assert result_a.canonical_bytes() == result_b.canonical_bytes()


def test_capped_kelly_matches_frozen_edge_formula_exactly() -> None:
    request = make_request(
        equity="100000",
        price="10",
        multiplier="10",
        annualization_factor="1",
        loss_per_unit="1",
        kelly_estimate=KellyEstimateV1(
            win_probability=observation("0.6"),
            net_odds=observation("2"),
            window_start_ns=NOW_NS - 10_000,
            window_end_ns=NOW_NS - 1_000,
        ),
    )
    policy = make_policy(
        SizingMode.CAPPED_KELLY,
        fixed_quantity=None,
        fractional_kelly_factor=D("0.25"),
    )

    result = size(request, policy)

    # max(0, (2*0.6 - (1-0.6))/2) * 0.25 * 100000 / (10*10) = 100.
    assert result.status is SizingStatus.SIZE
    assert result.unclamped_quantity == D("100")
    assert result.proposed_quantity == D("100")
    assert_within_caps(result, policy.caps)


def test_extreme_kelly_is_clamped_by_portfolio_heat_and_all_hard_caps() -> None:
    policy_caps = caps(portfolio_heat=D("80"), per_trade_loss=D("100"))
    request = make_request(
        equity="100000",
        price="10",
        loss_per_unit="2",
        lot_step="1",
        kelly_estimate=KellyEstimateV1(
            win_probability=observation("0.99"),
            net_odds=observation("10"),
            window_start_ns=NOW_NS - 10_000,
            window_end_ns=NOW_NS - 1_000,
        ),
    )
    policy = make_policy(
        SizingMode.CAPPED_KELLY,
        fixed_quantity=None,
        fractional_kelly_factor=D("1"),
        hard_caps=policy_caps,
    )

    result = size(request, policy)

    assert result.status is SizingStatus.SIZE
    assert result.unclamped_quantity > result.proposed_quantity
    assert result.proposed_quantity == D("40")
    assert any(hit.code == "PORTFOLIO_HEAT" for hit in result.cap_hits)
    assert_within_caps(result, policy_caps)


def test_negative_kelly_edge_and_missing_estimate_never_make_positive_size() -> None:
    valid_window = (NOW_NS - 10_000, NOW_NS - 1_000)
    negative_request = make_request(
        kelly_estimate=KellyEstimateV1(
            win_probability=observation("0.2"),
            net_odds=observation("2"),
            window_start_ns=valid_window[0],
            window_end_ns=valid_window[1],
        )
    )
    policy = make_policy(
        SizingMode.CAPPED_KELLY,
        fixed_quantity=None,
        fractional_kelly_factor=D("0.5"),
    )

    negative = size(negative_request, policy)
    missing = size(make_request(kelly_estimate=None), policy)

    assert negative.status is SizingStatus.NO_SIZE
    assert negative.proposed_quantity == D("0")
    assert missing.status is SizingStatus.NO_SIZE
    assert missing.proposed_quantity == D("0")


def test_lot_rounding_never_exceeds_proposal_or_cap_and_obeys_min_notional() -> None:
    policy_caps = caps(
        per_symbol_notional=D("20.95"),
        per_sector_notional=D("20.95"),
        gross_notional=D("20.95"),
        net_notional=D("20.95"),
    )
    request = make_request(
        price="10",
        lot_step="0.1",
        min_notional="20",
    )
    policy = make_policy(fixed_quantity=D("2.09"), hard_caps=policy_caps)

    result = size(request, policy)

    assert result.status is SizingStatus.SIZE
    assert result.proposed_quantity == D("2.0")
    assert result.proposed_quantity <= result.unclamped_quantity
    assert result.exposures is not None
    assert result.exposures.symbol_notional <= policy_caps.per_symbol_notional

    below_minimum = size(
        make_request(price="10", lot_step="0.1", min_notional="19.01"),
        make_policy(fixed_quantity=D("1.99"), hard_caps=policy_caps),
    )
    exact_minimum = size(
        make_request(price="10", lot_step="0.1", min_notional="19"),
        make_policy(fixed_quantity=D("1.99"), hard_caps=policy_caps),
    )

    assert below_minimum.status is SizingStatus.NO_SIZE
    assert below_minimum.proposed_quantity == D("0")
    assert exact_minimum.status is SizingStatus.SIZE
    assert exact_minimum.proposed_quantity == D("1.9")


def test_exact_hard_cap_is_feasible_and_one_lot_over_is_clamped_to_cap() -> None:
    exact_caps = caps(
        per_symbol_notional=D("20"),
        per_sector_notional=D("20"),
        gross_notional=D("20"),
        net_notional=D("20"),
        max_leverage=D("0.002"),
        per_trade_loss=D("2"),
        portfolio_heat=D("2"),
    )
    exact_policy = make_policy(fixed_quantity=D("2.0"), hard_caps=exact_caps)
    one_lot_over_policy = make_policy(fixed_quantity=D("2.1"), hard_caps=exact_caps)

    exact = size(make_request(price="10", lot_step="0.1"), exact_policy)
    over = size(make_request(price="10", lot_step="0.1"), one_lot_over_policy)

    assert exact.status is SizingStatus.SIZE
    assert exact.proposed_quantity == D("2.0")
    assert exact.exposures is not None
    assert exact.exposures.symbol_notional == exact_caps.per_symbol_notional
    assert exact.exposures.sector_notional == exact_caps.per_sector_notional
    assert exact.exposures.gross_notional == exact_caps.gross_notional
    assert exact.exposures.net_notional == exact_caps.net_notional
    assert exact.exposures.leverage == exact_caps.max_leverage
    assert exact.exposures.projected_worst_case_loss == exact_caps.per_trade_loss
    assert exact.exposures.portfolio_heat == exact_caps.portfolio_heat

    assert over.status is SizingStatus.SIZE
    assert over.unclamped_quantity == D("2.1")
    assert over.proposed_quantity == D("2.0")
    assert over.cap_hits
    assert_within_caps(over, exact_caps)


def test_exact_notional_fraction_above_hard_cap_never_returns_size() -> None:
    price_text = "1." + "0" * 32 + "1"
    cap_text = "1." + "0" * 32 + "2"
    # (1 + 1e-33)^2 = 1 + 2e-33 + 1e-66, without relying on ambient context.
    exact_notional = D("1." + "0" * 32 + "2" + "0" * 32 + "1")
    precise_caps = caps(
        per_symbol_notional=D(cap_text),
        per_sector_notional=D("1e10"),
        gross_notional=D("1e10"),
        net_notional=D("1e10"),
        max_leverage=D("1e10"),
        per_trade_loss=D("1e10"),
        portfolio_heat=D("1e10"),
    )
    assert exact_notional > precise_caps.per_symbol_notional

    result = size(
        make_request(price=price_text, multiplier=price_text, lot_step="1"),
        make_policy(fixed_quantity=D("1"), hard_caps=precise_caps),
    )

    assert result.status is SizingStatus.NO_SIZE
    assert result.proposed_quantity == D("0")
    assert (
        result.exposures is None
        or result.exposures.symbol_notional <= precise_caps.per_symbol_notional
    )


def test_policy_replace_rejects_invalid_nested_hard_cap() -> None:
    policy = make_policy(fixed_quantity=D("1"))

    with pytest.raises((TypeError, ValueError)):
        replace(
            policy,
            caps=replace(policy.caps, per_symbol_notional=D("-1")),
        )


@pytest.mark.parametrize("clone", [copy.copy, copy.deepcopy], ids=["copy", "deepcopy"])
def test_policy_copy_operations_are_rejected(clone) -> None:
    policy = make_policy(fixed_quantity=D("1"))

    with pytest.raises((TypeError, ValueError)):
        clone(policy)


def test_policy_pickle_is_rejected() -> None:
    policy = make_policy(fixed_quantity=D("1"))

    with pytest.raises((TypeError, ValueError)):
        pickle.dumps(policy)

def test_canonical_hash_normalizes_equivalent_decimal_spellings() -> None:
    one_decimal = make_request(equity="1.0")
    two_decimals = make_request(equity="1.00")

    assert canonical_hash(one_decimal) == canonical_hash(two_decimals)


def test_inverse_volatility_sub_lot_target_returns_no_size_per_asset() -> None:
    gross_target = D("1.99999999999999999999999999999998")

    results = inverse_volatility_pair(gross_target)

    assert all(result.status is SizingStatus.NO_SIZE for result in results)
    assert all(result.proposed_quantity == D("0") for result in results)


@pytest.mark.parametrize(
    "gross_target",
    [
        D("1.99999999999999999999999999999998"),
        D("2"),
        D("2.00000000000000000000000000000001"),
    ],
)
def test_inverse_volatility_aggregate_never_exceeds_exact_gross_target(
    gross_target: Decimal,
) -> None:
    results = inverse_volatility_pair(gross_target)

    # Each unit notional is exactly one; compare total proposed lots directly
    # with the requested aggregate target, without context rounding.
    assert sum((result.proposed_quantity for result in results), D("0")) <= gross_target


def test_reviewer_inverse_volatility_vector_stays_below_one_lot() -> None:
    a_returns = tuple(D("-1") if index % 2 == 0 else D("1") for index in range(20))
    b_returns = tuple(
        D(value)
        for value in (1, 0, -3, -1, 3, -1, -3, -1, 1, -1, 3, -3, -3, -2, -2, -1, 2, 0, -2, 0)
    )
    return_series = (series("A", a_returns), series("B", b_returns))

    def sample_variance(values: tuple[Decimal, ...]) -> Fraction:
        exact_values = tuple(Fraction(value) for value in values)
        mean = sum(exact_values, Fraction(0)) / len(exact_values)
        return sum(((value - mean) ** 2 for value in exact_values), Fraction(0)) / (
            len(exact_values) - 1
        )

    assert sample_variance(a_returns) == Fraction(20, 19)
    assert sample_variance(b_returns) == Fraction(1371, 380)
    gross_target = D("1.540146129294635100759845304072785")
    result = size(
        make_request(
            instrument="A",
            return_series=return_series,
            price="1",
            multiplier="1",
            lot_step="1",
            lookback_count=20,
            annualization_factor="1",
        ),
        make_policy(
            SizingMode.INVERSE_VOLATILITY,
            fixed_quantity=None,
            gross_exposure_target=gross_target,
        ),
    )

    assert result.status is SizingStatus.NO_SIZE
    assert result.proposed_quantity == D("0")


def test_seeded_inverse_volatility_lot_counts_match_exact_squared_bound() -> None:
    rng = random.Random(20261004)
    alternating_signs = tuple(-1 if index % 2 == 0 else 1 for index in range(20))

    def lot_fits(
        lots: int,
        gross_target: Fraction,
        lot_step: Fraction,
        own_variance: Fraction,
        other_variance: Fraction,
    ) -> bool:
        order_notional = lots * lot_step
        if order_notional > gross_target:
            return False
        remaining_target = gross_target - order_notional
        # k*lot <= G*sigma_other/(sigma_own+sigma_other), squared exactly.
        return order_notional**2 * own_variance <= remaining_target**2 * other_variance

    for _ in range(32):
        scale_a = D(rng.randint(1, 30)) / D("10")
        scale_b = D(rng.randint(1, 30)) / D("10")
        returns_a = tuple(D(sign) * scale_a for sign in alternating_signs)
        returns_b = tuple(D(sign) * scale_b for sign in alternating_signs)
        variance_a = Fraction(20, 19) * Fraction(scale_a) ** 2
        variance_b = Fraction(20, 19) * Fraction(scale_b) ** 2
        gross_target = D(rng.randint(100, 10_000)) / D("100")
        lot_step = D("1")
        gross_fraction = Fraction(gross_target)
        lot_fraction = Fraction(lot_step)
        return_series = (series("A", returns_a), series("B", returns_b))
        policy = make_policy(
            SizingMode.INVERSE_VOLATILITY,
            fixed_quantity=None,
            gross_exposure_target=gross_target,
        )

        results = {}
        for instrument, own_variance, other_variance in (
            ("A", variance_a, variance_b),
            ("B", variance_b, variance_a),
        ):
            expected_lots = 0
            while lot_fits(
                expected_lots + 1,
                gross_fraction,
                lot_fraction,
                own_variance,
                other_variance,
            ):
                expected_lots += 1
            results[instrument] = size(
                make_request(
                    instrument=instrument,
                    return_series=return_series,
                    price="1",
                    multiplier="1",
                    lot_step=str(lot_step),
                    lookback_count=20,
                    annualization_factor="1",
                ),
                policy,
            )
            assert results[instrument].proposed_quantity == expected_lots * lot_step
            assert results[instrument].status is (
                SizingStatus.SIZE if expected_lots else SizingStatus.NO_SIZE
            )

        proposed_gross = sum(
            (Fraction(result.proposed_quantity) for result in results.values()), Fraction(0)
        )
        assert proposed_gross <= gross_fraction


def test_walsh_three_asset_erc_target_below_one_lot_returns_zero() -> None:
    patterns = tuple(
        tuple(
            D("1") if index & (1 << bit) == 0 else D("-1")
            for index in range(32)
        )
        for bit in range(4)
    )
    u, v, w, x = patterns
    a = tuple(left + right for left, right in zip(u, v, strict=True))
    b = tuple(left + right for left, right in zip(u, w, strict=True))
    c = tuple(left + right for left, right in zip(u, x, strict=True))
    vectors = (a, b, c)

    def sample_covariance(left: tuple[Decimal, ...], right: tuple[Decimal, ...]) -> Fraction:
        exact_left = tuple(Fraction(value) for value in left)
        exact_right = tuple(Fraction(value) for value in right)
        mean_left = sum(exact_left, Fraction(0)) / len(exact_left)
        mean_right = sum(exact_right, Fraction(0)) / len(exact_right)
        return sum(
            (
                (left_value - mean_left) * (right_value - mean_right)
                for left_value, right_value in zip(exact_left, exact_right, strict=True)
            ),
            Fraction(0),
        ) / (len(left) - 1)

    expected_covariance = tuple(
        tuple(Fraction(64 if row == column else 32, 31) for column in range(3))
        for row in range(3)
    )
    assert tuple(
        tuple(sample_covariance(left, right) for right in vectors) for left in vectors
    ) == expected_covariance

    gross_target = D("2.9999999999999")
    assert Fraction(gross_target) / 3 < 1
    high_caps = caps(
        per_symbol_notional=D("1000000"),
        per_sector_notional=D("1000000"),
        gross_notional=D("1000000"),
        net_notional=D("1000000"),
        max_leverage=D("1000"),
        per_trade_loss=D("1000000"),
        portfolio_heat=D("1000000"),
    )
    result = size(
        make_request(
            instrument="A",
            return_series=tuple(
                series(symbol, values) for symbol, values in zip("ABC", vectors, strict=True)
            ),
            price="1",
            multiplier="1",
            lot_step="1",
            lookback_count=32,
            annualization_factor="1",
        ),
        make_policy(
            SizingMode.RISK_PARITY,
            fixed_quantity=None,
            gross_exposure_target=gross_target,
            hard_caps=high_caps,
        ),
    )

    assert result.status is SizingStatus.NO_SIZE
    assert result.proposed_quantity == D("0")


def test_seeded_correlated_erc_lots_stay_within_exact_gross_target_bound() -> None:
    rng = random.Random(20261005)
    patterns = tuple(
        tuple(
            D("1") if index & (1 << bit) == 0 else D("-1")
            for index in range(32)
        )
        for bit in range(4)
    )
    common, factor_a, factor_b, factor_c = patterns
    high_caps = caps(
        per_symbol_notional=D("1000000"),
        per_sector_notional=D("1000000"),
        gross_notional=D("1000000"),
        net_notional=D("1000000"),
        max_leverage=D("1000"),
        per_trade_loss=D("1000000"),
        portfolio_heat=D("1000000"),
    )

    def covariance(left: tuple[Decimal, ...], right: tuple[Decimal, ...]) -> Fraction:
        left_values = tuple(Fraction(value) for value in left)
        right_values = tuple(Fraction(value) for value in right)
        mean_left = sum(left_values, Fraction(0)) / len(left_values)
        mean_right = sum(right_values, Fraction(0)) / len(right_values)
        return sum(
            (
                (left_value - mean_left) * (right_value - mean_right)
                for left_value, right_value in zip(left_values, right_values, strict=True)
            ),
            Fraction(0),
        ) / (len(left_values) - 1)

    for _ in range(16):
        loadings = tuple((rng.randint(1, 5), rng.randint(1, 5)) for _ in range(3))
        ga, sa = loadings[0]
        gb, sb = loadings[1]
        gc, sc = loadings[2]
        a_returns = tuple(
            ga * common[index] + sa * factor_a[index] for index in range(32)
        )
        b_returns = tuple(
            gb * common[index] + sb * factor_b[index] for index in range(32)
        )
        c_returns = tuple(
            gc * common[index] + sc * factor_c[index] for index in range(32)
        )
        vectors = (a_returns, b_returns, c_returns)
        covariance_matrix = tuple(
            tuple(covariance(left, right) for right in vectors) for left in vectors
        )
        assert all(covariance_matrix[i][j] > 0 for i in range(3) for j in range(3))
        return_series = tuple(
            series(symbol, values)
            for symbol, values in zip("ABC", vectors, strict=True)
        )
        gross_target = D(rng.randint(5_000, 100_000)) / D("1000")
        lot_step = D("1")
        # ERC weights are nonnegative and sum to one, so the full gross target
        # is a conservative exact upper bound for any one asset's target.
        upper_bound_lots = Fraction(gross_target) // Fraction(lot_step)
        policy = make_policy(
            SizingMode.RISK_PARITY,
            fixed_quantity=None,
            gross_exposure_target=gross_target,
            hard_caps=high_caps,
        )

        for instrument in "ABC":
            result = size(
                make_request(
                    instrument=instrument,
                    return_series=return_series,
                    price="1",
                    multiplier="1",
                    lot_step=str(lot_step),
                    lookback_count=32,
                    annualization_factor="1",
                ),
                policy,
            )
            assert Fraction(result.proposed_quantity) <= (
                upper_bound_lots * Fraction(lot_step)
            )
            assert Fraction(result.proposed_quantity) <= Fraction(gross_target)
            if result.status is SizingStatus.SIZE:
                assert result.proposed_quantity % lot_step == 0


@pytest.mark.parametrize(
    ("mode", "field", "value"),
    [
        (SizingMode.FIXED, "fixed_quantity", None),
        (SizingMode.INVERSE_VOLATILITY, "gross_exposure_target", None),
    ],
)
def test_replace_rejects_missing_mode_required_policy_fields(
    mode: SizingMode, field: str, value: Decimal | None
) -> None:
    policy = make_policy(
        mode,
        fixed_quantity=D("1") if mode is SizingMode.FIXED else None,
        gross_exposure_target=(
            D("2") if mode is SizingMode.INVERSE_VOLATILITY else None
        ),
    )

    with pytest.raises(SizingInputError):
        replace(policy, **{field: value})


def test_negative_risk_budget_is_rejected_at_construction() -> None:
    with pytest.raises(SizingInputError):
        RiskBudgetV1(instrument="A", fraction=D("-0.1"))


def test_observation_source_id_rejects_newline_at_construction() -> None:
    with pytest.raises(SizingInputError):
        ObservationV1(
            value=D("1"),
            event_ns=NOW_NS - 1_000,
            available_ns=NOW_NS - 500,
            source_id="feed\nforged",
            source_version="fixture-v1",
            validation_status="VALIDATED",
        )


def test_existing_position_heat_reduces_new_quantity_conservatively() -> None:
    position = PositionV1(
        instrument="B",
        instrument_currency="USD",
        quantity=D("3"),
        price=observation("10"),
        fx_to_account=observation("1"),
        loss_per_unit=observation("1"),
        contract_multiplier=D("1"),
        as_of_ns=NOW_NS - 1_000,
        available_ns=NOW_NS - 500,
        source_id="synthetic-positions",
        source_version="fixture-v1",
        validation_status="VALIDATED",
    )
    policy_caps = caps(portfolio_heat=D("4"))
    request = make_request(
        positions=(position,),
        loss_per_unit="1",
        lot_step="1",
    )
    policy = make_policy(fixed_quantity=D("5"), hard_caps=policy_caps)

    result = size(request, policy)

    assert result.status is SizingStatus.SIZE
    assert result.proposed_quantity == D("1")
    assert result.exposures is not None
    assert result.exposures.portfolio_heat == D("4")
    assert_within_caps(result, policy_caps)


@pytest.mark.parametrize(
    "status",
    ["GRID_VARIANT", "FAILED_OOS", "PARAMETER_ONLY"],
)
def test_unvalidated_strategy_asset_provenance_cannot_increase_sizing(
    status: str,
) -> None:
    fixture_file = Path(__file__).parent / "fixtures" / "asset_provenance_negative.json"
    entries = json.loads(fixture_file.read_text(encoding="utf-8"))
    fixture = next(item for item in entries if item["status"] == status)
    request = make_request(
        equity="1000000",
        price="1",
        kelly_estimate=KellyEstimateV1(
            win_probability=observation("0.99"),
            net_odds=observation("10"),
            window_start_ns=NOW_NS - 10_000,
            window_end_ns=NOW_NS - 1_000,
        ),
        candidate_provenance=AssetProvenanceV1(**fixture),
    )
    policy = make_policy(
        SizingMode.CAPPED_KELLY,
        fixed_quantity=None,
        fractional_kelly_factor=D("1"),
    )

    result = size(request, policy)

    assert result.status is SizingStatus.NO_SIZE
    assert result.proposed_quantity == D("0")
    assert result.unclamped_quantity == D("0")
    assert result.reasons


def test_numerical_and_asof_failures_deny_instead_of_guessing() -> None:
    policy = make_policy()
    future_price_request = make_request(price="10")
    future_price_request = replace(
        future_price_request,
        price=observation("10", available_ns=NOW_NS + 1),
    )
    failures = (
        make_request(price="0"),
        future_price_request,
        make_request(return_series=()),
        make_request(
            return_series=(
                series("A", (D("0"),) * 20),
                orthogonal_series()[1],
            )
        ),
        make_request(price="10", sector_map=()),
    )

    for request in failures:
        result = size(request, policy)
        assert result.status is SizingStatus.NO_SIZE
        assert result.proposed_quantity == D("0")
        assert result.reasons


def test_return_series_rejects_nonfinite_decimal_evidence() -> None:
    with pytest.raises(SizingInputError, match="INVALID_DECIMAL"):
        ReturnPointV1(timestamp_ns=NOW_NS - 20_000, value=D("NaN"))


def test_same_asof_replay_has_identical_canonical_result_bytes() -> None:
    request = make_request()
    policy = make_policy(fixed_quantity=D("2.5"))

    first = size(request, policy)
    second = size(request, policy)

    assert first.canonical_bytes() == second.canonical_bytes()
