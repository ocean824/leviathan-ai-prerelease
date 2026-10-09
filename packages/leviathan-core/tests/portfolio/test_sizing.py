"""Writer unit tests for the pure sizing arithmetic and denial boundaries."""

from dataclasses import replace
from decimal import ROUND_DOWN, Decimal

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
    SizingInputError,
    SizingMode,
    SizingPolicyV1,
    SizingRequestV1,
    SizingStatus,
    size,
)

D = Decimal


def observation(value: str, *, event_ns: int = 100) -> ObservationV1:
    return ObservationV1(D(value), event_ns, event_ns, "fixture", "v1", "VALIDATED")


def sector(instrument: str, label: str = "tech") -> SectorEntryV1:
    return SectorEntryV1(instrument, label, 100, 100, "fixture", "v1", "VALIDATED")


def series(instrument: str, values: tuple[str, ...]) -> ReturnSeriesV1:
    return ReturnSeriesV1(
        instrument,
        100,
        100,
        tuple(ReturnPointV1(index + 1, D(value)) for index, value in enumerate(values)),
        "fixture",
        "v1",
        "VALIDATED",
    )


def request(**changes: object) -> SizingRequestV1:
    base = SizingRequestV1(
        tenant_id="tenant",
        strategy_revision_hash="strategy-v1",
        portfolio_revision_hash="portfolio-v1",
        instrument="A",
        side="BUY",
        instrument_currency="USD",
        account_currency="USD",
        evaluation_ns=100,
        equity=observation("10000"),
        positions=(),
        sector_map=(sector("A"),),
        price=observation("100"),
        fx_to_account=observation("1"),
        return_series=(series("A", tuple("1" if i % 2 else "-1" for i in range(20))),),
        kelly_estimate=None,
        worst_case_loss_per_unit=observation("10"),
        contract_multiplier=D(1),
        lot_step=D(1),
        min_notional=D(100),
        lookback_count=20,
        annualization_factor=D(1),
        risk_rail_policy_digest="risk-v1",
        candidate_provenance=None,
    )
    return replace(base, **changes)


def policy(**changes: object) -> SizingPolicyV1:
    base = SizingPolicyV1(
        mode=SizingMode.FIXED,
        fixed_quantity=D(10),
        risk_budget_fractions=(),
        fractional_kelly_factor=None,
        gross_exposure_target=None,
        caps=HardCapsV1(D(300), D(500), D(1000), D(1000), D(1), D(100), D(100)),
        max_age_ns=10,
        policy_digest="risk-v1",
    )
    return replace(base, **changes)


def test_fixed_clamps_to_hard_cap_then_floors_lot() -> None:
    result = size(request(lot_step=D("0.7")), policy())
    assert result.status == SizingStatus.SIZE
    assert result.unclamped_quantity == D(10)
    assert result.proposed_quantity == D("2.8")
    assert result.exposures is not None
    assert result.exposures.symbol_notional == D(280)
    assert result.cap_hits[0].code == "PER_SYMBOL_NOTIONAL"
    assert result.cap_hits[0].unclamped_quantity == D(10)
    assert result.formula_version == "PORT-FORMULA-v1"
    assert result.canonical_bytes() == size(request(lot_step=D("0.7")), policy()).canonical_bytes()


def test_unrepresentable_exact_notional_denies_with_precision_code() -> None:
    near_one = "1." + "0" * 32 + "1"
    cap = "1." + "0" * 32 + "2"
    hard_caps = replace(policy().caps, per_symbol_notional=D(cap))
    candidate = request(
        price=observation(near_one),
        contract_multiplier=D(near_one),
        min_notional=D(0),
    )

    result = size(candidate, policy(fixed_quantity=D(1), caps=hard_caps))
    assert result.status == SizingStatus.NO_SIZE
    assert result.reasons == ("PRECISION_EXCEEDED",)
    assert result.exposures is None


def test_missing_fx_and_future_sector_fail_closed() -> None:
    assert size(request(fx_to_account=None), policy()).reasons == ("MISSING_EVIDENCE",)
    future = replace(sector("A"), available_ns=101)
    assert size(request(sector_map=(future,)), policy()).reasons == (
        "FUTURE_OR_CONFLICTING_EVIDENCE",
    )


def test_reduce_can_cure_existing_symbol_breach() -> None:
    position = PositionV1(
        "A",
        "USD",
        D(5),
        observation("100"),
        observation("1"),
        observation("10"),
        D(1),
        100,
        100,
        "fixture",
        "v1",
        "VALIDATED",
    )
    result = size(
        request(side="SELL", positions=(position,)),
        policy(fixed_quantity=D(2)),
    )
    assert result.status == SizingStatus.SIZE
    assert result.proposed_quantity == D(2)
    assert result.exposures is not None
    assert result.exposures.symbol_notional == D(300)
    assert result.exposures.projected_worst_case_loss == D(0)


def test_short_close_and_multi_position_heat_cap() -> None:
    short = PositionV1(
        "A",
        "USD",
        D(-2),
        observation("100"),
        observation("1"),
        observation("10"),
        D(1),
        100,
        100,
        "fixture",
        "v1",
        "VALIDATED",
    )
    close = size(
        request(positions=(short,)),
        policy(fixed_quantity=D(2), caps=replace(policy().caps, per_symbol_notional=D(0))),
    )
    assert close.status == SizingStatus.SIZE
    assert close.exposures is not None
    assert close.exposures.symbol_notional == close.exposures.projected_worst_case_loss == D(0)

    other = replace(short, instrument="B", quantity=D(2))
    caps = replace(policy().caps, per_sector_notional=D(250), portfolio_heat=D(25))
    crowded = size(
        request(
            positions=(other,),
            sector_map=(sector("A"), sector("B")),
            lot_step=D("0.1"),
            min_notional=D(50),
        ),
        policy(caps=caps),
    )
    assert crowded.status == SizingStatus.SIZE
    assert crowded.proposed_quantity == D("0.5")
    assert crowded.exposures is not None
    assert crowded.exposures.sector_notional == D(250)
    assert crowded.exposures.portfolio_heat == D(25)


def test_exact_lot_and_min_notional_boundary() -> None:
    exact = size(request(), policy(fixed_quantity=D(1)))
    assert exact.status == SizingStatus.SIZE
    below = size(request(min_notional=D(101)), policy(fixed_quantity=D(1)))
    assert below.status == SizingStatus.NO_SIZE
    assert below.reasons == ("BELOW_MIN_NOTIONAL",)


def test_zero_feasible_size_retains_cap_hit_audit() -> None:
    denied = size(request(), policy(caps=replace(policy().caps, per_symbol_notional=D(0))))
    assert denied.status == SizingStatus.NO_SIZE
    assert denied.reasons == ("HARD_CAP_NO_FEASIBLE_LOT",)
    assert denied.cap_hits[0].code == "PER_SYMBOL_NOTIONAL"
    assert denied.cap_hits[0].unclamped_quantity == D(10)
    assert denied.cap_hits[0].clamped_quantity == D(0)


def test_kelly_zero_edge_and_unvalidated_asset_are_denied() -> None:
    estimate = KellyEstimateV1(observation("0.5"), observation("1"), 1, 100)
    kelly = policy(
        mode=SizingMode.CAPPED_KELLY, fixed_quantity=None, fractional_kelly_factor=D("0.5")
    )
    assert size(request(kelly_estimate=estimate), kelly).reasons == ("ZERO_PROPOSAL",)
    for status in ("GRID_VARIANT", "FAILED_OOS", "PARAMETER_ONLY"):
        denied = size(request(candidate_provenance=AssetProvenanceV1("MTR", status)), policy())
        assert denied.reasons == ("UNVALIDATED_ASSET_INPUT",)


def test_annualized_sample_volatility_controls_budgeted_quantity() -> None:
    alternating = tuple("0.01" if i % 2 else "-0.01" for i in range(20))
    budget = policy(
        mode=SizingMode.VOLATILITY_SCALED,
        fixed_quantity=None,
        risk_budget_fractions=(RiskBudgetV1("A", D("0.1")),),
        caps=HardCapsV1(*(D(100000) for _ in range(7))),
    )
    result = size(
        request(
            return_series=(series("A", alternating),),
            lookback_count=20,
            annualization_factor=D(252),
        ),
        budget,
    )
    sigma = (D(20) * D("0.01") ** 2 / D(19) * D(252)).sqrt()
    expected = (D(10000) * D("0.1") / sigma / D(100)).to_integral_value(rounding=ROUND_DOWN)
    assert result.status == SizingStatus.SIZE
    assert result.proposed_quantity == expected


def test_risk_parity_two_uncorrelated_series_is_permutation_stable() -> None:
    a = series("A", tuple("1" if i % 2 else "-1" for i in range(20)))
    b = series("B", tuple("2" if i % 4 < 2 else "-2" for i in range(20)))
    rules = policy(
        mode=SizingMode.RISK_PARITY,
        fixed_quantity=None,
        gross_exposure_target=D(9000),
        caps=HardCapsV1(*(D(100000) for _ in range(7))),
    )
    base = request(return_series=(a, b), lookback_count=20, annualization_factor=D(1))
    one = size(base, rules)
    two = size(replace(base, return_series=(b, a)), rules)
    assert one.status == two.status == SizingStatus.SIZE
    assert one.proposed_quantity == two.proposed_quantity
    assert one.proposed_quantity == D(60)


def test_three_asset_correlated_reference_and_nonconvergence() -> None:
    n = 24
    u = [D(1) if i % 2 else D(-1) for i in range(n)]
    v = [D(1) if i % 4 < 2 else D(-1) for i in range(n)]
    w = [D(1) if i % 8 < 4 else D(-1) for i in range(n)]
    correlated = (
        series("A", tuple(str(x) for x in u)),
        series("B", tuple(str(u[i] + v[i]) for i in range(n))),
        series("C", tuple(str(u[i] + v[i] + w[i]) for i in range(n))),
    )
    rules = policy(
        mode=SizingMode.RISK_PARITY,
        fixed_quantity=None,
        gross_exposure_target=D(9000),
        caps=HardCapsV1(*(D(100000) for _ in range(7))),
    )
    base = request(return_series=correlated, lookback_count=n, annualization_factor=D(1))
    result = size(base, rules)
    assert result.status == SizingStatus.SIZE
    assert result.proposed_quantity == D(40)
    # A=u, B=u+v, C=u+v+w. Orthogonal basis u/v/w yields
    # sample covariance (24/23) * [[1,1,1],[1,2,2],[1,2,3]].
    near_offset = D("0.1")
    slow = (
        correlated[0],
        series("B", tuple(str(-u[i] + near_offset * v[i]) for i in range(n))),
        series("C", tuple(str(v[i] + near_offset * w[i]) for i in range(n))),
    )
    denied = size(replace(base, return_series=slow), rules)
    assert denied.status == SizingStatus.NO_SIZE
    assert denied.reasons == ("SOLVER_NOT_CONVERGED",)


def test_misaligned_or_float_returns_are_denied() -> None:
    a = series("A", tuple("0.01" if i % 2 else "-0.01" for i in range(20)))
    b = replace(a, instrument="B", points=a.points[:-1])
    rules = policy(mode=SizingMode.RISK_PARITY, fixed_quantity=None, gross_exposure_target=D(1000))
    assert size(
        request(return_series=(a, b), lookback_count=20, annualization_factor=D(1)), rules
    ).reasons == ("RETURNS_MISALIGNED",)
    with pytest.raises(SizingInputError, match="INVALID_FIELD_TYPE"):
        replace(a.points[0], value=0.01)


def test_zero_variance_and_collinear_covariance_boundaries() -> None:
    a_values = tuple("1" if i % 2 else "-1" for i in range(20))
    a = series("A", a_values)
    b = series("B", tuple(str(D(value) * D(2)) for value in a_values))
    parity = policy(
        mode=SizingMode.RISK_PARITY,
        fixed_quantity=None,
        gross_exposure_target=D(1000),
    )
    paired = request(return_series=(a, b))
    assert size(paired, parity).reasons == ("COVARIANCE_SINGULAR",)
    volatility = policy(
        mode=SizingMode.VOLATILITY_SCALED,
        fixed_quantity=None,
        risk_budget_fractions=(RiskBudgetV1("A", D("0.2")), RiskBudgetV1("B", D("0.2"))),
    )
    assert size(paired, volatility).status == SizingStatus.SIZE
    zero = series("A", ("0",) * 20)
    assert size(request(return_series=(zero,)), policy()).reasons == ("NONPOSITIVE_VOLATILITY",)
