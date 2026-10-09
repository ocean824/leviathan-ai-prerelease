"""Owned synthetic arithmetic checks for the pure ARB-001 kernel."""

import copy
import pickle
from dataclasses import replace
from decimal import Decimal

import pytest
from pydantic import BaseModel

from leviathan_core.defi_arb import (
    ArbInputError,
    ArbPolicyV1,
    ArbRouteV1,
    FlashLoanV1,
    ForkSnapshotV1,
    GasEvidenceV1,
    SimulationResultV1,
    SwapLegV1,
    TokenV1,
    require_simulation_result,
    simulate_route,
)
from leviathan_core.seal import SealError


def _case() -> tuple[ArbRouteV1, ArbPolicyV1, ForkSnapshotV1]:
    tokens = (
        TokenV1("synthetic", "T", 0, Decimal("1"), 0, "t-oracle"),
        TokenV1("synthetic", "U", 0, Decimal("1"), 0, "u-oracle"),
    )
    legs = (
        SwapLegV1(
            "CONSTANT_PRODUCT",
            "pool-1",
            "dex-1",
            "T",
            "U",
            100_000,
            200_000,
            10_000,
            0,
            1_900,
            0,
            "reserve-1",
        ),
        SwapLegV1(
            "CONSTANT_PRODUCT",
            "pool-2",
            "dex-2",
            "U",
            "T",
            100_000,
            100_000,
            10_000,
            0,
            1_800,
            0,
            "reserve-2",
        ),
    )
    route = ArbRouteV1(
        "route-1",
        "DEX_DEX",
        "synthetic",
        "fork-1",
        "block-1",
        0,
        500_000_000,
        FlashLoanV1("lender", "T", 1_000, Decimal("1000"), 100),
        legs,
        tokens,
        GasEvidenceV1(1, 1, "T", "gas-1"),
        "route-digest",
    )
    policy = ArbPolicyV1(
        ("synthetic",),
        ("T", "U"),
        ("dex-1", "dex-2"),
        ("lender",),
        1_000,
        1,
        1,
        Decimal("1"),
        10_000,
        10_000,
        10_000,
        Decimal("1"),
        500_000_000,
        500_000_000,
        500_000_000,
    )
    snapshot = ForkSnapshotV1("synthetic", "fork-1", "block-1", "snapshot-digest")
    return route, policy, snapshot


def test_worst_case_minimums_and_repayment_are_exact() -> None:
    route, policy, snapshot = _case()
    result = simulate_route(route, policy, snapshot, as_of_ns=500_000_000)
    assert result.status == "PASS"
    assert result.proceeds_units == 1_800
    assert result.flash_fee_units == 10
    assert result.repayment_units == 1_010
    assert result.gas_cost_value == Decimal("1")
    assert result.min_profit_value == Decimal("789")
    assert result.price_impact_bps_exact[0] == (100, 1)
    assert result.slippage_bps_exact[0] == (40_000, 99)
    assert result.oracle_deviation_bps_exact[0] == (10_000, 1)
    assert result.swap_fee_units_exact == ((0, 1), (0, 1))
    assert require_simulation_result(result) is result


def test_quote_and_block_changes_fail_closed() -> None:
    route, policy, snapshot = _case()
    assert simulate_route(route, policy, snapshot, as_of_ns=500_000_001).reason_codes == (
        "QUOTE_EXPIRED",
    )
    changed = replace(snapshot, block_hash="reorged")
    assert simulate_route(route, policy, changed, as_of_ns=0).reason_codes == ("BLOCK_MISMATCH",)


def test_no_non_atomic_or_unsupported_pool_succeeds() -> None:
    route, policy, snapshot = _case()
    assert (
        simulate_route(replace(route, mode="CEX_DEX"), policy, snapshot, as_of_ns=0).status
        == "FAIL"
    )
    legs = (replace(route.legs[0], pool_type="STABLE_SWAP"), route.legs[1])
    assert simulate_route(replace(route, legs=legs), policy, snapshot, as_of_ns=0).reason_codes == (
        "UNSUPPORTED_POOL_TYPE",
    )


def test_same_pool_cannot_be_quoted_twice_from_independent_reserves() -> None:
    route, policy, snapshot = _case()
    duplicate = replace(
        route.legs[1],
        venue_id=route.legs[0].venue_id,
        pool_id=route.legs[0].pool_id,
    )
    with pytest.raises(ArbInputError):
        replace(route, legs=(route.legs[0], duplicate))
    object.__setattr__(route, "legs", (route.legs[0], duplicate))
    assert simulate_route(route, policy, snapshot, as_of_ns=0).reason_codes == (
        "DUPLICATE_POOL",
    )


def test_each_market_metric_has_an_independent_exact_cap() -> None:
    route, policy, snapshot = _case()
    assert simulate_route(
        route, replace(policy, max_price_impact_bps=99), snapshot, as_of_ns=0
    ).reason_codes == ("PRICE_IMPACT_CAP",)
    assert simulate_route(
        route, replace(policy, max_slippage_bps=404), snapshot, as_of_ns=0
    ).reason_codes == ("SLIPPAGE_CAP",)
    assert simulate_route(
        route, replace(policy, max_oracle_deviation_bps=9_999), snapshot, as_of_ns=0
    ).reason_codes == ("ORACLE_DEVIATION",)


def test_result_cannot_be_consumed_after_tampering() -> None:
    route, policy, snapshot = _case()
    result = simulate_route(route, policy, snapshot, as_of_ns=0)
    object.__setattr__(result, "status", "FAIL")
    with pytest.raises(SealError):
        require_simulation_result(result)


def test_records_reject_copy_pickle_invalid_replace_and_issuance_reentry() -> None:
    route, policy, snapshot = _case()
    result = simulate_route(route, policy, snapshot, as_of_ns=0)
    for record in (route, policy, result):
        with pytest.raises((ArbInputError, SealError)):
            copy.copy(record)
        with pytest.raises((ArbInputError, SealError)):
            copy.deepcopy(record)
        with pytest.raises((ArbInputError, SealError)):
            pickle.dumps(record)
    with pytest.raises(ArbInputError):
        replace(policy, max_quote_age_ns=500_000_001)
    payload = result.model_dump()
    unissued = SimulationResultV1(**payload)
    with pytest.raises(SealError):
        require_simulation_result(unissued)
    with pytest.raises(SealError):
        BaseModel.__init__(result, **payload)


def test_evidence_digest_binds_each_pool_reserve_even_with_same_input_label() -> None:
    route, policy, snapshot = _case()
    baseline = simulate_route(route, policy, snapshot, as_of_ns=0)
    leg = replace(route.legs[0], reserve_out_units=199_999)
    changed_route = replace(route, legs=(leg, route.legs[1]))
    changed = simulate_route(changed_route, policy, snapshot, as_of_ns=0)
    assert baseline.evidence_digest != changed.evidence_digest
