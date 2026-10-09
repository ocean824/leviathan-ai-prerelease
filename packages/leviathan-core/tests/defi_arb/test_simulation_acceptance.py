"""Independent contract probes for the synthetic-only ARB-001 simulation."""

from __future__ import annotations

import ast
import json
import re
from dataclasses import replace
from decimal import Decimal
from pathlib import Path

import pytest

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

PACKAGE = Path(__file__).parents[2] / "src" / "leviathan_core" / "defi_arb"
FIXTURE = Path(__file__).parents[1] / "fixtures" / "defi_arb" / "synthetic_two_pool.json"
FORBIDDEN_MODULES = {
    "requests", "httpx", "urllib", "urllib3", "aiohttp", "websockets", "socket",
    "web3", "eth_account", "eth_keys", "brownie", "ape",
}
FORBIDDEN_CALLS = {
    "urlopen", "create_connection", "send_transaction", "send_raw_transaction",
    "eth_sendRawTransaction", "sign_transaction", "sign_message", "signTypedData",
    "HTTPProvider", "AsyncHTTPProvider", "WebSocketProvider",
}


def _case() -> tuple[ArbRouteV1, ArbPolicyV1, ForkSnapshotV1]:
    raw = json.loads(FIXTURE.read_text(encoding="utf-8"))
    route_data = raw["route"]
    route = ArbRouteV1(
        route_id=route_data["route_id"], mode=route_data["mode"],
        chain_id=route_data["chain_id"], snapshot_id=route_data["snapshot_id"],
        block_hash=route_data["block_hash"], quoted_at_ns=route_data["quoted_at_ns"],
        deadline_ns=route_data["deadline_ns"],
        flash_loan=FlashLoanV1(**route_data["flash_loan"]),
        legs=tuple(SwapLegV1(**leg) for leg in route_data["legs"]),
        tokens=tuple(TokenV1(**token) for token in route_data["tokens"]),
        gas=GasEvidenceV1(**route_data["gas"]), input_digest=route_data["input_digest"],
    )
    policy = ArbPolicyV1(
        **{
            **raw["policy"],
            "allowed_chains": tuple(raw["policy"]["allowed_chains"]),
            "allowed_tokens": tuple(raw["policy"]["allowed_tokens"]),
            "allowed_venues": tuple(raw["policy"]["allowed_venues"]),
            "allowed_flash_providers": tuple(raw["policy"]["allowed_flash_providers"]),
        }
    )
    return route, policy, ForkSnapshotV1(**raw["snapshot"])


def _simulate(
    route: ArbRouteV1 | None = None,
    policy: ArbPolicyV1 | None = None,
    snapshot: ForkSnapshotV1 | None = None,
    *,
    as_of_ns: int = 0,
) -> SimulationResultV1:
    base_route, base_policy, base_snapshot = _case()
    return simulate_route(
        route or base_route, policy or base_policy, snapshot or base_snapshot,
        as_of_ns=as_of_ns,
    )


def test_fixture_is_synthetic_and_constant_product_math_is_exact() -> None:
    route, _, _ = _case()
    first = route.legs[0]
    input_after_fee = route.flash_loan.principal_units * (10_000 - first.fee_bp)
    first_actual = (
        input_after_fee * first.reserve_out_units
        // (first.reserve_in_units * 10_000 + input_after_fee)
    )
    second = route.legs[1]
    second_actual = (
        first_actual * (10_000 - second.fee_bp) * second.reserve_out_units
        // (second.reserve_in_units * 10_000 + first_actual * (10_000 - second.fee_bp))
    )

    assert route.chain_id == "synthetic-chain"
    assert first_actual == 1980
    assert second_actual == 1941
    result = _simulate()
    assert result.status == "PASS"
    assert result.proceeds_units == second_actual
    assert result.confidence == "SYNTHETIC_ONLY"
    assert result.price_impact_bps_exact == ((100, 1), (6500, 33))
    assert result.slippage_bps_exact == ((0, 1), (0, 1))
    assert result.oracle_deviation_bps_exact == ((10_000, 1), (0, 1))
    assert result.swap_fee_units_exact == ((0, 1), (0, 1))


def test_flash_fee_rounds_up_and_repayment_is_principal_plus_fee() -> None:
    route, policy, _ = _case()
    loan = replace(route.flash_loan, principal_units=1001, principal=Decimal("1001"))
    result = _simulate(
        replace(route, flash_loan=loan),
        replace(policy, max_principal_units=1001),
    )
    assert result.flash_fee_units == 11
    assert result.repayment_units == 1012
    assert result.repayment_covered is True


@pytest.mark.parametrize(
    ("worst_output", "expected_profit"),
    [(1011, Decimal("0")), (1010, Decimal("-1"))],
)
def test_zero_or_negative_edge_cannot_pass(
    worst_output: int, expected_profit: Decimal,
) -> None:
    route, _, _ = _case()
    legs = (*route.legs[:-1], replace(route.legs[-1], min_output_units=worst_output))
    result = _simulate(replace(route, legs=legs))
    assert result.status == "FAIL"
    assert result.reason_codes == ("PROFIT_BELOW_THRESHOLD",)
    assert result.min_profit_value == expected_profit


def test_profit_threshold_is_strict_and_includes_all_costs() -> None:
    _, policy, _ = _case()
    baseline = _simulate()
    assert baseline.gas_cost_value == Decimal("1")
    assert baseline.min_profit_value == Decimal("930")
    assert _simulate(policy=replace(policy, min_profit_value=Decimal("930"))).reason_codes == (
        "PROFIT_BELOW_THRESHOLD",
    )
    assert _simulate(policy=replace(policy, min_profit_value=Decimal("929"))).status == "PASS"


def test_repayment_shortfall_fails_closed() -> None:
    route, _, _ = _case()
    legs = (*route.legs[:-1], replace(route.legs[-1], min_output_units=1000))
    result = _simulate(replace(route, legs=legs))
    assert result.status == "FAIL"
    assert result.reason_codes == ("MISSING_REPAYMENT",)
    assert result.repayment_covered is False


def test_gas_cost_uses_token_decimals_and_oracle_value() -> None:
    route, _, _ = _case()
    tokens = tuple(replace(token, decimals=2, oracle_price=Decimal("2")) for token in route.tokens)
    loan = replace(route.flash_loan, principal=Decimal("10"))
    gas = replace(route.gas, gas_units=5, max_fee_per_gas_units=3)
    # Gas is 15 smallest units / 100 * 2 price = exactly 0.3 value.
    _, policy, _ = _case()
    policy = replace(policy, max_gas_units=5, max_fee_per_gas_units=3)
    result = _simulate(replace(route, tokens=tokens, flash_loan=loan, gas=gas), policy)
    assert result.gas_cost_value == Decimal("0.3")


@pytest.mark.parametrize(
    ("gas_units", "fee_units"), [(3, 1), (1, 3)],
)
def test_gas_unit_and_max_fee_caps(gas_units: int, fee_units: int) -> None:
    route, _, _ = _case()
    result = _simulate(replace(route, gas=replace(
        route.gas, gas_units=gas_units, max_fee_per_gas_units=fee_units,
    )))
    assert result.status == "FAIL"
    assert result.reason_codes == ("GAS_CAP",)


def test_gas_cost_value_cap_and_principal_cap() -> None:
    _, policy, _ = _case()
    assert _simulate(policy=replace(policy, max_gas_cost_value=Decimal("0.99"))).reason_codes == (
        "GAS_CAP",
    )
    assert _simulate(policy=replace(policy, max_principal_units=999)).reason_codes == (
        "PRINCIPAL_CAP",
    )


def test_each_leg_enforces_its_input_liquidity_limit() -> None:
    route, _, _ = _case()
    legs = (*route.legs[:-1], replace(route.legs[-1], max_input_units=1000))
    result = _simulate(replace(route, legs=legs))
    assert result.reason_codes == ("INSUFFICIENT_LIQUIDITY",)


def test_slippage_is_reported_as_an_exact_ratio_and_capped() -> None:
    route, policy, _ = _case()
    token_b = replace(route.tokens[1], oracle_price=Decimal("0.5"))
    tokens = (route.tokens[0], token_b)
    result = _simulate(replace(route, tokens=tokens))
    assert result.slippage_bps_exact == ((0, 1), (0, 1))
    assert result.price_impact_bps_exact == ((100, 1), (6500, 33))
    assert result.oracle_deviation_bps_exact == ((0, 1), (10_000, 1))

    first = replace(route.legs[0], min_output_units=1960)
    second = replace(route.legs[1], min_output_units=1900)
    quoted = replace(route, legs=(first, second))
    assert _simulate(quoted).slippage_bps_exact == ((10_000, 99), (110_000, 961))
    strict = replace(policy, max_slippage_bps=10)
    failure = _simulate(quoted, strict)
    assert failure.reason_codes == ("SLIPPAGE_CAP",)
    assert failure.slippage_bps_exact[0] == (10_000, 99)


def test_price_impact_has_its_own_exact_bound() -> None:
    _, policy, _ = _case()
    strict = replace(policy, max_price_impact_bps=99)
    assert _simulate(policy=strict).reason_codes == ("PRICE_IMPACT_CAP",)


def test_swap_fee_is_reported_as_an_exact_input_unit_ratio() -> None:
    route, _, _ = _case()
    first = replace(route.legs[0], fee_bp=1, min_output_units=1979)
    second = replace(route.legs[1], min_output_units=1940)
    changed = replace(route, legs=(first, second))
    result = _simulate(changed)
    assert result.swap_fee_units_exact == ((1, 10), (0, 1))


def test_oracle_deviation_is_reported_exactly_and_capped() -> None:
    _, policy, _ = _case()
    result = _simulate()
    assert result.oracle_deviation_bps_exact[0] == (10_000, 1)
    strict = replace(policy, max_oracle_deviation_bps=9_999)
    assert _simulate(policy=strict).reason_codes == ("ORACLE_DEVIATION",)


def test_reserve_and_oracle_freshness_boundaries() -> None:
    _, policy, _ = _case()
    assert _simulate(as_of_ns=500_000_000).status == "PASS"
    stale_reserve = replace(policy, max_reserve_age_ns=499_999_999)
    assert _simulate(policy=stale_reserve, as_of_ns=500_000_000).reason_codes == (
        "STALE_RESERVE",
    )
    stale_oracle = replace(policy, max_oracle_age_ns=499_999_999)
    assert _simulate(policy=stale_oracle, as_of_ns=500_000_000).reason_codes == (
        "STALE_ORACLE",
    )


def test_quote_is_valid_at_500ms_and_expired_afterward() -> None:
    assert _simulate(as_of_ns=500_000_000).status == "PASS"
    assert _simulate(as_of_ns=500_000_001).reason_codes == ("QUOTE_EXPIRED",)


@pytest.mark.parametrize(
    ("replacement", "reason"),
    [
        ({"block_hash": "changed-block"}, "BLOCK_MISMATCH"),
        ({"snapshot_id": "other-snapshot"}, "BLOCK_MISMATCH"),
        ({"chain_id": "other-chain"}, "UNSUPPORTED_CHAIN"),
    ],
)
def test_changed_fork_identity_invalidates_result(
    replacement: dict[str, str], reason: str,
) -> None:
    _, _, snapshot = _case()
    assert _simulate(snapshot=replace(snapshot, **replacement)).reason_codes == (reason,)


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"mode": "CEX_DEX"}, "CEX_DEX_BLOCKED"),
        ({"chain_id": "other-chain"}, "UNSUPPORTED_CHAIN"),
        (
            {"legs": (
                replace(_case()[0].legs[0], venue_id="unknown"),
                _case()[0].legs[1],
            )},
            "UNSUPPORTED_VENUE",
        ),
        (
            {"legs": (
                replace(_case()[0].legs[0], pool_type="UNSUPPORTED"),
                _case()[0].legs[1],
            )},
            "UNSUPPORTED_POOL_TYPE",
        ),
    ],
)
def test_only_allowlisted_dex_dex_constant_product_routes_are_evaluated(
    changes: dict[str, object], reason: str,
) -> None:
    route, _, _ = _case()
    assert _simulate(replace(route, **changes)).reason_codes == (reason,)  # type: ignore[arg-type]


def test_unsupported_provider_and_token_are_rejected() -> None:
    route, _, _ = _case()
    provider = replace(route.flash_loan, provider_id="unknown-lender")
    assert _simulate(replace(route, flash_loan=provider)).reason_codes == (
        "UNSUPPORTED_FLASH_PROVIDER",
    )
    unsupported = replace(route.tokens[1], token_id="UNKNOWN")
    first, second = route.legs
    changed = replace(route, tokens=(route.tokens[0], unsupported), legs=(
        replace(first, token_out="UNKNOWN"), replace(second, token_in="UNKNOWN"),
    ))
    assert _simulate(changed).reason_codes == (
        "UNSUPPORTED_TOKEN",
    )


def test_reusing_the_same_venue_pool_selector_cannot_pass() -> None:
    route, _, _ = _case()
    repeated_pool = replace(
        route.legs[1],
        venue_id=route.legs[0].venue_id,
        pool_id=route.legs[0].pool_id,
    )

    try:
        duplicate_route = replace(route, legs=(route.legs[0], repeated_pool))
    except ArbInputError:
        return

    assert _simulate(duplicate_route).status == "FAIL"


def test_principal_must_equal_exact_token_units_and_decimal_inputs_reject_float() -> None:
    route, _, _ = _case()
    loan = replace(route.flash_loan, principal=Decimal("1000.1"))
    assert _simulate(replace(route, flash_loan=loan)).reason_codes == ("PRINCIPAL_MISMATCH",)
    with pytest.raises(ArbInputError):
        TokenV1("synthetic-chain", "FLOAT-TOKEN", 0, 1.0, 0, "oracle-float")  # type: ignore[arg-type]
    with pytest.raises(ArbInputError):
        FlashLoanV1("lender", "TOKEN-A", 1, 1.0, 0)  # type: ignore[arg-type]


@pytest.mark.parametrize("bad", [Decimal("NaN"), Decimal("Infinity"), Decimal("-Infinity")])
def test_nonfinite_oracle_and_principal_inputs_are_rejected(bad: Decimal) -> None:
    with pytest.raises(ArbInputError):
        TokenV1("synthetic-chain", "BAD", 0, bad, 0, "bad-oracle")
    with pytest.raises(ArbInputError):
        FlashLoanV1("lender", "TOKEN-A", 1, bad, 0)


def test_policy_requires_explicit_operator_caps() -> None:
    raw = json.loads(FIXTURE.read_text(encoding="utf-8"))["policy"]
    del raw["max_slippage_bps"]
    with pytest.raises(TypeError):
        ArbPolicyV1(
            **{
                **raw,
                "allowed_chains": ("synthetic-chain",),
                "allowed_tokens": ("TOKEN-A", "TOKEN-B"),
                "allowed_venues": ("fixture-dex-a", "fixture-dex-b"),
                "allowed_flash_providers": ("fixture-lender",),
            }
        )


def test_result_is_sealed_and_not_authority_to_activate_or_broadcast() -> None:
    result = _simulate()
    assert require_simulation_result(result) is result
    with pytest.raises(SealError):
        result.status = "LIVE"  # type: ignore[misc]
    object.__setattr__(result, "status", "LIVE")
    with pytest.raises(SealError):
        require_simulation_result(result)


def test_kernel_has_no_rpc_network_signer_or_key_imports_or_calls() -> None:
    forbidden_imports: list[str] = []
    forbidden_calls: list[str] = []
    for path in sorted(PACKAGE.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                forbidden_imports.extend(
                    alias.name.split(".")[0]
                    for alias in node.names
                    if alias.name.split(".")[0] in FORBIDDEN_MODULES
                )
            elif isinstance(node, ast.ImportFrom):
                module = (node.module or "").split(".")[0]
                if module in FORBIDDEN_MODULES:
                    forbidden_imports.append(module)
            elif isinstance(node, ast.Call):
                name = node.func.id if isinstance(node.func, ast.Name) else (
                    node.func.attr if isinstance(node.func, ast.Attribute) else ""
                )
                if name in FORBIDDEN_CALLS:
                    forbidden_calls.append(name)
    assert forbidden_imports == []
    assert forbidden_calls == []


def test_no_public_mempool_or_submission_option_is_in_the_route_api() -> None:
    fields = set(ArbRouteV1.__dataclass_fields__)
    assert not any(
        re.search(r"mempool|broadcast|sign|private.?key|submit", field, re.I)
        for field in fields
    )
