"""Pure, offline constant-product route simulation over supplied synthetic evidence."""

from __future__ import annotations

from fractions import Fraction

from leviathan_core.numeric import NumericError, parse_int, quotient_final
from leviathan_core.seal import Issuer, SealError, digest, require

from .models import (
    ArbInputError,
    ArbPolicyV1,
    ArbRouteV1,
    ForkSnapshotV1,
    SimulationResultV1,
    TokenV1,
)

_ISSUER = Issuer("arb001.simulation.v1")
_MAX_NS = (1 << 63) - 1
_MAX_QUOTE_AGE_NS = 500_000_000


def _pair(value: Fraction) -> tuple[int, int]:
    return value.numerator, value.denominator


def _issue(
    *,
    status: str,
    reason: str,
    evidence_digest: str,
    proceeds_units: int = 0,
    repayment_units: int = 0,
    flash_fee_units: int = 0,
    gas_cost: Fraction = Fraction(0),
    profit: Fraction = Fraction(0),
    price_impact: tuple[tuple[int, int], ...] = (),
    slippage: tuple[tuple[int, int], ...] = (),
    deviation: tuple[tuple[int, int], ...] = (),
    swap_fees: tuple[tuple[int, int], ...] = (),
) -> SimulationResultV1:
    gas_display = quotient_final(gas_cost.numerator, gas_cost.denominator)
    profit_display = quotient_final(profit.numerator, profit.denominator)
    return _ISSUER.issue(
        SimulationResultV1(
            status=status,
            reason_codes=(reason,),
            proceeds_units=proceeds_units,
            repayment_units=repayment_units,
            repayment_covered=proceeds_units >= repayment_units and repayment_units > 0,
            flash_fee_units=flash_fee_units,
            gas_cost_value=gas_display,
            min_profit_value=profit_display,
            price_impact_bps_exact=price_impact,
            slippage_bps_exact=slippage,
            oracle_deviation_bps_exact=deviation,
            swap_fee_units_exact=swap_fees,
            confidence="SYNTHETIC_ONLY" if status == "PASS" else "INVALID",
            evidence_digest=evidence_digest,
        )
    )


def _fail(
    code: str,
    evidence_digest: str,
    *,
    proceeds_units: int = 0,
    repayment_units: int = 0,
    flash_fee_units: int = 0,
    gas_cost: Fraction = Fraction(0),
    profit: Fraction = Fraction(0),
    price_impact: tuple[tuple[int, int], ...] = (),
    slippage: tuple[tuple[int, int], ...] = (),
    deviation: tuple[tuple[int, int], ...] = (),
    swap_fees: tuple[tuple[int, int], ...] = (),
) -> SimulationResultV1:
    return _issue(
        status="FAIL",
        reason=code,
        evidence_digest=evidence_digest,
        proceeds_units=proceeds_units,
        repayment_units=repayment_units,
        flash_fee_units=flash_fee_units,
        gas_cost=gas_cost,
        profit=profit,
        price_impact=price_impact,
        slippage=slippage,
        deviation=deviation,
        swap_fees=swap_fees,
    )


def _token_map(route: ArbRouteV1, policy: ArbPolicyV1, as_of_ns: int) -> dict[str, TokenV1]:
    tokens: dict[str, TokenV1] = {}
    for token in route.tokens:
        if type(token) is not TokenV1:
            raise ArbInputError("INVALID_ROUTE")
        token.__post_init__()
        if token.chain_id != route.chain_id or token.token_id not in policy.allowed_tokens:
            raise ArbInputError("UNSUPPORTED_TOKEN")
        if (
            token.oracle_as_of_ns > as_of_ns
            or as_of_ns - token.oracle_as_of_ns > policy.max_oracle_age_ns
        ):
            raise ArbInputError("STALE_ORACLE")
        if token.token_id in tokens:
            raise ArbInputError("INVALID_ROUTE")
        tokens[token.token_id] = token
    return tokens


def _simulate(
    route: ArbRouteV1,
    policy: ArbPolicyV1,
    snapshot: ForkSnapshotV1,
    as_of_ns: int,
    evidence_digest: str,
) -> SimulationResultV1:
    if route.mode != "DEX_DEX":
        return _fail("CEX_DEX_BLOCKED", evidence_digest)
    if route.chain_id not in policy.allowed_chains or snapshot.chain_id != route.chain_id:
        return _fail("UNSUPPORTED_CHAIN", evidence_digest)
    if route.snapshot_id != snapshot.snapshot_id or route.block_hash != snapshot.block_hash:
        return _fail("BLOCK_MISMATCH", evidence_digest)
    if as_of_ns < route.quoted_at_ns or as_of_ns > route.deadline_ns:
        return _fail("QUOTE_EXPIRED", evidence_digest)
    if as_of_ns - route.quoted_at_ns > min(policy.max_quote_age_ns, _MAX_QUOTE_AGE_NS):
        return _fail("QUOTE_EXPIRED", evidence_digest)
    if route.flash_loan.provider_id not in policy.allowed_flash_providers:
        return _fail("UNSUPPORTED_FLASH_PROVIDER", evidence_digest)
    if route.flash_loan.principal_units > policy.max_principal_units:
        return _fail("PRINCIPAL_CAP", evidence_digest)
    if (
        route.gas.gas_units > policy.max_gas_units
        or route.gas.max_fee_per_gas_units > policy.max_fee_per_gas_units
    ):
        return _fail("GAS_CAP", evidence_digest)

    tokens = _token_map(route, policy, as_of_ns)
    loan_token = tokens.get(route.flash_loan.token_id)
    gas_token = tokens.get(route.gas.native_token_id)
    if loan_token is None or gas_token is None:
        return _fail("UNSUPPORTED_TOKEN", evidence_digest)
    if Fraction(route.flash_loan.principal) != Fraction(
        route.flash_loan.principal_units, 10**loan_token.decimals
    ):
        return _fail("PRINCIPAL_MISMATCH", evidence_digest)
    gas_cost = Fraction(
        route.gas.gas_units * route.gas.max_fee_per_gas_units, 10**gas_token.decimals
    ) * Fraction(gas_token.oracle_price)
    if gas_cost > Fraction(policy.max_gas_cost_value):
        return _fail("GAS_CAP", evidence_digest, gas_cost=gas_cost)

    amount = route.flash_loan.principal_units
    current_token = route.flash_loan.token_id
    slippage: list[tuple[int, int]] = []
    deviation: list[tuple[int, int]] = []
    price_impact: list[tuple[int, int]] = []
    swap_fees: list[tuple[int, int]] = []
    for leg in route.legs:
        if leg.pool_type != "CONSTANT_PRODUCT":
            return _fail("UNSUPPORTED_POOL_TYPE", evidence_digest)
        if leg.venue_id not in policy.allowed_venues:
            return _fail("UNSUPPORTED_VENUE", evidence_digest)
        if (
            leg.reserve_as_of_ns > as_of_ns
            or as_of_ns - leg.reserve_as_of_ns > policy.max_reserve_age_ns
        ):
            return _fail("STALE_RESERVE", evidence_digest)
        if (
            leg.token_in != current_token
            or leg.token_out not in tokens
            or leg.token_in == leg.token_out
        ):
            return _fail("INVALID_ROUTE", evidence_digest)
        if amount > leg.max_input_units:
            return _fail("INSUFFICIENT_LIQUIDITY", evidence_digest)
        input_token = tokens[leg.token_in]
        output_token = tokens[leg.token_out]
        amount_after_fee = amount * (10_000 - leg.fee_bp)
        actual_out = (
            amount_after_fee
            * leg.reserve_out_units
            // (leg.reserve_in_units * 10_000 + amount_after_fee)
        )
        if (
            actual_out <= 0
            or actual_out >= leg.reserve_out_units
            or leg.min_output_units > actual_out
        ):
            return _fail("INSUFFICIENT_LIQUIDITY", evidence_digest)
        # The explicit per-leg minimum is the worst-case output supplied to the next leg.
        worst_out = leg.min_output_units
        oracle_ideal = (
            Fraction(amount, 10**input_token.decimals)
            * Fraction(input_token.oracle_price)
            / Fraction(output_token.oracle_price)
            * (10**output_token.decimals)
        )
        if oracle_ideal <= 0:
            return _fail("INVALID_ORACLE", evidence_digest)
        spot_out = Fraction(amount * leg.reserve_out_units, leg.reserve_in_units)
        impact_bp = (spot_out - actual_out) * 10_000 / spot_out
        slippage_bp = Fraction(actual_out - worst_out, actual_out) * 10_000
        deviation_bp = abs(spot_out - oracle_ideal) * 10_000 / oracle_ideal
        price_impact.append(_pair(impact_bp))
        slippage.append(_pair(slippage_bp))
        deviation.append(_pair(deviation_bp))
        swap_fees.append(_pair(Fraction(amount * leg.fee_bp, 10_000)))
        if impact_bp > policy.max_price_impact_bps:
            return _fail(
                "PRICE_IMPACT_CAP",
                evidence_digest,
                price_impact=tuple(price_impact),
                slippage=tuple(slippage),
                deviation=tuple(deviation),
                swap_fees=tuple(swap_fees),
            )
        if slippage_bp > policy.max_slippage_bps:
            return _fail(
                "SLIPPAGE_CAP",
                evidence_digest,
                price_impact=tuple(price_impact),
                slippage=tuple(slippage),
                deviation=tuple(deviation),
                swap_fees=tuple(swap_fees),
            )
        if deviation_bp > policy.max_oracle_deviation_bps:
            return _fail(
                "ORACLE_DEVIATION",
                evidence_digest,
                price_impact=tuple(price_impact),
                slippage=tuple(slippage),
                deviation=tuple(deviation),
                swap_fees=tuple(swap_fees),
            )
        amount = worst_out
        current_token = leg.token_out

    if current_token != route.flash_loan.token_id:
        return _fail("MISSING_REPAYMENT", evidence_digest)
    flash_fee = (route.flash_loan.principal_units * route.flash_loan.fee_bp + 9_999) // 10_000
    repayment = route.flash_loan.principal_units + flash_fee
    if amount < repayment:
        return _fail(
            "MISSING_REPAYMENT",
            evidence_digest,
            proceeds_units=amount,
            repayment_units=repayment,
            flash_fee_units=flash_fee,
            gas_cost=gas_cost,
            price_impact=tuple(price_impact),
            slippage=tuple(slippage),
            deviation=tuple(deviation),
            swap_fees=tuple(swap_fees),
        )
    profit = (
        Fraction(amount - repayment, 10**loan_token.decimals) * Fraction(loan_token.oracle_price)
        - gas_cost
    )
    if profit <= Fraction(policy.min_profit_value):
        return _fail(
            "PROFIT_BELOW_THRESHOLD",
            evidence_digest,
            proceeds_units=amount,
            repayment_units=repayment,
            flash_fee_units=flash_fee,
            gas_cost=gas_cost,
            profit=profit,
            price_impact=tuple(price_impact),
            slippage=tuple(slippage),
            deviation=tuple(deviation),
            swap_fees=tuple(swap_fees),
        )
    return _issue(
        status="PASS",
        reason="WITHIN_SYNTHETIC_LIMITS",
        evidence_digest=evidence_digest,
        proceeds_units=amount,
        repayment_units=repayment,
        flash_fee_units=flash_fee,
        gas_cost=gas_cost,
        profit=profit,
        price_impact=tuple(price_impact),
        slippage=tuple(slippage),
        deviation=tuple(deviation),
        swap_fees=tuple(swap_fees),
    )


def simulate_route(
    route: ArbRouteV1,
    policy: ArbPolicyV1,
    snapshot: ForkSnapshotV1,
    *,
    as_of_ns: int,
) -> SimulationResultV1:
    """Assess an offline fixture only; a PASS never authorizes activation or broadcast."""
    if (
        type(route) is not ArbRouteV1
        or type(policy) is not ArbPolicyV1
        or type(snapshot) is not ForkSnapshotV1
    ):
        raise ArbInputError("INVALID_INPUT")
    try:
        now = parse_int(as_of_ns, field="as_of_ns", min_value=0, max_value=_MAX_NS)
        route.__post_init__()
        policy.__post_init__()
        snapshot.__post_init__()
        evidence_digest = digest((route, policy, snapshot, now))
        result = _simulate(route, policy, snapshot, now, evidence_digest)
        if digest((route, policy, snapshot, now)) != evidence_digest:
            return _fail("EVIDENCE_CHANGED", digest((route, policy, snapshot, now)))
        return result
    except (ArbInputError, NumericError, SealError) as exc:
        # Digest the complete supported input tree even when a field is semantically invalid.
        try:
            evidence_digest = digest((route, policy, snapshot, as_of_ns))
        except (NumericError, SealError):
            raise ArbInputError("INVALID_INPUT") from None
        code = exc.code if isinstance(exc, ArbInputError) else "INVALID_NUMERIC"
        return _fail(code, evidence_digest)


def require_simulation_result(result: SimulationResultV1) -> SimulationResultV1:
    """Consume only an unchanged result issued by this kernel."""
    if type(result) is not SimulationResultV1:
        raise ArbInputError("INVALID_RESULT")
    return require(result, _ISSUER.tag)


__all__ = ["require_simulation_result", "simulate_route"]
