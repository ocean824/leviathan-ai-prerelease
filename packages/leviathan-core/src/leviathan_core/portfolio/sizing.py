"""Pure PORT-001 sizing proposals under conservative, account-currency hard caps.

This module cannot approve, persist, route, or submit an order. Downstream risk
authorities must evaluate a final intent against current authoritative state.
"""

from __future__ import annotations

from decimal import (
    ROUND_FLOOR,
    ROUND_HALF_EVEN,
    Context,
    Decimal,
    DecimalException,
    DivisionByZero,
    Inexact,
    InvalidOperation,
    Overflow,
    localcontext,
)
from fractions import Fraction
from itertools import pairwise
from math import isqrt

from leviathan_core.numeric import Ratio, sqrt_ge
from leviathan_core.portfolio.models import (
    CapHitV1,
    ExposureSnapshotV1,
    HardCapsV1,
    ObservationV1,
    PositionV1,
    SectorEntryV1,
    SizingMode,
    SizingPolicyV1,
    SizingRequestV1,
    SizingResultV1,
    SizingStatus,
    canonical_hash,
)

_D = Decimal
_ZERO = _D(0)
_ONE = _D(1)
_TOLERANCE = _D("1e-12")
# Inputs have |adjusted| <= 38; 160 decimal places leave ample room for
# a certified lower bound even at the smallest positive inverse sigma.
_SQRT_CERT_SCALE = 10**160
_CONTEXT = Context(
    prec=34, rounding=ROUND_HALF_EVEN, traps=[InvalidOperation, DivisionByZero, Overflow]
)
_EXACT_CONTEXT = Context(
    prec=34,
    rounding=ROUND_HALF_EVEN,
    traps=[InvalidOperation, DivisionByZero, Overflow, Inexact],
)


class _DenyError(Exception):
    def __init__(self, reason: str, cap_hits: tuple[CapHitV1, ...] = ()) -> None:
        self.reason = reason
        self.cap_hits = cap_hits
        super().__init__(reason)


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise _DenyError(reason)


def _exact_add(*values: Decimal) -> Decimal:
    try:
        with localcontext(_EXACT_CONTEXT):
            total = _ZERO
            for value in values:
                total += value
            return _number(total)
    except Inexact as exc:
        raise _DenyError("PRECISION_EXCEEDED") from exc


def _exact_product(*values: Decimal) -> Decimal:
    try:
        with localcontext(_EXACT_CONTEXT):
            product = _ONE
            for value in values:
                product *= value
            return _number(product)
    except Inexact as exc:
        raise _DenyError("PRECISION_EXCEEDED") from exc


def _number(value: object, *, positive: bool = False, nonnegative: bool = False) -> Decimal:
    _require(type(value) is Decimal and value.is_finite(), "INVALID_DECIMAL")
    assert isinstance(value, Decimal)
    coefficient = value.as_tuple().digits
    significant = len(coefficient)
    while significant > 1 and coefficient[significant - 1] == 0:
        significant -= 1
    _require(
        significant <= 34 and (value.is_zero() or abs(value.adjusted()) <= 38), "PRECISION_EXCEEDED"
    )
    if positive:
        _require(value > _ZERO, "NONPOSITIVE_INPUT")
    elif nonnegative:
        _require(value >= _ZERO, "NEGATIVE_INPUT")
    return value


def _timestamp(value: object) -> int:
    _require(
        isinstance(value, int) and not isinstance(value, bool) and value >= 0, "INVALID_TIMESTAMP"
    )
    assert isinstance(value, int)
    return value


class _Validator:
    def __init__(self, request: SizingRequestV1, policy: SizingPolicyV1) -> None:
        self.request = request
        self.policy = policy
        self.max_age = 0
        self.evaluation_ns = _timestamp(request.evaluation_ns)
        self.freshness_ns = _timestamp(policy.max_age_ns)

    def times(self, event_ns: int, available_ns: int) -> None:
        event = _timestamp(event_ns)
        available = _timestamp(available_ns)
        _require(event <= available <= self.evaluation_ns, "FUTURE_OR_CONFLICTING_EVIDENCE")
        age = self.evaluation_ns - event
        _require(age <= self.freshness_ns, "STALE_EVIDENCE")
        self.max_age = max(self.max_age, age)

    def observation(self, observation: ObservationV1) -> Decimal:
        _require(isinstance(observation, ObservationV1), "MISSING_EVIDENCE")
        _require(
            bool(observation.source_id) and bool(observation.source_version),
            "MISSING_SOURCE_VERSION",
        )
        _require(observation.validation_status == "VALIDATED", "UNVALIDATED_EVIDENCE")
        self.times(observation.event_ns, observation.available_ns)
        return _number(observation.value)

    def sector(self, entry: SectorEntryV1) -> None:
        _require(bool(entry.instrument) and bool(entry.sector), "MISSING_SECTOR")
        _require(bool(entry.source_id) and bool(entry.source_version), "MISSING_SOURCE_VERSION")
        _require(entry.validation_status == "VALIDATED", "UNVALIDATED_EVIDENCE")
        self.times(entry.event_ns, entry.available_ns)

    def window(self, start_ns: int, end_ns: int, observed_ns: int) -> None:
        start, end = _timestamp(start_ns), _timestamp(end_ns)
        _require(start < end <= _timestamp(observed_ns), "INVALID_ESTIMATE_WINDOW")
        _require(end <= self.evaluation_ns, "FUTURE_OR_CONFLICTING_EVIDENCE")


def _validate_caps(caps: HardCapsV1) -> None:
    _require(isinstance(caps, HardCapsV1), "MISSING_HARD_CAP")
    for name in (
        "per_symbol_notional",
        "per_sector_notional",
        "gross_notional",
        "net_notional",
        "max_leverage",
        "per_trade_loss",
        "portfolio_heat",
    ):
        _number(getattr(caps, name), nonnegative=True)


def _validate_common(
    request: SizingRequestV1,
    policy: SizingPolicyV1,
    validator: _Validator,
) -> tuple[dict[str, PositionV1], dict[str, str], Decimal, Decimal, Decimal]:
    _require(
        all(
            (
                request.tenant_id,
                request.strategy_revision_hash,
                request.portfolio_revision_hash,
                request.instrument,
                request.instrument_currency,
                request.account_currency,
                request.risk_rail_policy_digest,
                policy.policy_digest,
            )
        ),
        "MISSING_IDENTITY",
    )
    _require(request.risk_rail_policy_digest == policy.policy_digest, "POLICY_DIGEST_MISMATCH")
    _require(request.side in ("BUY", "SELL"), "INVALID_SIDE")
    if request.candidate_provenance is not None:
        _require(bool(request.candidate_provenance.asset_id), "MISSING_ASSET_PROVENANCE")
        _require(request.candidate_provenance.status == "VALIDATED", "UNVALIDATED_ASSET_INPUT")
    _validate_caps(policy.caps)
    equity = validator.observation(request.equity)
    _require(equity > _ZERO, "NONPOSITIVE_EQUITY")
    price = validator.observation(request.price)
    fx = validator.observation(request.fx_to_account)
    loss = validator.observation(request.worst_case_loss_per_unit)
    _require(price > _ZERO and fx > _ZERO and loss > _ZERO, "NONPOSITIVE_MARKET_INPUT")
    multiplier = _number(request.contract_multiplier, positive=True)
    _number(request.lot_step, positive=True)
    _number(request.min_notional, nonnegative=True)

    sectors: dict[str, str] = {}
    for entry in request.sector_map:
        _require(isinstance(entry, SectorEntryV1), "MISSING_SECTOR")
        validator.sector(entry)
        _require(entry.instrument not in sectors, "CONFLICTING_SECTOR")
        sectors[entry.instrument] = entry.sector
    _require(request.instrument in sectors, "MISSING_SECTOR")

    positions: dict[str, PositionV1] = {}
    for position in request.positions:
        _require(isinstance(position, PositionV1), "INVALID_POSITION")
        _require(
            bool(position.instrument) and bool(position.instrument_currency), "INVALID_POSITION"
        )
        _require(position.instrument not in positions, "CONFLICTING_POSITION")
        _require(position.instrument in sectors, "MISSING_SECTOR")
        _require(
            bool(position.source_id) and bool(position.source_version), "MISSING_SOURCE_VERSION"
        )
        _require(position.validation_status == "VALIDATED", "UNVALIDATED_EVIDENCE")
        validator.times(position.as_of_ns, position.available_ns)
        _number(position.quantity)
        _number(position.contract_multiplier, positive=True)
        _require(validator.observation(position.price) > _ZERO, "NONPOSITIVE_MARKET_INPUT")
        _require(validator.observation(position.fx_to_account) > _ZERO, "NONPOSITIVE_MARKET_INPUT")
        _require(validator.observation(position.loss_per_unit) > _ZERO, "NONPOSITIVE_MARKET_INPUT")
        positions[position.instrument] = position
    target = positions.get(request.instrument)
    if target is not None:
        _require(
            target.instrument_currency == request.instrument_currency
            and target.price.value == price
            and target.fx_to_account.value == fx
            and target.loss_per_unit.value == loss
            and target.contract_multiplier == multiplier,
            "CONFLICTING_POSITION_MARK",
        )
    return (
        positions,
        sectors,
        equity,
        _exact_product(price, fx, multiplier),
        _exact_product(loss, fx, multiplier),
    )


def _returns_and_volatility(
    request: SizingRequestV1,
    validator: _Validator,
) -> tuple[tuple[str, ...], dict[str, tuple[Decimal, ...]], dict[str, Decimal]]:
    _require(
        request.lookback_count is not None
        and isinstance(request.lookback_count, int)
        and not isinstance(request.lookback_count, bool)
        and request.lookback_count >= 20,
        "INVALID_LOOKBACK",
    )
    _require(request.annualization_factor is not None, "MISSING_ANNUALIZATION")
    _number(request.annualization_factor, positive=True)
    _require(bool(request.return_series), "MISSING_VOLATILITY")
    assert request.lookback_count is not None
    assert request.annualization_factor is not None
    returns: dict[str, tuple[Decimal, ...]] = {}
    sigmas: dict[str, Decimal] = {}
    aligned_timestamps: tuple[int, ...] | None = None
    aligned_as_of_ns: int | None = None
    for item in request.return_series:
        _require(bool(item.instrument) and item.instrument not in returns, "CONFLICTING_RETURNS")
        _require(bool(item.source_id) and bool(item.source_version), "MISSING_SOURCE_VERSION")
        _require(item.validation_status == "VALIDATED", "UNVALIDATED_EVIDENCE")
        validator.times(item.as_of_ns, item.available_ns)
        if aligned_as_of_ns is None:
            aligned_as_of_ns = item.as_of_ns
        _require(item.as_of_ns == aligned_as_of_ns, "RETURNS_MISALIGNED")
        _require(len(item.points) == request.lookback_count, "RETURNS_MISALIGNED")
        timestamps = tuple(_timestamp(point.timestamp_ns) for point in item.points)
        _require(
            all(a < b for a, b in pairwise(timestamps)) and timestamps[-1] <= item.as_of_ns,
            "RETURNS_MISALIGNED",
        )
        if aligned_timestamps is None:
            aligned_timestamps = timestamps
        _require(timestamps == aligned_timestamps, "RETURNS_MISALIGNED")
        values = tuple(_number(point.value) for point in item.points)
        returns[item.instrument] = values
        rational_values = tuple(Fraction(value) for value in values)
        mean = sum(rational_values, Fraction(0)) / request.lookback_count
        exact_variance = (
            sum(((value - mean) ** 2 for value in rational_values), Fraction(0))
            * Fraction(request.annualization_factor)
            / (request.lookback_count - 1)
        )
        variance = _D(exact_variance.numerator) / _D(exact_variance.denominator)
        sigma = variance.sqrt()
        _require(sigma > _ZERO, "NONPOSITIVE_VOLATILITY")
        sigmas[item.instrument] = sigma
    _require(request.instrument in sigmas, "INCOMPLETE_UNIVERSE")
    return tuple(sorted(sigmas)), returns, sigmas


def _validate_budgets(policy: SizingPolicyV1, universe: tuple[str, ...]) -> dict[str, Decimal]:
    budgets: dict[str, Decimal] = {}
    for item in policy.risk_budget_fractions:
        _require(
            bool(item.instrument) and item.instrument not in budgets, "CONFLICTING_RISK_BUDGET"
        )
        fraction = _number(item.fraction, positive=True)
        _require(fraction <= _ONE, "INVALID_RISK_BUDGET")
        budgets[item.instrument] = fraction
    _require(set(budgets) == set(universe), "INCOMPLETE_RISK_BUDGET")
    _require(sum(budgets.values(), _ZERO) <= _ONE, "INVALID_RISK_BUDGET")
    return budgets


def _validate_covariance(
    request: SizingRequestV1,
    universe: tuple[str, ...],
    returns: dict[str, tuple[Decimal, ...]],
) -> tuple[list[list[Decimal]], list[list[Fraction]], bool]:
    _require(len(returns) == len(universe), "INCOMPLETE_COVARIANCE")
    assert request.lookback_count is not None
    assert request.annualization_factor is not None
    count = request.lookback_count
    factor = Fraction(request.annualization_factor)
    rational_returns = {
        symbol: tuple(Fraction(value) for value in returns[symbol]) for symbol in universe
    }
    means = {symbol: sum(rational_returns[symbol], Fraction(0)) / count for symbol in universe}
    rational_matrix: list[list[Fraction]] = []
    for left in universe:
        row: list[Fraction] = []
        for right in universe:
            covariance = (
                sum(
                    (
                        (a - means[left]) * (b - means[right])
                        for a, b in zip(
                            rational_returns[left], rational_returns[right], strict=True
                        )
                    ),
                    Fraction(0),
                )
                * factor
                / (count - 1)
            )
            row.append(covariance)
        rational_matrix.append(row)
    _require(
        all(
            rational_matrix[i][j] == rational_matrix[j][i]
            for i in range(len(universe))
            for j in range(i + 1, len(universe))
        ),
        "ASYMMETRIC_COVARIANCE",
    )
    singular = _covariance_singular(rational_matrix)
    matrix = [
        [_D(entry.numerator) / _D(entry.denominator) for entry in row] for row in rational_matrix
    ]
    return matrix, rational_matrix, singular


def _covariance_singular(matrix: list[list[Fraction]]) -> bool:
    """Exact rational LDL check; zero pivots are singular, negative pivots deny."""
    n = len(matrix)
    _require(max(matrix[i][i] for i in range(n)) > 0, "NONPOSITIVE_VOLATILITY")
    residual = [row[:] for row in matrix]
    singular = False
    for pivot_index in range(n):
        pivot = residual[pivot_index][pivot_index]
        if pivot < 0:
            raise _DenyError("NUMERICAL_INSTABILITY")
        if pivot == 0:
            singular = True
            if any(residual[pivot_index][j] != 0 for j in range(pivot_index + 1, n)):
                raise _DenyError("NUMERICAL_INSTABILITY")
            continue
        for row in range(pivot_index + 1, n):
            for col in range(row, n):
                updated = (
                    residual[row][col]
                    - residual[row][pivot_index] * residual[pivot_index][col] / pivot
                )
                residual[row][col] = updated
                residual[col][row] = updated
    return singular


def _erc_weights(
    matrix: list[list[Decimal]], sigmas: list[Decimal]
) -> tuple[list[Decimal], Fraction]:
    """Cyclical coordinate descent on 1/2*x'Σ*x - sum(log x_i)."""
    x = [_ONE / sigma for sigma in sigmas]
    n = len(x)
    for _ in range(500):
        for i in range(n):
            a = matrix[i][i]
            b = sum((matrix[i][j] * x[j] for j in range(n) if j != i), _ZERO)
            discriminant = b * b + _D(4) * a
            _require(discriminant > _ZERO and a > _ZERO, "INVALID_COVARIANCE")
            root = discriminant.sqrt()
            x[i] = _D(2) / (b + root) if b >= _ZERO else (-b + root) / (_D(2) * a)
        total_x = sum(x, _ZERO)
        weights = [value / total_x for value in x]
        marginal = [sum((matrix[i][j] * weights[j] for j in range(n)), _ZERO) for i in range(n)]
        total_risk = sum((weights[i] * marginal[i] for i in range(n)), _ZERO)
        _require(total_risk > _ZERO, "INVALID_COVARIANCE")
        target = total_risk / _D(n)
        residual = max(abs(weights[i] * marginal[i] - target) for i in range(n))
        if residual <= _TOLERANCE * total_risk:
            return weights, Fraction(residual) / Fraction(total_risk)
    raise _DenyError("SOLVER_NOT_CONVERGED")


def _exact_inverse_vol_weights(
    covariance: list[list[Fraction]], *, for_erc: bool
) -> list[Fraction] | None:
    """Return exact weights when variance ratios have rational square roots.

    For two assets, the ERC cross terms cancel. For larger ERC universes,
    inverse-volatility weights are exact only on a diagonal covariance.
    """
    count = len(covariance)
    if (
        for_erc
        and count > 2
        and any(covariance[i][j] != 0 for i in range(count) for j in range(count) if i != j)
    ):
        return None
    base = covariance[0][0]
    inverse: list[Fraction] = []
    for index in range(count):
        ratio = covariance[index][index] / base
        numerator_root = isqrt(ratio.numerator)
        denominator_root = isqrt(ratio.denominator)
        if (
            numerator_root * numerator_root != ratio.numerator
            or denominator_root * denominator_root != ratio.denominator
        ):
            return None
        inverse.append(Fraction(denominator_root, numerator_root))
    total = sum(inverse, Fraction(0))
    return [value / total for value in inverse]


def _lower_decimal(value: Fraction) -> Decimal:
    """Display a rational target without showing more than its exact value."""
    with localcontext(_CONTEXT) as context:
        context.rounding = ROUND_FLOOR
        return _D(value.numerator) / _D(value.denominator)


def _inverse_sqrt_bounds(variance: Fraction) -> tuple[Fraction, Fraction]:
    """Certified rational bounds on inverse sigma for a positive exact variance."""
    _require(variance > 0, "NONPOSITIVE_VOLATILITY")
    inverse_variance = 1 / variance
    scale = _SQRT_CERT_SCALE
    root = isqrt((inverse_variance.numerator * scale * scale) // inverse_variance.denominator)
    lower = Fraction(root, scale)
    upper = lower if lower * lower == inverse_variance else Fraction(root + 1, scale)
    radicand = Ratio(inverse_variance.numerator, inverse_variance.denominator)
    _require(sqrt_ge(radicand, Ratio(lower.numerator, lower.denominator)), "NUMERICAL_INSTABILITY")
    if upper != lower:
        _require(
            not sqrt_ge(radicand, Ratio(upper.numerator, upper.denominator)),
            "NUMERICAL_INSTABILITY",
        )
    return lower, upper


def _inverse_vol_weight_lower(covariance: list[list[Fraction]], index: int) -> Fraction:
    """L_i / (L_i + sum U_j) is below the exact normalized inverse-vol weight."""
    bounds = [_inverse_sqrt_bounds(covariance[i][i]) for i in range(len(covariance))]
    numerator = bounds[index][0]
    denominator = numerator + sum(
        (bounds[i][1] for i in range(len(bounds)) if i != index), Fraction(0)
    )
    return numerator / denominator


def _proposal(
    request: SizingRequestV1,
    policy: SizingPolicyV1,
    validator: _Validator,
    equity: Decimal,
    unit_notional: Decimal,
    universe: tuple[str, ...],
    sigmas: dict[str, Decimal],
    covariance: list[list[Decimal]],
    exact_covariance: list[list[Fraction]],
    covariance_singular: bool,
) -> tuple[Decimal, Fraction, tuple[str, ...]]:
    try:
        mode = SizingMode(policy.mode)
    except ValueError as exc:
        raise _DenyError("INVALID_SIZING_MODE") from exc
    trace = [f"mode={mode.value}"]
    exact_target: Fraction | None = None
    if mode == SizingMode.FIXED:
        _require(policy.fixed_quantity is not None, "MISSING_FIXED_QUANTITY")
        quantity = _number(policy.fixed_quantity, positive=True)
        exact_target = Fraction(quantity)
    elif mode == SizingMode.CAPPED_KELLY:
        estimate = request.kelly_estimate
        _require(estimate is not None, "MISSING_KELLY_ESTIMATE")
        assert estimate is not None
        _require(
            estimate.win_probability.event_ns == estimate.net_odds.event_ns
            and estimate.win_probability.source_id == estimate.net_odds.source_id
            and estimate.win_probability.source_version == estimate.net_odds.source_version,
            "CONFLICTING_KELLY_ESTIMATE",
        )
        validator.window(
            estimate.window_start_ns, estimate.window_end_ns, estimate.win_probability.event_ns
        )
        validator.window(
            estimate.window_start_ns, estimate.window_end_ns, estimate.net_odds.event_ns
        )
        probability = validator.observation(estimate.win_probability)
        odds = validator.observation(estimate.net_odds)
        _require(_ZERO <= probability <= _ONE and odds > _ZERO, "INVALID_KELLY_ESTIMATE")
        _require(policy.fractional_kelly_factor is not None, "MISSING_KELLY_FRACTION")
        factor = _number(policy.fractional_kelly_factor, positive=True)
        _require(factor <= _ONE, "INVALID_KELLY_FRACTION")
        rational_probability = Fraction(probability)
        rational_odds = Fraction(odds)
        exact_edge = max(
            Fraction(0),
            (rational_odds * rational_probability - (1 - rational_probability)) / rational_odds,
        )
        exact_target = exact_edge * Fraction(factor) * Fraction(equity) / Fraction(unit_notional)
        quantity = _lower_decimal(exact_target)
        trace.append(f"kelly_edge={_lower_decimal(exact_edge)}")
    else:
        if mode == SizingMode.VOLATILITY_SCALED:
            budgets = _validate_budgets(policy, universe)
            symbol_index = universe.index(request.instrument)
            inverse_sigma_lower, _ = _inverse_sqrt_bounds(
                exact_covariance[symbol_index][symbol_index]
            )
            exact_target = (
                Fraction(equity)
                * Fraction(budgets[request.instrument])
                * inverse_sigma_lower
                / Fraction(unit_notional)
            )
            quantity = _lower_decimal(exact_target)
            trace.append(f"risk_budget_fraction={budgets[request.instrument]}")
        else:
            _require(policy.gross_exposure_target is not None, "MISSING_GROSS_EXPOSURE_TARGET")
            gross_target = _number(policy.gross_exposure_target, positive=True)
            _require(request.side == "BUY", "RISK_PARITY_LONG_ONLY")
            rational_weights = _exact_inverse_vol_weights(
                exact_covariance, for_erc=mode == SizingMode.RISK_PARITY
            )
            if mode == SizingMode.RISK_PARITY:
                _require(not covariance_singular, "COVARIANCE_SINGULAR")
            symbol_index = universe.index(request.instrument)
            if rational_weights is not None:
                exact_weight = rational_weights[symbol_index]
                exact_target = exact_weight * Fraction(gross_target) / Fraction(unit_notional)
                quantity = _lower_decimal(exact_target)
                weight = _lower_decimal(exact_weight)
            elif (
                mode == SizingMode.INVERSE_VOLATILITY
                or len(universe) == 2
                or all(
                    exact_covariance[i][j] == 0
                    for i in range(len(universe))
                    for j in range(len(universe))
                    if i != j
                )
            ):
                certified_weight = _inverse_vol_weight_lower(exact_covariance, symbol_index)
                exact_target = certified_weight * Fraction(gross_target) / Fraction(unit_notional)
                quantity = _lower_decimal(exact_target)
                weight = _lower_decimal(certified_weight)
            else:
                weights, relative_residual = _erc_weights(
                    covariance, [sigmas[symbol] for symbol in universe]
                )
                epsilon_bound = max(Fraction(_TOLERANCE), relative_residual)
                used_weight = max(Fraction(0), Fraction(weights[symbol_index]) - epsilon_bound)
                weight = _lower_decimal(used_weight)
                exact_target = used_weight * Fraction(gross_target) / Fraction(unit_notional)
                quantity = _lower_decimal(exact_target)
                trace.append(
                    f"solver_epsilon_bound={epsilon_bound.numerator}/{epsilon_bound.denominator}"
                )
            trace.append(f"target_weight={weight}")
    _require(quantity > _ZERO, "ZERO_PROPOSAL")
    _number(quantity)
    trace.append(f"unclamped_quantity={quantity}")
    return quantity, exact_target if exact_target is not None else Fraction(quantity), tuple(trace)


def _unit(position: PositionV1) -> Decimal:
    return _exact_product(
        position.price.value, position.fx_to_account.value, position.contract_multiplier
    )


def _loss_unit(position: PositionV1) -> Decimal:
    return _exact_product(
        position.loss_per_unit.value, position.fx_to_account.value, position.contract_multiplier
    )


def _cap_intersection(
    proposal_target: Fraction,
    request: SizingRequestV1,
    policy: SizingPolicyV1,
    positions: dict[str, PositionV1],
    sectors: dict[str, str],
    equity: Decimal,
    unit: Decimal,
    loss_unit: Decimal,
) -> tuple[Decimal, tuple[CapHitV1, ...]]:
    target_position = positions.get(request.instrument)
    old_qty = target_position.quantity if target_position else _ZERO
    direction = _ONE if request.side == "BUY" else -_ONE
    sector = sectors[request.instrument]
    other_sector = _ZERO
    other_gross = _ZERO
    other_net = _ZERO
    other_heat = _ZERO
    sector_totals: dict[str, Decimal] = {}
    caps = policy.caps
    for symbol, position in positions.items():
        if symbol == request.instrument:
            continue
        notional = _exact_product(abs(position.quantity), _unit(position))
        _require(notional <= caps.per_symbol_notional, "EXISTING_SYMBOL_CAP_BREACH")
        other_gross = _exact_add(other_gross, notional)
        other_net = _exact_add(other_net, _exact_product(position.quantity, _unit(position)))
        other_heat = _exact_add(
            other_heat, _exact_product(abs(position.quantity), _loss_unit(position))
        )
        position_sector = sectors[symbol]
        sector_totals[position_sector] = _exact_add(
            sector_totals.get(position_sector, _ZERO), notional
        )
        if position_sector == sector:
            other_sector = _exact_add(other_sector, notional)
    _require(
        all(
            total <= caps.per_sector_notional
            for label, total in sector_totals.items()
            if label != sector
        ),
        "EXISTING_SECTOR_CAP_BREACH",
    )

    lower, upper = Fraction(0), proposal_target
    hits: list[CapHitV1] = []

    def restrict(code: str, center: Fraction, slope: Fraction, allowance: Fraction) -> None:
        nonlocal lower, upper
        # |center + slope*q| <= allowance; slope is signed and nonzero.
        if allowance < 0:
            raise _DenyError(
                "HARD_CAP_NO_FEASIBLE_SIZE",
                (*hits, CapHitV1(code, _D(upper.numerator) / _D(upper.denominator), _ZERO)),
            )
        a = (-allowance - center) / slope
        b = (allowance - center) / slope
        cap_lower, cap_upper = min(a, b), max(a, b)
        if upper > cap_upper:
            before = _D(upper.numerator) / _D(upper.denominator)
            after_bound = max(Fraction(0), cap_upper)
            after_lots = after_bound // Fraction(request.lot_step)
            after = _exact_product(_D(after_lots), request.lot_step)
            hits.append(CapHitV1(code, before, after))
        lower = max(lower, cap_lower)
        upper = min(upper, cap_upper)
        if lower > upper:
            raise _DenyError("HARD_CAP_NO_FEASIBLE_SIZE", tuple(hits))

    restrict(
        "PER_SYMBOL_NOTIONAL",
        Fraction(old_qty),
        Fraction(direction),
        Fraction(caps.per_symbol_notional) / Fraction(unit),
    )
    restrict(
        "PER_SECTOR_NOTIONAL",
        Fraction(old_qty),
        Fraction(direction),
        (Fraction(caps.per_sector_notional) - Fraction(other_sector)) / Fraction(unit),
    )
    restrict(
        "GROSS_NOTIONAL",
        Fraction(old_qty),
        Fraction(direction),
        (Fraction(caps.gross_notional) - Fraction(other_gross)) / Fraction(unit),
    )
    restrict(
        "NET_NOTIONAL",
        Fraction(other_net) + Fraction(old_qty) * Fraction(unit),
        Fraction(direction) * Fraction(unit),
        Fraction(caps.net_notional),
    )
    restrict(
        "MAX_LEVERAGE",
        Fraction(old_qty),
        Fraction(direction),
        (Fraction(caps.max_leverage) * Fraction(equity) - Fraction(other_gross)) / Fraction(unit),
    )
    restrict(
        "PER_TRADE_LOSS",
        Fraction(old_qty),
        Fraction(direction),
        Fraction(abs(old_qty)) + Fraction(caps.per_trade_loss) / Fraction(loss_unit),
    )
    restrict(
        "PORTFOLIO_HEAT",
        Fraction(old_qty),
        Fraction(direction),
        (Fraction(caps.portfolio_heat) - Fraction(other_heat)) / Fraction(loss_unit),
    )
    lots = upper // Fraction(request.lot_step)
    # The upper interval may come from an approximation. Only a lot count
    # certified by the rational lower bound on the true target can survive.
    while lots > 0 and Fraction(lots) * Fraction(request.lot_step) > proposal_target:
        lots -= 1
    quantity = _exact_product(_D(lots), request.lot_step)
    if quantity <= _ZERO or Fraction(quantity) < lower:
        raise _DenyError("HARD_CAP_NO_FEASIBLE_LOT", tuple(hits))
    if _exact_product(quantity, unit) < request.min_notional:
        raise _DenyError("BELOW_MIN_NOTIONAL", tuple(hits))
    return quantity, tuple(hits)


def _exposures(
    quantity: Decimal,
    request: SizingRequestV1,
    positions: dict[str, PositionV1],
    sectors: dict[str, str],
    equity: Decimal,
    unit: Decimal,
    loss_unit: Decimal,
) -> ExposureSnapshotV1:
    old_qty = positions[request.instrument].quantity if request.instrument in positions else _ZERO
    direction = _ONE if request.side == "BUY" else -_ONE
    new_qty = _exact_add(old_qty, _exact_product(direction, quantity))
    sector = sectors[request.instrument]
    other_sector = other_gross = other_net = other_heat = _ZERO
    for symbol, position in positions.items():
        if symbol == request.instrument:
            continue
        notional = _exact_product(abs(position.quantity), _unit(position))
        other_gross = _exact_add(other_gross, notional)
        other_net = _exact_add(other_net, _exact_product(position.quantity, _unit(position)))
        other_heat = _exact_add(
            other_heat, _exact_product(abs(position.quantity), _loss_unit(position))
        )
        if sectors[symbol] == sector:
            other_sector = _exact_add(other_sector, notional)
    symbol_notional = _exact_product(abs(new_qty), unit)
    gross = _exact_add(other_gross, symbol_notional)
    return ExposureSnapshotV1(
        symbol_notional=symbol_notional,
        sector_notional=_exact_add(other_sector, symbol_notional),
        gross_notional=gross,
        net_notional=_exact_add(other_net, _exact_product(new_qty, unit)),
        leverage=gross / equity,
        projected_worst_case_loss=_exact_product(
            max(_ZERO, _exact_add(abs(new_qty), -abs(old_qty))), loss_unit
        ),
        portfolio_heat=_exact_add(other_heat, _exact_product(abs(new_qty), loss_unit)),
    )


def _verify_exposures(exposures: ExposureSnapshotV1, caps: HardCapsV1, equity: Decimal) -> None:
    for valid in (
        exposures.symbol_notional <= caps.per_symbol_notional,
        exposures.sector_notional <= caps.per_sector_notional,
        exposures.gross_notional <= caps.gross_notional,
        abs(exposures.net_notional) <= caps.net_notional,
        Fraction(exposures.gross_notional) <= Fraction(caps.max_leverage) * Fraction(equity),
        exposures.projected_worst_case_loss <= caps.per_trade_loss,
        exposures.portfolio_heat <= caps.portfolio_heat,
    ):
        _require(valid, "HARD_CAP_POSTCONDITION_FAILED")


def size(request: SizingRequestV1, policy: SizingPolicyV1) -> SizingResultV1:
    """Return a deterministic advisory proposal, or a typed NO_SIZE with reason."""
    input_hash, policy_hash = canonical_hash(request), canonical_hash(policy)
    validator: _Validator | None = None
    proposal = _ZERO
    hits: tuple[CapHitV1, ...] = ()
    trace: tuple[str, ...] = ()
    try:
        with localcontext(_CONTEXT):
            validator = _Validator(request, policy)
            positions, sectors, equity, unit, loss_unit = _validate_common(
                request,
                policy,
                validator,
            )
            universe, returns, sigmas = _returns_and_volatility(request, validator)
            covariance, exact_covariance, covariance_singular = _validate_covariance(
                request, universe, returns
            )
            proposal, proposal_target, trace = _proposal(
                request,
                policy,
                validator,
                equity,
                unit,
                universe,
                sigmas,
                covariance,
                exact_covariance,
                covariance_singular,
            )
            quantity, hits = _cap_intersection(
                proposal_target,
                request,
                policy,
                positions,
                sectors,
                equity,
                unit,
                loss_unit,
            )
            exposures = _exposures(quantity, request, positions, sectors, equity, unit, loss_unit)
            _verify_exposures(exposures, policy.caps, equity)
            return SizingResultV1(
                status=SizingStatus.SIZE,
                proposed_quantity=quantity,
                unclamped_quantity=proposal,
                reasons=(),
                cap_hits=hits,
                exposures=exposures,
                input_hash=input_hash,
                policy_hash=policy_hash,
                as_of_age_ns=validator.max_age,
                calculation_trace=(
                    *trace,
                    f"capped_quantity={quantity}",
                    f"lot_step={request.lot_step}",
                ),
            )
    except (_DenyError, DecimalException, TypeError, ValueError, AttributeError) as exc:
        reason = exc.reason if isinstance(exc, _DenyError) else "INVALID_NUMERIC_OR_INPUT"
        if isinstance(exc, _DenyError):
            hits = exc.cap_hits or hits
        return SizingResultV1(
            status=SizingStatus.NO_SIZE,
            proposed_quantity=_ZERO,
            unclamped_quantity=proposal,
            reasons=(reason,),
            cap_hits=hits,
            exposures=None,
            input_hash=input_hash,
            policy_hash=policy_hash,
            as_of_age_ns=validator.max_age if validator else None,
            calculation_trace=trace,
        )
