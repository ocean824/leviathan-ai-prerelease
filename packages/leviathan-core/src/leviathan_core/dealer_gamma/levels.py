"""Deterministic model-estimate levels over eligible option evidence."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from decimal import ROUND_HALF_EVEN, Decimal, localcontext
from fractions import Fraction
from functools import wraps
from itertools import pairwise
from typing import ParamSpec, TypeVar

from .models import (
    EXACT_CONTEXT,
    KERNEL_CONTEXT,
    MagnetV1,
    ModelLevelV1,
    OptionSeriesEvidenceV1,
    WallLevelsV1,
    canonical_decimal,
    exact_fraction_decimal,
)

ZERO = Decimal("0")
ONE = Decimal("1")
HUNDRED = Decimal("100")
P = ParamSpec("P")
T = TypeVar("T")


def exact_arithmetic(fn: Callable[P, T]) -> Callable[P, T]:
    @wraps(fn)
    def wrapped(*args: P.args, **kwargs: P.kwargs) -> T:
        with localcontext(EXACT_CONTEXT):
            return fn(*args, **kwargs)
    return wrapped


def adjusted_strike(series: OptionSeriesEvidenceV1) -> Fraction:
    """Keep the current-underlier strike exact until final display."""
    return Fraction(series.strike) / Fraction(series.split_factor)


def rounded_fraction_decimal(value: Fraction) -> Decimal:
    """Materialize a derived rational once under the versioned display context."""
    with localcontext(KERNEL_CONTEXT):
        return canonical_decimal(Decimal(value.numerator) / Decimal(value.denominator))


@exact_arithmetic
def adjusted_multiplier(series: OptionSeriesEvidenceV1) -> Decimal:
    """Resolve multiplier only from an explicit source basis."""
    if series.multiplier_basis == "PRE_ACTION":
        return series.multiplier * series.split_factor
    if series.multiplier_basis == "POST_ACTION_ADJUSTED":
        return series.multiplier
    raise ValueError("ADJUSTMENT_BASIS_UNKNOWN")


@exact_arithmetic
def wall_levels(
    series: tuple[OptionSeriesEvidenceV1, ...],
    option_type: str,
    method: str,
    spot: Decimal,
) -> WallLevelsV1:
    strengths: dict[Fraction, Fraction] = defaultdict(Fraction)
    for option in series:
        if option.option_type != option_type:
            continue
        strike = adjusted_strike(option)
        multiplier = adjusted_multiplier(option)
        if method == "OI_NOTIONAL":
            weight = Fraction(option.open_interest) * Fraction(multiplier) * Fraction(spot)
        else:
            weight = (Fraction(option.open_interest) * Fraction(multiplier)
                      * Fraction(option.gamma) * Fraction(spot) ** 2 / 100)
        strengths[strike] += weight
    ranked = sorted(((strike, weight) for strike, weight in strengths.items() if weight > ZERO),
                    key=lambda item: (-item[1], item[0]))
    if not ranked:
        return WallLevelsV1(primary=None, secondary=None, method=method)
    primary_strike, primary_strength = ranked[0]
    primary = ModelLevelV1(rounded_fraction_decimal(primary_strike), method=method,
                           strength=exact_fraction_decimal(primary_strength))
    secondary = None
    for strike, strength in ranked[1:]:
        if strength * 100 >= primary_strength * 95:
            secondary = ModelLevelV1(rounded_fraction_decimal(strike), method=method,
                                     strength=exact_fraction_decimal(strength))
            break
    return WallLevelsV1(primary=primary, secondary=secondary, method=method)


@exact_arithmetic
def max_pain(
    series: tuple[OptionSeriesEvidenceV1, ...],
    expiry_kind: str,
) -> ModelLevelV1 | None:
    eligible_dates = sorted({s.expiry_date for s in series if s.expiry_kind == expiry_kind})
    if not eligible_dates:
        return None
    expiry = eligible_dates[0]
    expiring = tuple(s for s in series if s.expiry_date == expiry)
    candidates = sorted({adjusted_strike(s) for s in expiring})
    if not candidates:
        return None

    def holder_payoff(candidate: Fraction) -> Fraction:
        total = Fraction()
        for option in expiring:
            strike = adjusted_strike(option)
            intrinsic = (candidate - strike if option.option_type == "CALL"
                         else strike - candidate)
            if intrinsic > 0:
                total += (Fraction(option.open_interest)
                          * Fraction(adjusted_multiplier(option)) * intrinsic)
        return total

    strike = min(candidates, key=lambda candidate: (holder_payoff(candidate), candidate))
    return ModelLevelV1(rounded_fraction_decimal(strike),
                        method=f"HOLDER_INTRINSIC_{expiry_kind}_V1",
                        strength=rounded_fraction_decimal(holder_payoff(strike)))


@exact_arithmetic
def magnets(series: tuple[OptionSeriesEvidenceV1, ...], spot: Decimal) -> tuple[MagnetV1, ...]:
    strengths: dict[Fraction, Fraction] = defaultdict(Fraction)
    for option in series:
        strike = adjusted_strike(option)
        strengths[strike] += (Fraction(option.open_interest)
                              * Fraction(adjusted_multiplier(option))
                              * Fraction(option.gamma) * Fraction(spot) ** 2 / 100)
    ranked = sorted(((strike, weight) for strike, weight in strengths.items() if weight > ZERO),
                    key=lambda item: (-item[1], item[0]))[:3]
    total = sum((weight for _, weight in ranked), Fraction())
    if total == 0:
        return ()
    with localcontext(KERNEL_CONTEXT) as ctx:
        ctx.prec = 34
        ctx.rounding = ROUND_HALF_EVEN
        normalized: list[MagnetV1] = []
        assigned = ZERO
        for index, (strike, weight) in enumerate(ranked):
            share = (ONE - assigned if index == len(ranked) - 1
                     else (Decimal((weight / total).numerator)
                           / Decimal((weight / total).denominator)).quantize(
                               Decimal("0.000000000000000001")))
            normalized.append(MagnetV1(rounded_fraction_decimal(strike), share))
            assigned += share
        return tuple(normalized)


def flip_level(
    grid: tuple[Decimal, ...],
    tolerance: Decimal,
    spot: Decimal,
    exposure_at: Callable[[Decimal], Decimal],
) -> tuple[ModelLevelV1 | None, str | None]:
    """Bracket every crossing; choose the one nearest spot, then the lower bracket.

    Bisection never leaves the supplied grid. Its reported error is half of the
    final bracket width, so callers can decide whether that is sufficiently exact.
    """
    points = tuple((price, exposure_at(price)) for price in grid)
    roots: list[ModelLevelV1] = []
    unresolved = False
    for index, (price, value) in enumerate(points):
        if value != ZERO:
            continue
        left = next((item[1] for item in reversed(points[:index]) if item[1] != ZERO), None)
        right = next((item[1] for item in points[index + 1:] if item[1] != ZERO), None)
        if left is not None and right is not None and (left > ZERO) != (right > ZERO):
            roots.append(ModelLevelV1(price, method="GRID_EXACT_ZERO_V1",
                                      lower_bracket=price, upper_bracket=price,
                                      error_bound=ZERO))
    with localcontext() as ctx:
        ctx.prec = 34
        ctx.rounding = ROUND_HALF_EVEN
        for (lower, lo_value), (upper, hi_value) in pairwise(points):
            if lo_value == ZERO or hi_value == ZERO or (lo_value > ZERO) == (hi_value > ZERO):
                continue
            for _ in range(128):
                if upper - lower <= tolerance * 2:
                    break
                mid = (lower + upper) / 2
                if mid in (lower, upper):
                    break
                mid_value = exposure_at(mid)
                if mid_value == ZERO:
                    lower = upper = mid
                    break
                if (mid_value > ZERO) == (lo_value > ZERO):
                    lower, lo_value = mid, mid_value
                else:
                    upper = mid
            if upper - lower > tolerance * 2:
                unresolved = True
                continue
            midpoint = (lower + upper) / 2
            roots.append(ModelLevelV1(midpoint, method="BRACKET_BISECTION_V1",
                                      lower_bracket=lower, upper_bracket=upper,
                                      error_bound=(upper - lower) / 2))
    if not roots:
        return None, "FLIP_TOLERANCE_NOT_MET" if unresolved else "FLIP_NOT_FOUND_IN_GRID"
    roots.sort(key=lambda root: (abs(root.value - spot), root.value))
    return roots[0], None
