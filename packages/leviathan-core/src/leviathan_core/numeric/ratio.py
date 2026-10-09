"""Rational comparisons and one final quotient rounding."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, DivisionByZero, Inexact, InvalidOperation, Overflow, localcontext
from fractions import Fraction
from typing import Any, SupportsIndex

from leviathan_core.numeric._context import numeric_context
from leviathan_core.numeric.errors import NumericError
from leviathan_core.numeric.parse import parse_decimal


@dataclass(frozen=True, slots=True)
class Ratio:
    """A normalized, deeply immutable exact rational."""

    numerator: int
    denominator: int

    def __post_init__(self) -> None:
        if type(self.numerator) is not int:
            raise NumericError("INVALID_INTEGER", "numerator")
        if type(self.denominator) is not int:
            raise NumericError("INVALID_INTEGER", "denominator")
        if self.denominator == 0:
            raise NumericError("DIVISION_BY_ZERO", "denominator")
        normalized = Fraction(self.numerator, self.denominator)
        object.__setattr__(self, "numerator", normalized.numerator)
        object.__setattr__(self, "denominator", normalized.denominator)

    @classmethod
    def from_decimals(cls, numerator: Decimal | int, denominator: Decimal | int) -> Ratio:
        """Build a rational without dividing or rounding either input."""
        top = _as_fraction(numerator, "numerator")
        bottom = _as_fraction(denominator, "denominator")
        if bottom == 0:
            raise NumericError("DIVISION_BY_ZERO", "denominator")
        ratio = top / bottom
        return cls(ratio.numerator, ratio.denominator)

    @classmethod
    def of(cls, numerator: Decimal | int, denominator: Decimal | int) -> Ratio:
        """Alias for :meth:`from_decimals`."""
        return cls.from_decimals(numerator, denominator)

    def _fraction(self) -> Fraction:
        return Fraction(self.numerator, self.denominator)

    def ge(self, other: Ratio | Decimal | int) -> bool:
        return self._fraction() >= _as_fraction(other, "other")

    def gt(self, other: Ratio | Decimal | int) -> bool:
        return self._fraction() > _as_fraction(other, "other")

    def le(self, other: Ratio | Decimal | int) -> bool:
        return self._fraction() <= _as_fraction(other, "other")

    def lt(self, other: Ratio | Decimal | int) -> bool:
        return self._fraction() < _as_fraction(other, "other")

    def eq(self, other: Ratio | Decimal | int) -> bool:
        return self._fraction() == _as_fraction(other, "other")

    def __copy__(self) -> Ratio:
        raise TypeError("Ratio does not support copying")

    def __deepcopy__(self, memo: dict[int, object]) -> Ratio:
        raise TypeError("Ratio does not support copying")

    def __reduce__(self) -> str | tuple[Any, ...]:
        raise TypeError("Ratio does not support serialization")

    def __reduce_ex__(self, protocol: SupportsIndex) -> str | tuple[Any, ...]:
        raise TypeError("Ratio does not support serialization")


def _as_fraction(value: Ratio | Decimal | int, field: str) -> Fraction:
    if isinstance(value, Ratio):
        return Fraction(value.numerator, value.denominator)
    return Fraction(parse_decimal(value, field=field))


def sqrt_ge(radicand: Ratio | Decimal | int, threshold: Ratio | Decimal | int) -> bool:
    """Compare a square root exactly, including nonpositive thresholds."""
    radicand_fraction = _as_fraction(radicand, "radicand")
    threshold_fraction = _as_fraction(threshold, "threshold")
    if radicand_fraction < 0:
        raise NumericError("OUT_OF_RANGE", "radicand")
    if threshold_fraction <= 0:
        return True
    return radicand_fraction >= threshold_fraction * threshold_fraction


def quotient_final(
    numerator: Ratio | Decimal | int, denominator: Ratio | Decimal | int
) -> Decimal:
    """Round a final quotient once under the owned half-even context."""
    top = _as_fraction(numerator, "numerator")
    bottom = _as_fraction(denominator, "denominator")
    if bottom == 0:
        raise NumericError("DIVISION_BY_ZERO", "denominator")
    quotient = top / bottom
    try:
        with localcontext(numeric_context(final_quotient=True)):
            result = Decimal(quotient.numerator) / Decimal(quotient.denominator)
    except Overflow:
        raise NumericError("MAGNITUDE_OUT_OF_BOUNDS", "value") from None
    except DivisionByZero:
        raise NumericError("DIVISION_BY_ZERO", "denominator") from None
    except (Inexact, InvalidOperation):
        raise NumericError("INVALID_DECIMAL", "value") from None
    return parse_decimal(result, field="value")
