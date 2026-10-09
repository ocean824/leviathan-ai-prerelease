"""Exact Decimal arithmetic with no ambient-context influence."""

from __future__ import annotations

from collections.abc import Iterable
from decimal import Decimal, DivisionByZero, Inexact, InvalidOperation, Overflow, localcontext
from typing import Literal

from leviathan_core.numeric._context import numeric_context
from leviathan_core.numeric.errors import NumericError
from leviathan_core.numeric.parse import parse_decimal


def _arithmetic_error(exc: ArithmeticError) -> NumericError:
    if isinstance(exc, Overflow):
        return NumericError("MAGNITUDE_OUT_OF_BOUNDS", "value")
    if isinstance(exc, DivisionByZero):
        return NumericError("DIVISION_BY_ZERO", "value")
    if isinstance(exc, Inexact):
        return NumericError("PRECISION_EXCEEDED", "value")
    return NumericError("INVALID_DECIMAL", "value")


def _binary(a: Decimal | int, b: Decimal | int, operation: Literal["add", "sub", "mul"]) -> Decimal:
    left = parse_decimal(a, field="value")
    right = parse_decimal(b, field="value")
    try:
        with localcontext(numeric_context()):
            if operation == "add":
                result = left + right
            elif operation == "sub":
                result = left - right
            else:
                result = left * right
    except (Overflow, DivisionByZero, Inexact, InvalidOperation) as exc:
        raise _arithmetic_error(exc) from None
    return parse_decimal(result, field="value")


def exact_add(a: Decimal | int, b: Decimal | int) -> Decimal:
    """Add exactly or raise rather than return a rounded result."""
    return _binary(a, b, "add")


def exact_sub(a: Decimal | int, b: Decimal | int) -> Decimal:
    """Subtract exactly or raise rather than return a rounded result."""
    return _binary(a, b, "sub")


def exact_mul(a: Decimal | int, b: Decimal | int) -> Decimal:
    """Multiply exactly or raise rather than return a rounded result."""
    return _binary(a, b, "mul")


def exact_sum(values: Iterable[Decimal | int]) -> Decimal:
    """Sum a stream with an Inexact trap on every intermediate result."""
    total = Decimal(0)
    try:
        with localcontext(numeric_context()):
            for value in values:
                total += parse_decimal(value, field="value")
    except (Overflow, DivisionByZero, Inexact, InvalidOperation) as exc:
        raise _arithmetic_error(exc) from None
    return parse_decimal(total, field="value")
