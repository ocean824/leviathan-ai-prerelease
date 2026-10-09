"""Exact, bounded parsing before any Decimal expansion or arithmetic."""

from __future__ import annotations

import re
from decimal import Decimal, InvalidOperation

from leviathan_core.numeric.errors import NumericError, require_field

_DECIMAL_RE = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?\Z", re.ASCII)
_MAX_INT_BITS = 130  # Every integer with adjusted exponent <= 38 fits below this limit.


def _fixed_text(value: Decimal) -> str:
    """Emit exact fixed-point text after the caller has checked magnitude."""
    if value.is_zero():
        return "0"
    parts = value.as_tuple()
    digits = parts.digits
    end = len(digits)
    while end > 1 and digits[end - 1] == 0:
        end -= 1
    coefficient = "".join(str(digit) for digit in digits[:end])
    if not isinstance(parts.exponent, int):
        raise NumericError("INVALID_DECIMAL", "value")
    exponent = parts.exponent + len(digits) - end
    if exponent >= 0:
        fixed = coefficient + "0" * exponent
    else:
        point = len(coefficient) + exponent
        fixed = (
            coefficient[:point] + "." + coefficient[point:]
            if point > 0
            else "0." + "0" * -point + coefficient
        )
    return "-" + fixed if parts.sign else fixed


def _significant_digits(value: Decimal) -> int:
    digits = value.as_tuple().digits
    count = len(digits)
    while count > 1 and digits[count - 1] == 0:
        count -= 1
    return count


def _checked_decimal(
    value: object, *, field: str, max_sig_digits: int, max_abs_adjusted: int
) -> Decimal:
    if type(value) is int:
        if value.bit_length() > _MAX_INT_BITS:
            raise NumericError("MAGNITUDE_OUT_OF_BOUNDS", field)
        decimal = Decimal(value)
    elif isinstance(value, Decimal):
        decimal = value
    elif isinstance(value, str) and _DECIMAL_RE.fullmatch(value) is not None:
        try:
            decimal = Decimal(value)
        except InvalidOperation:
            raise NumericError("INVALID_DECIMAL", field) from None
    else:
        raise NumericError("INVALID_DECIMAL", field)

    if not decimal.is_finite():
        raise NumericError("INVALID_DECIMAL", field)
    if abs(decimal.adjusted()) > max_abs_adjusted:
        raise NumericError("MAGNITUDE_OUT_OF_BOUNDS", field)
    if _significant_digits(decimal) > max_sig_digits:
        raise NumericError("PRECISION_EXCEEDED", field)
    return Decimal(_fixed_text(decimal))


def _policy_decimal(
    value: object, field: str, max_sig_digits: int, max_abs_adjusted: int
) -> Decimal:
    try:
        return _checked_decimal(
            value, field=field, max_sig_digits=max_sig_digits, max_abs_adjusted=max_abs_adjusted
        )
    except NumericError:
        raise NumericError("POLICY_OUT_OF_BOUNDS", field) from None


def parse_decimal(
    value: object,
    *,
    field: str,
    max_sig_digits: int = 34,
    max_abs_adjusted: int = 38,
    min_value: Decimal | int | str | None = None,
    max_value: Decimal | int | str | None = None,
) -> Decimal:
    """Parse an exact Decimal under a policy that may tighten, never loosen."""
    require_field(field)
    if (
        type(max_sig_digits) is not int
        or not 1 <= max_sig_digits <= 34
        or type(max_abs_adjusted) is not int
        or not 0 <= max_abs_adjusted <= 38
    ):
        raise NumericError("POLICY_OUT_OF_BOUNDS", field)

    lower = (
        _policy_decimal(min_value, field, max_sig_digits, max_abs_adjusted)
        if min_value is not None
        else None
    )
    upper = (
        _policy_decimal(max_value, field, max_sig_digits, max_abs_adjusted)
        if max_value is not None
        else None
    )
    if lower is not None and upper is not None and lower > upper:
        raise NumericError("POLICY_OUT_OF_BOUNDS", field)

    result = _checked_decimal(
        value, field=field, max_sig_digits=max_sig_digits, max_abs_adjusted=max_abs_adjusted
    )
    if (lower is not None and result < lower) or (upper is not None and result > upper):
        raise NumericError("OUT_OF_RANGE", field)
    return result


def parse_int(value: object, *, field: str, min_value: int, max_value: int) -> int:
    """Parse an exact integer using bit length before comparison or conversion."""
    require_field(field)
    if type(min_value) is not int or type(max_value) is not int or min_value > max_value:
        raise NumericError("POLICY_OUT_OF_BOUNDS", field)
    if type(value) is not int:
        raise NumericError("INVALID_INTEGER", field)
    max_bits = max(min_value.bit_length(), max_value.bit_length())
    if value.bit_length() > max_bits or value < min_value or value > max_value:
        raise NumericError("OUT_OF_RANGE", field)
    return value
