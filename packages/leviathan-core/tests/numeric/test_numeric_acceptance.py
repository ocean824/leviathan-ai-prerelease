"""Independent acceptance tests for the NUM-001 public numeric contract."""

from __future__ import annotations

import json
import random
import tracemalloc
from collections.abc import Callable, Iterable
from decimal import ROUND_DOWN, ROUND_HALF_EVEN, ROUND_UP, Decimal, localcontext
from fractions import Fraction
from pathlib import Path

import pytest

from leviathan_core.numeric import (
    NumericError,
    Ratio,
    canonical_json,
    canonical_str,
    exact_add,
    exact_mul,
    exact_sub,
    exact_sum,
    parse_decimal,
    parse_int,
    quotient_final,
    sqrt_ge,
)

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "fraction_property.json"
PROPERTY_FIXTURE = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def assert_content_free(error: NumericError, inputs: Iterable[object]) -> None:
    """Check the public diagnostic contains classification only, never input."""
    rendered = str(error)
    assert error.code in {
        "INVALID_DECIMAL",
        "INVALID_INTEGER",
        "PRECISION_EXCEEDED",
        "MAGNITUDE_OUT_OF_BOUNDS",
        "OUT_OF_RANGE",
        "POLICY_OUT_OF_BOUNDS",
        "DIVISION_BY_ZERO",
    }
    for value in inputs:
        if isinstance(value, (str, Decimal, int)):
            if isinstance(value, int) and value.bit_length() > 4096:
                continue
            token = str(value)
            if token:
                assert token not in rendered
                assert all(token not in str(arg) for arg in error.args)


def expect_numeric_error(
    call: Callable[[], object],
    *,
    code: str | None = None,
    field: str | None = None,
    inputs: Iterable[object] = (),
) -> NumericError:
    with pytest.raises(NumericError) as caught:
        call()
    error = caught.value
    if code is not None:
        assert error.code == code
    if field is not None:
        assert error.field == field
    assert_content_free(error, inputs)
    return error


@pytest.mark.parametrize(
    ("value", "code"),
    [
        (True, "INVALID_DECIMAL"),
        (False, "INVALID_DECIMAL"),
        (1.25, "INVALID_DECIMAL"),
        (float("nan"), "INVALID_DECIMAL"),
        (float("inf"), "INVALID_DECIMAL"),
        (float("-inf"), "INVALID_DECIMAL"),
        (Decimal("NaN"), "INVALID_DECIMAL"),
        (Decimal("Infinity"), "INVALID_DECIMAL"),
        ("NaN", "INVALID_DECIMAL"),
        ("Infinity", "INVALID_DECIMAL"),
        ("\uFF11\uFF12.5", "INVALID_DECIMAL"),
    ],
)
def test_decimal_parser_rejects_inexact_or_nonfinite_inputs(
    value: object, code: str
) -> None:
    expect_numeric_error(
        lambda: parse_decimal(value, field="price"),
        code=code,
        field="price",
        inputs=(value,),
    )


def test_decimal_parser_normalizes_and_accepts_magnitude_boundary() -> None:
    at_boundary = parse_decimal("1E+34", field="amount")
    redundant_zeroes = parse_decimal(Decimal("1." + "0" * 50), field="amount")
    assert at_boundary == Decimal("1E+34")
    assert redundant_zeroes == Decimal(1)
    assert canonical_str(redundant_zeroes) == "1"
    assert canonical_str(parse_decimal("-0.000", field="amount")) == "0"
    assert canonical_str(parse_decimal("123.4500", field="amount")) == "123.45"


def test_decimal_parser_rejects_precision_and_magnitude_with_typed_errors() -> None:
    too_precise = "12345678901234567890123456789012345"
    expect_numeric_error(
        lambda: parse_decimal(too_precise, field="amount"),
        code="PRECISION_EXCEEDED",
        field="amount",
        inputs=(too_precise,),
    )
    expect_numeric_error(
        lambda: parse_decimal("1E+100000", field="amount"),
        code="MAGNITUDE_OUT_OF_BOUNDS",
        field="amount",
        inputs=("1E+100000",),
    )


def test_compact_exponent_rejection_has_bounded_allocation() -> None:
    compact = "1E+100000"
    tracemalloc.start()
    before, _ = tracemalloc.get_traced_memory()
    expect_numeric_error(
        lambda: parse_decimal(compact, field="amount"),
        code="MAGNITUDE_OUT_OF_BOUNDS",
        field="amount",
        inputs=(compact,),
    )
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert peak - before < 256 * 1024


def test_decimal_parser_rejects_huge_integer_without_rendering_it() -> None:
    huge_integer = 10**5000
    error = expect_numeric_error(
        lambda: parse_decimal(huge_integer, field="quantity"),
        field="quantity",
        inputs=(huge_integer,),
    )
    assert len(str(error)) < 256


@pytest.mark.parametrize(
    ("value", "code"),
    [
        (True, "INVALID_INTEGER"),
        (1.0, "INVALID_INTEGER"),
        ("1", "INVALID_INTEGER"),
        (Decimal("1"), "INVALID_INTEGER"),
    ],
)
def test_integer_parser_rejects_bool_float_and_coercible_values(
    value: object, code: str
) -> None:
    expect_numeric_error(
        lambda: parse_int(value, field="count", min_value=0, max_value=100),
        code=code,
        field="count",
        inputs=(value,),
    )


def test_integer_parser_enforces_inclusive_bounds_and_huge_magnitude() -> None:
    assert parse_int(0, field="count", min_value=0, max_value=10) == 0
    assert parse_int(10, field="count", min_value=0, max_value=10) == 10
    expect_numeric_error(
        lambda: parse_int(-1, field="count", min_value=0, max_value=10),
        code="OUT_OF_RANGE",
        field="count",
        inputs=(-1,),
    )
    expect_numeric_error(
        lambda: parse_int(11, field="count", min_value=0, max_value=10),
        code="OUT_OF_RANGE",
        field="count",
        inputs=(11,),
    )
    huge_integer = 10**5000
    expect_numeric_error(
        lambda: parse_int(huge_integer, field="count", min_value=0, max_value=10),
        field="count",
        inputs=(huge_integer,),
    )


@pytest.mark.parametrize("field", ["", "Upper", "1bad", "bad-name", "x" * 65])
def test_parse_field_grammar_is_checked_as_call_contract(field: str) -> None:
    with pytest.raises(TypeError):
        parse_decimal("1", field=field)
    with pytest.raises(TypeError):
        parse_int(1, field=field, min_value=0, max_value=2)


def test_parse_policies_only_tighten_defaults_and_ranges_are_inclusive() -> None:
    assert parse_decimal("1.25", field="price", min_value="1", max_value="2") == Decimal(
        "1.25"
    )
    for kwargs in (
        {"max_sig_digits": 35},
        {"max_abs_adjusted": 39},
    ):
        expect_numeric_error(
            lambda kwargs=kwargs: parse_decimal("1", field="price", **kwargs),
            code="POLICY_OUT_OF_BOUNDS",
            field="price",
            inputs=("1",),
        )
    expect_numeric_error(
        lambda: parse_decimal("0.99", field="price", min_value="1"),
        code="OUT_OF_RANGE",
        field="price",
        inputs=("0.99",),
    )
    expect_numeric_error(
        lambda: parse_decimal("2.01", field="price", max_value="2"),
        code="OUT_OF_RANGE",
        field="price",
        inputs=("2.01",),
    )


def test_exact_arithmetic_refuses_unrepresentable_results() -> None:
    large = Decimal("9999999999999999999999999999999999")
    tenth = Decimal("0.1")
    expect_numeric_error(
        lambda: exact_add(large, tenth),
        code="PRECISION_EXCEEDED",
        inputs=(large, tenth),
    )
    expect_numeric_error(
        lambda: exact_sum([large, tenth]),
        code="PRECISION_EXCEEDED",
        inputs=(large, tenth),
    )
    expect_numeric_error(
        lambda: exact_mul(Decimal("9" * 18), Decimal("9" * 18)),
        code="PRECISION_EXCEEDED",
        inputs=(Decimal("9" * 18),),
    )


def test_arithmetic_is_independent_of_ambient_decimal_context() -> None:
    left = Decimal("12345678901234567890123456789012")
    right = Decimal("0.75")
    expected = (
        exact_add(left, right),
        exact_sub(left, right),
        exact_mul(Decimal("1.25"), Decimal("2.4")),
        exact_sum([left, right, Decimal("0.25")]),
    )
    for rounding in (ROUND_DOWN, ROUND_UP, ROUND_HALF_EVEN):
        with localcontext() as context:
            context.prec = 1
            context.Emax = 9
            context.Emin = -9
            context.rounding = rounding
            actual = (
                exact_add(left, right),
                exact_sub(left, right),
                exact_mul(Decimal("1.25"), Decimal("2.4")),
                exact_sum([left, right, Decimal("0.25")]),
            )
        assert actual == expected


def _decimal_from_coefficient(coefficient: int, scale: int) -> Decimal:
    sign = "-" if coefficient < 0 else ""
    digits = str(abs(coefficient))
    if scale == 0:
        return Decimal(sign + digits)
    digits = digits.rjust(scale + 1, "0")
    return Decimal(f"{sign}{digits[:-scale]}.{digits[-scale:]}")


def test_seeded_exact_ops_match_fraction_or_raise_without_rounding() -> None:
    rng = random.Random(PROPERTY_FIXTURE["seed"])
    count = PROPERTY_FIXTURE["cases_per_operation"]
    bound = PROPERTY_FIXTURE["coefficient_bound"]
    max_scale = PROPERTY_FIXTURE["maximum_scale"]

    def operand() -> Decimal:
        return _decimal_from_coefficient(
            rng.randint(-bound, bound), rng.randint(0, max_scale)
        )

    operations = (
        ("add", exact_add, lambda a, b: Fraction(a) + Fraction(b)),
        ("sub", exact_sub, lambda a, b: Fraction(a) - Fraction(b)),
        ("mul", exact_mul, lambda a, b: Fraction(a) * Fraction(b)),
    )
    for name, operation, reference in operations:
        succeeded = 0
        for _ in range(count):
            left, right = operand(), operand()
            expected = reference(left, right)
            try:
                result = operation(left, right)
            except NumericError as error:
                assert_content_free(error, (left, right))
            else:
                assert Fraction(result) == expected, name
                succeeded += 1
        assert succeeded == count

    succeeded = 0
    for _ in range(count):
        values = [operand() for _ in range(rng.randint(0, 8))]
        expected = sum((Fraction(value) for value in values), Fraction())
        try:
            result = exact_sum(values)
        except NumericError as error:
            assert_content_free(error, values)
        else:
            assert Fraction(result) == expected
            succeeded += 1
    assert succeeded == count


def test_ratio_compares_exactly_at_34_digit_boundary() -> None:
    denominator = 10**34 - 1
    numerator = (4 * denominator - 1) // 5
    assert 5 * numerator - 4 * denominator == -1
    ratio = Ratio(numerator, denominator)
    assert ratio.lt(Decimal("0.8"))
    assert not ratio.ge(Decimal("0.8"))
    assert ratio.eq(Ratio.of(numerator, denominator))


def test_sqrt_comparison_squares_exactly_around_sqrt_three_halves() -> None:
    below = Decimal("1.224744871391589049098642037352")
    above = Decimal("1.224744871391589049098642037353")
    assert Fraction(below) ** 2 < Fraction(3, 2)
    assert Fraction(above) ** 2 > Fraction(3, 2)
    assert sqrt_ge(Ratio(3, 2), below)
    assert not sqrt_ge(Ratio(3, 2), above)


def test_final_quotient_rounds_once_half_even() -> None:
    result = quotient_final(4, 3)
    expected = Decimal("1.333333333333333333333333333333333")
    assert result == expected
    assert canonical_str(result) == "1.333333333333333333333333333333333"


def test_division_by_zero_is_typed_and_content_free() -> None:
    expect_numeric_error(
        lambda: quotient_final(Decimal("123.45"), 0),
        code="DIVISION_BY_ZERO",
        inputs=(Decimal("123.45"), 0),
    )


def test_canonical_json_is_order_independent_and_normalizes_decimals() -> None:
    first = {"b": Decimal("0.50"), "a": 1}
    second = {"a": 1, "b": Decimal("0.5")}
    assert canonical_json(first) == canonical_json(second)


def test_canonical_json_preserves_numeric_type_boundaries() -> None:
    assert canonical_json({"amount": 1}) != canonical_json({"amount": "1"})
    assert canonical_json({"amount": Decimal("0.5")}) != canonical_json(
        {"amount": "0.5"}
    )
    integer_bytes = canonical_json(1)
    assert integer_bytes == canonical_json(Decimal("1"))
    assert integer_bytes == canonical_json(Decimal("1.00"))
    assert canonical_json(True) != integer_bytes


def test_canonical_json_preserves_numeric_types_inside_nested_payloads() -> None:
    numeric = {"outer": [{"amount": Decimal("0.5"), "count": 1}]}
    textual = {"outer": [{"amount": "0.5", "count": "1"}]}
    assert canonical_json(numeric) != canonical_json(textual)
    assert canonical_json({"outer": [{"amount": 1}]}) != canonical_json(
        {"outer": [{"amount": "1"}]}
    )


def test_seeded_numeric_payloads_never_collide_with_text_payloads() -> None:
    rng = random.Random(PROPERTY_FIXTURE["seed"] ^ 0x4E554D)
    bound = PROPERTY_FIXTURE["coefficient_bound"]
    max_scale = PROPERTY_FIXTURE["maximum_scale"]
    for _ in range(PROPERTY_FIXTURE["cases_per_operation"]):
        coefficient = rng.randint(-bound, bound)
        decimal_value = _decimal_from_coefficient(
            coefficient, rng.randint(0, max_scale)
        )
        nested_number = {"payload": [{"value": decimal_value, "integer": coefficient}]}
        nested_text = {
            "payload": [{"value": str(decimal_value), "integer": str(coefficient)}]
        }
        assert canonical_json(nested_number) != canonical_json(nested_text)
        assert canonical_json({"payload": [{"integer": coefficient}]}) == (
            canonical_json({"payload": [{"integer": Decimal(coefficient)}]})
        )


def test_canonical_json_rejects_float_with_content_free_numeric_error() -> None:
    expect_numeric_error(
        lambda: canonical_json({"amount": 0.125}),
        inputs=(0.125,),
    )


def test_canonical_json_rejects_non_string_keys_and_unsupported_values() -> None:
    expect_numeric_error(
        lambda: canonical_json({1: "value"}),
        inputs=(1,),
    )
    expect_numeric_error(
        lambda: canonical_json({"value": object()}),
    )
