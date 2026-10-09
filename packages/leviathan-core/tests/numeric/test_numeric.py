"""NUM-001 exact numeric primitive and property regressions."""

from __future__ import annotations

import copy
import hashlib
import pickle
import random
import tracemalloc
from dataclasses import FrozenInstanceError, replace
from decimal import ROUND_UP, Decimal, localcontext
from fractions import Fraction

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


def test_decimal_boundary_is_exact_ascii_and_bounded_before_expansion() -> None:
    assert parse_decimal("1E+34", field="price") == Decimal("1E+34")
    assert parse_decimal(Decimal("1." + "0" * 50), field="price") == Decimal(1)
    assert canonical_str(Decimal("1E-38")) == "0." + "0" * 37 + "1"
    assert canonical_str(Decimal("-0.000")) == "0"

    tracemalloc.start()
    try:
        with pytest.raises(NumericError) as exc:
            parse_decimal("1E+100000", field="price")
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert exc.value.code == "MAGNITUDE_OUT_OF_BOUNDS"
    assert peak < 2_000_000


@pytest.mark.parametrize(
    "bad",
    [True, False, 1.0, float("nan"), float("inf"), Decimal("NaN"), Decimal("Infinity")],
)
def test_decimal_rejects_boolean_float_and_nonfinite(bad: object) -> None:
    with pytest.raises(NumericError) as exc:
        parse_decimal(bad, field="price")
    assert exc.value.code == "INVALID_DECIMAL"
    assert exc.value.field == "price"


@pytest.mark.parametrize("bad", ["01", "+1", ".5", "1.", " 1", "\u0661", "1\ud800"])
def test_decimal_string_grammar_is_strict_ascii(bad: str) -> None:
    with pytest.raises(NumericError) as exc:
        parse_decimal(bad, field="price")
    assert exc.value.code == "INVALID_DECIMAL"


def test_significant_digits_and_policy_can_only_tighten() -> None:
    with pytest.raises(NumericError) as exc:
        parse_decimal("12345678901234567890123456789012345", field="price")
    assert exc.value.code == "PRECISION_EXCEEDED"
    with pytest.raises(NumericError) as exc:
        parse_decimal("123", field="price", max_sig_digits=2)
    assert exc.value.code == "PRECISION_EXCEEDED"
    for kwargs in ({"max_sig_digits": 35}, {"max_abs_adjusted": 39}):
        with pytest.raises(NumericError) as exc:
            parse_decimal("1", field="price", **kwargs)
        assert exc.value.code == "POLICY_OUT_OF_BOUNDS"
    with pytest.raises(NumericError) as exc:
        parse_decimal("3", field="price", min_value=0, max_value=2)
    assert exc.value.code == "OUT_OF_RANGE"


def test_integer_type_and_bit_length_precheck() -> None:
    assert parse_int(5, field="count", min_value=0, max_value=5) == 5
    with pytest.raises(NumericError) as exc:
        parse_int(True, field="count", min_value=0, max_value=5)
    assert exc.value.code == "INVALID_INTEGER"
    huge = 10**5000
    with pytest.raises(NumericError) as exc:
        parse_int(huge, field="count", min_value=0, max_value=10)
    assert exc.value.code == "OUT_OF_RANGE"
    with pytest.raises(NumericError) as exc:
        parse_decimal(huge, field="price")
    assert exc.value.code == "MAGNITUDE_OUT_OF_BOUNDS"


def test_field_names_are_programming_errors_and_numeric_errors_are_content_free() -> None:
    for bad_field in ("Price", "a-b", "", "x" * 65, "a\ud800"):
        with pytest.raises(TypeError):
            parse_decimal("1", field=bad_field)
    secret = "PRIVATE_SECRET_123"
    with pytest.raises(NumericError) as exc:
        parse_decimal(secret, field="price")
    assert exc.value.code == "INVALID_DECIMAL"
    assert exc.value.field == "price"
    assert secret not in str(exc.value)
    assert all(secret not in str(arg) for arg in exc.value.args)


def test_exact_arithmetic_traps_inexact_and_ignores_ambient_context() -> None:
    value = Decimal("9" * 34)
    for operation in (lambda: exact_add(value, 2), lambda: exact_sum([value, 2])):
        with pytest.raises(NumericError) as exc:
            operation()
        assert exc.value.code == "PRECISION_EXCEEDED"

    with localcontext() as ambient:
        ambient.prec = 1
        ambient.Emax = 9
        ambient.rounding = ROUND_UP
        assert exact_add(Decimal("12.25"), Decimal("0.25")) == Decimal("12.5")
        assert exact_sub(Decimal("12.25"), Decimal("0.25")) == Decimal("12")
        assert exact_mul(Decimal("1E+34"), 2) == Decimal("2E+34")
        assert exact_sum([Decimal("1.1"), Decimal("2.2")]) == Decimal("3.3")


def test_ratio_and_sqrt_decisions_never_round_a_quotient() -> None:
    denominator = 10**33 + 4
    numerator = (4 * denominator - 1) // 5
    assert 5 * numerator - 4 * denominator == -1
    ratio = Ratio.of(numerator, denominator)
    assert ratio.lt(Decimal("0.8"))
    assert not ratio.ge(Decimal("0.8"))
    assert ratio.eq(Ratio(numerator, denominator))
    assert ratio.gt(0) and ratio.le(1)

    root_input = Ratio(3, 2)
    just_above = Decimal("1.224744871391589049098642037352946")
    just_below = Decimal("1.224744871391589049098642037352944")
    assert not sqrt_ge(root_input, just_above)
    assert sqrt_ge(root_input, just_below)
    assert sqrt_ge(root_input, 0)


def test_final_quotient_rounds_once_half_even() -> None:
    assert quotient_final(4, 3) == Decimal("1." + "3" * 33)
    with localcontext() as ambient:
        ambient.prec = 1
        ambient.rounding = ROUND_UP
        assert quotient_final(4, 3) == Decimal("1." + "3" * 33)
    with pytest.raises(NumericError) as exc:
        quotient_final(4, 0)
    assert exc.value.code == "DIVISION_BY_ZERO"


def test_canonical_json_is_sorted_and_normalizes_numeric_types() -> None:
    left = canonical_json({"b": Decimal("0.50"), "a": 1})
    right = canonical_json({"a": Decimal("1.0"), "b": Decimal("0.5")})
    assert left == right == b'{"a":1,"b":0.5}'
    assert canonical_json({"zero": Decimal("-0")}) == canonical_json({"zero": 0})
    with pytest.raises(NumericError):
        canonical_json({"unsafe": 0.5})


@pytest.mark.parametrize(
    ("numeric", "text"),
    [
        ({"amount": 1}, {"amount": "1"}),
        ({"amount": Decimal("0.5")}, {"amount": "0.5"}),
        ([1, "2"], ["1", 2]),
        ({"nested": [Decimal("2.0"), {"item": 3}]}, {"nested": ["2", {"item": "3"}]}),
        ({"flag": True}, {"flag": 1}),
        ({"missing": None}, {"missing": "null"}),
    ],
)
def test_canonical_json_preserves_numeric_text_and_other_json_types(
    numeric: object, text: object
) -> None:
    numeric_bytes = canonical_json(numeric)
    text_bytes = canonical_json(text)
    assert numeric_bytes != text_bytes
    assert hashlib.sha256(numeric_bytes).digest() != hashlib.sha256(text_bytes).digest()


def test_canonical_json_uses_ascii_safe_escaping_and_typed_failures() -> None:
    assert canonical_json({"café": "é"}) == b'{"caf\\u00e9":"\\u00e9"}'
    for invalid in ({1: "value"}, {"value": float("nan")}, {"value": {1, 2}}):
        with pytest.raises(NumericError) as exc:
            canonical_json(invalid)
        assert exc.value.code == "INVALID_DECIMAL"


def test_seeded_typed_payloads_never_collide_unless_numeric_values_are_equal() -> None:
    rng = random.Random(20261002)
    for _ in range(1000):
        value = rng.randint(-(10**12), 10**12)
        numeric = {"nested": [value, {"amount": Decimal(f"{value}.00")} ]}
        numeric_equivalent = {"nested": [Decimal(value), {"amount": value}]}
        text = {"nested": [str(value), {"amount": f"{value}.00"}]}
        mixed = {"nested": [value, {"amount": f"{value}.00"}]}
        canonical = canonical_json(numeric)
        assert canonical == canonical_json(numeric_equivalent)
        assert canonical != canonical_json(text)
        assert canonical != canonical_json(mixed)


def test_ratio_freeze_blocks_copy_pickle_and_invalid_replace() -> None:
    ratio = Ratio(2, 4)
    assert ratio == Ratio(1, 2)
    assert replace(ratio, numerator=3) == Ratio(3, 2)
    with pytest.raises(FrozenInstanceError):
        ratio.numerator = 99  # type: ignore[misc]
    for copier in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(TypeError):
            copier(ratio)
    with pytest.raises(NumericError):
        replace(ratio, denominator=0)


def test_seeded_exact_operations_match_fraction_or_raise_for_1000_cases_each() -> None:
    rng = random.Random(20261001)
    for _ in range(1000):
        inputs = [
            Decimal(f"{rng.randint(-10**19, 10**19)}e-{rng.randint(0, 12)}")
            for _ in range(3)
        ]
        a, b, _ = inputs
        scenarios = (
            (lambda a=a, b=b: exact_add(a, b), Fraction(a) + Fraction(b)),
            (lambda a=a, b=b: exact_sub(a, b), Fraction(a) - Fraction(b)),
            (lambda a=a, b=b: exact_mul(a, b), Fraction(a) * Fraction(b)),
            (
                lambda inputs=tuple(inputs): exact_sum(inputs),
                sum((Fraction(x) for x in inputs), Fraction(0)),
            ),
        )
        for operation, expected in scenarios:
            try:
                actual = operation()
            except NumericError as exc:
                assert exc.code in {"PRECISION_EXCEEDED", "MAGNITUDE_OUT_OF_BOUNDS"}
            else:
                assert Fraction(actual) == expected
