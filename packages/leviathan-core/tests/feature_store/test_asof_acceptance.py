"""Independent requirement-level acceptance cases for FEAT-001.

These tests exercise only the frozen public API and deliberately keep the
observation fixtures in memory.  They do not assert persistence or throughput.
"""

from decimal import Decimal
from itertools import permutations

import pytest
from pydantic import ValidationError

from leviathan_core.feature_store import (
    FeatureDefinitionConflictError,
    FeatureDefinitionV1,
    FeatureKernelV1,
    FeatureObservationCollisionError,
    FeatureObservationV1,
    FeatureQueryV1,
    FeatureVersionNotFoundError,
    query_asof,
)

ASOF = 100


def definition(*, version: str = "1.0.0", published: bool = True) -> FeatureDefinitionV1:
    return FeatureDefinitionV1(
        feature_name="mid_price",
        feature_version=version,
        value_kind="decimal",
        published=published,
    )


def observation(
    key: str,
    *,
    event: int,
    available: int,
    value: Decimal | str | int = "101.25",
    version: str = "1.0.0",
    instrument: str = "XYZ",
    dataset: str = "quotes-v1",
    quality: str | None = None,
    is_null: bool = False,
    received: int | None = None,
) -> FeatureObservationV1:
    return FeatureObservationV1(
        feature_name="mid_price",
        feature_version=version,
        instrument_id=instrument,
        source_dataset=dataset,
        source_record_key=key,
        event_time_ns=event,
        availability_ns=available,
        value_decimal=value,
        quality=quality,
        is_null=is_null,
        local_receipt_ns=received,
    )


def query(*, asof: int = ASOF, version: str = "1.0.0") -> FeatureQueryV1:
    return FeatureQueryV1(
        feature_name="mid_price",
        feature_version=version,
        instrument_id="XYZ",
        asof_ns=asof,
    )


def resolve(observations: list[FeatureObservationV1], *, asof: int = ASOF):
    return query_asof(query(asof=asof), [definition()], observations)


def test_rejects_observation_available_after_asof_even_if_event_is_earlier() -> None:
    result = resolve([observation("late-arrival", event=50, available=ASOF + 1)])

    assert result.found is False
    assert result.value_decimal is None
    assert result.source_record_key is None
    assert result.source_keys == ()


def test_rejects_future_event_even_if_it_claims_early_availability() -> None:
    result = resolve([observation("future-event", event=ASOF + 1, available=ASOF + 1)])

    assert result.found is False
    assert result.source_keys == ()


def test_both_asof_boundaries_are_inclusive() -> None:
    result = resolve([observation("at-boundary", event=ASOF, available=ASOF)])

    assert result.found is True
    assert result.value_decimal == Decimal("101.25")
    assert result.event_time_ns == ASOF
    assert result.availability_ns == ASOF
    assert result.source_record_key == "at-boundary"


def test_availability_before_event_is_invalid() -> None:
    with pytest.raises(ValueError):
        observation("impossible-clock-order", event=51, available=50)


def test_future_label_spoof_cannot_leak_through_earlier_event_time() -> None:
    safe = observation("known", event=40, available=45, value="12.00")
    spoofed_label = observation("future-label", event=60, available=60, value="999999")

    result = resolve([safe, spoofed_label], asof=50)

    assert result.found is True
    assert result.value_decimal == Decimal("12.00")
    assert "future-label" not in result.source_keys


def test_later_correction_does_not_rewrite_earlier_snapshot() -> None:
    original = observation("record-original", event=20, available=30, value="10.125")
    correction = observation("record-correction", event=20, available=ASOF + 10, value="10.875")
    kernel = FeatureKernelV1(definitions=[definition()], observations=[original, correction])

    before_correction_was_known = kernel.query(query(asof=ASOF))

    assert before_correction_was_known.found is True
    assert before_correction_was_known.value_decimal == Decimal("10.125")
    assert before_correction_was_known.source_record_key == "record-original"


def test_greatest_visible_tie_tuple_wins_deterministically() -> None:
    rows = [
        observation("older-availability", event=70, available=75, value="1"),
        observation("older-event", event=80, available=90, value="2"),
        observation("z-source-key", event=90, available=90, value="3"),
        observation("a-source-key", event=90, available=90, value="4"),
    ]

    result = resolve(rows)

    assert result.source_record_key == "z-source-key"
    assert result.value_decimal == Decimal("3")


def test_exact_decimal_and_null_quality_round_trip_without_float_conversion() -> None:
    precise = observation(
        "precise",
        event=10,
        available=10,
        value="1234567890123456.789012345678901234",
        quality="verified",
    )
    null = FeatureObservationV1(
        feature_name="mid_price",
        feature_version="1.0.0",
        instrument_id="XYZ",
        source_dataset="quotes-v1",
        source_record_key="null-value",
        event_time_ns=11,
        availability_ns=11,
        value_decimal=None,
        quality="source_missing",
        is_null=True,
    )
    precise_result = resolve([precise])
    null_result = resolve([null])

    assert precise_result.value_decimal == Decimal("1234567890123456.789012345678901234")
    assert type(precise_result.value_decimal) is Decimal
    assert precise_result.quality == "verified"
    assert null_result.found is True
    assert null_result.value_decimal is None
    assert null_result.is_null is True
    assert null_result.quality == "source_missing"


def test_typed_decimal_vector_round_trip_preserves_element_order_and_precision() -> None:
    vector_definition = FeatureDefinitionV1(
        feature_name="greeks",
        feature_version="2.0.0",
        value_kind="vector",
        published=True,
    )
    vector_observation = FeatureObservationV1(
        feature_name="greeks",
        feature_version="2.0.0",
        instrument_id="XYZ",
        source_dataset="options-v1",
        source_record_key="greeks-1",
        event_time_ns=10,
        availability_ns=10,
        value_vector=["0.125", "-2.000000000000000001", "3"],
    )
    result = query_asof(
        FeatureQueryV1(
            feature_name="greeks",
            feature_version="2.0.0",
            instrument_id="XYZ",
            asof_ns=10,
        ),
        [vector_definition],
        [vector_observation],
    )

    assert result.value_vector == (
        Decimal("0.125"),
        Decimal("-2.000000000000000001"),
        Decimal("3"),
    )
    assert result.value_decimal is None


def test_canonical_decimal_spelling_has_same_semantic_observation_hash() -> None:
    lexical_integer = observation("canonical", event=10, available=10, value="1.00")
    decimal_value = observation("canonical", event=10, available=10, value=Decimal("1.0"))

    assert lexical_integer.semantic_hash == decimal_value.semantic_hash


def test_semantically_equal_duplicate_values_have_byte_identical_result_in_any_order() -> None:
    first = observation("same-slot", event=10, available=10, value="1.0")
    second = observation("same-slot", event=10, available=10, value="1.00")
    outputs = [
        resolve([first, second]).model_dump_json().encode("utf-8"),
        resolve([second, first]).model_dump_json().encode("utf-8"),
    ]

    assert outputs[0] == outputs[1]
    assert b'"1"' in outputs[0]


def test_negative_zero_and_zero_have_one_canonical_value_and_identical_result_bytes() -> None:
    negative_zero = observation("zero-slot", event=10, available=10, value="-0.00")
    positive_zero = observation("zero-slot", event=10, available=10, value="0")
    negative_result = resolve([negative_zero])
    positive_result = resolve([positive_zero])

    assert negative_result.value_decimal == Decimal("0")
    assert negative_result.model_dump_json().encode("utf-8") == (
        positive_result.model_dump_json().encode("utf-8")
    )


@pytest.mark.parametrize("value", ["1e39", "1e-39"])
def test_decimal_adjusted_exponent_outside_38_is_rejected(value: str) -> None:
    with pytest.raises(ValidationError):
        observation("exponent-bound", event=10, available=10, value=value)


def test_decimal_adjusted_exponent_boundary_38_is_accepted() -> None:
    largest = observation("exp-plus-boundary", event=10, available=10, value="1e38")
    smallest = observation("exp-minus-boundary", event=10, available=10, value="1e-38")

    assert largest.value_decimal == Decimal("1" + "0" * 38)
    assert smallest.value_decimal == Decimal("0." + "0" * 37 + "1")


def test_decimal_significant_digit_limit_rejects_35_and_50_without_echo() -> None:
    for digit_count in (35, 50):
        rejected_value = "9" * digit_count + f"e-{digit_count - 1}"

        with pytest.raises(ValidationError) as caught:
            observation(
                f"digits-rejected-{digit_count}",
                event=10,
                available=10,
                value=rejected_value,
            )

        error = caught.value
        assert rejected_value not in repr(error.args)
        assert rejected_value not in str(error)
        assert rejected_value not in repr(error)
        assert rejected_value not in repr(error.errors())
        assert rejected_value not in error.json()
        for entry in error.errors():
            assert entry["type"] == "feature_boundary_invalid"
            assert entry["msg"] == "FEATURE_BOUNDARY_INVALID"
            assert entry["input"] is None
            assert entry["loc"]
            assert all(part in FeatureObservationV1.model_fields for part in entry["loc"])
        for chained in (error.__cause__, error.__context__):
            assert chained is None or (
                rejected_value not in str(chained) and rejected_value not in repr(chained)
            )


def test_feature_definition_requires_explicit_publication_state() -> None:
    with pytest.raises(ValidationError):
        FeatureDefinitionV1(
            feature_name="mid_price",
            feature_version="1.0.0",
            value_kind="decimal",
        )


@pytest.mark.parametrize("field", ["definition", "observation", "query"])
def test_lone_surrogate_text_is_rejected_during_model_validation(field: str) -> None:
    with pytest.raises(ValidationError):
        if field == "definition":
            FeatureDefinitionV1(
                feature_name="bad\ud800",
                feature_version="1.0.0",
                value_kind="decimal",
                published=True,
            )
        elif field == "observation":
            observation("bad\ud800", event=10, available=10)
        else:
            FeatureQueryV1(
                feature_name="mid_price",
                feature_version="1.0.0",
                instrument_id="bad\ud800",
                asof_ns=10,
            )


@pytest.mark.parametrize("bad_value", [1.5, float("nan"), float("inf"), float("-inf")])
def test_rejects_float_and_non_finite_float_inputs(bad_value: float) -> None:
    with pytest.raises((TypeError, ValueError)):
        observation("not-exact", event=10, available=10, value=bad_value)  # type: ignore[arg-type]


@pytest.mark.parametrize("bad_value", [Decimal("NaN"), Decimal("Infinity"), Decimal("-Infinity")])
def test_rejects_non_finite_decimal_values(bad_value: Decimal) -> None:
    with pytest.raises((TypeError, ValueError)):
        observation("not-finite", event=10, available=10, value=bad_value)


def test_same_version_definition_mutation_is_rejected() -> None:
    first = definition()
    changed = FeatureDefinitionV1(
        feature_name="mid_price",
        feature_version="1.0.0",
        value_kind="vector",
        published=True,
    )

    assert first.semantic_hash != changed.semantic_hash
    with pytest.raises(FeatureDefinitionConflictError):
        FeatureKernelV1(definitions=[first, changed], observations=[])


def test_unknown_version_query_is_typed_not_found_and_never_falls_back() -> None:
    with pytest.raises(FeatureVersionNotFoundError):
        query_asof(
            query(version="9.9.9"),
            [definition()],
            [observation("known", event=1, available=1)],
        )


def test_unpublished_version_is_invisible_to_asof_reads() -> None:
    hidden_definition = definition(published=False)
    hidden_observation = observation("unpublished", event=10, available=10)

    with pytest.raises(FeatureVersionNotFoundError):
        query_asof(query(), [hidden_definition], [hidden_observation])


def test_input_permutations_produce_identical_result_hashes_and_lineage() -> None:
    rows = [
        observation("a", event=10, available=20, value="1.0"),
        observation("b", event=20, available=20, value="2.0"),
        observation("c", event=30, available=30, value="3.0"),
    ]
    outputs = [resolve(list(order)) for order in permutations(rows)]

    assert len({item.observation_hash for item in outputs}) == 1
    assert len({item.definition_hash for item in outputs}) == 1
    assert len({item.value_decimal for item in outputs}) == 1
    assert len({item.source_keys for item in outputs}) == 1
    assert len({item.lineage for item in outputs}) == 1


def test_local_receipt_time_is_excluded_from_semantic_hashes_and_query_result() -> None:
    first = observation("stable-key", event=10, available=10, value="7.125", received=100)
    second = observation("stable-key", event=10, available=10, value="7.125", received=999_999)

    assert first.semantic_hash == second.semantic_hash
    assert resolve([first]).observation_hash == resolve([second]).observation_hash


def test_equal_order_key_with_different_semantics_is_rejected_as_collision() -> None:
    first = observation("same-key", event=10, available=10, value="1.0")
    changed = observation("same-key", event=10, available=10, value="2.0")

    with pytest.raises(FeatureObservationCollisionError):
        resolve([first, changed])


def test_identical_duplicate_observation_is_idempotent() -> None:
    one = observation("same-key", event=10, available=10, value="1.00", received=1)
    duplicate = observation("same-key", event=10, available=10, value="1.00", received=2)

    result = resolve([one, duplicate])

    assert result.found is True
    assert result.source_keys == ("same-key",)
    assert result.value_decimal == Decimal("1.00")


def test_feature_and_instrument_scope_do_not_cross_contaminate() -> None:
    other_instrument = FeatureObservationV1(
        feature_name="mid_price",
        feature_version="1.0.0",
        instrument_id="ABC",
        source_dataset="quotes-v1",
        source_record_key="other-instrument",
        event_time_ns=10,
        availability_ns=10,
        value_decimal="999",
    )

    result = resolve([other_instrument])

    assert result.found is False


def test_missing_observation_is_missing_never_zero() -> None:
    result = resolve([])

    assert result.found is False
    assert result.value_decimal is None
    assert result.value_vector is None
    assert result.is_null is False
    assert result.source_record_key is None
    assert result.source_keys == ()
