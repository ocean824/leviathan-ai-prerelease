"""FEAT-001 point-in-time and provenance regression tests."""

import json
from decimal import Decimal
from itertools import permutations

import pytest
from pydantic import ValidationError

from leviathan_core.feature_store import (
    FeatureDefinitionConflictError,
    FeatureDefinitionV1,
    FeatureFrozenError,
    FeatureKernelV1,
    FeatureObservationCollisionError,
    FeatureObservationV1,
    FeatureQueryV1,
    FeatureVersionNotFoundError,
)


def _definition(**changes: object) -> FeatureDefinitionV1:
    fields: dict[str, object] = {
        "feature_name": "signal",
        "feature_version": "v1",
        "value_kind": "decimal",
        "published": True,
    }
    fields.update(changes)
    return FeatureDefinitionV1.model_validate(fields)


def _observation(**changes: object) -> FeatureObservationV1:
    fields: dict[str, object] = {
        "feature_name": "signal",
        "feature_version": "v1",
        "instrument_id": "XNYS:ABC",
        "source_dataset": "prices",
        "source_record_key": "r1",
        "event_time_ns": 10,
        "availability_ns": 10,
        "value_decimal": "1.00",
    }
    fields.update(changes)
    return FeatureObservationV1.model_validate(fields)


def _query(asof_ns: int, **changes: object) -> FeatureQueryV1:
    fields: dict[str, object] = {
        "feature_name": "signal",
        "feature_version": "v1",
        "instrument_id": "XNYS:ABC",
        "asof_ns": asof_ns,
    }
    fields.update(changes)
    return FeatureQueryV1.model_validate(fields)


def test_both_event_and_availability_must_be_known_at_cutoff() -> None:
    early = _observation()
    late_correction = _observation(availability_ns=30, value_decimal="2")
    future_event = _observation(
        event_time_ns=40, availability_ns=40, source_record_key="label", value_decimal="99"
    )
    kernel = FeatureKernelV1([_definition()], [future_event, late_correction, early])

    before = kernel.query(_query(20))
    after = kernel.query(_query(50))

    assert before.value_decimal == Decimal("1.00")
    assert before.source_keys == ("r1",)
    assert before.availability_ns == 10
    assert after.value_decimal == Decimal("99")
    assert after.source_keys == ("label",)


def test_missing_is_not_zero_and_unpublished_version_is_invisible() -> None:
    kernel = FeatureKernelV1(
        [_definition(), _definition(feature_version="draft", published=False)],
        [_observation(feature_version="draft", value_decimal="5")],
    )

    missing = kernel.query(_query(100))
    assert not missing.found
    assert missing.value_decimal is None
    assert missing.source_keys == ()
    assert missing.lineage.definition_sha256 == missing.definition_hash
    assert missing.lineage.observation_sha256 is None

    with pytest.raises(FeatureVersionNotFoundError):
        kernel.query(_query(100, feature_version="draft"))
    with pytest.raises(FeatureVersionNotFoundError):
        kernel.query(_query(100, feature_version="unknown"))


def test_exact_decimal_null_quality_and_vector_provenance() -> None:
    decimal_value = _observation(value_decimal="1.2300", quality="confirmed")
    same_semantics = _observation(value_decimal=Decimal("1.23"), local_receipt_ns=999)
    assert decimal_value.value_decimal == Decimal("1.2300")
    assert decimal_value.semantic_hash != same_semantics.semantic_hash  # quality is semantic
    assert decimal_value.semantic_hash == _observation(
        value_decimal=Decimal("1.23"), quality="confirmed", local_receipt_ns=999
    ).semantic_hash

    null_value = _observation(
        source_record_key="r2", availability_ns=20, value_decimal=None, is_null=True, quality="gap"
    )
    vector = _observation(
        feature_name="embedding",
        value_decimal=None,
        value_vector=("1.200", Decimal("-0.00")),
    )
    kernel = FeatureKernelV1(
        [_definition(), _definition(feature_name="embedding", value_kind="vector")],
        [decimal_value, null_value, vector],
    )
    first = kernel.query(_query(10))
    later = kernel.query(_query(20))
    vector_result = kernel.query(_query(10, feature_name="embedding"))

    assert first.value_decimal == Decimal("1.2300")
    assert first.quality == "confirmed"
    assert first.observation_hash == decimal_value.semantic_hash
    assert first.lineage.source_dataset == "prices"
    assert later.found and later.is_null and later.value_decimal is None
    assert later.quality == "gap"
    assert vector_result.value_vector == (Decimal("1.200"), Decimal("-0.00"))
    assert vector_result.value_decimal is None


def test_definition_is_immutable_within_version() -> None:
    with pytest.raises(FeatureDefinitionConflictError):
        FeatureKernelV1([_definition(), _definition(value_kind="vector")], [])
    with pytest.raises(FeatureDefinitionConflictError):
        FeatureKernelV1([_definition(published=False), _definition()], [])


def test_input_order_and_local_receipt_do_not_change_selection() -> None:
    observations = [
        _observation(source_record_key="a", value_decimal="1"),
        _observation(source_record_key="b", value_decimal="2"),
        _observation(source_record_key="c", availability_ns=12, value_decimal="3"),
    ]
    outputs = [
        FeatureKernelV1([_definition()], order).query(_query(20))
        for order in permutations(observations)
    ]
    assert all(output == outputs[0] for output in outputs)
    assert outputs[0].source_keys == ("c",)
    assert outputs[0].value_decimal == Decimal("3")

    duplicate = _observation(local_receipt_ns=123)
    baseline = _observation(local_receipt_ns=456)
    assert duplicate.semantic_hash == baseline.semantic_hash
    assert FeatureKernelV1([_definition()], [duplicate, baseline]).query(_query(10)).found


def test_same_order_slot_with_different_content_is_an_error() -> None:
    kernel = FeatureKernelV1([_definition()], [_observation(), _observation(value_decimal="2")])
    with pytest.raises(FeatureObservationCollisionError):
        kernel.query(_query(10))


@pytest.mark.parametrize("left,right,canonical", [("1.0", "1.00", "1"), ("-0", "0", "0")])
def test_equal_semantic_duplicates_have_identical_json_bytes(
    left: str, right: str, canonical: str
) -> None:
    first = _observation(value_decimal=left, local_receipt_ns=10)
    second = _observation(value_decimal=right, local_receipt_ns=20)
    first_result = FeatureKernelV1([_definition()], [first, second]).query(_query(10))
    second_result = FeatureKernelV1([_definition()], [second, first]).query(_query(10))

    assert str(first.value_decimal) == canonical
    assert str(second.value_decimal) == canonical
    assert first_result.model_dump_json().encode("utf-8") == second_result.model_dump_json().encode(
        "utf-8"
    )


def test_vector_elements_are_canonical_at_construction() -> None:
    vector = _observation(value_decimal=None, value_vector=["1.00", "-0", "1E+2"])
    assert tuple(str(element) for element in vector.value_vector or ()) == ("1", "0", "100")
    assert "1E+2" not in vector.model_dump_json()


@pytest.mark.parametrize(
    "bad_value",
    ["1E+39", "1E-39", "1E+100000", "0." + "1" * 51],
)
def test_decimal_exponent_and_precision_are_bounded(bad_value: str) -> None:
    with pytest.raises(ValidationError):
        _observation(value_decimal=bad_value)
    with pytest.raises(ValidationError):
        _observation(value_decimal=None, value_vector=[bad_value])


def test_bounded_large_exponents_are_exact_without_scientific_output() -> None:
    positive = _observation(value_decimal="1E+38")
    negative = _observation(value_decimal="1E-38")
    assert str(positive.value_decimal) == "1" + "0" * 38
    assert negative.value_decimal == Decimal("1E-38")
    assert json.loads(positive.model_dump_json())["value_decimal"] == "1" + "0" * 38
    assert json.loads(negative.model_dump_json())["value_decimal"] == "0." + "0" * 37 + "1"


def test_non_encodable_text_is_rejected_before_hashing() -> None:
    bad = "bad\ud800"
    for changes in ({"feature_name": bad}, {"feature_version": bad}):
        with pytest.raises(ValidationError):
            _definition(**changes)
    for changes in (
        {"instrument_id": bad},
        {"source_dataset": bad},
        {"source_record_key": bad},
        {"quality": bad},
    ):
        with pytest.raises(ValidationError):
            _observation(**changes)
    with pytest.raises(ValidationError):
        _query(10, instrument_id=bad)
    assert FeatureKernelV1([_definition()], []).query(_query(10)).found is False


def test_publication_must_be_explicit() -> None:
    with pytest.raises(ValidationError):
        FeatureDefinitionV1(feature_name="signal", feature_version="v1", value_kind="decimal")


def test_frozen_feature_records_never_echo_assignment_values() -> None:
    sentinel = "FEAT_ASSIGNMENT_SECRET_76193"
    result = FeatureKernelV1([_definition()], [_observation()]).query(_query(10))
    records = (
        (_definition(), "feature_name"),
        (_observation(), "value_decimal"),
        (_query(10), "instrument_id"),
        (result.lineage, "source_dataset"),
        (result, "value_decimal"),
    )
    for record, field in records:
        before = record.model_dump_json()
        with pytest.raises(FeatureFrozenError) as assigned:
            setattr(record, field, sentinel)
        with pytest.raises(FeatureFrozenError) as deleted:
            delattr(record, field)
        for caught in (assigned, deleted):
            error = caught.value
            assert error.code == "FROZEN_FEATURE_MODEL"
            assert str(error) == "FROZEN_FEATURE_MODEL"
            assert error.args == ("FROZEN_FEATURE_MODEL",)
            assert error.__cause__ is None
            assert error.__context__ is None
            assert sentinel not in repr(error)
        assert record.model_dump_json() == before


@pytest.mark.parametrize(
    "changes",
    [
        {"value_decimal": 1.2},
        {"value_decimal": "NaN"},
        {"value_decimal": "Infinity"},
        {"value_decimal": None, "value_vector": ["1", 2.5]},
        {"availability_ns": 9},
        {"value_decimal": None},
        {"is_null": True},
    ],
)
def test_invalid_observations_are_rejected(changes: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        _observation(**changes)
