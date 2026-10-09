"""SEAL-001 issuance regressions for FEAT-001 query results."""

from __future__ import annotations

import copy
import hashlib
import json
import pickle
from collections.abc import Iterator
from decimal import Decimal

import pytest
from pydantic import TypeAdapter, ValidationError

from leviathan_core.feature_store.asof import FeatureKernelV1
from leviathan_core.feature_store.models import (
    FeatureDefinitionV1,
    FeatureObservationV1,
    FeatureQueryV1,
    FeatureResultSealError,
    FeatureResultV1,
    require_feature_result,
)


def _issued_result() -> FeatureResultV1:
    definition = FeatureDefinitionV1(
        feature_name="mid_price",
        feature_version="1.0.0",
        value_kind="decimal",
        published=True,
    )
    observation = FeatureObservationV1(
        feature_name="mid_price",
        feature_version="1.0.0",
        instrument_id="XNYS:ABC",
        source_dataset="quotes-v1",
        source_record_key="r1",
        event_time_ns=90,
        availability_ns=95,
        value_decimal=Decimal("101.250"),
        quality="confirmed",
    )
    query = FeatureQueryV1(
        feature_name="mid_price",
        feature_version="1.0.0",
        instrument_id="XNYS:ABC",
        asof_ns=100,
    )
    return FeatureKernelV1([definition], [observation]).query(query)


def _assert_untrusted(value: object) -> None:
    with pytest.raises(FeatureResultSealError) as raised:
        require_feature_result(value)
    assert raised.value.code == "FEATURE_RESULT_UNTRUSTED"
    assert raised.value.args == ("FEATURE_RESULT_UNTRUSTED",)
    assert str(raised.value) == "FEATURE_RESULT_UNTRUSTED"
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None


def test_query_issues_exact_type_and_keeps_golden_json_bytes() -> None:
    result = _issued_result()
    assert type(result) is FeatureResultV1
    assert require_feature_result(result) is result

    expected = (
        '{"found":true,"feature_name":"mid_price","feature_version":"1.0.0",'
        '"instrument_id":"XNYS:ABC","asof_ns":100,"value_decimal":"101.25",'
        '"value_vector":null,"quality":"confirmed","is_null":false,'
        '"source_dataset":"quotes-v1","source_record_key":"r1","event_time_ns":90,'
        '"availability_ns":95,"source_keys":["r1"],'
        '"definition_hash":"f7783edca8ed17d554ccb9ac62fb894b83cc6534be1f33dda4ca2865d340e76b",'
        '"observation_hash":"210d27032e39913691a18bdd94dd2c850b66c2bf95225ca359d696ea7064aac4",'
        '"lineage":{"definition_sha256":"f7783edca8ed17d554ccb9ac62fb894b83cc6534be1f33dda4ca2865d340e76b",'
        '"observation_sha256":"210d27032e39913691a18bdd94dd2c850b66c2bf95225ca359d696ea7064aac4",'
        '"source_dataset":"quotes-v1","source_record_key":"r1"}}'
    )
    encoded = result.model_dump_json().encode("utf-8")
    assert encoded == expected.encode("utf-8")
    assert hashlib.sha256(encoded).hexdigest() == (
        "dcfc972286114a0ec232cf27d67f24db0e6fbc3170c8b0d6a0cc3dcb672516b6"
    )


def test_issued_results_round_trip_through_json_validation() -> None:
    decimal_definition = FeatureDefinitionV1(
        feature_name="mid_price",
        feature_version="1.0.0",
        value_kind="decimal",
        published=True,
    )
    vector_definition = FeatureDefinitionV1(
        feature_name="embedding",
        feature_version="1.0.0",
        value_kind="vector",
        published=True,
    )
    query = FeatureQueryV1(
        feature_name="mid_price",
        feature_version="1.0.0",
        instrument_id="XNYS:ABC",
        asof_ns=100,
    )
    found = _issued_result()
    not_found = FeatureKernelV1([decimal_definition], []).query(query)
    vector = FeatureKernelV1(
        [vector_definition],
        [
            FeatureObservationV1(
                feature_name="embedding",
                feature_version="1.0.0",
                instrument_id="XNYS:ABC",
                source_dataset="embeddings-v1",
                source_record_key="vector-1",
                event_time_ns=90,
                availability_ns=95,
                value_vector=(Decimal("1.25"), Decimal("-0")),
            )
        ],
    ).query(
        FeatureQueryV1(
            feature_name="embedding",
            feature_version="1.0.0",
            instrument_id="XNYS:ABC",
            asof_ns=100,
        )
    )

    for result in (found, not_found, vector):
        encoded = result.model_dump_json()
        model_round_trip = FeatureResultV1.model_validate_json(encoded)
        adapter_round_trip = TypeAdapter(FeatureResultV1).validate_json(encoded)
        assert model_round_trip.model_dump_json().encode("utf-8") == encoded.encode("utf-8")
        assert adapter_round_trip.model_dump_json().encode("utf-8") == encoded.encode("utf-8")

    payload = found.model_dump(mode="python")
    payload["source_keys"] = ["r1"]
    python_list_result = FeatureResultV1(**payload)
    assert python_list_result.source_keys == ("r1",)


def test_hostile_source_keys_list_subclass_gets_sanitized_validation_error() -> None:
    class HostileList(list[str]):
        def __iter__(self) -> Iterator[str]:
            raise RuntimeError("hostile list iteration")

    payload = _issued_result().model_dump(mode="python")
    payload["source_keys"] = HostileList(["SOURCE_KEYS_SECRET_CANARY"])

    with pytest.raises(ValidationError) as raised:
        FeatureResultV1(**payload)

    _assert_redacted_validation(raised.value, ("SOURCE_KEYS_SECRET_CANARY",))


def test_direct_and_constructed_values_are_unissued() -> None:
    issued = _issued_result()
    payload = issued.model_dump(mode="python")

    direct = FeatureResultV1(**payload)
    constructed = FeatureResultV1.model_construct(**payload)

    _assert_untrusted(direct)
    _assert_untrusted(constructed)


def test_copy_model_copy_and_pickle_do_not_preserve_issuance() -> None:
    issued = _issued_result()
    copied = copy.copy(issued)
    deep_copied = copy.deepcopy(issued)
    model_copied = issued.model_copy()
    restored = pickle.loads(pickle.dumps(issued))

    for value in (copied, deep_copied, model_copied, restored):
        _assert_untrusted(value)


def test_wrong_type_is_rejected_without_echoing_input() -> None:
    _assert_untrusted({"secret-canary": "must not escape"})


def test_tampered_issued_content_is_rejected() -> None:
    result = _issued_result()
    object.__getattribute__(result, "__dict__")["definition_hash"] = "0" * 64

    _assert_untrusted(result)


def test_reinitialization_is_rejected_before_writes() -> None:
    result = _issued_result()
    before_json = result.model_dump_json()
    before_state = dict(object.__getattribute__(result, "__dict__"))
    before_fields_set = set(object.__getattribute__(result, "__pydantic_fields_set__"))

    with pytest.raises(FeatureResultSealError) as raised:
        FeatureResultV1.__init__(result, **result.model_dump(mode="python"))

    assert raised.value.code == "FEATURE_RESULT_UNTRUSTED"
    assert raised.value.args == ("FEATURE_RESULT_UNTRUSTED",)
    assert str(raised.value) == "FEATURE_RESULT_UNTRUSTED"
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    assert object.__getattribute__(result, "__dict__") == before_state
    assert object.__getattribute__(result, "__pydantic_fields_set__") == before_fields_set
    assert result.model_dump_json() == before_json
    assert require_feature_result(result) is result


def _assert_redacted_validation(error: ValidationError, canaries: tuple[str, ...]) -> None:
    rendered = "\n".join(
        (str(error), repr(error), error.json(), repr(error.errors()), repr(error.args))
    )
    for canary in canaries:
        assert canary not in rendered
    assert error.__cause__ is None
    assert error.__context__ is None
    for detail in error.errors():
        assert detail["type"] == "feature_boundary_invalid"
        assert detail["msg"] == "FEATURE_BOUNDARY_INVALID"
        assert detail["input"] is None


def test_num001_precision_bounds_and_34_digit_value() -> None:
    for value in (
        "12345678901234567890123456789012345",
        "12345678901234567890.000000000000000001",
    ):
        with pytest.raises(ValidationError) as raised:
            FeatureObservationV1(
                feature_name="bounded",
                feature_version="v1",
                instrument_id="XNYS:ABC",
                source_dataset="quotes-v1",
                source_record_key="precision-bound",
                event_time_ns=10,
                availability_ns=10,
                value_decimal=value,
            )
        _assert_redacted_validation(raised.value, (value,))

    exact_value = "1234567890123456.789012345678901234"
    definition = FeatureDefinitionV1(
        feature_name="bounded",
        feature_version="v1",
        value_kind="decimal",
        published=True,
    )
    observation = FeatureObservationV1(
        feature_name="bounded",
        feature_version="v1",
        instrument_id="XNYS:ABC",
        source_dataset="quotes-v1",
        source_record_key="exact-34",
        event_time_ns=10,
        availability_ns=10,
        value_decimal=exact_value,
    )
    query = FeatureQueryV1(
        feature_name="bounded", feature_version="v1", instrument_id="XNYS:ABC", asof_ns=10
    )
    result = FeatureKernelV1([definition], [observation]).query(query)
    assert require_feature_result(result) is result
    assert result.value_decimal == Decimal(exact_value)
    assert json.loads(result.model_dump_json())["value_decimal"] == exact_value


def test_validation_errors_redact_inputs_across_entry_paths_and_nested_models() -> None:
    secret = "FEAT_SECRET_CANARY_846203"
    base = {
        "feature_name": "safe-name",
        "feature_version": "v1",
        "instrument_id": "XNYS:ABC",
        "source_dataset": "quotes-v1",
        "source_record_key": secret,
        "event_time_ns": 20,
        "availability_ns": 19,
        "value_decimal": "1",
    }

    with pytest.raises(ValidationError) as constructed:
        FeatureObservationV1(**base)
    _assert_redacted_validation(constructed.value, (secret,))

    oversized = {**base, "availability_ns": 20, "value_decimal": "7" * 39}
    with pytest.raises(ValidationError) as validated:
        FeatureObservationV1.model_validate(oversized)
    _assert_redacted_validation(validated.value, ("7" * 39, secret))

    with pytest.raises(ValidationError) as json_validated:
        FeatureObservationV1.model_validate_json(json.dumps(oversized))
    _assert_redacted_validation(json_validated.value, ("7" * 39, secret))

    payload = _issued_result().model_dump(mode="python")
    lineage = dict(payload["lineage"])
    lineage[secret] = "another-secret-value"
    payload["lineage"] = lineage
    with pytest.raises(ValidationError) as nested:
        FeatureResultV1.model_validate(payload)
    _assert_redacted_validation(nested.value, (secret, "another-secret-value"))
