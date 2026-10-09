"""Independent acceptance checks for FEAT-001 FeatureResult issuance."""

from __future__ import annotations

import copy
import hashlib
import pickle
from collections.abc import Callable
from decimal import Decimal

import pytest
from pydantic import ValidationError

from leviathan_core.feature_store.asof import FeatureKernelV1
from leviathan_core.feature_store.models import (
    FeatureDefinitionV1,
    FeatureObservationV1,
    FeatureQueryV1,
    FeatureResultSealError,
    FeatureResultV1,
    require_feature_result,
)

GOLDEN_JSON = (
    b'{"found":true,"feature_name":"mid_price","feature_version":"1.0.0",'
    b'"instrument_id":"XNYS:ABC","asof_ns":100,"value_decimal":"101.25",'
    b'"value_vector":null,"quality":"confirmed","is_null":false,'
    b'"source_dataset":"quotes-v1","source_record_key":"r1","event_time_ns":90,'
    b'"availability_ns":95,"source_keys":["r1"],"definition_hash":'
    b'"f7783edca8ed17d554ccb9ac62fb894b83cc6534be1f33dda4ca2865d340e76b",'
    b'"observation_hash":"210d27032e39913691a18bdd94dd2c850b66c2bf95225ca359d696ea7064aac4",'
    b'"lineage":{"definition_sha256":'
    b'"f7783edca8ed17d554ccb9ac62fb894b83cc6534be1f33dda4ca2865d340e76b",'
    b'"observation_sha256":"210d27032e39913691a18bdd94dd2c850b66c2bf95225ca359d696ea7064aac4",'
    b'"source_dataset":"quotes-v1","source_record_key":"r1"}}'
)
GOLDEN_SHA256 = "dcfc972286114a0ec232cf27d67f24db0e6fbc3170c8b0d6a0cc3dcb672516b6"


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


def _observation_with_value(value: Decimal) -> FeatureObservationV1:
    return FeatureObservationV1(
        feature_name="mid_price",
        feature_version="1.0.0",
        instrument_id="XNYS:ABC",
        source_dataset="quotes-v1",
        source_record_key="boundary",
        event_time_ns=90,
        availability_ns=95,
        value_decimal=value,
    )


def _assert_untrusted(value: object) -> None:
    with pytest.raises(FeatureResultSealError) as caught:
        require_feature_result(value)

    error = caught.value
    assert error.code == "FEATURE_RESULT_UNTRUSTED"
    assert error.args == ("FEATURE_RESULT_UNTRUSTED",)
    assert str(error) == "FEATURE_RESULT_UNTRUSTED"


def test_only_kernel_query_results_are_accepted_by_typed_verifier() -> None:
    issued = _issued_result()

    assert require_feature_result(issued) is issued


@pytest.mark.parametrize(
    "forge",
    [
        pytest.param(lambda value: FeatureResultV1(**value.model_dump()), id="constructor"),
        pytest.param(
            lambda value: FeatureResultV1.model_construct(**value.model_dump()),
            id="model-construct",
        ),
        pytest.param(copy.copy, id="copy"),
        pytest.param(copy.deepcopy, id="deepcopy"),
        pytest.param(lambda value: value.model_copy(), id="model-copy"),
        pytest.param(lambda value: pickle.loads(pickle.dumps(value)), id="pickle"),
    ],
)
def test_forged_or_reconstituted_result_is_unissued(
    forge: Callable[[FeatureResultV1], object],
) -> None:
    forged = forge(_issued_result())

    _assert_untrusted(forged)


def test_wrong_types_and_altered_result_digests_are_rejected() -> None:
    issued = _issued_result()
    _assert_untrusted(object())

    object.__getattribute__(issued, "__dict__")["definition_hash"] = "0" * 64
    _assert_untrusted(issued)


def test_tampering_after_issue_is_detected() -> None:
    issued = _issued_result()
    object.__getattribute__(issued, "__dict__")["value_decimal"] = Decimal("999.5")

    _assert_untrusted(issued)


def test_reinitialization_fails_before_mutating_issued_result() -> None:
    issued = _issued_result()
    before = issued.model_dump_json()

    with pytest.raises(FeatureResultSealError) as caught:
        FeatureResultV1.__init__(issued, **issued.model_dump())

    assert caught.value.code == "FEATURE_RESULT_UNTRUSTED"
    assert caught.value.args == ("FEATURE_RESULT_UNTRUSTED",)
    assert str(caught.value) == "FEATURE_RESULT_UNTRUSTED"
    assert issued.model_dump_json() == before
    assert require_feature_result(issued) is issued


def test_genuine_missing_query_result_is_issued_as_well() -> None:
    definition = FeatureDefinitionV1(
        feature_name="mid_price",
        feature_version="1.0.0",
        value_kind="decimal",
        published=True,
    )
    query = FeatureQueryV1(
        feature_name="mid_price",
        feature_version="1.0.0",
        instrument_id="XNYS:ABC",
        asof_ns=100,
    )

    result = FeatureKernelV1([definition], []).query(query)

    assert result.found is False
    assert require_feature_result(result) is result


def test_num001_34_digit_value_issues_and_round_trips_exactly() -> None:
    exact_value = "1234567890123456.789012345678901234"
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
        source_record_key="r34",
        event_time_ns=90,
        availability_ns=95,
        value_decimal=Decimal(exact_value),
    )
    query = FeatureQueryV1(
        feature_name="mid_price",
        feature_version="1.0.0",
        instrument_id="XNYS:ABC",
        asof_ns=100,
    )

    result = FeatureKernelV1([definition], [observation]).query(query)
    verified = require_feature_result(result)

    assert verified.value_decimal == Decimal(exact_value)
    assert type(verified.value_decimal) is Decimal
    assert f'"value_decimal":"{exact_value}"' in verified.model_dump_json()


def test_num001_35_and_39_digit_inputs_fail_content_free_before_query() -> None:
    allowed_observation_fields = set(FeatureObservationV1.model_fields)

    for digit_count in (35, 39):
        rejected_value = "9" * digit_count + f"e-{digit_count - 1}"
        submitted_decimal = Decimal(rejected_value)
        with pytest.raises(ValidationError) as caught:
            _observation_with_value(submitted_decimal)

        error = caught.value
        assert error.__cause__ is None
        assert error.__context__ is None
        canaries = {rejected_value, str(submitted_decimal), repr(submitted_decimal)}
        for canary in canaries:
            assert canary not in str(error)
            assert canary not in repr(error)
            assert canary not in repr(error.args)
            assert canary not in repr(error.errors())
            assert canary not in error.json()
        for entry in error.errors():
            assert entry["type"] == "feature_boundary_invalid"
            assert entry["msg"] == "FEATURE_BOUNDARY_INVALID"
            assert entry["input"] is None
            assert entry["loc"]
            assert all(part in allowed_observation_fields for part in entry["loc"])


def test_query_serialization_remains_byte_identical_to_prechange_golden() -> None:
    result = _issued_result()
    serialized = result.model_dump_json().encode("utf-8")

    assert serialized == GOLDEN_JSON
    assert hashlib.sha256(serialized).hexdigest() == GOLDEN_SHA256
