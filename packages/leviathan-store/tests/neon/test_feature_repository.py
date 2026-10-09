"""Focused fake-Neon transaction and FEAT-001 as-of tests."""

from __future__ import annotations

import warnings
from collections.abc import Iterator
from decimal import Decimal

import pytest
from leviathan_store.neon import (
    FeaturePersistenceError,
    NeonFeatureRepositoryV1,
    require_feature_write_ack,
)
from pydantic import ValidationError

from leviathan_core.feature_store import (
    FeatureDefinitionV1,
    FeatureObservationV1,
    FeatureQueryV1,
)


def _repo() -> NeonFeatureRepositoryV1:
    repo = NeonFeatureRepositoryV1()
    repo.register_org("org-a")
    repo.register_dataset("org-a", "dataset-a", "owner-a")
    repo.register_instrument("org-a", "instrument-a")
    repo.register_access_policy("org-a", "dataset-a", "policy-a", "org", "org-a", ("read", "write"))
    ack = repo.publish_definition(
        "org-a",
        "dataset-a",
        FeatureDefinitionV1(
            feature_name="momentum", feature_version="v1", value_kind="decimal", published=True
        ),
        git_ref="git:deadbeef",
        data_interval_start_ns=1,
        data_interval_end_ns=100,
    )
    assert require_feature_write_ack(ack).inserted_count == 1
    return repo


def _obs(key: str, value: Decimal, *, availability: int, event: int = 10) -> FeatureObservationV1:
    return FeatureObservationV1(
        feature_name="momentum",
        feature_version="v1",
        instrument_id="instrument-a",
        source_dataset="dataset-a",
        source_record_key=key,
        event_time_ns=event,
        availability_ns=availability,
        value_decimal=value,
    )


def _query(asof: int) -> FeatureQueryV1:
    return FeatureQueryV1(
        feature_name="momentum", feature_version="v1", instrument_id="instrument-a", asof_ns=asof
    )


def test_future_correction_visibility_and_batch_rollback() -> None:
    repo = _repo()
    early = _obs("first", Decimal("1.25"), availability=10)
    correction = _obs("correction", Decimal("2.50"), availability=30)
    ack = repo.insert_observations("org-a", "dataset-a", (early, correction))
    assert require_feature_write_ack(ack).inserted_count == 2
    assert repo.query_asof("org-a", "dataset-a", _query(20)).value_decimal == Decimal("1.25")
    assert repo.query_asof("org-a", "dataset-a", _query(30)).value_decimal == Decimal("2.5")
    with pytest.raises(FeaturePersistenceError, match="FAKE_TRANSACTION_ABORTED"):
        repo.insert_observations(
            "org-a",
            "dataset-a",
            (_obs("later", Decimal("3"), availability=40),),
            fail_before_commit=True,
        )
    assert repo.query_asof("org-a", "dataset-a", _query(50)).value_decimal == Decimal("2.5")
    assert repo.get_lineage("org-a", "dataset-a", "momentum", "v1")[:3] == ("git:deadbeef", 1, 100)


def test_idempotent_source_conflict_and_34_digit_roundtrip() -> None:
    repo = _repo()
    exact = Decimal("0.1234567890123456789012345678901234")
    observation = _obs("exact", exact, availability=10)
    ack = repo.insert_observations("org-a", "dataset-a", (observation, observation))
    assert (ack.inserted_count, ack.idempotent_count) == (1, 1)
    assert repo.query_asof("org-a", "dataset-a", _query(10)).value_decimal == exact
    oversized = "0.12345678901234567890123456789012345"
    with pytest.raises(ValidationError) as boundary_error:
        _obs("oversized", Decimal(oversized), availability=10)
    assert "FEATURE_BOUNDARY_INVALID" in str(boundary_error.value)
    assert oversized not in repr(boundary_error.value)
    assert oversized not in boundary_error.value.json()
    assert all(error["input"] is None for error in boundary_error.value.errors())
    assert (
        repo.observations_in_range(
            "org-a",
            "dataset-a",
            "momentum",
            "v1",
            "instrument-a",
            start_ns=10,
            end_ns=10,
            asof_ns=10,
        )[0].value_decimal
        == exact
    )
    with pytest.raises(FeaturePersistenceError, match="OBSERVATION_CONFLICT"):
        repo.insert_observations(
            "org-a", "dataset-a", (_obs("exact", Decimal("9"), availability=10),)
        )
    assert repo.query_asof("org-a", "dataset-a", _query(10)).value_decimal == exact


def test_orphan_value_requires_dataset_policy_and_instrument() -> None:
    repo = NeonFeatureRepositoryV1()
    repo.register_org("org-a")
    repo.register_dataset("org-a", "dataset-a", "owner-a")
    with pytest.raises(FeaturePersistenceError, match="ACCESS_POLICY_NOT_FOUND"):
        repo.publish_definition(
            "org-a",
            "dataset-a",
            FeatureDefinitionV1(
                feature_name="momentum", feature_version="v1", value_kind="decimal", published=True
            ),
            git_ref="git:deadbeef",
            data_interval_start_ns=1,
            data_interval_end_ns=100,
        )


def test_registered_upstream_lineage_preserves_source_and_is_scoped() -> None:
    repo = _repo()
    repo.register_dataset("org-a", "upstream-a", "owner-a")
    repo.register_access_policy("org-a", "upstream-a", "policy-upstream", "org", "org-a", ("read",))
    ack = repo.register_upstream_lineage(
        "org-a", "dataset-a", "momentum", "v1", "upstream-a", "job-a", "run-a"
    )
    assert require_feature_write_ack(ack).inserted_count == 1
    assert repo.get_upstream_lineage("org-a", "dataset-a", "momentum", "v1") == (
        ("upstream-a", "job-a", "run-a"),
    )
    upstream = FeatureObservationV1(
        feature_name="momentum",
        feature_version="v1",
        instrument_id="instrument-a",
        source_dataset="upstream-a",
        source_record_key="source-key",
        event_time_ns=10,
        availability_ns=10,
        value_decimal=Decimal("3.25"),
    )
    repo.insert_observations("org-a", "dataset-a", (upstream,))
    result = repo.query_asof("org-a", "dataset-a", _query(10))
    assert (result.source_dataset, result.value_decimal) == ("upstream-a", Decimal("3.25"))
    assert repo.observations_in_range(
        "org-a",
        "dataset-a",
        "momentum",
        "v1",
        "instrument-a",
        start_ns=10,
        end_ns=10,
        asof_ns=10,
    ) == (upstream,)
    with pytest.raises(FeaturePersistenceError, match="DATASET_SCOPE_MISMATCH"):
        repo.insert_observations(
            "org-a", "dataset-a", (upstream.model_copy(update={"source_dataset": "other"}),)
        )


def test_iterator_error_is_content_free_and_commits_no_rows() -> None:
    repo = _repo()

    def broken() -> Iterator[FeatureObservationV1]:
        yield _obs("one", Decimal("1"), availability=10)
        raise RuntimeError("SECRET_ITERATOR_PAYLOAD")

    with pytest.raises(FeaturePersistenceError) as caught:
        repo.insert_observations("org-a", "dataset-a", broken())
    assert caught.value.code == "INVALID_OBSERVATION"
    assert "SECRET_ITERATOR_PAYLOAD" not in str(caught.value)
    assert caught.value.args == ("INVALID_OBSERVATION",)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert repo.query_asof("org-a", "dataset-a", _query(10)).found is False


def test_tampered_observation_has_no_warning_or_exception_context() -> None:
    repo = _repo()
    bad = _obs("bad", Decimal("1"), availability=10).model_copy(
        update={"event_time_ns": "SECRET_PYDANTIC_PAYLOAD"}
    )
    with warnings.catch_warnings(record=True) as emitted:
        warnings.simplefilter("always")
        with pytest.raises(FeaturePersistenceError) as caught:
            repo.insert_observations("org-a", "dataset-a", (bad,))
    assert caught.value.code == "INVALID_OBSERVATION"
    assert caught.value.args == ("INVALID_OBSERVATION",)
    assert "SECRET_PYDANTIC_PAYLOAD" not in str(caught.value)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert all("SECRET_PYDANTIC_PAYLOAD" not in str(item.message) for item in emitted)
    assert repo.query_asof("org-a", "dataset-a", _query(10)).found is False


def test_unpublished_query_error_has_no_exception_context() -> None:
    repo = _repo()
    repo.publish_definition(
        "org-a",
        "dataset-a",
        FeatureDefinitionV1(
            feature_name="draft", feature_version="v1", value_kind="decimal", published=False
        ),
        git_ref="git:draft",
        data_interval_start_ns=0,
        data_interval_end_ns=100,
    )
    query = FeatureQueryV1(
        feature_name="draft", feature_version="v1", instrument_id="instrument-a", asof_ns=10
    )
    with pytest.raises(FeaturePersistenceError) as caught:
        repo.query_asof("org-a", "dataset-a", query)
    assert caught.value.code == "QUERY_FAILED"
    assert caught.value.__context__ is None
    assert caught.value.__cause__ is None


def test_scope_ids_and_policy_subject_kind_are_closed() -> None:
    repo = _repo()
    with pytest.raises(FeaturePersistenceError, match="INVALID_IDENTITY"):
        repo.register_org("org\npeer")
    with pytest.raises(FeaturePersistenceError, match="INVALID_IDENTITY"):
        repo.register_dataset("org-a", "dataset\npeer", "owner-a")
    with pytest.raises(FeaturePersistenceError, match="INVALID_POLICY"):
        repo.register_access_policy(
            "org-a", "dataset-a", "policy-unknown", "unknown-subject-kind", "org-a", ("read",)
        )
