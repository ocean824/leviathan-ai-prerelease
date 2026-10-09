"""Independent, synthetic acceptance probes for STOR-001's fake repository."""

from __future__ import annotations

import copy
import pickle
import re
import warnings
from decimal import Decimal, localcontext
from pathlib import Path

import pytest
from leviathan_store.neon import (
    FeaturePersistenceError,
    FeatureWriteAckV1,
    NeonFeatureRepositoryV1,
    require_feature_write_ack,
)
from pydantic import BaseModel, ValidationError

from leviathan_core.feature_store import (
    FeatureDefinitionV1,
    FeatureObservationV1,
    FeatureQueryV1,
)
from leviathan_core.seal import SealError

ORG = "org-a"
DATASET = "dataset-a"
INSTRUMENT = "instrument-a"
FEATURE = "feature-x"
VERSION = "v1"


def _repo() -> NeonFeatureRepositoryV1:
    repo = NeonFeatureRepositoryV1()
    repo.register_org(ORG)
    repo.register_dataset(ORG, DATASET, "owner-a")
    repo.register_instrument(ORG, INSTRUMENT)
    repo.register_access_policy(ORG, DATASET, "policy-a", "org", ORG, ("read", "write"))
    repo.publish_definition(
        ORG,
        DATASET,
        FeatureDefinitionV1(
            feature_name=FEATURE,
            feature_version=VERSION,
            value_kind="decimal",
            published=True,
        ),
        git_ref="git:synthetic-0123456789abcdef",
        data_interval_start_ns=0,
        data_interval_end_ns=10_000,
    )
    return repo


def _observation(
    key: str,
    value: Decimal | None,
    *,
    event: int = 10,
    available: int | None = None,
    feature: str = FEATURE,
    version: str = VERSION,
    instrument: str = INSTRUMENT,
    dataset: str = DATASET,
    vector: tuple[Decimal, ...] | None = None,
    quality: str | None = None,
    is_null: bool = False,
) -> FeatureObservationV1:
    return FeatureObservationV1(
        feature_name=feature,
        feature_version=version,
        instrument_id=instrument,
        source_dataset=dataset,
        source_record_key=key,
        event_time_ns=event,
        availability_ns=event if available is None else available,
        value_decimal=value,
        value_vector=vector,
        quality=quality,
        is_null=is_null,
    )


def _query(asof: int, *, feature: str = FEATURE, version: str = VERSION) -> FeatureQueryV1:
    return FeatureQueryV1(
        feature_name=feature,
        feature_version=version,
        instrument_id=INSTRUMENT,
        asof_ns=asof,
    )


def _assert_code(action: object, code: str) -> None:
    with pytest.raises(FeaturePersistenceError) as caught:
        action()  # type: ignore[operator]
    assert caught.value.code == code
    assert str(caught.value) == code
    assert caught.value.args == (code,)
    assert caught.value.__cause__ is None


def test_fake_backend_and_write_ack_are_typed_issued_commit_proofs() -> None:
    repo = _repo()
    assert repo.backend == "FAKE_NEON"
    ack = repo.insert_observations(ORG, DATASET, (_observation("k1", Decimal("1.25")),))
    assert require_feature_write_ack(ack) is ack
    assert (ack.backend, ack.boundary, ack.committed) == (
        "FAKE_NEON",
        "fake_transaction_commit",
        True,
    )
    assert (ack.inserted_count, ack.idempotent_count, ack.transaction_sequence) == (1, 0, 2)

    forged = FeatureWriteAckV1(
        transaction_sequence=ack.transaction_sequence,
        inserted_count=ack.inserted_count,
        idempotent_count=ack.idempotent_count,
    )
    with pytest.raises(SealError):
        require_feature_write_ack(forged)
    parsed = FeatureWriteAckV1.model_validate(ack.model_dump())
    assert parsed == ack and parsed is not ack
    with pytest.raises(SealError):
        require_feature_write_ack(parsed)


def test_ack_issuance_cannot_be_transferred_copied_reinitialized_or_tampered() -> None:
    ack = _repo().insert_observations(ORG, DATASET, (_observation("k1", Decimal("1")),))
    clone = ack.model_copy()
    assert clone == ack and clone is not ack
    with pytest.raises(SealError):
        require_feature_write_ack(clone)
    for action in (
        lambda: copy.copy(ack),
        lambda: copy.deepcopy(ack),
        lambda: pickle.dumps(ack),
        lambda: ack.copy(),
        lambda: FeatureWriteAckV1.model_construct(
            transaction_sequence=ack.transaction_sequence,
            inserted_count=ack.inserted_count,
            idempotent_count=ack.idempotent_count,
        ),
        lambda: BaseModel.__init__(
            ack,
            transaction_sequence=ack.transaction_sequence,
            inserted_count=ack.inserted_count,
            idempotent_count=ack.idempotent_count,
        ),
        lambda: ack.__setstate__({"__dict__": {"inserted_count": 999}}),
    ):
        with pytest.raises(SealError):
            action()

    with pytest.raises(SealError):
        ack.inserted_count = 999  # type: ignore[misc]
    with pytest.raises(SealError):
        del ack.inserted_count  # type: ignore[misc]
    assert require_feature_write_ack(ack) is ack
    object.__getattribute__(ack, "__dict__")["inserted_count"] = 999
    with pytest.raises(SealError):
        require_feature_write_ack(ack)


def test_org_dataset_policy_and_instrument_boundaries_prevent_orphan_or_cross_org_reads() -> None:
    repo = _repo()
    _assert_code(lambda: repo.register_dataset("missing-org", "other", "owner"), "ORG_NOT_FOUND")
    _assert_code(
        lambda: repo.insert_observations(
            ORG, DATASET, (_observation("wrong-instrument", Decimal("1"), instrument="ghost"),)
        ),
        "INSTRUMENT_NOT_FOUND",
    )
    _assert_code(
        lambda: repo.insert_observations(
            ORG, DATASET, (_observation("wrong-scope", Decimal("1"), dataset="other-dataset"),)
        ),
        "DATASET_SCOPE_MISMATCH",
    )
    _assert_code(
        lambda: repo.query_asof("other-org", DATASET, _query(10)), "DATASET_NOT_FOUND"
    )
    empty = NeonFeatureRepositoryV1()
    empty.register_org(ORG)
    empty.register_dataset(ORG, DATASET, "owner-a")
    _assert_code(
        lambda: empty.register_access_policy(
            ORG, DATASET, "bad-policy", "org", ORG, ("read", "read")
        ),
        "INVALID_POLICY",
    )
    with pytest.raises(FeaturePersistenceError) as caught:
        empty.publish_definition(
            ORG,
            DATASET,
            FeatureDefinitionV1(
                feature_name=FEATURE,
                feature_version=VERSION,
                value_kind="decimal",
                published=True,
            ),
            git_ref="git:synthetic",
            data_interval_start_ns=0,
            data_interval_end_ns=10,
        )
    assert caught.value.code == "ACCESS_POLICY_NOT_FOUND"


def test_definitions_are_idempotent_immutable_and_lineage_is_retrievable() -> None:
    repo = _repo()
    original = FeatureDefinitionV1(
        feature_name=FEATURE,
        feature_version=VERSION,
        value_kind="decimal",
        published=True,
    )
    first = repo.publish_definition(
        ORG,
        DATASET,
        original,
        git_ref="git:synthetic-0123456789abcdef",
        data_interval_start_ns=0,
        data_interval_end_ns=10_000,
    )
    assert (first.inserted_count, first.idempotent_count) == (0, 1)
    assert repo.get_definition(ORG, DATASET, FEATURE, VERSION) == original
    git_ref, start, end, definition_hash = repo.get_lineage(ORG, DATASET, FEATURE, VERSION)
    assert (git_ref, start, end, definition_hash) == (
        "git:synthetic-0123456789abcdef",
        0,
        10_000,
        original.semantic_hash,
    )
    _assert_code(
        lambda: repo.publish_definition(
            ORG,
            DATASET,
            FeatureDefinitionV1(
                feature_name=FEATURE,
                feature_version=VERSION,
                value_kind="vector",
                published=True,
            ),
            git_ref="git:synthetic-0123456789abcdef",
            data_interval_start_ns=0,
            data_interval_end_ns=10_000,
        ),
        "DEFINITION_CONFLICT",
    )


def test_asof_requires_event_and_availability_visibility_and_hides_late_corrections() -> None:
    repo = _repo()
    early = _observation("early", Decimal("1.0"), event=10, available=10)
    late_correction = _observation("correction", Decimal("2.0"), event=10, available=20)
    future_event = _observation("future-label", Decimal("99"), event=30, available=30)
    repo.insert_observations(ORG, DATASET, (early, late_correction, future_event))

    before_correction = repo.query_asof(ORG, DATASET, _query(19))
    at_correction = repo.query_asof(ORG, DATASET, _query(20))
    before_future_event = repo.query_asof(ORG, DATASET, _query(29))
    assert before_correction.value_decimal == Decimal("1")
    assert before_correction.availability_ns == 10
    assert at_correction.value_decimal == Decimal("2")
    assert at_correction.availability_ns == 20
    assert before_future_event.value_decimal == Decimal("2")

    exact_cutoff = repo.query_asof(ORG, DATASET, _query(30))
    assert exact_cutoff.value_decimal == Decimal("99")
    # A row with event time in range but knowledge time beyond as-of stays invisible.
    range_rows = repo.observations_in_range(
        ORG,
        DATASET,
        FEATURE,
        VERSION,
        INSTRUMENT,
        start_ns=10,
        end_ns=30,
        asof_ns=19,
    )
    assert range_rows == (early,)


def test_range_bounds_are_inclusive_and_results_have_deterministic_tie_order() -> None:
    repo = _repo()
    rows = (
        _observation("z", Decimal("3"), event=20, available=20),
        _observation("a", Decimal("1"), event=10, available=10),
        _observation("b", Decimal("2"), event=10, available=10),
        _observation("later-known", Decimal("4"), event=10, available=11),
        _observation("outside-start", Decimal("0"), event=9, available=9),
        _observation("outside-end", Decimal("5"), event=21, available=21),
    )
    repo.insert_observations(ORG, DATASET, rows)
    got = repo.observations_in_range(
        ORG,
        DATASET,
        FEATURE,
        VERSION,
        INSTRUMENT,
        start_ns=10,
        end_ns=20,
        asof_ns=20,
    )
    assert tuple(item.source_record_key for item in got) == ("a", "b", "later-known", "z")
    assert got[0].event_time_ns == 10 and got[-1].event_time_ns == 20


def test_batch_prevalidation_and_failpoint_leave_no_partial_values_visible() -> None:
    repo = _repo()
    _assert_code(
        lambda: repo.insert_observations(
            ORG,
            DATASET,
            (_observation("staged-first", Decimal("1")),),
            fail_before_commit=True,
        ),
        "FAKE_TRANSACTION_ABORTED",
    )
    _assert_code(
        lambda: repo.insert_observations(
            ORG,
            DATASET,
            (
                _observation("would-be-partial", Decimal("2")),
                _observation("wrong-scope", Decimal("3"), dataset="other"),
            ),
        ),
        "DATASET_SCOPE_MISMATCH",
    )
    assert repo.query_asof(ORG, DATASET, _query(100)).found is False
    assert repo.observations_in_range(
        ORG,
        DATASET,
        FEATURE,
        VERSION,
        INSTRUMENT,
        start_ns=0,
        end_ns=100,
        asof_ns=100,
    ) == ()


def test_same_source_key_and_semantic_hash_is_idempotent_but_changed_content_conflicts() -> None:
    repo = _repo()
    first = _observation("same-key", Decimal("1.00"))
    ack = repo.insert_observations(ORG, DATASET, (first, first))
    assert (ack.inserted_count, ack.idempotent_count) == (1, 1)
    equivalent_scale = _observation("same-key", Decimal("1.0"))
    repeated = repo.insert_observations(ORG, DATASET, (equivalent_scale,))
    assert (repeated.inserted_count, repeated.idempotent_count) == (0, 1)
    _assert_code(
        lambda: repo.insert_observations(
            ORG,
            DATASET,
            (_observation("same-key", Decimal("2")),),
        ),
        "OBSERVATION_CONFLICT",
    )
    assert repo.query_asof(ORG, DATASET, _query(100)).value_decimal == Decimal("1")


def test_decimal_vector_null_and_quality_values_roundtrip_without_precision_loss() -> None:
    repo = _repo()
    exact = Decimal("1234567890123456789012345678901234")
    with pytest.raises(ValidationError):
        _observation(
            "thirty-five-digit",
            Decimal("12345678901234567890123456789012345"),
            quality="verified",
        )
    with localcontext() as context:
        context.prec = 2
        repo.insert_observations(
            ORG,
            DATASET,
            (_observation("thirty-four-digit", exact, quality="verified"),),
        )
    got = repo.query_asof(ORG, DATASET, _query(10))
    assert got.value_decimal == exact
    assert got.quality == "verified"
    assert got.observation_hash == _observation(
        "thirty-four-digit", exact, quality="verified"
    ).semantic_hash

    vector_definition = FeatureDefinitionV1(
        feature_name="vector-x",
        feature_version="v1",
        value_kind="vector",
        published=True,
    )
    repo.publish_definition(
        ORG,
        DATASET,
        vector_definition,
        git_ref="git:vector-source",
        data_interval_start_ns=0,
        data_interval_end_ns=10_000,
    )
    vector = _observation(
        "vector-row",
        None,
        feature="vector-x",
        vector=(Decimal("1.20"), Decimal("-3.400"), exact),
        quality="estimated",
    )
    repo.insert_observations(ORG, DATASET, (vector,))
    vector_result = repo.query_asof(ORG, DATASET, _query(10, feature="vector-x"))
    assert vector_result.value_vector == (Decimal("1.2"), Decimal("-3.4"), exact)
    assert vector_result.quality == "estimated"

    null_definition = FeatureDefinitionV1(
        feature_name="nullable-x",
        feature_version="v1",
        value_kind="decimal",
        published=True,
    )
    repo.publish_definition(
        ORG,
        DATASET,
        null_definition,
        git_ref="git:null-source",
        data_interval_start_ns=0,
        data_interval_end_ns=10_000,
    )
    repo.insert_observations(
        ORG,
        DATASET,
        (_observation("null-row", None, feature="nullable-x", is_null=True, quality="missing"),),
    )
    null_result = repo.query_asof(ORG, DATASET, _query(10, feature="nullable-x"))
    assert null_result.found and null_result.is_null
    assert null_result.value_decimal is None and null_result.value_vector is None
    assert null_result.quality == "missing"


def test_invalid_input_errors_are_content_free_and_failpoints_are_strict_bools() -> None:
    repo = _repo()
    canary = "SECRET bad id\x00"
    with pytest.raises(FeaturePersistenceError) as caught:
        repo.register_org(canary)
    assert caught.value.code == "INVALID_IDENTITY"
    assert canary not in str(caught.value)
    assert canary not in repr(caught.value.args)
    with pytest.raises(ValidationError):
        _observation("too-large-exponent", Decimal("1e39"))
    _assert_code(
        lambda: repo.observations_in_range(
            ORG,
            DATASET,
            FEATURE,
            VERSION,
            INSTRUMENT,
            start_ns=True,  # type: ignore[arg-type]
            end_ns=10,
            asof_ns=10,
        ),
        "INVALID_UTC_NS",
    )
    with pytest.raises(FeaturePersistenceError) as caught_bool:
        repo.insert_observations(
            ORG,
            DATASET,
            (_observation("valid", Decimal("1")),),
            fail_before_commit=1,  # type: ignore[arg-type]
        )
    assert caught_bool.value.code == "INVALID_FAILPOINT"


def test_upstream_lineage_scopes_source_dataset_and_preserves_it_on_query() -> None:
    repo = _repo()
    repo.register_dataset(ORG, "upstream-a", "upstream-owner")
    repo.register_org("org-b")
    repo.register_dataset("org-b", "upstream-b", "other-owner")
    repo.register_dataset(ORG, "unlinked-a", "unlinked-owner")

    ack = repo.register_upstream_lineage(
        ORG, DATASET, FEATURE, VERSION, "upstream-a", "feature-job", "run-001"
    )
    assert ack.inserted_count == 1
    assert repo.get_upstream_lineage(ORG, DATASET, FEATURE, VERSION) == (
        ("upstream-a", "feature-job", "run-001"),
    )

    upstream = _observation(
        "upstream-row",
        Decimal("7.25"),
        dataset="upstream-a",
    )
    linked_ack = repo.insert_observations(ORG, DATASET, (upstream,))
    assert linked_ack.inserted_count == 1
    result = repo.query_asof(ORG, DATASET, _query(10))
    assert result.value_decimal == Decimal("7.25")
    assert result.source_dataset == "upstream-a"

    for bad_source in ("unlinked-a", "upstream-b"):
        with pytest.raises(FeaturePersistenceError) as caught:
            repo.insert_observations(
                ORG,
                DATASET,
                (_observation(f"unlinked-{bad_source}", Decimal("9"), dataset=bad_source),),
            )
        assert caught.value.code == "DATASET_SCOPE_MISMATCH"
    with pytest.raises(FeaturePersistenceError) as cross_org:
        repo.register_upstream_lineage(
            ORG, DATASET, FEATURE, VERSION, "upstream-b", "feature-job", "run-002"
        )
    assert cross_org.value.code == "DATASET_NOT_FOUND"
    assert repo.query_asof(ORG, DATASET, _query(10)).source_dataset == "upstream-a"


def test_observation_iterator_runtime_failure_is_sanitized_and_atomic() -> None:
    repo = _repo()
    canary = "SECRET_ITERATOR_PAYLOAD"

    def rows():
        yield _observation("valid-before-failure", Decimal("1.5"))
        raise RuntimeError(canary)

    with pytest.raises(FeaturePersistenceError) as caught:
        repo.insert_observations(ORG, DATASET, rows())
    assert caught.value.code == "INVALID_OBSERVATION"
    assert canary not in str(caught.value)
    assert canary not in repr(caught.value.args)
    assert caught.value.args == ("INVALID_OBSERVATION",)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert repo.query_asof(ORG, DATASET, _query(100)).found is False
    assert repo.observations_in_range(
        ORG,
        DATASET,
        FEATURE,
        VERSION,
        INSTRUMENT,
        start_ns=0,
        end_ns=100,
        asof_ns=100,
    ) == ()


def test_model_copy_observation_payload_is_sanitized_without_warning_or_commit() -> None:
    repo = _repo()
    canary = "SECRET_PYDANTIC_PAYLOAD"
    forged = _observation("tampered-row", Decimal("2.5")).model_copy(
        update={"event_time_ns": canary}
    )

    with warnings.catch_warnings(record=True) as emitted:
        warnings.simplefilter("always")
        with pytest.raises(FeaturePersistenceError) as caught:
            repo.insert_observations(ORG, DATASET, (forged,))

    assert not any(canary in str(warning.message) for warning in emitted)
    assert caught.value.code == "INVALID_OBSERVATION"
    assert canary not in str(caught.value)
    assert canary not in repr(caught.value.args)
    assert caught.value.args == ("INVALID_OBSERVATION",)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert repo.query_asof(ORG, DATASET, _query(100)).found is False
    assert repo.observations_in_range(
        ORG,
        DATASET,
        FEATURE,
        VERSION,
        INSTRUMENT,
        start_ns=0,
        end_ns=100,
        asof_ns=100,
    ) == ()


@pytest.mark.parametrize(
    ("entity", "bad_id"),
    [
        ("org", "org\nforged"),
        ("org", "org\r\nforged"),
        ("dataset", "dataset\nforged"),
        ("dataset", "dataset\r\nforged"),
        ("instrument", "instrument\nforged"),
        ("instrument", "instrument\r\nforged"),
    ],
)
def test_embedded_line_breaks_in_repository_ids_are_rejected(entity: str, bad_id: str) -> None:
    repo = NeonFeatureRepositoryV1()
    repo.register_org(ORG)
    with pytest.raises(FeaturePersistenceError) as caught:
        if entity == "org":
            repo.register_org(bad_id)
        elif entity == "dataset":
            repo.register_dataset(ORG, bad_id, "owner-a")
        else:
            repo.register_instrument(ORG, bad_id)
    assert caught.value.code == "INVALID_IDENTITY"
    assert bad_id not in str(caught.value)
    assert bad_id not in repr(caught.value.args)


def test_unknown_access_policy_subject_type_is_rejected() -> None:
    repo = NeonFeatureRepositoryV1()
    repo.register_org(ORG)
    repo.register_dataset(ORG, DATASET, "owner-a")
    for subject_type in ("org", "user", "service", "role"):
        repo.register_access_policy(
            ORG,
            DATASET,
            f"policy-{subject_type}",
            subject_type,
            f"subject-{subject_type}",
            ("read",),
        )
    with pytest.raises(FeaturePersistenceError) as caught:
        repo.register_access_policy(
            ORG, DATASET, "policy-unknown", "mystery-principal", "subject-a", ("read",)
        )
    assert caught.value.code == "INVALID_POLICY"


def test_migration_has_published_feature_version_update_and_delete_guards() -> None:
    migration = Path(__file__).parents[2] / "migrations" / "feature_001.sql"
    sql = migration.read_text(encoding="utf-8")
    for operation in ("UPDATE", "DELETE"):
        trigger = re.search(
            rf"CREATE\s+TRIGGER\s+[A-Za-z0-9_]+\s+BEFORE\s+{operation}\s+ON\s+"
            r"stor_feature_versions\b.*?EXECUTE\s+(?:FUNCTION|PROCEDURE)\s+([A-Za-z0-9_.]+)",
            sql,
            re.IGNORECASE | re.DOTALL,
        )
        assert trigger is not None, (
            f"feature-version migration must install a {operation} guard trigger"
        )
        function_name = re.escape(trigger.group(1).split(".")[-1])
        function = re.search(
            rf"CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+(?:[A-Za-z0-9_]+\.)?{function_name}\b"
            r".*?AS\s+\$\$(.*?)\$\$\s*;",
            sql,
            re.IGNORECASE | re.DOTALL,
        )
        assert function is not None, "trigger function body must be present in the migration"
        assert re.search(r"OLD\s*\.\s*published", function.group(1), re.IGNORECASE)
        assert re.search(r"RAISE\s+EXCEPTION", function.group(1), re.IGNORECASE)
