from __future__ import annotations

import copy
import pickle
from datetime import UTC, datetime, timedelta
from decimal import Decimal, Inexact, localcontext

import pytest

from leviathan_core.signal.signal_models import (
    ConfirmedStructurePivot,
    FinalizedStructureBar,
    SignalQuality,
    StructureContext,
    StructureEvaluation,
    StructureEvaluationError,
)
from leviathan_core.signal.structure_events import evaluate_structure

BAR_CLOSE = datetime(2026, 1, 5, 15, 0, tzinfo=UTC)
PIVOT_TIME = BAR_CLOSE - timedelta(minutes=2)
PIVOT_CONFIRMED = BAR_CLOSE - timedelta(minutes=1)


def make_context(*, detector_version: str = "1.0.0") -> StructureContext:
    return StructureContext(
        symbol="NQH6",
        venue="CME",
        timeframe="1m",
        detector_id="structure-v1",
        detector_version=detector_version,
    )


def make_bar(
    *, close: Decimal = Decimal("111"), input_version: str = "input-1"
) -> FinalizedStructureBar:
    return FinalizedStructureBar(
        bar_id="bar-1",
        close_time=BAR_CLOSE,
        previous_close=Decimal("109"),
        close=close,
        input_version=input_version,
    )


def make_pivot(
    *,
    pivot_id: str = "pivot-high-1",
    price: Decimal = Decimal("110"),
    pivot_time: datetime = PIVOT_TIME,
    confirmed_at: datetime = PIVOT_CONFIRMED,
) -> ConfirmedStructurePivot:
    return ConfirmedStructurePivot(
        pivot_id=pivot_id,
        kind="high",
        pivot_time=pivot_time,
        confirmed_at=confirmed_at,
        price=price,
        feature_version="features-1",
    )


def make_evaluation(
    *,
    close: Decimal = Decimal("111"),
    pivots: tuple[ConfirmedStructurePivot, ...] | None = None,
    observed_at: datetime = BAR_CLOSE + timedelta(milliseconds=10),
    input_version: str = "input-1",
    detector_version: str = "1.0.0",
) -> StructureEvaluation:
    return StructureEvaluation(
        context=make_context(detector_version=detector_version),
        bar=make_bar(close=close, input_version=input_version),
        pivots=(make_pivot(),) if pivots is None else pivots,
        observed_at=observed_at,
    )


def _json(signal: object) -> dict[str, object]:
    return signal.model_dump(mode="json")  # type: ignore[attr-defined,no-any-return]


def test_finalized_crossing_emits_one_exact_decimal_signal() -> None:
    first = evaluate_structure(make_evaluation())
    replay = evaluate_structure(make_evaluation(), history=first)

    assert len(first) == 1
    assert first[0].kind == "INITIAL"
    assert first[0].detector_type in {"msb", "bos"}
    assert first[0].direction == "bull"
    assert first[0].broken_level == Decimal("110")
    assert first[0].bar_close == BAR_CLOSE
    assert first[0].finalized is True
    assert first[0].confidence == Decimal("1")
    assert first[0].dedupe_key
    assert replay == ()


def test_close_must_strictly_break_pivot_and_exact_comparison_has_no_float_rounding() -> None:
    at_level = evaluate_structure(make_evaluation(close=Decimal("110.00")))
    above_level = evaluate_structure(make_evaluation(close=Decimal("110.0000000000000000001")))

    assert at_level == ()
    assert len(above_level) == 1
    assert above_level[0].broken_level == Decimal("110")


def test_pivot_confirmed_after_bar_close_is_never_used() -> None:
    future_confirmed = make_pivot(confirmed_at=BAR_CLOSE + timedelta(microseconds=1))
    future_by_pivot_time = make_pivot(
        pivot_time=BAR_CLOSE + timedelta(microseconds=1),
        confirmed_at=BAR_CLOSE + timedelta(seconds=1),
    )

    assert evaluate_structure(make_evaluation(pivots=(future_confirmed,))) == ()
    assert evaluate_structure(make_evaluation(pivots=(future_by_pivot_time,))) == ()


def test_ingest_time_is_excluded_from_semantic_identity() -> None:
    early = evaluate_structure(make_evaluation(observed_at=BAR_CLOSE + timedelta(milliseconds=5)))
    late = evaluate_structure(make_evaluation(observed_at=BAR_CLOSE + timedelta(seconds=1)))

    assert len(early) == len(late) == 1
    assert early[0].dedupe_key == late[0].dedupe_key
    assert early[0].id == late[0].id
    assert early[0].ts_ingest != late[0].ts_ingest


def test_revised_signal_references_prior_and_does_not_mutate_history() -> None:
    original = evaluate_structure(make_evaluation())[0]
    before = _json(original)

    revision = evaluate_structure(
        make_evaluation(close=Decimal("112"), input_version="input-2"),
        history=(original,),
    )

    assert len(revision) == 1
    assert revision[0].kind == "REVISION"
    assert revision[0].revision_of == original.id
    assert revision[0].broken_level == original.broken_level
    assert _json(original) == before


def test_invalidated_final_signal_emits_tombstone_with_lineage() -> None:
    original = evaluate_structure(make_evaluation())[0]

    tombstone = evaluate_structure(
        make_evaluation(close=Decimal("109"), input_version="input-2"),
        history=(original,),
    )

    assert len(tombstone) == 1
    assert tombstone[0].kind == "TOMBSTONE"
    assert tombstone[0].revision_of == original.id
    assert original.kind == "INITIAL"


def test_future_ingested_history_does_not_suppress_point_in_time_initial() -> None:
    as_of = BAR_CLOSE + timedelta(milliseconds=5)
    future_ingested = evaluate_structure(
        make_evaluation(observed_at=BAR_CLOSE + timedelta(seconds=1))
    )[0]
    current = evaluate_structure(
        make_evaluation(observed_at=as_of),
        history=(future_ingested,),
    )

    assert future_ingested.bar_close <= as_of
    assert future_ingested.ts_ingest > as_of
    assert len(current) == 1
    assert current[0].kind == "INITIAL"
    assert current[0].revision_of is None


def test_detector_version_is_identity_and_revisions_stay_within_version() -> None:
    version_one = evaluate_structure(make_evaluation())[0]
    version_two = evaluate_structure(
        make_evaluation(detector_version="2.0.0"),
        history=(version_one,),
    )[0]
    same_version_revision = evaluate_structure(
        make_evaluation(close=Decimal("112"), input_version="input-2"),
        history=(version_one,),
    )[0]

    assert version_one.kind == "INITIAL"
    assert version_two.kind == "INITIAL"
    assert version_two.detector_version == "2.0.0"
    assert version_two.dedupe_key != version_one.dedupe_key
    assert version_two.revision_of is None
    assert same_version_revision.kind == "REVISION"
    assert same_version_revision.detector_version == version_one.detector_version
    assert same_version_revision.revision_of == version_one.id


def test_pivot_permutation_and_numeric_spelling_preserve_output_identity() -> None:
    older = make_pivot(
        pivot_id="pivot-high-older",
        price=Decimal("105.00"),
        pivot_time=BAR_CLOSE - timedelta(minutes=3),
        confirmed_at=BAR_CLOSE - timedelta(minutes=2),
    )
    latest = make_pivot(price=Decimal("110.0"))
    left = evaluate_structure(make_evaluation(pivots=(older, latest)))[0]
    right = evaluate_structure(
        make_evaluation(pivots=(make_pivot(price=Decimal("110.00")), older))
    )[0]

    assert left.id == right.id
    assert left.dedupe_key == right.dedupe_key
    assert left.broken_level == right.broken_level == Decimal("110")


def test_input_models_are_immutable_and_block_copy_pickle_and_pydantic_bypasses() -> None:
    context = make_context()

    for operation in (
        lambda: copy.copy(context),
        lambda: copy.deepcopy(context),
        lambda: pickle.dumps(context),
        lambda: context.model_copy(update={"symbol": "ES"}),
        lambda: StructureContext.model_construct(symbol="ES"),
    ):
        with pytest.raises(StructureEvaluationError):
            operation()

    with pytest.raises(StructureEvaluationError):
        context.symbol = "ES"  # type: ignore[misc]


def test_decimal_inputs_reject_float_and_more_than_34_significant_digits() -> None:
    with pytest.raises(StructureEvaluationError) as float_error:
        make_bar(close=1.1)  # type: ignore[arg-type]
    assert float_error.value.code == "UNPROCESSABLE_INPUT"
    assert float_error.value.error_type == "INVALID_DECIMAL"

    raw = "1.2345678901234567890123456789012345"
    with pytest.raises(StructureEvaluationError) as error:
        make_pivot(price=Decimal(raw))

    assert error.value.error_type == "PRECISION_EXCEEDED"
    assert raw not in error.value.json()


def test_decimal_magnitude_is_rejected_before_expansion_and_1e34_is_valid() -> None:
    accepted = make_pivot(price=Decimal("1E+34"))
    assert accepted.price == Decimal("1E+34")

    with pytest.raises(StructureEvaluationError) as error:
        make_pivot(price=Decimal("1E+100000"))

    assert error.value.error_type == "MAGNITUDE_EXCEEDED"
    assert error.value.json()


def test_public_model_validation_raises_content_free_typed_error() -> None:
    raw = "1.2345678901234567890123456789012345"

    with pytest.raises(StructureEvaluationError) as error:
        make_pivot(price=Decimal(raw))

    assert raw not in str(error.value)
    assert raw not in repr(error.value.args)
    assert set(error.value.errors()[0]) == {"loc", "type", "code"}
    assert raw not in error.value.json()


def test_bool_is_rejected_for_integer_fields_and_policy_like_context_revalidates() -> None:
    with pytest.raises(StructureEvaluationError):
        SignalQuality(
            late_data=False,
            gap=False,
            stale_input=False,
            source_lag_ms=True,  # type: ignore[arg-type]
        )

    with pytest.raises(StructureEvaluationError):
        StructureContext(
            symbol="NQH6",
            venue="CME",
            timeframe="1m",
            detector_id="structure-v1",
            detector_version="",
        )


def test_decimal_evaluation_is_independent_of_ambient_context() -> None:
    normal = evaluate_structure(make_evaluation())
    with localcontext() as context:
        context.prec = 2
        context.traps[Inexact] = True
        constrained = evaluate_structure(make_evaluation())

    assert normal[0].id == constrained[0].id
    assert normal[0].broken_level == constrained[0].broken_level
