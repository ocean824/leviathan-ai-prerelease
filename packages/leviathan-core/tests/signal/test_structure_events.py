import copy
import pickle
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest

from leviathan_core.signal.signal_models import (
    ConfirmedStructurePivot,
    FinalizedStructureBar,
    StructureContext,
    StructureEvaluation,
    StructureEvaluationError,
    StructureGapNoticeV1,
    StructureSignalV1,
)
from leviathan_core.signal.structure_events import evaluate_structure

_CLOSE = datetime(2026, 9, 30, 15, 0, tzinfo=UTC)
_CONTEXT = StructureContext(
    symbol="NQ", venue="XCME", timeframe="1m", detector_id="structure", detector_version="1"
)


def _evaluation(
    *,
    previous_close: str = "100",
    close: str = "111",
    bar_id: str = "bar-1",
    observed_at: datetime = _CLOSE,
    close_time: datetime = _CLOSE,
    context: StructureContext = _CONTEXT,
    pivots: tuple[ConfirmedStructurePivot, ...] | None = None,
    input_version: str = "input-v1",
    gap: bool = False,
    stale_input: bool = False,
) -> StructureEvaluation:
    if pivots is None:
        pivots = (
            ConfirmedStructurePivot(
                pivot_id="pivot-1",
                kind="high",
                pivot_time=_CLOSE - timedelta(minutes=3),
                confirmed_at=_CLOSE - timedelta(minutes=1),
                price=Decimal("110"),
                feature_version="feature-v1",
            ),
        )
    return StructureEvaluation(
        context=context,
        bar=FinalizedStructureBar(
            bar_id=bar_id,
            close_time=close_time,
            previous_close=Decimal(previous_close),
            close=Decimal(close),
            input_version=input_version,
            gap=gap,
            stale_input=stale_input,
        ),
        pivots=pivots,
        observed_at=observed_at,
    )


def test_final_break_has_level_and_semantic_replay_identity() -> None:
    # Given a finalized close crossing a confirmed high.
    evaluation = _evaluation()

    # When the same input is evaluated again with a later ingest time.
    first = evaluate_structure(evaluation)
    repeated = evaluate_structure(_evaluation(observed_at=_CLOSE + timedelta(seconds=1)))

    # Then its economic identity is stable, and history suppresses a duplicate.
    assert len(first) == len(repeated) == 1
    assert isinstance(first[0], StructureSignalV1)
    assert first[0].direction == "bull"
    assert first[0].broken_level == Decimal("110")
    assert first[0].dedupe_key == repeated[0].dedupe_key
    assert evaluate_structure(evaluation, first) == ()


def test_pivot_confirmed_after_bar_close_is_ineligible() -> None:
    # Given a pivot whose confirmation arrives after the evaluated close.
    future = ConfirmedStructurePivot(
        pivot_id="future",
        kind="high",
        pivot_time=_CLOSE - timedelta(minutes=3),
        confirmed_at=_CLOSE + timedelta(microseconds=1),
        price=Decimal("110"),
        feature_version="feature-v1",
    )

    # When the bar is evaluated.
    events = evaluate_structure(_evaluation(pivots=(future,)))

    # Then no historical break uses that future confirmation.
    assert events == ()


def test_revision_then_tombstone_preserves_original() -> None:
    # Given an original break followed by a timely bar correction.
    initial = evaluate_structure(_evaluation())
    revised = evaluate_structure(_evaluation(close="112", input_version="input-v2"), initial)

    # When the correction removes the crossing altogether.
    cancelled = evaluate_structure(
        _evaluation(close="109", input_version="input-v3"), initial + revised
    )

    # Then each change is an immutable event referencing its predecessor.
    assert isinstance(initial[0], StructureSignalV1)
    assert isinstance(revised[0], StructureSignalV1)
    assert isinstance(cancelled[0], StructureSignalV1)
    assert revised[0].kind == "REVISION"
    assert revised[0].revision_of == initial[0].id
    assert cancelled[0].kind == "TOMBSTONE"
    assert cancelled[0].revision_of == revised[0].id
    assert initial[0].broken_level == Decimal("110")


def test_late_revision_emits_deduplicated_gap_notice() -> None:
    # Given a bar correction arriving after its watermark.
    initial = evaluate_structure(_evaluation())
    late = _evaluation(close="109", observed_at=_CLOSE + timedelta(seconds=3))

    # When it is evaluated against the prior signal.
    notices = evaluate_structure(late, initial)

    # Then the ignored correction remains observable without replacing history.
    assert len(notices) == 1
    assert isinstance(notices[0], StructureGapNoticeV1)
    assert notices[0].quality.gap is True
    assert notices[0].revision_of == initial[0].id
    assert evaluate_structure(late, initial + notices) == ()


def test_changed_ingest_time_outside_watermark_remains_duplicate() -> None:
    # Given an unchanged signal evaluated long after the bar close.
    initial = evaluate_structure(_evaluation())

    # When only the injected observation time changes.
    repeated = evaluate_structure(_evaluation(observed_at=_CLOSE + timedelta(days=1)), initial)

    # Then ingest time cannot create a revision or gap notice.
    assert repeated == ()


def test_opposite_break_invalidates_prior_signal() -> None:
    # Given a bullish break and a later confirmed low.
    initial = evaluate_structure(_evaluation())
    low = ConfirmedStructurePivot(
        pivot_id="low-1",
        kind="low",
        pivot_time=_CLOSE - timedelta(minutes=2),
        confirmed_at=_CLOSE,
        price=Decimal("90"),
        feature_version="feature-v1",
    )

    # When a subsequent finalized close crosses below the low.
    opposite = evaluate_structure(
        _evaluation(
            bar_id="bar-2",
            previous_close="111",
            close="89",
            close_time=_CLOSE + timedelta(minutes=1),
            observed_at=_CLOSE + timedelta(minutes=1),
            pivots=(low,),
        ),
        initial,
    )

    # Then the old signal is tombstoned and the new bearish break is emitted.
    assert len(opposite) == 2
    assert isinstance(opposite[0], StructureSignalV1)
    assert opposite[0].kind == "TOMBSTONE"
    assert opposite[0].revision_of == initial[0].id
    assert isinstance(opposite[1], StructureSignalV1)
    assert opposite[1].direction == "bear"
    assert opposite[1].detector_type == "msb"


def test_future_tombstone_cannot_revise_an_earlier_bar() -> None:
    # Given an earlier bullish break and a later bearish invalidation.
    initial = evaluate_structure(_evaluation())
    low = ConfirmedStructurePivot(
        pivot_id="low-1",
        kind="low",
        pivot_time=_CLOSE - timedelta(minutes=2),
        confirmed_at=_CLOSE,
        price=Decimal("90"),
        feature_version="feature-v1",
    )
    future = evaluate_structure(
        _evaluation(
            bar_id="bar-2",
            previous_close="111",
            close="89",
            close_time=_CLOSE + timedelta(minutes=1),
            observed_at=_CLOSE + timedelta(minutes=1),
            pivots=(low,),
        ),
        initial,
    )

    # When the earlier bar is replayed with that future history present.
    replayed = evaluate_structure(_evaluation(), initial + future)

    # Then the future tombstone cannot change the earlier result.
    assert replayed == ()


def test_future_ingested_history_cannot_suppress_earlier_asof_signal() -> None:
    # Given an event ingested after an earlier evaluation's as-of time.
    later = evaluate_structure(_evaluation(observed_at=_CLOSE + timedelta(milliseconds=100)))

    # When the same bar is evaluated as of an earlier ingest time.
    earlier = evaluate_structure(
        _evaluation(observed_at=_CLOSE + timedelta(milliseconds=10)), later
    )

    # Then future history cannot suppress the initial signal.
    assert len(earlier) == 1
    assert isinstance(earlier[0], StructureSignalV1)
    assert earlier[0].kind == "INITIAL"


def test_new_detector_version_starts_independent_signal_lineage() -> None:
    # Given a finalized break under detector version one.
    initial = evaluate_structure(_evaluation())
    next_context = StructureContext(
        symbol="NQ", venue="XCME", timeframe="1m", detector_id="structure", detector_version="2"
    )

    # When the same bar is evaluated under detector version two.
    next_version = evaluate_structure(_evaluation(context=next_context), initial)

    # Then it begins an independent initial event and semantic key.
    assert len(next_version) == 1
    assert isinstance(next_version[0], StructureSignalV1)
    assert next_version[0].kind == "INITIAL"
    assert next_version[0].revision_of is None
    assert next_version[0].dedupe_key != initial[0].dedupe_key


def test_gap_and_stale_quality_are_preserved() -> None:
    # Given an input bar marked with gap and stale provenance.
    evaluation = _evaluation(gap=True, stale_input=True)

    # When a break is emitted.
    events = evaluate_structure(evaluation)

    # Then consumers receive the quality facts on the event.
    assert events[0].quality.gap is True
    assert events[0].quality.stale_input is True


def test_models_reject_copy_pickle_and_validation_bypass() -> None:
    # Given an immutable public input model.
    bar = _evaluation().bar

    # When copy and construction bypasses are attempted, then all are rejected.
    with pytest.raises(StructureEvaluationError):
        copy.copy(bar)
    with pytest.raises(StructureEvaluationError):
        copy.deepcopy(bar)
    with pytest.raises(StructureEvaluationError):
        pickle.dumps(bar)
    with pytest.raises(StructureEvaluationError):
        bar.model_copy(update={"close": Decimal("NaN")})
    with pytest.raises(StructureEvaluationError):
        FinalizedStructureBar.model_construct(bar_id="bypass")


@pytest.mark.parametrize("price", [float("nan"), float("inf"), 110.0, Decimal("NaN")])
def test_float_or_nonfinite_price_is_rejected(price: Decimal | float) -> None:
    # Given an untrusted noncanonical price.
    # When it crosses the model boundary, then it is rejected.
    with pytest.raises(StructureEvaluationError):
        ConfirmedStructurePivot.model_validate(
            {
                "pivot_id": "bad",
                "kind": "high",
                "pivot_time": _CLOSE - timedelta(minutes=3),
                "confirmed_at": _CLOSE - timedelta(minutes=1),
                "price": price,
                "feature_version": "feature-v1",
            }
        )


def test_public_validation_error_redacts_decimal_input() -> None:
    # Given a price whose coefficient exceeds the working precision.
    invalid_price = Decimal("1" * 35)

    # When the public constructor validates it.
    with pytest.raises(StructureEvaluationError) as caught:
        FinalizedStructureBar(
            bar_id="bar-redact",
            close_time=_CLOSE,
            previous_close=Decimal("1"),
            close=invalid_price,
            input_version="v1",
        )

    # Then every public error view carries codes and location, never the price.
    error = caught.value
    assert error.code == "UNPROCESSABLE_INPUT"
    assert error.loc == ("close",)
    assert error.error_type == "PRECISION_EXCEEDED"
    assert set(error.errors()[0]) == {"loc", "type", "code"}
    assert str(invalid_price) not in f"{error} {error.args} {error.errors()} {error.json()}"


def test_unknown_field_name_is_redacted_from_error_location() -> None:
    # Given a caller-controlled extra key containing a secret.
    secret = "SENSITIVE_KEY_123"

    # When the model_validate boundary parses the mapping.
    with pytest.raises(StructureEvaluationError) as caught:
        StructureContext.model_validate(
            {
                "symbol": "NQ",
                "venue": "XCME",
                "timeframe": "1m",
                "detector_id": "structure",
                "detector_version": "1",
                secret: "SENSITIVE_VALUE_456",
            }
        )

    # Then the location is structural and neither key nor value is exposed.
    error = caught.value
    assert error.loc == ("unknown_field",)
    assert secret not in f"{error} {error.args} {error.errors()} {error.json()}"
    assert "SENSITIVE_VALUE_456" not in error.json()
