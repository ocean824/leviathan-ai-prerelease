"""Focused recurrence and checkpoint tests for the offline indicator kernel."""

from __future__ import annotations

import copy
import pickle
import tracemalloc
from dataclasses import FrozenInstanceError, replace
from decimal import Decimal, localcontext

import pytest

from leviathan_core.indicator_state import (
    FinalBarV1,
    IndicatorAvailabilityError,
    IndicatorCheckpointError,
    IndicatorConflictError,
    IndicatorDefinitionV1,
    IndicatorPrecisionExceededError,
    IndicatorResultV1,
    IndicatorStateV1,
    IndicatorValidationError,
    advance,
    batch,
    resume,
)
from leviathan_core.indicator_state.models import require_indicator_result
from leviathan_core.seal import SealError


def definition(kind: str, period: int | None) -> IndicatorDefinitionV1:
    return IndicatorDefinitionV1(
        kind=kind,
        period=period,
        formula_version="IND-FORMULA-v1",
        parameter_version="p1",
        instrument_id="ES",
        venue="CME",
        timeframe="1m",
        source_version="s1",
        adjustment_version="unadjusted",
        calendar_version="c1",
    )


def bar(
    index: int,
    close: str,
    *,
    high: str | None = None,
    low: str | None = None,
    volume: str | None = "1",
    session: str = "RTH1",
    availability_ns: int | None = None,
) -> FinalBarV1:
    end = index * 60_000_000_000
    return FinalBarV1(
        bar_id=f"bar{index}",
        instrument_id="ES",
        venue="CME",
        timeframe="1m",
        session_key=session,
        source_version="s1",
        adjustment_version="unadjusted",
        calendar_version="c1",
        bar_end_ns=end,
        event_time_ns=end,
        availability_ns=availability_ns or end,
        open=close,
        high=high or close,
        low=low or close,
        close=close,
        volume=volume,
    )


def test_ema_seed_and_prefix_parity() -> None:
    spec = definition("EMA", 3)
    bars = [bar(i, str(i)) for i in range(1, 5)]
    cutoff = bars[-1].availability_ns
    results = batch(bars, spec, cutoff)
    assert [item.value for item in results] == [None, None, Decimal("2"), Decimal("3")]
    state = None
    for size, item in enumerate(bars, start=1):
        state, point = advance(state, item, spec, cutoff)
        assert point.canonical_bytes() == batch(bars[:size], spec, cutoff)[-1].canonical_bytes()
        assert tuple(value.canonical_bytes() for value in state.results) == tuple(
            value.canonical_bytes() for value in batch(bars[:size], spec, cutoff)
        )
    assert state is not None
    assert resume(state, bars, spec, cutoff).input_digest == state.input_digest


def test_ema_repeating_alpha_is_not_rounded_before_smoothing() -> None:
    bars = [bar(1, "0.25"), bar(2, "0.75"), bar(3, "2.5")]
    values = batch(bars, definition("EMA", 2), bars[-1].availability_ns)
    assert values[1].value == Decimal("0.5")
    assert values[2].value == Decimal("1." + "8" + "3" * 32)


@pytest.mark.parametrize(
    ("closes", "expected", "quality"),
    [
        (["1", "2", "3"], Decimal("100"), ()),
        (["3", "2", "1"], Decimal("0"), ()),
        (["1", "1", "1"], None, ("FLAT_NO_MOVEMENT",)),
        (["1", "2", "1"], Decimal("50"), ()),
    ],
)
def test_rsi_wilder_edges(
    closes: list[str], expected: Decimal | None, quality: tuple[str, ...]
) -> None:
    bars = [bar(i, close) for i, close in enumerate(closes, start=1)]
    result = batch(bars, definition("RSI", 2), bars[-1].availability_ns)
    assert [item.value for item in result[:2]] == [None, None]
    assert result[-1].value == expected
    assert result[-1].quality_flags == quality


def test_rsi_uses_exact_current_average_ratio_before_output_rounding() -> None:
    bars = [bar(1, "10"), bar(2, "11"), bar(3, "8")]
    result = batch(bars, definition("RSI", 2), bars[-1].availability_ns)
    assert result[-1].value == Decimal("25")


def test_atr_wilder_reference() -> None:
    bars = [
        bar(1, "10", high="11", low="9"),
        bar(2, "12", high="13", low="10"),
        bar(3, "9", high="12", low="8"),
    ]
    assert [item.value for item in batch(bars, definition("ATR", 2), bars[-1].availability_ns)] == [
        None,
        Decimal("2.5"),
        Decimal("3.25"),
    ]


def test_atr_derived_output_may_be_smaller_than_input_magnitude_floor() -> None:
    low = Decimal("1E-38")
    first = replace(bar(1, "1"), open=low, high=Decimal("2E-38"), low=low, close=low)
    second = replace(bar(2, "1"), open=low, high=low, low=low, close=low)
    spec = definition("ATR", 2)
    cutoff = second.availability_ns
    expected = batch([first, second], spec, cutoff)
    assert expected[0].value is None
    assert expected[1].value == Decimal("5E-39")
    assert require_indicator_result(expected[1]).value == Decimal("5E-39")
    with pytest.raises(IndicatorValidationError, match="indicator number out of range"):
        replace(first, close=Decimal("5E-39"))
    state, _ = advance(None, first, spec, cutoff)
    state, result = advance(state, second, spec, cutoff)
    assert result.canonical_bytes() == expected[1].canonical_bytes()
    assert state.results == expected


def test_reinitializing_issued_indicator_result_is_rejected_without_mutation() -> None:
    items = [bar(1, "1"), bar(2, "2")]
    result = batch(items, definition("EMA", 2), items[-1].availability_ns)[-1]
    assert result.value == Decimal("1.5")
    before = result.canonical_bytes()

    with pytest.raises(SealError) as caught:
        IndicatorResultV1.__init__(
            result,
            value=Decimal("9"),
            warmup=result.warmup,
            gap=result.gap,
            late=result.late,
            invalid=result.invalid,
            sample_count=result.sample_count,
            bar_end_ns=result.bar_end_ns,
            bar_id=result.bar_id,
            input_digest=result.input_digest,
            revision=result.revision,
            definition_hash=result.definition_hash,
            formula_version=result.formula_version,
            quality_flags=result.quality_flags,
        )

    assert caught.value.code == "SEAL_FORBIDDEN_OPERATION"
    assert result.canonical_bytes() == before
    assert require_indicator_result(result) is result


def test_vwap_session_reset_and_zero_volume() -> None:
    bars = [
        bar(1, "10", volume="1"),
        bar(2, "20", volume="3"),
        bar(3, "5", volume="0", session="RTH2"),
        bar(4, "7", volume="2", session="RTH2"),
    ]
    values = batch(bars, definition("VWAP", None), bars[-1].availability_ns)
    assert [point.value for point in values] == [Decimal("10"), Decimal("17.5"), None, Decimal("7")]
    assert values[2].quality_flags == ("NO_VOLUME",)


def test_vwap_single_bar_keeps_repeating_typical_price_exact_until_output() -> None:
    first = bar(1, "1", high="2", low="1", volume="9")
    result = batch([first], definition("VWAP", None), first.availability_ns)
    assert result[0].value == Decimal("1." + "3" * 33)


def test_vwap_continuation_uses_scaled_exact_session_totals() -> None:
    spec = definition("VWAP", None)
    first = bar(1, "1", high="2", low="1", volume="9")
    second = bar(2, "4", high="5", low="3", volume="3")
    cutoff = second.availability_ns
    state, first_result = advance(None, first, spec, cutoff)
    state, second_result = advance(state, second, spec, cutoff)
    assert first_result.value == Decimal("1." + "3" * 33)
    assert second_result.value == Decimal("2")
    assert state._snapshots[-1].vwap_num == Decimal("72")
    assert state._snapshots[-1].vwap_den == Decimal("36")
    assert tuple(item.canonical_bytes() for item in state.results) == tuple(
        item.canonical_bytes() for item in batch([first, second], spec, cutoff)
    )


def test_vwap_missing_volume_is_distinct_from_zero_total() -> None:
    bars = [bar(1, "10", volume=None), bar(2, "20", volume="2")]
    values = batch(bars, definition("VWAP", None), bars[-1].availability_ns)
    assert values[0].value is None
    assert "MISSING_VOLUME" in values[0].quality_flags
    assert "NO_VOLUME" not in values[0].quality_flags
    assert values[1].value == Decimal("20")  # missing bar is excluded
    assert "GAP" not in values[1].quality_flags
    carrying = batch(
        [bar(1, "10", volume="2"), bar(2, "20", volume=None)],
        definition("VWAP", None),
        bars[-1].availability_ns,
    )[-1]
    assert carrying.value is None
    assert carrying.invalid and carrying.quality_flags == ("MISSING_VOLUME",)


def test_late_revision_and_future_availability() -> None:
    spec = definition("EMA", 2)
    first, second, third = (bar(i, str(i)) for i in range(1, 4))
    correction = replace(first, close=Decimal("10"), availability_ns=third.availability_ns + 1)
    early = batch([first, second, third, correction], spec, third.availability_ns)
    assert early[-1].value == Decimal("2.5")
    state = None
    for item in (first, second, third):
        state, _ = advance(state, item, spec, correction.availability_ns)
    assert state is not None
    with pytest.raises(IndicatorAvailabilityError):
        advance(state, correction, spec, third.availability_ns)
    revised, _ = advance(state, correction, spec, correction.availability_ns)
    expected = batch([first, second, third, correction], spec, correction.availability_ns)
    assert [item.canonical_bytes() for item in revised.results] == [
        item.canonical_bytes() for item in expected
    ]
    assert revised.results[0].late
    assert revised.revision == 1
    assert state.results[-1].value == Decimal("2.5")


def test_resume_rebuilds_mismatched_checkpoint_and_adds_newly_available_bar() -> None:
    spec = definition("EMA", 2)
    first = bar(1, "1")
    second = bar(2, "2")
    checkpoint, _ = advance(None, first, spec, first.availability_ns)
    other_checkpoint, _ = advance(None, bar(1, "3"), spec, first.availability_ns)
    rebuilt = resume(
        other_checkpoint,
        [first, second],
        spec,
        second.availability_ns,
    )
    assert rebuilt.results[-1].value == Decimal("1.5")
    assert rebuilt.input_digest != checkpoint.input_digest
    resumed = resume(checkpoint, [first, second], spec, second.availability_ns)
    assert resumed.input_digest == rebuilt.input_digest


def test_replaced_checkpoint_cannot_corrupt_ema_history() -> None:
    spec = definition("EMA", 2)
    first, second = bar(1, "1"), bar(2, "1")
    checkpoint, _ = advance(None, first, spec, first.availability_ns)
    changed_first = replace(first, close=Decimal("2"))
    with pytest.raises(IndicatorCheckpointError):
        replace(checkpoint, bars=(changed_first,))
    with pytest.raises(IndicatorCheckpointError):
        replace(checkpoint, _snapshots=())
    with pytest.raises(IndicatorCheckpointError):
        IndicatorStateV1(
            bars=checkpoint.bars,
            results=checkpoint.results,
            input_digest=checkpoint.input_digest,
            definition_hash=checkpoint.definition_hash,
            last_bar_id=checkpoint.last_bar_id,
            revision=checkpoint.revision,
            asof_ns=checkpoint.asof_ns,
        )
    state, point = advance(checkpoint, second, spec, second.availability_ns)
    assert point.value == Decimal("1")
    assert state.bars == (first, second)
    assert batch([changed_first, second], spec, second.availability_ns)[-1].value == Decimal("1.5")


def test_public_objects_reject_copy_deepcopy_and_pickle() -> None:
    spec = definition("EMA", 2)
    item = bar(1, "1")
    state, result = advance(None, item, spec, item.availability_ns)
    for value in (spec, item, result, state):
        for operation in (copy.copy, copy.deepcopy, pickle.dumps):
            with pytest.raises(IndicatorValidationError):
                operation(value)


def test_bad_batch_definition_has_typed_redacted_error() -> None:
    with pytest.raises(IndicatorValidationError) as error:
        batch([], "SENSITIVE-DEFINITION", 200)  # type: ignore[arg-type]
    assert "SENSITIVE" not in str(error.value)


def test_precision_boundary_never_rounds_input_and_ignores_ambient_context() -> None:
    spec = definition("EMA", 2)
    first = bar(1, "100")
    second = bar(2, "102")
    baseline = batch([first, second], spec, second.availability_ns)
    with pytest.raises(IndicatorPrecisionExceededError, match="PRECISION_EXCEEDED"):
        replace(first, close="1." + "2" * 34)
    assert replace(first, close="1." + "0" * 50).close == Decimal("1")
    with localcontext() as ambient:
        ambient.prec = 2
        ambient.Emax = 0
        result = batch([first, second], spec, second.availability_ns)
    assert [item.canonical_bytes() for item in result] == [
        item.canonical_bytes() for item in baseline
    ]


def test_compact_huge_exponent_is_rejected_before_expansion() -> None:
    compact = Decimal("1E+100000")
    tracemalloc.start()
    try:
        with pytest.raises(IndicatorValidationError, match="indicator number out of range"):
            replace(bar(1, "1"), close=compact)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 500_000


def test_stored_vwap_volume_and_ema_seed_never_round() -> None:
    huge = "9" * 34
    vwap_bars = [bar(1, "1", volume=huge), bar(2, "1", volume="2")]
    with pytest.raises(IndicatorPrecisionExceededError, match="PRECISION_EXCEEDED"):
        batch(vwap_bars, definition("VWAP", None), vwap_bars[-1].availability_ns)
    ema_bars = [bar(1, huge), bar(2, "2")]
    with pytest.raises(IndicatorPrecisionExceededError, match="PRECISION_EXCEEDED"):
        batch(ema_bars, definition("EMA", 2), ema_bars[-1].availability_ns)


def test_exponent_34_is_one_significant_digit() -> None:
    compact = Decimal("1E+34")
    expanded = "1" + "0" * 34
    first = bar(1, "1")
    left = replace(first, close=compact)
    right = replace(first, close=expanded)
    assert left.close == compact
    assert left.semantic_hash == right.semantic_hash


def test_correction_older_than_retained_checkpoint_replays_from_source() -> None:
    spec = definition("EMA", 2)
    bars = [bar(i, str(i)) for i in range(1, 7)]
    cutoff = bars[-1].availability_ns + 1
    state = None
    for item in bars:
        state, _ = advance(state, item, spec, cutoff)
    assert state is not None and state._checkpoint_start > 0
    correction = replace(bars[0], close=Decimal("10"), availability_ns=cutoff)
    revised, _ = advance(state, correction, spec, cutoff)
    expected = batch([*bars, correction], spec, cutoff)
    assert [point.canonical_bytes() for point in revised.results] == [
        point.canonical_bytes() for point in expected
    ]


def test_redacted_validation_conflict_and_deep_freeze() -> None:
    spec = definition("EMA", 2)
    item = bar(1, "1")
    with pytest.raises(IndicatorValidationError) as error:
        replace(item, instrument_id="SECRET bad id")
    assert "SECRET" not in str(error.value)
    state, _ = advance(None, item, spec, item.availability_ns)
    with pytest.raises(FrozenInstanceError):
        state.bars = ()  # type: ignore[misc]
    with pytest.raises(IndicatorValidationError):
        replace(state, bars=[item])  # type: ignore[arg-type]
    with pytest.raises(IndicatorValidationError):
        result = state.results[0]
        IndicatorResultV1(
            value=result.value,
            warmup=result.warmup,
            gap=result.gap,
            late=result.late,
            invalid=result.invalid,
            sample_count=result.sample_count,
            bar_end_ns=result.bar_end_ns,
            bar_id=result.bar_id,
            input_digest=result.input_digest,
            revision=result.revision,
            definition_hash=result.definition_hash,
            formula_version=result.formula_version,
            quality_flags=["WARMUP"],  # type: ignore[arg-type]
        )
    with pytest.raises(IndicatorConflictError):
        advance(state, replace(item, close=Decimal("2")), spec, item.availability_ns)
