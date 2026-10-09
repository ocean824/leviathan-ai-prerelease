"""Independent contract tests for the offline indicator parity kernel."""

from __future__ import annotations

import copy
import json
import pickle
from dataclasses import replace
from decimal import Decimal
from pathlib import Path

import pytest

from leviathan_core.indicator_state import (
    FinalBarV1,
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

FIXTURES = Path(__file__).parent / "fixtures" / "kernel"
VECTORS = json.loads((FIXTURES / "reference_vectors.json").read_text(encoding="utf-8"))
ASOF = 10_000


def _definition(kind: str, period: int | None = 2) -> IndicatorDefinitionV1:
    return IndicatorDefinitionV1(
        kind=kind,
        period=period,
        formula_version="IND-FORMULA-v1",
        parameter_version="test-parameters-v1",
        instrument_id="SYNTH:TEST",
        venue="SYNTH",
        timeframe="1m",
        source_version="synthetic-source-v1",
        adjustment_version="unadjusted-v1",
        calendar_version="synthetic-calendar-v1",
    )


def _bar(
    i: int,
    *,
    close: str | Decimal,
    high: str | None = None,
    low: str | None = None,
    open_: str | None = None,
    volume: str | None = "1",
    session: str = "session-a",
    availability: int | None = None,
    source: str = "synthetic-source-v1",
    adjustment: str = "unadjusted-v1",
    finalized: bool = True,
    gap: bool = False,
) -> FinalBarV1:
    c = Decimal(close)
    return FinalBarV1(
        bar_id=f"bar-{i}",
        instrument_id="SYNTH:TEST",
        venue="SYNTH",
        timeframe="1m",
        session_key=session,
        source_version=source,
        adjustment_version=adjustment,
        calendar_version="synthetic-calendar-v1",
        bar_end_ns=i * 60,
        event_time_ns=i * 60,
        availability_ns=i * 60 if availability is None else availability,
        open=c if open_ is None else Decimal(open_),
        high=None if high is None else Decimal(high),
        low=None if low is None else Decimal(low),
        close=c,
        volume=None if volume is None else Decimal(volume),
        finalized=finalized,
        gap=gap,
    )


def _close_bars(values: list[str]) -> list[FinalBarV1]:
    return [_bar(i + 1, close=value, high=value, low=value) for i, value in enumerate(values)]


def _vwap_bars() -> list[FinalBarV1]:
    rows = VECTORS["vwap_session_reset"]["ohlcv"]
    sessions = VECTORS["vwap_session_reset"]["session_keys"]
    return [
        _bar(
            i + 1,
            open_=open_value,
            high=high_value,
            low=low_value,
            close=close_value,
            volume=volume,
            session=sessions[i],
        )
        for i, (open_value, high_value, low_value, close_value, volume) in enumerate(rows)
    ]


@pytest.mark.parametrize(
    ("kind", "values_key"),
    [("EMA", "ema_n2"), ("RSI", "rsi_n2")],
)
def test_reference_values_match_frozen_formula_v1(kind: str, values_key: str) -> None:
    vector = VECTORS[values_key]
    results = batch(_close_bars(vector["closes"]), _definition(kind, vector["period"]), ASOF)
    assert [result.value for result in results] == [
        None if value is None or value == "null" else Decimal(value)
        for value in vector["expected"]
    ]


@pytest.mark.parametrize(
    ("series", "expected_key"),
    [
        ("flat_closes", "flat"),
        ("gain_only_closes", "gain_only"),
        ("loss_only_closes", "loss_only"),
    ],
)
def test_rsi_wilder_zero_gain_loss_edges_are_explicit(series: str, expected_key: str) -> None:
    vector = VECTORS["rsi_edges_n2"]
    results = batch(_close_bars(vector[series]), _definition("RSI", vector["period"]), ASOF)
    expected = vector["expected"][expected_key]
    assert results[-1].value == (None if expected is None else Decimal(expected))
    if expected_key == "flat":
        assert results[-1].invalid
        assert "FLAT_NO_MOVEMENT" in results[-1].quality_flags
    else:
        assert not results[-1].invalid


def test_atr_wilder_reference_values_and_missing_high_low_quality() -> None:
    vector = VECTORS["atr_n2"]
    bars = [
        _bar(i + 1, open_=open_value, high=high_value, low=low_value, close=close_value)
        for i, (open_value, high_value, low_value, close_value) in enumerate(vector["ohlc"])
    ]
    results = batch(bars, _definition("ATR", vector["period"]), ASOF)
    assert [result.value for result in results] == [
        None if value == "null" else Decimal(value) for value in vector["expected"]
    ]
    missing_range = _bar(4, close="15", high=None, low=None)
    invalid = batch([*bars, missing_range], _definition("ATR"), ASOF)[-1]
    assert invalid.value is None
    assert invalid.invalid


def test_atr_seed_output_can_be_below_input_exponent_bound() -> None:
    bars = [
        _bar(1, close="1E-38", high="2E-38", low="1E-38"),
        _bar(2, close="1E-38", high="1E-38", low="1E-38"),
    ]
    results = batch(bars, _definition("ATR", period=2), ASOF)
    assert results[0].value is None
    assert results[1].value == Decimal("5E-39")


def test_vwap_uses_typical_price_and_resets_at_injected_session_boundary() -> None:
    results = batch(_vwap_bars(), _definition("VWAP", period=None), ASOF)
    assert [result.value for result in results] == [Decimal("10"), Decimal("11"), Decimal("16")]


def test_single_bar_vwap_of_four_thirds_rounds_once_for_output() -> None:
    vector = VECTORS["vwap_exact_scaled_accumulation"]
    open_value, high, low, close, volume = vector["ohlcv"][0]
    bar = _bar(
        1,
        open_=open_value,
        high=high,
        low=low,
        close=close,
        volume=volume,
        session=vector["session_keys"][0],
    )
    result = batch([bar], _definition("VWAP", period=None), ASOF)[0]
    assert result.value == Decimal(vector["expected"][0])


def test_vwap_continuation_uses_exact_scaled_accumulation_not_rounded_output() -> None:
    vector = VECTORS["vwap_exact_scaled_accumulation"]
    bars = [
        _bar(
            index + 1,
            open_=open_value,
            high=high,
            low=low,
            close=close,
            volume=volume,
            session=vector["session_keys"][index],
        )
        for index, (open_value, high, low, close, volume) in enumerate(vector["ohlcv"])
    ]
    results = batch(bars, _definition("VWAP", period=None), ASOF)
    assert [result.value for result in results] == [
        Decimal(expected) for expected in vector["expected"]
    ]
    assert vector["exact_cumulative_numerator"] == ["12", "14"]
    assert vector["exact_cumulative_volume"] == ["9", "11"]


def test_vwap_without_volume_is_unavailable_and_flagged() -> None:
    results = batch(
        [
            _bar(1, close="10", high="12", low="8", volume="2"),
            _bar(2, close="12", high="14", low="10", volume=None),
            _bar(3, close="12", high="14", low="10", volume="2"),
        ],
        _definition("VWAP", period=None),
        ASOF,
    )
    assert results[0].value == Decimal("10")
    assert results[1].value is None and results[1].invalid
    assert "MISSING_VOLUME" in results[1].quality_flags
    assert "NO_VOLUME" not in results[1].quality_flags
    assert results[2].value == Decimal("11")


def test_zero_total_session_volume_has_null_vwap_and_no_volume_flag() -> None:
    result = batch(
        [_bar(1, close="10", high="12", low="8", volume="0")],
        _definition("VWAP", period=None),
        ASOF,
    )[0]
    assert result.value is None
    assert result.invalid
    assert "NO_VOLUME" in result.quality_flags


@pytest.mark.parametrize("period", [2, 10_000])
def test_period_endpoints_are_accepted(period: int) -> None:
    definition = _definition("EMA", period)
    assert definition.period == period


@pytest.mark.parametrize("period", [1, 10_001])
def test_period_outside_contract_range_is_rejected(period: int) -> None:
    with pytest.raises(IndicatorValidationError):
        _definition("EMA", period)


@pytest.mark.parametrize("kind", ["SMA", "MACD", "UNKNOWN"])
def test_kernel_rejects_indicators_outside_first_slice(kind: str) -> None:
    with pytest.raises((IndicatorValidationError, ValueError)):
        _definition(kind)


def test_no_period_is_allowed_only_for_vwap() -> None:
    assert _definition("VWAP", period=None).period is None
    with pytest.raises(IndicatorValidationError):
        _definition("EMA", period=None)


def test_full_lookback_warmup_never_emits_a_valid_value_early() -> None:
    closes = VECTORS["ema_n2"]["closes"]
    results = batch(_close_bars(closes), _definition("EMA"), ASOF)
    assert results[0].value is None and results[0].warmup
    assert "WARMUP" in results[0].quality_flags
    assert results[1].value == Decimal("11") and not results[1].warmup


@pytest.mark.parametrize("kind", ["EMA", "RSI", "ATR", "VWAP"])
def test_incremental_and_batch_outputs_match_byte_for_byte_at_every_prefix(kind: str) -> None:
    bars_by_kind = {
        "EMA": _close_bars(["10", "12", "14", "13", "16"]),
        "RSI": _close_bars(["10", "12", "11", "12", "13"]),
        "ATR": [
            _bar(i + 1, open_=open_value, high=high_value, low=low_value, close=close_value)
            for i, (open_value, high_value, low_value, close_value)
            in enumerate(VECTORS["atr_n2"]["ohlc"])
        ],
        "VWAP": _vwap_bars(),
    }
    bars = bars_by_kind[kind]
    definition = _definition(kind, None if kind == "VWAP" else 2)
    state: IndicatorStateV1 | None = None
    for end, bar in enumerate(bars, start=1):
        state, result = advance(state, bar, definition, ASOF)
        expected = batch(bars[:end], definition, ASOF)
        assert state.results == expected
        assert result.canonical_bytes() == expected[-1].canonical_bytes()
        assert result.input_digest == expected[-1].input_digest


def test_duplicate_delivery_is_semantically_idempotent() -> None:
    bars = _close_bars(["10", "12", "14"])
    definition = _definition("EMA")
    duplicate_batch = batch([bars[0], bars[0], *bars[1:]], definition, ASOF)
    ordinary_batch = batch(bars, definition, ASOF)
    ordinary_by_id = {item.bar_id: item.canonical_bytes() for item in ordinary_batch}
    duplicate_by_id = {item.bar_id: item.canonical_bytes() for item in duplicate_batch}
    assert duplicate_by_id == ordinary_by_id


def test_reordered_harmless_duplicate_deliveries_preserve_canonical_results() -> None:
    bars = _close_bars(["10", "12", "14"])
    ordinary = batch(bars, _definition("EMA"), ASOF)
    reordered = batch([bars[1], bars[0], bars[1], bars[2]], _definition("EMA"), ASOF)
    assert {item.bar_id: item.canonical_bytes() for item in reordered} == {
        item.bar_id: item.canonical_bytes() for item in ordinary
    }


def test_future_available_bar_cannot_change_earlier_asof_output() -> None:
    bars = _close_bars(["10", "12"])
    available_at_cutoff = _bar(3, close="14", high="15", low="13", availability=ASOF)
    future = _bar(3, close="100", high="101", low="99", availability=ASOF + 1)
    earlier = batch(bars, _definition("EMA"), ASOF)
    inclusive = batch([*bars, available_at_cutoff], _definition("EMA"), ASOF)
    with_future = batch([*bars, future], _definition("EMA"), ASOF)
    assert inclusive[-1].bar_id == available_at_cutoff.bar_id
    assert [x.canonical_bytes() for x in with_future] == [x.canonical_bytes() for x in earlier]


def test_unfinalized_bar_is_not_used_as_a_finalized_result() -> None:
    bars = _close_bars(["10", "12"])
    provisional = _bar(3, close="500", high="501", low="499", finalized=False)
    try:
        results = batch([*bars, provisional], _definition("EMA"), ASOF)
    except IndicatorValidationError:
        return
    assert all(item.bar_id != provisional.bar_id for item in results)


def test_gap_and_late_quality_flags_are_preserved_on_result() -> None:
    gap = _bar(1, close="10", high="12", low="8", gap=True)
    result: IndicatorResultV1 = batch([gap], _definition("EMA"), ASOF)[0]
    assert result.gap


def test_adjusted_and_unadjusted_bars_cannot_be_mixed() -> None:
    base = _bar(1, close="10", high="12", low="8")
    incompatible = _bar(2, close="12", high="14", low="10", adjustment="adjusted-v1")
    with pytest.raises((IndicatorValidationError, IndicatorConflictError)):
        batch([base, incompatible], _definition("EMA"), ASOF)


def test_warm_start_requires_matching_definition_and_verified_prefix() -> None:
    bars = _close_bars(["10", "12", "14"])
    definition = _definition("EMA")
    state, _ = advance(None, bars[0], definition, ASOF)
    resumed = resume(state, bars[:1], definition, ASOF)
    assert resumed.definition_hash == state.definition_hash
    assert resumed.last_bar_id == state.last_bar_id
    assert resumed.input_digest == state.input_digest


def test_checkpoint_digest_mismatch_restarts_from_the_verified_source_prefix() -> None:
    definition = _definition("EMA")
    original = _close_bars(["10"])
    checkpoint, _ = advance(None, original[0], definition, ASOF)
    verified_prefix = _close_bars(["10", "13"])
    restarted = resume(checkpoint, verified_prefix, definition, ASOF)
    expected = batch(verified_prefix, definition, ASOF)
    assert restarted.results == expected
    assert restarted.input_digest == expected[-1].input_digest


def test_checkpoints_are_kernel_issued_and_cannot_be_forged_with_replace() -> None:
    definition = _definition("EMA")
    checkpoint, _ = advance(None, _close_bars(["10"])[0], definition, ASOF)
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
    with pytest.raises(IndicatorCheckpointError):
        replace(checkpoint, asof_ns=checkpoint.asof_ns)


def test_public_indicator_models_reject_copy_deepcopy_and_pickle() -> None:
    definition = _definition("EMA")
    bar = _close_bars(["10"])[0]
    state, result = advance(None, bar, definition, ASOF)
    models = (definition, bar, result, state)
    operations = (
        copy.copy,
        copy.deepcopy,
        lambda value: pickle.loads(pickle.dumps(value)),
    )
    for model in models:
        for operation in operations:
            with pytest.raises(IndicatorValidationError):
                operation(model)


def test_late_correction_creates_a_revision_without_mutating_prior_asof_state() -> None:
    definition = _definition("EMA")
    bars = _close_bars(["10", "12", "14"])
    state: IndicatorStateV1 | None = None
    for bar in bars:
        state, _ = advance(state, bar, definition, ASOF)
    assert state is not None
    prior_results = state.results
    prior_asof = state.asof_ns
    corrected = _bar(3, close="20", high="22", low="18", availability=ASOF + 1)
    revised_state, revised_result = advance(state, corrected, definition, ASOF + 1)
    assert revised_result.revision > state.results[-1].revision
    assert revised_state.asof_ns == ASOF + 1
    assert state.results == prior_results
    assert state.asof_ns == prior_asof


def test_result_records_the_formula_version_and_canonical_quality_flags() -> None:
    result = batch(_close_bars(["10"]), _definition("EMA"), ASOF)[0]
    assert result.formula_version == "IND-FORMULA-v1"
    assert "WARMUP" in result.quality_flags


def test_decimal_inputs_remain_decimal_and_preserve_exact_reference_arithmetic() -> None:
    results = batch(_close_bars(["0.1", "0.2", "0.3"]), _definition("EMA"), ASOF)
    assert isinstance(results[-1].value, Decimal)
    assert results[-1].value == Decimal("0.25")


def test_decimal_inputs_over_kernel_precision_are_rejected_before_arithmetic() -> None:
    over_precision = "0." + "1" * 35
    with pytest.raises(IndicatorPrecisionExceededError) as error:
        _bar(1, close=over_precision, high=over_precision, low=over_precision)
    assert str(error.value) == "PRECISION_EXCEEDED"


def test_decimal_at_kernel_precision_limit_is_accepted_without_rounding() -> None:
    at_limit = "0." + "1" * 34
    bar = _bar(1, close=at_limit, high=at_limit, low=at_limit)
    assert bar.close == Decimal(at_limit)
    assert len(bar.close.as_tuple().digits) == 34


def test_large_positive_decimal_exponent_is_rejected_as_a_bounded_value() -> None:
    with pytest.raises(IndicatorValidationError) as error:
        _bar(
            1,
            close=Decimal("1E+100000"),
            high="1E+100000",
            low="1E+100000",
        )
    assert str(error.value) == "indicator number out of range"


def test_vwap_volume_sum_beyond_kernel_precision_raises_without_rounding() -> None:
    thirty_four_nines = "9" * 34
    bars = (
        _bar(1, close="1", high="1", low="1", volume=thirty_four_nines),
        _bar(2, close="1", high="1", low="1", volume="2"),
    )
    with pytest.raises(IndicatorPrecisionExceededError) as error:
        batch(bars, _definition("VWAP", period=None), ASOF)
    assert str(error.value) == "PRECISION_EXCEEDED"


def test_ema_seed_sum_beyond_kernel_precision_raises_without_rounding() -> None:
    thirty_four_nines = "9" * 34
    bars = (
        _bar(1, close=thirty_four_nines),
        _bar(2, close="2"),
    )
    with pytest.raises(IndicatorPrecisionExceededError) as error:
        batch(bars, _definition("EMA", period=3), ASOF)
    assert str(error.value) == "PRECISION_EXCEEDED"


def test_decimal_one_times_ten_to_thirty_four_is_accepted_as_one_digit() -> None:
    value = Decimal("1E+34")
    bar = _bar(1, close=value, high="1E+34", low="1E+34")
    assert bar.close == value
    assert len(value.as_tuple().digits) == 1
    assert value.adjusted() == 34
