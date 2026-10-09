"""Focused offline adapter checks across the IND and FEAT boundaries."""

from __future__ import annotations

import copy
import pickle
from decimal import Decimal
from typing import Any

import pytest
from issued_result_support import issue_fixture_result

from leviathan_core.indicator_state import IndicatorDefinitionV1, batch
from leviathan_core.indicator_state.adapter import (
    IndicatorAdapterError,
    NormalizedBarPortV1,
    feature_definition,
    issue_normalized_bar_port,
    to_feature_observation,
    to_feature_observations,
    to_final_bar,
)
from leviathan_core.seal import SealError


def _port(**changes: object) -> NormalizedBarPortV1:
    data: dict[str, Any] = {
        "provider": "provider1",
        "source_dataset": "bars1",
        "source_record_key": "record1",
        "source_payload_sha256": "a" * 64,
        "instrument_id": "ES",
        "venue": "CME",
        "timeframe": "1m",
        "source_version": "s1",
        "adjustment_basis": "raw",
        "adjustment_version": "v1",
        "calendar_version": "c1",
        "calendar_session_id": "20261005",
        "auction_session_id": "RTH",
        "bar_start_ns": 60_000_000_000,
        "bar_end_ns": 120_000_000_000,
        "event_time_ns": 120_000_000_000,
        "availability_ns": 121_000_000_000,
        "watermark_ns": 120_000_000_000,
        "finalized_at_ns": 120_000_000_000,
        "open": Decimal("2"),
        "high": Decimal("2"),
        "low": Decimal("1"),
        "close": Decimal("1"),
        "volume": Decimal("9"),
        "finalized": True,
        "gap": False,
        "quality_flags": (),
        "revision": 0,
        "correction_id": None,
    }
    data.update(changes)
    return NormalizedBarPortV1(**data)


def _definition(**changes: object) -> IndicatorDefinitionV1:
    data: dict[str, Any] = {
        "kind": "VWAP",
        "period": None,
        "formula_version": "IND-FORMULA-v1",
        "parameter_version": "p1",
        "instrument_id": "ES",
        "venue": "CME",
        "timeframe": "1m",
        "source_version": "s1",
        "adjustment_version": "raw:v1",
        "calendar_version": "c1",
    }
    data.update(changes)
    return IndicatorDefinitionV1(**data)


def test_final_bar_and_observation_round_trip() -> None:
    port = issue_normalized_bar_port(_port())
    definition = _definition()
    bar = to_final_bar(port, definition, asof_ns=121_000_000_000)
    result = batch((bar,), definition, 121_000_000_000)[0]
    assert result.value == Decimal("1." + "3" * 33)
    feature = feature_definition(port, definition, published=False)
    observation = to_feature_observation(port, definition, result, availability_ns=121_000_000_000)
    assert observation.feature_name == feature.feature_name
    assert observation.feature_version == feature.feature_version
    assert observation.value_decimal == result.value
    assert observation.availability_ns == port.availability_ns
    assert observation.event_time_ns == bar.bar_end_ns
    assert observation.is_null is False
    assert (
        observation.semantic_hash
        == to_feature_observation(
            port, definition, result, availability_ns=121_000_000_000
        ).semantic_hash
    )


def test_finality_and_availability_gates() -> None:
    definition = _definition()
    provisional = issue_normalized_bar_port(
        _port(finalized=False, finalized_at_ns=None, watermark_ns=110_000_000_000)
    )
    with pytest.raises(IndicatorAdapterError, match="PROVISIONAL_BAR"):
        to_final_bar(provisional, definition, asof_ns=121_000_000_000)
    final = issue_normalized_bar_port(_port())
    with pytest.raises(IndicatorAdapterError, match="UNAVAILABLE_BAR"):
        to_final_bar(final, definition, asof_ns=120_000_000_000)
    with pytest.raises(SealError, match="SEAL_INVALID_MODEL"):
        _port(watermark_ns=122_000_000_000)


def test_lineage_revision_and_session_are_deterministic() -> None:
    definition = _definition()
    first = issue_normalized_bar_port(_port())
    duplicate = issue_normalized_bar_port(_port(source_record_key="record2"))
    correction = issue_normalized_bar_port(
        _port(revision=1, correction_id="correction1", availability_ns=122_000_000_000)
    )
    first_bar = to_final_bar(first, definition, asof_ns=122_000_000_000)
    correction_bar = to_final_bar(correction, definition, asof_ns=122_000_000_000)
    assert first_bar.bar_id == to_final_bar(duplicate, definition, asof_ns=122_000_000_000).bar_id
    assert first_bar.bar_id == correction_bar.bar_id
    assert (
        first_bar.session_key
        != to_final_bar(
            issue_normalized_bar_port(_port(auction_session_id="ETH")),
            definition,
            asof_ns=122_000_000_000,
        ).session_key
    )
    with pytest.raises(IndicatorAdapterError, match="LINEAGE_MISMATCH"):
        to_final_bar(first, _definition(adjustment_version="split:v1"), asof_ns=122_000_000_000)


def test_unissued_and_copy_are_refused() -> None:
    candidate = _port()
    with pytest.raises(IndicatorAdapterError, match="UNISSUED_BAR_PORT"):
        to_final_bar(candidate, _definition(), asof_ns=121_000_000_000)
    issued = issue_normalized_bar_port(candidate)
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(SealError):
            operation(issued)


def test_issue_revalidates_mutated_candidate_before_sealing() -> None:
    candidate = _port()
    object.__setattr__(candidate, "watermark_ns", 1)
    with pytest.raises(IndicatorAdapterError) as error:
        issue_normalized_bar_port(candidate)
    assert error.value.code == "INVALID_BAR_PORT"


def test_conflicting_indicator_results_are_rejected_before_rows() -> None:
    port = issue_normalized_bar_port(_port())
    definition = _definition()
    bar = to_final_bar(port, definition, asof_ns=121_000_000_000)
    result = batch((bar,), definition, 121_000_000_000)[0]
    fields = {
        "warmup": result.warmup,
        "gap": result.gap,
        "late": result.late,
        "invalid": result.invalid,
        "sample_count": result.sample_count,
        "bar_end_ns": result.bar_end_ns,
        "bar_id": result.bar_id,
        "input_digest": result.input_digest,
        "revision": result.revision,
        "definition_hash": result.definition_hash,
        "formula_version": result.formula_version,
        "quality_flags": result.quality_flags,
    }
    left = issue_fixture_result(**fields, value=Decimal("1.25"))
    right = issue_fixture_result(**fields, value=Decimal("2.5"))

    with pytest.raises(IndicatorAdapterError) as error:
        to_feature_observations(
            port,
            definition,
            (left, right),
            availability_ns=121_000_000_000,
        )
    assert error.value.code == "CONFLICTING_INDICATOR_RESULT"

    # Independent singular calls still carry content-derived, distinct keys.
    left_row = to_feature_observation(port, definition, left, availability_ns=121_000_000_000)
    right_row = to_feature_observation(port, definition, right, availability_ns=121_000_000_000)
    assert left_row.source_record_key != right_row.source_record_key


def test_output_outside_feat_domain_is_typed() -> None:
    port = issue_normalized_bar_port(
        _port(
            open=Decimal("2E-38"),
            high=Decimal("2E-38"),
            low=Decimal("1E-38"),
            close=Decimal("1E-38"),
        )
    )
    definition = _definition(kind="ATR", period=2)
    bar = to_final_bar(port, definition, asof_ns=121_000_000_000)
    second = issue_normalized_bar_port(
        _port(
            bar_start_ns=120_000_000_000,
            bar_end_ns=180_000_000_000,
            event_time_ns=180_000_000_000,
            availability_ns=181_000_000_000,
            finalized_at_ns=180_000_000_000,
            watermark_ns=180_000_000_000,
            source_record_key="record2",
            open=Decimal("1E-38"),
            high=Decimal("1E-38"),
            low=Decimal("1E-38"),
            close=Decimal("1E-38"),
        )
    )
    second_bar = to_final_bar(second, definition, asof_ns=181_000_000_000)
    result = batch((bar, second_bar), definition, 181_000_000_000)[1]
    assert result.value == Decimal("5E-39")
    with pytest.raises(IndicatorAdapterError, match="FEATURE_VALUE_OUT_OF_DOMAIN"):
        to_feature_observation(second, definition, result, availability_ns=181_000_000_000)


def test_warmup_is_a_nullable_observation() -> None:
    port = issue_normalized_bar_port(_port())
    definition = _definition(kind="EMA", period=2)
    bar = to_final_bar(port, definition, asof_ns=121_000_000_000)
    result = batch((bar,), definition, 121_000_000_000)[0]
    assert result.value is None and result.warmup
    observation = to_feature_observation(port, definition, result, availability_ns=121_000_000_000)
    assert observation.is_null
    assert observation.value_decimal is None
    assert observation.quality == "WARMUP"


def test_correction_is_new_asof_row_and_parameter_version_changes_key() -> None:
    definition = _definition()
    initial = issue_normalized_bar_port(_port())
    corrected = issue_normalized_bar_port(
        _port(revision=1, correction_id="fix1", availability_ns=122_000_000_000)
    )
    initial_bar = to_final_bar(initial, definition, asof_ns=121_000_000_000)
    initial_result = batch((initial_bar,), definition, 121_000_000_000)[0]
    corrected_bar = to_final_bar(corrected, definition, asof_ns=122_000_000_000)
    corrected_result = batch((corrected_bar,), definition, 122_000_000_000)[0]
    first_row = to_feature_observation(
        initial, definition, initial_result, availability_ns=121_000_000_000
    )
    next_row = to_feature_observation(
        corrected, definition, corrected_result, availability_ns=122_000_000_000
    )
    assert first_row.source_record_key != next_row.source_record_key
    assert first_row.availability_ns < next_row.availability_ns
    assert feature_definition(initial, definition, published=False).feature_version != (
        feature_definition(
            initial, _definition(parameter_version="p2"), published=False
        ).feature_version
    )
