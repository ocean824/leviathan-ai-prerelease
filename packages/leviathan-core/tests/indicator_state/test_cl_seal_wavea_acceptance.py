"""Independent CL-SEAL-WAVEA acceptance checks for IND-001/IND-002."""

from __future__ import annotations

from decimal import Decimal

import pytest
from issued_result_support import issue_result_from_kernel

from leviathan_core.feature_store import FeatureObservationV1
from leviathan_core.indicator_state import (
    IndicatorDefinitionV1,
    IndicatorResultV1,
)
from leviathan_core.indicator_state.adapter import (
    IndicatorAdapterError,
    NormalizedBarPortV1,
    issue_normalized_bar_port,
    to_feature_observation,
    to_final_bar,
)
from leviathan_core.indicator_state.models import require_indicator_result
from leviathan_core.seal import SealError

ASOF_NS = 121_000_000_000


def _definition() -> IndicatorDefinitionV1:
    return IndicatorDefinitionV1(
        kind="VWAP",
        period=None,
        formula_version="IND-FORMULA-v1",
        parameter_version="p1",
        instrument_id="ES",
        venue="CME",
        timeframe="1m",
        source_version="s1",
        adjustment_version="raw:v1",
        calendar_version="c1",
    )


def _issued_port() -> NormalizedBarPortV1:
    return issue_normalized_bar_port(
        NormalizedBarPortV1(
            provider="SYNTH",
            source_dataset="bars-v1",
            source_record_key="row-1",
            source_payload_sha256="a" * 64,
            instrument_id="ES",
            venue="CME",
            timeframe="1m",
            source_version="s1",
            adjustment_basis="raw",
            adjustment_version="v1",
            calendar_version="c1",
            calendar_session_id="session-1",
            auction_session_id="RTH",
            bar_start_ns=60_000_000_000,
            bar_end_ns=120_000_000_000,
            event_time_ns=120_000_000_000,
            availability_ns=ASOF_NS,
            watermark_ns=120_000_000_000,
            finalized_at_ns=120_000_000_000,
            open=Decimal("2"),
            high=Decimal("2"),
            low=Decimal("1"),
            close=Decimal("1"),
            volume=Decimal("9"),
            finalized=True,
            gap=False,
            quality_flags=(),
            revision=0,
            correction_id=None,
        )
    )


def _kernel_result() -> tuple[NormalizedBarPortV1, IndicatorDefinitionV1, IndicatorResultV1]:
    port = _issued_port()
    definition = _definition()
    finalized_bar = to_final_bar(port, definition, asof_ns=ASOF_NS)
    result = issue_result_from_kernel((finalized_bar,), definition, ASOF_NS)
    return port, definition, result


def test_ind001_kernel_result_is_issued_and_consumable_by_ind002() -> None:
    port, definition, result = _kernel_result()

    assert require_indicator_result(result) is result
    observation = to_feature_observation(port, definition, result, availability_ns=ASOF_NS)

    assert isinstance(observation, FeatureObservationV1)
    assert observation.value_decimal == result.value


def test_ind002_rejects_directly_constructed_unissued_result() -> None:
    port, definition, issued = _kernel_result()
    candidate = IndicatorResultV1(
        value=issued.value,
        warmup=issued.warmup,
        gap=issued.gap,
        late=issued.late,
        invalid=issued.invalid,
        sample_count=issued.sample_count,
        bar_end_ns=issued.bar_end_ns,
        bar_id=issued.bar_id,
        input_digest=issued.input_digest,
        revision=issued.revision,
        definition_hash=issued.definition_hash,
        formula_version=issued.formula_version,
        quality_flags=issued.quality_flags,
    )

    with pytest.raises(IndicatorAdapterError) as caught:
        to_feature_observation(port, definition, candidate, availability_ns=ASOF_NS)

    assert caught.value.code == "SEAL_NOT_ISSUED"


def test_issued_indicator_result_rejects_reinitialization_without_mutation() -> None:
    _, _, issued = _kernel_result()
    original_value = issued.value

    with pytest.raises(SealError) as caught:
        issued.__init__(
            value=Decimal("9"),
            warmup=issued.warmup,
            gap=issued.gap,
            late=issued.late,
            invalid=issued.invalid,
            sample_count=issued.sample_count,
            bar_end_ns=issued.bar_end_ns,
            bar_id=issued.bar_id,
            input_digest=issued.input_digest,
            revision=issued.revision,
            definition_hash=issued.definition_hash,
            formula_version=issued.formula_version,
            quality_flags=issued.quality_flags,
        )

    assert caught.value.code == "SEAL_FORBIDDEN_OPERATION"
    assert issued.value == original_value
    assert require_indicator_result(issued) is issued
