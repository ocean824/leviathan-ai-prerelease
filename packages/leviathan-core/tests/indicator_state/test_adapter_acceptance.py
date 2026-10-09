"""Independent contract acceptance for the offline IND-002 adapter."""

from __future__ import annotations

import copy
import gc
import pickle
from decimal import Decimal, localcontext

import pytest
from issued_result_support import issue_fixture_result

from leviathan_core.feature_store import (
    FeatureDefinitionV1,
    FeatureFrozenError,
    FeatureObservationV1,
    FeatureQueryV1,
    query_asof,
)
from leviathan_core.indicator_state import adapter as adapter_module
from leviathan_core.indicator_state.adapter import (
    IndicatorAdapterError,
    NormalizedBarPortV1,
    feature_definition,
    issue_normalized_bar_port,
    to_feature_observation,
    to_feature_observations,
    to_final_bar,
)
from leviathan_core.indicator_state.models import (
    IndicatorDefinitionV1,
    IndicatorResultV1,
    IndicatorValidationError,
)
from leviathan_core.seal import SealError

ASOF = 1_700_000_000_000_000_000
BAR_END = ASOF - 1_000_000
BAR_START = BAR_END - 60_000_000_000
AVAILABILITY = BAR_END + 100


def _payload(**changes: object) -> dict[str, object]:
    values: dict[str, object] = {
        "provider": "SYNTH",
        "source_dataset": "synthetic-bars-v1",
        "source_record_key": "bar-record-001",
        "source_payload_sha256": "a" * 64,
        "instrument_id": "SYNTH:XYZ",
        "venue": "SYNTH",
        "timeframe": "1m",
        "source_version": "bars-v1",
        "adjustment_basis": "RAW",
        "adjustment_version": "v1",
        "calendar_version": "calendar-v1",
        "calendar_session_id": "session-2026-10-05",
        "auction_session_id": "continuous",
        "bar_start_ns": BAR_START,
        "bar_end_ns": BAR_END,
        "event_time_ns": BAR_END,
        "availability_ns": AVAILABILITY,
        "watermark_ns": BAR_END,
        "finalized_at_ns": BAR_END + 50,
        "open": Decimal("10.00"),
        "high": Decimal("11.00"),
        "low": Decimal("9.00"),
        "close": Decimal("10.50"),
        "volume": Decimal("100"),
        "finalized": True,
        "gap": False,
        "quality_flags": (),
        "revision": 0,
        "correction_id": None,
    }
    values.update(changes)
    return values


def _candidate(**changes: object) -> NormalizedBarPortV1:
    return NormalizedBarPortV1(**_payload(**changes))


def _port(**changes: object) -> NormalizedBarPortV1:
    return issue_normalized_bar_port(_candidate(**changes))


def _definition(
    *,
    kind: str = "EMA",
    period: int | None = 3,
    parameter_version: str = "ema-period-3-v1",
    instrument_id: str = "SYNTH:XYZ",
    venue: str = "SYNTH",
    timeframe: str = "1m",
    source_version: str = "bars-v1",
    adjustment_version: str = "RAW:v1",
    calendar_version: str = "calendar-v1",
) -> IndicatorDefinitionV1:
    return IndicatorDefinitionV1(
        kind=kind,  # type: ignore[arg-type]
        period=period,
        formula_version="IND-FORMULA-v1",
        parameter_version=parameter_version,
        instrument_id=instrument_id,
        venue=venue,
        timeframe=timeframe,
        source_version=source_version,
        adjustment_version=adjustment_version,
        calendar_version=calendar_version,
    )


def _result(
    port: NormalizedBarPortV1,
    definition: IndicatorDefinitionV1,
    *,
    value: Decimal | None = Decimal("1.234567890123456789012345678901234"),
    revision: int = 0,
    warmup: bool = False,
    gap: bool = False,
    late: bool = False,
    invalid: bool = False,
    quality_flags: tuple[str, ...] = (),
) -> IndicatorResultV1:
    bar = to_final_bar(port, definition, asof_ns=port.availability_ns + 1)
    return issue_fixture_result(
        value=value,
        warmup=warmup,
        gap=gap,
        late=late,
        invalid=invalid,
        sample_count=0 if value is None else 3,
        bar_end_ns=bar.bar_end_ns,
        bar_id=bar.bar_id,
        input_digest="b" * 64,
        revision=revision,
        definition_hash=definition.semantic_hash,
        formula_version=definition.formula_version,
        quality_flags=quality_flags,
    )


def _observation(
    port: NormalizedBarPortV1,
    definition: IndicatorDefinitionV1,
    result: IndicatorResultV1 | None = None,
    *,
    available: int = AVAILABILITY,
) -> FeatureObservationV1:
    return to_feature_observation(
        port,
        definition,
        _result(port, definition) if result is None else result,
        availability_ns=available,
    )


def _assert_adapter_error(call, code: str) -> None:
    with pytest.raises(IndicatorAdapterError) as caught:
        call()
    assert caught.value.code == code
    assert caught.value.args == (code,)


def test_valid_final_bar_and_feature_map_preserve_source_and_utc_lineage():
    port = _port()
    definition = _definition()
    bar = to_final_bar(port, definition, asof_ns=AVAILABILITY)

    assert bar.instrument_id == port.instrument_id
    assert bar.venue == port.venue
    assert bar.timeframe == port.timeframe
    assert bar.source_version == port.source_version
    assert bar.adjustment_version == "RAW:v1"
    assert bar.calendar_version == port.calendar_version
    assert bar.event_time_ns == port.event_time_ns
    assert bar.availability_ns == port.availability_ns
    assert bar.bar_end_ns == port.bar_end_ns
    assert bar.finalized is True
    assert bar.gap is False

    definition_out = feature_definition(port, definition, published=False)
    observation = _observation(port, definition)
    assert isinstance(definition_out, FeatureDefinitionV1)
    assert observation.feature_name == definition_out.feature_name
    assert observation.feature_version == definition_out.feature_version
    assert observation.instrument_id == port.instrument_id
    assert observation.source_dataset == "SYNTH:synthetic-bars-v1"
    assert observation.event_time_ns == port.bar_end_ns
    assert observation.availability_ns == AVAILABILITY
    assert observation.value_decimal == Decimal("1.234567890123456789012345678901234")
    assert observation.local_receipt_ns is None


def test_normalized_bar_fields_are_all_required_and_unissued_inputs_cannot_convert():
    assert all(field.is_required() for field in NormalizedBarPortV1.model_fields.values())
    candidate = _candidate()
    _assert_adapter_error(
        lambda: to_final_bar(candidate, _definition(), asof_ns=AVAILABILITY),
        "UNISSUED_BAR_PORT",
    )


def test_preissuance_watermark_tampering_cannot_certify_an_unsettled_bar():
    candidate = _candidate()
    object.__setattr__(candidate, "watermark_ns", candidate.bar_end_ns - 1)
    try:
        issued = issue_normalized_bar_port(candidate)
    except IndicatorAdapterError:
        return

    with pytest.raises(IndicatorAdapterError):
        to_final_bar(issued, _definition(), asof_ns=AVAILABILITY)


@pytest.mark.parametrize(
    ("changes", "asof", "code"),
    [
        ({"finalized": False, "finalized_at_ns": None}, AVAILABILITY, "PROVISIONAL_BAR"),
        ({}, AVAILABILITY - 1, "UNAVAILABLE_BAR"),
    ],
)
def test_provisional_or_not_yet_available_bars_are_rejected(changes, asof, code):
    port = _port(**changes)
    _assert_adapter_error(lambda: to_final_bar(port, _definition(), asof_ns=asof), code)


def test_future_finalization_time_is_not_visible_until_its_exact_asof():
    port = _port(
        finalized_at_ns=AVAILABILITY + 1,
        availability_ns=AVAILABILITY + 1,
    )
    _assert_adapter_error(
        lambda: to_final_bar(port, _definition(), asof_ns=AVAILABILITY),
        "UNAVAILABLE_BAR",
    )
    bar = to_final_bar(port, _definition(), asof_ns=AVAILABILITY + 1)
    assert bar.availability_ns == AVAILABILITY + 1


def test_adjustment_basis_version_must_match_the_indicator_definition():
    port = _port(adjustment_basis="SPLIT", adjustment_version="adj-2026-v2")
    matching = _definition(adjustment_version="SPLIT:adj-2026-v2")
    mixed = _definition(adjustment_version="RAW:unadjusted-v1")

    assert to_final_bar(port, matching, asof_ns=AVAILABILITY).adjustment_version == (
        "SPLIT:adj-2026-v2"
    )
    _assert_adapter_error(
        lambda: to_final_bar(port, mixed, asof_ns=AVAILABILITY), "LINEAGE_MISMATCH"
    )


def test_calendar_session_and_auction_session_are_part_of_the_bar_identity():
    definition = _definition()
    first = _port(
        bar_start_ns=BAR_END - 3_600_000_000_000 - 60_000_000_000,
        bar_end_ns=BAR_END - 3_600_000_000_000,
        event_time_ns=BAR_END - 3_600_000_000_000,
        availability_ns=BAR_END - 3_600_000_000_000 + 100,
        watermark_ns=BAR_END - 3_600_000_000_000,
        finalized_at_ns=BAR_END - 3_600_000_000_000 + 50,
        calendar_session_id="dst-fold-session-a",
        auction_session_id="opening-auction",
    )
    second = _port(
        calendar_session_id="dst-fold-session-a",
        auction_session_id="continuous-session",
    )
    first_bar = to_final_bar(first, definition, asof_ns=AVAILABILITY)
    second_bar = to_final_bar(second, definition, asof_ns=AVAILABILITY)

    assert first_bar.bar_end_ns != second_bar.bar_end_ns
    assert first_bar.session_key != second_bar.session_key
    assert first_bar.bar_id != second_bar.bar_id


def test_feature_definition_key_binds_formula_parameters_source_and_timeframe():
    port = _port()
    base = feature_definition(port, _definition(), published=False)
    replay = feature_definition(port, _definition(), published=False)
    changed_formula = feature_definition(
        port, _definition(parameter_version="ema-period-4-v1", period=4), published=False
    )
    changed_timeframe_port = _port(timeframe="5m")
    changed_timeframe_definition = _definition(timeframe="5m")
    changed_timeframe = feature_definition(
        changed_timeframe_port, changed_timeframe_definition, published=False
    )

    assert (base.feature_name, base.feature_version) == (
        replay.feature_name,
        replay.feature_version,
    )
    assert base.feature_version != changed_formula.feature_version
    assert base.feature_version != changed_timeframe.feature_version


def test_feature_observation_is_visible_only_at_its_feat_availability_time():
    port = _port()
    definition = _definition()
    feat_definition = feature_definition(port, definition, published=True)
    observation = _observation(port, definition, available=AVAILABILITY + 5)
    query_fields = {
        "feature_name": feat_definition.feature_name,
        "feature_version": feat_definition.feature_version,
        "instrument_id": port.instrument_id,
    }

    too_early = query_asof(
        FeatureQueryV1(**query_fields, asof_ns=AVAILABILITY + 4),
        (feat_definition,),
        (observation,),
    )
    visible = query_asof(
        FeatureQueryV1(**query_fields, asof_ns=AVAILABILITY + 5),
        (feat_definition,),
        (observation,),
    )
    assert too_early.found is False
    assert visible.found is True
    assert visible.availability_ns == AVAILABILITY + 5


def test_late_correction_becomes_a_new_asof_row_without_mutating_prior_observation():
    definition = _definition()
    original_port = _port()
    original_result = _result(original_port, definition)
    original = _observation(original_port, definition, original_result)

    corrected_port = _port(
        source_payload_sha256="c" * 64,
        source_record_key="bar-record-001-revision-1",
        availability_ns=AVAILABILITY + 100,
        finalized_at_ns=AVAILABILITY + 50,
        revision=1,
        correction_id="correction-001",
        close=Decimal("10.75"),
    )
    corrected_result = _result(corrected_port, definition, revision=1)
    corrected = _observation(
        corrected_port,
        definition,
        corrected_result,
        available=AVAILABILITY + 100,
    )

    assert original is not corrected
    assert original.event_time_ns == corrected.event_time_ns
    assert original.availability_ns == AVAILABILITY
    assert corrected.availability_ns == AVAILABILITY + 100
    assert original.source_record_key != corrected.source_record_key
    assert original.value_decimal == Decimal("1.234567890123456789012345678901234")
    assert corrected.value_decimal == original.value_decimal


@pytest.mark.parametrize(
    ("result_changes", "quality"),
    [
        ({"value": None, "warmup": True}, "WARMUP"),
        ({"value": None, "invalid": True}, "INVALID"),
        ({"value": None, "gap": True}, "GAP"),
    ],
)
def test_warmup_invalid_and_gap_results_are_null_with_explicit_quality(result_changes, quality):
    port = _port(gap=quality == "GAP", quality_flags=("GAP",) if quality == "GAP" else ())
    definition = _definition()
    result = _result(port, definition, **result_changes)
    observation = _observation(port, definition, result)

    assert observation.is_null is True
    assert observation.value_decimal is None
    assert quality in (observation.quality or "").split("|")


def test_ind_result_outside_feat_domain_fails_typed_instead_of_becoming_null():
    port = _port()
    definition = _definition()
    result = _result(port, definition, value=Decimal("1E+39"))

    _assert_adapter_error(
        lambda: to_feature_observation(port, definition, result, availability_ns=AVAILABILITY),
        "FEATURE_VALUE_OUT_OF_DOMAIN",
    )


def test_input_and_result_identity_do_not_depend_on_ambient_decimal_context_or_scale():
    port = _port()
    definition = _definition()
    first = _observation(
        port,
        definition,
        _result(port, definition, value=Decimal("12.500")),
    )
    with localcontext() as context:
        context.prec = 2
        context.Emax = 2
        context.Emin = -2
        second = _observation(
            port,
            definition,
            _result(port, definition, value=Decimal("12.5")),
        )

    assert first.value_decimal == second.value_decimal == Decimal("12.5")
    assert first.semantic_hash == second.semantic_hash


@pytest.mark.parametrize("field", ("revision", "availability_ns", "bar_end_ns"))
def test_integer_fields_reject_bool(field: str):
    with pytest.raises(SealError):
        _candidate(**{field: True})


def test_numeric_magnitude_is_bounded_before_decimal_expansion():
    with pytest.raises(SealError):
        _candidate(close=Decimal("1E+100000"))


def test_bad_public_adapter_input_is_typed_and_does_not_echo_canary():
    canary = "IND_ADAPTER_CANARY_7ad"
    with pytest.raises(IndicatorAdapterError) as caught:
        to_final_bar(canary, _definition(), asof_ns=AVAILABILITY)  # type: ignore[arg-type]
    assert caught.value.code == "INVALID_BAR_PORT"
    assert canary not in str(caught.value)
    assert canary not in repr(caught.value.args)


def test_copy_deepcopy_and_pickle_are_not_alternate_port_issuance_paths():
    port = _port()
    for operation in (
        lambda: copy.copy(port),
        lambda: copy.deepcopy(port),
        lambda: pickle.dumps(port),
    ):
        with pytest.raises(SealError):
            operation()


def test_issued_port_rejects_assignment_deletion_reinit_and_tampering_on_use():
    port = _port()
    definition = _definition()
    with pytest.raises(SealError):
        port.finalized = False  # type: ignore[misc]
    with pytest.raises(SealError):
        del port.finalized  # type: ignore[misc]
    with pytest.raises(SealError):
        NormalizedBarPortV1.__init__(port, **_payload())
    with pytest.raises(SealError):
        port.__setstate__({"finalized": False})

    object.__setattr__(port, "finalized", False)
    _assert_adapter_error(
        lambda: to_final_bar(port, definition, asof_ns=AVAILABILITY), "UNISSUED_BAR_PORT"
    )


def test_issuer_registry_uses_identity_for_equal_port_instances_after_collection():
    payload = _payload()
    first = issue_normalized_bar_port(NormalizedBarPortV1(**payload))
    second = issue_normalized_bar_port(NormalizedBarPortV1(**payload))
    definition = _definition()
    assert first == second
    assert first is not second
    assert (
        to_final_bar(first, definition, asof_ns=AVAILABILITY).bar_id
        == to_final_bar(second, definition, asof_ns=AVAILABILITY).bar_id
    )

    del first
    gc.collect()
    assert to_final_bar(second, definition, asof_ns=AVAILABILITY).finalized is True


def test_feat_observation_assignment_and_deletion_raise_content_free_frozen_error():
    observation = _observation(_port(), _definition())
    canary = "FEATURE_ASSIGNMENT_CANARY"

    with pytest.raises(FeatureFrozenError) as assignment:
        observation.value_decimal = canary  # type: ignore[misc,assignment]
    assert canary not in str(assignment.value)
    assert canary not in repr(assignment.value.args)
    with pytest.raises(FeatureFrozenError):
        del observation.value_decimal  # type: ignore[misc]


def test_definition_and_result_must_match_port_and_formula_lineage():
    port = _port()
    definition = _definition()
    result = _result(port, definition)
    wrong = _definition(source_version="other-source-v2")
    _assert_adapter_error(
        lambda: to_feature_observation(port, wrong, result, availability_ns=AVAILABILITY),
        "LINEAGE_MISMATCH",
    )
    mismatched_result = issue_fixture_result(
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
        definition_hash="d" * 64,
        formula_version=result.formula_version,
        quality_flags=result.quality_flags,
    )
    _assert_adapter_error(
        lambda: to_feature_observation(
            port, definition, mismatched_result, availability_ns=AVAILABILITY
        ),
        "RESULT_MISMATCH",
    )


def test_indicator_domain_failure_is_not_confused_with_warmup_or_invalid_null():
    port = _port()
    definition = _definition()
    with pytest.raises(IndicatorValidationError):
        _result(port, definition, value=Decimal("NaN"))


def test_feature_definition_publication_argument_is_a_typed_bool():
    with pytest.raises(IndicatorAdapterError) as caught:
        feature_definition(_port(), _definition(), published="false")  # type: ignore[arg-type]
    assert caught.value.code == "INVALID_BAR_PORT"


def test_replace_revalidates_indicator_definition_instead_of_mutating_it():
    definition = _definition()
    with pytest.raises(IndicatorValidationError):
        # The stdlib dataclass contract validates replacement fields eagerly.
        from dataclasses import replace

        replace(definition, period=True)


def test_conflicting_batch_results_fail_before_constructing_any_feature_rows(monkeypatch):
    port = _port()
    definition = _definition()
    results = (
        _result(port, definition, value=Decimal("1.25")),
        _result(port, definition, value=Decimal("2.5")),
    )
    original_constructor = adapter_module.FeatureObservationV1
    constructed = 0

    def track_construction(**fields):
        nonlocal constructed
        constructed += 1
        return original_constructor(**fields)

    monkeypatch.setattr(adapter_module, "FeatureObservationV1", track_construction)
    with pytest.raises(IndicatorAdapterError) as caught:
        to_feature_observations(port, definition, results, availability_ns=AVAILABILITY)

    assert caught.value.code == "CONFLICTING_INDICATOR_RESULT"
    assert constructed == 0


def test_conflicting_result_content_has_distinct_identity_across_singular_calls():
    port = _port()
    definition = _definition()
    first = to_feature_observation(
        port,
        definition,
        _result(port, definition, value=Decimal("1.25")),
        availability_ns=AVAILABILITY,
    )
    second = to_feature_observation(
        port,
        definition,
        _result(port, definition, value=Decimal("2.5")),
        availability_ns=AVAILABILITY,
    )

    assert first.value_decimal == Decimal("1.25")
    assert second.value_decimal == Decimal("2.5")
    assert first.source_record_key != second.source_record_key
