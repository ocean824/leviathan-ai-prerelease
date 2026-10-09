"""Independent acceptance checks for C-102's Decimal compatibility boundary."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import get_type_hints

import pytest
from pydantic import ValidationError

from leviathan_core.research.replay_job import run_replay_job
from leviathan_core.schemas.decision import DecisionPacket
from leviathan_core.schemas.enums import (
    Direction,
    EventRisk,
    OrderbookBias,
    Permission,
    SessionLabel,
    TruthStatus,
)
from leviathan_core.schemas.truth import TruthValidationResult
from leviathan_core.state.session_classifier import SessionContext, classify_session

TESTS_ROOT = Path(__file__).resolve().parents[1]
REPLAY_FIXTURES = TESTS_ROOT / "fixtures" / "replay_job"


def _decision(confidence: object) -> DecisionPacket:
    return DecisionPacket(
        decision_id="decision-c102",
        setup_id="setup-c102",
        permission=Permission.APPROVE,
        direction=Direction.LONG,
        confidence=confidence,
        entry_style="breakout",
        scaling_allowed=True,
        justification="synthetic acceptance fixture",
    )


def _truth(modifier: object) -> TruthValidationResult:
    return TruthValidationResult(
        setup_id="setup-c102",
        orderbook_bias=OrderbookBias.BULLISH,
        options_context="synthetic context",
        event_risk=EventRisk.SAFE,
        sentiment_modifier=modifier,
        truth_status=TruthStatus.CONFIRMED,
    )


def _session_quality(quality: object) -> SessionContext:
    return SessionContext(
        label=SessionLabel.NY_OVERLAP,
        quality=quality,
        is_dead_time=False,
    )


def test_existing_finite_replay_persists_byte_identical_result_json(tmp_path: Path) -> None:
    fixture = REPLAY_FIXTURES / "v1-nq.json"
    risk_lock = REPLAY_FIXTURES / "risk_lock.yaml"
    expected_input = (REPLAY_FIXTURES / "v1-nq.input.canonical.golden.json").read_bytes()
    expected = (REPLAY_FIXTURES / "v1-nq.result.canonical.golden.json").read_bytes()

    artifacts = run_replay_job(fixture, risk_lock, tmp_path / "c102-golden")

    assert artifacts.input_path.read_bytes() == expected_input
    assert artifacts.result_path.read_bytes() == expected
    persisted = json.loads(artifacts.result_path.read_bytes())
    assert persisted["decision"]["confidence"] == "0.9133"
    assert persisted["truth"]["sentiment_modifier"] == "0.05"
    assert persisted["session"]["quality"] == "1"


def test_c102_numeric_fields_are_decimal_in_memory_and_classifier_returns_decimal() -> None:
    assert get_type_hints(DecisionPacket)["confidence"] is Decimal
    assert get_type_hints(TruthValidationResult)["sentiment_modifier"] is Decimal
    assert get_type_hints(SessionContext)["quality"] is Decimal

    decision = _decision(Decimal("0.9133"))
    truth = _truth(Decimal("0.05"))
    legacy_float_decision = _decision(0.9133)
    legacy_float_truth = _truth(0.05)
    legacy_float_session = _session_quality(0.45)
    session = classify_session(datetime(2026, 4, 15, 14, 30, tzinfo=UTC))

    assert type(decision.confidence) is Decimal
    assert type(truth.sentiment_modifier) is Decimal
    assert type(legacy_float_decision.confidence) is Decimal
    assert legacy_float_decision.confidence == Decimal("0.9133")
    assert type(legacy_float_truth.sentiment_modifier) is Decimal
    assert legacy_float_truth.sentiment_modifier == Decimal("0.05")
    assert type(legacy_float_session.quality) is Decimal
    assert legacy_float_session.quality == Decimal("0.45")
    assert type(session.quality) is Decimal


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")])
def test_nonfinite_float_inputs_are_rejected(bad: float) -> None:
    with pytest.raises(ValidationError):
        _decision(bad)
    with pytest.raises(ValidationError):
        _truth(bad)
    with pytest.raises(ValidationError):
        _session_quality(bad)


@pytest.mark.parametrize("bad", [Decimal("NaN"), Decimal("Infinity"), Decimal("-Infinity")])
def test_nonfinite_decimal_inputs_are_rejected(bad: Decimal) -> None:
    with pytest.raises(ValidationError):
        _decision(bad)
    with pytest.raises(ValidationError):
        _truth(bad)
    with pytest.raises(ValidationError):
        _session_quality(bad)


@pytest.mark.parametrize(
    ("factory", "lower", "upper", "below", "above"),
    [
        (_decision, Decimal("0"), Decimal("1"), Decimal("-0.0001"), Decimal("1.0001")),
        (_truth, Decimal("-0.25"), Decimal("0.25"), Decimal("-0.2501"), Decimal("0.2501")),
        (_session_quality, Decimal("0"), Decimal("1"), Decimal("-0.0001"), Decimal("1.0001")),
    ],
)
def test_original_numeric_bounds_are_preserved(
    factory: Callable[[object], object],
    lower: Decimal,
    upper: Decimal,
    below: Decimal,
    above: Decimal,
) -> None:
    assert type(factory(lower)) in {DecisionPacket, TruthValidationResult, SessionContext}
    assert type(factory(upper)) in {DecisionPacket, TruthValidationResult, SessionContext}
    for out_of_bounds in (below, above):
        with pytest.raises(ValidationError):
            factory(out_of_bounds)


def test_num001_34_digit_boundary_and_exact_decimal_scale_are_preserved() -> None:
    at_precision_limit = Decimal("0." + "1234567890" * 3 + "1234")
    over_precision_limit = Decimal("0." + "1" * 35)
    trailing_zero_value = Decimal("0.25" + "0" * 50)
    assert len(at_precision_limit.as_tuple().digits) == 34

    assert _decision(at_precision_limit).confidence == at_precision_limit
    assert _truth(at_precision_limit).sentiment_modifier == at_precision_limit
    assert _session_quality(at_precision_limit).quality == at_precision_limit
    assert _truth(trailing_zero_value).sentiment_modifier == Decimal("0.25" + "0" * 50)

    for factory in (_decision, _truth, _session_quality):
        with pytest.raises(ValidationError):
            factory(over_precision_limit)


def test_num001_adjusted_exponent_bounds_are_enforced_without_rounding() -> None:
    minimum = Decimal("1e-38")
    assert _decision(minimum).confidence == minimum
    with pytest.raises(ValidationError):
        _decision(Decimal("1e-39"))


def test_session_classifier_quality_is_exact_at_each_window_boundary() -> None:
    cases = (
        (datetime(2026, 4, 15, 0, 0, tzinfo=UTC), Decimal("0.45")),
        (datetime(2026, 4, 15, 7, 0, tzinfo=UTC), Decimal("0.85")),
        (datetime(2026, 4, 15, 14, 30, tzinfo=UTC), Decimal("1.00")),
        (datetime(2026, 4, 15, 16, 0, tzinfo=UTC), Decimal("0.35")),
    )
    for instant, expected_quality in cases:
        actual = classify_session(instant)
        assert type(actual.quality) is Decimal
        assert actual.quality == expected_quality
