"""C-102 exact-decimal model boundary and replay compatibility tests."""

from __future__ import annotations

import json
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

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "replay_job"


def _decision(confidence: object) -> DecisionPacket:
    return DecisionPacket(
        decision_id="decision-c102",
        setup_id="setup-c102",
        permission=Permission.APPROVE,
        direction=Direction.LONG,
        confidence=confidence,
        entry_style="breakout",
        scaling_allowed=True,
        justification="synthetic C-102 decimal fixture",
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


def _session(quality: object) -> SessionContext:
    return SessionContext(label=SessionLabel.NY_OVERLAP, quality=quality, is_dead_time=False)


def test_numeric_types_are_decimal_and_legacy_json_numbers_validate() -> None:
    assert get_type_hints(DecisionPacket)["confidence"] is Decimal
    assert get_type_hints(TruthValidationResult)["sentiment_modifier"] is Decimal
    assert get_type_hints(SessionContext)["quality"] is Decimal

    decision = DecisionPacket.model_validate_json(
        '{"decision_id":"d","setup_id":"s","permission":"approve",'
        '"direction":"long","confidence":0.9133,"entry_style":"breakout",'
        '"scaling_allowed":true,"justification":"legacy"}'
    )
    truth = TruthValidationResult.model_validate_json(
        '{"setup_id":"s","orderbook_bias":"bullish","options_context":"ctx",'
        '"event_risk":"safe","sentiment_modifier":0.05,"truth_status":"confirmed"}'
    )
    session = SessionContext.model_validate_json(
        '{"label":"ny_overlap","quality":1.0,"is_dead_time":false}'
    )
    assert decision.confidence == Decimal("0.9133") and type(decision.confidence) is Decimal
    assert truth.sentiment_modifier == Decimal("0.05") and type(truth.sentiment_modifier) is Decimal
    assert session.quality == Decimal("1") and type(session.quality) is Decimal


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")])
def test_nonfinite_legacy_float_inputs_are_rejected(bad: float) -> None:
    for build in (_decision, _truth, _session):
        with pytest.raises(ValidationError):
            build(bad)


def test_decimal_bounds_and_num001_precision_are_enforced_without_rounding() -> None:
    assert _decision(Decimal("0.1234567890123456789012345678901234")).confidence == Decimal(
        "0.1234567890123456789012345678901234"
    )
    assert _truth(Decimal("0.250")).sentiment_modifier == Decimal("0.25")
    assert _session(Decimal("1.000")).quality == Decimal("1")

    for build, invalid in (
        (_decision, Decimal("1.0001")),
        (_decision, Decimal("0." + "1" * 35)),
        (_truth, Decimal("-0.2501")),
        (_truth, Decimal("0." + "1" * 35)),
        (_session, Decimal("-0.0001")),
        (_session, Decimal("1.0001")),
    ):
        with pytest.raises(ValidationError):
            build(invalid)

    with pytest.raises(ValidationError):
        _decision(Decimal("1e-39"))


def test_session_classifier_returns_exact_decimal_at_window_boundaries() -> None:
    expected = (
        (datetime(2026, 4, 15, 0, 0, tzinfo=UTC), Decimal("0.45")),
        (datetime(2026, 4, 15, 7, 0, tzinfo=UTC), Decimal("0.85")),
        (datetime(2026, 4, 15, 14, 30, tzinfo=UTC), Decimal("1.00")),
        (datetime(2026, 4, 15, 16, 0, tzinfo=UTC), Decimal("0.35")),
    )
    for instant, quality in expected:
        actual = classify_session(instant)
        assert type(actual.quality) is Decimal
        assert actual.quality == quality


def test_replay_result_bytes_match_preexisting_golden_fixture(tmp_path: Path) -> None:
    artifacts = run_replay_job(
        FIXTURES / "v1-nq.json",
        FIXTURES / "risk_lock.yaml",
        tmp_path / "c102-decimal-golden",
    )
    expected_input = (FIXTURES / "v1-nq.input.canonical.golden.json").read_bytes()
    expected = (FIXTURES / "v1-nq.result.canonical.golden.json").read_bytes()
    assert artifacts.input_path.read_bytes() == expected_input
    actual = artifacts.result_path.read_bytes()
    assert actual == expected
    persisted = json.loads(actual)
    assert persisted["decision"]["confidence"] == "0.9133"
    assert persisted["truth"]["sentiment_modifier"] == "0.05"
    assert persisted["session"]["quality"] == "1"
