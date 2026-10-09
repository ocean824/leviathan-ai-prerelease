"""Worker unit checks for the bounded Echoes kernel."""

from __future__ import annotations

import copy
import pickle
from dataclasses import replace
from decimal import Decimal, localcontext

import pytest

from leviathan_core.analytics_intel.echoes import (
    EchoPolicyV1,
    EchoQueryV1,
    EchoSampleV1,
    evaluate_echoes,
)
from leviathan_core.analytics_intel.read_model import AnalyticsError, PolicyV1


class _Calendar:
    def session_for_ns(self, event_ns: int) -> str:
        return "2026-09-30"

    def trailing_sessions(self, asof_ns: int, count: int) -> tuple[str, ...]:
        return ("2026-09-30",)

    def hour_for_ns(self, event_ns: int) -> tuple[str, str, int, int]:
        return "2026-09-30", "09", 0, -300


def _policy() -> PolicyV1:
    return PolicyV1(
        "INT-008-POLICY-v1",
        "echoes",
        EchoPolicyV1("INT-008-POLICY-v1", 20, 5, (5, 20, 60), Decimal("1.96"), Decimal("0.2")),
    )


def _query() -> EchoQueryV1:
    return EchoQueryV1(
        "query",
        "A",
        "XNYS",
        100,
        101,
        101,
        "f1",
        "r1",
        "bull",
        {"x": Decimal(50), "constant": Decimal(1)},
        5,
        "cal1",
        "TEST",
        False,
        101,
        True,
    )


def _sample(index: int) -> EchoSampleV1:
    return EchoSampleV1(
        f"s{index}",
        "A",
        "XNYS",
        index,
        index + 1,
        index + 1,
        True,
        "f1",
        "r1",
        "bull",
        {"x": Decimal(index), "constant": Decimal(1)},
        Decimal(100 + index),
        "source1",
        "dataset1",
        "rev1",
        "OK",
    )


def test_twenty_mature_neighbors_and_wilson_boundary() -> None:
    samples = [_sample(index) for index in range(25)]
    insufficient = evaluate_echoes(_query(), samples[:-1], _policy(), _Calendar())
    assert insufficient.status == "INSUFFICIENT_DATA"
    assert len(insufficient.neighbors) == 19
    ready = evaluate_echoes(_query(), samples, _policy(), _Calendar())
    assert ready.status == "READY"
    assert len(ready.neighbors) == 20
    assert ready.positive_share == 1
    assert ready.wilson_low is not None and 0 < ready.wilson_low < 1
    assert ready.wilson_high == 1
    assert ready.cohens_d == 0
    assert ready.effect_label == "NEGLIGIBLE"
    assert ready.excluded_features == ("constant",)
    assert ready.tile.to_dict()["label"] == "MODEL_ESTIMATE"


def test_future_revision_is_invisible_and_decimal_context_is_owned() -> None:
    samples = [_sample(index) for index in range(25)]
    future = replace(samples[5], close=Decimal(900), availability_ns=102, revision="rev2")
    normal = evaluate_echoes(_query(), samples, _policy(), _Calendar())
    with localcontext() as context:
        context.prec = 5
        context.Emax = 9
        alternate = evaluate_echoes(_query(), [*samples, future], _policy(), _Calendar())
    assert alternate.forward_returns == normal.forward_returns
    assert alternate.tile.to_dict() == normal.tile.to_dict()


def test_neighbor_order_uses_exact_distance_when_display_values_round_to_a_tie() -> None:
    query = replace(_query(), features={"x": Decimal("1e20"), "y": Decimal(0)})
    samples = [
        replace(
            _sample(index),
            features={
                "x": Decimal(0 if index < 2 else 1),
                "y": Decimal(1 if index == 0 else 0),
            },
        )
        for index in range(25)
    ]
    result = evaluate_echoes(query, samples, _policy(), _Calendar())
    assert result.status == "READY"
    assert result.neighbors.index("s1") < result.neighbors.index("s0")
    first = result.neighbors.index("s1")
    second = result.neighbors.index("s0")
    assert result.distances[first] == result.distances[second]


def test_derived_distance_can_exceed_input_exponent_limit() -> None:
    query = replace(_query(), features={"x": Decimal("1E+38")})
    samples = [
        replace(_sample(index), features={"x": Decimal(index) * Decimal("1E-38")})
        for index in range(25)
    ]
    result = evaluate_echoes(query, samples, _policy(), _Calendar())
    assert result.status == "READY"
    assert all(distance.adjusted() > 38 for distance in result.distances)


def test_policy_and_sample_freeze_paths() -> None:
    policy = _policy()
    with pytest.raises(AnalyticsError, match="POLICY_OUT_OF_BOUNDS"):
        replace(policy.domain, k=19)
    sample = _sample(0)
    for action in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(AnalyticsError):
            action(sample)
    with pytest.raises(TypeError):
        sample.features["x"] = Decimal(2)
