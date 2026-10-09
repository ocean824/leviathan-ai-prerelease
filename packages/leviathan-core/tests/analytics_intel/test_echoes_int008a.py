"""INT-008A point-in-time replay checks for the advisory Echoes kernel."""

from __future__ import annotations

from dataclasses import replace
from decimal import Decimal
from random import Random

import pytest

from leviathan_core.analytics_intel.echoes import (
    EchoPolicyV1,
    EchoQueryV1,
    EchoSampleV1,
    _log_ratio,
    _sqrt_ratio_final,
    evaluate_echoes,
)
from leviathan_core.analytics_intel.read_model import AnalyticsError, PolicyV1
from leviathan_core.numeric import Ratio


class _Calendar:
    def session_for_ns(self, event_ns: int) -> str:
        return "2026-09-30"


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
        {"x": Decimal(50)},
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
        {"x": Decimal(index)},
        Decimal(100 + index),
        "source1",
        "dataset1",
        "rev1",
        "OK",
    )


def test_future_available_insertions_leave_the_full_asof_result_unchanged() -> None:
    samples = [_sample(index) for index in range(25)]
    baseline = evaluate_echoes(_query(), samples, _policy(), _Calendar())
    assert baseline.status == "READY"

    random = Random(8008)
    for case in range(40):
        event_ns = random.randrange(0, 151)
        future = replace(
            _sample(case % len(samples)),
            state_id=f"future-{case}",
            event_ns=event_ns,
            availability_ns=1000,
            revision="future",
        )
        insertion = random.randrange(len(samples) + 1)
        replay = evaluate_echoes(
            _query(),
            [*samples[:insertion], future, *samples[insertion:]],
            _policy(),
            _Calendar(),
        )
        assert replay == baseline


def test_exact_square_root_display_rounds_midpoints_half_even_once() -> None:
    scale = 10**33
    for whole in (scale, scale + 1):
        midpoint_square = (2 * whole + 1) ** 2
        midpoint = Ratio(midpoint_square, 4 * scale * scale)
        rounded = _sqrt_ratio_final(midpoint)
        expected_units = whole + (whole % 2)
        expected = Decimal((0, tuple(int(digit) for digit in str(expected_units)), -33))
        assert rounded == expected

    assert _sqrt_ratio_final(Ratio((2 * scale + 1) ** 2 + 1, 4 * scale * scale)) > 1


def test_parallel_feature_version_cannot_displace_pinned_history() -> None:
    samples = [_sample(index) for index in range(25)]
    original = evaluate_echoes(_query(), samples, _policy(), _Calendar())
    other_version = [
        replace(
            sample,
            feature_version="f2",
            availability_ns=sample.availability_ns + 1,
            close=Decimal(500),
            state_id=f"other-{sample.bar_index}",
        )
        for sample in samples[:3]
    ]
    replay = evaluate_echoes(_query(), [*samples, *other_version], _policy(), _Calendar())
    assert replay == original


def test_same_time_revision_sequence_is_numeric_and_ambiguous_ties_fail() -> None:
    samples = [_sample(index) for index in range(25)]
    ninth = replace(samples[10], revision="r9", close=Decimal(111))
    tenth = replace(samples[10], revision="r10", close=Decimal(112))
    replay = evaluate_echoes(_query(), [*samples, tenth, ninth], _policy(), _Calendar())
    provenance = replay.tile.payload["contributing_provenance"]
    assert next(row for row in provenance if row["bar_index"] == 10)["revision"] == "r10"
    with pytest.raises(AnalyticsError, match="HISTORY_CONFLICT"):
        evaluate_echoes(
            _query(), [*samples, ninth, replace(ninth, close=Decimal(113))], _policy(), _Calendar()
        )


def test_query_bar_endpoint_and_late_correction_have_complete_provenance() -> None:
    samples = [_sample(index) for index in range(30)]
    query = replace(_query(), bar_index=29, event_ns=30, availability_ns=30)
    before = evaluate_echoes(query, samples, _policy(), _Calendar())
    assert before.status == "READY"
    assert "s24" in before.neighbors
    correction = replace(
        samples[29],
        close=Decimal(190),
        availability_ns=102,
        source_version="source2",
        dataset_version="dataset2",
        revision="rev2",
    )
    after = evaluate_echoes(
        replace(query, asof_ns=102), [*samples, correction], _policy(), _Calendar()
    )
    assert after.tile.availability_ns == "102"
    assert after.tile.source_version == "MIXED"
    assert after.tile.dataset_version == "MIXED"
    assert after.forward_returns != before.forward_returns
    rows = after.tile.payload["contributing_provenance"]
    endpoint = next(row for row in rows if row["bar_index"] == 29)
    assert endpoint["revision"] == "rev2"
    assert endpoint["roles"] == ("BASELINE_ENDPOINT", "NEIGHBOR_ENDPOINT")
    assert after.tile.payload["confidence_semantics"] == "POSITIVE_SHARE"
    assert after.tile.payload["unconditional_regime_scope"] == "ALL_REGIMES"


def test_log_ratio_matches_correctly_rounded_high_precision_reference() -> None:
    start = Decimal("4.02780899625925003011276566235960")
    end = Decimal("7.21725360494395316532970479102501")
    _, displayed = _log_ratio(Ratio.from_decimals(end, start))
    assert displayed == Decimal("0.5832519386824964132662214060462561")
