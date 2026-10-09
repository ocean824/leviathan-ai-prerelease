"""Worker unit checks for confirmed Wyckoff evidence transitions."""

from __future__ import annotations

from dataclasses import replace
from decimal import Decimal
from random import Random

import pytest

from leviathan_core.analytics_intel.read_model import AnalyticsError, PolicyV1
from leviathan_core.analytics_intel.wyckoff import (
    WyckoffEvidenceV1,
    WyckoffPolicyV1,
    evaluate_wyckoff,
)


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
        "wyckoff",
        WyckoffPolicyV1(
            "INT-008-POLICY-v1",
            20,
            14,
            Decimal(2),
            Decimal("1.5"),
            Decimal("0.5"),
            3,
            Decimal("1.5"),
            Decimal("0.5"),
            3,
            3,
            2,
            20,
        ),
    )


def _bar(
    index: int,
    high: str = "11",
    low: str = "9",
    close: str = "10",
    volume: str = "1",
) -> WyckoffEvidenceV1:
    return WyckoffEvidenceV1(
        f"bar{index}",
        "A",
        "XNYS",
        index + 1,
        index + 1,
        True,
        "2026-09-30",
        "cal1",
        "1m",
        "source1",
        "adj1",
        "dataset1",
        "rev1",
        None,
        "OK",
        Decimal(high),
        Decimal(low),
        Decimal(close),
        Decimal(volume),
    )


def _sequence() -> list[WyckoffEvidenceV1]:
    return [
        *[_bar(index) for index in range(20)],
        _bar(20, "10", "6", "8", "3"),
        _bar(21, "11", "8", "9"),
        _bar(22, "13", "8", "10"),
        _bar(23, "12", "8", "10"),
        _bar(24, "11.5", "8", "10"),
        _bar(25, "10", "6.5", "8"),
    ]


def test_ar_requires_two_confirming_bars_then_st_starts_b() -> None:
    sequence = _sequence()
    pending = evaluate_wyckoff(sequence, 23, _policy(), _Calendar())
    assert pending.label == "UNDETERMINED"
    assert "AR_UNCONFIRMED" in pending.conflicts
    confirmed = evaluate_wyckoff(sequence, 25, _policy(), _Calendar())
    assert confirmed.phase == "A"
    assert confirmed.event_ns == 25
    assert "AR" in confirmed.event_markers
    assert "bar22" in confirmed.evidence_ids
    b = evaluate_wyckoff(sequence, 26, _policy(), _Calendar())
    assert b.phase == "B"
    assert b.label == "ACCUMULATION"
    assert "ST" in b.event_markers


def test_new_extreme_blocks_unconfirmed_ar() -> None:
    sequence = _sequence()
    sequence[21] = _bar(21, "11", "5.9", "9")
    result = evaluate_wyckoff(sequence, 26, _policy(), _Calendar())
    assert result.label == "UNDETERMINED"
    assert result.conflicts == ("CLIMAX_SUPERSEDED",)


def test_bound_policy_rejected_during_construction() -> None:
    with pytest.raises(AnalyticsError, match="POLICY_OUT_OF_BOUNDS"):
        replace(_policy().domain, ar_pivot_bars=3)


def test_buying_climax_uses_mirrored_pivot_and_utad() -> None:
    bars = [
        *[_bar(i, "101", "99", "100", "100") for i in range(20)],
        _bar(20, "104", "100", "102", "300"),
        _bar(21, "101", "99", "100", "100"),
        _bar(22, "100", "96", "98", "100"),
        _bar(23, "101", "97", "99", "100"),
        _bar(24, "100", "98", "99", "100"),
        _bar(25, "103.5", "99", "100", "100"),
        _bar(26, "104.5", "100", "103", "100"),
    ]
    result = evaluate_wyckoff(bars, 27, _policy(), _Calendar())
    assert result.label == "UPTHRUST"
    assert result.phase == "C"
    assert result.event_markers[:3] == ("BC", "AR", "ST")


def test_late_linked_correction_changes_revision_without_rewriting_replay() -> None:
    bars = _sequence()
    old = bars[21]
    corrected = replace(
        old,
        high=Decimal("11.2"),
        availability_ns=100,
        revision="rev2",
        corrects_id=old.evidence_id,
    )
    earlier = evaluate_wyckoff([*bars, corrected], 99, _policy(), _Calendar())
    later = evaluate_wyckoff([*bars, corrected], 100, _policy(), _Calendar())
    replay = evaluate_wyckoff(bars, 99, _policy(), _Calendar())
    assert earlier.revision == replay.revision
    assert later.revision != earlier.revision
    assert later.tombstone_of == old.evidence_id
    assert evaluate_wyckoff([corrected, *bars], 100, _policy(), _Calendar()).revision == (
        later.revision
    )
    with pytest.raises(AnalyticsError, match="UNLINKED_CORRECTION"):
        evaluate_wyckoff(
            [replace(corrected, corrects_id="wrong"), *bars],
            100,
            _policy(),
            _Calendar(),
        )


def test_future_available_bars_cannot_change_asof_slots_or_cadence() -> None:
    bars = [
        replace(bar, event_ns=(index + 1) * 10, availability_ns=(index + 1) * 10)
        for index, bar in enumerate(_sequence())
    ]
    asof_ns = 250
    baseline = evaluate_wyckoff(bars, asof_ns, _policy(), _Calendar())
    assert baseline.phase == "A"

    random = Random(2088)
    event_times = [0, 5, 245, 250, 260, 400]
    event_times.extend(random.randrange(0, 401) for _ in range(40))
    for case, event_ns in enumerate(event_times):
        unavailable = replace(
            _bar(1000 + case),
            event_ns=event_ns,
            availability_ns=max(asof_ns + 1000, event_ns),
        )
        insertion = random.randrange(len(bars) + 1)
        replay = evaluate_wyckoff(
            [*bars[:insertion], unavailable, *bars[insertion:]],
            asof_ns,
            _policy(),
            _Calendar(),
        )
        assert replay == baseline
