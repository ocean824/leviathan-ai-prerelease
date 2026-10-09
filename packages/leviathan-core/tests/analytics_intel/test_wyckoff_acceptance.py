"""Independent INT-008B boundaries and pivot-confirmation acceptance cases."""

from __future__ import annotations

import json
import random
from dataclasses import replace
from decimal import Decimal, localcontext
from pathlib import Path

import pytest

from leviathan_core.analytics_intel.read_model import AnalyticsError, PolicyV1, decimal_context
from leviathan_core.analytics_intel.wyckoff import (
    WyckoffEvidenceV1,
    WyckoffPolicyV1,
    evaluate_wyckoff,
)

FIXTURE = Path(__file__).parent / "fixtures" / "wyckoff" / "threshold_cases.json"
VALUES = json.loads(FIXTURE.read_text(encoding="utf-8"))


class Calendar:
    def session_for_ns(self, event_ns: int) -> str | None:
        return "2026-09-30"

    def trailing_sessions(self, asof_ns: int, count: int) -> tuple[str, ...]:
        return ("2026-09-30",)

    def hour_for_ns(self, event_ns: int) -> tuple[str, str, int, int] | None:
        return ("2026-09-30", "09", 0, 0)


def policy() -> PolicyV1:
    domain = WyckoffPolicyV1(
        policy_version="INT-008-POLICY-v1",
        volume_window=20,
        atr_window=14,
        climax_volume_multiple=Decimal("2"),
        climax_range_atr_multiple=Decimal("1.5"),
        false_break_atr_multiple=Decimal("0.5"),
        false_break_return_bars=3,
        strength_volume_multiple=Decimal("1.5"),
        secondary_test_atr_multiple=Decimal("0.5"),
        phase_c_hold_bars=3,
        phase_e_break_bars=3,
        ar_pivot_bars=2,
        ar_max_bars=20,
    )
    return PolicyV1("INT-008-POLICY-v1", "wyckoff", domain)


def bar(
    i: int,
    *,
    high: str = "100",
    low: str = "98",
    close: str = "99",
    volume: str = "100",
) -> WyckoffEvidenceV1:
    return WyckoffEvidenceV1(
        evidence_id=f"bar-{i}",
        instrument_id="XYZ",
        venue="XNYS",
        event_ns=i,
        availability_ns=i,
        finalized=True,
        session="2026-09-30",
        calendar_version="calendar-v1",
        timeframe="1m",
        source_version="source-v1",
        adjustment_version="adjustment-v1",
        dataset_version="dataset-v1",
        revision="r1",
        corrects_id=None,
        quality="VALID",
        high=Decimal(high),
        low=Decimal(low),
        close=Decimal(close),
        volume=Decimal(volume),
    )


def sc_bars(*, climax_volume: str = "200", climax_range: str = "3.12") -> list[WyckoffEvidenceV1]:
    result = [bar(i, high="101", low="99", close="100") for i in range(20)]
    with localcontext(decimal_context()):
        low = Decimal("100") - Decimal(climax_range)
    result.append(bar(20, high="100", low=str(low), close="98", volume=climax_volume))
    # The first confirmed two-bar pivot is index 22. The confirmation arrives
    # only after both right-hand bars (23 and 24) are visible.
    result.extend(
        [
            bar(21, high="101", low="99", close="100"),
            bar(22, high="105", low="100", close="103"),
            bar(23, high="103", low="100", close="101"),
            bar(24, high="104", low="100", close="102"),
        ]
    )
    return result


def timestamped_sc_bars() -> list[WyckoffEvidenceV1]:
    return [
        replace(item, event_ns=(index + 1) * 10, availability_ns=(index + 1) * 10)
        for index, item in enumerate(sc_bars())
    ]


def test_climax_inclusive_volume_and_range_boundaries_and_ar_confirmation() -> None:
    # ATR14 is exactly (13*2 + 3.12)/14 = 2.08; 1.5*ATR = 3.12.
    result = evaluate_wyckoff(sc_bars(), asof_ns=24, policy=policy(), calendar=Calendar())

    assert result.status == "READY"
    assert result.phase == "A"
    assert result.label == "ACCUMULATION"
    assert result.event_markers == ("SC", "AR")
    assert result.evidence_ids[:2] == ("bar-20", "bar-22")
    assert result.tile.label == "MODEL_ESTIMATE"
    assert result.policy_version == "INT-008-POLICY-v1"
    assert not {"route_permit", "order_intent", "order_authority"}.intersection(result.tile.payload)


def test_future_available_earlier_bar_does_not_change_asof_replay() -> None:
    bars = timestamped_sc_bars()
    baseline = evaluate_wyckoff(bars, asof_ns=250, policy=policy(), calendar=Calendar())
    late_prior = replace(
        bar(999),
        evidence_id="late-prior-bar",
        event_ns=0,
        availability_ns=1_000,
    )

    with_insert = evaluate_wyckoff(
        [*bars, late_prior], asof_ns=250, policy=policy(), calendar=Calendar()
    )

    assert baseline.status == "READY"
    assert baseline.phase == "A"
    assert with_insert == baseline


def test_seeded_future_available_bar_insertions_preserve_earlier_result() -> None:
    bars = timestamped_sc_bars()
    baseline = evaluate_wyckoff(bars, asof_ns=250, policy=policy(), calendar=Calendar())
    randomizer = random.Random(20_261_005)

    assert baseline.status == "READY"
    assert baseline.phase == "A"
    for insertion in range(64):
        event_ns = randomizer.randrange(0, 501)
        availability_ns = max(251, event_ns) + randomizer.randrange(0, 2_000)
        future_bar = replace(
            bar(1_000 + insertion),
            evidence_id=f"future-insert-{insertion:02d}",
            event_ns=event_ns,
            availability_ns=availability_ns,
        )

        observed = evaluate_wyckoff(
            [*bars, future_bar], asof_ns=250, policy=policy(), calendar=Calendar()
        )

        assert observed == baseline, f"future insertion {insertion} changed as-of replay"


@pytest.mark.parametrize(
    "bars",
    [
        sc_bars(climax_volume="199.9999999999999999999999999999999"),
        sc_bars(climax_range="3.1199999999999999999999999999999"),
    ],
)
def test_climax_requires_both_inclusive_thresholds(bars: list[WyckoffEvidenceV1]) -> None:
    result = evaluate_wyckoff(bars, asof_ns=24, policy=policy(), calendar=Calendar())
    assert result.phase is None
    assert "SC" not in result.event_markers


def test_confirmed_ar_pivot_ties_are_not_pivots() -> None:
    bars = sc_bars()
    # The high at candidate 22 equals its right neighbor at 23, so the strict
    # pivot condition fails. Flat later bars provide no replacement pivot.
    bars[23] = bar(23, high="105", low="100", close="101")
    bars.extend(bar(i) for i in range(25, 43))
    result = evaluate_wyckoff(bars, asof_ns=42, policy=policy(), calendar=Calendar())

    assert result.status == "UNDETERMINED"
    assert result.label == "UNDETERMINED"
    assert result.conflicts == ("AR_NOT_FOUND",)


def test_pivot_is_undetermined_until_both_right_bars_are_available() -> None:
    bars = sc_bars()[:24]
    result = evaluate_wyckoff(bars, asof_ns=23, policy=policy(), calendar=Calendar())

    assert result.status == "UNDETERMINED"
    assert result.conflicts == ("AR_UNCONFIRMED",)
    assert result.event_ns == 23


def test_unfinalized_ar_right_bars_cannot_be_replaced_by_later_visible_bars() -> None:
    bars = sc_bars()
    bars[23] = replace(bars[23], finalized=False)
    bars[24] = replace(bars[24], finalized=False)
    bars.extend((bar(25, high="100", low="99"), bar(26, high="100", low="99")))

    result = evaluate_wyckoff(bars, asof_ns=26, policy=policy(), calendar=Calendar())

    assert result.status == "UNDETERMINED"
    assert result.phase is None
    assert result.conflicts == ("AR_UNCONFIRMED",)


def test_new_climax_extreme_before_pivot_confirmation_is_undetermined() -> None:
    bars = sc_bars()[:22]
    bars[21] = bar(21, high="99", low="96", close="97")
    result = evaluate_wyckoff(bars, asof_ns=21, policy=policy(), calendar=Calendar())

    assert result.status == "UNDETERMINED"
    assert result.conflicts == ("CLIMAX_SUPERSEDED",)


def test_phases_advance_a_through_e_without_skipping() -> None:
    bars = sc_bars()
    bars.extend(
        [
            bar(25, high="101", low="97.5", close="99"),  # ST completes A.
            bar(26, high="100", low="96", close="97"),  # Spring and return inside.
            bar(27, high="100", low="97", close="98"),
            bar(28, high="100", low="97", close="98"),  # Three-bar C hold.
            bar(29, high="107", low="105", close="106", volume="157.5"),  # SOS at 1.5x.
            bar(30, high="107", low="104", close="106"),  # Pullback LPS.
            bar(31, high="107", low="105", close="106"),
            bar(32, high="107", low="105", close="106"),  # Third post-LPS close.
            bar(33, high="107", low="105", close="106"),
        ]
    )
    expected = {24: "A", 25: "B", 26: "C", 28: "C", 29: "D", 30: "D", 31: "D", 32: "D", 33: "E"}

    observed = {asof: evaluate_wyckoff(bars, asof, policy(), Calendar()).phase for asof in expected}
    assert observed == expected


def test_strictly_rising_post_sos_continuation_is_not_lps_or_phase_e() -> None:
    bars = sc_bars()
    bars.extend(
        [
            bar(25, high="101", low="97.5", close="99"),
            bar(26, high="100", low="96", close="97"),
            bar(27, high="100", low="97", close="98"),
            bar(28, high="100", low="97", close="98"),
            bar(29, high="107", low="105", close="106", volume="157.5"),
            bar(30, high="108", low="106", close="107"),
            bar(31, high="109", low="107", close="108"),
            bar(32, high="110", low="108", close="109"),
            bar(33, high="111", low="109", close="110"),
        ]
    )

    result = evaluate_wyckoff(bars, asof_ns=33, policy=policy(), calendar=Calendar())

    assert result.status == "READY"
    assert result.phase == "D"
    assert result.label == "SOS"
    assert "LPS" not in result.event_markers
    assert "E_CONFIRM" not in result.event_markers


def test_climax_collision_is_undetermined_instead_of_selecting_a_side() -> None:
    bars = [bar(i, high="100", low="98", close="99") for i in range(20)]
    # Fresh 20-bar low and high simultaneously, with both climax thresholds met.
    bars.append(bar(20, high="101.12", low="96.88", close="99", volume="200"))
    result = evaluate_wyckoff(bars, 20, policy(), Calendar())

    assert result.status == "UNDETERMINED"
    assert result.label == "UNDETERMINED"
    assert "SC" in result.conflicts and "BC" in result.conflicts


def test_climax_must_be_a_20_bar_extreme() -> None:
    bars = [bar(i, high="101", low="99", close="100") for i in range(20)]
    bars[1] = bar(1, high="98", low="96", close="97")
    bars.append(bar(20, high="100", low="96.1", close="98", volume="200"))
    result = evaluate_wyckoff(bars, 20, policy(), Calendar())

    assert result.phase is None
    assert "SC" not in result.event_markers


def test_bc_utad_distribution_uses_strict_ar_pivot_and_false_break_threshold() -> None:
    bars = [bar(i, high="101", low="99", close="100") for i in range(20)]
    bars.extend(
        [
            bar(20, high="103.12", low="100", close="102", volume="200"),  # BC.
            bar(21, high="101", low="99", close="100"),
            bar(22, high="100", low="95", close="97"),  # Two-bar AR pivot low.
            bar(23, high="100", low="97", close="98"),
            bar(24, high="100", low="96", close="98"),  # Confirms AR.
            bar(25, high="102.5", low="99", close="101", volume="100"),  # ST.
            bar(26, high="104", low="100", close="103", volume="100"),  # UTAD.
        ]
    )
    result = evaluate_wyckoff(bars, asof_ns=26, policy=policy(), calendar=Calendar())

    assert result.status == "READY"
    assert result.label == "UPTHRUST"
    assert result.phase == "C"
    assert result.event_markers == ("BC", "AR", "ST", "UPTHRUST")
    assert result.evidence_ids[:3] == ("bar-20", "bar-22", "bar-24")


def test_late_climax_correction_replays_only_after_availability() -> None:
    bars = sc_bars()
    original = bars[20]
    correction = replace(
        original,
        availability_ns=25,
        revision="r2",
        corrects_id=original.evidence_id,
        volume=Decimal("199"),
    )
    bars.append(correction)

    before = evaluate_wyckoff(bars, asof_ns=24, policy=policy(), calendar=Calendar())
    after = evaluate_wyckoff(bars, asof_ns=25, policy=policy(), calendar=Calendar())

    assert before.phase == "A"
    assert before.label == "ACCUMULATION"
    assert after.phase is None
    assert after.status == "INSUFFICIENT_DATA"
    assert after.tombstone_of == original.evidence_id


def test_wrong_kind_and_version_policies_are_rejected() -> None:
    with pytest.raises(AnalyticsError) as error:
        evaluate_wyckoff(sc_bars(), 24, None, Calendar())  # type: ignore[arg-type]
    assert error.value.code == "MISSING_POLICY"

    with pytest.raises(AnalyticsError) as error:
        PolicyV1("INT-008-POLICY-v1", "echoes", policy().domain)
    assert error.value.code == "UNSUPPORTED_POLICY"

    with pytest.raises(AnalyticsError) as error:
        WyckoffPolicyV1(
            policy_version="INT-008-POLICY-v2",
            volume_window=20,
            atr_window=14,
            climax_volume_multiple=Decimal("2"),
            climax_range_atr_multiple=Decimal("1.5"),
            false_break_atr_multiple=Decimal("0.5"),
            false_break_return_bars=3,
            strength_volume_multiple=Decimal("1.5"),
            secondary_test_atr_multiple=Decimal("0.5"),
            phase_c_hold_bars=3,
            phase_e_break_bars=3,
            ar_pivot_bars=2,
            ar_max_bars=20,
        )
    assert error.value.code == "UNSUPPORTED_POLICY"
