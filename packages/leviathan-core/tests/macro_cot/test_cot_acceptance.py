from __future__ import annotations

import copy
import json
import pickle
from dataclasses import fields, replace
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal, localcontext
from pathlib import Path

import pytest

from leviathan_core.macro_cot import (
    COTMarketMapV1,
    COTPolicyV1,
    COTReportVintageV1,
    COTResultV1,
    COTSnapshotV1,
    COTValidationError,
    calculate,
)

FIXTURES = Path(__file__).parent / "fixtures" / "kernel"
FUTURE_ASOF_NS = int(datetime(2030, 1, 1, tzinfo=UTC).timestamp() * 1_000_000_000)


def _report_ns(report_day: date, offset_ns: int = 0) -> int:
    midnight = datetime(report_day.year, report_day.month, report_day.day, tzinfo=UTC)
    if offset_ns >= 1_000_000_000_000_000:
        return offset_ns
    return int(midnight.timestamp() * 1_000_000_000) + offset_ns


def _row(*, report_date: date, revision: int = 1, published: int = 200,
         received: int | None = None, available: int | None = None,
         long: str = "130", short: str = "70", oi: str = "1000",
         preliminary: bool = False, source: str = "CFTC", constituent: str = "c1",
         market_code: str | None = None):
    received = published if received is None else received
    available = received if available is None else available
    suffix = constituent[1:] if constituent.startswith("c") else ""
    default_code = int(suffix) if suffix.isdigit() else 99
    code = market_code or f"{default_code:03d}"
    return COTReportVintageV1(
        cftc_market_code=code, constituent_id=constituent,
        report_date=report_date, report_family="Disaggregated Futures",
        source=source, revision=revision, is_preliminary=preliminary,
        published_ns=_report_ns(report_date, published),
        received_ns=_report_ns(report_date, received),
        available_ns=_report_ns(report_date, available),
        mm_long=Decimal(long), mm_short=Decimal(short), open_interest=Decimal(oi),
    )


def _policy(**kwargs):
    return COTPolicyV1(min_lookback_samples=104, **kwargs)


def _snapshot(rows, constituents=("c1",), *, effective_from=date(2020, 1, 1), driver_weights=()):
    mapping = COTMarketMapV1(
        market_id="CL", version="map-v1", constituent_ids=tuple(constituents),
        effective_from=effective_from,
        constituent_codes=tuple((ident, _row_code(ident)) for ident in constituents),
        driver_weights=driver_weights,
    )
    return COTSnapshotV1(market_map=mapping, vintages=tuple(rows))


def _row_code(constituent: str) -> str:
    suffix = constituent[1:] if constituent.startswith("c") else ""
    return f"{int(suffix):03d}" if suffix.isdigit() else "099"


def test_actual_release_and_revision_visibility_are_point_in_time():
    fixture = json.loads((FIXTURES / "vintage_release.json").read_text(encoding="utf-8-sig"))
    report_day = date.fromisoformat(fixture["report_date"])
    rows = [
        _row(report_date=report_day, revision=fixture["final_revision"],
             published=fixture["release_ns"], long=fixture["current_long"]),
        _row(report_date=report_day, revision=fixture["higher_preliminary_revision"],
             published=fixture["release_ns"], long="999", preliminary=True),
    ]
    invisible = calculate(
        _snapshot(rows), _policy(),
        _report_ns(report_day, fixture["asof_before_release_ns"]),
    )
    assert invisible.status == "UNAVAILABLE"
    visible = calculate(_snapshot(rows), _policy(), _report_ns(report_day, fixture["release_ns"]))
    assert visible.is_preliminary is False
    assert visible.newer_preliminary_not_selected is True
    assert visible.selected_revision_ids == (("c1", fixture["final_revision"]),)
    assert visible.net_mm == Decimal("60")


def test_preliminary_is_explicit_when_no_finalized_vintage_is_visible():
    row = _row(report_date=date(2026, 9, 1), revision=4, preliminary=True)
    result = calculate(_snapshot([row]), _policy(), FUTURE_ASOF_NS)
    assert result.is_preliminary is True
    assert "PRELIMINARY_ONLY" in result.reason_codes


def test_normalization_and_wow_use_previous_available_report():
    older = date(2026, 8, 18)
    current = date(2026, 9, 1)  # skipped report date does not synthesize a zero row
    rows = [
        _row(report_date=older, long="110", short="80", oi="900", published=100),
        _row(report_date=current, long="130", short="70", oi="1000", published=200),
    ]
    result = calculate(_snapshot(rows), _policy(), FUTURE_ASOF_NS)
    assert result.net_mm == Decimal("60")
    assert result.net_mm_pct_oi == Decimal("0.06")
    assert result.wow_delta_mm == Decimal("30")
    assert result.gap is True
    assert result.previous_report_date == older


def test_percentile_window_uses_normalized_samples_and_inclusive_ties():
    start = date(2023, 9, 5)
    rows = [
        _row(report_date=start + timedelta(days=7 * i), long="101", short="100", oi="1000",
             published=100 + i, revision=1)
        for i in range(104)
    ]
    # Same normalized net/OI value: inclusive empirical CDF puts the current tie at 100.
    result = calculate(_snapshot(rows), _policy(), FUTURE_ASOF_NS)
    assert result.percentile == Decimal("100")
    assert result.sample_count == 104
    assert result.lookback_samples_used == 104
    assert result.low_confidence is False


def test_unranked_source_and_invalid_oi_fail_closed():
    with pytest.raises(COTValidationError):
        calculate(_snapshot([_row(report_date=date(2026, 9, 1), source="unknown-feed")]),
                  _policy(), FUTURE_ASOF_NS)
    with pytest.raises(COTValidationError):
        calculate(_snapshot([_row(report_date=date(2026, 9, 1), oi="0")]),
                  _policy(), FUTURE_ASOF_NS)



def test_partial_constituent_mapping_is_degraded_without_percentile_or_tags():
    row = _row(report_date=date(2026, 9, 1), constituent="c1")
    result = calculate(
        _snapshot([row], constituents=("c1", "c2")), _policy(), FUTURE_ASOF_NS
    )
    assert result.status == "DEGRADED"
    assert result.percentile is None
    assert result.contrarian_tag is None
    assert result.confirmation_bias is None


def test_visible_unmapped_constituent_fails_closed_but_future_unmapped_row_is_invisible():
    visible = _row(report_date=date(2026, 9, 1), constituent="outside-map")
    with pytest.raises(COTValidationError, match="unmapped constituent"):
        calculate(_snapshot([visible]), _policy(), FUTURE_ASOF_NS)
    future = _row(report_date=date(2026, 9, 1), constituent="outside-map", published=500)
    result = calculate(
        _snapshot([future]), _policy(),
        _report_ns(future.report_date, 499),
    )
    assert result.status == "UNAVAILABLE"


def test_mapping_effective_date_truncates_history_and_too_few_samples_withholds_percentile():
    start = date(2022, 1, 4)
    rows = [_row(report_date=start + timedelta(days=7 * i), long=str(100 + i),
                 short="100", oi="1000", published=100 + i) for i in range(156)]
    mapping = COTMarketMapV1(
        market_id="CL", version="map-v2", constituent_ids=("c1",),
        effective_from=start + timedelta(days=7 * 100),
        constituent_codes=(("c1", "001"),),
    )
    result = calculate(COTSnapshotV1(mapping, tuple(rows)), _policy(), FUTURE_ASOF_NS)
    assert "LOOKBACK_TRUNCATED_BY_MAPPING" in result.reason_codes
    assert result.lookback_samples_requested == 156
    assert result.lookback_samples_used == 56
    insufficient = calculate(
        COTSnapshotV1(mapping, tuple(rows)),
        COTPolicyV1(min_lookback_samples=104), FUTURE_ASOF_NS,
    )
    assert insufficient.percentile is None
    assert insufficient.contrarian_tag is None
    assert "INSUFFICIENT_HISTORY" in insufficient.reason_codes


def test_mapping_must_be_effective_for_latest_visible_report():
    report = _row(report_date=date(2026, 9, 1))
    mapping = COTMarketMapV1(
        market_id="CL", version="future-map", constituent_ids=("c1",),
        effective_from=date(2026, 9, 2), constituent_codes=(("c1", "001"),),
    )
    with pytest.raises(COTValidationError) as exc:
        calculate(COTSnapshotV1(mapping, (report,)), _policy(), FUTURE_ASOF_NS)
    assert exc.value.reason_code == "MAPPING_VERSION_NOT_EFFECTIVE"


def test_driver_weight_validation_uses_decimal_tolerance():
    valid = COTMarketMapV1(
        market_id="CL", version="weighted", constituent_ids=("c1",),
        effective_from=date(2020, 1, 1), constituent_codes=(("c1", "001"),),
        driver_weights=(("Energy", Decimal("0.995")),),
    )
    row = _row(report_date=date(2026, 9, 1))
    calculate(COTSnapshotV1(valid, (row,)), _policy(), FUTURE_ASOF_NS)
    invalid = COTMarketMapV1(
        market_id="CL", version="bad-weight", constituent_ids=("c1",),
        effective_from=date(2020, 1, 1), constituent_codes=(("c1", "001"),),
        driver_weights=(("Energy", Decimal("0.98")),),
    )
    with pytest.raises(COTValidationError):
        calculate(COTSnapshotV1(invalid, (row,)), _policy(), FUTURE_ASOF_NS)




def test_percentile_tag_boundaries_use_the_156_report_window():
    latest = date(2026, 9, 1)
    def result_at_rank(rank):
        values = [value for value in range(1, 157) if value != rank]
        rows = [
            _row(report_date=latest - timedelta(days=7 * (len(values) - i)),
                 long=str(100 + value), short="100", oi="1000", published=100 + i)
            for i, value in enumerate(values)
        ]
        rows.append(_row(report_date=latest, long=str(100 + rank), short="100",
                         oi="1000", published=200))
        return calculate(_snapshot(rows), _policy(), FUTURE_ASOF_NS)

    at_10_below = result_at_rank(15)
    at_10_above = result_at_rank(16)
    at_35_below = result_at_rank(54)
    at_35_above = result_at_rank(55)
    at_65_below = result_at_rank(101)
    at_65_above = result_at_rank(102)
    at_90_below = result_at_rank(140)
    at_90_above = result_at_rank(141)
    assert at_10_below.contrarian_tag == "contrarian_long"
    assert at_10_above.contrarian_tag == "none"
    assert at_35_below.confirmation_bias == "bias_short_cover"
    assert at_35_above.confirmation_bias == "neutral"
    assert at_65_below.confirmation_bias == "neutral"
    assert at_65_above.confirmation_bias == "bias_trend_follow_long"
    assert at_90_below.contrarian_tag == "none"
    assert at_90_above.contrarian_tag == "contrarian_short"


def test_exact_percentile_thresholds_are_inclusive_for_all_policy_tags():
    latest = date(2026, 9, 1)

    def at_exact_percentile(rank):
        values = [value for value in range(1, 141) if value != rank]
        rows = [
            _row(report_date=latest - timedelta(days=7 * (len(values) - index)),
                 long=str(100 + value), short="100", oi="1000", published=100 + index)
            for index, value in enumerate(values)
        ]
        rows.append(_row(report_date=latest, long=str(100 + rank), short="100",
                         oi="1000", published=1000))
        return calculate(_snapshot(rows), _policy(), FUTURE_ASOF_NS)

    at_10 = at_exact_percentile(14)
    at_35 = at_exact_percentile(49)
    at_65 = at_exact_percentile(91)
    at_90 = at_exact_percentile(126)
    assert at_10.percentile == Decimal("10")
    assert at_10.contrarian_tag == "contrarian_long"
    assert at_35.percentile == Decimal("35")
    assert at_35.confirmation_bias == "bias_short_cover"
    assert at_65.percentile == Decimal("65")
    assert at_65.confirmation_bias == "bias_trend_follow_long"
    assert at_90.percentile == Decimal("90")
    assert at_90.contrarian_tag == "contrarian_short"


def test_exact_100_of_104_percentile_is_compared_without_rounded_promotion():
    latest = date(2026, 9, 1)
    rank = 100
    values = [value for value in range(1, 105) if value != rank]
    rows = [
        _row(report_date=latest - timedelta(days=7 * (len(values) - index)),
             long=str(100 + value), short="100", oi="1000", published=100 + index)
        for index, value in enumerate(values)
    ]
    rows.append(_row(report_date=latest, long=str(100 + rank), short="100",
                     oi="1000", published=1000))
    snapshot = _snapshot(rows)
    below = calculate(
        snapshot, _policy(contrarian_short_min=Decimal("96.15384615384615384615384615384614")),
        FUTURE_ASOF_NS,
    )
    above = calculate(
        snapshot, _policy(contrarian_short_min=Decimal("96.15384615384615384615384615384616")),
        FUTURE_ASOF_NS,
    )
    result = below
    assert result.sample_count == 104
    assert result.percentile == Decimal("96.15384615384615384615384615384615")
    assert result.contrarian_tag == "contrarian_short"
    assert result.contrarian_tag != "contrarian_long"
    assert above.contrarian_tag == "none"


def test_latest_vintage_revision_is_asof_stable_and_driver_mapping_is_preserved():
    report_day = date(2026, 9, 1)
    rows = (
        _row(report_date=report_day, revision=1, published=100, long="120"),
        _row(report_date=report_day, revision=2, published=200, long="140"),
    )
    mapping = COTMarketMapV1(
        market_id="CL", version="energy-v1", constituent_ids=("c1",),
        effective_from=date(2020, 1, 1), constituent_codes=(("c1", "001"),),
        driver_weights=(("Energy", Decimal("1")),),
    )
    snapshot = COTSnapshotV1(mapping, rows)
    earlier = calculate(snapshot, _policy(), _report_ns(report_day, 150))
    later = calculate(snapshot, _policy(), _report_ns(report_day, 250))
    assert earlier.selected_revision_ids == (("c1", 1),)
    assert later.selected_revision_ids == (("c1", 2),)
    assert earlier.net_mm == Decimal("50")
    assert later.net_mm == Decimal("70")
    assert earlier.driver_weights == (("Energy", Decimal("1")),)
    assert later.driver_weights == earlier.driver_weights




def test_confidence_boundary_at_104_and_full_156_report_window():
    start = date(2023, 9, 5)
    for count, low_confidence in ((103, True), (104, False), (155, False), (156, False)):
        rows = [
            _row(report_date=start + timedelta(days=7 * i), long=str(100 + (i % 17)),
                 short="100", oi="1000", published=100 + i)
            for i in range(count)
        ]
        result = calculate(_snapshot(rows), _policy(), FUTURE_ASOF_NS)
        assert result.sample_count == min(count, 156)
        assert result.low_confidence is low_confidence
        assert result.lookback_samples_requested == 156


def test_release_before_position_report_date_is_rejected():
    report_day = date(2026, 9, 1)
    early_release = int(datetime(2026, 8, 1, tzinfo=UTC).timestamp() * 1_000_000_000)
    row = _row(report_date=report_day, published=early_release)
    asof = int(datetime(2026, 9, 2, tzinfo=UTC).timestamp() * 1_000_000_000)

    with pytest.raises(COTValidationError) as exc:
        calculate(_snapshot([row]), _policy(), asof)

    assert exc.value.reason_code == "RELEASE_BEFORE_REPORT"


def test_sixty_digit_near_tie_is_rejected_but_exact_supported_values_rank_exactly():
    report_day = date(2026, 9, 1)
    sixty_digit = Decimal("0." + "9" * 60)
    with pytest.raises(COTValidationError) as too_precise:
        calculate(
            _snapshot([_row(report_date=report_day, long=str(sixty_digit), short="0")]),
            _policy(), FUTURE_ASOF_NS,
        )
    assert too_precise.value.reason_code == "PRECISION_EXCEEDED"

    nearly_one = Decimal("0." + "9" * 34)
    rows = [
        _row(report_date=report_day - timedelta(days=7 * (104 - index)),
             long="0.9", short="0", oi="1")
        for index in range(102)
    ]
    rows.extend((
        _row(report_date=report_day - timedelta(days=7), long="1", short="0", oi="1"),
        _row(report_date=report_day, long=str(nearly_one), short="0", oi="1"),
    ))
    result = calculate(_snapshot(rows), _policy(), FUTURE_ASOF_NS)
    assert result.percentile == Decimal("99.03846153846153846153846153846154")


def test_result_arithmetic_ignores_ambient_decimal_context():
    report_day = date(2026, 9, 1)
    rows = (
        _row(report_date=report_day - timedelta(days=7), long="1000000.000000000",
             short="0", oi="1000000"),
        _row(report_date=report_day, long="1000000.123456789", short="0", oi="1000000"),
    )
    snapshot = _snapshot(rows)
    expected = calculate(snapshot, _policy(), FUTURE_ASOF_NS)
    with localcontext() as context:
        context.prec = 6
        constrained = calculate(snapshot, _policy(), FUTURE_ASOF_NS)

    assert constrained == expected
    assert expected.wow_delta_mm == Decimal("0.123456789")
    assert expected.wow_delta_pct_oi == Decimal("1.23456789E-7")


@pytest.mark.parametrize(
    "policy_changes",
    (
        {"weight_tolerance": Decimal("1")},
        {"low_confidence_min_samples": 1},
    ),
)
def test_policy_cannot_weaken_backend_v1_bounds(policy_changes):
    row = _row(report_date=date(2026, 9, 1))
    with pytest.raises(COTValidationError) as exc:
        calculate(_snapshot([row]), _policy(**policy_changes), FUTURE_ASOF_NS)
    assert exc.value.reason_code == "POLICY_OUT_OF_BOUNDS"


def test_finalized_lower_priority_source_beats_ranked_preliminary():
    report_day = date(2026, 9, 1)
    rows = (
        _row(report_date=report_day, source="CFTC", revision=9,
             long="999", preliminary=True),
        _row(report_date=report_day, source="BACKFILL", revision=2,
             long="140", short="70"),
    )
    policy = _policy(source_priority=("CFTC", "BACKFILL"))

    result = calculate(_snapshot(rows), policy, FUTURE_ASOF_NS)

    assert result.is_preliminary is False
    assert result.selected_vintages[0].source == "BACKFILL"
    assert result.net_mm == Decimal("70")
    assert "PRELIMINARY_ONLY" not in result.reason_codes


def test_nested_mapping_inputs_and_reconstructed_objects_are_deeply_frozen():
    constituents = ["c1"]
    codes = [["c1", "001"]]
    weights = [["Energy", Decimal("1")]]
    mapping = COTMarketMapV1(
        market_id="CL", version="frozen-map", constituent_ids=constituents,
        effective_from=date(2020, 1, 1), constituent_codes=codes,
        driver_weights=weights,
    )
    rows = [_row(report_date=date(2026, 9, 1))]
    snapshot = COTSnapshotV1(market_map=mapping, vintages=rows)
    result = calculate(snapshot, _policy(), FUTURE_ASOF_NS)
    constituents.append("changed")
    codes[0][1] = "999"
    weights[0][0] = "Rates"
    rows.clear()

    assert mapping.constituent_ids == ("c1",)
    assert mapping.constituent_codes == (("c1", "001"),)
    assert mapping.driver_weights == (("Energy", Decimal("1")),)
    assert snapshot.vintages[0].report_date == date(2026, 9, 1)
    assert result.driver_weights == (("Energy", Decimal("1")),)
    replacement = replace(mapping)
    assert replacement.constituent_ids == ("c1",)
    assert replacement.driver_weights == (("Energy", Decimal("1")),)
    with pytest.raises(TypeError):
        copy.copy(mapping)
    with pytest.raises(TypeError):
        copy.deepcopy(mapping)
    with pytest.raises(TypeError):
        pickle.dumps(mapping)


def test_duplicate_cftc_code_mapping_is_rejected_as_ambiguous():
    mapping = COTMarketMapV1(
        market_id="CL", version="ambiguous-map", constituent_ids=("c1", "c2"),
        effective_from=date(2020, 1, 1),
        constituent_codes=(("c1", "001"), ("c2", "001")),
    )
    rows = (
        _row(report_date=date(2026, 9, 1), constituent="c1"),
        _row(report_date=date(2026, 9, 1), constituent="c2"),
    )

    with pytest.raises(COTValidationError) as exc:
        calculate(COTSnapshotV1(mapping, rows), _policy(), FUTURE_ASOF_NS)

    assert exc.value.reason_code == "MAPPING_AMBIGUOUS"


def test_35_digit_input_and_inexact_sum_of_two_34_digit_longs_are_rejected():
    report_day = date(2026, 9, 1)
    with pytest.raises(COTValidationError) as input_error:
        _row(report_date=report_day, long="1." + "2" * 34)
    assert input_error.value.reason_code == "PRECISION_EXCEEDED"

    constituents = ("c1", "c2")
    rows = tuple(
        _row(report_date=report_day, constituent=constituent,
             long="9" * 34, short="0", oi="1")
        for constituent in constituents
    )
    with pytest.raises(COTValidationError) as arithmetic_error:
        calculate(_snapshot(rows, constituents=constituents), _policy(), FUTURE_ASOF_NS)
    assert arithmetic_error.value.reason_code == "PRECISION_EXCEEDED"


def test_two_constituent_34_digit_long_short_cancellation_is_exact_zero():
    report_day = date(2026, 9, 1)
    huge_position = "9" * 34
    constituents = ("c1", "c2")
    rows = tuple(
        _row(
            report_date=report_day, constituent=constituent,
            long=huge_position, short=huge_position, oi="100",
        )
        for constituent in constituents
    )

    result = calculate(
        _snapshot(rows, constituents=constituents), _policy(), FUTURE_ASOF_NS,
    )

    assert result.status == "DEGRADED"
    assert result.net_mm == Decimal("0")
    assert result.net_mm_pct_oi == Decimal("0")
    assert result.sample_count == 1
    assert "INSUFFICIENT_HISTORY" in result.reason_codes


def test_policy_bounds_apply_at_construction_and_replace_time():
    valid = _policy()
    invalid_constructors = (
        lambda: COTPolicyV1(min_lookback_samples=103),
        lambda: COTPolicyV1(min_lookback_samples=104, weight_tolerance=Decimal("0.0101")),
        lambda: COTPolicyV1(min_lookback_samples=104, source_priority=()),
    )
    invalid_replacements = (
        lambda: replace(valid, min_lookback_samples=103),
        lambda: replace(valid, weight_tolerance=Decimal("0.0101")),
        lambda: replace(valid, source_priority=()),
    )
    for construct in (*invalid_constructors, *invalid_replacements):
        with pytest.raises(COTValidationError) as exc:
            construct()
        assert exc.value.reason_code == "POLICY_OUT_OF_BOUNDS"


def test_boolean_is_rejected_in_vintage_policy_snapshot_result_integer_fields():
    row = _row(report_date=date(2026, 9, 1))
    snapshot = _snapshot((row,))
    policy = _policy()
    result = calculate(snapshot, policy, FUTURE_ASOF_NS)
    invalid_constructors = (
        lambda: _row(report_date=date(2026, 9, 1), revision=True),
        lambda: replace(row, published_ns=True),
        lambda: replace(policy, min_lookback_samples=True),
        lambda: replace(result, sample_count=True),
        lambda: calculate(snapshot, policy, True),
    )
    for construct in invalid_constructors:
        with pytest.raises(COTValidationError):
            construct()


def test_vintage_code_must_match_the_effective_market_map():
    mapping = COTMarketMapV1(
        market_id="CL", version="bound-map", constituent_ids=("c1",),
        effective_from=date(2020, 1, 1), constituent_codes=(("c1", "001"),),
    )
    mismatched = _row(
        report_date=date(2026, 9, 1), constituent="c1", market_code="999",
    )

    with pytest.raises(COTValidationError) as exc:
        calculate(COTSnapshotV1(mapping, (mismatched,)), _policy(), FUTURE_ASOF_NS)

    assert exc.value.reason_code == "MAPPING_AMBIGUOUS"


def test_pre_effective_old_market_code_truncates_lookback_without_mapping_ambiguity():
    old_day = date(2024, 1, 2)
    current_day = date(2024, 1, 9)
    old_row = _row(
        report_date=old_day, long="115", short="70", market_code="OLD-CFTC-CL",
    )
    current_row = _row(
        report_date=current_day, long="130", short="70", market_code="CFTC-CL",
    )
    mapping = COTMarketMapV1(
        market_id="CL", version="current-code-v2", constituent_ids=("c1",),
        effective_from=current_day, constituent_codes=(("c1", "CFTC-CL"),),
    )
    result = calculate(
        COTSnapshotV1(mapping, (old_row, current_row)), _policy(), FUTURE_ASOF_NS,
    )
    assert result.net_mm == Decimal("60")
    assert "LOOKBACK_TRUNCATED_BY_MAPPING" in result.reason_codes
    assert "MAPPING_AMBIGUOUS" not in result.reason_codes
    assert result.min_lookback_samples == 104


def test_cot_result_state_and_tags_are_closed_and_consistent_on_replace():
    row = _row(report_date=date(2026, 9, 1))
    result = calculate(_snapshot((row,)), _policy(), FUTURE_ASOF_NS)
    assert result.status == "DEGRADED"
    with pytest.raises(COTValidationError):
        replace(result, status="OK", reason_codes=())
    for changes in ({"status": "TRADE_SAFE"}, {"contrarian_tag": "BUY_NOW"},
                    {"confirmation_bias": "BUY_NOW"}):
        with pytest.raises(COTValidationError):
            replace(result, **changes)

    start = date(2024, 1, 2)
    complete_rows = tuple(
        _row(report_date=start + timedelta(days=7 * index), long="101", short="100")
        for index in range(104)
    )
    valid = calculate(_snapshot(complete_rows), _policy(), FUTURE_ASOF_NS)
    assert valid.status == "OK"
    public_state = {field.name: getattr(valid, field.name) for field in fields(valid)}
    with pytest.raises(COTValidationError) as construct_error:
        COTResultV1(**public_state)
    assert construct_error.value.reason_code == "RESULT_NOT_ISSUED"
    for reconstruct in (lambda: replace(valid),
                       lambda: replace(valid, driver_weights=(("Energy", Decimal("1")),))):
        with pytest.raises(COTValidationError) as replace_error:
            reconstruct()
        assert replace_error.value.reason_code == "RESULT_NOT_ISSUED"
    with pytest.raises(COTValidationError) as token_error:
        replace(valid, driver_weights=(), _issue_token=None)
    assert token_error.value.reason_code == "RESULT_NOT_ISSUED"
    with pytest.raises(TypeError):
        replace(valid, driver_weights=(), _seal=valid.percentile)
