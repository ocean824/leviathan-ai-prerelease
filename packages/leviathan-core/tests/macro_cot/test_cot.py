"""COT kernel regressions for vintage, exact rank, policy and immutability gates."""

import copy
import pickle
from dataclasses import replace
from datetime import date, timedelta
from decimal import Decimal, localcontext

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

_EPOCH = date(1970, 1, 1)
_DAY_NS = 86_400_000_000_000


def _ns(day: date) -> int:
    return (day - _EPOCH).days * _DAY_NS


def _row(
    report_date: date,
    *,
    ident: str = "CL",
    code: str = "CFTC-CL",
    long: str = "20",
    short: str = "0",
    oi: str = "100",
    source: str = "CFTC",
    revision: int = 0,
    preliminary: bool = False,
    release_ns: int | None = None,
) -> COTReportVintageV1:
    released = release_ns if release_ns is not None else _ns(report_date + timedelta(days=3))
    return COTReportVintageV1(
        cftc_market_code=code,
        constituent_id=ident,
        report_date=report_date,
        report_family="Disaggregated Futures",
        source=source,
        revision=revision,
        is_preliminary=preliminary,
        published_ns=released,
        received_ns=released,
        available_ns=released,
        mm_long=Decimal(long),
        mm_short=Decimal(short),
        open_interest=Decimal(oi),
    )


def _map(
    *,
    ids: tuple[str, ...] = ("CL",),
    codes: tuple[tuple[str, str], ...] = (("CL", "CFTC-CL"),),
    weights: tuple[tuple[str, Decimal], ...] = (),
) -> COTMarketMapV1:
    return COTMarketMapV1(
        "WTI", "map-v1", ids, date(2019, 1, 1),
        constituent_codes=codes, driver_weights=weights,
    )


def _snapshot(*rows: COTReportVintageV1, mapping: COTMarketMapV1 | None = None) -> COTSnapshotV1:
    return COTSnapshotV1(mapping or _map(), rows)


def _policy(**kwargs: object) -> COTPolicyV1:
    return COTPolicyV1(min_lookback_samples=104, **kwargs)  # type: ignore[arg-type]


def test_actual_release_and_report_observation_are_both_visibility_gates() -> None:
    report_date = date(2024, 1, 2)
    report = _row(report_date)
    snapshot = _snapshot(report)
    before = calculate(snapshot, _policy(), _ns(report_date + timedelta(days=2)))
    at_release = calculate(snapshot, _policy(), _ns(report_date + timedelta(days=3)))
    assert before.status == "UNAVAILABLE"
    assert at_release.status == "DEGRADED"
    impossible = _row(report_date, release_ns=_ns(report_date - timedelta(days=1)))
    with pytest.raises(COTValidationError) as error:
        calculate(_snapshot(impossible), _policy(), _ns(report_date))
    assert error.value.reason_code == "RELEASE_BEFORE_REPORT"


def test_finalized_beats_higher_priority_preliminary_across_ranked_sources() -> None:
    report_date = date(2024, 1, 2)
    preliminary = _row(report_date, long="99", preliminary=True)
    final = _row(report_date, long="20", source="BACKFILL", revision=1)
    policy = _policy(source_priority=("CFTC", "BACKFILL"))
    result = calculate(_snapshot(preliminary, final), policy, _ns(report_date + timedelta(days=4)))
    assert result.net_mm == Decimal(20)
    assert not result.is_preliminary
    assert result.selected_revision_ids == (("CL", 1),)


def test_mapping_binds_code_and_rejects_ambiguous_identity() -> None:
    report_date = date(2024, 1, 2)
    with pytest.raises(COTValidationError) as error:
        calculate(
            _snapshot(_row(report_date, code="WRONG")),
            _policy(), _ns(report_date + timedelta(days=4)),
        )
    assert error.value.reason_code == "MAPPING_AMBIGUOUS"
    ambiguous = _map(ids=("CL", "QM"), codes=(("CL", "001"), ("QM", "001")))
    with pytest.raises(COTValidationError) as error:
        calculate(COTSnapshotV1(ambiguous, ()), _policy(), _ns(report_date))
    assert error.value.reason_code == "MAPPING_AMBIGUOUS"


def test_pre_effective_old_code_does_not_invalidate_current_mapping() -> None:
    old_day = date(2024, 1, 2)
    current_day = old_day + timedelta(weeks=1)
    mapping = COTMarketMapV1(
        "WTI", "map-v2", ("CL",), current_day,
        constituent_codes=(("CL", "CFTC-CL"),),
    )
    result = calculate(
        _snapshot(
            _row(old_day, code="OLD-CFTC-CL"),
            _row(current_day, code="CFTC-CL"),
            mapping=mapping,
        ),
        _policy(),
        _ns(current_day + timedelta(days=4)),
    )
    assert result.report_date == current_day
    assert result.status == "DEGRADED"
    assert result.lookback_samples_used == 1
    assert "LOOKBACK_TRUNCATED_BY_MAPPING" in result.reason_codes


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"source": "UNTRUSTED_SECRET_MARKER"}, "UNRANKED_SOURCE"),
        ({"ident": "UNTRUSTED_SECRET_MARKER"}, "MAPPING_AMBIGUOUS"),
    ],
)
def test_validation_errors_do_not_echo_untrusted_identifiers(
    change: dict[str, str], reason: str
) -> None:
    day = date(2024, 1, 2)
    with pytest.raises(COTValidationError) as error:
        calculate(_snapshot(_row(day, **change)), _policy(), _ns(day + timedelta(days=4)))
    assert error.value.reason_code == reason
    assert "UNTRUSTED_SECRET_MARKER" not in str(error.value)


def test_exact_near_tie_rank_survives_34_digit_output_rounding() -> None:
    start = date(2020, 1, 7)
    prior = [
        _row(start + timedelta(weeks=index), long="0.5" if index < 51 else "1", oi="1")
        for index in range(103)
    ]
    current_day = start + timedelta(weeks=103)
    current = _row(current_day, long="0." + "9" * 34, oi="1")
    result = calculate(_snapshot(*prior, current), _policy(), _ns(current_day + timedelta(days=4)))
    assert result.percentile == Decimal(50)
    assert result.percentile_method == "inclusive_empirical_cdf_upper_ties"
    assert result.contrarian_tag == "none"
    assert not result.low_confidence


def test_wow_outputs_ignore_hostile_ambient_decimal_context() -> None:
    first_day = date(2024, 1, 2)
    second_day = first_day + timedelta(weeks=1)
    rows = (
        _row(first_day, long="1000000.000000000", oi="1000"),
        _row(second_day, long="1000000.123456789", oi="1000"),
    )
    asof = _ns(second_day + timedelta(days=4))
    normal = calculate(_snapshot(*rows), _policy(), asof)
    with localcontext() as hostile:
        hostile.prec = 6
        distorted = calculate(_snapshot(*rows), _policy(), asof)
    assert normal.wow_delta_mm == distorted.wow_delta_mm == Decimal("0.123456789")
    assert normal.wow_delta_pct_oi == distorted.wow_delta_pct_oi


@pytest.mark.parametrize(
    "change",
    [
        {"min_lookback_samples": 1},
        {"low_confidence_min_samples": 1},
        {"weight_tolerance": Decimal("1")},
        {"contrarian_long_max": Decimal("20")},
        {"lookback_reports": 20},
    ],
)
def test_governed_policy_cannot_be_weakened(change: dict[str, object]) -> None:
    with pytest.raises(COTValidationError) as error:
        replace(_policy(), **change)
    assert error.value.reason_code == "POLICY_OUT_OF_BOUNDS"


def test_policy_reconstruction_rejects_empty_source_priority() -> None:
    with pytest.raises(COTValidationError) as error:
        replace(_policy(), source_priority=())
    assert error.value.reason_code == "POLICY_OUT_OF_BOUNDS"


def test_decimal_bounds_and_canonical_evidence() -> None:
    with pytest.raises(COTValidationError) as error:
        _row(date(2024, 1, 2), long="0." + "1" * 35)
    assert error.value.reason_code == "PRECISION_EXCEEDED"
    with pytest.raises(COTValidationError, match="bounds"):
        _row(date(2024, 1, 2), long="1E+39")
    day = date(2024, 1, 2)
    integer = _row(day, long="120")
    decimal = _row(day, long="120.0")
    assert integer == decimal
    assert repr(integer) == repr(decimal)
    assert integer.mm_long == Decimal("1.2E+2")
    asof = _ns(day + timedelta(days=4))
    assert repr(calculate(_snapshot(integer), _policy(), asof)) == repr(
        calculate(_snapshot(decimal), _policy(), asof)
    )


def test_exact_sum_of_two_valid_positions_never_rounds() -> None:
    day = date(2024, 1, 2)
    mapping = _map(ids=("CL", "QM"), codes=(("CL", "CFTC-CL"), ("QM", "CFTC-QM")))
    positions = (
        _row(day, ident="CL", code="CFTC-CL", long="9" * 34, oi="1"),
        _row(day, ident="QM", code="CFTC-QM", long="9" * 34, oi="1"),
    )
    with pytest.raises(COTValidationError) as error:
        calculate(_snapshot(*positions, mapping=mapping), _policy(), _ns(day + timedelta(days=4)))
    assert error.value.reason_code == "PRECISION_EXCEEDED"


def test_exact_constituent_cancellation_materializes_zero_net() -> None:
    day = date(2024, 1, 2)
    mapping = _map(ids=("CL", "QM"), codes=(("CL", "CFTC-CL"), ("QM", "CFTC-QM")))
    positions = (
        _row(day, ident="CL", code="CFTC-CL", long="9" * 34, short="9" * 34),
        _row(day, ident="QM", code="CFTC-QM", long="9" * 34, short="9" * 34),
    )
    result = calculate(
        _snapshot(*positions, mapping=mapping), _policy(), _ns(day + timedelta(days=4))
    )
    assert result.status == "DEGRADED"
    assert result.net_mm == Decimal(0)
    assert result.net_mm_pct_oi == Decimal(0)
    assert "INSUFFICIENT_HISTORY" in result.reason_codes


def test_inexact_wow_position_delta_fails_closed() -> None:
    first = date(2024, 1, 2)
    second = first + timedelta(weeks=1)
    rows = (
        _row(first, long="0", short="9" * 34),
        _row(second, long="9" * 34, short="0"),
    )
    with pytest.raises(COTValidationError) as error:
        calculate(_snapshot(*rows), _policy(), _ns(second + timedelta(days=4)))
    assert error.value.reason_code == "PRECISION_EXCEEDED"


def test_percentile_threshold_uses_exact_rank_ratio() -> None:
    start = date(2020, 1, 7)
    rows = tuple(
        _row(start + timedelta(weeks=index), long="1" if index < 103 else "0", oi="1")
        for index in range(104)
    )
    policy = _policy(contrarian_long_max=Decimal("0.9615384615384615384615384615384615"))
    result = calculate(_snapshot(*rows), policy, _ns(start + timedelta(weeks=103, days=4)))
    assert result.percentile == policy.contrarian_long_max
    assert result.contrarian_tag == "none"


def test_nested_collections_are_detached_and_result_reconstruction_is_sealed() -> None:
    day = date(2024, 1, 2)
    weights = [["Energy", Decimal("1.0")]]
    mapping = COTMarketMapV1(
        "WTI", "map-v1", ["CL"], date(2019, 1, 1),
        constituent_codes=[["CL", "CFTC-CL"]], driver_weights=weights,
    )
    result = calculate(COTSnapshotV1(mapping, [_row(day)]), _policy(), _ns(day + timedelta(days=4)))
    weights[0][0] = "Rates"
    assert mapping.driver_weights == result.driver_weights == (("Energy", Decimal(1)),)
    assert mapping.constituent_ids == ("CL",)
    assert isinstance(result.selected_vintages, tuple)
    with pytest.raises(COTValidationError) as error:
        replace(result, driver_weights=[["Energy", Decimal("1.00")]])
    assert error.value.reason_code == "RESULT_NOT_ISSUED"
    with pytest.raises(COTValidationError):
        replace(result, selected_vintages=[{"mutable": True}])
    with pytest.raises(TypeError):
        copy.copy(result)
    with pytest.raises(TypeError):
        pickle.dumps(result)


def test_public_result_constructor_cannot_issue_status() -> None:
    with pytest.raises(COTValidationError) as error:
        COTResultV1(
            "WTI", "UNAVAILABLE", 0, "map-v1", "backend-prd-v1",
            reason_codes=("NO_PUBLISHED_VINTAGE",),
        )
    assert error.value.reason_code == "RESULT_NOT_ISSUED"


@pytest.mark.parametrize(
    "change",
    [
        {"status": "TRADE_SAFE"},
        {"contrarian_tag": "BUY_NOW"},
        {"confirmation_bias": "BUY_NOW"},
        {"status": "OK", "reason_codes": (), "warnings": (), "low_confidence": False},
        {"reason_codes": ()},
    ],
)
def test_result_reconstruction_rejects_forged_states(change: dict[str, object]) -> None:
    day = date(2024, 1, 2)
    result = calculate(_snapshot(_row(day)), _policy(), _ns(day + timedelta(days=4)))
    assert result.status == "DEGRADED"
    with pytest.raises(COTValidationError) as error:
        replace(result, **change)
    assert error.value.reason_code == "INVALID_RESULT_STATE"


def test_partial_mapping_and_missing_weeks_are_explicit() -> None:
    first_day = date(2024, 1, 2)
    current_day = first_day + timedelta(weeks=3)
    result = calculate(
        _snapshot(_row(first_day, long="20"), _row(current_day, long="40")),
        _policy(), _ns(current_day + timedelta(days=4)),
    )
    assert result.gap
    assert result.wow_delta_mm == Decimal(20)
    assert result.percentile is None
    assert "INSUFFICIENT_HISTORY" in result.reason_codes
    partial_map = _map(ids=("CL", "QM"), codes=(("CL", "CFTC-CL"), ("QM", "CFTC-QM")))
    partial = calculate(
        _snapshot(_row(current_day), mapping=partial_map),
        _policy(), _ns(current_day + timedelta(days=4)),
    )
    assert partial.status == "DEGRADED"
    assert partial.net_mm is None
