"""DP-001 worker tests for point-in-time and arithmetic invariants."""

import copy
import pickle
import random
from dataclasses import replace
from datetime import UTC, date, datetime, timedelta, timezone
from decimal import Decimal, localcontext

import pytest

from leviathan_core.dark_pool import (
    AggregateContextV1,
    BaselineSampleV1,
    DarkLensError,
    DarkLensPolicyV1,
    DarkLensSnapshotV1,
    DarkPrintV1,
    ExchangeSessionV1,
    LitTradeV1,
    VenueRuleV1,
    calculate,
)

_VENUES = (
    VenueRuleV1("TRF", "OFF_EXCHANGE"),
    VenueRuleV1("FINRA-TRF", "OFF_EXCHANGE"),
    VenueRuleV1("ATS", "OFF_EXCHANGE"),
    VenueRuleV1("XNYS", "LIT"),
)


def _snapshot(
    dark_prints: tuple[DarkPrintV1, ...] = (),
    lit_trades: tuple[LitTradeV1, ...] = (),
    calendar: tuple[ExchangeSessionV1, ...] = (),
    baseline_samples: tuple[BaselineSampleV1, ...] = (),
    aggregate_context: tuple[AggregateContextV1, ...] = (),
    mode: str = "OFFLINE",
    revision: int = 0,
) -> DarkLensSnapshotV1:
    return DarkLensSnapshotV1(
        dark_prints,
        lit_trades,
        calendar,
        baseline_samples,
        aggregate_context,
        mode,
        revision,
        _VENUES,
    )


def _ny_offset(day: date) -> timezone:
    march_first = date(day.year, 3, 1)
    november_first = date(day.year, 11, 1)
    second_march_sunday = 1 + (6 - march_first.weekday()) % 7 + 7
    first_november_sunday = 1 + (6 - november_first.weekday()) % 7
    in_dst = (
        date(day.year, 3, second_march_sunday) <= day < date(day.year, 11, first_november_sunday)
    )
    return timezone(timedelta(hours=-4 if in_dst else -5))


def _ns(day: date, hour: int, minute: int) -> int:
    local = datetime(day.year, day.month, day.day, hour, minute, tzinfo=_ny_offset(day))
    return int(local.timestamp()) * 10**9


def _session(day: date, close_hour: int = 16) -> ExchangeSessionV1:
    return ExchangeSessionV1(
        day,
        _ns(day, 9, 30),
        _ns(day, close_hour, 0),
        "America/New_York",
        "nyse-v1",
        utc_offset_minutes=int(_ny_offset(day).utcoffset(None).total_seconds() // 60),
    )


def _policy(day: date, **changes: object) -> DarkLensPolicyV1:
    policy = DarkLensPolicyV1(
        instrument_id="UUID-1",
        window_start_ns=_ns(day, 9, 30),
        window_end_ns=_ns(day, 9, 35),
        calendar_version="nyse-v1",
        min_notional=Decimal("0"),
        min_lit_volume=Decimal("1"),
    )
    return replace(policy, **changes)


def _dark(day: date, native_id: str = "dark-1", **changes: object) -> DarkPrintV1:
    event = DarkPrintV1(
        instrument_id="UUID-1",
        source_id="fixture",
        dataset_id="print-v1",
        venue="TRF",
        native_id=native_id,
        event_ns=_ns(day, 9, 31),
        published_ns=_ns(day, 9, 32),
        available_ns=_ns(day, 9, 32),
        exchange_tz="America/New_York",
        calendar_version="nyse-v1",
        price=Decimal("101"),
        size=Decimal("100"),
        side="U",
        reference_mid=Decimal("100"),
    )
    return replace(event, **changes)


def _lit(day: date, native_id: str = "lit-1", **changes: object) -> LitTradeV1:
    event = LitTradeV1(
        instrument_id="UUID-1",
        source_id="fixture",
        dataset_id="lit-v1",
        venue="XNYS",
        native_id=native_id,
        event_ns=_ns(day, 9, 31),
        published_ns=_ns(day, 9, 32),
        available_ns=_ns(day, 9, 32),
        exchange_tz="America/New_York",
        calendar_version="nyse-v1",
        price=Decimal("100"),
        size=Decimal("100"),
    )
    return replace(event, **changes)


def test_publication_asof_and_lit_only_vwap() -> None:
    day = date(2026, 9, 29)
    dark = _dark(day)
    lit = _lit(day)
    trf = _lit(day, "off-exchange", price=Decimal("1"), is_off_exchange=True)
    trf_venue = _lit(day, "trf-venue", venue="FINRA-TRF", price=Decimal("2"))
    snapshot = _snapshot((dark,), (lit, trf, trf_venue), (_session(day),))
    before = calculate(snapshot, _policy(day), _ns(day, 9, 31))
    after = calculate(snapshot, _policy(day), _ns(day, 9, 33))
    assert before.total_dp_trades == 0
    assert before.lit_vwap is None
    assert after.dp_vwap == Decimal("101")
    assert after.lit_vwap == Decimal("100")
    assert after.divergence == Decimal("0.01")
    assert after.ranked_prints[0].side == "B"
    assert after.ranked_prints[0].side_inferred
    assert after.observed_lag_ns == 60_000_000_000
    assert after.digest == calculate(snapshot, _policy(day), _ns(day, 9, 33)).digest
    assert "not live" in after.delay_label


def test_delayed_finra_aggregate_is_context_only() -> None:
    day = date(2026, 9, 29)
    aggregate = AggregateContextV1(
        instrument_id="UUID-1",
        source_id="FINRA",
        dataset_id="OTC-weekly",
        venue="ATS",
        native_id="week-39",
        event_ns=_ns(day, 9, 31),
        published_ns=_ns(day, 9, 32),
        available_ns=_ns(day, 9, 33),
        exchange_tz="America/New_York",
        calendar_version="nyse-v1",
        release_vintage="2026-W39",
    )
    result = calculate(
        _snapshot(calendar=(_session(day),), aggregate_context=(aggregate,)),
        _policy(day),
        _ns(day, 9, 34),
    )
    assert result.source_state == "AGGREGATE_ONLY"
    assert result.ranked_prints == ()
    assert result.dp_vwap is None
    assert "2026-W39" in result.delay_label
    with pytest.raises(DarkLensError, match="AGGREGATE_ONLY"):
        _dark(day, source_state="AGGREGATE_ONLY")


def test_min_notional_counts_low_and_zero_mid_side() -> None:
    day = date(2026, 9, 29)
    small = _dark(day, "small", size=Decimal("1"), reference_mid=Decimal("0"))
    large = _dark(day, "large", size=Decimal("100"), side="S")
    result = calculate(
        _snapshot((small, large), (_lit(day),), (_session(day),)),
        _policy(day, min_notional=Decimal("1000"), counts_low=True),
        _ns(day, 9, 34),
    )
    assert result.total_dp_trades == 2
    assert result.counts_low == 1
    assert result.total_notional == Decimal("10201")
    assert result.total_notional_ranked == Decimal("10100")
    assert result.vwap_basis == "ALL_ELIGIBLE_PRINTS"
    assert result.min_notional == Decimal("1000")
    assert len(result.ranked_prints) == 1
    assert result.ranked_prints[0].side == "S"
    assert result.session_metrics[0].unknown_notional == Decimal("101")
    with pytest.raises(DarkLensError, match="INVALID_VENUE_FILTER"):
        _policy(day, venue_filter="include_trf")


def test_correction_revises_only_later_asof_and_offline_recomputes() -> None:
    day = date(2026, 9, 29)
    original = _dark(day)
    correction = replace(
        original,
        price=Decimal("102"),
        correction_id="1",
        supersedes_id="0",
        published_ns=_ns(day, 9, 33),
        available_ns=_ns(day, 9, 33),
    )
    snapshot = _snapshot((correction, original), (_lit(day),), (_session(day),))
    prior = calculate(snapshot, _policy(day), _ns(day, 9, 32))
    later = calculate(snapshot, _policy(day), _ns(day, 9, 34))
    assert prior.dp_vwap == Decimal("101")
    assert later.dp_vwap == Decimal("102")
    assert later.revision == prior.revision + 1
    assert (
        later.digest
        == calculate(
            replace(snapshot, dark_prints=(original, correction)), _policy(day), _ns(day, 9, 34)
        ).digest
    )
    late = replace(correction, available_ns=_ns(day, 9, 40), published_ns=_ns(day, 9, 40))
    online = calculate(
        replace(snapshot, dark_prints=(original, late), mode="ONLINE"),
        _policy(day),
        _ns(day, 9, 41),
    )
    offline = calculate(
        replace(snapshot, dark_prints=(original, late), mode="OFFLINE"),
        _policy(day),
        _ns(day, 9, 41),
    )
    assert online.dp_vwap == Decimal("101")
    assert online.recompute_pending
    assert offline.dp_vwap == Decimal("102")


def test_overflow_fails_closed_and_conflict_rejected() -> None:
    day = date(2026, 9, 29)
    huge = _dark(day, size=Decimal("1000000000000"))
    result = calculate(
        _snapshot((huge,), (_lit(day),), (_session(day),)),
        _policy(day),
        _ns(day, 9, 34),
    )
    assert not result.valid
    assert result.flags == ("OVERFLOW",)
    assert result.ranked_prints == ()
    assert result.total_notional is None
    with pytest.raises(DarkLensError, match="CONFLICTING_DUPLICATE"):
        calculate(
            _snapshot(
                (_dark(day), _dark(day, price=Decimal("102"))), (_lit(day),), (_session(day),)
            ),
            _policy(day),
            _ns(day, 9, 34),
        )


def test_dst_calendar_and_prior_trading_day_baseline() -> None:
    day = date(2026, 11, 3)
    previous = [day - timedelta(days=index) for index in range(1, 20)]
    previous = [candidate for candidate in previous if candidate.weekday() < 5][:10]
    calendar = (*(_session(candidate) for candidate in previous), _session(day))
    baseline = tuple(
        BaselineSampleV1(
            candidate,
            _ns(candidate, 9, 30),
            Decimal(index) / Decimal("1000"),
            _ns(candidate, 16, 0),
            _ns(candidate, 16, 0),
            "baseline-fixture",
            instrument_id="UUID-1",
            window_end_ns=_ns(candidate, 9, 35),
        )
        for index, candidate in enumerate(previous)
    )
    result = calculate(
        _snapshot((_dark(day),), (_lit(day),), calendar, baseline),
        _policy(day),
        _ns(day, 9, 34),
    )
    assert result.divergence_z is not None
    assert result.session_metrics[0].start_ns == _ns(day, 9, 30)
    assert datetime.fromtimestamp(result.session_metrics[0].start_ns / 10**9, UTC).hour == 14
    assert "baseline-fixture" in result.source_ids


def test_missing_calendar_offset_fails_closed() -> None:
    day = date(2026, 9, 29)
    with pytest.raises(DarkLensError) as error:
        calculate(
            _snapshot(calendar=(replace(_session(day), utc_offset_minutes=None),)),
            _policy(day),
            _ns(day, 9, 34),
        )
    assert error.value.code == "CALENDAR_OFFSET_UNKNOWN"


def test_early_close_and_split_fx_adjustments() -> None:
    day = date(2026, 11, 27)
    window_start = _ns(day, 12, 30)
    window_end = _ns(day, 12, 35)
    dark = _dark(
        day,
        event_ns=_ns(day, 12, 31),
        published_ns=_ns(day, 12, 32),
        available_ns=_ns(day, 12, 32),
        price=Decimal("50"),
        size=Decimal("100"),
        fx_rate=Decimal("1.2"),
        fx_version="USD-v2",
        split_factor=Decimal("2"),
        split_version="split-v3",
    )
    lit = _lit(
        day,
        event_ns=_ns(day, 12, 31),
        published_ns=_ns(day, 12, 32),
        available_ns=_ns(day, 12, 32),
        price=Decimal("25"),
        size=Decimal("100"),
        fx_rate=Decimal("1.2"),
    )
    result = calculate(
        _snapshot((dark,), (lit,), (_session(day, close_hour=13),)),
        _policy(day, window_start_ns=window_start, window_end_ns=window_end),
        _ns(day, 12, 34),
    )
    assert result.dp_vwap == Decimal("30")
    assert result.lit_vwap == Decimal("30")
    assert result.total_notional == Decimal("6000")
    assert result.session_metrics[-1].start_ns == _ns(day, 12, 0)
    assert any("split-v3" in version for version in result.adjustment_versions)


def test_quantile_ties_are_stably_binned_and_licensed_state_needs_evidence() -> None:
    day = date(2026, 9, 29)
    prints = tuple(_dark(day, f"d-{index}") for index in range(10))
    result = calculate(
        _snapshot(prints, (_lit(day),), (_session(day),)),
        _policy(day, bucket_scheme="quantile", quantile_count=5),
        _ns(day, 9, 34),
    )
    assert sorted(row.count for row in result.bucket_counts) == [2, 2, 2, 2, 2]
    assert {row.bucket for row in result.bucket_counts} == {"q1", "q2", "q3", "q4", "q5"}
    with pytest.raises(DarkLensError) as error:
        _dark(day, source_state="LICENSED_PRINT")
    assert error.value.code == "INVALID_ENTITLEMENT"


def test_baseline_scope_and_release_are_checked_even_without_lit_data() -> None:
    day = date(2026, 9, 29)
    prior = day - timedelta(days=1)
    sample = BaselineSampleV1(
        prior,
        _ns(prior, 9, 30),
        Decimal("0.01"),
        _ns(prior, 9, 36),
        _ns(prior, 9, 36),
        "prior-baseline",
        instrument_id="OTHER",
        window_end_ns=_ns(prior, 9, 35),
    )
    with pytest.raises(DarkLensError, match="SCOPE_MISMATCH"):
        calculate(
            _snapshot(calendar=(_session(prior), _session(day)), baseline_samples=(sample,)),
            _policy(day),
            _ns(day, 9, 34),
        )
    with pytest.raises(DarkLensError, match="INVALID_BASELINE"):
        replace(sample, instrument_id="UUID-1", available_ns=_ns(prior, 9, 34))


def test_registry_correction_and_aggregate_context_fail_closed() -> None:
    day = date(2026, 9, 29)
    policy = _policy(day)
    session = (_session(day),)
    with pytest.raises(DarkLensError, match="UNKNOWN_VENUE"):
        calculate(
            _snapshot(lit_trades=(_lit(day, venue="XTRF"),), calendar=session),
            policy,
            _ns(day, 9, 34),
        )
    orphan = _dark(
        day,
        correction_id="42",
        published_ns=_ns(day, 9, 33),
        available_ns=_ns(day, 9, 33),
        price=Decimal("102"),
    )
    with pytest.raises(DarkLensError, match="ORPHAN_CORRECTION"):
        calculate(
            _snapshot(dark_prints=(_dark(day), orphan), calendar=session),
            policy,
            _ns(day, 9, 34),
        )
    context = AggregateContextV1(
        instrument_id="UUID-1",
        source_id="FINRA",
        dataset_id="weekly",
        venue="ATS",
        native_id="W39",
        event_ns=_ns(day, 9, 39),
        published_ns=_ns(day, 9, 32),
        available_ns=_ns(day, 9, 32),
        exchange_tz="America/New_York",
        calendar_version="nyse-v1",
        release_vintage="2026-W39",
    )
    with pytest.raises(DarkLensError, match="FUTURE_EVENT"):
        calculate(
            _snapshot(calendar=session, aggregate_context=(context,)),
            policy,
            _ns(day, 9, 34),
        )
    with pytest.raises(DarkLensError, match="INVALID_CALENDAR"):
        calculate(
            _snapshot(
                calendar=session,
                aggregate_context=(
                    replace(context, event_ns=_ns(day, 9, 31), calendar_version="other"),
                ),
            ),
            policy,
            _ns(day, 9, 34),
        )


def test_decimal_canonical_bounds_exact_product_and_owned_context() -> None:
    day = date(2026, 9, 29)
    snapshot = _snapshot((_dark(day),), (_lit(day),), (_session(day),))
    first = calculate(snapshot, _policy(day, fixed_thresholds=(Decimal("1000"),)), _ns(day, 9, 34))
    second = calculate(
        snapshot, _policy(day, fixed_thresholds=(Decimal("1000.0"),)), _ns(day, 9, 34)
    )
    assert first.digest == second.digest
    assert first.ranked_prints[0].bucket == second.ranked_prints[0].bucket
    with pytest.raises(DarkLensError, match="DECIMAL_OUT_OF_BOUNDS"):
        _dark(day, price=Decimal("1E+999999"))
    product_over_cap = calculate(
        _snapshot(
            (_dark(day, price=Decimal("1234567890123456789012345678901234"), size=Decimal(9)),),
            calendar=(_session(day),),
        ),
        _policy(day),
        _ns(day, 9, 34),
    )
    assert product_over_cap.flags == ("OVERFLOW",)
    assert product_over_cap.total_notional is None
    overflow = calculate(
        _snapshot(
            (_dark(day, price=Decimal("1E+38"), size=Decimal("100")),), calendar=(_session(day),)
        ),
        _policy(day),
        _ns(day, 9, 34),
    )
    assert overflow.flags == ("OVERFLOW",)
    assert overflow.total_notional is None and overflow.ranked_prints == ()
    with localcontext() as ambient:
        ambient.prec = 2
        ambient.Emax = 1
        assert (
            calculate(
                snapshot, _policy(day, fixed_thresholds=(Decimal("1000"),)), _ns(day, 9, 34)
            ).digest
            == first.digest
        )


def test_freeze_reconstruction_ascii_and_boolean_granularity() -> None:
    day = date(2026, 9, 29)
    event = _dark(day)
    snapshot = _snapshot((event,), (_lit(day),), (_session(day),))
    result = calculate(snapshot, _policy(day), _ns(day, 9, 34))
    for value in (event, snapshot, result):
        for operation in (copy.copy, copy.deepcopy, pickle.dumps):
            with pytest.raises(DarkLensError, match="IMMUTABLE_COPY"):
                operation(value)
    with pytest.raises(DarkLensError, match="INVALID_COLLECTION"):
        replace(event, condition_codes=(["A"],))
    mutable_rows: list[object] = []
    reconstructed = replace(snapshot, dark_prints=mutable_rows)
    mutable_rows.append("invalid")
    assert reconstructed.dark_prints == ()
    with pytest.raises(DarkLensError, match="UNISSUED_RESULT"):
        replace(result, total_notional=Decimal("999"))
    with pytest.raises(TypeError):
        replace(result, _seal="forged")
    with pytest.raises(DarkLensError, match="UNISSUED_RESULT"):
        replace(result, _issuer=result._seal)
    with pytest.raises(DarkLensError, match="INVALID_FLAG"):
        replace(event, is_odd_lot="false")
    with pytest.raises(DarkLensError, match="INVALID_TIME"):
        replace(event, available_ns=True)
    with pytest.raises(DarkLensError, match="INVALID_SESSION"):
        _policy(day, lunch_start="\u0661\u0661:\u0663\u0660")
    with pytest.raises(DarkLensError, match="INVALID_CALENDAR"):
        replace(_session(day), local_open_time="\u0669:\u0663\u0660")


def test_invisible_baseline_and_late_orphan_do_not_bypass_point_in_time() -> None:
    day = date(2026, 9, 29)
    prior = day - timedelta(days=1)
    policy = _policy(day)
    base = _snapshot((_dark(day),), (_lit(day),), (_session(day), _session(prior)))
    asof = _ns(day, 9, 34)
    earlier = calculate(base, policy, asof)
    future = BaselineSampleV1(
        prior,
        _ns(prior, 9, 30),
        Decimal("0.01"),
        _ns(day, 9, 36),
        _ns(day, 9, 36),
        "future-other",
        instrument_id="OTHER",
        window_end_ns=_ns(prior, 9, 35),
    )
    assert calculate(replace(base, baseline_samples=(future,)), policy, asof) == earlier
    orphan = _dark(
        day,
        correction_id="42",
        supersedes_id=None,
        published_ns=_ns(day, 9, 40),
        available_ns=_ns(day, 9, 40),
    )
    with pytest.raises(DarkLensError, match="ORPHAN_CORRECTION"):
        calculate(
            replace(base, dark_prints=(_dark(day), orphan), mode="ONLINE"), policy, _ns(day, 9, 41)
        )


def test_exact_adjustment_cancels_large_intermediate_and_trailing_zeros() -> None:
    day = date(2026, 9, 29)
    event = _dark(
        day,
        price=Decimal("1E+20"),
        size=Decimal("1E+20"),
        fx_rate=Decimal("1E-30"),
    )
    result = calculate(
        _snapshot((event,), (_lit(day),), (_session(day),)),
        _policy(day),
        _ns(day, 9, 34),
    )
    assert result.total_notional == Decimal("1E+10")
    assert result.dp_vwap == Decimal("1E-10")
    canonical = replace(event, price=Decimal("1." + "0" * 50))
    assert canonical.price == Decimal(1)


def test_exact_pressure_comparison_and_exact_cap_before_materialization() -> None:
    day = date(2026, 9, 29)
    near_cap = Decimal("5000000000000.000000000000000000001")
    first = _dark(day, "first", price=near_cap, size=Decimal(1), side="B")
    result = calculate(
        _snapshot((first,), (_lit(day),), (_session(day),)),
        _policy(day),
        _ns(day, 9, 34),
    )
    assert result.valid
    assert result.total_notional == near_cap
    assert result.session_metrics[0].cluster_label == "High Buy Pressure"
    second = _dark(day, "second", price=near_cap, size=Decimal(1), side="B")
    exceeded = calculate(
        _snapshot((first, second), (_lit(day),), (_session(day),)),
        _policy(day, pressure_threshold_bp=Decimal(0)),
        _ns(day, 9, 34),
    )
    assert exceeded.flags == ("OVERFLOW",)
    assert exceeded.total_notional is None and exceeded.ranked_prints == ()


def test_tiny_nonzero_variance_yields_finite_final_z() -> None:
    day = date(2026, 9, 29)
    previous = [day - timedelta(days=index) for index in range(1, 20)]
    previous = [candidate for candidate in previous if candidate.weekday() < 5][:10]
    samples = tuple(
        BaselineSampleV1(
            prior,
            _ns(prior, 9, 30),
            Decimal(0) if index % 2 == 0 else Decimal("1E-38"),
            _ns(prior, 16, 0),
            _ns(prior, 16, 0),
            f"baseline-{index}",
            instrument_id="UUID-1",
            window_end_ns=_ns(prior, 9, 35),
        )
        for index, prior in enumerate(previous)
    )
    result = calculate(
        _snapshot(
            (_dark(day),),
            (_lit(day),),
            (*(_session(prior) for prior in previous), _session(day)),
            samples,
        ),
        _policy(day),
        _ns(day, 9, 34),
    )
    assert result.divergence_z == Decimal("2E36")
    assert result.z_reason is None


def test_seeded_numeric_inputs_never_leak_decimal_exceptions() -> None:
    day = date(2026, 9, 29)
    generator = random.Random(20261005)
    for index in range(120):
        price = Decimal(f"{generator.randint(1, 9999)}E{generator.randint(-40, 40)}")
        size = Decimal(f"{generator.randint(1, 9999)}E{generator.randint(-40, 40)}")
        fx_rate = Decimal(f"{generator.randint(1, 9999)}E{generator.randint(-40, 40)}")
        try:
            dark = _dark(day, f"random-{index}", price=price, size=size, fx_rate=fx_rate)
            calculate(
                _snapshot((dark,), (_lit(day),), (_session(day),)),
                _policy(day),
                _ns(day, 9, 34),
            )
        except DarkLensError:
            pass
