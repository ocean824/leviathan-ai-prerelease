from __future__ import annotations

import copy
import json
import pickle
import random
from dataclasses import fields, is_dataclass, replace
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal, DecimalException, localcontext
from pathlib import Path

import pytest

from leviathan_core.dark_pool import (
    AggregateContextV1,
    BaselineSampleV1,
    DarkLensError,
    DarkLensPolicyV1,
    DarkLensResultV1,
    DarkLensSnapshotV1,
    DarkPrintV1,
    ExchangeSessionV1,
    LitTradeV1,
    VenueRuleV1,
    calculate,
)

FIXTURES = Path(__file__).parent / "fixtures" / "kernel"
TZ = "UTC"


def _dark(native_id: str, *, event=120, published=121, available=122,
          price="10.25", size="10", side="B", source_state="SYNTHETIC",
          entitlement="SYNTHETIC", mid=None, odd=False, correction="0", fx="1",
          supersedes=None, venue="TRF-X"):
    return DarkPrintV1(
        "SYNTH-X", "fixture", "dataset-v1", venue, native_id,
        event, published, available, TZ, "test-calendar-v1", Decimal(price), Decimal(size),
        fx_rate=Decimal(fx),
        condition_codes=(), is_odd_lot=odd, entitlement_status=entitlement,
        source_state=source_state, side=side,
        reference_mid=Decimal(mid) if mid is not None else None, correction_id=correction,
        supersedes_id=supersedes,
    )


def _lit(native_id: str, *, event=110, published=111, available=112,
         price="10", size="10", off=False, venue="XNYS"):
    return LitTradeV1(
        "SYNTH-X", "lit-fixture", "lit-v1", venue, native_id,
        event, published, available, TZ, "test-calendar-v1", Decimal(price), Decimal(size),
        is_off_exchange=off,
    )


def _policy(**kwargs):
    start = kwargs.pop("window_start_ns", 100)
    end = kwargs.pop("window_end_ns", 300)
    return DarkLensPolicyV1(
        "SYNTH-X", start, end, "test-calendar-v1", min_notional=Decimal("100"),
        min_lit_volume=Decimal("10"), **kwargs,
    )

def _snapshot(dark=(), lit=(), contexts=(), calendar=None, baseline_samples=()):
    if calendar is None:
        calendar = (
            ExchangeSessionV1(
                date(1970, 1, 1), 0, 1000, TZ, "test-calendar-v1", "00:00", 0,
            ),
        )
    return DarkLensSnapshotV1(
        dark_prints=tuple(dark), lit_trades=tuple(lit), baseline_samples=tuple(baseline_samples),
        aggregate_context=tuple(contexts),
        calendar=tuple(calendar), venue_registry=tuple(
            VenueRuleV1(venue, "OFF_EXCHANGE" if venue in {"TRF-X", "ATS"}
                        else "LIT")
            for venue in sorted({row.venue for row in (*dark, *lit, *contexts)})
        ),
    )


def test_future_publication_and_availability_are_excluded_and_trf_never_enters_lit_vwap():
    fixture = json.loads((FIXTURES / "point_in_time_lit_only.json").read_text(encoding="utf-8-sig"))
    dark = _dark("dp-1", event=120, published=121, available=122)
    future = _dark("dp-future", event=250, published=301, available=301, price="999", size="999")
    result = calculate(
        _snapshot(
            (dark, future),
            (_lit("lit-1"), _lit("trf-lit", price="100", size="100", off=True)),
        ),
        _policy(), fixture["asof_ns"],
    )
    assert result.asof_ns == fixture["asof_ns"]
    assert result.source_state == "SYNTHETIC"
    assert result.total_dp_trades == 1
    assert result.counts_low is None
    assert result.lit_vwap == Decimal("10")
    assert result.dp_vwap == Decimal("10.25")
    assert result.divergence == Decimal("0.025")
    assert all(row.event_ns != 250 for row in result.ranked_prints)


def test_delayed_aggregate_context_keeps_aggregate_only_label_and_never_ranks_as_print():
    context = AggregateContextV1(
        "SYNTH-X", "finra", "delayed-v1", "ATS", "agg-1", 120, 130, 140,
        TZ, "test-calendar-v1", "weekly-release-1",
    )
    result = calculate(_snapshot((), (), (context,)), _policy(), 200)
    assert result.aggregate_context_ids
    assert result.source_state == "AGGREGATE_ONLY"
    assert result.ranked_prints == ()
    with pytest.raises(DarkLensError) as exc:
        _dark("fake-print", source_state="AGGREGATE_ONLY")
    assert exc.value.code == "AGGREGATE_ONLY"


def test_low_notional_and_side_unknown_are_not_promoted_into_rank_or_pressure():
    included = _dark("above", price="20", size="10", side="U")
    excluded = _dark("below", price="2", size="10", side="U")
    result = calculate(_snapshot((included, excluded)), _policy(counts_low=True), 200)
    assert result.total_dp_trades == 2
    assert result.total_notional == Decimal("220")
    assert result.total_notional_ranked == Decimal("200")
    assert result.vwap_basis == "ALL_ELIGIBLE_PRINTS"
    assert result.dp_vwap == Decimal("11")
    assert result.counts_low == 1
    assert len(result.ranked_prints) == 1
    assert result.ranked_prints[0].event_ns == 120
    assert result.ranked_prints[0].side == "U"
    assert result.ranked_prints[0].side_inferred is False


def test_decimal_overflow_fails_closed_without_saturated_rank_or_total():
    enormous = _dark("huge", price="1E+38", size="1E+2")
    result = calculate(_snapshot((enormous,)), _policy(), 200)
    assert result.valid is False
    assert "OVERFLOW" in result.flags
    assert result.total_notional is None
    assert result.ranked_prints == ()


def test_permutation_does_not_change_semantic_digest_or_rank_order():
    a = _dark("a", price="20", size="10")
    b = _dark("b", price="30", size="10", event=130, published=131, available=132)
    lit = (
        _lit("l1"),
        _lit("l2", event=131, published=132, available=133, price="11"),
    )
    forward = calculate(_snapshot((a, b), lit), _policy(), 200)
    reversed_input = calculate(_snapshot((b, a), tuple(reversed(lit))), _policy(), 200)
    assert forward.digest == reversed_input.digest
    assert forward.ranked_prints == reversed_input.ranked_prints


def test_missing_lit_volume_is_invalid_with_reason_and_future_baseline_cannot_score_z():
    result = calculate(_snapshot((_dark("dp"),), (), calendar=None), _policy(), 200)
    assert result.valid is False
    assert result.lit_vwap is None
    assert result.divergence is None
    assert result.reason_if_invalid
    assert result.divergence_z is None






def test_unknown_reference_mid_stays_unknown_and_valid_mid_is_labeled_inferred():
    unknown = calculate(_snapshot((_dark("unknown", side="U"),)), _policy(), 200)
    assert unknown.ranked_prints[0].side == "U"
    assert unknown.ranked_prints[0].side_inferred is False
    inferred = calculate(_snapshot((_dark("inferred", side="U", mid="10"),)), _policy(), 200)
    assert inferred.ranked_prints[0].side == "B"
    assert inferred.ranked_prints[0].side_inferred is True


def test_online_correction_at_two_minute_watermark_is_visible_and_later_one_is_pending():
    event_ns = 100_000_000_000
    base = _dark("correction-key", event=event_ns, published=event_ns + 1,
                 available=event_ns + 1, price="10", correction="0")
    at_limit = _dark("correction-key", event=event_ns, published=event_ns + 120_000_000_000,
                    available=event_ns + 120_000_000_000, price="20", correction="1",
                    supersedes="0")
    session = ExchangeSessionV1(date(1970, 1, 1), 0, 300_000_000_000,
                                TZ, "test-calendar-v1", "00:00", 0)
    snapshot = DarkLensSnapshotV1(
        dark_prints=(base, at_limit), calendar=(session,), mode="ONLINE",
        venue_registry=(VenueRuleV1("TRF-X", "OFF_EXCHANGE"),),
    )
    policy = _policy(window_start_ns=event_ns, window_end_ns=event_ns + 1_000_000_000)
    before = calculate(snapshot, policy, event_ns + 119_000_000_000)
    at_boundary = calculate(snapshot, policy, event_ns + 120_000_000_000)
    assert before.total_notional == Decimal("100")
    assert at_boundary.total_notional == Decimal("200")
    assert at_boundary.revision == 1
    assert at_boundary.recompute_pending is False

    too_late = _dark("correction-key", event=event_ns, published=event_ns + 120_000_000_001,
                     available=event_ns + 120_000_000_001, price="30", correction="2",
                     supersedes="1")
    late_snapshot = DarkLensSnapshotV1(
        dark_prints=(base, at_limit, too_late), calendar=(session,), mode="ONLINE",
        venue_registry=(VenueRuleV1("TRF-X", "OFF_EXCHANGE"),),
    )
    late = calculate(late_snapshot, policy, event_ns + 120_000_000_001)
    assert late.total_notional == Decimal("200")
    assert late.recompute_pending is True


def test_explicit_exchange_offsets_map_open_lunch_close_across_dst_and_early_close():
    def ns(value):
        return int(value.replace(tzinfo=UTC).timestamp()) * 1_000_000_000

    friday = date(2026, 3, 6)
    monday = date(2026, 3, 9)
    sessions = (
        ExchangeSessionV1(friday, ns(datetime(2026, 3, 6, 14, 30)),
                          ns(datetime(2026, 3, 6, 21, 0)), "America/New_York",
                          "test-calendar-v1", "09:30", -300),
        ExchangeSessionV1(monday, ns(datetime(2026, 3, 9, 13, 30)),
                          ns(datetime(2026, 3, 9, 20, 0)), "America/New_York",
                          "test-calendar-v1", "09:30", -240),
    )
    assert sessions[0].utc_offset_minutes == -300
    assert sessions[1].utc_offset_minutes == -240
    friday_length = sessions[0].close_ns - sessions[0].open_ns
    monday_length = sessions[1].close_ns - sessions[1].open_ns
    assert friday_length == monday_length
    for session in sessions:
        policy = _policy(window_start_ns=session.open_ns,
                         window_end_ns=session.close_ns, open_minutes=60, close_minutes=60)
        result = calculate(_snapshot(calendar=(session,)), policy, session.close_ns)
        assert result.session_metrics[0].start_ns == session.open_ns
        assert result.session_metrics[-1].end_ns == session.close_ns
        assert result.session_ids == ("open", "lunch", "close")


def test_calendar_without_explicit_timezone_offset_fails_closed():
    session = ExchangeSessionV1(date(1970, 1, 1), 0, 1000, TZ, "test-calendar-v1")
    with pytest.raises(DarkLensError) as exc:
        calculate(_snapshot(calendar=(session,)), _policy(), 200)
    assert exc.value.code == "CALENDAR_OFFSET_UNKNOWN"


def test_scope_mismatched_baseline_is_rejected_and_baseline_must_be_available_after_window():
    sample = BaselineSampleV1(
        date(1970, 1, 1), 100, Decimal("0.1"), 201, 202, "scope-mismatch",
        instrument_id="OTHER", window_end_ns=200,
    )
    with pytest.raises(DarkLensError) as scope:
        calculate(_snapshot((_dark("current"),), (_lit("lit"),),
                            calendar=(_default_session(),), baseline_samples=(sample,)),
                  _policy(), 250)
    assert scope.value.code == "SCOPE_MISMATCH"
    with pytest.raises(DarkLensError) as availability:
        BaselineSampleV1(
            date(1970, 1, 1), 100, Decimal("0.1"), 199, 199, "early-baseline",
            instrument_id="SYNTH-X", window_end_ns=200,
        )
    assert availability.value.code == "INVALID_BASELINE"


def _default_session():
    return ExchangeSessionV1(date(1970, 1, 1), 0, 1000, TZ, "test-calendar-v1", "00:00", 0)


def test_unknown_venue_is_rejected_by_injected_registry():
    unknown = _dark("unknown-venue", venue="XTRF")
    snapshot = DarkLensSnapshotV1(
        dark_prints=(unknown,), calendar=(_default_session(),), venue_registry=(),
    )
    with pytest.raises(DarkLensError) as exc:
        calculate(snapshot, _policy(), 200)
    assert exc.value.code == "UNKNOWN_VENUE"


def test_equal_decimal_scales_have_equal_records_labels_and_digest():
    first = calculate(_snapshot((_dark("scale", price="1000", size="1"),)),
                      _policy(), 200)
    second = calculate(_snapshot((_dark("scale", price="1000.0", size="1.0"),)),
                       _policy(), 200)
    assert first.ranked_prints == second.ranked_prints
    assert first.bucket_counts == second.bucket_counts
    assert first.digest == second.digest


def test_correction_requires_a_valid_supersedes_link():
    base = _dark("event-chain")
    dangling = _dark("event-chain", correction="1", supersedes="not-the-base")
    with pytest.raises(DarkLensError) as exc:
        calculate(_snapshot((base, dangling)), _policy(), 200)
    assert exc.value.code == "ORPHAN_CORRECTION"


def test_future_other_instrument_baseline_cannot_change_earlier_asof_success():
    dark = _dark("future-baseline", price="10.1", size="10")
    lit = _lit("future-baseline-lit", price="10", size="10")
    calendar = (_default_session(),)
    policy = _policy()
    before = calculate(_snapshot((dark,), (lit,), calendar=calendar), policy, 200)
    invisible_other_instrument = BaselineSampleV1(
        date(1970, 1, 1), 100, Decimal("0.2"), 201, 202, "future-other-instrument",
        instrument_id="OTHER", window_end_ns=199,
    )

    after = calculate(
        _snapshot((dark,), (lit,), calendar=calendar,
                  baseline_samples=(invisible_other_instrument,)),
        policy, 200,
    )

    assert before.valid is True
    assert after.valid is True
    assert repr(after).encode("utf-8") == repr(before).encode("utf-8")


def test_representable_adjusted_notional_survives_large_intermediate_product():
    dark = _dark("large-product", price="1E20", size="1E20", fx="1E-30")
    lit = _lit("large-product-lit", price="1E-10", size="1E20")

    result = calculate(_snapshot((dark,), (lit,)), _policy(), 200)

    assert result.valid is True
    assert result.total_notional == Decimal("1E10")
    assert result.dp_vwap == Decimal("1E-10")
    assert "OVERFLOW" not in result.flags


def test_decimal_with_fifty_trailing_zeroes_canonicalizes_to_one():
    value = Decimal("1." + "0" * 50)
    row = _dark("long-trailing-zero", price=str(value))

    assert row.price == Decimal("1")


def test_replace_cannot_change_issued_result_total_without_resealing():
    result = calculate(
        _snapshot((_dark("sealed-total", price="20", size="10"),),
                  (_lit("sealed-total-lit"),)),
        _policy(), 200,
    )
    assert result.valid is True

    with pytest.raises(DarkLensError) as integrity_error:
        replace(result, total_notional=Decimal("999"))
    assert integrity_error.value.code == "UNISSUED_RESULT"
    with pytest.raises(TypeError):
        replace(result, total_notional=Decimal("999"), _seal=result._seal)

    public_fields = {
        field.name: getattr(result, field.name)
        for field in fields(DarkLensResultV1)
        if field.init
    }
    with pytest.raises(DarkLensError) as issuance_error:
        DarkLensResultV1(**public_fields)
    assert issuance_error.value.code == "UNISSUED_RESULT"


def test_online_late_orphan_correction_is_rejected_before_pending_status():
    event_ns = 100_000_000_000
    base = _dark(
        "late-orphan-key", event=event_ns, published=event_ns + 1,
        available=event_ns + 1, correction="0",
    )
    orphan = _dark(
        "late-orphan-key", event=event_ns,
        published=event_ns + 120_000_000_001,
        available=event_ns + 120_000_000_001,
        correction="42", supersedes=None,
    )
    session = ExchangeSessionV1(
        date(1970, 1, 1), 0, 300_000_000_000, TZ, "test-calendar-v1", "00:00", 0,
    )
    snapshot = DarkLensSnapshotV1(
        dark_prints=(base, orphan), calendar=(session,), mode="ONLINE",
        venue_registry=(VenueRuleV1("TRF-X", "OFF_EXCHANGE"),),
    )

    with pytest.raises(DarkLensError) as error:
        calculate(
            snapshot,
            _policy(window_start_ns=event_ns, window_end_ns=event_ns + 1_000_000_000),
            event_ns + 120_000_000_001,
        )

    assert error.value.code == "ORPHAN_CORRECTION"


def test_integer_fields_reject_bool_and_replace_revalidates_nested_freeze():
    dark = _dark("integer-and-replace")
    snapshot = _snapshot((dark,), (_lit("lit"),))
    policy = _policy()
    result = calculate(snapshot, policy, 200)
    invalid_replacements = (
        lambda: replace(dark, available_ns=True),
        lambda: replace(policy, open_minutes=True),
        lambda: replace(snapshot, revision=True),
        lambda: calculate(snapshot, policy, True),
        lambda: replace(result, revision=True),
        lambda: replace(dark, condition_codes=["X"]),
    )
    for reconstruct in invalid_replacements:
        with pytest.raises(DarkLensError):
            reconstruct()
    with pytest.raises(DarkLensError) as replacement_error:
        replace(result, ranked_prints=[])
    assert replacement_error.value.code == "UNISSUED_RESULT"


def test_public_dark_pool_records_reject_copy_deepcopy_and_pickle():
    snapshot = _snapshot((_dark("frozen"),), (_lit("lit"),))
    policy = _policy()
    result = calculate(snapshot, policy, 200)
    records = []
    seen = set()

    def collect(value):
        if id(value) in seen:
            return
        seen.add(id(value))
        if is_dataclass(value) and not isinstance(value, type):
            records.append(value)
            for field in fields(value):
                collect(getattr(value, field.name))
        elif isinstance(value, (tuple, list)):
            for item in value:
                collect(item)

    for root in (snapshot, policy, result):
        collect(root)
    for record in records:
        for operation in (copy.copy, copy.deepcopy, pickle.dumps):
            with pytest.raises(DarkLensError) as exc:
                operation(record)
            assert exc.value.code == "IMMUTABLE_COPY"


def test_exact_150bp_pressure_accepts_large_34_digit_under_cap_notionals():
    base = 12345678901234567890123456789012
    buy_price = f"{203 * base}E-22"
    sell_price = f"{197 * base}E-22"
    assert len(str(203 * base)) == 34
    assert len(str(197 * base)) == 34

    buy = _dark("pressure-buy", event=120, price=buy_price, size="1", side="B")
    sell = _dark("pressure-sell", event=121, price=sell_price, size="1", side="S")
    lit = _lit("pressure-lit", price="10", size="10")
    result = calculate(_snapshot((buy, sell), (lit,)), _policy(), 200)

    assert result.valid is True
    assert result.buy_sell_imbalance_bp == Decimal("150")
    assert result.total_notional == Decimal(f"{400 * base}E-22")
    assert result.total_notional < Decimal("9223372036854.775807")
    assert result.session_metrics[0].cluster_label == "High Buy Pressure"


def test_combined_valid_print_notionals_over_cap_fail_with_overflow_flag():
    each_price = f"{5 * 10**33 - 1}E-21"
    first = _dark("cap-first", price=each_price, size="1", side="B")
    second = _dark("cap-second", price=each_price, size="1", side="B")
    result = calculate(_snapshot((first, second)), _policy(), 200)

    assert result.valid is False
    assert result.flags == ("OVERFLOW",)
    assert result.reason_if_invalid == "OVERFLOW"
    assert result.total_notional is None
    assert result.ranked_prints == ()


def test_tiny_nonzero_baseline_variance_produces_finite_large_z_score():
    day_ns = 86_400_000_000_000
    sessions = tuple(
        ExchangeSessionV1(
            date(1970, 1, 1) + timedelta(days=index), index * day_ns,
            index * day_ns + 12 * 3_600_000_000_000, TZ, "test-calendar-v1", "00:00", 0,
        )
        for index in range(11)
    )
    current_open = 10 * day_ns
    start = current_open + 100
    policy = _policy(window_start_ns=start, window_end_ns=start + 200)
    dark = _dark("tiny-variance-dark", event=start + 10, published=start + 11,
                 available=start + 12, price="10.1", size="10")
    lit = _lit("tiny-variance-lit", event=start + 20, published=start + 21,
               available=start + 22, price="10", size="10")
    samples = tuple(
        BaselineSampleV1(
            date(1970, 1, 1) + timedelta(days=index), index * day_ns + 100,
            Decimal("0") if index % 2 == 0 else Decimal("1E-38"),
            index * day_ns + 301, index * day_ns + 302, f"tiny-baseline-{index}",
            instrument_id="SYNTH-X", window_end_ns=index * day_ns + 300,
        )
        for index in range(10)
    )
    result = calculate(
        _snapshot((dark,), (lit,), calendar=sessions, baseline_samples=samples),
        policy, start + 100,
    )

    assert result.valid is True
    assert result.divergence_z is not None
    assert result.divergence_z.is_finite()
    assert result.divergence_z == Decimal("2E36")
    assert result.z_reason is None


def test_exact_third_current_divergence_is_one_sigma_above_symmetric_baseline():
    day_ns = 86_400_000_000_000
    sessions = tuple(
        ExchangeSessionV1(
            date(1970, 1, 1) + timedelta(days=index), index * day_ns,
            index * day_ns + 12 * 3_600_000_000_000, TZ, "test-calendar-v1", "00:00", 0,
        )
        for index in range(11)
    )
    current_open = 10 * day_ns
    start = current_open + 100
    policy = _policy(window_start_ns=start, window_end_ns=start + 200)
    dark = _dark("third-z-dark", event=start + 10, published=start + 11,
                 available=start + 12, price="4", size="10")
    lit = _lit("third-z-lit", event=start + 20, published=start + 21,
               available=start + 22, price="3", size="10")
    low = Decimal("0.3333333333333333333333333333333332")
    high = Decimal("0.3333333333333333333333333333333334")
    samples = tuple(
        BaselineSampleV1(
            date(1970, 1, 1) + timedelta(days=index), index * day_ns + 100,
            low if index % 2 == 0 else high, index * day_ns + 301,
            index * day_ns + 302, f"third-z-baseline-{index}",
            instrument_id="SYNTH-X", window_end_ns=index * day_ns + 300,
        )
        for index in range(10)
    )
    result = calculate(
        _snapshot((dark,), (lit,), calendar=sessions, baseline_samples=samples),
        policy, start + 100,
    )

    assert result.valid is True
    assert result.divergence == Decimal("0.3333333333333333333333333333333333")
    assert result.divergence_z == Decimal("0.3333333333333333333333333333333333")
    assert result.z_reason is None


def test_single_print_with_over_cap_product_returns_overflow_not_precision_error():
    over_cap = _dark(
        "single-product-over-cap",
        price="5000000000000.000000000000000000001",
        size="2",
    )
    result = calculate(_snapshot((over_cap,)), _policy(), 200)

    assert result.valid is False
    assert result.flags == ("OVERFLOW",)
    assert result.reason_if_invalid == "OVERFLOW"
    assert result.total_notional is None
    assert result.ranked_prints == ()


def test_seeded_decimal_inputs_never_leak_raw_decimal_exceptions():
    rng = random.Random(20261005)

    def operand():
        digits = rng.randint(1, 34)
        coefficient = rng.randint(1, 10**digits - 1)
        exponent = rng.randint(-38, 38 - digits)
        return f"{coefficient}E{exponent:+d}"

    for index in range(64):
        try:
            dark = _dark(
                f"seeded-decimal-{index}", price=operand(), size=operand(), fx=operand(),
            )
            lit = _lit(f"seeded-lit-{index}", price="10", size="10")
            calculate(_snapshot((dark,), (lit,)), _policy(), 200)
        except DecimalException as exc:
            pytest.fail(f"raw decimal exception escaped seeded case {index}: {exc!r}")
        except DarkLensError:
            # Contract failures are typed; raw Decimal exceptions are not.
            pass


def test_decimal_precision_limit_and_exact_notional_arithmetic_never_round():
    with pytest.raises(DarkLensError) as input_error:
        _dark("too-precise", price="1.12345678901234567890123456789012345")
    assert input_error.value.code == "PRECISION_EXCEEDED"

    # Cap validation takes precedence when a valid product also exceeds the cap.
    notional_over_precision = _dark(
        "exact-product", price="1234567890123456789012345678901234", size="9",
    )
    result = calculate(_snapshot((notional_over_precision,)), _policy(), 200)
    assert result.valid is False
    assert result.flags == ("OVERFLOW",)
    assert result.reason_if_invalid == "OVERFLOW"
    assert result.total_notional is None


def test_ambient_decimal_context_does_not_change_dark_pool_results():
    snapshot = _snapshot((_dark("context", price="12345.67", size="8.25"),),
                         (_lit("lit-context", price="123"),))
    expected = calculate(snapshot, _policy(), 200)
    with localcontext() as context:
        context.prec = 6
        context.Emax = 9
        constrained = calculate(snapshot, _policy(), 200)
    assert constrained == expected
    assert constrained.digest == expected.digest


def test_include_trf_venue_filter_is_rejected():
    with pytest.raises(DarkLensError):
        _policy(venue_filter="include_trf")




def test_nine_vs_ten_prior_baseline_samples_and_future_sample_exclusion():
    day_ns = 86_400_000_000_000
    current_open = 10 * day_ns
    sessions = tuple(
        ExchangeSessionV1(date(1970, 1, 1) + timedelta(days=index),
                          index * day_ns, index * day_ns + 12 * 3_600_000_000_000,
                          TZ, "test-calendar-v1", "00:00", 0)
        for index in range(11)
    )
    start = current_open + 100
    policy = _policy(window_start_ns=start, window_end_ns=start + 200)
    dark = _dark("current", event=start + 10, published=start + 11,
                 available=start + 12, price="20", size="10")
    lit = _lit("current-lit", event=start + 20, published=start + 21,
               available=start + 22, price="10", size="10")
    samples = tuple(
        BaselineSampleV1(
            date(1970, 1, 1) + timedelta(days=index), index * day_ns + 100,
            Decimal(index), index * day_ns + 301, index * day_ns + 302,
            f"baseline-{index}", instrument_id="SYNTH-X",
            window_end_ns=index * day_ns + 300,
        )
        for index in range(10)
    )
    nine = calculate(
        DarkLensSnapshotV1(dark_prints=(dark,), lit_trades=(lit,), calendar=sessions,
                           baseline_samples=samples[:9], venue_registry=(
                               VenueRuleV1("TRF-X", "OFF_EXCHANGE"),
                               VenueRuleV1("XNYS", "LIT"),
                           )),
        policy, start + 100,
    )
    ten = calculate(
        DarkLensSnapshotV1(dark_prints=(dark,), lit_trades=(lit,), calendar=sessions,
                           baseline_samples=(*samples, BaselineSampleV1(
                               date(1970, 1, 10), 9 * day_ns + 100,
                               Decimal("999"), start + 200, start + 200,
                               "future-baseline", instrument_id="SYNTH-X",
                               window_end_ns=9 * day_ns + 300)),
                           venue_registry=(VenueRuleV1("TRF-X", "OFF_EXCHANGE"),
                                           VenueRuleV1("XNYS", "LIT"))),
        policy, start + 100,
    )
    assert nine.divergence_z is None
    assert nine.z_reason == "BASELINE_INSUFFICIENT"
    assert ten.divergence_z is not None
    assert "future-baseline" not in ten.source_ids


def test_missing_trading_day_calendar_is_rejected_and_early_close_bounds_close_window():
    no_calendar = DarkLensSnapshotV1(dark_prints=(), calendar=())
    with pytest.raises(DarkLensError) as exc:
        calculate(no_calendar, _policy(), 200)
    assert exc.value.code == "MISSING_CALENDAR"

    open_ns = int(datetime(2026, 7, 2, 13, 30, tzinfo=UTC).timestamp()) * 1_000_000_000
    close_ns = int(datetime(2026, 7, 2, 17, 0, tzinfo=UTC).timestamp()) * 1_000_000_000
    early_close = ExchangeSessionV1(
        date(2026, 7, 2), open_ns, close_ns, "America/New_York", "test-calendar-v1",
        "09:30", -240,
    )
    result = calculate(
        _snapshot(calendar=(early_close,)),
        _policy(window_start_ns=open_ns, window_end_ns=close_ns), close_ns,
    )
    assert result.session_metrics[-1].start_ns == close_ns - 60 * 60_000_000_000
    assert result.session_metrics[-1].end_ns == close_ns
