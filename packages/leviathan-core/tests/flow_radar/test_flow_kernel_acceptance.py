from __future__ import annotations

import copy
import pickle
from dataclasses import replace
from datetime import date
from decimal import Decimal, Inexact, localcontext

import pytest

from leviathan_core.flow_radar import (
    BurstPolicy,
    Entitlement,
    FilterPolicy,
    OpenInterest,
    OptionPrint,
    OptionSide,
    PrintFlag,
    Quote,
    SessionCalendar,
    SourceStamp,
    TradeSide,
    TradingSession,
    UnderlyingMid,
    detect_bursts,
    evaluate_flow,
    reconcile_evaluations,
    tilt_snapshots,
)
from leviathan_core.flow_radar.bursts import StrikeLadder
from leviathan_core.flow_radar.models import FlowError

DAY0 = date(2026, 1, 2)
DAY1 = date(2026, 1, 5)
DAY2 = date(2026, 1, 6)
DAY3 = date(2026, 1, 7)
START = 40_000_000_000
EVENT = 50_000_000_000
END = 60_000_000_000
CALENDAR = SessionCalendar(
    sessions=(
        TradingSession(DAY0, 0, 10_000_000_000),
        TradingSession(DAY1, 20_000_000_000, 30_000_000_000),
        TradingSession(DAY2, 35_000_000_000, 39_000_000_000),
        TradingSession(DAY3, START, END),
    )
)
EXPIRY = date(2026, 2, 20)


def stamp(
    key: str,
    *,
    event_ns: int = EVENT,
    available_ns: int | None = None,
    entitlement: Entitlement = Entitlement.SYNTHETIC,
    ingest_ns: int | None = None,
    request_id: str | None = None,
    correction_of: str | None = None,
) -> SourceStamp:
    return SourceStamp(
        provider="vendor",
        dataset="options-v1",
        session="session-2026-01-07",
        venue="CBOE",
        native_record_key=key,
        event_ns=event_ns,
        available_ns=EVENT if available_ns is None else available_ns,
        entitlement=entitlement,
        ingest_ns=ingest_ns,
        request_id=request_id,
        correction_of=correction_of,
    )


def print_event(
    key: str = "print-1",
    *,
    ticker: str = "XYZ",
    event_ns: int = EVENT,
    available_ns: int | None = None,
    price: Decimal = Decimal("2"),
    strike: Decimal = Decimal("101.01"),
    cp: OptionSide = OptionSide.CALL,
    trade_side: TradeSide = TradeSide.BUY,
    size: Decimal = Decimal("1"),
    flags: tuple[PrintFlag, ...] = (),
    common_order_id: str | None = None,
    entitlement: Entitlement = Entitlement.SYNTHETIC,
    ingest_ns: int | None = None,
    request_id: str | None = None,
    correction_of: str | None = None,
) -> OptionPrint:
    return OptionPrint(
        stamp=stamp(
            key,
            event_ns=event_ns,
            available_ns=event_ns if available_ns is None else available_ns,
            entitlement=entitlement,
            ingest_ns=ingest_ns,
            request_id=request_id,
            correction_of=correction_of,
        ),
        ticker=ticker,
        expiry=EXPIRY,
        strike=strike,
        cp=cp,
        trade_side=trade_side,
        size=size,
        price=price,
        multiplier=Decimal("100"),
        flags=flags,
        common_order_id=common_order_id,
    )


def underlying(ticker: str = "XYZ", *, event_ns: int = EVENT) -> UnderlyingMid:
    return UnderlyingMid(
        stamp=stamp(f"underlying-{ticker}", event_ns=event_ns, available_ns=event_ns),
        ticker=ticker,
        mid=Decimal("100"),
    )


def quote_for(
    trade: OptionPrint,
    *,
    age_ns: int = 0,
    bid: Decimal = Decimal("1.9"),
    ask: Decimal = Decimal("2"),
) -> Quote:
    quote_time = trade.stamp.event_ns - age_ns
    return Quote(
        stamp=stamp(
            "quote-" + trade.stamp.native_record_key,
            event_ns=quote_time,
            available_ns=trade.stamp.event_ns,
        ),
        ticker=trade.ticker,
        expiry=trade.expiry,
        strike=trade.strike,
        cp=trade.cp,
        bid=bid,
        ask=ask,
    )


def oi_for(
    trade: OptionPrint, *, as_of_day: date = DAY2, contracts: Decimal = Decimal("1")
) -> OpenInterest:
    return OpenInterest(
        stamp=stamp("oi-" + trade.stamp.native_record_key, event_ns=EVENT - 1),
        ticker=trade.ticker,
        expiry=trade.expiry,
        strike=trade.strike,
        cp=trade.cp,
        contracts=contracts,
        as_of_day=as_of_day,
    )


def evaluated(
    trade: OptionPrint,
    *,
    policy: FilterPolicy | None = None,
    quote: Quote | None = None,
    oi: OpenInterest | None = None,
    mid: UnderlyingMid | None = None,
):
    return evaluate_flow(
        trade,
        CALENDAR,
        underlying=underlying(trade.ticker) if mid is None else mid,
        quote=quote,
        oi=oi,
        policy=policy,
    )


def test_decimal_premium_and_required_synthetic_entitlement_are_preserved() -> None:
    trade = print_event(entitlement=Entitlement.SYNTHETIC)
    result = evaluated(trade)

    assert result.integrity_ok is True
    assert result.accepted is True
    assert result.premium == Decimal("200")
    assert result.print.stamp.entitlement is Entitlement.SYNTHETIC
    assert {Entitlement.ENTITLED, Entitlement.UNVERIFIED, Entitlement.SYNTHETIC} == {
        print_event(f"e-{index}", entitlement=label).stamp.entitlement
        for index, label in enumerate(Entitlement)
    }


def test_missing_wrong_session_and_untimely_underlying_fail_base_integrity() -> None:
    trade = print_event()
    late_mid = underlying(event_ns=EVENT + 1)
    old_session_mid = UnderlyingMid(
        stamp=stamp("old-mid", event_ns=29_000_000_000, available_ns=EVENT),
        ticker="XYZ",
        mid=Decimal("100"),
    )

    assert evaluated(trade, mid=None).integrity_ok is True  # helper injects a valid mid
    missing = evaluate_flow(trade, CALENDAR)
    assert missing.integrity_ok is False
    assert "BASE_INTEGRITY" in missing.reasons
    assert evaluated(trade, mid=late_mid).integrity_ok is False
    assert evaluated(trade, mid=old_session_mid).integrity_ok is False


def test_nbbo_freshness_boundary_is_inclusive_and_strict_near_ask_fails_closed() -> None:
    trade = print_event(price=Decimal("1.98"))
    exact = evaluated(
        trade,
        quote=quote_for(trade, age_ns=500_000_000),
        policy=FilterPolicy(near_ask=True),
    )
    stale = evaluated(
        trade,
        quote=quote_for(trade, age_ns=500_000_001),
        policy=FilterPolicy(near_ask=True),
    )

    assert exact.near_ask is True
    assert exact.accepted is True
    assert stale.near_ask is None
    assert stale.accepted is False
    assert "NEAR_ASK_UNKNOWN" in stale.reasons


def test_near_ask_threshold_comparison_is_exact() -> None:
    at_boundary = print_event(price=Decimal("1.98"))
    below_boundary = print_event(key="print-below", price=Decimal("1.979999999999999999"))

    exact = evaluated(
        at_boundary,
        quote=quote_for(at_boundary),
        policy=FilterPolicy(near_ask=True),
    )
    below = evaluated(
        below_boundary,
        quote=quote_for(below_boundary),
        policy=FilterPolicy(near_ask=True),
    )

    assert exact.near_ask is True
    assert below.near_ask is False
    assert "NEAR_ASK_FALSE" in below.reasons


def test_oi_uses_injected_trading_day_calendar_and_strict_greater_than() -> None:
    trade = print_event(size=Decimal("10"))
    exact = evaluated(
        trade,
        oi=oi_for(trade, as_of_day=DAY2, contracts=Decimal("10")),
        policy=FilterPolicy(vol_gt_oi=True),
    )
    previous_session = evaluated(
        trade,
        oi=oi_for(trade, as_of_day=DAY2, contracts=Decimal("9")),
        policy=FilterPolicy(vol_gt_oi=True),
    )
    stale = evaluated(
        trade,
        oi=oi_for(trade, as_of_day=DAY1, contracts=Decimal("0")),
        policy=FilterPolicy(vol_gt_oi=True),
    )

    assert exact.vol_gt_oi is False
    assert "VOL_GT_OI_FALSE" in exact.reasons
    assert previous_session.vol_gt_oi is True
    assert previous_session.accepted is True
    assert stale.vol_gt_oi is None
    assert "VOL_GT_OI_UNKNOWN" in stale.reasons


def test_otm_uses_call_put_direction_and_exact_configured_buffer_boundary() -> None:
    call_at_boundary = print_event(strike=Decimal("100.500"))
    call_past_boundary = print_event(key="call-past", strike=Decimal("100.5001"))
    put_at_boundary = print_event(key="put-boundary", cp=OptionSide.PUT, strike=Decimal("99.500"))
    put_past_boundary = print_event(key="put-past", cp=OptionSide.PUT, strike=Decimal("99.4999"))
    policy = FilterPolicy(otm_only=True)

    assert evaluated(call_at_boundary, policy=policy).otm is False
    assert evaluated(call_past_boundary, policy=policy).otm is True
    assert evaluated(put_at_boundary, policy=policy).otm is False
    assert evaluated(put_past_boundary, policy=policy).otm is True


def test_burst_gap_and_total_window_boundaries_are_inclusive() -> None:
    exact_gap = tuple(
        evaluated(print_event(f"gap-{i}", event_ns=EVENT + i * 1_500_000_000)) for i in range(3)
    )
    over_gap = tuple(
        evaluated(
            print_event(
                f"gap-over-{i}",
                event_ns=EVENT + (i * 1_500_000_000 if i < 2 else 3_000_000_001),
            )
        )
        for i in range(3)
    )
    exact_window_offsets = (
        0,
        1_000_000_000,
        2_000_000_000,
        3_000_000_000,
        4_000_000_000,
        5_000_000_000,
        6_500_000_000,
        8_000_000_000,
    )
    over_window_offsets = (*exact_window_offsets[:-1], 8_000_000_001)
    exact_window = tuple(
        evaluated(print_event(f"window-{i}", event_ns=EVENT + offset))
        for i, offset in enumerate(exact_window_offsets)
    )
    over_window = tuple(
        evaluated(print_event(f"window-over-{i}", event_ns=EVENT + offset))
        for i, offset in enumerate(over_window_offsets)
    )
    strict_eight = BurstPolicy(min_count=8, min_notional=Decimal("999999"))

    gap_groups = detect_bursts(exact_gap, CALENDAR, BurstPolicy(min_count=3))
    over_gap_groups = detect_bursts(over_gap, CALENDAR, BurstPolicy(min_count=3))
    assert len(gap_groups) == 1
    assert over_gap_groups == ()
    assert len(detect_bursts(exact_window, CALENDAR, strict_eight)) == 1
    assert detect_bursts(over_window, CALENDAR, strict_eight) == ()


def test_burst_identity_is_per_ticker_and_exact_strike() -> None:
    mixed_tickers = tuple(
        evaluated(print_event(f"ticker-{i}", ticker="XYZ" if i < 2 else "ABC")) for i in range(3)
    )
    mixed_strikes = tuple(
        evaluated(
            print_event(
                f"strike-{i}",
                strike=Decimal("101") if i < 2 else Decimal("102"),
            )
        )
        for i in range(3)
    )
    policy = BurstPolicy(min_count=3, min_notional=Decimal("999999"))

    assert detect_bursts(mixed_tickers, CALENDAR, policy) == ()
    assert detect_bursts(mixed_strikes, CALENDAR, policy) == ()

    adjacent = detect_bursts(
        mixed_strikes,
        CALENDAR,
        policy,
        strike_ladders=(
            StrikeLadder(
                version="ladder-v1",
                ticker="XYZ",
                expiry=EXPIRY,
                strikes=(Decimal("101"), Decimal("102")),
            ),
        ),
    )
    assert len(adjacent) == 1
    assert adjacent[0].strikes == (Decimal("101"), Decimal("102"))
    assert adjacent[0].strike_ladder_version == "ladder-v1"

    non_adjacent = tuple(
        evaluated(
            print_event(
                f"nonadjacent-{i}",
                strike=strike,
            )
        )
        for i, strike in enumerate((Decimal("101"), Decimal("102"), Decimal("104")))
    )
    with_gap = detect_bursts(
        non_adjacent,
        CALENDAR,
        policy,
        strike_ladders=(
            StrikeLadder(
                version="ladder-v1",
                ticker="XYZ",
                expiry=EXPIRY,
                strikes=(
                    Decimal("101"),
                    Decimal("102"),
                    Decimal("103"),
                    Decimal("104"),
                ),
            ),
        ),
    )
    assert with_gap == ()


def test_burst_outputs_are_permutation_invariant() -> None:
    evaluations = tuple(
        evaluated(print_event(f"burst-{i}", event_ns=EVENT + i * 100_000_000)) for i in range(4)
    )
    policy = BurstPolicy(min_count=3)
    forward = detect_bursts(evaluations, CALENDAR, policy)
    reversed_output = detect_bursts(tuple(reversed(evaluations)), CALENDAR, policy)

    assert forward == reversed_output
    assert forward[0].member_ids == tuple(sorted(forward[0].member_ids))


def test_reconciliation_distinguishes_refetch_correction_and_unlineaged_retime() -> None:
    original = print_event("same-key")
    refetch = print_event("same-key", ingest_ns=EVENT + 1, request_id="request-2")
    original_eval = evaluated(original)
    refetch_eval = evaluated(refetch)
    duplicate = reconcile_evaluations((original_eval, refetch_eval))

    assert len(duplicate.accepted) == 1
    assert duplicate.duplicate_keys == (original.stamp.source_key,)
    assert duplicate.correction_keys == ()

    correction = print_event("same-key", price=Decimal("2.1"), correction_of=original.record_id)
    corrected = reconcile_evaluations((original_eval, evaluated(correction)))
    assert len(corrected.accepted) == 1
    assert corrected.accepted[0].print == correction
    assert corrected.correction_keys == (original.stamp.source_key,)

    retimed = print_event("same-key", event_ns=EVENT + 1)
    unlinked = reconcile_evaluations((original_eval, evaluated(retimed)))
    assert unlinked.accepted == ()
    assert unlinked.conflict_keys == (original.stamp.source_key,)


def test_tilt_zero_denominator_is_null_and_permutation_does_not_change_snapshots() -> None:
    empty = tilt_snapshots((), "XYZ", EVENT, CALENDAR)
    assert len(empty) == 4
    assert all(snapshot.call_notional == 0 for snapshot in empty)
    assert all(snapshot.put_notional == 0 for snapshot in empty)
    assert all(snapshot.tilt is None for snapshot in empty)

    evaluations = (
        evaluated(print_event("call", price=Decimal("2"), size=Decimal("1"))),
        evaluated(print_event("put", cp=OptionSide.PUT, price=Decimal("1"), size=Decimal("2"))),
    )
    forward = tilt_snapshots(evaluations, "XYZ", EVENT, CALENDAR)
    reverse = tilt_snapshots(tuple(reversed(evaluations)), "XYZ", EVENT, CALENDAR)
    assert forward == reverse
    assert forward[0].call_notional == Decimal("200")
    assert forward[0].put_notional == Decimal("200")
    assert forward[0].tilt == Decimal("0")


def test_future_available_correction_cannot_change_an_earlier_tilt_snapshot() -> None:
    original = print_event("as-of-print", price=Decimal("2"), available_ns=EVENT)
    original_evaluation = evaluated(original)
    correction = print_event(
        "as-of-print",
        price=Decimal("2.1"),
        available_ns=EVENT + 1,
        correction_of=original.record_id,
    )
    correction_evaluation = evaluated(correction)

    at_t = tilt_snapshots((original_evaluation,), "XYZ", EVENT, CALENDAR)
    with_future_correction = tilt_snapshots(
        (original_evaluation, correction_evaluation), "XYZ", EVENT, CALENDAR
    )
    reversed_with_future_correction = tilt_snapshots(
        (correction_evaluation, original_evaluation), "XYZ", EVENT, CALENDAR
    )
    at_t_plus_1 = tilt_snapshots(
        (original_evaluation, correction_evaluation), "XYZ", EVENT + 1, CALENDAR
    )

    assert original.stamp.available_ns == EVENT
    assert correction.stamp.available_ns == EVENT + 1
    assert at_t == with_future_correction
    assert with_future_correction == reversed_with_future_correction
    assert at_t[0].call_notional == Decimal("200")
    assert at_t_plus_1[0].call_notional == Decimal("210")


def test_adjusted_print_retains_original_split_values() -> None:
    adjusted = OptionPrint(
        stamp=stamp("split-print"),
        ticker="XYZ",
        expiry=EXPIRY,
        strike=Decimal("50"),
        cp=OptionSide.CALL,
        trade_side=TradeSide.BUY,
        size=Decimal("2"),
        price=Decimal("1"),
        multiplier=Decimal("100"),
        original_strike=Decimal("100"),
        original_size=Decimal("1"),
        adjustment_version="split-2-for-1-v1",
    )
    result = evaluated(adjusted)

    assert result.print.strike == Decimal("50")
    assert result.print.size == Decimal("2")
    assert result.print.original_strike == Decimal("100")
    assert result.print.original_size == Decimal("1")
    assert result.print.adjustment_version == "split-2-for-1-v1"


def test_models_block_copy_pickle_validate_replace_and_reject_boolean_timestamps() -> None:
    trade = print_event()
    for operation in (
        lambda: copy.copy(trade),
        lambda: copy.deepcopy(trade),
        lambda: pickle.dumps(trade),
    ):
        with pytest.raises(FlowError):
            operation()

    with pytest.raises(FlowError) as bool_error:
        stamp("bool-ns", event_ns=True)  # type: ignore[arg-type]
    assert bool_error.value.code == "INVALID_UTC_NS"

    with pytest.raises(FlowError) as invalid_replace:
        replace(FilterPolicy(), otm_buffer=Decimal("1"))
    assert invalid_replace.value.code == "POLICY_OUT_OF_BOUNDS"

    with pytest.raises(FlowError):
        replace(BurstPolicy(), min_count=True)


def test_decimal_contract_rejects_float_and_precision_overflow_with_typed_code() -> None:
    with pytest.raises(FlowError) as float_error:
        print_event(price=1.25)  # type: ignore[arg-type]
    assert float_error.value.code == "INVALID_DECIMAL"

    with pytest.raises(FlowError) as precision_error:
        print_event(strike=Decimal("1.2345678901234567890123456789012345"))
    assert precision_error.value.code == "PRECISION_EXCEEDED"


def test_decimal_magnitude_is_checked_before_expansion() -> None:
    accepted = print_event(price=Decimal("1E+34"))
    assert accepted.price == Decimal("1E+34")

    with pytest.raises(FlowError) as error:
        print_event(price=Decimal("1E+100000"))
    assert error.value.code == "MAGNITUDE_EXCEEDED"


def test_arithmetic_precision_overflow_is_typed_and_errors_do_not_echo_input() -> None:
    large_price = Decimal("1234567890123456789")
    oversized_product = print_event(
        "oversized-product",
        price=large_price,
        size=large_price,
        strike=Decimal("1"),
        cp=OptionSide.PUT,
    )
    with pytest.raises(FlowError) as arithmetic_error:
        evaluated(oversized_product)
    assert arithmetic_error.value.code == "PRECISION_EXCEEDED"

    secret_numeric_input = Decimal("1.2345678901234567890123456789012345")
    with pytest.raises(FlowError) as validation_error:
        print_event("private-value", price=secret_numeric_input)
    assert validation_error.value.code == "PRECISION_EXCEEDED"
    assert str(secret_numeric_input) not in str(validation_error.value)
    assert str(secret_numeric_input) not in repr(validation_error.value.args)


def test_canonical_numeric_identity_and_kernel_decimal_context() -> None:
    first = print_event(price=Decimal("2.0"), strike=Decimal("101.0"))
    second = print_event(price=Decimal("2.00"), strike=Decimal("101.00"))
    assert first.record_id == second.record_id

    normal = evaluated(first)
    with localcontext() as context:
        context.prec = 2
        context.traps[Inexact] = True
        constrained = evaluated(second)
    assert normal.premium == constrained.premium == Decimal("200")
    assert normal.accepted == constrained.accepted


def test_final_quotient_is_rounded_once_at_kernel_precision() -> None:
    evaluations = (
        evaluated(print_event("ratio-call", price=Decimal("2"))),
        evaluated(print_event("ratio-put", cp=OptionSide.PUT, price=Decimal("1"))),
    )

    result = tilt_snapshots(evaluations, "XYZ", EVENT, CALENDAR)

    assert result[0].tilt == Decimal("0.3333333333333333333333333333333333")
