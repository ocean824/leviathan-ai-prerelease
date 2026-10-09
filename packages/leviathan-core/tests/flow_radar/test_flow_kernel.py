import pickle
from copy import copy, deepcopy
from dataclasses import replace
from datetime import date
from decimal import Context, Decimal, localcontext
from itertools import permutations
from random import Random

import pytest

from leviathan_core.flow_radar import (
    BurstPolicy,
    Entitlement,
    FilterPolicy,
    FlowError,
    OpenInterest,
    OptionPrint,
    OptionSide,
    PrintFlag,
    Quote,
    SessionCalendar,
    SourceStamp,
    StrikeLadder,
    TradeSide,
    TradingSession,
    UnderlyingMid,
    detect_bursts,
    evaluate_flow,
    reconcile_evaluations,
    tilt_snapshots,
)

DAY = date(2026, 9, 30)
OPEN = 1_780_000_000_000_000_000


def calendar() -> SessionCalendar:
    return SessionCalendar(
        sessions=(
            TradingSession(
                date(2026, 9, 28), OPEN - 172_800_000_000_000, OPEN - 149_400_000_000_000
            ),
            TradingSession(date(2026, 9, 29), OPEN - 86_400_000_000_000, OPEN - 63_000_000_000_000),
            TradingSession(DAY, OPEN, OPEN + 23_400_000_000_000),
        )
    )


def stamp(key: str, event_ns: int = OPEN + 1_000_000_000) -> SourceStamp:
    return SourceStamp(
        provider="fixture",
        dataset="v1",
        session="day",
        venue="XNAS",
        native_record_key=key,
        event_ns=event_ns,
        available_ns=event_ns,
        entitlement=Entitlement.SYNTHETIC,
    )


def option(
    key: str = "a",
    *,
    event_ns: int = OPEN + 1_000_000_000,
    ticker: str = "ABC",
    cp: OptionSide = OptionSide.CALL,
) -> OptionPrint:
    return OptionPrint(
        stamp=stamp(key, event_ns),
        ticker=ticker,
        expiry=date(2026, 10, 16),
        strike=Decimal("105"),
        cp=cp,
        trade_side=TradeSide.BUY,
        size=Decimal("100"),
        price=Decimal("2.5"),
        multiplier=Decimal("100"),
    )


def underlying(at_ns: int = OPEN + 1_000_000_000) -> UnderlyingMid:
    return UnderlyingMid(stamp=stamp("underlying", at_ns), ticker="ABC", mid=Decimal("100"))


def test_strict_decimal_and_deep_freeze() -> None:
    base = option()
    with pytest.raises(FlowError):
        replace(base, price=2.5)
    with pytest.raises(FlowError):
        replace(base, price=Decimal("NaN"))
    with pytest.raises(FlowError):
        replace(base.stamp, event_ns=True)
    for operation in (copy, deepcopy, pickle.dumps):
        with pytest.raises(FlowError):
            operation(base)
    with pytest.raises(FlowError):
        replace(base, flags=["SWEEP"])
    with pytest.raises(FlowError):
        replace(base, original_strike=Decimal("110"))
    with pytest.raises(FlowError):
        replace(base.stamp, provider="vendor\nname")
    evaluation = evaluate_flow(base, calendar(), underlying=underlying())
    with pytest.raises(FlowError):
        replace(evaluation, accepted="false")
    with pytest.raises(FlowError):
        replace(evaluation, premium=Decimal("999"))


def test_canonical_identity_and_explicit_correction() -> None:
    trade = option()
    refetch = replace(trade, stamp=replace(trade.stamp, ingest_ns=OPEN + 2, request_id="r2"))
    assert refetch.record_id == trade.record_id
    assert replace(trade, price=Decimal("2.50")).record_id == trade.record_id
    first = evaluate_flow(trade, calendar(), underlying=underlying())
    duplicate = evaluate_flow(refetch, calendar(), underlying=underlying())
    duplicate_result = reconcile_evaluations((first, duplicate))
    assert len(duplicate_result.accepted) == 1
    assert duplicate_result.duplicate_keys == (trade.stamp.source_key,)
    filtered = evaluate_flow(
        trade,
        calendar(),
        underlying=underlying(),
        policy=FilterPolicy(min_premium=Decimal("1000000")),
    )
    inconsistent = reconcile_evaluations((first, filtered))
    assert inconsistent.conflict_keys == (trade.stamp.source_key,)
    assert reconcile_evaluations((filtered, first)) == inconsistent
    correction = replace(
        trade, stamp=replace(trade.stamp, correction_of=trade.record_id), price=Decimal("3")
    )
    correction_result = reconcile_evaluations(
        (first, evaluate_flow(correction, calendar(), underlying=underlying()))
    )
    assert correction_result.accepted[0].print.record_id == correction.record_id
    assert correction_result.correction_keys == (trade.stamp.source_key,)
    retimed = replace(
        correction,
        stamp=replace(
            correction.stamp,
            event_ns=trade.stamp.event_ns + 1,
            available_ns=trade.stamp.available_ns + 1,
        ),
    )
    retimed_result = reconcile_evaluations(
        (first, evaluate_flow(retimed, calendar(), underlying=underlying()))
    )
    assert retimed_result.accepted[0].print.record_id == retimed.record_id
    orphan = replace(trade, stamp=replace(trade.stamp, correction_of="0" * 64), price=Decimal("3"))
    orphan_result = reconcile_evaluations(
        (evaluate_flow(orphan, calendar(), underlying=underlying()),)
    )
    assert orphan_result.conflict_keys == (trade.stamp.source_key,)
    conflict = replace(trade, price=Decimal("4"))
    assert reconcile_evaluations(
        (first, evaluate_flow(conflict, calendar(), underlying=underlying()))
    ).conflict_keys == (trade.stamp.source_key,)


def test_otm_direction_and_zero_tilt() -> None:
    call = option()
    put = replace(option("put", cp=OptionSide.PUT), strike=Decimal("95"))
    policy = FilterPolicy(otm_only=True)
    assert evaluate_flow(call, calendar(), underlying=underlying(), policy=policy).otm is True
    assert evaluate_flow(put, calendar(), underlying=underlying(), policy=policy).otm is True
    assert tilt_snapshots((), "ABC", call.stamp.event_ns, calendar())[0].tilt is None


def test_decimal_arithmetic_ignores_ambient_context() -> None:
    trade = replace(option(), price=Decimal("2.50000000000000000001"))
    reference = evaluate_flow(trade, calendar(), underlying=underlying()).premium
    with localcontext(Context(prec=5, Emax=10)):
        observed = evaluate_flow(trade, calendar(), underlying=underlying()).premium
    assert observed == reference


def test_burst_window_boundaries_and_ticker_isolation() -> None:
    start = OPEN + 1_000_000_000
    offsets = (
        0,
        1_500_000_000,
        3_000_000_000,
        4_500_000_000,
        6_000_000_000,
        7_500_000_000,
        8_000_000_000,
    )
    trades = tuple(option(str(i), event_ns=start + offset) for i, offset in enumerate(offsets))
    foreign = option("foreign", event_ns=start + 4_000_000_000, ticker="XYZ")
    evaluations = (
        *(evaluate_flow(trade, calendar(), underlying=underlying()) for trade in trades),
        evaluate_flow(foreign, calendar(), underlying=replace(underlying(), ticker="XYZ")),
    )
    burst = detect_bursts(evaluations, calendar())
    assert len(burst) == 1
    assert burst[0].member_ids == tuple(sorted(trade.record_id for trade in trades))
    assert burst[0].last_ns - burst[0].first_ns == 8_000_000_000
    assert burst[0].ticker == "ABC"


def test_sweep_requires_vendor_flag_or_more_than_group_count_same_order() -> None:
    trades = tuple(
        replace(
            option(str(i), event_ns=OPEN + 1_000_000_000 + i * 1_000_000_000),
            common_order_id="order-1",
        )
        for i in range(3)
    )
    trades = (
        trades[0],
        replace(trades[1], stamp=replace(trades[1].stamp, venue="XNYS")),
        trades[2],
    )
    evaluations = tuple(
        evaluate_flow(trade, calendar(), underlying=underlying()) for trade in trades
    )
    assert detect_bursts(evaluations, calendar())[0].is_sweep is False


def test_balanced_tilt_and_filtered_view() -> None:
    call = replace(option(), size=Decimal("10"))
    put = replace(option("put", cp=OptionSide.PUT), strike=Decimal("95"), size=Decimal("10"))
    evaluations = (
        evaluate_flow(call, calendar(), underlying=underlying()),
        evaluate_flow(
            put,
            calendar(),
            underlying=underlying(),
            policy=FilterPolicy(required_cp=OptionSide.CALL),
        ),
    )
    all_tilt = tilt_snapshots(evaluations, "ABC", call.stamp.event_ns, calendar())
    filtered_tilt = tilt_snapshots(
        evaluations, "ABC", call.stamp.event_ns, calendar(), filtered_only=True
    )
    assert all_tilt[0].tilt == Decimal("0")
    assert filtered_tilt[0].tilt == Decimal("1")


def test_vendor_flag_and_split_lineage_are_preserved() -> None:
    base = option()
    adjusted = replace(
        base,
        flags=(PrintFlag.SWEEP, PrintFlag.MULTI_LEG),
        strike=Decimal("52.5"),
        size=Decimal("200"),
        original_strike=Decimal("105"),
        original_size=Decimal("100"),
        adjustment_version="split-v1",
    )
    result = evaluate_flow(adjusted, calendar(), underlying=underlying())
    assert result.is_sweep
    assert adjusted.original_strike == base.strike
    assert adjusted.original_size == base.size
    assert adjusted.adjustment_version == "split-v1"


def test_freshness_boundaries_and_strict_unknowns() -> None:
    trade = option()
    quote = Quote(
        stamp=stamp("q", trade.stamp.event_ns - 500_000_000),
        ticker="ABC",
        expiry=trade.expiry,
        strike=trade.strike,
        cp=trade.cp,
        bid=Decimal("2"),
        ask=Decimal("2.5"),
    )
    oi = OpenInterest(
        stamp=stamp("oi", OPEN - 70_000_000_000_000),
        ticker="ABC",
        expiry=trade.expiry,
        strike=trade.strike,
        cp=trade.cp,
        contracts=Decimal("50"),
        as_of_day=date(2026, 9, 29),
    )
    policy = FilterPolicy(vol_gt_oi=True, near_ask=True)
    fresh = evaluate_flow(
        trade, calendar(), underlying=underlying(), quote=quote, oi=oi, policy=policy
    )
    assert fresh.accepted and fresh.vol_gt_oi is True and fresh.near_ask is True
    stale = evaluate_flow(
        trade,
        calendar(),
        underlying=underlying(),
        quote=replace(quote, stamp=stamp("q", trade.stamp.event_ns - 500_000_001)),
        oi=replace(oi, as_of_day=date(2026, 9, 28)),
        policy=policy,
    )
    assert not stale.accepted and stale.vol_gt_oi is None and stale.near_ask is None
    equal_oi = replace(oi, contracts=trade.size)
    equal_result = evaluate_flow(
        trade,
        calendar(),
        underlying=underlying(),
        oi=equal_oi,
        policy=FilterPolicy(vol_gt_oi=True),
    )
    assert equal_result.vol_gt_oi is False and not equal_result.accepted


def test_burst_and_tilt_replay_permutation() -> None:
    base = option()
    trades = tuple(
        option(str(i), event_ns=base.stamp.event_ns + i * 1_500_000_000) for i in range(3)
    )
    evaluations = tuple(
        evaluate_flow(trade, calendar(), underlying=underlying()) for trade in trades
    )
    reversed_evaluations = evaluations[::-1]
    assert detect_bursts(evaluations, calendar()) == detect_bursts(reversed_evaluations, calendar())
    assert detect_bursts(evaluations, calendar())[0].member_ids == tuple(
        sorted(t.record_id for t in trades)
    )
    assert tilt_snapshots(evaluations, "ABC", trades[-1].stamp.event_ns, calendar()) == (
        tilt_snapshots(reversed_evaluations, "ABC", trades[-1].stamp.event_ns, calendar())
    )
    assert tilt_snapshots(evaluations, "ABC", trades[-1].stamp.event_ns, calendar())[
        0
    ].tilt == Decimal("1")
    expected_bursts = detect_bursts(evaluations, calendar())
    expected_tilt = tilt_snapshots(evaluations, "ABC", trades[-1].stamp.event_ns, calendar())
    for ordering in permutations(evaluations):
        assert detect_bursts(ordering, calendar()) == expected_bursts
        assert (
            tilt_snapshots(ordering, "ABC", trades[-1].stamp.event_ns, calendar()) == expected_tilt
        )


def test_burst_strike_identity_requires_versioned_adjacent_ladder() -> None:
    trades = tuple(
        replace(
            option(str(i), event_ns=OPEN + 1_000_000_000 + i * 1_000_000_000),
            strike=Decimal(str(strike)),
        )
        for i, strike in enumerate((100, 105, 110))
    )
    evaluations = tuple(evaluate_flow(t, calendar(), underlying=underlying()) for t in trades)
    policy = BurstPolicy(min_count=3, min_notional=Decimal("1000000"))
    assert detect_bursts(evaluations, calendar(), policy) == ()
    ladder = StrikeLadder("v1", "ABC", trades[0].expiry, tuple(t.strike for t in trades))
    expected = detect_bursts(evaluations, calendar(), policy, strike_ladders=(ladder,))
    assert len(expected) == 1
    assert expected[0].strikes == (Decimal("100"), Decimal("105"), Decimal("110"))
    assert expected[0].strike_ladder_version == "v1"
    for ordering in permutations(evaluations):
        assert detect_bursts(ordering, calendar(), policy, strike_ladders=(ladder,)) == expected
    assert (
        detect_bursts(
            (evaluations[0], evaluations[2]),
            calendar(),
            policy,
            strike_ladders=(ladder,),
        )
        == ()
    )
    with pytest.raises(FlowError):
        replace(ladder, strikes=(Decimal("105"), Decimal("100")))
    with pytest.raises(FlowError):
        detect_bursts(evaluations, calendar(), policy, strike_ladders=(ladder, ladder))


def test_exact_premium_arithmetic_and_policy_replace() -> None:
    trade = replace(
        option(),
        price=Decimal("1.000000000000000000000000000000001"),
        multiplier=Decimal("11"),
    )
    with pytest.raises(FlowError, match="PRECISION_EXCEEDED"):
        evaluate_flow(trade, calendar(), underlying=underlying())
    with pytest.raises(FlowError, match="POLICY_OUT_OF_BOUNDS"):
        replace(FilterPolicy(), aggression_threshold=Decimal("0.79"))
    with pytest.raises(FlowError, match="POLICY_OUT_OF_BOUNDS"):
        replace(BurstPolicy(), window_ns=8_000_000_001)


def test_future_available_records_never_change_earlier_tilt_bytes() -> None:
    base = option("point-in-time")
    as_of_ns = base.stamp.event_ns
    base_evaluation = evaluate_flow(base, calendar(), underlying=underlying())
    baseline = repr(tilt_snapshots((base_evaluation,), "ABC", as_of_ns, calendar())).encode()
    rng = Random(0xF1001)

    for trial in range(40):
        correction = replace(
            base,
            stamp=replace(
                base.stamp,
                available_ns=as_of_ns + rng.randint(1, 1_000_000_000),
                correction_of=base.record_id,
            ),
            price=Decimal(str(rng.randint(3, 9))),
        )
        future = [
            evaluate_flow(correction, calendar(), underlying=underlying()),
        ]
        for offset in range(rng.randrange(4)):
            unrelated = option(f"future-{trial}-{offset}")
            unrelated = replace(
                unrelated,
                stamp=replace(
                    unrelated.stamp,
                    available_ns=as_of_ns + rng.randint(1, 1_000_000_000),
                ),
            )
            future.append(evaluate_flow(unrelated, calendar(), underlying=underlying()))
        rng.shuffle(future)
        insertion = rng.randrange(len(future) + 1)
        observations = (*future[:insertion], base_evaluation, *future[insertion:])
        actual = repr(tilt_snapshots(observations, "ABC", as_of_ns, calendar())).encode()
        assert actual == baseline, f"future insertion changed as-of snapshot in trial {trial}"

    visible_correction = replace(
        base,
        stamp=replace(
            base.stamp,
            available_ns=as_of_ns + 1,
            correction_of=base.record_id,
        ),
        price=Decimal("3"),
    )
    corrected = evaluate_flow(visible_correction, calendar(), underlying=underlying())
    visible = tilt_snapshots((base_evaluation, corrected), "ABC", as_of_ns + 1, calendar())
    assert visible[0].call_notional == Decimal("30000")
