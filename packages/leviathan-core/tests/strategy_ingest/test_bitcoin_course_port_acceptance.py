"""Independent source-parity and safety acceptance for the Bitcoin course port."""

from __future__ import annotations

import ast
import inspect
from decimal import ROUND_CEILING, ROUND_FLOOR, Decimal, localcontext
from pathlib import Path

import pytest

from leviathan_core.numeric._context import numeric_context
from leviathan_core.strategy_ingest.library.asset_recovery.bitcoin_course_strategies import (
    BitcoinCourseStrategyError,
    CourseBarV1,
    CourseSignalV1,
    CourseStrategyConfigV1,
    generate_course_signals,
    run_course_backtest,
)
from leviathan_core.strategy_ingest.library.asset_recovery.bitcoin_hft_mm import (
    HftMarketMakerConfigV1,
    HftMarketMakerError,
    build_hft_mm_quote,
)
from leviathan_market_data.live.book_cache import (
    BookCache,
    BookKeyV1,
    BookSnapshotReceiptV1,
    is_issued_book_snapshot_receipt,
)
from leviathan_market_data.normalization import Normalizer, VendorRecord
from leviathan_market_data.schema import NormalizedMarketEventV1
from leviathan_market_data.symbology import InstrumentMapping, MappingRegistry

BASE_NS = 1_780_000_000_000_000_000
PROVIDER = "databento"
DATASET = "mbp-10"
VENUE = "XNAS"
NATIVE_SYMBOL = "BTC-USD"
INSTRUMENT_ID = "synthetic-btc-usd"
SESSION = "synthetic-live-session"


def _bar(timestamp_ns: int, close: str) -> CourseBarV1:
    price = Decimal(close)
    return CourseBarV1(
        timestamp_ns=timestamp_ns,
        open=price,
        high=price,
        low=price,
        close=price,
        volume=Decimal("10"),
    )


def _normalized_book(
    *,
    sequence: int,
    event_time_ns: int,
    bid: str = "99.99",
    bid_size: str = "10",
    ask: str = "100.01",
    ask_size: str = "10",
    provider: str = PROVIDER,
    source_mode: str = "live",
    quality_flags: tuple[str, ...] = (),
) -> NormalizedMarketEventV1:
    mapping = InstrumentMapping(
        provider=provider,
        dataset=DATASET,
        venue=VENUE,
        native_symbol=NATIVE_SYMBOL,
        instrument_id=INSTRUMENT_ID,
        leviathan_symbol="BTCUSD",
        instrument_type="crypto",
        mapping_version="synthetic-map-v1",
        tick_size="0.01",
    )
    record = VendorRecord(
        provider=provider,
        dataset=DATASET,
        venue=VENUE,
        native_symbol=NATIVE_SYMBOL,
        channel="l2",
        event_type="book_snapshot",
        event_time_ns=event_time_ns,
        source_record_ref=f"synthetic://book/{sequence}",
        payload={
            "levels": [
                {"side": "bid", "price": bid, "size": bid_size, "level": 0},
                {"side": "ask", "price": ask, "size": ask_size, "level": 0},
            ]
        },
        source_mode=source_mode,  # type: ignore[arg-type]
        source_time_ns=event_time_ns,
        exchange_time_ns=event_time_ns,
        native_sequence=sequence,
        source_record_key=f"synthetic-book-key-{sequence}",
        ingest_time_ns=event_time_ns + 1,
        received_time_ns=event_time_ns + 1,
        processing_time_ns=event_time_ns + 2,
        quality_flags=quality_flags,
        provider_session_id=SESSION,
    )
    normalizer = Normalizer(MappingRegistry((mapping,)))
    return normalizer.normalize(record, now_ns=event_time_ns + 1_000_000)


def _book_history_and_receipt(
    *,
    sequence_pair: tuple[int, int] = (500, 501),
    second_flags: tuple[str, ...] = (),
    provider: str = PROVIDER,
    ttl_ns: int = 5_000_000_000,
) -> tuple[tuple[NormalizedMarketEventV1, ...], BookSnapshotReceiptV1, int]:
    first_sequence, second_sequence = sequence_pair
    events = (
        _normalized_book(sequence=first_sequence, event_time_ns=BASE_NS),
        _normalized_book(
            sequence=second_sequence,
            event_time_ns=BASE_NS + 1_000,
            bid="100.00",
            bid_size="12",
            ask="100.02",
            ask_size="8",
            provider=provider,
            quality_flags=second_flags,
        ),
    )
    cache = BookCache(ttl_ns=ttl_ns)
    for event in events:
        applied = cache.apply(event)
        assert applied.status == "APPLIED"
    key = BookKeyV1(
        provider=provider,
        dataset=DATASET,
        venue=VENUE,
        instrument_id=INSTRUMENT_ID,
    )
    receipt = cache.snapshot(key, now_ns=events[-1].event_time_ns + 1)
    assert is_issued_book_snapshot_receipt(receipt)
    return events, receipt, events[-1].event_time_ns + 500_001


def _quote_config(**overrides: object) -> HftMarketMakerConfigV1:
    values: dict[str, object] = {
        "gamma": Decimal("0.1"),
        "k": Decimal("15"),
        "ofi_beta": Decimal("0.5"),
        "max_inventory": Decimal("10"),
        "quote_size": Decimal("2"),
        "min_spread": Decimal("0.0001"),
        "max_spread": Decimal("0.2"),
        "tick_size": Decimal("0.05"),
        "fee_rate": Decimal("0.0001"),
        "latency_penalty_per_second": Decimal("0.05"),
        "half_life_ticks": Decimal("50"),
        "min_volatility": Decimal("0.0001"),
        "max_book_age_ns": 1_000_000,
        "max_latency_ns": 1_000_000,
        "max_history": 10,
    }
    values.update(overrides)
    return HftMarketMakerConfigV1(**values)  # type: ignore[arg-type]


def _within(actual: Decimal, expected: Decimal) -> None:
    assert abs(actual - expected) < Decimal("1e-25")


def test_course_backtest_matches_source_one_bar_lag_and_fee_math() -> None:
    bars = (_bar(BASE_NS, "100"), _bar(BASE_NS + 1, "110"), _bar(BASE_NS + 2, "99"))
    signals = tuple(
        CourseSignalV1(
            strategy_id="momentum",
            label="synthetic test signal",
            timestamp_ns=bar.timestamp_ns,
            signal=signal,  # type: ignore[arg-type]
        )
        for bar, signal in zip(bars, (1, -1, 0), strict=True)
    )

    points = run_course_backtest(
        bars,
        signals,
        initial_capital=Decimal("100000"),
        commission=Decimal("0.001"),
    )

    assert [point.lagged_position for point in points] == [0, 1, -1]
    assert [point.gross_return for point in points] == [
        Decimal("0"),
        Decimal("0.1"),
        Decimal("0.1"),
    ]
    assert [point.commission_cost for point in points] == [
        Decimal("0"),
        Decimal("0.001"),
        Decimal("0.002"),
    ]
    assert [point.net_return for point in points] == [
        Decimal("0"),
        Decimal("0.099"),
        Decimal("0.098"),
    ]
    assert points[1].equity == Decimal("100000") * Decimal("1.099")
    assert points[2].equity == points[1].equity * Decimal("1.098")


def test_course_strategy_proxy_labels_are_explicit_and_not_overclaimed() -> None:
    bars = tuple(_bar(BASE_NS + index, str(100 + index)) for index in range(40))
    expected_labels = {
        "volatility_percentile_regime_proxy": "not HMM",
        "signed_volume_order_flow_proxy": "not an order book",
        "single_series_pairs_proxy": "not cointegration",
        "ohlc_market_making_proxy": "not L2 market making",
    }

    for strategy_id, phrase in expected_labels.items():
        signals = generate_course_signals(strategy_id, bars)
        assert len(signals) == len(bars)
        assert all(item.strategy_id == strategy_id for item in signals)
        assert all(phrase in item.label for item in signals)

    with pytest.raises(BitcoinCourseStrategyError) as unknown:
        generate_course_signals("hmm", bars)  # type: ignore[arg-type]
    assert unknown.value.code == "INVALID_STRATEGY"
    assert "hmm" not in str(unknown.value)


def test_course_configuration_preserves_source_strategy_defaults() -> None:
    config = CourseStrategyConfigV1()
    assert config.momentum_lookback == 20
    assert config.momentum_threshold == Decimal("0.02")
    assert config.regime_lookback == 20
    assert config.regime_percentile_window == 100
    assert config.order_flow_lookback == 10
    assert config.order_flow_threshold == Decimal("0.6")
    assert config.pairs_lookback == 20
    assert config.pairs_entry_z == Decimal("2")
    assert config.market_making_gamma == Decimal("0.1")
    assert config.market_making_k == Decimal("1.5")


def test_every_ported_course_strategy_returns_time_aligned_closed_signals() -> None:
    strategy_ids = (
        "momentum",
        "mean_reversion",
        "vwap",
        "kalman_trend",
        "volatility_percentile_regime_proxy",
        "signed_volume_order_flow_proxy",
        "spread_decomposition",
        "volatility_term_structure",
        "single_series_pairs_proxy",
        "ohlc_market_making_proxy",
    )
    bars = tuple(_bar(BASE_NS + index, str(100 + index)) for index in range(40))

    for strategy_id in strategy_ids:
        signals = generate_course_signals(strategy_id, bars)  # type: ignore[arg-type]
        assert len(signals) == len(bars)
        assert tuple(item.timestamp_ns for item in signals) == tuple(
            bar.timestamp_ns for bar in bars
        )
        assert all(item.strategy_id == strategy_id for item in signals)
        assert all(item.signal in {-1, 0, 1} and item.label for item in signals)


def test_hft_formula_matches_cpp_core_blend_spread_cost_and_tick_rounding() -> None:
    history, receipt, now_ns = _book_history_and_receipt()
    config = _quote_config()
    inventory = Decimal("4")

    quote = build_hft_mm_quote(history, receipt, inventory=inventory, now_ns=now_ns, config=config)

    mid = Decimal("100.01")
    microprice = (Decimal("100.02") * 12 + Decimal("100.00") * 8) / 20
    # A bid price increase contributes current bid size; an ask price increase
    # contributes previous ask size under the source's top-of-book OFI rule.
    ofi = Decimal("1.1")
    previous_mid = Decimal("100")
    return_fraction = mid / previous_mid - Decimal("1")
    alpha = (
        Decimal("1")
        - (-Decimal("0.6931471805599453094172321214581766") / config.half_life_ticks).exp()
    )
    variance = max(
        config.min_volatility * config.min_volatility,
        alpha * return_fraction * return_fraction,
    )
    age_ns = now_ns - history[-1].event_time_ns
    with localcontext(numeric_context(final_quotient=True)):
        sigma = variance.sqrt()
        reservation_raw = mid - inventory * config.gamma * variance + config.ofi_beta * ofi * sigma
        reservation = Decimal("0.7") * reservation_raw + Decimal("0.3") * microprice
        cpp_half_spread = (Decimal("1") / config.gamma) * (
            Decimal("1") + config.gamma / config.k
        ).ln()
        cpp_half_spread += config.gamma * variance
        fee_padding = mid * config.fee_rate
        latency_padding = (
            mid * config.latency_penalty_per_second * Decimal(age_ns) / Decimal("1000000000")
        )
        half_spread = max(
            mid * config.min_spread / 2,
            cpp_half_spread + fee_padding + latency_padding,
        )
        skew = inventory / config.max_inventory * half_spread * Decimal("0.5")
        raw_bid = reservation - half_spread - skew
        raw_ask = reservation + half_spread - skew
        expected_bid = (raw_bid / config.tick_size).to_integral_value(
            rounding=ROUND_FLOOR
        ) * config.tick_size
        expected_ask = (raw_ask / config.tick_size).to_integral_value(
            rounding=ROUND_CEILING
        ) * config.tick_size

    assert quote.mid_price == mid
    assert quote.microprice == microprice
    _within(quote.sigma, sigma)
    _within(quote.l2_ofi, ofi)
    _within(quote.reservation_price, reservation)
    _within(quote.half_spread, half_spread)
    assert quote.fee_padding == fee_padding
    assert quote.latency_padding == latency_padding
    assert quote.bid_price == expected_bid
    assert quote.ask_price == expected_ask
    assert quote.bid_price % config.tick_size == 0
    assert quote.ask_price % config.tick_size == 0
    assert quote.bid_price <= raw_bid
    assert quote.ask_price >= raw_ask
    assert quote.asof_ns == history[-1].event_time_ns
    assert quote.age_ns == age_ns
    assert quote.native_sequence == history[-1].native_sequence
    assert quote.provider == PROVIDER
    assert quote.disposition == "QUOTE_ONLY"


def test_hft_inventory_skew_and_inventory_cap_are_enforced() -> None:
    history, receipt, now_ns = _book_history_and_receipt()
    config = _quote_config(tick_size=Decimal("0.00001"))
    flat = build_hft_mm_quote(
        history, receipt, inventory=Decimal("0"), now_ns=now_ns, config=config
    )
    long = build_hft_mm_quote(
        history, receipt, inventory=Decimal("4"), now_ns=now_ns, config=config
    )
    assert long.reservation_price < flat.reservation_price
    assert long.bid_price < flat.bid_price
    assert long.ask_price < flat.ask_price

    at_cap = build_hft_mm_quote(
        history, receipt, inventory=config.max_inventory, now_ns=now_ns, config=config
    )
    assert at_cap.bid_quantity == 0
    assert at_cap.ask_quantity == config.quote_size
    with pytest.raises(HftMarketMakerError) as over_cap:
        build_hft_mm_quote(
            history,
            receipt,
            inventory=config.max_inventory + Decimal("0.01"),
            now_ns=now_ns,
            config=config,
        )
    assert over_cap.value.code == "INVALID_INVENTORY"


def test_hft_minimum_spread_floor_is_applied() -> None:
    history, receipt, now_ns = _book_history_and_receipt()
    config = _quote_config(min_spread=Decimal("0.02"))
    quote = build_hft_mm_quote(
        history, receipt, inventory=Decimal("0"), now_ns=now_ns, config=config
    )
    assert quote.half_spread == quote.mid_price * config.min_spread / 2


def test_hft_computed_spread_above_max_fails_closed_without_quote() -> None:
    """Coordinator ruling: above-max spreads deny, diverging from C++ clamp behavior."""
    history, receipt, now_ns = _book_history_and_receipt()
    config = _quote_config(max_spread=Decimal("0.001"), tick_size=Decimal("0.01"))
    with pytest.raises(HftMarketMakerError) as denied:
        build_hft_mm_quote(
            history,
            receipt,
            inventory=Decimal("0"),
            now_ns=now_ns,
            config=config,
        )
    assert denied.value.code == "SPREAD_LIMIT_CONFLICT"
    assert "SPREAD_LIMIT_CONFLICT" in str(denied.value)


def test_hft_requires_real_normalized_l2_not_signed_volume_or_trade_data() -> None:
    _history, receipt, now_ns = _book_history_and_receipt()
    mapping = InstrumentMapping(
        provider=PROVIDER,
        dataset=DATASET,
        venue=VENUE,
        native_symbol=NATIVE_SYMBOL,
        instrument_id=INSTRUMENT_ID,
        leviathan_symbol="BTCUSD",
        instrument_type="crypto",
        mapping_version="synthetic-map-v1",
        tick_size="0.01",
    )
    trade_record = VendorRecord(
        provider=PROVIDER,
        dataset=DATASET,
        venue=VENUE,
        native_symbol=NATIVE_SYMBOL,
        channel="trades",
        event_type="trade",
        event_time_ns=BASE_NS,
        source_record_ref="synthetic://trade/500",
        payload={"price": "100.00", "size": "5", "side": "buy"},
        source_mode="live",
        source_time_ns=BASE_NS,
        exchange_time_ns=BASE_NS,
        native_sequence=500,
        source_record_key="synthetic-trade-key-500",
        provider_session_id=SESSION,
    )
    trade = Normalizer(MappingRegistry((mapping,))).normalize(
        trade_record, now_ns=BASE_NS + 1_000_000
    )

    with pytest.raises(HftMarketMakerError) as rejected:
        build_hft_mm_quote((trade, trade), receipt, inventory=Decimal("0"), now_ns=now_ns)
    assert rejected.value.code == "L2_PROVIDER_REQUIRED"
    assert "synthetic://trade/500" not in str(rejected.value)


def test_hft_denies_sequence_gaps_stale_books_and_bad_quality() -> None:
    gap_history, gap_receipt, gap_now = _book_history_and_receipt(sequence_pair=(500, 502))
    with pytest.raises(HftMarketMakerError) as gap:
        build_hft_mm_quote(gap_history, gap_receipt, inventory=Decimal("0"), now_ns=gap_now)
    assert gap.value.code == "L2_SEQUENCE_GAP"

    stale_history, stale_receipt, _ = _book_history_and_receipt()
    stale_config = _quote_config(max_book_age_ns=1_000_000, max_latency_ns=1_000_000)
    stale_now = stale_history[-1].event_time_ns + 1_000_001
    with pytest.raises(HftMarketMakerError) as stale:
        build_hft_mm_quote(
            stale_history,
            stale_receipt,
            inventory=Decimal("0"),
            now_ns=stale_now,
            config=stale_config,
        )
    assert stale.value.code == "L2_BOOK_STALE"

    bad_history, bad_receipt, bad_now = _book_history_and_receipt(second_flags=("GAP",))
    with pytest.raises(HftMarketMakerError) as bad_quality:
        build_hft_mm_quote(bad_history, bad_receipt, inventory=Decimal("0"), now_ns=bad_now)
    assert bad_quality.value.code == "L2_PROVIDER_REQUIRED"


def test_hft_source_documents_comment_code_formula_discrepancy() -> None:
    import leviathan_core.strategy_ingest.library.asset_recovery.bitcoin_hft_mm as module

    module_doc = inspect.getdoc(module) or ""
    normalized = module_doc.lower().replace("—", "-")
    assert "hft_mm.cpp" in normalized
    assert "910" in normalized and "915" in normalized
    assert "2/gamma" in normalized and "1/gamma" in normalized
    assert "b33b15a2b8d55ff42e21c0bec89496c3672c12edd7490175426c22bb6468990d" in normalized
    assert "4b993bdb3c841d114b4a02c92498cecf8091ebd9d1c04d0c465618502fe04dc3" in normalized
    assert "comment" in normalized and "executable" in normalized


def test_hft_module_has_no_direct_order_or_execution_calls() -> None:
    import leviathan_core.strategy_ingest.library.asset_recovery.bitcoin_hft_mm as module

    source_path = Path(inspect.getsourcefile(module) or "")
    syntax = ast.parse(source_path.read_text(encoding="utf-8"))
    imports = {
        alias.name
        for node in ast.walk(syntax)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imports.update(
        node.module
        for node in ast.walk(syntax)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    )
    assert not any(
        "execution" in name or "broker" in name or "oms" in name or "risk" in name
        for name in imports
    )
    forbidden_calls = {
        "submit_order",
        "place_order",
        "send_order",
        "cancel_order",
        "route_order",
        "create_order",
    }
    calls = {
        node.func.attr
        for node in ast.walk(syntax)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert not calls.intersection(forbidden_calls)
    assert "quote proposal" in (inspect.getdoc(module) or "").lower()
