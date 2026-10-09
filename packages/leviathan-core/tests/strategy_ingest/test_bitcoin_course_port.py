from __future__ import annotations

import copy
import pickle
from decimal import Decimal, localcontext
from hashlib import sha256

import pytest

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
from leviathan_market_data.live.book_cache import BookCache, BookKeyV1
from leviathan_market_data.schema import (
    BookLevel,
    BookSnapshotPayload,
    NormalizedMarketEventV1,
    PriceValue,
    TradePayload,
)

_BASE_NS = 1_780_000_000_000_000_000
_PROVIDER = "databento"
_DATASET = "mbp-10"
_VENUE = "XTEST"
_INSTRUMENT = "BTC-USD"
_SESSION = "paper-session"


def _bar(index: int, close: str, *, volume: str = "10") -> CourseBarV1:
    value = Decimal(close)
    return CourseBarV1(
        timestamp_ns=_BASE_NS + index,
        open=value,
        high=value + Decimal("1"),
        low=value - Decimal("1"),
        close=value,
        volume=Decimal(volume),
    )


def _levels(bid: str, bid_size: str, ask: str, ask_size: str) -> BookSnapshotPayload:
    return BookSnapshotPayload(
        levels=(
            BookLevel(side="bid", price=PriceValue(value=bid), size=bid_size),
            BookLevel(side="ask", price=PriceValue(value=ask), size=ask_size),
        )
    )


def _book_event(
    sequence: int,
    payload: BookSnapshotPayload | TradePayload,
    *,
    at_ns: int | None = None,
) -> NormalizedMarketEventV1:
    timestamp = _BASE_NS + sequence if at_ns is None else at_ns
    return NormalizedMarketEventV1(
        event_id=f"00000000-0000-0000-0000-{sequence:012d}",
        provider=_PROVIDER,
        dataset=_DATASET,
        venue=_VENUE,
        native_symbol="BTCUSD",
        leviathan_symbol="BTCUSD",
        instrument_id=_INSTRUMENT,
        instrument_type="crypto",
        channel="l2" if payload.kind == "book_snapshot" else "trade",
        event_type=payload.kind,
        source_mode="live",
        event_time_ns=timestamp,
        source_time_ns=timestamp,
        exchange_time_ns=timestamp,
        ingest_time_ns=timestamp,
        processing_time_ns=timestamp,
        received_time_ns=timestamp,
        native_sequence=sequence,
        sequence_synthetic=False,
        native_trade_id=None,
        source_record_key=f"record-{sequence}",
        provider_session_id=_SESSION,
        source_record_ref=f"databento://fixture/{sequence}",
        source_payload_sha256=sha256(f"payload-{sequence}".encode()).hexdigest(),
        mapping_version="mapping/1",
        identity_policy_version="identity/1",
        quality_flags=(),
        reconstructed=False,
        idempotency_key=f"event-{sequence}",
        payload=payload,
    )


def _two_book_history(
    *,
    first_sequence: int = 40,
    second_sequence: int = 41,
    first: BookSnapshotPayload | None = None,
    second: BookSnapshotPayload | None = None,
) -> tuple[tuple[NormalizedMarketEventV1, ...], object]:
    previous = _book_event(
        first_sequence,
        first or _levels("99", "2", "101", "4"),
        at_ns=_BASE_NS + 10_000,
    )
    current = _book_event(
        second_sequence,
        second or _levels("100", "3", "102", "5"),
        at_ns=_BASE_NS + 10_100,
    )
    cache = BookCache(ttl_ns=1_000_000)
    assert cache.apply(previous).coherent
    assert cache.apply(current).coherent
    key = BookKeyV1(
        provider=_PROVIDER,
        dataset=_DATASET,
        venue=_VENUE,
        instrument_id=_INSTRUMENT,
    )
    receipt = cache.snapshot(key, now_ns=current.event_time_ns + 1)
    return (previous, current), receipt


def test_all_course_strategies_have_explicit_labels_and_deterministic_outputs() -> None:
    bars = tuple(_bar(i, str(100 + i % 9), volume=str(5 + i % 4)) for i in range(160))
    strategies = (
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
    outputs = {strategy: generate_course_signals(strategy, bars) for strategy in strategies}
    assert all(len(value) == len(bars) for value in outputs.values())
    assert outputs["volatility_percentile_regime_proxy"][0].label == (
        "volatility-percentile regime proxy (not HMM)"
    )
    assert outputs["signed_volume_order_flow_proxy"][0].label == (
        "signed-volume order-flow proxy (not an order book)"
    )
    assert outputs["single_series_pairs_proxy"][0].label == (
        "single-series moving-average proxy (not cointegration)"
    )
    assert outputs == {strategy: generate_course_signals(strategy, bars) for strategy in strategies}


def test_course_strategy_rejects_unordered_bars_and_bad_decimal_inputs() -> None:
    with pytest.raises(BitcoinCourseStrategyError):
        CourseBarV1(_BASE_NS, Decimal("1"), Decimal("1"), Decimal("1"), Decimal("1"), 0.1)  # type: ignore[arg-type]
    bars = (_bar(2, "100"), _bar(1, "101"))
    with pytest.raises(BitcoinCourseStrategyError, match="INVALID_BAR"):
        generate_course_signals("momentum", bars)


def test_course_backtest_lags_positions_and_charges_commission_on_changes() -> None:
    bars = (_bar(0, "100"), _bar(1, "110"), _bar(2, "99"))
    signals = tuple(
        CourseSignalV1(
            strategy_id="momentum", label="test", timestamp_ns=bar.timestamp_ns, signal=value
        )
        for bar, value in zip(bars, (1, -1, 0), strict=True)
    )
    result = run_course_backtest(bars, signals, commission=Decimal("0.001"))
    assert tuple(row.lagged_position for row in result) == (0, 1, -1)
    assert tuple(row.commission_cost for row in result) == (
        Decimal("0"),
        Decimal("0.001"),
        Decimal("0.002"),
    )
    assert result[1].gross_return == Decimal("0.1")
    assert result[1].net_return == Decimal("0.099")


def test_public_course_values_are_frozen_and_decimal_context_independent() -> None:
    bar = _bar(0, "100.00")
    with pytest.raises((TypeError, BitcoinCourseStrategyError)):
        copy.copy(bar)
    with pytest.raises((TypeError, BitcoinCourseStrategyError)):
        pickle.dumps(bar)
    bars = tuple(_bar(i, str(100 + i)) for i in range(50))
    with localcontext() as context:
        context.prec = 5
        low_precision = generate_course_signals("momentum", bars)
    with localcontext() as context:
        context.prec = 50
        high_precision = generate_course_signals("momentum", bars)
    assert low_precision == high_precision
    with pytest.raises(BitcoinCourseStrategyError):
        CourseStrategyConfigV1(momentum_lookback=True)  # type: ignore[arg-type]


def test_hft_market_maker_uses_coherent_l2_costs_and_inventory_caps() -> None:
    history, receipt = _two_book_history()
    result = build_hft_mm_quote(
        history,
        receipt,  # type: ignore[arg-type]
        inventory=Decimal("99.5"),
        now_ns=_BASE_NS + 10_101,
    )
    assert result.disposition == "QUOTE_ONLY"
    assert result.bid_quantity == Decimal("0.5")
    assert result.ask_quantity == Decimal("1")
    assert result.l2_ofi > 0
    assert result.fee_padding > 0
    assert result.latency_padding > 0
    assert result.age_ns == 1
    assert result.bid_price < result.ask_price
    assert result.bid_price % Decimal("0.01") == 0
    assert result.ask_price % Decimal("0.01") == 0


def test_hft_market_maker_rejects_signed_volume_stale_gapped_and_unissued_books() -> None:
    history, receipt = _two_book_history()
    with pytest.raises(HftMarketMakerError, match="L2_BOOK_STALE"):
        build_hft_mm_quote(history, receipt, inventory=Decimal("0"), now_ns=_BASE_NS + 10_000_000)  # type: ignore[arg-type]
    gap_history, gap_receipt = _two_book_history(first_sequence=40, second_sequence=42)
    with pytest.raises(HftMarketMakerError, match="L2_SEQUENCE_GAP"):
        build_hft_mm_quote(
            gap_history, gap_receipt, inventory=Decimal("0"), now_ns=_BASE_NS + 10_101
        )  # type: ignore[arg-type]
    current = history[-1]
    trade = TradePayload(price=PriceValue(value="101"), size="1", side="buy")
    volume_only = _book_event(42, trade, at_ns=current.event_time_ns + 1)
    bad_receipt = type(receipt)(
        coherent=True,
        snapshot=receipt.snapshot,
        reason="HEALTHY",
        updated_time_ns=current.event_time_ns,
        eviction_count=0,
    )
    with pytest.raises(HftMarketMakerError, match="L2_PROVIDER_REQUIRED"):
        build_hft_mm_quote(
            (history[-2], volume_only),
            bad_receipt,
            inventory=Decimal("0"),
            now_ns=current.event_time_ns + 2,
        )  # type: ignore[arg-type]
    with pytest.raises(HftMarketMakerError, match="L2_BOOK_GAP"):
        build_hft_mm_quote(
            history, bad_receipt, inventory=Decimal("0"), now_ns=current.event_time_ns + 2
        )


def test_hft_market_maker_denies_cost_adjusted_spread_above_configured_cap() -> None:
    history, receipt = _two_book_history()
    config = HftMarketMakerConfigV1(
        fee_rate=Decimal("0.009"),
        latency_penalty_per_second=Decimal("1000000"),
        max_latency_ns=1_000_000,
    )
    with pytest.raises(HftMarketMakerError, match="SPREAD_LIMIT_CONFLICT"):
        build_hft_mm_quote(
            history,
            receipt,  # type: ignore[arg-type]
            inventory=Decimal("0"),
            now_ns=_BASE_NS + 10_100 + 999_999,
            config=config,
        )


def test_hft_market_maker_rejects_inventory_outside_cap() -> None:
    history, receipt = _two_book_history()
    with pytest.raises(HftMarketMakerError, match="INVALID_INVENTORY"):
        build_hft_mm_quote(
            history,
            receipt,  # type: ignore[arg-type]
            inventory=Decimal("100.01"),
            now_ns=_BASE_NS + 10_101,
        )
