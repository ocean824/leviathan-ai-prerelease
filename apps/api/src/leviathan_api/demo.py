"""Canonical NQ opening-range-break demo payloads.

Mirrors packages/leviathan-core/tests/fixtures/replay_nq_breakout.json —
the module-map handoff fixture — so the operator terminal can run the
full pipeline end-to-end before any live data provider is configured.
"""

from datetime import UTC, datetime, timedelta
from decimal import Decimal

from leviathan_core.schemas import (
    Bar,
    CandidateSetup,
    EventRisk,
    MarketState,
    OrderbookBias,
    RequiredStream,
    StrategyGenome,
    StreamFreshness,
    TruthStatus,
    TruthValidationResult,
)

DEMO_SETUP = CandidateSetup(
    setup_id="setup_demo_nq_orb",
    instrument="NQ",
    timestamp=datetime(2026, 4, 15, 14, 35, tzinfo=UTC),
    signal_features=("msb_up", "opening_range_break", "ema_alignment"),
    session_label="ny_open",
    range_label="above_opening_range_high",
    state_label=MarketState.BREAKOUT,
    liquidity_features=("equal_highs_swept", "inefficiency_below"),
)

DEMO_GENOME = StrategyGenome(
    strategy_id="genome_nq_opening_range_break_v1",
    family="opening_range_break",
    market="NQ",
    timeframe="1m-5m",
    session_dependencies=("ny_open", "ny_overlap"),
    state_dependencies=(MarketState.BREAKOUT, MarketState.TREND_CONTINUATION),
    entry_conditions=("opening range defined", "structure break above ORH", "sweep complete"),
    exit_conditions=("2R achieved", "failed acceptance back inside range"),
    risk_profile="moderate_intraday",
    failure_modes=("fake breakout", "news reversal"),
)

DEMO_TRUTH = TruthValidationResult(
    setup_id=DEMO_SETUP.setup_id,
    orderbook_bias=OrderbookBias.BULLISH,
    options_context="No large bearish sweep detected in near-dated contracts.",
    event_risk=EventRisk.SAFE,
    sentiment_modifier=0.07,
    truth_status=TruthStatus.CONFIRMED,
    notes="Aggressive buyers lifted the offer after the sweep.",
)

_OHLC = (
    ("18250", "18258", "18246", "18255"),
    ("18255", "18262", "18248", "18260"),
    ("18260", "18266", "18255", "18264"),
    ("18264", "18272", "18260", "18270"),
)

DEMO_BARS: tuple[Bar, ...] = tuple(
    Bar(
        instrument="NQ",
        timestamp=DEMO_SETUP.timestamp + timedelta(minutes=i),
        open=Decimal(o),
        high=Decimal(h),
        low=Decimal(lo),
        close=Decimal(c),
        volume=Decimal(1000),
    )
    for i, (o, h, lo, c) in enumerate(_OHLC)
)

DEMO_STOP = Decimal("18240")
DEMO_TARGET = Decimal("18270")
DEMO_REQUIRED_STREAMS = (
    RequiredStream(stream_id="bars.1m", symbol="NQ", provider="demo"),
)
DEMO_STREAM_FRESHNESS = (
    StreamFreshness(
        stream_id="bars.1m",
        symbol="NQ",
        provider="demo",
        source_ts=DEMO_BARS[-1].timestamp,
        exchange_ts=DEMO_BARS[-1].timestamp,
        received_at=DEMO_BARS[-1].timestamp,
    ),
)
