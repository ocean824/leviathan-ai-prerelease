"""Tests for Research Domain: InMemoryGenomeStore, RbiStage, RbiGate."""

from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest

from leviathan_core.research import BacktestMetrics, InMemoryGenomeStore, RbiGate, RbiStage
from leviathan_core.schemas import StrategyGenome
from leviathan_core.schemas.enums import MarketState

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_NOW = datetime(2026, 4, 15, 14, 0, 0, tzinfo=UTC)


def _genome(strategy_id: str = "genome_test_001") -> StrategyGenome:
    return StrategyGenome(
        strategy_id=strategy_id,
        family="opening_range_break",
        market="NQ",
        timeframe="5m",
        risk_profile="moderate_intraday",
        state_dependencies=(MarketState.BREAKOUT,),
        entry_conditions=("structure break above range high",),
        exit_conditions=("2R achieved",),
    )


def _passing_metrics() -> BacktestMetrics:
    return BacktestMetrics(
        sharpe=Decimal("2.1"),
        max_dd_pct=Decimal("8.5"),
        win_rate_pct=Decimal("58.0"),
        profit_factor=Decimal("2.2"),
        trades=250,
    )


# ---------------------------------------------------------------------------
# RbiStage enum
# ---------------------------------------------------------------------------


def test_rbi_stage_values_exist() -> None:
    assert RbiStage.RESEARCH == "research"
    assert RbiStage.BACKTEST_INITIAL == "backtest_initial"
    assert RbiStage.BACKTEST_MONTE_CARLO == "backtest_monte_carlo"
    assert RbiStage.BACKTEST_WALK_FORWARD == "backtest_walk_forward"
    assert RbiStage.BACKTEST_REGIME == "backtest_regime"
    assert RbiStage.PAPER_TRADE == "paper_trade"
    assert RbiStage.DEPLOYED == "deployed"


def test_rbi_stage_is_str_enum() -> None:
    assert isinstance(RbiStage.RESEARCH, str)


# ---------------------------------------------------------------------------
# RbiGate — passing case
# ---------------------------------------------------------------------------


def test_rbi_gate_passes_with_all_metrics_above_thresholds() -> None:
    gate = RbiGate()
    passed, failures = gate.check(_passing_metrics())
    assert passed is True
    assert failures == []


# ---------------------------------------------------------------------------
# RbiGate — individual failure cases (named)
# ---------------------------------------------------------------------------


def test_rbi_gate_fails_sharpe_too_low() -> None:
    gate = RbiGate()
    metrics = BacktestMetrics(
        sharpe=Decimal("1.5"),  # exactly at threshold, not above
        max_dd_pct=Decimal("8.0"),
        win_rate_pct=Decimal("57.0"),
        profit_factor=Decimal("1.7"),
        trades=200,
    )
    passed, failures = gate.check(metrics)
    assert passed is False
    assert any("sharpe" in f for f in failures)


def test_rbi_gate_fails_max_dd_too_high() -> None:
    gate = RbiGate()
    metrics = BacktestMetrics(
        sharpe=Decimal("2.0"),
        max_dd_pct=Decimal("15.0"),  # exactly at limit, not below
        win_rate_pct=Decimal("57.0"),
        profit_factor=Decimal("1.7"),
        trades=200,
    )
    passed, failures = gate.check(metrics)
    assert passed is False
    assert any("max_dd_pct" in f for f in failures)


def test_rbi_gate_fails_win_rate_too_low() -> None:
    gate = RbiGate()
    metrics = BacktestMetrics(
        sharpe=Decimal("2.0"),
        max_dd_pct=Decimal("8.0"),
        win_rate_pct=Decimal("55.0"),  # exactly at threshold, not above
        profit_factor=Decimal("1.7"),
        trades=200,
    )
    passed, failures = gate.check(metrics)
    assert passed is False
    assert any("win_rate_pct" in f for f in failures)


def test_rbi_gate_fails_profit_factor_too_low() -> None:
    gate = RbiGate()
    metrics = BacktestMetrics(
        sharpe=Decimal("2.0"),
        max_dd_pct=Decimal("8.0"),
        win_rate_pct=Decimal("57.0"),
        profit_factor=Decimal("1.6"),  # exactly at threshold, not above
        trades=200,
    )
    passed, failures = gate.check(metrics)
    assert passed is False
    assert any("profit_factor" in f for f in failures)


def test_rbi_gate_fails_trades_too_few() -> None:
    gate = RbiGate()
    metrics = BacktestMetrics(
        sharpe=Decimal("2.0"),
        max_dd_pct=Decimal("8.0"),
        win_rate_pct=Decimal("57.0"),
        profit_factor=Decimal("1.7"),
        trades=100,  # exactly at threshold, not above
    )
    passed, failures = gate.check(metrics)
    assert passed is False
    assert any("trades" in f for f in failures)


def test_rbi_gate_reports_multiple_failures() -> None:
    gate = RbiGate()
    metrics = BacktestMetrics(
        sharpe=Decimal("0.5"),      # fail
        max_dd_pct=Decimal("25.0"), # fail
        win_rate_pct=Decimal("40.0"), # fail
        profit_factor=Decimal("0.8"), # fail
        trades=30,                  # fail
    )
    passed, failures = gate.check(metrics)
    assert passed is False
    assert len(failures) == 5
    assert any("sharpe" in f for f in failures)
    assert any("max_dd_pct" in f for f in failures)
    assert any("win_rate_pct" in f for f in failures)
    assert any("profit_factor" in f for f in failures)
    assert any("trades" in f for f in failures)


def test_rbi_gate_passes_at_just_above_each_threshold() -> None:
    """Values microscopically above each threshold should all pass."""
    gate = RbiGate()
    metrics = BacktestMetrics(
        sharpe=Decimal("1.51"),
        max_dd_pct=Decimal("14.99"),
        win_rate_pct=Decimal("55.01"),
        profit_factor=Decimal("1.61"),
        trades=101,
    )
    passed, failures = gate.check(metrics)
    assert passed is True
    assert failures == []


# ---------------------------------------------------------------------------
# InMemoryGenomeStore — basic operations
# ---------------------------------------------------------------------------


def test_store_put_and_get() -> None:
    store = InMemoryGenomeStore()
    g = _genome()
    store.put(g)
    assert store.get("genome_test_001") is g


def test_store_get_unknown_returns_none() -> None:
    store = InMemoryGenomeStore()
    assert store.get("nonexistent") is None


def test_store_put_replaces_existing() -> None:
    store = InMemoryGenomeStore()
    g1 = _genome("gid_01")
    store.put(g1)
    # Put a new genome with same id but different field.
    g2 = StrategyGenome(
        strategy_id="gid_01",
        family="mean_reversion",
        market="ES",
        timeframe="15m",
        risk_profile="conservative",
    )
    store.put(g2)
    retrieved = store.get("gid_01")
    assert retrieved is not None
    assert retrieved.family == "mean_reversion"


# ---------------------------------------------------------------------------
# InMemoryGenomeStore — record_validation and staleness
# ---------------------------------------------------------------------------


def test_genome_with_no_validations_is_stale() -> None:
    store = InMemoryGenomeStore()
    store.put(_genome())
    assert store.is_stale("genome_test_001", _NOW) is True


def test_genome_with_recent_passed_validation_is_not_stale() -> None:
    store = InMemoryGenomeStore()
    store.put(_genome())
    store.record_validation(
        "genome_test_001",
        stage=RbiStage.BACKTEST_INITIAL,
        passed=True,
        metrics={"sharpe": "2.1"},
        at=_NOW - timedelta(days=7),
    )
    assert store.is_stale("genome_test_001", _NOW) is False


def test_genome_stale_boundary_exactly_14_days() -> None:
    """A PASSED validation exactly 14 days ago is still within the window (cutoff = as_of - 14 days,
    and we check >= cutoff, so exactly at cutoff is NOT stale)."""
    store = InMemoryGenomeStore()
    store.put(_genome())
    validation_at = _NOW - timedelta(days=14)
    store.record_validation(
        "genome_test_001",
        stage=RbiStage.BACKTEST_INITIAL,
        passed=True,
        metrics={},
        at=validation_at,
    )
    # Exactly 14 days ago: at >= cutoff (cutoff = as_of - 14d = validation_at exactly)
    assert store.is_stale("genome_test_001", _NOW) is False


def test_genome_stale_just_beyond_14_days() -> None:
    """A PASSED validation 14 days and 1 second ago is outside the window → stale."""
    store = InMemoryGenomeStore()
    store.put(_genome())
    validation_at = _NOW - timedelta(days=14, seconds=1)
    store.record_validation(
        "genome_test_001",
        stage=RbiStage.BACKTEST_INITIAL,
        passed=True,
        metrics={},
        at=validation_at,
    )
    assert store.is_stale("genome_test_001", _NOW) is True


def test_genome_with_only_failed_validations_is_stale() -> None:
    store = InMemoryGenomeStore()
    store.put(_genome())
    store.record_validation(
        "genome_test_001",
        stage=RbiStage.BACKTEST_INITIAL,
        passed=False,  # failed — does not count
        metrics={"sharpe": "0.5"},
        at=_NOW - timedelta(days=3),
    )
    assert store.is_stale("genome_test_001", _NOW) is True


def test_genome_with_old_passed_and_recent_failed_is_stale() -> None:
    """Old PASSED + recent FAILED → stale (old pass is outside window)."""
    store = InMemoryGenomeStore()
    store.put(_genome())
    store.record_validation(
        "genome_test_001",
        stage=RbiStage.BACKTEST_INITIAL,
        passed=True,
        metrics={},
        at=_NOW - timedelta(days=20),  # outside 14-day window
    )
    store.record_validation(
        "genome_test_001",
        stage=RbiStage.PAPER_TRADE,
        passed=False,
        metrics={},
        at=_NOW - timedelta(days=2),
    )
    assert store.is_stale("genome_test_001", _NOW) is True


def test_record_validation_unknown_genome_raises() -> None:
    store = InMemoryGenomeStore()
    with pytest.raises(KeyError, match="unknown_id"):
        store.record_validation("unknown_id", "backtest_initial", True, {}, _NOW)


def test_is_stale_unknown_genome_raises() -> None:
    store = InMemoryGenomeStore()
    with pytest.raises(KeyError, match="ghost_genome"):
        store.is_stale("ghost_genome", _NOW)


def test_is_stale_requires_tz_aware_datetime() -> None:
    store = InMemoryGenomeStore()
    store.put(_genome())
    naive = datetime(2026, 4, 15, 14, 0, 0)  # no tzinfo
    with pytest.raises(ValueError, match="timezone-aware"):
        store.is_stale("genome_test_001", naive)


# ---------------------------------------------------------------------------
# InMemoryGenomeStore — list_active
# ---------------------------------------------------------------------------


def test_list_active_excludes_stale_genomes() -> None:
    store = InMemoryGenomeStore()
    active = _genome("active_001")
    stale = _genome("stale_002")

    store.put(active)
    store.put(stale)

    # active has recent validation
    store.record_validation(
        "active_001", RbiStage.BACKTEST_INITIAL, True, {}, _NOW - timedelta(days=5)
    )
    # stale has no validation

    result = store.list_active(_NOW)
    ids = {g.strategy_id for g in result}
    assert "active_001" in ids
    assert "stale_002" not in ids


def test_list_active_with_all_stale_returns_empty() -> None:
    store = InMemoryGenomeStore()
    store.put(_genome("g1"))
    store.put(_genome("g2"))
    assert store.list_active(_NOW) == []


def test_list_active_with_all_active_returns_all() -> None:
    store = InMemoryGenomeStore()
    for i in range(3):
        gid = f"g{i}"
        store.put(_genome(gid))
        store.record_validation(gid, RbiStage.PAPER_TRADE, True, {}, _NOW - timedelta(days=1))

    result = store.list_active(_NOW)
    assert len(result) == 3


def test_list_active_requires_tz_aware_datetime() -> None:
    store = InMemoryGenomeStore()
    naive = datetime(2026, 4, 15, 14, 0, 0)
    with pytest.raises(ValueError, match="timezone-aware"):
        store.list_active(naive)


# ---------------------------------------------------------------------------
# InMemoryGenomeStore — validation_history
# ---------------------------------------------------------------------------


def test_validation_history_returns_records_in_insertion_order() -> None:
    store = InMemoryGenomeStore()
    store.put(_genome())
    t1 = _NOW - timedelta(days=10)
    t2 = _NOW - timedelta(days=5)
    store.record_validation(
        "genome_test_001", RbiStage.BACKTEST_INITIAL, False, {"sharpe": "0.8"}, t1
    )
    store.record_validation(
        "genome_test_001", RbiStage.BACKTEST_INITIAL, True, {"sharpe": "2.1"}, t2
    )

    history = store.validation_history("genome_test_001")
    assert len(history) == 2
    assert history[0].passed is False
    assert history[1].passed is True
    assert history[0].at == t1
    assert history[1].at == t2


def test_validation_history_unknown_genome_raises() -> None:
    store = InMemoryGenomeStore()
    with pytest.raises(KeyError):
        store.validation_history("unknown")


def test_validation_history_returns_copy_not_reference() -> None:
    store = InMemoryGenomeStore()
    store.put(_genome())
    store.record_validation("genome_test_001", RbiStage.RESEARCH, True, {}, _NOW)
    h = store.validation_history("genome_test_001")
    h.clear()  # mutate the returned list
    assert len(store.validation_history("genome_test_001")) == 1  # store unaffected
