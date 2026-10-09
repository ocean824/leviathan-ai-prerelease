"""RBI (Research-Backtest-Implement) stage enum and initial-backtest gate.

The RBI gauntlet is the mandatory path from research to live deployment.
No genome bypasses this sequence.

Stages (in order):
    RESEARCH              — strategy concept and doctrine validation
    BACKTEST_INITIAL      — first pass backtest with basic metrics gate
    BACKTEST_MONTE_CARLO  — Monte Carlo robustness simulation
    BACKTEST_WALK_FORWARD — walk-forward out-of-sample validation
    BACKTEST_REGIME       — regime-specific stress testing
    PAPER_TRADE           — live paper trading (no capital at risk)
    DEPLOYED              — production live execution

Initial backtest thresholds (RbiGate):
    sharpe           > 1.5
    max_dd_pct       < 15 %
    win_rate_pct     > 55 %
    profit_factor    > 1.6
    trades           > 100
"""

from decimal import Decimal
from enum import StrEnum

from pydantic import Field

from leviathan_core.schemas.base import LeviathanModel


class RbiStage(StrEnum):
    """Ordered stages of the Research → Backtest → Implement gauntlet."""

    RESEARCH = "research"
    BACKTEST_INITIAL = "backtest_initial"
    BACKTEST_MONTE_CARLO = "backtest_monte_carlo"
    BACKTEST_WALK_FORWARD = "backtest_walk_forward"
    BACKTEST_REGIME = "backtest_regime"
    PAPER_TRADE = "paper_trade"
    DEPLOYED = "deployed"


class BacktestMetrics(LeviathanModel):
    """Initial backtest metrics submitted to the RBI gate.

    All rate fields are expressed as percentages (e.g. 57.3 for 57.3 %).
    ``trades`` is the total number of trades in the backtest sample.
    """

    sharpe: Decimal = Field(description="Annualised Sharpe ratio")
    max_dd_pct: Decimal = Field(description="Maximum drawdown as a percentage, e.g. 12.5")
    win_rate_pct: Decimal = Field(description="Win rate as a percentage, e.g. 57.3")
    profit_factor: Decimal = Field(description="Gross profit / gross loss")
    trades: int = Field(description="Total number of trades in the backtest", ge=0)


# Threshold constants — single source of truth.
_MIN_SHARPE = Decimal("1.5")
_MAX_DD_PCT = Decimal("15")
_MIN_WIN_RATE_PCT = Decimal("55")
_MIN_PROFIT_FACTOR = Decimal("1.6")
_MIN_TRADES = 100


class RbiGate:
    """Initial backtest qualification gate.

    Checks a BacktestMetrics object against the five mandatory thresholds.
    Returns ``(passed, failures)`` where ``failures`` is a list of human-
    readable strings naming each metric that failed, or an empty list if all
    thresholds were met.

    This gate corresponds to the BACKTEST_INITIAL stage. Passing it is
    necessary but not sufficient for deployment — Monte Carlo, walk-forward,
    and regime stages follow.
    """

    def check(self, metrics: BacktestMetrics) -> tuple[bool, list[str]]:
        """Evaluate metrics against initial backtest thresholds.

        Args:
            metrics: BacktestMetrics for the strategy under evaluation.

        Returns:
            A tuple ``(passed, failures)``:
            - ``passed`` is True iff all five thresholds are satisfied.
            - ``failures`` lists each named threshold violation; empty on pass.
        """
        failures: list[str] = []

        if metrics.sharpe <= _MIN_SHARPE:
            failures.append(
                f"sharpe={metrics.sharpe} <= {_MIN_SHARPE} (required > {_MIN_SHARPE})"
            )
        if metrics.max_dd_pct >= _MAX_DD_PCT:
            failures.append(
                f"max_dd_pct={metrics.max_dd_pct} >= {_MAX_DD_PCT}% (required < {_MAX_DD_PCT}%)"
            )
        if metrics.win_rate_pct <= _MIN_WIN_RATE_PCT:
            failures.append(
                f"win_rate_pct={metrics.win_rate_pct} <= {_MIN_WIN_RATE_PCT}%"
                f" (required > {_MIN_WIN_RATE_PCT}%)"
            )
        if metrics.profit_factor <= _MIN_PROFIT_FACTOR:
            failures.append(
                f"profit_factor={metrics.profit_factor} <= {_MIN_PROFIT_FACTOR}"
                f" (required > {_MIN_PROFIT_FACTOR})"
            )
        if metrics.trades <= _MIN_TRADES:
            failures.append(
                f"trades={metrics.trades} <= {_MIN_TRADES} (required > {_MIN_TRADES})"
            )

        return (len(failures) == 0, failures)
