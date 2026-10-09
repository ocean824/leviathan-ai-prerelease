from decimal import Decimal

from leviathan_core.backtest_lab.evaluation_standard import (
    EvaluationStandardSpecV1,
    StrategyReturnStreamV1,
    evaluate_standard,
)
from leviathan_core.backtest_lab.walkforward import FoldManifestV1, FoldV1
from leviathan_core.seal import digest


def _manifest() -> FoldManifestV1:
    fold = FoldV1("wf-1", 1, 1, 4, 4, 7, 0, "reset", (), (1, 1), (1, 1))
    prefix = ("sanitized-data", "v1", "u1", "UTC", "v1", *("a" * 64 for _ in range(5)))
    stable = (*prefix, (fold,), ())
    return FoldManifestV1(
        dataset_id="sanitized-data",
        dataset_version="v1",
        universe_version="u1",
        calendar_id="UTC",
        calendar_version="v1",
        dataset_snapshot_sha256="a" * 64,
        coverage_snapshot_sha256="a" * 64,
        universe_snapshot_sha256="a" * 64,
        feature_snapshot_sha256="a" * 64,
        spec_sha256="a" * 64,
        folds=(fold,),
        manifest_sha256=digest(stable),
    )


def _four_is_manifest() -> FoldManifestV1:
    fold = FoldV1("wf-4is", 1, 1, 5, 5, 8, 0, "reset", (), (1, 1), (1, 1))
    prefix = ("sanitized-data", "v1", "u1", "UTC", "v1", *("a" * 64 for _ in range(5)))
    return FoldManifestV1(
        dataset_id="sanitized-data",
        dataset_version="v1",
        universe_version="u1",
        calendar_id="UTC",
        calendar_version="v1",
        dataset_snapshot_sha256="a" * 64,
        coverage_snapshot_sha256="a" * 64,
        universe_snapshot_sha256="a" * 64,
        feature_snapshot_sha256="a" * 64,
        spec_sha256="a" * 64,
        folds=(fold,),
        manifest_sha256=digest((*prefix, (fold,), ())),
    )


def _stream(
    name: str,
    returns: tuple[str, ...],
    *,
    trade_returns: tuple[str, ...] | None = None,
    turnover: tuple[str, ...] | None = None,
) -> StrategyReturnStreamV1:
    return StrategyReturnStreamV1(
        name,
        tuple(range(1, len(returns) + 1)),
        tuple(Decimal(x) for x in returns),
        tuple(Decimal(x) for x in (trade_returns or returns)),
        tuple(Decimal(x) for x in (turnover or ("0.1",) * len(returns))),
    )


def _spec(
    *, max_correlation: str = "1", max_weight: str = "1", weight_step: str = "0.01"
) -> EvaluationStandardSpecV1:
    return EvaluationStandardSpecV1(
        periods_per_year=1,
        risk_free_per_period=Decimal("0"),
        max_correlation=Decimal(max_correlation),
        max_weight=Decimal(max_weight),
        weight_step=Decimal(weight_step),
    )


def test_hand_calculated_oos_metrics_match_known_return_series() -> None:
    stream = _stream(
        "known",
        ("0.01", "0.02", "-0.01", "-0.1", "0.2", "0", "0"),
        trade_returns=("0.01", "0.02", "-0.01", "-0.1", "0.2", "0", "0"),
        turnover=("0.1", "0.2", "0.3", "0.3", "0.3", "0.3", "0.3"),
    )
    report = evaluate_standard((stream,), _manifest(), _spec())
    metrics = report.folds[0].oos_metrics

    # OOS is [-10%, +20%, 0%]: mean=1/30, population SD=10%, downside RMS=10%/sqrt(3).
    assert abs(metrics.sharpe - Decimal("0.2672612419124244")) < Decimal("1e-16")
    assert abs(metrics.sortino - Decimal("0.577350269189625764")) < Decimal("1e-15")
    assert metrics.max_drawdown == Decimal("0.1")
    assert metrics.max_drawdown_duration == 1
    assert abs(metrics.cagr - Decimal("0.0259856")) < Decimal("0.000001")
    assert metrics.profit_factor == Decimal(2)
    assert metrics.win_rate == Decimal("0.5")
    assert metrics.expectancy == Decimal("0.05")
    assert metrics.turnover == Decimal("0.3")


def test_optimizer_enforces_exact_correlation_and_weight_caps_deterministically() -> None:
    streams = (
        _stream("a", ("0.01", "0.02", "0.03", "0.04", "0.01", "0.02", "0.03")),
        _stream("b", ("0.01", "0.02", "0.03", "0.04", "-0.5", "0.7", "0.4")),
        _stream("c", ("0.03", "0.01", "0.01", "0.03", "0.02", "0.01", "0.02")),
    )
    spec = _spec(max_correlation="0.5", max_weight="0.4", weight_step="0.1")
    first = evaluate_standard(streams, _four_is_manifest(), spec).folds[0]
    second = evaluate_standard(streams, _four_is_manifest(), spec).folds[0]
    assert first == second
    assert first.selected_strategy_ids == ("a", "c")
    assert dict(first.weights) == {"a": Decimal("0.4"), "c": Decimal("0.4")}
    assert sum(weight for _, weight in first.weights) <= Decimal("0.8")
    assert abs(first.oos_metrics.expectancy - Decimal("0.0146666666666667")) < Decimal("1e-16")
    matrix = {left: dict(rights) for left, rights in first.correlation_matrix}
    assert matrix["a"]["b"] == Decimal(1)
    assert abs(matrix["a"]["c"]) <= Decimal("0.5")


def test_out_of_sample_changes_cannot_change_selection_weights_or_is_metrics() -> None:
    baseline = (
        _stream("a", ("0.01", "0.03", "-0.01", "0.02", "0.01", "0.02", "0.03")),
        _stream("b", ("0.03", "0.01", "0.02", "0.01", "0.02", "0.01", "0.02")),
    )
    altered_oos = (
        _stream("a", ("0.01", "0.03", "-0.01", "0.02", "-0.9", "0.8", "-0.7")),
        _stream("b", ("0.03", "0.01", "0.02", "0.01", "0.9", "-0.8", "0.7")),
    )
    first = evaluate_standard(baseline, _manifest(), _spec(max_correlation="1")).folds[0]
    changed = evaluate_standard(altered_oos, _manifest(), _spec(max_correlation="1")).folds[0]
    assert first.selected_strategy_ids == changed.selected_strategy_ids
    assert first.weights == changed.weights
    assert first.is_metrics == changed.is_metrics
    assert first.correlation_matrix == changed.correlation_matrix
    assert first.oos_metrics != changed.oos_metrics
