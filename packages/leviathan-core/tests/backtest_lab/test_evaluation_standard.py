from decimal import Decimal

from leviathan_core.backtest_lab.evaluation_standard import (
    EvaluationStandardSpecV1,
    StrategyReturnStreamV1,
    evaluate_standard,
)
from leviathan_core.backtest_lab.walkforward import FoldManifestV1, FoldV1
from leviathan_core.seal import digest


def _manifest() -> FoldManifestV1:
    fold = FoldV1("fold-1", 1, 1, 4, 4, 7, 0, "reset", (), (1, 1), (1, 1))
    prefix = ("data", "v1", "u1", "cal", "v1", *("a" * 64 for _ in range(5)))
    stable = (*prefix, (fold,), ())
    return FoldManifestV1(
        dataset_id="data",
        dataset_version="v1",
        universe_version="u1",
        calendar_id="cal",
        calendar_version="v1",
        dataset_snapshot_sha256="a" * 64,
        coverage_snapshot_sha256="a" * 64,
        universe_snapshot_sha256="a" * 64,
        feature_snapshot_sha256="a" * 64,
        spec_sha256="a" * 64,
        folds=(fold,),
        manifest_sha256=digest(stable),
    )


def _stream(name: str, oos: Decimal) -> StrategyReturnStreamV1:
    return StrategyReturnStreamV1(
        name,
        (1, 2, 3, 4, 5, 6),
        (Decimal("0.01"), Decimal("0.02"), Decimal("-0.01"), oos, oos, oos),
        (Decimal("0.01"), Decimal("0.02"), Decimal("-0.01"), oos, oos, oos),
        (Decimal("0.1"),) * 6,
    )


def test_walk_forward_selection_uses_is_only_and_weights_respect_cap() -> None:
    spec = EvaluationStandardSpecV1(
        252, Decimal("0"), Decimal("0.5"), Decimal("0.4"), Decimal("0.1")
    )
    first = evaluate_standard(
        (_stream("a", Decimal("0.03")), _stream("b", Decimal("0.03"))), _manifest(), spec
    )
    changed_oos = evaluate_standard(
        (_stream("a", Decimal("-0.9")), _stream("b", Decimal("1"))), _manifest(), spec
    )
    assert first.folds[0].selected_strategy_ids == changed_oos.folds[0].selected_strategy_ids
    assert first.folds[0].selected_strategy_ids == ("a",)
    assert sum(weight for _, weight in first.folds[0].weights) <= Decimal("0.4")
    assert len(first.folds[0].correlation_matrix) == 2


def test_evaluation_report_includes_requested_metrics_and_is_oos() -> None:
    report = evaluate_standard(
        (_stream("single", Decimal("0.01")),),
        _manifest(),
        EvaluationStandardSpecV1(
            252, Decimal("0.0001"), Decimal("1"), Decimal("1"), Decimal("0.01")
        ),
    )
    metrics = report.folds[0].oos_metrics
    assert metrics.sharpe.is_finite()
    assert metrics.sortino.is_finite()
    assert metrics.max_drawdown >= 0
    assert metrics.max_drawdown_duration >= 0
    assert metrics.cagr.is_finite()
    assert metrics.profit_factor >= 0
    assert 0 <= metrics.win_rate <= 1
    assert metrics.expectancy.is_finite()
    assert metrics.turnover == Decimal("0.1")
