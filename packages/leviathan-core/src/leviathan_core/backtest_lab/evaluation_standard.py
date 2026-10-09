"""Deterministic strategy evaluation on strict BT-004 walk-forward folds.

The AI Trading Floor ``CONVENTIONS.md`` sections 3 and 8 require daily-return
Sharpe (annualized by the explicitly configured periodicity), honest IS/OOS
separation, portfolio correlation analysis and lagged weights. Every fold
optimizer below sees only the fold's IS slice; OOS is read afterward to score
the frozen selection. Decimal values are converted to exact fractions at the
boundary and rounded only for reported Decimal metrics.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, localcontext
from fractions import Fraction
from math import isqrt

from leviathan_core.backtest_lab.walkforward import FoldManifestV1
from leviathan_core.numeric import Ratio, parse_decimal, quotient_final

_MAX_STREAMS = 64
_MAX_ROWS = 100_000
_SCALE = 10**18


class EvaluationStandardError(ValueError):
    """Content-free evaluation error with a stable code."""

    def __init__(self, code: str = "EVALUATION_INVALID") -> None:
        self.code = code
        super().__init__(code)


def _decimal(x: object) -> Decimal:
    try:
        return parse_decimal(x, field="value")
    except (TypeError, ValueError):
        raise EvaluationStandardError() from None


def _q(x: Fraction | int) -> Decimal:
    value = Fraction(x)
    return quotient_final(Ratio(value.numerator, value.denominator), 1)


@dataclass(frozen=True, slots=True)
class StrategyReturnStreamV1:
    strategy_id: str
    timestamps_ns: tuple[int, ...]
    period_returns: tuple[Decimal, ...]
    trade_returns: tuple[Decimal, ...]
    turnover: tuple[Decimal, ...]

    def __post_init__(self) -> None:
        if (
            type(self.strategy_id) is not str
            or not self.strategy_id
            or len(self.strategy_id) > 96
            or type(self.timestamps_ns) is not tuple
            or type(self.period_returns) is not tuple
            or type(self.trade_returns) is not tuple
            or type(self.turnover) is not tuple
            or not self.timestamps_ns
            or len(self.timestamps_ns) > _MAX_ROWS
            or len(self.timestamps_ns) != len(self.period_returns)
            or len(self.turnover) != len(self.timestamps_ns)
            or len(self.trade_returns) != len(self.timestamps_ns)
            or any(type(t) is not int or t < 0 for t in self.timestamps_ns)
            or any(a >= b for a, b in zip(self.timestamps_ns, self.timestamps_ns[1:], strict=False))
        ):
            raise EvaluationStandardError("RETURN_STREAM_INVALID")
        object.__setattr__(self, "period_returns", tuple(_decimal(x) for x in self.period_returns))
        object.__setattr__(self, "trade_returns", tuple(_decimal(x) for x in self.trade_returns))
        object.__setattr__(self, "turnover", tuple(_decimal(x) for x in self.turnover))
        if any(x < 0 for x in self.turnover):
            raise EvaluationStandardError("RETURN_STREAM_INVALID")


@dataclass(frozen=True, slots=True)
class EvaluationStandardSpecV1:
    periods_per_year: int
    risk_free_per_period: Decimal
    max_correlation: Decimal
    max_weight: Decimal
    weight_step: Decimal

    def __post_init__(self) -> None:
        if type(self.periods_per_year) is not int or not 1 <= self.periods_per_year <= 100_000:
            raise EvaluationStandardError("EVALUATION_SPEC_INVALID")
        for name in ("risk_free_per_period", "max_correlation", "max_weight", "weight_step"):
            object.__setattr__(self, name, _decimal(getattr(self, name)))
        if (
            not 0 <= self.max_correlation <= 1
            or not 0 < self.max_weight <= 1
            or not 0 < self.weight_step <= self.max_weight
        ):
            raise EvaluationStandardError("EVALUATION_SPEC_INVALID")


@dataclass(frozen=True, slots=True)
class EvaluationMetricSetV1:
    sharpe: Decimal
    sortino: Decimal
    max_drawdown: Decimal
    max_drawdown_duration: int
    cagr: Decimal
    profit_factor: Decimal
    win_rate: Decimal
    expectancy: Decimal
    turnover: Decimal


@dataclass(frozen=True, slots=True)
class EvaluationFoldV1:
    fold_id: str
    selected_strategy_ids: tuple[str, ...]
    weights: tuple[tuple[str, Decimal], ...]
    correlation_matrix: tuple[tuple[str, tuple[tuple[str, Decimal], ...]], ...]
    is_metrics: EvaluationMetricSetV1
    oos_metrics: EvaluationMetricSetV1


@dataclass(frozen=True, slots=True)
class EvaluationStandardReportV1:
    fold_manifest_sha256: str
    folds: tuple[EvaluationFoldV1, ...]


def _sqrt_fraction(value: Fraction) -> Decimal:
    if value <= 0:
        return Decimal(0)
    n = value.numerator * _SCALE * _SCALE // value.denominator
    return Decimal(isqrt(n)).scaleb(-18)


def _corr_parts(
    a: tuple[Decimal, ...], b: tuple[Decimal, ...]
) -> tuple[Fraction, Fraction, Fraction]:
    if len(a) != len(b) or len(a) < 2:
        return Fraction(), Fraction(), Fraction()
    fa, fb = [Fraction(x) for x in a], [Fraction(x) for x in b]
    ma, mb = sum(fa, Fraction()) / len(fa), sum(fb, Fraction()) / len(fb)
    cov = sum(((x - ma) * (y - mb) for x, y in zip(fa, fb, strict=False)), Fraction())
    va = sum(((x - ma) ** 2 for x in fa), Fraction())
    vb = sum(((x - mb) ** 2 for x in fb), Fraction())
    return cov, va, vb


def _metrics(
    returns: tuple[Decimal, ...],
    trade_returns: tuple[Decimal, ...],
    turnover: tuple[Decimal, ...],
    spec: EvaluationStandardSpecV1,
) -> EvaluationMetricSetV1:
    if not returns:
        raise EvaluationStandardError("EMPTY_EVALUATION_WINDOW")
    values = tuple(Fraction(x) for x in returns)
    rf = Fraction(spec.risk_free_per_period)
    excess = tuple(x - rf for x in values)
    mean = sum(excess, Fraction()) / len(excess)
    variance = sum(((x - mean) ** 2 for x in excess), Fraction()) / len(excess)
    annual_scale = Fraction(_sqrt_fraction(Fraction(spec.periods_per_year)))
    sharpe = (
        _q(mean * annual_scale / Fraction(_sqrt_fraction(variance)))
        if variance
        else _q(mean * annual_scale)
    )
    downside = tuple(min(x, Fraction()) for x in excess)
    down_var = sum((x * x for x in downside), Fraction()) / len(downside)
    sortino = (
        _q(mean * annual_scale / Fraction(_sqrt_fraction(down_var)))
        if down_var
        else _q(mean * annual_scale)
    )
    equity = Fraction(1)
    peak = Fraction(1)
    max_dd = Fraction()
    duration = 0
    longest = 0
    for r in values:
        equity *= 1 + r
        if equity > peak:
            peak, duration = equity, 0
        else:
            duration += 1
            longest = max(longest, duration)
            max_dd = max(max_dd, (peak - equity) / peak)
    if equity > 0:
        with localcontext() as ctx:
            ctx.prec = 34
            growth = Decimal(equity.numerator) / Decimal(equity.denominator)
            cagr = growth ** (Decimal(spec.periods_per_year) / Decimal(len(values))) - Decimal(1)
            cagr = +cagr
    else:
        cagr = Decimal(-1)
    tr = tuple(Fraction(x) for x in trade_returns if x != 0)
    gains = sum((x for x in tr if x > 0), Fraction())
    losses = -sum((x for x in tr if x < 0), Fraction())
    pf = _q(gains / losses) if losses else (Decimal(0) if gains == 0 else Decimal("1E+18"))
    win = quotient_final(sum(1 for x in tr if x > 0), len(tr)) if tr else Decimal(0)
    expectancy = _q(sum(tr, Fraction()) / len(tr)) if tr else Decimal(0)
    turn = _q(sum((Fraction(x) for x in turnover), Fraction()) / len(turnover))
    return EvaluationMetricSetV1(
        sharpe, sortino, _q(max_dd), longest, _decimal(cagr), pf, win, expectancy, turn
    )


def evaluate_standard(
    streams: tuple[StrategyReturnStreamV1, ...],
    fold_manifest: FoldManifestV1,
    spec: EvaluationStandardSpecV1,
) -> EvaluationStandardReportV1:
    """Select a low-correlation capped portfolio using IS data, then score OOS."""
    if (
        type(streams) is not tuple
        or not streams
        or len(streams) > _MAX_STREAMS
        or len({s.strategy_id for s in streams}) != len(streams)
        or type(fold_manifest) is not FoldManifestV1
    ):
        raise EvaluationStandardError()
    by_id = {s.strategy_id: s for s in streams}
    folds: list[EvaluationFoldV1] = []
    for fold in fold_manifest.folds:
        # The masks and selection statistics are formed exclusively from IS timestamps.
        is_slices: dict[str, tuple[list[int], list[Decimal]]] = {}
        for sid, stream in by_id.items():
            is_rows = [
                (t, r)
                for t, r in zip(stream.timestamps_ns, stream.period_returns, strict=False)
                if fold.is_start_ns <= t < fold.is_end_ns
            ]
            is_slices[sid] = ([t for t, _ in is_rows], [r for _, r in is_rows])
        if any(not vals[0] for vals in is_slices.values()):
            raise EvaluationStandardError("FOLD_COVERAGE_INCOMPLETE")
        ids = tuple(sorted(by_id))
        # Correlations use common IS timestamp intersections only.
        corr: dict[tuple[str, str], tuple[Fraction, Fraction, Fraction]] = {}
        for i, left in enumerate(ids):
            for right in ids[i:]:
                lm = dict(zip(*is_slices[left], strict=True))
                rm = dict(zip(*is_slices[right], strict=True))
                common = sorted(set(lm).intersection(rm))
                val = _corr_parts(tuple(lm[t] for t in common), tuple(rm[t] for t in common))
                corr[left, right] = corr[right, left] = val
        # Deterministic greedy optimizer: descending IS Sharpe, ID tie-break; only
        # admit a candidate when abs(corr) is within the injected cap.
        ranked = sorted(ids, key=lambda sid: (-_is_score(tuple(is_slices[sid][1]), spec), sid))
        selected: list[str] = []
        for candidate in ranked:
            if all(
                _abs_corr_within(corr[candidate, chosen], spec.max_correlation)
                for chosen in selected
            ):
                selected.append(candidate)
        if not selected:
            raise EvaluationStandardError("NO_STRATEGY_SELECTED")
        per_weight = min(Fraction(spec.max_weight), Fraction(1, len(selected)))
        per_weight = per_weight // Fraction(spec.weight_step) * Fraction(spec.weight_step)
        if per_weight <= 0:
            raise EvaluationStandardError("WEIGHT_STEP_TOO_LARGE")
        weights = {sid: per_weight for sid in selected}
        is_times = sorted(set.intersection(*(set(is_slices[sid][0]) for sid in selected)))
        # OOS data is first accessed after selected IDs and weights are fixed.
        oos_slices: dict[str, tuple[list[int], list[Decimal]]] = {}
        for sid in selected:
            stream = by_id[sid]
            oos_rows = [
                (t, r)
                for t, r in zip(stream.timestamps_ns, stream.period_returns, strict=True)
                if fold.oos_start_ns <= t < fold.oos_end_ns
            ]
            oos_slices[sid] = ([t for t, _ in oos_rows], [r for _, r in oos_rows])
        if any(not vals[0] for vals in oos_slices.values()):
            raise EvaluationStandardError("FOLD_COVERAGE_INCOMPLETE")
        oos_times = sorted(set.intersection(*(set(oos_slices[sid][0]) for sid in selected)))
        is_maps = {sid: dict(zip(*is_slices[sid], strict=False)) for sid in selected}
        oos_maps = {sid: dict(zip(*oos_slices[sid], strict=False)) for sid in selected}
        mixed_is = tuple(
            _q(sum((Fraction(is_maps[sid][t]) * weights[sid] for sid in selected), Fraction()))
            for t in is_times
        )
        mixed_oos = tuple(
            _q(sum((Fraction(oos_maps[sid][t]) * weights[sid] for sid in selected), Fraction()))
            for t in oos_times
        )
        is_trade_maps = {
            sid: dict(zip(by_id[sid].timestamps_ns, by_id[sid].trade_returns, strict=True))
            for sid in selected
        }
        is_trade = tuple(
            _q(
                sum(
                    (Fraction(is_trade_maps[sid][t]) * weights[sid] for sid in selected), Fraction()
                )
            )
            for t in is_times
        )
        oos_trade = tuple(
            _q(
                sum(
                    (Fraction(is_trade_maps[sid][t]) * weights[sid] for sid in selected), Fraction()
                )
            )
            for t in oos_times
        )
        is_turn = tuple(
            _q(
                sum(
                    (
                        Fraction(by_id[sid].turnover[by_id[sid].timestamps_ns.index(t)])
                        * weights[sid]
                        for sid in selected
                    ),
                    Fraction(),
                )
            )
            for t in is_times
        )
        oos_turn = tuple(
            _q(
                sum(
                    (
                        Fraction(by_id[sid].turnover[by_id[sid].timestamps_ns.index(t)])
                        * weights[sid]
                        for sid in selected
                    ),
                    Fraction(),
                )
            )
            for t in oos_times
        )
        is_metrics = _metrics(mixed_is, is_trade, is_turn, spec)
        oos_metrics = _metrics(mixed_oos, oos_trade, oos_turn, spec)
        matrix = tuple((a, tuple((b, _corr_display(corr[a, b])) for b in ids)) for a in ids)
        folds.append(
            EvaluationFoldV1(
                fold.fold_id,
                tuple(selected),
                tuple((sid, _q(weights[sid])) for sid in selected),
                matrix,
                is_metrics,
                oos_metrics,
            )
        )
    return EvaluationStandardReportV1(fold_manifest.manifest_sha256, tuple(folds))


def _is_score(values: tuple[Decimal, ...], spec: EvaluationStandardSpecV1) -> Fraction:
    xs = tuple(Fraction(v) - Fraction(spec.risk_free_per_period) for v in values)
    if not xs:
        return Fraction(-(10**9))
    # Policy objective: maximize average excess IS return; ties use strategy ID.
    return sum(xs, Fraction()) / len(xs)


def _abs_corr_within(parts: tuple[Fraction, Fraction, Fraction], cap: Decimal) -> bool:
    # Exact |cov| / sqrt(va*vb) <= cap comparison, squared without approximation.
    cov, va, vb = parts
    if va == 0 or vb == 0:
        return True
    threshold = Fraction(cap)
    return cov * cov <= threshold * threshold * va * vb


def _corr_display(parts: tuple[Fraction, Fraction, Fraction]) -> Decimal:
    cov, va, vb = parts
    if va == 0 or vb == 0:
        return Decimal(0)
    sign = -1 if cov < 0 else 1
    magnitude = abs(cov)
    denominator_root = isqrt((va * vb).numerator * _SCALE * _SCALE // (va * vb).denominator)
    if denominator_root == 0:
        return Decimal(0)
    scaled = magnitude.numerator * _SCALE * _SCALE // (magnitude.denominator * denominator_root)
    return Decimal(sign * scaled).scaleb(-18)
