"""Exact in-sample/OOS aggregation for complete walk-forward fold artifacts."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from decimal import Decimal

from leviathan_core.numeric import exact_sum, parse_decimal, quotient_final
from leviathan_core.numeric.errors import NumericError
from leviathan_core.seal import MAX_DIGEST_NODES_CEILING, Issuer, SealError

from .walkforward import (
    FoldManifestV1,
    InputTooLargeError,
    _FrozenRecord,
    _require_manifest,
    _sha256,
    _token,
)


class FoldMetricsError(ValueError):
    """Base for content-free fold metric contract failures."""

    code = "FOLD_METRICS_INVALID"

    def __init__(self) -> None:
        super().__init__(self.code)


class IncompleteFoldAggregationError(FoldMetricsError):
    code = "FOLD_METRICS_INCOMPLETE"


class MetricValueError(FoldMetricsError):
    code = "METRIC_VALUE_INVALID"


@dataclass(frozen=True, slots=True)
class MetricValueV1(_FrozenRecord):
    name: str
    value: Decimal

    def __post_init__(self) -> None:
        _token(self.name)
        try:
            value = parse_decimal(self.value, field="metric")
        except (TypeError, ValueError, NumericError):
            raise MetricValueError() from None
        object.__setattr__(self, "value", value)


@dataclass(frozen=True, slots=True)
class CompletedFoldMetricsV1(_FrozenRecord):
    """One completed fold artifact; partial IS/OOS metric sets are invalid."""

    fold_id: str
    fold_manifest_sha256: str
    is_metrics: tuple[MetricValueV1, ...]
    oos_metrics: tuple[MetricValueV1, ...]

    def __post_init__(self) -> None:
        _token(self.fold_id)
        _sha256(self.fold_manifest_sha256)
        try:
            is_metrics = tuple(self.is_metrics)
            oos_metrics = tuple(self.oos_metrics)
        except (TypeError, ValueError):
            raise MetricValueError() from None
        if (
            not is_metrics
            or not oos_metrics
            or any(type(value) is not MetricValueV1 for value in (*is_metrics, *oos_metrics))
            or len({value.name for value in is_metrics}) != len(is_metrics)
            or len({value.name for value in oos_metrics}) != len(oos_metrics)
            or {value.name for value in is_metrics} != {value.name for value in oos_metrics}
        ):
            raise MetricValueError()
        object.__setattr__(
            self, "is_metrics", tuple(sorted(is_metrics, key=lambda item: item.name))
        )
        object.__setattr__(
            self, "oos_metrics", tuple(sorted(oos_metrics, key=lambda item: item.name))
        )


@dataclass(frozen=True, slots=True)
class AggregatedMetricV1(_FrozenRecord):
    name: str
    is_mean: Decimal
    oos_mean: Decimal

    def __post_init__(self) -> None:
        _token(self.name)
        try:
            is_mean = parse_decimal(self.is_mean, field="metric")
            oos_mean = parse_decimal(self.oos_mean, field="metric")
        except (TypeError, ValueError, NumericError):
            raise MetricValueError() from None
        object.__setattr__(self, "is_mean", is_mean)
        object.__setattr__(self, "oos_mean", oos_mean)


@dataclass(frozen=True, slots=True, weakref_slot=True)
class OOSAggregateV1(_FrozenRecord):
    fold_manifest_sha256: str
    fold_ids: tuple[str, ...]
    metrics: tuple[AggregatedMetricV1, ...]

    def __post_init__(self) -> None:
        _sha256(self.fold_manifest_sha256)
        if (
            type(self.fold_ids) is not tuple
            or not self.fold_ids
            or any(type(value) is not str for value in self.fold_ids)
            or len(self.fold_ids) != len(set(self.fold_ids))
            or type(self.metrics) is not tuple
            or not self.metrics
            or any(type(value) is not AggregatedMetricV1 for value in self.metrics)
        ):
            raise FoldMetricsError()
        for fold_id in self.fold_ids:
            _token(fold_id)
        metrics = tuple(sorted(self.metrics, key=lambda item: item.name))
        if len({metric.name for metric in metrics}) != len(metrics):
            raise FoldMetricsError()
        object.__setattr__(self, "metrics", metrics)


_AGGREGATE_ISSUER = Issuer("bt004.oos_aggregate.v1", max_digest_nodes=MAX_DIGEST_NODES_CEILING)


def aggregate_oos(
    manifest: FoldManifestV1,
    artifacts: Iterable[CompletedFoldMetricsV1],
) -> OOSAggregateV1:
    """Require one complete, manifest-bound artifact per fold and report both means."""
    _require_manifest(manifest)
    try:
        frozen = tuple(artifacts)
    except (TypeError, ValueError):
        raise IncompleteFoldAggregationError() from None
    if (
        not frozen
        or any(type(item) is not CompletedFoldMetricsV1 for item in frozen)
        or len({item.fold_id for item in frozen}) != len(frozen)
        or {item.fold_id for item in frozen} != {fold.fold_id for fold in manifest.folds}
        or any(item.fold_manifest_sha256 != manifest.manifest_sha256 for item in frozen)
    ):
        raise IncompleteFoldAggregationError()
    by_fold = {item.fold_id: item for item in frozen}
    ordered = tuple(by_fold[fold.fold_id] for fold in manifest.folds)
    metric_names = {item.name for item in ordered[0].is_metrics}
    if not metric_names or any(
        {metric.name for metric in item.is_metrics} != metric_names
        or {metric.name for metric in item.oos_metrics} != metric_names
        for item in ordered
    ):
        raise IncompleteFoldAggregationError()

    aggregates: list[AggregatedMetricV1] = []
    try:
        for name in sorted(metric_names):
            is_mean = quotient_final(
                exact_sum(
                    next(metric.value for metric in item.is_metrics if metric.name == name)
                    for item in ordered
                ),
                len(ordered),
            )
            oos_mean = quotient_final(
                exact_sum(
                    next(metric.value for metric in item.oos_metrics if metric.name == name)
                    for item in ordered
                ),
                len(ordered),
            )
            aggregates.append(AggregatedMetricV1(name, is_mean, oos_mean))
    except (NumericError, StopIteration, TypeError, ValueError):
        raise MetricValueError() from None

    result = OOSAggregateV1(
        fold_manifest_sha256=manifest.manifest_sha256,
        fold_ids=tuple(fold.fold_id for fold in manifest.folds),
        metrics=tuple(aggregates),
    )
    try:
        return _AGGREGATE_ISSUER.issue(result)
    except SealError:
        raise InputTooLargeError() from None


__all__ = [
    "AggregatedMetricV1",
    "CompletedFoldMetricsV1",
    "FoldMetricsError",
    "IncompleteFoldAggregationError",
    "MetricValueError",
    "MetricValueV1",
    "OOSAggregateV1",
    "aggregate_oos",
]
