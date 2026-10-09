from __future__ import annotations

import sys
import time
from decimal import Decimal
from pathlib import Path

import pytest

# `infra/` is intentionally not installed as a runtime package in this bounded slice.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from infra.cloud.telemetry.catalog import (
    METRIC_CATALOG_V1,
    MetricCollectorV1,
    MetricError,
    MetricKind,
    MetricLabelsV1,
    MetricName,
    OrderOutcome,
    RiskDenialReason,
)
from infra.cloud.telemetry.health import (
    DependencyName,
    HealthError,
    HealthKernelV1,
    ProbeResultV1,
    ProbeStatus,
    livez,
)


def _labels(**updates: str) -> MetricLabelsV1:
    values = {
        "service": "leviathan",
        "component": "engine",
        "env": "test",
        "region": "local",
        "instance": "node-a",
    }
    values.update(updates)
    return MetricLabelsV1(**values)


class _Probe:
    def __init__(self, result: ProbeResultV1) -> None:
        self.result = result

    def check(self, now_ns: int) -> ProbeResultV1:
        return self.result


class _Policy:
    def allows(self, principal: object, action: str) -> bool:
        return False


def test_catalog_has_closed_names_kinds_and_units() -> None:
    by_name = {definition.name: definition for definition in METRIC_CATALOG_V1}
    assert by_name[MetricName.DECISION_LATENCY].kind is MetricKind.HISTOGRAM
    assert by_name[MetricName.DECISION_LATENCY].unit == "seconds"
    assert by_name[MetricName.ORDER_ACK_LATENCY].unit == "seconds"
    assert by_name[MetricName.STREAM_FRESHNESS_LAG].unit == "seconds"
    assert len(by_name) == 9


def test_histograms_use_injected_monotonic_time_and_report_percentiles() -> None:
    times = iter((1_000_000_000, 1_100_000_000, 2_000_000_000, 2_400_000_000))
    collector = MetricCollectorV1(monotonic_ns=lambda: next(times))
    labels = _labels()
    with collector.measure(MetricName.DECISION_LATENCY, labels):
        pass
    with collector.measure(MetricName.DECISION_LATENCY, labels):
        pass
    (sample,) = collector.snapshot()
    assert sample.name is MetricName.DECISION_LATENCY
    assert sample.value == (Decimal("0.1"), Decimal("0.4"), Decimal("0.4"))
    assert sample.count == 2


def test_decimal_float_samples_use_shortest_round_trip_value() -> None:
    collector = MetricCollectorV1()
    assert collector.observe(MetricName.DECISION_LATENCY, 0.1, _labels())
    (sample,) = collector.snapshot()
    assert sample.value == (Decimal("0.1"), Decimal("0.1"), Decimal("0.1"))


def test_counter_labels_are_closed_and_gauge_is_boolean() -> None:
    collector = MetricCollectorV1()
    labels = _labels()
    assert collector.increment(MetricName.ORDERS_TOTAL, labels, outcome=OrderOutcome.ACCEPTED)
    assert collector.increment(
        MetricName.RISK_DENIALS_TOTAL, labels, reason=RiskDenialReason.STALE_DATA
    )
    assert collector.set_gauge(MetricName.HALT_ENGAGED, True, labels)
    with pytest.raises(MetricError) as error:
        collector.increment(MetricName.ORDERS_TOTAL, labels, outcome="custom")  # type: ignore[arg-type]
    assert error.value.code == "METRIC_LABEL_INVALID"
    with pytest.raises(MetricError):
        collector.set_gauge(MetricName.HALT_ENGAGED, 2, labels)


def test_label_validation_and_optional_cardinality_overflow_are_bounded() -> None:
    with pytest.raises(MetricError):
        _labels(symbol="token=secret")
    with pytest.raises(MetricError):
        _labels(service="A" * 65)
    with pytest.raises(MetricError):
        _labels(instance="555-123-4567")
    with pytest.raises(MetricError):
        _labels(instance="aaaaBBBB1111.ccccDDDD2222.eeeeFFFF3333")
    collector = MetricCollectorV1(max_optional_values=2)
    for symbol in ("AAA", "BBB", "CCC"):
        assert collector.set_gauge(
            MetricName.STREAM_FRESHNESS_LAG, Decimal("0.1"), _labels(symbol=symbol)
        )
    snapshot = collector.snapshot()
    assert collector.overflow_count == 1
    overflow = [series for series in snapshot if series.name is MetricName.LABEL_OVERFLOW_TOTAL]
    assert len(overflow) == 1
    series = [item for item in snapshot if item.name is MetricName.STREAM_FRESHNESS_LAG]
    assert len(series) == 3
    assert any(("symbol", "__overflow__") in item.labels for item in series)


def test_series_cap_aggregates_to_overflow_without_growing_state() -> None:
    collector = MetricCollectorV1(max_series_per_metric=1)
    assert collector.set_gauge(MetricName.STREAM_FRESHNESS_LAG, 1, _labels(instance="node-a"))
    assert collector.set_gauge(MetricName.STREAM_FRESHNESS_LAG, 2, _labels(instance="node-b"))
    series = [item for item in collector.snapshot() if item.name is MetricName.STREAM_FRESHNESS_LAG]
    assert len(series) == 1
    assert ("instance", "unknown") in series[0].labels
    assert collector.overflow_count == 2


def test_livez_is_dependency_free() -> None:
    response = livez()
    assert response.status_code == 200
    assert response.statuses == {}


def test_readyz_fails_missing_stale_unhealthy_and_threshold_dependencies() -> None:
    now = 2_000_000_000
    healthy = ProbeResultV1(ProbeStatus.HEALTHY, now, Decimal("0"))
    probes = {dependency: _Probe(healthy) for dependency in DependencyName}
    probes[DependencyName.STREAMS] = _Probe(
        ProbeResultV1(ProbeStatus.HEALTHY, now, Decimal("0.300"))
    )
    probes.pop(DependencyName.CACHE)
    kernel = HealthKernelV1(
        probes=probes,
        policy=_Policy(),
        utc_ns=lambda: now,
        probe_timeout_ns=10_000_000,
    )
    try:
        response = kernel.readyz()
        assert response.status_code == 503
        assert response.statuses[DependencyName.CACHE] is ProbeStatus.UNKNOWN
        assert response.statuses[DependencyName.STREAMS] is ProbeStatus.UNHEALTHY
        assert set(response.statuses) == set(DependencyName)
        with pytest.raises(TypeError):
            response.statuses[DependencyName.DB] = ProbeStatus.UNKNOWN  # type: ignore[index]
    finally:
        kernel.close()


def test_readyz_fails_stale_observation_and_time_sync_skew() -> None:
    now = 8_000_000_000
    healthy = ProbeResultV1(ProbeStatus.HEALTHY, now, Decimal("0"))
    probes = {dependency: _Probe(healthy) for dependency in DependencyName}
    probes[DependencyName.DB] = _Probe(
        ProbeResultV1(ProbeStatus.HEALTHY, now - 5_000_000_001, Decimal("0"))
    )
    probes[DependencyName.TIME_SYNC] = _Probe(
        ProbeResultV1(ProbeStatus.HEALTHY, now, Decimal("0.020"))
    )
    kernel = HealthKernelV1(probes=probes, policy=_Policy(), utc_ns=lambda: now)
    try:
        response = kernel.readyz()
        assert response.status_code == 503
        assert response.statuses[DependencyName.DB] is ProbeStatus.UNHEALTHY
        assert response.statuses[DependencyName.TIME_SYNC] is ProbeStatus.UNHEALTHY
    finally:
        kernel.close()


def test_probe_failure_and_timeout_fail_closed() -> None:
    now = 3_000_000_000

    class Raises:
        def check(self, now_ns: int) -> ProbeResultV1:
            raise RuntimeError("must not escape")

    class Hangs:
        def check(self, now_ns: int) -> ProbeResultV1:
            time.sleep(0.03)
            return ProbeResultV1(ProbeStatus.HEALTHY, now)

    kernel = HealthKernelV1(
        probes={DependencyName.DB: Raises(), DependencyName.CACHE: Hangs()},
        policy=_Policy(),
        utc_ns=lambda: now,
        probe_timeout_ns=1_000_000,
    )
    try:
        response = kernel.readyz()
        assert response.statuses[DependencyName.DB] is ProbeStatus.UNHEALTHY
        assert response.statuses[DependencyName.CACHE] is ProbeStatus.UNHEALTHY
        assert response.status_code == 503
    finally:
        kernel.close()


def test_timed_out_inflight_probe_never_becomes_healthy_on_reuse() -> None:
    now = 4_000_000_000

    class SlowHealthy:
        calls = 0

        def check(self, now_ns: int) -> ProbeResultV1:
            self.calls += 1
            time.sleep(0.08)
            return ProbeResultV1(ProbeStatus.HEALTHY, now)

    probe = SlowHealthy()
    kernel = HealthKernelV1(
        probes={DependencyName.DB: probe},
        policy=_Policy(),
        utc_ns=lambda: now,
        probe_timeout_ns=50_000_000,
    )
    try:
        first = kernel.readyz()
        assert first.statuses[DependencyName.DB] is ProbeStatus.UNHEALTHY
        time.sleep(0.04)
        second = kernel.readyz()
        assert second.statuses[DependencyName.DB] is ProbeStatus.UNHEALTHY
        assert probe.calls == 1
    finally:
        kernel.close()


def test_healthz_denial_is_uniform_and_content_free() -> None:
    kernel = HealthKernelV1(probes={}, policy=_Policy(), utc_ns=lambda: 1)
    try:
        with pytest.raises(HealthError) as error:
            kernel.healthz(object())  # type: ignore[arg-type]
        assert error.value.code == "HEALTH_ACCESS_DENIED"
        assert str(error.value) == "HEALTH_ACCESS_DENIED"
    finally:
        kernel.close()
