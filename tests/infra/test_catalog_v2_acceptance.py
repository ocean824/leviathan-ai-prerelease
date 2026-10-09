"""Independent acceptance for the PRD-aligned additive V2 metrics catalog."""

from __future__ import annotations

import sys
from dataclasses import fields
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from infra.cloud.telemetry.catalog import (
    METRIC_CATALOG_V1,
    METRIC_CATALOG_V2,
    MetricKind,
    MetricLabelsV1,
    MetricLabelsV2,
    MetricName,
    MetricNameV2,
)

_COMMON_LABELS = ("service", "component", "env", "region", "instance", "venue")

_PRD_METRICS = {
    "pipeline_ingest_throughput_msgs_per_s": ("gauge", "messages/second", None, ()),
    "pipeline_lag_ms": ("gauge", "milliseconds", None, ()),
    "decision_latency_ms_p50": ("histogram", "milliseconds", 50, ()),
    "decision_latency_ms_p95": ("histogram", "milliseconds", 95, ()),
    "decision_latency_ms_p99": ("histogram", "milliseconds", 99, ()),
    "order_submit_latency_ms_p50": ("histogram", "milliseconds", 50, ()),
    "order_submit_latency_ms_p95": ("histogram", "milliseconds", 95, ()),
    "order_submit_latency_ms_p99": ("histogram", "milliseconds", 99, ()),
    "order_gateway_throughput_orders_per_s": ("gauge", "orders/second", None, ()),
    "execution_fills_total": ("counter", "count", None, ()),
    "execution_fill_ratio": ("gauge", "ratio", None, ()),
    "error_rate_per_s": ("gauge", "errors/second", None, ("error_code",)),
    "queue_depth": ("gauge", "count", None, ("queue",)),
    "cache_hit_ratio": ("gauge", "ratio", None, ()),
    "connector_connectivity_status": ("gauge", "0|1", None, ()),
    "heartbeat_skew_ms": ("gauge", "milliseconds", None, ()),
}

_EXTENSION_METRICS = {
    "leviathan_stream_freshness_lag_seconds": ("gauge", "seconds", None, ()),
    "leviathan_halt_engaged": ("gauge", "boolean", None, ()),
    "leviathan_risk_denials_total": ("counter", "count", None, ("reason",)),
    "leviathan_label_overflow_total": ("counter", "count", None, ()),
}


def _v2_catalog() -> dict[str, object]:
    return {definition.name.value: definition for definition in METRIC_CATALOG_V2}


def test_v2_catalog_matches_every_prd_metric_name_type_unit_and_label() -> None:
    catalog = _v2_catalog()

    assert set(catalog) == set(_PRD_METRICS) | set(_EXTENSION_METRICS)
    for name, (kind, unit, percentile, extra_labels) in _PRD_METRICS.items():
        definition = catalog[name]
        assert definition.name.value == name
        assert definition.kind.value == kind
        assert definition.unit == unit
        assert definition.percentile == percentile
        assert definition.additional_labels == extra_labels
        assert definition.required_labels == _COMMON_LABELS + extra_labels
        assert definition.is_extension is False


def test_v1_only_metrics_remain_explicitly_marked_extensions() -> None:
    catalog = _v2_catalog()

    for name, (kind, unit, percentile, extra_labels) in _EXTENSION_METRICS.items():
        definition = catalog[name]
        assert definition.kind.value == kind
        assert definition.unit == unit
        assert definition.percentile == percentile
        assert definition.additional_labels == extra_labels
        assert definition.is_extension is True

    assert {name for name, definition in catalog.items() if definition.is_extension} == set(
        _EXTENSION_METRICS
    )


def test_v2_labels_require_venue_and_rename_strategy_to_strategy_id() -> None:
    label_fields = {field.name for field in fields(MetricLabelsV2)}
    assert {"service", "component", "env", "region", "instance", "venue"} <= label_fields
    assert "strategy_id" in label_fields
    assert "strategy" not in label_fields

    labels = MetricLabelsV2(
        service="leviathan",
        component="engine",
        env="test",
        region="local",
        instance="node-a",
        venue="XCME",
        strategy_id="mean-reversion",
        symbol="ES",
    )
    assert labels.as_dict() == {
        "service": "leviathan",
        "component": "engine",
        "env": "test",
        "region": "local",
        "instance": "node-a",
        "venue": "XCME",
        "strategy_id": "mean-reversion",
        "symbol": "ES",
    }
    with pytest.raises(TypeError):
        MetricLabelsV2(
            service="leviathan",
            component="engine",
            env="test",
            region="local",
            instance="node-a",
        )


def test_v1_catalog_and_label_api_remain_unchanged() -> None:
    assert tuple(
        (item.name.value, item.kind.value, item.unit, item.label) for item in METRIC_CATALOG_V1
    ) == (
        ("leviathan_decision_latency_seconds", "histogram", "seconds", None),
        ("leviathan_order_ack_latency_seconds", "histogram", "seconds", None),
        ("leviathan_pipeline_lag_seconds", "histogram", "seconds", None),
        ("leviathan_stream_freshness_lag_seconds", "gauge", "seconds", None),
        ("leviathan_time_sync_offset_seconds", "gauge", "seconds", None),
        ("leviathan_halt_engaged", "gauge", "boolean", None),
        ("leviathan_orders_total", "counter", "count", "outcome"),
        ("leviathan_risk_denials_total", "counter", "count", "reason"),
        ("leviathan_label_overflow_total", "counter", "count", None),
    )
    assert MetricName.DECISION_LATENCY.value == "leviathan_decision_latency_seconds"
    assert MetricKind.HISTOGRAM.value == "histogram"
    assert {field.name for field in fields(MetricLabelsV1)} == {
        "service",
        "component",
        "env",
        "region",
        "instance",
        "strategy",
        "symbol",
        "venue",
    }
    assert MetricLabelsV1("leviathan", "engine", "test", "local", "node-a").as_dict() == {
        "service": "leviathan",
        "component": "engine",
        "env": "test",
        "region": "local",
        "instance": "node-a",
    }


def test_v2_public_names_are_the_prd_and_extension_set() -> None:
    assert {name.value for name in MetricNameV2} == set(_PRD_METRICS) | set(_EXTENSION_METRICS)
