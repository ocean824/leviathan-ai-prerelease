"""Unit checks for the additive PRD-aligned metric catalog V2."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from infra.cloud.telemetry.catalog import (
    METRIC_CATALOG_V1,
    METRIC_CATALOG_V2,
    METRIC_LABELS_V2_OPTIONAL,
    METRIC_LABELS_V2_REQUIRED,
    MetricDefinitionV2,
    MetricError,
    MetricKind,
    MetricLabelsV1,
    MetricLabelsV2,
    MetricNameV2,
    RiskDenialReason,
)


def test_v2_catalog_has_exact_prd_names_types_units_and_dimensions() -> None:
    expected = {
        "pipeline_ingest_throughput_msgs_per_s": (MetricKind.GAUGE, "messages/second", (), None),
        "pipeline_lag_ms": (MetricKind.GAUGE, "milliseconds", (), None),
        "decision_latency_ms_p50": (MetricKind.HISTOGRAM, "milliseconds", (), 50),
        "decision_latency_ms_p95": (MetricKind.HISTOGRAM, "milliseconds", (), 95),
        "decision_latency_ms_p99": (MetricKind.HISTOGRAM, "milliseconds", (), 99),
        "order_submit_latency_ms_p50": (MetricKind.HISTOGRAM, "milliseconds", (), 50),
        "order_submit_latency_ms_p95": (MetricKind.HISTOGRAM, "milliseconds", (), 95),
        "order_submit_latency_ms_p99": (MetricKind.HISTOGRAM, "milliseconds", (), 99),
        "order_gateway_throughput_orders_per_s": (
            MetricKind.GAUGE,
            "orders/second",
            (),
            None,
        ),
        "execution_fills_total": (MetricKind.COUNTER, "count", (), None),
        "execution_fill_ratio": (MetricKind.GAUGE, "ratio", (), None),
        "error_rate_per_s": (MetricKind.GAUGE, "errors/second", ("error_code",), None),
        "queue_depth": (MetricKind.GAUGE, "count", ("queue",), None),
        "cache_hit_ratio": (MetricKind.GAUGE, "ratio", (), None),
        "connector_connectivity_status": (MetricKind.GAUGE, "0|1", (), None),
        "heartbeat_skew_ms": (MetricKind.GAUGE, "milliseconds", (), None),
    }
    assert {
        definition.name.value: (
            definition.kind,
            definition.unit,
            definition.additional_labels,
            definition.percentile,
        )
        for definition in METRIC_CATALOG_V2
        if not definition.is_extension
    } == expected
    assert all(
        not definition.is_extension
        for definition in METRIC_CATALOG_V2
        if not definition.name.value.startswith("leviathan_")
    )


def test_v2_catalog_retains_only_named_v1_extensions_and_marks_them() -> None:
    expected = {
        "leviathan_stream_freshness_lag_seconds": (MetricKind.GAUGE, "seconds"),
        "leviathan_halt_engaged": (MetricKind.GAUGE, "boolean"),
        "leviathan_risk_denials_total": (MetricKind.COUNTER, "count"),
        "leviathan_label_overflow_total": (MetricKind.COUNTER, "count"),
    }
    extensions = {
        definition.name.value: definition
        for definition in METRIC_CATALOG_V2
        if definition.is_extension
    }
    assert {
        name: (definition.kind, definition.unit) for name, definition in extensions.items()
    } == expected
    assert extensions["leviathan_risk_denials_total"].additional_labels == ("reason",)
    assert set(MetricNameV2) == {definition.name for definition in METRIC_CATALOG_V2}


def test_v2_label_schema_requires_venue_and_uses_strategy_id() -> None:
    assert METRIC_LABELS_V2_REQUIRED == (
        "service",
        "component",
        "env",
        "region",
        "instance",
        "venue",
    )
    assert METRIC_LABELS_V2_OPTIONAL == ("strategy_id", "symbol")
    labels = MetricLabelsV2(
        service="leviathan",
        component="engine",
        env="staging",
        region="local",
        instance="node-a",
        venue="XNAS",
        strategy_id="momentum.v2",
        symbol="AAPL",
        error_code="E_TIMEOUT",
        queue="orders.inbound",
        reason=RiskDenialReason.LIMIT,
    )
    assert labels.as_dict() == {
        "service": "leviathan",
        "component": "engine",
        "env": "staging",
        "region": "local",
        "instance": "node-a",
        "venue": "XNAS",
        "strategy_id": "momentum.v2",
        "symbol": "AAPL",
        "error_code": "E_TIMEOUT",
        "queue": "orders.inbound",
        "reason": "limit",
    }
    assert next(
        definition
        for definition in METRIC_CATALOG_V2
        if definition.name is MetricNameV2.ERROR_RATE_PER_S
    ).required_labels == (*METRIC_LABELS_V2_REQUIRED, "error_code")
    assert next(
        definition
        for definition in METRIC_CATALOG_V2
        if definition.name is MetricNameV2.QUEUE_DEPTH
    ).required_labels == (*METRIC_LABELS_V2_REQUIRED, "queue")

    with pytest.raises(TypeError):
        MetricLabelsV2(
            service="leviathan",
            component="engine",
            env="staging",
            region="local",
            instance="node-a",
        )  # type: ignore[call-arg]


@pytest.mark.parametrize("value", ["", "café", "A" * 65, "Bearer abcdefghijklmnopqrstuvwxyz"])
def test_v2_labels_reject_unsafe_values(value: str) -> None:
    with pytest.raises(MetricError) as error:
        MetricLabelsV2(
            service=value,
            component="engine",
            env="staging",
            region="local",
            instance="node-a",
            venue="XNAS",
        )
    assert error.value.code == "METRIC_LABEL_INVALID"
    assert error.value.args == ("METRIC_LABEL_INVALID",)


def test_v2_definition_validation_and_v1_catalog_compatibility() -> None:
    with pytest.raises(MetricError) as invalid:
        MetricDefinitionV2(
            MetricNameV2.DECISION_LATENCY_P50,
            MetricKind.HISTOGRAM,
            "milliseconds",
            percentile=95,
        )
    assert invalid.value.code == "METRIC_DEFINITION_INVALID"

    assert {
        (definition.name.value, definition.kind, definition.unit, definition.label)
        for definition in METRIC_CATALOG_V1
    } == {
        ("leviathan_decision_latency_seconds", MetricKind.HISTOGRAM, "seconds", None),
        ("leviathan_order_ack_latency_seconds", MetricKind.HISTOGRAM, "seconds", None),
        ("leviathan_pipeline_lag_seconds", MetricKind.HISTOGRAM, "seconds", None),
        ("leviathan_stream_freshness_lag_seconds", MetricKind.GAUGE, "seconds", None),
        ("leviathan_time_sync_offset_seconds", MetricKind.GAUGE, "seconds", None),
        ("leviathan_halt_engaged", MetricKind.GAUGE, "boolean", None),
        ("leviathan_orders_total", MetricKind.COUNTER, "count", "outcome"),
        ("leviathan_risk_denials_total", MetricKind.COUNTER, "count", "reason"),
        ("leviathan_label_overflow_total", MetricKind.COUNTER, "count", None),
    }
    legacy_labels = MetricLabelsV1(
        service="leviathan",
        component="engine",
        env="staging",
        region="local",
        instance="node-a",
        strategy="momentum.v1",
    )
    assert legacy_labels.as_dict()["strategy"] == "momentum.v1"
    assert "strategy_id" not in legacy_labels.as_dict()
