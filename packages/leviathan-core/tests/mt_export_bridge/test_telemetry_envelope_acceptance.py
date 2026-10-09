from __future__ import annotations

import json
from decimal import Decimal

import pytest

from leviathan_core.execution.broker_port_v1 import BrokerVenue
from leviathan_core.mt_export_telemetry import (
    TelemetryAlertCodeV1,
    TelemetryAlertSeverityV1,
    TelemetryAlertSummaryV1,
    TelemetryEnvelopeV1,
    TelemetryEnvironmentV1,
    TelemetryError,
    TelemetryErrorCodeV1,
    TelemetryLabelNameV1,
    TelemetryLabelV1,
    TelemetryMetricNameV1,
    TelemetryMetricSummaryV1,
    TelemetryQueueV1,
    TelemetryRegionV1,
    TelemetryRiskDenialReasonV1,
    TelemetryServiceV1,
)
from leviathan_core.observability.models import ErrorCode

NOW_NS = 1_800_000_000_000_000_000
MAX_ENVELOPE_BYTES = 32_768
BASE_LABELS = (
    TelemetryLabelV1(TelemetryLabelNameV1.SERVICE, TelemetryServiceV1.MT_BRIDGE),
    TelemetryLabelV1(TelemetryLabelNameV1.COMPONENT, "agent"),
    TelemetryLabelV1(TelemetryLabelNameV1.ENV, TelemetryEnvironmentV1.TEST),
    TelemetryLabelV1(TelemetryLabelNameV1.REGION, TelemetryRegionV1.LOCAL),
    TelemetryLabelV1(TelemetryLabelNameV1.INSTANCE, "agent-01"),
    TelemetryLabelV1(TelemetryLabelNameV1.VENUE, BrokerVenue.MT5),
)


def _metric(
    *,
    name: TelemetryMetricNameV1 = TelemetryMetricNameV1.PIPELINE_LAG,
    value: Decimal | int | str = Decimal("12.5"),
    labels: tuple[TelemetryLabelV1, ...] = BASE_LABELS,
) -> TelemetryMetricSummaryV1:
    return TelemetryMetricSummaryV1(name=name, value=value, labels=labels)


def _create(
    *,
    agent_id: str = "agent-01",
    artifact_id: str = "artifact-01",
    correlation_id: str = "corr-01",
    occurred_utc_ns: int = NOW_NS,
    utc_ns=lambda: NOW_NS,
    alerts: tuple[TelemetryAlertSummaryV1, ...] = (),
    metrics: tuple[TelemetryMetricSummaryV1, ...] = (),
    schema_version: int = 1,
    future_tolerance_ns: int = 5_000_000_000,
) -> TelemetryEnvelopeV1:
    return TelemetryEnvelopeV1.create(
        agent_id=agent_id,
        artifact_id=artifact_id,
        correlation_id=correlation_id,
        occurred_utc_ns=occurred_utc_ns,
        utc_ns=utc_ns,
        alerts=alerts,
        metrics=metrics,
        schema_version=schema_version,
        future_tolerance_ns=future_tolerance_ns,
    )


def test_version_one_envelope_is_correlated_and_within_byte_limit() -> None:
    event = _create(metrics=(_metric(),))
    payload = json.loads(event.to_json())

    assert payload["schema_version"] == 1
    assert payload["agent_id"] == "agent-01"
    assert payload["artifact_id"] == "artifact-01"
    assert payload["correlation_id"] == "corr-01"
    assert payload["occurred_utc_ns"] == NOW_NS
    assert event.serialized_size_bytes == len(event.to_json().encode("utf-8"))
    assert event.serialized_size_bytes <= MAX_ENVELOPE_BYTES


@pytest.mark.parametrize("version", [0, 2, True])
def test_unknown_or_non_exact_version_is_rejected_without_echo(version: object) -> None:
    with pytest.raises(TelemetryError) as raised:
        _create(schema_version=version)  # type: ignore[arg-type]

    assert raised.value.code is TelemetryErrorCodeV1.VERSION_UNSUPPORTED
    assert str(raised.value) == TelemetryErrorCodeV1.VERSION_UNSUPPORTED.value
    assert str(version) not in str(raised.value)


@pytest.mark.parametrize("field", ["agent_id", "artifact_id", "correlation_id"])
def test_required_identifiers_reject_empty_values_without_echo(field: str) -> None:
    kwargs = {field: ""}
    with pytest.raises(TelemetryError) as raised:
        _create(**kwargs)

    assert raised.value.code is TelemetryErrorCodeV1.IDENTIFIER_INVALID


def test_correlation_id_is_a_required_argument() -> None:
    with pytest.raises(TypeError):
        TelemetryEnvelopeV1.create(
            agent_id="agent-01",
            artifact_id="artifact-01",
            occurred_utc_ns=NOW_NS,
            utc_ns=lambda: NOW_NS,
        )  # type: ignore[call-arg]


def test_identifier_length_boundary_is_exact() -> None:
    accepted_id = "a" * 64
    rejected_id = accepted_id + "a"
    accepted = _create(agent_id=accepted_id)
    assert accepted.agent_id == accepted_id

    with pytest.raises(TelemetryError) as raised:
        _create(agent_id=rejected_id)
    assert raised.value.code is TelemetryErrorCodeV1.IDENTIFIER_INVALID
    assert rejected_id not in str(raised.value)


def test_alert_and_metric_collection_bounds_are_enforced() -> None:
    alert = TelemetryAlertSummaryV1(
        TelemetryAlertCodeV1.AGENT_OFFLINE,
        TelemetryAlertSeverityV1.WARNING,
    )
    assert len(_create(alerts=(alert,) * 32).alerts) == 32

    with pytest.raises(TelemetryError) as too_many_alerts:
        _create(alerts=(alert,) * 33)
    assert too_many_alerts.value.code is TelemetryErrorCodeV1.LIMIT_EXCEEDED

    metric = _metric()
    with pytest.raises(TelemetryError) as too_many_metrics:
        _create(metrics=(metric,) * 129)
    assert too_many_metrics.value.code is TelemetryErrorCodeV1.LIMIT_EXCEEDED


@pytest.mark.parametrize("environment", tuple(TelemetryEnvironmentV1))
def test_environment_label_accepts_only_closed_catalog_values(
    environment: TelemetryEnvironmentV1,
) -> None:
    labels = (
        *BASE_LABELS[:2],
        TelemetryLabelV1(TelemetryLabelNameV1.ENV, environment),
        *BASE_LABELS[3:],
    )
    event = _create(metrics=(_metric(labels=labels),))

    assert event.metrics[0].labels[2].value == environment.value


def test_environment_label_rejects_unknown_value_without_echo() -> None:
    labels = (
        *BASE_LABELS[:2],
        TelemetryLabelV1(TelemetryLabelNameV1.ENV, "qa"),
        *BASE_LABELS[3:],
    )
    with pytest.raises(TelemetryError) as raised:
        _create(metrics=(_metric(labels=labels),))

    assert raised.value.code is TelemetryErrorCodeV1.LABEL_INVALID
    assert "qa" not in str(raised.value)


def test_label_cardinality_accepts_one_hundred_and_rejects_one_hundred_one() -> None:
    accepted_metrics = tuple(
        _metric(
            labels=(
                *BASE_LABELS,
                TelemetryLabelV1(TelemetryLabelNameV1.STRATEGY_ID, f"strategy-{index:03}"),
            )
        )
        for index in range(100)
    )
    accepted = _create(metrics=accepted_metrics)
    assert len(accepted.metrics) == 100

    # The last record must introduce the 101st value for the bounded label key.
    over_limit = (
        *accepted_metrics,
        _metric(
            labels=(
                *BASE_LABELS,
                TelemetryLabelV1(TelemetryLabelNameV1.STRATEGY_ID, "strategy-100"),
            )
        ),
    )
    assert len(over_limit) == 101
    with pytest.raises(TelemetryError) as raised:
        _create(metrics=over_limit)
    assert raised.value.code is TelemetryErrorCodeV1.LIMIT_EXCEEDED
    assert "strategy-100" not in str(raised.value)


def test_eight_digit_label_value_is_allowed() -> None:
    labels = (
        *BASE_LABELS[:4],
        TelemetryLabelV1(TelemetryLabelNameV1.INSTANCE, "12345678"),
        *BASE_LABELS[5:],
    )
    event = _create(metrics=(_metric(labels=labels),))

    assert event.metrics[0].labels[4].value == "12345678"


@pytest.mark.parametrize("value", ["123456789", "1234567890123456"])
def test_nine_or_more_digit_label_value_is_rejected(value: str) -> None:
    labels = (
        *BASE_LABELS[:4],
        TelemetryLabelV1(TelemetryLabelNameV1.INSTANCE, value),
        *BASE_LABELS[5:],
    )
    with pytest.raises(TelemetryError) as raised:
        _create(metrics=(_metric(labels=labels),))

    assert raised.value.code is TelemetryErrorCodeV1.LABEL_INVALID
    assert value not in str(raised.value)
    assert value not in repr(raised.value)


def test_uppercase_symbol_is_canonicalized_to_lowercase() -> None:
    labels = (
        *BASE_LABELS,
        TelemetryLabelV1(TelemetryLabelNameV1.SYMBOL, "EURUSD"),
    )
    event = _create(metrics=(_metric(labels=labels),))
    payload = json.loads(event.to_json())

    assert event.metrics[0].labels[-1].value == "eurusd"
    assert payload["metrics"][0]["labels"][-1]["value"] == "eurusd"


def test_generic_label_rejects_dotted_identifier() -> None:
    labels = (
        *BASE_LABELS[:3],
        TelemetryLabelV1(TelemetryLabelNameV1.REGION, "region.us"),
        *BASE_LABELS[4:],
    )
    with pytest.raises(TelemetryError) as raised:
        _create(metrics=(_metric(labels=labels),))

    assert raised.value.code is TelemetryErrorCodeV1.LABEL_INVALID
    assert "region.us" not in str(raised.value)


@pytest.mark.parametrize("value", ["password", "hunter2", "policy"])
def test_reason_label_rejects_password_and_unknown_reason(value: str) -> None:
    labels = (
        *BASE_LABELS,
        TelemetryLabelV1(TelemetryLabelNameV1.REASON, value),
    )
    with pytest.raises(TelemetryError) as raised:
        _create(metrics=(_metric(name=TelemetryMetricNameV1.RISK_DENIALS_TOTAL, labels=labels),))

    assert raised.value.code is TelemetryErrorCodeV1.LABEL_INVALID
    assert value not in str(raised.value)
    assert value not in repr(raised.value)


@pytest.mark.parametrize("reason", tuple(TelemetryRiskDenialReasonV1))
def test_reason_label_accepts_each_catalog_enum_value(
    reason: TelemetryRiskDenialReasonV1,
) -> None:
    labels = (
        *BASE_LABELS,
        TelemetryLabelV1(TelemetryLabelNameV1.REASON, reason),
    )
    event = _create(
        metrics=(_metric(name=TelemetryMetricNameV1.RISK_DENIALS_TOTAL, labels=labels),)
    )
    payload = json.loads(event.to_json())

    assert payload["metrics"][0]["labels"][-1]["value"] == reason.value


def test_metric_specific_correlation_labels_are_required() -> None:
    with pytest.raises(TelemetryError) as raised:
        _create(metrics=(_metric(name=TelemetryMetricNameV1.QUEUE_DEPTH),))
    assert raised.value.code is TelemetryErrorCodeV1.LABEL_INVALID


def test_serialized_payload_size_limit_is_enforced() -> None:
    label_names = (
        TelemetryLabelNameV1.SERVICE,
        TelemetryLabelNameV1.COMPONENT,
        TelemetryLabelNameV1.ENV,
        TelemetryLabelNameV1.REGION,
        TelemetryLabelNameV1.INSTANCE,
        TelemetryLabelNameV1.VENUE,
        TelemetryLabelNameV1.ERROR_CODE,
        TelemetryLabelNameV1.STRATEGY_ID,
        TelemetryLabelNameV1.SYMBOL,
    )
    prefixes = ("s", "c", "e", "r", "i", "v", "x", "t", "y")
    metrics = tuple(
        _metric(
            name=TelemetryMetricNameV1.ERROR_RATE_PER_S,
            labels=tuple(
                TelemetryLabelV1(
                    name,
                    TelemetryEnvironmentV1.TEST
                    if name is TelemetryLabelNameV1.ENV
                    else f"Y{index:03}Z"
                    if name is TelemetryLabelNameV1.SYMBOL
                    else TelemetryServiceV1.MT_BRIDGE
                    if name is TelemetryLabelNameV1.SERVICE
                    else TelemetryRegionV1.LOCAL
                    if name is TelemetryLabelNameV1.REGION
                    else BrokerVenue.MT5
                    if name is TelemetryLabelNameV1.VENUE
                    else TelemetryErrorCodeV1.INPUT_INVALID
                    if name is TelemetryLabelNameV1.ERROR_CODE
                    else f"{prefix}{index:03}" + "z" * 60,
                )
                for name, prefix in zip(label_names, prefixes, strict=True)
            ),
        )
        for index in range(100)
    )

    with pytest.raises(TelemetryError) as raised:
        _create(metrics=metrics)
    assert raised.value.code is TelemetryErrorCodeV1.PAYLOAD_TOO_LARGE
    assert "zzzz" not in str(raised.value)


@pytest.mark.parametrize(
    "value",
    [
        "api_key=secret-canary-value",
        "Bearer secret-canary-value",
        "operator entered arbitrary free text",
        "customer@example.invalid",
        "123456789",
        "1234567890123456",
        "dot.value",
    ],
)
def test_secret_pii_and_free_text_label_values_are_rejected(value: str) -> None:
    labels = (
        *BASE_LABELS,
        TelemetryLabelV1(TelemetryLabelNameV1.SYMBOL, value),
    )
    with pytest.raises(TelemetryError) as raised:
        _create(metrics=(_metric(labels=labels),))

    assert raised.value.code is TelemetryErrorCodeV1.LABEL_INVALID
    assert value not in str(raised.value)
    assert value not in repr(raised.value)
    assert all(value not in str(arg) for arg in raised.value.args)


def test_envelope_has_no_free_text_or_raw_payload_fields() -> None:
    event = _create(metrics=(_metric(),))
    payload = json.loads(event.to_json())

    assert set(payload) == {
        "schema_version",
        "event_type",
        "agent_id",
        "artifact_id",
        "correlation_id",
        "occurred_utc_ns",
        "alerts",
        "metrics",
    }
    assert "payload" not in TelemetryEnvelopeV1.model_fields
    assert "message" not in TelemetryEnvelopeV1.model_fields
    assert "raw_fills" not in TelemetryEnvelopeV1.model_fields


def test_future_tolerance_exact_boundary_and_one_nanosecond_over() -> None:
    accepted = _create(
        occurred_utc_ns=NOW_NS + 5,
        utc_ns=lambda: NOW_NS,
        future_tolerance_ns=5,
    )
    assert accepted.occurred_utc_ns == NOW_NS + 5

    with pytest.raises(TelemetryError) as raised:
        _create(
            occurred_utc_ns=NOW_NS + 6,
            utc_ns=lambda: NOW_NS,
            future_tolerance_ns=5,
        )
    assert raised.value.code is TelemetryErrorCodeV1.TIME_INVALID


@pytest.mark.parametrize(
    ("label_name", "value"),
    [
        (TelemetryLabelNameV1.COMPONENT, "password"),
        (TelemetryLabelNameV1.INSTANCE, "hunter2"),
        (TelemetryLabelNameV1.COMPONENT, "api-gateway"),
    ],
)
def test_denied_component_and_instance_values_fail_without_echo(
    label_name: TelemetryLabelNameV1,
    value: str,
) -> None:
    labels = tuple(
        TelemetryLabelV1(label.name, value if label.name is label_name else label.value)
        for label in BASE_LABELS
    )
    with pytest.raises(TelemetryError) as raised:
        _create(metrics=(_metric(labels=labels),))

    assert raised.value.code is TelemetryErrorCodeV1.LABEL_INVALID
    assert value not in str(raised.value)
    assert value not in repr(raised.value)
    assert all(value not in str(arg) for arg in raised.value.args)


def test_component_bridge_one_is_accepted() -> None:
    labels = tuple(
        TelemetryLabelV1(
            label.name,
            "bridge-1" if label.name is TelemetryLabelNameV1.COMPONENT else label.value,
        )
        for label in BASE_LABELS
    )
    event = _create(metrics=(_metric(labels=labels),))

    assert event.metrics[0].labels[1].value == "bridge-1"


@pytest.mark.parametrize("service", tuple(TelemetryServiceV1))
def test_service_label_requires_and_accepts_each_typed_value(service: TelemetryServiceV1) -> None:
    labels = tuple(
        TelemetryLabelV1(
            label.name, service if label.name is TelemetryLabelNameV1.SERVICE else label.value
        )
        for label in BASE_LABELS
    )
    event = _create(metrics=(_metric(labels=labels),))

    assert event.metrics[0].labels[0].value == service.value


@pytest.mark.parametrize("region", tuple(TelemetryRegionV1))
def test_region_label_requires_and_accepts_each_typed_value(region: TelemetryRegionV1) -> None:
    labels = tuple(
        TelemetryLabelV1(
            label.name, region if label.name is TelemetryLabelNameV1.REGION else label.value
        )
        for label in BASE_LABELS
    )
    event = _create(metrics=(_metric(labels=labels),))

    assert event.metrics[0].labels[3].value == region.value


@pytest.mark.parametrize("venue", tuple(BrokerVenue))
def test_venue_label_accepts_each_typed_broker_venue(venue: BrokerVenue) -> None:
    labels = tuple(
        TelemetryLabelV1(
            label.name, venue if label.name is TelemetryLabelNameV1.VENUE else label.value
        )
        for label in BASE_LABELS
    )
    event = _create(metrics=(_metric(labels=labels),))

    assert event.metrics[0].labels[5].value == venue.value


@pytest.mark.parametrize(
    ("label_name", "raw_value"),
    [
        (TelemetryLabelNameV1.SERVICE, "mt-bridge"),
        (TelemetryLabelNameV1.ENV, "test"),
        (TelemetryLabelNameV1.REGION, "local"),
        (TelemetryLabelNameV1.VENUE, "MT5"),
    ],
)
def test_closed_domain_rejects_raw_string_even_when_catalog_value(
    label_name: TelemetryLabelNameV1, raw_value: str
) -> None:
    labels = tuple(
        TelemetryLabelV1(label.name, raw_value if label.name is label_name else label.value)
        for label in BASE_LABELS
    )
    with pytest.raises(TelemetryError) as raised:
        _create(metrics=(_metric(labels=labels),))

    assert raised.value.code is TelemetryErrorCodeV1.LABEL_INVALID
    assert raw_value not in str(raised.value)
    assert raw_value not in repr(raised.value)


def test_queue_label_requires_typed_queue_value() -> None:
    labels = (
        *BASE_LABELS,
        TelemetryLabelV1(TelemetryLabelNameV1.QUEUE, TelemetryQueueV1.ORDERS_INBOUND),
    )
    event = _create(metrics=(_metric(name=TelemetryMetricNameV1.QUEUE_DEPTH, labels=labels),))
    assert event.metrics[0].labels[-1].value == TelemetryQueueV1.ORDERS_INBOUND.value

    raw_labels = (*BASE_LABELS, TelemetryLabelV1(TelemetryLabelNameV1.QUEUE, "orders.inbound"))
    with pytest.raises(TelemetryError) as raised:
        _create(metrics=(_metric(name=TelemetryMetricNameV1.QUEUE_DEPTH, labels=raw_labels),))
    assert raised.value.code is TelemetryErrorCodeV1.LABEL_INVALID
    assert "orders.inbound" not in str(raised.value)


@pytest.mark.parametrize(
    "error_code",
    [TelemetryErrorCodeV1.INPUT_INVALID, ErrorCode.INVALID_INPUT],
)
def test_error_code_label_accepts_each_declared_error_enum(
    error_code: TelemetryErrorCodeV1 | ErrorCode,
) -> None:
    labels = (
        *BASE_LABELS,
        TelemetryLabelV1(TelemetryLabelNameV1.ERROR_CODE, error_code),
    )
    event = _create(metrics=(_metric(name=TelemetryMetricNameV1.ERROR_RATE_PER_S, labels=labels),))
    assert event.metrics[0].labels[-1].value == error_code.value


@pytest.mark.parametrize("raw_value", ["TELEMETRY_INPUT_INVALID", "INVALID_INPUT"])
def test_error_code_label_rejects_raw_string(raw_value: str) -> None:
    labels = (*BASE_LABELS, TelemetryLabelV1(TelemetryLabelNameV1.ERROR_CODE, raw_value))
    with pytest.raises(TelemetryError) as raised:
        _create(metrics=(_metric(name=TelemetryMetricNameV1.ERROR_RATE_PER_S, labels=labels),))
    assert raised.value.code is TelemetryErrorCodeV1.LABEL_INVALID
    assert raw_value not in str(raised.value)


@pytest.mark.parametrize(
    ("label_name", "value"),
    [
        (TelemetryLabelNameV1.COMPONENT, "agent-123456789-worker"),
        (TelemetryLabelNameV1.INSTANCE, "bridge-123456789-01"),
        (TelemetryLabelNameV1.STRATEGY_ID, "strategy-123456789-live"),
    ],
)
def test_generic_id_labels_reject_embedded_nine_digit_run_without_echo(
    label_name: TelemetryLabelNameV1, value: str
) -> None:
    labels = (
        *BASE_LABELS,
        *(
            (TelemetryLabelV1(TelemetryLabelNameV1.STRATEGY_ID, value),)
            if label_name is TelemetryLabelNameV1.STRATEGY_ID
            else ()
        ),
    )
    labels = tuple(
        TelemetryLabelV1(label.name, value if label.name is label_name else label.value)
        for label in labels
    )
    with pytest.raises(TelemetryError) as raised:
        _create(metrics=(_metric(labels=labels),))

    assert raised.value.code is TelemetryErrorCodeV1.LABEL_INVALID
    assert value not in str(raised.value)
    assert value not in repr(raised.value)
    assert all(value not in str(arg) for arg in raised.value.args)
