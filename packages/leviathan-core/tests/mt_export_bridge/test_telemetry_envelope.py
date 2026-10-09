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
    TelemetryEventTypeV1,
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
from leviathan_core.seal import require

NOW_NS = 1_800_000_000_000_000_000
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


def test_envelope_is_versioned_sealed_and_correlated_to_artifact() -> None:
    event = _create(
        alerts=(
            TelemetryAlertSummaryV1(
                TelemetryAlertCodeV1.CHECKSUM_MISMATCH,
                TelemetryAlertSeverityV1.ERROR,
                2,
            ),
        ),
        metrics=(_metric(),),
    )

    require(event, "mtbr.telemetry_envelope.v1")
    payload = json.loads(event.to_json())
    assert payload["schema_version"] == 1
    assert payload["event_type"] == TelemetryEventTypeV1.AGENT_TELEMETRY.value
    assert payload["agent_id"] == "agent-01"
    assert payload["artifact_id"] == "artifact-01"
    assert payload["correlation_id"] == "corr-01"
    assert payload["occurred_utc_ns"] == NOW_NS
    assert payload["alerts"][0]["code"] == TelemetryAlertCodeV1.CHECKSUM_MISMATCH.value
    assert payload["metrics"][0]["name"] == TelemetryMetricNameV1.PIPELINE_LAG.value
    assert event.serialized_size_bytes <= 32_768


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("agent_id", "Bearer live-credential-value"),
        ("artifact_id", "api_key=hidden-value"),
        ("correlation_id", "person@example.com"),
    ],
)
def test_secret_or_pii_shaped_identifiers_fail_without_echo(field: str, value: str) -> None:
    kwargs = {field: value}
    with pytest.raises(TelemetryError) as exc_info:
        _create(**kwargs)

    assert exc_info.value.code is TelemetryErrorCodeV1.IDENTIFIER_INVALID
    assert value not in str(exc_info.value)
    assert value not in repr(exc_info.value)
    assert all(value not in str(arg) for arg in exc_info.value.args)


@pytest.mark.parametrize("value", ["password", "hunter2", "api_key=secret", "caller text", "other"])
def test_nonclosed_reason_values_are_rejected_without_echo(value: str) -> None:
    labels = (*BASE_LABELS, TelemetryLabelV1(TelemetryLabelNameV1.REASON, value))
    with pytest.raises(TelemetryError) as exc_info:
        _create(metrics=(_metric(name=TelemetryMetricNameV1.RISK_DENIALS_TOTAL, labels=labels),))

    assert exc_info.value.code is TelemetryErrorCodeV1.LABEL_INVALID
    assert value not in str(exc_info.value)
    assert value not in repr(exc_info.value)
    assert value not in str(exc_info.value.args)


@pytest.mark.parametrize("reason", list(TelemetryRiskDenialReasonV1))
def test_closed_risk_denial_reason_values_are_accepted(reason: TelemetryRiskDenialReasonV1) -> None:
    labels = (*BASE_LABELS, TelemetryLabelV1(TelemetryLabelNameV1.REASON, reason))
    event = _create(
        metrics=(_metric(name=TelemetryMetricNameV1.RISK_DENIALS_TOTAL, labels=labels),)
    )

    payload = json.loads(event.to_json())
    assert payload["metrics"][0]["labels"][-1]["value"] == reason.value


@pytest.mark.parametrize("env", list(TelemetryEnvironmentV1))
def test_closed_environment_values_are_accepted(env: TelemetryEnvironmentV1) -> None:
    labels = tuple(
        TelemetryLabelV1(
            label.name,
            env if label.name is TelemetryLabelNameV1.ENV else label.value,
        )
        for label in BASE_LABELS
    )
    assert _create(metrics=(_metric(labels=labels),)).metrics[0].labels[2].value == env.value


def test_envelope_has_no_free_text_or_redaction_field() -> None:
    event = _create(metrics=(_metric(),))
    payload = json.loads(event.to_json())

    assert "redacted" not in TelemetryEnvelopeV1.model_fields
    assert "redacted" not in payload
    assert "payload" not in TelemetryEnvelopeV1.model_fields
    assert "message" not in TelemetryEnvelopeV1.model_fields


def test_label_values_must_use_exact_lowercase_identifier_grammar() -> None:
    value = "AbCd"
    labels = tuple(
        TelemetryLabelV1(
            label.name,
            value if label.name is TelemetryLabelNameV1.SERVICE else label.value,
        )
        for label in BASE_LABELS
    )
    with pytest.raises(TelemetryError) as exc_info:
        _create(metrics=(_metric(labels=labels),))
    assert exc_info.value.code is TelemetryErrorCodeV1.LABEL_INVALID
    assert value not in str(exc_info.value)


def test_symbol_uses_closed_grammar_and_is_normalized_to_lowercase() -> None:
    labels = (*BASE_LABELS, TelemetryLabelV1(TelemetryLabelNameV1.SYMBOL, "EURUSD"))
    event = _create(metrics=(_metric(labels=labels),))
    assert event.metrics[0].labels[-1].value == "eurusd"

    for invalid in ("lowercase", "bad_symbol", "symbol-name-too-long-for-limit"):
        bad_labels = (*BASE_LABELS, TelemetryLabelV1(TelemetryLabelNameV1.SYMBOL, invalid))
        with pytest.raises(TelemetryError) as exc_info:
            _create(metrics=(_metric(labels=bad_labels),))
        assert exc_info.value.code is TelemetryErrorCodeV1.LABEL_INVALID
        assert invalid not in str(exc_info.value)


def test_short_numeric_label_is_allowed_but_long_numeric_pii_is_rejected() -> None:
    accepted_labels = (*BASE_LABELS, TelemetryLabelV1(TelemetryLabelNameV1.SYMBOL, "7203"))
    event = _create(metrics=(_metric(labels=accepted_labels),))
    assert event.metrics[0].labels[-1].value == "7203"

    for value in ("123456789", "1234567890123456"):
        labels = (*BASE_LABELS, TelemetryLabelV1(TelemetryLabelNameV1.INSTANCE, value))
        with pytest.raises(TelemetryError) as exc_info:
            _create(metrics=(_metric(labels=labels),))
        assert exc_info.value.code is TelemetryErrorCodeV1.LABEL_INVALID
        assert value not in str(exc_info.value)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        (TelemetryLabelNameV1.SERVICE, "mt-bridge"),
        (TelemetryLabelNameV1.REGION, "local"),
        (TelemetryLabelNameV1.VENUE, "MT5"),
        (TelemetryLabelNameV1.ENV, "test"),
        (TelemetryLabelNameV1.REASON, "halt"),
    ],
)
def test_typed_enum_label_domains_reject_raw_strings(
    name: TelemetryLabelNameV1, value: str
) -> None:
    labels = tuple(
        TelemetryLabelV1(label.name, value if label.name is name else label.value)
        for label in BASE_LABELS
    )
    if name is TelemetryLabelNameV1.REASON:
        labels = (*labels, TelemetryLabelV1(name, value))
    with pytest.raises(TelemetryError) as exc_info:
        _create(metrics=(_metric(labels=labels),))
    assert exc_info.value.code is TelemetryErrorCodeV1.LABEL_INVALID
    assert value not in str(exc_info.value)


@pytest.mark.parametrize(
    ("name", "enum_values"),
    [
        (TelemetryLabelNameV1.SERVICE, tuple(TelemetryServiceV1)),
        (TelemetryLabelNameV1.REGION, tuple(TelemetryRegionV1)),
        (TelemetryLabelNameV1.ENV, tuple(TelemetryEnvironmentV1)),
        (TelemetryLabelNameV1.VENUE, tuple(BrokerVenue)),
    ],
)
def test_every_closed_enum_domain_value_is_accepted(name, enum_values) -> None:
    for enum_value in enum_values:
        labels = tuple(
            TelemetryLabelV1(label.name, enum_value if label.name is name else label.value)
            for label in BASE_LABELS
        )
        event = _create(metrics=(_metric(labels=labels),))
        serialized = json.loads(event.to_json())["metrics"][0]["labels"]
        assert next(item["value"] for item in serialized if item["name"] == name.value)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        (TelemetryLabelNameV1.COMPONENT, "password"),
        (TelemetryLabelNameV1.INSTANCE, "hunter2"),
        (TelemetryLabelNameV1.INSTANCE, "agent-123456789"),
        (TelemetryLabelNameV1.COMPONENT, "api-gateway"),
        (TelemetryLabelNameV1.STRATEGY_ID, "secret"),
        (TelemetryLabelNameV1.STRATEGY_ID, "strategy-123456789"),
        (TelemetryLabelNameV1.COMPONENT, "apikey"),
        (TelemetryLabelNameV1.COMPONENT, "key"),
        (TelemetryLabelNameV1.COMPONENT, "token"),
        (TelemetryLabelNameV1.COMPONENT, "passwd"),
        (TelemetryLabelNameV1.COMPONENT, "bearer"),
        (TelemetryLabelNameV1.COMPONENT, "auth"),
        (TelemetryLabelNameV1.COMPONENT, "akia"),
        (TelemetryLabelNameV1.COMPONENT, "ghp"),
        (TelemetryLabelNameV1.COMPONENT, "xox"),
        (TelemetryLabelNameV1.COMPONENT, "sk"),
        (TelemetryLabelNameV1.COMPONENT, "api_key"),
    ],
)
def test_system_identifier_labels_reject_lesson_19_deny_words(
    name: TelemetryLabelNameV1, value: str
) -> None:
    labels = tuple(
        TelemetryLabelV1(label.name, value if label.name is name else label.value)
        for label in BASE_LABELS
    )
    if name not in {label.name for label in BASE_LABELS}:
        labels = (*labels, TelemetryLabelV1(name, value))
    with pytest.raises(TelemetryError) as exc_info:
        _create(metrics=(_metric(labels=labels),))
    assert exc_info.value.code is TelemetryErrorCodeV1.LABEL_INVALID
    assert value not in str(exc_info.value)
    assert value not in repr(exc_info.value)


def test_system_identifier_label_accepts_closed_identifier() -> None:
    labels = tuple(
        TelemetryLabelV1(
            label.name,
            "bridge-1" if label.name is TelemetryLabelNameV1.COMPONENT else label.value,
        )
        for label in BASE_LABELS
    )
    event = _create(metrics=(_metric(labels=labels),))
    assert event.metrics[0].labels[1].value == "bridge-1"


@pytest.mark.parametrize("error_code", [*TelemetryErrorCodeV1, *ErrorCode])
def test_error_code_enum_domains_accept_only_typed_members(error_code) -> None:
    labels = (*BASE_LABELS, TelemetryLabelV1(TelemetryLabelNameV1.ERROR_CODE, error_code))
    event = _create(metrics=(_metric(name=TelemetryMetricNameV1.ERROR_RATE_PER_S, labels=labels),))
    payload = json.loads(event.to_json())
    assert payload["metrics"][0]["labels"][-1]["value"] == error_code.value

    raw_labels = (*BASE_LABELS, TelemetryLabelV1(TelemetryLabelNameV1.ERROR_CODE, error_code.value))
    with pytest.raises(TelemetryError) as exc_info:
        _create(metrics=(_metric(name=TelemetryMetricNameV1.ERROR_RATE_PER_S, labels=raw_labels),))
    assert exc_info.value.code is TelemetryErrorCodeV1.LABEL_INVALID


def test_queue_label_accepts_only_known_typed_queue() -> None:
    labels = (
        *BASE_LABELS,
        TelemetryLabelV1(TelemetryLabelNameV1.QUEUE, TelemetryQueueV1.ORDERS_INBOUND),
    )
    event = _create(metrics=(_metric(name=TelemetryMetricNameV1.QUEUE_DEPTH, labels=labels),))
    assert event.metrics[0].labels[-1].value == TelemetryQueueV1.ORDERS_INBOUND.value

    for value in ("orders.inbound", "orders.outbound"):
        invalid = (*BASE_LABELS, TelemetryLabelV1(TelemetryLabelNameV1.QUEUE, value))
        with pytest.raises(TelemetryError) as exc_info:
            _create(metrics=(_metric(name=TelemetryMetricNameV1.QUEUE_DEPTH, labels=invalid),))
        assert exc_info.value.code is TelemetryErrorCodeV1.LABEL_INVALID
        assert value not in str(exc_info.value)


def test_unknown_schema_version_is_rejected_with_a_closed_code() -> None:
    with pytest.raises(TelemetryError) as exc_info:
        _create(schema_version=2)

    assert exc_info.value.code is TelemetryErrorCodeV1.VERSION_UNSUPPORTED
    assert "2" not in str(exc_info.value)


@pytest.mark.parametrize(
    ("timestamp", "clock", "tolerance"),
    [
        (-1, lambda: NOW_NS, 0),
        (NOW_NS + 1, lambda: NOW_NS, 0),
        (NOW_NS + 10, lambda: NOW_NS, 5),
        (NOW_NS, lambda: -1, 0),
        (NOW_NS, lambda: 1.0, 0),
    ],
)
def test_invalid_or_future_utc_timestamp_is_rejected(timestamp: int, clock, tolerance: int) -> None:
    with pytest.raises(TelemetryError) as exc_info:
        _create(
            occurred_utc_ns=timestamp,
            utc_ns=clock,
            future_tolerance_ns=tolerance,
        )

    assert exc_info.value.code is TelemetryErrorCodeV1.TIME_INVALID


def test_injected_clock_tolerance_accepts_exact_boundary() -> None:
    event = _create(
        occurred_utc_ns=NOW_NS + 7,
        utc_ns=lambda: NOW_NS,
        future_tolerance_ns=7,
    )

    assert event.occurred_utc_ns == NOW_NS + 7


def test_metric_catalog_names_and_exact_decimal_values_are_closed() -> None:
    event = _create(metrics=(_metric(value="0.125"),))
    assert event.metrics[0].value == Decimal("0.125")

    with pytest.raises(TelemetryError) as float_error:
        _create(metrics=(_metric(value=0.1),))  # type: ignore[arg-type]
    assert float_error.value.code is TelemetryErrorCodeV1.INPUT_INVALID

    with pytest.raises(TelemetryError):
        _create(metrics=(_metric(name="caller.metric"),))  # type: ignore[arg-type]


def test_metric_specific_labels_are_required_and_unknown_labels_rejected() -> None:
    labels_without_queue = BASE_LABELS
    with pytest.raises(TelemetryError) as missing:
        _create(
            metrics=(_metric(name=TelemetryMetricNameV1.QUEUE_DEPTH, labels=labels_without_queue),)
        )
    assert missing.value.code is TelemetryErrorCodeV1.LABEL_INVALID

    bad_labels = (*BASE_LABELS, TelemetryLabelV1("payload", "value"))  # type: ignore[arg-type]
    with pytest.raises(TelemetryError) as invalid:
        _create(metrics=(_metric(labels=bad_labels),))
    assert invalid.value.code is TelemetryErrorCodeV1.LABEL_INVALID


def test_per_envelope_optional_label_cardinality_is_bounded() -> None:
    metrics = tuple(
        _metric(
            labels=(
                *BASE_LABELS,
                TelemetryLabelV1(TelemetryLabelNameV1.STRATEGY_ID, f"strategy-{index:03}"),
            )
        )
        for index in range(101)
    )

    with pytest.raises(TelemetryError) as exc_info:
        _create(metrics=metrics)
    assert exc_info.value.code is TelemetryErrorCodeV1.LIMIT_EXCEEDED


def test_summary_count_and_serialized_size_bounds_are_enforced() -> None:
    repeated = tuple(_metric() for _ in range(129))
    with pytest.raises(TelemetryError) as count_error:
        _create(metrics=repeated)
    assert count_error.value.code is TelemetryErrorCodeV1.LIMIT_EXCEEDED

    large_labels = tuple(
        TelemetryLabelV1(
            TelemetryLabelNameV1(name),
            TelemetryEnvironmentV1.TEST
            if name == "env"
            else TelemetryServiceV1.MT_BRIDGE
            if name == "service"
            else TelemetryRegionV1.LOCAL
            if name == "region"
            else BrokerVenue.MT5
            if name == "venue"
            else "svc-" + "a" * 60,
        )
        for name in ("service", "component", "env", "region", "instance", "venue")
    )
    many_large = tuple(_metric(labels=large_labels) for _ in range(128))
    with pytest.raises(TelemetryError) as size_error:
        _create(metrics=many_large)
    assert size_error.value.code is TelemetryErrorCodeV1.PAYLOAD_TOO_LARGE


def test_alert_and_label_inputs_are_immutable_after_envelope_creation() -> None:
    label = TelemetryLabelV1(TelemetryLabelNameV1.SYMBOL, "EURUSD")
    event = _create(metrics=(_metric(labels=(*BASE_LABELS, label)),))
    original = event.to_json()

    with pytest.raises((AttributeError, TypeError)):
        label.value = "CHANGED"  # type: ignore[misc]
    assert event.to_json() == original


def test_model_copy_and_validation_cannot_bypass_issued_envelope_boundary() -> None:
    event = _create()

    with pytest.raises(TelemetryError) as copy_error:
        event.model_copy(update={"agent_id": "caller-controlled-text"})
    assert copy_error.value.code is TelemetryErrorCodeV1.INPUT_INVALID

    with pytest.raises(TelemetryError) as validate_error:
        TelemetryEnvelopeV1.model_validate(
            {"schema_version": 1, "agent_id": "caller-controlled-text"}
        )
    assert validate_error.value.code is TelemetryErrorCodeV1.INPUT_INVALID

    assert event.to_json() == event.model_dump_json()
    assert len(event.model_dump_json().encode("utf-8")) <= 32_768
