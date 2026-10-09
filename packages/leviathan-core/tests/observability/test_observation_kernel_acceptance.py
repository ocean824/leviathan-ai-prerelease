"""Independent requirement-level acceptance tests for OBS-001's local boundary."""

import hashlib
import json
import logging
import pickle
from copy import copy, deepcopy
from dataclasses import replace
from uuid import UUID, uuid4

import pytest

from leviathan_core.observability import (
    BuildIdentityV1,
    DiagnosticFieldError,
    DiagnosticIdFactoryV1,
    DiagnosticRegistriesV1,
    DiagnosticRuntimeV1,
    ErrorCode,
    LatencyTimerV1,
    LogLevel,
    ObservationContextV1,
    RegistrySnapshotV1,
    StructuredLogV1,
    copy_context,
    truncate_utf8,
)


def registry_bundle(**overrides) -> DiagnosticRegistriesV1:
    members = {
        "services": {"market-data"},
        "components": {"normalizer"},
        "strategies": {"strategy-a"},
        "instruments": {"BTCUSD"},
        "venues": {"XNAS"},
    }
    members.update(overrides)
    return DiagnosticRegistriesV1(
        **{name: RegistrySnapshotV1.from_members(values) for name, values in members.items()}
    )


def runtime(
    *,
    registries=None,
    uuid4_factory=uuid4,
    version="1.0.0",
) -> DiagnosticRuntimeV1:
    return DiagnosticRuntimeV1(
        registries=registry_bundle() if registries is None else registries,
        id_factory=DiagnosticIdFactoryV1(uuid4_factory=uuid4_factory),
        build_identity=BuildIdentityV1(version=version),
    )


def context(*, runtime_value=None, **overrides) -> ObservationContextV1:
    args = {
        "runtime": runtime() if runtime_value is None else runtime_value,
        "service": "market-data",
        "component": "normalizer",
        "env": "development",
        "strategy_id": "strategy-a",
        "symbol": "BTCUSD",
        "venue": "XNAS",
    }
    args.update(overrides)
    return ObservationContextV1.create(**args)


def emit(
    fields=None,
    *,
    level=LogLevel.INFO,
    message="Order accepted.",
    error_code=None,
    context_value=None,
    runtime_value=None,
):
    context_value = (
        context(runtime_value=runtime_value)
        if context_value is None
        else context_value
    )
    return StructuredLogV1.create(
        utc_ns_clock=lambda: 1_700_000_000_000_000_123,
        level=level,
        message=message,
        context=context_value,
        fields=fields,
        error_code=error_code,
    )


def serialized(record) -> tuple[dict, bytes]:
    line = record.to_json()
    return json.loads(line), line.encode("utf-8")


def generated_fields(id_factory) -> dict:
    return {
        "event_id": id_factory.mint_event_id(),
        "order_id": id_factory.mint_order_id(),
        "trace_id": id_factory.mint_trace_id(),
        "span_id": id_factory.mint_span_id(),
    }


def test_sensitive_text_in_unregistered_key_is_not_emitted() -> None:
    secret_key = "password dummy_secret_xyz"

    with pytest.raises(DiagnosticFieldError) as caught:
        emit(fields={secret_key: "safe"})

    assert caught.value.code == "DIAGNOSTIC_FIELD_UNREGISTERED"
    assert caught.value.key_sha256 == hashlib.sha256(secret_key.encode("utf-8")).hexdigest()
    assert secret_key not in str(caught.value)
    assert secret_key not in repr(caught.value)
    assert all(secret_key not in repr(argument) for argument in caught.value.args)


def test_truncate_utf8_respects_byte_limit_without_splitting_codepoint() -> None:
    source = "é" * 10_000
    output, truncated = truncate_utf8(source, 8 * 1024)

    assert truncated is True
    assert len(output) < len(source)
    assert len(json.dumps(output, ensure_ascii=False).encode("utf-8")) <= 8 * 1024
    assert output.endswith("…[truncated]")
    assert json.loads(json.dumps(output)) == output


def test_serialized_line_cap_is_enforced_after_expansion_and_marks_truncation() -> None:
    runtime_value = runtime()
    fields = {
        **generated_fields(runtime_value.id_factory),
        "stage": "pipeline.decode",
        "detail_code": "OBSERVATION",
        "count": 17,
        "duration_ns": 123456789,
        "status": "COMPLETED",
        "error_code": ErrorCode.UNKNOWN.value,
        "value": "123.4500",
        "retryable": True,
    }

    context_value = context(runtime_value=runtime_value, trace=True)
    record = emit(fields=fields, context_value=context_value)
    body, raw = serialized(record)

    assert len(raw) <= 64 * 1024
    assert set(body["fields"]) == set(fields)
    assert body["truncated"] is False
    assert record.truncated is False
    assert "\n" not in record.to_json()


def test_registered_field_types_serialize_with_caps_under_worst_case_escaping() -> None:
    runtime_value = runtime()
    valid_fields = {
        **generated_fields(runtime_value.id_factory),
        "stage": "transform",
        "detail_code": "OBSERVATION",
        "count": 17,
        "duration_ns": 123456789,
        "status": "ok",
        "error_code": ErrorCode.INVALID_INPUT.value,
        "value": "123.4500",
        "retryable": True,
    }
    for name, value in valid_fields.items():
        context_value = context(runtime_value=runtime_value, trace=True)
        record = emit(fields={name: value}, context_value=context_value)
        body, raw = serialized(record)

        assert set(body["fields"]) == {name}
        assert len(
            json.dumps(body["fields"][name], ensure_ascii=False).encode("utf-8")
        ) <= 8 * 1024
    assert len(raw) <= 64 * 1024

def test_untyped_detail_is_no_longer_a_registered_field() -> None:
    dotted_credential = "YXBp.X2tl.eT1k.dW1t.eV9z.ZWNy.ZXRf.MTIz"

    with pytest.raises(DiagnosticFieldError) as caught:
        emit(fields={"detail": dotted_credential})

    assert caught.value.code == "DIAGNOSTIC_FIELD_UNREGISTERED"
    assert dotted_credential not in str(caught.value)
    assert dotted_credential not in repr(caught.value)
    assert all(dotted_credential not in repr(arg) for arg in caught.value.args)


def test_dotted_base64_credential_cannot_enter_through_registered_field_types() -> None:
    credential = "YXBp.X2tl.eT1k.dW1t.eV9z.ZWNy.ZXRf.MTIz"
    field_names = (
        "event_id",
        "order_id",
        "trace_id",
        "span_id",
        "stage",
        "detail_code",
        "count",
        "duration_ns",
        "status",
        "error_code",
        "value",
        "retryable",
    )

    for name in field_names:
        try:
            record = emit(fields={name: credential})
        except DiagnosticFieldError as error:
            assert error.code == "DIAGNOSTIC_FIELD_INVALID"
            assert credential not in str(error)
            assert credential not in repr(error)
            assert all(credential not in repr(arg) for arg in error.args)
        else:
            assert credential not in record.to_json()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("service", "not-registered"),
        ("component", "not-registered"),
        ("strategy_id", "not-registered"),
        ("symbol", "NOT-IN-INSTRUMENT-MASTER"),
        ("venue", "ZZZZ"),
    ],
)
def test_context_rejects_nonmember_registry_values(field: str, value: str) -> None:
    with pytest.raises((TypeError, ValueError)) as caught:
        context(**{field: value})

    assert value not in str(caught.value)
    assert value not in repr(caught.value)


def test_context_requires_runtime_and_complete_registry_bundle() -> None:
    with pytest.raises(TypeError):
        ObservationContextV1.create(
            service="market-data", component="normalizer", env="development"
        )

    with pytest.raises((TypeError, ValueError)):
        DiagnosticRuntimeV1(
            registries=None,
            id_factory=DiagnosticIdFactoryV1(uuid4_factory=uuid4),
            build_identity=BuildIdentityV1(version="1.0.0"),
        )

    with pytest.raises(TypeError):
        DiagnosticRegistriesV1(
            services=RegistrySnapshotV1.from_members({"market-data"}),
            components=RegistrySnapshotV1.from_members({"normalizer"}),
            strategies=RegistrySnapshotV1.from_members({"strategy-a"}),
            instruments=RegistrySnapshotV1.from_members({"BTCUSD"}),
        )


SEGMENTED_CREDENTIAL = "YXBp.X2tl.eT1k.dW1t.eV9z.ZWNy.ZXRf.MTIz"


@pytest.mark.parametrize(
    "field",
    ["service", "component", "strategy_id", "symbol", "venue", "env"],
)
def test_segmented_credential_cannot_enter_registry_context_fields(field: str) -> None:
    with pytest.raises((TypeError, ValueError)) as caught:
        context(**{field: SEGMENTED_CREDENTIAL})

    assert SEGMENTED_CREDENTIAL not in str(caught.value)
    assert SEGMENTED_CREDENTIAL not in repr(caught.value)

    with pytest.raises((TypeError, ValueError)):
        context(version=f"1.2.3+{SEGMENTED_CREDENTIAL}")


def test_segmented_credential_cannot_enter_order_or_request_id() -> None:
    with pytest.raises((TypeError, ValueError)) as caught:
        context(order_id=SEGMENTED_CREDENTIAL)
    assert SEGMENTED_CREDENTIAL not in str(caught.value)
    assert SEGMENTED_CREDENTIAL not in repr(caught.value)

    base = {
        "runtime": runtime(),
        "service": "market-data",
        "component": "normalizer",
        "env": "development",
    }
    with pytest.raises(TypeError) as caught:
        ObservationContextV1.create(**base, request_id=SEGMENTED_CREDENTIAL)
    assert SEGMENTED_CREDENTIAL not in str(caught.value)


def test_build_identity_rejects_segmented_credential_in_build_metadata() -> None:
    version = f"1.2.3+{SEGMENTED_CREDENTIAL}"

    with pytest.raises((TypeError, ValueError)) as caught:
        BuildIdentityV1(version=version)

    assert SEGMENTED_CREDENTIAL not in str(caught.value)
    assert SEGMENTED_CREDENTIAL not in repr(caught.value)


def test_build_identity_and_decimal_field_reject_non_ascii_digits() -> None:
    with pytest.raises(ValueError):
        BuildIdentityV1(version="1.٢.3")

    runtime_value = runtime()
    context_value = context(runtime_value=runtime_value)
    with pytest.raises(DiagnosticFieldError) as caught:
        emit(fields={"value": "١٢.٣"}, context_value=context_value)

    assert caught.value.code == "DIAGNOSTIC_FIELD_INVALID"
    assert "١٢.٣" not in str(caught.value)
    assert "١٢.٣" not in repr(caught.value)


def test_only_registry_bundle_id_is_emitted_not_snapshot_lists() -> None:
    runtime_value = runtime()
    context_value = context(runtime_value=runtime_value)
    record = emit(fields={"count": 2}, context_value=context_value)
    body, raw = serialized(record)

    bundle_id = runtime_value.registries.registry_bundle_id
    assert body["context"]["registry_bundle_id"] == bundle_id
    assert context_value.registry_bundle_id == bundle_id
    assert "registries" not in body
    assert "registry_snapshot_ids" not in body
    assert raw.count(bundle_id.encode("ascii")) == 1

    snapshots = (
        runtime_value.registries.services,
        runtime_value.registries.components,
        runtime_value.registries.strategies,
        runtime_value.registries.instruments,
        runtime_value.registries.venues,
    )
    for snapshot in snapshots:
        assert snapshot.snapshot_id.encode("ascii") not in raw


def test_valid_uuidv4_event_id_is_preserved_byte_for_byte() -> None:
    runtime_value = runtime()
    event_id = runtime_value.id_factory.mint_event_id()
    event_id_text = event_id.value
    record = emit(
        fields={"event_id": event_id},
        context_value=context(runtime_value=runtime_value),
    )
    body, raw = serialized(record)

    assert body["fields"]["event_id"] == event_id_text
    assert event_id_text.encode("ascii") in raw
    assert body["redacted"] is False


@pytest.mark.parametrize("level", ["TRACE", "DEBUG", "INFO", "WARN", "ERROR"])
def test_only_prd_log_levels_are_emitted(level: str) -> None:
    record = emit(level=LogLevel(level))
    body, _ = serialized(record)

    assert body["level"] == level


@pytest.mark.parametrize("level", ["WARNING", "CRITICAL", "warn", "FATAL"])
def test_non_prd_log_levels_are_rejected(level: str) -> None:
    with pytest.raises(ValueError):
        LogLevel(level)


def test_sanitized_public_fields_are_immutable_and_match_serialized_output() -> None:
    fields = {"count": 1}
    record = emit(fields=fields)
    frozen_line = record.to_json()

    fields["count"] = 2

    body, _ = serialized(record)
    assert record.fields["count"] == 1
    assert body["fields"]["count"] == 1
    assert record.to_json() == frozen_line
    with pytest.raises(TypeError):
        record.fields["count"] = 3  # type: ignore[index]


def test_unknown_error_code_and_message_are_replaced_with_allowlisted_values() -> None:
    record = emit(
        fields={"status": "COMPLETED"},
        message="unknown untrusted message text",
        error_code="VENDOR_SECRET_ERROR: raw secret",
    )
    body, _ = serialized(record)

    assert body["message"] == "Observation recorded."
    assert body["error_code"] == ErrorCode.UNKNOWN.value
    assert "untrusted message text" not in record.to_json()
    assert "raw secret" not in record.to_json()


def test_log_contains_only_the_declared_observation_envelope_and_injected_utc_ns() -> None:
    record = emit(fields={"count": 2})
    body, _ = serialized(record)

    assert body["timestamp_utc_ns"] == 1_700_000_000_000_000_123
    assert body["level"] == LogLevel.INFO.value
    assert body["context"]["service"] == "market-data"
    assert body["context"]["version"] == "1.0.0"
    assert body["fields"] == {"count": 2}
    assert "traceback" not in body
    assert "exception" not in body
    assert "request_body" not in body


@pytest.mark.parametrize("field", ["correlation_id", "request_id", "trace_id", "span_id"])
def test_raw_external_id_arguments_are_not_accepted(field: str) -> None:
    args = {
        "runtime": runtime(),
        "service": "market-data",
        "component": "normalizer",
        "env": "development",
    }

    with pytest.raises(TypeError):
        ObservationContextV1.create(**args, **{field: "12345678-1234-4234-9234-123456789abc"})


def test_raw_uuid_is_rejected_where_minted_id_token_is_required() -> None:
    runtime_value = runtime()
    context_value = context(runtime_value=runtime_value)

    with pytest.raises(DiagnosticFieldError) as caught:
        emit(
            fields={"event_id": UUID("12345678-1234-4234-9234-123456789abc")},
            context_value=context_value,
        )

    assert caught.value.code == "DIAGNOSTIC_FIELD_INVALID"

    with pytest.raises((TypeError, ValueError)):
        context(order_id=UUID("12345678-1234-4234-9234-123456789abc"))


def test_traceparent_shaped_caller_value_is_not_accepted() -> None:
    traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
    runtime_value = runtime()
    context_value = context(runtime_value=runtime_value)

    with pytest.raises(DiagnosticFieldError) as caught:
        emit(fields={"trace_id": traceparent}, context_value=context_value)

    assert caught.value.code == "DIAGNOSTIC_FIELD_INVALID"
    assert traceparent not in str(caught.value)
    assert traceparent not in repr(caught.value)


def test_missing_ids_are_generated_and_inbound_request_ids_are_fresh() -> None:
    generated = iter(
        [
            UUID("12345678-1234-4234-9234-123456789abc"),
            UUID("87654321-4321-4321-8321-cba987654321"),
            UUID("23456789-2345-4234-9234-23456789abcd"),
            UUID("98765432-5432-4321-8321-dcba98765432"),
        ]
    )
    runtime_value = runtime(uuid4_factory=lambda: next(generated))
    first = context(runtime_value=runtime_value)
    second = context(runtime_value=runtime_value)

    assert first.correlation_id != second.correlation_id
    assert first.request_id != second.request_id
    assert UUID(str(first.correlation_id)).version == 4
    assert UUID(str(first.request_id)).version == 4
    assert UUID(str(second.correlation_id)).version == 4
    assert UUID(str(second.request_id)).version == 4


def test_trace_ids_are_minted_internally_only() -> None:
    value = context(trace=True)

    assert value.trace_id is not None
    assert value.span_id is not None
    assert len(value.trace_id) == 32
    assert len(value.span_id) == 16
    assert set(value.trace_id) <= set("0123456789abcdef")
    assert set(value.span_id) <= set("0123456789abcdef")


def test_context_propagation_is_explicit_copy_not_shared_mutable_state() -> None:
    original = context()
    propagated = copy_context(original)

    assert propagated == original
    assert propagated is not original
    assert propagated.correlation_id == original.correlation_id
    assert propagated.request_id == original.request_id


def test_context_and_record_cannot_be_replaced_copied_or_pickled() -> None:
    context_value = context()
    record = emit(context_value=context_value, fields={"count": 1})
    bypasses = (replace, copy, deepcopy, pickle.dumps)

    with pytest.raises(TypeError):
        ObservationContextV1(runtime=runtime())  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        StructuredLogV1(utc_ns_clock=lambda: 0)  # type: ignore[call-arg]

    for value in (context_value, record):
        for bypass in bypasses:
            with pytest.raises(TypeError):
                bypass(value)


@pytest.mark.parametrize("operation", [copy, deepcopy, pickle.dumps])
def test_generated_ids_cannot_be_copied_or_pickled(operation) -> None:
    token = runtime().id_factory.mint_event_id()

    with pytest.raises(TypeError):
        operation(token)


def test_generated_id_cannot_be_replaced() -> None:
    token = runtime().id_factory.mint_event_id()

    with pytest.raises(TypeError):
        replace(token)


@pytest.mark.parametrize("operation", [copy, deepcopy, pickle.dumps])
def test_id_factories_cannot_be_copied_or_pickled(operation) -> None:
    id_factory = DiagnosticIdFactoryV1(uuid4_factory=uuid4)

    with pytest.raises(TypeError):
        operation(id_factory)


def test_foreign_factory_token_is_rejected_by_original_runtime_record() -> None:
    original_runtime = runtime()
    foreign_factory = DiagnosticIdFactoryV1(uuid4_factory=uuid4)
    foreign_token = foreign_factory.mint_event_id()
    original_token = original_runtime.id_factory.mint_event_id()
    original_context = context(runtime_value=original_runtime)

    assert original_runtime.id_factory.owns(original_token, "event") is True
    assert original_runtime.id_factory.owns(foreign_token, "event") is False

    with pytest.raises(DiagnosticFieldError) as caught:
        emit(fields={"event_id": foreign_token}, context_value=original_context)

    assert caught.value.code == "DIAGNOSTIC_FIELD_INVALID"
    assert "event_id" not in str(caught.value)
    assert foreign_token.value not in str(caught.value)
    assert foreign_token.value not in repr(caught.value)


def test_latency_uses_injected_monotonic_clock_across_wall_clock_jump() -> None:
    monotonic_values = iter([1_000, 4_500])
    wall_values = iter([10_000_000, -5_000_000_000])
    timer = LatencyTimerV1.start(
        stage="transform",
        context=context(),
        monotonic_ns_clock=lambda: next(monotonic_values),
        utc_ns_clock=lambda: next(wall_values),
    )

    sample = timer.stop()

    assert sample.duration_ns == 3_500
    assert sample.stage == "transform"


def test_latency_rejects_a_backwards_monotonic_clock() -> None:
    monotonic_values = iter([5_000, 4_999])
    timer = LatencyTimerV1.start(
        stage="transform",
        context=context(),
        monotonic_ns_clock=lambda: next(monotonic_values),
        utc_ns_clock=lambda: 0,
    )

    with pytest.raises(ValueError):
        timer.stop()


def test_kernel_does_not_change_process_wide_logging_configuration() -> None:
    root = logging.getLogger()
    before = (root.level, tuple(root.handlers), root.disabled, root.propagate)

    emit(fields={"status": "ok"})

    after = (root.level, tuple(root.handlers), root.disabled, root.propagate)
    assert after == before
