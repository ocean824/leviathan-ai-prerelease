"""OBS-001 closed-value boundary and reviewer reproductions (LEV-REQ-024)."""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import pickle
from dataclasses import replace
from decimal import Decimal
from uuid import UUID, uuid4

import pytest

from leviathan_core.observability import (
    BuildIdentityV1,
    DiagnosticFieldError,
    DiagnosticFieldRegistryV1,
    DiagnosticIdError,
    DiagnosticIdFactoryV1,
    DiagnosticRegistriesV1,
    DiagnosticRegistryError,
    DiagnosticRuntimeV1,
    GeneratedIdV1,
    LatencyTimerV1,
    LogLevel,
    ObservationContextError,
    ObservationContextV1,
    RegistrySnapshotV1,
    StructuredLogV1,
    copy_context,
    truncate_utf8,
)

TOKEN = "YXBp.X2tl.eT1k.dW1t.eV9z.ZWNy.ZXRf.MTIz"


def runtime(*, version: str = "1.2.3") -> DiagnosticRuntimeV1:
    snapshot = RegistrySnapshotV1.from_members
    registries = DiagnosticRegistriesV1(
        services=snapshot({"api"}),
        components=snapshot({"pipeline", "queue"}),
        strategies=snapshot({"strategy-a"}),
        instruments=snapshot({"BTCUSD"}),
        venues=snapshot({"XNAS"}),
    )
    return DiagnosticRuntimeV1(
        registries=registries,
        id_factory=DiagnosticIdFactoryV1(uuid4_factory=uuid4),
        build_identity=BuildIdentityV1(version),
    )


def context(
    *, runtime_value: DiagnosticRuntimeV1 | None = None, **overrides: object
) -> ObservationContextV1:
    values: dict[str, object] = {
        "runtime": runtime_value if runtime_value is not None else runtime(),
        "service": "api",
        "component": "pipeline",
        "env": "development",
    }
    values.update(overrides)
    return ObservationContextV1.create(**values)  # type: ignore[arg-type]


def record(fields: object, *, ctx: ObservationContextV1 | None = None) -> StructuredLogV1:
    return StructuredLogV1.create(
        utc_ns_clock=lambda: 42,
        level=LogLevel.INFO,
        message="Observation recorded.",
        context=ctx if ctx is not None else context(),
        fields=fields,  # type: ignore[arg-type]
    )


def test_registry_snapshots_are_immutable_and_bundle_id_is_ordered() -> None:
    first = RegistrySnapshotV1.from_members(["api", "core"])
    second = RegistrySnapshotV1.from_members(["core", "api"])
    assert first.snapshot_id == second.snapshot_id
    assert len(first.snapshot_id) == 64
    with pytest.raises(AttributeError):
        first.members.add("secret")  # type: ignore[attr-defined]
    registries = runtime().registries
    ids = [
        registries.services.snapshot_id,
        registries.components.snapshot_id,
        registries.strategies.snapshot_id,
        registries.instruments.snapshot_id,
        registries.venues.snapshot_id,
    ]
    expected = hashlib.sha256(
        json.dumps(ids, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()
    assert registries.registry_bundle_id == expected


def test_missing_registry_and_nonmember_fail_with_safe_typed_errors() -> None:
    with pytest.raises(DiagnosticRegistryError) as missing:
        DiagnosticRuntimeV1(
            registries=None,  # type: ignore[arg-type]
            id_factory=DiagnosticIdFactoryV1(uuid4_factory=uuid4),
            build_identity=BuildIdentityV1("1.0.0"),
        )
    assert missing.value.code == "REGISTRY_REQUIRED"
    with pytest.raises(DiagnosticRegistryError):
        context(runtime=None)
    for field, value in (
        ("service", "unknown"),
        ("component", "unknown"),
        ("strategy_id", "not-registered"),
        ("symbol", "NOTMASTER"),
        ("venue", "XXXX"),
    ):
        with pytest.raises(ObservationContextError) as caught:
            context(**{field: value})
        assert caught.value.code == "REGISTRY_NON_MEMBER"
        assert value not in repr(caught.value)


def test_build_identity_is_ascii_semver_without_build_metadata() -> None:
    assert BuildIdentityV1("1.2.3-rc.1").version == "1.2.3-rc.1"
    assert context(runtime_value=runtime(version="1.2.3-rc.1")).version == "1.2.3-rc.1"
    for invalid in (
        "1.2.3+build",
        f"1.2.3+{TOKEN}",
        "1.2.3-abcdefghijklmnopq",
        "1.2.3-a.b.c.d",
        "01.2.3",
        "\u0661.2.3",
    ):
        with pytest.raises(ObservationContextError) as caught:
            BuildIdentityV1(invalid)
        assert caught.value.code == "BUILD_IDENTITY_INVALID"
        assert invalid not in repr(caught.value)


def test_generated_ids_only_and_same_factory_issuer() -> None:
    run = runtime()
    ctx = context(runtime_value=run, trace=True, order_id=run.id_factory.mint_order_id())
    assert ctx.correlation_id.version == 4
    assert UUID(ctx.request_id).version == 4
    assert len(ctx.trace_id or "") == 32 and len(ctx.span_id or "") == 16
    assert ctx.order_id is not None and UUID(ctx.order_id).version == 4
    assert ctx.registry_bundle_id == run.registries.registry_bundle_id
    entry = record(
        {
            "event_id": run.id_factory.mint_event_id(),
            "order_id": run.id_factory.mint_order_id(),
            "trace_id": run.id_factory.mint_trace_id(),
            "span_id": run.id_factory.mint_span_id(),
        },
        ctx=ctx,
    )
    payload = json.loads(entry.to_json())
    assert payload["context"]["registry_bundle_id"] == ctx.registry_bundle_id
    assert "snapshot_id" not in entry.to_json()
    assert UUID(payload["fields"]["event_id"]).version == 4
    assert not entry.redacted
    with pytest.raises(ObservationContextError):
        context(runtime_value=run, order_id=runtime().id_factory.mint_order_id())
    with pytest.raises(DiagnosticFieldError):
        record({"event_id": runtime().id_factory.mint_event_id()}, ctx=ctx)
    with pytest.raises(TypeError):
        GeneratedIdV1()  # type: ignore[call-arg]
    with pytest.raises(DiagnosticIdError):
        DiagnosticIdFactoryV1(uuid4_factory=lambda: UUID(int=0)).mint_event_id()


@pytest.mark.parametrize(
    "field",
    ["service", "component", "strategy_id", "symbol", "venue", "env", "order_id"],
)
def test_r10_segmented_credential_rejected_in_every_open_context_slot(field: str) -> None:
    with pytest.raises((ObservationContextError, DiagnosticRegistryError)) as caught:
        context(**{field: TOKEN})
    assert TOKEN not in repr(caught.value)


@pytest.mark.parametrize(
    "field", ["correlation_id", "request_id", "trace_id", "span_id", "version"]
)
def test_r10_raw_inbound_ids_and_per_call_version_are_not_in_api(field: str) -> None:
    with pytest.raises(TypeError) as caught:
        context(**{field: TOKEN})
    assert TOKEN not in str(caught.value)


def test_r10_build_metadata_and_raw_field_ids_rejected() -> None:
    with pytest.raises(ObservationContextError):
        BuildIdentityV1(f"1.2.3+{TOKEN}")
    for field in ("event_id", "order_id", "trace_id", "span_id"):
        with pytest.raises(DiagnosticFieldError) as caught:
            record({field: TOKEN})
        assert caught.value.code == "DIAGNOSTIC_FIELD_INVALID"
        assert TOKEN not in repr(caught.value)
    assert TOKEN not in record({"stage": "pipeline.decode"}).to_json()


@pytest.mark.parametrize(
    "decimal",
    ["\u0661", "\u0661.\u0662", "1.\u0662", "\u0967\u0968.\u0969"],
)
def test_r11_unicode_digits_rejected_in_decimal(decimal: str) -> None:
    with pytest.raises(DiagnosticFieldError) as caught:
        record({"value": decimal})
    assert caught.value.code == "DIAGNOSTIC_FIELD_INVALID"
    assert decimal not in repr(caught.value)


def test_registered_scalar_fields_and_r9_id_round_trip() -> None:
    run = runtime()
    ctx = context(runtime_value=run)
    event = run.id_factory.mint_event_id()
    entry = record(
        {
            "event_id": event,
            "stage": "pipeline.decode",
            "detail_code": "VALIDATED",
            "count": 7,
            "duration_ns": 100,
            "status": "COMPLETED",
            "error_code": "UNKNOWN",
            "value": Decimal("2.50"),
            "retryable": False,
        },
        ctx=ctx,
    )
    assert entry.fields["event_id"] == event.value
    assert json.loads(entry.to_json())["fields"] == dict(entry.fields)
    assert not entry.redacted and not entry.truncated
    assert DiagnosticFieldRegistryV1().get("detail") is None


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("detail", '{"password":"dummy_secret_123"}'),
        ("detail", "ValueError('password', 'dummy_secret_789')"),
        ("email", "alice.review@example.test"),
        ("ssn", "123-45-6789"),
        ("password dummy_secret_xyz", "safe"),
        ("api_key_dummy_secret_xyz", "safe"),
        ("detail", TOKEN),
    ],
)
def test_r1_r2_r3_r8_unregistered_keys_fail_hash_only(key: str, value: str) -> None:
    with pytest.raises(DiagnosticFieldError) as caught:
        record({key: value})
    assert caught.value.code == "DIAGNOSTIC_FIELD_UNREGISTERED"
    assert caught.value.key_sha256 == hashlib.sha256(key.encode()).hexdigest()
    for shown in (str(caught.value), repr(caught.value), repr(caught.value.args)):
        assert key not in shown and value not in shown


def test_r4_nested_values_rejected_and_public_fields_immutable() -> None:
    with pytest.raises(DiagnosticFieldError):
        record({"status": {"status": "ok"}})
    entry = record({"status": "ok"})
    with pytest.raises(TypeError):
        entry.fields["status"] = "secret"  # type: ignore[index]
    assert dict(entry.fields) == json.loads(entry.to_json())["fields"]


@pytest.mark.parametrize(
    "raw",
    ["\x01" * 8192, '"' * 8192, "é" * 8192],
    ids=["control", "quotes", "unicode"],
)
def test_r5_serialized_field_cap_and_visible_suffix(raw: str) -> None:
    bounded, cut = truncate_utf8(raw)
    assert cut and bounded.endswith("…[truncated]")
    assert len(json.dumps(bounded, ensure_ascii=False).encode("utf-8")) <= 8192
    assert truncate_utf8("normal") == ("normal", False)


def test_direct_construction_replace_copy_deepcopy_pickle_blocked() -> None:
    ctx = context()
    entry = record({})
    for cls in (ObservationContextV1, StructuredLogV1):
        with pytest.raises(TypeError):
            cls()  # type: ignore[call-arg]
    for obj in (ctx, entry):
        for operation in (
            lambda value: replace(value),
            copy.copy,
            copy.deepcopy,
            pickle.dumps,
        ):
            with pytest.raises(TypeError):
                operation(obj)
    propagated = copy_context(ctx)
    assert propagated is not ctx and propagated == ctx


def test_r13_factory_and_token_cannot_be_copied_or_pickled() -> None:
    factory = DiagnosticIdFactoryV1(uuid4_factory=uuid4)
    token = factory.mint_event_id()
    for obj in (factory, token):
        for operation in (copy.copy, copy.deepcopy, pickle.dumps):
            with pytest.raises(TypeError):
                operation(obj)
    with pytest.raises(TypeError):
        replace(token)
    successor = replace(factory)
    assert successor is not factory
    assert not successor.owns(token, "event")
    assert not factory.owns(successor.mint_event_id(), "event")
    other = DiagnosticIdFactoryV1(uuid4_factory=uuid4)
    assert not factory.owns(other.mint_event_id(), "event")


def test_explicit_async_copy_and_injected_clocks() -> None:
    original = context()

    async def hop(received: ObservationContextV1) -> ObservationContextV1:
        await asyncio.sleep(0)
        return copy_context(received)

    copied = asyncio.run(hop(original))
    assert copied.request_id == original.request_id
    monotonic = iter([100, 165])
    timer = LatencyTimerV1.start(
        stage="pipeline.decode",
        context=copied,
        monotonic_ns_clock=lambda: next(monotonic),
        utc_ns_clock=lambda: 9000,
    )
    sample = timer.stop()
    assert (sample.duration_ns, sample.timestamp_utc_ns) == (65, 9000)
    with pytest.raises(ValueError):
        LatencyTimerV1.start(
            stage=TOKEN,
            context=copied,
            monotonic_ns_clock=lambda: 1,
            utc_ns_clock=lambda: 2,
        )


def test_unknown_message_and_malformed_field_container_fail_closed() -> None:
    entry = StructuredLogV1.create(
        utc_ns_clock=lambda: 3,
        level=LogLevel.ERROR,
        message="SECRET traceback",
        context=context(),
        error_code="UNRECOGNIZED_ERROR",
    )
    assert entry.message == "Observation recorded."
    assert "SECRET" not in entry.to_json()
    malformed = record(object())
    assert json.loads(malformed.to_json())["error_code"] == "REDACTION_FAILURE"
