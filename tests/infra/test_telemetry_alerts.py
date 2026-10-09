"""Unit coverage for fake-first OBS-005 alert and retention kernels."""

from __future__ import annotations

import asyncio
import hashlib
import json
import sys
from dataclasses import replace
from decimal import Decimal
from pathlib import Path
from typing import cast
from uuid import uuid4

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from infra.cloud.telemetry.alerts import (
    AlertDeliveryV1,
    AlertEngineV1,
    AlertError,
    AlertFailureModeV1,
    AlertObservationV1,
    AlertOutboxV1,
    AlertQueueResultV1,
)
from infra.cloud.telemetry.catalog import MetricLabelsV1
from infra.cloud.telemetry.correlation import CorrelationError, CorrelationKernelV1
from infra.cloud.telemetry.retention import (
    LegalHoldPort,
    RetentionActionV1,
    RetentionAuditPort,
    RetentionAuditRecordV1,
    RetentionClassV1,
    RetentionPlannerV1,
    RetentionReasonV1,
    RetentionRecordV1,
)

from leviathan_core.observability.context import DiagnosticIdFactoryV1, GeneratedIdV1
from leviathan_core.observability.live_log import LiveLogBufferV1
from leviathan_core.observability.models import LogLevel

_NS = 1_000_000_000
_DAY_NS = 86_400 * _NS


def _ids() -> DiagnosticIdFactoryV1:
    return DiagnosticIdFactoryV1(uuid4_factory=uuid4)


class _FakeHolds(LegalHoldPort):
    def __init__(self, value: bool | None = False, error: Exception | None = None) -> None:
        self.value = value
        self.error = error
        self.lookups = 0

    def is_held(self, record_id: GeneratedIdV1) -> bool | None:
        self.lookups += 1
        if self.error is not None:
            raise self.error
        return self.value


class _FakeAudit(RetentionAuditPort):
    def __init__(self, max_entries: int = 100) -> None:
        self.max_entries = max_entries
        self.records: list[RetentionAuditRecordV1] = []
        self.tip = "0" * 64

    def append(
        self,
        *,
        record_key_sha256: str,
        retention_class: RetentionClassV1,
        action: RetentionActionV1,
        reason: RetentionReasonV1,
        recorded_utc_ns: int,
    ) -> RetentionAuditRecordV1:
        if len(self.records) >= self.max_entries:
            raise RuntimeError("audit unavailable")
        sequence = len(self.records) + 1
        payload = {
            "sequence": sequence,
            "record_key_sha256": record_key_sha256,
            "retention_class": retention_class.value,
            "action": action.value,
            "reason": reason.value,
            "recorded_utc_ns": recorded_utc_ns,
            "previous_hash": self.tip,
        }
        digest = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii")
        ).hexdigest()
        record = RetentionAuditRecordV1(
            sequence,
            record_key_sha256,
            retention_class,
            action,
            reason,
            recorded_utc_ns,
            self.tip,
            digest,
        )
        self.records.append(record)
        self.tip = digest
        return record

    def snapshot(self) -> tuple[RetentionAuditRecordV1, ...]:
        return tuple(self.records)


class _MalformedAckAudit(_FakeAudit):
    def __init__(self, field: str) -> None:
        super().__init__()
        self.field = field

    def append(
        self,
        *,
        record_key_sha256: str,
        retention_class: RetentionClassV1,
        action: RetentionActionV1,
        reason: RetentionReasonV1,
        recorded_utc_ns: int,
    ) -> RetentionAuditRecordV1:
        record = super().append(
            record_key_sha256=record_key_sha256,
            retention_class=retention_class,
            action=action,
            reason=reason,
            recorded_utc_ns=recorded_utc_ns,
        )
        if self.field == "type":
            return cast(RetentionAuditRecordV1, object())
        mutations: dict[str, object] = {
            "sequence": -4,
            "record_key_sha256": "f" * 64,
            "retention_class": RetentionClassV1.METRIC_5S,
            "action": RetentionActionV1.RETAIN,
            "reason": RetentionReasonV1.POLICY_UNKNOWN,
            "recorded_utc_ns": recorded_utc_ns + 1,
            "previous_hash": "1" * 64,
            "record_hash": "forged",
        }
        return replace(record, **{self.field: mutations[self.field]})


class _Policy:
    def allows(self, principal: object, action: str) -> bool:
        return True


def _labels(**changes: str) -> MetricLabelsV1:
    values = {
        "service": "leviathan",
        "component": "engine",
        "env": "test",
        "region": "local",
        "instance": "node-a",
    }
    values.update(changes)
    return MetricLabelsV1(**values)


def _observation(at_ns: int, **changes: object) -> AlertObservationV1:
    values: dict[str, object] = {
        "timestamp_utc_ns": at_ns,
        "labels": _labels(),
    }
    values.update(changes)
    return AlertObservationV1(**values)  # type: ignore[arg-type]


def test_alert_threshold_windows_are_exact_and_observations_are_safe() -> None:
    engine = AlertEngineV1(_ids())
    assert engine.evaluate(_observation(0, decision_p99_seconds=Decimal("0.008"))) == ()
    (decision_page,) = engine.evaluate(_observation(_NS, decision_p99_seconds=Decimal("0.0080001")))
    assert decision_page.failure_mode is AlertFailureModeV1.DECISION_LATENCY
    assert decision_page.dashboard_ref == "unavailable"
    assert decision_page.runbook_ref == "unavailable"
    assert decision_page.deployment_sha256 == "0" * 64

    lag = AlertEngineV1(_ids())
    assert lag.evaluate(_observation(0, pipeline_lag_seconds=Decimal("0.501"))) == ()
    assert lag.evaluate(_observation(300 * _NS - 1, pipeline_lag_seconds=Decimal("0.501"))) == ()
    assert lag.evaluate(_observation(300 * _NS, pipeline_lag_seconds=Decimal("0.501"))) == ()
    (lag_page,) = lag.evaluate(_observation(300 * _NS + 1, pipeline_lag_seconds=Decimal("0.501")))
    assert lag_page.failure_mode is AlertFailureModeV1.PIPELINE_LAG

    with pytest.raises(AlertError) as error:
        _observation(1, error_rate_5m=Decimal("1.01"))
    assert error.value.code == "ALERT_OBSERVATION_INVALID"


def test_alert_groups_by_service_component_and_failure_mode_and_inhibits_venue() -> None:
    engine = AlertEngineV1(_ids())
    (first,) = engine.evaluate(
        _observation(0, decision_p99_seconds=Decimal("0.009"), labels=_labels(instance="node-a"))
    )
    assert (
        engine.evaluate(
            _observation(
                1, decision_p99_seconds=Decimal("0.009"), labels=_labels(instance="node-b")
            )
        )
        == ()
    )
    assert first.root_cause_id == hashlib.sha256(b"leviathan|engine|decision_latency").hexdigest()

    inhibited = AlertEngineV1(_ids())
    common = {"venue": "XNAS"}
    assert (
        inhibited.evaluate(
            _observation(
                0, connector_up=False, pipeline_lag_seconds=Decimal("0.6"), labels=_labels(**common)
            )
        )
        == ()
    )
    assert (
        inhibited.evaluate(
            _observation(
                60 * _NS,
                connector_up=False,
                pipeline_lag_seconds=Decimal("0.6"),
                labels=_labels(**common),
            )
        )
        == ()
    )
    (connector_page,) = inhibited.evaluate(
        _observation(
            60 * _NS + 1,
            connector_up=False,
            pipeline_lag_seconds=Decimal("0.6"),
            labels=_labels(**common),
        )
    )
    assert connector_page.failure_mode is AlertFailureModeV1.CONNECTOR_DOWN
    assert (
        inhibited.evaluate(
            _observation(
                300 * _NS + 1,
                connector_up=False,
                pipeline_lag_seconds=Decimal("0.6"),
                labels=_labels(**common),
            )
        )
        == ()
    )


def test_error_skew_readiness_and_market_hours_rules() -> None:
    error_engine = AlertEngineV1(_ids())
    assert error_engine.evaluate(_observation(0, error_rate_5m=Decimal("0.02"))) == ()
    (error_page,) = error_engine.evaluate(_observation(1, error_rate_5m=Decimal("0.0201")))
    assert error_page.failure_mode is AlertFailureModeV1.ERROR_RATE

    skew_engine = AlertEngineV1(_ids())
    assert skew_engine.evaluate(_observation(0, time_sync_offset_seconds=Decimal("-0.051"))) == ()
    assert (
        skew_engine.evaluate(
            _observation(120 * _NS - 1, time_sync_offset_seconds=Decimal("-0.051"))
        )
        == ()
    )
    assert (
        skew_engine.evaluate(_observation(120 * _NS, time_sync_offset_seconds=Decimal("-0.051")))
        == ()
    )
    (skew_page,) = skew_engine.evaluate(
        _observation(120 * _NS + 1, time_sync_offset_seconds=Decimal("-0.051"))
    )
    assert skew_page.failure_mode is AlertFailureModeV1.TIME_SYNC_SKEW

    readiness_engine = AlertEngineV1(_ids())
    assert (
        readiness_engine.evaluate(_observation(0, readiness_ready=False, market_hours=False)) == ()
    )
    assert (
        readiness_engine.evaluate(_observation(1, readiness_ready=False, market_hours=True)) == ()
    )
    assert (
        readiness_engine.evaluate(
            _observation(120 * _NS + 1, readiness_ready=False, market_hours=True)
        )
        == ()
    )
    (readiness_page,) = readiness_engine.evaluate(
        _observation(120 * _NS + 2, readiness_ready=False, market_hours=True)
    )
    assert readiness_page.failure_mode is AlertFailureModeV1.READINESS_FAILURE


def test_correlation_denies_unverified_principal_with_content_free_error() -> None:
    kernel = CorrelationKernelV1(LiveLogBufferV1(max_orgs=1), _Policy())

    async def run() -> None:
        with pytest.raises(CorrelationError) as error:
            await kernel.correlate(object(), "00000000-0000-4000-8000-000000000000")  # type: ignore[arg-type]
        assert error.value.code == "CORRELATION_ACCESS_DENIED"
        assert str(error.value) == "CORRELATION_ACCESS_DENIED"

    asyncio.run(run())


def test_alert_outbox_drops_trace_first_and_backpressures_critical() -> None:
    engine = AlertEngineV1(_ids())
    (page,) = engine.evaluate(_observation(0, decision_p99_seconds=Decimal("0.009")))
    outbox = AlertOutboxV1(max_items=1)
    assert outbox.submit(page, LogLevel.DEBUG) is AlertQueueResultV1.QUEUED
    assert outbox.submit(page, LogLevel.ERROR) is AlertQueueResultV1.QUEUED
    assert outbox.pending == 1
    assert outbox.drain(limit=1) == (AlertDeliveryV1(LogLevel.ERROR, page),)
    assert outbox.submit(page, LogLevel.ERROR) is AlertQueueResultV1.QUEUED
    assert outbox.submit(page, LogLevel.WARN) is AlertQueueResultV1.BACKPRESSURED
    assert outbox.drain(limit=1) == (AlertDeliveryV1(LogLevel.ERROR, page),)
    assert outbox.submit(page, LogLevel.TRACE) is AlertQueueResultV1.QUEUED
    assert outbox.submit(page, LogLevel.DEBUG) is AlertQueueResultV1.DROPPED_LOW_PRIORITY


@pytest.mark.parametrize(
    ("retention_class", "days"),
    [
        (RetentionClassV1.METRIC_5S, 7),
        (RetentionClassV1.METRIC_30S, 30),
        (RetentionClassV1.METRIC_5M, 90),
        (RetentionClassV1.LOG_HOT, 14),
        (RetentionClassV1.LOG_ARCHIVE, 90),
        (RetentionClassV1.TRACE_HOT, 7),
        (RetentionClassV1.TRACE_SUMMARY, 30),
    ],
)
def test_retention_uses_exact_utc_ns_expiry(retention_class: RetentionClassV1, days: int) -> None:
    audit = _FakeAudit()
    planner = RetentionPlannerV1(audit, _FakeHolds())
    record = RetentionRecordV1(_ids().mint_event_id(), retention_class, 0)
    expiry = days * _DAY_NS
    before = planner.plan(record, expiry - 1)
    at = planner.plan(record, expiry)
    assert before.action is RetentionActionV1.RETAIN
    assert before.expires_utc_ns == expiry
    assert at.action is RetentionActionV1.DELETE_ELIGIBLE
    assert at.reason is RetentionReasonV1.RETENTION_EXPIRED
    assert at.audit_sequence == 2
    assert len(audit.snapshot()) == 2


def test_retention_holds_unknown_policy_and_audit_failure_block_deletion() -> None:
    record = RetentionRecordV1(_ids().mint_event_id(), RetentionClassV1.LOG_HOT, 0)
    planner = RetentionPlannerV1(_FakeAudit(), _FakeHolds(True))
    held = planner.plan(record, 15 * _DAY_NS)
    unknown_planner = RetentionPlannerV1(_FakeAudit(), _FakeHolds(None))
    unknown_hold = unknown_planner.plan(record, 15 * _DAY_NS)
    unknown_policy = planner.plan(record, 15 * _DAY_NS, policy_known=False)
    assert held.action is RetentionActionV1.HELD
    assert held.reason is RetentionReasonV1.LEGAL_HOLD
    assert unknown_hold.action is RetentionActionV1.HELD
    assert unknown_hold.reason is RetentionReasonV1.HOLD_UNKNOWN
    assert unknown_policy.action is RetentionActionV1.BLOCKED
    assert unknown_policy.reason is RetentionReasonV1.POLICY_UNKNOWN

    full_audit = _FakeAudit(max_entries=1)
    fail_closed = RetentionPlannerV1(full_audit, _FakeHolds())
    assert fail_closed.plan(record, 1).action is RetentionActionV1.RETAIN
    denied = fail_closed.plan(record, 15 * _DAY_NS)
    assert denied.action is RetentionActionV1.BLOCKED
    assert denied.reason is RetentionReasonV1.AUDIT_UNAVAILABLE


@pytest.mark.parametrize(
    "field",
    [
        "type",
        "sequence",
        "record_key_sha256",
        "retention_class",
        "action",
        "reason",
        "recorded_utc_ns",
        "previous_hash",
        "record_hash",
    ],
)
def test_malformed_retention_audit_ack_never_authorizes_expired_record(field: str) -> None:
    audit = _MalformedAckAudit(field)
    planner = RetentionPlannerV1(audit, _FakeHolds())
    record = RetentionRecordV1(_ids().mint_event_id(), RetentionClassV1.LOG_HOT, 0)

    decision = planner.plan(record, 14 * _DAY_NS)

    assert decision.action is RetentionActionV1.BLOCKED
    assert decision.reason is RetentionReasonV1.AUDIT_UNAVAILABLE
    assert decision.audit_sequence is None
    assert decision.audit_hash is None


def test_fake_retention_audit_chain_links_append_only_records() -> None:
    audit = _FakeAudit()
    planner = RetentionPlannerV1(audit, _FakeHolds())
    record = RetentionRecordV1(_ids().mint_event_id(), RetentionClassV1.TRACE_HOT, 0)
    planner.plan(record, 0)
    planner.plan(record, 7 * _DAY_NS)
    rows = audit.snapshot()
    assert rows[0].previous_hash == "0" * 64
    assert rows[1].previous_hash == rows[0].record_hash
    assert (
        rows[1].record_hash
        == hashlib.sha256(
            json.dumps(
                {
                    "sequence": rows[1].sequence,
                    "record_key_sha256": rows[1].record_key_sha256,
                    "retention_class": rows[1].retention_class.value,
                    "action": rows[1].action.value,
                    "reason": rows[1].reason.value,
                    "recorded_utc_ns": rows[1].recorded_utc_ns,
                    "previous_hash": rows[1].previous_hash,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
        ).hexdigest()
    )


@pytest.mark.parametrize("failure", [RuntimeError("synthetic"), TimeoutError()])
def test_unresolved_legal_hold_is_audited_and_never_deleted(failure: Exception) -> None:
    audit = _FakeAudit()
    holds = _FakeHolds(error=failure)
    planner = RetentionPlannerV1(audit, holds)
    record = RetentionRecordV1(_ids().mint_event_id(), RetentionClassV1.LOG_HOT, 0)
    decision = planner.plan(record, 15 * _DAY_NS)
    (audit_record,) = audit.snapshot()
    assert holds.lookups == 1
    assert decision.action is RetentionActionV1.HELD
    assert decision.reason is RetentionReasonV1.HOLD_UNKNOWN
    assert audit_record.action is RetentionActionV1.HELD
