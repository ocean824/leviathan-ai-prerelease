"""Independent OBS-005 alert acceptance against contract semantics."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import sys
from dataclasses import replace
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from uuid import uuid4

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from infra.cloud.telemetry.alerts import (
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
    RetentionActionV1,
    RetentionAuditRecordV1,
    RetentionClassV1,
    RetentionPlannerV1,
    RetentionReasonV1,
    RetentionRecordV1,
)

from leviathan_core.observability.context import (
    BuildIdentityV1,
    DiagnosticIdFactoryV1,
    DiagnosticRegistriesV1,
    DiagnosticRuntimeV1,
    GeneratedIdV1,
    ObservationContextV1,
    RegistrySnapshotV1,
)
from leviathan_core.observability.live_log import (
    LiveLogBufferV1,
    LiveLogEventV1,
    LiveLogResultCodeV1,
    LiveLogSummaryCodeV1,
    LiveLogToolCategoryV1,
    LiveLogToolNameV1,
)
from leviathan_core.observability.models import LogLevel
from leviathan_core.security.principal_verifier import (
    PrincipalVerifier,
    RSAPublicKeyV1,
    TrustedIssuerV1,
    VerifiedPrincipalV1,
)

_T0 = 1_800_000_000_000_000_000
_NS = 1_000_000_000
_NOW = datetime(2026, 10, 6, 12, 0, tzinfo=UTC)
_NOW_NS = int(_NOW.timestamp()) * _NS
_ISSUER = "https://obs005.synthetic.invalid"
_AUDIENCE = "leviathan-api"
_KID = "obs005-test-key"
_PROJECT = "leviathan-ai"
_KEY_DATA = json.loads(
    (
        Path(__file__).resolve().parents[2]
        / "packages"
        / "leviathan-core"
        / "tests"
        / "security"
        / "fixtures"
        / "sec003_synthetic_rsa.json"
    ).read_text(encoding="utf-8")
)
_PUBLIC_N = int(_KEY_DATA["modulus_hex"], 16)
_PUBLIC_E = int(_KEY_DATA["public_exponent_hex"], 16)
_PRIVATE_D = int(_KEY_DATA["private_exponent_hex"], 16)
_SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")


class _KeySet:
    def get_key(self, issuer: str, kid: str) -> RSAPublicKeyV1 | None:
        if (issuer, kid) == (_ISSUER, _KID):
            return RSAPublicKeyV1(_PUBLIC_N, _PUBLIC_E)
        return None


class _Revocations:
    def is_revoked(self, issuer: str, jti: str) -> bool:
        return False


class _CorrelationPolicy:
    def __init__(self, allowed: bool = True) -> None:
        self.allowed = allowed
        self.actions: list[str] = []

    def allows(self, principal: VerifiedPrincipalV1, action: str) -> bool:
        self.actions.append(action)
        return self.allowed


class _LegalHolds:
    def __init__(self, result: bool | None = False) -> None:
        self.result = result
        self.records: list[GeneratedIdV1] = []

    def is_held(self, record_id: GeneratedIdV1) -> bool | None:
        self.records.append(record_id)
        return self.result


class _FakeRetentionAudit:
    def __init__(self) -> None:
        self.records: list[RetentionAuditRecordV1] = []

    def append(
        self,
        *,
        record_key_sha256: str,
        retention_class: RetentionClassV1,
        action: RetentionActionV1,
        reason: RetentionReasonV1,
        recorded_utc_ns: int,
    ) -> RetentionAuditRecordV1:
        sequence = len(self.records) + 1
        previous_hash = self.records[-1].record_hash if self.records else "0" * 64
        payload = {
            "sequence": sequence,
            "record_key_sha256": record_key_sha256,
            "retention_class": retention_class.value,
            "action": action.value,
            "reason": reason.value,
            "recorded_utc_ns": recorded_utc_ns,
            "previous_hash": previous_hash,
        }
        record_hash = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii")
        ).hexdigest()
        record = RetentionAuditRecordV1(
            sequence,
            record_key_sha256,
            retention_class,
            action,
            reason,
            recorded_utc_ns,
            previous_hash,
            record_hash,
        )
        self.records.append(record)
        return record

    def snapshot(self) -> tuple[RetentionAuditRecordV1, ...]:
        return tuple(self.records)


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _verified_principal(
    *,
    org_id: str = "obs005-org-a",
    role: str = "Operator",
    scopes: tuple[str, ...] = (
        "ops.observability.correlate",
        "logs.append",
        "logs.read",
    ),
) -> VerifiedPrincipalV1:
    issued = int(_NOW.timestamp())
    claims = {
        "iss": _ISSUER,
        "aud": _AUDIENCE,
        "org": org_id,
        "sub": "obs005-synthetic-operator",
        "role": role,
        "scope": list(scopes),
        "env": "staging",
        "jti": f"jti-{org_id}-{role}-{len(scopes)}",
        "iat": issued,
        "nbf": issued,
        "exp": issued + 300,
    }
    header = {"alg": "RS256", "kid": _KID, "typ": "JWT"}
    signing_input = ".".join(
        _b64(json.dumps(item, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        for item in (header, claims)
    ).encode("ascii")
    digest_info = _SHA256_DIGEST_INFO + hashlib.sha256(signing_input).digest()
    key_bytes = (_PUBLIC_N.bit_length() + 7) // 8
    padding_length = key_bytes - len(digest_info) - 3
    encoded = b"\x00\x01" + b"\xff" * padding_length + b"\x00" + digest_info
    signature = pow(int.from_bytes(encoded, "big"), _PRIVATE_D, _PUBLIC_N).to_bytes(
        key_bytes, "big"
    )
    token = f"{signing_input.decode('ascii')}.{_b64(signature)}"
    return PrincipalVerifier(
        trusted_issuer=TrustedIssuerV1(
            _ISSUER,
            _AUDIENCE,
            org_id,
            _PROJECT,
            "staging",
        ),
        key_set=_KeySet(),
        revocations=_Revocations(),
        clock=lambda: _NOW,
    ).verify(token)


def _event() -> LiveLogEventV1:
    runtime = DiagnosticRuntimeV1(
        registries=DiagnosticRegistriesV1(
            services=RegistrySnapshotV1.from_members({"leviathan-ai"}),
            components=RegistrySnapshotV1.from_members({"obs005-worker"}),
            strategies=RegistrySnapshotV1.from_members({"strategy-alpha"}),
            instruments=RegistrySnapshotV1.from_members({"ES"}),
            venues=RegistrySnapshotV1.from_members({"XCME"}),
        ),
        id_factory=DiagnosticIdFactoryV1(uuid4_factory=uuid4),
        build_identity=BuildIdentityV1("1.2.3"),
    )
    context = ObservationContextV1.create(
        runtime=runtime,
        service="leviathan-ai",
        component="obs005-worker",
        env="staging",
        symbol="ES",
        venue="XCME",
    )
    return LiveLogEventV1.create(
        context=context,
        started_utc_ns=_NOW_NS,
        ended_utc_ns=_NOW_NS + 100,
        tool_name=LiveLogToolNameV1.OTHER,
        tool_category=LiveLogToolCategoryV1.SYSTEM,
        result_code=LiveLogResultCodeV1.SUCCESS,
        summary_code=LiveLogSummaryCodeV1.TOOL_COMPLETED,
    )


def _labels(**changes: str) -> MetricLabelsV1:
    values = {
        "service": "leviathan",
        "component": "engine",
        "env": "test",
        "region": "local",
        "instance": "node-a",
        "venue": "XCME",
    }
    values.update(changes)
    return MetricLabelsV1(**values)


def _ids() -> DiagnosticIdFactoryV1:
    return DiagnosticIdFactoryV1(uuid4_factory=uuid4)


def _observation(
    timestamp: int,
    *,
    labels: MetricLabelsV1 | None = None,
    decision: Decimal | None = None,
    order_ack: Decimal | None = None,
    pipeline: Decimal | None = None,
    connector_up: bool | None = None,
    error_rate: Decimal | None = None,
    skew: Decimal | None = None,
    readiness: bool | None = None,
    market_hours: bool = True,
) -> AlertObservationV1:
    return AlertObservationV1(
        timestamp_utc_ns=timestamp,
        labels=labels or _labels(),
        decision_p99_seconds=decision,
        order_ack_p99_seconds=order_ack,
        pipeline_lag_seconds=pipeline,
        connector_up=connector_up,
        error_rate_5m=error_rate,
        time_sync_offset_seconds=skew,
        readiness_ready=readiness,
        market_hours=market_hours,
        dashboard_ref="dashboards/ops",
        runbook_ref="runbooks/telemetry",
        deployment_sha256="a" * 64,
    )


def test_latency_and_error_thresholds_fire_only_above_exact_limits() -> None:
    engine = AlertEngineV1(_ids())

    assert (
        engine.evaluate(
            _observation(
                _T0,
                decision=Decimal("0.008"),
                order_ack=Decimal("0.012"),
                error_rate=Decimal("0.02"),
            )
        )
        == ()
    )

    pages = engine.evaluate(
        _observation(
            _T0 + 1,
            decision=Decimal("0.008000001"),
            order_ack=Decimal("0.012000001"),
            error_rate=Decimal("0.020001"),
        )
    )
    assert {page.failure_mode for page in pages} == {
        AlertFailureModeV1.DECISION_LATENCY,
        AlertFailureModeV1.ORDER_ACK_LATENCY,
        AlertFailureModeV1.ERROR_RATE,
    }


@pytest.mark.parametrize(
    ("field", "mode", "value"),
    [
        ("pipeline", AlertFailureModeV1.PIPELINE_LAG, Decimal("0.500001")),
        ("connector_up", AlertFailureModeV1.CONNECTOR_DOWN, False),
        ("skew", AlertFailureModeV1.TIME_SYNC_SKEW, Decimal("-0.050001")),
        ("readiness", AlertFailureModeV1.READINESS_FAILURE, False),
    ],
)
def test_sustained_thresholds_require_strictly_more_than_the_window(
    field: str, mode: AlertFailureModeV1, value: Decimal | bool
) -> None:
    window = {
        AlertFailureModeV1.PIPELINE_LAG: 300 * _NS,
        AlertFailureModeV1.CONNECTOR_DOWN: 60 * _NS,
        AlertFailureModeV1.TIME_SYNC_SKEW: 120 * _NS,
        AlertFailureModeV1.READINESS_FAILURE: 120 * _NS,
    }[mode]
    kwargs = {field: value}
    engine = AlertEngineV1(_ids())

    assert engine.evaluate(_observation(_T0, **kwargs)) == ()
    assert engine.evaluate(_observation(_T0 + window, **kwargs)) == ()
    pages = engine.evaluate(_observation(_T0 + window + 1, **kwargs))
    assert len(pages) == 1
    assert pages[0].failure_mode is mode


def test_readiness_failure_is_suppressed_outside_market_hours() -> None:
    engine = AlertEngineV1(_ids())
    assert engine.evaluate(_observation(_T0, readiness=False, market_hours=False)) == ()
    assert engine.evaluate(_observation(_T0 + 180 * _NS, readiness=False, market_hours=False)) == ()


def test_connector_root_inhibits_sustained_downstream_venue_page() -> None:
    engine = AlertEngineV1(_ids())
    assert engine.evaluate(_observation(_T0, connector_up=False, pipeline=Decimal("0.6"))) == ()
    connector_pages = engine.evaluate(
        _observation(
            _T0 + 60 * _NS,
            connector_up=False,
            pipeline=Decimal("0.6"),
        )
    )
    assert connector_pages == ()
    connector_pages = engine.evaluate(
        _observation(
            _T0 + 60 * _NS + 1,
            connector_up=False,
            pipeline=Decimal("0.6"),
        )
    )
    assert [page.failure_mode for page in connector_pages] == [AlertFailureModeV1.CONNECTOR_DOWN]
    assert (
        engine.evaluate(
            _observation(
                _T0 + 300 * _NS + 1,
                connector_up=False,
                pipeline=Decimal("0.6"),
            )
        )
        == ()
    )


def test_one_active_root_is_paged_once_across_repeated_observations() -> None:
    engine = AlertEngineV1(_ids())
    first = engine.evaluate(_observation(_T0, decision=Decimal("0.009")))
    later = engine.evaluate(_observation(_T0 + 10 * _NS, decision=Decimal("0.010")))
    assert len(first) == 1
    assert later == ()


def test_resolved_root_can_page_again_when_the_failure_recurs() -> None:
    engine = AlertEngineV1(_ids())
    assert len(engine.evaluate(_observation(_T0, decision=Decimal("0.009")))) == 1
    assert engine.evaluate(_observation(_T0 + 1, decision=None)) == ()
    recurrence = engine.evaluate(_observation(_T0 + 2, decision=Decimal("0.009")))
    assert len(recurrence) == 1
    assert recurrence[0].failure_mode is AlertFailureModeV1.DECISION_LATENCY


def test_root_grouping_uses_service_component_and_failure_mode() -> None:
    engine = AlertEngineV1(_ids())
    assert len(engine.evaluate(_observation(_T0, decision=Decimal("0.009")))) == 1
    assert (
        engine.evaluate(
            _observation(
                _T0 + 1,
                labels=_labels(instance="node-b", region="east", env="staging"),
                decision=Decimal("0.009"),
            )
        )
        == ()
    )


def test_emitted_alert_has_safe_actionable_metadata_and_factory_owned_ids() -> None:
    ids = _ids()
    affected = ids.mint_order_id()
    page = AlertEngineV1(ids).evaluate(
        AlertObservationV1(
            timestamp_utc_ns=_T0,
            labels=_labels(),
            decision_p99_seconds=Decimal("0.009"),
            dashboard_ref="dashboards/ops",
            runbook_ref="runbooks/telemetry",
            deployment_sha256="b" * 64,
            affected_ids=(affected,),
        )
    )[0]
    assert page.dashboard_ref == "dashboards/ops"
    assert page.runbook_ref == "runbooks/telemetry"
    assert page.deployment_sha256 == "b" * 64
    assert page.affected_ids == (affected,)
    assert len(page.root_cause_id) == 64
    assert "principal" not in repr(page).lower()


def test_missing_alert_references_use_explicit_safe_markers() -> None:
    page = AlertEngineV1(_ids()).evaluate(
        AlertObservationV1(
            timestamp_utc_ns=_T0,
            labels=_labels(),
            decision_p99_seconds=Decimal("0.009"),
        )
    )[0]
    assert page.dashboard_ref == "unavailable"
    assert page.runbook_ref == "unavailable"
    assert page.deployment_sha256 == "0" * 64


def test_secret_shaped_alert_reference_is_rejected_without_echoing_value() -> None:
    secret = "token=synthetic_canary"
    with pytest.raises(AlertError) as invalid:
        AlertObservationV1(
            timestamp_utc_ns=_T0,
            labels=_labels(),
            decision_p99_seconds=Decimal("0.009"),
            dashboard_ref=secret,
        )
    assert invalid.value.code == "ALERT_OBSERVATION_INVALID"
    assert secret not in str(invalid.value)


def test_unowned_affected_identifier_is_rejected_without_echoing_it() -> None:
    owner = _ids()
    other = _ids()
    foreign_id = other.mint_event_id()
    with pytest.raises(AlertError) as error:
        AlertEngineV1(owner).evaluate(
            AlertObservationV1(
                timestamp_utc_ns=_T0,
                labels=_labels(),
                decision_p99_seconds=Decimal("0.009"),
                affected_ids=(foreign_id,),
            )
        )
    assert error.value.code == "ALERT_ID_INVALID"
    assert str(foreign_id.value) not in str(error.value)


def test_backpressure_drops_debug_before_warn_and_error() -> None:
    page = AlertEngineV1(_ids()).evaluate(_observation(_T0, decision=Decimal("0.009")))[0]
    outbox = AlertOutboxV1(max_items=1)
    assert outbox.submit(page, LogLevel.DEBUG) is AlertQueueResultV1.QUEUED
    assert outbox.submit(page, LogLevel.WARN) is AlertQueueResultV1.QUEUED
    assert outbox.pending == 1
    assert outbox.submit(page, LogLevel.ERROR) is AlertQueueResultV1.BACKPRESSURED
    delivery = outbox.drain(limit=1)[0]
    assert delivery.page == page
    assert delivery.level is LogLevel.WARN


_DAY_NS = 86_400 * _NS
_RETENTION_DAYS = {
    RetentionClassV1.METRIC_5S: 7,
    RetentionClassV1.METRIC_30S: 30,
    RetentionClassV1.METRIC_5M: 90,
    RetentionClassV1.LOG_HOT: 14,
    RetentionClassV1.LOG_ARCHIVE: 90,
    RetentionClassV1.TRACE_HOT: 7,
    RetentionClassV1.TRACE_SUMMARY: 30,
}


@pytest.mark.parametrize(("retention_class", "days"), _RETENTION_DAYS.items())
def test_retention_classes_keep_their_exact_utc_expiry(
    retention_class: RetentionClassV1, days: int
) -> None:
    audit = _FakeRetentionAudit()
    holds = _LegalHolds(False)
    planner = RetentionPlannerV1(audit, holds)
    record = RetentionRecordV1(_ids().mint_event_id(), retention_class, _T0)
    expected_expiry = _T0 + days * _DAY_NS

    decision = planner.plan(record, expected_expiry - 1)
    assert decision.action is RetentionActionV1.RETAIN
    assert decision.expires_utc_ns == expected_expiry
    assert decision.audit_sequence == 1
    assert decision.audit_hash == audit.snapshot()[0].record_hash


def test_deletion_becomes_eligible_at_exact_expiry_only_after_audit() -> None:
    audit = _FakeRetentionAudit()
    holds = _LegalHolds(False)
    planner = RetentionPlannerV1(audit, holds)
    record = RetentionRecordV1(_ids().mint_event_id(), RetentionClassV1.METRIC_5S, _T0)
    expiry = _T0 + 7 * _DAY_NS

    decision = planner.plan(record, expiry)

    assert decision.action is RetentionActionV1.DELETE_ELIGIBLE
    entry = audit.snapshot()[0]
    assert entry.action is RetentionActionV1.DELETE_ELIGIBLE
    assert entry.sequence == decision.audit_sequence
    assert entry.record_hash == decision.audit_hash
    assert holds.records == [record.record_id]


@pytest.mark.parametrize(
    ("policy_known", "hold", "expected_action", "expected_reason"),
    [
        (False, False, RetentionActionV1.BLOCKED, RetentionReasonV1.POLICY_UNKNOWN),
        (True, True, RetentionActionV1.HELD, RetentionReasonV1.LEGAL_HOLD),
        (True, None, RetentionActionV1.HELD, RetentionReasonV1.HOLD_UNKNOWN),
    ],
)
def test_unknown_policy_or_hold_and_active_hold_never_allow_deletion(
    policy_known: bool,
    hold: bool | None,
    expected_action: RetentionActionV1,
    expected_reason: RetentionReasonV1,
) -> None:
    audit = _FakeRetentionAudit()
    record = RetentionRecordV1(_ids().mint_event_id(), RetentionClassV1.METRIC_5S, _T0)
    holds = _LegalHolds(hold)
    planner = RetentionPlannerV1(audit, holds)

    decision = planner.plan(
        record,
        _T0 + 8 * _DAY_NS,
        policy_known=policy_known,
    )

    assert decision.action is expected_action
    assert decision.reason is expected_reason
    assert audit.snapshot()[0].action is expected_action


@pytest.mark.parametrize("failure", [RuntimeError, TimeoutError])
def test_legal_hold_resolver_failure_is_audited_and_fails_closed(
    failure: type[Exception],
) -> None:
    class BrokenHolds:
        def is_held(self, record_id: GeneratedIdV1) -> bool:
            raise failure("synthetic hold source failure")

    audit = _FakeRetentionAudit()
    record = RetentionRecordV1(_ids().mint_event_id(), RetentionClassV1.LOG_HOT, _T0)
    planner = RetentionPlannerV1(audit, BrokenHolds())
    decision = planner.plan(record, _T0 + 15 * _DAY_NS)

    assert decision.action is RetentionActionV1.HELD
    assert decision.reason is RetentionReasonV1.HOLD_UNKNOWN
    assert audit.snapshot()[0].action is RetentionActionV1.HELD
    assert "synthetic hold source failure" not in repr(decision)


def test_non_boolean_legal_hold_result_is_treated_as_unknown_hold() -> None:
    class InvalidHolds:
        def is_held(self, record_id: GeneratedIdV1) -> bool | None:
            return "unknown"  # type: ignore[return-value]

    audit = _FakeRetentionAudit()
    record = RetentionRecordV1(_ids().mint_event_id(), RetentionClassV1.METRIC_30S, _T0)
    decision = RetentionPlannerV1(audit, InvalidHolds()).plan(record, _T0 + 31 * _DAY_NS)
    assert decision.action is RetentionActionV1.HELD
    assert decision.reason is RetentionReasonV1.HOLD_UNKNOWN
    assert audit.snapshot()[0].action is RetentionActionV1.HELD


def test_audit_failure_blocks_retention_eligibility_without_echoing_error() -> None:
    class BrokenAudit:
        def append(self, **kwargs: object) -> RetentionAuditRecordV1:
            raise RuntimeError("synthetic audit secret")

    record = RetentionRecordV1(_ids().mint_event_id(), RetentionClassV1.METRIC_5S, _T0)
    decision = RetentionPlannerV1(BrokenAudit(), _LegalHolds(False)).plan(record, _T0 + 8 * _DAY_NS)
    assert decision.action is RetentionActionV1.BLOCKED
    assert decision.reason is RetentionReasonV1.AUDIT_UNAVAILABLE
    assert decision.audit_sequence is None
    assert "synthetic audit secret" not in repr(decision)


@pytest.mark.parametrize(
    ("field", "forged_value"),
    [
        ("retention_class", RetentionClassV1.LOG_HOT),
        ("action", RetentionActionV1.RETAIN),
        ("reason", RetentionReasonV1.NOT_EXPIRED),
        ("record_key_sha256", "f" * 64),
        ("recorded_utc_ns", _T0 + 8 * _DAY_NS - 1),
        ("sequence", -1),
        ("sequence", 0),
        ("previous_hash", "f" * 64),
        ("record_hash", "f" * 64),
        ("record_hash", "F" * 64),
    ],
)
def test_malformed_audit_ack_never_makes_expired_record_eligible(
    field: str, forged_value: object
) -> None:
    class MalformedAudit:
        def append(
            self,
            *,
            record_key_sha256: str,
            retention_class: RetentionClassV1,
            action: RetentionActionV1,
            reason: RetentionReasonV1,
            recorded_utc_ns: int,
        ) -> RetentionAuditRecordV1:
            valid = _FakeRetentionAudit().append(
                record_key_sha256=record_key_sha256,
                retention_class=retention_class,
                action=action,
                reason=reason,
                recorded_utc_ns=recorded_utc_ns,
            )
            return replace(valid, **{field: forged_value})

    record = RetentionRecordV1(_ids().mint_event_id(), RetentionClassV1.METRIC_5S, _T0)
    decision = RetentionPlannerV1(MalformedAudit(), _LegalHolds(False)).plan(
        record, _T0 + 8 * _DAY_NS
    )

    assert decision.action is RetentionActionV1.BLOCKED
    assert decision.reason is RetentionReasonV1.AUDIT_UNAVAILABLE
    assert decision.audit_sequence is None
    assert decision.audit_hash is None


def test_wrong_audit_ack_type_blocks_expired_retention() -> None:
    class WrongTypeAudit:
        def append(
            self,
            *,
            record_key_sha256: str,
            retention_class: RetentionClassV1,
            action: RetentionActionV1,
            reason: RetentionReasonV1,
            recorded_utc_ns: int,
        ) -> RetentionAuditRecordV1:
            return object()  # type: ignore[return-value]

    record = RetentionRecordV1(_ids().mint_event_id(), RetentionClassV1.METRIC_5S, _T0)
    decision = RetentionPlannerV1(WrongTypeAudit(), _LegalHolds(False)).plan(
        record, _T0 + 8 * _DAY_NS
    )
    assert decision.action is RetentionActionV1.BLOCKED
    assert decision.reason is RetentionReasonV1.AUDIT_UNAVAILABLE
    assert decision.audit_sequence is None
    assert decision.audit_hash is None


def test_duplicate_audit_sequence_cannot_authorize_second_expired_action() -> None:
    class DuplicateSequenceAudit:
        def __init__(self) -> None:
            self._valid = _FakeRetentionAudit()
            self._calls = 0

        def append(
            self,
            *,
            record_key_sha256: str,
            retention_class: RetentionClassV1,
            action: RetentionActionV1,
            reason: RetentionReasonV1,
            recorded_utc_ns: int,
        ) -> RetentionAuditRecordV1:
            self._calls += 1
            record = self._valid.append(
                record_key_sha256=record_key_sha256,
                retention_class=retention_class,
                action=action,
                reason=reason,
                recorded_utc_ns=recorded_utc_ns,
            )
            if self._calls == 1:
                return record
            return replace(record, sequence=1)

    audit = DuplicateSequenceAudit()
    planner = RetentionPlannerV1(audit, _LegalHolds(False))
    record = RetentionRecordV1(_ids().mint_event_id(), RetentionClassV1.METRIC_5S, _T0)
    expired_at = _T0 + 8 * _DAY_NS
    first = planner.plan(record, expired_at)
    second = planner.plan(record, expired_at + 1)

    assert first.action is RetentionActionV1.DELETE_ELIGIBLE
    assert second.action is RetentionActionV1.BLOCKED
    assert second.reason is RetentionReasonV1.AUDIT_UNAVAILABLE
    assert second.audit_sequence is None
    assert second.audit_hash is None


def test_log_hot_can_be_archived_for_the_optional_archive_window() -> None:
    audit = _FakeRetentionAudit()
    planner = RetentionPlannerV1(audit, _LegalHolds(False))
    record = RetentionRecordV1(_ids().mint_event_id(), RetentionClassV1.LOG_HOT, _T0)
    decision = planner.plan(
        record,
        _T0 + 15 * _DAY_NS,
        archive_enabled=True,
    )
    assert decision.action is RetentionActionV1.ARCHIVE_ELIGIBLE
    assert decision.expires_utc_ns == _T0 + 90 * _DAY_NS


def test_correlation_is_authorized_and_confined_to_verified_org() -> None:
    async def scenario() -> None:
        principal_a = _verified_principal(org_id="obs005-org-a")
        principal_b = _verified_principal(org_id="obs005-org-b")
        event = _event()
        buffer = LiveLogBufferV1(max_entries=8, max_orgs=4)
        await buffer.append(principal_a, event)
        policy = _CorrelationPolicy()
        kernel = CorrelationKernelV1(buffer, policy)

        visible = await kernel.correlate(principal_a, event.correlation_id)
        hidden = await kernel.correlate(principal_b, event.correlation_id)

        assert len(visible) == 1
        assert visible[0].event.correlation_id == event.correlation_id
        assert hidden == ()
        assert policy.actions == [
            "ops.observability.correlate",
            "ops.observability.correlate",
        ]
        serialized = visible[0].event.serialized_line
        assert "obs005-org-a" not in serialized
        assert "obs005-synthetic-operator" not in serialized

    asyncio.run(scenario())


def test_correlation_allows_devops_with_verified_scope_and_policy() -> None:
    async def scenario() -> None:
        principal = _verified_principal(role="dEvOpS")
        event = _event()
        buffer = LiveLogBufferV1(max_entries=4, max_orgs=2)
        await buffer.append(principal, event)
        policy = _CorrelationPolicy()
        result = await CorrelationKernelV1(buffer, policy).correlate(
            principal, event.correlation_id
        )
        assert len(result) == 1
        assert policy.actions == ["ops.observability.correlate"]

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("principal", "policy_allowed"),
    [
        ({"role": "Operator"}, True),
        (_verified_principal(role="Analyst"), True),
        (
            _verified_principal(scopes=("logs.append", "logs.read")),
            True,
        ),
        (
            _verified_principal(scopes=("ops.observability.correlate", "logs.append")),
            True,
        ),
        (_verified_principal(), False),
    ],
)
def test_correlation_denies_unverified_wrong_role_missing_scope_or_policy_denial(
    principal: object, policy_allowed: bool
) -> None:
    async def scenario() -> None:
        kernel = CorrelationKernelV1(
            LiveLogBufferV1(max_orgs=2), _CorrelationPolicy(policy_allowed)
        )
        with pytest.raises(CorrelationError) as denied:
            await kernel.correlate(principal, "00000000-0000-4000-8000-000000000001")
        assert denied.value.code == "CORRELATION_ACCESS_DENIED"
        assert "obs005" not in str(denied.value)

    asyncio.run(scenario())


def test_malformed_correlation_id_is_rejected_with_a_fixed_error() -> None:
    async def scenario() -> None:
        kernel = CorrelationKernelV1(LiveLogBufferV1(max_orgs=2), _CorrelationPolicy())
        with pytest.raises(CorrelationError) as invalid:
            await kernel.correlate(_verified_principal(), "sk_test_synthetic_canary")
        assert invalid.value.code == "CORRELATION_ID_INVALID"
        assert "sk_test_synthetic_canary" not in str(invalid.value)

    asyncio.run(scenario())
