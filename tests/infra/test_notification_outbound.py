"""Unit tests for the synthetic, outbound-only notification kernel."""

from __future__ import annotations

import copy
import pickle
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

import pytest

import leviathan_core.security.authz_models as authz_models
from leviathan_core.seal import SealError
from leviathan_core.security import (
    AuthorizationPolicyV1,
    EffectV1,
    PolicyRuleV1,
    PrincipalV1,
    TrustedPrincipalAdapterV1,
    TrustedPrincipalV1,
)

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from infra.cloud.notification.models import (
    FakeTransportStatusV1,
    NotificationAuditRecordV1,
    NotificationChannelV1,
    NotificationConsentV1,
    NotificationDeliveryStateV1,
    NotificationEventTypeV1,
    NotificationEventV1,
    NotificationReasonCodeV1,
    NotificationRouteV1,
    NotificationScopeV1,
    NotificationTemplateV1,
    require_notification_audit_record,
    require_notification_delivery,
)
from infra.cloud.notification.outbound import NotificationOutbound
from infra.cloud.notification.transport import FakeNotificationTransport

NOW = datetime(2026, 10, 6, 12, 0, tzinfo=UTC)
NOW_NS = 1_791_288_000_000_000_000
ORG = "org-alpha"
PROJECT = "project-alpha"
DESTINATION = "ops-room"


def _principal(*, project: str = PROJECT, env: str = "paper") -> TrustedPrincipalV1:
    claims = PrincipalV1(
        principal_id="synthetic.operator",
        project_id=project,
        roles=("notification.sender",),
        env=env,
        venue="XNAS",
    )
    return TrustedPrincipalAdapterV1.from_verified_claims(
        claims, verifier_marker=authz_models._VERIFIER_MARKER
    )


def _policy(*, action: str = "notification:send") -> AuthorizationPolicyV1:
    return AuthorizationPolicyV1(
        "v1",
        PROJECT,
        datetime(2026, 10, 7, tzinfo=UTC),
        (
            PolicyRuleV1(
                rule_id="notify.allow",
                effect=EffectV1.ALLOW,
                roles=("notification.sender",),
                actions=(action,),
                resources=(f"notification:{ORG}",),
                env="paper",
                not_before=datetime(2026, 10, 6, 11, 59, tzinfo=UTC),
                not_after=datetime(2026, 10, 6, 12, 1, tzinfo=UTC),
                venue="XNAS",
            ),
        ),
    )


class _Consent:
    def __init__(self, consent: NotificationConsentV1 | None) -> None:
        self.consent = consent
        self.calls = 0

    def get_consent(self, *, org_id: str, destination_alias: str) -> NotificationConsentV1 | None:
        self.calls += 1
        return self.consent


class _Idempotency:
    def __init__(self) -> None:
        self.claimed: set[str] = set()
        self.completed: dict[str, NotificationDeliveryStateV1] = {}
        self.released: list[str] = []

    def claim(self, key: str) -> bool:
        if key in self.claimed:
            return False
        self.claimed.add(key)
        return True

    def release(self, key: str) -> None:
        self.claimed.discard(key)
        self.released.append(key)

    def complete(self, key: str, state: NotificationDeliveryStateV1) -> None:
        self.completed[key] = state


class _AmbiguousClaimIdempotency(_Idempotency):
    def __init__(self) -> None:
        super().__init__()
        self.claim_calls = 0
        self.lock = threading.Lock()

    def claim(self, key: str) -> bool:
        with self.lock:
            self.claim_calls += 1
            if self.claim_calls == 1:
                self.claimed.add(key)
                return True
            if self.claim_calls == 2:
                raise RuntimeError("ambiguous synthetic claim failure")
            return key not in self.claimed


class _NonBoolClaimIdempotency(_Idempotency):
    def claim(self, key: str) -> bool:
        return 1  # type: ignore[return-value]


class _Quota:
    def __init__(self, allowed: bool = True) -> None:
        self.allowed = allowed
        self.calls = 0

    def consume(
        self,
        *,
        org_id: str,
        destination_alias: str,
        now_utc_ns: int,
        max_per_minute: int,
    ) -> bool:
        self.calls += 1
        return self.allowed


class _Audit:
    def __init__(self, *, error: Exception | None = None, delay_ns: int = 0) -> None:
        self.error = error
        self.delay_ns = delay_ns
        self.records: list[NotificationAuditRecordV1] = []

    def append(self, record: NotificationAuditRecordV1, *, deadline_monotonic_ns: int) -> None:
        if self.error is not None:
            raise self.error
        if self.delay_ns:
            import time

            time.sleep(self.delay_ns / 1_000_000_000)
        self.records.append(record)


class _BlockingAllowAudit(_Audit):
    def __init__(self) -> None:
        super().__init__()
        self.allow_started = threading.Event()
        self.release_allow = threading.Event()

    def append(self, record: NotificationAuditRecordV1, *, deadline_monotonic_ns: int) -> None:
        if record.decision == "ALLOW":
            self.allow_started.set()
            if not self.release_allow.wait(timeout=2):
                raise TimeoutError("synthetic audit latch expired")
        super().append(record, deadline_monotonic_ns=deadline_monotonic_ns)


def _consent(
    *,
    granted: bool = True,
    revoked_at_ns: int | None = None,
    org_id: str = ORG,
    event_types: tuple[NotificationEventTypeV1, ...] = tuple(NotificationEventTypeV1),
) -> NotificationConsentV1:
    return NotificationConsentV1(
        consent_id="consent.1",
        org_id=org_id,
        destination_alias=DESTINATION,
        channel=NotificationChannelV1.TELEGRAM,
        allowed_event_types=event_types,
        granted=granted,
        recorded_at_ns=NOW_NS - 1,
        revoked_at_ns=revoked_at_ns,
    )


def _event(
    event_type: NotificationEventTypeV1 = NotificationEventTypeV1.SIGNAL,
    *,
    event_id: str = "event.1",
    org_id: str = ORG,
    destination_alias: str = DESTINATION,
) -> NotificationEventV1:
    templates = {
        NotificationEventTypeV1.SIGNAL: NotificationTemplateV1.SIGNAL_NOTICE,
        NotificationEventTypeV1.FILL: NotificationTemplateV1.FILL_NOTICE,
        NotificationEventTypeV1.RISK: NotificationTemplateV1.RISK_NOTICE,
    }
    return NotificationEventV1(
        event_id=event_id,
        org_id=org_id,
        event_type=event_type,
        occurred_at_ns=NOW_NS,
        correlation_id="corr.1",
        template_id=templates[event_type],
        destination_alias=destination_alias,
    )


def _system(
    *,
    event_types: tuple[NotificationEventTypeV1, ...] = tuple(NotificationEventTypeV1),
    consent: NotificationConsentV1 | None = None,
    policy: AuthorizationPolicyV1 | None = None,
    quota: _Quota | None = None,
    audit: _Audit | None = None,
    transport: FakeNotificationTransport | None = None,
    now: datetime = NOW,
    missing_consent_port: bool = False,
    idempotency: _Idempotency | None = None,
    audit_timeout_ns: int = 250_000_000,
) -> tuple[NotificationOutbound, _Idempotency, _Quota, _Audit, FakeNotificationTransport]:
    route = NotificationRouteV1(DESTINATION, NotificationChannelV1.TELEGRAM, event_types)
    scope = NotificationScopeV1(ORG, PROJECT, "paper", (route,), 12)
    idempotency_port = idempotency or _Idempotency()
    quota_port = quota or _Quota()
    audit_port = audit or _Audit()
    transport_port = transport or FakeNotificationTransport((FakeTransportStatusV1.DELIVERED,))
    outbound = NotificationOutbound(
        policy=policy if policy is not None else _policy(),
        scopes=(scope,),
        consent=(
            None
            if missing_consent_port
            else _Consent(consent if consent is not None else _consent())
        ),
        idempotency=idempotency_port,
        quota=quota_port,
        audit=audit_port,
        transport=transport_port,
        clock=lambda: now,
        audit_timeout_ns=audit_timeout_ns,
    )
    return outbound, idempotency_port, quota_port, audit_port, transport_port


@pytest.mark.parametrize("event_type", tuple(NotificationEventTypeV1))
def test_fixed_templates_send_all_supported_event_types(
    event_type: NotificationEventTypeV1,
) -> None:
    outbound, _, _, audit, transport = _system()

    result = outbound.send(_principal(), _event(event_type))

    assert result.state is NotificationDeliveryStateV1.DELIVERED
    assert result.reason_code is NotificationReasonCodeV1.AUTHORIZED
    assert len(audit.records) == 1
    assert audit.records[0].decision == "ALLOW"
    assert len(audit.records[0].request_sha256) == 64
    assert len(audit.records[0].decision_sha256) == 64
    assert len(audit.records[0].principal_sha256) == 64
    assert transport.attempts[0].payload in {
        "A signal notification is available.",
        "A fill notification is available.",
        "A risk notification is available.",
    }
    assert "event.1" not in transport.attempts[0].payload


@pytest.mark.parametrize(
    ("consent", "missing_port"),
    [
        (None, True),
        (_consent(granted=False), False),
        (_consent(revoked_at_ns=NOW_NS), False),
    ],
)
def test_missing_denied_or_revoked_consent_never_sends(
    consent: NotificationConsentV1 | None, missing_port: bool
) -> None:
    outbound, _, _, audit, transport = _system(consent=consent, missing_consent_port=missing_port)

    result = outbound.send(_principal(), _event())

    assert result.state is NotificationDeliveryStateV1.DENIED
    assert result.reason_code is NotificationReasonCodeV1.NOT_AUTHORIZED
    assert transport.attempts == ()
    assert audit.records[-1].decision == "DENY"


def test_scope_policy_and_environment_mismatches_fail_closed() -> None:
    outbound, _, _, _, transport = _system()

    for principal, event in (
        (_principal(project="project-other"), _event()),
        (_principal(env="live"), _event()),
        (_principal(), _event(org_id="org-other")),
        (_principal(), _event(destination_alias="unknown-room")),
    ):
        result = outbound.send(principal, event)
        assert result.state is NotificationDeliveryStateV1.DENIED
        assert result.reason_code is NotificationReasonCodeV1.NOT_AUTHORIZED

    assert transport.attempts == ()


def test_policy_missing_or_wrong_action_denies() -> None:
    route = NotificationRouteV1(
        DESTINATION, NotificationChannelV1.TELEGRAM, tuple(NotificationEventTypeV1)
    )
    scopes = (NotificationScopeV1(ORG, PROJECT, "paper", (route,), 12),)
    missing_transport = FakeNotificationTransport()
    outbound = NotificationOutbound(
        policy=None,
        scopes=scopes,
        consent=_Consent(_consent()),
        idempotency=_Idempotency(),
        quota=_Quota(),
        audit=_Audit(),
        transport=FakeNotificationTransport(),
        clock=lambda: NOW,
    )
    result = outbound.send(_principal(), _event())
    assert result.state is NotificationDeliveryStateV1.DENIED
    assert missing_transport.attempts == ()

    denied, _, _, _, denied_transport = _system(policy=_policy(action="notification:read"))
    assert denied.send(_principal(), _event()).state is NotificationDeliveryStateV1.DENIED
    assert denied_transport.attempts == ()


def test_duplicate_event_is_idempotent_and_quota_failure_releases_claim() -> None:
    outbound, idempotency, _, _, transport = _system()
    event = _event()

    assert outbound.send(_principal(), event).state is NotificationDeliveryStateV1.DELIVERED
    assert outbound.send(_principal(), event).state is NotificationDeliveryStateV1.DENIED
    assert len(transport.attempts) == 1

    quota_denied, quota_idem, _, _, quota_transport = _system(quota=_Quota(False))
    result = quota_denied.send(_principal(), _event())
    assert result.state is NotificationDeliveryStateV1.DENIED
    assert len(quota_idem.released) == 1
    assert quota_transport.attempts == ()
    assert len(idempotency.completed) == 1


def test_ambiguous_claim_cannot_release_another_sender_key() -> None:
    blocking_audit = _BlockingAllowAudit()
    idempotency = _AmbiguousClaimIdempotency()
    outbound, _, _, _, transport = _system(
        audit=blocking_audit,
        idempotency=idempotency,
        audit_timeout_ns=1_800_000_000,
    )
    principal, event = _principal(), _event()

    with ThreadPoolExecutor(max_workers=1) as executor:
        first = executor.submit(outbound.send, principal, event)
        assert blocking_audit.allow_started.wait(timeout=2)

        ambiguous = outbound.send(principal, event)
        duplicate = outbound.send(principal, event)
        blocking_audit.release_allow.set()
        delivered = first.result(timeout=2)

    assert ambiguous.state is NotificationDeliveryStateV1.DENIED
    assert ambiguous.reason_code is NotificationReasonCodeV1.CLAIM_AMBIGUOUS
    assert duplicate.state is NotificationDeliveryStateV1.DENIED
    assert duplicate.reason_code is NotificationReasonCodeV1.NOT_AUTHORIZED
    assert delivered.state is NotificationDeliveryStateV1.DELIVERED
    assert idempotency.claim_calls == 3
    assert idempotency.released == []
    assert len(transport.attempts) == 1


def test_non_boolean_claim_result_fails_closed_without_releasing_key() -> None:
    idempotency = _NonBoolClaimIdempotency()
    outbound, _, _, _, transport = _system(idempotency=idempotency)

    result = outbound.send(_principal(), _event())

    assert result.state is NotificationDeliveryStateV1.DENIED
    assert result.reason_code is NotificationReasonCodeV1.CLAIM_AMBIGUOUS
    assert idempotency.released == []
    assert transport.attempts == ()


@pytest.mark.parametrize("audit", [None, _Audit(error=RuntimeError("sensitive detail"))])
def test_missing_or_failed_audit_prevents_release(audit: _Audit | None) -> None:
    route = NotificationRouteV1(
        DESTINATION, NotificationChannelV1.TELEGRAM, tuple(NotificationEventTypeV1)
    )
    outbound = NotificationOutbound(
        policy=_policy(),
        scopes=(NotificationScopeV1(ORG, PROJECT, "paper", (route,), 12),),
        consent=_Consent(_consent()),
        idempotency=_Idempotency(),
        quota=_Quota(),
        audit=audit,
        transport=FakeNotificationTransport((FakeTransportStatusV1.DELIVERED,)),
        clock=lambda: NOW,
    )

    result = outbound.send(_principal(), _event())

    assert result.state is NotificationDeliveryStateV1.DENIED
    assert result.reason_code is NotificationReasonCodeV1.NOT_AUTHORIZED


def test_audit_deadline_overrun_denies_even_if_append_returns() -> None:
    outbound, _, _, _, transport = _system(audit=_Audit(delay_ns=5_000_000))
    outbound._audit_timeout_ns = 1  # type: ignore[attr-defined]

    result = outbound.send(_principal(), _event())

    assert result.state is NotificationDeliveryStateV1.DENIED
    assert transport.attempts == ()


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (FakeTransportStatusV1.FAILED, NotificationDeliveryStateV1.FAILED),
        (FakeTransportStatusV1.UNKNOWN, NotificationDeliveryStateV1.UNKNOWN),
    ],
)
def test_failed_or_unknown_transport_is_reported_without_retry(
    status: FakeTransportStatusV1, expected: NotificationDeliveryStateV1
) -> None:
    outbound, idempotency, _, _, transport = _system(transport=FakeNotificationTransport((status,)))

    result = outbound.send(_principal(), _event())

    assert result.state is expected
    assert len(transport.attempts) == 1
    assert next(iter(idempotency.completed.values())) is expected


def test_payload_and_audit_are_redacted_and_results_are_sealed() -> None:
    outbound, _, _, audit, transport = _system()
    result = outbound.send(_principal(), _event(event_id="event.private-ssn-123-45-6789"))

    assert result.state is NotificationDeliveryStateV1.DELIVERED
    assert len(transport.attempts[0].payload) < 64
    assert "private" not in transport.attempts[0].payload
    assert "123-45-6789" not in repr(audit.records[0])
    assert "event.private-ssn-123-45-6789" not in repr(audit.records[0])
    assert require_notification_delivery(result) is result
    with pytest.raises(SealError):
        require_notification_delivery(result.model_copy(update={"state": "DENIED"}))
    with pytest.raises(SealError):
        require_notification_audit_record(audit.records[0].model_copy(update={"decision": "DENY"}))


def test_security_values_reject_copy_pickle_and_free_text_payload_fields() -> None:
    event = _event()
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(TypeError):
            operation(event)
    with pytest.raises(TypeError):
        NotificationEventV1(
            event_id="event.2",
            org_id=ORG,
            event_type=NotificationEventTypeV1.SIGNAL,
            occurred_at_ns=NOW_NS,
            correlation_id="corr.2",
            template_id=NotificationTemplateV1.SIGNAL_NOTICE,
            destination_alias=DESTINATION,
            text="secret data",  # type: ignore[call-arg]
        )


def test_fake_transport_consumes_scripted_outcomes_and_has_no_inbound_api() -> None:
    fake = FakeNotificationTransport(
        (FakeTransportStatusV1.FAILED, FakeTransportStatusV1.DELIVERED)
    )
    kwargs = {
        "channel": NotificationChannelV1.TELEGRAM,
        "destination_alias": DESTINATION,
        "payload": "safe fixture",
        "idempotency_key": "idempotency.1",
        "deadline_monotonic_ns": 1,
    }

    assert fake.send(**kwargs) is FakeTransportStatusV1.FAILED
    assert fake.send(**kwargs) is FakeTransportStatusV1.DELIVERED
    assert not hasattr(fake, "receive")
    assert not hasattr(fake, "poll_commands")
