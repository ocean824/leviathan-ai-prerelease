"""Contract-level acceptance for outbound-only notifications with fake ports."""

from __future__ import annotations

import copy
import pickle
import sys
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from infra.cloud.notification.models import (
    FakeTransportStatusV1,
    NotificationChannelV1,
    NotificationConsentV1,
    NotificationDeliveryStateV1,
    NotificationEventTypeV1,
    NotificationEventV1,
    NotificationModelError,
    NotificationReasonCodeV1,
    NotificationRouteV1,
    NotificationScopeV1,
    NotificationTemplateV1,
    require_notification_audit_record,
    require_notification_delivery,
)
from infra.cloud.notification.outbound import NotificationOutbound
from infra.cloud.notification.transport import FakeNotificationTransport

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

_NOW = datetime(2026, 10, 6, 12, tzinfo=UTC)
_NOW_NS = 1_791_288_000_000_000_000
_ORG = "org-acceptance"
_PROJECT = "project-acceptance"
_DESTINATION = "ops-room"
_EVENT_TEMPLATES = {
    NotificationEventTypeV1.SIGNAL: NotificationTemplateV1.SIGNAL_NOTICE,
    NotificationEventTypeV1.FILL: NotificationTemplateV1.FILL_NOTICE,
    NotificationEventTypeV1.RISK: NotificationTemplateV1.RISK_NOTICE,
}


def _principal(*, project: str = _PROJECT, env: str = "paper") -> TrustedPrincipalV1:
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
        _PROJECT,
        _NOW + timedelta(days=1),
        (
            PolicyRuleV1(
                rule_id="notify.acceptance.allow",
                effect=EffectV1.ALLOW,
                roles=("notification.sender",),
                actions=(action,),
                resources=(f"notification:{_ORG}",),
                env="paper",
                not_before=_NOW - timedelta(minutes=1),
                not_after=_NOW + timedelta(minutes=1),
                venue="XNAS",
            ),
        ),
    )


def _event(
    event_type: NotificationEventTypeV1 = NotificationEventTypeV1.SIGNAL,
    *,
    event_id: str = "event.acceptance.1",
    org_id: str = _ORG,
    destination_alias: str = _DESTINATION,
) -> NotificationEventV1:
    return NotificationEventV1(
        event_id=event_id,
        org_id=org_id,
        event_type=event_type,
        occurred_at_ns=_NOW_NS,
        correlation_id="correlation.acceptance.1",
        template_id=_EVENT_TEMPLATES[event_type],
        destination_alias=destination_alias,
    )


def _consent(
    *,
    granted: bool = True,
    org_id: str = _ORG,
    destination_alias: str = _DESTINATION,
    channel: NotificationChannelV1 = NotificationChannelV1.TELEGRAM,
    event_types: tuple[NotificationEventTypeV1, ...] = tuple(NotificationEventTypeV1),
    recorded_at_ns: int = _NOW_NS - 1,
    revoked_at_ns: int | None = None,
) -> NotificationConsentV1:
    return NotificationConsentV1(
        consent_id="consent.acceptance.1",
        org_id=org_id,
        destination_alias=destination_alias,
        channel=channel,
        allowed_event_types=event_types,
        granted=granted,
        recorded_at_ns=recorded_at_ns,
        revoked_at_ns=revoked_at_ns,
    )


class _ConsentPort:
    def __init__(self, consent: NotificationConsentV1 | None) -> None:
        self.consent = consent
        self.calls: list[tuple[str, str]] = []

    def get_consent(self, *, org_id: str, destination_alias: str) -> NotificationConsentV1 | None:
        self.calls.append((org_id, destination_alias))
        return self.consent


class _IdempotencyPort:
    def __init__(self) -> None:
        self.claimed: set[str] = set()
        self.released: list[str] = []
        self.completed: dict[str, NotificationDeliveryStateV1] = {}

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


class _QuotaPort:
    def __init__(self, allowed: bool = True) -> None:
        self.allowed = allowed
        self.calls: list[tuple[str, str, int, int]] = []

    def consume(
        self,
        *,
        org_id: str,
        destination_alias: str,
        now_utc_ns: int,
        max_per_minute: int,
    ) -> bool:
        self.calls.append((org_id, destination_alias, now_utc_ns, max_per_minute))
        return self.allowed


class _AuditPort:
    def __init__(self, *, failure: Exception | None = None) -> None:
        self.failure = failure
        self.records = []
        self.deadlines: list[int] = []

    def append(self, record: object, *, deadline_monotonic_ns: int) -> None:
        self.deadlines.append(deadline_monotonic_ns)
        if self.failure is not None:
            raise self.failure
        self.records.append(record)


def _outbound(
    *,
    policy: AuthorizationPolicyV1 | None = None,
    missing_policy: bool = False,
    consent: NotificationConsentV1 | None = None,
    missing_consent: bool = False,
    scope_org: str = _ORG,
    scope_project: str = _PROJECT,
    scope_env: str = "paper",
    routes: tuple[NotificationRouteV1, ...] | None = None,
    max_per_minute: int = 8,
    quota_allowed: bool = True,
    audit_failure: Exception | None = None,
    missing_audit: bool = False,
    transport: FakeNotificationTransport | None = None,
) -> tuple[
    NotificationOutbound,
    _ConsentPort | None,
    _IdempotencyPort,
    _QuotaPort,
    _AuditPort | None,
    FakeNotificationTransport,
]:
    if routes is None:
        routes = (
            NotificationRouteV1(
                _DESTINATION,
                NotificationChannelV1.TELEGRAM,
                tuple(NotificationEventTypeV1),
            ),
        )
    scopes = (NotificationScopeV1(scope_org, scope_project, scope_env, routes, max_per_minute),)
    consent_port = None if missing_consent else _ConsentPort(consent or _consent())
    idempotency = _IdempotencyPort()
    quota = _QuotaPort(quota_allowed)
    audit = None if missing_audit else _AuditPort(failure=audit_failure)
    fake_transport = transport or FakeNotificationTransport((FakeTransportStatusV1.DELIVERED,))
    outbound = NotificationOutbound(
        policy=None if missing_policy else (policy or _policy()),
        scopes=scopes,
        consent=consent_port,
        idempotency=idempotency,
        quota=quota,
        audit=audit,
        transport=fake_transport,
        clock=lambda: _NOW,
    )
    return outbound, consent_port, idempotency, quota, audit, fake_transport


def _assert_denied(result: object) -> None:
    assert result.state is NotificationDeliveryStateV1.DENIED
    assert result.reason_code is NotificationReasonCodeV1.NOT_AUTHORIZED
    assert require_notification_delivery(result) is result


@pytest.mark.parametrize("event_type", tuple(NotificationEventTypeV1))
def test_each_contract_event_type_uses_safe_fixed_copy_and_audits(
    event_type: NotificationEventTypeV1,
) -> None:
    outbound, _, _, _, audit, transport = _outbound()

    delivery = outbound.send(_principal(), _event(event_type, event_id="event-123-45-6789"))

    assert delivery.state is NotificationDeliveryStateV1.DELIVERED
    assert len(transport.attempts) == 1
    assert transport.attempts[0].payload in {
        "A signal notification is available.",
        "A fill notification is available.",
        "A risk notification is available.",
    }
    assert "event-123-45-6789" not in transport.attempts[0].payload
    assert audit is not None and len(audit.records) == 1
    assert require_notification_audit_record(audit.records[0]) is audit.records[0]
    assert audit.records[0].decision == "ALLOW"
    assert len(audit.records[0].request_sha256) == 64
    assert len(audit.records[0].principal_sha256) == 64
    assert len(audit.records[0].decision_sha256) == 64
    assert "event-123-45-6789" not in repr(audit.records[0])
    assert "123-45-6789" not in repr(audit.records[0])


@pytest.mark.parametrize(
    "consent",
    (
        _consent(granted=False),
        _consent(revoked_at_ns=_NOW_NS),
        _consent(recorded_at_ns=_NOW_NS + 1),
        _consent(org_id="org-other"),
        _consent(channel=NotificationChannelV1.SIGNAL),
        _consent(event_types=(NotificationEventTypeV1.FILL,)),
    ),
)
def test_unrecorded_or_mismatched_consent_never_reaches_transport(
    consent: NotificationConsentV1,
) -> None:
    outbound, _, _, _, audit, transport = _outbound(consent=consent)

    result = outbound.send(_principal(), _event())

    _assert_denied(result)
    assert transport.attempts == ()
    assert audit is not None and audit.records[-1].decision == "DENY"


def test_missing_consent_evidence_is_default_denied() -> None:
    outbound, _, _, _, _, transport = _outbound(missing_consent=True)

    _assert_denied(outbound.send(_principal(), _event()))

    assert transport.attempts == ()


@pytest.mark.parametrize(
    ("principal", "event"),
    (
        (_principal(project="project-other"), _event()),
        (_principal(env="live"), _event()),
        (_principal(), _event(org_id="org-other")),
        (_principal(), _event(destination_alias="unknown-destination")),
        (_principal(), _event(NotificationEventTypeV1.RISK)),
    ),
)
def test_identity_org_route_and_event_scope_mismatches_deny(
    principal: TrustedPrincipalV1, event: NotificationEventV1
) -> None:
    route = NotificationRouteV1(
        _DESTINATION,
        NotificationChannelV1.TELEGRAM,
        (NotificationEventTypeV1.SIGNAL,),
    )
    outbound, _, _, _, _, transport = _outbound(routes=(route,))

    _assert_denied(outbound.send(principal, event))

    assert transport.attempts == ()


@pytest.mark.parametrize(
    "outbound_options", ({"missing_policy": True}, {"policy": _policy(action="notification:read")})
)
def test_missing_or_non_send_authorization_policy_denies(
    outbound_options: dict[str, object],
) -> None:
    outbound, _, _, _, _, transport = _outbound(**outbound_options)

    _assert_denied(outbound.send(_principal(), _event()))

    assert transport.attempts == ()


def test_duplicate_event_id_is_one_shot_and_does_not_retry() -> None:
    outbound, _, idempotency, _, _, transport = _outbound()
    event = _event()

    first = outbound.send(_principal(), event)
    duplicate = outbound.send(_principal(), event)

    assert first.state is NotificationDeliveryStateV1.DELIVERED
    _assert_denied(duplicate)
    assert len(transport.attempts) == 1
    assert len(idempotency.completed) == 1
    key = next(iter(idempotency.completed))
    assert len(key) == 64 and event.event_id not in key


def test_quota_denial_releases_idempotency_claim_and_sends_nothing() -> None:
    outbound, _, idempotency, quota, _, transport = _outbound(quota_allowed=False, max_per_minute=1)

    _assert_denied(outbound.send(_principal(), _event()))

    assert quota.calls == [(_ORG, _DESTINATION, _NOW_NS, 1)]
    assert len(idempotency.released) == 1
    assert transport.attempts == ()


def test_audit_failure_prevents_any_transport_release() -> None:
    outbound, _, idempotency, _, audit, transport = _outbound(
        audit_failure=RuntimeError("synthetic private audit failure")
    )

    _assert_denied(outbound.send(_principal(), _event()))

    assert audit is not None and audit.records == []
    assert len(idempotency.released) == 1
    assert transport.attempts == ()


def test_transport_timeout_is_unknown_and_duplicate_call_is_not_retried() -> None:
    fake = FakeNotificationTransport(error=TimeoutError("synthetic timeout detail"))
    outbound, _, idempotency, _, audit, _ = _outbound(transport=fake)

    result = outbound.send(_principal(), _event())
    repeated = outbound.send(_principal(), _event())

    assert result.state is NotificationDeliveryStateV1.UNKNOWN
    assert result.reason_code is NotificationReasonCodeV1.TRANSPORT_UNKNOWN
    _assert_denied(repeated)
    assert len(fake.attempts) == 1
    assert len(idempotency.completed) == 1
    assert audit is not None and audit.records[0].decision == "ALLOW"


def test_transport_failure_stays_delivery_local_and_fake_has_no_inbound_command() -> None:
    fake = FakeNotificationTransport((FakeTransportStatusV1.FAILED,))
    outbound, _, idempotency, _, _, _ = _outbound(transport=fake)

    result = outbound.send(_principal(), _event())

    assert result.state is NotificationDeliveryStateV1.FAILED
    assert result.reason_code is NotificationReasonCodeV1.TRANSPORT_FAILED
    assert next(iter(idempotency.completed.values())) is NotificationDeliveryStateV1.FAILED
    assert len(fake.attempts) == 1
    assert not hasattr(fake, "receive")
    assert not hasattr(fake, "poll_commands")


def test_event_metadata_cannot_carry_free_text_or_secret_destination() -> None:
    with pytest.raises(TypeError):
        NotificationEventV1(
            event_id="event.extra-field",
            org_id=_ORG,
            event_type=NotificationEventTypeV1.SIGNAL,
            occurred_at_ns=_NOW_NS,
            correlation_id="correlation.acceptance.2",
            template_id=NotificationTemplateV1.SIGNAL_NOTICE,
            destination_alias=_DESTINATION,
            body="private payload",  # type: ignore[call-arg]
        )
    with pytest.raises(ValueError):
        _event(destination_alias="telegram-bot-token")


def test_delivery_failure_does_not_mutate_source_event() -> None:
    event = _event()
    fake = FakeNotificationTransport((FakeTransportStatusV1.FAILED,))
    outbound, _, _, _, _, _ = _outbound(transport=fake)

    result = outbound.send(_principal(), event)

    assert result.state is NotificationDeliveryStateV1.FAILED
    assert event.delivery_state is NotificationDeliveryStateV1.PENDING


def test_invalid_event_metadata_rejects_bool_timestamps_without_echoing_input() -> None:
    with pytest.raises(NotificationModelError) as timestamp_error:
        replace(_event(), occurred_at_ns=True)
    assert timestamp_error.value.code == "INVALID_NOTIFICATION"
    assert "True" not in str(timestamp_error.value)

    secret_like_alias = "telegram-bot-secret-fragment"
    with pytest.raises(NotificationModelError) as alias_error:
        _event(destination_alias=secret_like_alias)
    assert alias_error.value.code == "INVALID_NOTIFICATION"
    assert secret_like_alias not in str(alias_error.value)


def test_inputs_cannot_be_copied_or_serialized_to_recreate_capabilities() -> None:
    event = _event()
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(TypeError):
            operation(event)

    outbound, _, _, _, audit, _ = _outbound()
    result = outbound.send(_principal(), event)
    assert require_notification_delivery(result) is result
    assert audit is not None
    with pytest.raises(SealError):
        require_notification_delivery(result.model_copy(update={"state": "DENIED"}))
    with pytest.raises(SealError):
        require_notification_audit_record(audit.records[0].model_copy(update={"decision": "DENY"}))


class _HeldAmbiguousClaimPort(_IdempotencyPort):
    """Model an owner-held key whose second claim result is transport-ambiguous."""

    def __init__(self) -> None:
        super().__init__()
        import threading

        self._lock = threading.Lock()
        self.claim_calls = 0

    def claim(self, key: str) -> bool:
        with self._lock:
            self.claim_calls += 1
            if self.claim_calls == 1:
                self.claimed.add(key)
                return True
            if self.claim_calls == 2:
                raise TimeoutError("synthetic claim acknowledgment ambiguity")
            if key in self.claimed:
                return False
            self.claimed.add(key)
            return True

    def release(self, key: str) -> None:
        with self._lock:
            super().release(key)


class _NonBooleanClaimPort(_IdempotencyPort):
    def claim(self, key: str) -> bool:
        self.claimed.add(key)
        return 1  # type: ignore[return-value]


def _outbound_with_ports(
    *, idempotency: object, audit: object, transport: FakeNotificationTransport
) -> NotificationOutbound:
    route = NotificationRouteV1(
        _DESTINATION,
        NotificationChannelV1.TELEGRAM,
        tuple(NotificationEventTypeV1),
    )
    return NotificationOutbound(
        policy=_policy(),
        scopes=(NotificationScopeV1(_ORG, _PROJECT, "paper", (route,), 8),),
        consent=_ConsentPort(_consent()),
        idempotency=idempotency,
        quota=_QuotaPort(),
        audit=audit,
        transport=transport,
        clock=lambda: _NOW,
        audit_timeout_ns=2_000_000_000,
    )


class _PauseAllowAuditPort(_AuditPort):
    def __init__(self, allow_entered: object, resume_allow: object) -> None:
        super().__init__()
        self._allow_entered = allow_entered
        self._resume_allow = resume_allow

    def append(self, record: object, *, deadline_monotonic_ns: int) -> None:
        self.deadlines.append(deadline_monotonic_ns)
        if record.decision == "ALLOW":
            self._allow_entered.set()
            if not self._resume_allow.wait(timeout=3):
                raise TimeoutError("synthetic audit pause expired")
        self.records.append(record)


def test_ambiguous_claim_cannot_release_another_callers_held_key() -> None:
    import threading
    from concurrent.futures import ThreadPoolExecutor

    allow_entered = threading.Event()
    resume_allow = threading.Event()
    claims = _HeldAmbiguousClaimPort()
    transport = FakeNotificationTransport((FakeTransportStatusV1.DELIVERED,))
    audit = _PauseAllowAuditPort(allow_entered, resume_allow)
    outbound = _outbound_with_ports(idempotency=claims, audit=audit, transport=transport)
    principal = _principal()
    event = _event()

    with ThreadPoolExecutor(max_workers=1) as pool:
        first_attempt = pool.submit(outbound.send, principal, event)
        try:
            assert allow_entered.wait(timeout=1)
            ambiguous = outbound.send(principal, event)
            retry = outbound.send(principal, event)
            assert ambiguous.state is NotificationDeliveryStateV1.DENIED
            assert ambiguous.reason_code.value == "CLAIM_AMBIGUOUS"
            assert require_notification_delivery(ambiguous) is ambiguous
            _assert_denied(retry)
            assert claims.released == []
        finally:
            resume_allow.set()
        first_result = first_attempt.result(timeout=3)

    assert first_result.state is NotificationDeliveryStateV1.DELIVERED
    assert claims.claim_calls == 3
    assert claims.released == []
    assert len(transport.attempts) == 1


def test_non_boolean_claim_fails_closed_without_releasing_or_sending() -> None:
    claims = _NonBooleanClaimPort()
    transport = FakeNotificationTransport((FakeTransportStatusV1.DELIVERED,))
    audit = _AuditPort()
    outbound = _outbound_with_ports(idempotency=claims, audit=audit, transport=transport)

    result = outbound.send(_principal(), _event())

    assert result.state is NotificationDeliveryStateV1.DENIED
    assert result.reason_code.value == "CLAIM_AMBIGUOUS"
    assert require_notification_delivery(result) is result
    assert claims.released == []
    assert transport.attempts == ()
