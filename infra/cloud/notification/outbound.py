"""Fail-closed outbound notification orchestration over injected fakeable ports."""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Callable
from contextlib import suppress
from datetime import UTC, datetime
from typing import Protocol

from leviathan_core.seal import Issuer, require
from leviathan_core.security import (
    ActionV1,
    AuthorizationContextV1,
    AuthorizationPolicyV1,
    ResourceV1,
    TrustedPrincipalV1,
    authorize,
)

from .models import (
    _AUDIT_TAG,
    _DELIVERY_TAG,
    FakeTransportStatusV1,
    NotificationAuditRecordV1,
    NotificationChannelV1,
    NotificationConsentV1,
    NotificationDeliveryStateV1,
    NotificationDeliveryV1,
    NotificationEventV1,
    NotificationReasonCodeV1,
    NotificationScopeV1,
    NotificationTemplateV1,
    require_notification_audit_record,
)
from .transport import NotificationTransportPort

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_MAX_AUDIT_TIMEOUT_NS = 2_500_000_000
_MAX_TRANSPORT_TIMEOUT_NS = 5_000_000_000
_AUDIT_ISSUER = Issuer(_AUDIT_TAG)
_DELIVERY_ISSUER = Issuer(_DELIVERY_TAG)


class NotificationError(ValueError):
    """Content-free notification configuration or delivery error."""

    def __init__(self, code: str = "INVALID_CONFIGURATION") -> None:
        self.code = (
            code
            if code in {"INVALID_CONFIGURATION", "AUDIT_APPEND_DENIED"}
            else "INVALID_CONFIGURATION"
        )
        super().__init__(self.code)


class NotificationConsentPort(Protocol):
    """Returns the current recorded consent for an org-scoped destination alias."""

    def get_consent(
        self, *, org_id: str, destination_alias: str
    ) -> NotificationConsentV1 | None: ...


class NotificationIdempotencyPort(Protocol):
    """Atomic, durable-integration boundary for one-shot notification attempts."""

    def claim(self, idempotency_key: str) -> bool: ...

    def release(self, idempotency_key: str) -> None: ...

    def complete(self, idempotency_key: str, state: NotificationDeliveryStateV1) -> None: ...


class NotificationQuotaPort(Protocol):
    """Atomically consumes one org/destination rate slot or fails closed."""

    def consume(
        self,
        *,
        org_id: str,
        destination_alias: str,
        now_utc_ns: int,
        max_per_minute: int,
    ) -> bool: ...


class NotificationAuditPort(Protocol):
    """The adapter must honor the monotonic append deadline and raise on failure."""

    def append(self, record: NotificationAuditRecordV1, *, deadline_monotonic_ns: int) -> None: ...


def _utc_ns(value: object) -> int | None:
    if type(value) is not datetime or value.tzinfo is not UTC:
        return None
    delta = value - _EPOCH
    result = (
        delta.days * 86_400_000_000_000 + delta.seconds * 1_000_000_000 + delta.microseconds * 1_000
    )
    return result if result >= 1 else None


def _sha256(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("ascii")).hexdigest()


def _event_digest(event: NotificationEventV1) -> str:
    return _sha256(
        (
            event.event_id,
            event.org_id,
            event.event_type.value,
            event.occurred_at_ns,
            event.correlation_id,
            event.template_id.value,
            event.destination_alias,
            event.delivery_state.value,
        )
    )


def _decision_digest(allowed: bool) -> str:
    return _sha256(
        (
            "ALLOW" if allowed else "DENY",
            "AUTHORIZED" if allowed else "NOT_AUTHORIZED",
        )
    )


def _principal_digest(principal: TrustedPrincipalV1) -> str:
    return _sha256(
        (
            principal.principal_id,
            principal.project_id,
            tuple(sorted(principal.roles)),
            principal.env,
            principal.venue,
            principal.portfolio,
            principal.strategy,
        )
    )


def _idempotency_key(event: NotificationEventV1) -> str:
    return _sha256((event.org_id, event.event_id))


def _issue_audit_record(
    *,
    org_id: str,
    request_digest: str,
    principal_digest: str,
    allowed: bool,
    recorded_at_ns: int,
) -> NotificationAuditRecordV1:
    record = NotificationAuditRecordV1(
        org_id=org_id,
        request_sha256=request_digest,
        principal_sha256=principal_digest,
        decision_sha256=_decision_digest(allowed),
        decision="ALLOW" if allowed else "DENY",
        reason_code=(
            NotificationReasonCodeV1.AUTHORIZED
            if allowed
            else NotificationReasonCodeV1.NOT_AUTHORIZED
        ),
        recorded_at_ns=recorded_at_ns,
    )
    return _AUDIT_ISSUER.issue(record)


def require_notification_delivery(value: NotificationDeliveryV1) -> NotificationDeliveryV1:
    return require(value, _DELIVERY_TAG)


def _issue_delivery(
    state: NotificationDeliveryStateV1,
    reason: NotificationReasonCodeV1,
) -> NotificationDeliveryV1:
    return _DELIVERY_ISSUER.issue(NotificationDeliveryV1(state=state, reason_code=reason))


def _payload(template: NotificationTemplateV1) -> str:
    """Render fixed safe copy only; event IDs and user data never enter message text."""

    return {
        NotificationTemplateV1.SIGNAL_NOTICE: "A signal notification is available.",
        NotificationTemplateV1.FILL_NOTICE: "A fill notification is available.",
        NotificationTemplateV1.RISK_NOTICE: "A risk notification is available.",
    }[template]


class NotificationOutbound:
    """Consent-, scope-, policy-, quota- and audit-gated notification sender."""

    def __init__(
        self,
        *,
        policy: AuthorizationPolicyV1 | None,
        scopes: tuple[NotificationScopeV1, ...],
        consent: NotificationConsentPort | None,
        idempotency: NotificationIdempotencyPort | None,
        quota: NotificationQuotaPort | None,
        audit: NotificationAuditPort | None,
        transport: NotificationTransportPort | None,
        clock: Callable[[], datetime],
        audit_timeout_ns: int = 250_000_000,
        transport_timeout_ns: int = 2_000_000_000,
    ) -> None:
        if (
            type(scopes) is not tuple
            or any(type(scope) is not NotificationScopeV1 for scope in scopes)
            or len({scope.org_id for scope in scopes}) != len(scopes)
            or (policy is not None and type(policy) is not AuthorizationPolicyV1)
            or not callable(clock)
            or type(audit_timeout_ns) is not int
            or not 1 <= audit_timeout_ns <= _MAX_AUDIT_TIMEOUT_NS
            or type(transport_timeout_ns) is not int
            or not 1 <= transport_timeout_ns <= _MAX_TRANSPORT_TIMEOUT_NS
        ):
            raise NotificationError()
        self._policy = policy
        self._scopes = {scope.org_id: scope for scope in scopes}
        self._consent = consent
        self._idempotency = idempotency
        self._quota = quota
        self._audit = audit
        self._transport = transport
        self._clock = clock
        self._audit_timeout_ns = audit_timeout_ns
        self._transport_timeout_ns = transport_timeout_ns

    def _append_audit(self, record: NotificationAuditRecordV1) -> bool:
        if self._audit is None:
            return False
        try:
            require_notification_audit_record(record)
            started = time.monotonic_ns()
            deadline = started + self._audit_timeout_ns
            self._audit.append(record, deadline_monotonic_ns=deadline)
            return time.monotonic_ns() <= deadline
        except Exception:
            return False

    def _best_effort_deny_audit(
        self,
        principal: object,
        event: object,
        now_utc_ns: int | None,
    ) -> None:
        if (
            now_utc_ns is None
            or type(principal) is not TrustedPrincipalV1
            or type(event) is not NotificationEventV1
        ):
            return
        try:
            record = _issue_audit_record(
                org_id=event.org_id,
                request_digest=_event_digest(event),
                principal_digest=_principal_digest(principal),
                allowed=False,
                recorded_at_ns=now_utc_ns,
            )
            self._append_audit(record)
        except Exception:
            return

    def _deny(
        self,
        principal: object,
        event: object,
        now_utc_ns: int | None,
        *,
        reason_code: NotificationReasonCodeV1 = NotificationReasonCodeV1.NOT_AUTHORIZED,
    ) -> NotificationDeliveryV1:
        self._best_effort_deny_audit(principal, event, now_utc_ns)
        return _issue_delivery(
            NotificationDeliveryStateV1.DENIED,
            reason_code,
        )

    def _consent_allows(
        self,
        *,
        event: NotificationEventV1,
        route_channel: NotificationChannelV1,
        now_utc_ns: int,
    ) -> bool:
        if self._consent is None:
            return False
        try:
            consent = self._consent.get_consent(
                org_id=event.org_id,
                destination_alias=event.destination_alias,
            )
        except Exception:
            return False
        if type(consent) is not NotificationConsentV1:
            return False
        return (
            consent.org_id == event.org_id
            and consent.destination_alias == event.destination_alias
            and consent.channel is route_channel
            and consent.granted is True
            and consent.recorded_at_ns <= now_utc_ns
            and (consent.revoked_at_ns is None or consent.revoked_at_ns > now_utc_ns)
            and event.event_type in consent.allowed_event_types
        )

    def send(
        self,
        principal: TrustedPrincipalV1,
        event: NotificationEventV1,
    ) -> NotificationDeliveryV1:
        """Send one event or return the same denial for all authorization failures."""

        now: datetime | None
        try:
            now = self._clock()
        except Exception:
            now = None
        now_utc_ns = _utc_ns(now)
        claimed_key: str | None = None
        if (
            type(principal) is not TrustedPrincipalV1
            or type(event) is not NotificationEventV1
            or now_utc_ns is None
            or type(now) is not datetime
            or self._policy is None
            or self._consent is None
            or self._idempotency is None
            or self._quota is None
            or self._audit is None
            or self._transport is None
        ):
            return self._deny(principal, event, now_utc_ns)
        try:
            event.__post_init__()
        except Exception:
            return self._deny(principal, event, now_utc_ns)

        scope = self._scopes.get(event.org_id)
        route = (
            next(
                (
                    item
                    for item in scope.routes
                    if item.destination_alias == event.destination_alias
                ),
                None,
            )
            if scope is not None
            else None
        )
        if (
            scope is None
            or route is None
            or principal.project_id != scope.project_id
            or principal.env != scope.env
            or event.event_type not in route.allowed_event_types
        ):
            return self._deny(principal, event, now_utc_ns)

        try:
            authorization = authorize(
                principal,
                ActionV1("notification:send"),
                ResourceV1(
                    f"notification:{event.org_id}",
                    scope.project_id,
                    scope.env,
                    principal.venue,
                    principal.portfolio,
                    principal.strategy,
                ),
                AuthorizationContextV1(
                    scope.project_id,
                    scope.env,
                    now,
                    principal.venue,
                    principal.portfolio,
                    principal.strategy,
                ),
                self._policy,
            )
        except Exception:
            return self._deny(principal, event, now_utc_ns)
        if authorization.allowed is not True:
            return self._deny(principal, event, now_utc_ns)
        if not self._consent_allows(
            event=event,
            route_channel=route.channel,
            now_utc_ns=now_utc_ns,
        ):
            return self._deny(principal, event, now_utc_ns)

        event_hash = _event_digest(event)
        principal_hash = _principal_digest(principal)
        claimed_key = _idempotency_key(event)
        try:
            claimed = self._idempotency.claim(claimed_key)
        except Exception:
            return self._deny(
                principal,
                event,
                now_utc_ns,
                reason_code=NotificationReasonCodeV1.CLAIM_AMBIGUOUS,
            )
        if type(claimed) is not bool:
            return self._deny(
                principal,
                event,
                now_utc_ns,
                reason_code=NotificationReasonCodeV1.CLAIM_AMBIGUOUS,
            )
        if not claimed:
            return self._deny(principal, event, now_utc_ns)

        try:
            quota_allowed = self._quota.consume(
                org_id=event.org_id,
                destination_alias=event.destination_alias,
                now_utc_ns=now_utc_ns,
                max_per_minute=scope.max_per_minute,
            )
        except Exception:
            quota_allowed = False
        if type(quota_allowed) is not bool or not quota_allowed:
            with suppress(Exception):
                self._idempotency.release(claimed_key)
            return self._deny(principal, event, now_utc_ns)

        try:
            audit_record = _issue_audit_record(
                org_id=event.org_id,
                request_digest=event_hash,
                principal_digest=principal_hash,
                allowed=True,
                recorded_at_ns=now_utc_ns,
            )
        except Exception:
            audit_record = None
        if audit_record is None or not self._append_audit(audit_record):
            with suppress(Exception):
                self._idempotency.release(claimed_key)
            return _issue_delivery(
                NotificationDeliveryStateV1.DENIED,
                NotificationReasonCodeV1.NOT_AUTHORIZED,
            )

        deadline = time.monotonic_ns() + self._transport_timeout_ns
        try:
            status = self._transport.send(
                channel=route.channel,
                destination_alias=event.destination_alias,
                payload=_payload(event.template_id),
                idempotency_key=claimed_key,
                deadline_monotonic_ns=deadline,
            )
            if time.monotonic_ns() > deadline or type(status) is not FakeTransportStatusV1:
                status = FakeTransportStatusV1.UNKNOWN
        except TimeoutError:
            status = FakeTransportStatusV1.UNKNOWN
        except Exception:
            status = FakeTransportStatusV1.FAILED

        state = {
            FakeTransportStatusV1.DELIVERED: NotificationDeliveryStateV1.DELIVERED,
            FakeTransportStatusV1.FAILED: NotificationDeliveryStateV1.FAILED,
            FakeTransportStatusV1.UNKNOWN: NotificationDeliveryStateV1.UNKNOWN,
        }[status]
        reason = {
            FakeTransportStatusV1.DELIVERED: NotificationReasonCodeV1.AUTHORIZED,
            FakeTransportStatusV1.FAILED: NotificationReasonCodeV1.TRANSPORT_FAILED,
            FakeTransportStatusV1.UNKNOWN: NotificationReasonCodeV1.TRANSPORT_UNKNOWN,
        }[status]
        try:
            self._idempotency.complete(claimed_key, state)
        except Exception:
            state = NotificationDeliveryStateV1.UNKNOWN
            reason = NotificationReasonCodeV1.TRANSPORT_UNKNOWN
        # Once a transport call starts, the claim stays consumed even if its result is unknown.
        return _issue_delivery(state, reason)


__all__ = [
    "NotificationAuditPort",
    "NotificationConsentPort",
    "NotificationError",
    "NotificationIdempotencyPort",
    "NotificationOutbound",
    "NotificationQuotaPort",
    "NotificationTransportPort",
    "require_notification_delivery",
]
