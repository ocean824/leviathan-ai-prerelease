"""Closed synthetic notification records for the outbound-only boundary."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Literal

from pydantic import Field

from leviathan_core.seal import SealedModel, require

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z", re.ASCII)
_SECRET_SEGMENT = re.compile(
    r"(?:^|[-_.:])(?:token|secret|password|passwd|credential|api[-_]?key|"
    r"private[-_]?key|bot[-_]?key)(?:[-_.:]|$)",
    re.IGNORECASE | re.ASCII,
)
_DELIVERY_TAG = "notify001.delivery.v1"
_AUDIT_TAG = "notify001.audit_record.v1"


class NotificationModelError(ValueError):
    """Content-free rejection for malformed notification values."""

    def __init__(self, code: str = "INVALID_NOTIFICATION") -> None:
        self.code = (
            code
            if code in {"INVALID_NOTIFICATION", "INVALID_CONSENT", "INVALID_SCOPE"}
            else "INVALID_NOTIFICATION"
        )
        super().__init__(self.code)


class _NoSerialization:
    """Notification inputs cannot be copied or reconstituted by serialization."""

    def __copy__(self) -> Any:
        raise TypeError("notification value cannot be copied")

    def __deepcopy__(self, memo: object) -> Any:
        raise TypeError("notification value cannot be copied")

    def __reduce__(self) -> Any:
        raise TypeError("notification value cannot be serialized")

    def __reduce_ex__(self, protocol: object) -> Any:
        raise TypeError("notification value cannot be serialized")


class NotificationChannelV1(StrEnum):
    TELEGRAM = "TELEGRAM"
    SIGNAL = "SIGNAL"


class NotificationEventTypeV1(StrEnum):
    SIGNAL = "SIGNAL"
    FILL = "FILL"
    RISK = "RISK"


class NotificationTemplateV1(StrEnum):
    SIGNAL_NOTICE = "signal.notice.v1"
    FILL_NOTICE = "fill.notice.v1"
    RISK_NOTICE = "risk.notice.v1"


class NotificationDeliveryStateV1(StrEnum):
    PENDING = "PENDING"
    DELIVERED = "DELIVERED"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"
    DENIED = "DENIED"


class NotificationReasonCodeV1(StrEnum):
    AUTHORIZED = "AUTHORIZED"
    NOT_AUTHORIZED = "NOT_AUTHORIZED"
    CLAIM_AMBIGUOUS = "CLAIM_AMBIGUOUS"
    TRANSPORT_FAILED = "TRANSPORT_FAILED"
    TRANSPORT_UNKNOWN = "TRANSPORT_UNKNOWN"


class FakeTransportStatusV1(StrEnum):
    DELIVERED = "DELIVERED"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"


def _safe_identifier(value: object) -> bool:
    return (
        type(value) is str
        and _IDENTIFIER.fullmatch(value) is not None
        and _SECRET_SEGMENT.search(value) is None
    )


@dataclass(frozen=True, slots=True)
class NotificationEventV1(_NoSerialization):
    """Metadata-only outbound event; no caller-supplied message or payload."""

    event_id: str
    org_id: str
    event_type: NotificationEventTypeV1
    occurred_at_ns: int
    correlation_id: str
    template_id: NotificationTemplateV1
    destination_alias: str
    delivery_state: NotificationDeliveryStateV1 = NotificationDeliveryStateV1.PENDING

    def __post_init__(self) -> None:
        expected_template = {
            NotificationEventTypeV1.SIGNAL: NotificationTemplateV1.SIGNAL_NOTICE,
            NotificationEventTypeV1.FILL: NotificationTemplateV1.FILL_NOTICE,
            NotificationEventTypeV1.RISK: NotificationTemplateV1.RISK_NOTICE,
        }
        if (
            not all(
                _safe_identifier(value)
                for value in (
                    self.event_id,
                    self.org_id,
                    self.correlation_id,
                    self.destination_alias,
                )
            )
            or type(self.event_type) is not NotificationEventTypeV1
            or type(self.template_id) is not NotificationTemplateV1
            or expected_template.get(self.event_type) is not self.template_id
            or type(self.occurred_at_ns) is not int
            or self.occurred_at_ns < 1
            or type(self.delivery_state) is not NotificationDeliveryStateV1
            or self.delivery_state is not NotificationDeliveryStateV1.PENDING
        ):
            raise NotificationModelError()


@dataclass(frozen=True, slots=True)
class NotificationRouteV1(_NoSerialization):
    """One explicitly scoped destination and the event categories it accepts."""

    destination_alias: str
    channel: NotificationChannelV1
    allowed_event_types: tuple[NotificationEventTypeV1, ...]

    def __post_init__(self) -> None:
        if (
            not _safe_identifier(self.destination_alias)
            or type(self.channel) is not NotificationChannelV1
            or type(self.allowed_event_types) is not tuple
            or not self.allowed_event_types
            or any(type(item) is not NotificationEventTypeV1 for item in self.allowed_event_types)
            or len(set(self.allowed_event_types)) != len(self.allowed_event_types)
        ):
            raise NotificationModelError("INVALID_SCOPE")


@dataclass(frozen=True, slots=True)
class NotificationScopeV1(_NoSerialization):
    """Trusted org/project/environment routing and rate-limit configuration."""

    org_id: str
    project_id: str
    env: str
    routes: tuple[NotificationRouteV1, ...]
    max_per_minute: int

    def __post_init__(self) -> None:
        if (
            not all(_safe_identifier(value) for value in (self.org_id, self.project_id, self.env))
            or type(self.routes) is not tuple
            or not self.routes
            or any(type(item) is not NotificationRouteV1 for item in self.routes)
            or len({item.destination_alias for item in self.routes}) != len(self.routes)
            or type(self.max_per_minute) is not int
            or not 1 <= self.max_per_minute <= 1000
        ):
            raise NotificationModelError("INVALID_SCOPE")


@dataclass(frozen=True, slots=True)
class NotificationConsentV1(_NoSerialization):
    """A recorded consent row returned by the injected consent port."""

    consent_id: str
    org_id: str
    destination_alias: str
    channel: NotificationChannelV1
    allowed_event_types: tuple[NotificationEventTypeV1, ...]
    granted: bool
    recorded_at_ns: int
    revoked_at_ns: int | None = None

    def __post_init__(self) -> None:
        if (
            not all(
                _safe_identifier(value)
                for value in (self.consent_id, self.org_id, self.destination_alias)
            )
            or type(self.channel) is not NotificationChannelV1
            or type(self.allowed_event_types) is not tuple
            or not self.allowed_event_types
            or any(type(item) is not NotificationEventTypeV1 for item in self.allowed_event_types)
            or len(set(self.allowed_event_types)) != len(self.allowed_event_types)
            or type(self.granted) is not bool
            or type(self.recorded_at_ns) is not int
            or self.recorded_at_ns < 1
            or (
                self.revoked_at_ns is not None
                and (
                    type(self.revoked_at_ns) is not int or self.revoked_at_ns < self.recorded_at_ns
                )
            )
        ):
            raise NotificationModelError("INVALID_CONSENT")


class NotificationDeliveryV1(SealedModel):
    """Issued content-free outcome; it carries no event or destination data."""

    schema_version: Literal[1] = 1
    state: NotificationDeliveryStateV1
    reason_code: NotificationReasonCodeV1


class NotificationAuditRecordV1(SealedModel):
    """Issued redacted audit intent, bound only to content digests and stable codes."""

    schema_version: Literal[1] = 1
    org_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
    request_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    principal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    decision_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    decision: Literal["ALLOW", "DENY"]
    reason_code: NotificationReasonCodeV1
    recorded_at_ns: int = Field(ge=1)


def require_notification_delivery(value: NotificationDeliveryV1) -> NotificationDeliveryV1:
    return require(value, _DELIVERY_TAG)


def require_notification_audit_record(
    value: NotificationAuditRecordV1,
) -> NotificationAuditRecordV1:
    return require(value, _AUDIT_TAG)


__all__ = [
    "FakeTransportStatusV1",
    "NotificationAuditRecordV1",
    "NotificationChannelV1",
    "NotificationConsentV1",
    "NotificationDeliveryStateV1",
    "NotificationDeliveryV1",
    "NotificationEventTypeV1",
    "NotificationEventV1",
    "NotificationReasonCodeV1",
    "NotificationRouteV1",
    "NotificationScopeV1",
    "NotificationTemplateV1",
    "require_notification_audit_record",
    "require_notification_delivery",
]
