"""UTC-nanosecond retention planning with an injected append-only audit port.

The planner only emits eligibility decisions. It does not delete data or
connect to R2, Neon, or another retention service.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Final, Protocol

from leviathan_core.observability.context import GeneratedIdV1

_DAY_NS: Final = 86_400 * 1_000_000_000
_MAX_UTC_NS: Final = (1 << 63) - 1
_MAX_AUDIT_SEQUENCE: Final = (1 << 63) - 1
_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)


class RetentionError(ValueError):
    """Content-free retention failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class RetentionClassV1(StrEnum):
    METRIC_5S = "metric_5s"
    METRIC_30S = "metric_30s"
    METRIC_5M = "metric_5m"
    LOG_HOT = "log_hot"
    LOG_ARCHIVE = "log_archive"
    TRACE_HOT = "trace_hot"
    TRACE_SUMMARY = "trace_summary"


class RetentionActionV1(StrEnum):
    RETAIN = "retain"
    ARCHIVE_ELIGIBLE = "archive_eligible"
    DELETE_ELIGIBLE = "delete_eligible"
    HELD = "held"
    BLOCKED = "blocked"


class RetentionReasonV1(StrEnum):
    NOT_EXPIRED = "not_expired"
    RETENTION_EXPIRED = "retention_expired"
    LEGAL_HOLD = "legal_hold"
    HOLD_UNKNOWN = "hold_unknown"
    POLICY_UNKNOWN = "policy_unknown"
    AUDIT_UNAVAILABLE = "audit_unavailable"


_RETENTION_NS: Final[dict[RetentionClassV1, int]] = {
    RetentionClassV1.METRIC_5S: 7 * _DAY_NS,
    RetentionClassV1.METRIC_30S: 30 * _DAY_NS,
    RetentionClassV1.METRIC_5M: 90 * _DAY_NS,
    RetentionClassV1.LOG_HOT: 14 * _DAY_NS,
    RetentionClassV1.LOG_ARCHIVE: 90 * _DAY_NS,
    RetentionClassV1.TRACE_HOT: 7 * _DAY_NS,
    RetentionClassV1.TRACE_SUMMARY: 30 * _DAY_NS,
}


@dataclass(frozen=True, slots=True)
class RetentionRecordV1:
    record_id: GeneratedIdV1
    retention_class: RetentionClassV1
    created_utc_ns: int

    def __post_init__(self) -> None:
        if (
            type(self.record_id) is not GeneratedIdV1
            or type(self.retention_class) is not RetentionClassV1
            or type(self.created_utc_ns) is not int
            or not 0 <= self.created_utc_ns <= _MAX_UTC_NS
        ):
            raise RetentionError("RETENTION_RECORD_INVALID")


@dataclass(frozen=True, slots=True)
class RetentionAuditRecordV1:
    sequence: int
    record_key_sha256: str
    retention_class: RetentionClassV1
    action: RetentionActionV1
    reason: RetentionReasonV1
    recorded_utc_ns: int
    previous_hash: str
    record_hash: str


class RetentionAuditPort(Protocol):
    def append(
        self,
        *,
        record_key_sha256: str,
        retention_class: RetentionClassV1,
        action: RetentionActionV1,
        reason: RetentionReasonV1,
        recorded_utc_ns: int,
    ) -> RetentionAuditRecordV1: ...


class LegalHoldPort(Protocol):
    """Trusted hold lookup; ``None`` means the hold state is unresolved."""

    def is_held(self, record_id: GeneratedIdV1) -> bool | None: ...


@dataclass(frozen=True, slots=True)
class RetentionDecisionV1:
    record_key_sha256: str
    retention_class: RetentionClassV1
    action: RetentionActionV1
    reason: RetentionReasonV1
    expires_utc_ns: int | None
    audit_sequence: int | None
    audit_hash: str | None


class RetentionPlannerV1:
    """Resolve exact expiries and legal holds before reporting delete eligibility."""

    def __init__(self, audit: RetentionAuditPort, legal_holds: LegalHoldPort) -> None:
        if not callable(getattr(audit, "append", None)) or not callable(
            getattr(legal_holds, "is_held", None)
        ):
            raise RetentionError("RETENTION_CONFIG_INVALID")
        self._audit = audit
        self._legal_holds = legal_holds
        self._last_audit_sequence: int | None = None
        self._last_audit_hash: str | None = None

    def _audit_ack_matches(
        self,
        acknowledgment: object,
        *,
        record_key: str,
        retention_class: RetentionClassV1,
        action: RetentionActionV1,
        reason: RetentionReasonV1,
        recorded_utc_ns: int,
    ) -> bool:
        if type(acknowledgment) is not RetentionAuditRecordV1:
            return False
        if (
            type(acknowledgment.sequence) is not int
            or not 1 <= acknowledgment.sequence <= _MAX_AUDIT_SEQUENCE
            or type(acknowledgment.record_key_sha256) is not str
            or acknowledgment.record_key_sha256 != record_key
            or type(acknowledgment.retention_class) is not RetentionClassV1
            or acknowledgment.retention_class is not retention_class
            or type(acknowledgment.action) is not RetentionActionV1
            or acknowledgment.action is not action
            or type(acknowledgment.reason) is not RetentionReasonV1
            or acknowledgment.reason is not reason
            or type(acknowledgment.recorded_utc_ns) is not int
            or acknowledgment.recorded_utc_ns != recorded_utc_ns
            or type(acknowledgment.previous_hash) is not str
            or _SHA256.fullmatch(acknowledgment.previous_hash) is None
            or type(acknowledgment.record_hash) is not str
            or _SHA256.fullmatch(acknowledgment.record_hash) is None
        ):
            return False
        if self._last_audit_sequence is not None:
            if acknowledgment.sequence != self._last_audit_sequence + 1:
                return False
            if acknowledgment.previous_hash != self._last_audit_hash:
                return False
        payload = {
            "sequence": acknowledgment.sequence,
            "record_key_sha256": acknowledgment.record_key_sha256,
            "retention_class": acknowledgment.retention_class.value,
            "action": acknowledgment.action.value,
            "reason": acknowledgment.reason.value,
            "recorded_utc_ns": acknowledgment.recorded_utc_ns,
            "previous_hash": acknowledgment.previous_hash,
        }
        expected_hash = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii")
        ).hexdigest()
        return acknowledgment.record_hash == expected_hash

    def plan(
        self,
        record: RetentionRecordV1,
        now_utc_ns: int,
        *,
        policy_known: bool = True,
        archive_enabled: bool = False,
    ) -> RetentionDecisionV1:
        if (
            type(record) is not RetentionRecordV1
            or type(now_utc_ns) is not int
            or not 0 <= now_utc_ns <= _MAX_UTC_NS
            or type(policy_known) is not bool
            or type(archive_enabled) is not bool
        ):
            raise RetentionError("RETENTION_INPUT_INVALID")
        record_key = hashlib.sha256(record.record_id.value.encode("ascii")).hexdigest()
        expiry = record.created_utc_ns + _RETENTION_NS[record.retention_class]
        if expiry > _MAX_UTC_NS:
            raise RetentionError("RETENTION_EXPIRY_INVALID")
        try:
            legal_hold = self._legal_holds.is_held(record.record_id)
        except Exception:
            legal_hold = None
        if not policy_known:
            action, reason = RetentionActionV1.BLOCKED, RetentionReasonV1.POLICY_UNKNOWN
        elif legal_hold is None or type(legal_hold) is not bool:
            action, reason = RetentionActionV1.HELD, RetentionReasonV1.HOLD_UNKNOWN
        elif legal_hold:
            action, reason = RetentionActionV1.HELD, RetentionReasonV1.LEGAL_HOLD
        elif now_utc_ns < expiry:
            action, reason = RetentionActionV1.RETAIN, RetentionReasonV1.NOT_EXPIRED
        elif record.retention_class is RetentionClassV1.LOG_HOT and archive_enabled:
            action, reason = RetentionActionV1.ARCHIVE_ELIGIBLE, RetentionReasonV1.RETENTION_EXPIRED
            expiry = record.created_utc_ns + _RETENTION_NS[RetentionClassV1.LOG_ARCHIVE]
        else:
            action, reason = RetentionActionV1.DELETE_ELIGIBLE, RetentionReasonV1.RETENTION_EXPIRED
        try:
            audit_ack = self._audit.append(
                record_key_sha256=record_key,
                retention_class=record.retention_class,
                action=action,
                reason=reason,
                recorded_utc_ns=now_utc_ns,
            )
            if not self._audit_ack_matches(
                audit_ack,
                record_key=record_key,
                retention_class=record.retention_class,
                action=action,
                reason=reason,
                recorded_utc_ns=now_utc_ns,
            ):
                raise ValueError("invalid audit acknowledgment")
        except Exception:
            action, reason = RetentionActionV1.BLOCKED, RetentionReasonV1.AUDIT_UNAVAILABLE
            audit_sequence, audit_hash = None, None
        else:
            self._last_audit_sequence = audit_ack.sequence
            self._last_audit_hash = audit_ack.record_hash
            audit_sequence, audit_hash = audit_ack.sequence, audit_ack.record_hash
        return RetentionDecisionV1(
            record_key,
            record.retention_class,
            action,
            reason,
            expiry,
            audit_sequence,
            audit_hash,
        )


__all__ = [
    "LegalHoldPort",
    "RetentionActionV1",
    "RetentionAuditPort",
    "RetentionAuditRecordV1",
    "RetentionClassV1",
    "RetentionDecisionV1",
    "RetentionError",
    "RetentionPlannerV1",
    "RetentionReasonV1",
    "RetentionRecordV1",
]
