"""Versioned risk-audit records and the atomic persistence port."""

from __future__ import annotations

import re
from hashlib import sha256
from typing import Protocol

from pydantic import ConfigDict, Field

from leviathan_core.numeric import NumericError, canonical_json
from leviathan_core.seal import Issuer, SealedModel, SealError, require

_EVENT_ISSUER = Issuer("risk005.audit_event.v1")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
RISK_AUDIT_GENESIS_HASH = sha256(b"leviathan.risk005.audit.genesis.v1").hexdigest()


class RiskAuditEventV1(SealedModel):
    """Append-only event; actor identity and policy values are represented by hashes."""

    model_config = ConfigDict(
        frozen=True, extra="forbid", strict=True, revalidate_instances="always"
    )

    schema_version: int = Field(default=1, ge=1, le=1)
    sequence: int = Field(ge=1)
    event_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    correlation_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
    attempt_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
    actor_ref: str = Field(pattern=r"^[0-9a-f]{64}$")
    action: str = Field(pattern=r"^[A-Z][A-Z0-9_]{0,63}$")
    decision: str = Field(pattern=r"^(ALLOW|DENY|RECORDED)$")
    reason_code: str = Field(pattern=r"^[A-Z][A-Z0-9_]{0,63}$")
    environment: str = Field(min_length=1, max_length=128)
    account_id: str = Field(min_length=1, max_length=128)
    scope: str = Field(pattern=r"^(ACCOUNT|STRATEGY|VENUE|INSTRUMENT|ORDER)$")
    before_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    after_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    source_event_ids: tuple[str, ...] = ()
    recorded_at_ns: int = Field(ge=0)
    predecessor_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    event_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


class RiskAuditEventHashError(ValueError):
    """Content-free failure from the canonical risk-audit event hasher."""

    __slots__ = ("code",)

    def __init__(self) -> None:
        self.code = "INVALID_RISK_AUDIT_EVENT"
        super().__init__(self.code)

    def __str__(self) -> str:
        return self.code


def risk_audit_event_hash(event: RiskAuditEventV1, previous_hash: str) -> str:
    """Encode a typed event into the canonical digest; this does not verify authenticity.

    Callers that need trusted event provenance must separately use
    :func:`require_risk_audit_event`.
    """
    if (
        type(event) is not RiskAuditEventV1
        or type(event.schema_version) is not int
        or type(event.sequence) is not int
        or type(event.recorded_at_ns) is not int
        or type(previous_hash) is not str
        or _SHA256.fullmatch(previous_hash) is None
    ):
        raise RiskAuditEventHashError
    try:
        payload = {
            "schema_version": event.schema_version,
            "sequence": event.sequence,
            "correlation_id": event.correlation_id,
            "attempt_id": event.attempt_id,
            "actor_ref": event.actor_ref,
            "action": event.action,
            "decision": event.decision,
            "reason_code": event.reason_code,
            "environment": event.environment,
            "account_id": event.account_id,
            "scope": event.scope,
            "before_digest": event.before_digest,
            "after_digest": event.after_digest,
            "source_event_ids": event.source_event_ids,
            "recorded_at_ns": event.recorded_at_ns,
            "predecessor_hash": previous_hash,
        }
        encoded = canonical_json(payload)
    except (NumericError, TypeError, ValueError):
        raise RiskAuditEventHashError from None
    return sha256(bytes.fromhex(previous_hash) + b"\x00" + encoded).hexdigest()


def require_risk_audit_event(value: object) -> RiskAuditEventV1:
    """Require an exact, intact event issued by the trusted risk-audit port."""
    if type(value) is not RiskAuditEventV1:
        raise RiskAuditEventHashError
    try:
        return require(value, _EVENT_ISSUER.tag)
    except (SealError, TypeError, ValueError):
        raise RiskAuditEventHashError from None


def _issue_event(**fields: object) -> RiskAuditEventV1:
    """Private store-only issuance path; public constructors are not trusted evidence."""
    return _EVENT_ISSUER.issue(RiskAuditEventV1(**fields))  # type: ignore[arg-type]


class RiskAuditPort(Protocol):
    """Atomic write boundary; a soft-approval ALLOW is not a HARD risk decision.

    C-101 must independently hard-assess the same order and current policy at
    routing. These methods record only the scoped SOFT-rule satisfaction.
    """

    async def apply_policy_change(
        self,
        *,
        change: object,
        current_policy: object,
        proposed_policy: object,
        actor: object,
        authorization_policy: object,
    ) -> RiskAuditEventV1: ...

    async def consume_soft_approval(
        self,
        *,
        approval: object,
        order_digest: str,
        environment: str,
        account_id: str,
        strategy_id: str,
        venue_id: str,
        instrument_id: str,
        soft_rule_id: str,
        policy_version: int,
        consumer: object,
    ) -> RiskAuditEventV1: ...

    async def issue_soft_approval(
        self,
        *,
        request: object,
        requester: object,
        approval: object,
        approvers: tuple[object, ...],
    ) -> RiskAuditEventV1: ...

    async def trusted_now_ns(self) -> int: ...

    def required_approvers(self, soft_rule_id: str) -> int: ...


__all__ = [
    "RISK_AUDIT_GENESIS_HASH",
    "RiskAuditEventHashError",
    "RiskAuditEventV1",
    "RiskAuditPort",
    "require_risk_audit_event",
    "risk_audit_event_hash",
]
