"""Offline verification for complete risk-audit evidence segments.

``CHAIN_VERIFIED_TO_SUPPLIED_HEAD_CORRELATION_ONLY`` proves the supplied
segment is internally consistent from genesis through the caller-provided
head and contains an ORDER-scope terminal event whose ``correlation_id``
equals the requester-provided string. It does not prove that the string is an
issued C-101 decision ID or that the supplied head is the live store head.
"""

from __future__ import annotations

import re
from enum import StrEnum

from pydantic import ConfigDict, Field

from leviathan_core.risk_limits.audit_port import (
    RISK_AUDIT_GENESIS_HASH,
    RiskAuditEventHashError,
    RiskAuditEventV1,
    require_risk_audit_event,
    risk_audit_event_hash,
)
from leviathan_core.seal import Issuer, SealedModel, SealError, require

_RESULT_ISSUER = Issuer("risk.evidence.chain.verification.v1")
_DECISION_REF = re.compile(r"dec_[0-9a-f]{12}\Z", re.ASCII)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)


class RiskAuditTerminalActionV1(StrEnum):
    """Closed set of risk-audit event kinds that record an outcome."""

    SOFT_APPROVAL_CONSUMED = "SOFT_APPROVAL_CONSUMED"


class RiskAuditChainDiagnosticV1(StrEnum):
    """Content-free verification diagnostics; none is a success marker."""

    NOT_GENESIS = "NOT_GENESIS"
    GAP = "GAP"
    HASH_MISMATCH = "HASH_MISMATCH"
    HEAD_MISMATCH = "HEAD_MISMATCH"
    DECISION_ABSENT = "DECISION_ABSENT"
    DECISION_INCOMPLETE = "DECISION_INCOMPLETE"
    TYPE_INVALID = "TYPE_INVALID"


class RiskAuditChainProvenanceV1(StrEnum):
    CHAIN_VERIFIED_TO_SUPPLIED_HEAD_CORRELATION_ONLY = (
        "CHAIN_VERIFIED_TO_SUPPLIED_HEAD_CORRELATION_ONLY"
    )


class RiskAuditDecisionBindingV1(StrEnum):
    CORRELATION_ID_STRING_ONLY_NOT_C101_AUTHENTICATED = (
        "CORRELATION_ID_STRING_ONLY_NOT_C101_AUTHENTICATED"
    )


class RiskAuditDecisionV1(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    RECORDED = "RECORDED"


class RiskAuditChainVerificationV1(SealedModel):
    """Sealed result carrying a requester-supplied, unauthenticated correlation match."""

    model_config = ConfigDict(
        frozen=True, extra="forbid", strict=True, revalidate_instances="always"
    )

    decision_ref: str = Field(pattern=r"^dec_[0-9a-f]{12}$")
    event_count: int = Field(ge=1)
    head_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    terminal_event_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    terminal_action: RiskAuditTerminalActionV1
    terminal_decision: RiskAuditDecisionV1
    decision_binding: RiskAuditDecisionBindingV1
    provenance: RiskAuditChainProvenanceV1


class RiskEvidenceChainError(ValueError):
    """Content-free error raised when a verification result is unissued/tampered."""

    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)

    def __str__(self) -> str:
        return self.code


def require_risk_audit_chain_verification(value: object) -> RiskAuditChainVerificationV1:
    """Require an exact intact result issued by this verification kernel."""
    if type(value) is not RiskAuditChainVerificationV1:
        raise RiskEvidenceChainError("UNVERIFIED_SEAL")
    try:
        require(value, _RESULT_ISSUER.tag)
        RiskAuditChainVerificationV1.model_validate(value.model_dump(mode="python"))
    except (SealError, TypeError, ValueError):
        raise RiskEvidenceChainError("UNVERIFIED_SEAL") from None
    return value


def verify_risk_audit_segment(
    events: tuple[RiskAuditEventV1, ...],
    *,
    decision_ref: str,
    head_digest: str,
) -> RiskAuditChainVerificationV1 | RiskAuditChainDiagnosticV1:
    """Verify the full global risk-audit chain from canonical genesis.

    Every event is individually seal-verified and hash-checked. The segment
    must include an ORDER-scope terminal event whose ``correlation_id`` equals
    the requester-provided string. This does not authenticate that string as
    an issued C-101 decision ID. Unrelated decisions remain in the global run.
    """
    if (
        type(events) is not tuple
        or type(decision_ref) is not str
        or _DECISION_REF.fullmatch(decision_ref) is None
        or type(head_digest) is not str
        or _SHA256.fullmatch(head_digest) is None
    ):
        return RiskAuditChainDiagnosticV1.TYPE_INVALID
    if not events:
        return RiskAuditChainDiagnosticV1.NOT_GENESIS

    checked_events: list[RiskAuditEventV1] = []
    for event in events:
        if type(event) is not RiskAuditEventV1:
            return RiskAuditChainDiagnosticV1.TYPE_INVALID
        try:
            checked = require_risk_audit_event(event)
        except RiskAuditEventHashError:
            return RiskAuditChainDiagnosticV1.TYPE_INVALID
        checked_events.append(checked)

    if checked_events[0].sequence != 1:
        return RiskAuditChainDiagnosticV1.NOT_GENESIS

    predecessor = RISK_AUDIT_GENESIS_HASH
    decision_seen = False
    terminal_event: RiskAuditEventV1 | None = None
    for expected_sequence, event in enumerate(checked_events, start=1):
        if event.sequence != expected_sequence:
            return RiskAuditChainDiagnosticV1.GAP
        if event.predecessor_hash != predecessor:
            return RiskAuditChainDiagnosticV1.HASH_MISMATCH
        try:
            expected_hash = risk_audit_event_hash(event, predecessor)
        except RiskAuditEventHashError:
            return RiskAuditChainDiagnosticV1.TYPE_INVALID
        if event.event_hash != expected_hash or event.event_id != expected_hash:
            return RiskAuditChainDiagnosticV1.HASH_MISMATCH
        predecessor = expected_hash
        if event.correlation_id == decision_ref:
            decision_seen = True
            if (
                event.scope == "ORDER"
                and event.action in {item.value for item in RiskAuditTerminalActionV1}
            ):
                terminal_event = event

    if head_digest != predecessor:
        return RiskAuditChainDiagnosticV1.HEAD_MISMATCH
    if not decision_seen:
        return RiskAuditChainDiagnosticV1.DECISION_ABSENT
    if terminal_event is None:
        return RiskAuditChainDiagnosticV1.DECISION_INCOMPLETE

    result = RiskAuditChainVerificationV1(
        decision_ref=decision_ref,
        event_count=len(checked_events),
        head_digest=head_digest,
        terminal_event_id=terminal_event.event_id,
        terminal_action=RiskAuditTerminalActionV1(terminal_event.action),
        terminal_decision=RiskAuditDecisionV1(terminal_event.decision),
        decision_binding=RiskAuditDecisionBindingV1.CORRELATION_ID_STRING_ONLY_NOT_C101_AUTHENTICATED,
        provenance=RiskAuditChainProvenanceV1.CHAIN_VERIFIED_TO_SUPPLIED_HEAD_CORRELATION_ONLY,
    )
    return _RESULT_ISSUER.issue(result)


__all__ = [
    "RiskAuditChainDiagnosticV1",
    "RiskAuditChainProvenanceV1",
    "RiskAuditChainVerificationV1",
    "RiskAuditDecisionBindingV1",
    "RiskAuditDecisionV1",
    "RiskAuditTerminalActionV1",
    "RiskEvidenceChainError",
    "require_risk_audit_chain_verification",
    "verify_risk_audit_segment",
]
