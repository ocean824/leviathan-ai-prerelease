from __future__ import annotations

from hashlib import sha256

import pytest

from leviathan_core.numeric import canonical_json
from leviathan_core.reporting.risk_evidence_chain import (
    RiskAuditChainDiagnosticV1,
    RiskAuditChainProvenanceV1,
    RiskAuditChainVerificationV1,
    RiskAuditDecisionBindingV1,
    RiskAuditDecisionV1,
    RiskAuditTerminalActionV1,
    RiskEvidenceChainError,
    require_risk_audit_chain_verification,
    verify_risk_audit_segment,
)
from leviathan_core.risk_limits.audit_port import (
    RISK_AUDIT_GENESIS_HASH,
    RiskAuditEventV1,
    _issue_event,
    risk_audit_event_hash,
)


def _event(
    *,
    sequence: int,
    correlation_id: str,
    action: str,
    predecessor_hash: str,
    decision: str = "ALLOW",
) -> RiskAuditEventV1:
    fields: dict[str, object] = {
        "schema_version": 1,
        "sequence": sequence,
        "correlation_id": correlation_id,
        "attempt_id": f"attempt_{sequence}",
        "actor_ref": "1" * 64,
        "action": action,
        "decision": decision,
        "reason_code": "SYNTHETIC_TEST",
        "environment": "paper",
        "account_id": "synthetic-account",
        "scope": "ACCOUNT" if action == "LIMIT_POLICY_CHANGE" else "ORDER",
        "before_digest": None,
        "after_digest": "2" * 64,
        "source_event_ids": (),
        "recorded_at_ns": 1_700_000_000_000_000_000 + sequence - 1,
        "predecessor_hash": predecessor_hash,
        "event_id": "0" * 64,
        "event_hash": "0" * 64,
    }
    provisional = RiskAuditEventV1.model_validate(fields)
    event_hash = risk_audit_event_hash(provisional, predecessor_hash)
    fields["event_id"] = event_hash
    fields["event_hash"] = event_hash
    return _issue_event(**fields)  # type: ignore[arg-type]


def _valid_segment() -> tuple[RiskAuditEventV1, ...]:
    first = _event(
        sequence=1,
        correlation_id="dec_000000000009",
        action="LIMIT_POLICY_CHANGE",
        predecessor_hash=RISK_AUDIT_GENESIS_HASH,
    )
    second = _event(
        sequence=2,
        correlation_id="dec_000000000001",
        action="SOFT_APPROVAL_ISSUED",
        predecessor_hash=first.event_hash,
    )
    third = _event(
        sequence=3,
        correlation_id="dec_000000000001",
        action="SOFT_APPROVAL_CONSUMED",
        predecessor_hash=second.event_hash,
    )
    return first, second, third


def test_hash_matches_pre_migration_store_golden_vector() -> None:
    body = {
        "schema_version": 1,
        "sequence": 1,
        "correlation_id": "dec_0123456789ab",
        "attempt_id": "attempt_1",
        "actor_ref": "1" * 64,
        "action": "LIMIT_POLICY_CHANGE",
        "decision": "ALLOW",
        "reason_code": "POLICY_UPDATED",
        "environment": "paper",
        "account_id": "synthetic-account",
        "scope": "ACCOUNT",
        "before_digest": None,
        "after_digest": "2" * 64,
        "source_event_ids": (),
        "recorded_at_ns": 1_700_000_000_000_000_000,
        "predecessor_hash": RISK_AUDIT_GENESIS_HASH,
    }
    old_store_digest = sha256(
        bytes.fromhex(RISK_AUDIT_GENESIS_HASH) + b"\x00" + canonical_json(body)
    ).hexdigest()
    assert old_store_digest == "768a87a2ec6fc4e81fdd5947e03de12553a9b010aa8ab3cd9c05a5822971a5f6"
    event = RiskAuditEventV1.model_validate(
        {
            **body,
            "event_id": old_store_digest,
            "event_hash": old_store_digest,
        }
    )
    assert risk_audit_event_hash(event, RISK_AUDIT_GENESIS_HASH) == old_store_digest


def test_complete_global_chain_verifies_decision_inside_run() -> None:
    events = _valid_segment()
    result = verify_risk_audit_segment(
        events,
        decision_ref="dec_000000000001",
        head_digest=events[-1].event_hash,
    )
    assert type(result) is RiskAuditChainVerificationV1
    assert result.decision_ref == "dec_000000000001"
    assert result.event_count == 3
    assert result.head_digest == events[-1].event_hash
    assert result.terminal_event_id == events[-1].event_id
    assert result.terminal_action is RiskAuditTerminalActionV1.SOFT_APPROVAL_CONSUMED
    assert result.terminal_decision is RiskAuditDecisionV1.ALLOW
    assert (
        result.decision_binding
        is RiskAuditDecisionBindingV1.CORRELATION_ID_STRING_ONLY_NOT_C101_AUTHENTICATED
    )
    assert (
        result.provenance
        is RiskAuditChainProvenanceV1.CHAIN_VERIFIED_TO_SUPPLIED_HEAD_CORRELATION_ONLY
    )
    assert require_risk_audit_chain_verification(result) == result


@pytest.mark.parametrize(
    ("events", "decision_ref", "head_digest", "diagnostic"),
    [
        ((), "dec_000000000001", "0" * 64, RiskAuditChainDiagnosticV1.NOT_GENESIS),
        (
            (_event(
                sequence=2,
                correlation_id="dec_000000000001",
                action="LIMIT_POLICY_CHANGE",
                predecessor_hash=RISK_AUDIT_GENESIS_HASH,
            ),),
            "dec_000000000001",
            "0" * 64,
            RiskAuditChainDiagnosticV1.NOT_GENESIS,
        ),
    ],
)
def test_non_genesis_segment_is_rejected(
    events: tuple[RiskAuditEventV1, ...],
    decision_ref: str,
    head_digest: str,
    diagnostic: RiskAuditChainDiagnosticV1,
) -> None:
    assert verify_risk_audit_segment(
        events, decision_ref=decision_ref, head_digest=head_digest
    ) is diagnostic


def test_reordered_or_truncated_decision_is_rejected() -> None:
    events = _valid_segment()
    reordered = verify_risk_audit_segment(
        (events[0], events[2], events[1]),
        decision_ref="dec_000000000001",
        head_digest=events[2].event_hash,
    )
    assert reordered is RiskAuditChainDiagnosticV1.GAP
    truncated = verify_risk_audit_segment(
        events[:2],
        decision_ref="dec_000000000001",
        head_digest=events[1].event_hash,
    )
    assert truncated is RiskAuditChainDiagnosticV1.DECISION_INCOMPLETE


def test_foreign_decision_and_head_mismatch_are_content_free() -> None:
    events = _valid_segment()
    absent = verify_risk_audit_segment(
        events,
        decision_ref="dec_000000000003",
        head_digest=events[-1].event_hash,
    )
    assert absent is RiskAuditChainDiagnosticV1.DECISION_ABSENT
    mismatch = verify_risk_audit_segment(
        events,
        decision_ref="dec_000000000001",
        head_digest="f" * 64,
    )
    assert mismatch is RiskAuditChainDiagnosticV1.HEAD_MISMATCH


def test_account_policy_change_with_decision_reference_is_not_terminal() -> None:
    policy_change = _event(
        sequence=1,
        correlation_id="dec_000000000001",
        action="LIMIT_POLICY_CHANGE",
        predecessor_hash=RISK_AUDIT_GENESIS_HASH,
    )
    result = verify_risk_audit_segment(
        (policy_change,),
        decision_ref="dec_000000000001",
        head_digest=policy_change.event_hash,
    )
    assert result is RiskAuditChainDiagnosticV1.DECISION_INCOMPLETE


def test_invalid_types_and_unissued_success_fail_closed() -> None:
    events = _valid_segment()
    assert (
        verify_risk_audit_segment(
            [*events],  # type: ignore[arg-type]
            decision_ref="dec_000000000001",
            head_digest=events[-1].event_hash,
        )
        is RiskAuditChainDiagnosticV1.TYPE_INVALID
    )
    unissued = RiskAuditChainVerificationV1(
        decision_ref="dec_000000000001",
        event_count=2,
        head_digest=events[-1].event_hash,
        terminal_event_id=events[-1].event_id,
        terminal_action=RiskAuditTerminalActionV1.SOFT_APPROVAL_CONSUMED,
        terminal_decision=RiskAuditDecisionV1.ALLOW,
        decision_binding=RiskAuditDecisionBindingV1.CORRELATION_ID_STRING_ONLY_NOT_C101_AUTHENTICATED,
        provenance=RiskAuditChainProvenanceV1.CHAIN_VERIFIED_TO_SUPPLIED_HEAD_CORRELATION_ONLY,
    )
    with pytest.raises(RiskEvidenceChainError) as exc:
        require_risk_audit_chain_verification(unissued)
    assert exc.value.code == "UNVERIFIED_SEAL"
    assert str(exc.value) == "UNVERIFIED_SEAL"
