from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from leviathan_core.pipeline import PipelineResult
from leviathan_core.reporting.risk_evidence_chain import (
    RiskAuditChainProvenanceV1,
    RiskAuditChainVerificationV1,
    RiskAuditDecisionBindingV1,
    RiskAuditDecisionV1,
    RiskAuditTerminalActionV1,
    verify_risk_audit_segment,
)
from leviathan_core.reporting.risk_evidence_export import (
    RiskEvidenceErrorCodeV1,
    RiskEvidenceExportError,
    RiskEvidencePolicyDigestSourceV1,
    RiskEvidenceProvenanceV1,
    _audit_chain_projection_digest,
    build_risk_evidence_export,
    require_risk_evidence_export,
    serialize_risk_evidence_export,
)
from leviathan_core.risk_limits.audit_port import (
    RISK_AUDIT_GENESIS_HASH,
    RiskAuditEventV1,
    _issue_event,
    risk_audit_event_hash,
)
from leviathan_core.schemas import (
    CandidateSetup,
    DecisionPacket,
    Direction,
    EventRisk,
    OrderbookBias,
    Permission,
    RiskAction,
    RiskVerdict,
    TradeJournalRecord,
    TradeOutcome,
    TruthStatus,
    TruthValidationResult,
)
from leviathan_core.state.session_classifier import SessionContext

_AT = datetime(2026, 10, 6, 14, 0, tzinfo=UTC)
_DECISION = "dec_0123456789ab"
_POLICY_DIGEST = "a" * 64


def _inputs(
    decision_id: str = _DECISION,
) -> tuple[PipelineResult, RiskVerdict, TradeJournalRecord, dict[str, object]]:
    setup_id = "setup-0123456789abcdef"
    setup = CandidateSetup(setup_id=setup_id, instrument="ES", timestamp=_AT)
    decision = DecisionPacket(
        decision_id=decision_id,
        setup_id=setup_id,
        permission=Permission.REJECT,
        direction=Direction.FLAT,
        confidence=0.0,
        entry_style="none",
        scaling_allowed=False,
        justification="synthetic fixture",
    )
    verdict = RiskVerdict(
        decision_id=decision_id,
        action=RiskAction.REJECT,
        reason="private risk text",
        halts_engaged=(),
        findings=(),
    )
    journal = TradeJournalRecord(
        trade_id="trade-0123456789abcdef",
        setup_id=setup_id,
        decision_id=decision_id,
        outcome=TradeOutcome.BLOCKED,
        post_trade_notes="synthetic private notes",
    )
    pipeline = PipelineResult(
        setup=setup,
        session=SessionContext(label="ny_open", quality=0.9, is_dead_time=False),
        range_context=None,
        truth=TruthValidationResult(
            setup_id=setup_id,
            orderbook_bias=OrderbookBias.NEUTRAL,
            options_context="synthetic",
            event_risk=EventRisk.SAFE,
            sentiment_modifier=0.0,
            truth_status=TruthStatus.CONFIRMED,
        ),
        decision=decision,
        verdict=verdict,
        final_verdict=verdict,
        findings=(),
        intent=None,
        journal_record=journal,
    )
    read_view: dict[str, object] = {
        "decision_id": decision_id,
        "status": "blocked",
        "stage": "blocked",
        "final": True,
        "assessment": verdict.model_dump(mode="json"),
        "authorization": None,
        "paper_draft": None,
        "policy_digest": _POLICY_DIGEST,
        "outcome": {"kind": "pre_sim_block", "journal_outcome": "blocked"},
        "final_verdict": verdict.model_dump(mode="json"),
        "journal_record": journal.model_dump(mode="json"),
    }
    return pipeline, verdict, journal, read_view


def _event(
    *, sequence: int, correlation_id: str, action: str, predecessor_hash: str
) -> RiskAuditEventV1:
    fields: dict[str, object] = {
        "schema_version": 1,
        "sequence": sequence,
        "correlation_id": correlation_id,
        "attempt_id": f"attempt_{sequence}",
        "actor_ref": "1" * 64,
        "action": action,
        "decision": "ALLOW",
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
    digest = risk_audit_event_hash(provisional, predecessor_hash)
    fields["event_id"] = digest
    fields["event_hash"] = digest
    return _issue_event(**fields)


def _segment_events(decision_ref: str = _DECISION) -> tuple[RiskAuditEventV1, ...]:
    first = _event(
        sequence=1,
        correlation_id="dec_000000000009",
        action="LIMIT_POLICY_CHANGE",
        predecessor_hash=RISK_AUDIT_GENESIS_HASH,
    )
    second = _event(
        sequence=2,
        correlation_id=decision_ref,
        action="SOFT_APPROVAL_ISSUED",
        predecessor_hash=first.event_hash,
    )
    third = _event(
        sequence=3,
        correlation_id=decision_ref,
        action="SOFT_APPROVAL_CONSUMED",
        predecessor_hash=second.event_hash,
    )
    return first, second, third


def _verified_segment(decision_ref: str = _DECISION) -> RiskAuditChainVerificationV1:
    events = _segment_events(decision_ref)
    result = verify_risk_audit_segment(
        events, decision_ref=decision_ref, head_digest=events[-1].event_hash
    )
    assert type(result) is RiskAuditChainVerificationV1
    return result


def test_chain_verified_export_retains_only_closed_bound_metadata() -> None:
    inputs = _inputs()
    verification = _verified_segment()

    result = build_risk_evidence_export(
        *inputs,
        chain_verification=verification,
        expected_chain_head=verification.head_digest,
    )
    payload = json.loads(serialize_risk_evidence_export(result))
    record = payload["records"][0]

    assert require_risk_evidence_export(result) is result
    assert result.schema_version == "risk.evidence.export.v2"
    assert result.provenance is (
        RiskAuditChainProvenanceV1.CHAIN_VERIFIED_TO_SUPPLIED_HEAD_CORRELATION_ONLY
    )
    assert result.records[0].provenance is RiskEvidenceProvenanceV1.TYPED_UNSEALED
    assert (
        result.records[0].policy_digest_source is RiskEvidencePolicyDigestSourceV1.READ_VIEW_UNBOUND
    )
    assert (
        payload["provenance"]
        == RiskAuditChainProvenanceV1.CHAIN_VERIFIED_TO_SUPPLIED_HEAD_CORRELATION_ONLY.value
    )
    assert payload["audit_chain_head_digest"] == verification.head_digest
    assert payload["audit_chain_event_count"] == verification.event_count
    assert payload["audit_chain_terminal_event_id"] == verification.terminal_event_id
    assert (
        payload["audit_chain_terminal_action"]
        == RiskAuditTerminalActionV1.SOFT_APPROVAL_CONSUMED.value
    )
    assert payload["audit_chain_terminal_decision"] == RiskAuditDecisionV1.ALLOW.value
    assert (
        payload["audit_chain_decision_binding"]
        == RiskAuditDecisionBindingV1.CORRELATION_ID_STRING_ONLY_NOT_C101_AUTHENTICATED.value
    )
    assert len(payload["audit_chain_projection_digest"]) == 64
    assert record["provenance"] == RiskEvidenceProvenanceV1.TYPED_UNSEALED
    assert "private risk text" not in serialize_risk_evidence_export(result).decode()
    assert "synthetic private notes" not in serialize_risk_evidence_export(result).decode()
    assert "synthetic-account" not in serialize_risk_evidence_export(result).decode()
    assert "attempt_1" not in serialize_risk_evidence_export(result).decode()


def test_chain_claim_preserves_cross_checked_read_view_provenance() -> None:
    pipeline, verdict, journal, read_view = _inputs()
    read_view["paper_draft"] = {"policy_digest": _POLICY_DIGEST}
    verification = _verified_segment()

    result = build_risk_evidence_export(
        pipeline,
        verdict,
        journal,
        read_view,
        chain_verification=verification,
        expected_chain_head=verification.head_digest,
    )

    assert result.provenance is (
        RiskAuditChainProvenanceV1.CHAIN_VERIFIED_TO_SUPPLIED_HEAD_CORRELATION_ONLY
    )
    assert (
        result.records[0].policy_digest_source
        is RiskEvidencePolicyDigestSourceV1.READ_VIEW_CROSS_CHECKED
    )
    assert result.records[0].provenance is RiskEvidenceProvenanceV1.TYPED_UNSEALED


@pytest.mark.parametrize(
    ("verification", "expected_head"),
    [
        (None, "a" * 64),
        (_verified_segment(), None),
    ],
)
def test_chain_verification_and_expected_head_must_be_supplied_together(
    verification: RiskAuditChainVerificationV1 | None,
    expected_head: str | None,
) -> None:
    with pytest.raises(RiskEvidenceExportError) as error:
        build_risk_evidence_export(
            *_inputs(),
            chain_verification=verification,
            expected_chain_head=expected_head,
        )
    assert error.value.code == RiskEvidenceErrorCodeV1.CHAIN_INVALID


def test_foreign_decision_segment_is_rejected() -> None:
    verification = _verified_segment("dec_000000000001")

    with pytest.raises(RiskEvidenceExportError) as error:
        build_risk_evidence_export(
            *_inputs(),
            chain_verification=verification,
            expected_chain_head=verification.head_digest,
        )
    assert error.value.code == RiskEvidenceErrorCodeV1.CHAIN_INVALID


def test_stale_expected_head_is_rejected() -> None:
    verification = _verified_segment()

    with pytest.raises(RiskEvidenceExportError) as error:
        build_risk_evidence_export(
            *_inputs(),
            chain_verification=verification,
            expected_chain_head="f" * 64,
        )
    assert error.value.code == RiskEvidenceErrorCodeV1.CHAIN_INVALID


def test_unissued_tampered_and_non_typed_segments_are_rejected() -> None:
    verification = _verified_segment()
    unissued = RiskAuditChainVerificationV1.model_validate(verification.model_dump(mode="python"))
    tampered = _verified_segment()
    object.__setattr__(tampered, "head_digest", "f" * 64)

    raw_events = _segment_events()
    for value in (unissued, tampered, True, raw_events):
        with pytest.raises(RiskEvidenceExportError) as error:
            build_risk_evidence_export(
                *_inputs(),
                chain_verification=value,  # type: ignore[arg-type]
                expected_chain_head=verification.head_digest,
            )
        assert error.value.code == RiskEvidenceErrorCodeV1.CHAIN_INVALID


def test_incomplete_verifier_diagnostic_cannot_be_exported() -> None:
    first = _event(
        sequence=1,
        correlation_id=_DECISION,
        action="SOFT_APPROVAL_ISSUED",
        predecessor_hash=RISK_AUDIT_GENESIS_HASH,
    )
    incomplete = verify_risk_audit_segment(
        (first,), decision_ref=_DECISION, head_digest=first.event_hash
    )

    with pytest.raises(RiskEvidenceExportError) as error:
        build_risk_evidence_export(
            *_inputs(),
            chain_verification=incomplete,  # type: ignore[arg-type]
            expected_chain_head=first.event_hash,
        )
    assert error.value.code == RiskEvidenceErrorCodeV1.CHAIN_INVALID


def test_chain_metadata_digest_is_rechecked_by_export_require() -> None:
    verification = _verified_segment()
    result = build_risk_evidence_export(
        *_inputs(),
        chain_verification=verification,
        expected_chain_head=verification.head_digest,
    )
    object.__setattr__(result, "audit_chain_head_digest", "f" * 64)

    with pytest.raises(RiskEvidenceExportError) as error:
        require_risk_evidence_export(result)
    assert error.value.code in {
        RiskEvidenceErrorCodeV1.UNVERIFIED_SEAL,
        RiskEvidenceErrorCodeV1.CHAIN_INVALID,
    }


def test_chain_projection_digest_binds_export_record_hash() -> None:
    verification = _verified_segment()
    result = build_risk_evidence_export(
        *_inputs(),
        chain_verification=verification,
        expected_chain_head=verification.head_digest,
    )
    record = result.records[0]
    original = result.audit_chain_projection_digest
    changed = _audit_chain_projection_digest(
        decision_ref=record.decision_ref,
        record_hash="f" * 64,
        head_digest=verification.head_digest,
        event_count=verification.event_count,
        terminal_event_id=verification.terminal_event_id,
        terminal_action=verification.terminal_action,
        terminal_decision=verification.terminal_decision,
        decision_binding=verification.decision_binding,
    )

    assert original != changed


def test_unwired_export_keeps_legacy_typed_unsealed_schema() -> None:
    result = build_risk_evidence_export(*_inputs())
    payload = json.loads(serialize_risk_evidence_export(result))

    assert result.schema_version == "risk.evidence.export.v1"
    assert result.provenance is RiskEvidenceProvenanceV1.TYPED_UNSEALED
    assert set(payload) == {"schema", "complete", "provenance", "records", "head_hash"}
    assert payload["provenance"] == RiskEvidenceProvenanceV1.TYPED_UNSEALED.value
