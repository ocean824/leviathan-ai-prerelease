"""Independent black-box acceptance for chain-aware risk evidence exports."""

from __future__ import annotations

import inspect
import json
from datetime import UTC, datetime
from hashlib import sha256

import pytest

from leviathan_core.numeric import canonical_json
from leviathan_core.pipeline import PipelineResult
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
from leviathan_core.reporting.risk_evidence_export import (
    RiskEvidenceErrorCodeV1,
    RiskEvidenceExportError,
    RiskEvidencePolicyDigestSourceV1,
    RiskEvidenceProvenanceV1,
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
_FOREIGN_DECISION = "dec_000000000001"
_POLICY_DIGEST = "a" * 64
_VERDICT_REDACTION_CANARY = "SYNTHETIC_PRIVATE_VERDICT_TEXT_7865"
_JOURNAL_REDACTION_CANARY = "SYNTHETIC_PRIVATE_JOURNAL_TEXT_9264"
_AUDIT_ROW_CANARY = "SYNTHETIC_RAW_AUDIT_ROW_5317"


def _inputs(
    decision_id: str = _DECISION,
    *,
    cross_checked: bool = False,
) -> tuple[PipelineResult, RiskVerdict, TradeJournalRecord, dict[str, object]]:
    setup_id = "setup-risk-evidence-acceptance"
    setup = CandidateSetup(setup_id=setup_id, instrument="SYNTH-ES", timestamp=_AT)
    decision = DecisionPacket(
        decision_id=decision_id,
        setup_id=setup_id,
        permission=Permission.REJECT,
        direction=Direction.FLAT,
        confidence=0.0,
        entry_style="none",
        scaling_allowed=False,
        justification="synthetic acceptance fixture",
    )
    verdict = RiskVerdict(
        decision_id=decision_id,
        action=RiskAction.REJECT,
        reason=_VERDICT_REDACTION_CANARY,
        halts_engaged=(),
        findings=(),
    )
    journal = TradeJournalRecord(
        trade_id="trade-risk-evidence-acceptance",
        setup_id=setup_id,
        decision_id=decision_id,
        outcome=TradeOutcome.BLOCKED,
        post_trade_notes=_JOURNAL_REDACTION_CANARY,
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
        "authorization": {"policy_digest": _POLICY_DIGEST} if cross_checked else None,
        "paper_draft": None,
        "policy_digest": _POLICY_DIGEST,
        "outcome": {"kind": "pre_sim_block", "journal_outcome": "blocked"},
        "final_verdict": verdict.model_dump(mode="json"),
        "journal_record": journal.model_dump(mode="json"),
    }
    return pipeline, verdict, journal, read_view


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
        "attempt_id": f"acceptance-attempt-{sequence}",
        "actor_ref": "1" * 64,
        "action": action,
        "decision": decision,
        "reason_code": _AUDIT_ROW_CANARY,
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
    # The audit store's sealed fixture issuer creates synthetic source rows;
    # the test exercises the public verifier and exporter boundaries below.
    return _issue_event(**fields)  # type: ignore[arg-type]


def _events(decision_ref: str = _DECISION) -> tuple[RiskAuditEventV1, ...]:
    first = _event(
        sequence=1,
        correlation_id="dec_000000000009",
        action="LIMIT_POLICY_CHANGE",
        predecessor_hash=RISK_AUDIT_GENESIS_HASH,
        decision="RECORDED",
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


def _verified(
    decision_ref: str = _DECISION,
) -> tuple[tuple[RiskAuditEventV1, ...], RiskAuditChainVerificationV1]:
    events = _events(decision_ref)
    result = verify_risk_audit_segment(
        events,
        decision_ref=decision_ref,
        head_digest=events[-1].event_hash,
    )
    assert type(result) is RiskAuditChainVerificationV1
    return events, result


def _export(
    verification: object,
    expected_head: str | None,
    *,
    inputs: tuple[PipelineResult, RiskVerdict, TradeJournalRecord, dict[str, object]] | None = None,
) -> object:
    return build_risk_evidence_export(
        *(inputs if inputs is not None else _inputs()),
        chain_verification=verification,  # type: ignore[arg-type]
        expected_chain_head=expected_head,
    )


def _expect_chain_rejection(verification: object, expected_head: str | None) -> None:
    with pytest.raises(RiskEvidenceExportError) as error:
        _export(verification, expected_head)
    assert error.value.code == RiskEvidenceErrorCodeV1.CHAIN_INVALID.value
    assert str(error.value) == RiskEvidenceErrorCodeV1.CHAIN_INVALID.value


def test_only_verified_same_decision_and_supplied_head_get_chain_provenance() -> None:
    events, verification = _verified()
    export = _export(verification, verification.head_digest)

    assert require_risk_evidence_export(export) is export
    assert export.schema_version == "risk.evidence.export.v2"
    assert (
        export.provenance
        is RiskAuditChainProvenanceV1.CHAIN_VERIFIED_TO_SUPPLIED_HEAD_CORRELATION_ONLY
    )
    assert export.audit_chain_head_digest == verification.head_digest
    assert export.audit_chain_event_count == len(events)
    assert export.audit_chain_terminal_event_id == events[-1].event_id
    assert export.audit_chain_terminal_action is RiskAuditTerminalActionV1.SOFT_APPROVAL_CONSUMED
    assert export.audit_chain_terminal_decision is RiskAuditDecisionV1.ALLOW
    assert (
        export.audit_chain_decision_binding
        is RiskAuditDecisionBindingV1.CORRELATION_ID_STRING_ONLY_NOT_C101_AUTHENTICATED
    )


@pytest.mark.parametrize("decision_ref", [_FOREIGN_DECISION])
def test_foreign_decision_segment_is_rejected(decision_ref: str) -> None:
    _events_for_foreign_decision, verification = _verified(decision_ref)
    _expect_chain_rejection(verification, verification.head_digest)


def test_stale_supplied_head_is_rejected() -> None:
    events, verification = _verified()
    stale_head = events[-2].event_hash

    assert stale_head != verification.head_digest
    _expect_chain_rejection(verification, stale_head)


@pytest.mark.parametrize("reserved_value", [True, (), []])
def test_boolean_and_raw_row_inputs_are_not_verifier_results(reserved_value: object) -> None:
    _events_fixture, verification = _verified()
    if reserved_value == () or reserved_value == []:
        supplied: object = _events_fixture if reserved_value == () else list(_events_fixture)
    else:
        supplied = reserved_value
    _expect_chain_rejection(supplied, verification.head_digest)


def test_directly_constructed_or_mutated_verification_is_rejected() -> None:
    _events_fixture, verification = _verified()
    direct = RiskAuditChainVerificationV1.model_validate(verification.model_dump(mode="python"))
    with pytest.raises(RiskEvidenceChainError):
        require_risk_audit_chain_verification(direct)
    _expect_chain_rejection(direct, verification.head_digest)

    tampered = _verified()[1]
    object.__setattr__(tampered, "head_digest", "f" * 64)
    _expect_chain_rejection(tampered, verification.head_digest)


def test_tampered_event_row_cannot_be_exported() -> None:
    events = _events()
    object.__setattr__(events[1], "reason_code", "ALTERED_SYNTHETIC_REASON")
    rejected = verify_risk_audit_segment(
        events,
        decision_ref=_DECISION,
        head_digest=events[-1].event_hash,
    )

    assert rejected is RiskAuditChainDiagnosticV1.TYPE_INVALID
    _expect_chain_rejection(rejected, events[-1].event_hash)


def test_incomplete_segment_without_consumed_terminal_is_rejected() -> None:
    events = _events()
    incomplete_events = events[:-1]
    rejected = verify_risk_audit_segment(
        incomplete_events,
        decision_ref=_DECISION,
        head_digest=incomplete_events[-1].event_hash,
    )

    assert rejected is RiskAuditChainDiagnosticV1.DECISION_INCOMPLETE
    _expect_chain_rejection(rejected, incomplete_events[-1].event_hash)


@pytest.mark.parametrize("one_sided", [(None, "a" * 64), ("not-a-verification", None)])
def test_chain_arguments_must_be_supplied_as_a_pair(
    one_sided: tuple[object | None, str | None],
) -> None:
    with pytest.raises(RiskEvidenceExportError) as error:
        build_risk_evidence_export(
            *_inputs(),
            chain_verification=one_sided[0],  # type: ignore[arg-type]
            expected_chain_head=one_sided[1],
        )
    assert error.value.code == RiskEvidenceErrorCodeV1.CHAIN_INVALID.value


@pytest.mark.parametrize("cross_checked", [False, True])
def test_unwired_typed_unsealed_and_read_view_provenance_remain_unchanged(
    cross_checked: bool,
) -> None:
    inputs = _inputs(cross_checked=cross_checked)
    export = build_risk_evidence_export(*inputs)
    payload = json.loads(serialize_risk_evidence_export(export))
    expected_source = (
        RiskEvidencePolicyDigestSourceV1.READ_VIEW_CROSS_CHECKED
        if cross_checked
        else RiskEvidencePolicyDigestSourceV1.READ_VIEW_UNBOUND
    )

    assert export.schema_version == "risk.evidence.export.v1"
    assert export.provenance is RiskEvidenceProvenanceV1.TYPED_UNSEALED
    assert export.records[0].provenance is RiskEvidenceProvenanceV1.TYPED_UNSEALED
    assert export.records[0].policy_digest_source is expected_source
    assert payload["provenance"] == RiskEvidenceProvenanceV1.TYPED_UNSEALED.value
    assert payload["records"][0]["provenance"] == RiskEvidenceProvenanceV1.TYPED_UNSEALED.value
    assert payload["records"][0]["policy_digest_source"] == expected_source.value


def test_chain_export_preserves_redaction_read_view_and_projection_digests() -> None:
    inputs = _inputs(cross_checked=True)
    baseline = build_risk_evidence_export(*inputs)
    events, verification = _verified()
    chain_export = _export(verification, verification.head_digest, inputs=inputs)
    encoded = serialize_risk_evidence_export(chain_export)
    payload = json.loads(encoded)
    record = payload["records"][0]

    assert chain_export.records[0].provenance is RiskEvidenceProvenanceV1.TYPED_UNSEALED
    assert (
        chain_export.records[0].policy_digest_source
        is RiskEvidencePolicyDigestSourceV1.READ_VIEW_CROSS_CHECKED
    )
    assert chain_export.records[0].projection_digests == baseline.records[0].projection_digests
    assert (
        record["projection_digests"]
        == json.loads(serialize_risk_evidence_export(baseline))["records"][0]["projection_digests"]
    )
    assert chain_export.audit_chain_projection_digest == payload["audit_chain_projection_digest"]
    assert len(chain_export.audit_chain_projection_digest) == 64
    expected_chain_projection = sha256(
        canonical_json(
            {
                "schema": "risk.evidence.audit-chain.projection.v2",
                "decision_ref": record["decision_ref"],
                "record_hash": record["record_hash"],
                "head_digest": payload["audit_chain_head_digest"],
                "event_count": payload["audit_chain_event_count"],
                "terminal_event_id": payload["audit_chain_terminal_event_id"],
                "terminal_action": payload["audit_chain_terminal_action"],
                "terminal_decision": payload["audit_chain_terminal_decision"],
                "decision_binding": payload["audit_chain_decision_binding"],
                "provenance": payload["provenance"],
            }
        )
    ).hexdigest()
    assert chain_export.audit_chain_projection_digest == expected_chain_projection
    assert payload["schema"] == "risk.evidence.export.v2"
    assert payload["provenance"] == (
        RiskAuditChainProvenanceV1.CHAIN_VERIFIED_TO_SUPPLIED_HEAD_CORRELATION_ONLY.value
    )
    for secret in (_VERDICT_REDACTION_CANARY, _JOURNAL_REDACTION_CANARY, _AUDIT_ROW_CANARY):
        assert secret.encode() not in encoded
    assert "audit_events" not in payload
    assert "rows" not in payload
    assert [event.event_hash for event in events] == [event.event_hash for event in _events()]


def test_export_is_read_only_and_exposes_no_audit_writer_parameter() -> None:
    events, verification = _verified()
    before = tuple((event.sequence, event.event_hash) for event in events)
    parameter_names = set(inspect.signature(build_risk_evidence_export).parameters)

    assert not parameter_names.intersection({"audit", "audit_port", "store", "writer"})
    export = _export(verification, verification.head_digest)
    serialize_risk_evidence_export(export)
    assert tuple((event.sequence, event.event_hash) for event in events) == before


def test_export_mutation_is_rejected_by_public_require_boundary() -> None:
    _events_fixture, verification = _verified()
    export = _export(verification, verification.head_digest)
    object.__setattr__(export, "audit_chain_projection_digest", "f" * 64)

    with pytest.raises(RiskEvidenceExportError) as error:
        require_risk_evidence_export(export)
    assert error.value.code in {
        RiskEvidenceErrorCodeV1.UNVERIFIED_SEAL.value,
        RiskEvidenceErrorCodeV1.CHAIN_INVALID.value,
    }


def test_export_projection_digests_match_the_canonical_closed_projection() -> None:
    _events_fixture, verification = _verified()
    export = _export(verification, verification.head_digest)
    record = export.records[0]
    projections = {item.source.value: item.digest for item in record.projection_digests}
    expected = sha256(
        canonical_json(
            {
                "schema": "risk.evidence.risk_verdict.projection.v1",
                "decision_ref": record.decision_ref,
                "outcome": record.outcome.value,
                "risk_findings": tuple(item.value for item in record.risk_findings),
                "halt_state": record.halt_state,
                "halt_reason_codes": record.halt_reason_codes,
            }
        )
    ).hexdigest()

    assert projections["RISK_VERDICT"] == expected
    assert all(len(value) == 64 for value in projections.values())
