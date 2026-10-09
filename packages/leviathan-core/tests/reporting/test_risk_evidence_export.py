from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from leviathan_core.pipeline import PipelineResult
from leviathan_core.reporting.risk_evidence_export import (
    RiskEvidenceErrorCodeV1,
    RiskEvidenceExportError,
    RiskEvidenceExportV1,
    RiskEvidenceLocalHaltCodeV1,
    RiskEvidencePolicyDigestSourceV1,
    RiskEvidenceProvenanceV1,
    build_risk_evidence_export,
    require_risk_evidence_export,
    serialize_risk_evidence_export,
)
from leviathan_core.schemas import (
    CandidateSetup,
    DecisionPacket,
    Direction,
    EventRisk,
    GateFinding,
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
_DIGEST = "a" * 64


def _inputs(
    *,
    action: RiskAction = RiskAction.REJECT,
    halt_reasons: tuple[str, ...] = (),
    findings: tuple[GateFinding, ...] = (),
    decision_id: str = "dec_0123456789ab",
    verdict_reason: str = "private risk notes MUST NOT be exported",
    journal_notes: str = "synthetic account-id=ACCT-SECRET and strategy payload=SECRET-CANARY",
) -> tuple[PipelineResult, RiskVerdict, TradeJournalRecord, dict[str, object]]:
    setup_id = "setup-0123456789abcdef"
    setup = CandidateSetup(
        setup_id=setup_id,
        instrument="ES",
        timestamp=_AT,
    )
    decision = DecisionPacket(
        decision_id=decision_id,
        setup_id=setup_id,
        permission=Permission.REJECT,
        direction=Direction.FLAT,
        confidence=0.0,
        entry_style="none",
        scaling_allowed=False,
        justification="synthetic test fixture",
    )
    verdict = RiskVerdict(
        decision_id=decision_id,
        action=action,
        reason=verdict_reason,
        halts_engaged=halt_reasons,
        findings=findings,
    )
    journal = TradeJournalRecord(
        trade_id="trade-0123456789abcdef",
        setup_id=setup_id,
        decision_id=decision_id,
        outcome=TradeOutcome.BLOCKED,
        post_trade_notes=journal_notes,
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
        findings=findings,
        intent=None,
        journal_record=journal,
    )
    view: dict[str, object] = {
        "decision_id": decision_id,
        "status": "blocked",
        "stage": "blocked",
        "final": True,
        "assessment": verdict.model_dump(mode="json"),
        "authorization": None,
        "paper_draft": None,
        "policy_digest": _DIGEST,
        "outcome": {"kind": "pre_sim_block", "journal_outcome": "blocked"},
        "final_verdict": verdict.model_dump(mode="json"),
        "journal_record": journal.model_dump(mode="json"),
    }
    return pipeline, verdict, journal, view


def test_complete_blocked_evidence_is_sealed_hash_linked_and_redacted() -> None:
    pipeline, verdict, journal, view = _inputs()

    result = build_risk_evidence_export(pipeline, verdict, journal, view)
    repeat = build_risk_evidence_export(pipeline, verdict, journal, view)
    encoded = serialize_risk_evidence_export(result)
    payload = json.loads(encoded)
    record = payload["records"][0]

    assert serialize_risk_evidence_export(repeat) == encoded
    assert require_risk_evidence_export(result) is result
    assert result.complete is True
    assert result.head_hash == record["record_hash"]
    assert record["decision_ref"] == pipeline.decision.decision_id
    assert record["journal_outcome"] == "blocked"
    assert record["provenance"] == RiskEvidenceProvenanceV1.TYPED_UNSEALED.value
    assert payload["provenance"] == RiskEvidenceProvenanceV1.TYPED_UNSEALED.value
    assert record["halt_state"] is False
    assert record["setup_at_utc"] == _AT.isoformat()
    assert (
        record["policy_digest_source"] == RiskEvidencePolicyDigestSourceV1.READ_VIEW_UNBOUND.value
    )
    assert [item["source"] for item in record["projection_digests"]] == [
        "RISK_VERDICT",
        "TRADE_JOURNAL",
    ]
    assert b"ACCT-SECRET" not in encoded
    assert b"SECRET-CANARY" not in encoded
    assert b"private risk notes" not in encoded
    assert b"synthetic test fixture" not in encoded


def test_incomplete_or_mismatched_read_view_has_no_success_marker() -> None:
    pipeline, verdict, journal, view = _inputs()
    view["final"] = False

    with pytest.raises(RiskEvidenceExportError) as error:
        build_risk_evidence_export(pipeline, verdict, journal, view)

    assert error.value.code == RiskEvidenceErrorCodeV1.INCOMPLETE_EVIDENCE.value


def test_read_view_from_another_decision_is_rejected() -> None:
    pipeline, verdict, journal, view = _inputs()
    view["decision_id"] = "decision-other"

    with pytest.raises(RiskEvidenceExportError) as error:
        build_risk_evidence_export(pipeline, verdict, journal, view)

    assert error.value.code == RiskEvidenceErrorCodeV1.INCOMPLETE_EVIDENCE.value


def test_invalid_policy_digest_is_content_free_failure() -> None:
    pipeline, verdict, journal, view = _inputs()
    view["policy_digest"] = "caller supplied secret text"

    with pytest.raises(RiskEvidenceExportError) as error:
        build_risk_evidence_export(pipeline, verdict, journal, view)

    assert error.value.code == RiskEvidenceErrorCodeV1.POLICY_DIGEST_INVALID.value
    assert "secret" not in str(error.value)


@pytest.mark.parametrize("digest", ["0" * 64, "g" * 64, "short"])
def test_invalid_or_genesis_policy_digest_is_rejected(digest: str) -> None:
    pipeline, verdict, journal, view = _inputs()
    view["policy_digest"] = digest

    with pytest.raises(RiskEvidenceExportError) as error:
        build_risk_evidence_export(pipeline, verdict, journal, view)

    assert error.value.code == RiskEvidenceErrorCodeV1.POLICY_DIGEST_INVALID.value


@pytest.mark.parametrize("source_key", ["authorization", "paper_draft"])
def test_read_view_digest_mismatch_is_rejected(source_key: str) -> None:
    pipeline, verdict, journal, view = _inputs()
    if source_key == "authorization":
        view[source_key] = {"policy_digest": "b" * 64}
    else:
        view[source_key] = {"policy_digest": "b" * 64}

    with pytest.raises(RiskEvidenceExportError) as error:
        build_risk_evidence_export(pipeline, verdict, journal, view)

    assert error.value.code == RiskEvidenceErrorCodeV1.POLICY_DIGEST_INVALID.value


def test_matching_embedded_policy_digest_is_marked_cross_checked() -> None:
    pipeline, verdict, journal, view = _inputs()
    view["paper_draft"] = {"policy_digest": _DIGEST}

    result = build_risk_evidence_export(pipeline, verdict, journal, view)

    assert (
        result.records[0].policy_digest_source
        is RiskEvidencePolicyDigestSourceV1.READ_VIEW_CROSS_CHECKED
    )


def test_decision_reference_must_use_closed_generated_id_grammar() -> None:
    pipeline, verdict, journal, view = _inputs(decision_id="acct_4111111111111111")

    with pytest.raises(RiskEvidenceExportError) as error:
        build_risk_evidence_export(pipeline, verdict, journal, view)

    assert error.value.code == RiskEvidenceErrorCodeV1.INVALID_INPUT.value
    assert "4111111111111111" not in str(error.value)


def test_unknown_halt_reason_is_rejected_without_export() -> None:
    pipeline, verdict, journal, view = _inputs(
        action=RiskAction.HALT_ALL_TRADING,
        halt_reasons=("operator said stop because secret",),
    )
    view["assessment"] = verdict.model_dump(mode="json")
    view["final_verdict"] = verdict.model_dump(mode="json")

    with pytest.raises(RiskEvidenceExportError) as error:
        build_risk_evidence_export(pipeline, verdict, journal, view)

    assert error.value.code == RiskEvidenceErrorCodeV1.HALT_REASON_INVALID.value


def test_closed_halt_reason_is_exported_as_code() -> None:
    pipeline, verdict, journal, view = _inputs(
        action=RiskAction.HALT_ALL_TRADING,
        halt_reasons=("operator_halt",),
    )

    result = build_risk_evidence_export(pipeline, verdict, journal, view)
    record = result.records[0]

    assert record.halt_state is True
    assert record.halt_reason_codes == ("operator_halt",)


def test_global_kill_without_source_reason_has_export_local_closed_code() -> None:
    pipeline, verdict, journal, view = _inputs(
        action=RiskAction.HALT_ALL_TRADING,
        findings=(GateFinding.GLOBAL_KILL,),
    )

    result = build_risk_evidence_export(pipeline, verdict, journal, view)

    assert result.records[0].halt_reason_codes == (
        RiskEvidenceLocalHaltCodeV1.GLOBAL_KILL_UNSPECIFIED.value,
    )


def test_export_changes_when_an_exported_closed_verdict_finding_changes() -> None:
    first = build_risk_evidence_export(*_inputs())
    second = build_risk_evidence_export(*_inputs(findings=(GateFinding.LOCK_MISSING,)))

    assert serialize_risk_evidence_export(first) != serialize_risk_evidence_export(second)


def test_free_text_only_differences_intentionally_leave_projection_identical() -> None:
    original = build_risk_evidence_export(*_inputs())
    changed_text = build_risk_evidence_export(
        *_inputs(
            verdict_reason="another private diagnostic reason",
            journal_notes="another account and strategy payload",
        )
    )

    assert serialize_risk_evidence_export(original) == serialize_risk_evidence_export(changed_text)


def test_unissued_or_tampered_export_never_passes_require() -> None:
    pipeline, verdict, journal, view = _inputs()
    issued = build_risk_evidence_export(pipeline, verdict, journal, view)
    unissued = RiskEvidenceExportV1(
        records=issued.records,
        head_hash=issued.head_hash,
    )

    with pytest.raises(RiskEvidenceExportError) as unissued_error:
        require_risk_evidence_export(unissued)
    assert unissued_error.value.code == RiskEvidenceErrorCodeV1.UNVERIFIED_SEAL.value

    object.__setattr__(issued.records[0], "decision_ref", "decision-tampered")
    with pytest.raises(RiskEvidenceExportError) as tampered_error:
        serialize_risk_evidence_export(issued)
    assert tampered_error.value.code in {
        RiskEvidenceErrorCodeV1.UNVERIFIED_SEAL.value,
        RiskEvidenceErrorCodeV1.CHAIN_INVALID.value,
    }
