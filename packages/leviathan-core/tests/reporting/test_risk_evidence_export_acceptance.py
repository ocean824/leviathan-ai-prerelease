from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256

import pytest

from leviathan_core.numeric import canonical_json
from leviathan_core.pipeline import PipelineResult
from leviathan_core.reporting.risk_evidence_export import (
    RiskEvidenceErrorCodeV1,
    RiskEvidenceExportError,
    RiskEvidenceExportV1,
    RiskEvidencePolicyDigestSourceV1,
    RiskEvidenceProvenanceV1,
    RiskEvidenceRecordV1,
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
from leviathan_core.seal import SealError
from leviathan_core.state.session_classifier import SessionContext

AT = datetime(2026, 10, 6, 14, 30, tzinfo=UTC)
POLICY_DIGEST = "d" * 64
ACCOUNT_CANARY = "FULL-ACCOUNT-ID-CANARY-928374"
SECRET_CANARY = "PRIVATE-STRATEGY-PAYLOAD-CANARY"
CREDENTIAL_CANARY = "credential://synthetic-secret-reference"


def _case(
    *,
    decision_id: str = "dec_0123456789ab",
    action: RiskAction = RiskAction.REJECT,
    halts: tuple[str, ...] = (),
    findings: tuple[GateFinding, ...] = (),
    verdict_reason: str = f"private detail {SECRET_CANARY}; {CREDENTIAL_CANARY}",
    journal_notes: str = f"account={ACCOUNT_CANARY}; strategy={SECRET_CANARY}",
) -> tuple[PipelineResult, RiskVerdict, TradeJournalRecord, dict[str, object]]:
    setup_id = "setup-independent-001"
    setup = CandidateSetup(setup_id=setup_id, instrument="SYNTH-ES", timestamp=AT)
    decision = DecisionPacket(
        decision_id=decision_id,
        setup_id=setup_id,
        permission=Permission.REJECT,
        direction=Direction.FLAT,
        confidence=0.0,
        entry_style="none",
        scaling_allowed=False,
        justification="synthetic diagnostic fixture",
    )
    verdict = RiskVerdict(
        decision_id=decision_id,
        action=action,
        reason=verdict_reason,
        halts_engaged=halts,
        findings=findings,
    )
    journal = TradeJournalRecord(
        trade_id="trade-independent-001",
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
    read_view: dict[str, object] = {
        "decision_id": decision_id,
        "status": "blocked",
        "stage": "blocked",
        "final": True,
        "assessment": verdict.model_dump(mode="json"),
        "authorization": {"operator": ACCOUNT_CANARY, "credential_ref": CREDENTIAL_CANARY},
        "paper_draft": {"raw_strategy_payload": SECRET_CANARY},
        "policy_digest": POLICY_DIGEST,
        "outcome": {"kind": "pre_sim_block", "journal_outcome": "blocked"},
        "final_verdict": verdict.model_dump(mode="json"),
        "journal_record": journal.model_dump(mode="json"),
    }
    return pipeline, verdict, journal, read_view


def _build():
    return build_risk_evidence_export(*_case())


def _projection_digests(result) -> dict[str, str]:
    return {item.source.value: item.digest for item in result.records[0].projection_digests}


def _risk_verdict_projection_digest(result) -> str:
    record = result.records[0]
    projection = {
        "schema": "risk.evidence.risk_verdict.projection.v1",
        "decision_ref": record.decision_ref,
        "outcome": record.outcome.value,
        "risk_findings": tuple(item.value for item in record.risk_findings),
        "halt_state": record.halt_state,
        "halt_reason_codes": record.halt_reason_codes,
    }
    return sha256(canonical_json(projection)).hexdigest()


def _trade_journal_projection_digest(result) -> str:
    record = result.records[0]
    projection = {
        "schema": "risk.evidence.trade_journal.projection.v1",
        "decision_ref": record.decision_ref,
        "journal_outcome": record.journal_outcome.value,
    }
    return sha256(canonical_json(projection)).hexdigest()


def test_export_is_repeatable_redacted_and_labels_c101_as_unsealed() -> None:
    first = serialize_risk_evidence_export(_build())
    second = serialize_risk_evidence_export(_build())

    assert first == second
    payload = json.loads(first)
    assert payload["complete"] is True
    assert len(payload["records"]) == 1
    record = payload["records"][0]
    assert record["provenance"] == RiskEvidenceProvenanceV1.TYPED_UNSEALED.value
    assert (
        record["policy_digest_source"]
        == RiskEvidencePolicyDigestSourceV1.READ_VIEW_UNBOUND.value
    )
    assert record["setup_at_utc"] == AT.isoformat()
    assert [item["source"] for item in record["projection_digests"]] == [
        "RISK_VERDICT",
        "TRADE_JOURNAL",
    ]
    assert record["policy_digest"] == POLICY_DIGEST
    assert record["record_hash"] == payload["head_hash"]
    assert record["provenance"] not in {"SEALED", "SEALED_VERIFIED", "CHAIN_VERIFIED"}
    assert payload["provenance"] == RiskEvidenceProvenanceV1.TYPED_UNSEALED.value
    assert "evidence_refs" not in record

    for excluded in (ACCOUNT_CANARY, SECRET_CANARY, CREDENTIAL_CANARY):
        assert excluded.encode("ascii") not in first


def test_output_contains_only_the_content_minimized_schema() -> None:
    payload = json.loads(serialize_risk_evidence_export(_build()))
    assert set(payload) == {"schema", "complete", "provenance", "records", "head_hash"}
    assert payload["provenance"] == "TYPED_UNSEALED"
    assert set(payload["records"][0]) == {
        "schema",
        "sequence",
        "decision_ref",
        "outcome",
        "journal_outcome",
        "policy_digest",
        "policy_digest_source",
        "risk_findings",
        "halt_state",
        "halt_reason_codes",
        "setup_at_utc",
        "provenance",
        "projection_digests",
        "previous_hash",
        "record_hash",
    }


def test_policy_digest_is_nonzero_and_records_cross_check_provenance() -> None:
    pipeline, verdict, journal, view = _case()
    view["policy_digest"] = "0" * 64
    with pytest.raises(RiskEvidenceExportError) as zero_digest:
        build_risk_evidence_export(pipeline, verdict, journal, view)
    assert zero_digest.value.code == RiskEvidenceErrorCodeV1.POLICY_DIGEST_INVALID.value

    pipeline, verdict, journal, view = _case()
    view["authorization"] = {"policy_digest": POLICY_DIGEST}
    checked = build_risk_evidence_export(pipeline, verdict, journal, view)
    assert (
        checked.records[0].policy_digest_source
        is RiskEvidencePolicyDigestSourceV1.READ_VIEW_CROSS_CHECKED
    )
    assert checked.records[0].provenance is RiskEvidenceProvenanceV1.TYPED_UNSEALED
    assert checked.provenance is RiskEvidenceProvenanceV1.TYPED_UNSEALED

    pipeline, verdict, journal, view = _case()
    unbound = build_risk_evidence_export(pipeline, verdict, journal, view)
    assert (
        unbound.records[0].policy_digest_source
        is RiskEvidencePolicyDigestSourceV1.READ_VIEW_UNBOUND
    )
    assert unbound.records[0].provenance is RiskEvidenceProvenanceV1.TYPED_UNSEALED


def test_provenance_enum_has_no_unreachable_verification_claims() -> None:
    # This slice consumes no risk_limits chain segment, so CHAIN_VERIFIED is not representable.
    assert {item.value for item in RiskEvidenceProvenanceV1} == {"TYPED_UNSEALED"}
    assert "CHAIN_VERIFIED" not in {item.value for item in RiskEvidenceProvenanceV1}


@pytest.mark.parametrize("source_key", ["authorization", "paper_draft"])
def test_policy_digest_must_match_any_embedded_view_digest(source_key: str) -> None:
    pipeline, verdict, journal, view = _case()
    view[source_key] = {"policy_digest": "b" * 64}
    with pytest.raises(RiskEvidenceExportError) as caught:
        build_risk_evidence_export(pipeline, verdict, journal, view)
    assert caught.value.code == RiskEvidenceErrorCodeV1.POLICY_DIGEST_INVALID.value
    assert "b" * 64 not in str(caught.value)


@pytest.mark.parametrize(
    "decision_id",
    [
        "acct_4111111111111111",
        "credential:synthetic-secret-reference",
        "JOHN.SMITH.acct.12345678",
        "tok_live_abcdefghijklmnop",
        "dec_0123456789abc",
        "dec_0123456789AB",
        "dec_",
    ],
)
def test_decision_reference_rejects_non_generated_or_sensitive_ids(decision_id: str) -> None:
    pipeline, verdict, journal, view = _case(decision_id=decision_id)
    with pytest.raises(RiskEvidenceExportError) as caught:
        build_risk_evidence_export(pipeline, verdict, journal, view)
    assert caught.value.code == RiskEvidenceErrorCodeV1.INVALID_INPUT.value
    assert decision_id not in str(caught.value)


def test_generated_decision_reference_is_accepted() -> None:
    pipeline, verdict, journal, view = _case(decision_id="dec_abcdef012345")
    result = build_risk_evidence_export(pipeline, verdict, journal, view)
    assert result.records[0].decision_ref == "dec_abcdef012345"


def test_projection_digest_is_consumer_recomputable_and_tracks_closed_verdict_fields() -> None:
    baseline = build_risk_evidence_export(*_case())
    baseline_digests = _projection_digests(baseline)
    assert baseline_digests["RISK_VERDICT"] == _risk_verdict_projection_digest(baseline)
    assert baseline_digests["TRADE_JOURNAL"] == _trade_journal_projection_digest(baseline)

    changed_action = build_risk_evidence_export(*_case(action=RiskAction.WAIT))
    changed_decision_ref = build_risk_evidence_export(
        *_case(decision_id="dec_abcdef012345")
    )
    changed_finding = build_risk_evidence_export(
        *_case(findings=(GateFinding.LOCK_MISSING,))
    )
    changed_halt = build_risk_evidence_export(
        *_case(action=RiskAction.HALT_ALL_TRADING, halts=("operator_halt",))
    )
    assert _projection_digests(changed_action)["RISK_VERDICT"] != baseline_digests["RISK_VERDICT"]
    assert (
        _projection_digests(changed_decision_ref)["RISK_VERDICT"]
        != baseline_digests["RISK_VERDICT"]
    )
    assert (
        _projection_digests(changed_decision_ref)["TRADE_JOURNAL"]
        != baseline_digests["TRADE_JOURNAL"]
    )
    assert _projection_digests(changed_finding)["RISK_VERDICT"] != baseline_digests["RISK_VERDICT"]
    assert _projection_digests(changed_halt)["RISK_VERDICT"] != baseline_digests["RISK_VERDICT"]


def test_free_text_only_verdict_and_journal_differences_leave_projections_unchanged() -> None:
    first = build_risk_evidence_export(*_case())
    second = build_risk_evidence_export(
        *_case(
            verdict_reason="different diagnostic prose with another credential:canary",
            journal_notes="different private notes for account=SECOND-ACCOUNT-CANARY",
        )
    )
    assert _projection_digests(first) == _projection_digests(second)
    assert serialize_risk_evidence_export(first) == serialize_risk_evidence_export(second)


def test_global_kill_without_named_reason_gets_only_export_local_code() -> None:
    pipeline, verdict, journal, view = _case(
        action=RiskAction.HALT_ALL_TRADING,
        findings=(GateFinding.GLOBAL_KILL,),
    )
    result = build_risk_evidence_export(pipeline, verdict, journal, view)
    assert result.records[0].halt_reason_codes == ("GLOBAL_KILL_UNSPECIFIED",)
    assert result.records[0].halt_state is True

    pipeline, verdict, journal, view = _case(
        action=RiskAction.HALT_ALL_TRADING,
        halts=("operator_halt",),
        findings=(GateFinding.GLOBAL_KILL,),
    )
    named = build_risk_evidence_export(pipeline, verdict, journal, view)
    assert named.records[0].halt_reason_codes == ("operator_halt",)
    assert "GLOBAL_KILL_UNSPECIFIED" not in named.records[0].halt_reason_codes


@pytest.mark.parametrize(
    ("outcome", "halt_reason_codes"),
    [
        (RiskAction.REJECT, ("GLOBAL_KILL_UNSPECIFIED",)),
        (
            RiskAction.HALT_ALL_TRADING,
            ("GLOBAL_KILL_UNSPECIFIED", "operator_halt"),
        ),
    ],
)
def test_global_kill_unspecified_is_invalid_outside_its_exact_case(
    outcome: RiskAction, halt_reason_codes: tuple[str, ...]
) -> None:
    payload = json.loads(serialize_risk_evidence_export(_build()))["records"][0]
    payload["schema_version"] = 1
    payload.pop("schema")
    payload["outcome"] = outcome.value
    payload["halt_state"] = True
    payload["halt_reason_codes"] = halt_reason_codes

    with pytest.raises(SealError) as caught:
        RiskEvidenceRecordV1.model_validate_json(json.dumps(payload))
    assert caught.value.code == "SEAL_INVALID_MODEL"


def test_unissued_export_has_no_success_marker() -> None:
    issued = _build()
    unissued = RiskEvidenceExportV1(records=issued.records, head_hash=issued.head_hash)

    with pytest.raises(RiskEvidenceExportError) as caught:
        serialize_risk_evidence_export(unissued)

    assert caught.value.code == RiskEvidenceErrorCodeV1.UNVERIFIED_SEAL.value
    assert str(caught.value) == "UNVERIFIED_SEAL"


def test_tampered_seal_and_broken_hash_link_never_serialize_success() -> None:
    export = _build()
    object.__setattr__(export.records[0], "record_hash", "f" * 64)

    with pytest.raises(RiskEvidenceExportError) as caught:
        serialized = serialize_risk_evidence_export(export)
        pytest.fail(f"tampered chain unexpectedly serialized: {serialized!r}")

    assert caught.value.code in {
        RiskEvidenceErrorCodeV1.UNVERIFIED_SEAL.value,
        RiskEvidenceErrorCodeV1.CHAIN_INVALID.value,
    }
    assert "f" * 64 not in str(caught.value)


def test_unsealed_c101_input_is_revalidated_and_malformed_view_fails_closed() -> None:
    pipeline, verdict, journal, read_view = _case()
    result = build_risk_evidence_export(pipeline, verdict, journal, read_view)
    assert require_risk_evidence_export(result) is result
    assert result.records[0].provenance is RiskEvidenceProvenanceV1.TYPED_UNSEALED

    bad_view = dict(read_view)
    bad_view["final"] = False
    with pytest.raises(RiskEvidenceExportError) as caught:
        build_risk_evidence_export(pipeline, verdict, journal, bad_view)
    assert caught.value.code == RiskEvidenceErrorCodeV1.INCOMPLETE_EVIDENCE.value
    assert "False" not in str(caught.value)
