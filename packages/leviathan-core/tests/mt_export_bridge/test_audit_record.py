"""Tests for sealed append-only MT export audit records."""

from __future__ import annotations

from dataclasses import fields
from hashlib import sha256

import pytest

from leviathan_core.mt_export_audit import (
    AuditActionV1,
    AuditChainV1,
    AuditError,
    AuditRecordV1,
    append_audit_record,
    new_audit_chain,
    require_audit_chain,
    require_audit_record,
)
from leviathan_core.seal import SealError

_ARTIFACT_DIGEST_A = sha256(b"synthetic build artifact A").hexdigest()
_ARTIFACT_DIGEST_B = sha256(b"synthetic build artifact B").hexdigest()
_PLAN_DIGEST = sha256(b"synthetic action plan").hexdigest()
_PARAMETER_MAPPING_DIGEST = sha256(b"synthetic parameter mapping").hexdigest()


def _params_for_action(action: AuditActionV1, *, variant: str = "A") -> dict[str, object]:
    if action is AuditActionV1.CODEGEN:
        return {
            "template_id": "template-main",
            "template_version": "version-1" if variant == "A" else "version-2",
            "platform": "MT5",
            "parameter_mapping_digest": _PARAMETER_MAPPING_DIGEST,
        }
    if action is AuditActionV1.BUILD:
        return {
            "export_job_id": "job-17",
            "platform": "MT5",
            "artifact_sha256": _ARTIFACT_DIGEST_A if variant == "A" else _ARTIFACT_DIGEST_B,
            "build_status": "Ready",
        }
    if action is AuditActionV1.DEPLOY:
        return {
            "target_id": "target-demo",
            "artifact_id": "artifact-a" if variant == "A" else "artifact-b",
            "mode": "DEMO",
            "plan_digest": _PLAN_DIGEST,
        }
    return {
        "target_id": "target-demo",
        "current_artifact_id": "artifact-current",
        "prior_artifact_id": "artifact-prior-a" if variant == "A" else "artifact-prior-b",
        "forward_deployment_id": "deployment-7",
        "plan_digest": _PLAN_DIGEST,
    }


def _append(
    chain: AuditChainV1,
    *,
    action: AuditActionV1 = AuditActionV1.BUILD,
    occurred_ns: int = 100,
    before: dict[str, object] | None = None,
    after: dict[str, object] | None = None,
) -> AuditChainV1:
    default_before = _params_for_action(action, variant="A")
    default_after = _params_for_action(action, variant="B")
    return append_audit_record(
        chain,
        actor_ref="agent:build-worker",
        action=action,
        occurred_ns=occurred_ns,
        target_ids=("mt5:demo", "mt4:demo"),
        correlation_id="corr-17",
        artifact_id="artifact-42",
        before_params_map=default_before if before is None else before,
        after_params_map=default_after if after is None else after,
    )


def test_append_links_sealed_records_and_digests_parameter_maps_only() -> None:
    chain = _append(
        new_audit_chain(),
        before=_params_for_action(AuditActionV1.BUILD, variant="A"),
        after=_params_for_action(AuditActionV1.BUILD, variant="B"),
    )
    record = chain.records[0]

    assert require_audit_chain(chain) is chain
    assert require_audit_record(record) is record
    assert record.sequence == 0
    assert record.actor_ref == "agent:build-worker"
    assert record.action is AuditActionV1.BUILD
    assert record.occurred_ns == 100
    assert record.target_ids == ("mt4:demo", "mt5:demo")
    assert record.correlation_id == "corr-17"
    assert record.artifact_id == "artifact-42"
    assert record.before_params_digest != record.after_params_digest
    assert record.previous_hash == "0" * 64
    assert chain.head_hash == record.record_hash
    assert not {
        "before_params_map",
        "after_params_map",
        "export_job_id",
        "artifact_sha256",
    }.intersection(item.name for item in fields(record))
    serialized = record.canonical_bytes() + chain.canonical_bytes()
    assert b"export_job_id" not in serialized
    assert _ARTIFACT_DIGEST_A.encode() not in serialized
    assert _ARTIFACT_DIGEST_B.encode() not in serialized


def test_append_is_deterministic_and_extends_previous_hash() -> None:
    first = _append(new_audit_chain())
    replay = _append(new_audit_chain())
    assert first.records[0].canonical_bytes() == replay.records[0].canonical_bytes()

    extended = _append(
        first,
        occurred_ns=101,
        before=_params_for_action(AuditActionV1.BUILD, variant="B"),
        after=_params_for_action(AuditActionV1.BUILD, variant="A"),
    )
    assert len(extended.records) == 2
    assert extended.records[1].sequence == 1
    assert extended.records[1].previous_hash == first.head_hash
    assert extended.head_hash == extended.records[1].record_hash
    assert extended.last_occurred_ns == 101
    assert require_audit_chain(extended) is extended


def test_parameter_map_sensitive_fields_are_rejected_without_echo() -> None:
    marker = "SYNTHETIC_SECRET_CANARY"
    with pytest.raises(AuditError) as caught:
        _append(new_audit_chain(), before={"api_key": marker})
    assert caught.value.code == "INVALID_PARAMS_MAP"
    assert marker not in str(caught.value)
    assert marker not in repr(caught.value.args)

    with pytest.raises(AuditError) as caught_value:
        _append(new_audit_chain(), before={"credential": "irrelevant"})
    assert caught_value.value.code == "INVALID_PARAMS_MAP"
    assert "irrelevant" not in str(caught_value.value)


@pytest.mark.parametrize(
    "before",
    [
        {"display_name": "letmein"},
        {"operator_note": "arbitrary caller text"},
        {"unexpected_digest": _ARTIFACT_DIGEST_A},
    ],
)
def test_unrecognized_or_free_text_parameters_are_rejected_without_digest(
    before: dict[str, object],
) -> None:
    chain = new_audit_chain()
    original = chain.canonical_bytes()
    with pytest.raises(AuditError) as caught:
        _append(chain, before=before)

    assert caught.value.code == "INVALID_PARAMS_MAP"
    assert "letmein" not in str(caught.value)
    assert "arbitrary caller text" not in str(caught.value)
    assert chain.records == ()
    assert chain.canonical_bytes() == original
    assert require_audit_chain(chain) is chain


@pytest.mark.parametrize(
    "action",
    [AuditActionV1.CODEGEN, AuditActionV1.BUILD, AuditActionV1.DEPLOY, AuditActionV1.ROLLBACK],
)
def test_each_action_accepts_only_its_complete_closed_parameter_schema(
    action: AuditActionV1,
) -> None:
    record = _append(new_audit_chain(), action=action).records[0]
    assert record.action is action
    assert require_audit_record(record) is record


def test_bad_action_or_time_is_rejected_with_content_free_codes() -> None:
    chain = new_audit_chain()
    with pytest.raises(AuditError) as bad_action:
        append_audit_record(
            chain,
            actor_ref="agent:one",
            action="LIVE_TRADE",  # type: ignore[arg-type]
            occurred_ns=1,
            target_ids=("mt5:demo",),
            correlation_id="corr-1",
            artifact_id="artifact-1",
            before_params_map={},
            after_params_map={},
        )
    assert bad_action.value.code == "INVALID_ACTION"
    assert "LIVE_TRADE" not in str(bad_action.value)

    with pytest.raises(AuditError) as bad_time:
        _append(chain, occurred_ns=True)
    assert bad_time.value.code == "INVALID_TIME"


def test_direct_construction_and_reinitialization_are_rejected_before_mutation() -> None:
    chain = _append(new_audit_chain())
    record = chain.records[0]
    record_before = record.canonical_bytes()
    chain_before = chain.canonical_bytes()
    record_values = {item.name: getattr(record, item.name) for item in fields(record)}

    with pytest.raises(AuditError) as direct_record:
        AuditRecordV1(**record_values)
    assert direct_record.value.code == "UNISSUED_RECORD"

    with pytest.raises(SealError) as reinit_record:
        record.__init__(**record_values)
    assert reinit_record.value.code == "SEAL_FORBIDDEN_OPERATION"
    assert record.canonical_bytes() == record_before
    assert require_audit_record(record) is record

    with pytest.raises(SealError) as reinit_chain:
        chain.__init__(records=(), head_hash="0" * 64, last_occurred_ns=None)
    assert reinit_chain.value.code == "SEAL_FORBIDDEN_OPERATION"
    assert chain.canonical_bytes() == chain_before
    assert require_audit_chain(chain) is chain


@pytest.mark.parametrize("mutation", ["delete", "reorder"])
def test_chain_tamper_delete_or_reorder_is_detected(mutation: str) -> None:
    chain = _append(new_audit_chain())
    chain = _append(chain, occurred_ns=101)
    changed = chain.records[:1] if mutation == "delete" else tuple(reversed(chain.records))

    object.__setattr__(chain, "records", changed)
    with pytest.raises(SealError) as caught:
        require_audit_chain(chain)
    assert caught.value.code == "SEAL_TAMPERED"


def test_reordered_record_content_is_detected_by_seal() -> None:
    chain = _append(new_audit_chain())
    record = chain.records[0]
    object.__setattr__(record, "actor_ref", "agent:forged")
    with pytest.raises(SealError) as caught:
        require_audit_record(record)
    assert caught.value.code == "SEAL_TAMPERED"
