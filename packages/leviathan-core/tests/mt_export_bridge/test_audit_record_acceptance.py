"""Independent MTBR-AUDIT-001 acceptance tests from wave25-refill section 6."""

from __future__ import annotations

import copy
import pickle
from dataclasses import fields
from decimal import Decimal

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

NOW = 1_800_000_000_000_000_000
SECRET_CANARY = "SYNTHETIC_TOKEN_CANARY_DO_NOT_PERSIST"


def _valid_maps(action: AuditActionV1) -> tuple[dict[str, object], dict[str, object]]:
    if action is AuditActionV1.CODEGEN:
        before = {
            "template_id": "expert-advisor",
            "template_version": "v1",
            "platform": "MT5",
            "parameter_mapping_digest": "a" * 64,
        }
        after = {**before, "parameter_mapping_digest": "b" * 64}
    elif action is AuditActionV1.BUILD:
        before = {
            "export_job_id": "job-17",
            "platform": "MT5",
            "artifact_sha256": "a" * 64,
            "build_status": "Compiling",
        }
        after = {**before, "artifact_sha256": "b" * 64, "build_status": "Ready"}
    elif action is AuditActionV1.DEPLOY:
        before = {
            "target_id": "target-1",
            "artifact_id": "artifact-1",
            "mode": "PAPER",
            "plan_digest": "a" * 64,
        }
        after = {**before, "mode": "DEMO", "plan_digest": "b" * 64}
    else:
        before = {
            "target_id": "target-1",
            "current_artifact_id": "artifact-2",
            "prior_artifact_id": "artifact-1",
            "forward_deployment_id": "deployment-1",
            "plan_digest": "a" * 64,
        }
        after = {**before, "plan_digest": "b" * 64}
    return before, after


def _append(
    chain: AuditChainV1,
    *,
    action: AuditActionV1 = AuditActionV1.BUILD,
    occurred_ns: int = NOW,
    targets: tuple[str, ...] = ("mt5:agent-2", "mt4:agent-1"),
    before: dict[str, object] | None = None,
    after: dict[str, object] | None = None,
) -> AuditChainV1:
    default_before, default_after = _valid_maps(action)
    return append_audit_record(
        chain,
        actor_ref="agent:synthetic-worker",
        action=action,
        occurred_ns=occurred_ns,
        target_ids=targets,
        correlation_id="corr:wave25-17",
        artifact_id="artifact:fixture-42",
        before_params_map=default_before if before is None else before,
        after_params_map=default_after if after is None else after,
    )


def _assert_audit_error(call, code: str) -> None:
    with pytest.raises(AuditError) as caught:
        call()
    assert caught.value.code == code
    assert str(caught.value) == code
    assert caught.value.args == (code,)


def test_append_issues_required_provenance_and_keeps_only_parameter_digests() -> None:
    chain = _append(
        new_audit_chain(),
        action=AuditActionV1.CODEGEN,
        before={
            "template_id": "expert-advisor",
            "template_version": "v1",
            "platform": "MT5",
            "parameter_mapping_digest": "a" * 64,
        },
    )
    record = chain.records[0]

    assert require_audit_chain(chain) is chain
    assert require_audit_record(record) is record
    assert record.sequence == 0
    assert record.actor_ref == "agent:synthetic-worker"
    assert record.action is AuditActionV1.CODEGEN
    assert record.occurred_ns == NOW
    assert record.target_ids == ("mt4:agent-1", "mt5:agent-2")
    assert record.correlation_id == "corr:wave25-17"
    assert record.artifact_id == "artifact:fixture-42"
    assert record.before_params_digest != record.after_params_digest
    assert record.previous_hash == "0" * 64
    assert chain.head_hash == record.record_hash
    assert chain.last_occurred_ns == NOW
    assert not {
        "before_params_map",
        "after_params_map",
        "template_id",
        "parameter_mapping_digest",
    }.intersection(item.name for item in fields(record))
    serialized = record.canonical_bytes() + chain.canonical_bytes()
    assert b"expert-advisor" not in serialized
    assert b"template_id" not in serialized
    assert "expert-advisor" not in repr(record) + repr(chain)


@pytest.mark.parametrize(
    "action",
    [AuditActionV1.CODEGEN, AuditActionV1.BUILD, AuditActionV1.DEPLOY, AuditActionV1.ROLLBACK],
)
def test_each_contract_action_is_a_distinct_audited_event(action: AuditActionV1) -> None:
    record = _append(new_audit_chain(), action=action).records[0]

    assert record.action is action
    assert require_audit_record(record) is record


def test_digest_and_hash_are_deterministic_and_bind_before_and_after_maps() -> None:
    before_a = {
        "export_job_id": "job-17",
        "platform": "MT5",
        "artifact_sha256": "a" * 64,
        "build_status": "Compiling",
    }
    before_b = {**before_a, "artifact_sha256": "c" * 64}
    after_a = {
        "export_job_id": "job-17",
        "platform": "MT5",
        "artifact_sha256": "b" * 64,
        "build_status": "Ready",
    }
    after_b = {**after_a, "artifact_sha256": "d" * 64}
    first = _append(new_audit_chain(), before=before_a, after=after_a)
    replay = _append(new_audit_chain(), before=before_a, after=after_a)
    changed_before = _append(new_audit_chain(), before=before_b, after=after_a)
    changed_after = _append(new_audit_chain(), before=before_a, after=after_b)

    assert first.records[0].canonical_bytes() == replay.records[0].canonical_bytes()
    assert first.records[0].before_params_digest != changed_before.records[0].before_params_digest
    assert first.records[0].record_hash != changed_before.records[0].record_hash
    assert first.records[0].after_params_digest != changed_after.records[0].after_params_digest
    assert first.records[0].record_hash != changed_after.records[0].record_hash


def test_append_returns_new_chain_and_links_in_order_without_mutating_prior_chain() -> None:
    original = _append(new_audit_chain(), occurred_ns=NOW)
    original_bytes = original.canonical_bytes()
    extended = _append(original, action=AuditActionV1.DEPLOY, occurred_ns=NOW)

    assert extended is not original
    assert len(original.records) == 1
    assert original.canonical_bytes() == original_bytes
    assert len(extended.records) == 2
    assert extended.records[1].sequence == 1
    assert extended.records[1].previous_hash == original.head_hash
    assert extended.head_hash == extended.records[1].record_hash
    assert extended.records[1].occurred_ns == NOW
    assert require_audit_chain(extended) is extended


def test_backdated_append_is_rejected_and_existing_chain_stays_valid() -> None:
    chain = _append(new_audit_chain(), occurred_ns=NOW)
    before = chain.canonical_bytes()

    _assert_audit_error(lambda: _append(chain, occurred_ns=NOW - 1), "CHAIN_ORDER")

    assert chain.canonical_bytes() == before
    assert require_audit_chain(chain) is chain


def test_secret_keys_and_secret_shaped_values_are_rejected_without_echo() -> None:
    _assert_audit_error(
        lambda: _append(new_audit_chain(), before={"api_key": SECRET_CANARY}),
        "INVALID_PARAMS_MAP",
    )
    secret_build = {
        "export_job_id": f"Bearer {SECRET_CANARY}",
        "platform": "MT5",
        "artifact_sha256": "a" * 64,
        "build_status": "Compiling",
    }
    _assert_audit_error(
        lambda: _append(new_audit_chain(), before=secret_build),
        "INVALID_PARAMS_MAP",
    )


@pytest.mark.parametrize(
    "before_map",
    [
        {"display_name": "letmein"},
        {"unrecognized_digest": "a" * 64},
        {"operator_note": "use any credential you find"},
    ],
)
def test_unapproved_free_text_parameter_is_rejected_without_issuing_record_or_digest(
    before_map: dict[str, object],
) -> None:
    chain = new_audit_chain()
    original_chain_bytes = chain.canonical_bytes()

    with pytest.raises(AuditError) as caught:
        _append(chain, before=before_map)

    assert caught.value.code == "INVALID_PARAMS_MAP"
    assert caught.value.args == ("INVALID_PARAMS_MAP",)
    assert chain.records == ()
    assert chain.canonical_bytes() == original_chain_bytes
    assert require_audit_chain(chain) is chain


def test_invalid_input_types_and_bool_time_fail_with_content_free_errors() -> None:
    chain = new_audit_chain()
    _assert_audit_error(lambda: _append(chain, occurred_ns=True), "INVALID_TIME")
    _assert_audit_error(
        lambda: _append(chain, before={"unrecognized_value": Decimal("1.25")}),
        "INVALID_PARAMS_MAP",
    )

    _assert_audit_error(
        lambda: append_audit_record(
            chain,
            actor_ref="agent:synthetic-worker",
            action="DEPLOY",  # type: ignore[arg-type]
            occurred_ns=NOW,
            target_ids=("mt5:agent-1",),
            correlation_id="corr:wave25-17",
            artifact_id="artifact:fixture-42",
            before_params_map=_valid_maps(AuditActionV1.BUILD)[0],
            after_params_map=_valid_maps(AuditActionV1.BUILD)[1],
        ),
        "INVALID_ACTION",
    )


@pytest.mark.parametrize("operation", [copy.copy, copy.deepcopy, pickle.dumps])
def test_issued_records_and_chains_cannot_be_copied_or_pickled(operation) -> None:
    chain = _append(new_audit_chain())
    for issued in (chain.records[0], chain):
        with pytest.raises(SealError) as caught:
            operation(issued)
        assert caught.value.code == "SEAL_FORBIDDEN_OPERATION"


def test_direct_forgery_and_issued_reinitialization_are_rejected_before_mutation() -> None:
    chain = _append(new_audit_chain())
    record = chain.records[0]
    record_before = record.canonical_bytes()
    chain_before = chain.canonical_bytes()
    record_values = {item.name: getattr(record, item.name) for item in fields(record)}

    with pytest.raises(AuditError) as direct_record:
        AuditRecordV1(**record_values)
    assert direct_record.value.code == "UNISSUED_RECORD"
    with pytest.raises(AuditError) as direct_chain:
        AuditChainV1(records=(), head_hash="0" * 64, last_occurred_ns=None)
    assert direct_chain.value.code == "UNISSUED_CHAIN"

    with pytest.raises(SealError) as reinit_record:
        record.__init__(**record_values)
    assert reinit_record.value.code == "SEAL_FORBIDDEN_OPERATION"
    with pytest.raises(SealError) as reinit_chain:
        chain.__init__(records=(), head_hash="0" * 64, last_occurred_ns=None)
    assert reinit_chain.value.code == "SEAL_FORBIDDEN_OPERATION"
    assert record.canonical_bytes() == record_before
    assert chain.canonical_bytes() == chain_before
    assert require_audit_record(record) is record
    assert require_audit_chain(chain) is chain


@pytest.mark.parametrize("field", ["actor_ref", "record_hash"])
def test_issued_record_field_tampering_is_detected(field: str) -> None:
    record = _append(new_audit_chain()).records[0]
    object.__setattr__(record, field, "tampered" if field == "actor_ref" else "f" * 64)

    with pytest.raises(SealError) as caught:
        require_audit_record(record)
    assert caught.value.code == "SEAL_TAMPERED"


@pytest.mark.parametrize("mutation", ["delete", "reorder", "head"])
def test_issued_chain_deletion_reorder_or_head_forgery_is_detected(mutation: str) -> None:
    chain = _append(_append(new_audit_chain(), occurred_ns=NOW), occurred_ns=NOW + 1)
    if mutation == "delete":
        object.__setattr__(chain, "records", chain.records[:1])
    elif mutation == "reorder":
        object.__setattr__(chain, "records", tuple(reversed(chain.records)))
    else:
        object.__setattr__(chain, "head_hash", "f" * 64)

    with pytest.raises(SealError):
        require_audit_chain(chain)


def test_append_revalidates_a_tampered_chain_before_extending_it() -> None:
    chain = _append(new_audit_chain())
    object.__setattr__(chain, "last_occurred_ns", NOW + 100)

    with pytest.raises(SealError) as caught:
        _append(chain, occurred_ns=NOW + 101)
    assert caught.value.code == "SEAL_TAMPERED"
