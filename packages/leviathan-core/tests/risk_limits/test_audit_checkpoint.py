"""Focused signed-checkpoint verification tests using synthetic risk events."""

from __future__ import annotations

import pytest

from leviathan_core.execution.order_models import LedgerIntegrityKey
from leviathan_core.risk_limits.audit_checkpoint import (
    MAX_CHECKPOINT_SUFFIX_ROWS,
    RiskAuditCheckpointError,
    RiskAuditHeadV1,
    RiskAuditScopeV1,
    create_risk_audit_checkpoint,
    verify_suffix_from_checkpoint,
)
from leviathan_core.risk_limits.audit_port import (
    RISK_AUDIT_GENESIS_HASH,
    RiskAuditEventV1,
    _issue_event,
    risk_audit_event_hash,
)
from leviathan_core.seal import SealedModel

KEY = LedgerIntegrityKey(b"risk-audit-checkpoint synthetic unit key 0001")
OTHER_KEY = LedgerIntegrityKey(b"risk-audit-checkpoint synthetic unit key 0002")
SCOPE = RiskAuditScopeV1(environment="paper", account_id="account-a")


def _events() -> tuple[RiskAuditEventV1, ...]:
    result: list[RiskAuditEventV1] = []
    previous = RISK_AUDIT_GENESIS_HASH
    for sequence, (environment, account_id) in enumerate(
        (("paper", "account-a"), ("paper", "account-b"), ("paper", "account-a")),
        start=1,
    ):
        body = {
            "schema_version": 1,
            "sequence": sequence,
            "event_id": "0" * 64,
            "correlation_id": f"corr-{sequence}",
            "attempt_id": f"attempt-{sequence}",
            "actor_ref": f"{sequence:064x}",
            "action": "LIMIT_POLICY_CHANGE",
            "decision": "RECORDED",
            "reason_code": "TEST_FIXTURE",
            "environment": environment,
            "account_id": account_id,
            "scope": "ACCOUNT",
            "before_digest": None,
            "after_digest": None,
            "source_event_ids": (),
            "recorded_at_ns": sequence,
            "predecessor_hash": previous,
            "event_hash": "0" * 64,
        }
        candidate = RiskAuditEventV1(**body)
        event_hash = risk_audit_event_hash(candidate, previous)
        body["event_id"] = event_hash
        body["event_hash"] = event_hash
        result.append(_issue_event(**body))
        previous = event_hash
    return tuple(result)


def _head(events: tuple[RiskAuditEventV1, ...], sequence: int) -> RiskAuditHeadV1:
    return RiskAuditHeadV1(
        sequence=sequence,
        head_hash=RISK_AUDIT_GENESIS_HASH if sequence == 0 else events[sequence - 1].event_hash,
    )


def test_checkpoint_derives_key_identity_but_core_result_is_unissued() -> None:
    events = _events()
    checkpoint = create_risk_audit_checkpoint(events[:1], key=KEY, scope=SCOPE)
    same_key_checkpoint = create_risk_audit_checkpoint(events[:1], key=KEY, scope=SCOPE)
    same_material = LedgerIntegrityKey(b"risk-audit-checkpoint synthetic unit key 0001")
    same_material_checkpoint = create_risk_audit_checkpoint(
        events[:1], key=same_material, scope=SCOPE
    )
    other_key_checkpoint = create_risk_audit_checkpoint(events[:1], key=OTHER_KEY, scope=SCOPE)

    assert checkpoint.key_id == same_key_checkpoint.key_id == same_material_checkpoint.key_id
    assert checkpoint.signature == same_material_checkpoint.signature
    assert checkpoint.key_id != other_key_checkpoint.key_id
    assert checkpoint.signature != other_key_checkpoint.signature

    candidate = verify_suffix_from_checkpoint(
        checkpoint,
        events[1:],
        supplied_head=_head(events, 3),
        key=KEY,
        scope=SCOPE,
    )
    assert not isinstance(candidate, SealedModel)
    assert tuple(item.sequence for item in candidate.events) == (3,)
    assert candidate.supplied_head == _head(events, 3)


@pytest.mark.parametrize(
    ("checkpoint_update", "key", "scope", "head_sequence"),
    [
        ({"signature": "0" * 64}, KEY, SCOPE, 3),
        ({}, OTHER_KEY, SCOPE, 3),
        ({}, KEY, RiskAuditScopeV1(environment="live", account_id="account-a"), 3),
        ({}, KEY, SCOPE, 0),
        ({"schema_version": 2}, KEY, SCOPE, 3),
        ({"environment": "live"}, KEY, SCOPE, 3),
        ({"account_id": "account-b"}, KEY, SCOPE, 3),
        ({"sequence": 2}, KEY, SCOPE, 3),
        ({"head_hash": "f" * 64}, KEY, SCOPE, 3),
        ({"key_id": "f" * 64}, KEY, SCOPE, 3),
    ],
)
def test_invalid_checkpoint_signature_key_scope_schema_and_future_are_content_free(
    checkpoint_update: dict[str, object],
    key: LedgerIntegrityKey,
    scope: RiskAuditScopeV1,
    head_sequence: int,
) -> None:
    events = _events()
    checkpoint = create_risk_audit_checkpoint(events[:1], key=KEY, scope=SCOPE)
    if checkpoint_update:
        checkpoint = checkpoint.model_copy(update=checkpoint_update)
    with pytest.raises(RiskAuditCheckpointError) as caught:
        verify_suffix_from_checkpoint(
            checkpoint,
            events[1:] if head_sequence == 3 else (),
            supplied_head=_head(events, head_sequence),
            key=key,
            scope=scope,
        )
    assert str(caught.value) == "CHECKPOINT_INVALID"
    assert caught.value.__context__ is None
    assert caught.value.__cause__ is None


@pytest.mark.parametrize(
    ("rows", "head_sequence"),
    [
        ((2, 1, 3), 3),  # reorder
        ((3,), 3),  # missing first suffix row
        ((2,), 3),  # truncated suffix
        ((), 3),  # missing suffix
    ],
)
def test_reordered_missing_or_truncated_suffix_is_rejected(
    rows: tuple[int, ...], head_sequence: int
) -> None:
    events = _events()
    checkpoint = create_risk_audit_checkpoint(events[:1], key=KEY, scope=SCOPE)
    with pytest.raises(RiskAuditCheckpointError):
        verify_suffix_from_checkpoint(
            checkpoint,
            tuple(events[index - 1] for index in rows),
            supplied_head=_head(events, head_sequence),
            key=KEY,
            scope=SCOPE,
        )


def test_head_mismatch_unissued_event_and_core_candidate_fail_closed() -> None:
    events = _events()
    checkpoint = create_risk_audit_checkpoint(events[:1], key=KEY, scope=SCOPE)
    with pytest.raises(RiskAuditCheckpointError):
        verify_suffix_from_checkpoint(
            checkpoint,
            events[1:],
            supplied_head=RiskAuditHeadV1(sequence=3, head_hash="f" * 64),
            key=KEY,
            scope=SCOPE,
        )
    unissued = RiskAuditEventV1.model_validate(events[1].model_dump(mode="python"))
    with pytest.raises(RiskAuditCheckpointError):
        verify_suffix_from_checkpoint(
            checkpoint,
            (unissued, events[2]),
            supplied_head=_head(events, 3),
            key=KEY,
            scope=SCOPE,
        )
    candidate = verify_suffix_from_checkpoint(
        checkpoint,
        events[1:],
        supplied_head=_head(events, 3),
        key=KEY,
        scope=SCOPE,
    )
    assert not isinstance(candidate, SealedModel)


def test_core_verifier_rejects_suffix_above_declared_bound() -> None:
    events = _events()
    checkpoint = create_risk_audit_checkpoint((), key=KEY, scope=SCOPE)
    oversized = events * ((MAX_CHECKPOINT_SUFFIX_ROWS // len(events)) + 1)
    with pytest.raises(RiskAuditCheckpointError) as caught:
        verify_suffix_from_checkpoint(
            checkpoint,
            oversized,
            supplied_head=_head(events, 3),
            key=KEY,
            scope=SCOPE,
        )
    assert str(caught.value) == "CHECKPOINT_INVALID"


def test_genesis_checkpoint_verifies_complete_chain_and_head() -> None:
    events = _events()
    checkpoint = create_risk_audit_checkpoint((), key=KEY, scope=SCOPE)
    assert checkpoint.sequence == 0
    assert checkpoint.head_hash == RISK_AUDIT_GENESIS_HASH
    result = verify_suffix_from_checkpoint(
        checkpoint,
        events,
        supplied_head=_head(events, 3),
        key=KEY,
        scope=SCOPE,
    )
    assert tuple(event.sequence for event in result.events) == (1, 3)


def test_checkpoint_prefix_must_be_global_contiguous_genesis_history() -> None:
    events = _events()
    with pytest.raises(RiskAuditCheckpointError):
        create_risk_audit_checkpoint((events[1],), key=KEY, scope=SCOPE)
    with pytest.raises(RiskAuditCheckpointError):
        create_risk_audit_checkpoint((events[0], events[2]), key=KEY, scope=SCOPE)
