"""SQLite tests for store-anchored risk-audit checkpoint suffix reads."""

from __future__ import annotations

import pytest
from leviathan_store.risk_limit_events import (
    RISK_LIMITS_METADATA,
    RiskLimitEventStore,
    RiskLimitEventStoreError,
    require_verified_risk_audit_suffix,
    risk_audit_events,
    risk_audit_head,
)
from sqlalchemy import delete, insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

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

pytestmark = pytest.mark.asyncio
KEY = LedgerIntegrityKey(b"risk-audit-checkpoint synthetic store key 0001")
SCOPE = RiskAuditScopeV1(environment="paper", account_id="account-a")


def _events(count: int = 3) -> tuple[RiskAuditEventV1, ...]:
    result: list[RiskAuditEventV1] = []
    previous = RISK_AUDIT_GENESIS_HASH
    for sequence in range(1, count + 1):
        account_id = "account-b" if sequence == 2 or sequence % 23 == 0 else "account-a"
        environment = "paper"
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
        digest = risk_audit_event_hash(RiskAuditEventV1(**body), previous)
        body["event_id"] = digest
        body["event_hash"] = digest
        event = _issue_event(**body)
        result.append(event)
        previous = digest
    return tuple(result)


async def _store_with_rows(events: tuple[RiskAuditEventV1, ...]):
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(RISK_LIMITS_METADATA.create_all)
        if events:
            await connection.execute(
                insert(risk_audit_events),
                [
                    {
                        "sequence": event.sequence,
                        "event_id": event.event_id,
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
                        "source_event_ids": list(event.source_event_ids),
                        "recorded_at_ns": event.recorded_at_ns,
                        "predecessor_hash": event.predecessor_hash,
                        "event_hash": event.event_hash,
                    }
                    for event in events
                ],
            )
        await connection.execute(
            insert(risk_audit_head).values(
                head_id=1,
                sequence=len(events),
                chain_tip=events[-1].event_hash if events else RISK_AUDIT_GENESIS_HASH,
            )
        )
    sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    store = object.__new__(RiskLimitEventStore)
    store._sessions = sessions
    return engine, store


async def test_store_verifies_global_suffix_then_projects_scope_and_keeps_full_replay() -> None:
    events = _events()
    engine, store = await _store_with_rows(events)
    try:
        assert await store.verify_audit_chain() is True
        checkpoint = create_risk_audit_checkpoint(events[:1], key=KEY, scope=SCOPE)
        core_candidate = verify_suffix_from_checkpoint(
            checkpoint,
            events[1:],
            supplied_head=RiskAuditHeadV1(sequence=3, head_hash=events[-1].event_hash),
            key=KEY,
            scope=SCOPE,
        )
        with pytest.raises(RiskAuditCheckpointError) as unissued:
            require_verified_risk_audit_suffix(core_candidate)
        assert str(unissued.value) == "CHECKPOINT_INVALID"
        verified = await store.verify_audit_suffix_from_checkpoint(
            checkpoint,
            supplied_head=RiskAuditHeadV1(sequence=3, head_hash=events[-1].event_hash),
            key=KEY,
            scope=SCOPE,
        )
        assert tuple(item.sequence for item in verified.events) == (3,)
        assert verified.events[0].account_id == "account-a"
        assert require_verified_risk_audit_suffix(verified) is verified
    finally:
        await engine.dispose()


async def test_store_suffix_limit_accepts_256_and_rejects_257_interleaved_rows() -> None:
    events = _events(MAX_CHECKPOINT_SUFFIX_ROWS + 1)
    engine, store = await _store_with_rows(events)
    checkpoint = create_risk_audit_checkpoint((), key=KEY, scope=SCOPE)
    try:
        at_limit = await store.verify_audit_suffix_from_checkpoint(
            checkpoint,
            supplied_head=RiskAuditHeadV1(
                sequence=MAX_CHECKPOINT_SUFFIX_ROWS,
                head_hash=events[MAX_CHECKPOINT_SUFFIX_ROWS - 1].event_hash,
            ),
            key=KEY,
            scope=SCOPE,
        )
        assert len(at_limit.events) == 244
        assert len({event.account_id for event in events[:MAX_CHECKPOINT_SUFFIX_ROWS]}) == 2
        with pytest.raises(RiskLimitEventStoreError) as over_limit:
            await store.verify_audit_suffix_from_checkpoint(
                checkpoint,
                supplied_head=RiskAuditHeadV1(
                    sequence=MAX_CHECKPOINT_SUFFIX_ROWS + 1,
                    head_hash=events[MAX_CHECKPOINT_SUFFIX_ROWS].event_hash,
                ),
                key=KEY,
                scope=SCOPE,
            )
        assert over_limit.value.code == "AUDIT_SUFFIX_LIMIT"
        assert str(over_limit.value) == "AUDIT_SUFFIX_LIMIT"
    finally:
        await engine.dispose()


async def test_unauthenticated_sequence_variants_share_one_fixed_error() -> None:
    events = _events(MAX_CHECKPOINT_SUFFIX_ROWS + 1)
    engine, store = await _store_with_rows(events)
    valid = create_risk_audit_checkpoint((), key=KEY, scope=SCOPE)
    supplied_head = RiskAuditHeadV1(
        sequence=MAX_CHECKPOINT_SUFFIX_ROWS + 1,
        head_hash=events[MAX_CHECKPOINT_SUFFIX_ROWS].event_hash,
    )
    try:
        errors: list[tuple[str, str]] = []
        for sequence in (0, 1):
            junk = valid.model_copy(update={"sequence": sequence, "signature": "0" * 64})
            with pytest.raises(RiskLimitEventStoreError) as caught:
                await store.verify_audit_suffix_from_checkpoint(
                    junk,
                    supplied_head=supplied_head,
                    key=KEY,
                    scope=SCOPE,
                )
            errors.append((caught.value.code, str(caught.value)))
        assert errors == [("AUDIT_CHAIN_INVALID", "AUDIT_CHAIN_INVALID")] * 2
    finally:
        await engine.dispose()


async def test_store_rejects_deleted_checkpoint_anchor_and_preserves_full_chain_failure() -> None:
    events = _events()
    engine, store = await _store_with_rows(events)
    checkpoint = create_risk_audit_checkpoint(events[:2], key=KEY, scope=SCOPE)
    try:
        async with store._sessions() as session, session.begin():
            await session.execute(
                delete(risk_audit_events).where(risk_audit_events.c.sequence == 2)
            )
        with pytest.raises(RiskLimitEventStoreError) as caught:
            await store.verify_audit_suffix_from_checkpoint(
                checkpoint,
                supplied_head=RiskAuditHeadV1(sequence=3, head_hash=events[-1].event_hash),
                key=KEY,
                scope=SCOPE,
            )
        assert caught.value.code == "AUDIT_CHAIN_INVALID"
        assert str(caught.value) == "AUDIT_CHAIN_INVALID"
        assert await store.verify_audit_chain() is False
    finally:
        await engine.dispose()


async def test_store_rejects_future_checkpoint_and_mismatched_supplied_head() -> None:
    events = _events()
    engine, store = await _store_with_rows(events[:2])
    future_checkpoint = create_risk_audit_checkpoint(events, key=KEY, scope=SCOPE)
    valid_checkpoint = create_risk_audit_checkpoint(events[:1], key=KEY, scope=SCOPE)
    try:
        with pytest.raises(RiskLimitEventStoreError) as future:
            await store.verify_audit_suffix_from_checkpoint(
                future_checkpoint,
                supplied_head=RiskAuditHeadV1(sequence=2, head_hash=events[1].event_hash),
                key=KEY,
                scope=SCOPE,
            )
        assert future.value.code == "AUDIT_CHAIN_INVALID"
        with pytest.raises(RiskLimitEventStoreError) as mismatch:
            await store.verify_audit_suffix_from_checkpoint(
                valid_checkpoint,
                supplied_head=RiskAuditHeadV1(sequence=2, head_hash="f" * 64),
                key=KEY,
                scope=SCOPE,
            )
        assert mismatch.value.code == "AUDIT_CHAIN_INVALID"
    finally:
        await engine.dispose()
