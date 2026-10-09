"""Independent acceptance checks for the durable MCP audit store."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi import HTTPException
from leviathan_store.engine import init_sync_schema
from leviathan_store.mcp_audit import (
    McpAuditScopeV1,
    McpAuditStore,
    McpAuditStoreError,
)
from leviathan_store.tables import McpAuditHeadRow, McpAuditRow
from sqlalchemy import create_engine, delete, select, text
from sqlalchemy import event as sqlalchemy_event
from sqlalchemy.orm import Session, sessionmaker

from leviathan_api.mcp_runtime_factory import (
    McpRuntimeFactoryConfigV1,
    build_mcp_control,
)
from leviathan_api.routers.mcp_control import McpControlRuntime
from leviathan_core.execution.order_models import LedgerIntegrityKey
from leviathan_core.mcp_control.audit_chain import append_audit_event
from leviathan_core.mcp_control.control_service import (
    empty_control_snapshot,
    record_request_denial,
)
from leviathan_core.mcp_control.state_models import AuditEventV1
from leviathan_core.risk.halt import HaltAuthority

_KEY = LedgerIntegrityKey(b"acceptance-only-mcp-audit-key-material-0001")
_SCOPE = McpAuditScopeV1(project_id="leviathan-ai", environment="PAPER")
_EVENT_CANARY = "private-event-text-canary-7a91"


@pytest.fixture
def audit_database(tmp_path: Path) -> Iterator[tuple[sessionmaker[Session], Path]]:
    database_path = tmp_path / "mcp-audit-acceptance.sqlite"
    engine = create_engine(f"sqlite:///{database_path}")
    init_sync_schema(engine)
    yield sessionmaker(engine, expire_on_commit=False), database_path
    engine.dispose()


def _events(count: int) -> tuple[AuditEventV1, ...]:
    events: tuple[AuditEventV1, ...] = ()
    for sequence in range(count):
        events = append_audit_event(
            events,
            org_id=f"org-{sequence % 2}",
            agent_id=f"agent-{sequence % 3}",
            session_id="session-audit-acceptance",
            action_id=f"action-{sequence}",
            kind="control.updated",
            reason_codes=("POLICY_ALLOWED",),
            recorded_at_ns=1_800_000_000_000_000_000 + sequence,
        )
    return events


def _store(
    sessions: sessionmaker[Session],
    *,
    key: LedgerIntegrityKey = _KEY,
    scope: McpAuditScopeV1 = _SCOPE,
) -> McpAuditStore:
    return McpAuditStore(sessions, key=key, scope=scope)


def _rows(session: Session) -> tuple[McpAuditRow, ...]:
    return tuple(session.scalars(select(McpAuditRow).order_by(McpAuditRow.sequence)))


def test_append_is_scoped_monotonic_durable_and_verifies_on_reopen(
    audit_database: Any,
) -> None:
    sessions, database_path = audit_database
    events = _events(4)
    store = _store(sessions)

    for event_record in events:
        assert store.append(event_record) is None

    # Acknowledgment means the committed rows are visible from a fresh engine.
    reader_engine = create_engine(f"sqlite:///{database_path}")
    try:
        reader_sessions = sessionmaker(reader_engine, expire_on_commit=False)
        with reader_sessions() as session:
            rows = _rows(session)
            head = session.get(McpAuditHeadRow, "mcp-audit-v1")
        assert [row.sequence for row in rows] == [0, 1, 2, 3]
        assert [row.event_id for row in rows] == [item.event_id for item in events]
        assert head is not None and head.sequence_count == len(events)

        reopened = _store(reader_sessions)
        assert reopened.append(events[-1]) is None  # exact replay is idempotent
        with reader_sessions() as session:
            assert len(_rows(session)) == 4
    finally:
        reader_engine.dispose()

    # A skipped sequence is rejected without advancing the durable head.
    with pytest.raises(McpAuditStoreError) as error:
        store.append(_events(6)[5])
    assert error.value.code == "AUDIT_STORE_UNAVAILABLE"
    with sessions() as session:
        head = session.get(McpAuditHeadRow, "mcp-audit-v1")
        assert head is not None and head.sequence_count == 4


def test_batch_append_rolls_back_partway_failure_and_retries_once(
    audit_database: Any,
) -> None:
    sessions, _ = audit_database
    store = _store(sessions)
    batch = _events(2)
    transaction_starts = 0

    def count_transaction_starts(_session: Session, _transaction: Any, _connection: Any) -> None:
        nonlocal transaction_starts
        transaction_starts += 1

    sqlalchemy_event.listen(Session, "after_begin", count_transaction_starts)
    try:
        assert store.append_batch(()) is None
    finally:
        sqlalchemy_event.remove(Session, "after_begin", count_transaction_starts)
    assert transaction_starts == 0
    with sessions() as session:
        assert _rows(session) == ()
        head = session.get(McpAuditHeadRow, "mcp-audit-v1")
        assert head is not None and head.sequence_count == 0

    def fail_before_commit(_session: Session) -> None:
        raise RuntimeError(_EVENT_CANARY)

    sqlalchemy_event.listen(Session, "before_commit", fail_before_commit)
    try:
        with pytest.raises(McpAuditStoreError) as error:
            store.append_batch(batch)
    finally:
        sqlalchemy_event.remove(Session, "before_commit", fail_before_commit)

    assert error.value.code == "AUDIT_STORE_UNAVAILABLE"
    assert str(error.value) == "AUDIT_STORE_UNAVAILABLE"
    with sessions() as session:
        assert _rows(session) == ()
        head = session.get(McpAuditHeadRow, "mcp-audit-v1")
        assert head is not None and head.sequence_count == 0

    store.append_batch(batch)
    store.append_batch(batch)  # exact batch replay is idempotent
    with sessions() as session:
        rows = _rows(session)
        head = session.get(McpAuditHeadRow, "mcp-audit-v1")
    assert [row.sequence for row in rows] == [0, 1]
    assert [row.event_id for row in rows] == [event.event_id for event in batch]
    assert len({row.event_id for row in rows}) == 2
    assert head is not None and head.sequence_count == 2


@pytest.mark.parametrize("tamper", ("mutate", "reorder", "truncate_middle", "truncate_tail"))
def test_reopen_rejects_chain_mutation_reordering_and_truncation(
    audit_database: Any,
    tamper: str,
) -> None:
    sessions, _ = audit_database
    for event_record in _events(4):
        _store(sessions).append(event_record)

    with sessions.begin() as session:
        if tamper == "mutate":
            session.execute(
                text("UPDATE mcp_audit_events SET event_json = '{}' WHERE sequence = 1")
            )
        elif tamper == "reorder":
            session.execute(text("UPDATE mcp_audit_events SET sequence = -1 WHERE sequence = 0"))
            session.execute(text("UPDATE mcp_audit_events SET sequence = 0 WHERE sequence = 1"))
            session.execute(text("UPDATE mcp_audit_events SET sequence = 1 WHERE sequence = -1"))
        else:
            sequence = 1 if tamper == "truncate_middle" else 3
            session.execute(delete(McpAuditRow).where(McpAuditRow.sequence == sequence))

    with pytest.raises(McpAuditStoreError) as error:
        _store(sessions)
    assert error.value.code == "AUDIT_STORE_UNAVAILABLE"
    assert str(error.value) == "AUDIT_STORE_UNAVAILABLE"


def test_reopen_rejects_wrong_key_and_cross_scope_copy(audit_database: Any) -> None:
    sessions, database_path = audit_database
    _store(sessions).append(_events(1)[0])

    with pytest.raises(McpAuditStoreError) as wrong_key:
        _store(
            sessions,
            key=LedgerIntegrityKey(b"different-acceptance-integrity-key-00002"),
        )
    assert wrong_key.value.code == "AUDIT_STORE_UNAVAILABLE"

    foreign_path = Path(database_path).with_name("foreign-peer.sqlite")
    foreign_engine = create_engine(f"sqlite:///{foreign_path}")
    init_sync_schema(foreign_engine)
    try:
        foreign_sessions = sessionmaker(foreign_engine, expire_on_commit=False)
        with sessions() as source, foreign_sessions.begin() as target:
            head = source.get(McpAuditHeadRow, "mcp-audit-v1")
            rows = _rows(source)
            assert head is not None
            target.add(
                McpAuditHeadRow(
                    store_id=head.store_id,
                    scope_project_id=head.scope_project_id,
                    scope_environment=head.scope_environment,
                    sequence_count=head.sequence_count,
                    chain_tip=head.chain_tip,
                    checkpoint_mac=head.checkpoint_mac,
                )
            )
            for row in rows:
                target.add(
                    McpAuditRow(
                        sequence=row.sequence,
                        event_id=row.event_id,
                        event_json=row.event_json,
                        scope_project_id=row.scope_project_id,
                        scope_environment=row.scope_environment,
                        previous_mac=row.previous_mac,
                        row_mac=row.row_mac,
                    )
                )
        with pytest.raises(McpAuditStoreError) as cross_scope:
            _store(
                foreign_sessions,
                scope=McpAuditScopeV1(project_id="other-project", environment="PAPER"),
            )
        assert cross_scope.value.code == "AUDIT_STORE_UNAVAILABLE"
    finally:
        foreign_engine.dispose()


def test_storage_and_commit_failures_are_not_acknowledged_or_leaked(
    audit_database: Any,
    caplog: pytest.LogCaptureFixture,
) -> None:
    sessions, _ = audit_database
    store = _store(sessions)
    event_record = append_audit_event(
        (),
        org_id="org-private",
        agent_id="agent-private",
        session_id="session-private",
        action_id=_EVENT_CANARY,
        kind="control.updated",
        reason_codes=("POLICY_ALLOWED",),
        recorded_at_ns=1_800_000_000_000_000_000,
    )[0]

    def crash_before_commit(_session: Session) -> None:
        raise RuntimeError(_EVENT_CANARY)

    sqlalchemy_event.listen(Session, "before_commit", crash_before_commit)
    try:
        with pytest.raises(McpAuditStoreError) as error:
            store.append(event_record)
    finally:
        sqlalchemy_event.remove(Session, "before_commit", crash_before_commit)

    assert error.value.code == "AUDIT_STORE_UNAVAILABLE"
    assert str(error.value) == "AUDIT_STORE_UNAVAILABLE"
    assert _EVENT_CANARY not in repr(error.value)
    assert _EVENT_CANARY not in caplog.text
    with sessions() as session:
        assert _rows(session) == ()
        head = session.get(McpAuditHeadRow, "mcp-audit-v1")
        assert head is not None and head.sequence_count == 0

    # A later schema/storage error has the same fixed public failure surface.
    with sessions.begin() as session:
        session.execute(text("DROP TABLE mcp_audit_events"))
    with pytest.raises(McpAuditStoreError) as storage_error:
        store.append(event_record)
    assert storage_error.value.code == "AUDIT_STORE_UNAVAILABLE"
    assert _EVENT_CANARY not in str(storage_error.value)
    assert _EVENT_CANARY not in caplog.text


class _UnusedResolver:
    def resolve_verified(self, *_args: object, **_kwargs: object) -> object:
        raise AssertionError("resolver is not used by the commit probe")


def _runtime_with_durable_store(
    sessions: sessionmaker[Session],
) -> tuple[McpControlRuntime, McpAuditStore]:
    store = _store(sessions)
    runtime = McpControlRuntime(
        context_resolver=lambda *_args, **_kwargs: None,
        grants_resolver=lambda *_args, **_kwargs: (),
        attestation_resolver=lambda *_args, **_kwargs: None,
        approval_resolver=lambda *_args, **_kwargs: None,
        halt_authority=HaltAuthority(clock=lambda: 1_800_000_000_000_000_000),
        snapshot=empty_control_snapshot(),
        now_ns=lambda: 1_800_000_000_000_000_000,
    )
    build_mcp_control(
        McpRuntimeFactoryConfigV1(runtime=runtime, resolver=_UnusedResolver(), audit=store)
    )
    return runtime, store


def _denial_snapshot(
    snapshot: Any,
    *,
    count: int,
) -> Any:
    revised = snapshot
    for index in range(count):
        revised = record_request_denial(
            revised,
            org_id="org-atomicity",
            principal_id=f"principal-{index}",
            reason_code="POLICY_DENIED",
            now_ns=1_800_000_000_000_000_000 + index,
        )
    return revised


def test_real_runtime_commit_rolls_back_second_insert_and_retries_exactly_once(
    audit_database: Any,
) -> None:
    sessions, _ = audit_database
    runtime, _store_instance = _runtime_with_durable_store(sessions)
    original_snapshot = runtime.snapshot
    revised = _denial_snapshot(original_snapshot, count=2)
    insert_count = 0

    def fail_second_row_insert(_mapper: object, _connection: object, _row: McpAuditRow) -> None:
        nonlocal insert_count
        insert_count += 1
        if insert_count == 2:
            raise RuntimeError(_EVENT_CANARY)

    sqlalchemy_event.listen(McpAuditRow, "before_insert", fail_second_row_insert)
    try:
        with pytest.raises(HTTPException) as error:
            runtime.commit(revised)
    finally:
        sqlalchemy_event.remove(McpAuditRow, "before_insert", fail_second_row_insert)

    assert error.value.status_code == 503
    assert error.value.detail == "AUDIT_UNAVAILABLE"
    assert error.value.__cause__ is None
    assert runtime.snapshot is original_snapshot
    with sessions() as session:
        assert _rows(session) == ()
        head = session.get(McpAuditHeadRow, "mcp-audit-v1")
        assert head is not None and head.sequence_count == 0

    runtime.commit(revised)
    assert runtime.snapshot == revised
    with sessions() as session:
        rows = _rows(session)
        head = session.get(McpAuditHeadRow, "mcp-audit-v1")
    assert [row.sequence for row in rows] == [0, 1]
    assert [row.event_id for row in rows] == [event.event_id for event in revised.audit_events]
    assert len({row.event_id for row in rows}) == 2
    assert head is not None and head.sequence_count == 2


def test_same_event_id_with_different_content_is_fixed_integrity_error(
    audit_database: Any,
) -> None:
    sessions, _ = audit_database
    store = _store(sessions)
    event_record = _events(1)[0]
    store.append(event_record)
    changed = event_record.model_copy(update={"reason_codes": ("POLICY_DENIED",)})

    with pytest.raises(McpAuditStoreError) as error:
        store.append(changed)

    assert error.value.code == "AUDIT_STORE_UNAVAILABLE"
    assert str(error.value) == "AUDIT_STORE_UNAVAILABLE"
    with sessions() as session:
        rows = _rows(session)
        head = session.get(McpAuditHeadRow, "mcp-audit-v1")
    assert len(rows) == 1
    assert rows[0].event_id == event_record.event_id
    assert head is not None and head.sequence_count == 1
