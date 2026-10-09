"""Durability and tamper tests for the local MCP audit store."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from leviathan_store.engine import init_sync_schema
from leviathan_store.mcp_audit import McpAuditScopeV1, McpAuditStore, McpAuditStoreError
from leviathan_store.tables import McpAuditHeadRow, McpAuditRow, SchemaMigrationRow
from sqlalchemy import create_engine, delete, inspect, select, text
from sqlalchemy import event as sqlalchemy_event
from sqlalchemy.orm import Session, sessionmaker

from leviathan_core.execution.order_models import LedgerIntegrityKey
from leviathan_core.mcp_control.audit_chain import append_audit_event
from leviathan_core.mcp_control.state_models import AuditEventV1

_KEY = LedgerIntegrityKey(b"synthetic-mcp-audit-test-integrity-key-0001")
_SCOPE = McpAuditScopeV1("leviathan-ai", "PAPER")


@pytest.fixture
def database(tmp_path: Path) -> Iterator[tuple[sessionmaker[Session], Path]]:
    path = tmp_path / "mcp-audit.sqlite"
    engine = create_engine(f"sqlite:///{path}")
    init_sync_schema(engine)
    yield sessionmaker(engine, expire_on_commit=False), path
    engine.dispose()


def _events(count: int) -> tuple[AuditEventV1, ...]:
    events: tuple[AuditEventV1, ...] = ()
    for index in range(count):
        events = append_audit_event(
            events,
            org_id=f"org-{index % 2}",
            agent_id=f"agent-{index % 3}",
            session_id=None,
            action_id=f"action-{index}",
            kind="control.updated",
            reason_codes=("POLICY_ALLOWED",),
            recorded_at_ns=1_800_000_000_000_000_000 + index,
        )
    return events


def _store(
    sessions: sessionmaker[Session],
    *,
    key: LedgerIntegrityKey = _KEY,
    scope: McpAuditScopeV1 = _SCOPE,
) -> McpAuditStore:
    return McpAuditStore(sessions, key=key, scope=scope)


def test_append_is_durable_ordered_and_idempotent_on_reopen(database: Any) -> None:
    sessions, path = database
    events = _events(4)
    store = _store(sessions)
    for event in events:
        assert store.append(event) is None

    reopened_engine = create_engine(f"sqlite:///{path}")
    init_sync_schema(reopened_engine)
    reopened_sessions = sessionmaker(reopened_engine, expire_on_commit=False)
    reopened = _store(reopened_sessions)
    assert reopened.append(events[-1]) is None
    with reopened_sessions() as session:
        rows = tuple(session.scalars(select_rows()))
        head = session.get(McpAuditHeadRow, "mcp-audit-v1")
        migrations = tuple(session.scalars(select(SchemaMigrationRow.version)))
    assert [row.sequence for row in rows] == [0, 1, 2, 3]
    assert [row.event_id for row in rows] == [event.event_id for event in events]
    assert head is not None and head.sequence_count == 4
    assert migrations == ()
    reopened_engine.dispose()


def test_batch_append_is_atomic_and_retry_is_idempotent(database: Any) -> None:
    sessions, _ = database
    store = _store(sessions)
    events = _events(2)
    inserts = 0

    def fail_on_second_insert(_mapper: Any, _connection: Any, _target: McpAuditRow) -> None:
        nonlocal inserts
        inserts += 1
        if inserts == 2:
            raise RuntimeError("synthetic mid-batch failure canary")

    sqlalchemy_event.listen(McpAuditRow, "before_insert", fail_on_second_insert)
    try:
        with pytest.raises(McpAuditStoreError) as error:
            store.append_batch(events)
    finally:
        sqlalchemy_event.remove(McpAuditRow, "before_insert", fail_on_second_insert)

    assert error.value.code == "AUDIT_STORE_UNAVAILABLE"
    assert "synthetic mid-batch failure canary" not in str(error.value)
    with sessions() as session:
        assert tuple(session.scalars(select_rows())) == ()
        head = session.get(McpAuditHeadRow, "mcp-audit-v1")
        assert head is not None and head.sequence_count == 0

    store.append_batch(events)
    store.append_batch(events)
    with sessions() as session:
        rows = tuple(session.scalars(select_rows()))
        head = session.get(McpAuditHeadRow, "mcp-audit-v1")
    assert [row.event_id for row in rows] == [event.event_id for event in events]
    assert head is not None and head.sequence_count == 2


def test_empty_batch_is_a_transaction_free_noop(database: Any) -> None:
    sessions, _ = database
    store = _store(sessions)
    begin_count = 0

    def count_transaction(_session: Session, _transaction: Any, _connection: Any) -> None:
        nonlocal begin_count
        begin_count += 1

    sqlalchemy_event.listen(Session, "after_begin", count_transaction)
    try:
        assert store.append_batch(()) is None
    finally:
        sqlalchemy_event.remove(Session, "after_begin", count_transaction)

    assert begin_count == 0
    with sessions() as session:
        rows = tuple(session.scalars(select_rows()))
        head = session.get(McpAuditHeadRow, "mcp-audit-v1")
    assert rows == ()
    assert head is not None and head.sequence_count == 0


def test_batch_append_accepts_identical_persisted_prefix_and_rejects_conflict(
    database: Any,
) -> None:
    sessions, _ = database
    store = _store(sessions)
    events = _events(3)
    store.append_batch(events[:2])
    store.append_batch(events)
    store.append_batch(events[:2])
    with sessions() as session:
        rows = tuple(session.scalars(select_rows()))
    assert [row.event_id for row in rows] == [event.event_id for event in events]

    altered = events[0].model_copy(update={"kind": "control.deleted"})
    with pytest.raises(McpAuditStoreError) as error:
        store.append_batch((altered,))
    assert error.value.code == "AUDIT_STORE_UNAVAILABLE"


def test_schema_initialization_registers_tables_without_migration_version() -> None:
    engine = create_engine("sqlite:///:memory:")
    init_sync_schema(engine)
    table_names = set(inspect(engine).get_table_names())
    assert {"mcp_audit_events", "mcp_audit_heads"} <= table_names
    with sessionmaker(engine)() as session:
        assert tuple(session.scalars(select(SchemaMigrationRow.version))) == ()
    engine.dispose()


@pytest.mark.parametrize(
    "mutation",
    [
        "UPDATE mcp_audit_events SET event_json = '{}' WHERE sequence = 1",
        "DELETE FROM mcp_audit_events WHERE sequence = 1",
        "DELETE FROM mcp_audit_events WHERE sequence = 2",
    ],
)
def test_reopen_rejects_mutation_and_truncation(database: Any, mutation: str) -> None:
    sessions, _ = database
    for event in _events(3):
        _store(sessions).append(event)
    with sessions.begin() as session:
        session.execute(text(mutation))
    with pytest.raises(McpAuditStoreError) as error:
        _store(sessions)
    assert error.value.code == "AUDIT_STORE_UNAVAILABLE"
    assert str(error.value) == "AUDIT_STORE_UNAVAILABLE"


def test_reopen_rejects_reordered_rows(database: Any) -> None:
    sessions, _ = database
    for event in _events(3):
        _store(sessions).append(event)
    with sessions.begin() as session:
        rows = tuple(session.scalars(select_rows()))
        first, second = rows[:2]
        first_values = _row_values(first)
        second_values = _row_values(second)
        session.execute(delete(McpAuditRow).where(McpAuditRow.sequence.in_((0, 1))))
        session.add(McpAuditRow(**{**second_values, "sequence": 0}))
        session.add(McpAuditRow(**{**first_values, "sequence": 1}))
    with pytest.raises(McpAuditStoreError):
        _store(sessions)


def test_wrong_key_and_cross_scope_copy_are_rejected(database: Any) -> None:
    sessions, _ = database
    _store(sessions).append(_events(1)[0])
    with pytest.raises(McpAuditStoreError):
        _store(
            sessions,
            key=LedgerIntegrityKey(b"different-synthetic-integrity-key-material"),
        )
    with pytest.raises(McpAuditStoreError):
        _store(sessions, scope=McpAuditScopeV1("other-project", "PAPER"))


@pytest.mark.parametrize(
    ("project_id", "environment"),
    [("../project", "PAPER"), ("UPPER", "PAPER"), ("project", "paper")],
)
def test_scope_uses_closed_project_and_environment_values(
    project_id: str, environment: str
) -> None:
    with pytest.raises(McpAuditStoreError) as error:
        McpAuditScopeV1(project_id, environment)  # type: ignore[arg-type]
    assert error.value.code == "AUDIT_STORE_UNAVAILABLE"


def test_gaps_and_foreign_scope_rows_fail_closed(database: Any) -> None:
    sessions, _ = database
    store = _store(sessions)
    with pytest.raises(McpAuditStoreError):
        store.append(_events(2)[1])
    with sessions.begin() as session:
        row = McpAuditRow(
            sequence=0,
            event_id="0" * 64,
            event_json="{}",
            scope_project_id="other-project",
            scope_environment="PAPER",
            previous_mac="0" * 64,
            row_mac="0" * 64,
        )
        session.add(row)
    with pytest.raises(McpAuditStoreError):
        _store(sessions)


def test_storage_failure_is_content_free(database: Any) -> None:
    sessions, path = database
    store = _store(sessions)
    event = _events(1)[0]
    with sessions.begin() as session:
        session.execute(text("DROP TABLE mcp_audit_events"))
    with pytest.raises(McpAuditStoreError) as error:
        store.append(event)
    assert error.value.code == "AUDIT_STORE_UNAVAILABLE"
    assert str(path) not in str(error.value)
    assert event.action_id not in str(error.value)


def test_failed_commit_is_not_acknowledged_or_persisted(database: Any) -> None:
    sessions, _ = database
    store = _store(sessions)
    audit_event = _events(1)[0]

    def fail_commit(_session: Session) -> None:
        raise RuntimeError("synthetic commit failure canary")

    sqlalchemy_event.listen(Session, "before_commit", fail_commit)
    try:
        with pytest.raises(McpAuditStoreError) as error:
            store.append_batch((audit_event,))
    finally:
        sqlalchemy_event.remove(Session, "before_commit", fail_commit)

    assert error.value.code == "AUDIT_STORE_UNAVAILABLE"
    assert "synthetic commit failure canary" not in str(error.value)
    with sessions() as session:
        assert session.get(McpAuditRow, 0) is None
        head = session.get(McpAuditHeadRow, "mcp-audit-v1")
        assert head is not None and head.sequence_count == 0


def select_rows() -> Any:
    return select(McpAuditRow).order_by(McpAuditRow.sequence)


def _row_values(row: McpAuditRow) -> dict[str, object]:
    return {
        "sequence": row.sequence,
        "event_id": row.event_id,
        "event_json": row.event_json,
        "scope_project_id": row.scope_project_id,
        "scope_environment": row.scope_environment,
        "previous_mac": row.previous_mac,
        "row_mac": row.row_mac,
    }
