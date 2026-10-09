"""Independent black-box acceptance for bounded MCP audit appends."""

from __future__ import annotations

import logging
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest
from leviathan_store.engine import init_sync_schema
from leviathan_store.mcp_audit import McpAuditScopeV1, McpAuditStore, McpAuditStoreError
from leviathan_store.tables import McpAuditHeadRow, McpAuditRow
from sqlalchemy import create_engine, delete, select, text
from sqlalchemy import event as sqlalchemy_event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from leviathan_core.execution.order_models import LedgerIntegrityKey
from leviathan_core.mcp_control.audit_chain import _append_to_verified_prefix, append_audit_event
from leviathan_core.mcp_control.state_models import AuditEventV1

_KEY = LedgerIntegrityKey(b"synthetic-mcp-audit-append-acceptance-key-0001")
_SCOPE = McpAuditScopeV1("acceptance-project", "PAPER")
_OTHER_KEY = LedgerIntegrityKey(b"different-synthetic-mcp-audit-key-0002")
_OTHER_SCOPE = McpAuditScopeV1("other-acceptance-project", "PAPER")


def _make_database(
    path: Path, *, echo: bool = False, hide_parameters: bool = True
) -> tuple[Engine, sessionmaker[Session]]:
    engine = create_engine(
        f"sqlite:///{path.as_posix()}",
        connect_args={"timeout": 5.0},
        echo=echo,
        hide_parameters=hide_parameters,
    )
    init_sync_schema(engine)
    return engine, sessionmaker(engine, expire_on_commit=False)


def _events(count: int, namespace: str = "append-acceptance") -> tuple[AuditEventV1, ...]:
    events: tuple[AuditEventV1, ...] = ()
    for index in range(count):
        events = _append_to_verified_prefix(
            events,
            org_id=f"synthetic-org-{index % 3}",
            agent_id=f"synthetic-agent-{index % 4}",
            session_id=None,
            action_id=f"{namespace}-{index}",
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


def _rows(sessions: sessionmaker[Session]) -> tuple[McpAuditRow, ...]:
    with sessions() as session:
        return tuple(session.scalars(select(McpAuditRow).order_by(McpAuditRow.sequence)))


def _head(sessions: sessionmaker[Session]) -> McpAuditHeadRow:
    with sessions() as session:
        head = session.get(McpAuditHeadRow, "mcp-audit-v1")
    assert head is not None
    return head


def _reopen(
    path: Path,
    *,
    key: LedgerIntegrityKey = _KEY,
    scope: McpAuditScopeV1 = _SCOPE,
) -> tuple[Engine, sessionmaker[Session], McpAuditStore]:
    engine, sessions = _make_database(path)
    return engine, sessions, _store(sessions, key=key, scope=scope)


def test_atomic_batch_failure_rolls_back_and_same_batch_retries_once(
    tmp_path: Path,
) -> None:
    engine, sessions = _make_database(tmp_path / "atomic.sqlite")
    try:
        store = _store(sessions)
        batch = _events(3, "atomic-synthetic")
        with engine.begin() as connection:
            connection.exec_driver_sql(
                """
                CREATE TRIGGER synthetic_fail_second_row
                BEFORE INSERT ON mcp_audit_events
                WHEN NEW.sequence = 1
                BEGIN SELECT RAISE(ABORT, 'synthetic-rollback-canary'); END;
                """
            )

        with pytest.raises(McpAuditStoreError) as raised:
            store.append_batch(batch)
        assert raised.value.code == "AUDIT_STORE_UNAVAILABLE"
        assert "synthetic-rollback-canary" not in str(raised.value)
        assert len(_rows(sessions)) == 0
        assert _head(sessions).sequence_count == 0

        with engine.begin() as connection:
            connection.exec_driver_sql("DROP TRIGGER synthetic_fail_second_row")
        store.append_batch(batch)
        store.append_batch(batch)
        rows = _rows(sessions)
        assert [row.event_id for row in rows] == [event.event_id for event in batch]
        assert _head(sessions).sequence_count == len(batch)
    finally:
        engine.dispose()


def test_event_id_is_idempotent_and_conflicting_content_fails_closed(
    tmp_path: Path,
) -> None:
    engine, sessions = _make_database(tmp_path / "idempotency.sqlite")
    try:
        store = _store(sessions)
        event = _events(1, "idempotency-synthetic")[0]
        store.append(event)
        store.append(event)
        assert len(_rows(sessions)) == 1

        altered = event.model_copy(update={"kind": "control.deleted"})
        with pytest.raises(McpAuditStoreError) as raised:
            store.append(altered)
        assert raised.value.code == "AUDIT_STORE_UNAVAILABLE"
        assert _head(sessions).sequence_count == 1
        assert len(_rows(sessions)) == 1
    finally:
        engine.dispose()


@pytest.mark.parametrize("corruption", ("event", "reorder", "truncate", "row_scope"))
def test_corruption_reorder_truncation_and_foreign_scope_are_rejected_on_reopen(
    tmp_path: Path, corruption: str
) -> None:
    path = tmp_path / f"tamper-{corruption}.sqlite"
    engine, sessions = _make_database(path)
    store = _store(sessions)
    store.append_batch(_events(4, f"tamper-{corruption}"))
    store.verify_chain()

    with sessions.begin() as session:
        if corruption == "event":
            session.execute(
                text("UPDATE mcp_audit_events SET event_json = '{}' WHERE sequence = 1")
            )
        elif corruption == "truncate":
            session.execute(text("DELETE FROM mcp_audit_events WHERE sequence = 3"))
        elif corruption == "row_scope":
            session.execute(
                text(
                    "UPDATE mcp_audit_events SET scope_project_id = 'foreign-project' "
                    "WHERE sequence = 1"
                )
            )
        else:
            first, second = tuple(
                session.scalars(
                    select(McpAuditRow)
                    .where(McpAuditRow.sequence.in_((0, 1)))
                    .order_by(McpAuditRow.sequence)
                )
            )
            first_values = _row_values(first)
            second_values = _row_values(second)
            session.execute(delete(McpAuditRow).where(McpAuditRow.sequence.in_((0, 1))))
            session.add(McpAuditRow(**{**second_values, "sequence": 0}))
            session.add(McpAuditRow(**{**first_values, "sequence": 1}))
    with pytest.raises(McpAuditStoreError) as audit_error:
        store.verify_chain()
    assert audit_error.value.code == "AUDIT_STORE_UNAVAILABLE"
    engine.dispose()

    reopened_engine, reopened_sessions = _make_database(path)
    try:
        with pytest.raises(McpAuditStoreError) as raised:
            _store(reopened_sessions)
        assert raised.value.code == "AUDIT_STORE_UNAVAILABLE"
        assert str(raised.value) == "AUDIT_STORE_UNAVAILABLE"
    finally:
        reopened_engine.dispose()


@pytest.mark.parametrize("mismatch", ("wrong_key", "wrong_scope"))
def test_wrong_key_and_cross_scope_database_are_rejected_on_reopen(
    tmp_path: Path, mismatch: str
) -> None:
    path = tmp_path / f"scope-{mismatch}.sqlite"
    engine, sessions = _make_database(path)
    _store(sessions).append_batch(_events(2, f"scope-{mismatch}"))
    engine.dispose()

    reopened_engine, reopened_sessions = _make_database(path)
    try:
        kwargs: dict[str, object] = (
            {"key": _OTHER_KEY} if mismatch == "wrong_key" else {"scope": _OTHER_SCOPE}
        )
        with pytest.raises(McpAuditStoreError) as raised:
            _store(reopened_sessions, **kwargs)  # type: ignore[arg-type]
        assert raised.value.code == "AUDIT_STORE_UNAVAILABLE"
    finally:
        reopened_engine.dispose()


def test_wipe_and_rollback_limit_is_explicit_and_reproduced(tmp_path: Path) -> None:
    path = tmp_path / "no-external-anchor.sqlite"
    engine, sessions = _make_database(path)
    store = _store(sessions)
    events = _events(3, "anchor-limit-synthetic")
    store.append_batch(events[:2])
    engine.dispose()

    # Restoring a genuine earlier rows-plus-head snapshot is internally valid;
    # this store has no external monotonic anchor with which to detect rollback.
    import shutil

    snapshot = tmp_path / "earlier-valid-snapshot.sqlite"
    shutil.copyfile(path, snapshot)
    rollback_engine, rollback_sessions, _ = _reopen(path)
    try:
        _store(rollback_sessions).append(events[2])
    finally:
        rollback_engine.dispose()
    shutil.copyfile(snapshot, path)
    restored_engine, restored_sessions, _ = _reopen(path)
    try:
        assert _head(restored_sessions).sequence_count == 2
        assert len(_rows(restored_sessions)) == 2
    finally:
        restored_engine.dispose()

    # A total wipe is also indistinguishable from a new empty database absent
    # an external anchor. Verify the exact limitation and record it in the QA ledger.
    wiped_engine, wiped_sessions = _make_database(path)
    with wiped_sessions.begin() as session:
        session.execute(delete(McpAuditRow))
        session.execute(delete(McpAuditHeadRow))
    wiped_engine.dispose()
    empty_engine, empty_sessions, _ = _reopen(path)
    try:
        assert _head(empty_sessions).sequence_count == 0
        assert _rows(empty_sessions) == ()
    finally:
        empty_engine.dispose()


def test_concurrent_identical_writers_serialize_without_duplicate_rows(
    tmp_path: Path,
) -> None:
    path = tmp_path / "concurrent-replay.sqlite"
    setup_engine, setup_sessions = _make_database(path)
    store = _store(setup_sessions)
    event = _events(1, "concurrent-identical-synthetic")[0]
    second_engine, second_sessions = _make_database(path)
    second_store = _store(second_sessions)
    barrier = threading.Barrier(2)

    def append_after_barrier(candidate: McpAuditStore) -> None:
        barrier.wait(timeout=5)
        candidate.append(event)

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [
                pool.submit(append_after_barrier, store),
                pool.submit(append_after_barrier, second_store),
            ]
            for future in futures:
                future.result(timeout=10)
    finally:
        setup_engine.dispose()
        second_engine.dispose()

    reopened_engine, reopened_sessions, _ = _reopen(path)
    try:
        rows = _rows(reopened_sessions)
        assert len(rows) == 1
        assert rows[0].event_id == event.event_id
        assert _head(reopened_sessions).sequence_count == 1
    finally:
        reopened_engine.dispose()


def test_append_waits_for_an_existing_begin_immediate_writer_lock(
    tmp_path: Path,
) -> None:
    path = tmp_path / "begin-immediate-contention.sqlite"
    lock_engine, _lock_sessions = _make_database(path)
    writer_engine, writer_sessions = _make_database(path)
    store = _store(writer_sessions)
    lock_connection = lock_engine.connect()
    lock_connection.exec_driver_sql("BEGIN IMMEDIATE")
    begin_attempted = threading.Event()
    finished = threading.Event()

    def notice_begin(
        _connection: Any,
        _cursor: Any,
        statement: str,
        _parameters: Any,
        _context: Any,
        _executemany: bool,
    ) -> None:
        if "begin immediate" in statement.casefold():
            begin_attempted.set()

    sqlalchemy_event.listen(writer_engine, "before_cursor_execute", notice_begin)

    def append_event() -> None:
        try:
            store.append(_events(1, "lock-contention-synthetic")[0])
        finally:
            finished.set()

    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(append_event)
            assert begin_attempted.wait(timeout=3)
            assert not finished.wait(timeout=0.1)
            lock_connection.commit()
            future.result(timeout=8)
    finally:
        sqlalchemy_event.remove(writer_engine, "before_cursor_execute", notice_begin)
        if lock_connection.in_transaction():
            lock_connection.exec_driver_sql("ROLLBACK")
        lock_connection.close()
        lock_engine.dispose()
        writer_engine.dispose()

    reopened_engine, reopened_sessions, _ = _reopen(path)
    try:
        assert _head(reopened_sessions).sequence_count == 1
        assert len(_rows(reopened_sessions)) == 1
    finally:
        reopened_engine.dispose()


def test_distinct_concurrent_same_sequence_does_not_fork_chain(tmp_path: Path) -> None:
    path = tmp_path / "concurrent-conflict.sqlite"
    first_engine, first_sessions = _make_database(path)
    first_store = _store(first_sessions)
    second_engine, second_sessions = _make_database(path)
    second_store = _store(second_sessions)
    first_event = _events(1, "concurrent-winner-a")[0]
    second_event = _events(1, "concurrent-winner-b")[0]
    barrier = threading.Barrier(2)

    def append_after_barrier(candidate: McpAuditStore, candidate_event: AuditEventV1) -> str:
        barrier.wait(timeout=5)
        try:
            candidate.append(candidate_event)
            return "accepted"
        except McpAuditStoreError:
            return "rejected"

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = (
                pool.submit(append_after_barrier, first_store, first_event),
                pool.submit(append_after_barrier, second_store, second_event),
            )
            results = [future.result(timeout=10) for future in futures]
    finally:
        first_engine.dispose()
        second_engine.dispose()

    assert sorted(results) == ["accepted", "rejected"]
    reopened_engine, reopened_sessions, _ = _reopen(path)
    try:
        rows = _rows(reopened_sessions)
        assert len(rows) == 1
        assert rows[0].event_id in {first_event.event_id, second_event.event_id}
        assert _head(reopened_sessions).sequence_count == 1
    finally:
        reopened_engine.dispose()


def test_append_reads_constant_rows_across_chain_sizes(tmp_path: Path) -> None:
    row_reads_by_size: dict[int, int] = {}
    event_queries_by_size: dict[int, int] = {}
    statement_counts_by_size: dict[int, int] = {}

    for size in (10, 100, 500, 1_000):
        engine, sessions = _make_database(tmp_path / f"bounded-{size}.sqlite")
        store = _store(sessions)
        all_events = _events(size + 1, f"bounded-{size}-synthetic")
        store.append_batch(all_events[:size])
        counts = {"rows": 0, "event_selects": 0, "statements": 0}

        def count_loaded_row(
            _session: Session, instance: object, counts: dict[str, int] = counts
        ) -> None:
            if isinstance(instance, McpAuditRow):
                counts["rows"] += 1

        def count_sql(
            _connection: Any,
            _cursor: Any,
            statement: str,
            _parameters: Any,
            _context: Any,
            _executemany: bool,
            counts: dict[str, int] = counts,
        ) -> None:
            normalized = statement.casefold()
            counts["statements"] += 1
            if "select" in normalized and "mcp_audit_events" in normalized:
                counts["event_selects"] += 1
                assert "where" in normalized, "append issued an unbounded audit-row scan"

        sqlalchemy_event.listen(Session, "loaded_as_persistent", count_loaded_row)
        sqlalchemy_event.listen(engine, "before_cursor_execute", count_sql)
        try:
            store.append(all_events[size])
        finally:
            sqlalchemy_event.remove(Session, "loaded_as_persistent", count_loaded_row)
            sqlalchemy_event.remove(engine, "before_cursor_execute", count_sql)
            engine.dispose()

        row_reads_by_size[size] = counts["rows"]
        event_queries_by_size[size] = counts["event_selects"]
        statement_counts_by_size[size] = counts["statements"]

    assert max(row_reads_by_size.values()) <= 2
    assert max(event_queries_by_size.values()) <= 3
    assert max(statement_counts_by_size.values()) <= 12
    assert max(row_reads_by_size.values()) - min(row_reads_by_size.values()) <= 2
    assert max(statement_counts_by_size.values()) - min(statement_counts_by_size.values()) <= 2


def test_append_uses_begin_immediate_and_engine_has_durable_sqlite_pragmas(
    tmp_path: Path,
) -> None:
    engine, sessions = _make_database(tmp_path / "pragmas.sqlite")
    store = _store(sessions)
    statements: list[str] = []

    def capture_sql(
        _connection: Any,
        _cursor: Any,
        statement: str,
        _parameters: Any,
        _context: Any,
        _executemany: bool,
    ) -> None:
        statements.append(statement.casefold())

    sqlalchemy_event.listen(engine, "before_cursor_execute", capture_sql)
    try:
        store.append(_events(1, "begin-immediate-synthetic")[0])
    finally:
        sqlalchemy_event.remove(engine, "before_cursor_execute", capture_sql)

    begins = [index for index, sql in enumerate(statements) if "begin immediate" in sql]
    selects = [index for index, sql in enumerate(statements) if sql.lstrip().startswith("select")]
    assert begins and selects and begins[0] < selects[0]
    with engine.connect() as connection:
        assert connection.exec_driver_sql("PRAGMA journal_mode").scalar_one().casefold() == "delete"
        assert connection.exec_driver_sql("PRAGMA synchronous").scalar_one() == 2
        assert connection.exec_driver_sql("PRAGMA busy_timeout").scalar_one() >= 1_000
    engine.dispose()


def test_echo_engine_does_not_log_event_json(
    caplog: pytest.LogCaptureFixture, tmp_path: Path
) -> None:
    canary = "synthetic-event-json-log-canary"
    event = append_audit_event(
        (),
        org_id="synthetic-org",
        agent_id="synthetic-agent",
        session_id=None,
        action_id=canary,
        kind="control.updated",
        reason_codes=("POLICY_ALLOWED",),
        recorded_at_ns=1_800_000_000_000_000_000,
    )[0]
    caplog.set_level(logging.INFO, logger="sqlalchemy.engine.Engine")
    rejected_engine, rejected_sessions = _make_database(
        tmp_path / "echo-rejected.sqlite", echo=True, hide_parameters=True
    )
    try:
        with pytest.raises(McpAuditStoreError) as raised:
            _store(rejected_sessions)
        assert raised.value.code == "AUDIT_STORE_UNAVAILABLE"
    finally:
        rejected_engine.dispose()

    engine, sessions = _make_database(tmp_path / "echo-disabled.sqlite")
    try:
        _store(sessions).append(event)
        assert canary not in caplog.text
    finally:
        engine.dispose()


def _percentile_95(samples_ns: list[int]) -> float:
    ordered = sorted(samples_ns)
    index = min(len(ordered) - 1, int((len(ordered) - 1) * 0.95))
    return float(ordered[index])


@pytest.mark.skipif(
    os.environ.get("LEVIATHAN_RUN_PERF") != "1",
    reason="wall-clock p95 benchmark is opt-in; default acceptance uses row/query counts",
)
def test_opt_in_append_p95_at_500_is_bounded_vs_10(tmp_path: Path) -> None:
    all_events = _events(530, "opt-in-perf-synthetic")
    p95_by_size: dict[int, float] = {}
    for size in (10, 500):
        engine, sessions = _make_database(tmp_path / f"p95-{size}.sqlite")
        store = _store(sessions)
        store.append_batch(all_events[:size])
        samples: list[int] = []
        try:
            for event in all_events[size : size + 30]:
                started_ns = time.perf_counter_ns()
                store.append(event)
                samples.append(time.perf_counter_ns() - started_ns)
        finally:
            engine.dispose()
        p95_by_size[size] = _percentile_95(samples)

    assert p95_by_size[500] <= 1.5 * p95_by_size[10]
