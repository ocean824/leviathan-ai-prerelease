"""Default correctness checks and opt-in timing for MCP audit append cost."""

from __future__ import annotations

import logging
import math
import os
import threading
import time
from collections.abc import Iterator
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
from leviathan_core.mcp_control.audit_chain import _append_to_verified_prefix
from leviathan_core.mcp_control.state_models import AuditEventV1

_KEY = LedgerIntegrityKey(b"synthetic-mcp-audit-perf-integrity-key-0001")
_SCOPE = McpAuditScopeV1("leviathan-ai", "PAPER")


@pytest.fixture
def database(tmp_path: Path) -> Iterator[tuple[Engine, sessionmaker[Session]]]:
    engine = create_engine(f"sqlite:///{tmp_path / 'mcp-audit-perf.sqlite'}")
    init_sync_schema(engine)
    yield engine, sessionmaker(engine, expire_on_commit=False)
    engine.dispose()


def _events(count: int, prefix: tuple[AuditEventV1, ...] = ()) -> tuple[AuditEventV1, ...]:
    events = prefix
    for index in range(len(prefix), count):
        events = _append_to_verified_prefix(
            events,
            org_id=f"org-{index % 2}",
            agent_id=f"agent-{index % 3}",
            session_id=None,
            action_id=f"perf-action-{index}",
            kind="control.updated",
            reason_codes=("POLICY_ALLOWED",),
            recorded_at_ns=1_800_000_000_000_000_000 + index,
        )
    return events


def _store(sessions: sessionmaker[Session]) -> McpAuditStore:
    return McpAuditStore(sessions, key=_KEY, scope=_SCOPE)


def test_append_reads_only_tail_and_indexed_id(database: Any) -> None:
    engine, sessions = database
    store = _store(sessions)
    events = _events(100)
    reads: list[str] = []
    decoded_rows = 0

    def count_event_reads(
        _connection: Any, _cursor: Any, statement: str, _parameters: Any, _context: Any, _many: bool
    ) -> None:
        if "mcp_audit_events" in statement.lower() and statement.lstrip().lower().startswith(
            "select"
        ):
            reads.append(statement.lower())

    def count_decoded_row(_target: McpAuditRow, _context: Any) -> None:
        nonlocal decoded_rows
        decoded_rows += 1

    sqlalchemy_event.listen(engine, "before_cursor_execute", count_event_reads)
    sqlalchemy_event.listen(McpAuditRow, "load", count_decoded_row)
    per_append: list[int] = []
    rows_per_append: list[int] = []
    try:
        for event in events:
            before = len(reads)
            rows_before = decoded_rows
            store.append(event)
            per_append.append(len(reads) - before)
            rows_per_append.append(decoded_rows - rows_before)
    finally:
        sqlalchemy_event.remove(engine, "before_cursor_execute", count_event_reads)
        sqlalchemy_event.remove(McpAuditRow, "load", count_decoded_row)

    assert max(per_append) <= 2
    assert max(rows_per_append) <= 1
    assert all("order by" not in statement for statement in reads)
    assert len(reads) <= len(events) * 2


def test_explicit_full_verification_detects_middle_row_tampering(database: Any) -> None:
    _engine, sessions = database
    store = _store(sessions)
    store.append_batch(_events(3))
    with sessions.begin() as session:
        session.execute(text("UPDATE mcp_audit_events SET event_json = '{}' WHERE sequence = 1"))
    with pytest.raises(McpAuditStoreError) as error:
        store.verify_chain()
    assert error.value.code == "AUDIT_STORE_UNAVAILABLE"
    assert str(error.value) == "AUDIT_STORE_UNAVAILABLE"


def test_verification_and_reopen_use_consistent_snapshot_during_appends(database: Any) -> None:
    _engine, sessions = database
    store = _store(sessions)
    writer_store = _store(sessions)
    start = threading.Barrier(3)
    writer_done = threading.Event()
    failures: list[str] = []

    def writer() -> None:
        start.wait()
        try:
            for index in range(60):
                writer_store.append(_events(index + 1)[-1])
        except Exception:
            failures.append("writer")
        finally:
            writer_done.set()

    def verifier() -> None:
        start.wait()
        checks = 0
        try:
            while not writer_done.is_set() or checks < 60:
                store.verify_chain()
                checks += 1
                if checks % 10 == 0 and not writer_done.is_set():
                    # Reopen exercises the constructor's full verification path.
                    _store(sessions)
        except Exception:
            failures.append("verifier")

    threads = [threading.Thread(target=writer), threading.Thread(target=verifier)]
    for thread in threads:
        thread.start()
    start.wait()
    for thread in threads:
        thread.join(timeout=20)

    assert all(not thread.is_alive() for thread in threads)
    assert failures == []
    store.verify_chain()
    with sessions() as session:
        head = session.get(McpAuditHeadRow, "mcp-audit-v1")
    assert head is not None and head.sequence_count == 60


@pytest.mark.parametrize("tamper", ["head_mac", "tail_mac", "tail_head_link"])
def test_append_rejects_tampered_authenticated_head_or_tail(database: Any, tamper: str) -> None:
    _engine, sessions = database
    store = _store(sessions)
    prefix = _events(2)
    store.append_batch(prefix)
    with sessions.begin() as session:
        if tamper == "head_mac":
            head = session.get(McpAuditHeadRow, "mcp-audit-v1")
            assert head is not None
            head.checkpoint_mac = "invalid-checkpoint-mac"
        elif tamper == "tail_mac":
            tail = session.get(McpAuditRow, 1)
            assert tail is not None
            tail.row_mac = "invalid-row-mac"
        else:
            tail = session.get(McpAuditRow, 1)
            assert tail is not None
            tail.previous_mac = "validly-authenticated-wrong-link"
            tail.row_mac = store._row_mac(
                sequence=tail.sequence,
                event_id=tail.event_id,
                event_json=tail.event_json,
                previous_mac=tail.previous_mac,
            )

    with pytest.raises(McpAuditStoreError) as error:
        store.append(_events(3, prefix)[-1])
    assert error.value.code == "AUDIT_STORE_UNAVAILABLE"
    assert str(error.value) == "AUDIT_STORE_UNAVAILABLE"


def test_append_rechecks_synchronous_on_the_checked_out_connection(database: Any) -> None:
    engine, sessions = database
    store = _store(sessions)

    def turn_synchronous_off(dbapi_connection: Any, _record: Any, _proxy: Any) -> None:
        dbapi_connection.execute("PRAGMA synchronous=OFF")

    sqlalchemy_event.listen(engine, "checkout", turn_synchronous_off)
    with pytest.raises(McpAuditStoreError) as error:
        store.append(_events(1)[0])
    sqlalchemy_event.remove(engine, "checkout", turn_synchronous_off)
    assert error.value.code == "AUDIT_STORE_UNAVAILABLE"
    with sessions() as session:
        head = session.get(McpAuditHeadRow, "mcp-audit-v1")
        first_row = session.scalar(select(McpAuditRow.sequence).limit(1))
    assert head is not None and head.sequence_count == 0
    assert first_row is None


@pytest.mark.parametrize(
    ("pragma", "value"),
    [("journal_mode", "WAL"), ("synchronous", "NORMAL")],
)
def test_constructor_rejects_unsafe_durability_pragmas(
    tmp_path: Path, pragma: str, value: str
) -> None:
    engine = create_engine(
        f"sqlite:///{tmp_path / f'unsafe-{pragma}.sqlite'}", pool_size=1, max_overflow=0
    )
    init_sync_schema(engine)
    with engine.connect() as connection:
        connection.exec_driver_sql(f"PRAGMA {pragma}={value}")
    sessions = sessionmaker(engine, expire_on_commit=False)
    try:
        with pytest.raises(McpAuditStoreError) as error:
            McpAuditStore(sessions, key=_KEY, scope=_SCOPE)
        assert error.value.code == "AUDIT_STORE_UNAVAILABLE"
    finally:
        engine.dispose()


def test_store_rejects_pysqlite_begin_event_recipe(database: Any) -> None:
    engine, _sessions = database

    def disable_driver_begin(connection: Any, _record: Any) -> None:
        connection.isolation_level = None

    def begin_with_recipe(connection: Any) -> None:
        connection.exec_driver_sql("BEGIN")

    sqlalchemy_event.listen(engine, "connect", disable_driver_begin)
    sqlalchemy_event.listen(engine, "begin", begin_with_recipe)
    sessions = sessionmaker(engine, expire_on_commit=False)
    with pytest.raises(McpAuditStoreError) as error:
        McpAuditStore(sessions, key=_KEY, scope=_SCOPE)
    assert error.value.code == "AUDIT_STORE_UNAVAILABLE"


def test_engine_logging_configuration_is_rejected_or_redacts_parameters(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    for logger_level, hide_parameters, expected_ok in (
        (logging.INFO, False, False),
        (logging.DEBUG, True, False),
        (logging.INFO, True, True),
    ):
        engine = create_engine(
            f"sqlite:///{tmp_path / f'logging-{logger_level}-{hide_parameters}.sqlite'}",
            hide_parameters=hide_parameters,
        )
        init_sync_schema(engine)
        previous_level = engine.logger.level
        engine.logger.setLevel(logger_level)
        sessions = sessionmaker(engine, expire_on_commit=False)
        try:
            if expected_ok:
                store = McpAuditStore(sessions, key=_KEY, scope=_SCOPE)
                store.append(_events(1)[0])
            else:
                with pytest.raises(McpAuditStoreError):
                    McpAuditStore(sessions, key=_KEY, scope=_SCOPE)
            assert engine.logger.level == logger_level
        finally:
            engine.logger.setLevel(previous_level)
            engine.dispose()
    assert "perf-action-0" not in caplog.text


def test_concurrent_identical_batches_serialize_as_idempotent_success(database: Any) -> None:
    _engine, sessions = database
    stores = (_store(sessions), _store(sessions))
    batch = _events(8)
    start = threading.Barrier(3)
    results: list[str] = []

    def append(store: McpAuditStore) -> None:
        start.wait()
        try:
            store.append_batch(batch)
            results.append("ok")
        except McpAuditStoreError:
            results.append("denied")

    workers = [threading.Thread(target=append, args=(store,)) for store in stores]
    for worker in workers:
        worker.start()
    start.wait()
    for worker in workers:
        worker.join(timeout=10)

    assert all(not worker.is_alive() for worker in workers)
    assert results == ["ok", "ok"]
    with sessions() as session:
        rows = tuple(session.scalars(select(McpAuditRow).order_by(McpAuditRow.sequence)))
        head = session.get(McpAuditHeadRow, "mcp-audit-v1")
    assert [row.event_id for row in rows] == [event.event_id for event in batch]
    assert head is not None and head.sequence_count == len(batch)


def test_sqlite_durability_settings_are_full_and_echo_is_rejected(
    database: Any, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    engine, sessions = database
    with engine.connect() as connection:
        assert connection.exec_driver_sql("PRAGMA journal_mode").scalar() == "delete"
        assert connection.exec_driver_sql("PRAGMA synchronous").scalar() == 2
    _store(sessions)

    echo_engine = create_engine(f"sqlite:///{tmp_path / 'echo.sqlite'}", echo=True)
    init_sync_schema(echo_engine)
    echo_sessions = sessionmaker(echo_engine)
    try:
        with pytest.raises(McpAuditStoreError):
            McpAuditStore(echo_sessions, key=_KEY, scope=_SCOPE)
    finally:
        echo_engine.dispose()
    assert "perf-action" not in caplog.text


def _p95_ms(samples: list[float]) -> float:
    ordered = sorted(samples)
    return ordered[math.ceil(0.95 * len(ordered)) - 1] * 1_000


@pytest.mark.skipif(os.environ.get("LEVIATHAN_RUN_PERF") != "1", reason="opt-in timing test")
def test_append_p95_is_flat_through_one_thousand_rows(tmp_path: Path) -> None:
    """Report p95 at each required size; timing is intentionally opt-in."""

    rows_at_size: dict[int, float] = {}
    sample_count = 100
    for target_size in (10, 100, 500, 1_000):
        engine = create_engine(f"sqlite:///{tmp_path / f'audit-{target_size}.sqlite'}")
        init_sync_schema(engine)
        sessions = sessionmaker(engine, expire_on_commit=False)
        store = _store(sessions)
        prefix = _events(target_size)
        store.append_batch(prefix)
        next_event = _events(target_size + 1, prefix)[-1]
        with sessions() as session:
            baseline_head = session.get(McpAuditHeadRow, "mcp-audit-v1")
            assert baseline_head is not None
            baseline_tip = baseline_head.chain_tip
            baseline_mac = baseline_head.checkpoint_mac
        samples: list[float] = []
        for _offset in range(sample_count):
            started = time.perf_counter()
            store.append(next_event)
            samples.append(time.perf_counter() - started)
            # Restore the authenticated fixture snapshot outside the timer.
            with sessions.begin() as session:
                session.execute(delete(McpAuditRow).where(McpAuditRow.sequence == target_size))
                head = session.get(McpAuditHeadRow, "mcp-audit-v1")
                assert head is not None
                head.sequence_count = target_size
                head.chain_tip = baseline_tip
                head.checkpoint_mac = baseline_mac
        rows_at_size[target_size] = _p95_ms(samples)
        engine.dispose()

    print("MCP audit append p95 ms at exact starting chain sizes:", rows_at_size)
    assert rows_at_size[500] <= 1.5 * rows_at_size[10]
