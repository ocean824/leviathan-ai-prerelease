from __future__ import annotations

from pathlib import Path

import pytest
from leviathan_store.engine import create_sync_engine_and_sessionmaker, init_sync_schema
from leviathan_store.mcp_audit import McpAuditScopeV1, McpAuditStore
from leviathan_store.omega_due_queue import _ROW_DOMAIN, OmegaDueQueueStore
from leviathan_store.tables import OmegaTaskRow
from test_omega_due_queue import _create, _record

from leviathan_core.execution.order_models import LedgerIntegrityKey
from leviathan_core.omega_link.task_bridge import TaskBridgeError

_KEY = LedgerIntegrityKey(b"synthetic-cross-store-key-material-32-bytes")
_MCP_ROW_DOMAIN = b"leviathan.mcp.audit.store.row.v1\x00"


def test_omega_and_mcp_row_domains_reject_cross_store_signatures() -> None:
    engine, sessions = create_sync_engine_and_sessionmaker("sqlite:///:memory:")
    try:
        init_sync_schema(engine)
        due = OmegaDueQueueStore(sessions, key=_KEY)
        mcp = McpAuditStore(
            sessions,
            key=_KEY,
            scope=McpAuditScopeV1("project-test", "PAPER"),
        )
        due_payload = due._signed_row(
            peer_system="peer.alpha",
            task_id="task.alpha",
            state="pending",
            expires_at_ns=10,
            sla_due_at_ns=5,
            revision=1,
            payload={"record": "synthetic"},
            idempotency_key=None,
            request_digest=None,
            idempotency_expires_at_ns=None,
        )
        mcp_payload = mcp._row_payload(
            sequence=1,
            event_id="event.alpha",
            event_json="{}",
            previous_mac="0" * 64,
        )
        assert due_payload.startswith(_ROW_DOMAIN)
        assert mcp_payload.startswith(_MCP_ROW_DOMAIN)
        assert not _KEY.verify(due_payload, _KEY.sign(mcp_payload))
        assert not _KEY.verify(mcp_payload, _KEY.sign(due_payload))
    finally:
        engine.dispose()


def test_legacy_untagged_row_fails_closed_when_store_reopens(tmp_path: Path) -> None:
    database_path = tmp_path / "omega.sqlite3"
    engine, sessions = create_sync_engine_and_sessionmaker(f"sqlite:///{database_path}")
    init_sync_schema(engine)
    store = OmegaDueQueueStore(sessions, key=_KEY)
    created = _create(store, _record())
    assert created.record is not None
    with sessions.begin() as session:
        row = session.get(
            OmegaTaskRow,
            (created.record.peer_system, created.record.task.task_id),
        )
        assert row is not None
        signed = store._signed_row(
            peer_system=row.peer_system,
            task_id=row.task_id,
            state=row.state,
            expires_at_ns=row.expires_at_ns,
            sla_due_at_ns=row.sla_due_at_ns,
            revision=row.revision,
            payload=row.payload,
            idempotency_key=row.idempotency_key,
            request_digest=row.request_digest,
            idempotency_expires_at_ns=row.idempotency_expires_at_ns,
        )
        assert signed.startswith(_ROW_DOMAIN)
        row.row_hmac = _KEY.sign(signed[len(_ROW_DOMAIN) :])
    engine.dispose()

    reopened_engine, reopened_sessions = create_sync_engine_and_sessionmaker(
        f"sqlite:///{database_path}"
    )
    try:
        init_sync_schema(reopened_engine)
        with pytest.raises(TaskBridgeError) as raised:
            OmegaDueQueueStore(reopened_sessions, key=_KEY)
        assert raised.value.code == "TASK_STORE_UNAVAILABLE"
        assert raised.value.status_code == 503
        assert str(raised.value) == "TASK_STORE_UNAVAILABLE"
    finally:
        reopened_engine.dispose()
