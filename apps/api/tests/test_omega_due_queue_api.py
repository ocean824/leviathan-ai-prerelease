"""Unit coverage for the peer-scoped OMEGA due queue route."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from leviathan_api.routers import omega_tasks
from leviathan_core.omega_link.state_models import HandoffTaskV1, OmegaPolicyV1
from leviathan_core.omega_link.task_bridge import (
    OmegaTaskRuntime,
    TaskBridgeError,
    TaskRecordV1,
    _issue_task_record_snapshot,
)

_NOW_NS = 9_000_000_000_000
_PEER = "peer-alpha"
_FOREIGN_PEER = "peer-beta"


def _record(peer_system: str, task_id: str) -> TaskRecordV1:
    created_at_ns = _NOW_NS - 10_000_000_000
    task = HandoffTaskV1(
        version="1",
        task_id=task_id,
        task_type="analysis",
        created_by="agent-alpha",
        assigned_to="agent-beta",
        state="pending",
        created_at_ns=created_at_ns,
        ttl_ms=1_000,
        sla_ms=500,
        context_hash="a" * 64,
        tool_allowlist=("research.read",),
    )
    return _issue_task_record_snapshot(
        peer_system=peer_system,
        task=task,
        priority="normal",
        requires_risk_guard=False,
        context_payload_hex=b"synthetic private task context".hex(),
        model_route_json="{}",
        revision=1,
    )


class _Store:
    def __init__(
        self, records: tuple[TaskRecordV1, ...] = (), *, ignore_peer: bool = False
    ) -> None:
        self.records = records
        self.ignore_peer = ignore_peer
        self.list_calls: list[dict[str, object]] = []
        self.global_list_calls = 0

    def create(self, **kwargs: object) -> None:
        return None

    def get_task(self, peer_system: str, task_id: str) -> None:
        return None

    def replace_task(self, **kwargs: object) -> bool:
        return False

    def list_due(self, *, now_ns: int, limit: int) -> tuple[TaskRecordV1, ...]:
        self.global_list_calls += 1
        rows = sorted(
            self.records,
            key=lambda record: (record.task.expires_at_ns, record.task.task_id),
        )
        return tuple(rows[:limit])

    def list_due_for_peer(
        self,
        *,
        now_ns: int,
        limit: int,
        peer_system: str,
    ) -> tuple[TaskRecordV1, ...]:
        self.list_calls.append({"now_ns": now_ns, "limit": limit, "peer_system": peer_system})
        rows = [
            record
            for record in self.records
            if self.ignore_peer or record.peer_system == peer_system
        ]
        rows.sort(key=lambda record: (record.task.expires_at_ns, record.task.task_id))
        return tuple(rows[:limit])


class _Ports:
    def snapshot(self, peer_system: str) -> None:
        return None

    def verify(self, *args: object, **kwargs: object) -> None:
        return None

    def get_manifest(self, peer_system: str) -> None:
        return None

    def authorize_tool(self, **kwargs: object) -> None:
        return None

    def append(self, entry: object) -> None:
        return None

    def read(self, **kwargs: object) -> tuple[()]:
        return ()

    def enqueue(self, event: object) -> None:
        return None

    def consume(self, *args: object, **kwargs: object) -> None:
        return None

    def route_task(self, **kwargs: object) -> None:
        return None


def _client(
    monkeypatch: pytest.MonkeyPatch,
    store: _Store,
    *,
    scopes: tuple[str, ...] = ("task:audit.read",),
) -> TestClient:
    ports = _Ports()
    runtime = OmegaTaskRuntime(
        bridge_health_port=ports,
        session_verifier=ports,
        manifest_port=ports,
        mcp_authorizer=ports,
        task_store=cast(Any, store),
        audit_sink=cast(Any, ports),
        event_outbox=cast(Any, ports),
        rate_limiter=cast(Any, ports),
        model_policy=cast(Any, ports),
        omega_policy=OmegaPolicyV1(version="1", max_heartbeat_age_ns=1_000_000_000),
        clock=lambda: _NOW_NS,
    )
    session = SimpleNamespace(
        session_id="session-alpha",
        agent_id="agent-alpha",
        scopes=scopes,
    )
    peer = SimpleNamespace(peer_system=_PEER)
    manifest = object()
    health = object()

    def authenticate(
        request: Any, current_runtime: OmegaTaskRuntime
    ) -> tuple[Any, Any, Any, Any, int, str]:
        request.state.omega_audit_context = (
            current_runtime,
            peer,
            session,
            "trace_due_queue",
            _NOW_NS,
        )
        request.state.omega_audit_task_id = None
        request.state.omega_audit_tool_id = None
        return peer, session, manifest, health, _NOW_NS, "trace_due_queue"

    monkeypatch.setattr(omega_tasks, "_authenticate", authenticate)
    monkeypatch.setattr(omega_tasks, "_require_bridge", lambda *args: None)
    monkeypatch.setattr(omega_tasks, "_rate", lambda *args: None)
    monkeypatch.setattr(omega_tasks, "_audit", lambda *args, **kwargs: "audit-id")

    app = FastAPI()
    app.include_router(omega_tasks.build_router(runtime))
    app.state.omega_tasks = runtime
    return TestClient(app)


def test_due_queue_filters_in_store_before_limit_and_serializes_allowlisted_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    own_first = _record(_PEER, "task-own-1")
    own_second = _record(_PEER, "task-own-2")
    foreign = _record(_FOREIGN_PEER, "task-foreign")
    store = _Store((own_first, foreign, own_second))
    with _client(monkeypatch, store) as client:
        response = client.get("/v1/omega/tasks/due?limit=1")

    assert response.status_code == 200
    body = response.json()
    assert body["peer_system"] == _PEER
    assert body["now_ns"] == _NOW_NS
    assert body["has_more"] is True
    assert [item["task_id"] for item in body["items"]] == ["task-own-1"]
    assert set(body["items"][0]) == {
        "task_id",
        "task_type",
        "state",
        "priority",
        "created_at_ns",
        "expires_at_ns",
        "sla_ms",
        "revision",
    }
    assert "synthetic private task context" not in response.text
    assert "model_route" not in response.text
    assert store.list_calls == [{"peer_system": _PEER, "now_ns": _NOW_NS, "limit": 2}]
    assert store.global_list_calls == 0


def test_due_queue_rejects_store_rows_from_another_peer_without_disclosing_them(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _Store(
        (_record(_PEER, "task-own"), _record(_FOREIGN_PEER, "secret-foreign-task")),
        ignore_peer=True,
    )
    with _client(monkeypatch, store) as client:
        response = client.get("/v1/omega/tasks/due?limit=2")

    assert response.status_code == 503
    assert response.json() == {"detail": "TASK_STORE_UNAVAILABLE"}
    assert "secret-foreign-task" not in response.text
    assert _FOREIGN_PEER not in response.text


def test_due_queue_default_limit_is_bounded_with_one_lookahead(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _Store()
    with _client(monkeypatch, store) as client:
        response = client.get("/v1/omega/tasks/due")

    assert response.status_code == 200
    assert response.json()["items"] == []
    assert response.json()["has_more"] is False
    assert store.list_calls == [{"peer_system": _PEER, "now_ns": _NOW_NS, "limit": 101}]


@pytest.mark.parametrize(
    "query",
    [
        "?limit=0",
        "?limit=501",
        "?limit=1&limit=2",
        "?other=1",
        "?peer_system=peer-beta",
        "?limit=999999999999",
    ],
)
def test_due_queue_rejects_invalid_or_duplicate_query_without_echoing_input(
    monkeypatch: pytest.MonkeyPatch, query: str
) -> None:
    with _client(monkeypatch, _Store()) as client:
        response = client.get(f"/v1/omega/tasks/due{query}")

    assert response.status_code == 422
    assert response.json() == {"detail": "INVALID_QUERY"}
    assert query not in response.text


def test_due_queue_requires_session_audit_read_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    with _client(monkeypatch, _Store(), scopes=()) as client:
        response = client.get("/v1/omega/tasks/due")

    assert response.status_code == 403
    assert response.json() == {"detail": "SCOPE_DENIED"}


def test_due_queue_without_runtime_fails_closed() -> None:
    app = FastAPI()
    app.include_router(omega_tasks.router)
    with TestClient(app) as client:
        response = client.get("/v1/omega/tasks/due")

    assert response.status_code == 503
    assert response.json() == {"detail": "NOT_CONFIGURED"}


def test_due_queue_mount_rejects_legacy_global_only_store(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _LegacyStore:
        def __init__(self) -> None:
            self.global_calls: list[dict[str, int]] = []

        def create(self, **kwargs: object) -> None:
            return None

        def get_task(self, peer_system: str, task_id: str) -> None:
            return None

        def replace_task(self, **kwargs: object) -> bool:
            return False

        def list_due(self, *, now_ns: int, limit: int) -> tuple[TaskRecordV1, ...]:
            self.global_calls.append({"now_ns": now_ns, "limit": limit})
            return ()

    legacy_store = _LegacyStore()
    with pytest.raises(TaskBridgeError) as error:
        _client(monkeypatch, cast(Any, legacy_store))

    assert error.value.code == "NOT_CONFIGURED"
    assert legacy_store.global_calls == []
