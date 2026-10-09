"""Independent acceptance checks for the peer-scoped OMEGA due queue."""

from __future__ import annotations

from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from test_omega_tasks_acceptance import (
    _CREATOR_SESSION,
    _PEER,
    _TASK_TOOL,
    _WORKER,
    _handoff,
    _handoff_body,
    _headers,
    _route_result,
    issue_agent_session,
)

from leviathan_api.routers.omega_tasks import build_router
from leviathan_core.omega_link.state_models import AgentSessionV1, HandoffTaskV1
from leviathan_core.omega_link.task_bridge import TaskBridgeError, issue_task_record

pytest_plugins = ("test_omega_tasks_acceptance",)


class _PeerFilteredStore:
    """Route-local store double that records the required peer-scoped query."""

    def __init__(self, delegate: Any) -> None:
        self.delegate = delegate
        self.foreign: list[object] = []
        self.calls: list[dict[str, object]] = []
        self.fail_with: Exception | None = None
        self.return_override: object | None = None

    def create(self, **kwargs: Any):
        return self.delegate.create(**kwargs)

    def get_task(self, peer_system: str, task_id: str):
        return self.delegate.get_task(peer_system, task_id)

    def replace_task(self, **kwargs: Any):
        return self.delegate.replace_task(**kwargs)

    def list_due_for_peer(self, *, peer_system: str, now_ns: int, limit: int) -> tuple[object, ...]:
        self.calls.append({"peer_system": peer_system, "now_ns": now_ns, "limit": limit})
        if self.fail_with is not None:
            raise self.fail_with
        if self.return_override is not None:
            return self.return_override  # type: ignore[return-value]
        candidates = [*self.delegate.records.values(), *self.foreign]
        visible = [
            record
            for record in candidates
            if getattr(record, "peer_system", None) == peer_system and _is_due(record, now_ns)
        ]
        visible.sort(key=lambda record: (record.task.expires_at_ns, record.task.task_id))
        return tuple(visible[:limit])


class _LegacyGlobalOnlyStore:
    """Reference-store shape: global list_due exists; peer-filtered query does not."""

    def __init__(self, delegate: Any) -> None:
        self.delegate = delegate
        self.global_calls: list[dict[str, int]] = []

    def __getattr__(self, name: str) -> Any:
        return getattr(self.delegate, name)

    def list_due(self, *, now_ns: int, limit: int):
        self.global_calls.append({"now_ns": now_ns, "limit": limit})
        return self.delegate.list_due(now_ns, limit)


def _is_due(record: object, now_ns: int) -> bool:
    task = getattr(record, "task", None)
    if task is None:
        return False
    return (task.state == "pending" and task.expires_at_ns <= now_ns) or (
        task.state == "in_progress"
        and (task.expires_at_ns <= now_ns or task.created_at_ns + task.sla_ms * 1_000_000 <= now_ns)
    )


@pytest.fixture
def due_route(bridge: Any) -> Iterator[Any]:
    """Mount only the reserved router and inject verified synthetic authorities."""
    runtime = bridge.runtime
    original_store = runtime.task_store
    store = _PeerFilteredStore(original_store)
    runtime.task_store = store

    app = FastAPI()
    app.include_router(build_router(runtime))
    app.state.omega_adapter = bridge.adapter
    app.state.omega_tasks = runtime

    @app.middleware("http")
    async def inject_test_tls(request: Request, call_next):
        extensions = dict(request.scope.get("extensions", {}))
        extensions["tls"] = {"client_cert_der": bridge.certificate[0]}
        request.scope["extensions"] = extensions
        return await call_next(request)

    try:
        with TestClient(app) as client:
            yield SimpleNamespace(bridge=bridge, client=client, store=store)
    finally:
        runtime.task_store = original_store


def _create_due_task(due_route: Any, *, task_id_suffix: str = "one") -> str:
    response = _handoff(
        due_route.bridge,
        key=f"due-{task_id_suffix}",
        body=_handoff_body(ttl_ms=1_000, sla_ms=500),
    )
    assert response.status_code == 202, response.text
    return response.json()["task_id"]


def _add_foreign_due_record(due_route: Any, *, created_at_ns: int) -> str:
    foreign_task_id = f"foreign-peer-private-task-{len(due_route.store.foreign) + 1}"
    task = HandoffTaskV1(
        version="1",
        task_id=foreign_task_id,
        task_type="analysis",
        created_by="agent.foreign",
        assigned_to=_WORKER,
        state="pending",
        created_at_ns=created_at_ns,
        ttl_ms=1_000,
        sla_ms=500,
        context_hash="a" * 64,
        tool_allowlist=(_TASK_TOOL,),
    )
    model_route = _route_result(
        task_type="analysis",
        agent_id="agent.foreign",
        tools=(_TASK_TOOL,),
        now_ns=created_at_ns,
    )
    record = issue_task_record(
        peer_system="foreign-peer-private-name",
        task=task,
        priority="urgent",
        requires_risk_guard=False,
        context_payload=b"private foreign prompt sentinel",
        model_route=model_route,
    )
    due_route.store.foreign.append(record)
    return foreign_task_id


def _set_due_clock(bridge: Any, task_id: str) -> int:
    record = bridge.store.records[(_PEER, task_id)]
    bridge.now[0] = record.task.expires_at_ns
    return bridge.now[0]


def test_peer_filtered_limit_lookahead_and_status_only_response(due_route: Any) -> None:
    task_ids = [_create_due_task(due_route, task_id_suffix=str(i)) for i in range(3)]
    foreign_id = _add_foreign_due_record(due_route, created_at_ns=due_route.bridge.now[0])
    expected_now = _set_due_clock(due_route.bridge, task_ids[0])
    # All three own-peer tasks have the same one-second expiry.
    due_route.bridge.now[0] = max(
        due_route.bridge.store.records[(_PEER, task_id)].task.expires_at_ns for task_id in task_ids
    )
    expected_now = due_route.bridge.now[0]

    response = due_route.client.get(
        "/v1/omega/tasks/due?limit=2", headers=_headers(due_route.bridge)
    )

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["peer_system"] == _PEER
    assert payload["now_ns"] == expected_now
    assert payload["has_more"] is True
    assert len(payload["items"]) == 2
    assert {item["task_id"] for item in payload["items"]}.issubset(set(task_ids))
    assert foreign_id not in response.text
    assert "foreign-peer-private-name" not in response.text
    assert "private foreign prompt sentinel" not in response.text
    assert set(payload) == {"peer_system", "now_ns", "items", "has_more"}
    item_keys = {
        "task_id",
        "task_type",
        "state",
        "priority",
        "created_at_ns",
        "expires_at_ns",
        "sla_ms",
        "revision",
    }
    assert all(set(item) == item_keys for item in payload["items"])
    assert due_route.store.calls[-1] == {
        "peer_system": _PEER,
        "now_ns": expected_now,
        "limit": 3,
    }


def test_foreign_peer_rows_do_not_inflate_has_more(due_route: Any) -> None:
    task_ids = [_create_due_task(due_route, task_id_suffix=str(i)) for i in range(2)]
    foreign_ids = [
        _add_foreign_due_record(
            due_route,
            created_at_ns=due_route.bridge.now[0],
        )
        for _ in range(3)
    ]
    due_route.bridge.now[0] = max(
        due_route.bridge.store.records[(_PEER, task_id)].task.expires_at_ns for task_id in task_ids
    )

    response = due_route.client.get(
        "/v1/omega/tasks/due?limit=2", headers=_headers(due_route.bridge)
    )

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["has_more"] is False
    assert {item["task_id"] for item in payload["items"]} == set(task_ids)
    assert not any(task_id in response.text for task_id in foreign_ids)
    assert due_route.store.calls[-1]["limit"] == 3


def test_due_route_uses_one_trusted_clock_read(due_route: Any) -> None:
    task_id = _create_due_task(due_route)
    now_ns = _set_due_clock(due_route.bridge, task_id)
    reads_before = due_route.bridge.clock_reads[0]

    response = due_route.client.get("/v1/omega/tasks/due", headers=_headers(due_route.bridge))

    assert response.status_code == 200, response.text
    assert due_route.bridge.clock_reads[0] == reads_before + 1
    assert response.json()["now_ns"] == now_ns
    assert due_route.store.calls[-1]["now_ns"] == now_ns
    assert due_route.store.calls[-1]["limit"] == 101


def test_authentication_and_scope_failures_are_content_free(due_route: Any) -> None:
    missing_auth = due_route.client.get("/v1/omega/tasks/due")
    assert missing_auth.status_code == 401
    assert missing_auth.json() == {"detail": "OMEGA_AUTH_DENIED"}

    wrong_omega_scope = due_route.client.get(
        "/v1/omega/tasks/due",
        headers=_headers(due_route.bridge, scope="not-omega-task"),
    )
    assert wrong_omega_scope.status_code == 401
    assert wrong_omega_scope.json() == {"detail": "OMEGA_AUTH_DENIED"}

    wrong_session_scope = due_route.client.get(
        "/v1/omega/tasks/due",
        headers=_headers(due_route.bridge, session_id="session-without-audit"),
    )
    # Unknown and inactive session evidence is a single public session denial.
    assert wrong_session_scope.status_code == 403
    assert wrong_session_scope.json() == {"detail": "SESSION_DENIED"}
    assert due_route.store.calls == []


def test_authenticated_session_without_audit_scope_is_denied(due_route: Any) -> None:
    old = due_route.bridge.sessions[_CREATOR_SESSION]
    stripped = AgentSessionV1(
        version=old.version,
        session_id=old.session_id,
        peer_system=old.peer_system,
        agent_id=old.agent_id,
        scopes=tuple(scope for scope in old.scopes if scope != "task:audit.read"),
        manifest_hash=old.manifest_hash,
        status=old.status,
        issued_at_ns=old.issued_at_ns,
        expires_at_ns=old.expires_at_ns,
        action_budget=old.action_budget,
    )
    due_route.bridge.sessions[_CREATOR_SESSION] = issue_agent_session(session=stripped)
    try:
        response = due_route.client.get(
            "/v1/omega/tasks/due", headers=_headers(due_route.bridge, nonce="wrong-scope")
        )
    finally:
        due_route.bridge.sessions[_CREATOR_SESSION] = old

    assert response.status_code == 403
    assert response.json() == {"detail": "SCOPE_DENIED"}
    assert "task:audit.read" not in response.text
    assert due_route.store.calls == []


def test_invalid_and_duplicate_query_parameters_are_content_free(due_route: Any) -> None:
    for query in ("?limit=0", "?limit=501", "?limit=1&limit=2", "?peer_system=foreign"):
        response = due_route.client.get(
            f"/v1/omega/tasks/due{query}", headers=_headers(due_route.bridge)
        )
        assert response.status_code == 422
        assert response.json() == {"detail": "INVALID_QUERY"}
    assert due_route.store.calls == []


def test_store_failure_does_not_echo_exception_or_task_data(due_route: Any) -> None:
    due_route.store.fail_with = RuntimeError(
        "foreign-peer-private-name private foreign prompt sentinel raw-task-identifier"
    )

    response = due_route.client.get("/v1/omega/tasks/due", headers=_headers(due_route.bridge))

    assert response.status_code == 503
    assert response.json() == {"detail": "TASK_STORE_UNAVAILABLE"}
    assert "foreign-peer-private-name" not in response.text
    assert "private foreign prompt sentinel" not in response.text
    assert "raw-task-identifier" not in response.text


def test_returned_foreign_row_fails_closed_without_peer_data(due_route: Any) -> None:
    foreign_id = _add_foreign_due_record(due_route, created_at_ns=due_route.bridge.now[0])
    due_route.store.return_override = tuple(due_route.store.foreign)

    response = due_route.client.get("/v1/omega/tasks/due", headers=_headers(due_route.bridge))

    assert response.status_code == 503
    assert response.json() == {"detail": "TASK_STORE_UNAVAILABLE"}
    assert foreign_id not in response.text
    assert "foreign-peer-private-name" not in response.text
    assert "private foreign prompt sentinel" not in response.text


def test_reference_store_without_peer_query_never_calls_global_list_due(
    due_route: Any,
) -> None:
    runtime = due_route.bridge.runtime
    peer_filtered_store = runtime.task_store
    legacy_store = _LegacyGlobalOnlyStore(due_route.store.delegate)
    runtime.task_store = legacy_store
    try:
        with pytest.raises(TaskBridgeError) as raised:
            build_router(runtime)
    finally:
        runtime.task_store = peer_filtered_store

    assert raised.value.code == "NOT_CONFIGURED"
    assert raised.value.status_code == 503
    assert str(raised.value) == "NOT_CONFIGURED"
    assert legacy_store.global_calls == []


def test_route_is_get_only(due_route: Any) -> None:
    response = due_route.client.post("/v1/omega/tasks/due")

    assert response.status_code == 405
    assert due_route.store.calls == []
