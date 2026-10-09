from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from leviathan_store import create_engine_and_sessionmaker
from leviathan_store.chat_history import ChatHistoryStore

from leviathan_api.routers import chat_history as chat_history_router
from leviathan_api.routers.chat_history import build_chat_history_router


@pytest.fixture
def chat_api(tmp_path, monkeypatch: pytest.MonkeyPatch) -> Any:  # type: ignore[no-untyped-def]
    engine, sessions = create_engine_and_sessionmaker(
        f"sqlite+aiosqlite:///{(tmp_path / 'chat-api.sqlite3').as_posix()}"
    )
    store = ChatHistoryStore(sessions)
    asyncio.run(store.initialize())
    principal = SimpleNamespace(principal_id="account-1")
    monkeypatch.setattr(chat_history_router, "require_trusted_principal", lambda value: value)
    app = FastAPI()
    app.include_router(build_chat_history_router(store, lambda _request: principal, lambda: 100))
    with TestClient(app) as client:
        yield client, store, engine
    asyncio.run(engine.dispose())


def test_chat_history_routes_are_scoped_idempotent_and_no_store(chat_api: Any) -> None:
    client, store, _engine = chat_api
    created = client.post(
        "/chat/history/conversations",
        json={"title": "Support chat", "model_alias": "fast", "user_scope": "attacker"},
    )
    assert created.status_code == 422
    assert created.headers["cache-control"] == "no-store"

    created = client.post(
        "/chat/history/conversations", json={"title": "Support chat", "model_alias": "fast"}
    )
    assert created.status_code == 201
    assert created.headers["cache-control"] == "no-store"
    conversation = created.json()
    assert conversation["user_scope"] == "account-1"
    conversation_id = conversation["conversation_id"]

    payload = {
        "message_id": "client-msg-1",
        "role": "user",
        "content": {"text": "hello", "tool_card": {"type": "status", "label": "ready"}},
        "provider_usage": {"tokens": 3, "cost": "0.0100"},
    }
    first = client.post(f"/chat/history/conversations/{conversation_id}/messages", json=payload)
    duplicate = client.post(f"/chat/history/conversations/{conversation_id}/messages", json=payload)
    assert first.status_code == duplicate.status_code == 200
    assert first.json() == duplicate.json()
    assert first.json()["provider_usage"] == {"tokens": 3, "cost": "0.01"}
    assert first.headers["cache-control"] == "no-store"

    rejected = client.post(
        f"/chat/history/conversations/{conversation_id}/messages",
        json={"message_id": "secret", "role": "assistant", "content": "Bearer abc"},
    )
    assert rejected.status_code == 400
    assert rejected.json() == {"code": "SECRET_DETECTED"}
    assert rejected.headers["cache-control"] == "no-store"

    exported = client.get(f"/chat/history/conversations/{conversation_id}/export")
    assert exported.status_code == 200
    assert exported.headers["cache-control"] == "no-store"
    assert len(exported.json()["messages"]) == 1
    removed = client.delete(f"/chat/history/conversations/{conversation_id}")
    assert removed.status_code == 204
    assert removed.headers["cache-control"] == "no-store"
    events = asyncio.run(store.list_audit_events("account-1"))
    assert len(events) == 1 and events[0].action == "conversation.deleted"


def test_cursor_and_foreign_conversation_errors_are_no_store(chat_api: Any) -> None:
    client, _store, _engine = chat_api
    response = client.get("/chat/history/conversations?limit=0")
    assert response.status_code == 400
    assert response.json() == {"code": "INVALID_REQUEST"}
    assert response.headers["cache-control"] == "no-store"

    missing = client.get("/chat/history/conversations/not-owned/messages")
    assert missing.status_code == 404
    assert missing.json() == {"code": "NOT_FOUND"}
    assert missing.headers["cache-control"] == "no-store"
