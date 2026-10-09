"""Independent acceptance for the account-scoped chat history API."""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
import pytest
from fastapi import FastAPI, Request
from httpx import ASGITransport, AsyncClient
from leviathan_store.chat_history import ChatHistoryError, ChatHistoryStore, ChatMessageV1
from leviathan_store.engine import create_engine_and_sessionmaker
from sqlalchemy import text

from leviathan_api.routers.chat_history import build_chat_history_router
from leviathan_core.security.authz_models import (
    _VERIFIER_MARKER,
    PrincipalV1,
    TrustedPrincipalAdapterV1,
    TrustedPrincipalV1,
)

_PATH = "/chat/history"
_NOW = 1_800_000_000_000_000_000
_DAY_NS = 86_400_000_000_000
_CANARY = "sk-testfixturetoken"


def _principal(principal_id: str) -> TrustedPrincipalV1:
    claims = PrincipalV1(
        principal_id=principal_id,
        project_id="chat-history-acceptance",
        roles=("operator",),
        env="test",
    )
    return TrustedPrincipalAdapterV1.from_verified_claims(claims, verifier_marker=_VERIFIER_MARKER)


async def _harness(
    tmp_path: Any,
) -> tuple[ChatHistoryStore, FastAPI, dict[str, TrustedPrincipalV1], Any]:
    engine, sessions = create_engine_and_sessionmaker(
        f"sqlite+aiosqlite:///{(tmp_path / 'chat-history.sqlite3').as_posix()}"
    )
    store = ChatHistoryStore(sessions)
    await store.initialize()
    active: dict[str, TrustedPrincipalV1] = {"principal": _principal("principal-a")}

    def resolve_principal(_request: Request) -> object:
        return active["principal"]

    app = FastAPI()
    app.include_router(build_chat_history_router(store, resolve_principal, lambda: _NOW))
    return store, app, active, engine


def _assert_no_store(response: httpx.Response) -> None:
    assert response.headers.get("cache-control") == "no-store"
    assert response.headers.get("pragma") == "no-cache"
    assert response.headers.get("x-content-type-options") == "nosniff"


@pytest.mark.asyncio
async def test_principals_are_isolated_for_list_read_append_delete_and_export(
    tmp_path: Any,
) -> None:
    store, app, active, engine = await _harness(tmp_path)
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            created_a = await client.post(
                f"{_PATH}/conversations", json={"title": "A private", "model_alias": "m1"}
            )
            _assert_no_store(created_a)
            assert created_a.status_code == 201
            conversation_a = created_a.json()["conversation_id"]
            appended_a = await client.post(
                f"{_PATH}/conversations/{conversation_a}/messages",
                json={"message_id": "message-a", "role": "user", "content": "A only"},
            )
            _assert_no_store(appended_a)
            assert appended_a.status_code == 200

            active["principal"] = _principal("principal-b")
            created_b = await client.post(
                f"{_PATH}/conversations", json={"title": "B private", "model_alias": "m1"}
            )
            _assert_no_store(created_b)
            assert created_b.status_code == 201
            conversation_b = created_b.json()["conversation_id"]
            appended_b = await client.post(
                f"{_PATH}/conversations/{conversation_b}/messages",
                json={"message_id": "message-b", "role": "assistant", "content": "B only"},
            )
            _assert_no_store(appended_b)
            assert appended_b.status_code == 200

            page_b = await client.get(f"{_PATH}/conversations")
            _assert_no_store(page_b)
            assert [row["conversation_id"] for row in page_b.json()["conversations"]] == [
                conversation_b
            ]
            for path in (
                f"{_PATH}/conversations/{conversation_a}/messages",
                f"{_PATH}/conversations/{conversation_a}/export",
            ):
                denied = await client.get(path)
                _assert_no_store(denied)
                assert denied.status_code == 404
                assert denied.json() == {"code": "NOT_FOUND"}
            denied_append = await client.post(
                f"{_PATH}/conversations/{conversation_a}/messages",
                json={"message_id": "cross-scope", "role": "user", "content": "B"},
            )
            _assert_no_store(denied_append)
            assert denied_append.status_code == 404
            assert denied_append.json() == {"code": "NOT_FOUND"}
            denied_delete = await client.delete(f"{_PATH}/conversations/{conversation_a}")
            _assert_no_store(denied_delete)
            assert denied_delete.status_code == 404

            export_b = await client.get(f"{_PATH}/conversations/{conversation_b}/export")
            _assert_no_store(export_b)
            assert export_b.status_code == 200
            assert export_b.json()["conversation"]["conversation_id"] == conversation_b
            assert [row["message_id"] for row in export_b.json()["messages"]] == ["message-b"]

            active["principal"] = _principal("principal-a")
            page_a = await client.get(f"{_PATH}/conversations")
            _assert_no_store(page_a)
            assert [row["conversation_id"] for row in page_a.json()["conversations"]] == [
                conversation_a
            ]
            own_messages = await client.get(f"{_PATH}/conversations/{conversation_a}/messages")
            _assert_no_store(own_messages)
            assert [row["message_id"] for row in own_messages.json()["messages"]] == ["message-a"]
            export_a = await client.get(f"{_PATH}/conversations/{conversation_a}/export")
            _assert_no_store(export_a)
            assert [row["message_id"] for row in export_a.json()["messages"]] == ["message-a"]

            deleted = await client.delete(f"{_PATH}/conversations/{conversation_a}")
            _assert_no_store(deleted)
            assert deleted.status_code == 204
            assert deleted.content == b""
            async with engine.connect() as connection:
                remaining = await connection.scalar(
                    text(
                        "SELECT COUNT(*) FROM chat_history_messages "
                        "WHERE user_scope = :scope AND conversation_id = :conversation_id"
                    ),
                    {"scope": "principal-a", "conversation_id": conversation_a},
                )
            assert remaining == 0
            events_a = await store.list_audit_events("principal-a")
            assert len(events_a) == 1
            assert events_a[0].conversation_id == conversation_a
            assert events_a[0].action == "conversation.deleted"

            active["principal"] = _principal("principal-b")
            surviving_b = await client.get(f"{_PATH}/conversations/{conversation_b}/messages")
            _assert_no_store(surviving_b)
            assert [row["message_id"] for row in surviving_b.json()["messages"]] == ["message-b"]
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_duplicate_message_id_is_idempotent_and_cursor_excludes_later_appends(
    tmp_path: Any,
) -> None:
    store, app, _active, engine = await _harness(tmp_path)
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            created = await client.post(
                f"{_PATH}/conversations", json={"title": "pagination", "model_alias": "m1"}
            )
            conversation_id = created.json()["conversation_id"]
            for message_id in ("m-1", "m-2", "m-3"):
                result = await client.post(
                    f"{_PATH}/conversations/{conversation_id}/messages",
                    json={"message_id": message_id, "role": "user", "content": message_id},
                )
                _assert_no_store(result)
                assert result.status_code == 200

            duplicate = await client.post(
                f"{_PATH}/conversations/{conversation_id}/messages",
                json={"message_id": "m-3", "role": "user", "content": "different retry body"},
            )
            _assert_no_store(duplicate)
            assert duplicate.status_code == 200
            assert duplicate.json()["content"] == {"text": "m-3"}
            first_page = await client.get(
                f"{_PATH}/conversations/{conversation_id}/messages", params={"limit": 2}
            )
            _assert_no_store(first_page)
            assert [row["message_id"] for row in first_page.json()["messages"]] == ["m-3", "m-2"]
            cursor = first_page.json()["next_cursor"]
            assert cursor

            later_responses = await asyncio.gather(
                client.post(
                    f"{_PATH}/conversations/{conversation_id}/messages",
                    json={"message_id": "m-4", "role": "user", "content": "after cursor"},
                ),
                client.post(
                    f"{_PATH}/conversations/{conversation_id}/messages",
                    json={"message_id": "m-5", "role": "user", "content": "concurrent append"},
                ),
            )
            for response in later_responses:
                _assert_no_store(response)
            assert all(response.status_code == 200 for response in later_responses)
            second_page = await client.get(
                f"{_PATH}/conversations/{conversation_id}/messages",
                params={"limit": 2, "cursor": cursor},
            )
            _assert_no_store(second_page)
            assert [row["message_id"] for row in second_page.json()["messages"]] == ["m-1"]
            assert second_page.json()["next_cursor"] is None

            all_messages = await store.list_messages("principal-a", conversation_id, limit=10)
            assert len(all_messages.messages) == 5
            assert len({row.message_id for row in all_messages.messages}) == 5
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_secret_and_size_rejections_are_typed_and_store_nothing(tmp_path: Any) -> None:
    _store, app, _active, engine = await _harness(tmp_path)
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            created = await client.post(
                f"{_PATH}/conversations", json={"title": "guardrails", "model_alias": "m1"}
            )
            conversation_id = created.json()["conversation_id"]

            secret = await client.post(
                f"{_PATH}/conversations/{conversation_id}/messages",
                json={"message_id": "secret", "role": "user", "content": f"leak {_CANARY}"},
            )
            _assert_no_store(secret)
            assert secret.status_code == 400
            assert secret.json() == {"code": "SECRET_DETECTED"}
            assert _CANARY not in secret.text

            oversized = await client.post(
                f"{_PATH}/conversations/{conversation_id}/messages",
                json={"message_id": "too-large", "role": "user", "content": "x" * (33 * 1024)},
            )
            _assert_no_store(oversized)
            assert oversized.status_code == 413
            assert oversized.json() == {"code": "PAYLOAD_TOO_LARGE"}
            assert (
                len(
                    (await client.get(f"{_PATH}/conversations/{conversation_id}/messages")).json()[
                        "messages"
                    ]
                )
                == 0
            )

            over_page_cap = await client.get(f"{_PATH}/conversations", params={"limit": 101})
            _assert_no_store(over_page_cap)
            assert over_page_cap.status_code == 400
            assert over_page_cap.json() == {"code": "INVALID_REQUEST"}
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_purge_removes_only_conversations_past_their_retention_deadline(
    tmp_path: Any,
) -> None:
    store, _app, _active, engine = await _harness(tmp_path)
    try:
        expired = await store.create_conversation("principal-a", "expired", "m1", _NOW)
        retained = await store.create_conversation("principal-b", "retained", "m1", _NOW + _DAY_NS)
        await store.append_message(
            "principal-a",
            expired.conversation_id,
            ChatMessageV1(
                "expired-message", expired.conversation_id, "user", {"text": "remove"}, _NOW
            ),
        )
        deleted_count = await store.purge_expired(expired.retention_until_ns + 1)
        assert deleted_count == 1

        with pytest.raises(ChatHistoryError) as missing:
            await store.export_conversation("principal-a", expired.conversation_id)
        assert getattr(missing.value, "code", None) == "NOT_FOUND"
        still_here = await store.export_conversation("principal-b", retained.conversation_id)
        assert still_here["conversation"]["conversation_id"] == retained.conversation_id
        events_a = await store.list_audit_events("principal-a")
        events_b = await store.list_audit_events("principal-b")
        assert [(event.conversation_id, event.action) for event in events_a] == [
            (expired.conversation_id, "conversation.expired")
        ]
        assert events_b == ()
    finally:
        await engine.dispose()
