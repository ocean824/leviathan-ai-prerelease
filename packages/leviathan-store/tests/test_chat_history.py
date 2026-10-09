from __future__ import annotations

import pytest
import pytest_asyncio
from leviathan_store import create_engine_and_sessionmaker
from leviathan_store.chat_history import (
    RETENTION_DAYS_DEFAULT,
    ChatHistoryError,
    ChatHistoryStore,
    ChatMessageV1,
)


@pytest_asyncio.fixture
async def history_store(tmp_path):  # type: ignore[no-untyped-def]
    engine, sessions = create_engine_and_sessionmaker(
        f"sqlite+aiosqlite:///{(tmp_path / 'chat.sqlite3').as_posix()}"
    )
    store = ChatHistoryStore(sessions)
    await store.initialize()
    yield store
    await engine.dispose()


def message(conversation_id: str, message_id: str, text: str, at: int) -> ChatMessageV1:
    return ChatMessageV1(message_id, conversation_id, "user", {"text": text}, at)


@pytest.mark.asyncio
async def test_create_and_list_conversations_use_scoped_retention(
    history_store: ChatHistoryStore,
) -> None:
    now = 1_000_000
    created = await history_store.create_conversation("acct-a", "Title", "model-x", now)
    assert created.user_scope == "acct-a"
    assert created.revision == 0
    assert (
        created.retention_until_ns - created.created_at_ns
        == RETENTION_DAYS_DEFAULT * 86_400_000_000_000
    )
    assert (await history_store.list_conversations("acct-a")).conversations == (created,)
    assert (await history_store.list_conversations("acct-b")).conversations == ()


@pytest.mark.asyncio
async def test_append_is_idempotent_and_message_ids_are_conversation_scoped(
    history_store: ChatHistoryStore,
) -> None:
    first = await history_store.create_conversation("acct-a", "A", "m", 10)
    second = await history_store.create_conversation("acct-a", "B", "m", 11)
    stored = await history_store.append_message(
        "acct-a", first.conversation_id, message(first.conversation_id, "client-1", "hello", 12)
    )
    duplicate = await history_store.append_message(
        "acct-a",
        first.conversation_id,
        message(first.conversation_id, "client-1", "different body", 13),
    )
    assert duplicate == stored
    other_conversation = await history_store.append_message(
        "acct-a",
        second.conversation_id,
        message(second.conversation_id, "client-1", "also valid", 14),
    )
    assert other_conversation.content == {"text": "also valid"}
    assert (await history_store.list_messages("acct-a", first.conversation_id)).messages == (
        stored,
    )


@pytest.mark.asyncio
async def test_secret_shaped_tokens_and_oversized_messages_are_rejected(
    history_store: ChatHistoryStore,
) -> None:
    conversation = await history_store.create_conversation("acct-a", "A", "m", 10)
    for text, expected in (
        ("Bearer very-secret", "SECRET_DETECTED"),
        ("x" * 32_769, "PAYLOAD_TOO_LARGE"),
    ):
        with pytest.raises(ChatHistoryError) as error:
            await history_store.append_message(
                "acct-a",
                conversation.conversation_id,
                message(conversation.conversation_id, str(len(text)), text, 11),
            )
        assert error.value.code == expected


@pytest.mark.asyncio
async def test_cursor_pages_are_stable_when_new_messages_arrive(
    history_store: ChatHistoryStore,
) -> None:
    conversation = await history_store.create_conversation("acct-a", "A", "m", 10)
    for index in range(3):
        await history_store.append_message(
            "acct-a",
            conversation.conversation_id,
            message(conversation.conversation_id, f"m{index}", str(index), 20 + index),
        )
    first_page = await history_store.list_messages("acct-a", conversation.conversation_id, limit=2)
    assert first_page.next_cursor is not None
    await history_store.append_message(
        "acct-a",
        conversation.conversation_id,
        message(conversation.conversation_id, "later", "later", 99),
    )
    second_page = await history_store.list_messages(
        "acct-a", conversation.conversation_id, limit=2, cursor=first_page.next_cursor
    )
    assert [row.message_id for row in first_page.messages + second_page.messages] == [
        "m2",
        "m1",
        "m0",
    ]


@pytest.mark.asyncio
async def test_delete_is_hard_and_audited_and_purge_expired_counts_rows(
    history_store: ChatHistoryStore,
) -> None:
    conversation = await history_store.create_conversation("acct-a", "A", "m", 10)
    await history_store.append_message(
        "acct-a",
        conversation.conversation_id,
        message(conversation.conversation_id, "m1", "hi", 11),
    )
    event = await history_store.delete_conversation("acct-a", conversation.conversation_id, 12)
    assert event.action == "conversation.deleted"
    assert (await history_store.list_audit_events("acct-a")) == (event,)
    with pytest.raises(ChatHistoryError) as error:
        await history_store.export_conversation("acct-a", conversation.conversation_id)
    assert error.value.code == "NOT_FOUND"

    expiring = await history_store.create_conversation("acct-a", "B", "m", 100)
    assert await history_store.purge_expired(expiring.retention_until_ns - 1) == 0
    assert await history_store.purge_expired(expiring.retention_until_ns) == 1


@pytest.mark.asyncio
async def test_foreign_scope_cannot_read_or_delete_conversation(
    history_store: ChatHistoryStore,
) -> None:
    conversation = await history_store.create_conversation("acct-a", "A", "m", 10)
    for operation in (
        lambda: history_store.export_conversation("acct-b", conversation.conversation_id),
        lambda: history_store.delete_conversation("acct-b", conversation.conversation_id, 12),
    ):
        with pytest.raises(ChatHistoryError) as error:
            await operation()
        assert error.value.code == "NOT_FOUND"
    assert (await history_store.list_conversations("acct-a")).conversations == (conversation,)
