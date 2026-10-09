"""Account-scoped durable chat history.

Retention defaults to 90 days as a proposed policy value. Callers should treat
this default as pending product approval and may explicitly configure the
retention duration when constructing a store.
"""

from __future__ import annotations

import base64
import json
import re
import uuid
from dataclasses import asdict, dataclass
from decimal import Decimal, InvalidOperation
from typing import Any, Literal

from sqlalchemy import (
    JSON,
    BigInteger,
    Column,
    ForeignKey,
    Integer,
    MetaData,
    String,
    Table,
    and_,
    delete,
    insert,
    or_,
    select,
    update,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

RETENTION_DAYS_DEFAULT = 90
_DAY_NS = 86_400_000_000_000
_MAX_CONTENT_BYTES = 32 * 1024
_MAX_EXPORT_BYTES = 2 * 1024 * 1024
_MAX_PAGE_SIZE = 100
_MAX_CURSOR_BYTES = 2048
_MAX_ID_LENGTH = 128
_MAX_JSON_DEPTH = 8
_SECRET_PATTERN = re.compile(r"(?:sk_live_|sk-|whsec_|bearer\s+)", re.IGNORECASE)
_ROLE_VALUES = frozenset({"user", "assistant", "tool", "system"})
_metadata = MetaData()

_conversations = Table(
    "chat_history_conversations",
    _metadata,
    Column("conversation_id", String(128), primary_key=True),
    Column("user_scope", String(256), nullable=False, index=True),
    Column("title", String(512), nullable=False),
    Column("model_alias", String(128), nullable=False),
    Column("created_at_ns", BigInteger, nullable=False),
    Column("updated_at_ns", BigInteger, nullable=False),
    Column("revision", Integer, nullable=False),
    Column("retention_until_ns", BigInteger, nullable=False, index=True),
)
_messages = Table(
    "chat_history_messages",
    _metadata,
    Column("message_id", String(128), primary_key=True),
    Column(
        "conversation_id",
        String(128),
        ForeignKey("chat_history_conversations.conversation_id", ondelete="CASCADE"),
        primary_key=True,
        nullable=False,
        index=True,
    ),
    Column("user_scope", String(256), primary_key=True, index=True),
    Column("role", String(16), nullable=False),
    Column("content", JSON, nullable=False),
    Column("created_at_ns", BigInteger, nullable=False),
    Column("provider_usage", JSON, nullable=True),
)
_audit_events = Table(
    "chat_history_audit_events",
    _metadata,
    Column("event_id", String(128), primary_key=True),
    Column("user_scope", String(256), nullable=False, index=True),
    Column("conversation_id", String(128), nullable=False),
    Column("action", String(64), nullable=False),
    Column("occurred_at_ns", BigInteger, nullable=False),
)


class ChatHistoryError(Exception):
    """Input-free error with a stable machine-readable code."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class ConversationV1:
    conversation_id: str
    user_scope: str
    title: str
    model_alias: str
    created_at_ns: int
    updated_at_ns: int
    revision: int
    retention_until_ns: int


@dataclass(frozen=True, slots=True)
class ChatMessageV1:
    message_id: str
    conversation_id: str
    role: Literal["user", "assistant", "tool", "system"]
    content: dict[str, Any]
    created_at_ns: int
    provider_usage: dict[str, int | str | None] | None = None


@dataclass(frozen=True, slots=True)
class ConversationPageV1:
    conversations: tuple[ConversationV1, ...]
    next_cursor: str | None


@dataclass(frozen=True, slots=True)
class MessagePageV1:
    messages: tuple[ChatMessageV1, ...]
    next_cursor: str | None


@dataclass(frozen=True, slots=True)
class ChatAuditEventV1:
    event_id: str
    user_scope: str
    conversation_id: str
    action: Literal["conversation.deleted", "conversation.expired"]
    occurred_at_ns: int


def _require_text(value: object, *, maximum: int, code: str = "INVALID_REQUEST") -> str:
    if type(value) is not str or not value or len(value) > maximum:
        raise ChatHistoryError(code)
    return value


def _require_ns(value: object) -> int:
    if type(value) is not int or value < 0 or value > 9_223_372_036_854_775_807:
        raise ChatHistoryError("INVALID_REQUEST")
    return value


def _clean_json(value: object, *, depth: int = 0) -> object:
    if depth > _MAX_JSON_DEPTH:
        raise ChatHistoryError("INVALID_REQUEST")
    if value is None or type(value) in (bool, int, float):
        if type(value) is float and (value != value or value in (float("inf"), float("-inf"))):
            raise ChatHistoryError("INVALID_REQUEST")
        return value
    if type(value) is str:
        if _SECRET_PATTERN.search(value):
            raise ChatHistoryError("SECRET_DETECTED")
        return value
    if type(value) is list or type(value) is tuple:
        if len(value) > 256:
            raise ChatHistoryError("INVALID_REQUEST")
        return [_clean_json(item, depth=depth + 1) for item in value]
    if type(value) is dict:
        if len(value) > 128 or any(type(key) is not str for key in value):
            raise ChatHistoryError("INVALID_REQUEST")
        return {key: _clean_json(item, depth=depth + 1) for key, item in value.items()}
    raise ChatHistoryError("INVALID_REQUEST")


def _canonical_content(content: object) -> dict[str, Any]:
    if type(content) is str:
        candidate: object = {"text": content}
    else:
        candidate = content
    if type(candidate) is not dict or set(candidate) - {"text", "tool_card"}:
        raise ChatHistoryError("INVALID_REQUEST")
    text = candidate.get("text")
    if type(text) is not str:
        raise ChatHistoryError("INVALID_REQUEST")
    cleaned = _clean_json(candidate)
    if type(cleaned) is not dict:
        raise ChatHistoryError("INVALID_REQUEST")
    encoded = json.dumps(cleaned, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )
    if len(encoded) > _MAX_CONTENT_BYTES:
        raise ChatHistoryError("PAYLOAD_TOO_LARGE")
    return cleaned


def _canonical_usage(usage: object) -> dict[str, int | str | None] | None:
    if usage is None:
        return None
    if type(usage) is not dict or set(usage) != {"tokens", "cost"}:
        raise ChatHistoryError("INVALID_REQUEST")
    tokens = usage["tokens"]
    if type(tokens) is not int or not 0 <= tokens <= 2**63 - 1:
        raise ChatHistoryError("INVALID_REQUEST")
    cost = usage["cost"]
    if cost is not None:
        if type(cost) is not str or len(cost) > 128:
            raise ChatHistoryError("INVALID_REQUEST")
        try:
            decimal_cost = Decimal(cost)
        except InvalidOperation:
            raise ChatHistoryError("INVALID_REQUEST") from None
        if not decimal_cost.is_finite() or decimal_cost < 0:
            raise ChatHistoryError("INVALID_REQUEST")
        cost = format(decimal_cost, "f")
        if "." in cost:
            cost = cost.rstrip("0").rstrip(".")
        if cost in {"", "-0"}:
            cost = "0"
        if len(cost) > 128:
            raise ChatHistoryError("INVALID_REQUEST")
    return {"tokens": tokens, "cost": cost}


def _conversation(row: Any) -> ConversationV1:
    return ConversationV1(
        conversation_id=row.conversation_id,
        user_scope=row.user_scope,
        title=row.title,
        model_alias=row.model_alias,
        created_at_ns=row.created_at_ns,
        updated_at_ns=row.updated_at_ns,
        revision=row.revision,
        retention_until_ns=row.retention_until_ns,
    )


def _message(row: Any) -> ChatMessageV1:
    return ChatMessageV1(
        message_id=row.message_id,
        conversation_id=row.conversation_id,
        role=row.role,
        content=row.content,
        created_at_ns=row.created_at_ns,
        provider_usage=row.provider_usage,
    )


def _encode_cursor(data: dict[str, object]) -> str:
    raw = json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _decode_cursor(
    cursor: str | None, *, kind: str, scope: str, conversation_id: str | None = None
) -> dict[str, Any] | None:
    if cursor is None:
        return None
    if type(cursor) is not str or len(cursor) > _MAX_CURSOR_BYTES:
        raise ChatHistoryError("INVALID_CURSOR")
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        data = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))
    except (ValueError, UnicodeError, json.JSONDecodeError):
        raise ChatHistoryError("INVALID_CURSOR") from None
    keys = {"kind", "scope", "conversation_id", "last_time", "last_id", "high_time", "high_id"}
    if (
        type(data) is not dict
        or set(data) != keys
        or data.get("kind") != kind
        or data.get("scope") != scope
        or data.get("conversation_id") != conversation_id
        or any(type(data.get(k)) is not str for k in ("last_id", "high_id"))
        or any(type(data.get(k)) is not int or data[k] < 0 for k in ("last_time", "high_time"))
    ):
        raise ChatHistoryError("INVALID_CURSOR")
    return data


class ChatHistoryStore:
    """SQL-backed chat history; all operations require an explicit trusted scope."""

    def __init__(
        self,
        sessionmaker: async_sessionmaker[AsyncSession],
        *,
        retention_days: int = RETENTION_DAYS_DEFAULT,
    ) -> None:
        if type(retention_days) is not int or not 1 <= retention_days <= 3650:
            raise ChatHistoryError("INVALID_REQUEST")
        self._sessions = sessionmaker
        self._retention_days = retention_days

    async def initialize(self) -> None:
        bind = self._sessions.kw.get("bind")
        if bind is None:
            raise RuntimeError("CHAT_HISTORY_ENGINE_REQUIRED")
        async with bind.begin() as connection:
            await connection.run_sync(_metadata.create_all)

    async def create_conversation(
        self, user_scope: str, title: str, model_alias: str, now_ns: int
    ) -> ConversationV1:
        scope = _require_text(user_scope, maximum=256)
        title_value = _require_text(title, maximum=512)
        alias = _require_text(model_alias, maximum=128)
        now = _require_ns(now_ns)
        conversation_id = str(uuid.uuid4())
        retention_until_ns = now + self._retention_days * _DAY_NS
        if retention_until_ns > 9_223_372_036_854_775_807:
            raise ChatHistoryError("INVALID_REQUEST")
        values = {
            "conversation_id": conversation_id,
            "user_scope": scope,
            "title": title_value,
            "model_alias": alias,
            "created_at_ns": now,
            "updated_at_ns": now,
            "revision": 0,
            "retention_until_ns": retention_until_ns,
        }
        async with self._sessions() as session, session.begin():
            await session.execute(insert(_conversations).values(**values))
        return ConversationV1(
            conversation_id=conversation_id,
            user_scope=scope,
            title=title_value,
            model_alias=alias,
            created_at_ns=now,
            updated_at_ns=now,
            revision=0,
            retention_until_ns=retention_until_ns,
        )

    async def list_conversations(
        self, user_scope: str, limit: int = 50, cursor: str | None = None
    ) -> ConversationPageV1:
        scope = _require_text(user_scope, maximum=256)
        page_size = self._page_size(limit)
        position = _decode_cursor(cursor, kind="conversations", scope=scope)
        async with self._sessions() as session:
            if position is None:
                high = await session.execute(
                    select(_conversations.c.updated_at_ns, _conversations.c.conversation_id)
                    .where(_conversations.c.user_scope == scope)
                    .order_by(
                        _conversations.c.updated_at_ns.desc(),
                        _conversations.c.conversation_id.desc(),
                    )
                    .limit(1)
                )
                high_row = high.first()
                if high_row is None:
                    return ConversationPageV1((), None)
                high_time, high_id = int(high_row[0]), str(high_row[1])
            else:
                high_time, high_id = position["high_time"], position["high_id"]
                last_time, last_id = position["last_time"], position["last_id"]
            conditions = [
                _conversations.c.user_scope == scope,
                or_(
                    _conversations.c.updated_at_ns < high_time,
                    and_(
                        _conversations.c.updated_at_ns == high_time,
                        _conversations.c.conversation_id <= high_id,
                    ),
                ),
            ]
            if position is not None:
                conditions.append(
                    or_(
                        _conversations.c.updated_at_ns < last_time,
                        and_(
                            _conversations.c.updated_at_ns == last_time,
                            _conversations.c.conversation_id < last_id,
                        ),
                    )
                )
            statement = (
                select(_conversations)
                .where(*conditions)
                .order_by(
                    _conversations.c.updated_at_ns.desc(), _conversations.c.conversation_id.desc()
                )
                .limit(page_size + 1)
            )
            rows = list((await session.execute(statement)).all())
        has_more = len(rows) > page_size
        page_rows = rows[:page_size]
        items = tuple(_conversation(row) for row in page_rows)
        next_cursor = None
        if has_more and page_rows:
            last = page_rows[-1]
            next_cursor = _encode_cursor(
                {
                    "kind": "conversations",
                    "scope": scope,
                    "conversation_id": None,
                    "last_time": last.updated_at_ns,
                    "last_id": last.conversation_id,
                    "high_time": high_time,
                    "high_id": high_id,
                }
            )
        return ConversationPageV1(items, next_cursor)

    async def append_message(
        self, user_scope: str, conversation_id: str, message: ChatMessageV1
    ) -> ChatMessageV1:
        scope = _require_text(user_scope, maximum=256)
        conversation = _require_text(conversation_id, maximum=_MAX_ID_LENGTH)
        if type(message) is not ChatMessageV1:
            raise ChatHistoryError("INVALID_REQUEST")
        message_id = _require_text(message.message_id, maximum=_MAX_ID_LENGTH)
        if message.conversation_id != conversation:
            raise ChatHistoryError("INVALID_REQUEST")
        if message.role not in _ROLE_VALUES:
            raise ChatHistoryError("INVALID_REQUEST")
        content = _canonical_content(message.content)
        usage = _canonical_usage(message.provider_usage)
        created_at_ns = _require_ns(message.created_at_ns)
        values = {
            "message_id": message_id,
            "conversation_id": conversation,
            "user_scope": scope,
            "role": message.role,
            "content": content,
            "created_at_ns": created_at_ns,
            "provider_usage": usage,
        }
        async with self._sessions() as session, session.begin():
            existing = await session.execute(
                select(_messages).where(
                    _messages.c.user_scope == scope,
                    _messages.c.conversation_id == conversation,
                    _messages.c.message_id == message_id,
                )
            )
            existing_row = existing.first()
            if existing_row is not None:
                return _message(existing_row)
            owner = await session.execute(
                select(_conversations.c.conversation_id).where(
                    _conversations.c.conversation_id == conversation,
                    _conversations.c.user_scope == scope,
                )
            )
            if owner.first() is None:
                raise ChatHistoryError("NOT_FOUND")
            try:
                async with session.begin_nested():
                    await session.execute(insert(_messages).values(**values))
            except IntegrityError:
                duplicate = await session.execute(
                    select(_messages).where(
                        _messages.c.user_scope == scope,
                        _messages.c.conversation_id == conversation,
                        _messages.c.message_id == message_id,
                    )
                )
                duplicate_row = duplicate.first()
                if duplicate_row is not None:
                    return _message(duplicate_row)
                raise ChatHistoryError("CONFLICT") from None
            await session.execute(
                update(_conversations)
                .where(
                    _conversations.c.conversation_id == conversation,
                    _conversations.c.user_scope == scope,
                )
                .values(updated_at_ns=created_at_ns, revision=_conversations.c.revision + 1)
            )
        return ChatMessageV1(
            message_id=message_id,
            conversation_id=conversation,
            role=message.role,
            content=content,
            created_at_ns=created_at_ns,
            provider_usage=usage,
        )

    async def list_messages(
        self, user_scope: str, conversation_id: str, limit: int = 50, cursor: str | None = None
    ) -> MessagePageV1:
        scope = _require_text(user_scope, maximum=256)
        conversation = _require_text(conversation_id, maximum=_MAX_ID_LENGTH)
        page_size = self._page_size(limit)
        position = _decode_cursor(
            cursor, kind="messages", scope=scope, conversation_id=conversation
        )
        async with self._sessions() as session:
            owner = await session.execute(
                select(_conversations.c.conversation_id).where(
                    _conversations.c.conversation_id == conversation,
                    _conversations.c.user_scope == scope,
                )
            )
            if owner.first() is None:
                raise ChatHistoryError("NOT_FOUND")
            if position is None:
                high = await session.execute(
                    select(_messages.c.created_at_ns, _messages.c.message_id)
                    .where(
                        _messages.c.user_scope == scope, _messages.c.conversation_id == conversation
                    )
                    .order_by(_messages.c.created_at_ns.desc(), _messages.c.message_id.desc())
                    .limit(1)
                )
                high_row = high.first()
                if high_row is None:
                    return MessagePageV1((), None)
                high_time, high_id = int(high_row[0]), str(high_row[1])
            else:
                high_time, high_id = position["high_time"], position["high_id"]
                last_time, last_id = position["last_time"], position["last_id"]
            conditions = [
                _messages.c.user_scope == scope,
                _messages.c.conversation_id == conversation,
                or_(
                    _messages.c.created_at_ns < high_time,
                    and_(_messages.c.created_at_ns == high_time, _messages.c.message_id <= high_id),
                ),
            ]
            if position is not None:
                conditions.append(
                    or_(
                        _messages.c.created_at_ns < last_time,
                        and_(
                            _messages.c.created_at_ns == last_time, _messages.c.message_id < last_id
                        ),
                    )
                )
            statement = (
                select(_messages)
                .where(*conditions)
                .order_by(_messages.c.created_at_ns.desc(), _messages.c.message_id.desc())
                .limit(page_size + 1)
            )
            rows = list((await session.execute(statement)).all())
        has_more = len(rows) > page_size
        page_rows = rows[:page_size]
        items = tuple(_message(row) for row in page_rows)
        next_cursor = None
        if has_more and page_rows:
            last = page_rows[-1]
            next_cursor = _encode_cursor(
                {
                    "kind": "messages",
                    "scope": scope,
                    "conversation_id": conversation,
                    "last_time": last.created_at_ns,
                    "last_id": last.message_id,
                    "high_time": high_time,
                    "high_id": high_id,
                }
            )
        return MessagePageV1(items, next_cursor)

    async def delete_conversation(
        self, user_scope: str, conversation_id: str, now_ns: int
    ) -> ChatAuditEventV1:
        scope = _require_text(user_scope, maximum=256)
        conversation = _require_text(conversation_id, maximum=_MAX_ID_LENGTH)
        now = _require_ns(now_ns)
        async with self._sessions() as session, session.begin():
            owner = await session.execute(
                select(_conversations.c.conversation_id).where(
                    _conversations.c.conversation_id == conversation,
                    _conversations.c.user_scope == scope,
                )
            )
            if owner.first() is None:
                raise ChatHistoryError("NOT_FOUND")
            event = ChatAuditEventV1(
                str(uuid.uuid4()), scope, conversation, "conversation.deleted", now
            )
            await session.execute(
                insert(_audit_events).values(
                    event_id=event.event_id,
                    user_scope=scope,
                    conversation_id=conversation,
                    action=event.action,
                    occurred_at_ns=now,
                )
            )
            await session.execute(
                delete(_messages).where(
                    _messages.c.conversation_id == conversation, _messages.c.user_scope == scope
                )
            )
            await session.execute(
                delete(_conversations).where(
                    _conversations.c.conversation_id == conversation,
                    _conversations.c.user_scope == scope,
                )
            )
        return event

    async def export_conversation(self, user_scope: str, conversation_id: str) -> dict[str, object]:
        scope = _require_text(user_scope, maximum=256)
        conversation = _require_text(conversation_id, maximum=_MAX_ID_LENGTH)
        async with self._sessions() as session:
            conversation_result = await session.execute(
                select(_conversations).where(
                    _conversations.c.conversation_id == conversation,
                    _conversations.c.user_scope == scope,
                )
            )
            row = conversation_result.first()
            if row is None:
                raise ChatHistoryError("NOT_FOUND")
            messages_result = await session.execute(
                select(_messages)
                .where(_messages.c.conversation_id == conversation, _messages.c.user_scope == scope)
                .order_by(_messages.c.created_at_ns, _messages.c.message_id)
                .limit(10_001)
            )
            messages = list(messages_result.all())
        if len(messages) > 10_000:
            raise ChatHistoryError("PAYLOAD_TOO_LARGE")
        export: dict[str, object] = {
            "schema_version": "leviathan.chat-history-export/1",
            "conversation": asdict(_conversation(row)),
            "messages": [
                {
                    "message_id": item.message_id,
                    "conversation_id": item.conversation_id,
                    "role": item.role,
                    "content": item.content,
                    "created_at_ns": item.created_at_ns,
                    "provider_usage": item.provider_usage,
                }
                for item in (_message(message_row) for message_row in messages)
            ],
        }
        encoded = json.dumps(export, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(encoded) > _MAX_EXPORT_BYTES:
            raise ChatHistoryError("PAYLOAD_TOO_LARGE")
        return export

    async def list_audit_events(self, user_scope: str) -> tuple[ChatAuditEventV1, ...]:
        scope = _require_text(user_scope, maximum=256)
        async with self._sessions() as session:
            result = await session.execute(
                select(_audit_events)
                .where(_audit_events.c.user_scope == scope)
                .order_by(_audit_events.c.occurred_at_ns, _audit_events.c.event_id)
            )
            return tuple(
                ChatAuditEventV1(
                    row.event_id,
                    row.user_scope,
                    row.conversation_id,
                    row.action,
                    row.occurred_at_ns,
                )
                for row in result.all()
            )

    async def purge_expired(self, now_ns: int) -> int:
        now = _require_ns(now_ns)
        count = 0
        async with self._sessions() as session, session.begin():
            expired = list(
                (
                    await session.execute(
                        select(_conversations.c.conversation_id, _conversations.c.user_scope).where(
                            _conversations.c.retention_until_ns <= now
                        )
                    )
                ).all()
            )
            for conversation_id, scope in expired:
                event = ChatAuditEventV1(
                    str(uuid.uuid4()), scope, conversation_id, "conversation.expired", now
                )
                await session.execute(
                    insert(_audit_events).values(
                        event_id=event.event_id,
                        user_scope=scope,
                        conversation_id=conversation_id,
                        action=event.action,
                        occurred_at_ns=now,
                    )
                )
                await session.execute(
                    delete(_messages).where(
                        _messages.c.conversation_id == conversation_id,
                        _messages.c.user_scope == scope,
                    )
                )
                await session.execute(
                    delete(_conversations).where(
                        _conversations.c.conversation_id == conversation_id,
                        _conversations.c.user_scope == scope,
                    )
                )
                count += 1
        return count

    @staticmethod
    def _page_size(limit: int) -> int:
        if type(limit) is not int or not 1 <= limit <= _MAX_PAGE_SIZE:
            raise ChatHistoryError("INVALID_REQUEST")
        return limit


__all__ = [
    "RETENTION_DAYS_DEFAULT",
    "ChatAuditEventV1",
    "ChatHistoryError",
    "ChatHistoryStore",
    "ChatMessageV1",
    "ConversationPageV1",
    "ConversationV1",
    "MessagePageV1",
]
