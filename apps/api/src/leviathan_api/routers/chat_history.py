"""Account-scoped chat history routes with no-store responses."""

from __future__ import annotations

import inspect
from collections.abc import Callable
from dataclasses import asdict
from typing import Any, Literal

from fastapi import APIRouter, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from fastapi.routing import APIRoute
from leviathan_store.chat_history import ChatHistoryError, ChatHistoryStore, ChatMessageV1
from pydantic import BaseModel, ConfigDict, Field

from leviathan_core.security.authz_models import require_trusted_principal

_NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache", "X-Content-Type-Options": "nosniff"}


class _NoStoreRoute(APIRoute):
    def get_route_handler(self) -> Callable[..., Any]:
        original = super().get_route_handler()

        async def handler(request: Request) -> Response:
            try:
                response = await original(request)
            except RequestValidationError:
                response = JSONResponse(
                    status_code=422,
                    content={"code": "INVALID_REQUEST"},
                    headers=_NO_STORE,
                )
            for key, value in _NO_STORE.items():
                response.headers[key] = value
            return response

        return handler


class _CreateConversationBody(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    title: str = Field(min_length=1, max_length=512)
    model_alias: str = Field(min_length=1, max_length=128)


class _AppendMessageBody(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    message_id: str = Field(min_length=1, max_length=128)
    role: Literal["user", "assistant", "tool", "system"]
    content: str | dict[str, Any]
    provider_usage: dict[str, int | str | None] | None = None


def _error_status(code: str) -> int:
    return {
        "NOT_FOUND": 404,
        "INVALID_REQUEST": 400,
        "INVALID_CURSOR": 400,
        "SECRET_DETECTED": 400,
        "PAYLOAD_TOO_LARGE": 413,
        "CONFLICT": 409,
    }.get(code, 400)


def _json(status_code: int, content: object) -> JSONResponse:
    return JSONResponse(status_code=status_code, content=content, headers=_NO_STORE)


def build_chat_history_router(
    store: ChatHistoryStore,
    principal_resolver: Callable[[Request], object],
    clock: Callable[[], int],
) -> APIRouter:
    """Build an unmounted router; scope is always taken from a verified principal."""
    if (
        type(store) is not ChatHistoryStore
        or not callable(principal_resolver)
        or not callable(clock)
    ):
        raise TypeError("INVALID_CHAT_HISTORY_DEPENDENCY")

    router = APIRouter(prefix="/chat/history", tags=["chat-history"], route_class=_NoStoreRoute)

    async def scope_for(request: Request) -> str:
        try:
            principal = principal_resolver(request)
            if inspect.isawaitable(principal):
                principal = await principal
            trusted = require_trusted_principal(principal)
            return trusted.principal_id
        except Exception:
            raise ChatHistoryError("UNAUTHENTICATED") from None

    async def now() -> int:
        try:
            value = clock()
            if inspect.isawaitable(value):
                value = await value
            if type(value) is not int or value < 0:
                raise ValueError
            return value
        except Exception:
            raise ChatHistoryError("INVALID_REQUEST") from None

    async def invoke(operation: Callable[[], Any]) -> JSONResponse:
        try:
            value = operation()
            if inspect.isawaitable(value):
                value = await value
            if hasattr(value, "__dataclass_fields__"):
                value = asdict(value)
            return _json(200, value)
        except ChatHistoryError as exc:
            status = 401 if exc.code == "UNAUTHENTICATED" else _error_status(exc.code)
            return _json(status, {"code": exc.code})
        except Exception:
            return _json(500, {"code": "CHAT_HISTORY_UNAVAILABLE"})

    @router.get("/conversations")
    async def list_conversations(
        request: Request, limit: int = 50, cursor: str | None = None
    ) -> Response:
        async def run() -> object:
            scope = await scope_for(request)
            return await store.list_conversations(scope, limit=limit, cursor=cursor)

        return await invoke(run)

    @router.post("/conversations")
    async def create_conversation(request: Request, body: _CreateConversationBody) -> Response:
        async def run() -> object:
            scope = await scope_for(request)
            return await store.create_conversation(scope, body.title, body.model_alias, await now())

        result = await invoke(run)
        if result.status_code == 200:
            result.status_code = 201
        return result

    @router.post("/conversations/{conversation_id}/messages")
    async def append_message(
        request: Request, conversation_id: str, body: _AppendMessageBody
    ) -> Response:
        async def run() -> object:
            scope = await scope_for(request)
            message = ChatMessageV1(
                message_id=body.message_id,
                conversation_id=conversation_id,
                role=body.role,
                content=body.content if isinstance(body.content, dict) else {"text": body.content},
                created_at_ns=await now(),
                provider_usage=body.provider_usage,
            )
            return await store.append_message(scope, conversation_id, message)

        return await invoke(run)

    @router.get("/conversations/{conversation_id}/messages")
    async def list_messages(
        request: Request, conversation_id: str, limit: int = 50, cursor: str | None = None
    ) -> Response:
        async def run() -> object:
            scope = await scope_for(request)
            return await store.list_messages(scope, conversation_id, limit=limit, cursor=cursor)

        return await invoke(run)

    @router.delete("/conversations/{conversation_id}")
    async def delete_conversation(request: Request, conversation_id: str) -> Response:
        async def run() -> object:
            scope = await scope_for(request)
            return await store.delete_conversation(scope, conversation_id, await now())

        result = await invoke(run)
        if result.status_code == 200:
            return Response(status_code=204, headers=_NO_STORE)
        return result

    @router.get("/conversations/{conversation_id}/export")
    async def export_conversation(request: Request, conversation_id: str) -> Response:
        async def run() -> object:
            scope = await scope_for(request)
            return await store.export_conversation(scope, conversation_id)

        return await invoke(run)

    return router


__all__ = ["build_chat_history_router"]
