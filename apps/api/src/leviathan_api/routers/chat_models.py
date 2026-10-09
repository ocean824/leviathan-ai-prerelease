"""Explicitly mounted, account-authorized and no-store CHAT-001 router factory."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Callable, Coroutine, MutableMapping
from typing import Any

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.routing import APIRoute
from starlette.types import Receive, Scope, Send

from leviathan_api.chat.models import (
    ChatErrorCodeV1,
    ChatRequestV1,
    ChatServiceError,
)
from leviathan_api.chat.port import ChatModelPort
from leviathan_core.security.authz_models import TrustedPrincipalV1, require_trusted_principal

_MAX_BODY_BYTES = 300_000
_STATUS_BY_CODE = {
    ChatErrorCodeV1.AUTH_REQUIRED: 401,
    ChatErrorCodeV1.REQUEST_INVALID: 422,
    ChatErrorCodeV1.MODEL_NOT_ALLOWED: 403,
    ChatErrorCodeV1.POLICY_DENIED: 403,
    ChatErrorCodeV1.BUDGET_EXCEEDED: 429,
    ChatErrorCodeV1.RATE_LIMITED: 429,
    ChatErrorCodeV1.DISCLOSURE_REQUIRED: 403,
    ChatErrorCodeV1.CREDENTIAL_UNAVAILABLE: 503,
    ChatErrorCodeV1.ENDPOINT_UNSAFE: 503,
    ChatErrorCodeV1.PROVIDER_UNAVAILABLE: 503,
    ChatErrorCodeV1.PROVIDER_RATE_LIMITED: 503,
    ChatErrorCodeV1.PROVIDER_TIMEOUT: 504,
    ChatErrorCodeV1.PROVIDER_INVALID_RESPONSE: 502,
    ChatErrorCodeV1.CANCELLED: 499,
}


class _NoStoreRoute(APIRoute):
    """Apply no-store even to controlled route errors and method mismatches."""

    def get_route_handler(self) -> Callable[[Request], Coroutine[Any, Any, Response]]:
        original = super().get_route_handler()

        async def handler(request: Request) -> Response:
            try:
                response = await original(request)
            except ChatServiceError as exc:
                response = JSONResponse(
                    status_code=_STATUS_BY_CODE[exc.code],
                    content={"code": exc.code.value},
                )
            response.headers["Cache-Control"] = "no-store"
            response.headers["Pragma"] = "no-cache"
            return response

        return handler

    async def handle(self, scope: Scope, receive: Receive, send: Send) -> None:
        async def no_store_send(message: MutableMapping[str, Any]) -> None:
            if message.get("type") == "http.response.start":
                headers = [
                    (key, value)
                    for key, value in message.get("headers", [])
                    if key.lower() not in (b"cache-control", b"pragma")
                ]
                headers.extend(((b"cache-control", b"no-store"), (b"pragma", b"no-cache")))
                message["headers"] = headers
            await send(message)

        await super().handle(scope, receive, no_store_send)


def create_chat_models_router(service: ChatModelPort) -> APIRouter:
    """Create but do not mount CHAT routes; application integration owns mounting."""
    if any(
        not callable(getattr(service, method, None))
        for method in ("list_models", "complete", "stream")
    ):
        raise TypeError("CHAT_SERVICE_INVALID")
    router = APIRouter(prefix="/chat", tags=["chat"], route_class=_NoStoreRoute)

    def principal_for(request: Request) -> TrustedPrincipalV1:
        try:
            return require_trusted_principal(getattr(request.state, "trusted_principal", None))
        except Exception:
            raise ChatServiceError(ChatErrorCodeV1.AUTH_REQUIRED) from None

    async def request_model(request: Request) -> ChatRequestV1:
        chunks: list[bytes] = []
        total = 0
        async for chunk in request.stream():
            total += len(chunk)
            if total > _MAX_BODY_BYTES:
                raise ChatServiceError(ChatErrorCodeV1.REQUEST_INVALID)
            chunks.append(chunk)
        body = b"".join(chunks)
        try:
            return ChatRequestV1.model_validate_json(body)
        except Exception:
            raise ChatServiceError(ChatErrorCodeV1.REQUEST_INVALID) from None

    @router.get("/models")
    def list_models(request: Request) -> Response:
        principal = principal_for(request)
        try:
            rows = service.list_models(principal)
        except ChatServiceError:
            raise
        except Exception:
            raise ChatServiceError(ChatErrorCodeV1.PROVIDER_UNAVAILABLE) from None
        return JSONResponse(content={"models": [row.model_dump(mode="json") for row in rows]})

    @router.post("/complete")
    async def complete(request: Request) -> Response:
        principal = principal_for(request)
        payload = await request_model(request)
        try:
            result = await service.complete(principal, payload)
        except ChatServiceError:
            raise
        except Exception:
            raise ChatServiceError(ChatErrorCodeV1.PROVIDER_UNAVAILABLE) from None
        return JSONResponse(content=result.model_dump(mode="json"))

    @router.post("/stream")
    async def stream(request: Request) -> Response:
        principal = principal_for(request)
        payload = await request_model(request)
        if not payload.stream:
            raise ChatServiceError(ChatErrorCodeV1.REQUEST_INVALID)

        async def events() -> AsyncIterator[bytes]:
            async for event in service.stream(principal, payload):
                data = json.dumps(
                    event.model_dump(mode="json"), separators=(",", ":"), ensure_ascii=False
                )
                yield f"event: {event.event}\ndata: {data}\n\n".encode()

        return StreamingResponse(
            events(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-store", "Pragma": "no-cache", "X-Accel-Buffering": "no"},
        )

    @router.api_route(
        "/{unmatched:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]
    )
    def not_found(request: Request) -> Response:
        method_by_path = {
            "/chat/models": "GET, HEAD",
            "/chat/complete": "POST",
            "/chat/stream": "POST",
        }
        allowed = method_by_path.get(request.url.path)
        if allowed is not None:
            return JSONResponse(
                status_code=405,
                content={"code": "METHOD_NOT_ALLOWED"},
                headers={"Allow": allowed},
            )
        return JSONResponse(status_code=404, content={"code": "NOT_FOUND"})

    return router


__all__ = ["create_chat_models_router"]
