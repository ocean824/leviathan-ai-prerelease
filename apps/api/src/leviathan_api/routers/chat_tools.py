"""Authenticated router factory for the CHAT-002 MCP tool bridge."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import NoReturn, TypeVar

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from pydantic import BaseModel, ValidationError
from starlette.routing import Match
from starlette.types import Message, Receive, Scope, Send

from leviathan_api.chat.tool_bridge import (
    ChatToolBridgeError,
    ChatToolBridgeV1,
    ChatToolConfirmRequestV1,
    ChatToolPlanRequestV1,
    ChatToolReadRequestV1,
    ToolDecisionCodeV1,
)
from leviathan_core.seal import verify
from leviathan_core.security.principal_verifier import (
    PrincipalVerificationError,
    VerifiedPrincipalV1,
)

_MAX_BODY_BYTES = 16_384
_VERIFIED_PRINCIPAL_TAG = "sec003.verified_principal.v1"
_ModelT = TypeVar("_ModelT", bound=BaseModel)


class _NoStoreRoute(APIRoute):
    def matches(self, scope: Scope) -> tuple[Match, Scope]:
        match, child_scope = super().matches(scope)
        if (
            match is Match.PARTIAL
            and scope.get("type") == "http"
            and self.path_regex.match(scope.get("path", "")) is not None
        ):
            return Match.FULL, child_scope
        return match, child_scope

    async def handle(self, scope: Scope, receive: Receive, send: Send) -> None:
        if self.methods is not None and scope.get("method") not in self.methods:
            response = JSONResponse(
                status_code=405,
                content={"version": "1", "code": "METHOD_NOT_ALLOWED"},
                headers={"Allow": ", ".join(sorted(self.methods)), "Cache-Control": "no-store"},
            )
            await response(scope, receive, send)
            return

        async def send_no_store(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = [
                    (name, value)
                    for name, value in message.get("headers", [])
                    if name.lower() != b"cache-control"
                ]
                headers.append((b"cache-control", b"no-store"))
                message = {**message, "headers": headers}
            await send(message)

        await super().handle(scope, receive, send_no_store)


def _duplicate_rejecting_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


async def _parse_request(request: Request, model: type[_ModelT]) -> _ModelT:
    if (
        request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        != "application/json"
    ):
        raise HTTPException(status_code=415, detail={"version": "1", "code": "JSON_REQUIRED"})
    try:
        body = await request.body()
        if not body or len(body) > _MAX_BODY_BYTES:
            raise ValueError
        raw = json.loads(
            body,
            object_pairs_hook=_duplicate_rejecting_object,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid number")),
        )
        if type(raw) is not dict:
            raise ValueError
        # JSON-mode validation accepts wire enum strings while preserving the
        # model's strict field validation. The body was already parsed above
        # to reject duplicate keys before this call.
        return model.model_validate_json(body)
    except (ValueError, TypeError, ValidationError):
        raise HTTPException(
            status_code=422, detail={"version": "1", "code": "REQUEST_INVALID"}
        ) from None


def _principal(
    request: Request, resolver: Callable[[Request], VerifiedPrincipalV1]
) -> VerifiedPrincipalV1:
    try:
        principal = resolver(request)
    except HTTPException:
        raise
    except PrincipalVerificationError:
        raise HTTPException(
            status_code=401, detail={"version": "1", "code": "UNAUTHENTICATED"}
        ) from None
    except Exception:
        raise HTTPException(
            status_code=503, detail={"version": "1", "code": "AUTH_UNAVAILABLE"}
        ) from None
    if type(principal) is not VerifiedPrincipalV1 or not verify(principal, _VERIFIED_PRINCIPAL_TAG):
        raise HTTPException(status_code=401, detail={"version": "1", "code": "UNAUTHENTICATED"})
    return principal


def _typed_error(error: ChatToolBridgeError) -> NoReturn:
    status = (
        503
        if error.code is ToolDecisionCodeV1.DEPENDENCY_UNAVAILABLE
        else 422
        if error.code is ToolDecisionCodeV1.INVALID_PROPOSAL
        else 403
    )
    raise HTTPException(
        status_code=status,
        detail={"version": "1", "code": error.code.value},
    ) from None


def create_chat_tools_router(
    bridge: ChatToolBridgeV1,
    principal_resolver: Callable[[Request], VerifiedPrincipalV1],
) -> APIRouter:
    """Return an unmounted router; app integration owns registration."""
    if type(bridge) is not ChatToolBridgeV1 or not callable(principal_resolver):
        raise TypeError("CHAT_TOOLS_UNAVAILABLE")
    router = APIRouter(prefix="/chat/tools", tags=["chat-tools"], route_class=_NoStoreRoute)

    @router.get("/registry")
    async def registry(request: Request) -> dict[str, object]:
        principal = _principal(request, principal_resolver)
        try:
            registry_value = await bridge.list_registry(principal)
            return registry_value.model_dump(mode="json")
        except ChatToolBridgeError as error:
            _typed_error(error)
        except Exception:
            raise HTTPException(
                status_code=503, detail={"version": "1", "code": "CHAT_TOOLS_UNAVAILABLE"}
            ) from None

    @router.post("/plan")
    async def plan(request: Request) -> dict[str, object]:
        principal = _principal(request, principal_resolver)
        payload = await _parse_request(request, ChatToolPlanRequestV1)
        try:
            result = await bridge.plan(principal, payload)
            return result.model_dump(mode="json")
        except ChatToolBridgeError as error:
            _typed_error(error)
        except Exception:
            raise HTTPException(
                status_code=503, detail={"version": "1", "code": "CHAT_TOOLS_UNAVAILABLE"}
            ) from None

    @router.post("/confirm")
    async def confirm(request: Request) -> dict[str, object]:
        principal = _principal(request, principal_resolver)
        payload = await _parse_request(request, ChatToolConfirmRequestV1)
        try:
            result = await bridge.confirm(principal, payload)
            return result.model_dump(mode="json")
        except ChatToolBridgeError as error:
            _typed_error(error)
        except Exception:
            raise HTTPException(
                status_code=503, detail={"version": "1", "code": "CHAT_TOOLS_UNAVAILABLE"}
            ) from None

    @router.post("/read")
    async def read(request: Request) -> dict[str, object]:
        principal = _principal(request, principal_resolver)
        payload = await _parse_request(request, ChatToolReadRequestV1)
        try:
            result = await bridge.read(principal, payload)
            return result.model_dump(mode="json")
        except ChatToolBridgeError as error:
            _typed_error(error)
        except Exception:
            raise HTTPException(
                status_code=503, detail={"version": "1", "code": "CHAT_TOOLS_UNAVAILABLE"}
            ) from None

    return router


__all__ = ["create_chat_tools_router"]
