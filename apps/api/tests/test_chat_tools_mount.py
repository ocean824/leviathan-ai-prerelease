"""Mount and fail-closed boundary tests for the CHAT-002 router integration."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import leviathan_api.chat_tools_runtime as chat_tools_runtime
from leviathan_api.chat.tool_bridge import AppRouteOutcomeV1, ChatToolBridgeV1
from leviathan_api.chat_tools_runtime import (
    CHAT_TOOL_APP_ROUTE_ALLOWLIST_V1,
    AppRoutePortAdapterV1,
    ChatToolApprovalStoreV1,
)
from leviathan_api.main import create_app
from leviathan_api.wave35_mounts import Wave35MountDependenciesV1
from leviathan_core.agent_council.model_registry import ModelRegistryV1
from leviathan_core.security.principal_verifier import VerifiedPrincipalV1


class _Routes:
    def __init__(self) -> None:
        self.calls: list[str] = []

    async def invoke(
        self,
        _principal: VerifiedPrincipalV1,
        *,
        route_id: str,
        arguments: Mapping[str, object],
        idempotency_key: str,
    ) -> AppRouteOutcomeV1:
        del arguments, idempotency_key
        self.calls.append(route_id)
        return AppRouteOutcomeV1(
            status_code=202,
            allowed=True,
            effect_performed=True,
            output={"route_id": route_id},
        )


def test_chat_tools_is_mounted_once_and_missing_bridge_is_typed_503(tmp_path: Path) -> None:
    app = create_app(
        wave35_mount_dependencies=Wave35MountDependenciesV1(
            app_data_dir=tmp_path,
            model_registry=ModelRegistryV1(version="v1", entries=()),
        )
    )

    for _ in range(2):
        with TestClient(app) as client:
            response = client.get("/api/chat/tools/registry")
            assert response.status_code == 503
            assert response.json() == {"code": "CHAT_TOOLS_NOT_CONFIGURED"}

    operations = {
        (path, method)
        for path, item in app.openapi()["paths"].items()
        for method in item
        if method in {"get", "post"} and path.startswith("/api/chat/tools/")
    }
    assert operations == {
        ("/api/chat/tools/registry", "get"),
        ("/api/chat/tools/plan", "post"),
        ("/api/chat/tools/confirm", "post"),
        ("/api/chat/tools/read", "post"),
    }


def test_configured_bridge_without_sec003_resolver_uses_router_503(tmp_path: Path) -> None:
    bridge = ChatToolBridgeV1(mcp=None, audit=None)
    app = create_app(
        wave35_mount_dependencies=Wave35MountDependenciesV1(
            app_data_dir=tmp_path,
            model_registry=ModelRegistryV1(version="v1", entries=()),
            chat_tool_bridge=bridge,
        )
    )
    with TestClient(app) as client:
        response = client.get("/api/chat/tools/registry")
    assert response.status_code == 503
    assert response.json() == {"detail": {"version": "1", "code": "AUTH_UNAVAILABLE"}}


def test_unsealed_principal_is_rejected_by_router(tmp_path: Path) -> None:
    bridge = ChatToolBridgeV1(mcp=None, audit=None)
    app = create_app(
        wave35_mount_dependencies=Wave35MountDependenciesV1(
            app_data_dir=tmp_path,
            model_registry=ModelRegistryV1(version="v1", entries=()),
            chat_tool_bridge=bridge,
            verified_principal_resolver=lambda _request: cast(VerifiedPrincipalV1, object()),
        )
    )
    with TestClient(app) as client:
        response = client.get("/api/chat/tools/registry")
    assert response.status_code == 401
    assert response.json() == {"detail": {"version": "1", "code": "UNAUTHENTICATED"}}


def test_app_route_adapter_has_closed_exact_allowlist_and_preserves_typed_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    routes = _Routes()
    adapter = AppRoutePortAdapterV1(routes)
    principal = cast(VerifiedPrincipalV1, object())
    monkeypatch.setattr(chat_tools_runtime, "_verified", lambda _value: True)

    allowed = asyncio.run(
        adapter.invoke(
            principal,
            route_id="orders.create_then_submit",
            arguments={"environment": "paper"},
            idempotency_key="chat-route-idem-0001",
        )
    )
    assert allowed.status_code == 202
    assert allowed.effect_performed is True
    assert routes.calls == ["orders.create_then_submit"]

    assert not any("live-activation" in route for route in CHAT_TOOL_APP_ROUTE_ALLOWLIST_V1)
    denied = asyncio.run(
        adapter.invoke(
            principal,
            route_id="live-activation.enable",
            arguments={"environment": "paper"},
            idempotency_key="chat-route-idem-0002",
        )
    )
    assert denied.status_code == 403
    assert denied.allowed is False
    assert denied.effect_performed is False
    assert denied.reason_codes == ("CHAT_ROUTE_DENIED",)
    assert routes.calls == ["orders.create_then_submit"]


def test_chat_tool_approval_is_digest_bound_and_single_use(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(chat_tools_runtime, "_verified", lambda _value: True)
    principal = cast(VerifiedPrincipalV1, SimpleNamespace(subject_id="synthetic-user"))
    now = 100
    store = ChatToolApprovalStoreV1(
        tmp_path / "chat" / "tool-approvals.sqlite3", now_ns=lambda: now
    )
    digest = "a" * 64
    confirmation = f"CONFIRM paper.orders.create_submit {digest[:12]}"
    proof = store.issue(
        principal,
        plan_id="plan-synthetic-1",
        account_id="account-synthetic-1",
        tool_id="paper.orders.create_submit",
        digest=digest,
        route="orders.create_then_submit",
        policy_revision="policy-synthetic-1",
        typed_confirmation=confirmation,
        expected_confirmation=confirmation,
        expires_at_ns=200,
    )
    kwargs = {
        "plan_id": "plan-synthetic-1",
        "digest": digest,
        "typed_confirmation": confirmation,
        "approval_proof": proof,
        "idempotency_key": "chat-idempotency-0001",
    }
    first = asyncio.run(store.verify_and_consume(principal, **kwargs))
    second = asyncio.run(store.verify_and_consume(principal, **kwargs))
    assert first.approved is True
    assert first.account_id == "account-synthetic-1"
    assert second.approved is False
    store.close()


def test_default_deny_composition_reuses_mcp_state_without_creating_authority(
    tmp_path: Path,
) -> None:
    app = FastAPI()
    app.state.mcp_control_runtime = None
    app.state.mcp_control_binding = None
    from leviathan_api.chat_tools_runtime import compose_chat_tools_runtime

    runtime = compose_chat_tools_runtime(
        app,
        bridge=None,
        app_data_dir=tmp_path,
        now_ns=lambda: 10,
    )
    assert runtime.configured is False
    assert runtime.bridge.registry.entries
    assert app.state.mcp_control_runtime is None
    assert app.state.mcp_control_binding is None
    runtime.approval_store.close()
