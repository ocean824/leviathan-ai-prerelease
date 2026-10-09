"""Black-box acceptance for the Wave 35 API router mounts."""

from __future__ import annotations

import asyncio
import base64
from collections import Counter
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient
from leviathan_store.chat_history import ChatHistoryStore
from leviathan_store.engine import create_engine_and_sessionmaker
from leviathan_store.preferences import PreferencesStore
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from leviathan_api.chat.models import (
    ChatApiShapeV1,
    ChatModelPublicV1,
    ChatRequestRecordV1,
    ChatResultV1,
    ChatStreamEventV1,
    ChatUsageV1,
)
from leviathan_api.chat.port import ChatModelPort
from leviathan_api.main import create_app
from leviathan_api.wave35_mounts import Wave35MountDependenciesV1
from leviathan_core.execution import broker_port_v1 as broker
from leviathan_core.execution.mt5_ea_host import (
    EaCapAssessmentV1,
    EaHostingServiceV1,
    issue_ea_cap_assessment,
)
from leviathan_core.execution.order_models import BrokerObservation, OrderState
from leviathan_core.risk.halt import HaltAuthority
from leviathan_core.security.authz_models import (
    _VERIFIER_MARKER,
    PrincipalV1,
    TrustedPrincipalAdapterV1,
    TrustedPrincipalV1,
)
from leviathan_market_data.providers.registry import (
    CredentialResolversV1,
    CredentialRouteV1,
    DataSourceRegistryV1,
    DataSourceStatusV1,
    ProviderHealthV1,
)

_EXPECTED_OPERATIONS = {
    ("/api/data-sources", "GET"),
    ("/api/preferences/{namespace}", "GET"),
    ("/api/preferences/{namespace}", "PUT"),
    ("/api/preferences/{namespace}", "DELETE"),
    ("/api/chat/history/conversations", "GET"),
    ("/api/chat/history/conversations", "POST"),
    ("/api/chat/history/conversations/{conversation_id}/messages", "GET"),
    ("/api/chat/history/conversations/{conversation_id}/messages", "POST"),
    ("/api/chat/history/conversations/{conversation_id}", "DELETE"),
    ("/api/chat/history/conversations/{conversation_id}/export", "GET"),
    ("/api/chat/models", "GET"),
    ("/api/chat/complete", "POST"),
    ("/api/chat/stream", "POST"),
    ("/api/connections/catalog", "GET"),
    ("/api/connections/status", "GET"),
    ("/api/connections/{provider}/connect", "POST"),
    ("/api/connections/{provider}/cancel", "POST"),
    ("/api/connections/{provider}/disconnect", "POST"),
    ("/api/mt5/ea-host/v1/install", "POST"),
    ("/api/mt5/ea-host/v1/sessions/{session_id}", "GET"),
    ("/api/mt5/ea-host/v1/sessions/{session_id}/kill", "POST"),
}


def test_real_create_app_mounts_each_wave35_operation_once_in_openapi() -> None:
    app = create_app()
    with TestClient(app):
        schema = app.openapi()
        documented = Counter(
            (path, method.upper())
            for path, methods in schema["paths"].items()
            for method in methods
            if method.lower() in {"get", "post", "put", "patch", "delete", "head", "options"}
        )

        assert set(documented) >= _EXPECTED_OPERATIONS
        assert all(documented[operation] == 1 for operation in _EXPECTED_OPERATIONS)


def test_unconfigured_wave35_mounts_fail_closed_without_startup_or_request_500() -> None:
    app = create_app(
        wave35_mount_dependencies=Wave35MountDependenciesV1(
            principal_resolver=lambda _request: _principal("synthetic-connection-operator")
        )
    )
    with TestClient(app) as client:
        data_sources = client.get("/api/data-sources")
        assert data_sources.status_code == 200
        source_rows = data_sources.json()["sources"]
        assert {row["provider_id"] for row in source_rows} >= {
            "fred",
            "bls",
            "bea",
            "eia",
            "unusual_whales",
        }
        assert all(row["status"] == "NOT_CONFIGURED" for row in source_rows)

        connection_catalog = client.get("/api/connections/catalog")
        connection_status = client.get("/api/connections/status")
        assert connection_catalog.status_code == 200
        assert connection_catalog.json() == {"providers": []}
        assert connection_status.status_code == 200
        assert connection_status.json() == {"connections": []}
        for action in ("connect", "cancel", "disconnect"):
            denied = client.post(f"/api/connections/alpaca/{action}")
            assert denied.status_code == 404
            assert denied.json() == {"error": {"code": "PROVIDER_NOT_FOUND"}}

        unconfigured_responses = (
            client.get("/api/preferences/workspace"),
            client.put(
                "/api/preferences/workspace",
                headers={"If-Match": "*"},
                json={"document": {"layout": "compact"}},
            ),
            client.delete("/api/preferences/workspace"),
            client.get("/api/chat/history/conversations"),
            client.post(
                "/api/chat/history/conversations",
                json={"title": "synthetic", "model_alias": "none"},
            ),
            client.get("/api/chat/history/conversations/synthetic/messages"),
            client.post(
                "/api/chat/history/conversations/synthetic/messages",
                json={"message_id": "m1", "role": "user", "content": "synthetic"},
            ),
            client.delete("/api/chat/history/conversations/synthetic"),
            client.get("/api/chat/history/conversations/synthetic/export"),
        )
        assert all(response.status_code == 503 for response in unconfigured_responses)
        assert all(
            response.json() == {"code": "NOT_CONFIGURED"} for response in unconfigured_responses
        )

        models = client.get("/api/chat/models")
        assert models.status_code == 200
        assert models.json() == {"models": []}

        chat_request = {
            "request_id": "synthetic-request",
            "model_alias": "missing",
            "messages": [{"role": "user", "content": "synthetic"}],
            "max_output_tokens": 16,
        }
        complete = client.post("/api/chat/complete", json=chat_request)
        stream = client.post(
            "/api/chat/stream",
            json={**chat_request, "stream": True},
        )
        assert complete.status_code == stream.status_code == 503
        assert complete.json() == stream.json() == {"code": "MODEL_NOT_CONFIGURED"}

        ea_responses = (
            client.post("/api/mt5/ea-host/v1/install", json={}),
            client.get("/api/mt5/ea-host/v1/sessions/synthetic-session"),
            client.post("/api/mt5/ea-host/v1/sessions/synthetic-session/kill"),
        )
        assert all(response.status_code == 503 for response in ea_responses)
        assert all(
            response.json() == {"error": {"code": "NOT_CONFIGURED"}} for response in ea_responses
        )
        assert all(
            response.status_code != 500 for response in unconfigured_responses + ea_responses
        )


def _principal(principal_id: str) -> TrustedPrincipalV1:
    claims = PrincipalV1(
        principal_id=principal_id,
        project_id="leviathan-ai",
        roles=("operator",),
        env="development",
    )
    return TrustedPrincipalAdapterV1.from_verified_claims(claims, verifier_marker=_VERIFIER_MARKER)


class _FakeChatService(ChatModelPort):
    def __init__(self) -> None:
        self.principals: list[str] = []

    def list_models(self, principal: TrustedPrincipalV1) -> tuple[ChatModelPublicV1, ...]:
        self.principals.append(principal.principal_id)
        return (
            ChatModelPublicV1(
                alias="synthetic.model",
                provider="synthetic",
                model_version="v1",
                registry_version="synthetic-v1",
                modalities=("text",),
                max_context_tokens=128,
                max_output_tokens=32,
            ),
        )

    async def complete(self, principal: TrustedPrincipalV1, request: Any) -> ChatResultV1:
        self.principals.append(principal.principal_id)
        record = ChatRequestRecordV1(
            request_id=request.request_id,
            model_alias=request.model_alias,
            api_shape=ChatApiShapeV1.OPENAI_CHAT_COMPLETIONS,
            registry_version="synthetic-v1",
            policy_version="synthetic-v1",
            elapsed_ns=1,
            usage=ChatUsageV1(input_tokens=1, output_tokens=1),
            cost_status="unavailable",
            cost_usd=None,
            hosted_egress_disclosed=request.hosted_egress_disclosed,
        )
        return ChatResultV1(
            events=(
                ChatStreamEventV1(event="start", request_id=request.request_id),
                ChatStreamEventV1(
                    event="text_delta", request_id=request.request_id, text_delta="synthetic"
                ),
                ChatStreamEventV1(
                    event="finish", request_id=request.request_id, finish_reason="stop"
                ),
            ),
            record=record,
        )

    def stream(
        self, principal: TrustedPrincipalV1, request: Any
    ) -> AsyncIterator[ChatStreamEventV1]:
        self.principals.append(principal.principal_id)

        async def events() -> AsyncIterator[ChatStreamEventV1]:
            yield ChatStreamEventV1(event="start", request_id=request.request_id)
            yield ChatStreamEventV1(
                event="text_delta", request_id=request.request_id, text_delta="synthetic"
            )
            yield ChatStreamEventV1(
                event="finish", request_id=request.request_id, finish_reason="stop"
            )

        return events()


class _FakeEaFilesystem:
    def __init__(self) -> None:
        self.installs: list[dict[str, object]] = []

    def install_pair(self, **kwargs: object) -> None:
        self.installs.append(kwargs)


class _FakeEaBridge:
    def __init__(self) -> None:
        self.observed_at = datetime.fromtimestamp(1_800_000_000, tz=UTC)
        self.venue = broker._issue_venue_identity(
            broker.BrokerVenue.MT5,
            broker.BrokerEnvironment.DEMO,
            "synthetic-demo-account",
        )
        self.disabled: list[str] = []
        self.closed: list[str] = []

    def read_account_view(self, _account_id: str) -> broker.AccountViewV1:
        order = BrokerObservation(
            observation_id="synthetic-ea-observation",
            environment="demo",
            account_id="synthetic-demo-account",
            venue="MT5",
            client_order_id="synthetic-ea-order",
            status=OrderState.WORKING,
            observed_at=self.observed_at,
            venue_order_id="synthetic-ea-venue-order",
        )
        return broker._issue_account_view(
            "synthetic-demo-account",
            (order,),
            (("EURUSD", Decimal("0.25")),),
            1,
            (),
            self.observed_at,
            complete=True,
            broker_observed_at=self.observed_at,
        )

    def disable_expert(self, session_id: str) -> bool:
        self.disabled.append(session_id)
        return True

    def close_all(self, _account_id: str) -> bool:
        self.closed.append(_account_id)
        return True


class _FakeEaCapEvaluator:
    def assess(self, view: broker.AccountViewV1, *, as_of_ns: int) -> EaCapAssessmentV1:
        return issue_ea_cap_assessment(view, status="WITHIN_CAPS", observed_at_ns=as_of_ns)


def test_configured_fake_services_work_and_user_stores_follow_only_trusted_principal(
    tmp_path: Path,
) -> None:
    sync_engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    preferences_store = PreferencesStore(sync_engine, clock_ns=lambda: 1_800_000_000_000_000_000)
    async_engine, sessions = create_engine_and_sessionmaker(
        f"sqlite+aiosqlite:///{(tmp_path / 'history.sqlite3').as_posix()}"
    )
    history_store = ChatHistoryStore(sessions)
    asyncio.run(history_store.initialize())
    active = {"principal": _principal("synthetic-user-a")}
    resolver_calls: list[str] = []

    def resolve_principal(_request: Any) -> TrustedPrincipalV1:
        selected = active["principal"]
        resolver_calls.append(selected.principal_id)
        return selected

    chat_service = _FakeChatService()
    bridge = _FakeEaBridge()
    filesystem = _FakeEaFilesystem()
    ea_service = EaHostingServiceV1(
        data_root=tmp_path / "synthetic-ea-root",
        bridge=bridge,
        filesystem=filesystem,
        cap_evaluator=_FakeEaCapEvaluator(),
        halt=HaltAuthority(),
        clock_ns=lambda: 1_800_000_000_000_000_000,
    )
    dependencies = Wave35MountDependenciesV1(
        principal_resolver=resolve_principal,
        preferences_store=preferences_store,
        chat_history_store=history_store,
        chat_model_service=chat_service,
        mt5_bridge_port=bridge,
        ea_host_service=ea_service,
    )

    try:
        with TestClient(create_app(wave35_mount_dependencies=dependencies)) as client:
            models = client.get("/api/chat/models")
            assert models.status_code == 200
            assert models.json()["models"][0]["alias"] == "synthetic.model"
            assert chat_service.principals == ["synthetic-user-a"]

            chat_request = {
                "request_id": "synthetic-chat-request",
                "model_alias": "synthetic.model",
                "messages": [{"role": "user", "content": "synthetic prompt"}],
                "max_output_tokens": 8,
            }
            completed = client.post("/api/chat/complete", json=chat_request)
            assert completed.status_code == 200
            assert completed.json()["record"]["request_id"] == "synthetic-chat-request"
            streamed = client.post("/api/chat/stream", json={**chat_request, "stream": True})
            assert streamed.status_code == 200
            assert "event: start" in streamed.text
            assert chat_service.principals == [
                "synthetic-user-a",
                "synthetic-user-a",
                "synthetic-user-a",
            ]

            preference = client.put(
                "/api/preferences/workspace?user_scope=synthetic-user-b",
                headers={"If-Match": "*", "X-User-Scope": "synthetic-user-b"},
                json={"document": {"private": "A-only"}},
            )
            assert preference.status_code == 200
            assert preference.json()["user_scope"] == "synthetic-user-a"

            created = client.post(
                "/api/chat/history/conversations?principal_id=synthetic-user-b",
                json={"title": "A-only", "model_alias": "synthetic.model"},
            )
            assert created.status_code == 201
            conversation_a = created.json()["conversation_id"]

            active["principal"] = _principal("synthetic-user-b")
            b_preferences = client.get(
                "/api/preferences/workspace?user_scope=synthetic-user-a",
                headers={"X-User-Scope": "synthetic-user-a"},
            )
            assert b_preferences.status_code == 404
            b_conversations = client.get("/api/chat/history/conversations")
            assert b_conversations.status_code == 200
            assert b_conversations.json()["conversations"] == []
            cross_scope = client.get(f"/api/chat/history/conversations/{conversation_a}/messages")
            assert cross_scope.status_code == 404
            assert cross_scope.json() == {"code": "NOT_FOUND"}

            active["principal"] = _principal("synthetic-ea-operator")
            install = client.post(
                "/api/mt5/ea-host/v1/install",
                json={
                    "ea_filename": "SyntheticRisk.ex5",
                    "ea_base64": base64.b64encode(b"synthetic EA bytes; never execute").decode(
                        "ascii"
                    ),
                    "set_filename": "SyntheticRisk.set",
                    "set_base64": base64.b64encode(b"synthetic preset only").decode("ascii"),
                    "terminal_family": "MT5",
                    "symbol": "EURUSD",
                    "timeframe": "M5",
                },
            )
            assert install.status_code == 201
            assert install.json()["execution_allowed"] is False
            assert len(filesystem.installs) == 1
            session_id = install.json()["session_id"]
            monitored = client.get(f"/api/mt5/ea-host/v1/sessions/{session_id}")
            assert monitored.status_code == 200
            assert monitored.json()["state"] == "MONITORING"
            assert monitored.json()["execution_allowed"] is False
            killed = client.post(f"/api/mt5/ea-host/v1/sessions/{session_id}/kill")
            assert killed.status_code == 200
            assert killed.json()["state"] == "STOPPED"
            assert bridge.disabled == [session_id]
            assert bridge.closed == ["synthetic-demo-account"]

            assert resolver_calls
            assert set(resolver_calls) == {
                "synthetic-user-a",
                "synthetic-user-b",
                "synthetic-ea-operator",
            }
    finally:
        sync_engine.dispose()
        asyncio.run(async_engine.dispose())


def test_injected_data_source_registry_resolves_only_synthetic_vault_credentials() -> None:
    from types import SimpleNamespace

    observed: list[str] = []
    secret = "synthetic-vault-secret-not-for-response"

    class SyntheticProvider:
        PROVIDER_ID = "synthetic.provider"
        CAPABILITIES = frozenset({"TEST_HEALTH"})
        CREDENTIAL_NAMES = ("api_key",)

        @staticmethod
        def build_adapter(*, resolve_secret: Any, transport: object) -> object:
            del transport
            observed.append(resolve_secret("api_key"))
            return SimpleNamespace(credential_loaded=True)

    registry = DataSourceRegistryV1()
    adapter = registry.register_module(
        SyntheticProvider,
        credential_route=CredentialRouteV1.VAULT_REF,
        credential_ref="vault://leviathan-ai/development/SYNTHETIC/DEFAULT",
        resolvers=CredentialResolversV1(vault_ref=lambda _ref, _name: secret),
        transport=object(),
    )
    assert adapter.credential_loaded is True
    assert observed == [secret]
    assert registry.get("synthetic.provider").status is DataSourceStatusV1.NOT_CONFIGURED
    registry.update_health(
        ProviderHealthV1(
            provider_id="synthetic.provider",
            status=DataSourceStatusV1.READY,
            source_time_ns=1_800_000_000_000_000_000,
            received_time_ns=1_800_000_000_000_000_000,
        )
    )
    app = create_app(
        wave35_mount_dependencies=Wave35MountDependenciesV1(data_source_registry=registry)
    )
    with TestClient(app) as client:
        response = client.get("/api/data-sources")
    assert response.status_code == 200
    body = response.text
    assert "synthetic.provider" in body
    assert "READY" in body
    assert secret not in body
