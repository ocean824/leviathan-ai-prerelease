from __future__ import annotations

import asyncio
import base64
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from leviathan_store import create_engine_and_sessionmaker
from leviathan_store.chat_history import ChatHistoryStore
from leviathan_store.preferences import UserPreferencesV1

from leviathan_api.chat.models import ChatModelPublicV1, ChatRequestV1, ChatStreamEventV1
from leviathan_api.main import create_app
from leviathan_api.wave35_mounts import Wave35MountDependenciesV1
from leviathan_core.execution.broker_port_v1 import (
    BrokerEnvironment,
    BrokerVenue,
    _issue_venue_identity,
)
from leviathan_core.execution.mt5_ea_host import EaHostingServiceV1
from leviathan_core.risk.halt import HaltAuthority
from leviathan_core.risk.halt_store import (
    HaltStore,
    ProfileClassification,
    ProfileEvidence,
)
from leviathan_core.security.authz_models import (
    _VERIFIER_MARKER,
    PrincipalV1,
    TrustedPrincipalAdapterV1,
    TrustedPrincipalV1,
)
from leviathan_market_data.providers.registry import (
    CredentialResolversV1,
    DataSourceRegistryV1,
)


def _principal() -> TrustedPrincipalV1:
    return TrustedPrincipalAdapterV1.from_verified_claims(
        PrincipalV1(
            principal_id="w35-operator",
            project_id="leviathan-ai",
            roles=("operator",),
            env="development",
        ),
        verifier_marker=_VERIFIER_MARKER,
    )


class _PublicProvider:
    PROVIDER_ID = "w35_fake"
    CAPABILITIES = frozenset({"QUOTES"})
    CREDENTIAL_NAMES: tuple[str, ...] = ()

    @staticmethod
    def build_adapter(*, resolve_secret: Any, transport: object) -> object:
        del resolve_secret, transport
        return object()


class _Preferences:
    def get(self, user_scope: str, namespace: str) -> UserPreferencesV1 | None:
        if (user_scope, namespace) not in self.records:
            return None
        return self.records[(user_scope, namespace)]

    def put(
        self,
        user_scope: str,
        namespace: str,
        document: dict[str, object],
        *,
        if_match: str,
    ) -> UserPreferencesV1:
        del if_match
        record = UserPreferencesV1(
            schema_version=1,
            user_scope=user_scope,
            namespace=namespace,
            document=document,
            updated_at_ns=100,
            revision=1,
        )
        self.records[(user_scope, namespace)] = record
        return record

    def delete(self, user_scope: str, namespace: str) -> None:
        self.records.pop((user_scope, namespace), None)

    def __init__(self) -> None:
        self.records: dict[tuple[str, str], UserPreferencesV1] = {}


class _ChatService:
    def list_models(self, _principal: TrustedPrincipalV1) -> tuple[ChatModelPublicV1, ...]:
        self.list_calls += 1
        return ()

    async def complete(self, _principal: TrustedPrincipalV1, _request: ChatRequestV1) -> Any:
        return _DumpResult({"status": "complete"})

    def stream(
        self, _principal: TrustedPrincipalV1, request: ChatRequestV1
    ) -> AsyncIterator[ChatStreamEventV1]:
        async def events() -> AsyncIterator[ChatStreamEventV1]:
            yield ChatStreamEventV1(event="start", request_id=request.request_id)

        return events()

    def __init__(self) -> None:
        self.list_calls = 0


class _DumpResult:
    def __init__(self, value: dict[str, str]) -> None:
        self.value = value

    def model_dump(self, *, mode: str) -> dict[str, str]:
        del mode
        return self.value


class _Mt5Bridge:
    venue = _issue_venue_identity(BrokerVenue.MT5, BrokerEnvironment.DEMO, "account-1")

    def read_account_view(self, _account_id: str) -> Any:
        raise RuntimeError("not needed by install")

    def disable_expert(self, _session_id: str) -> bool:
        return True

    def close_all(self, _account_id: str) -> bool:
        return True


class _Filesystem:
    def install_pair(self, **_kwargs: object) -> None:
        return None


def _ea_service(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[EaHostingServiceV1, _Mt5Bridge, HaltStore]:
    halt_path = tmp_path / "w35-halt.sqlite3"
    HaltStore.provision_new(
        halt_path,
        tmp_path,
        ProfileEvidence(
            ProfileClassification.NEVER_PROVISIONED,
            verified=True,
            references=("test:w35",),
        ),
    )
    store = HaltStore(halt_path, tmp_path)
    bridge = _Mt5Bridge()
    service = EaHostingServiceV1(
        data_root=tmp_path / "ea",
        bridge=bridge,
        filesystem=_Filesystem(),
        cap_evaluator=None,
        halt=HaltAuthority(store),
        clock_ns=lambda: 1_800_000_000_000_000_000,
    )
    del monkeypatch
    return service, bridge, store


def test_create_app_registers_all_mounts_and_fails_closed(client: TestClient) -> None:
    schema = client.get("/openapi.json").json()
    paths = schema["paths"]
    expected = {
        "/api/data-sources",
        "/api/preferences/{namespace}",
        "/api/chat/history/conversations",
        "/api/chat/models",
        "/api/chat/complete",
        "/api/chat/stream",
        "/api/mt5/ea-host/v1/install",
        "/api/mt5/ea-host/v1/sessions/{session_id}",
        "/api/mt5/ea-host/v1/sessions/{session_id}/kill",
        "/api/connections/catalog",
        "/api/connections/status",
    }
    assert expected <= set(paths)

    sources = client.get("/api/data-sources")
    assert sources.status_code == 200
    assert len(sources.json()["sources"]) == 7
    assert {row["status"] for row in sources.json()["sources"]} == {"NOT_CONFIGURED"}

    assert client.get("/api/preferences/test.pref").json() == {"code": "NOT_CONFIGURED"}
    assert client.get("/api/chat/history/conversations").json() == {"code": "NOT_CONFIGURED"}
    assert client.get("/api/chat/models").status_code == 200
    assert client.get("/api/chat/models").json() == {"models": []}
    assert client.post("/api/chat/complete", json={}).json() == {"code": "MODEL_NOT_CONFIGURED"}
    assert client.post("/api/chat/stream", json={}).json() == {"code": "MODEL_NOT_CONFIGURED"}
    assert client.post("/api/mt5/ea-host/v1/install", json={}).json() == {
        "error": {"code": "NOT_CONFIGURED"}
    }
    assert client.get("/api/mt5/ea-host/v1/sessions/session-1").json() == {
        "error": {"code": "NOT_CONFIGURED"}
    }
    assert client.post("/api/mt5/ea-host/v1/sessions/session-1/kill", json={}).json() == {
        "error": {"code": "NOT_CONFIGURED"}
    }
    assert client.get("/api/connections/catalog").status_code == 401
    assert client.get("/api/connections/status").status_code == 401


def test_configured_registry_preferences_history_chat_and_mt5(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    principal = _principal()
    registry = DataSourceRegistryV1()
    registry.register_module(
        _PublicProvider(),
        credential_route=None,
        credential_ref=None,
        resolvers=CredentialResolversV1(),
        transport=object(),
    )
    history_engine, sessions = create_engine_and_sessionmaker(
        f"sqlite+aiosqlite:///{(tmp_path / 'history.sqlite3').as_posix()}"
    )
    history_store = ChatHistoryStore(sessions)
    asyncio.run(history_store.initialize())
    preferences_store = _Preferences()
    chat_service = _ChatService()
    ea_service, bridge, halt_store = _ea_service(tmp_path, monkeypatch)
    dependencies = Wave35MountDependenciesV1(
        data_source_registry=registry,
        preferences_store=preferences_store,
        chat_history_store=history_store,
        chat_model_service=chat_service,
        mt5_bridge_port=bridge,
        ea_host_service=ea_service,
        principal_resolver=lambda _request: principal,
        clock_ns=lambda: 1_800_000_000_000_000_000,
    )
    app = create_app(wave35_mount_dependencies=dependencies)
    try:
        with TestClient(app) as client:
            assert client.get("/api/connections/catalog").json() == {"providers": []}
            assert client.get("/api/connections/status").json() == {"connections": []}
            source_rows = client.get("/api/data-sources").json()["sources"]
            assert source_rows[0]["provider_id"] == "w35_fake"

        pref = client.put(
            "/api/preferences/test.pref",
            headers={"If-Match": "*"},
            json={"document": {"theme": "dark"}},
        )
        assert pref.status_code == 200
        assert pref.json()["document"] == {"theme": "dark"}

        history = client.post(
            "/api/chat/history/conversations",
            json={"title": "hello", "model_alias": "safe"},
        )
        assert history.status_code == 201

        models = client.get("/api/chat/models")
        assert models.status_code == 200
        assert chat_service.list_calls == 1
        completed = client.post(
            "/api/chat/complete",
            json={
                "request_id": "w35-request",
                "model_alias": "safe",
                "messages": [{"role": "user", "content": "hello"}],
                "max_output_tokens": 8,
            },
        )
        assert completed.status_code == 200
        assert completed.json() == {"status": "complete"}

        installed = client.post(
            "/api/mt5/ea-host/v1/install",
            json={
                "ea_filename": "demo.ex5",
                "ea_base64": base64.b64encode(b"ea").decode("ascii"),
                "set_filename": "demo.set",
                "set_base64": base64.b64encode(b"set").decode("ascii"),
                "terminal_family": "MT5",
                "symbol": "EURUSD",
                "timeframe": "M1",
            },
        )
        assert installed.status_code == 201
        assert installed.json()["execution_allowed"] is False
    finally:
        asyncio.run(history_engine.dispose())
        halt_store.close()
