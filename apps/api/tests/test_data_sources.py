from __future__ import annotations

from collections.abc import Callable

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from leviathan_api.routers.data_sources import create_data_sources_router
from leviathan_market_data.providers.registry import (
    CredentialResolversV1,
    CredentialRouteV1,
    DataSourceRegistryV1,
    DataSourceStatusV1,
    HealthErrorCodeV1,
    ProviderHealthV1,
)


class FakeKeyedProvider:
    PROVIDER_ID = "safe_feed"
    CAPABILITIES = frozenset({"TRADES"})
    CREDENTIAL_NAMES: tuple[str, ...] = ("api_key",)

    @staticmethod
    def build_adapter(*, resolve_secret: Callable[[str], str], transport: object) -> object:
        return object()


class FakePublicProvider:
    PROVIDER_ID = "public_feed"
    CAPABILITIES = frozenset({"QUOTES"})
    CREDENTIAL_NAMES: tuple[str, ...] = ()

    @staticmethod
    def build_adapter(*, resolve_secret: Callable[[str], str], transport: object) -> object:
        return object()


def test_status_endpoint_returns_safe_registered_source_health() -> None:
    registry = DataSourceRegistryV1()
    registry.register_module(
        FakeKeyedProvider(),
        credential_route=CredentialRouteV1.VAULT_REF,
        credential_ref="vault://leviathan-ai/development/SAFE_FEED/DEFAULT",
        resolvers=CredentialResolversV1(vault_ref=lambda _ref, _name: "secret-must-not-appear"),
        transport=object(),
    )
    registry.update_health(
        ProviderHealthV1(
            provider_id="safe_feed",
            status=DataSourceStatusV1.DEGRADED,
            source_time_ns=123,
            received_time_ns=145,
            error_code=HealthErrorCodeV1.NETWORK_UNAVAILABLE,
        )
    )
    app = FastAPI()
    app.include_router(create_data_sources_router(registry))

    response = TestClient(app).get("/data-sources")

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    body = response.json()
    assert body == {
        "schema_version": "leviathan.data-sources/1",
        "sources": [
            {
                "provider_id": "safe_feed",
                "display_name": "Safe Feed",
                "capabilities": ["TRADES"],
                "requires_credentials": True,
                "credential_route": "vault_ref",
                "status": "DEGRADED",
                "source_time_ns": 123,
                "received_time_ns": 145,
                "error_code": "NETWORK_UNAVAILABLE",
            }
        ],
    }
    assert "vault://" not in response.text
    assert "secret-must-not-appear" not in response.text


def test_missing_health_is_not_configured_and_unknown_provider_is_absent() -> None:
    registry = DataSourceRegistryV1()
    registry.register_module(
        FakePublicProvider(),
        credential_route=None,
        credential_ref=None,
        resolvers=CredentialResolversV1(),
        transport=object(),
    )
    app = FastAPI()
    app.include_router(create_data_sources_router(registry))

    response = TestClient(app).get("/data-sources")

    assert response.status_code == 200
    row = response.json()["sources"][0]
    assert row["status"] == "NOT_CONFIGURED"
    assert row["source_time_ns"] is None
    assert row["received_time_ns"] is None
    assert row["error_code"] is None


def test_registry_failure_is_content_free(monkeypatch: pytest.MonkeyPatch) -> None:
    registry = DataSourceRegistryV1()
    monkeypatch.setattr(
        DataSourceRegistryV1,
        "list_sources",
        lambda _self: (_ for _ in ()).throw(RuntimeError("secret input")),
    )
    app = FastAPI()
    app.include_router(create_data_sources_router(registry))

    response = TestClient(app).get("/data-sources")

    assert response.status_code == 503
    assert response.json() == {"code": "DATA_SOURCES_UNAVAILABLE"}
    assert "secret input" not in response.text
