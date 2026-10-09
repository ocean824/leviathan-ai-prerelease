from __future__ import annotations

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


def _registered_registry() -> tuple[DataSourceRegistryV1, str]:
    registry = DataSourceRegistryV1()
    gateway_material = "fixture-proxy-material-never-return-this"
    module = type(
        "GatewayProvider",
        (),
        {
            "PROVIDER_ID": "gateway.feed",
            "CAPABILITIES": frozenset({"TRADES", "QUOTES"}),
            "CREDENTIAL_NAMES": ("api_key",),
            "build_adapter": staticmethod(
                lambda *, resolve_secret, transport: object()
            ),
        },
    )
    registry.register_module(
        module,
        credential_route=CredentialRouteV1.GATEWAY,
        credential_ref=None,
        resolvers=CredentialResolversV1(
            gateway=lambda _provider_id, _name: gateway_material
        ),
        transport=object(),
    )
    registry.update_health(
        ProviderHealthV1(
            provider_id="gateway.feed",
            status=DataSourceStatusV1.DEGRADED,
            source_time_ns=1_800_000_000_000_000_101,
            received_time_ns=1_800_000_000_000_000_117,
            error_code=HealthErrorCodeV1.SOURCE_STALE,
        )
    )
    return registry, gateway_material


def test_router_factory_is_unmounted_and_returns_only_sanitized_source_health() -> None:
    registry, gateway_material = _registered_registry()
    router = create_data_sources_router(registry)
    app = FastAPI()

    # Creating the router does not install it into an application.
    assert TestClient(app).get("/data-sources").status_code == 404

    app.include_router(router)
    response = TestClient(app).get("/data-sources")

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.json() == {
        "schema_version": "leviathan.data-sources/1",
        "sources": [
            {
                "provider_id": "gateway.feed",
                "display_name": "Gateway.Feed",
                "capabilities": ["QUOTES", "TRADES"],
                "requires_credentials": True,
                "credential_route": "gateway",
                "status": "DEGRADED",
                "source_time_ns": 1_800_000_000_000_000_101,
                "received_time_ns": 1_800_000_000_000_000_117,
                "error_code": "SOURCE_STALE",
            }
        ],
    }
    assert "credential_ref" not in response.text
    assert "vault://" not in response.text
    assert gateway_material not in response.text


def test_unavailable_registry_response_is_content_free(monkeypatch) -> None:
    registry = DataSourceRegistryV1()
    secret_error = "provider key=fixture-secret-never-return-this"

    def fail_list_sources(self):
        raise RuntimeError(secret_error)

    monkeypatch.setattr(DataSourceRegistryV1, "list_sources", fail_list_sources)
    app = FastAPI()
    app.include_router(create_data_sources_router(registry))

    response = TestClient(app).get("/data-sources")

    assert response.status_code == 503
    assert response.headers["cache-control"] == "no-store"
    assert response.json() == {"code": "DATA_SOURCES_UNAVAILABLE"}
    assert secret_error not in response.text
