from __future__ import annotations

import base64
import time
from collections.abc import Iterator

import pytest
from fastapi import FastAPI
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from leviathan_api.connections_runtime import (
    AuthMethodV1,
    CapabilityV1,
    ConnectInitiateV1,
    ConnectInitiationV1,
    ConnectionActionResultV1,
    ConnectionActionV1,
    ConnectionCatalogEntryV1,
    ConnectionCatalogV1,
    ConnectionsRuntimeV1,
    ConnectionStateV1,
    ConnectionStatusV1,
    CredentialConnectInitiateV1,
    EnvironmentV1,
    ProviderV1,
)
from leviathan_api.routers.connections import create_connections_router
from leviathan_core.security.authz_models import (
    _VERIFIER_MARKER,
    PrincipalV1,
    TrustedPrincipalAdapterV1,
)

_NOW_NS = time.time_ns()


def _principal(
    *,
    project_id: str = "project-a",
    roles: tuple[str, ...] = ("operator",),
    environment: str = "paper",
) -> object:
    claims = PrincipalV1(
        principal_id="operator-1",
        project_id=project_id,
        roles=roles,
        env=environment,
    )
    return TrustedPrincipalAdapterV1.from_verified_claims(claims, verifier_marker=_VERIFIER_MARKER)


def _entry(
    provider: ProviderV1,
    *,
    method: AuthMethodV1 = "api_key",
    environments: tuple[EnvironmentV1, ...] = (EnvironmentV1.PAPER,),
    default_route: bool = False,
) -> ConnectionCatalogEntryV1:
    return ConnectionCatalogEntryV1(
        provider_id=provider,
        capabilities=(CapabilityV1.ACCOUNT_READ,),
        environments=environments,
        auth_method=method,
        default_route=default_route,
    )


class _FakePorts:
    def __init__(self) -> None:
        self.calls: list[tuple[object, ...]] = []
        self.provider = ProviderV1.SNAPTRADE
        self.catalog = ConnectionCatalogV1(
            providers=(
                _entry(ProviderV1.SNAPTRADE, method="oauth"),
                _entry(ProviderV1.ALPACA, method="api_key"),
            )
        )
        self.connect_result: ConnectInitiationV1 = CredentialConnectInitiateV1(
            provider_id=ProviderV1.ALPACA,
            environment=EnvironmentV1.PAPER,
            auth_method="api_key",
            credential_entry_handle="entry-handle-01",
        )

    def get_catalog(self, project_id: str) -> ConnectionCatalogV1:
        self.calls.append(("catalog", project_id))
        return self.catalog

    def get_status(
        self, project_id: str, environment: EnvironmentV1
    ) -> tuple[ConnectionStatusV1, ...]:
        self.calls.append(("status", project_id, environment))
        return (
            ConnectionStatusV1(
                provider_id=ProviderV1.ALPACA,
                environment=environment,
                state=ConnectionStateV1.DISCONNECTED,
                configured=False,
            ),
        )

    def initiate_connect(
        self, project_id: str, provider: ProviderV1, environment: EnvironmentV1
    ) -> ConnectInitiationV1:
        self.calls.append(("connect", project_id, provider, environment))
        return self.connect_result

    def cancel_connect(
        self, project_id: str, provider: ProviderV1, environment: EnvironmentV1
    ) -> ConnectionActionV1:
        self.calls.append(("cancel", project_id, provider, environment))
        return ConnectionActionV1(
            provider_id=provider,
            environment=environment,
            result=ConnectionActionResultV1.CANCELLED,
        )

    def disconnect(
        self, project_id: str, provider: ProviderV1, environment: EnvironmentV1
    ) -> ConnectionActionV1:
        self.calls.append(("disconnect", project_id, provider, environment))
        return ConnectionActionV1(
            provider_id=provider,
            environment=environment,
            result=ConnectionActionResultV1.DISCONNECTED,
        )


def _app(*, principal: object | None, ports: _FakePorts | None = None) -> FastAPI:
    app = FastAPI()
    selected = _FakePorts() if ports is None else ports
    runtime = ConnectionsRuntimeV1(
        catalog_port=selected,
        status_port=selected,
        connect_port=selected,
        cancel_port=selected,
        disconnect_port=selected,
        clock_ns=lambda: _NOW_NS,
        oauth_host_allowlist=((ProviderV1.SNAPTRADE, "auth.example.invalid"),),
    )
    app.include_router(create_connections_router(runtime))

    if principal is not None:

        @app.middleware("http")
        async def inject_principal(request, call_next):  # type: ignore[no-untyped-def]
            request.state.trusted_principal = principal
            return await call_next(request)

    return app


@pytest.fixture
def client() -> Iterator[TestClient]:
    with TestClient(_app(principal=_principal())) as active:
        yield active


def test_catalog_and_status_are_scoped_to_issued_project_and_environment() -> None:
    ports = _FakePorts()
    with TestClient(_app(principal=_principal(project_id="project-b"), ports=ports)) as client:
        catalog = client.get("/connections/catalog")
        status = client.get("/connections/status")

    assert catalog.status_code == 200
    assert catalog.json() == {
        "providers": [
            {
                "provider_id": "snaptrade",
                "capabilities": ["ACCOUNT_READ"],
                "environments": ["PAPER"],
                "auth_method": "oauth",
                "default_route": False,
            },
            {
                "provider_id": "alpaca",
                "capabilities": ["ACCOUNT_READ"],
                "environments": ["PAPER"],
                "auth_method": "api_key",
                "default_route": False,
            },
        ]
    }
    assert status.status_code == 200
    assert status.json()["connections"][0]["environment"] == "PAPER"
    assert ports.calls == [
        ("catalog", "project-b"),
        ("catalog", "project-b"),
        ("status", "project-b", EnvironmentV1.PAPER),
    ]


def test_missing_and_forged_principal_are_rejected_before_port_calls() -> None:
    ports = _FakePorts()
    with TestClient(_app(principal=None, ports=ports)) as client:
        response = client.get("/connections/catalog")
    assert response.status_code == 401
    assert response.json() == {"error": {"code": "PRINCIPAL_UNTRUSTED"}}
    assert ports.calls == []

    with TestClient(_app(principal={"project_id": "project-a"}, ports=ports)) as client:
        forged = client.get("/connections/status")
    assert forged.status_code == 401
    assert forged.json() == {"error": {"code": "PRINCIPAL_UNTRUSTED"}}
    assert ports.calls == []


def test_issued_principal_without_operator_role_gets_forbidden() -> None:
    ports = _FakePorts()
    with TestClient(_app(principal=_principal(roles=("viewer",)), ports=ports)) as client:
        response = client.post("/connections/alpaca/connect")
    assert response.status_code == 403
    assert response.json() == {"error": {"code": "CONNECTION_FORBIDDEN"}}
    assert ports.calls == []


def test_api_key_connect_returns_only_credential_entry_handle(client: TestClient) -> None:
    response = client.post("/connections/alpaca/connect")
    assert response.status_code == 202
    assert response.json() == {
        "provider_id": "alpaca",
        "environment": "PAPER",
        "auth_method": "api_key",
        "credential_entry_handle": "entry-handle-01",
    }
    assert "secret" not in response.text.lower()


def test_oauth_connect_requires_allowlisted_host_and_bounded_single_use_state(
    client: TestClient,
) -> None:
    state = base64.urlsafe_b64encode(b"s" * 32).decode("ascii").rstrip("=")
    redirect_uri = "http://127.0.0.1:54321/callback"
    ports = _FakePorts()
    ports.connect_result = ConnectInitiateV1(
        provider_id=ProviderV1.SNAPTRADE,
        environment=EnvironmentV1.PAPER,
        auth_method="oauth",
        authorization_url=(
            "https://auth.example.invalid/authorize?client_id=public&response_type=code"
            f"&redirect_uri={redirect_uri}&state={state}"
        ),
        authorization_host="auth.example.invalid",
        redirect_uri=redirect_uri,
        state=state,
        expires_at_ns=str(_NOW_NS + 600_000_000_000),
        single_use=True,
        request_id="req-0001",
    )
    with TestClient(_app(principal=_principal(), ports=ports)) as oauth_client:
        response = oauth_client.post("/connections/snaptrade/connect")
    assert response.status_code == 202
    assert response.json()["provider_id"] == "snaptrade"
    assert response.json()["authorization_host"] == "auth.example.invalid"
    assert response.json()["state"] == state
    assert response.json()["single_use"] is True
    assert response.json()["expires_at_ns"] == str(_NOW_NS + 600_000_000_000)

    ports.connect_result = ConnectInitiateV1(
        provider_id=ProviderV1.SNAPTRADE,
        environment=EnvironmentV1.PAPER,
        auth_method="oauth",
        authorization_url=(
            "https://attacker.invalid/authorize?client_id=public&response_type=code"
            f"&redirect_uri={redirect_uri}&state={state}"
        ),
        authorization_host="attacker.invalid",
        redirect_uri=redirect_uri,
        state=state,
        expires_at_ns=str(_NOW_NS + 600_000_000_000),
        single_use=True,
        request_id="req-0002",
    )
    with TestClient(_app(principal=_principal(), ports=ports)) as oauth_client:
        rejected = oauth_client.post("/connections/snaptrade/connect")
    assert rejected.status_code == 503
    assert rejected.json() == {"error": {"code": "CONNECTIONS_UNAVAILABLE"}}
    assert "attacker.invalid" not in rejected.text
    assert state not in rejected.text

    for invalid_expiry in (
        str(_NOW_NS - 1),
        str(_NOW_NS + 600_000_000_001),
    ):
        ports.connect_result = ConnectInitiateV1(
            provider_id=ProviderV1.SNAPTRADE,
            environment=EnvironmentV1.PAPER,
            auth_method="oauth",
            authorization_url=(
                "https://auth.example.invalid/authorize?client_id=public"
                f"&response_type=code&redirect_uri={redirect_uri}&state={state}"
            ),
            authorization_host="auth.example.invalid",
            redirect_uri=redirect_uri,
            state=state,
            expires_at_ns=invalid_expiry,
            single_use=True,
            request_id="req-expiry",
        )
        with TestClient(_app(principal=_principal(), ports=ports)) as oauth_client:
            invalid = oauth_client.post("/connections/snaptrade/connect")
        assert invalid.status_code == 503
        assert invalid.json() == {"error": {"code": "CONNECTIONS_UNAVAILABLE"}}
        assert state not in invalid.text

    ports.connect_result = ConnectInitiateV1(
        provider_id=ProviderV1.SNAPTRADE,
        environment=EnvironmentV1.PAPER,
        auth_method="oauth",
        authorization_url=(
            "https://auth.example.invalid/authorize?client_id=public&client_secret=LEAK"
            f"&response_type=code&redirect_uri={redirect_uri}&state={state}"
        ),
        authorization_host="auth.example.invalid",
        redirect_uri=redirect_uri,
        state=state,
        expires_at_ns=str(_NOW_NS + 60_000_000_000),
        single_use=True,
        request_id="req-url-secret",
    )
    with TestClient(_app(principal=_principal(), ports=ports)) as oauth_client:
        secret_query = oauth_client.post("/connections/snaptrade/connect")
    assert secret_query.status_code == 503
    assert "LEAK" not in secret_query.text
    assert "client_secret" not in secret_query.text


def test_connect_rejects_credential_request_body_without_echo_or_forwarding(
    client: TestClient,
) -> None:
    canary = "credential-secret-canary"
    response = client.post(
        "/connections/alpaca/connect", json={"api_key": canary, "secret": canary}
    )
    assert response.status_code == 400
    assert response.json() == {"error": {"code": "UNSUPPORTED_BODY"}}
    assert canary not in response.text


@pytest.mark.parametrize(
    ("path", "expected"),
    (
        ("/connections/alpaca/cancel", "CANCELLED"),
        ("/connections/alpaca/disconnect", "DISCONNECTED"),
    ),
)
def test_cancel_and_disconnect_are_scoped_allowlisted_actions(
    client: TestClient, path: str, expected: str
) -> None:
    response = client.post(path)
    assert response.status_code == 200
    assert response.json()["result"] == expected


def test_unknown_provider_and_live_scope_are_fixed_denials(client: TestClient) -> None:
    unknown = client.post("/connections/not_a_provider/connect")
    assert unknown.status_code == 404
    assert unknown.json() == {"error": {"code": "PROVIDER_NOT_FOUND"}}

    live_ports = _FakePorts()
    live_ports.catalog = ConnectionCatalogV1(
        providers=(_entry(ProviderV1.ALPACA, environments=(EnvironmentV1.LIVE,)),)
    )
    with TestClient(
        _app(principal=_principal(environment="live"), ports=live_ports)
    ) as live_client:
        unsupported = live_client.post("/connections/alpaca/connect")
    assert unsupported.status_code == 403
    assert unsupported.json() == {"error": {"code": "CONNECTION_FORBIDDEN"}}
    assert not any(call[0] == "connect" for call in live_ports.calls)


def test_missing_ports_and_port_exceptions_are_fixed_503() -> None:
    empty_runtime = ConnectionsRuntimeV1()
    app = FastAPI()
    app.include_router(create_connections_router(empty_runtime))

    @app.middleware("http")
    async def inject_empty_runtime_principal(request, call_next):  # type: ignore[no-untyped-def]
        request.state.trusted_principal = _principal()
        return await call_next(request)

    with TestClient(app) as client:
        response = client.get("/connections/catalog")
    assert response.status_code == 503
    assert response.json() == {"error": {"code": "CONNECTIONS_UNAVAILABLE"}}

    class BrokenCatalog:
        def get_catalog(self, project_id: str) -> ConnectionCatalogV1:
            raise RuntimeError("secret-canary-must-not-escape")

    broken_runtime = ConnectionsRuntimeV1(catalog_port=BrokenCatalog())
    broken_app = FastAPI()
    broken_app.include_router(create_connections_router(broken_runtime))

    @broken_app.middleware("http")
    async def inject(request, call_next):  # type: ignore[no-untyped-def]
        request.state.trusted_principal = _principal()
        return await call_next(request)

    with TestClient(broken_app) as client:
        unavailable = client.get("/connections/catalog")
    assert unavailable.status_code == 503
    assert unavailable.json() == {"error": {"code": "CONNECTIONS_UNAVAILABLE"}}
    assert "secret-canary" not in unavailable.text


def test_router_exposes_no_order_or_live_enable_endpoint(client: TestClient) -> None:
    paths = {
        route.path
        for route in create_connections_router(ConnectionsRuntimeV1()).routes
        if isinstance(route, APIRoute)
    }
    assert paths == {
        "/connections/catalog",
        "/connections/status",
        "/connections/{provider}/connect",
        "/connections/{provider}/cancel",
        "/connections/{provider}/disconnect",
    }
    assert not any("order" in path or "live" in path for path in paths)
