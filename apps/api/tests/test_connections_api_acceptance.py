"""Independent public-contract acceptance tests for the local connections API."""

from __future__ import annotations

import base64
from collections.abc import Iterator
from contextlib import contextmanager
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from leviathan_api.auth import OperatorPrincipalMiddleware, make_local_operator_profile
from leviathan_api.connections_runtime import (
    CapabilityV1,
    ConnectInitiateV1,
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

_BASE_URL = "http://127.0.0.1:49381"
_PORT = 49381
_CAPABILITY = "a1" * 32
_PROJECT = "conn003-project"
_CANARY = "CONN003_SYNTHETIC_CREDENTIAL_CANARY_7FQ9V6_PRIVATE"
_NOW_NS = 1_800_000_000_000_000_000
_AUTHORIZATION_HOST = "oauth.fixture.test"
_REDIRECT_URI = f"{_BASE_URL}/callback"


def _catalog() -> ConnectionCatalogV1:
    return ConnectionCatalogV1(
        providers=(
            ConnectionCatalogEntryV1(
                provider_id=ProviderV1.ALPACA,
                capabilities=(CapabilityV1.ACCOUNT_READ, CapabilityV1.API_KEY_CONNECT),
                environments=(EnvironmentV1.PAPER,),
                auth_method="api_key",
                default_route=False,
            ),
            ConnectionCatalogEntryV1(
                provider_id=ProviderV1.SNAPTRADE,
                capabilities=(CapabilityV1.ACCOUNT_READ, CapabilityV1.OAUTH_CONNECT),
                environments=(EnvironmentV1.PAPER,),
                auth_method="oauth",
                default_route=True,
            ),
        )
    )


class _FakePorts:
    """Injected ports retain a canary but expose only the public DTOs."""

    def __init__(self, *, catalog: ConnectionCatalogV1 | None = None) -> None:
        self.catalog = _catalog() if catalog is None else catalog
        self.credential_store = {"api_key": _CANARY}
        self.calls: list[tuple[object, ...]] = []
        self.order_calls = 0
        self.fail_catalog = False
        self.oauth_url_canary = False
        self.state_counter = 0
        self.disconnect_counter = 0

    def get_catalog(self, project_id: str) -> ConnectionCatalogV1:
        self.calls.append(("catalog", project_id))
        if self.fail_catalog:
            raise RuntimeError(f"provider error {_CANARY}")
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
    ) -> ConnectInitiateV1 | CredentialConnectInitiateV1:
        self.calls.append(("connect", project_id, provider, environment))
        if provider is ProviderV1.ALPACA:
            return CredentialConnectInitiateV1(
                provider_id=provider,
                environment=environment,
                auth_method="api_key",
                credential_entry_handle="vault-handle-conn003",
            )
        self.state_counter += 1
        state_bytes = b"conn003-state-" + self.state_counter.to_bytes(2, "big")
        state_bytes = state_bytes.ljust(32, b"x")
        state = base64.urlsafe_b64encode(state_bytes).decode("ascii").rstrip("=")
        query_values = {"state": state, "redirect_uri": _REDIRECT_URI}
        if self.oauth_url_canary:
            query_values["client_secret"] = _CANARY
        query = urlencode(query_values)
        return ConnectInitiateV1(
            provider_id=provider,
            environment=environment,
            auth_method="oauth",
            authorization_url=f"https://{_AUTHORIZATION_HOST}/authorize?{query}",
            authorization_host=_AUTHORIZATION_HOST,
            redirect_uri=_REDIRECT_URI,
            state=state,
            expires_at_ns=str(_NOW_NS + 300_000_000_000),
            single_use=True,
            request_id=f"conn003-request-{self.state_counter:02d}",
        )

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
        self.disconnect_counter += 1
        result = (
            ConnectionActionResultV1.DISCONNECTED
            if self.disconnect_counter == 1
            else ConnectionActionResultV1.ALREADY_DISCONNECTED
        )
        return ConnectionActionV1(
            provider_id=provider,
            environment=environment,
            result=result,
        )


def _runtime(ports: _FakePorts, *, missing: str | None = None) -> ConnectionsRuntimeV1:
    return ConnectionsRuntimeV1(
        catalog_port=None if missing == "catalog" else ports,
        status_port=None if missing == "status" else ports,
        connect_port=None if missing == "connect" else ports,
        cancel_port=None if missing == "cancel" else ports,
        disconnect_port=None if missing == "disconnect" else ports,
        clock_ns=lambda: _NOW_NS,
        oauth_host_allowlist=((ProviderV1.SNAPTRADE, _AUTHORIZATION_HOST),),
    )


@contextmanager
def _client(
    ports: _FakePorts,
    *,
    missing: str | None = None,
    roles: tuple[str, ...] = ("operator",),
    project_id: str = _PROJECT,
    env: str = "paper",
) -> Iterator[TestClient]:
    app = FastAPI()
    app.include_router(create_connections_router(_runtime(ports, missing=missing)))
    app.add_middleware(
        OperatorPrincipalMiddleware,
        capability=_CAPABILITY,
        port=_PORT,
        profile=make_local_operator_profile(
            principal_id="conn003-test-operator",
            project_id=project_id,
            env=env,
            roles=roles,
        ),
    )
    with TestClient(app, base_url=_BASE_URL) as client:
        yield client


@pytest.fixture
def ports() -> _FakePorts:
    return _FakePorts()


@pytest.fixture
def client(ports: _FakePorts) -> Iterator[TestClient]:
    with _client(ports) as test_client:
        yield test_client


def _headers(*, post: bool = False, authorized: bool = True) -> dict[str, str]:
    headers = {"x-leviathan-capability": _CAPABILITY} if authorized else {}
    if post:
        headers["origin"] = _BASE_URL
    return headers


def _assert_secret_absent(response) -> None:  # type: ignore[no-untyped-def]
    assert _CANARY not in response.text


def _assert_fixed_error(response, status: int, code: str) -> None:  # type: ignore[no-untyped-def]
    assert response.status_code == status
    assert response.json() == {"error": {"code": code}}
    assert response.headers.get("cache-control") == "no-store"
    _assert_secret_absent(response)


def test_catalog_status_and_snaptrade_default_are_sanitized(
    client: TestClient, ports: _FakePorts
) -> None:
    catalog = client.get("/connections/catalog", headers=_headers())
    status = client.get("/connections/status", headers=_headers())
    query_override = client.get(
        "/connections/status?project_id=attacker-project&environment=LIVE",
        headers=_headers(),
    )

    assert catalog.status_code == status.status_code == 200
    _assert_fixed_error(query_override, 400, "UNSUPPORTED_QUERY")
    _assert_secret_absent(catalog)
    _assert_secret_absent(status)
    catalog_body = catalog.json()
    assert set(catalog_body) == {"providers"}
    snaptrade = next(row for row in catalog_body["providers"] if row["provider_id"] == "snaptrade")
    assert snaptrade["default_route"] is True
    assert set(snaptrade) == {
        "provider_id",
        "capabilities",
        "environments",
        "auth_method",
        "default_route",
    }
    assert status.json() == {
        "connections": [
            {
                "provider_id": "alpaca",
                "environment": "PAPER",
                "state": "DISCONNECTED",
                "configured": False,
            }
        ]
    }
    assert ("catalog", _PROJECT) in ports.calls
    assert ("status", _PROJECT, EnvironmentV1.PAPER) in ports.calls


def test_oauth_connect_returns_bound_authorization_and_single_use_state(
    client: TestClient,
) -> None:
    first = client.post("/connections/snaptrade/connect", headers=_headers(post=True))
    second = client.post("/connections/snaptrade/connect", headers=_headers(post=True))

    assert first.status_code == second.status_code == 202
    first_body = first.json()
    second_body = second.json()
    assert set(first_body) == {
        "provider_id",
        "environment",
        "auth_method",
        "authorization_url",
        "authorization_host",
        "redirect_uri",
        "state",
        "expires_at_ns",
        "single_use",
        "request_id",
    }
    assert first_body["provider_id"] == "snaptrade"
    assert first_body["environment"] == "PAPER"
    assert first_body["auth_method"] == "oauth"
    assert first_body["state"] != second_body["state"]
    authorization = urlsplit(first_body["authorization_url"])
    assert authorization.scheme == "https"
    assert authorization.hostname == first_body["authorization_host"]
    assert authorization.username is None and authorization.password is None
    assert authorization.fragment == ""
    authorization_query = parse_qs(authorization.query, strict_parsing=True)
    assert authorization_query == {
        "state": [first_body["state"]],
        "redirect_uri": [first_body["redirect_uri"]],
    }
    redirect = urlsplit(first_body["redirect_uri"])
    assert redirect.scheme == "http"
    assert redirect.hostname == "127.0.0.1"
    assert redirect.port is not None and redirect.path == "/callback"
    assert redirect.query == "" and redirect.fragment == ""
    assert first_body["single_use"] is True
    assert first_body["expires_at_ns"].isdigit()
    expiry_ns = int(first_body["expires_at_ns"])
    assert _NOW_NS < expiry_ns <= _NOW_NS + 600_000_000_000
    state = first_body["state"]
    state_bytes = base64.urlsafe_b64decode(state + "=" * (-len(state) % 4))
    assert len(state_bytes) >= 32
    assert base64.urlsafe_b64encode(state_bytes).decode("ascii").rstrip("=") == state
    for response in (first, second):
        _assert_secret_absent(response)


def test_key_connect_returns_only_a_handle_and_rejects_credential_bodies(
    client: TestClient, ports: _FakePorts
) -> None:
    response = client.post("/connections/alpaca/connect", headers=_headers(post=True))
    rejected = client.post(
        "/connections/alpaca/connect",
        headers=_headers(post=True),
        json={"api_key": _CANARY},
    )

    assert response.status_code == 202
    assert response.json() == {
        "provider_id": "alpaca",
        "environment": "PAPER",
        "auth_method": "api_key",
        "credential_entry_handle": "vault-handle-conn003",
    }
    _assert_secret_absent(response)
    assert ports.credential_store == {"api_key": _CANARY}
    _assert_fixed_error(rejected, 400, "UNSUPPORTED_BODY")


def test_provider_oauth_secret_echo_is_rejected_without_response_leak(
    ports: _FakePorts,
) -> None:
    ports.oauth_url_canary = True
    with _client(ports) as client:
        response = client.post("/connections/snaptrade/connect", headers=_headers(post=True))

    _assert_fixed_error(response, 503, "CONNECTIONS_UNAVAILABLE")


def test_cancel_and_disconnect_are_idempotent(client: TestClient) -> None:
    cancel_first = client.post("/connections/snaptrade/cancel", headers=_headers(post=True))
    cancel_repeat = client.post("/connections/snaptrade/cancel", headers=_headers(post=True))
    disconnect_first = client.post("/connections/alpaca/disconnect", headers=_headers(post=True))
    disconnect_repeat = client.post("/connections/alpaca/disconnect", headers=_headers(post=True))

    assert cancel_first.status_code == cancel_repeat.status_code == 200
    assert cancel_first.json() == cancel_repeat.json()
    assert cancel_first.json()["result"] == "CANCELLED"
    assert disconnect_first.status_code == disconnect_repeat.status_code == 200
    assert disconnect_first.json()["result"] == "DISCONNECTED"
    assert disconnect_repeat.json()["result"] == "ALREADY_DISCONNECTED"
    for response in (cancel_first, cancel_repeat, disconnect_first, disconnect_repeat):
        _assert_secret_absent(response)


def test_auth_role_and_environment_scope_are_enforced(
    ports: _FakePorts,
) -> None:
    with _client(ports, roles=("viewer",)) as viewer:
        denied_role = viewer.get("/connections/catalog", headers=_headers())
    with _client(ports, roles=("admin",)) as admin:
        allowed_admin = admin.get("/connections/catalog", headers=_headers())
    unauthenticated = FastAPI()
    unauthenticated.include_router(create_connections_router(_runtime(ports)))
    with TestClient(unauthenticated, base_url=_BASE_URL) as anonymous:
        denied_principal = anonymous.get("/connections/catalog")
    with _client(ports, env="development") as out_of_scope:
        denied_environment = out_of_scope.post(
            "/connections/alpaca/connect",
            headers=_headers(post=True),
        )
    with _client(ports) as query_override:
        denied_query_override = query_override.post(
            "/connections/alpaca/connect?project_id=attacker-project&environment=LIVE",
            headers=_headers(post=True),
        )

    _assert_fixed_error(denied_role, 403, "CONNECTION_FORBIDDEN")
    assert allowed_admin.status_code == 200
    _assert_secret_absent(allowed_admin)
    _assert_fixed_error(denied_principal, 401, "PRINCIPAL_UNTRUSTED")
    _assert_fixed_error(denied_environment, 403, "CONNECTION_FORBIDDEN")
    _assert_fixed_error(denied_query_override, 400, "UNSUPPORTED_QUERY")
    assert ("connect", _PROJECT, ProviderV1.ALPACA, EnvironmentV1.DEVELOPMENT) not in ports.calls


@pytest.mark.parametrize(
    ("missing", "method", "path"),
    [
        ("catalog", "get", "/connections/catalog"),
        ("status", "get", "/connections/status"),
        ("connect", "post", "/connections/snaptrade/connect"),
        ("cancel", "post", "/connections/snaptrade/cancel"),
        ("disconnect", "post", "/connections/alpaca/disconnect"),
    ],
)
def test_missing_port_returns_fixed_unavailable_response(
    missing: str, method: str, path: str
) -> None:
    ports = _FakePorts()
    with _client(ports, missing=missing) as client:
        response = client.request(method.upper(), path, headers=_headers(post=method == "post"))
    _assert_fixed_error(response, 503, "CONNECTIONS_UNAVAILABLE")


def test_provider_failures_are_sanitized_and_unknown_provider_is_not_guessed(
    ports: _FakePorts,
) -> None:
    ports.fail_catalog = True
    with _client(ports) as client:
        unavailable = client.get("/connections/catalog", headers=_headers())
    _assert_fixed_error(unavailable, 503, "CONNECTIONS_UNAVAILABLE")

    ports.fail_catalog = False
    with _client(ports) as client:
        unknown = client.post("/connections/unknown/connect", headers=_headers(post=True))
    _assert_fixed_error(unknown, 404, "PROVIDER_NOT_FOUND")


def test_router_contains_only_connection_routes_and_never_calls_orders(
    ports: _FakePorts,
) -> None:
    router = create_connections_router(_runtime(ports))
    observed = {(route.path, tuple(sorted(route.methods or ()))) for route in router.routes}
    assert observed == {
        ("/connections/catalog", ("GET",)),
        ("/connections/status", ("GET",)),
        ("/connections/{provider}/connect", ("POST",)),
        ("/connections/{provider}/cancel", ("POST",)),
        ("/connections/{provider}/disconnect", ("POST",)),
    }
    assert not any("order" in path.lower() or "live" in path.lower() for path, _ in observed)

    with _client(ports) as client:
        responses = [
            client.get("/connections/catalog", headers=_headers()),
            client.get("/connections/status", headers=_headers()),
            client.post("/connections/snaptrade/connect", headers=_headers(post=True)),
            client.post("/connections/snaptrade/cancel", headers=_headers(post=True)),
            client.post("/connections/alpaca/disconnect", headers=_headers(post=True)),
            client.post("/connections/orders", headers=_headers(post=True)),
            client.post("/connections/live/enable", headers=_headers(post=True)),
        ]
    assert responses[-2].status_code == responses[-1].status_code == 404
    assert ports.order_calls == 0
    for response in responses:
        _assert_secret_absent(response)
