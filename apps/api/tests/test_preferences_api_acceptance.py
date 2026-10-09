"""Independent black-box acceptance for authenticated user preferences persistence."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from leviathan_store.preferences import PreferencesStore
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from leviathan_api.auth import OperatorPrincipalMiddleware, make_local_operator_profile
from leviathan_api.routers.preferences import build_preferences_router

_CAPABILITY = "ab" * 32
_PORT_A = 49131
_PORT_B = 49132
_NAMESPACE = "workspace"
_ROUTE = f"/api/preferences/{_NAMESPACE}"
_CLOCK_NS = 1_800_000_000_000_000_000


def _headers(port: int) -> dict[str, str]:
    origin = f"http://127.0.0.1:{port}"
    return {"x-leviathan-capability": _CAPABILITY, "origin": origin}


def _client(
    store: PreferencesStore,
    *,
    principal_id: str | None,
    port: int,
    roles: tuple[str, ...] = ("operator",),
    project_id: str = "leviathan-ai",
) -> TestClient:
    app = FastAPI()
    app.include_router(
        build_preferences_router(
            store,
            lambda request: getattr(request.state, "trusted_principal", None),
        )
    )
    if principal_id is not None:
        app.add_middleware(
            OperatorPrincipalMiddleware,
            capability=_CAPABILITY,
            port=port,
            profile=make_local_operator_profile(
                principal_id=principal_id,
                project_id=project_id,
                env="development",
                roles=roles,
            ),
        )
    return TestClient(app, base_url=f"http://127.0.0.1:{port}")


@pytest.fixture
def clients() -> Iterator[tuple[TestClient, TestClient, PreferencesStore]]:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    store = PreferencesStore(engine=engine, clock_ns=lambda: _CLOCK_NS)
    with (
        _client(store, principal_id="preferences-user-a", port=_PORT_A) as client_a,
        _client(store, principal_id="preferences-user-b", port=_PORT_B) as client_b,
    ):
        yield client_a, client_b, store
    engine.dispose()


def _no_store(response: Any) -> None:
    assert response.headers.get("cache-control", "").lower() == "no-store"


def _record(response: Any) -> dict[str, Any]:
    value = response.json()
    assert isinstance(value, dict)
    assert set(value) == {
        "schema_version",
        "user_scope",
        "namespace",
        "document",
        "updated_at_ns",
        "revision",
    }
    return value


def test_scope_comes_only_from_trusted_principal_and_namespaces_are_isolated(
    clients: tuple[TestClient, TestClient, PreferencesStore],
) -> None:
    client_a, client_b, _store = clients
    created = client_a.put(
        _ROUTE,
        headers={**_headers(_PORT_A), "If-Match": "*"},
        json={"document": {"density": "compact"}},
    )
    assert created.status_code == 200
    _no_store(created)
    assert _record(created)["user_scope"] == "preferences-user-a"

    # A query claim cannot select another user's row.
    hidden = client_b.get(f"{_ROUTE}?user_scope=preferences-user-a", headers=_headers(_PORT_B))
    assert hidden.status_code in (404, 422)
    _no_store(hidden)
    if hidden.status_code == 404:
        assert hidden.json() == {"error": {"code": "PREFERENCE_NOT_FOUND"}}
    created_b = client_b.put(
        _ROUTE,
        headers={**_headers(_PORT_B), "If-Match": "*"},
        json={"document": {"density": "wide"}},
    )
    assert created_b.status_code == 200
    _no_store(created_b)
    assert _record(created_b)["user_scope"] == "preferences-user-b"
    assert _record(client_a.get(_ROUTE, headers=_headers(_PORT_A)))["document"] == {
        "density": "compact"
    }

    # A body/query claim is either rejected or ignored; it never changes scope.
    spoofed = client_a.put(
        "/api/preferences/spoof-check?user_scope=preferences-user-b",
        headers={**_headers(_PORT_A), "If-Match": "*"},
        json={"user_scope": "preferences-user-b", "document": {"density": "wide"}},
    )
    assert spoofed.status_code in (200, 422)
    _no_store(spoofed)
    if spoofed.status_code == 200:
        assert _record(spoofed)["user_scope"] == "preferences-user-a"
        not_visible_to_b = client_b.get("/api/preferences/spoof-check", headers=_headers(_PORT_B))
        assert not_visible_to_b.status_code == 404
        _no_store(not_visible_to_b)


def test_if_match_create_update_conflict_and_missing_precondition(
    clients: tuple[TestClient, TestClient, PreferencesStore],
) -> None:
    client_a, _client_b, _store = clients
    missing = client_a.put(_ROUTE, headers=_headers(_PORT_A), json={"document": {"v": 1}})
    assert missing.status_code == 412
    _no_store(missing)
    assert missing.json() == {"error": {"code": "PRECONDITION_REQUIRED"}}

    created = client_a.put(
        _ROUTE,
        headers={**_headers(_PORT_A), "If-Match": "*"},
        json={"document": {"v": 1}},
    )
    assert created.status_code == 200
    _no_store(created)
    assert _record(created)["revision"] == 1

    updated = client_a.put(
        _ROUTE,
        headers={**_headers(_PORT_A), "If-Match": '"1"'},
        json={"document": {"v": 2}},
    )
    assert updated.status_code == 200
    _no_store(updated)
    assert _record(updated)["revision"] == 2
    assert _record(updated)["document"] == {"v": 2}

    for if_match in ("1", "*"):
        conflict = client_a.put(
            _ROUTE,
            headers={**_headers(_PORT_A), "If-Match": if_match},
            json={"document": {"v": 3}},
        )
        assert conflict.status_code == 409
        _no_store(conflict)
        body = conflict.json()
        assert body["error"] == {"code": "REVISION_CONFLICT"}
        assert body["current"]["revision"] == 2
        assert body["current"]["document"] == {"v": 2}


def test_secret_shaped_nested_keys_are_rejected_without_echo_or_write(
    clients: tuple[TestClient, TestClient, PreferencesStore],
) -> None:
    client_a, _client_b, _store = clients
    canary = "synthetic-pref-secret-canary-92831"
    response = client_a.put(
        _ROUTE,
        headers={**_headers(_PORT_A), "If-Match": "*"},
        json={"document": {"layout": {"api_token": canary}}},
    )
    assert response.status_code == 422
    _no_store(response)
    assert response.json() == {"error": {"code": "PREFERENCES_INVALID"}}
    assert canary not in response.text
    absent = client_a.get(_ROUTE, headers=_headers(_PORT_A))
    assert absent.status_code == 404
    _no_store(absent)


def test_document_size_boundary_and_413_overflow(
    clients: tuple[TestClient, TestClient, PreferencesStore],
) -> None:
    client_a, _client_b, _store = clients
    # Canonical JSON for {"blob":"..."} contributes exactly 11 framing bytes.
    at_limit = client_a.put(
        "/api/preferences/size-boundary",
        headers={**_headers(_PORT_A), "If-Match": "*"},
        json={"document": {"blob": "x" * (65_536 - 11)}},
    )
    assert at_limit.status_code == 200
    _no_store(at_limit)

    oversized = client_a.put(
        "/api/preferences/oversized",
        headers={**_headers(_PORT_A), "If-Match": "*"},
        json={"document": {"blob": "x" * (65_537 - 11)}},
    )
    assert oversized.status_code == 413
    _no_store(oversized)
    assert oversized.json() == {"error": {"code": "DOCUMENT_TOO_LARGE"}}
    assert len(oversized.content) < 4096


def test_missing_trusted_principal_is_401_and_no_store() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:", poolclass=StaticPool)
    store = PreferencesStore(engine=engine, clock_ns=lambda: _CLOCK_NS)
    with _client(store, principal_id=None, port=_PORT_A) as client:
        response = client.get(_ROUTE)
    engine.dispose()
    assert response.status_code == 401
    _no_store(response)
    assert response.json() == {"error": {"code": "UNAUTHENTICATED"}}


def test_scope_denial_and_framework_method_errors_are_uncached() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:", poolclass=StaticPool)
    store = PreferencesStore(engine=engine, clock_ns=lambda: _CLOCK_NS)
    with (
        _client(
            store,
            principal_id="preferences-auditor",
            port=_PORT_A,
            roles=("auditor",),
        ) as denied_client,
        _client(store, principal_id="preferences-user-a", port=_PORT_B) as client,
    ):
        denied = denied_client.get(_ROUTE, headers=_headers(_PORT_A))
        assert denied.status_code == 403
        _no_store(denied)
        assert denied.json() == {"error": {"code": "PREFERENCES_SCOPE_DENIED"}}

        method_error = client.patch(_ROUTE, headers=_headers(_PORT_B))
        assert method_error.status_code == 405
        _no_store(method_error)
    engine.dispose()
