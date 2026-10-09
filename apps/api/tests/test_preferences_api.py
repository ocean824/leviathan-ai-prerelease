"""HTTP adapter tests for authenticated user preferences."""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from leviathan_store.preferences import PreferencesError, UserPreferencesV1

from leviathan_api.routers.preferences import build_preferences_router
from leviathan_core.security.authz_models import (
    _VERIFIER_MARKER,
    PrincipalV1,
    TrustedPrincipalAdapterV1,
    TrustedPrincipalV1,
)

_PATH = "/api/preferences/terminal.theme"


def _principal(
    principal_id: str = "operator-1",
    *,
    project_id: str = "leviathan-ai",
    roles: tuple[str, ...] = ("operator",),
) -> TrustedPrincipalV1:
    claims = PrincipalV1(
        principal_id=principal_id,
        project_id=project_id,
        roles=roles,
        env="test",
    )
    return TrustedPrincipalAdapterV1.from_verified_claims(claims, verifier_marker=_VERIFIER_MARKER)


class _Store:
    def __init__(self) -> None:
        self.records: dict[tuple[str, str], UserPreferencesV1] = {}
        self.calls: list[tuple[str, str, str]] = []

    def get(self, user_scope: str, namespace: str) -> UserPreferencesV1 | None:
        self.calls.append(("get", user_scope, namespace))
        return self.records.get((user_scope, namespace))

    def put(
        self, user_scope: str, namespace: str, document: dict[str, object], *, if_match: str
    ) -> UserPreferencesV1:
        self.calls.append(("put", user_scope, namespace))
        key = (user_scope, namespace)
        current = self.records.get(key)
        if if_match == "*":
            if current is not None:
                raise PreferencesError("REVISION_CONFLICT", current)
            revision = 1
        else:
            if current is None or current.revision != int(if_match):
                raise PreferencesError("REVISION_CONFLICT", current)
            revision = current.revision + 1
        record = UserPreferencesV1(
            1, user_scope, namespace, document, 1_800_000_000_000_000_000, revision
        )
        self.records[key] = record
        return record

    def delete(self, user_scope: str, namespace: str) -> None:
        self.calls.append(("delete", user_scope, namespace))
        self.records.pop((user_scope, namespace), None)


def _client(store: _Store, principal: TrustedPrincipalV1 | None = None) -> TestClient:
    app = FastAPI()

    @app.middleware("http")
    async def set_principal(request: Request, call_next):
        request.state.principal = principal
        return await call_next(request)

    app.include_router(build_preferences_router(store, lambda request: request.state.principal))
    return TestClient(app)


def _no_store(response) -> None:
    assert response.headers["cache-control"] == "no-store"


def test_principal_scope_conditional_writes_and_current_conflict() -> None:
    store = _Store()
    client = _client(store, _principal())
    created = client.put(_PATH, headers={"If-Match": "*"}, json={"document": {"theme": "dark"}})
    assert created.status_code == 200
    assert created.json()["user_scope"] == "operator-1"
    assert created.json()["revision"] == 1
    assert created.json()["updated_at_ns"] == "1800000000000000000"
    _no_store(created)

    changed = client.put(_PATH, headers={"If-Match": '"1"'}, json={"document": {"theme": "light"}})
    assert changed.status_code == 200
    assert changed.json()["revision"] == 2
    conflict = client.put(_PATH, headers={"If-Match": "1"}, json={"document": {"theme": "blue"}})
    assert conflict.status_code == 409
    assert conflict.json()["current"]["document"] == {"theme": "light"}
    _no_store(conflict)
    assert store.calls == [
        ("put", "operator-1", "terminal.theme"),
        ("put", "operator-1", "terminal.theme"),
        ("put", "operator-1", "terminal.theme"),
    ]


def test_get_delete_and_missing_precondition() -> None:
    store = _Store()
    client = _client(store, _principal())
    missing = client.get(_PATH)
    assert missing.status_code == 404
    _no_store(missing)
    required = client.put(_PATH, json={"document": {"theme": "dark"}})
    assert required.status_code == 412
    created = client.put(_PATH, headers={"If-Match": "*"}, json={"document": {"theme": "dark"}})
    assert client.get(_PATH).json() == created.json()
    deleted = client.delete(_PATH)
    assert deleted.status_code == 204
    _no_store(deleted)
    assert client.get(_PATH).status_code == 404


def test_auth_scope_is_trusted_and_body_or_query_cannot_select_user() -> None:
    store = _Store()
    unauthenticated = _client(store).get(_PATH)
    forbidden = _client(store, _principal(project_id="other")).get(_PATH)
    role_denied = _client(store, _principal(roles=("viewer",))).get(_PATH)
    assert unauthenticated.status_code == 401
    assert forbidden.status_code == role_denied.status_code == 403
    _no_store(unauthenticated)

    client = _client(store, _principal("operator-a"))
    spoof = client.put(
        _PATH + "?user_scope=operator-b",
        headers={"If-Match": "*"},
        json={"user_scope": "operator-b", "document": {"theme": "dark"}},
    )
    assert spoof.status_code == 422
    assert store.calls == []


def test_document_secret_keys_and_oversize_are_content_free() -> None:
    store = _Store()
    client = _client(store, _principal())
    secret = client.put(
        _PATH, headers={"If-Match": "*"}, json={"document": {"apiKey": "do-not-echo"}}
    )
    assert secret.status_code == 422
    assert "do-not-echo" not in secret.text
    _no_store(secret)
    too_large = client.put(
        _PATH,
        headers={"If-Match": "*"},
        json={"document": {"value": "x" * 65_530}},
    )
    assert too_large.status_code == 413
    assert "x" * 20 not in too_large.text
    _no_store(too_large)
    assert store.calls == []


def test_unissued_principal_is_unauthenticated() -> None:
    forged = object.__new__(TrustedPrincipalV1)
    response = _client(_Store(), forged).get(_PATH)
    assert response.status_code == 401
    assert response.json() == {"error": {"code": "UNAUTHENTICATED"}}
    _no_store(response)


def test_framework_method_rejection_is_also_no_store() -> None:
    response = _client(_Store(), _principal()).patch(_PATH, json={})
    assert response.status_code == 405
    _no_store(response)
