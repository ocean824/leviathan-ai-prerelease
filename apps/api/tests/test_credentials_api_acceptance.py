"""Independent contract tests for the write-only credential API."""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr

from leviathan_api.credential_connections import (
    CredentialAuditEventV1,
    CredentialConnectionsRuntimeV1,
    CredentialReferenceV1,
    CredentialStatusV1,
    CredentialTestResultV1,
)
from leviathan_api.main import create_app
from leviathan_core.security.authz_models import (
    _VERIFIER_MARKER,
    PrincipalV1,
    TrustedPrincipalAdapterV1,
)
from leviathan_vault.app_credentials import DPAPICredentialStore, InMemoryCredentialStore

CANARY = "API_CRED_SYNTHETIC_SECRET_" + "Z" * 211 + "_PRIVATE_END"
ROTATED = "API_CRED_ROTATED_SECRET_" + "Y" * 197 + "_PRIVATE_END"
KEY_ID = "API_SYNTHETIC_KEY_ID_731"
API_PREFIX = "/live-trading/credentials"


def _markers(value: str) -> tuple[str, ...]:
    raw = value.encode("utf-8")
    markers = [
        value,
        value[:15],
        value[-15:],
        value[::-1],
        hashlib.sha256(raw).hexdigest(),
        base64.urlsafe_b64encode(raw).decode("ascii"),
    ]
    return tuple(markers)


def _contains_exact_value(value: object, expected: object) -> bool:
    if isinstance(value, dict):
        return any(
            "length" in str(key).lower() or _contains_exact_value(item, expected)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(_contains_exact_value(item, expected) for item in value)
    return value == expected


def _assert_no_canary(text: str) -> None:
    for secret in (CANARY, ROTATED, KEY_ID):
        for marker in _markers(secret):
            assert marker not in text


def _body(secret: str = CANARY, *, confirm: str | None = None) -> dict[str, object]:
    result: dict[str, object] = {
        "key_id": KEY_ID,
        "secret_key": secret,
        "account_id": "SYNTHETIC-account-731",
    }
    if confirm is not None:
        result["confirm_environment"] = confirm
    return result


def _store(tmp_path: Path) -> InMemoryCredentialStore | DPAPICredentialStore:
    # The API is always given an explicit, test-owned store; Windows DPAPI
    # fixtures are rooted below pytest's temporary directory.
    if os.name == "nt":
        return DPAPICredentialStore(tmp_path / "credential-store")
    return InMemoryCredentialStore()


class _Tester:
    def test(self, reference: CredentialReferenceV1) -> CredentialTestResultV1:
        return CredentialTestResultV1(verified=True)


class _Audit:
    def append(self, event: CredentialAuditEventV1) -> None:
        return None


class _Status:
    def read_status(self, reference: CredentialReferenceV1) -> CredentialStatusV1:
        return CredentialStatusV1(
            provider_id=reference.provider_id,
            environment=reference.environment,
            configured=False,
        )

    def record_status(self, status: CredentialStatusV1) -> None:
        return None


class _Bindings:
    def resolve_bindings(self, provider: str, account_id: str) -> tuple[()]:
        return ()

    def bump_credential_revision(
        self, organization_id: str, account_id: str, provider: str
    ) -> None:
        return None


def _app(store: InMemoryCredentialStore | DPAPICredentialStore | None, **kwargs: Any):
    runtime = None
    if store is not None:
        runtime = CredentialConnectionsRuntimeV1(
            credential_store=store,
            project_secret_store=None,
            tester=_Tester(),  # type: ignore[arg-type]
            audit=_Audit(),  # type: ignore[arg-type]
            status=_Status(),  # type: ignore[arg-type]
            live_bindings=_Bindings(),  # type: ignore[arg-type]
            clock_ns=lambda: 1_800_000_000_000_000_000,
        )
    app = create_app(
        credential_store=store,
        credential_connections_runtime=runtime,
        **kwargs,
    )
    claims = PrincipalV1(
        principal_id="credential-acceptance-owner",
        project_id="leviathan-ai",
        roles=("operator",),
        env="production",
    )
    principal = TrustedPrincipalAdapterV1.from_verified_claims(
        claims, verifier_marker=_VERIFIER_MARKER
    )

    @app.middleware("http")
    async def inject_trusted_principal(request, call_next):  # type: ignore[no-untyped-def]
        request.state.trusted_principal = principal
        return await call_next(request)

    return app


def _client_for(
    store: InMemoryCredentialStore | DPAPICredentialStore | None,
    **kwargs: Any,
) -> TestClient:
    return TestClient(
        _app(store, **kwargs),
        base_url="http://127.0.0.1:8000",
        client=("127.0.0.1", 51000),
    )


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local-app-data"))
    return _client_for(_store(tmp_path))


def _assert_no_store_header(response: Any) -> None:
    assert "no-store" in response.headers.get("cache-control", "").lower()
    _assert_no_canary(response.text)
    try:
        response_data = response.json()
    except ValueError:
        return
    for secret in (CANARY, ROTATED, KEY_ID):
        assert not _contains_exact_value(response_data, len(secret))
        assert not _contains_exact_value(response_data, str(len(secret)))


def _profile_rows(data: object) -> list[dict[str, object]]:
    if isinstance(data, list):
        rows = data
    else:
        assert isinstance(data, dict)
        rows = data.get("profiles", data.get("credentials"))
    assert isinstance(rows, list)
    assert all(isinstance(row, dict) for row in rows)
    return rows


def test_status_is_write_only_and_reports_configuration_only(client: TestClient) -> None:
    put = client.put(f"{API_PREFIX}/ALPACA/PAPER/default", json=_body())
    assert put.status_code == 200
    _assert_no_store_header(put)

    response = client.get(API_PREFIX)
    assert response.status_code == 200
    _assert_no_store_header(response)
    rows = _profile_rows(response.json())
    row = next(
        item
        for item in rows
        if item.get("provider") == "ALPACA" and item.get("environment") == "PAPER"
    )
    assert row.get("profile") == "default"
    configured = row.get("configured")
    assert isinstance(configured, dict)
    assert configured.get("key_id") is True
    assert configured.get("secret_key") is True
    assert row.get("verification") == "NOT_TESTED"
    assert "updated_at" in row
    _assert_no_canary(json.dumps(response.json(), sort_keys=True))


def test_partial_put_retains_omitted_secret_and_bumps_revision(
    client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local-app-data"))
    client = _client_for(store)

    first = client.put(f"{API_PREFIX}/ALPACA/PAPER/default", json=_body())
    assert first.status_code == 200
    _assert_no_store_header(first)
    second = client.put(
        f"{API_PREFIX}/ALPACA/PAPER/default", json={"key_id": "API_SYNTHETIC_KEY_ID_731B"}
    )
    assert second.status_code == 200
    _assert_no_store_header(second)

    resolved = store.resolve("ALPACA", "PAPER", "default")
    assert resolved.secret("secret_key").get_secret_value() == CANARY
    assert resolved.secret("key_id").get_secret_value() == "API_SYNTHETIC_KEY_ID_731B"
    assert resolved.revision > 1


def test_live_put_requires_literal_confirmation_and_never_enables_live_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local-app-data"))
    calls: list[object] = []

    def runtime_factory(*args: object, **kwargs: object) -> object:
        calls.append((args, kwargs))
        return object()

    client = _client_for(_store(tmp_path), order_runtime_factory=runtime_factory)
    app = client.app
    initial_live_enabled = getattr(app.state, "live_enabled", None)

    with caplog.at_level(logging.DEBUG):
        denied = client.put(f"{API_PREFIX}/ALPACA/LIVE/default", json=_body())
        assert denied.status_code == 409
        _assert_no_store_header(denied)
        assert denied.json().get("code") == "LIVE_CONFIRMATION_REQUIRED"

        accepted = client.put(
            f"{API_PREFIX}/ALPACA/LIVE/default", json=_body(ROTATED, confirm="LIVE")
        )
        assert accepted.status_code == 200
        _assert_no_store_header(accepted)

    assert calls == []
    assert getattr(app.state, "live_enabled", None) == initial_live_enabled
    _assert_no_canary(caplog.text)


def test_live_delete_requires_confirmation_in_json_body(
    client: TestClient,
) -> None:
    created = client.put(f"{API_PREFIX}/ALPACA/LIVE/default", json=_body(confirm="LIVE"))
    assert created.status_code == 200
    _assert_no_store_header(created)

    denied = client.request("DELETE", f"{API_PREFIX}/ALPACA/LIVE/default", json={})
    assert denied.status_code == 409
    _assert_no_store_header(denied)
    assert denied.json().get("code") == "LIVE_CONFIRMATION_REQUIRED"

    confirmation = client.post(
        f"{API_PREFIX}/ALPACA/LIVE/default/remove-confirmation",
        headers={"Origin": "http://127.0.0.1:8000"},
    )
    assert confirmation.status_code == 200
    deleted = client.request(
        "DELETE",
        f"{API_PREFIX}/ALPACA/LIVE/default",
        json={
            "confirm_environment": "LIVE",
            "confirmation_token": confirmation.json()["confirmation_token"],
        },
    )
    assert deleted.status_code == 204
    _assert_no_store_header(deleted)


def test_invalid_body_is_content_free_and_includes_only_code_and_location(
    client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    body = _body()
    body["secret_key"] = CANARY
    body["unexpected_field"] = CANARY
    with caplog.at_level(logging.DEBUG):
        response = client.put(f"{API_PREFIX}/ALPACA/PAPER/default", json=body)
    assert response.status_code == 422
    _assert_no_store_header(response)
    data = response.json()
    assert set(data) == {"code", "loc"}
    assert isinstance(data["code"], str)
    assert isinstance(data["loc"], list)
    _assert_no_canary(caplog.text)


def test_oversized_secret_body_fails_with_content_free_client_error(
    client: TestClient,
) -> None:
    oversized = "API_SYNTHETIC_OVERSIZE_SECRET_" + "W" * (1024 * 1024)
    response = client.put(
        f"{API_PREFIX}/ALPACA/PAPER/default",
        json={"key_id": KEY_ID, "secret_key": oversized},
    )
    assert 400 <= response.status_code < 500
    _assert_no_store_header(response)
    assert len(response.content) < 4096
    for marker in _markers(oversized):
        assert marker not in response.text


@pytest.mark.parametrize("bad_id", ["Upper", "..", "a.b", "con", "COM1", "x" * 65, "", 17])
def test_invalid_mcp_server_id_is_content_free_422(client: TestClient, bad_id: object) -> None:
    response = client.put(
        f"{API_PREFIX}/MCP/PAPER/default",
        json={"server_id": bad_id, "token": CANARY},
    )
    assert response.status_code == 422
    _assert_no_store_header(response)
    assert response.json().get("code") == "INVALID_ID"


def test_mounted_path_has_single_api_prefix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local-app-data"))
    outer = FastAPI()
    outer.mount("/api", _app(_store(tmp_path)))
    mounted = TestClient(outer)

    visible = mounted.get(f"/api{API_PREFIX}")
    assert visible.status_code == 200
    _assert_no_store_header(visible)
    doubled = mounted.get(f"/api/api{API_PREFIX}")
    assert doubled.status_code == 404
    _assert_no_canary(doubled.text)


def test_missing_store_fails_closed_for_every_route_with_no_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local-app-data"))
    client = TestClient(create_app(credential_store=None))
    responses = (
        client.get(API_PREFIX),
        client.put(f"{API_PREFIX}/ALPACA/PAPER/default", json=_body()),
        client.request("DELETE", f"{API_PREFIX}/ALPACA/PAPER/default", json={}),
    )
    for response in responses:
        assert response.status_code == 503
        _assert_no_store_header(response)
        assert response.json().get("code") in {
            "NOT_CONFIGURED",
            "CREDENTIALS_NOT_CONFIGURED",
        }


@pytest.mark.skipif(os.name != "nt", reason="DPAPI corruption status is Windows-only")
def test_corrupt_profile_has_content_free_status_and_can_be_deleted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local-app-data"))
    root = tmp_path / "runtime-credentials"
    store = DPAPICredentialStore(root)
    store.put_profile(
        "ALPACA",
        "PAPER",
        "broken",
        {"key_id": SecretStr(KEY_ID), "secret_key": SecretStr(CANARY)},
    )
    store.put_profile(
        "ALPACA",
        "PAPER",
        "healthy",
        {"key_id": SecretStr(KEY_ID), "secret_key": SecretStr(ROTATED)},
    )
    corrupt_file = root / "PAPER" / "ALPACA" / "broken" / "profile.json"
    corrupt_file.write_bytes(b"synthetic-corrupt-profile-envelope")
    reopened = DPAPICredentialStore(root)
    client = _client_for(reopened)

    status = client.get(API_PREFIX)
    assert status.status_code == 200
    _assert_no_store_header(status)
    rows = _profile_rows(status.json())
    corrupt_row = next(row for row in rows if row.get("profile") == "broken")
    assert corrupt_row.get("status") == "CORRUPT"
    configured = corrupt_row.get("configured")
    assert isinstance(configured, dict)
    assert configured and all(value is False for value in configured.values())
    assert corrupt_row.get("updated_at") is None
    assert corrupt_row.get("verification") == "NOT_TESTED"
    assert any(row.get("profile") == "healthy" for row in rows)

    confirmation = client.post(
        f"{API_PREFIX}/ALPACA/PAPER/broken/remove-confirmation",
        headers={"Origin": "http://127.0.0.1:8000"},
    )
    assert confirmation.status_code == 200
    deleted = client.request(
        "DELETE",
        f"{API_PREFIX}/ALPACA/PAPER/broken",
        json={"confirmation_token": confirmation.json()["confirmation_token"]},
    )
    assert deleted.status_code == 204
    _assert_no_store_header(deleted)
    assert reopened.corrupt_profiles() == ()
    after_delete = client.get(API_PREFIX)
    assert after_delete.status_code == 200
    _assert_no_store_header(after_delete)
    assert all(row.get("profile") != "broken" for row in _profile_rows(after_delete.json()))
