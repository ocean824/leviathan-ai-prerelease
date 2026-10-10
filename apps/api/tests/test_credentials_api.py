from __future__ import annotations

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
from leviathan_vault.app_credentials import InMemoryCredentialStore


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


def _runtime(store: InMemoryCredentialStore) -> CredentialConnectionsRuntimeV1:
    return CredentialConnectionsRuntimeV1(
        credential_store=store,
        project_secret_store=None,
        tester=_Tester(),  # type: ignore[arg-type]
        audit=_Audit(),  # type: ignore[arg-type]
        status=_Status(),  # type: ignore[arg-type]
        live_bindings=_Bindings(),  # type: ignore[arg-type]
        clock_ns=lambda: 1_800_000_000_000_000_000,
    )


def _client(store: InMemoryCredentialStore | None = None) -> TestClient:
    app = create_app(
        credential_store=store,
        credential_connections_runtime=_runtime(store) if store is not None else None,
    )
    claims = PrincipalV1(
        principal_id="credential-owner",
        project_id="leviathan-ai",
        roles=("operator",),
        env="production",
    )
    principal = TrustedPrincipalAdapterV1.from_verified_claims(
        claims, verifier_marker=_VERIFIER_MARKER
    )

    @app.middleware("http")
    async def inject_principal(request, call_next):  # type: ignore[no-untyped-def]
        request.state.trusted_principal = principal
        return await call_next(request)

    return TestClient(
        app,
        base_url="http://127.0.0.1:8000",
        client=("127.0.0.1", 51000),
    )


def _remove(client: TestClient, root: str, *, live: bool = False) -> object:
    confirmation = client.post(
        f"{root}/remove-confirmation",
        headers={"Origin": "http://127.0.0.1:8000"},
    )
    assert confirmation.status_code == 200
    body: dict[str, object] = {"confirmation_token": confirmation.json()["confirmation_token"]}
    if live:
        body["confirm_environment"] = "LIVE"
    return client.request("DELETE", root, json=body)


def test_status_is_content_free_and_uncached() -> None:
    store = InMemoryCredentialStore()
    with _client(store) as client:
        response = client.put(
            "/live-trading/credentials/ALPACA/PAPER/default",
            json={
                "key_id": "SYNTHETIC-not-a-secret-0001",
                "secret_key": "SYNTHETIC-not-a-secret-0002",
            },
        )
        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-store"
        status = client.get("/live-trading/credentials")
        assert status.status_code == 200
        assert status.headers["cache-control"] == "no-store"
        assert status.json()["profiles"][0]["configured"] == {"key_id": True, "secret_key": True}
        for secret in ("SYNTHETIC-not-a-secret-0001", "SYNTHETIC-not-a-secret-0002"):
            assert secret not in status.text
            assert secret not in response.text


def test_partial_put_live_confirmation_delete_and_exact_paths() -> None:
    with _client(InMemoryCredentialStore()) as client:
        root = "/live-trading/credentials/ALPACA/LIVE/default"
        assert client.put(root, json={"key_id": "SYNTHETIC-key-0001"}).status_code == 409
        assert (
            client.put(
                root,
                json={
                    "key_id": "SYNTHETIC-key-0001",
                    "account_id": "acct-synthetic-1",
                    "confirm_environment": "LIVE",
                },
            ).status_code
            == 200
        )
        assert (
            client.put(
                root,
                json={
                    "secret_key": "SYNTHETIC-secret-0002",
                    "account_id": "acct-synthetic-1",
                    "confirm_environment": "LIVE",
                },
            ).status_code
            == 200
        )
        assert client.get("/live-trading/credentials").json()["profiles"][0]["configured"] == {
            "key_id": True,
            "secret_key": True,
        }
        assert client.delete(root).status_code == 409
        malformed = client.request("DELETE", root, json={"confirm_environment": "PAPER"})
        assert malformed.status_code == 422
        assert "PAPER" not in malformed.text
        deleted = _remove(client, root, live=True)
        assert hasattr(deleted, "status_code")
        assert deleted.status_code == 204
        assert deleted.headers["cache-control"] == "no-store"
        assert client.get("/api/live-trading/credentials").status_code == 200


def test_no_store_missing_store_and_content_free_validation(caplog) -> None:
    synthetic = "SYNTHETIC-invalid-body-probe-98765"
    with _client() as client:
        missing = client.get("/live-trading/credentials")
        assert missing.status_code == 503
        assert missing.json() == {"code": "NOT_CONFIGURED", "loc": []}
        assert missing.headers["cache-control"] == "no-store"
        assert (
            client.put(
                "/live-trading/credentials/ALPACA/LIVE/default",
                json={"key_id": "SYNTHETIC-not-a-secret-0001"},
            ).status_code
            == 503
        )
        assert client.delete("/live-trading/credentials/ALPACA/LIVE/default").status_code == 503
    with _client(InMemoryCredentialStore()) as client:
        invalid = client.put(
            "/live-trading/credentials/ALPACA/PAPER/default",
            json={
                "key_id": synthetic,
                "unexpected": synthetic,
            },
        )
        assert invalid.status_code == 422
        assert synthetic not in invalid.text
        assert "input" not in invalid.text
        assert invalid.headers["cache-control"] == "no-store"
        assert synthetic not in caplog.text


def test_mutation_does_not_enable_orders_or_live_mode() -> None:
    store = InMemoryCredentialStore()
    app = create_app(credential_store=store, credential_connections_runtime=_runtime(store))
    claims = PrincipalV1(
        principal_id="credential-owner",
        project_id="leviathan-ai",
        roles=("operator",),
        env="production",
    )
    principal = TrustedPrincipalAdapterV1.from_verified_claims(
        claims, verifier_marker=_VERIFIER_MARKER
    )

    @app.middleware("http")
    async def inject_principal(request, call_next):  # type: ignore[no-untyped-def]
        request.state.trusted_principal = principal
        return await call_next(request)

    with TestClient(app) as client:
        response = client.put(
            "/live-trading/credentials/ALPACA/LIVE/default",
            json={
                "key_id": "SYNTHETIC-key-0001",
                "secret_key": "SYNTHETIC-secret-0002",
                "account_id": "acct-synthetic-1",
                "confirm_environment": "LIVE",
            },
        )
        assert response.status_code == 200
        assert app.state.order_runtime_factory is None
        assert app.state.credential_store.status_all()[0].environment == "LIVE"


def test_request_body_and_secret_field_sizes_are_bounded() -> None:
    with _client(InMemoryCredentialStore()) as client:
        large_body = client.put(
            "/live-trading/credentials/ALPACA/PAPER/default",
            content=b"{" + b" " * (16 * 1024) + b"}",
            headers={"content-type": "application/json"},
        )
        assert large_body.status_code == 413
        assert large_body.json() == {"code": "REQUEST_TOO_LARGE", "loc": ["body"]}
        assert large_body.headers["cache-control"] == "no-store"

        oversized_secret = client.put(
            "/live-trading/credentials/ALPACA/PAPER/default",
            json={"key_id": "SYNTHETIC-" + ("x" * 4096)},
        )
        assert oversized_secret.status_code == 422
        assert "SYNTHETIC" not in oversized_secret.text
        assert oversized_secret.headers["cache-control"] == "no-store"


def test_status_reports_corruption_per_profile_without_hiding_healthy_profiles() -> None:
    class StoreWithCorruptProfile(InMemoryCredentialStore):
        def corrupt_profiles(self) -> tuple[tuple[str, str, str], ...]:
            return (("ALPACA", "PAPER", "damaged"),)

    store = StoreWithCorruptProfile()
    store.put_profile(
        "ALPACA",
        "PAPER",
        "healthy",
        {
            "key_id": SecretStr("SYNTHETIC-healthy-key-0001"),
            "secret_key": SecretStr("SYNTHETIC-healthy-secret-0001"),
        },
    )
    with _client(store) as client:
        response = client.get("/live-trading/credentials")
    assert response.status_code == 200
    rows = response.json()["profiles"]
    healthy = next(row for row in rows if row["profile"] == "healthy")
    damaged = next(row for row in rows if row["profile"] == "damaged")
    assert healthy["configured"] == {"key_id": True, "secret_key": True}
    assert damaged["status"] == "CORRUPT"
    assert damaged["configured"] == {"key_id": False, "secret_key": False}
    assert response.headers["cache-control"] == "no-store"


def test_legacy_mutation_requires_trusted_principal() -> None:
    store = InMemoryCredentialStore()
    app = create_app(credential_store=store, credential_connections_runtime=_runtime(store))
    with TestClient(app) as client:
        response = client.put(
            "/live-trading/credentials/ALPACA/PAPER/default",
            json={"key_id": "SYNTHETIC-key-0001"},
        )
    assert response.status_code == 401
    assert response.json() == {"code": "PRINCIPAL_UNTRUSTED"}
    assert store.status_all() == ()
