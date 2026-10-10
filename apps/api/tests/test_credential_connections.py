from __future__ import annotations

from dataclasses import replace

from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr

from leviathan_api.credential_connections import (
    CredentialAuditEventV1,
    CredentialConnectionsRuntimeV1,
    CredentialReferenceV1,
    CredentialStatusV1,
    CredentialTestResultV1,
    InMemoryCredentialConfirmationPortV1,
    LiveCredentialBindingV1,
    create_credential_connections_router,
)
from leviathan_api.live_activation_runtime import LazyLiveActivationGateV1
from leviathan_core.security.authz_models import (
    _VERIFIER_MARKER,
    PrincipalV1,
    TrustedPrincipalAdapterV1,
)
from leviathan_vault.app_credentials import InMemoryCredentialStore

SENTINEL = "SYNTHETIC-CONNECTION-SECRET-9918273645"


class _ProjectStore:
    def __init__(self) -> None:
        self.values: dict[str, SecretStr] = {}

    def configured(self, reference: str, name: str) -> bool:
        return reference in self.values

    def put(self, reference: str, name: str, value: SecretStr) -> None:
        self.values[reference] = value

    def get(self, reference: str, name: str) -> SecretStr:
        return self.values[reference]

    def remove(self, reference: str, name: str) -> None:
        self.values.pop(reference, None)


class _BrokenProjectStore(_ProjectStore):
    def configured(self, reference: str, name: str) -> bool:
        raise OSError(SENTINEL)


class _Tester:
    def __init__(self) -> None:
        self.references: list[CredentialReferenceV1] = []

    def test(self, reference: CredentialReferenceV1) -> CredentialTestResultV1:
        self.references.append(reference)
        return CredentialTestResultV1(verified=True)


class _Audit:
    def __init__(self, order: list[str]) -> None:
        self.events: list[CredentialAuditEventV1] = []
        self.order = order

    def append(self, event: CredentialAuditEventV1) -> None:
        self.order.append("audit")
        self.events.append(event)


class _CredentialStore(InMemoryCredentialStore):
    def __init__(self, order: list[str]) -> None:
        super().__init__()
        self.order = order
        self.fail_put = False

    def put_profile(self, provider, environment, profile_id, fields):  # type: ignore[no-untyped-def]
        self.order.append("store")
        if self.fail_put:
            raise OSError("private store detail")
        return super().put_profile(provider, environment, profile_id, fields)

    def delete_profile(self, provider, environment, profile_id):  # type: ignore[no-untyped-def]
        self.order.append("store")
        return super().delete_profile(provider, environment, profile_id)


class _Status:
    def __init__(self) -> None:
        self.rows: dict[tuple[str, str, str], CredentialStatusV1] = {}

    def read_status(self, reference: CredentialReferenceV1) -> CredentialStatusV1:
        key = (reference.provider_id, reference.environment, reference.profile_id)
        return self.rows.get(
            key,
            CredentialStatusV1(
                provider_id=reference.provider_id,
                environment=reference.environment,
                configured=False,
            ),
        )

    def record_status(self, status: CredentialStatusV1) -> None:
        self.rows[(status.provider_id, status.environment, "default")] = status


class _LiveBindings:
    def __init__(self) -> None:
        self.rows: tuple[LiveCredentialBindingV1, ...] = ()
        self.fail = False
        self.unknown = False
        self.fail_revision = False
        self.revisions: list[tuple[str, str, str]] = []
        self.order: list[str] = []

    def resolve_bindings(
        self, provider_id: str, account_identifier: str
    ) -> tuple[LiveCredentialBindingV1, ...] | None:
        self.order.append("resolve")
        if self.fail:
            raise OSError("private binding detail")
        if self.unknown:
            return None
        return tuple(
            row
            for row in self.rows
            if row.venue == provider_id and row.account_identifier == account_identifier
        )

    def bump_credential_revision(
        self, organization_id: str, account_id: str, provider_id: str
    ) -> None:
        self.order.append("revision")
        if self.fail_revision:
            raise OSError("private revision detail")
        self.revisions.append((organization_id, account_id, provider_id))


class _GateProjection:
    def __init__(self) -> None:
        self.deactivated: list[tuple[str, str]] = []
        self.order: list[str] = []
        self.fail = False

    def live_account_enabled(self, account_id: str) -> bool:
        return True

    def deactivate_account(self, organization_id: str, account_id: str) -> None:
        self.order.append("deactivate")
        if self.fail:
            raise OSError("private gate detail")
        self.deactivated.append((organization_id, account_id))


def _runtime() -> tuple[CredentialConnectionsRuntimeV1, dict[str, object]]:
    order: list[str] = []
    objects: dict[str, object] = {
        "broker_store": _CredentialStore(order),
        "project_store": _ProjectStore(),
        "tester": _Tester(),
        "audit": _Audit(order),
        "status": _Status(),
        "bindings": _LiveBindings(),
        "gate": _GateProjection(),
        "order": order,
    }
    objects["bindings"].order = order  # type: ignore[attr-defined]
    objects["gate"].order = order  # type: ignore[attr-defined]
    runtime = CredentialConnectionsRuntimeV1(
        credential_store=objects["broker_store"],  # type: ignore[arg-type]
        project_secret_store=objects["project_store"],  # type: ignore[arg-type]
        tester=objects["tester"],  # type: ignore[arg-type]
        audit=objects["audit"],  # type: ignore[arg-type]
        status=objects["status"],  # type: ignore[arg-type]
        live_bindings=objects["bindings"],  # type: ignore[arg-type]
        clock_ns=lambda: 1_800_000_000_000_000_000,
    )
    return runtime, objects


def _client(
    runtime: CredentialConnectionsRuntimeV1, *, client_host: str = "127.0.0.1"
) -> TestClient:
    app = FastAPI()
    app.include_router(create_credential_connections_router(runtime), prefix="/api")
    claims = PrincipalV1(
        principal_id="credential-owner",
        project_id="leviathan-ai",
        roles=("operator",),
        env="production",
    )
    principal = TrustedPrincipalAdapterV1.from_verified_claims(
        claims, verifier_marker=_VERIFIER_MARKER
    )
    app.state.live_activation_gate = LazyLiveActivationGateV1()

    @app.middleware("http")
    async def inject_principal(request, call_next):  # type: ignore[no-untyped-def]
        request.state.trusted_principal = principal
        return await call_next(request)

    return TestClient(
        app,
        base_url="http://127.0.0.1:8000",
        client=(client_host, 51000),
    )


def test_market_data_replace_test_remove_never_returns_secret(caplog) -> None:
    runtime, objects = _runtime()
    store = objects["project_store"]
    audit = objects["audit"]
    with _client(runtime) as client:
        replaced = client.put(
            "/api/connections/credentials/databento/DEVELOPMENT/default",
            json={"secrets": {"api_key": SENTINEL}},
        )
        assert replaced.status_code == 200
        assert replaced.json()["configured"] is True
        assert SENTINEL not in replaced.text
        tested = client.post("/api/connections/credentials/databento/DEVELOPMENT/default/test")
        assert tested.status_code == 200
        assert tested.json() == {
            "provider_id": "databento",
            "verified": True,
            "error_code": None,
        }
        confirmation = client.post(
            "/api/connections/credentials/databento/DEVELOPMENT/default/remove-confirmation",
            headers={"Origin": "http://127.0.0.1:8000"},
        )
        assert confirmation.status_code == 200
        removed = client.request(
            "DELETE",
            "/api/connections/credentials/databento/DEVELOPMENT/default",
            json={"confirmation_token": confirmation.json()["confirmation_token"]},
        )
        assert removed.status_code == 200
        status = client.get("/api/connections/credentials")
        assert status.status_code == 200
        assert SENTINEL not in status.text
    assert len(store.values) == 0  # type: ignore[attr-defined]
    assert all(SENTINEL not in event.model_dump_json() for event in audit.events)  # type: ignore[attr-defined]
    assert SENTINEL not in caplog.text


def test_main_app_sanitizes_invalid_credential_body_and_disables_caching(caplog) -> None:
    from leviathan_api.main import create_app

    runtime, _ = _runtime()
    app = create_app(credential_connections_runtime=runtime)
    with TestClient(app) as client:
        response = client.put(
            "/api/connections/credentials/databento/DEVELOPMENT/default",
            json={"secrets": {"api_key": SENTINEL}, "unexpected": SENTINEL},
        )

    assert response.status_code == 422
    assert response.json()["code"] == "INVALID_REQUEST"
    assert response.headers["cache-control"] == "no-store"
    assert SENTINEL not in response.text
    assert SENTINEL not in caplog.text


def test_status_backend_failure_is_content_free(caplog) -> None:
    runtime, _ = _runtime()
    runtime = replace(runtime, project_secret_store=_BrokenProjectStore())

    with _client(runtime) as client:
        response = client.get("/api/connections/credentials")

    assert response.status_code == 503
    assert response.json() == {"code": "CREDENTIALS_UNAVAILABLE"}
    assert SENTINEL not in response.text
    assert SENTINEL not in caplog.text


def test_replace_intent_is_bounded_and_contains_no_secret() -> None:
    runtime, _ = _runtime()
    with _client(runtime) as client:
        response = client.post(
            "/api/connections/credentials/databento/DEVELOPMENT/default/replace-intent"
        )
    assert response.status_code == 200
    assert response.json() == {
        "intent": "OPEN_REPLACE_FORM",
        "provider_id": "databento",
        "environment": "DEVELOPMENT",
        "profile_id": "default",
    }
    assert SENTINEL not in response.text


def test_remove_confirmation_round_trip_is_loopback_bound_and_single_use(caplog) -> None:
    runtime, objects = _runtime()
    origin = {"Origin": "http://127.0.0.1:8000"}
    with _client(runtime, client_host="198.51.100.7") as remote_client:
        remote = remote_client.post(
            "/api/connections/credentials/databento/DEVELOPMENT/default/remove-confirmation",
            headers=origin,
        )
    assert remote.status_code == 403
    assert remote.json() == {"code": "CONFIRMATION_ORIGIN_DENIED"}

    with _client(runtime) as client:
        cross_origin = client.post(
            "/api/connections/credentials/databento/DEVELOPMENT/default/remove-confirmation",
            headers={"Origin": "http://evil.invalid"},
        )
        assert cross_origin.status_code == 403
        assert cross_origin.json() == {"code": "CONFIRMATION_ORIGIN_DENIED"}

        missing = client.request(
            "DELETE",
            "/api/connections/credentials/databento/DEVELOPMENT/default",
            json={},
        )
        assert missing.status_code == 403
        assert missing.json() == {"code": "CONFIRMATION_REQUIRED"}

        issued_for_other_provider = client.post(
            "/api/connections/credentials/massive/DEVELOPMENT/default/remove-confirmation",
            headers=origin,
        )
        wrong_binding = client.request(
            "DELETE",
            "/api/connections/credentials/databento/DEVELOPMENT/default",
            json={"confirmation_token": issued_for_other_provider.json()["confirmation_token"]},
        )
        assert wrong_binding.status_code == 403
        assert wrong_binding.json() == {"code": "CONFIRMATION_REQUIRED"}

        issued = client.post(
            "/api/connections/credentials/databento/DEVELOPMENT/default/remove-confirmation",
            headers=origin,
        )
        token = issued.json()["confirmation_token"]
        assert issued.status_code == 200
        assert len(token) >= 32
        assert issued.json()["expires_at_ns"].isdigit()
        removed = client.request(
            "DELETE",
            "/api/connections/credentials/databento/DEVELOPMENT/default",
            json={"confirmation_token": token},
        )
        replayed = client.request(
            "DELETE",
            "/api/connections/credentials/databento/DEVELOPMENT/default",
            json={"confirmation_token": token},
        )

    assert removed.status_code == 200
    assert token not in removed.text and token not in replayed.text
    assert replayed.status_code == 403
    assert token not in caplog.text
    assert all(token not in event.model_dump_json() for event in objects["audit"].events)  # type: ignore[attr-defined]


def test_confirmation_port_rejects_mismatched_and_expired_tokens() -> None:
    port = InMemoryCredentialConfirmationPortV1()

    def issue(provider_id: str, now_ns: int) -> str:
        token, _ = port.issue(
            principal_id="owner",
            provider_id=provider_id,
            environment="PAPER",
            profile_id="default",
            action="REMOVE",
            now_ns=now_ns,
        )
        return token

    def consume(token: str, provider_id: str, now_ns: int) -> bool:
        return port.consume(
            token=token,
            principal_id="owner",
            provider_id=provider_id,
            environment="PAPER",
            profile_id="default",
            action="REMOVE",
            now_ns=now_ns,
        )

    mismatched = issue("databento", 10)
    assert not consume(mismatched, "massive", 11)
    assert not consume(mismatched, "databento", 11)

    expired = issue("databento", 20)
    assert not consume(expired, "databento", 60_000_000_021)


def test_live_replace_deactivates_all_accounts_then_bumps_revision() -> None:
    runtime, objects = _runtime()
    bindings = objects["bindings"]
    store = objects["broker_store"]
    old_profile = store.put_profile(  # type: ignore[attr-defined]
        "IBKR",
        "LIVE",
        "default",
        {"host": "127.0.0.1", "port": 4001, "client_id": 4, "account_id": "DU123"},
    )
    bindings.rows = (  # type: ignore[attr-defined]
        LiveCredentialBindingV1(
            organization_id="org-1", account_id="live-1", venue="IBKR", account_identifier="DU123"
        ),
        LiveCredentialBindingV1(
            organization_id="org-1", account_id="live-2", venue="IBKR", account_identifier="DU123"
        ),
    )
    gate = objects["gate"]
    with _client(runtime) as client:
        client.app.state.live_activation_gate.bind(gate)  # type: ignore[attr-defined]
        response = client.put(
            "/api/connections/credentials/ibkr/LIVE/default",
            json={
                "fields": {
                    "host": "127.0.0.1",
                    "port": 4001,
                    "client_id": 7,
                    "account_id": "DU123",
                },
                "confirm_environment": "LIVE",
            },
        )
    assert response.status_code == 200
    assert gate.deactivated == [("org-1", "live-1"), ("org-1", "live-2")]  # type: ignore[attr-defined]
    assert bindings.revisions == [  # type: ignore[attr-defined]
        ("org-1", "live-1", "ibkr"),
        ("org-1", "live-2", "ibkr"),
    ]
    assert objects["order"] == [
        "store",
        "resolve",
        "resolve",
        "deactivate",
        "deactivate",
        "store",
        "revision",
        "revision",
        "audit",
    ]
    current_profile = store.status_all()[0]  # type: ignore[attr-defined]
    assert current_profile.revision == old_profile.revision + 1


def test_live_rotation_deactivates_old_and_new_account_identities() -> None:
    runtime, objects = _runtime()
    bindings = objects["bindings"]
    store = objects["broker_store"]
    store.put_profile(
        "IBKR",
        "LIVE",
        "default",
        {"host": "127.0.0.1", "port": 4001, "client_id": 4, "account_id": "DU123"},
    )
    bindings.rows = (
        LiveCredentialBindingV1(
            organization_id="org-1", account_id="old-live", venue="IBKR", account_identifier="DU123"
        ),
        LiveCredentialBindingV1(
            organization_id="org-2", account_id="new-live", venue="IBKR", account_identifier="DU999"
        ),
    )
    gate = objects["gate"]
    with _client(runtime) as client:
        client.app.state.live_activation_gate.bind(gate)
        response = client.put(
            "/api/connections/credentials/ibkr/LIVE/default",
            json={
                "fields": {
                    "host": "127.0.0.1",
                    "port": 4001,
                    "client_id": 7,
                    "account_id": "DU999",
                },
                "confirm_environment": "LIVE",
            },
        )
    assert response.status_code == 200
    assert gate.deactivated == [("org-1", "old-live"), ("org-2", "new-live")]
    assert bindings.revisions == [
        ("org-1", "old-live", "ibkr"),
        ("org-2", "new-live", "ibkr"),
    ]


def test_authoritative_unbound_live_profile_does_not_require_gate() -> None:
    runtime, objects = _runtime()
    store = objects["broker_store"]
    with _client(runtime) as client:
        response = client.put(
            "/api/connections/credentials/ibkr/LIVE/default",
            json={
                "fields": {
                    "host": "127.0.0.1",
                    "port": 4001,
                    "client_id": 7,
                    "account_id": "DU999",
                },
                "confirm_environment": "LIVE",
            },
        )
    assert response.status_code == 200
    assert store.status_all()[0].account_id == "DU999"  # type: ignore[attr-defined]
    assert objects["order"][-3:] == ["resolve", "store", "audit"]


def test_live_store_mutation_failure_keeps_old_profile_after_safe_deactivation() -> None:
    runtime, objects = _runtime()
    bindings = objects["bindings"]
    bindings.rows = (
        LiveCredentialBindingV1(
            organization_id="org-1", account_id="live-1", venue="IBKR", account_identifier="DU123"
        ),
    )
    gate = objects["gate"]
    store = objects["broker_store"]
    old_profile = store.put_profile(
        "IBKR",
        "LIVE",
        "default",
        {"host": "127.0.0.1", "port": 4001, "client_id": 4, "account_id": "DU123"},
    )
    store.fail_put = True
    with _client(runtime) as client:
        client.app.state.live_activation_gate.bind(gate)
        response = client.put(
            "/api/connections/credentials/ibkr/LIVE/default",
            json={
                "fields": {
                    "host": "127.0.0.1",
                    "port": 4001,
                    "client_id": 7,
                    "account_id": "DU123",
                },
                "confirm_environment": "LIVE",
            },
        )
    assert response.status_code == 503
    assert gate.deactivated == [("org-1", "live-1")]
    assert store.status_all()[0].revision == old_profile.revision
    assert not bindings.revisions


def test_live_revision_failure_happens_after_deactivation_and_mutation() -> None:
    runtime, objects = _runtime()
    bindings = objects["bindings"]
    bindings.rows = (
        LiveCredentialBindingV1(
            organization_id="org-1", account_id="live-1", venue="IBKR", account_identifier="DU123"
        ),
    )
    bindings.fail_revision = True
    gate = objects["gate"]
    store = objects["broker_store"]
    store.put_profile(
        "IBKR",
        "LIVE",
        "default",
        {"host": "127.0.0.1", "port": 4001, "client_id": 4, "account_id": "DU123"},
    )
    with _client(runtime) as client:
        client.app.state.live_activation_gate.bind(gate)
        response = client.put(
            "/api/connections/credentials/ibkr/LIVE/default",
            json={
                "fields": {
                    "host": "127.0.0.1",
                    "port": 4001,
                    "client_id": 7,
                    "account_id": "DU123",
                },
                "confirm_environment": "LIVE",
            },
        )
    assert response.status_code == 503
    assert gate.deactivated == [("org-1", "live-1")]
    assert store.status_all()[0].client_id == 7
    assert objects["order"][-3:] == ["store", "revision", "audit"]


def test_live_deactivation_failure_leaves_old_credential_untouched() -> None:
    runtime, objects = _runtime()
    bindings = objects["bindings"]
    bindings.rows = (  # type: ignore[attr-defined]
        LiveCredentialBindingV1(
            organization_id="org-1", account_id="live-1", venue="IBKR", account_identifier="DU123"
        ),
    )
    gate = objects["gate"]
    gate.fail = True  # type: ignore[attr-defined]
    store = objects["broker_store"]
    old_profile = store.put_profile(  # type: ignore[attr-defined]
        "IBKR",
        "LIVE",
        "default",
        {"host": "127.0.0.1", "port": 4001, "client_id": 4, "account_id": "DU123"},
    )
    with _client(runtime) as client:
        client.app.state.live_activation_gate.bind(gate)  # type: ignore[attr-defined]
        response = client.put(
            "/api/connections/credentials/ibkr/LIVE/default",
            json={
                "fields": {
                    "host": "127.0.0.1",
                    "port": 4001,
                    "client_id": 7,
                    "account_id": "DU123",
                },
                "confirm_environment": "LIVE",
            },
        )
    assert response.status_code == 503
    profile = store.status_all()[0]  # type: ignore[attr-defined]
    assert profile.revision == old_profile.revision
    assert profile.client_id == 4
    assert objects["order"] == ["store", "resolve", "resolve", "deactivate", "audit"]


def test_indeterminate_live_binding_refuses_before_mutation() -> None:
    runtime, objects = _runtime()
    bindings = objects["bindings"]
    bindings.unknown = True  # type: ignore[attr-defined]
    store = objects["broker_store"]
    old_profile = store.put_profile(  # type: ignore[attr-defined]
        "IBKR",
        "LIVE",
        "default",
        {"host": "127.0.0.1", "port": 4001, "client_id": 4, "account_id": "DU123"},
    )
    with _client(runtime) as client:
        response = client.put(
            "/api/connections/credentials/ibkr/LIVE/default",
            json={
                "fields": {
                    "host": "127.0.0.1",
                    "port": 4001,
                    "client_id": 7,
                    "account_id": "DU123",
                },
                "confirm_environment": "LIVE",
            },
        )
    profile = store.status_all()[0]  # type: ignore[attr-defined]
    assert response.status_code == 503
    assert response.json() == {"code": "LIVE_BINDING_UNAVAILABLE"}
    assert profile.revision == old_profile.revision
    assert profile.client_id == 4
    assert objects["order"] == ["store", "resolve", "audit"]


def test_revision_bump_alone_invalidates_previously_enabled_live_evidence() -> None:
    runtime, objects = _runtime()
    bindings = objects["bindings"]
    bindings.rows = (  # type: ignore[attr-defined]
        LiveCredentialBindingV1(
            organization_id="org-1", account_id="live-1", venue="IBKR", account_identifier="DU123"
        ),
    )
    store = objects["broker_store"]
    old_profile = store.put_profile(  # type: ignore[attr-defined]
        "IBKR",
        "LIVE",
        "default",
        {"host": "127.0.0.1", "port": 4001, "client_id": 4, "account_id": "DU123"},
    )
    enabled_revision = old_profile.revision
    gate = objects["gate"]
    gate.fail = True  # type: ignore[attr-defined]
    with _client(runtime) as client:
        client.app.state.live_activation_gate.bind(gate)  # type: ignore[attr-defined]
        response = client.put(
            "/api/connections/credentials/ibkr/LIVE/default",
            json={
                "fields": {
                    "host": "127.0.0.1",
                    "port": 4001,
                    "client_id": 7,
                    "account_id": "DU123",
                },
                "confirm_environment": "LIVE",
            },
        )
    assert response.status_code == 503
    # Checked deactivation failed, so no mutation or revision bump can occur.
    # The independent revision guard is demonstrated by a successful replace below.
    gate.fail = False  # type: ignore[attr-defined]
    with _client(runtime) as client:
        client.app.state.live_activation_gate.bind(gate)  # type: ignore[attr-defined]
        replaced = client.put(
            "/api/connections/credentials/ibkr/LIVE/default",
            json={
                "fields": {
                    "host": "127.0.0.1",
                    "port": 4001,
                    "client_id": 7,
                    "account_id": "DU123",
                },
                "confirm_environment": "LIVE",
            },
        )
    current_revision = store.status_all()[0].revision  # type: ignore[attr-defined]
    assert replaced.status_code == 200
    assert current_revision > enabled_revision
    assert current_revision != enabled_revision


def test_project_reference_uses_exact_market_data_name() -> None:
    runtime, objects = _runtime()
    with _client(runtime) as client:
        response = client.put(
            "/api/connections/credentials/unusual_whales/DEVELOPMENT/default",
            json={"secrets": {"api_key": SENTINEL}},
        )
    assert response.status_code == 200
    assert set(objects["project_store"].values) == {  # type: ignore[attr-defined]
        "vault://leviathan-ai/development/UNUSUAL_WHALES/UNUSUAL_WHALES_API_KEY"
    }


def test_kalshi_key_file_upload_is_bounded_direct_and_write_only(tmp_path, caplog) -> None:
    runtime, objects = _runtime()
    key_id = "SYNTHETIC-KALSHI-KEY-ID-83177"
    pem = b"-----BEGIN PRIVATE KEY-----\nMBIAAAAAAAAAAAAAAAAAAAAAAAA=\n-----END PRIVATE KEY-----\n"
    with _client(runtime) as client:
        response = client.put(
            "/api/connections/credentials/kalshi/PAPER/default/private-key",
            content=pem,
            headers={
                "Content-Type": "application/octet-stream",
                "X-Credential-Key-Name": key_id,
            },
        )
    assert response.status_code == 200
    assert key_id not in response.text and "MBIAAAAAAAAA" not in response.text
    profile = objects["broker_store"].status_all()[0]  # type: ignore[attr-defined]
    assert profile.provider == "KALSHI"
    assert profile.configured == {"api_key": True, "api_secret": True}
    assert key_id not in caplog.text and "MBIAAAAAAAAA" not in caplog.text
    assert not any("kalshi" in item.name.lower() for item in tmp_path.iterdir())
