"""Independent public-boundary acceptance for write-only Connections credentials."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr, ValidationError

import leviathan_api.wave35_mounts as wave35_mounts
from leviathan_api.chat.models import ChatToolProposalV1
from leviathan_api.chat.tool_bridge import (
    AppRouteOutcomeV1,
    ChatToolBridgeV1,
    ChatToolReadRequestV1,
    ToolDecisionCodeV1,
)
from leviathan_api.credential_connections import (
    BROKER_IDS,
    DATA_SECRET_NAMES,
    CredentialActionRequestV1,
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
from leviathan_api.market_data_runtime_config import MarketDataRuntimeConfigV1
from leviathan_api.middleware.license_gate import FEATURE_KEYS_V1, LicenseGateMiddleware
from leviathan_api.settings import Settings
from leviathan_api.state import build_app_state
from leviathan_api.wave35_mounts import (
    Wave35MountDependenciesV1,
    close_wave35_mounts,
    configure_wave35_mounts,
)
from leviathan_core.risk.halt_store import HaltStore, ProfileClassification, ProfileEvidence
from leviathan_core.security.authz_models import (
    _VERIFIER_MARKER,
    PrincipalV1,
    TrustedPrincipalAdapterV1,
)
from leviathan_core.security.principal_verifier import (
    PrincipalVerifier,
    RSAPublicKeyV1,
    TrustedIssuerV1,
    VerifiedPrincipalV1,
)
from leviathan_vault.app_credentials import InMemoryCredentialStore
from leviathan_vault.project_secrets import MacOSProjectSecretStore, ProjectSecretError

_SECRET = "SYNTHETIC-CREDENTIAL-LEAK-SENTINEL-20261009-Q7m2"
_PASSWORD = "SYNTHETIC-MT5-PASSWORD-SENTINEL-20261009-P4k8"
_NOW_NS = 1_800_000_000_000_000_000


class _ProjectSecrets:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], SecretStr] = {}

    def configured(self, reference: str, name: str) -> bool:
        return (reference, name) in self.values

    def put(self, reference: str, name: str, value: SecretStr) -> None:
        self.values[(reference, name)] = value

    def get(self, reference: str, name: str) -> SecretStr:
        return self.values[(reference, name)]

    def remove(self, reference: str, name: str) -> None:
        self.values.pop((reference, name), None)


class _BrokerStore(InMemoryCredentialStore):
    def __init__(self) -> None:
        super().__init__()
        self.fail_put = False

    def put_profile(self, provider: str, environment: str, profile_id: str, fields: Any) -> Any:
        if self.fail_put:
            raise OSError(_SECRET)
        return super().put_profile(provider, environment, profile_id, fields)


class _Audit:
    def __init__(self) -> None:
        self.events: list[CredentialAuditEventV1] = []

    def append(self, event: CredentialAuditEventV1) -> None:
        self.events.append(event)


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


class _Tester:
    def __init__(self) -> None:
        self.references: list[CredentialReferenceV1] = []

    def test(self, reference: CredentialReferenceV1) -> CredentialTestResultV1:
        self.references.append(reference)
        return CredentialTestResultV1(verified=True)


class _Bindings:
    def __init__(self) -> None:
        self.rows: tuple[LiveCredentialBindingV1, ...] = ()
        self.unknown = False
        self.revisions: list[tuple[str, str, str]] = []

    def resolve_bindings(
        self, venue: str, account_identifier: str
    ) -> tuple[LiveCredentialBindingV1, ...] | None:
        if self.unknown:
            return None
        return tuple(
            row
            for row in self.rows
            if row.venue == venue and row.account_identifier == account_identifier
        )

    def bump_credential_revision(
        self, organization_id: str, account_id: str, provider_id: str
    ) -> None:
        self.revisions.append((organization_id, account_id, provider_id))


class _Gate:
    def __init__(self, order: list[str] | None = None) -> None:
        self.deactivated: list[tuple[str, str]] = []
        self.fail = False
        self.order = order if order is not None else []

    def live_account_enabled(self, _account_id: str) -> bool:
        return True

    def deactivate_account(self, organization_id: str, account_id: str) -> None:
        self.order.append("deactivate")
        if self.fail:
            raise OSError(_SECRET)
        self.deactivated.append((organization_id, account_id))


class _Clock:
    def __init__(self, now_ns: int = _NOW_NS) -> None:
        self.now_ns = now_ns

    def __call__(self) -> int:
        return self.now_ns


def _runtime(
    *, clock: _Clock | None = None
) -> tuple[CredentialConnectionsRuntimeV1, dict[str, Any]]:
    order: list[str] = []
    objects: dict[str, Any] = {
        "broker": _BrokerStore(),
        "project": _ProjectSecrets(),
        "audit": _Audit(),
        "status": _Status(),
        "tester": _Tester(),
        "bindings": _Bindings(),
        "gate": _Gate(order),
        "order": order,
        "clock": clock or _Clock(),
    }
    runtime = CredentialConnectionsRuntimeV1(
        credential_store=objects["broker"],
        project_secret_store=objects["project"],
        tester=objects["tester"],
        audit=objects["audit"],
        status=objects["status"],
        live_bindings=objects["bindings"],
        clock_ns=objects["clock"],
        confirmation_port=InMemoryCredentialConfirmationPortV1(),
    )
    return runtime, objects


def _client(
    runtime: CredentialConnectionsRuntimeV1,
    *,
    license_state: str | None = None,
) -> TestClient:
    app = FastAPI()
    app.include_router(create_credential_connections_router(runtime), prefix="/api")
    principal = TrustedPrincipalAdapterV1.from_verified_claims(
        PrincipalV1(
            principal_id="credential-acceptance-operator",
            project_id="leviathan-ai",
            roles=("operator",),
            env="production",
        ),
        verifier_marker=_VERIFIER_MARKER,
    )
    app.state.live_activation_gate = LazyLiveActivationGateV1()

    @app.middleware("http")
    async def inject_principal(request, call_next):  # type: ignore[no-untyped-def]
        request.state.trusted_principal = principal
        return await call_next(request)

    if license_state is None:
        return TestClient(app, base_url="http://127.0.0.1:8000", client=("127.0.0.1", 51000))
    features = ",".join(sorted(FEATURE_KEYS_V1))
    return TestClient(
        LicenseGateMiddleware(
            app,
            environ={
                "LEVIATHAN_LICENSE_STATE": license_state,
                "LEVIATHAN_LICENSE_FEATURES": features,
            },
        ),
        base_url="http://127.0.0.1:8000",
        client=("127.0.0.1", 51000),
    )


def _live_binding(provider: str, account_identifier: str) -> LiveCredentialBindingV1:
    return LiveCredentialBindingV1(
        organization_id="org-credential-acceptance",
        account_id="live-account-credential-acceptance",
        venue=BROKER_IDS[provider],
        account_identifier=account_identifier,
    )


def _key_pair_with_sentinel() -> tuple[bytes, str]:
    payload = (_SECRET + "-KALSHI-KEY-MATERIAL").encode("ascii")
    der = b"\x30" + bytes([len(payload)]) + payload
    body = base64.b64encode(der).decode("ascii")
    pem = f"-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----\n"
    return pem.encode("ascii"), pem


def test_sentinel_never_leaks_from_data_mt5_or_kalshi_mutations(
    caplog: pytest.LogCaptureFixture,
) -> None:
    runtime, objects = _runtime()
    key_bytes, pem_text = _key_pair_with_sentinel()
    captured_api: list[tuple[str, dict[str, str]]] = []
    with _client(runtime) as client:
        data = client.put(
            "/api/connections/credentials/databento/DEVELOPMENT/default",
            json={"secrets": {"api_key": _SECRET}},
        )
        mt5 = client.put(
            "/api/connections/credentials/mt5_forexcom/DEMO/default",
            json={
                "fields": {"server": "demo.synthetic", "login": "acct-42"},
                "secrets": {"password": _PASSWORD},
            },
        )
        kalshi = client.put(
            "/api/connections/credentials/kalshi/PAPER/default/private-key",
            content=key_bytes,
            headers={
                "Content-Type": "application/octet-stream",
                "X-Credential-Key-Name": "synthetic-kalshi-key",
            },
        )
        for response in (data, mt5, kalshi):
            captured_api.append((response.text, dict(response.headers)))
            assert response.status_code == 200

    audit_wire = "\n".join(event.model_dump_json() for event in objects["audit"].events)
    logs = caplog.text
    errors = "\n".join(str(error) for error in caplog.records)
    corpus = repr((captured_api, audit_wire, logs, errors))
    for canary in (_SECRET, _PASSWORD, pem_text, base64.b64encode(key_bytes).decode("ascii")):
        assert canary not in corpus
    assert len(objects["audit"].events) == 3


def test_validation_exception_text_never_contains_submitted_secret() -> None:
    oversized = _SECRET + ("x" * 16384)
    with pytest.raises(ValidationError) as raised:
        CredentialActionRequestV1.model_validate({"secrets": {"api_key": oversized}})
    assert _SECRET not in str(raised.value)
    assert _SECRET not in repr(raised.value.args)


def test_backend_failure_response_headers_and_logs_are_content_free(
    caplog: pytest.LogCaptureFixture,
) -> None:
    runtime, objects = _runtime()
    objects["broker"].fail_put = True
    with _client(runtime) as client:
        response = client.put(
            "/api/connections/credentials/mt5_forexcom/DEMO/default",
            json={
                "fields": {"server": "demo.synthetic", "login": "account-42"},
                "secrets": {"password": _PASSWORD},
            },
        )
    assert response.status_code == 503
    assert response.json() == {"code": "CREDENTIALS_UNAVAILABLE"}
    exposed = response.text + repr(dict(response.headers)) + caplog.text
    exposed += "\n".join(str(record) for record in caplog.records)
    assert _PASSWORD not in exposed


def test_connections_written_market_data_keys_resolve_under_exact_refs() -> None:
    runtime, objects = _runtime()
    with _client(runtime) as client:
        for index, (provider, name) in enumerate(DATA_SECRET_NAMES.items()):
            value = f"SYNTHETIC-DATA-KEY-{index:02d}-20261009"
            response = client.put(
                f"/api/connections/credentials/{provider}/DEVELOPMENT/default",
                json={"secrets": {"api_key": value}},
            )
            assert response.status_code == 200
            reference = f"vault://leviathan-ai/development/{provider.upper()}/{name}"
            assert objects["project"].get(reference, name).get_secret_value() == value
            assert objects["project"].configured(reference, name)


def test_wave35_market_data_ref_resolver_reads_connections_written_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime, objects = _runtime()
    written: dict[str, str] = {}
    with _client(runtime) as client:
        for index, (provider, _name) in enumerate(DATA_SECRET_NAMES.items()):
            value = f"SYNTHETIC-WAVE35-KEY-{index:02d}-20261009"
            response = client.put(
                f"/api/connections/credentials/{provider}/DEVELOPMENT/default",
                json={"secrets": {"api_key": value}},
            )
            assert response.status_code == 200
            written[provider] = value

    config = MarketDataRuntimeConfigV1.model_validate(
        {
            "schema_version": 1,
            "project_id": "credential-acceptance",
            "environment": "PAPER",
            "databento": {
                "enabled": False,
                "dataset": "synthetic-dataset",
                "stype_in": "raw_symbol",
                "schemas": ("trades",),
                "instruments": ("SYNTHETIC.SYMBOL",),
            },
            "massive": {
                "enabled": False,
                "dataset": "synthetic-dataset",
                "stype_in": "raw_symbol",
                "schemas": ("trades",),
                "instruments": ("SYNTHETIC.SYMBOL",),
            },
            "backfill": {
                "max_jobs": 2,
                "max_records": 1000,
                "max_window_ns": 86400000000000,
                "max_estimated_usd": "3.50",
            },
            "reconnect": {"min_delay_ms": 200, "max_delay_ms": 5000, "max_attempts": 5},
        },
        strict=True,
    )
    app = FastAPI()
    settings = Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        halt_store_path=tmp_path / "halt-state.sqlite3",
    )
    repo = Path(__file__).resolve().parents[3]
    lock_path = repo / "tests" / "fixtures" / "risk_lock" / "risk_governance.lock.yaml"
    HaltStore.provision_new(
        settings.halt_store_path,
        tmp_path,
        ProfileEvidence(
            ProfileClassification.NEVER_PROVISIONED,
            verified=True,
            references=("pytest:credential-device-acceptance",),
        ),
    )
    settings.risk_lock_sha256 = hashlib.sha256(lock_path.read_bytes()).hexdigest()
    app_state = build_app_state(
        settings=settings,
        lock_path=lock_path,
    )
    dependencies = Wave35MountDependenciesV1(
        project_secret_store=objects["project"],
        market_data_runtime_config=config,
    )
    resolver_calls: list[tuple[str, str, str]] = []

    class _ResolverProbe:
        def __init__(self, *, vault_ref_resolver: Any, **_kwargs: Any) -> None:
            self.vault_ref_resolver = vault_ref_resolver

        def start(self) -> None:
            return None

        async def close(self) -> None:
            return None

        def read_venue_health(self, *_args: Any, **_kwargs: Any) -> None:
            return None

        def read_latest(self, *_args: Any, **_kwargs: Any) -> None:
            return None

        def preview_backfill(self, *_args: Any, **_kwargs: Any) -> None:
            return None

        async def enqueue_backfill(self, *_args: Any, **_kwargs: Any) -> None:
            return None

        def read_backfill_job(self, *_args: Any, **_kwargs: Any) -> None:
            return None

        async def open_chart_stream(self, *_args: Any, **_kwargs: Any) -> None:
            return None

    monkeypatch.setattr(wave35_mounts, "MarketDataRuntime", _ResolverProbe)
    try:
        configure_wave35_mounts(app, dependencies, app_state=app_state)
        market_data_runtime = app.state.market_data_runtime
        assert market_data_runtime is not None
        for provider, value in written.items():
            if provider not in {"databento", "massive"}:
                continue
            secret_name = DATA_SECRET_NAMES[provider]
            reference = f"vault://leviathan-ai/development/{provider.upper()}/{secret_name}"
            resolved = market_data_runtime.vault_ref_resolver(reference, secret_name)
            resolver_calls.append((reference, secret_name, resolved))
            assert resolved == value
        assert {row[0] for row in resolver_calls} == {
            f"vault://leviathan-ai/development/{provider.upper()}/{DATA_SECRET_NAMES[provider]}"
            for provider in ("databento", "massive")
        }
    finally:
        asyncio.run(close_wave35_mounts(app))
        app_state.halts.close()


class _FakeKeyring:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, username: str) -> str | None:
        return self.values.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self.values[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        self.values.pop((service, username), None)


def test_non_apple_keychain_backend_is_rejected_without_secret_echo() -> None:
    keyring = _FakeKeyring()
    with pytest.raises(ProjectSecretError) as raised:
        MacOSProjectSecretStore(keyring)
    assert raised.value.code == "SECRET_UNAVAILABLE"
    assert "SYNTHETIC" not in str(raised.value)


def _legacy_app(runtime: CredentialConnectionsRuntimeV1, objects: dict[str, Any]) -> FastAPI:
    app = FastAPI()
    app.include_router(create_credential_connections_router(runtime))
    app.state.credential_store = objects["broker"]
    app.state.credential_connections_runtime = runtime
    app.state.live_activation_gate = LazyLiveActivationGateV1()
    app.state.live_activation_gate.bind(objects["gate"])

    principal = TrustedPrincipalAdapterV1.from_verified_claims(
        PrincipalV1(
            principal_id="credential-acceptance-operator",
            project_id="leviathan-ai",
            roles=("operator",),
            env="production",
        ),
        verifier_marker=_VERIFIER_MARKER,
    )

    @app.middleware("http")
    async def inject_principal(request, call_next):  # type: ignore[no-untyped-def]
        request.state.trusted_principal = principal
        return await call_next(request)

    return app


def test_legacy_live_trading_replace_cannot_bypass_live_deactivation_and_revision() -> None:
    runtime, objects = _runtime()
    binding = _live_binding("mt5_forexcom", "demo.synthetic:login-42")
    objects["bindings"].rows = (binding,)
    store = objects["broker"]
    old = store.put_profile(
        "MT5",
        "LIVE",
        "default",
        {"server": "demo.synthetic", "login": "login-42", "password": SecretStr("old")},
    )
    app = _legacy_app(runtime, objects)
    with TestClient(app, base_url="http://127.0.0.1:8000", client=("127.0.0.1", 51000)) as client:
        response = client.put(
            "/live-trading/credentials/MT5/LIVE/default",
            json={
                "server": "demo.synthetic",
                "login": "login-42",
                "password": _PASSWORD,
                "confirm_environment": "LIVE",
            },
        )
    current = store.resolve("MT5", "LIVE", "default")
    assert response.status_code == 200
    assert objects["gate"].deactivated == [(binding.organization_id, binding.account_id)]
    assert objects["bindings"].revisions == [
        (binding.organization_id, binding.account_id, "mt5_forexcom")
    ]
    assert current.revision > old.revision, (response.json(), store.status_all())
    assert current.secret("password").get_secret_value() == _PASSWORD


def test_legacy_live_trading_remove_cannot_bypass_live_deactivation_and_revision() -> None:
    runtime, objects = _runtime()
    binding = _live_binding("mt5_forexcom", "demo.synthetic:login-42")
    objects["bindings"].rows = (binding,)
    store = objects["broker"]
    store.put_profile(
        "MT5",
        "LIVE",
        "default",
        {"server": "demo.synthetic", "login": "login-42", "password": SecretStr("old")},
    )
    app = _legacy_app(runtime, objects)
    with TestClient(app, base_url="http://127.0.0.1:8000", client=("127.0.0.1", 51000)) as client:
        confirmation = client.post(
            "/live-trading/credentials/MT5/LIVE/default/remove-confirmation",
            headers={"Origin": "http://127.0.0.1:8000"},
        )
        assert confirmation.status_code == 200
        response = client.request(
            "DELETE",
            "/live-trading/credentials/MT5/LIVE/default",
            json={
                "confirm_environment": "LIVE",
                "confirmation_token": confirmation.json()["confirmation_token"],
            },
        )
    assert response.status_code == 204
    assert objects["gate"].deactivated == [(binding.organization_id, binding.account_id)]
    assert objects["bindings"].revisions == [
        (binding.organization_id, binding.account_id, "mt5_forexcom")
    ]
    assert not any(
        profile.provider == "MT5" and profile.environment == "LIVE"
        for profile in store.status_all()
    )


def test_live_replace_deactivates_before_mutation_and_bumps_revision() -> None:
    runtime, objects = _runtime()
    binding = _live_binding("mt5_forexcom", "demo.synthetic:login-42")
    objects["bindings"].rows = (binding,)
    old = objects["broker"].put_profile(
        "MT5_FOREXCOM",
        "LIVE",
        "default",
        {"server": "demo.synthetic", "login": "login-42", "password": SecretStr("old-password")},
    )
    gate = objects["gate"]
    store = objects["broker"]
    original_put = store.put_profile

    def record_put(provider, env, profile_id, fields):  # type: ignore[no-untyped-def]
        objects.setdefault("order", []).append("mutate")
        return original_put(provider, env, profile_id, fields)

    store.put_profile = record_put  # type: ignore[method-assign]
    with _client(runtime) as client:
        client.app.state.live_activation_gate.bind(gate)
        response = client.put(
            "/api/connections/credentials/mt5_forexcom/LIVE/default",
            json={
                "fields": {"server": "demo.synthetic", "login": "login-42"},
                "secrets": {"password": _PASSWORD},
                "confirm_environment": "LIVE",
            },
        )
    assert response.status_code == 200
    profile = store.status_all()[0]
    assert (
        store.resolve("MT5_FOREXCOM", "LIVE", "default").secret("password").get_secret_value()
        == _PASSWORD
    )
    assert profile.revision > old.revision
    assert objects["bindings"].revisions == [
        (binding.organization_id, binding.account_id, "mt5_forexcom")
    ]
    assert objects["order"].index("deactivate") < objects["order"].index("mutate")


def test_live_deactivation_failure_refuses_mutation_and_preserves_old_secret() -> None:
    runtime, objects = _runtime()
    binding = _live_binding("mt5_forexcom", "demo.synthetic:login-42")
    objects["bindings"].rows = (binding,)
    old = objects["broker"].put_profile(
        "MT5_FOREXCOM",
        "LIVE",
        "default",
        {"server": "demo.synthetic", "login": "login-42", "password": SecretStr("old-password")},
    )
    objects["gate"].fail = True
    with _client(runtime) as client:
        client.app.state.live_activation_gate.bind(objects["gate"])
        response = client.put(
            "/api/connections/credentials/mt5_forexcom/LIVE/default",
            json={
                "fields": {"server": "demo.synthetic", "login": "login-42"},
                "secrets": {"password": _PASSWORD},
                "confirm_environment": "LIVE",
            },
        )
    assert response.status_code == 503
    assert response.json() == {"code": "LIVE_ACTIVATION_UNAVAILABLE"}
    current = objects["broker"].status_all()[0]
    assert current.revision == old.revision
    assert (
        objects["broker"]
        .resolve("MT5_FOREXCOM", "LIVE", "default")
        .secret("password")
        .get_secret_value()
        == "old-password"
    )
    assert not objects["bindings"].revisions


def test_unknown_live_bindings_fail_closed_before_mutation() -> None:
    runtime, objects = _runtime()
    old = objects["broker"].put_profile(
        "MT5_FOREXCOM",
        "LIVE",
        "default",
        {"server": "demo.synthetic", "login": "login-42", "password": SecretStr("old-password")},
    )
    objects["bindings"].unknown = True
    with _client(runtime) as client:
        response = client.put(
            "/api/connections/credentials/mt5_forexcom/LIVE/default",
            json={
                "fields": {"server": "demo.synthetic", "login": "login-42"},
                "secrets": {"password": _PASSWORD},
                "confirm_environment": "LIVE",
            },
        )
    assert response.status_code == 503
    assert response.json() == {"code": "LIVE_BINDING_UNAVAILABLE"}
    current = objects["broker"].status_all()[0]
    assert current.revision == old.revision
    assert (
        objects["broker"]
        .resolve("MT5_FOREXCOM", "LIVE", "default")
        .secret("password")
        .get_secret_value()
        == "old-password"
    )


def test_remove_confirmation_is_bound_single_use_and_clock_expiring() -> None:
    clock = _Clock()
    runtime, objects = _runtime(clock=clock)
    objects["project"].put(
        "vault://leviathan-ai/development/DATABENTO/DATABENTO_API_KEY",
        "DATABENTO_API_KEY",
        SecretStr("old"),
    )
    with _client(runtime) as client:
        path = "/api/connections/credentials/databento/DEVELOPMENT/default"
        confirmation = client.post(
            path + "/remove-confirmation", headers={"Origin": "http://127.0.0.1:8000"}
        )
        token = confirmation.json()["confirmation_token"]
        removed = client.request("DELETE", path, json={"confirmation_token": token})
        reused = client.request("DELETE", path, json={"confirmation_token": token})
        mismatched_provider = client.post(
            "/api/connections/credentials/massive/DEVELOPMENT/default/remove-confirmation",
            headers={"Origin": "http://127.0.0.1:8000"},
        )
        wrong_provider_remove = client.request(
            "DELETE",
            path,
            json={"confirmation_token": mismatched_provider.json()["confirmation_token"]},
        )
        missing = client.request("DELETE", path, json={})
        other_profile_token, _ = runtime.confirmation_port.issue(
            principal_id="credential-acceptance-operator",
            provider_id="databento",
            environment="DEVELOPMENT",
            profile_id="other-profile",
            action="REMOVE",
            now_ns=clock.now_ns,
        )
        wrong_profile = client.request(
            "DELETE", path, json={"confirmation_token": other_profile_token}
        )
        expiring = client.post(
            path + "/remove-confirmation", headers={"Origin": "http://127.0.0.1:8000"}
        )
        clock.now_ns += 60_000_000_000
        expired = client.request(
            "DELETE", path, json={"confirmation_token": expiring.json()["confirmation_token"]}
        )
    assert removed.status_code == 200
    for response in (reused, wrong_provider_remove, missing, wrong_profile, expired):
        assert response.status_code == 403
        assert response.json() == {"code": "CONFIRMATION_REQUIRED"}
    assert not objects["project"].values


@pytest.mark.parametrize(
    "bad_body",
    [
        b"not-a-pem-private-key",
        b"-----BEGIN PRIVATE KEY-----\nnot-base64!!\n-----END PRIVATE KEY-----\n",
    ],
)
def test_kalshi_upload_rejects_non_pem_without_echo(bad_body: bytes) -> None:
    runtime, _ = _runtime()
    with _client(runtime) as client:
        response = client.put(
            "/api/connections/credentials/kalshi/PAPER/default/private-key",
            content=bad_body,
            headers={
                "Content-Type": "application/octet-stream",
                "X-Credential-Key-Name": "synthetic",
            },
        )
    assert response.status_code == 422
    assert response.json() == {"code": "INVALID_CREDENTIAL"}
    assert "not-a-pem" not in response.text


def test_kalshi_upload_rejects_oversize_before_mutation() -> None:
    runtime, objects = _runtime()
    huge = b"x" * (64 * 1024 + 1)
    with _client(runtime) as client:
        response = client.put(
            "/api/connections/credentials/kalshi/PAPER/default/private-key",
            content=huge,
            headers={
                "Content-Type": "application/octet-stream",
                "X-Credential-Key-Name": "synthetic",
            },
        )
    assert response.status_code == 422
    assert response.json() == {"code": "INVALID_CREDENTIAL"}
    assert not objects["broker"].status_all()


def test_grace_read_only_denies_replace_and_remove() -> None:
    runtime, objects = _runtime()
    objects["project"].put(
        "vault://leviathan-ai/development/DATABENTO/DATABENTO_API_KEY",
        "DATABENTO_API_KEY",
        SecretStr("old"),
    )
    with _client(runtime, license_state="GRACE_READ_ONLY") as client:
        path = "/api/connections/credentials/databento/DEVELOPMENT/default"
        replace = client.put(path, json={"secrets": {"api_key": _SECRET}})
        remove = client.request("DELETE", path, json={"confirmation_token": "a" * 48})
    assert replace.status_code == 403 and replace.json() == {"code": "LICENSE_READ_ONLY"}
    assert remove.status_code == 403 and remove.json() == {"code": "LICENSE_READ_ONLY"}
    assert (
        objects["project"]
        .get("vault://leviathan-ai/development/DATABENTO/DATABENTO_API_KEY", "DATABENTO_API_KEY")
        .get_secret_value()
        == "old"
    )


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _chat_principal() -> VerifiedPrincipalV1:
    fixture = (
        Path(__file__).resolve().parents[3]
        / "packages/leviathan-core/tests/security/fixtures/sec003_synthetic_rsa.json"
    )
    key = json.loads(fixture.read_text(encoding="utf-8"))
    modulus = int(key["modulus_hex"], 16)
    private = int(key["private_exponent_hex"], 16)
    exponent = int(key["public_exponent_hex"], 16)
    now = datetime.fromtimestamp(_NOW_NS / 1_000_000_000, tz=UTC)
    seconds = int(now.timestamp())
    header = _b64url(
        json.dumps({"alg": "RS256", "kid": "chat-synthetic-key"}, separators=(",", ":")).encode()
    )
    claims = {
        "iss": "chat-synthetic-idp",
        "aud": "chat-backend",
        "org": "org-chat-fixture",
        "sub": "credential-chat-reader",
        "role": "Operator",
        "scope": ["mcp:read"],
        "env": "paper",
        "jti": "credential-read-jti",
        "iat": seconds,
        "nbf": seconds,
        "exp": seconds + 300,
        "portfolio": "paper-account",
    }
    payload = _b64url(json.dumps(claims, sort_keys=True, separators=(",", ":")).encode())
    signing_input = f"{header}.{payload}".encode("ascii")
    digest_info = (
        bytes.fromhex("3031300d060960864801650304020105000420")
        + hashlib.sha256(signing_input).digest()
    )
    width = (modulus.bit_length() + 7) // 8
    encoded = b"\x00\x01" + b"\xff" * (width - len(digest_info) - 3) + b"\x00" + digest_info
    signature = pow(int.from_bytes(encoded, "big"), private, modulus).to_bytes(width, "big")
    token = f"{header}.{payload}.{_b64url(signature)}"
    verifier = PrincipalVerifier(
        trusted_issuer=TrustedIssuerV1(
            issuer="chat-synthetic-idp",
            audience="chat-backend",
            org_id="org-chat-fixture",
            project_id="project-chat-fixture",
            env="paper",
        ),
        key_set=type(
            "Keys",
            (),
            {
                "get_key": lambda _self, issuer, kid: (
                    RSAPublicKeyV1(modulus, exponent)
                    if (issuer, kid) == ("chat-synthetic-idp", "chat-synthetic-key")
                    else None
                )
            },
        )(),
        revocations=type("Revocations", (), {"is_revoked": lambda _self, _issuer, _jti: False})(),
        clock=lambda: now,
    )
    return verifier.verify(token)


def test_chat_read_tool_status_output_contains_no_written_secret() -> None:
    runtime, _objects = _runtime()
    with _client(runtime) as http:
        replaced = http.put(
            "/api/connections/credentials/databento/DEVELOPMENT/default",
            json={"secrets": {"api_key": _SECRET}},
        )
        assert replaced.status_code == 200

        class _Route:
            async def invoke(self, _principal, *, route_id, arguments, idempotency_key):  # type: ignore[no-untyped-def]
                assert route_id == "credential_connections"
                response = http.get("/api/connections/credentials")
                return AppRouteOutcomeV1(
                    status_code=response.status_code,
                    allowed=True,
                    effect_performed=False,
                    output=response.json(),
                )

        class _Audit:
            async def append(self, _event):  # type: ignore[no-untyped-def]
                return None

        bridge = ChatToolBridgeV1(
            mcp=None, app_routes=_Route(), audit=_Audit(), now_ns=lambda: _NOW_NS
        )
        result = asyncio.run(
            bridge.read(
                _chat_principal(),
                ChatToolReadRequestV1(
                    version="1",
                    request_id="credential-read-request-1",
                    proposal=ChatToolProposalV1(
                        name="connections.credentials.status.read", arguments_json="{}"
                    ),
                ),
            )
        )
    assert result.status is ToolDecisionCodeV1.READ_ALLOWED
    assert result.output_json is not None
    assert _SECRET not in result.output_json
