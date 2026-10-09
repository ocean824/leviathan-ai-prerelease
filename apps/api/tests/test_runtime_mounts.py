from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from leviathan_store.omega_due_queue import OmegaDueQueueStore
from pydantic import SecretStr

from leviathan_api.deployment_config import (
    LEDGER_INTEGRITY_SERVICE_ID,
    PROJECT_ID,
    DeploymentConfigV1,
)
from leviathan_api.mcp_runtime_factory import McpVerifiedResolverPort
from leviathan_api.omega_runtime_factory import OmegaTasksConfig
from leviathan_api.routers.mcp_control import McpControlRuntime
from leviathan_api.runtime_mounts import (
    McpRuntimeFactory,
    OmegaConfigFactory,
    RuntimeMountDependenciesV1,
    RuntimeMountStatusV1,
    VaultResolverPort,
    configure_runtime_mounts,
)
from leviathan_api.state import AppState
from leviathan_core.deployment_secret_refs import (
    issue_allowed_secret_bindings,
    issue_provider_alias_map,
)
from leviathan_core.execution.order_models import LedgerIntegrityKey
from leviathan_core.omega_link.heartbeat_adapter import InMemoryOmegaNonceStore
from leviathan_core.risk.halt import HaltAuthority
from leviathan_core.security.principal_verifier import (
    PrincipalVerifier,
    TrustedIssuerV1,
    VerifiedPrincipalV1,
)

REFERENCE = "vault://leviathan-ai/development/synthetic-provider/LEDGER_INTEGRITY_KEY"
KEY_MATERIAL = "synthetic-ledger-key-material-32-bytes-minimum"


class _Vault:
    def __init__(self, value: str = KEY_MATERIAL) -> None:
        self.value = value

    def get(self, name: str, scope: str, environment: str) -> SecretStr:
        assert name == "LEDGER_INTEGRITY_KEY"
        assert scope == "leviathan-ai"
        assert environment == "development"
        return SecretStr(self.value)


class _Log:
    def __init__(self) -> None:
        self.entries: list[dict[str, object]] = []

    def warning(self, _event: str, **values: object) -> None:
        self.entries.append(values)


class _Port:
    def snapshot(self, **_kwargs: object) -> object:
        return None

    def verify(self, **_kwargs: object) -> object:
        return None

    def get_manifest(self, **_kwargs: object) -> object:
        return None

    def authorize_tool(self, **_kwargs: object) -> object:
        return None

    def append(self, **_kwargs: object) -> None:
        return None

    def read(self, **_kwargs: object) -> tuple[()]:
        return ()

    def enqueue(self, **_kwargs: object) -> None:
        return None

    def consume(self, **_kwargs: object) -> object:
        return None

    def route_task(self, **_kwargs: object) -> object:
        return None


class _KeySet:
    def get_key(self, _issuer: str, _kid: str) -> None:
        return None


class _Revocations:
    def is_revoked(self, _issuer: str, _jti: str) -> bool:
        return False


class _Resolver(McpVerifiedResolverPort):
    def resolve_verified(
        self, _token: object, *, peer_certificate_der: object | None = None
    ) -> VerifiedPrincipalV1:
        raise AssertionError("unauthenticated test must not invoke the verifier")


def _config_text(environment: str = "PAPER", *, heartbeat: bool = True) -> str:
    heartbeat_line = "max_heartbeat_age_ns = 2000000000\n" if heartbeat else ""
    return (
        "[project]\n"
        f'project_id = "{PROJECT_ID}"\n'
        f'environment = "{environment}"\n\n'
        "[secrets]\n"
        f'ledger_integrity_key_ref = "{REFERENCE}"\n\n'
        "[omega]\n"
        'due_store_path = "omega-due.sqlite3"\n'
        f"{heartbeat_line}\n[mcp_control]\n"
        'audit_store_path = "mcp-audit.sqlite3"\n'
    )


def _dependencies(
    tmp_path: Path,
    *,
    environment: str = "PAPER",
    heartbeat: bool = True,
    vault: VaultResolverPort | None = None,
    omega: OmegaConfigFactory | None = None,
    mcp: McpRuntimeFactory | None = None,
    resolver: McpVerifiedResolverPort | None = None,
) -> RuntimeMountDependenciesV1:
    config_path = tmp_path / "runtime.toml"
    app_data = tmp_path / "runtime-data"
    app_data.mkdir(parents=True, exist_ok=True)
    config_path.write_text(_config_text(environment, heartbeat=heartbeat), encoding="utf-8")
    return RuntimeMountDependenciesV1(
        config_path=config_path,
        app_data_dir=app_data,
        allowed_bindings=issue_allowed_secret_bindings(
            ((LEDGER_INTEGRITY_SERVICE_ID, "development", REFERENCE),)
        ),
        provider_aliases=issue_provider_alias_map(()),
        vault_resolver=vault,
        omega_config_factory=omega,
        mcp_runtime_factory=mcp,
        mcp_resolver=resolver,
    )


def _omega_factory(
    config: DeploymentConfigV1,
    _key: LedgerIntegrityKey,
    _app_state: AppState,
    due_store: OmegaDueQueueStore,
) -> OmegaTasksConfig:
    policy = config.omega_policy
    certificate = b"synthetic-peer-certificate"
    fingerprint = hashlib.sha256(certificate).hexdigest()
    verifier = PrincipalVerifier(
        trusted_issuer=TrustedIssuerV1(
            issuer="test-issuer",
            audience="test-audience",
            org_id="test-org",
            project_id="test-project",
            env="PAPER",
        ),
        key_set=_KeySet(),
        revocations=_Revocations(),
        clock=lambda: datetime.now(UTC),
    )
    port: Any = _Port()
    return OmegaTasksConfig(
        bridge_health_port=port,
        session_verifier=port,
        manifest_port=port,
        mcp_authorizer=port,
        task_store=due_store,
        audit_sink=port,
        event_outbox=port,
        rate_limiter=port,
        model_policy=port,
        omega_policy=policy,
        clock=lambda: 1,
        adapter_verifier=verifier,
        pinned_certificates={fingerprint: "synthetic-peer"},
        nonce_store=InMemoryOmegaNonceStore(),
        adapter_clock_ns=lambda: 1,
        response_signer=lambda payload: hashlib.sha256(payload).hexdigest(),
        denial_auditor=lambda _code: None,
        capability_manifest_hash="a" * 64,
        close_resources=lambda: None,
    )


def _mcp_factory(_config: DeploymentConfigV1, app_state: AppState) -> McpControlRuntime:
    return McpControlRuntime(
        context_resolver=lambda *_args, **_kwargs: None,
        grants_resolver=lambda *_args, **_kwargs: (),
        attestation_resolver=lambda *_args, **_kwargs: None,
        approval_resolver=lambda *_args, **_kwargs: None,
        halt_authority=app_state.halts,
        now_ns=lambda: 1,
    )


def _configure(
    dependencies: RuntimeMountDependenciesV1, tmp_path: Path
) -> tuple[FastAPI, RuntimeMountStatusV1, _Log]:
    app = FastAPI()
    logger = _Log()
    app_state = cast(AppState, SimpleNamespace(halts=HaltAuthority()))
    status = configure_runtime_mounts(
        app,
        dependencies,
        logger=logger,
        app_state=app_state,
    )
    return app, status, logger


def test_missing_config_fails_closed_without_exposing_input(tmp_path: Path) -> None:
    dependencies = RuntimeMountDependenciesV1()
    app, status, logger = _configure(dependencies, tmp_path)
    assert status.omega_reason == "RUNTIME_NOT_CONFIGURED"
    assert status.mcp_reason == "RUNTIME_NOT_CONFIGURED"
    assert logger.entries == [{"subsystem": "runtime", "reason_code": "RUNTIME_NOT_CONFIGURED"}]
    assert app.state.omega_tasks is None
    assert app.state.mcp_control_runtime is None


def test_live_config_and_missing_heartbeat_are_rejected_content_free(tmp_path: Path) -> None:
    _, status, logger = _configure(
        _dependencies(tmp_path / "live", environment="LIVE", vault=_Vault()),
        tmp_path,
    )
    assert status.omega_reason == "RUNTIME_NOT_CONFIGURED"
    assert status.mcp_reason == "RUNTIME_NOT_CONFIGURED"
    assert logger.entries[-1]["reason_code"] == "RUNTIME_NOT_CONFIGURED"

    no_sla = tmp_path / "no-sla"
    no_sla.mkdir()
    _, status, logger = _configure(_dependencies(no_sla, heartbeat=False, vault=_Vault()), tmp_path)
    assert status.omega_reason == "RUNTIME_NOT_CONFIGURED"
    assert logger.entries[-1]["reason_code"] == "HEARTBEAT_SLA_REQUIRED"


def test_vault_failure_is_fixed_and_never_logs_secret(tmp_path: Path) -> None:
    secret_canary = "sk_live_synthetic_secret_canary"

    class BrokenVault:
        def get(self, _name: str, _scope: str, _environment: str) -> SecretStr:
            raise RuntimeError(secret_canary)

    app, status, logger = _configure(_dependencies(tmp_path, vault=BrokenVault()), tmp_path)
    assert status.omega_reason == "RUNTIME_NOT_CONFIGURED"
    assert status.mcp_reason == "RUNTIME_NOT_CONFIGURED"
    assert secret_canary not in repr(logger.entries)
    assert app.state.omega_tasks is None


def test_missing_runtime_ports_have_subsystem_specific_fixed_codes(tmp_path: Path) -> None:
    app, status, logger = _configure(_dependencies(tmp_path, vault=_Vault()), tmp_path)
    assert status.omega_reason == "OMEGA_PORTS_UNAVAILABLE"
    assert status.mcp_reason == "MCP_CONTROL_UNAVAILABLE"
    assert app.state.omega_tasks is None
    assert logger.entries == [
        {"subsystem": "omega", "reason_code": "OMEGA_PORTS_UNAVAILABLE"},
        {"subsystem": "mcp_control", "reason_code": "MCP_CONTROL_UNAVAILABLE"},
    ]


def test_complete_synthetic_dependencies_configure_both_runtimes(tmp_path: Path) -> None:
    dependencies = _dependencies(
        tmp_path,
        vault=_Vault(),
        omega=_omega_factory,
        mcp=_mcp_factory,
        resolver=_Resolver(),
    )
    app, status, logger = _configure(dependencies, tmp_path)
    assert status.omega_reason is None
    assert status.mcp_reason is None
    assert app.state.omega_tasks is not None
    assert app.state.omega_adapter is not None
    assert app.state.mcp_control_runtime is not None
    assert app.state.mcp_control_principal_resolver is not None
    assert logger.entries == []
    # Runtime resources are temporary test files and are closed after assertions.
    from leviathan_api.runtime_mounts import close_runtime_mounts

    close_runtime_mounts(app)


def test_unconfigured_routes_remain_registered_and_return_no_store_503(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import leviathan_api.main as main

    class _Halts:
        fault_code = None
        halted = False

        def close(self) -> None:
            return None

    fake_state = SimpleNamespace(
        settings=SimpleNamespace(
            database_url="unused", operating_mode=SimpleNamespace(value="PAPER")
        ),
        orders=None,
        dispatch_gate=None,
        halts=_Halts(),
        killed_providers=set(),
    )

    class _Engine:
        async def dispose(self) -> None:
            return None

    async def _build_db(_url: str) -> tuple[object, object]:
        return _Engine(), object()

    monkeypatch.setattr(main, "build_app_state", lambda: fake_state)
    monkeypatch.setattr(main, "build_db", _build_db)
    client = TestClient(main.create_app())
    for path in ("/v1/omega/tools/manifest", "/mcp/tools"):
        response = client.get(path)
        assert response.status_code == 503
        assert response.json() == {"detail": "RUNTIME_NOT_CONFIGURED"}
        assert response.headers["cache-control"] == "no-store"
    from leviathan_api.routers import mcp_control, omega_tasks

    assert any(
        getattr(route, "path", None) == "/v1/omega/tools/manifest"
        for route in omega_tasks.router.routes
    )
    assert any(getattr(route, "path", None) == "/mcp/tools" for route in mcp_control.router.routes)
    client.close()
