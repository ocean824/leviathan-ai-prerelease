"""Black-box acceptance for config-gated OMEGA and MCP runtime mounts."""

from __future__ import annotations

import base64
import hashlib
import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest
from fastapi.testclient import TestClient
from httpx import Response
from leviathan_store.omega_due_queue import OmegaDueQueueStore
from pydantic import SecretStr

from leviathan_api.deployment_config import (
    LEDGER_INTEGRITY_SERVICE_ID,
    PROJECT_ID,
    DeploymentConfigV1,
)
from leviathan_api.main import create_app
from leviathan_api.mcp_runtime_factory import McpVerifiedResolverPort
from leviathan_api.omega_runtime_factory import OmegaTasksConfig
from leviathan_api.routers.mcp_control import McpControlRuntime
from leviathan_api.runtime_mounts import RuntimeMountDependenciesV1
from leviathan_api.state import AppState
from leviathan_core.deployment_secret_refs import (
    AllowedSecretBindingsV1,
    ProviderAliasMapV1,
    issue_allowed_secret_bindings,
    issue_provider_alias_map,
)
from leviathan_core.execution.order_models import LedgerIntegrityKey
from leviathan_core.mcp_control.policy_models import PolicyContextV1
from leviathan_core.omega_link.heartbeat_adapter import InMemoryOmegaNonceStore
from leviathan_core.omega_link.task_bridge import (
    AuditSinkPort,
    BridgeHealthPort,
    EventOutboxPort,
    ManifestPort,
    MCPAuthorizerPort,
    ModelPolicyPort,
    RateLimiterPort,
    SessionVerifierPort,
)
from leviathan_core.security.principal_verifier import (
    PrincipalVerifier,
    RSAPublicKeyV1,
    TrustedIssuerV1,
    VerifiedPrincipalV1,
)

_REFERENCE = "vault://leviathan-ai/development/synthetic-provider/LEDGER_INTEGRITY_KEY"
_SYNTHETIC_KEY = "synthetic-deploy-mount-key-material-for-tests-only"
_CANARY = "deploy-mount-no-echo-canary-731d"
_CERTIFICATE = b"synthetic deploy-mount acceptance certificate"
_NOW_NS = int(datetime(2026, 10, 6, tzinfo=UTC).timestamp() * 1_000_000_000)
_ROOT = Path(__file__).resolve().parents[3]
_RSA_FIXTURE = json.loads(
    (_ROOT / "packages/leviathan-core/tests/security/fixtures/sec003_synthetic_rsa.json").read_text(
        encoding="utf-8"
    )
)


class _Vault:
    def __init__(self, secret: str = _SYNTHETIC_KEY, *, failure: str | None = None) -> None:
        self.secret = secret
        self.failure = failure
        self.calls: list[tuple[str, str, str]] = []

    def get(self, name: str, scope: str, environment: str) -> SecretStr:
        self.calls.append((name, scope, environment))
        if self.failure is not None:
            raise RuntimeError(self.failure)
        return SecretStr(self.secret)


class _OmegaPorts:
    """Typed synthetic bridge ports; methods are inert and perform no I/O."""

    def snapshot(self, _peer_system: str) -> object:
        return object()

    def verify(self, *_args: object, **_kwargs: object) -> None:
        return None

    def get_manifest(self, _peer_system: str) -> object:
        return object()

    def authorize_tool(self, **_kwargs: object) -> object:
        return object()

    def append(self, _entry: object) -> object:
        return object()

    def read(self, **_kwargs: object) -> tuple[()]:
        return ()

    def enqueue(self, _event: object) -> None:
        return None

    def consume(self, *_args: object, **_kwargs: object) -> object:
        return object()

    def route_task(self, **_kwargs: object) -> object:
        return object()


class _KeySet:
    def get_key(self, issuer: str, kid: str) -> RSAPublicKeyV1 | None:
        if (issuer, kid) != ("mount.synthetic", "mount-key"):
            return None
        return RSAPublicKeyV1(
            int(_RSA_FIXTURE["modulus_hex"], 16),
            int(_RSA_FIXTURE["public_exponent_hex"], 16),
        )


class _Revocations:
    def is_revoked(self, _issuer: str, _jti: str) -> bool:
        return False


class _McpResolver:
    def __init__(self) -> None:
        self.verifier = PrincipalVerifier(
            trusted_issuer=TrustedIssuerV1(
                issuer="mount.synthetic",
                audience="leviathan-api",
                org_id="synthetic-org",
                project_id="leviathan-ai",
                env="test",
                require_mtls=True,
            ),
            key_set=_KeySet(),
            revocations=_Revocations(),
            clock=lambda: datetime(2026, 10, 6, tzinfo=UTC),
        )

    def resolve_verified(
        self, token: object, *, peer_certificate_der: object | None = None
    ) -> VerifiedPrincipalV1:
        if type(token) is not str:
            raise ValueError("invalid synthetic token")
        del peer_certificate_der
        return self.verifier.verify(token, peer_certificate_der=_CERTIFICATE)


def _bindings(
    reference: str = _REFERENCE,
) -> tuple[AllowedSecretBindingsV1, ProviderAliasMapV1]:
    return (
        issue_allowed_secret_bindings(((LEDGER_INTEGRITY_SERVICE_ID, "development", reference),)),
        issue_provider_alias_map(()),
    )


def _toml(
    *,
    environment: str = "PAPER",
    project_id: str = PROJECT_ID,
    reference: str = _REFERENCE,
    include_sla: bool = True,
    extra: str = "",
) -> str:
    sla = "max_heartbeat_age_ns = 2000000000\n" if include_sla else ""
    return (
        "[project]\n"
        f'project_id = "{project_id}"\n'
        f'environment = "{environment}"\n\n'
        "[secrets]\n"
        f'ledger_integrity_key_ref = "{reference}"\n\n'
        "[omega]\n"
        'due_store_path = "omega/due.sqlite3"\n'
        f"{sla}\n"
        "[mcp_control]\n"
        'audit_store_path = "mcp/audit.sqlite3"\n'
        f"{extra}"
    )


def _write_config(tmp_path: Path, document: str) -> tuple[Path, Path]:
    app_data = tmp_path / "app-data"
    app_data.mkdir()
    (app_data / "omega").mkdir()
    (app_data / "mcp").mkdir()
    config = tmp_path / "deployment.toml"
    config.write_text(document, encoding="utf-8")
    return config, app_data


def _dependencies(
    config: Path | None,
    app_data: Path | None,
    *,
    reference: str = _REFERENCE,
    vault: _Vault | None = None,
    omega: bool = False,
    mcp: bool = False,
    resolver: McpVerifiedResolverPort | None = None,
) -> RuntimeMountDependenciesV1:
    bindings, aliases = _bindings(reference)

    def omega_factory(
        config_value: DeploymentConfigV1,
        _key: LedgerIntegrityKey,
        _app_state: AppState,
        due_store: OmegaDueQueueStore,
    ) -> OmegaTasksConfig:
        ports = _OmegaPorts()
        verifier = PrincipalVerifier(
            trusted_issuer=TrustedIssuerV1(
                issuer="mount.synthetic",
                audience="leviathan-api",
                org_id="synthetic-org",
                project_id="leviathan-ai",
                env="test",
                require_mtls=True,
            ),
            key_set=_KeySet(),
            revocations=_Revocations(),
            clock=lambda: datetime(2026, 10, 6, tzinfo=UTC),
        )
        return OmegaTasksConfig(
            bridge_health_port=cast(BridgeHealthPort, ports),
            session_verifier=cast(SessionVerifierPort, ports),
            manifest_port=cast(ManifestPort, ports),
            mcp_authorizer=cast(MCPAuthorizerPort, ports),
            task_store=due_store,
            audit_sink=cast(AuditSinkPort, ports),
            event_outbox=cast(EventOutboxPort, ports),
            rate_limiter=cast(RateLimiterPort, ports),
            model_policy=cast(ModelPolicyPort, ports),
            omega_policy=config_value.omega_policy,
            clock=lambda: 1_800_000_000_000_000_000,
            adapter_verifier=verifier,
            pinned_certificates={hashlib.sha256(_CERTIFICATE).hexdigest(): "peer.synthetic"},
            nonce_store=InMemoryOmegaNonceStore(),
            adapter_clock_ns=lambda: 1_800_000_000_000_000_000,
            response_signer=lambda payload: hashlib.sha256(payload).hexdigest(),
            denial_auditor=lambda _code: None,
            capability_manifest_hash="a" * 64,
            close_resources=lambda: None,
        )

    def mcp_factory(_config: DeploymentConfigV1, app_state: AppState) -> McpControlRuntime:
        def policy_context(
            principal: VerifiedPrincipalV1,
            *,
            now_ns: int,
            **_selectors: object,
        ) -> PolicyContextV1:
            return PolicyContextV1._from_trusted_adapter(
                version="1",
                org_id=principal.org_id,
                desk_id=principal.project_id,
                agent_id="agent.synthetic",
                session_id="session.synthetic",
                evaluation_time_ns=now_ns,
                principal_verified=True,
                attestation_verified=True,
                session_active=True,
                halt_clear=True,
                risk_snapshot_at_ns=now_ns,
                risk_snapshot_max_age_ns=1_000_000_000,
                bridge_online=True,
                tools=(),
                global_max_notional=None,
                global_max_leverage=None,
                live_financial_enabled=False,
                market_open=True,
                liquidity_ok=True,
                egress_allowed=True,
                allowed_egress_domains=(),
                config_approvals=(),
                rate_remaining=10,
                max_session_quota=10,
                max_session_lifetime_ns=1_000_000_000,
                elevation_requires_approval=False,
                allowed_venues=(),
                blocked_symbols=(),
                allowed_order_types=(),
            )

        return McpControlRuntime(
            context_resolver=policy_context,
            grants_resolver=lambda *_args, **_kwargs: (),
            attestation_resolver=lambda *_args, **_kwargs: None,
            approval_resolver=lambda *_args, **_kwargs: None,
            halt_authority=app_state.halts,
            now_ns=lambda: _NOW_NS,
        )

    return RuntimeMountDependenciesV1(
        config_path=config,
        app_data_dir=app_data,
        allowed_bindings=bindings,
        provider_aliases=aliases,
        vault_resolver=vault,
        omega_config_factory=omega_factory if omega else None,
        mcp_runtime_factory=mcp_factory if mcp else None,
        mcp_resolver=resolver,
    )


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _mcp_token() -> str:
    now = _NOW_NS // 1_000_000_000
    header = _b64(
        json.dumps(
            {"alg": "RS256", "kid": "mount-key", "typ": "JWT"}, separators=(",", ":")
        ).encode()
    )
    claims = _b64(
        json.dumps(
            {
                "iss": "mount.synthetic",
                "aud": "leviathan-api",
                "org": "synthetic-org",
                "sub": "operator.synthetic",
                "role": "Operator",
                "scope": ["mcp:read"],
                "env": "test",
                "jti": "synthetic-mcp-jti",
                "iat": now - 1,
                "nbf": now - 1,
                "exp": now + 300,
                "cnf": {"x5t#S256": _b64(hashlib.sha256(_CERTIFICATE).digest())},
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    )
    signing_input = f"{header}.{claims}".encode("ascii")
    digest_info = (
        bytes.fromhex("3031300d060960864801650304020105000420")
        + hashlib.sha256(signing_input).digest()
    )
    modulus = int(_RSA_FIXTURE["modulus_hex"], 16)
    private_exponent = int(_RSA_FIXTURE["private_exponent_hex"], 16)
    width = (modulus.bit_length() + 7) // 8
    padding = width - len(digest_info) - 3
    encoded = b"\x00\x01" + b"\xff" * padding + b"\x00" + digest_info
    signature = pow(int.from_bytes(encoded, "big"), private_exponent, modulus)
    signature_segment = _b64(signature.to_bytes(width, "big"))
    return f"{header}.{claims}.{signature_segment}"


def _assert_runtime_unavailable(
    response: Response, expected: str = "RUNTIME_NOT_CONFIGURED"
) -> None:
    assert response.status_code == 503
    assert response.json() == {"detail": expected}
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.parametrize(
    ("document", "resolver_mode", "expected_reason"),
    [
        ("[project\n", "valid", "RUNTIME_NOT_CONFIGURED"),
        (
            _toml(extra='unexpected = "unknown-canary"\n'),
            "valid",
            "RUNTIME_NOT_CONFIGURED",
        ),
        (_toml(reference=_CANARY), "valid", "RUNTIME_NOT_CONFIGURED"),
        (
            _toml().replace(f'ledger_integrity_key_ref = "{_REFERENCE}"\n', ""),
            "valid",
            "RUNTIME_NOT_CONFIGURED",
        ),
        (_toml(include_sla=False), "valid", "RUNTIME_NOT_CONFIGURED"),
        (_toml(environment="LIVE"), "valid", "RUNTIME_NOT_CONFIGURED"),
        (_toml(project_id="another-project"), "valid", "RUNTIME_NOT_CONFIGURED"),
        (
            _toml(reference="vault://another-project/development/provider/LEDGER_INTEGRITY_KEY"),
            "valid",
            "RUNTIME_NOT_CONFIGURED",
        ),
        (_toml(), "missing", "RUNTIME_NOT_CONFIGURED"),
        (_toml(), "failure", "RUNTIME_NOT_CONFIGURED"),
    ],
)
def test_invalid_deployment_keeps_app_up_and_both_mounts_fail_closed(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture[str],
    document: str,
    resolver_mode: str,
    expected_reason: str,
) -> None:
    caplog.set_level(logging.WARNING)
    config, app_data = _write_config(tmp_path, document)
    vault = (
        None
        if resolver_mode == "missing"
        else (_Vault(failure=_CANARY) if resolver_mode == "failure" else _Vault())
    )
    dependencies = _dependencies(
        config,
        app_data,
        # Bind only the approved synthetic ref; malformed/literal/cross-project
        # references must fail validation before any vault lookup.
        reference=_REFERENCE,
        vault=vault,
    )
    app = create_app(runtime_mount_dependencies=dependencies)
    mounted_paths = set(app.openapi()["paths"])
    assert "/v1/omega/tools/manifest" in mounted_paths
    assert "/mcp/tools" in mounted_paths

    with TestClient(app) as client:
        omega_response = client.get("/v1/omega/tools/manifest")
        mcp_response = client.get("/mcp/tools")
        health = client.get("/health")

    _assert_runtime_unavailable(omega_response, expected_reason)
    _assert_runtime_unavailable(mcp_response, expected_reason)
    assert health.status_code == 200
    captured = capsys.readouterr()
    combined = omega_response.text + mcp_response.text + caplog.text + captured.out + captured.err
    assert _CANARY not in combined
    assert _SYNTHETIC_KEY not in combined
    assert "unknown-canary" not in combined


def test_missing_config_starts_with_routes_registered_and_no_store(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("LEVIATHAN_DEPLOYMENT_CONFIG_PATH", raising=False)
    monkeypatch.delenv("LEVIATHAN_APP_DATA_DIR", raising=False)
    app = create_app(runtime_mount_dependencies=RuntimeMountDependenciesV1())
    with TestClient(app) as client:
        _assert_runtime_unavailable(client.get("/v1/omega/tools/manifest"))
        _assert_runtime_unavailable(client.get("/mcp/tools"))
        assert client.get("/health").status_code == 200


def test_configured_paper_mounts_reach_their_authentication_boundaries(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config, app_data = _write_config(tmp_path, _toml())
    vault = _Vault()
    dependencies = _dependencies(
        config,
        app_data,
        vault=vault,
        omega=True,
        mcp=True,
        resolver=_McpResolver(),
    )
    app = create_app(runtime_mount_dependencies=dependencies)

    with TestClient(app) as client:
        omega = client.get("/v1/omega/tools/manifest")
        mcp = client.get("/mcp/tools")
        authenticated_mcp = client.get(
            "/mcp/tools?agent_id=agent.synthetic&session_id=session.synthetic",
            headers={"Authorization": f"Bearer {_mcp_token()}"},
        )

    assert vault.calls == [("LEDGER_INTEGRITY_KEY", "leviathan-ai", "development")]
    assert omega.status_code == 401
    assert omega.json() == {"detail": "OMEGA_AUTH_DENIED"}
    assert omega.headers["cache-control"] == "no-store"
    assert mcp.status_code == 401
    assert mcp.json() == {"detail": "UNAUTHENTICATED"}
    assert mcp.headers["cache-control"] == "no-store"
    assert authenticated_mcp.status_code == 200
    assert authenticated_mcp.json() == {"version": "1", "tools": []}
    assert authenticated_mcp.headers["cache-control"] == "no-store"
    captured = capsys.readouterr()
    combined = omega.text + mcp.text + authenticated_mcp.text + captured.out + captured.err
    assert _SYNTHETIC_KEY not in combined
    assert _CANARY not in combined


def test_missing_omega_ports_is_distinct_and_missing_mcp_dependencies_stay_gated(
    tmp_path: Path,
) -> None:
    config, app_data = _write_config(tmp_path, _toml())
    dependencies = _dependencies(config, app_data, vault=_Vault())
    app = create_app(runtime_mount_dependencies=dependencies)

    with TestClient(app) as client:
        omega = client.get("/v1/omega/tools/manifest")
        mcp = client.get("/mcp/tools")

    _assert_runtime_unavailable(omega, "OMEGA_PORTS_UNAVAILABLE")
    _assert_runtime_unavailable(mcp, "MCP_CONTROL_UNAVAILABLE")


def test_orders_activity_precedes_dynamic_order_route_and_health_is_preserved() -> None:
    app = create_app(runtime_mount_dependencies=RuntimeMountDependenciesV1())
    with TestClient(app) as client:
        activity = client.get("/orders/activity")
        health = client.get("/health")

    assert activity.status_code == 401
    assert activity.json() == {"error": {"code": "PRINCIPAL_UNTRUSTED"}}
    assert health.status_code == 200
    assert health.json()["status"] == "ok"
    assert health.json()["service"] == "leviathan-api"
