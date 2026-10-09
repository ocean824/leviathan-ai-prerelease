"""Fail-closed startup composition for optional PAPER runtime routers."""

from __future__ import annotations

import os
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Protocol

from fastapi import FastAPI
from leviathan_store.engine import (
    create_sync_engine_and_sessionmaker,
    init_sync_schema,
)
from leviathan_store.mcp_audit import McpAuditScopeV1, McpAuditStore
from leviathan_store.omega_due_queue import OmegaDueQueueStore
from pydantic import SecretStr

from leviathan_api.deployment_config import (
    DeploymentConfigCode,
    DeploymentConfigError,
    DeploymentConfigV1,
    DeploymentDiagnosticCode,
    load_deployment_config,
    require_deployment_config,
)
from leviathan_api.mcp_runtime_factory import (
    McpControlBinding,
    McpRuntimeFactoryConfigV1,
    McpVerifiedResolverPort,
    build_mcp_control,
)
from leviathan_api.omega_runtime_factory import (
    OmegaTasksConfig,
    build_omega_tasks,
)
from leviathan_api.routers.mcp_control import McpControlRuntime
from leviathan_api.state import AppState
from leviathan_core.deployment_secret_refs import (
    AllowedSecretBindingsV1,
    ProviderAliasMapV1,
)
from leviathan_core.execution.order_models import LedgerIntegrityKey

CONFIG_PATH_ENV = "LEVIATHAN_DEPLOYMENT_CONFIG_PATH"
APP_DATA_DIR_ENV = "LEVIATHAN_APP_DATA_DIR"
VAULT_ROOT_ENV = "XYRA_FACTORY_ROOT"


class VaultResolverPort(Protocol):
    """Existing XYRA vault read boundary; implementations return redacted secrets."""

    def get(self, name: str, scope: str, environment: str) -> SecretStr: ...


OmegaConfigFactory = Callable[
    [DeploymentConfigV1, LedgerIntegrityKey, AppState, OmegaDueQueueStore], OmegaTasksConfig
]
McpRuntimeFactory = Callable[[DeploymentConfigV1, AppState], McpControlRuntime]


@dataclass(frozen=True, slots=True)
class RuntimeMountDependenciesV1:
    """Explicit deployment inputs and trusted runtime assemblers.

    The OMEGA factory supplies the still-unassembled production bridge/session/
    manifest/MCP/audit/outbox/rate/model and adapter-trust ports. No inert
    runtime is synthesized when that provider is absent.
    """

    config_path: str | Path | None = None
    app_data_dir: str | Path | None = None
    allowed_bindings: AllowedSecretBindingsV1 | None = None
    provider_aliases: ProviderAliasMapV1 | None = None
    vault_resolver: VaultResolverPort | None = None
    omega_config_factory: OmegaConfigFactory | None = None
    mcp_runtime_factory: McpRuntimeFactory | None = None
    mcp_resolver: McpVerifiedResolverPort | None = None


@dataclass(frozen=True, slots=True)
class RuntimeMountStatusV1:
    omega_reason: str | None
    mcp_reason: str | None


def _deployment_paths(
    dependencies: RuntimeMountDependenciesV1,
) -> tuple[Path | None, Path | None]:
    config_path = dependencies.config_path
    app_data_dir = dependencies.app_data_dir
    if config_path is None:
        config_path = os.environ.get(CONFIG_PATH_ENV)
    if app_data_dir is None:
        app_data_dir = os.environ.get(APP_DATA_DIR_ENV)
    if not config_path or not app_data_dir:
        return None, None
    return Path(config_path), Path(app_data_dir)


def _vault_resolver(dependencies: RuntimeMountDependenciesV1) -> VaultResolverPort | None:
    if dependencies.vault_resolver is not None:
        return dependencies.vault_resolver
    factory_root = os.environ.get(VAULT_ROOT_ENV)
    if not factory_root:
        return None
    try:
        from leviathan_vault.client import XyraVault

        return XyraVault(Path(factory_root))
    except Exception:
        return None


def _startup_reason_code(error: Exception) -> str:
    if isinstance(error, DeploymentConfigError):
        return error.diagnostic_code.value
    if isinstance(error, ValueError) and str(error) == "KEY_REF_UNRESOLVABLE":
        return DeploymentDiagnosticCode.KEY_UNRESOLVABLE.value
    return "RUNTIME_NOT_CONFIGURED"


def _make_key(config: DeploymentConfigV1, resolver: VaultResolverPort) -> LedgerIntegrityKey:
    reference = config.ledger_integrity_key_ref
    secret = resolver.get(reference.name, "leviathan-ai", reference.environment)
    if type(secret) is not SecretStr:
        raise ValueError("KEY_REF_UNRESOLVABLE")
    material = bytearray(secret.get_secret_value().encode("utf-8", errors="strict"))
    try:
        return LedgerIntegrityKey(bytes(material))
    finally:
        material[:] = b"\0" * len(material)


def _sqlite_url(path: Path) -> str:
    return f"sqlite:///{path.as_posix()}"


def _close_once(*callbacks: Callable[[], object]) -> Callable[[], None]:
    closed = False

    def close() -> None:
        nonlocal closed
        if closed:
            return
        closed = True
        first_error: Exception | None = None
        for callback in callbacks:
            try:
                callback()
            except Exception as error:  # cleanup continues without exposing details
                if first_error is None:
                    first_error = error
        if first_error is not None:
            raise RuntimeError("RUNTIME_CLEANUP_FAILED") from None

    return close


def _log_unavailable(logger: object, subsystem: str, reason: str) -> None:
    warning = getattr(logger, "warning", None)
    if callable(warning):
        if reason in {code.value for code in DeploymentDiagnosticCode}:
            legacy_reason = {
                DeploymentDiagnosticCode.SLA_MISSING.value: "HEARTBEAT_SLA_REQUIRED",
                DeploymentDiagnosticCode.KEY_UNRESOLVABLE.value: "KEY_REF_UNRESOLVABLE",
            }.get(reason, "RUNTIME_NOT_CONFIGURED")
            warning(
                "runtime_mount_unavailable",
                subsystem=subsystem,
                reason_code=legacy_reason,
            )
            info = getattr(logger, "info", None)
            if callable(info):
                info(
                    "runtime_mount_diagnostic",
                    subsystem=subsystem,
                    reason_code=reason,
                )
            return
        warning("runtime_mount_unavailable", subsystem=subsystem, reason_code=reason)


def configure_runtime_mounts(
    app: FastAPI,
    dependencies: RuntimeMountDependenciesV1,
    *,
    logger: object,
    app_state: AppState,
) -> RuntimeMountStatusV1:
    """Load and compose PAPER runtimes; failures are recorded, never raised."""

    state = app.state
    state.runtime_mount_status = RuntimeMountStatusV1(
        omega_reason="RUNTIME_NOT_CONFIGURED", mcp_reason="RUNTIME_NOT_CONFIGURED"
    )
    state.omega_tasks = None
    state.omega_tasks_binding = None
    state.mcp_control_runtime = None
    state.mcp_control_principal_resolver = None
    state.mcp_control_binding = None
    state.runtime_mount_engines = []

    try:
        paths = _deployment_paths(dependencies)
        if paths[0] is None or paths[1] is None:
            raise DeploymentConfigError(
                DeploymentConfigCode.CONFIG_READ_FAILED,
                DeploymentDiagnosticCode.CONFIG_ABSENT,
            )
        if dependencies.allowed_bindings is None or dependencies.provider_aliases is None:
            raise ValueError("RUNTIME_NOT_CONFIGURED")
        config = require_deployment_config(
            load_deployment_config(
                paths[0],
                app_data_dir=paths[1],
                allowed_bindings=dependencies.allowed_bindings,
                provider_aliases=dependencies.provider_aliases,
            )
        )
        resolver = _vault_resolver(dependencies)
        if resolver is None:
            raise ValueError("KEY_REF_UNRESOLVABLE")
    except Exception as error:
        reason = _startup_reason_code(error)
        state.runtime_mount_status = RuntimeMountStatusV1(
            "RUNTIME_NOT_CONFIGURED", "RUNTIME_NOT_CONFIGURED"
        )
        _log_unavailable(logger, "runtime", reason)
        return RuntimeMountStatusV1(
            state.runtime_mount_status.omega_reason,
            state.runtime_mount_status.mcp_reason,
        )
    try:
        key = _make_key(config, resolver)
    except Exception:
        state.runtime_mount_status = RuntimeMountStatusV1(
            "RUNTIME_NOT_CONFIGURED", "RUNTIME_NOT_CONFIGURED"
        )
        _log_unavailable(
            logger,
            "runtime",
            DeploymentDiagnosticCode.KEY_UNRESOLVABLE.value,
        )
        return RuntimeMountStatusV1(
            state.runtime_mount_status.omega_reason,
            state.runtime_mount_status.mcp_reason,
        )

    omega_reason: str | None = None
    mcp_reason: str | None = None
    due_engine = None
    audit_engine = None
    omega_cleanup: Callable[[], object] | None = None

    if dependencies.omega_config_factory is None:
        omega_reason = "OMEGA_PORTS_UNAVAILABLE"
    else:
        try:
            due_engine, due_sessions = create_sync_engine_and_sessionmaker(
                _sqlite_url(config.omega_due_store_path)
            )
            init_sync_schema(due_engine)
            due_store = OmegaDueQueueStore(due_sessions, key=key)
            omega_config = dependencies.omega_config_factory(config, key, app_state, due_store)
            if (
                type(omega_config) is not OmegaTasksConfig
                or omega_config.task_store is not due_store
                or omega_config.omega_policy is not config.omega_policy
                or not callable(omega_config.close_resources)
            ):
                raise ValueError("OMEGA_PORTS_UNAVAILABLE")
            omega_cleanup = _close_once(omega_config.close_resources, due_engine.dispose)
            omega_config = replace(
                omega_config,
                close_resources=omega_cleanup,
            )
            omega_binding = build_omega_tasks(omega_config)
            state.omega_tasks = omega_binding.runtime
            state.omega_adapter = omega_binding.adapter
            state.omega_tasks_binding = omega_binding
        except Exception:
            if due_engine is not None and getattr(state, "omega_tasks_binding", None) is None:
                if omega_cleanup is not None:
                    with suppress(Exception):
                        omega_cleanup()
                with suppress(Exception):
                    due_engine.dispose()
            omega_reason = "OMEGA_PORTS_UNAVAILABLE"

    mcp_ready = all(
        dependency is not None
        for dependency in (dependencies.mcp_runtime_factory, dependencies.mcp_resolver)
    )
    if not mcp_ready:
        mcp_reason = "MCP_CONTROL_UNAVAILABLE"
    else:
        try:
            audit_engine, audit_sessions = create_sync_engine_and_sessionmaker(
                _sqlite_url(config.mcp_audit_store_path)
            )
            init_sync_schema(audit_engine)
            audit_store = McpAuditStore(
                audit_sessions,
                key=key,
                scope=McpAuditScopeV1(config.project_id, config.environment),
            )
            assert dependencies.mcp_runtime_factory is not None
            assert dependencies.mcp_resolver is not None
            runtime = dependencies.mcp_runtime_factory(config, app_state)
            mcp_binding: McpControlBinding = build_mcp_control(
                McpRuntimeFactoryConfigV1(
                    runtime=runtime,
                    resolver=dependencies.mcp_resolver,
                    audit=audit_store,
                )
            )
            state.mcp_control_runtime = mcp_binding.runtime
            state.mcp_control_principal_resolver = mcp_binding.principal_resolver
            state.mcp_control_binding = mcp_binding
            state.runtime_mount_engines.append(audit_engine)
        except Exception:
            if audit_engine is not None and getattr(state, "mcp_control_binding", None) is None:
                with suppress(Exception):
                    audit_engine.dispose()
            mcp_reason = "MCP_CONTROL_UNAVAILABLE"

    if omega_reason is not None:
        _log_unavailable(logger, "omega", omega_reason)
    if mcp_reason is not None:
        _log_unavailable(logger, "mcp_control", mcp_reason)
    state.runtime_mount_status = RuntimeMountStatusV1(omega_reason, mcp_reason)
    return RuntimeMountStatusV1(omega_reason, mcp_reason)


def close_runtime_mounts(app: FastAPI) -> None:
    """Close constructed bindings and their independent store engines."""

    state = app.state
    for name in ("omega_tasks_binding", "mcp_control_binding"):
        binding = getattr(state, name, None)
        close = getattr(binding, "close", None)
        if callable(close):
            with suppress(Exception):
                close()
    engines = getattr(state, "runtime_mount_engines", ())
    for engine in engines:
        with suppress(Exception):
            engine.dispose()
    state.runtime_mount_engines = []


__all__ = [
    "APP_DATA_DIR_ENV",
    "CONFIG_PATH_ENV",
    "RuntimeMountDependenciesV1",
    "RuntimeMountStatusV1",
    "VaultResolverPort",
    "close_runtime_mounts",
    "configure_runtime_mounts",
]
