"""Strict offline loader for a project-scoped local PAPER deployment config."""

from __future__ import annotations

import tomllib
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Any, Literal, NoReturn

from pydantic import Field, model_validator

from leviathan_core.deployment_secret_refs import (
    AllowedSecretBindingsV1,
    ProviderAliasMapV1,
    SecretReferenceError,
    SecretReferenceV1,
    validate_secret_reference,
)
from leviathan_core.omega_link.state_models import OmegaPolicyV1
from leviathan_core.seal import Issuer, SealedModel, SealError, require

PROJECT_ID = "e2c897ec-b728-40a2-8c2d-c38b874c9006"
LEDGER_INTEGRITY_SERVICE_ID = "leviathan-api"
PAPER_VAULT_ENVIRONMENT: Literal["development"] = "development"
_MAX_CONFIG_BYTES = 65_536
_REFERENCE_TAG = "deployment.secret_refs.reference.v1"
_CONFIG_TAG = "deployment.config.v1"
_CONFIG_ISSUER = Issuer(_CONFIG_TAG)


class DeploymentConfigCode(StrEnum):
    CONFIG_READ_FAILED = "CONFIG_READ_FAILED"
    CONFIG_INVALID = "CONFIG_INVALID"
    HEARTBEAT_SLA_REQUIRED = "HEARTBEAT_SLA_REQUIRED"
    SECRET_REFERENCE_INVALID = "SECRET_REFERENCE_INVALID"
    STORE_PATH_INVALID = "STORE_PATH_INVALID"
    UNISSUED_CONFIG = "UNISSUED_CONFIG"


class DeploymentDiagnosticCode(StrEnum):
    """Closed, content-free startup diagnostics for deployment configuration."""

    CONFIG_ABSENT = "CONFIG_ABSENT"
    CONFIG_READ_FAILED = "CONFIG_READ_FAILED"
    CONFIG_PARSE = "CONFIG_PARSE"
    CONFIG_SCHEMA_INVALID = "CONFIG_SCHEMA_INVALID"
    UNKNOWN_KEY = "UNKNOWN_KEY"
    ENV_NOT_PAPER = "ENV_NOT_PAPER"
    PROJECT_SCOPE_INVALID = "PROJECT_SCOPE_INVALID"
    KEY_REF_INVALID = "KEY_REF_INVALID"
    KEY_UNRESOLVABLE = "KEY_UNRESOLVABLE"
    PATH_INVALID = "PATH_INVALID"
    PATHS_COLLIDE = "PATHS_COLLIDE"
    SLA_MISSING = "SLA_MISSING"


class DeploymentConfigError(ValueError):
    """Fixed-code config failure that never echoes input values."""

    def __init__(
        self,
        code: DeploymentConfigCode,
        diagnostic_code: DeploymentDiagnosticCode | None = None,
    ) -> None:
        if type(code) is not DeploymentConfigCode:
            raise TypeError("CONFIG_INVALID")
        if diagnostic_code is not None and type(diagnostic_code) is not DeploymentDiagnosticCode:
            raise TypeError("CONFIG_INVALID")
        self.code = code
        self.diagnostic_code = diagnostic_code or _DEFAULT_DIAGNOSTIC[code]
        super().__init__(code.value)


_DEFAULT_DIAGNOSTIC = {
    DeploymentConfigCode.CONFIG_READ_FAILED: DeploymentDiagnosticCode.CONFIG_READ_FAILED,
    DeploymentConfigCode.CONFIG_INVALID: DeploymentDiagnosticCode.CONFIG_SCHEMA_INVALID,
    DeploymentConfigCode.HEARTBEAT_SLA_REQUIRED: DeploymentDiagnosticCode.SLA_MISSING,
    DeploymentConfigCode.SECRET_REFERENCE_INVALID: DeploymentDiagnosticCode.KEY_REF_INVALID,
    DeploymentConfigCode.STORE_PATH_INVALID: DeploymentDiagnosticCode.PATH_INVALID,
    DeploymentConfigCode.UNISSUED_CONFIG: DeploymentDiagnosticCode.CONFIG_SCHEMA_INVALID,
}


class DeploymentConfigV1(SealedModel):
    """PAPER config candidate; consumers must call require_deployment_config first."""

    project_id: str
    environment: Literal["PAPER"]
    app_data_dir_value: str = Field(alias="app_data_dir")
    ledger_integrity_key_ref: SecretReferenceV1
    omega_due_store_path_value: str = Field(alias="omega_due_store_path")
    mcp_audit_store_path_value: str = Field(alias="mcp_audit_store_path")
    omega_policy: OmegaPolicyV1

    def __init__(self, /, **data: Any) -> None:
        if _CONFIG_ISSUER.issued_here(self):
            raise SealError("SEAL_FORBIDDEN_OPERATION")
        reference = data.get("ledger_integrity_key_ref")
        if type(reference) is not SecretReferenceV1:
            raise SealError("SEAL_INVALID_MODEL")
        try:
            require(reference, _REFERENCE_TAG)
        except SealError:
            raise SealError("SEAL_INVALID_MODEL") from None
        super().__init__(**data)

    @property
    def app_data_dir(self) -> Path:
        return Path(self.app_data_dir_value)

    @property
    def omega_due_store_path(self) -> Path:
        return Path(self.omega_due_store_path_value)

    @property
    def mcp_audit_store_path(self) -> Path:
        return Path(self.mcp_audit_store_path_value)

    @model_validator(mode="after")
    def _bounded_paper_config(self) -> DeploymentConfigV1:
        if self.project_id != PROJECT_ID or self.environment != "PAPER":
            raise ValueError("invalid deployment scope")
        reference = self.ledger_integrity_key_ref
        if type(reference) is not SecretReferenceV1:
            raise ValueError("invalid secret reference")
        if (
            reference.service_id != LEDGER_INTEGRITY_SERVICE_ID
            or reference.environment != PAPER_VAULT_ENVIRONMENT
            or not reference.canonical_ref.startswith("vault://leviathan-ai/development/")
        ):
            raise ValueError("invalid secret reference")
        root_value = self.app_data_dir_value
        if (
            type(root_value) is not str
            or not root_value.isascii()
            or any(ord(char) < 32 for char in root_value)
        ):
            raise ValueError("invalid app data directory")
        raw_root = Path(root_value)
        if not raw_root.is_absolute() or any(part in {".", ".."} for part in raw_root.parts):
            raise ValueError("invalid app data directory")
        root = raw_root.resolve(strict=False)
        for store_path_value in (
            self.omega_due_store_path_value,
            self.mcp_audit_store_path_value,
        ):
            if (
                type(store_path_value) is not str
                or not store_path_value.isascii()
                or any(ord(char) < 32 for char in store_path_value)
            ):
                raise ValueError("invalid store path")
            store_path = Path(store_path_value)
            if not store_path.is_absolute() or any(
                part in {".", ".."} for part in store_path.parts
            ):
                raise ValueError("invalid store path")
            resolved = store_path.resolve(strict=False)
            try:
                resolved.relative_to(root)
            except ValueError:
                raise ValueError("invalid store path") from None
            if resolved == root:
                raise ValueError("invalid store path")
        return self


def _fail(
    code: DeploymentConfigCode,
    diagnostic_code: DeploymentDiagnosticCode | None = None,
) -> NoReturn:
    raise DeploymentConfigError(code, diagnostic_code)


def _table(value: object) -> dict[str, object]:
    if type(value) is not dict:
        _fail(DeploymentConfigCode.CONFIG_INVALID)
    return value


def _exact_keys(value: dict[str, object], keys: set[str]) -> None:
    if value.keys() - keys:
        _fail(DeploymentConfigCode.CONFIG_INVALID, DeploymentDiagnosticCode.UNKNOWN_KEY)
    if value.keys() != keys:
        _fail(DeploymentConfigCode.CONFIG_INVALID, DeploymentDiagnosticCode.CONFIG_SCHEMA_INVALID)


def _relative_store_path(value: object, app_data_dir: Path) -> Path:
    if (
        type(value) is not str
        or not value
        or not value.isascii()
        or "\\" in value
        or ":" in value
        or value.startswith("/")
    ):
        _fail(DeploymentConfigCode.STORE_PATH_INVALID)
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        _fail(DeploymentConfigCode.STORE_PATH_INVALID)
    relative = PurePosixPath(value)
    if relative.is_absolute():
        _fail(DeploymentConfigCode.STORE_PATH_INVALID)
    root = app_data_dir.resolve(strict=False)
    candidate = root.joinpath(*relative.parts).resolve(strict=False)
    try:
        candidate.relative_to(root)
    except ValueError:
        _fail(DeploymentConfigCode.STORE_PATH_INVALID)
    if candidate == root:
        _fail(DeploymentConfigCode.STORE_PATH_INVALID)
    return candidate


def _validate_document(
    value: object,
    *,
    app_data_dir: Path,
    allowed_bindings: AllowedSecretBindingsV1,
    provider_aliases: ProviderAliasMapV1,
) -> DeploymentConfigV1:
    root = _table(value)
    _exact_keys(root, {"project", "secrets", "omega", "mcp_control"})

    project = _table(root["project"])
    _exact_keys(project, {"project_id", "environment"})
    project_id = project["project_id"]
    environment = project["environment"]
    if type(project_id) is not str or project_id != PROJECT_ID:
        _fail(DeploymentConfigCode.CONFIG_INVALID, DeploymentDiagnosticCode.PROJECT_SCOPE_INVALID)
    if type(environment) is not str or environment != "PAPER":
        _fail(DeploymentConfigCode.CONFIG_INVALID, DeploymentDiagnosticCode.ENV_NOT_PAPER)

    secrets = _table(root["secrets"])
    _exact_keys(secrets, {"ledger_integrity_key_ref"})
    reference = secrets["ledger_integrity_key_ref"]
    if type(reference) is not str or not reference.startswith("vault://"):
        _fail(
            DeploymentConfigCode.SECRET_REFERENCE_INVALID,
            DeploymentDiagnosticCode.KEY_REF_INVALID,
        )

    omega = _table(root["omega"])
    if "max_heartbeat_age_ns" not in omega:
        _fail(DeploymentConfigCode.HEARTBEAT_SLA_REQUIRED, DeploymentDiagnosticCode.SLA_MISSING)
    _exact_keys(omega, {"due_store_path", "max_heartbeat_age_ns"})
    heartbeat_age_ns = omega["max_heartbeat_age_ns"]
    if type(heartbeat_age_ns) is not int:
        _fail(DeploymentConfigCode.CONFIG_INVALID)
    try:
        policy = OmegaPolicyV1(version="1", max_heartbeat_age_ns=heartbeat_age_ns)
    except Exception:
        _fail(DeploymentConfigCode.CONFIG_INVALID)

    mcp_control = _table(root["mcp_control"])
    _exact_keys(mcp_control, {"audit_store_path"})
    due_path = _relative_store_path(omega["due_store_path"], app_data_dir)
    audit_path = _relative_store_path(mcp_control["audit_store_path"], app_data_dir)
    if due_path == audit_path or due_path in audit_path.parents or audit_path in due_path.parents:
        _fail(DeploymentConfigCode.STORE_PATH_INVALID, DeploymentDiagnosticCode.PATHS_COLLIDE)

    try:
        secret_ref = validate_secret_reference(
            reference,
            service_id=LEDGER_INTEGRITY_SERVICE_ID,
            environment=PAPER_VAULT_ENVIRONMENT,
            allowed_bindings=allowed_bindings,
            provider_aliases=provider_aliases,
        )
        require(secret_ref, _REFERENCE_TAG)
    except (SecretReferenceError, SealError, ValueError, TypeError):
        _fail(
            DeploymentConfigCode.SECRET_REFERENCE_INVALID,
            DeploymentDiagnosticCode.KEY_REF_INVALID,
        )

    config = DeploymentConfigV1(
        project_id=project_id,
        environment="PAPER",
        app_data_dir=str(app_data_dir.resolve(strict=False)),
        ledger_integrity_key_ref=secret_ref,
        omega_due_store_path=str(due_path),
        mcp_audit_store_path=str(audit_path),
        omega_policy=policy,
    )
    return _CONFIG_ISSUER.issue(config)


def require_deployment_config(value: object) -> DeploymentConfigV1:
    """Return an unchanged loader-issued config, or fail with a fixed code."""
    if type(value) is not DeploymentConfigV1:
        _fail(DeploymentConfigCode.UNISSUED_CONFIG)
    try:
        require(value, _CONFIG_TAG)
    except SealError:
        _fail(DeploymentConfigCode.UNISSUED_CONFIG)
    return value


def load_deployment_config(
    config_path: str | Path,
    *,
    app_data_dir: str | Path,
    allowed_bindings: AllowedSecretBindingsV1,
    provider_aliases: ProviderAliasMapV1,
) -> DeploymentConfigV1:
    """Read one bounded TOML document; never resolves secrets or opens store paths."""
    if (
        type(allowed_bindings) is not AllowedSecretBindingsV1
        or type(provider_aliases) is not ProviderAliasMapV1
    ):
        _fail(DeploymentConfigCode.SECRET_REFERENCE_INVALID)
    if not isinstance(config_path, (str, Path)) or not isinstance(app_data_dir, (str, Path)):
        _fail(DeploymentConfigCode.CONFIG_READ_FAILED, DeploymentDiagnosticCode.CONFIG_ABSENT)
    try:
        source = Path(config_path)
        root = Path(app_data_dir)
        if not root.is_absolute():
            _fail(DeploymentConfigCode.STORE_PATH_INVALID)
        with source.open("rb") as stream:
            raw = stream.read(_MAX_CONFIG_BYTES + 1)
        if len(raw) > _MAX_CONFIG_BYTES:
            _fail(
                DeploymentConfigCode.CONFIG_READ_FAILED,
                DeploymentDiagnosticCode.CONFIG_READ_FAILED,
            )
        try:
            text = raw.decode("utf-8", errors="strict")
            parsed = tomllib.loads(text)
        except (UnicodeDecodeError, tomllib.TOMLDecodeError):
            _fail(DeploymentConfigCode.CONFIG_INVALID, DeploymentDiagnosticCode.CONFIG_PARSE)
    except DeploymentConfigError:
        raise
    except (OSError, ValueError, TypeError):
        code = (
            DeploymentDiagnosticCode.CONFIG_ABSENT
            if not source.exists()
            else DeploymentDiagnosticCode.CONFIG_READ_FAILED
        )
        _fail(DeploymentConfigCode.CONFIG_READ_FAILED, code)

    return _validate_document(
        parsed,
        app_data_dir=root,
        allowed_bindings=allowed_bindings,
        provider_aliases=provider_aliases,
    )


__all__ = [
    "LEDGER_INTEGRITY_SERVICE_ID",
    "PAPER_VAULT_ENVIRONMENT",
    "PROJECT_ID",
    "DeploymentConfigCode",
    "DeploymentConfigError",
    "DeploymentConfigV1",
    "DeploymentDiagnosticCode",
    "load_deployment_config",
    "require_deployment_config",
]
