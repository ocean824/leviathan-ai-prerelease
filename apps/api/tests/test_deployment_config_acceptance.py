from __future__ import annotations

import builtins
import copy
import io
import json
import pickle
import socket
import tomllib
from collections.abc import Callable
from pathlib import Path

import pytest

from leviathan_api.deployment_config import (
    LEDGER_INTEGRITY_SERVICE_ID,
    PROJECT_ID,
    DeploymentConfigCode,
    DeploymentConfigError,
    DeploymentConfigV1,
    load_deployment_config,
    require_deployment_config,
)
from leviathan_core.deployment_secret_refs import (
    AllowedSecretBindingsV1,
    ProviderAliasMapV1,
    SecretReferenceV1,
    issue_allowed_secret_bindings,
    issue_provider_alias_map,
    validate_secret_reference,
)
from leviathan_core.omega_link.state_models import OmegaPolicyV1
from leviathan_core.seal import SealError

REFERENCE = "vault://leviathan-ai/development/synthetic-provider/LEDGER_INTEGRITY_KEY"
LITERAL_CANARY = "sk_live_acceptance_never_echo_this"


def _bindings(reference: str = REFERENCE) -> tuple[AllowedSecretBindingsV1, ProviderAliasMapV1]:
    return (
        issue_allowed_secret_bindings(((LEDGER_INTEGRITY_SERVICE_ID, "development", reference),)),
        issue_provider_alias_map(()),
    )


def _toml(
    *,
    environment: str = "PAPER",
    reference: str = REFERENCE,
    due_path: str = "omega/due.sqlite3",
    audit_path: str = "mcp/audit.sqlite3",
    include_sla: bool = True,
    extra: str = "",
) -> str:
    sla = "max_heartbeat_age_ns = 2000000000\n" if include_sla else ""
    return (
        "[project]\n"
        f'project_id = "{PROJECT_ID}"\n'
        f'environment = "{environment}"\n\n'
        "[secrets]\n"
        f'ledger_integrity_key_ref = "{reference}"\n\n'
        "[omega]\n"
        f"due_store_path = {json.dumps(due_path)}\n"
        f"{sla}\n"
        "[mcp_control]\n"
        f"audit_store_path = {json.dumps(audit_path)}\n"
        f"{extra}"
    )


def _load(config: Path, app_data: Path, reference: str = REFERENCE) -> DeploymentConfigV1:
    bindings, aliases = _bindings(reference)
    return load_deployment_config(
        config,
        app_data_dir=app_data,
        allowed_bindings=bindings,
        provider_aliases=aliases,
    )


def _issued_reference() -> SecretReferenceV1:
    bindings, aliases = _bindings()
    return validate_secret_reference(
        REFERENCE,
        service_id=LEDGER_INTEGRITY_SERVICE_ID,
        environment="development",
        allowed_bindings=bindings,
        provider_aliases=aliases,
    )


def _write(tmp_path: Path, text: str) -> tuple[Path, Path]:
    app_data = tmp_path / "app-data"
    app_data.mkdir()
    config = tmp_path / "deployment.toml"
    config.write_text(text, encoding="utf-8")
    return config, app_data


def _assert_fixed_failure(
    operation: Callable[[], object], code: DeploymentConfigCode, canary: str | None = None
) -> None:
    with pytest.raises(DeploymentConfigError) as captured:
        operation()
    error = captured.value
    assert error.code is code
    assert error.args == (code.value,)
    assert str(error) == code.value
    assert error.__cause__ is None
    assert error.__context__ is None
    if canary:
        assert canary not in repr(error)
        assert canary not in repr(error.args)


def test_example_config_is_parseable_synthetic_and_has_no_implicit_sla() -> None:
    example = Path(__file__).parents[1] / "config" / "local-paper.example.toml"
    raw = example.read_text(encoding="utf-8")
    parsed = tomllib.loads(raw)

    assert parsed["project"]["environment"] == "PAPER"
    assert parsed["secrets"]["ledger_integrity_key_ref"].startswith("vault://")
    assert "max_heartbeat_age_ns" not in parsed["omega"]
    assert "LedgerIntegrityKey(" not in raw
    assert "sk_live_" not in raw


def test_public_loader_returns_typed_project_scoped_metadata_without_material(
    tmp_path: Path,
) -> None:
    config, app_data = _write(tmp_path, _toml())
    loaded = _load(config, app_data)

    assert type(loaded) is DeploymentConfigV1
    assert loaded.project_id == PROJECT_ID
    assert loaded.environment == "PAPER"
    assert type(loaded.omega_policy) is OmegaPolicyV1
    assert loaded.omega_policy.max_heartbeat_age_ns == 2_000_000_000
    assert type(loaded.ledger_integrity_key_ref) is SecretReferenceV1
    assert loaded.ledger_integrity_key_ref.canonical_ref == REFERENCE
    assert loaded.ledger_integrity_key_ref.service_id == LEDGER_INTEGRITY_SERVICE_ID
    assert loaded.ledger_integrity_key_ref.environment == "development"
    assert loaded.omega_due_store_path == (app_data / "omega/due.sqlite3").resolve()
    assert loaded.mcp_audit_store_path == (app_data / "mcp/audit.sqlite3").resolve()
    assert not loaded.omega_due_store_path.exists()
    assert not loaded.mcp_audit_store_path.exists()
    assert not hasattr(loaded, "ledger_integrity_key")


@pytest.mark.parametrize(
    ("document", "code"),
    [
        (_toml(extra='unexpected = "no"\n'), DeploymentConfigCode.CONFIG_INVALID),
        (
            _toml().replace("[mcp_control]\n", '[mcp_control]\nother = "no"\n'),
            DeploymentConfigCode.CONFIG_INVALID,
        ),
        (_toml(environment="LIVE"), DeploymentConfigCode.CONFIG_INVALID),
        (_toml(include_sla=False), DeploymentConfigCode.HEARTBEAT_SLA_REQUIRED),
        (_toml(due_path="../outside.sqlite3"), DeploymentConfigCode.STORE_PATH_INVALID),
    ],
)
def test_strict_config_policy_and_path_fail_closed(
    tmp_path: Path, document: str, code: DeploymentConfigCode
) -> None:
    config, app_data = _write(tmp_path, document)
    _assert_fixed_failure(lambda: _load(config, app_data), code)


def test_literal_key_like_value_is_rejected_without_echo(tmp_path: Path) -> None:
    config, app_data = _write(tmp_path, _toml(reference=LITERAL_CANARY))
    _assert_fixed_failure(
        lambda: _load(config, app_data),
        DeploymentConfigCode.SECRET_REFERENCE_INVALID,
        LITERAL_CANARY,
    )


def test_valid_load_reads_only_config_and_makes_no_network_calls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, app_data = _write(tmp_path, _toml())
    expected = config.resolve()
    actual_reads: list[Path] = []
    original_io_open = io.open
    original_builtin_open = builtins.open

    def checked_open(file, *args, **kwargs):
        path = Path(file).resolve() if isinstance(file, (str, Path)) else None
        if path != expected:
            raise AssertionError("unexpected file read")
        actual_reads.append(path)
        return original_io_open(file, *args, **kwargs)

    def checked_builtin_open(file, *args, **kwargs):
        path = Path(file).resolve() if isinstance(file, (str, Path)) else None
        if path != expected:
            raise AssertionError("unexpected file read")
        return original_builtin_open(file, *args, **kwargs)

    def deny_network(*args, **kwargs):
        raise AssertionError("network access is forbidden")

    monkeypatch.setattr(io, "open", checked_open)
    monkeypatch.setattr(builtins, "open", checked_builtin_open)
    monkeypatch.setattr(socket, "create_connection", deny_network)
    monkeypatch.setattr(socket, "getaddrinfo", deny_network)

    loaded = _load(config, app_data)

    assert type(loaded) is DeploymentConfigV1
    assert actual_reads == [expected]
    assert not (app_data / "omega/due.sqlite3").exists()
    assert not (app_data / "mcp/audit.sqlite3").exists()


def test_public_require_accepts_only_the_loader_issued_instance(tmp_path: Path) -> None:
    config_path, app_data = _write(tmp_path, _toml())
    loaded = _load(config_path, app_data)

    assert require_deployment_config(loaded) is loaded

    direct = DeploymentConfigV1(
        project_id=loaded.project_id,
        environment=loaded.environment,
        app_data_dir=str(loaded.app_data_dir),
        ledger_integrity_key_ref=_issued_reference(),
        omega_due_store_path=str(loaded.omega_due_store_path),
        mcp_audit_store_path=str(loaded.mcp_audit_store_path),
        omega_policy=loaded.omega_policy,
    )
    assert direct is not loaded
    with pytest.raises(DeploymentConfigError) as captured:
        require_deployment_config(direct)
    assert captured.value.code is DeploymentConfigCode.UNISSUED_CONFIG
    assert captured.value.args == ("UNISSUED_CONFIG",)
    assert str(captured.value) == "UNISSUED_CONFIG"
    assert PROJECT_ID not in repr(captured.value.__context__)


@pytest.mark.parametrize(
    "changes",
    [
        {"project_id": "foreign-project-canary"},
        {"environment": "LIVE"},
        {"ledger_integrity_key_ref": LITERAL_CANARY},
        {"omega_due_store_path": "C:/outside/due.sqlite3"},
        {"mcp_audit_store_path": "C:/outside/audit.sqlite3"},
        {"omega_policy": object()},
    ],
)
def test_constructor_rejects_forged_scope_secret_paths_and_policy(
    tmp_path: Path, changes: dict[str, object]
) -> None:
    config_path, app_data = _write(tmp_path, _toml())
    loaded = _load(config_path, app_data)
    fields: dict[str, object] = {
        "project_id": loaded.project_id,
        "environment": loaded.environment,
        "app_data_dir": str(loaded.app_data_dir),
        "ledger_integrity_key_ref": _issued_reference(),
        "omega_due_store_path": str(loaded.omega_due_store_path),
        "mcp_audit_store_path": str(loaded.mcp_audit_store_path),
        "omega_policy": loaded.omega_policy,
    }
    fields.update(changes)

    with pytest.raises(SealError) as captured:
        DeploymentConfigV1(**fields)
    assert str(captured.value) in {"SEAL_INVALID_MODEL", "SEAL_TAMPERED"}
    assert captured.value.__cause__ is None
    if "ledger_integrity_key_ref" in changes:
        assert LITERAL_CANARY not in repr(captured.value)


def test_unissued_construction_and_clone_pickle_or_reinit_cannot_gain_trust(
    tmp_path: Path,
) -> None:
    config_path, app_data = _write(tmp_path, _toml())
    loaded = _load(config_path, app_data)

    with pytest.raises(SealError):
        DeploymentConfigV1.model_construct(
            project_id=PROJECT_ID,
            environment="PAPER",
            app_data_dir=str(loaded.app_data_dir),
            ledger_integrity_key_ref=_issued_reference(),
            omega_due_store_path=str(loaded.omega_due_store_path),
            mcp_audit_store_path=str(loaded.mcp_audit_store_path),
            omega_policy=loaded.omega_policy,
        )
    with pytest.raises(SealError):
        copy.copy(loaded)
    with pytest.raises(SealError):
        copy.deepcopy(loaded)
    with pytest.raises(SealError):
        pickle.dumps(loaded)

    before = loaded.model_dump()
    with pytest.raises(SealError):
        loaded.__init__(project_id="forged-after-issuance")
    assert loaded.model_dump() == before
    assert require_deployment_config(loaded) is loaded


def test_public_require_detects_post_issuance_field_tampering(tmp_path: Path) -> None:
    config_path, app_data = _write(tmp_path, _toml())
    loaded = _load(config_path, app_data)
    object.__setattr__(loaded, "project_id", "tampered-project-canary")

    with pytest.raises(DeploymentConfigError) as captured:
        require_deployment_config(loaded)
    assert captured.value.code is DeploymentConfigCode.UNISSUED_CONFIG
    assert captured.value.args == ("UNISSUED_CONFIG",)
    assert str(captured.value) == "UNISSUED_CONFIG"
    assert "tampered-project-canary" not in repr(captured.value.__context__)
