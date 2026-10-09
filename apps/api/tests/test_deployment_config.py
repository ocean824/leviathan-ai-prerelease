from __future__ import annotations

import copy
import json
import pickle
import tomllib
from pathlib import Path

import pytest

from leviathan_api.deployment_config import (
    LEDGER_INTEGRITY_SERVICE_ID,
    PROJECT_ID,
    DeploymentConfigCode,
    DeploymentConfigError,
    DeploymentConfigV1,
    load_deployment_config,
)
from leviathan_core.deployment_secret_refs import (
    issue_allowed_secret_bindings,
    issue_provider_alias_map,
    validate_secret_reference,
)
from leviathan_core.omega_link.state_models import OmegaPolicyV1
from leviathan_core.seal import SealError, require

REFERENCE = "vault://leviathan-ai/development/synthetic-provider/LEDGER_INTEGRITY_KEY"
LIVE_REFERENCE = "vault://leviathan-ai/live/synthetic-provider/LEDGER_INTEGRITY_KEY"


def _tables(reference: str = REFERENCE):
    bindings = issue_allowed_secret_bindings(
        ((LEDGER_INTEGRITY_SERVICE_ID, "development", reference),)
    )
    aliases = issue_provider_alias_map(())
    return bindings, aliases


def _document(
    *,
    project_id: str = PROJECT_ID,
    environment: str = "PAPER",
    reference: str = REFERENCE,
    due_path: str = "omega-due.sqlite3",
    audit_path: str = "mcp-audit.sqlite3",
    heartbeat: object = 2_000_000_000,
    add_heartbeat: bool = True,
    extra: str = "",
) -> str:
    omega = f"due_store_path = {json.dumps(due_path)}\n"
    if add_heartbeat:
        omega += f"max_heartbeat_age_ns = {heartbeat!r}\n"
    return (
        "[project]\n"
        f'project_id = "{project_id}"\n'
        f'environment = "{environment}"\n\n'
        "[secrets]\n"
        f'ledger_integrity_key_ref = "{reference}"\n\n'
        "[omega]\n"
        + omega
        + "\n[mcp_control]\n"
        + f"audit_store_path = {json.dumps(audit_path)}\n"
        + extra
    )


def _write(tmp_path: Path, content: str) -> tuple[Path, Path]:
    config = tmp_path / "config.toml"
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    config.write_text(content, encoding="utf-8")
    return config, data


def _load(config: Path, data: Path, reference: str = REFERENCE) -> DeploymentConfigV1:
    bindings, aliases = _tables(reference)
    return load_deployment_config(
        config,
        app_data_dir=data,
        allowed_bindings=bindings,
        provider_aliases=aliases,
    )


def _issued_reference(reference: str = REFERENCE):
    bindings, aliases = _tables(reference)
    return validate_secret_reference(
        reference,
        service_id=LEDGER_INTEGRITY_SERVICE_ID,
        environment="development",
        allowed_bindings=bindings,
        provider_aliases=aliases,
    )


def _assert_code(call, code: DeploymentConfigCode, secret: str | None = None) -> None:
    with pytest.raises(DeploymentConfigError) as raised:
        call()
    assert raised.value.code is code
    assert str(raised.value) == code.value
    if secret:
        assert secret not in str(raised.value)


def test_loads_typed_paper_config_and_never_opens_store_paths(tmp_path: Path) -> None:
    config, data = _write(tmp_path, _document())
    loaded = _load(config, data)
    assert type(loaded) is DeploymentConfigV1
    assert loaded.project_id == PROJECT_ID
    assert loaded.environment == "PAPER"
    assert type(loaded.omega_policy) is OmegaPolicyV1
    assert loaded.omega_policy.max_heartbeat_age_ns == 2_000_000_000
    assert loaded.omega_due_store_path == (data / "omega-due.sqlite3").resolve()
    assert loaded.mcp_audit_store_path == (data / "mcp-audit.sqlite3").resolve()
    assert type(loaded.ledger_integrity_key_ref).__name__ == "SecretReferenceV1"
    assert loaded.ledger_integrity_key_ref.canonical_ref == REFERENCE
    assert loaded.ledger_integrity_key_ref.environment == "development"
    assert not loaded.omega_due_store_path.exists()
    assert not loaded.mcp_audit_store_path.exists()
    with pytest.raises(SealError):
        require(loaded.ledger_integrity_key_ref, "unrelated.issuer")


def test_loader_issues_config_and_public_require_rejects_direct_construction(
    tmp_path: Path,
) -> None:
    config_path, data = _write(tmp_path, _document())
    loaded = _load(config_path, data)
    from leviathan_api.deployment_config import require_deployment_config

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
    with pytest.raises(DeploymentConfigError) as raised:
        require_deployment_config(direct)
    assert raised.value.code is DeploymentConfigCode.UNISSUED_CONFIG
    assert str(raised.value) == "UNISSUED_CONFIG"


@pytest.mark.parametrize(
    "changes",
    [
        {"project_id": "other-project"},
        {"environment": "LIVE"},
        {"ledger_integrity_key_ref": "sk_live_synthetic_secret"},
        {"omega_due_store_path": Path("C:/outside.sqlite3")},
        {"mcp_audit_store_path": Path("C:/outside.sqlite3")},
        {"omega_policy": object()},
    ],
)
def test_model_level_invariants_reject_directly_forged_fields(
    tmp_path: Path, changes: dict[str, object]
) -> None:
    config_path, data = _write(tmp_path, _document())
    loaded = _load(config_path, data)
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
    with pytest.raises(SealError) as raised:
        DeploymentConfigV1(**fields)
    assert str(raised.value) in {"SEAL_INVALID_MODEL", "SEAL_TAMPERED"}
    assert "sk_live_synthetic_secret" not in str(raised.value)


def test_construct_copy_pickle_and_reinitialization_cannot_forge_issued_config(
    tmp_path: Path,
) -> None:
    config_path, data = _write(tmp_path, _document())
    loaded = _load(config_path, data)
    from leviathan_api.deployment_config import require_deployment_config

    with pytest.raises(SealError):
        DeploymentConfigV1.model_construct(
            project_id="other-project",
            environment="LIVE",
            app_data_dir=Path("C:/"),
            ledger_integrity_key_ref="sk_live_synthetic_secret",
            omega_due_store_path=Path("C:/outside.sqlite3"),
            mcp_audit_store_path=Path("C:/outside.sqlite3"),
            omega_policy=object(),
        )
    with pytest.raises(SealError):
        copy.copy(loaded)
    with pytest.raises(SealError):
        copy.deepcopy(loaded)
    with pytest.raises(SealError):
        pickle.dumps(loaded)
    before = loaded.model_dump()
    with pytest.raises(SealError):
        loaded.__init__(project_id="other-project")
    assert require_deployment_config(loaded) is loaded
    assert loaded.model_dump() == before


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (lambda text: text + "\n[unexpected]\nvalue = 1\n", DeploymentConfigCode.CONFIG_INVALID),
        (
            lambda text: text.replace('environment = "PAPER"\n', 'environment = "LIVE"\n'),
            DeploymentConfigCode.CONFIG_INVALID,
        ),
        (
            lambda text: text.replace(
                f'project_id = "{PROJECT_ID}"', 'project_id = "another-project"'
            ),
            DeploymentConfigCode.CONFIG_INVALID,
        ),
        (
            lambda text: text.replace("max_heartbeat_age_ns = 2000000000\n", ""),
            DeploymentConfigCode.HEARTBEAT_SLA_REQUIRED,
        ),
        (
            lambda text: text.replace(
                "max_heartbeat_age_ns = 2000000000", "max_heartbeat_age_ns = true"
            ),
            DeploymentConfigCode.CONFIG_INVALID,
        ),
        (
            lambda text: text.replace(
                "max_heartbeat_age_ns = 2000000000", "max_heartbeat_age_ns = 0"
            ),
            DeploymentConfigCode.CONFIG_INVALID,
        ),
        (
            lambda text: text.replace(
                "max_heartbeat_age_ns = 2000000000", "max_heartbeat_age_ns = 1800000000001"
            ),
            DeploymentConfigCode.CONFIG_INVALID,
        ),
        (
            lambda text: text.replace("[project]\n", '[project]\nextra = "unknown"\n'),
            DeploymentConfigCode.CONFIG_INVALID,
        ),
    ],
)
def test_strict_schema_and_operator_policy_fail_closed(tmp_path: Path, mutate, code) -> None:
    config, data = _write(tmp_path, mutate(_document()))
    _assert_code(lambda: _load(config, data), code)


def test_missing_omega_table_fails_for_required_sla(tmp_path: Path) -> None:
    content = _document().replace(
        '[omega]\ndue_store_path = "omega-due.sqlite3"\nmax_heartbeat_age_ns = 2000000000\n',
        '[omega]\ndue_store_path = "omega-due.sqlite3"\n',
    )
    config, data = _write(tmp_path, content)
    _assert_code(lambda: _load(config, data), DeploymentConfigCode.HEARTBEAT_SLA_REQUIRED)


@pytest.mark.parametrize(
    "reference", [LIVE_REFERENCE, "not-a-vault-ref", "sk_live_synthetic_secret_material"]
)
def test_invalid_or_wrong_environment_reference_is_fixed_and_content_free(
    tmp_path: Path, reference: str
) -> None:
    config, data = _write(tmp_path, _document(reference=reference))
    _assert_code(
        lambda: _load(config, data),
        DeploymentConfigCode.SECRET_REFERENCE_INVALID,
        reference,
    )


def test_wrong_binding_is_rejected_before_any_factory_or_store_use(tmp_path: Path) -> None:
    config, data = _write(tmp_path, _document())
    other_ref = "vault://leviathan-ai/development/other-provider/LEDGER_INTEGRITY_KEY"
    bindings, aliases = _tables(other_ref)
    _assert_code(
        lambda: load_deployment_config(
            config,
            app_data_dir=data,
            allowed_bindings=bindings,
            provider_aliases=aliases,
        ),
        DeploymentConfigCode.SECRET_REFERENCE_INVALID,
    )
    assert not (data / "omega-due.sqlite3").exists()
    assert not (data / "mcp-audit.sqlite3").exists()


@pytest.mark.parametrize(
    "value",
    [
        "../outside.sqlite3",
        "sub/../../outside.sqlite3",
        "/outside.sqlite3",
        "C:/outside.sqlite3",
        "sub\\outside.sqlite3",
        "",
        "./same.sqlite3",
    ],
)
def test_store_paths_reject_escape_and_nonportable_grammar(tmp_path: Path, value: str) -> None:
    config, data = _write(tmp_path, _document(due_path=value))
    _assert_code(lambda: _load(config, data), DeploymentConfigCode.STORE_PATH_INVALID, value)


def test_store_paths_reject_symlink_escape(tmp_path: Path) -> None:
    config, data = _write(tmp_path, _document(due_path="escape/due.sqlite3"))
    outside = tmp_path / "outside"
    outside.mkdir()
    try:
        (data / "escape").symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable on this host")
    _assert_code(lambda: _load(config, data), DeploymentConfigCode.STORE_PATH_INVALID)


def test_store_paths_reject_windows_junction_escape(tmp_path: Path) -> None:
    import _winapi

    config, data = _write(tmp_path, _document(due_path="junction/due.sqlite3"))
    outside = tmp_path / "outside"
    outside.mkdir()
    junction = data / "junction"
    try:
        _winapi.CreateJunction(str(outside), str(junction))
    except OSError:
        pytest.skip("directory junction creation is unavailable on this host")
    assert junction.exists()
    _assert_code(lambda: _load(config, data), DeploymentConfigCode.STORE_PATH_INVALID)


def test_audit_path_also_rejects_escape(tmp_path: Path) -> None:
    config, data = _write(tmp_path, _document(audit_path="../outside.sqlite3"))
    _assert_code(lambda: _load(config, data), DeploymentConfigCode.STORE_PATH_INVALID)


def test_example_is_synthetic_and_intentionally_missing_operator_sla() -> None:
    path = Path(__file__).parents[1] / "config" / "local-paper.example.toml"
    content = path.read_text(encoding="utf-8")
    assert "vault://leviathan-ai/development/example-provider/EXAMPLE_LEDGER_KEY" in content
    assert "max_heartbeat_age_ns =" not in content
    assert "# max_heartbeat_age_ns is required" in content
    parsed = tomllib.loads(content)
    assert "max_heartbeat_age_ns" not in parsed["omega"]
    assert "LedgerIntegrityKey(" not in content


def test_malformed_and_oversized_config_errors_do_not_echo_content(tmp_path: Path) -> None:
    config, data = _write(tmp_path, "[broken\nvalue = 'do-not-echo-this'")
    _assert_code(
        lambda: _load(config, data), DeploymentConfigCode.CONFIG_INVALID, "do-not-echo-this"
    )
    config.write_bytes(b"x" * 65_537)
    _assert_code(lambda: _load(config, data), DeploymentConfigCode.CONFIG_READ_FAILED, "x" * 20)


def test_unreadable_config_has_fixed_error(tmp_path: Path) -> None:
    missing = tmp_path / "missing-secret-shaped-name.toml"
    data = tmp_path / "data"
    data.mkdir()
    _assert_code(
        lambda: _load(missing, data),
        DeploymentConfigCode.CONFIG_READ_FAILED,
        "missing-secret-shaped-name",
    )
