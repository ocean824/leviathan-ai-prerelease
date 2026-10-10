from __future__ import annotations

import ast
import os
from pathlib import Path

import pytest

WORKTREE = Path(__file__).resolve().parents[3]
SOURCE_ROOT = Path(os.environ.get("CREDENTIAL_ACCEPTANCE_SOURCE_ROOT", str(WORKTREE))).resolve()
API = SOURCE_ROOT / "apps/api/src/leviathan_api"
VAULT = SOURCE_ROOT / "packages/leviathan-vault/src/leviathan_vault"


def _function(path: Path, name: str) -> ast.FunctionDef:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return next(
        n
        for n in tree.body
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name
    )


def _any_function(path: Path, name: str) -> ast.FunctionDef:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return next(
        n
        for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name
    )


def _method(path: Path, class_name: str, method_name: str) -> ast.FunctionDef:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == class_name)
    return next(
        n
        for n in cls.body
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == method_name
    )


def _calls(node: ast.AST) -> set[str]:
    return {
        n.func.id
        for n in ast.walk(node)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
    }


def test_import_origin_matches_requested_worktree_when_configured() -> None:
    expected_worktree = os.environ.get("LEVIATHAN_ACCEPTANCE_WORKTREE")
    if not expected_worktree:
        pytest.skip("set LEVIATHAN_ACCEPTANCE_WORKTREE to verify import origin")

    import leviathan_api.chat.tool_bridge as bridge
    import leviathan_api.credential_connections as connections
    import leviathan_api.routers.live_activation as activation
    import leviathan_vault.app_credentials as credentials
    import leviathan_vault.project_secrets as project_secrets

    expected_root = Path(expected_worktree).resolve()
    for module in (connections, bridge, activation, credentials, project_secrets):
        assert Path(module.__file__).resolve().is_relative_to(expected_root), module.__file__


def test_chat_and_standing_delegation_cannot_mutate_credentials() -> None:
    from leviathan_api.chat import capabilities_v1, tool_bridge

    credential_tools = [
        row
        for row in tool_bridge._REGISTRY  # noqa: SLF001
        if "credential" in row.tool_id.casefold() or "credential" in row.route_path.casefold()
    ]
    assert credential_tools
    assert all(row.capability == "read" and not row.mutating for row in credential_tools)
    assert {row.tool_id for row in credential_tools} == {
        "connections.credentials.status.read",
        "connections.credentials.test",
    }
    protected = [
        p
        for p in capabilities_v1.CAPABILITY_POLICIES
        if p.capability_id in {"credentials.put", "credentials.delete", "credentials.change"}
    ]
    assert {p.capability_id for p in protected} == {
        "credentials.put",
        "credentials.delete",
        "credentials.change",
    }
    assert all(p.chat_surface == capabilities_v1.ChatSurfaceV1.UI_ONLY for p in protected)
    assert all(p.confirmation_class == capabilities_v1.ConfirmationClassV1.O2 for p in protected)
    assert not {"credentials.put", "credentials.delete", "credentials.change"}.intersection(
        capabilities_v1._DELEGATION_ACTION_BY_CAPABILITY  # noqa: SLF001
    )
    source = ast.parse((API / "chat/tool_bridge.py").read_text(encoding="utf-8"))
    entries = [
        n
        for n in ast.walk(source)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Name)
        and n.func.id == "ChatToolRegistryEntryV1"
    ]
    for entry in entries:
        kwargs = {kw.arg: kw.value for kw in entry.keywords if kw.arg}
        tool_id = ast.literal_eval(kwargs["tool_id"]) if "tool_id" in kwargs else ""
        if "credential" in tool_id.casefold():
            assert ast.literal_eval(kwargs.get("capability", ast.Constant(""))) == "read"
            assert ast.literal_eval(kwargs.get("mutating", ast.Constant(False))) is False
    source_ids = {
        ast.literal_eval({kw.arg: kw.value for kw in n.keywords if kw.arg}["tool_id"])
        for n in entries
        if "tool_id" in {kw.arg: kw.value for kw in n.keywords if kw.arg}
        and "credential"
        in ast.literal_eval({kw.arg: kw.value for kw in n.keywords if kw.arg}["tool_id"]).casefold()
    }
    assert source_ids == {"connections.credentials.status.read", "connections.credentials.test"}


def test_legacy_routes_delegate_to_the_single_shared_mutation_service() -> None:
    source = API / "credential_connections.py"
    replace = _any_function(source, "legacy_replace")
    remove = _any_function(source, "legacy_remove")
    assert "_replace_broker_profile" in _calls(replace)
    assert "_remove_broker_profile" in _calls(remove)
    # The routers module may validate requests, but may not write the credential store.
    routes = (API / "routers/credentials.py").read_text(encoding="utf-8")
    tree = ast.parse(routes)
    assert not any(
        isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr in {"put_profile", "delete_profile", "put", "remove"}
        for n in ast.walk(tree)
    )
    assert "_replace_broker_profile" in _calls(replace)


def test_status_schema_and_chat_registry_are_write_only() -> None:
    from leviathan_api.credential_connections import CredentialReferenceV1, CredentialStatusV1

    status_fields = set(CredentialStatusV1.model_fields)
    assert not status_fields.intersection(
        {"password", "secret", "token", "private_key", "credential_value"}
    )
    reference_fields = set(CredentialReferenceV1.model_fields)
    assert not reference_fields.intersection(
        {"password", "secret", "token", "private_key", "credential_value"}
    )
    source = (API / "credential_connections.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    status_routes = [
        n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "list_status"
    ]
    assert status_routes
    assert all("get_secret_value" not in ast.unparse(n) for n in status_routes)


def test_windows_store_encrypts_fake_secret_before_any_disk_write(tmp_path: Path) -> None:
    from leviathan_vault.app_credentials import DPAPICredentialStore

    put = _method(VAULT / "app_credentials.py", "DPAPICredentialStore", "put_profile")
    source_text = ast.unparse(put)
    assert "_crypt(" in source_text and "_atomic(" in source_text
    assert source_text.index("_crypt(") < source_text.index("_atomic(")

    sentinel = "SYNTHETIC-DEVICE-ACCEPTANCE-SECRET-8f42c1"
    store = DPAPICredentialStore(tmp_path / "credential-vault")
    from pydantic import SecretStr

    store.put_profile(
        "MT5",
        "DEMO",
        "acceptance",
        {
            "server": "Demo-Server",
            "login": "987654",
            "password": SecretStr(sentinel),
        },
    )
    files = [p for p in (tmp_path / "credential-vault").rglob("*") if p.is_file()]
    assert files
    for path in files:
        assert sentinel.encode("ascii") not in path.read_bytes(), path.name
    assert (
        store.resolve("MT5", "DEMO", "acceptance").secret("password").get_secret_value() == sentinel
    )


def test_non_apple_keyring_backend_fails_closed_without_echo() -> None:
    from leviathan_vault.project_secrets import MacOSProjectSecretStore, ProjectSecretError

    class GenericKeyring:
        def get_password(self, service: str, username: str) -> str | None:
            return None

        def set_password(self, service: str, username: str, password: str) -> None:
            pass

        def delete_password(self, service: str, username: str) -> None:
            pass

    with pytest.raises(ProjectSecretError) as err:
        MacOSProjectSecretStore(GenericKeyring())
    assert str(err.value) == "SECRET_UNAVAILABLE"
    init = _method(VAULT / "project_secrets.py", "MacOSProjectSecretStore", "__init__")
    assert "require_macos_keychain_backend" in _calls(init)


def test_project_secret_factory_is_platform_gated(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import leviathan_vault.project_secrets as module

    selected: list[str] = []

    class WindowsFake:
        def __init__(self, _root: Path, _bindings: Path) -> None:
            selected.append("windows")

    class MacFake:
        def __init__(self) -> None:
            selected.append("macos")

    monkeypatch.setattr(module, "WindowsProjectSecretStore", WindowsFake)
    monkeypatch.setattr(module, "MacOSProjectSecretStore", MacFake)
    monkeypatch.setattr(module.sys, "platform", "win32")
    module.project_secret_store_for_platform(tmp_path, tmp_path / "bindings")
    monkeypatch.setattr(module.sys, "platform", "darwin")
    module.project_secret_store_for_platform()
    assert selected == ["windows", "macos"]
    monkeypatch.setattr(module.sys, "platform", "linux")
    with pytest.raises(module.ProjectSecretError) as err:
        module.project_secret_store_for_platform()
    assert str(err.value) == "SECRET_UNAVAILABLE"


def test_account_owner_mismatch_fails_closed() -> None:
    from types import SimpleNamespace

    from leviathan_api.routers.live_activation import LiveAccountEvidenceV1, _owner_account

    class Accounts:
        def read_account(self, principal, account_id):
            return LiveAccountEvidenceV1(
                account_id=account_id,
                organization_id="org-a",
                device_id="device-a",
                owner_principal_id="owner-b",
                environment="live",
                binding_revision="bind-1",
                credential_revision="cred-1",
            )

    ports = SimpleNamespace(accounts=Accounts())
    assert _owner_account(ports, SimpleNamespace(principal_id="owner-a"), "account-a") is None
    owner_source = ast.unparse(_function(API / "routers/live_activation.py", "_owner_account"))
    assert "owner_principal_id" in owner_source and "principal.principal_id" in owner_source


def test_device_binding_mismatch_is_checked_at_authorization_boundary() -> None:
    # Check the serving decision, not merely that a device id is present in a schema.
    from types import SimpleNamespace

    from leviathan_api.routers.live_activation import LiveAccountEvidenceV1, _owner_account

    class Accounts:
        def read_account(self, _principal, account_id):
            return LiveAccountEvidenceV1(
                account_id=account_id,
                organization_id="org-a",
                device_id="device-stored",
                owner_principal_id="owner-a",
                environment="live",
                binding_revision="bind-1",
                credential_revision="cred-1",
            )

    mismatch = _owner_account(
        SimpleNamespace(accounts=Accounts()),
        SimpleNamespace(principal_id="owner-a", device_id="device-current"),
        "account-a",
    )
    assert mismatch is None, "a credential/account binding from another device must fail closed"
    path = API / "routers/live_activation.py"
    node = _function(path, "_owner_account")
    source = ast.unparse(node)
    assert "device_id" in source and ("!=" in source or "not in" in source), source
