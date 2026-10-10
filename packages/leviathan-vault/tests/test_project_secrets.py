from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import SecretStr

from leviathan_vault.project_secrets import (
    MacOSProjectSecretStore,
    ProjectSecretError,
    WindowsProjectSecretStore,
    project_secret_store_for_platform,
)

REFERENCE = "vault://leviathan-ai/development/DATABENTO/DATABENTO_API_KEY"


class _Keychain:
    __module__ = "keyring.backends.macOS"

    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, username: str) -> str | None:
        return self.values.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self.values[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        self.values.pop((service, username), None)


def test_macos_project_secret_store_uses_keychain_reference_as_identity() -> None:
    backend = _Keychain()
    store = MacOSProjectSecretStore(backend)
    assert store.configured(REFERENCE, "DATABENTO_API_KEY") is False
    store.put(REFERENCE, "DATABENTO_API_KEY", SecretStr("synthetic-project-secret"))
    assert store.configured(REFERENCE, "DATABENTO_API_KEY") is True
    assert (
        store.get(REFERENCE, "DATABENTO_API_KEY").get_secret_value() == "synthetic-project-secret"
    )
    store.remove(REFERENCE, "DATABENTO_API_KEY")
    assert store.configured(REFERENCE, "DATABENTO_API_KEY") is False


def test_platform_factory_selects_windows_dpapi_project_store(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("leviathan_vault.project_secrets.sys.platform", "win32")
    factory_root = tmp_path / "vault"
    factory_root.mkdir()
    store = project_secret_store_for_platform(factory_root, tmp_path / "bindings.json")
    assert isinstance(store, WindowsProjectSecretStore)


def test_platform_factory_fails_closed_without_supported_backend(monkeypatch) -> None:
    monkeypatch.setattr("leviathan_vault.project_secrets.sys.platform", "linux")
    with pytest.raises(ProjectSecretError) as failure:
        project_secret_store_for_platform()
    assert str(failure.value) == "SECRET_UNAVAILABLE"


def test_macos_project_secret_factory_rejects_non_apple_keyring_backend(monkeypatch) -> None:
    class NonAppleBackend(_Keychain):
        __module__ = "keyring.backends.Windows"

    monkeypatch.setattr("leviathan_vault.project_secrets.sys.platform", "darwin")
    monkeypatch.setitem(
        sys.modules,
        "keyring",
        SimpleNamespace(get_keyring=lambda: NonAppleBackend()),
    )
    with pytest.raises(ProjectSecretError) as failure:
        project_secret_store_for_platform()
    assert str(failure.value) == "SECRET_UNAVAILABLE"
