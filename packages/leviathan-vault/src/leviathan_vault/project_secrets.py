"""Platform-neutral write-only access to project-scoped provider secrets."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any, Protocol, cast

from pydantic import SecretStr

from leviathan_vault.app_credentials import require_macos_keychain_backend
from leviathan_vault.client import PROJECT_SCOPE, XyraVault
from leviathan_vault.import_keys import (
    ImportPlan,
    ParsedCredential,
    import_plan,
    remove_project_secret,
)

_REFERENCE = re.compile(
    r"vault://leviathan-ai/(development|live)/([A-Z][A-Z0-9_]*)/([A-Z][A-Z0-9_]*)\Z",
    re.ASCII,
)
_SERVICE = "xyra-project-secret-v1"


class ProjectSecretError(ValueError):
    """Fixed, value-free project secret failure."""

    def __init__(self, code: str = "SECRET_UNAVAILABLE") -> None:
        self.code = code
        super().__init__(code)


class ProjectSecretStorePort(Protocol):
    def configured(self, reference: str, name: str) -> bool: ...
    def put(self, reference: str, name: str, value: SecretStr) -> None: ...
    def get(self, reference: str, name: str) -> SecretStr: ...
    def remove(self, reference: str, name: str) -> None: ...


class KeyringBackendPort(Protocol):
    def get_password(self, service: str, username: str) -> str | None: ...
    def set_password(self, service: str, username: str, password: str) -> None: ...
    def delete_password(self, service: str, username: str) -> None: ...


def _identity(reference: str, name: str) -> tuple[str, str, str]:
    match = _REFERENCE.fullmatch(reference) if type(reference) is str else None
    if match is None or type(name) is not str or match.group(3) != name:
        raise ProjectSecretError("SECRET_REFERENCE_DENIED")
    environment, provider, _ = match.groups()
    return provider, environment, name


class WindowsProjectSecretStore:
    """Use the existing Xyra import transaction and Set-XyraSecret broker."""

    def __init__(self, factory_root: Path, bindings: Path) -> None:
        self._factory_root = factory_root
        self._bindings = bindings
        self._reader = XyraVault(factory_root)

    def configured(self, reference: str, name: str) -> bool:
        _provider, environment, _ = _identity(reference, name)
        try:
            self._reader.get(name, PROJECT_SCOPE, environment)
            return True
        except Exception as exc:
            if getattr(exc, "args", ()) and exc.args[0] == "SECRET_NOT_CONFIGURED":
                return False
            return False

    def put(self, reference: str, name: str, value: SecretStr) -> None:
        provider, environment, _ = _identity(reference, name)
        if type(value) is not SecretStr or not value.get_secret_value():
            raise ProjectSecretError("SECRET_WRITE_FAILED")
        try:
            item = ParsedCredential(
                provider=provider,
                name=name,
                environment=environment,
                value=value.get_secret_value(),
            )
            import_plan(
                self._factory_root,
                ImportPlan((item,), (), (), ()),
                PROJECT_SCOPE,
                replace=True,
                bindings=self._bindings,
            )
        except Exception:
            raise ProjectSecretError("SECRET_WRITE_FAILED") from None

    def get(self, reference: str, name: str) -> SecretStr:
        _provider, environment, _ = _identity(reference, name)
        try:
            return self._reader.get(name, PROJECT_SCOPE, environment)
        except Exception:
            raise ProjectSecretError("SECRET_READ_FAILED") from None

    def remove(self, reference: str, name: str) -> None:
        _provider, environment, _ = _identity(reference, name)
        try:
            remove_project_secret(self._factory_root, name, environment, bindings=self._bindings)
        except Exception:
            raise ProjectSecretError("SECRET_REMOVE_FAILED") from None


class MacOSProjectSecretStore:
    """Use Keychain with the canonical market-data reference as the account key."""

    def __init__(self, keyring_backend: KeyringBackendPort | None = None) -> None:
        try:
            if keyring_backend is None:
                import importlib

                keyring: Any = importlib.import_module("keyring")
                selected = keyring.get_keyring()
            else:
                selected = keyring_backend
            self._keyring = cast(KeyringBackendPort, require_macos_keychain_backend(selected))
        except Exception:
            raise ProjectSecretError("SECRET_UNAVAILABLE") from None

    def configured(self, reference: str, name: str) -> bool:
        _identity(reference, name)
        try:
            return self._keyring.get_password(_SERVICE, reference) is not None
        except Exception:
            return False

    def put(self, reference: str, name: str, value: SecretStr) -> None:
        _identity(reference, name)
        if type(value) is not SecretStr or not value.get_secret_value():
            raise ProjectSecretError("SECRET_WRITE_FAILED")
        try:
            self._keyring.set_password(_SERVICE, reference, value.get_secret_value())
        except Exception:
            raise ProjectSecretError("SECRET_WRITE_FAILED") from None

    def get(self, reference: str, name: str) -> SecretStr:
        _identity(reference, name)
        try:
            value = self._keyring.get_password(_SERVICE, reference)
            if type(value) is not str or not value:
                raise ValueError
            return SecretStr(value)
        except Exception:
            raise ProjectSecretError("SECRET_READ_FAILED") from None

    def remove(self, reference: str, name: str) -> None:
        _identity(reference, name)
        try:
            self._keyring.delete_password(_SERVICE, reference)
        except Exception:
            raise ProjectSecretError("SECRET_REMOVE_FAILED") from None


def project_secret_store_for_platform(
    factory_root: Path | None = None, bindings: Path | None = None
) -> ProjectSecretStorePort:
    if sys.platform == "win32" and factory_root is not None and bindings is not None:
        return WindowsProjectSecretStore(factory_root, bindings)
    if sys.platform == "darwin":
        return MacOSProjectSecretStore()
    raise ProjectSecretError("SECRET_UNAVAILABLE")


__all__ = [
    "MacOSProjectSecretStore",
    "ProjectSecretError",
    "ProjectSecretStorePort",
    "WindowsProjectSecretStore",
    "project_secret_store_for_platform",
]
