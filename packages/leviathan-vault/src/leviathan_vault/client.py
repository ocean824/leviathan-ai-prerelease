"""Read-only client for the exact-scope XYRA CurrentUser DPAPI store."""

from __future__ import annotations

import ctypes
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import SecretStr

NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,79}$")
SCOPE_RE = re.compile(r"^[a-z][a-z0-9-]{1,63}$")
ENV_RE = re.compile(r"^[a-z][a-z0-9-]{1,31}$")
PROJECT_SCOPE = "leviathan-ai"
PROJECT_ENVIRONMENTS = frozenset({"development", "live"})
REPARSE_POINT = 0x400


class VaultError(ValueError):
    """A broker-compatible code, never a secret value or platform exception."""


@dataclass(frozen=True)
class CredentialRef:
    provider: str
    name: str
    scope: str
    environment: str


@dataclass(frozen=True)
class VaultStatus:
    name: str
    scope: str
    environment: str
    status: str = "ENCRYPTED_ROUNDTRIP_VERIFIED"
    provider_authentication: str = "NOT_TESTED"


def validate_identity(name: str, scope: str, environment: str) -> None:
    if not (
        NAME_RE.fullmatch(name) and SCOPE_RE.fullmatch(scope) and ENV_RE.fullmatch(environment)
    ):
        raise VaultError("SECRET_SCOPE_DENIED")


def store_reference(name: str, scope: str, environment: str) -> str:
    validate_identity(name, scope, environment)
    return f"dpapi-current-user://{scope}--{environment}--{name}.dpapi"


class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


def _blob(data: bytearray) -> tuple[_DataBlob, Any]:
    buffer = (ctypes.c_ubyte * len(data)).from_buffer(data)
    return _DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte))), buffer


def _unprotect(ciphertext: bytearray, entropy: bytearray) -> SecretStr:
    if os.name != "nt":
        raise VaultError("SECRET_READ_FAILED")
    encrypted_blob, encrypted_buffer = _blob(ciphertext)
    entropy_blob, entropy_buffer = _blob(entropy)
    output = _DataBlob()
    crypt32 = getattr(ctypes, "WinDLL")("crypt32", use_last_error=True)  # noqa: B009
    kernel32 = getattr(ctypes, "WinDLL")("kernel32", use_last_error=True)  # noqa: B009
    crypt32.CryptUnprotectData.argtypes = [
        ctypes.POINTER(_DataBlob),
        ctypes.c_void_p,
        ctypes.POINTER(_DataBlob),
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(_DataBlob),
    ]
    crypt32.CryptUnprotectData.restype = ctypes.c_int
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    try:
        ok = crypt32.CryptUnprotectData(
            ctypes.byref(encrypted_blob),
            None,
            ctypes.byref(entropy_blob),
            None,
            None,
            0,
            ctypes.byref(output),
        )
        if not ok or not output.pbData or output.cbData == 0 or output.cbData % 2:
            raise VaultError("SECRET_READ_FAILED")
        plaintext = bytearray(
            (ctypes.c_ubyte * output.cbData).from_address(ctypes.addressof(output.pbData.contents))
        )
        try:
            return SecretStr(plaintext.decode("utf-16-le", errors="strict"))
        finally:
            plaintext[:] = b"\0" * len(plaintext)
    except VaultError:
        raise
    except Exception:
        raise VaultError("SECRET_READ_FAILED") from None
    finally:
        if output.pbData:
            ctypes.memset(output.pbData, 0, output.cbData)
            kernel32.LocalFree(output.pbData)
        ciphertext[:] = b"\0" * len(ciphertext)
        entropy[:] = b"\0" * len(entropy)
        _ = (encrypted_buffer, entropy_buffer)


class XyraVault:
    """Read only; registry and ciphertext must be produced by Xyra.Secrets.psm1."""

    def __init__(self, factory_root: Path) -> None:
        self.factory_root = factory_root.resolve(strict=True)

    def _deny_reparse(self, path: Path) -> None:
        if not path.is_relative_to(self.factory_root):
            raise VaultError("SECRET_READ_FAILED")
        cursor = path
        if os.name == "nt":
            kernel32 = getattr(ctypes, "WinDLL")("kernel32", use_last_error=True)  # noqa: B009
            kernel32.GetFileAttributesW.argtypes = [ctypes.c_wchar_p]
            kernel32.GetFileAttributesW.restype = ctypes.c_uint32
            while True:
                if os.path.lexists(cursor):
                    attributes = kernel32.GetFileAttributesW(str(cursor))
                    if attributes == 0xFFFFFFFF or attributes & REPARSE_POINT:
                        raise VaultError("SECRET_READ_FAILED")
                if cursor == self.factory_root:
                    break
                cursor = cursor.parent
        elif any(part.is_symlink() for part in (path.parent.parent, path.parent, path)):
            raise VaultError("SECRET_READ_FAILED")

    def _path(self, name: str, scope: str, environment: str) -> Path:
        if scope != PROJECT_SCOPE or environment not in PROJECT_ENVIRONMENTS:
            raise VaultError("SECRET_SCOPE_DENIED")
        expected = store_reference(name, scope, environment)
        try:
            registry = json.loads(
                (self.factory_root / "registries" / "SECRET_REGISTRY.yaml").read_text(
                    encoding="utf-8-sig"
                )
            )
            entries = [
                entry
                for entry in registry["entries"]
                if entry.get("name") == name
                and entry.get("scope") == scope
                and entry.get("environment") == environment
            ]
        except Exception:
            raise VaultError("SECRET_READ_FAILED") from None
        if len(entries) != 1 or entries[0].get("inherit_to_projects") is not False:
            raise VaultError("SECRET_SCOPE_DENIED")
        if entries[0].get("store_reference") != expected:
            raise VaultError("SECRET_REFERENCE_DENIED")
        path = self.factory_root / ".local" / "secrets" / expected.split("://", 1)[1]
        self._deny_reparse(path)
        return path

    def get(self, name: str, scope: str, environment: str) -> SecretStr:
        path = self._path(name, scope, environment)
        if not path.is_file():
            raise VaultError("SECRET_NOT_CONFIGURED")
        try:
            ciphertext = bytearray(path.read_bytes())
            entropy = bytearray(f"xyra-secret-v1|{scope}|{environment}|{name}".encode())
            return _unprotect(ciphertext, entropy)
        except VaultError:
            raise
        except Exception:
            raise VaultError("SECRET_READ_FAILED") from None

    def status(self, name: str, scope: str, environment: str) -> VaultStatus:
        self.get(name, scope, environment)
        return VaultStatus(name, scope, environment)


class InMemoryVault:
    """Synthetic test double with the same exact-scope lookup policy."""

    def __init__(self) -> None:
        self._values: dict[tuple[str, str, str], SecretStr] = {}

    def put(self, name: str, scope: str, environment: str, value: str) -> None:
        if scope != PROJECT_SCOPE or environment not in PROJECT_ENVIRONMENTS:
            raise VaultError("SECRET_SCOPE_DENIED")
        validate_identity(name, scope, environment)
        if not value:
            raise VaultError("SECRET_READ_FAILED")
        self._values[(name, scope, environment)] = SecretStr(value)

    def get(self, name: str, scope: str, environment: str) -> SecretStr:
        if scope != PROJECT_SCOPE or environment not in PROJECT_ENVIRONMENTS:
            raise VaultError("SECRET_SCOPE_DENIED")
        validate_identity(name, scope, environment)
        try:
            return self._values[(name, scope, environment)]
        except KeyError:
            raise VaultError("SECRET_SCOPE_DENIED") from None

    def status(self, name: str, scope: str, environment: str) -> VaultStatus:
        self.get(name, scope, environment)
        return VaultStatus(name, scope, environment)
