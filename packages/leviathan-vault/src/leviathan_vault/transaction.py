"""Recoverable, serialized snapshots for a broker-owned DPAPI import.

Snapshots are hardlinks to *encrypted* files or nonsecret metadata. The broker
remains the only process that creates plaintext or DPAPI ciphertext. A journal
allows a later import to finish rollback after interruption; this is not an
OS-crash atomicity guarantee. The lock serializes importers only; direct broker
writers require an exclusive maintenance window or a broker-wide lock.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import uuid
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import Any, cast

from leviathan_vault.client import PROJECT_ENVIRONMENTS, PROJECT_SCOPE, validate_identity

_REPARSE_POINT = 0x400
_TX_ID = re.compile(r"^[0-9a-f]{32}$")
_HASH = re.compile(r"^[0-9a-f]{64}$")
_PHASES = frozenset({"preparing", "applying", "committed", "rolled_back"})


class TransactionError(ValueError):
    """Fixed code only; journal and exceptions never include values."""


def _deny_reparse(path: Path) -> None:
    """Reject reparse points on Windows and symlinks on other platforms."""
    cursor = path.absolute()
    kernel32 = None
    if os.name == "nt":
        kernel32 = getattr(ctypes, "WinDLL")("kernel32", use_last_error=True)  # noqa: B009
        kernel32.GetFileAttributesW.argtypes = [ctypes.c_wchar_p]
        kernel32.GetFileAttributesW.restype = ctypes.c_uint32
    while True:
        if os.path.lexists(cursor):
            try:
                if kernel32 is not None:
                    attributes = kernel32.GetFileAttributesW(str(cursor))
                    if attributes == 0xFFFFFFFF or attributes & _REPARSE_POINT:
                        raise TransactionError("IMPORT_PATH_DENIED")
                elif stat.S_ISLNK(cursor.lstat().st_mode):
                    raise TransactionError("IMPORT_PATH_DENIED")
            except TransactionError:
                raise
            except OSError:
                raise TransactionError("IMPORT_PATH_DENIED") from None
        if cursor == cursor.parent:
            return
        cursor = cursor.parent


def _snapshot_path(target: Path, txid: str) -> Path:
    return target.with_name(f".{target.name}.xyra-{txid}.snapshot")


def _fingerprint(path: Path) -> dict[str, int | str]:
    stat = path.stat()
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return {
        "sha256": digest.hexdigest(),
        "size": stat.st_size,
        "device": stat.st_dev,
        "inode": stat.st_ino,
    }


_PRIVATE_DIRECTORY_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$path = $env:XYRA_IMPORT_BACKUP_ROOT
$trustedAdministrativeOwner = 'S-1-5-32-544'
try {
    $actual = [System.IO.Directory]::GetAccessControl($path)
} catch { exit 11 }
if ($null -eq $actual) { exit 16 }
try {
    $ownerSid = $actual.GetOwner([Security.Principal.SecurityIdentifier])
    if ($null -eq $ownerSid) { exit 17 }
    $owner = $ownerSid.Value
} catch { exit 17 }
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($null -eq $identity -or $null -eq $identity.User) { exit 18 }
    $sid = $identity.User
    $principal = New-Object Security.Principal.WindowsPrincipal(
        $identity)
    $adminSid = New-Object Security.Principal.SecurityIdentifier($trustedAdministrativeOwner)
    $elevatedAdministrator = $principal.IsInRole($adminSid)
} catch { exit 18 }
# Owners have implicit WRITE_DAC. An Administrators-owned root is trusted only
# when this process has an enabled, elevated Administrators token.
if ($owner -ne $sid.Value -and
    -not ($owner -eq $trustedAdministrativeOwner -and $elevatedAdministrator)) { exit 12 }
try {
    $rules = @($actual.GetAccessRules($true, $true,
        [Security.Principal.SecurityIdentifier]))
    $protected = $actual.AreAccessRulesProtected
} catch { exit 14 }
if ($protected -and
    $rules.Count -eq 1 -and $rules[0].IdentityReference.Value -eq $sid.Value -and
    $rules[0].AccessControlType -eq 'Allow' -and
    $rules[0].FileSystemRights -eq 'FullControl') { exit 0 }
try {
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
} catch { exit 15 }
try {
    $rule = New-Object Security.AccessControl.FileSystemAccessRule(
        $sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $acl.AddAccessRule($rule)
    [System.IO.Directory]::SetAccessControl($path, $acl)
} catch { exit 13 }
try {
    $actual = [System.IO.Directory]::GetAccessControl($path)
} catch { exit 14 }
if ($null -eq $actual) { exit 16 }
try {
    $rules = @($actual.GetAccessRules($true, $true,
        [Security.Principal.SecurityIdentifier]))
    $protected = $actual.AreAccessRulesProtected
} catch { exit 14 }
if (-not $protected) { exit 15 }
if ($rules.Count -ne 1 -or $rules[0].IdentityReference.Value -ne $sid.Value -or
    $rules[0].AccessControlType -ne 'Allow' -or
    $rules[0].FileSystemRights -ne 'FullControl') { exit 14 }
"""


def _protect_backup_root(path: Path) -> None:
    executable = shutil.which("powershell.exe")
    if executable is None:
        raise TransactionError("IMPORT_LOCKED")
    try:
        result = subprocess.run(
            [executable, "-NoProfile", "-NonInteractive", "-Command", _PRIVATE_DIRECTORY_SCRIPT],
            env={**os.environ, "XYRA_IMPORT_BACKUP_ROOT": str(path)},
            capture_output=True,
            timeout=30,
            check=False,
        )
        if result.returncode:
            raise TransactionError("IMPORT_LOCKED")
    except TransactionError:
        raise
    except Exception:
        raise TransactionError("IMPORT_LOCKED") from None


def _atomic_journal(path: Path, document: dict[str, Any], *, create: bool = False) -> None:
    pending: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=path.parent,
            prefix=".journal-",
            suffix=".pending",
            delete=False,
        ) as handle:
            pending = Path(handle.name)
            json.dump(document, handle, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        if create:
            os.link(pending, path)
        else:
            os.replace(pending, path)
    finally:
        if pending is not None:
            pending.unlink(missing_ok=True)


@contextmanager
def import_lock(factory_root: Path) -> Iterator[Path]:
    """One importer per factory; lock is released by Windows on process death."""
    if os.name != "nt":
        raise TransactionError("IMPORT_PLATFORM_DENIED")
    import msvcrt

    backup_root = factory_root / ".local" / "registry-backups"
    _deny_reparse(backup_root)
    backup_root.mkdir(parents=True, exist_ok=True)
    _deny_reparse(backup_root)
    _protect_backup_root(backup_root)
    lock_path = backup_root / ".import.lock"
    _deny_reparse(lock_path)
    try:
        handle = lock_path.open("a+b")
        if handle.seek(0, os.SEEK_END) == 0:
            handle.write(b"\0")
            handle.flush()
        handle.seek(0)
        getattr(msvcrt, "locking")(  # noqa: B009
            handle.fileno(),
            getattr(msvcrt, "LK_NBLCK"),  # noqa: B009
            1,
        )
    except OSError:
        if "handle" in locals():
            handle.close()
        raise TransactionError("IMPORT_LOCKED") from None
    try:
        yield backup_root
    finally:
        handle.seek(0)
        getattr(msvcrt, "locking")(  # noqa: B009
            handle.fileno(),
            getattr(msvcrt, "LK_UNLCK"),  # noqa: B009
            1,
        )
        handle.close()


class ImportTransaction:
    def __init__(
        self,
        factory_root: Path,
        bindings: Path | None,
        backup_root: Path,
        txid: str,
        document: dict[str, Any],
    ) -> None:
        self.factory_root = factory_root.absolute()
        self.bindings = bindings.absolute() if bindings is not None else None
        self.backup_root = backup_root
        self.txid = txid
        self.path = backup_root / f"tx-{txid}.json"
        self.document = document

    @classmethod
    def begin(
        cls,
        factory_root: Path,
        bindings: Path | None,
        backup_root: Path,
        affected: list[tuple[str, str, str]],
    ) -> ImportTransaction:
        if bindings is None:
            raise TransactionError("IMPORT_SNAPSHOT_FAILED")
        txid = uuid.uuid4().hex
        registry = factory_root / "registries" / "SECRET_REGISTRY.yaml"
        items: list[dict[str, Any]] = []
        for role, target in (("registry", registry), ("bindings", bindings)):
            _deny_reparse(target)
            if not target.is_file():
                raise TransactionError("IMPORT_SNAPSHOT_FAILED")
            items.append({"role": role, "existed": True, "original": _fingerprint(target)})
        for name, scope, environment in affected:
            validate_identity(name, scope, environment)
            if scope != PROJECT_SCOPE or environment not in PROJECT_ENVIRONMENTS:
                raise TransactionError("IMPORT_PATH_DENIED")
            target = factory_root / ".local" / "secrets" / (f"{scope}--{environment}--{name}.dpapi")
            _deny_reparse(target)
            existed = os.path.lexists(target)
            if existed and not target.is_file():
                raise TransactionError("IMPORT_SNAPSHOT_FAILED")
            items.append(
                {
                    "role": "secret",
                    "name": name,
                    "scope": scope,
                    "environment": environment,
                    "existed": existed,
                    "original": _fingerprint(target) if existed else None,
                }
            )
        document: dict[str, Any] = {
            "version": 2,
            "txid": txid,
            "factory": str(factory_root.absolute()),
            "bindings": str(bindings.absolute()),
            "phase": "preparing",
            "items": items,
        }
        transaction = cls(factory_root, bindings, backup_root, txid, document)
        journal_created = False
        try:
            if os.path.lexists(transaction.path):
                raise TransactionError("IMPORT_SNAPSHOT_FAILED")
            for item in items:
                target = transaction._target(item)
                _deny_reparse(target)
                for candidate in (_snapshot_path(target, txid), transaction._restore_path(target)):
                    _deny_reparse(candidate)
                    if os.path.lexists(candidate):
                        raise TransactionError("IMPORT_SNAPSHOT_FAILED")
            backup = backup_root / f"SECRET_REGISTRY-{txid}.yaml"
            _deny_reparse(backup)
            if os.path.lexists(backup):
                raise TransactionError("IMPORT_SNAPSHOT_FAILED")
            _atomic_journal(transaction.path, document, create=True)
            journal_created = True
            shutil.copy2(registry, backup)
            for item in items:
                if item["existed"]:
                    target = transaction._target(item)
                    snapshot = _snapshot_path(target, txid)
                    os.link(target, snapshot)
                    if (
                        not os.path.samefile(target, snapshot)
                        or _fingerprint(snapshot) != item["original"]
                    ):
                        raise TransactionError("IMPORT_SNAPSHOT_FAILED")
            transaction._validated_items(require_complete=True)
            document["phase"] = "applying"
            _atomic_journal(transaction.path, document)
            return transaction
        except Exception:
            if journal_created:
                with suppress(Exception):
                    transaction._cleanup()
            raise TransactionError("IMPORT_SNAPSHOT_FAILED") from None

    def _restore_path(self, target: Path) -> Path:
        return target.with_name(f".{target.name}.xyra-{self.txid}.restore")

    def _target(self, item: dict[str, Any]) -> Path:
        role = item["role"]
        if role == "registry":
            return self.factory_root / "registries" / "SECRET_REGISTRY.yaml"
        if role == "bindings" and self.bindings is not None:
            return self.bindings
        if role == "secret":
            name, scope, environment = item["name"], item["scope"], item["environment"]
            validate_identity(name, scope, environment)
            if scope == PROJECT_SCOPE and environment in PROJECT_ENVIRONMENTS:
                return (
                    self.factory_root
                    / ".local"
                    / "secrets"
                    / (f"{scope}--{environment}--{name}.dpapi")
                )
        raise TransactionError("IMPORT_RECOVERY_FAILED")

    def _validated_items(self, *, require_complete: bool = False) -> list[dict[str, Any]]:
        try:
            if (
                not isinstance(self.document, dict)
                or self.document.get("version") != 2
                or self.document.get("txid") != self.txid
                or self.document.get("factory") != str(self.factory_root)
                or self.document.get("bindings")
                != (str(self.bindings) if self.bindings is not None else None)
                or self.document.get("phase") not in _PHASES
            ):
                raise ValueError
            items = cast(list[dict[str, Any]], self.document["items"])
            if not isinstance(items, list) or len(items) < 2:
                raise ValueError
            roles = [item["role"] for item in items]
            if roles[:2] != ["registry", "bindings"] or any(role != "secret" for role in roles[2:]):
                raise ValueError
            secret_keys: set[tuple[str, str, str]] = set()
            for item in items:
                if not isinstance(item, dict) or not isinstance(item.get("existed"), bool):
                    raise ValueError
                expected_fields = {"role", "existed", "original"}
                if item["role"] == "secret":
                    expected_fields |= {"name", "scope", "environment"}
                if set(item) != expected_fields:
                    raise ValueError
                if item["role"] != "secret" and item["existed"] is not True:
                    raise ValueError
                target = self._target(item)
                _deny_reparse(target)
                snapshot = _snapshot_path(target, self.txid)
                _deny_reparse(snapshot)
                restore = self._restore_path(target)
                _deny_reparse(restore)
                original = item["original"]
                if item["existed"]:
                    if (
                        not isinstance(original, dict)
                        or set(original) != {"sha256", "size", "device", "inode"}
                        or not isinstance(original["sha256"], str)
                        or not _HASH.fullmatch(original["sha256"])
                        or any(
                            type(original[field]) is not int or original[field] < 0
                            for field in ("size", "device", "inode")
                        )
                    ):
                        raise ValueError
                    if os.path.lexists(snapshot):
                        if not snapshot.is_file() or _fingerprint(snapshot) != original:
                            raise ValueError
                    elif require_complete:
                        raise ValueError
                elif original is not None or os.path.lexists(snapshot):
                    raise ValueError
                if os.path.lexists(restore) and (
                    self.document["phase"] != "applying"
                    or not item["existed"]
                    or not os.path.lexists(snapshot)
                    or not os.path.samefile(restore, snapshot)
                ):
                    raise ValueError
                if item["role"] == "secret":
                    key = item["name"], item["scope"], item["environment"]
                    if key in secret_keys:
                        raise ValueError
                    secret_keys.add(key)
            return items
        except Exception:
            raise TransactionError("IMPORT_RECOVERY_FAILED") from None

    def _cleanup(self) -> None:
        if self.document.get("phase") == "applying":
            raise TransactionError("IMPORT_RECOVERY_FAILED")
        for item in self._validated_items():
            _snapshot_path(self._target(item), self.txid).unlink(missing_ok=True)
        self.path.unlink(missing_ok=True)

    def commit(self) -> None:
        try:
            self.document["phase"] = "committed"
            _atomic_journal(self.path, self.document)
        except Exception:
            self.document["phase"] = "applying"
            raise TransactionError("IMPORT_JOURNAL_FAILED") from None
        # Committed data remains authoritative; a later import cleans snapshots.
        with suppress(Exception):
            self._cleanup()

    def rollback(self) -> None:
        try:
            items = self._validated_items(require_complete=True)
            if self.document["phase"] != "applying":
                raise ValueError
            for item in items:
                target = self._target(item)
                snapshot = _snapshot_path(target, self.txid)
                _deny_reparse(target)
                if item["existed"]:
                    restore = self._restore_path(target)
                    _deny_reparse(restore)
                    if os.path.lexists(restore):
                        if not os.path.samefile(restore, snapshot):
                            raise OSError
                        restore.unlink()
                    os.link(snapshot, restore)
                    os.replace(restore, target)
                    if not os.path.samefile(target, snapshot):
                        raise OSError
                elif os.path.lexists(target):
                    target.unlink()
            self.document["phase"] = "rolled_back"
            _atomic_journal(self.path, self.document)
        except Exception:
            self.document["phase"] = "applying"
            self.document["recovery_failed"] = True
            with suppress(Exception):
                _atomic_journal(self.path, self.document)
            raise TransactionError("IMPORT_RECOVERY_FAILED") from None
        # Files are restored and the journal says so before cleanup can start.
        with suppress(Exception):
            self._cleanup()

    @classmethod
    def recover(
        cls, factory_root: Path, bindings: Path | None, backup_root: Path, journal_path: Path
    ) -> None:
        try:
            txid = journal_path.stem.removeprefix("tx-")
            if not _TX_ID.fullmatch(txid) or journal_path != backup_root / f"tx-{txid}.json":
                raise ValueError
            _deny_reparse(journal_path)
            document = cast(dict[str, Any], json.loads(journal_path.read_text(encoding="utf-8")))
            expected_bindings = str(bindings.absolute()) if bindings is not None else None
            if document.get("version") != 2 or document.get("factory") != str(
                factory_root.absolute()
            ):
                raise ValueError
            if document.get("bindings") != expected_bindings:
                raise ValueError
            transaction = cls(factory_root, bindings, backup_root, txid, document)
            phase = document.get("phase")
            transaction._validated_items(require_complete=phase == "applying")
            if phase == "applying":
                transaction.rollback()
            elif phase in {"preparing", "committed", "rolled_back"}:
                transaction._cleanup()
            else:
                raise ValueError
        except Exception:
            raise TransactionError("IMPORT_RECOVERY_FAILED") from None


def recover_pending(factory_root: Path, bindings: Path | None, backup_root: Path) -> None:
    _deny_reparse(backup_root)
    for journal in sorted(backup_root.glob("tx-*.json")):
        ImportTransaction.recover(factory_root, bindings, backup_root, journal)
