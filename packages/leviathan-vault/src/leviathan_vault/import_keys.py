"""Import provider credentials through Set-XyraSecret, never a second write path."""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from leviathan_vault.client import (
    PROJECT_ENVIRONMENTS,
    PROJECT_SCOPE,
    VaultError,
    store_reference,
    validate_identity,
)
from leviathan_vault.transaction import (
    ImportTransaction,
    TransactionError,
    _deny_reparse,
    import_lock,
    recover_pending,
)

FIELD_LABELS = {
    "KEY": "API_KEY", "API KEY": "API_KEY", "API_KEY": "API_KEY",
    "X API KEY": "API_KEY", "API TOKEN": "API_KEY",
    "SECRET": "SECRET", "API SECRET": "API_SECRET", "HEADER": "HEADER",
    "TOKEN": "TOKEN", "ACCESS TOKEN": "ACCESS_TOKEN", "CREDENTIAL": "CREDENTIAL",
    "ACCOUNT ID": "ACCOUNT_ID", "CLIENT ID": "CLIENT_ID",
}
LOGIN_RE = re.compile(r"\b(login|password|e-?mail)\b|[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", re.I)
ALIAS_RE = re.compile(r"\bsame\s+([A-Za-z][A-Za-z0-9 ._-]*)\s+key\b", re.I)
NO_KEY_RE = re.compile(r"\b(no key|requires? key|not purchased|web[ -]?form only)\b", re.I)
URL_RE = re.compile(r"^https?://", re.I)
SEPARATOR_RE = re.compile(r"^\s*[=\-_*]{4,}\s*$")
FIELD_RE = re.compile(r"^([A-Za-z][A-Za-z0-9 _/-]{0,39}):\s*(.*)$")
DESIGNATIONS = {
    "DATABENTO": ("DATABENTO", "development"),
    "FRED": ("FRED", "development"),
    "COPERNICUS": ("COPERNICUS", "development"),
    "MASSIVE": ("MASSIVE", "development"),
    "POLYGON": ("MASSIVE", "development"),
    "KALSHI_MARKET_DATA": ("KALSHI_MARKET_DATA", "development"),
    "POLYMARKET_MARKET_DATA": ("POLYMARKET_MARKET_DATA", "development"),
    "IBKR": ("IBKR", "live"),
    "FOREX_COM_MT5": ("FOREX_COM_MT5", "live"),
    "KALSHI": ("KALSHI", "live"),
    "KALSHI_AUTHENTICATED": ("KALSHI", "live"),
    "POLYMARKET": ("POLYMARKET", "live"),
    "POLYMARKET_AUTHENTICATED": ("POLYMARKET", "live"),
}
CANONICAL_FIELDS = {("KALSHI", "HEADER"): "API_KEY"}


class ImportErrorCode(ValueError):  # noqa: N818
    """Fixed code only; parsed values are never included in exceptions."""


@dataclass(frozen=True)
class ParsedCredential:
    provider: str
    name: str
    environment: str
    value: str = field(repr=False)
    classification: str = "secret"


@dataclass(frozen=True)
class ManifestAlias:
    provider: str
    target_provider: str
    target_name: str
    environment: str


@dataclass(frozen=True)
class ImportPlan:
    credentials: tuple[ParsedCredential, ...]
    aliases: tuple[ManifestAlias, ...]
    interactive_login_skipped: tuple[str, ...]
    requires_key: tuple[str, ...]


@dataclass(frozen=True)
class ImportResult:
    imported: int
    would_import: int
    skipped_existing: int
    aliases: int
    interactive_login_skipped: int
    requires_key: int
    dry_run: bool
    bindings_required: bool
    unresolved_mappings: tuple[str, ...]


def _slug(label: str) -> str:
    return re.sub(r"_+", "_", re.sub(r"[^A-Z0-9]+", "_", label.upper())).strip("_")


def _provider(label: str) -> str:
    result = _slug(label)
    if len(result) < 3 or len(result) > 60:
        raise ImportErrorCode("IMPORT_FORMAT_DENIED")
    return result


def _designation(provider: str) -> tuple[str, str]:
    try:
        return DESIGNATIONS[provider]
    except KeyError:
        raise ImportErrorCode("IMPORT_FORMAT_DENIED") from None


def _field(label: str) -> str | None:
    normalized = _slug(label)
    return FIELD_LABELS.get(normalized.replace("_", " "))


def parse_key_text(text: str) -> ImportPlan:
    """Parse the masked-contract format without retaining URL lines as credentials."""
    credentials: list[ParsedCredential] = []
    aliases: list[ManifestAlias] = []
    skipped: list[str] = []
    requires: list[str] = []
    provider: str | None = None
    block: list[str] = []
    section = ""

    def finish() -> None:
        nonlocal provider, block
        if provider is None:
            block = []
            return
        if any(LOGIN_RE.search(line) for line in block if not URL_RE.match(line)):
            skipped.append(provider)
            provider, block = None, []
            return
        alias_lines = [ALIAS_RE.search(line) for line in block]
        aliases_only = any(alias_lines) and all(
            URL_RE.match(line) or ALIAS_RE.search(line) or NO_KEY_RE.search(line)
            for line in block
        )
        if aliases_only:
            for alias in alias_lines:
                if alias:
                    target, environment = _designation(_provider(alias.group(1)))
                    if provider in DESIGNATIONS and _designation(provider)[1] != environment:
                        raise ImportErrorCode("IMPORT_FORMAT_DENIED")
                    aliases.append(ManifestAlias(
                        provider, target, f"{target}_API_KEY", environment
                    ))
            provider, block = None, []
            return
        if all(URL_RE.match(line) or NO_KEY_RE.search(line) for line in block):
            requires.append(provider)
            provider, block = None, []
            return
        canonical_provider, environment = _designation(provider)
        found = 0
        for line in block:
            alias = ALIAS_RE.search(line)
            if alias:
                target, target_environment = _designation(_provider(alias.group(1)))
                if target_environment != environment:
                    raise ImportErrorCode("IMPORT_FORMAT_DENIED")
                aliases.append(ManifestAlias(
                    canonical_provider, target, f"{target}_API_KEY", environment
                ))
                continue
            if URL_RE.match(line) or NO_KEY_RE.search(line):
                continue
            pieces = [piece.strip() for piece in line.split("|")]
            for piece in pieces:
                match = FIELD_RE.match(piece)
                if match:
                    label, value = match.groups()
                    if not value or URL_RE.match(value) or NO_KEY_RE.search(value):
                        continue
                    field_name = _field(label)
                    if field_name is None:
                        raise ImportErrorCode("IMPORT_FORMAT_DENIED")
                elif len(piece) >= 8 and not any(char.isspace() for char in piece):
                    field_name, value = "CREDENTIAL", piece
                else:
                    continue
                field_name = CANONICAL_FIELDS.get((canonical_provider, field_name), field_name)
                name = f"{canonical_provider}_{field_name}"
                try:
                    validate_identity(name, "leviathan-ai", environment)
                except VaultError:
                    raise ImportErrorCode("IMPORT_FORMAT_DENIED") from None
                credentials.append(ParsedCredential(
                    canonical_provider, name, environment, value,
                    ("public-configuration" if field_name in {"ACCOUNT_ID", "CLIENT_ID"}
                     else "secret"),
                ))
                found += 1
        if found == 0 and not any(alias.provider == provider for alias in aliases):
            requires.append(provider)
        provider, block = None, []

    for raw in text.splitlines():
        line = raw.strip()
        if not line or SEPARATOR_RE.fullmatch(line):
            finish()
            continue
        if not line:
            continue
        match = FIELD_RE.match(line)
        if provider is None and match and _field(match.group(1)) is None:
            provider = _provider(match.group(1))
            block = []
            continue
        if provider is None and line == line.upper() and ":" not in line:
            section = line
            continue
        if provider is not None:
            block.append(line)
    finish()
    _ = section
    keys = [(item.name, item.environment) for item in credentials]
    if len(keys) != len(set(keys)):
        raise ImportErrorCode("IMPORT_FORMAT_DENIED")
    return ImportPlan(tuple(credentials), tuple(aliases), tuple(skipped), tuple(requires))


def parse_key_file(source: Path) -> ImportPlan:
    try:
        return parse_key_text(source.read_text(encoding="utf-8-sig"))
    except ImportErrorCode:
        raise
    except Exception:
        raise ImportErrorCode("IMPORT_READ_FAILED") from None


def _entry(item: ParsedCredential, scope: str) -> dict[str, Any]:
    return {
        "store_reference": store_reference(item.name, scope, item.environment),
        "scope": scope,
        "environment": item.environment,
        "purpose": f"Leviathan {item.provider.lower()} provider integration",
        "owner": "local-user",
        "name": item.name,
        "classification": item.classification,
        "inherit_to_projects": False,
        "provider": item.provider.lower().replace("_", "-"),
        "rotation": "ON_PROVIDER_ROTATION" if item.classification == "secret" else "NOT_APPLICABLE",
        "validation": {
            "provider_permissions": "NOT_VERIFIED",
            "checked_at": datetime.now(UTC).isoformat(),
            "provider_authentication": "NOT_TESTED",
            "local_storage": "PENDING_WRITE",
        },
    }


def _atomic_json(path: Path, document: dict[str, Any]) -> None:
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=path.parent,
            prefix=".pending-", suffix=".json", delete=False,
        ) as handle:
            temporary = Path(handle.name)
            json.dump(document, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _preflight_replaceable(path: Path, code: str) -> None:
    """Check known Windows denial without touching the destination itself."""
    first: Path | None = None
    second: Path | None = None
    try:
        if os.name != "nt":
            raise OSError
        _deny_reparse(path)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetFileAttributesW.argtypes = [ctypes.c_wchar_p]
        kernel32.GetFileAttributesW.restype = ctypes.c_uint32
        kernel32.CreateFileW.argtypes = [
            ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
            ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
        ]
        kernel32.CreateFileW.restype = ctypes.c_void_p
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel32.CloseHandle.restype = ctypes.c_int
        attributes = kernel32.GetFileAttributesW(str(path))
        parent_attributes = kernel32.GetFileAttributesW(str(path.parent))
        if (attributes == 0xFFFFFFFF or attributes & 0x1
                or parent_attributes == 0xFFFFFFFF or not parent_attributes & 0x10):
            raise OSError
        share_all = 0x1 | 0x2 | 0x4
        for candidate, access, flags in (
            (path, 0x00010000, 0),  # DELETE on the existing destination
            (path.parent, 0x0002 | 0x0040, 0x02000000),  # ADD_FILE, DELETE_CHILD
        ):
            handle = kernel32.CreateFileW(
                str(candidate), access, share_all, None, 3, flags, None,
            )
            if handle in (None, ctypes.c_void_p(-1).value):
                raise OSError
            kernel32.CloseHandle(handle)
        with tempfile.NamedTemporaryFile(
            "wb", dir=path.parent, prefix=".xyra-replace-probe-", delete=False,
        ) as handle:
            first = Path(handle.name)
        with tempfile.NamedTemporaryFile(
            "wb", dir=path.parent, prefix=".xyra-replace-probe-", delete=False,
        ) as handle:
            second = Path(handle.name)
        os.replace(first, second)
    except Exception:
        raise ImportErrorCode(code) from None
    finally:
        cleanup_failed = False
        for probe_path in (first, second):
            if probe_path is not None:
                try:
                    probe_path.unlink(missing_ok=True)
                except OSError:
                    cleanup_failed = True
        if cleanup_failed:
            raise ImportErrorCode(code)


_BROKER_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
try {
    Import-Module (Join-Path $env:XYRA_FACTORY_ROOT 'tools/secrets/Xyra.Secrets.psm1') -Force
    [Console]::InputEncoding = New-Object Text.UTF8Encoding($false)
    $secure = New-Object Security.SecureString
    try {
        while (($code = [Console]::In.Read()) -ge 0) { $secure.AppendChar([char]$code) }
        $secure.MakeReadOnly()
        $parameters = @{
            Name = $env:XYRA_SECRET_NAME
            Scope = $env:XYRA_SECRET_SCOPE
            Environment = $env:XYRA_SECRET_ENVIRONMENT
            Value = $secure
        }
        if ($env:XYRA_SECRET_REPLACE -eq '1') { $parameters.Replace = $true }
        Set-XyraSecret @parameters
    } finally { $secure.Dispose() }
} catch { exit 1 }
"""


def _broker_write(factory_root: Path, item: ParsedCredential, scope: str, replace: bool) -> None:
    executable = shutil.which("powershell.exe")
    if executable is None:
        raise ImportErrorCode("SECRET_WRITE_FAILED")
    env = os.environ.copy()
    env.update({
        "XYRA_FACTORY_ROOT": str(factory_root), "XYRA_SECRET_NAME": item.name,
        "XYRA_SECRET_SCOPE": scope, "XYRA_SECRET_ENVIRONMENT": item.environment,
        "XYRA_SECRET_REPLACE": "1" if replace else "0",
    })
    try:
        result = subprocess.run(
            [executable, "-NoProfile", "-NonInteractive", "-Command", _BROKER_SCRIPT],
            input=item.value, text=True, encoding="utf-8", capture_output=True,
            env=env, timeout=60, check=False,
        )
        if result.returncode:
            raise ImportErrorCode("SECRET_WRITE_FAILED")
    except ImportErrorCode:
        raise
    except Exception:
        raise ImportErrorCode("SECRET_WRITE_FAILED") from None


def _binding_key(item: dict[str, Any], *, project_only: bool = False) -> tuple[str, str, str]:
    try:
        name, scope, environment = item["name"], item["scope"], item["environment"]
        validate_identity(name, scope, environment)
        if project_only and (scope != PROJECT_SCOPE or environment not in PROJECT_ENVIRONMENTS):
            raise ValueError
        if project_only and not name.startswith(f"{_slug(item['provider'])}_"):
            raise ValueError
        return name, scope, environment
    except Exception:
        raise ImportErrorCode("IMPORT_BINDINGS_FAILED") from None


def _prepare_bindings(
    path: Path, plan: ImportPlan, scope: str,
    selected: list[tuple[ParsedCredential, bool]],
    valid_targets: set[tuple[str, str, str]],
) -> dict[str, Any]:
    try:
        document = cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8-sig")))
        bindings: list[dict[str, Any]] = document["bindings"]
        aliases: list[dict[str, Any]] = document["aliases"]
        if not isinstance(bindings, list) or not isinstance(aliases, list):
            raise TypeError
        binding_keys = {_binding_key(existing_binding, project_only=True)
                        for existing_binding in bindings}
        if len(binding_keys) != len(bindings):
            raise ValueError
        edges: dict[tuple[str, str, str], tuple[str, str, str]] = {}
        for existing_alias in aliases:
            key = _binding_key(existing_alias, project_only=True)
            target = _binding_key(existing_alias["target"], project_only=True)
            source_designation = _slug(existing_alias["provider"])
            if (source_designation in DESIGNATIONS
                    and _designation(source_designation)[1] != key[2]):
                raise ValueError
            if key[1:] != target[1:]:
                raise ValueError
            if key in edges or key in binding_keys:
                raise ValueError
            edges[key] = target
        pending_bindings: list[dict[str, Any]] = []
        selected_keys = {(credential.name, scope, credential.environment)
                         for credential, _ in selected}
        plan_keys = {(credential.name, scope, credential.environment)
                     for credential in plan.credentials}
        touched_providers = {
            (credential.provider.lower().replace("_", "-"), credential.environment)
            for credential in plan.credentials
        }
        for existing_binding in bindings:
            if (existing_binding.get("state") == "pending_import"
                    and (existing_binding.get("provider"),
                         existing_binding.get("environment")) in touched_providers
                    and _binding_key(existing_binding, project_only=True) not in plan_keys):
                raise ValueError
        for existing_binding in bindings:
            if (_binding_key(existing_binding) in selected_keys
                    and existing_binding.get("state") in {
                        "pending_import", "registry_entry_present_unverified"
                    }):
                existing_binding["state"] = "locally_stored"
        for credential in plan.credentials:
            key = credential.name, scope, credential.environment
            if key not in binding_keys:
                pending_bindings.append({
                    "provider": credential.provider.lower().replace("_", "-"),
                    "name": credential.name, "scope": scope,
                    "environment": credential.environment,
                    "state": ("locally_stored" if key in selected_keys
                              else "registry_entry_present_unverified"),
                })
                binding_keys.add(key)
        pending_aliases: list[dict[str, Any]] = []
        for alias in plan.aliases:
            canonical_target, target_environment = _designation(alias.target_provider)
            if (canonical_target != alias.target_provider
                    or target_environment != alias.environment
                    or (alias.provider in DESIGNATIONS
                        and _designation(alias.provider)[1] != alias.environment)
                    or alias.target_name != f"{canonical_target}_API_KEY"):
                raise ValueError
            key = f"{alias.provider}_API_KEY", scope, alias.environment
            target = alias.target_name, scope, alias.environment
            validate_identity(*key)
            validate_identity(*target)
            if alias.environment not in PROJECT_ENVIRONMENTS:
                raise ValueError
            if key in binding_keys:
                raise ValueError
            if key in edges:
                if edges[key] != target:
                    raise ValueError
                continue
            edges[key] = target
            pending_aliases.append({
                "provider": alias.provider.lower().replace("_", "-"),
                "name": key[0], "scope": scope, "environment": alias.environment,
                "target": {
                    "provider": alias.target_provider.lower().replace("_", "-"),
                    "name": target[0], "scope": scope, "environment": alias.environment,
                },
            })
        for source in edges:
            seen: set[tuple[str, str, str]] = set()
            cursor = source
            while cursor not in binding_keys:
                if cursor in seen or cursor not in edges:
                    raise ValueError
                seen.add(cursor)
                cursor = edges[cursor]
            if cursor not in valid_targets:
                raise ValueError
        bindings.extend(pending_bindings)
        aliases.extend(pending_aliases)
        return document
    except Exception:
        raise ImportErrorCode("IMPORT_BINDINGS_FAILED") from None


def _import_plan_locked(factory_root: Path, plan: ImportPlan, scope: str, *, dry_run: bool,
                        replace: bool, bindings: Path | None,
                        backup_root: Path | None) -> ImportResult:
    if scope != PROJECT_SCOPE:
        raise VaultError("SECRET_SCOPE_DENIED")
    validate_identity("DUMMY", scope, "development")
    registry_path = factory_root / "registries" / "SECRET_REGISTRY.yaml"
    _deny_reparse(registry_path)
    try:
        registry = json.loads(registry_path.read_text(encoding="utf-8-sig"))
        entries: list[dict[str, Any]] = registry["entries"]
        if not isinstance(entries, list) or not all(isinstance(entry, dict) for entry in entries):
            raise TypeError
    except Exception:
        raise ImportErrorCode("IMPORT_REGISTRY_FAILED") from None
    selected: list[tuple[ParsedCredential, bool]] = []
    skipped = 0
    for item in plan.credentials:
        validate_identity(item.name, scope, item.environment)
        canonical_provider, expected_environment = _designation(item.provider)
        if (item.environment not in PROJECT_ENVIRONMENTS
                or item.provider != canonical_provider
                or item.environment != expected_environment
                or not item.name.startswith(f"{canonical_provider}_")):
            raise ImportErrorCode("IMPORT_FORMAT_DENIED")
        field_name = item.name.removeprefix(f"{canonical_provider}_")
        if field_name not in set(FIELD_LABELS.values()) or (
            (canonical_provider, field_name) in CANONICAL_FIELDS
        ):
            raise ImportErrorCode("IMPORT_FORMAT_DENIED")
        classification = (
            "public-configuration" if field_name in {"ACCOUNT_ID", "CLIENT_ID"} else "secret"
        )
        if item.classification != classification:
            raise ImportErrorCode("IMPORT_FORMAT_DENIED")
        matches = [entry for entry in entries if entry.get("name") == item.name
                   and entry.get("scope") == scope
                   and entry.get("environment") == item.environment]
        if len(matches) > 1:
            raise ImportErrorCode("IMPORT_REGISTRY_FAILED")
        if matches and not replace:
            skipped += 1
        else:
            selected.append((item, bool(matches)))
    if (plan.credentials or plan.aliases) and bindings is None and not dry_run:
        raise ImportErrorCode("IMPORT_BINDINGS_REQUIRED")
    registered_keys: set[tuple[str, str, str]] = set()
    valid_targets: set[tuple[str, str, str]] = set()
    for entry in entries:
        try:
            key = _binding_key(entry)
            if key in registered_keys:
                raise ImportErrorCode("IMPORT_REGISTRY_FAILED")
            registered_keys.add(key)
            if (key[1] == PROJECT_SCOPE and key[2] in PROJECT_ENVIRONMENTS
                    and entry.get("inherit_to_projects") is False
                    and entry.get("store_reference") == store_reference(*key)):
                valid_targets.add(key)
        except ImportErrorCode:
            raise ImportErrorCode("IMPORT_REGISTRY_FAILED") from None
    valid_targets.update((item.name, scope, item.environment) for item in plan.credentials
                         if (item.name, scope, item.environment) not in registered_keys)
    bindings_document = (
        _prepare_bindings(bindings, plan, scope, selected, valid_targets)
        if bindings is not None else None
    )
    if bindings is not None:
        try:
            old_bindings = json.loads(bindings.read_text(encoding="utf-8-sig"))
        except Exception:
            raise ImportErrorCode("IMPORT_BINDINGS_FAILED") from None
    else:
        old_bindings = None
    bindings_changed = bindings_document != old_bindings
    if not dry_run and (selected or bindings_changed):
        if backup_root is None:
            raise ImportErrorCode("IMPORT_LOCKED")
        _preflight_replaceable(registry_path, "IMPORT_REGISTRY_FAILED")
        if bindings is not None:
            _preflight_replaceable(bindings, "IMPORT_BINDINGS_FAILED")
        transaction = ImportTransaction.begin(
            factory_root, bindings, backup_root,
            [(item.name, scope, item.environment) for item, _ in selected],
        )
        error: BaseException | None = None
        try:
            for item, exists in selected:
                if not exists:
                    entries.append(_entry(item, scope))
                    try:
                        _atomic_json(registry_path, registry)
                    except Exception:
                        raise ImportErrorCode("IMPORT_REGISTRY_FAILED") from None
                _broker_write(factory_root, item, scope, exists)
                if not exists:
                    entries[-1]["validation"]["local_storage"] = "ENCRYPTED_ROUNDTRIP_VERIFIED"
                    try:
                        _atomic_json(registry_path, registry)
                    except Exception:
                        raise ImportErrorCode("IMPORT_REGISTRY_FAILED") from None
            if bindings is not None and bindings_document is not None:
                try:
                    _atomic_json(bindings, bindings_document)
                except Exception:
                    raise ImportErrorCode("IMPORT_BINDINGS_FAILED") from None
            transaction.commit()
        except BaseException as caught:
            error = caught
        if error is not None:
            try:
                transaction.rollback()
            except TransactionError:
                raise ImportErrorCode("IMPORT_RECOVERY_FAILED") from None
            if isinstance(error, (ImportErrorCode, VaultError, TransactionError)):
                raise error
            raise ImportErrorCode("IMPORT_TRANSACTION_FAILED") from None
    unresolved = tuple(sorted(
        {item.name for item in plan.credentials}
        | {f"{item.provider}_API_KEY" for item in plan.aliases}
    )) if bindings is None else ()
    return ImportResult(0 if dry_run else len(selected), len(selected) if dry_run else 0,
                        skipped, len(plan.aliases), len(plan.interactive_login_skipped),
                        len(plan.requires_key), dry_run, bool(unresolved), unresolved)


def import_plan(factory_root: Path, plan: ImportPlan, scope: str, *, dry_run: bool = False,
                replace: bool = False, bindings: Path | None = None) -> ImportResult:
    if scope != PROJECT_SCOPE:
        raise VaultError("SECRET_SCOPE_DENIED")
    if (plan.credentials or plan.aliases) and bindings is None and not dry_run:
        raise ImportErrorCode("IMPORT_BINDINGS_REQUIRED")
    if bindings is not None:
        _deny_reparse(bindings)
        if not bindings.is_file():
            raise ImportErrorCode("IMPORT_BINDINGS_FAILED")
    if dry_run:
        return _import_plan_locked(factory_root, plan, scope, dry_run=True, replace=replace,
                                   bindings=bindings, backup_root=None)
    with import_lock(factory_root) as backup_root:
        # A pending recovery may replace protected targets, so check before it runs.
        _preflight_replaceable(
            factory_root / "registries" / "SECRET_REGISTRY.yaml", "IMPORT_REGISTRY_FAILED"
        )
        if bindings is not None:
            _preflight_replaceable(bindings, "IMPORT_BINDINGS_FAILED")
        recover_pending(factory_root, bindings, backup_root)
        return _import_plan_locked(factory_root, plan, scope, dry_run=False, replace=replace,
                                   bindings=bindings, backup_root=backup_root)


def _default_factory_root() -> Path:
    explicit = os.environ.get("XYRA_FACTORY_ROOT")
    if explicit:
        return Path(explicit)
    for parent in Path.cwd().parents:
        candidate = parent / "factory" / "registries" / "SECRET_REGISTRY.yaml"
        if candidate.is_file():
            return parent / "factory"
    raise ImportErrorCode("IMPORT_FACTORY_ROOT_REQUIRED")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Import provider keys into the XYRA secret registry"
    )
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--scope", required=True)
    parser.add_argument("--factory-root", type=Path)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--replace", action="store_true")
    parser.add_argument("--bindings", type=Path)
    args = parser.parse_args(argv)
    try:
        plan = parse_key_file(args.source)
        result = import_plan(args.factory_root or _default_factory_root(), plan, args.scope,
                             dry_run=args.dry_run, replace=args.replace,
                             bindings=args.bindings)
        print(json.dumps(result.__dict__, sort_keys=True))
        return 0
    except (ImportErrorCode, VaultError, TransactionError) as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
