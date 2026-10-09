"""Explicit, audited upgrade of one reviewed pre-HALT desktop risk-lock pin."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import shutil
import stat
import tempfile
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

from platform_paths import data_root as resolve_data_root
from profile_provision import _write_marker, provision_profile

from leviathan_core.risk.halt_store import (
    LEGACY_UNKNOWN_REASON,
    HaltStore,
    ProfileClassification,
)

OLD_LOCK_SHA256 = "46a03497679f8a59c82229ba28cef4bf56b7c1d7c30ae936016f876c9eaf3c51"
NEW_LOCK_SHA256 = "cfe9cf34554145327145de881ae0ac38642176a91a481c06fe830da10aa9fb87"
ALLOWED_MIGRATIONS = {OLD_LOCK_SHA256: NEW_LOCK_SHA256}
CONFIRMATION = f"MIGRATE:{OLD_LOCK_SHA256}:{NEW_LOCK_SHA256}"
JOURNAL_NAME = "risk-lock.pending.json"
AUDIT_NAME = "risk-lock-migration.audit.jsonl"


class RiskLockMigrationError(RuntimeError):
    """Redacted operator-facing refusal."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _checked(path: Path, *, directory: bool) -> None:
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise RiskLockMigrationError("MIGRATION_PATH_UNAVAILABLE") from exc
    if stat.S_ISLNK(info.st_mode) or (
        os.name == "nt" and info.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT
    ):
        raise RiskLockMigrationError("MIGRATION_REPARSE_POINT")
    if directory and not stat.S_ISDIR(info.st_mode):
        raise RiskLockMigrationError("MIGRATION_PATH_INVALID")
    if not directory and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
        raise RiskLockMigrationError("MIGRATION_PATH_INVALID")


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _atomic_bytes(path: Path, payload: bytes, *, readonly: bool = False) -> None:
    descriptor, name = tempfile.mkstemp(prefix=".migration-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        if path.exists():
            path.chmod(stat.S_IREAD | stat.S_IWRITE)
        os.replace(temporary, path)
        if readonly:
            path.chmod(stat.S_IREAD)
    finally:
        temporary.unlink(missing_ok=True)


def _audit(path: Path, event: dict[str, object]) -> None:
    if path.exists():
        _checked(path, directory=False)
    record = (json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n").encode()
    descriptor = os.open(path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
    try:
        os.write(descriptor, record)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _events(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    _checked(path, directory=False)
    try:
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    except (OSError, ValueError) as exc:
        raise RiskLockMigrationError("MIGRATION_AUDIT_INVALID") from exc


def _entry_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for directory, label in ((root, b"root/"), (root / "data", b"data/")):
        _checked(directory, directory=True)
        names: list[tuple[int, ...]] = []
        for entry in directory.iterdir():
            _checked(entry, directory=entry.is_dir())
            encoded = entry.name.encode("utf-16-le")
            names.append(
                tuple(
                    int.from_bytes(encoded[offset : offset + 2], "little")
                    for offset in range(0, len(encoded), 2)
                )
            )
        for name in sorted(names):
            digest.update(label)
            for unit in name:
                digest.update(unit.to_bytes(2, "little"))
            digest.update(b"\x00\x00")
    return digest.hexdigest()


@contextlib.contextmanager
def _instance_lock(root: Path) -> Iterator[None]:
    path = root / "desktop-instance.lock"
    if path.exists():
        _checked(path, directory=False)
    with path.open("a+b") as handle:
        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            handle.write(b"0")
            handle.flush()
            os.fsync(handle.fileno())
        handle.seek(0)
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise RiskLockMigrationError("MIGRATION_PROFILE_BUSY") from exc
        try:
            yield
        finally:
            handle.seek(0)
            if os.name == "nt":
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _valid_migrated_profile(root: Path, *, require_halt: bool) -> bool:
    marker = root / "data" / "profile.json"
    path = root / "data" / "halt-state.sqlite3"
    if not marker.is_file() or not path.is_file():
        return False
    try:
        recorded = json.loads(marker.read_text(encoding="utf-8"))
        if recorded.get("classification_used") != "PRE_HALT_INSTALL":
            return False
        store = HaltStore(path, path.parent)
        try:
            halts = store.load()
            return not require_halt or LEGACY_UNKNOWN_REASON in halts
        finally:
            store.close()
    except (OSError, ValueError, RuntimeError):
        return False


def _complete_interrupted_legacy_provision(
    root: Path, journal: dict[str, object], journal_path: Path, audit_path: Path
) -> bool:
    """Commit a verified legacy halt without deleting authoritative halt state."""
    store_path = root / "data" / "halt-state.sqlite3"
    marker_path = root / "data" / "profile.json"
    target = root / "infra" / "risk" / "risk_governance.lock.yaml"
    database = root / "data" / "leviathan.db"
    if not store_path.exists():
        if marker_path.exists() or any(
            entry.name.lower().startswith("halt-state.sqlite3")
            for entry in store_path.parent.iterdir()
        ):
            raise RiskLockMigrationError("MIGRATION_HALT_STATE_INCOMPLETE")
        return False
    _checked(store_path, directory=False)
    if _sha256(target) != journal["new_lock_sha256"] or _sha256(database) != journal["db_sha256"]:
        raise RiskLockMigrationError("MIGRATION_TARGET_CHANGED")
    try:
        store = HaltStore(store_path, store_path.parent)
        try:
            if LEGACY_UNKNOWN_REASON not in store.load():
                raise RiskLockMigrationError("MIGRATION_LEGACY_HALT_MISSING")
        finally:
            store.close()
    except (OSError, ValueError, RuntimeError) as exc:
        raise RiskLockMigrationError("MIGRATION_HALT_STORE_INVALID") from exc
    if marker_path.exists():
        _checked(marker_path, directory=False)
        if not _valid_migrated_profile(root, require_halt=True):
            raise RiskLockMigrationError("MIGRATION_MARKER_INVALID")
    else:
        _write_marker(marker_path, ProfileClassification.PRE_HALT_INSTALL)
    _audit(
        audit_path,
        {
            "event": "COMMIT",
            "id": journal["id"],
            "at_utc": _now(),
            "new_lock_sha256": journal["new_lock_sha256"],
            "db_sha256": journal["db_sha256"],
            "halt_reason": LEGACY_UNKNOWN_REASON,
            "recovered_after_crash": True,
        },
    )
    journal_path.unlink()
    return True


def _rollback(root: Path, journal: dict[str, object], journal_path: Path, audit_path: Path) -> None:
    migration_id = journal["id"]
    backup_dir = root / "migrations" / str(journal["backup"])
    if backup_dir.parent != journal_path.parent:
        raise RiskLockMigrationError("MIGRATION_BACKUP_INVALID")
    _checked(backup_dir, directory=True)
    lock_backup = backup_dir / "risk_governance.lock.yaml"
    db_backup = backup_dir / "leviathan.db"
    for path, expected in (
        (lock_backup, journal["old_lock_sha256"]),
        (db_backup, journal["db_sha256"]),
    ):
        _checked(path, directory=False)
        if _sha256(path) != expected:
            raise RiskLockMigrationError("MIGRATION_BACKUP_INVALID")
    target_lock = root / "infra" / "risk" / "risk_governance.lock.yaml"
    target_db = root / "data" / "leviathan.db"
    if target_lock.exists() and _sha256(target_lock) not in (
        journal["old_lock_sha256"],
        journal["new_lock_sha256"],
    ):
        raise RiskLockMigrationError("MIGRATION_TARGET_CHANGED")
    _atomic_bytes(target_lock, lock_backup.read_bytes(), readonly=True)
    if _sha256(target_db) != journal["db_sha256"]:
        _atomic_bytes(target_db, db_backup.read_bytes())
    if (
        _sha256(target_lock) != journal["old_lock_sha256"]
        or _sha256(target_db) != journal["db_sha256"]
    ):
        raise RiskLockMigrationError("MIGRATION_ROLLBACK_FAILED")
    _audit(
        audit_path,
        {
            "event": "ROLLBACK",
            "id": migration_id,
            "at_utc": _now(),
            "lock_sha256": journal["old_lock_sha256"],
            "db_sha256": journal["db_sha256"],
        },
    )
    journal_path.unlink()


def _resume(root: Path, journal_path: Path, audit_path: Path) -> bool:
    if not journal_path.exists():
        return False
    _checked(journal_path, directory=False)
    try:
        journal = json.loads(journal_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RiskLockMigrationError("MIGRATION_JOURNAL_INVALID") from exc
    if (
        not isinstance(journal, dict)
        or set(journal) != {"id", "backup", "old_lock_sha256", "new_lock_sha256", "db_sha256"}
        or not isinstance(journal["backup"], str)
        or "/" in journal["backup"]
        or "\\" in journal["backup"]
        or journal["backup"] in ("", ".", "..")
        or journal["old_lock_sha256"] != OLD_LOCK_SHA256
        or journal["new_lock_sha256"] != NEW_LOCK_SHA256
    ):
        raise RiskLockMigrationError("MIGRATION_JOURNAL_INVALID")
    target = root / "infra" / "risk" / "risk_governance.lock.yaml"
    backup_dir = root / "migrations" / journal["backup"]
    _checked(backup_dir, directory=True)
    for name, expected in (
        ("risk_governance.lock.yaml", journal["old_lock_sha256"]),
        ("leviathan.db", journal["db_sha256"]),
    ):
        backed_up = backup_dir / name
        _checked(backed_up, directory=False)
        if _sha256(backed_up) != expected:
            raise RiskLockMigrationError("MIGRATION_BACKUP_INVALID")
    committed = any(
        event.get("event") == "COMMIT" and event.get("id") == journal["id"]
        for event in _events(audit_path)
    )
    if (
        committed
        and _sha256(target) == NEW_LOCK_SHA256
        and _sha256(root / "data" / "leviathan.db") == journal["db_sha256"]
        and _valid_migrated_profile(root, require_halt=False)
    ):
        journal_path.unlink()
        return True
    if _complete_interrupted_legacy_provision(root, journal, journal_path, audit_path):
        return True
    _rollback(root, journal, journal_path, audit_path)
    return False


def ensure_no_pending_migration(root: Path) -> None:
    if (root / "migrations" / JOURNAL_NAME).exists():
        raise RiskLockMigrationError("RISK_LOCK_MIGRATION_PENDING")


def migrate_profile(root: Path, bundled_lock: Path, expected_hash: str, confirmation: str) -> str:
    """Run only for an operator's exact-hash CLI confirmation."""
    if confirmation != CONFIRMATION:
        raise RiskLockMigrationError("MIGRATION_CONFIRMATION_REQUIRED")
    if expected_hash != NEW_LOCK_SHA256 or _sha256(bundled_lock) != expected_hash:
        raise RiskLockMigrationError("MIGRATION_BUNDLE_PIN_UNEXPECTED")
    _checked(root, directory=True)
    _checked(root / "data", directory=True)
    _checked(root / "infra", directory=True)
    _checked(root / "infra" / "risk", directory=True)
    digest = _entry_digest(root)
    migrations = root / "migrations"
    migrations.mkdir(exist_ok=True)
    _checked(migrations, directory=True)
    journal_path = migrations / JOURNAL_NAME
    audit_path = migrations / AUDIT_NAME
    target = root / "infra" / "risk" / "risk_governance.lock.yaml"
    db = root / "data" / "leviathan.db"
    with _instance_lock(root):
        if _resume(root, journal_path, audit_path):
            return "ALREADY_MIGRATED"
        _checked(target, directory=False)
        _checked(db, directory=False)
        if any((root / "data" / f"leviathan.db{suffix}").exists() for suffix in ("-wal", "-shm")):
            raise RiskLockMigrationError("MIGRATION_DB_NOT_QUIESCENT")
        old_hash = _sha256(target)
        if old_hash == expected_hash and _valid_migrated_profile(root, require_halt=False):
            return "ALREADY_MIGRATED"
        if ALLOWED_MIGRATIONS.get(old_hash) != expected_hash:
            raise RiskLockMigrationError("MIGRATION_OLD_PIN_UNLISTED")
        if (root / "data" / "profile.json").exists() or any(
            entry.name.lower().startswith("halt-state.sqlite3")
            for entry in (root / "data").iterdir()
        ):
            raise RiskLockMigrationError("MIGRATION_HALT_STATE_PREEXISTS")
        db_hash = _sha256(db)
        migration_id = uuid.uuid4().hex
        backup_name = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ") + "-" + migration_id
        backup = migrations / backup_name
        backup.mkdir()
        lock_backup = backup / "risk_governance.lock.yaml"
        db_backup = backup / "leviathan.db"
        shutil.copyfile(target, lock_backup)
        shutil.copyfile(db, db_backup)
        if _sha256(lock_backup) != old_hash or _sha256(db_backup) != db_hash:
            raise RiskLockMigrationError("MIGRATION_BACKUP_FAILED")
        lock_backup.chmod(stat.S_IREAD)
        db_backup.chmod(stat.S_IREAD)
        backup.chmod(stat.S_IREAD | stat.S_IEXEC)
        journal = {
            "id": migration_id,
            "backup": backup_name,
            "old_lock_sha256": old_hash,
            "new_lock_sha256": expected_hash,
            "db_sha256": db_hash,
        }
        _audit(
            audit_path,
            {
                "event": "BEGIN",
                "id": migration_id,
                "at_utc": _now(),
                "old_lock_sha256": old_hash,
                "new_lock_sha256": expected_hash,
                "db_sha256": db_hash,
                "backup": backup_name,
                "backup_lock_sha256": _sha256(lock_backup),
                "backup_db_sha256": _sha256(db_backup),
            },
        )
        _atomic_bytes(journal_path, json.dumps(journal, sort_keys=True).encode())
        try:
            _atomic_bytes(target, bundled_lock.read_bytes(), readonly=True)
            if _sha256(target) != expected_hash:
                raise RiskLockMigrationError("MIGRATION_NEW_PIN_FAILED")
            provision_profile(root, preexisted=True, entry_digest=digest)
            if not _valid_migrated_profile(root, require_halt=True):
                raise RiskLockMigrationError("MIGRATION_LEGACY_HALT_MISSING")
            _audit(
                audit_path,
                {
                    "event": "COMMIT",
                    "id": migration_id,
                    "at_utc": _now(),
                    "new_lock_sha256": expected_hash,
                    "db_sha256": _sha256(db),
                    "halt_reason": LEGACY_UNKNOWN_REASON,
                },
            )
            journal_path.unlink()
        except Exception:
            _rollback(root, journal, journal_path, audit_path)
            raise
        return "MIGRATED_HALTED"


def run_cli(argv: list[str], bundled_lock: Path, expected_hash: str) -> int:
    parser = argparse.ArgumentParser(prog="leviathan-desktop migrate-risk-lock")
    parser.add_argument("--confirm", required=True, help="MIGRATE:<old SHA-256>:<new SHA-256>")
    args = parser.parse_args(argv)
    try:
        root = resolve_data_root()
    except RuntimeError:
        if os.name == "nt":
            raise RiskLockMigrationError("LOCALAPPDATA_REQUIRED") from None
        raise RiskLockMigrationError("DATA_ROOT_REQUIRED") from None
    outcome = migrate_profile(root, bundled_lock, expected_hash, args.confirm)
    print(f"RISK_LOCK_MIGRATION {outcome}", flush=True)
    return 0
