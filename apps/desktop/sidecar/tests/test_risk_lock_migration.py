"""An isolated synthetic v1 profile exercises the explicit lock upgrade."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import stat
import sys
from pathlib import Path

import pytest

from leviathan_core.risk.halt import HaltAuthority
from leviathan_core.risk.halt_store import LEGACY_UNKNOWN_REASON, HaltStore

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "generated"))
import leviathan_desktop
import profile_provision
import risk_lock_migration as migration

REPO = Path(__file__).resolve().parents[4]
CURRENT_LOCK = REPO / "infra" / "risk" / "risk_governance.lock.yaml"
OLD_FIXTURE = Path(__file__).parent / "fixtures" / "risk_governance_v1.lock.yaml"
SYNTHETIC_REF = "vault://leviathan-ai/synthetic-test-ref"
FORBIDDEN_SECRET = "sk-synthetic-plaintext-must-never-appear"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def v1_profile(tmp_path: Path) -> Path:
    root = tmp_path / "LOCALAPPDATA" / "LeviathanAI"
    (root / "data").mkdir(parents=True)
    (root / "infra" / "risk").mkdir(parents=True)
    target = root / "infra" / "risk" / "risk_governance.lock.yaml"
    target.write_bytes(OLD_FIXTURE.read_bytes())
    target.chmod(stat.S_IREAD)
    database = root / "data" / "leviathan.db"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE synthetic_v1_credentials (reference TEXT NOT NULL)")
        connection.execute("INSERT INTO synthetic_v1_credentials VALUES (?)", (SYNTHETIC_REF,))
    assert digest(OLD_FIXTURE) == migration.OLD_LOCK_SHA256
    assert digest(CURRENT_LOCK) == migration.NEW_LOCK_SHA256
    assert FORBIDDEN_SECRET.encode() not in target.read_bytes() + database.read_bytes()
    return root


def test_explicit_upgrade_backs_up_and_audits_then_starts_halted(tmp_path: Path) -> None:
    root = v1_profile(tmp_path)
    target = root / "infra" / "risk" / "risk_governance.lock.yaml"
    database = root / "data" / "leviathan.db"
    before_db = digest(database)
    outcome = migration.migrate_profile(
        root, CURRENT_LOCK, migration.NEW_LOCK_SHA256, migration.CONFIRMATION
    )
    assert outcome == "MIGRATED_HALTED"
    assert digest(target) == migration.NEW_LOCK_SHA256
    assert digest(database) == before_db
    assert not (root / "migrations" / migration.JOURNAL_NAME).exists()
    marker = json.loads((root / "data" / "profile.json").read_text(encoding="utf-8"))
    assert marker["classification_used"] == "PRE_HALT_INSTALL"
    store_path = root / "data" / "halt-state.sqlite3"
    store = HaltStore(store_path, store_path.parent)
    authority = HaltAuthority(store)
    assert authority.halted
    assert authority.active == (LEGACY_UNKNOWN_REASON,)
    assert authority.lift_committed(LEGACY_UNKNOWN_REASON)
    authority.close()
    reopened = HaltStore(store_path, store_path.parent)
    assert HaltAuthority(reopened).halted is False
    reopened.close()
    assert (
        migration.migrate_profile(
            root, CURRENT_LOCK, migration.NEW_LOCK_SHA256, migration.CONFIRMATION
        )
        == "ALREADY_MIGRATED"
    )
    audit = root / "migrations" / migration.AUDIT_NAME
    records = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines()]
    assert [record["event"] for record in records] == ["BEGIN", "COMMIT"]
    assert records[0]["old_lock_sha256"] == migration.OLD_LOCK_SHA256
    assert records[0]["new_lock_sha256"] == migration.NEW_LOCK_SHA256
    assert records[0]["db_sha256"] == before_db
    backup = root / "migrations" / records[0]["backup"]
    backed_lock = backup / "risk_governance.lock.yaml"
    backed_db = backup / "leviathan.db"
    assert digest(backed_lock) == migration.OLD_LOCK_SHA256
    assert digest(backed_db) == before_db
    assert backed_lock.stat().st_mode & stat.S_IWRITE == 0
    assert backed_db.stat().st_mode & stat.S_IWRITE == 0
    assert backup.stat().st_mode & stat.S_IWRITE == 0
    assert SYNTHETIC_REF.encode() in backed_db.read_bytes()
    # The fixture uses vault references only; migration adds no secret value to
    # either the backup or the append-only hash/event audit.
    assert FORBIDDEN_SECRET.encode() not in backed_lock.read_bytes() + backed_db.read_bytes()
    assert SYNTHETIC_REF not in audit.read_text(encoding="utf-8")
    assert FORBIDDEN_SECRET not in audit.read_text(encoding="utf-8")


def test_confirmation_and_unlisted_lock_are_refused_without_target_change(tmp_path: Path) -> None:
    root = v1_profile(tmp_path)
    target = root / "infra" / "risk" / "risk_governance.lock.yaml"
    with pytest.raises(migration.RiskLockMigrationError, match="CONFIRMATION_REQUIRED"):
        migration.migrate_profile(root, CURRENT_LOCK, migration.NEW_LOCK_SHA256, "")
    assert digest(target) == migration.OLD_LOCK_SHA256
    target.chmod(stat.S_IREAD | stat.S_IWRITE)
    target.write_bytes(b"unlisted synthetic local policy")
    unknown_hash = digest(target)
    with pytest.raises(migration.RiskLockMigrationError, match="OLD_PIN_UNLISTED"):
        migration.migrate_profile(
            root, CURRENT_LOCK, migration.NEW_LOCK_SHA256, migration.CONFIRMATION
        )
    assert digest(target) == unknown_hash
    assert not (root / "data" / "halt-state.sqlite3").exists()


def test_crash_after_pin_swap_rolls_back_verified_backup_before_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = v1_profile(tmp_path)
    target = root / "infra" / "risk" / "risk_governance.lock.yaml"
    original = migration.provision_profile

    def crash(*_args: object, **_kwargs: object) -> None:
        raise KeyboardInterrupt("synthetic process crash")

    with monkeypatch.context() as patch:
        patch.setattr(migration, "provision_profile", crash)
        with pytest.raises(KeyboardInterrupt):
            migration.migrate_profile(
                root, CURRENT_LOCK, migration.NEW_LOCK_SHA256, migration.CONFIRMATION
            )
    assert digest(target) == migration.NEW_LOCK_SHA256
    with pytest.raises(migration.RiskLockMigrationError, match="PENDING"):
        migration.ensure_no_pending_migration(root)
    assert migration.provision_profile is original
    assert (
        migration.migrate_profile(
            root, CURRENT_LOCK, migration.NEW_LOCK_SHA256, migration.CONFIRMATION
        )
        == "MIGRATED_HALTED"
    )
    assert digest(target) == migration.NEW_LOCK_SHA256
    records = [
        json.loads(line)
        for line in (root / "migrations" / migration.AUDIT_NAME)
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    assert [record["event"] for record in records] == ["BEGIN", "ROLLBACK", "BEGIN", "COMMIT"]
    assert not (root / "migrations" / migration.JOURNAL_NAME).exists()
    store_path = root / "data" / "halt-state.sqlite3"
    store = HaltStore(store_path, store_path.parent)
    assert LEGACY_UNKNOWN_REASON in store.load()
    store.close()


def test_tampered_backup_blocks_crash_recovery(tmp_path: Path, monkeypatch) -> None:
    root = v1_profile(tmp_path)

    def crash(*_args: object, **_kwargs: object) -> None:
        raise KeyboardInterrupt("synthetic process crash")

    with monkeypatch.context() as patch:
        patch.setattr(migration, "provision_profile", crash)
        with pytest.raises(KeyboardInterrupt):
            migration.migrate_profile(
                root, CURRENT_LOCK, migration.NEW_LOCK_SHA256, migration.CONFIRMATION
            )
    journal = json.loads((root / "migrations" / migration.JOURNAL_NAME).read_text(encoding="utf-8"))
    backup = root / "migrations" / journal["backup"] / "leviathan.db"
    backup.chmod(stat.S_IREAD | stat.S_IWRITE)
    backup.write_bytes(b"tampered")
    with pytest.raises(migration.RiskLockMigrationError, match="BACKUP_INVALID"):
        migration.migrate_profile(
            root, CURRENT_LOCK, migration.NEW_LOCK_SHA256, migration.CONFIRMATION
        )
    with pytest.raises(migration.RiskLockMigrationError, match="PENDING"):
        migration.ensure_no_pending_migration(root)


def test_crash_after_audit_commit_resumes_without_repeating_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = v1_profile(tmp_path)
    real_audit = migration._audit

    def crash_after_commit(path: Path, event: dict[str, object]) -> None:
        real_audit(path, event)
        if event["event"] == "COMMIT":
            raise KeyboardInterrupt("synthetic post-commit crash")

    with monkeypatch.context() as patch:
        patch.setattr(migration, "_audit", crash_after_commit)
        with pytest.raises(KeyboardInterrupt):
            migration.migrate_profile(
                root, CURRENT_LOCK, migration.NEW_LOCK_SHA256, migration.CONFIRMATION
            )
    assert (root / "migrations" / migration.JOURNAL_NAME).exists()
    assert (
        migration.migrate_profile(
            root, CURRENT_LOCK, migration.NEW_LOCK_SHA256, migration.CONFIRMATION
        )
        == "ALREADY_MIGRATED"
    )
    assert not (root / "migrations" / migration.JOURNAL_NAME).exists()
    records = [
        json.loads(line)
        for line in (root / "migrations" / migration.AUDIT_NAME)
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    assert [record["event"] for record in records] == ["BEGIN", "COMMIT"]
    store_path = root / "data" / "halt-state.sqlite3"
    store = HaltStore(store_path, store_path.parent)
    assert LEGACY_UNKNOWN_REASON in store.load()
    store.close()


def test_crash_after_legacy_store_commit_completes_with_original_halt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = v1_profile(tmp_path)

    def crash_before_marker(*_args: object, **_kwargs: object) -> None:
        raise KeyboardInterrupt("synthetic crash after durable halt commit")

    with monkeypatch.context() as patch:
        patch.setattr(profile_provision, "_write_marker", crash_before_marker)
        with pytest.raises(KeyboardInterrupt):
            migration.migrate_profile(
                root, CURRENT_LOCK, migration.NEW_LOCK_SHA256, migration.CONFIRMATION
            )
    store_path = root / "data" / "halt-state.sqlite3"
    assert store_path.exists()
    assert not (root / "data" / "profile.json").exists()
    assert (
        migration.migrate_profile(
            root, CURRENT_LOCK, migration.NEW_LOCK_SHA256, migration.CONFIRMATION
        )
        == "ALREADY_MIGRATED"
    )
    marker = json.loads((root / "data" / "profile.json").read_text(encoding="utf-8"))
    assert marker["classification_used"] == "PRE_HALT_INSTALL"
    store = HaltStore(store_path, store_path.parent)
    assert LEGACY_UNKNOWN_REASON in store.load()
    store.close()
    events = [
        json.loads(line)["event"]
        for line in (root / "migrations" / migration.AUDIT_NAME)
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    assert events == ["BEGIN", "COMMIT"]


def test_invalid_partial_halt_store_stays_closed_for_manual_recovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = v1_profile(tmp_path)

    def crash_with_partial_store(*_args: object, **_kwargs: object) -> None:
        (root / "data" / "halt-state.sqlite3").write_bytes(b"invalid synthetic partial store")
        raise KeyboardInterrupt("synthetic incomplete halt store")

    with monkeypatch.context() as patch:
        patch.setattr(migration, "provision_profile", crash_with_partial_store)
        with pytest.raises(KeyboardInterrupt):
            migration.migrate_profile(
                root, CURRENT_LOCK, migration.NEW_LOCK_SHA256, migration.CONFIRMATION
            )
    with pytest.raises(migration.RiskLockMigrationError, match="HALT_STORE_INVALID"):
        migration.migrate_profile(
            root, CURRENT_LOCK, migration.NEW_LOCK_SHA256, migration.CONFIRMATION
        )
    with pytest.raises(migration.RiskLockMigrationError, match="PENDING"):
        migration.ensure_no_pending_migration(root)
    assert (root / "data" / "halt-state.sqlite3").read_bytes() == b"invalid synthetic partial store"
    assert (
        digest(root / "infra" / "risk" / "risk_governance.lock.yaml") == migration.NEW_LOCK_SHA256
    )


def test_crash_after_legacy_marker_before_commit_resumes_without_rollback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = v1_profile(tmp_path)
    real_audit = migration._audit

    def crash_before_commit(path: Path, event: dict[str, object]) -> None:
        if event["event"] == "COMMIT":
            raise KeyboardInterrupt("synthetic crash before audit commit")
        real_audit(path, event)

    with monkeypatch.context() as patch:
        patch.setattr(migration, "_audit", crash_before_commit)
        with pytest.raises(KeyboardInterrupt):
            migration.migrate_profile(
                root, CURRENT_LOCK, migration.NEW_LOCK_SHA256, migration.CONFIRMATION
            )
    assert (root / "data" / "profile.json").exists()
    assert (
        migration.migrate_profile(
            root, CURRENT_LOCK, migration.NEW_LOCK_SHA256, migration.CONFIRMATION
        )
        == "ALREADY_MIGRATED"
    )
    store_path = root / "data" / "halt-state.sqlite3"
    store = HaltStore(store_path, store_path.parent)
    assert LEGACY_UNKNOWN_REASON in store.load()
    store.close()
    events = [
        json.loads(line)["event"]
        for line in (root / "migrations" / migration.AUDIT_NAME)
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    assert events == ["BEGIN", "COMMIT"]


def test_cli_confirmation_uses_synthetic_profile(tmp_path: Path, monkeypatch, capsys) -> None:
    root = v1_profile(tmp_path)
    monkeypatch.setenv("LOCALAPPDATA", str(root.parent))
    assert (
        migration.run_cli(
            ["--confirm", migration.CONFIRMATION], CURRENT_LOCK, migration.NEW_LOCK_SHA256
        )
        == 0
    )
    assert "MIGRATED_HALTED" in capsys.readouterr().out


def test_normal_startup_refuses_old_pin_until_explicit_cli_upgrade(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = v1_profile(tmp_path)
    monkeypatch.setenv("LOCALAPPDATA", str(root.parent))
    monkeypatch.setattr(leviathan_desktop, "bundled_path", lambda _relative: CURRENT_LOCK)
    monkeypatch.setattr(leviathan_desktop, "RISK_LOCK_SHA256", migration.NEW_LOCK_SHA256)
    with pytest.raises(RuntimeError, match="local risk governance lock is modified"):
        leviathan_desktop.configure_data()
    assert not (root / "data" / "halt-state.sqlite3").exists()
    assert (
        migration.run_cli(
            ["--confirm", migration.CONFIRMATION], CURRENT_LOCK, migration.NEW_LOCK_SHA256
        )
        == 0
    )
    assert leviathan_desktop.configure_data() == root
    store_path = root / "data" / "halt-state.sqlite3"
    store = HaltStore(store_path, store_path.parent)
    assert LEGACY_UNKNOWN_REASON in store.load()
    store.close()
