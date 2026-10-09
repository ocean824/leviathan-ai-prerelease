"""Synthetic-only contract probes for the local halt authority."""

import hashlib
import json
import os
import sqlite3
import stat
import subprocess
import sys
import threading
from datetime import UTC, datetime
from pathlib import Path

import pytest

from leviathan_core.risk.halt import HaltAuthority
from leviathan_core.risk.halt_store import (
    FAULT_REASON,
    HaltStore,
    HaltStoreError,
    ProfileClassification,
    ProfileEvidence,
    ProvisionResult,
)


def evidence(kind: ProfileClassification) -> ProfileEvidence:
    return ProfileEvidence(kind, verified=True, references=("synthetic:profile-metadata",))


def new_store(tmp_path: Path) -> tuple[Path, HaltStore]:
    path = tmp_path / "halt-state.sqlite3"
    assert (
        HaltStore.provision_new(path, tmp_path, evidence(ProfileClassification.NEVER_PROVISIONED))
        is ProvisionResult.CREATED
    )
    return path, HaltStore(path, tmp_path)


def test_memory_instances_are_isolated_and_never_open_host_store() -> None:
    at = datetime(2026, 9, 30, 1, 2, 3, 456789, tzinfo=UTC)
    left = HaltAuthority(clock=lambda: at)
    right = HaltAuthority(clock=lambda: at)
    left.engage("omega")
    assert left.snapshot() == {"omega": "2026-09-30T01:02:03.456789Z"}
    assert right.snapshot() == {} and not right.halted
    left.lift("omega")
    assert not left.halted


def test_generation_is_durable_across_engage_and_lift(tmp_path: Path) -> None:
    path, store = new_store(tmp_path)
    authority = HaltAuthority(store)
    assert authority.generation == 0
    authority.engage("durable-generation")
    assert authority.generation == 1
    assert authority.lift_committed("durable-generation") is True
    assert authority.generation == 2
    authority.close()

    restarted = HaltAuthority(HaltStore(path, tmp_path))
    assert restarted.generation == 2
    restarted.close()


def test_provision_evidence_missing_store_and_legacy_unknown(tmp_path: Path) -> None:
    path = tmp_path / "halt-state.sqlite3"
    with pytest.raises(HaltStoreError):
        HaltStore(path, tmp_path)
    with pytest.raises(HaltStoreError):
        HaltStore.provision_new(path, tmp_path, evidence(ProfileClassification.UNKNOWN))
    with pytest.raises(HaltStoreError):
        HaltStore.provision_legacy(
            path, tmp_path, evidence(ProfileClassification.ALREADY_PROVISIONED)
        )
    assert not path.exists()
    assert (
        HaltStore.provision_legacy(path, tmp_path, evidence(ProfileClassification.PRE_HALT_INSTALL))
        is ProvisionResult.CREATED
    )
    store = HaltStore(path, tmp_path)
    authority = HaltAuthority(store)
    assert authority.active == ("legacy_state_unknown",)
    authority.close()
    before = _semantic_state(path)
    assert (
        HaltStore.provision_new(path, tmp_path, evidence(ProfileClassification.UNKNOWN))
        is ProvisionResult.ALREADY_VALIDATED
    )
    assert _semantic_state(path) == before


def test_exact_v1_checksum_duplicate_engage_named_lift_and_restart(tmp_path: Path) -> None:
    path, store = new_store(tmp_path)
    at = datetime(2026, 9, 30, 1, 2, 3, 456789, tzinfo=UTC)
    authority = HaltAuthority(store, clock=lambda: at)
    authority.engage("Ωmega")
    authority.engage("Ωmega")
    authority.engage("risk")
    assert authority.lift_committed("absent") is False
    assert authority.snapshot()["Ωmega"] == "2026-09-30T01:02:03.456789Z"
    with sqlite3.connect(path) as db:
        meta = db.execute("SELECT schema_version, generation, state_sha256 FROM meta").fetchone()
        assert db.execute("PRAGMA user_version").fetchone() == (1,)
        assert db.execute("PRAGMA journal_mode").fetchone() == ("delete",)
    assert meta[:2] == (1, 2)
    payload = {
        "generation": 2,
        "halts": [
            {"engaged_at_utc": "2026-09-30T01:02:03.456789Z", "reason": "risk"},
            {"engaged_at_utc": "2026-09-30T01:02:03.456789Z", "reason": "Ωmega"},
        ],
        "schema_version": 1,
    }
    expected = hashlib.sha256(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    assert meta[2] == expected
    authority.close()
    restarted = HaltAuthority(HaltStore(path, tmp_path))
    assert restarted.snapshot() == {
        "Ωmega": "2026-09-30T01:02:03.456789Z",
        "risk": "2026-09-30T01:02:03.456789Z",
    }
    assert restarted.lift_committed("risk") is True
    assert restarted.active == ("Ωmega",)
    restarted.close()
    again = HaltAuthority(HaltStore(path, tmp_path))
    assert again.active == ("Ωmega",)
    again.close()


def test_legacy_snapshot_retains_utc_timestamp(tmp_path: Path) -> None:
    path = tmp_path / "halt-state.sqlite3"
    at = datetime(2020, 1, 2, 3, 4, 5, tzinfo=UTC)
    HaltStore.provision_legacy(
        path,
        tmp_path,
        evidence(ProfileClassification.PRE_HALT_INSTALL),
        {"old_kill": at},
    )
    authority = HaltAuthority(HaltStore(path, tmp_path))
    assert authority.snapshot() == {"old_kill": "2020-01-02T03:04:05.000000Z"}
    authority.close()


def test_reason_is_nfc_normalized_before_storage(tmp_path: Path) -> None:
    _, store = new_store(tmp_path)
    authority = HaltAuthority(store)
    authority.engage("e\u0301")
    authority.engage("é")
    assert authority.active == ("é",)
    authority.close()


@pytest.mark.parametrize("reason", ["", " bad", "bad ", "a\x00b", "a\x80b", FAULT_REASON])
def test_invalid_reason_rejected_before_mutation(tmp_path: Path, reason: str) -> None:
    path, store = new_store(tmp_path)
    authority = HaltAuthority(store)
    before = path.read_bytes()
    with pytest.raises(ValueError):
        authority.engage(reason)
    assert path.read_bytes() == before
    authority.close()


@pytest.mark.parametrize("damage", ["empty", "garbage", "checksum", "version", "extra_table"])
def test_invalid_existing_store_never_reinitialized(tmp_path: Path, damage: str) -> None:
    path, store = new_store(tmp_path)
    store.close()
    if damage == "empty":
        path.write_bytes(b"")
    elif damage == "garbage":
        path.write_bytes(b"not sqlite")
    else:
        with sqlite3.connect(path) as db:
            if damage == "checksum":
                db.execute("UPDATE meta SET state_sha256=?", ("0" * 64,))
            elif damage == "version":
                db.execute("PRAGMA user_version=2")
            else:
                db.execute("CREATE TABLE unexpected(x INTEGER)")
    before = path.read_bytes()
    with pytest.raises(HaltStoreError):
        HaltStore(path, tmp_path)
    with pytest.raises(HaltStoreError):
        HaltStore.provision_new(path, tmp_path, evidence(ProfileClassification.NEVER_PROVISIONED))
    assert path.read_bytes() == before


def test_second_writer_blocked_and_fault_latches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path, store = new_store(tmp_path)
    with pytest.raises(HaltStoreError, match="HALT_STORE_BUSY"):
        HaltStore(path, tmp_path)
    authority = HaltAuthority(store)

    def broken_load(*, integrity: bool = False) -> dict[str, str]:
        raise HaltStoreError()

    monkeypatch.setattr(store, "load", broken_load)
    assert authority.halted
    assert authority.active == (FAULT_REASON,)
    assert authority.fault_code == "HALT_STORE_UNAVAILABLE"
    with pytest.raises(HaltStoreError):
        authority.engage("after_fault")
    authority.close()


def test_other_process_cannot_start_second_writer(tmp_path: Path) -> None:
    path, store = new_store(tmp_path)
    probe = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; from pathlib import Path; "
            "from leviathan_core.risk.halt_store import HaltStore; "
            "p=Path(sys.argv[1]); HaltStore(p,p.parent)",
            str(path),
        ],
        check=False,
        capture_output=True,
        timeout=10,
    )
    assert probe.returncode != 0
    assert b"HALT_STORE_BUSY" in probe.stderr
    store.close()


def test_uncertain_commit_fault_latches_then_restart_recovers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path, store = new_store(tmp_path)
    authority = HaltAuthority(store)
    real_mutate = store.mutate

    def committed_but_unacknowledged(
        reason: str, *, engage_at: str | None
    ) -> tuple[bool, dict[str, str]]:
        real_mutate(reason, engage_at=engage_at)
        raise HaltStoreError()

    monkeypatch.setattr(store, "mutate", committed_but_unacknowledged)
    with pytest.raises(HaltStoreError):
        authority.engage("unacknowledged")
    assert authority.halted and authority.fault_code == "HALT_STORE_UNAVAILABLE"
    authority.close()
    restarted = HaltAuthority(HaltStore(path, tmp_path))
    assert restarted.active == ("unacknowledged",)
    restarted.close()


def test_checksum_damage_after_startup_latches_fault(tmp_path: Path) -> None:
    path, store = new_store(tmp_path)
    authority = HaltAuthority(store)
    with sqlite3.connect(path) as db:
        db.execute("UPDATE meta SET state_sha256=?", ("f" * 64,))
    assert authority.halted and authority.active == (FAULT_REASON,)
    authority.close()


@pytest.mark.skipif(os.name != "nt", reason="Windows FILE_ATTRIBUTE_READONLY contract")
def test_windows_readonly_store_cannot_pass_startup(tmp_path: Path) -> None:
    path, store = new_store(tmp_path)
    store.close()
    path.chmod(stat.S_IREAD)
    try:
        assert path.stat().st_file_attributes & stat.FILE_ATTRIBUTE_READONLY
        with pytest.raises(HaltStoreError):
            HaltStore(path, tmp_path)
    finally:
        path.chmod(stat.S_IREAD | stat.S_IWRITE)


def test_startup_requires_real_meta_write(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path, store = new_store(tmp_path)
    store.close()
    original = HaltStore._connection

    def deny_update(self: HaltStore) -> sqlite3.Connection:
        connection = original(self)

        def authorizer(action: int, *_args: object) -> int:
            return sqlite3.SQLITE_DENY if action == sqlite3.SQLITE_UPDATE else sqlite3.SQLITE_OK

        connection.set_authorizer(authorizer)
        return connection

    monkeypatch.setattr(HaltStore, "_connection", deny_update)
    with pytest.raises(HaltStoreError):
        HaltStore(path, tmp_path)


def test_startup_requires_directory_journal_permission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path, store = new_store(tmp_path)
    store.close()

    def deny_probe(*_args: object, **_kwargs: object) -> tuple[int, str]:
        raise PermissionError("synthetic directory ACL denial")

    monkeypatch.setattr("leviathan_core.risk.halt_store.tempfile.mkstemp", deny_probe)
    with pytest.raises(HaltStoreError):
        HaltStore(path, tmp_path)


def test_concurrent_engage_serializes_single_commit(tmp_path: Path) -> None:
    path, store = new_store(tmp_path)
    authority = HaltAuthority(store)
    barrier = threading.Barrier(9)

    def engage() -> None:
        barrier.wait()
        authority.engage("same_reason")

    threads = [threading.Thread(target=engage) for _ in range(8)]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join(timeout=5)
        assert not thread.is_alive()
    assert authority.active == ("same_reason",)
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT generation FROM meta").fetchone() == (1,)
    authority.close()


def test_reparse_escape_is_rejected(tmp_path: Path) -> None:
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    alias = tmp_path / "alias"
    try:
        alias.symlink_to(elsewhere, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable")
    with pytest.raises(HaltStoreError):
        HaltStore.provision_new(
            alias / "halt-state.sqlite3",
            alias,
            evidence(ProfileClassification.NEVER_PROVISIONED),
        )


_CRASH_PROBE = """
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from leviathan_core.risk.halt import HaltAuthority
from leviathan_core.risk.halt_store import HaltStore

path = Path(sys.argv[1])
operation, boundary = sys.argv[2:4]
store = HaltStore(path, path.parent)
authority = HaltAuthority(store, clock=lambda: datetime(2026, 9, 30, tzinfo=UTC))
real_connection = store._connection

class CrashConnection:
    def __init__(self, connection):
        self.connection = connection
    def execute(self, *args):
        return self.connection.execute(*args)
    def commit(self):
        if boundary == 'before':
            os._exit(41)
        self.connection.commit()
        os._exit(42)
    def close(self):
        self.connection.close()

store._connection = lambda: CrashConnection(real_connection())
authority._refresh = lambda: None  # Startup restore has already validated the store.
if operation == 'engage':
    authority.engage('crash_reason')
else:
    authority.lift('crash_reason')
"""


@pytest.mark.parametrize("operation", ["engage", "lift"])
@pytest.mark.parametrize("boundary", ["before", "after"])
def test_crash_at_sqlite_commit_boundary(tmp_path: Path, operation: str, boundary: str) -> None:
    path, store = new_store(tmp_path)
    if operation == "lift":
        HaltAuthority(store).engage("crash_reason")
    store.close()
    crashed = subprocess.run(
        [sys.executable, "-c", _CRASH_PROBE, str(path), operation, boundary],
        check=False,
        capture_output=True,
        timeout=10,
    )
    assert crashed.returncode == (41 if boundary == "before" else 42), crashed.stderr
    restarted = HaltAuthority(HaltStore(path, tmp_path))
    expected_active = (operation == "engage") == (boundary == "after")
    assert ("crash_reason" in restarted.active) is expected_active
    restarted.close()


_STARTUP_CRASH_PROBE = """
import os
import sys
from pathlib import Path
from leviathan_core.risk.halt_store import HaltStore

path = Path(sys.argv[1])
boundary = sys.argv[2]
real_connection = HaltStore._connection

class CrashConnection:
    def __init__(self, connection):
        self.connection = connection
    def execute(self, sql, *params):
        result = self.connection.execute(sql, *params)
        if sql.startswith('UPDATE meta SET generation=generation+1') and boundary == 'first':
            os._exit(51)
        return result
    def commit(self):
        self.connection.commit()
        if boundary == 'committed':
            os._exit(52)
    def close(self):
        self.connection.close()

HaltStore._connection = lambda self: CrashConnection(real_connection(self))
HaltStore(path, path.parent)
"""


def _semantic_state(path: Path) -> tuple[tuple[int, str], list[tuple[str, str]]]:
    with sqlite3.connect(path) as db:
        meta = db.execute("SELECT generation, state_sha256 FROM meta").fetchone()
        halts = db.execute("SELECT reason, engaged_at_utc FROM halts ORDER BY reason").fetchall()
    assert meta is not None
    return meta, halts


@pytest.mark.parametrize("boundary", ["first", "committed"])
def test_startup_round_trip_crash_recovers_without_semantic_change(
    tmp_path: Path, boundary: str
) -> None:
    path, store = new_store(tmp_path)
    authority = HaltAuthority(store)
    authority.engage("persistent_halt")
    authority.close()
    before = _semantic_state(path)
    crashed = subprocess.run(
        [sys.executable, "-c", _STARTUP_CRASH_PROBE, str(path), boundary],
        check=False,
        capture_output=True,
        timeout=10,
    )
    assert crashed.returncode == (51 if boundary == "first" else 52), crashed.stderr
    journal = path.with_name(path.name + "-journal")
    if boundary == "first":
        assert journal.exists() and journal.stat().st_size > 0
    else:
        assert not journal.exists()
    reopened = HaltStore(path, tmp_path)
    assert "persistent_halt" in reopened.load()
    reopened.close()
    assert _semantic_state(path) == before
    assert not journal.exists()
