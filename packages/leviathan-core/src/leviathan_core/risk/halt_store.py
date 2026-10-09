"""The local, single-writer SQLite v1 authority for named halts.

The database is deliberately separate from the product route-attempt database.
Only explicit, evidenced pre-start provisioning may create it.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import re
import sqlite3
import stat
import tempfile
import threading
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

SCHEMA_VERSION = 1
FAULT_REASON = "__halt_store_unavailable__"
LEGACY_UNKNOWN_REASON = "legacy_state_unknown"
_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT_STATUSES = frozenset(("COMMITTED", "NOT_COMMITTED", "UNKNOWN"))
_META_SQL = (
    "CREATE TABLE meta(id INTEGER PRIMARY KEY CHECK(id=1), "
    "schema_version INTEGER NOT NULL, generation INTEGER NOT NULL CHECK(generation>=0), "
    "state_sha256 TEXT NOT NULL)"
)
_HALTS_SQL = (
    "CREATE TABLE halts(reason TEXT PRIMARY KEY COLLATE BINARY, engaged_at_utc TEXT NOT NULL)"
)


class HaltStoreError(RuntimeError):
    """Redacted durable-authority failure. Details must never reach HTTP."""

    def __init__(
        self, code: str = "HALT_STORE_UNAVAILABLE", commit_status: str = "UNKNOWN"
    ) -> None:
        self.code = code
        self.commit_status = commit_status if commit_status in _COMMIT_STATUSES else "UNKNOWN"
        super().__init__(code)


class ProfileClassification(StrEnum):
    NEVER_PROVISIONED = "NEVER_PROVISIONED"
    PRE_HALT_INSTALL = "PRE_HALT_INSTALL"
    ALREADY_PROVISIONED = "ALREADY_PROVISIONED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class ProfileEvidence:
    classification: ProfileClassification
    verified: bool
    references: tuple[str, ...] = ()


class ProvisionResult(StrEnum):
    CREATED = "CREATED"
    ALREADY_VALIDATED = "ALREADY_VALIDATED"


def normalize_reason(reason: str) -> str:
    if not isinstance(reason, str):
        raise ValueError("halt reason must be text")
    normalized = unicodedata.normalize("NFC", reason)
    size = len(normalized.encode("utf-8"))
    if (
        not 1 <= size <= 128
        or normalized != normalized.strip()
        or normalized == FAULT_REASON
        or any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in normalized)
    ):
        raise ValueError("invalid halt reason")
    return normalized


def timestamp_utc(value: datetime) -> str:
    offset = value.utcoffset()
    if value.tzinfo is None or offset is None or offset.total_seconds() != 0:
        raise ValueError("halt clock must return an aware UTC datetime")
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _parse_timestamp(value: object) -> datetime:
    if not isinstance(value, str) or _TIMESTAMP.fullmatch(value) is None:
        raise HaltStoreError()
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise HaltStoreError() from exc
    if timestamp_utc(parsed) != value:
        raise HaltStoreError()
    return parsed


def _checksum(generation: int, halts: Mapping[str, str]) -> str:
    rows = [
        {"engaged_at_utc": halts[reason], "reason": reason}
        for reason in sorted(halts, key=lambda item: item.encode("utf-8"))
    ]
    payload = {"generation": generation, "halts": rows, "schema_version": SCHEMA_VERSION}
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    return hashlib.sha256(encoded).hexdigest()


def _check_local_path(path: Path, data_root: Path) -> None:
    if not path.is_absolute() or not data_root.is_absolute() or path.parent != data_root:
        raise HaltStoreError("HALT_STORE_PATH_INVALID")
    if os.name == "nt":
        if str(path).startswith("\\\\"):
            raise HaltStoreError("HALT_STORE_PATH_INVALID")
        import ctypes

        drive_type = ctypes.windll.kernel32.GetDriveTypeW(str(Path(path.anchor)))
        if drive_type != 3:  # DRIVE_FIXED; never trust a remote/removable profile store.
            raise HaltStoreError("HALT_STORE_PATH_INVALID")
    for part in (data_root, path, path.with_name(path.name + ".lock")):
        probe = part
        while True:
            try:
                info = os.lstat(probe)
            except FileNotFoundError:
                pass
            except OSError as exc:
                raise HaltStoreError("HALT_STORE_PATH_INVALID") from exc
            else:
                if stat.S_ISLNK(info.st_mode) or (
                    os.name == "nt" and info.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT
                ):
                    raise HaltStoreError("HALT_STORE_PATH_INVALID")
                if (
                    os.name == "nt"
                    and probe == path
                    and info.st_file_attributes & stat.FILE_ATTRIBUTE_READONLY
                ):
                    raise HaltStoreError()
                if probe == path and info.st_nlink != 1:
                    raise HaltStoreError("HALT_STORE_PATH_INVALID")
            if probe == probe.parent:
                break
            probe = probe.parent
    try:
        path.resolve(strict=False).relative_to(data_root.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise HaltStoreError("HALT_STORE_PATH_INVALID") from exc


class _WriterLock:
    def __init__(self, path: Path) -> None:
        self._fd: int | None = None
        try:
            flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_BINARY", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            self._fd = os.open(path, flags, 0o600)
            if os.fstat(self._fd).st_size == 0:
                os.write(self._fd, b"0")
                os.fsync(self._fd)
            os.lseek(self._fd, 0, os.SEEK_SET)
        except OSError as exc:
            self.close()
            raise HaltStoreError() from exc
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(self._fd, msvcrt.LK_NBLCK, 1)
            else:
                fcntl = importlib.import_module("fcntl")
                fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, PermissionError) as exc:
            self.close()
            raise HaltStoreError("HALT_STORE_BUSY") from exc

    def close(self) -> None:
        if self._fd is not None:
            fd, self._fd = self._fd, None
            try:
                if os.name == "nt":
                    import msvcrt

                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                else:
                    fcntl = importlib.import_module("fcntl")
                    fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(fd)


class HaltStore:
    """Owns a held OS writer lock; connections are confined to caller threads."""

    def __init__(self, path: Path, data_root: Path) -> None:
        self.path = Path(path)
        self.data_root = Path(data_root)
        self._mutex = threading.RLock()
        self._lock: _WriterLock | None = None
        _check_local_path(self.path, self.data_root)
        try:
            self._lock = _WriterLock(self.path.with_name(self.path.name + ".lock"))
            self.load(integrity=True)
        except Exception:
            self.close()
            raise

    def close(self) -> None:
        with self._mutex:
            if self._lock is not None:
                self._lock.close()
                self._lock = None

    def _connection(self) -> sqlite3.Connection:
        try:
            _check_local_path(self.path, self.data_root)
            if not self.path.is_file() or self.path.stat().st_size == 0:
                raise HaltStoreError()
            connection = sqlite3.connect(self.path.as_uri() + "?mode=rw", uri=True, timeout=0)
            try:
                mode = connection.execute("PRAGMA journal_mode=DELETE").fetchone()
                connection.execute("PRAGMA synchronous=EXTRA")
                sync = connection.execute("PRAGMA synchronous").fetchone()
                if mode != ("delete",) or sync != (3,):
                    raise HaltStoreError()
                return connection
            except Exception:
                connection.close()
                raise
        except (sqlite3.Error, OSError) as exc:
            raise HaltStoreError() from exc

    @staticmethod
    def _read(
        connection: sqlite3.Connection, *, integrity: bool = False
    ) -> tuple[int, dict[str, str]]:
        if integrity and connection.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
            raise HaltStoreError()
        if connection.execute("PRAGMA user_version").fetchone() != (SCHEMA_VERSION,):
            raise HaltStoreError()
        tables = connection.execute(
            "SELECT name, sql FROM sqlite_master WHERE type='table' ORDER BY name"
        ).fetchall()
        if tables != [("halts", _HALTS_SQL), ("meta", _META_SQL)]:
            raise HaltStoreError()
        objects = connection.execute(
            "SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name"
        ).fetchall()
        if objects != [
            ("index", "sqlite_autoindex_halts_1", "halts", None),
            ("table", "halts", "halts", _HALTS_SQL),
            ("table", "meta", "meta", _META_SQL),
        ]:
            raise HaltStoreError()
        rows = connection.execute(
            "SELECT id, schema_version, generation, state_sha256, "
            "typeof(id), typeof(schema_version), typeof(generation), typeof(state_sha256) FROM meta"
        ).fetchall()
        if len(rows) != 1:
            raise HaltStoreError()
        row = rows[0]
        if (
            row[0] != 1
            or row[1] != SCHEMA_VERSION
            or not isinstance(row[2], int)
            or row[2] < 0
            or row[4:] != ("integer", "integer", "integer", "text")
            or not isinstance(row[3], str)
            or _SHA256.fullmatch(row[3]) is None
        ):
            raise HaltStoreError()
        halts: dict[str, str] = {}
        for reason, engaged_at, reason_type, at_type in connection.execute(
            "SELECT reason, engaged_at_utc, typeof(reason), typeof(engaged_at_utc) FROM halts"
        ):
            if reason_type != "text" or at_type != "text":
                raise HaltStoreError()
            try:
                if normalize_reason(reason) != reason:
                    raise HaltStoreError()
            except ValueError as exc:
                raise HaltStoreError() from exc
            _parse_timestamp(engaged_at)
            if reason in halts:
                raise HaltStoreError()
            halts[reason] = engaged_at
        if _checksum(row[2], halts) != row[3]:
            raise HaltStoreError()
        return row[2], halts

    def load(self, *, integrity: bool = False) -> dict[str, str]:
        with self._mutex:
            if self._lock is None:
                raise HaltStoreError()
            if integrity:
                self._prove_directory_writable()
            connection = self._connection()
            try:
                connection.execute("BEGIN IMMEDIATE")
                _, halts = self._read(connection, integrity=integrity)
                if integrity:
                    before = connection.execute(
                        "SELECT generation, state_sha256 FROM meta WHERE id=1"
                    ).fetchone()
                    # The first value change dirties the page and creates a
                    # rollback journal; the second restores semantic state.
                    connection.execute("UPDATE meta SET generation=generation+1 WHERE id=1")
                    if connection.execute("SELECT changes()").fetchone() != (1,):
                        raise HaltStoreError()
                    connection.execute("UPDATE meta SET generation=generation-1 WHERE id=1")
                    if connection.execute("SELECT changes()").fetchone() != (1,):
                        raise HaltStoreError()
                    after = connection.execute(
                        "SELECT generation, state_sha256 FROM meta WHERE id=1"
                    ).fetchone()
                    if before != after:
                        raise HaltStoreError()
                connection.commit()
                return halts
            except (sqlite3.Error, OSError, HaltStoreError) as exc:
                raise HaltStoreError() from exc
            finally:
                connection.close()

    @property
    def generation(self) -> int:
        """Read the checksummed durable mutation generation without changing it."""
        with self._mutex:
            if self._lock is None:
                raise HaltStoreError()
            connection = self._connection()
            try:
                connection.execute("BEGIN IMMEDIATE")
                generation, _halts = self._read(connection)
                connection.commit()
                return generation
            except (sqlite3.Error, OSError, HaltStoreError) as exc:
                raise HaltStoreError() from exc
            finally:
                connection.close()

    def _prove_directory_writable(self) -> None:
        fd: int | None = None
        probe_path: str | None = None
        failure: OSError | None = None
        try:
            fd, probe_path = tempfile.mkstemp(prefix=".halt-journal-probe-", dir=self.data_root)
            os.write(fd, b"0")
            os.fsync(fd)
        except OSError as exc:
            failure = exc
        finally:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError as exc:
                    failure = failure or exc
            if probe_path is not None:
                try:
                    os.unlink(probe_path)
                except OSError as exc:
                    failure = failure or exc
        if failure is not None:
            raise HaltStoreError() from failure

    def mutate(self, reason: str, *, engage_at: str | None) -> tuple[bool, dict[str, str]]:
        with self._mutex:
            if self._lock is None:
                raise HaltStoreError(commit_status="NOT_COMMITTED")
            try:
                connection = self._connection()
            except HaltStoreError as exc:
                raise HaltStoreError(commit_status="NOT_COMMITTED") from exc
            commit_started = False
            try:
                connection.execute("BEGIN IMMEDIATE")
                generation, halts = self._read(connection)
                changed = (reason not in halts) if engage_at is not None else (reason in halts)
                if changed:
                    if engage_at is not None:
                        _parse_timestamp(engage_at)
                        halts[reason] = engage_at
                        connection.execute(
                            "INSERT INTO halts(reason, engaged_at_utc) VALUES(?, ?)",
                            (reason, engage_at),
                        )
                    else:
                        del halts[reason]
                        connection.execute("DELETE FROM halts WHERE reason=?", (reason,))
                    generation += 1
                    connection.execute(
                        "UPDATE meta SET generation=?, state_sha256=? WHERE id=1",
                        (generation, _checksum(generation, halts)),
                    )
                commit_started = True
                connection.commit()
                return changed, halts
            except (sqlite3.Error, OSError, HaltStoreError) as exc:
                status = "UNKNOWN" if commit_started else "NOT_COMMITTED"
                raise HaltStoreError(commit_status=status) from exc
            finally:
                connection.close()

    @classmethod
    def provision_new(
        cls, path: Path, data_root: Path, evidence: ProfileEvidence
    ) -> ProvisionResult:
        return cls._provision(
            path, data_root, evidence, ProfileClassification.NEVER_PROVISIONED, {}
        )

    @classmethod
    def provision_legacy(
        cls,
        path: Path,
        data_root: Path,
        evidence: ProfileEvidence,
        snapshot: Mapping[str, datetime] | None = None,
    ) -> ProvisionResult:
        if Path(path).exists():
            return cls._provision(
                path, data_root, evidence, ProfileClassification.PRE_HALT_INSTALL, {}
            )
        imported = (
            {normalize_reason(reason): timestamp_utc(at) for reason, at in snapshot.items()}
            if snapshot is not None
            else {LEGACY_UNKNOWN_REASON: timestamp_utc(datetime.now(UTC))}
        )
        if snapshot is not None and len(imported) != len(snapshot):
            raise ValueError("duplicate normalized legacy halt reason")
        return cls._provision(
            path, data_root, evidence, ProfileClassification.PRE_HALT_INSTALL, imported
        )

    @classmethod
    def _provision(
        cls,
        path: Path,
        data_root: Path,
        evidence: ProfileEvidence,
        required: ProfileClassification,
        initial: Mapping[str, str],
    ) -> ProvisionResult:
        path, data_root = Path(path), Path(data_root)
        _check_local_path(path, data_root)
        lock = _WriterLock(path.with_name(path.name + ".lock"))
        try:
            if path.exists():
                # Reuse the held lock; never attempt a second lock in this process.
                store = object.__new__(cls)
                store.path, store.data_root = path, data_root
                store._mutex, store._lock = threading.RLock(), lock  # noqa: SLF001 - same-class init
                store.load(integrity=True)
                return ProvisionResult.ALREADY_VALIDATED
            if (
                not evidence.verified
                or evidence.classification is not required
                or not evidence.references
            ):
                raise HaltStoreError("HALT_STORE_PROVISION_DENIED")
            try:
                fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
                os.close(fd)
                connection = sqlite3.connect(path.as_uri() + "?mode=rw", uri=True)
                try:
                    if connection.execute("PRAGMA journal_mode=DELETE").fetchone() != ("delete",):
                        raise HaltStoreError()
                    connection.execute("PRAGMA synchronous=EXTRA")
                    if connection.execute("PRAGMA synchronous").fetchone() != (3,):
                        raise HaltStoreError()
                    connection.execute("BEGIN IMMEDIATE")
                    connection.execute(_META_SQL)
                    connection.execute(_HALTS_SQL)
                    for reason, at in initial.items():
                        connection.execute("INSERT INTO halts VALUES(?, ?)", (reason, at))
                    connection.execute(
                        "INSERT INTO meta VALUES(1, ?, 0, ?)",
                        (SCHEMA_VERSION, _checksum(0, initial)),
                    )
                    connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
                    connection.commit()
                finally:
                    connection.close()
            except (sqlite3.Error, OSError, HaltStoreError) as exc:
                # A failed/partial first provision is deliberately retained as invalid.
                raise HaltStoreError() from exc
            return ProvisionResult.CREATED
        finally:
            lock.close()
