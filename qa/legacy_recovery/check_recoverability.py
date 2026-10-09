"""Read-only verification of an archived import's recoverable Git evidence.

This module does not repair, migrate, check out, or write to the repository.
The verifier is deliberately evidence-driven; a historical PASS flag is not
accepted as proof.
"""

from __future__ import annotations

import hashlib
import os
import queue
import re
import stat
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Literal

from pydantic import ConfigDict

from leviathan_core.numeric import canonical_json
from leviathan_core.seal import Issuer, SealedModel, SealError, require

_ISSUER = Issuer("legacy001.recovery.v1")
_RELOCATION_ISSUER = Issuer("legacy001.relocation.v1")
_OID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z", re.ASCII)
_REF = re.compile(r"refs/(?:heads|tags)/[A-Za-z0-9._/-]+\Z", re.ASCII)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_MAX_GIT_OUTPUT = 4 * 1024 * 1024
_MAX_DIRTY_SNAPSHOT = 64 * 1024 * 1024
_GIT_CHUNK_SIZE = 64 * 1024
_GIT_DEFAULT_TIMEOUT_SECONDS = 30
_GIT_HEAVY_TIMEOUT_SECONDS = 120
_REASONS = frozenset(
    {
        "INVALID_EVIDENCE",
        "REPOSITORY_UNAVAILABLE",
        "COMMIT_UNREACHABLE",
        "REF_MISSING",
        "REF_MISMATCH",
        "BINARY_MISSING",
        "BINARY_DIGEST_MISMATCH",
        "DIRTY_BYTES_MISSING",
        "DIRTY_DIGEST_MISMATCH",
        "STALE_RELOCATION",
        "GIT_TIMEOUT",
        "OUTPUT_TOO_LARGE",
    }
)
BlockedReason = Literal[
    "INVALID_EVIDENCE",
    "REPOSITORY_UNAVAILABLE",
    "COMMIT_UNREACHABLE",
    "REF_MISSING",
    "REF_MISMATCH",
    "BINARY_MISSING",
    "BINARY_DIGEST_MISMATCH",
    "DIRTY_BYTES_MISSING",
    "DIRTY_DIGEST_MISMATCH",
    "STALE_RELOCATION",
    "GIT_TIMEOUT",
    "OUTPUT_TOO_LARGE",
]


class RecoveryError(ValueError):
    """Content-free public error. It never retains caller-supplied evidence."""

    def __init__(self, code: Literal["INVALID_EVIDENCE"]) -> None:
        self.code = code
        super().__init__(code)


def _invalid() -> None:
    raise RecoveryError("INVALID_EVIDENCE")


@dataclass(frozen=True, slots=True)
class BinaryAssetEvidenceV1:
    """A digest-pinned binary path at one retained Git ref."""

    ref: str
    path: str
    sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.ref) is not str
            or _REF.fullmatch(self.ref) is None
            or type(self.path) is not str
            or not self.path
            or "\\" in self.path
            or PurePosixPath(self.path).is_absolute()
            or any(part in ("", ".", "..") for part in self.path.split("/"))
            or type(self.sha256) is not str
            or _SHA256.fullmatch(self.sha256) is None
        ):
            _invalid()


@dataclass(frozen=True, slots=True)
class DirtySnapshotEvidenceV1:
    """Location and SHA-256 for separately retained original dirty bytes."""

    path: Path
    sha256: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.path, Path)
            or not self.path.is_absolute()
            or type(self.sha256) is not str
            or _SHA256.fullmatch(self.sha256) is None
        ):
            _invalid()


@dataclass(frozen=True, slots=True)
class ImportEvidenceV1:
    """Minimal immutable evidence extracted from an archived import record."""

    source_path: str
    successor_path: str
    commit_oids: tuple[str, ...]
    refs: tuple[tuple[str, str], ...]
    binary_assets: tuple[BinaryAssetEvidenceV1, ...]
    dirty_snapshot: DirtySnapshotEvidenceV1
    schema_version: str = "1"

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not str
            or self.schema_version != "1"
            or type(self.source_path) is not str
            or not self.source_path
            or type(self.successor_path) is not str
            or not self.successor_path
            or type(self.commit_oids) is not tuple
            or not self.commit_oids
            or any(type(oid) is not str or _OID.fullmatch(oid) is None for oid in self.commit_oids)
            or len(set(self.commit_oids)) != len(self.commit_oids)
            or type(self.refs) is not tuple
            or not self.refs
            or any(
                type(item) is not tuple
                or len(item) != 2
                or type(item[0]) is not str
                or _REF.fullmatch(item[0]) is None
                or type(item[1]) is not str
                or _OID.fullmatch(item[1]) is None
                for item in self.refs
            )
            or len({name for name, _ in self.refs}) != len(self.refs)
            or type(self.binary_assets) is not tuple
            or any(type(asset) is not BinaryAssetEvidenceV1 for asset in self.binary_assets)
            or type(self.dirty_snapshot) is not DirtySnapshotEvidenceV1
        ):
            _invalid()


@dataclass(frozen=True)
class ApprovedRelocationV1:
    """Coordinator-approved mapping from the archived successor to its registry path."""

    source_path: str
    registered_path: str
    approval_id: str

    def __post_init__(self) -> None:
        if (
            type(self.source_path) is not str
            or not self.source_path
            or type(self.registered_path) is not str
            or not self.registered_path
            or type(self.approval_id) is not str
            or not self.approval_id.strip()
        ):
            _invalid()


class RecoveryReportV1(SealedModel):
    """Sanitized, immutable summary of the recoverability evidence checks."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    schema_version: Literal["1"]
    status: Literal["BLOCKED", "REACHABLE_RESTORATION_NOT_VERIFIED"]
    blocked_reason: BlockedReason | None
    detail: Literal[
        "RELOCATION_REQUIRED", "RELOCATION_UNVERIFIED", "RELOCATION_MISMATCH"
    ] | None
    registered_repo_path: str
    import_evidence_digest: str
    relocation_digest: str | None
    relocation_approval_id: str | None
    evidence_ref_oids: tuple[tuple[str, str], ...]
    evidence_commit_oids: tuple[str, ...]
    verifier_version: Literal["1"]
    checked_at_ns: int
    restoration: Literal["NOT_VERIFIED"]


class _GitAbortError(Exception):
    """Content-free bounded Git process failure."""

    def __init__(self, code: Literal["GIT_TIMEOUT", "OUTPUT_TOO_LARGE"]) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class _ReportContext:
    registered_repo_path: str
    import_evidence_digest: str
    relocation_digest: str | None
    relocation_approval_id: str | None
    evidence_ref_oids: tuple[tuple[str, str], ...]
    evidence_commit_oids: tuple[str, ...]
    checked_at_ns: int


def _normalized_path(value: str | Path, *, strict: bool) -> str | None:
    try:
        path = Path(value)
        if not path.is_absolute():
            return None
        resolved = path.resolve(strict=strict)
    except (OSError, RuntimeError, TypeError, ValueError):
        return None
    return os.path.normcase(os.path.normpath(str(resolved)))


def _evidence_digest(evidence: object) -> str:
    try:
        if type(evidence) is not ImportEvidenceV1:
            raise ValueError
        semantic = {
            "schema_version": evidence.schema_version,
            "source_path": _normalized_path(evidence.source_path, strict=False),
            "successor_path": _normalized_path(evidence.successor_path, strict=False),
            "commit_oids": evidence.commit_oids,
            "refs": evidence.refs,
            "binary_assets": tuple(
                {"ref": asset.ref, "path": asset.path, "sha256": asset.sha256}
                for asset in evidence.binary_assets
            ),
            "dirty_snapshot": {
                "path": _normalized_path(evidence.dirty_snapshot.path, strict=False),
                "sha256": evidence.dirty_snapshot.sha256,
            },
        }
        return hashlib.sha256(canonical_json(semantic)).hexdigest()
    except Exception:
        return hashlib.sha256(b"LEGACY001_INVALID_EVIDENCE").hexdigest()


def _relocation_digest(relocation: object) -> str | None:
    if type(relocation) is not ApprovedRelocationV1:
        return None
    try:
        semantic = {
            "source_path": _normalized_path(relocation.source_path, strict=False),
            "registered_path": _normalized_path(relocation.registered_path, strict=False),
            "approval_id": relocation.approval_id,
        }
        return hashlib.sha256(canonical_json(semantic)).hexdigest()
    except Exception:
        return None


def _context(
    registered_repo: object,
    evidence: object,
    relocation: object,
    clock_ns: Callable[[], int],
) -> _ReportContext:
    registered = (
        _normalized_path(registered_repo, strict=False)
        if isinstance(registered_repo, Path)
        else None
    ) or "<unavailable>"
    try:
        checked_at_ns = clock_ns()
    except Exception:
        checked_at_ns = 0
    if type(checked_at_ns) is not int or checked_at_ns < 0:
        checked_at_ns = 0
    refs = evidence.refs if type(evidence) is ImportEvidenceV1 else ()
    commits = evidence.commit_oids if type(evidence) is ImportEvidenceV1 else ()
    relocation_id: str | None = None
    if type(relocation) is ApprovedRelocationV1:
        try:
            require(relocation, _RELOCATION_ISSUER.tag)
            relocation_id = relocation.approval_id
        except SealError:
            pass
    return _ReportContext(
        registered_repo_path=registered,
        import_evidence_digest=_evidence_digest(evidence),
        relocation_digest=_relocation_digest(relocation),
        relocation_approval_id=relocation_id,
        evidence_ref_oids=refs,
        evidence_commit_oids=commits,
        checked_at_ns=checked_at_ns,
    )


def _report(
    context: _ReportContext,
    reason: BlockedReason | None,
    detail: Literal[
        "RELOCATION_REQUIRED", "RELOCATION_UNVERIFIED", "RELOCATION_MISMATCH"
    ] | None = None,
) -> RecoveryReportV1:
    if reason is not None and reason not in _REASONS:
        reason = "INVALID_EVIDENCE"
    report = RecoveryReportV1(
        schema_version="1",
        status="BLOCKED" if reason is not None else "REACHABLE_RESTORATION_NOT_VERIFIED",
        blocked_reason=reason,
        detail=detail,
        registered_repo_path=context.registered_repo_path,
        import_evidence_digest=context.import_evidence_digest,
        relocation_digest=context.relocation_digest,
        relocation_approval_id=context.relocation_approval_id,
        evidence_ref_oids=context.evidence_ref_oids,
        evidence_commit_oids=context.evidence_commit_oids,
        verifier_version="1",
        checked_at_ns=context.checked_at_ns,
        restoration="NOT_VERIFIED",
    )
    return _ISSUER.issue(report)


def require_recovery_report(report: object) -> RecoveryReportV1:
    """Require a report issued by this verifier and unchanged since issuance."""
    if type(report) is not RecoveryReportV1:
        raise RecoveryError("INVALID_EVIDENCE")
    try:
        return require(report, _ISSUER.tag)
    except SealError:
        raise RecoveryError("INVALID_EVIDENCE") from None


def _git_environment(home: str) -> dict[str, str]:
    """Construct a minimal Git environment, dropping inherited GIT_* controls."""
    allowed = {"PATH", "SYSTEMROOT", "TEMP", "TMP"}
    environment = {
        key: value for key, value in os.environ.items() if key.upper() in allowed
    }
    environment.update(
        {
            "HOME": home,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    return environment


def _pump_stdout(
    stream: BinaryIO, chunks: queue.Queue[bytes | None], stop: threading.Event
) -> None:
    try:
        while not stop.is_set():
            chunk = stream.read(_GIT_CHUNK_SIZE)
            if not chunk:
                break
            while not stop.is_set():
                try:
                    chunks.put(chunk, timeout=0.05)
                    break
                except queue.Full:
                    continue
    except OSError:
        pass
    finally:
        while not stop.is_set():
            try:
                chunks.put(None, timeout=0.05)
                break
            except queue.Full:
                continue


def _git(
    repository: Path, git_dir: Path, home: str, *args: str
) -> bytes | None:
    """Run one hardened, read-only Git query with bounded output and time."""
    timeout = (
        _GIT_HEAVY_TIMEOUT_SECONDS
        if args[0] in {"fsck", "rev-list"}
        else _GIT_DEFAULT_TIMEOUT_SECONDS
    )
    command = [
        "git",
        "-C",
        str(repository),
        "-c",
        "core.fsmonitor=false",
        "-c",
        f"core.hooksPath={os.devnull}",
        "-c",
        "core.sshCommand=",
        "-c",
        "protocol.allow=never",
        "-c",
        "core.alternateRefsCommand=",
        "-c",
        "uploadpack.packObjectsHook=",
        f"--git-dir={git_dir}",
        f"--work-tree={repository}",
        "--no-replace-objects",
        *args,
    ]
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            cwd=repository,
            env=_git_environment(home),
            shell=False,
        )
    except OSError:
        return None
    if process.stdout is None:
        process.kill()
        process.wait()
        return None

    chunks: queue.Queue[bytes | None] = queue.Queue(maxsize=1)
    stop = threading.Event()
    reader = threading.Thread(
        target=_pump_stdout, args=(process.stdout, chunks, stop), daemon=True
    )
    reader.start()
    output = bytearray()
    deadline = time.monotonic() + timeout

    def stop_process() -> None:
        stop.set()
        if process.poll() is None:
            process.kill()
        with suppress(subprocess.TimeoutExpired):
            process.wait(timeout=2)
        reader.join(timeout=2)

    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            stop_process()
            raise _GitAbortError("GIT_TIMEOUT")
        try:
            chunk = chunks.get(timeout=min(remaining, 0.1))
        except queue.Empty:
            if process.poll() is not None and not reader.is_alive():
                break
            continue
        if chunk is None:
            break
        if len(output) + len(chunk) > _MAX_GIT_OUTPUT:
            stop_process()
            raise _GitAbortError("OUTPUT_TOO_LARGE")
        output.extend(chunk)

    remaining = max(0.001, deadline - time.monotonic())
    try:
        return_code = process.wait(timeout=remaining)
    except subprocess.TimeoutExpired:
        stop_process()
        raise _GitAbortError("GIT_TIMEOUT") from None
    return bytes(output) if return_code == 0 else None


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _is_junction(path: Path) -> bool:
    probe = getattr(path, "is_junction", None)
    return bool(probe()) if callable(probe) else False


def _git_directory(repository: Path) -> Path | None:
    candidate = repository / ".git"
    try:
        if candidate.is_symlink() or _is_junction(candidate):
            return None
        git_dir = candidate.resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    if not git_dir.is_dir() or not _inside(git_dir, repository):
        return None
    return git_dir


def _ref_oid(repository: Path, git_dir: Path, home: str, ref: str) -> bytes | None:
    return _git(repository, git_dir, home, "show-ref", "--verify", "--hash", ref)


def _has_binary(
    repository: Path, git_dir: Path, home: str, asset: BinaryAssetEvidenceV1
) -> tuple[bool, bool]:
    raw = _git(repository, git_dir, home, "show", f"{asset.ref}:{asset.path}")
    if raw is None:
        return False, False
    return True, hashlib.sha256(raw).hexdigest() == asset.sha256


def _dirty_bytes(snapshot: DirtySnapshotEvidenceV1) -> tuple[bool, bool]:
    path = snapshot.path
    try:
        if path.is_symlink() or _is_junction(path):
            return False, False
        resolved = path.resolve(strict=True)
        info = resolved.stat()
        if not stat.S_ISREG(info.st_mode):
            return False, False
        if info.st_size > _MAX_DIRTY_SNAPSHOT:
            raise _GitAbortError("OUTPUT_TOO_LARGE")
        digest = hashlib.sha256()
        bytes_read = 0
        with resolved.open("rb") as stream:
            while chunk := stream.read(_GIT_CHUNK_SIZE):
                bytes_read += len(chunk)
                if bytes_read > _MAX_DIRTY_SNAPSHOT:
                    raise _GitAbortError("OUTPUT_TOO_LARGE")
                digest.update(chunk)
    except _GitAbortError:
        raise
    except OSError:
        return False, False
    return True, digest.hexdigest() == snapshot.sha256


def verify_recoverability(
    registered_repo: Path,
    evidence: ImportEvidenceV1,
    relocation: ApprovedRelocationV1 | None = None,
    *,
    clock_ns: Callable[[], int] = time.time_ns,
) -> RecoveryReportV1:
    """Check retained evidence through hardened, read-only Git queries.

    The result can never claim a complete recovery PASS because this slice does not
    perform a disposable restore. All Git output is capped and all failures are
    represented by allowlisted codes without retaining command output.
    """
    context = _context(registered_repo, evidence, relocation, clock_ns)
    if not isinstance(registered_repo, Path) or type(evidence) is not ImportEvidenceV1 or (
        relocation is not None and type(relocation) is not ApprovedRelocationV1
    ):
        return _report(context, "INVALID_EVIDENCE")

    try:
        current_repo = registered_repo.resolve(strict=True)
    except (OSError, RuntimeError):
        return _report(context, "REPOSITORY_UNAVAILABLE")
    if not current_repo.is_dir():
        return _report(context, "REPOSITORY_UNAVAILABLE")
    current_path = _normalized_path(current_repo, strict=True)
    archived_successor = _normalized_path(evidence.successor_path, strict=False)
    if current_path is None or archived_successor is None:
        return _report(context, "STALE_RELOCATION", "RELOCATION_MISMATCH")

    relocation_is_issued = False
    if relocation is not None:
        try:
            require(relocation, _RELOCATION_ISSUER.tag)
            relocation_is_issued = True
        except SealError:
            return _report(context, "STALE_RELOCATION", "RELOCATION_UNVERIFIED")

    if archived_successor != current_path:
        if relocation is None:
            return _report(context, "STALE_RELOCATION", "RELOCATION_REQUIRED")
        if not relocation_is_issued:
            return _report(context, "STALE_RELOCATION", "RELOCATION_UNVERIFIED")
        approved_source = _normalized_path(relocation.source_path, strict=False)
        approved_target = _normalized_path(relocation.registered_path, strict=False)
        if approved_source != archived_successor or approved_target != current_path:
            return _report(context, "STALE_RELOCATION", "RELOCATION_MISMATCH")

    try:
        with tempfile.TemporaryDirectory(prefix="legacy001-home-") as home:
            git_dir = _git_directory(current_repo)
            if git_dir is None:
                return _report(context, "REPOSITORY_UNAVAILABLE")

            actual_git_dir = _git(
                current_repo, git_dir, home, "rev-parse", "--absolute-git-dir"
            )
            if actual_git_dir is None:
                return _report(context, "REPOSITORY_UNAVAILABLE")
            try:
                resolved_actual_git_dir = Path(
                    actual_git_dir.decode("utf-8", errors="strict").strip()
                ).resolve(strict=True)
            except (OSError, RuntimeError, UnicodeError):
                return _report(context, "REPOSITORY_UNAVAILABLE")
            if resolved_actual_git_dir != git_dir or not _inside(git_dir, current_repo):
                return _report(context, "REPOSITORY_UNAVAILABLE")

            worktree = _git(current_repo, git_dir, home, "rev-parse", "--is-inside-work-tree")
            if worktree != b"true\n":
                return _report(context, "REPOSITORY_UNAVAILABLE")
            if _git(
                current_repo,
                git_dir,
                home,
                "fsck",
                "--full",
                "--no-reflogs",
                "--connectivity-only",
            ) is None:
                return _report(context, "REPOSITORY_UNAVAILABLE")

            expected_refs = dict(evidence.refs)
            for ref, expected_oid in evidence.refs:
                actual_oid = _ref_oid(current_repo, git_dir, home, ref)
                if actual_oid is None:
                    return _report(context, "REF_MISSING")
                if actual_oid.strip().decode("ascii", errors="ignore") != expected_oid:
                    return _report(context, "REF_MISMATCH")

            reachable = _git(current_repo, git_dir, home, "rev-list", "--all")
            if reachable is None:
                return _report(context, "REPOSITORY_UNAVAILABLE")
            reachable_oids = set(reachable.decode("ascii", errors="ignore").splitlines())
            for oid in evidence.commit_oids:
                if oid not in reachable_oids:
                    return _report(context, "COMMIT_UNREACHABLE")

            for asset in evidence.binary_assets:
                if asset.ref not in expected_refs:
                    return _report(context, "INVALID_EVIDENCE")
                present, digest_matches = _has_binary(current_repo, git_dir, home, asset)
                if not present:
                    return _report(context, "BINARY_MISSING")
                if not digest_matches:
                    return _report(context, "BINARY_DIGEST_MISMATCH")

            present, digest_matches = _dirty_bytes(evidence.dirty_snapshot)
            if not present:
                return _report(context, "DIRTY_BYTES_MISSING")
            if not digest_matches:
                return _report(context, "DIRTY_DIGEST_MISMATCH")
    except _GitAbortError as failure:
        return _report(context, failure.code)

    return _report(context, None)
