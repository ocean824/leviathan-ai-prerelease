"""Contract acceptance probes for read-only legacy recovery verification.

Requirement-to-case map:
- cycle-1 ruling: replace earlier PASS expectations with
  REACHABLE_RESTORATION_NOT_VERIFIED; restoration remains NOT_VERIFIED
- complete reachable history/ref/binary/dirty evidence -> restoration not verified
- absent/mismatched refs -> REF_MISSING / REF_MISMATCH
- absent/changed binary -> BINARY_MISSING / BINARY_DIGEST_MISMATCH
- absent/changed archived dirty bytes -> DIRTY_BYTES_MISSING / DIRTY_DIGEST_MISMATCH
- unreachable commit and invalid repo -> exact blocked reason
- unapproved or inconsistent relocation -> STALE_RELOCATION
- hostile Git config and inherited GIT_* cannot execute or redirect work
- reports bind normalized repo, evidence and relocation digests; status never PASS
- timeout and output-cap failures return typed blocked reasons
- malformed evidence, including a historical ``passed`` flag alone -> no PASS
- repository and separate evidence tree remain byte-identical across verification
"""

from __future__ import annotations

import hashlib
import io
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from check_recoverability import (
    ApprovedRelocationV1,
    BinaryAssetEvidenceV1,
    DirtySnapshotEvidenceV1,
    ImportEvidenceV1,
    RecoveryError,
    require_recovery_report,
    verify_recoverability,
)

_BINARY = b"synthetic legacy asset bytes\x00\x01"
_DIRTY_SNAPSHOT = b"synthetic recoverable dirty snapshot\n"
_REF = "refs/heads/main"


def _git(repo: Path, *args: str) -> str:
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_AUTHOR_NAME": "Synthetic Acceptance",
            "GIT_AUTHOR_EMAIL": "acceptance@example.invalid",
            "GIT_COMMITTER_NAME": "Synthetic Acceptance",
            "GIT_COMMITTER_EMAIL": "acceptance@example.invalid",
        }
    )
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _make_evidence(tmp_path: Path) -> tuple[Path, ImportEvidenceV1, str]:
    repo = tmp_path / "registered-repo"
    repo.mkdir()
    _git(repo, "init", "--quiet", "--initial-branch=main")
    binary_path = repo / "assets" / "synthetic.bin"
    binary_path.parent.mkdir()
    binary_path.write_bytes(_BINARY)
    _git(repo, "add", "assets/synthetic.bin")
    _git(repo, "commit", "--quiet", "-m", "synthetic imported history")
    commit_oid = _git(repo, "rev-parse", "HEAD")

    snapshot_path = tmp_path / "evidence" / "dirty.snapshot"
    snapshot_path.parent.mkdir()
    snapshot_path.write_bytes(_DIRTY_SNAPSHOT)
    evidence = ImportEvidenceV1(
        source_path=str(repo),
        successor_path=str(repo),
        commit_oids=(commit_oid,),
        refs=((_REF, commit_oid),),
        binary_assets=(
            BinaryAssetEvidenceV1(
                ref=_REF,
                path="assets/synthetic.bin",
                sha256=_sha256(_BINARY),
            ),
        ),
        dirty_snapshot=DirtySnapshotEvidenceV1(
            path=snapshot_path,
            sha256=_sha256(_DIRTY_SNAPSHOT),
        ),
    )
    return repo, evidence, commit_oid


def _tree_bytes(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _status(report: object) -> str:
    return str(report.status)


def _assert_blocked(report: object, reason: str) -> None:
    assert _status(report) == "BLOCKED"
    assert report.blocked_reason == reason


def _assert_not_verified(report: object) -> None:
    assert _status(report) == "REACHABLE_RESTORATION_NOT_VERIFIED"
    assert report.blocked_reason is None
    assert report.restoration == "NOT_VERIFIED"


def test_complete_synthetic_evidence_never_claims_restoration_pass(
    tmp_path: Path,
) -> None:
    repo, evidence, _ = _make_evidence(tmp_path)
    before = _tree_bytes(tmp_path)

    report = verify_recoverability(repo, evidence)

    _assert_not_verified(report)
    assert _tree_bytes(tmp_path) == before


def test_dirty_worktree_is_preserved_and_does_not_replace_archived_dirty_evidence(
    tmp_path: Path,
) -> None:
    repo, evidence, _ = _make_evidence(tmp_path)
    (repo / "assets" / "synthetic.bin").write_bytes(b"current synthetic edit")
    (repo / "untracked.txt").write_bytes(b"current untracked synthetic bytes")
    before = _tree_bytes(tmp_path)

    report = verify_recoverability(repo, evidence)

    _assert_not_verified(report)
    assert _tree_bytes(tmp_path) == before


def test_missing_ref_is_blocked_and_repository_is_unchanged(tmp_path: Path) -> None:
    repo, evidence, commit_oid = _make_evidence(tmp_path)
    broken = replace(evidence, refs=(("refs/heads/missing", commit_oid),))
    before = _tree_bytes(tmp_path)

    report = verify_recoverability(repo, broken)

    _assert_blocked(report, "REF_MISSING")
    assert _tree_bytes(tmp_path) == before


def test_ref_target_mismatch_has_a_distinct_blocked_reason(tmp_path: Path) -> None:
    repo, evidence, _ = _make_evidence(tmp_path)
    broken = replace(evidence, refs=((_REF, "0" * 40),))

    report = verify_recoverability(repo, broken)

    _assert_blocked(report, "REF_MISMATCH")


def test_unreachable_commit_is_blocked(tmp_path: Path) -> None:
    repo, evidence, _ = _make_evidence(tmp_path)
    broken = replace(evidence, commit_oids=("0" * 40,))

    report = verify_recoverability(repo, broken)

    _assert_blocked(report, "COMMIT_UNREACHABLE")


def test_missing_binary_is_blocked_and_repository_is_unchanged(tmp_path: Path) -> None:
    repo, evidence, _ = _make_evidence(tmp_path)
    missing_binary = replace(
        evidence.binary_assets[0],
        path="assets/absent.bin",
    )
    broken = replace(evidence, binary_assets=(missing_binary,))
    before = _tree_bytes(tmp_path)

    report = verify_recoverability(repo, broken)

    _assert_blocked(report, "BINARY_MISSING")
    assert _tree_bytes(tmp_path) == before


def test_changed_binary_digest_is_blocked(tmp_path: Path) -> None:
    repo, evidence, _ = _make_evidence(tmp_path)
    changed_binary = replace(
        evidence.binary_assets[0],
        sha256=_sha256(b"different synthetic asset bytes"),
    )
    broken = replace(evidence, binary_assets=(changed_binary,))

    report = verify_recoverability(repo, broken)

    _assert_blocked(report, "BINARY_DIGEST_MISMATCH")


def test_missing_dirty_snapshot_bytes_are_blocked(tmp_path: Path) -> None:
    repo, evidence, _ = _make_evidence(tmp_path)
    evidence.dirty_snapshot.path.unlink()
    before = _tree_bytes(tmp_path)

    report = verify_recoverability(repo, evidence)

    _assert_blocked(report, "DIRTY_BYTES_MISSING")
    assert _tree_bytes(tmp_path) == before


def test_changed_dirty_snapshot_is_blocked_without_echoing_its_bytes(
    tmp_path: Path,
) -> None:
    repo, evidence, _ = _make_evidence(tmp_path)
    evidence.dirty_snapshot.path.write_bytes(b"changed synthetic snapshot bytes")

    report = verify_recoverability(repo, evidence)

    _assert_blocked(report, "DIRTY_DIGEST_MISMATCH")
    assert b"changed synthetic snapshot bytes" not in str(report).encode()


def test_non_git_registered_directory_is_repository_unavailable(tmp_path: Path) -> None:
    _, evidence, _ = _make_evidence(tmp_path)
    invalid_repo = tmp_path / "not-a-git-repository"
    invalid_repo.mkdir()
    evidence_for_invalid_repo = replace(evidence, successor_path=str(invalid_repo.resolve()))

    report = verify_recoverability(invalid_repo, evidence_for_invalid_repo)

    _assert_blocked(report, "REPOSITORY_UNAVAILABLE")


@pytest.mark.parametrize(
    ("relocation", "detail"),
    [(None, "RELOCATION_REQUIRED"), ("mismatched", "RELOCATION_UNVERIFIED")],
)
def test_stale_relocation_is_blocked_without_approved_matching_record(
    tmp_path: Path,
    relocation: str | None,
    detail: str,
) -> None:
    repo, evidence, _ = _make_evidence(tmp_path)
    stale_source = "C:/archived/old-repository"
    stale_evidence = replace(
        evidence,
        source_path=stale_source,
        successor_path=stale_source,
    )
    approved = (
        None
        if relocation is None
        else ApprovedRelocationV1(
            source_path="C:/different/source",
            registered_path=str(repo),
            approval_id="synthetic-approval-1",
        )
    )
    before = _tree_bytes(tmp_path)

    report = verify_recoverability(repo, stale_evidence, approved)

    _assert_blocked(report, "STALE_RELOCATION")
    assert report.detail == detail
    assert _tree_bytes(tmp_path) == before


def test_unissued_relocation_is_blocked_and_bound_in_report(
    tmp_path: Path,
) -> None:
    repo, evidence, _ = _make_evidence(tmp_path)
    old_path = "C:/archived/old-repository"
    relocated = replace(evidence, source_path=old_path, successor_path=old_path)
    forged = ApprovedRelocationV1(
        source_path=old_path,
        registered_path=str(repo),
        approval_id="synthetic-approval-1",
    )
    before = _tree_bytes(tmp_path)

    report = verify_recoverability(repo, relocated, forged)

    _assert_blocked(report, "STALE_RELOCATION")
    assert report.detail == "RELOCATION_UNVERIFIED"
    assert report.relocation_digest is not None
    assert report.relocation_approval_id is None
    assert _tree_bytes(tmp_path) == before


def test_report_binds_normalized_repository_evidence_and_relocation_digests(
    tmp_path: Path,
) -> None:
    repo, evidence, _ = _make_evidence(tmp_path)
    report = verify_recoverability(repo, evidence, clock_ns=lambda: 123456789)
    changed_evidence = verify_recoverability(
        repo,
        replace(evidence, source_path="C:/different/synthetic-source"),
        clock_ns=lambda: 123456789,
    )
    forged_relocation = ApprovedRelocationV1(
        source_path=str(repo),
        registered_path=str(repo),
        approval_id="synthetic-unissued",
    )
    with_relocation = verify_recoverability(
        repo,
        evidence,
        forged_relocation,
        clock_ns=lambda: 123456789,
    )

    _assert_not_verified(report)
    assert report.registered_repo_path == os.path.normcase(str(repo.resolve()))
    assert report.import_evidence_digest != "0" * 64
    assert changed_evidence.import_evidence_digest != report.import_evidence_digest
    assert report.relocation_digest is None
    assert report.checked_at_ns == 123456789
    assert with_relocation.relocation_digest is not None
    assert with_relocation.relocation_digest != report.relocation_digest
    assert with_relocation.relocation_approval_id is None
    assert require_recovery_report(report) == report

    forged_report = report.model_copy(update={"registered_repo_path": "C:/forged/repo"})
    with pytest.raises(RecoveryError):
        require_recovery_report(forged_report)


@pytest.mark.parametrize("hostile_setting", ["core.fsmonitor", "core.hooksPath"])
def test_hostile_fsmonitor_or_hook_marker_never_executes(
    tmp_path: Path,
    hostile_setting: str,
) -> None:
    repo, evidence, _ = _make_evidence(tmp_path)
    marker = tmp_path / "hostile-marker.txt"

    if hostile_setting == "core.fsmonitor":
        script = tmp_path / "fsmonitor-marker.py"
        script.write_text(
            "import pathlib, sys\n"
            "pathlib.Path(sys.argv[1]).write_text('executed', encoding='utf-8')\n",
            encoding="utf-8",
        )
        command = subprocess.list2cmdline([sys.executable, str(script), str(marker)])
        _git(repo, "config", "core.fsmonitor", command)
    else:
        hooks_path = tmp_path / "hostile-hooks"
        hooks_path.mkdir()
        hook = hooks_path / "post-checkout"
        hook.write_text(
            f'#!/bin/sh\nprintf "executed" > "{marker.as_posix()}"\n',
            encoding="utf-8",
        )
        hook.chmod(0o755)
        _git(repo, "config", "core.hooksPath", str(hooks_path))

    before = _tree_bytes(tmp_path)
    report = verify_recoverability(repo, evidence)

    _assert_not_verified(report)
    assert not marker.exists()
    assert _tree_bytes(tmp_path) == before


def test_inherited_git_environment_does_not_redirect_empty_repository(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_repo, evidence, _ = _make_evidence(tmp_path)
    empty_repo = tmp_path / "empty-not-a-repository"
    empty_repo.mkdir()
    monkeypatch.setenv("GIT_DIR", str(source_repo / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(source_repo))
    monkeypatch.setenv("GIT_OBJECT_DIRECTORY", str(source_repo / ".git" / "objects"))
    monkeypatch.setenv(
        "GIT_ALTERNATE_OBJECT_DIRECTORIES", str(source_repo / ".git" / "objects")
    )
    empty_evidence = replace(evidence, successor_path=str(empty_repo.resolve()))

    unavailable = verify_recoverability(empty_repo, empty_evidence)

    _assert_blocked(unavailable, "REPOSITORY_UNAVAILABLE")

    monkeypatch.setenv("GIT_DIR", str(empty_repo))
    monkeypatch.setenv("GIT_WORK_TREE", str(empty_repo))
    monkeypatch.setenv("GIT_OBJECT_DIRECTORY", str(empty_repo / "objects"))
    monkeypatch.setenv("GIT_ALTERNATE_OBJECT_DIRECTORIES", str(empty_repo / "objects"))
    actual_popen = subprocess.Popen
    child_environments: list[dict[str, str]] = []

    def capture_popen(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
        environment = kwargs["env"]
        assert isinstance(environment, dict)
        child_environments.append(environment)
        return actual_popen(*args, **kwargs)

    monkeypatch.setattr(subprocess, "Popen", capture_popen)

    report = verify_recoverability(source_repo, evidence)

    _assert_not_verified(report)
    assert report.registered_repo_path == os.path.normcase(str(source_repo.resolve()))
    assert child_environments
    for environment in child_environments:
        assert "GIT_DIR" not in environment
        assert "GIT_WORK_TREE" not in environment
        assert "GIT_OBJECT_DIRECTORY" not in environment
        assert "GIT_ALTERNATE_OBJECT_DIRECTORIES" not in environment


class _OutputProcess:
    def __init__(self, output: bytes, *, timeout: bool = False) -> None:
        self.stdout = io.BytesIO(output)
        self._timeout = timeout
        self._killed = False

    def poll(self) -> int | None:
        return None if self._timeout and not self._killed else 0

    def wait(self, timeout: float | None = None) -> int:
        if self._timeout and not self._killed:
            raise subprocess.TimeoutExpired("git", timeout)
        return 0

    def kill(self) -> None:
        self._killed = True


def test_git_timeout_is_reported_as_typed_blocked_reason(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, evidence, _ = _make_evidence(tmp_path)
    process = _OutputProcess(b"", timeout=True)
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: process)

    report = verify_recoverability(repo, evidence)

    _assert_blocked(report, "GIT_TIMEOUT")


def test_git_output_cap_is_reported_as_typed_blocked_reason(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, evidence, _ = _make_evidence(tmp_path)
    process = _OutputProcess(b"x" * (4 * 1024 * 1024 + 1))
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: process)

    report = verify_recoverability(repo, evidence)

    _assert_blocked(report, "OUTPUT_TOO_LARGE")


def test_invalid_evidence_does_not_pass_from_historical_pass_flag(
    tmp_path: Path,
) -> None:
    repo, _, _ = _make_evidence(tmp_path)
    malformed = SimpleNamespace(passed=True)
    before = _tree_bytes(repo)

    report = verify_recoverability(repo, malformed)

    _assert_blocked(report, "INVALID_EVIDENCE")
    assert _tree_bytes(repo) == before
