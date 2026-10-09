from __future__ import annotations

import hashlib
import os
import subprocess
import threading
from dataclasses import replace
from pathlib import Path
from typing import Any

import check_recoverability as verifier
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


def _git(path: Path, *args: str) -> bytes:
    completed = subprocess.run(
        ["git", *args], cwd=path, capture_output=True, check=True
    )
    return completed.stdout


def _repository(path: Path) -> tuple[str, str]:
    path.mkdir()
    _git(path, "init", "-b", "main")
    _git(path, "config", "user.name", "Synthetic Fixture")
    _git(path, "config", "user.email", "fixture@example.invalid")
    asset_path = path / "assets" / "archive.bin"
    asset_path.parent.mkdir()
    asset_path.write_bytes(b"synthetic binary fixture\x00\x01")
    _git(path, "add", "assets/archive.bin")
    _git(path, "commit", "-m", "synthetic import commit")
    commit = _git(path, "rev-parse", "HEAD").decode("ascii").strip()
    ref_oid = _git(path, "show-ref", "--verify", "--hash", "refs/heads/main").decode(
        "ascii"
    ).strip()
    return commit, ref_oid


def _evidence(repo: Path, tmp_path: Path) -> ImportEvidenceV1:
    commit, actual_ref_oid = _repository(repo)
    dirty = tmp_path / "archived-dirty.patch"
    dirty_bytes = b"synthetic recorded dirty patch bytes\n"
    dirty.write_bytes(dirty_bytes)
    return ImportEvidenceV1(
        source_path="C:/synthetic/legacy",
        successor_path=str(repo.resolve()),
        commit_oids=(commit,),
        refs=(("refs/heads/main", actual_ref_oid),),
        binary_assets=(
            BinaryAssetEvidenceV1(
                "refs/heads/main",
                "assets/archive.bin",
                hashlib.sha256(b"synthetic binary fixture\x00\x01").hexdigest(),
            ),
        ),
        dirty_snapshot=DirtySnapshotEvidenceV1(dirty, hashlib.sha256(dirty_bytes).hexdigest()),
    )


def test_reachable_synthetic_evidence_passes_and_does_not_change_repo(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    evidence = _evidence(repo, tmp_path)
    before = _git(repo, "status", "--porcelain=v1")

    result = verify_recoverability(repo, evidence)

    assert (result.status, result.blocked_reason) == (
        "REACHABLE_RESTORATION_NOT_VERIFIED",
        None,
    )
    assert result.restoration == "NOT_VERIFIED"
    assert require_recovery_report(result) is result
    assert _git(repo, "status", "--porcelain=v1") == before


def test_missing_ref_has_exact_blocked_reason_even_when_commit_is_elsewhere(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    evidence = _evidence(repo, tmp_path)
    _git(repo, "tag", "retained", evidence.commit_oids[0])
    _git(repo, "update-ref", "-d", "refs/heads/main")

    result = verify_recoverability(repo, evidence)

    assert (result.status, result.blocked_reason) == ("BLOCKED", "REF_MISSING")


def test_missing_binary_has_exact_blocked_reason(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    evidence = _evidence(repo, tmp_path)
    missing = replace(
        evidence,
        binary_assets=(
            BinaryAssetEvidenceV1(
                "refs/heads/main",
                "assets/not-retained.bin",
                evidence.binary_assets[0].sha256,
            ),
        ),
    )

    result = verify_recoverability(repo, missing)

    assert (result.status, result.blocked_reason) == ("BLOCKED", "BINARY_MISSING")


def test_dirty_bytes_missing_has_exact_blocked_reason(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    evidence = _evidence(repo, tmp_path)
    evidence.dirty_snapshot.path.unlink()

    result = verify_recoverability(repo, evidence)

    assert (result.status, result.blocked_reason) == ("BLOCKED", "DIRTY_BYTES_MISSING")


def test_dirty_bytes_changed_has_exact_blocked_reason_without_echo(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    evidence = _evidence(repo, tmp_path)
    secret_fixture = b"synthetic dirty payload must never appear in output"
    evidence.dirty_snapshot.path.write_bytes(secret_fixture)

    result = verify_recoverability(repo, evidence)

    assert (result.status, result.blocked_reason) == ("BLOCKED", "DIRTY_DIGEST_MISMATCH")
    assert secret_fixture.decode() not in str(result)


def test_stale_relocation_blocks_until_explicit_mapping_is_supplied(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    evidence = _evidence(repo, tmp_path)
    stale = replace_evidence_successor(evidence, "C:/old/location/repo")

    blocked = verify_recoverability(repo, stale)
    approved = verifier._RELOCATION_ISSUER.issue(  # noqa: SLF001
        ApprovedRelocationV1(
            source_path="C:/old/location/repo",
            registered_path=str(repo.resolve()),
            approval_id="synthetic-approval-01",
        )
    )
    passed = verify_recoverability(repo, stale, approved)

    assert (blocked.status, blocked.blocked_reason) == ("BLOCKED", "STALE_RELOCATION")
    assert (passed.status, passed.blocked_reason) == (
        "REACHABLE_RESTORATION_NOT_VERIFIED",
        None,
    )
    assert passed.relocation_approval_id == "synthetic-approval-01"
    assert passed.relocation_digest is not None


def test_unissued_relocation_is_rejected_and_never_passes(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    evidence = replace_evidence_successor(_evidence(repo, tmp_path), "C:/old/repo")
    forged = ApprovedRelocationV1("C:/old/repo", str(repo.resolve()), "x")

    report = verify_recoverability(repo, evidence, forged)

    assert (report.status, report.blocked_reason, report.detail) == (
        "BLOCKED",
        "STALE_RELOCATION",
        "RELOCATION_UNVERIFIED",
    )
    assert report.relocation_approval_id is None
    assert report.restoration == "NOT_VERIFIED"


def replace_evidence_successor(evidence: ImportEvidenceV1, path: str) -> ImportEvidenceV1:
    return replace(evidence, successor_path=path)


def test_ref_mismatch_and_binary_digest_mismatch_are_distinct(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    evidence = _evidence(repo, tmp_path)
    wrong_ref = replace(evidence, refs=(("refs/heads/main", "0" * len(evidence.refs[0][1])),))
    assert verify_recoverability(repo, wrong_ref).blocked_reason == "REF_MISMATCH"

    wrong_digest = ImportEvidenceV1(
        source_path=evidence.source_path,
        successor_path=evidence.successor_path,
        commit_oids=evidence.commit_oids,
        refs=(("refs/heads/main", evidence.refs[0][1]),),
        binary_assets=(
            BinaryAssetEvidenceV1("refs/heads/main", "assets/archive.bin", "a" * 64),
        ),
        dirty_snapshot=evidence.dirty_snapshot,
    )
    assert verify_recoverability(repo, wrong_digest).blocked_reason == "BINARY_DIGEST_MISMATCH"



def test_malformed_evidence_error_is_typed_and_does_not_retain_value() -> None:
    secret = "credential-like-synthetic-fixture"
    with pytest.raises(RecoveryError) as caught:
        BinaryAssetEvidenceV1("refs/heads/main", "../" + secret, "a" * 64)

    assert caught.value.code == "INVALID_EVIDENCE"
    assert secret not in str(caught.value)
    assert secret not in repr(caught.value.__dict__)


def test_verifier_invokes_only_hardened_read_only_git_queries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    evidence = _evidence(repo, tmp_path)
    real_popen = subprocess.Popen
    commands: list[list[str]] = []
    environments: list[dict[str, str]] = []

    def checked_popen(command: list[str], **kwargs: Any) -> Any:
        commands.append(command)
        environments.append(kwargs["env"])
        assert kwargs["shell"] is False
        return real_popen(command, **kwargs)

    monkeypatch.setattr(subprocess, "Popen", checked_popen)
    result = verify_recoverability(repo, evidence)

    assert result.status == "REACHABLE_RESTORATION_NOT_VERIFIED"
    assert commands
    subcommands = {command[command.index("--no-replace-objects") + 1] for command in commands}
    assert subcommands == {"rev-parse", "fsck", "show-ref", "rev-list", "show"}
    for command in commands:
        assert "--no-replace-objects" in command
        assert all(
            value in command
            for value in (
                "core.fsmonitor=false",
                f"core.hooksPath={os.devnull}",
                "core.sshCommand=",
                "protocol.allow=never",
                "core.alternateRefsCommand=",
                "uploadpack.packObjectsHook=",
            )
        )
        assert f"--git-dir={repo / '.git'}" in command
        assert f"--work-tree={repo}" in command
    assert all("GIT_DIR" not in environment for environment in environments)
    assert all(environment["GIT_CONFIG_NOSYSTEM"] == "1" for environment in environments)
    assert all(environment["GIT_NO_REPLACE_OBJECTS"] == "1" for environment in environments)
    assert all("GIT_DIR" not in key for environment in environments for key in environment)


def test_repo_local_fsmonitor_command_never_runs(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    evidence = _evidence(repo, tmp_path)
    marker = tmp_path / "fsmonitor-marker.txt"
    command = f'cmd.exe /c echo executed ^> "{marker}"'
    _git(repo, "config", "core.fsmonitor", command)

    report = verify_recoverability(repo, evidence)

    assert report.status == "REACHABLE_RESTORATION_NOT_VERIFIED"
    assert not marker.exists()


def test_inherited_git_dir_cannot_redirect_verification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    other = tmp_path / "other"
    evidence = _evidence(other, tmp_path)
    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.setenv("GIT_DIR", str(other / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(other))
    monkeypatch.setenv("GIT_OBJECT_DIRECTORY", str(other / ".git" / "objects"))
    monkeypatch.setenv("GIT_ALTERNATE_OBJECT_DIRECTORIES", str(other / ".git" / "objects"))

    report = verify_recoverability(empty, replace(evidence, successor_path=str(empty.resolve())))

    assert (report.status, report.blocked_reason) == ("BLOCKED", "REPOSITORY_UNAVAILABLE")


def test_replace_refs_cannot_substitute_verified_binary_bytes(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    evidence = _evidence(repo, tmp_path)
    original_oid = _git(repo, "rev-parse", "refs/heads/main:assets/archive.bin").decode().strip()
    replacement = tmp_path / "replacement.bin"
    replacement.write_bytes(b"synthetic substituted blob")
    replacement_oid = _git(repo, "hash-object", "-w", str(replacement)).decode().strip()
    _git(repo, "replace", original_oid, replacement_oid)

    report = verify_recoverability(repo, evidence)

    assert report.status == "REACHABLE_RESTORATION_NOT_VERIFIED"


def test_report_binds_normalized_repo_evidence_and_time(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    evidence = _evidence(repo, tmp_path)

    report = verify_recoverability(repo, evidence, clock_ns=lambda: 123456789)
    changed = verify_recoverability(
        repo,
        replace(evidence, source_path="C:/another/source"),
        clock_ns=lambda: 123456789,
    )

    assert report.registered_repo_path == os.path.normcase(str(repo.resolve()))
    assert report.import_evidence_digest != "0" * 64
    assert changed.import_evidence_digest != report.import_evidence_digest
    assert report.checked_at_ns == 123456789
    assert report.restoration == "NOT_VERIFIED"
    assert report.status == "REACHABLE_RESTORATION_NOT_VERIFIED"

    copied = report.model_copy(update={"registered_repo_path": "C:/forged/repo"})
    with pytest.raises(RecoveryError):
        require_recovery_report(copied)


class _StubProcess:
    def __init__(self, data: bytes, *, block: bool = False) -> None:
        self.stdout = _StubPipe(data, block=block)
        self._exit = threading.Event()
        if not block:
            self._exit.set()

    def poll(self) -> int | None:
        return 0 if self._exit.is_set() else None

    def wait(self, timeout: float | None = None) -> int:
        self._exit.wait(timeout)
        return 0 if self._exit.is_set() else 1

    def kill(self) -> None:
        self._exit.set()
        self.stdout.release.set()


class _StubPipe:
    def __init__(self, data: bytes, *, block: bool) -> None:
        self.data = data
        self.block = block
        self.release = threading.Event()

    def read(self, size: int) -> bytes:
        if self.block:
            self.release.wait()
            return b""
        chunk, self.data = self.data[:size], self.data[size:]
        return chunk


def test_git_output_cap_returns_typed_code(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    git_dir = repo / ".git"
    git_dir.mkdir()
    fake = _StubProcess(b"x" * (verifier._MAX_GIT_OUTPUT + 1))  # noqa: SLF001
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: fake)

    with pytest.raises(verifier._GitAbortError) as caught:  # noqa: SLF001
        verifier._git(repo, git_dir, str(tmp_path), "rev-parse", "HEAD")  # noqa: SLF001

    assert caught.value.code == "OUTPUT_TOO_LARGE"
    assert str(caught.value) == "OUTPUT_TOO_LARGE"


def test_git_timeout_returns_typed_code(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    git_dir = repo / ".git"
    git_dir.mkdir()
    fake = _StubProcess(b"", block=True)
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: fake)
    monkeypatch.setattr(verifier, "_GIT_DEFAULT_TIMEOUT_SECONDS", 0)

    with pytest.raises(verifier._GitAbortError) as caught:  # noqa: SLF001
        verifier._git(repo, git_dir, str(tmp_path), "rev-parse", "HEAD")  # noqa: SLF001

    assert caught.value.code == "GIT_TIMEOUT"
    assert str(caught.value) == "GIT_TIMEOUT"
