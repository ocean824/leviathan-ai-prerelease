from __future__ import annotations

import hashlib
import json
import sys
import tempfile
from pathlib import Path

import pytest

from leviathan_core.research.replay_job import (
    ReplayArtifacts,
    ReplayJobError,
    VerifiedReplayArtifactsV1,
    canonical_bytes,
    load_verified_replay_result,
    require_verified_replay_artifacts,
    run_replay_job,
    verify_replay_artifacts,
)
from leviathan_core.strategy_ingest import paper_promotion

_PACKAGE_ROOT = Path(__file__).parents[2]
_FIXTURE = _PACKAGE_ROOT / "tests" / "fixtures" / "replay_job" / "v1-nq.json"
_RISK_LOCK = _PACKAGE_ROOT / "tests" / "fixtures" / "replay_job" / "risk_lock.yaml"
_MEMBERS = (
    "input.canonical.json",
    "input.sha256",
    "result.canonical.json",
    "result.sha256",
    "diagnostics.json",
    "risk_audit.jsonl",
)


def _artifacts(tmp_path: Path) -> ReplayArtifacts:
    return run_replay_job(_FIXTURE, _RISK_LOCK, tmp_path / "replay")


def _rewrite_complete(root: Path) -> None:
    files = {name: root.joinpath(name).read_bytes() for name in _MEMBERS}
    hashes = {name: hashlib.sha256(contents).hexdigest() for name, contents in files.items()}
    marker = {
        "schema_version": "leviathan.replay-complete/1",
        "files": hashes,
        "input_sha256": hashes["input.canonical.json"],
        "result_sha256": hashes["result.canonical.json"],
    }
    root.joinpath("COMPLETE").write_bytes(canonical_bytes(marker))


def _track_tempdirs(
    monkeypatch: pytest.MonkeyPatch,
) -> list[tempfile.TemporaryDirectory[str]]:
    original_tempdir = tempfile.TemporaryDirectory
    created: list[tempfile.TemporaryDirectory[str]] = []

    def tracked_tempdir(
        *, prefix: str | None = None
    ) -> tempfile.TemporaryDirectory[str]:
        value = original_tempdir(prefix=prefix)
        created.append(value)
        return value

    monkeypatch.setattr(tempfile, "TemporaryDirectory", tracked_tempdir)
    return created


def test_reproduction_accepts_genuine_bundle_and_cleans_temp_on_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifacts = _artifacts(tmp_path)
    verified = verify_replay_artifacts(artifacts)
    created = _track_tempdirs(monkeypatch)

    assert paper_promotion._replay_is_reproduced(verified, _RISK_LOCK.read_bytes())
    assert len(created) == 1
    assert not Path(created[0].name).exists()


def test_reproduction_cleans_temp_after_runner_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    verified = verify_replay_artifacts(_artifacts(tmp_path))
    created = _track_tempdirs(monkeypatch)

    def fail_run(*_args: object, **_kwargs: object) -> ReplayArtifacts:
        raise RuntimeError("synthetic reproduction failure")

    monkeypatch.setattr(paper_promotion, "run_replay_job", fail_run)

    assert not paper_promotion._replay_is_reproduced(verified, _RISK_LOCK.read_bytes())
    assert len(created) == 1
    assert not Path(created[0].name).exists()


def test_reproduction_rejects_consistently_rewritten_blocked_result(
    tmp_path: Path,
) -> None:
    manifest = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    manifest["risk"]["initial_halts"] = ["synthetic-test-halt"]
    fixture = tmp_path / "halted-input.json"
    fixture.write_text(json.dumps(manifest), encoding="utf-8")
    artifacts = run_replay_job(fixture, _RISK_LOCK, tmp_path / "halted-run")
    root = artifacts.complete_path.parent
    result = json.loads(artifacts.result_path.read_text(encoding="utf-8"))
    assert result["status"] == "blocked"

    result["status"] = "completed"
    result_bytes = canonical_bytes(result)
    artifacts.result_path.write_bytes(result_bytes)
    artifacts.result_path.with_name("result.sha256").write_bytes(
        (hashlib.sha256(result_bytes).hexdigest() + "\n").encode("ascii")
    )
    diagnostics_path = root / "diagnostics.json"
    diagnostics = json.loads(diagnostics_path.read_text(encoding="utf-8"))
    diagnostics["status"] = "completed"
    diagnostics_path.write_bytes(canonical_bytes(diagnostics))
    _rewrite_complete(root)
    rewritten = ReplayArtifacts(
        hashlib.sha256((root / "input.canonical.json").read_bytes()).hexdigest(),
        hashlib.sha256(result_bytes).hexdigest(),
        root / "input.canonical.json",
        root / "result.canonical.json",
        root / "COMPLETE",
    )
    verified = verify_replay_artifacts(rewritten)
    assert verified.result_status == "completed"

    assert not paper_promotion._replay_is_reproduced(verified, _RISK_LOCK.read_bytes())


def test_replay_readback_returns_typed_sealed_complete_bundle(tmp_path: Path) -> None:
    artifacts = _artifacts(tmp_path)

    verified = verify_replay_artifacts(artifacts)

    assert type(verified) is VerifiedReplayArtifactsV1
    assert require_verified_replay_artifacts(verified) is verified
    assert verified.status == "COMPLETE"
    assert verified.provenance == "C102_COMPLETE_REHASHED"
    assert len(verified.artifact_sha256) == 6
    assert verified.dataset_id == "synthetic-nq-opening-range"
    assert verified.strategy_id == "synthetic-nq-breakout-v1"
    assert verified.first_bar_ns == 1_776_263_700_000_000_000
    assert verified.last_bar_ns == 1_776_263_880_000_000_000
    loaded = load_verified_replay_result(verified)
    result_path = artifacts.result_path
    assert canonical_bytes(loaded.model_dump(mode="json")) == result_path.read_bytes()
    assert loaded.status == "completed"


def test_result_loader_rehashes_after_the_verified_issue(tmp_path: Path) -> None:
    artifacts = _artifacts(tmp_path)
    verified = verify_replay_artifacts(artifacts)
    artifacts.result_path.write_bytes(artifacts.result_path.read_bytes() + b" ")

    with pytest.raises(ReplayJobError) as error:
        load_verified_replay_result(verified)

    assert error.value.code == "ARTIFACT_INVALID"
    assert str(error.value) == "ARTIFACT_INVALID: replay result evidence is invalid"


@pytest.mark.parametrize(
    "name",
    (
        "input.canonical.json",
        "result.canonical.json",
        "COMPLETE",
        "risk_audit.jsonl",
    ),
)
def test_replay_readback_rejects_tampered_files(tmp_path: Path, name: str) -> None:
    artifacts = _artifacts(tmp_path)
    path = artifacts.complete_path.parent / name
    path.write_bytes(path.read_bytes() + b" ")

    with pytest.raises(ReplayJobError) as error:
        verify_replay_artifacts(artifacts)

    assert error.value.code == "ARTIFACT_INVALID"
    assert str(error.value) == "ARTIFACT_INVALID: replay artifact set is invalid"


def test_replay_readback_rejects_missing_and_extra_files(tmp_path: Path) -> None:
    artifacts = _artifacts(tmp_path)
    artifacts.complete_path.parent.joinpath("diagnostics.json").unlink()
    with pytest.raises(ReplayJobError, match=r"^ARTIFACT_INVALID:"):
        verify_replay_artifacts(artifacts)

    other = _artifacts(tmp_path / "other")
    other.complete_path.parent.joinpath("extra.txt").write_text("extra", encoding="utf-8")
    with pytest.raises(ReplayJobError, match=r"^ARTIFACT_INVALID:"):
        verify_replay_artifacts(other)


def test_replay_readback_rejects_noncomplete_status_and_lock_mismatch(
    tmp_path: Path,
) -> None:
    artifacts = _artifacts(tmp_path)
    root = artifacts.complete_path.parent
    diagnostics = json.loads(root.joinpath("diagnostics.json").read_text(encoding="utf-8"))
    diagnostics["status"] = "failed"
    root.joinpath("diagnostics.json").write_bytes(canonical_bytes(diagnostics))
    _rewrite_complete(root)
    with pytest.raises(ReplayJobError, match=r"^ARTIFACT_INVALID:"):
        verify_replay_artifacts(artifacts)

    other = _artifacts(tmp_path / "other")
    root = other.complete_path.parent
    result = json.loads(root.joinpath("result.canonical.json").read_text(encoding="utf-8"))
    result["verified_lock_sha256"] = "0" * 64
    root.joinpath("result.canonical.json").write_bytes(canonical_bytes(result))
    root.joinpath("result.sha256").write_text(
        hashlib.sha256(root.joinpath("result.canonical.json").read_bytes()).hexdigest() + "\n",
        encoding="ascii",
    )
    _rewrite_complete(root)
    with pytest.raises(ReplayJobError, match=r"^ARTIFACT_INVALID:"):
        verify_replay_artifacts(other)


def test_replay_readback_rejects_symlink(tmp_path: Path) -> None:
    artifacts = _artifacts(tmp_path)
    path = artifacts.complete_path.parent / "input.canonical.json"
    target = tmp_path / "target.json"
    target.write_bytes(path.read_bytes())
    path.unlink()
    try:
        path.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are unavailable on this host")

    with pytest.raises(ReplayJobError) as error:
        verify_replay_artifacts(artifacts)

    assert error.value.code == "ARTIFACT_INVALID"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows junction check")
@pytest.mark.parametrize(
    ("location", "operation"),
    (
        ("root", "verify"),
        ("root", "load"),
        ("nested", "verify"),
        ("nested", "load"),
    ),
)
def test_replay_readback_rejects_junctions(tmp_path: Path, location: str, operation: str) -> None:
    import _winapi

    artifacts = _artifacts(tmp_path)
    verified = verify_replay_artifacts(artifacts) if operation == "load" else None
    root = artifacts.complete_path.parent
    target = tmp_path / "junction-target"
    target.mkdir()
    if location == "root":
        root.rename(target / "bundle")
        _winapi.CreateJunction(str(target / "bundle"), str(root))
    else:
        _winapi.CreateJunction(str(target), str(root / "nested"))

    with pytest.raises(ReplayJobError) as error:
        if operation == "verify":
            verify_replay_artifacts(artifacts)
        else:
            assert verified is not None
            load_verified_replay_result(verified)

    assert error.value.code == "ARTIFACT_INVALID"
