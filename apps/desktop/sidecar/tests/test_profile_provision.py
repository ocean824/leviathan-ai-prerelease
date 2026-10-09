"""Desktop profile transitions must preserve durable halt history or fail closed."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from leviathan_core.risk.halt_store import (
    LEGACY_UNKNOWN_REASON,
    HaltStore,
    ProfileClassification,
    ProvisionResult,
)

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import profile_provision

DIGEST = "a" * 64


def data_root(tmp_path: Path) -> Path:
    root = tmp_path / "LeviathanAI"
    (root / "data").mkdir(parents=True)
    return root


def test_never_provisioned_profile_starts_unhalted_and_writes_marker(tmp_path: Path) -> None:
    root = data_root(tmp_path)
    path, classification, result = profile_provision.provision_profile(
        root, preexisted=False, entry_digest=DIGEST
    )
    assert classification is ProfileClassification.NEVER_PROVISIONED
    assert result is ProvisionResult.CREATED
    with_store = HaltStore(path, path.parent)
    assert with_store.load() == {}
    with_store.close()
    marker = json.loads((root / "data/profile.json").read_text(encoding="utf-8"))
    assert marker["halt_store_provisioned"] is True
    assert marker["classification_used"] == "NEVER_PROVISIONED"


def test_pre_halt_install_starts_with_durable_unknown_halt(tmp_path: Path) -> None:
    root = data_root(tmp_path)
    path, classification, result = profile_provision.provision_profile(
        root, preexisted=True, entry_digest=DIGEST
    )
    assert classification is ProfileClassification.PRE_HALT_INSTALL
    assert result is ProvisionResult.CREATED
    store = HaltStore(path, path.parent)
    assert set(store.load()) == {LEGACY_UNKNOWN_REASON}
    store.close()


def test_valid_marker_and_store_are_already_provisioned(tmp_path: Path) -> None:
    root = data_root(tmp_path)
    path, _, _ = profile_provision.provision_profile(root, preexisted=False, entry_digest=DIGEST)
    marker = root / "data/profile.json"
    before = marker.read_bytes()
    _, classification, result = profile_provision.provision_profile(
        root, preexisted=True, entry_digest=DIGEST
    )
    assert classification is ProfileClassification.ALREADY_PROVISIONED
    assert result is ProvisionResult.ALREADY_VALIDATED
    assert marker.read_bytes() == before
    store = HaltStore(path, path.parent)
    assert store.load() == {}
    store.close()


def test_crash_after_store_commit_before_marker_write_recovers(tmp_path: Path, monkeypatch) -> None:
    root = data_root(tmp_path)
    path = root / "data/halt-state.sqlite3"

    def crash(*_args) -> None:
        raise profile_provision.ProfileProvisionError("INJECTED_MARKER_FAILURE")

    with monkeypatch.context() as patch:
        patch.setattr(profile_provision, "_write_marker", crash)
        with pytest.raises(profile_provision.ProfileProvisionError, match="INJECTED"):
            profile_provision.provision_profile(root, preexisted=False, entry_digest=DIGEST)
    assert path.is_file()
    assert not (root / "data/profile.json").exists()
    _, classification, result = profile_provision.provision_profile(
        root, preexisted=True, entry_digest=DIGEST
    )
    assert classification is ProfileClassification.ALREADY_PROVISIONED
    assert result is ProvisionResult.ALREADY_VALIDATED
    assert (root / "data/profile.json").is_file()


def test_marker_present_but_store_deleted_fails_closed(tmp_path: Path) -> None:
    root = data_root(tmp_path)
    path, _, _ = profile_provision.provision_profile(root, preexisted=False, entry_digest=DIGEST)
    path.unlink()
    with pytest.raises(profile_provision.ProfileProvisionError, match="HALT_STORE_MISSING"):
        profile_provision.provision_profile(root, preexisted=True, entry_digest=DIGEST)


@pytest.mark.parametrize(
    "name", ["halt-state.sqlite3-journal", "halt-state.sqlite3-wal", "halt-state.sqlite3.lock"]
)
def test_store_residue_without_store_fails_closed(tmp_path: Path, name: str) -> None:
    root = data_root(tmp_path)
    (root / "data" / name).write_bytes(b"residue")
    with pytest.raises(profile_provision.ProfileProvisionError, match="HALT_STORE_RESIDUE"):
        profile_provision.provision_profile(root, preexisted=False, entry_digest=DIGEST)


@pytest.mark.parametrize("contents", ["not-json", '{"schema_version": 99}', "{}"])
def test_malformed_or_unknown_marker_fails_closed(tmp_path: Path, contents: str) -> None:
    root = data_root(tmp_path)
    (root / "data/profile.json").write_text(contents, encoding="utf-8")
    with pytest.raises(profile_provision.ProfileProvisionError, match="PROFILE_MARKER_INVALID"):
        profile_provision.provision_profile(root, preexisted=False, entry_digest=DIGEST)


def test_invalid_existing_store_is_never_reprovisioned(tmp_path: Path) -> None:
    root = data_root(tmp_path)
    path = root / "data/halt-state.sqlite3"
    path.write_bytes(b"corrupt")
    with pytest.raises(profile_provision.ProfileProvisionError, match="HALT_STORE_UNAVAILABLE"):
        profile_provision.provision_profile(root, preexisted=False, entry_digest=DIGEST)
    assert path.read_bytes() == b"corrupt"


def test_reparse_profile_root_fails_closed(tmp_path: Path) -> None:
    target = data_root(tmp_path)
    link = tmp_path / "linked-profile"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("Windows symlink privilege is unavailable")
    with pytest.raises(profile_provision.ProfileProvisionError, match="PROFILE_REPARSE_POINT"):
        profile_provision.provision_profile(link, preexisted=True, entry_digest=DIGEST)
