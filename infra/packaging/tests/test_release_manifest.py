"""The released BOM must describe current staged bytes, even after a stale run."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from release_manifest import digest, release_record


def test_sidecar_bom_replaces_stale_file_and_release_rejects_mutation(tmp_path: Path) -> None:
    repo = tmp_path
    staged = repo / "apps/desktop/src-tauri/resources/sidecar"
    bundle = repo / "apps/desktop/src-tauri/target/release/bundle"
    nsis = bundle / "nsis"
    staged.mkdir(parents=True)
    nsis.mkdir(parents=True)
    (staged / "leviathan-desktop.exe").write_bytes(b"first build")
    bom = bundle / "leviathan-sidecar.cdx.json"
    bom.write_text('{"stale": true}', encoding="utf-8")

    script = Path(__file__).resolve().parents[1] / "release_manifest.py"
    subprocess.run(
        [sys.executable, str(script), "sidecar", "--repo", str(repo)],
        check=True,
        capture_output=True,
    )
    contents = json.loads(bom.read_text(encoding="utf-8"))
    assert "stale" not in contents
    assert contents["components"][0]["hashes"][0]["content"] == digest(
        staged / "leviathan-desktop.exe"
    )

    installer = nsis / "Leviathan AI_0.1.0_x64-setup.exe"
    installer.write_bytes(b"installer")
    webview = repo / "webview.exe"
    webview.write_bytes(b"offline runtime")
    lock = repo / "apps/desktop/src-tauri/Cargo.lock"
    lock.write_text(
        'version = 4\n[[package]]\nname = "tauri"\nversion = "2.12.0"\n', encoding="utf-8"
    )
    ui_lock = repo / "apps/terminal/package-lock.json"
    ui_lock.parent.mkdir(parents=True)
    ui_lock.write_text(
        '{"packages": {"node_modules/react": {"version": "19.2.7"}}}', encoding="utf-8"
    )
    (repo / "apps/desktop/README.md").write_text("source", encoding="utf-8")
    fixture = repo / "apps/desktop/sidecar/tests/fixtures/risk_governance_v1.lock.yaml"
    fixture.parent.mkdir(parents=True)
    fixture.write_text("synthetic: true\n", encoding="utf-8")
    (repo / "infra/packaging").mkdir(parents=True)
    (repo / "infra/packaging/acceptance.json").write_text('{"generated": true}', encoding="utf-8")
    record = release_record(repo, installer, staged, bom, webview)
    assert record["installer"]["sha256"] == digest(installer)
    assert record["sidecar"]["bom"]["sha256"] == digest(bom)
    assert record["rust"]["components"][0]["version"] == "2.12.0"
    assert record["ui"]["components"][0]["version"] == "19.2.7"
    assert "acceptance.json" not in (repo / "infra/packaging/SHA256-INVENTORY.txt").read_text(
        encoding="utf-8"
    )
    inventory = (repo / "infra/packaging/SHA256-INVENTORY.txt").read_text(encoding="utf-8")
    assert f"{digest(fixture)}  {fixture.relative_to(repo).as_posix()}" in inventory
    assert record["sourceInventory"]["sha256"] == digest(
        repo / "infra/packaging/SHA256-INVENTORY.txt"
    )

    (staged / "leviathan-desktop.exe").write_bytes(b"second build")
    with pytest.raises(RuntimeError, match="does not match"):
        release_record(repo, installer, staged, bom, webview)
