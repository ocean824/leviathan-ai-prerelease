"""Offline contract checks for the separate ADMIN-APP-001 desktop client."""

from __future__ import annotations

import json
import os
import re
import subprocess
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
APP = ROOT / "apps" / "admin"
UI = APP / "ui"
TAURI = APP / "src-tauri"
SIX_STATUSES = ["ACTIVE", "PAST_DUE", "PAUSED", "SUSPENDED", "CANCELED", "EXPIRED"]


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _config() -> dict[str, object]:
    return json.loads(_text(TAURI / "tauri.conf.json"))


def _ui_source_files() -> list[Path]:
    return sorted(path for path in (UI / "src").rglob("*") if path.is_file())


def test_admin_shell_has_no_python_sidecar() -> None:
    config_text = (TAURI / "tauri.conf.json").read_text(encoding="utf-8").casefold()
    build_script = APP / "scripts" / "build.ps1"
    tauri_build_script = TAURI / "build.rs"
    assert build_script.is_file()
    assert tauri_build_script.is_file()
    build_text = _text(build_script).casefold()
    tauri_build_text = _text(tauri_build_script).casefold()
    for text in (config_text, build_text, tauri_build_text):
        assert "python" not in text
        assert "pyinstaller" not in text
        assert "sidecar" not in text
    config = _config()
    bundle = config["bundle"]
    assert isinstance(bundle, dict)
    assert "externalBin" not in bundle


def test_csp_allows_only_local_app_and_configured_https_worker() -> None:
    config = _config()
    app = config["app"]
    assert isinstance(app, dict)
    security = app["security"]
    assert isinstance(security, dict)
    csp = security["csp"]
    assert isinstance(csp, str)
    match = re.search(r"(?:^|;)\s*connect-src\s+([^;]+)", csp)
    assert match is not None
    connect_sources = match.group(1).split()
    worker_sources = [source for source in connect_sources if source.startswith("https://")]
    assert len(connect_sources) == 2
    assert set(connect_sources) == {"'self'", worker_sources[0]}
    assert len(worker_sources) == 1
    assert not any(
        "*" in source or source in {"http:", "ws:", "wss:"} for source in connect_sources
    )

    vite = _text(UI / "vite.config.ts")
    fallback = re.search(r"fallbackWorkerOrigin\s*=\s*['\"](https://[^'\"]+)['\"]", vite)
    assert fallback is not None
    configured = os.environ.get("VITE_ADMIN_WORKER_ORIGIN", fallback.group(1))
    assert re.fullmatch(r"https://[A-Za-z0-9.-]+(?::[0-9]{1,5})?", configured)
    assert worker_sources == [configured]
    validator = re.search(r"parsed\.protocol\s*!==\s*'https:'", vite)
    assert validator is not None


def test_tauri_identity_and_updater_channel_are_admin_specific() -> None:
    admin = _config()
    desktop_path = ROOT / "apps" / "desktop" / "src-tauri" / "tauri.conf.json"
    desktop = json.loads(_text(desktop_path))
    assert admin["identifier"] != desktop["identifier"]
    assert admin["productName"] != desktop["productName"]
    assert isinstance(admin["identifier"], str) and admin["identifier"].endswith(".admin")
    bundle = admin["bundle"]
    assert isinstance(bundle, dict)
    assert "icons/icon.ico" in bundle["icon"]
    assert (TAURI / "icons" / "icon.ico").is_file()

    updater = admin["plugins"]["updater"]
    endpoints = updater["endpoints"]
    assert updater["endpoints"]
    assert all("/admin/" in endpoint for endpoint in endpoints)
    assert all("/desktop/" not in endpoint for endpoint in endpoints)


def test_ui_has_exact_six_statuses_and_no_trial_text_or_persistent_token_storage() -> None:
    models = _text(UI / "src" / "api" / "models.ts")
    status_line = re.search(r"SUBSCRIPTION_STATUSES\s*=\s*\[([^]]*)\]", models)
    assert status_line is not None
    statuses = re.findall(r"['\"]([A-Z_]+)['\"]", status_line.group(1))
    assert statuses == SIX_STATUSES

    files = _ui_source_files()
    assert files
    for path in files:
        text = _text(path)
        assert "trial" not in text.casefold(), path.relative_to(UI)
        assert not re.search(
            r"(?:localStorage|sessionStorage)\s*(?:\.\s*(?:setItem|removeItem|clear)\s*\(|\[\s*['\"])",
            text,
        ), path.relative_to(UI)
        assert not re.search(r"(?:localStorage|sessionStorage)\s*\.\s*setItem", text)


def test_six_admin_screens_and_fake_api_mutation_case_pass() -> None:
    app_source = _text(UI / "src" / "AdminApp.tsx")
    for label in (
        "Sign in",
        "Accounts",
        "Users & Roles",
        "Subscriptions",
        "Devices",
        "Audit",
    ):
        assert label in app_source
    assert 'data-testid="admin-app"' in app_source

    result = subprocess.run(
        [
            "npm.cmd",
            "run",
            "test",
            "--",
            "--config",
            "../qa/vitest.config.ts",
        ],
        cwd=UI,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
    )
    assert result.returncode == 0, f"UI Vitest failed:\n{result.stdout}\n{result.stderr}"


def test_rust_dependencies_and_lockfile_use_exact_pins() -> None:
    manifest_path = TAURI / "Cargo.toml"
    manifest = tomllib.loads(_text(manifest_path).lstrip("\ufeff"))
    expected = {
        "tauri-build": "=2.7.0",
        "tauri": "=2.12.0",
        "tauri-plugin-updater": "=2.13.1",
        "tauri-plugin-process": "=2.3.1",
    }
    groups = ("build-dependencies", "dependencies")
    declared: dict[str, str] = {}
    for group in groups:
        declared.update(
            {
                name: value["version"]
                for name, value in manifest.get(group, {}).items()
                if isinstance(value, dict) and "version" in value
            }
        )
    for name, version in expected.items():
        assert declared[name] == version

    lock = tomllib.loads(_text(TAURI / "Cargo.lock"))
    packages = {package["name"]: package["version"] for package in lock["package"]}
    for name, version in expected.items():
        assert packages[name] == version.removeprefix("=")
