"""Create deterministic inventories for one Windows desktop installer build.

The sidecar CycloneDX BOM inventories staged *files*, not the build venv. Rust
and UI lockfiles inventory resolved components separately in the release record.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tomllib
from pathlib import Path


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def write_json(path: Path, value: object) -> None:
    temporary = path.with_name(path.name + ".new")
    temporary.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def sidecar_files(staged: Path) -> list[dict[str, object]]:
    files = []
    for path in sorted(staged.rglob("*")):
        if path.is_file():
            files.append(
                {
                    "path": path.relative_to(staged).as_posix(),
                    "bytes": path.stat().st_size,
                    "sha256": digest(path),
                }
            )
    if not files or not any(item["path"] == "leviathan-desktop.exe" for item in files):
        raise RuntimeError("The staged sidecar executable is missing")
    return files


def sidecar_bom(files: list[dict[str, object]]) -> dict[str, object]:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "leviathan-desktop-sidecar",
                "version": "0.1.0",
            },
            "properties": [
                {
                    "name": "inventory:scope",
                    "value": (
                        "staged PyInstaller one-folder files; "
                        "not a Python distribution dependency graph"
                    ),
                }
            ],
        },
        "components": [
            {
                "type": "file",
                "bom-ref": "sidecar:" + str(item["path"]),
                "name": str(item["path"]),
                "hashes": [{"alg": "SHA-256", "content": item["sha256"]}],
                "properties": [{"name": "inventory:bytes", "value": str(item["bytes"])}],
            }
            for item in files
        ],
    }


def source_inventory(repo: Path) -> str:
    roots = (repo / "apps" / "desktop", repo / "infra" / "packaging")
    excluded = {
        ".venv",
        ".tmp",
        "target",
        "resources",
        "gen",
        "build",
        "dist",
        "__pycache__",
        ".pytest_cache",
        "node_modules",
    }
    allowed = {
        ".gitignore",
        ".py",
        ".ps1",
        ".js",
        ".mjs",
        ".rs",
        ".toml",
        ".lock",
        ".json",
        ".md",
        ".html",
        ".spec",
        ".ico",
        ".yaml",
    }
    lines = []
    for root in roots:
        for path in root.rglob("*"):
            if not path.is_file() or any(part in excluded for part in path.relative_to(root).parts):
                continue
            relative = path.relative_to(root).as_posix()
            if (
                root.name == "packaging"
                and relative not in {"README.md", "release_manifest.py"}
                and not (relative.startswith("tests/") and path.suffix == ".py")
            ):
                continue
            if "generated" in path.relative_to(root).parts and path.name != ".gitignore":
                continue
            if path.name in allowed or path.suffix in allowed:
                lines.append(f"{digest(path)}  {path.relative_to(repo).as_posix()}")
    if not lines:
        raise RuntimeError("Source inventory is empty")
    return "\n".join(sorted(lines, key=lambda line: line.split("  ", 1)[1])) + "\n"


def release_record(
    repo: Path, installer: Path, staged: Path, bom: Path, webview: Path
) -> dict[str, object]:
    bundle = repo / "apps" / "desktop" / "src-tauri" / "target" / "release" / "bundle"
    files = sidecar_files(staged)
    current_bom = json.loads(bom.read_text(encoding="utf-8"))
    if current_bom != sidecar_bom(files):
        raise RuntimeError("Sidecar BOM does not match the current staged files")
    source_path = repo / "infra" / "packaging" / "SHA256-INVENTORY.txt"
    source_path.write_text(source_inventory(repo), encoding="utf-8", newline="\n")
    rust_lock = repo / "apps" / "desktop" / "src-tauri" / "Cargo.lock"
    ui_lock = repo / "apps" / "terminal" / "package-lock.json"
    rust = tomllib.loads(rust_lock.read_text(encoding="utf-8"))
    ui = json.loads(ui_lock.read_text(encoding="utf-8"))
    ui_packages = ui["packages"]
    result = {
        "schemaVersion": 1,
        "scope": (
            "unsigned Windows NSIS installer; inventories list staged sidecar "
            "files and lockfile-resolved Rust/UI build inputs"
        ),
        "installer": {
            "path": installer.relative_to(repo).as_posix(),
            "bytes": installer.stat().st_size,
            "sha256": digest(installer),
        },
        "sidecar": {
            "bom": {"path": bom.relative_to(repo).as_posix(), "sha256": digest(bom)},
            "fileCount": len(files),
            "filesSha256": hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest(),
        },
        "rust": {
            "lockfileSha256": digest(rust_lock),
            "components": [
                {"name": pkg["name"], "version": pkg["version"], "checksum": pkg.get("checksum")}
                for pkg in rust["package"]
            ],
        },
        "ui": {
            "lockfileSha256": digest(ui_lock),
            "components": [
                {
                    "path": name,
                    "version": pkg.get("version"),
                    "integrity": pkg.get("integrity"),
                    "buildOnly": pkg.get("dev", False),
                }
                for name, pkg in sorted(ui_packages.items())
                if name
            ],
        },
        "webview": {
            "delivery": "Tauri offlineInstaller",
            "installerCacheFile": webview.name,
            "installerCacheBytes": webview.stat().st_size,
            "installerCacheSha256": digest(webview),
            "note": (
                "Hash identifies the offline runtime input cached by Tauri; "
                "the NSIS installer hash binds the final package."
            ),
        },
        "sourceInventory": {
            "path": source_path.relative_to(repo).as_posix(),
            "sha256": digest(source_path),
        },
    }
    if not bundle.is_dir():
        raise RuntimeError("Release bundle directory is missing")
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=("sidecar", "release"))
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--webview", type=Path)
    args = parser.parse_args()
    repo = args.repo.resolve()
    staged = repo / "apps" / "desktop" / "src-tauri" / "resources" / "sidecar"
    bundle = repo / "apps" / "desktop" / "src-tauri" / "target" / "release" / "bundle"
    bundle.mkdir(parents=True, exist_ok=True)
    bom = bundle / "leviathan-sidecar.cdx.json"
    if args.phase == "sidecar":
        bom.unlink(missing_ok=True)
        files = sidecar_files(staged)
        write_json(bom, sidecar_bom(files))
        print(f"Sidecar CycloneDX file BOM: {len(files)} files, SHA-256 {digest(bom)}")
        return
    if args.webview is None or not args.webview.is_file():
        raise RuntimeError("Exact cached WebView2 offline installer is required")
    installers = sorted((bundle / "nsis").glob("*-setup.exe"))
    if len(installers) != 1:
        raise RuntimeError(f"Expected one NSIS installer, found {len(installers)}")
    record = release_record(repo, installers[0], staged, bom, args.webview)
    target = bundle / "release-manifest.json"
    write_json(target, record)
    print(f"Release manifest: {target}, SHA-256 {digest(target)}")


if __name__ == "__main__":
    main()
