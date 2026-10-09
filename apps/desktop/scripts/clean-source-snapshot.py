"""Copy only reviewable source into an empty tree for a clean PKG build."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

SOURCE_EXTENSIONS = {
    ".py",
    ".pyi",
    ".ts",
    ".tsx",
    ".js",
    ".mjs",
    ".rs",
    ".toml",
    ".yaml",
    ".yml",
    ".md",
    ".json",
    ".lock",
    ".spec",
    ".ico",
    ".html",
}
EXCLUDED_PARTS = {
    ".git",
    ".local",
    ".venv",
    ".tmp",
    "node_modules",
    "target",
    "dist",
    "build",
    "__pycache__",
    ".pytest_cache",
    "generated",
    "gen",
}
UNTRACKED_PREFIXES = ("apps/api/", "apps/terminal/", "packages/", "tests/", "infra/risk/")


def git_paths(repo: Path, *args: str) -> set[str]:
    result = subprocess.run(
        ["git", "ls-files", "-z", *args], cwd=repo, check=True, capture_output=True
    )
    return {item.decode("utf-8") for item in result.stdout.split(b"\0") if item}


def allowed(path: str) -> bool:
    if path.replace("\\", "/").endswith("/generated/.gitignore"):
        return True
    parts = Path(path).parts
    lowered = {part.lower() for part in parts}
    if lowered & EXCLUDED_PARTS or "leviathan_api_keys.txt" in lowered:
        return False
    if Path(path).name.lower() in {".env", ".env.local"}:
        return False
    return Path(path).suffix.lower() not in {".pem", ".pfx", ".key", ".p12"}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    repo = args.repo.resolve()
    destination = args.destination.resolve()
    expected_parent = (repo / "apps/desktop/.tmp").resolve()
    if not destination.is_relative_to(expected_parent) or destination.exists():
        raise RuntimeError("Destination must be a fresh directory under apps/desktop/.tmp")
    sys.path.insert(0, str(repo))
    from infra.packaging.release_manifest import source_inventory

    owned = {line.split("  ", 1)[1] for line in source_inventory(repo).splitlines()}
    tracked = git_paths(repo)
    new = git_paths(repo, "--others", "--exclude-standard")
    untracked = {
        path
        for path in new
        if path in owned
        or (path.startswith(UNTRACKED_PREFIXES) and Path(path).suffix in SOURCE_EXTENSIONS)
    }
    selected = sorted(path for path in tracked | untracked | owned if allowed(path))
    if not selected or "pyproject.toml" not in selected or "uv.lock" not in selected:
        raise RuntimeError("Required root source manifests are missing")
    destination.mkdir(parents=True)
    copied = []
    for relative in selected:
        source = repo / relative
        if not source.is_file() or source.is_symlink():
            raise RuntimeError(f"Unsafe or missing source file: {relative}")
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        copied.append({"path": relative, "sha256": hashlib.sha256(target.read_bytes()).hexdigest()})
    manifest = {
        "scope": "fresh source snapshot; no prior dependency/build/staged outputs",
        "sourceCount": len(copied),
        "sourceFiles": copied,
    }
    evidence = destination / "infra/packaging/clean-snapshot-manifest.json"
    evidence.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(f"Clean source snapshot: {destination}; {len(copied)} files")
    print(f"Manifest SHA-256: {hashlib.sha256(evidence.read_bytes()).hexdigest()}")


if __name__ == "__main__":
    main()
