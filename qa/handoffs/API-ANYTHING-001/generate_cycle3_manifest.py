from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
EXCLUDED_PARTS = {
    ".git", ".venv", "node_modules", "target", "dist", "__pycache__",
    ".pytest_cache", ".mypy_cache", ".ruff_cache", ".scratch", ".vendor-build",
}
OWNED_ELSEWHERE = {
    "packages/leviathan-market-data/src/leviathan_market_data/public_sources/registry.py",
    "packages/leviathan-market-data/src/leviathan_market_data/public_sources/sources.py",
    "packages/leviathan-market-data/src/leviathan_market_data/public_sources/__init__.py",
}
EXCLUDED_PREFIXES = (
    "artifacts/leviathan-build/market-data-buildout/api-anything-001-c1/",
    "qa/integration-backups/",
    "qa/acceptance/API-ANYTHING-001/cycle2/",
)


def omitted(relative: str) -> bool:
    return (
        relative in OWNED_ELSEWHERE
        or any(relative.startswith(prefix) for prefix in EXCLUDED_PREFIXES)
        or any(part in EXCLUDED_PARTS for part in Path(relative).parts)
    )


def main() -> None:
    files = []
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(ROOT).as_posix()
        if omitted(relative) or relative.endswith("cycle-3-start.json"):
            continue
        files.append(
            {
                "path": relative,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "bytes": path.stat().st_size,
            }
        )
    files.sort(key=lambda item: item["path"])
    manifest = {
        "cycle": "API-ANYTHING-001-C3",
        "created_at": datetime.now(UTC).isoformat(),
        "source_tree": "api-anything-001-c2",
        "source_ledger_sha256": "a900b25debe9f63da02723e8d70092f93d1b50d7aca377c55be00939e4cbdcf6",
        "file_count": len(files),
        "exclusions": [
            "build/cache directories",
            "PUBLIC-DATA-001 public_sources files",
            "Cycle 1 stray artifact",
            "qa/acceptance/API-ANYTHING-001/cycle2 (independent acceptance files)",
        ],
        "files": files,
    }
    output = ROOT / "qa/handoffs/API-ANYTHING-001/cycle-3-start.json"
    output.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {output}; {len(files)} files")


if __name__ == "__main__":
    main()
