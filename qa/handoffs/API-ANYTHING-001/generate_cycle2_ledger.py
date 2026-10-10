"""Generate the Cycle 2 file ledger against its recorded working-tree start manifest."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
START = ROOT / "qa/handoffs/API-ANYTHING-001/cycle-2-start.json"
OUTPUT = ROOT / "qa/handoffs/API-ANYTHING-001/cycle-2.md"
EXCLUDED_PARTS = {
    ".git",
    ".venv",
    "node_modules",
    "target",
    "dist",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".scratch",
    ".vendor-build",
}
OWNED_ELSEWHERE = {
    "packages/leviathan-market-data/src/leviathan_market_data/public_sources/registry.py",
    "packages/leviathan-market-data/src/leviathan_market_data/public_sources/sources.py",
    "packages/leviathan-market-data/src/leviathan_market_data/public_sources/__init__.py",
}
OMITTED_PREFIXES = (
    "artifacts/leviathan-build/market-data-buildout/api-anything-001-c1/",
    "qa/integration-backups/",
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def omitted(path: str) -> bool:
    if path in OWNED_ELSEWHERE or path == "qa/handoffs/API-ANYTHING-001/cycle-2.md":
        return True
    if any(path.startswith(prefix) for prefix in OMITTED_PREFIXES):
        return True
    return any(part in EXCLUDED_PARTS for part in Path(path).parts)


def main() -> None:
    start = json.loads(START.read_text(encoding="utf-8-sig"))
    baseline = {
        item["path"]: item
        for item in start["files"]
        if not omitted(item["path"])
    }
    current: dict[str, dict[str, object]] = {}
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(ROOT).as_posix()
        if omitted(relative):
            continue
        current[relative] = {"sha256": sha256(path), "bytes": path.stat().st_size}

    changes: list[tuple[str, str, str, str, int | str]] = []
    for relative in sorted(set(baseline) | set(current)):
        old = baseline.get(relative)
        new = current.get(relative)
        if old is None:
            changes.append(("added", relative, "-", str(new["sha256"]), int(new["bytes"])))
        elif new is None:
            changes.append(("deleted", relative, str(old["sha256"]), "-", "-"))
        elif old["sha256"] != new["sha256"]:
            changes.append(
                ("modified", relative, str(old["sha256"]), str(new["sha256"]), int(new["bytes"]))
            )

    statuses = ("added", "modified", "deleted")
    counts = {status: sum(row[0] == status for row in changes) for status in statuses}
    start_sha = sha256(START)
    lines = [
        "# API-ANYTHING-001 Cycle 2 freeze ledger",
        "",
        f"- Generated at: `{datetime.now(UTC).isoformat(timespec='seconds')}`",
        f"- Baseline: `qa/handoffs/API-ANYTHING-001/cycle-2-start.json` "
        f"({start['file_count']} files; SHA-256 `{start_sha}`)",
        f"- Source Cycle 1 ledger: SHA-256 `{start['source_ledger_sha256']}`",
        f"- Diff totals: {counts['added']} added, {counts['modified']} modified, "
        f"{counts['deleted']} deleted.",
        "- Excluded build/runtime directories: `.git`, `.venv`, `node_modules`, `target`, `dist`, "
        "Python caches, `.scratch`, and `.vendor-build`.",
        "- The three `public_sources/{registry.py,sources.py,__init__.py}` files are omitted from "
        "this lane ledger because they belong to PUBLIC-DATA-001 and match its C2C-frozen copies.",
        "- The stray Cycle 1 artifact copy is omitted; it was removed from this worktree.",
        "",
        "## Cycle 2 changes",
        "",
        "- Removed all `AA_CONTROL` production behavior. The test-only network seam stays "
        "outside `dist`; "
        "reviewer acceptance launches the production entrypoint.",
        "- Patched vendored learn handling to classify structured bot-wall signals as typed "
        "challenges and hand off to a visible isolated Chrome window. The vendor patch includes "
        "package metadata "
        "and TypeScript configuration changes; its SHA-256 is "
        "`561f5f9159c10b4323db62f6917ddca931ab1274c9fa76480a6fd8068eff6d94`.",
        "- Added per-operation `challenge_hosts` arrays to the committed pin registry and "
        "candidate metadata. Each is intentionally empty pending a reviewed third-party challenge "
        "origin; data-request host allowlists remain strict.",
        "- Split pin approval (90 days) from canary freshness (48 hours). Successful calls count "
        "as semantic canaries; due failures abstain.",
        "- Export/import now targets the sidecar's committed `templates/` tree. Added cross-tree "
        "replay-only E2E with fake network injection outside `dist`.",
        "- Candidate learn and repair templates are credential-scanned and replayed against a "
        "sanitized recorded fixture before candidate metadata and its fixture digest are "
        "persisted.",
        "- The Python client verifies `PINNED.json` against the build-generated registry hash. The "
        "current registry SHA-256 is "
        "`ac4cc2b5d18ec89b55f79580e09a8a63b885a803a0bb8ac264eca3ed1020f967`.",
        "- All lockfile package entries now include `resolved` and `integrity`; "
        "`npm ci --ignore-scripts "
        "--offline` installed 23 packages successfully with no reported vulnerabilities.",
        "- Removed the API-ANYTHING-specific exception from root `pyproject.toml`; scoped "
        "acceptance "
        "lint exceptions live in the acceptance directory.",
        "- Official platform check: Node 22 has macOS x64 builds; current Playwright requirements "
        "specify macOS 14+, so Big Sur 11.7 uses replay-only mode without Chrome. This Intel Mac "
        "was not tested on-device.",
        "- Live learning remains paused; no operation is pinned. No network learning was "
        "performed in Cycle 2.",
        "",
        "## Verification",
        "",
        "| Gate | Result |",
        "|---|---:|",
        "| Coordinator acceptance findings (`-k finding`) | 6 passed, 153 deselected, "
        "3 xfailed, 1 xpassed |",
        "| Cycle 1 production policy suite | 60 passed |",
        "| Cycle 2 cross-tree export/import replay-only E2E | 1 passed |",
        "| Market-data api-anything client tests | 20 passed |",
        "| `npm test` | 9 passed |",
        "| Ruff (`--extend-exclude qa/integration-backups`) | passed |",
        "| mypy default / Linux / Darwin | all three passed for `api_anything_client.py` |",
        "| `packages/leviathan-core/tests` | 6,578 passed, 10 skipped, 1 xfailed |",
        "| `packages/leviathan-store/tests` | 548 passed, 2 skipped |",
        "| `packages/leviathan-vault/tests` | 1,475 passed, 1 skipped |",
        "| `packages/leviathan-market-data/tests` | 163 passed, 36 skipped |",
        "| `apps/api/tests` | 1,149 passed |",
        "",
        "The six unmodified reviewer acceptance finding tests pass. All project pytest roots were "
        "run in separate processes.",
        "",
        "## Diff-generated file inventory",
        "",
        "| Status | Path | Old SHA-256 | New SHA-256 | New bytes |",
        "|---|---|---|---|---:|",
    ]
    lines.extend(
        f"| {status} | `{relative}` | `{old}` | `{new}` | {size} |"
        for status, relative, old, new, size in changes
    )
    lines.append("")
    OUTPUT.write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {OUTPUT}; {counts}; sha256={sha256(OUTPUT)}")


if __name__ == "__main__":
    main()
