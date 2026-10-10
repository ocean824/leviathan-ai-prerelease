from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
HANDOFF = ROOT / "qa/handoffs/API-ANYTHING-001"
START = HANDOFF / "cycle-4-start.json"
OUTPUT = HANDOFF / "cycle-4.md"
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
EXCLUDED_PREFIXES = (
    "qa/integration-backups/",
    "qa/acceptance/API-ANYTHING-001/cycle2/",
)
OWNED_ELSEWHERE = {
    "packages/leviathan-market-data/src/leviathan_market_data/public_sources/registry.py",
    "packages/leviathan-market-data/src/leviathan_market_data/public_sources/sources.py",
    "packages/leviathan-market-data/src/leviathan_market_data/public_sources/__init__.py",
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def omitted(relative: str) -> bool:
    parts = Path(relative).parts
    return (
        relative in OWNED_ELSEWHERE
        or relative == OUTPUT.relative_to(ROOT).as_posix()
        or any(relative.startswith(prefix) for prefix in EXCLUDED_PREFIXES)
        or any(part in EXCLUDED_PARTS for part in parts)
    )


def current_files() -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(ROOT).as_posix()
        if omitted(relative):
            continue
        result[relative] = {
            "sha256": sha256(path),
            "bytes": path.stat().st_size,
        }
    return result


def main() -> None:
    start = json.loads(START.read_text(encoding="utf-8"))
    baseline = {item["path"]: item for item in start["files"] if not omitted(item["path"])}
    current = current_files()
    changes: list[tuple[str, str, str, str, object]] = []
    for relative in sorted(set(baseline) | set(current)):
        old = baseline.get(relative)
        new = current.get(relative)
        if old is None:
            changes.append(("added", relative, "-", str(new["sha256"]), new["bytes"]))
        elif new is None:
            changes.append(("deleted", relative, str(old["sha256"]), "-", "-"))
        elif old["sha256"] != new["sha256"]:
            changes.append(
                ("modified", relative, str(old["sha256"]), str(new["sha256"]), new["bytes"])
            )

    statuses = ("added", "modified", "deleted")
    counts = {status: sum(row[0] == status for row in changes) for status in statuses}
    start_sha = sha256(START)
    lines = [
        "# API-ANYTHING-001 Cycle 4 freeze ledger",
        "",
        f"- Generated at: `{datetime.now(UTC).isoformat(timespec='seconds')}`",
        f"- Baseline: C4 start manifest ({start['file_count']} files; SHA-256 `{start_sha}`)",
        f"- Source Cycle 3 ledger SHA-256: `{start['source_ledger_sha256']}`",
        f"- Diff totals: {counts['added']} added, {counts['modified']} modified, "
        f"{counts['deleted']} deleted.",
        "- Excluded generated/cache directories: `.git`, `.venv`, `node_modules`, `target`, "
        "`dist`, "
        "Python caches, `.scratch`, and `.vendor-build`.",
        "- Excluded the three shared `public_sources` files owned by PUBLIC-DATA-001, "
        "integration backups, and independent `qa/acceptance/API-ANYTHING-001/cycle2/` files.",
        "",
        "## Cycle 4 changes",
        "",
        "- The learn canary merges structured 403/429/503 wall signals into the vendor result, "
        "resets the signal per request, and routes a recorded 403 wall through the built vendor "
        "and hand-off logic. The production stdio test exercises learn dispatch in "
        "replay-only mode.",
        "- Added per-operation native-to-contract response recipes, passed them to `addOperation`, "
        "and recorded the recipe digest, fixture origin, and review note in candidate and pin "
        "metadata. Realistic native bodies for all five operations pass the built extractor and "
        "strict schemas.",
        "- HTML fixture sanitization removes scripts, forms, hidden fields, credentials, and "
        "patterned personal values; tests cover Fed and Senate-style pages. JSON redaction is "
        "value/pattern based.",
        "- First-seen is write-once per source key plus content hash. A persisted monotonic floor "
        "prevents clock rollback from moving new stamps backward. Three-fetch regression coverage "
        "passes.",
        "- Raw fixture replay stores temporary homes under app data and bypasses network pacing. "
        "The real-vendor test verifies replay completes under one second at a five-second cadence.",
        "- Removed the dead `headlessUserAgent()` / `probeHeadlessUA()` implementation from the "
        "vendor patch and built runtime. Removed the stray worktree `artifacts/` copy and verified "
        "it is absent.",
        "- Live learning remains paused; no operation is pinned or activated. Candidates require "
        "writer, acceptance, review, and coordinator integration before a committed pin can serve.",
        "",
        "## Verification",
        "",
        "| Gate | Result | Scope |",
        "|---|---:|---|",
        "| `npm test` | 21 passed | Sidecar unit tests and production stdio end-to-end tests |",
        "| Market-data pytest | 1,150 passed | Explicit C4 package source path; all tests |",
        "| Coordinator finding acceptance | 9 passed, 210 deselected, 3 xfailed, 1 xpassed | "
        "`-k finding`; independent cycle2 directory excluded |",
        "| Cycle 1 production-policy acceptance | 60 passed | "
        "`qa/acceptance/API-ANYTHING-001/cycle1` |",
        "| Ruff | scoped pass; 67 legacy F811 findings in whole-tree run | Excluded "
        "integration backups and acceptance cycle1/cycle2; changed harnesses and ledger script "
        "pass independently |",
        "| mypy | passed | Default (442 files), Linux, and Darwin client-platform runs |",
        "| Broad legacy acceptance collection | 116 failed, 103 passed, 3 xfailed, 1 xpassed | "
        "Not a C4 gate: it expects old unpinned status and client envelopes, and its ledger test "
        "hard-codes the previous freeze; independent cycle2 remains excluded |",
        "",
        "All C4 changes are included before hashing this ledger. No live learning was performed. "
        "The sidecar does not serve any operation until a reviewed, hash-pinned registry entry is "
        "integrated. The independent cycle2 acceptance directory was not modified or included in "
        "the ledger; its owner-maintained tests are separate from this lane.",
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
    print(f"wrote {OUTPUT}; {len(changes)} changed files; start SHA-256 {start_sha}")


if __name__ == "__main__":
    main()
