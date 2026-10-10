from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
HANDOFF = ROOT / "qa/handoffs/API-ANYTHING-001"
START = HANDOFF / "cycle-3-start.json"
OUTPUT = HANDOFF / "cycle-3.md"
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
        "# API-ANYTHING-001 Cycle 3 freeze ledger",
        "",
        f"- Generated at: `{datetime.now(UTC).isoformat(timespec='seconds')}`",
        f"- Baseline: C3 start manifest ({start['file_count']} files; SHA-256 `{start_sha}`)",
        f"- Source Cycle 2 ledger SHA-256: `{start['source_ledger_sha256']}`",
        f"- Diff totals: {counts['added']} added, {counts['modified']} modified, "
        f"{counts['deleted']} deleted.",
        "- Excluded generated/cache directories: `.git`, `.venv`, `node_modules`, `target`, "
        "`dist`, "
        "Python caches, `.scratch`, and `.vendor-build`.",
        "- Excluded the three shared `public_sources` files owned by PUBLIC-DATA-001, "
        "integration backups, and independent `qa/acceptance/API-ANYTHING-001/cycle2/` files.",
        "",
        "## Cycle 3 changes",
        "",
        "- Completed learn challenge hand-off for both vendor warning and 200 interstitial paths "
        "using the real vendor and recorded challenge fixtures.",
        "- Applied live wall-clock date checks only to live rows; fixture rows use their recorded "
        "`fetched_at` for semantic validation.",
        "- Candidate replay now runs sanitized raw response bodies through the template and "
        "compares extracted rows with the fixture's typed rows.",
        "- Added `skipPacing` to the internal vendor execution options and used it only for local "
        "fixture replay. The test runs the real vendor call path with a fake fetch response at a "
        "5-second site pace, "
        "then asserts fixture replay finishes in under 1 second.",
        "- Preserved challenge-host exceptions for the visible challenge window while keeping "
        "robots rules on data hosts; retained import containment and strict native output checks.",
        "- Live learning remains paused and the committed pin registry still has no active learned "
        "templates.",
        "",
        "## Verification",
        "",
        "| Gate | Result | Scope |",
        "|---|---:|---|",
        "| `npm test` | 15 passed | Sidecar unit and stdio end-to-end tests |",
        "| Targeted market-data pytest | 21 passed | API-Anything client and template-transfer "
        "tests |",
        "| Coordinator finding acceptance | 12 passed, 299 deselected, 3 xfailed, 1 xpassed | "
        "`-k finding`; independent cycle2 folder excluded |",
        "| Cycle 1 production-policy acceptance | 60 passed | Separate acceptance root |",
        "| Ruff | passed | `--extend-exclude qa/integration-backups,qa/acceptance/"
        "API-ANYTHING-001/cycle2` |",
        "| mypy | passed | Default, `--platform linux`, and `--platform darwin` for "
        "`api_anything_client.py` |",
        "| Independent Cycle 2 acceptance suite | 43 failed, 49 passed | Excluded from this "
        "ledger; owner-maintained fixture setup still expects the legacy envelope |",
        "",
        "The C3 fixture-pacing regression is covered by the real-vendor test. The preceding "
        "paced call uses a fake fetch response; local replay adds no pacing wait and performs no "
        "network request. "
        "The independent Cycle 2 suite is reported as a limitation, not as a pass.",
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
