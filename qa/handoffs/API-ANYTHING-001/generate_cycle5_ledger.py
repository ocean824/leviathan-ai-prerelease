from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

# The generator emits long, exact test IDs and report prose into the ledger.
# ruff: noqa: E501

ROOT = Path(__file__).resolve().parents[3]
HANDOFF = ROOT / "qa/handoffs/API-ANYTHING-001"
START = HANDOFF / "cycle-5-start.json"
OUTPUT = HANDOFF / "cycle-5.md"
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
        or relative in {OUTPUT.relative_to(ROOT).as_posix(), START.relative_to(ROOT).as_posix()}
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
        result[relative] = {"sha256": sha256(path), "bytes": path.stat().st_size}
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
            changes.append(("modified", relative, str(old["sha256"]), str(new["sha256"]), new["bytes"]))

    statuses = ("added", "modified", "deleted")
    counts = {status: sum(row[0] == status for row in changes) for status in statuses}
    start_sha = sha256(START)
    c1_failures = [
        "test_c1_pins_policy.py::test_pinned_operation_serves_typed_provenanced_records_through_the_real_runtime[calendar.fed]",
        "test_c1_pins_policy.py::test_pinned_operation_serves_typed_provenanced_records_through_the_real_runtime[earnings.forward]",
        "test_c1_pins_policy.py::test_pinned_operation_serves_typed_provenanced_records_through_the_real_runtime[senate.efd.ptr]",
        "test_c1_pins_policy.py::test_pinned_operation_serves_typed_provenanced_records_through_the_real_runtime[cboe.daily.stats]",
        "test_c1_pins_policy.py::test_pinned_operation_serves_typed_provenanced_records_through_the_real_runtime[cnn.fear_greed]",
        "test_c1_pins_policy.py::test_stale_canary_runs_a_new_canary_before_serving",
        "test_c1_pins_policy.py::test_template_pointing_at_a_foreign_host_is_blocked_before_any_request",
        "test_c1_pins_policy.py::test_redirect_to_another_host_is_blocked_and_never_followed",
        "test_c1_pins_policy.py::test_redirect_within_the_allowed_host_is_followed",
        "test_c1_pins_policy.py::test_http_downgrade_redirect_is_blocked",
        "test_c1_pins_policy.py::test_robots_disallow_blocks_the_data_request",
        "test_c1_pins_policy.py::test_robots_specific_allow_beats_broader_disallow_and_our_agent_group_wins",
        "test_c1_pins_policy.py::test_robots_server_error_fails_closed_but_404_means_allowed",
        "test_c1_pins_policy.py::test_robots_policy_is_cached_on_disk_between_restarts",
        "test_c1_pins_policy.py::test_semantically_wrong_rows_are_rejected[cnn.fear_greed-stale observation-<lambda>]",
        "test_c1_pins_policy.py::test_semantically_wrong_rows_are_rejected[cnn.fear_greed-future observation-<lambda>]",
        "test_c1_pins_policy.py::test_semantically_wrong_rows_are_rejected[cnn.fear_greed-empty result-<lambda>]",
        "test_c1_pins_policy.py::test_semantically_wrong_rows_are_rejected[cnn.fear_greed-duplicate ids-<lambda>]",
        "test_c1_pins_policy.py::test_semantically_wrong_rows_are_rejected[calendar.fed-empty event name-<lambda>]",
        "test_c1_pins_policy.py::test_semantically_wrong_rows_are_rejected[calendar.fed-scheduled absurdly far away-<lambda>]",
        "test_c1_pins_policy.py::test_semantically_wrong_rows_are_rejected[earnings.forward-ticker lowercase-<lambda>]",
        "test_c1_pins_policy.py::test_semantically_wrong_rows_are_rejected[earnings.forward-scheduled two years back-<lambda>]",
        "test_c1_pins_policy.py::test_semantically_wrong_rows_are_rejected[senate.efd.ptr-report on a foreign host-<lambda>]",
        "test_c1_pins_policy.py::test_semantically_wrong_rows_are_rejected[senate.efd.ptr-no transactions-<lambda>]",
        "test_c1_pins_policy.py::test_semantically_wrong_rows_are_rejected[cboe.daily.stats-value out of range-<lambda>]",
        "test_c1_pins_policy.py::test_semantically_wrong_rows_are_rejected[cboe.daily.stats-stale-<lambda>]",
        "test_c1_pins_policy.py::test_semantically_wrong_rows_are_rejected[cboe.daily.stats-term structure without maturity-<lambda>]",
        "test_c1_pins_policy.py::test_schema_invalid_rows_are_rejected",
        "test_c2_template_transfer_replay.py::test_cross_tree_export_import_then_replay_only_call_succeeds",
    ]
    lines = [
        "# API-ANYTHING-001 Cycle 5 freeze ledger",
        "",
        f"- Generated at: `{datetime.now(UTC).isoformat(timespec='seconds')}`",
        f"- Baseline: C5 start manifest ({start['file_count']} files; SHA-256 `{start_sha}`)",
        f"- Source Cycle 4 ledger SHA-256: `{start['source_ledger_sha256']}`",
        f"- Diff totals: {counts['added']} added, {counts['modified']} modified, {counts['deleted']} deleted.",
        "- Excluded generated/cache directories: `.git`, `.venv`, `node_modules`, `target`, `dist`, Python caches, `.scratch`, and `.vendor-build`.",
        "- Excluded the three shared `public_sources` files owned by PUBLIC-DATA-001, integration backups, and independent `qa/acceptance/API-ANYTHING-001/cycle2/` files.",
        "",
        "## Cycle 5 changes",
        "",
        "- Fixture sanitation now accepts each operation's native mapping recipe. It preserves the values selected by `extract`/`pick`, and redacts only unconsumed fields. Per-operation tests feed realistic JSON bodies with multi-word capitalized values through the built vendor extractor and assert `extract(sanitized) == extract(raw)` for all five operations.",
        "- Fed and Senate mapping recipes remain JSON and now have registry-level `recorded-native-body-required` pin gates. The runtime rejects a pin for either operation unless its mapping provenance is a recorded native body from a live response.",
        "- `templateMatchesMapping` runs against each committed template at call time before fixture replay or request serving.",
        "- Added a production stdio learn test that feeds a recorded 403 challenge page to the real vendored `addOperation`; the production learn branch emits `USER_ACTION_REQUIRED`, performs the test-only handoff seam, resumes with a recorded success capture, and returns a candidate-only result.",
        "- Regenerated `api-anything-runtime.patch` as one eight-file unified diff. The generator verifies reverse application against the vendored patched state and clean application to the reconstructed pristine tree. SHA-256 is pinned in the build script and runtime manifest.",
        "- Created the C5 tree's own `.venv` with `uv sync --locked`; generated environments and build outputs are excluded from the ledger.",
        "",
        "## Verification",
        "",
        "| Gate | Result | Scope |",
        "|---|---:|---|",
        "| `npm test` | 24 passed | Collector sidecar build, unit tests, and production stdio process tests |",
        "| Core pytest | 6,578 passed; 10 skipped; 1 xfailed | Separate `uv run pytest -q packages/leviathan-core/tests` process |",
        "| Store pytest | 548 passed; 2 skipped | Separate process |",
        "| Vault pytest | 163 passed; 36 skipped | Separate process |",
        "| Market-data pytest | 1,150 passed | Separate process |",
        "| API pytest | 1,475 passed; 1 skipped | Separate process; 15 existing warnings |",
        "| Mypy | passed, 442 files | Default, `--platform linux`, and `--platform darwin` |",
        "| Ruff requested command | 67 pre-existing F811 findings | `uv run ruff check . --extend-exclude qa/integration-backups`; findings are duplicate fixture imports in untouched acceptance cycle1 files |",
        "| Ruff owned handoff script | passed | `generate_cycle5_ledger.py` |",
        "| Finding acceptance | 7 passed, 2 failed, 210 deselected, 3 xfailed, 1 xpassed | Exact failures: `test_03_real_vendor_loopback.py::test_finding_second_call_in_same_process_must_not_block_for_the_cadence` and `test_03_real_vendor_loopback.py::test_finding_bot_wall_reaches_the_user_action_handoff_with_real_vendor`; both use the stale generic `extract: data` template. Acceptance-owned files were not modified. |",
        "| Full cycle1 acceptance | 31 passed, 29 failed | Existing pinned-template fixtures use a generic `data` extractor and Fed/Senate pins lack recorded-body metadata required by C5. Acceptance-owned files were not modified. |",
        "",
        "### Full cycle1 acceptance failure IDs",
        "",
        "The full cycle1 acceptance failure IDs are:",
        *[f"- `{failure}`" for failure in c1_failures],
        "",
        "These old fixtures are rejected at call-time mapping validation before their intended assertions run.",
        "",
        "The independent cycle2 acceptance directory is not present in this tree and was not touched. No live site learning was performed. The committed activation registry still pins no operations; candidates remain quarantined pending the normal writer, acceptance, review, and coordinator integration flow.",
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
