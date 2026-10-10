"""Runs the Node acceptance units against the freshly built dist, and verifies the frozen ledger."""

from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path

import aa_harness as H

NEW_LEDGER_SHA = "803d3b88dcc3734fd01c8b65695fa567966822aff7fb91d7fe8e00ac770fcb13"
OLD_LEDGER_SHA = "fa0e4956aff2248a050d59e656046151fb26e3984b92379431c5201ee375d956"


def test_node_unit_suite(collector: Path) -> None:
    env = {**__import__("os").environ, "AA_DIST": str(collector / "dist")}
    done = subprocess.run(
        [H.NODE, "--test", str(H.HERE / "node_units.test.mjs")],
        cwd=collector, env=env, capture_output=True, text=True, timeout=180,
    )
    assert done.returncode == 0, done.stdout[-4000:] + done.stderr[-2000:]
    assert re.search(r"fail 0", done.stdout)
    assert int(re.search(r"pass (\d+)", done.stdout).group(1)) >= 15


def test_frozen_ledger_hash_and_every_listed_file_hash() -> None:
    ledger = H.WORKTREE / "qa" / "handoffs" / "API-ANYTHING-001" / "cycle-0.md"
    assert hashlib.sha256(ledger.read_bytes()).hexdigest() == NEW_LEDGER_SHA != OLD_LEDGER_SHA
    checked = 0
    for line in ledger.read_text(encoding="utf-8").splitlines():
        m = re.match(r"- (added|modified): `([^`]+)` \S+ SHA-256 `([0-9a-f]{64})`", line)
        if not m:
            continue
        assert H.sha256_file(H.WORKTREE / m.group(2)) == m.group(3), m.group(2)
        checked += 1
    assert checked == 174
    assert not [l for l in ledger.read_text(encoding="utf-8").splitlines() if l.startswith("- deleted")]


def test_built_dist_matches_frozen_sources_not_a_stale_artifact(collector: Path) -> None:
    for name in ("main", "challenge", "canary", "contracts"):
        assert (collector / "dist" / f"{name}.js").exists()
    assert H.load_mutant() is not None or "HUMAN_ACTION_TIMEOUT_MS = 120_000" in (
        collector / "dist" / "contracts.js"
    ).read_text(encoding="utf-8")
