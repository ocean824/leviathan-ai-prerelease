"""Mutation runner.  Each mutant edits a *scratch copy* of the built dist (or of the Python client)
-- never the frozen sources -- then reruns the relevant acceptance files.  A mutant is KILLED when the
mutated run fails at least one test that the unmutated baseline run passes.

    python run_mutants.py            # full run, writes mutation-results.json
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
WORKTREE = HERE.parents[2]
PYTHON = sys.executable

T1, T2, T3, T4, T5 = (
    "test_01_transport_and_no_templates.py",
    "test_02_templates_repair_challenge.py",
    "test_03_real_vendor_loopback.py",
    "test_04_client_records_failclosed.py",
    "test_05_node_units_and_ledger.py",
)

MUTANTS = [
    dict(id="M01-skip-repair-canary", rule=3, target="main", find="if (!canaryCompatible(baseline, records)) {", replace="if (false) {", files=[T2]),
    dict(id="M02-skip-learn-canary", rule=3, target="main", find="if (!canaryCompatible(candidates[0] ?? [], candidates[1] ?? []))", replace="if (false)", files=[T2]),
    dict(id="M03-auto-dismiss-challenge-as-completed", rule=4, target="main", find='if (outcome === "declined") {', replace="if (false) {", files=[T2]),
    dict(id="M04-ignore-challenge-timeout", rule=4, target="main", find='if (outcome === "timeout") {', replace="if (false) {", files=[T2]),
    dict(id="M05-no-user-action-notification", rule=4, target="main", find="emit(JSON.stringify(notification));", replace="", files=[T2]),
    dict(id="M06-accept-non-allowlisted-operation", rule=1, target="contracts", find="export const operationContracts = {", replace='export const operationContracts = { "evil.op": { site: "evil", operation: "x", challengeUrl: "https://evil.invalid/", factor: "e", cadenceSeconds: 1, records: z.array(z.unknown()), input: z.object({}).strict(), tos: "REVIEW", tosUrl: "https://evil.invalid/" },', files=[T1, T5]),
    dict(id="M07-skip-template-hash-pin", rule=3, target="main", find="if (hashBefore !== pinned.sha256) {", replace="if (false) {", files=[T2]),
    dict(id="M08-canary-always-compatible", rule=3, target="canary", find="priorSignature === canarySignature(candidate)", replace="true", files=[T5, T2]),
    dict(id="M09-challenge-timeout-returns-completed", rule=4, target="challenge", find='return "timeout";', replace='return "completed";', files=[T5]),
    dict(id="M10-challenge-window-headless", rule=4, target="challenge", find="headless: false,", replace="headless: true,", files=[T5]),
    dict(id="M11-human-wait-unbounded-ish", rule=4, target="contracts", find="HUMAN_ACTION_TIMEOUT_MS = 120_000", replace="HUMAN_ACTION_TIMEOUT_MS = 3_600_000", files=[T2, T5]),
    dict(id="M12-missing-knowable-at-borrowed-from-fetch", rule=5, target="main", find="const knowableAt = publicTime(value.knowable_at);", replace="const knowableAt = publicTime(value.knowable_at) ?? fetchedAt;", files=[T2]),
    dict(id="M13-client-accepts-future-knowable-at", rule=5, target="client", find="record.knowable_at is not None and record.knowable_at > decision_as_of", replace="False", files=[T4]),
    dict(id="M14-client-missing-knowable-at-not-abstained", rule=5, target="client", find="if record.knowable_at is not None and record.knowable_at <= decision_as_of:", replace="if True:", files=[T4]),
    dict(id="M15-client-drops-redistribution-check", rule=5, target="client", find='if raw.get("redistribution") is not False:', replace="if False:", files=[T4]),
    dict(id="M16-client-allowlist-widened", rule=1, target="client", find='"cnn.fear_greed": EmptyQueryV1,', replace='"cnn.fear_greed": EmptyQueryV1,\n    "evil.op": EmptyQueryV1,', files=[T1]),
    dict(id="M17-client-timeout-not-enforced", rule=1, target="client", find="raw = self._replies.get(timeout=self._timeout_s)", replace="raw = self._replies.get(timeout=self._timeout_s * 40)", files=[T1]),
    dict(id="M18-client-lifetime-unbounded", rule=1, target="client", find="if time.monotonic() - self._started_at < MAX_PROCESS_LIFETIME_SECONDS:", replace="if True:", files=[T1]),
    dict(id="M19-client-source-identity-unchecked", rule=5, target="client", find="reply.source_id != _SOURCE_IDS[operation_id]", replace="False", files=[T4]),
    dict(id="M20-client-future-asof-accepted", rule=5, target="client", find="if record.as_of > decision_as_of:", replace="if False:", files=[T4]),
]


def pytest(files: list[str], env_extra: dict[str, str]) -> tuple[set[str], str, int]:
    import os

    env = {**os.environ, **env_extra}
    cmd = [PYTHON, "-m", "pytest", *[str(HERE / f) for f in files], "-q", "-p", "no:cacheprovider",
           "-c", "/dev/null", f"--rootdir={HERE}", "-rf", "--tb=no"]
    done = subprocess.run(cmd, capture_output=True, text=True, env=env, cwd=WORKTREE, timeout=1500)
    failed = set(re.findall(r"^FAILED (\S+)", done.stdout, flags=re.M))
    errors = set(re.findall(r"^ERROR (\S+)", done.stdout, flags=re.M))
    return failed | errors, done.stdout, done.returncode


def main() -> int:
    t0 = time.time()
    print("baseline ...", flush=True)
    baseline_failed, out, _ = pytest([T1, T2, T3, T4, T5], {})
    print(out.strip().splitlines()[-1], flush=True)
    results = []
    scratch = Path(tempfile.mkdtemp(prefix="aa-mutants-"))
    for m in MUTANTS:
        path = scratch / f"{m['id']}.json"
        path.write_text(json.dumps(m), encoding="utf-8")
        failed, out, rc = pytest(m["files"], {"AA_MUTANT": str(path)})
        new = sorted(failed - baseline_failed)
        applicable = "MUTANT_NOT_APPLICABLE" not in out
        status = "INVALID(not applicable)" if not applicable else ("KILLED" if new else "SURVIVED")
        results.append({"id": m["id"], "rule": m["rule"], "target": m["target"], "status": status,
                        "killed_by": [n.split("::", 1)[-1] for n in new][:6], "tail": out.strip().splitlines()[-1]})
        print(f"{status:10} {m['id']:48} killed_by={len(new)}", flush=True)
    summary = {
        "baseline_failed_findings": sorted(n.split("::", 1)[-1] for n in baseline_failed),
        "mutants": results,
        "killed": sum(r["status"] == "KILLED" for r in results),
        "survived": [r["id"] for r in results if r["status"] == "SURVIVED"],
        "invalid": [r["id"] for r in results if r["status"].startswith("INVALID")],
        "total": len(results),
        "seconds": round(time.time() - t0),
    }
    (HERE / "mutation-results.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps({k: v for k, v in summary.items() if k != "mutants"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
