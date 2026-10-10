"""Cycle-2+ mutation runner.  Each mutant is applied to the SCRATCH build (or to a scratch copy of a Python module) by the
harness (AA_MUTANT); the frozen tree is never written.  KILLED = a test that passes on the unmutated build fails.

    python run_mutants_c2.py [--only M07,M08] [--list]
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PY = sys.executable
T = {k: str(HERE / v) for k, v in {
    "pins": "test_c2_pins_policy.py", "lim": "test_c2_limiter_candidates.py", "chal": "test_c2_challenge_replay.py",
    "know": "test_c2_knowable_firstseen.py", "cli": "test_c2_client.py", "node": "test_c2_node_static.py", "p2": "test_c3_p2.py", "rec": "test_c4_learn_recipes.py", "san": "test_c4_sanitize.py", "gaps": "test_c5_gaps.py"}.items()}

# id, target, file (vendor/other), find, replace, why, tests
M = [
    ("M01", "rate-limiter", None, "if (now < lastSend + minIntervalMs)", "if (false)", "limiter: send spacing removed", ["lim", "gaps"]),
    ("M02", "rate-limiter", None, "if (now < lastSuccess + cadenceMs)", "if (false)", "limiter: cadence (NOT_DUE) removed", ["lim", "node"]),
    ("M03", "rate-limiter", None, "if (now < backoff)", "if (false)", "limiter: 429 backoff ignored", ["lim", "node"]),
    ("M04", "robots", None, "robotsAllows(policy.robots[parsed.hostname.toLowerCase()] ?? [], parsed.pathname + parsed.search)", "true", "robots.txt rules ignored", ["pins", "node"]),
    ("M05", "robots", None, "policy.allowedHosts.includes(parsed.hostname.toLowerCase()) &&", "true &&", "host allowlist ignored", ["pins", "node"]),
    ("M06", "main", None, "if (!nextUrl || !urlAllowed(nextUrl, requestPolicy))", "if (!nextUrl)", "redirect host/robots check removed", ["pins"]),
    ("M07", "main", None, "hashBefore !== pinned.sha256", "false", "pinned template digest not checked", ["pins"]),
    ("M08", "main", None, "!== PIN_REGISTRY_SHA256", '=== "never"', "registry hash baked into dist not checked", ["lim"]),
    ("M09", "main", None, "containsCredentialMaterial(parsedCandidate) || containsCredentialMaterial(rows)", "false", "repair candidates not scanned for credentials", ["lim"]),
    ("M10", "main", None, "const knowableAt = new Date(Math.max(...knowledgeStamps)).toISOString();",
     'const knowableAt = typeof value.knowable_at === "string" ? value.knowable_at : new Date(Math.max(...knowledgeStamps)).toISOString();',
     "source-claimed knowable_at trusted", ["know"]),
    ("M11", "main", None, "const challenge = apiResult.challenge === true || currentChallengeSignal;",
     "const challenge = apiResult.challenge === true || currentChallengeSignal || /captcha|challenge/i.test(apiResult.reason ?? \"\");",
     "challenge detected from reason text", ["chal"]),
    ("M12", "main", None, "requestPolicy = await buildRequestPolicy(pinned.allowed_hosts, activeDataDir);",
     "requestPolicy = process.env.AA_CONTROL ? { allowedHosts: pinned.allowed_hosts, robots: {} } : await buildRequestPolicy(pinned.allowed_hosts, activeDataDir);",
     "AA_CONTROL robots bypass reintroduced", ["node", "pins"]),
    ("M13", "challenge", None, "if (challengeWords.test(text) || text.trim().length < 30)", "if (false)", "window completes without checking the page cleared", ["node"]),
    ("M14", "challenge", None, 'return confirmPage.isClosed() ? "declined" : "timeout";', 'return "completed";', "window wait timeout/dismiss counted as completed", ["node"]),
    ("M15", "pinned", None, '"operations": {}', '"operations": {"cnn.fear_greed": {"version": "x", "sha256": "' + "0" * 64 + '"}}', "committed registry pins a bogus operation", ["lim", "pins"]),
    ("M16", "client", None, 'child_env["LEVIATHAN_COLLECTOR_DATA"] = self._data_dir', 'child_env.update(os.environ); child_env["LEVIATHAN_COLLECTOR_DATA"] = self._data_dir', "child inherits the full environment", ["cli"]),
    ("M17", "client", None, '["taskkill.exe", "/PID", str(process.pid), "/T", "/F"],\n                stdin', '["taskkill.exe", "/PID", str(process.pid), "/F"],\n                stdin', "kill without the process tree", ["cli"]),
    ("M18", "client", None, "+ HUMAN_ACTION_TIMEOUT_SECONDS\n                            + CALL_TIMEOUT_SECONDS,", "+ 0,", "no separate human-wait budget", ["cli"]),
    ("M19", "client", None, 'platform.system() == "Darwin"', "False", "Big Sur replay-only detection removed", ["chal"]),
    ("M20", "client", None, 'if hashlib.sha256(registry_bytes).hexdigest() != manifest.get("pin_registry_sha256"):', "if False:", "client does not verify PINNED.json against the build manifest", ["cli"]),
    ("M21", "client", None, "or (self.knowable_at is not None and self.knowable_at > self.fetched_at)", "", "client accepts future knowable_at (result level)", ["cli"]),
    ("M22", "client", None, 'if raw.get("redistribution") is not False:', "if False:", "client drops the per-record redistribution check", ["cli"]),
    ("M23", "templates", None, 'hashlib.sha256(raw).hexdigest() != envelope.get("sha256")', "False", "import does not verify the bundle digest", ["cli"]),
    ("M25", "fixture-replay", None, "skipPacing: true,", "", "fixture replay waits on the site pace again", ["p2", "node"]),
    ("M26", "main", None, "semanticCheck(operationId, extracted, Date.parse(fixture.fetched_at));", "semanticCheck(operationId, extracted);", "pinned fixture rows judged by today's wall clock", ["p2"]),
    ("M27", "main", None, 'if (stableJson(extracted) !== stableJson(fixture.rows))\n            throw new Error("FIXTURE_TEMPLATE_OUTPUT_MISMATCH");', "", "fixture rows no longer compared with the template's extraction", ["p2"]),
    ("M28", "fixture-sanitize", None, "return JSON.stringify(redactJson(parsed, consumedPaths(recipe)));", "return JSON.stringify(parsed);", "candidate fixture not redacted of personal values at all", ["san"]),
    ("M29", "learn-canary", None, "if (result.challenge) {", "if (false) {", "learn canary never hands off a wall", ["p2", "node"]),
    ("M30", "vendor-dist", "classify.js", 'return { ...is("blocked", wall), challenge: true };', 'return is("blocked", wall);', "vendor stops flagging walls as challenges", ["p2", "chal"]),
    ("M31", "main", None, "containsCredentialMaterial(fixture.raw_body)", "false", "fixture raw bodies not scanned for credentials", ["p2"]),
    ("M32", "semantic", None, "scheduled < now - 365 * day || scheduled > now + 365 * day", "false", "semantic window check removed (earnings)", ["pins", "p2"]),
    # ---- cycle 4/5 additions
    ("M33", "main", None, 'throw new Error("TEMPLATE_MAPPING_MISMATCH");', ";", "call-time template-vs-recipe check removed", ["rec", "pins", "gaps"]),
    ("M34", "main", None, 'throw new Error("CANDIDATE_MAPPING_MISMATCH");', ";", "learn-time template-vs-recipe check removed", ["rec", "gaps"]),
    ("M35", "main", None, 'entry.fixture_origin !== "recorded-live-response"', "false", "Fed/Senate pins no longer need a recorded live response", ["rec"]),
    ("M36", "main", None, 'entry.mapping_sha256 !== createHash("sha256")', 'false && entry.mapping_sha256 !== createHash("sha256")', "recipe digest in the pin entry not checked", ["rec"]),
    ("M37", "first-seen", None, "let firstSeen = ledger[identity];", "let firstSeen = undefined;", "first-seen no longer write-once", ["rec", "know"]),
    ("M38", "challenge-signal", None, "[403, 429, 503].includes(status)", "[429, 503].includes(status)", "403 bot-wall bodies no longer recognised", ["rec"]),
    ("M39", "challenge-signal", None, "|datadome)", ")", "wall marker datadome dropped", ["rec"]),
    ("M44", "challenge-signal", None, "verify you are human|", "", "wall marker `verify you are human` dropped", ["rec"]),
    ("M45", "challenge-signal", None, "cf-chl-|", "", "wall marker cf-chl- dropped", ["rec"]),
    ("M40", "fixture-sanitize", None, "redactJson(parsed, consumedPaths(recipe))", "redactJson(parsed, [])", "recipe-picked values redacted again", ["san", "rec"]),
    ("M41", "fixture-sanitize", None, "    assertNoCredential(parsed);\n", "", "JSON credential scan removed from the sanitiser", ["san"]),
    ("M42", "fixture-sanitize", None, '"script,style,input,textarea,select,option,[hidden],[type=hidden]"', '"style"', "HTML scripts/inputs/hidden fields kept", ["san"]),
    ("M43", "main", None, "!templateMatchesMapping(parsedTemplate, operationId)", "false", "template/recipe mismatch check disabled (both sites)", ["rec", "pins", "gaps"]),
    ("M24", "templates", None, "_reject_session_material(parsed)\n    envelope", "envelope", "export does not reject session material", ["cli"]),
]


def run(files: list[str], mutant_file: str | None) -> tuple[set[str], str]:
    env = {**os.environ}
    env.pop("AA_MUTANT", None)
    if mutant_file:
        env["AA_MUTANT"] = mutant_file
    cmd = [PY, "-B", "-m", "pytest", *files, "-p", "no:cacheprovider", "-c", "/dev/null", f"--rootdir={HERE.parent}", "-q", "-rf", "--tb=no"]
    done = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, env=env, timeout=3600)
    failed = set(re.findall(r"^(?:FAILED|ERROR) (\S+)", done.stdout, flags=re.M))
    return failed, done.stdout


def main() -> int:
    only = None
    if "--only" in sys.argv:
        only = set(sys.argv[sys.argv.index("--only") + 1].split(","))
    t0 = time.time()
    baseline: dict[str, set[str]] = {}
    scratch = Path(tempfile.mkdtemp(prefix="aa-c2-mutants-"))
    results = []
    for mid, target, _file, find, replace, why, tests in M:
        if only and mid not in only:
            continue
        for key in tests:
            if key not in baseline:
                baseline[key], out = run([T[key]], None)
                print(f"baseline {key}: {len(baseline[key])} failing -> {out.strip().splitlines()[-1]}", flush=True)
        spec = scratch / f"{mid}.json"
        spec.write_text(json.dumps({"target": target, "file": _file, "find": find, "replace": replace}), encoding="utf-8")
        failed, out = run([T[k] for k in tests], str(spec))
        base = set().union(*(baseline[k] for k in tests))
        new = sorted(failed - base)
        if "MUTANT_NOT_APPLICABLE" in out:
            status = "INVALID(not applicable)"
        else:
            status = "KILLED" if new else "SURVIVED"
        results.append({"id": mid, "target": target, "mutation": why, "status": status, "killed_by": [n.split("::", 1)[-1] for n in new][:5]})
        print(f"{status:24} {mid} {why} ({len(new)} new failures)", flush=True)
    summary = {"total": len(results), "killed": sum(r["status"] == "KILLED" for r in results),
               "survived": [r["id"] for r in results if r["status"] == "SURVIVED"], "invalid": [r["id"] for r in results if r["status"].startswith("INVALID")],
               "baseline_failing": {k: sorted(v) for k, v in baseline.items()}, "results": results, "seconds": round(time.time() - t0)}
    (HERE / "mutation-results-c2.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps({k: v for k, v in summary.items() if k not in {"results", "baseline_failing"}}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
