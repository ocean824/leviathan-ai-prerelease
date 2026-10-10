"""Cycle 2: Node units + the writer's own Node tests (incl. real-stdio E2E) on the scratch production build, plus static
hygiene checks of the shipped bytes (no AA_CONTROL, no import paths, no solver/spoofing, ledger)."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

import aa_harness as A
import c2_harness as C
import pytest

pytest_plugins = ("c2_fixtures",)

HERE = Path(__file__).resolve().parent
COLLECTOR_SRC = A.WORKTREE / "services" / "public-collector"
LEDGER_SHA = "7839a91e6856a8daa16b9e76683a0b155913b439e0886cba91034c5c399f6b01"


def run_node(args: list[str], cwd: Path, env_extra: dict[str, str] | None = None, timeout: int = 300):
    env = {**os.environ, **(env_extra or {})}
    env.pop("AA_CONTROL", None)
    return subprocess.run([A.NODE, *args], cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout)


def test_node_unit_suite(collector: Path) -> None:
    done = run_node(["--test", str(HERE / "node_units_c2.test.mjs"), str(HERE / "node_units_c3.test.mjs")], collector, {"AA_DIST": str(collector / "dist")})
    assert done.returncode == 0, done.stdout[-5000:] + done.stderr[-2000:]
    assert re.search(r"fail 0", done.stdout) and int(re.search(r"pass (\d+)", done.stdout).group(1)) >= 28


def test_writers_node_tests_and_real_stdio_e2e_pass_on_a_clean_scratch_build(collector: Path) -> None:
    done = run_node(["--test", *[str(p) for p in sorted((collector / "dist").glob("*.test.js"))], str(collector / "e2e" / "stdio.test.mjs")], collector)
    assert done.returncode == 0, done.stdout[-5000:] + done.stderr[-2000:]
    assert re.search(r"fail 0", done.stdout) and int(re.search(r"pass (\d+)", done.stdout).group(1)) >= 15


def test_ledger_hashes_and_cycle_inventory() -> None:
    ledger = A.WORKTREE / "qa" / "handoffs" / "API-ANYTHING-001" / "cycle-5.md"
    assert hashlib.sha256(ledger.read_bytes()).hexdigest() == LEDGER_SHA
    rows = [m.groups() for m in (re.match(r"\| (?:added|modified) \| `([^`]+)` \| `[^`]*` \| `([0-9a-f]{64})` \|", l) for l in ledger.read_text(encoding="utf-8").splitlines()) if m]
    assert len(rows) == 17
    assert not (A.WORKTREE / "qa/handoffs/API-ANYTHING-001/make_cycle5_start.py").exists(), "the ledger's deleted row"
    # qa/acceptance/** are the reviewer's own files; the collision fix legitimately re-touched some of them afterwards.
    bad = [p for p, h in rows if not p.startswith("qa/acceptance/") and hashlib.sha256((A.WORKTREE / p).read_bytes()).hexdigest() != h]
    assert bad == []
    assert sum(1 for p, _ in rows if not p.startswith("qa/acceptance/")) == 17


# ------------------------------------------------------------------ shipped bytes

def shipped_files(collector: Path):
    for root in (collector / "dist", collector / "vendor" / "api-anything" / "dist"):
        for p in root.rglob("*"):
            if p.suffix in {".js", ".mjs", ".cjs"} and not p.name.endswith(".test.js"):
                yield p


def test_no_test_mode_switch_ships_in_dist_or_the_vendor_runtime_or_python(collector: Path) -> None:
    hits = {}
    for p in shipped_files(collector):
        text = p.read_text(encoding="utf-8")
        for token in ("AA_CONTROL", "AA_TEST", "AA_FAKENET", "AA_STUB", "template-registry.json", "loopback acceptance"):
            if token in text:
                hits.setdefault(p.name, []).append(token)
    for p in (A.WORKTREE / "packages" / "leviathan-market-data" / "src" / "leviathan_market_data" / "public_sources").glob("api_anything*.py"):
        text = p.read_text(encoding="utf-8")
        for token in ("AA_CONTROL", "AA_TEST"):
            if token in text:
                hits.setdefault(p.name, []).append(token)
    for p in (COLLECTOR_SRC / "src").glob("*.ts"):
        if p.name.endswith(".test.ts"):
            continue
        if "AA_CONTROL" in p.read_text(encoding="utf-8"):
            hits.setdefault(p.name, []).append("AA_CONTROL")
    assert hits == {}, hits


def test_the_shipped_sidecar_ignores_the_old_harness_switch(prod_real, app_data, sidecar1) -> None:
    """Even if AA_CONTROL is set, the production entrypoint behaves exactly as without it."""
    C.write_pin(prod_real, "cnn.fear_greed")
    sc = sidecar1(prod_real, app_data, world=C.default_world(robots="User-agent: *\nDisallow: /\n"), extra_env={"AA_CONTROL": "1", "AA_TEST_CONTROL": "1"})
    reply, _ = sc.call("cnn.fear_greed")
    assert reply["status"] != "OK" and sc.non_robots_requests() == []


def test_vendor_runtime_has_no_cookie_or_profile_import_path(collector: Path) -> None:
    dist = collector / "vendor" / "api-anything" / "dist"
    names = {p.name for p in dist.glob("*.js")}
    assert names.isdisjoint({"import.js", "login.js", "mcp.js", "cli.js", "secrets.js"} - {"secrets.js"}), names
    for p in dist.glob("*.js"):
        text = p.read_text(encoding="utf-8")
        for token in ("reimportIfBrowser", "importSession", "API_ANYTHING_BROWSER_ROOTS", "Safe Storage", "browserRoots", "from \"./import.js\"", "from \"./login.js\""):
            assert token not in text, (p.name, token)
    assert (dist / "execute.js").exists()


def test_planted_browser_pin_in_a_session_file_is_ignored(prod_real, app_data, sidecar1, tmp_path) -> None:
    owner = tmp_path / "owner-browser-root"
    (owner / "Default" / "Network").mkdir(parents=True)
    (owner / "Default" / "Network" / "Cookies").write_bytes(b"not a real cookie db")
    spy = tmp_path / "spy.mjs"
    spy.write_text(
        'import fs from "node:fs"; import { syncBuiltinESMExports } from "node:module";\n'
        'const { appendFileSync } = fs; const mark = process.env.AA_SPY_MARK;\n'
        'for (const m of ["readdirSync","copyFileSync","existsSync","readFileSync","openSync","statSync"]) { const o = fs[m];\n'
        '  fs[m] = function (p, ...r) { if (mark && String(p).includes(mark)) appendFileSync(process.env.AA_STUB_LOG, JSON.stringify({ev:"spy",m,p:String(p)})+"\\n"); return o.call(this,p,...r); }; }\n'
        'syncBuiltinESMExports();\n', encoding="utf-8")
    world = C.default_world()
    world["hosts"]["www.cnn.com"]["routes"][C.FEED_PATH] = {"status": 401, "json": {"error": "unauthorized"}}
    C.write_pin(prod_real, "cnn.fear_greed")
    sessions = app_data / "isolated" / "cnn-fear-greed" / "sessions"
    sessions.mkdir(parents=True)
    (sessions / "cnn-fear-greed.json").write_text(json.dumps({"cookies": [], "values": {}, "source": "chrome:Default"}), encoding="utf-8")
    roots = [{"name": "Chrome", "family": "chromium", "root": str(owner), "password": "x", "iterations": 1}]
    sc = sidecar1(prod_real, app_data, world=world, node_args=("--import", spy.as_uri()),
                  extra_env={"API_ANYTHING_BROWSER_ROOTS": json.dumps(roots), "AA_SPY_MARK": "owner-browser-root"})
    reply, _ = sc.call("cnn.fear_greed", timeout=30)
    assert reply["records"] == [] and reply["status"] == "DEGRADED"
    assert sc.stub_events("spy") == [], "the sidecar touched the owner's browser profile"
    assert all(r["cookie"] is None and r["auth"] is None for r in sc.requests())


def test_no_solver_or_fingerprint_spoofing_in_shipped_code(collector: Path) -> None:
    roots = [COLLECTOR_SRC / "src", A.WORKTREE / "packages" / "leviathan-market-data" / "src" / "leviathan_market_data" / "public_sources"]
    hits = []
    for root in roots:
        for p in root.rglob("*"):
            if p.suffix in {".ts", ".py"} and not p.name.endswith(".test.ts"):
                hits += [(p.name, m.group(0)) for m in A.FORBIDDEN.finditer(p.read_text(encoding="utf-8"))]
    for p in shipped_files(collector):
        hits += [(p.name, m.group(0)) for m in A.FORBIDDEN.finditer(p.read_text(encoding="utf-8"))]
    assert hits == [], hits[:5]
    browser = (collector / "vendor" / "api-anything" / "dist" / "browser.js").read_text(encoding="utf-8")
    assert "LEVIATHAN_PUBLIC_USER_AGENT" in browser
    for bad in ("AutomationControlled", "navigator.webdriver", "addInitScript"):
        assert bad not in browser, bad
    for p in shipped_files(collector):  # the headless-UA rewriting helper must at least be unreachable
        assert "headlessUserAgent(" not in p.read_text(encoding="utf-8").replace("export async function headlessUserAgent(", ""), p.name


def test_headless_user_agent_helper_is_removed_from_the_shipped_runtime(collector: Path) -> None:
    for p in shipped_files(collector):
        text = p.read_text(encoding="utf-8")
        assert "headlessUserAgent" not in text and "probeHeadlessUA" not in text and 'replace("HeadlessChrome"' not in text, p.name


def test_no_listening_socket_primitives_in_shipped_runtime(collector: Path) -> None:
    pat = re.compile(r"\.listen\(|createServer\(|node:net|node:dgram|WebSocketServer|--remote-debugging-port")
    hits = [p.name for p in shipped_files(collector) if pat.search(p.read_text(encoding="utf-8"))]
    assert hits == [], hits


def test_a_real_sidecar_listens_on_no_port_while_serving(prod_real, app_data, sidecar1) -> None:
    C.write_pin(prod_real, "cnn.fear_greed")
    sc = sidecar1(prod_real, app_data, world=C.default_world())
    assert sc.call("cnn.fear_greed")[0]["status"] == "OK"
    assert A.open_sockets(sc.proc.pid) == []
