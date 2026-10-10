"""Real wrapper + real vendored api-anything, driven against a loopback fake site (no live site, no
Chrome: only tier-1 HTTP is ever reached).  Proves behaviour the stubbed tests cannot."""

from __future__ import annotations

import json
from pathlib import Path

import aa_harness as H
import pytest
from conftest import client

OP = "cnn.fear_greed"
SITE = "cnn-fear-greed"


@pytest.fixture
def planted(v_realvendor_fakechallenge: Path, data_dir: Path, fake_site, sidecar_factory):
    H.plant_template(data_dir, SITE, fake_site.template(SITE), OP, variant=v_realvendor_fakechallenge)
    sc = sidecar_factory(
        v_realvendor_fakechallenge,
        data_dir,
        node_args=("--import", (H.HERE / "loopback-injection.mjs").as_uri()),
        extra_env={"AA_TEST_LOOPBACK_URL": f"http://127.0.0.1:{fake_site.port}"},
    )
    sc.set_control({"challenge_outcome": "completed"})
    return sc


def test_end_to_end_pinned_template_returns_typed_provenanced_record(planted, fake_site) -> None:
    reply, notes = planted.call(OP, {})
    assert notes == [] and reply["status"] == "OK"
    assert reply["template_version"] == "planted-1" and reply["source_tier"] == 3
    assert reply["redistribution"] is False and reply["source_id"] == f"api_anything.{OP}"
    [rec] = reply["records"]
    assert rec["redistribution"] is False and rec["knowable_at"] == "2026-10-08T00:00:05.000Z"
    assert rec["as_of"] == "2026-10-08T00:00:00.000Z" and rec["quality"] == "first_observed"
    assert fake_site.hits == 1


def test_hash_pin_is_enforced_with_the_real_vendor_and_no_request_leaves(
    v_realvendor_fakechallenge: Path, data_dir: Path, fake_site, sidecar_factory
) -> None:
    entry = H.plant_template(data_dir, SITE, fake_site.template(SITE), OP)
    (data_dir / entry["template_path"]).write_bytes(fake_site.template(SITE) + b" ")
    sc = sidecar_factory(v_realvendor_fakechallenge, data_dir)
    reply, _ = sc.call(OP, {})
    assert reply["error_code"] == "TEMPLATE_UNAVAILABLE" and reply["records"] == []
    assert fake_site.hits == 0


def test_finding_second_call_in_same_process_must_not_block_for_the_cadence(planted, fake_site) -> None:
    """FINDING (high): main.ts passes minIntervalMs = cadence (3600 s .. 86400 s) to api-anything,
    whose pace() *sleeps* until lastSend+minInterval.  The second request to a site in the same Node
    process (process lifetime is 15 min) therefore blocks for up to 24 h; the Python client kills the
    child after 150 s as COLLECTOR_UNAVAILABLE.  Learn issues two back-to-back calls to one site, so
    learn cannot complete either."""
    first, _ = planted.call(OP, {})
    assert first["status"] == "OK"
    second, _ = planted.call(OP, {}, timeout=10)  # raises TimeoutError while blocked
    assert second["status"] in {"OK", "DEGRADED"}


def test_finding_bot_wall_reaches_the_user_action_handoff_with_real_vendor(planted, fake_site) -> None:
    """FINDING (high): the wrapper detects a bot check by matching the vendor's *reason* text with
    /challenge|captcha|bot|robot|human|cloudflare/, but at maxTier=1 the vendor replaces the wall's
    reason with 'needs tier 2, capped at 1', so a real bot wall never produces USER_ACTION_REQUIRED."""
    fake_site.mode = "captcha"
    reply, notes = planted.call(OP, {}, timeout=15)
    assert notes and notes[0]["status"] == "USER_ACTION_REQUIRED", (
        f"bot wall was reported as {reply.get('error_code')!r} with no notification"
    )


# ---- rule 2: the vendored cookie-import path must be unreachable ----------------------------

SPY = """
import fs from "node:fs";
import { syncBuiltinESMExports } from "node:module";
const { appendFileSync } = fs;
const mark = process.env.AA_SPY_MARK;
const note = (m, p) => { if (mark && String(p).includes(mark)) appendFileSync(process.env.AA_LOG, JSON.stringify({ ev: "spy", m, p: String(p) }) + "\\n"); };
for (const m of ["readdirSync", "copyFileSync", "existsSync", "readFileSync", "openSync"]) {
  const orig = fs[m];
  fs[m] = function (p, ...rest) { note(m, p); return orig.call(this, p, ...rest); };
}
syncBuiltinESMExports();
"""


def test_finding_owner_browser_cookie_import_is_unreachable(
    v_realvendor_fakechallenge: Path, data_dir: Path, fake_site, sidecar_factory, tmp_path: Path
) -> None:
    """FINDING (medium, defence in depth): the design says source import behaviour is disabled, but
    the vendored execute.ts still calls reimportIfBrowser() on an auth failure.  If an isolated
    session file ever carries a browser pin ("chrome:Default"), the sidecar reads the browser roots
    (here an injected fake 'owner browser'; on macOS the default Chrome/Brave/Firefox roots).
    Nothing creates such a pin today, but nothing prevents it either (e.g. an exported/imported
    app-data directory), and the product contract is 'never imported'."""
    owner = tmp_path / "owner-browser-root"
    (owner / "Default" / "Network").mkdir(parents=True)
    (owner / "Default" / "Network" / "Cookies").write_bytes(b"not a real cookie db")
    spy = tmp_path / "spy.mjs"
    spy.write_text(SPY, encoding="utf-8")
    H.plant_template(data_dir, SITE, fake_site.template(SITE), OP)
    sessions = data_dir / "isolated" / SITE / "sessions"
    sessions.mkdir(parents=True)
    (sessions / f"{SITE}.json").write_text(
        json.dumps({"cookies": [], "values": {}, "source": "chrome:Default"}), encoding="utf-8"
    )
    fake_site.mode = "auth"
    roots = [{"name": "Chrome", "family": "chromium", "root": str(owner), "password": "x", "iterations": 1}]
    sc = sidecar_factory(
        v_realvendor_fakechallenge,
        data_dir,
        extra_env={
            "API_ANYTHING_BROWSER_ROOTS": json.dumps(roots),
            "AA_SPY_MARK": "owner-browser-root",
        },
        node_args=("--import", spy.as_uri()),
    )
    reply, _ = sc.call(OP, {}, timeout=15)
    assert reply["records"] == []
    touched = sc.log_events("spy")
    assert touched == [], f"sidecar touched the owner's browser profile: {touched[:3]}"


# ---- Python client + real sidecar: env hygiene ------------------------------------------------

def test_finding_child_env_must_not_carry_secrets_or_browser_roots(tmp_path: Path) -> None:
    """FINDING (medium): CollectorSupervisor starts the child with os.environ.copy().  The design
    says the sidecar gets no vault credentials and no ambient browser profile; every secret-looking
    variable (and API_ANYTHING_* overrides such as API_ANYTHING_BROWSER_ROOTS) is inherited."""
    import os

    script = tmp_path / "envdump.py"
    out = tmp_path / "env.json"
    script.write_text(
        "import sys,json,os\n"
        "line=sys.stdin.readline(); req=json.loads(line)\n"
        f"open({str(out)!r},'w').write(json.dumps(sorted(os.environ)))\n"
        "print(json.dumps({'schema_version':1,'request_id':req['request_id'],'operation_id':None,"
        "'template_version':None,'source_id':None,'source_tier':None,'status':'OK',"
        "'fetched_at':'2026-10-09T15:00:00Z','as_of':None,'knowable_at':None,'redistribution':False,"
        "'records':[]}),flush=True)\n",
        encoding="utf-8",
    )
    planted = {
        "LEVIATHAN_VAULT_PASSPHRASE": "x",
        "DATABENTO_API_KEY": "x",
        "SOME_SERVICE_TOKEN": "x",
        "API_ANYTHING_BROWSER_ROOTS": "[]",
        "API_ANYTHING_HOME": "x",
    }
    old = {k: os.environ.get(k) for k in planted}
    os.environ.update(planted)
    sup = client.CollectorSupervisor(__import__("sys").executable, script, data_dir=tmp_path / "d")
    try:
        sup.health()
    finally:
        sup.close()
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    seen = set(json.loads(out.read_text(encoding="utf-8")))
    leaked = sorted(seen & set(planted))
    assert leaked == [], f"child inherited: {leaked}"
