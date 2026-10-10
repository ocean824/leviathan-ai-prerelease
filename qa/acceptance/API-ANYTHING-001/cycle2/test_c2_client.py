"""Cycle 2: the typed Python client against the cycle-1+ contract (pins, new record fields), plus child hygiene:
minimal environment, process-tree kill, the separate human-wait budget, and template export/import."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import sys
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import aa_harness as A
import c2_harness as C
import pytest
from leviathan_market_data.public_sources import api_anything_client as client

pytest_plugins = ("c2_fixtures",)

templates = C.load_templates()
E = client.PublicOperationErrorCode
NOW = datetime.now(UTC)


def z(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


OP = "cnn.fear_greed"
VALUES = {
    "calendar.fed": {"event_name": "FOMC", "agency": "FRB", "release_type": "meeting", "scheduled_at": z(NOW + timedelta(days=30)), "published_at": z(NOW - timedelta(hours=3))},
    "earnings.forward": {"ticker": "AAPL", "fiscal_period": "Q4", "event_type": "earnings", "scheduled_at": z(NOW + timedelta(days=20)), "status": "confirmed", "published_at": None},
    "senate.efd.ptr": {"report_url": "https://efdsearch.senate.gov/search/view/ptr/abc/", "filed_at": z(NOW - timedelta(days=1)),
                       "transactions": [{"ticker": "MSFT", "trade_date": z(NOW - timedelta(days=4)), "transaction_type": "Purchase", "amount_range": "$1,001 - $15,000"}]},
    "cboe.daily.stats": {"observed_at": z(NOW - timedelta(days=1)), "metric": "put_call_ratio", "value": 0.87, "unit": "ratio", "maturity": None, "published_at": z(NOW - timedelta(hours=20))},
    "cnn.fear_greed": {"value": 42, "label": "Fear", "observed_at": z(NOW - timedelta(hours=2))},
}
ARGS = {"calendar.fed": {"year": 2026}, "earnings.forward": {"symbols": ["AAPL"]}, "senate.efd.ptr": {"page": 1},
        "cboe.daily.stats": {"date": "2026-10-08"}, "cnn.fear_greed": {}}
TOS = {"calendar.fed": "fed-public-schedule-2026-10-09", "earnings.forward": "yahoo-finance-owner-review-2026-10-09", "senate.efd.ptr": "senate-efd-public-filings-2026-10-09",
       "cboe.daily.stats": "cboe-market-data-owner-review-2026-10-09", "cnn.fear_greed": "cnn-owner-review-2026-10-09"}
APPROVED = NOW - timedelta(days=10)
SHA = hashlib.sha256(b"template").hexdigest()


def collector_root(tmp: Path, op: str = OP, *, pin: bool = True, manifest_ok: bool = True) -> Path:
    """<root>/dist/<script>, <root>/templates/PINNED.json, <root>/runtime-manifest.json: the layout the client verifies."""
    root = tmp / "collector"
    (root / "dist").mkdir(parents=True, exist_ok=True)
    (root / "templates").mkdir(exist_ok=True)
    registry = {"schema_version": 1, "operations": {}, "tos_reviews": {}}
    if pin:
        registry["operations"][op] = {"version": "pin-1", "sha256": SHA, "tos_review_id": TOS[op], "approved_at": z(APPROVED),
                                      "allowed_hosts": ["www.cnn.com"], "challenge_hosts": [], "review_note": "fixture review", "template_path": f"{op}/pin-1.json"}
    raw = json.dumps(registry).encode()
    (root / "templates" / "PINNED.json").write_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest() if manifest_ok else "0" * 64
    (root / "runtime-manifest.json").write_text(json.dumps({"pin_registry_sha256": digest}), encoding="utf-8")
    return root


def reply(op=OP, **over):
    fetched = NOW
    rec = {
        "record_id": "rec-1", "as_of": z(NOW - timedelta(hours=2)), "event_at": None, "published_at": z(NOW - timedelta(hours=3)),
        "available_at": z(NOW - timedelta(hours=3)), "knowable_at": z(NOW - timedelta(minutes=30)), "first_seen_at": z(NOW - timedelta(minutes=30)),
        "quality": "source_timestamped", "values": copy.deepcopy(VALUES[op]), "redistribution": False,
    }
    body = {
        "schema_version": 1, "request_id": str(uuid.uuid4()), "operation_id": op, "template_version": "pin-1", "template_sha256": SHA,
        "approval_id": TOS[op], "approval_deadline": z(APPROVED + timedelta(days=90)), "freshness_deadline": z(fetched + timedelta(hours=48)),
        "source_id": f"api_anything.{op}", "source_tier": 3, "status": "OK", "fetched_at": z(fetched),
        "as_of": rec["as_of"], "knowable_at": rec["knowable_at"], "redistribution": False, "records": [rec],
    }
    body.update(over)
    return body


def served(tmp: Path, body: dict, op=OP, *, pin=True, manifest_ok=True, method="call", launch_marker: Path | None = None):
    root = collector_root(tmp, op, pin=pin, manifest_ok=manifest_ok)
    script = root / "dist" / f"child-{uuid.uuid4().hex[:6]}.py"
    mark = f"open({str(launch_marker)!r},'w').write('x')\n" if launch_marker else ""
    script.write_text(
        "import sys,json\n" + mark + "req=json.loads(sys.stdin.readline())\n"
        f"body=json.loads({json.dumps(json.dumps(body))})\nbody['request_id']=req['request_id']\nprint(json.dumps(body),flush=True)\nsys.stdin.readline()\n",
        encoding="utf-8",
    )
    sup = client.CollectorSupervisor(sys.executable, script, data_dir=tmp / "data", timeout_s=20)
    try:
        return getattr(sup, method)(op, ARGS[op])
    finally:
        sup.close()


def parse(body, op=OP):
    return client.parse_operation_result(client.SidecarReply.model_validate_json(json.dumps(body)), None)


# ------------------------------------------------------------------ contract + fail closed

@pytest.mark.parametrize("op", list(VALUES))
def test_every_operation_yields_the_full_cycle1_provenance(op, tmp_path) -> None:
    r = served(tmp_path, reply(op), op)
    assert r.source_tier == 3 and r.redistribution is False and r.template_sha256 == SHA and r.approval_id == TOS[op]
    for stamp in (r.fetched_at, r.freshness_deadline, r.approval_deadline):
        assert stamp.tzinfo is not None
    [rec] = r.records
    assert rec.first_seen_at <= rec.knowable_at <= r.fetched_at and rec.template_sha256 == SHA and rec.approval_id == TOS[op]
    assert rec.redistribution is False and len(rec.record_digest) == 64 and rec.freshness_deadline == r.freshness_deadline


def test_no_pin_means_no_process_and_template_unpinned(tmp_path) -> None:
    marker = tmp_path / "started.txt"
    with pytest.raises(client.PublicOperationError) as exc:
        served(tmp_path, reply(), pin=False, launch_marker=marker)
    assert exc.value.code is E.TEMPLATE_UNPINNED and not marker.exists()


def test_a_registry_that_does_not_match_the_build_manifest_is_refused_before_any_launch(tmp_path) -> None:
    marker = tmp_path / "started.txt"
    with pytest.raises(client.PublicOperationError) as exc:
        served(tmp_path, reply(), manifest_ok=False, launch_marker=marker)
    assert exc.value.code in {E.TEMPLATE_UNPINNED, E.PIN_REGISTRY_INVALID} and not marker.exists()


@pytest.mark.parametrize(("label", "mutate"), [
    ("version differs from the pin", lambda b: b.update(template_version="pin-2")),
    ("template sha differs from the pin", lambda b: b.update(template_sha256="1" * 64)),
    ("approval id differs from the pin", lambda b: b.update(approval_id="other-review")),
    ("approval deadline is not approved_at + 90 days", lambda b: b.update(approval_deadline=z(APPROVED + timedelta(days=200)))),
])
def test_reply_that_disagrees_with_the_committed_pin_is_refused(label, mutate, tmp_path) -> None:
    body = reply()
    mutate(body)
    with pytest.raises(client.PublicOperationError) as exc:
        served(tmp_path, body)
    assert exc.value.code in {E.TEMPLATE_UNAVAILABLE, E.SCHEMA_INVALID}, label


@pytest.mark.parametrize(("label", "mutate"), [
    ("top redistribution missing", lambda b: b.pop("redistribution")),
    ("top redistribution true", lambda b: b.update(redistribution=True)),
    ("record redistribution true", lambda b: b["records"][0].update(redistribution=True)),
    ("record redistribution missing", lambda b: b["records"][0].pop("redistribution")),
    ("source_tier 2", lambda b: b.update(source_tier=2)),
    ("source_id mismatch", lambda b: b.update(source_id="api_anything.calendar.fed")),
    ("operation unknown", lambda b: b.update(operation_id="evil.op")),
    ("template_sha256 missing", lambda b: b.pop("template_sha256")),
    ("approval_id missing", lambda b: b.pop("approval_id")),
    ("freshness_deadline missing", lambda b: b.pop("freshness_deadline")),
    ("freshness_deadline beyond fetched + 48h", lambda b: b.update(freshness_deadline=z(NOW + timedelta(hours=60)))),
    ("freshness_deadline already past", lambda b: b.update(freshness_deadline=z(NOW - timedelta(hours=1)))),
    ("quality unknown", lambda b: b["records"][0].update(quality="guessed")),
    ("first_seen_at missing", lambda b: b["records"][0].pop("first_seen_at")),
    ("first_seen after fetched", lambda b: b["records"][0].update(first_seen_at=z(NOW + timedelta(hours=1)))),
    ("knowable before first seen", lambda b: b["records"][0].update(knowable_at=z(NOW - timedelta(hours=1)))),
    ("published after knowable", lambda b: b["records"][0].update(published_at=z(NOW - timedelta(minutes=5)))),
    ("available after knowable", lambda b: b["records"][0].update(available_at=z(NOW - timedelta(minutes=5)))),
    ("as_of after knowable", lambda b: b["records"][0].update(as_of=z(NOW - timedelta(minutes=5)))),
    ("first_observed with knowable != first_seen", lambda b: b["records"][0].update(quality="first_observed", published_at=None, available_at=None, knowable_at=z(NOW - timedelta(minutes=10)))),
    ("availability_unknown but knowable set", lambda b: b["records"][0].update(quality="availability_unknown")),
    ("source_timestamped without any source time", lambda b: b["records"][0].update(published_at=None, available_at=None)),
    ("result knowable differs from the newest record", lambda b: b.update(knowable_at=z(NOW - timedelta(minutes=5)))),
    ("future fetched_at", lambda b: b.update(fetched_at=z(NOW + timedelta(hours=2)))),
    ("501 records", lambda b: b.update(records=[dict(b["records"][0], record_id=f"r{i}") for i in range(501)])),
    ("values extra field", lambda b: b["records"][0]["values"].update(extra=1)),
    ("values out of range", lambda b: b["records"][0]["values"].update(value=101)),
    ("naive timestamp", lambda b: b["records"][0].update(knowable_at="2026-10-09T14:59:00")),
    ("unknown top-level field", lambda b: b.update(surprise=1)),
])
def test_malformed_or_untrusted_replies_fail_closed(label, mutate, tmp_path) -> None:
    body = reply()
    mutate(body)
    with pytest.raises(client.PublicOperationError) as exc:
        served(tmp_path, body)
    assert exc.value.code in {E.SCHEMA_INVALID, E.TEMPLATE_UNAVAILABLE}, label


@pytest.mark.parametrize("code", [c.value for c in E if c is not E.COLLECTOR_UNAVAILABLE])
def test_every_sidecar_error_code_raises_its_typed_error(code, tmp_path) -> None:
    with pytest.raises(client.PublicOperationError) as exc:
        served(tmp_path, reply(error_code=code, status="DEGRADED", records=[]))
    assert exc.value.code.value == code


def test_missing_knowable_at_abstains(tmp_path) -> None:
    body = reply()
    rec = body["records"][0]
    rec.update(quality="availability_unknown", knowable_at=None, published_at=None, available_at=None)
    body["knowable_at"] = None
    r = served(tmp_path, body)
    assert r.records[0].knowable_at is None and r.evidence_records(NOW + timedelta(minutes=1)) == ()


def test_evidence_rules_future_stale_expired_and_cap(tmp_path) -> None:
    r = served(tmp_path, reply())
    assert len(r.evidence_records(NOW + timedelta(minutes=1))) == 1
    with pytest.raises(client.PublicOperationError) as e1:  # decision before the observation
        r.evidence_records(NOW - timedelta(days=1))
    assert e1.value.code is E.SCHEMA_INVALID
    with pytest.raises(client.PublicOperationError) as e2:  # canary window expired
        r.evidence_records(NOW + timedelta(hours=49))
    assert e2.value.code is E.TEMPLATE_UNAVAILABLE
    with pytest.raises(client.PublicOperationError) as e3:  # evidence older than the 7-day window for this feed
        r.evidence_records(NOW + timedelta(days=8))
    assert e3.value.code in {E.OPERATION_DEGRADED, E.TEMPLATE_UNAVAILABLE}
    many = reply()
    many["records"] = [dict(many["records"][0], record_id=f"r{i}") for i in range(129)]
    big = served(tmp_path / "many", many)
    with pytest.raises(client.PublicOperationError) as e4:
        big.evidence_records(NOW + timedelta(minutes=1))
    assert e4.value.code is E.SCHEMA_INVALID


@pytest.mark.parametrize(("op", "days", "ok"), [("cnn.fear_greed", 6, True), ("cnn.fear_greed", 8, False), ("cboe.daily.stats", 13, True), ("cboe.daily.stats", 15, False)])
def test_per_operation_evidence_age_windows(op, days, ok, tmp_path) -> None:
    body = reply(op)
    rec = body["records"][0]
    old = NOW - timedelta(days=days)
    rec.update(as_of=z(old), published_at=z(old), available_at=z(old))
    rec["values"].update({"observed_at": z(old)})
    r = served(tmp_path, body, op)
    if ok:
        assert len(r.evidence_records(NOW + timedelta(minutes=1))) == 1
    else:
        with pytest.raises(client.PublicOperationError):
            r.evidence_records(NOW + timedelta(minutes=1))


def test_package_resolves_to_this_worktree() -> None:
    assert A.WORKTREE in Path(client.__file__).resolve().parents


# ------------------------------------------------------------------ child hygiene

def _env_dumper(tmp: Path) -> Path:
    root = collector_root(tmp)
    out = tmp / "env.json"
    script = root / "dist" / "env_child.py"
    script.write_text(
        "import sys,json,os\nreq=json.loads(sys.stdin.readline())\n"
        f"open({str(out)!r},'w').write(json.dumps(dict(os.environ)))\n"
        "print(json.dumps({'schema_version':1,'request_id':req['request_id'],'operation_id':None,'template_version':None,'source_id':None,'source_tier':None,'status':'OK','fetched_at':'2026-10-09T15:00:00Z','as_of':None,'knowable_at':None,'redistribution':False,'records':[]}),flush=True)\n",
        encoding="utf-8")
    return script


def test_child_receives_a_minimal_allowlisted_environment(tmp_path, monkeypatch) -> None:
    planted = {"LEVIATHAN_VAULT_PASSPHRASE": "x", "DATABENTO_API_KEY": "x", "SOME_SERVICE_TOKEN": "x", "AA_CONTROL": "1", "AA_TEST_CONTROL": "1",
               "API_ANYTHING_BROWSER_ROOTS": "[]", "API_ANYTHING_HOME": "x", "HTTPS_PROXY": "http://evil.invalid", "NODE_OPTIONS": "--require evil.js", "CHROME_PATH": "x"}
    for k, v in planted.items():
        monkeypatch.setenv(k, v)
    sup = client.CollectorSupervisor(sys.executable, _env_dumper(tmp_path), data_dir=tmp_path / "data")
    try:
        sup.health()
    finally:
        sup.close()
    seen = json.loads((tmp_path / "env.json").read_text(encoding="utf-8"))
    assert not (set(seen) & set(planted)), sorted(set(seen) & set(planted))
    allowed = {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "TMPDIR", "LOCALAPPDATA", "PROGRAMFILES", "PROGRAMFILES(X86)", "LEVIATHAN_COLLECTOR_DATA",
               "LEVIATHAN_PUBLIC_USER_AGENT", "LEVIATHAN_REPLAY_ONLY"}
    extras = {k for k in seen if k.upper() not in allowed and not k.upper().startswith(("PYTHON", "__", "SYSTEMDRIVE", "COMSPEC", "PATHEXT", "LC_", "LANG", "UV_INTERNAL"))}
    assert not extras, f"unexpected inherited variables: {sorted(extras)}"
    assert seen["LEVIATHAN_COLLECTOR_DATA"] == str(tmp_path / "data") and seen["LEVIATHAN_PUBLIC_USER_AGENT"] == "LeviathanPublicCollector/1.0"


def _alive(pid: int) -> bool:
    if os.name == "nt":
        out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"], capture_output=True, text=True).stdout
        return str(pid) in out
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def test_timeout_kills_the_whole_process_tree_including_a_browser_like_grandchild(tmp_path) -> None:
    root = collector_root(tmp_path)
    pidfile = tmp_path / "grandchild.pid"
    script = root / "dist" / "tree_child.py"
    script.write_text(
        "import sys,subprocess,time\nsys.stdin.readline()\n"
        f"g=subprocess.Popen([sys.executable,'-c','import time;time.sleep(120)'])\nopen({str(pidfile)!r},'w').write(str(g.pid))\ntime.sleep(120)\n",
        encoding="utf-8")
    sup = client.CollectorSupervisor(sys.executable, script, data_dir=tmp_path / "data", timeout_s=1.5)
    with pytest.raises(client.PublicOperationError) as exc:
        sup.health()
    assert exc.value.code is E.COLLECTOR_UNAVAILABLE
    gpid = int(pidfile.read_text(encoding="utf-8"))
    deadline = time.monotonic() + 8
    while _alive(gpid) and time.monotonic() < deadline:
        time.sleep(0.2)
    alive = _alive(gpid)
    if alive:
        subprocess.run(["taskkill", "/PID", str(gpid), "/F"], capture_output=True)
    assert not alive, "the grandchild (stand-in for Chrome) survived the kill"


def test_force_close_clears_stale_profile_locks_only_under_the_data_dir(tmp_path) -> None:
    root = collector_root(tmp_path)
    data = tmp_path / "data"
    inside = data / "isolated" / "cnn-fear-greed" / "profile"
    inside.mkdir(parents=True)
    (inside / "lockfile").write_text("x")
    (inside / "SingletonLock").write_text("x")
    outside = tmp_path / "owner-chrome" / "User Data"
    outside.mkdir(parents=True)
    (outside / "SingletonLock").write_text("x")
    script = root / "dist" / "hang.py"
    script.write_text("import sys,time\nsys.stdin.readline()\ntime.sleep(60)\n", encoding="utf-8")
    sup = client.CollectorSupervisor(sys.executable, script, data_dir=data, timeout_s=1.0)
    with pytest.raises(client.PublicOperationError):
        sup.health()
    assert not (inside / "lockfile").exists() and not (inside / "SingletonLock").exists()
    assert (outside / "SingletonLock").exists(), "a lock outside the app-data dir must never be touched"


def _notifier(tmp: Path, delay: float, notify: bool) -> Path:
    root = collector_root(tmp)
    note = {"type": "notification", "request_id": str(uuid.uuid4()), "status": "USER_ACTION_REQUIRED", "source_id": f"api_anything.{OP}", "operation_id": OP, "message": "m"}
    reply_body = reply()
    script = root / "dist" / f"slow_{notify}.py"
    script.write_text(
        "import sys,json,time\nreq=json.loads(sys.stdin.readline())\n"
        + (f"print(json.dumps({note!r}),flush=True)\n" if notify else "")
        + f"time.sleep({delay})\nbody=json.loads({json.dumps(json.dumps(reply_body))})\nbody['request_id']=req['request_id']\nprint(json.dumps(body),flush=True)\nsys.stdin.readline()\n",
        encoding="utf-8")
    return script


def test_human_wait_has_its_own_budget_separate_from_the_call_timeout(tmp_path) -> None:
    sup = client.CollectorSupervisor(sys.executable, _notifier(tmp_path / "a", 3.0, True), data_dir=tmp_path / "d", timeout_s=1.0)
    try:
        r = sup.call(OP, {})
        assert r.status is client.OperationStatus.OK, "after USER_ACTION_REQUIRED the call may legitimately outlive the 1 s call timeout"
        assert sup.next_event(1) is not None
    finally:
        sup.close()
    sup2 = client.CollectorSupervisor(sys.executable, _notifier(tmp_path / "b", 3.0, False), data_dir=tmp_path / "d2", timeout_s=1.0)
    with pytest.raises(client.PublicOperationError) as exc:
        sup2.call(OP, {})
    assert exc.value.code is E.COLLECTOR_UNAVAILABLE, "without a hand-off the normal timeout still applies"
    assert client.HUMAN_ACTION_TIMEOUT_SECONDS == 600.0 and client.CALL_TIMEOUT_SECONDS <= 180


# ------------------------------------------------------------------ Big Sur export / import into the real template location

def _pinned_pair(collector: Path, tmp: Path):
    source = C.make_variant(collector, f"x-src-{tmp.name}", vendor="real", challenge="real")
    entry = C.write_pin(source, OP)
    dest = C.make_variant(collector, f"x-dst-{tmp.name}", vendor="real", challenge="real")
    reg = dest / "templates" / "PINNED.json"
    reg.write_bytes((source / "templates" / "PINNED.json").read_bytes())
    (dest / "templates" / OP).mkdir(parents=True, exist_ok=True)
    (dest / "templates" / entry["fixture_path"]).write_bytes((source / "templates" / entry["fixture_path"]).read_bytes())
    C.seal_dist(dest / "dist", reg)
    return source, dest, entry


def test_export_import_lands_in_the_sidecars_real_template_location_and_replays_on_big_sur(collector, tmp_path, sidecar1) -> None:
    source, dest, entry = _pinned_pair(collector, tmp_path)
    bundle = tmp_path / "bundle.json"
    digest = templates.export_pinned_template(OP, data_dir=tmp_path / "unused", registry_path=source / "templates" / "PINNED.json", destination=bundle)
    assert digest == entry["sha256"]
    target = dest / "templates" / entry["template_path"]
    assert not target.exists()
    assert templates.import_pinned_template(bundle, registry_path=dest / "templates" / "PINNED.json", data_dir=tmp_path / "unused") == entry["sha256"]
    assert target.read_bytes() == (source / "templates" / entry["template_path"]).read_bytes(), "installed where the sidecar loads templates"
    data = tmp_path / "bigsur"
    data.mkdir()
    sc = sidecar1(dest, data, world=C.default_world(), extra_env={"LEVIATHAN_REPLAY_ONLY": "1"})
    reply_, notes = sc.call(OP)
    assert notes == [] and reply_["status"] == "OK" and reply_["template_sha256"] == entry["sha256"]
    assert not [p for p in data.rglob("*") if p.is_file() and p.name in {"Cookies", "Login Data"}]


@pytest.mark.parametrize(("field", "value"), [("sha256", "0" * 64), ("version", "pin-evil"), ("approval_id", "other"), ("allowed_hosts", ["evil.example"]),
                                                ("challenge_hosts", ["evil.example"]), ("review_note", "tampered"), ("operation_id", "calendar.fed")])
def test_tampered_bundles_are_refused_and_install_nothing(collector, tmp_path, field, value) -> None:
    source, dest, entry = _pinned_pair(collector, tmp_path)
    bundle = tmp_path / "bundle.json"
    templates.export_pinned_template(OP, data_dir=tmp_path, registry_path=source / "templates" / "PINNED.json", destination=bundle)
    doc = json.loads(bundle.read_text(encoding="utf-8"))
    doc[field] = value
    bundle.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(client.PublicOperationError):
        templates.import_pinned_template(bundle, registry_path=dest / "templates" / "PINNED.json", data_dir=tmp_path)
    assert not (dest / "templates" / entry["template_path"]).exists()


def test_bundle_with_a_swapped_template_body_is_refused(collector, tmp_path) -> None:
    import base64
    source, dest, entry = _pinned_pair(collector, tmp_path)
    bundle = tmp_path / "bundle.json"
    templates.export_pinned_template(OP, data_dir=tmp_path, registry_path=source / "templates" / "PINNED.json", destination=bundle)
    doc = json.loads(bundle.read_text(encoding="utf-8"))
    doc["template_base64"] = base64.b64encode(C.template_for(OP, host="evil.example")).decode()
    bundle.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(client.PublicOperationError):
        templates.import_pinned_template(bundle, registry_path=dest / "templates" / "PINNED.json", data_dir=tmp_path)
    assert not (dest / "templates" / entry["template_path"]).exists()


@pytest.mark.parametrize("secret_key", ["cookie", "Authorization", "session_id", "access_token", "password"])
def test_session_material_is_rejected_on_export(collector, tmp_path, secret_key) -> None:
    source = C.make_variant(collector, f"x-sec-{tmp_path.name}", vendor="real", challenge="real")
    tpl = json.loads(C.template_for(OP))
    tpl["operations"][0]["request"]["headers"][secret_key] = "x"
    C.write_pin(source, OP, template=json.dumps(tpl).encode())
    with pytest.raises(client.PublicOperationError):
        templates.export_pinned_template(OP, data_dir=tmp_path, registry_path=source / "templates" / "PINNED.json", destination=tmp_path / "b.json")
    assert not (tmp_path / "b.json").exists()


def test_export_requires_the_template_to_match_its_pin_and_the_op_to_be_pinned(collector, tmp_path) -> None:
    source, _, entry = _pinned_pair(collector, tmp_path)
    (source / "templates" / entry["template_path"]).write_bytes(b'{"tampered": true}')
    with pytest.raises(client.PublicOperationError):
        templates.export_pinned_template(OP, data_dir=tmp_path, registry_path=source / "templates" / "PINNED.json", destination=tmp_path / "b.json")
    with pytest.raises(client.PublicOperationError) as exc:
        templates.export_pinned_template("calendar.fed", data_dir=tmp_path, registry_path=source / "templates" / "PINNED.json", destination=tmp_path / "c.json")
    assert exc.value.code is E.TEMPLATE_UNPINNED


def test_finding_import_must_not_write_outside_the_templates_tree(collector, tmp_path) -> None:
    source, dest, entry = _pinned_pair(collector, tmp_path)
    bundle = tmp_path / "bundle.json"
    templates.export_pinned_template(OP, data_dir=tmp_path, registry_path=source / "templates" / "PINNED.json", destination=bundle)
    reg = dest / "templates" / "PINNED.json"
    registry = json.loads(reg.read_text(encoding="utf-8"))
    registry["operations"][OP]["template_path"] = "../../escaped.json"
    reg.write_text(json.dumps(registry), encoding="utf-8")
    from contextlib import suppress

    with suppress(client.PublicOperationError):
        templates.import_pinned_template(bundle, registry_path=reg, data_dir=tmp_path)
    assert not (dest.parent / "escaped.json").exists() and not (dest / "templates" / ".." / ".." / "escaped.json").resolve().exists(), "import must not write outside the templates tree"
