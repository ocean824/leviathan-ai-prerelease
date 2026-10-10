"""Rules 2, 3 and 4 against the real wrapper with a *stub* vendor (call/heal/addOperation are
scripted) and a fake challenge window.  Exercises the wrapper's own decisions: pinning, versioning,
strict schema validation, canary comparison, user-action hand-off, bounded wait, isolation."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import aa_harness as H
import pytest

OP = "calendar.fed"
SITE = "fed-calendar"
ARGS = {"year": 2026}
T1 = b'{"name":"fed-calendar","marker":"v1"}'
T2 = b'{"name":"fed-calendar","marker":"v2-candidate"}'


def row(name="FOMC", published=True, **extra):
    r = {
        "event_name": name,
        "agency": "FRB",
        "scheduled_at": "2026-12-09T19:00:00Z",
        "release_type": "meeting",
        "knowable_at": "2026-10-01T00:00:00Z",
    }
    if published:
        r["published_at"] = "2026-10-01T00:00:00Z"
    r.update(extra)
    return r


def ok(rows):
    return {"result": {"ok": True, "class": "ok", "tier": 1, "data": rows}}


def blocked(reason="captcha challenge detected"):
    return {"result": {"ok": False, "class": "blocked", "reason": reason}}


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


@pytest.fixture
def sc(v_stub: Path, data_dir: Path, sidecar_factory):
    return sidecar_factory(v_stub, data_dir)


def activate(sc, rows=None, template=T1):
    rows = rows or [row()]
    sc.set_control({"learn": [{"write_site": template.decode()}], "call": [ok(rows), ok(rows)]})
    reply, _ = sc.learn(OP, [ARGS, {"year": 2027}])
    assert reply["status"] == "OK", reply
    return reply


# ------------------------------------------------------------------ rule 3: pinned, versioned

def test_learn_activates_a_hash_pinned_versioned_template(sc, data_dir: Path) -> None:
    reply = activate(sc)
    entry = sc.registry()["active"][OP]
    assert re.fullmatch(r"[a-f0-9]{64}", entry["sha256"]) and entry["sha256"] == sha(T1)
    assert entry["version"] == reply["template_version"]
    stored = data_dir / entry["template_path"]
    assert stored.read_bytes() == T1 and data_dir in stored.resolve().parents
    assert reply["source_tier"] == 3 and reply["redistribution"] is False
    assert all(r["redistribution"] is False for r in reply["records"])
    assert (data_dir / "last-good" / f"{OP}.json").exists()


def test_learn_requires_canary_agreement_between_examples(sc) -> None:
    sc.set_control({"learn": [{"write_site": T1.decode()}], "call": [ok([row()]), ok([row(published=False)])]})
    reply, _ = sc.learn(OP, [ARGS, {"year": 2027}])
    assert reply["status"] == "DEGRADED" and reply["records"] == []
    assert OP not in sc.registry().get("active", {}), "mismatching examples must not activate a template"


def test_learn_with_empty_second_example_is_not_activated(sc) -> None:
    sc.set_control({"learn": [{"write_site": T1.decode()}], "call": [ok([row()]), ok([])]})
    reply, _ = sc.learn(OP, [ARGS, {"year": 2027}])
    assert reply["status"] == "DEGRADED"
    assert OP not in sc.registry().get("active", {})


def test_learn_with_schema_invalid_output_is_not_activated(sc) -> None:
    bad = row()
    bad["unexpected"] = "field"
    sc.set_control({"learn": [{"write_site": T1.decode()}], "call": [ok([bad]), ok([bad])]})
    reply, _ = sc.learn(OP, [ARGS, {"year": 2027}])
    assert reply["error_code"] == "SCHEMA_INVALID" and reply["records"] == []
    assert OP not in sc.registry().get("active", {})


def test_learn_when_site_call_fails_is_not_activated(sc) -> None:
    sc.set_control({"learn": [{"write_site": T1.decode()}], "call": [blocked("HTTP 500"), blocked("HTTP 500")]})
    reply, _ = sc.learn(OP, [ARGS, {"year": 2027}])
    assert reply["status"] == "DEGRADED" and OP not in sc.registry().get("active", {})


def test_repair_with_matching_canary_activates_new_immutable_version(sc, data_dir: Path) -> None:
    activate(sc)
    old = sc.registry()["active"][OP]
    sc.set_control({"heal": [{"write_site": T2.decode(), **ok([row("FOMC-2")])}], "call": [ok([row()])]})
    reply, _ = sc.repair(OP, ARGS)
    assert reply["status"] == "OK", reply
    new = sc.registry()["active"][OP]
    assert new["version"] != old["version"] and new["sha256"] == sha(T2) != old["sha256"]
    assert reply["template_version"] == new["version"]
    assert (data_dir / old["template_path"]).read_bytes() == T1, "old version file is immutable"
    assert (data_dir / new["template_path"]).read_bytes() == T2
    sc.call(OP, ARGS)
    assert sc.log_events("call")[-1]["site_sha"] == sha(T2)


def test_repair_canary_failure_keeps_old_version_serving(sc, data_dir: Path) -> None:
    activate(sc)
    old = sc.registry()["active"][OP]
    drift = row("FOMC-2", published=False)  # zod-valid but record shape differs from last good
    sc.set_control({"heal": [{"write_site": T2.decode(), **ok([drift])}], "call": [ok([row()])]})
    reply, _ = sc.repair(OP, ARGS)
    assert reply["error_code"] == "OPERATION_DEGRADED" and reply["records"] == []
    assert sc.registry()["active"][OP] == old
    assert sorted(p.name for p in (data_dir / "template-versions" / OP).iterdir()) == [
        Path(old["template_path"]).name
    ], "a rejected candidate must not even be stored as an active-capable version"
    # the previous version still serves, with the previous pinned bytes
    reply2, _ = sc.call(OP, ARGS)
    assert reply2["status"] == "OK" and reply2["template_version"] == old["version"]
    assert sc.log_events("call")[-1]["site_sha"] == old["sha256"]


def test_repair_schema_invalid_candidate_keeps_old_version(sc) -> None:
    activate(sc)
    old = sc.registry()["active"][OP]
    sc.set_control({"heal": [{"write_site": T2.decode(), **ok([{"event_name": "x"}])}]})
    reply, _ = sc.repair(OP, ARGS)
    assert reply["error_code"] == "SCHEMA_INVALID" and reply["records"] == []
    assert sc.registry()["active"][OP] == old


def test_repair_that_returns_no_data_is_not_activated(sc) -> None:
    activate(sc)
    old = sc.registry()["active"][OP]
    sc.set_control({"heal": [{"result": {"ok": True, "class": "ok", "healed": False}}]})
    reply, _ = sc.repair(OP, ARGS)
    assert reply["status"] == "DEGRADED" and reply["records"] == []
    assert sc.registry()["active"][OP] == old


def test_repair_failure_abstains_and_keeps_old(sc) -> None:
    activate(sc)
    old = sc.registry()["active"][OP]
    sc.set_control({"heal": [blocked("recapture needs the browser")]})
    reply, _ = sc.repair(OP, ARGS)
    assert reply["status"] == "DEGRADED" and reply["records"] == []
    assert sc.registry()["active"][OP] == old


def test_repair_without_last_good_baseline_does_not_activate(sc, data_dir: Path) -> None:
    activate(sc)
    old = sc.registry()["active"][OP]
    (data_dir / "last-good" / f"{OP}.json").unlink()
    sc.set_control({"heal": [{"write_site": T2.decode(), **ok([row()])}]})
    reply, _ = sc.repair(OP, ARGS)
    assert reply["error_code"] == "OPERATION_DEGRADED" and sc.registry()["active"][OP] == old


def test_when_old_version_cannot_serve_operation_abstains(sc) -> None:
    activate(sc)
    sc.set_control({"call": [blocked("HTTP 500: upstream drift")]})
    reply, _ = sc.call(OP, ARGS)
    assert reply["status"] == "DEGRADED" and reply["records"] == [] and reply["error_code"] == "OPERATION_DEGRADED"


def test_tampered_template_file_is_refused_not_served(sc, data_dir: Path) -> None:
    activate(sc)
    entry = sc.registry()["active"][OP]
    (data_dir / entry["template_path"]).write_bytes(T2)
    before = len(sc.log_events("call"))
    reply, _ = sc.call(OP, ARGS)
    assert reply["error_code"] == "TEMPLATE_UNAVAILABLE" and reply["records"] == []
    assert len(sc.log_events("call")) == before, "no vendor call may run on an unpinned template"


def test_tampered_runtime_copy_is_restored_from_pinned_bytes(sc, data_dir: Path) -> None:
    activate(sc)
    entry = sc.registry()["active"][OP]
    sc.call(OP, ARGS)
    runtime_copy = data_dir / "isolated" / SITE / "sites" / f"{SITE}.json"
    runtime_copy.write_bytes(b'{"name":"fed-calendar","marker":"evil"}')
    sc.call(OP, ARGS)
    assert sc.log_events("call")[-1]["site_sha"] == entry["sha256"]


@pytest.mark.parametrize(
    "mutate",
    [
        lambda e: e.update(sha256="0" * 64),
        lambda e: e.update(sha256="ZZ"),
        lambda e: e.pop("sha256"),
        lambda e: e.update(version=""),
        lambda e: e.update(template_path="../../outside.json"),
        lambda e: e.update(template_path="C:/Windows/win.ini"),
    ],
)
def test_invalid_or_escaping_registry_entries_fail_closed(sc, data_dir: Path, mutate) -> None:
    activate(sc)
    reg = sc.registry()
    mutate(reg["active"][OP])
    (data_dir / "template-registry.json").write_text(json.dumps(reg), encoding="utf-8")
    before = len(sc.log_events("call"))
    reply, _ = sc.call(OP, ARGS)
    assert reply["error_code"] == "TEMPLATE_UNAVAILABLE" and reply["records"] == []
    assert len(sc.log_events("call")) == before


def test_corrupt_registry_means_all_operations_unavailable(sc, data_dir: Path) -> None:
    activate(sc)
    (data_dir / "template-registry.json").write_text("{not json", encoding="utf-8")
    reply, _ = sc.call(OP, ARGS)
    assert reply["error_code"] == "TEMPLATE_UNAVAILABLE"


def test_missing_knowable_at_stays_null_and_quality_unknown_through_the_sidecar(sc) -> None:
    activate(sc)
    bare = row()
    bare.pop("knowable_at")
    bare.pop("published_at")
    sc.set_control({"call": [ok([bare])]})
    reply, _ = sc.call(OP, ARGS)
    [rec] = reply["records"]
    assert rec["knowable_at"] is None and reply["knowable_at"] is None
    assert rec["available_at"] is None and rec["quality"] == "availability_unknown"
    assert rec["redistribution"] is False and reply["redistribution"] is False


# ------------------------------------------------------------------ rule 4: bot checks

def _challenge_setup(sc, outcome):
    activate(sc)
    sc.set_control({"challenge_outcome": outcome, "call": [blocked(), ok([row("after-user")])]})


def test_challenge_declined_gives_typed_notification_then_declined_and_abstains(sc, data_dir: Path) -> None:
    _challenge_setup(sc, "declined")
    n_calls = len(sc.log_events("call"))
    reply, notes = sc.call(OP, ARGS)
    assert len(notes) == 1
    note = notes[0]
    assert note["type"] == "notification" and note["status"] == "USER_ACTION_REQUIRED"
    assert note["operation_id"] == OP and note["source_id"] == f"api_anything.{OP}"
    assert note["request_id"] == reply["request_id"] and 0 < len(note["message"]) <= 256
    assert reply["status"] == "USER_ACTION_DECLINED" and reply["error_code"] == "USER_ACTION_DECLINED"
    assert reply["records"] == []
    assert len(sc.log_events("call")) == n_calls + 1, "no retry after a decline"
    [ch] = sc.log_events("challenge")
    assert ch["timeoutMs"] == 120_000
    assert ch["url"].startswith("https://www.federalreserve.gov/")


def test_challenge_timeout_gives_timeout_and_abstains(sc) -> None:
    _challenge_setup(sc, "timeout")
    n_calls = len(sc.log_events("call"))
    reply, notes = sc.call(OP, ARGS)
    assert len(notes) == 1
    assert reply["status"] == "TIMEOUT" and reply["error_code"] == "TIMEOUT" and reply["records"] == []
    assert len(sc.log_events("call")) == n_calls + 1


def test_challenge_completed_resumes_with_one_retry(sc) -> None:
    _challenge_setup(sc, "completed")
    n_calls = len(sc.log_events("call"))
    reply, notes = sc.call(OP, ARGS)
    assert len(notes) == 1 and reply["status"] == "OK"
    assert reply["records"][0]["values"]["event_name"] == "after-user"
    calls = sc.log_events("call")[n_calls:]
    assert len(calls) == 2 and calls[0]["maxTier"] == 1 and calls[1]["maxTier"] == 2


def test_notification_precedes_wait_for_the_window(sc) -> None:
    """The user must be told before the (up to 120 s) wait starts."""
    _challenge_setup(sc, "declined")
    sc.set_control({"challenge_outcome": "declined", "call": [blocked()]})
    sc.send({"method": "call", "request_id": "3f2b8c9e-9a71-4d57-bb0a-4e0e4f6b8d11", "operation_id": OP, "args": ARGS})
    first = sc.read_line()
    assert first["type"] == "notification"


def test_challenge_profile_is_inside_app_data_never_owner_profile(sc, data_dir: Path) -> None:
    _challenge_setup(sc, "declined")
    sc.call(OP, ARGS)
    [ch] = sc.log_events("challenge")
    profile = Path(ch["profileDir"]).resolve()
    assert data_dir.resolve() in profile.parents, profile
    assert not re.search(r"Google[\\/]+Chrome|User Data|BraveSoftware|Mozilla|Microsoft[\\/]+Edge", str(profile)), profile


@pytest.mark.parametrize("reason", ["HTTP 500", "needs tier 2, capped at 1", "rate limited", "drift"])
def test_non_challenge_failures_do_not_raise_user_action(sc, reason: str) -> None:
    activate(sc)
    sc.set_control({"challenge_outcome": "completed", "call": [blocked(reason)]})
    reply, notes = sc.call(OP, ARGS)
    assert notes == [] and reply["status"] == "DEGRADED" and sc.log_events("challenge") == []


@pytest.mark.parametrize("reason", ["captcha challenge detected", "Cloudflare challenge page (HTTP 403)",
                                    "robot check", "please verify you are human"])
def test_challenge_reasons_route_to_user_action(sc, reason: str) -> None:
    activate(sc)
    sc.set_control({"challenge_outcome": "declined", "call": [blocked(reason)]})
    reply, notes = sc.call(OP, ARGS)
    assert len(notes) == 1 and reply["status"] == "USER_ACTION_DECLINED"


def test_challenge_during_repair_hands_off_and_declines(sc) -> None:
    activate(sc)
    old = sc.registry()["active"][OP]
    sc.set_control({"challenge_outcome": "declined", "heal": [blocked()]})
    reply, notes = sc.repair(OP, ARGS)
    assert len(notes) == 1 and reply["status"] == "USER_ACTION_DECLINED" and reply["records"] == []
    assert sc.registry()["active"][OP] == old


def test_finding_learn_challenge_must_open_visible_window(sc) -> None:
    """FINDING: a first-time learn has no pinned template, so processRequest gets no profileDir and the
    wrapper emits the notification but never opens the window (it throws USER_ACTION_REQUIRED)."""
    sc.set_control({"challenge_outcome": "completed", "learn": [{"throw": "captcha challenge detected"}]})
    reply, notes = sc.learn(OP, [ARGS, {"year": 2027}])
    assert len(notes) == 1 and notes[0]["status"] == "USER_ACTION_REQUIRED"
    assert sc.log_events("challenge"), "user was notified but no visible window was ever opened"


@pytest.mark.xfail(reason="OBSERVATION (low): worst-case call = 15s tier-1 + 120s human wait + 15s retry = "
                   "150s, exactly the Python CALL_TIMEOUT_SECONDS; no margin, a slow solve can be killed "
                   "by the client as COLLECTOR_UNAVAILABLE", strict=False)
def test_finding_client_timeout_has_margin_over_worst_case_human_flow(collector: Path) -> None:
    text = (collector / "dist" / "contracts.js").read_text(encoding="utf-8")
    num = lambda n: int(re.search(rf"{n} = ([\d_]+)", text).group(1).replace("_", ""))  # noqa: E731
    from conftest import client

    worst = 2 * num("OPERATION_TIMEOUT_MS") + num("HUMAN_ACTION_TIMEOUT_MS")
    assert worst / 1000 < client.CALL_TIMEOUT_SECONDS


# ------------------------------------------------------------------ rule 2: isolation

def test_all_vendor_work_runs_under_app_data_even_if_env_points_elsewhere(
    v_stub: Path, data_dir: Path, sidecar_factory
) -> None:
    owner = data_dir.parent / "owner-home" / ".api-anything"
    sc = sidecar_factory(v_stub, data_dir, extra_env={"API_ANYTHING_HOME": str(owner)})
    activate(sc)
    sc.set_control({"call": [ok([row()])], "heal": [{"write_site": T1.decode(), **ok([row()])}]})
    sc.call(OP, ARGS)
    sc.repair(OP, ARGS)
    homes = {e["home"] for e in sc.log_events() if "home" in e}
    assert homes
    for h in homes:
        assert data_dir.resolve() in Path(h).resolve().parents, h
    assert not owner.exists()


def test_wrapper_does_not_import_or_reference_browser_cookie_machinery() -> None:
    text = (H.COLLECTOR_SRC / "src" / "main.ts").read_text(encoding="utf-8") + (
        H.COLLECTOR_SRC / "src" / "challenge.ts"
    ).read_text(encoding="utf-8")
    for needle in ("import.js", "login.js", "importSession", "reimportIfBrowser", "addCookies",
                   "storageState", "cookies(", "userDataDir", "executablePath", "channel:"):
        assert needle not in text, needle


def test_no_solver_or_fingerprint_spoofing_anywhere_in_product_code() -> None:
    roots = [
        H.COLLECTOR_SRC / "src",
        H.WORKTREE / "packages" / "leviathan-market-data" / "src" / "leviathan_market_data" / "public_sources",
    ]
    hits = []
    for root in roots:
        for path in root.rglob("*"):
            if path.suffix in {".ts", ".py", ".js", ".mjs"} and not path.name.endswith(".test.ts"):
                for m in H.FORBIDDEN.finditer(path.read_text(encoding="utf-8")):
                    hits.append((path.name, m.group(0)))
    assert hits == []
    # the vendored browser layer: only its own UA override (honest, declared) is allowed
    vendor = (H.COLLECTOR_SRC / "vendor" / "api-anything" / "src" / "browser.ts").read_text(encoding="utf-8")
    assert "LEVIATHAN_PUBLIC_USER_AGENT" in vendor
    for bad in ("AutomationControlled", "navigator.webdriver", "addInitScript", "stealth"):
        assert bad not in vendor, bad
