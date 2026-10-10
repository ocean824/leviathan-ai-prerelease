"""Cycle 2: challenge hand-off on the production call path, distinct outcomes, and replay-only (Big Sur) mode."""

from __future__ import annotations

import json
from pathlib import Path

import aa_harness as A
import c2_harness as C
import pytest

pytest_plugins = ("c2_fixtures",)

OP = "cnn.fear_greed"
WALL_BODIES = {
    "captcha": "<html><body>Please complete the CAPTCHA</body></html>",
    "verify human": "<html><body>Please verify you are human to continue</body></html>",
    "cloudflare": "<html><script>window._cf_chl_opt={}</script></html>",
    "cf-chl": "<html><form id='cf-chl-widget'></form></html>",
    "px": "<html><div id='px-captcha'></div></html>",
    "datadome": "<html>datadome protection</html>",
}


def wall_world(status=403, body=WALL_BODIES["captcha"], then_ok=True):
    world = C.default_world()
    routes = [{"status": status, "text": body, "headers": {"content-type": "text/html"}}]
    if then_ok:
        routes.append({"status": 200, "json": C.native_body(OP, C.fresh_rows(OP))})
    world["hosts"]["www.cnn.com"]["routes"][C.FEED_PATH] = routes
    return world


def walled(prod, data, sidecar1, outcome="completed", **kw):
    C.write_pin(prod, OP)
    sc = sidecar1(prod, data, world=wall_world(**kw))
    sc.set_control({"challenge_outcome": outcome})
    return sc


@pytest.mark.parametrize("marker", list(WALL_BODIES))
@pytest.mark.parametrize("status", [403, 503])
def test_real_bot_wall_markers_hand_off_to_the_user_then_resume(prod_realfc, app_data, sidecar1, marker, status) -> None:
    sc = walled(prod_realfc, app_data, sidecar1, status=status, body=WALL_BODIES[marker])
    reply, notes = sc.call(OP, timeout=60)
    assert len(notes) == 1 and notes[0]["type"] == "notification" and notes[0]["status"] == "USER_ACTION_REQUIRED"
    assert notes[0]["operation_id"] == OP and notes[0]["source_id"] == f"api_anything.{OP}" and notes[0]["request_id"] == reply["request_id"]
    assert reply["status"] == "OK" and len(reply["records"]) == 1, "after the user clears the check the operation resumes"
    [window] = sc.stub_events("challenge")
    assert Path(window["profileDir"]).resolve() == (app_data / "isolated" / "cnn-fear-greed" / "profile").resolve()
    assert window["url"] == "https://www.cnn.com/markets/fear-and-greed" and window["timeoutMs"] == 600_000
    assert window["challengeHosts"] == [] and Path(window["dataDir"]).resolve() == app_data.resolve()
    assert len(sc.non_robots_requests()) == 2


@pytest.mark.parametrize(("outcome", "status", "code"), [
    ("declined", "USER_ACTION_DECLINED", "USER_ACTION_DECLINED"), ("timeout", "TIMEOUT", "TIMEOUT"),
    ("window_failed", "DEGRADED", "CHALLENGE_WINDOW_FAILED"), ("browser_unavailable", "DEGRADED", "BROWSER_UNAVAILABLE")])
def test_each_non_completed_outcome_is_distinct_and_abstains_without_retrying(prod_realfc, app_data, sidecar1, outcome, status, code) -> None:
    sc = walled(prod_realfc, app_data, sidecar1, outcome)
    reply, notes = sc.call(OP, timeout=60)
    assert reply["status"] == status and reply["error_code"] == code and reply["records"] == []
    assert len(sc.non_robots_requests()) == 1, "no further request after a non-completed hand-off"
    assert len(notes) == 1


def test_a_plain_403_without_wall_markers_is_not_a_challenge(prod_realfc, app_data, sidecar1) -> None:
    sc = walled(prod_realfc, app_data, sidecar1, body="Forbidden", then_ok=False)
    reply, notes = sc.call(OP, timeout=60)
    assert notes == [] and sc.stub_events("challenge") == [] and reply["status"] == "DEGRADED" and reply["records"] == []


def test_a_challenge_word_in_the_vendor_reason_text_alone_is_not_a_signal(prod_stub, app_data, sidecar1) -> None:
    C.write_pin(prod_stub, OP)
    sc = sidecar1(prod_stub, app_data, world=C.default_world())
    ok = {"result": {"ok": True, "class": "ok", "data": C.fresh_rows(OP)}}  # first call = the pinned-fixture replay
    sc.set_control({"challenge_outcome": "completed", "call": [ok, {"result": {"ok": False, "class": "blocked", "reason": "captcha challenge detected"}}]})
    reply, notes = sc.call(OP)
    assert len(sc.stub_events("call")) == 2, "the live call must actually have been reached"
    assert notes == [] and sc.stub_events("challenge") == [] and reply["status"] == "DEGRADED" and reply["error_code"] != "TEMPLATE_UNAVAILABLE"


def test_a_structured_vendor_challenge_flag_is_a_signal(prod_stub, app_data, sidecar1) -> None:
    C.write_pin(prod_stub, OP)
    rows = C.fresh_rows(OP)
    ok = {"result": {"ok": True, "class": "ok", "data": rows}}
    wall = {"result": {"ok": False, "class": "blocked", "challenge": True, "reason": "wall"}}
    sc = sidecar1(prod_stub, app_data, world=C.default_world())
    sc.set_control({"challenge_outcome": "declined", "call": [ok, wall]})  # first call = fixture replay, second = the live call
    reply, notes = sc.call(OP)
    assert len(notes) == 1 and reply["status"] == "USER_ACTION_DECLINED"


def test_repair_with_a_wall_also_hands_off(prod_stub, app_data, sidecar1) -> None:
    C.write_pin(prod_stub, OP)
    sc = sidecar1(prod_stub, app_data, world=C.default_world())
    rows = C.fresh_rows(OP)
    sc.set_control({"challenge_outcome": "declined", "call": [{"result": {"ok": True, "class": "ok", "data": rows}}],
                    "heal": [{"result": {"ok": False, "class": "blocked", "challenge": True, "reason": "wall"}}]})
    reply, notes = sc.repair(OP)
    assert len(notes) == 1 and reply["status"] == "USER_ACTION_DECLINED"
    assert not (app_data / "candidates").exists() or not list((app_data / "candidates").rglob("*.json"))


def test_observation_a_200_status_interstitial_page_is_not_data_and_ideally_a_hand_off(prod_realfc, app_data, sidecar1) -> None:
    """A bot interstitial served with HTTP 200 must never become records.  (Cycle 3 is to hand it off as well.)"""
    world = wall_world(status=200, body=WALL_BODIES["verify human"], then_ok=False)
    C.write_pin(prod_realfc, OP)
    sc = sidecar1(prod_realfc, app_data, world=world)
    sc.set_control({"challenge_outcome": "declined"})
    reply, notes = sc.call(OP, timeout=60)
    assert reply["records"] == [] and reply["status"] != "OK"


# ------------------------------------------------------------------ replay-only (macOS 11.7 / Big Sur)

def test_replay_only_sidecar_refuses_learn_and_repair_without_a_browser(prod_stub, app_data, sidecar1) -> None:
    C.write_pin(prod_stub, OP)
    sc = sidecar1(prod_stub, app_data, world=C.default_world(), extra_env={"LEVIATHAN_REPLAY_ONLY": "1"})
    for method in (sc.learn, sc.repair):
        reply, notes = method(OP)
        assert reply["error_code"] == "BROWSER_UNAVAILABLE" and notes == [] and reply["records"] == []
    assert sc.stub_events("learn") == [] and sc.stub_events("heal") == [] and sc.stub_events("challenge") == []


def test_replay_only_sidecar_serves_pinned_http_and_never_opens_a_window_on_a_wall(prod_realfc, app_data, sidecar1) -> None:
    C.write_pin(prod_realfc, OP)
    sc = sidecar1(prod_realfc, app_data, world=C.default_world(), extra_env={"LEVIATHAN_REPLAY_ONLY": "1"})
    assert sc.call(OP)[0]["status"] == "OK"
    sc.close()
    data2 = app_data.parent / "second"
    data2.mkdir()
    sc2 = sidecar1(prod_realfc, data2, world=wall_world(), extra_env={"LEVIATHAN_REPLAY_ONLY": "1"})
    sc2.set_control({"challenge_outcome": "completed"})
    reply, notes = sc2.call(OP, timeout=60)
    assert reply["error_code"] == "BROWSER_UNAVAILABLE" and notes == [] and sc2.stub_events("challenge") == []


def _fake_child(tmp: Path, body: str) -> Path:
    # layout the client expects: <root>/dist/<script>, <root>/templates/PINNED.json, <root>/runtime-manifest.json
    (tmp / "dist").mkdir(parents=True, exist_ok=True)
    script = tmp / "dist" / "fake_sidecar.py"
    script.write_text("import sys,json,os,time\n" + body, encoding="utf-8")
    return script


def test_client_detects_big_sur_and_never_asks_for_a_browser(tmp_path: Path, monkeypatch) -> None:
    import platform
    from leviathan_market_data.public_sources import api_anything_client as client
    monkeypatch.setattr(platform, "system", lambda: "Darwin")
    monkeypatch.setattr(platform, "mac_ver", lambda: ("11.7.10", ("", "", ""), "x86_64"))
    marker = tmp_path / "started.txt"
    sup = client.CollectorSupervisor("python", _fake_child(tmp_path, f"open({str(marker)!r},'w').write('x')\n"), data_dir=tmp_path / "d")
    for method in (lambda: sup.learn(OP, ({}, {})), lambda: sup.repair(OP, {})):
        with pytest.raises(client.PublicOperationError) as exc:
            method()
        assert exc.value.code is client.PublicOperationErrorCode.BROWSER_UNAVAILABLE
    assert not marker.exists(), "no sidecar process may start just to refuse learn/repair"


def test_client_passes_replay_only_to_the_child_on_big_sur_and_not_elsewhere(tmp_path: Path, monkeypatch) -> None:
    import platform
    import sys
    from leviathan_market_data.public_sources import api_anything_client as client
    out = tmp_path / "env.json"
    body = ("req=json.loads(sys.stdin.readline())\n" f"open({str(out)!r},'w').write(json.dumps(dict(os.environ)))\n"
            "print(json.dumps({'schema_version':1,'request_id':req['request_id'],'operation_id':None,'template_version':None,'source_id':None,'source_tier':None,'status':'OK','fetched_at':'2026-10-09T15:00:00Z','as_of':None,'knowable_at':None,'redistribution':False,'records':[]}),flush=True)\n")
    for system, ver, expect in (("Darwin", "11.7.10", "1"), ("Darwin", "14.2", None), ("Windows", "", None)):
        monkeypatch.setattr(platform, "system", lambda s=system: s)
        monkeypatch.setattr(platform, "mac_ver", lambda v=ver: (v, ("", "", ""), "x86_64"))
        sup = client.CollectorSupervisor(sys.executable, _fake_child(tmp_path / system / ver.replace(".", "_"), body), data_dir=tmp_path / "d")
        try:
            sup.health()
        finally:
            sup.close()
        assert json.loads(out.read_text(encoding="utf-8")).get("LEVIATHAN_REPLAY_ONLY") == expect, (system, ver)
