"""Cycle 2: persistent limiter (never sleeps the cadence), candidate-only learn/repair, first-time-learn window.
Production entrypoint; fake internet via the node --import seam; no AA_CONTROL anywhere."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

import aa_harness as A
import c2_harness as C
import pytest

pytest_plugins = ("c2_fixtures",)

OP = "cnn.fear_greed"


def pinned(prod, data, sidecar1, op=OP, world=None, **pin):
    C.write_pin(prod, op, **pin)
    return sidecar1(prod, data, world=world or C.default_world(op))


def timed(fn, *a, **kw):
    t0 = time.monotonic()
    out = fn(*a, **kw)
    return out, time.monotonic() - t0


def ok(rows, op=OP):
    # "fetch": the scripted vendor goes through the production fetch hook (publicFetch), as the real vendor does,
    # so the collector records the raw response body that candidate fixtures are built from.
    return {"result": {"ok": True, "class": "ok", "tier": 1, "data": rows}, "fetch": f"https://{C.SITE_HOST[op]}{C.FEED_PATH}"}


# ------------------------------------------------------------------ limiter

def test_second_call_is_refused_immediately_not_slept(prod_real, app_data, sidecar1) -> None:
    sc = pinned(prod_real, app_data, sidecar1)
    (first, _), t1 = timed(sc.call, OP)
    assert first["status"] == "OK"
    (second, _), t2 = timed(sc.call, OP)
    assert second["error_code"] in {"RATE_LIMITED", "NOT_DUE"} and second["records"] == [] and second["status"] == "DEGRADED"
    assert t2 < 3, f"second call took {t2:.1f}s: the limiter must answer, not sleep"
    assert t1 < 20, f"first call took {t1:.1f}s"
    assert len(sc.non_robots_requests()) == 1, "a refused call must not send a request"


def test_within_cadence_but_past_min_interval_is_not_due_and_instant(prod_real, app_data, sidecar1) -> None:
    sc = pinned(prod_real, app_data, sidecar1)
    sc.call(OP)
    sc.age_rate_state(OP, 10)  # beyond the 5 s spacing, far inside the 3600 s cadence
    (reply, _), elapsed = timed(sc.call, OP)
    assert reply["error_code"] == "NOT_DUE" and reply["records"] == []
    assert elapsed < 3 and len(sc.non_robots_requests()) == 1


def test_due_again_after_the_cadence(prod_real, app_data, sidecar1) -> None:
    sc = pinned(prod_real, app_data, sidecar1)
    sc.call(OP)
    sc.age_rate_state(OP, 3700)
    reply, _ = sc.call(OP)
    assert reply["status"] == "OK" and len(sc.non_robots_requests()) == 2


def test_limiter_state_is_persisted_across_restarts(prod_real, app_data, sidecar1) -> None:
    sc = pinned(prod_real, app_data, sidecar1)
    sc.call(OP)
    state = json.loads((app_data / "rate-state.json").read_text(encoding="utf-8"))["operations"][OP]
    assert {"last_send_at", "last_success_at"} <= set(state)
    sc.close()
    sc2 = sidecar1(prod_real, app_data, world=C.default_world())
    n = len(sc2.non_robots_requests())
    reply, elapsed = timed(sc2.call, OP)
    assert reply[0]["error_code"] in {"RATE_LIMITED", "NOT_DUE"} and elapsed < 3
    assert len(sc2.non_robots_requests()) == n, "a fresh process must honour the previous process's send time"


def test_state_is_per_operation_and_cadence_is_per_operation(prod_real, app_data, sidecar1) -> None:
    C.write_pin(prod_real, OP)
    C.write_pin(prod_real, "calendar.fed")
    world = C.default_world(OP)
    world["hosts"].update(C.default_world("calendar.fed")["hosts"])
    sc = sidecar1(prod_real, app_data, world=world)
    assert sc.call(OP)[0]["status"] == "OK"
    assert sc.call("calendar.fed")[0]["status"] == "OK", "one operation's send must not throttle another"


def test_http_429_with_retry_after_backs_off_and_survives_restart(prod_real, app_data, sidecar1) -> None:
    world = C.default_world()
    world["hosts"]["www.cnn.com"]["routes"][C.FEED_PATH] = {"status": 429, "retry_after": 120, "text": "slow down"}
    sc = pinned(prod_real, app_data, sidecar1, world=world)
    (reply, _), elapsed = timed(sc.call, OP)
    assert reply["error_code"] == "RATE_LIMITED" and reply["records"] == [] and elapsed < 15
    until = json.loads((app_data / "rate-state.json").read_text(encoding="utf-8"))["operations"][OP]["backoff_until"]
    from datetime import datetime
    delta = (datetime.fromisoformat(until.replace("Z", "+00:00")) - C.now()).total_seconds()
    assert 100 < delta <= 125, delta
    sent = len(sc.non_robots_requests())
    sc.age_rate_state(OP, 10)  # past the 5 s spacing but well inside the backoff
    again, _ = sc.call(OP)
    assert again["error_code"] == "RATE_LIMITED" and len(sc.non_robots_requests()) == sent
    sc.close()
    sc2 = sidecar1(prod_real, app_data, world=C.default_world())
    n = len(sc2.non_robots_requests())
    assert sc2.call(OP)[0]["error_code"] == "RATE_LIMITED" and len(sc2.non_robots_requests()) == n, "backoff must persist"
    sc2.age_rate_state(OP, 200)
    assert sc2.call(OP)[0]["status"] == "OK", "backoff expires"


def test_http_429_without_retry_after_uses_a_default_backoff(prod_real, app_data, sidecar1) -> None:
    world = C.default_world()
    world["hosts"]["www.cnn.com"]["routes"][C.FEED_PATH] = {"status": 429, "text": "slow down"}
    sc = pinned(prod_real, app_data, sidecar1, world=world)
    assert sc.call(OP)[0]["error_code"] == "RATE_LIMITED"
    from datetime import datetime
    until = json.loads((app_data / "rate-state.json").read_text(encoding="utf-8"))["operations"][OP]["backoff_until"]
    assert 45 < (datetime.fromisoformat(until.replace("Z", "+00:00")) - C.now()).total_seconds() <= 65


def test_repeated_calls_never_block_the_pipe(prod_real, app_data, sidecar1) -> None:
    sc = pinned(prod_real, app_data, sidecar1)
    start = time.monotonic()
    codes = [sc.call(OP)[0].get("error_code") for _ in range(8)]
    assert time.monotonic() - start < 25
    assert codes[0] is None and set(codes[1:]) <= {"RATE_LIMITED", "NOT_DUE"} and len(set(codes[1:])) >= 1
    assert sc.health()[0]["status"] == "OK"


def test_corrupt_rate_state_fails_closed(prod_real, app_data, sidecar1) -> None:
    (app_data / "rate-state.json").write_text("{not json", encoding="utf-8")
    sc = pinned(prod_real, app_data, sidecar1)
    reply, _ = sc.call(OP)
    assert reply["status"] == "DEGRADED" and reply["records"] == [] and len(sc.non_robots_requests()) == 0


def test_a_failed_call_does_not_advance_the_success_clock(prod_real, app_data, sidecar1) -> None:
    world = C.default_world()
    world["hosts"]["www.cnn.com"]["routes"][C.FEED_PATH] = {"status": 500, "text": "oops"}
    sc = pinned(prod_real, app_data, sidecar1, world=world)
    assert sc.call(OP)[0]["status"] == "DEGRADED"
    state = json.loads((app_data / "rate-state.json").read_text(encoding="utf-8"))["operations"][OP]
    assert "last_success_at" not in state and "last_send_at" in state
    sc.age_rate_state(OP, 10)
    sc.set_world(C.default_world())
    assert sc.call(OP)[0]["status"] == "OK", "after a failure only the spacing applies, not the cadence"


def test_learn_and_repair_use_short_persisted_spacing_not_the_cadence(prod_stub, app_data, sidecar1) -> None:
    tpl = C.template_for(OP, recipe=True).decode()
    C.write_pin(prod_stub, OP)
    sc = sidecar1(prod_stub, app_data, world=C.default_world())
    sc.set_control({"learn": [{"write_site": tpl}], "call": [ok(C.fresh_rows(OP))], "heal": [{"write_site": tpl, **ok(C.fresh_rows(OP))}]})
    first, _ = sc.learn(OP)
    assert first["status"] == "OK" and first["candidate_only"] is True
    (second, _), elapsed = timed(sc.learn, OP)
    assert second["error_code"] == "RATE_LIMITED" and elapsed < 3
    assert json.loads((app_data / "rate-state.json").read_text(encoding="utf-8"))["operations"][OP]["last_learn_at"]
    sc.close()
    sc2 = sidecar1(prod_stub, app_data, world=C.default_world())
    sc2.set_control({"learn": [{"write_site": tpl}], "call": [ok(C.fresh_rows(OP))]})
    assert sc2.learn(OP)[0]["error_code"] == "RATE_LIMITED", "learn spacing persists across restarts"
    sc2.age_rate_state(OP, 10)
    assert sc2.learn(OP)[0]["status"] == "OK", "learn is allowed again after the short spacing, whatever the cadence"
    sc2.age_rate_state(OP, 10)
    sc2.set_control({"heal": [{"write_site": tpl, **ok(C.fresh_rows(OP))}], "call": [ok(C.fresh_rows(OP))]})
    assert sc2.repair(OP)[0]["error_code"] == "TEMPLATE_UNPINNED", "repair ran (candidate produced), not NOT_DUE"


# ------------------------------------------------------------------ candidate-only learn / repair

def candidates(data: Path, op=OP):
    d = data / "candidates" / op
    return sorted(p.name for p in d.iterdir()) if d.exists() else []


def test_learn_produces_a_quarantined_candidate_and_activates_nothing(prod_stub, app_data, sidecar1) -> None:
    before = (prod_stub / "templates" / "PINNED.json").read_bytes()
    pin_hash = (prod_stub / "dist" / "pin-hash.js").read_bytes()
    tpl = C.template_for(OP, recipe=True)
    sc = sidecar1(prod_stub, app_data, world=C.default_world())
    rows = C.fresh_rows(OP)
    sc.set_control({"learn": [{"write_site": tpl.decode()}], "call": [ok(rows)]})
    reply, _ = sc.learn(OP)
    assert reply["status"] == "OK" and reply["candidate_only"] is True and reply["records"] == []
    assert reply["template_sha256"] == hashlib.sha256(tpl).hexdigest() and reply["knowable_at"] is None
    names = candidates(app_data)
    assert len(names) == 3, names
    version = reply["template_version"]
    assert (app_data / "candidates" / OP / f"{version}.json").read_bytes() == tpl
    meta = json.loads((app_data / "candidates" / OP / f"{version}.candidate.json").read_text(encoding="utf-8"))
    assert meta["sha256"] == reply["template_sha256"] and meta["operation_id"] == OP and meta["version"] == version
    assert set(meta["allowed_hosts"]) <= {"www.cnn.com", "cnn.com", "cdn.cnn.com"} and meta["allowed_hosts"] and meta["tos_review_id"] == "cnn-owner-review-2026-10-09"
    assert meta["fixture_sha256"] == hashlib.sha256((app_data / "candidates" / OP / f"{version}.fixture.json").read_bytes()).hexdigest()
    assert "review" in meta["review_note"].lower() and "pin" in meta["review_note"].lower()
    assert (prod_stub / "templates" / "PINNED.json").read_bytes() == before and (prod_stub / "dist" / "pin-hash.js").read_bytes() == pin_hash
    reply2, _ = sc.call(OP)
    assert reply2["error_code"] == "TEMPLATE_UNPINNED", "a learned candidate must not serve"
    assert not (app_data / "last-good").exists() or not list((app_data / "last-good").iterdir())


@pytest.mark.parametrize("label", ["cookie header", "authorization key", "bearer value", "access_token query"])
def test_learned_candidates_containing_credentials_are_rejected(prod_stub, app_data, sidecar1, label) -> None:
    import json as j
    base = j.loads(C.template_for(OP, recipe=True))
    req = base["operations"][0]["request"]
    if label == "cookie header":
        req["headers"]["cookie"] = "session=abc123"
    elif label == "authorization key":
        req["headers"]["Authorization"] = "x"
    elif label == "bearer value":
        req["headers"]["x-note"] = "Bearer abcdefghijklmnop"
    else:
        req["url"] += "?access_token=abc"
    sc = sidecar1(prod_stub, app_data, world=C.default_world())
    sc.set_control({"learn": [{"write_site": j.dumps(base)}], "call": [ok(C.fresh_rows(OP))]})
    reply, _ = sc.learn(OP)
    assert reply["status"] == "DEGRADED" and reply["error_code"] == "OPERATION_DEGRADED", label
    assert candidates(app_data) == [], "a rejected candidate must leave no files"


def test_learned_rows_that_embed_credentials_are_rejected(prod_stub, app_data, sidecar1) -> None:
    rows = C.fresh_rows("calendar.fed")
    rows[0]["event_name"] = "visit https://x.example/?access_token=abc123"
    sc = sidecar1(prod_stub, app_data, world=C.default_world("calendar.fed"))
    sc.set_control({"learn": [{"write_site": C.template_for("calendar.fed", recipe=True).decode()}], "call": [ok(rows, "calendar.fed")]})
    reply, _ = sc.learn("calendar.fed")
    assert reply["status"] == "DEGRADED" and candidates(app_data, "calendar.fed") == []


@pytest.mark.parametrize("label", ["stale", "empty", "schema"])
def test_learn_with_semantically_bad_or_invalid_rows_creates_no_candidate(prod_stub, app_data, sidecar1, label) -> None:
    rows = {"stale": C.fresh_rows(OP, age_minutes=60 * 24 * 30), "empty": [], "schema": [{"value": 1}]}[label]
    sc = sidecar1(prod_stub, app_data, world=C.default_world())
    sc.set_control({"learn": [{"write_site": C.template_for(OP, recipe=True).decode()}], "call": [ok(rows)]})
    reply, _ = sc.learn(OP)
    assert reply["status"] == "DEGRADED" and reply.get("candidate_only") is not True, label
    assert candidates(app_data) == [], label


def test_learn_is_rejected_when_the_template_cannot_be_replayed_against_its_own_fixture(prod_stub, app_data, sidecar1) -> None:
    sc = sidecar1(prod_stub, app_data, world=C.default_world())
    good = ok(C.fresh_rows(OP))
    bad = {"result": {"ok": False, "class": "drift", "reason": "extract path missing"}}
    sc.set_control({"learn": [{"write_site": C.template_for(OP, recipe=True).decode()}], "call": [good, good, bad]})  # 2 examples, then the replay
    reply, _ = sc.learn(OP)
    assert reply["status"] == "DEGRADED" and candidates(app_data) == []


def test_repair_yields_a_candidate_and_never_swaps_the_pinned_template(prod_stub, app_data, sidecar1) -> None:
    entry = C.write_pin(prod_stub, OP)
    registry_before = (prod_stub / "templates" / "PINNED.json").read_bytes()
    t2 = C.template_for(OP, path="/fixture/v2.json").decode()
    sc = sidecar1(prod_stub, app_data, world=C.default_world())
    rows = C.fresh_rows(OP)
    sc.set_control({"heal": [{"write_site": t2, **ok(rows)}], "call": [ok(rows)]})
    reply, _ = sc.repair(OP)
    assert reply["error_code"] == "TEMPLATE_UNPINNED" and reply["records"] == []
    assert reply["template_sha256"] == hashlib.sha256(t2.encode()).hexdigest() != entry["sha256"]
    assert len(candidates(app_data)) == 3
    assert (prod_stub / "templates" / "PINNED.json").read_bytes() == registry_before
    sc.age_rate_state(OP, 3700)
    served, _ = sc.call(OP)
    assert served["status"] == "OK" and served["template_sha256"] == entry["sha256"], "the pinned version keeps serving"
    assert sc.stub_events("call")[-1]["site_sha"] == entry["sha256"]


def test_repair_candidates_with_credentials_or_bad_rows_are_rejected(prod_stub, app_data, sidecar1) -> None:
    C.write_pin(prod_stub, OP)
    sc = sidecar1(prod_stub, app_data, world=C.default_world())
    cred = json.loads(C.template_for(OP))
    cred["operations"][0]["request"]["headers"]["cookie"] = "s=1"
    sc.set_control({"heal": [{"write_site": json.dumps(cred), **ok(C.fresh_rows(OP))}], "call": [ok(C.fresh_rows(OP))]})
    assert sc.repair(OP)[0]["error_code"] == "OPERATION_DEGRADED" and candidates(app_data) == []
    sc.age_rate_state(OP, 10)
    sc.set_control({"heal": [{"write_site": C.template_for(OP).decode(), **ok(C.fresh_rows(OP, age_minutes=60 * 24 * 30))}], "call": [ok(C.fresh_rows(OP))]})
    assert sc.repair(OP)[0]["status"] == "DEGRADED" and candidates(app_data) == []


# ------------------------------------------------------------------ first-time learn: window in production

def test_first_time_learn_challenge_notifies_and_opens_the_isolated_window(prod_stub, app_data, sidecar1) -> None:
    sc = sidecar1(prod_stub, app_data, world=C.default_world())
    tpl = C.template_for(OP, recipe=True).decode()
    sc.set_control({"challenge_outcome": "completed", "learn": [{"throw": "bot wall", "challenge": True}, {"write_site": tpl}],
                    "call": [ok(C.fresh_rows(OP))]})
    reply, notes = sc.learn(OP)
    assert len(notes) == 1 and notes[0]["status"] == "USER_ACTION_REQUIRED" and notes[0]["operation_id"] == OP
    assert notes[0]["source_id"] == f"api_anything.{OP}" and notes[0]["request_id"] == reply["request_id"]
    [window] = sc.stub_events("challenge")
    assert Path(window["profileDir"]).resolve() == (app_data / "learning" / "cnn-fear_greed" / "profile").resolve()
    assert window["url"] == "https://www.cnn.com/markets/fear-and-greed" and window["timeoutMs"] == 600_000
    assert window["challengeHosts"] == [] and Path(window["dataDir"]).resolve() == app_data.resolve()
    assert reply["status"] == "OK" and reply["candidate_only"] is True, "learning resumes after the user finishes"
    assert len(sc.stub_events("learn")) == 2


@pytest.mark.parametrize(("outcome", "status", "code"), [
    ("declined", "USER_ACTION_DECLINED", "USER_ACTION_DECLINED"), ("timeout", "TIMEOUT", "TIMEOUT"),
    ("window_failed", "DEGRADED", "CHALLENGE_WINDOW_FAILED"), ("browser_unavailable", "DEGRADED", "BROWSER_UNAVAILABLE")])
def test_first_time_learn_challenge_outcomes_are_distinct_and_abstain(prod_stub, app_data, sidecar1, outcome, status, code) -> None:
    sc = sidecar1(prod_stub, app_data, world=C.default_world())
    sc.set_control({"challenge_outcome": outcome, "learn": [{"throw": "bot wall", "challenge": True}]})
    reply, notes = sc.learn(OP)
    assert reply["status"] == status and reply["error_code"] == code and reply["records"] == []
    assert candidates(app_data) == [] and len(sc.stub_events("learn")) == 1, "no relearn after a non-completed outcome"


def test_learn_failure_with_a_challenge_word_but_no_structured_signal_opens_no_window(prod_stub, app_data, sidecar1) -> None:
    sc = sidecar1(prod_stub, app_data, world=C.default_world())
    sc.set_control({"challenge_outcome": "completed", "learn": [{"throw": "captcha challenge detected by text only"}]})
    reply, notes = sc.learn(OP)
    assert reply["status"] == "DEGRADED" and notes == [] and sc.stub_events("challenge") == []


# ------------------------------------------------------------------ the committed registry

def test_committed_registry_hash_is_baked_into_the_build_and_unpinned(collector: Path) -> None:
    committed = A.WORKTREE / "services" / "public-collector" / "templates" / "PINNED.json"
    digest = hashlib.sha256(committed.read_bytes()).hexdigest()
    baked = (collector / "dist" / "pin-hash.js").read_text(encoding="utf-8")
    assert digest in baked
    assert digest in (A.WORKTREE / "services" / "public-collector" / "src" / "pin-hash.ts").read_text(encoding="utf-8")
    manifest = json.loads((A.WORKTREE / "services" / "public-collector" / "runtime-manifest.json").read_text(encoding="utf-8"))
    rebuilt = json.loads((collector / "runtime-manifest.json").read_text(encoding="utf-8"))
    assert manifest == rebuilt, "the vendored runtime must rebuild byte-identically from the patch"
    assert manifest["pin_registry_sha256"] == digest
    assert json.loads(committed.read_text(encoding="utf-8"))["operations"] == {}
    assert json.loads((collector / "templates" / "PINNED.json").read_text(encoding="utf-8"))["operations"] == {}, "the built registry pins nothing"


def test_registry_edited_without_rebuilding_is_refused(prod_real, app_data, sidecar1) -> None:
    """The registry hash baked into dist must match PINNED.json: an edited file is PIN_REGISTRY_INVALID, never trusted."""
    C.write_pin(prod_real, OP)
    (prod_real / "dist" / "pin-hash.js").write_text('export const PIN_REGISTRY_SHA256 = "' + "0" * 64 + '";\n', encoding="utf-8")
    sc = sidecar1(prod_real, app_data, world=C.default_world())
    reply, _ = sc.call(OP)
    assert reply["status"] == "DEGRADED" and reply["records"] == [] and sc.requests() == []
    assert reply["error_code"] in {"PIN_REGISTRY_INVALID", "OPERATION_DEGRADED"}
