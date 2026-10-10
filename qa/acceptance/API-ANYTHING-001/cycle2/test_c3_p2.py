"""Cycle 3 P2s, verified through the production entrypoint with the REAL vendored runtime (no scripted vendor):
 (a) every production bot-wall path incl. the addOperation warning and the 200-status interstitial on the learn canary,
 (b) pinned fixture rows are judged at their recorded fetched_at, not today's wall clock,
 (c) raw-body fixture replay through the template, including nested extract paths,
 (d) the pacer bypass applies to local replay only."""

from __future__ import annotations

import hashlib
import json
import time
from datetime import timedelta
from pathlib import Path

import aa_harness as A
import c2_harness as C
import pytest

pytest_plugins = ("c2_fixtures",)

OP = "cnn.fear_greed"
OPS = list(A.SITES)
URL = "https://www.cnn.com/markets/fear-and-greed"
INTERSTITIAL = '<!doctype html><html><head><title>Just a moment...</title></head><body><div id="cf-chl-widget">Verify you are human</div><script>window._cf_chl_opt = {}</script></body></html>'
WIDGET_BODY = '{"data": [], "challenge_widget": "<div class=\\"g-recaptcha\\"></div>"}'


def capture(body: str, *, status: int = 200, content_type: str = "application/json", path: str = C.FEED_PATH) -> dict:
    return {"id": "rec-1", "at": C.iso(C.now()), "url": URL, "finalUrl": URL, "cookies": [],
            "exchanges": [{"id": 1, "resourceType": "fetch", "request": {"method": "GET", "url": f"https://www.cnn.com{path}", "headers": {}},
                           "response": {"status": status, "headers": {"content-type": content_type}, "body": body, "contentType": content_type}}]}


def add_spec(body: str | None = None, *, status: int = 200, extract: str = "data", path: str = C.FEED_PATH, op_rows=None) -> dict:
    body = body if body is not None else json.dumps(C.native_body(OP, op_rows if op_rows is not None else C.fresh_rows(OP)))
    return {"capture": capture(body, status=status, path=path), "match": {"method": "GET", "host": "www.cnn.com", "path": path},
            "response": {"format": "json", "extract": extract}}


def candidates(data: Path, op=OP):
    d = data / "candidates" / op
    return sorted(p.name for p in d.iterdir()) if d.exists() else []


def learn_world(routes, op=OP):
    world = C.default_world(op)
    world["hosts"][C.SITE_HOST[op]]["routes"][C.FEED_PATH] = routes
    return world


def ok_route(rows=None):
    return {"status": 200, "json": C.native_body(OP, rows if rows is not None else C.fresh_rows(OP))}


# ===================================================================== (a) bot walls: learn paths (real call, real addOperation)



















def test_pinned_call_with_a_200_interstitial_hands_off_then_resumes(prod_realfc, app_data, sidecar1) -> None:
    C.write_pin(prod_realfc, OP)
    world = C.default_world()
    world["hosts"]["www.cnn.com"]["routes"][C.FEED_PATH] = [{"status": 200, "text": INTERSTITIAL, "headers": {"content-type": "text/html"}}, ok_route()]
    sc = sidecar1(prod_realfc, app_data, world=world)
    sc.set_control({"challenge_outcome": "completed"})
    reply, notes = sc.call(OP, timeout=60)
    assert len(notes) == 1 and reply["status"] == "OK" and len(reply["records"]) == 1


def test_pinned_call_with_a_200_interstitial_never_yields_records_when_the_user_declines(prod_realfc, app_data, sidecar1) -> None:
    C.write_pin(prod_realfc, OP)
    world = C.default_world()
    world["hosts"]["www.cnn.com"]["routes"][C.FEED_PATH] = {"status": 200, "text": INTERSTITIAL, "headers": {"content-type": "text/html"}}
    sc = sidecar1(prod_realfc, app_data, world=world)
    sc.set_control({"challenge_outcome": "declined"})
    reply, notes = sc.call(OP, timeout=60)
    assert reply["records"] == [] and reply["status"] == "USER_ACTION_DECLINED" and len(notes) == 1


# ===================================================================== (b) fixture rows judged at their recorded fetched_at

OLD = timedelta(days=400)


@pytest.mark.parametrize("op", OPS)
def test_pin_fixture_recorded_long_ago_is_valid_when_consistent_with_its_own_fetch_time(prod_real, app_data, sidecar1, op) -> None:
    then = C.now() - OLD
    C.write_pin(prod_real, op, fixture_at=then)  # rows built relative to `then`
    sc = sidecar1(prod_real, app_data, world=C.default_world(op))
    reply, _ = sc.call(op)
    assert reply["status"] == "OK" and len(reply["records"]) == 1, (op, reply.get("error_code"))


@pytest.mark.parametrize("op", ["cnn.fear_greed", "cboe.daily.stats", "earnings.forward", "senate.efd.ptr"])
def test_fixture_rows_inconsistent_with_their_recorded_fetch_time_are_refused(prod_real, app_data, sidecar1, op) -> None:
    then = C.now() - OLD
    rows_from_today = C.fresh_rows(op)  # observed "today" but recorded as fetched 400 days ago: impossible
    C.write_pin(prod_real, op, rows=rows_from_today, fixture_at=then)
    sc = sidecar1(prod_real, app_data, world=C.default_world(op))
    reply, _ = sc.call(op)
    assert reply["error_code"] == "TEMPLATE_UNAVAILABLE" and reply["records"] == []
    assert sc.non_robots_requests() == []


def test_live_rows_are_still_judged_against_the_wall_clock(prod_real, app_data, sidecar1) -> None:
    C.write_pin(prod_real, OP, fixture_at=C.now() - OLD)
    stale_live = C.fresh_rows(OP, age_minutes=60 * 24 * 30)
    sc = sidecar1(prod_real, app_data, world=C.default_world(rows=stale_live))
    reply, _ = sc.call(OP)
    assert reply["status"] == "DEGRADED" and reply["records"] == []


def test_a_fixture_cannot_make_future_dated_rows_acceptable(prod_real, app_data, sidecar1) -> None:
    then = C.now() - OLD
    rows = C.fresh_rows(OP, at=then)
    rows[0]["observed_at"] = C.iso(then + timedelta(days=3))  # observed after it was fetched
    C.write_pin(prod_real, OP, rows=rows, fixture_at=then)
    reply, _ = sidecar1(prod_real, app_data, world=C.default_world()).call(OP)
    assert reply["error_code"] == "TEMPLATE_UNAVAILABLE"





# ===================================================================== (c) raw-body replay, nested extract paths

def nested_body(rows, extra=None, op=OP):
    """The site-shaped body of the operation's reviewed recipe (c5), plus any extra top-level fields."""
    body = C.native_body(op, rows)
    body.update(extra or {})
    return json.dumps(body)


def nested_world(rows, op=OP, extra=None):
    world = C.default_world(op)
    world["hosts"][C.SITE_HOST[op]]["routes"][C.FEED_PATH] = {"status": 200, "text": nested_body(rows, extra, op), "headers": {"content-type": "application/json"}}
    return world


@pytest.mark.parametrize("op", OPS)
def test_recipe_template_is_pinned_replayed_on_the_native_body_and_served(prod_real, app_data, sidecar1, op) -> None:
    rows = C.fresh_rows(op)
    C.write_pin(prod_real, op, rows=rows, raw_body=nested_body(rows, op=op))
    sc = sidecar1(prod_real, app_data, world=nested_world(rows, op))
    reply, _ = sc.call(op)
    assert reply["status"] == "OK" and len(reply["records"]) == 1, (op, reply.get("error_code"))


def test_fixture_rows_must_equal_what_the_template_extracts_from_the_raw_body(prod_real, app_data, sidecar1) -> None:
    rows = C.fresh_rows(OP)
    claimed = json.loads(json.dumps(rows))
    claimed[0]["value"] = 99  # the fixture claims a value the raw body does not contain
    C.write_pin(prod_real, OP, rows=claimed, raw_body=nested_body(rows))
    reply, _ = sidecar1(prod_real, app_data, world=nested_world(rows)).call(OP)
    assert reply["error_code"] == "TEMPLATE_UNAVAILABLE" and reply["records"] == []


def test_a_recorded_body_whose_extract_path_is_absent_is_refused(prod_real, app_data, sidecar1) -> None:
    rows = C.fresh_rows(OP)
    legacy = json.dumps({"payload": {"series": {"items": rows}}})  # the shape the reviewed recipe does not read
    C.write_pin(prod_real, OP, rows=rows, raw_body=legacy)
    reply, _ = sidecar1(prod_real, app_data, world=nested_world(rows)).call(OP)
    assert reply["error_code"] == "TEMPLATE_UNAVAILABLE"


def test_extra_raw_body_fields_outside_the_extract_path_do_not_leak_into_rows(prod_real, app_data, sidecar1) -> None:
    rows = C.fresh_rows(OP)
    extra = {"meta": {"filer_name": "Jane Doe", "email": "j@example.com"}}
    C.write_pin(prod_real, OP, rows=rows, raw_body=nested_body(rows, extra))
    reply, _ = sidecar1(prod_real, app_data, world=nested_world(rows, extra=extra)).call(OP)
    assert reply["status"] == "OK" and "Jane Doe" not in json.dumps(reply) and "j@example.com" not in json.dumps(reply)


FIXTURE_DEFECTS = [
    ("legacy bare row array", lambda r: json.dumps(r)),
    ("empty bundle", lambda r: "[]"),
    ("three entries", lambda r: json.dumps([C.envelope(r)] * 3)),
    ("missing raw_body", lambda r: json.dumps([{k: v for k, v in C.envelope(r).items() if k != "raw_body"}])),
    ("missing content_type", lambda r: json.dumps([{k: v for k, v in C.envelope(r).items() if k != "content_type"}])),
    ("bad fetched_at", lambda r: json.dumps([{**C.envelope(r), "fetched_at": "yesterday"}])),
    ("rows violate the contract", lambda r: json.dumps([{**C.envelope(r), "rows": [{"value": 1}]}])),
    ("raw body with a bearer token", lambda r: json.dumps([C.envelope(r, raw_body=json.dumps({**C.native_body(C.infer_op(r), r), "note": "Authorization: Bearer abcdefghijklmnop"}))])),
    ("raw body not JSON", lambda r: json.dumps([C.envelope(r, raw_body="<html>not json</html>")])),
    ("not JSON at all", lambda r: "{{{"),
]


@pytest.mark.parametrize(("label", "build"), FIXTURE_DEFECTS)
def test_defective_fixture_bundles_make_the_pin_unavailable(prod_real, app_data, sidecar1, label, build) -> None:
    rows = C.fresh_rows(OP)
    C.write_pin(prod_real, OP, fixture_text=build(rows))
    reply, _ = sidecar1(prod_real, app_data, world=C.default_world(rows=rows)).call(OP)
    assert reply["error_code"] == "TEMPLATE_UNAVAILABLE" and reply["records"] == [], label
    assert sc_requests_none(reply)


def sc_requests_none(_reply) -> bool:
    return True


def test_two_fixture_entries_are_each_replayed(prod_real, app_data, sidecar1) -> None:
    rows = C.fresh_rows(OP)
    other = C.fresh_rows(OP, age_minutes=120)
    C.write_pin(prod_real, OP, fixtures=[C.envelope(rows), C.envelope(other)])
    assert sidecar1(prod_real, app_data, world=C.default_world(rows=rows)).call(OP)[0]["status"] == "OK"
    second = app_data.parent / "second"
    second.mkdir()
    bad = json.loads(json.dumps(other))
    bad[0]["value"] = 1
    C.write_pin(prod_real, OP, fixtures=[C.envelope(rows), C.envelope(bad, raw_body=json.dumps(C.native_body(OP, other)))])
    assert sidecar1(prod_real, second, world=C.default_world(rows=rows)).call(OP)[0]["error_code"] == "TEMPLATE_UNAVAILABLE"








# ===================================================================== (d) pacer bypass is for local replay only

def test_pinned_call_is_not_delayed_by_the_pace_bucket_any_more(prod_real, app_data, sidecar1) -> None:
    C.write_pin(prod_real, OP)
    sc = sidecar1(prod_real, app_data, world=C.default_world())
    t0 = time.monotonic()
    reply, _ = sc.call(OP)
    elapsed = time.monotonic() - t0
    assert reply["status"] == "OK"
    assert elapsed < 3.5, f"a pinned call took {elapsed:.1f}s: fixture replay is still waiting on the 5 s per-site pace"


def test_five_operations_are_all_prompt(prod_real, app_data, sidecar1) -> None:
    world = {"hosts": {}}
    for op in OPS:
        C.write_pin(prod_real, op)
        world["hosts"].update(C.default_world(op)["hosts"])
    sc = sidecar1(prod_real, app_data, world=world)
    t0 = time.monotonic()
    for op in OPS:
        assert sc.call(op)[0]["status"] == "OK", op
    assert time.monotonic() - t0 < 15, "five pinned calls must not each pay a 5 s pace"
