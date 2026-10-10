"""Cycle 1 / P1: activation only through a pinned PINNED.json entry; per-operation host, redirect and
robots allowlist; semantic canary.  Production path (no AA_CONTROL), real vendored runtime, fake internet."""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta
from pathlib import Path

import aa_harness as A
import c1_harness as C
import pytest

pytest_plugins = ("c1_fixtures",)

OPS = list(A.SITES)
COMMITTED = A.WORKTREE / "services" / "public-collector" / "templates" / "PINNED.json"


def served(prod, data, sidecar1, op="cnn.fear_greed", world=None, **pin):
    C.write_pin(prod, op, **pin)
    sc = sidecar1(prod, data, world=world or C.default_world(op))
    return sc


# ---------------------------------------------------------------- committed registry

def test_committed_registry_pins_nothing_and_records_every_tos_review() -> None:
    registry = json.loads(COMMITTED.read_text(encoding="utf-8"))
    assert registry["operations"] == {}, "cycle 1 pins no template"
    reviews = registry["tos_reviews"]
    for contract_review in ("fed-public-schedule-2026-10-09", "yahoo-finance-owner-review-2026-10-09", "senate-efd-public-filings-2026-10-09",
                            "cboe-market-data-owner-review-2026-10-09", "cnn-owner-review-2026-10-09"):
        assert reviews[contract_review]["redistribution"] is False
        assert reviews[contract_review]["verdict"] in {"ALLOWED", "INTERNAL_SINGLE_USER_ONLY"}
    assert reviews["excluded-automated-access"]["verdict"] == "EXCLUDED"
    assert "FedWatch" in reviews["excluded-automated-access"]["decision"]


@pytest.mark.parametrize("op", OPS)
def test_unpinned_operations_abstain_without_touching_the_network(prod_real, app_data, sidecar1, op) -> None:
    sc = sidecar1(prod_real, app_data, world=C.default_world(op))
    for method in (sc.call, sc.repair):
        reply, notes = method(op)
        assert reply["error_code"] == "TEMPLATE_UNPINNED" and reply["status"] == "DEGRADED"
        assert reply["records"] == [] and reply["redistribution"] is False and reply["source_tier"] == 3
        assert notes == []
    assert sc.requests() == [], "an unpinned operation must not even fetch robots.txt"
    assert sc.alive() and sc.health()[0]["status"] == "OK"


def test_the_sidecar_cannot_be_activated_by_a_file_in_app_data(prod_real, app_data, sidecar1) -> None:
    """Activation lives only in the committed PINNED.json beside the code, never in the data dir."""
    tpl = C.template_for("cnn.fear_greed")
    import hashlib
    (app_data / "template-versions" / "cnn.fear_greed").mkdir(parents=True)
    (app_data / "template-versions" / "cnn.fear_greed" / "x.json").write_bytes(tpl)
    (app_data / "template-registry.json").write_text(json.dumps({"schema_version": 1, "active": {"cnn.fear_greed": {
        "version": "x", "sha256": hashlib.sha256(tpl).hexdigest(), "template_path": "template-versions/cnn.fear_greed/x.json"}}}), encoding="utf-8")
    sc = sidecar1(prod_real, app_data, world=C.default_world())
    reply, _ = sc.call("cnn.fear_greed")
    assert reply["error_code"] == "TEMPLATE_UNPINNED"
    assert sc.requests() == []


# ---------------------------------------------------------------- the pinned happy path, all five operations

@pytest.mark.parametrize("op", OPS)
def test_pinned_operation_serves_typed_provenanced_records_through_the_real_runtime(prod_real, app_data, sidecar1, op) -> None:
    sc = served(prod_real, app_data, sidecar1, op)
    reply, notes = sc.call(op)
    assert notes == [] and reply["status"] == "OK", reply
    entry = C.read_registry(prod_real)["operations"][op]
    assert reply["template_version"] == entry["version"] and reply["template_sha256"] == entry["sha256"]
    assert reply["approval_id"] == entry["tos_review_id"]
    deadline = datetime.fromisoformat(reply["freshness_deadline"].replace("Z", "+00:00"))
    fetched = datetime.fromisoformat(reply["fetched_at"].replace("Z", "+00:00"))
    assert deadline == fetched + timedelta(hours=48)
    assert reply["source_tier"] == 3 and reply["redistribution"] is False and reply["source_id"] == f"api_anything.{op}"
    [rec] = reply["records"]
    assert rec["redistribution"] is False and rec["first_seen_at"] and rec["quality"] in {"source_timestamped", "first_observed"}
    assert rec["knowable_at"] is not None
    hosts = {r["host"] for r in sc.requests()}
    assert hosts == {C.SITE_HOST[op]}, hosts
    first = sc.requests()[0]
    assert first["path"] == "/robots.txt", "robots.txt must be consulted before any data request"
    for r in sc.requests():
        assert r["ua"] == "LeviathanPublicCollector/1.0" and r["cookie"] is None and r["auth"] is None


# ---------------------------------------------------------------- pin integrity

PIN_DEFECTS = [
    ("template sha256 not hex", {"sha256": "ZZ"}),
    ("template sha256 wrong", {"sha256": "0" * 64}),
    ("template path traversal", {"template_path": "../../../outside.json"}),
    ("fixture path traversal", {"fixture_path": "../../../outside.json"}),
    ("fixture digest wrong", {"fixture_sha256": "0" * 64}),
    ("fixture digest not hex", {"fixture_sha256": "nothex"}),
    ("fixture path empty", {"fixture_path": ""}),
    ("host outside the operation allowlist", {"allowed_hosts": ["www.cnn.com", "evil.example"]}),
    ("empty review note", {"review_note": "   "}),
    ("tos review id mismatch", {"tos_review_id": "fed-public-schedule-2026-10-09"}),
    ("challenge host outside reviewed operation list", {"challenge_hosts": ["evil.example"]}),
    ("empty version", {"version": ""}),
    ("hosts not a list", {"allowed_hosts": "www.cnn.com"}),
]


@pytest.mark.parametrize(("label", "mutate"), PIN_DEFECTS)
def test_defective_pin_entries_fail_closed_and_fetch_nothing_from_the_site(prod_real, app_data, sidecar1, label, mutate) -> None:
    sc = served(prod_real, app_data, sidecar1, mutate=mutate)
    reply, _ = sc.call("cnn.fear_greed")
    assert reply["error_code"] in {"TEMPLATE_UNAVAILABLE", "TEMPLATE_UNPINNED"}, (label, reply)
    assert reply["records"] == []
    assert sc.non_robots_requests() == [], label


def test_stale_canary_runs_a_new_canary_before_serving(prod_real, app_data, sidecar1) -> None:
    sc = served(prod_real, app_data, sidecar1, approved_at=C.now() - timedelta(days=3))
    (app_data / "canary-state.json").write_text(
        json.dumps({"cnn.fear_greed": C.iso(C.now() - timedelta(days=3))}), encoding="utf-8"
    )
    reply, _ = sc.call("cnn.fear_greed")
    fetched = datetime.fromisoformat(reply["fetched_at"].replace("Z", "+00:00"))
    deadline = datetime.fromisoformat(reply["freshness_deadline"].replace("Z", "+00:00"))
    assert reply["status"] == "OK" and len(reply["records"]) == 1
    assert deadline == fetched + timedelta(hours=48)
    assert sc.non_robots_requests()


def test_tampered_template_file_is_refused(prod_real, app_data, sidecar1) -> None:
    entry = C.write_pin(prod_real, "cnn.fear_greed")
    (prod_real / "templates" / entry["template_path"]).write_bytes(C.template_for("cnn.fear_greed", host="evil.example"))
    sc = sidecar1(prod_real, app_data, world=C.default_world())
    reply, _ = sc.call("cnn.fear_greed")
    assert reply["error_code"] == "TEMPLATE_UNAVAILABLE"
    assert sc.requests() == []


def test_fixture_that_fails_the_semantic_check_blocks_the_pin(prod_real, app_data, sidecar1) -> None:
    rows = C.fresh_rows("cnn.fear_greed", age_minutes=60 * 24 * 30)  # a month old: stale for a 7-day feed
    sc = served(prod_real, app_data, sidecar1, rows=rows)
    reply, _ = sc.call("cnn.fear_greed")
    assert reply["error_code"] == "TEMPLATE_UNAVAILABLE"


@pytest.mark.parametrize("review", ["cnn-owner-review-2026-10-09"])
@pytest.mark.parametrize(("change", "label"), [({"verdict": "EXCLUDED"}, "excluded"), ({"redistribution": True}, "redistributable"),
                                               ({"verdict": "SOMETHING"}, "unknown verdict"), ({"_delete": True}, "missing review")])
def test_a_source_without_an_approving_tos_review_is_never_called(prod_real, app_data, sidecar1, review, change, label) -> None:
    sc = served(prod_real, app_data, sidecar1)
    C.set_tos(prod_real, review, **change)
    reply, _ = sc.call("cnn.fear_greed")
    assert reply["error_code"] == "OPERATION_DEGRADED" and reply["records"] == [], label
    assert sc.non_robots_requests() == []


def test_missing_or_corrupt_registry_fails_closed(prod_real, app_data, sidecar1) -> None:
    (prod_real / "templates" / "PINNED.json").write_text("{not json", encoding="utf-8")
    sc = sidecar1(prod_real, app_data, world=C.default_world())
    reply, _ = sc.call("cnn.fear_greed")
    assert reply["status"] == "DEGRADED" and reply["records"] == []
    assert sc.requests() == [] and sc.alive()


def test_observation_robots_are_fetched_for_unvalidated_pin_hosts(prod_real, app_data, sidecar1) -> None:
    """An unreviewed host is rejected before its robots.txt or data URL can be fetched."""
    sc = served(prod_real, app_data, sidecar1, mutate={"allowed_hosts": ["www.cnn.com", "evil.example"]})
    sc.call("cnn.fear_greed")
    assert not any(r["host"] == "evil.example" for r in sc.requests())


# ---------------------------------------------------------------- host / redirect / robots allowlist

def test_template_pointing_at_a_foreign_host_is_blocked_before_any_request(prod_real, app_data, sidecar1) -> None:
    sc = served(prod_real, app_data, sidecar1, template=C.template_for("cnn.fear_greed", host="evil.example", path="/steal"))
    reply, _ = sc.call("cnn.fear_greed")
    assert reply["error_code"] == "OPERATION_DEGRADED" and reply["records"] == []
    assert not any(r["host"] == "evil.example" for r in sc.requests())


def test_redirect_to_another_host_is_blocked_and_never_followed(prod_real, app_data, sidecar1) -> None:
    world = C.default_world()
    world["hosts"]["www.cnn.com"]["routes"][C.FEED_PATH] = {"status": 302, "location": "https://evil.example/steal"}
    sc = served(prod_real, app_data, sidecar1, world=world)
    reply, _ = sc.call("cnn.fear_greed")
    assert reply["error_code"] == "OPERATION_DEGRADED" and reply["records"] == []
    assert not any(r["host"] == "evil.example" for r in sc.requests())


def test_redirect_within_the_allowed_host_is_followed(prod_real, app_data, sidecar1) -> None:
    world = C.default_world()
    world["hosts"]["www.cnn.com"]["routes"]["/fixture/old.json"] = {"status": 302, "location": "https://www.cnn.com" + C.FEED_PATH}
    tpl = C.template_for("cnn.fear_greed", path="/fixture/old.json")
    sc = served(prod_real, app_data, sidecar1, world=world, template=tpl)
    reply, _ = sc.call("cnn.fear_greed")
    assert reply["status"] == "OK", reply
    assert [r["path"] for r in sc.non_robots_requests()] == ["/fixture/old.json", C.FEED_PATH]


def test_http_downgrade_redirect_is_blocked(prod_real, app_data, sidecar1) -> None:
    world = C.default_world()
    world["hosts"]["www.cnn.com"]["routes"][C.FEED_PATH] = {"status": 302, "location": "http://www.cnn.com" + C.FEED_PATH}
    sc = served(prod_real, app_data, sidecar1, world=world)
    reply, _ = sc.call("cnn.fear_greed")
    assert reply["error_code"] == "OPERATION_DEGRADED"
    assert all(r["url"].startswith("https://") for r in sc.requests())


def test_robots_disallow_blocks_the_data_request(prod_real, app_data, sidecar1) -> None:
    world = C.default_world(robots="User-agent: *\nDisallow: /fixture/\n")
    sc = served(prod_real, app_data, sidecar1, world=world)
    reply, _ = sc.call("cnn.fear_greed")
    assert reply["error_code"] == "OPERATION_DEGRADED" and reply["records"] == []
    assert sc.non_robots_requests() == [] and [r["path"] for r in sc.requests()] == ["/robots.txt"]


def test_robots_specific_allow_beats_broader_disallow_and_our_agent_group_wins(prod_real, app_data, sidecar1) -> None:
    robots = "User-agent: *\nDisallow: /\n\nUser-agent: LeviathanPublicCollector\nDisallow: /private/\nAllow: /fixture/\n"
    sc = served(prod_real, app_data, sidecar1, world=C.default_world(robots=robots))
    assert sc.call("cnn.fear_greed")[0]["status"] == "OK"


def test_robots_server_error_fails_closed_but_404_means_allowed(prod_real, app_data, sidecar1, tmp_path: Path) -> None:
    sc = served(prod_real, app_data, sidecar1, world=C.default_world(robots={"status": 500, "text": "oops"}))
    reply, _ = sc.call("cnn.fear_greed")
    assert reply["status"] == "DEGRADED" and reply["records"] == [] and sc.non_robots_requests() == []
    data2 = tmp_path / "second"
    data2.mkdir()
    sc2 = sidecar1(prod_real, data2, world=C.default_world(robots=None))
    assert sc2.call("cnn.fear_greed")[0]["status"] == "OK"


def test_robots_policy_is_cached_on_disk_between_restarts(prod_real, app_data, sidecar1) -> None:
    sc = served(prod_real, app_data, sidecar1)
    sc.call("cnn.fear_greed")
    assert (app_data / "policy" / "robots.json").exists()
    sc.close()
    before = len(sc.requests())
    sc2 = sidecar1(prod_real, app_data, world=C.default_world())
    sc2.age_rate_state("cnn.fear_greed", 7200)
    assert sc2.call("cnn.fear_greed")[0]["status"] == "OK"
    assert not any(r["path"] == "/robots.txt" for r in sc2.requests()[before:]), "robots.txt re-fetched despite fresh cache"


# ---------------------------------------------------------------- semantic canary

SEMANTIC_BAD = {
    "cnn.fear_greed": [("stale observation", lambda r: r[0].update(observed_at=C.iso(C.now() - timedelta(days=30)))),
                       ("future observation", lambda r: r[0].update(observed_at=C.iso(C.now() + timedelta(days=2)))),
                       ("empty result", lambda r: r.clear()),
                       ("duplicate ids", lambda r: r.append(dict(r[0])))],
    "calendar.fed": [("empty event name", lambda r: r[0].update(event_name="   ")),
                     ("scheduled absurdly far away", lambda r: r[0].update(scheduled_at=C.iso(C.now() + timedelta(days=4000))))],
    "earnings.forward": [("ticker lowercase", lambda r: r[0].update(ticker="aapl")),
                         ("scheduled two years back", lambda r: r[0].update(scheduled_at=C.iso(C.now() - timedelta(days=800))))],
    "senate.efd.ptr": [("report on a foreign host", lambda r: r[0].update(report_url="https://evil.example/ptr/1")),
                       ("no transactions", lambda r: r[0].update(transactions=[]))],
    "cboe.daily.stats": [("value out of range", lambda r: r[0].update(value=900.0)),
                         ("stale", lambda r: r[0].update(observed_at=C.iso(C.now() - timedelta(days=60)))),
                         ("term structure without maturity", lambda r: r[0].update(metric="vix_term_structure", maturity=None))],
}


@pytest.mark.parametrize(("op", "label", "break_rows"), [(op, label, fn) for op, cases in SEMANTIC_BAD.items() for label, fn in cases])
def test_semantically_wrong_rows_never_become_records(prod_real, app_data, sidecar1, op, label, break_rows) -> None:
    sc = served(prod_real, app_data, sidecar1, op)  # fixture rows are fine; the live answer is not
    rows = C.fresh_rows(op)
    break_rows(rows)
    sc.set_world(C.default_world(op, rows=rows))
    reply, _ = sc.call(op)
    assert reply["records"] == [] and reply["status"] == "DEGRADED", (label, reply)
    assert reply["error_code"] in {"OPERATION_DEGRADED", "SCHEMA_INVALID"}
    assert not (app_data / "last-good").exists() or not list((app_data / "last-good").iterdir())


def test_schema_invalid_rows_are_rejected(prod_real, app_data, sidecar1) -> None:
    sc = served(prod_real, app_data, sidecar1)
    rows = C.fresh_rows("cnn.fear_greed")
    rows[0]["surprise"] = 1
    sc.set_world(C.default_world(rows=rows))
    reply, _ = sc.call("cnn.fear_greed")
    assert reply["error_code"] == "SCHEMA_INVALID" and reply["records"] == []


# ---------------------------------------------------------------- AA_CONTROL (the harness switch) must not be a production policy bypass

PROD_SOURCES = [A.WORKTREE / "services/public-collector/src/main.ts", A.WORKTREE / "services/public-collector/src/robots.ts",
                A.WORKTREE / "services/public-collector/src/challenge.ts", A.WORKTREE / "services/public-collector/vendor/api-anything/src/browser.ts"]


def test_finding_acceptance_harness_env_var_is_wired_into_production_code() -> None:
    """FINDING (high): AA_CONTROL is the env var the cycle-0 ACCEPTANCE HARNESS used to point its stub vendor at a control
    file.  Cycle 1 reads it in production code to relax policy (see the behavioural tests below)."""
    hits = {p.name: len(re.findall(r"AA_CONTROL", p.read_text(encoding="utf-8"))) for p in PROD_SOURCES}
    assert sum(hits.values()) == 0, hits


def test_finding_aa_control_must_not_replace_the_pin_registry(prod_real, app_data, sidecar1) -> None:
    """With AA_CONTROL set, a file in the app-data dir activates a template that PINNED.json does not know."""
    import hashlib
    tpl = C.template_for("cnn.fear_greed")
    (app_data / "t").mkdir()
    (app_data / "t" / "x.json").write_bytes(tpl)
    (app_data / "template-registry.json").write_text(json.dumps({"schema_version": 1, "active": {"cnn.fear_greed": {
        "version": "x", "sha256": hashlib.sha256(tpl).hexdigest(), "template_path": "t/x.json"}}}), encoding="utf-8")
    sc = sidecar1(prod_real, app_data, world=C.default_world(), extra_env={"AA_CONTROL": "1"})
    reply, _ = sc.call("cnn.fear_greed")
    assert reply["error_code"] == "TEMPLATE_UNPINNED", f"unpinned template served under AA_CONTROL: {reply['status']}"


def test_finding_aa_control_must_not_disable_robots(prod_real, app_data, sidecar1) -> None:
    sc = served(prod_real, app_data, sidecar1, world=C.default_world(robots="User-agent: *\nDisallow: /\n"), )
    sc.close()
    sc2 = sidecar1(prod_real, app_data, world=C.default_world(robots="User-agent: *\nDisallow: /\n"), extra_env={"AA_CONTROL": "1"})
    reply, _ = sc2.call("cnn.fear_greed")
    assert reply["status"] != "OK", "robots.txt disallow was ignored under AA_CONTROL"
