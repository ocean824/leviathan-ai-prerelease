"""Cycle 5: gates that the broader suites only exercised indirectly (found by mutation: the mutant survived)."""

from __future__ import annotations

import json

import aa_harness as A
import c2_harness as C
import pytest
from test_c4_learn_recipes import EXAMPLES, add_spec, candidate_files, native_route, world_for  # noqa: F401

pytest_plugins = ("c2_fixtures",)

OPS = list(A.SITES)


# ---------------------------------------------------------------- send spacing is enforced after a FAILED call too

def test_a_call_straight_after_a_failed_call_is_held_by_the_send_spacing(prod_real, app_data, sidecar1) -> None:
    op = "cnn.fear_greed"
    world = C.default_world(op)
    world["hosts"]["www.cnn.com"]["routes"][C.FEED_PATH] = {"status": 500, "text": "oops"}
    C.write_pin(prod_real, op)
    sc = sidecar1(prod_real, app_data, world=world)
    assert sc.call(op)[0]["status"] == "DEGRADED"
    sent = len(sc.non_robots_requests())
    sc.set_world(C.default_world(op))
    again, _ = sc.call(op)
    assert again["error_code"] == "RATE_LIMITED" and again["records"] == []
    assert len(sc.non_robots_requests()) == sent, "the spacing must hold the request back before it is sent"


# ---------------------------------------------------------------- the template must BE the reviewed recipe, not merely replay the same rows

def drop_unused_pick(template: dict) -> dict:
    """Remove the `record_id=` pick: the rows in the fixture carry no record_id, so the replay output is identical."""
    response = template["operations"][0]["response"]
    response["pick"] = [p for p in response["pick"] if not p.startswith("record_id=")]
    return template


@pytest.mark.parametrize("op", OPS)
def test_a_pinned_template_with_identical_output_but_not_the_reviewed_recipe_is_refused_at_call_time(prod_real, app_data, sidecar1, op) -> None:
    template = drop_unused_pick(json.loads(C.template_for(op)))
    rows = C.fresh_rows(op)
    assert all("record_id" not in r for r in rows)
    C.write_pin(prod_real, op, template=json.dumps(template).encode(), rows=rows)
    sc = sidecar1(prod_real, app_data, world=C.default_world(op, rows=rows))
    reply, _ = sc.call(op)
    assert reply["status"] != "OK" and reply["records"] == [], (op, reply.get("error_code"))
    assert sc.non_robots_requests() == [], "a template that is not the reviewed recipe must never be served"


@pytest.mark.parametrize("op", ["cnn.fear_greed", "calendar.fed"])
def test_the_control_with_the_reviewed_recipe_serves(prod_real, app_data, sidecar1, op) -> None:
    C.write_pin(prod_real, op)
    reply, _ = sidecar1(prod_real, app_data, world=C.default_world(op)).call(op)
    assert reply["status"] == "OK"


@pytest.mark.parametrize("op", OPS)
def test_a_learned_template_that_differs_from_the_recipe_only_where_the_output_is_unchanged_is_refused(prod_mixed, app_data, sidecar1, op) -> None:
    case = C.native_case(op)
    recipe = C.mapping_for(prod_mixed / "dist")[op]["recipe"]
    # drop the pick that the realistic body does carry but whose contract field is optional (record_id): rows then differ,
    # so build the body WITHOUT that source field and the replay is identical either way
    body = json.loads(case["text"])
    items = body
    for key in recipe["extract"].split("."):
        items = items[key]
    for item in items:
        item.pop("id", None)
    text = json.dumps(body)
    other = {"format": "json", "extract": recipe["extract"], "pick": [p for p in recipe["pick"] if not p.startswith("record_id=")]}
    sc = sidecar1(prod_mixed, app_data, world=world_for(op, native_route(text)))
    sc.set_control({"add_operation": [add_spec(op, text, response=other)]})
    reply, _ = sc.learn(op, EXAMPLES[op][0], timeout=90)
    assert reply["status"] == "DEGRADED" and candidate_files(app_data, op) == [], (op, reply.get("error_code"))
