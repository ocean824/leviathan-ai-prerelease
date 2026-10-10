"""Cycle 2: collector first-seen stamp and the computed knowable_at rule, end to end through the sidecar."""

from __future__ import annotations

import json
from datetime import datetime, timedelta

import aa_harness as A
import c2_harness as C
import pytest

pytest_plugins = ("c2_fixtures",)

OP = "calendar.fed"


def dt(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def pinned(prod, data, sidecar1, op=OP, rows=None):
    C.write_pin(prod, op)
    return sidecar1(prod, data, world=C.default_world(op, rows=rows))


def ledger(data, op=OP):
    return json.loads((data / "first-seen" / f"{op}.json").read_text(encoding="utf-8"))


def test_record_carries_a_collector_first_seen_and_computed_knowable_at(prod_real, app_data, sidecar1) -> None:
    sc = pinned(prod_real, app_data, sidecar1)
    reply, _ = sc.call(OP)
    [rec] = reply["records"]
    fetched, first = dt(reply["fetched_at"]), dt(rec["first_seen_at"])
    assert first == fetched, "a record first seen now is stamped with the collector's fetch time"
    assert dt(rec["knowable_at"]) == max(first, dt(rec["published_at"])) and dt(rec["knowable_at"]) <= fetched
    assert rec["quality"] == "source_timestamped" and dt(rec["as_of"]) <= dt(rec["knowable_at"])
    assert reply["knowable_at"] == rec["knowable_at"]


def test_a_row_without_source_times_is_first_observed_and_knowable_when_first_seen(prod_real, app_data, sidecar1) -> None:
    rows = C.fresh_rows("earnings.forward")
    sc = pinned(prod_real, app_data, sidecar1, op="earnings.forward", rows=rows)
    reply, _ = sc.call("earnings.forward")
    [rec] = reply["records"]
    assert rec["published_at"] is None and rec["quality"] == "first_observed"
    assert rec["knowable_at"] == rec["first_seen_at"] and dt(rec["knowable_at"]) <= dt(reply["fetched_at"])


def test_a_source_claimed_knowable_at_is_ignored(prod_real, app_data, sidecar1) -> None:
    # senate's reviewed recipe is the one that picks a source-claimed knowable_at (availableAt): the claim must not be trusted
    op = "senate.efd.ptr"
    rows = C.fresh_rows(op, extra={"knowable_at": C.iso(C.now() - timedelta(days=400))})
    sc = pinned(prod_real, app_data, sidecar1, op=op, rows=rows)
    reply, _ = sc.call(op)
    [rec] = reply["records"]
    assert dt(rec["knowable_at"]) >= dt(rec["first_seen_at"]) and dt(rec["knowable_at"]) > C.now() - timedelta(minutes=5)
    assert "knowable_at" not in rec["values"]


def test_publication_after_the_fetch_is_a_hard_error_not_a_record(prod_real, app_data, sidecar1) -> None:
    rows = C.fresh_rows(OP)
    rows[0]["published_at"] = C.iso(C.now() + timedelta(days=1))
    sc = pinned(prod_real, app_data, sidecar1, rows=rows)
    reply, _ = sc.call(OP)
    assert reply["records"] == [] and reply["status"] == "DEGRADED"


def test_first_seen_is_written_to_a_persistent_ledger(prod_real, app_data, sidecar1) -> None:
    sc = pinned(prod_real, app_data, sidecar1)
    reply, _ = sc.call(OP)
    entries = ledger(app_data)
    assert len(entries) == 1 and next(iter(entries.values())) == reply["records"][0]["first_seen_at"]


def test_first_seen_stays_put_across_later_fetches_of_the_same_record(prod_real, app_data, sidecar1) -> None:
    """A record that has been visible since the first fetch must keep its original first_seen_at (and knowable_at)."""
    sc = pinned(prod_real, app_data, sidecar1)
    first, _ = sc.call(OP)
    original = first["records"][0]
    stamps = [original["first_seen_at"]]
    for _ in range(2):
        sc.age_rate_state(OP, 90000)
        later, _ = sc.call(OP)
        assert later["status"] == "OK", later.get("error_code")
        assert dt(later["fetched_at"]) > dt(first["fetched_at"])
        stamps.append(later["records"][0]["first_seen_at"])
        assert later["records"][0]["record_id"] == original["record_id"]
    assert stamps == [original["first_seen_at"]] * 3, f"first_seen_at drifted across fetches: {stamps}"
    assert list(ledger(app_data).values()) == [original["first_seen_at"]], "the ledger must keep the first sighting, not the latest"


def test_a_new_record_gets_its_own_first_seen(prod_real, app_data, sidecar1) -> None:
    sc = pinned(prod_real, app_data, sidecar1)
    first, _ = sc.call(OP)
    rows = C.fresh_rows(OP) + C.fresh_rows(OP, extra={"event_name": "Another meeting"})
    sc.set_world(C.default_world(OP, rows=rows))
    sc.age_rate_state(OP, 90000)
    later, _ = sc.call(OP)
    by_name = {r["values"]["event_name"]: r for r in later["records"]}
    assert dt(by_name["Another meeting"]["first_seen_at"]) > dt(first["records"][0]["first_seen_at"])


def test_a_corrupt_first_seen_ledger_fails_closed(prod_real, app_data, sidecar1) -> None:
    (app_data / "first-seen").mkdir()
    (app_data / "first-seen" / f"{OP}.json").write_text("[1,2,3]", encoding="utf-8")
    sc = pinned(prod_real, app_data, sidecar1)
    reply, _ = sc.call(OP)
    assert reply["records"] == [] and reply["status"] == "DEGRADED"
    assert reply["error_code"] in {"FIRST_SEEN_LEDGER_INVALID", "OPERATION_DEGRADED"}
