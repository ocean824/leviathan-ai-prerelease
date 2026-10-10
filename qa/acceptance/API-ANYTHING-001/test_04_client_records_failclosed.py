"""Rule 5: the typed client fails closed; records carry full provenance; point-in-time discipline."""

from __future__ import annotations

import copy
import json
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from conftest import client, registry

E = client.PublicOperationErrorCode
FETCHED = "2026-10-09T15:00:00Z"
DECISION = datetime(2026, 10, 9, 15, 1, tzinfo=UTC)

VALUES = {
    "calendar.fed": {
        "event_name": "FOMC", "agency": "FRB", "release_type": "meeting",
        "scheduled_at": "2026-12-09T19:00:00Z", "published_at": "2026-10-09T13:00:00Z",
    },
    "earnings.forward": {
        "ticker": "AAPL", "fiscal_period": "Q4 2026", "event_type": "earnings",
        "scheduled_at": "2026-10-30T20:00:00Z", "status": "confirmed", "published_at": None,
    },
    "senate.efd.ptr": {
        "report_url": "https://efdsearch.senate.gov/search/view/ptr/abc/", "filed_at": "2026-10-09T12:00:00Z",
        "transactions": [{"ticker": "MSFT", "trade_date": "2026-10-01T00:00:00Z",
                          "transaction_type": "Purchase", "amount_range": "$1,001 - $15,000"}],
    },
    "cboe.daily.stats": {
        "observed_at": "2026-10-08T21:00:00Z", "metric": "put_call_ratio", "value": 0.87,
        "unit": "ratio", "maturity": None, "published_at": "2026-10-08T21:30:00Z",
    },
    "cnn.fear_greed": {"value": 42, "label": "Fear", "observed_at": "2026-10-09T14:59:00Z"},
}
TAGS = {
    "calendar.fed": ("event_risk",), "earnings.forward": ("earnings", "event_risk"),
    "senate.efd.ptr": ("political_trades",), "cboe.daily.stats": ("volatility",),
    "cnn.fear_greed": ("sentiment",),
}


def reply(op="cnn.fear_greed", **over):
    rec = {
        "record_id": "rec-1", "as_of": "2026-10-09T14:59:00Z", "event_at": None,
        "published_at": "2026-10-09T14:59:00Z", "available_at": "2026-10-09T14:59:00Z",
        "knowable_at": "2026-10-09T14:59:00Z", "quality": "source_timestamped",
        "values": copy.deepcopy(VALUES[op]), "redistribution": False,
    }
    body = {
        "schema_version": 1, "request_id": str(uuid.uuid4()), "operation_id": op, "template_version": "t-1",
        "source_id": f"api_anything.{op}", "source_tier": 3, "status": "OK", "fetched_at": FETCHED,
        "as_of": "2026-10-09T14:59:00Z", "knowable_at": "2026-10-09T14:59:00Z", "redistribution": False,
        "records": [rec],
    }
    body.update(over)
    return body


def parse(body):
    return client.parse_operation_result(client.SidecarReply.model_validate_json(json.dumps(body)))


def served(tmp_path: Path, body: dict, op="cnn.fear_greed", args=None, method="call"):
    """Whole path: real CollectorSupervisor <-> fake child that answers with `body`."""
    script = tmp_path / f"child-{uuid.uuid4().hex[:6]}.py"
    script.write_text(
        "import sys,json\n"
        "req=json.loads(sys.stdin.readline())\n"
        f"body=json.loads({json.dumps(json.dumps(body, allow_nan=True))})\n"
        "body['request_id']=req['request_id']\n"
        "print(json.dumps(body),flush=True)\n"
        "sys.stdin.readline()\n",
        encoding="utf-8",
    )
    sup = client.CollectorSupervisor(sys.executable, script, data_dir=tmp_path / "d", timeout_s=15)
    try:
        return getattr(sup, method)(op, args or {})
    finally:
        sup.close()


@pytest.mark.parametrize("op", list(VALUES))
def test_every_operation_yields_complete_provenance(op: str, tmp_path: Path) -> None:
    result = served(tmp_path, reply(op), op=op, args={
        "calendar.fed": {"year": 2026}, "earnings.forward": {"symbols": ["AAPL"]},
        "senate.efd.ptr": {"page": 1}, "cboe.daily.stats": {"date": "2026-10-08"}, "cnn.fear_greed": {},
    }[op])
    assert result.source_tier == 3 and result.redistribution is False
    assert result.operation_id == op and result.template_version == "t-1"
    assert result.fetched_at == datetime(2026, 10, 9, 15, 0, tzinfo=UTC)
    assert result.status is client.OperationStatus.OK
    [rec] = result.records
    assert rec.operation_id == op and rec.template_version == "t-1" and rec.source_tier == 3
    assert rec.redistribution is False and rec.factor_tags == TAGS[op]
    for stamp in (rec.fetched_at, rec.as_of, rec.knowable_at):
        assert stamp is not None and stamp.tzinfo is not None
    assert len(rec.record_digest) == 64 and rec.record_id == "rec-1"
    assert rec.source_id == f"api_anything.{op}"


def test_record_digest_is_deterministic_and_covers_provenance() -> None:
    a = parse(reply()).records[0].record_digest
    assert parse(reply()).records[0].record_digest == a
    changed = reply()
    changed["records"][0]["values"]["value"] = 43
    assert parse(changed).records[0].record_digest != a
    changed = reply()
    changed["records"][0]["knowable_at"] = "2026-10-09T14:58:00Z"
    assert parse(changed).records[0].record_digest != a
    changed = reply(template_version="t-2")
    assert parse(changed).records[0].record_digest != a


@pytest.mark.parametrize("code", [c.value for c in E if c is not E.COLLECTOR_UNAVAILABLE])
def test_sidecar_error_codes_raise_typed_errors(code: str, tmp_path: Path) -> None:
    body = reply(error_code=code, status="DEGRADED", records=[])
    with pytest.raises(client.PublicOperationError) as exc:
        served(tmp_path, body)
    assert exc.value.code.value == code


@pytest.mark.parametrize(
    ("label", "mutate"),
    [
        ("top redistribution missing", lambda b: b.pop("redistribution")),
        ("top redistribution true", lambda b: b.update(redistribution=True)),
        ("record redistribution true", lambda b: b["records"][0].update(redistribution=True)),
        ("record redistribution missing", lambda b: b["records"][0].pop("redistribution")),
        ("source_tier 2", lambda b: b.update(source_tier=2)),
        ("source_tier 1", lambda b: b.update(source_tier=1)),
        ("source_id mismatch", lambda b: b.update(source_id="api_anything.calendar.fed")),
        ("source_id other vendor", lambda b: b.update(source_id="evil.cnn.fear_greed")),
        ("operation unknown", lambda b: b.update(operation_id="evil.op")),
        ("operation None on OK", lambda b: b.update(operation_id=None)),
        ("template_version None", lambda b: b.update(template_version=None)),
        ("quality unknown", lambda b: b["records"][0].update(quality="guessed")),
        ("record_id missing", lambda b: b["records"][0].pop("record_id")),
        ("values missing", lambda b: b["records"][0].pop("values")),
        ("values extra field", lambda b: b["records"][0]["values"].update(extra=1)),
        ("values field missing", lambda b: b["records"][0]["values"].pop("label")),
        ("values out of range", lambda b: b["records"][0]["values"].update(value=101)),
        ("values wrong type", lambda b: b["records"][0]["values"].update(value="42")),
        ("naive record timestamp", lambda b: b["records"][0].update(knowable_at="2026-10-09T14:59:00")),
        ("naive fetched_at", lambda b: b.update(fetched_at="2026-10-09T15:00:00")),
        ("garbage timestamp", lambda b: b["records"][0].update(as_of="yesterday")),
        ("record as_of after fetched_at", lambda b: b["records"][0].update(as_of="2026-10-09T15:00:01Z")),
        ("record knowable_at after fetched_at", lambda b: b["records"][0].update(knowable_at="2026-10-09T15:00:01Z")),
        ("result as_of after fetched_at", lambda b: b.update(as_of="2026-10-09T15:00:01Z")),
        ("result knowable_at after fetched_at", lambda b: b.update(knowable_at="2026-10-09T15:00:01Z")),
        ("501 records", lambda b: b.update(records=[dict(b["records"][0], record_id=f"r{i}") for i in range(501)])),
        ("unknown top-level field", lambda b: b.update(surprise=1)),
        ("schema_version 2", lambda b: b.update(schema_version=2)),
        ("status invalid", lambda b: b.update(status="MAYBE")),
        ("overlong record_id", lambda b: b["records"][0].update(record_id="x" * 513)),
    ],
)
def test_malformed_or_untrusted_replies_fail_closed(label: str, mutate, tmp_path: Path) -> None:
    body = reply()
    mutate(body)
    with pytest.raises(client.PublicOperationError) as exc:
        served(tmp_path, body)
    assert exc.value.code is E.SCHEMA_INVALID, label


def test_nan_in_numeric_value_fails_closed(tmp_path: Path) -> None:
    body = reply("cboe.daily.stats")
    body["records"][0]["values"]["value"] = float("nan")
    with pytest.raises(client.PublicOperationError) as exc:
        served(tmp_path, body, op="cboe.daily.stats", args={"date": "2026-10-08"})
    assert exc.value.code is E.SCHEMA_INVALID


def test_future_knowable_or_asof_is_a_hard_error_at_decision_time() -> None:
    result = parse(reply(fetched_at="2026-10-09T15:30:00Z"))  # fetch happened later than the decision
    early = datetime(2026, 10, 9, 14, 0, tzinfo=UTC)
    with pytest.raises(client.PublicOperationError) as exc:
        result.evidence_records(early)
    assert exc.value.code is E.SCHEMA_INVALID
    only_knowable_late = reply(fetched_at="2026-10-09T15:30:00Z")
    only_knowable_late["records"][0]["as_of"] = "2026-10-09T13:00:00Z"
    only_knowable_late["as_of"] = "2026-10-09T13:00:00Z"
    only_knowable_late["records"][0]["knowable_at"] = "2026-10-09T15:10:00Z"
    with pytest.raises(client.PublicOperationError) as exc2:
        parse(only_knowable_late).evidence_records(datetime(2026, 10, 9, 15, 0, tzinfo=UTC))
    assert exc2.value.code is E.SCHEMA_INVALID


def test_missing_knowable_at_abstains_not_errors_and_never_borrows_fetch_time() -> None:
    body = reply()
    body["records"][0]["knowable_at"] = None
    body["knowable_at"] = None
    body["records"][0]["quality"] = "availability_unknown"
    result = parse(body)
    assert result.records[0].knowable_at is None
    assert result.evidence_records(DECISION) == ()


def test_mixed_records_only_knowable_ones_become_evidence() -> None:
    body = reply()
    second = dict(body["records"][0], record_id="rec-2", knowable_at=None, quality="availability_unknown")
    body["records"].append(second)
    kept = parse(body).evidence_records(DECISION)
    assert [r.record_id for r in kept] == ["rec-1"]


def test_future_event_at_is_allowed_scheduled_metadata() -> None:
    body = reply("calendar.fed")
    body["records"][0]["event_at"] = "2026-12-09T19:00:00Z"
    [rec] = parse(body).evidence_records(DECISION)
    assert rec.event_at > DECISION


def test_evidence_cap_is_exact_no_silent_truncation() -> None:
    def many(n):
        body = reply()
        body["records"] = [dict(body["records"][0], record_id=f"r{i}") for i in range(n)]
        return parse(body)

    assert len(many(client.MAX_EVIDENCE_REFS).evidence_records(DECISION)) == 128
    with pytest.raises(client.PublicOperationError) as exc:
        many(client.MAX_EVIDENCE_REFS + 1).evidence_records(DECISION)
    assert exc.value.code is E.SCHEMA_INVALID


def test_naive_decision_time_is_rejected() -> None:
    with pytest.raises(client.PublicOperationError):
        parse(reply()).evidence_records(datetime(2026, 10, 9, 15, 1))


@pytest.mark.parametrize(
    ("status", "code"),
    [("DEGRADED", E.OPERATION_DEGRADED), ("USER_ACTION_REQUIRED", E.USER_ACTION_REQUIRED),
     ("USER_ACTION_DECLINED", E.USER_ACTION_DECLINED), ("TIMEOUT", E.TIMEOUT)],
)
def test_non_ok_status_never_yields_evidence(status: str, code) -> None:
    result = parse(reply(status=status))
    with pytest.raises(client.PublicOperationError) as exc:
        result.evidence_records(DECISION)
    assert exc.value.code is code


def test_finding_knowable_at_may_not_precede_publication_or_availability() -> None:
    """FINDING (medium, point-in-time leak): knowable_at is trusted verbatim from the scraped source.
    A record published at 14:50 and available at 14:55 but claiming knowable_at 14:00 is returned as
    evidence for a 14:10 decision.  The client (and the sidecar's eventAndValues) never check
    knowable_at >= max(published_at, available_at)."""
    body = reply()
    rec = body["records"][0]
    rec.update(as_of="2026-10-09T14:00:00Z", knowable_at="2026-10-09T14:00:00Z",
               published_at="2026-10-09T14:50:00Z", available_at="2026-10-09T14:55:00Z")
    body["as_of"] = "2026-10-09T14:00:00Z"
    body["knowable_at"] = "2026-10-09T14:00:00Z"
    decision = datetime(2026, 10, 9, 14, 10, tzinfo=UTC)
    try:
        leaked = parse(body).evidence_records(decision)
    except client.PublicOperationError:
        return
    assert leaked == (), "record not yet published/available at the decision time was returned as evidence"


def test_user_action_notification_flow_is_typed_and_consumable(tmp_path: Path) -> None:
    note = {"type": "notification", "request_id": str(uuid.uuid4()), "status": "USER_ACTION_REQUIRED",
            "source_id": "api_anything.calendar.fed", "operation_id": "calendar.fed",
            "message": "Leviathan needs you to complete a check on fed-calendar."}
    script = tmp_path / "c.py"
    script.write_text(
        "import sys,json\nreq=json.loads(sys.stdin.readline())\n"
        f"print(json.dumps({json.dumps(note)}),flush=True)\n"
        "print(json.dumps({'schema_version':1,'request_id':req['request_id'],'operation_id':'calendar.fed',"
        "'template_version':'t','source_id':'api_anything.calendar.fed','source_tier':3,'status':'USER_ACTION_DECLINED',"
        "'fetched_at':'2026-10-09T15:00:00Z','as_of':None,'knowable_at':None,'redistribution':False,'records':[],"
        "'error_code':'USER_ACTION_DECLINED'}),flush=True)\nsys.stdin.readline()\n",
        encoding="utf-8",
    )
    sup = client.CollectorSupervisor(sys.executable, script, data_dir=tmp_path / "d", timeout_s=15)
    try:
        with pytest.raises(client.PublicOperationError) as exc:
            sup.call("calendar.fed", {"year": 2026})
        assert exc.value.code is E.USER_ACTION_DECLINED
        event = sup.next_event(2)
        assert event is not None and event.status == "USER_ACTION_REQUIRED" and event.operation_id == "calendar.fed"
    finally:
        sup.close()


@pytest.mark.parametrize(
    "bad",
    [
        {"source_id": "evil.source"},
        {"operation_id": "evil.op"},
        {"status": "DEGRADED"},
        {"message": ""},
        {"extra": 1},
    ],
)
def test_malformed_notifications_fail_closed(bad: dict, tmp_path: Path) -> None:
    note = {"type": "notification", "request_id": str(uuid.uuid4()), "status": "USER_ACTION_REQUIRED",
            "source_id": "api_anything.calendar.fed", "operation_id": "calendar.fed", "message": "m"}
    note.update(bad)
    script = tmp_path / "c.py"
    script.write_text(
        "import sys,json,time\nreq=json.loads(sys.stdin.readline())\n"
        f"print(json.dumps({json.dumps(note)}),flush=True)\ntime.sleep(5)\n",
        encoding="utf-8",
    )
    sup = client.CollectorSupervisor(sys.executable, script, data_dir=tmp_path / "d", timeout_s=10)
    with pytest.raises(client.PublicOperationError) as exc:
        sup.call("calendar.fed", {"year": 2026})
    assert exc.value.code is E.SCHEMA_INVALID


@pytest.mark.xfail(reason="OBSERVATION (low): the notification queue is bounded at 16 and put() blocks the reader "
                   "thread when full, so 17 unconsumed notifications stall the reply stream until the 150 s "
                   "timeout kills the child", strict=False)
def test_finding_unconsumed_notifications_do_not_stall_replies(tmp_path: Path) -> None:
    note = {"type": "notification", "request_id": str(uuid.uuid4()), "status": "USER_ACTION_REQUIRED",
            "source_id": "api_anything.calendar.fed", "operation_id": "calendar.fed", "message": "m"}
    script = tmp_path / "c.py"
    script.write_text(
        "import sys,json\nreq=json.loads(sys.stdin.readline())\n"
        f"[print(json.dumps({json.dumps(note)}),flush=True) for _ in range(20)]\n"
        "print(json.dumps({'schema_version':1,'request_id':req['request_id'],'operation_id':None,'template_version':None,"
        "'source_id':None,'source_tier':None,'status':'OK','fetched_at':'2026-10-09T15:00:00Z','as_of':None,"
        "'knowable_at':None,'redistribution':False,'records':[]}),flush=True)\nsys.stdin.readline()\n",
        encoding="utf-8",
    )
    sup = client.CollectorSupervisor(sys.executable, script, data_dir=tmp_path / "d", timeout_s=4)
    try:
        assert sup.health().status is client.OperationStatus.OK
    finally:
        sup.close()


def test_intel_payload_keeps_full_record_and_digest() -> None:
    rec = parse(reply("calendar.fed")).records[0]
    payload = registry.intel_evidence_payload(rec)
    json.dumps(payload)  # serialisable
    for key in ("operation_id", "template_version", "source_tier", "source_id", "record_id", "fetched_at",
                "as_of", "event_at", "published_at", "available_at", "knowable_at", "factor_tags", "quality",
                "status", "typed_values", "redistribution", "record_digest"):
        assert key in payload, key
    assert payload["redistribution"] is False and payload["source_tier"] == 3
    assert payload["record_digest"] == rec.record_digest and payload["operation_id"] == "calendar.fed"


def test_registry_contributions_are_tier3_not_redistributable_and_exclude_fedwatch() -> None:
    sources = registry.PUBLIC_SOURCES
    assert len(sources) == 5
    for s in sources:
        assert s.tier == 3 and s.redistribution is False
        assert s.source_id.startswith("api_anything.")
        assert "fedwatch" not in (s.endpoint + s.tos_url).lower() and "cmegroup" not in s.endpoint.lower()
    by = {s.source_id: s for s in sources}
    assert by["api_anything.calendar.fed"].tos_classification == "ALLOWED"
    assert all(s.tos_classification == "REVIEW" for k, s in by.items() if k != "api_anything.calendar.fed")


def test_record_dataclass_itself_refuses_redistribution_true_and_naive_stamps() -> None:
    good = parse(reply()).records[0]
    kwargs = {f: getattr(good, f) for f in (
        "operation_id", "template_version", "source_id", "source_tier", "record_id", "fetched_at", "as_of",
        "event_at", "published_at", "available_at", "knowable_at", "factor_tags", "quality", "status", "data")}
    with pytest.raises(client.PublicOperationError):
        client.PublicOperationRecordV1(**kwargs, redistribution=True)  # type: ignore[arg-type]
    naive = dict(kwargs, knowable_at=datetime(2026, 10, 9, 14, 0))
    with pytest.raises(client.PublicOperationError):
        client.PublicOperationRecordV1(**naive)


def test_record_level_future_observation_is_a_hard_error_even_if_reply_header_is_old() -> None:
    body = reply(fetched_at="2026-10-09T15:30:00Z")
    body["as_of"] = "2026-10-09T13:00:00Z"  # header looks fine
    body["records"][0]["as_of"] = "2026-10-09T15:10:00Z"  # but this record observes the future
    body["records"][0]["knowable_at"] = "2026-10-09T13:00:00Z"
    with pytest.raises(client.PublicOperationError) as exc:
        parse(body).evidence_records(datetime(2026, 10, 9, 15, 0, tzinfo=UTC))
    assert exc.value.code is E.SCHEMA_INVALID
