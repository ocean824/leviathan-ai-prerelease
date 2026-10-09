"""Independent HTTP acceptance for the archived knowledge boundary."""

from __future__ import annotations

import copy
import json
import pickle
import socket
from datetime import UTC, datetime
from email.utils import format_datetime

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from pydantic import BaseModel

from leviathan_api.routers.knowledge_archive import (
    KnowledgeArchiveRuntime,
    router,
)
from leviathan_core.knowledge_sync.archive_models import ArchivedRecordV1
from leviathan_core.knowledge_sync.legacy_dlq import (
    DeadLetterV1,
    LegacyDLQError,
    LegacyJobV1,
    PublishDispositionV1,
    PublishResultV1,
    dead_letter_residual,
    reject_legacy_publish,
    scheduler_decision,
    start_scheduler,
)
from leviathan_core.seal import SealError, verify
from leviathan_core.security.authz_models import (
    _VERIFIER_MARKER,
    PrincipalV1,
    TrustedPrincipalAdapterV1,
    TrustedPrincipalV1,
)

ORG = "synthetic-knowledge-org"
OTHER_ORG = "synthetic-other-org"
NOW = datetime(2026, 10, 6, 12, 0, tzinfo=UTC)
NOW_NS = 1_791_288_000_000_000_000
SUNSET_NS = 1_800_000_000_000_000_000
CANARY = "SYNTHETIC_ARCHIVE_SECRET_CANARY"


def principal(*, project_id: str = ORG, roles: tuple[str, ...] = ("audit",)) -> TrustedPrincipalV1:
    claims = PrincipalV1(
        principal_id="synthetic-archive-reader",
        project_id=project_id,
        roles=roles,
        env="paper",
    )
    return TrustedPrincipalAdapterV1.from_verified_claims(
        claims,
        verifier_marker=_VERIFIER_MARKER,
    )


def record(
    number: int,
    *,
    org_id: str = ORG,
    created_at_ns: int = NOW_NS - 2,
    updated_at_ns: int = NOW_NS - 1,
    payload_json: str | None = None,
    tags: tuple[str, ...] = ("synthetic", "legacy"),
) -> ArchivedRecordV1:
    return ArchivedRecordV1(
        schema_version="1",
        org_id=org_id,
        record_id=f"00000000-0000-0000-0000-{number:012d}",
        source_type="api",
        created_at_ns=created_at_ns,
        updated_at_ns=updated_at_ns,
        tags=tags,
        payload_json=(
            json.dumps(
                {
                    "ordinary": {"status": "archived", "count": 3},
                    "credentials": {"token": CANARY, "nested": {"api_key": CANARY}},
                },
                separators=(",", ":"),
            )
            if payload_json is None
            else payload_json
        ),
        status="archived",
    )


class FakeRepository:
    def __init__(
        self,
        *,
        records: tuple[ArchivedRecordV1, ...] = (),
        detail: dict[tuple[str, str], ArchivedRecordV1] | None = None,
        runs: dict[tuple[str, str], tuple[ArchivedRecordV1, ...]] | None = None,
    ) -> None:
        self.records = records
        self.detail = detail or {}
        self.runs = runs or {}
        self.calls: list[tuple[object, ...]] = []

    def list_archived_records(self, org_id: str) -> tuple[ArchivedRecordV1, ...]:
        self.calls.append(("list", org_id))
        return self.records

    def get_archived_record(self, org_id: str, ingestion_id: str) -> ArchivedRecordV1 | None:
        self.calls.append(("detail", org_id, ingestion_id))
        return self.detail.get((org_id, ingestion_id))

    def list_archived_runs(self, org_id: str, ingestion_id: str) -> tuple[ArchivedRecordV1, ...]:
        self.calls.append(("runs", org_id, ingestion_id))
        return self.runs.get((org_id, ingestion_id), ())


class FakeAudit:
    def __init__(self) -> None:
        self.events: list[object] = []

    def record(self, event: object) -> None:
        self.events.append(event)


class FakeMetrics:
    def __init__(self) -> None:
        self.increments: list[tuple[str, dict[str, str]]] = []

    def increment(self, name: str, *, labels: dict[str, str]) -> None:
        self.increments.append((name, dict(labels)))


class FakeAlerts:
    def __init__(self) -> None:
        self.events: list[object] = []

    def emit(self, alert: object) -> None:
        self.events.append(alert)


@pytest.fixture
def local_api():
    repository = FakeRepository()
    audit = FakeAudit()
    metrics = FakeMetrics()
    alerts = FakeAlerts()
    runtime = KnowledgeArchiveRuntime(
        repository=repository,
        audit=audit,
        metrics=metrics,
        alerts=alerts,
        clock=lambda: NOW,
        sunset_at_ns=SUNSET_NS,
        daily_threshold=2,
    )
    current_principal: list[object | None] = [principal()]
    app = FastAPI()
    app.include_router(router)

    @app.middleware("http")
    async def inject_trusted_principal(request: Request, call_next):
        request.state.trusted_principal = current_principal[0]
        return await call_next(request)

    app.state.knowledge_archive = runtime
    with TestClient(app) as client:
        yield client, repository, audit, metrics, alerts, current_principal


def assert_deprecation_headers(response, *, etag: bool = False) -> None:
    expected = {"deprecation", "sunset", "link"}
    if etag:
        expected.add("etag")
    assert expected <= {name.lower() for name in response.headers}
    assert response.headers["Deprecation"] == "true"
    assert response.headers["Sunset"] == format_datetime(
        datetime.fromtimestamp(SUNSET_NS // 1_000_000_000, UTC), usegmt=True
    )
    assert response.headers["Sunset"].endswith("GMT")
    assert response.headers["Link"].count('rel="successor-version"') == 2
    assert response.headers["Link"].count(".invalid") == 2


def test_local_router_lists_only_visible_org_records_and_masks_nested_values(local_api):
    client, repository, audit, metrics, _alerts, _who = local_api
    own = record(1)
    foreign = record(2, org_id=OTHER_ORG)
    future = record(3, created_at_ns=NOW_NS + 1, updated_at_ns=NOW_NS + 1)
    repository.records = (foreign, future, own)

    response = client.get("/v1/knowledge/ingestions")

    assert response.status_code == 200
    assert_deprecation_headers(response, etag=True)
    payload = response.json()
    assert payload["data"][0]["id"] == own.record_id
    assert payload["meta"]["replacement"] == {
        "market_data_doc": "https://docs.example.invalid/market-data-pipeline",
        "ea_builder_doc": "https://docs.example.invalid/ea-builder-knowledge",
    }
    assert OTHER_ORG not in response.text
    assert "000000000002" not in response.text
    assert CANARY not in response.text
    assert payload["data"][0]["data"]["credentials"]["token"] == "****"
    assert payload["data"][0]["data"]["ordinary"]["count"] == "****"
    assert repository.calls == [("list", ORG)]
    assert len(audit.events) == 1
    assert metrics.increments == [
        ("archived_knowledge.calls_total", {"method": "GET", "status": "200"})
    ]


def test_detail_and_runs_are_org_scoped_and_missing_equals_foreign(local_api):
    client, repository, _audit, _metrics, _alerts, current_principal = local_api
    own = record(10)
    foreign = record(11, org_id=OTHER_ORG)
    future = record(
        13,
        created_at_ns=NOW_NS + 1,
        updated_at_ns=NOW_NS + 1,
    )
    own_id = "synthetic-ingestion-10"
    foreign_id = "synthetic-ingestion-11"
    future_id = "synthetic-ingestion-13"
    repository.detail[(ORG, own_id)] = own
    repository.detail[(ORG, foreign_id)] = foreign
    repository.detail[(ORG, future_id)] = future
    run = record(12)
    repository.runs[(ORG, own_id)] = (run,)
    repository.runs[(ORG, future_id)] = (run,)

    own_response = client.get(f"/v1/knowledge/ingestions/{own_id}")
    missing_response = client.get("/v1/knowledge/ingestions/missing")
    foreign_response = client.get(f"/v1/knowledge/ingestions/{foreign_id}")
    runs_response = client.get(f"/v1/knowledge/ingestions/{own_id}/runs")
    future_runs_response = client.get(f"/v1/knowledge/ingestions/{future_id}/runs")

    assert own_response.status_code == 200
    assert own_response.json()["data"]["id"] == own.record_id
    assert_deprecation_headers(own_response, etag=True)
    assert missing_response.status_code == foreign_response.status_code == 404
    assert missing_response.content == foreign_response.content
    assert OTHER_ORG not in foreign_response.text
    assert future_runs_response.status_code == 404
    assert future_runs_response.content == missing_response.content
    assert runs_response.status_code == 200
    assert runs_response.json()["data"][0]["id"] == run.record_id
    assert repository.calls == [
        ("detail", ORG, own_id),
        ("detail", ORG, "missing"),
        ("detail", ORG, foreign_id),
        ("detail", ORG, own_id),
        ("runs", ORG, own_id),
        ("detail", ORG, future_id),
    ]

    current_principal[0] = principal(project_id=OTHER_ORG)
    scoped = client.get(f"/v1/knowledge/ingestions/{own_id}")
    assert scoped.status_code == 404
    assert ORG not in scoped.text
    assert repository.calls[-1] == ("detail", OTHER_ORG, own_id)


def test_authentication_and_role_denials_happen_before_repository_access(local_api):
    client, repository, _audit, _metrics, _alerts, current_principal = local_api
    repository.records = (record(20),)

    current_principal[0] = None
    unauthenticated = client.get("/v1/knowledge/ingestions")
    current_principal[0] = principal(roles=("trader",))
    forbidden = client.get("/v1/knowledge/ingestions")

    assert unauthenticated.status_code == 401
    assert forbidden.status_code == 403
    assert_deprecation_headers(unauthenticated)
    assert_deprecation_headers(forbidden)
    assert repository.calls == []


def test_query_pagination_and_conditional_etag_are_served_by_local_router(local_api):
    client, repository, _audit, _metrics, _alerts, _who = local_api
    repository.records = tuple(record(i, created_at_ns=NOW_NS - i) for i in range(1, 4))

    first = client.get("/v1/knowledge/ingestions?limit=1")
    assert first.status_code == 200
    assert first.json()["meta"]["cursor"] == "1"
    assert first.headers["X-Next-Cursor"] == "1"
    second = client.get("/v1/knowledge/ingestions?limit=1&cursor=1")
    assert second.status_code == 200
    assert first.json()["data"][0]["id"] != second.json()["data"][0]["id"]

    not_modified = client.get(
        "/v1/knowledge/ingestions?limit=1",
        headers={"If-None-Match": first.headers["ETag"]},
    )
    assert not_modified.status_code == 304
    assert not not_modified.content
    assert not_modified.headers["ETag"] == first.headers["ETag"]
    assert_deprecation_headers(not_modified, etag=True)


def test_runs_route_applies_filters_and_advances_cursors(local_api):
    client, repository, _audit, _metrics, _alerts, _who = local_api
    ingestion_id = "synthetic-ingestion-runs-pages"
    repository.detail[(ORG, ingestion_id)] = record(61)
    repository.runs[(ORG, ingestion_id)] = tuple(
        record(
            number,
            created_at_ns=NOW_NS - 1_000 + number,
            tags=("keep",) if number % 2 == 0 else ("skip",),
        )
        for number in range(100, 220)
    )
    path = f"/v1/knowledge/ingestions/{ingestion_id}/runs"

    first = client.get(f"{path}?tag=keep&limit=10")
    second = client.get(f"{path}?tag=keep&limit=10&cursor=10")

    assert first.status_code == second.status_code == 200
    first_ids = [item["id"] for item in first.json()["data"]]
    second_ids = [item["id"] for item in second.json()["data"]]
    assert len(first_ids) == len(second_ids) == 10
    assert set(first_ids).isdisjoint(second_ids)
    assert first.headers["X-Next-Cursor"] == "10"
    assert second.headers["X-Next-Cursor"] == "20"
    assert all("keep" in item["tags"] for item in first.json()["data"])
    assert all("keep" in item["tags"] for item in second.json()["data"])
    assert repository.calls == [
        ("detail", ORG, ingestion_id),
        ("runs", ORG, ingestion_id),
        ("detail", ORG, ingestion_id),
        ("runs", ORG, ingestion_id),
    ]


@pytest.mark.parametrize(
    ("path", "query"),
    [
        ("/v1/knowledge/ingestions", "limit=0"),
        ("/v1/knowledge/ingestions", "limit=201"),
        ("/v1/knowledge/ingestions", "cursor=SYNTHETIC_CURSOR_SECRET"),
        ("/v1/knowledge/ingestions", "tag=bad%20tag"),
        ("/v1/knowledge/ingestions", "tag=one&tag=two"),
        (
            "/v1/knowledge/ingestions/synthetic-parent/runs",
            "limit=0",
        ),
        (
            "/v1/knowledge/ingestions/synthetic-parent/runs",
            "cursor=SYNTHETIC_CURSOR_SECRET",
        ),
        (
            "/v1/knowledge/ingestions/synthetic-parent/runs",
            "tag=bad%20tag",
        ),
    ],
)
def test_invalid_list_and_runs_queries_are_audited_content_free_400s(
    local_api, path: str, query: str
) -> None:
    client, repository, audit, metrics, _alerts, _who = local_api
    response = client.get(f"{path}?{query}")

    assert response.status_code == 400
    error_code = response.json()["error"]["code"]
    assert error_code in {
        "INVALID_QUERY",
        "INVALID_CURSOR",
        "INVALID_LIMIT",
        "INVALID_TAG",
        "INVALID_TIME",
        "INVALID_TIME_RANGE",
    }
    assert "SYNTHETIC_CURSOR_SECRET" not in response.text
    assert len(audit.events) == 1
    assert audit.events[0].status_code == 400
    assert metrics.increments == [
        ("archived_knowledge.calls_total", {"method": "GET", "status": "400"})
    ]
    assert not any(call[0] == "runs" for call in repository.calls)


def test_unknown_http_method_uses_bounded_other_metric_and_audit_labels(local_api):
    client, repository, audit, metrics, _alerts, _who = local_api

    response = client.request("BREW", "/v1/knowledge/ingestions")

    assert response.status_code == 410
    assert response.json()["error"]["code"] == "LEGACY_ARCHIVED"
    assert repository.calls == []
    assert audit.events[0].method == "OTHER"
    assert audit.events[0].endpoint.startswith("OTHER ")
    assert metrics.increments == [
        ("archived_knowledge.calls_total", {"method": "OTHER", "status": "410"})
    ]


def test_overlong_http_method_is_audited_400_without_echoing_method(local_api):
    client, repository, audit, metrics, _alerts, _who = local_api
    method = "M" * 65

    response = client.request(method, "/v1/knowledge/ingestions")

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "INVALID_METHOD"
    assert method not in response.text
    assert repository.calls == []
    assert len(audit.events) == 1
    assert audit.events[0].method == "OTHER"
    assert metrics.increments == [
        ("archived_knowledge.calls_total", {"method": "OTHER", "status": "400"})
    ]


@pytest.mark.parametrize(
    ("method", "path"),
    [
        (method, path)
        for method in (
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
            "OPTIONS",
            "TRACE",
            "CONNECT",
            "COPY",
            "LINK",
            "UNLINK",
            "PURGE",
            "LOCK",
            "UNLOCK",
            "PROPFIND",
            "VIEW",
        )
        for path in (
            "/v1/knowledge/ingestions",
            "/v1/knowledge/ingestions/synthetic-id",
            "/v1/knowledge/ingestions/synthetic-id/runs",
        )
    ],
)
def test_every_write_verb_and_run_launch_path_returns_410_without_storage(
    local_api, method: str, path: str
) -> None:
    client, repository, audit, metrics, _alerts, _who = local_api

    response = client.request(method, path)

    assert response.status_code == 410
    assert response.json()["error"]["code"] == "LEGACY_ARCHIVED"
    assert_deprecation_headers(response)
    assert repository.calls == []
    assert len(audit.events) == 1
    assert metrics.increments == [
        ("archived_knowledge.calls_total", {"method": method, "status": "410"})
    ]


def test_query_values_and_secret_canaries_do_not_leak_into_audit_or_errors(local_api):
    client, repository, audit, _metrics, _alerts, _who = local_api
    repository.records = (record(30),)
    hostile_filter = "customer_secret_filter"
    response = client.get(f"/v1/knowledge/ingestions?{hostile_filter}=SYNTHETIC_FILTER_VALUE")
    malformed = client.get("/v1/knowledge/ingestions?limit=999")

    assert response.status_code == 200
    assert response.json()["meta"]["warnings"] == ["IGNORED_UNKNOWN_FILTER"]
    assert malformed.status_code == 400
    assert malformed.json()["error"]["code"] == "INVALID_LIMIT"
    for event in audit.events:
        assert hostile_filter not in str(event)
        assert "SYNTHETIC_FILTER_VALUE" not in str(event)
        assert CANARY not in str(event)
    assert hostile_filter not in response.text
    assert CANARY not in response.text
    assert "999" not in malformed.text


def test_each_call_is_audited_counted_and_threshold_alerts_once_per_day(local_api):
    client, _repository, audit, metrics, alerts, _who = local_api

    first = client.get("/v1/knowledge/ingestions")
    second = client.get("/v1/knowledge/ingestions")
    third = client.post("/v1/knowledge/ingestions")

    assert first.status_code == second.status_code == 200
    assert third.status_code == 410
    assert len(audit.events) == len(metrics.increments) == 3
    assert len(alerts.events) == 1
    alert = alerts.events[0]
    assert alert.day_utc == "2026-10-06"
    assert alert.observed_calls == 2
    assert alert.daily_threshold == 2
    assert [event.status_code for event in audit.events] == [200, 200, 410]
    assert [labels["status"] for _, labels in metrics.increments] == ["200", "200", "410"]


def test_route_uses_only_injected_local_ports_and_never_opens_network_connections(
    local_api, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, repository, _audit, _metrics, _alerts, _who = local_api
    repository.records = (record(40),)
    attempted: list[object] = []

    def deny_connect(*args: object, **kwargs: object) -> None:
        attempted.append((args, kwargs))
        raise AssertionError("network access is outside the acceptance fixture")

    monkeypatch.setattr(socket.socket, "connect", deny_connect)
    monkeypatch.setattr(socket, "create_connection", deny_connect)

    response = client.get("/v1/knowledge/ingestions")

    assert response.status_code == 200
    assert attempted == []
    assert repository.calls == [("list", ORG)]


class FakeDeadLetterSink:
    def __init__(self) -> None:
        self.published: list[DeadLetterV1] = []

    def publish(self, message: DeadLetterV1) -> None:
        self.published.append(message)


def test_new_legacy_publish_is_nacked_without_queue_write_and_residual_is_correlated():
    job = LegacyJobV1(
        schema_version="1",
        job_id="synthetic-job-55",
        correlation_id="synthetic-correlation-55",
        reason="ARCHIVED_PIPELINE",
    )
    sink = FakeDeadLetterSink()

    result = reject_legacy_publish(job)
    assert sink.published == []
    dead_letter = dead_letter_residual(job, sink=sink)

    assert result.status_code == 410
    assert result.disposition is PublishDispositionV1.NACK_LEGACY_ARCHIVED
    assert result.correlation_id == job.correlation_id
    assert sink.published == [dead_letter]
    assert dead_letter.schema_version == "1"
    assert dead_letter.topic == "knowledge.ingest.dlq"
    assert dead_letter.job_id == job.job_id
    assert dead_letter.correlation_id == job.correlation_id
    assert dead_letter.reason == job.reason


def test_archived_scheduler_cannot_start_or_restart():
    first = scheduler_decision()
    second = scheduler_decision()

    assert first.may_start is second.may_start is False
    assert first.reason == second.reason == "LEGACY_ARCHIVED"
    with pytest.raises(LegacyDLQError) as caught:
        start_scheduler()
    assert caught.value.code == "SCHEDULER_DISABLED"
    assert "synthetic" not in str(caught.value)


def test_issued_dead_letter_results_are_sealed_frozen_and_tamper_evident():
    job = LegacyJobV1(
        schema_version="1",
        job_id="synthetic-job-freeze",
        correlation_id="synthetic-correlation-freeze",
        reason="ARCHIVED_PIPELINE",
    )
    issued = reject_legacy_publish(job)
    tag = "know_legacy002.dlq.v1"

    assert verify(issued, tag)
    with pytest.raises(SealError):
        copy.copy(issued)
    with pytest.raises(SealError):
        copy.deepcopy(issued)
    with pytest.raises(SealError):
        pickle.dumps(issued)
    with pytest.raises(SealError):
        issued.model_copy(update={"status_code": 200})
    with pytest.raises(SealError):
        issued.model_construct(
            schema_version="1",
            disposition=PublishDispositionV1.NACK_LEGACY_ARCHIVED,
            status_code=200,
            correlation_id="forged-correlation",
        )
    with pytest.raises(SealError):
        BaseModel.__init__(
            issued,
            schema_version="1",
            disposition=PublishDispositionV1.NACK_LEGACY_ARCHIVED,
            status_code=200,
            correlation_id="forged-correlation",
        )
    with pytest.raises(SealError):
        BaseModel.__setstate__(issued, {"status_code": 200})
    assert issued.status_code == 410
    assert issued.correlation_id == job.correlation_id
    assert verify(issued, tag)

    forged = PublishResultV1(
        schema_version="1",
        disposition=PublishDispositionV1.NACK_LEGACY_ARCHIVED,
        status_code=410,
        correlation_id=job.correlation_id,
    )
    assert not verify(forged, tag)

    sink = FakeDeadLetterSink()
    dead_letter = dead_letter_residual(job, sink=sink)
    assert verify(dead_letter, tag)
    object.__setattr__(dead_letter, "reason", "FORGED_REASON")
    assert not verify(dead_letter, tag)


def test_dead_letter_sink_failure_is_typed_and_does_not_echo_sink_text():
    class BrokenSink:
        def publish(self, _message: DeadLetterV1) -> None:
            raise RuntimeError("SYNTHETIC_SINK_SECRET")

    job = LegacyJobV1(
        schema_version="1",
        job_id="synthetic-job-broken",
        correlation_id="synthetic-correlation-broken",
        reason="ARCHIVED_PIPELINE",
    )
    sink = FakeDeadLetterSink()

    with pytest.raises(LegacyDLQError) as miswired:
        dead_letter_residual(job, sink=object())  # type: ignore[arg-type]
    assert miswired.value.code == "INVALID_SINK"
    assert sink.published == []

    with pytest.raises(LegacyDLQError) as caught:
        dead_letter_residual(job, sink=BrokenSink())
    assert caught.value.code == "SINK_PUBLISH_FAILED"
    assert "SYNTHETIC_SINK_SECRET" not in str(caught.value)
    assert "SYNTHETIC_SINK_SECRET" not in repr(caught.value.args)


def test_secret_bearing_free_text_reason_is_rejected_before_sink_use():
    secret_reason = "postgresql://admin:SYNTHETIC_REASON_SECRET@db.invalid/prod"
    sink = FakeDeadLetterSink()

    with pytest.raises(LegacyDLQError) as caught:
        LegacyJobV1(
            schema_version="1",
            job_id="synthetic-job-secret-reason",
            correlation_id="synthetic-correlation-secret-reason",
            reason=secret_reason,
        )

    assert caught.value.code == "INVALID_JOB"
    assert secret_reason not in str(caught.value)
    assert secret_reason not in repr(caught.value.args)
    assert "SYNTHETIC_REASON_SECRET" not in repr(caught.value.__context__)
    assert sink.published == []
