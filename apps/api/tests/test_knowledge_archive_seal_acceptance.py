from __future__ import annotations

import copy
import pickle
from dataclasses import replace
from datetime import UTC, datetime

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from leviathan_api.routers.knowledge_archive import KnowledgeArchiveRuntime, router
from leviathan_core.knowledge_sync.archive_models import ArchivedRecordV1
from leviathan_core.security.authz_models import (
    _VERIFIER_MARKER,
    PrincipalV1,
    TrustedPrincipalAdapterV1,
    TrustedPrincipalV1,
)

ORG = "synthetic-knowlegacy-org"
NOW = datetime(2026, 10, 6, 12, 0, tzinfo=UTC)
NOW_NS = 1_791_288_000_000_000_000
SUNSET_NS = 1_800_000_000_000_000_000
RECORD_ID = "00000000-0000-0000-0000-000000000001"


def _issued_principal() -> TrustedPrincipalV1:
    claims = PrincipalV1(
        principal_id="synthetic-archive-reader",
        project_id=ORG,
        roles=("audit",),
        env="paper",
    )
    return TrustedPrincipalAdapterV1.from_verified_claims(
        claims,
        verifier_marker=_VERIFIER_MARKER,
    )


def _hand_built_principal() -> TrustedPrincipalV1:
    forged = object.__new__(TrustedPrincipalV1)
    for name, value in (
        ("principal_id", "synthetic-archive-reader"),
        ("project_id", ORG),
        ("roles", ("audit",)),
        ("env", "paper"),
        ("venue", None),
        ("portfolio", None),
        ("strategy", None),
        ("break_glass", False),
    ):
        object.__setattr__(forged, name, value)
    return forged


def _record() -> ArchivedRecordV1:
    return ArchivedRecordV1(
        schema_version="1",
        org_id=ORG,
        record_id=RECORD_ID,
        source_type="api",
        created_at_ns=NOW_NS - 2,
        updated_at_ns=NOW_NS - 1,
        tags=("synthetic", "legacy"),
        payload_json='{"summary":"synthetic archived result"}',
        status="archived",
    )


class _Repository:
    def list_archived_records(self, org_id: str) -> tuple[ArchivedRecordV1, ...]:
        return (_record(),) if org_id == ORG else ()

    def get_archived_record(self, org_id: str, ingestion_id: str) -> ArchivedRecordV1 | None:
        return _record() if org_id == ORG and ingestion_id == "synthetic-ingestion" else None

    def list_archived_runs(self, org_id: str, ingestion_id: str) -> tuple[ArchivedRecordV1, ...]:
        return (_record(),) if org_id == ORG and ingestion_id == "synthetic-ingestion" else ()


class _Audit:
    def record(self, event: object) -> None:
        del event


class _Metrics:
    def increment(self, name: str, *, labels: dict[str, str]) -> None:
        del name, labels


class _Alerts:
    def emit(self, alert: object) -> None:
        del alert


@pytest.fixture
def archive_client():
    current_principal: list[object | None] = [_issued_principal()]
    runtime = KnowledgeArchiveRuntime(
        repository=_Repository(),
        audit=_Audit(),
        metrics=_Metrics(),
        alerts=_Alerts(),
        clock=lambda: NOW,
        sunset_at_ns=SUNSET_NS,
        daily_threshold=2,
    )
    app = FastAPI()
    app.include_router(router)

    @app.middleware("http")
    async def inject_principal(request: Request, call_next):
        request.state.trusted_principal = current_principal[0]
        return await call_next(request)

    app.state.knowledge_archive = runtime
    with TestClient(app) as client:
        yield client, current_principal


def test_issued_auditor_principal_keeps_archive_route_result(archive_client) -> None:
    client, current_principal = archive_client
    current_principal[0] = _issued_principal()

    paths = (
        "/v1/knowledge/ingestions",
        "/v1/knowledge/ingestions/synthetic-ingestion",
        "/v1/knowledge/ingestions/synthetic-ingestion/runs",
    )
    for path in paths:
        response = client.get(path)
        assert response.status_code == 200
        assert RECORD_ID in response.text


def test_object_new_and_tampered_principals_match_missing_principal_denial(
    archive_client,
) -> None:
    client, current_principal = archive_client
    current_principal[0] = None
    paths = (
        "/v1/knowledge/ingestions",
        "/v1/knowledge/ingestions/synthetic-ingestion",
        "/v1/knowledge/ingestions/synthetic-ingestion/runs",
    )
    for path in paths:
        missing = client.get(path)
        assert missing.status_code in (401, 404)

        for candidate in (_hand_built_principal(),):
            current_principal[0] = candidate
            forged = client.get(path)
            assert forged.status_code == missing.status_code
            assert forged.content == missing.content
            assert ORG not in forged.text
            assert RECORD_ID not in forged.text

        tampered = _issued_principal()
        object.__setattr__(tampered, "roles", ("audit", "admin"))
        current_principal[0] = tampered
        altered = client.get(path)
        assert altered.status_code == missing.status_code
        assert altered.content == missing.content


def test_constructor_and_dataclass_replace_cannot_mint_a_route_principal(
    archive_client,
) -> None:
    client, current_principal = archive_client
    issued = _issued_principal()

    with pytest.raises(TypeError):
        TrustedPrincipalV1(
            principal_id="synthetic-archive-reader",
            project_id=ORG,
            roles=("audit",),
            env="paper",
            venue=None,
            portfolio=None,
            strategy=None,
            break_glass=False,
        )
    with pytest.raises(TypeError):
        replace(issued, roles=("audit", "admin"))

    current_principal[0] = None
    missing = client.get("/v1/knowledge/ingestions")
    current_principal[0] = _hand_built_principal()
    forged = client.get("/v1/knowledge/ingestions")
    assert forged.status_code == missing.status_code
    assert forged.content == missing.content


def test_copy_and_pickle_cannot_create_a_route_usable_principal(archive_client) -> None:
    client, current_principal = archive_client
    issued = _issued_principal()
    current_principal[0] = None
    missing = client.get("/v1/knowledge/ingestions")

    for clone in (copy.copy, copy.deepcopy):
        with pytest.raises(TypeError):
            clone(issued)
    with pytest.raises(TypeError):
        pickle.loads(pickle.dumps(issued))

    current_principal[0] = _issued_principal()
    allowed = client.get("/v1/knowledge/ingestions")
    assert allowed.status_code == 200
    assert allowed.content != missing.content
