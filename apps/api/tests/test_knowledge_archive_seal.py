"""CL-KNOWLEGACY-SEAL: the archive routes act only for issued principals."""

from __future__ import annotations

import json
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

ORG = "synthetic-knowledge-org"
NOW = datetime(2026, 10, 6, 12, 0, tzinfo=UTC)
NOW_NS = 1_791_288_000_000_000_000
SUNSET_NS = 1_800_000_000_000_000_000
_FIELDS = ("principal_id", "project_id", "roles", "env", "venue", "portfolio", "strategy",
           "break_glass")
RECORD = ArchivedRecordV1(
    schema_version="1", org_id=ORG, record_id="00000000-0000-0000-0000-000000000001",
    source_type="api", created_at_ns=NOW_NS - 2, updated_at_ns=NOW_NS - 1,
    tags=("synthetic",), payload_json=json.dumps({"ordinary": {"count": 3}}), status="archived",
)
PATHS = (
    "/v1/knowledge/ingestions",
    f"/v1/knowledge/ingestions/{RECORD.record_id}",
    f"/v1/knowledge/ingestions/{RECORD.record_id}/runs",
)


def _claims(roles: tuple[str, ...] = ("audit",)) -> PrincipalV1:
    return PrincipalV1(principal_id="synthetic-reader", project_id=ORG, roles=roles, env="paper")


def _issued(roles: tuple[str, ...] = ("audit",)) -> TrustedPrincipalV1:
    return TrustedPrincipalAdapterV1.from_verified_claims(
        _claims(roles), verifier_marker=_VERIFIER_MARKER
    )


def _hand_built() -> TrustedPrincipalV1:
    claims = _claims()
    principal = object.__new__(TrustedPrincipalV1)
    for name in _FIELDS:
        object.__setattr__(principal, name, getattr(claims, name))
    return principal


class _Repository:
    def list_archived_records(self, org_id: str) -> tuple[ArchivedRecordV1, ...]:
        return (RECORD,)

    def get_archived_record(self, org_id: str, ingestion_id: str) -> ArchivedRecordV1 | None:
        return RECORD if ingestion_id == RECORD.record_id else None

    def list_archived_runs(self, org_id: str, ingestion_id: str) -> tuple[ArchivedRecordV1, ...]:
        return (RECORD,)


class _Audit:
    def __init__(self) -> None:
        self.events: list[object] = []

    def record(self, event: object) -> None:
        self.events.append(event)


class _Metrics:
    def increment(self, name: str, *, labels: dict[str, str]) -> None:
        return None


class _Alerts:
    def emit(self, alert: object) -> None:
        return None


@pytest.fixture
def api():
    audit = _Audit()
    runtime = KnowledgeArchiveRuntime(
        repository=_Repository(), audit=audit, metrics=_Metrics(), alerts=_Alerts(),
        clock=lambda: NOW, sunset_at_ns=SUNSET_NS, daily_threshold=100,
    )
    current: list[object | None] = [None]
    app = FastAPI()
    app.include_router(router)

    @app.middleware("http")
    async def inject(request: Request, call_next):
        request.state.trusted_principal = current[0]
        return await call_next(request)

    app.state.knowledge_archive = runtime
    with TestClient(app) as client:
        yield client, audit, current


def _response_shape(response) -> tuple[int, str, str]:
    return response.status_code, response.text, response.headers.get("deprecation", "")


def _actors(audit: _Audit) -> list[str]:
    return [str(getattr(event, "actor_id", "?")) for event in audit.events]


def test_issued_principal_is_served_unchanged(api) -> None:
    client, audit, current = api
    current[0] = _issued()
    for path in PATHS:
        assert client.get(path).status_code == 200
    assert set(_actors(audit)) == {"synthetic-reader"}


@pytest.mark.parametrize("path", PATHS)
def test_hand_built_principal_gets_the_same_response_as_no_principal(api, path) -> None:
    client, audit, current = api
    current[0] = None
    anonymous = _response_shape(client.get(path))
    assert anonymous[0] in (401, 404)
    current[0] = _hand_built()  # right org and a read role: allowed if it were trusted
    assert _response_shape(client.get(path)) == anonymous
    assert "synthetic-reader" not in _actors(audit)  # the forged id is never recorded


@pytest.mark.parametrize("path", PATHS)
def test_tampered_issued_principal_is_denied(api, path) -> None:
    client, audit, current = api
    current[0] = None
    anonymous = _response_shape(client.get(path))
    weak = _issued(("viewer",))  # no read role
    object.__setattr__(weak, "roles", ("audit",))  # escalate after issuance
    current[0] = weak
    assert _response_shape(client.get(path)) == anonymous
    moved = _issued()
    object.__setattr__(moved, "project_id", "synthetic-other-org")
    current[0] = moved
    assert _response_shape(client.get(path)) == anonymous
    assert "synthetic-reader" not in _actors(audit)


def test_forged_principal_is_recorded_as_anonymous(api) -> None:
    client, audit, current = api
    current[0] = _hand_built()
    client.get(PATHS[0])
    assert audit.events and set(_actors(audit)) == {"anonymous"}
