from __future__ import annotations

from collections.abc import Iterable

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from leviathan_api.routers.mt_export_build_status import router
from leviathan_core.mt_export_bridge_build_view import (
    BuildEventV1,
    BuildSeverityV1,
    BuildStatusV1,
)
from leviathan_core.security.authz_models import (
    _VERIFIER_MARKER,
    PrincipalV1,
    TrustedPrincipalAdapterV1,
)

PROJECT_ID = "project-alpha"
EXPORT_JOB_ID = "job-42"
SECRET_LOG = "synthetic-private-build-output"


def _principal():
    claims = PrincipalV1(
        principal_id="operator-1",
        project_id=PROJECT_ID,
        roles=("operator",),
        env="development",
    )
    return TrustedPrincipalAdapterV1.from_verified_claims(claims, verifier_marker=_VERIFIER_MARKER)


def _event(status: BuildStatusV1, *, line: int, message: str = SECRET_LOG) -> BuildEventV1:
    return BuildEventV1(
        status=status, severity=BuildSeverityV1.INFO, source_line=line, message=message
    )


class FakeBuildEventReadPort:
    def __init__(self, events: Iterable[BuildEventV1] = ()) -> None:
        self.events = events
        self.calls: list[tuple[str, str, int]] = []

    def read_build_events(
        self, project_id: str, export_job_id: str, *, limit: int
    ) -> Iterable[BuildEventV1]:
        self.calls.append((project_id, export_job_id, limit))
        return self.events


def _client(port: object | None = None, *, authenticate: bool = True) -> TestClient:
    app = FastAPI()
    app.include_router(router)
    if port is not None:
        app.state.build_event_read_port = port
    if authenticate:
        principal = _principal()

        @app.middleware("http")
        async def add_trusted_principal(request: Request, call_next):
            request.state.trusted_principal = principal
            return await call_next(request)

    return TestClient(app)


def test_projects_ordered_status_and_redacted_logs_for_trusted_project() -> None:
    port = FakeBuildEventReadPort(
        (_event(BuildStatusV1.GENERATING, line=11), _event(BuildStatusV1.COMPILING, line=12))
    )
    with _client(port) as client:
        response = client.get(f"/v1/mt-export/builds/{EXPORT_JOB_ID}")

    assert response.status_code == 200
    assert response.json() == {
        "export_job_id": EXPORT_JOB_ID,
        "status": "Compiling",
        "logs": [
            {"severity": "Info", "source_line": 11, "message": "[REDACTED]"},
            {"severity": "Info", "source_line": 12, "message": "[REDACTED]"},
        ],
        "live_enabled": False,
    }
    assert port.calls == [(PROJECT_ID, EXPORT_JOB_ID, 50)]
    assert SECRET_LOG not in response.text


def test_absent_port_returns_fixed_content_free_503() -> None:
    with _client() as client:
        response = client.get(f"/v1/mt-export/builds/{EXPORT_JOB_ID}")

    assert response.status_code == 503
    assert response.json() == {"detail": "BUILD_STATUS_UNAVAILABLE"}


def test_authentication_is_required_before_port_access() -> None:
    port = FakeBuildEventReadPort(())
    with _client(port, authenticate=False) as client:
        response = client.get(f"/v1/mt-export/builds/{EXPORT_JOB_ID}")

    assert response.status_code == 401
    assert response.json() == {"detail": "PRINCIPAL_REQUIRED"}
    assert port.calls == []


@pytest.mark.parametrize("job_id", ["bad.id", "UpperCase", "with space", ""])
def test_invalid_job_id_is_rejected_without_calling_port(job_id: str) -> None:
    port = FakeBuildEventReadPort(())
    with _client(port) as client:
        response = client.get(f"/v1/mt-export/builds/{job_id}")

    assert response.status_code == 400
    assert response.json() == {"detail": "INVALID_EXPORT_JOB_ID"}
    assert port.calls == []
    assert "bad.id" not in response.text


@pytest.mark.parametrize("query", ["?limit=0", "?limit=101", "?limit=1.0", "?limit=1&limit=2"])
def test_invalid_limit_is_rejected_with_fixed_error(query: str) -> None:
    port = FakeBuildEventReadPort(())
    with _client(port) as client:
        response = client.get(f"/v1/mt-export/builds/{EXPORT_JOB_ID}{query}")

    assert response.status_code == 422
    assert response.json() == {"detail": "INVALID_LIMIT"}
    assert port.calls == []


def test_unknown_query_fields_are_rejected_without_echo() -> None:
    marker = "caller-free-text-marker"
    with _client(FakeBuildEventReadPort(())) as client:
        response = client.get(f"/v1/mt-export/builds/{EXPORT_JOB_ID}?{marker}=value")

    assert response.status_code == 422
    assert response.json() == {"detail": "INVALID_QUERY"}
    assert marker not in response.text


def test_over_limit_source_is_bounded_to_limit_plus_one_and_fails_closed() -> None:
    consumed: list[int] = []

    def event_stream() -> Iterable[BuildEventV1]:
        for index, status in enumerate(
            (
                BuildStatusV1.GENERATING,
                BuildStatusV1.COMPILING,
                BuildStatusV1.PACKAGING,
                BuildStatusV1.READY,
            ),
            start=1,
        ):
            consumed.append(index)
            yield _event(status, line=index)

    port = FakeBuildEventReadPort(event_stream())
    with _client(port) as client:
        response = client.get(f"/v1/mt-export/builds/{EXPORT_JOB_ID}?limit=2")

    assert response.status_code == 503
    assert response.json() == {"detail": "BUILD_STATUS_UNAVAILABLE"}
    assert consumed == [1, 2, 3]
    assert port.calls == [(PROJECT_ID, EXPORT_JOB_ID, 2)]


def test_port_failure_is_content_free_and_does_not_echo_exception() -> None:
    marker = "do-not-return-this-error"

    class BrokenPort:
        def read_build_events(
            self, project_id: str, export_job_id: str, *, limit: int
        ) -> Iterable[BuildEventV1]:
            raise RuntimeError(marker)

    with _client(BrokenPort()) as client:
        response = client.get(f"/v1/mt-export/builds/{EXPORT_JOB_ID}")

    assert response.status_code == 503
    assert response.json() == {"detail": "BUILD_STATUS_UNAVAILABLE"}
    assert marker not in response.text


def test_non_get_method_has_no_write_route() -> None:
    with _client(FakeBuildEventReadPort(())) as client:
        response = client.post(f"/v1/mt-export/builds/{EXPORT_JOB_ID}")

    assert response.status_code == 405
    assert response.json() == {"detail": "Method Not Allowed"}


@pytest.mark.parametrize(
    ("method", "path", "port", "authenticate", "status_code"),
    [
        ("GET", f"/v1/mt-export/builds/{EXPORT_JOB_ID}", FakeBuildEventReadPort(()), True, 200),
        ("GET", f"/v1/mt-export/builds/{EXPORT_JOB_ID}", None, True, 503),
        ("GET", f"/v1/mt-export/builds/{EXPORT_JOB_ID}", FakeBuildEventReadPort(()), False, 401),
        ("GET", "/v1/mt-export/builds/bad.id", FakeBuildEventReadPort(()), True, 400),
        (
            "GET",
            f"/v1/mt-export/builds/{EXPORT_JOB_ID}?unexpected=1",
            FakeBuildEventReadPort(()),
            True,
            422,
        ),
        ("POST", f"/v1/mt-export/builds/{EXPORT_JOB_ID}", FakeBuildEventReadPort(()), True, 405),
        ("TRACE", f"/v1/mt-export/builds/{EXPORT_JOB_ID}", FakeBuildEventReadPort(()), True, 405),
        (
            "PROPFIND",
            f"/v1/mt-export/builds/{EXPORT_JOB_ID}",
            FakeBuildEventReadPort(()),
            True,
            405,
        ),
    ],
)
def test_every_route_response_is_no_store(
    method: str, path: str, port: object | None, authenticate: bool, status_code: int
) -> None:
    with _client(port, authenticate=authenticate) as client:
        response = client.request(method, path)

    assert response.status_code == status_code
    assert response.headers["cache-control"] == "no-store"
