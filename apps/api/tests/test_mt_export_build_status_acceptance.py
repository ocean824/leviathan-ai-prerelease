"""Independent fake-first acceptance for the MT export build-status router."""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Iterable

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from leviathan_api.auth import OperatorPrincipalMiddleware, make_local_operator_profile
from leviathan_api.routers import mt_export_build_status as build_status_api
from leviathan_core.mt_export_bridge_build_view import (
    BuildEventV1,
    BuildSeverityV1,
    BuildStatusV1,
    project_build_events,
)
from leviathan_core.security.authz_models import TrustedPrincipalV1, require_trusted_principal

PORT = 43181
BASE_URL = f"http://127.0.0.1:{PORT}"
CAPABILITY = "e" * 64
PROJECT_ID = "synthetic-project-003"
EXPORT_JOB_ID = "synthetic-job-017"
RAW_EVENT_TEXT = "synthetic-private-build-output-keep-out-of-response"
CALLER_TEXT = "caller-free-text-sentinel-avoid-recording"


def _events() -> tuple[BuildEventV1, ...]:
    return (
        BuildEventV1(
            status=BuildStatusV1.GENERATING,
            severity=BuildSeverityV1.INFO,
            source_line=17,
            message=RAW_EVENT_TEXT + "-generating",
        ),
        BuildEventV1(
            status=BuildStatusV1.COMPILING,
            severity=BuildSeverityV1.WARNING,
            source_line=29,
            message=RAW_EVENT_TEXT + "-compiling",
        ),
        BuildEventV1(
            status=BuildStatusV1.PACKAGING,
            severity=BuildSeverityV1.ERROR,
            source_line=41,
            message=RAW_EVENT_TEXT + "-packaging",
        ),
    )


class FakeBuildEventPort:
    def __init__(self, events: Iterable[BuildEventV1]) -> None:
        self.events = events
        self.calls: list[tuple[str, str, int]] = []

    def read_build_events(
        self, project_id: str, export_job_id: str, *, limit: int
    ) -> Iterable[BuildEventV1]:
        self.calls.append((project_id, export_job_id, limit))
        return self.events


def _app(port: object | None = None) -> FastAPI:
    app = FastAPI()
    app.include_router(build_status_api.router)
    if port is not None:
        app.state.build_event_read_port = port
    profile = make_local_operator_profile(
        principal_id="synthetic-operator-011",
        project_id=PROJECT_ID,
        env="test",
    )
    app.add_middleware(
        OperatorPrincipalMiddleware,
        capability=CAPABILITY,
        port=PORT,
        profile=profile,
    )
    return app


def _headers(*, capability: str = CAPABILITY) -> dict[str, str]:
    return {"X-Leviathan-Capability": capability}


def _path(export_job_id: str = EXPORT_JOB_ID) -> str:
    return f"/v1/mt-export/builds/{export_job_id}"


def test_absent_port_returns_fixed_content_free_503() -> None:
    app = _app()
    with TestClient(app, base_url=BASE_URL) as client:
        response = client.get(_path(), headers=_headers())

    assert response.status_code == 503
    assert response.json() == {"detail": "BUILD_STATUS_UNAVAILABLE"}
    assert RAW_EVENT_TEXT not in response.text
    assert PROJECT_ID not in response.text


def test_cache_control_no_store_covers_success_client_errors_and_unavailable() -> None:
    fake = FakeBuildEventPort(_events())
    app = _app(fake)
    with TestClient(app, base_url=BASE_URL) as client:
        success = client.get(_path(), headers=_headers())
        bad_query = client.get(_path() + "?limit=0", headers=_headers())
        bad_id = client.get(_path("INVALID.ID"), headers=_headers())
        unauthorized = client.get(_path())

    absent_port_app = _app()
    with TestClient(absent_port_app, base_url=BASE_URL) as client:
        unavailable = client.get(_path(), headers=_headers())

    responses = (success, bad_query, bad_id, unauthorized, unavailable)
    assert tuple(response.status_code for response in responses) == (200, 422, 400, 401, 503)
    assert all(response.headers.get("cache-control") == "no-store" for response in responses)


def test_fake_port_is_project_scoped_and_router_matches_projection_exactly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events = _events()
    fake = FakeBuildEventPort(events)
    app = _app(fake)
    verified: list[TrustedPrincipalV1] = []
    real_require = require_trusted_principal

    def record_trusted_principal(value: object) -> TrustedPrincipalV1:
        principal = real_require(value)
        verified.append(principal)
        return principal

    monkeypatch.setattr(build_status_api, "require_trusted_principal", record_trusted_principal)

    with TestClient(app, base_url=BASE_URL) as client:
        response = client.get(
            _path(),
            headers={**_headers(), "X-Project-ID": "caller-forged-project"},
        )

    expected = project_build_events(events)
    assert response.status_code == 200
    assert response.json() == {
        "export_job_id": EXPORT_JOB_ID,
        "status": expected.status.value,
        "logs": [entry.model_dump(mode="json") for entry in expected.logs],
        "live_enabled": False,
    }
    assert fake.calls == [(PROJECT_ID, EXPORT_JOB_ID, build_status_api.DEFAULT_EVENT_LIMIT)]
    assert len(verified) == 1
    assert require_trusted_principal(verified[0]) is verified[0]


def test_principal_is_required_and_untrusted_request_values_never_scope_the_port() -> None:
    fake = FakeBuildEventPort(_events())
    app = _app(fake)
    with TestClient(app, base_url=BASE_URL) as client:
        response = client.get(
            _path(),
            headers={
                "X-Project-ID": "other-project",
                "X-Role": "admin",
                "Cookie": "role=admin; project_id=other-project",
            },
        )

    assert response.status_code == 401
    assert response.json() == {"detail": "PRINCIPAL_REQUIRED"}
    assert fake.calls == []


def test_projection_redacts_event_messages_and_lesson_19_text_and_hashes_do_not_escape(
    caplog: pytest.LogCaptureFixture,
) -> None:
    fake = FakeBuildEventPort(_events())
    app = _app(fake)
    caplog.set_level(logging.DEBUG, logger="leviathan_api")
    caller_hash = hashlib.sha256(CALLER_TEXT.encode("utf-8")).hexdigest()
    raw_event_hash = hashlib.sha256(RAW_EVENT_TEXT.encode("utf-8")).hexdigest()

    with TestClient(app, base_url=BASE_URL) as client:
        response = client.get(_path(), headers=_headers())

    application_logs = "\n".join(
        record.getMessage()
        for record in caplog.records
        if record.name == "leviathan_api" or record.name.startswith("leviathan_api.")
    )
    exposed = response.text + application_logs
    assert response.status_code == 200
    assert RAW_EVENT_TEXT not in exposed
    assert CALLER_TEXT not in exposed
    assert raw_event_hash not in exposed
    assert caller_hash not in exposed
    assert all(log["message"] == "[REDACTED]" for log in response.json()["logs"])


def test_unknown_query_values_are_rejected_without_echo_or_recording(
    caplog: pytest.LogCaptureFixture,
) -> None:
    fake = FakeBuildEventPort(_events())
    app = _app(fake)
    caplog.set_level(logging.DEBUG, logger="leviathan_api")
    caller_hash = hashlib.sha256(CALLER_TEXT.encode("utf-8")).hexdigest()

    with TestClient(app, base_url=BASE_URL) as client:
        response = client.get(_path() + f"?note={CALLER_TEXT}", headers=_headers())

    application_logs = "\n".join(
        record.getMessage()
        for record in caplog.records
        if record.name == "leviathan_api" or record.name.startswith("leviathan_api.")
    )
    exposed = response.text + application_logs
    assert response.status_code == 422
    assert response.json() == {"detail": "INVALID_QUERY"}
    assert CALLER_TEXT not in exposed
    assert caller_hash not in exposed
    assert fake.calls == []


def test_missing_wrong_launch_and_tampered_capabilities_give_same_401() -> None:
    app = _app(FakeBuildEventPort(_events()))
    with TestClient(app, base_url=BASE_URL) as client:
        responses = (
            client.get(_path()),
            client.get(_path(), headers=_headers(capability="not-a-capability")),
            client.get(_path(), headers=_headers(capability="f" * 64)),
            client.get(_path(), headers=_headers(capability="d" * 64)),
        )

    assert all(response.status_code == 401 for response in responses)
    assert {response.text for response in responses} == {'{"detail":"PRINCIPAL_REQUIRED"}'}


@pytest.mark.parametrize("method", ("POST", "PUT", "PATCH", "DELETE", "TRACE", "PROPFIND"))
def test_route_is_get_only(method: str) -> None:
    fake = FakeBuildEventPort(_events())
    app = _app(fake)
    with TestClient(app, base_url=BASE_URL) as client:
        response = client.request(method, _path(), headers=_headers(), json={"status": "READY"})

    assert response.status_code == 405
    assert response.headers.get("cache-control") == "no-store"
    assert fake.calls == []


@pytest.mark.parametrize("limit", ("0", "101", "999", "-1", "1.5", "1e2", "bad-limit"))
def test_invalid_or_out_of_range_limit_has_fixed_422(limit: str) -> None:
    fake = FakeBuildEventPort(_events())
    app = _app(fake)
    with TestClient(app, base_url=BASE_URL) as client:
        response = client.get(_path() + f"?limit={limit}", headers=_headers())

    assert response.status_code == 422
    assert response.json() == {"detail": "INVALID_LIMIT"}
    assert fake.calls == []


def test_duplicate_limit_and_invalid_job_id_are_content_free() -> None:
    fake = FakeBuildEventPort(_events())
    app = _app(fake)
    with TestClient(app, base_url=BASE_URL) as client:
        duplicate_limit = client.get(_path() + "?limit=2&limit=3", headers=_headers())
        invalid_id = client.get(_path("UPPERCASE-SENTINEL"), headers=_headers())

    assert duplicate_limit.status_code == 422
    assert duplicate_limit.json() == {"detail": "INVALID_LIMIT"}
    assert invalid_id.status_code == 400
    assert invalid_id.json() == {"detail": "INVALID_EXPORT_JOB_ID"}
    assert "UPPERCASE-SENTINEL" not in duplicate_limit.text + invalid_id.text
    assert fake.calls == []


def test_port_exception_and_overflow_return_same_fixed_503(
    caplog: pytest.LogCaptureFixture,
) -> None:
    class RaisingPort:
        def read_build_events(
            self, project_id: str, export_job_id: str, *, limit: int
        ) -> Iterable[BuildEventV1]:
            raise RuntimeError("synthetic-port-secret-like-failure")

    class LongPort:
        pulled = 0

        def read_build_events(
            self, project_id: str, export_job_id: str, *, limit: int
        ) -> Iterable[BuildEventV1]:
            def generate() -> Iterable[BuildEventV1]:
                for event in _events():
                    self.pulled += 1
                    yield event
                    if self.pulled == 3:
                        break

            return generate()

    app = _app(RaisingPort())
    overflow_port = LongPort()
    app_overflow = _app(overflow_port)
    caplog.set_level(logging.DEBUG, logger="leviathan_api")

    with TestClient(app, base_url=BASE_URL) as client:
        upstream_failure = client.get(_path(), headers=_headers())
    with TestClient(app_overflow, base_url=BASE_URL) as client:
        overflow = client.get(_path() + "?limit=2", headers=_headers())

    assert upstream_failure.status_code == overflow.status_code == 503
    assert upstream_failure.text == overflow.text == '{"detail":"BUILD_STATUS_UNAVAILABLE"}'
    assert "synthetic-port-secret-like-failure" not in upstream_failure.text
    application_logs = "\n".join(
        record.getMessage()
        for record in caplog.records
        if record.name == "leviathan_api" or record.name.startswith("leviathan_api.")
    )
    assert "synthetic-port-secret-like-failure" not in application_logs
    assert CALLER_TEXT not in application_logs
    assert hashlib.sha256(CALLER_TEXT.encode("utf-8")).hexdigest() not in application_logs
    assert overflow_port.pulled == 3


def test_default_and_requested_limits_are_forwarded_exactly_to_fake_port() -> None:
    events = _events()[:2]
    fake = FakeBuildEventPort(events)
    app = _app(fake)
    with TestClient(app, base_url=BASE_URL) as client:
        response = client.get(_path() + "?limit=2", headers=_headers())

    assert response.status_code == 200
    assert fake.calls == [(PROJECT_ID, EXPORT_JOB_ID, 2)]
