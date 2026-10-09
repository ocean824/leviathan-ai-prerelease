"""Worker tests for the principal-scoped MT agent health status router."""

from __future__ import annotations

from dataclasses import dataclass

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from leviathan_api.auth import (
    OperatorPrincipalMiddleware,
    make_local_operator_profile,
)
from leviathan_api.routers.mt_export_agent_health_status import (
    AgentHealthStatusReadPort,
    create_agent_health_status_router,
)
from leviathan_core.mt_export_agent_health import (
    AgentHealthPolicyV1,
    AgentHeartbeatV1,
    AgentReportedStatusV1,
    MtPlatformV1,
    make_agent_health_policy,
)

PORT = 49329
BASE_URL = f"http://127.0.0.1:{PORT}"
CAPABILITY = "ab" * 32
GOOD_HEADERS = {"x-leviathan-capability": CAPABILITY}
NOW = 1_800_000_000_000_000_000
MIN_DISK = 1_000_000
MIN_BUILD = 100
PATH = "/mt-export/agents/agent-7/health"


@dataclass
class _Clock:
    value: object = NOW
    calls: int = 0

    def now_utc_ns(self) -> int:
        self.calls += 1
        return self.value  # type: ignore[return-value]


class _ReadPort:
    def __init__(
        self,
        snapshot: tuple[AgentHeartbeatV1 | None, AgentHealthPolicyV1] | None,
    ) -> None:
        self.snapshot = snapshot
        self.calls: list[tuple[str, str, str]] = []
        self.failure: Exception | None = None

    def read_snapshot(
        self, *, principal_id: str, project_id: str, agent_ref: str
    ) -> tuple[AgentHeartbeatV1 | None, AgentHealthPolicyV1] | None:
        self.calls.append((principal_id, project_id, agent_ref))
        if self.failure is not None:
            raise self.failure
        return self.snapshot


def _policy() -> AgentHealthPolicyV1:
    return make_agent_health_policy(
        expected_platform=MtPlatformV1.MT5,
        min_terminal_build=MIN_BUILD,
        min_free_disk_bytes=MIN_DISK,
        max_clock_skew_ns=2_000_000_000,
        required_capabilities=("compile", "trade"),
    )


def _heartbeat(**changes: object) -> AgentHeartbeatV1:
    values: dict[str, object] = {
        "heartbeat_utc_ns": NOW,
        "free_disk_bytes": MIN_DISK,
        "platform": MtPlatformV1.MT5,
        "terminal_build": MIN_BUILD,
        "status": AgentReportedStatusV1.OK,
        "capabilities": ("compile", "trade"),
    }
    values.update(changes)
    return AgentHeartbeatV1(**values)  # type: ignore[arg-type]


def _app(
    *,
    enabled: bool = True,
    read_port: AgentHealthStatusReadPort | None = None,
    clock: _Clock | None = None,
    authenticated: bool = True,
) -> FastAPI:
    app = FastAPI()
    app.include_router(
        create_agent_health_status_router(
            enabled=enabled,
            read_port=read_port,
            clock=clock,
        )
    )
    if authenticated:
        app.add_middleware(
            OperatorPrincipalMiddleware,
            capability=CAPABILITY,
            port=PORT,
            profile=make_local_operator_profile(
                principal_id="local-operator",
                project_id="paper-project",
                env="paper",
            ),
        )
    return app


def test_router_is_disabled_by_default_and_disabled_or_portless_are_fixed_503() -> None:
    port = _ReadPort((_heartbeat(), _policy()))
    clock = _Clock()
    default_app = FastAPI()
    default_app.include_router(create_agent_health_status_router())
    for app in (
        default_app,
        _app(enabled=False, read_port=port, clock=clock),
        _app(enabled=True, read_port=None, clock=clock),
        _app(enabled=True, read_port=port, clock=None),
    ):
        with TestClient(app, base_url=BASE_URL) as client:
            response = client.get(PATH, headers=GOOD_HEADERS)
        assert response.status_code == 503
        assert response.json() == {"error": {"code": "SERVICE_UNAVAILABLE"}}
        assert response.headers["cache-control"] == "no-store"
    assert port.calls == []
    assert clock.calls == 0


def test_healthy_response_is_principal_scoped_fresh_and_allowlisted() -> None:
    port = _ReadPort((_heartbeat(), _policy()))
    clock = _Clock(NOW)
    with TestClient(_app(read_port=port, clock=clock), base_url=BASE_URL) as client:
        response = client.get(PATH, headers=GOOD_HEADERS)

    assert response.status_code == 200
    assert response.json() == {
        "state": "HEALTHY",
        "reason_codes": [],
        "observed_at_utc_ns": NOW,
        "heartbeat_age_ns": 0,
        "activation_permitted": False,
    }
    assert set(response.json()) == {
        "state",
        "reason_codes",
        "observed_at_utc_ns",
        "heartbeat_age_ns",
        "activation_permitted",
    }
    assert response.headers["cache-control"] == "no-store"
    assert port.calls == [("local-operator", "paper-project", "agent-7")]
    assert clock.calls == 1


@pytest.mark.parametrize(
    ("heartbeat", "reason"),
    [
        (None, "HEARTBEAT_MISSING"),
        (_heartbeat(heartbeat_utc_ns=NOW - 10_000_000_001), "HEARTBEAT_STALE"),
        (_heartbeat(heartbeat_utc_ns=NOW + 2_000_000_001), "CLOCK_SKEW"),
        (_heartbeat(status=AgentReportedStatusV1.DEGRADED), "STATUS_DEGRADED"),
    ],
)
def test_unhealthy_kernel_result_is_exposed_without_activation(
    heartbeat: AgentHeartbeatV1 | None, reason: str
) -> None:
    port = _ReadPort((heartbeat, _policy()))
    clock = _Clock(NOW)
    with TestClient(_app(read_port=port, clock=clock), base_url=BASE_URL) as client:
        response = client.get(PATH, headers=GOOD_HEADERS)

    assert response.status_code == 200
    assert response.json()["state"] == "UNHEALTHY"
    assert reason in response.json()["reason_codes"]
    assert response.json()["activation_permitted"] is False
    assert clock.calls == 1


def test_untrusted_principal_invalid_path_and_query_never_read_snapshot() -> None:
    port = _ReadPort((_heartbeat(), _policy()))
    clock = _Clock(NOW)
    with TestClient(
        _app(read_port=port, clock=clock, authenticated=False), base_url=BASE_URL
    ) as client:
        unauthenticated = client.get(PATH)
    with TestClient(_app(read_port=port, clock=clock), base_url=BASE_URL) as client:
        invalid_ref = client.get("/mt-export/agents/prøbe/health", headers=GOOD_HEADERS)
        invalid_query = client.get(PATH + "?now=" + str(NOW), headers=GOOD_HEADERS)

    assert unauthenticated.status_code == 401
    assert unauthenticated.json() == {"error": {"code": "AUTH_REQUIRED"}}
    for response in (invalid_ref, invalid_query):
        assert response.status_code == 400
        assert response.json() == {"error": {"code": "INVALID_REQUEST"}}
    assert port.calls == []
    assert clock.calls == 0


def test_missing_snapshot_and_port_exception_are_content_free() -> None:
    canary = "secret canary must never appear"
    missing = _ReadPort(None)
    failed = _ReadPort((_heartbeat(), _policy()))
    failed.failure = RuntimeError(canary)
    with TestClient(_app(read_port=missing, clock=_Clock()), base_url=BASE_URL) as client:
        missing_response = client.get(PATH, headers=GOOD_HEADERS)
    with TestClient(_app(read_port=failed, clock=_Clock()), base_url=BASE_URL) as client:
        failed_response = client.get(PATH, headers=GOOD_HEADERS)

    assert missing_response.status_code == 404
    assert missing_response.json() == {"error": {"code": "HEALTH_SNAPSHOT_NOT_FOUND"}}
    assert failed_response.status_code == 503
    assert failed_response.json() == {"error": {"code": "HEALTH_STATUS_UNAVAILABLE"}}
    assert canary not in failed_response.text


def test_invalid_snapshot_and_unissued_policy_fail_closed() -> None:
    class _MalformedPort:
        def read_snapshot(self, **kwargs: str) -> object:
            return ["not a typed snapshot"]

    direct_policy = AgentHealthPolicyV1(
        expected_platform=MtPlatformV1.MT5,
        min_terminal_build=MIN_BUILD,
        min_free_disk_bytes=MIN_DISK,
        max_clock_skew_ns=2_000_000_000,
        required_capabilities=("compile", "trade"),
        allowed_builds=None,
    )
    for port in (
        _MalformedPort(),
        _ReadPort((_heartbeat(), direct_policy)),
    ):
        with TestClient(_app(read_port=port, clock=_Clock()), base_url=BASE_URL) as client:
            response = client.get(PATH, headers=GOOD_HEADERS)
        assert response.status_code == 503
        assert response.json() == {"error": {"code": "HEALTH_STATUS_UNAVAILABLE"}}


def test_router_declares_only_get_and_does_not_register_itself_elsewhere() -> None:
    router = create_agent_health_status_router()

    assert len(router.routes) == 1
    assert router.routes[0].path == "/mt-export/agents/{agent_ref}/health"
    assert router.routes[0].methods == {"GET"}
    app = FastAPI()
    app.include_router(router)
    with TestClient(app, base_url=BASE_URL) as client:
        responses = [
            client.request(method, PATH, content="METHOD_CANARY")
            for method in ("POST", "TRACE", "CONNECT", "PROPFIND", "XYRA")
        ]

    for response in responses:
        assert response.status_code == 405
        assert response.json() == {"error": {"code": "METHOD_NOT_ALLOWED"}}
        assert response.headers["cache-control"] == "no-store"
        assert "METHOD_CANARY" not in response.text
