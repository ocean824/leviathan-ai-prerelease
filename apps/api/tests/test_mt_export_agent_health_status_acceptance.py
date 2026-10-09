"""Independent boundary tests for the MT export agent-health read router."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from leviathan_api.auth import (
    LocalOperatorProfileV1,
    OperatorPrincipalMiddleware,
    make_local_operator_profile,
)
from leviathan_api.routers.mt_export_agent_health_status import (
    create_agent_health_status_router,
)
from leviathan_core.mt_export_agent_health import (
    AgentHealthPolicyV1,
    AgentHealthReasonV1,
    AgentHealthStateV1,
    AgentHeartbeatV1,
    MtPlatformV1,
    make_agent_health_policy,
)

PORT = 43862
BASE_URL = f"http://127.0.0.1:{PORT}"
CAPABILITY = "c" * 64
AGENT_REF = "agent-accepted-17"
SECRET_CANARY = "AGENT_HEALTH_SYNTHETIC_SECRET_CANARY_91b3"
NOW_NS = 9_000_000_000_000


class _Clock:
    def __init__(self, now_ns: int = NOW_NS) -> None:
        self.now_ns = now_ns
        self.calls = 0

    def now_utc_ns(self) -> int:
        self.calls += 1
        return self.now_ns


def _profile(
    *, principal_id: str = "operator-health", project_id: str = "project-health"
) -> LocalOperatorProfileV1:
    return make_local_operator_profile(principal_id=principal_id, project_id=project_id, env="test")


def _policy() -> AgentHealthPolicyV1:
    return make_agent_health_policy(
        expected_platform=MtPlatformV1.MT5,
        min_terminal_build=100,
        min_free_disk_bytes=1_000,
        max_clock_skew_ns=0,
        required_capabilities=("health.read",),
        allowed_builds=(100, 101),
    )


def _heartbeat(
    *,
    timestamp: object = NOW_NS,
    platform: object = MtPlatformV1.MT5,
    terminal_build: object = 100,
    free_disk_bytes: object = 1_000_000,
    status: object = "OK",
    capabilities: object = ("health.read",),
) -> AgentHeartbeatV1:
    return AgentHeartbeatV1(
        heartbeat_utc_ns=timestamp,
        free_disk_bytes=free_disk_bytes,
        platform=platform,
        terminal_build=terminal_build,
        status=status,
        capabilities=capabilities,
    )


class _ReadPort:
    def __init__(
        self,
        snapshots: dict[
            tuple[str, str, str], tuple[AgentHeartbeatV1 | None, AgentHealthPolicyV1] | None
        ]
        | None = None,
        *,
        error: Exception | None = None,
    ) -> None:
        self.snapshots = {} if snapshots is None else snapshots
        self.error = error
        self.calls: list[tuple[str, str, str]] = []

    def read_snapshot(
        self, *, principal_id: str, project_id: str, agent_ref: str
    ) -> tuple[AgentHeartbeatV1 | None, AgentHealthPolicyV1] | None:
        self.calls.append((principal_id, project_id, agent_ref))
        if self.error is not None:
            raise self.error
        return self.snapshots.get((principal_id, project_id, agent_ref))


def _client(
    *,
    enabled: bool = True,
    read_port: object | None,
    clock: object | None,
    profile: LocalOperatorProfileV1 | None = None,
) -> TestClient:
    app = FastAPI()
    app.include_router(
        create_agent_health_status_router(enabled=enabled, read_port=read_port, clock=clock)
    )
    if profile is not None:
        app.add_middleware(
            OperatorPrincipalMiddleware,
            capability=CAPABILITY,
            port=PORT,
            profile=profile,
        )
    return TestClient(app, base_url=BASE_URL)


def _headers() -> dict[str, str]:
    return {"X-Leviathan-Capability": CAPABILITY}


def _path(agent_ref: str = AGENT_REF) -> str:
    return f"/mt-export/agents/{agent_ref}/health"


def _assert_no_store(response: Any) -> None:
    assert "no-store" in response.headers.get("cache-control", "").lower()


def test_router_defaults_to_disabled_and_returns_fixed_503_without_reading() -> None:
    port = _ReadPort()
    client = _client(enabled=False, read_port=port, clock=_Clock(), profile=_profile())
    with client:
        response = client.get(_path(), headers=_headers())

    assert response.status_code == 503
    assert response.json() == {"error": {"code": "SERVICE_UNAVAILABLE"}}
    assert port.calls == []
    _assert_no_store(response)


@pytest.mark.parametrize(
    ("read_port", "clock"),
    ((None, _Clock()), (_ReadPort(), None)),
    ids=("missing-port", "missing-clock"),
)
def test_enabled_but_portless_or_clockless_is_the_same_fixed_503(
    read_port: object | None, clock: object | None
) -> None:
    client = _client(enabled=True, read_port=read_port, clock=clock, profile=_profile())
    with client:
        response = client.get(_path(), headers=_headers())

    assert response.status_code == 503
    assert response.json() == {"error": {"code": "SERVICE_UNAVAILABLE"}}
    if isinstance(read_port, _ReadPort):
        assert read_port.calls == []
    _assert_no_store(response)


def test_absent_and_forged_principals_have_identical_fixed_401() -> None:
    port = _ReadPort()
    absent = _client(read_port=port, clock=_Clock(), profile=None)

    class _ForgedPrincipal:
        def __init__(self, app: Any) -> None:
            self.app = app

        async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
            if scope.get("type") == "http":
                scope.setdefault("state", {})["trusted_principal"] = object()
            await self.app(scope, receive, send)

    forged_inner = FastAPI()
    forged_inner.include_router(
        create_agent_health_status_router(enabled=True, read_port=port, clock=_Clock())
    )
    forged = TestClient(_ForgedPrincipal(forged_inner), base_url=BASE_URL)

    with absent, forged:
        absent_response = absent.get(_path())
        forged_response = forged.get(_path())

    assert absent_response.status_code == forged_response.status_code == 401
    assert absent_response.json() == forged_response.json() == {"error": {"code": "AUTH_REQUIRED"}}
    assert port.calls == []
    _assert_no_store(absent_response)
    _assert_no_store(forged_response)


def test_valid_result_uses_injected_clock_and_allowlists_output_fields() -> None:
    profile = _profile()
    clock = _Clock()
    port = _ReadPort(
        {
            (profile.principal_id, profile.project_id, AGENT_REF): (
                _heartbeat(timestamp=NOW_NS - 1_000_000_000),
                _policy(),
            )
        }
    )
    with _client(read_port=port, clock=clock, profile=profile) as client:
        response = client.get(_path(), headers=_headers())

    assert response.status_code == 200
    body = response.json()
    assert set(body) == {
        "state",
        "reason_codes",
        "observed_at_utc_ns",
        "heartbeat_age_ns",
        "activation_permitted",
    }
    assert body == {
        "state": AgentHealthStateV1.HEALTHY.value,
        "reason_codes": [],
        "observed_at_utc_ns": NOW_NS,
        "heartbeat_age_ns": 1_000_000_000,
        "activation_permitted": False,
    }
    assert clock.calls == 1
    assert port.calls == [(profile.principal_id, profile.project_id, AGENT_REF)]
    assert AGENT_REF not in response.text
    assert profile.principal_id not in response.text
    assert profile.project_id not in response.text
    _assert_no_store(response)


@pytest.mark.parametrize(
    ("timestamp", "expected_reason"),
    (
        (NOW_NS - 10_000_000_001, AgentHealthReasonV1.HEARTBEAT_STALE.value),
        (NOW_NS + 1, AgentHealthReasonV1.CLOCK_SKEW.value),
    ),
    ids=("stale-by-injected-clock", "future-by-injected-clock"),
)
def test_freshness_uses_only_the_injected_clock(timestamp: int, expected_reason: str) -> None:
    profile = _profile()
    clock = _Clock(NOW_NS)
    port = _ReadPort(
        {
            (profile.principal_id, profile.project_id, AGENT_REF): (
                _heartbeat(timestamp=timestamp),
                _policy(),
            )
        }
    )
    with _client(read_port=port, clock=clock, profile=profile) as client:
        response = client.get(_path(), headers=_headers())

    assert response.status_code == 200
    body = response.json()
    assert body["state"] == AgentHealthStateV1.UNHEALTHY.value
    assert body["reason_codes"] == [expected_reason]
    assert body["observed_at_utc_ns"] == NOW_NS
    assert body["activation_permitted"] is False
    assert clock.calls == 1
    assert port.calls == [(profile.principal_id, profile.project_id, AGENT_REF)]
    _assert_no_store(response)


def test_exact_ten_second_age_is_still_fresh() -> None:
    profile = _profile()
    clock = _Clock(NOW_NS)
    port = _ReadPort(
        {
            (profile.principal_id, profile.project_id, AGENT_REF): (
                _heartbeat(timestamp=NOW_NS - 10_000_000_000),
                _policy(),
            )
        }
    )
    with _client(read_port=port, clock=clock, profile=profile) as client:
        response = client.get(_path(), headers=_headers())

    assert response.status_code == 200
    body = response.json()
    assert body["state"] == AgentHealthStateV1.HEALTHY.value
    assert body["reason_codes"] == []
    assert body["heartbeat_age_ns"] == 10_000_000_000
    assert body["observed_at_utc_ns"] == NOW_NS
    assert clock.calls == 1
    _assert_no_store(response)


def test_unhealthy_build_platform_and_reported_status_are_closed_reasons() -> None:
    profile = _profile()
    port = _ReadPort(
        {
            (profile.principal_id, profile.project_id, AGENT_REF): (
                _heartbeat(
                    platform="MT4",
                    terminal_build=99,
                    status="ERROR",
                ),
                _policy(),
            )
        }
    )
    with _client(read_port=port, clock=_Clock(), profile=profile) as client:
        response = client.get(_path(), headers=_headers())

    assert response.status_code == 200
    body = response.json()
    assert body["state"] == AgentHealthStateV1.UNHEALTHY.value
    assert set(body["reason_codes"]) == {
        AgentHealthReasonV1.BUILD_BELOW_MINIMUM.value,
        AgentHealthReasonV1.BUILD_NOT_ALLOWED.value,
        AgentHealthReasonV1.PLATFORM_INCOMPATIBLE.value,
        AgentHealthReasonV1.STATUS_ERROR.value,
    }
    assert SECRET_CANARY not in response.text
    assert "MT4" not in response.text
    assert set(body) == {
        "state",
        "reason_codes",
        "observed_at_utc_ns",
        "heartbeat_age_ns",
        "activation_permitted",
    }
    _assert_no_store(response)


def test_secret_shaped_heartbeat_value_is_replaced_by_a_closed_reason_code() -> None:
    profile = _profile()
    port = _ReadPort(
        {
            (profile.principal_id, profile.project_id, AGENT_REF): (
                _heartbeat(terminal_build=SECRET_CANARY),
                _policy(),
            )
        }
    )
    with _client(read_port=port, clock=_Clock(), profile=profile) as client:
        response = client.get(_path(), headers=_headers())

    assert response.status_code == 200
    body = response.json()
    assert set(body) == {
        "state",
        "reason_codes",
        "observed_at_utc_ns",
        "heartbeat_age_ns",
        "activation_permitted",
    }
    assert body["state"] == AgentHealthStateV1.UNHEALTHY.value
    assert AgentHealthReasonV1.BUILD_UNPARSABLE.value in body["reason_codes"]
    assert SECRET_CANARY not in response.text
    _assert_no_store(response)


def test_same_agent_reference_is_scoped_by_verified_principal_and_project() -> None:
    alpha = _profile(principal_id="operator-alpha", project_id="project-alpha")
    beta = _profile(principal_id="operator-beta", project_id="project-beta")
    port = _ReadPort(
        {
            (alpha.principal_id, alpha.project_id, AGENT_REF): (
                _heartbeat(timestamp=NOW_NS),
                _policy(),
            ),
            (beta.principal_id, beta.project_id, AGENT_REF): (
                _heartbeat(timestamp=NOW_NS - 10_000_000_001),
                _policy(),
            ),
        }
    )
    with _client(read_port=port, clock=_Clock(), profile=alpha) as alpha_client:
        alpha_response = alpha_client.get(_path(), headers=_headers())
    with _client(read_port=port, clock=_Clock(), profile=beta) as beta_client:
        beta_response = beta_client.get(_path(), headers=_headers())

    assert alpha_response.status_code == beta_response.status_code == 200
    assert alpha_response.json()["state"] == AgentHealthStateV1.HEALTHY.value
    assert beta_response.json()["state"] == AgentHealthStateV1.UNHEALTHY.value
    assert beta_response.json()["reason_codes"] == [AgentHealthReasonV1.HEARTBEAT_STALE.value]
    assert port.calls == [
        (alpha.principal_id, alpha.project_id, AGENT_REF),
        (beta.principal_id, beta.project_id, AGENT_REF),
    ]
    _assert_no_store(alpha_response)
    _assert_no_store(beta_response)


def test_missing_snapshot_and_port_failure_have_fixed_non_echoing_errors() -> None:
    profile = _profile()
    path = _path()
    missing_port = _ReadPort()
    failing_port = _ReadPort(error=RuntimeError(SECRET_CANARY))
    with _client(read_port=missing_port, clock=_Clock(), profile=profile) as client:
        missing = client.get(path, headers=_headers())
    with _client(read_port=failing_port, clock=_Clock(), profile=profile) as client:
        failed = client.get(path, headers=_headers())

    assert missing.status_code == 404
    assert missing.json() == {"error": {"code": "HEALTH_SNAPSHOT_NOT_FOUND"}}
    assert failed.status_code == 503
    assert failed.json() == {"error": {"code": "HEALTH_STATUS_UNAVAILABLE"}}
    assert SECRET_CANARY not in failed.text
    assert (
        missing_port.calls
        == failing_port.calls
        == [(profile.principal_id, profile.project_id, AGENT_REF)]
    )
    _assert_no_store(missing)
    _assert_no_store(failed)


def test_unissued_policy_is_a_fixed_unavailable_response() -> None:
    profile = _profile()
    unissued_policy = AgentHealthPolicyV1(
        expected_platform=MtPlatformV1.MT5,
        min_terminal_build=100,
        min_free_disk_bytes=1_000,
        max_clock_skew_ns=0,
        required_capabilities=("health.read",),
        allowed_builds=(100, 101),
    )
    port = _ReadPort(
        {
            (profile.principal_id, profile.project_id, AGENT_REF): (
                _heartbeat(),
                unissued_policy,
            )
        }
    )
    with _client(read_port=port, clock=_Clock(), profile=profile) as client:
        response = client.get(_path(), headers=_headers())

    assert response.status_code == 503
    assert response.json() == {"error": {"code": "HEALTH_STATUS_UNAVAILABLE"}}
    assert SECRET_CANARY not in response.text
    assert len(port.calls) == 1
    _assert_no_store(response)


def test_invalid_ref_and_query_inputs_are_rejected_without_echo() -> None:
    profile = _profile()
    port = _ReadPort()
    invalid_ref = "credential%3D" + SECRET_CANARY
    with _client(read_port=port, clock=_Clock(), profile=profile) as client:
        invalid_path = client.get(_path(invalid_ref), headers=_headers())
        query_input = client.get(_path() + "?credential=" + SECRET_CANARY, headers=_headers())

    assert invalid_path.status_code == 400
    assert invalid_path.json() == {"error": {"code": "INVALID_REQUEST"}}
    assert SECRET_CANARY not in invalid_path.text
    assert query_input.status_code == 400
    assert query_input.json() == {"error": {"code": "INVALID_REQUEST"}}
    assert SECRET_CANARY not in query_input.text
    assert port.calls == []
    _assert_no_store(invalid_path)
    _assert_no_store(query_input)


@pytest.mark.parametrize(
    "method",
    ("POST", "PUT", "DELETE", "TRACE", "CONNECT", "PROPFIND", "XYRAUNKNOWN"),
)
def test_only_get_is_registered_and_other_methods_are_fixed_no_store_405(
    method: str,
) -> None:
    port = _ReadPort()
    router = create_agent_health_status_router(enabled=True, read_port=port, clock=_Clock())
    methods = {method for route in router.routes for method in getattr(route, "methods", set())}
    assert methods == {"GET"}

    app = FastAPI()
    app.include_router(router)
    app.add_middleware(
        OperatorPrincipalMiddleware,
        capability=CAPABILITY,
        port=PORT,
        profile=_profile(),
    )
    with TestClient(app, base_url=BASE_URL) as client:
        response = client.request(
            method,
            _path(),
            headers={**_headers(), "Origin": BASE_URL},
            json={"heartbeat_utc_ns": SECRET_CANARY, "host": SECRET_CANARY},
        )

    assert response.status_code == 405
    assert SECRET_CANARY not in response.text
    assert port.calls == []
    _assert_no_store(response)
