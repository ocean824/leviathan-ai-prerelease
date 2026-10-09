from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import cast

import pytest
from fastapi import FastAPI, Request
from fastapi.responses import Response
from fastapi.testclient import TestClient

from leviathan_api.routers.mt_export_deploy_status import (
    DeploymentPlanReadPortV1,
    create_mt_export_deploy_status_router,
)
from leviathan_core.mt_export_bridge_artifacts import MtPlatformV1
from leviathan_core.mt_export_deploy_plan import (
    DeploymentAccountKindV1,
    DeploymentActionV1,
    DeploymentArtifactSnapshotV1,
    DeploymentHealthV1,
    DeploymentPlanRequestV1,
    DeploymentTargetSnapshotV1,
)
from leviathan_core.security.authz_models import (
    _VERIFIER_MARKER,
    PrincipalV1,
    TrustedPrincipalAdapterV1,
    TrustedPrincipalV1,
)

_PROJECT = "synthetic-project-042"
_PLAN_REF = "synthetic-plan-ref-42"
_UNAVAILABLE_BODY = {"error": {"code": "DEPLOY_PLAN_STATUS_UNAVAILABLE"}}


def _request() -> DeploymentPlanRequestV1:
    return DeploymentPlanRequestV1(
        artifact=DeploymentArtifactSnapshotV1("synthetic-artifact-42", MtPlatformV1.MT5),
        targets=(
            DeploymentTargetSnapshotV1(
                target_id="paper-target-1",
                platform=MtPlatformV1.MT5,
                account_kind=DeploymentAccountKindV1.PAPER,
                capabilities=("activate", "download", "stage"),
                health=DeploymentHealthV1.HEALTHY,
                observed_at_ns=990,
            ),
            DeploymentTargetSnapshotV1(
                target_id="live-target-1",
                platform=MtPlatformV1.MT5,
                account_kind=DeploymentAccountKindV1.LIVE,
                capabilities=("activate", "download", "stage"),
                health=DeploymentHealthV1.HEALTHY,
                observed_at_ns=990,
            ),
        ),
        action=DeploymentActionV1.ACTIVATE,
        required_capabilities=("activate",),
        now_ns=1_000,
        maximum_health_age_ns=20,
        canary_percentage=100,
    )


def _principal(project_id: str = _PROJECT) -> TrustedPrincipalV1:
    claims = PrincipalV1(
        principal_id="synthetic-status-reader",
        project_id=project_id,
        roles=("operator",),
        env="paper",
    )
    return TrustedPrincipalAdapterV1.from_verified_claims(
        claims,
        verifier_marker=_VERIFIER_MARKER,
    )


class _ReadPort:
    def __init__(
        self,
        snapshot: DeploymentPlanRequestV1 | None,
        *,
        error: Exception | None = None,
    ) -> None:
        self.snapshot = snapshot
        self.error = error
        self.calls: list[tuple[str, str]] = []

    def read_plan_request(self, project_id: str, plan_ref: str) -> DeploymentPlanRequestV1 | None:
        self.calls.append((project_id, plan_ref))
        if self.error is not None:
            raise self.error
        return self.snapshot


def _client(
    *,
    read_port: DeploymentPlanReadPortV1 | None = None,
    enabled: bool = False,
    principal: object | None = None,
) -> TestClient:
    app = FastAPI()
    app.include_router(
        create_mt_export_deploy_status_router(
            read_port=read_port,
            enabled=enabled,
        )
    )

    @app.middleware("http")
    async def attach_principal(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        request.state.trusted_principal = principal
        return await call_next(request)

    return TestClient(app)


def test_router_is_disabled_by_default_and_disabled_or_missing_port_share_fixed_503() -> None:
    port = _ReadPort(_request())
    with _client(read_port=port) as disabled, _client(enabled=True) as portless:
        first = disabled.get(f"/mt-export/deployment/plans/{_PLAN_REF}")
        second = portless.get(f"/mt-export/deployment/plans/{_PLAN_REF}")

    assert first.status_code == second.status_code == 503
    assert first.json() == second.json() == _UNAVAILABLE_BODY
    assert port.calls == []


@pytest.mark.parametrize(
    ("method", "enabled", "port", "principal", "suffix", "query", "status"),
    (
        ("get", False, _ReadPort(None), _principal(), _PLAN_REF, "", 503),
        ("get", True, _ReadPort(_request()), _principal(), _PLAN_REF, "", 200),
        ("get", True, _ReadPort(_request()), None, _PLAN_REF, "", 401),
        ("get", True, _ReadPort(None), _principal(), _PLAN_REF, "", 404),
        ("get", True, _ReadPort(_request()), _principal(), "bad!ref", "", 400),
        ("get", True, _ReadPort(_request()), _principal(), _PLAN_REF, "?q=1", 400),
        ("post", True, _ReadPort(_request()), _principal(), _PLAN_REF, "", 405),
    ),
)
def test_every_router_response_has_no_store(
    method: str,
    enabled: bool,
    port: DeploymentPlanReadPortV1 | None,
    principal: object | None,
    suffix: str,
    query: str,
    status: int,
) -> None:
    with _client(read_port=port, enabled=enabled, principal=principal) as client:
        response = getattr(client, method)(f"/mt-export/deployment/plans/{suffix}{query}")

    assert response.status_code == status
    assert response.headers["Cache-Control"] == "no-store"


def test_issued_principal_scopes_single_read_and_response_is_allowlisted_non_executable() -> None:
    port = _ReadPort(_request())
    with _client(read_port=port, enabled=True, principal=_principal()) as client:
        response = client.get(f"/mt-export/deployment/plans/{_PLAN_REF}")

    assert response.status_code == 200
    assert port.calls == [(_PROJECT, _PLAN_REF)]
    body = response.json()
    assert set(body) == {
        "schema_version",
        "artifact_id",
        "action",
        "evaluated_at_ns",
        "target_decisions",
        "canary_target_ids",
        "remainder_target_ids",
        "blocked_target_ids",
        "execution_permitted",
    }
    assert body["action"] == "ACTIVATE"
    assert body["execution_permitted"] is False
    assert body["canary_target_ids"] == ["paper-target-1"]
    assert body["blocked_target_ids"] == ["live-target-1"]
    assert body["target_decisions"][1] == {
        "target_id": "live-target-1",
        "decision": "PLAN_BLOCKED",
        "block_code": "LIVE_ACCOUNT_OPERATOR_SWITCH_REQUIRED",
        "canary_partition": "BLOCKED",
        "operator_switch_required": True,
        "execution_permitted": False,
    }
    assert _PLAN_REF not in response.text


@pytest.mark.parametrize("principal", [None, object()])
def test_missing_or_unissued_principal_is_fixed_401_before_port_read(
    principal: object | None,
) -> None:
    port = _ReadPort(_request())
    with _client(read_port=port, enabled=True, principal=principal) as client:
        response = client.get(f"/mt-export/deployment/plans/{_PLAN_REF}")

    assert response.status_code == 401
    assert response.json() == {"error": {"code": "PRINCIPAL_UNTRUSTED"}}
    assert port.calls == []


@pytest.mark.parametrize("bad_ref", ["bad%20reference", "x" * 129, ""])
def test_invalid_plan_reference_is_rejected_without_echo_or_port_read(bad_ref: str) -> None:
    port = _ReadPort(_request())
    with _client(read_port=port, enabled=True, principal=_principal()) as client:
        response = client.get(f"/mt-export/deployment/plans/{bad_ref}")

    assert response.status_code in {400, 404}
    assert "bad reference" not in response.text
    assert response.text != bad_ref
    assert port.calls == []


def test_query_parameters_are_not_accepted_or_passed_to_the_read_port() -> None:
    port = _ReadPort(_request())
    with _client(read_port=port, enabled=True, principal=_principal()) as client:
        response = client.get(
            f"/mt-export/deployment/plans/{_PLAN_REF}?payload=synthetic-free-text"
        )

    assert response.status_code == 400
    assert response.json() == {"error": {"code": "UNSUPPORTED_QUERY"}}
    assert "synthetic-free-text" not in response.text
    assert port.calls == []


def test_missing_plan_returns_fixed_not_found() -> None:
    port = _ReadPort(None)
    with _client(read_port=port, enabled=True, principal=_principal()) as client:
        response = client.get(f"/mt-export/deployment/plans/{_PLAN_REF}")

    assert response.status_code == 404
    assert response.json() == {"error": {"code": "DEPLOY_PLAN_NOT_FOUND"}}
    assert port.calls == [(_PROJECT, _PLAN_REF)]


@pytest.mark.parametrize(
    "port",
    [
        _ReadPort(_request(), error=RuntimeError("synthetic-private-port-error")),
        _ReadPort(cast(DeploymentPlanRequestV1, object())),
    ],
)
def test_port_failures_and_invalid_snapshots_share_content_free_503(port: _ReadPort) -> None:
    with _client(read_port=port, enabled=True, principal=_principal()) as client:
        response = client.get(f"/mt-export/deployment/plans/{_PLAN_REF}")

    assert response.status_code == 503
    assert response.json() == _UNAVAILABLE_BODY
    assert "synthetic-private-port-error" not in response.text
    assert port.calls == [(_PROJECT, _PLAN_REF)]


@pytest.mark.parametrize("method", ["post", "put", "patch", "delete"])
def test_router_exposes_no_non_get_operation(method: str) -> None:
    port = _ReadPort(_request())
    with _client(read_port=port, enabled=True, principal=_principal()) as client:
        response = getattr(client, method)(f"/mt-export/deployment/plans/{_PLAN_REF}")

    assert response.status_code == 405
    assert port.calls == []
