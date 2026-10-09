"""Independent acceptance tests for the MT deployment status read router."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

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

_PROJECT = "acceptance-project-17"
_OTHER_PROJECT = "acceptance-project-93"
_REF = "plan-acceptance-004"
_UNAVAILABLE = {"error": {"code": "DEPLOY_PLAN_STATUS_UNAVAILABLE"}}
_SECRET_CANARY = "synthetic-secret-canary-do-not-render"
_UNSET = object()


def _request() -> DeploymentPlanRequestV1:
    return DeploymentPlanRequestV1(
        artifact=DeploymentArtifactSnapshotV1("artifact-acceptance-1", MtPlatformV1.MT5),
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
            DeploymentTargetSnapshotV1(
                target_id="stale-target-1",
                platform=MtPlatformV1.MT5,
                account_kind=DeploymentAccountKindV1.PAPER,
                capabilities=("activate",),
                health=DeploymentHealthV1.HEALTHY,
                observed_at_ns=1,
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
        principal_id="acceptance-status-reader",
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
        snapshot: object,
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
        return self.snapshot  # type: ignore[return-value]


def _client(
    *,
    port: DeploymentPlanReadPortV1 | None = None,
    enabled: bool | None = None,
    principal: object = _UNSET,
) -> TestClient:
    app = FastAPI()
    if enabled is None:
        app.include_router(create_mt_export_deploy_status_router(read_port=port))
    else:
        app.include_router(create_mt_export_deploy_status_router(read_port=port, enabled=enabled))
    app.state.acceptance_principal = principal

    @app.middleware("http")
    async def inject_principal(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        value = app.state.acceptance_principal
        if value is not _UNSET:
            request.state.trusted_principal = value
        return await call_next(request)

    return TestClient(app)


def _assert_no_store(response: Response) -> None:
    directives = {
        item.strip().split("=", maxsplit=1)[0].lower()
        for item in response.headers.get("cache-control", "").split(",")
    }
    assert "no-store" in directives


def test_router_is_get_only() -> None:
    port = _ReadPort(_request())
    path = f"/mt-export/deployment/plans/{_REF}"
    with _client(port=port, enabled=True, principal=_principal()) as client:
        responses = [
            client.request(method, path)
            for method in (
                "POST",
                "PUT",
                "PATCH",
                "DELETE",
                "HEAD",
                "OPTIONS",
                "TRACE",
                "CONNECT",
                "PROPFIND",
                "BREW",
            )
        ]

    assert all(response.status_code == 405 for response in responses)
    for response in responses:
        _assert_no_store(response)
    assert port.calls == []


def test_default_disabled_and_portless_share_fixed_503() -> None:
    port = _ReadPort(_request())
    with (
        _client(port=port, principal=_principal()) as default_disabled,
        _client(enabled=True, principal=_principal()) as portless,
    ):
        first = default_disabled.get(f"/mt-export/deployment/plans/{_REF}")
        second = portless.get(f"/mt-export/deployment/plans/{_REF}")

    assert first.status_code == second.status_code == 503
    assert first.json() == second.json() == _UNAVAILABLE
    _assert_no_store(first)
    _assert_no_store(second)
    assert port.calls == []


@pytest.mark.parametrize("principal", (None, "forged-principal-canary"))
def test_absent_or_forged_principal_is_uniform_401_before_read(principal: object) -> None:
    port = _ReadPort(_request())
    with _client(port=port, enabled=True, principal=principal) as client:
        response = client.get(f"/mt-export/deployment/plans/{_REF}")

    assert response.status_code == 401
    assert response.json() == {"error": {"code": "PRINCIPAL_UNTRUSTED"}}
    _assert_no_store(response)
    assert "forged-principal-canary" not in response.text
    assert port.calls == []


def test_success_is_project_scoped_bounded_and_non_executable() -> None:
    class ProjectScopedPort(_ReadPort):
        def read_plan_request(
            self, project_id: str, plan_ref: str
        ) -> DeploymentPlanRequestV1 | None:
            self.calls.append((project_id, plan_ref))
            return _request() if project_id == _PROJECT else None

    port = ProjectScopedPort(None)
    with (
        _client(port=port, enabled=True, principal=_principal(_PROJECT)) as owner,
        _client(port=port, enabled=True, principal=_principal(_OTHER_PROJECT)) as other,
    ):
        response = owner.get(f"/mt-export/deployment/plans/{_REF}")
        cross_project = other.get(f"/mt-export/deployment/plans/{_REF}")

    assert response.status_code == 200
    _assert_no_store(response)
    assert cross_project.status_code == 404
    assert cross_project.json() == {"error": {"code": "DEPLOY_PLAN_NOT_FOUND"}}
    assert port.calls == [(_PROJECT, _REF), (_OTHER_PROJECT, _REF)]
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
    assert body["execution_permitted"] is False
    decisions = {item["target_id"]: item for item in body["target_decisions"]}
    assert set(decisions) == {"paper-target-1", "live-target-1", "stale-target-1"}
    assert all(
        set(item)
        == {
            "target_id",
            "decision",
            "block_code",
            "canary_partition",
            "operator_switch_required",
            "execution_permitted",
        }
        for item in decisions.values()
    )
    assert decisions["paper-target-1"]["decision"] == "ACTIVATE"
    assert decisions["paper-target-1"]["execution_permitted"] is False
    assert decisions["live-target-1"]["decision"] == "PLAN_BLOCKED"
    assert decisions["live-target-1"]["block_code"] == "LIVE_ACCOUNT_OPERATOR_SWITCH_REQUIRED"
    assert decisions["stale-target-1"]["decision"] == "PLAN_BLOCKED"
    assert decisions["stale-target-1"]["block_code"] == "HEALTH_STALE"
    assert _REF not in response.text


@pytest.mark.parametrize(
    ("suffix", "query", "expected_code"),
    (
        ("bad!ref", "", "INVALID_PLAN_REF"),
        ("bad%2Fref", "", "INVALID_PLAN_REF"),
        ("r" * 129, "", "INVALID_PLAN_REF"),
        (_REF, f"?search={_SECRET_CANARY}", "UNSUPPORTED_QUERY"),
    ),
)
def test_invalid_path_and_query_are_fixed_bounded_4xx(
    suffix: str, query: str, expected_code: str
) -> None:
    port = _ReadPort(_request())
    with _client(port=port, enabled=True, principal=_principal()) as client:
        response = client.get(f"/mt-export/deployment/plans/{suffix}{query}")

    assert response.status_code == 400
    assert response.json() == {"error": {"code": expected_code}}
    _assert_no_store(response)
    assert _SECRET_CANARY not in response.text
    assert port.calls == []


def test_missing_ref_uses_fixed_404_without_echo_and_reads_once() -> None:
    port = _ReadPort(None)
    missing_ref = "missing-plan-09"
    with _client(port=port, enabled=True, principal=_principal()) as client:
        response = client.get(f"/mt-export/deployment/plans/{missing_ref}")

    assert response.status_code == 404
    assert response.json() == {"error": {"code": "DEPLOY_PLAN_NOT_FOUND"}}
    _assert_no_store(response)
    assert missing_ref not in response.text
    assert port.calls == [(_PROJECT, missing_ref)]


@pytest.mark.parametrize("failure", ("port", "snapshot"))
def test_port_failure_and_invalid_snapshot_are_same_content_free_503(failure: str) -> None:
    port = (
        _ReadPort(_request(), error=RuntimeError(_SECRET_CANARY))
        if failure == "port"
        else _ReadPort(object())
    )
    with _client(port=port, enabled=True, principal=_principal()) as client:
        response = client.get(f"/mt-export/deployment/plans/{_REF}")

    assert response.status_code == 503
    assert response.json() == _UNAVAILABLE
    _assert_no_store(response)
    assert _SECRET_CANARY not in response.text
    assert port.calls == [(_PROJECT, _REF)]
