from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.middleware.base import RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from leviathan_api.routers.mt_export_rollback_status import create_router
from leviathan_core.mt_export_bridge_artifacts import DeploymentModeV1, MtPlatformV1
from leviathan_core.mt_export_rollback_plan import (
    RollbackArtifactV1,
    RollbackProposalV1,
    RollbackTargetV1,
    _issue_rollback_artifact,
    _issue_rollback_proposal,
    _issue_rollback_target,
)
from leviathan_core.security.authz_models import (
    _VERIFIER_MARKER,
    PrincipalV1,
    TrustedPrincipalAdapterV1,
)

_CANARY = "synthetic-status-query-canary"
_SHA_A = "a" * 64
_SHA_B = "b" * 64


class _MemoryPort:
    def __init__(
        self, proposal: RollbackProposalV1 | None, *, project_id: str = "synthetic-project"
    ) -> None:
        self.proposal = proposal
        self.project_id = project_id
        self.calls: list[tuple[str, str]] = []

    def get_proposal(self, project_id: str, proposal_ref: str) -> RollbackProposalV1 | None:
        self.calls.append((project_id, proposal_ref))
        if project_id != self.project_id or proposal_ref not in (
            "proposal-001",
            "group/proposal-001",
        ):
            return None
        return self.proposal


def _principal(*, project_id: str = "synthetic-project") -> object:
    claims = PrincipalV1(
        principal_id="synthetic-rollback-reader",
        project_id=project_id,
        roles=("operator",),
        env="development",
    )
    return TrustedPrincipalAdapterV1.from_verified_claims(
        claims,
        verifier_marker=_VERIFIER_MARKER,
    )


def _proposal(
    *, mode: DeploymentModeV1 = DeploymentModeV1.PAPER, prior: bool = True
) -> RollbackProposalV1:
    target = _issue_rollback_target(
        target_id="target-001",
        platform=MtPlatformV1.MT5,
        mode=mode,
    )
    current = _issue_rollback_artifact(
        artifact_id="artifact-current",
        target_id="target-001",
        platform=MtPlatformV1.MT5,
        created_at_ns=200,
        artifact_sha256=_SHA_A,
        provenance_sha256=_SHA_B,
    )
    earlier = (
        _issue_rollback_artifact(
            artifact_id="artifact-prior",
            target_id="target-001",
            platform=MtPlatformV1.MT5,
            created_at_ns=100,
            artifact_sha256=_SHA_B,
            provenance_sha256=_SHA_A,
        )
        if prior
        else None
    )
    return _issue_rollback_proposal(
        target=target,
        current_artifact=current,
        prior_artifact=earlier,
        forward_deployment_id="deployment-forward-001",
    )


def _client(
    *,
    proposal: RollbackProposalV1 | None = None,
    principal: object | None = _principal(),
    enabled: bool = True,
    portless: bool = False,
) -> tuple[TestClient, _MemoryPort | None]:
    app = FastAPI()
    port = None if portless else _MemoryPort(proposal)
    app.include_router(create_router(read_port=port, enabled=enabled))

    if principal is not None:

        @app.middleware("http")
        async def set_principal(request: Request, call_next: RequestResponseEndpoint) -> Response:
            request.state.trusted_principal = principal
            return await call_next(request)

    return TestClient(app), port


def test_ready_plan_is_allowlisted_and_never_executable() -> None:
    client, port = _client(proposal=_proposal())
    with client:
        response = client.get("/mt-export/rollback/proposals/proposal-001")

    assert response.status_code == 200
    assert response.json() == {
        "plan": {
            "status": "READY",
            "target_id": "target-001",
            "platform": "MT5",
            "mode": "PAPER",
            "current_artifact_id": "artifact-current",
            "prior_artifact_id": "artifact-prior",
            "forward_deployment_id": "deployment-forward-001",
            "block_code": None,
            "executable": False,
        }
    }
    assert port is not None and port.calls == [("synthetic-project", "proposal-001")]
    assert "provenance_sha256" not in response.text


def test_closed_identifier_grammar_accepts_hierarchical_reference() -> None:
    client, port = _client(proposal=_proposal())
    with client:
        response = client.get("/mt-export/rollback/proposals/group/proposal-001")

    assert response.status_code == 200
    assert response.json()["plan"]["executable"] is False
    assert port is not None
    assert port.calls == [("synthetic-project", "group/proposal-001")]


@pytest.mark.parametrize(
    ("proposal", "expected_code"),
    (
        (_proposal(prior=False), "NO_PRIOR_ARTIFACT"),
        (_proposal(mode=DeploymentModeV1.LIVE), "LIVE_OPERATOR_SWITCH"),
    ),
)
def test_blocked_inputs_return_non_executable_plan(
    proposal: RollbackProposalV1, expected_code: str
) -> None:
    client, _ = _client(proposal=proposal)
    with client:
        response = client.get("/mt-export/rollback/proposals/proposal-001")

    assert response.status_code == 200
    assert response.json()["plan"]["status"] == "BLOCKED"
    assert response.json()["plan"]["block_code"] == expected_code
    assert response.json()["plan"]["executable"] is False


@pytest.mark.parametrize(("enabled", "portless"), ((False, False), (True, True), (False, True)))
def test_disabled_or_portless_is_same_fixed_503(enabled: bool, portless: bool) -> None:
    client, _ = _client(proposal=_proposal(), enabled=enabled, portless=portless)
    with client:
        response = client.get("/mt-export/rollback/proposals/proposal-001")

    assert response.status_code == 503
    assert response.json() == {"detail": "FEATURE_UNAVAILABLE"}


@pytest.mark.parametrize("principal", (None, _CANARY))
def test_missing_or_forged_principal_is_fixed_401(principal: object | None) -> None:
    client, port = _client(proposal=_proposal(), principal=principal)
    with client:
        response = client.get("/mt-export/rollback/proposals/proposal-001")

    assert response.status_code == 401
    assert response.json() == {"detail": "AUTH_REQUIRED"}
    assert _CANARY not in response.text
    assert port is not None and port.calls == []


def test_unissued_proposal_is_rejected_without_echoing_input() -> None:
    unissued = RollbackProposalV1(
        target=RollbackTargetV1(
            target_id="target-001",
            platform=MtPlatformV1.MT5,
            mode=DeploymentModeV1.PAPER,
        ),
        current_artifact=RollbackArtifactV1(
            artifact_id="artifact-current",
            target_id="target-001",
            platform=MtPlatformV1.MT5,
            created_at_ns=200,
            artifact_sha256=_SHA_A,
            provenance_sha256=_SHA_B,
        ),
        prior_artifact=None,
        forward_deployment_id="deployment-forward-001",
    )
    client, _ = _client(proposal=unissued)
    with client:
        response = client.get("/mt-export/rollback/proposals/proposal-001")

    assert response.status_code == 422
    assert response.json() == {"detail": "INVALID_INPUT"}


def test_unknown_reference_and_query_values_are_not_echoed() -> None:
    client, port = _client(proposal=_proposal())
    with client:
        missing = client.get(f"/mt-export/rollback/proposals/{_CANARY}")
        query = client.get("/mt-export/rollback/proposals/proposal-001", params={"filter": _CANARY})

    assert missing.status_code == 404
    assert missing.json() == {"detail": "PROPOSAL_NOT_FOUND"}
    assert query.status_code == 400
    assert query.json() == {"detail": "INVALID_QUERY"}
    assert _CANARY not in missing.text + query.text
    assert port is not None and port.calls == [("synthetic-project", _CANARY)]


def test_cross_project_reference_is_indistinguishable_from_missing() -> None:
    foreign_client, foreign_port = _client(
        proposal=_proposal(), principal=_principal(project_id="other-project")
    )
    missing_client, _ = _client(proposal=None)
    with foreign_client, missing_client:
        foreign = foreign_client.get("/mt-export/rollback/proposals/proposal-001")
        missing = missing_client.get("/mt-export/rollback/proposals/proposal-001")

    assert foreign.status_code == missing.status_code == 404
    assert foreign.json() == missing.json() == {"detail": "PROPOSAL_NOT_FOUND"}
    assert foreign_port is not None
    assert foreign_port.calls == [("other-project", "proposal-001")]


@pytest.mark.parametrize("proposal_ref", ("é", "x" * 129))
def test_invalid_reference_grammar_returns_fixed_error(proposal_ref: str) -> None:
    client, port = _client(proposal=_proposal())
    with client:
        response = client.get(f"/mt-export/rollback/proposals/{proposal_ref}")

    assert response.status_code == 400
    assert response.json() == {"detail": "INVALID_REFERENCE"}
    assert proposal_ref not in response.text
    assert port is not None and port.calls == []


def test_port_exception_is_fixed_and_never_returned() -> None:
    class BrokenPort:
        def get_proposal(self, _project_id: str, _proposal_ref: str) -> None:
            raise RuntimeError(_CANARY)

    client = TestClient(FastAPI())
    app = client.app
    assert isinstance(app, FastAPI)
    app.include_router(create_router(read_port=BrokenPort(), enabled=True))

    @app.middleware("http")
    async def set_principal(request: Request, call_next: RequestResponseEndpoint) -> Response:
        request.state.trusted_principal = _principal()
        return await call_next(request)

    with client:
        response = client.get("/mt-export/rollback/proposals/proposal-001")

    assert response.status_code == 503
    assert response.json() == {"detail": "PROPOSAL_UNAVAILABLE"}
    assert _CANARY not in response.text


def test_only_get_is_registered() -> None:
    client, _ = _client(proposal=_proposal())
    with client:
        for method in ("post", "put", "patch", "delete", "head"):
            response = getattr(client, method)("/mt-export/rollback/proposals/proposal-001")
            assert response.status_code == 405, method


@pytest.mark.parametrize(
    ("method", "path", "principal", "enabled", "expected_status"),
    (
        ("get", "/mt-export/rollback/proposals/proposal-001", _principal(), True, 200),
        ("get", "/mt-export/rollback/proposals/proposal-001?filter=x", _principal(), True, 400),
        ("get", "/mt-export/rollback/proposals/missing", _principal(), True, 404),
        ("get", "/mt-export/rollback/proposals/proposal-001", None, True, 401),
        ("get", "/mt-export/rollback/proposals/proposal-001", _principal(), False, 503),
        ("post", "/mt-export/rollback/proposals/proposal-001", _principal(), True, 405),
    ),
)
def test_every_route_response_is_no_store(
    method: str,
    path: str,
    principal: object | None,
    enabled: bool,
    expected_status: int,
) -> None:
    client, _ = _client(proposal=_proposal(), principal=principal, enabled=enabled)
    with client:
        response = getattr(client, method)(path)

    assert response.status_code == expected_status
    assert response.headers["cache-control"] == "no-store"
