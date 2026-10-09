"""Independent acceptance tests for the MT rollback status read router."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

import pytest
from fastapi import FastAPI, Request
from fastapi.responses import Response
from fastapi.testclient import TestClient

from leviathan_api.routers.mt_export_rollback_status import (
    RollbackProposalReadPortV1,
    create_router,
)
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
    TrustedPrincipalV1,
)

_PROJECT = "acceptance-project-17"
_OTHER_PROJECT = "acceptance-project-93"
_REF = "proposal-acceptance-004"
_CANARY = "synthetic-secret-canary-do-not-render"
_SHA_A = "a" * 64
_SHA_B = "b" * 64
_UNSET = object()


def _principal(project_id: str = _PROJECT) -> TrustedPrincipalV1:
    claims = PrincipalV1(
        principal_id="acceptance-rollback-reader",
        project_id=project_id,
        roles=("operator",),
        env="paper",
    )
    return TrustedPrincipalAdapterV1.from_verified_claims(
        claims,
        verifier_marker=_VERIFIER_MARKER,
    )


def _proposal(
    *, mode: DeploymentModeV1 = DeploymentModeV1.PAPER, prior: bool = True
) -> RollbackProposalV1:
    target = _issue_rollback_target(
        target_id="target-acceptance-1",
        platform=MtPlatformV1.MT5,
        mode=mode,
    )
    current = _issue_rollback_artifact(
        artifact_id="artifact-current-1",
        target_id="target-acceptance-1",
        platform=MtPlatformV1.MT5,
        created_at_ns=200,
        artifact_sha256=_SHA_A,
        provenance_sha256=_SHA_B,
    )
    earlier = (
        _issue_rollback_artifact(
            artifact_id="artifact-prior-1",
            target_id="target-acceptance-1",
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
        forward_deployment_id="forward-deployment-1",
    )


class _ProjectPort:
    def __init__(
        self,
        records: dict[tuple[str, str], RollbackProposalV1],
        *,
        error: Exception | None = None,
    ) -> None:
        self.records = records
        self.error = error
        self.calls: list[tuple[str, str]] = []

    def get_proposal(self, project_id: str, proposal_ref: str) -> RollbackProposalV1 | None:
        self.calls.append((project_id, proposal_ref))
        if self.error is not None:
            raise self.error
        return self.records.get((project_id, proposal_ref))


def _client(
    *,
    port: RollbackProposalReadPortV1 | None = None,
    enabled: bool | None = None,
    principal: object = _UNSET,
) -> TestClient:
    app = FastAPI()
    if enabled is None:
        app.include_router(create_router(read_port=port))
    else:
        app.include_router(create_router(read_port=port, enabled=enabled))
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
    port = _ProjectPort({(_PROJECT, _REF): _proposal()})
    path = f"/mt-export/rollback/proposals/{_REF}"
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
    port = _ProjectPort({(_PROJECT, _REF): _proposal()})
    with (
        _client(port=port, principal=_principal()) as default_disabled,
        _client(enabled=True, principal=_principal()) as portless,
    ):
        first = default_disabled.get(f"/mt-export/rollback/proposals/{_REF}")
        second = portless.get(f"/mt-export/rollback/proposals/{_REF}")

    assert first.status_code == second.status_code == 503
    assert first.json() == second.json() == {"detail": "FEATURE_UNAVAILABLE"}
    _assert_no_store(first)
    _assert_no_store(second)
    assert port.calls == []


@pytest.mark.parametrize("principal", (None, "forged-principal-canary"))
def test_absent_or_forged_principal_is_uniform_401_before_read(principal: object) -> None:
    port = _ProjectPort({(_PROJECT, _REF): _proposal()})
    with _client(port=port, enabled=True, principal=principal) as client:
        response = client.get(f"/mt-export/rollback/proposals/{_REF}")

    assert response.status_code == 401
    assert response.json() == {"detail": "AUTH_REQUIRED"}
    _assert_no_store(response)
    assert "forged-principal-canary" not in response.text
    assert port.calls == []


def test_owner_project_read_is_bounded_and_projection_is_non_executable() -> None:
    port = _ProjectPort({(_PROJECT, _REF): _proposal()})
    with _client(port=port, enabled=True, principal=_principal()) as client:
        response = client.get(f"/mt-export/rollback/proposals/{_REF}")

    assert response.status_code == 200
    _assert_no_store(response)
    assert port.calls == [(_PROJECT, _REF)]
    body = response.json()
    assert set(body) == {"plan"}
    plan = body["plan"]
    assert set(plan) == {
        "status",
        "target_id",
        "platform",
        "mode",
        "current_artifact_id",
        "prior_artifact_id",
        "forward_deployment_id",
        "block_code",
        "executable",
    }
    assert plan == {
        "status": "READY",
        "target_id": "target-acceptance-1",
        "platform": "MT5",
        "mode": "PAPER",
        "current_artifact_id": "artifact-current-1",
        "prior_artifact_id": "artifact-prior-1",
        "forward_deployment_id": "forward-deployment-1",
        "block_code": None,
        "executable": False,
    }
    assert _SHA_A not in response.text and _SHA_B not in response.text


def test_cross_project_and_missing_references_are_the_same_404() -> None:
    port = _ProjectPort({(_PROJECT, _REF): _proposal()})
    with (
        _client(port=port, enabled=True, principal=_principal(_PROJECT)) as owner,
        _client(port=port, enabled=True, principal=_principal(_OTHER_PROJECT)) as foreign,
    ):
        owned = owner.get(f"/mt-export/rollback/proposals/{_REF}")
        foreign_ref = foreign.get(f"/mt-export/rollback/proposals/{_REF}")
        absent = owner.get("/mt-export/rollback/proposals/missing-proposal-1")

    assert owned.status_code == 200
    _assert_no_store(owned)
    assert foreign_ref.status_code == absent.status_code == 404
    assert foreign_ref.json() == absent.json() == {"detail": "PROPOSAL_NOT_FOUND"}
    _assert_no_store(foreign_ref)
    _assert_no_store(absent)
    assert _REF not in foreign_ref.text + absent.text
    assert port.calls == [
        (_PROJECT, _REF),
        (_OTHER_PROJECT, _REF),
        (_PROJECT, "missing-proposal-1"),
    ]


def test_hierarchical_reference_uses_one_project_scoped_read() -> None:
    hierarchical_ref = "group/proposal-001"
    port = _ProjectPort({(_PROJECT, hierarchical_ref): _proposal()})
    with _client(port=port, enabled=True, principal=_principal()) as client:
        response = client.get(f"/mt-export/rollback/proposals/{hierarchical_ref}")

    assert response.status_code == 200
    _assert_no_store(response)
    assert response.json()["plan"]["executable"] is False
    assert port.calls == [(_PROJECT, hierarchical_ref)]


@pytest.mark.parametrize(
    ("reference", "query", "expected_code"),
    (
        ("bad!ref", "", "INVALID_REFERENCE"),
        ("pr%C3%B8posal", "", "INVALID_REFERENCE"),
        ("r" * 129, "", "INVALID_REFERENCE"),
        (_REF, f"?filter={_CANARY}", "INVALID_QUERY"),
    ),
)
def test_bad_ref_and_query_are_fixed_bounded_4xx(
    reference: str, query: str, expected_code: str
) -> None:
    port = _ProjectPort({(_PROJECT, _REF): _proposal()})
    with _client(port=port, enabled=True, principal=_principal()) as client:
        response = client.get(f"/mt-export/rollback/proposals/{reference}{query}")

    assert response.status_code == 400
    assert response.json() == {"detail": expected_code}
    _assert_no_store(response)
    assert _CANARY not in response.text
    assert port.calls == []


def test_live_target_and_missing_prior_are_blocked_not_executable() -> None:
    live_ref = "proposal-live-1"
    no_prior_ref = "proposal-no-prior-1"
    port = _ProjectPort(
        {
            (_PROJECT, live_ref): _proposal(mode=DeploymentModeV1.LIVE),
            (_PROJECT, no_prior_ref): _proposal(prior=False),
        }
    )
    with _client(port=port, enabled=True, principal=_principal()) as client:
        live = client.get(f"/mt-export/rollback/proposals/{live_ref}")
        no_prior = client.get(f"/mt-export/rollback/proposals/{no_prior_ref}")

    assert live.status_code == no_prior.status_code == 200
    _assert_no_store(live)
    _assert_no_store(no_prior)
    assert live.json()["plan"]["status"] == "BLOCKED"
    assert live.json()["plan"]["block_code"] == "LIVE_OPERATOR_SWITCH"
    assert no_prior.json()["plan"]["status"] == "BLOCKED"
    assert no_prior.json()["plan"]["block_code"] == "NO_PRIOR_ARTIFACT"
    assert live.json()["plan"]["executable"] is False
    assert no_prior.json()["plan"]["executable"] is False
    assert port.calls == [(_PROJECT, live_ref), (_PROJECT, no_prior_ref)]


def test_unissued_proposal_returns_bounded_error_without_secret_echo() -> None:
    unissued = RollbackProposalV1(
        target=RollbackTargetV1(
            target_id="unissued-target-1",
            platform=MtPlatformV1.MT5,
            mode=DeploymentModeV1.PAPER,
        ),
        current_artifact=RollbackArtifactV1(
            artifact_id="unissued-current-1",
            target_id="unissued-target-1",
            platform=MtPlatformV1.MT5,
            created_at_ns=200,
            artifact_sha256=_SHA_A,
            provenance_sha256=_SHA_B,
        ),
        prior_artifact=None,
        forward_deployment_id="unissued-forward-1",
    )
    port = _ProjectPort({(_PROJECT, _REF): unissued})
    with _client(port=port, enabled=True, principal=_principal()) as client:
        response = client.get(f"/mt-export/rollback/proposals/{_REF}")

    assert response.status_code == 422
    assert response.json() == {"detail": "INVALID_INPUT"}
    _assert_no_store(response)
    assert _SHA_A not in response.text and _SHA_B not in response.text
    assert port.calls == [(_PROJECT, _REF)]


def test_port_failure_is_fixed_and_never_returns_exception_text() -> None:
    port = _ProjectPort({}, error=RuntimeError(_CANARY))
    with _client(port=port, enabled=True, principal=_principal()) as client:
        response = client.get(f"/mt-export/rollback/proposals/{_REF}")

    assert response.status_code == 503
    assert response.json() == {"detail": "PROPOSAL_UNAVAILABLE"}
    _assert_no_store(response)
    assert _CANARY not in response.text
    assert port.calls == [(_PROJECT, _REF)]
