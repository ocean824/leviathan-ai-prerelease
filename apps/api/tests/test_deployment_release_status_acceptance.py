"""Independent acceptance tests for the read-only release-status API."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from fastapi.testclient import TestClient

from leviathan_api.routers.deployment_release_status import (
    create_deployment_release_status_router,
)
from leviathan_core.deployment_release_policy import (
    ApprovalEvidence,
    FindingSeverity,
    ReleaseEvidence,
    ReleasePolicy,
    TestEvidence,
    issue_release_evidence,
    issue_release_policy,
)
from leviathan_core.security.authz_models import (
    _VERIFIER_MARKER,
    PrincipalV1,
    TrustedPrincipalAdapterV1,
    TrustedPrincipalV1,
)

PROJECT_ID = "acceptance-project-001"
RELEASE_REF = "release-acceptance-002"
PATH = f"/deployment/releases/{RELEASE_REF}/readiness"
REQUIRED_TESTS = ("build-unit", "build-integration")
RELEASE_AUTHOR = "release-author-synthetic"
RELEASE_REQUESTER = "release-requester-synthetic"
_ABSENT = object()


class _ReadPort:
    def __init__(
        self,
        result: tuple[ReleaseEvidence, ReleasePolicy] | None,
        error: Exception | None = None,
    ) -> None:
        self.result = result
        self.error = error
        self.calls: list[tuple[str, str]] = []

    def read_release(
        self, project_id: str, release_ref: str
    ) -> tuple[ReleaseEvidence, ReleasePolicy] | None:
        self.calls.append((project_id, release_ref))
        if self.error is not None:
            raise self.error
        return self.result


class _SeedPrincipal:
    """ASGI wrapper for controlled request-state principal fixtures."""

    def __init__(self, app: Any, principal: object = _ABSENT) -> None:
        self.app = app
        self.principal = principal

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope.get("type") == "http" and self.principal is not _ABSENT:
            scope.setdefault("state", {})["trusted_principal"] = self.principal
        await self.app(scope, receive, send)


def _principal(project_id: str = PROJECT_ID) -> TrustedPrincipalV1:
    claims = PrincipalV1(
        principal_id="release-status-operator",
        project_id=project_id,
        roles=("operator",),
        env="test",
    )
    return TrustedPrincipalAdapterV1.from_verified_claims(claims, verifier_marker=_VERIFIER_MARKER)


def _forged_principal() -> TrustedPrincipalV1:
    claims = PrincipalV1(
        principal_id="release-status-forged",
        project_id=PROJECT_ID,
        roles=("operator",),
        env="test",
    )
    principal = object.__new__(TrustedPrincipalV1)
    for field in (
        "principal_id",
        "project_id",
        "roles",
        "env",
        "venue",
        "portfolio",
        "strategy",
        "break_glass",
    ):
        object.__setattr__(principal, field, getattr(claims, field))
    return principal


def _bundle(
    approvals: tuple[ApprovalEvidence, ...] | None = None,
    *,
    secret_refs: tuple[str, ...] = (),
) -> tuple[ReleaseEvidence, ReleasePolicy]:
    accepted_approvals = (
        (
            ApprovalEvidence("eligible-approver-one", "operator", True),
            ApprovalEvidence("eligible-approver-two", "release-manager", True),
        )
        if approvals is None
        else approvals
    )
    evidence = issue_release_evidence(
        release_id=RELEASE_REF,
        release_author_id=RELEASE_AUTHOR,
        release_requester_id=RELEASE_REQUESTER,
        created_utc_ns=1_800_000_000_000_000_000,
        promotion_approved=True,
        approvals=accepted_approvals,
        image_digest="sha256:" + "a" * 64,
        deterministic=True,
        tests=tuple(TestEvidence(test_id=test_id, passed=True) for test_id in REQUIRED_TESTS),
        findings=(),
        secret_refs=secret_refs,
    )
    policy = issue_release_policy(
        required_test_ids=REQUIRED_TESTS,
        disallowed_open_severities=(FindingSeverity.CRITICAL, FindingSeverity.HIGH),
        minimum_approvers=2,
    )
    return evidence, policy


def _client(
    *,
    enabled: bool = False,
    read_port: _ReadPort | None = None,
    principal: object = _ABSENT,
) -> TestClient:
    app = FastAPI()
    app.include_router(
        create_deployment_release_status_router(
            enabled=enabled,
            read_port=read_port,
        )
    )
    return TestClient(_SeedPrincipal(app, principal))


def test_readiness_get_is_only_method_and_uses_principal_project_scope() -> None:
    port = _ReadPort(_bundle())
    with _client(enabled=True, read_port=port, principal=_principal()) as client:
        response = client.get(PATH, params={"project_id": "forged-project"})
        unsupported = (
            client.post(PATH),
            client.put(PATH),
            client.patch(PATH),
            client.delete(PATH),
            client.head(PATH),
            client.options(PATH),
            client.request("TRACE", PATH),
            client.request("CONNECT", PATH),
            client.request("PROPFIND", PATH),
            client.request("BREW", PATH),
        )

    assert response.status_code == 200
    assert response.json() == {"ready": True, "blockers": []}
    assert all(item.status_code == 405 for item in unsupported)
    assert port.calls == [(PROJECT_ID, RELEASE_REF)]


def test_disabled_by_default_and_portless_routes_return_fixed_503() -> None:
    port = _ReadPort(_bundle())
    with _client(read_port=port, principal=_principal()) as disabled_client:
        disabled = disabled_client.get(PATH)
    with _client(enabled=True, principal=_principal()) as portless_client:
        portless = portless_client.get(PATH)

    assert disabled.status_code == portless.status_code == 503
    assert disabled.content == portless.content
    assert "RELEASE_STATUS_UNAVAILABLE" in disabled.text
    assert port.calls == []


def test_absent_and_forged_principals_have_uniform_401_without_port_access() -> None:
    port = _ReadPort(_bundle())
    with _client(enabled=True, read_port=port) as absent_client:
        absent = absent_client.get(PATH)
    with _client(enabled=True, read_port=port, principal=_forged_principal()) as forged_client:
        forged = forged_client.get(PATH)

    assert absent.status_code == forged.status_code == 401
    assert absent.content == forged.content
    assert "UNAUTHENTICATED" in absent.text
    assert port.calls == []


def test_readiness_requires_two_distinct_approvers_and_excludes_author_requester() -> None:
    cases = (
        (
            (
                ApprovalEvidence("eligible-approver-one", "operator", True),
                ApprovalEvidence("eligible-approver-two", "release-manager", True),
            ),
            True,
        ),
        (
            (
                ApprovalEvidence(RELEASE_AUTHOR, "operator", True),
                ApprovalEvidence("eligible-approver-one", "operator", True),
            ),
            False,
        ),
        (
            (
                ApprovalEvidence(RELEASE_REQUESTER, "operator", True),
                ApprovalEvidence("eligible-approver-one", "operator", True),
            ),
            False,
        ),
        (
            (
                ApprovalEvidence("eligible-approver-one", "operator", True),
                ApprovalEvidence("eligible-approver-one", "release-manager", True),
            ),
            False,
        ),
    )
    for approvals, expected_ready in cases:
        port = _ReadPort(_bundle(approvals))
        with _client(enabled=True, read_port=port, principal=_principal()) as client:
            response = client.get(PATH)

        assert response.status_code == 200
        assert response.json()["ready"] is expected_ready
        if not expected_ready:
            assert response.json()["blockers"] == ["APPROVALS_INSUFFICIENT"]


def test_tampered_issued_evidence_fails_closed() -> None:
    evidence, policy = _bundle()
    object.__setattr__(evidence, "promotion_approved", False)
    port = _ReadPort((evidence, policy))

    with _client(enabled=True, read_port=port, principal=_principal()) as client:
        response = client.get(PATH)

    assert response.status_code == 200
    assert response.json() == {"ready": False, "blockers": ["EVIDENCE_UNTRUSTED"]}


def test_response_contains_no_secret_refs_approval_details_or_provider_free_text() -> None:
    secret_ref_one = "vault://leviathan-ai/production/provider-alpha/DB_PASSWORD"
    secret_ref_two = "vault://leviathan-ai/live/provider-beta/SERVICE_TOKEN"
    approver_detail = "synthetic-approver-private-detail-canary"
    evidence, policy = _bundle(
        (
            ApprovalEvidence(approver_detail, "operator", True),
            ApprovalEvidence("eligible-approver-two", "release-manager", True),
        ),
        secret_refs=(secret_ref_one, secret_ref_two),
    )
    port = _ReadPort((evidence, policy))
    with _client(enabled=True, read_port=port, principal=_principal()) as client:
        success = client.get(PATH)

    assert success.status_code == 200
    assert set(success.json()) == {"ready", "blockers"}
    for hidden in (secret_ref_one, secret_ref_two, approver_detail, "sha256:" + "a" * 64):
        assert hidden not in success.text
    assert "provider" not in success.text.lower()

    failing_port = _ReadPort(None, RuntimeError("provider exception SECRET_CANARY_TEXT"))
    with _client(enabled=True, read_port=failing_port, principal=_principal()) as client:
        failure = client.get(PATH)
    assert failure.status_code == 503
    assert "RELEASE_STATUS_UNAVAILABLE" in failure.text
    assert "provider exception" not in failure.text
    assert "SECRET_CANARY_TEXT" not in failure.text
    assert "Traceback" not in failure.text


def test_every_response_class_is_marked_no_store() -> None:
    cases: list[tuple[int, Any]] = []

    with _client(enabled=True, read_port=_ReadPort(_bundle()), principal=_principal()) as client:
        cases.append((200, client.get(PATH)))
    with _client(enabled=True, read_port=_ReadPort(_bundle())) as client:
        cases.append((401, client.get(PATH)))
    with _client(enabled=True, read_port=_ReadPort(None), principal=_principal()) as client:
        cases.append((404, client.get(PATH)))
    with _client(read_port=_ReadPort(_bundle()), principal=_principal()) as client:
        cases.append((503, client.get(PATH)))
    with _client(enabled=True, read_port=_ReadPort(_bundle()), principal=_principal()) as client:
        for method in ("POST", "TRACE", "CONNECT", "PROPFIND", "BREW"):
            cases.append((405, client.request(method, PATH)))

    for expected_status, response in cases:
        assert response.status_code == expected_status
        assert response.headers["cache-control"] == "no-store"
