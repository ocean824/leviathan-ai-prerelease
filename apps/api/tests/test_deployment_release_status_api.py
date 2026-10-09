"""Focused contract tests for the release-readiness status projection."""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from leviathan_api.routers.deployment_release_status import (
    create_deployment_release_status_router,
)
from leviathan_core.deployment_release_policy import (
    ApprovalEvidence,
    FindingSeverity,
    ReadinessBlocker,
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

_PATH = "/deployment/releases/release-123/readiness"
_ERROR_UNAUTHENTICATED = {"error": {"code": "UNAUTHENTICATED"}}


def _principal(*, project_id: str = "project-a") -> TrustedPrincipalV1:
    claims = PrincipalV1(
        principal_id="operator-1", project_id=project_id, roles=("operator",), env="test"
    )
    return TrustedPrincipalAdapterV1.from_verified_claims(claims, verifier_marker=_VERIFIER_MARKER)


def _evidence(*, approvals: tuple[ApprovalEvidence, ...] | None = None) -> ReleaseEvidence:
    if approvals is None:
        approvals = (
            ApprovalEvidence("approver-a", "release-approver", True),
            ApprovalEvidence("approver-b", "security-approver", True),
        )
    return issue_release_evidence(
        release_id="release-123",
        release_author_id="author-1",
        release_requester_id="requester-1",
        created_utc_ns=1,
        promotion_approved=True,
        approvals=approvals,
        image_digest="sha256:" + "a" * 64,
        deterministic=True,
        tests=(TestEvidence(test_id="unit", passed=True),),
        findings=(),
        secret_refs=("vault://leviathan-ai/test/release/db-password",),
    )


def _policy():
    return issue_release_policy(
        required_test_ids=("unit",),
        disallowed_open_severities=(FindingSeverity.CRITICAL, FindingSeverity.HIGH),
    )


def _assert_no_store(response) -> None:
    assert response.headers["cache-control"] == "no-store"


class _Port:
    def __init__(self, record=None, *, error: Exception | None = None):
        self.record = record
        self.error = error
        self.calls: list[tuple[str, str]] = []

    def read_release(self, *, project_id: str, release_ref: str):
        self.calls.append((project_id, release_ref))
        if self.error is not None:
            raise self.error
        return self.record


def _app(*, principal=None, enabled=True, port=None) -> FastAPI:
    app = FastAPI()

    @app.middleware("http")
    async def inject_principal(request: Request, call_next):
        if principal is not ...:
            request.state.trusted_principal = principal
        return await call_next(request)

    app.include_router(create_deployment_release_status_router(enabled=enabled, read_port=port))
    return app


def test_disabled_and_portless_configuration_have_the_same_fixed_503() -> None:
    expected = {"error": {"code": "RELEASE_STATUS_UNAVAILABLE"}}
    disabled = TestClient(_app(enabled=False, port=_Port((_evidence(), _policy()))))
    portless = TestClient(_app(enabled=True, port=None))
    disabled_response = disabled.get(_PATH)
    portless_response = portless.get(_PATH)
    assert disabled_response.json() == expected
    assert portless_response.status_code == 503
    assert portless_response.json() == expected
    _assert_no_store(disabled_response)
    _assert_no_store(portless_response)


def test_valid_principal_reads_only_its_project_and_returns_allowlisted_readiness() -> None:
    port = _Port((_evidence(), _policy()))
    with TestClient(_app(principal=_principal(project_id="tenant-one"), port=port)) as client:
        response = client.get(_PATH)
    assert response.status_code == 200
    assert response.json() == {"ready": True, "blockers": []}
    _assert_no_store(response)
    assert port.calls == [("tenant-one", "release-123")]
    assert "vault://" not in response.text
    assert "secret_refs" not in response.text
    assert "approver" not in response.text
    assert "image_digest" not in response.text


def test_missing_and_unissued_principals_have_identical_401_envelopes() -> None:
    port = _Port((_evidence(), _policy()))
    unissued = object.__new__(TrustedPrincipalV1)
    missing = TestClient(_app(principal=..., port=port)).get(_PATH)
    forged = TestClient(_app(principal=unissued, port=port)).get(_PATH)
    assert missing.status_code == forged.status_code == 401
    assert missing.json() == forged.json() == _ERROR_UNAUTHENTICATED
    _assert_no_store(missing)
    _assert_no_store(forged)
    assert port.calls == []


def test_blocked_policy_is_informational_and_excludes_author_and_requester() -> None:
    evidence = _evidence(
        approvals=(
            ApprovalEvidence("author-1", "release-approver", True),
            ApprovalEvidence("requester-1", "security-approver", True),
        )
    )
    port = _Port((evidence, _policy()))
    with TestClient(_app(principal=_principal(), port=port)) as client:
        response = client.get(_PATH)
    assert response.status_code == 200
    assert response.json() == {
        "ready": False,
        "blockers": [ReadinessBlocker.APPROVALS_INSUFFICIENT.value],
    }
    _assert_no_store(response)


def test_missing_record_and_invalid_reference_fail_closed_without_extra_reads() -> None:
    port = _Port(None)
    with TestClient(_app(principal=_principal(), port=port)) as client:
        missing = client.get(_PATH)
        invalid = client.get("/deployment/releases/../readiness")
    assert missing.status_code == 404
    assert missing.json() == {"error": {"code": "RELEASE_STATUS_NOT_FOUND"}}
    _assert_no_store(missing)
    assert invalid.status_code in (404, 400)
    assert port.calls == [("project-a", "release-123")]


def test_query_scope_is_ignored_and_non_get_methods_cannot_write_readiness() -> None:
    port = _Port((_evidence(), _policy()))
    with TestClient(_app(principal=_principal(), port=port)) as client:
        query = client.get(_PATH + "?project_id=other")
        mismatches = tuple(
            client.request(method, _PATH)
            for method in ("POST", "TRACE", "CONNECT", "PROPFIND", "XYRA-UNKNOWN")
        )
    assert query.status_code == 200
    assert query.json() == {"ready": True, "blockers": []}
    _assert_no_store(query)
    assert all(response.status_code == 405 for response in mismatches)
    for response in mismatches:
        _assert_no_store(response)
        assert response.headers["allow"] == "GET"
    assert port.calls == [("project-a", "release-123")]


def test_port_failure_is_fixed_and_does_not_echo_exception_content() -> None:
    port = _Port(error=RuntimeError("SYNTHETIC-SENSITIVE-PORT-DETAIL"))
    with TestClient(_app(principal=_principal(), port=port)) as client:
        response = client.get(_PATH)
    assert response.status_code == 503
    assert response.json() == {"error": {"code": "RELEASE_STATUS_UNAVAILABLE"}}
    _assert_no_store(response)
    assert "SYNTHETIC-SENSITIVE" not in response.text


def test_unissued_evidence_and_policy_fail_closed_without_serializing_input() -> None:
    evidence = object.__new__(ReleaseEvidence)
    policy = object.__new__(ReleasePolicy)
    port = _Port((evidence, policy))
    with TestClient(_app(principal=_principal(), port=port)) as client:
        response = client.get(_PATH)
    assert response.status_code == 200
    assert response.json() == {
        "ready": False,
        "blockers": [ReadinessBlocker.EVIDENCE_UNTRUSTED.value],
    }
    _assert_no_store(response)
    assert "secret" not in response.text.lower()
