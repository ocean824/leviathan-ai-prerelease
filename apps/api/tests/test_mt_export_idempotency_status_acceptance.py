"""Independent boundary tests for the MT export idempotency read router."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from leviathan_api.auth import (
    LocalOperatorProfileV1,
    OperatorPrincipalMiddleware,
    make_local_operator_profile,
)
from leviathan_api.routers.mt_export_idempotency_status import (
    build_idempotency_status_router,
)
from leviathan_core.mt_export_idempotency import (
    ExportActionV1,
    RequestBindingV1,
    create_request_binding,
)

PORT = 43861
BASE_URL = f"http://127.0.0.1:{PORT}"
CAPABILITY = "a" * 64
OTHER_CAPABILITY = "b" * 64
REQUEST_REF = "request-accepted-17"
SECRET_CANARY = "IDEMP_STATUS_SYNTHETIC_SECRET_CANARY_7f0d5b"


def _profile(
    *, principal_id: str = "operator-alpha", project_id: str = "project-alpha"
) -> LocalOperatorProfileV1:
    return make_local_operator_profile(principal_id=principal_id, project_id=project_id, env="test")


def _binding(*, project_id: str, key: str, payload: Mapping[str, object]) -> RequestBindingV1:
    return create_request_binding(
        project_id=project_id,
        action=ExportActionV1.BUILD,
        idempotency_key=key,
        payload=payload,
    )


class _ReadPort:
    def __init__(
        self,
        records: dict[tuple[str, str, str], tuple[RequestBindingV1 | None, RequestBindingV1] | None]
        | None = None,
        *,
        error: Exception | None = None,
    ) -> None:
        self.records = {} if records is None else records
        self.error = error
        self.calls: list[tuple[str, str, str]] = []

    def read_bindings(
        self, *, principal: object, request_ref: str
    ) -> tuple[RequestBindingV1 | None, RequestBindingV1] | None:
        principal_id = getattr(principal, "principal_id", "")
        project_id = getattr(principal, "project_id", "")
        scope = (principal_id, project_id, request_ref)
        self.calls.append(scope)
        if self.error is not None:
            raise self.error
        return self.records.get(scope)


def _client(
    *,
    enabled: bool = True,
    read_port: object | None,
    profile: LocalOperatorProfileV1 | None = None,
) -> TestClient:
    app = FastAPI()
    app.include_router(build_idempotency_status_router(enabled=enabled, read_port=read_port))
    if profile is not None:
        app.add_middleware(
            OperatorPrincipalMiddleware,
            capability=CAPABILITY,
            port=PORT,
            profile=profile,
        )
    return TestClient(app, base_url=BASE_URL)


def _auth_headers(*, capability: str = CAPABILITY) -> dict[str, str]:
    return {"X-Leviathan-Capability": capability}


def _assert_no_store(response: Any) -> None:
    assert "no-store" in response.headers.get("cache-control", "").lower()


def test_router_is_disabled_by_default_and_returns_fixed_503_without_reading() -> None:
    port = _ReadPort()
    client = _client(enabled=False, read_port=port, profile=_profile())
    with client:
        response = client.get(
            f"/mt-export/idempotency/requests/{REQUEST_REF}", headers=_auth_headers()
        )

    assert response.status_code == 503
    assert response.json() == {"error": "unavailable"}
    assert port.calls == []
    _assert_no_store(response)


def test_enabled_router_without_port_returns_same_fixed_503() -> None:
    client = _client(enabled=True, read_port=None, profile=_profile())
    with client:
        response = client.get(
            f"/mt-export/idempotency/requests/{REQUEST_REF}", headers=_auth_headers()
        )

    assert response.status_code == 503
    assert response.json() == {"error": "unavailable"}
    _assert_no_store(response)


def test_absent_and_forged_principals_have_one_uniform_401() -> None:
    port = _ReadPort()
    path = f"/mt-export/idempotency/requests/{REQUEST_REF}"
    absent = _client(read_port=port, profile=None)

    class _ForgedPrincipal:
        def __init__(self, app: Any) -> None:
            self.app = app

        async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
            if scope.get("type") == "http":
                scope.setdefault("state", {})["trusted_principal"] = object()
            await self.app(scope, receive, send)

    forged_inner = FastAPI()
    forged_inner.include_router(build_idempotency_status_router(enabled=True, read_port=port))
    forged = TestClient(_ForgedPrincipal(forged_inner), base_url=BASE_URL)

    with absent, forged:
        missing_response = absent.get(path)
        forged_response = forged.get(path)

    assert missing_response.status_code == forged_response.status_code == 401
    assert missing_response.text == forged_response.text
    assert SECRET_CANARY not in missing_response.text
    assert port.calls == []


def test_missing_request_reference_is_fixed_and_does_not_echo_scope() -> None:
    port = _ReadPort()
    client = _client(read_port=port, profile=_profile())
    with client:
        response = client.get(
            "/mt-export/idempotency/requests/missing-opaque-ref",
            headers=_auth_headers(),
        )

    assert response.status_code == 404
    assert response.json() == {"error": "not_found"}
    assert port.calls == [("operator-alpha", "project-alpha", "missing-opaque-ref")]
    _assert_no_store(response)


def test_port_exception_and_invalid_binding_have_fixed_content_free_503() -> None:
    profile = _profile()
    path = f"/mt-export/idempotency/requests/{REQUEST_REF}"
    throwing_port = _ReadPort(error=RuntimeError(SECRET_CANARY))
    invalid_binding = RequestBindingV1(
        scope_fingerprint="a" * 64,
        payload_fingerprint="b" * 64,
        request_fingerprint="c" * 64,
    )
    invalid_port = _ReadPort(
        {(profile.principal_id, profile.project_id, REQUEST_REF): (None, invalid_binding)}
    )

    with _client(read_port=throwing_port, profile=profile) as exception_client:
        exception_response = exception_client.get(path, headers=_auth_headers())
    with _client(read_port=invalid_port, profile=profile) as invalid_client:
        invalid_response = invalid_client.get(path, headers=_auth_headers())

    assert exception_response.status_code == invalid_response.status_code == 503
    assert exception_response.json() == invalid_response.json() == {"error": "unavailable"}
    assert SECRET_CANARY not in exception_response.text
    assert SECRET_CANARY not in invalid_response.text
    assert len(throwing_port.calls) == len(invalid_port.calls) == 1


@pytest.mark.parametrize(
    ("prior_payload", "candidate_payload", "expected_status", "expected_reason"),
    (
        ({"field": "same"}, {"field": "same"}, "REPLAY", None),
        ({"field": "before"}, {"field": "after"}, "CONFLICT", "IDEMPOTENCY_CONFLICT"),
    ),
    ids=("same-content-replay", "changed-content-conflict"),
)
def test_success_is_a_closed_projection_of_exactly_one_scoped_read(
    prior_payload: dict[str, str],
    candidate_payload: dict[str, str],
    expected_status: str,
    expected_reason: str | None,
) -> None:
    profile = _profile()
    prior = _binding(
        project_id=profile.project_id,
        key=SECRET_CANARY,
        payload=prior_payload,
    )
    candidate = _binding(
        project_id=profile.project_id,
        key=SECRET_CANARY,
        payload=candidate_payload,
    )
    port = _ReadPort({(profile.principal_id, profile.project_id, REQUEST_REF): (prior, candidate)})

    with _client(read_port=port, profile=profile) as client:
        response = client.get(
            f"/mt-export/idempotency/requests/{REQUEST_REF}",
            headers=_auth_headers(),
        )

    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"status", "reason_code"}
    assert body["status"] == expected_status
    assert body["reason_code"] == expected_reason
    assert "request_fingerprint" not in body
    assert "fingerprint" not in response.text.lower()
    assert "payload" not in body
    assert "idempotency_key" not in body
    assert SECRET_CANARY not in response.text
    assert REQUEST_REF not in response.text
    assert port.calls == [(profile.principal_id, profile.project_id, REQUEST_REF)]
    _assert_no_store(response)


def test_same_reference_is_scoped_by_verified_principal_and_project() -> None:
    alpha = _profile(principal_id="operator-alpha", project_id="project-alpha")
    beta = _profile(principal_id="operator-beta", project_id="project-beta")
    alpha_prior = _binding(
        project_id=alpha.project_id, key="key-alpha", payload={"value": "before"}
    )
    alpha_candidate = _binding(
        project_id=alpha.project_id, key="key-alpha", payload={"value": "after"}
    )
    beta_candidate = _binding(project_id=beta.project_id, key="key-beta", payload={"value": "new"})
    port = _ReadPort(
        {
            (alpha.principal_id, alpha.project_id, REQUEST_REF): (
                alpha_prior,
                alpha_candidate,
            ),
            (beta.principal_id, beta.project_id, REQUEST_REF): (None, beta_candidate),
        }
    )

    with _client(read_port=port, profile=alpha) as alpha_client:
        alpha_response = alpha_client.get(
            f"/mt-export/idempotency/requests/{REQUEST_REF}", headers=_auth_headers()
        )
    with _client(read_port=port, profile=beta) as beta_client:
        beta_response = beta_client.get(
            f"/mt-export/idempotency/requests/{REQUEST_REF}", headers=_auth_headers()
        )

    assert alpha_response.status_code == beta_response.status_code == 200
    assert alpha_response.json()["status"] == "CONFLICT"
    assert beta_response.json()["status"] == "NEW"
    assert port.calls == [
        (alpha.principal_id, alpha.project_id, REQUEST_REF),
        (beta.principal_id, beta.project_id, REQUEST_REF),
    ]


def test_invalid_ascii_reference_is_rejected_without_echo_or_port_access() -> None:
    port = _ReadPort()
    client = _client(read_port=port, profile=_profile())
    invalid_ref = "api_key%3D" + SECRET_CANARY
    with client:
        response = client.get(
            f"/mt-export/idempotency/requests/{invalid_ref}", headers=_auth_headers()
        )

    assert response.status_code in {400, 404, 422}
    assert SECRET_CANARY not in response.text
    assert port.calls == []


def test_query_parameters_are_rejected_without_echo_or_port_access() -> None:
    port = _ReadPort()
    client = _client(read_port=port, profile=_profile())
    with client:
        response = client.get(
            f"/mt-export/idempotency/requests/{REQUEST_REF}?payload={SECRET_CANARY}",
            headers=_auth_headers(),
        )

    assert response.status_code == 400
    assert response.json() == {"error": "invalid_request"}
    assert SECRET_CANARY not in response.text
    assert port.calls == []


@pytest.mark.parametrize("method", ("POST", "PUT", "DELETE"))
def test_only_get_is_registered_and_write_methods_are_fixed_no_store_405(
    method: str,
) -> None:
    port = _ReadPort()
    router = build_idempotency_status_router(enabled=True, read_port=port)
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
            f"/mt-export/idempotency/requests/{REQUEST_REF}",
            headers={**_auth_headers(), "Origin": BASE_URL},
            json={"idempotency_key": SECRET_CANARY, "payload": SECRET_CANARY},
        )

    assert response.status_code == 405
    assert SECRET_CANARY not in response.text
    assert port.calls == []
    _assert_no_store(response)
