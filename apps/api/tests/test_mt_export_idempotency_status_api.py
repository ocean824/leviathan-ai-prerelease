"""Unit coverage for the fake-first duplicate-intent status router."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from leviathan_api.routers.mt_export_idempotency_status import (
    IdempotencyStatusRouteError,
    build_idempotency_status_router,
)
from leviathan_core.mt_export_idempotency import (
    DuplicateIntentStatusV1,
    ExportActionV1,
    RequestBindingV1,
    create_request_binding,
)
from leviathan_core.security.authz_models import (
    _VERIFIER_MARKER,
    PrincipalV1,
    TrustedPrincipalAdapterV1,
    TrustedPrincipalV1,
)

ROUTE = "/mt-export/idempotency/requests/ref-001"
KEY_CANARY = "secret-shaped-but-synthetic-key"
PAYLOAD_CANARY = "SYNTHETIC-PAYLOAD-CANARY"


def _principal(
    *, principal_id: str = "reader-1", project_id: str = "project-1"
) -> TrustedPrincipalV1:
    claims = PrincipalV1(
        principal_id=principal_id,
        project_id=project_id,
        roles=("operator",),
        env="paper",
    )
    return TrustedPrincipalAdapterV1.from_verified_claims(claims, verifier_marker=_VERIFIER_MARKER)


def _binding(
    *, key: str = "key-001", payload_value: str = "value-1", project_id: str = "project-1"
) -> RequestBindingV1:
    return create_request_binding(
        project_id=project_id,
        action=ExportActionV1.BUILD,
        idempotency_key=key,
        payload={"value": payload_value},
    )


class _Port:
    def __init__(
        self,
        rows: dict[tuple[str, str, str], tuple[RequestBindingV1 | None, RequestBindingV1] | None],
    ):
        self.rows = rows
        self.calls: list[tuple[TrustedPrincipalV1, str]] = []

    def read_bindings(
        self, *, principal: TrustedPrincipalV1, request_ref: str
    ) -> tuple[RequestBindingV1 | None, RequestBindingV1] | None:
        self.calls.append((principal, request_ref))
        return self.rows.get((principal.principal_id, principal.project_id, request_ref))


class _RaisingPort:
    def read_bindings(self, *, principal: TrustedPrincipalV1, request_ref: str) -> Any:
        raise RuntimeError(f"private canary: {PAYLOAD_CANARY} {KEY_CANARY}")


def _client(
    *,
    enabled: bool = True,
    port: object | None = None,
    current_principal: object | None = None,
) -> tuple[TestClient, list[object | None]]:
    app = FastAPI()
    app.include_router(
        build_idempotency_status_router(
            enabled=enabled,
            read_port=port,  # type: ignore[arg-type]
        )
    )
    current: list[object | None] = [current_principal]

    @app.middleware("http")
    async def inject_principal(request: Request, call_next: Callable[..., Any]):
        request.state.trusted_principal = current[0]
        return await call_next(request)

    return TestClient(app), current


def test_router_is_disabled_by_default_with_fixed_503() -> None:
    app = FastAPI()
    app.include_router(build_idempotency_status_router())
    with TestClient(app) as client:
        response = client.get(ROUTE)
    assert response.status_code == 503
    assert response.json() == {"error": "unavailable"}
    assert response.headers["cache-control"] == "no-store"


def test_portless_enabled_router_has_same_fixed_503() -> None:
    client, _ = _client(enabled=True)
    with client:
        response = client.get(ROUTE)
    assert response.status_code == 503
    assert response.json() == {"error": "unavailable"}


def test_factory_requires_typed_boolean_and_callable_port() -> None:
    with pytest.raises(IdempotencyStatusRouteError) as bad_enabled:
        build_idempotency_status_router(enabled="true")  # type: ignore[arg-type]
    assert str(bad_enabled.value) == "INVALID_CONFIGURATION"
    assert bad_enabled.value.__cause__ is None
    with pytest.raises(IdempotencyStatusRouteError) as bad_port:
        build_idempotency_status_router(enabled=True, read_port=object())  # type: ignore[arg-type]
    assert str(bad_port.value) == "INVALID_CONFIGURATION"


@pytest.mark.parametrize(
    ("prior", "candidate", "status", "reason"),
    [
        (None, _binding(), DuplicateIntentStatusV1.NEW, None),
        (_binding(), _binding(), DuplicateIntentStatusV1.REPLAY, None),
        (
            _binding(),
            _binding(payload_value="different"),
            DuplicateIntentStatusV1.CONFLICT,
            "IDEMPOTENCY_CONFLICT",
        ),
    ],
)
def test_get_returns_only_the_fixed_decision_fields(prior, candidate, status, reason) -> None:
    principal = _principal()
    port = _Port({(principal.principal_id, principal.project_id, "ref-001"): (prior, candidate)})
    client, _ = _client(port=port, current_principal=principal)
    with client:
        response = client.get(ROUTE)
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"status", "reason_code"}
    assert body == {
        "status": status.value,
        "reason_code": reason,
    }
    assert response.headers["cache-control"] == "no-store"
    assert port.calls == [(principal, "ref-001")]


def test_lookup_is_scoped_by_both_verified_principal_and_project() -> None:
    owner = _principal(principal_id="reader-owner", project_id="project-owner")
    other = _principal(principal_id="reader-other", project_id="project-other")
    candidate = _binding(project_id="project-owner")
    port = _Port({(owner.principal_id, owner.project_id, "ref-001"): (None, candidate)})
    client, current = _client(port=port, current_principal=owner)
    with client:
        assert client.get(ROUTE).status_code == 200
        current[0] = other
        denied = client.get(ROUTE)
    assert denied.status_code == 404
    assert denied.json() == {"error": "not_found"}
    assert len(port.calls) == 2 and port.calls[0][0] is owner and port.calls[1][0] is other


@pytest.mark.parametrize(
    "principal", [None, PrincipalV1("forged", "project-1", ("operator",), "paper")]
)
def test_missing_or_untrusted_principal_fails_before_port(principal: object | None) -> None:
    issued = _principal()
    port = _Port({(issued.principal_id, issued.project_id, "ref-001"): (None, _binding())})
    client, _ = _client(port=port, current_principal=principal)
    with client:
        response = client.get(ROUTE)
    assert response.status_code == 401
    assert response.json() == {"error": "unauthenticated"}
    assert port.calls == []


def test_unissued_principal_shape_is_denied() -> None:
    principal = _principal()
    forged = object.__new__(TrustedPrincipalV1)
    for name in (
        "principal_id",
        "project_id",
        "roles",
        "env",
        "venue",
        "portfolio",
        "strategy",
        "break_glass",
    ):
        object.__setattr__(forged, name, getattr(principal, name))
    port = _Port({})
    client, _ = _client(port=port, current_principal=forged)
    with client:
        response = client.get(ROUTE)
    assert response.status_code == 401
    assert response.json() == {"error": "unauthenticated"}
    assert port.calls == []


def test_unregistered_reference_is_fixed_not_found() -> None:
    principal = _principal()
    port = _Port({})
    client, _ = _client(port=port, current_principal=principal)
    with client:
        response = client.get(ROUTE)
    assert response.status_code == 404
    assert response.json() == {"error": "not_found"}
    assert port.calls == [(principal, "ref-001")]


@pytest.mark.parametrize("request_ref", ["bad/ref", "white space", "ümlaut", "x" * 129])
def test_invalid_reference_is_not_disclosed_or_looked_up(request_ref: str) -> None:
    principal = _principal()
    port = _Port({})
    client, _ = _client(port=port, current_principal=principal)
    with client:
        response = client.get(f"/mt-export/idempotency/requests/{request_ref}")
    assert response.status_code == 404
    assert response.json() == {"error": "not_found"}
    assert request_ref not in response.text
    assert port.calls == []


def test_query_inputs_are_rejected_before_lookup_and_never_echoed() -> None:
    principal = _principal()
    port = _Port({})
    client, _ = _client(port=port, current_principal=principal)
    with client:
        response = client.get(ROUTE + f"?idempotency_key={KEY_CANARY}&payload={PAYLOAD_CANARY}")
    assert response.status_code == 400
    assert response.json() == {"error": "invalid_request"}
    assert KEY_CANARY not in response.text and PAYLOAD_CANARY not in response.text
    assert port.calls == []


def test_port_exception_and_unissued_bindings_return_fixed_503() -> None:
    principal = _principal()
    client, _ = _client(port=_RaisingPort(), current_principal=principal)
    with client:
        raised = client.get(ROUTE)
    assert raised.status_code == 503
    assert raised.json() == {"error": "unavailable"}
    assert KEY_CANARY not in raised.text and PAYLOAD_CANARY not in raised.text

    issued = _binding()
    unissued = RequestBindingV1.model_validate(issued.model_dump())
    port = _Port({(principal.principal_id, principal.project_id, "ref-001"): (None, unissued)})
    client, _ = _client(port=port, current_principal=principal)
    with client:
        invalid = client.get(ROUTE)
    assert invalid.status_code == 503
    assert invalid.json() == {"error": "unavailable"}


def test_no_other_methods_are_registered() -> None:
    principal = _principal()
    candidate = _binding()
    port = _Port({(principal.principal_id, principal.project_id, "ref-001"): (None, candidate)})
    client, _ = _client(port=port, current_principal=principal)
    with client:
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            response = client.request(
                method, ROUTE, json={"key": KEY_CANARY, "payload": PAYLOAD_CANARY}
            )
            assert response.status_code == 405
            assert response.json() == {"error": "method_not_allowed"}
            assert response.headers["cache-control"] == "no-store"
            assert KEY_CANARY not in response.text and PAYLOAD_CANARY not in response.text
    assert port.calls == []


def test_response_never_contains_key_payload_reference_or_port_exception() -> None:
    principal = _principal()
    candidate = _binding(key=KEY_CANARY, payload_value=PAYLOAD_CANARY)
    port = _Port({(principal.principal_id, principal.project_id, "ref-001"): (None, candidate)})
    client, _ = _client(port=port, current_principal=principal)
    with client:
        response = client.get(ROUTE)
    for value in (
        KEY_CANARY,
        PAYLOAD_CANARY,
        "ref-001",
        principal.principal_id,
        principal.project_id,
    ):
        assert value not in response.text
    assert response.status_code == 200
