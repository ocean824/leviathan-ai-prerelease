from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from leviathan_api.routers import ea_template_catalog
from leviathan_api.routers.ea_template_catalog import router
from leviathan_core.ea_builder.export_source import standard_template_catalog_v1
from leviathan_core.security.authz_models import (
    _VERIFIER_MARKER,
    PrincipalV1,
    TrustedPrincipalAdapterV1,
)

CANARY = "synthetic-query-secret-canary"


def _principal() -> object:
    claims = PrincipalV1(
        principal_id="synthetic-ea-reader",
        project_id="synthetic-project",
        roles=("operator",),
        env="development",
    )
    return TrustedPrincipalAdapterV1.from_verified_claims(
        claims,
        verifier_marker=_VERIFIER_MARKER,
    )


def _client(*, principal: object = _principal()) -> TestClient:
    app = FastAPI()
    app.include_router(router)

    @app.middleware("http")
    async def set_principal(request, call_next):
        request.state.trusted_principal = principal
        return await call_next(request)

    return TestClient(app)


def test_get_catalog_returns_only_stable_metadata_and_digest() -> None:
    catalog = standard_template_catalog_v1()

    with _client() as client:
        response = client.get("/v1/ea/templates")

    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"catalog_id", "version", "catalog_digest", "templates"}
    assert body["catalog_id"] == catalog.catalog_id
    assert body["version"] == catalog.version
    assert body["catalog_digest"] == catalog.canonical_digest()
    assert body["templates"] == [
        {
            "template_id": f"{item.platform}:{item.block_id}",
            "block_id": item.block_id,
            "platform": item.platform,
        }
        for item in catalog.mappings
    ]
    assert all(set(item) == {"template_id", "block_id", "platform"} for item in body["templates"])


def test_get_template_returns_metadata_without_template_body() -> None:
    binding = standard_template_catalog_v1().mappings[0]
    template_id = f"{binding.platform}:{binding.block_id}"

    with _client() as client:
        response = client.get(f"/v1/ea/templates/{template_id}")

    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"catalog_id", "version", "catalog_digest", "template"}
    assert body["catalog_digest"] == standard_template_catalog_v1().canonical_digest()
    assert body["template"] == {
        "template_id": template_id,
        "block_id": binding.block_id,
        "platform": binding.platform,
    }


@pytest.mark.parametrize(
    ("principal", "request_path"),
    (
        (None, "/v1/ea/templates"),
        (CANARY, "/v1/ea/templates"),
        (None, "/v1/ea/templates/MT4:bar_event"),
        (CANARY, "/v1/ea/templates/MT4:bar_event"),
    ),
)
def test_missing_or_forged_principal_has_uniform_content_free_401(
    principal: object,
    request_path: str,
) -> None:
    app = FastAPI()
    app.include_router(router)
    if principal is not None:

        @app.middleware("http")
        async def set_forged_principal(request, call_next):
            request.state.trusted_principal = principal
            return await call_next(request)

    with TestClient(app) as client:
        response = client.get(request_path)

    assert response.status_code == 401
    assert response.json() == {"detail": "AUTH_REQUIRED"}
    assert CANARY not in response.text


def test_query_parameters_are_rejected_without_echo() -> None:
    with _client() as client:
        response = client.get("/v1/ea/templates", params={"unrecognized": CANARY})

    assert response.status_code == 400
    assert response.json() == {"detail": "INVALID_QUERY"}
    assert CANARY not in response.text


def test_duplicate_query_parameters_are_rejected_without_echo() -> None:
    with _client() as client:
        response = client.get(f"/v1/ea/templates?filter={CANARY}&filter=second")

    assert response.status_code == 400
    assert response.json() == {"detail": "INVALID_QUERY"}
    assert CANARY not in response.text


def test_unknown_template_id_is_fixed_and_never_echoes_input() -> None:
    with _client() as client:
        response = client.get(f"/v1/ea/templates/{CANARY}")

    assert response.status_code == 404
    assert response.json() == {"detail": "TEMPLATE_NOT_FOUND"}
    assert CANARY not in response.text


def test_catalog_failure_is_fixed_and_never_echoes_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail() -> object:
        raise RuntimeError(CANARY)

    monkeypatch.setattr(ea_template_catalog, "standard_template_catalog_v1", fail)

    with _client() as client:
        response = client.get("/v1/ea/templates")

    assert response.status_code == 503
    assert response.json() == {"detail": "CATALOG_UNAVAILABLE"}
    assert CANARY not in response.text


def test_mutating_methods_are_not_registered() -> None:
    with _client() as client:
        response = client.post("/v1/ea/templates")

    assert response.status_code == 405
