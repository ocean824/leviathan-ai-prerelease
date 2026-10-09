"""Independent offline acceptance for the fixed EA template catalog API."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from leviathan_api.routers import ea_template_catalog
from leviathan_core.ea_builder.export_source import standard_template_catalog_v1
from leviathan_core.security.authz_models import (
    _VERIFIER_MARKER,
    PrincipalV1,
    TrustedPrincipalAdapterV1,
    TrustedPrincipalV1,
)

BASE_PATH = "/v1/ea/templates"
PROJECT_CANARY = "synthetic-private-project-canary"
_MISSING = object()


def _issued_principal() -> TrustedPrincipalV1:
    claims = PrincipalV1(
        principal_id="synthetic-catalog-reader",
        project_id=PROJECT_CANARY,
        roles=("ea.catalog.read",),
        env="test",
    )
    return TrustedPrincipalAdapterV1.from_verified_claims(
        claims, verifier_marker=_VERIFIER_MARKER
    )


def _forged_principal() -> TrustedPrincipalV1:
    """Build an exact-type principal without the adapter's seal."""
    claims = PrincipalV1(
        principal_id="synthetic-forged-reader",
        project_id="synthetic-forged-project",
        roles=("ea.catalog.read",),
        env="test",
    )
    forged = object.__new__(TrustedPrincipalV1)
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
        object.__setattr__(forged, field, getattr(claims, field))
    return forged


def _app(principal: object = _MISSING) -> FastAPI:
    api = FastAPI()
    api.include_router(ea_template_catalog.router)
    api.state.acceptance_principal = principal

    @api.middleware("http")
    async def inject_test_principal(request: Request, call_next: Any):
        value = api.state.acceptance_principal
        if value is not _MISSING:
            request.state.trusted_principal = value
        return await call_next(request)

    return api


def _expected_catalog() -> dict[str, object]:
    catalog = standard_template_catalog_v1()
    return {
        "catalog_id": catalog.catalog_id,
        "version": catalog.version,
        "catalog_digest": catalog.canonical_digest(),
        "templates": [
            {
                "template_id": f"{mapping.platform}:{mapping.block_id}",
                "block_id": mapping.block_id,
                "platform": mapping.platform,
            }
            for mapping in catalog.mappings
        ],
    }


def test_list_and_detail_are_metadata_projection_of_standard_catalog() -> None:
    expected = _expected_catalog()
    client = TestClient(_app(_issued_principal()))

    listed = client.get(BASE_PATH)
    assert listed.status_code == 200
    assert listed.json() == expected

    template = expected["templates"][0]
    assert isinstance(template, dict)
    detail = client.get(f"{BASE_PATH}/{template['template_id']}")
    assert detail.status_code == 200
    assert detail.json() == {
        "catalog_id": expected["catalog_id"],
        "version": expected["version"],
        "catalog_digest": expected["catalog_digest"],
        "template": template,
    }


@pytest.mark.parametrize("method", ("POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"))
@pytest.mark.parametrize("suffix", ("", "/MT4:bar_event"))
def test_catalog_routes_are_get_only(method: str, suffix: str) -> None:
    client = TestClient(_app(_issued_principal()))

    response = client.request(method, f"{BASE_PATH}{suffix}")

    assert response.status_code == 405


def test_catalog_response_contains_no_template_source_or_principal_data() -> None:
    client = TestClient(_app(_issued_principal()))
    response = client.get(BASE_PATH)

    assert response.status_code == 200
    payload = response.json()
    assert set(payload) == {"catalog_id", "version", "catalog_digest", "templates"}
    assert all(
        set(item) == {"template_id", "block_id", "platform"}
        for item in payload["templates"]
    )
    serialized = response.text.casefold()
    assert PROJECT_CANARY.casefold() not in serialized
    assert "source_text" not in serialized
    assert "graph_json" not in serialized
    assert '"secret' not in serialized


def test_missing_and_forged_principals_have_the_same_fixed_401() -> None:
    client = TestClient(_app(_issued_principal()))
    # First ensure this isolated app's injected issued principal reaches the route.
    assert client.get(BASE_PATH).status_code == 200

    client.app.state.acceptance_principal = _MISSING
    missing = client.get(BASE_PATH)
    client.app.state.acceptance_principal = _forged_principal()
    forged = client.get(BASE_PATH)

    assert missing.status_code == forged.status_code == 401
    assert missing.json() == forged.json() == {"detail": "AUTH_REQUIRED"}
    assert missing.text == forged.text


def test_query_and_unknown_template_errors_are_fixed_and_do_not_echo_input() -> None:
    client = TestClient(_app(_issued_principal()))
    secret_canary = "synthetic-query-secret-canary"

    invalid_query = client.get(f"{BASE_PATH}?token={secret_canary}")
    duplicate_query = client.get(f"{BASE_PATH}?page=1&page=2")
    unknown_template = client.get(f"{BASE_PATH}/MT4:{secret_canary}")

    assert invalid_query.status_code == duplicate_query.status_code == 400
    assert invalid_query.json() == duplicate_query.json() == {"detail": "INVALID_QUERY"}
    assert secret_canary not in invalid_query.text
    assert secret_canary not in duplicate_query.text
    assert unknown_template.status_code == 404
    assert unknown_template.json() == {"detail": "TEMPLATE_NOT_FOUND"}
    assert secret_canary not in unknown_template.text


def test_catalog_failure_is_content_free(monkeypatch: pytest.MonkeyPatch) -> None:
    secret_canary = "synthetic-catalog-internal-detail"

    def fail_catalog():
        raise RuntimeError(secret_canary)

    monkeypatch.setattr(ea_template_catalog, "standard_template_catalog_v1", fail_catalog)
    response = TestClient(_app(_issued_principal())).get(BASE_PATH)

    assert response.status_code == 503
    assert response.json() == {"detail": "CATALOG_UNAVAILABLE"}
    assert secret_canary not in response.text
