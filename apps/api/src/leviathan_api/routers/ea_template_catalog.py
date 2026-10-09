"""Read-only HTTP projection of the standard EA template catalog."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from leviathan_core.ea_builder.export_source import (
    TemplateBindingV1,
    TemplateCatalogV1,
    standard_template_catalog_v1,
)
from leviathan_core.security.authz_models import (
    AuthorizationModelError,
    require_trusted_principal,
)

router = APIRouter(prefix="/v1/ea/templates", tags=["ea-template-catalog"])


def _error(status_code: int, code: str) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"detail": code})


def _authorized(request: Request) -> bool:
    principal = getattr(request.state, "trusted_principal", None)
    try:
        require_trusted_principal(principal)
    except AuthorizationModelError:
        return False
    return True


def _template_metadata(binding: TemplateBindingV1) -> dict[str, str]:
    return {
        "template_id": f"{binding.platform}:{binding.block_id}",
        "block_id": binding.block_id,
        "platform": binding.platform,
    }


def _catalog_response(
    catalog: TemplateCatalogV1,
    *,
    template: TemplateBindingV1 | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "catalog_id": catalog.catalog_id,
        "version": catalog.version,
        "catalog_digest": catalog.canonical_digest(),
    }
    if template is None:
        result["templates"] = [_template_metadata(item) for item in catalog.mappings]
    else:
        result["template"] = _template_metadata(template)
    return result


def _catalog_or_error() -> TemplateCatalogV1 | JSONResponse:
    try:
        return standard_template_catalog_v1()
    except Exception:
        return _error(503, "CATALOG_UNAVAILABLE")


def _query_error(request: Request) -> JSONResponse | None:
    if request.query_params.multi_items():
        return _error(400, "INVALID_QUERY")
    return None


@router.get("", response_model=None)
def get_template_catalog(request: Request) -> dict[str, Any] | JSONResponse:
    """Return stable identifiers and metadata, without template source bodies."""
    if not _authorized(request):
        return _error(401, "AUTH_REQUIRED")
    query_error = _query_error(request)
    if query_error is not None:
        return query_error
    catalog = _catalog_or_error()
    if isinstance(catalog, JSONResponse):
        return catalog
    try:
        return _catalog_response(catalog)
    except Exception:
        return _error(503, "CATALOG_UNAVAILABLE")


@router.get("/{template_id}", response_model=None)
def get_template_metadata(template_id: str, request: Request) -> dict[str, Any] | JSONResponse:
    """Return one metadata entry selected by its stable platform/block ID."""
    if not _authorized(request):
        return _error(401, "AUTH_REQUIRED")
    query_error = _query_error(request)
    if query_error is not None:
        return query_error
    catalog = _catalog_or_error()
    if isinstance(catalog, JSONResponse):
        return catalog
    template = next(
        (
            item
            for item in catalog.mappings
            if f"{item.platform}:{item.block_id}" == template_id
        ),
        None,
    )
    if template is None:
        return _error(404, "TEMPLATE_NOT_FOUND")
    try:
        return _catalog_response(catalog, template=template)
    except Exception:
        return _error(503, "CATALOG_UNAVAILABLE")


__all__ = ["router"]
