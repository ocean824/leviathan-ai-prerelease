"""Sanitized, read-only status API for registered data sources."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict

from leviathan_market_data.providers.registry import (
    DataSourceRegistryV1,
    DataSourceSnapshotV1,
)

_SCHEMA_VERSION: Literal["leviathan.data-sources/1"] = "leviathan.data-sources/1"


class DataSourcesResponseV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["leviathan.data-sources/1"]
    sources: tuple[DataSourceSnapshotV1, ...]


def create_data_sources_router(registry: DataSourceRegistryV1) -> APIRouter:
    """Build an unmounted router around the injected in-memory source registry."""
    if type(registry) is not DataSourceRegistryV1:
        raise TypeError("INVALID_DATA_SOURCE_REGISTRY")

    router = APIRouter(prefix="/data-sources", tags=["data-sources"])

    @router.get("", response_model=DataSourcesResponseV1)
    def read_data_sources(response: Response) -> DataSourcesResponseV1 | JSONResponse:
        response.headers["Cache-Control"] = "no-store"
        try:
            return DataSourcesResponseV1(
                schema_version=_SCHEMA_VERSION,
                sources=registry.list_sources(),
            )
        except Exception:
            return JSONResponse(
                status_code=503,
                content={"code": "DATA_SOURCES_UNAVAILABLE"},
                headers={"Cache-Control": "no-store"},
            )

    return router


__all__ = ["DataSourcesResponseV1", "create_data_sources_router"]
