"""LEVIATHAN AI API gateway entrypoint.

Wires the engine (sovereign risk stack, council, paper spine) into the
HTTP surface: health, risk, pipeline replay, and the ØMEGA protocol.

Run:  uv run uvicorn leviathan_api.main:app --reload
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import replace
from typing import cast

import structlog
from fastapi import FastAPI, Request, Response
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from starlette.types import ASGIApp, Message, Receive, Scope, Send

import leviathan_core
from leviathan_api import __version__
from leviathan_api.auth.worker_assertion import (
    WorkerAssertionError,
    WorkerAssertionVerifier,
    worker_assertion_error_response,
)
from leviathan_api.credential_connections import (
    CredentialConnectionsRuntimeV1,
    create_credential_connections_router,
)
from leviathan_api.db import build_db
from leviathan_api.live_activation_runtime import LazyLiveActivationGateV1
from leviathan_api.middleware.license_gate import LicenseGateMiddleware
from leviathan_api.middleware.observation import ObservationPropagationMiddleware
from leviathan_api.observation_runtime import (
    build_observation_dependencies,
    operator_principal_resolver,
)
from leviathan_api.routers import (
    credentials,
    deployment_release_status,
    ea_template_catalog,
    genomes,
    journal,
    knowledge_archive,
    mcp_control,
    mt_export_agent_health_status,
    mt_export_build_status,
    mt_export_deploy_status,
    mt_export_idempotency_status,
    mt_export_rollback_status,
    omega,
    omega_tasks,
    order_activity,
    orders,
    pipeline,
    risk,
)
from leviathan_api.routers.orders import OrderRuntime
from leviathan_api.runtime_mounts import (
    RuntimeMountDependenciesV1,
    RuntimeMountStatusV1,
    close_runtime_mounts,
    configure_runtime_mounts,
)
from leviathan_api.settings import get_settings
from leviathan_api.state import AppState, build_app_state
from leviathan_api.wave35_mounts import (
    Wave35MountDependenciesV1,
    close_wave35_mounts,
    configure_wave35_mounts,
    wave35_mount_gate,
)
from leviathan_core.risk.halt import mutation_response_scope
from leviathan_core.risk.halt_store import HaltStoreError
from leviathan_vault.app_credentials import (
    MAX_REQUEST_BODY_BYTES,
    CredentialError,
    CredentialStore,
)

log = structlog.get_logger()
OrderRuntimeFactory = Callable[[AppState, async_sessionmaker[AsyncSession]], OrderRuntime]


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    state = build_app_state()
    app.state.leviathan = state
    engine = None
    try:
        engine, sessionmaker = await build_db(state.settings.database_url)
        app.state.engine = engine
        app.state.sessionmaker = sessionmaker
        factory: OrderRuntimeFactory | None = app.state.order_runtime_factory
        if factory is not None:
            state.orders = factory(state, sessionmaker)
            if state.dispatch_gate is not None:
                state.dispatch_gate.bind_runtime(state.orders)
        configure_runtime_mounts(
            app,
            app.state.runtime_mount_dependencies,
            logger=log,
            app_state=state,
        )
        configure_wave35_mounts(
            app,
            app.state.wave35_mount_dependencies,
            app_state=state,
        )
        initialize_history = getattr(app.state, "wave35_initialize_history", None)
        if callable(initialize_history):
            await initialize_history()
        log.info("leviathan_engine_ready", mode=state.settings.operating_mode.value)
        yield
    finally:
        try:
            await close_wave35_mounts(app)
        finally:
            try:
                close_runtime_mounts(app)
            finally:
                try:
                    if state.orders is not None:
                        await state.orders.close()
                finally:
                    try:
                        if engine is not None:
                            await engine.dispose()
                    finally:
                        state.halts.close()


async def runtime_mount_gate(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    path = request.url.path
    subsystem: str | None = None
    if path == "/v1/omega" or path.startswith("/v1/omega/"):
        subsystem = "omega_reason"
    elif path == "/mcp" or path.startswith("/mcp/"):
        subsystem = "mcp_reason"
    if subsystem is not None:
        status = getattr(request.app.state, "runtime_mount_status", None)
        valid_reasons = {
            None,
            "RUNTIME_NOT_CONFIGURED",
            "OMEGA_PORTS_UNAVAILABLE",
            "MCP_CONTROL_UNAVAILABLE",
        }
        if type(status) is not RuntimeMountStatusV1:
            return JSONResponse(
                status_code=503,
                content={"detail": "RUNTIME_NOT_CONFIGURED"},
                headers={"Cache-Control": "no-store"},
            )
        for reason_value in (status.omega_reason, status.mcp_reason):
            if type(reason_value) not in (str, type(None)) or reason_value not in valid_reasons:
                return JSONResponse(
                    status_code=503,
                    content={"detail": "RUNTIME_NOT_CONFIGURED"},
                    headers={"Cache-Control": "no-store"},
                )
        reason = getattr(status, subsystem)
        if reason is not None:
            return JSONResponse(
                status_code=503,
                content={"detail": reason},
                headers={"Cache-Control": "no-store"},
            )
    return await call_next(request)


async def halt_mutation_response(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    if request.method != "POST" or request.url.path not in {
        "/risk/halt",
        "/risk/halt/lift",
        "/omega/kill",
    }:
        response = await call_next(request)
        _suspend_orders_if_unsafe(request)
        return response
    with mutation_response_scope() as outcome:
        response = await call_next(request)
        _suspend_orders_if_unsafe(request)
        state = getattr(request.app.state, "leviathan", None)
        if state is not None and state.halts.fault_code is not None:
            return JSONResponse(
                status_code=503,
                content={
                    "detail": "HALT_STORE_UNAVAILABLE",
                    "commit_status": outcome.commit_status,
                },
            )
        return response


def _suspend_orders_if_unsafe(request: Request) -> None:
    state = getattr(request.app.state, "leviathan", None)
    if state is None or state.orders is None:
        return
    if state.halts.fault_code is not None or state.halts.halted or state.killed_providers:
        state.orders.suspend()


async def halt_store_failure(_request: Request, _exc: HaltStoreError) -> JSONResponse:
    return JSONResponse(
        status_code=503,
        content={
            "detail": "HALT_STORE_UNAVAILABLE",
            "commit_status": _exc.commit_status,
        },
    )


def _is_credential_path(request: Request) -> bool:
    return any(
        path in request.url.path
        for path in ("/live-trading/credentials", "/connections/credentials")
    )


async def credential_error(_request: Request, exc: CredentialError) -> JSONResponse:
    status_code = {
        "NOT_CONFIGURED": 503,
        "LIVE_CONFIRMATION_REQUIRED": 409,
        "NOT_FOUND": 404,
        "CORRUPT": 503,
        "UNAVAILABLE": 503,
        "PATH_DENIED": 422,
    }.get(exc.code, 422)
    return JSONResponse(
        status_code=status_code,
        content={"code": exc.code, "loc": list(exc.loc)},
        headers={"Cache-Control": "no-store"},
    )


async def worker_assertion_error(
    _request: Request, exc: Exception
) -> JSONResponse:
    status_code, content = worker_assertion_error_response(cast(WorkerAssertionError, exc))
    return JSONResponse(
        status_code=status_code,
        content=content,
        headers={"Cache-Control": "no-store"},
    )

async def credential_validation_error(request: Request, exc: Exception) -> JSONResponse:
    validation_error = cast(RequestValidationError, exc)
    if not _is_credential_path(request):
        return await request_validation_exception_handler(request, validation_error)
    locations = [
        [part for part in error.get("loc", ()) if type(part) in (str, int)]
        for error in validation_error.errors()
    ]
    if any(error.get("type") == "invalid_id" for error in validation_error.errors()):
        locations = [[part for part in loc if part != "body"] for loc in locations]
        return JSONResponse(
            status_code=422,
            content={"code": "INVALID_ID", "loc": locations},
            headers={"Cache-Control": "no-store"},
        )
    return JSONResponse(
        status_code=422,
        content={"code": "INVALID_REQUEST", "loc": locations},
        headers={"Cache-Control": "no-store"},
    )


async def credential_no_store(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    response = await call_next(request)
    if _is_credential_path(request):
        response.headers["Cache-Control"] = "no-store"
    return response


class CredentialBodyLimitMiddleware:
    """Bound mutation request buffering before FastAPI parses JSON."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if (
            scope["type"] != "http"
            or scope["method"] not in {"PUT", "DELETE"}
            or not any(
                path in scope["path"]
                for path in ("/live-trading/credentials", "/connections/credentials")
            )
        ):
            await self.app(scope, receive, send)
            return
        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        content_length = headers.get(b"content-length")
        if content_length is not None:
            try:
                if int(content_length) > MAX_REQUEST_BODY_BYTES:
                    await self._reject(send, 413, b'{"code":"REQUEST_TOO_LARGE","loc":["body"]}')
                    return
            except ValueError:
                await self._reject(
                    send, 400, b'{"code":"INVALID_REQUEST","loc":["headers","content-length"]}'
                )
                return
        buffered: list[Message] = []
        body_size = 0
        while True:
            message = await receive()
            buffered.append(message)
            if message["type"] == "http.disconnect":
                await self._reject(send, 400, b'{"code":"INVALID_REQUEST","loc":["body"]}')
                return
            if message["type"] == "http.request":
                body_size += len(message.get("body", b""))
                if body_size > MAX_REQUEST_BODY_BYTES:
                    await self._reject(send, 413, b'{"code":"REQUEST_TOO_LARGE","loc":["body"]}')
                    return
                if not message.get("more_body", False):
                    break
        index = 0

        async def replay() -> Message:
            nonlocal index
            if index >= len(buffered):
                return {"type": "http.disconnect"}
            current = buffered[index]
            index += 1
            return current

        await self.app(scope, replay, send)

    @staticmethod
    async def _reject(send: Send, status_code: int, body: bytes) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": status_code,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                    (b"cache-control", b"no-store"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body, "more_body": False})


def health(request: Request) -> dict[str, str] | JSONResponse:
    state = request.app.state.leviathan
    if state.halts.fault_code is not None:
        return JSONResponse(
            status_code=503,
            content={"status": "unhealthy", "fault_code": "HALT_STORE_UNAVAILABLE"},
        )
    settings = get_settings()
    return {
        "status": "ok",
        "service": "leviathan-api",
        "version": __version__,
        "core_version": leviathan_core.__version__,
        "operating_mode": settings.operating_mode.value,
        "env": settings.env,
    }


def create_app(
    *,
    order_runtime_factory: OrderRuntimeFactory | None = None,
    credential_store: CredentialStore | None = None,
    credential_connections_runtime: CredentialConnectionsRuntimeV1 | None = None,
    runtime_mount_dependencies: RuntimeMountDependenciesV1 | None = None,
    wave35_mount_dependencies: Wave35MountDependenciesV1 | None = None,
    desktop_operator_capability: str | None = None,
    desktop_operator_port: int | None = None,
    desktop_operator_profile: object | None = None,
    desktop_operator_features: frozenset[str] = frozenset(),
    worker_assertion_verifier: WorkerAssertionVerifier | None = None,
) -> FastAPI:
    """Build the API; a paper runtime can be injected only at startup."""
    application = FastAPI(
        title="LEVIATHAN AI",
        version=__version__,
        description="Black Wealth Capital — trading intelligence gateway. "
        "Capital permission, not prediction.",
        lifespan=lifespan,
    )
    application.state.order_runtime_factory = order_runtime_factory
    application.state.credential_store = credential_store
    application.state.worker_assertion_verifier = worker_assertion_verifier
    application.state.credential_connections_runtime = credential_connections_runtime
    application.state.runtime_mount_dependencies = (
        runtime_mount_dependencies or RuntimeMountDependenciesV1()
    )
    if wave35_mount_dependencies is None:
        settings = get_settings()
        application.state.wave35_mount_dependencies = Wave35MountDependenciesV1(
            credential_store=credential_store,
            credential_connections_runtime=credential_connections_runtime,
            profile_id="default",
            credential_environment="LIVE" if settings.env == "live" else "PAPER",
        )
    elif credential_store is not None and wave35_mount_dependencies.credential_store is None:
        application.state.wave35_mount_dependencies = replace(
            wave35_mount_dependencies,
            credential_store=credential_store,
            credential_connections_runtime=(
                credential_connections_runtime
                or wave35_mount_dependencies.credential_connections_runtime
            ),
        )
    elif (
        credential_connections_runtime is not None
        and wave35_mount_dependencies.credential_connections_runtime is None
    ):
        application.state.wave35_mount_dependencies = replace(
            wave35_mount_dependencies,
            credential_connections_runtime=credential_connections_runtime,
        )
    else:
        application.state.wave35_mount_dependencies = wave35_mount_dependencies
    if application.state.credential_store is None:
        connections_runtime = (
            application.state.wave35_mount_dependencies.credential_connections_runtime
        )
        application.state.credential_store = (
            connections_runtime.credential_store if connections_runtime is not None else None
        )
    application.state.live_activation_gate = LazyLiveActivationGateV1()
    credential_runtime_for_legacy_routes = (
        application.state.wave35_mount_dependencies.credential_connections_runtime
    )
    application.state.runtime_mount_status = RuntimeMountStatusV1(
        "RUNTIME_NOT_CONFIGURED", "RUNTIME_NOT_CONFIGURED"
    )
    observation_dependencies = build_observation_dependencies(get_settings(), application)
    observation_runtime = observation_dependencies.runtime
    observation_env = observation_dependencies.health_env
    is_incident_active = observation_dependencies.incident_active
    record_observation_event = observation_dependencies.event_sink
    application.add_middleware(
        ObservationPropagationMiddleware,
        principal_resolver=operator_principal_resolver,
        runtime=observation_runtime,
        service="api",
        component="http",
        health_env=observation_env,
        incident_active=is_incident_active,
        event_sink=record_observation_event,
        # Anonymous attribution until SEC-003 verifier wiring under DESKTOP-SIGNIN / API auth.
        anonymous_policy="attribute_anonymous",
    )
    application.middleware("http")(halt_mutation_response)
    application.middleware("http")(credential_no_store)
    application.middleware("http")(runtime_mount_gate)
    application.add_middleware(CredentialBodyLimitMiddleware)
    application.add_middleware(LicenseGateMiddleware)
    if desktop_operator_capability is not None or desktop_operator_port is not None:
        if desktop_operator_capability is None or desktop_operator_port is None:
            raise ValueError("desktop operator capability and port must be provided together")
        from leviathan_api.auth import OperatorPrincipalMiddleware

        # The desktop path reuses the same principal source used by W35 and chart
        # WebSockets. The optional profile is derived only from shell launch env;
        # an absent profile leaves requests anonymous and privileged routes fail closed.
        application.add_middleware(
            OperatorPrincipalMiddleware,
            capability=desktop_operator_capability,
            port=desktop_operator_port,
            profile=desktop_operator_profile,
            features=desktop_operator_features,
            allow_anonymous=desktop_operator_profile is None,
        )
    application.middleware("http")(wave35_mount_gate)
    application.add_exception_handler(HaltStoreError, halt_store_failure)  # type: ignore[arg-type]
    application.add_exception_handler(CredentialError, credential_error)  # type: ignore[arg-type]
    application.add_exception_handler(WorkerAssertionError, worker_assertion_error)
    application.add_exception_handler(RequestValidationError, credential_validation_error)
    for item in (
        risk.router,
        pipeline.router,
        journal.router,
        genomes.router,
        credentials.router,
        create_credential_connections_router(
            credential_runtime_for_legacy_routes,
            include_connections=False,
            include_legacy=True,
        ),
        omega.router,
        # Deployment-configured, fail-closed routers remain registered when unconfigured.
        omega_tasks.router,
        mcp_control.router,
        # OMS-PAPER-ACTIVITY-READ-001: read-only, PAPER-only, operator principal required.
        # Mounted before orders.router so /orders/activity is not captured by /orders/{order_id}.
        order_activity.create_order_activity_router(enabled=True),
        orders.router,
        knowledge_archive.router,
        ea_template_catalog.router,
        # Read-only status routers: disabled by default, fixed 503 until a port is wired.
        mt_export_build_status.router,
        mt_export_deploy_status.create_mt_export_deploy_status_router(),
        mt_export_rollback_status.create_router(),
        mt_export_idempotency_status.build_idempotency_status_router(),
        mt_export_agent_health_status.create_agent_health_status_router(),
        deployment_release_status.create_deployment_release_status_router(),
    ):
        application.include_router(item)
    application.add_api_route("/health", health, methods=["GET"], response_model=None)
    return application


app = create_app()
