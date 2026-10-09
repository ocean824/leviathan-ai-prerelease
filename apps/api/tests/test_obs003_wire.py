"""OBS-003 app registration and nonblocking sink wiring tests."""

from __future__ import annotations

import logging
import time
from threading import Event
from typing import cast

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from starlette.types import ASGIApp, Receive, Scope, Send

from leviathan_api.main import CredentialBodyLimitMiddleware, create_app
from leviathan_api.middleware.observation import (
    ObservationPropagationMiddleware,
    ObservationRequestEventV1,
    current_observation,
)
from leviathan_api.observation_runtime import (
    NonBlockingObservationEventSinkV1,
    ObservationRuntimeConfigError,
    ObservationRuntimeConfigV1,
    build_observation_dependencies,
    build_observation_runtime,
    operator_principal_resolver,
)
from leviathan_api.settings import Settings, get_settings
from leviathan_core.observability import ObservationContextV1
from leviathan_core.security import principal_verifier as sec003
from leviathan_core.security.authz_models import PrincipalV1, TrustedPrincipalAdapterV1
from leviathan_core.security.principal_verifier import VerifiedPrincipalV1

_TRACE_ID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
_PARENT_ID = "bbbbbbbbbbbbbbbb"


def _issued_verified_principal() -> VerifiedPrincipalV1:
    value = sec003.VerifiedPrincipalV1(
        _construction_marker=sec003._CONSTRUCTION_MARKER,
        issuer="issuer.synthetic",
        audience="api.synthetic",
        org_id="org.synthetic",
        project_id="project.synthetic",
        subject_id="subject.synthetic",
        role="reader",
        scopes=("research.read",),
        env="development",
        venue=None,
        portfolio=None,
        strategy=None,
        jti="jti.synthetic",
        issued_at_ns=1,
        expires_at_ns=2,
        verified_at_ns=1,
        certificate_binding=None,
    )
    return sec003._SEALED.issue(value)


class _UpstreamVerifiedPrincipalMiddleware:
    """Test-only upstream auth adapter representing SEC-003 verification."""

    def __init__(self, app: ASGIApp, *, principal: object) -> None:
        self.app = app
        self.principal = principal

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            scope.setdefault("state", {})["verified_principal"] = self.principal
        await self.app(scope, receive, send)


def test_create_app_registers_observation_inside_body_limit_and_after_upstream_auth() -> None:
    app = create_app()
    middleware_types: list[object] = [cast(object, item.cls) for item in app.user_middleware]
    observation_index = middleware_types.index(cast(object, ObservationPropagationMiddleware))
    body_limit_index = middleware_types.index(cast(object, CredentialBodyLimitMiddleware))
    assert body_limit_index < observation_index

    # Adding upstream auth through Starlette's public API wraps the app outside
    # both middleware; it must populate verified_principal before observation.
    app.add_middleware(
        _UpstreamVerifiedPrincipalMiddleware,
        principal=_issued_verified_principal(),
    )
    middleware_types = [cast(object, item.cls) for item in app.user_middleware]
    upstream_auth_index = middleware_types.index(cast(object, _UpstreamVerifiedPrincipalMiddleware))
    assert upstream_auth_index < middleware_types.index(
        cast(object, ObservationPropagationMiddleware)
    )

    @app.get("/_obs003-wire/probe")
    async def probe(request: Request) -> dict[str, object]:
        carrier = current_observation()
        assert carrier is not None
        principal = request.state.verified_principal
        return {
            "principal_resolved": operator_principal_resolver(request) is principal,
            "local_trace_id": carrier.context.trace_id,
            "remote_trace_id": carrier.remote_parent.trace_id if carrier.remote_parent else None,
        }

    with TestClient(app) as client:
        response = client.get(
            "/_obs003-wire/probe",
            headers={"traceparent": f"00-{_TRACE_ID}-{_PARENT_ID}-01"},
        )
    assert response.status_code == 200
    body = response.json()
    assert body["principal_resolved"] is True
    assert body["local_trace_id"] != _TRACE_ID
    assert body["remote_trace_id"] == _TRACE_ID
    assert response.headers["traceparent"].startswith(f"00-{body['local_trace_id']}-")


def test_unauthenticated_request_is_handled_without_resolver_failure() -> None:
    app = create_app()

    @app.get("/_obs003-wire/anonymous")
    async def anonymous(request: Request) -> dict[str, object]:
        return {
            "principal_id": request.state.observation_principal_id,
            "principal_source": request.state.observation_principal_source,
        }

    with TestClient(app) as client:
        openapi_response = client.get("/openapi.json")
        response = client.get("/_obs003-wire/anonymous")
    assert openapi_response.status_code == 200
    assert openapi_response.headers.get("traceparent", "").startswith("00-")
    assert response.status_code == 200
    assert response.json() == {"principal_id": None, "principal_source": "anonymous"}
    assert response.headers.get("traceparent", "").startswith("00-")


def test_operator_principal_is_not_upgraded_to_sec003_verified_principal() -> None:
    claims = PrincipalV1(
        principal_id="operator.synthetic",
        project_id="project.synthetic",
        roles=("operator",),
        env="development",
    )
    trusted = TrustedPrincipalAdapterV1.from_verified_claims(
        claims,
        verifier_marker=sec003._VERIFIER_MARKER,  # type: ignore[attr-defined]
    )
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/protected",
            "headers": [],
            "state": {"trusted_principal": trusted},
        }
    )
    assert operator_principal_resolver(request) is None


def test_runtime_uses_configured_health_environment_and_closed_registries() -> None:
    runtime = build_observation_runtime(Settings(env="staging"))
    assert runtime.registries.services.members == frozenset({"api"})
    assert runtime.registries.components.members == frozenset({"http"})
    assert runtime.build_identity.version


def test_paper_desktop_smoke_settings_default_observation_runtime(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    # This mirrors the environment set by tests/paper_smoke/desktop_harness.py.
    monkeypatch.setenv("LEVIATHAN_ENV", "paper")
    monkeypatch.setenv("LEVIATHAN_OPERATING_MODE", "research")
    get_settings.cache_clear()
    try:
        with caplog.at_level(logging.WARNING, logger="leviathan_api.observation_runtime"):
            app = create_app()
        observation_middleware = next(
            item
            for item in app.user_middleware
            if cast(object, item.cls) is cast(object, ObservationPropagationMiddleware)
        )
        assert observation_middleware.kwargs["health_env"] == "development"
        sink = observation_middleware.kwargs["event_sink"]
        assert isinstance(sink, NonBlockingObservationEventSinkV1)
        assert sink._queue.maxsize == 256
        default_messages = [
            record.getMessage()
            for record in caplog.records
            if record.name == "leviathan_api.observation_runtime"
            and record.getMessage() == "OBSERVATION_RUNTIME_DEFAULTED"
        ]
        assert default_messages == ["OBSERVATION_RUNTIME_DEFAULTED"]
    finally:
        get_settings.cache_clear()


def test_explicit_malformed_observation_config_remains_a_typed_error(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with (
        caplog.at_level(logging.WARNING, logger="leviathan_api.observation_runtime"),
        pytest.raises(ObservationRuntimeConfigError) as error,
    ):
        build_observation_dependencies(
            Settings(env="development"),
            FastAPI(),
            config=ObservationRuntimeConfigV1(health_env="paper"),
        )
    assert str(error.value) == "OBSERVATION_RUNTIME_INVALID"
    assert not any(
        record.getMessage() == "OBSERVATION_RUNTIME_DEFAULTED" for record in caplog.records
    )


def test_slow_event_consumer_never_blocks_request_thread() -> None:
    runtime = build_observation_runtime(Settings(env="development"))
    context = ObservationContextV1.create(
        runtime=runtime,
        service="api",
        component="http",
        env="development",
        trace=True,
    )
    event = ObservationRequestEventV1(
        context=context,
        status_code=200,
        timestamp_utc_ns=1,
        duration_ns=1,
    )
    entered = Event()
    release = Event()

    def slow_consumer(_event: ObservationRequestEventV1) -> None:
        entered.set()
        release.wait(timeout=2)

    sink = NonBlockingObservationEventSinkV1(capacity=1, consumer=slow_consumer)
    sink(event)
    assert entered.wait(timeout=1)
    sink(event)  # fills the bounded queue while the consumer is blocked
    start = time.perf_counter()
    sink(event)  # full queue drops; it never waits for the slow consumer
    elapsed = time.perf_counter() - start
    release.set()
    sink._queue.join()
    assert elapsed < 0.1
    assert sink.dropped_count == 1
