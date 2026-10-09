"""OBS-003 worker tests; principal issuance is synthetic and process-local."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from leviathan_api.middleware.observation import (
    ObservationCarrierV1,
    ObservationPropagationMiddleware,
    copy_observation_for_async_hop,
    current_observation,
)
from leviathan_core.observability import (
    BuildIdentityV1,
    DiagnosticIdFactoryV1,
    DiagnosticRegistriesV1,
    DiagnosticRuntimeV1,
    RegistrySnapshotV1,
)
from leviathan_core.security import principal_verifier as sec003
from leviathan_core.security.principal_verifier import VerifiedPrincipalV1


def _runtime() -> DiagnosticRuntimeV1:
    snapshot = RegistrySnapshotV1.from_members
    return DiagnosticRuntimeV1(
        registries=DiagnosticRegistriesV1(
            services=snapshot({"api"}),
            components=snapshot({"http"}),
            strategies=snapshot({"strategy-a"}),
            instruments=snapshot({"BTCUSD"}),
            venues=snapshot({"XNAS"}),
        ),
        id_factory=DiagnosticIdFactoryV1(uuid4_factory=uuid4),
        build_identity=BuildIdentityV1("1.2.3"),
    )


def _verified_principal() -> VerifiedPrincipalV1:
    """Create a test-only sealed value at the already-verified boundary."""
    value = VerifiedPrincipalV1(
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


def _middleware(
    app: FastAPI,
    resolver: Callable[[Request], VerifiedPrincipalV1 | None],
    **kwargs: Any,
) -> ObservationPropagationMiddleware:
    return ObservationPropagationMiddleware(
        app,
        principal_resolver=resolver,
        runtime=_runtime(),
        service="api",
        component="http",
        **kwargs,
    )


def test_valid_remote_parent_links_but_does_not_replace_minted_context() -> None:
    app = FastAPI()
    principal = _verified_principal()
    states: list[dict[str, object]] = []

    def resolve(request: Request) -> VerifiedPrincipalV1:
        states.append(request.scope["state"])
        return principal

    @app.get("/protected")
    async def protected() -> dict[str, object]:
        carrier = current_observation()
        assert carrier is not None
        return {
            "trace_id": carrier.context.trace_id,
            "parent_trace_id": carrier.remote_parent.trace_id if carrier.remote_parent else None,
            "remote_correlation_id": carrier.remote_correlation_id,
            "remote_request_id": carrier.remote_request_id,
            "principal_in_carrier": hasattr(carrier, "principal"),
        }

    middleware = _middleware(app, resolve)
    trace_id = "4bf92f3577b34da6a3ce929d0e0e4736"
    parent_id = "00f067aa0ba902b7"
    with TestClient(middleware) as client:
        response = client.get(
            "/protected",
            headers={
                "traceparent": f"00-{trace_id}-{parent_id}-01",
                "tracestate": "vendor=value,other=ok",
                "x-correlation-id": "bad-correlation",
                "x-request-id": "caller controlled",
                "x-halt": "disabled",
            },
        )

    assert response.status_code == 200
    body = response.json()
    assert body["parent_trace_id"] == trace_id
    assert body["trace_id"] != trace_id
    assert body["remote_correlation_id"] is None
    assert body["remote_request_id"] is None
    assert body["principal_in_carrier"] is False
    assert response.headers["tracestate"] == "vendor=value,other=ok"
    output_parent, output_trace, output_span, output_flags = response.headers["traceparent"].split(
        "-"
    )
    assert (output_parent, output_flags) == ("00", "00")
    assert output_trace == body["trace_id"]
    assert output_span != parent_id
    assert UUID(response.headers["x-correlation-id"]).version == 4
    assert UUID(response.headers["x-request-id"]).version == 4
    assert response.headers["x-request-id"] != "caller-controlled"
    assert middleware.traceparent_invalid_count == 0
    assert middleware.invalid_correlation_id_count == 1
    assert middleware.invalid_request_id_count == 1
    state = states[0]
    assert "observation_latency" in state
    assert "principal" not in state["observation_carrier"].__dataclass_fields__


def test_valid_inbound_request_ids_are_links_not_local_ids() -> None:
    app = FastAPI()
    principal = _verified_principal()

    @app.get("/protected")
    async def protected() -> dict[str, str | None]:
        carrier = current_observation()
        assert carrier is not None
        return {
            "correlation": carrier.remote_correlation_id,
            "request": carrier.remote_request_id,
            "local_request": carrier.context.request_id,
        }

    inbound_correlation = "12345678-1234-4234-9234-123456789abc"
    inbound_request = "remote.request/7"
    middleware = _middleware(app, lambda _request: principal)
    with TestClient(middleware) as client:
        response = client.get(
            "/protected",
            headers={
                "x-correlation-id": inbound_correlation,
                "x-request-id": inbound_request,
            },
        )
    assert response.status_code == 200
    assert response.json() == {
        "correlation": inbound_correlation,
        "request": inbound_request,
        "local_request": response.headers["x-request-id"],
    }
    assert response.headers["x-request-id"] != inbound_request
    assert middleware.invalid_correlation_id_count == 0
    assert middleware.invalid_request_id_count == 0


@pytest.mark.parametrize("resolver_mode", ["missing", "unsealed", "raises"])
def test_unverified_principal_fails_closed_without_running_route(resolver_mode: str) -> None:
    app = FastAPI()
    route_called = False
    secret_marker = "synthetic-resolver-value-must-not-leak"

    def resolve(_request: Request) -> object:
        if resolver_mode == "raises":
            raise RuntimeError(secret_marker)
        if resolver_mode == "unsealed":
            return VerifiedPrincipalV1(
                _construction_marker=sec003._CONSTRUCTION_MARKER,
                issuer="issuer.synthetic",
                audience="api.synthetic",
                org_id="org.synthetic",
                project_id="project.synthetic",
                subject_id="subject.synthetic",
                role="reader",
                scopes=("research.read",),
                env="test",
                venue=None,
                portfolio=None,
                strategy=None,
                jti="jti.synthetic",
                issued_at_ns=1,
                expires_at_ns=2,
                verified_at_ns=1,
                certificate_binding=None,
            )
        return None

    @app.get("/protected")
    async def protected() -> dict[str, str]:
        nonlocal route_called
        route_called = True
        return {"status": "unexpected"}

    middleware = _middleware(app, resolve)
    with TestClient(middleware) as client:
        response = client.get("/protected")

    assert response.status_code == 401
    assert response.json() == {"detail": "UNAUTHENTICATED"}
    assert route_called is False
    assert secret_marker not in response.text
    assert "traceparent" in response.headers
    assert "x-correlation-id" in response.headers
    assert "x-request-id" in response.headers


def test_missing_principal_can_be_attributed_anonymously_when_configured() -> None:
    app = FastAPI()
    route_state: list[dict[str, object]] = []

    @app.get("/anonymous")
    async def anonymous(request: Request) -> dict[str, object]:
        route_state.append(request.scope["state"])
        return {"status": "ok"}

    middleware = _middleware(
        app,
        lambda _request: None,
        anonymous_policy="attribute_anonymous",
    )
    with TestClient(middleware) as client:
        response = client.get("/anonymous")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert route_state[0]["observation_principal_id"] is None
    assert route_state[0]["observation_principal_source"] == "anonymous"
    assert response.headers["traceparent"].startswith("00-")


def test_default_anonymous_policy_is_reject() -> None:
    middleware = _middleware(FastAPI(), lambda _request: None)
    assert middleware.anonymous_policy == "reject"


def test_unknown_anonymous_policy_is_rejected() -> None:
    with pytest.raises(ValueError, match=r"^anonymous policy is invalid$"):
        _middleware(FastAPI(), lambda _request: None, anonymous_policy="fallback")


def test_configured_health_exempt_skips_principal_resolver() -> None:
    app = FastAPI()
    calls = 0

    def resolve(_request: Request) -> None:
        nonlocal calls
        calls += 1
        return None

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    middleware = _middleware(app, resolve)
    with TestClient(middleware) as client:
        response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert calls == 0
    assert "/api/health" in middleware.exempt_paths
    assert middleware.exempt_paths == frozenset({"/health", "/api/health"})


@pytest.mark.parametrize(
    "headers",
    [
        [(b"traceparent", b"00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01")],
        [(b"traceparent", b"00-00000000000000000000000000000000-00f067aa0ba902b7-00")],
        [
            (b"traceparent", b"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
            (b"traceparent", b"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b8-01"),
        ],
    ],
)
def test_invalid_or_duplicate_traceparent_is_ignored_and_counted(headers) -> None:
    app = FastAPI()
    principal = _verified_principal()

    @app.get("/protected")
    async def protected() -> dict[str, str | None]:
        carrier = current_observation()
        assert carrier is not None
        return {
            "trace_id": carrier.context.trace_id,
            "parent_trace_id": carrier.remote_parent.trace_id if carrier.remote_parent else None,
        }

    middleware = _middleware(app, lambda _request: principal)
    raw_headers = [(b"host", b"testserver"), *headers, (b"tracestate", b"vendor=value")]
    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/protected",
        "raw_path": b"/protected",
        "query_string": b"",
        "headers": raw_headers,
        "server": ("testserver", 80),
        "client": ("testclient", 50000),
    }
    sent: list[dict[str, object]] = []

    async def receive() -> dict[str, object]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict[str, object]) -> None:
        sent.append(message)

    asyncio.run(middleware(scope, receive, send))
    response_headers = dict(sent[0]["headers"])
    assert middleware.traceparent_invalid_count == 1
    assert b"tracestate" not in response_headers
    body_message = next(item for item in sent if item["type"] == "http.response.body")
    body = json.loads(body_message["body"])
    assert body["parent_trace_id"] is None
    assert response_headers[b"traceparent"].decode().split("-")[1] == body["trace_id"]


def test_invalid_tracestate_is_dropped_but_valid_traceparent_is_linked() -> None:
    app = FastAPI()
    principal = _verified_principal()

    @app.get("/protected")
    async def protected() -> dict[str, str | None]:
        carrier = current_observation()
        assert carrier is not None
        return {"parent": carrier.remote_parent.trace_id if carrier.remote_parent else None}

    middleware = _middleware(app, lambda _request: principal)
    with TestClient(middleware) as client:
        response = client.get(
            "/protected",
            headers={
                "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00",
                "tracestate": "vendor=one,vendor=duplicate",
            },
        )
    assert response.status_code == 200
    assert response.json()["parent"] == "4bf92f3577b34da6a3ce929d0e0e4736"
    assert "tracestate" not in response.headers


def test_explicit_async_hop_copies_only_observation_context() -> None:
    app = FastAPI()
    principal = _verified_principal()

    @app.get("/protected")
    async def protected() -> dict[str, bool]:
        original = current_observation()
        copied = copy_observation_for_async_hop()

        async def child() -> tuple[ObservationCarrierV1 | None, ObservationCarrierV1 | None]:
            return current_observation(), copied

        inherited, explicit_copy = await asyncio.create_task(child())
        assert original is not None and copied is not None
        assert inherited is original
        assert explicit_copy is copied
        return {
            "copied_context_is_new": copied.context is not original.context,
            "trace_is_preserved": copied.context.trace_id == original.context.trace_id,
            "correlation_is_preserved": (
                copied.context.correlation_id == original.context.correlation_id
            ),
            "span_is_new": copied.context.span_id != original.context.span_id,
            "parent_is_local_span": copied.parent_span_id == original.context.span_id,
            "remote_parent_is_not_reused": copied.remote_parent is None,
            "principal_is_absent": not hasattr(copied, "principal"),
        }

    middleware = _middleware(app, lambda _request: principal)
    with TestClient(middleware) as client:
        response = client.get("/protected")
    assert response.status_code == 200
    assert response.json() == {
        "copied_context_is_new": True,
        "trace_is_preserved": True,
        "correlation_is_preserved": True,
        "span_is_new": True,
        "parent_is_local_span": True,
        "remote_parent_is_not_reused": True,
        "principal_is_absent": True,
    }


def test_nested_and_concurrent_async_hops_form_distinct_child_spans() -> None:
    app = FastAPI()
    principal = _verified_principal()

    @app.get("/protected")
    async def protected() -> dict[str, object]:
        root = current_observation()
        assert root is not None
        first = copy_observation_for_async_hop(root)
        assert first is not None
        second = copy_observation_for_async_hop(first)
        assert second is not None

        async def concurrent_hop() -> ObservationCarrierV1:
            await asyncio.sleep(0)
            child = copy_observation_for_async_hop()
            assert child is not None
            return child

        concurrent = await asyncio.gather(*(concurrent_hop() for _ in range(16)))
        children = [first, second, *concurrent]
        spans = [child.context.span_id for child in children]
        return {
            "root_span": root.context.span_id,
            "root_remote_parent": (
                root.remote_parent.parent_span_id if root.remote_parent else None
            ),
            "first": {
                "span": first.context.span_id,
                "parent": first.parent_span_id,
                "remote_parent": first.remote_parent,
            },
            "second": {
                "span": second.context.span_id,
                "parent": second.parent_span_id,
                "remote_parent": second.remote_parent,
            },
            "concurrent_parents": [child.parent_span_id for child in concurrent],
            "concurrent_spans_unique": len(set(spans)) == len(spans),
            "trace_preserved": all(
                child.context.trace_id == root.context.trace_id for child in children
            ),
            "correlation_preserved": all(
                child.context.correlation_id == root.context.correlation_id for child in children
            ),
        }

    middleware = _middleware(app, lambda _request: principal)
    trace_id = "4bf92f3577b34da6a3ce929d0e0e4736"
    parent_span_id = "00f067aa0ba902b7"
    with TestClient(middleware) as client:
        response = client.get(
            "/protected",
            headers={
                "traceparent": f"00-{trace_id}-{parent_span_id}-01",
            },
        )

    assert response.status_code == 200
    result = response.json()
    root_span = result["root_span"]
    first = result["first"]
    second = result["second"]
    assert result["root_remote_parent"] == parent_span_id
    assert first["span"] != root_span
    assert first["parent"] == root_span
    assert first["remote_parent"] is None
    assert second["span"] != first["span"]
    assert second["parent"] == first["span"]
    assert second["remote_parent"] is None
    assert result["concurrent_parents"] == [root_span] * 16
    assert result["concurrent_spans_unique"] is True
    assert result["trace_preserved"] is True
    assert result["correlation_preserved"] is True


@pytest.mark.parametrize("status_code", [400, 500])
def test_error_requests_are_sampled_and_event_sink_is_redacted(status_code: int) -> None:
    app = FastAPI()
    principal = _verified_principal()
    events = []
    captured_state: list[dict[str, object]] = []

    def resolve(request: Request) -> VerifiedPrincipalV1:
        captured_state.append(request.scope["state"])
        return principal

    @app.get("/protected")
    async def protected() -> Any:
        from starlette.responses import JSONResponse

        return JSONResponse(
            {"detail": "synthetic secret never passed to observation sink"},
            status_code=status_code,
        )

    middleware = _middleware(
        app,
        resolve,
        sample_healthy=lambda: False,
        event_sink=events.append,
        monotonic_ns_clock=iter([100, 350]).__next__,
        utc_ns_clock=lambda: 1_726_000_000_000_000_000,
    )
    with TestClient(middleware) as client:
        response = client.get("/protected")

    assert response.status_code == status_code
    assert len(events) == 1
    assert events[0].status_code == status_code
    assert "synthetic secret" not in repr(events[0])
    assert captured_state[0]["observation_latency"].duration_ns == 250
    assert captured_state[0]["observation_latency"].timestamp_utc_ns == 1_726_000_000_000_000_000


def test_client_incident_flag_does_not_control_sampling() -> None:
    app = FastAPI()
    principal = _verified_principal()
    events = []

    @app.get("/healthy")
    async def healthy() -> dict[str, str]:
        return {"status": "ok"}

    middleware = _middleware(
        app,
        lambda _request: principal,
        incident_active=lambda: False,
        sample_healthy=lambda: False,
        event_sink=events.append,
    )
    with TestClient(middleware) as client:
        normal = client.get("/healthy", headers={"x-incident": "true"})
    assert normal.status_code == 200
    assert events == []


def test_trusted_incident_mode_samples_healthy_request() -> None:
    app = FastAPI()
    principal = _verified_principal()
    events = []

    @app.get("/healthy")
    async def healthy() -> dict[str, str]:
        return {"status": "ok"}

    middleware = _middleware(
        app,
        lambda _request: principal,
        incident_active=lambda: True,
        sample_healthy=lambda: False,
        event_sink=events.append,
    )
    with TestClient(middleware) as client:
        response = client.get("/healthy")
    assert response.status_code == 200
    assert len(events) == 1
    assert events[0].status_code == 200
