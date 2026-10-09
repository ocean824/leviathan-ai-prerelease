"""Independent OBS-003 acceptance mapped to the propagation contract.

Requirement-to-case matrix:
* Header intake: strict W3C traceparent, associated bounded tracestate, canonical
  UUIDv4 correlation ID, bounded request ID; invalid/duplicate values are dropped
  without a 400 and counted without retaining caller text.
* Local identity: every request mints local OBS-001 trace/correlation/request IDs;
  inbound valid values remain remote-link metadata and response headers are local.
* Trust boundary: missing, unsealed, or resolver-failing principals fail closed on
  protected paths; exactly the two default health paths are exempt; caller flags do
  not grant access; the carrier and explicit async copy contain no principal.
* Clock and privacy: monotonic duration is independent of UTC clock jumps, and raw
  request bodies, auth material, and exception content never enter observation events.
* Sampling: 100% error capture and the healthy/incident policy are exercised through
  the middleware's injected deterministic sampling hooks.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import math
import random
from collections.abc import Callable
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from starlette.types import ASGIApp

from leviathan_api.middleware.observation import (
    ObservationPropagationMiddleware,
    copy_observation_for_async_hop,
    current_observation,
    verified_principal_from_request_state,
)
from leviathan_core.observability import (
    BuildIdentityV1,
    DiagnosticIdFactoryV1,
    DiagnosticRegistriesV1,
    DiagnosticRuntimeV1,
    RegistrySnapshotV1,
)
from leviathan_core.security.principal_verifier import (
    PrincipalVerifier,
    RSAPublicKeyV1,
    TrustedIssuerV1,
)

_REMOTE_TRACE = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
_REMOTE_PARENT = "bbbbbbbbbbbbbbbb"
_REMOTE_TRACEPARENT = f"00-{_REMOTE_TRACE}-{_REMOTE_PARENT}-01"
_REMOTE_CORRELATION = "123e4567-e89b-42d3-a456-426614174000"
_RAW_SECRET = "synthetic-request-secret-marker-47ad"
_SIGNATURE_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")
_PRINCIPAL_TIME = datetime(2026, 10, 6, 14, 30, tzinfo=UTC)


def _prime(rng: random.Random) -> int:
    while True:
        candidate = rng.getrandbits(1024) | (3 << 1022) | 1
        if any(candidate % divisor == 0 for divisor in (3, 5, 7, 11, 13, 17, 19, 23, 29)):
            continue
        s, d = 0, candidate - 1
        while d % 2 == 0:
            s, d = s + 1, d // 2
        for base in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
            x = pow(base, d, candidate)
            if x in (1, candidate - 1):
                continue
            for _ in range(s - 1):
                x = pow(x, 2, candidate)
                if x == candidate - 1:
                    break
            else:
                break
        else:
            return candidate


@pytest.fixture(scope="module")
def verified_principal():
    rng = random.Random(0x0B5003)
    p, q = _prime(rng), _prime(rng)
    while q == p or math.gcd(65537, (p - 1) * (q - 1)) != 1:
        q = _prime(rng)
    modulus = p * q
    public = RSAPublicKeyV1(modulus, 65537)
    private = pow(65537, -1, (p - 1) * (q - 1))
    now_seconds = int(_PRINCIPAL_TIME.timestamp())
    header = {"alg": "RS256", "kid": "obs003.test"}
    claims = {
        "iss": "issuer.synthetic",
        "aud": "api.synthetic",
        "org": "org.synthetic",
        "sub": "service.synthetic",
        "role": "operator",
        "scope": ["observability.read"],
        "env": "development",
        "venue": "XNAS",
        "portfolio": "portfolio.synthetic",
        "strategy": "strategy-a",
        "jti": "obs003-jti",
        "iat": now_seconds - 10,
        "nbf": now_seconds - 10,
        "exp": now_seconds + 100,
    }

    def b64(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    encoded_header = b64(json.dumps(header, sort_keys=True, separators=(",", ":")).encode())
    encoded_claims = b64(json.dumps(claims, sort_keys=True, separators=(",", ":")).encode())
    signing_input = f"{encoded_header}.{encoded_claims}"
    digest_info = _SIGNATURE_PREFIX + hashlib.sha256(signing_input.encode("ascii")).digest()
    block_size = (modulus.bit_length() + 7) // 8
    encoded_message = b"\x00\x01" + b"\xff" * (block_size - len(digest_info) - 3)
    encoded_message += b"\x00" + digest_info
    signature = pow(int.from_bytes(encoded_message, "big"), private, modulus)
    signature_bytes = signature.to_bytes(block_size, "big")
    token = f"{signing_input}.{b64(signature_bytes)}"

    class _Keys:
        def get_key(self, issuer: str, kid: str) -> RSAPublicKeyV1 | None:
            if issuer == "issuer.synthetic" and kid == "obs003.test":
                return public
            return None

    class _Revocations:
        def is_revoked(self, _issuer: str, _jti: str) -> bool:
            return False

    verifier = PrincipalVerifier(
        trusted_issuer=TrustedIssuerV1(
            issuer="issuer.synthetic",
            audience="api.synthetic",
            org_id="org.synthetic",
            project_id="leviathan-ai",
            env="development",
        ),
        key_set=_Keys(),
        revocations=_Revocations(),
        clock=lambda: _PRINCIPAL_TIME,
    )
    return verifier.verify(token)


def _runtime() -> DiagnosticRuntimeV1:
    return DiagnosticRuntimeV1(
        registries=DiagnosticRegistriesV1(
            services=RegistrySnapshotV1.from_members({"api"}),
            components=RegistrySnapshotV1.from_members({"pipeline"}),
            strategies=RegistrySnapshotV1.from_members({"strategy-a"}),
            instruments=RegistrySnapshotV1.from_members({"BTCUSD"}),
            venues=RegistrySnapshotV1.from_members({"XNAS"}),
        ),
        id_factory=DiagnosticIdFactoryV1(uuid4_factory=uuid4),
        build_identity=BuildIdentityV1(version="1.2.3"),
    )


def _app(
    *,
    principal_resolver: Callable[[Request], object | None] | None = None,
    middleware_options: dict[str, object] | None = None,
) -> tuple[ASGIApp, ObservationPropagationMiddleware]:
    app = FastAPI()

    @app.api_route("/health", methods=["GET", "POST"])
    @app.api_route("/api/health", methods=["GET", "POST"])
    @app.api_route("/protected", methods=["GET", "POST"])
    async def capture(request: Request) -> JSONResponse:
        carrier = current_observation()
        if carrier is None:
            return JSONResponse({"error": "NO_OBSERVATION"}, status_code=500)
        copied = copy_observation_for_async_hop(carrier)
        assert copied is not None
        context = carrier.context
        remote_parent = carrier.remote_parent
        remote_trace = getattr(remote_parent, "trace_id", None)
        remote_span = getattr(remote_parent, "parent_span_id", None)
        payload = {
            "trace_id": context.trace_id,
            "span_id": context.span_id,
            "correlation_id": str(context.correlation_id),
            "request_id": context.request_id,
            "remote_trace_id": remote_trace,
            "remote_parent_span_id": remote_span,
            "tracestate": carrier.tracestate,
            "remote_correlation_id": carrier.remote_correlation_id,
            "remote_request_id": carrier.remote_request_id,
            "local_registry_bundle_id": context.registry_bundle_id,
            "copy_is_distinct": copied is not carrier,
            "copy_context_is_distinct": copied.context is not context,
            "copy_correlation_id": str(copied.context.correlation_id),
            "carrier_has_principal": hasattr(carrier, "principal"),
        }
        if request.query_params.get("async_probe") == "1":
            child = copy_observation_for_async_hop(carrier)
            assert child is not None
            grandchild = copy_observation_for_async_hop(child)
            assert grandchild is not None

            async def sibling_hop():
                await asyncio.sleep(0)
                return copy_observation_for_async_hop(carrier)

            sibling_hops = await asyncio.gather(sibling_hop(), sibling_hop())
            assert all(sibling is not None for sibling in sibling_hops)

            def async_link_fields(hop):
                link = hop.remote_parent
                return {
                    "parent_span_id": hop.parent_span_id,
                    "remote_parent_is_none": link is None,
                    "remote_trace_id": getattr(link, "trace_id", None),
                    "remote_parent_span_id": getattr(link, "parent_span_id", None),
                    "tracestate": hop.tracestate,
                }

            payload["async_child"] = {
                "trace_id": child.context.trace_id,
                "span_id": child.context.span_id,
                **async_link_fields(child),
            }
            payload["async_grandchild"] = {
                "trace_id": grandchild.context.trace_id,
                "span_id": grandchild.context.span_id,
                **async_link_fields(grandchild),
            }
            payload["async_siblings"] = [
                {
                    "trace_id": sibling.context.trace_id,
                    "span_id": sibling.context.span_id,
                    **async_link_fields(sibling),
                }
                for sibling in sibling_hops
            ]
        return JSONResponse(payload)

    @app.post("/error")
    async def error_response() -> JSONResponse:
        return JSONResponse({"detail": "synthetic failure"}, status_code=500)

    @app.post("/raise")
    async def raise_error() -> JSONResponse:
        raise RuntimeError(_RAW_SECRET)

    resolver = principal_resolver or (lambda _request: None)
    middleware = ObservationPropagationMiddleware(
        app,
        principal_resolver=resolver,
        runtime=_runtime(),
        service="api",
        component="pipeline",
        **(middleware_options or {}),
    )
    return middleware, middleware


def _assert_fresh_response_ids(response, *, remote_trace: str | None = None) -> None:
    traceparent = response.headers["traceparent"]
    parts = traceparent.split("-")
    assert len(parts) == 4 and parts[0] == "00"
    assert len(parts[1]) == 32 and len(parts[2]) == 16
    assert parts[1] != "0" * 32 and parts[2] != "0" * 16
    assert parts[1] == parts[1].lower() and parts[2] == parts[2].lower()
    if remote_trace is not None:
        assert parts[1] != remote_trace
    assert response.headers["x-correlation-id"] != _REMOTE_CORRELATION
    assert response.headers["x-request-id"] != "remote-request-01"


def test_absent_headers_mint_local_ids_and_emit_traceparent() -> None:
    app, _ = _app()
    with TestClient(app) as client:
        response = client.get("/health")

    assert response.status_code == 200
    payload = response.json()
    assert payload["trace_id"] is not None
    assert payload["span_id"] is not None
    assert payload["correlation_id"] == response.headers["x-correlation-id"]
    assert payload["request_id"] == response.headers["x-request-id"]
    assert len(payload["local_registry_bundle_id"]) == 64
    assert payload["carrier_has_principal"] is False
    _assert_fresh_response_ids(response)


def test_valid_remote_headers_are_link_metadata_not_local_identity() -> None:
    app, _ = _app()
    headers = [
        ("traceparent", _REMOTE_TRACEPARENT),
        ("tracestate", "vendor-a=value-a,vendor-b=value-b"),
        ("X-Correlation-Id", _REMOTE_CORRELATION),
        ("X-Request-Id", "remote-request-01"),
    ]
    with TestClient(app) as client:
        response = client.get("/health", headers=headers)

    assert response.status_code == 200
    payload = response.json()
    assert payload["remote_trace_id"] == _REMOTE_TRACE
    assert payload["remote_parent_span_id"] == _REMOTE_PARENT
    assert payload["tracestate"] == "vendor-a=value-a,vendor-b=value-b"
    assert payload["remote_correlation_id"] == _REMOTE_CORRELATION
    assert payload["remote_request_id"] == "remote-request-01"
    assert payload["trace_id"] != _REMOTE_TRACE
    assert payload["correlation_id"] != _REMOTE_CORRELATION
    assert payload["request_id"] != "remote-request-01"
    _assert_fresh_response_ids(response, remote_trace=_REMOTE_TRACE)


@pytest.mark.parametrize(
    "traceparent",
    [
        "00-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-bbbbbbbbbbbbbbbb-01",
        "01-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01",
        "00-00000000000000000000000000000000-bbbbbbbbbbbbbbbb-01",
        "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-0000000000000000-01",
        "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-gg",
    ],
)
def test_invalid_traceparent_is_ignored_and_starts_fresh_trace(traceparent: str) -> None:
    app, middleware = _app()
    with TestClient(app) as client:
        response = client.get("/health", headers={"traceparent": traceparent})

    assert response.status_code == 200
    assert middleware.traceparent_invalid_count == 1
    assert response.json()["remote_trace_id"] is None
    _assert_fresh_response_ids(response)


def test_duplicate_traceparent_is_ignored_and_counted_without_400() -> None:
    app, middleware = _app()
    with TestClient(app) as client:
        response = client.get(
            "/health",
            headers=[
                ("traceparent", _REMOTE_TRACEPARENT),
                ("traceparent", _REMOTE_TRACEPARENT),
            ],
        )

    assert response.status_code == 200
    assert middleware.traceparent_invalid_count == 1
    assert response.json()["remote_trace_id"] is None
    _assert_fresh_response_ids(response)


@pytest.mark.parametrize(
    "tracestate",
    [
        "bad key=value",
        ",".join(f"vendor{i}=v" for i in range(33)),
        "vendor=" + "x" * 513,
    ],
)
def test_invalid_or_oversize_tracestate_is_dropped(tracestate: str) -> None:
    app, _ = _app()
    with TestClient(app) as client:
        response = client.get(
            "/health",
            headers={
                "traceparent": _REMOTE_TRACEPARENT,
                "tracestate": tracestate,
            },
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["remote_trace_id"] == _REMOTE_TRACE
    assert payload["tracestate"] is None


def test_tracestate_without_valid_traceparent_is_not_retained() -> None:
    app, _ = _app()
    with TestClient(app) as client:
        response = client.get(
            "/health",
            headers={
                "traceparent": "malformed",
                "tracestate": "vendor-a=value-a",
            },
        )

    assert response.json()["remote_trace_id"] is None
    assert response.json()["tracestate"] is None


def test_tracestate_at_32_member_boundary_is_retained() -> None:
    tracestate = ",".join(f"v{i}=x" for i in range(32))
    app, _ = _app()
    with TestClient(app) as client:
        response = client.get(
            "/health",
            headers={
                "traceparent": _REMOTE_TRACEPARENT,
                "tracestate": tracestate,
            },
        )

    assert response.status_code == 200
    assert response.json()["tracestate"] == tracestate


def test_tracestate_at_512_byte_boundary_is_retained() -> None:
    tracestate = f"a={'x' * 254},b={'y' * 253}"
    assert len(tracestate.encode("ascii")) == 512
    app, _ = _app()
    with TestClient(app) as client:
        response = client.get(
            "/health",
            headers={
                "traceparent": _REMOTE_TRACEPARENT,
                "tracestate": tracestate,
            },
        )

    assert response.status_code == 200
    assert response.json()["tracestate"] == tracestate


@pytest.mark.parametrize(
    "correlation_id",
    [
        "123E4567-E89B-42D3-A456-426614174000",
        "123e4567e89b42d3a456426614174000",
        "123e4567-e89b-42d3-0456-426614174000",
        "123e4567-e89b-12d3-a456-426614174000",
        "not-a-uuid",
    ],
)
def test_invalid_correlation_header_is_dropped_not_rejected(correlation_id: str) -> None:
    app, middleware = _app()
    with TestClient(app) as client:
        response = client.get("/health", headers={"X-Correlation-Id": correlation_id})

    assert response.status_code == 200
    assert middleware.invalid_correlation_id_count == 1
    assert response.json()["remote_correlation_id"] is None
    assert response.headers["x-correlation-id"] != correlation_id


def test_duplicate_correlation_and_request_ids_are_dropped_and_counted() -> None:
    app, middleware = _app()
    with TestClient(app) as client:
        response = client.get(
            "/health",
            headers=[
                ("X-Correlation-Id", _REMOTE_CORRELATION),
                ("X-Correlation-Id", _REMOTE_CORRELATION),
                ("X-Request-Id", "request-remote-a"),
                ("X-Request-Id", "request-remote-b"),
            ],
        )

    assert response.status_code == 200
    assert middleware.invalid_correlation_id_count == 1
    assert middleware.invalid_request_id_count == 1
    assert response.json()["remote_correlation_id"] is None
    assert response.json()["remote_request_id"] is None
    _assert_fresh_response_ids(response)


@pytest.mark.parametrize("request_id", ["bad id", "x" * 129, "a\nheader"])
def test_invalid_request_id_is_dropped_and_counted(request_id: str) -> None:
    app, middleware = _app()
    with TestClient(app) as client:
        response = client.get("/health", headers={"X-Request-Id": request_id})

    assert response.status_code == 200
    assert middleware.invalid_request_id_count == 1
    assert response.json()["remote_request_id"] is None
    assert request_id not in response.headers["x-request-id"]


def test_exact_default_health_exemptions_do_not_exempt_other_routes() -> None:
    app, _ = _app()
    with TestClient(app) as client:
        health = client.get("/health")
        api_health = client.get("/api/health")
        protected = client.get("/protected")

    assert health.status_code == 200
    assert api_health.status_code == 200
    assert protected.status_code == 401
    assert protected.json() == {"detail": "UNAUTHENTICATED"}


def test_missing_or_unsealed_principal_fails_closed_and_does_not_echo_resolver_error() -> None:
    app, _ = _app(principal_resolver=lambda _request: object())
    with TestClient(app) as client:
        unsealed = client.get("/protected")
    assert unsealed.status_code == 401
    assert "object at" not in unsealed.text

    def failing_resolver(_request: Request) -> object:
        raise RuntimeError(_RAW_SECRET)

    app, _ = _app(principal_resolver=failing_resolver)
    with TestClient(app, raise_server_exceptions=False) as client:
        failed = client.get("/protected")
    assert failed.status_code == 401
    assert _RAW_SECRET not in failed.text
    assert failed.json() == {"detail": "UNAUTHENTICATED"}


def test_caller_safety_flags_cannot_bypass_protected_path_authentication() -> None:
    app, _ = _app()
    with TestClient(app) as client:
        response = client.get(
            "/protected",
            headers={
                "X-Auth-Bypass": "true",
                "X-Admin": "true",
                "X-Risk-Approved": "true",
                "X-Execution-Eligible": "true",
            },
        )

    assert response.status_code == 401
    assert response.json() == {"detail": "UNAUTHENTICATED"}


def test_valid_sec003_principal_allows_protected_path_without_entering_carrier(
    verified_principal,
) -> None:
    app, _ = _app(principal_resolver=lambda _request: verified_principal)
    with TestClient(app) as client:
        response = client.get("/protected")

    assert response.status_code == 200
    assert response.json()["carrier_has_principal"] is False


def test_explicit_async_hop_copies_context_but_never_principal() -> None:
    app, _ = _app()
    with TestClient(app) as client:
        response = client.get(
            "/health",
            headers={
                "traceparent": _REMOTE_TRACEPARENT,
                "X-Correlation-Id": _REMOTE_CORRELATION,
                "X-Request-Id": "remote-request-01",
            },
        )

    payload = response.json()
    assert payload["copy_is_distinct"] is True
    assert payload["copy_context_is_distinct"] is True
    assert payload["copy_correlation_id"] == payload["correlation_id"]
    assert payload["carrier_has_principal"] is False


def _async_hop_payload() -> dict[str, object]:
    app, _ = _app()
    with TestClient(app) as client:
        response = client.get(
            "/health?async_probe=1",
            headers={"traceparent": _REMOTE_TRACEPARENT},
        )
    assert response.status_code == 200
    return response.json()


def test_async_hop_mints_distinct_child_span_with_parent_link() -> None:
    payload = _async_hop_payload()
    child = payload["async_child"]

    assert child["trace_id"] == payload["trace_id"]
    assert child["span_id"] != payload["span_id"]
    assert child["parent_span_id"] == payload["span_id"]
    assert child["trace_id"] == payload["trace_id"]


def test_two_async_hops_form_a_parented_span_chain() -> None:
    payload = _async_hop_payload()
    child = payload["async_child"]
    grandchild = payload["async_grandchild"]

    assert child["trace_id"] == grandchild["trace_id"] == payload["trace_id"]
    assert grandchild["span_id"] not in {payload["span_id"], child["span_id"]}
    assert grandchild["parent_span_id"] == child["span_id"]


def test_concurrent_async_hops_mint_distinct_sibling_span_ids() -> None:
    payload = _async_hop_payload()
    siblings = payload["async_siblings"]
    spans = [sibling["span_id"] for sibling in siblings]

    assert len(spans) == 2
    assert len(set(spans)) == 2
    assert payload["span_id"] not in spans
    assert all(sibling["trace_id"] == payload["trace_id"] for sibling in siblings)
    assert all(sibling["parent_span_id"] == payload["span_id"] for sibling in siblings)


def test_inbound_remote_parent_is_only_the_root_parent() -> None:
    payload = _async_hop_payload()
    child = payload["async_child"]
    grandchild = payload["async_grandchild"]

    assert payload["remote_trace_id"] == _REMOTE_TRACE
    assert payload["remote_parent_span_id"] == _REMOTE_PARENT
    assert child["remote_trace_id"] is None
    assert child["remote_parent_is_none"] is True
    assert child["remote_parent_span_id"] is None
    assert child["tracestate"] is None
    assert grandchild["remote_trace_id"] is None
    assert grandchild["remote_parent_is_none"] is True
    assert grandchild["remote_parent_span_id"] is None
    assert grandchild["tracestate"] is None
    assert child["parent_span_id"] == payload["span_id"]
    assert grandchild["parent_span_id"] == child["span_id"]


def test_verified_principal_request_state_helper_fails_closed_for_unissued_values() -> None:
    app = FastAPI()
    app.add_api_route("/set-untrusted", lambda: JSONResponse({"ok": True}))
    middleware = ObservationPropagationMiddleware(
        app,
        principal_resolver=verified_principal_from_request_state,
        runtime=_runtime(),
        service="api",
        component="pipeline",
    )

    class _UntrustedState:
        def __init__(self, inner: ASGIApp) -> None:
            self.inner = inner

        async def __call__(self, scope, receive, send) -> None:
            if scope["type"] == "http":
                scope.setdefault("state", {})["verified_principal"] = {
                    "role": "admin",
                    "secret": _RAW_SECRET,
                }
            await self.inner(scope, receive, send)

    with TestClient(_UntrustedState(middleware)) as client:
        response = client.get("/set-untrusted")

    assert response.status_code == 401
    assert _RAW_SECRET not in response.text


def test_error_events_are_always_sampled_and_never_include_body_or_exception_text() -> None:
    events = []
    app, _ = _app(
        middleware_options={
            "incident_active": lambda: False,
            "sample_healthy": lambda: False,
            "event_sink": events.append,
            "exempt_paths": {"/health", "/api/health", "/error", "/raise"},
        }
    )
    with TestClient(app, raise_server_exceptions=False) as client:
        healthy = client.get("/health")
        error = client.post(
            "/raise",
            content=_RAW_SECRET.encode(),
            headers={"Authorization": f"Bearer {_RAW_SECRET}"},
        )

    assert healthy.status_code == 200
    assert error.status_code == 500
    assert len(events) == 1
    assert events[0].status_code == 500
    assert _RAW_SECRET not in repr(events[0])
    assert _RAW_SECRET not in str(events[0])


def test_incident_hook_upsamples_healthy_events_and_duration_ignores_wall_clock_jump() -> None:
    events = []
    monotonic_values = iter((100, 125, 200, 250))
    utc_values = iter((1_900, 1_700))
    app, _ = _app(
        middleware_options={
            "incident_active": lambda: True,
            "sample_healthy": lambda: False,
            "event_sink": events.append,
            "monotonic_ns_clock": lambda: next(monotonic_values),
            "utc_ns_clock": lambda: next(utc_values),
        }
    )
    with TestClient(app) as client:
        first = client.get("/health")
        second = client.get("/health")

    assert first.status_code == second.status_code == 200
    assert len(events) == 2
    assert [event.duration_ns for event in events] == [25, 50]
    assert [event.timestamp_utc_ns for event in events] == [1_900, 1_700]


def test_healthy_baseline_sampler_can_select_a_record() -> None:
    events = []
    app, _ = _app(
        middleware_options={
            "incident_active": lambda: False,
            "sample_healthy": lambda: True,
            "event_sink": events.append,
        }
    )
    with TestClient(app) as client:
        response = client.get("/health")

    assert response.status_code == 200
    assert len(events) == 1
    assert events[0].status_code == 200


def test_observation_sink_failure_does_not_change_route_response() -> None:
    def broken_sink(_event: object) -> None:
        raise RuntimeError(_RAW_SECRET)

    app, _ = _app(
        middleware_options={
            "incident_active": lambda: True,
            "sample_healthy": lambda: False,
            "event_sink": broken_sink,
        }
    )
    with TestClient(app) as client:
        response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["local_registry_bundle_id"]
