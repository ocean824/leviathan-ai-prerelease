"""Independent create_app acceptance for OBS-003-WIRE-001."""

from __future__ import annotations

import base64
import hashlib
import inspect
import json
import math
import random
import time
from contextlib import asynccontextmanager
from dataclasses import fields, replace
from datetime import UTC, datetime
from pathlib import Path
from threading import Event

import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from starlette.types import ASGIApp, Receive, Scope, Send

from leviathan_api import main
from leviathan_api.auth import OperatorPrincipalMiddleware, make_local_operator_profile
from leviathan_api.middleware.observation import ObservationPropagationMiddleware
from leviathan_api.observation_runtime import (
    NonBlockingObservationEventSinkV1,
    ObservationRuntimeConfigError,
    ObservationRuntimeConfigV1,
    build_observation_dependencies,
    build_observation_runtime,
)
from leviathan_api.settings import Settings, get_settings
from leviathan_core.security.authz_models import is_trusted_principal
from leviathan_core.security.principal_verifier import (
    PrincipalVerifier,
    RSAPublicKeyV1,
    TrustedIssuerV1,
    VerifiedPrincipalV1,
)

_PORT = 49321
_CAPABILITY = "ab" * 32
_OPERATOR_HEADERS = {
    "x-leviathan-capability": _CAPABILITY,
    "origin": f"http://127.0.0.1:{_PORT}",
}
_NOW = datetime(2026, 10, 7, 12, 0, tzinfo=UTC)
_NOW_SECONDS = int(_NOW.timestamp())
_DIGEST_INFO_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")
_REMOTE_TRACE_ID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
_REMOTE_SPAN_ID = "bbbbbbbbbbbbbbbb"
_REMOTE_TRACEPARENT = f"00-{_REMOTE_TRACE_ID}-{_REMOTE_SPAN_ID}-01"
_ZERO_TRACEPARENT = "00-00000000000000000000000000000000-bbbbbbbbbbbbbbbb-01"


def _prime(rng: random.Random) -> int:
    while True:
        candidate = rng.getrandbits(1024) | (3 << 1022) | 1
        if any(candidate % divisor == 0 for divisor in (3, 5, 7, 11, 13, 17, 19, 23, 29)):
            continue
        s, d = 0, candidate - 1
        while d % 2 == 0:
            s, d = s + 1, d // 2
        for base in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
            value = pow(base, d, candidate)
            if value in (1, candidate - 1):
                continue
            for _ in range(s - 1):
                value = pow(value, 2, candidate)
                if value == candidate - 1:
                    break
            else:
                break
        else:
            return candidate


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _sec003_material() -> tuple[PrincipalVerifier, str]:
    """Build a real verifier and test-signed token; never instantiate its sealed output."""
    rng = random.Random(0x57495245)
    p, q = _prime(rng), _prime(rng)
    while q == p or math.gcd(65537, (p - 1) * (q - 1)) != 1:
        q = _prime(rng)
    modulus = p * q
    public_key = RSAPublicKeyV1(modulus, 65537)
    private_exponent = pow(65537, -1, (p - 1) * (q - 1))
    header = {"alg": "RS256", "kid": "wire.synthetic"}
    claims = {
        "iss": "issuer.wire.synthetic",
        "aud": "api.wire.synthetic",
        "org": "org.wire.synthetic",
        "sub": "operator.wire.synthetic",
        "role": "operator",
        "scope": ["observability.read"],
        "env": "development",
        "venue": "XNAS",
        "portfolio": "portfolio.wire.synthetic",
        "strategy": "strategy.wire.synthetic",
        "jti": "wire-jti-001",
        "iat": _NOW_SECONDS - 10,
        "nbf": _NOW_SECONDS - 10,
        "exp": _NOW_SECONDS + 100,
    }
    unsigned = ".".join(
        (
            _b64(json.dumps(header, sort_keys=True, separators=(",", ":")).encode()),
            _b64(json.dumps(claims, sort_keys=True, separators=(",", ":")).encode()),
        )
    ).encode("ascii")
    digest_info = _DIGEST_INFO_PREFIX + hashlib.sha256(unsigned).digest()
    block_size = (modulus.bit_length() + 7) // 8
    encoded = b"\x00\x01" + b"\xff" * (block_size - len(digest_info) - 3)
    encoded += b"\x00" + digest_info
    signature = pow(int.from_bytes(encoded, "big"), private_exponent, modulus)
    token = f"{unsigned.decode('ascii')}.{_b64(signature.to_bytes(block_size, 'big'))}"

    class _Keys:
        def get_key(self, issuer: str, kid: str) -> RSAPublicKeyV1 | None:
            if issuer == "issuer.wire.synthetic" and kid == "wire.synthetic":
                return public_key
            return None

    class _Revocations:
        def is_revoked(self, _issuer: str, _jti: str) -> bool:
            return False

    verifier = PrincipalVerifier(
        trusted_issuer=TrustedIssuerV1(
            issuer="issuer.wire.synthetic",
            audience="api.wire.synthetic",
            org_id="org.wire.synthetic",
            project_id="leviathan-ai",
            env="development",
        ),
        key_set=_Keys(),
        revocations=_Revocations(),
        clock=lambda: _NOW,
    )
    return verifier, token


class _TestSec003VerifierMiddleware:
    """Test-only upstream layer: issue state only from PrincipalVerifier.verify."""

    def __init__(self, app: ASGIApp, *, verifier: PrincipalVerifier, token: str) -> None:
        self.app = app
        self.verifier = verifier
        self.token = token

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") == "http":
            auth_values = [
                value
                for name, value in scope.get("headers", ())
                if name.lower() == b"authorization"
            ]
            if auth_values == [b"Bearer " + self.token.encode("ascii")]:
                scope.setdefault("state", {})["verified_principal"] = self.verifier.verify(
                    self.token
                )
        await self.app(scope, receive, send)


def _app_with_sink(
    monkeypatch: pytest.MonkeyPatch,
    consumer,
    *,
    capacity: int = 256,
):
    sink = NonBlockingObservationEventSinkV1(capacity=capacity, consumer=consumer)
    build = main.build_observation_dependencies

    def build_with_injected_consumer(settings, application, *args, **kwargs):
        kwargs["event_sink"] = sink
        dependencies = replace(
            build(settings, application, *args, **kwargs), incident_active=lambda: True
        )
        # Make success events observable deterministically in this test; production
        # sampling still runs through the same middleware and sink seam.
        return dependencies

    monkeypatch.setattr(main, "build_observation_dependencies", build_with_injected_consumer)
    app = main.create_app()

    @app.api_route("/wire/probe", methods=["GET", "POST"], include_in_schema=False)
    async def probe(request: Request) -> JSONResponse:
        carrier = request.state.observation_carrier
        trusted = getattr(request.state, "trusted_principal", None)
        verified = getattr(request.state, "verified_principal", None)
        remote_parent = carrier.remote_parent
        return JSONResponse(
            {
                "ok": True,
                "trusted_operator": bool(is_trusted_principal(trusted)),
                "trusted_principal_id": trusted.principal_id
                if is_trusted_principal(trusted)
                else None,
                "verified_principal_id": verified.subject_id
                if type(verified) is VerifiedPrincipalV1
                else None,
                "observation_principal_id": getattr(
                    request.state, "observation_principal_id", "missing"
                ),
                "observation_principal_source": getattr(
                    request.state, "observation_principal_source", "missing"
                ),
                "local_trace_id": carrier.context.trace_id,
                "local_span_id": carrier.context.span_id,
                "remote_trace_id": remote_parent.trace_id if remote_parent else None,
                "remote_parent_span_id": remote_parent.parent_span_id if remote_parent else None,
            }
        )

    return app, sink


def _middleware_index(app, target: type) -> int:
    return next(index for index, item in enumerate(app.user_middleware) if item.cls is target)


def test_real_app_registers_observation_middleware_once_in_declared_order() -> None:
    app = main.create_app()
    observation_items = [
        index
        for index, middleware in enumerate(app.user_middleware)
        if middleware.cls is ObservationPropagationMiddleware
    ]
    assert len(observation_items) == 1
    # Starlette's user_middleware list is outer-to-inner. create_app adds its
    # existing guards after observation so those guards wrap the OBS middleware.
    assert observation_items[0] == len(app.user_middleware) - 1


def test_removing_create_app_observation_registration_removes_trace_headers() -> None:
    app = main.create_app()
    app.user_middleware = [
        item for item in app.user_middleware if item.cls is not ObservationPropagationMiddleware
    ]
    with TestClient(app) as client:
        response = client.get("/openapi.json")

    assert response.status_code == 200
    assert "traceparent" not in response.headers


def test_observation_middleware_default_policy_still_rejects_missing_principal() -> None:
    app = FastAPI()
    app.add_middleware(
        ObservationPropagationMiddleware,
        principal_resolver=lambda _request: None,
        runtime=build_observation_runtime(get_settings()),
        service="api",
        component="http",
        sample_healthy=lambda: False,
    )

    with TestClient(app) as client:
        response = client.get("/private")

    assert response.status_code == 401
    assert response.json() == {"detail": "UNAUTHENTICATED"}


def test_missing_observation_config_defaults_and_serves_mounted_api_health(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """An unsupported implicit deployment env must not prevent the paper harness booting."""
    monkeypatch.setenv("LEVIATHAN_ENV", "paper")
    get_settings.cache_clear()
    events = []
    delivered = Event()

    def consume(event) -> None:
        events.append(event)
        delivered.set()

    child_app, _sink = _app_with_sink(monkeypatch, consume)

    @asynccontextmanager
    async def mounted_lifespan(_application):
        async with child_app.router.lifespan_context(child_app):
            yield

    host = FastAPI(lifespan=mounted_lifespan)
    host.mount("/api", child_app)
    with TestClient(host) as client:
        response = client.get("/api/health")
        probe = client.get("/api/wire/probe")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert probe.status_code == 200
    assert probe.json()["observation_principal_id"] is None
    assert probe.json()["observation_principal_source"] == "anonymous"
    assert delivered.wait(1)
    assert len(events) == 2
    assert all(event.context.env == "development" for event in events)
    assert all("principal" not in {field.name for field in fields(event)} for event in events)
    assert all(event.status_code == 200 for event in events)
    defaulted = [
        record
        for record in caplog.records
        if record.getMessage() == "OBSERVATION_RUNTIME_DEFAULTED"
    ]
    assert len(defaulted) == 1
    assert "paper" not in defaulted[0].getMessage().lower()


def test_malformed_explicit_observation_config_fails_closed(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with pytest.raises(ObservationRuntimeConfigError) as exc_info:
        build_observation_dependencies(
            Settings(env="development"),
            FastAPI(),
            config=ObservationRuntimeConfigV1(health_env="paper"),
        )

    assert str(exc_info.value) == "OBSERVATION_RUNTIME_INVALID"
    assert not any(
        record.getMessage() == "OBSERVATION_RUNTIME_DEFAULTED" for record in caplog.records
    )


def test_observation_registration_is_single_structural_and_inside_auth_guards() -> None:
    main_path = Path(__file__).parents[1] / "src" / "leviathan_api" / "main.py"
    source_text = main_path.read_text(encoding="utf-8")
    assert (
        source_text.count(
            "from leviathan_api.middleware.observation import ObservationPropagationMiddleware"
        )
        == 1
    )
    assert (
        source_text.count("application.add_middleware(\n        ObservationPropagationMiddleware,")
        == 1
    )
    assert source_text.count('anonymous_policy="attribute_anonymous"') == 1
    assert "observation_config" not in inspect.signature(main.create_app).parameters

    app = main.create_app()
    observation_index = _middleware_index(app, ObservationPropagationMiddleware)
    body_limit_index = _middleware_index(app, main.CredentialBodyLimitMiddleware)
    assert observation_index > body_limit_index
    assert app.user_middleware[observation_index].kwargs["anonymous_policy"] == (
        "attribute_anonymous"
    )

    app.add_middleware(
        OperatorPrincipalMiddleware,
        capability=_CAPABILITY,
        port=_PORT,
        profile=make_local_operator_profile(
            principal_id="wire-order-operator",
            project_id="wire-project",
            env="paper",
        ),
    )
    assert _middleware_index(app, OperatorPrincipalMiddleware) < _middleware_index(
        app, ObservationPropagationMiddleware
    )


def test_authenticated_sec002_operator_traces_without_sec003_attribution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events = []
    delivered = Event()

    def consume(event) -> None:
        events.append(event)
        delivered.set()

    app, _sink = _app_with_sink(monkeypatch, consume)
    app.add_middleware(
        OperatorPrincipalMiddleware,
        capability=_CAPABILITY,
        port=_PORT,
        profile=make_local_operator_profile(
            principal_id="wire-local-operator",
            project_id="wire-project",
            env="paper",
        ),
    )
    with TestClient(app, base_url=f"http://127.0.0.1:{_PORT}") as client:
        response = client.get("/wire/probe", headers=_OPERATOR_HEADERS)
        assert response.status_code == 200
        assert response.json()["ok"] is True
        assert response.json()["trusted_operator"] is True
        assert response.json()["trusted_principal_id"] == "wire-local-operator"
        assert response.json()["verified_principal_id"] is None
        assert response.json()["observation_principal_id"] is None
        assert response.json()["observation_principal_source"] == "anonymous"

        unauthenticated = client.get("/wire/probe")
        assert unauthenticated.status_code == 200
        assert unauthenticated.json()["trusted_operator"] is False
        assert unauthenticated.json()["verified_principal_id"] is None
        assert unauthenticated.json()["observation_principal_id"] is None
        assert unauthenticated.json()["observation_principal_source"] == "anonymous"
        assert "traceparent" in unauthenticated.headers

        # This pre-existing create_app route worked before WIRE and must not become
        # an OBS-level 401 merely because no SEC-003 verifier is installed.
        openapi = client.get("/openapi.json")
        assert openapi.status_code == 200
        assert "traceparent" in openapi.headers

    assert delivered.wait(1)
    assert events
    for event in events:
        assert "principal" not in {field.name for field in fields(event)}
        assert "principal" not in {field.name for field in fields(event.context)}
        # SEC-002's paper identity is not promoted into SEC-003 observation metadata.
        assert event.context.env == "development"


def test_sec003_verifier_runs_outside_observation_and_resolver_sees_issued_principal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events = []
    delivered = Event()

    def consume(event) -> None:
        events.append(event)
        delivered.set()

    verifier, token = _sec003_material()
    seen: list[VerifiedPrincipalV1 | None] = []
    real_resolver = main.operator_principal_resolver

    def capture_resolver(request: Request) -> VerifiedPrincipalV1 | None:
        principal = real_resolver(request)
        seen.append(principal)
        return principal

    monkeypatch.setattr(main, "operator_principal_resolver", capture_resolver)
    app, _sink = _app_with_sink(monkeypatch, consume)
    app.add_middleware(_TestSec003VerifierMiddleware, verifier=verifier, token=token)
    auth_index = _middleware_index(app, _TestSec003VerifierMiddleware)
    observation_index = _middleware_index(app, ObservationPropagationMiddleware)
    assert auth_index < observation_index

    with TestClient(app) as client:
        response = client.get("/wire/probe", headers={"authorization": f"Bearer {token}"})

    assert response.status_code == 200
    assert response.json()["verified_principal_id"] == "operator.wire.synthetic"
    assert seen and type(seen[0]) is VerifiedPrincipalV1
    assert seen[0].subject_id == "operator.wire.synthetic"
    assert delivered.wait(1)
    assert events
    assert not any("principal" in field.name for field in fields(events[0]))


def test_swapping_sec003_verifier_inside_observation_makes_resolver_anonymous(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verifier, token = _sec003_material()
    seen: list[VerifiedPrincipalV1 | None] = []
    real_resolver = main.operator_principal_resolver

    def capture_resolver(request: Request) -> VerifiedPrincipalV1 | None:
        principal = real_resolver(request)
        seen.append(principal)
        return principal

    monkeypatch.setattr(main, "operator_principal_resolver", capture_resolver)
    app, _sink = _app_with_sink(monkeypatch, lambda _event: None)
    app.add_middleware(_TestSec003VerifierMiddleware, verifier=verifier, token=token)
    auth_index = _middleware_index(app, _TestSec003VerifierMiddleware)
    observation_index = _middleware_index(app, ObservationPropagationMiddleware)
    app.user_middleware[auth_index], app.user_middleware[observation_index] = (
        app.user_middleware[observation_index],
        app.user_middleware[auth_index],
    )
    assert _middleware_index(app, ObservationPropagationMiddleware) < _middleware_index(
        app, _TestSec003VerifierMiddleware
    )

    with TestClient(app) as client:
        response = client.get("/wire/probe", headers={"authorization": f"Bearer {token}"})

    assert response.status_code == 200
    assert response.json()["verified_principal_id"] == "operator.wire.synthetic"
    assert response.json()["observation_principal_id"] is None
    assert response.json()["observation_principal_source"] == "anonymous"
    assert seen == [None]


def test_remote_traceparent_is_linked_but_local_response_trace_is_fresh(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    delivered = Event()
    app, _sink = _app_with_sink(monkeypatch, lambda _event: delivered.set())
    with TestClient(app) as client:
        response = client.get("/wire/probe", headers={"traceparent": _REMOTE_TRACEPARENT})

    assert response.status_code == 200
    payload = response.json()
    response_trace_id = response.headers["traceparent"].split("-")[1]
    assert payload["remote_trace_id"] == _REMOTE_TRACE_ID
    assert payload["remote_parent_span_id"] == _REMOTE_SPAN_ID
    assert payload["local_trace_id"] == response_trace_id
    assert payload["local_trace_id"] != _REMOTE_TRACE_ID
    assert payload["local_span_id"] != _REMOTE_SPAN_ID
    assert delivered.wait(1)


@pytest.mark.parametrize("traceparent", ["malformed", _ZERO_TRACEPARENT])
def test_malformed_traceparent_is_ignored_without_crashing(
    monkeypatch: pytest.MonkeyPatch,
    traceparent: str,
) -> None:
    app, _sink = _app_with_sink(monkeypatch, lambda _event: None)
    with TestClient(app) as client:
        response = client.get("/wire/probe", headers={"traceparent": traceparent})

    assert response.status_code == 200
    assert response.json()["ok"] is True
    assert response.json()["remote_trace_id"] is None
    assert len(response.headers["traceparent"].split("-")) == 4
    assert response.headers["traceparent"].split("-")[1] != "0" * 32


def test_event_sink_contains_redacted_event_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events = []
    delivered = Event()

    def consume(event) -> None:
        events.append(event)
        delivered.set()

    app, _sink = _app_with_sink(monkeypatch, consume)
    header_secret = "wire-private-header-79a1"
    body_secret = "wire-private-body-2f88"
    with TestClient(app) as client:
        response = client.post(
            "/wire/probe",
            headers={"x-private-value": header_secret},
            content=body_secret,
        )

    assert response.status_code == 200
    assert delivered.wait(1)
    assert len(events) == 1
    event = events[0]
    event_text = repr(event)
    assert header_secret not in event_text
    assert body_secret not in event_text
    assert not hasattr(event, "headers")
    assert not hasattr(event, "body")
    assert {field.name for field in fields(event)} == {
        "context",
        "status_code",
        "timestamp_utc_ns",
        "duration_ns",
    }


def test_slow_event_consumer_does_not_delay_response_and_full_queue_drops(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    consumer_started = Event()
    release_consumer = Event()

    def slow_consumer(_event) -> None:
        consumer_started.set()
        release_consumer.wait(2)

    app, sink = _app_with_sink(monkeypatch, slow_consumer, capacity=1)
    try:
        with TestClient(app) as client:
            warmup = client.get("/wire/probe")
            assert warmup.status_code == 200
            assert consumer_started.wait(1)

            second_started = time.perf_counter()
            second = client.get("/wire/probe")
            second_elapsed = time.perf_counter() - second_started
            third_started = time.perf_counter()
            third = client.get("/wire/probe")
            third_elapsed = time.perf_counter() - third_started

        assert second.status_code == third.status_code == 200
        assert second_elapsed < 0.75
        assert third_elapsed < 0.75
        assert sink.dropped_count == 1
    finally:
        release_consumer.set()
