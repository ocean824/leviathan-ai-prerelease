"""Fail-closed request observation and explicit trace propagation middleware.

Authentication is performed upstream. This middleware accepts only a
SEC-003 sealed principal supplied by its injected resolver; request headers
cannot assert identity or alter safety policy.
"""

from __future__ import annotations

import re
import secrets
import threading
import time
from _thread import LockType
from collections.abc import Callable, Iterable
from contextlib import suppress
from contextvars import ContextVar, Token
from dataclasses import dataclass
from typing import Literal
from uuid import UUID

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from leviathan_core.observability import (
    DiagnosticRuntimeV1,
    LatencySampleV1,
    LatencyTimerV1,
    ObservationContextV1,
)
from leviathan_core.seal import require
from leviathan_core.security.principal_verifier import VerifiedPrincipalV1

_PRINCIPAL_TAG = "sec003.verified_principal.v1"
_TRACEPARENT = re.compile(rb"00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})\Z", re.ASCII)
_SIMPLE_TRACESTATE_KEY = re.compile(rb"[a-z][a-z0-9_*/-]{0,255}\Z", re.ASCII)
_TENANT_TRACESTATE_KEY = re.compile(rb"[a-z0-9_*/-]{1,241}@[a-z][a-z0-9_*/-]{0,13}\Z", re.ASCII)
_REQUEST_ID = re.compile(rb"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z", re.ASCII)
_DEFAULT_EXEMPT_PATHS = frozenset({"/health", "/api/health"})


@dataclass(frozen=True, slots=True)
class RemoteParentLinkV1:
    """Validated remote W3C parent metadata, separate from our minted IDs."""

    trace_id: str
    parent_span_id: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.trace_id, str)
            or re.fullmatch(r"[0-9a-f]{32}", self.trace_id, re.ASCII) is None
            or self.trace_id == "0" * 32
            or not isinstance(self.parent_span_id, str)
            or re.fullmatch(r"[0-9a-f]{16}", self.parent_span_id, re.ASCII) is None
            or self.parent_span_id == "0" * 16
        ):
            raise ValueError("invalid remote trace parent")


@dataclass(frozen=True, slots=True)
class ObservationCarrierV1:
    """Explicit async-hop carrier containing observation data only."""

    context: ObservationContextV1
    remote_parent: RemoteParentLinkV1 | None
    tracestate: str | None
    remote_correlation_id: str | None = None
    remote_request_id: str | None = None
    parent_span_id: str | None = None

    def __post_init__(self) -> None:
        if type(self.context) is not ObservationContextV1:
            raise TypeError("context must be ObservationContextV1")
        if self.remote_parent is not None and type(self.remote_parent) is not RemoteParentLinkV1:
            raise TypeError("remote_parent must be RemoteParentLinkV1")
        if self.parent_span_id is not None and (
            re.fullmatch(r"[0-9a-f]{16}", self.parent_span_id, re.ASCII) is None
            or self.parent_span_id == "0" * 16
        ):
            raise ValueError("invalid local parent span id")
        if self.parent_span_id != self.context.parent_span_id:
            raise ValueError("carrier parent span does not match context")
        if self.parent_span_id is not None and self.remote_parent is not None:
            raise ValueError("child carrier cannot retain remote parent")
        if self.tracestate is not None and (
            self.remote_parent is None or not _valid_tracestate(self.tracestate.encode("ascii"))
        ):
            raise ValueError("invalid trace state")
        if self.remote_correlation_id is not None and not _valid_correlation_id(
            self.remote_correlation_id.encode("ascii")
        ):
            raise ValueError("invalid remote correlation id")
        if (
            self.remote_request_id is not None
            and _REQUEST_ID.fullmatch(self.remote_request_id.encode("ascii")) is None
        ):
            raise ValueError("invalid remote request id")


@dataclass(frozen=True, slots=True)
class ObservationRequestEventV1:
    """Redacted request completion event; contains no principal or raw request data."""

    context: ObservationContextV1
    status_code: int
    timestamp_utc_ns: int
    duration_ns: int

    def __post_init__(self) -> None:
        if (
            type(self.context) is not ObservationContextV1
            or type(self.status_code) is not int
            or not 100 <= self.status_code <= 599
            or type(self.timestamp_utc_ns) is not int
            or self.timestamp_utc_ns < 0
            or type(self.duration_ns) is not int
            or self.duration_ns < 0
        ):
            raise ValueError("invalid observation event")


_CURRENT_OBSERVATION: ContextVar[ObservationCarrierV1 | None] = ContextVar(
    "leviathan_api_observation", default=None
)


def current_observation() -> ObservationCarrierV1 | None:
    """Return the current request's diagnostic carrier, never its principal."""
    return _CURRENT_OBSERVATION.get()


def copy_observation_for_async_hop(
    carrier: ObservationCarrierV1 | None = None,
) -> ObservationCarrierV1 | None:
    """Explicitly copy diagnostic context across a task or queue boundary."""
    source = carrier if carrier is not None else _CURRENT_OBSERVATION.get()
    if source is None:
        return None
    if type(source) is not ObservationCarrierV1:
        raise TypeError("carrier must be ObservationCarrierV1")
    context = source.context.child_span()
    return ObservationCarrierV1(
        context=context,
        remote_parent=None,
        tracestate=None,
        remote_correlation_id=source.remote_correlation_id,
        remote_request_id=source.remote_request_id,
        parent_span_id=source.context.span_id,
    )


def verified_principal_from_request_state(request: Request) -> VerifiedPrincipalV1 | None:
    """Read the verified principal installed by an upstream auth layer."""
    value = getattr(request.state, "verified_principal", None)
    return value if type(value) is VerifiedPrincipalV1 else None


def _header_values(scope: Scope, name: bytes) -> list[bytes]:
    values: list[bytes] = []
    raw_headers = scope.get("headers", [])
    if not isinstance(raw_headers, (list, tuple)):
        return values
    for pair in raw_headers:
        if (
            isinstance(pair, (list, tuple))
            and len(pair) == 2
            and isinstance(pair[0], bytes)
            and isinstance(pair[1], bytes)
            and pair[0].lower() == name
        ):
            values.append(pair[1])
    return values


def _valid_correlation_id(raw: bytes) -> bool:
    try:
        value = raw.decode("ascii")
        parsed = UUID(value)
    except (UnicodeDecodeError, ValueError):
        return False
    return parsed.version == 4 and str(parsed).encode("ascii") == raw


def _remote_header_id(scope: Scope, name: bytes, *, correlation: bool) -> tuple[str | None, bool]:
    values = _header_values(scope, name)
    if not values:
        return None, False
    if len(values) != 1:
        return None, True
    value = values[0]
    valid = (
        _valid_correlation_id(value) if correlation else _REQUEST_ID.fullmatch(value) is not None
    )
    if not valid:
        return None, True
    return value.decode("ascii"), False


def _remote_parent(scope: Scope) -> tuple[RemoteParentLinkV1 | None, bool]:
    values = _header_values(scope, b"traceparent")
    if not values:
        return None, False
    if len(values) != 1:
        return None, True
    match = _TRACEPARENT.fullmatch(values[0])
    if match is None:
        return None, True
    trace_id, parent_span_id, _flags = (item.decode("ascii") for item in match.groups())
    if trace_id == "0" * 32 or parent_span_id == "0" * 16:
        return None, True
    return RemoteParentLinkV1(trace_id, parent_span_id), False


def _valid_tracestate(raw: bytes) -> bool:
    if not 1 <= len(raw) <= 512:
        return False
    try:
        raw.decode("ascii")
    except UnicodeDecodeError:
        return False
    members = raw.split(b",")
    if not 1 <= len(members) <= 32:
        return False
    seen: set[bytes] = set()
    for raw_member in members:
        member = raw_member.strip(b" ")
        if not 1 <= len(member) <= 256:
            return False
        key, separator, value = member.partition(b"=")
        if (
            not separator
            or not (_SIMPLE_TRACESTATE_KEY.fullmatch(key) or _TENANT_TRACESTATE_KEY.fullmatch(key))
            or key in seen
            or not 1 <= len(value) <= 256
            or value[:1] == b" "
            or value[-1:] == b" "
            or any(byte < 0x20 or byte > 0x7E or byte in {0x2C, 0x3D} for byte in value)
        ):
            return False
        seen.add(key)
    return True


def _validated_tracestate(scope: Scope, parent: RemoteParentLinkV1 | None) -> str | None:
    if parent is None:
        return None
    values = _header_values(scope, b"tracestate")
    if not values:
        return None
    raw = b",".join(values)
    if not _valid_tracestate(raw):
        return None
    return ",".join(part.strip(b" ").decode("ascii") for part in raw.split(b","))


class ObservationPropagationMiddleware:
    """Add minted OBS-001 context to authenticated HTTP requests and responses."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        principal_resolver: Callable[[Request], VerifiedPrincipalV1 | None],
        runtime: DiagnosticRuntimeV1,
        service: str,
        component: str,
        health_env: str = "development",
        exempt_paths: Iterable[str] = _DEFAULT_EXEMPT_PATHS,
        monotonic_ns_clock: Callable[[], int] = time.perf_counter_ns,
        utc_ns_clock: Callable[[], int] = time.time_ns,
        incident_active: Callable[[], bool] = lambda: False,
        sample_healthy: Callable[[], bool] = lambda: secrets.randbelow(1000) == 0,
        event_sink: Callable[[ObservationRequestEventV1], None] | None = None,
        anonymous_policy: Literal["reject", "attribute_anonymous"] = "reject",
    ) -> None:
        if (
            not callable(principal_resolver)
            or type(runtime) is not DiagnosticRuntimeV1
            or not callable(monotonic_ns_clock)
            or not callable(utc_ns_clock)
            or not callable(incident_active)
            or not callable(sample_healthy)
            or (event_sink is not None and not callable(event_sink))
        ):
            raise TypeError("observation middleware dependencies are invalid")
        try:
            configured_exempt = frozenset(exempt_paths)
        except TypeError as exc:
            raise TypeError("exempt_paths must be an iterable of paths") from exc
        if any(type(path) is not str or not path.startswith("/") for path in configured_exempt):
            raise ValueError("exempt paths must be absolute paths")
        if type(anonymous_policy) is not str or anonymous_policy not in {
            "reject",
            "attribute_anonymous",
        }:
            raise ValueError("anonymous policy is invalid")
        self.app: ASGIApp = app
        self.principal_resolver: Callable[[Request], VerifiedPrincipalV1 | None] = (
            principal_resolver
        )
        self.runtime: DiagnosticRuntimeV1 = runtime
        self.service: str = service
        self.component: str = component
        self.health_env: str = health_env
        self.exempt_paths: frozenset[str] = configured_exempt
        self.monotonic_ns_clock: Callable[[], int] = monotonic_ns_clock
        self.utc_ns_clock: Callable[[], int] = utc_ns_clock
        self.incident_active: Callable[[], bool] = incident_active
        self.sample_healthy: Callable[[], bool] = sample_healthy
        self.event_sink: Callable[[ObservationRequestEventV1], None] | None = event_sink
        self.anonymous_policy: Literal["reject", "attribute_anonymous"] = anonymous_policy
        self._traceparent_invalid: int = 0
        self._invalid_correlation_id: int = 0
        self._invalid_request_id: int = 0
        self._counter_lock: LockType = threading.Lock()

    @property
    def traceparent_invalid_count(self) -> int:
        """Content-free count of invalid or duplicated inbound traceparent fields."""
        with self._counter_lock:
            return self._traceparent_invalid

    @property
    def invalid_correlation_id_count(self) -> int:
        with self._counter_lock:
            return self._invalid_correlation_id

    @property
    def invalid_request_id_count(self) -> int:
        with self._counter_lock:
            return self._invalid_request_id

    def _record_invalid_traceparent(self) -> None:
        with self._counter_lock:
            self._traceparent_invalid += 1

    def _record_invalid_remote_id(self, *, correlation: bool) -> None:
        with self._counter_lock:
            if correlation:
                self._invalid_correlation_id += 1
            else:
                self._invalid_request_id += 1

    def _sample_request(self, status_code: int) -> bool:
        if status_code >= 400:
            return True
        try:
            if self.incident_active():
                return True
        except Exception:
            return True
        try:
            return bool(self.sample_healthy())
        except Exception:
            return True

    def _record_event(self, event: ObservationRequestEventV1) -> bool:
        sampled = self._sample_request(event.status_code)
        if sampled and self.event_sink is not None:
            with suppress(Exception):
                self.event_sink(event)
        return sampled

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive)
        state = scope.get("state")
        if state is None:
            state = {}
            scope["state"] = state
        if not isinstance(state, dict):
            await JSONResponse({"detail": "OBSERVATION_UNAVAILABLE"}, status_code=503)(
                scope, receive, send
            )
            return

        exempt = request.url.path in self.exempt_paths
        principal: VerifiedPrincipalV1 | None = None
        unauthorized = False
        principal_source = "anonymous"
        if not exempt:
            try:
                candidate = self.principal_resolver(request)
                if candidate is None:
                    unauthorized = self.anonymous_policy == "reject"
                else:
                    principal = require(candidate, _PRINCIPAL_TAG)
                    if type(principal) is not VerifiedPrincipalV1:
                        unauthorized = True
                    else:
                        principal_source = "verified"
            except Exception:
                unauthorized = True
        if principal is not None:
            state["observation_principal_id"] = principal.subject_id
            state["observation_principal_source"] = principal_source
        elif not unauthorized:
            state["observation_principal_id"] = None
            state["observation_principal_source"] = "anonymous"

        parent, invalid_parent = _remote_parent(scope)
        if invalid_parent:
            self._record_invalid_traceparent()
        tracestate = _validated_tracestate(scope, parent)
        remote_correlation_id, invalid_correlation_id = _remote_header_id(
            scope, b"x-correlation-id", correlation=True
        )
        remote_request_id, invalid_request_id = _remote_header_id(
            scope, b"x-request-id", correlation=False
        )
        if invalid_correlation_id:
            self._record_invalid_remote_id(correlation=True)
        if invalid_request_id:
            self._record_invalid_remote_id(correlation=False)
        env = principal.env if principal is not None else self.health_env
        try:
            observation = ObservationContextV1.create(
                runtime=self.runtime,
                service=self.service,
                component=self.component,
                env=env,
                trace=True,
            )
            carrier = ObservationCarrierV1(
                observation,
                parent,
                tracestate,
                remote_correlation_id,
                remote_request_id,
                observation.parent_span_id,
            )
            state["observation_context"] = observation
            state["observation_remote_parent"] = parent
            state["observation_tracestate"] = tracestate
            state["observation_carrier"] = carrier
            timer = LatencyTimerV1.start(
                stage="unknown",
                context=observation,
                monotonic_ns_clock=self.monotonic_ns_clock,
                utc_ns_clock=self.utc_ns_clock,
            )
        except Exception:
            await JSONResponse({"detail": "OBSERVATION_UNAVAILABLE"}, status_code=503)(
                scope, receive, send
            )
            return

        token: Token[ObservationCarrierV1 | None] = _CURRENT_OBSERVATION.set(carrier)
        status_code = 500

        async def send_with_observation(message: Message) -> None:
            nonlocal status_code
            if message.get("type") == "http.response.start":
                code = message.get("status")
                if type(code) is int:
                    status_code = code
                headers = [
                    (name, value)
                    for name, value in message.get("headers", [])
                    if name.lower()
                    not in {b"traceparent", b"tracestate", b"x-correlation-id", b"x-request-id"}
                ]
                assert observation.trace_id is not None and observation.span_id is not None
                headers.extend(
                    [
                        (
                            b"traceparent",
                            f"00-{observation.trace_id}-{observation.span_id}-00".encode("ascii"),
                        ),
                        (b"x-correlation-id", str(observation.correlation_id).encode("ascii")),
                        (b"x-request-id", observation.request_id.encode("ascii")),
                    ]
                )
                if tracestate is not None:
                    headers.append((b"tracestate", tracestate.encode("ascii")))
                message = {**message, "headers": headers}
            await send(message)

        try:
            if unauthorized:
                await JSONResponse({"detail": "UNAUTHENTICATED"}, status_code=401)(
                    scope, receive, send_with_observation
                )
            else:
                await self.app(scope, receive, send_with_observation)
        finally:
            sample: LatencySampleV1 | None
            try:
                sample = timer.stop()
                state["observation_latency"] = sample
            except Exception:
                sample = None
                state["observation_latency"] = None
            if sample is not None:
                event = ObservationRequestEventV1(
                    context=observation,
                    status_code=status_code,
                    timestamp_utc_ns=sample.timestamp_utc_ns,
                    duration_ns=sample.duration_ns,
                )
                state["observation_sampled"] = self._record_event(event)
                if state["observation_sampled"]:
                    state["observation_event"] = event
            _CURRENT_OBSERVATION.reset(token)
