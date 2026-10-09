"""Application-owned, privacy-bounded OBS-001 runtime wiring."""

from __future__ import annotations

import logging
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from queue import Full, Queue
from threading import Lock, Thread
from uuid import uuid4

from fastapi import FastAPI
from starlette.requests import HTTPConnection

from leviathan_api import __version__
from leviathan_api.middleware.observation import ObservationRequestEventV1
from leviathan_api.settings import Settings
from leviathan_core.observability import (
    BuildIdentityV1,
    DiagnosticIdFactoryV1,
    DiagnosticRegistriesV1,
    DiagnosticRuntimeV1,
    RegistrySnapshotV1,
)
from leviathan_core.seal import SealError, require
from leviathan_core.security.principal_verifier import VerifiedPrincipalV1

_VERIFIED_PRINCIPAL_TAG = "sec003.verified_principal.v1"
_ALLOWED_HEALTH_ENVS = frozenset({"development", "staging", "production"})
_LOGGER = logging.getLogger(__name__)


class ObservationRuntimeConfigError(ValueError):
    """Content-free invalid runtime configuration error."""

    def __init__(self) -> None:
        super().__init__("OBSERVATION_RUNTIME_INVALID")


class NonBlockingObservationEventSinkV1:
    """Bounded event queue with optional background delivery and drop accounting.

    Calls to this sink only perform `put_nowait`; a slow consumer runs on a daemon
    thread and can fill the queue, at which point events are dropped and counted.
    Event records contain typed observation context and timing/status only. This
    sink never logs and never receives request headers or bodies.
    """

    __slots__ = ("_consumer", "_dropped", "_lock", "_queue", "_worker")

    def __init__(
        self,
        *,
        capacity: int = 256,
        consumer: Callable[[ObservationRequestEventV1], None] | None = None,
    ) -> None:
        if type(capacity) is not int or not 1 <= capacity <= 4096:
            raise ObservationRuntimeConfigError()
        if consumer is not None and not callable(consumer):
            raise ObservationRuntimeConfigError()
        self._queue: Queue[ObservationRequestEventV1] = Queue(maxsize=capacity)
        self._consumer = consumer
        self._dropped = 0
        self._lock = Lock()
        self._worker: Thread | None = None
        if consumer is not None:
            worker = Thread(target=self._deliver, name="observation-event-sink", daemon=True)
            self._worker = worker
            worker.start()

    @property
    def dropped_count(self) -> int:
        with self._lock:
            return self._dropped

    def _drop(self) -> None:
        with self._lock:
            self._dropped += 1

    def __call__(self, event: ObservationRequestEventV1) -> None:
        try:
            if type(event) is not ObservationRequestEventV1:
                self._drop()
                return
            self._queue.put_nowait(event)
        except Full:
            self._drop()
        except Exception:
            # The instrumentation boundary must not affect request handling.
            with suppress(Exception):
                self._drop()

    def _deliver(self) -> None:
        consumer = self._consumer
        if consumer is None:
            return
        while True:
            event = self._queue.get()
            try:
                consumer(event)
            except Exception:
                self._drop()
            finally:
                self._queue.task_done()


@dataclass(frozen=True, slots=True)
class ObservationRuntimeDependenciesV1:
    runtime: DiagnosticRuntimeV1
    health_env: str
    incident_active: Callable[[], bool]
    event_sink: NonBlockingObservationEventSinkV1


@dataclass(frozen=True, slots=True)
class ObservationRuntimeConfigV1:
    """Explicit OBS configuration; its only field is a closed health environment."""

    health_env: str


def _build_observation_runtime(health_env: str) -> DiagnosticRuntimeV1:
    if type(health_env) is not str or health_env not in _ALLOWED_HEALTH_ENVS:
        raise ObservationRuntimeConfigError()

    snapshot = RegistrySnapshotV1.from_members
    return DiagnosticRuntimeV1(
        registries=DiagnosticRegistriesV1(
            services=snapshot({"api"}),
            components=snapshot({"http"}),
            strategies=snapshot({"api-unused"}),
            instruments=snapshot({"UNSPECIFIED"}),
            venues=snapshot({"NONE"}),
        ),
        id_factory=DiagnosticIdFactoryV1(uuid4_factory=uuid4),
        build_identity=BuildIdentityV1(version=__version__),
    )


def build_observation_runtime(settings: Settings) -> DiagnosticRuntimeV1:
    """Build the closed OBS-001 registries and ID factory for the API process."""
    if type(settings) is not Settings:
        raise ObservationRuntimeConfigError()
    return _build_observation_runtime(settings.env)


def operator_principal_resolver(request: HTTPConnection) -> VerifiedPrincipalV1 | None:
    """Return only an already-issued SEC-003 principal from trusted request state.

    The current operator middleware creates a SEC-002 TrustedPrincipalV1; it does
    not authenticate a signed SEC-003 token. That value cannot be upgraded here.
    Until the API installs a SEC-003 verifier upstream, this resolver returns
    None, preserving anonymous diagnostic attribution while trace IDs propagate.
    """
    try:
        value = getattr(request.state, "verified_principal", None)
        if type(value) is not VerifiedPrincipalV1:
            return None
        return require(value, _VERIFIED_PRINCIPAL_TAG)
    except (AttributeError, SealError):
        return None


def incident_active_from_app(application: FastAPI) -> Callable[[], bool]:
    """Read the live HALT authority without consulting request-supplied data."""

    def is_incident_active() -> bool:
        try:
            app_state = getattr(application.state, "leviathan", None)
            halts = getattr(app_state, "halts", None)
            if halts is None:
                return False
            return bool(halts.halted or halts.fault_code is not None)
        except Exception:
            # Treat a broken HALT read as active so request failures are sampled.
            return True

    return is_incident_active


def build_observation_dependencies(
    settings: Settings | None,
    application: FastAPI,
    *,
    event_sink: NonBlockingObservationEventSinkV1 | None = None,
    config: ObservationRuntimeConfigV1 | None = None,
) -> ObservationRuntimeDependenciesV1:
    if type(application) is not FastAPI:
        raise ObservationRuntimeConfigError()
    if config is not None:
        if type(config) is not ObservationRuntimeConfigV1:
            raise ObservationRuntimeConfigError()
        health_env = config.health_env
        runtime = _build_observation_runtime(health_env)
    else:
        try:
            if type(settings) is not Settings:
                raise ObservationRuntimeConfigError()
            health_env = settings.env
            runtime = build_observation_runtime(settings)
        except ObservationRuntimeConfigError:
            _LOGGER.warning("OBSERVATION_RUNTIME_DEFAULTED")
            return default_observation_dependencies(application, event_sink=event_sink)
    return ObservationRuntimeDependenciesV1(
        runtime=runtime,
        health_env=health_env,
        incident_active=incident_active_from_app(application),
        event_sink=(event_sink if event_sink is not None else NonBlockingObservationEventSinkV1()),
    )


def default_observation_dependencies(
    application: FastAPI,
    *,
    event_sink: NonBlockingObservationEventSinkV1 | None = None,
) -> ObservationRuntimeDependenciesV1:
    """Build the deterministic in-memory OBS runtime used for invalid implicit config."""
    if type(application) is not FastAPI:
        raise ObservationRuntimeConfigError()
    return ObservationRuntimeDependenciesV1(
        runtime=_build_observation_runtime("development"),
        health_env="development",
        incident_active=incident_active_from_app(application),
        event_sink=(event_sink if event_sink is not None else NonBlockingObservationEventSinkV1()),
    )


__all__ = [
    "NonBlockingObservationEventSinkV1",
    "ObservationRuntimeConfigError",
    "ObservationRuntimeConfigV1",
    "ObservationRuntimeDependenciesV1",
    "build_observation_dependencies",
    "build_observation_runtime",
    "default_observation_dependencies",
    "incident_active_from_app",
    "operator_principal_resolver",
]
