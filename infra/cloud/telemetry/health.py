"""Fail-closed readiness kernel over injected dependency probes."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Mapping
from concurrent.futures import Future, ThreadPoolExecutor, TimeoutError
from dataclasses import dataclass
from decimal import Decimal
from enum import StrEnum
from types import MappingProxyType
from typing import Protocol

from leviathan_core.seal import SealError, require
from leviathan_core.security.principal_verifier import VerifiedPrincipalV1


class DependencyName(StrEnum):
    DB = "DB"
    CACHE = "CACHE"
    STREAMS = "STREAMS"
    OMS_VENUE = "OMS_VENUE"
    CONFIG = "CONFIG"
    RISK_RULES = "RISK_RULES"
    TIME_SYNC = "TIME_SYNC"


class ProbeStatus(StrEnum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    UNHEALTHY = "UNHEALTHY"
    UNKNOWN = "UNKNOWN"


_DEPENDENCIES = tuple(DependencyName)
_PRINCIPAL_TAG = "sec003.verified_principal.v1"
_HEALTH_SCOPE = "ops.health.read"
_ALLOWED_ROLES = frozenset({"Operator", "DevOps"})


class HealthError(RuntimeError):
    """Content-free kernel error."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class ProbeResultV1:
    status: ProbeStatus
    observed_ns: int
    value: Decimal | None = None

    def __post_init__(self) -> None:
        if (
            type(self.status) is not ProbeStatus
            or type(self.observed_ns) is not int
            or self.observed_ns < 0
            or (self.value is not None and type(self.value) is not Decimal)
            or (self.value is not None and not self.value.is_finite())
        ):
            raise HealthError("PROBE_RESULT_INVALID")


class ReadinessProbe(Protocol):
    def check(self, now_ns: int) -> ProbeResultV1: ...


class HealthPolicy(Protocol):
    def allows(self, principal: VerifiedPrincipalV1, action: str) -> bool: ...


@dataclass(frozen=True, slots=True)
class HealthResponseV1:
    status_code: int
    statuses: Mapping[DependencyName, ProbeStatus]

    def __post_init__(self) -> None:
        if type(self.status_code) is not int or self.status_code not in (200, 503):
            raise HealthError("HEALTH_RESPONSE_INVALID")
        object.__setattr__(self, "statuses", MappingProxyType(dict(self.statuses)))

    @property
    def ready(self) -> bool:
        return self.status_code == 200


@dataclass(frozen=True, slots=True)
class _ProbeTask:
    future: Future[ProbeResultV1]
    started_ns: int


def livez() -> HealthResponseV1:
    """Report kernel responsiveness without touching dependencies or auth."""
    return HealthResponseV1(200, MappingProxyType({}))


class HealthKernelV1:
    """Evaluate all seven dependencies using bounded, injected probes."""

    def __init__(
        self,
        *,
        probes: Mapping[DependencyName, ReadinessProbe],
        policy: HealthPolicy,
        utc_ns: Callable[[], int] = time.time_ns,
        monotonic_ns: Callable[[], int] = time.monotonic_ns,
        stream_lag_threshold_seconds: Decimal = Decimal("0.300"),
        time_sync_threshold_seconds: Decimal = Decimal("0.020"),
        probe_timeout_ns: int = 100_000_000,
        max_observation_age_ns: int = 5_000_000_000,
    ) -> None:
        if (
            not isinstance(probes, Mapping)
            or any(type(key) is not DependencyName for key in probes)
            or any(not callable(getattr(probe, "check", None)) for probe in probes.values())
            or not callable(getattr(policy, "allows", None))
            or not callable(utc_ns)
            or not callable(monotonic_ns)
            or type(stream_lag_threshold_seconds) is not Decimal
            or not stream_lag_threshold_seconds.is_finite()
            or stream_lag_threshold_seconds <= 0
            or type(time_sync_threshold_seconds) is not Decimal
            or not time_sync_threshold_seconds.is_finite()
            or time_sync_threshold_seconds <= 0
            or type(probe_timeout_ns) is not int
            or not 1 <= probe_timeout_ns <= 1_000_000_000
            or type(max_observation_age_ns) is not int
            or not 1 <= max_observation_age_ns <= 60_000_000_000
        ):
            raise HealthError("HEALTH_CONFIG_INVALID")
        self._probes = MappingProxyType(dict(probes))
        self._policy = policy
        self._utc_ns = utc_ns
        self._monotonic_ns = monotonic_ns
        self._stream_threshold = stream_lag_threshold_seconds
        self._time_sync_threshold = time_sync_threshold_seconds
        self._timeout_ns = probe_timeout_ns
        self._max_age_ns = max_observation_age_ns
        self._executor = ThreadPoolExecutor(
            max_workers=len(_DEPENDENCIES), thread_name_prefix="health-probe"
        )
        self._lock = threading.Lock()
        self._inflight: dict[DependencyName, _ProbeTask] = {}
        self._closed = False

    def livez(self) -> HealthResponseV1:
        return livez()

    def _probe(self, dependency: DependencyName, now_ns: int) -> ProbeResultV1:
        probe = self._probes.get(dependency)
        if probe is None:
            return ProbeResultV1(ProbeStatus.UNKNOWN, now_ns)
        try:
            started_ns = self._monotonic_ns()
        except Exception:
            return ProbeResultV1(ProbeStatus.UNHEALTHY, now_ns)
        if type(started_ns) is not int or started_ns < 0:
            return ProbeResultV1(ProbeStatus.UNHEALTHY, now_ns)
        with self._lock:
            if self._closed:
                return ProbeResultV1(ProbeStatus.UNHEALTHY, now_ns)
            task = self._inflight.get(dependency)
            if task is None:
                task = _ProbeTask(self._executor.submit(probe.check, now_ns), started_ns)
                self._inflight[dependency] = task
        elapsed_ns = started_ns - task.started_ns
        remaining_ns = self._timeout_ns - elapsed_ns
        if elapsed_ns < 0 or remaining_ns <= 0:
            if task.future.done():
                with self._lock:
                    if self._inflight.get(dependency) is task:
                        self._inflight.pop(dependency, None)
            return ProbeResultV1(ProbeStatus.UNHEALTHY, now_ns)
        try:
            result = task.future.result(timeout=remaining_ns / 1_000_000_000)
        except TimeoutError:
            if task.future.done():
                with self._lock:
                    if self._inflight.get(dependency) is task:
                        self._inflight.pop(dependency, None)
            return ProbeResultV1(ProbeStatus.UNHEALTHY, now_ns)
        except Exception:
            with self._lock:
                if self._inflight.get(dependency) is task:
                    self._inflight.pop(dependency, None)
            return ProbeResultV1(ProbeStatus.UNHEALTHY, now_ns)
        with self._lock:
            if self._inflight.get(dependency) is task:
                self._inflight.pop(dependency, None)
        try:
            finished_ns = self._monotonic_ns()
        except Exception:
            return ProbeResultV1(ProbeStatus.UNHEALTHY, now_ns)
        if (
            type(finished_ns) is not int
            or finished_ns < task.started_ns
            or finished_ns - task.started_ns >= self._timeout_ns
        ):
            return ProbeResultV1(ProbeStatus.UNHEALTHY, now_ns)
        if type(result) is not ProbeResultV1:
            return ProbeResultV1(ProbeStatus.UNHEALTHY, now_ns)
        if result.observed_ns > now_ns or now_ns - result.observed_ns > self._max_age_ns:
            return ProbeResultV1(ProbeStatus.UNHEALTHY, result.observed_ns)
        if result.status is not ProbeStatus.HEALTHY:
            return result
        if dependency is DependencyName.STREAMS and (
            result.value is None or result.value >= self._stream_threshold
        ):
            return ProbeResultV1(ProbeStatus.UNHEALTHY, result.observed_ns)
        if dependency is DependencyName.TIME_SYNC and (
            result.value is None or abs(result.value) >= self._time_sync_threshold
        ):
            return ProbeResultV1(ProbeStatus.UNHEALTHY, result.observed_ns)
        return result

    def _statuses(self) -> Mapping[DependencyName, ProbeStatus]:
        now_ns = self._utc_ns()
        if type(now_ns) is not int or now_ns < 0:
            return MappingProxyType({name: ProbeStatus.UNKNOWN for name in _DEPENDENCIES})
        statuses = {dependency: ProbeStatus.UNKNOWN for dependency in _DEPENDENCIES}
        for dependency in _DEPENDENCIES:
            try:
                statuses[dependency] = self._probe(dependency, now_ns).status
            except Exception:
                statuses[dependency] = ProbeStatus.UNHEALTHY
        return MappingProxyType(statuses)

    def readyz(self) -> HealthResponseV1:
        statuses = self._statuses()
        ready = all(status is ProbeStatus.HEALTHY for status in statuses.values())
        return HealthResponseV1(200 if ready else 503, statuses)

    def healthz(self, principal: VerifiedPrincipalV1) -> HealthResponseV1:
        try:
            if type(principal) is not VerifiedPrincipalV1:
                raise SealError("principal rejected")
            require(principal, _PRINCIPAL_TAG)
            permitted = (
                principal.role in _ALLOWED_ROLES
                and _HEALTH_SCOPE in principal.scopes
                and self._policy.allows(principal, _HEALTH_SCOPE) is True
            )
        except Exception:
            permitted = False
        if not permitted:
            raise HealthError("HEALTH_ACCESS_DENIED") from None
        return HealthResponseV1(200, self._statuses())

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
        self._executor.shutdown(wait=False, cancel_futures=True)

    def __enter__(self) -> HealthKernelV1:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


__all__ = [
    "DependencyName",
    "HealthError",
    "HealthKernelV1",
    "HealthPolicy",
    "HealthResponseV1",
    "ProbeResultV1",
    "ProbeStatus",
    "ReadinessProbe",
    "livez",
]
