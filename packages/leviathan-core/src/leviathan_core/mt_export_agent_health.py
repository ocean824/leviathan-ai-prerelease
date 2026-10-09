"""Fail-closed health evaluation for synthetic MT terminal-agent heartbeats."""

from __future__ import annotations

import re
from collections.abc import Collection, Iterable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Literal, Protocol, cast

from pydantic import Field, model_validator

from leviathan_core.seal import Issuer, SealedModel, SealError, require

_POLICY_TAG = "mtbr.agent_health.policy.v1"
_HEALTH_TAG = "mtbr.agent_health.result.v1"
_POLICY_ISSUER = Issuer(_POLICY_TAG)
_HEALTH_ISSUER = Issuer(_HEALTH_TAG)
_MAX_HEARTBEAT_AGE_NS = 10_000_000_000
_MAX_CLOCK_SKEW_NS = 2_000_000_000
_INT64_MAX = (1 << 63) - 1
_BUILD_RE = re.compile(r"[0-9]{1,10}\Z", re.ASCII)
_CAPABILITY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}\Z", re.ASCII)


class AgentHealthError(ValueError):
    """Content-free error emitted at the public health-kernel boundary."""

    _CODES = frozenset(
        {
            "INVALID_HEARTBEAT",
            "INVALID_POLICY",
            "POLICY_OUT_OF_BOUNDS",
            "CLOCK_UNAVAILABLE",
            "CLOCK_INVALID",
            "HEALTH_EVALUATION_FAILED",
            "UNISSUED_HEALTH",
        }
    )

    def __init__(self, code: str) -> None:
        self.code = (
            code
            if type(code) is str and code in self._CODES
            else "HEALTH_EVALUATION_FAILED"
        )
        super().__init__(self.code)


class MtPlatformV1(StrEnum):
    MT4 = "MT4"
    MT5 = "MT5"


class AgentReportedStatusV1(StrEnum):
    OK = "OK"
    DEGRADED = "DEGRADED"
    ERROR = "ERROR"


class AgentHealthStateV1(StrEnum):
    HEALTHY = "HEALTHY"
    UNHEALTHY = "UNHEALTHY"


class AgentHealthReasonV1(StrEnum):
    BUILD_BELOW_MINIMUM = "BUILD_BELOW_MINIMUM"
    BUILD_MISSING = "BUILD_MISSING"
    BUILD_NOT_ALLOWED = "BUILD_NOT_ALLOWED"
    BUILD_UNPARSABLE = "BUILD_UNPARSABLE"
    CAPABILITIES_UNKNOWN = "CAPABILITIES_UNKNOWN"
    CAPABILITY_MISSING = "CAPABILITY_MISSING"
    CLOCK_SKEW = "CLOCK_SKEW"
    DISK_LOW = "DISK_LOW"
    DISK_UNKNOWN = "DISK_UNKNOWN"
    HEARTBEAT_MISSING = "HEARTBEAT_MISSING"
    HEARTBEAT_STALE = "HEARTBEAT_STALE"
    HEARTBEAT_TIMESTAMP_INVALID = "HEARTBEAT_TIMESTAMP_INVALID"
    HEARTBEAT_TIMESTAMP_MISSING = "HEARTBEAT_TIMESTAMP_MISSING"
    PLATFORM_INCOMPATIBLE = "PLATFORM_INCOMPATIBLE"
    PLATFORM_MISSING = "PLATFORM_MISSING"
    PLATFORM_UNKNOWN = "PLATFORM_UNKNOWN"
    STATUS_DEGRADED = "STATUS_DEGRADED"
    STATUS_ERROR = "STATUS_ERROR"
    STATUS_MISSING = "STATUS_MISSING"
    STATUS_UNKNOWN = "STATUS_UNKNOWN"


class UtcNsClock(Protocol):
    """Trusted UTC-nanosecond time source injected by the caller."""

    def now_utc_ns(self) -> int: ...


@dataclass(frozen=True, slots=True)
class AgentHeartbeatV1:
    """Untrusted synthetic heartbeat facts; evaluation validates every field.

    Scalar fields intentionally accept raw objects so absent or malformed source
    facts become typed unhealthy reasons instead of leaking validation details.
    Capability collections are copied into a canonical tuple at construction.
    """

    heartbeat_utc_ns: object
    free_disk_bytes: object
    platform: object
    terminal_build: object
    status: object
    capabilities: object
    _invalid_fields: frozenset[str] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        invalid: set[str] = set()
        for name, allowed in (
            ("heartbeat_utc_ns", (int, bool)),
            ("free_disk_bytes", (int, bool)),
            ("platform", (str, MtPlatformV1)),
            ("terminal_build", (int, bool, str)),
            ("status", (str, AgentReportedStatusV1)),
        ):
            value = getattr(self, name)
            if (value is not None and type(value) not in allowed) or (
                type(value) is str and len(value) > 128
            ):
                object.__setattr__(self, name, None)
                invalid.add(name)

        raw_capabilities = self.capabilities
        if raw_capabilities is None:
            pass
        elif type(raw_capabilities) in (tuple, list, set, frozenset):
            collection = cast(Collection[object], raw_capabilities)
            try:
                if len(collection) > 128:
                    raise ValueError
                values: tuple[object, ...] = tuple(cast(Iterable[object], collection))
                if any(
                    type(value) is not str
                    or _CAPABILITY_RE.fullmatch(value) is None
                    for value in values
                ):
                    raise ValueError
                object.__setattr__(self, "capabilities", tuple(sorted(set(values))))
            except Exception:
                object.__setattr__(self, "capabilities", None)
                invalid.add("capabilities")
        else:
            object.__setattr__(self, "capabilities", None)
            invalid.add("capabilities")
        object.__setattr__(self, "_invalid_fields", frozenset(invalid))

    @property
    def invalid_fields(self) -> frozenset[str]:
        """Field names whose unsafe raw values were discarded on construction."""

        return self._invalid_fields


class AgentHealthPolicyV1(SealedModel):
    """SEAL-issued compatibility, capacity and clock-skew requirements."""

    expected_platform: MtPlatformV1
    min_terminal_build: int = Field(ge=1, le=_INT64_MAX)
    min_free_disk_bytes: int = Field(ge=1, le=_INT64_MAX)
    max_clock_skew_ns: int = Field(ge=0, le=_MAX_CLOCK_SKEW_NS)
    required_capabilities: tuple[str, ...]
    allowed_builds: tuple[int, ...] | None = None

    @model_validator(mode="after")
    def _validate_canonical_values(self) -> AgentHealthPolicyV1:
        if type(self.expected_platform) is not MtPlatformV1:
            raise ValueError("INVALID_POLICY")
        if type(self.min_terminal_build) is not int:
            raise ValueError("INVALID_POLICY")
        if type(self.min_free_disk_bytes) is not int:
            raise ValueError("INVALID_POLICY")
        if type(self.max_clock_skew_ns) is not int:
            raise ValueError("INVALID_POLICY")
        if type(self.required_capabilities) is not tuple:
            raise ValueError("INVALID_POLICY")
        if self.required_capabilities != tuple(sorted(set(self.required_capabilities))):
            raise ValueError("INVALID_POLICY")
        if any(
            type(value) is not str or _CAPABILITY_RE.fullmatch(value) is None
            for value in self.required_capabilities
        ):
            raise ValueError("INVALID_POLICY")
        if self.allowed_builds is not None:
            if type(self.allowed_builds) is not tuple:
                raise ValueError("INVALID_POLICY")
            if not self.allowed_builds or self.allowed_builds != tuple(
                sorted(set(self.allowed_builds))
            ):
                raise ValueError("INVALID_POLICY")
            if any(
                type(build) is not int or not 1 <= build <= _INT64_MAX
                for build in self.allowed_builds
            ):
                raise ValueError("INVALID_POLICY")
        return self


class AgentHealthV1(SealedModel):
    """Immutable decision evidence; it never grants activation permission."""

    state: AgentHealthStateV1
    reason_codes: tuple[AgentHealthReasonV1, ...]
    observed_at_utc_ns: int = Field(ge=0, le=_INT64_MAX)
    heartbeat_age_ns: int | None = Field(default=None, ge=0, le=_INT64_MAX)
    activation_permitted: Literal[False] = False

    @model_validator(mode="after")
    def _validate_decision(self) -> AgentHealthV1:
        if type(self.state) is not AgentHealthStateV1:
            raise ValueError("INVALID_HEALTH")
        if type(self.reason_codes) is not tuple:
            raise ValueError("INVALID_HEALTH")
        if self.reason_codes != tuple(
            sorted(set(self.reason_codes), key=lambda reason: reason.value)
        ):
            raise ValueError("INVALID_HEALTH")
        expected = (
            AgentHealthStateV1.HEALTHY
            if not self.reason_codes
            else AgentHealthStateV1.UNHEALTHY
        )
        if self.state is not expected or self.activation_permitted is not False:
            raise ValueError("INVALID_HEALTH")
        return self

    @property
    def healthy(self) -> bool:
        return _HEALTH_ISSUER.issued_here(self) and self.state is AgentHealthStateV1.HEALTHY


def _policy_collection(value: object, *, max_count: int, allow_empty: bool) -> tuple[str, ...]:
    if isinstance(value, (str, bytes, bytearray, dict)):
        raise AgentHealthError("INVALID_POLICY")
    try:
        if isinstance(value, Collection) and len(value) > max_count:
            raise AgentHealthError("INVALID_POLICY")
        iterator = iter(cast(Iterable[object], value))
        bounded_items: list[object] = []
        for item in iterator:
            if len(bounded_items) == max_count:
                raise AgentHealthError("INVALID_POLICY")
            bounded_items.append(item)
        items = tuple(bounded_items)
    except AgentHealthError:
        raise
    except Exception:
        raise AgentHealthError("INVALID_POLICY") from None
    if (not allow_empty and not items) or any(
        type(item) is not str or _CAPABILITY_RE.fullmatch(item) is None for item in items
    ):
        raise AgentHealthError("INVALID_POLICY")
    if len(items) != len(set(items)):
        raise AgentHealthError("INVALID_POLICY")
    return tuple(sorted(cast(tuple[str, ...], items)))


def _build_collection(value: object) -> tuple[int, ...] | None:
    if value is None:
        return None
    if isinstance(value, (str, bytes, bytearray, dict)):
        raise AgentHealthError("INVALID_POLICY")
    try:
        if isinstance(value, Collection) and len(value) > 128:
            raise AgentHealthError("POLICY_OUT_OF_BOUNDS")
        iterator = iter(cast(Iterable[object], value))
        bounded_items: list[object] = []
        for item in iterator:
            if len(bounded_items) == 128:
                raise AgentHealthError("POLICY_OUT_OF_BOUNDS")
            bounded_items.append(item)
        items = tuple(bounded_items)
    except AgentHealthError:
        raise
    except Exception:
        raise AgentHealthError("INVALID_POLICY") from None
    if not items or any(
        type(item) is not int or not 1 <= item <= _INT64_MAX for item in items
    ):
        raise AgentHealthError("POLICY_OUT_OF_BOUNDS")
    if len(items) != len(set(items)):
        raise AgentHealthError("INVALID_POLICY")
    return tuple(sorted(cast(tuple[int, ...], items)))


def make_agent_health_policy(
    *,
    expected_platform: MtPlatformV1,
    min_terminal_build: int,
    min_free_disk_bytes: int,
    max_clock_skew_ns: int,
    required_capabilities: object,
    allowed_builds: object = None,
) -> AgentHealthPolicyV1:
    """Validate and seal one explicit health policy (there are no defaults)."""

    if type(expected_platform) is not MtPlatformV1:
        raise AgentHealthError("INVALID_POLICY")
    if (
        type(min_terminal_build) is not int
        or type(min_free_disk_bytes) is not int
        or type(max_clock_skew_ns) is not int
    ):
        raise AgentHealthError("INVALID_POLICY")
    if (
        not 1 <= min_terminal_build <= _INT64_MAX
        or not 1 <= min_free_disk_bytes <= _INT64_MAX
        or not 0 <= max_clock_skew_ns <= _MAX_CLOCK_SKEW_NS
    ):
        raise AgentHealthError("POLICY_OUT_OF_BOUNDS")
    capabilities = _policy_collection(
        required_capabilities, max_count=64, allow_empty=True
    )
    builds = _build_collection(allowed_builds)
    try:
        policy = AgentHealthPolicyV1(
            expected_platform=expected_platform,
            min_terminal_build=min_terminal_build,
            min_free_disk_bytes=min_free_disk_bytes,
            max_clock_skew_ns=max_clock_skew_ns,
            required_capabilities=capabilities,
            allowed_builds=builds,
        )
        return _POLICY_ISSUER.issue(policy)
    except AgentHealthError:
        raise
    except Exception:
        raise AgentHealthError("INVALID_POLICY") from None


def _clock_value(clock: object) -> int:
    try:
        method = getattr(clock, "now_utc_ns", None)
        if not callable(method):
            raise AgentHealthError("CLOCK_UNAVAILABLE")
        value = method()
    except AgentHealthError:
        raise
    except Exception:
        raise AgentHealthError("CLOCK_UNAVAILABLE") from None
    if type(value) is not int or not 0 <= value <= _INT64_MAX:
        raise AgentHealthError("CLOCK_INVALID")
    return value


def _parse_platform(value: object) -> MtPlatformV1 | None:
    if type(value) is MtPlatformV1:
        return value
    if type(value) is str:
        try:
            return MtPlatformV1(value)
        except ValueError:
            return None
    return None


def _parse_build(value: object) -> int | None:
    if type(value) is int:
        return value if 1 <= value <= _INT64_MAX else None
    if type(value) is str and _BUILD_RE.fullmatch(value) is not None:
        parsed = int(value)
        return parsed if parsed > 0 else None
    return None


def _reported_status(value: object) -> AgentReportedStatusV1 | None:
    if type(value) is AgentReportedStatusV1:
        return value
    if type(value) is str:
        try:
            return AgentReportedStatusV1(value)
        except ValueError:
            return None
    return None


def evaluate_agent_health(
    heartbeat: AgentHeartbeatV1 | None,
    policy: AgentHealthPolicyV1,
    clock: UtcNsClock,
) -> AgentHealthV1:
    """Evaluate synthetic terminal facts against one read from the trusted clock."""

    if heartbeat is not None and type(heartbeat) is not AgentHeartbeatV1:
        raise AgentHealthError("INVALID_HEARTBEAT")
    if type(policy) is not AgentHealthPolicyV1:
        raise AgentHealthError("INVALID_POLICY")
    try:
        require(policy, _POLICY_TAG)
    except SealError:
        raise AgentHealthError("INVALID_POLICY") from None

    now = _clock_value(clock)
    reasons: set[AgentHealthReasonV1] = set()
    age: int | None = None
    if heartbeat is None:
        reasons.add(AgentHealthReasonV1.HEARTBEAT_MISSING)
    else:
        invalid = heartbeat.invalid_fields
        timestamp = heartbeat.heartbeat_utc_ns
        if timestamp is None:
            reasons.add(
                AgentHealthReasonV1.HEARTBEAT_TIMESTAMP_INVALID
                if "heartbeat_utc_ns" in invalid
                else AgentHealthReasonV1.HEARTBEAT_TIMESTAMP_MISSING
            )
        elif type(timestamp) is not int or not 0 <= timestamp <= _INT64_MAX:
            reasons.add(AgentHealthReasonV1.HEARTBEAT_TIMESTAMP_INVALID)
        elif timestamp > now:
            delta = timestamp - now
            if delta > policy.max_clock_skew_ns:
                reasons.add(AgentHealthReasonV1.CLOCK_SKEW)
            else:
                age = 0
        else:
            age = now - timestamp
            if age > _MAX_HEARTBEAT_AGE_NS:
                reasons.add(AgentHealthReasonV1.HEARTBEAT_STALE)

        disk = heartbeat.free_disk_bytes
        if (
            "free_disk_bytes" in invalid
            or type(disk) is not int
            or disk < 0
        ):
            reasons.add(AgentHealthReasonV1.DISK_UNKNOWN)
        elif disk < policy.min_free_disk_bytes:
            reasons.add(AgentHealthReasonV1.DISK_LOW)

        status = heartbeat.status
        if status is None:
            reasons.add(
                AgentHealthReasonV1.STATUS_UNKNOWN
                if "status" in invalid
                else AgentHealthReasonV1.STATUS_MISSING
            )
        else:
            parsed_status = _reported_status(status)
            if parsed_status is None:
                reasons.add(AgentHealthReasonV1.STATUS_UNKNOWN)
            elif parsed_status is AgentReportedStatusV1.DEGRADED:
                reasons.add(AgentHealthReasonV1.STATUS_DEGRADED)
            elif parsed_status is AgentReportedStatusV1.ERROR:
                reasons.add(AgentHealthReasonV1.STATUS_ERROR)

        platform = heartbeat.platform
        if platform is None:
            reasons.add(
                AgentHealthReasonV1.PLATFORM_UNKNOWN
                if "platform" in invalid
                else AgentHealthReasonV1.PLATFORM_MISSING
            )
        else:
            parsed_platform = _parse_platform(platform)
            if parsed_platform is None:
                reasons.add(AgentHealthReasonV1.PLATFORM_UNKNOWN)
            elif parsed_platform is not policy.expected_platform:
                reasons.add(AgentHealthReasonV1.PLATFORM_INCOMPATIBLE)

        build_value = heartbeat.terminal_build
        if build_value is None:
            reasons.add(
                AgentHealthReasonV1.BUILD_UNPARSABLE
                if "terminal_build" in invalid
                else AgentHealthReasonV1.BUILD_MISSING
            )
        else:
            build = _parse_build(build_value)
            if build is None:
                reasons.add(AgentHealthReasonV1.BUILD_UNPARSABLE)
            else:
                if build < policy.min_terminal_build:
                    reasons.add(AgentHealthReasonV1.BUILD_BELOW_MINIMUM)
                if policy.allowed_builds is not None and build not in policy.allowed_builds:
                    reasons.add(AgentHealthReasonV1.BUILD_NOT_ALLOWED)

        capabilities = heartbeat.capabilities
        if type(capabilities) is not tuple or any(
            type(capability) is not str for capability in capabilities
        ):
            reasons.add(AgentHealthReasonV1.CAPABILITIES_UNKNOWN)
        elif any(capability not in capabilities for capability in policy.required_capabilities):
            reasons.add(AgentHealthReasonV1.CAPABILITY_MISSING)

    ordered = tuple(sorted(reasons, key=lambda reason: reason.value))
    state = AgentHealthStateV1.HEALTHY if not ordered else AgentHealthStateV1.UNHEALTHY
    try:
        result = AgentHealthV1(
            state=state,
            reason_codes=ordered,
            observed_at_utc_ns=now,
            heartbeat_age_ns=age,
            activation_permitted=False,
        )
        return _HEALTH_ISSUER.issue(result)
    except Exception:
        raise AgentHealthError("HEALTH_EVALUATION_FAILED") from None


def is_issued_agent_health(value: object) -> bool:
    """Check both issuance identity and content integrity for a health result."""

    return type(value) is AgentHealthV1 and _HEALTH_ISSUER.issued_here(value)


def require_agent_health(value: object) -> AgentHealthV1:
    """Require an issued, intact result at a downstream evidence boundary."""

    if type(value) is not AgentHealthV1:
        raise AgentHealthError("UNISSUED_HEALTH")
    try:
        return require(value, _HEALTH_TAG)
    except SealError:
        raise AgentHealthError("UNISSUED_HEALTH") from None


__all__ = [
    "AgentHealthError",
    "AgentHealthPolicyV1",
    "AgentHealthReasonV1",
    "AgentHealthStateV1",
    "AgentHealthV1",
    "AgentHeartbeatV1",
    "AgentReportedStatusV1",
    "MtPlatformV1",
    "UtcNsClock",
    "evaluate_agent_health",
    "is_issued_agent_health",
    "make_agent_health_policy",
    "require_agent_health",
]
