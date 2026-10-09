"""Typed, package-local observation records with safe JSON serialization."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Never, SupportsIndex

from leviathan_core.observability.context import ObservationContextV1
from leviathan_core.observability.redaction import (
    MAX_LINE_BYTES,
    DiagnosticFieldError,
    DiagnosticFieldRegistryV1,
    RedactionError,
    sanitize_fields,
)

_STAGES = DiagnosticFieldRegistryV1().fields["stage"].allowed_values
_SAFE_MESSAGES = frozenset(
    {
        "Observation recorded.",
        "Operation started.",
        "Operation completed.",
        "Operation failed.",
        "Latency recorded.",
    }
)


class LogLevel(StrEnum):
    TRACE = "TRACE"
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARN = "WARN"
    ERROR = "ERROR"


class ErrorCode(StrEnum):
    UNKNOWN = "UNKNOWN"
    INVALID_INPUT = "INVALID_INPUT"
    INTERNAL_ERROR = "INTERNAL_ERROR"
    REDACTION_FAILURE = "REDACTION_FAILURE"
    DIAGNOSTIC_FIELD_UNREGISTERED = "DIAGNOSTIC_FIELD_UNREGISTERED"


_ERROR_MESSAGES = {
    ErrorCode.UNKNOWN: "Operation failed.",
    ErrorCode.INVALID_INPUT: "Operation failed.",
    ErrorCode.INTERNAL_ERROR: "Operation failed.",
    ErrorCode.REDACTION_FAILURE: "Observation redaction failed.",
    ErrorCode.DIAGNOSTIC_FIELD_UNREGISTERED: "Operation failed.",
}


def _context_payload(context: ObservationContextV1) -> dict[str, str]:
    result = {
        "service": context.service,
        "component": context.component,
        "version": context.version,
        "env": context.env,
        "registry_bundle_id": context.registry_bundle_id,
        "correlation_id": str(context.correlation_id),
        "request_id": context.request_id,
    }
    for key in ("trace_id", "span_id", "strategy_id", "order_id", "symbol", "venue"):
        value = getattr(context, key)
        if value is not None:
            result[key] = value
    return result


def _encode(payload: dict[str, object]) -> str:
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


@dataclass(frozen=True, slots=True, init=False, repr=False)
class StructuredLogV1:
    """A diagnostic record; it has no route or execution authority."""

    timestamp_utc_ns: int
    level: LogLevel
    message: str
    context: ObservationContextV1
    fields: Mapping[str, object] = field(default_factory=dict, repr=False)
    error_code: ErrorCode | str | None = None
    truncated: bool = field(default=False, init=False)
    redacted: bool = field(default=False, init=False)
    _json: str = field(default="", init=False, repr=False)

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError("use StructuredLogV1.create")

    def __post_init__(self) -> None:
        if isinstance(self.timestamp_utc_ns, bool) or not isinstance(self.timestamp_utc_ns, int):
            raise ValueError("timestamp_utc_ns must be an integer")
        if self.timestamp_utc_ns < 0:
            raise ValueError("timestamp_utc_ns must be nonnegative")
        if not isinstance(self.context, ObservationContextV1):
            raise TypeError("context must be ObservationContextV1")
        try:
            level = LogLevel(self.level)
        except ValueError as exc:
            raise ValueError("invalid log level") from exc
        object.__setattr__(self, "level", level)
        if self.error_code is None:
            error = None
            message = self.message if self.message in _SAFE_MESSAGES else "Observation recorded."
        else:
            try:
                error = ErrorCode(self.error_code)
            except ValueError:
                error = ErrorCode.UNKNOWN
                message = "Observation recorded."
            else:
                message = _ERROR_MESSAGES[error]
        safe_context = _context_payload(self.context)
        try:
            safe_fields, truncated, redacted = sanitize_fields(
                self.fields, id_factory=self.context.runtime.id_factory
            )
        except DiagnosticFieldError:
            raise
        except (RedactionError, ValueError, TypeError, RecursionError):
            safe_fields, truncated = {}, False
            redacted = False
            error = ErrorCode.REDACTION_FAILURE
            level = LogLevel.ERROR
            message = _ERROR_MESSAGES[error]
        object.__setattr__(self, "fields", MappingProxyType(dict(safe_fields)))
        object.__setattr__(self, "error_code", error)
        object.__setattr__(self, "level", level)
        object.__setattr__(self, "message", message)
        payload: dict[str, object] = {
            "schema_version": 1,
            "timestamp_utc_ns": self.timestamp_utc_ns,
            "level": level.value,
            "message": message,
            "context": safe_context,
            "fields": safe_fields,
            "error_code": error.value if error is not None else None,
            "truncated": truncated,
            "redacted": redacted,
        }
        encoded = _encode(payload)
        if len(encoded.encode("utf-8")) > MAX_LINE_BYTES:
            payload["fields"] = {}
            payload["truncated"] = True
            encoded = _encode(payload)
            truncated = True
            object.__setattr__(self, "fields", MappingProxyType({}))
        if len(encoded.encode("utf-8")) > MAX_LINE_BYTES:
            raise ValueError("diagnostic envelope exceeds line limit")
        object.__setattr__(self, "truncated", truncated)
        object.__setattr__(self, "redacted", redacted)
        object.__setattr__(self, "_json", encoded)

    @classmethod
    def create(
        cls,
        *,
        utc_ns_clock: Callable[[], int],
        level: LogLevel,
        message: str,
        context: ObservationContextV1,
        fields: Mapping[str, object] | None = None,
        error_code: ErrorCode | str | None = None,
    ) -> StructuredLogV1:
        """Take wall time only from the supplied UTC-nanosecond clock."""
        result = object.__new__(cls)
        object.__setattr__(result, "timestamp_utc_ns", utc_ns_clock())
        object.__setattr__(result, "level", level)
        object.__setattr__(result, "message", message)
        object.__setattr__(result, "context", context)
        object.__setattr__(result, "fields", fields if fields is not None else {})
        object.__setattr__(result, "error_code", error_code)
        result.__post_init__()
        return result

    def to_json(self) -> str:
        """Return a prebuilt UTF-8-safe JSON line (without a newline)."""
        return self._json

    def __copy__(self) -> StructuredLogV1:
        raise TypeError("diagnostic record cannot be copied")

    def __deepcopy__(self, memo: dict[int, object]) -> StructuredLogV1:
        raise TypeError("diagnostic record cannot be copied")

    def __reduce__(self) -> Never:
        raise TypeError("diagnostic record cannot be pickled")

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        raise TypeError("diagnostic record cannot be pickled")


@dataclass(frozen=True, slots=True)
class LatencySampleV1:
    stage: str
    duration_ns: int
    timestamp_utc_ns: int
    context: ObservationContextV1

    def __post_init__(self) -> None:
        if not isinstance(self.stage, str) or self.stage not in _STAGES:
            raise ValueError("invalid latency stage")
        if self.duration_ns < 0 or self.timestamp_utc_ns < 0:
            raise ValueError("invalid latency clock")


@dataclass(frozen=True, slots=True)
class LatencyTimerV1:
    """Measure elapsed time without consulting the wall clock for duration."""

    stage: str
    context: ObservationContextV1
    monotonic_ns_clock: Callable[[], int] = field(repr=False)
    utc_ns_clock: Callable[[], int] = field(repr=False)
    started_monotonic_ns: int

    @classmethod
    def start(
        cls,
        *,
        stage: str,
        context: ObservationContextV1,
        monotonic_ns_clock: Callable[[], int],
        utc_ns_clock: Callable[[], int],
    ) -> LatencyTimerV1:
        if not isinstance(stage, str) or stage not in _STAGES:
            raise ValueError("invalid latency stage")
        return cls(stage, context, monotonic_ns_clock, utc_ns_clock, monotonic_ns_clock())

    def stop(self) -> LatencySampleV1:
        end = self.monotonic_ns_clock()
        if end < self.started_monotonic_ns:
            raise ValueError("monotonic clock moved backwards")
        return LatencySampleV1(
            stage=self.stage,
            duration_ns=end - self.started_monotonic_ns,
            timestamp_utc_ns=self.utc_ns_clock(),
            context=self.context,
        )
