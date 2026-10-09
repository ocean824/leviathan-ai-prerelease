"""Closed-value, read-only live log surface for operator-visible agent events.

The event boundary accepts only OBS-001 context and code-defined enums. It has
no field for prompts, reasoning, tool arguments, or tool results.
"""

from __future__ import annotations

import asyncio
import json
from collections import deque
from collections.abc import AsyncIterator
from dataclasses import dataclass
from enum import StrEnum
from typing import Final, cast

from leviathan_core.observability.context import ObservationContextV1
from leviathan_core.observability.models import ErrorCode, LogLevel, StructuredLogV1
from leviathan_core.observability.redaction import MAX_LINE_BYTES
from leviathan_core.seal import Issuer, SealedModel, SealError, require
from leviathan_core.security.principal_verifier import VerifiedPrincipalV1

_PRINCIPAL_TAG: Final = "sec003.verified_principal.v1"
_EVENT_TAG: Final = "observability.live_log_event.v1"
_EVENT_ISSUER: Final = Issuer(_EVENT_TAG)
_EVENT_CONSTRUCTION_MARKER: Final = object()
_MAX_READ_LIMIT: Final = 1000
_MAX_UTC_NS: Final = (1 << 63) - 1
_MAX_DURATION_NS: Final = 10**18
_MAX_ORGS: Final = 100_000


class LiveLogErrorCodeV1(StrEnum):
    PRINCIPAL_INVALID = "LIVE_LOG_PRINCIPAL_INVALID"
    APPEND_FORBIDDEN = "LIVE_LOG_APPEND_FORBIDDEN"
    READ_FORBIDDEN = "LIVE_LOG_READ_FORBIDDEN"
    EVENT_INVALID = "LIVE_LOG_EVENT_INVALID"
    LIMIT_INVALID = "LIVE_LOG_LIMIT_INVALID"
    BUFFER_INVALID = "LIVE_LOG_BUFFER_INVALID"
    CAPACITY_EXCEEDED = "LIVE_LOG_CAPACITY_EXCEEDED"
    REDACTION_FAILURE = "LIVE_LOG_REDACTION_FAILURE"


class LiveLogError(ValueError):
    """Content-free live-log failure carrying one fixed error code."""

    def __init__(self, code: LiveLogErrorCodeV1) -> None:
        self.code = code
        super().__init__(code.value)


class LiveLogToolNameV1(StrEnum):
    FILE_READ = "FILE_READ"
    FILE_WRITE = "FILE_WRITE"
    SEARCH = "SEARCH"
    TERMINAL = "TERMINAL"
    BROWSER = "BROWSER"
    MCP = "MCP"
    OTHER = "OTHER"


class LiveLogToolCategoryV1(StrEnum):
    RESEARCH = "RESEARCH"
    DATA = "DATA"
    EXECUTION = "EXECUTION"
    RISK = "RISK"
    SYSTEM = "SYSTEM"
    OTHER = "OTHER"


class LiveLogResultCodeV1(StrEnum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    DENIED = "DENIED"
    TIMEOUT = "TIMEOUT"
    UNKNOWN = "UNKNOWN"
    REDACTION_FAILURE = "REDACTION_FAILURE"


class LiveLogSummaryCodeV1(StrEnum):
    TASK_STARTED = "TASK_STARTED"
    TOOL_STARTED = "TOOL_STARTED"
    TOOL_COMPLETED = "TOOL_COMPLETED"
    TOOL_FAILED = "TOOL_FAILED"
    DECISION_READY = "DECISION_READY"
    DECISION_BLOCKED = "DECISION_BLOCKED"
    DETAIL_UNAVAILABLE = "DETAIL_UNAVAILABLE"


_SUMMARY_MESSAGES: Final[dict[LiveLogSummaryCodeV1, str]] = {
    LiveLogSummaryCodeV1.TASK_STARTED: "Operation started.",
    LiveLogSummaryCodeV1.TOOL_STARTED: "Operation started.",
    LiveLogSummaryCodeV1.TOOL_COMPLETED: "Operation completed.",
    LiveLogSummaryCodeV1.TOOL_FAILED: "Operation failed.",
    LiveLogSummaryCodeV1.DECISION_READY: "Observation recorded.",
    LiveLogSummaryCodeV1.DECISION_BLOCKED: "Operation failed.",
    LiveLogSummaryCodeV1.DETAIL_UNAVAILABLE: "Observation recorded.",
}


class LiveLogEventV1(SealedModel):
    """Immutable sanitized event. Construction is restricted to ``create``."""

    event_id: str
    started_utc_ns: int
    ended_utc_ns: int
    duration_ns: int
    service: str
    component: str
    correlation_id: str
    tool_name: LiveLogToolNameV1
    tool_category: LiveLogToolCategoryV1
    result_code: LiveLogResultCodeV1
    summary_code: LiveLogSummaryCodeV1
    message: str
    level: LogLevel
    redacted: bool
    truncated: bool
    error_code: ErrorCode | None
    serialized_line: str

    def __init__(self, *, _construction_marker: object | None = None, **data: object) -> None:
        if _construction_marker is not _EVENT_CONSTRUCTION_MARKER:
            raise LiveLogError(LiveLogErrorCodeV1.EVENT_INVALID)
        super().__init__(**data)

    @classmethod
    def create(
        cls,
        *,
        context: ObservationContextV1,
        started_utc_ns: int,
        ended_utc_ns: int,
        tool_name: LiveLogToolNameV1,
        tool_category: LiveLogToolCategoryV1,
        result_code: LiveLogResultCodeV1,
        summary_code: LiveLogSummaryCodeV1 | None = None,
    ) -> LiveLogEventV1:
        if type(context) is not ObservationContextV1:
            raise LiveLogError(LiveLogErrorCodeV1.EVENT_INVALID)
        if (
            type(started_utc_ns) is not int
            or type(ended_utc_ns) is not int
            or not 0 <= started_utc_ns <= ended_utc_ns <= _MAX_UTC_NS
            or ended_utc_ns - started_utc_ns > _MAX_DURATION_NS
        ):
            raise LiveLogError(LiveLogErrorCodeV1.EVENT_INVALID)
        if (
            type(tool_name) is not LiveLogToolNameV1
            or type(tool_category) is not LiveLogToolCategoryV1
            or type(result_code) is not LiveLogResultCodeV1
        ):
            raise LiveLogError(LiveLogErrorCodeV1.EVENT_INVALID)

        summary_is_permitted = type(summary_code) is LiveLogSummaryCodeV1
        safe_summary = (
            cast(LiveLogSummaryCodeV1, summary_code)
            if summary_is_permitted
            else LiveLogSummaryCodeV1.DETAIL_UNAVAILABLE
        )
        duration_ns = ended_utc_ns - started_utc_ns
        event_token = context.runtime.id_factory.mint_event_id()
        status = {
            LiveLogResultCodeV1.SUCCESS: "COMPLETED",
            LiveLogResultCodeV1.FAILURE: "FAILED",
            LiveLogResultCodeV1.DENIED: "FAILED",
            LiveLogResultCodeV1.TIMEOUT: "FAILED",
            LiveLogResultCodeV1.UNKNOWN: "PENDING",
            LiveLogResultCodeV1.REDACTION_FAILURE: "FAILED",
        }[result_code]
        error = {
            LiveLogResultCodeV1.FAILURE: ErrorCode.INTERNAL_ERROR,
            LiveLogResultCodeV1.DENIED: ErrorCode.INVALID_INPUT,
            LiveLogResultCodeV1.TIMEOUT: ErrorCode.UNKNOWN,
            LiveLogResultCodeV1.REDACTION_FAILURE: ErrorCode.REDACTION_FAILURE,
        }.get(result_code)
        level = (
            LogLevel.ERROR
            if result_code
            in {
                LiveLogResultCodeV1.FAILURE,
                LiveLogResultCodeV1.DENIED,
                LiveLogResultCodeV1.TIMEOUT,
                LiveLogResultCodeV1.REDACTION_FAILURE,
            }
            else LogLevel.INFO
        )

        observation = StructuredLogV1.create(
            utc_ns_clock=lambda: ended_utc_ns,
            level=level,
            message=_SUMMARY_MESSAGES[safe_summary],
            context=context,
            fields={
                "event_id": event_token,
                "duration_ns": duration_ns,
                "status": status,
            },
            error_code=error,
        )
        observation_payload = json.loads(observation.to_json())
        redaction_failed = observation.error_code is ErrorCode.REDACTION_FAILURE
        if redaction_failed:
            safe_summary = LiveLogSummaryCodeV1.DETAIL_UNAVAILABLE
        safe_result = (
            LiveLogResultCodeV1.REDACTION_FAILURE if redaction_failed else result_code
        )
        safe_message = (
            "Observation redaction failed."
            if redaction_failed
            else observation.message
        )
        safe_level = LogLevel.ERROR if redaction_failed else observation.level
        observed_error = observation.error_code
        safe_error = (
            ErrorCode.REDACTION_FAILURE
            if redaction_failed
            else observed_error
            if isinstance(observed_error, ErrorCode)
            else ErrorCode.UNKNOWN
            if observed_error is not None
            else None
        )
        redacted = observation.redacted or (
            summary_code is not None and not summary_is_permitted
        )
        payload: dict[str, object] = {
            "schema_version": 1,
            "event_id": event_token.value,
            "started_utc_ns": started_utc_ns,
            "ended_utc_ns": ended_utc_ns,
            "duration_ns": duration_ns,
            "agent_identity": {
                "service": context.service,
                "component": context.component,
            },
            "correlation_id": str(context.correlation_id),
            "tool_name": tool_name.value,
            "tool_category": tool_category.value,
            "result_code": safe_result.value,
            "summary_code": safe_summary.value,
            "message": safe_message,
            "level": safe_level.value,
            "context": observation_payload["context"],
            "fields": observation_payload["fields"],
            "redacted": redacted,
            "truncated": observation.truncated,
            "error_code": safe_error.value if safe_error is not None else None,
        }
        serialized = json.dumps(
            payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False
        )
        truncated = observation.truncated
        if len(serialized.encode("utf-8")) > MAX_LINE_BYTES:
            payload.update(
                {
                    "agent_identity": {},
                    "context": {},
                    "fields": {"event_id": event_token.value},
                    "summary_code": LiveLogSummaryCodeV1.DETAIL_UNAVAILABLE.value,
                    "message": "Observation redaction failed.",
                    "level": LogLevel.ERROR.value,
                    "redacted": True,
                    "truncated": True,
                    "error_code": ErrorCode.REDACTION_FAILURE.value,
                }
            )
            serialized = json.dumps(
                payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False
            )
            redacted = True
            truncated = True
            safe_summary = LiveLogSummaryCodeV1.DETAIL_UNAVAILABLE
            safe_result = LiveLogResultCodeV1.REDACTION_FAILURE
            safe_message = "Observation redaction failed."
            safe_level = LogLevel.ERROR
            safe_error = ErrorCode.REDACTION_FAILURE
        if len(serialized.encode("utf-8")) > MAX_LINE_BYTES:
            raise LiveLogError(LiveLogErrorCodeV1.REDACTION_FAILURE)

        event = cls(
            _construction_marker=_EVENT_CONSTRUCTION_MARKER,
            event_id=event_token.value,
            started_utc_ns=started_utc_ns,
            ended_utc_ns=ended_utc_ns,
            duration_ns=duration_ns,
            service=context.service,
            component=context.component,
            correlation_id=str(context.correlation_id),
            tool_name=tool_name,
            tool_category=tool_category,
            result_code=safe_result,
            summary_code=safe_summary,
            message=safe_message,
            level=safe_level,
            redacted=redacted,
            truncated=truncated,
            error_code=safe_error,
            serialized_line=serialized,
        )
        return _EVENT_ISSUER.issue(event)

    def to_json(self) -> str:
        """Return the prebuilt safe line, without a trailing newline."""
        require(self, _EVENT_TAG)
        return self.serialized_line


@dataclass(frozen=True, slots=True)
class LiveLogEntryV1:
    """One ordered read result; the tenant partition is never included."""

    sequence: int
    gap_before: bool
    event: LiveLogEventV1


class LiveLogBufferV1:
    """Bounded in-memory writer. Readers receive a separate read-only view."""

    def __init__(self, max_entries: int = 1024, *, max_orgs: int) -> None:
        if type(max_entries) is not int or not 1 <= max_entries <= 100_000:
            raise LiveLogError(LiveLogErrorCodeV1.BUFFER_INVALID)
        if type(max_orgs) is not int or not 1 <= max_orgs <= _MAX_ORGS:
            raise LiveLogError(LiveLogErrorCodeV1.BUFFER_INVALID)
        self._max_entries = max_entries
        self._max_orgs = max_orgs
        self._entries: deque[tuple[str, int, LiveLogEventV1]] = deque(maxlen=max_entries)
        # Counters intentionally outlive retained entries: evicting or resetting
        # one would allow a returning organization to reuse a stream sequence.
        self._sequences: dict[str, int] = {}
        self._condition = asyncio.Condition()

    def view(self) -> LiveLogViewV1:
        """Return an object with read methods only."""
        return LiveLogViewV1(self)

    async def append(self, principal: VerifiedPrincipalV1, event: LiveLogEventV1) -> int:
        """Append one validated event under the verified principal's org scope."""
        organization_id = _verified_org(principal)
        if "logs.append" not in principal.scopes:
            raise LiveLogError(LiveLogErrorCodeV1.APPEND_FORBIDDEN)
        if type(event) is not LiveLogEventV1:
            raise LiveLogError(LiveLogErrorCodeV1.EVENT_INVALID)
        try:
            require(event, _EVENT_TAG)
        except SealError:
            raise LiveLogError(LiveLogErrorCodeV1.EVENT_INVALID) from None
        async with self._condition:
            current_sequence = self._sequences.get(organization_id)
            if current_sequence is None:
                if len(self._sequences) >= self._max_orgs:
                    raise LiveLogError(LiveLogErrorCodeV1.CAPACITY_EXCEEDED)
                sequence = 1
            else:
                sequence = current_sequence + 1
            self._sequences[organization_id] = sequence
            self._entries.append((organization_id, sequence, event))
            self._condition.notify_all()
        return sequence

    async def _read_org(
        self, organization_id: str, *, after_sequence: int, limit: int
    ) -> tuple[LiveLogEntryV1, ...]:
        async with self._condition:
            matches = [
                (sequence, event)
                for org, sequence, event in self._entries
                if org == organization_id and sequence > after_sequence
            ][:limit]
        previous = after_sequence
        result: list[LiveLogEntryV1] = []
        for sequence, event in matches:
            result.append(LiveLogEntryV1(sequence, sequence > previous + 1, event))
            previous = sequence
        return tuple(result)

    async def read_live(
        self,
        principal: VerifiedPrincipalV1,
        *,
        after_sequence: int = 0,
        limit: int = 100,
    ) -> tuple[LiveLogEntryV1, ...]:
        organization_id = _readable_org(principal)
        if (
            type(after_sequence) is not int
            or after_sequence < 0
            or type(limit) is not int
            or not 1 <= limit <= _MAX_READ_LIMIT
        ):
            raise LiveLogError(LiveLogErrorCodeV1.LIMIT_INVALID)
        return await self._read_org(
            organization_id, after_sequence=after_sequence, limit=limit
        )

    async def wait_for_change(
        self, principal: VerifiedPrincipalV1, *, after_sequence: int
    ) -> None:
        organization_id = _readable_org(principal)
        if type(after_sequence) is not int or after_sequence < 0:
            raise LiveLogError(LiveLogErrorCodeV1.LIMIT_INVALID)
        await self._wait_for_org_change(organization_id, after_sequence)

    async def _wait_for_org_change(self, organization_id: str, after_sequence: int) -> None:
        async with self._condition:
            while not any(
                org == organization_id and sequence > after_sequence
                for org, sequence, _event in self._entries
            ):
                await self._condition.wait()


class LiveLogViewV1:
    """Read-only live access. It exposes no append, pause, export or route API."""

    def __init__(self, buffer: LiveLogBufferV1) -> None:
        self._buffer = buffer

    async def read_live(
        self,
        principal: VerifiedPrincipalV1,
        *,
        after_sequence: int = 0,
        limit: int = 100,
    ) -> tuple[LiveLogEntryV1, ...]:
        return await self._buffer.read_live(
            principal,
            after_sequence=after_sequence,
            limit=limit,
        )

    async def stream_live(
        self,
        principal: VerifiedPrincipalV1,
        *,
        after_sequence: int = 0,
    ) -> AsyncIterator[LiveLogEntryV1]:
        _readable_org(principal)
        if type(after_sequence) is not int or after_sequence < 0:
            raise LiveLogError(LiveLogErrorCodeV1.LIMIT_INVALID)
        cursor = after_sequence
        while True:
            entries = await self._buffer.read_live(
                principal, after_sequence=cursor, limit=_MAX_READ_LIMIT
            )
            if entries:
                for entry in entries:
                    cursor = entry.sequence
                    yield entry
                continue
            await self._buffer.wait_for_change(principal, after_sequence=cursor)


def _verified_org(principal: VerifiedPrincipalV1) -> str:
    if type(principal) is not VerifiedPrincipalV1:
        raise LiveLogError(LiveLogErrorCodeV1.PRINCIPAL_INVALID)
    try:
        require(principal, _PRINCIPAL_TAG)
    except SealError:
        raise LiveLogError(LiveLogErrorCodeV1.PRINCIPAL_INVALID) from None
    return principal.org_id


def _readable_org(principal: VerifiedPrincipalV1) -> str:
    organization_id = _verified_org(principal)
    if (
        "logs.read" not in principal.scopes
        or principal.role.casefold() not in {"operator", "devops"}
    ):
        raise LiveLogError(LiveLogErrorCodeV1.READ_FORBIDDEN)
    return organization_id
