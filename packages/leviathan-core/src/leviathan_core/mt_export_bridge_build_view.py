"""Pure, content-safe projection of synthetic MT4/MT5 build events."""

from __future__ import annotations

from collections.abc import Iterable
from enum import StrEnum
from typing import Literal

from pydantic import Field, model_validator

from leviathan_core.seal import Issuer, SealedModel

BUILD_VIEW_SEAL_TAG = "mtbr_build_vm001_view_v1"
_BUILD_VIEW_ISSUER = Issuer(BUILD_VIEW_SEAL_TAG)
_REDACTED_MESSAGE: Literal["[REDACTED]"] = "[REDACTED]"
_PROJECTION_FAILURE_TOKEN = object()


class _ProjectionFailureError(Exception):
    """Private control-flow signal for failures detected by this projection."""

    __slots__ = ("code", "token")

    def __init__(self, token: object, code: str) -> None:
        self.token = token
        self.code = code


class BuildStatusV1(StrEnum):
    IDLE = "Idle"
    GENERATING = "Generating"
    COMPILING = "Compiling"
    PACKAGING = "Packaging"
    READY = "Ready"
    FAILED = "Failed"


class BuildSeverityV1(StrEnum):
    INFO = "Info"
    WARNING = "Warning"
    ERROR = "Error"


class BuildViewError(ValueError):
    """Content-free projection failure with a stable reason code."""

    __slots__ = ("code",)

    _CODES = frozenset({"INVALID_EVENTS", "INVALID_TRANSITION"})

    def __init__(self, code: str) -> None:
        if type(code) is not str or code not in self._CODES:
            code = "INVALID_EVENTS"
        self.code = code
        super().__init__(code)


class BuildEventV1(SealedModel):
    """One untrusted synthetic status/log event supplied to the projection."""

    status: BuildStatusV1
    severity: BuildSeverityV1
    source_line: int | None = Field(default=None, ge=1, le=2**31 - 1)
    message: str = Field(max_length=4096)


class BuildLogEntryV1(SealedModel):
    """Safe log metadata; source text is never carried into a view."""

    severity: BuildSeverityV1
    source_line: int | None
    message: Literal["[REDACTED]"] = _REDACTED_MESSAGE


class BuildViewV1(SealedModel):
    """Immutable projected state and redacted log metadata."""

    status: BuildStatusV1
    logs: tuple[BuildLogEntryV1, ...]

    @model_validator(mode="after")
    def _validate_log_metadata(self) -> BuildViewV1:
        if any(type(line) is not BuildLogEntryV1 for line in self.logs):
            raise ValueError("INVALID_EVENTS")
        return self

    @property
    def packaging_allowed(self) -> bool:
        return _BUILD_VIEW_ISSUER.issued_here(self) and self.status is BuildStatusV1.READY

    @property
    def deploy_allowed(self) -> bool:
        # Deployment is outside this pure build-view slice.
        return False


_TRANSITIONS: dict[BuildStatusV1, frozenset[BuildStatusV1]] = {
    BuildStatusV1.IDLE: frozenset({BuildStatusV1.GENERATING}),
    BuildStatusV1.GENERATING: frozenset({BuildStatusV1.COMPILING, BuildStatusV1.FAILED}),
    BuildStatusV1.COMPILING: frozenset({BuildStatusV1.PACKAGING, BuildStatusV1.FAILED}),
    BuildStatusV1.PACKAGING: frozenset({BuildStatusV1.READY, BuildStatusV1.FAILED}),
    BuildStatusV1.READY: frozenset(),
    BuildStatusV1.FAILED: frozenset(),
}


def project_build_events(events: Iterable[BuildEventV1]) -> BuildViewV1:
    """Project ordered synthetic events without retaining any raw log content."""

    if isinstance(events, (str, bytes, bytearray)):
        raise BuildViewError("INVALID_EVENTS")

    status = BuildStatusV1.IDLE
    logs: list[BuildLogEntryV1] = []
    error_code: str | None = None
    try:
        for event in events:
            if type(event) is not BuildEventV1:
                raise _ProjectionFailureError(_PROJECTION_FAILURE_TOKEN, "INVALID_EVENTS")
            allowed = _TRANSITIONS[status]
            if event.status not in allowed:
                raise _ProjectionFailureError(_PROJECTION_FAILURE_TOKEN, "INVALID_TRANSITION")
            status = event.status
            logs.append(
                BuildLogEntryV1(
                    severity=event.severity,
                    source_line=event.source_line,
                )
            )
    except _ProjectionFailureError as failure:
        if type(failure) is _ProjectionFailureError and failure.token is _PROJECTION_FAILURE_TOKEN:
            error_code = failure.code
        else:
            error_code = "INVALID_EVENTS"
    except Exception:
        error_code = "INVALID_EVENTS"

    if error_code is not None:
        raise BuildViewError(error_code)

    view: BuildViewV1 | None = None
    try:
        view = BuildViewV1(status=status, logs=tuple(logs))
        issued_view = _BUILD_VIEW_ISSUER.issue(view)
    except Exception:
        issued_view = None
    if issued_view is None:
        raise BuildViewError("INVALID_EVENTS")
    return issued_view


__all__ = [
    "BUILD_VIEW_SEAL_TAG",
    "BuildEventV1",
    "BuildLogEntryV1",
    "BuildSeverityV1",
    "BuildStatusV1",
    "BuildViewError",
    "BuildViewV1",
    "project_build_events",
]
