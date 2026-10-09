"""Pure legacy ingestion rejection and residual dead-letter decisions."""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Any, Literal, Protocol

from pydantic import field_validator

from leviathan_core.seal import Issuer, SealedModel

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z", re.ASCII)
_ISSUER = Issuer("know_legacy002.dlq.v1")


class LegacyDLQCode(StrEnum):
    INVALID_JOB = "INVALID_JOB"
    INVALID_SINK = "INVALID_SINK"
    SINK_PUBLISH_FAILED = "SINK_PUBLISH_FAILED"
    SCHEDULER_DISABLED = "SCHEDULER_DISABLED"


class LegacyDLQError(ValueError):
    """Content-free failure for invalid legacy queue operations."""

    def __init__(self, code: LegacyDLQCode) -> None:
        self.code = code
        super().__init__(code.value)


class LegacyReasonV1(StrEnum):
    """Only the non-sensitive archived-pipeline reason is queueable here."""

    ARCHIVED_PIPELINE = "ARCHIVED_PIPELINE"


def _id(value: object) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise LegacyDLQError(LegacyDLQCode.INVALID_JOB)
    return value


class LegacyJobV1(SealedModel):
    """Residual queue metadata; message/source bytes are deliberately absent."""

    schema_version: Literal["1"]
    job_id: str
    correlation_id: str
    reason: Literal["ARCHIVED_PIPELINE"]

    def __init__(self, **data: Any) -> None:
        try:
            super().__init__(**data)
        except Exception:
            raise LegacyDLQError(LegacyDLQCode.INVALID_JOB) from None

    @field_validator("job_id", "correlation_id")
    @classmethod
    def _valid_id(cls, value: str) -> str:
        return _id(value)


class DeadLetterV1(SealedModel):
    schema_version: Literal["1"]
    topic: Literal["knowledge.ingest.dlq"]
    job_id: str
    correlation_id: str
    reason: Literal["ARCHIVED_PIPELINE"]


class PublishDispositionV1(StrEnum):
    NACK_LEGACY_ARCHIVED = "NACK_LEGACY_ARCHIVED"


class PublishResultV1(SealedModel):
    schema_version: Literal["1"]
    disposition: Literal[PublishDispositionV1.NACK_LEGACY_ARCHIVED]
    status_code: Literal[410]
    correlation_id: str


class SchedulerDecisionV1(SealedModel):
    schema_version: Literal["1"]
    may_start: Literal[False]
    reason: Literal["LEGACY_ARCHIVED"]


class DeadLetterSinkPort(Protocol):
    def publish(self, message: DeadLetterV1) -> None: ...


def _job(value: object) -> LegacyJobV1:
    if type(value) is not LegacyJobV1:
        raise LegacyDLQError(LegacyDLQCode.INVALID_JOB)
    try:
        return LegacyJobV1(**value.model_dump())
    except Exception:
        raise LegacyDLQError(LegacyDLQCode.INVALID_JOB) from None


def reject_legacy_publish(job: LegacyJobV1) -> PublishResultV1:
    """NACK new legacy publishes as archived; this function writes no queue."""
    safe_job = _job(job)
    return _ISSUER.issue(
        PublishResultV1(
            schema_version="1",
            disposition=PublishDispositionV1.NACK_LEGACY_ARCHIVED,
            status_code=410,
            correlation_id=safe_job.correlation_id,
        )
    )


def dead_letter_residual(job: LegacyJobV1, *, sink: DeadLetterSinkPort) -> DeadLetterV1:
    """Send only preserved identifiers/reason to an explicitly injected sink."""
    safe_job = _job(job)
    publish = getattr(sink, "publish", None)
    if not callable(publish):
        raise LegacyDLQError(LegacyDLQCode.INVALID_SINK)
    message = _ISSUER.issue(
        DeadLetterV1(
            schema_version="1",
            topic="knowledge.ingest.dlq",
            job_id=safe_job.job_id,
            correlation_id=safe_job.correlation_id,
            reason=safe_job.reason,
        )
    )
    try:
        publish(message)
    except Exception:
        raise LegacyDLQError(LegacyDLQCode.SINK_PUBLISH_FAILED) from None
    return message


def scheduler_decision() -> SchedulerDecisionV1:
    """Schedulers cannot be started or restarted for the archived pipeline."""
    return _ISSUER.issue(
        SchedulerDecisionV1(schema_version="1", may_start=False, reason="LEGACY_ARCHIVED")
    )


def start_scheduler() -> None:
    raise LegacyDLQError(LegacyDLQCode.SCHEDULER_DISABLED)
