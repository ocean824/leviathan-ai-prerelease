"""Bounded serial backfill job queue with explicit preflight and status."""

from __future__ import annotations

import asyncio
import threading
from collections import OrderedDict
from contextlib import suppress
from dataclasses import dataclass
from typing import Final, Protocol
from uuid import uuid4

MAX_BACKFILL_JOBS: Final = 16
MAX_RETAINED_BACKFILL_JOBS: Final = 16


class BackfillJobsError(ValueError):
    """Content-free backfill planner error."""

    _CODES = frozenset({"INVALID_REQUEST", "QUEUE_FULL", "NOT_CONFIGURED", "JOB_NOT_FOUND"})

    def __init__(self, code: str) -> None:
        self.code = code if type(code) is str and code in self._CODES else "INVALID_REQUEST"
        super().__init__(self.code)


@dataclass(frozen=True, slots=True)
class BackfillPreview:
    estimated_event_count: int | None


@dataclass(frozen=True, slots=True)
class BackfillJob:
    job_id: str
    status: str
    completed_count: int
    remaining_count: int
    source_state: str
    gap_state: str
    last_event_time_ns: int | None = None
    last_ingest_time_ns: int | None = None


class BackfillExecutor(Protocol):
    def preview(self, request: object) -> BackfillPreview: ...

    async def execute(self, request: object) -> tuple[int, int | None, int | None]: ...


@dataclass(slots=True)
class _MutableJob:
    job_id: str
    request: object
    completed_count: int = 0
    remaining_count: int = 0
    status: str = "QUEUED"
    source_state: str = "AVAILABLE"
    gap_state: str = "UNKNOWN"
    last_event_time_ns: int | None = None
    last_ingest_time_ns: int | None = None

    def snapshot(self) -> BackfillJob:
        return BackfillJob(
            self.job_id,
            self.status,
            self.completed_count,
            self.remaining_count,
            self.source_state,
            self.gap_state,
            self.last_event_time_ns,
            self.last_ingest_time_ns,
        )


class BackfillJobQueue:
    """One async worker, queue cap 16, no implicit retries or hidden cost bypass."""

    def __init__(
        self,
        executor: BackfillExecutor | None,
        *,
        max_jobs: int = MAX_BACKFILL_JOBS,
        max_terminal_jobs: int = MAX_RETAINED_BACKFILL_JOBS,
    ) -> None:
        if (
            type(max_jobs) is not int
            or not 1 <= max_jobs <= MAX_BACKFILL_JOBS
            or type(max_terminal_jobs) is not int
            or not 1 <= max_terminal_jobs <= MAX_RETAINED_BACKFILL_JOBS
        ):
            raise BackfillJobsError("INVALID_REQUEST")
        self._executor = executor
        self._max_jobs = max_jobs
        self._jobs: dict[str, _MutableJob] = {}
        self._terminal_jobs: OrderedDict[str, _MutableJob] = OrderedDict()
        self._max_terminal_jobs = max_terminal_jobs
        self._queue: asyncio.Queue[str] = asyncio.Queue(maxsize=max_jobs)
        self._worker: asyncio.Task[None] | None = None
        self._accepting = True
        self._lock = threading.RLock()

    def start(self) -> None:
        if not self._accepting:
            return
        if self._executor is None:
            return
        if self._worker is None or self._worker.done():
            self._worker = asyncio.create_task(self._run(), name="market-data-backfill")

    def preview(self, request: object) -> BackfillPreview:
        if self._executor is None:
            raise BackfillJobsError("NOT_CONFIGURED")
        try:
            result = self._executor.preview(request)
        except Exception:
            raise BackfillJobsError("NOT_CONFIGURED") from None
        if type(result) is not BackfillPreview or (
            result.estimated_event_count is not None
            and (type(result.estimated_event_count) is not int or result.estimated_event_count < 0)
        ):
            raise BackfillJobsError("NOT_CONFIGURED")
        return result

    def enqueue(self, request: object) -> str:
        if not self._accepting:
            raise BackfillJobsError("QUEUE_FULL")
        if self._executor is None:
            raise BackfillJobsError("NOT_CONFIGURED")
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            raise BackfillJobsError("NOT_CONFIGURED") from None
        with self._lock:
            if len(self._jobs) >= self._max_jobs or self._queue.full():
                raise BackfillJobsError("QUEUE_FULL")
            job_id = uuid4().hex
            job = _MutableJob(job_id, request)
            self._jobs[job_id] = job
            try:
                self._queue.put_nowait(job_id)
            except asyncio.QueueFull:
                self._jobs.pop(job_id, None)
                raise BackfillJobsError("QUEUE_FULL") from None
        if self._worker is None or self._worker.done():
            loop.call_soon(self.start)
        return job_id

    def read(self, job_id: str) -> BackfillJob | None:
        with self._lock:
            job = self._jobs.get(job_id) or self._terminal_jobs.get(job_id)
            return job.snapshot() if job is not None else None

    async def close(self) -> None:
        self._accepting = False
        worker = self._worker
        if worker is not None:
            worker.cancel()
            with suppress(asyncio.CancelledError):
                await worker
        with self._lock:
            for job_id, job in tuple(self._jobs.items()):
                if job.status in {"QUEUED", "RUNNING"}:
                    job.status = "CANCELLED"
                    job.source_state = "UNKNOWN"
                    self._retain_terminal(job_id, job)
            self._jobs.clear()

    async def _run(self) -> None:
        while self._accepting:
            job_id = await self._queue.get()
            try:
                with self._lock:
                    job = self._jobs.get(job_id)
                    if job is None:
                        continue
                    job.status = "RUNNING"
                try:
                    assert self._executor is not None
                    count, last_event, last_ingest = await self._executor.execute(job.request)
                    if type(count) is not int or count < 0:
                        raise ValueError("INVALID_RESULT")
                    with self._lock:
                        job.completed_count = count
                        job.remaining_count = 0
                        job.last_event_time_ns = last_event
                        job.last_ingest_time_ns = last_ingest
                        job.status = "COMPLETED"
                        job.gap_state = "NONE"
                        self._jobs.pop(job_id, None)
                        self._retain_terminal(job_id, job)
                except asyncio.CancelledError:
                    raise
                except Exception:
                    with self._lock:
                        job.status = "FAILED"
                        job.source_state = "UNKNOWN"
                        job.gap_state = "UNKNOWN"
                        self._jobs.pop(job_id, None)
                        self._retain_terminal(job_id, job)
            finally:
                self._queue.task_done()

    def _retain_terminal(self, job_id: str, job: _MutableJob) -> None:
        self._terminal_jobs.pop(job_id, None)
        self._terminal_jobs[job_id] = job
        while len(self._terminal_jobs) > self._max_terminal_jobs:
            self._terminal_jobs.popitem(last=False)


__all__ = ["BackfillJob", "BackfillJobQueue", "BackfillJobsError", "BackfillPreview"]
