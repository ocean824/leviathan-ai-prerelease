from __future__ import annotations

import asyncio

import pytest

from leviathan_market_data.live.backfill_jobs import (
    BackfillJobQueue,
    BackfillJobsError,
    BackfillPreview,
)


class _FastExecutor:
    def preview(self, _request: object) -> BackfillPreview:
        return BackfillPreview(estimated_event_count=1)

    async def execute(self, _request: object) -> tuple[int, int | None, int | None]:
        return (1, 10, 20)


class _HeldExecutor(_FastExecutor):
    def __init__(self) -> None:
        self.entered = asyncio.Event()
        self.release = asyncio.Event()

    async def execute(self, _request: object) -> tuple[int, int | None, int | None]:
        self.entered.set()
        await self.release.wait()
        return (1, 10, 20)


async def _wait_terminal(queue: BackfillJobQueue, job_id: str) -> str:
    for _ in range(1_000):
        status = queue.read(job_id)
        if status is not None and status.status in {"COMPLETED", "FAILED", "CANCELLED"}:
            return status.status
        await asyncio.sleep(0)
    raise AssertionError("job did not reach a terminal state")


@pytest.mark.asyncio
async def test_sequential_terminal_jobs_do_not_consume_active_capacity() -> None:
    queue = BackfillJobQueue(_FastExecutor(), max_jobs=1, max_terminal_jobs=3)
    queue.start()
    job_ids: list[str] = []
    try:
        for index in range(24):
            job_id = queue.enqueue(index)
            job_ids.append(job_id)
            assert await _wait_terminal(queue, job_id) == "COMPLETED"

        assert len(queue._jobs) == 0
        assert len(queue._terminal_jobs) == 3
        assert queue.read(job_ids[0]) is None
        last_status = queue.read(job_ids[-1])
        assert last_status is not None
        assert last_status.status == "COMPLETED"
    finally:
        await queue.close()


@pytest.mark.asyncio
async def test_active_job_cap_still_rejects_seventeenth_concurrent_job() -> None:
    executor = _HeldExecutor()
    queue = BackfillJobQueue(executor)
    queue.start()
    job_ids = [queue.enqueue(index) for index in range(16)]
    try:
        await asyncio.wait_for(executor.entered.wait(), timeout=1)
        with pytest.raises(BackfillJobsError) as error:
            queue.enqueue("seventeenth")
        assert error.value.code == "QUEUE_FULL"

        executor.release.set()
        for job_id in job_ids:
            assert await _wait_terminal(queue, job_id) == "COMPLETED"
        assert len(queue._jobs) == 0
        assert len(queue._terminal_jobs) == 16
    finally:
        executor.release.set()
        await queue.close()
