"""Shared fixtures — a fresh in-memory SQLite database per test.

``sqlite+aiosqlite:///:memory:`` gives each test its own throwaway
database. The engine is disposed at teardown so no state bleeds between
tests.
"""

from collections.abc import AsyncIterator

import pytest_asyncio
from leviathan_store import create_engine_and_sessionmaker, init_schema
from sqlalchemy.ext.asyncio import AsyncSession


@pytest_asyncio.fixture
async def session() -> AsyncIterator[AsyncSession]:
    engine, sessionmaker = create_engine_and_sessionmaker("sqlite+aiosqlite:///:memory:")
    await init_schema(engine)
    async with sessionmaker() as s:
        yield s
    await engine.dispose()
