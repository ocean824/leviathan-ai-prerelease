"""Database lifecycle for the gateway.

SQLite (aiosqlite) until Docker brings TimescaleDB; the store package is
dialect-portable so the swap is a URL change plus Alembic adoption.
Seeds the demo genome so the terminal has real rows before live feeds.
"""

from pathlib import Path

import leviathan_store.live_activation  # noqa: F401
from leviathan_store.engine import create_engine_and_sessionmaker, init_schema
from leviathan_store.repositories import GenomeRepository
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from leviathan_api.demo import DEMO_GENOME
from leviathan_core.schemas import utcnow


def _ensure_sqlite_dir(database_url: str) -> None:
    prefix = "sqlite+aiosqlite:///"
    if database_url.startswith(prefix):
        db_path = database_url.removeprefix(prefix)
        if db_path != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)


async def build_db(
    database_url: str,
) -> tuple[AsyncEngine, async_sessionmaker[AsyncSession]]:
    _ensure_sqlite_dir(database_url)
    engine, sessionmaker = create_engine_and_sessionmaker(database_url)
    await init_schema(engine)
    await _seed_demo_genome(sessionmaker)
    return engine, sessionmaker


async def _seed_demo_genome(sessionmaker: async_sessionmaker[AsyncSession]) -> None:
    async with sessionmaker() as session:
        repo = GenomeRepository(session)
        if await repo.get(DEMO_GENOME.strategy_id) is None:
            now = utcnow()
            await repo.upsert(DEMO_GENOME, at=now)
            await repo.record_validation(
                DEMO_GENOME.strategy_id,
                stage="backtest_initial",
                passed=True,
                metrics={"sharpe": "1.8", "max_dd_pct": "9.5", "win_rate_pct": "58"},
                at=now,
            )
        await session.commit()
