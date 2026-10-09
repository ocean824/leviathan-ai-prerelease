"""Async engine and session wiring for LEVIATHAN persistence.

Everything downstream takes an :class:`~sqlalchemy.ext.asyncio.AsyncSession`,
so the only job here is to build the async engine, hand back a
sessionmaker bound to it, and (in dev/test) stamp the schema onto a fresh
database.

Schema management is intentionally minimal today: :func:`init_schema`
runs ``metadata.create_all`` against the current engine, which is all
SQLite/aiosqlite needs. Alembic migrations are *deferred* until
PostgreSQL/TimescaleDB arrives with Docker — at that point create_all is
retired in favour of versioned migrations. Until then, use only
dialect-portable column types so this schema stands up unchanged on both
engines.
"""

from datetime import UTC, datetime
from typing import cast

from sqlalchemy import Table, insert, inspect, select, text
from sqlalchemy import create_engine as create_sync_engine
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import Session, sessionmaker

from leviathan_store.tables import (
    McpAuditHeadRow,
    McpAuditRow,
    OmsEventRow,
    OmsFillCorrectionRow,
    OmsFillRow,
    OmsLedgerHeadRow,
    OmsObservationRow,
    OmsOrderRow,
    RouteAttemptRow,
    SchemaMigrationRow,
    StoreBase,
)


def create_engine_and_sessionmaker(
    database_url: str,
) -> tuple[AsyncEngine, async_sessionmaker[AsyncSession]]:
    """Build an async engine and a sessionmaker bound to it.

    ``database_url`` is a SQLAlchemy async URL, e.g.
    ``sqlite+aiosqlite:///:memory:`` for tests or
    ``sqlite+aiosqlite:///leviathan.db`` for local dev. Postgres arrives
    as ``postgresql+asyncpg://...`` once Docker is installed.
    """
    engine = create_async_engine(database_url)
    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
    return engine, sessionmaker


def create_sync_engine_and_sessionmaker(
    database_url: str,
) -> tuple[Engine, sessionmaker[Session]]:
    """Build synchronous sessions for adapters whose port is synchronous.

    Use a synchronous SQLAlchemy URL (for example ``sqlite:///leviathan.db``).
    This connects to the same durable SQLite database as the async engine when
    both URLs name the same file.
    """
    engine = create_sync_engine(database_url)
    sessions = sessionmaker(engine, expire_on_commit=False)
    return engine, sessions


def init_sync_schema(engine: Engine) -> None:
    """Create registered tables for a synchronous engine without migrations."""
    cast(Table, McpAuditHeadRow.__table__).create(engine, checkfirst=True)
    cast(Table, McpAuditRow.__table__).create(engine, checkfirst=True)
    StoreBase.metadata.create_all(engine)


async def init_schema(engine: AsyncEngine) -> None:
    """Create every table on ``engine`` if it does not already exist.

    Dev/test convenience only — ``metadata.create_all`` never alters an
    existing table. Alembic migrations replace this the moment Postgres
    lands; see the module docstring.
    """
    async with engine.begin() as conn:
        # C-101 v1 is an invoked additive migration, including populated DBs.
        await conn.run_sync(cast(Table, RouteAttemptRow.__table__).create, checkfirst=True)
        await conn.run_sync(cast(Table, SchemaMigrationRow.__table__).create, checkfirst=True)
        columns, primary_key = await conn.run_sync(
            lambda sync_conn: (
                {col["name"] for col in inspect(sync_conn).get_columns("route_attempts")},
                inspect(sync_conn).get_pk_constraint("route_attempts")["constrained_columns"],
            )
        )
        required = {column.name for column in RouteAttemptRow.__table__.columns}
        if not required.issubset(columns) or primary_key != ["decision_id"]:
            raise RuntimeError("route_attempts v1 schema verification failed")
        migration = await conn.scalar(
            select(SchemaMigrationRow.version).where(SchemaMigrationRow.version == 1)
        )
        if migration is None:
            await conn.execute(
                insert(SchemaMigrationRow).values(
                    version=1, name="c101_route_attempts_v1", applied_at=datetime.now(UTC)
                )
            )
        # OMS v2 adds four new tables. Existing route_attempts rows and v1
        # migration evidence are left untouched, including populated databases.
        for row_type in (
            OmsOrderRow,
            OmsEventRow,
            OmsFillRow,
            OmsObservationRow,
            OmsFillCorrectionRow,
        ):
            await conn.run_sync(cast(Table, row_type.__table__).create, checkfirst=True)
        oms_required = {
            "oms_orders": {column.name for column in OmsOrderRow.__table__.columns} - {"chain"},
            "oms_order_events": {column.name for column in OmsEventRow.__table__.columns}
            - {"chain", "ledger_sequence"},
            "oms_fills": {column.name for column in OmsFillRow.__table__.columns}
            - {"chain", "ledger_sequence"},
            "oms_observations": {column.name for column in OmsObservationRow.__table__.columns}
            - {"chain", "ledger_sequence"},
            "oms_fill_corrections": {
                column.name for column in OmsFillCorrectionRow.__table__.columns
            } - {"chain", "ledger_sequence"},
        }
        oms_columns = await conn.run_sync(
            lambda sync_conn: {
                table: {column["name"] for column in inspect(sync_conn).get_columns(table)}
                for table in oms_required
            }
        )
        if any(
            not required.issubset(oms_columns[table]) for table, required in oms_required.items()
        ):
            raise RuntimeError("OMS v2 schema verification failed")
        oms_migration = await conn.scalar(
            select(SchemaMigrationRow.version).where(SchemaMigrationRow.version == 2)
        )
        if oms_migration is None:
            await conn.execute(
                insert(SchemaMigrationRow).values(
                    version=2, name="oms_order_ledger_v1", applied_at=datetime.now(UTC)
                )
            )
        # ADR-0004 v3 is additive. Unchained legacy rows remain present but
        # cannot pass OrderLedger's authenticated read boundary.
        for table, additions in {
            "oms_orders": ("chain",),
            "oms_order_events": ("ledger_sequence", "chain"),
            "oms_fills": ("ledger_sequence", "chain"),
            "oms_observations": ("ledger_sequence", "chain"),
            "oms_fill_corrections": ("ledger_sequence", "chain"),
        }.items():
            def existing_columns(sync_conn: Connection, table: str = table) -> set[str]:
                return {
                    column["name"] for column in inspect(sync_conn).get_columns(table)
                }

            present = await conn.run_sync(existing_columns)
            for column in additions:
                if column not in present:
                    sql_type = "INTEGER" if column == "ledger_sequence" else "VARCHAR"
                    await conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {sql_type}"))
        await conn.run_sync(cast(Table, OmsLedgerHeadRow.__table__).create, checkfirst=True)
        integrity_migration = await conn.scalar(
            select(SchemaMigrationRow.version).where(SchemaMigrationRow.version == 3)
        )
        if integrity_migration is None:
            await conn.execute(
                insert(SchemaMigrationRow).values(
                    version=3, name="oms_integrity_chain_v1", applied_at=datetime.now(UTC)
                )
            )
        # ADR-0006 keeps a signed account guard in the existing OMS head.
        head_columns = await conn.run_sync(
            lambda sync_conn: {
                column["name"]
                for column in inspect(sync_conn).get_columns("oms_ledger_heads")
            }
        )
        for column in (
            "guard_order_id", "guard_action", "guard_client_order_id",
            "guard_attempt", "guard_revision",
        ):
            if column not in head_columns:
                sql_type = "INTEGER" if column in {"guard_attempt", "guard_revision"} else "VARCHAR"
                await conn.execute(
                    text(f"ALTER TABLE oms_ledger_heads ADD COLUMN {column} {sql_type}")
                )
        guard_migration = await conn.scalar(
            select(SchemaMigrationRow.version).where(SchemaMigrationRow.version == 4)
        )
        if guard_migration is None:
            await conn.execute(
                insert(SchemaMigrationRow).values(
                    version=4, name="oms_dispatch_guard_v1", applied_at=datetime.now(UTC)
                )
            )
        # Amendment 2 adds a signed, monotonic fence for each account guard.
        head_columns = await conn.run_sync(
            lambda sync_conn: {
                column["name"]
                for column in inspect(sync_conn).get_columns("oms_ledger_heads")
            }
        )
        if "fence_epoch" not in head_columns:
            await conn.execute(text("ALTER TABLE oms_ledger_heads ADD COLUMN fence_epoch INTEGER"))
        fence_migration = await conn.scalar(
            select(SchemaMigrationRow.version).where(SchemaMigrationRow.version == 5)
        )
        if fence_migration is None:
            await conn.execute(
                insert(SchemaMigrationRow).values(
                    version=5, name="oms_dispatch_fence_v1", applied_at=datetime.now(UTC)
                )
            )
        await conn.run_sync(cast(Table, McpAuditHeadRow.__table__).create, checkfirst=True)
        await conn.run_sync(cast(Table, McpAuditRow.__table__).create, checkfirst=True)
        await conn.run_sync(StoreBase.metadata.create_all)
