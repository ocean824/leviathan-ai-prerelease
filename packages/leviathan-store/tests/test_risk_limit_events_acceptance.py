"""Independent migration and durable-audit acceptance tests; SQLite is disposable."""

from __future__ import annotations

from pathlib import Path

import pytest
from leviathan_store.migrations.risk_limits_v1 import (
    MigrationWriterCollisionError,
    migrate_risk_limits_v1,
)
from sqlalchemy import Column, Integer, MetaData, String, Table, inspect, select
from sqlalchemy.ext.asyncio import create_async_engine

NOW_NS = 1_800_000_000_000_000_000
EXPECTED_RISK_TABLES = {
    "risk_policy_state",
    "risk_audit_events",
    "risk_audit_head",
    "risk_soft_approval_claims",
    "risk_soft_approvals",
    "risk_limit_migration_versions",
}


class _WriterGuard:
    def __init__(self, acquired: bool) -> None:
        self.acquired = acquired
        self.calls: list[tuple[str, str]] = []

    async def acquire(self, writer_name: str) -> bool:
        self.calls.append(("acquire", writer_name))
        return self.acquired

    async def release(self, writer_name: str) -> None:
        self.calls.append(("release", writer_name))


async def _table_names(engine: object) -> set[str]:
    async with engine.connect() as connection:
        return await connection.run_sync(lambda conn: set(inspect(conn).get_table_names()))


@pytest.mark.asyncio
async def test_exclusive_writer_collision_refuses_before_any_schema_write() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    guard = _WriterGuard(acquired=False)
    try:
        with pytest.raises(MigrationWriterCollisionError) as collision:
            await migrate_risk_limits_v1(engine, writer_guard=guard, applied_at_ns=NOW_NS)
        assert str(collision.value) == "exclusive product database writer slot unavailable"
        assert guard.calls == [("acquire", "risk_limits_v1")]
        assert await _table_names(engine) == set()
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_migration_is_additive_and_leaves_existing_oms_table_unchanged(
    tmp_path: Path,
) -> None:
    database = tmp_path / "risk005-migration.sqlite"
    engine = create_async_engine(f"sqlite+aiosqlite:///{database}")
    metadata = MetaData()
    sentinel = Table(
        "oms_orders",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("sentinel", String(32), nullable=False),
    )
    try:
        async with engine.begin() as connection:
            await connection.run_sync(metadata.create_all)
            await connection.execute(sentinel.insert().values(id=7, sentinel="untouched"))
        guard = _WriterGuard(acquired=True)
        await migrate_risk_limits_v1(engine, writer_guard=guard, applied_at_ns=NOW_NS)
        await migrate_risk_limits_v1(engine, writer_guard=guard, applied_at_ns=NOW_NS + 1)

        names = await _table_names(engine)
        assert names >= EXPECTED_RISK_TABLES
        assert "oms_orders" in names
        assert not {name for name in names if name.startswith("oms_")} - {"oms_orders"}
        assert not {name for name in names if name.startswith("orders")}
        assert guard.calls == [
            ("acquire", "risk_limits_v1"),
            ("release", "risk_limits_v1"),
            ("acquire", "risk_limits_v1"),
            ("release", "risk_limits_v1"),
        ]

        async with engine.connect() as connection:
            result = await connection.execute(select(sentinel.c.id, sentinel.c.sentinel))
            assert result.all() == [(7, "untouched")]
            oms_columns = await connection.run_sync(
                lambda conn: [column["name"] for column in inspect(conn).get_columns("oms_orders")]
            )
            assert oms_columns == ["id", "sentinel"]
            versions = await connection.exec_driver_sql(
                "SELECT version, name, applied_at_ns FROM risk_limit_migration_versions"
            )
            assert versions.all() == [(1, "risk_limits_v1", NOW_NS)]
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_migration_uses_only_risk_prefixed_tables_on_a_blank_product_database() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    guard = _WriterGuard(acquired=True)
    try:
        await migrate_risk_limits_v1(engine, writer_guard=guard, applied_at_ns=NOW_NS)
        names = await _table_names(engine)
        assert names == EXPECTED_RISK_TABLES
        assert all(name.startswith("risk_") for name in names)
    finally:
        await engine.dispose()
