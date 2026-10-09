"""Replay-verified ledger projections for bounded paper activity reads."""

import asyncio
import sqlite3
import time
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import leviathan_store.oms_ledger as oms_ledger_module
import pytest
from leviathan_store.engine import create_engine_and_sessionmaker, init_schema
from leviathan_store.oms_ledger import OrderLedger
from leviathan_store.tables import OmsOrderRow
from sqlalchemy import event, update

from leviathan_core.execution.order_models import (
    ClientIdKey,
    LedgerIntegrityKey,
    OMSConflict,
    OMSLedgerCorruption,
    OMSValidationError,
    OrderRequest,
)

pytestmark = pytest.mark.asyncio
_CLIENT_KEY = ClientIdKey(b"oms-activity-store-synthetic-client-key")


def _request(*, environment: str = "paper", intent: str = "activity-intent") -> OrderRequest:
    return OrderRequest(
        project_id="leviathan-ai",
        environment=environment,
        account_id=f"{environment}-activity",
        venue="IBKR_TWS",
        instrument_id="NQ-202612",
        native_contract_id="contract-1",
        side="BUY",
        quantity=Decimal("1.25"),
        order_type="MARKET",
        time_in_force="DAY",
        client_order_id=_CLIENT_KEY.derive(f"{environment}-activity", intent, 1),
        intent_idempotency_key=intent,
        attempt=1,
        strategy_id="activity-store-strategy",
        risk_policy_digest="b" * 64,
        actor_id="activity-store-operator",
        capability="paper-submit",
    )


async def test_activity_snapshot_is_authenticated_and_supports_high_water(
    tmp_path: Path,
) -> None:
    engine, sessions = create_engine_and_sessionmaker(
        f"sqlite+aiosqlite:///{tmp_path}/activity-store.db"
    )
    await init_schema(engine)
    ledger = OrderLedger(
        sessions, key=LedgerIntegrityKey(b"oms-activity-store-synthetic-integrity-key")
    )
    try:
        assert await ledger.account_activity_snapshot("paper", "paper-activity") == (
            0,
            (),
            (),
            (),
        )
        first = await ledger.create(_request())
        at_create, created_orders, fills, corrections = await ledger.account_activity_snapshot(
            "paper", "paper-activity"
        )
        assert created_orders[0][1].order_id == first.order_id
        assert created_orders[0][2].tzinfo is not None
        assert created_orders[0][2].utcoffset() == datetime.now(UTC).utcoffset()
        assert not fills and not corrections

        second = await ledger.create(_request(intent="activity-intent-2"))
        current, current_orders, _, _ = await ledger.account_activity_snapshot(
            "paper", "paper-activity"
        )
        (
            historical,
            historical_orders,
            historical_fills,
            historical_corrections,
        ) = await ledger.account_activity_snapshot("paper", "paper-activity", at_create)
        assert current > at_create
        assert {row[1].order_id for row in current_orders} == {first.order_id, second.order_id}
        assert historical == at_create
        assert [row[1].order_id for row in historical_orders] == [first.order_id]
        assert not historical_fills and not historical_corrections
        with pytest.raises(OMSLedgerCorruption):
            await ledger.account_activity_snapshot("paper", "paper-activity", current + 1)
        with pytest.raises(OMSValidationError) as error:
            await ledger.account_activity_snapshot("live", "paper-activity")
        assert error.value.code == "INVALID_ACTIVITY_QUERY"
    finally:
        await engine.dispose()


async def test_activity_snapshot_isolation_hides_order_update_after_capture(
    tmp_path: Path,
) -> None:
    engine, sessions = create_engine_and_sessionmaker(
        f"sqlite+aiosqlite:///{tmp_path}/activity-snapshot-isolation.db"
    )
    await init_schema(engine)
    ledger = OrderLedger(
        sessions,
        key=LedgerIntegrityKey(b"oms-activity-snapshot-isolation-integrity-key"),
    )
    try:
        created = await ledger.create(_request(intent="snapshot-isolation"))
        snapshot = await ledger.begin_activity_read_snapshot("paper", "paper-activity")
        try:
            async with sessions() as writer:
                await writer.execute(
                    update(OmsOrderRow)
                    .where(OmsOrderRow.order_id == created.order_id)
                    .values(state="CANCELED")
                )
                await writer.commit()

            result = await ledger.activity_snapshot_from_snapshot(snapshot, None)
            assert result[1][0][1].state.value == "CREATED"
        finally:
            await ledger.close_activity_read_snapshot(snapshot)

        with pytest.raises(OMSLedgerCorruption):
            await ledger.account_activity_snapshot("paper", "paper-activity")
    finally:
        await engine.dispose()


async def test_reader_thread_startup_does_not_block_event_loop(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine, sessions = create_engine_and_sessionmaker(
        f"sqlite+aiosqlite:///{tmp_path}/activity-worker-startup.db"
    )
    await init_schema(engine)
    ledger = OrderLedger(
        sessions,
        key=LedgerIntegrityKey(b"oms-activity-worker-startup-integrity-key"),
    )
    original_run = oms_ledger_module._ActivityReadWorker._run

    def delayed_run(worker: oms_ledger_module._ActivityReadWorker) -> None:
        time.sleep(0.4)
        original_run(worker)

    monkeypatch.setattr(oms_ledger_module._ActivityReadWorker, "_run", delayed_run)
    try:
        read = asyncio.create_task(ledger.begin_activity_read_snapshot("paper", "paper-activity"))
        timer_started = time.monotonic()
        await asyncio.sleep(0.05)
        timer_elapsed = time.monotonic() - timer_started
        snapshot = await read
        assert timer_elapsed < 0.2
        await ledger.close_activity_read_snapshot(snapshot)
    finally:
        await engine.dispose()


async def test_activity_page_avoids_history_sized_account_row_materialization(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine, sessions = create_engine_and_sessionmaker(
        f"sqlite+aiosqlite:///{tmp_path}/activity-page-bounded.db"
    )
    await init_schema(engine)
    ledger = OrderLedger(
        sessions, key=LedgerIntegrityKey(b"oms-activity-page-synthetic-integrity-key")
    )
    try:
        await ledger.create(_request(intent="bounded-page-1"))
        await ledger.create(_request(intent="bounded-page-2"))
        await ledger.create(_request(intent="bounded-page-3"))

        async def no_full_account_rows(*_args: object, **_kwargs: object) -> object:
            raise AssertionError("bounded activity reads must stream, not collect account rows")

        monkeypatch.setattr(ledger, "_account_rows", no_full_account_rows)
        page = await ledger.account_activity_page(
            "paper",
            "paper-activity",
            after_sequence=0,
            high_water_sequence=None,
            limit=1,
        )
        assert len(page.items) == 2  # limit + 1 lookahead, for a stable next cursor.
        assert page.has_more is True
        assert page.high_water_sequence > 0
        assert len(page.net_filled_units) == 1
    finally:
        await engine.dispose()


async def test_file_backed_activity_read_fails_closed_when_wal_cannot_be_verified(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "activity-read-only.db"
    engine, sessions = create_engine_and_sessionmaker(f"sqlite+aiosqlite:///{database_path}")
    await init_schema(engine)

    def reject_wal_for_file_database(
        _connection: object,
        _cursor: object,
        statement: str,
        _parameters: object,
        _context: object,
        _executemany: bool,
    ) -> None:
        if statement.strip().upper() == "PRAGMA JOURNAL_MODE=WAL":
            raise sqlite3.OperationalError("attempt to change journal mode")

    # Model a filesystem/SQLite refusal to enable WAL while retaining the real
    # file-backed URL classification and engine behavior.
    event.listen(engine.sync_engine, "before_cursor_execute", reject_wal_for_file_database)
    ledger = OrderLedger(
        sessions,
        key=LedgerIntegrityKey(b"oms-activity-read-only-integrity-key"),
    )
    try:
        with pytest.raises(OMSConflict) as error:
            await ledger.begin_activity_read_snapshot("paper", "paper-activity")
        assert error.value.code == "ACTIVITY_WAL_REQUIRED"
        assert ledger._activity_wal_ready is False
    finally:
        await engine.dispose()
