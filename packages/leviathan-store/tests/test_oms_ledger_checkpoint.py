"""Signed OMS account-chain checkpoints and scheduled full verification."""

import hashlib
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path

import pytest
from leviathan_store.engine import create_engine_and_sessionmaker, init_schema
from leviathan_store.oms_ledger import OrderLedger
from leviathan_store.oms_operator_resolution import OmsOperatorResolutionRow
from leviathan_store.tables import OmsEventRow, OmsObservationRow, OmsOrderRow
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from leviathan_core.execution.order_models import (
    BrokerObservation,
    LedgerIntegrityKey,
    OMSLedgerCorruption,
    OrderRequest,
    OrderState,
)
from leviathan_core.numeric import canonical_json

pytestmark = pytest.mark.asyncio
_KEY = LedgerIntegrityKey(b"oms-checkpoint-unit-synthetic-key-0001")


def _request() -> OrderRequest:
    return OrderRequest(
        project_id="leviathan-ai",
        environment="demo",
        account_id="checkpoint-account",
        venue="MT5-FAKE",
        instrument_id="EURUSD",
        native_contract_id="EURUSD.demo",
        side="BUY",
        quantity=Decimal("1"),
        order_type="MARKET",
        time_in_force="DAY",
        client_order_id="checkpoint-client-1",
        intent_idempotency_key="checkpoint-intent-1",
        attempt=1,
        strategy_id="checkpoint-strategy",
        risk_policy_digest="c" * 64,
        actor_id="operator-1",
        capability="paper-submit",
    )


async def _append_replay_rows(
    ledger: OrderLedger,
    sessions: async_sessionmaker[AsyncSession],
    order_id: str,
    *,
    first: int,
    last: int,
) -> None:
    async with sessions() as session:
        row = await session.get(OmsOrderRow, order_id)
        assert row is not None
        created_at = row.created_at.replace(tzinfo=UTC)
        request = _request()
        for number in range(first, last + 1):
            observed_at = created_at + timedelta(seconds=number)
            observation = BrokerObservation(
                observation_id=f"checkpoint-observation-{number}",
                environment=request.environment,
                account_id=request.account_id,
                venue=request.venue,
                client_order_id="checkpoint-client-1",
                status=OrderState.WORKING,
                observed_at=observed_at,
                venue_order_id=None,
                broker_sequence=number,
            )
            session.add(
                OmsObservationRow(
                    order_id=order_id,
                    venue=request.venue,
                    account_id=request.account_id,
                    observation_id=observation.observation_id,
                    evidence=observation.payload(),
                    recorded_at=observed_at,
                )
            )
            session.add(
                OmsEventRow(
                    order_id=order_id,
                    sequence=number,
                    state=OrderState.WORKING.value,
                    code="BROKER_RECONCILIATION",
                    evidence={
                        "observation_id": observation.observation_id,
                        "discrepancies": [],
                    },
                    recorded_at=observed_at,
                )
            )
        row.version = last
        row.state = OrderState.WORKING.value
        row.updated_at = created_at + timedelta(seconds=last + 1)
        await ledger._seal_account(session, "demo", "checkpoint-account")
        await session.commit()


async def _checkpoint_ledger(
    tmp_path: Path,
) -> tuple[AsyncEngine, async_sessionmaker[AsyncSession], OrderLedger, str]:
    engine, sessions = create_engine_and_sessionmaker(
        f"sqlite+aiosqlite:///{tmp_path / 'oms-checkpoint.db'}"
    )
    await init_schema(engine)
    ledger = OrderLedger(sessions, key=_KEY)
    created = await ledger.create(_request())
    # One create event plus two append-only evidence rows per observation.
    await _append_replay_rows(ledger, sessions, created.order_id, first=1, last=130)
    await _append_replay_rows(ledger, sessions, created.order_id, first=131, last=132)
    return engine, sessions, ledger, created.order_id


async def test_signed_checkpoint_bounds_read_suffix_and_full_verifier_checks_prefix(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    engine, sessions, ledger, order_id = await _checkpoint_ledger(tmp_path)
    try:
        async with sessions() as session:
            checkpoint_count = await session.scalar(
                text(
                    "SELECT COUNT(*) FROM oms_ledger_checkpoints "
                    "WHERE environment='demo' AND account_id='checkpoint-account'"
                )
            )
        assert checkpoint_count == 1
        # The durable read verifies only four child rows after sequence 261.
        with caplog.at_level("INFO", logger="leviathan_store.oms_ledger"):
            assert await ledger.verify_account_integrity("demo", "checkpoint-account") == 4
        assert "suffix_rows=4 orders_verified=1" in caplog.text
        assert await ledger.verify_account_integrity_full("demo", "checkpoint-account") == 265

        # Alter a pre-checkpoint event while keeping its ordinary business values
        # well-formed. Normal reads trust the authenticated checkpoint; the
        # scheduled full-chain audit detects the old-row tamper and emits the alert.
        async with sessions() as session:
            await session.execute(
                text(
                    "UPDATE oms_order_events SET recorded_at=:changed "
                    "WHERE order_id=:order_id AND sequence=1"
                ),
                {
                    "changed": (datetime.now(UTC) + timedelta(seconds=2)).isoformat(),
                    "order_id": order_id,
                },
            )
            await session.commit()
        assert await ledger.verify_account_integrity("demo", "checkpoint-account") == 4
        with (
            caplog.at_level("ERROR", logger="leviathan_store.oms_ledger"),
            pytest.raises(OMSLedgerCorruption) as error,
        ):
            await ledger.verify_account_integrity_full("demo", "checkpoint-account")
        assert error.value.code == "OMS_LEDGER_CORRUPT"
        assert "OMS_LEDGER_FULL_VERIFY_FAILED" in caplog.text
    finally:
        await engine.dispose()


async def test_forged_checkpoint_fails_closed(tmp_path: Path) -> None:
    engine, sessions, ledger, _order_id = await _checkpoint_ledger(tmp_path)
    try:
        async with sessions() as session:
            await session.execute(
                text(
                    "UPDATE oms_ledger_checkpoints SET signature=:signature "
                    "WHERE environment='demo' AND account_id='checkpoint-account'"
                ),
                {"signature": "0" * 64},
            )
            await session.commit()
        with pytest.raises(OMSLedgerCorruption) as error:
            await ledger.verify_account_integrity("demo", "checkpoint-account")
        assert error.value.code == "OMS_LEDGER_CORRUPT"
    finally:
        await engine.dispose()


@pytest.mark.parametrize("sequence", [134, 265])
async def test_normal_verifier_detects_missing_checkpointed_child_rows(
    tmp_path: Path, sequence: int
) -> None:
    engine, sessions, ledger, order_id = await _checkpoint_ledger(tmp_path)
    try:
        async with sessions() as session:
            await session.execute(
                text(
                    "DELETE FROM oms_order_events "
                    "WHERE order_id=:order_id AND ledger_sequence=:sequence"
                ),
                {"order_id": order_id, "sequence": sequence},
            )
            await session.commit()
        with pytest.raises(OMSLedgerCorruption) as error:
            await ledger.verify_account_integrity("demo", "checkpoint-account")
        assert error.value.code == "OMS_LEDGER_CORRUPT"
    finally:
        await engine.dispose()


async def test_missing_checkpoint_table_is_not_recreated_by_a_read(tmp_path: Path) -> None:
    engine, sessions, ledger, _order_id = await _checkpoint_ledger(tmp_path)
    try:
        async with sessions() as session:
            await session.execute(text("DROP TABLE oms_ledger_checkpoints"))
            await session.commit()
        assert await ledger.verify_account_integrity("demo", "checkpoint-account") == 265
        async with sessions() as session:
            table_exists = await session.scalar(
                text(
                    "SELECT COUNT(*) FROM sqlite_master "
                    "WHERE type='table' AND name='oms_ledger_checkpoints'"
                )
            )
        assert table_exists == 0
    finally:
        await engine.dispose()


async def test_normal_verifier_rejects_reordered_suffix_rows(tmp_path: Path) -> None:
    engine, sessions, ledger, order_id = await _checkpoint_ledger(tmp_path)
    try:
        async with sessions() as session:
            await session.execute(
                text(
                    "UPDATE oms_order_events SET ledger_sequence=-1 "
                    "WHERE order_id=:order_id AND ledger_sequence=264"
                ),
                {"order_id": order_id},
            )
            await session.execute(
                text(
                    "UPDATE oms_order_events SET ledger_sequence=264 "
                    "WHERE order_id=:order_id AND ledger_sequence=265"
                ),
                {"order_id": order_id},
            )
            await session.execute(
                text(
                    "UPDATE oms_order_events SET ledger_sequence=265 "
                    "WHERE order_id=:order_id AND ledger_sequence=-1"
                ),
                {"order_id": order_id},
            )
            await session.commit()
        with pytest.raises(OMSLedgerCorruption) as error:
            await ledger.verify_account_integrity("demo", "checkpoint-account")
        assert error.value.code == "OMS_LEDGER_CORRUPT"
    finally:
        await engine.dispose()


async def test_resolution_linkage_is_verified_by_get_and_normal_integrity_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine, sessions, ledger, order_id = await _checkpoint_ledger(tmp_path)
    try:
        async with sessions() as session:
            row = await session.get(OmsOrderRow, order_id)
            assert row is not None
            request = _request()
            observation_id = "checkpoint-resolution-observation"
            observation = {
                "observation_id": observation_id,
                "venue": request.venue,
                "environment": request.environment,
            }
            affected_ids = [order_id]
            identity_payload = {
                "environment": request.environment,
                "account_id": request.account_id,
                "binding_venue": request.venue,
                "binding_environment": request.environment,
                "observations": [[observation_id, request.venue, request.environment]],
                "affected_order_ids": affected_ids,
            }
            identity_digest = hashlib.sha256(canonical_json(identity_payload)).hexdigest()
            conflict_id = "b" * 64
            resolution_id = "a" * 64
            broker_digest = "c" * 64
            recorded_at = row.updated_at.replace(tzinfo=UTC) + timedelta(seconds=1)
            row.state = OrderState.WORKING.value
            row.version = 134
            row.discrepancies = []
            row.updated_at = recorded_at
            session.add_all(
                [
                    OmsEventRow(
                        order_id=order_id,
                        sequence=133,
                        state=OrderState.RECONCILE_REQUIRED.value,
                        code="VENUE_ACCOUNT_CONFLICT",
                        evidence={
                            "discrepancies": ["VENUE_ACCOUNT_CONFLICT"],
                            "binding_venue": request.venue,
                            "binding_environment": request.environment,
                            "observations": [observation],
                            "affected_order_ids": affected_ids,
                            "identity_digest": identity_digest,
                        },
                        recorded_at=recorded_at,
                    ),
                    OmsOperatorResolutionRow(
                        resolution_id=resolution_id,
                        environment=request.environment,
                        account_id=request.account_id,
                        conflict_id=conflict_id,
                        binding_venue=request.venue,
                        binding_environment=request.environment,
                        observation_ids=[observation_id],
                        identity_digest=identity_digest,
                        idempotency_digest="d" * 64,
                        operator_principal_id="operator.synthetic",
                        reason_code="BINDING_VERIFIED",
                        broker_revision=1,
                        broker_evidence_digest=broker_digest,
                        prior_ledger_revision=265,
                        resolved_at_ns=1_799_000_000_000_000_000,
                        affected_order_ids=affected_ids,
                        ledger_sequence=None,
                        chain=None,
                        recorded_at=recorded_at,
                    ),
                    OmsEventRow(
                        order_id=order_id,
                        sequence=134,
                        state=OrderState.WORKING.value,
                        code="VENUE_ACCOUNT_CONFLICT_RESOLVED",
                        evidence={
                            "resolution_id": resolution_id,
                            "conflict_id": conflict_id,
                            "broker_revision": 1,
                            "broker_evidence_digest": broker_digest,
                            "prior_ledger_revision": 265,
                            "identity_digest": identity_digest,
                            "discrepancies": [],
                            "resolved_state": OrderState.WORKING.value,
                        },
                        recorded_at=recorded_at,
                    ),
                ]
            )
            monkeypatch.setattr("leviathan_store.oms_ledger._CHECKPOINT_INTERVAL", 1)
            await ledger._seal_account(session, "demo", "checkpoint-account")
            await session.commit()

        async with sessions() as session:
            resolution = await session.scalar(select(OmsOperatorResolutionRow))
            assert resolution is not None
            resolution.broker_evidence_digest = "e" * 64
            await session.commit()
        with pytest.raises(OMSLedgerCorruption):
            await ledger.get(order_id)
        with pytest.raises(OMSLedgerCorruption):
            await ledger.verify_account_integrity("demo", "checkpoint-account")
    finally:
        await engine.dispose()
