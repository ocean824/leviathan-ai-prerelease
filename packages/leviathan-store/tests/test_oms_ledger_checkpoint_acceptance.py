"""Independent acceptance coverage for durable OMS ledger checkpoints."""

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path

import pytest
from leviathan_store.engine import create_engine_and_sessionmaker, init_schema
from leviathan_store.oms_ledger import OrderLedger
from leviathan_store.tables import OmsEventRow, OmsObservationRow, OmsOrderRow
from sqlalchemy import text

from leviathan_core.execution.order_models import (
    BrokerObservation,
    Fill,
    FillCorrection,
    LedgerIntegrityKey,
    OMSLedgerCorruption,
    OrderRequest,
    OrderState,
    PaperDispatchEvidence,
)

pytestmark = pytest.mark.asyncio
_KEY = LedgerIntegrityKey(b"oms-checkpoint-independent-acceptance-key")
_NOW = datetime.now(UTC)


def _request(*, suffix: str = "main") -> OrderRequest:
    return OrderRequest(
        project_id="leviathan-ai",
        environment="demo",
        account_id="checkpoint-acceptance-account",
        venue="MT5-FAKE",
        instrument_id="EURUSD",
        native_contract_id="EURUSD.demo",
        side="BUY",
        quantity=Decimal("1"),
        order_type="MARKET",
        time_in_force="DAY",
        client_order_id=f"checkpoint-acceptance-client-{suffix}",
        intent_idempotency_key=f"checkpoint-acceptance-intent-{suffix}",
        attempt=1,
        strategy_id="checkpoint-acceptance-strategy",
        risk_policy_digest="d" * 64,
        actor_id="synthetic-operator",
        capability="paper-submit",
    )


def _dispatch_evidence(order_id: str, request: OrderRequest) -> PaperDispatchEvidence:
    return PaperDispatchEvidence(
        order_id=order_id,
        request_digest=request.digest,
        account_id=request.account_id,
        venue=request.venue,
        strategy_id=request.strategy_id,
        policy_digest=request.risk_policy_digest,
        account_session_verified=True,
        entitled=True,
        feed_fresh=True,
        risk_approved=True,
        halt_clear=True,
        allowlisted=True,
    )


async def _new_ledger(path: Path) -> tuple[OrderLedger, object]:
    engine, sessions = create_engine_and_sessionmaker(f"sqlite+aiosqlite:///{path}")
    await init_schema(engine)
    return OrderLedger(sessions, key=_KEY), engine


async def _seed_checkpointed_chain(path: Path) -> tuple[OrderLedger, object, str]:
    ledger, engine = await _new_ledger(path)
    request = _request()
    created = await ledger.create(request)
    # Seed authentic synthetic rows in one fixture transaction so each
    # verifier assertion measures its work without test setup doing quadratic writes.
    async with ledger._sessions() as session:
        order = await session.get(OmsOrderRow, created.order_id)
        assert order is not None
        created_at = order.created_at.replace(tzinfo=UTC)
        for sequence in range(1, 129):
            observed_at = created_at + timedelta(seconds=sequence)
            observation = BrokerObservation(
                observation_id=f"checkpoint-acceptance-observation-{sequence}",
                environment=request.environment,
                account_id=request.account_id,
                venue=request.venue,
                client_order_id=request.client_order_id,
                status=OrderState.WORKING,
                observed_at=observed_at,
                venue_order_id=None,
                broker_sequence=sequence,
            )
            session.add(
                OmsObservationRow(
                    order_id=created.order_id,
                    venue=request.venue,
                    account_id=request.account_id,
                    observation_id=observation.observation_id,
                    evidence=observation.payload(),
                    recorded_at=observed_at,
                )
            )
            session.add(
                OmsEventRow(
                    order_id=created.order_id,
                    sequence=sequence,
                    state=OrderState.WORKING.value,
                    code="BROKER_RECONCILIATION",
                    evidence={"observation_id": observation.observation_id, "discrepancies": []},
                    recorded_at=observed_at,
                )
            )
        order.version = 128
        order.state = OrderState.WORKING.value
        order.updated_at = created_at + timedelta(seconds=129)
        await ledger._seal_account(session, "demo", request.account_id)
        await session.commit()
    return ledger, engine, created.order_id


async def test_checkpoint_read_authenticates_only_bounded_suffix_and_reopens_from_disk(
    tmp_path: Path,
) -> None:
    ledger, engine, order_id = await _seed_checkpointed_chain(tmp_path / "bounded-checkpoint.db")
    try:
        async with ledger._sessions() as session:
            total_rows = await session.scalar(
                text("SELECT COUNT(*) FROM oms_order_events WHERE order_id=:order_id"),
                {"order_id": order_id},
            )
            checkpoint_rows = await session.scalar(
                text(
                    "SELECT COUNT(*) FROM oms_ledger_checkpoints "
                    "WHERE environment='demo' AND account_id=:account_id"
                ),
                {"account_id": "checkpoint-acceptance-account"},
            )
        assert checkpoint_rows == 1
        suffix_rows = await ledger.verify_account_integrity("demo", "checkpoint-acceptance-account")
        assert type(suffix_rows) is int
        assert 0 <= suffix_rows <= 256
        assert suffix_rows < total_rows

        await engine.dispose()
        reopened, reopened_engine = await _new_ledger(tmp_path / "bounded-checkpoint.db")
        try:
            # A fresh ledger instance reconstructs authority from signed durable rows.
            assert (
                await reopened.verify_account_integrity("demo", "checkpoint-acceptance-account")
                == suffix_rows
            )
        finally:
            await reopened_engine.dispose()
    finally:
        await engine.dispose()


async def test_forged_checkpoint_is_rejected(tmp_path: Path) -> None:
    ledger, engine, _order_id = await _seed_checkpointed_chain(tmp_path / "forged-checkpoint.db")
    try:
        async with ledger._sessions() as session:
            await session.execute(
                text(
                    "UPDATE oms_ledger_checkpoints SET chain_head=:head "
                    "WHERE environment='demo' AND account_id=:account_id"
                ),
                {"head": "f" * 64, "account_id": "checkpoint-acceptance-account"},
            )
            await session.commit()
        with pytest.raises(OMSLedgerCorruption) as error:
            await ledger.verify_account_integrity("demo", "checkpoint-acceptance-account")
        assert error.value.code == "OMS_LEDGER_CORRUPT"
    finally:
        await engine.dispose()


async def test_legacy_chain_without_checkpoint_is_verified_from_genesis(tmp_path: Path) -> None:
    ledger, engine, _order_id = await _seed_checkpointed_chain(tmp_path / "legacy-no-checkpoint.db")
    try:
        async with ledger._sessions() as session:
            await session.execute(text("DELETE FROM oms_ledger_checkpoints"))
            await session.commit()

        # Older databases without a checkpoint remain readable by replaying genesis.
        verified_rows = await ledger.verify_account_integrity(
            "demo", "checkpoint-acceptance-account"
        )
        assert verified_rows > 256
        assert (
            await ledger.verify_account_integrity_full("demo", "checkpoint-acceptance-account")
            == verified_rows
        )
    finally:
        await engine.dispose()


async def test_scheduled_full_verifier_catches_old_row_tamper_and_alerts(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    ledger, engine, order_id = await _seed_checkpointed_chain(tmp_path / "old-row-tamper.db")
    try:
        async with ledger._sessions() as session:
            await session.execute(
                text(
                    "UPDATE oms_order_events SET recorded_at=:changed "
                    "WHERE order_id=:order_id AND sequence=1"
                ),
                {
                    "changed": (_NOW + timedelta(days=1)).isoformat(),
                    "order_id": order_id,
                },
            )
            await session.commit()

        # Ordinary reads authenticate from the checkpoint; scheduled replay goes to genesis.
        assert await ledger.verify_account_integrity("demo", "checkpoint-acceptance-account") <= 256
        with (
            caplog.at_level("ERROR", logger="leviathan_store.oms_ledger"),
            pytest.raises(OMSLedgerCorruption) as error,
        ):
            await ledger.verify_account_integrity_full("demo", "checkpoint-acceptance-account")
        assert error.value.code == "OMS_LEDGER_CORRUPT"
        assert "OMS_LEDGER_FULL_VERIFY_FAILED" in caplog.text
    finally:
        await engine.dispose()


async def test_reopened_ledger_rejects_persisted_checkpoint_tamper(tmp_path: Path) -> None:
    database = tmp_path / "restart-reverification.db"
    ledger, engine, _order_id = await _seed_checkpointed_chain(database)
    assert await ledger.verify_account_integrity("demo", "checkpoint-acceptance-account") <= 256
    async with ledger._sessions() as session:
        await session.execute(
            text(
                "UPDATE oms_ledger_checkpoints SET signature=:signature "
                "WHERE environment='demo' AND account_id=:account_id"
            ),
            {
                "signature": "0" * 64,
                "account_id": "checkpoint-acceptance-account",
            },
        )
        await session.commit()
    await engine.dispose()

    reopened, engine = await _new_ledger(database)
    try:
        with pytest.raises(OMSLedgerCorruption) as error:
            await reopened.verify_account_integrity("demo", "checkpoint-acceptance-account")
        assert error.value.code == "OMS_LEDGER_CORRUPT"
    finally:
        await engine.dispose()


async def test_order_fill_correction_and_observation_write_semantics_remain_intact(
    tmp_path: Path,
) -> None:
    ledger, engine = await _new_ledger(tmp_path / "writes-unchanged.db")
    request = _request(suffix="write-semantics")
    try:
        created = await ledger.create(request)
        await ledger.mark_submitting(
            created.order_id, _dispatch_evidence(created.order_id, request)
        )
        submitted = await ledger.mark_submit_result(
            created.order_id, OrderState.WORKING, "venue-order-write"
        )
        assert submitted.state is OrderState.WORKING

        fill = Fill(
            venue=request.venue,
            account_id=request.account_id,
            execution_id="checkpoint-write-fill",
            quantity=Decimal("0.4"),
            price=Decimal("1.1"),
            occurred_at=_NOW,
        )
        with_fill = await ledger.record_fill(created.order_id, fill)
        assert with_fill.filled_quantity == Decimal("0.4")

        correction = FillCorrection(
            venue=request.venue,
            account_id=request.account_id,
            execution_id=fill.execution_id,
            correction_id="checkpoint-write-correction",
            revision=1,
            revised_quantity=Decimal("0.3"),
            revised_price=Decimal("1.2"),
            occurred_at=_NOW + timedelta(seconds=1),
        )
        corrected = await ledger.record_fill_correction(created.order_id, correction)
        assert corrected.filled_quantity == Decimal("0.3")

        observation = BrokerObservation(
            observation_id="checkpoint-write-observation",
            environment=request.environment,
            account_id=request.account_id,
            venue=request.venue,
            client_order_id=request.client_order_id,
            status=OrderState.WORKING,
            observed_at=_NOW + timedelta(seconds=2),
            venue_order_id="venue-order-write",
        )
        observed = await ledger.record_observation(created.order_id, observation)
        assert observed.state is OrderState.WORKING
        assert observed.filled_quantity == Decimal("0.3")
        assert await ledger.verify_account_integrity("demo", request.account_id) <= 256
    finally:
        await engine.dispose()
