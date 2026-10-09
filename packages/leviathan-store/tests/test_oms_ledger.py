"""Durable OMS uniqueness, restart recovery and additive schema evidence."""

import asyncio
import copy
import pickle
import random
import shutil
import threading
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path

import pytest
from leviathan_store.engine import create_engine_and_sessionmaker, init_schema
from leviathan_store.oms_ledger import OrderLedger
from leviathan_store.tables import (
    OmsEventRow,
    OmsFillCorrectionRow,
    OmsFillRow,
    OmsLedgerHeadRow,
    OmsObservationRow,
    OmsOrderRow,
    SchemaMigrationRow,
)
from sqlalchemy import select, text, update

from leviathan_core.execution.order_models import (
    BrokerObservation,
    Fill,
    FillCorrection,
    LedgerIntegrityKey,
    OMSConflict,
    OMSDiscrepancy,
    OMSLedgerCorruption,
    OMSValidationError,
    OrderRequest,
    OrderState,
    PaperDispatchEvidence,
)

pytestmark = pytest.mark.asyncio
_INTEGRITY_KEY = LedgerIntegrityKey(b"oms-store-unit-synthetic-integrity-key")


def request() -> OrderRequest:
    return OrderRequest(
        project_id="leviathan-ai",
        environment="demo",
        account_id="demo-1",
        venue="MT5-FAKE",
        instrument_id="EURUSD",
        native_contract_id="EURUSD.demo",
        side="BUY",
        quantity=Decimal("1.0"),
        order_type="MARKET",
        time_in_force="DAY",
        client_order_id="caller-1",
        intent_idempotency_key="caller-1",
        attempt=1,
        strategy_id="strat-1",
        risk_policy_digest="b" * 64,
        actor_id="operator-1",
        capability="demo-submit",
    )


def evidence(order_id: str, req: OrderRequest) -> PaperDispatchEvidence:
    return PaperDispatchEvidence(
        order_id=order_id,
        request_digest=req.digest,
        account_id=req.account_id,
        venue=req.venue,
        strategy_id=req.strategy_id,
        policy_digest=req.risk_policy_digest,
        account_session_verified=True,
        entitled=True,
        feed_fresh=True,
        risk_approved=True,
        halt_clear=True,
        allowlisted=True,
    )


async def test_idempotency_survives_reopen_and_conflict(tmp_path: object) -> None:
    url = f"sqlite+aiosqlite:///{tmp_path}/oms.db"
    engine, sessions = create_engine_and_sessionmaker(url)
    await init_schema(engine)
    ledger = OrderLedger(sessions, key=_INTEGRITY_KEY)
    req = request()
    first = await ledger.create(req)
    await engine.dispose()
    engine2, sessions2 = create_engine_and_sessionmaker(url)
    await init_schema(engine2)
    reopened = OrderLedger(sessions2, key=_INTEGRITY_KEY)
    assert (await reopened.create(req)).order_id == first.order_id
    with pytest.raises(OMSConflict, match="IDEMPOTENCY_CONFLICT"):
        await reopened.create(replace(req, quantity=Decimal("2")))
    async with sessions2() as session:
        assert (await session.scalars(select(SchemaMigrationRow.version))).all() == [1, 2, 3, 4, 5]
    await engine2.dispose()


async def test_dispose_keeps_writer_lock_during_active_dispatch(tmp_path: Path) -> None:
    url = f"sqlite+aiosqlite:///{tmp_path}/active-lock.db"
    engine, sessions = create_engine_and_sessionmaker(url)
    await init_schema(engine)
    ledger = OrderLedger(sessions, key=_INTEGRITY_KEY)
    ledger.active_dispatch.add("in-flight")
    await engine.dispose()

    other_engine, other_sessions = create_engine_and_sessionmaker(url)
    with pytest.raises(OMSConflict, match="OMS_LEDGER_LOCKED"):
        OrderLedger(other_sessions, key=_INTEGRITY_KEY)
    await other_engine.dispose()

    ledger.active_dispatch.clear()
    await engine.dispose()
    reopened_engine, reopened_sessions = create_engine_and_sessionmaker(url)
    OrderLedger(reopened_sessions, key=_INTEGRITY_KEY)
    await reopened_engine.dispose()


async def test_ledger_owner_cannot_be_copied_or_reinitialized(tmp_path: Path) -> None:
    engine, sessions = create_engine_and_sessionmaker(
        f"sqlite+aiosqlite:///{tmp_path}/sealed-owner.db"
    )
    await init_schema(engine)
    ledger = OrderLedger(sessions, key=_INTEGRITY_KEY)
    for attempt in (
        lambda: copy.copy(ledger),
        lambda: copy.deepcopy(ledger),
        lambda: pickle.dumps(ledger),
        lambda: OrderLedger.__init__(ledger, sessions, key=_INTEGRITY_KEY),
    ):
        with pytest.raises(OMSConflict, match="OMS_LEDGER_LOCKED"):
            attempt()
    with pytest.raises(OMSValidationError, match="OMS_LEDGER_SEALED"):
        type("ForgedLedger", (OrderLedger,), {})
    assert (await ledger.create(request())).state is OrderState.CREATED
    ledger.close()
    await engine.dispose()


async def test_memory_owner_claim_is_atomic_across_threads() -> None:
    engine, sessions = create_engine_and_sessionmaker("sqlite+aiosqlite:///:memory:")
    await init_schema(engine)
    barrier = threading.Barrier(2)

    def claim() -> OrderLedger | OMSConflict:
        barrier.wait()
        try:
            return OrderLedger(sessions, key=_INTEGRITY_KEY)
        except OMSConflict as exc:
            return exc

    first, second = await asyncio.gather(
        asyncio.to_thread(claim), asyncio.to_thread(claim)
    )
    winners = [item for item in (first, second) if isinstance(item, OrderLedger)]
    failures = [item for item in (first, second) if isinstance(item, OMSConflict)]
    assert len(winners) == len(failures) == 1
    assert failures[0].code == "OMS_LEDGER_LOCKED"
    winners[0].close()
    await engine.dispose()


async def test_direct_guard_mutation_requires_actor(tmp_path: Path) -> None:
    url = f"sqlite+aiosqlite:///{tmp_path}/guard-clearance.db"
    engine, sessions = create_engine_and_sessionmaker(url)
    await init_schema(engine)
    ledger = OrderLedger(sessions, key=_INTEGRITY_KEY)
    req = request()
    created = await ledger.create(req)
    await ledger.mark_submitting(created.order_id, evidence(created.order_id, req))
    with pytest.raises(OMSValidationError, match="OMS_ACTOR_REQUIRED"):
        await ledger.arm_dispatch_guard(
            created.order_id, action="SUBMIT", broker_revision=0
        )
    with pytest.raises(OMSValidationError, match="OMS_ACTOR_REQUIRED"):
        await ledger.mark_submit_stale(created.order_id)
    with pytest.raises(OMSValidationError, match="OMS_ACTOR_REQUIRED"):
        await ledger.complete_guarded_submit(
            created.order_id, OrderState.WORKING, "venue-guarded"
        )
    assert await ledger.account_guard(req.environment, req.account_id) is None
    await engine.dispose()


async def test_restart_marks_committed_attempt_unknown(tmp_path: object) -> None:
    url = f"sqlite+aiosqlite:///{tmp_path}/oms.db"
    engine, sessions = create_engine_and_sessionmaker(url)
    await init_schema(engine)
    ledger = OrderLedger(sessions, key=_INTEGRITY_KEY)
    req = request()
    created = await ledger.create(req)
    marked = await ledger.mark_submitting(created.order_id, evidence(created.order_id, req))
    assert marked.state == OrderState.SUBMITTING
    await engine.dispose()
    engine2, sessions2 = create_engine_and_sessionmaker(url)
    reopened = OrderLedger(sessions2, key=_INTEGRITY_KEY)
    recovered = await reopened.recover_uncertain()
    assert len(recovered) == 1
    assert recovered[0].state == OrderState.UNKNOWN_SUBMIT
    with pytest.raises(OMSConflict, match="SUBMIT_ALREADY_ATTEMPTED"):
        await reopened.mark_submitting(
            created.order_id, evidence(created.order_id, req)
        )
    await engine2.dispose()


async def test_execution_unique_across_orders_and_overfill_visible(tmp_path: object) -> None:
    engine, sessions = create_engine_and_sessionmaker(f"sqlite+aiosqlite:///{tmp_path}/oms.db")
    await init_schema(engine)
    ledger = OrderLedger(sessions, key=_INTEGRITY_KEY)
    req = request()
    one = await ledger.create(req)
    req2 = replace(req, client_order_id="caller-2")
    two = await ledger.create(req2)
    await ledger.mark_submitting(one.order_id, evidence(one.order_id, req))
    await ledger.mark_submit_result(one.order_id, OrderState.WORKING, "venue-1")
    await ledger.mark_submitting(two.order_id, evidence(two.order_id, req2))
    fill = Fill(
        venue=req.venue,
        account_id=req.account_id,
        execution_id="exe-1",
        quantity=Decimal("2"),
        price=Decimal("1.20"),
        occurred_at=datetime(2026, 9, 30, tzinfo=UTC),
    )
    view = await ledger.record_fill(one.order_id, fill)
    assert view.state == OrderState.RECONCILE_REQUIRED
    assert view.filled_quantity == Decimal("2")
    assert "OVERFILL" in view.discrepancies
    with pytest.raises(OMSConflict, match="EXECUTION_ID_CONFLICT"):
        await ledger.record_fill(two.order_id, fill)
    await engine.dispose()


async def test_fill_sum_never_rounds_away_small_execution(tmp_path: object) -> None:
    engine, sessions = create_engine_and_sessionmaker(f"sqlite+aiosqlite:///{tmp_path}/oms.db")
    await init_schema(engine)
    ledger = OrderLedger(sessions, key=_INTEGRITY_KEY)
    req = replace(request(), quantity=Decimal("2"))
    created = await ledger.create(req)
    await ledger.mark_submitting(created.order_id, evidence(created.order_id, req))
    first = Fill(
        venue=req.venue,
        account_id=req.account_id,
        execution_id="exe-1",
        quantity=Decimal("0.1234567890123456789012345678901234"),
        price=Decimal("1"),
        occurred_at=datetime(2026, 9, 30, tzinfo=UTC),
    )
    await ledger.record_fill(created.order_id, first)
    second = replace(first, execution_id="exe-2", quantity=Decimal("1E-35"))
    with pytest.raises(OMSValidationError, match="PRECISION_EXCEEDED"):
        await ledger.record_fill(created.order_id, second)
    assert (await ledger.get(created.order_id)).filled_quantity == first.quantity
    await engine.dispose()


async def test_unknown_order_blocks_next_submit_on_same_account(tmp_path: object) -> None:
    engine, sessions = create_engine_and_sessionmaker(f"sqlite+aiosqlite:///{tmp_path}/oms.db")
    await init_schema(engine)
    ledger = OrderLedger(sessions, key=_INTEGRITY_KEY)
    req = request()
    first = await ledger.create(req)
    await ledger.mark_submitting(first.order_id, evidence(first.order_id, req))
    await ledger.mark_submit_result(first.order_id, OrderState.UNKNOWN_SUBMIT)
    req2 = replace(req, client_order_id="caller-2")
    second = await ledger.create(req2)
    with pytest.raises(OMSValidationError, match="ACCOUNT_RECONCILIATION_REQUIRED"):
        await ledger.mark_submitting(second.order_id, evidence(second.order_id, req2))
    assert (await ledger.get(second.order_id)).state == OrderState.RISK_REJECTED
    assert (await ledger.events(second.order_id))[-1]["code"] == ("ACCOUNT_RECONCILIATION_REQUIRED")
    await engine.dispose()


async def test_filled_order_with_unresolved_gtd_discrepancy_blocks_account(
    tmp_path: object,
) -> None:
    engine, sessions = create_engine_and_sessionmaker(f"sqlite+aiosqlite:///{tmp_path}/oms.db")
    await init_schema(engine)
    ledger = OrderLedger(sessions, key=_INTEGRITY_KEY)
    expiry = datetime(2026, 9, 30, tzinfo=UTC)
    req = replace(request(), time_in_force="GTD", expires_at=expiry)
    first = await ledger.create(req)
    await ledger.mark_submitting(first.order_id, evidence(first.order_id, req))
    await ledger.mark_submit_result(first.order_id, OrderState.WORKING, "venue-1")
    filled = await ledger.record_fill(
        first.order_id,
        Fill(
            venue=req.venue,
            account_id=req.account_id,
            execution_id="late-1",
            quantity=Decimal(1),
            price=Decimal("1.2"),
            occurred_at=datetime(2026, 9, 30, 0, 0, 1, tzinfo=UTC),
        ),
    )
    assert filled.state == OrderState.FILLED
    assert "FILL_AFTER_GTD" in filled.discrepancies
    req2 = replace(request(), client_order_id="caller-2")
    second = await ledger.create(req2)
    with pytest.raises(OMSValidationError, match="ACCOUNT_RECONCILE_REQUIRED"):
        await ledger.mark_submitting(second.order_id, evidence(second.order_id, req2))
    await engine.dispose()


async def test_compact_corrupt_fill_magnitude_rejected_before_arithmetic(tmp_path: object) -> None:
    engine, sessions = create_engine_and_sessionmaker(f"sqlite+aiosqlite:///{tmp_path}/oms.db")
    await init_schema(engine)
    ledger = OrderLedger(sessions, key=_INTEGRITY_KEY)
    req = request()
    created = await ledger.create(req)
    await ledger.mark_submitting(created.order_id, evidence(created.order_id, req))
    await ledger.mark_submit_result(created.order_id, OrderState.WORKING, "venue-1")
    await ledger.record_fill(
        created.order_id,
        Fill(
            venue=req.venue,
            account_id=req.account_id,
            execution_id="exe-1",
            quantity=Decimal("0.5"),
            price=Decimal("1.2"),
            occurred_at=datetime(2026, 9, 30, tzinfo=UTC),
        ),
    )
    async with sessions() as session:
        await session.execute(
            update(OmsFillRow)
            .where(OmsFillRow.execution_id == "exe-1")
            .values(quantity="1E+100000")
        )
        await session.commit()
    with pytest.raises(OMSValidationError) as captured:
        await ledger.get(created.order_id)
    assert captured.value.code == "OMS_LEDGER_CORRUPT"
    assert "100000" not in str(captured.value)
    assert captured.value.args == ("OMS_LEDGER_CORRUPT",)
    await engine.dispose()


async def test_interleaved_fills_rejects_and_cancels_keep_order_invariants(
    tmp_path: object,
) -> None:
    engine, sessions = create_engine_and_sessionmaker(f"sqlite+aiosqlite:///{tmp_path}/oms.db")
    await init_schema(engine)
    ledger = OrderLedger(sessions, key=_INTEGRITY_KEY)
    terminal = {OrderState.REJECTED, OrderState.CANCELED, OrderState.FILLED, OrderState.EXPIRED}
    generator = random.Random(76031)
    for case in range(24):
        req = replace(request(), account_id=f"demo-{case}", client_order_id=f"caller-{case}")
        created = await ledger.create(req)
        await ledger.mark_submitting(created.order_id, evidence(created.order_id, req))
        await ledger.mark_submit_result(created.order_id, OrderState.WORKING, f"venue-{case}")
        actions = ["fill-1", "fill-2", "reject", "cancel"]
        generator.shuffle(actions)
        previous = await ledger.get(created.order_id)
        assert previous is not None
        for step, action in enumerate(actions):
            try:
                if action.startswith("fill"):
                    await ledger.record_fill(
                        created.order_id,
                        Fill(
                            venue=req.venue,
                            account_id=req.account_id,
                            execution_id=f"execution-{case}-{step}",
                            quantity=Decimal("0.25"),
                            price=Decimal("1.2"),
                            occurred_at=datetime(2026, 9, 30, 15, step, tzinfo=UTC),
                        ),
                    )
                elif action == "reject":
                    await ledger.record_observation(
                        created.order_id,
                        BrokerObservation(
                            observation_id=f"reject-{case}",
                            environment=req.environment,
                            account_id=req.account_id,
                            venue=req.venue,
                            client_order_id=req.client_order_id,
                            venue_order_id=f"venue-{case}",
                            status=OrderState.REJECTED,
                            observed_at=datetime(2026, 9, 30, 15, step, tzinfo=UTC),
                            broker_sequence=step,
                        ),
                    )
                elif (
                    previous.state in {OrderState.WORKING, OrderState.PARTIALLY_FILLED}
                    and not previous.discrepancies
                ):
                    await ledger.mark_cancel_pending(created.order_id)
                    await ledger.mark_cancel_result(created.order_id, OrderState.CANCELED)
            except OMSDiscrepancy:
                pass
            current = await ledger.get(created.order_id)
            assert current is not None
            assert current.filled_quantity >= 0
            assert current.filled_quantity >= previous.filled_quantity
            if previous.state in terminal:
                assert current.state == previous.state
            previous = current
        if previous.discrepancies:
            next_request = replace(req, client_order_id=f"next-{case}")
            second = await ledger.create(next_request)
            with pytest.raises(OMSValidationError, match="ACCOUNT_RECONCILE_REQUIRED"):
                await ledger.mark_submitting(
                    second.order_id, evidence(second.order_id, next_request)
                )
    await engine.dispose()


async def test_broker_sequence_orders_equal_timestamp_observations(tmp_path: object) -> None:
    engine, sessions = create_engine_and_sessionmaker(f"sqlite+aiosqlite:///{tmp_path}/oms.db")
    await init_schema(engine)
    ledger = OrderLedger(sessions, key=_INTEGRITY_KEY)
    req = request()
    created = await ledger.create(req)
    await ledger.mark_submitting(created.order_id, evidence(created.order_id, req))
    await ledger.mark_submit_result(created.order_id, OrderState.WORKING, "venue-1")
    common = {
        "environment": req.environment,
        "account_id": req.account_id,
        "venue": req.venue,
        "client_order_id": req.client_order_id,
        "venue_order_id": "venue-1",
        "observed_at": datetime(2026, 9, 30, 15, tzinfo=UTC),
    }
    await ledger.record_observation(
        created.order_id,
        BrokerObservation(
            observation_id="cancel-seq-2",
            status=OrderState.CANCELED,
            broker_sequence=2,
            **common,
        ),
    )
    stale = await ledger.record_observation(
        created.order_id,
        BrokerObservation(
            observation_id="work-seq-1",
            status=OrderState.WORKING,
            broker_sequence=1,
            **common,
        ),
    )
    assert stale.state is OrderState.CANCELED
    assert (await ledger.events(created.order_id))[-1]["code"] == "STALE_BROKER_OBSERVATION"
    with pytest.raises(OMSDiscrepancy, match="BROKER_STATE_DIVERGENCE"):
        await ledger.record_observation(
            created.order_id,
            BrokerObservation(
                observation_id="work-seq-3",
                status=OrderState.WORKING,
                broker_sequence=3,
                **common,
            ),
        )
    assert (await ledger.get(created.order_id)).state is OrderState.CANCELED
    await engine.dispose()


async def test_late_submit_rejection_cannot_erase_early_execution(tmp_path: object) -> None:
    engine, sessions = create_engine_and_sessionmaker(f"sqlite+aiosqlite:///{tmp_path}/oms.db")
    await init_schema(engine)
    ledger = OrderLedger(sessions, key=_INTEGRITY_KEY)
    req = request()
    created = await ledger.create(req)
    await ledger.mark_submitting(created.order_id, evidence(created.order_id, req))
    await ledger.record_fill(
        created.order_id,
        Fill(
            venue=req.venue,
            account_id=req.account_id,
            execution_id="early-execution",
            quantity=Decimal("0.25"),
            price=Decimal("1.2"),
            occurred_at=datetime(2026, 9, 30, tzinfo=UTC),
        ),
    )
    with pytest.raises(OMSDiscrepancy, match="REJECT_AFTER_FILL"):
        await ledger.mark_submit_result(created.order_id, OrderState.REJECTED)
    persisted = await ledger.get(created.order_id)
    assert persisted is not None
    assert persisted.state is OrderState.PARTIALLY_FILLED
    assert persisted.filled_quantity == Decimal("0.25")
    assert "REJECT_AFTER_FILL" in persisted.discrepancies
    assert (await ledger.events(created.order_id))[-1]["code"] == "REJECT_AFTER_FILL"
    await engine.dispose()


async def test_seeded_single_column_oms_mutations_fail_closed(tmp_path: object) -> None:
    mutations = [
        "order_digest", "order_state", "event_sequence", "event_code",
        "fill_quantity", "fill_scope", "correction_revision", "correction_price",
        "observation_status", "observation_scope",
    ]
    generator = random.Random(96039)
    mutations.extend(generator.choice(mutations) for _ in range(10))
    generator.shuffle(mutations)
    for case, mutation in enumerate(mutations):
        engine, sessions = create_engine_and_sessionmaker(
            f"sqlite+aiosqlite:///{tmp_path}/mutation-{case}.db"
        )
        await init_schema(engine)
        ledger = OrderLedger(sessions, key=_INTEGRITY_KEY)
        req = request()
        created = await ledger.create(req)
        await ledger.mark_submitting(created.order_id, evidence(created.order_id, req))
        await ledger.mark_submit_result(created.order_id, OrderState.WORKING, "venue-1")
        await ledger.record_fill(
            created.order_id,
            Fill(
                venue=req.venue,
                account_id=req.account_id,
                execution_id="mutation-execution",
                quantity=Decimal("0.25"),
                price=Decimal("1.2"),
                occurred_at=datetime(2026, 9, 30, 15, tzinfo=UTC),
            ),
        )
        await ledger.record_observation(
            created.order_id,
            BrokerObservation(
                observation_id="mutation-observation",
                environment=req.environment,
                account_id=req.account_id,
                venue=req.venue,
                client_order_id=req.client_order_id,
                venue_order_id="venue-1",
                status=OrderState.PARTIALLY_FILLED,
                observed_at=datetime(2026, 9, 30, 15, 1, tzinfo=UTC),
            ),
        )
        if mutation.startswith("correction"):
            await ledger.record_fill_correction(
                created.order_id,
                FillCorrection(
                    venue=req.venue,
                    account_id=req.account_id,
                    execution_id="mutation-execution",
                    correction_id="mutation-correction",
                    revision=1,
                    revised_quantity=Decimal("0.2"),
                    revised_price=Decimal("1.1"),
                    occurred_at=datetime(2026, 9, 30, 15, 2, tzinfo=UTC),
                ),
            )
        async with sessions() as session:
            if mutation == "order_digest":
                statement = update(OmsOrderRow).values(request_digest="0" * 64)
            elif mutation == "order_state":
                statement = update(OmsOrderRow).values(state="NOT_A_STATE")
            elif mutation == "event_sequence":
                statement = update(OmsEventRow).where(OmsEventRow.sequence == 1).values(sequence=99)
            elif mutation == "event_code":
                statement = (
                    update(OmsEventRow)
                    .where(OmsEventRow.sequence == 1)
                    .values(code="NOT_A_CODE")
                )
            elif mutation == "fill_quantity":
                statement = update(OmsFillRow).values(quantity="2")
            elif mutation == "fill_scope":
                statement = update(OmsFillRow).values(account_id="other-account")
            elif mutation == "correction_revision":
                statement = update(OmsFillCorrectionRow).values(revision=3)
            elif mutation == "correction_price":
                statement = update(OmsFillCorrectionRow).values(revised_price="-1")
            else:
                persisted = await session.scalar(
                    select(OmsObservationRow).where(OmsObservationRow.order_id == created.order_id)
                )
                assert persisted is not None
                changed = dict(persisted.evidence)
                changed["status" if mutation == "observation_status" else "account_id"] = (
                    "NOT_A_STATUS" if mutation == "observation_status" else "other-account"
                )
                statement = update(OmsObservationRow).values(evidence=changed)
            await session.execute(statement)
            await session.commit()
        with pytest.raises(OMSLedgerCorruption) as failure:
            await ledger.get(created.order_id)
        assert failure.value.code == "OMS_LEDGER_CORRUPT"
        assert failure.value.args == ("OMS_LEDGER_CORRUPT",)
        next_req = replace(req, client_order_id=f"next-{case}")
        with pytest.raises(OMSLedgerCorruption):
            await ledger.create(next_req)
        await engine.dispose()


async def test_seeded_every_oms_column_mutation_blocks_dispatch(tmp_path: Path) -> None:
    """Every persisted column is authenticated, including valid enum changes."""
    source = tmp_path / "authenticated-source.db"
    engine, sessions = create_engine_and_sessionmaker(f"sqlite+aiosqlite:///{source}")
    await init_schema(engine)
    ledger = OrderLedger(sessions, key=_INTEGRITY_KEY)
    req = request()
    first = await ledger.create(req)
    await ledger.mark_submitting(first.order_id, evidence(first.order_id, req))
    await ledger.mark_submit_result(first.order_id, OrderState.WORKING, "venue-1")
    await ledger.record_fill(
        first.order_id,
        Fill(req.venue, req.account_id, "fuzz-fill", Decimal("0.25"),
             Decimal("1.2"), datetime(2026, 9, 30, 15, tzinfo=UTC)),
    )
    await ledger.record_fill_correction(
        first.order_id,
        FillCorrection(req.venue, req.account_id, "fuzz-fill", "fuzz-correction", 1,
                       Decimal("0.2"), Decimal("1.1"),
                       datetime(2026, 9, 30, 15, 1, tzinfo=UTC)),
    )
    await ledger.record_observation(
        first.order_id,
        BrokerObservation("fuzz-observation", req.environment, req.account_id,
                          req.venue, req.client_order_id, OrderState.PARTIALLY_FILLED,
                          datetime(2026, 9, 30, 15, 2, tzinfo=UTC), "venue-1"),
    )
    second_req = replace(req, client_order_id="fuzz-second")
    second = await ledger.create(second_req)
    await engine.dispose()

    models = (OmsOrderRow, OmsEventRow, OmsFillRow, OmsFillCorrectionRow,
              OmsObservationRow, OmsLedgerHeadRow)
    columns = [(model, column.name) for model in models for column in model.__table__.columns]
    random.Random(960401).shuffle(columns)
    for number, (model, name) in enumerate(columns):
        target = tmp_path / f"authenticated-{number}.db"
        shutil.copyfile(source, target)
        test_engine, test_sessions = create_engine_and_sessionmaker(
            f"sqlite+aiosqlite:///{target}"
        )
        async with test_sessions() as session:
            if model is OmsLedgerHeadRow:
                row = await session.get(model, (req.environment, req.account_id))
            else:
                row = await session.scalar(
                    select(model).where(model.order_id == first.order_id)
                )
            assert row is not None
            original = getattr(row, name)
            if isinstance(original, datetime):
                changed = original + timedelta(seconds=1)
            elif type(original) is bool:
                changed = not original
            elif type(original) is int:
                changed = original + 10_000
            elif isinstance(original, dict):
                changed = dict(original)
                if "status" in changed:
                    changed["status"] = OrderState.CANCELED.value
                elif "actor_id" in changed:
                    changed["actor_id"] = "alternate-actor"
                elif "request_digest" in changed:
                    changed["request_digest"] = "f" * 64
                else:
                    changed["extra"] = "valid-json"
            elif isinstance(original, list):
                changed = [*original, "BROKER_STATE_DIVERGENCE"]
            elif original is None:
                changed = "alternate-id"
            elif name == "state":
                changed = OrderState.CANCELED.value
            elif name == "code":
                changed = "BROKER_RECONCILIATION"
            elif name == "environment":
                changed = "paper"
            elif isinstance(original, str) and len(original) == 64 and all(
                character in "0123456789abcdef" for character in original
            ):
                changed = ("f" if original[0] != "f" else "e") + original[1:]
            elif name in {"quantity", "price", "commission", "revised_quantity",
                          "revised_price", "revised_commission"}:
                changed = "1.3" if original != "1.3" else "1.4"
            else:
                changed = f"alternate-{original}"
            assert changed != original
            await session.execute(
                update(model).where(
                    model.id == row.id if model not in (OmsOrderRow, OmsLedgerHeadRow)
                    else model.order_id == first.order_id if model is OmsOrderRow
                    else (model.environment == req.environment) &
                         (model.account_id == req.account_id)
                ).values({name: changed})
            )
            await session.commit()
        reopened = OrderLedger(test_sessions, key=_INTEGRITY_KEY)
        with pytest.raises(OMSLedgerCorruption) as failure:
            await reopened.mark_submitting(second.order_id, evidence(second.order_id, second_req))
        assert failure.value.code == "OMS_LEDGER_CORRUPT", (model.__tablename__, name)
        await test_engine.dispose()


async def test_v3_additive_migration_leaves_legacy_rows_closed(tmp_path: Path) -> None:
    database = tmp_path / "legacy-v2.db"
    engine, sessions = create_engine_and_sessionmaker(f"sqlite+aiosqlite:///{database}")
    await init_schema(engine)
    ledger = OrderLedger(sessions, key=_INTEGRITY_KEY)
    created = await ledger.create(request())
    async with engine.begin() as connection:
        await connection.execute(text("DROP TABLE oms_ledger_heads"))
        await connection.execute(text("ALTER TABLE oms_orders DROP COLUMN chain"))
        for table in (
            "oms_order_events", "oms_fills", "oms_fill_corrections", "oms_observations"
        ):
            await connection.execute(text(f"ALTER TABLE {table} DROP COLUMN chain"))
            await connection.execute(text(f"ALTER TABLE {table} DROP COLUMN ledger_sequence"))
        await connection.execute(text("DELETE FROM schema_migrations WHERE version = 3"))
    await init_schema(engine)
    with pytest.raises(OMSLedgerCorruption, match="OMS_LEDGER_CORRUPT"):
        await ledger.get(created.order_id)
    async with sessions() as session:
        assert (await session.scalars(select(SchemaMigrationRow.version))).all() == [1, 2, 3, 4, 5]
    await engine.dispose()
