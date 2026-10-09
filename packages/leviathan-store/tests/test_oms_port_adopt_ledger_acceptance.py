"""Independent persistence acceptance for BrokerPortV1 execution replay."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Literal

import pytest
from leviathan_store.engine import create_engine_and_sessionmaker, init_schema
from leviathan_store.oms_ledger import open_order_gateway_actor
from leviathan_store.tables import OmsFillRow
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncEngine

from leviathan_core.execution.broker_port import BrokerVenue, FakeBrokerPort, FakeSubmitResult
from leviathan_core.execution.broker_port_v1 import (
    BrokerPortV1,
    _issue_account_view,
    _issue_execution,
)
from leviathan_core.execution.broker_reconciliation import FakeBrokerReconciliation
from leviathan_core.execution.oms import DispatchGate, DispatchGateCode, OrderGatewayActor
from leviathan_core.execution.order_models import (
    BrokerObservation,
    ClientIdKey,
    LedgerIntegrityKey,
    OMSValidationError,
    OrderRequest,
    OrderSnapshot,
    OrderState,
    PaperDispatchEvidence,
)

pytestmark = pytest.mark.asyncio

_ACCOUNT = "oms-port-demo-account"
_NOW = datetime(2026, 10, 5, 16, 0, tzinfo=UTC)
_LEDGER_KEY = LedgerIntegrityKey(b"oms-port-adopt-store-ledger-key-32byte")
_CLIENT_KEY = ClientIdKey(b"oms-port-adopt-store-client-key-32-bytes")


def _request(
    intent: str = "oms-port-store-intent",
    *,
    venue: BrokerVenue = BrokerVenue.ALPACA,
    environment: str = "demo",
) -> OrderRequest:
    return OrderRequest(
        project_id="leviathan-ai",
        environment=environment,
        account_id=_ACCOUNT,
        venue=venue.value,
        instrument_id="EURUSD",
        native_contract_id="demo-EURUSD",
        side="BUY",
        quantity=Decimal("1"),
        order_type="LIMIT",
        time_in_force="DAY",
        client_order_id=None,
        intent_idempotency_key=intent,
        attempt=1,
        strategy_id="oms-port-store-acceptance",
        risk_policy_digest="e" * 64,
        actor_id="synthetic-operator",
        capability=f"{environment}-submit",
        limit_price=Decimal("1.1"),
    )


def _evidence(order: OrderSnapshot) -> PaperDispatchEvidence:
    request = order.request
    return PaperDispatchEvidence(
        order_id=order.order_id,
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


async def _open(
    database: Path,
    memory: FakeBrokerReconciliation,
    dispatch_gate: DispatchGate | None = None,
    venue: BrokerVenue = BrokerVenue.ALPACA,
    environment: str = "demo",
) -> tuple[OrderGatewayActor, FakeBrokerPort, AsyncEngine]:
    engine, sessions = create_engine_and_sessionmaker(
        f"sqlite+aiosqlite:///{database}"
    )
    await init_schema(engine)
    broker = FakeBrokerPort(
        memory, account_id=_ACCOUNT, environment=environment, venue=venue
    )
    assert isinstance(broker, BrokerPortV1)
    actor = open_order_gateway_actor(
        sessions,
        broker,
        memory,
        _CLIENT_KEY,
        ledger_key=_LEDGER_KEY,
        dispatch_gate=dispatch_gate,
        allow_in_memory=True,
    )
    return actor, broker, engine


def _partial_fill_observation(
    order: OrderSnapshot, memory: FakeBrokerReconciliation, observation_id: str
) -> BrokerObservation:
    return BrokerObservation(
        observation_id=observation_id,
        environment=order.request.environment,
        account_id=order.request.account_id,
        venue=order.request.venue,
        client_order_id=order.request.client_order_id or "",
        status=OrderState.PARTIALLY_FILLED,
        observed_at=_NOW,
        venue_order_id=order.venue_order_id,
        broker_sequence=memory.snapshot_account(_ACCOUNT).revision,
    )


class _FixedGate:
    def __init__(self, submit_code: DispatchGateCode, cancel_code: DispatchGateCode):
        self.submit_code = submit_code
        self.cancel_code = cancel_code

    def check(
        self, action: Literal["SUBMIT", "CANCEL"], _scope: OrderSnapshot
    ) -> DispatchGateCode:
        return self.submit_code if action == "SUBMIT" else self.cancel_code


async def _submitted_order_with_fill(
    database: Path, memory: FakeBrokerReconciliation, intent: str
) -> tuple[OrderGatewayActor, FakeBrokerPort, AsyncEngine, OrderSnapshot]:
    actor, broker, engine = await _open(database, memory)
    broker.queue_submit(FakeSubmitResult(f"venue-{intent}"))
    created = await actor.create(_request(intent))
    working = await actor.submit(created.order_id, _evidence(created))
    assert working.state is OrderState.WORKING
    broker.record_execution(
        created.request.client_order_id or "",
        "cycle1-shared-execution",
        Decimal("0.25"),
        Decimal("1.1"),
        _NOW,
    )
    broker.queue_observation(
        _partial_fill_observation(working, memory, f"{intent}-partial-observation")
    )
    filled = await actor.reconcile(created.order_id)
    assert filled.state is OrderState.PARTIALLY_FILLED
    assert filled.filled_quantity == Decimal("0.25")
    return actor, broker, engine, filled


def _queue_execution_view_mutation(
    order: OrderSnapshot,
    broker: FakeBrokerPort,
    *,
    field: str,
    value: object,
) -> None:
    original_view = broker.read_account_view(order.request.account_id)
    original = original_view.executions[0]
    instrument_id = original.instrument_id
    side = original.side
    quantity = original.quantity
    price = original.price
    executed_at = original.executed_at
    if field == "instrument":
        instrument_id = str(value)
    elif field == "side":
        side = str(value)
    elif field == "quantity":
        quantity = Decimal(value)  # type: ignore[arg-type]
    elif field == "price":
        price = Decimal(value)  # type: ignore[arg-type]
    elif field == "executed_at":
        executed_at = value  # type: ignore[assignment]
    else:
        raise AssertionError(f"unsupported execution mutation: {field}")
    changed = _issue_execution(
        original.execution_id,
        original.venue_order_id,
        original.client_order_id,
        instrument_id,
        side,
        quantity,
        price,
        executed_at,
    )
    signed_quantity = quantity if side == "BUY" else -quantity
    broker.queue_account_view(
        _issue_account_view(
            order.request.account_id,
            original_view.open_orders,
            ((instrument_id, signed_quantity),),
            original_view.broker_revision,
            (changed,),
            original_view.executions_since,
            complete=True,
        )
    )


async def test_execution_dedup_survives_actor_restart(tmp_path: Path) -> None:
    database = tmp_path / "v1-execution-restart.db"
    memory = FakeBrokerReconciliation()
    actor, broker, engine = await _open(database, memory)
    try:
        broker.queue_submit(FakeSubmitResult("venue-order-demo-1"))
        created = await actor.create(_request())
        await actor.submit(created.order_id, _evidence(created))
        broker.record_execution(
            created.request.client_order_id or "",
            "execution-stable-id",
            Decimal("0.4"),
            Decimal("1.1"),
            _NOW,
        )
        broker.queue_observation(
            _partial_fill_observation(created, memory, "initial-partial-fill")
        )
        first = await actor.reconcile(created.order_id)
        assert first.state is OrderState.PARTIALLY_FILLED
        assert first.filled_quantity == Decimal("0.4")
    finally:
        await actor.close()
        await engine.dispose()

    reopened, _reopened_broker, reopened_engine = await _open(database, memory)
    try:
        await reopened.recover_uncertain()
        _reopened_broker.queue_observation(
            _partial_fill_observation(created, memory, "replayed-partial-fill")
        )
        replayed = await reopened.reconcile(created.order_id)
        assert replayed.state is OrderState.PARTIALLY_FILLED
        assert replayed.filled_quantity == Decimal("0.4")
        async with reopened_engine.connect() as connection:
            result = await connection.execute(
                select(func.count()).select_from(OmsFillRow).where(
                    OmsFillRow.order_id == created.order_id,
                    OmsFillRow.execution_id == "execution-stable-id",
                )
            )
        assert result.scalar_one() == 1
    finally:
        await reopened.close()
        await reopened_engine.dispose()


async def test_submit_gate_denial_snapshot_and_event_survive_restart(
    tmp_path: Path,
) -> None:
    database = tmp_path / "v1-gate-denial.db"
    memory = FakeBrokerReconciliation()
    gate = _FixedGate(DispatchGateCode.DENY_HALT, DispatchGateCode.ALLOW)
    actor, broker, engine = await _open(database, memory, gate)
    try:
        created = await actor.create(_request())
        denied = await actor.submit(created.order_id, _evidence(created))
        assert denied.state is OrderState.REJECTED_HALTED
        assert broker.submit_calls == 0
        events = await actor._ledger.events(created.order_id)
        assert any(
            event["code"] == "DISPATCH_GATE_DENIED"
            and event["evidence"].get("reason") == "DENY_HALT"
            for event in events
        )
    finally:
        await actor.close()
        await engine.dispose()

    reopened, reopened_broker, reopened_engine = await _open(
        database, memory, gate
    )
    try:
        persisted = await reopened.get(created.order_id)
        assert persisted.state is OrderState.REJECTED_HALTED
        assert reopened_broker.submit_calls == 0
        events = await reopened._ledger.events(created.order_id)
        assert any(event["code"] == "DISPATCH_GATE_DENIED" for event in events)
    finally:
        await reopened.close()
        await reopened_engine.dispose()


async def test_cancel_scope_gate_denial_is_durable_and_never_calls_fake(
    tmp_path: Path,
) -> None:
    database = tmp_path / "v1-cancel-gate-denial.db"
    memory = FakeBrokerReconciliation()
    gate = _FixedGate(DispatchGateCode.ALLOW, DispatchGateCode.DENY_SCOPE)
    actor, broker, engine = await _open(database, memory, gate)
    try:
        broker.queue_submit(FakeSubmitResult("venue-order-scope-gate"))
        created = await actor.create(_request())
        await actor.submit(created.order_id, _evidence(created))
        denied = await actor.cancel(created.order_id)
        assert denied.state is OrderState.RECONCILE_REQUIRED
        assert "GATE_DENIED_CANCEL" in denied.discrepancies
        assert broker.cancel_calls == 0
    finally:
        await actor.close()
        await engine.dispose()

    reopened, reopened_broker, reopened_engine = await _open(
        database, memory, gate
    )
    try:
        persisted = await reopened.get(created.order_id)
        assert persisted.state is OrderState.RECONCILE_REQUIRED
        assert "GATE_DENIED_CANCEL" in persisted.discrepancies
        assert reopened_broker.cancel_calls == 0
        events = await reopened._ledger.events(created.order_id)
        assert any(event["code"] == "DISPATCH_GATE_DENIED" for event in events)
    finally:
        await reopened.close()
        await reopened_engine.dispose()


async def test_reopened_wrong_venue_quarantines_before_import_and_blocks_account(
    tmp_path: Path,
) -> None:
    database = tmp_path / "venue-swap-after-restart.db"
    memory = FakeBrokerReconciliation()
    actor, broker, engine = await _open(database, memory)
    try:
        broker.queue_submit(FakeSubmitResult("venue-alpaca-original"))
        created = await actor.create(_request("venue-swap-original"))
        working = await actor.submit(created.order_id, _evidence(created))
        assert working.state is OrderState.WORKING
        broker.record_execution(
            created.request.client_order_id or "",
            "venue-swap-execution",
            Decimal("0.4"),
            Decimal("1.1"),
            _NOW,
        )
    finally:
        await actor.close()
        await engine.dispose()

    reopened, ibkr_broker, reopened_engine = await _open(
        database, memory, venue=BrokerVenue.IBKR_TWS
    )
    try:
        quarantined = await reopened.reconcile(created.order_id)
        assert quarantined.state is OrderState.RECONCILE_REQUIRED
        assert "VENUE_ACCOUNT_CONFLICT" in quarantined.discrepancies
        assert quarantined.filled_quantity == 0
        events = await reopened._ledger.events(created.order_id)
        assert any(event["code"] == "VENUE_ACCOUNT_CONFLICT" for event in events)
        async with reopened_engine.connect() as connection:
            count = await connection.scalar(
                select(func.count()).select_from(OmsFillRow).where(
                    OmsFillRow.order_id == created.order_id
                )
            )
        assert count == 0

        another = await reopened.create(
            _request("venue-swap-account-block", venue=BrokerVenue.IBKR_TWS)
        )
        with pytest.raises(OMSValidationError) as blocked:
            await reopened.submit(another.order_id, _evidence(another))
        assert blocked.value.code == "ACCOUNT_RECONCILE_REQUIRED"
        assert ibkr_broker.submit_calls == 0
    finally:
        await reopened.close()
        await reopened_engine.dispose()


async def test_wrong_venue_working_order_blocks_submit_after_restart_without_reconcile(
    tmp_path: Path,
) -> None:
    database = tmp_path / "venue-swap-no-fill-before-submit.db"
    memory = FakeBrokerReconciliation()
    actor, broker, engine = await _open(database, memory)
    try:
        broker.queue_submit(FakeSubmitResult("venue-alpaca-no-fill"))
        original = await actor.create(_request("venue-swap-no-fill-original"))
        working = await actor.submit(original.order_id, _evidence(original))
        assert working.state is OrderState.WORKING
        assert working.filled_quantity == 0
    finally:
        await actor.close()
        await engine.dispose()

    reopened, ibkr_broker, reopened_engine = await _open(
        database, memory, venue=BrokerVenue.IBKR_TWS
    )
    try:
        candidate = await reopened.create(
            _request("venue-swap-no-fill-candidate", venue=BrokerVenue.IBKR_TWS)
        )
        with pytest.raises(OMSValidationError):
            await reopened.submit(candidate.order_id, _evidence(candidate))

        quarantined = await reopened.get(original.order_id)
        assert quarantined.state is OrderState.RECONCILE_REQUIRED
        assert "VENUE_ACCOUNT_CONFLICT" in quarantined.discrepancies
        assert quarantined.filled_quantity == 0
        events = await reopened._ledger.events(original.order_id)
        assert any(event["code"] == "VENUE_ACCOUNT_CONFLICT" for event in events)
        assert ibkr_broker.submit_calls == 0
    finally:
        await reopened.close()
        await reopened_engine.dispose()


async def test_wrong_venue_sealed_open_order_quarantines_before_submit(
    tmp_path: Path,
) -> None:
    database = tmp_path / "wrong-venue-open-order-image.db"
    memory = FakeBrokerReconciliation()
    actor, broker, engine = await _open(database, memory)
    try:
        broker.queue_submit(FakeSubmitResult("venue-open-order-original"))
        original = await actor.create(_request("wrong-venue-open-original"))
        working = await actor.submit(original.order_id, _evidence(original))
        assert working.state is OrderState.WORKING

        account_view = broker.read_account_view(_ACCOUNT)
        assert len(account_view.open_orders) == 1
        known = account_view.open_orders[0]
        wrong_venue = "IBKR_TWS" if known.venue != "IBKR_TWS" else "ALPACA"
        mismatched = BrokerObservation(
            observation_id="wrong-venue-open-order-observation",
            environment=known.environment,
            account_id=known.account_id,
            venue=wrong_venue,
            client_order_id=known.client_order_id,
            status=known.status,
            observed_at=known.observed_at,
            venue_order_id=known.venue_order_id,
            broker_sequence=known.broker_sequence,
        )
        broker.queue_account_view(
            _issue_account_view(
                _ACCOUNT,
                (mismatched,),
                account_view.positions,
                account_view.broker_revision,
                account_view.executions,
                account_view.executions_since,
                complete=True,
            )
        )
        candidate = await actor.create(_request("wrong-venue-open-candidate"))
        calls_before = broker.submit_calls
        with pytest.raises(OMSValidationError):
            await actor.submit(candidate.order_id, _evidence(candidate))

        quarantined = await actor.get(original.order_id)
        assert quarantined.state is OrderState.RECONCILE_REQUIRED
        assert "VENUE_ACCOUNT_CONFLICT" in quarantined.discrepancies
        events = await actor._ledger.events(original.order_id)
        assert any(event["code"] == "VENUE_ACCOUNT_CONFLICT" for event in events)
        assert broker.submit_calls == calls_before
    finally:
        await actor.close()
        await engine.dispose()


async def test_wrong_venue_observation_without_reference_order_is_durable_conflict(
    tmp_path: Path,
) -> None:
    database = tmp_path / "wrong-venue-observation-without-reference.db"
    original_memory = FakeBrokerReconciliation()
    actor, broker, engine = await _open(database, original_memory)
    try:
        broker.queue_submit(FakeSubmitResult("venue-reference-order"))
        original = await actor.create(_request("wrong-venue-reference-order"))
        working = await actor.submit(original.order_id, _evidence(original))
        assert working.state is OrderState.WORKING
    finally:
        await actor.close()
        await engine.dispose()

    empty_memory = FakeBrokerReconciliation()
    reopened, reopened_broker, reopened_engine = await _open(
        database, empty_memory
    )
    try:
        conflicting_observation = BrokerObservation(
            observation_id="wrong-venue-unmatched-observation",
            environment=original.request.environment,
            account_id=original.request.account_id,
            venue="IBKR_TWS",
            client_order_id=original.request.client_order_id or "",
            status=OrderState.WORKING,
            observed_at=_NOW,
            venue_order_id=original.venue_order_id,
            broker_sequence=0,
        )
        reopened_broker.queue_account_view(
            _issue_account_view(
                _ACCOUNT,
                (conflicting_observation,),
                (),
                0,
                (),
                _NOW,
                complete=True,
            )
        )
        candidate = await reopened.create(
            _request("wrong-venue-unmatched-candidate")
        )
        with pytest.raises(OMSValidationError):
            await reopened.submit(candidate.order_id, _evidence(candidate))

        quarantined = await reopened.get(original.order_id)
        assert quarantined.state is OrderState.RECONCILE_REQUIRED
        assert "VENUE_ACCOUNT_CONFLICT" in quarantined.discrepancies
        events = await reopened._ledger.events(original.order_id)
        assert any(event["code"] == "VENUE_ACCOUNT_CONFLICT" for event in events)
        assert reopened_broker.submit_calls == 0
    finally:
        await reopened.close()
        await reopened_engine.dispose()


async def test_wrong_venue_observation_linked_to_second_order_marks_both_orders(
    tmp_path: Path,
) -> None:
    database = tmp_path / "linked-wrong-venue-observation.db"
    memory = FakeBrokerReconciliation()
    actor, broker, engine = await _open(database, memory)
    try:
        broker.queue_submit(
            FakeSubmitResult("venue-first-rejected", OrderState.REJECTED)
        )
        first = await actor.create(_request("linked-observation-first"))
        rejected = await actor.submit(first.order_id, _evidence(first))
        assert rejected.state is OrderState.REJECTED

        broker.queue_submit(FakeSubmitResult("venue-second-working"))
        second = await actor.create(_request("linked-observation-second"))
        working = await actor.submit(second.order_id, _evidence(second))
        assert working.state is OrderState.WORKING

        account_view = broker.read_account_view(_ACCOUNT)
        known = next(
            item for item in account_view.open_orders
            if item.client_order_id == second.request.client_order_id
        )
        conflicting = BrokerObservation(
            observation_id="linked-wrong-venue-observation",
            environment=known.environment,
            account_id=known.account_id,
            venue="IBKR_TWS",
            client_order_id=second.request.client_order_id or "",
            status=known.status,
            observed_at=known.observed_at,
            venue_order_id=second.venue_order_id,
            broker_sequence=known.broker_sequence,
        )
        broker.queue_account_view(
            _issue_account_view(
                _ACCOUNT,
                (conflicting,),
                account_view.positions,
                account_view.broker_revision,
                account_view.executions,
                account_view.executions_since,
                complete=True,
            )
        )
        submits_before = broker.submit_calls
        cancels_before = broker.cancel_calls
        try:
            await actor.reconcile(second.order_id)
        except OMSValidationError as error:
            assert error.code == "VENUE_ACCOUNT_CONFLICT"

        first_after = await actor.get(first.order_id)
        second_after = await actor.get(second.order_id)
        assert first_after.state is OrderState.REJECTED
        assert "VENUE_ACCOUNT_CONFLICT" in first_after.discrepancies
        assert second_after.state is OrderState.RECONCILE_REQUIRED
        assert "VENUE_ACCOUNT_CONFLICT" in second_after.discrepancies
        assert broker.submit_calls == submits_before
        assert broker.cancel_calls == cancels_before
    finally:
        await actor.close()
        await engine.dispose()


async def test_unlinked_wrong_venue_observation_marks_first_binding_and_blocks_submit(
    tmp_path: Path,
) -> None:
    database = tmp_path / "unlinked-wrong-venue-observation.db"
    memory = FakeBrokerReconciliation()
    actor, broker, engine = await _open(database, memory)
    try:
        broker.queue_submit(
            FakeSubmitResult("venue-unlinked-first-rejected", OrderState.REJECTED)
        )
        first = await actor.create(_request("unlinked-observation-first"))
        rejected = await actor.submit(first.order_id, _evidence(first))
        assert rejected.state is OrderState.REJECTED

        broker.queue_submit(FakeSubmitResult("venue-unlinked-second-working"))
        second = await actor.create(_request("unlinked-observation-second"))
        working = await actor.submit(second.order_id, _evidence(second))
        assert working.state is OrderState.WORKING

        account_view = broker.read_account_view(_ACCOUNT)
        known = next(
            item for item in account_view.open_orders
            if item.client_order_id == second.request.client_order_id
        )
        unlinked = BrokerObservation(
            observation_id="unlinked-wrong-venue-observation",
            environment=known.environment,
            account_id=known.account_id,
            venue="IBKR_TWS",
            client_order_id="unknown-broker-client-id",
            status=OrderState.WORKING,
            observed_at=known.observed_at,
            venue_order_id="unknown-broker-order-id",
            broker_sequence=known.broker_sequence,
        )
        broker.queue_account_view(
            _issue_account_view(
                _ACCOUNT,
                (unlinked,),
                account_view.positions,
                account_view.broker_revision,
                account_view.executions,
                account_view.executions_since,
                complete=True,
            )
        )
        submits_before = broker.submit_calls
        try:
            await actor.reconcile(second.order_id)
        except OMSValidationError as error:
            assert error.code == "VENUE_ACCOUNT_CONFLICT"

        first_after = await actor.get(first.order_id)
        second_after = await actor.get(second.order_id)
        assert first_after.state is OrderState.REJECTED
        assert "VENUE_ACCOUNT_CONFLICT" in first_after.discrepancies
        assert second_after.state is OrderState.WORKING
        assert "VENUE_ACCOUNT_CONFLICT" not in second_after.discrepancies

        candidate = await actor.create(_request("unlinked-observation-candidate"))
        with pytest.raises(OMSValidationError):
            await actor.submit(candidate.order_id, _evidence(candidate))
        assert broker.submit_calls == submits_before
    finally:
        await actor.close()
        await engine.dispose()


async def test_terminal_historical_order_binds_account_venue_across_restart(
    tmp_path: Path,
) -> None:
    database = tmp_path / "terminal-venue-binding-after-restart.db"
    memory = FakeBrokerReconciliation()
    actor, broker, engine = await _open(database, memory)
    try:
        broker.queue_submit(
            FakeSubmitResult("venue-alpaca-terminal", OrderState.REJECTED)
        )
        historical = await actor.create(_request("venue-binding-terminal-history"))
        rejected = await actor.submit(historical.order_id, _evidence(historical))
        assert rejected.state is OrderState.REJECTED
    finally:
        await actor.close()
        await engine.dispose()

    reopened, ibkr_broker, reopened_engine = await _open(
        database, memory, venue=BrokerVenue.IBKR_TWS
    )
    try:
        candidate = await reopened.create(
            _request("venue-binding-terminal-candidate", venue=BrokerVenue.IBKR_TWS)
        )
        with pytest.raises(OMSValidationError):
            await reopened.submit(candidate.order_id, _evidence(candidate))

        preserved = await reopened.get(historical.order_id)
        assert preserved.state is OrderState.REJECTED
        assert "VENUE_ACCOUNT_CONFLICT" in preserved.discrepancies
        events = await reopened._ledger.events(historical.order_id)
        assert any(event["code"] == "VENUE_ACCOUNT_CONFLICT" for event in events)
        assert ibkr_broker.submit_calls == 0
    finally:
        await reopened.close()
        await reopened_engine.dispose()


async def test_account_binding_rejects_cross_environment_historical_order(
    tmp_path: Path,
) -> None:
    database = tmp_path / "environment-binding-after-restart.db"
    memory = FakeBrokerReconciliation()
    actor, broker, engine = await _open(
        database, memory, environment="paper"
    )
    try:
        broker.queue_submit(FakeSubmitResult("venue-paper-historical"))
        historical = await actor.create(
            _request("environment-binding-paper-history", environment="paper")
        )
        working = await actor.submit(
            historical.order_id, _evidence(historical)
        )
        assert working.state is OrderState.WORKING
    finally:
        await actor.close()
        await engine.dispose()

    reopened, demo_broker, reopened_engine = await _open(
        database, memory, environment="demo"
    )
    try:
        candidate = await reopened.create(
            _request("environment-binding-demo-candidate", environment="demo")
        )
        with pytest.raises(OMSValidationError):
            await reopened.submit(candidate.order_id, _evidence(candidate))

        quarantined = await reopened.get(historical.order_id)
        assert quarantined.state is OrderState.RECONCILE_REQUIRED
        assert "VENUE_ACCOUNT_CONFLICT" in quarantined.discrepancies
        events = await reopened._ledger.events(historical.order_id)
        assert any(event["code"] == "VENUE_ACCOUNT_CONFLICT" for event in events)
        assert demo_broker.submit_calls == 0
    finally:
        await reopened.close()
        await reopened_engine.dispose()


async def test_changed_price_same_execution_id_quarantines_before_next_submit(
    tmp_path: Path,
) -> None:
    database = tmp_path / "changed-execution-before-submit.db"
    memory = FakeBrokerReconciliation()
    actor, broker, engine = await _open(database, memory)
    try:
        broker.queue_submit(FakeSubmitResult("venue-exact-execution"))
        first = await actor.create(_request("exact-execution-first"))
        working = await actor.submit(first.order_id, _evidence(first))
        broker.record_execution(
            first.request.client_order_id or "",
            "changed-price-shared-execution",
            Decimal("0.25"),
            Decimal("1.1"),
            _NOW,
        )
        broker.queue_observation(
            _partial_fill_observation(working, memory, "exact-first-fill-observation")
        )
        accepted = await actor.reconcile(first.order_id)
        assert accepted.filled_quantity == Decimal("0.25")

        _queue_execution_view_mutation(
            accepted,
            broker,
            field="price",
            value=Decimal("1.2"),
        )
        second = await actor.create(_request("exact-execution-second"))
        with pytest.raises(OMSValidationError) as conflict:
            await actor.submit(second.order_id, _evidence(second))
        assert conflict.value.code == "BROKER_EXECUTION_CONFLICT"

        quarantined = await actor.get(first.order_id)
        assert quarantined.state is OrderState.RECONCILE_REQUIRED
        assert "BROKER_EXECUTION_CONFLICT" in quarantined.discrepancies
        assert quarantined.filled_quantity == Decimal("0.25")
        assert broker.submit_calls == 1
        events = await actor._ledger.events(first.order_id)
        assert any(
            event["code"] == "BROKER_EXECUTION_CONFLICT" for event in events
        )
    finally:
        await actor.close()
        await engine.dispose()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("instrument", "MSFT"),
        ("side", "SELL"),
        ("price", Decimal("1.2")),
        ("quantity", Decimal("0.5")),
        ("executed_at", _NOW + timedelta(seconds=1)),
    ],
)
async def test_execution_scope_or_same_id_conflict_quarantines_without_overwrite(
    tmp_path: Path, field: str, value: object
) -> None:
    intent = f"execution-conflict-{field}"
    memory = FakeBrokerReconciliation()
    actor, broker, engine, filled = await _submitted_order_with_fill(
        tmp_path / f"execution-conflict-{field}.db", memory, intent
    )
    try:
        _queue_execution_view_mutation(
            filled, broker, field=field, value=value
        )
        broker.queue_observation(
            _partial_fill_observation(
                filled, memory, f"changed-{field}-observation"
            )
        )

        quarantined = await actor.reconcile(filled.order_id)
        assert quarantined.state is OrderState.RECONCILE_REQUIRED
        assert "BROKER_EXECUTION_CONFLICT" in quarantined.discrepancies
        assert quarantined.filled_quantity == Decimal("0.25")
        events = await actor._ledger.events(filled.order_id)
        assert any(event["code"] == "BROKER_EXECUTION_CONFLICT" for event in events)

        later = await actor.create(_request(f"blocked-after-{field}"))
        with pytest.raises(OMSValidationError):
            await actor.submit(later.order_id, _evidence(later))
        assert broker.submit_calls == 1
        assert (await actor.get(filled.order_id)).filled_quantity == Decimal("0.25")
    finally:
        await actor.close()
        await engine.dispose()
