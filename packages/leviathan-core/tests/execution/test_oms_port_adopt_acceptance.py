"""Independent acceptance of the OMS actor's BrokerPortV1 adoption."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from leviathan_store.engine import create_engine_and_sessionmaker, init_schema
from leviathan_store.oms_ledger import open_order_gateway_actor
from sqlalchemy.ext.asyncio import AsyncEngine

from leviathan_core.execution.broker_port import (
    BrokerVenue,
    FakeBrokerPort,
    FakeCancelResult,
    FakeDispatchPermit,
    FakeSubmitResult,
)
from leviathan_core.execution.broker_port_v1 import (
    BrokerOutcomeUnknown,
    BrokerPortV1,
    BrokerRejected,
    BrokerRejectionCode,
    BrokerUnknownCode,
    SubmitResultV1,
)
from leviathan_core.execution.broker_reconciliation import FakeBrokerReconciliation
from leviathan_core.execution.oms import (
    DispatchGate,
    DispatchGateCode,
    OrderGatewayActor,
)
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

_NOW = datetime(2026, 10, 5, 16, 0, tzinfo=UTC)
_ACCOUNT = "oms-port-paper-account"
_LEDGER_KEY = LedgerIntegrityKey(b"oms-port-adopt-acceptance-ledger-key-32")
_CLIENT_KEY = ClientIdKey(b"oms-port-adopt-acceptance-client-key-32")


def _request(
    intent: str = "oms-port-intent", *, venue: str = "ALPACA"
) -> OrderRequest:
    return OrderRequest(
        project_id="leviathan-ai",
        environment="paper",
        account_id=_ACCOUNT,
        venue=venue,
        instrument_id="AAPL",
        native_contract_id="paper-AAPL",
        side="BUY",
        quantity=Decimal("1"),
        order_type="LIMIT",
        time_in_force="DAY",
        client_order_id=None,
        intent_idempotency_key=intent,
        attempt=1,
        strategy_id="oms-port-acceptance-strategy",
        risk_policy_digest="d" * 64,
        actor_id="synthetic-operator",
        capability="paper-submit",
        limit_price=Decimal("100"),
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


def _observation(
    order: OrderSnapshot,
    reconciliation: FakeBrokerReconciliation,
    observation_id: str,
    status: OrderState = OrderState.PARTIALLY_FILLED,
) -> BrokerObservation:
    request = order.request
    return BrokerObservation(
        observation_id=observation_id,
        environment=request.environment,
        account_id=request.account_id,
        venue=request.venue,
        client_order_id=request.client_order_id or "",
        status=status,
        observed_at=_NOW,
        venue_order_id=order.venue_order_id,
        broker_sequence=reconciliation.snapshot_account(_ACCOUNT).revision,
    )


async def _open(
    database: Path,
    memory: FakeBrokerReconciliation | None = None,
    dispatch_gate: DispatchGate | None = None,
) -> tuple[
    OrderGatewayActor, FakeBrokerPort, FakeBrokerReconciliation, AsyncEngine
]:
    engine, sessions = create_engine_and_sessionmaker(
        f"sqlite+aiosqlite:///{database}"
    )
    await init_schema(engine)
    reconciliation = memory or FakeBrokerReconciliation()
    broker = FakeBrokerPort(
        reconciliation, account_id=_ACCOUNT, environment="paper"
    )
    assert isinstance(broker, BrokerPortV1)
    actor = open_order_gateway_actor(
        sessions,
        broker,
        reconciliation,
        _CLIENT_KEY,
        ledger_key=_LEDGER_KEY,
        dispatch_gate=dispatch_gate,
        allow_in_memory=True,
    )
    return actor, broker, reconciliation, engine


async def _close(actor: OrderGatewayActor, engine: AsyncEngine) -> None:
    await actor.close()
    await engine.dispose()


async def test_v1_actor_submit_partial_fill_dedup_cancel_and_permit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    actor, broker, memory, engine = await _open(tmp_path / "v1-roundtrip.db")
    try:
        broker.queue_submit(FakeSubmitResult("venue-order-1"))
        created = await actor.create(_request())

        permit_calls: list[tuple[str, str, int, bool]] = []
        consume_calls: list[tuple[str, str, int]] = []
        acknowledgements: list[type[Any]] = []
        submit = broker.submit
        consume = FakeDispatchPermit.consume

        def record_consumption(
            permit: FakeDispatchPermit, order_id: str, digest: str, revision: int
        ) -> None:
            consume_calls.append((order_id, digest, revision))
            consume(permit, order_id, digest, revision)

        monkeypatch.setattr(FakeDispatchPermit, "consume", record_consumption)

        def record_permit(request: OrderRequest, permit: Any, revision: int) -> Any:
            result = submit(request, permit, revision)
            acknowledgements.append(type(result))
            permit_calls.append(
                (
                    permit.order_id,
                    request.digest,
                    revision,
                    bool(getattr(permit, "_spent", False)),
                )
            )
            return result

        broker.submit = record_permit  # type: ignore[method-assign]
        working = await actor.submit(created.order_id, _evidence(created))
        assert working.state is OrderState.WORKING
        assert broker.submit_calls == 1
        assert acknowledgements == [SubmitResultV1]
        assert permit_calls == [(created.order_id, created.request.digest, 0, True)]
        assert consume_calls == [(created.order_id, created.request.digest, 0)]

        broker.record_execution(
            created.request.client_order_id or "",
            "exec-v1-1",
            Decimal("0.25"),
            Decimal("100"),
            _NOW,
        )
        broker.queue_observation(_observation(working, memory, "partial-observation-1"))
        broker.queue_observation(_observation(working, memory, "partial-observation-2"))
        partial = await actor.reconcile(created.order_id)
        replayed = await actor.reconcile(created.order_id)
        assert partial.state is OrderState.PARTIALLY_FILLED
        assert replayed.filled_quantity == Decimal("0.25")

        broker.queue_cancel(FakeCancelResult(True))
        canceled = await actor.cancel(created.order_id)
        assert canceled.state is OrderState.CANCELED
        assert broker.cancel_calls == 1
    finally:
        await _close(actor, engine)


async def test_v1_unknown_outcomes_persist_and_restart_without_retry(tmp_path: Path) -> None:
    database = tmp_path / "v1-unknown.db"
    memory = FakeBrokerReconciliation()
    actor, broker, memory, engine = await _open(database, memory)
    try:
        broker.queue_submit(
            BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_SUBMIT)
        )
        created = await actor.create(_request("unknown-submit"))
        await actor.submit(created.order_id, _evidence(created))
        assert (await actor.get(created.order_id)).state is OrderState.UNKNOWN_SUBMIT
        assert broker.submit_calls == 1
    finally:
        await _close(actor, engine)

    reopened, reopened_broker, _memory, reopened_engine = await _open(database, memory)
    try:
        await reopened.recover_uncertain()
        assert (await reopened.get(created.order_id)).state is OrderState.UNKNOWN_SUBMIT
        assert reopened_broker.submit_calls == 0
    finally:
        await _close(reopened, reopened_engine)


async def test_v1_broker_rejection_keeps_closed_code(tmp_path: Path) -> None:
    actor, broker, _memory, engine = await _open(tmp_path / "v1-rejected.db")
    try:
        broker.queue_submit(
            BrokerRejected(BrokerRejectionCode.SHORT_SALE_UNSUPPORTED)
        )
        created = await actor.create(_request("rejected"))
        await actor.submit(created.order_id, _evidence(created))
        rejected = await actor.get(created.order_id)
        assert rejected.state is OrderState.REJECTED
        events = await actor._ledger.events(created.order_id)
        assert any(
            event["code"] == "SHORT_SALE_UNSUPPORTED"
            or event["evidence"].get("rejection_code") == "SHORT_SALE_UNSUPPORTED"
            for event in events
        )
    finally:
        await _close(actor, engine)


async def test_wrong_request_venue_is_terminally_rejected_without_transport(
    tmp_path: Path,
) -> None:
    actor, broker, _memory, engine = await _open(
        tmp_path / "v1-venue-mismatch.db"
    )
    try:
        created = await actor.create(_request("wrong-venue", venue="IBKR_TWS"))
        rejected = await actor.submit(created.order_id, _evidence(created))
        assert rejected.state is OrderState.REJECTED
        assert broker.submit_calls == 0
        assert broker.cancel_calls == 0
        events = await actor._ledger.events(created.order_id)
        assert any(
            event["code"] == "VENUE_MISMATCH"
            or event["evidence"].get("reason") == "VENUE_MISMATCH"
            for event in events
        )
    finally:
        await _close(actor, engine)


async def test_cancel_venue_mismatch_quarantines_working_order_without_transport(
    tmp_path: Path,
) -> None:
    actor, broker, memory, engine = await _open(
        tmp_path / "v1-cancel-venue-mismatch.db"
    )
    try:
        broker.queue_submit(FakeSubmitResult("venue-order-cancel-mismatch"))
        created = await actor.create(_request("cancel-venue-mismatch"))
        working = await actor.submit(created.order_id, _evidence(created))
        assert working.state is OrderState.WORKING
        assert broker.submit_calls == 1

        wrong_venue = FakeBrokerPort(
            memory,
            account_id=_ACCOUNT,
            environment="paper",
            venue=BrokerVenue.IBKR_TWS,
        )
        # Simulate the broker binding changing after submit while preserving the
        # actor's exact account and environment scope.
        broker.venue = wrong_venue.venue
        quarantined = await actor.cancel(created.order_id)

        assert quarantined.state is OrderState.RECONCILE_REQUIRED
        assert "VENUE_MISMATCH" in quarantined.discrepancies
        assert broker.cancel_calls == 0
        events = await actor._ledger.events(created.order_id)
        assert any(event["code"] == "VENUE_MISMATCH" for event in events)
    finally:
        await _close(actor, engine)


async def test_v1_unknown_cancel_is_persisted_without_retry(tmp_path: Path) -> None:
    actor, broker, _memory, engine = await _open(tmp_path / "v1-unknown-cancel.db")
    try:
        broker.queue_submit(FakeSubmitResult("venue-order-unknown-cancel"))
        created = await actor.create(_request("unknown-cancel"))
        working = await actor.submit(created.order_id, _evidence(created))
        assert working.state is OrderState.WORKING

        broker.queue_cancel(
            BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_CANCEL)
        )
        unknown = await actor.cancel(created.order_id)
        assert unknown.state is OrderState.UNKNOWN_CANCEL
        await actor.cancel(created.order_id)
        assert broker.cancel_calls == 1
    finally:
        await _close(actor, engine)


async def test_incomplete_account_view_blocks_before_dispatch(tmp_path: Path) -> None:
    actor, broker, _memory, engine = await _open(tmp_path / "v1-incomplete-view.db")
    try:
        created = await actor.create(_request("incomplete-view"))
        broker.queue_account_view(
            BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_ACCOUNT_VIEW)
        )
        with pytest.raises(OMSValidationError):
            await actor.submit(created.order_id, _evidence(created))
        assert broker.submit_calls == 0
        assert (await actor.get(created.order_id)).state is not OrderState.WORKING
    finally:
        await _close(actor, engine)


async def test_quantity_only_broker_evidence_never_invents_fill_details(
    tmp_path: Path,
) -> None:
    actor, broker, memory, engine = await _open(
        tmp_path / "v1-quantity-only-execution.db"
    )
    try:
        broker.queue_submit(FakeSubmitResult("venue-order-quantity-only"))
        created = await actor.create(_request("quantity-only"))
        working = await actor.submit(created.order_id, _evidence(created))
        client_id = created.request.client_order_id or ""
        memory.record_execution(
            _ACCOUNT, client_id, "quantity-only-execution", Decimal("0.25")
        )

        with pytest.raises(BrokerOutcomeUnknown) as incomplete:
            broker.read_account_view(_ACCOUNT)
        assert incomplete.value.code == "UNKNOWN_ACCOUNT_VIEW"
        broker.queue_observation(
            _observation(
                working,
                memory,
                "quantity-only-observation",
                status=OrderState.WORKING,
            )
        )
        unresolved = await actor.reconcile(created.order_id)
        assert unresolved.state is OrderState.WORKING
        assert unresolved.filled_quantity == 0
        assert broker.submit_calls == 1

        # Complete the same broker execution with explicit economics and time.
        broker.record_execution(
            client_id,
            "quantity-only-execution",
            Decimal("0.25"),
            Decimal("100"),
            _NOW,
        )
        exact_view = broker.read_account_view(_ACCOUNT)
        assert len(exact_view.executions) == 1
        assert exact_view.executions[0].price == Decimal("100")
        assert exact_view.executions[0].executed_at == _NOW
        broker.queue_observation(
            _observation(working, memory, "completed-execution-observation")
        )
        complete = await actor.reconcile(created.order_id)
        assert complete.filled_quantity == Decimal("0.25")
    finally:
        await _close(actor, engine)


async def test_stale_account_view_blocks_before_dispatch(tmp_path: Path) -> None:
    actor, broker, memory, engine = await _open(tmp_path / "v1-stale-view.db")
    try:
        created = await actor.create(_request("stale-view"))
        stale_view = broker.read_account_view(_ACCOUNT)
        memory.record_dispatch(_ACCOUNT, "external-unmatched-order")
        broker.queue_account_view(stale_view)
        with pytest.raises(OMSValidationError):
            await actor.submit(created.order_id, _evidence(created))
        assert broker.submit_calls == 0
        assert (await actor.get(created.order_id)).state is not OrderState.WORKING
    finally:
        await _close(actor, engine)


class _TestDispatchGate:
    def __init__(self) -> None:
        self.halted = False
        self.cancel_code = DispatchGateCode.ALLOW
        self.after_arm = False
        self.require_after_arm = False
        self.calls: list[tuple[str, str]] = []

    def check(self, action: str, scope: OrderSnapshot) -> DispatchGateCode:
        self.calls.append((action, scope.order_id))
        if action == "SUBMIT":
            if self.require_after_arm:
                assert self.after_arm
            return (
                DispatchGateCode.DENY_HALT
                if self.halted else DispatchGateCode.ALLOW
            )
        return self.cancel_code


async def test_halt_flip_after_guard_rejects_without_port_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    gate = _TestDispatchGate()
    gate.require_after_arm = True
    actor, broker, _memory, engine = await _open(
        tmp_path / "v1-gate-halt.db", dispatch_gate=gate
    )
    try:
        original_arm = actor._ledger.arm_dispatch_guard

        async def arm_then_halt(*args: Any, **kwargs: Any) -> Any:
            result = await original_arm(*args, **kwargs)
            gate.after_arm = True
            gate.halted = True
            return result

        monkeypatch.setattr(actor._ledger, "arm_dispatch_guard", arm_then_halt)
        created = await actor.create(_request("gate-halt"))
        outcome = await actor.submit(created.order_id, _evidence(created))
        assert broker.submit_calls == 0
        assert outcome.state is OrderState.REJECTED_HALTED
        events = await actor._ledger.events(created.order_id)
        assert any(
            event["code"] == "DISPATCH_GATE_DENIED"
            and event["evidence"].get("reason") == "DENY_HALT"
            for event in events
        )
    finally:
        await _close(actor, engine)


async def test_cancel_is_allowed_under_halt_and_scope_denial_quarantines(
    tmp_path: Path,
) -> None:
    gate = _TestDispatchGate()
    actor, broker, _memory, engine = await _open(
        tmp_path / "v1-gate-cancel.db", dispatch_gate=gate
    )
    try:
        broker.queue_submit(FakeSubmitResult("venue-order-gate-1"))
        created = await actor.create(_request("gate-cancel"))
        await actor.submit(created.order_id, _evidence(created))
        gate.halted = True
        gate.after_arm = True
        broker.queue_cancel(FakeCancelResult(True))
        canceled = await actor.cancel(created.order_id)
        assert canceled.state is OrderState.CANCELED
        assert broker.cancel_calls == 1

        broker.queue_submit(FakeSubmitResult("venue-order-gate-2"))
        scoped = await actor.create(_request("gate-cancel-scope"))
        gate.halted = False
        await actor.submit(scoped.order_id, _evidence(scoped))
        gate.cancel_code = DispatchGateCode.DENY_SCOPE
        denied = await actor.cancel(scoped.order_id)
        assert denied.state is OrderState.RECONCILE_REQUIRED
        assert "GATE_DENIED_CANCEL" in denied.discrepancies
        assert broker.cancel_calls == 1
    finally:
        await _close(actor, engine)


class _RaisingDispatchGate:
    def check(self, _action: str, _scope: OrderSnapshot) -> DispatchGateCode:
        raise RuntimeError("synthetic dispatch gate failure")


async def test_dispatch_gate_exception_fails_closed(tmp_path: Path) -> None:
    actor, broker, _memory, engine = await _open(
        tmp_path / "v1-gate-error.db", dispatch_gate=_RaisingDispatchGate()
    )
    try:
        created = await actor.create(_request("gate-error"))
        denied = await actor.submit(created.order_id, _evidence(created))
        assert broker.submit_calls == 0
        assert denied.state is OrderState.REJECTED_HALTED
        events = await actor._ledger.events(created.order_id)
        assert any(event["code"] == "DISPATCH_GATE_DENIED" for event in events)
    finally:
        await _close(actor, engine)
