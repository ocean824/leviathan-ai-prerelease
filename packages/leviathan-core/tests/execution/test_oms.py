"""Fake-only gateway lifecycle and failure tests."""

import asyncio
import copy
import pickle
import random
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import cast

import pytest
from leviathan_store.engine import create_engine_and_sessionmaker, init_schema
from leviathan_store.oms_ledger import OrderLedger, open_order_gateway_actor

from leviathan_core.execution.broker_port import (
    FakeBrokerPort,
    FakeCancelResult,
    FakeSubmitResult,
    make_venue_dispatch_capability,
)
from leviathan_core.execution.broker_port_v1 import BrokerVenue
from leviathan_core.execution.broker_reconciliation import (
    BrokerReconciliationStatus,
    FakeBrokerReconciliation,
    broker_evidence_digest,
)
from leviathan_core.execution.oms import (
    DispatchGateCode,
    OrderGateway,
    OrderGatewayActor,
)
from leviathan_core.execution.order_models import (
    BrokerObservation,
    ClientIdKey,
    Fill,
    FillCorrection,
    LedgerIntegrityKey,
    OMSConflict,
    OMSDiscrepancy,
    OMSStaleBrokerView,
    OMSValidationError,
    OperatorAuthorizationKey,
    OrderRequest,
    OrderSnapshot,
    OrderState,
    PaperDispatchEvidence,
    parse_oms_decimal,
)

NOW = datetime(2026, 9, 30, tzinfo=UTC)
_INTEGRITY_KEY = LedgerIntegrityKey(b"oms-core-unit-synthetic-integrity-key!")
_CLIENT_KEY = ClientIdKey(b"oms-core-unit-synthetic-client-id-key!")


def request(*, tif: str = "DAY", expiry: datetime | None = None) -> OrderRequest:
    return OrderRequest(
        project_id="leviathan-ai",
        environment="paper",
        account_id="paper-1",
        venue=BrokerVenue.IBKR_TWS.value,
        instrument_id="NQ-202612",
        native_contract_id="con-1",
        side="BUY",
        quantity=Decimal("2"),
        order_type="LIMIT",
        time_in_force=tif,
        client_order_id=_CLIENT_KEY.derive("paper-1", "caller-1", 1),
        intent_idempotency_key="caller-1",
        attempt=1,
        strategy_id="strategy-1",
        risk_policy_digest="a" * 64,
        actor_id="operator-1",
        capability="paper-submit",
        limit_price=Decimal("100"),
        expires_at=expiry,
    )


def evidence(order_id: str, req: OrderRequest, **overrides: bool) -> PaperDispatchEvidence:
    data = {
        "account_session_verified": True,
        "entitled": True,
        "feed_fresh": True,
        "risk_approved": True,
        "halt_clear": True,
        "allowlisted": True,
    }
    data.update(overrides)
    return PaperDispatchEvidence(
        order_id=order_id,
        request_digest=req.digest,
        account_id=req.account_id,
        venue=req.venue,
        strategy_id=req.strategy_id,
        policy_digest=req.risk_policy_digest,
        **data,
    )


async def gateway(
    tmp_path: object,
) -> tuple[OrderGatewayActor, OrderLedger, FakeBrokerPort, object]:
    engine, sessions = create_engine_and_sessionmaker(f"sqlite+aiosqlite:///{tmp_path}/oms.db")
    await init_schema(engine)
    reconciliation = FakeBrokerReconciliation()
    broker = FakeBrokerPort(
        reconciliation, account_id="paper-1", venue=BrokerVenue.IBKR_TWS,
    )
    actor = open_order_gateway_actor(
        sessions, broker, reconciliation, _CLIENT_KEY,
        ledger_key=_INTEGRITY_KEY, allow_in_memory=True,
    )
    ledger = cast(OrderLedger, vars(actor)["_ledger"])
    return actor, ledger, broker, engine


@pytest.mark.asyncio
async def test_actor_factory_refuses_second_memory_owner() -> None:
    engine, sessions = create_engine_and_sessionmaker("sqlite+aiosqlite:///:memory:")
    await init_schema(engine)
    reconciliation = FakeBrokerReconciliation()
    broker = FakeBrokerPort(
        reconciliation, account_id="paper-1", venue=BrokerVenue.IBKR_TWS,
    )
    with pytest.raises(OMSValidationError, match="OMS_FILE_LEDGER_REQUIRED"):
        open_order_gateway_actor(
            sessions, broker, reconciliation, _CLIENT_KEY, ledger_key=_INTEGRITY_KEY
        )
    temporary_engine, temporary_sessions = create_engine_and_sessionmaker(
        "sqlite+aiosqlite:///"
    )
    with pytest.raises(OMSValidationError, match="OMS_FILE_LEDGER_REQUIRED"):
        open_order_gateway_actor(
            temporary_sessions, broker, reconciliation, _CLIENT_KEY,
            ledger_key=_INTEGRITY_KEY,
        )
    await temporary_engine.dispose()
    actor = open_order_gateway_actor(
        sessions, broker, reconciliation, _CLIENT_KEY,
        ledger_key=_INTEGRITY_KEY, allow_in_memory=True,
    )
    with pytest.raises(OMSConflict, match="OMS_LEDGER_LOCKED"):
        open_order_gateway_actor(
            sessions, broker, reconciliation, _CLIENT_KEY,
            ledger_key=_INTEGRITY_KEY, allow_in_memory=True,
        )
    with pytest.raises(OMSConflict, match="OMS_LEDGER_LOCKED"):
        OrderLedger(sessions, key=_INTEGRITY_KEY)
    owned = cast(OrderLedger, vars(actor)["_ledger"])
    with pytest.raises(OMSValidationError, match="OMS_ACTOR_REQUIRED"):
        await owned.create(request())
    with pytest.raises(OMSValidationError, match="OMS_ACTOR_REQUIRED"):
        OrderGateway(owned, broker, reconciliation, _CLIENT_KEY)
    with pytest.raises(OMSValidationError, match="OMS_ACTOR_REQUIRED"):
        type("ForgedGateway", (OrderGateway,), {})
    with pytest.raises(OMSValidationError, match="OMS_ACTOR_REQUIRED"):
        type("ForgedActor", (OrderGatewayActor,), {})
    gateway_impl = cast(OrderGateway, vars(actor)["_gateway"])
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(OMSValidationError, match="OMS_ACTOR_REQUIRED"):
            operation(actor)
        with pytest.raises(OMSValidationError, match="OMS_ACTOR_REQUIRED"):
            operation(gateway_impl)
    with pytest.raises(OMSValidationError, match="OMS_ACTOR_REQUIRED"):
        OrderGateway.__init__(
            gateway_impl, owned, broker, reconciliation, _CLIENT_KEY
        )
    with pytest.raises(OMSValidationError, match="OMS_ACTOR_REQUIRED"):
        OrderGatewayActor.__init__(
            actor, gateway_impl, owned, owned.close
        )
    await actor.close()
    reopened = open_order_gateway_actor(
        sessions, broker, reconciliation, _CLIENT_KEY,
        ledger_key=_INTEGRITY_KEY, allow_in_memory=True,
    )
    await engine.dispose()
    with pytest.raises(OMSConflict, match="OMS_LEDGER_LOCKED"):
        OrderLedger(sessions, key=_INTEGRITY_KEY)
    await reopened.close()
    await engine.dispose()


@pytest.mark.asyncio
async def test_actor_serializes_submits_from_two_threads(tmp_path: Path) -> None:
    actor, _ledger, broker, engine = await gateway(tmp_path)
    created = await actor.create(request())
    broker.queue_submit(FakeSubmitResult("venue-threaded"))
    proof = evidence(created.order_id, created.request)

    def submit_from_thread() -> object:
        try:
            return asyncio.run(actor.submit(created.order_id, proof))
        except OMSConflict as exc:
            return exc

    first, second = await asyncio.gather(
        asyncio.to_thread(submit_from_thread),
        asyncio.to_thread(submit_from_thread),
    )
    assert broker.submit_calls == 1
    assert sorted(
        value.state.value if isinstance(value, OrderSnapshot) else value.code
        for value in (first, second)
    ) == ["SUBMIT_ALREADY_ATTEMPTED", "WORKING"]
    await actor.close()
    await engine.dispose()


@pytest.mark.asyncio
async def test_operator_release_waits_for_actor_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine, sessions = create_engine_and_sessionmaker(
        f"sqlite+aiosqlite:///{tmp_path}/queued-release.db"
    )
    await init_schema(engine)
    reconciliation = FakeBrokerReconciliation()
    broker = FakeBrokerPort(
        reconciliation, account_id="paper-1", venue=BrokerVenue.IBKR_TWS,
    )
    operator_key = OperatorAuthorizationKey(b"oms-actor-synthetic-operator-key!!")
    actor = open_order_gateway_actor(
        sessions, broker, reconciliation, _CLIENT_KEY,
        ledger_key=_INTEGRITY_KEY, operator_key=operator_key,
        allow_in_memory=True,
    )
    ledger = cast(OrderLedger, vars(actor)["_ledger"])
    created = await actor.create(request())
    broker.queue_submit(FakeSubmitResult("venue-queued-release"))
    armed = asyncio.Event()
    resume = asyncio.Event()
    original = ledger.arm_dispatch_guard

    async def pause_after_guard(
        order_id: str, *, action: str, broker_revision: int
    ) -> OrderSnapshot:
        snapshot = await original(
            order_id, action=action, broker_revision=broker_revision
        )
        armed.set()
        await resume.wait()
        return snapshot

    monkeypatch.setattr(ledger, "arm_dispatch_guard", pause_after_guard)
    submit_task = asyncio.create_task(
        actor.submit(created.order_id, evidence(created.order_id, created.request))
    )
    await armed.wait()
    guard, guard_id, _snapshot, _journal = await ledger.operator_guard_context(
        created.request.environment, created.request.account_id
    )
    lookup = await reconciliation.find_by_client_order_id(
        guard.account_id, guard.client_order_id
    )
    view = await reconciliation.account_view(guard.account_id, None)
    confirmation = operator_key.confirm(
        "operator-1", guard_id, broker_evidence_digest(lookup, view)
    )
    release_task = asyncio.create_task(
        actor.operator_release_guard(
            created.request.environment, created.request.account_id, confirmation
        )
    )
    await asyncio.sleep(0)
    assert not release_task.done()
    resume.set()
    assert (await submit_task).state is OrderState.WORKING
    with pytest.raises(OMSConflict, match="DISPATCH_GUARD_REQUIRED"):
        await release_task
    assert broker.submit_calls == 1
    assert await actor.account_guard(
        created.request.environment, created.request.account_id
    ) is None
    await actor.close()
    await engine.dispose()


@pytest.mark.asyncio
@pytest.mark.parametrize("seed", range(12))
async def test_seeded_revision_race_never_dispatches_unreconciled_activity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, seed: int
) -> None:
    rng = random.Random(seed)
    atomic = rng.choice((True, False))
    unknown_execution = rng.choice((True, False))
    engine, sessions = create_engine_and_sessionmaker(
        f"sqlite+aiosqlite:///{tmp_path}/race-{seed}.db"
    )
    await init_schema(engine)
    reconciliation = FakeBrokerReconciliation()
    capability = (
        make_venue_dispatch_capability(True)
        if atomic else make_venue_dispatch_capability(False, timedelta(seconds=1))
    )
    broker = FakeBrokerPort(
        reconciliation, capability, account_id="paper-1",
        venue=BrokerVenue.IBKR_TWS,
    )
    oms = open_order_gateway_actor(
        sessions, broker, reconciliation, _CLIENT_KEY,
        ledger_key=_INTEGRITY_KEY, allow_in_memory=True,
    )
    ledger = cast(OrderLedger, vars(oms)["_ledger"])
    req = replace(request(), intent_idempotency_key=f"race-{seed}", client_order_id=None)
    candidate = await oms.create(req)
    broker.queue_submit(FakeSubmitResult(f"venue-race-{seed}"))
    broker.queue_cancel(FakeCancelResult(True))
    original = ledger.mark_submitting

    async def inject_after_claim(order_id: str, proof: PaperDispatchEvidence):
        marked = await original(order_id, proof)
        unknown_id = f"unknown-race-{seed}"
        if unknown_execution:
            reconciliation.record_execution(
                req.account_id, unknown_id, f"execution-race-{seed}", Decimal("0.25")
            )
        else:
            reconciliation.record_dispatch(req.account_id, unknown_id)
            reconciliation.record_outcome(
                req.account_id, unknown_id, OrderState.WORKING,
                f"venue-unknown-race-{seed}",
            )
        return marked

    monkeypatch.setattr(ledger, "mark_submitting", inject_after_claim)
    expected_error = OMSStaleBrokerView if atomic else OMSDiscrepancy
    with pytest.raises(expected_error):
        await oms.submit(
            candidate.order_id, evidence(candidate.order_id, candidate.request)
        )
    assert broker.submit_calls == (0 if atomic else 1)
    assert broker.cancel_calls == (0 if atomic else 1)
    restored = await ledger.get(candidate.order_id)
    assert restored is not None
    assert restored.state is OrderState.RECONCILE_REQUIRED
    candidate_lookup = await reconciliation.find_by_client_order_id(
        req.account_id, candidate.request.client_order_id or "missing"
    )
    expected_status = (
        BrokerReconciliationStatus.NOT_FOUND
        if atomic else BrokerReconciliationStatus.FOUND
    )
    assert candidate_lookup.status is expected_status
    await oms.close()
    await engine.dispose()


@pytest.mark.asyncio
async def test_compensating_cancel_scope_denial_is_visible(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class ScopeGate:
        def check(self, action: str, _scope: OrderSnapshot) -> DispatchGateCode:
            return (
                DispatchGateCode.ALLOW if action == "SUBMIT"
                else DispatchGateCode.DENY_SCOPE
            )

    engine, sessions = create_engine_and_sessionmaker(
        f"sqlite+aiosqlite:///{tmp_path}/compensating-gate.db"
    )
    await init_schema(engine)
    reconciliation = FakeBrokerReconciliation()
    broker = FakeBrokerPort(
        reconciliation,
        make_venue_dispatch_capability(False, timedelta(seconds=1)),
        account_id="paper-1",
        venue=BrokerVenue.IBKR_TWS,
    )
    actor = open_order_gateway_actor(
        sessions, broker, reconciliation, _CLIENT_KEY,
        ledger_key=_INTEGRITY_KEY, dispatch_gate=ScopeGate(),
        allow_in_memory=True,
    )
    ledger = cast(OrderLedger, vars(actor)["_ledger"])
    created = await actor.create(request())
    broker.queue_submit(FakeSubmitResult("venue-compensating-gate"))
    original = ledger.mark_submitting

    async def add_unknown(order_id: str, proof: PaperDispatchEvidence) -> OrderSnapshot:
        marked = await original(order_id, proof)
        reconciliation.record_dispatch("paper-1", "unknown-compensating-gate")
        reconciliation.record_outcome(
            "paper-1", "unknown-compensating-gate", OrderState.WORKING,
            "venue-unknown-compensating-gate",
        )
        return marked

    monkeypatch.setattr(ledger, "mark_submitting", add_unknown)
    with pytest.raises(OMSDiscrepancy, match="POST_DISPATCH_CONFLICT"):
        await actor.submit(created.order_id, evidence(created.order_id, created.request))
    snapshot = await actor.get(created.order_id)
    assert snapshot is not None
    assert snapshot.state is OrderState.RECONCILE_REQUIRED
    assert "GATE_DENIED_CANCEL" in snapshot.discrepancies
    assert broker.cancel_calls == 0
    await actor.close()
    await engine.dispose()


@pytest.mark.asyncio
async def test_cancel_postcheck_conflict_keeps_guard_and_discrepancy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    oms, ledger, broker, engine = await gateway(tmp_path)
    req = request()
    order = await oms.create(req)
    broker.queue_submit(FakeSubmitResult("venue-cancel-conflict"))
    await oms.submit(order.order_id, evidence(order.order_id, order.request))
    broker.queue_cancel(FakeCancelResult(True))
    original_cancel = broker.cancel

    def cancel_then_add_unknown(snapshot):
        result = original_cancel(snapshot)
        broker.reconciliation.record_dispatch(req.account_id, "late-unknown-cancel")
        broker.reconciliation.record_outcome(
            req.account_id, "late-unknown-cancel", OrderState.WORKING,
            "venue-late-unknown-cancel",
        )
        return result

    monkeypatch.setattr(broker, "cancel", cancel_then_add_unknown)
    canceled = await oms.cancel(order.order_id)
    assert canceled.state is OrderState.CANCELED
    assert "POST_DISPATCH_CONFLICT" in canceled.discrepancies
    assert await ledger.account_guard(req.environment, req.account_id) is not None
    other = await oms.create(
        replace(req, intent_idempotency_key="other-after-cancel-conflict", client_order_id=None)
    )
    with pytest.raises(OMSValidationError, match="ACCOUNT_RECONCILE_REQUIRED"):
        await oms.submit(other.order_id, evidence(other.order_id, other.request))
    assert broker.submit_calls == 1
    await oms.close()
    await engine.dispose()


def test_client_id_vector_and_input_boundary() -> None:
    expected = "oms_tzvrhred36j6ebk4kec3kkx45ds3v2ulav7nsscpqmg4jpigvbyq"
    assert _CLIENT_KEY.derive("paper-1", "caller-1", 1) == expected
    assert _CLIENT_KEY.derive("paper-1", "caller-1", 2) != expected
    assert _CLIENT_KEY.derive("paper-1", "caller-2", 1) != expected
    with pytest.raises(OMSValidationError, match="INVALID_ATTEMPT"):
        _CLIENT_KEY.derive("paper-1", "caller-1", True)  # type: ignore[arg-type]
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(TypeError):
            operation(_CLIENT_KEY)
    assert "synthetic" not in repr(_CLIENT_KEY)


@pytest.mark.asyncio
async def test_gateway_derives_and_rechecks_client_identity(tmp_path: object) -> None:
    engine, sessions = create_engine_and_sessionmaker(
        f"sqlite+aiosqlite:///{tmp_path}/oms.db"
    )
    await init_schema(engine)
    ledger = OrderLedger(sessions, key=_INTEGRITY_KEY)
    legacy = replace(request(), client_order_id="legacy-underived",
                     intent_idempotency_key="legacy-underived")
    old = await ledger.create(legacy)
    ledger.close()
    reconciliation = FakeBrokerReconciliation()
    broker = FakeBrokerPort(
        reconciliation, account_id="paper-1", venue=BrokerVenue.IBKR_TWS,
    )
    oms = open_order_gateway_actor(
        sessions, broker, reconciliation, _CLIENT_KEY,
        ledger_key=_INTEGRITY_KEY, allow_in_memory=True,
    )
    without_id = replace(request(), client_order_id=None)
    created = await oms.create(without_id)
    assert created.request.client_order_id == _CLIENT_KEY.derive("paper-1", "caller-1", 1)
    with pytest.raises(OMSValidationError, match="CLIENT_ID_NOT_DERIVED"):
        await oms.create(replace(request(), client_order_id="caller-chosen"))
    with pytest.raises(OMSValidationError, match="CLIENT_ID_NOT_DERIVED"):
        await oms.submit(old.order_id, evidence(old.order_id, legacy))
    assert broker.submit_calls == 0
    await oms.close()
    await engine.dispose()


@pytest.mark.asyncio
@pytest.mark.parametrize("query", ["lookup", "view"])
@pytest.mark.parametrize("status", [
    BrokerReconciliationStatus.UNAVAILABLE, BrokerReconciliationStatus.AMBIGUOUS,
])
async def test_preflight_uncertainty_never_dispatches(
    tmp_path: object, query: str, status: BrokerReconciliationStatus
) -> None:
    oms, ledger, broker, engine = await gateway(tmp_path)
    req = request()
    created = await oms.create(req)
    if query == "lookup":
        broker.reconciliation.queue_lookup(status)
    else:
        broker.reconciliation.queue_account_view(status)
    with pytest.raises(OMSValidationError) as error:
        await oms.submit(created.order_id, evidence(created.order_id, req))
    assert error.value.code == f"BROKER_RECONCILIATION_{status.value}"
    assert broker.submit_calls == 0
    assert (await ledger.get(created.order_id)).state == OrderState.CREATED
    await oms.close()
    await engine.dispose()


@pytest.mark.asyncio
async def test_submit_timeout_stays_unknown_and_never_retries(tmp_path: object) -> None:
    oms, ledger, broker, engine = await gateway(tmp_path)
    req = request()
    created = await oms.create(req)
    broker.queue_submit(TimeoutError("lost ack"))
    result = await oms.submit(created.order_id, evidence(created.order_id, req))
    assert result.state == OrderState.UNKNOWN_SUBMIT
    assert result.submit_attempted
    assert broker.submit_calls == 1
    with pytest.raises(OMSConflict, match="SUBMIT_ALREADY_ATTEMPTED"):
        await oms.submit(created.order_id, evidence(created.order_id, req))
    assert broker.submit_calls == 1
    assert [event["code"] for event in await ledger.events(created.order_id)].count(
        "OUTBOUND_SUBMIT_COMMITTED"
    ) == 1
    await oms.close()
    await engine.dispose()


@pytest.mark.asyncio
async def test_cancel_timeout_and_broker_evidence_resolution(tmp_path: object) -> None:
    oms, _, broker, engine = await gateway(tmp_path)
    req = request()
    created = await oms.create(req)
    broker.queue_submit(FakeSubmitResult("venue-1"))
    working = await oms.submit(created.order_id, evidence(created.order_id, req))
    assert working.state == OrderState.WORKING
    broker.queue_cancel(TimeoutError("uncertain cancel"))
    unknown = await oms.cancel(created.order_id)
    assert unknown.state == OrderState.UNKNOWN_CANCEL
    await oms.cancel(created.order_id)
    assert broker.cancel_calls == 1
    broker.queue_observation(None)
    assert (await oms.reconcile(created.order_id)).state == OrderState.UNKNOWN_CANCEL
    broker.queue_observation(
        BrokerObservation(
            observation_id="ob-1",
            environment=req.environment,
            account_id=req.account_id,
            venue=req.venue,
            client_order_id=req.client_order_id,
            venue_order_id="venue-1",
            status=OrderState.CANCELED,
            observed_at=NOW,
        )
    )
    assert (await oms.reconcile(created.order_id)).state == OrderState.CANCELED
    await oms.close()
    await engine.dispose()


@pytest.mark.asyncio
async def test_failed_proof_never_calls_fake_broker(tmp_path: object) -> None:
    oms, ledger, broker, engine = await gateway(tmp_path)
    req = request()
    created = await oms.create(req)
    with pytest.raises(OMSValidationError, match="HALT_ACTIVE"):
        await oms.submit(created.order_id, evidence(created.order_id, req, halt_clear=False))
    assert broker.submit_calls == 0
    assert (await oms.get(created.order_id)).state == OrderState.RISK_REJECTED
    assert (await ledger.events(created.order_id))[-1]["code"] == "HALT_ACTIVE"
    await oms.close()
    await engine.dispose()


@pytest.mark.asyncio
async def test_post_gtd_fill_kept_with_discrepancy(tmp_path: object) -> None:
    oms, _ledger, broker, engine = await gateway(tmp_path)
    req = request(tif="GTD", expiry=NOW)
    created = await oms.create(req)
    broker.queue_submit(FakeSubmitResult("venue-1"))
    await oms.submit(created.order_id, evidence(created.order_id, req))
    fill = Fill(
        venue=req.venue,
        account_id=req.account_id,
        execution_id="exe-1",
        quantity=Decimal("2"),
        price=Decimal("100"),
        occurred_at=NOW + timedelta(seconds=1),
    )
    filled = await oms.record_fill(created.order_id, fill)
    assert filled.state == OrderState.FILLED
    assert filled.filled_quantity == Decimal("2")
    assert "FILL_AFTER_GTD" in filled.discrepancies
    assert (await oms.record_fill(created.order_id, fill)).version == filled.version
    await oms.close()
    await engine.dispose()


@pytest.mark.asyncio
async def test_unscripted_cancel_is_unknown_and_not_local_cancel(tmp_path: object) -> None:
    oms, _, broker, engine = await gateway(tmp_path)
    req = request()
    created = await oms.create(req)
    broker.queue_submit(FakeSubmitResult("venue-1"))
    await oms.submit(created.order_id, evidence(created.order_id, req))
    assert (await oms.cancel(created.order_id)).state == OrderState.UNKNOWN_CANCEL
    assert broker.cancel_calls == 1
    await oms.close()
    await engine.dispose()


@pytest.mark.asyncio
async def test_open_order_observation_does_not_clear_cancel_uncertainty(tmp_path: object) -> None:
    oms, _, broker, engine = await gateway(tmp_path)
    req = request()
    created = await oms.create(req)
    broker.queue_submit(FakeSubmitResult("venue-1"))
    await oms.submit(created.order_id, evidence(created.order_id, req))
    broker.queue_cancel(TimeoutError("cancel ack missing"))
    await oms.cancel(created.order_id)
    broker.queue_observation(
        BrokerObservation(
            observation_id="open-1",
            environment=req.environment,
            account_id=req.account_id,
            venue=req.venue,
            client_order_id=req.client_order_id,
            venue_order_id="venue-1",
            status=OrderState.WORKING,
            observed_at=NOW,
        )
    )
    assert (await oms.reconcile(created.order_id)).state == (
        OrderState.CANCEL_REQUESTED_UNCONFIRMED
    )
    await oms.close()
    await engine.dispose()


@pytest.mark.asyncio
async def test_fill_bust_is_versioned_and_original_execution_retained(tmp_path: object) -> None:
    oms, ledger, broker, engine = await gateway(tmp_path)
    req = request()
    created = await oms.create(req)
    broker.queue_submit(FakeSubmitResult("venue-1"))
    await oms.submit(created.order_id, evidence(created.order_id, req))
    fill = Fill(
        venue=req.venue,
        account_id=req.account_id,
        execution_id="exe-1",
        quantity=Decimal("2"),
        price=Decimal("100"),
        occurred_at=NOW,
    )
    assert (await oms.record_fill(created.order_id, fill)).state == OrderState.FILLED
    correction = FillCorrection(
        venue=req.venue,
        account_id=req.account_id,
        execution_id="exe-1",
        correction_id="bust-1",
        revision=1,
        revised_quantity=Decimal(0),
        revised_price=None,
        occurred_at=NOW + timedelta(seconds=1),
    )
    view = await oms.record_fill_correction(created.order_id, correction)
    assert view.state == OrderState.FILLED
    assert view.filled_quantity == 0
    assert "FILL_CORRECTION" in view.discrepancies
    assert (await oms.record_fill_correction(created.order_id, correction)).version == view.version
    assert [event["code"] for event in await ledger.events(created.order_id)].count(
        "BROKER_FILL_CORRECTION"
    ) == 1
    await oms.close()
    await engine.dispose()


def test_live_scope_and_text_boolean_rejected() -> None:
    with pytest.raises(OMSValidationError, match="NON_LIVE_SCOPE_REQUIRED"):
        OrderRequest(**{**request().payload(), "environment": "live"})
    with pytest.raises(OMSValidationError, match="INVALID_DISPATCH_EVIDENCE"):
        evidence("order-1", request(), halt_clear="false")  # type: ignore[arg-type]


def test_canonical_decimal_and_freeze_rules() -> None:
    from dataclasses import replace

    req = request()
    assert req.digest == replace(req, quantity=Decimal("2.0")).digest
    with pytest.raises(OMSValidationError, match="PRECISION_EXCEEDED"):
        replace(req, quantity=Decimal("1.1234567890123456789012345678901234"))
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(TypeError):
            operation(req)


def test_compact_extreme_exponent_rejected_without_echo() -> None:
    raw = {**request().payload(), "quantity": "1E+100000"}
    with pytest.raises(OMSValidationError) as captured:
        OrderRequest.from_payload(raw)
    assert captured.value.code == "INVALID_STORED_REQUEST"
    assert "100000" not in str(captured.value)
    with pytest.raises(OMSValidationError) as bad_code:
        parse_oms_decimal("1E+100000", code="secret-input")
    assert bad_code.value.code == "INVALID_DECIMAL_ERROR_CODE"
    assert "secret-input" not in str(bad_code.value)
