"""Independent persistence acceptance for OMS-CORE-002 intent identity."""

from __future__ import annotations

import asyncio
import multiprocessing
import sqlite3
from datetime import timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from leviathan_store.engine import create_engine_and_sessionmaker, init_schema
from leviathan_store.oms_ledger import OrderLedger, open_order_gateway_actor
from sqlalchemy.ext.asyncio import AsyncEngine

from leviathan_core.execution.broker_port import (
    BrokerVenue,
    FakeBrokerPort,
    FakeCancelResult,
    FakeSubmitResult,
    make_venue_dispatch_capability,
)
from leviathan_core.execution.broker_port_v1 import (
    BrokerRejectionCode,
)
from leviathan_core.execution.broker_reconciliation import (
    BrokerReconciliationStatus,
    FakeBrokerReconciliation,
)
from leviathan_core.execution.oms import OrderGatewayActor
from leviathan_core.execution.order_models import (
    ClientIdKey,
    LedgerIntegrityKey,
    OMSConflict,
    OMSDiscrepancy,
    OMSValidationError,
    OperatorAuthorizationKey,
    OrderRequest,
    OrderSnapshot,
    OrderState,
    PaperDispatchEvidence,
)

pytestmark = pytest.mark.asyncio
_LEDGER_KEY = LedgerIntegrityKey(b"oms-core002-store-ledger-key-32-bytes")
_CLIENT_KEY = ClientIdKey(b"oms-core002-store-client-id-key-32-bytes")


def _second_process_open_ledger(database: str, result_queue: Any) -> None:
    async def attempt() -> None:
        engine, sessions = create_engine_and_sessionmaker(
            f"sqlite+aiosqlite:///{database}"
        )
        actor = None
        try:
            await init_schema(engine)
            reconciliation = FakeBrokerReconciliation()
            actor = open_order_gateway_actor(
                sessions,
                FakeBrokerPort(
                    reconciliation,
                    account_id="core002-store-account",
                    environment="demo",
                    venue=BrokerVenue.MT5,
                ),
                reconciliation,
                _CLIENT_KEY,
                ledger_key=_LEDGER_KEY,
                allow_in_memory=True,
            )
            result_queue.put("OPENED")
        except OMSConflict as exc:
            result_queue.put(exc.code)
        except Exception as exc:  # relay unexpected child failure to the parent test
            result_queue.put(f"UNEXPECTED:{type(exc).__name__}:{exc}")
        finally:
            if actor is not None:
                await actor.close()
            await _dispose_engine(engine)

    asyncio.run(attempt())


def _request(intent: str, attempt: int) -> OrderRequest:
    account_id = "core002-store-account"
    return OrderRequest(
        project_id="leviathan-ai",
        environment="demo",
        account_id=account_id,
        venue="MT5",
        instrument_id="EURUSD",
        native_contract_id="EURUSD.demo",
        side="BUY",
        quantity=Decimal("1"),
        order_type="MARKET",
        time_in_force="DAY",
        client_order_id=_CLIENT_KEY.derive(account_id, intent, attempt),
        intent_idempotency_key=intent,
        attempt=attempt,
        strategy_id="core002-store-strategy",
        risk_policy_digest="d" * 64,
        actor_id="synthetic-operator",
        capability="demo-submit",
    )


async def test_ledger_reopen_preserves_derived_identity_and_attempt_scope(
    tmp_path: Path,
) -> None:
    database = tmp_path / "derived-intent-ledger.db"
    actor, _ledger, _broker, _reconciliation, engine = await _open_guard_gateway(
        database
    )
    request = _request("store-intent", 1)
    first = await actor.create(request)
    replay = await actor.create(request)
    retry_request = _request("store-intent", 2)
    retry = await actor.create(retry_request)
    other_intent = await actor.create(_request("different-store-intent", 1))

    assert replay.order_id == first.order_id
    assert retry.order_id != first.order_id
    assert other_intent.order_id != first.order_id
    assert len({
        first.request.client_order_id,
        retry.request.client_order_id,
        other_intent.request.client_order_id,
    }) == 3
    await _dispose_engine(engine)

    reopened_actor, _reopened, _broker, _same_memory, engine = await _open_guard_gateway(
        database
    )
    restored = await reopened_actor.get(first.order_id)
    restored_retry = await reopened_actor.get(retry.order_id)
    assert restored is not None and restored_retry is not None
    assert restored.request.intent_idempotency_key == "store-intent"
    assert restored.request.attempt == 1
    assert restored.request.client_order_id == _CLIENT_KEY.derive(
        "core002-store-account", "store-intent", 1
    )
    assert restored_retry.request.attempt == 2
    assert restored_retry.request.client_order_id == _CLIENT_KEY.derive(
        "core002-store-account", "store-intent", 2
    )
    await _dispose_engine(engine)


async def test_client_id_key_representation_does_not_echo_synthetic_material() -> None:
    material = b"oms-core002-store-client-id-key-32-bytes"
    key = ClientIdKey(material)
    assert material.decode("ascii") not in repr(key)
    assert key.derive("core002-store-account", "stable-intent", 7) == key.derive(
        "core002-store-account", "stable-intent", 7
    )
    assert key.derive("core002-store-account", "stable-intent", 7) != key.derive(
        "core002-store-account", "stable-intent", 8
    )


@pytest.mark.parametrize(
    ("submit_state", "expected_state"),
    [
        (OrderState.WORKING, OrderState.RECONCILE_REQUIRED),
        (OrderState.REJECTED, OrderState.REJECTED),
    ],
)
async def test_post_dispatch_conflict_event_and_state_survive_reopen(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    submit_state: OrderState,
    expected_state: OrderState,
) -> None:
    database = tmp_path / f"post-dispatch-conflict-{submit_state.value}.db"
    gateway, ledger, broker, reconciliation, engine = await _open_guard_gateway(
        database
    )
    request = _request(f"post-dispatch-conflict-{submit_state.value}", 1)
    created = await gateway.create(request)
    evidence = PaperDispatchEvidence(
        order_id=created.order_id,
        request_digest=created.request.digest,
        account_id=created.request.account_id,
        venue=created.request.venue,
        strategy_id=created.request.strategy_id,
        policy_digest=created.request.risk_policy_digest,
        account_session_verified=True,
        entitled=True,
        feed_fresh=True,
        risk_approved=True,
        halt_clear=True,
        allowlisted=True,
    )

    original_mark_submitting = ledger.mark_submitting

    async def mark_then_add_unmatched_order(
        order_id: str, dispatch_evidence: PaperDispatchEvidence
    ) -> OrderSnapshot:
        marked = await original_mark_submitting(order_id, dispatch_evidence)
        reconciliation.record_dispatch(request.account_id, "unmatched-during-dispatch")
        reconciliation.record_outcome(
            request.account_id,
            "unmatched-during-dispatch",
            OrderState.WORKING,
            "venue-unmatched-during-dispatch",
        )
        return marked

    monkeypatch.setattr(ledger, "mark_submitting", mark_then_add_unmatched_order)
    broker.queue_submit(
        FakeSubmitResult(
            "venue-cycle3-candidate" if submit_state is OrderState.WORKING else None,
            state=submit_state,
        )
    )
    broker.queue_cancel(FakeCancelResult(True))

    with pytest.raises(OMSDiscrepancy) as conflict:
        await gateway.submit(created.order_id, evidence)

    assert conflict.value.code == "POST_DISPATCH_CONFLICT"
    assert broker.submit_calls == 1
    assert broker.cancel_calls == 1
    await _dispose_engine(engine)

    reopened_actor, reopened, _broker, _same_memory, engine = await _open_guard_gateway(
        database, reconciliation
    )
    restored = await reopened_actor.get(created.order_id)
    assert restored is not None
    assert restored.state is expected_state
    assert "POST_DISPATCH_CONFLICT" in restored.discrepancies
    assert restored.cancel_attempted is True
    events = await reopened.events(created.order_id)
    post_dispatch_event = next(
        event for event in events if event["code"] == "POST_DISPATCH_CONFLICT"
    )
    assert post_dispatch_event["evidence"] == {
        "cancel_requested": True,
        "cancel_confirmed": True,
        "discrepancies": ["POST_DISPATCH_CONFLICT"],
    }
    await _dispose_engine(engine)


async def _open_guard_gateway(
    database: Path,
    reconciliation: FakeBrokerReconciliation | None = None,
    operator_key: OperatorAuthorizationKey | None = None,
) -> tuple[OrderGatewayActor, OrderLedger, FakeBrokerPort, FakeBrokerReconciliation, AsyncEngine]:
    engine, sessions = create_engine_and_sessionmaker(f"sqlite+aiosqlite:///{database}")
    await init_schema(engine)
    broker_memory = reconciliation or FakeBrokerReconciliation()
    broker = FakeBrokerPort(
        broker_memory,
        make_venue_dispatch_capability(False, timedelta(seconds=30)),
        account_id="core002-store-account",
        environment="demo",
        venue=BrokerVenue.MT5,
    )
    gateway = open_order_gateway_actor(
        sessions,
        broker,
        broker_memory,
        _CLIENT_KEY,
        ledger_key=_LEDGER_KEY,
        operator_key=operator_key,
        allow_in_memory=True,
    )
    ledger = gateway._ledger
    _ACTORS_BY_ENGINE[id(engine)] = gateway
    return gateway, ledger, broker, broker_memory, engine


_ACTORS_BY_ENGINE: dict[int, OrderGatewayActor] = {}


async def _dispose_engine(engine: AsyncEngine) -> None:
    actor = _ACTORS_BY_ENGINE.pop(id(engine), None)
    if actor is not None:
        await actor.close()
    await engine.dispose()


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


async def _leave_orphan_guard(
    gateway: OrderGatewayActor,
    ledger: OrderLedger,
    monkeypatch: pytest.MonkeyPatch,
    intent: str,
) -> OrderSnapshot:
    request = _request(intent, 1)
    order = await gateway.create(request)
    original_arm = ledger.arm_dispatch_guard

    async def arm_then_crash(
        order_id: str, *, action: str, broker_revision: int
    ) -> OrderSnapshot:
        await original_arm(order_id, action=action, broker_revision=broker_revision)
        raise RuntimeError("synthetic crash after durable guard arm")

    monkeypatch.setattr(ledger, "arm_dispatch_guard", arm_then_crash)
    with pytest.raises(RuntimeError, match="synthetic crash"):
        await gateway.submit(
            order.order_id, _dispatch_evidence(order.order_id, order.request)
        )
    assert await gateway.account_guard("demo", request.account_id) is not None
    return order


@pytest.mark.parametrize("fault_timing", ["before_commit", "after_commit"])
async def test_guarded_submit_completion_fault_survives_reopen_and_blocks_other_intent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault_timing: str
) -> None:
    database = tmp_path / f"guarded-conflict-fault-{fault_timing}.db"
    gateway, ledger, broker, reconciliation, engine = await _open_guard_gateway(database)
    request = _request(f"guarded-conflict-fault-{fault_timing}", 1)
    order = await gateway.create(request)
    original_arm = ledger.arm_dispatch_guard

    async def arm_then_add_unknown(
        order_id: str, *, action: str, broker_revision: int
    ) -> OrderSnapshot:
        guard_snapshot = await original_arm(
            order_id, action=action, broker_revision=broker_revision
        )
        reconciliation.record_dispatch(request.account_id, "guard-fault-unknown")
        reconciliation.record_outcome(
            request.account_id,
            "guard-fault-unknown",
            OrderState.WORKING,
            "venue-guard-fault-unknown",
        )
        return guard_snapshot

    monkeypatch.setattr(ledger, "arm_dispatch_guard", arm_then_add_unknown)
    original_cancel = broker.cancel

    def cancel_only_after_write_ahead_guard(snapshot: OrderSnapshot) -> FakeCancelResult:
        with sqlite3.connect(database) as connection:
            event_codes = [
                row[0]
                for row in connection.execute(
                    "SELECT code FROM oms_order_events WHERE order_id = ? ORDER BY sequence",
                    (order.order_id,),
                )
            ]
        assert "CANCEL_IN_FLIGHT" in event_codes
        return original_cancel(snapshot)

    monkeypatch.setattr(broker, "cancel", cancel_only_after_write_ahead_guard)
    original_complete = ledger.complete_guarded_submit

    async def fail_complete(
        order_id: str,
        state: OrderState,
        venue_order_id: str | None,
        *,
        conflict: bool,
        cancel_confirmed: bool,
        rejection_code: BrokerRejectionCode | None = None,
    ) -> OrderSnapshot:
        if fault_timing == "before_commit":
            raise RuntimeError("synthetic guarded completion failure")
        await original_complete(
            order_id,
            state,
            venue_order_id,
            conflict=conflict,
            cancel_confirmed=cancel_confirmed,
            rejection_code=rejection_code,
        )
        raise RuntimeError("synthetic post-commit acknowledgement loss")

    monkeypatch.setattr(ledger, "complete_guarded_submit", fail_complete)
    broker.queue_submit(FakeSubmitResult("venue-guarded-candidate"))
    broker.queue_cancel(FakeCancelResult(False))

    with pytest.raises(RuntimeError):
        await gateway.submit(order.order_id, _dispatch_evidence(order.order_id, order.request))
    assert broker.submit_calls == 1
    assert broker.cancel_calls == 1
    await _dispose_engine(engine)

    gateway, reopened_ledger, reopened_broker, _same_reconciliation, engine = (
        await _open_guard_gateway(database, reconciliation)
    )
    await gateway.recover_uncertain()
    reopened = await gateway.get(order.order_id)
    assert reopened is not None
    guard = await reopened_ledger.account_guard("demo", request.account_id)
    assert guard is not None
    assert guard.order_id == order.order_id
    assert reopened.state is OrderState.RECONCILE_REQUIRED
    assert reopened.cancel_attempted

    # The unmatched account order has since closed; the remaining broker image
    # looks clean for the candidate, but cannot prove the earlier cancel did not
    # happen. Review is read-only and must leave the account held.
    reconciliation.record_outcome(
        request.account_id,
        "guard-fault-unknown",
        OrderState.CANCELED,
        "venue-guard-fault-unknown",
    )
    review = await gateway.operator_guard_review("demo", request.account_id)
    assert review.guard.order_id == order.order_id
    assert review.guard_id
    assert review.broker_evidence_digest
    assert await reopened_ledger.account_guard("demo", request.account_id) is not None

    different = await gateway.create(_request("different-after-guard-fault", 1))
    with pytest.raises(OMSValidationError) as blocked:
        await gateway.submit(
            different.order_id, _dispatch_evidence(different.order_id, different.request)
        )
    assert blocked.value.code == "ACCOUNT_RECONCILE_REQUIRED"
    assert reopened_broker.submit_calls == 0
    await _dispose_engine(engine)


@pytest.mark.parametrize(
    "broker_trace", ["none", "exact", "extra", "unavailable", "ambiguous"]
)
async def test_reopened_guard_never_auto_clears_under_any_broker_image(
    tmp_path: Path, broker_trace: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / f"guard-recovery-{broker_trace}.db"
    gateway, ledger, _broker, reconciliation, engine = await _open_guard_gateway(database)
    request = _request(f"guard-recovery-{broker_trace}", 1)
    order = await _leave_orphan_guard(
        gateway, ledger, monkeypatch, request.intent_idempotency_key
    )
    guarded_client_id = order.request.client_order_id
    assert guarded_client_id is not None
    if broker_trace in {"exact", "extra"}:
        reconciliation.record_dispatch(request.account_id, guarded_client_id)
        reconciliation.record_outcome(
            request.account_id,
            guarded_client_id,
            OrderState.WORKING,
            "venue-guarded-order",
        )
    if broker_trace == "extra":
        reconciliation.record_dispatch(request.account_id, "extra-guarded-account-order")
        reconciliation.record_outcome(
            request.account_id,
            "extra-guarded-account-order",
            OrderState.WORKING,
            "venue-extra-guarded-order",
        )
    if broker_trace == "unavailable":
        reconciliation.queue_lookup(BrokerReconciliationStatus.UNAVAILABLE)
        reconciliation.queue_account_view(BrokerReconciliationStatus.UNAVAILABLE)
    if broker_trace == "ambiguous":
        reconciliation.queue_lookup(BrokerReconciliationStatus.AMBIGUOUS)
        reconciliation.queue_account_view(BrokerReconciliationStatus.AMBIGUOUS)
    await _dispose_engine(engine)

    gateway, _reopened_ledger, broker, _same_reconciliation, engine = (
        await _open_guard_gateway(database, reconciliation)
    )
    await gateway.recover_uncertain()
    recovered = await gateway.get(order.order_id)
    assert recovered is not None
    assert recovered.state is OrderState.RECONCILE_REQUIRED
    before = await gateway.account_guard("demo", request.account_id)
    assert before is not None
    candidate = await gateway.create(_request(f"other-with-guard-{broker_trace}", 1))
    with pytest.raises(OMSValidationError) as blocked:
        await gateway.submit(
            candidate.order_id, _dispatch_evidence(candidate.order_id, candidate.request)
        )
    assert blocked.value.code == "ACCOUNT_RECONCILE_REQUIRED"
    assert broker.submit_calls == 0
    assert await gateway.account_guard("demo", request.account_id) is not None
    assert not hasattr(gateway, "reconcile_guard")
    await _dispose_engine(engine)


async def test_operator_release_requires_fresh_exact_confirmation_and_is_audited(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "operator-guard-release.db"
    operator_key = OperatorAuthorizationKey(
        b"synthetic-operator-authorization-key-32-bytes"
    )
    gateway, ledger, broker, reconciliation, engine = await _open_guard_gateway(
        database, operator_key=operator_key
    )
    request = _request("operator-release-intent", 1)
    order = await _leave_orphan_guard(
        gateway, ledger, monkeypatch, request.intent_idempotency_key
    )
    original_guard = await gateway.account_guard("demo", request.account_id)
    assert original_guard is not None
    old_fence_epoch = original_guard.fence_epoch
    assert old_fence_epoch >= 1

    # Reopening creates a new ledger instance with an empty active_dispatch set;
    # the durable guard can then be released by a fresh exact operator review.
    await _dispose_engine(engine)
    gateway, ledger, broker, _same_reconciliation, engine = await _open_guard_gateway(
        database, reconciliation, operator_key
    )
    await gateway.recover_uncertain()
    after_restart = await gateway.get(order.order_id)
    assert after_restart is not None
    assert after_restart.state is OrderState.RECONCILE_REQUIRED

    initial_review = await gateway.operator_guard_review("demo", request.account_id)
    wrong_guard_id = "0" * 64
    if wrong_guard_id == initial_review.guard_id:
        wrong_guard_id = "1" * 64
    wrong_guard_confirmation = operator_key.confirm(
        "synthetic-operator", wrong_guard_id, initial_review.broker_evidence_digest
    )
    with pytest.raises(OMSValidationError) as wrong_guard:
        await gateway.operator_release_guard(
            "demo", request.account_id, wrong_guard_confirmation
        )
    assert wrong_guard.value.code == "OPERATOR_CONFIRMATION_MISMATCH"
    assert await gateway.account_guard("demo", request.account_id) is not None

    # A newer broker image invalidates the review digest, even when its only
    # change is terminal evidence for this exact guarded client identity.
    assert order.request.client_order_id is not None
    reconciliation.record_dispatch(request.account_id, order.request.client_order_id)
    reconciliation.record_outcome(
        request.account_id,
        order.request.client_order_id,
        OrderState.CANCELED,
        "venue-operator-release-terminal",
    )
    stale_confirmation = operator_key.confirm(
        "synthetic-operator", initial_review.guard_id,
        initial_review.broker_evidence_digest,
    )
    with pytest.raises(OMSValidationError) as stale:
        await gateway.operator_release_guard(
            "demo", request.account_id, stale_confirmation
        )
    assert stale.value.code == "OPERATOR_CONFIRMATION_MISMATCH"
    assert await gateway.account_guard("demo", request.account_id) is not None

    fresh_review = await gateway.operator_guard_review("demo", request.account_id)
    wrong_digest = "0" * 64
    if wrong_digest == fresh_review.broker_evidence_digest:
        wrong_digest = "1" * 64
    mismatched_confirmation = operator_key.confirm(
        "synthetic-operator", fresh_review.guard_id, wrong_digest
    )
    with pytest.raises(OMSValidationError) as mismatch:
        await gateway.operator_release_guard(
            "demo", request.account_id, mismatched_confirmation
        )
    assert mismatch.value.code == "OPERATOR_CONFIRMATION_MISMATCH"
    assert await gateway.account_guard("demo", request.account_id) is not None

    release = operator_key.confirm(
        "synthetic-operator", fresh_review.guard_id,
        fresh_review.broker_evidence_digest,
    )
    released = await gateway.operator_release_guard(
        "demo", request.account_id, release
    )
    assert released.order_id == order.order_id
    assert await gateway.account_guard("demo", request.account_id) is None
    with pytest.raises(OMSConflict) as stale_fence:
        await gateway.assert_dispatch_fence(order.order_id, old_fence_epoch)
    assert stale_fence.value.code == "STALE_DISPATCH_FENCE"
    assert broker.submit_calls == 0
    events = await ledger.events(order.order_id)
    release_event = next(event for event in events if event["code"] == "OPERATOR_GUARD_RELEASED")
    assert release_event["evidence"]["operator_id"] == "synthetic-operator"
    assert release_event["evidence"]["guard_id"] == fresh_review.guard_id
    assert (
        release_event["evidence"]["broker_evidence_digest"]
        == fresh_review.broker_evidence_digest
    )
    assert "signature" not in release_event["evidence"]
    await _dispose_engine(engine)


async def test_second_process_cannot_open_the_locked_oms_ledger(tmp_path: Path) -> None:
    database = tmp_path / "exclusive-oms-ledger.db"
    _gateway, _ledger, _broker, _reconciliation, engine = await _open_guard_gateway(
        database
    )
    context = multiprocessing.get_context("spawn")
    result_queue = context.Queue()
    process = context.Process(
        target=_second_process_open_ledger,
        args=(str(database), result_queue),
    )
    try:
        process.start()
        await asyncio.to_thread(process.join, 15)
        if process.is_alive():
            process.terminate()
            await asyncio.to_thread(process.join, 5)
            pytest.fail("second ledger process did not terminate")
        assert process.exitcode == 0
        assert await asyncio.to_thread(result_queue.get, True, 5) == "OMS_LEDGER_LOCKED"
    finally:
        if process.is_alive():
            process.terminate()
            await asyncio.to_thread(process.join, 5)
        result_queue.close()
        await _dispose_engine(engine)


async def test_second_actor_attach_to_shared_memory_ledger_is_refused() -> None:
    engine, sessions = create_engine_and_sessionmaker("sqlite+aiosqlite:///:memory:")
    await init_schema(engine)
    reconciliation = FakeBrokerReconciliation()
    actor = open_order_gateway_actor(
        sessions,
        FakeBrokerPort(
            reconciliation,
            account_id="core002-store-account",
            environment="demo",
            venue=BrokerVenue.MT5,
        ),
        reconciliation,
        _CLIENT_KEY,
        ledger_key=_LEDGER_KEY,
        allow_in_memory=True,
    )
    try:
        with pytest.raises(OMSConflict) as refused:
            open_order_gateway_actor(
                sessions,
                FakeBrokerPort(
                    reconciliation,
                    account_id="core002-store-account",
                    environment="demo",
                    venue=BrokerVenue.MT5,
                ),
                reconciliation,
                _CLIENT_KEY,
                ledger_key=_LEDGER_KEY,
                allow_in_memory=True,
            )
        assert refused.value.code == "OMS_LEDGER_LOCKED"
    finally:
        await actor.close()
        await engine.dispose()
