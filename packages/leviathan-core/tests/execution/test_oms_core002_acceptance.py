"""Independent acceptance for externally anchored OMS submit idempotency."""

from __future__ import annotations

import asyncio
import random
import shutil
import sqlite3
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from leviathan_store.engine import create_engine_and_sessionmaker, init_schema
from leviathan_store.oms_ledger import OrderLedger, open_order_gateway_actor
from leviathan_store.tables import (
    OmsEventRow,
    OmsFillCorrectionRow,
    OmsFillRow,
    OmsLedgerHeadRow,
    OmsObservationRow,
    OmsOrderRow,
    StoreBase,
)
from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncEngine

from leviathan_core.execution.broker_port import (
    BrokerVenue,
    FakeBrokerPort,
    FakeCancelResult,
    FakeDispatchPermit,
    FakeSubmitResult,
    VenueDispatchCapability,
    make_venue_dispatch_capability,
)
from leviathan_core.execution.broker_port_v1 import _issue_execution
from leviathan_core.execution.broker_reconciliation import (
    BrokerReconciliationStatus,
    FakeBrokerReconciliation,
)
from leviathan_core.execution.oms import OrderGatewayActor
from leviathan_core.execution.order_models import (
    BrokerObservation,
    ClientIdKey,
    Fill,
    LedgerIntegrityKey,
    OMSConflict,
    OMSDiscrepancy,
    OMSError,
    OMSLedgerCorruption,
    OMSStaleBrokerView,
    OMSValidationError,
    OperatorAuthorizationKey,
    OrderRequest,
    OrderSnapshot,
    OrderState,
    PaperDispatchEvidence,
)

pytestmark = pytest.mark.asyncio
NOW = datetime(2026, 9, 30, 15, 0, tzinfo=UTC)
_LEDGER_KEY = LedgerIntegrityKey(b"oms-core002-independent-ledger-key-32-bytes")
_CLIENT_KEY_MATERIAL = b"oms-core002-independent-client-id-key-32-bytes"
_CLIENT_KEY = ClientIdKey(_CLIENT_KEY_MATERIAL)


def _request(
    *,
    intent: str = "core002-intent-1",
    attempt: int = 1,
    client_order_id: str | None = None,
) -> OrderRequest:
    return OrderRequest(
        project_id="leviathan-ai",
        environment="paper",
        account_id="core002-paper-account",
        venue="ALPACA",
        instrument_id="NQ-202612",
        native_contract_id="fake-contract-core002",
        side="BUY",
        quantity=Decimal("1"),
        order_type="LIMIT",
        time_in_force="DAY",
        client_order_id=client_order_id,
        intent_idempotency_key=intent,
        attempt=attempt,
        strategy_id="core002-acceptance-strategy",
        risk_policy_digest="c" * 64,
        actor_id="synthetic-operator",
        capability="paper-submit",
        limit_price=Decimal("100"),
    )


def _evidence(order_id: str, request: OrderRequest) -> PaperDispatchEvidence:
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


async def _open_gateway(
    database: Path,
    reconciliation: FakeBrokerReconciliation | None = None,
    capability: VenueDispatchCapability | None = None,
    operator_key: OperatorAuthorizationKey | None = None,
) -> tuple[
    OrderGatewayActor,
    OrderLedger,
    FakeBrokerPort,
    FakeBrokerReconciliation,
    AsyncEngine,
]:
    engine, sessions = create_engine_and_sessionmaker(f"sqlite+aiosqlite:///{database}")
    await init_schema(engine)
    fake_reconciliation = reconciliation or FakeBrokerReconciliation()
    broker = (
        FakeBrokerPort(
            fake_reconciliation,
            account_id="core002-paper-account",
            environment="paper",
            venue=BrokerVenue.ALPACA,
        )
        if capability is None
        else FakeBrokerPort(
            fake_reconciliation,
            capability,
            account_id="core002-paper-account",
            environment="paper",
            venue=BrokerVenue.ALPACA,
        )
    )
    gateway = open_order_gateway_actor(
        sessions,
        broker,
        fake_reconciliation,
        _CLIENT_KEY,
        ledger_key=_LEDGER_KEY,
        operator_key=operator_key,
        allow_in_memory=True,
    )
    ledger = gateway._ledger
    _ACTORS_BY_ENGINE[id(engine)] = gateway
    return gateway, ledger, broker, fake_reconciliation, engine


_ACTORS_BY_ENGINE: dict[int, OrderGatewayActor] = {}


async def _dispose_engine(engine: AsyncEngine) -> None:
    actor = _ACTORS_BY_ENGINE.pop(id(engine), None)
    if actor is not None:
        await actor.close()
    await engine.dispose()


def _restore_snapshot(snapshot: Path, database: Path) -> None:
    with sqlite3.connect(snapshot) as source, sqlite3.connect(database) as target:
        source.backup(target)


def _inject_during_marker(
    monkeypatch: pytest.MonkeyPatch,
    ledger: OrderLedger,
    mutation: Callable[[], None],
) -> None:
    original_mark = ledger.mark_submitting

    async def mark_then_mutate(order_id: str, evidence: PaperDispatchEvidence) -> OrderSnapshot:
        marked = await original_mark(order_id, evidence)
        mutation()
        return marked

    monkeypatch.setattr(ledger, "mark_submitting", mark_then_mutate)


def _inject_async_fault(
    monkeypatch: pytest.MonkeyPatch,
    target: object,
    method_name: str,
    timing: str,
) -> None:
    original = getattr(target, method_name)

    async def faulted(*args: Any, **kwargs: Any) -> Any:
        if timing == "before_commit":
            raise RuntimeError(f"injected {method_name} before commit")
        result = await original(*args, **kwargs)
        if timing == "after_commit":
            raise RuntimeError(f"injected {method_name} after commit")
        return result

    monkeypatch.setattr(target, method_name, faulted)


def _inject_async_fault_on_call(
    monkeypatch: pytest.MonkeyPatch,
    target: object,
    method_name: str,
    call_number: int,
    timing: str,
) -> Callable[[], int]:
    original = getattr(target, method_name)
    calls = 0

    async def faulted(*args: Any, **kwargs: Any) -> Any:
        nonlocal calls
        calls += 1
        if calls == call_number and timing == "before":
            raise RuntimeError(f"injected {method_name} await before delegate")
        result = await original(*args, **kwargs)
        if calls == call_number and timing == "after":
            raise RuntimeError(f"injected {method_name} await after delegate")
        return result

    monkeypatch.setattr(target, method_name, faulted)
    return lambda: calls


def _observe_stale_dispatches(
    monkeypatch: pytest.MonkeyPatch, broker: FakeBrokerPort
) -> list[OMSStaleBrokerView]:
    stale: list[OMSStaleBrokerView] = []
    original_submit = broker.submit

    def submit_with_stale_observation(
        request: OrderRequest,
        permit: FakeDispatchPermit,
        expected_revision: int,
    ) -> FakeSubmitResult:
        try:
            return original_submit(request, permit, expected_revision)
        except OMSStaleBrokerView as error:
            stale.append(error)
            raise

    monkeypatch.setattr(broker, "submit", submit_with_stale_observation)
    return stale


async def _seed_canceled_prior_attempt(
    gateway: OrderGatewayActor,
    ledger: OrderLedger,
    broker: FakeBrokerPort,
    reconciliation: FakeBrokerReconciliation,
    intent: str,
    terminal_at: datetime,
) -> tuple[OrderRequest, OrderSnapshot, str]:
    assert gateway._ledger is ledger
    request = _request(intent=intent, attempt=1)
    first = await gateway.create(request)
    broker.queue_submit(FakeSubmitResult(f"venue-{intent}-attempt-one"))
    await gateway.submit(first.order_id, _evidence(first.order_id, first.request))
    client_id = first.request.client_order_id
    assert client_id is not None
    venue_order_id = f"venue-{intent}-attempt-one"
    reconciliation.record_outcome(
        request.account_id,
        client_id,
        OrderState.CANCELED,
        venue_order_id,
        observed_at=terminal_at,
    )
    broker.queue_observation(
        BrokerObservation(
            observation_id=f"{intent}-attempt-one-canceled",
            environment=request.environment,
            account_id=request.account_id,
            venue=request.venue,
            client_order_id=client_id,
            status=OrderState.CANCELED,
            observed_at=terminal_at,
            venue_order_id=venue_order_id,
        )
    )
    await gateway.reconcile(first.order_id)
    return request, first, client_id


async def _erase_all_oms_rows(engine: AsyncEngine) -> None:
    child_tables = (
        OmsEventRow,
        OmsFillRow,
        OmsFillCorrectionRow,
        OmsObservationRow,
        OmsOrderRow,
        OmsLedgerHeadRow,
    )
    async with engine.begin() as connection:
        for row_type in child_tables:
            await connection.execute(delete(row_type))


async def _assert_all_oms_rows_empty(engine: AsyncEngine) -> None:
    async with engine.connect() as connection:
        for table in StoreBase.metadata.sorted_tables:
            if table.name.startswith("oms_"):
                count = await connection.scalar(select(func.count()).select_from(table))
                assert count == 0


async def test_pre_submit_snapshot_restore_cannot_dispatch_same_intent_twice(
    tmp_path: Path,
) -> None:
    database = tmp_path / "rollback.db"
    snapshot = tmp_path / "pre-submit.db"
    request = _request()
    gateway, _ledger, first_broker, reconciliation, engine = await _open_gateway(database)
    created = await gateway.create(request)
    await _dispose_engine(engine)
    shutil.copyfile(database, snapshot)

    first_broker.queue_submit(FakeSubmitResult("venue-core002-first"))
    gateway, _ledger, first_broker, reconciliation, engine = await _open_gateway(
        database, reconciliation
    )
    await gateway.submit(created.order_id, _evidence(created.order_id, created.request))
    assert first_broker.submit_calls == 1
    await _dispose_engine(engine)

    _restore_snapshot(snapshot, database)
    gateway, _ledger, second_broker, same_reconciliation, engine = await _open_gateway(
        database, reconciliation
    )
    assert same_reconciliation is reconciliation
    with pytest.raises(OMSConflict) as duplicate:
        await gateway.submit(created.order_id, _evidence(created.order_id, created.request))
    assert duplicate.value.code == "DUPLICATE_INTENT"
    assert first_broker.submit_calls + second_broker.submit_calls == 1
    await _dispose_engine(engine)


async def test_erasing_every_oms_row_including_head_cannot_dispatch_again(
    tmp_path: Path,
) -> None:
    database = tmp_path / "erasure.db"
    request = _request(intent="core002-erased-intent")
    gateway, _ledger, first_broker, reconciliation, engine = await _open_gateway(database)
    created = await gateway.create(request)
    first_broker.queue_submit(FakeSubmitResult("venue-core002-erasure-first"))
    await gateway.submit(created.order_id, _evidence(created.order_id, created.request))
    await _erase_all_oms_rows(engine)
    await _assert_all_oms_rows_empty(engine)

    recreated = await gateway.create(request)
    assert recreated.order_id != created.order_id
    with pytest.raises(OMSConflict) as duplicate:
        await gateway.submit(recreated.order_id, _evidence(recreated.order_id, recreated.request))
    assert duplicate.value.code == "DUPLICATE_INTENT"
    assert first_broker.submit_calls == 1
    assert reconciliation.find_calls >= 2
    await _dispose_engine(engine)


@pytest.mark.parametrize(
    "status",
    [BrokerReconciliationStatus.UNAVAILABLE, BrokerReconciliationStatus.AMBIGUOUS],
)
async def test_unavailable_or_ambiguous_reconciliation_never_dispatches(
    tmp_path: Path, status: BrokerReconciliationStatus
) -> None:
    gateway, _ledger, broker, reconciliation, engine = await _open_gateway(
        tmp_path / f"{status.value.lower()}.db"
    )
    request = _request(intent=f"core002-{status.value.lower()}")
    created = await gateway.create(request)
    reconciliation.queue_lookup(status)
    reconciliation.queue_account_view(status)

    with pytest.raises(OMSValidationError) as denied:
        await gateway.submit(created.order_id, _evidence(created.order_id, created.request))
    assert denied.value.code in {
        "BROKER_RECONCILIATION_UNAVAILABLE",
        "BROKER_RECONCILIATION_AMBIGUOUS",
    }
    assert broker.submit_calls == 0
    current = await gateway.get(created.order_id)
    assert current is not None
    assert current.state is OrderState.CREATED
    await _dispose_engine(engine)


async def test_client_ids_are_derived_unique_by_intent_and_attempt_and_key_is_redacted(
    tmp_path: Path,
) -> None:
    gateway, _ledger, broker, _reconciliation, engine = await _open_gateway(
        tmp_path / "derived-ids.db"
    )
    first_request = _request(intent="same-intent", attempt=1)
    first = await gateway.create(first_request)
    replay = await gateway.create(first_request)
    second_intent = await gateway.create(_request(intent="other-intent", attempt=1))
    second_attempt = await gateway.create(_request(intent="same-intent", attempt=2))

    first_client_id = first.request.client_order_id
    replay_client_id = replay.request.client_order_id
    second_intent_client_id = second_intent.request.client_order_id
    second_attempt_client_id = second_attempt.request.client_order_id
    assert first_client_id is not None
    assert replay_client_id is not None
    assert second_intent_client_id is not None
    assert second_attempt_client_id is not None
    assert first_client_id == replay_client_id
    assert first_client_id == _CLIENT_KEY.derive(first_request.account_id, "same-intent", 1)
    assert len({first_client_id, second_intent_client_id, second_attempt_client_id}) == 3
    assert first_client_id.startswith("oms_")
    assert _CLIENT_KEY_MATERIAL.decode("ascii") not in repr(_CLIENT_KEY)
    assert broker.submit_calls == 0
    await _dispose_engine(engine)


async def test_caller_supplied_non_derived_client_id_is_rejected_without_echo_or_dispatch(
    tmp_path: Path,
) -> None:
    gateway, _ledger, broker, _reconciliation, engine = await _open_gateway(
        tmp_path / "caller-id.db"
    )
    supplied = "caller-chosen-client-id"
    request = _request(intent="caller-id", client_order_id=supplied)

    with pytest.raises(OMSValidationError) as rejected:
        await gateway.create(request)
    assert rejected.value.code == "CLIENT_ID_NOT_DERIVED"
    assert supplied not in str(rejected.value)
    assert _CLIENT_KEY_MATERIAL.decode("ascii") not in str(rejected.value)
    assert _CLIENT_KEY_MATERIAL.decode("ascii") not in repr(_CLIENT_KEY)
    assert broker.submit_calls == 0
    await _dispose_engine(engine)


async def test_tampered_persisted_client_id_is_refused_before_dispatch(tmp_path: Path) -> None:
    gateway, _ledger, broker, _reconciliation, engine = await _open_gateway(
        tmp_path / "tampered-client-id.db"
    )
    request = _request(intent="persisted-client-id")
    created = await gateway.create(request)
    async with engine.begin() as connection:
        result = await connection.execute(
            update(OmsOrderRow)
            .where(OmsOrderRow.order_id == created.order_id)
            .values(client_order_id=_CLIENT_KEY.derive(request.account_id, "other-intent", 1))
        )
        assert result.rowcount == 1

    with pytest.raises(OMSLedgerCorruption) as rejected:
        await gateway.submit(created.order_id, _evidence(created.order_id, created.request))
    assert rejected.value.code == "OMS_LEDGER_CORRUPT"
    assert broker.submit_calls == 0
    await _dispose_engine(engine)


async def test_seeded_submit_rollback_erasure_restore_interleavings_dispatch_once(
    tmp_path: Path,
) -> None:
    seed = 20260930
    rng = random.Random(seed)
    database = tmp_path / "seeded-interleavings.db"
    snapshot = tmp_path / "seeded-pre-submit.db"
    request = _request(intent=f"seeded-{seed}")
    gateway, _ledger, broker, reconciliation, engine = await _open_gateway(database)
    created = await gateway.create(request)
    await _dispose_engine(engine)
    shutil.copyfile(database, snapshot)
    gateway, _ledger, broker, _same_reconciliation, engine = await _open_gateway(
        database, reconciliation
    )

    brokers: list[FakeBrokerPort] = []
    actions = ["submit"] + [
        rng.choice(("submit", "rollback", "erase", "restore")) for _ in range(12)
    ]
    for action in actions:
        if action == "rollback" or action == "restore":
            await _dispose_engine(engine)
            _restore_snapshot(snapshot, database)
            gateway, _ledger, broker, _same_reconciliation, engine = await _open_gateway(
                database, reconciliation
            )
            brokers.append(broker)
            continue
        if action == "erase":
            await _erase_all_oms_rows(engine)
            await _assert_all_oms_rows_empty(engine)
            continue

        try:
            current = await gateway.get(created.order_id)
        except OMSLedgerCorruption:
            # Erasure is fail-closed: a later submit must not bypass the
            # missing authenticated ledger state.
            continue
        if current is None:
            current = await gateway.create(request)
        if not brokers:
            broker.queue_submit(FakeSubmitResult("venue-seeded-first"))
        with suppress(OMSConflict, OMSValidationError):
            await gateway.submit(current.order_id, _evidence(current.order_id, current.request))
        if broker not in brokers:
            brokers.append(broker)

    assert sum(item.submit_calls for item in brokers) == 1
    await _dispose_engine(engine)


@pytest.mark.parametrize("erase_local", [False, True])
async def test_attempt_two_waits_for_working_attempt_one(tmp_path: Path, erase_local: bool) -> None:
    gateway, _ledger, broker, _reconciliation, engine = await _open_gateway(
        tmp_path / f"working-attempt-one-{erase_local}.db"
    )
    first_request = _request(intent="retry-working", attempt=1)
    first = await gateway.create(first_request)
    broker.queue_submit(FakeSubmitResult("venue-working-attempt-one"))
    await gateway.submit(first.order_id, _evidence(first.order_id, first.request))
    first_current = await gateway.get(first.order_id)
    assert first_current is not None
    assert first_current.state is OrderState.WORKING

    second_request = _request(intent="retry-working", attempt=2)
    if erase_local:
        await _erase_all_oms_rows(engine)
        await _assert_all_oms_rows_empty(engine)
    second = await gateway.create(second_request)

    with pytest.raises(OMSValidationError) as blocked:
        await gateway.submit(second.order_id, _evidence(second.order_id, second.request))
    assert blocked.value.code == "PRIOR_ATTEMPT_UNRESOLVED"
    assert broker.submit_calls == 1
    await _dispose_engine(engine)


@pytest.mark.parametrize("erase_local", [False, True])
async def test_attempt_two_requires_broker_found_evidence_for_attempt_one(
    tmp_path: Path, erase_local: bool
) -> None:
    gateway, _ledger, broker, _reconciliation, engine = await _open_gateway(
        tmp_path / f"missing-attempt-one-evidence-{erase_local}.db"
    )
    await gateway.create(_request(intent="retry-without-found-evidence", attempt=1))
    second_request = _request(intent="retry-without-found-evidence", attempt=2)
    if erase_local:
        await _erase_all_oms_rows(engine)
        await _assert_all_oms_rows_empty(engine)
    second = await gateway.create(second_request)

    with pytest.raises(OMSValidationError) as blocked:
        await gateway.submit(second.order_id, _evidence(second.order_id, second.request))
    assert blocked.value.code == "PRIOR_ATTEMPT_UNRESOLVED"
    assert broker.submit_calls == 0
    await _dispose_engine(engine)


@pytest.mark.parametrize("erase_local", [False, True])
async def test_attempt_two_dispatches_after_confirmed_zero_fill_cancel(
    tmp_path: Path, erase_local: bool
) -> None:
    gateway, _ledger, broker, reconciliation, engine = await _open_gateway(
        tmp_path / f"canceled-attempt-one-{erase_local}.db"
    )
    first_request = _request(intent="retry-canceled", attempt=1)
    first = await gateway.create(first_request)
    broker.queue_submit(FakeSubmitResult("venue-canceled-attempt-one"))
    await gateway.submit(first.order_id, _evidence(first.order_id, first.request))

    first_client_id = first.request.client_order_id
    assert first_client_id is not None
    reconciliation.record_outcome(
        first_request.account_id,
        first_client_id,
        OrderState.CANCELED,
        "venue-canceled-attempt-one",
    )
    broker.queue_observation(
        BrokerObservation(
            observation_id="attempt-one-cancel-confirmed",
            environment=first_request.environment,
            account_id=first_request.account_id,
            venue=first_request.venue,
            client_order_id=first_client_id,
            status=OrderState.CANCELED,
            observed_at=NOW,
            venue_order_id="venue-canceled-attempt-one",
        )
    )
    await gateway.reconcile(first.order_id)
    canceled = await gateway.get(first.order_id)
    assert canceled is not None
    assert canceled.state is OrderState.CANCELED
    if erase_local:
        await _erase_all_oms_rows(engine)
        await _assert_all_oms_rows_empty(engine)

    second_request = _request(intent="retry-canceled", attempt=2)
    second = await gateway.create(second_request)
    broker.queue_submit(FakeSubmitResult("venue-canceled-attempt-two"))
    submitted = await gateway.submit(second.order_id, _evidence(second.order_id, second.request))

    assert submitted.state is OrderState.WORKING
    assert broker.submit_calls == 2
    prior_match = await reconciliation.find_by_client_order_id(
        first_request.account_id, first_client_id
    )
    assert prior_match.match is not None
    assert prior_match.match.state is OrderState.CANCELED
    assert prior_match.match.filled_quantity == Decimal(0)
    await _dispose_engine(engine)


@pytest.mark.parametrize("erase_local", [False, True])
async def test_attempt_two_is_blocked_after_any_positive_prior_fill(
    tmp_path: Path, erase_local: bool
) -> None:
    gateway, _ledger, broker, reconciliation, engine = await _open_gateway(
        tmp_path / f"partially-filled-attempt-one-{erase_local}.db"
    )
    first_request = _request(intent="retry-partial", attempt=1)
    first = await gateway.create(first_request)
    broker.queue_submit(FakeSubmitResult("venue-partial-attempt-one"))
    await gateway.submit(first.order_id, _evidence(first.order_id, first.request))
    fill_quantity = Decimal("0.25")
    await gateway.record_fill(
        first.order_id,
        Fill(
            venue=first_request.venue,
            account_id=first_request.account_id,
            execution_id="attempt-one-partial-execution",
            quantity=fill_quantity,
            price=Decimal("100"),
            occurred_at=NOW,
        ),
    )
    first_client_id = first.request.client_order_id
    assert first_client_id is not None
    reconciliation.record_execution(
        first_request.account_id,
        first_client_id,
        "attempt-one-partial-execution",
        fill_quantity,
    )
    if erase_local:
        await _erase_all_oms_rows(engine)
        await _assert_all_oms_rows_empty(engine)

    second_request = _request(intent="retry-partial", attempt=2)
    second = await gateway.create(second_request)
    with pytest.raises(OMSValidationError) as blocked:
        await gateway.submit(second.order_id, _evidence(second.order_id, second.request))
    assert blocked.value.code == "PRIOR_ATTEMPT_UNRESOLVED"
    assert broker.submit_calls == 1
    await _dispose_engine(engine)


@pytest.mark.parametrize("erase_local", [False, True])
async def test_attempt_seventeen_is_outside_policy_even_after_erasure(
    tmp_path: Path, erase_local: bool
) -> None:
    gateway, _ledger, broker, _reconciliation, engine = await _open_gateway(
        tmp_path / f"attempt-seventeen-{erase_local}.db"
    )
    if erase_local:
        await gateway.create(_request(intent="before-attempt-seventeen", attempt=1))
        await _erase_all_oms_rows(engine)
        await _assert_all_oms_rows_empty(engine)

    with pytest.raises(OMSValidationError) as outside_policy:
        await gateway.create(_request(intent="attempt-seventeen", attempt=17))
    assert outside_policy.value.code == "POLICY_OUT_OF_BOUNDS"
    assert broker.submit_calls == 0
    await _dispose_engine(engine)


@pytest.mark.parametrize("activity", ["open_order", "execution"])
@pytest.mark.parametrize("erase_local", [False, True])
async def test_unmatched_broker_account_activity_quarantines_fresh_intent(
    tmp_path: Path, activity: str, erase_local: bool
) -> None:
    gateway, _ledger, broker, reconciliation, engine = await _open_gateway(
        tmp_path / f"unmatched-{activity}-{erase_local}.db"
    )
    if erase_local:
        await gateway.create(_request(intent="pre-erasure-local-order"))
        await _erase_all_oms_rows(engine)
        await _assert_all_oms_rows_empty(engine)

    if activity == "open_order":
        reconciliation.record_dispatch("core002-paper-account", "unmatched-broker-open-order")
        reconciliation.record_outcome(
            "core002-paper-account",
            "unmatched-broker-open-order",
            OrderState.WORKING,
            "venue-unmatched-open-order",
        )
    else:
        foreign = _request(intent="unmatched-broker-execution-order")
        foreign_client_id = _CLIENT_KEY.derive(
            foreign.account_id,
            foreign.intent_idempotency_key,
            foreign.attempt,
        )
        venue_order_id = "venue-unmatched-execution-order"
        reconciliation.record_dispatch("core002-paper-account", foreign_client_id)
        reconciliation.record_outcome(
            "core002-paper-account",
            foreign_client_id,
            OrderState.WORKING,
            venue_order_id,
        )
        reconciliation.record_execution(
            "core002-paper-account",
            foreign_client_id,
            "unmatched-broker-execution",
            Decimal("0.1"),
        )
        # This is a complete, exact broker execution whose order has no local
        # OMS row. A quantity-only ledger entry would correctly be unavailable.
        reconciliation.record_execution_detail(
            "core002-paper-account",
            _issue_execution(
                "unmatched-broker-execution",
                venue_order_id,
                foreign_client_id,
                foreign.instrument_id,
                foreign.side,
                Decimal("0.1"),
                Decimal("100"),
                NOW,
            ),
        )

    request = _request(intent=f"fresh-with-unmatched-{activity}", attempt=1)
    current = await gateway.create(request)
    with pytest.raises(OMSValidationError) as unmatched:
        await gateway.submit(current.order_id, _evidence(current.order_id, current.request))
    assert unmatched.value.code == "BROKER_ACCOUNT_ACTIVITY_UNMATCHED"
    quarantined = await gateway.get(current.order_id)
    assert quarantined is not None
    assert quarantined.state is OrderState.RECONCILE_REQUIRED
    assert broker.submit_calls == 0
    await _dispose_engine(engine)


async def test_seeded_attempt_and_unknown_activity_interleavings_never_redispatch(
    tmp_path: Path,
) -> None:
    seed = 202609302
    rng = random.Random(seed)
    database = tmp_path / "attempt-account-activity-property.db"
    snapshot = tmp_path / "attempt-account-activity-pre-submit.db"
    first_request = _request(intent=f"seeded-attempt-{seed}", attempt=1)
    gateway, _ledger, first_broker, reconciliation, engine = await _open_gateway(database)
    first = await gateway.create(first_request)
    await _dispose_engine(engine)
    shutil.copyfile(database, snapshot)
    gateway, _ledger, first_broker, reconciliation, engine = await _open_gateway(
        database, reconciliation
    )
    first_broker.queue_submit(FakeSubmitResult("venue-seeded-attempt-one"))
    await gateway.submit(first.order_id, _evidence(first.order_id, first.request))
    assert first_broker.submit_calls == 1

    brokers = [first_broker]
    actions = ["submit_attempt_two", "erase", "restore", "unmatched_open", "unmatched_execution"]
    rng.shuffle(actions)
    for index, action in enumerate(actions):
        if action == "erase":
            await _erase_all_oms_rows(engine)
            await _assert_all_oms_rows_empty(engine)
            continue
        if action == "restore":
            await _dispose_engine(engine)
            _restore_snapshot(snapshot, database)
            gateway, _ledger, broker, _same_reconciliation, engine = await _open_gateway(
                database, reconciliation
            )
            brokers.append(broker)
            continue
        if action == "unmatched_open":
            reconciliation.record_dispatch(first_request.account_id, f"seeded-unknown-open-{index}")
            reconciliation.record_outcome(
                first_request.account_id,
                f"seeded-unknown-open-{index}",
                OrderState.WORKING,
                f"venue-seeded-open-{index}",
            )
        if action == "unmatched_execution":
            reconciliation.record_execution(
                first_request.account_id,
                f"seeded-unknown-execution-order-{index}",
                f"seeded-unknown-execution-{index}",
                Decimal("0.1"),
            )

        second_request = _request(intent=first_request.intent_idempotency_key, attempt=2)
        second = await gateway.create(second_request)
        with pytest.raises(OMSError):
            await gateway.submit(second.order_id, _evidence(second.order_id, second.request))
        assert sum(port.submit_calls for port in brokers) == 1

    assert sum(port.submit_calls for port in brokers) == 1
    await _dispose_engine(engine)


@pytest.mark.parametrize("race", ["late_fill", "unknown_order"])
async def test_atomic_revision_race_refuses_without_dispatch_and_rechecks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, race: str
) -> None:
    gateway, ledger, broker, reconciliation, engine = await _open_gateway(
        tmp_path / f"atomic-race-{race}.db"
    )
    if race == "late_fill":
        first_request, _first, first_client_id = await _seed_canceled_prior_attempt(
            gateway,
            ledger,
            broker,
            reconciliation,
            "atomic-late-fill",
            NOW - timedelta(minutes=5),
        )
        request = _request(intent=first_request.intent_idempotency_key, attempt=2)

        def inject() -> None:
            reconciliation.record_execution(
                request.account_id,
                first_client_id,
                "atomic-race-late-fill",
                Decimal("0.25"),
            )
    else:
        request = _request(intent="atomic-unknown-order", attempt=1)

        def inject() -> None:
            reconciliation.record_dispatch(request.account_id, "atomic-race-unknown-order")
            reconciliation.record_outcome(
                request.account_id,
                "atomic-race-unknown-order",
                OrderState.WORKING,
                "venue-atomic-race-unknown",
            )

    candidate = await gateway.create(request)
    stale_dispatches = _observe_stale_dispatches(monkeypatch, broker)
    _inject_during_marker(monkeypatch, ledger, inject)

    with pytest.raises(OMSStaleBrokerView) as refused:
        await gateway.submit(candidate.order_id, _evidence(candidate.order_id, candidate.request))

    assert refused.value.code == "STALE_BROKER_VIEW"
    assert len(stale_dispatches) == 1
    assert stale_dispatches[0].code == "STALE_BROKER_VIEW"
    assert broker.submit_calls == (1 if race == "late_fill" else 0)
    candidate_lookup = await reconciliation.find_by_client_order_id(
        request.account_id, candidate.request.client_order_id or "missing-client-id"
    )
    assert candidate_lookup.status is BrokerReconciliationStatus.NOT_FOUND
    if race == "unknown_order":
        quarantined = await gateway.get(candidate.order_id)
        assert quarantined is not None
        assert quarantined.state is OrderState.RECONCILE_REQUIRED
    await _dispose_engine(engine)


@pytest.mark.parametrize("race", ["late_fill", "unknown_order"])
async def test_non_atomic_race_dispatches_then_cancels_and_records_conflict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, race: str
) -> None:
    capability = make_venue_dispatch_capability(False, timedelta(seconds=30))
    gateway, ledger, broker, reconciliation, engine = await _open_gateway(
        tmp_path / f"non-atomic-race-{race}.db", capability=capability
    )
    if race == "late_fill":
        first_request, _first, first_client_id = await _seed_canceled_prior_attempt(
            gateway,
            ledger,
            broker,
            reconciliation,
            "non-atomic-late-fill",
            NOW - timedelta(minutes=5),
        )
        request = _request(intent=first_request.intent_idempotency_key, attempt=2)

        def inject() -> None:
            reconciliation.record_execution(
                request.account_id,
                first_client_id,
                "non-atomic-race-late-fill",
                Decimal("0.25"),
            )
    else:
        request = _request(intent="non-atomic-unknown-order", attempt=1)

        def inject() -> None:
            reconciliation.record_dispatch(request.account_id, "non-atomic-race-unknown")
            reconciliation.record_outcome(
                request.account_id,
                "non-atomic-race-unknown",
                OrderState.WORKING,
                "venue-non-atomic-race-unknown",
            )

    candidate = await gateway.create(request)
    broker.queue_submit(FakeSubmitResult(f"venue-candidate-{race}"))
    broker.queue_cancel(FakeCancelResult(True))
    _inject_during_marker(monkeypatch, ledger, inject)

    with pytest.raises(OMSDiscrepancy) as conflict:
        await gateway.submit(candidate.order_id, _evidence(candidate.order_id, candidate.request))

    assert conflict.value.code == "POST_DISPATCH_CONFLICT"
    assert broker.submit_calls == (2 if race == "late_fill" else 1)
    assert broker.cancel_calls == 1
    conflicted = await gateway.get(candidate.order_id)
    assert conflicted is not None
    assert conflicted.state is OrderState.RECONCILE_REQUIRED
    assert "POST_DISPATCH_CONFLICT" in conflicted.discrepancies
    assert conflicted.cancel_attempted
    await _dispose_engine(engine)


async def test_non_atomic_retry_waits_for_terminal_settle_window(tmp_path: Path) -> None:
    capability = make_venue_dispatch_capability(False, timedelta(hours=1))
    gateway, ledger, broker, reconciliation, engine = await _open_gateway(
        tmp_path / "non-atomic-settle-window.db", capability=capability
    )
    first_request, _first, _client_id = await _seed_canceled_prior_attempt(
        gateway,
        ledger,
        broker,
        reconciliation,
        "non-atomic-settle-window",
        datetime.now(UTC) - timedelta(seconds=10),
    )
    second = await gateway.create(_request(intent=first_request.intent_idempotency_key, attempt=2))

    with pytest.raises(OMSValidationError) as unsettled:
        await gateway.submit(second.order_id, _evidence(second.order_id, second.request))

    assert unsettled.value.code == "PRIOR_ATTEMPT_UNRESOLVED"
    assert broker.submit_calls == 1
    await _dispose_engine(engine)


@pytest.mark.parametrize(
    ("boundary", "timing"),
    [
        (boundary, timing)
        for boundary in (
            "mark_submitting",
            "arm_dispatch_guard",
            "complete_guarded_submit",
        )
        for timing in ("before_commit", "after_commit")
    ],
)
async def test_submit_commit_faults_reopen_to_safe_guarded_or_verified_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
    timing: str,
) -> None:
    database = tmp_path / f"submit-fault-{boundary}-{timing}.db"
    gateway, ledger, broker, reconciliation, engine = await _open_gateway(database)
    request = _request(intent=f"submit-fault-{boundary}-{timing}")
    order = await gateway.create(request)
    broker.queue_submit(FakeSubmitResult(f"venue-{boundary}-{timing}"))
    _inject_async_fault(monkeypatch, ledger, boundary, timing)

    with pytest.raises(RuntimeError):
        await gateway.submit(order.order_id, _evidence(order.order_id, order.request))

    dispatched = broker.submit_calls == 1
    assert broker.submit_calls in {0, 1}
    await _dispose_engine(engine)

    gateway, reopened_ledger, reopened_broker, _same_memory, engine = await _open_gateway(
        database, reconciliation
    )
    restored = await gateway.get(order.order_id)
    assert restored is not None
    guard = await reopened_ledger.account_guard(request.environment, request.account_id)
    if dispatched and boundary == "complete_guarded_submit" and timing == "after_commit":
        assert restored.state is OrderState.WORKING
        assert restored.venue_order_id == f"venue-{boundary}-{timing}"
        assert guard is None
        assert restored.request.client_order_id is not None
        exact = await reconciliation.find_by_client_order_id(
            request.account_id, restored.request.client_order_id
        )
        assert exact.status is BrokerReconciliationStatus.FOUND
        assert exact.match is not None
        assert exact.match.state is OrderState.WORKING
        assert exact.match.venue_order_id == restored.venue_order_id
        finds_before = reconciliation.find_calls
        views_before = reconciliation.view_calls
        different = await gateway.create(
            _request(intent=f"different-after-clean-commit-{boundary}-{timing}")
        )
        reopened_broker.queue_submit(FakeSubmitResult("venue-after-clean-commit"))
        later = await gateway.submit(
            different.order_id, _evidence(different.order_id, different.request)
        )
        assert later.state is OrderState.WORKING
        assert reconciliation.find_calls > finds_before
        assert reconciliation.view_calls > views_before
        assert reopened_broker.submit_calls == 1
    elif dispatched:
        assert restored.state is OrderState.DISPATCH_IN_FLIGHT
        assert guard is not None
        assert guard.order_id == order.order_id
    else:
        assert restored.state is not OrderState.WORKING
        if boundary == "arm_dispatch_guard" and timing == "after_commit":
            assert guard is not None
            assert restored.state is OrderState.DISPATCH_IN_FLIGHT
        elif boundary == "mark_submitting" and timing == "before_commit":
            assert restored.state is OrderState.CREATED
            assert guard is None
        else:
            assert restored.state is OrderState.SUBMITTING
    if guard is not None or restored.state in {
        OrderState.SUBMITTING,
        OrderState.DISPATCH_IN_FLIGHT,
    }:
        different = await gateway.create(
            _request(intent=f"different-after-submit-fault-{boundary}-{timing}")
        )
        with pytest.raises((OMSConflict, OMSValidationError)):
            await gateway.submit(
                different.order_id, _evidence(different.order_id, different.request)
            )
    await _dispose_engine(engine)


@pytest.mark.parametrize(
    ("boundary", "timing"),
    [
        (boundary, timing)
        for boundary in (
            "mark_cancel_pending",
            "arm_dispatch_guard",
            "complete_guarded_cancel",
        )
        for timing in ("before_commit", "after_commit")
    ],
)
async def test_cancel_commit_faults_reopen_conservatively(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
    timing: str,
) -> None:
    database = tmp_path / f"cancel-fault-{boundary}-{timing}.db"
    gateway, ledger, broker, reconciliation, engine = await _open_gateway(database)
    request = _request(intent=f"cancel-fault-{boundary}-{timing}")
    order = await gateway.create(request)
    broker.queue_submit(FakeSubmitResult(f"venue-cancel-fault-{boundary}-{timing}"))
    working = await gateway.submit(order.order_id, _evidence(order.order_id, order.request))
    assert working.state is OrderState.WORKING
    broker.queue_cancel(FakeCancelResult(False))
    _inject_async_fault(monkeypatch, ledger, boundary, timing)

    with pytest.raises(RuntimeError):
        await gateway.cancel(order.order_id)

    cancel_dispatched = broker.cancel_calls == 1
    await _dispose_engine(engine)

    gateway, reopened_ledger, _new_broker, _same_memory, engine = await _open_gateway(
        database, reconciliation
    )
    restored = await gateway.get(order.order_id)
    assert restored is not None
    guard = await reopened_ledger.account_guard(request.environment, request.account_id)
    if cancel_dispatched and boundary == "complete_guarded_cancel" and timing == "after_commit":
        assert restored.state is OrderState.CANCEL_REQUESTED_UNCONFIRMED
        assert guard is not None
    elif cancel_dispatched:
        assert restored.state is OrderState.DISPATCH_IN_FLIGHT
        assert guard is not None
        assert guard.action == "CANCEL"
    elif boundary == "arm_dispatch_guard" and timing == "after_commit":
        assert restored.state is OrderState.DISPATCH_IN_FLIGHT
        assert guard is not None
    elif boundary == "mark_cancel_pending" and timing == "before_commit":
        assert restored.state is OrderState.WORKING
        assert guard is None
    else:
        assert restored.state is OrderState.CANCEL_PENDING
    if boundary in {"arm_dispatch_guard", "complete_guarded_cancel"} or (
        boundary == "mark_cancel_pending" and timing == "after_commit"
    ):
        different = await gateway.create(
            _request(intent=f"different-after-cancel-fault-{boundary}-{timing}")
        )
        with pytest.raises((OMSConflict, OMSValidationError)):
            await gateway.submit(
                different.order_id, _evidence(different.order_id, different.request)
            )
    await _dispose_engine(engine)


@pytest.mark.parametrize("timing", ["before_commit", "after_commit"])
async def test_retry_stale_reset_fault_keeps_guard_or_rechecks_before_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, timing: str
) -> None:
    database = tmp_path / f"retry-stale-fault-{timing}.db"
    gateway, ledger, broker, reconciliation, engine = await _open_gateway(database)
    first_request, _first, _first_client_id = await _seed_canceled_prior_attempt(
        gateway,
        ledger,
        broker,
        reconciliation,
        f"retry-stale-fault-{timing}",
        NOW - timedelta(minutes=5),
    )
    second = await gateway.create(_request(intent=first_request.intent_idempotency_key, attempt=2))

    def inject_unmatched_order() -> None:
        reconciliation.record_dispatch(request.account_id, f"retry-race-{timing}")
        reconciliation.record_outcome(
            request.account_id,
            f"retry-race-{timing}",
            OrderState.WORKING,
            f"venue-retry-race-{timing}",
        )

    request = second.request
    _inject_during_marker(monkeypatch, ledger, inject_unmatched_order)
    _inject_async_fault(monkeypatch, ledger, "mark_submit_stale", timing)

    with pytest.raises(RuntimeError):
        await gateway.submit(second.order_id, _evidence(second.order_id, second.request))

    assert broker.submit_calls == 1
    await _dispose_engine(engine)

    gateway, reopened_ledger, reopened_broker, _same_memory, engine = await _open_gateway(
        database, reconciliation
    )
    restored = await gateway.get(second.order_id)
    assert restored is not None
    guard = await reopened_ledger.account_guard(request.environment, request.account_id)
    if timing == "before_commit":
        assert guard is not None
        assert restored.state is OrderState.DISPATCH_IN_FLIGHT
    else:
        assert guard is None
        assert restored.state is OrderState.CREATED
    different = await gateway.create(_request(intent=f"different-after-retry-fault-{timing}"))
    with pytest.raises((OMSConflict, OMSValidationError)) as refused:
        await gateway.submit(different.order_id, _evidence(different.order_id, different.request))
    if timing == "after_commit":
        assert refused.value.code == "BROKER_ACCOUNT_ACTIVITY_UNMATCHED"
    assert reopened_broker.submit_calls == 0
    await _dispose_engine(engine)


async def test_seeded_submit_cancel_retry_await_faults_reopen_conservatively(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seed = 20261001
    rng = random.Random(seed)
    boundaries = [
        ("submit", "ledger", "verified_submit_snapshot", 1, "before"),
        ("submit", "reconciliation", "find_by_client_order_id", 1, "after"),
        ("submit", "reconciliation", "account_view", 1, "before"),
        ("submit", "reconciliation", "find_by_client_order_id", 2, "after"),
        ("submit", "reconciliation", "account_view", 2, "before"),
        ("submit", "ledger", "verified_submit_snapshot", 1, "after"),
        ("submit", "reconciliation", "account_view", 3, "after"),
        ("retry", "reconciliation", "find_by_client_order_id", 2, "before"),
        ("cancel", "reconciliation", "account_view", 1, "before"),
        ("cancel", "reconciliation", "find_by_client_order_id", 1, "after"),
        ("cancel", "reconciliation", "account_view", 2, "before"),
    ]
    rng.shuffle(boundaries)

    for index, (route, target_name, method_name, call_number, timing) in enumerate(boundaries):
        database = tmp_path / f"seeded-await-{seed}-{index}.db"
        gateway, ledger, broker, reconciliation, engine = await _open_gateway(database)
        intent = f"seeded-await-{seed}-{route}-{index}"
        if route == "retry":
            first_request, _first, _first_client_id = await _seed_canceled_prior_attempt(
                gateway,
                ledger,
                broker,
                reconciliation,
                intent,
                datetime.now(UTC) - timedelta(minutes=5),
            )
            order = await gateway.create(
                _request(intent=first_request.intent_idempotency_key, attempt=2)
            )
            broker.queue_submit(FakeSubmitResult(f"venue-seeded-retry-{index}"))
        elif route == "cancel":
            request = _request(intent=intent)
            order = await gateway.create(request)
            broker.queue_submit(FakeSubmitResult(f"venue-seeded-cancel-{index}"))
            working = await gateway.submit(order.order_id, _evidence(order.order_id, order.request))
            assert working.state is OrderState.WORKING
            broker.queue_cancel(FakeCancelResult(True))
        else:
            order = await gateway.create(_request(intent=intent))
            broker.queue_submit(FakeSubmitResult(f"venue-seeded-submit-{index}"))

        target = ledger if target_name == "ledger" else reconciliation
        fault_calls = _inject_async_fault_on_call(
            monkeypatch, target, method_name, call_number, timing
        )
        try:
            if route == "cancel":
                await gateway.cancel(order.order_id)
            else:
                await gateway.submit(
                    order.order_id,
                    _evidence(order.order_id, order.request),
                )
        except (RuntimeError, OMSConflict, OMSValidationError, OMSDiscrepancy):
            pass
        assert fault_calls() >= call_number, (seed, route, method_name, call_number, timing)

        attempted_submits = broker.submit_calls
        attempted_cancels = broker.cancel_calls
        await _dispose_engine(engine)
        gateway, reopened_ledger, reopened_broker, _same_memory, engine = await _open_gateway(
            database, reconciliation
        )
        restored = await gateway.get(order.order_id)
        assert restored is not None, (seed, route, method_name, call_number, timing)
        guard = await reopened_ledger.account_guard(
            order.request.environment, order.request.account_id
        )
        if guard is not None:
            assert guard.order_id == order.order_id
            assert restored.state in {
                OrderState.DISPATCH_IN_FLIGHT,
                OrderState.RECONCILE_REQUIRED,
                OrderState.CANCELED,
            }
        elif restored.state in {
            OrderState.SUBMITTING,
            OrderState.CANCEL_PENDING,
            OrderState.UNKNOWN_SUBMIT,
            OrderState.UNKNOWN_CANCEL,
            OrderState.RECONCILE_REQUIRED,
        }:
            blocked_order = await gateway.create(_request(intent=f"blocked-after-{seed}-{index}"))
            with pytest.raises((OMSConflict, OMSValidationError)):
                await gateway.submit(
                    blocked_order.order_id,
                    _evidence(blocked_order.order_id, blocked_order.request),
                )
            assert reopened_broker.submit_calls == 0
        assert attempted_submits >= (1 if route == "retry" else 0)
        assert attempted_cancels in {0, 1}
        await _dispose_engine(engine)


async def test_active_dispatch_refuses_operator_release_and_then_completes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "active-dispatch-release-fence.db"
    operator_key = OperatorAuthorizationKey(b"synthetic-active-dispatch-operator-key-32-bytes")
    gateway, ledger, broker, reconciliation, engine = await _open_gateway(
        database, operator_key=operator_key
    )
    request = _request(intent="active-dispatch-release-fence")
    order = await gateway.create(request)
    broker.queue_submit(FakeSubmitResult("venue-active-fence"))
    guard_committed = asyncio.Event()
    resume_dispatch = asyncio.Event()
    original_arm = ledger.arm_dispatch_guard

    async def arm_then_pause(order_id: str, *, action: str, broker_revision: int) -> OrderSnapshot:
        marked = await original_arm(order_id, action=action, broker_revision=broker_revision)
        guard_committed.set()
        await resume_dispatch.wait()
        return marked

    monkeypatch.setattr(ledger, "arm_dispatch_guard", arm_then_pause)
    dispatch = asyncio.create_task(
        gateway.submit(order.order_id, _evidence(order.order_id, order.request))
    )
    try:
        await asyncio.wait_for(guard_committed.wait(), timeout=5)
        confirmation = operator_key.confirm("synthetic-operator", "0" * 64, "1" * 64)
        release = asyncio.create_task(
            gateway.operator_release_guard(request.environment, request.account_id, confirmation)
        )
        await asyncio.sleep(0)
        assert not release.done()
        assert broker.submit_calls == 0
    finally:
        resume_dispatch.set()

    completed = await asyncio.wait_for(dispatch, timeout=5)
    with pytest.raises(OMSConflict) as release_after_completion:
        await release
    assert release_after_completion.value.code == "DISPATCH_GUARD_REQUIRED"
    assert completed.state is OrderState.WORKING
    assert completed.venue_order_id == "venue-active-fence"
    assert completed.discrepancies == ()
    assert broker.submit_calls == 1
    assert await gateway.account_guard(request.environment, request.account_id) is None
    assert completed.request.client_order_id is not None
    broker_match = await reconciliation.find_by_client_order_id(
        request.account_id, completed.request.client_order_id
    )
    assert broker_match.status is BrokerReconciliationStatus.FOUND
    assert broker_match.match is not None
    assert broker_match.match.state is completed.state
    assert broker_match.match.venue_order_id == completed.venue_order_id
    await _dispose_engine(engine)


async def test_actor_serializes_duplicate_submits_from_multiple_threads(
    tmp_path: Path,
) -> None:
    gateway, _ledger, broker, _reconciliation, engine = await _open_gateway(
        tmp_path / "threaded-actor-submit.db"
    )
    request = _request(intent="threaded-actor-submit")
    order = await gateway.create(request)
    broker.queue_submit(FakeSubmitResult("venue-threaded-actor-submit"))
    barrier = threading.Barrier(8)

    def submit_from_thread() -> tuple[str, str]:
        barrier.wait(timeout=10)
        try:
            result = asyncio.run(
                gateway.submit(order.order_id, _evidence(order.order_id, order.request))
            )
            return "ok", result.state.value
        except OMSConflict as error:
            return "conflict", error.code

    def run_threads() -> list[tuple[str, str]]:
        with ThreadPoolExecutor(max_workers=8) as pool:
            return list(pool.map(lambda _: submit_from_thread(), range(8)))

    outcomes = await asyncio.to_thread(run_threads)
    assert sum(kind == "ok" for kind, _value in outcomes) == 1
    assert all(
        code in {"WORKING", "SUBMIT_ALREADY_ATTEMPTED", "DISPATCH_ALREADY_ACTIVE"}
        for _kind, code in outcomes
    )
    assert broker.submit_calls == 1
    final = await gateway.get(order.order_id)
    assert final is not None and final.state is OrderState.WORKING
    await _dispose_engine(engine)
