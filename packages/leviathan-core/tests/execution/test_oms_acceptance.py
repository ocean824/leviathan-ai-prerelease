"""Independent acceptance of the OMS fake-only gateway contract."""

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path

import pytest
from leviathan_store.engine import create_engine_and_sessionmaker, init_schema
from leviathan_store.oms_ledger import OrderLedger, open_order_gateway_actor
from leviathan_store.tables import OmsObservationRow
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncEngine

from leviathan_core.execution.broker_port import (
    BrokerVenue,
    FakeBrokerPort,
    FakeSubmitResult,
)
from leviathan_core.execution.broker_reconciliation import FakeBrokerReconciliation
from leviathan_core.execution.oms import OrderGateway, OrderGatewayActor
from leviathan_core.execution.order_models import (
    BrokerObservation,
    ClientIdKey,
    Fill,
    FillCorrection,
    LedgerIntegrityKey,
    OMSConflict,
    OMSLedgerCorruption,
    OMSValidationError,
    OrderRequest,
    OrderState,
    PaperDispatchEvidence,
)

pytestmark = pytest.mark.asyncio
NOW = datetime(2026, 9, 30, 15, 0, tzinfo=UTC)
_INTEGRITY_KEY = LedgerIntegrityKey(b"oms-acceptance-synthetic-key-32-bytes!")
_CLIENT_ID_KEY = ClientIdKey(b"oms-acceptance-client-id-key-32-bytes!")


def _request(
    *,
    client_order_id: str = "acceptance-order-1",
    intent_idempotency_key: str | None = None,
    attempt: int = 1,
    tif: str = "DAY",
    expiry: datetime | None = None,
) -> OrderRequest:
    intent_key = intent_idempotency_key or client_order_id
    return OrderRequest(
        project_id="leviathan-ai",
        environment="paper",
        account_id="paper-account-1",
        venue="ALPACA",
        instrument_id="NQ-202612",
        native_contract_id="fake-contract-1",
        side="BUY",
        quantity=Decimal("2"),
        order_type="LIMIT",
        time_in_force=tif,
        client_order_id=_CLIENT_ID_KEY.derive("paper-account-1", intent_key, attempt),
        intent_idempotency_key=intent_key,
        attempt=attempt,
        strategy_id="acceptance-strategy",
        risk_policy_digest="a" * 64,
        actor_id="synthetic-operator",
        capability="paper-submit",
        limit_price=Decimal("100"),
        expires_at=expiry,
    )


def _evidence(
    order_id: str,
    request: OrderRequest,
    **overrides: bool,
) -> PaperDispatchEvidence:
    values = {
        "account_session_verified": True,
        "entitled": True,
        "feed_fresh": True,
        "risk_approved": True,
        "halt_clear": True,
        "allowlisted": True,
    }
    values.update(overrides)
    return PaperDispatchEvidence(
        order_id=order_id,
        request_digest=request.digest,
        account_id=request.account_id,
        venue=request.venue,
        strategy_id=request.strategy_id,
        policy_digest=request.risk_policy_digest,
        **values,
    )


async def _new_gateway(
    tmp_path: Path,
) -> tuple[OrderGatewayActor, OrderLedger, FakeBrokerPort, AsyncEngine]:
    engine, sessions = create_engine_and_sessionmaker(
        f"sqlite+aiosqlite:///{tmp_path / 'oms-acceptance.db'}"
    )
    await init_schema(engine)
    reconciliation = FakeBrokerReconciliation()
    broker = FakeBrokerPort(
        reconciliation,
        account_id="paper-account-1",
        environment="paper",
        venue=BrokerVenue.ALPACA,
    )
    actor = open_order_gateway_actor(
        sessions,
        broker,
        reconciliation,
        _CLIENT_ID_KEY,
        ledger_key=_INTEGRITY_KEY,
        allow_in_memory=True,
    )
    ledger = actor._ledger
    _ACTORS_BY_ENGINE[id(engine)] = actor
    return actor, ledger, broker, engine


_ACTORS_BY_ENGINE: dict[int, OrderGatewayActor] = {}


async def _dispose_engine(engine: AsyncEngine) -> None:
    actor = _ACTORS_BY_ENGINE.pop(id(engine), None)
    if actor is not None:
        await actor.close()
    await engine.dispose()


async def test_same_durable_idempotency_key_returns_one_local_order(tmp_path: Path) -> None:
    gateway, ledger, broker, engine = await _new_gateway(tmp_path)
    request = _request()
    broker.queue_submit(FakeSubmitResult("venue-order-idempotent"))

    first = await gateway.create(request)
    submitted = await gateway.submit(
        first.order_id, _evidence(first.order_id, request)
    )
    duplicate = await gateway.create(request)

    assert duplicate.order_id == first.order_id
    assert duplicate.request.digest == first.request.digest
    assert submitted.state is OrderState.WORKING
    with pytest.raises(OMSConflict, match="SUBMIT_ALREADY_ATTEMPTED"):
        await gateway.submit(duplicate.order_id, _evidence(duplicate.order_id, request))
    assert broker.submit_calls == 1
    assert [event["code"] for event in await ledger.events(first.order_id)] == [
        "ORDER_CREATED",
        "RISK_CHECK_STARTED",
        "FAKE_RISK_READY",
        "OUTBOUND_SUBMIT_COMMITTED",
        "DISPATCH_GUARD_SET",
        "BROKER_SUBMIT_RESULT",
    ]
    await _dispose_engine(engine)


async def test_submit_timeout_is_unknown_and_reconcile_never_blind_retries(
    tmp_path: Path,
) -> None:
    gateway, ledger, broker, engine = await _new_gateway(tmp_path)
    request = _request()
    created = await gateway.create(request)
    broker.queue_submit(TimeoutError("synthetic lost acknowledgement"))

    unknown = await gateway.submit(created.order_id, _evidence(created.order_id, request))

    assert unknown.state is OrderState.UNKNOWN_SUBMIT
    assert unknown.submit_attempted is True
    assert broker.submit_calls == 1
    assert broker.cancel_calls == 0
    with pytest.raises(OMSConflict, match="SUBMIT_ALREADY_ATTEMPTED"):
        await gateway.submit(created.order_id, _evidence(created.order_id, request))
    assert broker.submit_calls == 1
    broker.queue_observation(None)
    assert (await gateway.reconcile(created.order_id)).state is OrderState.UNKNOWN_SUBMIT
    assert broker.read_calls == 1
    assert [event["code"] for event in await ledger.events(created.order_id)].count(
        "OUTBOUND_SUBMIT_COMMITTED"
    ) == 1
    await _dispose_engine(engine)


async def test_late_fill_after_gtd_is_retained_with_discrepancy(tmp_path: Path) -> None:
    gateway, _ledger, broker, engine = await _new_gateway(tmp_path)
    request = _request(tif="GTD", expiry=NOW)
    created = await gateway.create(request)
    broker.queue_submit(FakeSubmitResult("venue-order-1"))
    await gateway.submit(created.order_id, _evidence(created.order_id, request))
    broker.queue_observation(
        BrokerObservation(
            observation_id="gtd-expiry-observation",
            environment=request.environment,
            account_id=request.account_id,
            venue=request.venue,
            client_order_id=request.client_order_id,
            status=OrderState.EXPIRED,
            observed_at=NOW + timedelta(seconds=1),
            venue_order_id="venue-order-1",
        )
    )
    expired = await gateway.reconcile(created.order_id)
    assert expired.state is OrderState.EXPIRED
    fill = Fill(
        venue=request.venue,
        account_id=request.account_id,
        execution_id="execution-gtd-late-1",
        quantity=Decimal("1"),
        price=Decimal("100"),
        occurred_at=NOW + timedelta(seconds=2),
    )

    with pytest.raises(OMSConflict, match="FILL_AFTER_TERMINAL"):
        await gateway.record_fill(created.order_id, fill)
    late = await gateway.get(created.order_id)
    assert late is not None

    assert late.filled_quantity == Decimal("1")
    assert "FILL_AFTER_GTD" in late.discrepancies
    assert "FILL_AFTER_TERMINAL" in late.discrepancies
    assert late.state is OrderState.EXPIRED
    await _dispose_engine(engine)


@pytest.mark.parametrize("conflict", ["fill_after_rejection", "rejection_after_partial_fill"])
async def test_rejection_fill_conflicts_preserve_order_and_block_account(
    tmp_path: Path, conflict: str
) -> None:
    gateway, _ledger, broker, engine = await _new_gateway(tmp_path)
    request = _request(client_order_id=f"gateway-conflict-{conflict}")
    created = await gateway.create(request)
    if conflict == "fill_after_rejection":
        broker.queue_submit(FakeSubmitResult("venue-rejected", OrderState.REJECTED))
        rejected = await gateway.submit(created.order_id, _evidence(created.order_id, request))
        assert rejected.state is OrderState.REJECTED
        try:
            await gateway.record_fill(
                created.order_id,
                Fill(
                    venue=request.venue,
                    account_id=request.account_id,
                    execution_id="gateway-fill-after-rejection",
                    quantity=request.quantity,
                    price=Decimal("100"),
                    occurred_at=NOW,
                ),
            )
        except OMSConflict as error:
            assert error.code == "FILL_AFTER_TERMINAL"
        expected_state = OrderState.REJECTED
        expected_quantity = request.quantity
        expected_discrepancy = "FILL_AFTER_TERMINAL"
    else:
        broker.queue_submit(FakeSubmitResult("venue-partial"))
        await gateway.submit(created.order_id, _evidence(created.order_id, request))
        partial = await gateway.record_fill(
            created.order_id,
            Fill(
                venue=request.venue,
                account_id=request.account_id,
                execution_id="gateway-partial-before-rejection",
                quantity=Decimal("0.5"),
                price=Decimal("100"),
                occurred_at=NOW,
            ),
        )
        assert partial.state is OrderState.PARTIALLY_FILLED
        broker.queue_observation(
            BrokerObservation(
                observation_id="gateway-reject-after-partial",
                environment=request.environment,
                account_id=request.account_id,
                venue=request.venue,
                client_order_id=request.client_order_id,
                status=OrderState.REJECTED,
                observed_at=NOW + timedelta(seconds=1),
                venue_order_id="venue-partial",
            )
        )
        try:
            await gateway.reconcile(created.order_id)
        except OMSConflict as error:
            assert error.code == "REJECT_AFTER_FILL"
        expected_state = OrderState.PARTIALLY_FILLED
        expected_quantity = Decimal("0.5")
        expected_discrepancy = "REJECT_AFTER_FILL"

    preserved = await gateway.get(created.order_id)
    assert preserved is not None
    assert preserved.state is expected_state
    assert preserved.filled_quantity == expected_quantity
    assert expected_discrepancy in preserved.discrepancies

    second_request = _request(client_order_id=f"gateway-second-{conflict}")
    second = await gateway.create(second_request)
    with pytest.raises(OMSValidationError, match="ACCOUNT_RECONCILE_REQUIRED"):
        await gateway.submit(second.order_id, _evidence(second.order_id, second_request))
    assert broker.submit_calls == 1
    await _dispose_engine(engine)


async def test_uncertain_close_does_not_clear_local_fill_or_cancel_state(
    tmp_path: Path,
) -> None:
    gateway, _ledger, broker, engine = await _new_gateway(tmp_path)
    request = _request()
    created = await gateway.create(request)
    broker.queue_submit(FakeSubmitResult("venue-order-1"))
    await gateway.submit(created.order_id, _evidence(created.order_id, request))
    partial = await gateway.record_fill(
        created.order_id,
        Fill(
            venue=request.venue,
            account_id=request.account_id,
            execution_id="execution-open-1",
            quantity=Decimal("1"),
            price=Decimal("100"),
            occurred_at=NOW,
        ),
    )
    broker.queue_cancel(TimeoutError("synthetic close timeout"))

    uncertain = await gateway.cancel(created.order_id)

    assert partial.state is OrderState.PARTIALLY_FILLED
    assert uncertain.state is OrderState.UNKNOWN_CANCEL
    assert uncertain.filled_quantity == Decimal("1")
    assert uncertain.cancel_attempted is True
    assert broker.cancel_calls == 1
    await gateway.cancel(created.order_id)
    assert broker.cancel_calls == 1
    broker.queue_observation(
        BrokerObservation(
            observation_id="cancel-still-working",
            environment=request.environment,
            account_id=request.account_id,
            venue=request.venue,
            client_order_id=request.client_order_id,
            status=OrderState.WORKING,
            observed_at=NOW + timedelta(seconds=1),
            venue_order_id="venue-order-1",
        )
    )
    unconfirmed = await gateway.reconcile(created.order_id)
    assert unconfirmed.state is OrderState.CANCEL_REQUESTED_UNCONFIRMED
    assert unconfirmed.filled_quantity == Decimal("1")
    broker.queue_observation(
        BrokerObservation(
            observation_id="cancel-confirmed",
            environment=request.environment,
            account_id=request.account_id,
            venue=request.venue,
            client_order_id=request.client_order_id,
            status=OrderState.CANCELED,
            observed_at=NOW + timedelta(seconds=2),
            venue_order_id="venue-order-1",
        )
    )
    confirmed = await gateway.reconcile(created.order_id)
    assert confirmed.state is OrderState.CANCELED
    assert confirmed.filled_quantity == Decimal("1")
    assert (await gateway.get(created.order_id)).filled_quantity == Decimal("1")
    await _dispose_engine(engine)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("account_session_verified", False),
        ("entitled", False),
        ("feed_fresh", False),
        ("risk_approved", False),
        ("halt_clear", False),
        ("allowlisted", False),
    ],
)
async def test_missing_dispatch_proof_denies_without_transport_call(
    tmp_path: Path, field: str, value: bool
) -> None:
    gateway, _ledger, broker, engine = await _new_gateway(tmp_path)
    request = _request()
    created = await gateway.create(request)

    with pytest.raises(OMSValidationError):
        evidence = _evidence(created.order_id, request, **{field: value})
        await gateway.submit(created.order_id, evidence)

    assert broker.submit_calls == 0
    denied = await gateway.get(created.order_id)
    assert denied.state is OrderState.RISK_REJECTED
    assert denied.submit_attempted is False
    await _dispose_engine(engine)


async def test_reconciliation_needs_matching_broker_evidence_and_gateway_is_fake_only(
    tmp_path: Path,
) -> None:
    gateway, _ledger, broker, engine = await _new_gateway(tmp_path)
    request = _request()
    created = await gateway.create(request)
    broker.queue_submit(TimeoutError("synthetic lost acknowledgement"))
    await gateway.submit(created.order_id, _evidence(created.order_id, request))
    broker.queue_observation(
        BrokerObservation(
            observation_id="wrong-account-observation",
            environment="paper",
            account_id="other-account",
            venue=request.venue,
            client_order_id=request.client_order_id,
            status=OrderState.WORKING,
            observed_at=NOW,
            venue_order_id="venue-order-1",
        )
    )

    with pytest.raises(OMSValidationError, match="OBSERVATION_SCOPE_MISMATCH"):
        await gateway.reconcile(created.order_id)
    assert (await gateway.get(created.order_id)).state is OrderState.UNKNOWN_SUBMIT
    assert broker.submit_calls == 1

    class LiveLookingTransport:
        pass

    with pytest.raises(OMSValidationError, match="OMS_ACTOR_REQUIRED"):
        OrderGateway(  # type: ignore[arg-type]
            _ledger,
            LiveLookingTransport(),
            FakeBrokerReconciliation(),
            _CLIENT_ID_KEY,
        )
    live_engine, live_sessions = create_engine_and_sessionmaker(
        f"sqlite+aiosqlite:///{tmp_path / 'live-looking-transport.db'}"
    )
    await init_schema(live_engine)
    with pytest.raises(OMSValidationError, match="BROKER_PORT_V1_REQUIRED"):
        open_order_gateway_actor(
            live_sessions,
            LiveLookingTransport(),  # type: ignore[arg-type]
            FakeBrokerReconciliation(),
            _CLIENT_ID_KEY,
            ledger_key=_INTEGRITY_KEY,
        )
    await live_engine.dispose()
    await _dispose_engine(engine)


async def test_startup_recovery_never_places_order(tmp_path: Path) -> None:
    gateway, _ledger, broker, engine = await _new_gateway(tmp_path)

    assert await gateway.recover_uncertain() == []
    assert broker.submit_calls == 0
    assert broker.cancel_calls == 0
    assert broker.read_calls == 0
    await _dispose_engine(engine)


async def test_valid_enum_observation_tamper_blocks_second_submit_before_fake_dispatch(
    tmp_path: Path,
) -> None:
    gateway, _ledger, broker, engine = await _new_gateway(tmp_path)
    request = _request(client_order_id="cancelled-observation-chain")
    created = await gateway.create(request)
    broker.queue_submit(FakeSubmitResult("venue-cancelled-observation"))
    await gateway.submit(created.order_id, _evidence(created.order_id, request))
    canceled = BrokerObservation(
        observation_id="valid-canceled-observation",
        environment=request.environment,
        account_id=request.account_id,
        venue=request.venue,
        client_order_id=request.client_order_id,
        status=OrderState.CANCELED,
        observed_at=NOW,
        venue_order_id="venue-cancelled-observation",
    )
    broker.queue_observation(canceled)
    await gateway.reconcile(created.order_id)
    second_request = _request(client_order_id="after-canceled-observation-tamper")
    second = await gateway.create(second_request)
    async with engine.begin() as connection:
        result = await connection.execute(
            update(OmsObservationRow)
            .where(OmsObservationRow.order_id == created.order_id)
            .where(OmsObservationRow.observation_id == canceled.observation_id)
            .values(evidence={**canceled.payload(), "status": OrderState.WORKING.value})
        )
        assert result.rowcount == 1

    with pytest.raises(OMSLedgerCorruption) as corruption:
        await gateway.submit(second.order_id, _evidence(second.order_id, second_request))
    assert corruption.value.code == "OMS_LEDGER_CORRUPT"
    assert corruption.value.args == ("OMS_LEDGER_CORRUPT",)
    assert str(corruption.value) == "OMS_LEDGER_CORRUPT"
    assert broker.submit_calls == 1
    await _dispose_engine(engine)


async def test_fill_revisions_and_busts_append_without_deleting_original(
    tmp_path: Path,
) -> None:
    gateway, ledger, broker, engine = await _new_gateway(tmp_path)
    request = _request()
    created = await gateway.create(request)
    broker.queue_submit(FakeSubmitResult("venue-order-correction"))
    await gateway.submit(created.order_id, _evidence(created.order_id, request))
    original = Fill(
        venue=request.venue,
        account_id=request.account_id,
        execution_id="corrected-execution-1",
        quantity=Decimal("2"),
        price=Decimal("100"),
        occurred_at=NOW,
    )
    await gateway.record_fill(created.order_id, original)
    revised = await gateway.record_fill_correction(
        created.order_id,
        FillCorrection(
            venue=request.venue,
            account_id=request.account_id,
            execution_id=original.execution_id,
            correction_id="correction-revision-1",
            revision=1,
            revised_quantity=Decimal("0.75"),
            revised_price=Decimal("101"),
            occurred_at=NOW + timedelta(seconds=1),
        ),
    )
    busted = await gateway.record_fill_correction(
        created.order_id,
        FillCorrection(
            venue=request.venue,
            account_id=request.account_id,
            execution_id=original.execution_id,
            correction_id="correction-revision-2",
            revision=2,
            revised_quantity=Decimal(0),
            revised_price=None,
            occurred_at=NOW + timedelta(seconds=2),
        ),
    )

    assert revised.filled_quantity == Decimal("0.75")
    assert revised.state is OrderState.FILLED
    assert busted.filled_quantity == Decimal(0)
    assert busted.state is OrderState.FILLED
    assert "FILL_CORRECTION" in busted.discrepancies
    second_request = _request(client_order_id="after-filled-correction")
    second = await gateway.create(second_request)
    with pytest.raises(OMSValidationError, match="ACCOUNT_RECONCILE_REQUIRED"):
        await gateway.submit(second.order_id, _evidence(second.order_id, second_request))
    assert broker.submit_calls == 1
    codes = [event["code"] for event in await ledger.events(created.order_id)]
    assert codes.count("BROKER_FILL") == 1
    assert codes.count("BROKER_FILL_CORRECTION") == 2
    await _dispose_engine(engine)
