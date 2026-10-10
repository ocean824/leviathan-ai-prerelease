from __future__ import annotations

from datetime import date
from decimal import Decimal
from pathlib import Path

import pytest
from leviathan_store.engine import create_engine_and_sessionmaker, init_schema
from leviathan_store.oms_ledger import open_order_gateway_actor

from leviathan_core.execution.broker_port import FakeBrokerPort
from leviathan_core.execution.broker_port_v1 import BrokerEnvironment, BrokerVenue
from leviathan_core.execution.broker_reconciliation import FakeBrokerReconciliation
from leviathan_core.execution.instrument_binding_v1 import (
    AssetClassV1,
    RollPolicyV1,
    VenueInstrumentBindingV1,
    VenueInstrumentCatalogV1,
    VenueOrderAdmissionV1,
    VenueOrderSupportV1,
)
from leviathan_core.execution.order_models import (
    ClientIdKey,
    LedgerIntegrityKey,
    OMSValidationError,
    OrderRequest,
    OrderTypeV1,
    PaperDispatchEvidence,
    TimeInForceV1,
)

_INTEGRITY_KEY = LedgerIntegrityKey(b"exec-contract-cycle2-synthetic-integrity")
_CLIENT_KEY = ClientIdKey(b"exec-contract-cycle2-synthetic-client-key")


def _request(*, time_in_force: str = "DAY") -> OrderRequest:
    return OrderRequest(
        project_id="leviathan-ai",
        environment="paper",
        account_id="paper-1",
        venue=BrokerVenue.IBKR.value,
        instrument_id="NQ-202612",
        native_contract_id="con-1",
        side="BUY",
        quantity=Decimal("1"),
        order_type="LIMIT",
        time_in_force=time_in_force,
        client_order_id=_CLIENT_KEY.derive("paper-1", "exec-contract-intent", 1),
        intent_idempotency_key="exec-contract-intent",
        attempt=1,
        strategy_id="strategy-1",
        risk_policy_digest="a" * 64,
        actor_id="operator-1",
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


def _admission(as_of: list[date]) -> VenueOrderAdmissionV1:
    binding = VenueInstrumentBindingV1(
        instrument_id="NQ-202612",
        venue=BrokerVenue.IBKR,
        environment=BrokerEnvironment.PAPER,
        venue_symbol="NQZ6",
        native_contract_id="con-1",
        asset_class=AssetClassV1.FUTURE,
        tick_size=Decimal("0.25"),
        lot_size=Decimal("1"),
        currency="USD",
        session_calendar_ref="calendar-cme-v1",
        revision="catalog-oms-test",
        expiry=date(2026, 10, 9),
        last_trade=date(2026, 10, 8),
        listed_at=date(2026, 1, 1),
        roll_policy=RollPolicyV1.CALENDAR,
    )
    catalog = VenueInstrumentCatalogV1("catalog-oms-test", (binding,))
    support = VenueOrderSupportV1(
        BrokerVenue.IBKR,
        BrokerEnvironment.PAPER,
        (OrderTypeV1.LIMIT,),
        (TimeInForceV1.DAY,),
    )
    return VenueOrderAdmissionV1(catalog, (support,), lambda: as_of[0])


@pytest.mark.asyncio
async def test_real_oms_actor_rejects_expired_submit_and_unsupported_tif(
    tmp_path: Path,
) -> None:
    engine, sessions = create_engine_and_sessionmaker(
        f"sqlite+aiosqlite:///{tmp_path}/bound-admission.db"
    )
    await init_schema(engine)
    reconciliation = FakeBrokerReconciliation()
    broker = FakeBrokerPort(
        reconciliation,
        account_id="paper-1",
        venue=BrokerVenue.IBKR,
    )
    as_of = [date(2026, 10, 7)]
    actor = open_order_gateway_actor(
        sessions,
        broker,
        reconciliation,
        _CLIENT_KEY,
        ledger_key=_INTEGRITY_KEY,
        venue_order_admission=_admission(as_of),
        allow_in_memory=True,
    )
    try:
        valid_intent = await actor.create(_request())
        as_of[0] = date(2026, 10, 8)
        with pytest.raises(OMSValidationError, match="INSTRUMENT_EXPIRED"):
            await actor.submit(
                valid_intent.order_id, _evidence(valid_intent.order_id, valid_intent.request)
            )
        assert broker.submit_calls == 0

        with pytest.raises(OMSValidationError, match="UNSUPPORTED_ORDER_COMBINATION"):
            await actor.create(_request(time_in_force="GTC"))
        assert broker.submit_calls == 0
    finally:
        await actor.close()
        await engine.dispose()


@pytest.mark.asyncio
async def test_new_canonical_venue_fails_closed_without_admission(tmp_path: Path) -> None:
    engine, sessions = create_engine_and_sessionmaker(
        f"sqlite+aiosqlite:///{tmp_path}/missing-admission.db"
    )
    await init_schema(engine)
    reconciliation = FakeBrokerReconciliation()
    broker = FakeBrokerPort(
        reconciliation,
        account_id="paper-1",
        venue=BrokerVenue.IBKR,
    )
    actor = open_order_gateway_actor(
        sessions,
        broker,
        reconciliation,
        _CLIENT_KEY,
        ledger_key=_INTEGRITY_KEY,
        allow_in_memory=True,
    )
    try:
        with pytest.raises(OMSValidationError, match="VENUE_ORDER_ADMISSION_REQUIRED"):
            await actor.create(_request())
        assert broker.submit_calls == 0
    finally:
        await actor.close()
        await engine.dispose()
