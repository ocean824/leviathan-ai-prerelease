from __future__ import annotations

from dataclasses import replace
from datetime import UTC, date, datetime
from decimal import Decimal
from pathlib import Path

import pytest
from leviathan_store.engine import create_engine_and_sessionmaker, init_schema
from leviathan_store.oms_ledger import open_order_gateway_actor

from leviathan_core.execution.brackets import BracketSpecV1
from leviathan_core.execution.broker_port import FakeBrokerPort
from leviathan_core.execution.broker_port_v1 import (
    BrokerEnvironment,
    BrokerVenue,
    EquityEvidenceKindV1,
    _issue_account_view,
    _issue_balance,
    _issue_equity_evidence,
    _issue_venue_identity,
)
from leviathan_core.execution.broker_reconciliation import FakeBrokerReconciliation
from leviathan_core.execution.brokers.alpaca_mapping import (
    AlpacaAssetV1,
)
from leviathan_core.execution.brokers.alpaca_mapping import (
    to_venue_instrument_binding as alpaca_binding,
)
from leviathan_core.execution.brokers.ibkr_mapping import (
    IBKRContractBindingV1,
)
from leviathan_core.execution.brokers.ibkr_mapping import (
    to_venue_instrument_binding as ibkr_binding,
)
from leviathan_core.execution.brokers.mt5_mapping import (
    MT5SymbolSpecV1,
)
from leviathan_core.execution.brokers.mt5_mapping import (
    to_venue_instrument_binding as mt5_binding,
)
from leviathan_core.execution.cancel_policy import (
    CancelResultV1,
    MassCancelResultV1,
    issue_mass_cancel_result,
)
from leviathan_core.execution.instrument_binding_v1 import (
    AssetClassV1,
    ExecutionContractError,
    FXValuationV1,
    MassCancelCompletionV1,
    RollPolicyV1,
    VenueInstrumentBindingV1,
    VenueInstrumentCatalogV1,
    VenueOrderAdmissionV1,
    VenueOrderSupportV1,
    account_snapshot_from_view,
    require_tradeable,
    summarize_mass_cancel,
    validate_venue_order_request,
)
from leviathan_core.execution.order_models import (
    ClientIdKey,
    LedgerIntegrityKey,
    OMSValidationError,
    OrderRequest,
    OrderTypeV1,
    PaperDispatchEvidence,
    PredictionOrderTermsV1,
    PredictionOutcomeV1,
    PredictionPriceUnitV1,
    PredictionPriceV1,
    TimeInForceV1,
)
from leviathan_core.execution.routing import RoutePlanInputV1, VenueQuoteV1, plan_route

NOW = 1_800_000_000_000
AS_OF = datetime(2026, 10, 9, tzinfo=UTC)
_OMS_INTEGRITY_KEY = LedgerIntegrityKey(b"exec-contract-acceptance-integrity-key-v1")
_OMS_CLIENT_KEY = ClientIdKey(b"exec-contract-acceptance-client-id-key-v1")


def _route_input(
    quote: VenueQuoteV1, *, order_type: str = "MARKET", tif: str = "DAY"
) -> RoutePlanInputV1:
    return RoutePlanInputV1(
        parent_request_digest="a" * 64,
        account_id="paper-account",
        instrument_id="gold",
        instrument_mapping_id="gold-map-v1",
        mapping_valid_from_ns=NOW - 1_000,
        mapping_valid_until_ns=NOW + 1_000,
        side="BUY",
        quantity=Decimal("1"),
        limit_price=None,
        lot_size=Decimal("1"),
        tick_size=Decimal("0.1"),
        multiplier=Decimal("10"),
        allowed_venues=(quote.venue_id,),
        venue_order=(quote.venue_id,),
        policy_revision="route-v1",
        routing_policy="best_price",
        max_venue_hops=1,
        order_type=order_type,
        tif=tif,
        hard_slippage_bps=Decimal("100"),
        latency_budget_ms=Decimal("100"),
        decision_time_ns=NOW,
        max_quote_age_ns=10_000,
        max_ping_age_ns=10_000,
        max_reconciliation_age_ns=10_000,
        max_slice_qty=Decimal("1"),
        depth_factor=Decimal("1"),
        venue_quotes=(quote,),
        session_close_ns=NOW + 500,
    )


def _quote(
    *, supported_order_types: tuple[str, ...], supported_tifs: tuple[str, ...]
) -> VenueQuoteV1:
    return VenueQuoteV1(
        venue_id="IBKR",
        bid=Decimal("2000"),
        ask=Decimal("2000.1"),
        bid_depth=Decimal("10"),
        ask_depth=Decimal("10"),
        event_time_ns=NOW - 10,
        receive_time_ns=NOW - 5,
        health="HEALTHY",
        permission=True,
        fee_bps=Decimal("0"),
        historical_slippage_bps=Decimal("0"),
        ping_ms=Decimal("1"),
        ping_time_ns=NOW - 10,
        lot_size=Decimal("1"),
        tick_size=Decimal("0.1"),
        mapped_instrument_id="gold",
        supported_order_types=supported_order_types,
        supported_tifs=supported_tifs,
    )


def test_gold_resolves_to_exact_venue_contracts_and_unsupported_venue_is_empty() -> None:
    gc = ibkr_binding(
        IBKRContractBindingV1("gold", "gc-dec-2026", 1001, "GCZ6", "FUT", "COMEX", "USD", "r1"),
        asset_class=AssetClassV1.FUTURE,
        tick_size=Decimal("0.1"),
        lot_size=Decimal("1"),
        session_calendar_ref="comex-v1",
        contract_multiplier=Decimal("100"),
        expiry=date(2026, 12, 28),
        roll_policy=RollPolicyV1.CALENDAR,
    )
    mgc = ibkr_binding(
        IBKRContractBindingV1("gold", "mgc-dec-2026", 1002, "MGCZ6", "FUT", "COMEX", "USD", "r1"),
        asset_class=AssetClassV1.FUTURE,
        tick_size=Decimal("0.1"),
        lot_size=Decimal("1"),
        session_calendar_ref="comex-v1",
        contract_multiplier=Decimal("10"),
        expiry=date(2027, 2, 26),
        roll_policy=RollPolicyV1.CALENDAR,
    )
    mt5 = mt5_binding(
        MT5SymbolSpecV1(
            "gold",
            "xauusd",
            "XAUUSD",
            "r2",
            Decimal("100"),
            Decimal("0.01"),
            Decimal("100"),
            Decimal("0.01"),
            Decimal("0.01"),
            Decimal("0.01"),
            2,
            0,
        ),
        asset_class=AssetClassV1.METAL,
        currency="USD",
        session_calendar_ref="forex-metals-v1",
    )
    catalog = VenueInstrumentCatalogV1("catalog-1", (mgc, gc, mt5))

    ibkr = catalog.resolve("gold", BrokerVenue.IBKR, BrokerEnvironment.PAPER)
    forex = catalog.resolve("gold", BrokerVenue.MT5_FOREXCOM, BrokerEnvironment.DEMO)
    assert tuple(item.venue_symbol for item in ibkr) == ("MGCZ6", "GCZ6")
    assert tuple(item.contract_multiplier for item in ibkr) == (Decimal("10"), Decimal("100"))
    assert all(item.tick_size == Decimal("0.1") and item.currency == "USD" for item in ibkr)
    assert len(forex) == 1 and forex[0].venue_symbol == "XAUUSD"
    assert (forex[0].tick_size, forex[0].lot_size, forex[0].contract_multiplier) == (
        Decimal("0.01"),
        Decimal("0.01"),
        Decimal("100"),
    )
    assert catalog.resolve("gold", BrokerVenue.ALPACA, BrokerEnvironment.PAPER) == ()


def test_mt5_demo_xauusd_rejects_differing_tick_native_symbol_collision() -> None:
    gold = mt5_binding(
        MT5SymbolSpecV1(
            "gold",
            "xauusd",
            "XAUUSD",
            "forex-r1",
            Decimal("100"),
            Decimal("0.01"),
            Decimal("100"),
            Decimal("0.01"),
            Decimal("0.01"),
            Decimal("0.01"),
            2,
            0,
        ),
        asset_class=AssetClassV1.METAL,
        currency="USD",
        session_calendar_ref="forex-metals-v1",
    )
    conflicting_symbol = replace(
        gold,
        instrument_id="silver",
        native_contract_id="misbound-xauusd",
        tick_size=Decimal("0.05"),
    )
    assert gold.venue is BrokerVenue.MT5_FOREXCOM
    assert gold.environment is BrokerEnvironment.DEMO
    assert gold.venue_symbol == "XAUUSD"
    assert conflicting_symbol.tick_size != gold.tick_size
    with pytest.raises(ExecutionContractError, match="CONFLICTING_VENUE_INSTRUMENT_BINDING"):
        VenueInstrumentCatalogV1("mt5-xauusd-collision", (gold, conflicting_symbol))


class _CalendarDate:
    def __init__(self, value: date) -> None:
        self.value = value
        self.calls: list[tuple[str, datetime]] = []

    def trading_date(self, calendar_ref: str, as_of: datetime) -> date:
        self.calls.append((calendar_ref, as_of))
        return self.value


def _tradeable_binding(**changes: object) -> VenueInstrumentBindingV1:
    values: dict[str, object] = {
        "instrument_id": "gold-dec-2026",
        "venue": BrokerVenue.IBKR,
        "environment": BrokerEnvironment.PAPER,
        "venue_symbol": "GCZ6",
        "native_contract_id": "gc-dec-2026",
        "asset_class": AssetClassV1.FUTURE,
        "tick_size": Decimal("0.1"),
        "lot_size": Decimal("1"),
        "currency": "USD",
        "session_calendar_ref": "comex-v1",
        "revision": "catalog-1",
        "expiry": date(2026, 12, 28),
        "roll_policy": RollPolicyV1.CALENDAR,
        "listed_at": date(2026, 1, 1),
        "last_trade": date(2026, 12, 27),
    }
    values.update(changes)
    return VenueInstrumentBindingV1(**values)  # type: ignore[arg-type]


def _order_request_for_binding(binding: VenueInstrumentBindingV1) -> OrderRequest:
    return OrderRequest(
        project_id="leviathan-ai",
        environment=binding.environment.value.lower(),
        account_id="paper-account",
        venue=binding.venue.value,
        instrument_id=binding.instrument_id,
        native_contract_id=binding.native_contract_id,
        side="BUY",
        quantity=Decimal("1"),
        order_type="MARKET",
        time_in_force="DAY",
        client_order_id="order-cycle1-1",
        intent_idempotency_key="intent-cycle1-1",
        attempt=1,
        strategy_id="strategy-cycle1",
        risk_policy_digest="a" * 64,
        actor_id="operator-cycle1",
        capability="paper-submit",
    )


def _actor_order_request(
    *, time_in_force: str = "DAY", intent_idempotency_key: str = "acceptance-intent"
) -> OrderRequest:
    return OrderRequest(
        project_id="leviathan-ai",
        environment="paper",
        account_id="acceptance-paper-account",
        venue=BrokerVenue.IBKR.value,
        instrument_id="acceptance-gold-future",
        native_contract_id="acceptance-gc-contract",
        side="BUY",
        quantity=Decimal("1"),
        order_type="LIMIT",
        time_in_force=time_in_force,
        client_order_id=_OMS_CLIENT_KEY.derive(
            "acceptance-paper-account", intent_idempotency_key, 1
        ),
        intent_idempotency_key=intent_idempotency_key,
        attempt=1,
        strategy_id="acceptance-strategy",
        risk_policy_digest="b" * 64,
        actor_id="acceptance-operator",
        capability="paper-submit",
        limit_price=Decimal("2000"),
    )


def _actor_dispatch_evidence(order_id: str, request: OrderRequest) -> PaperDispatchEvidence:
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


def test_tradeability_checks_listing_last_trade_expiry_and_datetime_calendar() -> None:
    binding = _tradeable_binding()
    require_tradeable(binding, date(2026, 12, 26))
    with pytest.raises(ExecutionContractError, match="INSTRUMENT_EXPIRED"):
        require_tradeable(binding, date(2026, 12, 27))
    with pytest.raises(ExecutionContractError, match="INSTRUMENT_EXPIRED"):
        require_tradeable(binding, date(2026, 12, 28))

    with pytest.raises(ExecutionContractError, match="INSTRUMENT_NOT_YET_LISTED"):
        require_tradeable(binding, date(2025, 12, 31))

    calendar = _CalendarDate(date(2026, 12, 26))
    instant = datetime(2026, 12, 27, 23, 0, tzinfo=UTC)
    require_tradeable(binding, instant, session_calendar=calendar)
    assert calendar.calls == [("comex-v1", instant)]

    non_dated = _tradeable_binding(expiry=None, last_trade=None, listed_at=None)
    require_tradeable(non_dated, date(2099, 1, 1))


def test_order_admission_rechecks_expiry_and_venue_capabilities() -> None:
    binding = _tradeable_binding()
    support = VenueOrderSupportV1(
        BrokerVenue.IBKR,
        BrokerEnvironment.PAPER,
        (OrderTypeV1.MARKET,),
        (TimeInForceV1.DAY,),
    )
    request = _order_request_for_binding(binding)
    validate_venue_order_request(request, binding, support, date(2026, 12, 26))

    with pytest.raises(ExecutionContractError, match="INSTRUMENT_EXPIRED"):
        validate_venue_order_request(request, binding, support, date(2026, 12, 27))

    limit_request = replace(request, order_type="LIMIT", limit_price=Decimal("2000"))
    with pytest.raises(ExecutionContractError, match="UNSUPPORTED_ORDER_COMBINATION"):
        validate_venue_order_request(limit_request, binding, support, date(2026, 12, 26))


@pytest.mark.asyncio
async def test_real_oms_actor_rejects_expired_submit_and_unsupported_tif(
    tmp_path: Path,
) -> None:
    engine, sessions = create_engine_and_sessionmaker(
        f"sqlite+aiosqlite:///{tmp_path / 'acceptance-admission.db'}"
    )
    await init_schema(engine)
    reconciliation = FakeBrokerReconciliation()
    broker = FakeBrokerPort(
        reconciliation,
        account_id="acceptance-paper-account",
        venue=BrokerVenue.IBKR,
    )
    as_of = [date(2026, 10, 7)]
    binding = VenueInstrumentBindingV1(
        instrument_id="acceptance-gold-future",
        venue=BrokerVenue.IBKR,
        environment=BrokerEnvironment.PAPER,
        venue_symbol="GCZ6",
        native_contract_id="acceptance-gc-contract",
        asset_class=AssetClassV1.FUTURE,
        tick_size=Decimal("0.25"),
        lot_size=Decimal("1"),
        currency="USD",
        session_calendar_ref="acceptance-comex-v1",
        revision="acceptance-catalog-v1",
        expiry=date(2026, 10, 9),
        last_trade=date(2026, 10, 8),
        listed_at=date(2026, 1, 1),
        roll_policy=RollPolicyV1.CALENDAR,
    )
    catalog = VenueInstrumentCatalogV1("acceptance-catalog-v1", (binding,))
    support = VenueOrderSupportV1(
        BrokerVenue.IBKR,
        BrokerEnvironment.PAPER,
        (OrderTypeV1.LIMIT,),
        (TimeInForceV1.DAY,),
    )
    admission = VenueOrderAdmissionV1(catalog, (support,), lambda: as_of[0])
    actor = open_order_gateway_actor(
        sessions,
        broker,
        reconciliation,
        _OMS_CLIENT_KEY,
        ledger_key=_OMS_INTEGRITY_KEY,
        venue_order_admission=admission,
        allow_in_memory=True,
    )
    try:
        created = await actor.create(_actor_order_request())
        as_of[0] = date(2026, 10, 8)
        with pytest.raises(OMSValidationError, match="INSTRUMENT_EXPIRED"):
            await actor.submit(
                created.order_id,
                _actor_dispatch_evidence(created.order_id, created.request),
            )
        assert broker.submit_calls == 0

        with pytest.raises(OMSValidationError, match="UNSUPPORTED_ORDER_COMBINATION"):
            await actor.create(
                _actor_order_request(
                    time_in_force="GTC", intent_idempotency_key="unsupported-tif-intent"
                )
            )
        assert broker.submit_calls == 0
    finally:
        await actor.close()
        await engine.dispose()


def test_prediction_contracts_enforce_outcome_price_and_product_scope() -> None:
    for venue in (BrokerVenue.KALSHI, BrokerVenue.POLYMARKET):
        terms = PredictionOrderTermsV1(
            PredictionOutcomeV1.YES,
            PredictionPriceV1(Decimal("63"), PredictionPriceUnitV1.CENTS),
        )
        no_terms = PredictionOrderTermsV1(
            PredictionOutcomeV1.NO,
            PredictionPriceV1(Decimal("0.37"), PredictionPriceUnitV1.PROBABILITY),
        )
        assert terms.outcome is PredictionOutcomeV1.YES
        assert no_terms.outcome is PredictionOutcomeV1.NO
        binding = VenueInstrumentBindingV1(
            instrument_id="event-1",
            venue=venue,
            environment=BrokerEnvironment.DEMO,
            venue_symbol="EVENT-YES",
            native_contract_id="market-1",
            asset_class=AssetClassV1.PREDICTION,
            tick_size=Decimal("0.01"),
            lot_size=Decimal("1"),
            currency="USD",
            session_calendar_ref="us-event-v1",
            revision="catalog-1",
            jurisdiction="US",
            product_flags=("ELIGIBILITY_REVIEW_REQUIRED",),
        )
        assert binding.jurisdiction == "US" and binding.product_flags
        with pytest.raises(ExecutionContractError, match="PREDICTION_PRODUCT_SCOPE_REQUIRED"):
            VenueInstrumentBindingV1(
                instrument_id="event-missing-scope",
                venue=venue,
                environment=BrokerEnvironment.DEMO,
                venue_symbol="EVENT-NO",
                native_contract_id="market-2",
                asset_class=AssetClassV1.PREDICTION,
                tick_size=Decimal("0.01"),
                lot_size=Decimal("1"),
                currency="USD",
                session_calendar_ref="us-event-v1",
                revision="catalog-1",
            )

    for value, unit in (
        (Decimal("101"), PredictionPriceUnitV1.CENTS),
        (Decimal("1.01"), PredictionPriceUnitV1.PROBABILITY),
    ):
        with pytest.raises(OMSValidationError, match="INVALID_PREDICTION_PRICE"):
            PredictionPriceV1(value, unit)


def test_order_type_tif_are_venue_scoped_and_bracket_oco_is_expressible() -> None:
    support = VenueOrderSupportV1(
        BrokerVenue.IBKR,
        BrokerEnvironment.PAPER,
        (OrderTypeV1.MARKET, OrderTypeV1.LIMIT),
        (TimeInForceV1.DAY, TimeInForceV1.GTC),
        bracket_via_oco=True,
    )
    assert support.bracket_via_oco
    bracket = BracketSpecV1(
        bracket_id="bracket-1",
        parent_request_digest="a" * 64,
        account_id="paper-account",
        environment="PAPER",
        instrument_id="gold",
        side="BUY",
        entry_quantity=Decimal("1"),
        take_profit_price=Decimal("2010"),
        stop_loss_price=Decimal("1990"),
        oco_mode="NATIVE",
        tick_size=Decimal("0.1"),
        lot_size=Decimal("1"),
        tif="GTC",
        policy_revision="bracket-v1",
        oco_group_id="oco-1",
    )
    assert bracket.oco_mode == "NATIVE" and bracket.oco_group_id == "oco-1"

    unsupported_type = plan_route(
        _route_input(_quote(supported_order_types=("LIMIT",), supported_tifs=("DAY",)))
    )
    assert any("ORDER_TYPE_UNSUPPORTED" in item.reason_codes for item in unsupported_type.rejected)
    unsupported_tif = plan_route(
        _route_input(_quote(supported_order_types=("MARKET",), supported_tifs=("GTC",)), tif="DAY")
    )
    assert any("TIF_UNSUPPORTED" in item.reason_codes for item in unsupported_tif.rejected)


class _FakeFxPort:
    def __init__(self) -> None:
        self.calls: list[tuple[Decimal, str, str, int]] = []

    def value_amount(
        self, amount: Decimal, source_currency: str, target_currency: str, *, as_of_ns: int
    ) -> FXValuationV1:
        self.calls.append((amount, source_currency, target_currency, as_of_ns))
        rate = Decimal("1.1")
        return FXValuationV1(
            source_currency, target_currency, amount, amount * rate, rate, as_of_ns, "a" * 64
        )


def test_account_snapshot_requires_asof_evidence_and_consistent_currency_and_fx() -> None:
    venue = _issue_venue_identity(BrokerVenue.IBKR, BrokerEnvironment.PAPER, "paper-account")
    balance = _issue_balance("USD", Decimal("1000"))
    buying_power = _issue_balance("USD", Decimal("5000"))
    equity = _issue_equity_evidence(
        "USD", Decimal("1100"), EquityEvidenceKindV1.TOTAL_EQUITY, NOW, "fake-adapter"
    )
    view = _issue_account_view(
        "paper-account",
        (),
        (),
        1,
        (),
        AS_OF,
        complete=True,
        balances=(balance,),
        broker_observed_at=AS_OF,
        equity=equity,
        venue_identity=venue,
        account_currency="USD",
        buying_power=buying_power,
    )
    snapshot = account_snapshot_from_view(view)
    assert snapshot.as_of == AS_OF and snapshot.evidence_digest == view.evidence_digest

    with pytest.raises(ExecutionContractError, match="INCOMPLETE_ACCOUNT_SNAPSHOT"):
        account_snapshot_from_view(
            _issue_account_view("paper-account", (), (), 2, (), AS_OF, complete=True)
        )
    from dataclasses import replace

    with pytest.raises(ExecutionContractError, match="INVALID_ACCOUNT_SNAPSHOT"):
        replace(snapshot, currency="EUR")
    with pytest.raises(ExecutionContractError, match="INVALID_ACCOUNT_SNAPSHOT"):
        replace(snapshot, as_of=None)
    with pytest.raises(ExecutionContractError, match="INVALID_ACCOUNT_SNAPSHOT"):
        replace(snapshot, cash_balances=(_issue_balance("EUR", Decimal("1000")),))

    fx = _FakeFxPort()
    value = fx.value_amount(Decimal("10"), "EUR", "USD", as_of_ns=NOW)
    assert value.target_amount == Decimal("11")
    assert fx.calls == [(Decimal("10"), "EUR", "USD", NOW)]
    with pytest.raises(ExecutionContractError, match="FX_VALUATION_MISMATCH"):
        FXValuationV1("EUR", "USD", Decimal("10"), Decimal("12"), Decimal("1.1"), NOW, "a" * 64)


def test_mass_cancel_distinguishes_complete_partial_and_unknown_outcomes() -> None:
    partial = issue_mass_cancel_result(
        MassCancelResultV1(
            request_idempotency_key="cancel-1",
            results=(),
            start_index=0,
            next_index=1,
            complete=False,
        )
    )
    full = issue_mass_cancel_result(
        MassCancelResultV1(
            request_idempotency_key="cancel-2",
            results=(),
            start_index=0,
            next_index=None,
            complete=True,
        )
    )
    unknown = issue_mass_cancel_result(
        MassCancelResultV1(
            request_idempotency_key="cancel-3",
            results=(
                CancelResultV1(
                    order_id="order-1",
                    idempotency_key="cancel-order-1",
                    lifecycle_state="CANCEL_REQUESTED_UNCONFIRMED",
                    oms_state="UNKNOWN_CANCEL",
                    reason_code="TRANSPORT_UNCERTAIN",
                    child_dispatch_stopped=True,
                    cancel_sent=True,
                    reconciled=False,
                    discrepancy_codes=(),
                    operator_alert_codes=(),
                    fill_execution_ids=(),
                ),
            ),
            start_index=0,
            next_index=None,
            complete=True,
        )
    )
    assert summarize_mass_cancel(partial) is MassCancelCompletionV1.IN_PROGRESS
    assert summarize_mass_cancel(full) is MassCancelCompletionV1.COMPLETE
    assert summarize_mass_cancel(unknown) is MassCancelCompletionV1.COMPLETE_WITH_UNCONFIRMED


def test_legacy_fake_mapping_contracts_remain_exact() -> None:
    alpaca = alpaca_binding(
        AlpacaAssetV1("spy", "asset-spy", "SPY", Decimal("0.01"), Decimal("1")),
        revision="alpaca-r1",
        currency="USD",
        session_calendar_ref="us-equity-v1",
    )
    assert (alpaca.venue, alpaca.venue_symbol, alpaca.native_contract_id) == (
        BrokerVenue.ALPACA,
        "SPY",
        "asset-spy",
    )
    assert BrokerVenue.IBKR_TWS.value == "IBKR_TWS"
    assert BrokerVenue.MT5.value == "MT5"
