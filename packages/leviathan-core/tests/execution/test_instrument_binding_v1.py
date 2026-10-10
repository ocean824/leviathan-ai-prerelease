from __future__ import annotations

import copy
import pickle
from dataclasses import replace
from datetime import UTC, date, datetime
from decimal import Decimal
from typing import cast

import pytest

from leviathan_core.execution.broker_port_v1 import (
    BrokerEnvironment,
    BrokerVenue,
    EquityEvidenceKindV1,
    _issue_account_view,
    _issue_balance,
    _issue_equity_evidence,
    _issue_venue_identity,
    require_account_view,
)
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
    AccountSnapshotV1,
    AssetClassV1,
    ExecutionContractError,
    FXValuationV1,
    MassCancelCompletionV1,
    RollPolicyV1,
    VenueInstrumentBindingV1,
    VenueInstrumentCatalogV1,
    VenueOrderSupportV1,
    account_snapshot_from_view,
    require_tradeable,
    summarize_mass_cancel,
    validate_venue_order_request,
)
from leviathan_core.execution.order_models import (
    OMSValidationError,
    OrderRequest,
    OrderTypeV1,
    PredictionOrderTermsV1,
    PredictionOutcomeV1,
    PredictionPriceUnitV1,
    PredictionPriceV1,
    TimeInForceV1,
)

_NOW = datetime(2026, 10, 9, tzinfo=UTC)


def _binding(
    venue: BrokerVenue,
    symbol: str,
    *,
    asset_class: AssetClassV1 = AssetClassV1.METAL,
    contract_id: str | None = None,
    instrument_id: str = "gold",
    jurisdiction: str | None = None,
    product_flags: tuple[str, ...] = (),
) -> VenueInstrumentBindingV1:
    return VenueInstrumentBindingV1(
        instrument_id=instrument_id,
        venue=venue,
        environment=BrokerEnvironment.DEMO,
        venue_symbol=symbol,
        native_contract_id=contract_id or symbol,
        asset_class=asset_class,
        tick_size=Decimal("0.01"),
        lot_size=Decimal("1"),
        currency="USD",
        session_calendar_ref="calendar-us-metals-v1",
        revision="catalog-1",
        contract_multiplier=Decimal("100"),
        expiry=date(2026, 12, 28) if venue is BrokerVenue.IBKR else None,
        roll_policy=RollPolicyV1.CALENDAR if venue is BrokerVenue.IBKR else RollPolicyV1.NONE,
        jurisdiction=jurisdiction,
        product_flags=product_flags,
    )


def test_catalog_round_trip_resolves_per_venue_and_rolls_are_explicit() -> None:
    gc = _binding(BrokerVenue.IBKR, "GCZ6", contract_id="gc-dec-2026")
    mgc = _binding(
        BrokerVenue.IBKR, "MGCZ6", contract_id="mgc-dec-2026", instrument_id="gold.micro"
    )
    forex = _binding(BrokerVenue.MT5_FOREXCOM, "XAUUSD", contract_id="forex-gold")
    catalog = VenueInstrumentCatalogV1("catalog-1", (gc, mgc, forex))

    assert catalog.resolve("gold", BrokerVenue.IBKR, BrokerEnvironment.DEMO) == (gc,)
    assert catalog.resolve("gold.micro", BrokerVenue.IBKR, BrokerEnvironment.DEMO) == (mgc,)
    assert catalog.resolve("gold", BrokerVenue.MT5_FOREXCOM, BrokerEnvironment.DEMO) == (forex,)
    assert catalog.resolve("gold", BrokerVenue.ALPACA, BrokerEnvironment.PAPER) == ()
    assert (
        catalog.resolve_for_month(
            "gold", BrokerVenue.IBKR, BrokerEnvironment.DEMO, expiry=date(2026, 12, 28)
        )
        is gc
    )
    with pytest.raises(TypeError, match="EXECUTION_CONTRACT_COPY_FORBIDDEN"):
        copy.copy(catalog)
    with pytest.raises(TypeError, match="EXECUTION_CONTRACT_PICKLE_FORBIDDEN"):
        pickle.dumps(catalog)


def test_catalog_rejects_native_and_internal_month_collisions() -> None:
    same_native_a = _binding(BrokerVenue.KALSHI, "MKT-1", contract_id="native-1")
    same_native_b = _binding(
        BrokerVenue.KALSHI, "MKT-1", contract_id="native-alias-2", instrument_id="event-b"
    )
    with pytest.raises(ExecutionContractError, match="CONFLICTING_VENUE_INSTRUMENT_BINDING"):
        VenueInstrumentCatalogV1("catalog-1", (same_native_a, same_native_b))

    # Metadata differences must not make a venue-native symbol look unique.
    gold_xau = _binding(
        BrokerVenue.MT5_FOREXCOM,
        "XAUUSD",
        instrument_id="gold",
        contract_id="xau-gold",
    )
    silver_xau = replace(
        gold_xau,
        instrument_id="silver",
        native_contract_id="xau-silver",
        tick_size=Decimal("0.05"),
    )
    with pytest.raises(ExecutionContractError, match="CONFLICTING_VENUE_INSTRUMENT_BINDING"):
        VenueInstrumentCatalogV1("catalog-1", (gold_xau, silver_xau))

    same_month_a = _binding(BrokerVenue.IBKR, "GCZ6", contract_id="gc-dec-2026")
    same_month_b = _binding(BrokerVenue.IBKR, "MGCZ6", contract_id="mgc-dec-2026")
    with pytest.raises(ExecutionContractError, match="AMBIGUOUS_INSTRUMENT_BINDING"):
        VenueInstrumentCatalogV1("catalog-1", (same_month_a, same_month_b))

    next_month = replace(
        same_month_a,
        venue_symbol="GCG7",
        native_contract_id="gc-jan-2027",
        expiry=date(2027, 1, 28),
    )
    month_catalog = VenueInstrumentCatalogV1("catalog-1", (same_month_a, next_month))
    assert (
        month_catalog.resolve_for_month(
            "gold", BrokerVenue.IBKR, BrokerEnvironment.DEMO, expiry=date(2027, 1, 28)
        )
        is next_month
    )
    with pytest.raises(ExecutionContractError, match="INSTRUMENT_BINDING_NOT_UNIQUE"):
        month_catalog.resolve_for_month(
            "gold", BrokerVenue.IBKR, BrokerEnvironment.DEMO, expiry=None
        )


def test_binding_rejects_implicit_or_invalid_product_and_roll_metadata() -> None:
    with pytest.raises(ExecutionContractError, match="INVALID_ROLL_METADATA"):
        VenueInstrumentBindingV1(
            "gold",
            BrokerVenue.IBKR,
            BrokerEnvironment.PAPER,
            "GCZ6",
            "gc-dec-2026",
            AssetClassV1.FUTURE,
            Decimal("0.1"),
            Decimal("1"),
            "USD",
            "calendar-comex-v1",
            "r1",
            expiry=date(2026, 12, 28),
        )
    with pytest.raises(ExecutionContractError, match="PREDICTION_PRODUCT_SCOPE_REQUIRED"):
        VenueInstrumentBindingV1(
            instrument_id="event-1",
            venue=BrokerVenue.KALSHI,
            environment=BrokerEnvironment.DEMO,
            venue_symbol="EVENT-YES",
            native_contract_id="market-1",
            asset_class=AssetClassV1.PREDICTION,
            tick_size=Decimal("0.01"),
            lot_size=Decimal("1"),
            currency="USD",
            session_calendar_ref="calendar-us-v1",
            revision="catalog-1",
        )
    with pytest.raises(ExecutionContractError, match="INVALID_DECIMAL"):
        VenueInstrumentBindingV1(
            "gold",
            BrokerVenue.IBKR,
            BrokerEnvironment.PAPER,
            "GC",
            "gc",
            AssetClassV1.METAL,
            Decimal("0"),
            Decimal("1"),
            "USD",
            "calendar-us-v1",
            "r1",
        )


def test_prediction_price_keeps_unit_explicit_and_enforces_bounds() -> None:
    terms = PredictionOrderTermsV1(
        PredictionOutcomeV1.YES,
        PredictionPriceV1(Decimal("63"), PredictionPriceUnitV1.CENTS),
    )
    assert terms.outcome is PredictionOutcomeV1.YES
    assert terms.price.value == Decimal("63")
    assert terms.price.unit is PredictionPriceUnitV1.CENTS
    assert PredictionPriceV1(Decimal("0.63"), PredictionPriceUnitV1.PROBABILITY).value == Decimal(
        "0.63"
    )
    with pytest.raises(OMSValidationError, match="INVALID_PREDICTION_PRICE"):
        PredictionPriceV1(Decimal("101"), PredictionPriceUnitV1.CENTS)
    with pytest.raises(OMSValidationError, match="INVALID_PREDICTION_PRICE"):
        PredictionPriceV1(Decimal("1.01"), PredictionPriceUnitV1.PROBABILITY)
    prediction_binding = _binding(
        BrokerVenue.POLYMARKET,
        "EVENT-YES",
        asset_class=AssetClassV1.PREDICTION,
        contract_id="market-event-1",
        jurisdiction="US",
        product_flags=("ELIGIBILITY_REVIEW_REQUIRED",),
    )
    assert prediction_binding.jurisdiction == "US"
    assert prediction_binding.product_flags == ("ELIGIBILITY_REVIEW_REQUIRED",)


def test_order_support_is_environment_scoped_and_o_co_is_separate() -> None:
    profile = VenueOrderSupportV1(
        BrokerVenue.IBKR,
        BrokerEnvironment.PAPER,
        (OrderTypeV1.MARKET, OrderTypeV1.LIMIT, OrderTypeV1.STOP, OrderTypeV1.STOP_LIMIT),
        (TimeInForceV1.DAY, TimeInForceV1.GTC, TimeInForceV1.GTD),
        bracket_via_oco=True,
    )
    assert profile.bracket_via_oco is True
    assert OrderTypeV1.STOP_LIMIT in profile.order_types
    assert TimeInForceV1.GTD in profile.time_in_force
    with pytest.raises(ExecutionContractError, match="INVALID_VENUE_ORDER_SUPPORT"):
        VenueOrderSupportV1(
            BrokerVenue.IBKR,
            BrokerEnvironment.LIVE,
            (OrderTypeV1.MARKET, OrderTypeV1.MARKET),
            (TimeInForceV1.DAY,),
        )
    with pytest.raises(ExecutionContractError, match="INVALID_VENUE_ORDER_SUPPORT"):
        VenueOrderSupportV1(
            BrokerVenue.KALSHI,
            BrokerEnvironment.DEMO,
            cast(tuple[OrderTypeV1, ...], ("ARBITRARY",)),
            (TimeInForceV1.DAY,),
        )


def test_dated_binding_tradeability_uses_listing_last_trade_and_expiry() -> None:
    dated = VenueInstrumentBindingV1(
        instrument_id="gold.future",
        venue=BrokerVenue.IBKR,
        environment=BrokerEnvironment.PAPER,
        venue_symbol="GCZ6",
        native_contract_id="gc-dec-2026",
        asset_class=AssetClassV1.FUTURE,
        tick_size=Decimal("0.1"),
        lot_size=Decimal("1"),
        currency="USD",
        session_calendar_ref="calendar-comex-v1",
        revision="catalog-1",
        expiry=date(2026, 12, 28),
        last_trade=date(2026, 12, 25),
        listed_at=date(2025, 12, 1),
        roll_policy=RollPolicyV1.CALENDAR,
    )
    require_tradeable(dated, date(2026, 10, 9))
    with pytest.raises(ExecutionContractError, match="INSTRUMENT_NOT_YET_LISTED"):
        require_tradeable(dated, date(2025, 11, 30))
    with pytest.raises(ExecutionContractError, match="INSTRUMENT_EXPIRED"):
        require_tradeable(dated, date(2026, 12, 25))
    with pytest.raises(ExecutionContractError, match="INSTRUMENT_EXPIRED"):
        require_tradeable(dated, date(2026, 12, 28))
    require_tradeable(_binding(BrokerVenue.MT5_FOREXCOM, "XAUUSD"), date(1900, 1, 1))

    class Calendar:
        received: tuple[str, datetime] | None = None

        def trading_date(self, calendar_ref: str, as_of: datetime) -> date:
            self.received = (calendar_ref, as_of)
            return date(2026, 12, 25)

    calendar = Calendar()
    with pytest.raises(ExecutionContractError, match="INSTRUMENT_EXPIRED"):
        require_tradeable(
            dated,
            datetime(2026, 12, 24, 23, tzinfo=UTC),
            session_calendar=calendar,
        )
    assert calendar.received == (
        "calendar-comex-v1",
        datetime(2026, 12, 24, 23, tzinfo=UTC),
    )


def test_order_admission_enforces_identity_support_oco_and_tradeability() -> None:
    binding = VenueInstrumentBindingV1(
        instrument_id="gold.future",
        venue=BrokerVenue.IBKR,
        environment=BrokerEnvironment.PAPER,
        venue_symbol="GCZ6",
        native_contract_id="gc-dec-2026",
        asset_class=AssetClassV1.FUTURE,
        tick_size=Decimal("0.1"),
        lot_size=Decimal("1"),
        currency="USD",
        session_calendar_ref="calendar-comex-v1",
        revision="catalog-1",
        expiry=date(2026, 12, 28),
        roll_policy=RollPolicyV1.CALENDAR,
    )
    request = OrderRequest(
        project_id="leviathan-ai",
        environment="paper",
        account_id="acct-1",
        venue="IBKR",
        instrument_id="gold.future",
        native_contract_id="gc-dec-2026",
        side="BUY",
        quantity=Decimal("1"),
        order_type="MARKET",
        time_in_force="DAY",
        client_order_id="client-1",
        intent_idempotency_key="intent-1",
        attempt=1,
        strategy_id="strategy-1",
        risk_policy_digest="a" * 64,
        actor_id="actor-1",
        capability="PAPER_ORDER",
    )
    full_support = VenueOrderSupportV1(
        BrokerVenue.IBKR,
        BrokerEnvironment.PAPER,
        (OrderTypeV1.MARKET, OrderTypeV1.LIMIT),
        (TimeInForceV1.DAY, TimeInForceV1.GTC),
        bracket_via_oco=True,
    )
    validate_venue_order_request(request, binding, full_support, date(2026, 10, 9))
    validate_venue_order_request(
        request,
        binding,
        full_support,
        date(2026, 10, 9),
        bracket_or_oco=True,
    )
    unsupported = VenueOrderSupportV1(
        BrokerVenue.IBKR,
        BrokerEnvironment.PAPER,
        (OrderTypeV1.LIMIT,),
        (TimeInForceV1.GTC,),
    )
    with pytest.raises(ExecutionContractError, match="UNSUPPORTED_ORDER_COMBINATION"):
        validate_venue_order_request(request, binding, unsupported, date(2026, 10, 9))
    unsupported_tif = VenueOrderSupportV1(
        BrokerVenue.IBKR,
        BrokerEnvironment.PAPER,
        (OrderTypeV1.MARKET,),
        (TimeInForceV1.GTC,),
    )
    with pytest.raises(ExecutionContractError, match="UNSUPPORTED_ORDER_COMBINATION"):
        validate_venue_order_request(request, binding, unsupported_tif, date(2026, 10, 9))
    limited = VenueOrderSupportV1(
        BrokerVenue.IBKR,
        BrokerEnvironment.PAPER,
        (OrderTypeV1.MARKET,),
        (TimeInForceV1.DAY,),
    )
    with pytest.raises(ExecutionContractError, match="UNSUPPORTED_BRACKET_OCO"):
        validate_venue_order_request(
            request,
            binding,
            limited,
            date(2026, 10, 9),
            bracket_or_oco=True,
        )
    with pytest.raises(ExecutionContractError, match="UNSUPPORTED_BRACKET_OCO"):
        validate_venue_order_request(
            replace(request, parent_order_id="parent-1"),
            binding,
            limited,
            date(2026, 10, 9),
        )
    with pytest.raises(ExecutionContractError, match="INSTRUMENT_EXPIRED"):
        validate_venue_order_request(request, binding, full_support, date(2026, 12, 28))
    with pytest.raises(ExecutionContractError, match="ORDER_BINDING_MISMATCH"):
        validate_venue_order_request(
            replace(request, native_contract_id="other-contract"),
            binding,
            full_support,
            date(2026, 10, 9),
        )


def test_mass_cancel_reports_pagination_and_per_order_uncertainty_separately() -> None:
    partial = issue_mass_cancel_result(
        MassCancelResultV1(
            request_idempotency_key="mass-1",
            results=(),
            start_index=0,
            next_index=10,
            complete=False,
        )
    )
    unconfirmed = CancelResultV1(
        order_id="order-1",
        idempotency_key="cancel-1",
        lifecycle_state="CANCEL_REQUESTED_UNCONFIRMED",
        oms_state="UNKNOWN_CANCEL",
        reason_code="TRANSPORT_UNCERTAIN",
        child_dispatch_stopped=True,
        cancel_sent=True,
        reconciled=False,
        discrepancy_codes=(),
        operator_alert_codes=(),
        fill_execution_ids=(),
    )
    complete_with_unknown = issue_mass_cancel_result(
        MassCancelResultV1(
            request_idempotency_key="mass-2",
            results=(unconfirmed,),
            start_index=0,
            next_index=None,
            complete=True,
        )
    )
    all_cancelled = issue_mass_cancel_result(
        MassCancelResultV1(
            request_idempotency_key="mass-3",
            results=(),
            start_index=0,
            next_index=None,
            complete=True,
        )
    )
    rejected = issue_mass_cancel_result(
        MassCancelResultV1(
            request_idempotency_key="mass-4",
            results=(
                CancelResultV1(
                    order_id="order-2",
                    idempotency_key="cancel-2",
                    lifecycle_state="REJECTED",
                    oms_state=None,
                    reason_code="VENUE_REJECTED",
                    child_dispatch_stopped=True,
                    cancel_sent=True,
                    reconciled=True,
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
    terminal_unreconciled = issue_mass_cancel_result(
        MassCancelResultV1(
            request_idempotency_key="mass-5",
            results=(
                CancelResultV1(
                    order_id="order-3",
                    idempotency_key="cancel-3",
                    lifecycle_state="CANCELED",
                    oms_state="CANCELED",
                    reason_code="CANCEL_CONFIRMED",
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
    assert (
        summarize_mass_cancel(complete_with_unknown)
        is MassCancelCompletionV1.COMPLETE_WITH_UNCONFIRMED
    )
    assert summarize_mass_cancel(all_cancelled) is MassCancelCompletionV1.COMPLETE
    assert summarize_mass_cancel(rejected) is MassCancelCompletionV1.COMPLETE_WITH_REJECTIONS
    assert (
        summarize_mass_cancel(terminal_unreconciled)
        is MassCancelCompletionV1.COMPLETE_WITH_UNCONFIRMED
    )


def test_fx_evidence_requires_exact_currency_pair_and_digest() -> None:
    evidence = FXValuationV1(
        "EUR", "USD", Decimal("10"), Decimal("11"), Decimal("1.1"), 1234, "a" * 64
    )
    assert evidence.target_amount == Decimal("11")
    with pytest.raises(ExecutionContractError, match="FX_VALUATION_MISMATCH"):
        FXValuationV1("EUR", "USD", Decimal("10"), Decimal("12"), Decimal("1.1"), 1234, "a" * 64)


def test_legacy_mapping_adapters_require_missing_metadata_explicitly() -> None:
    ibkr = IBKRContractBindingV1("gold", "gc-dec-2026", 1001, "GCZ6", "FUT", "COMEX", "USD", "r1")
    converted_ibkr = ibkr_binding(
        ibkr,
        asset_class=AssetClassV1.FUTURE,
        tick_size=Decimal("0.1"),
        lot_size=Decimal("1"),
        session_calendar_ref="calendar-comex-v1",
        expiry=date(2026, 12, 28),
        listed_at=date(2025, 12, 1),
        last_trade=date(2026, 12, 25),
        roll_policy=RollPolicyV1.CALENDAR,
    )
    mt5 = MT5SymbolSpecV1(
        "gold",
        "xauusd",
        "XAUUSD",
        "r1",
        Decimal("100"),
        Decimal("0.01"),
        Decimal("100"),
        Decimal("0.01"),
        Decimal("0.01"),
        Decimal("0.01"),
        2,
        0,
    )
    converted_mt5 = mt5_binding(
        mt5,
        asset_class=AssetClassV1.METAL,
        currency="USD",
        session_calendar_ref="calendar-forex-v1",
    )
    alpaca = AlpacaAssetV1("spy", "asset-spy", "SPY", Decimal("0.01"), Decimal("1"))
    converted_alpaca = alpaca_binding(
        alpaca,
        revision="alpaca-map-r1",
        currency="USD",
        session_calendar_ref="calendar-us-equity-v1",
    )
    assert (converted_ibkr.venue, converted_ibkr.venue_symbol) == (BrokerVenue.IBKR, "GCZ6")
    assert converted_ibkr.listed_at == date(2025, 12, 1)
    assert converted_ibkr.last_trade == date(2026, 12, 25)
    assert (converted_mt5.venue, converted_mt5.venue_symbol) == (
        BrokerVenue.MT5_FOREXCOM,
        "XAUUSD",
    )
    assert (converted_alpaca.venue, converted_alpaca.venue_symbol) == (BrokerVenue.ALPACA, "SPY")


def test_account_view_additions_are_sealed_and_legacy_payload_stays_valid() -> None:
    old_view = require_account_view(
        _issue_account_view("acct-1", (), (), 1, (), _NOW, complete=True)
    )
    identity = _issue_venue_identity(BrokerVenue.IBKR, BrokerEnvironment.PAPER, "acct-1")
    cash = _issue_balance("USD", Decimal("1000"))
    buying_power = _issue_balance("USD", Decimal("5000"))
    equity = _issue_equity_evidence(
        "USD", Decimal("1100"), EquityEvidenceKindV1.TOTAL_EQUITY, 10, "broker-adapter"
    )
    view = require_account_view(
        _issue_account_view(
            "acct-1",
            (),
            (),
            2,
            (),
            _NOW,
            complete=True,
            balances=(cash,),
            broker_observed_at=_NOW,
            equity=equity,
            venue_identity=identity,
            account_currency="USD",
            buying_power=buying_power,
        )
    )
    assert view.venue_identity is identity
    assert view.account_currency == "USD"
    assert view.balances == (cash,)
    assert view.buying_power is buying_power
    assert len(view.evidence_digest) == 64
    assert old_view.evidence_digest != view.evidence_digest
    snapshot = account_snapshot_from_view(view)
    assert type(snapshot) is AccountSnapshotV1
    assert snapshot.cash_balances == (cash,)
    assert snapshot.equity is equity
    assert snapshot.buying_power is buying_power
    assert snapshot.as_of == _NOW
    assert snapshot.evidence_digest == view.evidence_digest

    with pytest.raises(ExecutionContractError, match="INCOMPLETE_ACCOUNT_SNAPSHOT"):
        account_snapshot_from_view(old_view)
    no_cash_evidence = require_account_view(
        _issue_account_view(
            "acct-1",
            (),
            (),
            3,
            (),
            _NOW,
            complete=True,
            balances=(),
            broker_observed_at=_NOW,
            equity=equity,
            venue_identity=identity,
            account_currency="USD",
            buying_power=buying_power,
        )
    )
    with pytest.raises(ExecutionContractError, match="INCOMPLETE_ACCOUNT_SNAPSHOT"):
        account_snapshot_from_view(no_cash_evidence)
