from __future__ import annotations

import copy
import pickle
from datetime import UTC, datetime
from decimal import Decimal

import pytest

from leviathan_core.execution.broker_port import FakeBrokerPort
from leviathan_core.execution.broker_port_v1 import (
    AccountViewV1,
    BrokerEnvironment,
    BrokerPortError,
    EquityEvidenceKindV1,
    EquityEvidenceV1,
    _digest,
    _issue_account_view,
    _issue_equity_evidence,
)
from leviathan_core.execution.broker_reconciliation import FakeBrokerReconciliation
from leviathan_core.execution.brokers.alpaca_mapping import (
    AlpacaAssetMapV1,
    AlpacaAssetV1,
)
from leviathan_core.execution.brokers.alpaca_paper import (
    AlpacaAccountRecordV1,
    AlpacaBaseUrlIdentity,
    AlpacaPaperBrokerPortV1,
    AlpacaSessionBindingV1,
    FakeAlpacaOMSEvidence,
    RecordedAlpacaTransport,
)
from leviathan_core.execution.brokers.mt5_demo import (
    FakeMT5OMSEvidence,
    FakeMT5Transport,
    MT5DemoBrokerPortV1,
    MT5NativeAccountViewV1,
    MT5QuoteV1,
    MT5SessionBindingV1,
    MT5TerminalSnapshotV1,
)
from leviathan_core.execution.brokers.mt5_mapping import MT5SymbolSpecV1

_ACCOUNT = "synthetic-account"
_SINCE = datetime(2026, 10, 1, tzinfo=UTC)
_V13_EMPTY_DIGEST = "52f3bf57435bf35e72bbcb96613d776d6d8d831250dbd0a6dd2133bd591b754e"
_FAKE_NOW_NS = 1_000_000_000_000


def _equity(
    amount: object = Decimal("1234.5600"),
    kind: EquityEvidenceKindV1 = EquityEvidenceKindV1.NET_LIQUIDATION,
) -> EquityEvidenceV1:
    return _issue_equity_evidence(
        "USD",
        amount,
        kind,
        123456789,
        "synthetic-provider-v1",
    )


def _view(*, equity: EquityEvidenceV1 | None = None) -> AccountViewV1:
    return _issue_account_view(
        _ACCOUNT,
        (),
        (),
        1,
        (),
        _SINCE,
        complete=True,
        equity=equity,
    )


def _mt5_account_view() -> AccountViewV1:
    server = "FOREXcom-Demo"
    account_id = "demo-equity-01"
    now_ns = _FAKE_NOW_NS
    binding = MT5SessionBindingV1(
        project_id="leviathan-ai",
        environment="development",
        provider="FOREX.com",
        mode="DEMO",
        server=server,
        account_id=account_id,
        terminal_agent_id="synthetic-ea-1",
        protocol="FAKE_MT5_EA",
        protocol_version="1",
        mapping_revision="map-v1",
        broker_timezone="UTC",
        calendar_id="synthetic-weekly-calendar",
        trade_allowed=True,
        max_heartbeat_age_ns=1_000_000_000,
        max_quote_age_ns=500_000_000,
    )
    quote = MT5QuoteV1(
        native_symbol="EURUSD.demo",
        bid=Decimal("1.10000"),
        ask=Decimal("1.10002"),
        observed_ns=now_ns - 100_000_000,
    )
    snapshot = MT5TerminalSnapshotV1(
        server=server,
        account_id=account_id,
        mode="DEMO",
        terminal_agent_id="synthetic-ea-1",
        protocol="FAKE_MT5_EA",
        protocol_version="1",
        mapping_revision="map-v1",
        broker_timezone="UTC",
        calendar_id="synthetic-weekly-calendar",
        connected=True,
        trade_allowed=True,
        heartbeat_at_ns=now_ns - 100_000_000,
        broker_clock_skew_ms=0,
        session_open=True,
        news_blackout=False,
        margin_confirmed=True,
        calendar_ambiguous=False,
        quote=quote,
        broker_revision=7,
    )
    transport = FakeMT5Transport(snapshot)
    transport.queue_account_view(
        MT5NativeAccountViewV1(
            server=server,
            account_id=account_id,
            mode="DEMO",
            open_orders=(),
            deals=(),
            positions=(("EURUSD", Decimal("0")),),
            broker_revision=7,
            observed_ns=now_ns - 100_000_000,
            orders_complete=True,
            deals_complete=True,
            positions_complete=True,
            executions_since=datetime.fromtimestamp(0, UTC),
        )
    )
    adapter = MT5DemoBrokerPortV1(
        binding=binding,
        symbols=(
            MT5SymbolSpecV1(
                instrument_id="EURUSD",
                native_contract_id="EURUSD.demo",
                native_symbol="EURUSD.demo",
                revision="map-v1",
                contract_size=Decimal("100000"),
                lot_min=Decimal("0.01"),
                lot_max=Decimal("10"),
                lot_step=Decimal("0.01"),
                point=Decimal("0.00001"),
                tick_size=Decimal("0.00001"),
                digits=5,
                stops_level_points=10,
            ),
        ),
        transport=transport,
        oms_evidence=FakeMT5OMSEvidence(),
        clock_ns=lambda: now_ns,
        settle_window_ms=2_000,
    )
    return adapter.read_account_view(account_id)


def _alpaca_account_view() -> AccountViewV1:
    account_id = "synthetic-paper-account-01"
    binding = AlpacaSessionBindingV1(
        account_id=account_id,
        mapping_revision="synthetic-map-v1",
        calendar_revision="synthetic-calendar-v1",
        environment=BrokerEnvironment.PAPER,
        base_url_identity=AlpacaBaseUrlIdentity.PAPER,
    )
    assets = AlpacaAssetMapV1(
        revision="synthetic-map-v1",
        assets=(
            AlpacaAssetV1(
                instrument_id="equity-AAPL",
                asset_id="asset-AAPL",
                symbol="AAPL",
                tick_size=Decimal("0.01"),
                lot_size=Decimal("1"),
                round_quantity_toward_zero=False,
            ),
        ),
    )
    observed_at = datetime(2026, 10, 5, 15, tzinfo=UTC)
    transport = RecordedAlpacaTransport()
    transport.queue_account(
        AlpacaAccountRecordV1(
            account_id=account_id,
            broker_revision=10,
            open_orders=(),
            positions=(),
            observed_at=observed_at,
            venue_time_ns=100,
            executions_since=datetime(2026, 10, 5, 14, 59, tzinfo=UTC),
        )
    )
    adapter = AlpacaPaperBrokerPortV1(
        binding,
        assets,
        transport,
        oms_evidence=FakeAlpacaOMSEvidence(),
        clock_ns=lambda: 100,
    )
    return adapter.read_account_view(account_id)


def test_equity_evidence_is_issued_only_and_forgery_or_tampering_fails_closed() -> None:
    with pytest.raises(BrokerPortError) as direct:
        EquityEvidenceV1(
            "USD",
            Decimal("100"),
            EquityEvidenceKindV1.TOTAL_EQUITY,
            0,
            "fake-broker-v1",
        )
    assert direct.value.code == "UNISSUED_BROKER_RECORD"

    forged = object.__new__(EquityEvidenceV1)
    with pytest.raises(BrokerPortError) as forged_error:
        forged.assert_sealed()
    assert forged_error.value.code == "UNISSUED_BROKER_RECORD"

    evidence = _equity()
    assert evidence.amount == Decimal("1234.5600")
    evidence.assert_sealed()
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(BrokerPortError):
            operation(evidence)

    containing_view = _view(equity=evidence)
    object.__setattr__(evidence, "amount", Decimal("9999"))
    with pytest.raises(BrokerPortError) as tampered_evidence:
        evidence.assert_sealed()
    assert tampered_evidence.value.code == "BROKER_RECORD_TAMPERED"
    with pytest.raises(BrokerPortError) as tampered_view:
        containing_view.assert_sealed()
    assert tampered_view.value.code == "BROKER_RECORD_TAMPERED"


@pytest.mark.parametrize(
    "amount",
    [
        100,
        100.0,
        True,
        "100",
        Decimal("NaN"),
        Decimal("Infinity"),
    ],
)
def test_equity_amount_requires_finite_exact_decimal_num(amount: object) -> None:
    with pytest.raises(BrokerPortError) as error:
        _equity(amount)
    assert error.value.code == "INVALID_EQUITY_EVIDENCE"


def test_equity_kind_is_closed_to_the_two_declared_semantics() -> None:
    assert {kind.value for kind in EquityEvidenceKindV1} == {
        "NET_LIQUIDATION",
        "TOTAL_EQUITY",
    }
    for kind in EquityEvidenceKindV1:
        evidence = _equity(Decimal("125.75"), kind)
        assert evidence.kind is kind
        evidence.assert_sealed()

    for invalid_kind in ("CASH_BALANCE", None):
        with pytest.raises(BrokerPortError) as error:
            _issue_equity_evidence(
                "USD",
                Decimal("125.75"),
                invalid_kind,  # type: ignore[arg-type]
                123456789,
                "synthetic-provider-v1",
            )
        assert error.value.code == "INVALID_EQUITY_EVIDENCE"


def test_v13_account_view_shape_and_digest_are_unchanged_when_equity_is_absent() -> None:
    legacy = _issue_account_view(_ACCOUNT, (), (), 1, (), _SINCE, complete=True)
    explicit_none = _issue_account_view(
        _ACCOUNT,
        (),
        (),
        1,
        (),
        _SINCE,
        complete=True,
        equity=None,
    )

    assert legacy.equity is None
    assert explicit_none.equity is None
    assert legacy.seal_payload() == explicit_none.seal_payload()
    assert _digest(legacy).hex() == _V13_EMPTY_DIGEST
    assert _digest(explicit_none).hex() == _V13_EMPTY_DIGEST
    legacy.assert_sealed()
    explicit_none.assert_sealed()


def test_fake_broker_emits_deterministic_declared_equity_evidence() -> None:
    first_port = FakeBrokerPort(
        FakeBrokerReconciliation(),
        account_id="fake-equity-account",
    )
    second_port = FakeBrokerPort(
        FakeBrokerReconciliation(),
        account_id="fake-equity-account",
    )

    first_view = first_port.read_account_view("fake-equity-account")
    second_view = second_port.read_account_view("fake-equity-account")

    assert first_view.equity is not None
    assert second_view.equity is not None
    for evidence in (first_view.equity, second_view.equity):
        evidence.assert_sealed()
        assert evidence.currency == "USD"
        assert evidence.amount == Decimal("100000")
        assert evidence.kind is EquityEvidenceKindV1.TOTAL_EQUITY
        assert evidence.broker_observed_at_ns == 0
        assert evidence.semantics_declared_by == "fake-broker-v1"
    assert first_view.equity == second_view.equity
    assert _digest(first_view.equity) == _digest(second_view.equity)


def test_alpaca_paper_account_view_does_not_claim_equity_semantics() -> None:
    view = _alpaca_account_view()

    assert view.equity is None
    view.assert_sealed()


def test_mt5_demo_account_view_does_not_claim_equity_semantics() -> None:
    view = _mt5_account_view()

    assert view.equity is None
    view.assert_sealed()
