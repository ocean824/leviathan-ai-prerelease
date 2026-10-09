"""Focused bounded paper reconciliation tests."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from decimal import Decimal

from leviathan_core.execution.broker_port_v1 import (
    AccountViewV1,
    BrokerEnvironment,
    BrokerOutcomeUnknown,
    BrokerUnknownCode,
    BrokerVenue,
    VenueIdentityV1,
    _issue_account_view,
    _issue_execution,
    _issue_venue_identity,
)
from leviathan_core.execution.order_models import Fill, OrderRequest, OrderSnapshot, OrderState
from leviathan_core.execution.reconciliation import (
    LocalLedgerEvidenceV1,
    ReconcileResultV1,
    ReconcileStatus,
    RecordedExecutionV1,
    build_broker_snapshot,
    reconcile_account,
    reconcile_once,
    record_operator_resolution,
)
from leviathan_core.seal import require

_TIME = datetime(2026, 10, 5, tzinfo=UTC)


def _venue(environment: BrokerEnvironment = BrokerEnvironment.PAPER) -> VenueIdentityV1:
    return _issue_venue_identity(BrokerVenue.ALPACA, environment, "account-1")


def _view(*, quantity: Decimal | None = None) -> AccountViewV1:
    executions = ()
    if quantity is not None:
        executions = (
            _issue_execution(
                "execution-1",
                "native-1",
                "client-1",
                "AAPL",
                "BUY",
                quantity,
                Decimal("2"),
                _TIME,
            ),
        )
    return _issue_account_view("account-1", (), (), 1, executions, _TIME, complete=True)


def _request() -> OrderRequest:
    return OrderRequest(
        project_id="leviathan-ai",
        environment="paper",
        account_id="account-1",
        venue="ALPACA",
        instrument_id="AAPL",
        native_contract_id="asset-aapl",
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
        capability="paper-submit",
    )


def _ledger(*, execution: bool = False) -> LocalLedgerEvidenceV1:
    orders = ()
    executions = ()
    if execution:
        orders = (
            OrderSnapshot(
                "order-1",
                _request(),
                OrderState.FILLED,
                1,
                "native-1",
                Decimal("1"),
                (),
                True,
                False,
            ),
        )
        executions = (
            RecordedExecutionV1(
                "order-1",
                Fill("ALPACA", "account-1", "execution-1", Decimal("1"), Decimal("2"), _TIME),
            ),
        )
    return LocalLedgerEvidenceV1(
        BrokerEnvironment.PAPER,
        "account-1",
        orders,
        executions,
        (),
        1,
        venue=BrokerVenue.ALPACA,
    )


def test_empty_exact_paper_account_is_matched_but_unverified() -> None:
    venue = _venue()
    snapshot = build_broker_snapshot(_view(), venue, observed_at_ns=100)
    result = reconcile_account(snapshot, _ledger(), venue, now_ns=110, max_age_ns=10)
    require(result, "execution.reconciliation")
    assert result.account_status is ReconcileStatus.MATCHED
    assert not result.submission_blocked
    assert result.balances_status == "UNVERIFIED"
    assert result.session_status == "UNVERIFIED"
    assert result.observation_source == "LOCAL_OBSERVED_AT"


def test_exact_age_bound_and_wrong_account_block() -> None:
    venue = _venue()
    snapshot = build_broker_snapshot(_view(), venue, observed_at_ns=100)
    assert not reconcile_account(
        snapshot, _ledger(), venue, now_ns=110, max_age_ns=10
    ).submission_blocked
    stale = reconcile_account(snapshot, _ledger(), venue, now_ns=111, max_age_ns=10)
    assert stale.account_status is ReconcileStatus.UNKNOWN
    assert "STALE_LOCAL_OBSERVATION" in stale.divergence_codes
    wrong = _issue_venue_identity(BrokerVenue.ALPACA, BrokerEnvironment.PAPER, "other-account")
    mismatch = reconcile_account(snapshot, _ledger(), wrong, now_ns=100, max_age_ns=10)
    assert mismatch.account_status is ReconcileStatus.UNKNOWN
    assert mismatch.submission_blocked


def test_execution_correction_yields_compensating_event_and_operator_record() -> None:
    venue = _venue()
    snapshot = build_broker_snapshot(_view(quantity=Decimal("2")), venue, observed_at_ns=100)
    result = reconcile_account(snapshot, _ledger(execution=True), venue, now_ns=100, max_age_ns=10)
    assert result.account_status is ReconcileStatus.CONFLICT
    assert result.compensating_events[0].kind == "CORRECTION"
    assert result.compensating_events[0].prior_quantity == Decimal("1")
    assert result.compensating_events[0].revised_quantity == Decimal("2")
    resolution = record_operator_resolution(
        result, actor_id="operator-1", reason="broker-correction", evidence_digest="b" * 64
    )
    require(resolution, "execution.reconciliation")
    assert resolution.actor_id == "operator-1"
    assert result.submission_blocked


def test_bust_is_not_a_silent_close() -> None:
    venue = _venue()
    snapshot = build_broker_snapshot(_view(), venue, observed_at_ns=100)
    result = reconcile_account(snapshot, _ledger(execution=True), venue, now_ns=100, max_age_ns=10)
    assert result.submission_blocked
    assert result.compensating_events[0].kind == "BUST"
    assert result.compensating_events[0].revised_quantity == 0


class _UnknownBroker:
    def __init__(self) -> None:
        self.venue = _venue()
        self.submit_calls = 0
        self.cancel_calls = 0

    def read_account_view(self, account_id: str) -> AccountViewV1:
        raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_ACCOUNT_VIEW)


class _LedgerPort:
    def __init__(self) -> None:
        self.appended: list[ReconcileResultV1] = []

    async def account_evidence(
        self, environment: BrokerEnvironment, account_id: str
    ) -> LocalLedgerEvidenceV1:
        return _ledger()

    async def append_reconciliation(
        self, result: ReconcileResultV1, *, expected_ledger_revision: int
    ) -> None:
        assert expected_ledger_revision == 1
        self.appended.append(result)


def test_incomplete_read_appends_unknown_without_broker_side_effects() -> None:
    broker = _UnknownBroker()
    ledger = _LedgerPort()
    result = asyncio.run(
        reconcile_once(broker, ledger, broker.venue, observed_at_ns=100, now_ns=100, max_age_ns=10)
    )
    assert result.account_status is ReconcileStatus.UNKNOWN
    assert result.submission_blocked
    assert result.snapshot_digest is None
    assert ledger.appended == [result]
    assert broker.submit_calls == broker.cancel_calls == 0
