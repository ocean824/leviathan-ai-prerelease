"""Shared SEAL adoption contract for broker-port records."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any, cast

import pytest

from leviathan_core.execution.broker_port_v1 import (
    BrokerEnvironment,
    BrokerPortError,
    BrokerVenue,
    EquityEvidenceKindV1,
    _issue_account_view,
    _issue_balance,
    _issue_cancel_result,
    _issue_equity_evidence,
    _issue_execution,
    _issue_submit_result,
    _issue_venue_capability,
    _issue_venue_identity,
    require_account_view,
    require_balance,
    require_cancel_result,
    require_equity_evidence,
    require_execution,
    require_submit_result,
    require_venue_dispatch_capability,
    require_venue_identity,
)
from leviathan_core.execution.order_models import OrderState


def _issued_records() -> tuple[tuple[object, Callable[[object], object]], ...]:
    since = datetime(2026, 10, 1, tzinfo=UTC)
    execution = _issue_execution(
        "execution-1",
        "venue-order-1",
        "client-order-1",
        "AAPL",
        "BUY",
        Decimal("1"),
        Decimal("10.25"),
        since,
    )
    balance = _issue_balance("USD", Decimal("123.45"))
    equity = _issue_equity_evidence(
        "USD", Decimal("123.45"), EquityEvidenceKindV1.TOTAL_EQUITY, 123, "test-adapter-v1"
    )
    account = _issue_account_view(
        "account-1",
        (),
        (),
        1,
        (execution,),
        since,
        complete=True,
        balances=(balance,),
        equity=equity,
    )
    return (
        (_issue_venue_capability(True), require_venue_dispatch_capability),
        (
            _issue_venue_identity(BrokerVenue.ALPACA, BrokerEnvironment.PAPER, "account-1"),
            require_venue_identity,
        ),
        (_issue_submit_result("venue-order-1", OrderState.WORKING), require_submit_result),
        (_issue_cancel_result(True), require_cancel_result),
        (execution, require_execution),
        (balance, require_balance),
        (equity, require_equity_evidence),
        (account, require_account_view),
    )


def test_every_broker_record_uses_its_exact_typed_shared_seal_helper() -> None:
    for record, require_typed in _issued_records():
        assert require_typed(record) is record
        cast(Any, record).assert_sealed()


def test_typed_helpers_reject_wrong_type_and_unissued_instances() -> None:
    records = _issued_records()
    for index, (_record, require_typed) in enumerate(records):
        wrong_type = records[(index + 1) % len(records)][0]
        with pytest.raises(BrokerPortError, match="UNISSUED_BROKER_RECORD"):
            require_typed(wrong_type)
        with pytest.raises(BrokerPortError, match="UNISSUED_BROKER_RECORD"):
            require_typed(object())
