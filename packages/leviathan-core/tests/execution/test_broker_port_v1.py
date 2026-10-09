"""BROKER-PORT-001 type, seal, and Protocol contract tests."""

from __future__ import annotations

import copy
import gc
import pickle
from dataclasses import fields, replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import cast

import pytest

from leviathan_core.execution import order_models
from leviathan_core.execution.broker_port import FakeBrokerPort
from leviathan_core.execution.broker_port_v1 import (
    AccountViewV1,
    BrokerEnvironment,
    BrokerOutcomeUnknown,
    BrokerPortError,
    BrokerPortV1,
    BrokerRejected,
    BrokerRejectionCode,
    BrokerUnknownCode,
    BrokerVenue,
    CancelResultV1,
    ExecutionV1,
    OrderRequest,
    OrderSnapshot,
    SubmitResultV1,
    VenueDispatchCapabilityV1,
    VenueIdentityV1,
    _issue_account_view,
    _issue_cancel_result,
    _issue_execution,
    _issue_submit_result,
    _issue_venue_capability,
    _issue_venue_identity,
)
from leviathan_core.execution.order_models import BrokerObservation, OrderState


def test_closed_venue_identity_and_capability() -> None:
    venue = _issue_venue_identity(BrokerVenue.ALPACA, BrokerEnvironment.PAPER, "acct-1")
    atomic = _issue_venue_capability(True)
    non_atomic = _issue_venue_capability(False, timedelta(seconds=2))
    for value in (venue, atomic, non_atomic):
        value.assert_sealed()
        assert "acct-1" not in repr(value)
    with pytest.raises(BrokerPortError):
        VenueIdentityV1(BrokerVenue.ALPACA, BrokerEnvironment.PAPER, "acct-1")
    with pytest.raises(BrokerPortError):
        VenueDispatchCapabilityV1(True)
    with pytest.raises(BrokerPortError):
        _issue_venue_identity(cast(BrokerVenue, "ALPACA"), BrokerEnvironment.PAPER, "acct-1")
    with pytest.raises(BrokerPortError):
        _issue_venue_capability(False, None)
    with pytest.raises(BrokerPortError):
        _issue_venue_capability(True, timedelta(seconds=1))
    with pytest.raises(BrokerPortError):
        _issue_venue_capability(cast(bool, 1))


def test_result_validation_and_closed_content_free_errors() -> None:
    working = _issue_submit_result("venue-order-1", OrderState.WORKING)
    rejected = _issue_submit_result(
        None, OrderState.REJECTED, BrokerRejectionCode.DUPLICATE_CLIENT_ORDER_ID
    )
    cancel = _issue_cancel_result(False)
    for value in (working, rejected, cancel):
        value.assert_sealed()
    assert rejected.rejection_code is BrokerRejectionCode.DUPLICATE_CLIENT_ORDER_ID
    with pytest.raises(BrokerPortError):
        SubmitResultV1("venue-order-1", OrderState.WORKING)
    with pytest.raises(BrokerPortError):
        _issue_submit_result(None, OrderState.WORKING)
    with pytest.raises(BrokerPortError):
        _issue_submit_result("order", OrderState.REJECTED, BrokerRejectionCode.INVALID_ORDER)
    with pytest.raises(BrokerPortError):
        _issue_cancel_result(cast(bool, "false"))
    assert str(BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_SUBMIT)) == "UNKNOWN_SUBMIT"
    assert str(BrokerRejected(BrokerRejectionCode.RATE_LIMITED)) == "RATE_LIMITED"
    with pytest.raises(BrokerPortError):
        BrokerRejected(cast(BrokerRejectionCode, "secret venue text"))


def test_account_view_requires_sorted_unique_exact_positions_and_revision() -> None:
    since = datetime(2026, 1, 1, tzinfo=UTC)
    execution = _issue_execution(
        "exec-1", "venue-order-1", "client-1", "AAPL", "BUY", Decimal("1.00"),
        Decimal("100.00"), since,
    )
    view = _issue_account_view(
        "acct-1", (), (("AAPL", Decimal("1.00")), ("MSFT", Decimal("-2"))),
        7, (execution,), since, complete=True,
    )
    view.assert_sealed()
    execution.assert_sealed()
    assert execution.quantity == Decimal("1")
    assert execution.price == Decimal("100")
    assert view.executions == (execution,)
    assert view.positions == (("AAPL", Decimal("1")), ("MSFT", Decimal("-2")))
    for positions in (
        (("MSFT", Decimal(1)), ("AAPL", Decimal(2))),
        (("AAPL", Decimal(1)), ("AAPL", Decimal(2))),
        (("AAPL", Decimal("1E+100000")),),
    ):
        with pytest.raises(BrokerPortError):
            _issue_account_view("acct-1", (), positions, 7, (), since, complete=True)
    with pytest.raises(BrokerPortError):
        _issue_account_view("acct-1", (), (), cast(int, True), (), since, complete=True)
    with pytest.raises(BrokerPortError):
        AccountViewV1("acct-1", (), (), 0, (), since)
    with pytest.raises(BrokerOutcomeUnknown):
        _issue_account_view("acct-1", (), (), 0, (), since, complete=False)
    with pytest.raises(BrokerPortError):
        _issue_account_view("acct-1", (), (), 0, (execution, execution), since, complete=True)
    with pytest.raises(BrokerPortError):
        _issue_account_view("acct-1", (), (), 0, (execution,), since + timedelta(1), complete=True)
    with pytest.raises(BrokerPortError):
        _issue_execution(
            "bad", "order", None, "AAPL", "BUY", Decimal("1E+100000"), Decimal(1), since
        )
    with pytest.raises(BrokerPortError):
        ExecutionV1("exec-2", "order", None, "AAPL", "SELL", Decimal(1), Decimal(2), since)


def test_seals_resist_copy_replace_pickle_and_identity_collision() -> None:
    first = _issue_cancel_result(True)
    twin = _issue_cancel_result(True)
    first.assert_sealed()
    twin.assert_sealed()
    for operation in (copy.copy, copy.deepcopy, pickle.dumps, replace):
        with pytest.raises(BrokerPortError):
            operation(first)
    with pytest.raises(TypeError):
        replace(first, _seal="forged")
    object.__setattr__(first, "confirmed", False)
    with pytest.raises(BrokerPortError, match="BROKER_RECORD_TAMPERED"):
        first.assert_sealed()
    del first
    gc.collect()
    twin.assert_sealed()


def test_issued_records_reject_state_hooks_and_reinit_before_mutation() -> None:
    since = datetime(2026, 1, 1, tzinfo=UTC)
    records = (
        _issue_venue_capability(True),
        _issue_venue_identity(BrokerVenue.ALPACA, BrokerEnvironment.PAPER, "acct-1"),
        _issue_submit_result("order-1", OrderState.WORKING),
        _issue_cancel_result(True),
        _issue_execution("exec-1", "order-1", None, "AAPL", "BUY", Decimal(1), Decimal(2), since),
        _issue_account_view("acct-1", (), (), 0, (), since, complete=True),
    )
    for record in records:
        with pytest.raises(BrokerPortError, match="REINIT_FORBIDDEN"):
            record.__setstate__({"account_id": "changed-account"})
        with pytest.raises(BrokerPortError, match="REINIT_FORBIDDEN"):
            record.__getstate__()
        record.assert_sealed()
    venue = records[1]
    assert isinstance(venue, VenueIdentityV1)
    with pytest.raises(BrokerPortError, match="REINIT_FORBIDDEN"):
        VenueIdentityV1.__init__(
            venue, BrokerVenue.MT5, BrokerEnvironment.DEMO, "changed-account"
        )
    assert venue.account_id == "acct-1"
    venue.assert_sealed()


def test_seal_rejects_type_collisions_and_mutable_containers() -> None:
    since = datetime(2026, 1, 1, tzinfo=UTC)

    def issued_view() -> tuple[ExecutionV1, AccountViewV1]:
        execution = _issue_execution(
            "exec-1", "order-1", "client-1", "AAPL", "BUY", Decimal(1), Decimal(2), since
        )
        view = _issue_account_view(
            "acct-1", (), (("AAPL", Decimal(1)),), 1, (execution,), since, complete=True
        )
        return execution, view

    execution, view = issued_view()
    object.__setattr__(execution, "quantity", 1)
    with pytest.raises(BrokerPortError):
        execution.assert_sealed()
    with pytest.raises(BrokerPortError):
        view.assert_sealed()

    mutations: tuple[tuple[str, object], ...] = (
        ("broker_revision", Decimal(1)),
        ("positions", (("AAPL", 1),)),
        ("positions", [("AAPL", Decimal(1))]),
        ("executions", []),
        ("open_orders", []),
    )
    for field_name, mutated_value in mutations:
        _, fresh_view = issued_view()
        object.__setattr__(fresh_view, field_name, mutated_value)
        with pytest.raises(BrokerPortError):
            fresh_view.assert_sealed()

    issued_execution, fresh_view = issued_view()
    unissued_execution = object.__new__(ExecutionV1)
    for field in fields(ExecutionV1):
        object.__setattr__(
            unissued_execution, field.name, getattr(issued_execution, field.name)
        )
    object.__setattr__(fresh_view, "executions", (unissued_execution,))
    with pytest.raises(BrokerPortError, match="UNISSUED_BROKER_RECORD"):
        fresh_view.assert_sealed()

    capability = _issue_venue_capability(True)
    object.__setattr__(capability, "atomic_revision_dispatch", 1)
    with pytest.raises(BrokerPortError):
        capability.assert_sealed()


def test_protocol_is_runtime_checkable_and_legacy_fake_has_adoption_gap() -> None:
    class MinimalConformingPort:
        def __init__(self) -> None:
            self.capability = _issue_venue_capability(True)
            self.venue = _issue_venue_identity(
                BrokerVenue.ALPACA, BrokerEnvironment.PAPER, "acct-1"
            )

        def submit(
            self, request: OrderRequest, permit: object, expected_revision: int
        ) -> SubmitResultV1:
            raise NotImplementedError

        def cancel(self, order: OrderSnapshot) -> CancelResultV1:
            raise NotImplementedError

        def read_order(self, order: OrderSnapshot) -> BrokerObservation | None:
            raise NotImplementedError

        def read_account_view(self, account_id: str) -> AccountViewV1:
            return _issue_account_view(
                account_id, (), (), 0, (), datetime(2026, 1, 1, tzinfo=UTC), complete=True
            )

    assert isinstance(MinimalConformingPort(), BrokerPortV1)
    # OMS-PORT-ADOPT: legacy FakeBrokerPort has no venue identity or account view.
    assert hasattr(FakeBrokerPort, "read_account_view")
    assert OrderRequest is order_models.OrderRequest
    assert OrderSnapshot is order_models.OrderSnapshot
