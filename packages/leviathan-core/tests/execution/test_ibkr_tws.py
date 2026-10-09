"""Focused fake-transport tests for dispatch and reconciliation decisions."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime
from decimal import Decimal
from threading import Event, Thread

import pytest

from leviathan_core.execution.broker_port_v1 import (
    BrokerOutcomeUnknown,
    BrokerRejected,
    BrokerRejectionCode,
    BrokerUnknownCode,
)
from leviathan_core.execution.brokers.ibkr_mapping import (
    IBKRContractBindingV1,
    encode_order_ref,
)
from leviathan_core.execution.brokers.ibkr_tws import (
    FakeTwsTransport,
    IBKRCompletedOrdersEndV1,
    IBKRCompletedOrderV1,
    IBKRExecDetailsEndV1,
    IBKRExecDetailsV1,
    IBKROpenOrderEndV1,
    IBKROpenOrderV1,
    IBKROrderStatusV1,
    IBKRPaperSessionV1,
    IBKRPositionEndV1,
    IBKRTwsPaperAdapter,
)
from leviathan_core.execution.order_models import OrderRequest, OrderSnapshot, OrderState


@dataclass
class _Permit:
    order_id: str
    calls: list[tuple[str, str, int]]

    def consume(self, order_id: str, request_digest: str, expected_revision: int) -> None:
        self.calls.append((order_id, request_digest, expected_revision))
        assert order_id == self.order_id


def _request() -> OrderRequest:
    return OrderRequest(
        project_id="leviathan-ai",
        environment="paper",
        account_id="DU1234567",
        venue="IBKR_TWS",
        instrument_id="MES-TEST",
        native_contract_id="conid:900001",
        side="BUY",
        quantity=Decimal("2"),
        order_type="LIMIT",
        time_in_force="DAY",
        client_order_id="oms-order-1",
        intent_idempotency_key="intent-oms-order-1",
        attempt=1,
        strategy_id="test-strategy",
        risk_policy_digest="a" * 64,
        actor_id="test-actor",
        capability="paper-submit",
        limit_price=Decimal("5000.25"),
    )


def _adapter() -> tuple[IBKRTwsPaperAdapter, FakeTwsTransport]:
    session = IBKRPaperSessionV1(
        "DU1234567",
        17,
        "synthetic-session",
        17,
        executions_since=datetime(2026, 10, 5, tzinfo=UTC),
    )
    fake = FakeTwsTransport(session)
    binding = IBKRContractBindingV1(
        "MES-TEST", "conid:900001", 900001, "MES", "FUT", "CME", "USD", "r1"
    )
    return IBKRTwsPaperAdapter(fake, session, (binding,)), fake


def _complete_view(
    fake: FakeTwsTransport,
    *,
    request_id: int = 1,
    completed: tuple[IBKRCompletedOrderV1, ...] = (),
    executions: tuple[IBKRExecDetailsV1, ...] = (),
) -> None:
    fake.queue_all_open_orders((IBKROpenOrderEndV1(),))
    fake.queue_completed_orders((*completed, IBKRCompletedOrdersEndV1()))
    fake.queue_positions((IBKRPositionEndV1(),))
    fake.queue_executions((*executions, IBKRExecDetailsEndV1(request_id)))


def _native_open(request: OrderRequest, order_id: int = 41) -> IBKROpenOrderV1:
    return IBKROpenOrderV1(
        account_id=request.account_id,
        client_id=17,
        order_id=order_id,
        perm_id=9000 + order_id,
        order_ref=encode_order_ref(request.account_id, request.client_order_id),
        con_id=900001,
        status="Submitted",
        total_quantity=request.quantity,
    )


def _snapshot(request: OrderRequest) -> OrderSnapshot:
    return OrderSnapshot(
        order_id="oms-1",
        request=request,
        state=OrderState.WORKING,
        version=1,
        venue_order_id="9041",
        filled_quantity=Decimal("0"),
        discrepancies=(),
        submit_attempted=True,
        cancel_attempted=False,
    )


def test_submit_consumes_permit_once_and_requires_matching_callback() -> None:
    adapter, fake = _adapter()
    request = _request()
    _complete_view(fake)
    revision = adapter.read_account_view(request.account_id).broker_revision
    adapter.nextValidId(41)
    fake.queue_place((_native_open(request),))
    permit = _Permit("oms-1", [])

    result = adapter.submit(request, permit, revision)

    assert permit.calls == [("oms-1", request.digest, revision)]
    assert result.state is OrderState.WORKING
    assert result.venue_order_id == "9041"
    result.assert_sealed()
    assert fake.calls[-1][0] == "placeOrder"
    assert fake.calls[-1][1][0] == 41
    assert adapter.next_order_id == 42


def test_missing_place_callback_is_unknown_and_never_retried() -> None:
    adapter, fake = _adapter()
    request = _request()
    _complete_view(fake)
    revision = adapter.read_account_view(request.account_id).broker_revision
    adapter.nextValidId(41)
    fake.queue_place(())
    permit = _Permit("oms-1", [])

    with pytest.raises(BrokerOutcomeUnknown) as caught:
        adapter.submit(request, permit, revision)

    assert caught.value.code == BrokerUnknownCode.UNKNOWN_SUBMIT.value
    assert adapter.blocked
    assert permit.calls == [("oms-1", request.digest, revision)]
    with pytest.raises(BrokerOutcomeUnknown):
        adapter.submit(request, permit, revision)
    assert [name for name, _ in fake.calls].count("placeOrder") == 1


def test_reentrant_callback_during_permit_aborts_before_place_order() -> None:
    adapter, fake = _adapter()
    request = _request()
    _complete_view(fake)
    revision = adapter.read_account_view(request.account_id).broker_revision
    adapter.nextValidId(42)
    other = replace(
        request, client_order_id="unrelated-order", intent_idempotency_key="unrelated-intent"
    )

    class ReentrantPermit:
        order_id = "oms-1"
        consumed = False

        def consume(self, order_id: str, request_digest: str, expected_revision: int) -> None:
            assert (order_id, request_digest, expected_revision) == (
                self.order_id,
                request.digest,
                revision,
            )
            self.consumed = True
            adapter.openOrder(_native_open(other, order_id=42))

    permit = ReentrantPermit()
    with pytest.raises(BrokerOutcomeUnknown) as caught:
        adapter.submit(request, permit, revision)

    assert caught.value.code == BrokerUnknownCode.UNKNOWN_SUBMIT.value
    assert permit.consumed
    assert adapter.callback_sequence == 1
    assert adapter.next_order_id is not None and adapter.next_order_id > 42
    assert all(name != "placeOrder" for name, _ in fake.calls)


def test_concurrent_callback_arrival_during_permit_aborts_before_place_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter, fake = _adapter()
    request = _request()
    _complete_view(fake)
    revision = adapter.read_account_view(request.account_id).broker_revision
    adapter.nextValidId(42)
    other = replace(
        request, client_order_id="concurrent-order", intent_idempotency_key="concurrent-intent"
    )
    arrived = Event()
    original_note = adapter._note_callback_arrival

    def note_arrival() -> None:
        original_note()
        arrived.set()

    monkeypatch.setattr(adapter, "_note_callback_arrival", note_arrival)

    class ConcurrentPermit:
        order_id = "oms-1"
        thread: Thread | None = None

        def consume(self, order_id: str, request_digest: str, expected_revision: int) -> None:
            assert (order_id, request_digest, expected_revision) == (
                self.order_id,
                request.digest,
                revision,
            )
            self.thread = Thread(target=adapter.openOrder, args=(_native_open(other, 42),))
            self.thread.start()
            assert arrived.wait(2)

    permit = ConcurrentPermit()
    with pytest.raises(BrokerOutcomeUnknown) as caught:
        adapter.submit(request, permit, revision)
    if permit.thread is not None:
        permit.thread.join(2)

    assert caught.value.code == BrokerUnknownCode.UNKNOWN_SUBMIT.value
    assert permit.thread is not None and not permit.thread.is_alive()
    assert adapter.next_order_id is not None and adapter.next_order_id > 42
    assert all(name != "placeOrder" for name, _ in fake.calls)


def test_cancel_pending_is_unconfirmed_and_duplicate_cancel_is_blocked() -> None:
    adapter, fake = _adapter()
    request = _request()
    adapter.openOrder(_native_open(request))
    fake.queue_cancel(
        (IBKROrderStatusV1(17, 41, 9041, "PendingCancel", Decimal("0"), Decimal("2")),)
    )

    result = adapter.cancel(_snapshot(request))

    assert result.confirmed is False
    result.assert_sealed()
    with pytest.raises(BrokerOutcomeUnknown) as caught:
        adapter.cancel(_snapshot(request))
    assert caught.value.code == BrokerUnknownCode.UNKNOWN_CANCEL.value
    assert [name for name, _ in fake.calls].count("cancelOrder") == 1


def test_cancelled_callback_is_required_for_positive_confirmation() -> None:
    adapter, fake = _adapter()
    request = _request()
    adapter.openOrder(_native_open(request))
    fake.queue_cancel((IBKROrderStatusV1(17, 41, 9041, "Cancelled", Decimal("0"), Decimal("0")),))

    assert adapter.cancel(_snapshot(request)).confirmed is True


def test_stale_status_does_not_confirm_current_cancel_attempt() -> None:
    adapter, fake = _adapter()
    request = _request()
    adapter.openOrder(_native_open(request))
    adapter.orderStatus(
        IBKROrderStatusV1(17, 41, 9041, "PendingCancel", Decimal("0"), Decimal("2"))
    )
    fake.queue_cancel(())

    with pytest.raises(BrokerOutcomeUnknown) as caught:
        adapter.cancel(_snapshot(request))

    assert caught.value.code == BrokerUnknownCode.UNKNOWN_CANCEL.value
    assert adapter.blocked


def test_repeated_execution_query_preserves_exact_fill_once_per_view() -> None:
    adapter, fake = _adapter()
    request = _request()
    execution = IBKRExecDetailsV1(
        account_id=request.account_id,
        client_id=17,
        order_id=41,
        perm_id=9041,
        order_ref=encode_order_ref(request.account_id, request.client_order_id),
        con_id=900001,
        execution_id="exec-1",
        quantity=Decimal("0.5"),
        price=Decimal("5000.25"),
        side="BOT",
        executed_at=datetime(2026, 10, 5, 20, tzinfo=UTC),
    )
    _complete_view(fake, executions=(execution, execution))
    first = adapter.read_account_view(request.account_id)
    _complete_view(fake, request_id=2, executions=(execution,))
    second = adapter.read_account_view(request.account_id)

    for view in (first, second):
        assert len(view.executions) == 1
        assert view.executions[0].execution_id == "exec-1"
        assert view.executions[0].side == "BUY"
        view.assert_sealed()


def test_completed_order_is_read_by_ref_with_complete_account_evidence() -> None:
    adapter, fake = _adapter()
    request = _request()
    completed = IBKRCompletedOrderV1(
        account_id=request.account_id,
        client_id=17,
        order_id=41,
        perm_id=9041,
        order_ref=encode_order_ref(request.account_id, request.client_order_id),
        con_id=900001,
        status="Filled",
    )
    _complete_view(fake, completed=(completed,))

    observation = adapter.read_order(_snapshot(request))

    assert observation is not None
    assert observation.status is OrderState.FILLED
    assert observation.venue_order_id == "9041"
    assert [name for name, _ in fake.calls] == [
        "reqAllOpenOrders",
        "reqCompletedOrders",
        "reqPositions",
        "reqExecutions",
    ]


def test_complete_reconciliation_clears_soft_unknown_block() -> None:
    adapter, fake = _adapter()
    fake.queue_all_open_orders(())
    with pytest.raises(BrokerOutcomeUnknown):
        adapter.read_account_view("DU1234567")
    assert adapter.blocked
    _complete_view(fake)

    assert adapter.read_account_view("DU1234567").broker_revision == 1
    assert adapter.blocked is False


def test_client_zero_can_collect_master_account_view() -> None:
    session = IBKRPaperSessionV1(
        "DU1234567",
        0,
        "synthetic-client-zero",
        17,
        executions_since=datetime(2026, 10, 5, tzinfo=UTC),
    )
    fake = FakeTwsTransport(session)
    adapter = IBKRTwsPaperAdapter(fake, session, ())
    _complete_view(fake)

    assert adapter.read_account_view("DU1234567").account_id == "DU1234567"


def test_cross_component_open_order_makes_account_view_unknown() -> None:
    adapter, fake = _adapter()
    fake.queue_all_open_orders((IBKROpenOrderEndV1(),))
    fake.queue_completed_orders((_native_open(_request()), IBKRCompletedOrdersEndV1()))

    with pytest.raises(BrokerOutcomeUnknown) as caught:
        adapter.read_account_view("DU1234567")

    assert caught.value.code == BrokerUnknownCode.UNKNOWN_ACCOUNT_VIEW.value
    assert adapter.blocked
    assert adapter.callback_sequence == 1


def test_post_view_callback_prevents_submit_using_old_inventory() -> None:
    adapter, fake = _adapter()
    _complete_view(fake)
    view = adapter.read_account_view("DU1234567")
    adapter.openOrder(_native_open(_request()))
    adapter.nextValidId(42)
    other_request = replace(
        _request(), client_order_id="oms-order-2", intent_idempotency_key="intent-oms-order-2"
    )

    with pytest.raises(BrokerOutcomeUnknown) as caught:
        adapter.submit(other_request, _Permit("oms-2", []), view.broker_revision)

    assert caught.value.code == BrokerUnknownCode.UNKNOWN_ACCOUNT_VIEW.value
    assert all(name != "placeOrder" for name, _ in fake.calls)


def test_terminal_status_reversal_blocks_cancel_with_discrepancy() -> None:
    adapter, fake = _adapter()
    request = _request()
    adapter.openOrder(_native_open(request))
    fake.queue_cancel(
        (
            IBKROrderStatusV1(17, 41, 9041, "Cancelled", Decimal("0"), Decimal("0")),
            IBKROrderStatusV1(17, 41, 9041, "Submitted", Decimal("0"), Decimal("2")),
        )
    )

    with pytest.raises(BrokerOutcomeUnknown) as caught:
        adapter.cancel(_snapshot(request))

    assert caught.value.code == BrokerUnknownCode.UNKNOWN_CANCEL.value
    assert "ORDER_STATUS_CONFLICT" in adapter.discrepancies
    assert adapter.blocked
    assert [name for name, _ in fake.calls].count("cancelOrder") == 1


def test_mixed_callback_terminal_reversal_blocks_cancel() -> None:
    adapter, fake = _adapter()
    request = _request()
    adapter.openOrder(_native_open(request))
    fake.queue_cancel(
        (
            IBKRCompletedOrderV1(
                account_id=request.account_id,
                client_id=17,
                order_id=41,
                perm_id=9041,
                order_ref=encode_order_ref(request.account_id, request.client_order_id),
                con_id=900001,
                status="Cancelled",
            ),
            _native_open(request),
        )
    )

    with pytest.raises(BrokerOutcomeUnknown) as caught:
        adapter.cancel(_snapshot(request))

    assert caught.value.code == BrokerUnknownCode.UNKNOWN_CANCEL.value
    assert "ORDER_STATUS_CONFLICT" in adapter.discrepancies
    assert adapter.blocked


def test_snapshot_perm_id_mismatch_refuses_cancel_before_transport() -> None:
    adapter, fake = _adapter()
    request = _request()
    adapter.openOrder(_native_open(request))

    with pytest.raises(BrokerRejected) as caught:
        adapter.cancel(replace(_snapshot(request), venue_order_id="9999"))

    assert caught.value.code == BrokerRejectionCode.INVALID_ORDER.value
    assert all(name != "cancelOrder" for name, _ in fake.calls)
