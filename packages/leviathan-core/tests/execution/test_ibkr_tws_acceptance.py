"""Independent synthetic acceptance for the IBKR TWS paper adapter."""

from __future__ import annotations

import copy
import json
import pickle
from collections.abc import Callable
from dataclasses import fields, replace
from datetime import UTC, datetime
from decimal import Decimal, Inexact, localcontext
from pathlib import Path
from typing import Any

import pytest

from leviathan_core.execution.broker_port_v1 import (
    AccountViewV1,
    BrokerEnvironment,
    BrokerOutcomeUnknown,
    BrokerPortError,
    BrokerRejected,
    BrokerRejectionCode,
    BrokerUnknownCode,
    BrokerVenue,
    CancelResultV1,
    ExecutionV1,
    SubmitResultV1,
    VenueDispatchCapabilityV1,
    VenueIdentityV1,
)
from leviathan_core.execution.brokers.ibkr_mapping import (
    IBKRAdapterError,
    IBKRContractBindingV1,
    IBKRNativeContractV1,
    IBKRNativeOrderV1,
    encode_order_ref,
    map_order_request,
)
from leviathan_core.execution.brokers.ibkr_tws import (
    FakeTwsTransport,
    IBKRCompletedOrdersEndV1,
    IBKRCompletedOrderV1,
    IBKRErrorV1,
    IBKRExecDetailsEndV1,
    IBKRExecDetailsV1,
    IBKROpenOrderEndV1,
    IBKROpenOrderV1,
    IBKROrderStatusV1,
    IBKRPaperSessionV1,
    IBKRPositionEndV1,
    IBKRPositionV1,
    IBKRTwsPaperAdapter,
)
from leviathan_core.execution.order_models import (
    OMSValidationError,
    OrderRequest,
    OrderSnapshot,
    OrderState,
)

FIXTURE_DIR = Path(__file__).parents[1] / "fixtures" / "ibkr_tws"
MAPPING_FIXTURE = FIXTURE_DIR / "mapping_orders.jsonl"
PARTIAL_FILL_FIXTURE = FIXTURE_DIR / "partial_fill_callbacks.jsonl"
EXECUTIONS_SINCE = datetime(2026, 10, 5, 19, 0, tzinfo=UTC)
PAPER_SESSION = IBKRPaperSessionV1(
    account_id="DU9000001",
    client_id=17,
    session_id="synthetic-tws-session-1",
    master_client_id=17,
    executions_since=EXECUTIONS_SINCE,
)


def _request(**overrides: Any) -> OrderRequest:
    values: dict[str, Any] = {
        "project_id": "leviathan-ai",
        "environment": "paper",
        "account_id": "DU9000001",
        "venue": "IBKR_TWS",
        "instrument_id": "MES-20261218",
        "native_contract_id": "conid:900001",
        "side": "BUY",
        "quantity": Decimal("2.50"),
        "order_type": "LIMIT",
        "time_in_force": "DAY",
        "client_order_id": "oms-order-synthetic-0001",
        "intent_idempotency_key": "intent-synthetic-0001",
        "attempt": 1,
        "strategy_id": "synthetic-strategy",
        "risk_policy_digest": "a" * 64,
        "actor_id": "synthetic-operator",
        "capability": "paper-submit",
        "limit_price": Decimal("5000.125"),
    }
    values.update(overrides)
    if isinstance(values.get("expires_at"), str):
        values["expires_at"] = datetime.fromisoformat(values["expires_at"])
    return OrderRequest(**values)


def _binding(**overrides: Any) -> IBKRContractBindingV1:
    values: dict[str, Any] = {
        "instrument_id": "MES-20261218",
        "native_contract_id": "conid:900001",
        "con_id": 900001,
        "symbol": "MESZ6",
        "sec_type": "FUT",
        "exchange": "CME",
        "currency": "USD",
        "revision": "synthetic-r1",
    }
    values.update(overrides)
    return IBKRContractBindingV1(**values)


def _fixture_cases() -> list[dict[str, Any]]:
    return [json.loads(line) for line in MAPPING_FIXTURE.read_text().splitlines() if line]


def _adapter(
    *, session: IBKRPaperSessionV1 = PAPER_SESSION
) -> tuple[IBKRTwsPaperAdapter, FakeTwsTransport]:
    transport = FakeTwsTransport(session)
    adapter = IBKRTwsPaperAdapter(transport, session, (_binding(),))
    return adapter, transport


def _open_order(
    *,
    account_id: str = "DU9000001",
    client_id: int = 17,
    order_id: int = 41,
    perm_id: int = 9041,
    order_ref: str | None = None,
    client_order_id: str = "oms-order-synthetic-0001",
    quantity: Decimal = Decimal("2"),
    status: str = "Submitted",
) -> IBKROpenOrderV1:
    return IBKROpenOrderV1(
        account_id=account_id,
        client_id=client_id,
        order_id=order_id,
        perm_id=perm_id,
        order_ref=order_ref or encode_order_ref(account_id, client_order_id),
        con_id=900001,
        status=status,
        total_quantity=quantity,
    )


def _execution(
    *,
    execution_id: str = "synthetic-exec-1",
    quantity: Decimal = Decimal("0.25"),
    price: Decimal = Decimal("5000.125"),
    side: str = "BOT",
    executed_at: datetime = datetime(2026, 10, 5, 20, 0, tzinfo=UTC),
) -> IBKRExecDetailsV1:
    return IBKRExecDetailsV1(
        account_id="DU9000001",
        client_id=17,
        order_id=41,
        perm_id=9041,
        order_ref=encode_order_ref("DU9000001", "oms-order-synthetic-0001"),
        con_id=900001,
        execution_id=execution_id,
        quantity=quantity,
        price=price,
        side=side,
        executed_at=executed_at,
    )


def _queue_account_view(
    transport: FakeTwsTransport,
    *,
    open_orders: tuple[IBKROpenOrderV1, ...] = (),
    completed_orders: tuple[IBKRCompletedOrderV1, ...] = (),
    positions: tuple[IBKRPositionV1, ...] = (),
    executions: tuple[IBKRExecDetailsV1, ...] = (),
    request_id: int = 1,
    missing_end: str | None = None,
    failure_component: str | None = None,
) -> None:
    transport.queue_all_open_orders(
        open_orders + (() if missing_end == "open" else (IBKROpenOrderEndV1(),)),
        TimeoutError("synthetic component timeout") if failure_component == "open" else None,
    )
    transport.queue_completed_orders(
        completed_orders
        + (() if missing_end == "completed" else (IBKRCompletedOrdersEndV1(),)),
        TimeoutError("synthetic component timeout") if failure_component == "completed" else None,
    )
    transport.queue_positions(
        positions + (() if missing_end == "positions" else (IBKRPositionEndV1(),)),
        TimeoutError("synthetic component timeout") if failure_component == "positions" else None,
    )
    transport.queue_executions(
        executions
        + (() if missing_end == "executions" else (IBKRExecDetailsEndV1(request_id),)),
        TimeoutError("synthetic component timeout") if failure_component == "executions" else None,
    )


class _SyntheticPermit:
    def __init__(
        self,
        order_id: str,
        request: OrderRequest,
        revision: int,
        *,
        on_consume: Callable[[], None] | None = None,
    ) -> None:
        self.order_id = order_id
        self._request_digest = request.digest
        self._revision = revision
        self.consumed = False
        self._on_consume = on_consume

    def consume(self, order_id: str, request_digest: str, expected_revision: int) -> None:
        if (
            self.consumed
            or order_id != self.order_id
            or request_digest != self._request_digest
            or expected_revision != self._revision
        ):
            raise BrokerRejected(BrokerRejectionCode.INVALID_ORDER)
        self.consumed = True
        if self._on_consume is not None:
            self._on_consume()


def _snapshot(request: OrderRequest, *, venue_order_id: str = "9041") -> OrderSnapshot:
    return OrderSnapshot(
        order_id="oms-synthetic-snapshot-1",
        request=request,
        state=OrderState.WORKING,
        version=1,
        venue_order_id=venue_order_id,
        filled_quantity=Decimal("0"),
        discrepancies=(),
        submit_attempted=True,
        cancel_attempted=False,
    )


def _queue_place_ack(
    transport: FakeTwsTransport,
    request: OrderRequest,
    *,
    order_id: int = 41,
    perm_id: int = 9041,
) -> None:
    transport.queue_place(
        (
            _open_order(
                order_id=order_id,
                perm_id=perm_id,
                client_order_id=request.client_order_id,
                order_ref=encode_order_ref(request.account_id, request.client_order_id),
                quantity=request.quantity,
            ),
        )
    )


def _reconcile(adapter: IBKRTwsPaperAdapter, transport: FakeTwsTransport) -> Any:
    _queue_account_view(transport)
    return adapter.read_account_view("DU9000001")


def test_partial_fill_fixture_is_native_synthetic_and_exact() -> None:
    fixture = json.loads(PARTIAL_FILL_FIXTURE.read_text().splitlines()[0])
    native_executions = fixture["executions"]
    assert fixture["account_id"].startswith("DU")
    assert fixture["expected_unique_execution_ids"] == [
        "synthetic-exec-a",
        "synthetic-exec-b",
    ]
    assert fixture["expected_cumulative_quantity"] == "0.375"

    callbacks = [
        _execution(
            execution_id=native["execution_id"],
            quantity=Decimal(native["quantity"]),
            price=Decimal(native["price"]),
            side=native["side"],
            executed_at=datetime.fromisoformat(native["executed_at"].replace("Z", "+00:00")),
        )
        for native in native_executions
    ]

    assert [callback.execution_id for callback in callbacks] == [
        item["execution_id"] for item in native_executions
    ]
    assert callbacks[0] == callbacks[1]
    assert {callback.side for callback in callbacks} == {"BOT"}
    assert all(callback.executed_at is not None for callback in callbacks)
    assert all(callback.executed_at.utcoffset().total_seconds() == 0 for callback in callbacks)


def test_synthetic_mapping_fixtures_preserve_exact_ibkr_fields() -> None:
    cases = _fixture_cases()
    assert {case["case"] for case in cases} == {"market_day_buy", "limit_gtd_sell_utc"}

    for case in cases:
        request_fields = dict(case["request"])
        request_fields["quantity"] = Decimal(request_fields["quantity"])
        if request_fields.get("limit_price") is not None:
            request_fields["limit_price"] = Decimal(request_fields["limit_price"])
        request = _request(**request_fields)
        binding = IBKRContractBindingV1(**case["binding"])

        contract, order = map_order_request(request, binding)

        assert contract.con_id == binding.con_id
        assert contract.symbol == binding.symbol
        assert contract.sec_type == binding.sec_type
        assert contract.exchange == binding.exchange
        assert contract.currency == binding.currency
        expected = case["expected"]
        assert order.account == expected["account"]
        assert order.action == expected["action"]
        assert order.total_quantity == Decimal(expected["quantity"])
        assert order.order_type == expected["order_type"]
        assert order.tif == expected["tif"]
        assert order.order_ref == expected["order_ref"]
        assert order.lmt_price == (
            None if expected["limit_price"] is None else Decimal(expected["limit_price"])
        )
        assert order.good_till_date == expected["good_till_date"]


def test_order_ref_is_fixed_width_account_scoped_and_matches_contract_vector() -> None:
    account = "DU9000001"
    client_order_id = "oms-order-synthetic-0001"
    expected = "LI1UWY4Y4KSQGA3D7QRQQ43EQ2EEJM7P4GP"

    assert encode_order_ref(account, client_order_id) == expected
    assert encode_order_ref(account, client_order_id) == expected
    assert len(expected) == 35
    assert expected.isascii()
    assert encode_order_ref("DU9000002", client_order_id) != expected
    assert encode_order_ref(account, "oms-order-synthetic-0002") != expected
    assert client_order_id not in expected


def test_equivalent_exact_decimal_inputs_keep_the_same_order_identity() -> None:
    plain = _request(quantity=Decimal("2.5"), limit_price=Decimal("5000.125"))
    padded = _request(quantity=Decimal("2.5000"), limit_price=Decimal("5000.12500"))

    plain_order = map_order_request(plain, _binding())[1]
    padded_order = map_order_request(padded, _binding())[1]

    assert plain.digest == padded.digest
    assert plain_order.order_ref == padded_order.order_ref
    assert plain_order.total_quantity == padded_order.total_quantity == Decimal("2.5")
    assert plain_order.lmt_price == padded_order.lmt_price == Decimal("5000.125")


def test_financial_magnitude_is_bounded_before_native_mapping() -> None:
    with pytest.raises(OMSValidationError) as caught:
        _request(quantity=Decimal("1e39"))

    assert caught.value.code == "INVALID_QUANTITY"


def test_financial_precision_overflow_is_typed_and_not_rounded() -> None:
    with pytest.raises(OMSValidationError) as caught:
        _request(quantity=Decimal("12345678901234567890123456789012345"))

    assert caught.value.code == "PRECISION_EXCEEDED"


@pytest.mark.parametrize(
    ("request_overrides", "binding_overrides"),
    [
        ({"environment": "demo"}, {}),
        ({"venue": "OTHER_BROKER"}, {}),
        ({"instrument_id": "NQ-20261218"}, {}),
        ({"native_contract_id": "conid:999999"}, {}),
        ({}, {"instrument_id": "NQ-20261218"}),
        ({}, {"native_contract_id": "conid:999999"}),
    ],
)
def test_mapping_rejects_non_paper_or_inexact_contract_identity(
    request_overrides: dict[str, Any], binding_overrides: dict[str, Any]
) -> None:
    with pytest.raises(IBKRAdapterError) as caught:
        map_order_request(
            _request(**request_overrides), _binding(**binding_overrides)
        )

    assert caught.value.code == "ORDER_MAPPING_MISMATCH"


def test_gtd_mapping_rejects_subsecond_expiry_instead_of_rounding() -> None:
    request = _request(
        order_type="LIMIT",
        time_in_force="GTD",
        expires_at=datetime.fromisoformat("2026-10-05T16:30:00.000001-05:00"),
    )

    with pytest.raises(IBKRAdapterError) as caught:
        map_order_request(request, _binding())

    assert caught.value.code == "UNREPRESENTABLE_GTD"


def test_mapping_is_ambient_decimal_context_invariant() -> None:
    request = _request(quantity=Decimal("2.5000"), limit_price=Decimal("5000.1250"))
    expected = map_order_request(request, _binding())

    with localcontext() as context:
        context.prec = 2
        context.traps[Inexact] = True
        observed = map_order_request(request, _binding())

    assert observed == expected
    assert observed[1].total_quantity == Decimal("2.5")
    assert observed[1].lmt_price == Decimal("5000.125")


def test_native_binding_and_order_values_reject_copy_and_replace_bypass() -> None:
    binding = _binding()
    contract, order = map_order_request(_request(), binding)

    for value in (binding, contract, order):
        for operation in (copy.copy, copy.deepcopy, pickle.dumps):
            with pytest.raises(TypeError):
                operation(value)

    with pytest.raises(IBKRAdapterError) as caught:
        replace(binding, con_id=True)
    assert caught.value.code == "INVALID_CONTRACT_BINDING"

    with pytest.raises(IBKRAdapterError) as caught:
        replace(order, total_quantity=Decimal("0"))
    assert caught.value.code == "INVALID_NATIVE_ORDER"


@pytest.mark.parametrize(
    "constructor",
    [
        lambda: _binding(con_id=True),
        lambda: IBKRNativeContractV1(
            con_id=True,
            symbol="MESZ6",
            sec_type="FUT",
            exchange="CME",
            currency="USD",
        ),
        lambda: IBKRNativeOrderV1(
            account="DU9000001",
            action="BUY",
            total_quantity=True,
            order_type="MKT",
            tif="DAY",
            order_ref="LI1UWY4Y4KSQGA3D7QRQQ43EQ2EEJM7P4GP",
        ),
    ],
)
def test_native_integer_fields_reject_bool_as_an_integer(constructor: Any) -> None:
    with pytest.raises(IBKRAdapterError):
        constructor()


def test_invalid_mapping_errors_are_typed_and_do_not_echo_canary_values() -> None:
    canary = "private-account-canary-7d3f"

    with pytest.raises(IBKRAdapterError) as caught:
        encode_order_ref(canary, "invalid client id")

    error = caught.value
    assert error.code == "INVALID_CLIENT_IDENTITY"
    assert canary not in str(error)
    assert canary not in repr(error.args)


def test_tws_paper_session_is_explicit_and_bound_account_is_not_inferred_from_port() -> None:
    observed = IBKRPaperSessionV1(
        account_id="DU9000002",
        client_id=17,
        session_id="synthetic-tws-session-2",
        master_client_id=17,
        executions_since=EXECUTIONS_SINCE,
    )
    transport = FakeTwsTransport(observed)

    with pytest.raises(IBKRAdapterError) as caught:
        IBKRTwsPaperAdapter(transport, PAPER_SESSION, (_binding(),))

    assert caught.value.code == "PAPER_SESSION_MISMATCH"
    with pytest.raises(IBKRAdapterError) as caught:
        IBKRPaperSessionV1(
            account_id="DU9000001",
            client_id=17,
            session_id="synthetic-live-looking-session",
            master_client_id=17,
            mode="LIVE",
            executions_since=EXECUTIONS_SINCE,
        )
    assert caught.value.code == "PAPER_SESSION_REQUIRED"

    non_master = IBKRPaperSessionV1(
        account_id="DU9000001",
        client_id=18,
        session_id="synthetic-non-master-session",
        master_client_id=17,
        executions_since=EXECUTIONS_SINCE,
    )
    with pytest.raises(IBKRAdapterError) as caught:
        IBKRTwsPaperAdapter(FakeTwsTransport(non_master), non_master, (_binding(),))
    assert caught.value.code == "MASTER_CLIENT_REQUIRED"

    class NonFakeTransport:
        pass

    with pytest.raises(IBKRAdapterError) as caught:
        IBKRTwsPaperAdapter(NonFakeTransport(), PAPER_SESSION, (_binding(),))  # type: ignore[arg-type]
    assert caught.value.code == "FAKE_PAPER_TRANSPORT_REQUIRED"


def test_open_order_from_different_account_blocks_the_session() -> None:
    adapter, _transport = _adapter()

    with pytest.raises(IBKRAdapterError) as caught:
        adapter.openOrder(_open_order(account_id="DU9000002"))

    assert caught.value.code == "ACCOUNT_MISMATCH"
    assert adapter.blocked is True


def test_native_order_ids_advance_above_own_client_callbacks_and_exhaust_without_wrap() -> None:
    adapter, _transport = _adapter()
    adapter.nextValidId(41)
    assert adapter.next_order_id == 41

    adapter.openOrder(_open_order(order_id=41))
    assert adapter.next_order_id == 42

    adapter.nextValidId(41)
    assert adapter.next_order_id == 42

    adapter.nextValidId(2_147_483_647)
    assert adapter.next_order_id == 2_147_483_647
    adapter.openOrder(
        _open_order(
            order_id=2_147_483_647,
            perm_id=9042,
            order_ref=encode_order_ref("DU9000001", "oms-order-synthetic-0002"),
        )
    )
    assert adapter.next_order_id is None


def test_next_valid_id_rejects_bool_and_out_of_range_native_ids() -> None:
    adapter, _transport = _adapter()

    for invalid in (True, 0, 2_147_483_648):
        with pytest.raises(IBKRAdapterError) as caught:
            adapter.nextValidId(invalid)
        assert caught.value.code == "INVALID_CALLBACK"


def test_duplicate_execution_callback_is_idempotent() -> None:
    adapter, _transport = _adapter()
    event = _execution()

    adapter.execDetails(event)
    adapter.execDetails(event)

    assert adapter.blocked is False


def test_conflicting_duplicate_execution_id_blocks_with_closed_code() -> None:
    adapter, _transport = _adapter()
    adapter.execDetails(_execution())

    with pytest.raises(IBKRAdapterError) as caught:
        adapter.execDetails(_execution(quantity=Decimal("0.5")))

    assert caught.value.code == "EXECUTION_CONFLICT"
    assert adapter.blocked is True


def test_order_status_progress_is_monotone_and_exact() -> None:
    adapter, _transport = _adapter()
    initial = IBKROrderStatusV1(
        client_id=17,
        order_id=41,
        perm_id=9041,
        status="Submitted",
        filled=Decimal("0.25"),
        remaining=Decimal("1.75"),
    )
    advanced = IBKROrderStatusV1(
        client_id=17,
        order_id=41,
        perm_id=9041,
        status="Submitted",
        filled=Decimal("0.75"),
        remaining=Decimal("1.25"),
    )
    adapter.orderStatus(initial)
    adapter.orderStatus(advanced)

    with pytest.raises(IBKRAdapterError) as caught:
        adapter.orderStatus(initial)

    assert caught.value.code == "ORDER_STATUS_CONFLICT"


def test_callback_models_are_frozen_and_reject_copy_deepcopy_and_pickle() -> None:
    values = (
        PAPER_SESSION,
        _open_order(),
        _execution(),
        IBKROrderStatusV1(
            client_id=17,
            order_id=41,
            perm_id=9041,
            status="Submitted",
            filled=Decimal("0.25"),
            remaining=Decimal("1.75"),
        ),
        IBKRErrorV1(request_id=0, code=2104),
    )

    for value in values:
        for operation in (copy.copy, copy.deepcopy, pickle.dumps):
            with pytest.raises(TypeError):
                operation(value)


def test_callback_integer_fields_reject_bool_and_errors_do_not_echo_canary() -> None:
    with pytest.raises(IBKRAdapterError) as caught:
        IBKRExecDetailsV1(
            account_id="DU9000001",
            client_id=17,
            order_id=True,
            perm_id=9041,
            order_ref=encode_order_ref("DU9000001", "oms-order-synthetic-0001"),
            con_id=900001,
            execution_id="exec-canary-do-not-echo",
            quantity=Decimal("1"),
            price=Decimal("2"),
        )

    error = caught.value
    assert error.code == "INVALID_CALLBACK"
    assert "exec-canary-do-not-echo" not in str(error)
    assert "exec-canary-do-not-echo" not in repr(error.args)


@pytest.mark.parametrize(
    "side,executed_at",
    [
        ("HOLD-CANARY", datetime(2026, 10, 5, 20, 0, tzinfo=UTC)),
        ("BOT", datetime(2026, 10, 5, 20, 0)),
    ],
)
def test_execution_callback_rejects_invalid_native_enum_or_naive_time_without_echo(
    side: str, executed_at: datetime
) -> None:
    with pytest.raises(IBKRAdapterError) as caught:
        _execution(side=side, executed_at=executed_at)

    assert caught.value.code == "INVALID_CALLBACK"
    assert "HOLD-CANARY" not in str(caught.value)


def test_account_reconciliation_requests_all_components_for_bound_master_account() -> None:
    adapter, transport = _adapter()
    _queue_account_view(transport)

    view = adapter.read_account_view("DU9000001")

    assert view.account_id == "DU9000001"
    assert view.broker_revision == 1
    assert view.executions_since == EXECUTIONS_SINCE
    view.assert_sealed()
    assert adapter.venue.account_id == "DU9000001"
    adapter.venue.assert_sealed()
    assert adapter.capability.atomic_revision_dispatch is False
    assert adapter.capability.settle_window.total_seconds() > 0
    adapter.capability.assert_sealed()
    assert transport.calls == [
        ("reqAllOpenOrders", ()),
        ("reqCompletedOrders", (False,)),
        ("reqPositions", ()),
        ("reqExecutions", (1, "DU9000001", None, EXECUTIONS_SINCE)),
    ]


@pytest.mark.parametrize("missing_end", ["open", "completed", "positions", "executions"])
def test_incomplete_reconciliation_component_is_unknown_and_blocks(
    missing_end: str,
) -> None:
    adapter, transport = _adapter()
    _queue_account_view(transport, missing_end=missing_end)

    with pytest.raises(BrokerOutcomeUnknown) as caught:
        adapter.read_account_view("DU9000001")

    assert caught.value.code == BrokerUnknownCode.UNKNOWN_ACCOUNT_VIEW.value
    assert adapter.blocked is True
    assert all(method != "placeOrder" for method, _args in transport.calls)


@pytest.mark.parametrize("failure_component", ["open", "completed", "positions", "executions"])
def test_reconciliation_component_timeout_is_unknown_and_non_echoing(
    failure_component: str,
) -> None:
    adapter, transport = _adapter()
    _queue_account_view(transport, failure_component=failure_component)

    with pytest.raises(BrokerOutcomeUnknown) as caught:
        adapter.read_account_view("DU9000001")

    assert caught.value.code == BrokerUnknownCode.UNKNOWN_ACCOUNT_VIEW.value
    assert "synthetic component timeout" not in str(caught.value)
    assert "synthetic component timeout" not in repr(caught.value.args)
    assert adapter.blocked is True


def test_partial_fills_are_exactly_deduplicated_in_sealed_account_view() -> None:
    fixture = json.loads(PARTIAL_FILL_FIXTURE.read_text().splitlines()[0])
    adapter, transport = _adapter()
    callbacks = tuple(
        _execution(
            execution_id=item["execution_id"],
            quantity=Decimal(item["quantity"]),
            price=Decimal(item["price"]),
            side=item["side"],
            executed_at=datetime.fromisoformat(item["executed_at"].replace("Z", "+00:00")),
        )
        for item in fixture["executions"]
    )
    _queue_account_view(transport, executions=callbacks)

    view = adapter.read_account_view("DU9000001")

    assert [item.execution_id for item in view.executions] == fixture[
        "expected_unique_execution_ids"
    ]
    assert [item.side for item in view.executions] == ["BUY", "BUY"]
    assert sum((item.quantity for item in view.executions), Decimal("0")) == Decimal(
        fixture["expected_cumulative_quantity"]
    )
    assert [item.executed_at for item in view.executions] == [
        datetime(2026, 10, 5, 20, 0, tzinfo=UTC),
        datetime(2026, 10, 5, 20, 0, 1, tzinfo=UTC),
    ]
    assert all(item.assert_sealed() is None for item in view.executions)
    for execution in view.executions:
        for operation in (copy.copy, copy.deepcopy, pickle.dumps):
            with pytest.raises(BrokerPortError):
                operation(execution)
    view.assert_sealed()


def test_native_sld_execution_is_published_as_sell() -> None:
    adapter, transport = _adapter()
    _queue_account_view(transport, executions=(_execution(side="SLD"),))

    view = adapter.read_account_view("DU9000001")

    assert len(view.executions) == 1
    assert view.executions[0].side == "SELL"


def test_missing_execution_timestamp_bound_makes_account_view_unknown() -> None:
    session_without_bound = IBKRPaperSessionV1(
        account_id="DU9000001",
        client_id=17,
        session_id="synthetic-no-execution-bound",
        master_client_id=17,
    )
    transport = FakeTwsTransport(session_without_bound)
    adapter = IBKRTwsPaperAdapter(transport, session_without_bound, (_binding(),))
    _queue_account_view(transport)

    with pytest.raises(BrokerOutcomeUnknown) as caught:
        adapter.read_account_view("DU9000001")

    assert caught.value.code == BrokerUnknownCode.UNKNOWN_ACCOUNT_VIEW.value
    assert adapter.blocked is True


@pytest.mark.parametrize("missing", ["side", "executed_at"])
def test_execution_missing_native_side_or_time_makes_account_view_unknown(
    missing: str,
) -> None:
    adapter, transport = _adapter()
    callback = _execution()
    if missing == "side":
        callback = replace(callback, side=None)
    else:
        callback = replace(callback, executed_at=None)
    _queue_account_view(transport, executions=(callback,))

    with pytest.raises(BrokerOutcomeUnknown) as caught:
        adapter.read_account_view("DU9000001")

    assert caught.value.code == BrokerUnknownCode.UNKNOWN_ACCOUNT_VIEW.value
    assert adapter.blocked is True


def test_execution_before_configured_window_makes_account_view_unknown() -> None:
    adapter, transport = _adapter()
    stale_execution = _execution(
        executed_at=datetime(2026, 10, 5, 18, 59, 59, tzinfo=UTC)
    )
    _queue_account_view(transport, executions=(stale_execution,))

    with pytest.raises(BrokerOutcomeUnknown) as caught:
        adapter.read_account_view("DU9000001")

    assert caught.value.code == BrokerUnknownCode.UNKNOWN_ACCOUNT_VIEW.value
    assert adapter.blocked is True


def test_broker_port_records_are_issuer_only_immutable_and_digest_checked() -> None:
    adapter, transport = _adapter()
    request = _request()
    adapter.nextValidId(41)
    view = _reconcile(adapter, transport)
    _queue_place_ack(transport, request)
    result = adapter.submit(
        request,
        _SyntheticPermit("oms-sealed-record-permit", request, view.broker_revision),
        view.broker_revision,
    )
    transport.queue_cancel(
        (
            IBKROrderStatusV1(
                client_id=17,
                order_id=41,
                perm_id=9041,
                status="Cancelled",
                filled=Decimal("0"),
                remaining=Decimal("2.5"),
            ),
        )
    )
    cancel_result = adapter.cancel(_snapshot(request))
    execution_adapter, execution_transport = _adapter()
    _queue_account_view(execution_transport, executions=(_execution(),))
    execution_view = execution_adapter.read_account_view("DU9000001")
    records = (
        adapter.venue,
        adapter.capability,
        view,
        result,
        cancel_result,
        execution_view.executions[0],
        execution_view,
    )

    for record in records:
        record.assert_sealed()
        assert not hasattr(record, "__dict__")
        assert "<sealed>" in repr(record)
        assert all(field.name != "_issuer" for field in fields(record))
        assert all("seal" not in field.name.lower() for field in fields(record))
        assert getattr(record, "_issuer", None) is None
        for operation in (copy.copy, copy.deepcopy, pickle.dumps):
            with pytest.raises(BrokerPortError):
                operation(record)
        with pytest.raises(BrokerPortError):
            replace(record)
        first_field = fields(record)[0]
        with pytest.raises((AttributeError, BrokerPortError)):
            setattr(record, first_field.name, "assignment-canary")
        with pytest.raises((AttributeError, BrokerPortError)):
            delattr(record, first_field.name)
        altered_state = [getattr(record, field.name) for field in fields(record)]
        altered_state[0] = "state-canary"
        with pytest.raises(BrokerPortError):
            record.__setstate__(altered_state)

    with pytest.raises(BrokerPortError):
        type(adapter.venue)(
            venue=adapter.venue.venue,
            environment=adapter.venue.environment,
            account_id="DU9000001",
        )

    direct_constructors = (
        lambda: VenueIdentityV1(BrokerVenue.IBKR_TWS, BrokerEnvironment.PAPER, "DU9000001"),
        lambda: VenueDispatchCapabilityV1(True),
        lambda: SubmitResultV1("9041", OrderState.WORKING),
        lambda: CancelResultV1(True),
        lambda: AccountViewV1("DU9000001", (), (), 1, (), EXECUTIONS_SINCE),
        lambda: ExecutionV1(
            "synthetic-execution",
            "9041",
            "oms-order-synthetic-0001",
            "MES-20261218",
            "BUY",
            Decimal("0.25"),
            Decimal("5000.125"),
            datetime(2026, 10, 5, 20, 0, tzinfo=UTC),
        ),
    )
    for constructor in direct_constructors:
        with pytest.raises(BrokerPortError):
            constructor()

    issued_venue = adapter.venue
    with pytest.raises(BrokerPortError):
        VenueIdentityV1(
            issued_venue.venue,
            issued_venue.environment,
            issued_venue.account_id,
            _issuer=issued_venue,
        )

    venue = adapter.venue
    venue_state = tuple(getattr(venue, field.name) for field in fields(venue))
    with pytest.raises(BrokerPortError) as caught:
        venue.__init__(BrokerVenue.IBKR_TWS, BrokerEnvironment.PAPER, "DU9000001")
    assert caught.value.code == "REINIT_FORBIDDEN"
    assert tuple(getattr(venue, field.name) for field in fields(venue)) == venue_state

    left, _ = _adapter()
    right, _ = _adapter()
    left_venue = left.venue
    right_venue = right.venue
    assert left_venue == right_venue
    left_venue.assert_sealed()
    right_venue.assert_sealed()
    unissued_twin = object.__new__(VenueIdentityV1)
    for field in fields(left_venue):
        object.__setattr__(unissued_twin, field.name, getattr(left_venue, field.name))
    assert unissued_twin == left_venue
    with pytest.raises(BrokerPortError) as caught:
        unissued_twin.assert_sealed()
    assert caught.value.code == "UNISSUED_BROKER_RECORD"

    tamper_adapter, _ = _adapter()
    tampered = tamper_adapter.venue
    object.__setattr__(tampered, "account_id", "DU9000002")
    with pytest.raises(BrokerPortError) as caught:
        tampered.assert_sealed()
    assert caught.value.code == "BROKER_RECORD_TAMPERED"


def test_accepted_submit_permit_is_consumed_once_before_transport() -> None:
    adapter, transport = _adapter()
    request = _request()
    adapter.nextValidId(41)
    view = _reconcile(adapter, transport)
    _queue_place_ack(transport, request)
    permit = _SyntheticPermit("oms-ordered-permit", request, view.broker_revision)

    result = adapter.submit(request, permit, view.broker_revision)

    assert result.state is OrderState.WORKING
    assert permit.consumed is True
    place_calls = [call for call in transport.calls if call[0] == "placeOrder"]
    assert len(place_calls) == 1
    assert place_calls[0][1][0] == 41


def test_ambiguous_place_ack_is_unknown_and_never_blindly_retried() -> None:
    adapter, transport = _adapter()
    request = _request()
    adapter.nextValidId(41)
    view = _reconcile(adapter, transport)
    transport.queue_place(())
    permit = _SyntheticPermit("oms-synthetic-permit-1", request, view.broker_revision)

    with pytest.raises(BrokerOutcomeUnknown) as caught:
        adapter.submit(request, permit, view.broker_revision)
    assert caught.value.code == BrokerUnknownCode.UNKNOWN_SUBMIT.value
    assert len([call for call in transport.calls if call[0] == "placeOrder"]) == 1

    with pytest.raises(BrokerOutcomeUnknown):
        adapter.submit(request, permit, view.broker_revision)
    assert len([call for call in transport.calls if call[0] == "placeOrder"]) == 1


def test_reconnect_reconciles_complete_account_before_same_identity_retry() -> None:
    first_adapter, first_transport = _adapter()
    request = _request()
    first_adapter.nextValidId(41)
    first_view = _reconcile(first_adapter, first_transport)
    first_transport.queue_place(())
    with pytest.raises(BrokerOutcomeUnknown):
        first_adapter.submit(
            request,
            _SyntheticPermit("oms-first-attempt", request, first_view.broker_revision),
            first_view.broker_revision,
        )

    reconnected_session = IBKRPaperSessionV1(
        account_id="DU9000001",
        client_id=17,
        session_id="synthetic-tws-session-reconnected",
        master_client_id=17,
        executions_since=EXECUTIONS_SINCE,
    )
    second_transport = FakeTwsTransport(reconnected_session)
    second_adapter = IBKRTwsPaperAdapter(second_transport, reconnected_session, (_binding(),))
    _queue_account_view(
        second_transport,
        open_orders=(
            _open_order(
                client_order_id=request.client_order_id,
                order_ref=encode_order_ref(request.account_id, request.client_order_id),
            ),
        ),
    )
    reconciled = second_adapter.read_account_view("DU9000001")

    assert [method for method, _args in second_transport.calls] == [
        "reqAllOpenOrders",
        "reqCompletedOrders",
        "reqPositions",
        "reqExecutions",
    ]
    with pytest.raises(BrokerOutcomeUnknown) as caught:
        second_adapter.submit(
            request,
            _SyntheticPermit("oms-retry-permit", request, reconciled.broker_revision),
            reconciled.broker_revision,
        )
    assert caught.value.code == BrokerUnknownCode.UNKNOWN_SUBMIT.value
    assert all(method != "placeOrder" for method, _args in second_transport.calls)


def test_wrong_or_reused_permit_never_reaches_fake_transport() -> None:
    adapter, transport = _adapter()
    request = _request()
    adapter.nextValidId(41)
    view = _reconcile(adapter, transport)
    wrong_request = _request(client_order_id="oms-order-synthetic-wrong-permit")
    wrong_permit = _SyntheticPermit(
        "oms-wrong-bound-permit", wrong_request, view.broker_revision
    )

    with pytest.raises(BrokerRejected) as caught:
        adapter.submit(request, wrong_permit, view.broker_revision)
    assert caught.value.code == BrokerRejectionCode.INVALID_ORDER.value
    assert all(method != "placeOrder" for method, _args in transport.calls)

    permit = _SyntheticPermit("oms-single-use-permit", request, view.broker_revision)
    _queue_place_ack(transport, request)
    result = adapter.submit(request, permit, view.broker_revision)
    result.assert_sealed()
    assert permit.consumed is True

    # The submit callback invalidates the original account snapshot. Reconcile
    # the acknowledged order before testing permit reuse against a current view.
    _queue_account_view(
        transport,
        open_orders=(_open_order(quantity=request.quantity),),
        request_id=2,
    )
    reconciled = adapter.read_account_view("DU9000001")
    second_request = _request(client_order_id="oms-order-synthetic-second")
    # Keep the same consumed token, but bind its test double to the current
    # request and revision so rejection demonstrates single-use enforcement.
    permit._request_digest = second_request.digest
    permit._revision = reconciled.broker_revision
    with pytest.raises(BrokerRejected) as caught:
        adapter.submit(second_request, permit, reconciled.broker_revision)
    assert caught.value.code == BrokerRejectionCode.INVALID_ORDER.value
    assert len([call for call in transport.calls if call[0] == "placeOrder"]) == 1


def test_cancel_timeout_is_unknown_and_not_confirmed() -> None:
    adapter, transport = _adapter()
    request = _request()
    adapter.nextValidId(41)
    view = _reconcile(adapter, transport)
    _queue_place_ack(transport, request)
    adapter.submit(
        request,
        _SyntheticPermit("oms-cancel-setup", request, view.broker_revision),
        view.broker_revision,
    )
    transport.queue_cancel(())

    with pytest.raises(BrokerOutcomeUnknown) as caught:
        adapter.cancel(_snapshot(request))

    assert caught.value.code == BrokerUnknownCode.UNKNOWN_CANCEL.value
    assert adapter.blocked is True
    assert len([call for call in transport.calls if call[0] == "cancelOrder"]) == 1


def test_open_order_callback_in_completed_component_makes_view_unknown() -> None:
    adapter, transport = _adapter()
    transport.queue_all_open_orders((IBKROpenOrderEndV1(),))
    transport.queue_completed_orders(
        (
            _open_order(
                order_id=77,
                perm_id=9077,
                client_order_id="oms-external-during-completed",
            ),
            IBKRCompletedOrdersEndV1(),
        )
    )
    transport.queue_positions((IBKRPositionEndV1(),))
    transport.queue_executions((IBKRExecDetailsEndV1(1),))

    with pytest.raises(BrokerOutcomeUnknown) as caught:
        adapter.read_account_view("DU9000001")

    assert caught.value.code == BrokerUnknownCode.UNKNOWN_ACCOUNT_VIEW.value
    assert adapter.blocked is True
    assert all(method != "placeOrder" for method, _args in transport.calls)


def test_account_callback_after_sealed_view_makes_submit_unknown_before_handoff() -> None:
    adapter, transport = _adapter()
    adapter.nextValidId(41)
    view = _reconcile(adapter, transport)
    request = _request(client_order_id="oms-order-after-view")
    adapter.openOrder(
        _open_order(
            order_id=88,
            perm_id=9088,
            client_order_id="oms-external-after-view",
        )
    )
    _queue_place_ack(transport, request, order_id=41, perm_id=9042)
    permit = _SyntheticPermit("oms-after-view-permit", request, view.broker_revision)

    with pytest.raises(BrokerOutcomeUnknown) as caught:
        adapter.submit(request, permit, view.broker_revision)

    assert caught.value.code in {
        BrokerUnknownCode.UNKNOWN_SUBMIT.value,
        BrokerUnknownCode.UNKNOWN_ACCOUNT_VIEW.value,
    }
    assert all(method != "placeOrder" for method, _args in transport.calls)


@pytest.mark.parametrize(
    "observed_order_id",
    [41, 99],
    ids=["next-native-id", "unrelated-callback"],
)
def test_callback_inside_permit_consume_aborts_before_place_order(
    observed_order_id: int,
) -> None:
    adapter, transport = _adapter()
    adapter.nextValidId(41)
    view = _reconcile(adapter, transport)
    request = _request(client_order_id="oms-reentrant-callback-submit")

    def observe_other_order() -> None:
        adapter.openOrder(
            _open_order(
                order_id=observed_order_id,
                perm_id=99000 + observed_order_id,
                client_order_id=f"oms-external-observed-{observed_order_id}",
            )
        )

    permit = _SyntheticPermit(
        "oms-reentrant-consume-permit",
        request,
        view.broker_revision,
        on_consume=observe_other_order,
    )

    with pytest.raises(BrokerOutcomeUnknown):
        adapter.submit(request, permit, view.broker_revision)

    assert adapter.callback_sequence == 1
    assert adapter.next_order_id > observed_order_id
    assert all(method != "placeOrder" for method, _args in transport.calls)


def test_cancel_status_reversal_is_unknown_and_records_discrepancy() -> None:
    adapter, transport = _adapter()
    request = _request()
    adapter.nextValidId(41)
    view = _reconcile(adapter, transport)
    _queue_place_ack(transport, request)
    adapter.submit(
        request,
        _SyntheticPermit("oms-cancel-reversal-setup", request, view.broker_revision),
        view.broker_revision,
    )
    transport.queue_cancel(
        (
            IBKROrderStatusV1(
                client_id=17,
                order_id=41,
                perm_id=9041,
                status="Cancelled",
                filled=Decimal("0"),
                remaining=Decimal("2.5"),
            ),
            IBKROrderStatusV1(
                client_id=17,
                order_id=41,
                perm_id=9041,
                status="Submitted",
                filled=Decimal("0"),
                remaining=Decimal("2.5"),
            ),
        )
    )

    with pytest.raises(BrokerOutcomeUnknown) as caught:
        adapter.cancel(_snapshot(request))

    assert caught.value.code == BrokerUnknownCode.UNKNOWN_CANCEL.value
    assert "ORDER_STATUS_CONFLICT" in adapter.discrepancies
    assert adapter.blocked is True
    assert len([call for call in transport.calls if call[0] == "cancelOrder"]) == 1


def test_cancel_terminal_conflict_across_callback_types_is_unknown() -> None:
    adapter, transport = _adapter()
    request = _request()
    adapter.nextValidId(41)
    view = _reconcile(adapter, transport)
    _queue_place_ack(transport, request)
    adapter.submit(
        request,
        _SyntheticPermit("oms-mixed-callback-cancel-setup", request, view.broker_revision),
        view.broker_revision,
    )
    transport.queue_cancel(
        (
            IBKRCompletedOrderV1(
                account_id="DU9000001",
                client_id=17,
                order_id=41,
                perm_id=9041,
                order_ref=encode_order_ref("DU9000001", request.client_order_id),
                con_id=900001,
                status="Cancelled",
            ),
            _open_order(status="Submitted", quantity=request.quantity),
        )
    )

    with pytest.raises(BrokerOutcomeUnknown) as caught:
        adapter.cancel(_snapshot(request))

    assert caught.value.code == BrokerUnknownCode.UNKNOWN_CANCEL.value
    assert "ORDER_STATUS_CONFLICT" in adapter.discrepancies
    assert adapter.blocked is True
    assert len([call for call in transport.calls if call[0] == "cancelOrder"]) == 1


@pytest.mark.parametrize("mismatch", ["perm_id", "contract", "account"])
def test_cancel_snapshot_identity_mismatch_never_calls_native_cancel(
    mismatch: str,
) -> None:
    adapter, transport = _adapter()
    request = _request()
    adapter.nextValidId(41)
    view = _reconcile(adapter, transport)
    _queue_place_ack(transport, request)
    adapter.submit(
        request,
        _SyntheticPermit("oms-cancel-identity-setup", request, view.broker_revision),
        view.broker_revision,
    )

    if mismatch == "perm_id":
        snapshot = _snapshot(request, venue_order_id="99999")
        expected_error = BrokerRejected
    elif mismatch == "contract":
        wrong_contract_request = _request(instrument_id="NQ-20261218")
        snapshot = _snapshot(wrong_contract_request)
        expected_error = BrokerRejected
    else:
        wrong_account_request = _request(account_id="DU9000002")
        snapshot = _snapshot(wrong_account_request)
        expected_error = BrokerOutcomeUnknown

    with pytest.raises(expected_error) as caught:
        adapter.cancel(snapshot)

    if expected_error is BrokerRejected:
        assert caught.value.code == BrokerRejectionCode.INVALID_ORDER.value
    else:
        assert caught.value.code == BrokerUnknownCode.UNKNOWN_CANCEL.value
    assert all(method != "cancelOrder" for method, _args in transport.calls)
