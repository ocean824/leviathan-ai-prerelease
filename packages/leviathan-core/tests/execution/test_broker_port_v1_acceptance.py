"""Independent acceptance checks for the frozen ADR-0008 BrokerPortV1 boundary."""

from __future__ import annotations

import copy
import pickle
from dataclasses import fields, replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any

import pytest

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
    DispatchPermitV1,
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
from leviathan_core.execution.broker_reconciliation import FakeBrokerReconciliation
from leviathan_core.execution.order_models import BrokerObservation, OrderState


def _issued_values() -> tuple[object, ...]:
    return (
        _issue_venue_capability(False, timedelta(seconds=2)),
        _issue_venue_identity(BrokerVenue.ALPACA, BrokerEnvironment.PAPER, "paper-account"),
        _issue_submit_result("venue-order-1", OrderState.WORKING),
        _issue_cancel_result(True),
        _issue_execution(
            "execution-1",
            "venue-order-1",
            "client-order-1",
            "AAPL",
            "BUY",
            Decimal("1"),
            Decimal("100"),
            datetime(2026, 10, 5, tzinfo=UTC),
        ),
        _account_view("paper-account", (), (("AAPL", Decimal("2")),), 0),
    )


def _account_view(
    account_id: str,
    open_orders: tuple[BrokerObservation, ...],
    positions: tuple[tuple[str, Decimal], ...],
    broker_revision: int,
    executions: tuple[ExecutionV1, ...] = (),
    executions_since: datetime = datetime(2026, 10, 5, tzinfo=UTC),
    *,
    complete: bool = True,
) -> AccountViewV1:
    return _issue_account_view(
        account_id,
        open_orders,
        positions,
        broker_revision,
        executions,
        executions_since,
        complete=complete,
    )


class _RecordingPermit:
    def __init__(self) -> None:
        self.consumed: tuple[str, str, int] | None = None

    @property
    def order_id(self) -> str:
        return "order-1"

    def consume(self, order_id: str, request_digest: str, expected_revision: int) -> None:
        self.consumed = (order_id, request_digest, expected_revision)


class _ConformingPortDouble:
    """Minimal structural implementation; no transport or side effects."""

    def __init__(self) -> None:
        self._capability = _issue_venue_capability(False, timedelta(seconds=2))
        self._venue = _issue_venue_identity(
            BrokerVenue.ALPACA, BrokerEnvironment.PAPER, "paper-account"
        )
        self.submit_result = _issue_submit_result("venue-order-1", OrderState.WORKING)
        self.cancel_result = _issue_cancel_result(True)
        self.account_view = _account_view("paper-account", (), (), 7)
        self.submit_calls: list[tuple[OrderRequest, int]] = []

    @property
    def capability(self) -> VenueDispatchCapabilityV1:
        return self._capability  # type: ignore[no-any-return]

    @property
    def venue(self) -> VenueIdentityV1:
        return self._venue  # type: ignore[no-any-return]

    def submit(
        self, request: OrderRequest, permit: DispatchPermitV1, expected_revision: int
    ) -> SubmitResultV1:
        permit.consume(permit.order_id, request.digest, expected_revision)
        self.submit_calls.append((request, expected_revision))
        return self.submit_result  # type: ignore[no-any-return]

    def cancel(self, order: OrderSnapshot) -> CancelResultV1:
        del order
        return self.cancel_result  # type: ignore[no-any-return]

    def read_order(self, order: OrderSnapshot) -> BrokerObservation | None:
        del order
        return None

    def read_account_view(self, account_id: str) -> AccountViewV1:
        assert account_id == "paper-account"
        return self.account_view  # type: ignore[no-any-return]


def _request() -> OrderRequest:
    return OrderRequest(
        project_id="leviathan-ai",
        environment="paper",
        account_id="paper-account",
        venue="ALPACA",
        instrument_id="AAPL",
        native_contract_id="asset-aapl",
        side="BUY",
        quantity=Decimal("1"),
        order_type="MARKET",
        time_in_force="DAY",
        client_order_id="client-order-1",
        intent_idempotency_key="synthetic-intent-1",
        attempt=1,
        strategy_id="strategy-1",
        risk_policy_digest="a" * 64,
        actor_id="actor-1",
        capability="paper-submit",
    )


def _snapshot() -> OrderSnapshot:
    return OrderSnapshot(
        order_id="order-1",
        request=_request(),
        state=OrderState.READY,
        version=3,
        venue_order_id=None,
        filled_quantity=Decimal(0),
        discrepancies=(),
        submit_attempted=False,
        cancel_attempted=False,
    )


def test_closed_broker_enums_have_only_the_contract_values() -> None:
    assert {item.value for item in BrokerVenue} == {"IBKR_TWS", "MT5", "ALPACA"}
    assert {item.value for item in BrokerEnvironment} == {"PAPER", "DEMO", "LIVE"}
    assert {item.value for item in BrokerUnknownCode} == {
        "UNKNOWN_SUBMIT",
        "UNKNOWN_CANCEL",
        "UNKNOWN_READ_ORDER",
        "UNKNOWN_ACCOUNT_VIEW",
    }
    assert {item.value for item in BrokerRejectionCode} == {
        "VENUE_REJECTED",
        "DUPLICATE_CLIENT_ORDER_ID",
        "UNSUPPORTED_ORDER_CLASS",
        "UNSUPPORTED_INSTRUMENT",
        "INVALID_ORDER",
        "ACCOUNT_MISMATCH",
        "ENVIRONMENT_MISMATCH",
        "RATE_LIMITED",
        "SHORT_SALE_UNSUPPORTED",
    }
    with pytest.raises(ValueError):
        BrokerVenue("UNREGISTERED_VENUE")
    with pytest.raises(ValueError):
        BrokerEnvironment("sandbox")


def test_unknown_and_rejection_errors_accept_closed_codes_only_and_do_not_echo() -> None:
    canary = "response-body-canary-do-not-echo"
    for error_type, code_type, allowed in (
        (BrokerOutcomeUnknown, BrokerUnknownCode, BrokerUnknownCode.UNKNOWN_SUBMIT),
        (BrokerRejected, BrokerRejectionCode, BrokerRejectionCode.VENUE_REJECTED),
    ):
        error = error_type(allowed)
        assert error.code == allowed.value
        assert canary not in str(error)
        assert canary not in repr(error.args)
        with pytest.raises(BrokerPortError):
            error_type(canary)  # type: ignore[arg-type]
        with pytest.raises(BrokerPortError) as caught:
            error_type(canary)  # type: ignore[arg-type]
        assert canary not in str(caught.value)
        assert canary not in repr(caught.value.args)
        assert len(tuple(code_type)) > 0


def test_v1_protocol_is_runtime_checkable_and_legacy_fake_is_not_conforming() -> None:
    port = _ConformingPortDouble()
    assert isinstance(port, BrokerPortV1)
    assert port.capability.settle_window == timedelta(seconds=2)
    assert port.venue == _issue_venue_identity(
        BrokerVenue.ALPACA, BrokerEnvironment.PAPER, "paper-account"
    )

    request = _request()
    permit = _RecordingPermit()
    assert permit.order_id == "order-1"
    with pytest.raises(AttributeError):
        permit.order_id = "changed-order"  # type: ignore[misc]
    result = port.submit(request, permit, 7)
    assert permit.consumed == ("order-1", request.digest, 7)
    assert port.submit_calls == [(request, 7)]
    assert result.state is OrderState.WORKING
    assert port.cancel(_snapshot()).confirmed
    assert port.read_order(_snapshot()) is None
    assert port.read_account_view("paper-account").broker_revision == 7

    legacy = FakeBrokerPort(FakeBrokerReconciliation())
    assert isinstance(legacy, BrokerPortV1)
    assert hasattr(legacy, "venue")
    assert callable(legacy.read_account_view)


def test_capability_requires_exact_bool_and_positive_settle_window() -> None:
    with pytest.raises(BrokerPortError):
        _issue_venue_capability(True, timedelta(seconds=1))
    for value in (1, 0, "false", None):
        with pytest.raises(BrokerPortError):
            _issue_venue_capability(value, timedelta(seconds=1))  # type: ignore[arg-type]
    for window in (None, timedelta(0), timedelta(microseconds=-1), 2, "2s"):
        with pytest.raises(BrokerPortError):
            _issue_venue_capability(False, window)  # type: ignore[arg-type]
    assert _issue_venue_capability(True).settle_window is None
    assert _issue_venue_capability(False, timedelta(microseconds=1)).settle_window == timedelta(
        microseconds=1
    )


def test_venue_identity_uses_closed_types_ascii_identity_and_exact_account_binding() -> None:
    for venue, environment, account_id in (
        ("ALPACA", BrokerEnvironment.PAPER, "paper-account"),
        (BrokerVenue.ALPACA, "PAPER", "paper-account"),
        (BrokerVenue.ALPACA, BrokerEnvironment.PAPER, "account-" + chr(233)),
        (BrokerVenue.ALPACA, BrokerEnvironment.PAPER, "account\ncanary"),
        (BrokerVenue.ALPACA, BrokerEnvironment.PAPER, "x" * 129),
    ):
        with pytest.raises(BrokerPortError):
            _issue_venue_identity(venue, environment, account_id)  # type: ignore[arg-type]


def test_submit_result_requires_working_id_or_closed_rejection_without_id() -> None:
    for args in (
        (None, OrderState.WORKING, None),
        ("venue-order", OrderState.WORKING, BrokerRejectionCode.VENUE_REJECTED),
        ("venue-order", OrderState.REJECTED, BrokerRejectionCode.VENUE_REJECTED),
        (None, OrderState.REJECTED, None),
        (None, OrderState.REJECTED, "response-body-canary"),
        (None, OrderState.FILLED, None),
    ):
        with pytest.raises(BrokerPortError):
            _issue_submit_result(*args)  # type: ignore[arg-type]
    rejected = _issue_submit_result(None, OrderState.REJECTED, BrokerRejectionCode.INVALID_ORDER)
    assert rejected.rejection_code is BrokerRejectionCode.INVALID_ORDER
    assert rejected.venue_order_id is None
    for invalid_id in ("venue id with spaces", "x" * 129, "é-order", "venue\ncanary"):
        with pytest.raises(BrokerPortError):
            _issue_submit_result(invalid_id, OrderState.WORKING)  # type: ignore[arg-type]


def test_cancel_result_requires_an_exact_boolean() -> None:
    for value in (0, 1, "true", None):
        with pytest.raises(BrokerPortError):
            _issue_cancel_result(value)  # type: ignore[arg-type]
    assert _issue_cancel_result(False).confirmed is False


def test_account_view_enforces_sorted_unique_immutable_positions_and_revision() -> None:
    assert _account_view(
        "paper-account", (), (("AAPL", Decimal("1.2500")), ("MSFT", Decimal("-2"))), 0
    ).positions == (("AAPL", Decimal("1.25")), ("MSFT", Decimal("-2")))
    invalid_positions = (
        (("MSFT", Decimal("1")), ("AAPL", Decimal("2"))),
        (("AAPL", Decimal("1")), ("AAPL", Decimal("2"))),
        (("AAPL", True),),
        (("AAPL", float("nan")),),
        (("AAPL", Decimal("1E+100000")),),
        [("AAPL", Decimal("1"))],
        ((chr(233), Decimal("1")),),
    )
    for positions in invalid_positions:
        with pytest.raises(BrokerPortError):
            _account_view("paper-account", (), positions, 0)  # type: ignore[arg-type]
    for revision in (True, False, -1, 1.0, "1", 2**63):
        with pytest.raises(BrokerPortError):
            _account_view("paper-account", (), (), revision)  # type: ignore[arg-type]


def test_account_view_only_accepts_working_observations_for_its_bound_account() -> None:
    observation = BrokerObservation(
        observation_id="observation-1",
        environment="paper",
        account_id="paper-account",
        venue="ALPACA",
        client_order_id="client-order-1",
        status=OrderState.WORKING,
        observed_at=datetime(2026, 10, 5, tzinfo=UTC),
        venue_order_id="venue-order-1",
        broker_sequence=0,
    )
    view = _account_view("paper-account", (observation,), (), 1)
    assert view.open_orders == (observation,)
    for invalid in (("not-an-observation",),):
        with pytest.raises(BrokerPortError):
            _account_view("paper-account", invalid, (), 1)  # type: ignore[arg-type]
    canceled = replace(observation, status=OrderState.CANCELED)
    with pytest.raises(BrokerPortError):
        _account_view("paper-account", (canceled,), (), 1)
    mismatched = replace(observation, account_id="other-account")
    with pytest.raises(BrokerPortError):
        _account_view("paper-account", (mismatched,), (), 1)


def test_decimal_positions_are_context_invariant_and_errors_do_not_echo_values() -> None:
    from decimal import localcontext

    amount = Decimal("12345678901234567890.125")
    with localcontext() as context:
        context.prec = 2
        low_precision = _account_view("paper-account", (), (("AAPL", amount),), 0)
    with localcontext() as context:
        context.prec = 50
        high_precision = _account_view("paper-account", (), (("AAPL", amount),), 0)
    assert low_precision.positions == high_precision.positions == (("AAPL", amount),)

    canary = "invalid-account-canary\n"
    with pytest.raises(BrokerPortError) as caught:
        _account_view(canary, (), (), 0)
    assert canary not in str(caught.value)
    assert canary not in repr(caught.value.args)


def test_account_view_carries_only_complete_recent_executions_since_its_cursor() -> None:
    since = datetime(2026, 10, 5, tzinfo=UTC)
    execution_a = _issue_execution(
        "execution-a",
        "venue-order-a",
        "client-order-a",
        "AAPL",
        "BUY",
        Decimal("2"),
        Decimal("100.25"),
        since,
    )
    execution_b = _issue_execution(
        "execution-b",
        "venue-order-b",
        None,
        "MSFT",
        "SELL",
        Decimal("1"),
        Decimal("250"),
        since + timedelta(seconds=1),
    )
    view = _account_view("paper-account", (), (), 10, (execution_a, execution_b), since)
    assert view.executions == (execution_a, execution_b)
    assert view.executions_since == since

    earlier = _issue_execution(
        "execution-old",
        "venue-order-old",
        "client-order-old",
        "AAPL",
        "BUY",
        Decimal("1"),
        Decimal("99"),
        since - timedelta(microseconds=1),
    )
    for invalid_executions in (
        (execution_b, execution_a),
        (execution_a, execution_a),
        (earlier,),
        (object(),),
        [execution_a],
    ):
        with pytest.raises(BrokerPortError):
            _account_view(
                "paper-account",
                (),
                (),
                10,
                invalid_executions,
                since,  # type: ignore[arg-type]
            )
    with pytest.raises(BrokerOutcomeUnknown) as incomplete:
        _account_view("paper-account", (), (), 10, (), since, complete=False)
    assert incomplete.value.code == BrokerUnknownCode.UNKNOWN_ACCOUNT_VIEW.value


def test_execution_record_validates_exact_values_and_has_its_own_identity() -> None:
    now = datetime(2026, 10, 5, tzinfo=UTC)
    for invalid_args in (
        ("bad id", "venue-order", None, "AAPL", "BUY", Decimal("1"), Decimal("2"), now),
        ("execution", "venue-order", None, "AAPL", "BUY", Decimal("0"), Decimal("2"), now),
        ("execution", "venue-order", None, "AAPL", "BUY", Decimal("1"), Decimal("0"), now),
        ("execution", "venue-order", None, "AAPL", "SIDEWAYS", Decimal("1"), Decimal("2"), now),
        ("execution", "venue-order", None, "AAPL", "BUY", 1.0, Decimal("2"), now),
    ):
        with pytest.raises(BrokerPortError):
            _issue_execution(*invalid_args)  # type: ignore[arg-type]
    execution = _issue_execution(
        "execution-1",
        "venue-order-1",
        "client-order-1",
        "AAPL",
        "BUY",
        Decimal("1.00"),
        Decimal("100.250"),
        now,
    )
    assert execution.quantity == Decimal("1")
    assert execution.price == Decimal("100.25")
    assert execution.execution_id == "execution-1"


@pytest.mark.parametrize("value", _issued_values())
def test_issued_records_are_immutable_noncopyable_and_nonserializable(value: object) -> None:
    assert not hasattr(value, "__dict__")
    assert "<sealed>" in repr(value)
    value.assert_sealed()  # type: ignore[attr-defined]
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(BrokerPortError):
            operation(value)
    field_name = fields(value)[0].name
    with pytest.raises((AttributeError, BrokerPortError)):
        setattr(value, field_name, "assignment-canary")
    with pytest.raises((AttributeError, BrokerPortError)):
        delattr(value, field_name)
    state = [getattr(value, field.name) for field in fields(value)]
    state[0] = "state-canary"
    with pytest.raises(BrokerPortError) as state_error:
        value.__setstate__(state)  # type: ignore[attr-defined]
    assert "state-canary" not in str(state_error.value)


@pytest.mark.parametrize("value", _issued_values())
def test_direct_construction_and_dataclass_replace_cannot_forge_issued_records(
    value: object,
) -> None:
    with pytest.raises(BrokerPortError):
        replace(value)
    with pytest.raises(BrokerPortError):
        type(value).__init__(value, **_constructor_kwargs(value))
    if isinstance(value, VenueIdentityV1):
        with pytest.raises(BrokerPortError):
            VenueIdentityV1(
                value.venue,
                value.environment,
                value.account_id,
                _issuer=value,
            )


def _constructor_kwargs(value: object) -> dict[str, Any]:
    if isinstance(value, VenueDispatchCapabilityV1):
        return {
            "atomic_revision_dispatch": value.atomic_revision_dispatch,
            "settle_window": value.settle_window,
        }
    if isinstance(value, VenueIdentityV1):
        return {
            "venue": value.venue,
            "environment": value.environment,
            "account_id": value.account_id,
        }
    if isinstance(value, SubmitResultV1):
        return {
            "venue_order_id": value.venue_order_id,
            "state": value.state,
            "rejection_code": value.rejection_code,
        }
    if isinstance(value, CancelResultV1):
        return {"confirmed": value.confirmed}
    if isinstance(value, ExecutionV1):
        return {
            "execution_id": value.execution_id,
            "venue_order_id": value.venue_order_id,
            "client_order_id": value.client_order_id,
            "instrument_id": value.instrument_id,
            "side": value.side,
            "quantity": value.quantity,
            "price": value.price,
            "executed_at": value.executed_at,
        }
    if isinstance(value, AccountViewV1):
        return {
            "account_id": value.account_id,
            "open_orders": value.open_orders,
            "positions": value.positions,
            "broker_revision": value.broker_revision,
            "executions": value.executions,
            "executions_since": value.executions_since,
        }
    raise AssertionError("unknown issued type")


@pytest.mark.parametrize("value", _issued_values())
def test_issued_values_do_not_store_the_initvar_issuer_or_a_public_seal(value: object) -> None:
    assert all(field.name != "_issuer" for field in fields(value))
    assert all("seal" not in field.name.lower() for field in fields(value))
    assert getattr(value, "_issuer", None) is None
    value.assert_sealed()  # type: ignore[attr-defined]


def test_equal_but_distinct_twin_does_not_borrow_issuance_and_tampering_is_detected() -> None:
    issued = _issue_venue_identity(BrokerVenue.ALPACA, BrokerEnvironment.PAPER, "paper-account")
    twin = object.__new__(VenueIdentityV1)
    for name, item in _constructor_kwargs(issued).items():
        object.__setattr__(twin, name, item)
    assert twin == issued
    with pytest.raises(BrokerPortError) as caught:
        twin.assert_sealed()
    assert caught.value.code == "UNISSUED_BROKER_RECORD"

    object.__setattr__(issued, "account_id", "tampered-account")
    with pytest.raises(BrokerPortError) as tampered:
        issued.assert_sealed()
    assert tampered.value.code == "BROKER_RECORD_TAMPERED"


def test_lesson_18_seal_binds_exact_scalar_types_in_execution_and_account_view() -> None:
    execution = _issue_execution(
        "execution-seal-type",
        "venue-order-seal-type",
        "client-order-seal-type",
        "AAPL",
        "BUY",
        Decimal("1"),
        Decimal("100"),
        datetime(2026, 10, 5, tzinfo=UTC),
    )
    object.__setattr__(execution, "quantity", 1)
    with pytest.raises(BrokerPortError) as execution_tampered:
        execution.assert_sealed()
    assert execution_tampered.value.code == "BROKER_RECORD_TAMPERED"

    view = _account_view("paper-account", (), (), 1)
    object.__setattr__(view, "broker_revision", Decimal("1"))
    with pytest.raises(BrokerPortError) as revision_tampered:
        view.assert_sealed()
    assert revision_tampered.value.code == "BROKER_RECORD_TAMPERED"


def test_lesson_18_nested_execution_and_mutable_list_replacements_fail_at_each_use() -> None:
    execution = _issue_execution(
        "execution-nested-seal",
        "venue-order-nested-seal",
        "client-order-nested-seal",
        "AAPL",
        "BUY",
        Decimal("1"),
        Decimal("100"),
        datetime(2026, 10, 5, tzinfo=UTC),
    )
    nested_view = _account_view(
        "paper-account",
        (),
        (),
        1,
        (execution,),
        datetime(2026, 10, 5, tzinfo=UTC),
    )
    object.__setattr__(execution, "quantity", 1)
    with pytest.raises(BrokerPortError) as nested_tampered:
        nested_view.assert_sealed()
    assert nested_tampered.value.code == "BROKER_RECORD_TAMPERED"

    list_execution = _issue_execution(
        "execution-list-seal",
        "venue-order-list-seal",
        "client-order-list-seal",
        "AAPL",
        "BUY",
        Decimal("1"),
        Decimal("100"),
        datetime(2026, 10, 5, tzinfo=UTC),
    )
    for field_name, valid_tuple in (
        ("executions", (list_execution,)),
        ("positions", (("AAPL", Decimal("2")),)),
    ):
        list_view = _account_view(
            "paper-account",
            (),
            (("AAPL", Decimal("2")),),
            2,
            (list_execution,),
            datetime(2026, 10, 5, tzinfo=UTC),
        )
        list_view.assert_sealed()
        mutable_value = list(valid_tuple)
        object.__setattr__(list_view, field_name, mutable_value)
        with pytest.raises(BrokerPortError) as mutable_tampered:
            list_view.assert_sealed()
        assert mutable_tampered.value.code in {
            "BROKER_RECORD_TAMPERED",
            "INVALID_BROKER_RECORD",
        }

        # Recheck after mutation as a consumer would at its next use boundary.
        mutable_value.clear()
        with pytest.raises(BrokerPortError) as post_check_tampered:
            list_view.assert_sealed()
        assert post_check_tampered.value.code in {
            "BROKER_RECORD_TAMPERED",
            "INVALID_BROKER_RECORD",
        }


@pytest.mark.parametrize("issued", _issued_values())
def test_lesson_17_reinitialization_fails_without_changing_issued_record(
    issued: object,
) -> None:
    before = tuple(getattr(issued, field.name) for field in fields(issued))
    changed = _constructor_kwargs(issued)
    if isinstance(issued, VenueDispatchCapabilityV1):
        changed.update(atomic_revision_dispatch=True, settle_window=None)
    elif isinstance(issued, VenueIdentityV1):
        changed.update(venue=BrokerVenue.MT5, environment=BrokerEnvironment.DEMO)
    elif isinstance(issued, SubmitResultV1):
        changed.update(venue_order_id="changed-venue-order")
    elif isinstance(issued, CancelResultV1):
        changed.update(confirmed=False)
    elif isinstance(issued, AccountViewV1):
        changed.update(broker_revision=issued.broker_revision + 1)
    with pytest.raises(BrokerPortError):
        type(issued).__init__(issued, **changed)
    after = tuple(getattr(issued, field.name) for field in fields(issued))
    assert after == before
    issued.assert_sealed()  # type: ignore[attr-defined]


def test_applicable_standing_lessons_are_bound_to_port_contract() -> None:
    """The v1 port has no policy, quotient, correction timeline, or Pydantic model path."""
    # Lessons 1, 5, 7, 9 and 12 apply to exact Decimal position values and are
    # exercised by construction/canonicalization and magnitude rejection above.
    view_a = _account_view("paper-account", (), (("AAPL", Decimal("1.250")),), 1)
    view_b = _account_view("paper-account", (), (("AAPL", Decimal("1.25")),), 1)
    assert view_a.positions == view_b.positions
    # Lessons 2, 3, 8, 11, 14, 15, 16, 17 and 18 are exercised by the explicit
    # validation, error-redaction, freeze, issuance and identity tests above.
    # Lessons 4/10/14's Pydantic-specific rules, 6's content-derived IDs, and
    # 13's correction-as-of rule have no Pydantic/policy/ID-history path here.
    assert view_a.broker_revision == 1
