"""Offline unit checks for the Alpaca paper mapping and scripted transport."""

from __future__ import annotations

import copy
import pickle
from dataclasses import replace
from datetime import UTC, datetime
from decimal import Decimal

import pytest

from leviathan_core.execution.broker_port_v1 import (
    BrokerOutcomeUnknown,
    BrokerPortV1,
    BrokerRejected,
    BrokerRejectionCode,
    BrokerUnknownCode,
)
from leviathan_core.execution.brokers.alpaca_mapping import (
    AlpacaAssetMapV1,
    AlpacaAssetV1,
    AlpacaMappingError,
    AlpacaOrderSpecV1,
    map_alpaca_order,
)
from leviathan_core.execution.brokers.alpaca_paper import (
    AlpacaAccountRecordV1,
    AlpacaExecutionRecordV1,
    AlpacaOrderRecordV1,
    AlpacaPaperBrokerPortV1,
    AlpacaPaperError,
    AlpacaPositionRecordV1,
    AlpacaSessionBindingV1,
    AlpacaTradeUpdateV1,
    FakeAlpacaOMSEvidence,
    RecordedAlpacaTransport,
    RecordedHttpError,
)
from leviathan_core.execution.order_models import OrderRequest, OrderSnapshot, OrderState


def _assets(*, round_quantity: bool = False) -> AlpacaAssetMapV1:
    return AlpacaAssetMapV1(
        revision="asset-rev-1",
        assets=(
            AlpacaAssetV1(
                instrument_id="equity-AAPL",
                asset_id="asset-AAPL",
                symbol="AAPL",
                tick_size=Decimal("0.01"),
                lot_size=Decimal(1),
                round_quantity_toward_zero=round_quantity,
            ),
        ),
    )


def _spec(**overrides: object) -> AlpacaOrderSpecV1:
    fields: dict[str, object] = {
        "instrument_id": "equity-AAPL",
        "native_contract_id": "asset-AAPL",
        "side": "BUY",
        "quantity": Decimal(3),
        "order_type": "LIMIT",
        "time_in_force": "DAY",
        "client_order_id": "x" * 128,
        "limit_price": Decimal("123.45"),
    }
    fields.update(overrides)
    return AlpacaOrderSpecV1(**fields)  # type: ignore[arg-type]


def test_exact_equity_mapping_and_verbatim_client_id() -> None:
    mapped = map_alpaca_order(_spec(), _assets())
    assert mapped.to_wire() == {
        "symbol": "AAPL",
        "qty": "3",
        "side": "buy",
        "type": "limit",
        "time_in_force": "day",
        "client_order_id": "x" * 128,
        "order_class": "simple",
        "extended_hours": False,
        "limit_price": "123.45",
    }
    with pytest.raises(AlpacaMappingError, match="INVALID_CLIENT_ORDER_ID"):
        _spec(client_order_id="x" * 129)


def test_unsupported_scope_and_exact_tick_lot_rules() -> None:
    for order_class in ("bracket", "oco", "oto"):
        with pytest.raises(AlpacaMappingError, match="UNSUPPORTED_ORDER_CLASS"):
            _spec(order_class=order_class)
    for order_type in ("STOP", "STOP_LIMIT"):
        with pytest.raises(AlpacaMappingError, match="UNSUPPORTED_ORDER_TYPE"):
            _spec(order_type=order_type)
    with pytest.raises(AlpacaMappingError, match="UNSUPPORTED_ORDER_TYPE"):
        _spec(order_type=[])
    with pytest.raises(AlpacaMappingError, match="UNSUPPORTED_TIF"):
        _spec(time_in_force="GTD")
    with pytest.raises(AlpacaMappingError, match="UNSUPPORTED_INSTRUMENT"):
        _spec(instrument_kind="CRYPTO")
    with pytest.raises(AlpacaMappingError, match="UNSUPPORTED_NOTIONAL"):
        _spec(notional=Decimal(100))
    with pytest.raises(AlpacaMappingError, match="UNSUPPORTED_EXTENDED_HOURS"):
        _spec(extended_hours=True)
    with pytest.raises(AlpacaMappingError, match="TICK_VIOLATION"):
        map_alpaca_order(_spec(limit_price=Decimal("123.451")), _assets())
    with pytest.raises(AlpacaMappingError, match="LOT_VIOLATION"):
        map_alpaca_order(_spec(quantity=Decimal("3.5")), _assets())
    assert (
        map_alpaca_order(_spec(quantity=Decimal("3.5")), _assets(round_quantity=True)).to_wire()[
            "qty"
        ]
        == "3"
    )


def test_session_binding_is_paper_only_and_frozen() -> None:
    session = AlpacaSessionBindingV1(
        account_id="paper-acct", mapping_revision="asset-rev-1", calendar_revision="cal-1"
    )
    assert session.environment == "PAPER"
    with pytest.raises(AlpacaPaperError, match="PAPER_SESSION_REQUIRED"):
        replace(session, environment="LIVE")
    with pytest.raises(AlpacaPaperError, match="PAPER_SESSION_REQUIRED"):
        replace(session, base_url_identity="ALPACA_LIVE")
    with pytest.raises(AlpacaPaperError, match="INVALID_CREDENTIAL_REFERENCE"):
        replace(session, credential_ref="vault://leviathan-ai/live/alpaca/KEY")
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(TypeError):
            operation(session)


def test_recorded_transport_is_explicit_and_never_echoes_response_body() -> None:
    fake = RecordedAlpacaTransport()
    payload = map_alpaca_order(_spec(), _assets())
    with pytest.raises(TimeoutError, match="UNSCRIPTED_POST"):
        fake.post_order(payload)
    failure = RecordedHttpError(422, response_body={"secret": "canary-private"})
    assert "canary-private" not in str(failure)
    assert "canary-private" not in repr(failure)
    assert "canary-private" not in repr(failure.args)
    fake.queue_post(failure)
    with pytest.raises(RecordedHttpError):
        fake.post_order(payload)
    assert len(fake.post_payloads) == 2
    assert fake.post_payloads[1].client_order_id == "x" * 128


def test_recorded_zero_startup_orders_is_an_explicit_snapshot() -> None:
    fake = RecordedAlpacaTransport()
    observed_at = datetime(2026, 10, 5, tzinfo=UTC)
    fake.queue_account(
        AlpacaAccountRecordV1(
            account_id="paper-acct",
            broker_revision=3,
            open_orders=(),
            positions=(),
            observed_at=observed_at,
            venue_time_ns=100,
            executions_since=observed_at,
        )
    )
    view = fake.get_account_view("paper-acct")
    assert view.open_orders == ()
    assert view.broker_revision == 3
    with pytest.raises(TimeoutError, match="UNSCRIPTED_ACCOUNT_READ"):
        fake.get_account_view("paper-acct")


def test_recorded_order_result_rejects_mutable_replacement() -> None:
    record = AlpacaOrderRecordV1(
        venue_order_id="alpaca-1",
        client_order_id="client-1",
        account_id="paper-acct",
        state="new",
        observed_at=datetime(2026, 10, 5, tzinfo=UTC),
    )
    with pytest.raises(AlpacaPaperError, match="INVALID_ORDER_RECORD"):
        replace(record, broker_sequence=True)
    with pytest.raises(TypeError):
        copy.copy(record)


def _request() -> OrderRequest:
    return OrderRequest(
        project_id="leviathan-ai",
        environment="paper",
        account_id="paper-acct",
        venue="ALPACA",
        instrument_id="equity-AAPL",
        native_contract_id="asset-AAPL",
        side="BUY",
        quantity=Decimal(3),
        order_type="LIMIT",
        time_in_force="DAY",
        client_order_id="client-1",
        intent_idempotency_key="intent-1",
        attempt=1,
        strategy_id="strategy-1",
        risk_policy_digest="a" * 64,
        actor_id="operator-1",
        capability="paper-submit",
        limit_price=Decimal("123.45"),
    )


def _snapshot(venue_order_id: str | None = "alpaca-1") -> OrderSnapshot:
    return OrderSnapshot(
        order_id="local-1",
        request=_request(),
        state=OrderState.WORKING,
        version=1,
        venue_order_id=venue_order_id,
        filled_quantity=Decimal(0),
        discrepancies=(),
        submit_attempted=True,
        cancel_attempted=False,
    )


def _port(
    fake: RecordedAlpacaTransport,
    *,
    now_ns: int = 100,
    oms_evidence: FakeAlpacaOMSEvidence | None = None,
) -> AlpacaPaperBrokerPortV1:
    port = AlpacaPaperBrokerPortV1(
        AlpacaSessionBindingV1(
            account_id="paper-acct", mapping_revision="asset-rev-1", calendar_revision="cal-1"
        ),
        _assets(),
        fake,
        oms_evidence=oms_evidence or FakeAlpacaOMSEvidence(),
        clock_ns=lambda: now_ns,
    )
    assert isinstance(port, BrokerPortV1)
    return port


class _Permit:
    def __init__(self, request: OrderRequest, revision: int = 1) -> None:
        self.order_id = "local-1"
        self.request_digest = request.digest
        self.revision = revision
        self.used = False

    def consume(self, order_id: str, request_digest: str, expected_revision: int) -> None:
        if (
            self.used
            or order_id != self.order_id
            or request_digest != self.request_digest
            or expected_revision != self.revision
        ):
            raise ValueError("INVALID_PERMIT")
        self.used = True


def _account(
    *,
    revision: int = 1,
    venue_time_ns: int | None = 100,
    open_orders: tuple[AlpacaOrderRecordV1, ...] = (),
    positions: tuple[AlpacaPositionRecordV1, ...] = (),
    executions: tuple[AlpacaExecutionRecordV1, ...] = (),
) -> AlpacaAccountRecordV1:
    return AlpacaAccountRecordV1(
        account_id="paper-acct",
        broker_revision=revision,
        open_orders=open_orders,
        positions=positions,
        observed_at=datetime(2026, 10, 5, tzinfo=UTC),
        venue_time_ns=venue_time_ns,
        executions_since=datetime(2026, 10, 5, tzinfo=UTC),
        executions=executions,
    )


def test_account_view_is_sealed_and_zero_startup_orders_are_explicit() -> None:
    fake = RecordedAlpacaTransport()
    fake.queue_account(
        AlpacaAccountRecordV1(
            account_id="paper-acct",
            broker_revision=1,
            open_orders=(),
            positions=(),
            observed_at=datetime(2026, 10, 5, tzinfo=UTC),
            venue_time_ns=100,
            executions_since=datetime(2026, 10, 5, tzinfo=UTC),
        )
    )
    port = _port(fake)
    assert port.capability.atomic_revision_dispatch is False
    assert port.capability.settle_window is not None
    assert port.venue.account_id == "paper-acct"
    view = port.read_account_view("paper-acct")
    view.assert_sealed()
    assert view.open_orders == ()
    assert view.broker_revision == 1
    assert fake.account_lookup_ids == ["paper-acct"]


def test_post_construction_binding_tamper_stops_before_transport() -> None:
    fake = RecordedAlpacaTransport()
    port = _port(fake)
    object.__setattr__(port._binding, "environment", "LIVE")
    with pytest.raises(AlpacaPaperError, match="CONFIG_TAMPERED"):
        port.read_account_view("paper-acct")
    assert fake.account_lookup_ids == []


def test_read_order_uses_client_id_first_and_cancel_timeout_stays_unknown() -> None:
    fake = RecordedAlpacaTransport()
    port = _port(fake)
    fake.queue_client_read(
        AlpacaOrderRecordV1(
            venue_order_id="alpaca-1",
            client_order_id="client-1",
            account_id="paper-acct",
            state="partially_filled",
            observed_at=datetime(2026, 10, 5, tzinfo=UTC),
            filled_quantity=Decimal(1),
            broker_sequence=4,
        )
    )
    found = port.read_order(_snapshot())
    assert found is not None and found.status is OrderState.PARTIALLY_FILLED
    assert fake.client_lookup_ids == ["client-1"]
    assert fake.venue_lookup_ids == []
    fake.queue_account(
        _account(
            open_orders=(
                AlpacaOrderRecordV1(
                    venue_order_id="alpaca-1",
                    client_order_id="client-1",
                    account_id="paper-acct",
                    state="partially_filled",
                    observed_at=datetime(2026, 10, 5, tzinfo=UTC),
                    filled_quantity=Decimal(1),
                    broker_sequence=4,
                ),
            )
        )
    )
    fake.queue_delete(TimeoutError("canary-private"))
    with pytest.raises(BrokerOutcomeUnknown) as unknown:
        port.cancel(_snapshot())
    assert unknown.value.code == BrokerUnknownCode.UNKNOWN_CANCEL.value
    assert "canary-private" not in str(unknown.value)
    assert fake.delete_ids == ["alpaca-1"]


def test_read_rate_limit_is_typed_and_non_echoing() -> None:
    fake = RecordedAlpacaTransport()
    port = _port(fake)
    fake.queue_account(RecordedHttpError(429, response_body="private-canary"))
    with pytest.raises(BrokerRejected, match="RATE_LIMITED") as rejected:
        port.read_account_view("paper-acct")
    assert "private-canary" not in str(rejected.value)


def test_trade_update_partial_correction_and_replay_dedupe() -> None:
    fake = RecordedAlpacaTransport()
    port = _port(fake)
    when = datetime(2026, 10, 5, tzinfo=UTC)
    partial = AlpacaTradeUpdateV1(
        venue_order_id="alpaca-1",
        client_order_id="client-1",
        account_id="paper-acct",
        event_type="partial_fill",
        event_time=when,
        event_sequence=1,
        execution_id="exec-1",
        quantity=Decimal(1),
        price=Decimal("123.45"),
    )
    correction = AlpacaTradeUpdateV1(
        venue_order_id="alpaca-1",
        client_order_id="client-1",
        account_id="paper-acct",
        event_type="correction",
        event_time=when,
        event_sequence=2,
        execution_id="exec-1",
        quantity=Decimal("0.5"),
        price=Decimal("123.45"),
        correction_id="correction-1",
        revision=1,
    )
    fake.queue_updates((partial, correction))
    first = port.poll_trade_updates()
    assert len(first) == 2
    assert first[0].quantity == Decimal(1)
    assert first[1].revised_quantity == Decimal("0.5")
    fake.queue_updates((partial, correction))
    assert port.poll_trade_updates() == ()


def test_submit_consumes_permit_reconciles_and_posts_once() -> None:
    fake = RecordedAlpacaTransport()
    port = _port(fake)
    request = _request()
    permit = _Permit(request)
    fake.queue_account(_account())
    fake.queue_client_read(None)
    fake.queue_post(
        AlpacaOrderRecordV1(
            venue_order_id="alpaca-1",
            client_order_id=request.client_order_id,
            account_id=request.account_id,
            state="accepted",
            observed_at=datetime(2026, 10, 5, tzinfo=UTC),
        )
    )
    result = port.submit(request, permit, 1)
    result.assert_sealed()
    assert result.state is OrderState.WORKING
    assert result.venue_order_id == "alpaca-1"
    assert permit.used
    assert fake.account_lookup_ids == [request.account_id]
    assert fake.client_lookup_ids == [request.client_order_id]
    assert len(fake.post_payloads) == 1
    assert fake.post_payloads[0].client_order_id == request.client_order_id
    with pytest.raises(BrokerRejected):
        port.submit(request, permit, 1)
    assert len(fake.post_payloads) == 1


def test_duplicate_client_id_in_open_order_or_execution_never_posts() -> None:
    request = _request()
    existing = AlpacaOrderRecordV1(
        venue_order_id="alpaca-1",
        client_order_id=request.client_order_id,
        account_id=request.account_id,
        state="new",
        observed_at=datetime(2026, 10, 5, tzinfo=UTC),
    )
    execution = AlpacaExecutionRecordV1(
        execution_id="exec-1",
        venue_order_id="alpaca-1",
        client_order_id=request.client_order_id,
        account_id=request.account_id,
        asset_id="asset-AAPL",
        side="BUY",
        quantity=Decimal(1),
        price=Decimal("123.45"),
        executed_at=datetime(2026, 10, 5, tzinfo=UTC),
    )
    for open_orders, executions in (((existing,), ()), ((), (execution,))):
        fake = RecordedAlpacaTransport()
        port = _port(fake)
        fake.queue_account(_account(open_orders=open_orders, executions=executions))
        result = port.submit(request, _Permit(request), 1)
        result.assert_sealed()
        assert result.state is OrderState.REJECTED
        assert result.rejection_code is BrokerRejectionCode.DUPLICATE_CLIENT_ORDER_ID
        assert fake.client_lookup_ids == []
        assert fake.post_payloads == []


def test_incomplete_execution_identity_and_failed_clock_are_unknown() -> None:
    request = _request()
    execution = AlpacaExecutionRecordV1(
        execution_id="exec-1",
        venue_order_id="alpaca-1",
        client_order_id="other-client",
        account_id=request.account_id,
        asset_id="asset-AAPL",
        side="BUY",
        quantity=Decimal(1),
        price=Decimal("123.45"),
        executed_at=datetime(2026, 10, 5, tzinfo=UTC),
    )
    fake = RecordedAlpacaTransport()
    port = _port(fake)
    fake.queue_account(_account(executions=(execution, execution)))
    with pytest.raises(BrokerOutcomeUnknown) as unknown:
        port.read_account_view(request.account_id)
    assert unknown.value.code == BrokerUnknownCode.UNKNOWN_ACCOUNT_VIEW.value

    def failed_clock() -> int:
        raise RuntimeError("private-clock-canary")

    fake = RecordedAlpacaTransport()
    port = AlpacaPaperBrokerPortV1(
        AlpacaSessionBindingV1(
            account_id="paper-acct", mapping_revision="asset-rev-1", calendar_revision="cal-1"
        ),
        _assets(),
        fake,
        oms_evidence=FakeAlpacaOMSEvidence(),
        clock_ns=failed_clock,
    )
    fake.queue_account(_account())
    with pytest.raises(BrokerOutcomeUnknown) as unknown:
        port.submit(request, _Permit(request), 1)
    assert unknown.value.code == BrokerUnknownCode.UNKNOWN_SUBMIT.value
    assert "private-clock-canary" not in str(unknown.value)
    assert fake.post_payloads == []


def test_ambiguous_duplicate_open_order_identity_is_unknown() -> None:
    fake = RecordedAlpacaTransport()
    order = AlpacaOrderRecordV1(
        venue_order_id="alpaca-1",
        client_order_id="client-1",
        account_id="paper-acct",
        state="new",
        observed_at=datetime(2026, 10, 5, tzinfo=UTC),
    )
    fake.queue_account(_account(open_orders=(order, order)))
    with pytest.raises(BrokerOutcomeUnknown) as unknown:
        _port(fake).read_account_view("paper-acct")
    assert unknown.value.code == BrokerUnknownCode.UNKNOWN_ACCOUNT_VIEW.value


def test_sell_reserves_open_sell_quantity_and_denies_uncovered_short() -> None:
    request = replace(_request(), side="SELL")
    open_sell = AlpacaOrderRecordV1(
        venue_order_id="alpaca-reserved",
        client_order_id="other-client",
        account_id=request.account_id,
        state="partially_filled",
        observed_at=datetime(2026, 10, 5, tzinfo=UTC),
        filled_quantity=Decimal(1),
        asset_id=request.native_contract_id,
        side="SELL",
        quantity=Decimal(3),
    )
    for long_quantity, should_post in ((Decimal(4), False), (Decimal(5), True)):
        fake = RecordedAlpacaTransport()
        port = _port(fake)
        fake.queue_account(
            _account(
                open_orders=(open_sell,),
                positions=(AlpacaPositionRecordV1("asset-AAPL", long_quantity),),
            )
        )
        if should_post:
            fake.queue_client_read(None)
            fake.queue_post(
                AlpacaOrderRecordV1(
                    venue_order_id="alpaca-new",
                    client_order_id=request.client_order_id,
                    account_id=request.account_id,
                    state="accepted",
                    observed_at=datetime(2026, 10, 5, tzinfo=UTC),
                )
            )
            assert port.submit(request, _Permit(request), 1).state is OrderState.WORKING
        else:
            with pytest.raises(BrokerRejected) as rejected:
                port.submit(request, _Permit(request), 1)
            assert rejected.value.code == BrokerRejectionCode.INVALID_ORDER.value
            assert fake.client_lookup_ids == []
        assert bool(fake.post_payloads) is should_post

    fake = RecordedAlpacaTransport()
    incomplete_order = replace(open_sell, asset_id=None, side=None, quantity=None)
    fake.queue_account(
        _account(
            open_orders=(incomplete_order,),
            positions=(AlpacaPositionRecordV1("asset-AAPL", Decimal(5)),),
        )
    )
    with pytest.raises(BrokerOutcomeUnknown) as unknown:
        _port(fake).submit(request, _Permit(request), 1)
    assert unknown.value.code == BrokerUnknownCode.UNKNOWN_SUBMIT.value
    assert fake.client_lookup_ids == []
    assert fake.post_payloads == []


def test_conflicting_newer_execution_cannot_release_sell_reservation() -> None:
    first = replace(_request(), side="SELL", quantity=Decimal(7))
    second = replace(
        first,
        quantity=Decimal(4),
        client_order_id="client-2",
        intent_idempotency_key="intent-2",
    )
    evidence = FakeAlpacaOMSEvidence()
    first_fake = RecordedAlpacaTransport()
    first_port = _port(first_fake, oms_evidence=evidence)
    first_fake.queue_account(
        _account(positions=(AlpacaPositionRecordV1("asset-AAPL", Decimal(10)),))
    )
    first_fake.queue_client_read(None)
    first_fake.queue_post(
        AlpacaOrderRecordV1(
            venue_order_id="alpaca-1",
            client_order_id="client-1",
            account_id="paper-acct",
            state="accepted",
            observed_at=datetime(2026, 10, 5, tzinfo=UTC),
        )
    )
    assert first_port.submit(first, _Permit(first), 1).state is OrderState.WORKING

    second_fake = RecordedAlpacaTransport()
    second_port = _port(second_fake, oms_evidence=evidence)
    second_fake.queue_account(
        _account(
            revision=2,
            positions=(AlpacaPositionRecordV1("asset-AAPL", Decimal(10)),),
            executions=(
                AlpacaExecutionRecordV1(
                    execution_id="execution-conflict",
                    venue_order_id="alpaca-1",
                    client_order_id="client-1",
                    account_id="paper-acct",
                    asset_id="asset-AAPL",
                    side="BUY",
                    quantity=Decimal(1),
                    price=Decimal(100),
                    executed_at=datetime(2026, 10, 5, tzinfo=UTC),
                ),
            ),
        )
    )
    second_fake.queue_client_read(None)
    with pytest.raises(BrokerRejected) as rejected:
        second_port.submit(second, _Permit(second, revision=2), 2)
    assert rejected.value.code == BrokerRejectionCode.INVALID_ORDER.value
    assert second_fake.post_payloads == []


def test_shared_evidence_rejects_stale_or_conflicting_views_after_reflection() -> None:
    first = replace(_request(), side="SELL", quantity=Decimal(6))
    second = replace(
        first,
        client_order_id="client-2",
        intent_idempotency_key="intent-2",
        quantity=Decimal(3),
    )
    third = replace(
        first,
        client_order_id="client-3",
        intent_idempotency_key="intent-3",
        quantity=Decimal(5),
    )
    evidence = FakeAlpacaOMSEvidence()
    long_position = (AlpacaPositionRecordV1("asset-AAPL", Decimal(10)),)
    first_fake = RecordedAlpacaTransport()
    first_fake.queue_account(_account(revision=10, positions=long_position))
    first_fake.queue_client_read(None)
    first_fake.queue_post(
        AlpacaOrderRecordV1(
            venue_order_id="alpaca-1",
            client_order_id="client-1",
            account_id="paper-acct",
            state="accepted",
            observed_at=datetime(2026, 10, 5, tzinfo=UTC),
        )
    )
    assert (
        _port(first_fake, oms_evidence=evidence)
        .submit(first, _Permit(first, revision=10), 10)
        .state
        is OrderState.WORKING
    )

    second_fake = RecordedAlpacaTransport()
    second_fake.queue_account(
        _account(
            revision=11,
            positions=long_position,
            open_orders=(
                AlpacaOrderRecordV1(
                    venue_order_id="alpaca-1",
                    client_order_id="client-1",
                    account_id="paper-acct",
                    state="new",
                    observed_at=datetime(2026, 10, 5, tzinfo=UTC),
                    asset_id="asset-AAPL",
                    side="SELL",
                    quantity=Decimal(6),
                ),
            ),
        )
    )
    second_fake.queue_client_read(None)
    second_fake.queue_post(
        AlpacaOrderRecordV1(
            venue_order_id="alpaca-2",
            client_order_id="client-2",
            account_id="paper-acct",
            state="accepted",
            observed_at=datetime(2026, 10, 5, tzinfo=UTC),
        )
    )
    assert (
        _port(second_fake, oms_evidence=evidence)
        .submit(second, _Permit(second, revision=11), 11)
        .state
        is OrderState.WORKING
    )

    stale_fake = RecordedAlpacaTransport()
    stale_fake.queue_account(_account(revision=10, positions=long_position))
    with pytest.raises(BrokerOutcomeUnknown) as stale:
        _port(stale_fake, oms_evidence=evidence).submit(third, _Permit(third, revision=10), 10)
    assert stale.value.code == BrokerUnknownCode.UNKNOWN_SUBMIT.value
    assert stale_fake.post_payloads == []

    conflict_fake = RecordedAlpacaTransport()
    conflict_fake.queue_account(
        _account(
            revision=11,
            positions=(AlpacaPositionRecordV1("asset-AAPL", Decimal(11)),),
        )
    )
    with pytest.raises(BrokerOutcomeUnknown) as conflict:
        _port(conflict_fake, oms_evidence=evidence).submit(third, _Permit(third, revision=11), 11)
    assert conflict.value.code == BrokerUnknownCode.UNKNOWN_SUBMIT.value
    assert conflict_fake.post_payloads == []


def test_submit_timeout_rate_limit_and_skew_fail_closed() -> None:
    request = _request()
    for failure in (TimeoutError("private-canary"), RecordedHttpError(429)):
        fake = RecordedAlpacaTransport()
        port = _port(fake)
        fake.queue_account(_account())
        fake.queue_client_read(None)
        fake.queue_post(failure)
        with pytest.raises(BrokerOutcomeUnknown) as unknown:
            port.submit(request, _Permit(request), 1)
        assert unknown.value.code == BrokerUnknownCode.UNKNOWN_SUBMIT.value
        assert "private-canary" not in str(unknown.value)
        assert len(fake.post_payloads) == 1
    for skew_ns, should_post in ((249_000_000, True), (250_000_000, False)):
        fake = RecordedAlpacaTransport()
        port = _port(fake, now_ns=100 + skew_ns)
        fake.queue_account(_account())
        if should_post:
            fake.queue_client_read(None)
            fake.queue_post(
                AlpacaOrderRecordV1(
                    venue_order_id="alpaca-1",
                    client_order_id=request.client_order_id,
                    account_id=request.account_id,
                    state="new",
                    observed_at=datetime(2026, 10, 5, tzinfo=UTC),
                )
            )
            assert port.submit(request, _Permit(request), 1).state is OrderState.WORKING
        else:
            with pytest.raises(BrokerOutcomeUnknown):
                port.submit(request, _Permit(request), 1)
        assert bool(fake.post_payloads) is should_post


def test_lost_response_cannot_post_the_same_client_id_again() -> None:
    request = _request()
    fake = RecordedAlpacaTransport()
    port = _port(fake)
    fake.queue_account(_account(revision=1))
    fake.queue_client_read(None)
    fake.queue_post(ConnectionResetError("private-reset-canary"))
    with pytest.raises(BrokerOutcomeUnknown) as first:
        port.submit(request, _Permit(request, revision=1), 1)
    assert first.value.code == BrokerUnknownCode.UNKNOWN_SUBMIT.value
    assert len(fake.post_payloads) == 1

    fake.queue_account(_account(revision=2))
    fake.queue_client_read(None)
    with pytest.raises(BrokerOutcomeUnknown) as second:
        port.submit(request, _Permit(request, revision=2), 2)
    assert second.value.code == BrokerUnknownCode.UNKNOWN_SUBMIT.value
    assert "private-reset-canary" not in str(second.value)
    assert len(fake.post_payloads) == 1


def test_rejected_post_is_closed_and_duplicate_response_reconciles() -> None:
    request = _request()
    fake = RecordedAlpacaTransport()
    port = _port(fake)
    fake.queue_account(_account())
    fake.queue_client_read(None)
    fake.queue_post(RecordedHttpError(422, response_body="private-venue-canary"))
    result = port.submit(request, _Permit(request), 1)
    result.assert_sealed()
    assert result.state is OrderState.REJECTED
    assert result.rejection_code is BrokerRejectionCode.VENUE_REJECTED
    assert "private-venue-canary" not in str(result)

    fake = RecordedAlpacaTransport()
    port = _port(fake)
    fake.queue_account(_account())
    fake.queue_client_read(None)
    fake.queue_post(RecordedHttpError(409, reason_code="DUPLICATE_CLIENT_ORDER_ID"))
    fake.queue_client_read(
        AlpacaOrderRecordV1(
            venue_order_id="alpaca-existing",
            client_order_id=request.client_order_id,
            account_id=request.account_id,
            state="filled",
            observed_at=datetime(2026, 10, 5, tzinfo=UTC),
        )
    )
    result = port.submit(request, _Permit(request), 1)
    result.assert_sealed()
    assert result.state is OrderState.REJECTED
    assert result.rejection_code is BrokerRejectionCode.DUPLICATE_CLIENT_ORDER_ID
    assert fake.client_lookup_ids == [request.client_order_id, request.client_order_id]
    assert len(fake.post_payloads) == 1
