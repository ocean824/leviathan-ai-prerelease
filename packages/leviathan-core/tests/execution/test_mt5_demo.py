"""Writer checks for the fake-only FOREX.com/MT5 adapter."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime
from decimal import Decimal

import pytest

from leviathan_core.execution.broker_port_v1 import BrokerOutcomeUnknown, BrokerPortV1
from leviathan_core.execution.brokers.mt5_demo import (
    FakeMT5OMSEvidence,
    FakeMT5Transport,
    MT5DemoBrokerPortV1,
    MT5NativeAccountViewV1,
    MT5NativeCancelAckV1,
    MT5NativeEventV1,
    MT5NativeSubmitAckV1,
    MT5QuoteV1,
    MT5SessionBindingV1,
    MT5TerminalSnapshotV1,
    build_native_submit,
)
from leviathan_core.execution.brokers.mt5_mapping import (
    MT5AdapterError,
    MT5SymbolSpecV1,
    encode_correlation,
    minimum_stop_distance,
    to_native_price,
    to_native_volume,
)
from leviathan_core.execution.order_models import (
    BrokerObservation,
    OrderRequest,
    OrderSnapshot,
    OrderState,
)

NOW = 1_000_000_000_000


def _spec() -> MT5SymbolSpecV1:
    return MT5SymbolSpecV1(
        instrument_id="EURUSD",
        native_contract_id="EURUSD.demo",
        native_symbol="EURUSD.demo",
        revision="map1",
        contract_size=Decimal("100000"),
        lot_min=Decimal("0.01"),
        lot_max=Decimal("10"),
        lot_step=Decimal("0.01"),
        point=Decimal("0.00001"),
        tick_size=Decimal("0.00001"),
        digits=5,
        stops_level_points=10,
    )


def _binding() -> MT5SessionBindingV1:
    return MT5SessionBindingV1(
        project_id="leviathan-ai",
        environment="development",
        provider="FOREX.com",
        mode="DEMO",
        server="FOREXcom-Demo",
        account_id="demo-123",
        terminal_agent_id="ea-1",
        protocol="FAKE_MT5_EA",
        protocol_version="1",
        mapping_revision="map1",
        broker_timezone="UTC",
        calendar_id="forex-weekly",
        trade_allowed=True,
        max_heartbeat_age_ns=1_000_000_000,
        max_quote_age_ns=500_000_000,
    )


def _snapshot() -> MT5TerminalSnapshotV1:
    return MT5TerminalSnapshotV1(
        server="FOREXcom-Demo",
        account_id="demo-123",
        mode="DEMO",
        terminal_agent_id="ea-1",
        protocol="FAKE_MT5_EA",
        protocol_version="1",
        mapping_revision="map1",
        broker_timezone="UTC",
        calendar_id="forex-weekly",
        connected=True,
        trade_allowed=True,
        heartbeat_at_ns=NOW - 100_000_000,
        broker_clock_skew_ms=249,
        session_open=True,
        news_blackout=False,
        margin_confirmed=True,
        calendar_ambiguous=False,
        quote=MT5QuoteV1(
            native_symbol="EURUSD.demo",
            bid=Decimal("1.10000"),
            ask=Decimal("1.10002"),
            observed_ns=NOW - 100_000_000,
        ),
        broker_revision=7,
    )


def _request() -> OrderRequest:
    return OrderRequest(
        project_id="leviathan-ai",
        environment="demo",
        account_id="demo-123",
        venue="MT5",
        instrument_id="EURUSD",
        native_contract_id="EURUSD.demo",
        side="BUY",
        quantity=Decimal("100000"),
        order_type="MARKET",
        time_in_force="DAY",
        client_order_id="client-1",
        intent_idempotency_key="intent-1",
        attempt=1,
        strategy_id="strategy-1",
        risk_policy_digest="a" * 64,
        actor_id="operator-1",
        capability="DEMO_SUBMIT",
    )


def test_mapping_requires_exact_lot_and_price_ticks() -> None:
    spec = _spec()
    assert to_native_volume(Decimal("100000"), spec) == Decimal("1")
    assert to_native_price(Decimal("1.10002"), spec) == Decimal("1.10002")
    assert minimum_stop_distance(spec) == Decimal("0.0001")
    with pytest.raises(MT5AdapterError, match="LOT_STEP_MISMATCH"):
        to_native_volume(Decimal("100001"), spec)
    with pytest.raises(MT5AdapterError, match="LOT_OUT_OF_BOUNDS"):
        to_native_volume(Decimal("999"), spec)
    with pytest.raises(MT5AdapterError, match="PRICE_TICK_MISMATCH"):
        to_native_price(Decimal("1.100021"), spec)


def test_correlation_is_stable_short_and_account_bound() -> None:
    first = encode_correlation("demo-123", "client-1")
    assert first.comment == encode_correlation("demo-123", "client-1").comment
    assert len(first.comment) == 29
    assert first.magic == encode_correlation("demo-123", "client-1").magic
    assert first != encode_correlation("demo-456", "client-1")
    assert "client-1" not in first.comment


def test_pure_submit_translation_uses_exact_demo_binding() -> None:
    native = build_native_submit(
        _request(), _binding(), _snapshot(), _spec(), now_ns=NOW, expected_revision=7
    )
    assert native.account_id == "demo-123"
    assert native.server == "FOREXcom-Demo"
    assert native.volume_lots == Decimal("1")
    assert native.comment == encode_correlation("demo-123", "client-1").comment
    assert native.magic == encode_correlation("demo-123", "client-1").magic
    assert native.price is None


@pytest.mark.parametrize(
    ("changes", "code"),
    [
        ({"mode": "LIVE"}, "SESSION_MISMATCH"),
        ({"account_id": "other-demo"}, "SESSION_MISMATCH"),
        ({"heartbeat_at_ns": NOW - 2_000_000_000}, "SESSION_UNAVAILABLE"),
        ({"broker_clock_skew_ms": 250}, "CLOCK_SKEW_DENIED"),
        ({"news_blackout": True}, "NEWS_BLACKOUT"),
        ({"margin_confirmed": False}, "MARGIN_UNCONFIRMED"),
        ({"calendar_ambiguous": True}, "SESSION_CLOSED"),
    ],
)
def test_session_gate_fails_closed(changes: dict[str, object], code: str) -> None:
    with pytest.raises(MT5AdapterError) as caught:
        build_native_submit(
            _request(),
            _binding(),
            replace(_snapshot(), **changes),  # type: ignore[arg-type]
            _spec(),
            now_ns=NOW,
            expected_revision=7,
        )
    assert caught.value.code == code


def test_binding_rejects_live_and_cross_environment_credential_refs() -> None:
    data = {name: getattr(_binding(), name) for name in _binding().__dataclass_fields__}
    with pytest.raises(MT5AdapterError, match="INVALID_SESSION_BINDING"):
        MT5SessionBindingV1(**{**data, "mode": "LIVE"})
    with pytest.raises(MT5AdapterError, match="INVALID_SESSION_BINDING"):
        MT5SessionBindingV1(
            **{**data, "credential_ref": "vault://leviathan-ai/live/forexcom/MT5_DEMO"}
        )
    with pytest.raises(MT5AdapterError, match="INVALID_SESSION_BINDING"):
        MT5SessionBindingV1(
            **{**data, "credential_ref": "vault://leviathan-ai/development/ibkr/MT5_DEMO"}
        )


def test_fake_restart_has_zero_startup_orders_and_frozen_error_is_content_free() -> None:
    snapshot = _snapshot()
    fake = FakeMT5Transport(snapshot)
    fake.restart(snapshot)
    assert fake.submit_calls == []
    assert fake.cancel_calls == []
    canary = "SECRET_CANARY"
    with pytest.raises(MT5AdapterError) as caught:
        setattr(snapshot, canary, canary)
    error = caught.value
    assert error.code == "FROZEN_RECORD"
    for view in (str(error), repr(error.args), repr(error.errors()), error.json()):
        assert canary not in view


class _Permit:
    def __init__(
        self, request: OrderRequest, *, revision: int = 7, order_id: str = "oms-order-1"
    ) -> None:
        self.order_id = order_id
        self._digest = request.digest
        self._revision = revision
        self.consumed = False

    def consume(self, order_id: str, request_digest: str, expected_revision: int) -> None:
        if (
            self.consumed
            or order_id != self.order_id
            or request_digest != self._digest
            or expected_revision != self._revision
        ):
            raise ValueError("invalid permit")
        self.consumed = True


def _view(
    *,
    deals: tuple[MT5NativeEventV1, ...] = (),
    orders_complete: bool = True,
    deals_complete: bool = True,
    positions_complete: bool = True,
) -> MT5NativeAccountViewV1:
    return MT5NativeAccountViewV1(
        server="FOREXcom-Demo",
        account_id="demo-123",
        mode="DEMO",
        open_orders=(),
        deals=deals,
        positions=(("EURUSD", Decimal("100000")),),
        broker_revision=7,
        observed_ns=NOW - 100_000_000,
        orders_complete=orders_complete,
        deals_complete=deals_complete,
        positions_complete=positions_complete,
        executions_since=datetime.fromtimestamp(0, UTC),
    )


def _adapter(
    *,
    fake: FakeMT5Transport | None = None,
    evidence: FakeMT5OMSEvidence | None = None,
    clock_ns: Callable[[], int] | None = None,
) -> tuple[MT5DemoBrokerPortV1, FakeMT5Transport]:
    if fake is None:
        fake = FakeMT5Transport(_snapshot())
    if evidence is None:
        evidence = FakeMT5OMSEvidence()
    port = MT5DemoBrokerPortV1(
        binding=_binding(),
        symbols=(_spec(),),
        transport=fake,
        oms_evidence=evidence,
        clock_ns=clock_ns or (lambda: NOW),
        settle_window_ms=2_000,
    )
    assert isinstance(port, BrokerPortV1)
    return port, fake


def test_submit_consumes_permit_before_one_fake_terminal_call() -> None:
    port, fake = _adapter()
    request = _request()
    permit = _Permit(request)
    fake.queue_account_view(_view())
    fake.queue_submit(MT5NativeSubmitAckV1("ACCEPTED", "native-order-1"))
    result = port.submit(request, permit, 7)
    result.assert_sealed()
    assert result.venue_order_id == "native-order-1"
    assert permit.consumed
    assert len(fake.submit_calls) == 1
    assert fake.submit_calls[0].comment == encode_correlation("demo-123", "client-1").comment
    with pytest.raises(BrokerOutcomeUnknown, match="UNKNOWN_SUBMIT"):
        port.submit(request, _Permit(request), 7)
    assert len(fake.submit_calls) == 1


def test_conflicting_open_ticket_blocks_all_view_dependent_paths() -> None:
    port, fake = _adapter()
    first = _request()
    fake.queue_account_view(_view())
    fake.queue_submit(MT5NativeSubmitAckV1("ACCEPTED", "native-order-1"))
    assert port.submit(first, _Permit(first), 7).venue_order_id == "native-order-1"

    fake.restart(replace(_snapshot(), broker_revision=8))
    wrong_label = BrokerObservation(
        observation_id="open-conflict",
        environment="demo",
        account_id="demo-123",
        venue="MT5",
        client_order_id="client-foreign",
        status=OrderState.WORKING,
        observed_at=datetime.fromtimestamp(NOW / 1_000_000_000, UTC),
        venue_order_id="native-order-1",
    )
    conflicting_view = replace(_view(), open_orders=(wrong_label,), broker_revision=8)
    fake.queue_account_view(conflicting_view)
    with pytest.raises(BrokerOutcomeUnknown, match="UNKNOWN_ACCOUNT_VIEW"):
        port.read_account_view("demo-123")

    order = OrderSnapshot(
        order_id="oms-order-1",
        request=first,
        state=OrderState.WORKING,
        version=1,
        venue_order_id="native-order-1",
        filled_quantity=Decimal(0),
        discrepancies=(),
        submit_attempted=True,
        cancel_attempted=False,
    )
    fake.queue_read(None)
    fake.queue_account_view(conflicting_view)
    with pytest.raises(BrokerOutcomeUnknown, match="UNKNOWN_READ_ORDER"):
        port.read_order(order)
    fake.queue_account_view(conflicting_view)
    with pytest.raises(BrokerOutcomeUnknown, match="UNKNOWN_CANCEL"):
        port.cancel(order)
    assert fake.cancel_calls == []

    second = replace(first, client_order_id="client-2", intent_idempotency_key="intent-2")
    permit = _Permit(second, revision=8, order_id="oms-order-2")
    fake.queue_account_view(conflicting_view)
    with pytest.raises(BrokerOutcomeUnknown, match="UNKNOWN_SUBMIT"):
        port.submit(second, permit, 8)
    assert permit.consumed
    assert len(fake.submit_calls) == 1


def test_uncertain_submit_and_incomplete_account_view_never_retry() -> None:
    request = _request()
    port, fake = _adapter()
    fake.queue_account_view(_view(positions_complete=False))
    with pytest.raises(BrokerOutcomeUnknown, match="UNKNOWN_SUBMIT"):
        port.submit(request, _Permit(request), 7)
    assert fake.submit_calls == []

    port, fake = _adapter()
    fake.queue_account_view(_view())
    fake.queue_submit(TimeoutError("SECRET_CANARY"))
    with pytest.raises(BrokerOutcomeUnknown, match="UNKNOWN_SUBMIT") as caught:
        port.submit(request, _Permit(request), 7)
    assert "SECRET_CANARY" not in str(caught.value)
    assert len(fake.submit_calls) == 1
    with pytest.raises(BrokerOutcomeUnknown, match="UNKNOWN_SUBMIT"):
        port.submit(request, _Permit(request), 7)
    assert len(fake.submit_calls) == 1


def test_complete_account_view_issues_exact_deal_and_position() -> None:
    port, fake = _adapter()
    correlation = encode_correlation("demo-123", "client-1")
    deal = MT5NativeEventV1(
        kind="DEAL",
        native_id="deal-1",
        version=1,
        server="FOREXcom-Demo",
        account_id="demo-123",
        comment=correlation.comment,
        magic=correlation.magic,
        related_order_id="native-order-1",
        related_position_id="position-1",
        quantity=Decimal("25000"),
        price=Decimal("1.10002"),
        occurred_at_ns=NOW - 1_000_000_000,
        state="FILLED",
        instrument_id="EURUSD",
        side="BUY",
    )
    fake.queue_account_view(_view(deals=(deal,)))
    view = port.read_account_view("demo-123")
    view.assert_sealed()
    assert view.positions == (("EURUSD", Decimal("100000")),)
    assert len(view.executions) == 1
    view.executions[0].assert_sealed()
    assert view.executions[0].execution_id == "deal-1"
    assert view.executions[0].quantity == Decimal("25000")
    assert view.executions[0].client_order_id is None


def test_cancel_timeout_is_unconfirmed_and_no_retry() -> None:
    port, fake = _adapter()
    order = OrderSnapshot(
        order_id="oms-order-1",
        request=_request(),
        state=OrderState.WORKING,
        version=1,
        venue_order_id="native-order-1",
        filled_quantity=Decimal(0),
        discrepancies=(),
        submit_attempted=True,
        cancel_attempted=False,
    )
    fake.queue_account_view(_view())
    fake.queue_cancel(TimeoutError("SECRET_CANARY"))
    with pytest.raises(BrokerOutcomeUnknown, match="UNKNOWN_CANCEL"):
        port.cancel(order)
    assert fake.cancel_calls == ["native-order-1"]
    fake.queue_cancel(MT5NativeCancelAckV1(True))
    with pytest.raises(BrokerOutcomeUnknown, match="UNKNOWN_CANCEL"):
        port.cancel(order)
    assert fake.cancel_calls == ["native-order-1"]


def test_absent_order_requires_local_attempt_and_complete_history() -> None:
    request = _request()
    order = OrderSnapshot(
        order_id="oms-order-1",
        request=request,
        state=OrderState.WORKING,
        version=1,
        venue_order_id="native-order-1",
        filled_quantity=Decimal(0),
        discrepancies=(),
        submit_attempted=True,
        cancel_attempted=False,
    )
    fresh_port, fresh_fake = _adapter()
    fresh_fake.queue_read(None)
    fresh_fake.queue_account_view(_view())
    with pytest.raises(BrokerOutcomeUnknown, match="UNKNOWN_READ_ORDER"):
        fresh_port.read_order(order)

    clock = [NOW]
    port, fake = _adapter(clock_ns=lambda: clock[0])
    fake.queue_account_view(_view())
    fake.queue_submit(MT5NativeSubmitAckV1("ACCEPTED", "native-order-1"))
    port.submit(request, _Permit(request), 7)
    clock[0] = NOW + 200_000_000
    fake.queue_read(None)
    fake.queue_account_view(replace(_view(), observed_ns=NOW + 100_000_000))
    assert port.read_order(order) is None


def test_rewritten_native_ids_prevent_false_absence() -> None:
    evidence = FakeMT5OMSEvidence()
    port, fake = _adapter(evidence=evidence)
    request = _request()
    fake.queue_account_view(_view())
    fake.queue_submit(MT5NativeSubmitAckV1("ACCEPTED", "native-order-1"))
    port.submit(request, _Permit(request), 7)
    order = OrderSnapshot(
        order_id="oms-order-1",
        request=request,
        state=OrderState.WORKING,
        version=1,
        venue_order_id="native-order-1",
        filled_quantity=Decimal(0),
        discrepancies=(),
        submit_attempted=True,
        cancel_attempted=False,
    )
    rewritten = _deal(comment="LV1" + "B" * 26, magic=42)
    fake.queue_read(None)
    fake.queue_account_view(_view(deals=(rewritten,)))
    with pytest.raises(BrokerOutcomeUnknown, match="UNKNOWN_READ_ORDER"):
        port.read_order(order)

    other_label = BrokerObservation(
        observation_id="obs-rewritten",
        environment="demo",
        account_id="demo-123",
        venue="MT5",
        client_order_id="different-client",
        status=OrderState.WORKING,
        observed_at=datetime.fromtimestamp(NOW / 1_000_000_000, UTC),
        venue_order_id="native-order-1",
    )
    fake.queue_read(None)
    fake.queue_account_view(replace(_view(), open_orders=(other_label,)))
    with pytest.raises(BrokerOutcomeUnknown, match="UNKNOWN_READ_ORDER"):
        port.read_order(order)

    restarted, _ = _adapter(fake=fake, evidence=evidence)
    fake.queue_read(None)
    fake.queue_account_view(_view(deals=(rewritten,)))
    with pytest.raises(BrokerOutcomeUnknown, match="UNKNOWN_READ_ORDER"):
        restarted.read_order(replace(order, venue_order_id=None))
    fake.queue_account_view(_view(deals=(rewritten,)))
    assert restarted.read_account_view("demo-123").executions[0].client_order_id == "client-1"


def test_restart_evidence_and_unattributed_partial_deal_prevent_second_send() -> None:
    request = _request()
    evidence = FakeMT5OMSEvidence()
    port, fake = _adapter(evidence=evidence)
    fake.queue_account_view(_view())
    fake.queue_submit(MT5NativeSubmitAckV1("ACCEPTED", "native-order-1"))
    port.submit(request, _Permit(request), 7)
    rewritten = _deal(comment="LV1" + "B" * 26, magic=42)

    restarted, _ = _adapter(fake=fake, evidence=evidence)
    with pytest.raises(BrokerOutcomeUnknown, match="UNKNOWN_SUBMIT"):
        restarted.submit(request, _Permit(request), 7)
    assert len(fake.submit_calls) == 1

    # Missing durable mapping is not permission to adopt or resend a partial fill.
    unlinked, _ = _adapter(fake=fake, evidence=FakeMT5OMSEvidence())
    fake.queue_account_view(_view(deals=(rewritten,)))
    with pytest.raises(BrokerOutcomeUnknown, match="UNKNOWN_SUBMIT"):
        unlinked.submit(request, _Permit(request), 7)
    assert len(fake.submit_calls) == 1


def _deal(*, comment: str, magic: int, version: int = 1) -> MT5NativeEventV1:
    return MT5NativeEventV1(
        kind="DEAL",
        native_id="deal-1",
        version=version,
        server="FOREXcom-Demo",
        account_id="demo-123",
        comment=comment,
        magic=magic,
        related_order_id="native-order-1",
        related_position_id="position-1",
        quantity=Decimal("25000"),
        price=Decimal("1.10002"),
        occurred_at_ns=NOW - 1_000_000_000,
        state="FILLED",
        instrument_id="EURUSD",
        side="BUY",
    )


@pytest.mark.parametrize("collision_field", ["comment", "magic"])
def test_deal_history_correlation_ambiguity_denies_submit(collision_field: str) -> None:
    request = _request()
    port, fake = _adapter()
    own = encode_correlation("demo-123", "client-1")
    other = encode_correlation("demo-123", "client-2")
    foreign = _deal(
        comment=own.comment if collision_field == "comment" else other.comment,
        magic=own.magic if collision_field == "magic" else other.magic,
    )
    fake.queue_account_view(_view(deals=(foreign,)))
    with pytest.raises(BrokerOutcomeUnknown, match="UNKNOWN_SUBMIT"):
        port.submit(request, _Permit(request), 7)
    assert fake.submit_calls == []


def test_callback_dedupes_and_retains_corrected_deal_without_flattening() -> None:
    port, fake = _adapter()
    correlation = encode_correlation("demo-123", "client-1")
    fake.queue_account_view(_view())
    fake.queue_submit(MT5NativeSubmitAckV1("ACCEPTED", "native-order-1"))
    port.submit(_request(), _Permit(_request()), 7)
    first = _deal(comment=correlation.comment, magic=correlation.magic)
    assert port.ingest_callback(first).applied
    assert not port.ingest_callback(first).applied
    corrected = replace(first, version=2, quantity=Decimal("30000"))
    assert port.ingest_callback(corrected).applied
    assert port.deal_events == (corrected,)
    object.__setattr__(port.deal_events[0], "quantity", Decimal("1"))
    assert port.deal_events == (corrected,)
    assert fake.submit_calls and len(fake.submit_calls) == 1


def test_post_gtd_deal_is_recorded_with_alert_and_no_new_order() -> None:
    port, fake = _adapter()
    request = replace(
        _request(),
        time_in_force="GTD",
        expires_at=datetime.fromtimestamp(1_001, UTC),
    )
    fake.queue_account_view(_view())
    fake.queue_submit(MT5NativeSubmitAckV1("ACCEPTED", "native-order-1"))
    port.submit(request, _Permit(request), 7)
    correlation = encode_correlation("demo-123", "client-1")
    late = replace(
        _deal(comment=correlation.comment, magic=correlation.magic),
        occurred_at_ns=1_002_000_000_000,
    )
    decision = port.ingest_callback(late)
    assert decision.applied and decision.late_gtd
    assert decision.operator_alert_code == "LATE_GTD"
    assert port.late_gtd_alert_count == 1
    assert port.deal_events == (late,)
    assert len(fake.submit_calls) == 1
