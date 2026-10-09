"""Independent fake-only acceptance tests for the FOREX.com MT5 demo port."""

from __future__ import annotations

import base64
import copy
import pickle
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime
from decimal import Decimal, localcontext
from fractions import Fraction

import pytest

import leviathan_core.execution.brokers.mt5_demo as mt5_demo_module
from leviathan_core.execution.broker_port_v1 import (
    AccountViewV1,
    BrokerOutcomeUnknown,
    BrokerPortError,
    ExecutionV1,
    SubmitResultV1,
)
from leviathan_core.execution.brokers.mt5_demo import (
    FakeMT5OMSEvidence,
    FakeMT5Transport,
    MT5CallbackDecisionV1,
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
    MT5CorrelationV1,
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

NOW_NS = 1_000_000_000_000


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


def _binding(**changes: object) -> MT5SessionBindingV1:
    values: dict[str, object] = {
        "project_id": "leviathan-ai",
        "environment": "development",
        "provider": "FOREX.com",
        "mode": "DEMO",
        "server": "FOREXcom-Demo",
        "account_id": "demo-123",
        "terminal_agent_id": "ea-1",
        "protocol": "FAKE_MT5_EA",
        "protocol_version": "1",
        "mapping_revision": "map1",
        "broker_timezone": "UTC",
        "calendar_id": "forex-weekly",
        "trade_allowed": True,
        "max_heartbeat_age_ns": 1_000_000_000,
        "max_quote_age_ns": 500_000_000,
    }
    values.update(changes)
    return MT5SessionBindingV1(**values)  # type: ignore[arg-type]


def _snapshot(**changes: object) -> MT5TerminalSnapshotV1:
    values: dict[str, object] = {
        "server": "FOREXcom-Demo",
        "account_id": "demo-123",
        "mode": "DEMO",
        "terminal_agent_id": "ea-1",
        "protocol": "FAKE_MT5_EA",
        "protocol_version": "1",
        "mapping_revision": "map1",
        "broker_timezone": "UTC",
        "calendar_id": "forex-weekly",
        "connected": True,
        "trade_allowed": True,
        "heartbeat_at_ns": NOW_NS - 100_000_000,
        "broker_clock_skew_ms": 249,
        "session_open": True,
        "news_blackout": False,
        "margin_confirmed": True,
        "calendar_ambiguous": False,
        "quote": MT5QuoteV1(
            native_symbol="EURUSD.demo",
            bid=Decimal("1.10000"),
            ask=Decimal("1.10002"),
            observed_ns=NOW_NS - 100_000_000,
        ),
        "broker_revision": 7,
    }
    values.update(changes)
    return MT5TerminalSnapshotV1(**values)  # type: ignore[arg-type]


def _request(**changes: object) -> OrderRequest:
    values: dict[str, object] = {
        "project_id": "leviathan-ai",
        "environment": "demo",
        "account_id": "demo-123",
        "venue": "MT5",
        "instrument_id": "EURUSD",
        "native_contract_id": "EURUSD.demo",
        "side": "BUY",
        "quantity": Decimal("100000"),
        "order_type": "MARKET",
        "time_in_force": "DAY",
        "client_order_id": "client-1",
        "intent_idempotency_key": "intent-1",
        "attempt": 1,
        "strategy_id": "strategy-1",
        "risk_policy_digest": "a" * 64,
        "actor_id": "operator-1",
        "capability": "mt5-demo",
    }
    values.update(changes)
    return OrderRequest(**values)  # type: ignore[arg-type]


def _event(
    kind: str,
    native_id: str,
    comment: str,
    magic: int,
    *,
    version: int = 1,
    quantity: str = "25000",
    occurred_at_ns: int = NOW_NS - 200_000_000,
    related_order_id: str | None = "native-order-1",
    related_position_id: str | None = "position-1",
) -> MT5NativeEventV1:
    return MT5NativeEventV1(
        kind=kind,  # type: ignore[arg-type]
        native_id=native_id,
        version=version,
        server="FOREXcom-Demo",
        account_id="demo-123",
        comment=comment,
        magic=magic,
        related_order_id=related_order_id,
        related_position_id=related_position_id,
        quantity=Decimal(quantity),
        price=Decimal("1.10002") if kind == "DEAL" else None,
        occurred_at_ns=occurred_at_ns,
        state="FILLED" if kind == "DEAL" else "OPEN",
        instrument_id="EURUSD" if kind == "DEAL" else None,
        side="BUY" if kind == "DEAL" else None,
    )


def _native_view(
    *,
    open_orders: tuple[BrokerObservation, ...] = (),
    deals: tuple[MT5NativeEventV1, ...] = (),
    positions: tuple[tuple[str, Decimal], ...] = (("EURUSD", Decimal("0")),),
    orders_complete: bool = True,
    deals_complete: bool = True,
    positions_complete: bool = True,
    observed_ns: int = NOW_NS - 100_000_000,
    broker_revision: int = 7,
    executions_since: datetime | None = None,
) -> MT5NativeAccountViewV1:
    return MT5NativeAccountViewV1(
        server="FOREXcom-Demo",
        account_id="demo-123",
        mode="DEMO",
        open_orders=open_orders,
        deals=deals,
        positions=positions,
        broker_revision=broker_revision,
        observed_ns=observed_ns,
        orders_complete=orders_complete,
        deals_complete=deals_complete,
        positions_complete=positions_complete,
        executions_since=executions_since or datetime.fromtimestamp(0, UTC),
    )


def _adapter(
    clock_ns: Callable[[], int] | None = None,
    *,
    snapshot: MT5TerminalSnapshotV1 | None = None,
    transport: FakeMT5Transport | None = None,
    oms_evidence: FakeMT5OMSEvidence | None = None,
) -> tuple[MT5DemoBrokerPortV1, FakeMT5Transport]:
    transport = transport or FakeMT5Transport(snapshot or _snapshot())
    adapter = MT5DemoBrokerPortV1(
        binding=_binding(),
        symbols=(_spec(),),
        transport=transport,
        oms_evidence=oms_evidence or FakeMT5OMSEvidence(),
        clock_ns=clock_ns or (lambda: NOW_NS),
        settle_window_ms=2_000,
    )
    return adapter, transport


class _BoundPermit:
    def __init__(
        self,
        request: OrderRequest,
        *,
        order_id: str = "oms-order-1",
        revision: int = 7,
    ) -> None:
        self.order_id = order_id
        self._digest = request.digest
        self._revision = revision
        self.calls: list[tuple[str, str, int]] = []

    def consume(self, order_id: str, request_digest: str, expected_revision: int) -> None:
        self.calls.append((order_id, request_digest, expected_revision))
        if (
            order_id != self.order_id
            or request_digest != self._digest
            or expected_revision != self._revision
        ):
            raise ValueError("invalid permit")


def _order_snapshot(
    request: OrderRequest,
    *,
    venue_order_id: str | None = "native-order-1",
    order_id: str = "oms-order-1",
) -> OrderSnapshot:
    return OrderSnapshot(
        order_id=order_id,
        request=request,
        state=OrderState.WORKING,
        version=1,
        venue_order_id=venue_order_id,
        filled_quantity=Decimal("0"),
        discrepancies=(),
        submit_attempted=True,
        cancel_attempted=False,
    )


def test_correlation_layout_and_birthday_bounds() -> None:
    correlation = encode_correlation("demo-123", "client-1")

    assert len(correlation.comment) == 29
    assert correlation.comment.startswith("LV1")
    assert len(base64.b32decode(correlation.comment[3:] + "=" * 6)) == 16
    assert type(correlation.magic) is int
    assert 0 <= correlation.magic < 1 << 64
    assert "client-1" not in correlation.comment
    assert encode_correlation("demo-123", "client-1") == correlation
    assert encode_correlation("demo-456", "client-1") != correlation

    population = 1_000_000
    pairs = population * (population - 1)
    comment_bound = Fraction(pairs, 1 << 129)
    comment_magic_bound = Fraction(pairs, 1 << 193)
    assert comment_bound == Fraction(999_999_000_000, 1 << 129)
    assert comment_magic_bound == Fraction(999_999_000_000, 1 << 193)


def test_lot_conversion_uses_contract_multiplier_and_never_rounds() -> None:
    spec = _spec()

    assert to_native_volume(Decimal("250000"), spec) == Decimal("2.5")
    assert to_native_volume(Decimal("100000"), spec) == Decimal("1")
    with pytest.raises(MT5AdapterError) as caught:
        to_native_volume(Decimal("250001"), spec)
    assert caught.value.code == "LOT_STEP_MISMATCH"


def test_exact_mapping_is_independent_of_ambient_decimal_precision() -> None:
    spec = _spec()
    with localcontext() as context:
        context.prec = 2
        assert to_native_volume(Decimal("250000"), spec) == Decimal("2.5")
        assert to_native_price(Decimal("1.10002"), spec) == Decimal("1.10002")
        assert minimum_stop_distance(spec) == Decimal("0.0001")


def test_decimal_precision_bound_is_exact_and_never_rounded() -> None:
    accepted = Decimal("1.234567890123456789012345678901234")
    assert len(accepted.as_tuple().digits) == 34
    quote = MT5QuoteV1(
        native_symbol="EURUSD.demo",
        bid=accepted,
        ask=accepted,
        observed_ns=NOW_NS,
    )
    assert quote.bid == accepted

    with pytest.raises(MT5AdapterError) as over_precision:
        MT5QuoteV1(
            native_symbol="EURUSD.demo",
            bid=Decimal("1.2345678901234567890123456789012345"),
            ask=Decimal("1.2345678901234567890123456789012345"),
            observed_ns=NOW_NS,
        )
    assert over_precision.value.code == "INVALID_PRICE"

    huge_but_bounded = Decimal("1E+34")
    assert MT5QuoteV1(
        native_symbol="EURUSD.demo",
        bid=huge_but_bounded,
        ask=huge_but_bounded,
        observed_ns=NOW_NS,
    ).bid == huge_but_bounded


def test_config_values_are_frozen_and_replacements_revalidate() -> None:
    spec = _spec()
    binding = _binding()
    snapshot = _snapshot()

    with pytest.raises(MT5AdapterError) as caught:
        replace(spec, lot_max=Decimal("0.001"))
    assert caught.value.code == "INVALID_SYMBOL_MAPPING"

    with pytest.raises(MT5AdapterError) as bool_integer:
        replace(spec, digits=True)
    assert bool_integer.value.code == "INVALID_SYMBOL_MAPPING"

    for value in (spec, binding, snapshot):
        with pytest.raises(TypeError):
            copy.copy(value)
        with pytest.raises(TypeError):
            copy.deepcopy(value)
        with pytest.raises(TypeError):
            pickle.dumps(value)


def test_demo_binding_rejects_live_and_wrong_scope_configuration() -> None:
    for changes in (
        {"mode": "LIVE"},
        {"environment": "production"},
        {"trade_allowed": False},
        {"credential_ref": "vault://leviathan-ai/live/forexcom/MT5_DEMO"},
    ):
        with pytest.raises(MT5AdapterError) as caught:
            _binding(**changes)
        assert caught.value.code == "INVALID_SESSION_BINDING"


def test_submit_translation_rejects_live_wrong_account_server_and_symbol() -> None:
    binding = _binding()
    spec = _spec()
    cases = (
        (_request(), _snapshot(mode="LIVE"), spec, "SESSION_MISMATCH"),
        (_request(), _snapshot(account_id="demo-456"), spec, "SESSION_MISMATCH"),
        (_request(), _snapshot(server="FOREXcom-Live"), spec, "SESSION_MISMATCH"),
        (
            _request(account_id="demo-456"),
            _snapshot(),
            spec,
            "SESSION_MISMATCH",
        ),
        (
            _request(native_contract_id="GBPUSD.demo"),
            _snapshot(),
            spec,
            "UNSUPPORTED_SYMBOL",
        ),
    )
    for request, snapshot, symbol_spec, expected_code in cases:
        with pytest.raises(MT5AdapterError) as caught:
            build_native_submit(
                request,
                binding,
                snapshot,
                symbol_spec,
                now_ns=NOW_NS,
                expected_revision=7,
            )
        assert caught.value.code == expected_code


def test_terminal_identity_mismatch_blocks_submit_without_fallback() -> None:
    for changes in (
        {"mode": "LIVE"},
        {"account_id": "other-demo"},
        {"server": "FOREXcom-OtherDemo"},
    ):
        adapter, transport = _adapter(snapshot=_snapshot(**changes))
        request = _request()

        with pytest.raises(MT5AdapterError) as caught:
            adapter.submit(request, _BoundPermit(request), 7)

        assert caught.value.code == "SESSION_MISMATCH"
        assert transport.submit_calls == []
        assert transport.view_calls == 0


def test_submit_translation_applies_heartbeat_news_session_and_margin_gates() -> None:
    cases = (
        (_snapshot(heartbeat_at_ns=NOW_NS - 1_000_000_001), "SESSION_UNAVAILABLE"),
        (_snapshot(news_blackout=True), "NEWS_BLACKOUT"),
        (_snapshot(session_open=False), "SESSION_CLOSED"),
        (_snapshot(margin_confirmed=False), "MARGIN_UNCONFIRMED"),
    )
    for snapshot, expected_code in cases:
        with pytest.raises(MT5AdapterError) as caught:
            build_native_submit(
                _request(),
                _binding(),
                snapshot,
                _spec(),
                now_ns=NOW_NS,
                expected_revision=7,
            )
        assert caught.value.code == expected_code


def test_skew_boundary_allows_249_ms_and_blocks_250_ms() -> None:
    native = build_native_submit(
        _request(),
        _binding(),
        _snapshot(broker_clock_skew_ms=249),
        _spec(),
        now_ns=NOW_NS,
        expected_revision=7,
    )
    assert native.expected_revision == 7

    with pytest.raises(MT5AdapterError) as caught:
        build_native_submit(
            _request(),
            _binding(),
            _snapshot(broker_clock_skew_ms=250),
            _spec(),
            now_ns=NOW_NS,
            expected_revision=7,
        )
    assert caught.value.code == "CLOCK_SKEW_DENIED"


def test_minimum_stop_distance_compares_exactly_at_the_threshold() -> None:
    exact = build_native_submit(
        _request(order_type="LIMIT", limit_price=Decimal("1.09992")),
        _binding(),
        _snapshot(),
        _spec(),
        now_ns=NOW_NS,
        expected_revision=7,
    )
    assert exact.price == Decimal("1.09992")

    with pytest.raises(MT5AdapterError) as too_close:
        build_native_submit(
            _request(order_type="LIMIT", limit_price=Decimal("1.09993")),
            _binding(),
            _snapshot(),
            _spec(),
            now_ns=NOW_NS,
            expected_revision=7,
        )
    assert too_close.value.code == "STOP_DISTANCE_DENIED"


def test_fake_terminal_restart_has_no_startup_orders() -> None:
    snapshot = _snapshot()
    transport = FakeMT5Transport(snapshot)
    evidence = FakeMT5OMSEvidence()

    _adapter(snapshot=snapshot, transport=transport, oms_evidence=evidence)

    transport.restart(snapshot)
    _adapter(snapshot=snapshot, transport=transport, oms_evidence=evidence)

    assert transport.submit_calls == []
    assert transport.cancel_calls == []
    assert transport.read_calls == 0
    assert transport.view_calls == 0


@pytest.mark.parametrize("linked_kind", ["open_order", "deal"])
@pytest.mark.parametrize("ticket_source", ["order_snapshot", "durable_evidence"])
def test_read_order_stays_unknown_for_linked_ticket_after_adapter_restart(
    linked_kind: str, ticket_source: str
) -> None:
    request = _request()
    evidence = FakeMT5OMSEvidence()
    evidence.reserve(request, "oms-order-1", NOW_NS - 500_000_000)
    if ticket_source == "durable_evidence":
        evidence.bind_native("demo-123", "client-1", "native-order-1")
    snapshot = _snapshot()
    transport = FakeMT5Transport(snapshot)
    _adapter(snapshot=snapshot, transport=transport, oms_evidence=evidence)

    transport.restart(snapshot)
    adapter, _ = _adapter(snapshot=snapshot, transport=transport, oms_evidence=evidence)
    order = _order_snapshot(
        request,
        venue_order_id=(
            "native-order-1" if ticket_source == "order_snapshot" else None
        ),
    )
    transport.queue_read(None)
    if linked_kind == "open_order":
        linked_open_order = BrokerObservation(
            observation_id="obs-after-restart",
            environment="demo",
            account_id="demo-123",
            venue="MT5",
            client_order_id="other-client",
            status=OrderState.WORKING,
            observed_at=datetime.fromtimestamp(NOW_NS // 1_000_000_000, UTC),
            venue_order_id="native-order-1",
        )
        view = _native_view(open_orders=(linked_open_order,))
    else:
        linked_deal = _event(
            "DEAL",
            "deal-after-restart",
            "LV1" + "Z" * 26,
            9_999,
            related_order_id="native-order-1",
        )
        view = _native_view(deals=(linked_deal,))
    transport.queue_account_view(view)

    with pytest.raises(BrokerOutcomeUnknown) as caught:
        adapter.read_order(order)

    assert caught.value.code == "UNKNOWN_READ_ORDER"
    assert transport.submit_calls == []


def test_submit_unknown_attempt_remains_reserved_after_adapter_restart() -> None:
    request = _request()
    evidence = FakeMT5OMSEvidence()
    snapshot = _snapshot()
    transport = FakeMT5Transport(snapshot)
    adapter, _ = _adapter(snapshot=snapshot, transport=transport, oms_evidence=evidence)
    transport.queue_account_view(_native_view())
    transport.queue_submit(TimeoutError("synthetic timeout after dispatch"))

    with pytest.raises(BrokerOutcomeUnknown) as first_attempt:
        adapter.submit(request, _BoundPermit(request), 7)

    assert first_attempt.value.code == "UNKNOWN_SUBMIT"
    assert len(transport.submit_calls) == 1
    transport.restart(snapshot)
    restarted, _ = _adapter(snapshot=snapshot, transport=transport, oms_evidence=evidence)

    with pytest.raises(BrokerOutcomeUnknown) as retry:
        restarted.submit(request, _BoundPermit(request), 7)

    assert retry.value.code == "UNKNOWN_SUBMIT"
    assert len(transport.submit_calls) == 1


def test_unattributable_matching_deal_blocks_pre_submit_without_native_call() -> None:
    adapter, transport = _adapter()
    request = _request()
    unmatched_deal = _event(
        "DEAL",
        "unattributed-deal",
        "LV1" + "Z" * 26,
        8_888,
        quantity="100000",
        occurred_at_ns=NOW_NS - 200_000_000,
        related_order_id="unowned-native-order",
    )
    transport.queue_account_view(_native_view(deals=(unmatched_deal,)))

    with pytest.raises(BrokerOutcomeUnknown) as caught:
        adapter.submit(request, _BoundPermit(request), 7)

    assert caught.value.code == "UNKNOWN_SUBMIT"
    assert transport.submit_calls == []


@pytest.mark.parametrize("observed_delta_ns", [-1, 0])
def test_read_order_requires_account_view_strictly_after_attempt_time(
    observed_delta_ns: int,
) -> None:
    request = _request()
    attempted_ns = NOW_NS
    evidence = FakeMT5OMSEvidence()
    evidence.reserve(request, "oms-order-1", attempted_ns)
    adapter, transport = _adapter(oms_evidence=evidence)
    transport.queue_read(None)
    transport.queue_account_view(
        _native_view(observed_ns=attempted_ns + observed_delta_ns)
    )

    with pytest.raises(BrokerOutcomeUnknown) as caught:
        adapter.read_order(_order_snapshot(request))

    assert caught.value.code == "UNKNOWN_READ_ORDER"


def test_unknown_cancel_cannot_repeat_after_adapter_restart() -> None:
    request = _request()
    evidence = FakeMT5OMSEvidence()
    adapter, transport = _adapter(oms_evidence=evidence)
    transport.queue_account_view(_native_view())
    transport.queue_submit(MT5NativeSubmitAckV1("ACCEPTED", "native-order-cancel"))
    adapter.submit(request, _BoundPermit(request), 7)
    order = _order_snapshot(request, venue_order_id="native-order-cancel")
    transport.queue_account_view(_native_view())
    transport.queue_cancel(TimeoutError("synthetic cancel timeout"))

    with pytest.raises(BrokerOutcomeUnknown) as first_cancel:
        adapter.cancel(order)

    assert first_cancel.value.code == "UNKNOWN_CANCEL"
    assert transport.cancel_calls == ["native-order-cancel"]
    snapshot = _snapshot()
    transport.restart(snapshot)
    restarted, _ = _adapter(snapshot=snapshot, transport=transport, oms_evidence=evidence)
    transport.queue_account_view(_native_view())

    with pytest.raises(BrokerOutcomeUnknown) as repeated_cancel:
        restarted.cancel(order)

    assert repeated_cancel.value.code == "UNKNOWN_CANCEL"
    assert transport.cancel_calls == ["native-order-cancel"]


def test_post_gtd_deal_after_restart_uses_durable_native_link() -> None:
    request = _request(
        time_in_force="GTD",
        expires_at=datetime.fromtimestamp((NOW_NS + 1_000_000_000) / 1_000_000_000, UTC),
    )
    evidence = FakeMT5OMSEvidence()
    clock = [NOW_NS]
    adapter, transport = _adapter(
        lambda: clock[0],
        oms_evidence=evidence,
    )
    transport.queue_account_view(_native_view())
    transport.queue_submit(MT5NativeSubmitAckV1("ACCEPTED", "native-order-gtd"))
    result = adapter.submit(request, _BoundPermit(request), 7)
    result.assert_sealed()

    clock[0] = NOW_NS + 3_000_000_000
    restarted_snapshot = _snapshot(
        heartbeat_at_ns=clock[0] - 100_000_000,
        quote=MT5QuoteV1(
            native_symbol="EURUSD.demo",
            bid=Decimal("1.10000"),
            ask=Decimal("1.10002"),
            observed_ns=clock[0] - 100_000_000,
        ),
    )
    transport.restart(restarted_snapshot)
    restarted, _ = _adapter(
        lambda: clock[0],
        snapshot=restarted_snapshot,
        transport=transport,
        oms_evidence=evidence,
    )
    late_deal = _event(
        "DEAL",
        "late-gtd-after-restart",
        "LV1" + "Z" * 26,
        9_999,
        occurred_at_ns=NOW_NS + 2_000_000_000,
        related_order_id="native-order-gtd",
    )

    decision = restarted.ingest_callback(late_deal)

    assert decision.applied is True
    assert decision.late_gtd is True
    assert decision.operator_alert_code == "LATE_GTD"
    assert decision.discrepancy_code == "LATE_GTD"
    assert restarted.late_gtd_alert_count == 1
    assert len(transport.submit_calls) == 1


def test_account_view_rejects_pair_match_with_foreign_related_ticket() -> None:
    request = _request()
    evidence = FakeMT5OMSEvidence()
    adapter, transport = _adapter(oms_evidence=evidence)
    transport.queue_account_view(_native_view())
    transport.queue_submit(MT5NativeSubmitAckV1("ACCEPTED", "native-order-a"))
    adapter.submit(request, _BoundPermit(request), 7)
    correlation = encode_correlation(request.account_id, request.client_order_id)
    conflicting_deal = _event(
        "DEAL",
        "deal-foreign-link",
        correlation.comment,
        correlation.magic,
        related_order_id="foreign-native-ticket",
    )
    transport.queue_account_view(_native_view(deals=(conflicting_deal,)))

    with pytest.raises(BrokerOutcomeUnknown) as caught:
        adapter.read_account_view(request.account_id)

    assert caught.value.code == "UNKNOWN_ACCOUNT_VIEW"


def test_conflicting_callback_alerts_and_retains_actual_deal() -> None:
    request = _request()
    adapter, transport = _adapter()
    transport.queue_account_view(_native_view())
    transport.queue_submit(MT5NativeSubmitAckV1("ACCEPTED", "native-order-a"))
    adapter.submit(request, _BoundPermit(request), 7)
    correlation = encode_correlation(request.account_id, request.client_order_id)
    conflicting_deal = _event(
        "DEAL",
        "callback-foreign-link",
        correlation.comment,
        correlation.magic,
        related_order_id="foreign-native-ticket",
    )

    decision = adapter.ingest_callback(conflicting_deal)

    assert decision.applied is True
    assert decision.late_gtd is False
    assert decision.operator_alert_code == "RECONCILE_REQUIRED"
    assert decision.discrepancy_code is None
    assert adapter.deal_events == (conflicting_deal,)


@pytest.mark.parametrize(
    ("operation", "expected_code"),
    [
        ("read_account_view", "UNKNOWN_ACCOUNT_VIEW"),
        ("submit", "UNKNOWN_SUBMIT"),
        ("read_order", "UNKNOWN_READ_ORDER"),
        ("cancel", "UNKNOWN_CANCEL"),
    ],
)
def test_revision8_open_ticket_identity_conflict_blocks_all_adapter_paths(
    operation: str, expected_code: str
) -> None:
    evidence = FakeMT5OMSEvidence()
    transport = FakeMT5Transport(_snapshot())
    adapter, _ = _adapter(transport=transport, oms_evidence=evidence)
    client_one = _request()
    transport.queue_account_view(_native_view())
    transport.queue_submit(MT5NativeSubmitAckV1("ACCEPTED", "native-order-1"))
    adapter.submit(client_one, _BoundPermit(client_one), 7)

    snapshot_eight = _snapshot(broker_revision=8)
    transport.restart(snapshot_eight)
    view_eight = _native_view(
        open_orders=(
            BrokerObservation(
                observation_id="contradictory-open-ticket",
                environment="demo",
                account_id="demo-123",
                venue="MT5",
                client_order_id="client-foreign",
                status=OrderState.WORKING,
                observed_at=datetime.fromtimestamp(NOW_NS // 1_000_000_000, UTC),
                venue_order_id="native-order-1",
            ),
        ),
        observed_ns=NOW_NS,
        broker_revision=8,
    )
    restarted, _ = _adapter(
        snapshot=snapshot_eight,
        transport=transport,
        oms_evidence=evidence,
    )
    order_one = _order_snapshot(client_one, venue_order_id="native-order-1")

    if operation in {"read_account_view", "submit", "cancel"}:
        transport.queue_account_view(view_eight)
    elif operation == "read_order":
        transport.queue_read(None)
        transport.queue_account_view(view_eight)

    if operation == "submit":
        client_two = _request(
            client_order_id="client-2",
            intent_idempotency_key="intent-2",
        )

    with pytest.raises(BrokerOutcomeUnknown) as caught:
        if operation == "read_account_view":
            restarted.read_account_view("demo-123")
        elif operation == "submit":
            restarted.submit(
                client_two,
                _BoundPermit(client_two, order_id="oms-order-2", revision=8),
                8,
            )
        elif operation == "read_order":
            restarted.read_order(order_one)
        else:
            restarted.cancel(order_one)

    assert caught.value.code == expected_code
    assert len(transport.submit_calls) == 1
    assert transport.cancel_calls == []


def test_lost_ack_reserved_pair_can_attribute_deal_without_native_ticket() -> None:
    request = _request()
    evidence = FakeMT5OMSEvidence()
    adapter, transport = _adapter(oms_evidence=evidence)
    transport.queue_account_view(_native_view())
    transport.queue_submit(TimeoutError("synthetic lost submit acknowledgment"))

    with pytest.raises(BrokerOutcomeUnknown) as lost_ack:
        adapter.submit(request, _BoundPermit(request), 7)

    assert lost_ack.value.code == "UNKNOWN_SUBMIT"
    correlation = encode_correlation(request.account_id, request.client_order_id)
    unbound_deal = _event(
        "DEAL",
        "deal-after-lost-ack",
        correlation.comment,
        correlation.magic,
        related_order_id="native-ticket-without-durable-binding",
    )
    restarted, _ = _adapter(transport=transport, oms_evidence=evidence)
    transport.queue_account_view(_native_view(deals=(unbound_deal,)))

    view = restarted.read_account_view(request.account_id)

    assert len(view.executions) == 1
    assert view.executions[0].client_order_id == request.client_order_id


def test_durable_native_ticket_attributes_deal_when_pair_is_rewritten() -> None:
    request = _request()
    evidence = FakeMT5OMSEvidence()
    adapter, transport = _adapter(oms_evidence=evidence)
    transport.queue_account_view(_native_view())
    transport.queue_submit(MT5NativeSubmitAckV1("ACCEPTED", "native-order-a"))
    adapter.submit(request, _BoundPermit(request), 7)
    restarted, _ = _adapter(transport=transport, oms_evidence=evidence)
    rewritten_pair_deal = _event(
        "DEAL",
        "deal-known-native-rewritten-pair",
        "LV1" + "Z" * 26,
        7_777,
        related_order_id="native-order-a",
    )
    transport.queue_account_view(_native_view(deals=(rewritten_pair_deal,)))

    view = restarted.read_account_view(request.account_id)

    assert len(view.executions) == 1
    assert view.executions[0].client_order_id == request.client_order_id


def test_huge_compact_decimal_is_rejected_without_expansion() -> None:
    with pytest.raises(MT5AdapterError) as caught:
        MT5QuoteV1(
            native_symbol="EURUSD.demo",
            bid=Decimal("1E+100000"),
            ask=Decimal("1E+100000"),
            observed_ns=NOW_NS,
        )
    assert caught.value.code == "INVALID_PRICE"


def test_public_validation_errors_are_typed_and_do_not_echo_input() -> None:
    canary = "UNTRUSTED_NATIVE_SYMBOL_CANARY"
    with pytest.raises(MT5AdapterError) as caught:
        replace(_spec(), native_symbol=f"bad symbol {canary}")

    error = caught.value
    assert error.code == "INVALID_IDENTITY"
    for view in (str(error), repr(error.args), repr(error.errors()), error.json()):
        assert canary not in view


def test_deals_outside_the_account_view_time_window_are_rejected() -> None:
    correlation = encode_correlation("demo-123", "client-1")
    deal = _event("DEAL", "deal-window", correlation.comment, correlation.magic)
    cutoff = datetime.fromtimestamp((NOW_NS - 100_000_000) / 1_000_000_000, UTC)

    with pytest.raises(MT5AdapterError) as too_old:
        _native_view(deals=(deal,), executions_since=cutoff)
    assert too_old.value.code == "NATIVE_EVENT_INVALID"

    future_deal = _event(
        "DEAL",
        "deal-future",
        correlation.comment,
        correlation.magic,
        occurred_at_ns=NOW_NS + 1_000_000,
    )
    with pytest.raises(MT5AdapterError) as too_new:
        _native_view(deals=(future_deal,))
    assert too_new.value.code == "NATIVE_EVENT_INVALID"


def test_wrong_permit_is_rejected_before_any_native_submit() -> None:
    adapter, transport = _adapter()
    request = _request()
    wrong_permit = _BoundPermit(
        _request(client_order_id="different-client"),
        order_id="different-oms-order",
    )

    with pytest.raises(MT5AdapterError) as caught:
        adapter.submit(request, wrong_permit, 7)

    assert caught.value.code == "PERMIT_REQUIRED"
    assert wrong_permit.calls == [
        (wrong_permit.order_id, request.digest, 7)
    ]
    assert transport.submit_calls == []


def test_submit_timeout_and_incomplete_view_remain_unknown_without_retry() -> None:
    request = _request()
    adapter, transport = _adapter()
    transport.queue_account_view(_native_view(positions_complete=False))

    with pytest.raises(BrokerOutcomeUnknown) as incomplete:
        adapter.submit(request, _BoundPermit(request), 7)
    assert incomplete.value.code == "UNKNOWN_SUBMIT"
    assert transport.submit_calls == []

    adapter, transport = _adapter()
    permit = _BoundPermit(request)
    transport.queue_account_view(_native_view())
    transport.queue_submit(TimeoutError("synthetic timeout"))
    with pytest.raises(BrokerOutcomeUnknown) as uncertain:
        adapter.submit(request, permit, 7)
    assert uncertain.value.code == "UNKNOWN_SUBMIT"
    assert permit.calls == [(permit.order_id, request.digest, 7)]
    assert len(transport.submit_calls) == 1

    with pytest.raises(BrokerOutcomeUnknown) as retry:
        adapter.submit(request, _BoundPermit(request), 7)
    assert retry.value.code == "UNKNOWN_SUBMIT"
    assert len(transport.submit_calls) == 1


@pytest.mark.parametrize(
    "incomplete_field",
    ["orders_complete", "deals_complete", "positions_complete"],
)
def test_read_account_view_requires_orders_deals_and_positions_complete(
    incomplete_field: str,
) -> None:
    adapter, transport = _adapter()
    transport.queue_account_view(_native_view(**{incomplete_field: False}))

    with pytest.raises(BrokerOutcomeUnknown) as caught:
        adapter.read_account_view("demo-123")

    assert caught.value.code == "UNKNOWN_ACCOUNT_VIEW"


def test_cancel_timeout_stays_unknown_and_never_sends_a_second_cancel() -> None:
    adapter, transport = _adapter()
    order = _order_snapshot(_request())
    transport.queue_account_view(_native_view())
    transport.queue_cancel(TimeoutError("synthetic cancel timeout"))

    with pytest.raises(BrokerOutcomeUnknown) as caught:
        adapter.cancel(order)
    assert caught.value.code == "UNKNOWN_CANCEL"
    assert transport.cancel_calls == ["native-order-1"]

    transport.queue_account_view(_native_view())
    transport.queue_cancel(MT5NativeCancelAckV1(confirmed=True))
    with pytest.raises(BrokerOutcomeUnknown) as retry:
        adapter.cancel(order)
    assert retry.value.code == "UNKNOWN_CANCEL"
    assert transport.cancel_calls == ["native-order-1"]


def test_account_view_keeps_order_deal_and_position_identities_separate() -> None:
    adapter, transport = _adapter()
    corr = encode_correlation("demo-123", "client-1")
    shared_ticket = "ticket-77"
    observation = BrokerObservation(
        observation_id="obs-1",
        environment="demo",
        account_id="demo-123",
        venue="MT5",
        client_order_id="client-1",
        status=OrderState.WORKING,
        observed_at=datetime.fromtimestamp(NOW_NS / 1_000_000_000, UTC),
        venue_order_id=shared_ticket,
    )
    deal = _event(
        "DEAL",
        shared_ticket,
        corr.comment,
        corr.magic,
        related_order_id=shared_ticket,
        related_position_id=shared_ticket,
    )
    transport.queue_account_view(
        _native_view(
            open_orders=(observation,),
            deals=(deal,),
            positions=(("EURUSD", Decimal("25000")),),
        )
    )

    view = adapter.read_account_view("demo-123")
    view.assert_sealed()
    assert type(view) is AccountViewV1
    assert view.open_orders[0].venue_order_id == shared_ticket
    assert len(view.executions) == 1
    execution = view.executions[0]
    assert type(execution) is ExecutionV1
    execution.assert_sealed()
    assert execution.execution_id == shared_ticket
    assert execution.venue_order_id == shared_ticket
    assert view.positions == (("EURUSD", Decimal("25000")),)

    position_event = _event(
        "POSITION",
        shared_ticket,
        corr.comment,
        corr.magic,
        related_order_id=shared_ticket,
        related_position_id=shared_ticket,
    )
    position_decision = adapter.ingest_callback(position_event)
    assert position_decision.applied is True


def test_trust_bearing_outputs_require_private_issuance_and_recheck_digest() -> None:
    adapter, transport = _adapter()
    request = _request()
    transport.queue_account_view(_native_view())
    transport.queue_submit(MT5NativeSubmitAckV1("ACCEPTED", "native-order-1"))
    result = adapter.submit(request, _BoundPermit(request), 7)
    result.assert_sealed()
    assert "_issuer" not in type(result).__slots__

    with pytest.raises(BrokerPortError) as direct:
        SubmitResultV1("forged-order", OrderState.WORKING)
    assert direct.value.code == "UNISSUED_BROKER_RECORD"

    with pytest.raises(BrokerPortError) as replaced:
        replace(result, venue_order_id="other-order")
    assert replaced.value.code == "UNISSUED_BROKER_RECORD"

    with pytest.raises(BrokerPortError) as equal_replacement:
        replace(result)
    assert equal_replacement.value.code == "UNISSUED_BROKER_RECORD"

    with pytest.raises(BrokerPortError) as forged_issuer:
        replace(result, _issuer=object())
    assert forged_issuer.value.code == "UNISSUED_BROKER_RECORD"

    with pytest.raises(BrokerPortError) as reinitialized:
        result.__init__("other-order", OrderState.WORKING)
    assert reinitialized.value.code == "REINIT_FORBIDDEN"

    object.__setattr__(result, "venue_order_id", "tampered-order")
    with pytest.raises(BrokerPortError) as tampered:
        result.assert_sealed()
    assert tampered.value.code == "BROKER_RECORD_TAMPERED"


def test_issued_results_reject_copy_deepcopy_and_pickle() -> None:
    adapter, transport = _adapter()
    request = _request()
    transport.queue_account_view(_native_view())
    transport.queue_submit(MT5NativeSubmitAckV1("ACCEPTED", "native-order-1"))
    result = adapter.submit(request, _BoundPermit(request), 7)
    outputs = (result, adapter.capability, adapter.venue)

    for output in outputs:
        output.assert_sealed()
        with pytest.raises(BrokerPortError):
            copy.copy(output)
        with pytest.raises(BrokerPortError):
            copy.deepcopy(output)
        with pytest.raises(BrokerPortError):
            pickle.dumps(output)


def test_nested_execution_decimal_to_integer_tamper_invalidates_both_seals() -> None:
    adapter, transport = _adapter()
    correlation = encode_correlation("demo-123", "client-1")
    deal = _event("DEAL", "deal-seal", correlation.comment, correlation.magic)
    transport.queue_account_view(_native_view(deals=(deal,)))

    view = adapter.read_account_view("demo-123")
    execution = view.executions[0]
    view.assert_sealed()
    execution.assert_sealed()
    object.__setattr__(execution, "quantity", 25000)

    with pytest.raises(BrokerPortError):
        execution.assert_sealed()
    with pytest.raises(BrokerPortError):
        view.assert_sealed()


def test_account_view_tuple_to_list_type_confusion_fails_closed() -> None:
    adapter, transport = _adapter()
    transport.queue_account_view(_native_view())
    view = adapter.read_account_view("demo-123")
    view.assert_sealed()
    object.__setattr__(view, "open_orders", list(view.open_orders))

    with pytest.raises(BrokerPortError):
        view.assert_sealed()


def test_account_view_and_execution_direct_construction_are_unissued() -> None:
    with pytest.raises(BrokerPortError) as view_error:
        AccountViewV1(
            "demo-123",
            (),
            (),
            7,
            (),
            datetime.fromtimestamp(0, UTC),
        )
    assert view_error.value.code == "UNISSUED_BROKER_RECORD"

    with pytest.raises(BrokerPortError) as execution_error:
        ExecutionV1(
            "deal-1",
            "native-order-1",
            "client-1",
            "EURUSD",
            "BUY",
            Decimal("1"),
            Decimal("1.1"),
            datetime.fromtimestamp(1, UTC),
        )
    assert execution_error.value.code == "UNISSUED_BROKER_RECORD"


def test_callback_partial_fills_corrections_and_duplicates_are_versioned() -> None:
    adapter, transport = _adapter()
    request = _request()
    correlation = encode_correlation("demo-123", request.client_order_id)
    transport.queue_account_view(_native_view())
    transport.queue_submit(MT5NativeSubmitAckV1("ACCEPTED", "native-order-1"))
    result = adapter.submit(request, _BoundPermit(request), 7)
    result.assert_sealed()

    first_fill = _event("DEAL", "deal-1", correlation.comment, correlation.magic)
    second_fill = _event(
        "DEAL",
        "deal-2",
        correlation.comment,
        correlation.magic,
        quantity="30000",
    )
    corrected_fill = replace(first_fill, version=2, quantity=Decimal("20000"))

    assert adapter.ingest_callback(first_fill).applied is True
    assert adapter.ingest_callback(second_fill).applied is True
    duplicate = adapter.ingest_callback(first_fill)
    assert type(duplicate) is MT5CallbackDecisionV1
    assert duplicate.applied is False
    assert adapter.ingest_callback(corrected_fill).applied is True
    assert adapter.ingest_callback(first_fill).applied is False

    transport.queue_account_view(_native_view(deals=(corrected_fill, second_fill)))
    view = adapter.read_account_view("demo-123")
    assert [execution.execution_id for execution in view.executions] == ["deal-1", "deal-2"]
    assert [execution.quantity for execution in view.executions] == [
        Decimal("20000"),
        Decimal("30000"),
    ]
    assert sum((execution.quantity for execution in view.executions), Decimal(0)) == Decimal(
        "50000"
    )


def test_failed_exit_timeout_preserves_open_position_without_auto_flatten() -> None:
    adapter, transport = _adapter()
    exit_request = _request(side="SELL", client_order_id="exit-client")
    transport.queue_account_view(
        _native_view(positions=(("EURUSD", Decimal("100000")),))
    )
    transport.queue_submit(TimeoutError("synthetic exit timeout"))

    with pytest.raises(BrokerOutcomeUnknown) as caught:
        adapter.submit(exit_request, _BoundPermit(exit_request), 7)
    assert caught.value.code == "UNKNOWN_SUBMIT"
    assert len(transport.submit_calls) == 1

    transport.queue_account_view(
        _native_view(positions=(("EURUSD", Decimal("100000")),))
    )
    view = adapter.read_account_view("demo-123")
    assert view.positions == (("EURUSD", Decimal("100000")),)
    assert len(transport.submit_calls) == 1


def test_post_gtd_deal_is_retained_as_late_fill_without_new_order() -> None:
    clock = [NOW_NS]
    adapter, transport = _adapter(lambda: clock[0])
    expiry = datetime.fromtimestamp(1001, UTC)
    request = _request(time_in_force="GTD", expires_at=expiry)
    correlation = encode_correlation("demo-123", request.client_order_id)
    transport.queue_account_view(_native_view())
    transport.queue_submit(MT5NativeSubmitAckV1("ACCEPTED", "native-order-1"))

    result = adapter.submit(request, _BoundPermit(request), 7)
    result.assert_sealed()
    late_deal = _event(
        "DEAL",
        "late-deal-1",
        correlation.comment,
        correlation.magic,
        occurred_at_ns=NOW_NS + 1_000_001_000,
    )
    decision = adapter.ingest_callback(late_deal)

    assert decision.applied is True
    assert decision.late_gtd is True
    assert decision.operator_alert_code == "LATE_GTD"
    assert decision.discrepancy_code == "LATE_GTD"
    assert adapter.late_gtd_alert_count == 1
    assert len(transport.submit_calls) == 1

    clock[0] = late_deal.occurred_at_ns
    transport.queue_account_view(
        _native_view(
            deals=(late_deal,),
            positions=(("EURUSD", Decimal("25000")),),
            observed_ns=clock[0],
        )
    )
    account = adapter.read_account_view("demo-123")
    assert account.executions[0].execution_id == "late-deal-1"
    assert account.executions[0].quantity == Decimal("25000")
    assert account.positions == (("EURUSD", Decimal("25000")),)
    assert len(transport.submit_calls) == 1


@pytest.mark.parametrize("collision_field", ["comment", "magic"])
def test_comment_or_magic_collision_fails_closed_and_never_adopts_other_client(
    monkeypatch: pytest.MonkeyPatch,
    collision_field: str,
) -> None:
    first_request = _request(client_order_id="client-first")
    second_request = _request(client_order_id="client-second")
    first_corr = MT5CorrelationV1("LV1" + "A" * 26, 101)
    if collision_field == "comment":
        second_corr = MT5CorrelationV1(first_corr.comment, 202)
    else:
        second_corr = MT5CorrelationV1("LV1" + "B" * 26, first_corr.magic)

    def collision_encoder(account_id: str, client_order_id: str) -> MT5CorrelationV1:
        assert account_id == "demo-123"
        return first_corr if client_order_id == "client-first" else second_corr

    monkeypatch.setattr(mt5_demo_module, "encode_correlation", collision_encoder)
    adapter, transport = _adapter()
    transport.queue_account_view(_native_view())
    transport.queue_submit(MT5NativeSubmitAckV1("ACCEPTED", "native-order-1"))
    accepted = adapter.submit(first_request, _BoundPermit(first_request), 7)
    accepted.assert_sealed()

    transport.queue_account_view(_native_view())
    with pytest.raises(BrokerOutcomeUnknown) as collided_submit:
        adapter.submit(second_request, _BoundPermit(second_request, order_id="oms-order-2"), 7)
    assert collided_submit.value.code == "UNKNOWN_SUBMIT"
    assert len(transport.submit_calls) == 1

    order = _order_snapshot(second_request, order_id="oms-order-2")
    transport.queue_read(None)
    first_deal = _event(
        "DEAL",
        "deal-first",
        first_corr.comment,
        first_corr.magic,
    )
    transport.queue_account_view(_native_view(deals=(first_deal,)))
    with pytest.raises(BrokerOutcomeUnknown) as collided_read:
        adapter.read_order(order)
    assert collided_read.value.code == "UNKNOWN_READ_ORDER"
    assert len(transport.submit_calls) == 1
