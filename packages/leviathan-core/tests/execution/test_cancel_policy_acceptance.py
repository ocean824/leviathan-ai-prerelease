"""Independent acceptance checks for cancel and flatten policy boundaries."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest

from leviathan_core.execution.broker_port_v1 import (
    BrokerOutcomeUnknown,
    BrokerRejected,
    BrokerRejectionCode,
    BrokerUnknownCode,
)
from leviathan_core.execution.cancel_coordinator import CancelCoordinator
from leviathan_core.execution.cancel_policy import (
    CancelBrokerEvidenceV1,
    CancelExecutionV1,
    CancelPolicyCode,
    CancelPolicyError,
    CancelPolicyV1,
    CancelRequestV1,
    FlattenPolicyV1,
    FlattenRequestV1,
    MassCancelRequestV1,
    PositionSnapshotV1,
    issue_cancel_broker_evidence,
    issue_cancel_execution,
    issue_cancel_policy,
    issue_cancel_request,
    issue_flatten_policy,
    issue_flatten_request,
    issue_mass_cancel_request,
    issue_position_snapshot,
)

NOW = datetime(2026, 10, 6, 15, 0, tzinfo=UTC)
NOW_NS = 1_791_298_800_000_000_000


class _FakeBroker:
    def __init__(
        self,
        *,
        cancel_outcomes: tuple[CancelBrokerEvidenceV1 | Exception, ...],
        reconcile_outcomes: tuple[CancelBrokerEvidenceV1 | Exception, ...],
        trace: list[str],
    ) -> None:
        self.cancel_outcomes = list(cancel_outcomes)
        self.reconcile_outcomes = list(reconcile_outcomes)
        self.trace = trace
        self.cancel_calls = 0
        self.reconcile_calls = 0

    async def cancel(self, request: CancelRequestV1) -> CancelBrokerEvidenceV1:
        del request
        self.cancel_calls += 1
        self.trace.append("broker.cancel")
        outcome = self.cancel_outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    async def reconcile(self, request: CancelRequestV1) -> CancelBrokerEvidenceV1:
        del request
        self.reconcile_calls += 1
        self.trace.append("broker.reconcile")
        outcome = self.reconcile_outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class _FakeChildren:
    def __init__(self, trace: list[str]) -> None:
        self.trace = trace
        self.calls = 0

    async def stop_children(self, request: CancelRequestV1) -> None:
        del request
        self.calls += 1
        self.trace.append("children.stop")


class _FakeJournal:
    """In-memory committed journal for deterministic acceptance scenarios."""

    def __init__(self, trace: list[str]) -> None:
        self.trace = trace
        self.claimed_keys: set[str] = set()
        self.states: list[tuple[str, str]] = []
        self.sent: list[str] = []
        self.executions: list[str] = []
        self.discrepancies: list[str] = []
        self.alerts: list[str] = []

    async def begin_cancel(self, request: CancelRequestV1) -> bool:
        self.trace.append("journal.begin")
        if request.idempotency_key in self.claimed_keys:
            return False
        self.claimed_keys.add(request.idempotency_key)
        return True

    async def mark_cancel_sent(self, request: CancelRequestV1) -> None:
        self.trace.append("journal.sent")
        self.sent.append(request.idempotency_key)

    async def record_state(self, request: CancelRequestV1, state: str, reason_code: str) -> None:
        self.trace.append(f"journal.state:{state}")
        self.states.append((state, reason_code))

    async def record_execution(
        self, request: CancelRequestV1, execution: CancelExecutionV1
    ) -> None:
        del request
        self.trace.append("journal.execution")
        self.executions.append(execution.execution_id)

    async def record_discrepancy(self, request: CancelRequestV1, code: str) -> None:
        del request
        self.trace.append(f"journal.discrepancy:{code}")
        self.discrepancies.append(code)

    async def alert_operator(self, request: CancelRequestV1, code: str) -> None:
        del request
        self.trace.append(f"journal.alert:{code}")
        self.alerts.append(code)


class _FakeClock:
    def __init__(self, current: datetime) -> None:
        self.current = current
        self.reads = 0

    def now(self) -> datetime:
        self.reads += 1
        return self.current

    def advance(self, seconds: int) -> None:
        self.current += timedelta(seconds=seconds)


def _cancel_policy(
    *,
    halt_mass_cancel: bool = False,
    timeout_ms: int = 25,
    protective_leg_action: str = "CANCEL",
    maximum_mass_cancel_orders: int = 10,
) -> CancelPolicyV1:
    return issue_cancel_policy(
        CancelPolicyV1(
            policy_id="acceptance-cancel-policy",
            revision="revision-1",
            account_id="paper-account",
            venue="ALPACA",
            environment="paper",
            allowed_operator_ids=("operator-1",),
            instrument_ids=("NQ-202612",),
            strategy_ids=("strategy-1",),
            allowed_scopes=("ORDER", "ACCOUNT"),
            halt_requests_mass_cancel=halt_mass_cancel,
            cancel_timeout_ms=timeout_ms,
            maximum_mass_cancel_orders=maximum_mass_cancel_orders,
            protective_leg_action=protective_leg_action,  # type: ignore[arg-type]
            lost_connection_action="RECONCILE_AND_HOLD",
        )
    )


def _request(
    *,
    key: str = "cancel-key-1",
    trigger: str = "OPERATOR",
    order_id: str = "order-1",
    client_order_id: str = "client-1",
    venue_order_id: str = "venue-1",
    protective_leg: bool = False,
) -> CancelRequestV1:
    return issue_cancel_request(
        CancelRequestV1(
            order_id=order_id,
            client_order_id=client_order_id,
            venue_order_id=venue_order_id,
            account_id="paper-account",
            venue="ALPACA",
            environment="paper",
            instrument_id="NQ-202612",
            strategy_id="strategy-1",
            side="BUY",
            operator_id="operator-1",
            idempotency_key=key,
            scope="ORDER",
            trigger=trigger,  # type: ignore[arg-type]
            protective_leg=protective_leg,
            gtd_expiry_ns=None,
        )
    )


def _evidence(
    *,
    source: str,
    status: str,
    confirmed: bool = False,
    executions: tuple[CancelExecutionV1, ...] = (),
    request: CancelRequestV1 | None = None,
) -> CancelBrokerEvidenceV1:
    request = request if request is not None else _request()
    return issue_cancel_broker_evidence(
        CancelBrokerEvidenceV1(
            source=source,  # type: ignore[arg-type]
            order_id=request.order_id,
            client_order_id=request.client_order_id,
            venue_order_id=request.venue_order_id,
            account_id=request.account_id,
            venue=request.venue,
            environment=request.environment,
            instrument_id=request.instrument_id,
            side=request.side,
            status=status,  # type: ignore[arg-type]
            cancel_confirmed=confirmed,
            executions=executions,
            observed_at_ns=NOW_NS,
        )
    )


def _coordinator(
    *,
    broker: _FakeBroker,
    children: _FakeChildren,
    journal: _FakeJournal,
    clock: _FakeClock | None = None,
    halt_mass_cancel: bool = False,
    flatten_policy: FlattenPolicyV1 | None = None,
    protective_leg_action: str = "CANCEL",
    maximum_mass_cancel_orders: int = 10,
) -> CancelCoordinator:
    return CancelCoordinator(
        cancel_policy=_cancel_policy(
            halt_mass_cancel=halt_mass_cancel,
            protective_leg_action=protective_leg_action,
            maximum_mass_cancel_orders=maximum_mass_cancel_orders,
        ),
        flatten_policy=flatten_policy,
        broker=broker,
        child_dispatch=children,
        journal=journal,
        clock=clock if clock is not None else _FakeClock(NOW),
    )


def _flatten_policy() -> FlattenPolicyV1:
    return issue_flatten_policy(
        FlattenPolicyV1(
            policy_id="acceptance-flatten-policy",
            revision="revision-1",
            account_id="paper-account",
            venue="ALPACA",
            environment="paper",
            operator_ids=("operator-1",),
            instrument_ids=("NQ-202612",),
            strategy_ids=("strategy-1",),
            allowed_sides=("SELL",),
            allowed_session_states=("OPEN",),
            position_source="fake-position-feed",
            maximum_position_age_ns=60_000_000_000,
            maximum_quantity=Decimal("5"),
            maximum_slippage_bps=Decimal("25"),
        )
    )


def _flatten_request(
    *,
    human_confirmed: bool = True,
    halt_active: bool = False,
    operator_id: str = "operator-1",
    now_ns: int = NOW_NS,
) -> FlattenRequestV1:
    return issue_flatten_request(
        FlattenRequestV1(
            account_id="paper-account",
            venue="ALPACA",
            environment="paper",
            instrument_id="NQ-202612",
            strategy_id="strategy-1",
            operator_id=operator_id,
            idempotency_key="flatten-key-1",
            side="SELL",
            quantity=Decimal("1"),
            slippage_bps=Decimal("5"),
            session_state="OPEN",
            human_confirmed=human_confirmed,
            halt_active=halt_active,
            now_ns=now_ns,
        )
    )


def _position(*, observed_at_ns: int = NOW_NS) -> PositionSnapshotV1:
    return issue_position_snapshot(
        PositionSnapshotV1(
            account_id="paper-account",
            venue="ALPACA",
            environment="paper",
            instrument_id="NQ-202612",
            strategy_id="strategy-1",
            position_source="fake-position-feed",
            position_revision="position-rev-1",
            net_quantity=Decimal("2"),
            observed_at_ns=observed_at_ns,
        )
    )


@pytest.mark.asyncio
async def test_timeout_stops_children_sends_one_cancel_then_reconciles_without_confirmation() -> (
    None
):
    trace: list[str] = []
    broker = _FakeBroker(
        cancel_outcomes=(TimeoutError(),),
        reconcile_outcomes=(_evidence(source="RECONCILIATION", status="WORKING"),),
        trace=trace,
    )
    children = _FakeChildren(trace)
    journal = _FakeJournal(trace)
    result = await _coordinator(broker=broker, children=children, journal=journal).cancel(
        _request(), halt_active=False
    )

    assert broker.cancel_calls == 1
    assert broker.reconcile_calls == 1
    assert children.calls == 1
    assert trace.index("children.stop") < trace.index("broker.cancel")
    assert trace.index("journal.sent") < trace.index("broker.cancel")
    assert result.lifecycle_state == "CANCEL_REQUESTED_UNCONFIRMED"
    assert result.oms_state == "UNKNOWN_CANCEL"
    assert result.cancel_sent is True
    assert journal.states[-1] == ("CANCEL_REQUESTED_UNCONFIRMED", "UNKNOWN_CANCEL")


@pytest.mark.asyncio
async def test_repeated_idempotency_key_reconciles_without_a_second_cancel() -> None:
    trace: list[str] = []
    broker = _FakeBroker(
        cancel_outcomes=(TimeoutError(),),
        reconcile_outcomes=(
            _evidence(source="RECONCILIATION", status="WORKING"),
            _evidence(source="RECONCILIATION", status="WORKING"),
        ),
        trace=trace,
    )
    children = _FakeChildren(trace)
    journal = _FakeJournal(trace)
    coordinator = _coordinator(broker=broker, children=children, journal=journal)

    first = await coordinator.cancel(_request(), halt_active=False)
    second = await coordinator.cancel(_request(), halt_active=False)

    assert first.lifecycle_state == second.lifecycle_state == "CANCEL_REQUESTED_UNCONFIRMED"
    assert broker.cancel_calls == 1
    assert broker.reconcile_calls == 2
    assert journal.sent == ["cancel-key-1"]
    assert second.cancel_sent is False


@pytest.mark.asyncio
async def test_connection_loss_reconciles_and_never_blindly_retries_cancel() -> None:
    trace: list[str] = []
    broker = _FakeBroker(
        cancel_outcomes=(ConnectionError("synthetic transport loss"),),
        reconcile_outcomes=(_evidence(source="RECONCILIATION", status="WORKING"),),
        trace=trace,
    )
    journal = _FakeJournal(trace)
    result = await _coordinator(
        broker=broker, children=_FakeChildren(trace), journal=journal
    ).cancel(_request(), halt_active=False)

    assert broker.cancel_calls == 1
    assert broker.reconcile_calls == 1
    assert result.lifecycle_state == "CANCEL_REQUESTED_UNCONFIRMED"
    assert result.oms_state == "UNKNOWN_CANCEL"
    assert all(state != "CANCELED" for state, _ in journal.states)


@pytest.mark.asyncio
async def test_restart_resumes_existing_claim_by_reconciling_without_resending() -> None:
    trace: list[str] = []
    durable_journal = _FakeJournal(trace)
    first_broker = _FakeBroker(
        cancel_outcomes=(TimeoutError(),),
        reconcile_outcomes=(_evidence(source="RECONCILIATION", status="WORKING"),),
        trace=trace,
    )
    first = await _coordinator(
        broker=first_broker,
        children=_FakeChildren(trace),
        journal=durable_journal,
    ).cancel(_request(), halt_active=False)

    restarted_broker = _FakeBroker(
        cancel_outcomes=(),
        reconcile_outcomes=(_evidence(source="RECONCILIATION", status="WORKING"),),
        trace=trace,
    )
    resumed = await _coordinator(
        broker=restarted_broker,
        children=_FakeChildren(trace),
        journal=durable_journal,
    ).cancel(_request(), halt_active=False)

    assert first.lifecycle_state == resumed.lifecycle_state == "CANCEL_REQUESTED_UNCONFIRMED"
    assert first_broker.cancel_calls == 1
    assert restarted_broker.cancel_calls == 0
    assert restarted_broker.reconcile_calls == 1
    assert durable_journal.sent == ["cancel-key-1"]


@pytest.mark.asyncio
async def test_unconfirmed_canceled_label_is_not_terminal_without_broker_confirmation() -> None:
    trace: list[str] = []
    broker = _FakeBroker(
        cancel_outcomes=(_evidence(source="CANCEL_ACK", status="CANCELED"),),
        reconcile_outcomes=(_evidence(source="RECONCILIATION", status="CANCELED"),),
        trace=trace,
    )
    journal = _FakeJournal(trace)
    result = await _coordinator(
        broker=broker, children=_FakeChildren(trace), journal=journal
    ).cancel(_request(), halt_active=False)

    assert result.lifecycle_state == "CANCEL_REQUESTED_UNCONFIRMED"
    assert result.oms_state == "UNKNOWN_CANCEL"
    assert all(state != "CANCELED" for state, _ in journal.states)


@pytest.mark.asyncio
async def test_only_explicit_broker_cancel_confirmation_commits_terminal_state() -> None:
    trace: list[str] = []
    confirmed = _evidence(source="CANCEL_ACK", status="CANCELED", confirmed=True)
    broker = _FakeBroker(
        cancel_outcomes=(confirmed,),
        reconcile_outcomes=(),
        trace=trace,
    )
    journal = _FakeJournal(trace)
    result = await _coordinator(
        broker=broker, children=_FakeChildren(trace), journal=journal
    ).cancel(_request(), halt_active=False)

    assert result.lifecycle_state == "CANCELED"
    assert result.oms_state == "CANCELED"
    assert journal.states[-1] == ("CANCELED", "BROKER_CANCEL_CONFIRMED")
    assert broker.cancel_calls == 1
    assert broker.reconcile_calls == 0


@pytest.mark.asyncio
async def test_broker_rejected_cancel_is_recorded_without_claiming_canceled() -> None:
    trace: list[str] = []
    broker = _FakeBroker(
        cancel_outcomes=(BrokerRejected(BrokerRejectionCode.VENUE_REJECTED),),
        reconcile_outcomes=(),
        trace=trace,
    )
    journal = _FakeJournal(trace)
    result = await _coordinator(
        broker=broker, children=_FakeChildren(trace), journal=journal
    ).cancel(_request(), halt_active=False)

    assert result.lifecycle_state == "REJECTED"
    assert result.oms_state is None
    assert result.reason_code == BrokerRejectionCode.VENUE_REJECTED.value
    assert all(state != "CANCELED" for state, _ in journal.states)
    assert broker.cancel_calls == 1
    assert broker.reconcile_calls == 0


@pytest.mark.asyncio
async def test_protective_leg_preserve_blocks_cancel_but_explicit_cancel_policy_allows_it() -> None:
    trace: list[str] = []
    request = _request(key="protective-leg-key", protective_leg=True)
    blocked_broker = _FakeBroker(cancel_outcomes=(), reconcile_outcomes=(), trace=trace)
    blocked_journal = _FakeJournal(trace)
    blocked = _coordinator(
        broker=blocked_broker,
        children=_FakeChildren(trace),
        journal=blocked_journal,
        protective_leg_action="PRESERVE",
    )

    with pytest.raises(CancelPolicyError) as raised:
        await blocked.cancel(request, halt_active=False)

    assert raised.value.code == CancelPolicyCode.SCOPE_NOT_ALLOWED.value
    assert blocked_broker.cancel_calls == 0
    assert blocked_journal.claimed_keys == set()

    allowed_evidence = _evidence(
        source="CANCEL_ACK", status="CANCELED", confirmed=True, request=request
    )
    allowed_broker = _FakeBroker(
        cancel_outcomes=(allowed_evidence,), reconcile_outcomes=(), trace=trace
    )
    allowed = await _coordinator(
        broker=allowed_broker,
        children=_FakeChildren(trace),
        journal=_FakeJournal(trace),
        protective_leg_action="CANCEL",
    ).cancel(request, halt_active=False)

    assert allowed.lifecycle_state == "CANCELED"
    assert allowed_broker.cancel_calls == 1


@pytest.mark.asyncio
async def test_halt_policy_denies_mass_cancel_without_broker_dispatch() -> None:
    trace: list[str] = []
    broker = _FakeBroker(cancel_outcomes=(), reconcile_outcomes=(), trace=trace)
    coordinator = _coordinator(
        broker=broker,
        children=_FakeChildren(trace),
        journal=_FakeJournal(trace),
        halt_mass_cancel=False,
    )
    mass = issue_mass_cancel_request(
        MassCancelRequestV1(
            account_id="paper-account",
            venue="ALPACA",
            environment="paper",
            operator_id="operator-1",
            idempotency_key="mass-key-1",
            scope="ACCOUNT",
            requests=(_request(trigger="HALT"),),
            start_index=0,
            halt_active=True,
        )
    )

    with pytest.raises(CancelPolicyError) as raised:
        await coordinator.mass_cancel(mass, halt_active=True)

    assert raised.value.code == CancelPolicyCode.HALT_MASS_CANCEL_DENIED.value
    assert broker.cancel_calls == 0
    assert broker.reconcile_calls == 0


@pytest.mark.asyncio
async def test_mass_cancel_resumes_at_bounded_cursor_without_repeating_completed_orders() -> None:
    requests = tuple(
        _request(
            key=f"mass-cancel-key-{index}",
            order_id=f"order-{index}",
            client_order_id=f"client-{index}",
            venue_order_id=f"venue-{index}",
        )
        for index in range(1, 4)
    )
    trace: list[str] = []
    broker = _FakeBroker(
        cancel_outcomes=tuple(
            _evidence(source="CANCEL_ACK", status="CANCELED", confirmed=True, request=request)
            for request in requests
        ),
        reconcile_outcomes=(),
        trace=trace,
    )
    journal = _FakeJournal(trace)
    coordinator = _coordinator(
        broker=broker,
        children=_FakeChildren(trace),
        journal=journal,
        maximum_mass_cancel_orders=2,
    )

    first_page = issue_mass_cancel_request(
        MassCancelRequestV1(
            account_id="paper-account",
            venue="ALPACA",
            environment="paper",
            operator_id="operator-1",
            idempotency_key="mass-page-1",
            scope="ACCOUNT",
            requests=requests,
            start_index=0,
            halt_active=False,
        )
    )
    first_result = await coordinator.mass_cancel(first_page, halt_active=False)
    assert len(first_result.results) == 2
    assert first_result.complete is False
    assert first_result.next_index == 2
    assert broker.cancel_calls == 2

    resume = issue_mass_cancel_request(
        MassCancelRequestV1(
            account_id="paper-account",
            venue="ALPACA",
            environment="paper",
            operator_id="operator-1",
            idempotency_key="mass-page-2",
            scope="ACCOUNT",
            requests=requests,
            start_index=first_result.next_index,
            halt_active=False,
        )
    )
    final_result = await coordinator.mass_cancel(resume, halt_active=False)

    assert len(final_result.results) == 1
    assert final_result.complete is True
    assert final_result.next_index is None
    assert broker.cancel_calls == 3
    assert journal.sent == [item.idempotency_key for item in requests]


@pytest.mark.parametrize("halt_active,request_halt", [(True, False), (False, True)])
def test_halt_always_denies_flatten_eligibility(halt_active: bool, request_halt: bool) -> None:
    trace: list[str] = []
    broker = _FakeBroker(cancel_outcomes=(), reconcile_outcomes=(), trace=trace)
    coordinator = _coordinator(
        broker=broker,
        children=_FakeChildren(trace),
        journal=_FakeJournal(trace),
        flatten_policy=_flatten_policy(),
    )

    decision = coordinator.evaluate_flatten(
        _flatten_request(halt_active=request_halt), _position(), halt_active=halt_active
    )

    assert decision.approved_for_oms_review is False
    assert decision.denial_code == CancelPolicyCode.HALT_FLATTEN_DENIED.value
    assert decision.dispatch_permitted is False
    assert decision.requires_fresh_risk_halt_oms_checks is False
    assert broker.cancel_calls == 0


@pytest.mark.parametrize(
    "human_confirmed,operator_id", [(False, "operator-1"), (True, "forged-operator")]
)
def test_flatten_requires_human_confirmation_and_allowlisted_operator(
    human_confirmed: bool, operator_id: str
) -> None:
    trace: list[str] = []
    broker = _FakeBroker(cancel_outcomes=(), reconcile_outcomes=(), trace=trace)
    coordinator = _coordinator(
        broker=broker,
        children=_FakeChildren(trace),
        journal=_FakeJournal(trace),
        flatten_policy=_flatten_policy(),
    )

    decision = coordinator.evaluate_flatten(
        _flatten_request(human_confirmed=human_confirmed, operator_id=operator_id),
        _position(),
        halt_active=False,
    )

    assert decision.approved_for_oms_review is False
    assert decision.denial_code == CancelPolicyCode.FLATTEN_NOT_ALLOWED.value
    assert decision.dispatch_permitted is False


def test_flatten_without_explicit_policy_is_denied() -> None:
    trace: list[str] = []
    broker = _FakeBroker(cancel_outcomes=(), reconcile_outcomes=(), trace=trace)
    coordinator = _coordinator(
        broker=broker,
        children=_FakeChildren(trace),
        journal=_FakeJournal(trace),
        flatten_policy=None,
    )

    decision = coordinator.evaluate_flatten(_flatten_request(), _position(), halt_active=False)

    assert decision.approved_for_oms_review is False
    assert decision.denial_code == CancelPolicyCode.FLATTEN_POLICY_REQUIRED.value
    assert decision.dispatch_permitted is False


def test_stale_position_denies_flatten_eligibility() -> None:
    trace: list[str] = []
    broker = _FakeBroker(cancel_outcomes=(), reconcile_outcomes=(), trace=trace)
    coordinator = _coordinator(
        broker=broker,
        children=_FakeChildren(trace),
        journal=_FakeJournal(trace),
        flatten_policy=_flatten_policy(),
    )

    decision = coordinator.evaluate_flatten(
        _flatten_request(),
        _position(observed_at_ns=NOW_NS - 60_000_000_001),
        halt_active=False,
    )

    assert decision.denial_code == CancelPolicyCode.POSITION_STALE.value
    assert decision.dispatch_permitted is False


def test_caller_cannot_self_date_stale_position_to_make_it_fresh() -> None:
    old_observed_at_ns = NOW_NS - 120_000_000_000
    trace: list[str] = []
    broker = _FakeBroker(cancel_outcomes=(), reconcile_outcomes=(), trace=trace)
    coordinator = _coordinator(
        broker=broker,
        children=_FakeChildren(trace),
        journal=_FakeJournal(trace),
        flatten_policy=_flatten_policy(),
    )

    decision = coordinator.evaluate_flatten(
        _flatten_request(now_ns=old_observed_at_ns),
        _position(observed_at_ns=old_observed_at_ns),
        halt_active=False,
    )

    assert decision.approved_for_oms_review is False
    assert decision.denial_code == CancelPolicyCode.POSITION_STALE.value
    assert decision.dispatch_permitted is False


def test_flatten_uses_current_injected_clock_for_each_evaluation() -> None:
    old_observed_at_ns = NOW_NS - 30_000_000_000
    clock = _FakeClock(NOW)
    trace: list[str] = []
    broker = _FakeBroker(cancel_outcomes=(), reconcile_outcomes=(), trace=trace)
    coordinator = _coordinator(
        broker=broker,
        children=_FakeChildren(trace),
        journal=_FakeJournal(trace),
        clock=clock,
        flatten_policy=_flatten_policy(),
    )
    request = _flatten_request(now_ns=old_observed_at_ns)
    position = _position(observed_at_ns=old_observed_at_ns)

    fresh = coordinator.evaluate_flatten(request, position, halt_active=False)
    assert fresh.approved_for_oms_review is True
    assert clock.reads == 1

    clock.advance(31)
    stale = coordinator.evaluate_flatten(request, position, halt_active=False)

    assert stale.approved_for_oms_review is False
    assert stale.denial_code == CancelPolicyCode.POSITION_STALE.value
    assert stale.dispatch_permitted is False
    assert clock.reads == 2


def test_approved_flatten_is_policy_only_and_requires_fresh_oms_checks() -> None:
    trace: list[str] = []
    broker = _FakeBroker(cancel_outcomes=(), reconcile_outcomes=(), trace=trace)
    coordinator = _coordinator(
        broker=broker,
        children=_FakeChildren(trace),
        journal=_FakeJournal(trace),
        flatten_policy=_flatten_policy(),
    )

    decision = coordinator.evaluate_flatten(_flatten_request(), _position(), halt_active=False)

    assert decision.approved_for_oms_review is True
    assert decision.denial_code is None
    assert decision.dispatch_permitted is False
    assert decision.requires_fresh_risk_halt_oms_checks is True
    assert broker.cancel_calls == 0


@pytest.mark.asyncio
async def test_fill_racing_cancel_is_retained_while_cancel_remains_unconfirmed() -> None:
    fill = issue_cancel_execution(
        CancelExecutionV1(
            execution_id="execution-race-1",
            venue_order_id="venue-1",
            client_order_id="client-1",
            instrument_id="NQ-202612",
            side="BUY",
            quantity=Decimal("1"),
            price=Decimal("100"),
            executed_at=NOW,
        )
    )
    trace: list[str] = []
    broker = _FakeBroker(
        cancel_outcomes=(TimeoutError(),),
        reconcile_outcomes=(
            _evidence(
                source="RECONCILIATION",
                status="PARTIALLY_FILLED",
                executions=(fill,),
            ),
        ),
        trace=trace,
    )
    journal = _FakeJournal(trace)
    result = await _coordinator(
        broker=broker, children=_FakeChildren(trace), journal=journal
    ).cancel(_request(), halt_active=False)

    assert result.lifecycle_state == "CANCEL_REQUESTED_UNCONFIRMED"
    assert result.oms_state == "UNKNOWN_CANCEL"
    assert result.fill_execution_ids == ("execution-race-1",)
    assert journal.executions == ["execution-race-1"]
    assert broker.cancel_calls == 1


@pytest.mark.parametrize("reconcile_status", ["UNKNOWN_CANCEL", "PARTIALLY_FILLED"])
@pytest.mark.asyncio
async def test_post_gtd_fill_on_nonterminal_reconciliation_is_recorded_and_alerted(
    reconcile_status: str,
) -> None:
    expiry_ns = NOW_NS - 1_000_000
    request = issue_cancel_request(
        CancelRequestV1(
            order_id="order-1",
            client_order_id="client-1",
            venue_order_id="venue-1",
            account_id="paper-account",
            venue="ALPACA",
            environment="paper",
            instrument_id="NQ-202612",
            strategy_id="strategy-1",
            side="BUY",
            operator_id="operator-1",
            idempotency_key=f"cancel-key-{reconcile_status.lower()}",
            scope="ORDER",
            trigger="OPERATOR",
            protective_leg=False,
            gtd_expiry_ns=expiry_ns,
        )
    )
    fill = issue_cancel_execution(
        CancelExecutionV1(
            execution_id=f"execution-after-gtd-{reconcile_status.lower()}",
            venue_order_id="venue-1",
            client_order_id="client-1",
            instrument_id="NQ-202612",
            side="BUY",
            quantity=Decimal("1"),
            price=Decimal("100"),
            executed_at=NOW,
        )
    )
    trace: list[str] = []
    broker = _FakeBroker(
        cancel_outcomes=(BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_CANCEL),),
        reconcile_outcomes=(
            _evidence(
                source="RECONCILIATION",
                status=reconcile_status,
                executions=(fill,),
            ),
        ),
        trace=trace,
    )
    journal = _FakeJournal(trace)

    result = await _coordinator(
        broker=broker, children=_FakeChildren(trace), journal=journal
    ).cancel(request, halt_active=False)

    assert result.lifecycle_state == "CANCEL_REQUESTED_UNCONFIRMED"
    assert result.oms_state == "UNKNOWN_CANCEL"
    assert result.fill_execution_ids == (fill.execution_id,)
    assert result.discrepancy_codes == ("POST_GTD_FILL",)
    assert result.operator_alert_codes == ("POST_GTD_FILL",)
    assert journal.executions == [fill.execution_id]
    assert journal.discrepancies == ["POST_GTD_FILL"]
    assert journal.alerts == ["POST_GTD_FILL"]
    assert trace.index("journal.execution") < trace.index("journal.discrepancy:POST_GTD_FILL")
    assert trace.index("journal.discrepancy:POST_GTD_FILL") < trace.index(
        "journal.alert:POST_GTD_FILL"
    )


@pytest.mark.asyncio
async def test_late_fill_after_gtd_is_retained_and_alerts_operator() -> None:
    expiry_ns = NOW_NS - 1_000_000
    request = issue_cancel_request(
        CancelRequestV1(
            order_id="order-1",
            client_order_id="client-1",
            venue_order_id="venue-1",
            account_id="paper-account",
            venue="ALPACA",
            environment="paper",
            instrument_id="NQ-202612",
            strategy_id="strategy-1",
            side="BUY",
            operator_id="operator-1",
            idempotency_key="cancel-key-gtd",
            scope="ORDER",
            trigger="OPERATOR",
            protective_leg=False,
            gtd_expiry_ns=expiry_ns,
        )
    )
    fill = issue_cancel_execution(
        CancelExecutionV1(
            execution_id="execution-late-1",
            venue_order_id="venue-1",
            client_order_id="client-1",
            instrument_id="NQ-202612",
            side="BUY",
            quantity=Decimal("1"),
            price=Decimal("100"),
            executed_at=NOW,
        )
    )
    trace: list[str] = []
    broker = _FakeBroker(
        cancel_outcomes=(BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_CANCEL),),
        reconcile_outcomes=(
            _evidence(
                source="RECONCILIATION",
                status="CANCELED",
                confirmed=True,
                executions=(fill,),
            ),
        ),
        trace=trace,
    )
    journal = _FakeJournal(trace)
    result = await _coordinator(
        broker=broker, children=_FakeChildren(trace), journal=journal
    ).cancel(request, halt_active=False)

    assert result.lifecycle_state == "CANCELED"
    assert result.fill_execution_ids == ("execution-late-1",)
    assert result.discrepancy_codes == ("POST_GTD_FILL",)
    assert result.operator_alert_codes == ("POST_GTD_FILL",)
    assert journal.executions == ["execution-late-1"]
    assert journal.discrepancies == ["POST_GTD_FILL"]
    assert journal.alerts == ["POST_GTD_FILL"]
    assert broker.cancel_calls == 1
