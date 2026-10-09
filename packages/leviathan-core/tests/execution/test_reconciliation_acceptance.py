"""Contract-level acceptance for the read-only AccountView reconciliation slice."""

from __future__ import annotations

import asyncio
import copy
import pickle
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest

from leviathan_core.execution.broker_port_v1 import (
    AccountViewV1,
    BrokerEnvironment,
    BrokerOutcomeUnknown,
    BrokerUnknownCode,
    BrokerVenue,
    ExecutionV1,
    VenueIdentityV1,
    _issue_account_view,
    _issue_execution,
    _issue_venue_identity,
)
from leviathan_core.execution.order_models import (
    BrokerObservation,
    Fill,
    OrderRequest,
    OrderSnapshot,
    OrderState,
)
from leviathan_core.execution.reconciliation import (
    LocalLedgerEvidenceV1,
    ObservationSource,
    ReconcileError,
    ReconcileStatus,
    RecordedExecutionV1,
    VerificationStatus,
    append_operator_resolution,
    build_broker_snapshot,
    reconcile_account,
    reconcile_once,
    record_operator_resolution,
)
from leviathan_core.seal import SealError, require

NOW = datetime(2026, 10, 5, 12, 0, tzinfo=UTC)
NOW_NS = 1_791_201_600_000_000_000
ACCOUNT = "synthetic-paper-account-001"
CLIENT_ID = "synthetic-client-order-001"
ORDER_ID = "oms-order-1"
NATIVE_ID = "synthetic-venue-order-001"
INSTRUMENT = "ES-202612"
MAX_AGE_NS = 300_000_000_000


def _venue(
    environment: BrokerEnvironment = BrokerEnvironment.PAPER,
    *,
    account_id: str = ACCOUNT,
    venue: BrokerVenue = BrokerVenue.IBKR_TWS,
) -> VenueIdentityV1:
    return _issue_venue_identity(venue, environment, account_id)


def _request(*, tif: str = "DAY", expires_at: datetime | None = None) -> OrderRequest:
    return OrderRequest(
        project_id="leviathan-ai",
        environment="paper",
        account_id=ACCOUNT,
        venue=BrokerVenue.IBKR_TWS.value,
        instrument_id=INSTRUMENT,
        native_contract_id="synthetic-contract-1",
        side="BUY",
        quantity=Decimal("2"),
        order_type="LIMIT",
        time_in_force=tif,
        client_order_id=CLIENT_ID,
        intent_idempotency_key="synthetic-intent-1",
        attempt=1,
        strategy_id="synthetic-strategy",
        risk_policy_digest="a" * 64,
        actor_id="synthetic-operator",
        capability="paper-submit",
        limit_price=Decimal("5000"),
        expires_at=expires_at,
    )


def _order(
    *,
    state: OrderState = OrderState.WORKING,
    venue_order_id: str | None = NATIVE_ID,
    submit_attempted: bool = True,
    cancel_attempted: bool = False,
    tif: str = "DAY",
    expires_at: datetime | None = None,
    filled: Decimal = Decimal(0),
) -> OrderSnapshot:
    return OrderSnapshot(
        order_id=ORDER_ID,
        request=_request(tif=tif, expires_at=expires_at),
        state=state,
        version=4,
        venue_order_id=venue_order_id,
        filled_quantity=filled,
        discrepancies=(),
        submit_attempted=submit_attempted,
        cancel_attempted=cancel_attempted,
    )


def _observation(
    *,
    client_order_id: str = CLIENT_ID,
    venue_order_id: str | None = NATIVE_ID,
    state: OrderState = OrderState.WORKING,
    account_id: str = ACCOUNT,
) -> BrokerObservation:
    return BrokerObservation(
        observation_id="observation-1",
        environment="paper",
        account_id=account_id,
        venue=BrokerVenue.IBKR_TWS.value,
        client_order_id=client_order_id,
        status=state,
        observed_at=NOW,
        venue_order_id=venue_order_id,
        broker_sequence=7,
    )


def _execution(
    execution_id: str = "execution-1",
    *,
    quantity: Decimal = Decimal("1"),
    price: Decimal = Decimal("5000"),
    client_order_id: str | None = CLIENT_ID,
    venue_order_id: str = NATIVE_ID,
    instrument_id: str = INSTRUMENT,
    side: str = "BUY",
    executed_at: datetime = NOW,
) -> ExecutionV1:
    return _issue_execution(
        execution_id,
        venue_order_id,
        client_order_id,
        instrument_id,
        side,
        quantity,
        price,
        executed_at,
    )


def _view(
    *,
    account_id: str = ACCOUNT,
    orders: tuple[BrokerObservation, ...] = (),
    positions: tuple[tuple[str, Decimal], ...] = ((INSTRUMENT, Decimal("1")),),
    executions: tuple[ExecutionV1, ...] = (),
    revision: int = 7,
    executions_since: datetime = NOW - timedelta(minutes=5),
    complete: bool = True,
) -> AccountViewV1:
    return _issue_account_view(
        account_id,
        orders,
        positions,
        revision,
        executions,
        executions_since,
        complete=complete,
    )


def _ledger(
    *,
    environment: BrokerEnvironment = BrokerEnvironment.PAPER,
    account_id: str = ACCOUNT,
    venue: BrokerVenue = BrokerVenue.IBKR_TWS,
    orders: tuple[OrderSnapshot, ...] = (),
    executions: tuple[RecordedExecutionV1, ...] = (),
    positions: tuple[tuple[str, Decimal], ...] = ((INSTRUMENT, Decimal("1")),),
    revision: int = 12,
    previous_broker_revision: int | None = None,
    complete: bool = True,
) -> LocalLedgerEvidenceV1:
    return LocalLedgerEvidenceV1(
        environment=environment,
        account_id=account_id,
        venue=venue,
        orders=orders,
        executions=executions,
        positions=positions,
        ledger_revision=revision,
        previous_broker_revision=previous_broker_revision,
        complete=complete,
    )


def _reconcile(
    view: AccountViewV1,
    ledger: LocalLedgerEvidenceV1,
    *,
    observed_at_ns: int = NOW_NS,
    now_ns: int = NOW_NS,
    expected: VenueIdentityV1 | None = None,
):
    actual = _venue()
    snapshot = build_broker_snapshot(view, actual, observed_at_ns=observed_at_ns)
    return reconcile_account(
        snapshot,
        ledger,
        expected or actual,
        now_ns=now_ns,
        max_age_ns=MAX_AGE_NS,
    )


def _entity(result, kind: str, entity_id: str):
    return next(
        item for item in result.entities if item.kind == kind and item.entity_id == entity_id
    )


def test_matching_account_orders_executions_and_positions_is_exact_and_unblocked() -> None:
    fill = Fill(
        BrokerVenue.IBKR_TWS.value,
        ACCOUNT,
        "execution-1",
        Decimal("1"),
        Decimal("5000"),
        NOW,
    )
    recorded = RecordedExecutionV1(ORDER_ID, fill)
    order = _order(state=OrderState.PARTIALLY_FILLED, filled=Decimal("1"))
    view = _view(
        orders=(_observation(state=OrderState.PARTIALLY_FILLED),),
        executions=(_execution(),),
    )

    result = _reconcile(view, _ledger(orders=(order,), executions=(recorded,)))

    assert result.account_status is ReconcileStatus.MATCHED
    assert result.submission_blocked is False
    assert result.observation_source is ObservationSource.LOCAL_OBSERVED_AT
    assert result.observed_at_ns == NOW_NS
    assert result.balances_status is VerificationStatus.UNVERIFIED
    assert result.session_status is VerificationStatus.UNVERIFIED
    assert result.divergence_codes == ()


def test_lost_submit_ack_is_reconciled_without_resubmitting() -> None:
    local = _order(state=OrderState.UNKNOWN_SUBMIT, venue_order_id=None)
    venue = _venue()
    broker = _SyntheticBroker(venue, _view(orders=(_observation(),)))
    ledger_port = _SyntheticLedgerPort(_ledger(orders=(local,)))
    result = asyncio.run(
        reconcile_once(
            broker,
            ledger_port,
            venue,
            observed_at_ns=NOW_NS,
            now_ns=NOW_NS,
            max_age_ns=MAX_AGE_NS,
        )
    )

    assert result.account_status is ReconcileStatus.MATCHED
    assert result.submission_blocked is False
    assert result.order_updates[0].order_id == ORDER_ID
    assert result.order_updates[0].observed_state is OrderState.WORKING
    assert result.order_updates[0].venue_order_id == NATIVE_ID
    assert broker.submit_calls == broker.cancel_calls == 0
    assert broker.reads == 1
    assert ledger_port.appended == [result]


def test_lost_cancel_ack_never_turns_a_cancel_request_into_confirmation() -> None:
    local = _order(state=OrderState.CANCEL_REQUESTED_UNCONFIRMED, cancel_attempted=True)
    result = _reconcile(
        _view(orders=(_observation(state=OrderState.WORKING),)),
        _ledger(orders=(local,)),
    )

    assert result.account_status is ReconcileStatus.UNKNOWN
    assert result.submission_blocked is True
    assert "CANCEL_OUTCOME_UNKNOWN" in result.divergence_codes
    assert _entity(result, "ORDER", ORDER_ID).status is ReconcileStatus.UNKNOWN


def test_post_gtd_fill_is_retained_and_blocks_with_discrepancy() -> None:
    expiry = NOW - timedelta(seconds=1)
    order = _order(
        state=OrderState.PARTIALLY_FILLED,
        tif="GTD",
        expires_at=expiry,
        filled=Decimal("1"),
    )
    fill = Fill(
        BrokerVenue.IBKR_TWS.value,
        ACCOUNT,
        "late-execution",
        Decimal("1"),
        Decimal("5000"),
        NOW,
    )
    result = _reconcile(
        _view(executions=(_execution("late-execution"),)),
        _ledger(
            orders=(order,),
            executions=(RecordedExecutionV1(ORDER_ID, fill),),
        ),
    )

    assert result.submission_blocked is True
    assert result.account_status is ReconcileStatus.CONFLICT
    assert "POST_GTD_FILL" in result.divergence_codes
    assert any(
        entity.kind == "EXECUTION"
        and entity.entity_id == "late-execution"
        and entity.status is ReconcileStatus.CONFLICT
        for entity in result.entities
    )
    assert result.compensating_events == ()  # the late fill is retained, never erased


def test_replayed_duplicate_callback_is_deterministic_and_counts_execution_once() -> None:
    fill = Fill(
        BrokerVenue.IBKR_TWS.value,
        ACCOUNT,
        "execution-1",
        Decimal("1"),
        Decimal("5000"),
        NOW,
    )
    evidence = _ledger(
        orders=(_order(state=OrderState.PARTIALLY_FILLED, filled=Decimal("1")),),
        executions=(RecordedExecutionV1(ORDER_ID, fill),),
    )
    view = _view(executions=(_execution(),))

    first = _reconcile(view, evidence)
    replay = _reconcile(view, evidence)

    assert replay == first
    assert replay.snapshot_digest == first.snapshot_digest
    assert (
        len(
            [
                entity
                for entity in replay.entities
                if entity.kind == "EXECUTION" and entity.entity_id == "execution-1"
            ]
        )
        == 1
    )
    assert replay.compensating_events == ()


def test_changed_execution_emits_compensating_correction_and_blocks_for_review() -> None:
    fill = Fill(
        BrokerVenue.IBKR_TWS.value,
        ACCOUNT,
        "execution-1",
        Decimal("1"),
        Decimal("5000"),
        NOW,
    )
    result = _reconcile(
        _view(executions=(_execution(quantity=Decimal("2"), price=Decimal("5001")),)),
        _ledger(
            orders=(_order(state=OrderState.PARTIALLY_FILLED, filled=Decimal("1")),),
            executions=(RecordedExecutionV1(ORDER_ID, fill),),
        ),
    )

    assert result.submission_blocked is True
    assert "EXECUTION_CORRECTION" in result.divergence_codes
    assert len(result.compensating_events) == 1
    correction = result.compensating_events[0]
    assert correction.kind == "CORRECTION"
    assert correction.prior_quantity == Decimal("1")
    assert correction.revised_quantity == Decimal("2")
    assert correction.prior_price == Decimal("5000")
    assert correction.revised_price == Decimal("5001")
    assert correction.execution_id == "execution-1"


def test_vanished_execution_in_covered_window_emits_bust_not_deletion() -> None:
    fill = Fill(
        BrokerVenue.IBKR_TWS.value,
        ACCOUNT,
        "execution-1",
        Decimal("1"),
        Decimal("5000"),
        NOW - timedelta(minutes=1),
    )
    result = _reconcile(
        _view(executions_since=NOW - timedelta(minutes=5)),
        _ledger(
            orders=(_order(state=OrderState.PARTIALLY_FILLED, filled=Decimal("1")),),
            executions=(RecordedExecutionV1(ORDER_ID, fill),),
        ),
    )

    assert result.submission_blocked is True
    assert "EXECUTION_BUST" in result.divergence_codes
    assert len(result.compensating_events) == 1
    bust = result.compensating_events[0]
    assert bust.kind == "BUST"
    assert bust.execution_id == "execution-1"
    assert bust.prior_quantity == Decimal("1")
    assert bust.revised_quantity == Decimal(0)


def test_absent_execution_outside_declared_window_is_unknown_not_a_bust() -> None:
    fill = Fill(
        BrokerVenue.IBKR_TWS.value,
        ACCOUNT,
        "older-execution",
        Decimal("1"),
        Decimal("5000"),
        NOW - timedelta(days=1),
    )
    result = _reconcile(
        _view(executions_since=NOW - timedelta(minutes=5)),
        _ledger(
            orders=(_order(state=OrderState.PARTIALLY_FILLED, filled=Decimal("1")),),
            executions=(RecordedExecutionV1(ORDER_ID, fill),),
        ),
    )

    assert result.account_status is ReconcileStatus.UNKNOWN
    assert result.submission_blocked is True
    assert "EXECUTION_OUTSIDE_WINDOW" in result.divergence_codes
    assert result.compensating_events == ()


class _SyntheticBroker:
    def __init__(self, venue: VenueIdentityV1, view: AccountViewV1 | None) -> None:
        self._venue = venue
        self.view = view
        self.reads = 0
        self.submit_calls = 0
        self.cancel_calls = 0

    @property
    def venue(self) -> VenueIdentityV1:
        return self._venue

    def read_account_view(self, account_id: str) -> AccountViewV1:
        self.reads += 1
        if self.view is None:
            raise BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_ACCOUNT_VIEW)
        assert account_id == self._venue.account_id
        return self.view

    def submit(self, *args, **kwargs):
        self.submit_calls += 1
        raise AssertionError("reconciliation must never submit")

    def cancel(self, *args, **kwargs):
        self.cancel_calls += 1
        raise AssertionError("reconciliation must never cancel")


class _SyntheticLedgerPort:
    def __init__(self, ledger: LocalLedgerEvidenceV1) -> None:
        self.ledger = ledger
        self.reads: list[tuple[BrokerEnvironment, str]] = []
        self.appended = []
        self.resolutions = []

    async def account_evidence(self, environment: BrokerEnvironment, account_id: str):
        self.reads.append((environment, account_id))
        return self.ledger

    async def append_reconciliation(self, result, *, expected_ledger_revision: int) -> None:
        assert expected_ledger_revision == self.ledger.ledger_revision
        self.appended.append(result)

    async def append_operator_resolution(self, resolution) -> None:
        self.resolutions.append(resolution)


def test_incomplete_broker_read_is_unknown_and_recorded_without_fabrication() -> None:
    venue = _venue()
    broker = _SyntheticBroker(venue, None)
    ledger_port = _SyntheticLedgerPort(_ledger())

    result = asyncio.run(
        reconcile_once(
            broker,
            ledger_port,
            venue,
            observed_at_ns=NOW_NS,
            now_ns=NOW_NS,
            max_age_ns=MAX_AGE_NS,
        )
    )

    assert result.account_status is ReconcileStatus.UNKNOWN
    assert result.submission_blocked is True
    assert "BROKER_ACCOUNT_VIEW_UNKNOWN" in result.divergence_codes
    assert result.broker_revision is None
    assert result.snapshot_digest is None
    assert result.observation_source is ObservationSource.LOCAL_OBSERVED_AT
    assert broker.reads == 1
    assert broker.submit_calls == broker.cancel_calls == 0
    assert ledger_port.reads == [(BrokerEnvironment.PAPER, ACCOUNT)]
    assert ledger_port.appended == [result]


def test_incomplete_view_cannot_be_forged_as_empty_complete_account_snapshot() -> None:
    with pytest.raises(BrokerOutcomeUnknown) as raised:
        _view(complete=False)
    assert raised.value.code == BrokerUnknownCode.UNKNOWN_ACCOUNT_VIEW.value


def test_port_identity_mismatch_is_unknown_before_account_view_read() -> None:
    expected = _venue()
    actual = _venue(account_id="different-paper-account")
    broker = _SyntheticBroker(actual, _view(account_id=actual.account_id, positions=()))
    ledger_port = _SyntheticLedgerPort(_ledger())

    result = asyncio.run(
        reconcile_once(
            broker,
            ledger_port,
            expected,
            observed_at_ns=NOW_NS,
            now_ns=NOW_NS,
            max_age_ns=MAX_AGE_NS,
        )
    )

    assert result.account_status is ReconcileStatus.UNKNOWN
    assert result.submission_blocked is True
    assert "ACCOUNT_SCOPE_MISMATCH" in result.divergence_codes
    assert result.account_id == expected.account_id
    assert result.observed_account_id == actual.account_id
    assert result.broker_revision is None
    assert broker.reads == 0
    assert broker.submit_calls == broker.cancel_calls == 0


def test_wrong_account_view_from_expected_port_is_blocked_and_keyed_to_expected_account() -> None:
    expected = _venue()
    broker = _SyntheticBroker(
        expected,
        _view(account_id="unexpected-view-account", positions=()),
    )
    ledger_port = _SyntheticLedgerPort(_ledger())

    result = asyncio.run(
        reconcile_once(
            broker,
            ledger_port,
            expected,
            observed_at_ns=NOW_NS,
            now_ns=NOW_NS,
            max_age_ns=MAX_AGE_NS,
        )
    )

    assert result.account_status is ReconcileStatus.UNKNOWN
    assert result.submission_blocked is True
    assert result.account_id == expected.account_id
    assert result.observed_account_id == "unexpected-view-account"
    assert "ACCOUNT_SCOPE_MISMATCH" in result.divergence_codes
    assert broker.reads == 1
    assert ledger_port.appended == [result]
    assert broker.submit_calls == broker.cancel_calls == 0


def test_snapshot_and_expected_environment_or_account_mismatch_blocks() -> None:
    view = _view()
    ledger = _ledger()
    result = _reconcile(view, ledger, expected=_venue(BrokerEnvironment.DEMO))

    assert result.account_status is ReconcileStatus.UNKNOWN
    assert result.submission_blocked is True
    assert "ACCOUNT_SCOPE_MISMATCH" in result.divergence_codes


def test_local_observation_freshness_boundary_is_inclusive_and_never_uses_broker_time() -> None:
    view = _view()
    ledger = _ledger()
    at_boundary = _reconcile(view, ledger, observed_at_ns=NOW_NS - MAX_AGE_NS, now_ns=NOW_NS)
    one_ns_stale = _reconcile(view, ledger, observed_at_ns=NOW_NS - MAX_AGE_NS - 1, now_ns=NOW_NS)

    assert at_boundary.account_status is ReconcileStatus.MATCHED
    assert at_boundary.submission_blocked is False
    assert at_boundary.observation_source is ObservationSource.LOCAL_OBSERVED_AT
    assert at_boundary.observed_at_ns == NOW_NS - MAX_AGE_NS
    assert one_ns_stale.account_status is ReconcileStatus.UNKNOWN
    assert one_ns_stale.submission_blocked is True
    assert "STALE_LOCAL_OBSERVATION" in one_ns_stale.divergence_codes


def test_broker_only_order_is_not_guessed_from_matching_symbol_or_quantity() -> None:
    broker_only = _observation(
        client_order_id="unrecognized-client",
        venue_order_id="unrecognized-native",
    )
    result = _reconcile(_view(orders=(broker_only,)), _ledger(orders=()))

    assert result.account_status is ReconcileStatus.CONFLICT
    assert result.submission_blocked is True
    assert "BROKER_ONLY_ORDER" in result.divergence_codes
    assert _entity(result, "ORDER", "unrecognized-client").status is ReconcileStatus.BROKER_ONLY


def test_exact_position_mismatch_blocks_account() -> None:
    result = _reconcile(
        _view(positions=((INSTRUMENT, Decimal("1.0001")),)),
        _ledger(positions=((INSTRUMENT, Decimal("1")),)),
    )

    assert result.account_status is ReconcileStatus.CONFLICT
    assert result.submission_blocked is True
    assert "POSITION_MISMATCH" in result.divergence_codes
    assert _entity(result, "POSITION", INSTRUMENT).status is ReconcileStatus.CONFLICT


def test_recorded_execution_from_another_venue_cannot_match_this_account_view() -> None:
    other_venue_fill = Fill(
        "MT5",
        ACCOUNT,
        "execution-1",
        Decimal("1"),
        Decimal("5000"),
        NOW,
    )
    evidence = _ledger(
        orders=(_order(state=OrderState.PARTIALLY_FILLED, filled=Decimal("1")),),
        executions=(RecordedExecutionV1(ORDER_ID, other_venue_fill),),
    )

    try:
        result = _reconcile(_view(executions=(_execution(),)), evidence)
    except ReconcileError as error:
        assert error.code == "INVALID_LEDGER_EVIDENCE"
    else:
        assert result.submission_blocked is True
        assert any(
            entity.kind == "EXECUTION"
            and entity.entity_id == "execution-1"
            and entity.status is not ReconcileStatus.MATCHED
            for entity in result.entities
        )


def test_execution_with_conflicting_native_and_client_owners_is_not_attached() -> None:
    view = _view(
        executions=(
            _execution(
                venue_order_id="different-native-order",
                client_order_id=CLIENT_ID,
            ),
        )
    )
    result = _reconcile(
        view,
        _ledger(orders=(_order(state=OrderState.PARTIALLY_FILLED, filled=Decimal("1")),)),
    )

    assert result.submission_blocked is True
    assert "EXECUTION_IDENTITY_CONFLICT" in result.divergence_codes
    assert _entity(result, "EXECUTION", "execution-1").status is ReconcileStatus.CONFLICT


def test_execution_cannot_be_attributed_to_never_dispatched_unidentified_order() -> None:
    never_dispatched_request = replace(
        _request(),
        client_order_id=None,
        intent_idempotency_key="unidentified-never-dispatched-intent",
    )
    never_dispatched = replace(
        _order(
            state=OrderState.CREATED,
            venue_order_id=None,
            submit_attempted=False,
        ),
        order_id="oms-order-b",
        request=never_dispatched_request,
    )
    order_a = _order(
        state=OrderState.PARTIALLY_FILLED,
        venue_order_id=NATIVE_ID,
        filled=Decimal("1"),
    )
    fill_wrongly_linked_to_b = Fill(
        BrokerVenue.IBKR_TWS.value,
        ACCOUNT,
        "execution-a",
        Decimal("1"),
        Decimal("5000"),
        NOW,
    )
    result = _reconcile(
        _view(
            orders=(_observation(state=OrderState.PARTIALLY_FILLED),),
            executions=(_execution("execution-a"),),
        ),
        _ledger(
            orders=(never_dispatched, order_a),
            executions=(RecordedExecutionV1("oms-order-b", fill_wrongly_linked_to_b),),
        ),
    )

    assert result.submission_blocked is True
    assert any(
        entity.kind == "EXECUTION"
        and entity.entity_id == "execution-a"
        and entity.status is not ReconcileStatus.MATCHED
        for entity in result.entities
    )
    assert not any(
        event.order_id == "oms-order-b" and event.kind in {"BUST", "CORRECTION", "NEW_FILL"}
        for event in result.compensating_events
    )


def test_unexplained_partial_order_state_cannot_reconcile_as_matched() -> None:
    result = _reconcile(
        _view(orders=(_observation(state=OrderState.PARTIALLY_FILLED),)),
        _ledger(orders=(_order(state=OrderState.WORKING, filled=Decimal(0)),)),
    )

    assert result.submission_blocked is True
    assert _entity(result, "ORDER", ORDER_ID).status is not ReconcileStatus.MATCHED
    assert any("PARTIAL" in code for code in result.divergence_codes)


def test_missing_native_order_id_cannot_confirm_a_working_order() -> None:
    result = _reconcile(
        _view(orders=(_observation(venue_order_id=None),)),
        _ledger(orders=(_order(state=OrderState.WORKING, venue_order_id=NATIVE_ID),)),
    )

    assert result.submission_blocked is True
    assert _entity(result, "ORDER", ORDER_ID).status is not ReconcileStatus.MATCHED


def test_order_with_nonexistent_parent_lineage_is_rejected_at_reconciliation() -> None:
    orphan_request = replace(_request(), parent_order_id="missing-parent-order")
    orphan = replace(_order(), request=orphan_request)
    result = _reconcile(
        _view(orders=(_observation(),)),
        _ledger(orders=(orphan,)),
    )

    assert result.account_status is ReconcileStatus.UNKNOWN
    assert result.submission_blocked is True
    assert result.account_id == ACCOUNT
    assert "LOCAL_LINEAGE_INVALID" in result.divergence_codes


def test_caller_cannot_expand_maximum_observation_age_beyond_policy_bound() -> None:
    result = _reconcile(
        _view(),
        _ledger(),
        observed_at_ns=NOW_NS - MAX_AGE_NS - 1,
        now_ns=NOW_NS,
    )
    # Requesting a larger freshness window must not make the one-nanosecond-stale
    # observation acceptable. The effective bound remains the policy maximum.
    venue = _venue()
    snapshot = build_broker_snapshot(_view(), venue, observed_at_ns=NOW_NS - MAX_AGE_NS - 1)
    expanded_bound = reconcile_account(
        snapshot,
        _ledger(),
        venue,
        now_ns=NOW_NS,
        max_age_ns=MAX_AGE_NS + 1,
    )

    assert result.account_status is ReconcileStatus.UNKNOWN
    assert result.submission_blocked is True
    assert expanded_bound.account_status is ReconcileStatus.UNKNOWN
    assert expanded_bound.submission_blocked is True
    assert "STALE_LOCAL_OBSERVATION" in expanded_bound.divergence_codes


def test_restart_replay_is_stable_and_never_emits_startup_orders() -> None:
    view = _view()
    evidence = _ledger()
    first = _reconcile(view, evidence)
    # A new adapter/ledger-port pair represents process restart over the same durable evidence.
    broker = _SyntheticBroker(_venue(), view)
    ledger_port = _SyntheticLedgerPort(evidence)
    restarted = asyncio.run(
        reconcile_once(
            broker,
            ledger_port,
            _venue(),
            observed_at_ns=NOW_NS,
            now_ns=NOW_NS,
            max_age_ns=MAX_AGE_NS,
        )
    )

    assert restarted == first
    assert restarted.snapshot_digest == first.snapshot_digest
    assert broker.submit_calls == broker.cancel_calls == 0
    assert broker.reads == 1
    assert len(ledger_port.appended) == 1


def test_as04_close_without_broker_id_or_fill_keeps_position_open_and_blocks() -> None:
    # Synthetic close intent has no broker ID and no fill; absence is not proof of flatness.
    close_order = OrderSnapshot(
        order_id="synthetic-close-order",
        request=replace(
            _request(),
            side="SELL",
            client_order_id="synthetic-close-client",
            intent_idempotency_key="synthetic-close-intent",
        ),
        state=OrderState.UNKNOWN_SUBMIT,
        version=1,
        venue_order_id=None,
        filled_quantity=Decimal(0),
        discrepancies=(),
        submit_attempted=True,
        cancel_attempted=False,
    )
    result = _reconcile(
        _view(positions=((INSTRUMENT, Decimal("1")),)),
        _ledger(orders=(close_order,), positions=((INSTRUMENT, Decimal("1")),)),
    )

    assert result.submission_blocked is True
    assert result.account_status is ReconcileStatus.UNKNOWN
    assert _entity(result, "POSITION", INSTRUMENT).status is ReconcileStatus.MATCHED
    assert not result.compensating_events
    assert not result.order_updates


def test_paper_unverified_balance_and_session_are_explicit_but_nonblocking() -> None:
    result = _reconcile(_view(), _ledger())

    assert result.environment is BrokerEnvironment.PAPER
    assert result.balances_status is VerificationStatus.UNVERIFIED
    assert result.session_status is VerificationStatus.UNVERIFIED
    assert result.submission_blocked is False


def test_live_unverified_balance_and_session_are_blocking() -> None:
    venue = _venue(BrokerEnvironment.LIVE)
    view = _view(positions=())
    snapshot = build_broker_snapshot(view, venue, observed_at_ns=NOW_NS)
    ledger = _ledger(environment=BrokerEnvironment.LIVE, positions=())
    result = reconcile_account(
        snapshot,
        ledger,
        venue,
        now_ns=NOW_NS,
        max_age_ns=MAX_AGE_NS,
    )

    assert result.environment is BrokerEnvironment.LIVE
    assert result.balances_status is VerificationStatus.UNVERIFIED
    assert result.session_status is VerificationStatus.UNVERIFIED
    assert result.submission_blocked is True
    assert {"BALANCES_UNVERIFIED", "SESSION_UNVERIFIED"}.issubset(result.divergence_codes)


def test_operator_resolution_is_sealed_append_only_and_does_not_clear_hold() -> None:
    result = _reconcile(
        _view(positions=((INSTRUMENT, Decimal("2")),)),
        _ledger(positions=((INSTRUMENT, Decimal("1")),)),
    )
    resolution = record_operator_resolution(
        result,
        actor_id="synthetic-operator",
        reason="reviewed-broker-position-evidence",
        evidence_digest="b" * 64,
    )

    assert resolution.result_digest
    assert resolution.actor_id == "synthetic-operator"
    assert resolution.evidence_digest == "b" * 64
    assert result.submission_blocked is True  # recording a decision cannot itself resume trading
    ledger_port = _SyntheticLedgerPort(_ledger())
    appended = asyncio.run(
        append_operator_resolution(
            ledger_port,
            result,
            actor_id="synthetic-operator",
            reason="reviewed-broker-position-evidence",
            evidence_digest="b" * 64,
        )
    )
    assert appended == ledger_port.resolutions[0]
    assert result.submission_blocked is True
    with pytest.raises(ReconcileError) as raised:
        record_operator_resolution(
            result,
            actor_id="synthetic-operator",
            reason="reviewed",
            evidence_digest="sensitive-synthetic-sentinel",
        )
    assert raised.value.code == "INVALID_RESOLUTION_EVIDENCE"
    assert "sensitive-synthetic-sentinel" not in str(raised.value)


def test_issued_snapshot_and_result_reject_forgery_copy_and_serialization() -> None:
    venue = _venue()
    snapshot = build_broker_snapshot(_view(), venue, observed_at_ns=NOW_NS)
    result = reconcile_account(
        snapshot,
        _ledger(),
        venue,
        now_ns=NOW_NS,
        max_age_ns=MAX_AGE_NS,
    )

    for record in (snapshot, result):
        require(record, "execution.reconciliation")
        with pytest.raises(SealError):
            copy.copy(record)
        with pytest.raises(SealError):
            copy.deepcopy(record)
        with pytest.raises(SealError):
            pickle.dumps(record)
        with pytest.raises(TypeError):
            replace(record)
        object.__setattr__(record, "account_id", "tampered-account")
        with pytest.raises(SealError):
            require(record, "execution.reconciliation")
