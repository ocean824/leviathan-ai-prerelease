"""Focused reducer proofs for broker evidence and bounded protective proposals."""

from dataclasses import replace
from decimal import Decimal
from random import Random

import pytest

from leviathan_core.execution.brackets import (
    BracketEventKind as Kind,
)
from leviathan_core.execution.brackets import (
    BracketEventV1,
    BracketSpecV1,
    BracketValidationError,
    Quarantine,
    RequestCancelChild,
    RequestReconcile,
    RequestSubmitChild,
    initial_bracket_state,
    reduce,
)
from leviathan_core.execution.brackets import (
    BracketLeg as Leg,
)


@pytest.fixture
def spec() -> BracketSpecV1:
    return BracketSpecV1(
        bracket_id="b1",
        parent_request_digest="sha256:parent",
        account_id="paper-1",
        environment="paper",
        instrument_id="NQ-202612",
        side="BUY",
        entry_quantity=Decimal("10"),
        take_profit_price=Decimal("110"),
        stop_loss_price=Decimal("90"),
        oco_mode="SYNTHETIC",
        tick_size=Decimal("0.25"),
        lot_size=Decimal("1"),
        tif="GTD",
        gtd_time_ns=1000,
        policy_revision="r1",
    )


def event(
    kind: Kind,
    leg: Leg,
    sequence: int,
    quantity: str = "0",
    *,
    order_id: str | None = None,
    execution_id: str | None = None,
    **changes: object,
) -> BracketEventV1:
    defaults: dict[str, object] = {
        "event_id": f"event-{sequence}",
        "source": "broker-paper",
        "account_id": "paper-1",
        "environment": "paper",
        "instrument_id": "NQ-202612",
        "parent_request_digest": "sha256:parent",
        "kind": kind,
        "leg": leg,
        "local_sequence": sequence,
        "broker_event_time_ns": sequence,
        "received_time_ns": sequence + 1,
        "venue_order_id": order_id,
        "venue_execution_id": execution_id,
        "quantity": Decimal(quantity),
    }
    defaults.update(changes)
    return BracketEventV1(**defaults)  # type: ignore[arg-type]


def test_partial_parent_fill_proposes_only_confirmed_protection(spec: BracketSpecV1) -> None:
    state, effects = reduce(
        initial_bracket_state(spec),
        event(Kind.FILL, Leg.PARENT, 1, "4", order_id="parent", execution_id="parent-fill"),
    )
    submits = [effect for effect in effects if isinstance(effect, RequestSubmitChild)]
    assert len(submits) == 2
    assert {effect.quantity for effect in submits} == {Decimal("4")}
    assert state.desired_protective_quantity == Decimal("4")
    assert state.take_profit.active_quantity == state.stop_loss.active_quantity == Decimal(0)
    assert all(effect.idempotency_key.startswith("b1:") for effect in submits)
    same_state, duplicate_effects = reduce(state, state.events[0])
    assert same_state is state
    assert duplicate_effects == ()


def test_cancel_timeout_keeps_working_sibling_and_requests_reconcile(
    spec: BracketSpecV1,
) -> None:
    state = initial_bracket_state(spec)
    for callback in (
        event(Kind.FILL, Leg.PARENT, 1, "4", order_id="parent", execution_id="p1"),
        event(Kind.SUBMIT_CONFIRMED, Leg.TAKE_PROFIT, 2, "4", order_id="tp-1"),
        event(Kind.SUBMIT_CONFIRMED, Leg.STOP_LOSS, 3, "4", order_id="sl-1"),
    ):
        state, _ = reduce(state, callback)
    state, effects = reduce(
        state,
        event(Kind.FILL, Leg.TAKE_PROFIT, 4, "1", order_id="tp-1", execution_id="tp-f1"),
    )
    assert any(
        isinstance(effect, RequestCancelChild) and effect.leg == Leg.STOP_LOSS for effect in effects
    )
    assert state.outstanding_cancel_requests == (Leg.STOP_LOSS,)
    state, effects = reduce(
        state,
        event(Kind.CANCEL_TIMEOUT, Leg.STOP_LOSS, 5, order_id="sl-1"),
    )
    assert state.stop_loss.active_quantity == Decimal("4")
    assert state.stop_loss.unknown_quantity == Decimal("4")
    assert state.stop_loss.cancel_status == "CANCEL_REQUESTED_UNCONFIRMED"
    assert state.stop_loss.cancel_pending
    assert state.take_profit.dispatchable_quantity == state.stop_loss.dispatchable_quantity == 0
    assert len(effects) == 1 and isinstance(effects[0], RequestReconcile)


def test_correction_and_dual_leg_race_quarantine_without_offset(spec: BracketSpecV1) -> None:
    state = initial_bracket_state(spec)
    for callback in (
        event(Kind.FILL, Leg.PARENT, 1, "4", order_id="parent", execution_id="p1"),
        event(Kind.FILL, Leg.TAKE_PROFIT, 2, "3", order_id="tp-1", execution_id="tp-f1"),
    ):
        state, _ = reduce(state, callback)
    state, effects = reduce(
        state,
        event(Kind.FILL, Leg.STOP_LOSS, 3, "2", order_id="sl-1", execution_id="sl-f1"),
    )
    assert state.quarantined
    assert {"DUAL_LEG_FILL_RACE", "CHILD_OVERFILL"} <= set(state.discrepancy_codes)
    assert state.take_profit.filled_quantity == Decimal("3")
    assert state.stop_loss.filled_quantity == Decimal("2")
    assert any(isinstance(effect, Quarantine) for effect in effects)
    assert not any(isinstance(effect, RequestSubmitChild) for effect in effects)
    state, _ = reduce(
        state,
        event(
            Kind.FILL_CORRECTION,
            Leg.TAKE_PROFIT,
            4,
            "1",
            order_id="tp-1",
            execution_id="tp-f1",
            correction_version=1,
        ),
    )
    assert state.take_profit.filled_quantity == Decimal("1")
    assert state.quarantined  # Both legs still have broker-confirmed fills.


def test_amend_waits_for_cancel_confirmation(spec: BracketSpecV1) -> None:
    state = initial_bracket_state(spec)
    for callback in (
        event(Kind.FILL, Leg.PARENT, 1, "4", order_id="parent", execution_id="p1"),
        event(Kind.SUBMIT_CONFIRMED, Leg.STOP_LOSS, 2, "4", order_id="sl-old"),
    ):
        state, _ = reduce(state, callback)
    state, effects = reduce(
        state,
        event(
            Kind.AMEND_REQUESTED,
            Leg.STOP_LOSS,
            3,
            expected_version=2,
            new_price=Decimal("89.75"),
        ),
    )
    assert state.stop_loss.price == Decimal("90")
    assert state.stop_loss.pending_amend_price == Decimal("89.75")
    assert any(isinstance(effect, RequestCancelChild) for effect in effects)
    assert not any(isinstance(effect, RequestSubmitChild) for effect in effects)
    state, effects = reduce(
        state,
        event(Kind.CANCEL_CONFIRMED, Leg.STOP_LOSS, 4, order_id="sl-old"),
    )
    assert state.stop_loss.price == Decimal("89.75")
    assert "sl-old" in state.stop_loss.cancelled_order_ids
    assert any(
        isinstance(effect, RequestSubmitChild) and effect.price == Decimal("89.75")
        for effect in effects
    )


def test_failed_close_and_late_fill_keep_broker_evidence(spec: BracketSpecV1) -> None:
    state = initial_bracket_state(spec)
    for callback in (
        event(Kind.FILL, Leg.PARENT, 1, "4", order_id="parent", execution_id="p1"),
        event(Kind.SUBMIT_CONFIRMED, Leg.STOP_LOSS, 2, "4", order_id="sl-1"),
    ):
        state, _ = reduce(state, callback)
    state, _ = reduce(state, event(Kind.CLOSE_FAILED, Leg.STOP_LOSS, 3, order_id="sl-1"))
    assert state.stop_loss.active_quantity == Decimal("4")
    assert "FAILED_CLOSE" in state.discrepancy_codes
    late = event(
        Kind.FILL,
        Leg.STOP_LOSS,
        4,
        "1",
        order_id="sl-1",
        execution_id="late",
        broker_event_time_ns=1001,
    )
    state, _ = reduce(state, late)
    assert state.stop_loss.filled_quantity == Decimal("1")
    assert "LATE_CHILD_FILL_AFTER_GTD" in state.discrepancy_codes
    assert state.stop_loss.active_quantity == Decimal("3")


def test_cross_account_callback_quarantines_without_protection(spec: BracketSpecV1) -> None:
    wrong = replace(
        event(Kind.FILL, Leg.PARENT, 1, "10", order_id="parent", execution_id="p1"),
        account_id="other-account",
    )
    state, effects = reduce(initial_bracket_state(spec), wrong)
    assert state.parent_executed_quantity == 0
    assert state.quarantined
    assert "BRACKET_BINDING_MISMATCH" in state.discrepancy_codes
    assert not any(isinstance(effect, RequestSubmitChild) for effect in effects)


def test_decimal_input_rejects_more_than_34_significant_digits(spec: BracketSpecV1) -> None:
    with pytest.raises(BracketValidationError) as error:
        replace(spec, entry_quantity=Decimal("1." + "2" * 34))
    assert error.value.code == "PRECISION_EXCEEDED"
    assert replace(spec, entry_quantity=Decimal("1" + "0" * 34)).entry_quantity == Decimal(
        "1E+34"
    )


def test_inexact_protective_quantity_comparison_is_rejected(spec: BracketSpecV1) -> None:
    maximum = Decimal("9" * 34)
    state = initial_bracket_state(replace(spec, entry_quantity=maximum))
    with pytest.raises(BracketValidationError) as error:
        replace(
            state,
            take_profit=replace(
                state.take_profit,
                active_quantity=maximum,
                filled_quantity=Decimal("2"),
            ),
            parent_executed_quantity=maximum,
            desired_protective_quantity=maximum,
        )
    assert error.value.code == "PRECISION_EXCEEDED"


def test_consecutive_parent_fills_reserve_only_the_new_delta(spec: BracketSpecV1) -> None:
    state = initial_bracket_state(spec)
    proposals: dict[Leg, list[Decimal]] = {Leg.TAKE_PROFIT: [], Leg.STOP_LOSS: []}
    for sequence, quantity in ((1, "3"), (2, "2")):
        state, effects = reduce(
            state,
            event(
                Kind.FILL,
                Leg.PARENT,
                sequence,
                quantity,
                order_id="parent",
                execution_id=f"parent-fill-{sequence}",
            ),
        )
        for effect in effects:
            if isinstance(effect, RequestSubmitChild):
                proposals[effect.leg].append(effect.quantity)
    assert proposals == {
        Leg.TAKE_PROFIT: [Decimal("3"), Decimal("2")],
        Leg.STOP_LOSS: [Decimal("3"), Decimal("2")],
    }
    assert state.take_profit.proposed_pending_quantity == Decimal("5")
    assert state.stop_loss.proposed_pending_quantity == Decimal("5")
    assert not state.quarantined


def test_execution_identity_deduplicates_across_feed_sources(spec: BracketSpecV1) -> None:
    state, _ = reduce(
        initial_bracket_state(spec),
        event(Kind.FILL, Leg.PARENT, 1, "3", order_id="parent", execution_id="fill-1"),
    )
    duplicate = event(
        Kind.FILL,
        Leg.PARENT,
        2,
        "3",
        order_id="parent",
        execution_id="fill-1",
        source="feed-2",
    )
    state, effects = reduce(state, duplicate)
    assert state.parent_executed_quantity == Decimal("3")
    assert state.version == 1
    assert effects == ()
    conflict = replace(duplicate, event_id="conflict", local_sequence=3, quantity=Decimal("4"))
    state, effects = reduce(state, conflict)
    assert state.parent_executed_quantity == Decimal("3")
    assert state.quarantined
    assert "FILL_VERSION_CONFLICT" in state.discrepancy_codes
    assert any(isinstance(effect, Quarantine) for effect in effects)


def test_submit_callbacks_transfer_proposal_reservation(spec: BracketSpecV1) -> None:
    state = initial_bracket_state(spec)
    for sequence, quantity in ((1, "3"), (2, "2")):
        state, _ = reduce(
            state,
            event(
                Kind.FILL,
                Leg.PARENT,
                sequence,
                quantity,
                order_id="parent",
                execution_id=f"p-{sequence}",
            ),
        )
    for sequence, quantity in ((3, "3"), (4, "2")):
        state, _ = reduce(
            state,
            event(
                Kind.SUBMIT_REQUESTED,
                Leg.STOP_LOSS,
                sequence,
                quantity,
                order_id=f"sl-{sequence}",
            ),
        )
    assert state.stop_loss.pending_submit_quantity == Decimal("5")
    assert state.stop_loss.proposed_pending_quantity == 0
    assert not state.quarantined


def test_stale_submit_confirmation_does_not_release_reservation(spec: BracketSpecV1) -> None:
    state = initial_bracket_state(spec)
    for sequence, quantity in ((1, "3"), (2, "2")):
        state, _ = reduce(
            state,
            event(
                Kind.FILL,
                Leg.PARENT,
                sequence,
                quantity,
                order_id="parent",
                execution_id=f"p-{sequence}",
            ),
        )
    state, _ = reduce(
        state, event(Kind.SUBMIT_CONFIRMED, Leg.STOP_LOSS, 3, "3", order_id="sl-1")
    )
    assert state.stop_loss.proposed_pending_quantity == Decimal("2")
    state, _ = reduce(
        state, event(Kind.SUBMIT_CONFIRMED, Leg.STOP_LOSS, 4, "2", order_id="sl-1")
    )
    assert state.stop_loss.active_quantity == Decimal("3")
    assert state.stop_loss.proposed_pending_quantity == Decimal("2")


def test_atomic_amend_claim_cannot_replace_cancel_confirmation(spec: BracketSpecV1) -> None:
    state = initial_bracket_state(spec)
    for callback in (
        event(Kind.FILL, Leg.PARENT, 1, "5", order_id="parent", execution_id="p1"),
        event(Kind.SUBMIT_CONFIRMED, Leg.STOP_LOSS, 2, "5", order_id="sl-old"),
        event(
            Kind.AMEND_REQUESTED,
            Leg.STOP_LOSS,
            3,
            expected_version=2,
            new_price=Decimal("89.75"),
        ),
    ):
        state, _ = reduce(state, callback)
    state, effects = reduce(
        state,
        event(
            Kind.AMEND_CONFIRMED_ATOMIC,
            Leg.STOP_LOSS,
            4,
            expected_version=2,
            new_price=Decimal("89.75"),
        ),
    )
    assert state.stop_loss.price == Decimal("90")
    assert state.stop_loss.pending_amend_price == Decimal("89.75")
    assert "UNPROVEN_ATOMIC_AMEND" in state.discrepancy_codes
    assert not any(isinstance(effect, RequestSubmitChild) for effect in effects)
    state, effects = reduce(
        state, event(Kind.CANCEL_CONFIRMED, Leg.STOP_LOSS, 5, order_id="sl-old")
    )
    assert state.stop_loss.price == Decimal("89.75")
    assert any(isinstance(effect, RequestSubmitChild) for effect in effects)


def test_expiry_kind_and_broker_deadline_must_match_spec(spec: BracketSpecV1) -> None:
    gtd_state = initial_bracket_state(spec)
    day_spec = replace(spec, tif="DAY", gtd_time_ns=None, day_session_close_ns=1000)
    day_state = initial_bracket_state(day_spec)
    for state, callback, code in (
        (gtd_state, event(Kind.GTD_EXPIRED, Leg.PARENT, 1, broker_event_time_ns=999),
         "EXPIRY_BEFORE_DEADLINE"),
        (gtd_state, event(Kind.DAY_EXPIRED, Leg.PARENT, 1, broker_event_time_ns=1000),
         "EXPIRY_TIF_MISMATCH"),
        (day_state, event(Kind.GTD_EXPIRED, Leg.PARENT, 1, broker_event_time_ns=1000),
         "EXPIRY_TIF_MISMATCH"),
        (day_state, event(Kind.DAY_EXPIRED, Leg.PARENT, 1, broker_event_time_ns=999),
         "EXPIRY_BEFORE_DEADLINE"),
    ):
        with pytest.raises(BracketValidationError) as error:
            reduce(state, callback)
        assert error.value.code == code
        assert not state.gtd_expired and not state.day_expired
    expired, _ = reduce(
        day_state, event(Kind.DAY_EXPIRED, Leg.PARENT, 1, broker_event_time_ns=1000)
    )
    assert expired.day_expired


def test_large_exact_lot_fill_survives_reduction(spec: BracketSpecV1) -> None:
    quantity = Decimal("1E+34")
    large_spec = replace(spec, entry_quantity=quantity)
    state, effects = reduce(
        initial_bracket_state(large_spec),
        event(Kind.FILL, Leg.PARENT, 1, "1E+34", order_id="parent", execution_id="p1"),
    )
    assert state.desired_protective_quantity == quantity
    assert {effect.quantity for effect in effects if isinstance(effect, RequestSubmitChild)} == {
        quantity
    }


def test_seeded_order_interleavings_never_complete_with_live_opposition(
    spec: BracketSpecV1,
) -> None:
    random = Random(0x0C0)
    for _ in range(32):
        state = initial_bracket_state(spec)
        sequence = 0
        cancel_proposed: set[tuple[str, str]] = set()

        def observe(
            kind: Kind,
            leg: Leg,
            quantity: str = "0",
            *,
            order_id: str | None = None,
            execution_id: str | None = None,
            cancel_seen: set[tuple[str, str]] = cancel_proposed,
            **changes: object,
        ) -> None:
            nonlocal state, sequence
            sequence += 1
            state, effects = reduce(
                state,
                event(
                    kind,
                    leg,
                    sequence,
                    quantity,
                    order_id=order_id,
                    execution_id=execution_id,
                    **changes,
                ),
            )
            cancel_seen.update(
                (effect.venue_id, effect.venue_order_ids[0])
                for effect in effects
                if isinstance(effect, RequestCancelChild)
                and effect.leg == Leg.STOP_LOSS
            )
            if state.take_profit.filled_quantity > 0:
                live = set(state.stop_loss.live_order_ids)
                assert live <= cancel_seen
                if live or state.stop_loss.proposed_pending_quantity > 0:
                    assert state.status != "COMPLETED"

        observe(Kind.FILL, Leg.PARENT, "10", order_id="parent", execution_id="p1")
        observe(Kind.SUBMIT_CONFIRMED, Leg.TAKE_PROFIT, "5", order_id="tp")
        observe(Kind.SUBMIT_CONFIRMED, Leg.STOP_LOSS, "5", order_id="stop-A")
        submitted_b = random.choice((True, False))
        confirmed_b = random.choice((True, False))
        amended = random.choice((True, False))
        if submitted_b:
            observe(Kind.SUBMIT_REQUESTED, Leg.STOP_LOSS, "5")
        if confirmed_b:
            observe(Kind.SUBMIT_CONFIRMED, Leg.STOP_LOSS, "5", order_id="stop-B")
        if amended:
            observe(
                Kind.AMEND_REQUESTED,
                Leg.STOP_LOSS,
                expected_version=state.version,
                new_price=Decimal("89.75"),
            )
        observe(Kind.FILL, Leg.TAKE_PROFIT, "1", order_id="tp", execution_id="tp-1")
        if not submitted_b and random.choice((True, False)):
            observe(Kind.SUBMIT_REQUESTED, Leg.STOP_LOSS, "5")
        if random.choice((True, False)):
            observe(Kind.CANCEL_CONFIRMED, Leg.STOP_LOSS, order_id="stop-A")
        if not confirmed_b:
            observe(Kind.SUBMIT_CONFIRMED, Leg.STOP_LOSS, "5", order_id="stop-B")
        if not amended and random.choice((True, False)):
            observe(
                Kind.AMEND_REQUESTED,
                Leg.STOP_LOSS,
                expected_version=state.version,
                new_price=Decimal("89.75"),
            )
        if "stop-A" not in state.stop_loss.cancelled_order_ids:
            observe(Kind.CANCEL_CONFIRMED, Leg.STOP_LOSS, order_id="stop-A")
        assert state.status != "COMPLETED"
        observe(Kind.CANCEL_CONFIRMED, Leg.STOP_LOSS, order_id="stop-B")


def test_completion_requires_all_opposing_orders_terminal(spec: BracketSpecV1) -> None:
    state = initial_bracket_state(spec)
    for callback in (
        event(Kind.FILL, Leg.PARENT, 1, "10", order_id="parent", execution_id="p1"),
        event(Kind.SUBMIT_CONFIRMED, Leg.TAKE_PROFIT, 2, "10", order_id="tp"),
        event(Kind.SUBMIT_CONFIRMED, Leg.STOP_LOSS, 3, "5", order_id="stop-A"),
        event(Kind.SUBMIT_CONFIRMED, Leg.STOP_LOSS, 4, "5", order_id="stop-B"),
        event(Kind.FILL, Leg.TAKE_PROFIT, 5, "10", order_id="tp", execution_id="tp-1"),
        event(Kind.CANCEL_CONFIRMED, Leg.STOP_LOSS, 6, order_id="stop-A"),
    ):
        state, _ = reduce(state, callback)
    assert state.status == "CANCEL_PENDING"
    assert state.stop_loss.outstanding_cancel_order_ids == (
        ("VENUE_UNSPECIFIED", "stop-B"),
    )
    state, _ = reduce(state, event(Kind.ORDER_REJECTED, Leg.STOP_LOSS, 7, order_id="stop-B"))
    assert state.status == "COMPLETED"
    state, effects = reduce(
        state,
        event(Kind.SUBMIT_CONFIRMED, Leg.STOP_LOSS, 8, "5", order_id="stop-C"),
    )
    assert state.status == "CANCEL_PENDING"
    assert any(
        isinstance(effect, RequestCancelChild) and effect.venue_order_ids == ("stop-C",)
        for effect in effects
    )
    state, _ = reduce(
        state,
        event(Kind.FILL, Leg.STOP_LOSS, 9, "1", order_id="stop-C", execution_id="sl-1"),
    )
    assert "OPPOSING_FILL_AFTER_TERMINAL" in state.discrepancy_codes
    assert state.status == "BLOCKED" and state.account_blocked
    state, _ = reduce(
        state,
        event(
            Kind.FILL_BUST,
            Leg.STOP_LOSS,
            10,
            order_id="stop-C",
            execution_id="sl-1",
            correction_version=1,
        ),
    )
    assert state.status == "BLOCKED" and state.account_blocked


def test_same_order_number_at_two_venues_needs_two_cancels(spec: BracketSpecV1) -> None:
    state = initial_bracket_state(spec)
    for callback in (
        event(Kind.FILL, Leg.PARENT, 1, "10", order_id="parent", execution_id="p1"),
        event(Kind.SUBMIT_CONFIRMED, Leg.TAKE_PROFIT, 2, "5", order_id="tp"),
        event(Kind.SUBMIT_CONFIRMED, Leg.STOP_LOSS, 3, "5", order_id="same", venue_id="XNAS"),
        event(Kind.SUBMIT_CONFIRMED, Leg.STOP_LOSS, 4, "5", order_id="same", venue_id="XCME"),
    ):
        state, _ = reduce(state, callback)
    state, effects = reduce(
        state,
        event(Kind.FILL, Leg.TAKE_PROFIT, 5, "1", order_id="tp", execution_id="tp-1"),
    )
    cancels = [effect for effect in effects if isinstance(effect, RequestCancelChild)]
    assert {(effect.venue_id, effect.venue_order_ids) for effect in cancels} == {
        ("XNAS", ("same",)),
        ("XCME", ("same",)),
    }
    assert len({effect.idempotency_key for effect in cancels}) == 2
    assert len(state.stop_loss.live_order_ids) == 2


def test_cancel_obligation_survives_earlier_order_terminal(spec: BracketSpecV1) -> None:
    state = initial_bracket_state(spec)
    for callback in (
        event(Kind.FILL, Leg.PARENT, 1, "5", order_id="parent", execution_id="p1"),
        event(Kind.SUBMIT_CONFIRMED, Leg.STOP_LOSS, 2, "3", order_id="stop-A"),
        event(Kind.CANCEL_REQUESTED, Leg.STOP_LOSS, 3, order_id="stop-A"),
    ):
        state, _ = reduce(state, callback)
    state, effects = reduce(
        state, event(Kind.SUBMIT_CONFIRMED, Leg.STOP_LOSS, 4, "2", order_id="stop-B")
    )
    assert any(
        isinstance(effect, RequestCancelChild) and effect.venue_order_ids == ("stop-B",)
        for effect in effects
    )
    state, _ = reduce(state, event(Kind.CANCEL_CONFIRMED, Leg.STOP_LOSS, 5, order_id="stop-A"))
    assert state.status == "CANCEL_PENDING"
    assert state.stop_loss.outstanding_cancel_order_ids == (
        ("VENUE_UNSPECIFIED", "stop-B"),
    )
    state, _ = reduce(state, event(Kind.CANCEL_CONFIRMED, Leg.STOP_LOSS, 6, order_id="stop-B"))
    assert state.stop_loss.outstanding_cancel_order_ids == ()
    assert state.stop_loss.cancel_status == "CANCELED"
    state, effects = reduce(
        state, event(Kind.SUBMIT_CONFIRMED, Leg.STOP_LOSS, 7, "2", order_id="stop-C")
    )
    assert any(
        isinstance(effect, RequestCancelChild) and effect.venue_order_ids == ("stop-C",)
        for effect in effects
    )
