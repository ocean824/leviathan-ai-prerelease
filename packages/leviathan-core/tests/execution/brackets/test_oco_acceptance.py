"""Independent, adversarial acceptance coverage for the OCO state reducer."""

from __future__ import annotations

import copy
import json
import pickle
from dataclasses import replace
from decimal import ROUND_DOWN, Decimal, localcontext
from pathlib import Path
from typing import Any

import pytest

from leviathan_core.execution.brackets import (
    BracketEventKind,
    BracketEventV1,
    BracketLeg,
    BracketSpecV1,
    BracketValidationError,
    Quarantine,
    RequestCancelChild,
    RequestReconcile,
    RequestSubmitChild,
    initial_bracket_state,
    reduce_bracket,
    replay_bracket,
)

_FIXTURE = Path(__file__).parents[2] / "fixtures" / "brackets" / "base_bracket.json"


def spec(**changes: Any) -> BracketSpecV1:
    raw = json.loads(_FIXTURE.read_text(encoding="utf-8-sig"))
    for key in ("entry_quantity", "take_profit_price", "stop_loss_price", "tick_size", "lot_size"):
        raw[key] = Decimal(raw[key])
    raw.update(changes)
    return BracketSpecV1(**raw)


def event(
    kind: BracketEventKind,
    leg: BracketLeg,
    sequence: int,
    *,
    event_id: str | None = None,
    quantity: Decimal = Decimal(0),
    **changes: Any,
) -> BracketEventV1:
    base = dict(
        event_id=event_id or f"event-{sequence}-{kind.value}-{leg.value}",
        source="synthetic-broker-fixture",
        account_id="account-demo-001",
        environment="paper",
        instrument_id="ES-202612",
        parent_request_digest="sha256:parent-demo-001",
        kind=kind,
        leg=leg,
        local_sequence=sequence,
        broker_event_time_ns=sequence * 100,
        received_time_ns=sequence * 100 + 1,
        quantity=quantity,
        oco_group_id="oco-demo-001",
    )
    base.update(changes)
    return BracketEventV1(**base)


def confirmed_parent_fill(qty: str = "5") -> tuple[Any, tuple[Any, ...]]:
    state = initial_bracket_state(spec())
    return reduce_bracket(
        state,
        event(
            BracketEventKind.FILL,
            BracketLeg.PARENT,
            1,
            quantity=Decimal(qty),
            venue_order_id="parent-order",
            venue_execution_id="parent-exec-1",
        ),
    )


def confirm_child(
    state: Any, leg: BracketLeg, sequence: int, order_id: str
) -> tuple[Any, tuple[Any, ...]]:
    return reduce_bracket(
        state,
        event(
            BracketEventKind.SUBMIT_CONFIRMED,
            leg,
            sequence,
            quantity=Decimal("5"),
            venue_order_id=order_id,
        ),
    )


def test_initial_state_does_not_place_startup_orders() -> None:
    state = initial_bracket_state(spec())

    assert state.parent_executed_quantity == Decimal(0)
    assert state.desired_protective_quantity == Decimal(0)
    assert state.take_profit.active_quantity == Decimal(0)
    assert state.stop_loss.active_quantity == Decimal(0)
    assert state.take_profit.pending_submit_quantity == Decimal(0)
    assert state.stop_loss.pending_submit_quantity == Decimal(0)
    assert state.take_profit.submit_status == "NONE"
    assert state.stop_loss.submit_status == "NONE"


@pytest.mark.parametrize("mode", ["NATIVE", "SYNTHETIC"])
def test_protective_children_never_exceed_confirmed_partial_parent_fill(mode: str) -> None:
    parent_spec = spec(oco_mode=mode)
    state, effects = reduce_bracket(
        initial_bracket_state(parent_spec),
        event(
            BracketEventKind.FILL,
            BracketLeg.PARENT,
            1,
            quantity=Decimal("3"),
            venue_order_id="parent-order",
            venue_execution_id="parent-exec-1",
        ),
    )

    assert state.parent_executed_quantity == Decimal("3")
    assert state.desired_protective_quantity <= state.parent_executed_quantity
    for effect in effects:
        if isinstance(effect, RequestSubmitChild):
            assert effect.quantity <= Decimal("3")


def test_duplicate_fill_callback_is_idempotent_and_emits_no_duplicate_effect() -> None:
    state = initial_bracket_state(spec())
    fill = event(
        BracketEventKind.FILL,
        BracketLeg.PARENT,
        1,
        event_id="duplicate-fill",
        quantity=Decimal("4"),
        venue_order_id="parent-order",
        venue_execution_id="parent-exec-1",
    )
    after_first, first_effects = reduce_bracket(state, fill)
    after_replay, replay_effects = reduce_bracket(after_first, fill)

    assert after_replay == after_first
    assert replay_effects == ()
    submitted = sum(
        (effect.quantity for effect in first_effects if isinstance(effect, RequestSubmitChild)),
        Decimal(0),
    )
    assert submitted <= Decimal("8")


def test_distinct_out_of_order_parent_fills_are_not_lost_or_double_counted() -> None:
    state = initial_bracket_state(spec())
    later = event(
        BracketEventKind.FILL, BracketLeg.PARENT, 2, quantity=Decimal("2"),
        venue_order_id="parent-order", venue_execution_id="parent-exec-2",
    )
    earlier = event(
        BracketEventKind.FILL, BracketLeg.PARENT, 1, quantity=Decimal("3"),
        venue_order_id="parent-order", venue_execution_id="parent-exec-1",
    )
    state, _ = reduce_bracket(state, later)
    state, _ = reduce_bracket(state, earlier)

    assert state.parent_executed_quantity == Decimal("5")
    assert state.desired_protective_quantity <= state.parent_executed_quantity
    assert len(state.events) == 2


def test_consecutive_parent_fills_reserve_protection_per_leg_without_intervening_ack() -> None:
    state = initial_bracket_state(spec())
    first_fill = event(
        BracketEventKind.FILL,
        BracketLeg.PARENT,
        1,
        quantity=Decimal("3"),
        venue_id="VENUE_A",
        venue_order_id="parent-order",
        venue_execution_id="parent-exec-1",
    )
    state, first_effects = reduce_bracket(state, first_fill)
    second_fill = event(
        BracketEventKind.FILL,
        BracketLeg.PARENT,
        2,
        quantity=Decimal("2"),
        venue_id="VENUE_A",
        venue_order_id="parent-order",
        venue_execution_id="parent-exec-2",
    )
    state, second_effects = reduce_bracket(state, second_fill)

    for leg in (BracketLeg.TAKE_PROFIT, BracketLeg.STOP_LOSS):
        proposed = sum(
            (
                effect.quantity
                for effect in (*first_effects, *second_effects)
                if isinstance(effect, RequestSubmitChild) and effect.leg == leg
            ),
            Decimal(0),
        )
        assert proposed <= Decimal("5")
    assert state.parent_executed_quantity == Decimal("5")
    assert state.desired_protective_quantity <= state.parent_executed_quantity
    assert not any(isinstance(effect, RequestSubmitChild) for effect in second_effects) or all(
        effect.quantity <= Decimal("2")
        for effect in second_effects
        if isinstance(effect, RequestSubmitChild)
    )


def test_fill_identity_is_venue_execution_and_cross_feed_duplicate_counts_once() -> None:
    initial = initial_bracket_state(spec())
    first = event(
        BracketEventKind.FILL,
        BracketLeg.PARENT,
        1,
        quantity=Decimal("3"),
        source="feed-one",
        venue_id="VENUE_A",
        venue_order_id="parent-order",
        venue_execution_id="shared-exec",
    )
    duplicate = event(
        BracketEventKind.FILL,
        BracketLeg.PARENT,
        2,
        quantity=Decimal("3"),
        source="feed-two",
        venue_id="VENUE_A",
        venue_order_id="parent-order",
        venue_execution_id="shared-exec",
    )
    state, _ = reduce_bracket(initial, first)
    state, _ = reduce_bracket(state, duplicate)

    assert state.parent_executed_quantity == Decimal("3")
    assert first in state.events
    assert duplicate in state.events


def test_conflicting_same_venue_execution_duplicate_is_a_discrepancy() -> None:
    state = initial_bracket_state(spec())
    first = event(
        BracketEventKind.FILL,
        BracketLeg.PARENT,
        1,
        quantity=Decimal("3"),
        source="feed-one",
        venue_id="VENUE_A",
        venue_order_id="parent-order",
        venue_execution_id="shared-exec",
    )
    conflict = event(
        BracketEventKind.FILL,
        BracketLeg.PARENT,
        2,
        quantity=Decimal("4"),
        source="feed-two",
        venue_id="VENUE_A",
        venue_order_id="parent-order",
        venue_execution_id="shared-exec",
    )
    state, _ = reduce_bracket(state, first)
    state, effects = reduce_bracket(state, conflict)

    assert state.parent_executed_quantity == Decimal("3")
    assert state.discrepancy_codes
    assert state.quarantined
    assert not any(isinstance(effect, RequestSubmitChild) for effect in effects)


def test_cancel_request_is_not_confirmation_and_unknown_preserves_live_quantity() -> None:
    state, _ = confirmed_parent_fill("5")
    state, _ = confirm_child(state, BracketLeg.TAKE_PROFIT, 2, "tp-order")
    state, _ = confirm_child(state, BracketLeg.STOP_LOSS, 3, "sl-order")
    state, effects = reduce_bracket(
        state,
        event(
            BracketEventKind.FILL, BracketLeg.TAKE_PROFIT, 4,
            quantity=Decimal("2"), venue_order_id="tp-order", venue_execution_id="tp-exec-1",
        ),
    )

    cancel = next(e for e in effects if isinstance(e, RequestCancelChild))
    assert cancel.leg == BracketLeg.STOP_LOSS
    assert state.stop_loss.active_quantity == Decimal("5")
    assert state.stop_loss.cancel_status != "CANCEL_CONFIRMED"

    state, timeout_effects = reduce_bracket(
        state,
        event(BracketEventKind.CANCEL_TIMEOUT, BracketLeg.STOP_LOSS, 5, venue_order_id="sl-order"),
    )

    assert state.stop_loss.cancel_status == "CANCEL_REQUESTED_UNCONFIRMED"
    assert state.stop_loss.active_quantity == Decimal("5")
    assert any(isinstance(e, RequestReconcile) for e in timeout_effects)


def test_late_stop_order_confirmation_is_canceled_and_canceling_one_id_is_not_complete() -> None:
    state, _ = confirmed_parent_fill("10")
    state, _ = reduce_bracket(
        state,
        event(
            BracketEventKind.SUBMIT_REQUESTED,
            BracketLeg.STOP_LOSS,
            2,
            quantity=Decimal("5"),
        ),
    )
    state, _ = reduce_bracket(
        state,
        event(
            BracketEventKind.SUBMIT_CONFIRMED,
            BracketLeg.STOP_LOSS,
            3,
            quantity=Decimal("5"),
            venue_order_id="sl-order-A",
        ),
    )
    state, _ = reduce_bracket(
        state,
        event(
            BracketEventKind.SUBMIT_CONFIRMED,
            BracketLeg.TAKE_PROFIT,
            4,
            quantity=Decimal("5"),
            venue_order_id="tp-order-A",
        ),
    )
    state, tp_effects = reduce_bracket(
        state,
        event(
            BracketEventKind.FILL,
            BracketLeg.TAKE_PROFIT,
            5,
            quantity=Decimal("5"),
            venue_order_id="tp-order-A",
            venue_execution_id="tp-exec-A",
        ),
    )
    initial_cancel = next(
        effect for effect in tp_effects if isinstance(effect, RequestCancelChild)
    )
    assert initial_cancel.venue_order_ids == ("sl-order-A",)

    state, _ = reduce_bracket(
        state,
        event(
            BracketEventKind.CANCEL_REQUESTED,
            BracketLeg.STOP_LOSS,
            6,
            venue_order_id="sl-order-A",
        ),
    )
    state, late_confirm_effects = reduce_bracket(
        state,
        event(
            BracketEventKind.SUBMIT_CONFIRMED,
            BracketLeg.STOP_LOSS,
            7,
            quantity=Decimal("5"),
            venue_order_id="sl-order-B",
        ),
    )
    late_cancel = next(
        effect for effect in late_confirm_effects if isinstance(effect, RequestCancelChild)
    )
    assert late_cancel.venue_order_ids == ("sl-order-B",)

    state, _ = reduce_bracket(
        state,
        event(
            BracketEventKind.CANCEL_CONFIRMED,
            BracketLeg.STOP_LOSS,
            8,
            venue_order_id="sl-order-A",
        ),
    )
    assert state.stop_loss.active_quantity == Decimal("5")
    assert set(state.stop_loss.venue_order_ids) == {"sl-order-A", "sl-order-B"}
    assert state.stop_loss.cancelled_order_ids == ("sl-order-A",)
    assert BracketLeg.STOP_LOSS in state.outstanding_cancel_requests
    assert state.status != "COMPLETED"


def test_new_order_confirmed_on_cancel_pending_leg_gets_cancel_for_its_own_id() -> None:
    state, _ = confirmed_parent_fill("10")
    state, _ = confirm_child(state, BracketLeg.STOP_LOSS, 2, "sl-order-A")
    state, _ = reduce_bracket(
        state,
        event(
            BracketEventKind.SUBMIT_REQUESTED,
            BracketLeg.STOP_LOSS,
            3,
            quantity=Decimal("5"),
        ),
    )
    state, _ = confirm_child(state, BracketLeg.TAKE_PROFIT, 4, "tp-order-A")
    state, fill_effects = reduce_bracket(
        state,
        event(
            BracketEventKind.FILL,
            BracketLeg.TAKE_PROFIT,
            5,
            quantity=Decimal("5"),
            venue_order_id="tp-order-A",
            venue_execution_id="tp-exec-cancel-pending",
        ),
    )
    assert state.stop_loss.cancel_status == "CANCEL_PENDING"
    initial_cancel = next(
        effect for effect in fill_effects if isinstance(effect, RequestCancelChild)
    )
    assert initial_cancel.venue_order_ids == ("sl-order-A",)

    state, effects = reduce_bracket(
        state,
        event(
            BracketEventKind.SUBMIT_CONFIRMED,
            BracketLeg.STOP_LOSS,
            6,
            quantity=Decimal("5"),
            venue_order_id="sl-order-B",
        ),
    )

    cancel = next(effect for effect in effects if isinstance(effect, RequestCancelChild))
    assert cancel.leg == BracketLeg.STOP_LOSS
    assert cancel.venue_order_ids == ("sl-order-B",)
    assert "sl-order-B" in state.stop_loss.venue_order_ids


def test_fill_on_outstanding_opposing_order_is_discrepancy_and_quarantines() -> None:
    state, _ = confirmed_parent_fill("5")
    state, _ = confirm_child(state, BracketLeg.TAKE_PROFIT, 2, "tp-order-A")
    state, _ = confirm_child(state, BracketLeg.STOP_LOSS, 3, "sl-order-A")
    state, _ = reduce_bracket(
        state,
        event(
            BracketEventKind.FILL,
            BracketLeg.TAKE_PROFIT,
            4,
            quantity=Decimal("1"),
            venue_order_id="tp-order-A",
            venue_execution_id="tp-exec-outstanding",
        ),
    )
    state, _ = reduce_bracket(
        state,
        event(
            BracketEventKind.CANCEL_REQUESTED,
            BracketLeg.STOP_LOSS,
            5,
            venue_order_id="sl-order-A",
        ),
    )
    state, _ = reduce_bracket(
        state,
        event(
            BracketEventKind.CANCEL_CONFIRMED,
            BracketLeg.STOP_LOSS,
            6,
            venue_order_id="sl-order-A",
        ),
    )

    state, effects = reduce_bracket(
        state,
        event(
            BracketEventKind.FILL,
            BracketLeg.STOP_LOSS,
            7,
            quantity=Decimal("1"),
            venue_order_id="sl-order-A",
            venue_execution_id="sl-exec-outstanding",
        ),
    )

    assert "OPPOSING_FILL_AFTER_TERMINAL" in state.discrepancy_codes
    assert state.quarantined
    assert state.account_blocked
    assert not any(isinstance(effect, RequestSubmitChild) for effect in effects)


def test_submit_timeout_remains_unknown_and_requests_reconciliation() -> None:
    state, effects = confirmed_parent_fill("4")
    assert any(isinstance(e, RequestSubmitChild) for e in effects)

    state, timeout_effects = reduce_bracket(
        state,
        event(
            BracketEventKind.SUBMIT_TIMEOUT,
            BracketLeg.TAKE_PROFIT,
            2,
            quantity=Decimal("4"),
            venue_order_id="tp-order",
        ),
    )

    assert state.take_profit.submit_status == "UNKNOWN_SUBMIT"
    assert state.take_profit.active_quantity == Decimal(0)
    assert any(isinstance(e, RequestReconcile) for e in timeout_effects)


def test_both_legs_racing_or_child_overfill_quarantines_without_unwind_order() -> None:
    state, _ = confirmed_parent_fill("5")
    state, _ = confirm_child(state, BracketLeg.TAKE_PROFIT, 2, "tp-order")
    state, _ = confirm_child(state, BracketLeg.STOP_LOSS, 3, "sl-order")
    state, _ = reduce_bracket(
        state,
        event(
            BracketEventKind.FILL, BracketLeg.TAKE_PROFIT, 4,
            quantity=Decimal("3"), venue_order_id="tp-order", venue_execution_id="tp-exec",
        ),
    )
    state, effects = reduce_bracket(
        state,
        event(
            BracketEventKind.FILL, BracketLeg.STOP_LOSS, 5,
            quantity=Decimal("3"), venue_order_id="sl-order", venue_execution_id="sl-exec",
        ),
    )

    assert state.quarantined
    assert state.discrepancy_codes
    assert not any(isinstance(e, RequestSubmitChild) for e in effects)


def test_fill_corrections_and_busts_are_compensating_not_history_deletion() -> None:
    state, _ = confirmed_parent_fill("5")
    original = state.events[0]
    correction = event(
        BracketEventKind.FILL_CORRECTION,
        BracketLeg.PARENT,
        2,
        event_id="parent-fill-correction",
        quantity=Decimal("3"),
        correction_version=1,
        venue_order_id="parent-order",
        venue_execution_id="parent-exec-1",
    )
    state, _ = reduce_bracket(state, correction)

    assert original in state.events
    assert correction in state.events
    assert state.parent_executed_quantity == Decimal("3")
    assert state.desired_protective_quantity <= Decimal("3")

    bust = event(
        BracketEventKind.FILL_BUST,
        BracketLeg.PARENT,
        3,
        event_id="parent-fill-bust",
        quantity=Decimal(0),
        correction_version=2,
        venue_order_id="parent-order",
        venue_execution_id="parent-exec-1",
    )
    state, _ = reduce_bracket(state, bust)
    assert original in state.events
    assert correction in state.events
    assert bust in state.events
    assert state.parent_executed_quantity == Decimal(0)


def test_amend_uses_compare_and_swap_and_preserves_parent_lineage() -> None:
    state, _ = confirmed_parent_fill("5")
    stale_version = state.version - 1
    before = state
    amend = event(
        BracketEventKind.AMEND_REQUESTED,
        BracketLeg.STOP_LOSS,
        2,
        expected_version=stale_version,
        new_price=Decimal("97.50"),
    )

    after, effects = reduce_bracket(state, amend)

    assert after.version == before.version
    assert after.spec.parent_request_digest == before.spec.parent_request_digest
    assert after.spec.bracket_id == before.spec.bracket_id
    assert not any(isinstance(e, RequestSubmitChild) for e in effects)


def test_amend_replacement_waits_for_confirmed_cancel_of_old_child() -> None:
    state, _ = confirmed_parent_fill("5")
    state, _ = confirm_child(state, BracketLeg.STOP_LOSS, 2, "sl-order-v1")
    amend = event(
        BracketEventKind.AMEND_REQUESTED,
        BracketLeg.STOP_LOSS,
        3,
        expected_version=state.version,
        new_price=Decimal("97.50"),
    )

    state, amend_effects = reduce_bracket(state, amend)

    assert state.spec.parent_request_digest == "sha256:parent-demo-001"
    assert any(isinstance(effect, RequestCancelChild) for effect in amend_effects)
    assert not any(isinstance(effect, RequestSubmitChild) for effect in amend_effects)

    state, replacement_effects = reduce_bracket(
        state,
        event(
            BracketEventKind.CANCEL_CONFIRMED,
            BracketLeg.STOP_LOSS,
            4,
            venue_order_id="sl-order-v1",
        ),
    )

    replacements = [
        effect for effect in replacement_effects if isinstance(effect, RequestSubmitChild)
    ]
    assert replacements
    assert all(effect.price == Decimal("97.50") for effect in replacements)
    assert state.spec.bracket_id == "bracket-demo-001"


def test_atomic_amend_confirmation_is_rejected_without_trusted_capability() -> None:
    state, _ = confirmed_parent_fill("5")
    state, _ = confirm_child(state, BracketLeg.STOP_LOSS, 2, "sl-order-atomic")
    original_price = state.stop_loss.price
    requested_price = Decimal("97.50")
    state, _ = reduce_bracket(
        state,
        event(
            BracketEventKind.AMEND_REQUESTED,
            BracketLeg.STOP_LOSS,
            3,
            expected_version=state.version,
            new_price=requested_price,
        ),
    )

    atomic_event = event(
        BracketEventKind.AMEND_CONFIRMED_ATOMIC,
        BracketLeg.STOP_LOSS,
        4,
        expected_version=state.events[-1].expected_version,
        new_price=requested_price,
    )
    state, effects = reduce_bracket(state, atomic_event)

    assert state.stop_loss.price == original_price
    assert state.stop_loss.pending_amend_price == requested_price
    assert state.discrepancy_codes
    assert not any(isinstance(effect, RequestSubmitChild) for effect in effects)

    with pytest.raises(TypeError):
        event(
            BracketEventKind.AMEND_CONFIRMED_ATOMIC,
            BracketLeg.STOP_LOSS,
            5,
            expected_version=state.events[-2].expected_version,
            new_price=requested_price,
            atomic_amend_proven=True,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("account_id", "other-account"),
        ("environment", "live"),
        ("instrument_id", "OTHER"),
        ("parent_request_digest", "sha256:other-parent"),
        ("oco_group_id", "other-oco"),
    ],
)
def test_foreign_callback_cannot_change_this_bracket(field: str, value: str) -> None:
    state = initial_bracket_state(spec())
    foreign_fill = event(
        BracketEventKind.FILL,
        BracketLeg.PARENT,
        1,
        quantity=Decimal("1"),
        venue_order_id="foreign-order",
        venue_execution_id="foreign-exec",
        **{field: value},
    )

    after, effects = reduce_bracket(state, foreign_fill)

    assert after.parent_executed_quantity == Decimal(0)
    assert after.quarantined or after.discrepancy_codes
    assert not any(isinstance(e, RequestSubmitChild) for e in effects)


def test_late_gtd_fill_is_retained_as_fill_with_discrepancy() -> None:
    bracket = spec(tif="GTD", gtd_time_ns=1_000)
    state = initial_bracket_state(bracket)
    expiry = event(
        BracketEventKind.GTD_EXPIRED,
        BracketLeg.PARENT,
        1,
        broker_event_time_ns=1_000,
        received_time_ns=1_001,
    )
    state, _ = reduce_bracket(state, expiry)
    late_fill = event(
        BracketEventKind.FILL, BracketLeg.PARENT, 2,
        quantity=Decimal("1"),
        broker_event_time_ns=1_001,
        received_time_ns=1_002,
        venue_order_id="parent-order",
        venue_execution_id="late-exec",
    )

    after, effects = reduce_bracket(state, late_fill)

    assert late_fill in after.events
    assert after.parent_executed_quantity == Decimal("1")
    assert after.discrepancy_codes
    assert after.gtd_expired
    assert not after.quarantined or after.discrepancy_codes
    assert all(isinstance(e, (RequestReconcile,)) for e in effects) or effects == ()


def test_gtd_expiry_requires_gtd_tif_and_deadline_has_arrived() -> None:
    day_state = initial_bracket_state(spec(tif="DAY", day_session_close_ns=2_000))
    gtd_event = event(
        BracketEventKind.GTD_EXPIRED,
        BracketLeg.PARENT,
        1,
        broker_event_time_ns=2_000,
        received_time_ns=2_001,
    )
    with pytest.raises(BracketValidationError):
        reduce_bracket(day_state, gtd_event)

    gtd_state = initial_bracket_state(spec(tif="GTD", gtd_time_ns=1_000))
    before_deadline = event(
        BracketEventKind.GTD_EXPIRED,
        BracketLeg.PARENT,
        1,
        broker_event_time_ns=999,
        received_time_ns=1_000,
    )
    with pytest.raises(BracketValidationError):
        reduce_bracket(gtd_state, before_deadline)


def test_day_expiry_requires_day_tif_and_configured_session_close() -> None:
    day_state = initial_bracket_state(spec(tif="DAY", day_session_close_ns=1_000))
    before_close = event(
        BracketEventKind.DAY_EXPIRED,
        BracketLeg.PARENT,
        1,
        broker_event_time_ns=999,
        received_time_ns=1_000,
    )
    with pytest.raises(BracketValidationError):
        reduce_bracket(day_state, before_close)

    at_close = event(
        BracketEventKind.DAY_EXPIRED,
        BracketLeg.PARENT,
        1,
        broker_event_time_ns=1_000,
        received_time_ns=1_001,
    )
    expired, _ = reduce_bracket(day_state, at_close)
    assert expired.day_expired

    gtd_state = initial_bracket_state(spec(tif="GTD", gtd_time_ns=2_000))
    wrong_kind = event(
        BracketEventKind.DAY_EXPIRED,
        BracketLeg.PARENT,
        1,
        broker_event_time_ns=2_000,
        received_time_ns=2_001,
    )
    with pytest.raises(BracketValidationError):
        reduce_bracket(gtd_state, wrong_kind)


def test_failed_close_does_not_clear_local_fill_state() -> None:
    state, _ = confirmed_parent_fill("3")
    failed_close = event(
        BracketEventKind.CLOSE_FAILED,
        BracketLeg.PARENT,
        2,
        quantity=Decimal("3"),
    )

    after, effects = reduce_bracket(state, failed_close)

    assert after.parent_executed_quantity == Decimal("3")
    assert state.events[0] in after.events
    assert failed_close in after.events
    assert after.discrepancy_codes or after.quarantined
    assert not any(isinstance(e, RequestSubmitChild) for e in effects)


def test_replay_duplicate_events_does_not_emit_new_effects() -> None:
    parent = spec()
    fill = event(
        BracketEventKind.FILL,
        BracketLeg.PARENT,
        1,
        event_id="same-fill-event",
        quantity=Decimal("2"),
        venue_order_id="parent-order",
        venue_execution_id="parent-exec-1",
    )

    state, effects = replay_bracket(parent, (fill, fill))

    assert state.parent_executed_quantity == Decimal("2")
    assert effects == ()


def test_public_bracket_records_and_effects_cannot_be_copied_or_pickled() -> None:
    parent_spec = spec()
    parent_event = event(
        BracketEventKind.FILL,
        BracketLeg.PARENT,
        1,
        quantity=Decimal("5"),
        venue_order_id="parent-order",
        venue_execution_id="parent-exec-copy",
    )
    state, submit_effects = reduce_bracket(initial_bracket_state(parent_spec), parent_event)
    state, _ = confirm_child(state, BracketLeg.TAKE_PROFIT, 2, "tp-order-copy")
    state, _ = confirm_child(state, BracketLeg.STOP_LOSS, 3, "sl-order-copy")
    state, cancel_effects = reduce_bracket(
        state,
        event(
            BracketEventKind.FILL,
            BracketLeg.TAKE_PROFIT,
            4,
            quantity=Decimal("2"),
            venue_order_id="tp-order-copy",
            venue_execution_id="tp-exec-copy",
        ),
    )
    _, reconcile_effects = reduce_bracket(
        state,
        event(
            BracketEventKind.CANCEL_TIMEOUT,
            BracketLeg.STOP_LOSS,
            5,
            venue_order_id="sl-order-copy",
        ),
    )
    race_state, _ = confirmed_parent_fill("5")
    race_state, _ = confirm_child(race_state, BracketLeg.TAKE_PROFIT, 2, "tp-race")
    race_state, _ = confirm_child(race_state, BracketLeg.STOP_LOSS, 3, "sl-race")
    race_state, _ = reduce_bracket(
        race_state,
        event(
            BracketEventKind.FILL,
            BracketLeg.TAKE_PROFIT,
            4,
            quantity=Decimal("3"),
            venue_order_id="tp-race",
            venue_execution_id="tp-race-exec",
        ),
    )
    _, quarantine_effects = reduce_bracket(
        race_state,
        event(
            BracketEventKind.FILL,
            BracketLeg.STOP_LOSS,
            5,
            quantity=Decimal("3"),
            venue_order_id="sl-race",
            venue_execution_id="sl-race-exec",
        ),
    )

    effects = (
        next(item for item in submit_effects if isinstance(item, RequestSubmitChild)),
        next(item for item in cancel_effects if isinstance(item, RequestCancelChild)),
        next(item for item in reconcile_effects if isinstance(item, RequestReconcile)),
        next(item for item in quarantine_effects if isinstance(item, Quarantine)),
    )
    records = (
        parent_spec,
        parent_event,
        state,
        state.take_profit,
        *effects,
    )

    for record in records:
        with pytest.raises(BracketValidationError):
            copy.copy(record)
        with pytest.raises(BracketValidationError):
            copy.deepcopy(record)
        with pytest.raises(BracketValidationError):
            pickle.dumps(record)


def test_replace_revalidates_types_decimals_booleans_and_nested_collections() -> None:
    parent_spec = spec()
    fill = event(
        BracketEventKind.FILL,
        BracketLeg.PARENT,
        1,
        quantity=Decimal("1"),
        venue_order_id="parent-order",
        venue_execution_id="parent-exec-replace",
    )
    state, _ = reduce_bracket(initial_bracket_state(parent_spec), fill)

    with pytest.raises(BracketValidationError):
        replace(parent_spec, entry_quantity=1.0)
    with pytest.raises(BracketValidationError):
        replace(parent_spec, entry_quantity=Decimal("1e39"))
    with pytest.raises(BracketValidationError):
        replace(state, quarantined="true")
    with pytest.raises(BracketValidationError):
        replace(state, events=[fill])
    with pytest.raises(BracketValidationError):
        replace(state.take_profit, venue_order_ids=["mutable-order-id"])

    canonical = replace(parent_spec, entry_quantity=Decimal("10.0"))
    assert canonical == parent_spec
    assert canonical is not parent_spec


@pytest.mark.parametrize(
    "value",
    [Decimal("1e39"), Decimal("0." + "1" * 51)],
)
def test_bounded_decimal_inputs_fail_before_arithmetic_without_echo(
    value: Decimal,
) -> None:
    with pytest.raises(BracketValidationError) as error:
        spec(take_profit_price=value)

    assert str(value) not in str(error.value)


def test_three_significant_digits_with_fifty_trailing_zeros_are_accepted() -> None:
    padded_quantity = Decimal("1.23" + "0" * 50)
    padded_price = Decimal("110." + "0" * 50)
    submit = event(
        BracketEventKind.SUBMIT_REQUESTED,
        BracketLeg.TAKE_PROFIT,
        1,
        quantity=padded_quantity,
    )

    assert submit.quantity == Decimal("1.23")
    bracket = spec(take_profit_price=padded_price)
    assert bracket.take_profit_price == Decimal("110")


def test_reduction_is_independent_of_ambient_decimal_context() -> None:
    parent_spec = spec()
    parent_event = event(
        BracketEventKind.FILL,
        BracketLeg.PARENT,
        1,
        quantity=Decimal("2.5"),
        venue_order_id="parent-order",
        venue_execution_id="parent-exec-context",
    )
    initial = initial_bracket_state(parent_spec)
    expected = reduce_bracket(initial, parent_event)

    with localcontext() as context:
        context.prec = 2
        context.rounding = ROUND_DOWN
        context.Emax = 9
        context.Emin = -9
        actual = reduce_bracket(initial, parent_event)

    assert actual == expected


def test_precision_34_inexact_arithmetic_fails_with_typed_input_free_error() -> None:
    state, _ = confirmed_parent_fill("1")
    tiny_fill = event(
        BracketEventKind.FILL,
        BracketLeg.PARENT,
        2,
        quantity=Decimal("1e-34"),
        venue_order_id="parent-order",
        venue_execution_id="parent-exec-tiny",
    )

    with pytest.raises(BracketValidationError) as error:
        reduce_bracket(state, tiny_fill)

    assert str(tiny_fill.quantity) not in str(error.value)

