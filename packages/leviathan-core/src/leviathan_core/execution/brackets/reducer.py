"""Pure bracket/OCO reduction; returned effects are proposals, never broker actions."""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from decimal import Decimal, DecimalException, Inexact, Rounded, localcontext
from hashlib import sha256

from .models import (
    ZERO,
    BracketEffect,
    BracketEventKind,
    BracketEventV1,
    BracketLeg,
    BracketSpecV1,
    BracketStateV1,
    BracketValidationError,
    ChildStateV1,
    Quarantine,
    RequestCancelChild,
    RequestReconcile,
    RequestSubmitChild,
    _kernel_decimal_context,
)

CHILD_LEGS = (BracketLeg.TAKE_PROFIT, BracketLeg.STOP_LOSS)
ADVISORY_CODES = frozenset(
    {
        "LATE_PARENT_FILL_AFTER_GTD",
        "LATE_CHILD_FILL_AFTER_GTD",
        "LATE_PARENT_FILL_AFTER_DAY",
        "LATE_CHILD_FILL_AFTER_DAY",
        "UNPROVEN_ATOMIC_AMEND",
    }
)


@dataclass
class _Order:
    requested: Decimal = ZERO
    confirmed: Decimal = ZERO
    terminal_status: str = "NONE"
    submit_unknown: bool = False
    cancel_pending: bool = False
    cancel_unknown: bool = False


@dataclass
class _Child:
    price: Decimal
    orders: dict[tuple[str, str], _Order] = field(default_factory=dict)
    cancel_mode: bool = False
    pending_amend_price: Decimal | None = None
    pending_amend_base_version: int | None = None


def initial_bracket_state(spec: BracketSpecV1) -> BracketStateV1:
    """Build a zero-exposure state bound to one immutable bracket specification."""
    if type(spec) is not BracketSpecV1:
        raise BracketValidationError("INVALID_SPEC")
    return BracketStateV1(
        spec=spec,
        take_profit=ChildStateV1(BracketLeg.TAKE_PROFIT, spec.take_profit_price),
        stop_loss=ChildStateV1(BracketLeg.STOP_LOSS, spec.stop_loss_price),
        oco_linkage=spec.oco_group_id or f"{spec.bracket_id}:oco",
    )


def _key(spec: BracketSpecV1, leg: BracketLeg, version: int, action: str) -> str:
    return f"{spec.bracket_id}:{leg.value}:{version}:{action}"


def _cancel_key(
    spec: BracketSpecV1, leg: BracketLeg, identity: tuple[str, str], version: int
) -> str:
    payload = json.dumps(
        {
            "action": "cancel",
            "bracket_id": spec.bracket_id,
            "leg": leg.value,
            "venue_id": identity[0],
            "venue_order_id": identity[1],
            "version": version,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return "oco:" + sha256(payload.encode("ascii")).hexdigest()


def _floor_to_lot(quantity: Decimal, lot_size: Decimal) -> Decimal:
    quantity_num, quantity_den = quantity.as_integer_ratio()
    lot_num, lot_den = lot_size.as_integer_ratio()
    lots = (quantity_num * lot_den) // (quantity_den * lot_num)
    if lots == 0:
        return ZERO
    lot_parts = lot_size.as_tuple()
    assert isinstance(lot_parts.exponent, int)
    coefficient = lots * int("".join(str(digit) for digit in lot_parts.digits))
    exponent = lot_parts.exponent
    while coefficient % 10 == 0:
        coefficient //= 10
        exponent += 1
    return Decimal((0, tuple(int(digit) for digit in str(coefficient)), exponent))


def _rebuild(spec: BracketSpecV1, events: tuple[BracketEventV1, ...]) -> BracketStateV1:
    try:
        with localcontext(_kernel_decimal_context()):
            return _rebuild_in_context(spec, events)
    except (Inexact, Rounded):
        raise BracketValidationError("PRECISION_EXCEEDED") from None
    except DecimalException:
        raise BracketValidationError("DECIMAL_ARITHMETIC_INVALID") from None


def _rebuild_in_context(spec: BracketSpecV1, events: tuple[BracketEventV1, ...]) -> BracketStateV1:
    children = {
        BracketLeg.TAKE_PROFIT: _Child(spec.take_profit_price),
        BracketLeg.STOP_LOSS: _Child(spec.stop_loss_price),
    }
    # Values are (correction version, quantity, venue order ID, original event).
    fills: dict[tuple[str, str], tuple[int, Decimal, str, BracketEventV1]] = {}
    seen_events: dict[str, BracketEventV1] = {}
    seen_sequences: dict[int, str] = {}
    discrepancies: set[str] = set()
    kill_active = False
    gtd_expired = False
    day_expired = False
    opposing_fill_seen = False
    accepted = 0

    for event in sorted(events, key=lambda item: (item.local_sequence, item.event_id)):
        old = seen_events.get(event.event_id)
        if old is not None:
            if old != event:
                discrepancies.add("EVENT_ID_CONFLICT")
            continue
        seen_events[event.event_id] = event
        old_sequence = seen_sequences.get(event.local_sequence)
        if old_sequence is not None and old_sequence != event.event_id:
            discrepancies.add("LOCAL_SEQUENCE_CONFLICT")
            continue
        seen_sequences[event.local_sequence] = event.event_id
        if (
            event.account_id != spec.account_id
            or event.environment != spec.environment
            or event.instrument_id != spec.instrument_id
            or event.parent_request_digest != spec.parent_request_digest
            or (
                event.oco_group_id is not None
                and event.oco_group_id != (spec.oco_group_id or f"{spec.bracket_id}:oco")
            )
        ):
            discrepancies.add("BRACKET_BINDING_MISMATCH")
            continue
        prior_version = accepted
        accepted += 1

        if event.kind == BracketEventKind.KILL_ACTIVATED:
            kill_active = True
            continue
        if event.kind == BracketEventKind.GTD_EXPIRED:
            gtd_expired = True
            continue
        if event.kind == BracketEventKind.DAY_EXPIRED:
            day_expired = True
            continue
        if event.kind == BracketEventKind.CLOSE_FAILED:
            discrepancies.add("FAILED_CLOSE")
            continue

        if event.kind in {
            BracketEventKind.FILL,
            BracketEventKind.FILL_CORRECTION,
            BracketEventKind.FILL_BUST,
        }:
            assert event.venue_execution_id is not None
            assert event.venue_order_id is not None
            fill_key = (event.venue_id, event.venue_execution_id)
            prior = fills.get(fill_key)
            if prior is None:
                if event.kind != BracketEventKind.FILL or event.correction_version != 0:
                    discrepancies.add("ORPHAN_FILL_CORRECTION")
                    continue
            elif event.leg != prior[3].leg:
                discrepancies.add("EXECUTION_ID_LEG_CONFLICT")
                continue
            elif event.venue_order_id != prior[2]:
                discrepancies.add("FILL_ID_ORDER_CONFLICT")
                continue
            elif event.correction_version < prior[0]:
                accepted -= 1
                continue
            elif event.correction_version == prior[0]:
                if (event.quantity, event.venue_order_id, event.kind) != (
                    prior[1],
                    prior[2],
                    prior[3].kind,
                ):
                    discrepancies.add("FILL_VERSION_CONFLICT")
                else:
                    accepted -= 1
                continue
            elif event.kind == BracketEventKind.FILL:
                discrepancies.add("FILL_VERSION_CONFLICT")
                continue
            elif event.venue_order_id != prior[2]:
                discrepancies.add("FILL_ID_ORDER_CONFLICT")
                continue
            if event.kind == BracketEventKind.FILL_BUST:
                fills[fill_key] = (event.correction_version, ZERO, event.venue_order_id, event)
            else:
                fills[fill_key] = (
                    event.correction_version,
                    event.quantity,
                    event.venue_order_id,
                    event,
                )
            if any(
                entry[3].leg == BracketLeg.TAKE_PROFIT and entry[1] > ZERO
                for entry in fills.values()
            ) and any(
                entry[3].leg == BracketLeg.STOP_LOSS and entry[1] > ZERO
                for entry in fills.values()
            ):
                opposing_fill_seen = True
            late_gtd = (
                spec.tif == "GTD"
                and spec.gtd_time_ns is not None
                and event.broker_event_time_ns > spec.gtd_time_ns
            )
            late_day = (
                spec.tif == "DAY"
                and spec.day_session_close_ns is not None
                and event.broker_event_time_ns > spec.day_session_close_ns
            )
            if event.leg != BracketLeg.PARENT and late_gtd:
                discrepancies.add("LATE_CHILD_FILL_AFTER_GTD")
            if event.leg == BracketLeg.PARENT and late_gtd:
                discrepancies.add("LATE_PARENT_FILL_AFTER_GTD")
            if event.leg != BracketLeg.PARENT and late_day:
                discrepancies.add("LATE_CHILD_FILL_AFTER_DAY")
            if event.leg == BracketLeg.PARENT and late_day:
                discrepancies.add("LATE_PARENT_FILL_AFTER_DAY")
            continue

        if event.leg == BracketLeg.PARENT:
            discrepancies.add("INVALID_PARENT_EVENT")
            continue
        child = children[event.leg]
        order_id = event.venue_order_id or "<unbound>"
        identity = (event.venue_id, order_id)
        order = child.orders.setdefault(identity, _Order())

        if event.kind == BracketEventKind.SUBMIT_REQUESTED:
            if order.requested > ZERO or order.confirmed > ZERO:
                discrepancies.add("DUPLICATE_SUBMIT_REQUEST")
                continue
            order.requested = event.quantity
        elif event.kind in {BracketEventKind.SUBMIT_UNKNOWN, BracketEventKind.SUBMIT_TIMEOUT}:
            order.requested = max(order.requested, event.quantity)
            order.submit_unknown = True
        elif event.kind == BracketEventKind.SUBMIT_CONFIRMED:
            if event.venue_order_id is None:
                discrepancies.add("UNBOUND_SUBMIT_CONFIRMATION")
                continue
            if order.terminal_status != "NONE":
                discrepancies.add("ORDER_RECONFIRMED_AFTER_TERMINAL")
                order.terminal_status = "NONE"
            order.confirmed = max(order.confirmed, event.quantity)
            order.requested = ZERO
            order.submit_unknown = False
            # A request can precede the broker-assigned venue ID.
            unbound = (event.venue_id, "<unbound>")
            if order_id != "<unbound>" and unbound in child.orders:
                del child.orders[unbound]
        elif event.kind == BracketEventKind.CANCEL_REQUESTED:
            order.cancel_pending = True
            if child.pending_amend_price is None:
                child.cancel_mode = True
        elif event.kind in {BracketEventKind.CANCEL_UNKNOWN, BracketEventKind.CANCEL_TIMEOUT}:
            order.cancel_pending = True
            order.cancel_unknown = True
            if child.pending_amend_price is None:
                child.cancel_mode = True
        elif event.kind == BracketEventKind.CANCEL_CONFIRMED:
            if event.venue_order_id is None:
                discrepancies.add("UNBOUND_CANCEL_CONFIRMATION")
                continue
            order.terminal_status = "CANCELED"
            order.cancel_pending = False
            order.cancel_unknown = False
            order.submit_unknown = False
            order.requested = ZERO
            if child.pending_amend_price is None:
                child.cancel_mode = True
        elif event.kind in {BracketEventKind.ORDER_REJECTED, BracketEventKind.ORDER_EXPIRED}:
            if event.venue_order_id is None:
                discrepancies.add("UNBOUND_TERMINAL_CONFIRMATION")
                continue
            order.terminal_status = (
                "REJECTED"
                if event.kind == BracketEventKind.ORDER_REJECTED
                else "EXPIRED"
            )
            order.cancel_pending = False
            order.cancel_unknown = False
            order.submit_unknown = False
            order.requested = ZERO
        elif event.kind == BracketEventKind.AMEND_REQUESTED:
            if event.expected_version != prior_version:
                discrepancies.add("AMEND_VERSION_CONFLICT")
                accepted -= 1
            elif child.pending_amend_price is not None:
                discrepancies.add("CONCURRENT_AMEND_CONFLICT")
                accepted -= 1
            else:
                child.pending_amend_price = event.new_price
                child.pending_amend_base_version = event.expected_version
        elif event.kind == BracketEventKind.AMEND_CONFIRMED_ATOMIC:
            # This pure kernel has no trusted venue-capability issuer.
            discrepancies.add("UNPROVEN_ATOMIC_AMEND")
            accepted -= 1

    def filled(leg: BracketLeg) -> Decimal:
        return sum((entry[1] for entry in fills.values() if entry[3].leg == leg), ZERO)

    parent_filled = filled(BracketLeg.PARENT)
    tp_filled = filled(BracketLeg.TAKE_PROFIT)
    sl_filled = filled(BracketLeg.STOP_LOSS)
    if parent_filled > spec.entry_quantity:
        discrepancies.add("PARENT_OVERFILL")
    if tp_filled > ZERO and sl_filled > ZERO:
        discrepancies.add("DUAL_LEG_FILL_RACE")
    if opposing_fill_seen:
        discrepancies.add("OPPOSING_FILL_AFTER_TERMINAL")
    if tp_filled + sl_filled > parent_filled:
        discrepancies.add("CHILD_OVERFILL")
    desired = max(ZERO, min(spec.entry_quantity, parent_filled - tp_filled - sl_filled))
    # Integer ratios avoid Decimal remainder's precision-dependent failure.
    desired = _floor_to_lot(desired, spec.lot_size)
    linkage = spec.oco_group_id or f"{spec.bracket_id}:oco"

    for leg, child in children.items():
        if child.pending_amend_price is None:
            continue
        remaining = ZERO
        for identity, order in child.orders.items():
            order_filled = sum(
                (
                    entry[1]
                    for entry in fills.values()
                    if entry[3].leg == leg
                    and (entry[3].venue_id, entry[2]) == identity
                ),
                ZERO,
            )
            if order.terminal_status == "NONE":
                remaining += max(ZERO, order.confirmed - order_filled) + order.requested
        if remaining == ZERO:
            child.price = child.pending_amend_price
            child.pending_amend_price = None
            child.pending_amend_base_version = None

    def child_state(leg: BracketLeg) -> ChildStateV1:
        child = children[leg]
        active = ZERO
        unknown = ZERO
        pending = ZERO
        order_ids: list[str] = []
        cancelled_ids: list[str] = []
        live_ids: list[tuple[str, str]] = []
        pending_ids: list[tuple[str, str]] = []
        terminal_ids: list[tuple[str, str]] = []
        cancel_pending = False
        cancel_unknown = False
        submit_unknown = False
        for identity, order in child.orders.items():
            _, order_id = identity
            if order_id != "<unbound>":
                order_ids.append(order_id)
            order_filled = sum(
                (
                    entry[1]
                    for entry in fills.values()
                    if entry[3].leg == leg
                    and (entry[3].venue_id, entry[2]) == identity
                ),
                ZERO,
            )
            terminal = order.terminal_status != "NONE"
            working = ZERO if terminal else max(ZERO, order.confirmed - order_filled)
            active += working
            if order.terminal_status == "CANCELED":
                cancelled_ids.append(order_id)
            if order_id != "<unbound>" and (
                terminal or (order.confirmed > ZERO and working == ZERO and order_filled > ZERO)
            ):
                terminal_ids.append(identity)
            if order.requested > ZERO and order.confirmed == ZERO and not terminal:
                pending += order.requested
                if order_id != "<unbound>":
                    pending_ids.append(identity)
            if order_id != "<unbound>" and not terminal and (
                working > ZERO or order.requested > ZERO or order.cancel_pending
            ):
                live_ids.append(identity)
            if order.submit_unknown:
                unknown += order.requested
                submit_unknown = True
            if order.cancel_unknown:
                unknown += working
                cancel_unknown = True
            cancel_pending |= order.cancel_pending
        leg_filled = filled(leg)
        if active + leg_filled > parent_filled:
            discrepancies.add(f"{leg.value}_EXPOSURE_EXCEEDS_PARENT")
        if active + pending + leg_filled > parent_filled:
            discrepancies.add(f"{leg.value}_PENDING_EXCEEDS_PARENT")
        dispatchable = max(ZERO, desired - active - pending)
        if (
            kill_active
            or gtd_expired
            or day_expired
            or cancel_pending
            or unknown > ZERO
            or child.pending_amend_price is not None
        ):
            dispatchable = ZERO
        return ChildStateV1(
            leg=leg,
            price=child.price,
            active_quantity=active,
            filled_quantity=leg_filled,
            unknown_quantity=unknown,
            submitted_pending=pending > ZERO,
            cancel_pending=cancel_pending,
            cancel_status=(
                "CANCEL_REQUESTED_UNCONFIRMED"
                if cancel_unknown
                else "CANCEL_PENDING"
                if cancel_pending
                else "NONE"
            ),
            submit_status=(
                "UNKNOWN_SUBMIT"
                if submit_unknown
                else "SUBMIT_PENDING"
                if pending > ZERO
                else "NONE"
            ),
            pending_submit_quantity=pending,
            venue_order_ids=tuple(sorted(set(order_ids))),
            cancelled_order_ids=tuple(sorted(set(cancelled_ids))),
            live_order_ids=tuple(sorted(live_ids)),
            pending_order_ids=tuple(sorted(pending_ids)),
            terminal_order_ids=tuple(sorted(terminal_ids)),
            pending_amend_price=child.pending_amend_price,
            dispatchable_quantity=dispatchable,
        )

    tp = child_state(BracketLeg.TAKE_PROFIT)
    sl = child_state(BracketLeg.STOP_LOSS)
    cancel_ids: dict[BracketLeg, set[tuple[str, str]]] = {
        BracketLeg.TAKE_PROFIT: set(),
        BracketLeg.STOP_LOSS: set(),
    }
    if tp_filled > ZERO:
        cancel_ids[BracketLeg.STOP_LOSS].update(sl.live_order_ids)
    if sl_filled > ZERO:
        cancel_ids[BracketLeg.TAKE_PROFIT].update(tp.live_order_ids)
    if tp.cancel_pending:
        cancel_ids[BracketLeg.TAKE_PROFIT].update(tp.live_order_ids)
    if sl.cancel_pending:
        cancel_ids[BracketLeg.STOP_LOSS].update(sl.live_order_ids)
    if children[BracketLeg.TAKE_PROFIT].cancel_mode:
        cancel_ids[BracketLeg.TAKE_PROFIT].update(tp.live_order_ids)
    if children[BracketLeg.STOP_LOSS].cancel_mode:
        cancel_ids[BracketLeg.STOP_LOSS].update(sl.live_order_ids)
    for leg, child in children.items():
        if child.pending_amend_price is not None:
            state = tp if leg == BracketLeg.TAKE_PROFIT else sl
            cancel_ids[leg].update(state.live_order_ids)
    tp = replace(
        tp,
        outstanding_cancel_order_ids=tuple(sorted(cancel_ids[BracketLeg.TAKE_PROFIT])),
        cancel_pending=tp.cancel_pending or bool(cancel_ids[BracketLeg.TAKE_PROFIT]),
        cancel_status=(
            tp.cancel_status
            if tp.cancel_status == "CANCEL_REQUESTED_UNCONFIRMED"
            else "CANCEL_PENDING"
            if cancel_ids[BracketLeg.TAKE_PROFIT]
            else "CANCELED"
            if (sl_filled > ZERO or children[BracketLeg.TAKE_PROFIT].cancel_mode)
            and not tp.submitted_pending
            and tp.unknown_quantity == ZERO
            else tp.cancel_status
        ),
    )
    sl = replace(
        sl,
        outstanding_cancel_order_ids=tuple(sorted(cancel_ids[BracketLeg.STOP_LOSS])),
        cancel_pending=sl.cancel_pending or bool(cancel_ids[BracketLeg.STOP_LOSS]),
        cancel_status=(
            sl.cancel_status
            if sl.cancel_status == "CANCEL_REQUESTED_UNCONFIRMED"
            else "CANCEL_PENDING"
            if cancel_ids[BracketLeg.STOP_LOSS]
            else "CANCELED"
            if (tp_filled > ZERO or children[BracketLeg.STOP_LOSS].cancel_mode)
            and not sl.submitted_pending
            and sl.unknown_quantity == ZERO
            else sl.cancel_status
        ),
    )
    if children[BracketLeg.TAKE_PROFIT].cancel_mode and (
        tp.submitted_pending or tp.unknown_quantity > ZERO
    ) and tp.cancel_status == "NONE":
        tp = replace(tp, cancel_pending=True, cancel_status="CANCEL_PENDING")
    if children[BracketLeg.STOP_LOSS].cancel_mode and (
        sl.submitted_pending or sl.unknown_quantity > ZERO
    ) and sl.cancel_status == "NONE":
        sl = replace(sl, cancel_pending=True, cancel_status="CANCEL_PENDING")
    outstanding = {
        leg for leg in CHILD_LEGS if cancel_ids[leg]
    }
    if (
        outstanding
        or tp.cancel_pending
        or sl.cancel_pending
        or tp.submitted_pending
        or sl.submitted_pending
        or tp.unknown_quantity > ZERO
        or sl.unknown_quantity > ZERO
    ):
        tp = replace(tp, dispatchable_quantity=ZERO)
        sl = replace(sl, dispatchable_quantity=ZERO)
    if discrepancies - {"UNPROVEN_ATOMIC_AMEND"}:
        tp = replace(tp, dispatchable_quantity=ZERO)
        sl = replace(sl, dispatchable_quantity=ZERO)
    account_blocked = "OPPOSING_FILL_AFTER_TERMINAL" in discrepancies
    if account_blocked:
        status = "BLOCKED"
    elif tp_filled > ZERO or sl_filled > ZERO:
        status = (
            "CANCEL_PENDING"
            if outstanding
            or tp.live_order_ids
            or sl.live_order_ids
            or tp.submitted_pending
            or sl.submitted_pending
            or tp.unknown_quantity > ZERO
            or sl.unknown_quantity > ZERO
            else "COMPLETED"
        )
    else:
        status = (
            "CANCEL_PENDING" if outstanding or tp.cancel_pending or sl.cancel_pending else "ACTIVE"
        )
    return BracketStateV1(
        spec=spec,
        version=accepted,
        events=events,
        parent_executed_quantity=parent_filled,
        take_profit=tp,
        stop_loss=sl,
        desired_protective_quantity=desired,
        outstanding_cancel_requests=tuple(sorted(outstanding, key=str)),
        oco_linkage=linkage,
        discrepancy_codes=tuple(sorted(discrepancies)),
        quarantined=bool(discrepancies - ADVISORY_CODES),
        kill_active=kill_active,
        gtd_expired=gtd_expired,
        day_expired=day_expired,
        status=status,
        account_blocked=account_blocked,
    )


def _validate_expiry(spec: BracketSpecV1, event: BracketEventV1) -> None:
    if event.kind in {BracketEventKind.GTD_EXPIRED, BracketEventKind.DAY_EXPIRED} and (
        event.leg != BracketLeg.PARENT
    ):
        raise BracketValidationError("INVALID_EXPIRY_LEG")
    if event.kind == BracketEventKind.GTD_EXPIRED:
        if spec.tif != "GTD" or spec.gtd_time_ns is None:
            raise BracketValidationError("EXPIRY_TIF_MISMATCH")
        if event.broker_event_time_ns < spec.gtd_time_ns:
            raise BracketValidationError("EXPIRY_BEFORE_DEADLINE")
    if event.kind == BracketEventKind.DAY_EXPIRED:
        if spec.tif != "DAY":
            raise BracketValidationError("EXPIRY_TIF_MISMATCH")
        if spec.day_session_close_ns is None:
            raise BracketValidationError("SESSION_CLOSE_UNAVAILABLE")
        if event.broker_event_time_ns < spec.day_session_close_ns:
            raise BracketValidationError("EXPIRY_BEFORE_DEADLINE")


def _reduce_unchecked(
    state: BracketStateV1, event: BracketEventV1
) -> tuple[BracketStateV1, tuple[BracketEffect, ...]]:
    """Apply one validated event; callers own integrity and Decimal context checks."""
    if event in state.events:
        return state, ()
    _validate_expiry(state.spec, event)
    events = (*state.events, event)
    new_state = _rebuild(state.spec, events)
    effects: list[BracketEffect] = []
    reservations: dict[BracketLeg, Decimal] = {}
    for leg in CHILD_LEGS:
        prior_child = state.take_profit if leg == BracketLeg.TAKE_PROFIT else state.stop_loss
        observed_child = (
            new_state.take_profit if leg == BracketLeg.TAKE_PROFIT else new_state.stop_loss
        )
        prior_exposure = (
            prior_child.active_quantity
            + prior_child.pending_submit_quantity
            + prior_child.filled_quantity
        )
        observed_exposure = (
            observed_child.active_quantity
            + observed_child.pending_submit_quantity
            + observed_child.filled_quantity
        )
        # Transfer a proposal only when broker/local evidence increased exposure.
        acknowledged = max(ZERO, observed_exposure - prior_exposure)
        reservations[leg] = max(ZERO, prior_child.proposed_pending_quantity - acknowledged)

    overcommitted: set[str] = set()
    for leg in CHILD_LEGS:
        child = new_state.take_profit if leg == BracketLeg.TAKE_PROFIT else new_state.stop_loss
        if reservations[leg] > ZERO and (
            child.active_quantity
            + child.pending_submit_quantity
            + child.filled_quantity
            + reservations[leg]
            > new_state.parent_executed_quantity
        ):
            overcommitted.add(f"{leg.value}_PROPOSAL_OVERCOMMITTED")
    if overcommitted:
        new_state = replace(
            new_state,
            discrepancy_codes=tuple(sorted(set(new_state.discrepancy_codes) | overcommitted)),
            quarantined=True,
            take_profit=replace(new_state.take_profit, dispatchable_quantity=ZERO),
            stop_loss=replace(new_state.stop_loss, dispatchable_quantity=ZERO),
        )
    carried_children: dict[BracketLeg, ChildStateV1] = {}
    for leg in CHILD_LEGS:
        prior_child = state.take_profit if leg == BracketLeg.TAKE_PROFIT else state.stop_loss
        child = new_state.take_profit if leg == BracketLeg.TAKE_PROFIT else new_state.stop_loss
        obligations = set(child.outstanding_cancel_order_ids) | (
            set(prior_child.outstanding_cancel_order_ids) & set(child.live_order_ids)
        )
        if obligations:
            child = replace(
                child,
                outstanding_cancel_order_ids=tuple(sorted(obligations)),
                cancel_pending=True,
                cancel_status=(
                    "CANCEL_REQUESTED_UNCONFIRMED"
                    if child.cancel_status == "CANCEL_REQUESTED_UNCONFIRMED"
                    else "CANCEL_PENDING"
                ),
                dispatchable_quantity=ZERO,
            )
        carried_children[leg] = child
    carried_legs = tuple(
        leg for leg in CHILD_LEGS if carried_children[leg].outstanding_cancel_order_ids
    )
    new_state = replace(
        new_state,
        take_profit=carried_children[BracketLeg.TAKE_PROFIT],
        stop_loss=carried_children[BracketLeg.STOP_LOSS],
        outstanding_cancel_requests=carried_legs,
        status=(
            "CANCEL_PENDING"
            if carried_legs and new_state.status in {"ACTIVE", "COMPLETED"}
            else new_state.status
        ),
    )
    parent_fill_event = event.leg == BracketLeg.PARENT and event.kind in {
        BracketEventKind.FILL,
        BracketEventKind.FILL_CORRECTION,
        BracketEventKind.FILL_BUST,
    }
    updated_children: dict[BracketLeg, ChildStateV1] = {}
    for leg in CHILD_LEGS:
        prior_child = state.take_profit if leg == BracketLeg.TAKE_PROFIT else state.stop_loss
        child = new_state.take_profit if leg == BracketLeg.TAKE_PROFIT else new_state.stop_loss
        newly_outstanding = set(child.outstanding_cancel_order_ids) - set(
            prior_child.outstanding_cancel_order_ids
        )
        for identity in sorted(newly_outstanding):
            if (
                event.kind == BracketEventKind.CANCEL_REQUESTED
                and event.leg == leg
                and (event.venue_id, event.venue_order_id) == identity
            ):
                continue
            effects.append(
                RequestCancelChild(
                    _cancel_key(state.spec, leg, identity, new_state.version),
                    leg,
                    (identity[1],),
                    identity[0],
                )
            )
        replacement_ready = (
            event.kind == BracketEventKind.CANCEL_CONFIRMED
            and event.leg == leg
            and prior_child.pending_amend_price is not None
            and child.pending_amend_price is None
        )
        updated_unsubmitted_price = (
            event.kind == BracketEventKind.AMEND_REQUESTED
            and event.leg == leg
            and child.price != prior_child.price
        )
        available = max(ZERO, child.dispatchable_quantity - reservations[leg])
        if (
            (parent_fill_event or replacement_ready or updated_unsubmitted_price)
            and available > ZERO
            and not new_state.quarantined
        ):
            effects.append(
                RequestSubmitChild(
                    _key(state.spec, leg, new_state.version, "submit"),
                    leg,
                    available,
                    child.price,
                    new_state.oco_linkage,
                )
            )
            reservations[leg] += available
        updated_children[leg] = replace(
            child,
            proposed_pending_quantity=reservations[leg],
            dispatchable_quantity=max(ZERO, child.dispatchable_quantity - reservations[leg]),
        )
    final_status = new_state.status
    if not new_state.account_blocked and (
        new_state.take_profit.filled_quantity > ZERO
        or new_state.stop_loss.filled_quantity > ZERO
    ):
        updated_tp = updated_children[BracketLeg.TAKE_PROFIT]
        updated_sl = updated_children[BracketLeg.STOP_LOSS]
        tp_opposing_pending = (
            updated_sl.outstanding_cancel_order_ids
            or updated_sl.submitted_pending
            or updated_sl.unknown_quantity > ZERO
            or updated_sl.proposed_pending_quantity > ZERO
        )
        sl_opposing_pending = (
            updated_tp.outstanding_cancel_order_ids
            or updated_tp.submitted_pending
            or updated_tp.unknown_quantity > ZERO
            or updated_tp.proposed_pending_quantity > ZERO
        )
        cancellation_pending = bool(
            tp_opposing_pending
            or sl_opposing_pending
            or updated_tp.live_order_ids
            or updated_sl.live_order_ids
            or updated_tp.proposed_pending_quantity > ZERO
            or updated_sl.proposed_pending_quantity > ZERO
        )
        final_status = "CANCEL_PENDING" if cancellation_pending else "COMPLETED"
    new_state = replace(
        new_state,
        take_profit=updated_children[BracketLeg.TAKE_PROFIT],
        stop_loss=updated_children[BracketLeg.STOP_LOSS],
        status=final_status,
    )
    if event.kind in {
        BracketEventKind.SUBMIT_UNKNOWN,
        BracketEventKind.CANCEL_UNKNOWN,
        BracketEventKind.SUBMIT_TIMEOUT,
        BracketEventKind.CANCEL_TIMEOUT,
        BracketEventKind.GTD_EXPIRED,
        BracketEventKind.DAY_EXPIRED,
        BracketEventKind.CLOSE_FAILED,
    }:
        effects.append(
            RequestReconcile(
                _key(state.spec, event.leg, new_state.version, "reconcile"),
                event.leg,
                event.kind.value,
            )
        )
    new_codes = set(new_state.discrepancy_codes) - set(state.discrepancy_codes)
    if new_codes:
        if not any(isinstance(effect, RequestReconcile) for effect in effects):
            effects.append(
                RequestReconcile(
                    _key(state.spec, event.leg, new_state.version, "reconcile"),
                    event.leg,
                    ",".join(sorted(new_codes)),
                )
            )
        critical_codes = new_codes - ADVISORY_CODES
        if critical_codes:
            effects.append(
                Quarantine(
                    _key(state.spec, event.leg, new_state.version, "quarantine"),
                    event.leg,
                    tuple(sorted(critical_codes)),
                )
            )
    return new_state, tuple(effects)


def _reconstruct_state(spec: BracketSpecV1, events: tuple[BracketEventV1, ...]) -> BracketStateV1:
    reconstructed = initial_bracket_state(spec)
    for recorded in events:
        reconstructed, _ = _reduce_unchecked(reconstructed, recorded)
    return reconstructed


def reduce(
    state: BracketStateV1,
    event: BracketEventV1,
) -> tuple[BracketStateV1, tuple[BracketEffect, ...]]:
    """Reduce one observation and propose idempotent effects without performing I/O."""
    if type(state) is not BracketStateV1:
        raise BracketValidationError("STATE_INTEGRITY_INVALID")
    if type(event) is not BracketEventV1:
        raise BracketValidationError("INVALID_EVENT")
    try:
        with localcontext(_kernel_decimal_context()):
            if state != _reconstruct_state(state.spec, state.events):
                raise BracketValidationError("STATE_INTEGRITY_INVALID")
            return _reduce_unchecked(state, event)
    except (Inexact, Rounded):
        raise BracketValidationError("PRECISION_EXCEEDED") from None
    except DecimalException:
        raise BracketValidationError("DECIMAL_ARITHMETIC_INVALID") from None


reduce_bracket = reduce


def replay_bracket(
    spec: BracketSpecV1,
    events: Iterable[BracketEventV1],
) -> tuple[BracketStateV1, tuple[BracketEffect, ...]]:
    """Reconstruct state from history without redispatching past effects."""
    state = initial_bracket_state(spec)
    try:
        event_tuple = tuple(events)
    except TypeError:
        raise BracketValidationError("INVALID_EVENTS") from None
    if any(type(event) is not BracketEventV1 for event in event_tuple):
        raise BracketValidationError("INVALID_EVENTS")
    try:
        with localcontext(_kernel_decimal_context()):
            for event in sorted(event_tuple, key=lambda item: (item.local_sequence, item.event_id)):
                state, _ = _reduce_unchecked(state, event)
    except (Inexact, Rounded):
        raise BracketValidationError("PRECISION_EXCEEDED") from None
    except DecimalException:
        raise BracketValidationError("DECIMAL_ARITHMETIC_INVALID") from None
    return state, ()
