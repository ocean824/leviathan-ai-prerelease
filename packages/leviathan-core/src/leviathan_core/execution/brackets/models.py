"""Immutable inputs and outputs for the broker-evidence bracket reducer."""

from __future__ import annotations

import re
from dataclasses import dataclass
from decimal import (
    ROUND_HALF_EVEN,
    Clamped,
    Context,
    Decimal,
    DecimalException,
    DivisionByZero,
    FloatOperation,
    Inexact,
    InvalidOperation,
    Overflow,
    Rounded,
    Subnormal,
    Underflow,
    localcontext,
)
from enum import StrEnum
from typing import Never, SupportsIndex

ZERO = Decimal(0)
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}", re.ASCII)
_REASON = re.compile(r"[A-Za-z0-9_,.-]{1,255}", re.ASCII)


def _kernel_decimal_context() -> Context:
    # A fresh context prevents callers from changing future reductions via a shared object.
    return Context(
        prec=34,
        rounding=ROUND_HALF_EVEN,
        traps=[
            Clamped,
            DivisionByZero,
            FloatOperation,
            Inexact,
            InvalidOperation,
            Overflow,
            Subnormal,
            Underflow,
        ],
    )


class BracketValidationError(ValueError):
    """Typed, input-free rejection at the bracket kernel boundary."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class _NoCopy:
    def __copy__(self) -> Never:
        raise BracketValidationError("COPY_FORBIDDEN")

    def __deepcopy__(self, memo: dict[int, object]) -> Never:
        raise BracketValidationError("COPY_FORBIDDEN")

    def __reduce__(self) -> Never:
        raise BracketValidationError("PICKLE_FORBIDDEN")

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        raise BracketValidationError("PICKLE_FORBIDDEN")


def _identifier(value: object, name: str, *, optional: bool = False) -> None:
    if optional and value is None:
        return
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise BracketValidationError(f"INVALID_{name.upper()}")


def _reason(value: object) -> None:
    if type(value) is not str or _REASON.fullmatch(value) is None:
        raise BracketValidationError("INVALID_REASON")


def _nonnegative_int(value: object, name: str, *, optional: bool = False) -> None:
    if optional and value is None:
        return
    if type(value) is not int or value < 0:
        raise BracketValidationError(f"INVALID_{name.upper()}")


def _boolean(value: object, name: str) -> None:
    if type(value) is not bool:
        raise BracketValidationError(f"INVALID_{name.upper()}")


def _canonical_decimal(value: object, name: str, *, positive: bool = False) -> Decimal:
    if type(value) is not Decimal or not value.is_finite():
        raise BracketValidationError(f"INVALID_{name.upper()}")
    if abs(value.adjusted()) > 38:
        raise BracketValidationError("DECIMAL_OUT_OF_BOUNDS")
    if positive and value <= ZERO:
        raise BracketValidationError(f"INVALID_{name.upper()}")
    if not positive and value < ZERO:
        raise BracketValidationError(f"INVALID_{name.upper()}")
    if value.is_zero():
        return ZERO
    parts = value.as_tuple()
    coefficient = parts.digits
    exponent = parts.exponent
    assert isinstance(exponent, int)
    significant_length = len(coefficient)
    while significant_length > 1 and coefficient[significant_length - 1] == 0:
        significant_length -= 1
        exponent += 1
    if significant_length > _kernel_decimal_context().prec:
        raise BracketValidationError("PRECISION_EXCEEDED")
    return Decimal((parts.sign, coefficient[:significant_length], exponent))


def _decimal_field(owner: object, name: str, *, positive: bool = False) -> None:
    object.__setattr__(
        owner, name, _canonical_decimal(getattr(owner, name), name, positive=positive)
    )


def _is_exact_multiple(quantity: Decimal, increment: Decimal) -> bool:
    quantity_num, quantity_den = quantity.as_integer_ratio()
    increment_num, increment_den = increment.as_integer_ratio()
    return (quantity_num * increment_den) % (quantity_den * increment_num) == 0


def _tuple_field(owner: object, name: str, item_type: type[object]) -> None:
    value = getattr(owner, name)
    if type(value) is not tuple or any(type(item) is not item_type for item in value):
        raise BracketValidationError(f"INVALID_{name.upper()}")
    object.__setattr__(owner, name, tuple(value))


def _order_identities(owner: object, name: str) -> None:
    value = getattr(owner, name)
    if type(value) is not tuple:
        raise BracketValidationError(f"INVALID_{name.upper()}")
    for identity in value:
        if type(identity) is not tuple or len(identity) != 2:
            raise BracketValidationError(f"INVALID_{name.upper()}")
        _identifier(identity[0], "venue_id")
        _identifier(identity[1], "venue_order_id")
    if len(set(value)) != len(value):
        raise BracketValidationError(f"DUPLICATE_{name.upper()}")
    object.__setattr__(owner, name, tuple(value))


class BracketLeg(StrEnum):
    PARENT = "PARENT"
    TAKE_PROFIT = "TAKE_PROFIT"
    STOP_LOSS = "STOP_LOSS"


class BracketEventKind(StrEnum):
    FILL = "FILL"
    FILL_CORRECTION = "FILL_CORRECTION"
    FILL_BUST = "FILL_BUST"
    SUBMIT_REQUESTED = "SUBMIT_REQUESTED"
    SUBMIT_CONFIRMED = "SUBMIT_CONFIRMED"
    SUBMIT_UNKNOWN = "SUBMIT_UNKNOWN"
    SUBMIT_TIMEOUT = "SUBMIT_TIMEOUT"
    CANCEL_REQUESTED = "CANCEL_REQUESTED"
    CANCEL_CONFIRMED = "CANCEL_CONFIRMED"
    CANCEL_UNKNOWN = "CANCEL_UNKNOWN"
    CANCEL_TIMEOUT = "CANCEL_TIMEOUT"
    ORDER_REJECTED = "ORDER_REJECTED"
    ORDER_EXPIRED = "ORDER_EXPIRED"
    AMEND_REQUESTED = "AMEND_REQUESTED"
    AMEND_CONFIRMED_ATOMIC = "AMEND_CONFIRMED_ATOMIC"
    KILL_ACTIVATED = "KILL_ACTIVATED"
    GTD_EXPIRED = "GTD_EXPIRED"
    DAY_EXPIRED = "DAY_EXPIRED"
    CLOSE_FAILED = "CLOSE_FAILED"


@dataclass(frozen=True, slots=True)
class BracketSpecV1(_NoCopy):
    bracket_id: str
    parent_request_digest: str
    account_id: str
    environment: str
    instrument_id: str
    side: str
    entry_quantity: Decimal
    take_profit_price: Decimal
    stop_loss_price: Decimal
    oco_mode: str
    tick_size: Decimal
    lot_size: Decimal
    tif: str
    policy_revision: str
    gtd_time_ns: int | None = None
    oco_group_id: str | None = None
    day_session_close_ns: int | None = None

    def __post_init__(self) -> None:
        for name in (
            "bracket_id",
            "parent_request_digest",
            "account_id",
            "environment",
            "instrument_id",
            "policy_revision",
        ):
            _identifier(getattr(self, name), name)
        _identifier(self.oco_group_id, "oco_group_id", optional=True)
        if type(self.side) is not str or self.side not in {"BUY", "SELL"}:
            raise BracketValidationError("INVALID_SIDE")
        if type(self.oco_mode) is not str or self.oco_mode not in {"NATIVE", "SYNTHETIC"}:
            raise BracketValidationError("INVALID_OCO_MODE")
        if type(self.tif) is not str or self.tif not in {"DAY", "GTC", "GTD"}:
            raise BracketValidationError("INVALID_TIF")
        _nonnegative_int(self.gtd_time_ns, "gtd_time_ns", optional=True)
        _nonnegative_int(self.day_session_close_ns, "day_session_close_ns", optional=True)
        if self.tif == "GTD" and self.gtd_time_ns is None:
            raise BracketValidationError("GTD_DEADLINE_REQUIRED")
        if (self.tif != "GTD" and self.gtd_time_ns is not None) or (
            self.tif != "DAY" and self.day_session_close_ns is not None
        ):
            raise BracketValidationError("INVALID_TIF_COMBINATION")
        for name in (
            "entry_quantity",
            "take_profit_price",
            "stop_loss_price",
            "tick_size",
            "lot_size",
        ):
            _decimal_field(self, name, positive=True)
        try:
            with localcontext(_kernel_decimal_context()):
                if not _is_exact_multiple(self.entry_quantity, self.lot_size):
                    raise BracketValidationError("INVALID_LOT_MULTIPLE")
                if not _is_exact_multiple(
                    self.take_profit_price, self.tick_size
                ) or not _is_exact_multiple(self.stop_loss_price, self.tick_size):
                    raise BracketValidationError("INVALID_TICK_MULTIPLE")
        except (Inexact, Rounded):
            raise BracketValidationError("PRECISION_EXCEEDED") from None
        except DecimalException:
            raise BracketValidationError("DECIMAL_ARITHMETIC_INVALID") from None


@dataclass(frozen=True, slots=True)
class BracketEventV1(_NoCopy):
    event_id: str
    source: str
    account_id: str
    environment: str
    instrument_id: str
    parent_request_digest: str
    kind: BracketEventKind
    leg: BracketLeg
    local_sequence: int
    broker_event_time_ns: int
    received_time_ns: int
    venue_id: str = "VENUE_UNSPECIFIED"
    correction_version: int = 0
    venue_order_id: str | None = None
    venue_execution_id: str | None = None
    quantity: Decimal = ZERO
    expected_version: int | None = None
    new_price: Decimal | None = None
    oco_group_id: str | None = None

    def __post_init__(self) -> None:
        for name in (
            "event_id",
            "source",
            "account_id",
            "environment",
            "instrument_id",
            "parent_request_digest",
            "venue_id",
        ):
            _identifier(getattr(self, name), name)
        for name in ("venue_order_id", "venue_execution_id", "oco_group_id"):
            _identifier(getattr(self, name), name, optional=True)
        if type(self.kind) is not BracketEventKind:
            raise BracketValidationError("INVALID_EVENT_KIND")
        if type(self.leg) is not BracketLeg:
            raise BracketValidationError("INVALID_LEG")
        for name in (
            "local_sequence",
            "broker_event_time_ns",
            "received_time_ns",
            "correction_version",
        ):
            _nonnegative_int(getattr(self, name), name)
        _nonnegative_int(self.expected_version, "expected_version", optional=True)
        _decimal_field(self, "quantity")
        if self.new_price is not None:
            _decimal_field(self, "new_price", positive=True)
        if self.kind in {
            BracketEventKind.FILL,
            BracketEventKind.FILL_CORRECTION,
            BracketEventKind.FILL_BUST,
        } and (not self.venue_execution_id or not self.venue_order_id):
            raise BracketValidationError("FILL_IDENTIFIERS_REQUIRED")
        if (
            self.kind
            in {
                BracketEventKind.FILL,
                BracketEventKind.SUBMIT_REQUESTED,
                BracketEventKind.SUBMIT_CONFIRMED,
                BracketEventKind.SUBMIT_UNKNOWN,
                BracketEventKind.SUBMIT_TIMEOUT,
            }
            and self.quantity <= ZERO
        ):
            raise BracketValidationError("POSITIVE_QUANTITY_REQUIRED")
        if self.kind in {
            BracketEventKind.AMEND_REQUESTED,
            BracketEventKind.AMEND_CONFIRMED_ATOMIC,
        } and (self.expected_version is None or self.new_price is None):
            raise BracketValidationError("AMEND_FIELDS_REQUIRED")


@dataclass(frozen=True, slots=True)
class ChildStateV1(_NoCopy):
    leg: BracketLeg
    price: Decimal
    active_quantity: Decimal = ZERO
    filled_quantity: Decimal = ZERO
    unknown_quantity: Decimal = ZERO
    submitted_pending: bool = False
    cancel_pending: bool = False
    cancel_status: str = "NONE"
    submit_status: str = "NONE"
    pending_submit_quantity: Decimal = ZERO
    venue_order_ids: tuple[str, ...] = ()
    cancelled_order_ids: tuple[str, ...] = ()
    pending_amend_price: Decimal | None = None
    dispatchable_quantity: Decimal = ZERO
    proposed_pending_quantity: Decimal = ZERO
    live_order_ids: tuple[tuple[str, str], ...] = ()
    pending_order_ids: tuple[tuple[str, str], ...] = ()
    terminal_order_ids: tuple[tuple[str, str], ...] = ()
    outstanding_cancel_order_ids: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if type(self.leg) is not BracketLeg or self.leg == BracketLeg.PARENT:
            raise BracketValidationError("INVALID_CHILD_LEG")
        _decimal_field(self, "price", positive=True)
        for name in (
            "active_quantity",
            "filled_quantity",
            "unknown_quantity",
            "pending_submit_quantity",
            "dispatchable_quantity",
            "proposed_pending_quantity",
        ):
            _decimal_field(self, name)
        if self.pending_amend_price is not None:
            _decimal_field(self, "pending_amend_price", positive=True)
        _boolean(self.submitted_pending, "submitted_pending")
        _boolean(self.cancel_pending, "cancel_pending")
        if type(self.cancel_status) is not str or self.cancel_status not in {
            "NONE",
            "CANCEL_PENDING",
            "CANCEL_REQUESTED_UNCONFIRMED",
            "CANCELED",
        }:
            raise BracketValidationError("INVALID_CANCEL_STATUS")
        if type(self.submit_status) is not str or self.submit_status not in {
            "NONE",
            "SUBMIT_PENDING",
            "UNKNOWN_SUBMIT",
        }:
            raise BracketValidationError("INVALID_SUBMIT_STATUS")
        for name in ("venue_order_ids", "cancelled_order_ids"):
            _tuple_field(self, name, str)
            values = getattr(self, name)
            for value in values:
                _identifier(value, name)
            if len(set(values)) != len(values):
                raise BracketValidationError(f"DUPLICATE_{name.upper()}")
        for name in (
            "live_order_ids",
            "pending_order_ids",
            "terminal_order_ids",
            "outstanding_cancel_order_ids",
        ):
            _order_identities(self, name)
        live = set(self.live_order_ids)
        if live & set(self.terminal_order_ids):
            raise BracketValidationError("ORDER_LIVE_TERMINAL_CONFLICT")
        if not set(self.pending_order_ids) <= live or not set(
            self.outstanding_cancel_order_ids
        ) <= live:
            raise BracketValidationError("ORDER_SET_INCONSISTENT")
        if self.cancel_status == "CANCELED" and (
            self.outstanding_cancel_order_ids or self.live_order_ids
        ):
            raise BracketValidationError("CANCELED_WITH_LIVE_ORDER")


@dataclass(frozen=True, slots=True)
class BracketStateV1(_NoCopy):
    spec: BracketSpecV1
    take_profit: ChildStateV1
    stop_loss: ChildStateV1
    version: int = 0
    events: tuple[BracketEventV1, ...] = ()
    parent_executed_quantity: Decimal = ZERO
    desired_protective_quantity: Decimal = ZERO
    outstanding_cancel_requests: tuple[BracketLeg, ...] = ()
    oco_linkage: str = ""
    discrepancy_codes: tuple[str, ...] = ()
    quarantined: bool = False
    kill_active: bool = False
    gtd_expired: bool = False
    day_expired: bool = False
    status: str = "ACTIVE"
    account_blocked: bool = False

    def __post_init__(self) -> None:
        if type(self.spec) is not BracketSpecV1:
            raise BracketValidationError("INVALID_SPEC")
        if (
            type(self.take_profit) is not ChildStateV1
            or self.take_profit.leg != BracketLeg.TAKE_PROFIT
        ):
            raise BracketValidationError("INVALID_TAKE_PROFIT")
        if type(self.stop_loss) is not ChildStateV1 or self.stop_loss.leg != BracketLeg.STOP_LOSS:
            raise BracketValidationError("INVALID_STOP_LOSS")
        _nonnegative_int(self.version, "version")
        _tuple_field(self, "events", BracketEventV1)
        if self.version > len(self.events):
            raise BracketValidationError("INVALID_VERSION")
        for name in ("parent_executed_quantity", "desired_protective_quantity"):
            _decimal_field(self, name)
        if (
            self.desired_protective_quantity > self.parent_executed_quantity
            or self.desired_protective_quantity > self.spec.entry_quantity
        ):
            raise BracketValidationError("PROTECTION_EXCEEDS_PARENT")
        _tuple_field(self, "outstanding_cancel_requests", BracketLeg)
        if any(leg == BracketLeg.PARENT for leg in self.outstanding_cancel_requests):
            raise BracketValidationError("INVALID_CANCEL_LEG")
        _tuple_field(self, "discrepancy_codes", str)
        for code in self.discrepancy_codes:
            _identifier(code, "discrepancy_code")
        _identifier(self.oco_linkage, "oco_linkage")
        if type(self.status) is not str or self.status not in {
            "ACTIVE", "CANCEL_PENDING", "COMPLETED", "BLOCKED"
        }:
            raise BracketValidationError("INVALID_BRACKET_STATUS")
        for name in (
            "quarantined", "kill_active", "gtd_expired", "day_expired", "account_blocked"
        ):
            _boolean(getattr(self, name), name)
        if self.account_blocked != (self.status == "BLOCKED"):
            raise BracketValidationError("ACCOUNT_BLOCK_STATUS_MISMATCH")
        try:
            with localcontext(_kernel_decimal_context()):
                for child in (self.take_profit, self.stop_loss):
                    if child.dispatchable_quantity > self.desired_protective_quantity:
                        raise BracketValidationError("PROTECTION_EXCEEDS_PARENT")
                    if (
                        child.active_quantity
                        + child.filled_quantity
                        + child.pending_submit_quantity
                        + child.proposed_pending_quantity
                        > self.parent_executed_quantity
                        and not self.quarantined
                    ):
                        raise BracketValidationError("UNQUARANTINED_CHILD_OVERCOMMIT")
                    if child.unknown_quantity > ZERO and child.dispatchable_quantity > ZERO:
                        raise BracketValidationError("UNKNOWN_CHILD_DISPATCH")
        except (Inexact, Rounded):
            raise BracketValidationError("PRECISION_EXCEEDED") from None
        except DecimalException:
            raise BracketValidationError("DECIMAL_ARITHMETIC_INVALID") from None
        if self.status == "COMPLETED":
            if self.take_profit.filled_quantity == ZERO and self.stop_loss.filled_quantity == ZERO:
                raise BracketValidationError("COMPLETED_WITHOUT_FILL")
            for child in (self.take_profit, self.stop_loss):
                if (
                    child.live_order_ids
                    or child.pending_submit_quantity > ZERO
                    or child.proposed_pending_quantity > ZERO
                    or child.unknown_quantity > ZERO
                ):
                    raise BracketValidationError("COMPLETED_WITH_LIVE_OPPOSITION")
        if (self.kill_active or self.gtd_expired or self.day_expired or self.quarantined) and (
            self.take_profit.dispatchable_quantity > ZERO
            or self.stop_loss.dispatchable_quantity > ZERO
        ):
            raise BracketValidationError("DISPATCH_WHILE_BLOCKED")


@dataclass(frozen=True, slots=True)
class RequestSubmitChild(_NoCopy):
    idempotency_key: str
    leg: BracketLeg
    quantity: Decimal
    price: Decimal
    oco_group_id: str

    def __post_init__(self) -> None:
        _identifier(self.idempotency_key, "idempotency_key")
        _identifier(self.oco_group_id, "oco_group_id")
        if type(self.leg) is not BracketLeg or self.leg == BracketLeg.PARENT:
            raise BracketValidationError("INVALID_CHILD_LEG")
        _decimal_field(self, "quantity", positive=True)
        _decimal_field(self, "price", positive=True)


@dataclass(frozen=True, slots=True)
class RequestCancelChild(_NoCopy):
    idempotency_key: str
    leg: BracketLeg
    venue_order_ids: tuple[str, ...]
    venue_id: str = "VENUE_UNSPECIFIED"

    def __post_init__(self) -> None:
        _identifier(self.idempotency_key, "idempotency_key")
        _identifier(self.venue_id, "venue_id")
        if type(self.leg) is not BracketLeg or self.leg == BracketLeg.PARENT:
            raise BracketValidationError("INVALID_CHILD_LEG")
        _tuple_field(self, "venue_order_ids", str)
        if len(self.venue_order_ids) != 1:
            raise BracketValidationError("ONE_CANCEL_ORDER_REQUIRED")
        for order_id in self.venue_order_ids:
            _identifier(order_id, "venue_order_id")


@dataclass(frozen=True, slots=True)
class RequestReconcile(_NoCopy):
    idempotency_key: str
    leg: BracketLeg
    reason: str

    def __post_init__(self) -> None:
        _identifier(self.idempotency_key, "idempotency_key")
        if type(self.leg) is not BracketLeg:
            raise BracketValidationError("INVALID_LEG")
        _reason(self.reason)


@dataclass(frozen=True, slots=True)
class Quarantine(_NoCopy):
    idempotency_key: str
    leg: BracketLeg
    discrepancy_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        _identifier(self.idempotency_key, "idempotency_key")
        if type(self.leg) is not BracketLeg:
            raise BracketValidationError("INVALID_LEG")
        _tuple_field(self, "discrepancy_codes", str)
        if not self.discrepancy_codes:
            raise BracketValidationError("DISCREPANCY_REQUIRED")
        for code in self.discrepancy_codes:
            _identifier(code, "discrepancy_code")


BracketEffect = RequestSubmitChild | RequestCancelChild | RequestReconcile | Quarantine
