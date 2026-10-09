"""Immutable, offline routing inputs and planning evidence.

These records describe a preview. None grants authority to submit an order.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import InitVar, dataclass, field
from decimal import (
    ROUND_HALF_EVEN,
    Context,
    Decimal,
    DivisionByZero,
    Inexact,
    InvalidOperation,
    Overflow,
    localcontext,
)
from functools import wraps
from typing import Literal, NoReturn, SupportsIndex, TypeVar

Side = Literal["BUY", "SELL"]
RoutingPolicy = Literal["best_price", "best_liquidity", "latency_first", "custom"]
Tactic = Literal["DIRECT", "TWAP", "VWAP", "ICEBERG"]
Tif = Literal["IOC", "FOK", "DAY", "GTD"]
PlanStatus = Literal["PLANNED", "PARTIALLY_PLANNED", "BLOCKED", "FROZEN"]
BrokerOutcome = Literal[
    "REJECTED", "CANCELED", "TIMEOUT", "UNKNOWN_SUBMIT", "UNKNOWN_CANCEL", "PENDING"
]
JitterPolicyReason = Literal["JITTER_OUT_OF_BOUNDS", "MISSING_JITTER_SEED"]


class RouteValidationError(ValueError):
    """A parent request is malformed or incomplete and cannot be planned."""

    def __init__(self, code: str, reason_code: JitterPolicyReason | None = None) -> None:
        self.code = code
        self.reason_code = reason_code
        super().__init__(code if reason_code is None else f"{code}: {reason_code}")


_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/+-]{0,127}\Z", re.ASCII)
_DIGEST = re.compile(r"[0-9a-fA-F]{64}\Z", re.ASCII)
KERNEL_DECIMAL_CONTEXT = Context(
    prec=34, rounding=ROUND_HALF_EVEN, traps=[DivisionByZero, InvalidOperation, Overflow, Inexact]
)
_Record = TypeVar("_Record")


def _decimal_context(method: Callable[[_Record], None]) -> Callable[[_Record], None]:
    @wraps(method)
    def wrapped(record: _Record) -> None:
        with localcontext(KERNEL_DECIMAL_CONTEXT):
            try:
                method(record)
            except Inexact as exc:
                raise RouteValidationError("PRECISION_EXCEEDED") from exc

    return wrapped


def bounded_decimal(value: object, *, positive: bool = False) -> bool:
    """Validate finite exact input before any context-bounded arithmetic."""
    if not isinstance(value, Decimal) or not value.is_finite():
        return False
    if value.is_zero():
        return not positive
    digits = value.as_tuple().digits
    if abs(value.adjusted()) > 38:
        raise RouteValidationError("DECIMAL_OUT_OF_BOUNDS")
    significant = len(digits)
    while significant > 1 and digits[significant - 1] == 0:
        significant -= 1
    if significant > KERNEL_DECIMAL_CONTEXT.prec:
        raise RouteValidationError("PRECISION_EXCEEDED")
    return value > 0 if positive else value >= 0


def canonical_decimal(value: Decimal) -> str:
    """An ambient-context-independent numeric spelling for digests."""
    if not bounded_decimal(value):
        raise RouteValidationError("INVALID_DECIMAL")
    if value == 0:
        return "0"
    sign, digits, exponent = value.as_tuple()
    if not isinstance(exponent, int):
        raise RouteValidationError("INVALID_DECIMAL")
    significant = len(digits)
    while significant > 1 and digits[significant - 1] == 0:
        significant -= 1
        exponent += 1
    coefficient = "".join(str(digit) for digit in digits[:significant])
    if exponent >= 0:
        spelling = coefficient + "0" * exponent
    else:
        point = len(coefficient) + exponent
        spelling = (
            coefficient[:point] + "." + coefficient[point:]
            if point > 0
            else "0." + "0" * (-point) + coefficient
        )
    return "-" + spelling if sign else spelling


def _identifier(value: object) -> bool:
    return isinstance(value, str) and _IDENTIFIER.fullmatch(value) is not None


def _tuple_of(value: object, kind: type[object]) -> bool:
    return isinstance(value, tuple) and all(isinstance(item, kind) for item in value)


def _identifiers(value: object) -> bool:
    return isinstance(value, tuple) and all(_identifier(item) for item in value)


def _utc_ns(value: object) -> bool:
    return type(value) is int and value >= 0


def exact_multiple(value: Decimal, quantum: Decimal) -> bool:
    """Check lot/tick alignment with integer ratios, independent of Decimal context."""
    value_num, value_den = value.as_integer_ratio()
    quantum_num, quantum_den = quantum.as_integer_ratio()
    return (value_num * quantum_den) % (value_den * quantum_num) == 0


class _NoCopy:
    __slots__ = ()

    def __copy__(self) -> NoReturn:
        raise RouteValidationError("COPY_DISABLED")

    def __deepcopy__(self, memo: object) -> NoReturn:
        raise RouteValidationError("COPY_DISABLED")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise RouteValidationError("SERIALIZATION_DISABLED")


@dataclass(frozen=True, slots=True)
class VolumeCurveV1(_NoCopy):
    revision: str
    weights: tuple[Decimal, ...]

    @_decimal_context
    def __post_init__(self) -> None:
        if not _identifier(self.revision) or not isinstance(self.weights, tuple):
            raise RouteValidationError("INVALID_VOLUME_CURVE")
        if not self.weights or any(
            not bounded_decimal(item, positive=True) for item in self.weights
        ):
            raise RouteValidationError("INVALID_VOLUME_CURVE")


@dataclass(frozen=True, slots=True)
class TacticParamsV1(_NoCopy):
    duration_ns: int | None = None
    buckets: int | None = None
    peak_qty: Decimal | None = None
    jitter_seed: str | None = None
    jitter_max_ns: int = 0
    volume_curve: VolumeCurveV1 | None = None

    @_decimal_context
    def __post_init__(self) -> None:
        if self.duration_ns is not None and not _utc_ns(self.duration_ns):
            raise RouteValidationError("INVALID_TACTIC_PARAMS")
        if self.buckets is not None and not _utc_ns(self.buckets):
            raise RouteValidationError("INVALID_TACTIC_PARAMS")
        if (self.duration_ns is not None and self.duration_ns == 0) or (
            self.buckets is not None and not 1 <= self.buckets <= 1024
        ):
            raise RouteValidationError("POLICY_OUT_OF_BOUNDS")
        if self.peak_qty is not None and not bounded_decimal(self.peak_qty, positive=True):
            raise RouteValidationError("INVALID_TACTIC_PARAMS")
        if self.jitter_seed is not None and not _identifier(self.jitter_seed):
            raise RouteValidationError("INVALID_TACTIC_PARAMS")
        if not _utc_ns(self.jitter_max_ns):
            raise RouteValidationError("INVALID_TACTIC_PARAMS")
        if self.jitter_max_ns > 0:
            if self.jitter_seed is None:
                raise RouteValidationError("POLICY_OUT_OF_BOUNDS", "MISSING_JITTER_SEED")
            if (
                self.duration_ns is not None
                and self.buckets is not None
                and self.jitter_max_ns * 2 * self.buckets >= self.duration_ns
            ):
                raise RouteValidationError("POLICY_OUT_OF_BOUNDS", "JITTER_OUT_OF_BOUNDS")
        if self.volume_curve is not None and not isinstance(self.volume_curve, VolumeCurveV1):
            raise RouteValidationError("INVALID_TACTIC_PARAMS")


@dataclass(frozen=True, slots=True)
class VenueQuoteV1(_NoCopy):
    venue_id: str
    bid: Decimal | None
    ask: Decimal | None
    bid_depth: Decimal | None
    ask_depth: Decimal | None
    event_time_ns: int | None
    receive_time_ns: int | None
    health: str | None
    permission: bool | None
    fee_bps: Decimal | None
    historical_slippage_bps: Decimal | None
    ping_ms: Decimal | None
    ping_time_ns: int | None
    lot_size: Decimal | None
    tick_size: Decimal | None
    mapped_instrument_id: str | None
    supported_order_types: tuple[str, ...] = ()
    supported_tifs: tuple[str, ...] = ()
    own_bid: Decimal | None = None
    own_ask: Decimal | None = None

    @_decimal_context
    def __post_init__(self) -> None:
        if not _identifier(self.venue_id):
            raise RouteValidationError("INVALID_VENUE_ID")
        if self.mapped_instrument_id is not None and not _identifier(self.mapped_instrument_id):
            raise RouteValidationError("INVALID_INSTRUMENT_ID")
        if self.health is not None and not _identifier(self.health):
            raise RouteValidationError("INVALID_VENUE_HEALTH")
        if self.permission is not None and type(self.permission) is not bool:
            raise RouteValidationError("INVALID_PERMISSION_TYPE")
        if not _identifiers(self.supported_order_types) or not _identifiers(self.supported_tifs):
            raise RouteValidationError("MUTABLE_VENUE_CAPABILITIES")
        if any(
            value is not None and not bounded_decimal(value)
            for value in (
                self.bid,
                self.ask,
                self.bid_depth,
                self.ask_depth,
                self.fee_bps,
                self.historical_slippage_bps,
                self.ping_ms,
                self.lot_size,
                self.tick_size,
                self.own_bid,
                self.own_ask,
            )
        ):
            raise RouteValidationError("INVALID_QUOTE_DECIMAL")
        if any(
            value is not None and not _utc_ns(value)
            for value in (self.event_time_ns, self.receive_time_ns, self.ping_time_ns)
        ):
            raise RouteValidationError("INVALID_QUOTE_TIME")


@dataclass(frozen=True, slots=True)
class RoutePlanInputV1(_NoCopy):
    parent_request_digest: str
    account_id: str
    instrument_id: str
    instrument_mapping_id: str
    mapping_valid_from_ns: int
    mapping_valid_until_ns: int
    side: Side
    quantity: Decimal
    limit_price: Decimal | None
    lot_size: Decimal
    tick_size: Decimal
    multiplier: Decimal
    allowed_venues: tuple[str, ...]
    venue_order: tuple[str, ...]
    policy_revision: str
    routing_policy: RoutingPolicy
    max_venue_hops: int
    order_type: str
    tif: Tif
    hard_slippage_bps: Decimal
    latency_budget_ms: Decimal
    decision_time_ns: int
    max_quote_age_ns: int
    max_ping_age_ns: int
    max_reconciliation_age_ns: int
    max_slice_qty: Decimal
    depth_factor: Decimal
    venue_quotes: tuple[VenueQuoteV1, ...]
    tactic: Tactic = "DIRECT"
    tactic_params: TacticParamsV1 | None = None
    custom_venue_order: tuple[str, ...] = ()
    min_child_qty: Decimal = Decimal("0")
    gtd_expiry_ns: int | None = None
    session_close_ns: int | None = None

    @_decimal_context
    def __post_init__(self) -> None:
        if not isinstance(self.parent_request_digest, str) or not _DIGEST.fullmatch(
            self.parent_request_digest
        ):
            raise RouteValidationError("INVALID_PARENT_DIGEST")
        if (
            self.side not in {"BUY", "SELL"}
            or self.routing_policy
            not in {"best_price", "best_liquidity", "latency_first", "custom"}
            or self.tactic not in {"DIRECT", "TWAP", "VWAP", "ICEBERG"}
        ):
            raise RouteValidationError("INVALID_ROUTE_ENUM")
        if not all(
            _identifier(value)
            for value in (
                self.account_id,
                self.instrument_id,
                self.instrument_mapping_id,
                self.policy_revision,
                self.order_type,
                self.tif,
            )
        ):
            raise RouteValidationError("INVALID_REQUEST_IDENTITY")
        if not _identifiers(self.allowed_venues) or not _identifiers(self.venue_order):
            raise RouteValidationError("MUTABLE_VENUE_LIST")
        if not _identifiers(self.custom_venue_order):
            raise RouteValidationError("MUTABLE_CUSTOM_VENUE_LIST")
        if not _tuple_of(self.venue_quotes, VenueQuoteV1):
            raise RouteValidationError("MUTABLE_VENUE_SNAPSHOT")
        if self.tactic_params is not None and not isinstance(self.tactic_params, TacticParamsV1):
            raise RouteValidationError("INVALID_TACTIC_PARAMS")
        if (
            any(
                not _utc_ns(value)
                for value in (
                    self.mapping_valid_from_ns,
                    self.mapping_valid_until_ns,
                    self.decision_time_ns,
                    self.max_quote_age_ns,
                    self.max_ping_age_ns,
                    self.max_reconciliation_age_ns,
                )
            )
            or (self.gtd_expiry_ns is not None and not _utc_ns(self.gtd_expiry_ns))
            or (self.session_close_ns is not None and not _utc_ns(self.session_close_ns))
        ):
            raise RouteValidationError("INVALID_REQUEST_TIME")
        if type(self.max_venue_hops) is not int:
            raise RouteValidationError("POLICY_OUT_OF_BOUNDS")
        if any(
            not bounded_decimal(value, positive=True)
            for value in (
                self.quantity,
                self.lot_size,
                self.tick_size,
                self.multiplier,
                self.max_slice_qty,
                self.depth_factor,
            )
        ) or any(
            not bounded_decimal(value)
            for value in (self.hard_slippage_bps, self.latency_budget_ms, self.min_child_qty)
        ):
            raise RouteValidationError("INVALID_REQUEST_DECIMAL")
        if self.limit_price is not None and not bounded_decimal(self.limit_price, positive=True):
            raise RouteValidationError("INVALID_REQUEST_DECIMAL")
        if not exact_multiple(self.quantity, self.lot_size):
            raise RouteValidationError("INVALID_LOT_MULTIPLE")
        if self.limit_price is not None and not exact_multiple(self.limit_price, self.tick_size):
            raise RouteValidationError("INVALID_PRICE_TICK")
        if not 0 < self.max_venue_hops <= 32 or self.depth_factor > 1:
            raise RouteValidationError("POLICY_OUT_OF_BOUNDS")
        if self.order_type not in {"MARKET", "LIMIT"} or self.tif not in {
            "IOC",
            "FOK",
            "DAY",
            "GTD",
        }:
            raise RouteValidationError("INVALID_ORDER_TYPE_OR_TIF")
        if self.order_type == "LIMIT" and self.limit_price is None:
            raise RouteValidationError("MISSING_LIMIT_PRICE")
        if (self.tif != "GTD" and self.gtd_expiry_ns is not None) or (
            self.tif != "DAY" and self.session_close_ns is not None
        ):
            raise RouteValidationError("INVALID_TIF_COMBINATION")
        if self.tif == "DAY" and self.session_close_ns is None:
            raise RouteValidationError("MISSING_SESSION_CLOSE")
        if self.tif == "GTD" and self.gtd_expiry_ns is None:
            raise RouteValidationError("MISSING_GTD_EXPIRY")


@dataclass(frozen=True, slots=True)
class RouteCandidateV1(_NoCopy):
    venue_id: str
    rank: int
    executable_price: Decimal
    top_depth: Decimal
    slice_cap_qty: Decimal
    adverse_slippage_bps: Decimal
    expected_cost_bps: Decimal
    expected_latency_ms: Decimal

    @_decimal_context
    def __post_init__(self) -> None:
        if not _identifier(self.venue_id) or type(self.rank) is not int or self.rank < 0:
            raise RouteValidationError("INVALID_CANDIDATE")
        if any(
            not bounded_decimal(value)
            for value in (
                self.executable_price,
                self.top_depth,
                self.slice_cap_qty,
                self.adverse_slippage_bps,
                self.expected_cost_bps,
                self.expected_latency_ms,
            )
        ):
            raise RouteValidationError("INVALID_CANDIDATE")


@dataclass(frozen=True, slots=True)
class RejectedVenueV1(_NoCopy):
    venue_id: str
    reason_codes: tuple[str, ...]

    @_decimal_context
    def __post_init__(self) -> None:
        if not _identifier(self.venue_id) or not _identifiers(self.reason_codes):
            raise RouteValidationError("INVALID_REJECTION")


@dataclass(frozen=True, slots=True)
class ChildSliceV1(_NoCopy):
    sequence: int
    venue_id: str
    quantity: Decimal
    scheduled_at_ns: int
    display_quantity: Decimal
    order_type: str
    tif: Tif
    limit_price: Decimal | None

    @_decimal_context
    def __post_init__(self) -> None:
        if (
            type(self.sequence) is not int
            or self.sequence <= 0
            or not _identifier(self.venue_id)
            or not _utc_ns(self.scheduled_at_ns)
            or not _identifier(self.order_type)
            or not _identifier(self.tif)
        ):
            raise RouteValidationError("INVALID_CHILD_SLICE")
        if (
            not bounded_decimal(self.quantity, positive=True)
            or not bounded_decimal(self.display_quantity, positive=True)
            or self.display_quantity > self.quantity
        ):
            raise RouteValidationError("INVALID_CHILD_SLICE")
        if self.limit_price is not None and not bounded_decimal(self.limit_price, positive=True):
            raise RouteValidationError("INVALID_CHILD_SLICE")


@dataclass(frozen=True, slots=True)
class RoutePlanV1(_NoCopy):
    parent_request_digest: str
    policy_digest: str
    status: PlanStatus
    reference_price: Decimal | None
    candidates: tuple[RouteCandidateV1, ...]
    rejected: tuple[RejectedVenueV1, ...]
    children: tuple[ChildSliceV1, ...]
    reason_codes: tuple[str, ...] = ()
    attempted_venues: tuple[str, ...] = ()
    required_actions: tuple[str, ...] = ()
    unplanned_remainder: Decimal = Decimal("0")

    @_decimal_context
    def __post_init__(self) -> None:
        if not all(
            isinstance(value, str) and _DIGEST.fullmatch(value)
            for value in (self.parent_request_digest, self.policy_digest)
        ):
            raise RouteValidationError("INVALID_PLAN_DIGEST")
        if self.status not in {"PLANNED", "PARTIALLY_PLANNED", "BLOCKED", "FROZEN"}:
            raise RouteValidationError("INVALID_PLAN_STATUS")
        if (
            not _tuple_of(self.candidates, RouteCandidateV1)
            or not _tuple_of(self.rejected, RejectedVenueV1)
            or not _tuple_of(self.children, ChildSliceV1)
            or not _identifiers(self.reason_codes)
            or not _identifiers(self.attempted_venues)
            or not _identifiers(self.required_actions)
        ):
            raise RouteValidationError("MUTABLE_ROUTE_PLAN")
        if not bounded_decimal(self.unplanned_remainder):
            raise RouteValidationError("INVALID_REMAINDER")
        if self.reference_price is not None and not bounded_decimal(
            self.reference_price, positive=True
        ):
            raise RouteValidationError("INVALID_REFERENCE_PRICE")
        if self.status == "PARTIALLY_PLANNED" and (
            not self.children or self.unplanned_remainder <= 0
        ):
            raise RouteValidationError("INVALID_PARTIAL_PLAN")
        if self.status != "PARTIALLY_PLANNED" and self.unplanned_remainder != 0:
            raise RouteValidationError("INVALID_REMAINDER")
        if self.status in {"BLOCKED", "FROZEN"} and self.children:
            raise RouteValidationError("BLOCKED_PLAN_HAS_CHILDREN")


@dataclass(frozen=True, slots=True)
class ExecutionEvidenceV1(_NoCopy):
    execution_id: str
    quantity: Decimal
    event_time_ns: int | None = None

    @_decimal_context
    def __post_init__(self) -> None:
        if not _identifier(self.execution_id) or not bounded_decimal(self.quantity, positive=True):
            raise RouteValidationError("INVALID_EXECUTION_EVIDENCE")
        if self.event_time_ns is not None and not _utc_ns(self.event_time_ns):
            raise RouteValidationError("INVALID_EXECUTION_EVIDENCE")


@dataclass(frozen=True, slots=True)
class RerouteEvidenceV1(_NoCopy):
    """Typed broker assertions; construction alone never confirms a child."""

    venue_id: str
    broker_outcome: BrokerOutcome
    reconciled_at_ns: int | None
    live_qty: Decimal | None
    in_flight_qty: Decimal | None
    executions: tuple[ExecutionEvidenceV1, ...] = ()
    cancel_requested: bool = False
    latency_breached: bool = False
    gtd_expired: bool = False

    @_decimal_context
    def __post_init__(self) -> None:
        if not _identifier(self.venue_id) or not _identifier(self.broker_outcome):
            raise RouteValidationError("INVALID_REROUTE_EVIDENCE")
        if self.reconciled_at_ns is not None and not _utc_ns(self.reconciled_at_ns):
            raise RouteValidationError("INVALID_REROUTE_EVIDENCE")
        if any(
            value is not None and not bounded_decimal(value)
            for value in (self.live_qty, self.in_flight_qty)
        ):
            raise RouteValidationError("INVALID_REROUTE_EVIDENCE")
        if not _tuple_of(self.executions, ExecutionEvidenceV1):
            raise RouteValidationError("MUTABLE_EXECUTION_EVIDENCE")
        if any(
            type(value) is not bool
            for value in (self.cancel_requested, self.latency_breached, self.gtd_expired)
        ):
            raise RouteValidationError("INVALID_BOOLEAN_EVIDENCE")


# Only an in-process trusted broker adapter may obtain this module-private token.
# Caller-constructed reports and reconciliations have no dispatch authority.
_TRUSTED_ADAPTER_TOKEN = object()
_BROKER_REPORT_SEAL = object()
_RECONCILIATION_TOKEN = object()
_RECONCILED_SEAL = object()


@dataclass(frozen=True, slots=True)
class BrokerReportV1(_NoCopy):
    """Venue and child-bound broker report issued by the trusted adapter."""

    parent_request_digest: str
    policy_digest: str
    account_id: str
    child_sequences: tuple[int, ...]
    broker_order_ids: tuple[str, ...]
    terminal_receipt_ids: tuple[str, ...]
    reconciliation_receipt_id: str
    evidence: RerouteEvidenceV1
    _adapter_token: InitVar[object] = None
    _seal: object = field(init=False, repr=False, compare=False)

    def __post_init__(self, _adapter_token: object) -> None:
        if _adapter_token is not _TRUSTED_ADAPTER_TOKEN:
            raise RouteValidationError("UNTRUSTED_BROKER_REPORT")
        if not all(
            isinstance(value, str) and _DIGEST.fullmatch(value)
            for value in (self.parent_request_digest, self.policy_digest)
        ) or not _identifier(self.account_id):
            raise RouteValidationError("INVALID_BROKER_REPORT_BINDING")
        if (
            not isinstance(self.child_sequences, tuple)
            or not self.child_sequences
            or any(type(value) is not int or value <= 0 for value in self.child_sequences)
            or len(set(self.child_sequences)) != len(self.child_sequences)
            or not _identifiers(self.broker_order_ids)
            or not _identifiers(self.terminal_receipt_ids)
            or not _identifier(self.reconciliation_receipt_id)
            or not isinstance(self.evidence, RerouteEvidenceV1)
            or len(self.child_sequences) != len(self.broker_order_ids)
            or len(self.child_sequences) != len(self.terminal_receipt_ids)
            or len(set(self.broker_order_ids)) != len(self.broker_order_ids)
            or len(set(self.terminal_receipt_ids)) != len(self.terminal_receipt_ids)
        ):
            raise RouteValidationError("INVALID_BROKER_REPORT_BINDING")
        object.__setattr__(self, "_seal", _BROKER_REPORT_SEAL)


@dataclass(frozen=True, slots=True)
class ReconciledRerouteEvidenceV1(_NoCopy):
    """Reconciliation transition output bound to one prior plan object."""

    parent_request_digest: str
    policy_digest: str
    account_id: str
    previous_plan: RoutePlanV1
    evidence: tuple[RerouteEvidenceV1, ...]
    _transition_token: InitVar[object] = None
    _seal: object = field(init=False, repr=False, compare=False)

    def __post_init__(self, _transition_token: object) -> None:
        if _transition_token is not _RECONCILIATION_TOKEN:
            raise RouteValidationError("UNCONFIRMED_BROKER_EVIDENCE")
        if (
            not isinstance(self.parent_request_digest, str)
            or not _DIGEST.fullmatch(self.parent_request_digest)
            or not isinstance(self.policy_digest, str)
            or not _DIGEST.fullmatch(self.policy_digest)
            or not _identifier(self.account_id)
            or not isinstance(self.previous_plan, RoutePlanV1)
            or not _tuple_of(self.evidence, RerouteEvidenceV1)
        ):
            raise RouteValidationError("INVALID_RECONCILED_EVIDENCE")
        object.__setattr__(self, "_seal", _RECONCILED_SEAL)
