"""Pure venue ranking and reroute eligibility. No I/O or dispatch capability."""

from __future__ import annotations

import json
import re
from decimal import Decimal, Inexact, localcontext
from fractions import Fraction
from hashlib import sha256

from .models import (
    _BROKER_REPORT_SEAL,
    _RECONCILED_SEAL,
    _RECONCILIATION_TOKEN,
    KERNEL_DECIMAL_CONTEXT,
    BrokerReportV1,
    ExecutionEvidenceV1,
    ReconciledRerouteEvidenceV1,
    RejectedVenueV1,
    RerouteEvidenceV1,
    RouteCandidateV1,
    RoutePlanInputV1,
    RoutePlanV1,
    RouteValidationError,
    VenueQuoteV1,
    bounded_decimal,
    canonical_decimal,
    exact_multiple,
)
from .slicing import SlicePlanningError, floor_lot, make_slices

_BPS = Decimal("10000")
_VALID_ORDER_TYPES = frozenset({"MARKET", "LIMIT"})
_VALID_TIFS = frozenset({"IOC", "FOK", "DAY", "GTD"})


def _valid_decimal(value: object, *, positive: bool = False) -> bool:
    return bounded_decimal(value, positive=positive)


def _multiple(value: Decimal, quantum: Decimal) -> bool:
    return exact_multiple(value, quantum)


def _fraction(value: Decimal) -> Fraction:
    numerator, denominator = value.as_integer_ratio()
    return Fraction(numerator, denominator)


def _display_cost(
    adverse: Decimal, reference: Decimal, fee: Decimal, history: Decimal
) -> tuple[Decimal, Decimal]:
    with localcontext(KERNEL_DECIMAL_CONTEXT) as display_context:
        display_context.traps[Inexact] = False
        adverse_bps = adverse / reference * _BPS
        return adverse_bps, adverse_bps + history + fee


def _validate_request(request: RoutePlanInputV1) -> None:
    if not re.fullmatch(r"[0-9a-fA-F]{64}", request.parent_request_digest):
        raise RouteValidationError("parent_request_digest must be a SHA-256 hex digest")
    if not all((request.account_id, request.instrument_id, request.instrument_mapping_id)):
        raise RouteValidationError("account and dated instrument mapping are required")
    if not request.policy_revision:
        raise RouteValidationError("policy revision is required")
    if request.side not in {"BUY", "SELL"}:
        raise RouteValidationError("unsupported side")
    if request.routing_policy not in {"best_price", "best_liquidity", "latency_first", "custom"}:
        raise RouteValidationError("unsupported routing policy")
    if request.tactic not in {"DIRECT", "TWAP", "VWAP", "ICEBERG"}:
        raise RouteValidationError("unsupported tactic")
    if request.order_type not in _VALID_ORDER_TYPES or request.tif not in _VALID_TIFS:
        raise RouteValidationError("unsupported order type or TIF")
    if request.order_type == "LIMIT" and request.limit_price is None:
        raise RouteValidationError("limit order requires a price")
    for label, value in (
        ("quantity", request.quantity),
        ("lot_size", request.lot_size),
        ("tick_size", request.tick_size),
        ("multiplier", request.multiplier),
        ("max_slice_qty", request.max_slice_qty),
        ("depth_factor", request.depth_factor),
    ):
        if not _valid_decimal(value, positive=True):
            raise RouteValidationError(f"{label} must be a positive finite Decimal")
    for label, value in (
        ("hard_slippage_bps", request.hard_slippage_bps),
        ("latency_budget_ms", request.latency_budget_ms),
        ("min_child_qty", request.min_child_qty),
    ):
        if not _valid_decimal(value):
            raise RouteValidationError(f"{label} must be a nonnegative finite Decimal")
    if request.depth_factor > 1:
        raise RouteValidationError("depth_factor cannot exceed observed depth")
    if not _multiple(request.quantity, request.lot_size):
        raise RouteValidationError("INVALID_LOT_MULTIPLE")
    if request.limit_price is not None and (
        not _valid_decimal(request.limit_price, positive=True)
        or not _multiple(request.limit_price, request.tick_size)
    ):
        raise RouteValidationError("limit price must be a positive tick multiple")
    if (
        request.mapping_valid_from_ns < 0
        or request.mapping_valid_from_ns > request.decision_time_ns
        or request.mapping_valid_until_ns <= request.decision_time_ns
    ):
        raise RouteValidationError("dated mapping is not effective at decision time")
    if request.decision_time_ns < 0 or any(
        value < 0
        for value in (
            request.max_quote_age_ns,
            request.max_ping_age_ns,
            request.max_reconciliation_age_ns,
        )
    ):
        raise RouteValidationError("invalid decision time or freshness bound")
    if request.tif == "GTD" and request.gtd_expiry_ns is None:
        raise RouteValidationError("GTD requires an expiry")
    if request.gtd_expiry_ns is not None and request.gtd_expiry_ns <= 0:
        raise RouteValidationError("invalid GTD expiry")
    if not 0 < request.max_venue_hops <= 32:
        raise RouteValidationError("max_venue_hops must be between 1 and 32")
    if not isinstance(request.allowed_venues, tuple):
        raise RouteValidationError("allowed_venues must be an immutable tuple")
    if not isinstance(request.venue_order, tuple) or not isinstance(request.venue_quotes, tuple):
        raise RouteValidationError("venue order and complete quote snapshot must be tuples")
    if any(not venue for venue in request.allowed_venues + request.venue_order):
        raise RouteValidationError("empty venue ID")
    if len(set(request.allowed_venues)) != len(request.allowed_venues):
        raise RouteValidationError("duplicate allowed venue")
    if len(set(request.venue_order)) != len(request.venue_order):
        raise RouteValidationError("duplicate configured venue")
    if not set(request.allowed_venues) <= set(request.venue_order):
        raise RouteValidationError("configured venue order omits an allowed venue")
    quote_ids = [quote.venue_id for quote in request.venue_quotes]
    if len(set(quote_ids)) != len(quote_ids):
        raise RouteValidationError("duplicate venue quote")
    if not set(request.allowed_venues) <= set(quote_ids):
        raise RouteValidationError("incomplete venue snapshot")
    if request.routing_policy == "custom" and (
        len(set(request.custom_venue_order)) != len(request.custom_venue_order)
        or set(request.custom_venue_order) != set(request.allowed_venues)
    ):
        raise RouteValidationError("custom policy requires a complete venue priority")


def _policy_digest(request: RoutePlanInputV1) -> str:
    params = request.tactic_params
    document = {
        "version": "EXEC-ROUTE-001-v0.1",
        "revision": request.policy_revision,
        "account": request.account_id,
        "instrument": request.instrument_id,
        "mapping": request.instrument_mapping_id,
        "mapping_from_ns": request.mapping_valid_from_ns,
        "mapping_until_ns": request.mapping_valid_until_ns,
        "side": request.side,
        "quantity": canonical_decimal(request.quantity),
        "limit_price": None
        if request.limit_price is None
        else canonical_decimal(request.limit_price),
        "lot_size": canonical_decimal(request.lot_size),
        "tick_size": canonical_decimal(request.tick_size),
        "multiplier": canonical_decimal(request.multiplier),
        "allowed": sorted(request.allowed_venues),
        "venue_order": request.venue_order,
        "custom_order": request.custom_venue_order,
        "policy": request.routing_policy,
        "hops": request.max_venue_hops,
        "order_type": request.order_type,
        "tif": request.tif,
        "gtd_expiry_ns": request.gtd_expiry_ns,
        "session_close_ns": request.session_close_ns,
        "hard_slippage_bps": canonical_decimal(request.hard_slippage_bps),
        "latency_budget_ms": canonical_decimal(request.latency_budget_ms),
        "max_quote_age_ns": request.max_quote_age_ns,
        "max_ping_age_ns": request.max_ping_age_ns,
        "max_reconciliation_age_ns": request.max_reconciliation_age_ns,
        "max_slice_qty": canonical_decimal(request.max_slice_qty),
        "min_child_qty": canonical_decimal(request.min_child_qty),
        "depth_factor": canonical_decimal(request.depth_factor),
        "tactic": request.tactic,
        "tactic_params": None
        if params is None
        else {
            "duration_ns": params.duration_ns,
            "buckets": params.buckets,
            "peak_qty": None if params.peak_qty is None else canonical_decimal(params.peak_qty),
            "jitter_seed": params.jitter_seed,
            "jitter_max_ns": params.jitter_max_ns,
            "curve": None
            if params.volume_curve is None
            else {
                "revision": params.volume_curve.revision,
                "weights": [canonical_decimal(weight) for weight in params.volume_curve.weights],
            },
        },
    }
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"))
    return sha256(canonical.encode()).hexdigest()


def _quote_reasons(request: RoutePlanInputV1, quote: VenueQuoteV1) -> tuple[str, ...]:
    reasons: list[str] = []
    if quote.health != "HEALTHY":
        reasons.append("VENUE_NOT_HEALTHY")
    if quote.permission is not True:
        reasons.append("VENUE_NOT_PERMITTED")
    if quote.mapped_instrument_id != request.instrument_id:
        reasons.append("INSTRUMENT_NOT_MAPPED")
    if request.order_type not in quote.supported_order_types:
        reasons.append("ORDER_TYPE_UNSUPPORTED")
    if request.tif not in quote.supported_tifs:
        reasons.append("TIF_UNSUPPORTED")
    if (
        quote.event_time_ns is None
        or quote.receive_time_ns is None
        or quote.event_time_ns < 0
        or quote.event_time_ns > quote.receive_time_ns
        or quote.receive_time_ns > request.decision_time_ns
    ):
        reasons.append("UNKNOWN_QUOTE_TIME")
    elif request.decision_time_ns - quote.event_time_ns > request.max_quote_age_ns:
        reasons.append("STALE_QUOTE")
    if (
        quote.ping_time_ns is None
        or quote.ping_time_ns < 0
        or quote.ping_time_ns > request.decision_time_ns
        or not _valid_decimal(quote.ping_ms)
    ):
        reasons.append("UNKNOWN_PING")
    elif request.decision_time_ns - quote.ping_time_ns > request.max_ping_age_ns:
        reasons.append("STALE_PING")
    elif quote.ping_ms is not None and quote.ping_ms > request.latency_budget_ms:
        reasons.append("LATENCY_BUDGET")
    if not all(
        _valid_decimal(value, positive=True)
        for value in (quote.bid, quote.ask, quote.bid_depth, quote.ask_depth)
    ):
        reasons.append("UNKNOWN_QUOTE")
    elif quote.bid is not None and quote.ask is not None and quote.bid >= quote.ask:
        reasons.append("CROSSED_QUOTE")
    if not _valid_decimal(quote.lot_size, positive=True) or not _valid_decimal(
        quote.tick_size, positive=True
    ):
        reasons.append("UNMAPPED_LOT_TICK")
    else:
        assert quote.lot_size is not None and quote.tick_size is not None
        if not (
            _multiple(quote.lot_size, request.lot_size)
            or _multiple(request.lot_size, quote.lot_size)
        ):
            reasons.append("LOT_INCOMPATIBLE")
        if (
            quote.bid is not None
            and quote.ask is not None
            and all(_valid_decimal(value, positive=True) for value in (quote.bid, quote.ask))
            and (
                not _multiple(quote.bid, quote.tick_size)
                or not _multiple(quote.ask, quote.tick_size)
            )
        ):
            reasons.append("PRICE_TICK")
    if not _valid_decimal(quote.fee_bps) or not _valid_decimal(quote.historical_slippage_bps):
        reasons.append("UNKNOWN_COST")
    if request.side == "BUY":
        if (
            quote.ask is not None
            and _valid_decimal(quote.ask, positive=True)
            and quote.own_ask is not None
            and (not _valid_decimal(quote.own_ask, positive=True) or quote.own_ask <= quote.ask)
        ):
            reasons.append("OWN_QUOTE_CROSS")
        if (
            request.limit_price is not None
            and quote.ask is not None
            and _valid_decimal(quote.ask, positive=True)
            and quote.ask > request.limit_price
        ):
            reasons.append("LIMIT_PRICE")
    else:
        if (
            quote.bid is not None
            and _valid_decimal(quote.bid, positive=True)
            and quote.own_bid is not None
            and (not _valid_decimal(quote.own_bid, positive=True) or quote.own_bid >= quote.bid)
        ):
            reasons.append("OWN_QUOTE_CROSS")
        if (
            request.limit_price is not None
            and quote.bid is not None
            and _valid_decimal(quote.bid, positive=True)
            and quote.bid < request.limit_price
        ):
            reasons.append("LIMIT_PRICE")
    return tuple(dict.fromkeys(reasons))


def _rank_key(
    request: RoutePlanInputV1, candidate: RouteCandidateV1, exact_costs: dict[str, Fraction]
) -> tuple[Decimal | Fraction | int | str, ...]:
    configured = {venue: i for i, venue in enumerate(request.venue_order)}
    tie = (configured[candidate.venue_id], candidate.venue_id)
    if request.routing_policy == "best_price":
        return (exact_costs[candidate.venue_id], *tie)
    if request.routing_policy == "best_liquidity":
        return (-candidate.top_depth, exact_costs[candidate.venue_id], *tie)
    if request.routing_policy == "latency_first":
        return (candidate.expected_latency_ms, exact_costs[candidate.venue_id], *tie)
    custom = {venue: i for i, venue in enumerate(request.custom_venue_order)}
    return (custom[candidate.venue_id], *tie)


def _plan_route(
    request: RoutePlanInputV1,
    quantity: Decimal,
    allowed: frozenset[str],
    hop_budget: int,
    attempted: tuple[str, ...] = (),
) -> RoutePlanV1:
    digest = _policy_digest(request)
    quotes = {quote.venue_id: quote for quote in request.venue_quotes}
    preliminary: list[VenueQuoteV1] = []
    rejected: list[RejectedVenueV1] = []
    for venue in request.venue_order:
        if venue not in allowed:
            continue
        quote = quotes[venue]
        reasons = _quote_reasons(request, quote)
        if reasons:
            rejected.append(RejectedVenueV1(venue, reasons))
        else:
            preliminary.append(quote)
    if not preliminary:
        return RoutePlanV1(
            request.parent_request_digest,
            digest,
            "BLOCKED",
            None,
            (),
            tuple(rejected),
            (),
            ("NO_ELIGIBLE_VENUE",),
        )

    prices: list[Decimal] = []
    for quote in preliminary:
        price = quote.ask if request.side == "BUY" else quote.bid
        assert price is not None
        prices.append(price)
    reference = min(prices) if request.side == "BUY" else max(prices)
    candidates: list[RouteCandidateV1] = []
    exact_costs: dict[str, Fraction] = {}
    for quote in preliminary:
        price = quote.ask if request.side == "BUY" else quote.bid
        depth = quote.ask_depth if request.side == "BUY" else quote.bid_depth
        assert price is not None and depth is not None
        assert quote.lot_size is not None and quote.fee_bps is not None
        assert quote.historical_slippage_bps is not None and quote.ping_ms is not None
        effective_lot = max(request.lot_size, quote.lot_size)
        cap = floor_lot(min(request.max_slice_qty, depth * request.depth_factor), effective_lot)
        adverse = (price - reference) if request.side == "BUY" else (reference - price)
        exact_cost = (
            _fraction(adverse) * 10000 / _fraction(reference)
            + _fraction(quote.historical_slippage_bps)
            + _fraction(quote.fee_bps)
        )
        adverse_bps, cost = _display_cost(
            adverse, reference, quote.fee_bps, quote.historical_slippage_bps
        )
        candidate_reasons: list[str] = []
        if exact_cost > _fraction(request.hard_slippage_bps):
            candidate_reasons.append("HARD_SLIPPAGE")
        if cap <= 0:
            candidate_reasons.append("ZERO_SLICE_CAP")
        if cap < request.min_child_qty:
            candidate_reasons.append("BELOW_CHILD_MINIMUM")
        if candidate_reasons:
            rejected.append(RejectedVenueV1(quote.venue_id, tuple(candidate_reasons)))
            continue
        exact_costs[quote.venue_id] = exact_cost
        candidates.append(
            RouteCandidateV1(quote.venue_id, 0, price, depth, cap, adverse_bps, cost, quote.ping_ms)
        )
    candidates.sort(key=lambda candidate: _rank_key(request, candidate, exact_costs))
    ranked = tuple(
        RouteCandidateV1(
            candidate.venue_id,
            index + 1,
            candidate.executable_price,
            candidate.top_depth,
            candidate.slice_cap_qty,
            candidate.adverse_slippage_bps,
            candidate.expected_cost_bps,
            candidate.expected_latency_ms,
        )
        for index, candidate in enumerate(candidates)
    )
    rejected.sort(key=lambda item: (request.venue_order.index(item.venue_id), item.venue_id))
    if not ranked:
        return RoutePlanV1(
            request.parent_request_digest,
            digest,
            "BLOCKED",
            reference,
            (),
            tuple(rejected),
            (),
            ("NO_ELIGIBLE_VENUE",),
        )

    remaining = quantity
    allocations: list[tuple[str, Decimal, Decimal]] = []
    for candidate in ranked[:hop_budget]:
        quote = quotes[candidate.venue_id]
        assert quote.lot_size is not None
        lot = max(request.lot_size, quote.lot_size)
        available = floor_lot(candidate.top_depth * request.depth_factor, lot)
        take = floor_lot(min(remaining, available), lot)
        if take > 0:
            allocations.append((candidate.venue_id, take, lot))
            remaining -= take
        if remaining == 0:
            break
    if not allocations:
        return RoutePlanV1(
            request.parent_request_digest,
            digest,
            "BLOCKED",
            reference,
            ranked,
            tuple(rejected),
            (),
            ("INSUFFICIENT_OBSERVED_DEPTH",),
        )
    try:
        children = make_slices(request, tuple(allocations))
    except SlicePlanningError as exc:
        return RoutePlanV1(
            request.parent_request_digest,
            digest,
            "BLOCKED",
            reference,
            ranked,
            tuple(rejected),
            (),
            (str(exc),),
        )
    if sum((child.quantity for child in children), Decimal("0")) + remaining != quantity:
        raise AssertionError("slice conservation invariant")
    if request.tif == "FOK" and (len(children) != 1 or remaining != 0):
        return RoutePlanV1(
            request.parent_request_digest,
            digest,
            "BLOCKED",
            reference,
            ranked,
            tuple(rejected),
            (),
            ("FOK_REQUIRES_SINGLE_CHILD",),
        )
    if request.tif == "IOC" and request.tactic in {"TWAP", "VWAP"}:
        return RoutePlanV1(
            request.parent_request_digest,
            digest,
            "BLOCKED",
            reference,
            ranked,
            tuple(rejected),
            (),
            ("IOC_CANNOT_BE_SCHEDULED",),
        )
    used = tuple(dict.fromkeys(child.venue_id for child in children))
    return RoutePlanV1(
        request.parent_request_digest,
        digest,
        "PLANNED" if remaining == 0 else "PARTIALLY_PLANNED",
        reference,
        ranked,
        tuple(rejected),
        children,
        reason_codes=() if remaining == 0 else ("INSUFFICIENT_OBSERVED_DEPTH",),
        attempted_venues=(*attempted, *used),
        unplanned_remainder=remaining,
    )


def plan_route(request: RoutePlanInputV1) -> RoutePlanV1:
    """Return an offline preview; it is never a dispatch permit or reservation."""
    with localcontext(KERNEL_DECIMAL_CONTEXT):
        try:
            _validate_request(request)
            if (
                request.tif == "DAY"
                and request.session_close_ns is not None
                and request.decision_time_ns >= request.session_close_ns
            ):
                return _frozen(request, ("DAY_EXPIRED_CANCEL_REQUESTED_UNCONFIRMED",))
            if (
                request.tif == "GTD"
                and request.gtd_expiry_ns is not None
                and request.decision_time_ns >= request.gtd_expiry_ns
            ):
                return _frozen(request, ("GTD_EXPIRED_CANCEL_REQUESTED_UNCONFIRMED",))
            return _plan_route(
                request, request.quantity, frozenset(request.allowed_venues), request.max_venue_hops
            )
        except Inexact as exc:
            raise RouteValidationError("PRECISION_EXCEEDED") from exc


def _frozen(
    request: RoutePlanInputV1, reasons: tuple[str, ...], attempted: tuple[str, ...] = ()
) -> RoutePlanV1:
    actions: list[str] = []
    if any("CANCEL_REQUESTED_UNCONFIRMED" in reason for reason in reasons):
        actions.extend(("REQUEST_CANCEL", "RECONCILE"))
    elif any(
        reason
        in {
            "PRIOR_PLAN_MISMATCH",
            "MISSING_REROUTE_EVIDENCE",
            "INCOMPLETE_REROUTE_EVIDENCE",
            "DUPLICATE_OR_INVALID_EXECUTION_EVIDENCE",
            "RECONCILIATION_NOT_FRESH",
            "LIVE_OR_IN_FLIGHT_QUANTITY",
            "UNCONFIRMED_BROKER_EVIDENCE",
        }
        for reason in reasons
    ):
        actions.append("RECONCILE")
    if "POST_GTD_FILL_DISCREPANCY_OPERATOR_ALERT" in reasons:
        actions.extend(("RECORD_DISCREPANCY", "ALERT_OPERATOR"))
    return RoutePlanV1(
        request.parent_request_digest,
        _policy_digest(request),
        "FROZEN",
        None,
        (),
        (),
        (),
        tuple(dict.fromkeys(reasons)),
        attempted,
        tuple(actions),
    )


def _execution_total(evidence: tuple[RerouteEvidenceV1, ...]) -> Decimal | None:
    executions_by_venue: dict[tuple[str, str], ExecutionEvidenceV1] = {}
    total = Decimal("0")
    for item in evidence:
        for execution in item.executions:
            key = (item.venue_id, execution.execution_id)
            if (
                not isinstance(execution, ExecutionEvidenceV1)
                or not execution.execution_id
                or not _valid_decimal(execution.quantity, positive=True)
                or (
                    execution.event_time_ns is not None
                    and (
                        item.reconciled_at_ns is None
                        or not 0 <= execution.event_time_ns <= item.reconciled_at_ns
                    )
                )
            ):
                return None
            previous = executions_by_venue.get(key)
            if previous is not None:
                if previous != execution:
                    raise RouteValidationError("DISCREPANCY")
                continue
            executions_by_venue[key] = execution
            total += execution.quantity
    return total


def _reconcile_route_evidence(
    request: RoutePlanInputV1,
    previous_plan: RoutePlanV1,
    reports: tuple[BrokerReportV1, ...],
) -> ReconciledRerouteEvidenceV1:
    """Earn a terminal reconciliation only from sealed broker adapter reports."""
    with localcontext(KERNEL_DECIMAL_CONTEXT):
        _validate_request(request)
        if (
            previous_plan.parent_request_digest != request.parent_request_digest
            or previous_plan.policy_digest != _policy_digest(request)
            or previous_plan.status not in {"PLANNED", "PARTIALLY_PLANNED"}
            or not isinstance(reports, tuple)
        ):
            raise RouteValidationError("PRIOR_PLAN_MISMATCH")
        child_sequences: dict[str, set[int]] = {}
        for child in previous_plan.children:
            child_sequences.setdefault(child.venue_id, set()).add(child.sequence)
        if not child_sequences or len(reports) != len(child_sequences):
            raise RouteValidationError("INCOMPLETE_REROUTE_EVIDENCE")
        seen_venues: set[str] = set()
        seen_orders: set[tuple[str, str]] = set()
        seen_terminal_receipts: set[tuple[str, str]] = set()
        seen_reconciliation_receipts: set[tuple[str, str]] = set()
        evidence: list[RerouteEvidenceV1] = []
        for report in reports:
            if (
                not isinstance(report, BrokerReportV1) or report._seal is not _BROKER_REPORT_SEAL  # noqa: SLF001 - same-package seal check
            ):
                raise RouteValidationError("UNTRUSTED_BROKER_REPORT")
            item = report.evidence
            if (
                report.parent_request_digest != request.parent_request_digest
                or report.policy_digest != previous_plan.policy_digest
                or report.account_id != request.account_id
                or item.venue_id not in child_sequences
                or item.venue_id in seen_venues
                or set(report.child_sequences) != child_sequences[item.venue_id]
                or not seen_orders.isdisjoint(
                    (item.venue_id, order_id) for order_id in report.broker_order_ids
                )
                or not seen_terminal_receipts.isdisjoint(
                    (item.venue_id, receipt_id) for receipt_id in report.terminal_receipt_ids
                )
                or (item.venue_id, report.reconciliation_receipt_id) in seen_reconciliation_receipts
            ):
                raise RouteValidationError("INVALID_BROKER_REPORT_BINDING")
            if item.broker_outcome not in {"CANCELED", "REJECTED"}:
                raise RouteValidationError("UNCONFIRMED_BROKER_EVIDENCE")
            if (
                item.reconciled_at_ns is None
                or item.reconciled_at_ns > request.decision_time_ns
                or request.decision_time_ns - item.reconciled_at_ns
                > request.max_reconciliation_age_ns
                or item.live_qty != 0
                or item.in_flight_qty != 0
            ):
                raise RouteValidationError("UNCONFIRMED_BROKER_EVIDENCE")
            seen_venues.add(item.venue_id)
            seen_orders.update((item.venue_id, order_id) for order_id in report.broker_order_ids)
            seen_terminal_receipts.update(
                (item.venue_id, receipt_id) for receipt_id in report.terminal_receipt_ids
            )
            seen_reconciliation_receipts.add((item.venue_id, report.reconciliation_receipt_id))
            evidence.append(item)
        if seen_venues != set(child_sequences):
            raise RouteValidationError("INCOMPLETE_REROUTE_EVIDENCE")
        ordered = tuple(sorted(evidence, key=lambda item: item.venue_id))
        filled = _execution_total(ordered)
        if (
            filled is None
            or filled > request.quantity
            or not exact_multiple(filled, request.lot_size)
        ):
            raise RouteValidationError("DUPLICATE_OR_INVALID_EXECUTION_EVIDENCE")
        return ReconciledRerouteEvidenceV1(
            request.parent_request_digest,
            previous_plan.policy_digest,
            request.account_id,
            previous_plan,
            ordered,
            _transition_token=_RECONCILIATION_TOKEN,
        )


def reconcile_route_evidence(
    request: RoutePlanInputV1,
    previous_plan: RoutePlanV1,
    reports: tuple[BrokerReportV1, ...],
) -> ReconciledRerouteEvidenceV1:
    """Validate trusted reports and mint the only reroute-unlocking record."""
    with localcontext(KERNEL_DECIMAL_CONTEXT):
        try:
            return _reconcile_route_evidence(request, previous_plan, reports)
        except Inexact as exc:
            raise RouteValidationError("PRECISION_EXCEEDED") from exc


def _plan_reroute(
    request: RoutePlanInputV1,
    previous_plan: RoutePlanV1,
    evidence: ReconciledRerouteEvidenceV1 | RerouteEvidenceV1 | tuple[RerouteEvidenceV1, ...],
) -> RoutePlanV1:
    """Plan remaining quantity only after confirmed terminal outcomes and reconciliation.

    Timeout, lost ACK and cancel-request states never prove terminal broker state.
    A caller must provide evidence for every venue in the prior preview.
    """
    _validate_request(request)
    if (
        previous_plan.parent_request_digest != request.parent_request_digest
        or previous_plan.policy_digest != _policy_digest(request)
        or previous_plan.status not in {"PLANNED", "PARTIALLY_PLANNED"}
    ):
        return _frozen(request, ("PRIOR_PLAN_MISMATCH",))
    prior_venues = {child.venue_id for child in previous_plan.children}
    attempted = previous_plan.attempted_venues or tuple(sorted(prior_venues))
    if not prior_venues:
        return _frozen(request, ("MISSING_REROUTE_EVIDENCE",))
    if not isinstance(evidence, ReconciledRerouteEvidenceV1):
        raw = (evidence,) if isinstance(evidence, RerouteEvidenceV1) else evidence
        reasons = ["UNCONFIRMED_BROKER_EVIDENCE"]
        if isinstance(raw, tuple) and any(
            isinstance(item, RerouteEvidenceV1)
            and item.broker_outcome not in {"CANCELED", "REJECTED"}
            for item in raw
        ):
            reasons.append("CANCEL_REQUESTED_UNCONFIRMED")
        return _frozen(request, tuple(reasons), attempted)
    if (
        evidence._seal is not _RECONCILED_SEAL  # noqa: SLF001 - same-package seal check
        or evidence.parent_request_digest != request.parent_request_digest
        or evidence.policy_digest != previous_plan.policy_digest
        or evidence.account_id != request.account_id
        or evidence.previous_plan is not previous_plan
    ):
        return _frozen(request, ("UNCONFIRMED_BROKER_EVIDENCE",), attempted)
    evidence = evidence.evidence
    if {item.venue_id for item in evidence} != prior_venues or len(evidence) != len(prior_venues):
        return _frozen(request, ("INCOMPLETE_REROUTE_EVIDENCE",))
    filled = _execution_total(evidence)
    if filled is None or filled > request.quantity or not exact_multiple(filled, request.lot_size):
        return _frozen(request, ("DUPLICATE_OR_INVALID_EXECUTION_EVIDENCE",))
    late_fill = request.gtd_expiry_ns is not None and any(
        (item.gtd_expired and item.executions)
        or any(
            execution.event_time_ns is not None and execution.event_time_ns >= request.gtd_expiry_ns
            for execution in item.executions
        )
        for item in evidence
    )
    if (
        request.tif == "DAY"
        and request.session_close_ns is not None
        and request.decision_time_ns >= request.session_close_ns
    ):
        return _frozen(request, ("DAY_EXPIRED_CANCEL_REQUESTED_UNCONFIRMED",), attempted)
    if (
        request.tif == "GTD"
        and request.gtd_expiry_ns is not None
        and request.decision_time_ns >= request.gtd_expiry_ns
    ):
        reasons = ["GTD_EXPIRED_CANCEL_REQUESTED_UNCONFIRMED"]
        if late_fill:
            reasons.append("POST_GTD_FILL_DISCREPANCY_OPERATOR_ALERT")
        return _frozen(request, tuple(reasons), attempted)
    reasons = []
    for item in evidence:
        if item.broker_outcome not in {"REJECTED", "CANCELED"}:
            reasons.append("CANCEL_REQUESTED_UNCONFIRMED")
            reasons.append(item.broker_outcome)
            continue
        if (
            item.reconciled_at_ns is None
            or item.reconciled_at_ns < 0
            or item.reconciled_at_ns > request.decision_time_ns
            or request.decision_time_ns - item.reconciled_at_ns > request.max_reconciliation_age_ns
        ):
            reasons.append("RECONCILIATION_NOT_FRESH")
        if (
            not _valid_decimal(item.live_qty)
            or not _valid_decimal(item.in_flight_qty)
            or item.live_qty != 0
            or item.in_flight_qty != 0
        ):
            reasons.append("LIVE_OR_IN_FLIGHT_QUANTITY")
    if reasons:
        return _frozen(request, tuple(reasons), attempted)
    remaining = request.quantity - filled
    if remaining == 0:
        return _frozen(request, ("PARENT_ALREADY_FILLED",), attempted)
    available_venues = frozenset(request.allowed_venues) - set(attempted)
    if not available_venues:
        return _frozen(request, ("MAX_HOPS_OR_NO_NEW_VENUE",), attempted)
    if len(attempted) >= request.max_venue_hops:
        return _frozen(request, ("MAX_HOPS_OR_NO_NEW_VENUE",), attempted)
    # Prior venues have consumed hops; the planner may use only the remaining budget.
    return _plan_route(
        request, remaining, available_venues, request.max_venue_hops - len(attempted), attempted
    )


def plan_reroute(
    request: RoutePlanInputV1,
    previous_plan: RoutePlanV1,
    evidence: ReconciledRerouteEvidenceV1 | RerouteEvidenceV1 | tuple[RerouteEvidenceV1, ...],
) -> RoutePlanV1:
    """Assess evidence and return a safe offline reroute preview or freeze."""
    with localcontext(KERNEL_DECIMAL_CONTEXT):
        try:
            return _plan_reroute(request, previous_plan, evidence)
        except Inexact as exc:
            raise RouteValidationError("PRECISION_EXCEEDED") from exc
