"""Deterministic Decimal child scheduling with no future-liquidity assumptions."""

from __future__ import annotations

from decimal import Decimal, Inexact, localcontext
from fractions import Fraction
from hashlib import sha256

from .models import (
    KERNEL_DECIMAL_CONTEXT,
    ChildSliceV1,
    RoutePlanInputV1,
    RouteValidationError,
    TacticParamsV1,
    VolumeCurveV1,
)


class SlicePlanningError(ValueError):
    """A tactic or venue constraint denies a complete child schedule."""


def _lot_units(quantity: Decimal, lot: Decimal) -> int:
    quantity_num, quantity_den = quantity.as_integer_ratio()
    lot_num, lot_den = lot.as_integer_ratio()
    return (quantity_num * lot_den) // (quantity_den * lot_num)


def floor_lot(quantity: Decimal, lot: Decimal) -> Decimal:
    with localcontext(KERNEL_DECIMAL_CONTEXT):
        try:
            return Decimal(_lot_units(quantity, lot)) * lot
        except Inexact as exc:
            raise RouteValidationError("PRECISION_EXCEEDED") from exc


def _weighted_quantities(
    total: Decimal, lot: Decimal, weights: tuple[Decimal, ...]
) -> tuple[Decimal, ...]:
    units = _lot_units(total, lot)
    if (
        units < len(weights)
        or not weights
        or any(
            not isinstance(weight, Decimal) or not weight.is_finite() or weight <= 0
            for weight in weights
        )
    ):
        raise SlicePlanningError("ZERO_BUCKET_QUANTITY")
    exact_weights = [Fraction(weight) for weight in weights]
    weight_sum = sum(exact_weights, Fraction(0))
    exact = [Fraction(units) * weight / weight_sum for weight in exact_weights]
    whole = [int(value) for value in exact]
    remaining = units - sum(whole)
    by_remainder = sorted(range(len(weights)), key=lambda i: (-(exact[i] - whole[i]), i))
    for i in by_remainder[:remaining]:
        whole[i] += 1
    if any(value == 0 for value in whole):
        raise SlicePlanningError("ZERO_BUCKET_QUANTITY")
    return tuple(Decimal(value) * lot for value in whole)


def _bucket_time(request: RoutePlanInputV1, params: TacticParamsV1, index: int) -> int:
    assert params.duration_ns is not None
    assert params.buckets is not None
    base = request.decision_time_ns + index * params.duration_ns // params.buckets
    if params.jitter_max_ns == 0:
        return base
    if not isinstance(params.jitter_seed, str) or not params.jitter_seed:
        raise SlicePlanningError("MISSING_JITTER_SEED")
    if params.jitter_max_ns < 0 or params.jitter_max_ns * 2 * params.buckets >= params.duration_ns:
        raise SlicePlanningError("JITTER_OUT_OF_BOUNDS")
    digest = sha256(f"{params.jitter_seed}:{index}".encode()).digest()
    # Jitter stays within its bucket, including bucket zero.
    offset = int.from_bytes(digest[:8], "big") % (params.jitter_max_ns + 1)
    return base + offset


def _chunks(quantity: Decimal, lot: Decimal, cap: Decimal) -> tuple[Decimal, ...]:
    rounded_cap = floor_lot(cap, lot)
    if rounded_cap <= 0:
        raise SlicePlanningError("ZERO_SLICE_CAP")
    chunks: list[Decimal] = []
    remaining = quantity
    while remaining > 0:
        if len(chunks) >= 4096:
            raise SlicePlanningError("TOO_MANY_CHILDREN")
        size = min(remaining, rounded_cap)
        if size <= 0:
            raise SlicePlanningError("ZERO_CHILD_QUANTITY")
        chunks.append(size)
        remaining -= size
    return tuple(chunks)


def _make_slices(
    request: RoutePlanInputV1,
    allocations: tuple[tuple[str, Decimal, Decimal], ...],
) -> tuple[ChildSliceV1, ...]:
    """Expand venue allocations (venue, quantity, lot) into preview children."""
    params = request.tactic_params or TacticParamsV1()
    if not isinstance(params.jitter_max_ns, int) or params.jitter_max_ns < 0:
        raise SlicePlanningError("JITTER_OUT_OF_BOUNDS")
    if request.tactic in {"TWAP", "VWAP"}:
        if params.duration_ns is None or params.buckets is None:
            raise SlicePlanningError("MISSING_BUCKET_SCHEDULE")
        if (
            not isinstance(params.duration_ns, int)
            or not isinstance(params.buckets, int)
            or params.duration_ns <= 0
            or not 0 < params.buckets <= 1024
        ):
            raise SlicePlanningError("INVALID_BUCKET_SCHEDULE")
        if request.tactic == "VWAP" and (
            not isinstance(params.volume_curve, VolumeCurveV1)
            or not params.volume_curve.revision
            or not isinstance(params.volume_curve.weights, tuple)
            or len(params.volume_curve.weights) != params.buckets
        ):
            raise SlicePlanningError("MISSING_VERSIONED_VOLUME_CURVE")
    elif params.jitter_max_ns or params.jitter_seed:
        raise SlicePlanningError("JITTER_REQUIRES_BUCKET_TACTIC")

    if request.tactic == "ICEBERG" and (
        not isinstance(params.peak_qty, Decimal)
        or not params.peak_qty.is_finite()
        or params.peak_qty <= 0
    ):
        raise SlicePlanningError("MISSING_ICEBERG_PEAK")

    rows: list[tuple[int, str, Decimal, Decimal, Decimal]] = []
    for venue_id, allocated, lot in allocations:
        if request.tactic in {"TWAP", "VWAP"}:
            assert params.buckets is not None
            weights = (
                (Decimal("1"),) * params.buckets
                if request.tactic == "TWAP"
                else params.volume_curve.weights  # type: ignore[union-attr]
            )
            for index, bucket_qty in enumerate(_weighted_quantities(allocated, lot, weights)):
                when = _bucket_time(request, params, index)
                for size in _chunks(bucket_qty, lot, request.max_slice_qty):
                    if len(rows) >= 4096:
                        raise SlicePlanningError("TOO_MANY_CHILDREN")
                    rows.append((when, venue_id, size, size, lot))
        else:
            for size in _chunks(allocated, lot, request.max_slice_qty):
                display = size
                if request.tactic == "ICEBERG":
                    assert params.peak_qty is not None
                    display = min(size, floor_lot(params.peak_qty, lot))
                    if display <= 0:
                        raise SlicePlanningError("ZERO_ICEBERG_PEAK")
                if len(rows) >= 4096:
                    raise SlicePlanningError("TOO_MANY_CHILDREN")
                rows.append((request.decision_time_ns, venue_id, size, display, lot))

    # Arrival order and provider tuple order do not influence sequence numbering.
    venue_rank = {venue: index for index, venue in enumerate(request.venue_order)}
    rows.sort(key=lambda row: (row[0], venue_rank[row[1]], row[1]))
    if (
        request.tif == "DAY"
        and request.session_close_ns is not None
        and any(row[0] >= request.session_close_ns for row in rows)
    ):
        raise SlicePlanningError("DAY_EXPIRED_BEFORE_CHILD")
    if (
        request.tif == "GTD"
        and request.gtd_expiry_ns is not None
        and any(row[0] >= request.gtd_expiry_ns for row in rows)
    ):
        raise SlicePlanningError("GTD_EXPIRED_BEFORE_CHILD")
    if any(size < max(request.min_child_qty, lot) for _, _, size, _, lot in rows):
        raise SlicePlanningError("BELOW_CHILD_MINIMUM")
    return tuple(
        ChildSliceV1(
            sequence=index + 1,
            venue_id=venue,
            quantity=size,
            scheduled_at_ns=when,
            display_quantity=display,
            order_type=request.order_type,
            tif=request.tif,
            limit_price=request.limit_price,
        )
        for index, (when, venue, size, display, _) in enumerate(rows)
    )


def make_slices(
    request: RoutePlanInputV1,
    allocations: tuple[tuple[str, Decimal, Decimal], ...],
) -> tuple[ChildSliceV1, ...]:
    with localcontext(KERNEL_DECIMAL_CONTEXT):
        try:
            return _make_slices(request, allocations)
        except Inexact as exc:
            raise RouteValidationError("PRECISION_EXCEEDED") from exc
