"""Deterministic, simulation-only matching over the sealed BT-002 event clock."""

from __future__ import annotations

from dataclasses import InitVar, dataclass
from decimal import Decimal
from fractions import Fraction
from hashlib import sha256
from typing import Literal, cast

from leviathan_core.numeric import Ratio, canonical_json
from leviathan_core.numeric.ratio import quotient_final
from leviathan_core.seal import Issuer, SealError, require

from .clock import PreparedEventStreamV1, PreparedStreamManifestV1, verify_prepared_stream
from .costs import FeeModelV1, _reported
from .events import PreparedEventV1
from .latency import LatencyModelV1, sample_total_latency
from .orders import (
    _MAX_UTC_NS,
    _REQUEST_ISSUER,
    FillKernelError,
    FillPolicyError,
    FillRequestV1,
    FillValidationError,
    OrderRejectedError,
    _decimal,
    _FrozenInput,
    _ns,
    _text,
)

ExecutionMode = Literal[
    "L1_TOP_OF_BOOK",
    "L1_MIDPOINT_BENCHMARK",
    "L1_DEPTH_PROXY",
    "SYNTHETIC_L2",
    "RECORDED_L2",
]
QueueModel = Literal["PRICE_TIME_BOOK_SHARE"]
OrderStatus = Literal["FILLED", "PARTIALLY_FILLED", "CANCELLED", "UNFILLED"]
_ISSUER = Issuer("bt003.fill_trace.v1")
_POLICY_ISSUER = Issuer("bt003.fill_policy.v1")


def _currency(value: object) -> bool:
    return type(value) is str and len(value) == 3 and value.isascii() and value.isupper()


def _ratio(value: Fraction) -> Ratio:
    return Ratio(value.numerator, value.denominator)


def _decimal_fraction(value: Fraction) -> Decimal:
    result = quotient_final(Ratio(value.numerator, value.denominator), 1)
    if value > 0 and result <= 0:
        raise FillKernelError("FILL_QUANTITY_UNREPRESENTABLE") from None
    return result


def _event_id(event: PreparedEventV1) -> str:
    raw = event.raw
    identity = {
        "available_ns": raw.available_ns,
        "correction_key": raw.correction_key,
        "dataset_id": raw.dataset_id,
        "dataset_version": raw.dataset_version,
        "event_ns": raw.event_ns,
        "instrument": raw.instrument,
        "kind": raw.kind,
        "sequence": raw.sequence,
        "source": raw.source,
        "source_id": raw.source_id,
        "stream_id": raw.stream_id,
        "venue": raw.venue,
        "visible_ns": event.visible_ns,
    }
    return sha256(canonical_json(identity)).hexdigest()


def _fraction(value: Decimal) -> Fraction:
    return Fraction(value)


def _exact_fee(model: FeeModelV1, price: Decimal, quantity: Decimal) -> tuple[Fraction, Fraction]:
    notional = _fraction(price) * _fraction(quantity)
    fee = _fraction(model.fee_per_share) * _fraction(quantity)
    fee += notional * _fraction(model.fee_bps) / 10_000
    rebate = -_fraction(model.rebate_per_share) * _fraction(quantity)
    rebate -= notional * _fraction(model.rebate_bps) / 10_000
    return fee, rebate


@dataclass(frozen=True, slots=True)
class FillPolicyV1(_FrozenInput):
    """All execution choices are explicit, versioned and bound into each trace."""

    version: str
    calendar_id: str
    calendar_version: str
    execution_mode: ExecutionMode
    queue_model: QueueModel
    latency: LatencyModelV1
    fees: FeeModelV1
    max_book_age_ns: int
    book_share: Decimal = Decimal(1)

    def __post_init__(self) -> None:
        try:
            require(self, _POLICY_ISSUER.tag)
        except SealError as exc:
            if exc.code != "SEAL_NOT_ISSUED":
                raise FillPolicyError("POLICY_REINIT") from None
        else:
            raise FillPolicyError("POLICY_REINIT") from None
        if any(
            not _text(value)
            for value in (
                self.version,
                self.calendar_id,
                self.calendar_version,
            )
        ):
            raise FillPolicyError("INVALID_POLICY_IDENTIFIER") from None
        if type(self.execution_mode) is not str or self.execution_mode not in (
            "L1_TOP_OF_BOOK",
            "L1_MIDPOINT_BENCHMARK",
            "L1_DEPTH_PROXY",
            "SYNTHETIC_L2",
            "RECORDED_L2",
        ):
            raise FillPolicyError("INVALID_EXECUTION_MODE") from None
        if type(self.queue_model) is not str or self.queue_model != "PRICE_TIME_BOOK_SHARE":
            raise FillPolicyError("INVALID_QUEUE_MODEL") from None
        object.__setattr__(self, "book_share", _decimal(self.book_share, nonnegative=True))
        if self.book_share > Decimal(1):
            raise FillPolicyError("BOOK_SHARE_OUT_OF_BOUNDS") from None
        if type(self.latency) is not LatencyModelV1 or type(self.fees) is not FeeModelV1:
            raise FillPolicyError("INVALID_POLICY_MODEL") from None
        if type(self.max_book_age_ns) is not int or not 0 <= self.max_book_age_ns <= _MAX_UTC_NS:
            raise FillPolicyError("INVALID_BOOK_AGE") from None
        _POLICY_ISSUER.issue(self)


@dataclass(frozen=True, slots=True)
class FillV1(_FrozenInput):
    event_id: str
    visible_ns: int
    price: Decimal
    quantity: Decimal
    reference_price: Decimal | None
    fee_exact: Ratio
    rebate_exact: Ratio
    slippage_exact: Ratio

    def __post_init__(self) -> None:
        if not _text(self.event_id):
            raise FillValidationError("INVALID_EVENT_ID") from None
        _ns(self.visible_ns)
        object.__setattr__(self, "price", _decimal(self.price, positive=True))
        object.__setattr__(self, "quantity", _decimal(self.quantity, positive=True))
        if self.reference_price is not None:
            object.__setattr__(
                self, "reference_price", _decimal(self.reference_price, positive=True)
            )
        if any(
            type(value) is not Ratio
            for value in (
                self.fee_exact,
                self.rebate_exact,
                self.slippage_exact,
            )
        ):
            raise FillValidationError("INVALID_COST_COMPONENT") from None


@dataclass(frozen=True, slots=True)
class FillTransitionV1(_FrozenInput):
    event_id: str
    visible_ns: int
    state_before: str
    state_after: str
    reason: str
    fills: tuple[FillV1, ...]

    def __post_init__(self) -> None:
        if (
            not _text(self.event_id)
            or not _text(self.state_before)
            or not _text(self.state_after)
            or not _text(self.reason)
        ):
            raise FillValidationError("INVALID_TRANSITION") from None
        _ns(self.visible_ns)
        if type(self.fills) is not tuple or any(type(fill) is not FillV1 for fill in self.fills):
            raise FillValidationError("INVALID_TRANSITION_FILLS") from None


@dataclass(frozen=True, slots=True)
class FillTraceV1(_FrozenInput):
    order_id: str
    request_id: str
    policy_version: str
    policy_digest: str
    execution_mode: ExecutionMode
    benchmark_midpoint: Decimal | None
    latency_strategy_ns: int
    latency_network_ns: int
    latency_venue_ns: int
    eligible_from_ns: int
    fills: tuple[FillV1, ...]
    transitions: tuple[FillTransitionV1, ...]
    status: OrderStatus
    filled_quantity: Decimal
    remaining_quantity: Decimal
    total_fee: Decimal
    total_rebate: Decimal
    implementation_shortfall: Decimal
    currency: str
    minor_units: int
    _issuer: InitVar[Issuer | None] = None

    def __getattribute__(self, name: str) -> object:
        if not name.startswith("_") and name not in {"require_integrity", "canonical_bytes"}:
            try:
                require(self, _ISSUER.tag)
            except SealError as exc:
                if exc.code == "SEAL_NOT_ISSUED":
                    return object.__getattribute__(self, name)
                raise FillKernelError("FILL_TRACE_TAMPERED") from None
        return object.__getattribute__(self, name)

    def __post_init__(self, _issuer: Issuer | None) -> None:
        try:
            require(self, _ISSUER.tag)
        except SealError as exc:
            if exc.code != "SEAL_NOT_ISSUED":
                raise FillKernelError("FILL_TRACE_REINIT") from None
        else:
            raise FillKernelError("FILL_TRACE_REINIT") from None
        if _issuer is not _ISSUER:
            raise FillKernelError("FILL_TRACE_UNISSUED") from None
        if any(
            not _text(value)
            for value in (
                self.order_id,
                self.request_id,
                self.policy_version,
                self.policy_digest,
            )
        ):
            raise FillValidationError("INVALID_TRACE_IDENTIFIER") from None
        if type(self.execution_mode) is not str or self.execution_mode not in (
            "L1_TOP_OF_BOOK",
            "L1_MIDPOINT_BENCHMARK",
            "L1_DEPTH_PROXY",
            "SYNTHETIC_L2",
            "RECORDED_L2",
        ):
            raise FillValidationError("INVALID_EXECUTION_MODE") from None
        for value in (
            self.latency_strategy_ns,
            self.latency_network_ns,
            self.latency_venue_ns,
        ):
            _ns(value)
        _ns(self.eligible_from_ns)
        if type(self.fills) is not tuple or any(type(item) is not FillV1 for item in self.fills):
            raise FillValidationError("INVALID_TRACE_FILLS") from None
        if type(self.transitions) is not tuple or any(
            type(item) is not FillTransitionV1 for item in self.transitions
        ):
            raise FillValidationError("INVALID_TRACE_TRANSITIONS") from None
        if type(self.status) is not str or self.status not in (
            "FILLED",
            "PARTIALLY_FILLED",
            "CANCELLED",
            "UNFILLED",
        ):
            raise FillValidationError("INVALID_TRACE_STATUS") from None
        for field_name in ("filled_quantity", "remaining_quantity", "total_fee"):
            object.__setattr__(
                self, field_name, _decimal(getattr(self, field_name), nonnegative=True)
            )
        object.__setattr__(self, "total_rebate", _decimal(self.total_rebate))
        object.__setattr__(
            self,
            "implementation_shortfall",
            _decimal(self.implementation_shortfall),
        )
        if self.benchmark_midpoint is not None:
            object.__setattr__(
                self, "benchmark_midpoint", _decimal(self.benchmark_midpoint, positive=True)
            )
        if not _currency(self.currency):
            raise FillValidationError("INVALID_CURRENCY") from None
        if type(self.minor_units) is not int or not 0 <= self.minor_units <= 6:
            raise FillValidationError("INVALID_MINOR_UNIT_SCALE") from None
        _ISSUER.issue(self)

    def require_integrity(self) -> FillTraceV1:
        try:
            return require(self, _ISSUER.tag)
        except SealError:
            raise FillKernelError("FILL_TRACE_TAMPERED") from None

    def canonical_bytes(self) -> bytes:
        self.require_integrity()
        return _trace_bytes(self)


@dataclass(frozen=True, slots=True)
class _Level:
    side: Literal["bid", "ask"]
    price: Decimal
    size: Decimal


def _trace_bytes(trace: FillTraceV1) -> bytes:
    return canonical_json(
        {
            "benchmark_midpoint": trace.benchmark_midpoint,
            "currency": trace.currency,
            "eligible_from_ns": trace.eligible_from_ns,
            "execution_mode": trace.execution_mode,
            "fills": tuple(
                {
                    "event_id": fill.event_id,
                    "fee": (fill.fee_exact.numerator, fill.fee_exact.denominator),
                    "price": fill.price,
                    "quantity": fill.quantity,
                    "rebate": (fill.rebate_exact.numerator, fill.rebate_exact.denominator),
                    "reference_price": fill.reference_price,
                    "slippage": (fill.slippage_exact.numerator, fill.slippage_exact.denominator),
                    "visible_ns": fill.visible_ns,
                }
                for fill in trace.fills
            ),
            "filled_quantity": trace.filled_quantity,
            "latency": (
                trace.latency_strategy_ns,
                trace.latency_network_ns,
                trace.latency_venue_ns,
            ),
            "minor_units": trace.minor_units,
            "order_id": trace.order_id,
            "policy_digest": trace.policy_digest,
            "policy_version": trace.policy_version,
            "remaining_quantity": trace.remaining_quantity,
            "request_id": trace.request_id,
            "status": trace.status,
            "total_fee": trace.total_fee,
            "total_rebate": trace.total_rebate,
            "implementation_shortfall": trace.implementation_shortfall,
            "transitions": tuple(
                {
                    "event_id": item.event_id,
                    "fills": tuple(fill.event_id for fill in item.fills),
                    "reason": item.reason,
                    "state_after": item.state_after,
                    "state_before": item.state_before,
                    "visible_ns": item.visible_ns,
                }
                for item in trace.transitions
            ),
        }
    )


def _policy_digest(policy: FillPolicyV1) -> str:
    latency = policy.latency
    models: list[dict[str, object]] = []
    for name in ("strategy", "network", "venue"):
        model = getattr(latency, name)
        if hasattr(model, "delay_ns"):
            values: dict[str, object] = {"delay_ns": model.delay_ns, "kind": "fixed"}
        elif hasattr(model, "mean_ns"):
            values = {
                "kind": "normal",
                "mean_ns": model.mean_ns,
                "stddev_ns": model.stddev_ns,
                "seed": model.seed,
            }
        elif hasattr(model, "log_mean"):
            values = {
                "kind": "lognormal",
                "log_mean": model.log_mean,
                "log_stddev": model.log_stddev,
                "seed": model.seed,
            }
        else:
            values = {
                "kind": "empirical",
                "seed": model.seed,
                "snapshot_id": model.snapshot_id,
                "snapshot_sha256": model.snapshot_sha256,
            }
        values["version"] = model.version
        models.append(values)
    fee = policy.fees
    return sha256(
        canonical_json(
            {
                "book_share": policy.book_share,
                "calendar_id": policy.calendar_id,
                "calendar_version": policy.calendar_version,
                "execution_mode": policy.execution_mode,
                "fees": {
                    "currency": fee.currency,
                    "fee_bps": fee.fee_bps,
                    "fee_per_share": fee.fee_per_share,
                    "maximum_order_fee": fee.maximum_order_fee,
                    "minimum_order_fee": fee.minimum_order_fee,
                    "minor_units": fee.minor_units,
                    "rebate_bps": fee.rebate_bps,
                    "rebate_per_share": fee.rebate_per_share,
                    "version": fee.version,
                },
                "latency": models,
                "latency_version": latency.version,
                "max_book_age_ns": policy.max_book_age_ns,
                "policy_version": policy.version,
                "queue_model": policy.queue_model,
            }
        )
    ).hexdigest()


def _request_digest(request: FillRequestV1) -> str:
    return sha256(
        canonical_json(
            {
                "calendar_id": request.calendar_id,
                "calendar_version": request.calendar_version,
                "cancel_ns": request.cancel_ns,
                "cancel_sequence": request.cancel_sequence,
                "currency": request.currency,
                "expires_ns": request.expires_ns,
                "instrument": request.instrument,
                "limit_price": request.limit_price,
                "order_type": request.order_type,
                "quantity": request.quantity,
                "request_id": request.request_id,
                "session": (
                    request.session.venue,
                    request.session.session_date,
                    request.session.open_ns,
                    request.session.close_ns,
                ),
                "sessions": tuple(
                    (
                        session.venue,
                        session.session_date,
                        session.open_ns,
                        session.close_ns,
                    )
                    for session in request.sessions
                ),
                "side": request.side,
                "stop_price": request.stop_price,
                "submit_ns": request.submit_ns,
                "submit_sequence": request.submit_sequence,
                "time_in_force": request.time_in_force,
                "venue": request.venue,
            }
        )
    ).hexdigest()


def _event_levels(
    mode: ExecutionMode,
    book: dict[tuple[str, Decimal], Decimal],
    l1_quote: dict[tuple[str, Decimal], Decimal],
) -> tuple[_Level, ...]:
    if mode in ("L1_TOP_OF_BOOK", "L1_MIDPOINT_BENCHMARK", "L1_DEPTH_PROXY"):
        return tuple(
            _Level(cast(Literal["bid", "ask"], side), price, size)
            for (side, price), size in sorted(
                l1_quote.items(), key=lambda pair: (pair[0][0], pair[0][1])
            )
            if size > 0
        )
    return tuple(
        _Level(cast(Literal["bid", "ask"], side), price, size)
        for (side, price), size in sorted(book.items(), key=lambda pair: (pair[0][0], pair[0][1]))
        if size > 0
    )


def _update_book(
    event: PreparedEventV1,
    book: dict[tuple[str, Decimal], Decimal],
    consumed: dict[tuple[str, Decimal], Fraction],
) -> None:
    if event.raw.kind not in ("book_snapshot", "book_delta"):
        return
    if event.raw.kind == "book_snapshot":
        book.clear()
        consumed.clear()
    for level in event.adjusted_levels:
        key = (level.side, level.price)
        if level.size == 0:
            book.pop(key, None)
            consumed.pop(key, None)
        else:
            book[key] = level.size
            consumed[key] = Fraction(0)


def _update_l1_quote(
    event: PreparedEventV1,
    quote: dict[tuple[str, Decimal], Decimal],
    consumed: dict[tuple[str, Decimal], Fraction],
) -> None:
    if event.raw.kind != "quote":
        return
    quote.clear()
    consumed.clear()
    for side, price, size in (
        ("bid", event.adjusted_bid_price, event.adjusted_bid_size),
        ("ask", event.adjusted_ask_price, event.adjusted_ask_size),
    ):
        if price is not None and size is not None and size > 0:
            key = (side, price)
            quote[key] = size
            consumed[key] = Fraction(0)


def _available_levels(
    levels: tuple[_Level, ...], consumed: dict[tuple[str, Decimal], Fraction]
) -> tuple[_Level, ...]:
    available: list[_Level] = []
    for level in levels:
        key = (level.side, level.price)
        size = _fraction(level.size) - consumed.get(key, Fraction(0))
        if size > 0:
            available.append(_Level(level.side, level.price, _decimal_fraction(size)))
    return tuple(available)


def _levels_for_side(levels: tuple[_Level, ...], side: str) -> list[_Level]:
    wanted = "ask" if side == "BUY" else "bid"
    return sorted(
        (level for level in levels if level.side == wanted and level.size > 0),
        key=lambda level: level.price,
        reverse=wanted == "bid",
    )


def _marketable(side: str, limit: Decimal, level: _Level) -> bool:
    return level.price <= limit if side == "BUY" else level.price >= limit


def _bind_calendar_to_manifest(
    request: FillRequestV1,
    policy: FillPolicyV1,
    manifest: PreparedStreamManifestV1,
) -> None:
    if (
        request.calendar_id != policy.calendar_id
        or request.calendar_version != policy.calendar_version
        or request.calendar_id != manifest.calendar_id
        or request.calendar_version != manifest.calendar_version
    ):
        raise FillPolicyError("CALENDAR_MISMATCH") from None

    request_windows = (request.session, *request.sessions)
    if any(
        not any(
            window.venue == verified.venue
            and window.session_date == verified.session_date
            and verified.open_ns <= window.open_ns
            and window.close_ns <= verified.close_ns
            for verified in manifest.sessions
        )
        for window in request_windows
    ):
        raise FillPolicyError("CALENDAR_MISMATCH") from None


def match(
    request: FillRequestV1,
    policy: FillPolicyV1,
    events: PreparedEventStreamV1,
) -> FillTraceV1:
    """Match one order against eligible visible events, producing a sealed trace."""
    if type(request) is not FillRequestV1 or type(policy) is not FillPolicyV1:
        raise FillValidationError("INVALID_MATCH_INPUT") from None
    try:
        require(request, _REQUEST_ISSUER.tag)
        require(policy, _POLICY_ISSUER.tag)
    except SealError:
        raise FillKernelError("MATCH_INPUT_TAMPERED") from None
    if type(events) is not PreparedEventStreamV1:
        raise FillValidationError("INVALID_EVENT_STREAM") from None
    prepared_manifest = verify_prepared_stream(events)
    _bind_calendar_to_manifest(request, policy, prepared_manifest)
    if request.currency != policy.fees.currency:
        raise FillPolicyError("CURRENCY_MISMATCH") from None
    if request.time_in_force == "DAY" and request.expires_ns is not None:
        raise FillValidationError("DAY_EXPIRY_IS_SESSION_BOUND") from None
    if request.time_in_force != "GTC" and request.expires_ns is not None:
        raise FillValidationError("INVALID_EXPIRY") from None
    latency_parts = sample_total_latency(policy.latency, request.request_id)
    eligibility = request.submit_ns + latency_parts[3]
    if eligibility > _MAX_UTC_NS:
        raise FillValidationError("LATENCY_OUT_OF_BOUNDS") from None
    cancel_effective_ns = (
        request.cancel_ns + latency_parts[3] if request.cancel_ns is not None else None
    )
    if cancel_effective_ns is not None and cancel_effective_ns > _MAX_UTC_NS:
        raise FillValidationError("LATENCY_OUT_OF_BOUNDS") from None
    policy_hash = _policy_digest(policy)
    order_id = sha256(
        canonical_json(
            {
                "policy_digest": policy_hash,
                "request_digest": _request_digest(request),
            }
        )
    ).hexdigest()

    remaining = _fraction(request.quantity)
    filled = Fraction(0)
    exact_fees = Fraction(0)
    exact_rebates = Fraction(0)
    exact_shortfall = Fraction(0)
    fill_rows: list[FillV1] = []
    transitions: list[FillTransitionV1] = []
    book: dict[tuple[str, Decimal], Decimal] = {}
    book_visible_ns: int | None = None
    l1_quote: dict[tuple[str, Decimal], Decimal] = {}
    l1_quote_visible_ns: int | None = None
    consumed_l1: dict[tuple[str, Decimal], Fraction] = {}
    consumed_l2: dict[tuple[str, Decimal], Fraction] = {}
    prior_order: tuple[int, int] | None = None
    triggered = request.order_type not in ("STOP", "STOP_LIMIT")
    effective_type = request.order_type
    queue_remaining: Fraction | None = None
    benchmark: Decimal | None = None
    attempted_eligible = False
    terminal_reason: str | None = None
    last_stream_visible_ns: int | None = None

    for event in events:
        if type(event) is not PreparedEventV1:
            raise OrderRejectedError("UNTRUSTED_EVENT") from None
        try:
            require(event, "bt002.event.v1")
        except SealError:
            raise OrderRejectedError("UNTRUSTED_EVENT") from None
        if not event.simulator_eligible:
            raise OrderRejectedError("UNTRUSTED_EVENT") from None
        if event.view != "PIT" or event.raw.sequence is None:
            raise OrderRejectedError("UNTRUSTED_EVENT") from None
        order_key = (event.visible_ns, event.raw.sequence)
        if prior_order is not None and order_key < prior_order:
            raise FillKernelError("EVENT_ORDER_REGRESSED") from None
        prior_order = order_key
        last_stream_visible_ns = event.visible_ns
        raw = event.raw
        if raw.instrument != request.instrument:
            continue
        _ns(event.visible_ns)
        if raw.venue == request.venue:
            _update_book(event, book, consumed_l2)
            if raw.kind in ("book_snapshot", "book_delta"):
                book_visible_ns = event.visible_ns
            _update_l1_quote(event, l1_quote, consumed_l1)
            if raw.kind == "quote":
                l1_quote_visible_ns = event.visible_ns
        if raw.venue != request.venue:
            continue
        if (event.visible_ns, raw.sequence) < (eligibility, request.submit_sequence):
            continue
        if (
            request.time_in_force == "GTC"
            and request.expires_ns is not None
            and (event.visible_ns > request.expires_ns)
        ):
            terminal_reason = "EXPIRED"
            break
        if request.time_in_force == "DAY" and event.visible_ns >= request.session.close_ns:
            terminal_reason = "SESSION_CLOSED"
            break
        if cancel_effective_ns is not None and (
            (event.visible_ns, raw.sequence) >= (cancel_effective_ns, request.cancel_sequence or 0)
        ):
            terminal_reason = "CANCELLED_BY_REQUEST"
            break
        if request.time_in_force == "DAY" and event.visible_ns >= request.session.close_ns:
            terminal_reason = "SESSION_CLOSED"
            break
        if not any(
            window.open_ns <= event.visible_ns < window.close_ns for window in request.sessions
        ):
            continue
        if policy.execution_mode.startswith("L1_") and (
            l1_quote_visible_ns is not None
            and event.visible_ns - l1_quote_visible_ns > policy.max_book_age_ns
        ):
            raise FillKernelError("BOOK_STALE") from None
        if policy.execution_mode in ("SYNTHETIC_L2", "RECORDED_L2"):
            if not book:
                raise FillKernelError("DEPTH_UNAVAILABLE") from None
            if (
                book_visible_ns is None
                or event.visible_ns - book_visible_ns > policy.max_book_age_ns
            ):
                raise FillKernelError("BOOK_STALE") from None
        active_consumed = consumed_l1 if policy.execution_mode.startswith("L1_") else consumed_l2
        levels = _available_levels(
            _event_levels(policy.execution_mode, book, l1_quote), active_consumed
        )
        asks = _levels_for_side(levels, request.side)
        if policy.execution_mode == "L1_MIDPOINT_BENCHMARK":
            bid = next((price for (side, price) in l1_quote if side == "bid"), None)
            ask = next((price for (side, price) in l1_quote if side == "ask"), None)
            if bid is not None and ask is not None:
                benchmark = _decimal_fraction((_fraction(bid) + _fraction(ask)) / 2)
        before = "TRIGGERED" if triggered else "PENDING_TRIGGER"
        event_fills: list[FillV1] = []
        reason = "NO_EXECUTABLE_LIQUIDITY"
        attempted_eligible = True

        triggered_here = False
        if not triggered and raw.kind == "trade" and raw.price is not None:
            trade_price = event.adjusted_price
            stop_price = request.stop_price
            if trade_price is not None and (
                stop_price is not None
                and (
                    (request.side == "BUY" and trade_price >= stop_price)
                    or (request.side == "SELL" and trade_price <= stop_price)
                )
            ):
                triggered = True
                triggered_here = True
                effective_type = "MARKET" if request.order_type == "STOP" else "LIMIT"
                reason = "STOP_TRIGGERED"

        if (
            triggered
            and not triggered_here
            and queue_remaining is None
            and effective_type in ("LIMIT", "STOP_LIMIT")
            and request.limit_price is not None
            and not any(_marketable(request.side, request.limit_price, level) for level in asks)
        ):
            same_side = "bid" if request.side == "BUY" else "ask"
            queue_book = l1_quote if policy.execution_mode.startswith("L1_") else book
            queue_timestamp = (
                l1_quote_visible_ns if policy.execution_mode.startswith("L1_") else book_visible_ns
            )
            if queue_timestamp is not None and (
                event.visible_ns - queue_timestamp > policy.max_book_age_ns
            ):
                raise FillKernelError("BOOK_STALE") from None
            displayed = next(
                (
                    size
                    for (side, price), size in queue_book.items()
                    if side == same_side and price == request.limit_price
                ),
                Decimal(0),
            )
            queue_remaining = _fraction(displayed) * _fraction(policy.book_share)

        if triggered and remaining > 0:
            executable: list[tuple[Decimal, Decimal]] = []
            if effective_type in ("MARKET", "STOP"):
                executable = [(level.price, level.size) for level in asks]
            elif effective_type in ("LIMIT", "STOP_LIMIT"):
                if request.limit_price is None:
                    raise FillKernelError("INVALID_ACTIVE_LIMIT") from None
                executable = [
                    (level.price, level.size)
                    for level in asks
                    if _marketable(request.side, request.limit_price, level)
                ]
            for price, size in executable:
                take = min(remaining, _fraction(size))
                if take <= 0:
                    continue
                fill_qty = _decimal_fraction(take)
                exact_fee, exact_rebate = _exact_fee(policy.fees, price, fill_qty)
                slippage = Fraction(0)
                if benchmark is not None:
                    signed_difference = _fraction(price) - _fraction(benchmark)
                    if request.side == "SELL":
                        signed_difference = -signed_difference
                    slippage = signed_difference * _fraction(fill_qty)
                row = FillV1(
                    _event_id(event),
                    event.visible_ns,
                    price,
                    fill_qty,
                    benchmark,
                    _ratio(exact_fee),
                    _ratio(exact_rebate),
                    _ratio(slippage),
                )
                event_fills.append(row)
                fill_rows.append(row)
                remaining -= take
                consumed_key = ("ask" if request.side == "BUY" else "bid", price)
                active_consumed[consumed_key] = (
                    active_consumed.get(consumed_key, Fraction(0)) + take
                )
                filled += take
                exact_fees += exact_fee
                exact_rebates += exact_rebate
                exact_shortfall += slippage
                if remaining == 0:
                    break
            if event_fills:
                reason = "FILLED" if remaining == 0 else "PARTIAL_FILL"

            # Passive limit fills use a declared displayed queue. Only trade prints
            # at exactly the order price deplete queue; cancellations do not.
            if (
                not event_fills
                and effective_type in ("LIMIT", "STOP_LIMIT")
                and request.limit_price is not None
                and raw.kind == "trade"
                and event.adjusted_price == request.limit_price
                and event.adjusted_size is not None
            ):
                if queue_remaining is None:
                    queue_remaining = Fraction(0)
                traded = _fraction(event.adjusted_size)
                queue_take = min(queue_remaining, traded)
                queue_remaining -= queue_take
                after_queue = traded - queue_take
                if queue_remaining == 0 and after_queue > 0:
                    take = min(remaining, after_queue)
                    fill_qty = _decimal_fraction(take)
                    exact_fee, exact_rebate = _exact_fee(policy.fees, request.limit_price, fill_qty)
                    slippage = Fraction(0)
                    if benchmark is not None:
                        signed_difference = _fraction(request.limit_price) - _fraction(benchmark)
                        if request.side == "SELL":
                            signed_difference = -signed_difference
                        slippage = signed_difference * _fraction(fill_qty)
                    row = FillV1(
                        _event_id(event),
                        event.visible_ns,
                        request.limit_price,
                        fill_qty,
                        benchmark,
                        _ratio(exact_fee),
                        _ratio(exact_rebate),
                        _ratio(slippage),
                    )
                    event_fills.append(row)
                    fill_rows.append(row)
                    remaining -= take
                    filled += take
                    exact_fees += exact_fee
                    exact_rebates += exact_rebate
                    exact_shortfall += slippage
                    reason = "QUEUE_EXHAUSTED_FILL"
                elif queue_remaining == 0:
                    reason = "QUEUE_EXHAUSTED"

        after = "FILLED" if remaining == 0 else ("TRIGGERED" if triggered else "PENDING_TRIGGER")
        transitions.append(
            FillTransitionV1(
                _event_id(event), event.visible_ns, before, after, reason, tuple(event_fills)
            )
        )

        if request.time_in_force == "FOK" and attempted_eligible:
            # FOK is transactional at one event: discard partial fills if the
            # whole remaining order could not execute at this event.
            if remaining != 0:
                event_set = {id(item) for item in event_fills}
                fill_rows = [item for item in fill_rows if id(item) not in event_set]
                for item in event_fills:
                    qty = _fraction(item.quantity)
                    filled -= qty
                    remaining += qty
                    exact_fees -= Fraction(item.fee_exact.numerator, item.fee_exact.denominator)
                    exact_rebates -= Fraction(
                        item.rebate_exact.numerator, item.rebate_exact.denominator
                    )
                    exact_shortfall -= Fraction(
                        item.slippage_exact.numerator, item.slippage_exact.denominator
                    )
                transitions[-1] = FillTransitionV1(
                    _event_id(event),
                    event.visible_ns,
                    before,
                    before,
                    "FOK_NOT_FILLED",
                    (),
                )
                terminal_reason = "FOK_NOT_FILLED"
            break

        market_attempt = effective_type in ("MARKET", "STOP") and triggered
        if market_attempt and not triggered_here:
            if remaining == 0:
                terminal_reason = "FILLED"
            elif request.time_in_force == "IOC":
                terminal_reason = "IOC_REMAINDER_CANCELLED"
            else:
                terminal_reason = "UNFILLED_NO_LIQUIDITY"
            break
        if request.time_in_force == "IOC" and attempted_eligible:
            terminal_reason = "IOC_REMAINDER_CANCELLED"
            break
        if remaining == 0:
            terminal_reason = "FILLED"
            break

    if terminal_reason is None:
        terminal_reason = "END_OF_INPUT"
    if (
        remaining > 0
        and terminal_reason
        in (
            "UNFILLED_NO_LIQUIDITY",
            "IOC_REMAINDER_CANCELLED",
            "FOK_NOT_FILLED",
        )
        and transitions
    ):
        # Keep terminal cancellation visible on the last event transition.
        prior = transitions[-1]
        transitions[-1] = FillTransitionV1(
            prior.event_id,
            prior.visible_ns,
            prior.state_before,
            "CANCELLED",
            terminal_reason,
            prior.fills,
        )

    if (
        request.time_in_force == "GTC"
        and request.expires_ns is not None
        and (terminal_reason == "END_OF_INPUT")
        and last_stream_visible_ns is not None
        and (last_stream_visible_ns >= request.expires_ns)
    ):
        terminal_reason = "EXPIRED"
    if request.time_in_force == "DAY" and terminal_reason == "END_OF_INPUT":
        terminal_reason = "SESSION_CLOSED"

    if policy.fees.minimum_order_fee is not None and filled > 0:
        exact_fees = max(exact_fees, _fraction(policy.fees.minimum_order_fee))
    if policy.fees.maximum_order_fee is not None:
        exact_fees = min(exact_fees, _fraction(policy.fees.maximum_order_fee))
    total_fee = _reported(exact_fees, policy.fees.minor_units)
    total_rebate = _reported(exact_rebates, policy.fees.minor_units)
    status: OrderStatus
    if remaining == 0:
        status = "FILLED"
    elif filled > 0:
        status = "PARTIALLY_FILLED"
    elif terminal_reason in ("END_OF_INPUT", "SESSION_CLOSED", "EXPIRED"):
        status = "UNFILLED"
    else:
        status = "CANCELLED"
    trace = FillTraceV1(
        order_id=order_id,
        request_id=request.request_id,
        policy_version=policy.version,
        policy_digest=policy_hash,
        execution_mode=policy.execution_mode,
        benchmark_midpoint=benchmark,
        latency_strategy_ns=latency_parts[0],
        latency_network_ns=latency_parts[1],
        latency_venue_ns=latency_parts[2],
        eligible_from_ns=eligibility,
        fills=tuple(fill_rows),
        transitions=tuple(transitions),
        status=status,
        filled_quantity=_decimal_fraction(filled),
        remaining_quantity=_decimal_fraction(remaining),
        total_fee=total_fee,
        total_rebate=total_rebate,
        implementation_shortfall=_reported(exact_shortfall, policy.fees.minor_units),
        currency=request.currency,
        minor_units=policy.fees.minor_units,
        _issuer=_ISSUER,
    )
    return trace.require_integrity()
