"""L2-only, quote-proposal port of the bitcoin-course C++ market maker.

Only issued coherent snapshots of normalized live L2 from DATA-002/003 are
accepted. This module returns a quote proposal; it has no broker, OMS, or risk
gate bypass and never sends or offsets an order.

Source provenance: authorized ``bitcoin-course.zip`` SHA-256
``4B993BDB3C841D114B4A02C92498CECF8091EBD9D1C04D0C465618502FE04DC3``;
``cpp/hft_mm/hft_mm.cpp`` SHA-256
``B33B15A2B8D55FF42E21C0BEC89496C3672C12EDD7490175426C22BB6468990D``.
At source lines 910-915, the executable uses ``(1/gamma) * ln(1+gamma/k)``
despite a nearby comment describing a ``(2/gamma)`` term; this port follows
the executable expression.
At source lines 938-951, below-min spread is widened symmetrically to the
minimum as in the source. The coordinator-directed safety rule deliberately
denies an above-max computed spread with ``SPREAD_LIMIT_CONFLICT`` instead of
contracting it; this prevents tighter quotes when cost or volatility inputs
exceed the configured maximum.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import ROUND_CEILING, ROUND_FLOOR, Decimal, localcontext
from itertools import pairwise
from typing import NoReturn, SupportsIndex

from leviathan_core.numeric import NumericError, parse_decimal
from leviathan_core.numeric._context import numeric_context
from leviathan_market_data.live.book_cache import (
    BookSnapshotReceiptV1,
    is_issued_book_snapshot_receipt,
)
from leviathan_market_data.schema import BookLevel, BookSnapshotPayload, NormalizedMarketEventV1

_ZERO = Decimal("0")
_ONE = Decimal("1")
_TWO = Decimal("2")
_THREE = Decimal("3")
_NANOSECONDS = Decimal("1000000000")
_ALLOWED_PROVIDERS = frozenset({"databento", "massive"})
_BAD_QUALITY = frozenset(
    {"GAP", "SEQUENCE_GAP", "OUT_OF_ORDER", "STALE", "DEGRADED", "MISSING_BASE", "INCOMPLETE"}
)


class HftMarketMakerError(ValueError):
    """Content-free quote denial with a stable reason code."""

    _CODES = frozenset(
        {
            "INVALID_CONFIG",
            "INVALID_INVENTORY",
            "INVALID_TIME",
            "INVALID_L2_EVENT",
            "L2_PROVIDER_REQUIRED",
            "L2_BOOK_MISSING",
            "L2_BOOK_GAP",
            "L2_BOOK_STALE",
            "L2_HISTORY_INVALID",
            "L2_SEQUENCE_GAP",
            "L2_SESSION_MISMATCH",
            "L2_BOOK_CROSSED",
            "SPREAD_LIMIT_CONFLICT",
            "QUOTE_INVALID",
            "PRECISION_EXCEEDED",
            "MAGNITUDE_OUT_OF_BOUNDS",
            "INVALID_DECIMAL",
        }
    )

    def __init__(self, code: str) -> None:
        self.code = code if type(code) is str and code in self._CODES else "INVALID_L2_EVENT"
        super().__init__(self.code)


class _FrozenNoCopy:
    __slots__ = ()

    def __copy__(self) -> NoReturn:
        raise TypeError("COPY_FORBIDDEN")

    def __deepcopy__(self, memo: object) -> NoReturn:
        raise TypeError("COPY_FORBIDDEN")

    def __reduce__(self) -> NoReturn:
        raise TypeError("PICKLE_FORBIDDEN")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise TypeError("PICKLE_FORBIDDEN")


def _decimal(value: object, field: str, *, minimum: Decimal | str | None = None) -> Decimal:
    try:
        return parse_decimal(value, field=field, min_value=minimum)
    except NumericError as exc:
        raise HftMarketMakerError(exc.code) from None


@dataclass(frozen=True, slots=True)
class HftMarketMakerConfigV1(_FrozenNoCopy):
    """Bounded market-maker parameters, including costs and freshness limits."""

    gamma: Decimal = Decimal("0.1")
    k: Decimal = Decimal("15")
    ofi_beta: Decimal = Decimal("0.5")
    max_inventory: Decimal = Decimal("100")
    quote_size: Decimal = Decimal("1")
    min_spread: Decimal = Decimal("0.0001")
    max_spread: Decimal = Decimal("0.01")
    tick_size: Decimal = Decimal("0.01")
    fee_rate: Decimal = Decimal("0.001")
    latency_penalty_per_second: Decimal = Decimal("0.05")
    half_life_ticks: Decimal = Decimal("50")
    min_volatility: Decimal = Decimal("0.0001")
    max_book_age_ns: int = 1_000_000
    max_latency_ns: int = 1_000_000
    max_history: int = 101

    def __post_init__(self) -> None:
        for name in (
            "gamma",
            "k",
            "max_inventory",
            "quote_size",
            "tick_size",
            "half_life_ticks",
            "min_volatility",
        ):
            object.__setattr__(
                self,
                name,
                _decimal(getattr(self, name), name, minimum="0.000000000000000000000000000000001"),
            )
        for name in ("ofi_beta", "fee_rate", "latency_penalty_per_second"):
            object.__setattr__(self, name, _decimal(getattr(self, name), name, minimum="0"))
        for name in ("min_spread", "max_spread"):
            object.__setattr__(
                self,
                name,
                _decimal(getattr(self, name), name, minimum="0.000000000000000000000000000000001"),
            )
        if self.min_spread >= self.max_spread:
            raise HftMarketMakerError("INVALID_CONFIG")
        for name, maximum in (
            ("max_book_age_ns", 60_000_000_000),
            ("max_latency_ns", 60_000_000_000),
        ):
            value = getattr(self, name)
            if type(value) is not int or not 0 < value <= maximum:
                raise HftMarketMakerError("INVALID_CONFIG")
        if type(self.max_history) is not int or not 2 <= self.max_history <= 101:
            raise HftMarketMakerError("INVALID_CONFIG")


@dataclass(frozen=True, slots=True)
class HftMarketMakerQuoteV1(_FrozenNoCopy):
    """A paper-gated quote proposal with formula, cost and source provenance."""

    bid_price: Decimal
    bid_quantity: Decimal
    ask_price: Decimal
    ask_quantity: Decimal
    mid_price: Decimal
    microprice: Decimal
    reservation_price: Decimal
    sigma: Decimal
    l2_ofi: Decimal
    half_spread: Decimal
    fee_padding: Decimal
    latency_padding: Decimal
    inventory: Decimal
    asof_ns: int
    age_ns: int
    native_sequence: int
    provider: str
    dataset: str
    venue: str
    instrument_id: str
    disposition: str = "QUOTE_ONLY"


_DEFAULT_HFT_CONFIG = HftMarketMakerConfigV1()


def _is_book_event(event: object) -> bool:
    if type(event) is not NormalizedMarketEventV1:
        return False
    return (
        event.event_type == "book_snapshot"
        and event.source_mode == "live"
        and event.provider.lower() in _ALLOWED_PROVIDERS
        and event.provider_session_id is not None
        and isinstance(event.payload, BookSnapshotPayload)
        and not event.sequence_synthetic
        and event.native_sequence is not None
        and not event.reconstructed
        and not ({flag.upper() for flag in event.quality_flags} & _BAD_QUALITY)
    )


def _levels(levels: tuple[BookLevel, ...]) -> tuple[Decimal, Decimal, Decimal, Decimal]:
    bids = sorted(
        (
            (
                _decimal(level.price.value, "price", minimum="0.000000000000000000000000000000001"),
                _decimal(level.size, "size", minimum="0"),
            )
            for level in levels
            if level.side == "bid"
        ),
        key=lambda item: item[0],
        reverse=True,
    )
    asks = sorted(
        (
            (
                _decimal(level.price.value, "price", minimum="0.000000000000000000000000000000001"),
                _decimal(level.size, "size", minimum="0"),
            )
            for level in levels
            if level.side == "ask"
        ),
        key=lambda item: item[0],
    )
    if not bids or not asks or bids[0][1] <= 0 or asks[0][1] <= 0:
        raise HftMarketMakerError("L2_BOOK_MISSING")
    bid, bid_size = bids[0]
    ask, ask_size = asks[0]
    if bid >= ask:
        raise HftMarketMakerError("L2_BOOK_CROSSED")
    return bid, bid_size, ask, ask_size


def _ofi(
    previous: tuple[Decimal, Decimal, Decimal, Decimal],
    current: tuple[Decimal, Decimal, Decimal, Decimal],
) -> Decimal:
    prev_bid, prev_bid_size, prev_ask, prev_ask_size = previous
    bid, bid_size, ask, ask_size = current
    bid_flow = (
        bid_size
        if bid > prev_bid
        else -prev_bid_size
        if bid < prev_bid
        else bid_size - prev_bid_size
    )
    ask_flow = (
        -ask_size
        if ask < prev_ask
        else prev_ask_size
        if ask > prev_ask
        else prev_ask_size - ask_size
    )
    total = bid_size + ask_size
    return (bid_flow + ask_flow) / total if total else _ZERO


def build_hft_mm_quote(
    history: tuple[NormalizedMarketEventV1, ...],
    book_receipt: BookSnapshotReceiptV1,
    *,
    inventory: Decimal,
    now_ns: int,
    config: HftMarketMakerConfigV1 = _DEFAULT_HFT_CONFIG,
) -> HftMarketMakerQuoteV1:
    """Build one L2-backed quote proposal; stale, incomplete, or gapped books deny."""
    if type(config) is not HftMarketMakerConfigV1:
        raise HftMarketMakerError("INVALID_CONFIG")
    if type(now_ns) is not int or now_ns <= 0:
        raise HftMarketMakerError("INVALID_TIME")
    current_inventory = _decimal(inventory, "inventory")
    if abs(current_inventory) > config.max_inventory:
        raise HftMarketMakerError("INVALID_INVENTORY")
    if (
        type(history) is not tuple
        or not 2 <= len(history) <= config.max_history
        or any(not _is_book_event(event) for event in history)
    ):
        raise HftMarketMakerError("L2_PROVIDER_REQUIRED")
    if (
        type(book_receipt) is not BookSnapshotReceiptV1
        or not is_issued_book_snapshot_receipt(book_receipt)
        or not book_receipt.coherent
        or book_receipt.reason != "HEALTHY"
        or book_receipt.snapshot is None
        or book_receipt.updated_time_ns is None
    ):
        raise HftMarketMakerError("L2_BOOK_GAP")
    first = history[0]
    previous_event: NormalizedMarketEventV1 | None = None
    mids: list[Decimal] = []
    top_levels: list[tuple[Decimal, Decimal, Decimal, Decimal]] = []
    for event in history:
        if (
            event.provider != first.provider
            or event.dataset != first.dataset
            or event.venue != first.venue
            or event.instrument_id != first.instrument_id
            or event.provider_session_id != first.provider_session_id
        ):
            raise HftMarketMakerError("L2_SESSION_MISMATCH")
        if type(event.native_sequence) is not int or not isinstance(
            event.payload, BookSnapshotPayload
        ):
            raise HftMarketMakerError("L2_PROVIDER_REQUIRED")
        if previous_event is not None:
            if (
                type(previous_event.native_sequence) is not int
                or event.native_sequence != previous_event.native_sequence + 1
            ):
                raise HftMarketMakerError("L2_SEQUENCE_GAP")
            if event.event_time_ns <= previous_event.event_time_ns:
                raise HftMarketMakerError("L2_HISTORY_INVALID")
        current_top = _levels(event.payload.levels)
        top_levels.append(current_top)
        with localcontext(numeric_context(final_quotient=True)):
            mids.append((current_top[0] + current_top[2]) / _TWO)
        previous_event = event
    last = history[-1]
    if book_receipt.updated_time_ns != last.event_time_ns:
        raise HftMarketMakerError("L2_BOOK_GAP")
    age_ns = now_ns - book_receipt.updated_time_ns
    if age_ns < 0:
        raise HftMarketMakerError("INVALID_TIME")
    if age_ns > config.max_book_age_ns or age_ns > config.max_latency_ns:
        raise HftMarketMakerError("L2_BOOK_STALE")
    current_top = _levels(book_receipt.snapshot.levels)
    prev_top = top_levels[-2]
    if current_top != top_levels[-1]:
        raise HftMarketMakerError("L2_BOOK_GAP")

    with localcontext(numeric_context(final_quotient=True)):
        bid, bid_size, ask, ask_size = current_top
        mid = (bid + ask) / _TWO
        depth = bid_size + ask_size
        microprice = (ask * bid_size + bid * ask_size) / depth
        ofi = _ofi(prev_top, current_top)
        alpha = (
            _ONE - (-Decimal("0.6931471805599453094172321214581766") / config.half_life_ticks).exp()
        )
        variance = _ZERO
        for before, after in pairwise(mids):
            ret = after / before - _ONE
            variance = max(
                config.min_volatility * config.min_volatility,
                variance + alpha * (ret * ret - variance),
            )
        sigma = variance.sqrt()
        inventory_penalty = current_inventory * config.gamma * variance
        reservation = mid - inventory_penalty + config.ofi_beta * ofi * sigma
        reservation = Decimal("0.7") * reservation + Decimal("0.3") * microprice
        base_half_spread = (Decimal("1") / config.gamma) * (_ONE + config.gamma / config.k).ln()
        base_half_spread += config.gamma * variance
        fee_padding = mid * config.fee_rate
        latency_padding = mid * config.latency_penalty_per_second * Decimal(age_ns) / _NANOSECONDS
        min_half = mid * config.min_spread / _TWO
        max_half = mid * config.max_spread / _TWO
        half_spread = max(min_half, base_half_spread + fee_padding + latency_padding)
        if half_spread > max_half:
            raise HftMarketMakerError("SPREAD_LIMIT_CONFLICT")
        skew = current_inventory / config.max_inventory * half_spread * Decimal("0.5")
        raw_bid = reservation - half_spread - skew
        raw_ask = reservation + half_spread - skew
        bid_price = (raw_bid / config.tick_size).to_integral_value(
            rounding=ROUND_FLOOR
        ) * config.tick_size
        ask_price = (raw_ask / config.tick_size).to_integral_value(
            rounding=ROUND_CEILING
        ) * config.tick_size
        bid_qty = min(config.quote_size, config.max_inventory - current_inventory)
        ask_qty = min(config.quote_size, config.max_inventory + current_inventory)
        if bid_price <= 0 or ask_price <= bid_price:
            raise HftMarketMakerError("QUOTE_INVALID")
    if type(last.native_sequence) is not int:
        raise HftMarketMakerError("L2_SEQUENCE_GAP")
    return HftMarketMakerQuoteV1(
        bid_price=bid_price,
        bid_quantity=bid_qty,
        ask_price=ask_price,
        ask_quantity=ask_qty,
        mid_price=mid,
        microprice=microprice,
        reservation_price=reservation,
        sigma=sigma,
        l2_ofi=ofi,
        half_spread=half_spread,
        fee_padding=fee_padding,
        latency_padding=latency_padding,
        inventory=current_inventory,
        asof_ns=last.event_time_ns,
        age_ns=age_ns,
        native_sequence=last.native_sequence,
        provider=last.provider,
        dataset=last.dataset,
        venue=last.venue,
        instrument_id=last.instrument_id,
    )


__all__ = [
    "HftMarketMakerConfigV1",
    "HftMarketMakerError",
    "HftMarketMakerQuoteV1",
    "build_hft_mm_quote",
]
