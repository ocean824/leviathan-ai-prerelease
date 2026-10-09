"""Read-only projection of synthetic flash-loan route facts for display."""

from __future__ import annotations

import re
from dataclasses import dataclass, fields
from decimal import Decimal
from enum import StrEnum
from typing import Any, Literal, SupportsIndex, cast

from leviathan_core.numeric import NumericError, parse_decimal, parse_int
from leviathan_core.seal import Issuer

_VIEW_ISSUER = Issuer("fla.route_view.v1")
_IDENTIFIER = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z", re.ASCII)
_MAX_NS = (1 << 63) - 1
_MAX_HOPS = 8
_MAX_ROUTES = 5_000
_MAX_LOCKS = 64
_FRESH_CUTOFF_NS = 250_000_000
_AMBER_CUTOFF_NS = 750_000_000
_ERROR_CODES = frozenset(
    {
        "INVALID_INPUT",
        "INVALID_CLOCK",
        "INVALID_FILTER",
        "INVALID_SORT",
        "DUPLICATE_ROUTE_ID",
        "INPUT_LIMIT",
        "FORBIDDEN_OPERATION",
    }
)


class RouteViewError(ValueError):
    """A fixed-code rejection that never echoes route or filter values."""

    __slots__ = ("code",)

    def __init__(self, code: object) -> None:
        safe_code = code if type(code) is str and code in _ERROR_CODES else "INVALID_INPUT"
        self.code = safe_code
        super().__init__(safe_code)


class _Record:
    """Immutable display records reject serialization and copying by default."""

    def __copy__(self) -> Any:
        raise RouteViewError("FORBIDDEN_OPERATION")

    def __deepcopy__(self, memo: dict[int, object]) -> Any:
        raise RouteViewError("FORBIDDEN_OPERATION")

    def __reduce__(self) -> Any:
        raise RouteViewError("FORBIDDEN_OPERATION")

    def __reduce_ex__(self, protocol: SupportsIndex) -> Any:
        raise RouteViewError("FORBIDDEN_OPERATION")


class RouteClassV1(StrEnum):
    TRIANGULAR = "TRIANGULAR"
    CROSS_DEX = "CROSS_DEX"
    CEX_DEX = "CEX_DEX"


class AtomicityV1(StrEnum):
    ATOMIC = "ATOMIC"
    NON_ATOMIC = "NON_ATOMIC"


class MevRiskV1(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class RouteAgeBucketV1(StrEnum):
    FRESH = "FRESH"
    AMBER = "AMBER"
    STALE = "STALE"


class RouteDisplayStatusV1(StrEnum):
    VIABLE = "VIABLE"
    RISK_LOCKED = "RISK_LOCKED"
    STALE = "STALE"
    FLASH_INELIGIBLE = "FLASH_INELIGIBLE"
    NO_LIQUIDITY = "NO_LIQUIDITY"


class RouteLockCodeV1(StrEnum):
    MAX_NOTIONAL = "MAX_NOTIONAL"
    RATE_LIMIT = "RATE_LIMIT"
    TOKEN_BLOCKLIST = "TOKEN_BLOCKLIST"
    VENUE_BLOCKLIST = "VENUE_BLOCKLIST"
    SLIPPAGE_LIMIT = "SLIPPAGE_LIMIT"
    GAS_LIMIT = "GAS_LIMIT"
    TIME_WINDOW = "TIME_WINDOW"


class RouteReasonCodeV1(StrEnum):
    CEX_DEX = "CEX_DEX"
    LOCK_GAS_LIMIT = "LOCK_GAS_LIMIT"
    LOCK_MAX_NOTIONAL = "LOCK_MAX_NOTIONAL"
    LOCK_RATE_LIMIT = "LOCK_RATE_LIMIT"
    LOCK_SLIPPAGE_LIMIT = "LOCK_SLIPPAGE_LIMIT"
    LOCK_TIME_WINDOW = "LOCK_TIME_WINDOW"
    LOCK_TOKEN_BLOCKLIST = "LOCK_TOKEN_BLOCKLIST"
    LOCK_VENUE_BLOCKLIST = "LOCK_VENUE_BLOCKLIST"
    MEV_HIGH_PRIVATE_RELAY_REQUIRED = "MEV_HIGH_PRIVATE_RELAY_REQUIRED"
    NO_LIQUIDITY = "NO_LIQUIDITY"
    NON_ATOMIC = "NON_ATOMIC"
    STALE_DATA = "STALE_DATA"


class RouteViewSortFieldV1(StrEnum):
    NET_PROFIT = "NET_PROFIT"
    AGE = "AGE"
    GAS_COST = "GAS_COST"
    LATENCY = "LATENCY"
    HOP_COUNT = "HOP_COUNT"
    ROUTE_ID = "ROUTE_ID"


class SortDirectionV1(StrEnum):
    ASCENDING = "ASCENDING"
    DESCENDING = "DESCENDING"


@dataclass(frozen=True, slots=True)
class RouteHopV1(_Record):
    venue_id: str
    token_in: str
    token_out: str

    def __post_init__(self) -> None:
        _identifier(self.venue_id)
        _identifier(self.token_in)
        _identifier(self.token_out)


@dataclass(frozen=True, slots=True)
class RouteLockV1(_Record):
    code: RouteLockCodeV1
    tripped: bool

    def __post_init__(self) -> None:
        if type(self.code) is not RouteLockCodeV1 or type(self.tripped) is not bool:
            raise RouteViewError("INVALID_INPUT")


@dataclass(frozen=True, slots=True)
class RouteFactsV1(_Record):
    route_id: str
    route_class: RouteClassV1
    atomicity: AtomicityV1
    chain_id: str
    base_token: str
    quote_token: str
    hops: tuple[RouteHopV1, ...]
    net_profit: Decimal
    spread_bps: Decimal
    gas_cost: Decimal
    loan_size: Decimal
    slippage_headroom_bps: Decimal
    latency_eta_ms: int
    event_time_ns: int
    mev_risk: MevRiskV1
    private_relay_enabled: bool
    liquidity_available: bool
    locks: tuple[RouteLockV1, ...]

    def __post_init__(self) -> None:
        for value in (self.route_id, self.chain_id, self.base_token, self.quote_token):
            _identifier(value)
        if type(self.route_class) is not RouteClassV1 or type(self.atomicity) is not AtomicityV1:
            raise RouteViewError("INVALID_INPUT")
        if type(self.mev_risk) is not MevRiskV1:
            raise RouteViewError("INVALID_INPUT")
        if (
            type(self.private_relay_enabled) is not bool
            or type(self.liquidity_available) is not bool
        ):
            raise RouteViewError("INVALID_INPUT")
        if type(self.hops) is not tuple or not 1 <= len(self.hops) <= _MAX_HOPS:
            raise RouteViewError("INVALID_INPUT")
        if any(type(hop) is not RouteHopV1 for hop in self.hops):
            raise RouteViewError("INVALID_INPUT")
        for hop in self.hops:
            hop.__post_init__()
        for prior, following in zip(self.hops, self.hops[1:], strict=False):
            if prior.token_out != following.token_in:
                raise RouteViewError("INVALID_INPUT")
        if type(self.locks) is not tuple or len(self.locks) > _MAX_LOCKS:
            raise RouteViewError("INVALID_INPUT")
        if any(type(lock) is not RouteLockV1 for lock in self.locks):
            raise RouteViewError("INVALID_INPUT")
        for lock in self.locks:
            lock.__post_init__()
        if len({lock.code for lock in self.locks}) != len(self.locks):
            raise RouteViewError("INVALID_INPUT")
        object.__setattr__(self, "net_profit", _decimal(self.net_profit))
        object.__setattr__(self, "spread_bps", _decimal(self.spread_bps))
        object.__setattr__(self, "gas_cost", _decimal(self.gas_cost))
        object.__setattr__(self, "loan_size", _decimal(self.loan_size))
        object.__setattr__(self, "slippage_headroom_bps", _decimal(self.slippage_headroom_bps))
        _integer(self.latency_eta_ms, maximum=_MAX_NS)
        _integer(self.event_time_ns, maximum=_MAX_NS)


@dataclass(frozen=True, slots=True)
class RouteViewClockV1(_Record):
    now_ns: int

    def __post_init__(self) -> None:
        _integer(self.now_ns, maximum=_MAX_NS)


@dataclass(frozen=True, slots=True, weakref_slot=True)
class RouteViewV1(_Record):
    route_id: str
    route_class: RouteClassV1
    atomicity: AtomicityV1
    chain_id: str
    base_token: str
    quote_token: str
    hops: tuple[RouteHopV1, ...]
    venues: tuple[str, ...]
    net_profit: Decimal
    spread_bps: Decimal
    gas_cost: Decimal
    loan_size: Decimal
    slippage_headroom_bps: Decimal
    latency_eta_ms: int
    event_time_ns: int
    age_ns: int
    age_ms: int
    age_bucket: RouteAgeBucketV1
    mev_risk: MevRiskV1
    private_relay_enabled: bool
    liquidity_available: bool
    status: RouteDisplayStatusV1
    reason_codes: tuple[RouteReasonCodeV1, ...]
    read_only: Literal[True]

    def __post_init__(self) -> None:
        if self.read_only is not True:
            raise RouteViewError("INVALID_INPUT")


@dataclass(frozen=True, slots=True)
class RouteViewFilterV1(_Record):
    chain_id: str | None
    base_token: str | None
    quote_token: str | None
    min_net_profit: Decimal | None
    max_gas_cost: Decimal | None
    max_hop_count: int | None
    max_mev_risk: MevRiskV1 | None
    statuses: tuple[RouteDisplayStatusV1, ...]
    include_venues: tuple[str, ...]
    exclude_venues: tuple[str, ...]

    def __post_init__(self) -> None:
        for value in (self.chain_id, self.base_token, self.quote_token):
            if value is not None:
                _identifier(value)
        if self.min_net_profit is not None:
            object.__setattr__(self, "min_net_profit", _decimal(self.min_net_profit))
        if self.max_gas_cost is not None:
            object.__setattr__(self, "max_gas_cost", _decimal(self.max_gas_cost))
            if self.max_gas_cost < 0:
                raise RouteViewError("INVALID_FILTER")
        if self.max_hop_count is not None:
            _integer(self.max_hop_count, minimum=1, maximum=_MAX_HOPS)
        if self.max_mev_risk is not None and type(self.max_mev_risk) is not MevRiskV1:
            raise RouteViewError("INVALID_FILTER")
        if type(self.statuses) is not tuple or any(
            type(status) is not RouteDisplayStatusV1 for status in self.statuses
        ):
            raise RouteViewError("INVALID_FILTER")
        if len(set(self.statuses)) != len(self.statuses):
            raise RouteViewError("INVALID_FILTER")
        for venues in (self.include_venues, self.exclude_venues):
            if type(venues) is not tuple or len(venues) > _MAX_HOPS:
                raise RouteViewError("INVALID_FILTER")
            for venue in venues:
                _identifier(venue)
            if len(set(venues)) != len(venues):
                raise RouteViewError("INVALID_FILTER")


@dataclass(frozen=True, slots=True)
class RouteViewSortV1(_Record):
    field: RouteViewSortFieldV1
    descending: bool

    def __post_init__(self) -> None:
        if type(self.field) is not RouteViewSortFieldV1 or type(self.descending) is not bool:
            raise RouteViewError("INVALID_SORT")


def project_route(route: RouteFactsV1, *, clock: RouteViewClockV1) -> RouteViewV1:
    """Project validated facts to a display row without reading a live clock."""
    route = _revalidate(route, RouteFactsV1, "INVALID_INPUT")
    clock = _revalidate(clock, RouteViewClockV1, "INVALID_CLOCK")
    age_ns = clock.now_ns - route.event_time_ns
    if age_ns < 0:
        raise RouteViewError("INVALID_CLOCK")
    age_ms = age_ns // 1_000_000
    if age_ns < _FRESH_CUTOFF_NS:
        age_bucket = RouteAgeBucketV1.FRESH
    elif age_ns <= _AMBER_CUTOFF_NS:
        age_bucket = RouteAgeBucketV1.AMBER
    else:
        age_bucket = RouteAgeBucketV1.STALE

    reasons: set[RouteReasonCodeV1] = set()
    if route.route_class is RouteClassV1.CEX_DEX:
        reasons.add(RouteReasonCodeV1.CEX_DEX)
    if route.atomicity is AtomicityV1.NON_ATOMIC:
        reasons.add(RouteReasonCodeV1.NON_ATOMIC)
    if age_bucket is RouteAgeBucketV1.STALE:
        reasons.add(RouteReasonCodeV1.STALE_DATA)
    for lock in route.locks:
        if lock.tripped:
            reasons.add(_LOCK_REASON[lock.code])
    if route.mev_risk is MevRiskV1.HIGH and not route.private_relay_enabled:
        reasons.add(RouteReasonCodeV1.MEV_HIGH_PRIVATE_RELAY_REQUIRED)
    if not route.liquidity_available:
        reasons.add(RouteReasonCodeV1.NO_LIQUIDITY)

    flash_ineligible = bool(
        RouteReasonCodeV1.CEX_DEX in reasons or RouteReasonCodeV1.NON_ATOMIC in reasons
    )
    if flash_ineligible:
        status = RouteDisplayStatusV1.FLASH_INELIGIBLE
    elif age_bucket is RouteAgeBucketV1.STALE:
        status = RouteDisplayStatusV1.STALE
    elif any(lock.tripped for lock in route.locks) or (
        route.mev_risk is MevRiskV1.HIGH and not route.private_relay_enabled
    ):
        status = RouteDisplayStatusV1.RISK_LOCKED
    elif not route.liquidity_available:
        status = RouteDisplayStatusV1.NO_LIQUIDITY
    else:
        status = RouteDisplayStatusV1.VIABLE

    hops = tuple(_revalidate(hop, RouteHopV1, "INVALID_INPUT") for hop in route.hops)
    venues = tuple(hop.venue_id for hop in hops)
    return _VIEW_ISSUER.issue(
        RouteViewV1(
            route_id=route.route_id,
            route_class=route.route_class,
            atomicity=route.atomicity,
            chain_id=route.chain_id,
            base_token=route.base_token,
            quote_token=route.quote_token,
            hops=hops,
            venues=venues,
            net_profit=route.net_profit,
            spread_bps=route.spread_bps,
            gas_cost=route.gas_cost,
            loan_size=route.loan_size,
            slippage_headroom_bps=route.slippage_headroom_bps,
            latency_eta_ms=route.latency_eta_ms,
            event_time_ns=route.event_time_ns,
            age_ns=age_ns,
            age_ms=age_ms,
            age_bucket=age_bucket,
            mev_risk=route.mev_risk,
            private_relay_enabled=route.private_relay_enabled,
            liquidity_available=route.liquidity_available,
            status=status,
            reason_codes=tuple(sorted(reasons, key=lambda code: code.value)),
            read_only=True,
        )
    )


def list_routes(
    routes: tuple[RouteFactsV1, ...],
    *,
    clock: RouteViewClockV1,
    filters: RouteViewFilterV1,
    sort: RouteViewSortV1,
) -> tuple[RouteViewV1, ...]:
    """Filter and sort a synthetic route snapshot deterministically."""
    if type(routes) is not tuple or len(routes) > _MAX_ROUTES:
        raise RouteViewError("INPUT_LIMIT")
    checked_routes = tuple(_revalidate(route, RouteFactsV1, "INVALID_INPUT") for route in routes)
    if len({route.route_id for route in checked_routes}) != len(checked_routes):
        raise RouteViewError("DUPLICATE_ROUTE_ID")
    checked_clock = _revalidate(clock, RouteViewClockV1, "INVALID_CLOCK")
    checked_filter = _revalidate(filters, RouteViewFilterV1, "INVALID_FILTER")
    checked_sort = _revalidate(sort, RouteViewSortV1, "INVALID_SORT")

    projected = tuple(project_route(route, clock=checked_clock) for route in checked_routes)
    selected = [view for view in projected if _matches(view, checked_filter)]
    field = checked_sort.field
    if field is RouteViewSortFieldV1.ROUTE_ID:
        return tuple(
            sorted(selected, key=lambda view: view.route_id, reverse=checked_sort.descending)
        )

    selected.sort(key=lambda view: view.route_id)
    selected.sort(key=lambda view: _sort_value(view, field), reverse=checked_sort.descending)
    return tuple(selected)


def _matches(view: RouteViewV1, filters: RouteViewFilterV1) -> bool:
    if filters.chain_id is not None and view.chain_id != filters.chain_id:
        return False
    if filters.base_token is not None and view.base_token != filters.base_token:
        return False
    if filters.quote_token is not None and view.quote_token != filters.quote_token:
        return False
    if filters.min_net_profit is not None and view.net_profit < filters.min_net_profit:
        return False
    if filters.max_gas_cost is not None and view.gas_cost > filters.max_gas_cost:
        return False
    if filters.max_hop_count is not None and len(view.hops) > filters.max_hop_count:
        return False
    if filters.max_mev_risk is not None and _mev_rank(view.mev_risk) > _mev_rank(
        filters.max_mev_risk
    ):
        return False
    if filters.statuses and view.status not in filters.statuses:
        return False
    if filters.include_venues and not set(view.venues).intersection(filters.include_venues):
        return False
    return not set(view.venues).intersection(filters.exclude_venues)


def _sort_value(view: RouteViewV1, field: RouteViewSortFieldV1) -> Decimal | int | str:
    if field is RouteViewSortFieldV1.NET_PROFIT:
        return view.net_profit
    if field is RouteViewSortFieldV1.AGE:
        return view.age_ns
    if field is RouteViewSortFieldV1.GAS_COST:
        return view.gas_cost
    if field is RouteViewSortFieldV1.LATENCY:
        return view.latency_eta_ms
    if field is RouteViewSortFieldV1.HOP_COUNT:
        return len(view.hops)
    return view.route_id  # ROUTE_ID is handled separately.


def _mev_rank(risk: MevRiskV1) -> int:
    return {MevRiskV1.LOW: 0, MevRiskV1.MEDIUM: 1, MevRiskV1.HIGH: 2}[risk]


def _identifier(value: object) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise RouteViewError("INVALID_INPUT")
    return value


def _integer(value: object, *, minimum: int = 0, maximum: int = _MAX_NS) -> int:
    try:
        return parse_int(value, field="integer", min_value=minimum, max_value=maximum)
    except NumericError:
        raise RouteViewError("INVALID_INPUT") from None


def _decimal(value: object) -> Decimal:
    try:
        return parse_decimal(value, field="decimal")
    except NumericError:
        raise RouteViewError("INVALID_INPUT") from None


def _revalidate(value: object, expected: type[Any], code: str) -> Any:
    if type(value) is not expected:
        raise RouteViewError(code)
    try:
        return expected(
            **{field.name: getattr(value, field.name) for field in fields(cast(Any, expected))}
        )
    except RouteViewError:
        raise RouteViewError(code) from None
    except (AttributeError, TypeError, ValueError):
        raise RouteViewError(code) from None


_LOCK_REASON = {
    RouteLockCodeV1.MAX_NOTIONAL: RouteReasonCodeV1.LOCK_MAX_NOTIONAL,
    RouteLockCodeV1.RATE_LIMIT: RouteReasonCodeV1.LOCK_RATE_LIMIT,
    RouteLockCodeV1.TOKEN_BLOCKLIST: RouteReasonCodeV1.LOCK_TOKEN_BLOCKLIST,
    RouteLockCodeV1.VENUE_BLOCKLIST: RouteReasonCodeV1.LOCK_VENUE_BLOCKLIST,
    RouteLockCodeV1.SLIPPAGE_LIMIT: RouteReasonCodeV1.LOCK_SLIPPAGE_LIMIT,
    RouteLockCodeV1.GAS_LIMIT: RouteReasonCodeV1.LOCK_GAS_LIMIT,
    RouteLockCodeV1.TIME_WINDOW: RouteReasonCodeV1.LOCK_TIME_WINDOW,
}


__all__ = [
    "AtomicityV1",
    "MevRiskV1",
    "RouteAgeBucketV1",
    "RouteClassV1",
    "RouteDisplayStatusV1",
    "RouteFactsV1",
    "RouteHopV1",
    "RouteLockCodeV1",
    "RouteLockV1",
    "RouteReasonCodeV1",
    "RouteViewClockV1",
    "RouteViewError",
    "RouteViewFilterV1",
    "RouteViewSortFieldV1",
    "RouteViewSortV1",
    "RouteViewV1",
    "list_routes",
    "project_route",
]
