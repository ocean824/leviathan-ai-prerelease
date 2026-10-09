"""Owned checks for the read-only flash-loan route projection."""

import copy
import pickle
from dataclasses import fields, replace
from decimal import Decimal

import pytest

from leviathan_core.flash_loan_route_view import (
    AtomicityV1,
    MevRiskV1,
    RouteAgeBucketV1,
    RouteClassV1,
    RouteDisplayStatusV1,
    RouteFactsV1,
    RouteHopV1,
    RouteLockCodeV1,
    RouteLockV1,
    RouteReasonCodeV1,
    RouteViewClockV1,
    RouteViewError,
    RouteViewFilterV1,
    RouteViewSortFieldV1,
    RouteViewSortV1,
    RouteViewV1,
    list_routes,
    project_route,
)
from leviathan_core.seal import SealError, require


def _route(
    route_id: str = "route-a",
    *,
    route_class: RouteClassV1 = RouteClassV1.CROSS_DEX,
    atomicity: AtomicityV1 = AtomicityV1.ATOMIC,
    event_time_ns: int = 0,
    net_profit: Decimal = Decimal("12.5"),
    gas_cost: Decimal = Decimal("1.25"),
    mev_risk: MevRiskV1 = MevRiskV1.LOW,
    private_relay_enabled: bool = False,
    liquidity_available: bool = True,
    locks: tuple[RouteLockV1, ...] = (),
) -> RouteFactsV1:
    return RouteFactsV1(
        route_id=route_id,
        route_class=route_class,
        atomicity=atomicity,
        chain_id="chain-1",
        base_token="token-a",
        quote_token="token-b",
        hops=(
            RouteHopV1("venue-a", "token-a", "token-b"),
            RouteHopV1("venue-b", "token-b", "token-a"),
        ),
        net_profit=net_profit,
        spread_bps=Decimal("12.5"),
        gas_cost=gas_cost,
        loan_size=Decimal("100"),
        slippage_headroom_bps=Decimal("20"),
        latency_eta_ms=15,
        event_time_ns=event_time_ns,
        mev_risk=mev_risk,
        private_relay_enabled=private_relay_enabled,
        liquidity_available=liquidity_available,
        locks=locks,
    )


def _filters(**changes: object) -> RouteViewFilterV1:
    return RouteViewFilterV1(
        chain_id=changes.get("chain_id"),
        base_token=changes.get("base_token"),
        quote_token=changes.get("quote_token"),
        min_net_profit=changes.get("min_net_profit"),
        max_gas_cost=changes.get("max_gas_cost"),
        max_hop_count=changes.get("max_hop_count"),
        max_mev_risk=changes.get("max_mev_risk"),
        statuses=changes.get("statuses", ()),
        include_venues=changes.get("include_venues", ()),
        exclude_venues=changes.get("exclude_venues", ()),
    )


def _list(
    routes: tuple[RouteFactsV1, ...],
    *,
    filters: RouteViewFilterV1 | None = None,
    field: RouteViewSortFieldV1 = RouteViewSortFieldV1.ROUTE_ID,
    descending: bool = False,
    now_ns: int = 1,
):
    return list_routes(
        routes,
        clock=RouteViewClockV1(now_ns),
        filters=filters if filters is not None else _filters(),
        sort=RouteViewSortV1(field, descending),
    )


def test_injected_clock_projects_exact_age_boundaries() -> None:
    now = 1_000_000_000
    expected = (
        (249_999_999, 249, RouteAgeBucketV1.FRESH),
        (250_000_000, 250, RouteAgeBucketV1.AMBER),
        (750_000_000, 750, RouteAgeBucketV1.AMBER),
        (750_000_001, 750, RouteAgeBucketV1.STALE),
    )
    for age_ns, age_ms, bucket in expected:
        view = project_route(
            _route(event_time_ns=now - age_ns),
            clock=RouteViewClockV1(now),
        )
        assert view.age_ms == age_ms
        assert view.age_bucket is bucket


def test_future_route_event_rejected_without_reading_system_clock() -> None:
    with pytest.raises(RouteViewError) as caught:
        project_route(_route(event_time_ns=2), clock=RouteViewClockV1(1))
    assert caught.value.code == "INVALID_CLOCK"


def test_projected_views_are_issued_and_read_only_is_runtime_enforced() -> None:
    view = project_route(_route(), clock=RouteViewClockV1(1))
    assert view.read_only is True
    assert require(view, "fla.route_view.v1") is view

    view_fields = {field.name: getattr(view, field.name) for field in fields(view)}
    view_fields["read_only"] = False
    with pytest.raises(RouteViewError) as direct:
        RouteViewV1(**view_fields)
    assert direct.value.code == "INVALID_INPUT"

    with pytest.raises(RouteViewError) as replaced_false:
        replace(view, read_only=False)
    assert replaced_false.value.code == "INVALID_INPUT"

    unissued_direct = RouteViewV1(
        **{field.name: getattr(view, field.name) for field in fields(view)}
    )
    with pytest.raises(SealError) as direct_unissued:
        require(unissued_direct, "fla.route_view.v1")
    assert direct_unissued.value.code == "SEAL_NOT_ISSUED"

    unissued_replacement = replace(view, read_only=True)
    with pytest.raises(SealError) as replacement_unissued:
        require(unissued_replacement, "fla.route_view.v1")
    assert replacement_unissued.value.code == "SEAL_NOT_ISSUED"


def test_cex_dex_and_non_atomic_are_flash_ineligible_with_specific_reasons() -> None:
    cex = project_route(
        _route(route_class=RouteClassV1.CEX_DEX),
        clock=RouteViewClockV1(1),
    )
    assert cex.status is RouteDisplayStatusV1.FLASH_INELIGIBLE
    assert cex.reason_codes == (RouteReasonCodeV1.CEX_DEX,)
    assert cex.route_class is RouteClassV1.CEX_DEX

    non_atomic = project_route(
        _route(atomicity=AtomicityV1.NON_ATOMIC),
        clock=RouteViewClockV1(1),
    )
    assert non_atomic.status is RouteDisplayStatusV1.FLASH_INELIGIBLE
    assert non_atomic.atomicity is AtomicityV1.NON_ATOMIC
    assert non_atomic.reason_codes == (RouteReasonCodeV1.NON_ATOMIC,)


def test_specific_stale_reason_is_preserved_even_when_flash_ineligible() -> None:
    stale = project_route(
        _route(route_class=RouteClassV1.CEX_DEX, event_time_ns=0),
        clock=RouteViewClockV1(750_000_001),
    )
    assert stale.status is RouteDisplayStatusV1.FLASH_INELIGIBLE
    assert stale.reason_codes == (RouteReasonCodeV1.CEX_DEX, RouteReasonCodeV1.STALE_DATA)


@pytest.mark.parametrize(
    ("lock_code", "reason_code"),
    [
        (RouteLockCodeV1.MAX_NOTIONAL, RouteReasonCodeV1.LOCK_MAX_NOTIONAL),
        (RouteLockCodeV1.RATE_LIMIT, RouteReasonCodeV1.LOCK_RATE_LIMIT),
        (RouteLockCodeV1.TOKEN_BLOCKLIST, RouteReasonCodeV1.LOCK_TOKEN_BLOCKLIST),
        (RouteLockCodeV1.VENUE_BLOCKLIST, RouteReasonCodeV1.LOCK_VENUE_BLOCKLIST),
        (RouteLockCodeV1.SLIPPAGE_LIMIT, RouteReasonCodeV1.LOCK_SLIPPAGE_LIMIT),
        (RouteLockCodeV1.GAS_LIMIT, RouteReasonCodeV1.LOCK_GAS_LIMIT),
        (RouteLockCodeV1.TIME_WINDOW, RouteReasonCodeV1.LOCK_TIME_WINDOW),
    ],
)
def test_each_tripped_lock_projects_its_own_reason(
    lock_code: RouteLockCodeV1, reason_code: RouteReasonCodeV1
) -> None:
    route = _route(locks=(RouteLockV1(lock_code, True),))
    view = project_route(route, clock=RouteViewClockV1(1))
    assert view.status is RouteDisplayStatusV1.RISK_LOCKED
    assert view.reason_codes == (reason_code,)


def test_untripped_lock_does_not_block_but_high_mev_requires_private_relay() -> None:
    route = _route(
        mev_risk=MevRiskV1.HIGH,
        locks=(RouteLockV1(RouteLockCodeV1.MAX_NOTIONAL, False),),
    )
    blocked = project_route(route, clock=RouteViewClockV1(1))
    assert blocked.status is RouteDisplayStatusV1.RISK_LOCKED
    assert blocked.reason_codes == (RouteReasonCodeV1.MEV_HIGH_PRIVATE_RELAY_REQUIRED,)

    relayed = project_route(
        replace(route, private_relay_enabled=True),
        clock=RouteViewClockV1(1),
    )
    assert relayed.status is RouteDisplayStatusV1.VIABLE
    assert relayed.reason_codes == ()


def test_no_liquidity_has_specific_reason() -> None:
    view = project_route(
        _route(liquidity_available=False),
        clock=RouteViewClockV1(1),
    )
    assert view.status is RouteDisplayStatusV1.NO_LIQUIDITY
    assert view.reason_codes == (RouteReasonCodeV1.NO_LIQUIDITY,)


def test_filter_fields_are_explicit_and_filtering_is_deterministic() -> None:
    routes = (
        _route("route-c", net_profit=Decimal("3")),
        _route("route-b", net_profit=Decimal("5"), gas_cost=Decimal("2")),
        _route("route-a", net_profit=Decimal("5")),
    )
    filters = _filters(
        chain_id="chain-1",
        min_net_profit=Decimal("5"),
        max_gas_cost=Decimal("1.5"),
        max_hop_count=2,
        max_mev_risk=MevRiskV1.MEDIUM,
        statuses=(RouteDisplayStatusV1.VIABLE,),
        include_venues=("venue-a",),
        exclude_venues=("venue-x",),
    )
    forward = _list(routes, filters=filters, field=RouteViewSortFieldV1.NET_PROFIT, descending=True)
    reverse_input = _list(
        tuple(reversed(routes)),
        filters=filters,
        field=RouteViewSortFieldV1.NET_PROFIT,
        descending=True,
    )
    assert [view.route_id for view in forward] == ["route-a"]
    assert forward == reverse_input


def test_sort_ties_always_use_route_id_and_descending_is_repeatable() -> None:
    routes = (
        _route("route-c", net_profit=Decimal("4")),
        _route("route-a", net_profit=Decimal("4")),
        _route("route-b", net_profit=Decimal("4")),
    )
    first = _list(routes, field=RouteViewSortFieldV1.NET_PROFIT, descending=True)
    second = _list(tuple(reversed(routes)), field=RouteViewSortFieldV1.NET_PROFIT, descending=True)
    assert [view.route_id for view in first] == ["route-a", "route-b", "route-c"]
    assert first == second


def test_duplicate_ids_are_rejected_without_echoing_the_value() -> None:
    canary = "private-route-value"
    with pytest.raises(RouteViewError) as caught:
        _list((_route(canary), _route(canary)))
    assert caught.value.code == "DUPLICATE_ROUTE_ID"
    assert canary not in str(caught.value)
    assert canary not in repr(caught.value.args)


def test_routes_are_immutable_and_low_level_tampering_is_revalidated() -> None:
    route = _route()
    with pytest.raises(RouteViewError):
        copy.copy(route)
    with pytest.raises(RouteViewError):
        copy.deepcopy(route)
    with pytest.raises(RouteViewError):
        pickle.dumps(route)
    assert replace(route, route_id="route-replaced").route_id == "route-replaced"

    object.__setattr__(route, "route_id", "tampered\ncanary")
    with pytest.raises(RouteViewError) as caught:
        project_route(route, clock=RouteViewClockV1(1))
    assert caught.value.code == "INVALID_INPUT"
    assert "tampered" not in str(caught.value)


def test_inputs_reject_bool_as_timestamp_and_decimal_float() -> None:
    with pytest.raises(RouteViewError):
        RouteViewClockV1(True)  # type: ignore[arg-type]
    with pytest.raises(RouteViewError):
        _route(net_profit=1.25)  # type: ignore[arg-type]


def test_projection_exposes_only_read_only_state_without_action_surface() -> None:
    view = project_route(_route(), clock=RouteViewClockV1(1))
    assert isinstance(view, RouteViewV1)
    assert view.read_only is True
    forbidden = {"execute", "override", "simulate", "sign", "journal", "provider", "chain_client"}
    for field in fields(view):
        lowered = field.name.lower()
        assert not any(word in lowered for word in forbidden)
    assert view.status is RouteDisplayStatusV1.VIABLE
