"""Independent read-only route-view acceptance from wave24 §7 and the PRD."""

from __future__ import annotations

import importlib
import re
from collections.abc import Mapping
from dataclasses import fields, is_dataclass, replace
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

NOW_NS = 8_000_000_000
NANOSECONDS_PER_MILLISECOND = 1_000_000


def route(
    route_id: str = "route_a",
    *,
    route_class: RouteClassV1 = RouteClassV1.TRIANGULAR,
    atomicity: AtomicityV1 = AtomicityV1.ATOMIC,
    chain_id: str = "ethereum",
    base_token: str = "ETH",
    quote_token: str = "USDC",
    net_profit: Decimal = Decimal("1.5"),
    spread_bps: Decimal = Decimal("12.5"),
    gas_cost: Decimal = Decimal("40"),
    loan_size: Decimal = Decimal("1000"),
    slippage_headroom_bps: Decimal = Decimal("35"),
    latency_eta_ms: int = 100,
    age_ns: int = 100 * NANOSECONDS_PER_MILLISECOND,
    mev_risk: MevRiskV1 = MevRiskV1.LOW,
    private_relay_enabled: bool = False,
    liquidity_available: bool = True,
    locks: tuple[RouteLockV1, ...] = (),
    venue_ids: tuple[str, ...] = (),
    hop_count: int = 3,
) -> RouteFactsV1:
    tokens = [base_token]
    tokens.extend(f"MID_{route_id}_{index}" for index in range(hop_count - 1))
    tokens.append(base_token)
    venues = venue_ids or tuple(f"venue_{route_id}_{index}" for index in range(hop_count))
    assert len(venues) == hop_count
    hops = tuple(
        RouteHopV1(venue_id=venues[index], token_in=tokens[index], token_out=tokens[index + 1])
        for index in range(hop_count)
    )
    return RouteFactsV1(
        route_id=route_id,
        route_class=route_class,
        atomicity=atomicity,
        chain_id=chain_id,
        base_token=base_token,
        quote_token=quote_token,
        hops=hops,
        net_profit=net_profit,
        spread_bps=spread_bps,
        gas_cost=gas_cost,
        loan_size=loan_size,
        slippage_headroom_bps=slippage_headroom_bps,
        latency_eta_ms=latency_eta_ms,
        event_time_ns=NOW_NS - age_ns,
        mev_risk=mev_risk,
        private_relay_enabled=private_relay_enabled,
        liquidity_available=liquidity_available,
        locks=locks,
    )


def clock(now_ns: int = NOW_NS) -> RouteViewClockV1:
    return RouteViewClockV1(now_ns=now_ns)


def route_filter(**overrides: object) -> RouteViewFilterV1:
    values: dict[str, object] = {
        "chain_id": None,
        "base_token": None,
        "quote_token": None,
        "min_net_profit": None,
        "max_gas_cost": None,
        "max_hop_count": None,
        "max_mev_risk": None,
        "statuses": (),
        "include_venues": (),
        "exclude_venues": (),
    }
    values.update(overrides)
    return RouteViewFilterV1(**values)


def route_sort(
    field: RouteViewSortFieldV1 = RouteViewSortFieldV1.ROUTE_ID,
    *,
    descending: bool = False,
) -> RouteViewSortV1:
    return RouteViewSortV1(field=field, descending=descending)


def view_for(facts: RouteFactsV1):
    return project_route(facts, clock=clock())


def assert_read_only_no_enabled_action(state: object) -> None:
    """Walk the whole projection, including nested values, for action flags."""
    action_names = {
        "execute",
        "execute_enabled",
        "can_execute",
        "override",
        "override_enabled",
        "can_override",
        "simulate",
        "simulate_enabled",
        "can_simulate",
        "sign",
        "sign_enabled",
        "can_sign",
        "journal_write",
        "write_journal",
        "submit_transaction",
    }

    def visit(value: object) -> None:
        if is_dataclass(value) and not isinstance(value, type):
            visit({item.name: getattr(value, item.name) for item in fields(value)})
        elif hasattr(value, "model_dump"):
            visit(value.model_dump(mode="python"))
        elif isinstance(value, Mapping):
            for key, item in value.items():
                if isinstance(key, str) and key.lower() in action_names:
                    assert item is False or item is None, f"enabled action key: {key}"
                visit(item)
        elif isinstance(value, (tuple, list, set, frozenset)):
            for item in value:
                visit(item)

    assert getattr(state, "read_only", None) is True
    visit(state)


def safe_error(call, canary: str | None = None) -> RouteViewError:
    with pytest.raises(RouteViewError) as caught:
        call()
    error = caught.value
    assert error.code
    rendered = f"{error!s} {error!r} {error.args!r}"
    assert canary is None or canary not in rendered
    with pytest.raises(RouteViewError) as repeated:
        call()
    assert repeated.value.code == error.code
    return error


@pytest.mark.parametrize(
    "overrides",
    [
        {},
        {"age_ns": 800_000_000},
        {"locks": (RouteLockV1(code=RouteLockCodeV1.GAS_LIMIT, tripped=True),)},
        {"mev_risk": MevRiskV1.HIGH, "private_relay_enabled": False},
        {"liquidity_available": False},
    ],
)
def test_cex_dex_is_always_flash_ineligible_with_an_explicit_reason(overrides):
    facts = route(
        route_class=RouteClassV1.CEX_DEX,
        net_profit=Decimal("100"),
        **overrides,
    )
    view = view_for(facts)

    assert view.status is RouteDisplayStatusV1.FLASH_INELIGIBLE
    assert RouteReasonCodeV1.CEX_DEX in view.reason_codes
    assert view.atomicity is AtomicityV1.ATOMIC
    assert view.read_only is True
    assert_read_only_no_enabled_action(view)


def test_non_atomic_routes_are_flash_ineligible_and_keep_their_reason():
    view = view_for(route(atomicity=AtomicityV1.NON_ATOMIC))

    assert view.status is RouteDisplayStatusV1.FLASH_INELIGIBLE
    assert view.atomicity is AtomicityV1.NON_ATOMIC
    assert RouteReasonCodeV1.NON_ATOMIC in view.reason_codes


def test_stale_route_has_specific_reason_even_with_other_blockers():
    facts = route(
        route_id="stale_locked_route",
        age_ns=750_000_001,
        locks=(RouteLockV1(code=RouteLockCodeV1.GAS_LIMIT, tripped=True),),
    )
    view = view_for(facts)

    assert view.age_bucket is RouteAgeBucketV1.STALE
    assert RouteReasonCodeV1.STALE_DATA in view.reason_codes
    assert RouteReasonCodeV1.LOCK_GAS_LIMIT in view.reason_codes
    assert view.status in {
        RouteDisplayStatusV1.STALE,
        RouteDisplayStatusV1.RISK_LOCKED,
    }


def test_block_reasons_are_all_retained_in_canonical_order():
    view = view_for(
        route(
            route_class=RouteClassV1.CEX_DEX,
            atomicity=AtomicityV1.NON_ATOMIC,
            age_ns=800_000_000,
            mev_risk=MevRiskV1.HIGH,
            private_relay_enabled=False,
            liquidity_available=False,
            locks=(RouteLockV1(code=RouteLockCodeV1.RATE_LIMIT, tripped=True),),
        )
    )
    expected = (
        RouteReasonCodeV1.CEX_DEX,
        RouteReasonCodeV1.LOCK_RATE_LIMIT,
        RouteReasonCodeV1.MEV_HIGH_PRIVATE_RELAY_REQUIRED,
        RouteReasonCodeV1.NON_ATOMIC,
        RouteReasonCodeV1.NO_LIQUIDITY,
        RouteReasonCodeV1.STALE_DATA,
    )

    assert view.status is RouteDisplayStatusV1.FLASH_INELIGIBLE
    assert view.reason_codes == expected


@pytest.mark.parametrize("lock_code", tuple(RouteLockCodeV1))
def test_every_tripped_lock_has_its_own_specific_reason(lock_code: RouteLockCodeV1):
    view = view_for(route(locks=(RouteLockV1(code=lock_code, tripped=True),)))
    expected_reason = RouteReasonCodeV1[f"LOCK_{lock_code.value}"]

    assert view.status is RouteDisplayStatusV1.RISK_LOCKED
    assert expected_reason in view.reason_codes


def test_untripped_locks_do_not_emit_lock_reasons():
    facts = route(locks=tuple(RouteLockV1(code=code, tripped=False) for code in RouteLockCodeV1))
    view = view_for(facts)

    assert not any(reason.name.startswith("LOCK_") for reason in view.reason_codes)
    assert view.status is RouteDisplayStatusV1.VIABLE


def test_mev_high_requires_private_relay_and_exposes_the_reason():
    blocked = view_for(route(mev_risk=MevRiskV1.HIGH, private_relay_enabled=False))
    allowed_with_relay = view_for(route(mev_risk=MevRiskV1.HIGH, private_relay_enabled=True))

    assert blocked.status is RouteDisplayStatusV1.RISK_LOCKED
    assert RouteReasonCodeV1.MEV_HIGH_PRIVATE_RELAY_REQUIRED in blocked.reason_codes
    assert allowed_with_relay.status is RouteDisplayStatusV1.VIABLE
    assert RouteReasonCodeV1.MEV_HIGH_PRIVATE_RELAY_REQUIRED not in allowed_with_relay.reason_codes


@pytest.mark.parametrize(
    ("age_ns", "bucket", "age_ms"),
    [
        (249_999_999, RouteAgeBucketV1.FRESH, 249),
        (250_000_000, RouteAgeBucketV1.AMBER, 250),
        (750_000_000, RouteAgeBucketV1.AMBER, 750),
        (750_000_001, RouteAgeBucketV1.STALE, 750),
    ],
)
def test_age_bucket_uses_the_supplied_event_and_clock_pair(age_ns, bucket, age_ms):
    view = project_route(route(age_ns=age_ns), clock=clock(NOW_NS))

    assert view.age_bucket is bucket
    assert view.age_ms == age_ms


def test_future_event_time_is_rejected_against_the_injected_clock():
    error = safe_error(
        lambda: project_route(route(age_ns=-1), clock=clock(NOW_NS)),
    )

    assert error.code == "INVALID_CLOCK"


def filter_fixture() -> tuple[RouteFactsV1, ...]:
    return (
        route(
            "route_a",
            chain_id="ethereum",
            base_token="ETH",
            quote_token="USDC",
            net_profit=Decimal("1.5"),
            gas_cost=Decimal("40"),
            hop_count=2,
            venue_ids=("uni", "curve"),
            age_ns=100_000_000,
        ),
        route(
            "route_b",
            chain_id="polygon",
            base_token="ETH",
            quote_token="DAI",
            net_profit=Decimal("3"),
            gas_cost=Decimal("60"),
            hop_count=3,
            mev_risk=MevRiskV1.MEDIUM,
            venue_ids=("sushi", "uni", "curve"),
            age_ns=100_000_000,
        ),
        route(
            "route_c",
            chain_id="ethereum",
            base_token="WBTC",
            quote_token="USDC",
            net_profit=Decimal("2.5"),
            gas_cost=Decimal("20"),
            hop_count=4,
            mev_risk=MevRiskV1.HIGH,
            private_relay_enabled=True,
            venue_ids=("curve", "aave", "uni", "balancer"),
            age_ns=800_000_000,
        ),
        route(
            "route_d",
            chain_id="arbitrum",
            base_token="BTC",
            quote_token="USDC",
            net_profit=Decimal("0.5"),
            gas_cost=Decimal("20"),
            hop_count=1,
            liquidity_available=False,
            venue_ids=("aave",),
            age_ns=300_000_000,
        ),
    )


@pytest.mark.parametrize(
    ("filters", "expected_ids"),
    [
        ({"chain_id": "ethereum"}, ("route_a", "route_c")),
        ({"base_token": "ETH"}, ("route_a", "route_b")),
        ({"quote_token": "USDC"}, ("route_a", "route_c", "route_d")),
        ({"min_net_profit": Decimal("2")}, ("route_b", "route_c")),
        ({"max_gas_cost": Decimal("20")}, ("route_c", "route_d")),
        ({"max_hop_count": 2}, ("route_a", "route_d")),
        ({"max_mev_risk": MevRiskV1.MEDIUM}, ("route_a", "route_b", "route_d")),
        ({"statuses": (RouteDisplayStatusV1.NO_LIQUIDITY,)}, ("route_d",)),
        ({"include_venues": ("sushi",)}, ("route_b",)),
        ({"exclude_venues": ("uni",)}, ("route_d",)),
        (
            {"include_venues": ("uni",), "exclude_venues": ("uni",)},
            (),
        ),
    ],
)
def test_route_filters_are_applied_consistently(filters, expected_ids):
    result = list_routes(
        filter_fixture(),
        clock=clock(),
        filters=route_filter(**filters),
        sort=route_sort(),
    )

    assert tuple(item.route_id for item in result) == expected_ids
    for item in result:
        assert_read_only_no_enabled_action(item)


def test_sorts_are_repeatable_and_ties_break_by_route_id_in_both_directions():
    facts = filter_fixture()
    tie_cases = (
        (RouteViewSortFieldV1.NET_PROFIT, False),
        (RouteViewSortFieldV1.NET_PROFIT, True),
        (RouteViewSortFieldV1.AGE, False),
        (RouteViewSortFieldV1.AGE, True),
        (RouteViewSortFieldV1.GAS_COST, False),
        (RouteViewSortFieldV1.GAS_COST, True),
        (RouteViewSortFieldV1.LATENCY, False),
        (RouteViewSortFieldV1.LATENCY, True),
        (RouteViewSortFieldV1.HOP_COUNT, False),
        (RouteViewSortFieldV1.HOP_COUNT, True),
        (RouteViewSortFieldV1.ROUTE_ID, False),
        (RouteViewSortFieldV1.ROUTE_ID, True),
    )
    keys = {
        RouteViewSortFieldV1.NET_PROFIT: lambda item: item.net_profit,
        RouteViewSortFieldV1.AGE: lambda item: (NOW_NS - item.event_time_ns) // 1_000_000,
        RouteViewSortFieldV1.GAS_COST: lambda item: item.gas_cost,
        RouteViewSortFieldV1.LATENCY: lambda item: item.latency_eta_ms,
        RouteViewSortFieldV1.HOP_COUNT: lambda item: len(item.hops),
        RouteViewSortFieldV1.ROUTE_ID: lambda item: item.route_id,
    }

    for sort_field, descending in tie_cases:
        chosen_sort = route_sort(sort_field, descending=descending)
        result = list_routes(
            facts,
            clock=clock(),
            filters=route_filter(),
            sort=chosen_sort,
        )
        repeated = list_routes(
            tuple(reversed(facts)),
            clock=clock(),
            filters=route_filter(),
            sort=chosen_sort,
        )
        route_id_order = [item.route_id for item in sorted(facts, key=lambda item: item.route_id)]
        expected = sorted(
            route_id_order,
            key=lambda route_id: keys[sort_field](next(x for x in facts if x.route_id == route_id)),
            reverse=descending,
        )
        assert tuple(item.route_id for item in result) == tuple(expected)
        assert tuple(item.route_id for item in repeated) == tuple(expected)


def test_duplicate_route_ids_fail_with_content_free_stable_error():
    duplicate_id = "DUPLICATE_ROUTE_CANARY"
    values = (route(duplicate_id), route(duplicate_id, net_profit=Decimal("99")))

    def call():
        return list_routes(
            values,
            clock=clock(),
            filters=route_filter(),
            sort=route_sort(),
        )

    error = safe_error(call, duplicate_id)
    assert error.code


def test_projection_module_exposes_no_execute_override_simulate_or_sign_api():
    module = importlib.import_module("leviathan_core.flash_loan_route_view")
    forbidden = re.compile(r"execute|override|simulate|sign|journal_write", re.IGNORECASE)

    public_callables = (
        name for name, value in vars(module).items() if not name.startswith("_") and callable(value)
    )
    assert not tuple(name for name in public_callables if forbidden.search(name))

    projections = tuple(project_route(item, clock=clock()) for item in filter_fixture())
    for view in projections:
        assert_read_only_no_enabled_action(view)
    listed = list_routes(
        filter_fixture(),
        clock=clock(),
        filters=route_filter(),
        sort=route_sort(),
    )
    assert all(view.read_only is True for view in listed)
    for view in listed:
        assert_read_only_no_enabled_action(view)


def test_projected_route_views_are_issued_read_only_records():
    view = view_for(route("issued_view"))

    assert view.read_only is True
    assert require(view, "fla.route_view.v1") is view


def test_read_only_false_is_rejected_without_echoing_caller_content():
    valid = view_for(route("valid_route"))
    canary = "READ_ONLY_FALSE_CANARY"
    fields_by_name = {item.name: getattr(valid, item.name) for item in fields(RouteViewV1)}
    fields_by_name.update(route_id=canary, read_only=False)

    with pytest.raises(RouteViewError) as direct:
        RouteViewV1(**fields_by_name)
    assert direct.value.code == "INVALID_INPUT"
    assert canary not in f"{direct.value!s} {direct.value!r} {direct.value.args!r}"

    with pytest.raises(RouteViewError) as replaced:
        replace(valid, read_only=False)
    assert replaced.value.code == "INVALID_INPUT"
    assert canary not in f"{replaced.value!s} {replaced.value!r} {replaced.value.args!r}"


def test_replacement_with_read_only_true_is_a_valid_but_unissued_candidate():
    valid = view_for(route("issued_view"))
    replacement = replace(valid, read_only=True)

    assert replacement is not valid
    assert replacement.read_only is True
    with pytest.raises(SealError) as caught:
        require(replacement, "fla.route_view.v1")
    assert caught.value.code == "SEAL_NOT_ISSUED"
