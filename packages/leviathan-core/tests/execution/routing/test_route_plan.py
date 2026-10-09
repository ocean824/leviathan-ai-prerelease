"""Unit checks for the bounded offline routing kernel."""

import copy
import pickle
from dataclasses import replace
from decimal import Decimal, localcontext

import pytest

from leviathan_core.execution.routing import (
    BrokerReportV1,
    ExecutionEvidenceV1,
    ReconciledRerouteEvidenceV1,
    RerouteEvidenceV1,
    RoutePlanInputV1,
    RoutePlanV1,
    RouteValidationError,
    TacticParamsV1,
    VenueQuoteV1,
    VolumeCurveV1,
    plan_reroute,
    plan_route,
    reconcile_route_evidence,
)
from leviathan_core.execution.routing.models import _TRUSTED_ADAPTER_TOKEN

NOW = 1_000_000_000


def quote(venue: str, *, ask: str = "101", depth: str = "10") -> VenueQuoteV1:
    return VenueQuoteV1(
        venue_id=venue,
        bid=Decimal("100"),
        ask=Decimal(ask),
        bid_depth=Decimal(depth),
        ask_depth=Decimal(depth),
        event_time_ns=NOW - 100,
        receive_time_ns=NOW - 50,
        health="HEALTHY",
        permission=True,
        fee_bps=Decimal("0"),
        historical_slippage_bps=Decimal("0"),
        ping_ms=Decimal("2"),
        ping_time_ns=NOW - 100,
        lot_size=Decimal("1"),
        tick_size=Decimal("0.01"),
        mapped_instrument_id="NQ-2026Z",
        supported_order_types=("MARKET", "LIMIT"),
        supported_tifs=("DAY", "GTD", "IOC", "FOK"),
    )


def request(*quotes: VenueQuoteV1, quantity: str = "8") -> RoutePlanInputV1:
    return RoutePlanInputV1(
        parent_request_digest="a" * 64,
        account_id="paper-1",
        instrument_id="NQ-2026Z",
        instrument_mapping_id="map-v1",
        mapping_valid_from_ns=NOW - 10_000,
        mapping_valid_until_ns=NOW + 10_000,
        side="BUY",
        quantity=Decimal(quantity),
        limit_price=None,
        lot_size=Decimal("1"),
        tick_size=Decimal("0.01"),
        multiplier=Decimal("20"),
        allowed_venues=tuple(item.venue_id for item in quotes),
        venue_order=("A", "B"),
        policy_revision="routing-v1",
        routing_policy="best_price",
        max_venue_hops=2,
        order_type="MARKET",
        tif="DAY",
        hard_slippage_bps=Decimal("100"),
        latency_budget_ms=Decimal("10"),
        decision_time_ns=NOW,
        max_quote_age_ns=1_000,
        max_ping_age_ns=1_000,
        max_reconciliation_age_ns=1_000,
        max_slice_qty=Decimal("4"),
        depth_factor=Decimal("1"),
        venue_quotes=quotes,
        session_close_ns=NOW + 10_000,
    )


def trusted_evidence(
    item: RoutePlanInputV1,
    previous: RoutePlanV1,
    venue_evidence: tuple[RerouteEvidenceV1, ...],
) -> ReconciledRerouteEvidenceV1:
    reports = tuple(
        BrokerReportV1(
            parent_request_digest=item.parent_request_digest,
            policy_digest=previous.policy_digest,
            account_id=item.account_id,
            child_sequences=tuple(
                child.sequence for child in previous.children if child.venue_id == entry.venue_id
            ),
            broker_order_ids=tuple(
                f"order-{entry.venue_id}-{child.sequence}"
                for child in previous.children
                if child.venue_id == entry.venue_id
            ),
            terminal_receipt_ids=tuple(
                f"terminal-{entry.venue_id}-{child.sequence}"
                for child in previous.children
                if child.venue_id == entry.venue_id
            ),
            reconciliation_receipt_id=f"reconcile-{entry.venue_id}",
            evidence=entry,
            _adapter_token=_TRUSTED_ADAPTER_TOKEN,
        )
        for entry in venue_evidence
    )
    return reconcile_route_evidence(item, previous, reports)


def test_ranking_and_plan_are_independent_of_quote_arrival() -> None:
    left = plan_route(request(quote("B"), quote("A")))
    right = plan_route(request(quote("A"), quote("B")))
    assert left == right
    assert left.status == "PLANNED"
    assert [candidate.venue_id for candidate in left.candidates] == ["A", "B"]
    assert [child.quantity for child in left.children] == [Decimal("4"), Decimal("4")]
    assert sum((child.quantity for child in left.children), Decimal("0")) == Decimal("8")


def test_stale_and_unknown_quote_fail_closed() -> None:
    bad = replace(quote("A"), event_time_ns=NOW - 1_001)
    unknown = replace(quote("B"), ask=None)
    result = plan_route(request(bad, unknown))
    assert result.status == "BLOCKED"
    assert not result.children
    assert {item.venue_id for item in result.rejected} == {"A", "B"}


def test_missing_allowed_venue_is_invalid_snapshot() -> None:
    item = replace(request(quote("A")), allowed_venues=("A", "B"))
    with pytest.raises(RouteValidationError, match="incomplete venue snapshot"):
        plan_route(item)


def test_depth_and_lot_round_down_without_fabricated_liquidity() -> None:
    item = replace(
        request(quote("A", depth="5.9"), quantity="4"),
        venue_quotes=(replace(quote("A", depth="5.9"), lot_size=Decimal("2")),),
        max_slice_qty=Decimal("3.9"),
        depth_factor=Decimal("0.75"),
    )
    result = plan_route(item)
    assert result.status == "PLANNED"
    assert result.candidates[0].slice_cap_qty == Decimal("2")
    assert [child.quantity for child in result.children] == [Decimal("2"), Decimal("2")]
    partial = plan_route(replace(item, quantity=Decimal("6")))
    assert partial.status == "PARTIALLY_PLANNED"
    assert partial.unplanned_remainder == Decimal("2")
    assert sum((child.quantity for child in partial.children), Decimal("0")) == Decimal("4")


def test_twap_vwap_and_iceberg_require_explicit_bounded_parameters() -> None:
    base = request(quote("A"))
    params = TacticParamsV1(duration_ns=800, buckets=2, jitter_seed="seed", jitter_max_ns=50)
    twap = plan_route(replace(base, tactic="TWAP", tactic_params=params))
    assert twap.status == "PLANNED"
    assert [child.quantity for child in twap.children] == [Decimal("4"), Decimal("4")]
    assert twap == plan_route(replace(base, tactic="TWAP", tactic_params=params))
    assert plan_route(replace(base, tactic="VWAP", tactic_params=params)).status == "BLOCKED"
    curve = VolumeCurveV1("curve-v1", (Decimal("1"), Decimal("3")))
    vwap = plan_route(
        replace(base, tactic="VWAP", tactic_params=replace(params, volume_curve=curve))
    )
    assert [child.quantity for child in vwap.children] == [Decimal("2"), Decimal("4"), Decimal("2")]
    iceberg = plan_route(
        replace(base, tactic="ICEBERG", tactic_params=TacticParamsV1(peak_qty=Decimal("2")))
    )
    assert iceberg.status == "PLANNED"
    assert all(child.display_quantity <= Decimal("2") for child in iceberg.children)


def test_timeout_freezes_and_confirmed_reconciled_cancel_allows_remaining_route() -> None:
    base = request(quote("A"), quote("B", ask="102"))
    prior = plan_route(base)
    assert {child.venue_id for child in prior.children} == {"A"}
    timeout = RerouteEvidenceV1("A", "TIMEOUT", None, None, None)
    frozen = plan_reroute(base, prior, (timeout,))
    assert frozen.status == "FROZEN"
    assert "CANCEL_REQUESTED_UNCONFIRMED" in frozen.reason_codes
    confirmed = RerouteEvidenceV1(
        "A",
        "CANCELED",
        NOW,
        Decimal("0"),
        Decimal("0"),
        (ExecutionEvidenceV1("fill-1", Decimal("2")),),
    )
    assert plan_reroute(base, prior, (confirmed,)).status == "FROZEN"
    reroute = plan_reroute(base, prior, trusted_evidence(base, prior, (confirmed,)))
    assert reroute.status == "PLANNED"
    assert {child.venue_id for child in reroute.children} == {"B"}
    assert sum((child.quantity for child in reroute.children), Decimal("0")) == Decimal("6")
    duplicate = replace(
        confirmed,
        executions=(
            ExecutionEvidenceV1("fill-1", Decimal("2")),
            ExecutionEvidenceV1("fill-1", Decimal("2")),
        ),
    )
    assert plan_reroute(base, prior, (duplicate,)).status == "FROZEN"
    deduped = plan_reroute(base, prior, trusted_evidence(base, prior, (duplicate,)))
    assert deduped.status == "PLANNED"
    assert sum((child.quantity for child in deduped.children), Decimal("0")) == Decimal("6")


def test_post_gtd_fill_is_discrepancy_and_never_reroutes() -> None:
    base = replace(
        request(quote("A"), quote("B")),
        tif="GTD",
        gtd_expiry_ns=NOW + 100,
        session_close_ns=None,
    )
    prior = plan_route(base)
    later = replace(base, decision_time_ns=NOW + 200)
    evidence = tuple(
        RerouteEvidenceV1(
            venue_id,
            "CANCELED",
            NOW + 200,
            Decimal("0"),
            Decimal("0"),
            (ExecutionEvidenceV1("late", Decimal("1"), NOW + 150),) if index == 0 else (),
        )
        for index, venue_id in enumerate({child.venue_id for child in prior.children})
    )
    result = plan_reroute(later, prior, trusted_evidence(later, prior, evidence))
    assert result.status == "FROZEN"
    assert "POST_GTD_FILL_DISCREPANCY_OPERATOR_ALERT" in result.reason_codes
    assert not result.children


def test_day_tif_and_trusted_reconciliation_guards() -> None:
    base = request(quote("A"), quote("B", ask="102"))
    with pytest.raises(RouteValidationError, match="INVALID_TIF_COMBINATION"):
        replace(base, gtd_expiry_ns=NOW + 100)
    expired = plan_route(replace(base, session_close_ns=NOW + 100, decision_time_ns=NOW + 100))
    assert expired.status == "FROZEN"
    assert "DAY_EXPIRED_CANCEL_REQUESTED_UNCONFIRMED" in expired.reason_codes
    prior = plan_route(base)
    raw = RerouteEvidenceV1("A", "CANCELED", NOW, Decimal("0"), Decimal("0"))
    assert plan_reroute(base, prior, raw).status == "FROZEN"
    with pytest.raises(RouteValidationError, match="UNTRUSTED_BROKER_REPORT"):
        BrokerReportV1(
            base.parent_request_digest,
            prior.policy_digest,
            base.account_id,
            tuple(child.sequence for child in prior.children),
            tuple(f"order-{child.sequence}" for child in prior.children),
            tuple(f"receipt-{child.sequence}" for child in prior.children),
            "reconcile-A",
            raw,
        )
    report = BrokerReportV1(
        base.parent_request_digest,
        prior.policy_digest,
        base.account_id,
        tuple(child.sequence for child in prior.children),
        tuple(f"order-{child.sequence}" for child in prior.children),
        tuple(f"receipt-{child.sequence}" for child in prior.children),
        "reconcile-A",
        raw,
        _adapter_token=_TRUSTED_ADAPTER_TOKEN,
    )
    with pytest.raises(RouteValidationError, match="UNTRUSTED_BROKER_REPORT"):
        replace(report, evidence=raw)
    verified = trusted_evidence(base, prior, (raw,))
    with pytest.raises(RouteValidationError, match="UNCONFIRMED_BROKER_EVIDENCE"):
        replace(verified, evidence=())


def test_execution_identity_is_scoped_to_venue_and_conflicts_raise_discrepancy() -> None:
    a = replace(quote("A"), ask_depth=Decimal("4"))
    b = replace(quote("B", ask="102"), ask_depth=Decimal("4"))
    base = request(a, b)
    prior = plan_route(base)
    assert {child.venue_id for child in prior.children} == {"A", "B"}
    same_id = tuple(
        RerouteEvidenceV1(
            venue,
            "CANCELED",
            NOW,
            Decimal("0"),
            Decimal("0"),
            (ExecutionEvidenceV1("same-id", Decimal("1")),),
        )
        for venue in ("A", "B")
    )
    reports = tuple(
        BrokerReportV1(
            base.parent_request_digest,
            prior.policy_digest,
            base.account_id,
            tuple(child.sequence for child in prior.children if child.venue_id == item.venue_id),
            ("same-order-id",),
            ("same-terminal-receipt",),
            "same-reconciliation-receipt",
            item,
            _adapter_token=_TRUSTED_ADAPTER_TOKEN,
        )
        for item in same_id
    )
    verified = reconcile_route_evidence(base, prior, reports)
    assert verified.evidence == same_id
    conflict = replace(
        same_id[0],
        executions=(
            ExecutionEvidenceV1("same-id", Decimal("1")),
            ExecutionEvidenceV1("same-id", Decimal("2")),
        ),
    )
    with pytest.raises(RouteValidationError, match="DISCREPANCY"):
        trusted_evidence(base, prior, (conflict, same_id[1]))


def test_decimal_bounds_copy_and_replace_guards() -> None:
    base = request(quote("A"))
    with pytest.raises(RouteValidationError, match=r"^DECIMAL_OUT_OF_BOUNDS$"):
        replace(base, quantity=Decimal("1e39"))
    with pytest.raises(RouteValidationError, match=r"^PRECISION_EXCEEDED$"):
        replace(base, quantity=Decimal("1." + "1" * 35))
    with pytest.raises(RouteValidationError, match="MUTABLE_VENUE_LIST"):
        replace(base, allowed_venues=["A"])  # type: ignore[arg-type]
    for value in (base, base.venue_quotes[0], plan_route(base)):
        with pytest.raises(RouteValidationError, match="COPY_DISABLED"):
            copy.copy(value)
        with pytest.raises(RouteValidationError, match="COPY_DISABLED"):
            copy.deepcopy(value)
        with pytest.raises(RouteValidationError, match="SERIALIZATION_DISABLED"):
            pickle.dumps(value)


def test_numerically_equal_decimal_inputs_and_ambient_context_have_stable_digest() -> None:
    base = request(quote("A"), quote("B", ask="102"))
    equivalent = replace(
        base,
        quantity=Decimal("8.0"),
        max_slice_qty=Decimal("4.00"),
        hard_slippage_bps=Decimal("100.000"),
    )
    with localcontext() as context:
        context.prec = 6
        left = plan_route(base)
    with localcontext() as context:
        context.prec = 50
        right = plan_route(equivalent)
    assert left.policy_digest == right.policy_digest
    assert left == right
    trailing_zeros = replace(base, quantity=Decimal("8." + "0" * 50))
    assert plan_route(trailing_zeros).policy_digest == left.policy_digest


def test_tactic_bounds_are_checked_at_construction() -> None:
    with pytest.raises(RouteValidationError, match="POLICY_OUT_OF_BOUNDS"):
        TacticParamsV1(buckets=1025)
    with pytest.raises(RouteValidationError, match="POLICY_OUT_OF_BOUNDS"):
        TacticParamsV1(duration_ns=0)
    valid = TacticParamsV1(duration_ns=100, buckets=2)
    with pytest.raises(RouteValidationError, match="POLICY_OUT_OF_BOUNDS"):
        replace(valid, buckets=1025)
    with pytest.raises(RouteValidationError, match="POLICY_OUT_OF_BOUNDS") as jitter_bound:
        TacticParamsV1(duration_ns=10, buckets=2, jitter_seed="seed", jitter_max_ns=5)
    assert jitter_bound.value.reason_code == "JITTER_OUT_OF_BOUNDS"
    with pytest.raises(RouteValidationError, match="POLICY_OUT_OF_BOUNDS") as missing_seed:
        TacticParamsV1(duration_ns=10, buckets=2, jitter_max_ns=1)
    assert missing_seed.value.reason_code == "MISSING_JITTER_SEED"
    with pytest.raises(RouteValidationError, match="POLICY_OUT_OF_BOUNDS") as replaced_bound:
        replace(valid, duration_ns=10, jitter_seed="seed", jitter_max_ns=5)
    assert replaced_bound.value.reason_code == "JITTER_OUT_OF_BOUNDS"
    with pytest.raises(RouteValidationError, match="POLICY_OUT_OF_BOUNDS") as replaced_seed:
        replace(valid, duration_ns=10, jitter_max_ns=1)
    assert replaced_seed.value.reason_code == "MISSING_JITTER_SEED"
    # Compare against the exact rational bucket width, not its integer floor.
    assert TacticParamsV1(duration_ns=13, buckets=3, jitter_seed="seed", jitter_max_ns=2)
    with pytest.raises(RouteValidationError, match="POLICY_OUT_OF_BOUNDS") as exact_boundary:
        TacticParamsV1(duration_ns=12, buckets=3, jitter_seed="seed", jitter_max_ns=2)
    assert exact_boundary.value.reason_code == "JITTER_OUT_OF_BOUNDS"
