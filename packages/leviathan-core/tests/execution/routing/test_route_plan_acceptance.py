"""Independent acceptance tests for the deterministic route planner.

Assertions encode the frozen RISK/ROUTE contract and are intentionally independent
of the planner's scoring implementation.
"""

from __future__ import annotations

import copy
import json
import pickle
from dataclasses import replace
from decimal import ROUND_DOWN, Decimal, localcontext
from pathlib import Path
from typing import Any

import pytest

from leviathan_core.execution.routing import (
    BrokerReportV1,
    ExecutionEvidenceV1,
    RejectedVenueV1,
    RerouteEvidenceV1,
    RoutePlanInputV1,
    RouteValidationError,
    TacticParamsV1,
    VenueQuoteV1,
    VolumeCurveV1,
    plan_reroute,
    plan_route,
    reconcile_route_evidence,
)
from leviathan_core.execution.routing.models import _TRUSTED_ADAPTER_TOKEN

_FIXTURE = Path(__file__).parents[2] / "fixtures" / "routing" / "base_route.json"


def _decimalize_quote(raw: dict[str, Any]) -> VenueQuoteV1:
    for key in (
        "bid", "ask", "bid_depth", "ask_depth", "fee_bps",
        "historical_slippage_bps", "ping_ms", "lot_size", "tick_size",
        "own_bid", "own_ask",
    ):
        if raw.get(key) is not None:
            raw[key] = Decimal(raw[key])
    for key in ("supported_order_types", "supported_tifs"):
        raw[key] = tuple(raw.get(key, ()))
    return VenueQuoteV1(**raw)


def request(**changes: Any) -> RoutePlanInputV1:
    raw = json.loads(_FIXTURE.read_text(encoding="utf-8-sig"))
    raw["venue_quotes"] = tuple(_decimalize_quote(q) for q in raw["venue_quotes"])
    raw["allowed_venues"] = tuple(raw["allowed_venues"])
    raw["venue_order"] = tuple(raw["venue_order"])
    for key in (
        "quantity", "limit_price", "lot_size", "tick_size", "multiplier",
        "hard_slippage_bps", "latency_budget_ms", "max_slice_qty", "depth_factor",
    ):
        if raw.get(key) is not None:
            raw[key] = Decimal(raw[key])
    raw.update(changes)
    return RoutePlanInputV1(**raw)


def single_venue_request(**changes: Any) -> RoutePlanInputV1:
    base = request()
    quote = replace(base.venue_quotes[0], ask_depth=Decimal("20"))
    fields = {
        "allowed_venues": ("VENUE-A",),
        "venue_order": ("VENUE-A",),
        "max_venue_hops": 1,
        "max_slice_qty": Decimal("7"),
        "depth_factor": Decimal("1"),
        "venue_quotes": (quote,),
    }
    fields.update(changes)
    return replace(base, **fields)


def evidence_for_attempted_venues(
    previous: Any,
    *,
    outcome: str = "CANCELED",
    reconciled_at_ns: int | None = None,
    live_qty: Decimal | None = Decimal("0"),
    in_flight_qty: Decimal | None = Decimal("0"),
    execution_by_venue: dict[str, tuple[ExecutionEvidenceV1, ...]] | None = None,
    uncertain_venue: str | None = None,
    uncertain_outcome: str = "TIMEOUT",
) -> tuple[RerouteEvidenceV1, ...]:
    venues = previous.attempted_venues or tuple(
        candidate.venue_id for candidate in previous.candidates
    )
    return tuple(
        RerouteEvidenceV1(
            venue_id=venue_id,
            broker_outcome=(uncertain_outcome if venue_id == uncertain_venue else outcome),
            reconciled_at_ns=(None if venue_id == uncertain_venue else reconciled_at_ns),
            live_qty=(None if venue_id == uncertain_venue else live_qty),
            in_flight_qty=(None if venue_id == uncertain_venue else in_flight_qty),
            executions=(execution_by_venue or {}).get(venue_id, ()),
        )
        for venue_id in venues
    )


def trusted_evidence(
    request_value: RoutePlanInputV1,
    previous: Any,
    evidence: tuple[RerouteEvidenceV1, ...],
    *,
    shared_broker_order_id: str | None = None,
) -> Any:
    evidence_by_venue = {item.venue_id: item for item in evidence}
    child_sequences: dict[str, tuple[int, ...]] = {}
    for venue_id in {child.venue_id for child in previous.children}:
        child_sequences[venue_id] = tuple(
            child.sequence for child in previous.children if child.venue_id == venue_id
        )
    reports = tuple(
        BrokerReportV1(
            parent_request_digest=request_value.parent_request_digest,
            policy_digest=previous.policy_digest,
            account_id=request_value.account_id,
            child_sequences=sequences,
            broker_order_ids=tuple(
                (
                    shared_broker_order_id
                    if shared_broker_order_id is not None and index == 0
                    else f"broker-order-{venue_id}-{sequence}"
                )
                for index, sequence in enumerate(sequences)
            ),
            terminal_receipt_ids=tuple(
                f"terminal-receipt-{venue_id}-{sequence}" for sequence in sequences
            ),
            reconciliation_receipt_id=f"reconciliation-{venue_id}",
            evidence=evidence_by_venue[venue_id],
            _adapter_token=_TRUSTED_ADAPTER_TOKEN,
        )
        for venue_id, sequences in sorted(child_sequences.items())
    )
    return reconcile_route_evidence(request_value, previous, reports)


def _assert_no_executable_plan(result: Any) -> None:
    assert result.status != "PLANNED"
    assert result.children == ()


def test_tie_break_and_quote_permutation_are_stable() -> None:
    req = request(routing_policy="best_price")
    forward = plan_route(req)
    reversed_quotes = plan_route(replace(req, venue_quotes=tuple(reversed(req.venue_quotes))))

    assert forward == reversed_quotes
    assert forward.status == "PLANNED"
    assert forward.required_actions == ()
    assert forward.candidates[0].venue_id == "VENUE-A"
    assert tuple(child.sequence for child in forward.children) == tuple(
        sorted(child.sequence for child in forward.children)
    )
    assert sum((child.quantity for child in forward.children), Decimal(0)) <= req.quantity


def test_numerically_equal_decimal_inputs_have_the_same_policy_digest() -> None:
    integer_spelling = plan_route(request(quantity=Decimal("7")))
    fractional_spelling = plan_route(request(quantity=Decimal("7.0")))

    assert integer_spelling == fractional_spelling
    assert integer_spelling.policy_digest == fractional_spelling.policy_digest


def test_decimal_with_many_trailing_zeros_constructs_and_plans_canonically() -> None:
    padded_quantity = Decimal("8." + "0" * 50)
    padded_request = replace(request(), quantity=padded_quantity)
    canonical_request = replace(request(), quantity=Decimal("8"))

    padded_plan = plan_route(padded_request)
    canonical_plan = plan_route(canonical_request)

    assert padded_request.quantity == Decimal("8")
    assert padded_plan.status == "PLANNED"
    assert padded_plan == canonical_plan
    assert padded_plan.policy_digest == canonical_plan.policy_digest


def test_tactic_params_reject_out_of_bounds_values_on_construction_and_replace() -> None:
    with pytest.raises(RouteValidationError) as too_many_buckets:
        TacticParamsV1(buckets=1025)
    assert too_many_buckets.value.code == "POLICY_OUT_OF_BOUNDS"

    with pytest.raises(RouteValidationError) as zero_duration:
        TacticParamsV1(duration_ns=0)
    assert zero_duration.value.code == "POLICY_OUT_OF_BOUNDS"

    valid = TacticParamsV1(duration_ns=60_000, buckets=3)
    with pytest.raises(RouteValidationError) as replaced_buckets:
        replace(valid, buckets=1025)
    assert replaced_buckets.value.code == "POLICY_OUT_OF_BOUNDS"

    with pytest.raises(RouteValidationError) as replaced_duration:
        replace(valid, duration_ns=0)
    assert replaced_duration.value.code == "POLICY_OUT_OF_BOUNDS"


def test_jitter_bounds_are_validated_on_construction_and_replace() -> None:
    with pytest.raises(RouteValidationError) as jitter_exhausts_bucket:
        TacticParamsV1(
            duration_ns=10,
            buckets=2,
            jitter_max_ns=5,
            jitter_seed="seed",
    )
    assert jitter_exhausts_bucket.value.code == "POLICY_OUT_OF_BOUNDS"
    assert jitter_exhausts_bucket.value.reason_code == "JITTER_OUT_OF_BOUNDS"

    bounded = TacticParamsV1(
        duration_ns=10,
        buckets=2,
        jitter_max_ns=1,
        jitter_seed="seed",
    )
    with pytest.raises(RouteValidationError) as replaced_jitter:
        replace(bounded, jitter_max_ns=5)
    assert replaced_jitter.value.code == "POLICY_OUT_OF_BOUNDS"
    assert replaced_jitter.value.reason_code == "JITTER_OUT_OF_BOUNDS"

    with pytest.raises(RouteValidationError) as missing_seed:
        TacticParamsV1(duration_ns=10, buckets=2, jitter_max_ns=1)
    assert missing_seed.value.code == "POLICY_OUT_OF_BOUNDS"
    assert missing_seed.value.reason_code == "MISSING_JITTER_SEED"

    with pytest.raises(RouteValidationError) as replaced_missing_seed:
        replace(bounded, jitter_seed=None)
    assert replaced_missing_seed.value.code == "POLICY_OUT_OF_BOUNDS"
    assert replaced_missing_seed.value.reason_code == "MISSING_JITTER_SEED"


def test_route_math_is_independent_of_ambient_decimal_context() -> None:
    req = request()
    baseline = plan_route(req)

    with localcontext() as context:
        context.prec = 2
        context.rounding = ROUND_DOWN
        context.Emax = 9
        context.Emin = -9
        constrained_context = plan_route(req)

    assert constrained_context == baseline


@pytest.mark.parametrize(
    ("quantity", "expected_code"),
    [
        (Decimal("1e39"), "DECIMAL_OUT_OF_BOUNDS"),
        (Decimal("0." + "1" * 35), "PRECISION_EXCEEDED"),
    ],
)
def test_out_of_bounds_decimals_are_rejected_without_echoing_input(
    quantity: Decimal, expected_code: str,
) -> None:
    with pytest.raises(RouteValidationError) as error:
        request(quantity=quantity)

    assert error.value.code == expected_code
    assert str(quantity) not in str(error.value)


def test_decimal_precision_boundary_is_accepted_at_34_digits() -> None:
    quantity = Decimal("0." + "1" * 34)
    req = request(quantity=quantity, lot_size=quantity, max_slice_qty=quantity)

    assert req.quantity == quantity


def test_depth_product_that_would_round_at_precision_34_is_rejected() -> None:
    base = request()
    quote = replace(
        base.venue_quotes[0],
        ask_depth=Decimal("1." + "2" * 33),
    )
    req = request(
        allowed_venues=("VENUE-A",),
        venue_order=("VENUE-A",),
        venue_quotes=(quote,),
        depth_factor=Decimal("0." + "9" * 34),
    )

    with pytest.raises(RouteValidationError) as error:
        plan_route(req)

    assert error.value.code == "PRECISION_EXCEEDED"


def test_hard_slippage_uses_exact_comparison_at_fractional_bps_boundary() -> None:
    base = request()
    quotes = (
        replace(base.venue_quotes[0], bid=Decimal("2.75"), ask=Decimal("3")),
        replace(base.venue_quotes[1], bid=Decimal("3.75"), ask=Decimal("4")),
    )
    shared = {
        "allowed_venues": ("VENUE-A", "VENUE-B"),
        "venue_order": ("VENUE-A", "VENUE-B"),
        "venue_quotes": quotes,
        "depth_factor": Decimal("1"),
    }
    below_exact = plan_route(request(
        **shared,
        hard_slippage_bps=Decimal("3333.333333333333333333333333333333"),
    ))
    above_exact = plan_route(request(
        **shared,
        hard_slippage_bps=Decimal("3333.333333333333333333333333333334"),
    ))

    below_reasons = {
        rejected.venue_id: rejected.reason_codes for rejected in below_exact.rejected
    }
    above_candidates = {candidate.venue_id for candidate in above_exact.candidates}
    assert "HARD_SLIPPAGE" in below_reasons["VENUE-B"]
    assert "VENUE-B" in above_candidates


def test_route_models_are_deeply_frozen_and_cannot_be_copied_or_pickled() -> None:
    req = request()
    plan = plan_route(req)
    models = (
        req,
        req.venue_quotes[0],
        TacticParamsV1(),
        VolumeCurveV1("volume-v1", (Decimal("1"),)),
        plan.candidates[0],
        RejectedVenueV1("VENUE-X", ("INELIGIBLE",)),
        plan.children[0],
        plan,
        ExecutionEvidenceV1("execution-test", Decimal("1")),
        RerouteEvidenceV1(
            "VENUE-A", "REJECTED", 100_000, Decimal("0"), Decimal("0")
        ),
    )

    for model in models:
        with pytest.raises(RouteValidationError, match=r"^COPY_DISABLED$"):
            copy.copy(model)
        with pytest.raises(RouteValidationError, match=r"^COPY_DISABLED$"):
            copy.deepcopy(model)
        with pytest.raises(RouteValidationError, match=r"^SERIALIZATION_DISABLED$"):
            pickle.dumps(model)

    with pytest.raises(RouteValidationError):
        replace(req, quantity=Decimal("1e39"))
    with pytest.raises(RouteValidationError):
        replace(req, venue_quotes=list(req.venue_quotes))


def test_route_rejects_text_booleans_and_non_ascii_identifiers() -> None:
    req = request()
    with pytest.raises(RouteValidationError):
        replace(req.venue_quotes[0], permission="false")

    with pytest.raises(RouteValidationError):
        replace(req, account_id="account-é")

    with pytest.raises(RouteValidationError):
        request(allowed_venues=["VENUE-A"])


def test_plan_respects_maximum_venue_hops() -> None:
    req = request(max_venue_hops=1)
    result = plan_route(req)

    assert len(result.attempted_venues) <= 1
    assert result.status == "PARTIALLY_PLANNED"
    assert result.unplanned_remainder == Decimal("2")
    assert sum((child.quantity for child in result.children), Decimal(0)) == Decimal("5")
    assert (
        sum((child.quantity for child in result.children), Decimal(0))
        + result.unplanned_remainder
        == req.quantity
    )
    assert {child.venue_id for child in result.children} <= set(result.attempted_venues)


@pytest.mark.parametrize(
    ("field_changes", "quote_changes"),
    [
        ({}, {"event_time_ns": 1}),                         # stale
        ({}, {"health": None}),                            # unknown health
        ({}, {"permission": False}),                       # unentitled
        ({}, {"health": "DISABLED"}),                      # disabled
        ({}, {"bid": Decimal("101"), "ask": Decimal("100")}),  # crossed
        ({}, {"own_ask": Decimal("99.5")}),               # crosses own quote
        ({}, {"mapped_instrument_id": "WRONG"}),           # mapping mismatch
        ({}, {"ping_time_ns": 1}),                          # stale ping
    ],
)
def test_unsafe_venue_is_rejected(
    field_changes: dict[str, Any], quote_changes: dict[str, Any]
) -> None:
    req = request()
    quotes = list(req.venue_quotes)
    quotes[0] = replace(quotes[0], **quote_changes)
    result = plan_route(replace(req, venue_quotes=tuple(quotes), **field_changes))

    assert "VENUE-A" not in {candidate.venue_id for candidate in result.candidates}
    rejected = {venue.venue_id for venue in result.rejected}
    assert "VENUE-A" in rejected


def test_empty_venue_allowlist_never_routes() -> None:
    try:
        result = plan_route(request(allowed_venues=()))
    except RouteValidationError:
        return

    _assert_no_executable_plan(result)


def test_day_and_gtd_deadlines_must_match_the_time_in_force() -> None:
    with pytest.raises(RouteValidationError) as day_with_gtd:
        request(tif="DAY", gtd_expiry_ns=150_000)
    assert day_with_gtd.value.code == "INVALID_TIF_COMBINATION"

    with pytest.raises(RouteValidationError) as gtd_with_session_close:
        request(tif="GTD", gtd_expiry_ns=250_000, session_close_ns=200_000)
    assert gtd_with_session_close.value.code == "INVALID_TIF_COMBINATION"

    day_expired = plan_route(request(tif="DAY", session_close_ns=100_000))
    _assert_no_executable_plan(day_expired)
    assert "DAY_EXPIRED_CANCEL_REQUESTED_UNCONFIRMED" in day_expired.reason_codes


def test_same_execution_id_at_two_venues_counts_as_two_executions() -> None:
    req = request()
    previous = plan_route(req)
    venues = tuple(sorted({child.venue_id for child in previous.children}))
    assert len(venues) >= 2
    execution = ExecutionEvidenceV1("cross-venue-shared-execution", Decimal("1"))
    reports = evidence_for_attempted_venues(
        previous,
        reconciled_at_ns=req.decision_time_ns,
        execution_by_venue={venue: (execution,) for venue in venues},
    )
    sealed = trusted_evidence(req, previous, reports)
    result = plan_reroute(req, previous, sealed)

    assert result.status == "PLANNED"
    assert sum((child.quantity for child in result.children), Decimal(0)) == Decimal("5")


def test_conflicting_same_venue_execution_duplicate_is_a_discrepancy() -> None:
    req = request()
    previous = plan_route(req)
    first_venue = next(child.venue_id for child in previous.children)
    duplicate_evidence = evidence_for_attempted_venues(
        previous,
        reconciled_at_ns=req.decision_time_ns,
        execution_by_venue={
            first_venue: (
                ExecutionEvidenceV1("same-venue-execution", Decimal("1")),
                ExecutionEvidenceV1("same-venue-execution", Decimal("2")),
            )
        },
    )

    with pytest.raises(RouteValidationError) as error:
        trusted_evidence(req, previous, duplicate_evidence)
    assert error.value.code == "DISCREPANCY"


def test_parent_quantity_must_be_a_lot_multiple() -> None:
    quote = request().venue_quotes[0]
    quote = replace(quote, ask_depth=Decimal("1.9"), lot_size=Decimal("0.5"))
    with pytest.raises(RouteValidationError) as error:
        single_venue_request(
            quantity=Decimal("2.4"),
            lot_size=Decimal("0.5"),
            max_slice_qty=Decimal("2.4"),
            depth_factor=Decimal("0.8"),
            venue_quotes=(quote,),
            allowed_venues=("VENUE-A",),
            venue_order=("VENUE-A",),
        )

    assert str(error.value) == "INVALID_LOT_MULTIPLE"


def test_lot_aligned_parent_with_limited_depth_is_partially_planned() -> None:
    quote = request().venue_quotes[0]
    quote = replace(quote, ask_depth=Decimal("1.9"), lot_size=Decimal("0.5"))
    req = single_venue_request(
        quantity=Decimal("2.5"),
        lot_size=Decimal("0.5"),
        max_slice_qty=Decimal("2.5"),
        depth_factor=Decimal("0.8"),
        venue_quotes=(quote,),
        allowed_venues=("VENUE-A",),
        venue_order=("VENUE-A",),
    )
    result = plan_route(req)

    assert result.status == "PARTIALLY_PLANNED"
    assert result.children
    assert all(child.quantity % Decimal("0.5") == 0 for child in result.children)
    assert all(child.quantity <= req.quantity for child in result.children)
    assert sum((child.quantity for child in result.children), Decimal(0)) == Decimal("1.5")
    assert result.unplanned_remainder == Decimal("1.0")
    assert (
        sum((child.quantity for child in result.children), Decimal(0))
        + result.unplanned_remainder
        == req.quantity
    )
    assert "INSUFFICIENT_OBSERVED_DEPTH" in result.reason_codes


def test_zero_quantity_after_lot_rounding_is_rejected() -> None:
    quote = replace(request().venue_quotes[0], ask_depth=Decimal("0.4"), lot_size=Decimal("0.5"))
    req = request(
        quantity=Decimal("0.5"),
        lot_size=Decimal("0.5"),
        max_slice_qty=Decimal("0.5"),
        depth_factor=Decimal("1"),
        venue_quotes=(quote,),
        allowed_venues=("VENUE-A",),
        venue_order=("VENUE-A",),
    )

    try:
        result = plan_route(req)
    except RouteValidationError:
        return
    _assert_no_executable_plan(result)


def test_twap_requires_schedule_and_produces_deterministic_buckets() -> None:
    req = single_venue_request(
        tactic="TWAP",
        tactic_params=TacticParamsV1(duration_ns=60_000, buckets=3),
    )
    first = plan_route(req)
    second = plan_route(req)

    assert first == second
    assert first.status == "PLANNED"
    assert len(first.children) == 3
    assert sum((child.quantity for child in first.children), Decimal(0)) == req.quantity
    assert [child.scheduled_at_ns for child in first.children] == sorted(
        child.scheduled_at_ns for child in first.children
    )


@pytest.mark.parametrize(
    ("tactic", "params"),
    [
        ("TWAP", None),
        ("VWAP", TacticParamsV1(duration_ns=60_000, buckets=3)),
        ("ICEBERG", None),
    ],
)
def test_missing_tactic_parameters_are_rejected(tactic: str, params: TacticParamsV1 | None) -> None:
    req = single_venue_request(tactic=tactic, tactic_params=params)
    try:
        result = plan_route(req)
    except RouteValidationError:
        return
    _assert_no_executable_plan(result)


def test_vwap_requires_a_versioned_curve_and_iceberg_caps_displayed_quantity() -> None:
    curve = VolumeCurveV1(revision="volume-v3", weights=(Decimal("0.25"), Decimal("0.75")))
    vwap = plan_route(single_venue_request(
        tactic="VWAP",
        tactic_params=TacticParamsV1(duration_ns=60_000, buckets=2, volume_curve=curve),
    ))
    assert vwap.status == "PLANNED"
    assert sum((child.quantity for child in vwap.children), Decimal(0)) == Decimal("7")

    iceberg = plan_route(single_venue_request(
        tactic="ICEBERG",
        tactic_params=TacticParamsV1(peak_qty=Decimal("2")),
    ))
    assert iceberg.status == "PLANNED"
    assert all(child.display_quantity <= Decimal("2") for child in iceberg.children)


def test_jitter_requires_a_seed_and_seeded_schedule_is_repeatable() -> None:
    with pytest.raises(RouteValidationError) as missing_seed:
        TacticParamsV1(duration_ns=60_000, buckets=3, jitter_max_ns=1_000)
    assert missing_seed.value.code == "POLICY_OUT_OF_BOUNDS"
    assert missing_seed.value.reason_code == "MISSING_JITTER_SEED"

    seeded_request = single_venue_request(
        tactic="TWAP",
        tactic_params=TacticParamsV1(
            duration_ns=60_000,
            buckets=3,
            jitter_seed="synthetic-seed-001",
            jitter_max_ns=1_000,
        ),
    )
    first = plan_route(seeded_request)
    second = plan_route(seeded_request)

    assert first == second
    assert first.status == "PLANNED"
    assert all(
        seeded_request.decision_time_ns <= child.scheduled_at_ns
        <= seeded_request.decision_time_ns + 60_000 + 1_000
        for child in first.children
    )


def test_hard_slippage_cap_rejects_adverse_route() -> None:
    quotes = tuple(
        replace(q, historical_slippage_bps=Decimal("5"))
        for q in request().venue_quotes
    )
    req = request(hard_slippage_bps=Decimal("1"), venue_quotes=quotes)
    result = plan_route(req)

    _assert_no_executable_plan(result)
    assert result.reason_codes


@pytest.mark.parametrize("outcome", ["TIMEOUT", "UNKNOWN_SUBMIT", "UNKNOWN_CANCEL"])
def test_uncertain_prior_venue_freezes_reroute_without_confirming_cancel(outcome: str) -> None:
    req = request()
    previous = plan_route(req)
    evidence = evidence_for_attempted_venues(
        previous,
        reconciled_at_ns=req.decision_time_ns,
        uncertain_venue=(previous.attempted_venues or (previous.candidates[0].venue_id,))[0],
        uncertain_outcome=outcome,
    )

    result = plan_reroute(req, previous, evidence)

    assert result.status == "FROZEN"
    assert "UNCONFIRMED_BROKER_EVIDENCE" in result.reason_codes
    assert "RECONCILE" in result.required_actions
    assert result.children == ()


def test_reject_and_fresh_zero_live_reconciliation_allow_planned_reroute() -> None:
    req = request()
    previous = plan_route(req)
    evidence = evidence_for_attempted_venues(
        previous,
        outcome="REJECTED",
        reconciled_at_ns=req.decision_time_ns,
    )

    untrusted = plan_reroute(req, previous, evidence)
    assert untrusted.status == "FROZEN"
    assert "UNCONFIRMED_BROKER_EVIDENCE" in untrusted.reason_codes

    sealed = trusted_evidence(req, previous, evidence)
    result = plan_reroute(req, previous, sealed)

    assert result.status == "PLANNED"
    assert result.children


def test_same_broker_order_id_at_distinct_venues_is_accepted() -> None:
    req = request()
    previous = plan_route(req)
    venues = tuple(sorted({child.venue_id for child in previous.children}))
    assert len(venues) >= 2
    evidence = evidence_for_attempted_venues(
        previous,
        outcome="REJECTED",
        reconciled_at_ns=req.decision_time_ns,
    )

    sealed = trusted_evidence(
        req,
        previous,
        evidence,
        shared_broker_order_id="synthetic-shared-broker-order",
    )
    result = plan_reroute(req, previous, sealed)

    assert result.status == "PLANNED"
    assert result.children


def test_reroute_freezes_when_any_attempted_venue_lacks_terminal_evidence() -> None:
    req = request()
    previous = plan_route(req)
    all_evidence = evidence_for_attempted_venues(
        previous,
        outcome="REJECTED",
        reconciled_at_ns=req.decision_time_ns,
    )

    result = plan_reroute(req, previous, all_evidence[:1])

    assert result.status == "FROZEN"
    assert "UNCONFIRMED_BROKER_EVIDENCE" in result.reason_codes
    assert "RECONCILE" in result.required_actions
    assert result.children == ()


@pytest.mark.parametrize(
    ("reconciled_at", "live", "in_flight"),
    [
        (None, Decimal("0"), Decimal("0")),
        (90_000, Decimal("0"), Decimal("0")),
        (100_000, Decimal("1"), Decimal("0")),
        (100_000, Decimal("0"), Decimal("1")),
    ],
)
def test_reroute_requires_fresh_reconciliation_and_no_remaining_quantity(
    reconciled_at: int | None, live: Decimal, in_flight: Decimal
) -> None:
    req = request()
    previous = plan_route(req)
    evidence = evidence_for_attempted_venues(
        previous,
        reconciled_at_ns=reconciled_at,
        live_qty=live,
        in_flight_qty=in_flight,
    )

    result = plan_reroute(req, previous, evidence)

    _assert_no_executable_plan(result)


def test_duplicate_execution_evidence_freezes_instead_of_guessing_remaining_qty() -> None:
    req = request()
    previous = plan_route(req)
    execution = ExecutionEvidenceV1("execution-001", Decimal("1"))
    first_venue = (previous.attempted_venues or (previous.candidates[0].venue_id,))[0]
    evidence = evidence_for_attempted_venues(
        previous,
        reconciled_at_ns=req.decision_time_ns,
        execution_by_venue={first_venue: (execution, execution)},
    )

    result = plan_reroute(req, previous, evidence)

    assert result.status == "FROZEN"
    assert "UNCONFIRMED_BROKER_EVIDENCE" in result.reason_codes
    assert result.children == ()

    sealed = trusted_evidence(req, previous, evidence)
    result = plan_reroute(req, previous, sealed)
    assert result.status == "PLANNED"
    assert sum((child.quantity for child in result.children), Decimal(0)) == Decimal("6")


def test_fill_after_gtd_expiry_freezes_plan_and_flags_operator_discrepancy() -> None:
    base_quotes = request().venue_quotes
    initial_request = request(
        tif="GTD",
        gtd_expiry_ns=200_000,
        session_close_ns=None,
        venue_quotes=tuple(replace(q, supported_tifs=("GTD",)) for q in base_quotes),
    )
    previous = plan_route(initial_request)
    current_quotes = tuple(
        replace(
            q,
            event_time_ns=199_000,
            receive_time_ns=200_000,
            ping_time_ns=200_000,
        )
        for q in initial_request.venue_quotes
    )
    req = replace(initial_request, decision_time_ns=200_001, venue_quotes=current_quotes)
    first_venue = (previous.attempted_venues or (previous.candidates[0].venue_id,))[0]
    evidence = evidence_for_attempted_venues(
        previous,
        reconciled_at_ns=200_001,
        execution_by_venue={
            first_venue: (
                ExecutionEvidenceV1("late-exec-1", Decimal("1"), event_time_ns=200_000),
            )
        },
    )

    result = plan_reroute(req, previous, trusted_evidence(req, previous, evidence))

    assert result.status == "FROZEN"
    assert "POST_GTD_FILL_DISCREPANCY_OPERATOR_ALERT" in result.reason_codes
    assert result.required_actions == (
        "REQUEST_CANCEL",
        "RECONCILE",
        "RECORD_DISCREPANCY",
        "ALERT_OPERATOR",
    )
    assert result.children == ()

