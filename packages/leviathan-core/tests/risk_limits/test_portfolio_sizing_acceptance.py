"""Independent acceptance coverage for capped Kelly and portfolio heat."""

from __future__ import annotations

import copy
import json
import pickle
from dataclasses import replace
from decimal import ROUND_DOWN, Decimal, Inexact, Rounded, localcontext
from pathlib import Path
from typing import Any

import pytest

import leviathan_core.risk_limits.sizing_models as sizing_models_module
from leviathan_core.risk_limits import (
    DatedInstrumentV1,
    FxRateV1,
    HardLimitsV1,
    PolicyVerificationV1,
    PositionV1,
    ProjectedOrderV1,
    RiskStateV1,
    RollingRateCountV1,
    VerifiedHardLimitsV1,
    WorkingOrderV1,
    verify_hard_limits,
)
from leviathan_core.risk_limits.portfolio_sizing import size_portfolio
from leviathan_core.risk_limits.sizing_models import (
    CorrelationClusterV1,
    EquitySnapshotV1,
    PayoffEstimateV1,
    SizingDecisionV1,
    SizingEvidenceError,
    SizingEvidenceV1,
    SizingPolicyV1,
    StopLossV1,
)

_FIXTURES = Path(__file__).parents[1] / "fixtures" / "portfolio_sizing"
_RISK_FIXTURE = Path(__file__).parents[1] / "fixtures" / "risk_limits" / "base_policy.json"
_D = Decimal
_AS_OF = 1_000


class _PretendValidated:
    def __eq__(self, other: object) -> bool:
        return other == "VALIDATED"


class _TestOnlyVerifier:
    """Synthetic policy verifier; never wired to production."""

    def verify(
        self, policies: tuple[HardLimitsV1, ...], policy_digest: str
    ) -> PolicyVerificationV1:
        assert policies
        return PolicyVerificationV1(
            verifier_id="sizing-test-verifier",
            key_id="synthetic-test-key",
            policy_digest=policy_digest,
        )


def _base_records() -> dict[str, Any]:
    return json.loads((_FIXTURES / "base_sizing.json").read_text(encoding="utf-8"))


def _equity(**changes: Any) -> EquitySnapshotV1:
    fields = _base_records()["equity"]
    fields.update(changes)
    for key in ("equity", "buying_power"):
        fields[key] = _D(fields[key])
    return EquitySnapshotV1(**fields)


def _payoff(**changes: Any) -> PayoffEstimateV1:
    fields = _base_records()["payoff"]
    fields.update(changes)
    for key in ("win_probability", "win_payoff", "loss_payoff", "uncertainty_fraction"):
        fields[key] = _D(fields[key])
    return PayoffEstimateV1(**fields)


def _correlations(
    overrides: tuple[dict[str, Any], ...] | None = None,
) -> tuple[CorrelationClusterV1, ...]:
    entries = tuple(_base_records()["correlations"]) if overrides is None else overrides
    return tuple(
        CorrelationClusterV1(**entry) for entry in entries
    )


def _sizing_policy(**changes: Any) -> SizingPolicyV1:
    fields = _base_records()["policy"]
    fields.update(changes)
    for key in (
        "kelly_fraction_cap",
        "portfolio_heat_fraction_cap",
        "cluster_heat_fraction_cap",
        "lot_step",
    ):
        fields[key] = _D(fields[key])
    return SizingPolicyV1(**fields)


def _order(**changes: Any) -> ProjectedOrderV1:
    fields: dict[str, Any] = dict(
        environment="paper",
        account_id="account-demo-001",
        request_id="request-sizing-001",
        attempt_id="attempt-sizing-001",
        strategy_id="strategy-demo",
        venue_id="venue-demo",
        instrument_id="ES-202612",
        side="BUY",
        quantity=_D("2"),
        price=_D("100"),
        contract_multiplier=_D("1"),
        currency="USD",
        price_source_ns=990,
        price_ingest_ns=995,
        price_source_id="synthetic-price-001",
    )
    fields.update(changes)
    return ProjectedOrderV1(**fields)


def _state(**changes: Any) -> RiskStateV1:
    fields: dict[str, Any] = dict(
        environment="paper",
        account_id="account-demo-001",
        account_status="ACTIVE",
        source_ns=990,
        ingest_ns=995,
        last_committed_event_id="event-state-001",
        base_currency="USD",
        equity=_D("10000"),
        buying_power=_D("10000"),
        equity_source_ns=990,
        equity_ingest_ns=995,
        realized_pnl=_D("0"),
        unrealized_pnl=_D("0"),
        positions=(),
        committed_orders=(),
        reserved_orders=(),
        fx_rates=(),
        rolling_rate_counts=(RollingRateCountV1(60_000_000_000, 0, _AS_OF),),
    )
    fields.update(changes)
    return RiskStateV1(**fields)


def _evidence(
    *,
    order: ProjectedOrderV1 | None = None,
    state: RiskStateV1 | None = None,
    equity: EquitySnapshotV1 | None = None,
    payoff: PayoffEstimateV1 | None = None,
    correlations: tuple[CorrelationClusterV1, ...] | None = None,
    policy: SizingPolicyV1 | None = None,
    stops: tuple[StopLossV1, ...] | None = None,
) -> SizingEvidenceV1:
    return SizingEvidenceV1(
        order=order or _order(),
        state=state or _state(),
        equity=equity or _equity(),
        payoff=payoff or _payoff(),
        correlations=_correlations() if correlations is None else correlations,
        policy=policy or _sizing_policy(),
        stops=stops,
    )


def _hard_limits(**changes: Any) -> VerifiedHardLimitsV1:
    fields = json.loads(_RISK_FIXTURE.read_text(encoding="utf-8-sig"))
    fields["allowed_instruments"] = tuple(
        DatedInstrumentV1(**entry) for entry in fields["allowed_instruments"]
    )
    fields["allowed_strategies"] = tuple(fields["allowed_strategies"])
    fields["allowed_venues"] = tuple(fields["allowed_venues"])
    fields.update(changes)
    policy = HardLimitsV1(**fields)
    return verify_hard_limits((policy,), _TestOnlyVerifier())


def _size(
    evidence: SizingEvidenceV1 | None = None,
    hard_limits: VerifiedHardLimitsV1 | None = None,
    as_of_ns: int = _AS_OF,
):
    return size_portfolio(
        evidence if evidence is not None else _evidence(),
        hard_limits if hard_limits is not None else _hard_limits(),
        as_of_ns,
    )


def test_valid_sizing_is_a_lot_aligned_upper_bound_with_provenance() -> None:
    order = _order()
    decision = _size()

    assert decision.status == "SIZE"
    assert Decimal(0) <= decision.max_quantity <= order.quantity
    assert decision.max_quantity % _sizing_policy().lot_step == 0
    assert decision.reason_codes
    assert decision.evidence_digest
    assert decision.as_of_ns == _AS_OF


def test_missing_evidence_policy_or_hard_limits_fails_closed() -> None:
    assert size_portfolio(None, _hard_limits(), _AS_OF).status == "DENY"
    assert size_portfolio(_evidence(), None, _AS_OF).status == "DENY"

    missing_policy = replace(_evidence(), policy=None)
    decision = _size(missing_policy)
    assert decision.status == "DENY"


@pytest.mark.parametrize(
    ("payoff_changes", "expected_reason"),
    [
        ({"win_probability": "0.25"}, "KELLY_NONPOSITIVE"),
        ({"win_probability": "0.5", "win_payoff": "1", "loss_payoff": "1"}, "KELLY_NONPOSITIVE"),
        ({"sample_count": 0}, "PAYOFF_UNVERIFIED"),
        ({"validation_status": "UNVALIDATED"}, "PAYOFF_UNVERIFIED"),
        ({"uncertainty_fraction": "0.01"}, "PAYOFF_UNCERTAIN"),
    ],
)
def test_unproven_or_nonpositive_payoff_never_produces_size(
    payoff_changes: dict[str, Any], expected_reason: str
) -> None:
    decision = _size(_evidence(payoff=_payoff(**payoff_changes)))

    assert decision.status == "DENY"
    assert decision.max_quantity == 0
    assert expected_reason in decision.reason_codes


def test_equity_age_equality_is_eligible_and_plus_one_is_stale() -> None:
    as_of = 300_000_000_000
    exact_evidence = _evidence(
        order=_order(price_source_ns=0, price_ingest_ns=0),
        state=_state(
            source_ns=0,
            ingest_ns=0,
            equity_source_ns=0,
            equity_ingest_ns=0,
            rolling_rate_counts=(RollingRateCountV1(60_000_000_000, 0, as_of),),
        ),
        equity=_equity(event_ns=0, received_ns=0),
        payoff=_payoff(event_ns=0, received_ns=0),
        correlations=tuple(
            replace(item, event_ns=0, received_ns=0) for item in _correlations()
        ),
        policy=_sizing_policy(effective_until_ns=as_of + 2),
    )
    hard_limits = _hard_limits(
        max_data_age_ns=as_of,
        effective_until_ns=as_of + 2,
        allowed_instruments=(DatedInstrumentV1("ES-202612", 0, as_of + 2),),
    )
    exact = _size(exact_evidence, hard_limits, as_of)
    stale = _size(exact_evidence, hard_limits, as_of + 1)

    assert exact.status == "SIZE"
    assert "EQUITY_STALE" in stale.reason_codes
    assert stale.status == "DENY"


def test_state_and_market_evidence_must_be_fresh() -> None:
    as_of = 300_000_000_001
    common = dict(
        order=_order(price_source_ns=1, price_ingest_ns=1),
        equity=_equity(event_ns=1, received_ns=1),
        payoff=_payoff(event_ns=1, received_ns=1),
        correlations=tuple(
            replace(item, event_ns=1, received_ns=1) for item in _correlations()
        ),
        policy=_sizing_policy(effective_until_ns=as_of + 1),
    )
    stale_state = _evidence(
        **common,
        state=_state(
            source_ns=0,
            ingest_ns=1,
            equity_source_ns=1,
            equity_ingest_ns=1,
            rolling_rate_counts=(RollingRateCountV1(60_000_000_000, 0, as_of),),
        ),
    )
    limits = _hard_limits(
        max_data_age_ns=300_000_000_000,
        effective_until_ns=as_of + 1,
        allowed_instruments=(DatedInstrumentV1("ES-202612", 0, as_of + 1),),
    )
    stale_decision = _size(stale_state, limits, as_of)

    assert stale_decision.status == "DENY"
    assert "BROKER_STATE_STALE" in stale_decision.reason_codes


def test_correlation_mapping_is_required_for_every_exposure() -> None:
    no_candidate_mapping = _size(_evidence(correlations=()))
    unvalidated = _size(_evidence(correlations=(
        replace(_correlations()[0], validation_status="UNVALIDATED"),
    )))
    unmapped_position = PositionV1(
        instrument_id="NQ-202612",
        quantity=_D("1"),
        mark_price=_D("100"),
        contract_multiplier=_D("1"),
        currency="USD",
        price_source_ns=990,
        price_ingest_ns=995,
        price_source_id="synthetic-position-price",
    )
    missing_position_cluster = _size(_evidence(
        state=_state(positions=(unmapped_position,)),
        correlations=_correlations(),
    ))

    assert no_candidate_mapping.status == "DENY"
    assert "CORRELATION_MISSING" in no_candidate_mapping.reason_codes
    assert unvalidated.status == "DENY"
    assert "CORRELATION_UNVERIFIED" in unvalidated.reason_codes
    assert missing_position_cluster.status == "DENY"
    assert "CORRELATION_MISSING" in missing_position_cluster.reason_codes


def test_missing_or_stale_fx_denies_nonbase_currency_exposure() -> None:
    order = _order(currency="EUR")
    missing = _size(_evidence(order=order))
    stale_rate = FxRateV1(
        currency="EUR",
        base_currency="USD",
        base_units_per_unit=_D("1.1"),
        source_ns=0,
        ingest_ns=1,
        source_id="synthetic-fx-001",
    )
    as_of = 300_000_000_001
    stale_evidence = _evidence(
        order=replace(order, price_source_ns=1, price_ingest_ns=1),
        state=_state(
            source_ns=1,
            ingest_ns=1,
            equity_source_ns=1,
            equity_ingest_ns=1,
            rolling_rate_counts=(RollingRateCountV1(60_000_000_000, 0, as_of),),
            fx_rates=(stale_rate,),
        ),
        equity=_equity(event_ns=1, received_ns=1),
        payoff=_payoff(event_ns=1, received_ns=1),
        correlations=tuple(
            replace(item, event_ns=1, received_ns=1) for item in _correlations()
        ),
        policy=_sizing_policy(effective_until_ns=as_of + 1),
    )
    limits = _hard_limits(
        max_data_age_ns=300_000_000_000,
        effective_until_ns=as_of + 1,
        allowed_instruments=(DatedInstrumentV1("ES-202612", 0, as_of + 1),),
    )
    stale = _size(stale_evidence, limits, as_of)

    assert missing.status == "DENY"
    assert "FX_MISSING" in missing.reason_codes
    assert stale.status == "DENY"
    assert "FX_STALE" in stale.reason_codes


def test_portfolio_heat_cap_allows_equality_and_reduces_one_unit_over() -> None:
    exact_order = _order(quantity=_D("1"), price=_D("1"))
    evidence = _evidence(
        order=exact_order,
        state=_state(equity=_D("10"), buying_power=_D("10")),
        equity=_equity(equity=_D("10"), buying_power=_D("10")),
        policy=_sizing_policy(
            kelly_fraction_cap=_D("1"),
            portfolio_heat_fraction_cap=_D("0.1"),
        ),
    )
    exact = _size(evidence)
    one_over = _size(replace(evidence, order=replace(exact_order, quantity=_D("2"))))

    assert exact.status == "SIZE"
    assert exact.max_quantity == _D("1")
    assert one_over.status == "SIZE"
    assert one_over.max_quantity == _D("1")
    assert "HEAT_REDUCED" in one_over.reason_codes


def _candidate_stop(loss_per_unit: Decimal, **changes: Any) -> StopLossV1:
    fields: dict[str, Any] = dict(
        instrument_id="ES-202612",
        request_id="request-sizing-001",
        attempt_id="attempt-sizing-001",
        loss_per_unit=loss_per_unit,
        source_id="synthetic-stop-001",
        revision="stop-v1",
        event_ns=990,
        received_ns=995,
        validation_status="VALIDATED",
    )
    fields.update(changes)
    return StopLossV1(**fields)


def test_stop_loss_per_unit_must_be_positive_at_construction_and_replace() -> None:
    with pytest.raises(SizingEvidenceError) as direct:
        _candidate_stop(_D("0"))
    assert direct.value.code == "STOP_LOSS_INVALID"

    valid_stop = _candidate_stop(_D("1"))
    with pytest.raises(SizingEvidenceError) as replaced:
        replace(valid_stop, loss_per_unit=_D("0"))
    assert replaced.value.code == "STOP_LOSS_INVALID"


def test_exact_global_heat_cap_allows_equality_and_floors_the_excess_lot() -> None:
    evidence = _evidence(
        order=_order(quantity=_D("3"), price=_D("1")),
        state=_state(equity=_D("10"), buying_power=_D("10")),
        equity=_equity(equity=_D("10"), buying_power=_D("10")),
        payoff=_payoff(win_probability="0.9", win_payoff="100", loss_payoff="1"),
        policy=_sizing_policy(
            kelly_fraction_cap=_D("1"),
            portfolio_heat_fraction_cap=_D("0.1"),
            cluster_heat_fraction_cap=_D("0.5"),
        ),
        stops=(_candidate_stop(_D("0.5")),),
    )
    exactly_at_cap = _size(replace(evidence, order=replace(evidence.order, quantity=_D("2"))))
    one_lot_over = _size(evidence)

    assert exactly_at_cap.status == "SIZE"
    assert exactly_at_cap.max_quantity == _D("2")
    assert one_lot_over.status == "SIZE"
    assert one_lot_over.max_quantity == _D("2")
    assert "HEAT_REDUCED" in one_lot_over.reason_codes


def test_exact_cluster_heat_cap_reduces_without_rounding_toward_the_cap() -> None:
    evidence = _evidence(
        order=_order(quantity=_D("3"), price=_D("1")),
        state=_state(equity=_D("10"), buying_power=_D("10")),
        equity=_equity(equity=_D("10"), buying_power=_D("10")),
        payoff=_payoff(win_probability="0.9", win_payoff="100", loss_payoff="1"),
        policy=_sizing_policy(
            kelly_fraction_cap=_D("1"),
            portfolio_heat_fraction_cap=_D("0.5"),
            cluster_heat_fraction_cap=_D("0.1"),
        ),
        stops=(_candidate_stop(_D("0.5")),),
    )
    decision = _size(evidence)

    assert decision.status == "SIZE"
    assert decision.max_quantity == _D("2")
    assert "HEAT_REDUCED" in decision.reason_codes


@pytest.mark.parametrize(
    ("portfolio_cap", "cluster_cap", "expected_reason"),
    [
        (
            "0.3333333333333333333333333333333333",
            "0.5",
            "PORTFOLIO_HEAT_EXCEEDED",
        ),
        (
            "0.5",
            "0.3333333333333333333333333333333333",
            "CLUSTER_HEAT_EXCEEDED",
        ),
    ],
)
def test_repeating_heat_ratio_is_compared_exactly_not_rounded_down_to_cap(
    portfolio_cap: str, cluster_cap: str, expected_reason: str
) -> None:
    evidence = _evidence(
        order=_order(quantity=_D("1"), price=_D("1")),
        state=_state(equity=_D("3"), buying_power=_D("3")),
        equity=_equity(equity=_D("3"), buying_power=_D("3")),
        payoff=_payoff(win_probability="0.9", win_payoff="100", loss_payoff="1"),
        policy=_sizing_policy(
            kelly_fraction_cap=_D("1"),
            portfolio_heat_fraction_cap=_D(portfolio_cap),
            cluster_heat_fraction_cap=_D(cluster_cap),
        ),
    )
    decision = _size(evidence)

    assert decision.status == "DENY"
    assert decision.max_quantity == 0
    assert expected_reason in decision.reason_codes


def test_unknown_unvalidated_or_future_stop_uses_full_notional_loss() -> None:
    order = _order(quantity=_D("3"), price=_D("1"))
    evidence = _evidence(
        order=order,
        state=_state(equity=_D("10"), buying_power=_D("10")),
        equity=_equity(equity=_D("10"), buying_power=_D("10")),
        payoff=_payoff(win_probability="0.9", win_payoff="100", loss_payoff="1"),
        policy=_sizing_policy(
            kelly_fraction_cap=_D("1"),
            portfolio_heat_fraction_cap=_D("0.1"),
            cluster_heat_fraction_cap=_D("0.1"),
        ),
        stops=(_candidate_stop(_D("0.25")),),
    )
    unknown = _size(replace(evidence, stops=None))
    unvalidated = _size(replace(
        evidence,
        stops=(_candidate_stop(_D("0.25"), validation_status="UNVALIDATED"),),
    ))
    future = _size(replace(
        evidence,
        stops=(_candidate_stop(_D("0.25"), event_ns=1_001, received_ns=1_001),),
    ))

    assert unknown.max_quantity == _D("1")
    assert unvalidated.max_quantity == _D("1")
    assert future.max_quantity == _D("1")


def test_position_and_working_order_stop_keys_are_distinct_and_commitments_are_deduped() -> None:
    position = PositionV1(
        instrument_id="ES-202612",
        quantity=_D("1"),
        mark_price=_D("100"),
        contract_multiplier=_D("1"),
        currency="USD",
        price_source_ns=990,
        price_ingest_ns=995,
        price_source_id="synthetic-position-price",
    )
    working = WorkingOrderV1(
        request_id="working-request",
        attempt_id="working-attempt",
        instrument_id="ES-202612",
        side="BUY",
        quantity=_D("1"),
        price=_D("100"),
        contract_multiplier=_D("1"),
        currency="USD",
        price_source_ns=990,
        price_ingest_ns=995,
        price_source_id="synthetic-working-price",
    )
    baseline = _evidence(
        state=_state(positions=(position,), committed_orders=(working,)),
    )
    position_stop = StopLossV1(
        "ES-202612", None, None, _D("1"), "synthetic-position-stop", "v1", 990, 995, "VALIDATED"
    )
    working_stop = StopLossV1(
        "ES-202612", "working-request", "working-attempt", _D("1"),
        "synthetic-working-stop", "v1", 990, 995, "VALIDATED",
    )
    candidate_stop = _candidate_stop(_D("1"))
    stops = (position_stop, working_stop, candidate_stop)
    policy = _sizing_policy(
        portfolio_heat_fraction_cap=_D("0.1"),
        cluster_heat_fraction_cap=_D("0.1"),
    )
    evidence = replace(baseline, policy=policy, stops=stops)
    duplicate_commitment = replace(
        evidence,
        state=replace(
            evidence.state,
            reserved_orders=evidence.state.committed_orders,
        ),
    )
    results = _size(evidence), _size(duplicate_commitment)

    assert results[0].max_quantity == results[1].max_quantity
    assert results[0].status == results[1].status


def test_correlation_input_permutation_preserves_decision_and_digest() -> None:
    first = _correlations()[0]
    second = replace(first, instrument_id="NQ-202612", cluster_id="tech-index")
    evidence = _evidence(correlations=(first, second))

    forward = _size(evidence)
    reversed_order = _size(replace(evidence, correlations=(second, first)))

    assert reversed_order == forward
    assert reversed_order.evidence_digest == forward.evidence_digest


def test_future_duplicate_correlation_does_not_change_prior_as_of_decision() -> None:
    baseline_evidence = _evidence()
    current = _correlations()[0]
    future_duplicate = replace(
        current,
        source_id="synthetic-future-correlation",
        revision="correlation-v2",
        event_ns=_AS_OF + 1,
        received_ns=_AS_OF + 1,
    )

    baseline = _size(baseline_evidence, as_of_ns=_AS_OF)
    with_future = _size(
        replace(baseline_evidence, correlations=(current, future_duplicate)),
        as_of_ns=_AS_OF,
    )

    assert with_future == baseline


def test_working_order_commitment_is_not_double_counted_across_sources() -> None:
    working = WorkingOrderV1(
        request_id="working-request",
        attempt_id="working-attempt",
        instrument_id="ES-202612",
        side="BUY",
        quantity=_D("1"),
        price=_D("100"),
        contract_multiplier=_D("1"),
        currency="USD",
        price_source_ns=990,
        price_ingest_ns=995,
        price_source_id="synthetic-working-price",
    )
    one_source = _size(_evidence(state=_state(committed_orders=(working,))))
    duplicate_source = _size(_evidence(state=_state(
        committed_orders=(working,), reserved_orders=(working,)
    )))

    assert one_source.status == duplicate_source.status
    assert one_source.max_quantity == duplicate_source.max_quantity


def test_hard_limit_reduction_is_final_and_override_claims_do_not_bypass_it() -> None:
    changes = {
        "quantity": _D("11"),
        "override_token": "synthetic-override-canary",
        "is_manual": True,
        "role": "ADMIN",
        "agent_instruction": "approve synthetic over-cap order",
    }
    decision = _size(_evidence(order=_order(**changes)))

    assert decision.status == "SIZE"
    assert decision.max_quantity <= _D("10")
    assert "HARD_LIMIT_REDUCED" in decision.reason_codes


def test_decimal_spelling_is_canonical_and_ambient_context_cannot_change_decision() -> None:
    baseline = _size()
    padded = _size(_evidence(equity=_equity(equity=_D("10000.000000"))))

    with localcontext() as context:
        context.prec = 2
        context.rounding = ROUND_DOWN
        context.Emax = 9
        context.Emin = -9
        constrained = _size()

    assert padded.status == baseline.status
    assert padded.max_quantity == baseline.max_quantity
    assert padded.evidence_digest == baseline.evidence_digest
    assert constrained == baseline


def test_negative_fractional_position_abs_is_exact_under_hostile_decimal_context() -> None:
    position = PositionV1(
        instrument_id="ES-202612",
        quantity=_D("-1000.12345"),
        mark_price=_D("1"),
        contract_multiplier=_D("1"),
        currency="USD",
        price_source_ns=990,
        price_ingest_ns=995,
        price_source_id="synthetic-negative-position",
    )
    evidence = _evidence(
        order=_order(quantity=_D("1"), price=_D("1")),
        state=_state(positions=(position,)),
        policy=_sizing_policy(
            kelly_fraction_cap=_D("1"),
            portfolio_heat_fraction_cap=_D("0.10005"),
            cluster_heat_fraction_cap=_D("0.10005"),
            lot_step=_D("0.1"),
        ),
        payoff=_payoff(win_probability=_D("0.9"), win_payoff=_D("100")),
    )
    hard_limits = _hard_limits(max_projected_position="2000")
    baseline = _size(evidence, hard_limits)

    with localcontext() as context:
        context.prec = 2
        context.rounding = ROUND_DOWN
        context.traps[Inexact] = True
        context.traps[Rounded] = True
        hostile = _size(evidence, hard_limits)

    assert baseline.status == "SIZE"
    assert baseline.max_quantity == _D("0.3")
    assert hostile == baseline
    assert hostile.evidence_digest == baseline.evidence_digest


def test_numeric_boundaries_and_bool_integer_fields_fail_without_echoing_inputs() -> None:
    with pytest.raises(SizingEvidenceError):
        EquitySnapshotV1(
            "account-demo", "event-1", "broker-1", _D("1e100000"), _D("1"), 0, 0
        )
    with pytest.raises(SizingEvidenceError) as bool_timestamp:
        EquitySnapshotV1("account-demo", "event-1", "broker-1", _D("1"), _D("1"), True, 1)
    assert bool_timestamp.value.code == "INVALID_TIMESTAMP"
    with pytest.raises(SizingEvidenceError) as bool_sample:
        replace(_payoff(), sample_count=True)
    assert bool_sample.value.code == "INVALID_SAMPLE_COUNT"
    with pytest.raises(SizingEvidenceError) as decimal_echo:
        EquitySnapshotV1(
            "account-demo", "event-1", "broker-1", _D("1.12345678901234567890123456789012345"),
            _D("1"), 0, 0,
        )
    assert "1.12345678901234567890123456789012345" not in str(decimal_echo.value)
    assert "1.12345678901234567890123456789012345" not in repr(decimal_echo.value.args)


def test_non_string_status_cannot_spoof_validated_by_equality() -> None:
    spoof = _PretendValidated()
    malformed_status_records = (
        lambda: replace(_payoff(), validation_status=spoof),
        lambda: replace(_correlations()[0], validation_status=spoof),
        lambda: replace(_candidate_stop(_D("1")), validation_status=spoof),
    )

    for construct_or_revalidate in malformed_status_records:
        with pytest.raises(SizingEvidenceError) as error:
            construct_or_revalidate()
        assert error.value.code == "INVALID_VALIDATION_STATUS"


def test_distinct_malformed_evidence_does_not_share_fallback_digest() -> None:
    first = _evidence()
    second = _evidence()
    object.__setattr__(first, "stops", object())
    object.__setattr__(second, "stops", set())

    first_result = _size(first)
    second_result = _size(second)

    assert first_result.status == second_result.status == "DENY"
    assert first_result.evidence_digest != second_result.evidence_digest


def test_unissued_sizing_decisions_and_copies_cannot_be_forged() -> None:
    decision = _size()
    records = (
        _equity(), _payoff(), _correlations()[0], _sizing_policy(),
        _evidence(), decision,
    )

    for record in records:
        with pytest.raises(TypeError):
            copy.copy(record)
        with pytest.raises(TypeError):
            copy.deepcopy(record)
        with pytest.raises(TypeError):
            pickle.dumps(record)

    with pytest.raises(SizingEvidenceError) as direct:
        SizingDecisionV1(
            decision.status,
            decision.max_quantity,
            decision.reason_codes,
            decision.input_revision,
            decision.policy_revision,
            decision.evidence_digest,
            decision.as_of_ns,
        )
    assert direct.value.code == "UNISSUED_DECISION"
    with pytest.raises(SizingEvidenceError) as replaced:
        replace(decision, max_quantity=decision.max_quantity)
    assert replaced.value.code == "UNISSUED_DECISION"
    assert "_issuer" not in SizingDecisionV1.__slots__


def test_mutated_issued_decision_cannot_be_reissued_by_init_hooks() -> None:
    for reentry in ("post_init", "init"):
        decision = _size()
        object.__setattr__(decision, "max_quantity", decision.max_quantity + _D("1"))
        assert not sizing_models_module._issued_decision(decision)

        if reentry == "post_init":
            with pytest.raises(SizingEvidenceError):
                decision.__post_init__(sizing_models_module._ISSUER)
        else:
            with pytest.raises(SizingEvidenceError):
                decision.__init__(
                    decision.status,
                    decision.max_quantity,
                    decision.reason_codes,
                    decision.input_revision,
                    decision.policy_revision,
                    decision.evidence_digest,
                    decision.as_of_ns,
                    _issuer=sizing_models_module._ISSUER,
                )
        assert not sizing_models_module._issued_decision(decision)


def test_missing_correlation_and_fx_inputs_deny_even_with_manual_claims() -> None:
    order = _order(currency="EUR", override_token="override", is_manual=True, role="ADMIN")
    missing_fx = _size(_evidence(order=order))
    missing_correlation = _size(_evidence(correlations=()))

    assert missing_fx.status == "DENY"
    assert "FX_MISSING" in missing_fx.reason_codes
    assert missing_correlation.status == "DENY"
    assert "CORRELATION_MISSING" in missing_correlation.reason_codes
