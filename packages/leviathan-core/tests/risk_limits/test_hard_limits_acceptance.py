"""Independent fail-closed acceptance tests for the RISK-002 policy kernel."""

from __future__ import annotations

import copy
import json
import pickle
from dataclasses import replace
from decimal import ROUND_DOWN, Decimal, localcontext
from pathlib import Path
from typing import Any

import pytest

from leviathan_core.risk_limits import (
    DatedInstrumentV1,
    FxRateV1,
    HardLimitsV1,
    LimitAssessmentV1,
    PolicyVerificationV1,
    PositionV1,
    ProjectedOrderV1,
    RiskStateV1,
    RollingRateCountV1,
    VerifiedHardLimitsV1,
    WorkingOrderV1,
    assess_limits,
    verify_hard_limits,
)

_FIXTURE = Path(__file__).parents[1] / "fixtures" / "risk_limits" / "base_policy.json"
_AS_OF = 1_000
_D = Decimal


class _TestOnlyVerifier:
    def verify(
        self, policies: tuple[HardLimitsV1, ...], policy_digest: str
    ) -> PolicyVerificationV1:
        assert policies
        return PolicyVerificationV1(
            verifier_id="test-only-verifier",
            key_id="synthetic-test-key",
            policy_digest=policy_digest,
        )


def _account_policy(**changes: Any) -> HardLimitsV1:
    raw = json.loads(_FIXTURE.read_text(encoding="utf-8-sig"))
    raw["allowed_instruments"] = tuple(
        DatedInstrumentV1(**item) for item in raw["allowed_instruments"]
    )
    raw["allowed_strategies"] = tuple(raw["allowed_strategies"])
    raw["allowed_venues"] = tuple(raw["allowed_venues"])
    raw.update(changes)
    return HardLimitsV1(**raw)


def _verified(*policies: HardLimitsV1):
    return verify_hard_limits(tuple(policies), _TestOnlyVerifier())


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
        rolling_rate_counts=(
            RollingRateCountV1(window_ns=60_000_000_000, count=0, as_of_ns=1_000),
        ),
    )
    fields.update(changes)
    return RiskStateV1(**fields)


def _order(**changes: Any) -> ProjectedOrderV1:
    fields: dict[str, Any] = dict(
        environment="paper",
        account_id="account-demo-001",
        request_id="request-001",
        attempt_id="attempt-001",
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


def _assessment(
    order: ProjectedOrderV1 | None = None,
    policy: Any = None,
    state: RiskStateV1 | None = None,
    as_of_ns: int = _AS_OF,
) -> LimitAssessmentV1:
    return assess_limits(
        order if order is not None else _order(),
        policy if policy is not None else _verified(_account_policy()),
        state if state is not None else _state(),
        as_of_ns,
    )


def _assert_denied_or_rejected(call: Any) -> None:
    try:
        result = call()
    except (TypeError, ValueError):
        return
    assert result.decision == "DENY"
    assert result.reason_codes


def test_valid_verified_policy_allows_bounded_order() -> None:
    result = _assessment()

    assert result.decision == "ALLOW"
    assert result.state_event_id == "event-state-001"
    assert result.evidence_digest


@pytest.mark.parametrize(
    "missing_field",
    [
        "max_order_quantity",
        "max_order_notional",
        "max_projected_position",
        "max_gross_exposure",
        "max_net_exposure",
        "max_leverage",
        "max_daily_loss",
        "max_order_rate",
        "order_rate_window_ns",
    ],
)
def test_missing_cap_dimension_fails_closed(missing_field: str) -> None:
    _assert_denied_or_rejected(
        lambda: _assessment(policy=_verified(_account_policy(**{missing_field: None})))
    )


@pytest.mark.parametrize(
    ("policy", "order", "state"),
    [
        (None, _order(), _state()),
        (_verified(_account_policy()), None, _state()),
        (_verified(_account_policy()), _order(), None),
    ],
)
def test_missing_policy_order_or_state_fails_closed(policy: Any, order: Any, state: Any) -> None:
    _assert_denied_or_rejected(lambda: assess_limits(order, policy, state, _AS_OF))


def test_unverified_or_plain_policy_envelope_cannot_be_used() -> None:
    policy = _account_policy()
    order = _order()
    state = _state()

    _assert_denied_or_rejected(lambda: assess_limits(order, (policy,), state, _AS_OF))
    _assert_denied_or_rejected(lambda: assess_limits(order, policy, state, _AS_OF))
    with pytest.raises(TypeError):
        VerifiedHardLimitsV1()


def test_equal_cap_passes_and_one_unit_above_denies() -> None:
    policy = _account_policy(max_order_quantity="2", max_order_notional="200")
    verified = _verified(policy)

    equal = _assessment(order=_order(quantity=_D("2")), policy=verified)
    over = _assessment(order=_order(quantity=_D("3")), policy=verified)

    assert equal.decision == "ALLOW"
    assert over.decision == "DENY"
    assert over.reason_codes


def test_scope_intersection_uses_smallest_applicable_limit() -> None:
    account = _account_policy(max_order_quantity="10")
    strategy = _account_policy(
        revision="strategy-narrow-v1",
        scope="STRATEGY",
        strategy_id="strategy-demo",
        max_order_quantity="8",
    )
    venue = _account_policy(
        revision="venue-narrow-v1",
        scope="VENUE",
        venue_id="venue-demo",
        max_order_quantity="6",
    )
    instrument = _account_policy(
        revision="instrument-narrow-v1",
        scope="INSTRUMENT",
        instrument_id="ES-202612",
        max_order_quantity="4",
    )
    verified = _verified(account, strategy, venue, instrument)

    at_narrowest = _assessment(order=_order(quantity=_D("4")), policy=verified)
    above_narrowest = _assessment(order=_order(quantity=_D("5")), policy=verified)

    assert at_narrowest.decision == "ALLOW"
    assert above_narrowest.decision == "DENY"
    assert set(at_narrowest.matched_policy_revisions) == {
        "risk-policy-v1", "strategy-narrow-v1", "venue-narrow-v1", "instrument-narrow-v1"
    }


def test_specific_instrument_rule_cannot_loosen_account_cap() -> None:
    account = _account_policy(max_order_quantity="2")
    symbol = _account_policy(
        revision="symbol-loosen-attempt",
        scope="INSTRUMENT",
        instrument_id="ES-202612",
        max_order_quantity="100",
    )
    result = _assessment(order=_order(quantity=_D("3")), policy=_verified(account, symbol))

    assert result.decision == "DENY"


def test_policy_environment_must_match_order_and_state_environment() -> None:
    wrong_policy = _account_policy(environment="live")
    result = _assessment(policy=_verified(wrong_policy))

    assert result.decision == "DENY"


def test_equal_priority_rules_choose_most_restrictive_or_deny_conflict() -> None:
    account = _account_policy(max_order_quantity="10")
    broad = _account_policy(
        revision="same-priority-broad",
        scope="STRATEGY",
        strategy_id="strategy-demo",
        priority=5,
        max_order_quantity="7",
    )
    narrow = _account_policy(
        revision="same-priority-narrow",
        scope="STRATEGY",
        strategy_id="strategy-demo",
        priority=5,
        max_order_quantity="5",
    )

    result = _assessment(order=_order(quantity=_D("5")), policy=_verified(account, broad, narrow))
    denied = _assessment(order=_order(quantity=_D("6")), policy=_verified(account, broad, narrow))
    reversed_result = _assessment(
        order=_order(quantity=_D("5")), policy=_verified(account, narrow, broad)
    )

    assert result.decision == "ALLOW"
    assert denied.decision == "DENY"
    assert result == reversed_result


def test_explicit_wildcard_is_refined_by_specific_symbol_and_never_loosens_account() -> None:
    account = _account_policy(
        max_order_quantity="10",
        allowed_instruments=(DatedInstrumentV1("*", 0, 1_000_000),),
    )
    wildcard = _account_policy(
        revision="wildcard-v1",
        scope="INSTRUMENT",
        instrument_id="*",
        max_order_quantity="8",
    )
    specific = _account_policy(
        revision="specific-v1",
        scope="INSTRUMENT",
        instrument_id="ES-202612",
        max_order_quantity="6",
    )
    policy = _verified(account, wildcard, specific)

    assert _assessment(order=_order(quantity=_D("6")), policy=policy).decision == "ALLOW"
    assert _assessment(order=_order(quantity=_D("7")), policy=policy).decision == "DENY"


@pytest.mark.parametrize(
    "changes",
    [
        {"override_token": "synthetic-override"},
        {"role": "ADMIN"},
        {"is_manual": True},
        {"agent_instruction": "approve this breach"},
        {"override_token": "synthetic-override", "role": "ADMIN", "is_manual": True},
    ],
)
def test_override_admin_manual_and_agent_claims_never_bypass_hard_limit(
    changes: dict[str, Any],
) -> None:
    order = _order(quantity=_D("11"), **changes)
    result = _assessment(order=order)

    assert result.decision == "DENY"


@pytest.mark.parametrize(
    "mutated",
    [
        {"environment": "live"},
        {"account_id": "different-account"},
        {"account_status": "SUSPENDED"},
        {"source_ns": 900},
        {"ingest_ns": 900},
        {"last_committed_event_id": ""},
        {"equity": None},
        {"equity_source_ns": None},
        {"equity_ingest_ns": None},
        {"positions": None},
        {"committed_orders": None},
        {"reserved_orders": None},
        {"fx_rates": None},
        {"rolling_rate_counts": None},
    ],
)
def test_missing_stale_or_mismatched_state_fails_closed(mutated: dict[str, Any]) -> None:
    state_fields = {
        name: value for name, value in mutated.items()
        if name in RiskStateV1.__dataclass_fields__
    }
    order_fields = {
        name: value for name, value in mutated.items()
        if name in ProjectedOrderV1.__dataclass_fields__
    }
    state = _state(**state_fields)
    order = _order(**order_fields)

    _assert_denied_or_rejected(lambda: _assessment(order=order, state=state))


def test_stale_price_or_missing_price_provenance_fails_closed() -> None:
    stale = _order(price_source_ns=900, price_ingest_ns=995)
    missing_source = _order(price_source_id="")

    _assert_denied_or_rejected(lambda: _assessment(order=stale))
    _assert_denied_or_rejected(lambda: _assessment(order=missing_source))


def test_position_price_and_fx_state_provenance_must_be_current() -> None:
    position = PositionV1(
        instrument_id="ES-202612",
        quantity=_D("1"),
        mark_price=_D("100"),
        contract_multiplier=_D("1"),
        currency="USD",
        price_source_ns=900,
        price_ingest_ns=995,
        price_source_id="stale-position-mark",
    )
    stale_position = _state(positions=(position,))

    _assert_denied_or_rejected(lambda: _assessment(state=stale_position))


def test_foreign_currency_requires_current_fx_evidence() -> None:
    eur_order = _order(currency="EUR")
    missing = _assessment(order=eur_order)

    fresh_fx = FxRateV1(
        currency="EUR",
        base_currency="USD",
        base_units_per_unit=_D("1.1"),
        source_ns=990,
        ingest_ns=995,
        source_id="synthetic-fx-001",
    )
    valid_state = _state(fx_rates=(fresh_fx,))
    converted = _assessment(order=eur_order, state=valid_state)
    stale_fx = replace(fresh_fx, source_ns=900, ingest_ns=900)
    stale = _assessment(order=eur_order, state=_state(fx_rates=(stale_fx,)))

    assert missing.decision == "DENY"
    assert converted.decision == "ALLOW"
    assert stale.decision == "DENY"


def test_duplicate_committed_and_reserved_order_is_counted_once() -> None:
    existing = WorkingOrderV1(
        request_id="existing-request",
        attempt_id="existing-attempt",
        instrument_id="ES-202612",
        side="BUY",
        quantity=_D("3"),
        price=_D("100"),
        contract_multiplier=_D("1"),
        currency="USD",
        price_source_ns=990,
        price_ingest_ns=995,
        price_source_id="synthetic-working-price",
    )
    policy = _account_policy(max_projected_position="5")
    state = _state(committed_orders=(existing,), reserved_orders=(existing,))
    result = _assessment(
        order=_order(quantity=_D("2")),
        policy=_verified(policy),
        state=state,
    )

    assert result.decision == "ALLOW"


def test_account_strategy_venue_and_dated_instrument_allowlists_are_required() -> None:
    for field in ("allowed_strategies", "allowed_venues", "allowed_instruments"):
        _assert_denied_or_rejected(
            lambda field=field: _assessment(
                policy=_verified(_account_policy(**{field: None}))
            )
        )

    wrong_strategy = _assessment(order=_order(strategy_id="not-allowed"))
    wrong_venue = _assessment(order=_order(venue_id="not-allowed"))
    wrong_dated_instrument = _assessment(order=_order(instrument_id="NQ-202612"))

    assert wrong_strategy.decision == "DENY"
    assert wrong_venue.decision == "DENY"
    assert wrong_dated_instrument.decision == "DENY"


def test_rate_window_is_enforced_from_committed_state() -> None:
    policy = _account_policy(max_order_rate=2, order_rate_window_ns=100)
    state = _state(
        rolling_rate_counts=(RollingRateCountV1(window_ns=100, count=1, as_of_ns=1_000),)
    )

    assert _assessment(policy=_verified(policy), state=state).decision == "ALLOW"
    over = _state(
        rolling_rate_counts=(RollingRateCountV1(window_ns=100, count=2, as_of_ns=1_000),)
    )
    result = _assessment(policy=_verified(policy), state=over)

    assert result.decision == "DENY"


def test_rate_counter_must_cover_the_assessment_instant_even_with_age_budget() -> None:
    policy = _account_policy(max_order_rate=10, order_rate_window_ns=100, max_data_age_ns=300)
    stale_count = RollingRateCountV1(window_ns=100, count=0, as_of_ns=900)
    result = _assessment(policy=_verified(policy), state=_state(rolling_rate_counts=(stale_count,)))

    assert result.decision == "DENY"
    assert "rate_counter_stale" in result.reason_codes


def test_data_age_policy_boundary_and_stale_price_or_equity_fail_closed() -> None:
    maximum_age_ns = 300_000_000_000
    accepted = _account_policy(max_data_age_ns=maximum_age_ns)
    assert accepted.max_data_age_ns == maximum_age_ns
    with pytest.raises(ValueError) as error:
        _account_policy(max_data_age_ns=maximum_age_ns + 1)
    assert getattr(error.value, "code", None) == "POLICY_OUT_OF_BOUNDS"

    as_of_ns = 301_000_000_001
    stale_source_ns = as_of_ns - (maximum_age_ns + 1)
    policy = _account_policy(
        effective_until_ns=as_of_ns + 1,
        max_data_age_ns=maximum_age_ns,
        allowed_instruments=(DatedInstrumentV1("ES-202612", 0, as_of_ns + 1),),
    )
    boundary_source_ns = as_of_ns - maximum_age_ns
    boundary_order = _order(
        price_source_ns=boundary_source_ns,
        price_ingest_ns=as_of_ns,
    )
    boundary_state = _state(
        source_ns=as_of_ns,
        ingest_ns=as_of_ns,
        equity_source_ns=boundary_source_ns,
        equity_ingest_ns=as_of_ns,
        rolling_rate_counts=(
            RollingRateCountV1(window_ns=60_000_000_000, count=0, as_of_ns=as_of_ns),
        ),
    )
    exact_age_result = _assessment(
        order=boundary_order,
        policy=_verified(policy),
        state=boundary_state,
        as_of_ns=as_of_ns,
    )
    assert exact_age_result.decision == "ALLOW"

    stale_price = replace(boundary_order, price_source_ns=stale_source_ns)
    stale_equity = replace(boundary_state, equity_source_ns=stale_source_ns)

    assert _assessment(
        order=stale_price, policy=_verified(policy), state=boundary_state, as_of_ns=as_of_ns
    ).decision == "DENY"
    assert _assessment(
        order=boundary_order, policy=_verified(policy), state=stale_equity, as_of_ns=as_of_ns
    ).decision == "DENY"


def test_exact_gross_to_equity_comparison_allows_one_over_three_with_unit_leverage_cap() -> None:
    policy = _account_policy(
        max_order_quantity="1",
        max_order_notional="1",
        max_projected_position="1",
        max_gross_exposure="1",
        max_leverage="1",
    )
    order = _order(quantity=_D("1"), price=_D("1"))
    state = _state(equity=_D("3"), buying_power=_D("3"))

    result = _assessment(order=order, policy=_verified(policy), state=state)

    assert result.decision == "ALLOW"
    assert result.reason_codes == ("within_hard_limits",)


def test_hard_limit_replace_rejects_missing_cap_invalid_selector_and_date() -> None:
    policy = _account_policy()

    with pytest.raises(ValueError) as missing_cap:
        replace(policy, max_order_quantity=None)
    assert getattr(missing_cap.value, "code", None)

    with pytest.raises(ValueError) as bad_selector:
        replace(policy, scope="STRATEGY")
    assert getattr(bad_selector.value, "code", None) == "POLICY_SELECTOR_INVALID"

    with pytest.raises(ValueError) as bad_interval:
        replace(policy, effective_until_ns=policy.effective_from_ns)
    assert getattr(bad_interval.value, "code", None) == "POLICY_INTERVAL_INVALID"

    with pytest.raises(ValueError):
        verify_hard_limits((None,), _TestOnlyVerifier())


def test_daily_loss_uses_realized_and_unrealized_pnl_and_fails_closed() -> None:
    policy = _account_policy(max_daily_loss="500")
    at_boundary = _state(realized_pnl=_D("-300"), unrealized_pnl=_D("-200"))
    over_boundary = _state(realized_pnl=_D("-300"), unrealized_pnl=_D("-201"))

    assert _assessment(policy=_verified(policy), state=at_boundary).decision == "ALLOW"
    assert _assessment(policy=_verified(policy), state=over_boundary).decision == "DENY"


@pytest.mark.parametrize(
    ("quantity", "price", "multiplier"),
    [(2.0, _D("100"), _D("1")), (_D("2"), 100.0, _D("1")), (_D("2"), _D("100"), 1.0)],
)
def test_binary_float_values_are_never_accepted(
    quantity: Any, price: Any, multiplier: Any
) -> None:
    _assert_denied_or_rejected(
        lambda: _assessment(
            order=_order(quantity=quantity, price=price, contract_multiplier=multiplier)
        )
    )


def test_binary_float_policy_threshold_and_state_values_are_never_accepted() -> None:
    _assert_denied_or_rejected(
        lambda: _assessment(
            policy=_verified(_account_policy(max_order_quantity=10.0))
        )
    )

    _assert_denied_or_rejected(lambda: _assessment(state=_state(equity=10_000.0)))


def test_public_risk_records_reject_copy_deepcopy_and_pickle() -> None:
    policy = _account_policy()
    instrument = policy.allowed_instruments[0]
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
    working_order = WorkingOrderV1(
        request_id="working-copy",
        attempt_id="attempt-copy",
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
    fx_rate = FxRateV1(
        currency="EUR",
        base_currency="USD",
        base_units_per_unit=_D("1.1"),
        source_ns=990,
        ingest_ns=995,
        source_id="synthetic-fx",
    )
    rate_count = RollingRateCountV1(window_ns=60_000, count=1, as_of_ns=1_000)
    state = _state(
        positions=(position,),
        committed_orders=(working_order,),
        fx_rates=(fx_rate,),
        rolling_rate_counts=(rate_count,),
    )
    order = _order()
    verification = PolicyVerificationV1(
        verifier_id="test-verifier", key_id="test-key", policy_digest="a" * 64
    )
    records = (
        instrument,
        policy,
        position,
        working_order,
        fx_rate,
        rate_count,
        state,
        order,
        verification,
        _verified(policy),
        _assessment(order=order, policy=_verified(policy), state=state),
    )

    for record in records:
        with pytest.raises(TypeError):
            copy.copy(record)
        with pytest.raises(TypeError):
            copy.deepcopy(record)
        with pytest.raises(TypeError):
            pickle.dumps(record)


def test_risk_replace_revalidates_types_decimal_boolean_and_collections() -> None:
    state = _state()
    order = _order()
    policy = _account_policy()

    with pytest.raises((TypeError, ValueError)):
        replace(order, quantity=1.0)
    with pytest.raises((TypeError, ValueError)):
        replace(order, quantity=_D("1e39"))
    with pytest.raises((TypeError, ValueError)):
        replace(order, is_manual="false")
    with pytest.raises((TypeError, ValueError)):
        replace(state, positions=[])
    with pytest.raises((TypeError, ValueError)):
        replace(policy, allowed_strategies=["strategy-demo"])
    with pytest.raises((TypeError, ValueError)):
        replace(order, account_id="account-é")


@pytest.mark.parametrize(
    ("quantity", "expected_code"),
    [
        (_D("1e39"), "DECIMAL_OUT_OF_BOUNDS"),
        (_D("0." + "1" * 35), "PRECISION_EXCEEDED"),
    ],
)
def test_out_of_bounds_decimal_order_is_rejected_before_arithmetic(
    quantity: Decimal, expected_code: str
) -> None:
    with pytest.raises(ValueError) as error:
        _order(quantity=quantity)

    assert getattr(error.value, "code", None) == expected_code
    assert str(quantity) not in str(error.value)


def test_precision_34_decimal_boundary_is_accepted() -> None:
    order = _order(quantity=_D("0." + "1" * 34))

    assert order.quantity == _D("0." + "1" * 34)


def test_numerically_equal_decimal_orders_have_same_digest_and_assessment() -> None:
    integer_spelling = _assessment(order=_order(quantity=_D("2")))
    fractional_spelling = _assessment(order=_order(quantity=_D("2.0")))

    assert integer_spelling == fractional_spelling
    assert integer_spelling.evidence_digest == fractional_spelling.evidence_digest


def test_assessment_is_independent_of_ambient_decimal_context() -> None:
    baseline = _assessment()

    with localcontext() as context:
        context.prec = 2
        context.rounding = ROUND_DOWN
        context.Emax = 9
        context.Emin = -9
        altered = _assessment()

    assert altered == baseline


def test_precision_34_inexact_daily_loss_arithmetic_fails_closed() -> None:
    state = _state(realized_pnl=_D("-1"), unrealized_pnl=_D("1e-35"))

    result = _assessment(state=state)

    assert result.decision == "DENY"
    assert result.reason_codes


def test_exact_decimal_precision_is_preserved_without_binary_float() -> None:
    result = _assessment(
        order=_order(quantity=_D("0.1"), price=_D("100.0000000001"), contract_multiplier=_D("1"))
    )

    assert result.decision == "ALLOW"
    assert result.projected_values
    assert all(isinstance(value, str) for _, value in result.projected_values)


def test_assessment_is_permutation_invariant_for_policies_and_state_records() -> None:
    account = _account_policy(max_order_quantity="10")
    strategy = _account_policy(
        revision="strategy-permutation-v1",
        scope="STRATEGY",
        strategy_id="strategy-demo",
        max_order_quantity="8",
    )
    first_order = WorkingOrderV1(
        request_id="working-a", attempt_id="attempt-a", instrument_id="ES-202612",
        side="BUY", quantity=_D("1"), price=_D("100"), contract_multiplier=_D("1"),
        currency="USD", price_source_ns=990, price_ingest_ns=995, price_source_id="w-a",
    )
    second_order = replace(first_order, request_id="working-b", attempt_id="attempt-b")
    state_a = _state(committed_orders=(first_order, second_order))
    state_b = _state(committed_orders=(second_order, first_order))

    first = _assessment(policy=_verified(account, strategy), state=state_a)
    permuted = _assessment(policy=_verified(strategy, account), state=state_b)

    assert first == permuted

