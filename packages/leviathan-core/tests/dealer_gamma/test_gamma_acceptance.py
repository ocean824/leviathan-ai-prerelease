from __future__ import annotations

import copy
import json
import pickle
import random
from dataclasses import fields, is_dataclass, replace
from datetime import date
from decimal import Decimal, localcontext
from pathlib import Path

import pytest

from leviathan_core.dealer_gamma import (
    ChainSnapshotV1,
    DealerExposureAssumptionV1,
    DeliverableLegV1,
    ExchangeCalendarV1,
    GammaPolicyV1,
    GammaSnapshotV1,
    IntegerFieldError,
    OptionSeriesEvidenceV1,
    PolicyOutOfBoundsError,
    PrecisionExceededError,
    evaluate,
)

FIXTURES = Path(__file__).parent / "fixtures" / "kernel"


def _series(*, series_id="call-1", multiplier="100", oi="100", spot="100",
            gamma="0.02", expiry="2026-10-16", expiry_kind="WEEKLY", cutoff=2000,
            entitlement="ENTITLED", iv_available=1000, spot_available=1000,
            option_type="CALL", strike="100", split="1", halted=False,
            multiplier_basis="PRE_ACTION", adjustment_version="split-v1",
            deliverable_units=None, currency="USD"):
    multiplier_value = Decimal(multiplier)
    split_value = Decimal(split)
    if deliverable_units is None:
        deliverable_units = (
            DeliverableLegV1(
                kind="UNDERLIER", asset_id="XYZ",
                units=multiplier_value * split_value, currency="USD",
            ),
        )
    return OptionSeriesEvidenceV1(
        series_id=series_id, underlier="XYZ", contract=f"XYZ-{series_id}", venue="OPRA",
        option_type=option_type, strike=Decimal(strike), expiry_date=date.fromisoformat(expiry),
        expiry_kind=expiry_kind, settlement="PM", expiry_cutoff_ns=cutoff,
        multiplier=Decimal(multiplier), currency=currency, open_interest=Decimal(oi),
        oi_asof_ns=1000, spot=Decimal(spot), spot_observed_ns=1000,
        spot_available_ns=spot_available, bid=Decimal("2"), ask=Decimal("2.2"),
        quote_observed_ns=1000, quote_available_ns=1000, implied_vol=Decimal("0.25"),
        iv_observed_ns=1000, iv_available_ns=iv_available, gamma=Decimal(gamma),
        gamma_units="PER_UNDERLYING_UNIT", greek_observed_ns=1000, greek_available_ns=1000,
        source_id="chain-fixture", dataset_id="chain-v1",
        entitlement_id="test-entitlement", entitlement_status=entitlement,
        corporate_action_version="split-v1", split_factor=split_value, halted=halted,
        multiplier_basis=multiplier_basis, adjustment_version=adjustment_version,
        deliverable_units=tuple(deliverable_units) if deliverable_units is not None else None,
    )


def _snapshot(series, *, denominator="100", asof=1000, snapshot_id="live-1",
            trade_date=date(2026, 10, 16), session_close=5000):
    calendar = ExchangeCalendarV1(
        "XNYS", "cal-v1", trade_date, 0, session_close,
    )
    chain = ChainSnapshotV1(
        snapshot_id=snapshot_id, data_state="LIVE", underlier="XYZ", venue="OPRA",
        observed_ns=1000, available_ns=1000, revision=1, source_id="chain-fixture",
        dataset_id="chain-v1", calendar=calendar,
        eligible_expiries=tuple(sorted({s.expiry_date for s in series})),
        eligible_oi_denominator=Decimal(denominator), chain_complete=True,
        expected_series_count=len(series), series=tuple(series),
    )
    return GammaSnapshotV1(live=chain)


def _policy(*, call_sign=-1, put_sign=1, expiries=(date(2026, 10, 16),)):
    assumption = DealerExposureAssumptionV1(
        "scenario-v1", "v1", "explicit synthetic dealer position scenario",
        call_sign, put_sign,
    )
    return GammaPolicyV1(
        "gamma-policy", "v1", "calc-v1", "expiry-v1", expiries, assumption,
        (Decimal("80"), Decimal("100"), Decimal("120")), Decimal("0.01"),
    )


def test_known_series_exposure_reverses_with_dealer_sign_and_scales_by_multiplier():
    values = json.loads((FIXTURES / "known_series.json").read_text(encoding="utf-8-sig"))
    series = _series(multiplier=values["multiplier"], oi=values["open_interest"],
                     spot=values["spot"], gamma=values["gamma"])
    short_call = evaluate(_snapshot((series,)), _policy(call_sign=values["dealer_short_call"]),
                          values["asof_ns"]).live
    long_call = evaluate(_snapshot((series,)), _policy(call_sign=values["dealer_long_call"]),
                         values["asof_ns"]).live
    doubled = _series(multiplier="200")
    scaled = evaluate(_snapshot((doubled,)), _policy(), values["asof_ns"]).live
    assert short_call.aggregate_gamma == Decimal("-20000")
    assert long_call.aggregate_gamma == Decimal("20000")
    assert long_call.aggregate_gamma != 0
    assert scaled.aggregate_gamma == short_call.aggregate_gamma * Decimal("2")
    assert scaled.aggregate_gamma == Decimal("-40000")
    assert short_call.sign_label
    assert short_call.assumption_id == "scenario-v1"
    assert short_call.gamma_sign_regime_label == "MODEL_ESTIMATE"
    assert short_call.regime_label == "MODEL_ESTIMATE"


def test_unsigned_oi_is_only_a_named_scenario_and_pin_probability_is_never_fabricated():
    result = evaluate(_snapshot((_series(),)), _policy(), 1000)
    assert result.live.sign_label
    assert result.live.assumption_id == "scenario-v1"
    assert result.live.pin_probability is None
    assert all(m.label == "MODEL_ESTIMATE" for m in result.live.magnet_levels)
    assert result.live.regime in {"NEUTRAL", "POSITIVE_GAMMA", "NEGATIVE_GAMMA"}


def test_missing_entitlement_and_stale_spot_or_iv_do_not_produce_usable_levels():
    denied = evaluate(_snapshot((_series(entitlement="DENIED"),)), _policy(), 1000).live
    stale_spot = evaluate(_snapshot((_series(),)), _policy(), 3_000_000_001).live
    stale_iv = evaluate(_snapshot((_series(),)), _policy(), 11_000_000_001).live
    for result in (denied, stale_spot, stale_iv):
        assert result.status in {"UNAVAILABLE", "STALE", "DEGRADED"}
        assert result.flip is None
        assert result.call_wall is None or result.status == "DEGRADED"
        assert result.reasons


def test_null_flip_uses_database_neutral_canonical_rule_and_exact_zero_is_neutral():
    result = evaluate(_snapshot((_series(),)), _policy(expiries=(date(2026, 10, 16),)), 1000).live
    assert result.flip is None
    assert result.flip_reason == "FLIP_NOT_FOUND_IN_GRID"
    assert result.regime_reason == "FLIP_NULL_DB_RULE"
    assert result.regime == "NEUTRAL"
    assert result.regime_confidence == Decimal("0")
    assert result.gamma_sign_regime == "NEGATIVE_GAMMA"


def test_input_permutation_and_repeat_evaluation_preserve_semantic_digest():
    one = _series(series_id="a", strike="95")
    two = _series(series_id="b", option_type="PUT", strike="105", gamma="0.01")
    first = evaluate(_snapshot((one, two)), _policy(), 1000)
    permuted = evaluate(_snapshot((two, one), snapshot_id="live-1"), _policy(), 1000)
    assert first.semantic_digest == permuted.semantic_digest
    assert first.live.aggregate_gamma == permuted.live.aggregate_gamma
    assert first.live.pin_probability is None







def test_eighty_percent_oi_coverage_boundary_is_inclusive():
    passing = evaluate(_snapshot((_series(),), denominator="125"), _policy(), 1000).live
    below = evaluate(_snapshot((_series(),), denominator="126"), _policy(), 1000).live
    assert passing.coverage_ratio == Decimal("0.8")
    assert passing.status == "OK"
    assert below.coverage_ratio < Decimal("0.8")
    assert below.status == "DEGRADED"
    assert "LOW_OI_COVERAGE" in below.reasons


def test_split_mapping_adjusts_strike_and_multiplier_before_wall_calculation():
    adjusted = _series(strike="100", multiplier="50", split="2")
    plain = _series(strike="50", multiplier="100")
    post_action = _series(
        strike="100", multiplier="100", split="2",
        multiplier_basis="POST_ACTION_ADJUSTED",
        deliverable_units=(DeliverableLegV1(
            "UNDERLIER", "XYZ", Decimal("100"), "USD",
        ),),
    )
    mapped = evaluate(_snapshot((adjusted,)), _policy(), 1000).live
    post_mapped = evaluate(_snapshot((post_action,)), _policy(), 1000).live
    baseline = evaluate(_snapshot((plain,)), _policy(), 1000).live
    assert mapped.aggregate_gamma == baseline.aggregate_gamma
    assert post_mapped.aggregate_gamma == baseline.aggregate_gamma
    assert mapped.call_wall.primary.value == Decimal("50")
    assert mapped.call_wall.primary.label == "MODEL_ESTIMATE"
    assert post_mapped.call_wall.primary.value == Decimal("50")
    assert mapped.multiplier_bases == ("PRE_ACTION",)
    assert post_mapped.multiplier_bases == ("POST_ACTION_ADJUSTED",)
    assert mapped.adjustment_versions == ("split-v1",)


def test_three_for_one_pre_action_split_rounds_only_the_final_adjusted_strike():
    series = _series(strike="100", multiplier="100", split="3")
    result = evaluate(_snapshot((series,)), _policy(), 1000).live

    assert result.status == "OK"
    assert result.call_wall is not None
    assert result.call_wall.primary.value == Decimal(
        "33.33333333333333333333333333333333"
    )
    assert result.multiplier_bases == ("PRE_ACTION",)
    assert "PRECISION_EXCEEDED" not in result.reasons


def test_pre_action_split_strike_rounding_matches_exact_fraction_for_seeded_factors():
    generator = random.Random(20261005)
    split_factors = tuple(generator.randint(2, 19) for _ in range(24))

    for factor in split_factors:
        series = _series(
            series_id=f"split-{factor}", strike="100", multiplier="100", split=str(factor),
        )
        result = evaluate(_snapshot((series,)), _policy(), 1000).live
        with localcontext() as context:
            context.prec = 34
            expected = Decimal("100") / Decimal(factor)

        assert result.status == "OK", f"split factor {factor}: {result.reasons}"
        assert result.call_wall is not None
        assert result.call_wall.primary.value == expected
        assert result.multiplier_bases == ("PRE_ACTION",)


def test_deliverable_leg_kinds_cash_legs_and_nonstandard_other_asset():
    underlier = DeliverableLegV1("UNDERLIER", "XYZ", Decimal("150"), "USD")
    mixed = _series(
        series_id="mixed-cash", multiplier="150", multiplier_basis="POST_ACTION_ADJUSTED",
        deliverable_units=(underlier, DeliverableLegV1("CASH", "USD", Decimal("25"), "USD")),
    )
    underlier_only = _series(
        series_id="underlier-only", multiplier="150", multiplier_basis="POST_ACTION_ADJUSTED",
        deliverable_units=(underlier,),
    )
    cash_and_underlier = evaluate(_snapshot((mixed,)), _policy(), 1000).live
    plain = evaluate(_snapshot((underlier_only,)), _policy(), 1000).live
    assert cash_and_underlier.aggregate_gamma == plain.aggregate_gamma
    assert cash_and_underlier.coverage_ratio == plain.coverage_ratio

    other_asset = _series(
        series_id="other-asset", multiplier="100",
        deliverable_units=(
            DeliverableLegV1("UNDERLIER", "XYZ", Decimal("100"), "USD"),
            DeliverableLegV1("OTHER_ASSET", "ABC", Decimal("1"), "USD"),
        ),
    )
    excluded = evaluate(_snapshot((other_asset,)), _policy(), 1000).live
    assert any(
        item.series_id == "other-asset"
        and item.reason == "NON_STANDARD_DELIVERABLE_OTHER_ASSET"
        and item.status == "EXCLUDED"
        for item in excluded.excluded_series
    )
    assert excluded.coverage_ratio == Decimal("0")


def test_missing_multiplier_basis_or_deliverable_metadata_fails_closed():
    missing_basis = evaluate(
        _snapshot((_series(multiplier_basis=None),)), _policy(), 1000,
    ).live
    assert missing_basis.status == "UNAVAILABLE"
    assert "ADJUSTMENT_BASIS_UNKNOWN" in missing_basis.reasons
    assert missing_basis.flip is None
    missing_legs = evaluate(
        _snapshot((_series(deliverable_units=()),)), _policy(), 1000,
    ).live
    assert missing_legs.status == "UNAVAILABLE"
    assert "DELIVERABLE_UNITS_MISSING" in missing_legs.reasons
    missing_version = evaluate(
        _snapshot((_series(adjustment_version=None),)), _policy(), 1000,
    ).live
    assert missing_version.status == "UNAVAILABLE"
    assert "ADJUSTMENT_VERSION_MISSING" in missing_version.reasons


def test_nonpositive_split_factor_is_invalid_evidence_with_null_levels():
    invalid = _series(split="0")
    result = evaluate(_snapshot((invalid,)), _policy(), 1000).live
    assert result.status == "UNAVAILABLE"
    assert "INVALID_SPLIT_FACTOR" in result.reasons
    assert result.aggregate_gamma is None
    assert result.flip is None
    assert result.call_wall is None


def test_gamma_flip_returns_a_bracketed_model_estimate_when_sign_crosses():
    expiry = date(2027, 10, 16)
    cutoff = 31_536_000_000_001_000
    call = _series(
        series_id="call", strike="80", option_type="CALL",
        expiry=expiry.isoformat(), cutoff=cutoff,
    )
    put = _series(
        series_id="put", strike="120", option_type="PUT",
        expiry=expiry.isoformat(), cutoff=cutoff,
    )
    result = evaluate(
        _snapshot((call, put), denominator="200", trade_date=date(2026, 10, 15)),
        _policy(expiries=(expiry,)), 1000,
    ).live
    assert result.flip is not None
    assert result.flip.lower_bracket <= result.flip.value <= result.flip.upper_bracket
    assert result.flip.error_bound is not None
    assert result.flip.error_bound <= Decimal("0.01")
    assert result.flip.label == "MODEL_ESTIMATE"
    assert result.regime_label == "MODEL_ESTIMATE"


def test_zero_dte_magnet_weights_are_estimates_with_no_pin_probability():
    result = evaluate(_snapshot((_series(),)), _policy(), 1000).live
    assert result.has_0dte is True
    assert result.magnet_levels
    assert sum((magnet.weight for magnet in result.magnet_levels), Decimal("0")) == Decimal("1")
    assert all(magnet.label == "MODEL_ESTIMATE" for magnet in result.magnet_levels)
    assert result.pin_probability is None



def test_mixed_sign_gamma_flip_is_bracketed_and_nearby_roots_are_not_extrapolated():
    call = _series(series_id="short-call", strike="80", oi="110", cutoff=31_536_000_000_001_000)
    put = _series(series_id="long-put", option_type="PUT", strike="120", oi="100",
                  cutoff=31_536_000_000_001_000)
    result = evaluate(_snapshot((call, put), denominator="210"), _policy(), 1000).live
    assert result.flip is not None
    assert result.flip.lower_bracket < result.flip.upper_bracket
    assert result.flip.lower_bracket <= result.flip.value <= result.flip.upper_bracket
    assert result.flip.error_bound <= Decimal("0.01")
    assert result.gamma_sign_regime == "NEGATIVE_GAMMA"
    assert result.regime_label == "MODEL_ESTIMATE"


def test_wall_tie_returns_secondary_and_nearest_weekly_monthly_max_pain():
    weekly = date(2026, 10, 16)
    monthly = date(2026, 10, 30)
    series = (
        _series(series_id="call-95", strike="95", oi="200",
                expiry=weekly.isoformat(), expiry_kind="WEEKLY"),
        _series(
            series_id="call-100", strike="100", expiry=weekly.isoformat(),
            expiry_kind="WEEKLY",
        ),
        _series(
            series_id="call-110", strike="110", oi="90",
            expiry=weekly.isoformat(), expiry_kind="WEEKLY",
        ),
        _series(
            series_id="put-105", option_type="PUT", strike="105",
            expiry=weekly.isoformat(), expiry_kind="WEEKLY",
        ),
        _series(
            series_id="month-call", strike="100", expiry=monthly.isoformat(),
            expiry_kind="MONTHLY",
        ),
        _series(
            series_id="month-put", option_type="PUT", strike="110",
            expiry=monthly.isoformat(), expiry_kind="MONTHLY",
        ),
    )
    policy = _policy(expiries=(weekly, monthly))
    result = evaluate(
        _snapshot(series, denominator="700", trade_date=date(2026, 10, 15)),
        policy, 1000,
    ).live
    farther = (
        _series(series_id="far-weekly-call", strike="80", oi="900",
                expiry="2026-10-23", expiry_kind="WEEKLY"),
        _series(series_id="far-monthly-put", option_type="PUT", strike="120", oi="900",
                expiry="2026-11-27", expiry_kind="MONTHLY"),
    )
    with_farther_rolls = evaluate(
        _snapshot((*series, *farther), denominator="3100", trade_date=date(2026, 10, 15)),
        _policy(expiries=(weekly, date(2026, 10, 23), monthly, date(2026, 11, 27))),
        1000,
    ).live
    assert result.call_wall.primary.value == Decimal("95")
    assert result.call_wall.secondary.value == Decimal("100")
    assert result.call_wall.method == "OI_NOTIONAL"
    assert result.max_pain_weekly is not None
    assert result.max_pain_monthly is not None
    assert result.max_pain_weekly.method == "HOLDER_INTRINSIC_WEEKLY_V1"
    assert result.max_pain_monthly.method == "HOLDER_INTRINSIC_MONTHLY_V1"
    assert result.expiry_set == (weekly, monthly)
    assert with_farther_rolls.max_pain_weekly.value == result.max_pain_weekly.value
    assert with_farther_rolls.max_pain_monthly.value == result.max_pain_monthly.value


def test_0dte_respects_early_close_and_settled_evidence_is_independent():
    early_close = 1500
    live_series = _series(cutoff=2000)
    live_snapshot = _snapshot((live_series,), session_close=early_close)
    before_close = evaluate(live_snapshot, _policy(), early_close - 1)
    after_close = evaluate(live_snapshot, _policy(), early_close)
    assert before_close.live.has_0dte is True
    assert before_close.live.magnet_levels
    assert after_close.live.has_0dte is False
    assert after_close.live.magnet_levels == ()

    settled_expiry = date(2026, 10, 23)
    settled_series = replace(
        _series(
            series_id="settled-call", multiplier="200", cutoff=2000,
            expiry=settled_expiry.isoformat(),
        ),
        oi_asof_ns=700, spot_observed_ns=700, spot_available_ns=700,
        quote_observed_ns=700, quote_available_ns=700, iv_observed_ns=700,
        iv_available_ns=700, greek_observed_ns=700, greek_available_ns=700,
    )
    live_chain = live_snapshot.live
    settled_chain = replace(
        live_chain, snapshot_id="settled-independent", data_state="SETTLED",
        observed_ns=700, available_ns=900, revision=4, series=(settled_series,),
        calendar=replace(
            live_chain.calendar, trade_date=date(2026, 10, 15), session_close_ns=1500,
        ),
        eligible_expiries=(settled_expiry,),
    )
    policy = replace(_policy(), settled_eligible_expiries=(settled_expiry,))
    paired = evaluate(GammaSnapshotV1(live=live_chain, settled=settled_chain), policy, 1000)
    assert paired.live.snapshot_id == "live-1"
    assert paired.live.expiry_set == (date(2026, 10, 16),)
    assert paired.settled.snapshot_id == "settled-independent"
    assert paired.settled.expiry_set == (settled_expiry,)
    assert paired.settled.observed_ns == 700
    assert paired.settled.available_ns == 900
    assert paired.live.aggregate_gamma != paired.settled.aggregate_gamma
    assert paired.settled.revision == 4
    assert paired.settled_missing is False


def test_policy_cannot_loosen_coverage_or_freshness_thresholds():
    policy = _policy()
    with pytest.raises(PolicyOutOfBoundsError) as coverage:
        replace(policy, coverage_threshold=Decimal("0.79"))
    assert str(coverage.value) == "POLICY_OUT_OF_BOUNDS"
    with pytest.raises(PolicyOutOfBoundsError) as freshness:
        replace(policy, max_spot_age_ns=4_000_000_000)
    assert str(freshness.value) == "POLICY_OUT_OF_BOUNDS"


def test_local_expiry_before_calendar_trade_date_is_unavailable_even_with_future_cutoff():
    expired = _series(expiry="2026-10-15", cutoff=31_536_000_000_000_000)
    result = evaluate(
        _snapshot((expired,), trade_date=date(2026, 10, 16)), _policy(), 1000,
    ).live
    assert result.status == "UNAVAILABLE"
    assert "EXPIRY_BEFORE_TRADE_DATE" in result.reasons
    assert result.aggregate_gamma is None
    assert result.flip is None


def test_mixed_currency_exposures_are_separate_and_never_combined():
    usd = _series(series_id="usd-call", currency="USD")
    eur = _series(
        series_id="eur-call", currency="EUR",
        deliverable_units=(DeliverableLegV1("UNDERLIER", "XYZ", Decimal("100"), "EUR"),),
    )
    result = evaluate(
        _snapshot((usd, eur), denominator="200"), _policy(), 1000,
    ).live
    assert result.status == "DEGRADED"
    assert "MIXED_CURRENCY" in result.reasons
    assert result.aggregate_gamma is None
    assert result.flip is None
    assert result.call_wall is None
    assert {item.currency for item in result.currency_exposures} == {"USD", "EUR"}
    assert all(item.aggregate_gamma is not None for item in result.currency_exposures)


def test_gamma_decimal_inputs_are_bounded_and_arithmetic_ignores_ambient_emax():
    with pytest.raises(ValueError):
        _series(oi="1e39")
    with pytest.raises(ValueError):
        _series(gamma="123456789012345678901234567890123456789012345678901")

    snapshot = _snapshot((_series(),))
    expected = evaluate(snapshot, _policy(), 1000)
    with localcontext() as context:
        context.prec = 6
        context.Emax = 9
        constrained = evaluate(snapshot, _policy(), 1000)
    assert constrained == expected
    assert constrained.semantic_digest == expected.semantic_digest


def test_gex_precision_over_34_digits_is_rejected_without_rounding():
    with pytest.raises(PrecisionExceededError, match="PRECISION_EXCEEDED"):
        _series(gamma="1.12345678901234567890123456789012345")


def test_gex_exact_34_digit_exposure_arithmetic_preserves_last_digit():
    gamma = "1.23456789012345678901234567890123"
    series = _series(multiplier="1", oi="1", spot="1", gamma=gamma)
    result = evaluate(_snapshot((series,), denominator="1"), _policy(), 1000).live
    assert result.aggregate_gamma == Decimal("-0.0123456789012345678901234567890123")


def test_oi_coverage_uses_exact_ratio_below_point_eight_without_rounding_up():
    numerator = "7999999999999999999999999999999995"
    denominator = "9999999999999999999999999999999994"
    series = _series(oi=numerator, multiplier="1", spot="1", gamma="1")
    result = evaluate(
        _snapshot((series,), denominator=denominator), _policy(), 1000,
    ).live
    assert result.status == "DEGRADED"
    assert "LOW_OI_COVERAGE" in result.reasons
    assert result.coverage_exact is not None
    assert result.coverage_exact[0] * 5 < result.coverage_exact[1] * 4
    assert result.coverage_ratio == Decimal("0.8")
    assert result.flip is None
    assert result.call_wall is None


def test_34_digit_oi_times_multiplier_overflow_fails_closed():
    oi = "9999999999999999999999999999999999"
    series = _series(oi=oi, multiplier="2", spot="10", gamma="1")
    result = evaluate(_snapshot((series,), denominator=oi), _policy(), 1000).live
    assert result.status == "UNAVAILABLE"
    assert "PRECISION_EXCEEDED" in result.reasons
    assert result.aggregate_gamma is None
    assert result.currency_exposures == ()


def test_intermediate_spot_square_may_exceed_emax_when_final_exposure_is_valid():
    series = _series(multiplier="1", oi="1", spot="1E+20", gamma="1")
    result = evaluate(_snapshot((series,), denominator="1"), _policy(), 1000).live
    assert result.status == "OK"
    assert result.aggregate_gamma == Decimal("-1E+38")


def test_kernel_issued_result_replace_rejects_inconsistent_coverage_status_and_reasons():
    estimate = evaluate(_snapshot((_series(),)), _policy(), 1000)
    assert estimate.live.status == "OK"
    assert estimate.live.coverage_exact == (1, 1)
    invalid_changes = (
        {"coverage_exact": (0, 1)},
        {"status": "DEGRADED"},
        {"reasons": ("LOW_OI_COVERAGE",)},
    )
    for changes in invalid_changes:
        with pytest.raises(ValueError):
            replace(estimate.live, **changes)


def test_trailing_zero_decimal_beyond_raw_coefficient_cap_canonicalizes():
    trailing_zero_gamma = Decimal("1." + "0" * 50)
    canonical = _series(gamma=trailing_zero_gamma)
    ordinary = _series(gamma="1")
    assert canonical.gamma == Decimal("1")
    canonical_result = evaluate(_snapshot((canonical,)), _policy(), 1000)
    ordinary_result = evaluate(_snapshot((ordinary,)), _policy(), 1000)
    assert canonical_result.live == ordinary_result.live
    assert canonical_result.semantic_digest == ordinary_result.semantic_digest


def test_boolean_is_rejected_for_integer_calendar_evidence_policy_output_and_asof_fields():
    series = _series()
    snapshot = _snapshot((series,))
    policy = _policy()
    estimate = evaluate(snapshot, policy, 1000)
    invalid_replacements = (
        lambda: replace(snapshot.live.calendar, session_open_ns=True),
        lambda: replace(series, oi_asof_ns=True),
        lambda: replace(snapshot.live, revision=True),
        lambda: replace(policy, max_spot_age_ns=True),
        lambda: replace(estimate.live, revision=True),
        lambda: evaluate(snapshot, policy, True),
    )
    for reconstruct in invalid_replacements:
        with pytest.raises((IntegerFieldError, ValueError)):
            reconstruct()


def test_equivalent_gamma_scales_are_canonical_in_outputs_and_digest():
    ordinary = evaluate(_snapshot((_series(gamma="0.02"),)), _policy(), 1000)
    scaled_text = evaluate(_snapshot((_series(gamma="0.020"),)), _policy(), 1000)
    assert str(ordinary.live.aggregate_gamma) == str(scaled_text.live.aggregate_gamma)
    assert ordinary.live == scaled_text.live
    assert ordinary.semantic_digest == scaled_text.semantic_digest


def test_public_gamma_objects_cannot_be_copied_or_pickled_and_replace_revalidates():
    snapshot = _snapshot((_series(),))
    policy = _policy()
    estimate = evaluate(snapshot, policy, 1000)
    public_records = []
    seen = set()

    def collect(value):
        if id(value) in seen:
            return
        seen.add(id(value))
        if is_dataclass(value) and not isinstance(value, type):
            public_records.append(value)
            for field in fields(value):
                collect(getattr(value, field.name))
        elif isinstance(value, (tuple, list)):
            for item in value:
                collect(item)

    for root in (snapshot, policy, estimate):
        collect(root)
    for value in public_records:
        with pytest.raises((TypeError, ValueError)):
            copy.copy(value)
        with pytest.raises((TypeError, ValueError)):
            copy.deepcopy(value)
        with pytest.raises((TypeError, ValueError)):
            pickle.dumps(value)
    with pytest.raises(ValueError):
        replace(estimate.live, pin_probability=Decimal("0.9"))
    with pytest.raises(ValueError):
        replace(estimate.live, reasons=[])
    with pytest.raises(ValueError, match="RESULT_SEAL_INVALID"):
        replace(estimate.live, confidence=estimate.live.confidence)


def test_result_seals_cannot_be_replayed_through_replace_or_direct_construction():
    estimate = evaluate(_snapshot((_series(),)), _policy(), 1000)
    for record in (estimate.live, estimate):
        assert record is not None
        fields_for_init = {
            field.name: getattr(record, field.name)
            for field in fields(type(record))
            if field.init
        }
        with pytest.raises(ValueError, match="RESULT_SEAL_INVALID"):
            type(record)(**fields_for_init)
        with pytest.raises(ValueError, match="RESULT_SEAL_INVALID"):
            type(record)(**fields_for_init, _issue_token=record._seal)
        with pytest.raises(ValueError, match="RESULT_SEAL_INVALID"):
            replace(record, _issue_token=record._seal)
        for forged_seal in (record._seal, getattr(record, "semantic_digest", None)):
            with pytest.raises((TypeError, ValueError)):
                replace(record, _seal=forged_seal)
