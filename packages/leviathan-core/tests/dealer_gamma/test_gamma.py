"""GEX-001 examples for signed scenario arithmetic and evidence gates."""

import copy
import pickle
from dataclasses import fields, replace
from datetime import date, timedelta
from decimal import Decimal, localcontext
from random import Random

import pytest

from leviathan_core.dealer_gamma import (
    ChainSnapshotV1,
    DealerExposureAssumptionV1,
    DecimalOutOfBoundsError,
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
from leviathan_core.dealer_gamma.exposure import observed_exposure, repriced_gamma
from leviathan_core.dealer_gamma.levels import (
    adjusted_multiplier,
    adjusted_strike,
    flip_level,
    max_pain,
)
from leviathan_core.dealer_gamma.models import _RESULT_SENTINEL, _is_issued, _issue_results

D = Decimal
NOW = 1_800_000_000_000_000_000
DAY = 86_400_000_000_000
TRADE_DATE = date(2026, 9, 30)


def calendar() -> ExchangeCalendarV1:
    return ExchangeCalendarV1("XNYS", "2026a", TRADE_DATE, NOW - DAY // 24,
                              NOW + 4 * DAY // 24, early_close=True)


def series(series_id: str = "C100", **changes: object) -> OptionSeriesEvidenceV1:
    base = OptionSeriesEvidenceV1(
        series_id=series_id, underlier="XYZ", contract=f"XYZ-{series_id}", venue="XOPT",
        option_type="CALL", strike=D("100"), expiry_date=TRADE_DATE,
        expiry_kind="WEEKLY", settlement="PM", expiry_cutoff_ns=calendar().session_close_ns,
        multiplier=D("100"), currency="USD", open_interest=D("100"),
        oi_asof_ns=NOW - DAY, spot=D("100"), spot_observed_ns=NOW,
        spot_available_ns=NOW, bid=D("2"), ask=D("2.10"),
        quote_observed_ns=NOW, quote_available_ns=NOW, implied_vol=D("0.20"),
        iv_observed_ns=NOW, iv_available_ns=NOW, gamma=D("0.02"),
        gamma_units="PER_UNDERLYING_UNIT", greek_observed_ns=NOW,
        greek_available_ns=NOW, source_id="licensed-fixture", dataset_id="set-v1",
        entitlement_id="fixture-entitlement", entitlement_status="ENTITLED",
        corporate_action_version="no-action-v1",
        multiplier_basis="PRE_ACTION", adjustment_version="adjust-v1",
        deliverable_units=(DeliverableLegV1("UNDERLIER", "XYZ", D("100"), "USD"),),
    )
    return replace(base, **changes)


def assumption(call_sign: int = -1, put_sign: int = 1) -> DealerExposureAssumptionV1:
    return DealerExposureAssumptionV1("dealers_short_calls_long_puts", "1",
                                      "Declared OI fraction scenario, no observed inventory",
                                      call_sign, put_sign)


def policy(
    eligible_expiries: tuple[date, ...] = (TRADE_DATE,),
    dealer_assumption: DealerExposureAssumptionV1 | None = None,
) -> GammaPolicyV1:
    return GammaPolicyV1("offline-gex", "1", "gex-calc-1", "expiry-calendar-1",
                         eligible_expiries, dealer_assumption or assumption(),
                         (D("50"), D("75"), D("100"), D("125"), D("150")), D("0.0001"))


def snapshot(
    evidence: tuple[OptionSeriesEvidenceV1, ...] | None = None,
    denominator: Decimal | None = None,
) -> GammaSnapshotV1:
    evidence = evidence if evidence is not None else (series(),)
    denominator = denominator if denominator is not None else sum(
        (s.open_interest for s in evidence), D("0"))
    chain = ChainSnapshotV1(
        "live-1", "LIVE", "XYZ", "XOPT", NOW, NOW, 0,
        "licensed-fixture", "set-v1", calendar(), (TRADE_DATE,), denominator,
        True, len(evidence), evidence,
    )
    return GammaSnapshotV1(chain)


def test_signed_exposure_is_linear_and_reverses_with_assumption() -> None:
    option = series()
    base = observed_exposure(option, policy(), D("100"))
    assert base == D("-20000")
    assert (observed_exposure(replace(option, open_interest=D("200")), policy(), D("100"))
            == base * 2)
    assert observed_exposure(replace(option, multiplier=D("200")), policy(), D("100")) == base * 2
    reversed_policy = policy(dealer_assumption=assumption(1, -1))
    assert observed_exposure(option, reversed_policy, D("100")) == -base
    assert option.gamma >= D("0")
    assert repriced_gamma(option, option.spot, NOW) == option.gamma


def test_seeded_signed_exposure_properties() -> None:
    rng = Random(0x6E7)
    gamma_choices = (D("0.001"), D("0.02"), D("0.5"))
    spot_choices = (D("5"), D("100"), D("750"))
    # Each row is independent and can be isolated by its case index if it fails.
    cases = tuple((D(rng.randrange(1, 1001)), D(rng.randrange(1, 501)),
                   gamma_choices[rng.randrange(len(gamma_choices))],
                   spot_choices[rng.randrange(len(spot_choices))]) for _ in range(32))
    for index, (oi, multiplier, gamma, spot) in enumerate(cases):
        option = series(f"generated-{index}", open_interest=oi,
                        multiplier=multiplier, gamma=gamma, spot=spot)
        exposure = observed_exposure(option, policy(), spot)
        doubled = observed_exposure(replace(option, open_interest=oi * 2), policy(), spot)
        reversed_exposure = observed_exposure(
            option, policy(dealer_assumption=assumption(1, -1)), spot)
        assert doubled == exposure * 2, index
        assert reversed_exposure == -exposure, index


def test_split_maps_strike_and_preserves_notional() -> None:
    option = series(split_factor=D("2"),
                    deliverable_units=(DeliverableLegV1("UNDERLIER", "XYZ", D("200"),
                                                        "USD"),))
    assert adjusted_strike(option) == D("50")
    assert adjusted_multiplier(option) == D("200")
    result = evaluate(snapshot((option,)), policy(), NOW).live
    assert result is not None and result.status == "OK"
    assert result.call_wall is not None and result.call_wall.primary is not None
    assert result.call_wall.primary.value == D("50")


def test_max_pain_orders_exact_split_strikes_before_display_rounding() -> None:
    deliverable = (DeliverableLegV1("UNDERLIER", "XYZ", D("1"), "USD"),)
    common = dict(multiplier=D("1"), split_factor=D("3"),
                  multiplier_basis="POST_ACTION_ADJUSTED", deliverable_units=deliverable,
                  open_interest=D("1"))
    call = series("lower-call", strike=D("100"), **common)
    put = series("upper-put", option_type="PUT", strike=D("200"), **common)
    pain = max_pain((call, put), "WEEKLY")
    assert pain is not None
    assert pain.value == D("33.33333333333333333333333333333333")
    assert pain.strength == D("33.33333333333333333333333333333333")


def test_post_adjusted_multiplier_and_mixed_cash_deliverable() -> None:
    option = series(
        split_factor=D("2"), multiplier=D("150"),
        multiplier_basis="POST_ACTION_ADJUSTED", adjustment_version="occ-2026.1",
        deliverable_units=(DeliverableLegV1("UNDERLIER", "XYZ", D("150"), "USD"),
                           DeliverableLegV1("CASH", "USD", D("25.50"), "USD")),
    )
    assert adjusted_multiplier(option) == D("150")
    result = evaluate(snapshot((option,)), policy(), NOW).live
    assert result is not None and result.status == "OK"
    assert result.aggregate_gamma == D("-30000")
    assert result.gamma_units == "PER_UNDERLYING_UNIT"
    assert result.multiplier_bases == ("POST_ACTION_ADJUSTED",)
    assert result.adjustment_versions == ("occ-2026.1",)
    assert result.call_wall is not None and result.call_wall.primary is not None
    assert result.call_wall.primary.value == D("50")


def test_other_asset_is_explicitly_excluded_and_missing_basis_fails_closed() -> None:
    other = series(deliverable_units=(
        DeliverableLegV1("UNDERLIER", "XYZ", D("100"), "USD"),
        DeliverableLegV1("OTHER_ASSET", "SPINCO", D("25"), "USD"),
    ))
    result = evaluate(snapshot((other,)), policy(), NOW).live
    assert result is not None and result.status == "UNAVAILABLE"
    assert result.aggregate_gamma is None
    assert "NON_STANDARD_DELIVERABLE_OTHER_ASSET" in result.reasons
    assert result.excluded_series[0].status == "EXCLUDED"
    assert result.excluded_series[0].reason == "NON_STANDARD_DELIVERABLE_OTHER_ASSET"

    missing = replace(series(), multiplier_basis=None)
    result = evaluate(snapshot((missing,)), policy(), NOW).live
    assert result is not None and result.status == "UNAVAILABLE"
    assert "ADJUSTMENT_BASIS_UNKNOWN" in result.reasons
    assert result.excluded_series[0].status == "EXCLUDED"

    no_legs = replace(series(), deliverable_units=None)
    result = evaluate(snapshot((no_legs,)), policy(), NOW).live
    assert result is not None and "DELIVERABLE_UNITS_MISSING" in result.reasons

    no_version = replace(series(), adjustment_version=None)
    result = evaluate(snapshot((no_version,)), policy(), NOW).live
    assert result is not None and "ADJUSTMENT_VERSION_MISSING" in result.reasons


def test_flip_brackets_root_without_extrapolation() -> None:
    root, reason = flip_level((D("90"), D("110")), D("0.001"), D("100"),
                              lambda spot: spot - D("100"))
    assert reason is None and root is not None
    assert root.label == "MODEL_ESTIMATE"
    assert root.lower_bracket <= D("100") <= root.upper_bracket
    assert root.error_bound <= D("0.001")
    missing, reason = flip_level((D("90"), D("110")), D("0.001"), D("100"),
                                 lambda spot: spot + D("1"))
    assert missing is None and reason == "FLIP_NOT_FOUND_IN_GRID"
    exact, reason = flip_level((D("90"), D("100"), D("110")), D("0.001"),
                               D("100"), lambda spot: spot - D("100"))
    assert reason is None and exact is not None and exact.value == D("100")
    flat, reason = flip_level((D("90"), D("100"), D("110")), D("0.001"),
                              D("100"), lambda spot: D("0"))
    assert flat is None and reason == "FLIP_NOT_FOUND_IN_GRID"


def test_no_root_uses_canonical_neutral_but_retains_advisory_sign() -> None:
    output = evaluate(snapshot(), policy(), NOW)
    assert output.live is not None
    assert output.live.status == "OK"
    assert output.live.gamma_sign_regime == "NEGATIVE_GAMMA"
    assert output.live.gamma_sign_regime_label == "MODEL_ESTIMATE"
    assert output.live.regime == "NEUTRAL"
    assert output.live.regime_confidence == D("0")
    assert output.live.regime_reason == "FLIP_NULL_DB_RULE"
    assert output.live.flip is None
    assert output.live.flip_reason == "FLIP_NOT_FOUND_IN_GRID"
    assert output.live.pin_probability is None
    assert output.settled_missing and output.settled is None


def test_walls_secondary_tie_and_nearest_weekly_monthly() -> None:
    monthly = TRADE_DATE + timedelta(days=16)
    options = (
        series("C100"),
        series("C105", strike=D("105"), open_interest=D("96")),
        series("P95", option_type="PUT", strike=D("95"), open_interest=D("100")),
        series("M110", expiry_date=monthly, expiry_kind="MONTHLY",
               expiry_cutoff_ns=NOW + 16 * DAY, strike=D("110"),
               open_interest=D("50")),
    )
    chain = replace(snapshot(options).live, eligible_expiries=(TRADE_DATE, monthly))
    assert chain is not None
    chain = replace(chain, eligible_oi_denominator=D("346"))
    result = evaluate(GammaSnapshotV1(chain), policy((TRADE_DATE, monthly)), NOW).live
    assert result is not None and result.status == "OK"
    assert result.call_wall is not None
    assert result.call_wall.primary is not None and result.call_wall.primary.value == D("100")
    assert result.call_wall.secondary is not None and result.call_wall.secondary.value == D("105")
    assert result.max_pain_weekly is not None
    assert result.max_pain_monthly is not None
    assert result.max_pain_monthly.value == D("110")
    assert result.has_0dte and result.magnet_levels
    assert sum((m.weight for m in result.magnet_levels), D("0")) == D("1")


def test_max_pain_minimizes_holder_intrinsic_payoff() -> None:
    options = (
        series("C90", strike=D("90")),
        series("C100", strike=D("100")),
        series("P100", option_type="PUT", strike=D("100")),
        series("P110", option_type="PUT", strike=D("110")),
    )
    pain = max_pain(options, "WEEKLY")
    assert pain is not None and pain.value == D("100")
    assert pain.strength == D("200000")


def test_stale_coverage_entitlement_and_early_close_fail_closed() -> None:
    stale_spot = replace(series(), spot_observed_ns=NOW - 2_000_000_001,
                         spot_available_ns=NOW - 2_000_000_001)
    result = evaluate(snapshot((stale_spot,)), policy(), NOW).live
    assert result is not None and result.status == "STALE"
    assert "STALE_SPOT" in result.reasons and result.flip is None
    result = evaluate(snapshot(denominator=D("126")), policy(), NOW).live
    assert result is not None and result.status == "DEGRADED"
    assert "LOW_OI_COVERAGE" in result.reasons
    denied = replace(series(), entitlement_status="DENIED")
    result = evaluate(snapshot((denied,)), policy(), NOW).live
    assert result is not None and result.status == "UNAVAILABLE"
    assert "NO_ELIGIBLE_ENTITLED_SERIES" in result.reasons
    bad_split = replace(series(), split_factor=D("0"))
    result = evaluate(snapshot((bad_split,)), policy(), NOW).live
    assert result is not None and result.status == "UNAVAILABLE"
    assert "INVALID_SPLIT_FACTOR" in result.reasons
    after_close = calendar().session_close_ns + 1
    result = evaluate(snapshot(), policy(), after_close).live
    assert result is not None and not result.has_0dte
    assert result.status == "UNAVAILABLE"


def test_digest_is_order_independent_and_revision_sensitive() -> None:
    options = (series("C100"), series("P100", option_type="PUT"))
    first = snapshot(options)
    assert first.live is not None
    second = GammaSnapshotV1(replace(first.live, series=tuple(reversed(options))))
    assert evaluate(first, policy(), NOW).semantic_digest == evaluate(
        second, policy(), NOW).semantic_digest
    corrected = GammaSnapshotV1(replace(first.live, revision=1))
    assert evaluate(first, policy(), NOW).semantic_digest != evaluate(
        corrected, policy(), NOW).semantic_digest
    with localcontext() as context:
        context.prec = 6
        low_precision = evaluate(first, policy(), NOW)
    assert low_precision.semantic_digest == evaluate(first, policy(), NOW).semantic_digest
    equivalent = GammaSnapshotV1(replace(first.live, series=(
        replace(options[0], open_interest=D("100.00")), options[1])))
    assert evaluate(first, policy(), NOW).semantic_digest == evaluate(
        equivalent, policy(), NOW).semantic_digest


def test_settled_is_independent_and_expiry_roll_skips_early_close() -> None:
    next_weekly = TRADE_DATE + timedelta(days=2)
    after_close = calendar().session_close_ns + 1
    expired = series("expired")
    rolled = series("rolled", expiry_date=next_weekly,
                    expiry_cutoff_ns=NOW + 2 * DAY, strike=D("105"),
                    spot_observed_ns=after_close, spot_available_ns=after_close,
                    quote_observed_ns=after_close, quote_available_ns=after_close,
                    iv_observed_ns=after_close, iv_available_ns=after_close,
                    greek_observed_ns=after_close, greek_available_ns=after_close)
    live_chain = snapshot((expired, rolled)).live
    assert live_chain is not None
    live_chain = replace(live_chain, observed_ns=after_close, available_ns=after_close,
                         eligible_expiries=(TRADE_DATE, next_weekly),
                         eligible_oi_denominator=D("100"))
    live_result = evaluate(GammaSnapshotV1(live_chain),
                           policy((TRADE_DATE, next_weekly)), after_close).live
    assert live_result is not None and live_result.status == "OK"
    assert live_result.max_pain_weekly is not None
    assert live_result.max_pain_weekly.value == D("105")
    assert not live_result.has_0dte

    yesterday = NOW - DAY
    settled_available = yesterday + DAY // 24
    settled_series = replace(rolled, expiry_date=TRADE_DATE,
                             expiry_cutoff_ns=calendar().session_close_ns,
                             spot_observed_ns=yesterday,
                             spot_available_ns=settled_available,
                             quote_observed_ns=yesterday,
                             quote_available_ns=settled_available,
                             iv_observed_ns=yesterday,
                             iv_available_ns=settled_available,
                             greek_observed_ns=yesterday,
                             greek_available_ns=settled_available,
                             oi_asof_ns=yesterday)
    settled_calendar = ExchangeCalendarV1("XNYS", "2026a", TRADE_DATE - timedelta(days=1),
                                          yesterday - DAY // 24, yesterday + 4 * DAY // 24)
    settled_chain = replace(live_chain, snapshot_id="settled-1", data_state="SETTLED",
                            observed_ns=yesterday, available_ns=settled_available, revision=2,
                            calendar=settled_calendar, eligible_expiries=(TRADE_DATE,),
                            series=(settled_series,),
                            expected_series_count=1)
    paired_policy = replace(policy((TRADE_DATE, next_weekly)),
                            settled_eligible_expiries=(TRADE_DATE,))
    paired = evaluate(GammaSnapshotV1(live_chain, settled_chain),
                      paired_policy, after_close)
    assert paired.live is not None and paired.settled is not None
    assert paired.live.snapshot_id != paired.settled.snapshot_id
    assert paired.live.observed_ns != paired.settled.observed_ns
    assert paired.settled.available_ns > paired.settled.observed_ns
    assert paired.settled.status == "OK"
    assert paired.live.expiry_set != paired.settled.expiry_set
    assert not paired.settled_missing


def test_float_evidence_is_rejected() -> None:
    with pytest.raises(ValueError, match="binary floats"):
        series(gamma=0.02)
    with pytest.raises(ValueError, match="duplicate option contract"):
        snapshot((series("a", contract="same"), series("b", contract="same")))


def test_absent_dealer_assumption_reports_unknown_sign() -> None:
    unknown_policy = replace(policy(), assumption=None)
    result = evaluate(snapshot(), unknown_policy, NOW).live
    assert result is not None and result.status == "UNAVAILABLE"
    assert result.sign_label == "UNKNOWN_SIGN"
    assert result.regime == "NEUTRAL" and result.aggregate_gamma is None


def test_prd_policy_bounds_cannot_be_loosened_by_replace() -> None:
    base = policy()
    for change in ({"coverage_threshold": D("0.10")},
                   {"max_spot_age_ns": 4_000_000_000},
                   {"max_iv_age_ns": 10_000_000_001},
                   {"max_quote_age_ns": 10_000_000_001},
                   {"max_greek_age_ns": 10_000_000_001},
                   {"max_oi_age_ns": 172_800_000_000_001}):
        with pytest.raises(PolicyOutOfBoundsError, match="POLICY_OUT_OF_BOUNDS"):
            replace(base, **change)
    assert replace(base, coverage_threshold=D("0.90")).coverage_threshold == D("0.90")
    assert replace(base, max_spot_age_ns=1_000_000_000).max_spot_age_ns == 1_000_000_000


def test_past_local_expiry_cannot_be_revived_by_future_cutoff() -> None:
    previous = TRADE_DATE - timedelta(days=1)
    expired = series(expiry_date=previous, expiry_cutoff_ns=NOW + DAY)
    chain = snapshot((expired,)).live
    assert chain is not None
    result = evaluate(GammaSnapshotV1(replace(chain, eligible_expiries=(previous,))),
                      policy((previous,)), NOW).live
    assert result is not None and result.status == "UNAVAILABLE"
    assert "EXPIRY_BEFORE_TRADE_DATE" in result.reasons
    assert result.aggregate_gamma is None and result.call_wall is None


def test_bounded_decimal_and_hostile_ambient_context() -> None:
    with pytest.raises(DecimalOutOfBoundsError, match="DECIMAL_OUT_OF_BOUNDS"):
        series(open_interest=D("1E+999999"))
    ordinary_snapshot = snapshot()
    ordinary_policy = policy()
    expected = evaluate(ordinary_snapshot, ordinary_policy, NOW)
    with localcontext() as context:
        context.Emax = 1
        assert evaluate(ordinary_snapshot, ordinary_policy, NOW) == expected
    huge = series(open_interest=D("1E+38"))
    unavailable = evaluate(snapshot((huge,), D("1E+38")), policy(), NOW).live
    assert unavailable is not None and unavailable.status == "UNAVAILABLE"
    assert "PRECISION_EXCEEDED" in unavailable.reasons
    assert unavailable.aggregate_gamma is None


def test_replace_copy_pickle_and_equal_decimal_scale_are_frozen() -> None:
    result = evaluate(snapshot(), policy(), NOW)
    live = result.live
    assert live is not None
    with pytest.raises(ValueError, match="PIN_PROBABILITY_UNAVAILABLE"):
        replace(live, pin_probability=D("0.9"))
    with pytest.raises(ValueError, match="MUTABLE_COLLECTION_FORBIDDEN"):
        replace(live, reasons=[])
    for value in (series(), policy(), live, result):
        with pytest.raises(TypeError, match="FROZEN_MODEL_COPY_FORBIDDEN"):
            copy.copy(value)
        with pytest.raises(TypeError, match="FROZEN_MODEL_COPY_FORBIDDEN"):
            copy.deepcopy(value)
        with pytest.raises(TypeError, match="FROZEN_MODEL_PICKLE_FORBIDDEN"):
            pickle.dumps(value)
    equal_scale = evaluate(snapshot((series(gamma=D("0.020")),)), policy(), NOW)
    assert equal_scale == result
    assert str(equal_scale.live.aggregate_gamma) == str(live.aggregate_gamma)


def test_result_seal_rejects_public_issuance_and_changed_replacement() -> None:
    result = evaluate(snapshot(), policy(), NOW)
    live = result.live
    assert live is not None
    for record in (live, result):
        values = {item.name: getattr(record, item.name)
                  for item in fields(record) if item.name != "_seal"}
        with pytest.raises(ValueError, match="RESULT_SEAL_INVALID"):
            type(record)(**values)
    with pytest.raises(ValueError, match="RESULT_SEAL_INVALID"):
        replace(live, confidence=live.confidence)
    with pytest.raises(TypeError):
        replace(live, _seal=live._seal)
    with pytest.raises(ValueError, match="RESULT_SEAL_INVALID"):
        replace(live, _issue_token=live._seal)
    assert live._seal is not _RESULT_SENTINEL
    assert _is_issued(live) and _is_issued(result)
    equally_valued = evaluate(snapshot(), policy(), NOW)
    assert equally_valued == result and _is_issued(equally_valued)
    with _issue_results(), pytest.raises(ValueError, match="RESULT_SEAL_INVALID"):
        replace(live, _issue_token=live._seal)
    with pytest.raises(ValueError, match="COVERAGE_EVIDENCE_MISMATCH"):
        replace(live, coverage_exact=(0, 1))
    with pytest.raises(ValueError, match="RESULT_SEAL_INVALID"):
        replace(result, semantic_digest="forged")


def test_currency_exposures_are_never_combined_without_fx() -> None:
    usd = series("USD")
    eur = series("EUR", currency="EUR", deliverable_units=(
        DeliverableLegV1("UNDERLIER", "XYZ", D("100"), "EUR"),
    ))
    usd_only = evaluate(snapshot((usd,)), policy(), NOW).live
    mixed = evaluate(snapshot((usd, eur)), policy(), NOW).live
    assert usd_only is not None and mixed is not None
    assert len(usd_only.currency_exposures) == 1
    assert usd_only.currency_exposures[0].currency == "USD"
    assert mixed.status == "DEGRADED" and "MIXED_CURRENCY" in mixed.reasons
    assert mixed.aggregate_gamma is None and mixed.call_wall is None and mixed.flip is None
    assert tuple(item.currency for item in mixed.currency_exposures) == ("EUR", "USD")
    assert {item.aggregate_gamma for item in mixed.currency_exposures} == {D("-20000")}


def test_precision_boundary_and_bool_integer_fields() -> None:
    with pytest.raises(PrecisionExceededError, match="PRECISION_EXCEEDED"):
        series(gamma=D("12345678901234567890123456789012345"))
    assert series(gamma=D("1234567890123456789012345678901234")).gamma == D(
        "1234567890123456789012345678901234"
    )
    with pytest.raises(IntegerFieldError, match="INTEGER_REQUIRED"):
        series(expiry_cutoff_ns=True)
    with pytest.raises(IntegerFieldError, match="INTEGER_REQUIRED"):
        replace(calendar(), session_close_ns=True)
    chain = snapshot().live
    assert chain is not None
    with pytest.raises(ValueError):
        replace(chain, revision=True)
    with pytest.raises(PolicyOutOfBoundsError, match="POLICY_OUT_OF_BOUNDS"):
        replace(policy(), max_spot_age_ns=True)
    result = evaluate(snapshot(), policy(), NOW)
    assert result.live is not None
    with pytest.raises(IntegerFieldError, match="INTEGER_REQUIRED"):
        replace(result.live, revision=True)
    with pytest.raises(IntegerFieldError, match="INTEGER_REQUIRED"):
        replace(result, asof_ns=True)


def test_coverage_gate_uses_exact_ratio_below_eighty_percent() -> None:
    numerator = D("7999999999999999999999999999999995")
    denominator = D("9999999999999999999999999999999994")
    option = series(open_interest=numerator, multiplier=D("1"), spot=D("1"),
                    gamma=D("0"), deliverable_units=(
                        DeliverableLegV1("UNDERLIER", "XYZ", D("1"), "USD"),
                    ))
    result = evaluate(snapshot((option,), denominator), policy(), NOW).live
    assert result is not None and result.status == "DEGRADED"
    assert "LOW_OI_COVERAGE" in result.reasons
    assert result.coverage_exact is not None
    exact_numerator, exact_denominator = result.coverage_exact
    assert 5 * exact_numerator < 4 * exact_denominator
    assert result.aggregate_gamma is None and result.call_wall is None


def test_inexact_exposure_product_fails_with_precision_reason() -> None:
    oi = D("9999999999999999999999999999999999")
    option = series(open_interest=oi, multiplier=D("2"), gamma=D("1"), spot=D("10"),
                    deliverable_units=(
                        DeliverableLegV1("UNDERLIER", "XYZ", D("2"), "USD"),
                    ))
    with pytest.raises(PrecisionExceededError, match="PRECISION_EXCEEDED"):
        observed_exposure(option, policy(), option.spot)
    result = evaluate(snapshot((option,), oi), policy(), NOW).live
    assert result is not None and result.status == "UNAVAILABLE"
    assert "PRECISION_EXCEEDED" in result.reasons
    assert result.aggregate_gamma is None and result.call_wall is None
