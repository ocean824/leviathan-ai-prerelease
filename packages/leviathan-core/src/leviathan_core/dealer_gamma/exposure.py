"""Pure GEX-001 scenario arithmetic; no inventory inference or execution effect.

Decimal precision is 34 digits, ROUND_HALF_EVEN. Repricing preserves the
entitled observed gamma at its observed spot and uses a Black-Scholes zero-carry
lognormal gamma *shape ratio* at a fixed IV and ACT/365 time to the supplied
expiry cutoff. No normal CDF is needed. This is a versioned model estimate,
not a vendor Greek, calibrated inventory, or probability.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import replace
from decimal import ROUND_HALF_EVEN, Decimal, DecimalException, Inexact, localcontext
from fractions import Fraction
from typing import cast

from .levels import (
    adjusted_multiplier,
    adjusted_strike,
    flip_level,
    magnets,
    max_pain,
    rounded_fraction_decimal,
    wall_levels,
)
from .models import (
    _RESULT_SENTINEL,
    KERNEL_CONTEXT,
    ChainSnapshotV1,
    CurrencyExposureV1,
    ExcludedSeriesV1,
    GammaEstimateV1,
    GammaPolicyV1,
    GammaSnapshotV1,
    HorizonEstimateV1,
    OptionSeriesEvidenceV1,
    PrecisionExceededError,
    _issue_results,
    _reissue_result,
    exact_fraction_decimal,
    require_ns,
    semantic_digest,
)

ZERO = Decimal("0")
ONE = Decimal("1")
TWO = Decimal("2")
HUNDRED = Decimal("100")
YEAR_NS = Decimal("31536000000000000")  # 365 * 24 * 3600 * 1e9


def exact_sum(values: Iterable[Decimal]) -> Decimal:
    return exact_fraction_decimal(sum((Fraction(value) for value in values), Fraction()))


def signed_contracts(option: OptionSeriesEvidenceV1, policy: GammaPolicyV1) -> Decimal:
    assumption = policy.assumption
    if assumption is None:
        return ZERO
    sign = assumption.call_sign if option.option_type == "CALL" else assumption.put_sign
    return exact_fraction_decimal(Fraction(option.open_interest)
                                  * Fraction(assumption.oi_fraction) * sign)


def observed_exposure(option: OptionSeriesEvidenceV1, policy: GammaPolicyV1,
                      spot: Decimal) -> Decimal:
    """Signed dollar delta change per 1% spot move, not observed dealer inventory."""
    assumption = policy.assumption
    if assumption is None:
        return ZERO
    sign = assumption.call_sign if option.option_type == "CALL" else assumption.put_sign
    exact = (Fraction(option.open_interest) * Fraction(assumption.oi_fraction)
             * sign * Fraction(adjusted_multiplier(option)) * Fraction(option.gamma)
             * Fraction(spot) ** 2 / 100)
    return exact_fraction_decimal(exact)


def repriced_gamma(option: OptionSeriesEvidenceV1, candidate_spot: Decimal,
                   at_ns: int) -> Decimal:
    """Entitled gamma times BS_SPOT_ZERO_CARRY_SHAPE_V1 ratio.

    The normal density constant cancels. Provider gamma is the level anchor.
    Strike mapping uses the versioned split factor; this model assumes the
    provider Greek is per current underlying price unit.
    """
    if candidate_spot <= ZERO or at_ns >= option.expiry_cutoff_ns:
        raise ValueError("repricing requires positive spot and unexpired series")
    with localcontext(KERNEL_CONTEXT) as ctx:
        ctx.prec = 34
        ctx.rounding = ROUND_HALF_EVEN
        t = Decimal(option.expiry_cutoff_ns - at_ns) / YEAR_NS
        sigma_sqrt_t = option.implied_vol * t.sqrt()
        strike = adjusted_strike(option)

        def d1(spot: Decimal) -> Decimal:
            spot_strike_ratio = rounded_fraction_decimal(Fraction(spot) / strike)
            return (spot_strike_ratio.ln() + option.implied_vol * option.implied_vol
                    * t / TWO) / sigma_sqrt_t

        base = d1(option.spot)
        candidate = d1(candidate_spot)
        log_ratio = ((base * base - candidate * candidate) / TWO
                     + (option.spot / candidate_spot).ln())
        repriced = option.gamma * log_ratio.exp()
        if option.gamma > ZERO and repriced == ZERO:
            raise ValueError("gamma-shape underflow")
        return repriced


def exposure_at(series: tuple[OptionSeriesEvidenceV1, ...], policy: GammaPolicyV1,
                candidate_spot: Decimal, at_ns: int) -> Decimal:
    return sum((signed_contracts(s, policy) * adjusted_multiplier(s)
                * repriced_gamma(s, candidate_spot, at_ns)
                * candidate_spot * candidate_spot / HUNDRED for s in series), ZERO)


def _age(now_ns: int, observed_ns: int) -> int:
    return now_ns - observed_ns


def _freshness(age: int | None, limit: int) -> Decimal:
    if age is None or age > limit:
        return ZERO
    if limit == 0:
        return ONE
    return ONE - Decimal(age) / (Decimal(limit) * TWO)


def _dispersion(series: tuple[OptionSeriesEvidenceV1, ...]) -> Decimal:
    scores: list[Decimal] = []
    for s in series:
        if s.bid is None or s.ask is None or s.bid + s.ask == ZERO:
            scores.append(Decimal("0.5"))
            continue
        spread = TWO * (s.ask - s.bid) / (s.ask + s.bid)
        scores.append(max(ZERO, ONE - min(ONE, spread)))
    return sum(scores, ZERO) / Decimal(len(scores)) if scores else ZERO


def _unavailable(
    chain: ChainSnapshotV1,
    reasons: list[str],
    status: str,
    coverage: Decimal | None,
    spot_age: int | None,
    iv_age: int | None,
    oi_age: int | None,
    assumption_id: str | None,
    assumption_version: str | None,
    exclusions: list[ExcludedSeriesV1],
    coverage_exact: tuple[int, int] | None = None,
) -> HorizonEstimateV1:
    return HorizonEstimateV1(
        data_state=chain.data_state, status=status, reasons=tuple(sorted(set(reasons))),
        snapshot_id=chain.snapshot_id, revision=chain.revision, observed_ns=chain.observed_ns,
        available_ns=chain.available_ns,
        source_ids=tuple(sorted({chain.source_id, *(s.source_id for s in chain.series)})),
        calendar_id=chain.calendar.calendar_id, calendar_version=chain.calendar.version,
        expiry_set=tuple(sorted(chain.eligible_expiries)),
        active_expiry_set=(),
        settlement_conventions=tuple(sorted({s.settlement for s in chain.series})),
        assumption_id=assumption_id,
        assumption_version=assumption_version,
        multiplier_bases=tuple(sorted({s.multiplier_basis for s in chain.series
                                      if s.multiplier_basis is not None})),
        adjustment_versions=tuple(sorted({s.adjustment_version for s in chain.series
                                          if s.adjustment_version is not None})),
        gamma_units=None,
        excluded_series=tuple(sorted(exclusions, key=lambda item: (item.series_id, item.reason))),
        sign_label=("UNKNOWN_SIGN" if assumption_id is None or "UNKNOWN_DEALER_SIGN" in reasons
                    else "SCENARIO_ESTIMATE"),
        aggregate_gamma=None, currency_exposures=(), gamma_sign_regime="NEUTRAL",
        gamma_sign_regime_label="MODEL_ESTIMATE", gamma_sign_confidence=ZERO,
        gamma_sign_reason="NO_VALID_SIGNED_EXPOSURE", regime="NEUTRAL",
        regime_label="MODEL_ESTIMATE", regime_confidence=ZERO,
        regime_reason="FLIP_NULL_DB_RULE",
        coverage_ratio=coverage, coverage_exact=coverage_exact,
        spot_age_ns=spot_age, iv_age_ns=iv_age,
        oi_age_ns=oi_age, confidence=ZERO,
        confidence_method="COVERAGE_MIN_FRESHNESS_DISPERSION_V1", confidence_inputs=(),
        flip=None,
        flip_reason="INPUT_UNAVAILABLE", call_wall=None, put_wall=None,
        max_pain_weekly=None, max_pain_monthly=None, has_0dte=False,
        magnet_levels=(), pin_probability=None, _issue_token=_RESULT_SENTINEL,
    )


def _evaluate_horizon_impl(chain: ChainSnapshotV1, policy: GammaPolicyV1,
                           asof_ns: int) -> HorizonEstimateV1:
    clock = asof_ns if chain.data_state == "LIVE" else chain.observed_ns
    visibility_cutoff = asof_ns if chain.data_state == "SETTLED" else clock
    expected_expiries = (policy.settled_eligible_expiries
                         if chain.data_state == "SETTLED" and policy.settled_eligible_expiries
                         else policy.eligible_expiries)
    reasons: list[str] = []
    hard: list[str] = []
    stale: list[str] = []
    degraded: list[str] = []
    exclusions: list[ExcludedSeriesV1] = []

    def exclude(series: OptionSeriesEvidenceV1, reason: str) -> None:
        exclusions.append(ExcludedSeriesV1(series.series_id, reason))
    assumption_id = policy.assumption.assumption_id if policy.assumption else None
    assumption_version = policy.assumption.version if policy.assumption else None
    if chain.available_ns > asof_ns:
        hard.append("SNAPSHOT_NOT_AVAILABLE")
    if any(max(s.spot_available_ns, s.quote_available_ns, s.iv_available_ns,
               s.greek_available_ns) > chain.available_ns for s in chain.series):
        hard.append("SNAPSHOT_AVAILABILITY_INCONSISTENT")
    if any(max(s.spot_observed_ns, s.quote_observed_ns, s.iv_observed_ns,
               s.greek_observed_ns) > chain.observed_ns for s in chain.series):
        hard.append("SNAPSHOT_OBSERVATION_INCONSISTENT")
    if tuple(sorted(chain.eligible_expiries)) != tuple(sorted(expected_expiries)):
        hard.append("EXPIRY_SET_MISMATCH")
    if chain.eligible_oi_denominator is None or chain.eligible_oi_denominator == ZERO:
        hard.append("UNKNOWN_OI_DENOMINATOR")
    if not chain.series:
        hard.append("MISSING_CHAIN")
    if chain.expected_series_count is None:
        degraded.append("UNKNOWN_SERIES_COUNT")
    elif len(chain.series) < chain.expected_series_count:
        degraded.append("INCOMPLETE_SERIES_COUNT")
    if not chain.chain_complete:
        degraded.append("INCOMPLETE_CHAIN")
    if any(not s.chain_complete for s in chain.series):
        degraded.append("INCOMPLETE_SERIES_CHAIN")
    if any(s.expected_series_count is not None
           and s.expected_series_count != chain.expected_series_count
           for s in chain.series):
        degraded.append("SERIES_COUNT_METADATA_MISMATCH")
    if policy.assumption is None or (policy.assumption.call_sign == 0
                                      and policy.assumption.put_sign == 0):
        hard.append("UNKNOWN_DEALER_SIGN")

    selected: list[OptionSeriesEvidenceV1] = []
    for s in chain.series:
        effective_cutoff = (min(s.expiry_cutoff_ns, chain.calendar.session_close_ns)
                            if s.expiry_date == chain.calendar.trade_date
                            else s.expiry_cutoff_ns)
        if s.expiry_date < chain.calendar.trade_date:
            hard.append("EXPIRY_BEFORE_TRADE_DATE")
            exclude(s, "EXPIRY_BEFORE_TRADE_DATE")
            continue
        if s.expiry_date not in expected_expiries or effective_cutoff <= clock:
            continue
        if s.halted:
            degraded.append("HALTED_SERIES")
            exclude(s, "HALTED_SERIES")
            continue
        if (type(s.multiplier_basis) is not str
                or s.multiplier_basis not in {"PRE_ACTION", "POST_ACTION_ADJUSTED"}):
            hard.append("ADJUSTMENT_BASIS_UNKNOWN")
            exclude(s, "ADJUSTMENT_BASIS_UNKNOWN")
            continue
        if not s.adjustment_version:
            hard.append("ADJUSTMENT_VERSION_MISSING")
            exclude(s, "ADJUSTMENT_VERSION_MISSING")
            continue
        if s.split_factor <= ZERO:
            hard.append("INVALID_SPLIT_FACTOR")
            exclude(s, "INVALID_SPLIT_FACTOR")
            continue
        if not s.deliverable_units:
            hard.append("DELIVERABLE_UNITS_MISSING")
            exclude(s, "DELIVERABLE_UNITS_MISSING")
            continue
        if any(leg.kind == "OTHER_ASSET" for leg in s.deliverable_units):
            degraded.append("NON_STANDARD_DELIVERABLE_OTHER_ASSET")
            exclude(s, "NON_STANDARD_DELIVERABLE_OTHER_ASSET")
            continue
        if any(leg.kind == "UNDERLIER" and leg.asset_id != chain.underlier
               for leg in s.deliverable_units):
            hard.append("DELIVERABLE_UNDERLIER_MISMATCH")
            exclude(s, "DELIVERABLE_UNDERLIER_MISMATCH")
            continue
        if any(leg.kind == "UNDERLIER" and leg.currency != s.currency
               for leg in s.deliverable_units):
            hard.append("DELIVERABLE_CURRENCY_MISMATCH")
            exclude(s, "DELIVERABLE_CURRENCY_MISMATCH")
            continue
        underlier_units = exact_sum(leg.units for leg in s.deliverable_units
                                    if leg.kind == "UNDERLIER")
        if underlier_units != adjusted_multiplier(s):
            hard.append("DELIVERABLE_MULTIPLIER_MISMATCH")
            exclude(s, "DELIVERABLE_MULTIPLIER_MISMATCH")
            continue
        if s.entitlement_status != "ENTITLED" or not s.entitlement_id:
            degraded.append("MISSING_GREEK_ENTITLEMENT")
            exclude(s, "MISSING_GREEK_ENTITLEMENT")
            continue
        if s.gamma_units != "PER_UNDERLYING_UNIT":
            degraded.append("UNTRUSTED_GREEK_UNITS")
            exclude(s, "UNTRUSTED_GREEK_UNITS")
            continue
        if (s.spot_available_ns > visibility_cutoff
                or s.iv_available_ns > visibility_cutoff
                or s.greek_available_ns > visibility_cutoff
                or s.quote_available_ns > visibility_cutoff):
            degraded.append("EVIDENCE_NOT_AVAILABLE")
            exclude(s, "EVIDENCE_NOT_AVAILABLE")
            continue
        if s.oi_asof_ns > clock:
            degraded.append("FUTURE_OI")
            exclude(s, "FUTURE_OI")
            continue
        selected.append(s)
    eligible = tuple(sorted(selected, key=lambda s: s.series_id))
    if not eligible:
        hard.append("NO_ELIGIBLE_ENTITLED_SERIES")
    if len({s.spot for s in eligible}) > 1:
        hard.append("SPOT_MISMATCH")
    if any(s.corporate_action_version != eligible[0].corporate_action_version for s in eligible):
        hard.append("CORPORATE_ACTION_VERSION_MISMATCH")

    spot_age = max((_age(clock, s.spot_observed_ns) for s in eligible), default=None)
    iv_age = max((_age(clock, s.iv_observed_ns) for s in eligible), default=None)
    oi_age = max((_age(clock, s.oi_asof_ns) for s in eligible), default=None)
    quote_age = max((_age(clock, s.quote_observed_ns) for s in eligible), default=None)
    greek_age = max((_age(clock, s.greek_observed_ns) for s in eligible), default=None)
    for name, age, limit in (("SPOT", spot_age, policy.max_spot_age_ns),
                             ("IV", iv_age, policy.max_iv_age_ns),
                             ("QUOTE", quote_age, policy.max_quote_age_ns),
                             ("GREEK", greek_age, policy.max_greek_age_ns),
                             ("OI", oi_age, policy.max_oi_age_ns)):
        if age is None or age > limit:
            stale.append(f"STALE_{name}")

    coverage = None
    coverage_exact = None
    if chain.eligible_oi_denominator is not None and chain.eligible_oi_denominator > ZERO:
        numerator = exact_sum(s.open_interest for s in eligible)
        exact_ratio = Fraction(numerator) / Fraction(chain.eligible_oi_denominator)
        coverage_exact = (exact_ratio.numerator, exact_ratio.denominator)
        coverage = numerator / chain.eligible_oi_denominator
        if exact_ratio > 1:
            hard.append("OI_DENOMINATOR_UNDERCOUNTS")
        elif exact_ratio < Fraction(policy.coverage_threshold):
            degraded.append("LOW_OI_COVERAGE")
    if hard or stale or degraded:
        reasons.extend(hard + stale + degraded)
        status = "UNAVAILABLE" if hard else "STALE" if stale else "DEGRADED"
        return _unavailable(chain, reasons, status, coverage, spot_age, iv_age, oi_age,
                            assumption_id, assumption_version, exclusions, coverage_exact)

    currencies = tuple(sorted({s.currency for s in eligible}))
    currency_exposures = tuple(
        CurrencyExposureV1(currency, exact_sum(observed_exposure(s, policy, s.spot)
                                               for s in eligible if s.currency == currency))
        for currency in currencies
    )
    if len(currencies) > 1:
        unavailable = _unavailable(chain, ["MIXED_CURRENCY"], "DEGRADED", coverage,
                                   spot_age, iv_age, oi_age, assumption_id,
                                   assumption_version, exclusions, coverage_exact)
        return cast(HorizonEstimateV1, _reissue_result(
            unavailable, currency_exposures=currency_exposures,
            gamma_units="PER_UNDERLYING_UNIT"))

    assert eligible and coverage is not None and spot_age is not None and iv_age is not None
    assert oi_age is not None and quote_age is not None and greek_age is not None
    spot = eligible[0].spot
    with localcontext(KERNEL_CONTEXT) as ctx:
        ctx.prec = 34
        ctx.rounding = ROUND_HALF_EVEN
        freshness = min(_freshness(spot_age, policy.max_spot_age_ns),
                        _freshness(iv_age, policy.max_iv_age_ns),
                        _freshness(quote_age, policy.max_quote_age_ns),
                        _freshness(greek_age, policy.max_greek_age_ns))
        dispersion = _dispersion(eligible)
        confidence = coverage * freshness * dispersion
        aggregate = exact_sum(observed_exposure(s, policy, spot) for s in eligible)
        sign_regime = ("POSITIVE_GAMMA" if aggregate > ZERO else
                       "NEGATIVE_GAMMA" if aggregate < ZERO else "NEUTRAL")
        position_signs = {1 if signed_contracts(s, policy) > ZERO else -1
                          for s in eligible if signed_contracts(s, policy) != ZERO
                          and s.gamma > ZERO}
        flip_reason: str | None
        if len(position_signs) <= 1:
            # Positive lognormal gamma cannot reverse the sign of a portfolio
            # whose nonzero positions all have the same sign. This also avoids
            # mistaking numerical underflow at extreme grid points for a root.
            flip, flip_reason = None, "FLIP_NOT_FOUND_IN_GRID"
        else:
            try:
                flip, flip_reason = flip_level(
                    policy.flip_spot_grid, policy.flip_tolerance, spot,
                    lambda price: exposure_at(eligible, policy, price, clock),
                )
            except (DecimalException, OverflowError, ValueError):
                flip, flip_reason = None, "FLIP_NUMERIC_UNAVAILABLE"
        regime = sign_regime if flip is not None else "NEUTRAL"
        regime_confidence = confidence if flip is not None else ZERO
        regime_reason = None if flip is not None else "FLIP_NULL_DB_RULE"
        same_day = tuple(s for s in eligible if s.expiry_date == chain.calendar.trade_date)
        has_0dte = bool(chain.calendar.trading_session and
                        chain.calendar.session_open_ns <= clock < chain.calendar.session_close_ns
                        and same_day)
        result = HorizonEstimateV1(
            data_state=chain.data_state, status="OK", reasons=(),
            snapshot_id=chain.snapshot_id, revision=chain.revision, observed_ns=chain.observed_ns,
            available_ns=chain.available_ns,
            source_ids=tuple(sorted({chain.source_id, *(s.source_id for s in eligible)})),
            calendar_id=chain.calendar.calendar_id, calendar_version=chain.calendar.version,
            expiry_set=tuple(sorted(chain.eligible_expiries)),
            active_expiry_set=tuple(sorted({s.expiry_date for s in eligible})),
            settlement_conventions=tuple(sorted({s.settlement for s in eligible})),
            assumption_id=assumption_id,
            assumption_version=assumption_version,
            multiplier_bases=tuple(sorted({s.multiplier_basis for s in eligible
                                          if s.multiplier_basis is not None})),
            adjustment_versions=tuple(sorted({s.adjustment_version for s in eligible
                                              if s.adjustment_version is not None})),
            gamma_units="PER_UNDERLYING_UNIT",
            excluded_series=(),
            sign_label="SCENARIO_ESTIMATE", aggregate_gamma=aggregate,
            currency_exposures=currency_exposures,
            gamma_sign_regime=sign_regime, gamma_sign_regime_label="MODEL_ESTIMATE",
            gamma_sign_confidence=confidence,
            gamma_sign_reason=None if aggregate != ZERO else "EXACT_ZERO_GAMMA",
            regime=regime, regime_label="MODEL_ESTIMATE",
            regime_confidence=regime_confidence, regime_reason=regime_reason,
            coverage_ratio=coverage, spot_age_ns=spot_age, iv_age_ns=iv_age,
            coverage_exact=coverage_exact,
            oi_age_ns=oi_age, confidence=confidence,
            confidence_method="COVERAGE_MIN_FRESHNESS_DISPERSION_V1",
            confidence_inputs=(("coverage", coverage), ("freshness", freshness),
                               ("quote_dispersion", dispersion)),
            flip=flip, flip_reason=flip_reason,
            call_wall=wall_levels(eligible, "CALL", policy.wall_method, spot),
            put_wall=wall_levels(eligible, "PUT", policy.wall_method, spot),
            max_pain_weekly=max_pain(eligible, "WEEKLY"),
            max_pain_monthly=max_pain(eligible, "MONTHLY"),
            has_0dte=has_0dte, magnet_levels=magnets(same_day, spot) if has_0dte else (),
            pin_probability=None, _issue_token=_RESULT_SENTINEL,
        )
        return result


def _evaluate_horizon(chain: ChainSnapshotV1, policy: GammaPolicyV1,
                      asof_ns: int) -> HorizonEstimateV1:
    try:
        return _evaluate_horizon_impl(chain, policy, asof_ns)
    except (PrecisionExceededError, Inexact):
        assumption = policy.assumption
        return _unavailable(
            chain, ["PRECISION_EXCEEDED"], "UNAVAILABLE", None, None, None, None,
            assumption.assumption_id if assumption else None,
            assumption.version if assumption else None, [],
        )
    except (DecimalException, OverflowError):
        assumption = policy.assumption
        return _unavailable(
            chain, ["NUMERIC_UNAVAILABLE"], "UNAVAILABLE", None, None, None, None,
            assumption.assumption_id if assumption else None,
            assumption.version if assumption else None, [],
        )


def _evaluate_impl(snapshot: GammaSnapshotV1, policy: GammaPolicyV1,
                   asof_ns: int) -> GammaEstimateV1:
    require_ns(asof_ns, "asof_ns")
    live = _evaluate_horizon(snapshot.live, policy, asof_ns) if snapshot.live else None
    settled = _evaluate_horizon(snapshot.settled, policy, asof_ns) if snapshot.settled else None
    chain = snapshot.live or snapshot.settled
    assert chain is not None
    estimate = GammaEstimateV1(
        underlier=chain.underlier, asof_ns=asof_ns, policy_id=policy.policy_id,
        policy_version=policy.version, calc_version=policy.calc_version,
        expiry_policy_version=policy.expiry_policy_version,
        notional_scaling=policy.notional_scaling,
        greek_reprice_model=policy.greek_reprice_model, wall_method=policy.wall_method,
        live=live, settled=settled, settled_missing=snapshot.settled is None,
        semantic_digest="", _issue_token=_RESULT_SENTINEL,
    )
    normalized_live = (replace(snapshot.live, series=tuple(sorted(snapshot.live.series,
                        key=lambda s: s.series_id)),
                        eligible_expiries=tuple(sorted(snapshot.live.eligible_expiries)))
                       if snapshot.live else None)
    normalized_settled = (replace(snapshot.settled, series=tuple(sorted(snapshot.settled.series,
                           key=lambda s: s.series_id)),
                           eligible_expiries=tuple(sorted(snapshot.settled.eligible_expiries)))
                          if snapshot.settled else None)
    normalized_policy = replace(
        policy, eligible_expiries=tuple(sorted(policy.eligible_expiries)),
        settled_eligible_expiries=(tuple(sorted(policy.settled_eligible_expiries))
                                   if policy.settled_eligible_expiries else None),
    )
    digest = semantic_digest((normalized_live, normalized_settled, normalized_policy, estimate))
    return cast(GammaEstimateV1, _reissue_result(estimate, semantic_digest=digest))


def evaluate(snapshot: GammaSnapshotV1, policy: GammaPolicyV1,
             asof_ns: int) -> GammaEstimateV1:
    """Evaluate independently timestamped live/settled evidence without side effects.

    All arithmetic uses 34 significant Decimal digits with ROUND_HALF_EVEN,
    independent of the process decimal context.
    """
    with localcontext(KERNEL_CONTEXT), _issue_results():
        return _evaluate_impl(snapshot, policy, asof_ns)
