"""Nearest historical feature states with matured, point-in-time outcomes."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from datetime import date
from decimal import ROUND_CEILING, ROUND_FLOOR, Decimal, localcontext
from fractions import Fraction
from functools import cmp_to_key
from math import isqrt
from typing import Literal

from leviathan_core.numeric import Ratio

from .read_model import (
    POLICY_VERSION,
    AnalyticsError,
    AnalyticsTileV1,
    CalendarPort,
    FrozenValue,
    PolicyV1,
    checked_decimal,
    checked_int,
    checked_text,
    decimal_context,
    frozen_map,
    require_policy,
    safe_sqrt,
)


@dataclass(frozen=True, slots=True)
class EchoPolicyV1(FrozenValue):
    policy_version: str
    k: int
    max_lookback_years: int
    horizons: tuple[int, ...]
    wilson_z: Decimal
    negligible_d: Decimal

    def __post_init__(self) -> None:
        if self.policy_version != POLICY_VERSION:
            raise AnalyticsError("UNSUPPORTED_POLICY")
        if (
            type(self.k) is not int
            or self.k != 20
            or type(self.max_lookback_years) is not int
            or self.max_lookback_years != 5
            or self.horizons != (5, 20, 60)
            or checked_decimal(self.wilson_z) != Decimal("1.96")
            or checked_decimal(self.negligible_d) != Decimal("0.2")
        ):
            raise AnalyticsError("POLICY_OUT_OF_BOUNDS")


@dataclass(frozen=True, slots=True)
class EchoSampleV1(FrozenValue):
    state_id: str
    instrument_id: str
    venue: str
    bar_index: int
    event_ns: int
    availability_ns: int
    finalized: bool
    feature_version: str
    regime_version: str
    regime: str
    features: Mapping[str, Decimal]
    close: Decimal
    source_version: str
    dataset_version: str
    revision: str
    quality: str

    def __post_init__(self) -> None:
        for name in (
            "state_id",
            "instrument_id",
            "venue",
            "feature_version",
            "regime_version",
            "regime",
            "source_version",
            "dataset_version",
            "revision",
            "quality",
        ):
            checked_text(getattr(self, name))
        for name in ("bar_index", "event_ns", "availability_ns"):
            checked_int(getattr(self, name))
        if type(self.finalized) is not bool:
            raise AnalyticsError("INVALID_BOOLEAN")
        if self.availability_ns < self.event_ns:
            raise AnalyticsError("INVALID_TIMESTAMP")
        object.__setattr__(self, "features", frozen_map(self.features))
        object.__setattr__(self, "close", checked_decimal(self.close, positive=True))


@dataclass(frozen=True, slots=True)
class EchoQueryV1(FrozenValue):
    state_id: str
    instrument_id: str
    venue: str
    bar_index: int
    event_ns: int
    asof_ns: int
    feature_version: str
    regime_version: str
    regime: str
    features: Mapping[str, Decimal]
    horizon: int
    calendar_version: str
    entitlement: str
    stale: bool
    availability_ns: int
    finalized: bool

    def __post_init__(self) -> None:
        for name in (
            "state_id",
            "instrument_id",
            "venue",
            "feature_version",
            "regime_version",
            "regime",
            "calendar_version",
            "entitlement",
        ):
            checked_text(getattr(self, name))
        for name in ("bar_index", "event_ns", "asof_ns", "horizon", "availability_ns"):
            checked_int(getattr(self, name))
        if self.horizon not in (5, 20, 60):
            raise AnalyticsError("UNSUPPORTED_HORIZON")
        if self.event_ns > self.asof_ns or self.availability_ns > self.asof_ns:
            raise AnalyticsError("FUTURE_DATA")
        if self.availability_ns < self.event_ns:
            raise AnalyticsError("INVALID_TIMESTAMP")
        if type(self.stale) is not bool:
            raise AnalyticsError("INVALID_BOOLEAN")
        if type(self.finalized) is not bool:
            raise AnalyticsError("INVALID_BOOLEAN")
        if not self.finalized:
            raise AnalyticsError("UNFINALIZED_QUERY")
        object.__setattr__(self, "features", frozen_map(self.features))


@dataclass(frozen=True, slots=True)
class EchoResultV1(FrozenValue):
    status: Literal["READY", "INSUFFICIENT_DATA"]
    query: EchoQueryV1
    policy_version: str
    neighbors: tuple[str, ...]
    distances: tuple[Decimal, ...]
    forward_returns: tuple[Decimal, ...]
    excluded_features: tuple[str, ...]
    positive_share: Decimal | None
    wilson_low: Decimal | None
    wilson_high: Decimal | None
    cohens_d: Decimal | None
    effect_label: Literal["NEGLIGIBLE", "NON_NEGLIGIBLE"] | None
    tile: AnalyticsTileV1

    def __post_init__(self) -> None:
        if not isinstance(self.query, EchoQueryV1) or not isinstance(self.tile, AnalyticsTileV1):
            raise AnalyticsError("INVALID_RESULT")
        if self.status not in ("READY", "INSUFFICIENT_DATA"):
            raise AnalyticsError("INVALID_RESULT")
        if self.tile.kind != "echoes" or self.tile.instrument_id != self.query.instrument_id:
            raise AnalyticsError("INVALID_RESULT")
        if self.policy_version != POLICY_VERSION or self.tile.policy_version != POLICY_VERSION:
            raise AnalyticsError("INVALID_RESULT")
        if any(
            type(getattr(self, name)) is not tuple
            for name in ("neighbors", "distances", "forward_returns", "excluded_features")
        ):
            raise AnalyticsError("INVALID_RESULT")
        if len(self.neighbors) != len(self.distances) or len(self.neighbors) != len(
            self.forward_returns
        ):
            raise AnalyticsError("INVALID_RESULT")
        for text_value in (*self.neighbors, *self.excluded_features):
            checked_text(text_value)
        for decimal_value in (*self.distances, *self.forward_returns):
            checked_decimal(decimal_value, input_bound=False)
        if any(distance < 0 for distance in self.distances):
            raise AnalyticsError("INVALID_RESULT")
        for name in ("positive_share", "wilson_low", "wilson_high", "cohens_d"):
            optional_value = getattr(self, name)
            if optional_value is not None:
                checked_decimal(optional_value, input_bound=False)
        metrics = (self.positive_share, self.wilson_low, self.wilson_high, self.cohens_d)
        if (
            self.positive_share is not None
            and self.wilson_low is not None
            and self.wilson_high is not None
            and not (
                Decimal(0)
                <= self.wilson_low
                <= self.positive_share
                <= self.wilson_high
                <= Decimal(1)
            )
        ):
            raise AnalyticsError("INVALID_RESULT")
        if self.status == "READY":
            if (
                len(self.neighbors) != 20
                or any(value is None for value in metrics)
                or self.effect_label not in ("NEGLIGIBLE", "NON_NEGLIGIBLE")
                or self.tile.missing_reason is not None
            ):
                raise AnalyticsError("INVALID_RESULT")
        elif (
            any(value is not None for value in metrics)
            or self.effect_label is not None
            or self.tile.missing_reason != "INSUFFICIENT_DATA"
        ):
            raise AnalyticsError("INVALID_RESULT")


def _wilson(positive: int, count: int, z: Decimal) -> tuple[Decimal, Decimal, Decimal]:
    with localcontext(decimal_context()):
        n = Decimal(count)
        p = Decimal(positive) / n
        z2 = z * z
        denominator = 1 + z2 / n
        center = (p + z2 / (2 * n)) / denominator
        spread = z * safe_sqrt(p * (1 - p) / n + z2 / (4 * n * n)) / denominator
        return p, max(Decimal(0), center - spread), min(Decimal(1), center + spread)


def _pooled_d(
    chosen: list[Decimal], baseline: list[Decimal], threshold: Decimal
) -> tuple[Decimal | None, bool | None]:
    if len(chosen) < 2 or len(baseline) < 2:
        return None, None
    first = [Fraction(value) for value in chosen]
    second = [Fraction(value) for value in baseline]
    n1, n2 = len(first), len(second)
    mean1 = sum(first, Fraction(0)) / n1
    mean2 = sum(second, Fraction(0)) / n2
    var1 = sum(((value - mean1) ** 2 for value in first), Fraction(0)) / (n1 - 1)
    var2 = sum(((value - mean2) ** 2 for value in second), Fraction(0)) / (n2 - 1)
    pooled = ((n1 - 1) * var1 + (n2 - 1) * var2) / (n1 + n2 - 2)
    if pooled == 0:
        return None, None
    difference = mean1 - mean2
    squared_difference = difference * difference
    threshold_variance = pooled * Fraction(threshold) ** 2
    negligible = Ratio(squared_difference.numerator, squared_difference.denominator).lt(
        Ratio(threshold_variance.numerator, threshold_variance.denominator)
    )
    squared_effect = squared_difference / pooled
    magnitude = _sqrt_ratio_final(Ratio(squared_effect.numerator, squared_effect.denominator))
    return magnitude.copy_negate() if difference < 0 else magnitude, negligible


def _sqrt_ratio_final(value: Ratio) -> Decimal:
    """Round a nonnegative exact square root once to 34 significant digits."""
    numerator, denominator = value.numerator, value.denominator
    if numerator < 0:
        raise AnalyticsError("INVALID_ARITHMETIC")
    if numerator == 0:
        return Decimal(0)

    magnitude = len(str(numerator)) - len(str(denominator))
    if magnitude >= 0:
        below_power = numerator < denominator * 10**magnitude
    else:
        below_power = numerator * 10 ** (-magnitude) < denominator
    adjusted = magnitude - int(below_power)
    decimal_places = 33 - adjusted // 2
    if decimal_places >= 0:
        scaled_numerator = numerator * 10 ** (2 * decimal_places)
        scaled_denominator = denominator
    else:
        scaled_numerator = numerator
        scaled_denominator = denominator * 10 ** (-2 * decimal_places)

    whole = isqrt(scaled_numerator // scaled_denominator)
    midpoint_left = 4 * scaled_numerator
    midpoint_right = scaled_denominator * (2 * whole + 1) ** 2
    if midpoint_left > midpoint_right or (midpoint_left == midpoint_right and whole % 2):
        whole += 1
    digits = tuple(int(digit) for digit in str(whole))
    return checked_decimal(Decimal((0, digits, -decimal_places)), input_bound=False)


def _session_date(value: object) -> date:
    parsed: date | None = None
    with suppress(TypeError, ValueError):
        parsed = date.fromisoformat(value)  # type: ignore[arg-type]
    if parsed is None:
        raise AnalyticsError("INVALID_CALENDAR")
    return parsed


def _calendar_session(calendar: CalendarPort, event_ns: int) -> str | None:
    result: str | None = None
    failed = False
    try:
        result = calendar.session_for_ns(event_ns)
    except Exception:
        failed = True
    if failed:
        raise AnalyticsError("INVALID_CALENDAR")
    return result


def _revision_number(value: str) -> int | None:
    """Accept legacy rN/revN labels, but never lexically order them."""
    match = re.fullmatch(r"(?:r|rev)?([0-9]+)", value)
    if match is None:
        return None
    number: int | None = None
    with suppress(ValueError):
        number = int(match.group(1))
    return number


def _log_ratio(value: Ratio) -> tuple[Decimal, Decimal]:
    """Certify one final 34-digit rounding from directed ratio bounds."""
    if value.numerator <= 0:
        raise AnalyticsError("INVALID_ARITHMETIC")
    if value.eq(1):
        return Decimal(0), Decimal(0)
    for precision in (100, 200, 400, 800):
        context = decimal_context()
        context.prec = precision
        context.rounding = ROUND_FLOOR
        with localcontext(context):
            ratio_low = Decimal(value.numerator) / Decimal(value.denominator)
        context.rounding = ROUND_CEILING
        with localcontext(context):
            ratio_high = Decimal(value.numerator) / Decimal(value.denominator)
        context.rounding = decimal_context().rounding
        with localcontext(context) as work:
            log_low = work.ln(ratio_low)
            log_high = work.ln(ratio_high)
            # ln is correctly rounded at work precision; one adjacent value
            # on either side encloses its exact value at each ratio bound.
            lower = log_low.next_minus(context=work)
            upper = log_high.next_plus(context=work)
            precise = work.ln(Decimal(value.numerator) / Decimal(value.denominator))
        with localcontext(decimal_context()):
            rounded_low = +lower
            rounded_high = +upper
        if rounded_low == rounded_high:
            return precise, rounded_low
    raise AnalyticsError("INDETERMINATE_ARITHMETIC")


def _lookback_date(query_date: date, years: int) -> date:
    start: date | None = None
    try:
        start = query_date.replace(year=query_date.year - years)
    except ValueError:
        with suppress(ValueError):
            start = query_date.replace(year=query_date.year - years, day=28)
    if start is None:
        raise AnalyticsError("INVALID_CALENDAR")
    return start


def _rank_order(
    left: tuple[Decimal, EchoSampleV1, Decimal, Ratio, bool, Decimal, EchoSampleV1],
    right: tuple[Decimal, EchoSampleV1, Decimal, Ratio, bool, Decimal, EchoSampleV1],
) -> int:
    """Order by the exact squared distance before the documented tie breaks."""
    if left[3].lt(right[3]):
        return -1
    if left[3].gt(right[3]):
        return 1
    left_tie = (left[1].event_ns, left[1].state_id)
    right_tie = (right[1].event_ns, right[1].state_id)
    return (left_tie > right_tie) - (left_tie < right_tie)


def evaluate_echoes(
    query: EchoQueryV1,
    samples: Iterable[EchoSampleV1],
    policy: PolicyV1,
    calendar: CalendarPort,
) -> EchoResultV1:
    """Calculate one advisory estimate from finalized, mature historical states."""
    domain = require_policy(policy, "echoes", EchoPolicyV1)
    assert isinstance(domain, EchoPolicyV1)
    if not isinstance(query, EchoQueryV1):
        raise AnalyticsError("INVALID_QUERY")
    session = _calendar_session(calendar, query.event_ns)
    if session is None:
        raise AnalyticsError("UNKNOWN_SESSION")
    query_date = _session_date(session)
    lookback_start = _lookback_date(query_date, domain.max_lookback_years)
    visible: dict[int, EchoSampleV1] = {}
    for sample in samples:
        if not isinstance(sample, EchoSampleV1):
            raise AnalyticsError("INVALID_SAMPLE")
        if (
            not sample.finalized
            or sample.event_ns > query.asof_ns
            or sample.availability_ns > query.asof_ns
            or sample.instrument_id != query.instrument_id
            or sample.venue != query.venue
            or sample.feature_version != query.feature_version
        ):
            continue
        prior = visible.get(sample.bar_index)
        if prior is None or sample.availability_ns > prior.availability_ns:
            visible[sample.bar_index] = sample
        elif sample.availability_ns == prior.availability_ns:
            current_revision = _revision_number(sample.revision)
            prior_revision = _revision_number(prior.revision)
            if current_revision is None or prior_revision is None:
                if sample != prior:
                    raise AnalyticsError("HISTORY_CONFLICT")
            elif current_revision > prior_revision:
                visible[sample.bar_index] = sample
            elif current_revision == prior_revision and sample != prior:
                raise AnalyticsError("HISTORY_CONFLICT")
    history: list[EchoSampleV1] = []
    for sample in visible.values():
        sample_session = _calendar_session(calendar, sample.event_ns)
        if sample_session is None:
            continue
        sample_date = _session_date(sample_session)
        if (
            lookback_start <= sample_date <= query_date
            and sample.bar_index < query.bar_index
            and sample.event_ns < query.event_ns
        ):
            history.append(sample)
    contributors: dict[int, EchoSampleV1] = {sample.bar_index: sample for sample in history}
    roles: dict[int, set[str]] = {sample.bar_index: {"STANDARDIZATION"} for sample in history}
    baseline_pairs: list[tuple[EchoSampleV1, EchoSampleV1]] = []
    chosen_endpoints: dict[int, EchoSampleV1] = {}
    feature_names = set(query.features)
    for sample in history:
        feature_names.intersection_update(sample.features)
    excluded: list[str] = []
    scales: dict[str, Fraction] = {}
    with localcontext(decimal_context()):
        for name in sorted(query.features):
            if name not in feature_names or len(history) < 2:
                excluded.append(name)
                continue
            values = [Fraction(sample.features[name]) for sample in history]
            mean = sum(values, Fraction(0)) / len(values)
            variance = sum(((value - mean) ** 2 for value in values), Fraction(0)) / (
                len(values) - 1
            )
            if variance == 0:
                excluded.append(name)
            else:
                scales[name] = variance
        ranked: list[tuple[Decimal, EchoSampleV1, Decimal, Ratio, bool, Decimal, EchoSampleV1]] = []
        baseline: list[Decimal] = []
        for sample in history:
            if sample.bar_index + query.horizon > query.bar_index:
                continue
            end = visible.get(sample.bar_index + query.horizon)
            if (
                end is None
                or end.event_ns <= sample.event_ns
                or end.event_ns > query.event_ns
                or end.availability_ns > query.asof_ns
            ):
                continue
            forward_ratio = Ratio.from_decimals(end.close, sample.close)
            precise_outcome, outcome = _log_ratio(forward_ratio)
            baseline.append(precise_outcome)
            baseline_pairs.append((sample, end))
            contributors[end.bar_index] = end
            roles[sample.bar_index].add("BASELINE_START")
            roles.setdefault(end.bar_index, set()).add("BASELINE_ENDPOINT")
            if sample.regime_version != query.regime_version or sample.regime != query.regime:
                continue
            exact_distance_squared = sum(
                (
                    (Fraction(sample.features[name]) - Fraction(query.features[name])) ** 2
                    / variance
                    for name, variance in scales.items()
                ),
                Fraction(0),
            )
            exact_ratio = Ratio(
                exact_distance_squared.numerator, exact_distance_squared.denominator
            )
            distance = _sqrt_ratio_final(exact_ratio)
            ranked.append(
                (
                    distance,
                    sample,
                    outcome,
                    exact_ratio,
                    forward_ratio.gt(1),
                    precise_outcome,
                    end,
                )
            )
        ranked.sort(key=cmp_to_key(_rank_order))
        chosen = ranked[: domain.k]
        for item in chosen:
            roles[item[1].bar_index].add("NEIGHBOR_START")
            roles[item[6].bar_index].add("NEIGHBOR_ENDPOINT")
            chosen_endpoints[item[1].bar_index] = item[6]
        outcomes = [item[2] for item in chosen]
        d, negligible = (
            _pooled_d([item[5] for item in chosen], baseline, domain.negligible_d)
            if len(chosen) == domain.k and scales
            else (None, None)
        )
        ready = len(chosen) == domain.k and bool(scales) and d is not None
        share, low, high = (
            _wilson(sum(item[4] for item in chosen), len(outcomes), domain.wilson_z)
            if ready
            else (None, None, None)
        )
    contributing_records = [contributors[key] for key in sorted(contributors)]
    source_versions = sorted({item.source_version for item in contributing_records})
    dataset_versions = sorted({item.dataset_version for item in contributing_records})
    tile = AnalyticsTileV1(
        kind="echoes",
        instrument_id=query.instrument_id,
        venue=query.venue,
        session=session,
        event_ns=str(query.event_ns),
        asof_ns=str(query.asof_ns),
        availability_ns=str(
            max([query.availability_ns, *(item.availability_ns for item in contributing_records)])
        ),
        source_version=(source_versions[0] if len(source_versions) == 1 else "MIXED")
        if source_versions
        else "unavailable",
        dataset_version=(dataset_versions[0] if len(dataset_versions) == 1 else "MIXED")
        if dataset_versions
        else "unavailable",
        method_version="echoes-v1",
        parameter_version=policy.policy_version,
        calendar_version=query.calendar_version,
        policy_version=policy.policy_version,
        entitlement=query.entitlement,
        quality="READY" if ready else "INSUFFICIENT_DATA",
        lag_ns=str(query.asof_ns - query.event_ns),
        stale=query.stale,
        missing_reason=None if ready else "INSUFFICIENT_DATA",
        units="log_return",
        sample_count=len(chosen),
        confidence=share,
        payload={
            "horizon_bars": query.horizon,
            "neighbors": [item[1].state_id for item in chosen],
            "source_revisions": [item[1].revision for item in chosen],
            "contributing_revisions": [item.revision for item in contributing_records],
            "contributing_provenance": [
                {
                    "state_id": item.state_id,
                    "bar_index": item.bar_index,
                    "event_ns": str(item.event_ns),
                    "availability_ns": str(item.availability_ns),
                    "feature_version": item.feature_version,
                    "source_version": item.source_version,
                    "dataset_version": item.dataset_version,
                    "revision": item.revision,
                    "roles": sorted(roles[item.bar_index]),
                }
                for item in contributing_records
            ],
            "baseline_provenance": [
                {"start_state_id": start.state_id, "end_state_id": end.state_id}
                for start, end in baseline_pairs
            ],
            "neighbor_provenance": [
                {
                    "state_id": item[1].state_id,
                    "event_ns": str(item[1].event_ns),
                    "availability_ns": str(item[1].availability_ns),
                    "source_version": item[1].source_version,
                    "dataset_version": item[1].dataset_version,
                    "revision": item[1].revision,
                    "outcome_state_id": chosen_endpoints[item[1].bar_index].state_id,
                    "outcome_availability_ns": str(
                        chosen_endpoints[item[1].bar_index].availability_ns
                    ),
                    "outcome_source_version": chosen_endpoints[item[1].bar_index].source_version,
                    "outcome_dataset_version": chosen_endpoints[item[1].bar_index].dataset_version,
                    "outcome_revision": chosen_endpoints[item[1].bar_index].revision,
                }
                for item in chosen
            ],
            "forward_returns": outcomes,
            "positive_share": share,
            "confidence_semantics": "POSITIVE_SHARE",
            "wilson_low": low,
            "wilson_high": high,
            "cohens_d": d,
            "effect_label": ("NEGLIGIBLE" if negligible else "NON_NEGLIGIBLE")
            if negligible is not None
            else None,
            "excluded_features": excluded,
            "standardization_sd": "SAMPLE_N_MINUS_1",
            "standardization_sample_count": len(history),
            "unconditional_sample_count": len(baseline),
            "unconditional_regime_scope": "ALL_REGIMES",
            "lookback_start_session": lookback_start.isoformat(),
            "regime": query.regime,
        },
    )
    return EchoResultV1(
        status="READY" if ready else "INSUFFICIENT_DATA",
        query=query,
        policy_version=policy.policy_version,
        neighbors=tuple(item[1].state_id for item in chosen),
        distances=tuple(item[0] for item in chosen),
        forward_returns=tuple(outcomes),
        excluded_features=tuple(excluded),
        positive_share=share,
        wilson_low=low,
        wilson_high=high,
        cohens_d=d,
        effect_label=("NEGLIGIBLE" if negligible else "NON_NEGLIGIBLE")
        if negligible is not None
        else None,
        tile=tile,
    )
