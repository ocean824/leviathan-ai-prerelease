"""Offline per-asset session-hour movement and realized-volatility heatmap."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from decimal import Decimal, localcontext
from fractions import Fraction
from itertools import pairwise
from typing import Literal

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
    require_policy,
    safe_ln,
    safe_sqrt,
)

MINUTE_NS = 60_000_000_000


@dataclass(frozen=True, slots=True)
class MarketClockPolicyV1(FrozenValue):
    policy_version: str
    lookback_sessions: int
    minimum_sessions: int
    lower_percentile: Decimal
    upper_percentile: Decimal
    minimum_subbars: int
    bar_interval_ns: int
    volatility_estimator: str
    movement_estimator: str
    annualized: bool
    strict_alert: bool

    def __post_init__(self) -> None:
        if self.policy_version != POLICY_VERSION:
            raise AnalyticsError("UNSUPPORTED_POLICY")
        fixed_ints = {
            "lookback_sessions": 60,
            "minimum_sessions": 40,
            "minimum_subbars": 30,
            "bar_interval_ns": MINUTE_NS,
        }
        if any(
            type(getattr(self, field)) is not int or getattr(self, field) != value
            for field, value in fixed_ints.items()
        ):
            raise AnalyticsError("POLICY_OUT_OF_BOUNDS")
        if (
            checked_decimal(self.lower_percentile) != Decimal("0.2")
            or checked_decimal(self.upper_percentile) != Decimal("0.8")
            or self.volatility_estimator != "SAMPLE_SD_1M_CLOSE_LOG_RETURN"
            or self.movement_estimator != "ABS_HOURLY_OPEN_CLOSE_LOG_RETURN"
            or type(self.annualized) is not bool
            or self.annualized
            or type(self.strict_alert) is not bool
            or not self.strict_alert
        ):
            raise AnalyticsError("POLICY_OUT_OF_BOUNDS")


@dataclass(frozen=True, slots=True)
class MarketClockBarV1(FrozenValue):
    bar_id: str
    instrument_id: str
    venue: str
    interval_start_ns: int
    interval_end_ns: int
    availability_ns: int
    finalized: bool
    session: str
    calendar_version: str
    timezone: str
    source_version: str
    adjustment_version: str
    dataset_version: str
    quality: str
    open: Decimal
    close: Decimal
    high: Decimal
    low: Decimal

    def __post_init__(self) -> None:
        for name in (
            "bar_id",
            "instrument_id",
            "venue",
            "session",
            "calendar_version",
            "timezone",
            "source_version",
            "adjustment_version",
            "dataset_version",
            "quality",
        ):
            checked_text(getattr(self, name))
        for name in ("interval_start_ns", "interval_end_ns", "availability_ns"):
            checked_int(getattr(self, name))
        if self.interval_end_ns - self.interval_start_ns != MINUTE_NS:
            raise AnalyticsError("INVALID_INTERVAL")
        if self.availability_ns < self.interval_end_ns:
            raise AnalyticsError("INVALID_TIMESTAMP")
        if type(self.finalized) is not bool:
            raise AnalyticsError("INVALID_BOOLEAN")
        object.__setattr__(self, "open", checked_decimal(self.open, positive=True))
        object.__setattr__(self, "close", checked_decimal(self.close, positive=True))
        object.__setattr__(self, "high", checked_decimal(self.high, positive=True))
        object.__setattr__(self, "low", checked_decimal(self.low, positive=True))
        if self.high < max(self.open, self.close) or self.low > min(self.open, self.close):
            raise AnalyticsError("INVALID_BAR")


@dataclass(frozen=True, slots=True)
class MarketClockBucketV1(FrozenValue):
    instrument_id: str
    venue: str
    session_hour: str
    utc_offset_minutes: int
    calendar_version: str
    timezone: str
    status: Literal["READY", "INSUFFICIENT_DATA"]
    session_count: int
    missing_session_count: int
    missing_subbar_count: int
    mean_abs_return: Decimal | None
    mean_realized_volatility: Decimal | None
    move_p20: Decimal | None
    move_p80: Decimal | None
    volatility_p20: Decimal | None
    volatility_p80: Decimal | None
    alert_candidate: bool
    alert_reason: Literal["INSUFFICIENT_DATA", "ALERT_INDETERMINATE"] | None
    alert_hour_start_ns: int | None
    alert_move: Decimal | None
    source_ids: tuple[str, ...]
    policy_version: str
    tile: AnalyticsTileV1

    def __post_init__(self) -> None:
        if not isinstance(self.tile, AnalyticsTileV1):
            raise AnalyticsError("INVALID_RESULT")
        for name in ("instrument_id", "venue", "session_hour", "calendar_version", "timezone"):
            checked_text(getattr(self, name))
        if type(self.utc_offset_minutes) is not int or abs(self.utc_offset_minutes) > 840:
            raise AnalyticsError("INVALID_RESULT")
        if (
            self.status not in ("READY", "INSUFFICIENT_DATA")
            or self.policy_version != POLICY_VERSION
        ):
            raise AnalyticsError("INVALID_RESULT")
        if self.tile.kind != "market_clock" or self.tile.instrument_id != self.instrument_id:
            raise AnalyticsError("INVALID_RESULT")
        checked_int(self.session_count)
        checked_int(self.missing_session_count)
        checked_int(self.missing_subbar_count)
        if type(self.source_ids) is not tuple:
            raise AnalyticsError("INVALID_RESULT")
        for source_id in self.source_ids:
            checked_text(source_id)
        if type(self.alert_candidate) is not bool:
            raise AnalyticsError("INVALID_BOOLEAN")
        if self.alert_reason not in (None, "INSUFFICIENT_DATA", "ALERT_INDETERMINATE"):
            raise AnalyticsError("INVALID_RESULT")
        if self.alert_candidate and self.alert_reason is not None:
            raise AnalyticsError("INVALID_RESULT")
        for field in (
            "mean_abs_return",
            "mean_realized_volatility",
            "move_p20",
            "move_p80",
            "volatility_p20",
            "volatility_p80",
            "alert_move",
        ):
            value = getattr(self, field)
            if value is not None:
                checked_decimal(value, nonnegative=True)
        if self.alert_hour_start_ns is not None:
            checked_int(self.alert_hour_start_ns)
        measures = (
            self.mean_abs_return,
            self.mean_realized_volatility,
            self.move_p20,
            self.move_p80,
            self.volatility_p20,
            self.volatility_p80,
        )
        if self.status == "READY" and any(value is None for value in measures):
            raise AnalyticsError("INVALID_RESULT")
        if self.status == "READY" and self.tile.sample_count != self.session_count:
            raise AnalyticsError("INVALID_RESULT")
        if self.status == "INSUFFICIENT_DATA" and (
            any(value is not None for value in measures) or self.alert_candidate
        ):
            raise AnalyticsError("INVALID_RESULT")
        if self.alert_candidate and (
            self.alert_hour_start_ns is None or self.alert_move is None or self.move_p80 is None
        ):
            raise AnalyticsError("INVALID_RESULT")
        if (
            self.move_p20 is not None
            and self.move_p80 is not None
            and self.move_p20 > self.move_p80
        ):
            raise AnalyticsError("INVALID_RESULT")
        if (
            self.volatility_p20 is not None
            and self.volatility_p80 is not None
            and self.volatility_p20 > self.volatility_p80
        ):
            raise AnalyticsError("INVALID_RESULT")


@dataclass(frozen=True, slots=True)
class _Hour(FrozenValue):
    session: str
    label: str
    hour_start_ns: int
    offset: int
    bars: tuple[MarketClockBarV1, ...]
    missing_subbars: int
    finalized: bool
    movement: Decimal | None
    movement_ratio: Fraction | None
    volatility: Decimal | None


def _percentile_exact(values: list[Decimal], p: Decimal) -> Fraction:
    ordered = sorted(Fraction(value) for value in values)
    position = Fraction(len(ordered) - 1) * Fraction(p)
    lower = position.numerator // position.denominator
    fraction = position - lower
    if fraction == 0:
        return ordered[lower]
    return ordered[lower] + (ordered[lower + 1] - ordered[lower]) * fraction


def _fraction_decimal(value: Fraction) -> Decimal:
    with localcontext(decimal_context()):
        return Decimal(value.numerator) / Decimal(value.denominator)


def _ln_ratio_60(ratio: Fraction) -> Decimal:
    context = decimal_context()
    context.prec = 60
    with localcontext(context):
        return context.ln(Decimal(ratio.numerator)) - context.ln(Decimal(ratio.denominator))


def _alert_decision(
    current_ratio: Fraction, historical_ratios: list[Fraction], percentile: Decimal
) -> tuple[bool, Literal["ALERT_INDETERMINATE"] | None]:
    ordered = sorted(historical_ratios)
    position = Fraction(len(ordered) - 1) * Fraction(percentile)
    lower = position.numerator // position.denominator
    weight = position - lower
    lower_ratio = ordered[lower]
    upper_ratio = ordered[lower + 1] if weight else lower_ratio
    if weight == 0 or lower_ratio == upper_ratio:
        return current_ratio > lower_ratio, None
    lower_log = Fraction(_ln_ratio_60(lower_ratio))
    upper_log = Fraction(_ln_ratio_60(upper_ratio))
    threshold = lower_log + weight * (upper_log - lower_log)
    difference = Fraction(_ln_ratio_60(current_ratio)) - threshold
    # With bounded input prices, the two integer logarithms and their difference
    # have < 1E-55 absolute error at precision 60. Interpolation preserves that
    # bound, so 2E-55 certifies the sign of current minus threshold.
    margin = Fraction(Decimal("2E-55"))
    if difference > margin:
        return True, None
    if difference < -margin:
        return False, None
    return False, "ALERT_INDETERMINATE"


def _hour_value(
    session: str,
    label: str,
    hour_start_ns: int,
    offset: int,
    bars: list[MarketClockBarV1],
    minimum_subbars: int,
    hour_end_ns: int,
    asof_ns: int,
) -> _Hour:
    ordered = sorted(bars, key=lambda bar: bar.interval_start_ns)
    if (
        type(hour_end_ns) is not int
        or hour_end_ns <= hour_start_ns
        or hour_end_ns - hour_start_ns > 60 * MINUTE_NS
        or (hour_end_ns - hour_start_ns) % MINUTE_NS
    ):
        raise AnalyticsError("INVALID_CALENDAR")
    expected = set(range(hour_start_ns, hour_end_ns, MINUTE_NS))
    actual = [bar.interval_start_ns for bar in ordered]
    if len(set(actual)) != len(actual):
        raise AnalyticsError("HISTORY_CONFLICT")
    if any(start not in expected for start in actual):
        raise AnalyticsError("INVALID_INTERVAL")
    invalid_quality = sum(bar.quality not in ("OK", "GOOD", "VALID") for bar in ordered)
    missing = len(expected.difference(actual)) + invalid_quality
    finalized = asof_ns >= hour_end_ns and missing == 0
    if not finalized or len(ordered) < minimum_subbars:
        return _Hour(
            session,
            label,
            hour_start_ns,
            offset,
            tuple(ordered),
            missing,
            finalized,
            None,
            None,
            None,
        )
    returns: list[Decimal] = []
    with localcontext(decimal_context()):
        for previous, current in pairwise(ordered):
            if current.interval_start_ns == previous.interval_end_ns:
                returns.append(safe_ln(current.close / previous.close))
        if len(returns) < minimum_subbars - 1:
            return _Hour(
                session,
                label,
                hour_start_ns,
                offset,
                tuple(ordered),
                missing,
                False,
                None,
                None,
                None,
            )
        exact_returns = [Fraction(value) for value in returns]
        mean = sum(exact_returns, Fraction(0)) / len(exact_returns)
        variance = sum(((value - mean) ** 2 for value in exact_returns), Fraction(0)) / (
            len(exact_returns) - 1
        )
        volatility = safe_sqrt(_fraction_decimal(variance))
        movement = abs(safe_ln(ordered[-1].close / ordered[0].open))
        raw_ratio = Fraction(ordered[-1].close) / Fraction(ordered[0].open)
        movement_ratio = max(raw_ratio, 1 / raw_ratio)
    return _Hour(
        session,
        label,
        hour_start_ns,
        offset,
        tuple(ordered),
        missing,
        True,
        movement,
        movement_ratio,
        volatility,
    )


def aggregate_clock(
    bars: Iterable[MarketClockBarV1],
    asof_ns: int,
    policy: PolicyV1,
    calendar: CalendarPort,
    current_hour_start_ns: int | None = None,
) -> tuple[MarketClockBucketV1, ...]:
    """Build available hourly cells and advisory strict-greater-than alerts."""
    domain = require_policy(policy, "market_clock", MarketClockPolicyV1)
    assert isinstance(domain, MarketClockPolicyV1)
    checked_int(asof_ns)
    if current_hour_start_ns is not None:
        checked_int(current_hour_start_ns)
    current_session = calendar.session_for_ns(asof_ns)
    trailing = calendar.trailing_sessions(asof_ns, domain.lookback_sessions + 1)
    if not isinstance(trailing, tuple) or any(not isinstance(s, str) for s in trailing):
        raise AnalyticsError("INVALID_CALENDAR")
    historical_sessions = tuple(s for s in trailing if s != current_session)[
        -domain.lookback_sessions :
    ]
    if len(set(historical_sessions)) != len(historical_sessions):
        raise AnalyticsError("INVALID_CALENDAR")
    grouped: dict[tuple[str, str, str, str, str, str, int], list[MarketClockBarV1]] = defaultdict(
        list
    )
    scopes: set[tuple[str, str, str, str]] = set()
    for bar in bars:
        if not isinstance(bar, MarketClockBarV1):
            raise AnalyticsError("INVALID_BAR")
        scopes.add((bar.instrument_id, bar.venue, bar.calendar_version, bar.timezone))
        if not bar.finalized or bar.interval_end_ns > asof_ns or bar.availability_ns > asof_ns:
            continue
        calendar_hour = calendar.hour_for_ns(bar.interval_start_ns)
        if calendar_hour is None:
            continue
        session, label, hour_start, offset = calendar_hour
        if session != bar.session:
            raise AnalyticsError("CALENDAR_MISMATCH")
        if session not in historical_sessions and session != current_session:
            continue
        if (
            type(hour_start) is not int
            or type(offset) is not int
            or hour_start > bar.interval_start_ns
            or not isinstance(label, str)
        ):
            raise AnalyticsError("INVALID_CALENDAR")
        key = (
            bar.instrument_id,
            bar.venue,
            bar.calendar_version,
            bar.timezone,
            session,
            label,
            hour_start,
        )
        grouped[key].append(bar)
    by_cell: dict[tuple[str, str, str, str, str, int], list[_Hour]] = defaultdict(list)
    for key, group in grouped.items():
        instrument, venue, calendar_version, timezone, session, label, hour_start = key
        calendar_key = calendar.hour_for_ns(hour_start)
        if calendar_key is None or calendar_key[0] != session or calendar_key[1] != label:
            raise AnalyticsError("INVALID_CALENDAR")
        hour = _hour_value(
            session,
            label,
            hour_start,
            calendar_key[3],
            group,
            domain.minimum_subbars,
            calendar.hour_end_ns(hour_start),
            asof_ns,
        )
        by_cell[(instrument, venue, calendar_version, timezone, label, calendar_key[3])].append(
            hour
        )
    output: list[MarketClockBucketV1] = []
    for scope in sorted(scopes):
        instrument, venue, calendar_version, timezone = scope
        cells = sorted(key for key in by_cell if key[:4] == scope)
        for cell in cells:
            _, _, _, _, label, offset = cell
            grouped_hours = by_cell[cell]
            valid = [
                hour
                for hour in grouped_hours
                if hour.session in historical_sessions
                and hour.finalized
                and hour.movement is not None
                and hour.movement_ratio is not None
                and hour.volatility is not None
            ]
            current = next(
                (
                    hour
                    for hour in grouped_hours
                    if hour.hour_start_ns == current_hour_start_ns
                    and hour.session == current_session
                ),
                None,
            )
            ready = len(valid) >= domain.minimum_sessions
            moves = [hour.movement for hour in valid if hour.movement is not None]
            vols = [hour.volatility for hour in valid if hour.volatility is not None]
            with localcontext(decimal_context()):
                mean_move = (
                    _fraction_decimal(
                        sum((Fraction(value) for value in moves), Fraction(0)) / len(moves)
                    )
                    if ready
                    else None
                )
                mean_vol = (
                    _fraction_decimal(
                        sum((Fraction(value) for value in vols), Fraction(0)) / len(vols)
                    )
                    if ready
                    else None
                )
                move_p20 = (
                    _fraction_decimal(_percentile_exact(moves, domain.lower_percentile))
                    if ready
                    else None
                )
                exact_move_p80 = (
                    _percentile_exact(moves, domain.upper_percentile) if ready else None
                )
                move_p80 = _fraction_decimal(exact_move_p80) if exact_move_p80 is not None else None
                vol_p20 = (
                    _fraction_decimal(_percentile_exact(vols, domain.lower_percentile))
                    if ready
                    else None
                )
                vol_p80 = (
                    _fraction_decimal(_percentile_exact(vols, domain.upper_percentile))
                    if ready
                    else None
                )
            alert = False
            alert_reason: Literal["INSUFFICIENT_DATA", "ALERT_INDETERMINATE"] | None = None
            if current_hour_start_ns is not None:
                if (
                    not ready
                    or current is None
                    or not current.finalized
                    or current.movement_ratio is None
                ):
                    alert_reason = "INSUFFICIENT_DATA"
                else:
                    historical_ratios = [
                        hour.movement_ratio for hour in valid if hour.movement_ratio is not None
                    ]
                    alert, alert_reason = _alert_decision(
                        current.movement_ratio,
                        historical_ratios,
                        domain.upper_percentile,
                    )
            source_ids = tuple(bar.bar_id for hour in valid for bar in hour.bars)
            if current is not None:
                source_ids += tuple(bar.bar_id for bar in current.bars)
            latest = max(
                (bar for hour in grouped_hours for bar in hour.bars),
                key=lambda bar: bar.interval_end_ns,
            )
            source_versions = tuple(
                sorted({bar.source_version for hour in grouped_hours for bar in hour.bars})
            )
            dataset_versions = tuple(
                sorted({bar.dataset_version for hour in grouped_hours for bar in hour.bars})
            )
            adjustment_versions = tuple(
                sorted({bar.adjustment_version for hour in grouped_hours for bar in hour.bars})
            )
            event_ns = (
                current.bars[-1].interval_end_ns
                if current and current.bars
                else latest.interval_end_ns
            )
            availability_ns = max(
                (bar.availability_ns for hour in valid for bar in hour.bars),
                default=latest.availability_ns,
            )
            if current is not None:
                availability_ns = max(
                    availability_ns, *(bar.availability_ns for bar in current.bars)
                )
            tile = AnalyticsTileV1(
                kind="market_clock",
                instrument_id=instrument,
                venue=venue,
                session=current_session or latest.session,
                event_ns=str(event_ns),
                asof_ns=str(asof_ns),
                availability_ns=str(availability_ns),
                source_version=source_versions[0] if len(source_versions) == 1 else "MIXED",
                dataset_version=dataset_versions[0] if len(dataset_versions) == 1 else "MIXED",
                method_version="market-clock-v1",
                parameter_version=policy.policy_version,
                calendar_version=calendar_version,
                policy_version=policy.policy_version,
                entitlement="UNVERIFIED",
                quality="READY" if ready else "INSUFFICIENT_DATA",
                lag_ns=str(asof_ns - event_ns),
                stale=True,
                missing_reason=None if ready else "INSUFFICIENT_DATA",
                units="log_return_nonannualized",
                sample_count=len(valid),
                confidence=None,
                payload={
                    "session_hour": label,
                    "utc_offset_minutes": offset,
                    "timezone": timezone,
                    "mean_abs_return": mean_move,
                    "mean_realized_volatility": mean_vol,
                    "move_p20": move_p20,
                    "move_p80": move_p80,
                    "volatility_p20": vol_p20,
                    "volatility_p80": vol_p80,
                    "percentile_method": "linear_interpolation",
                    "volatility_estimator": domain.volatility_estimator,
                    "bar_interval_ns": domain.bar_interval_ns,
                    "annualized": False,
                    "alert_candidate": alert,
                    "alert_reason": alert_reason,
                    "alert_comparison_method": "RATIO_OR_CERTIFIED_LOG60",
                    "alert_comparison_margin": "2E-55",
                    "alert_hour_start_ns": (
                        current_hour_start_ns if current is not None and current.finalized else None
                    ),
                    "alert_threshold": move_p80,
                    "source_ids": source_ids,
                    "source_versions": source_versions,
                    "dataset_versions": dataset_versions,
                    "adjustment_versions": adjustment_versions,
                    "stale_state": "UNASSESSED",
                    "missing_session_count": max(0, len(historical_sessions) - len(valid)),
                    "missing_subbar_count": sum(hour.missing_subbars for hour in grouped_hours),
                },
            )
            output.append(
                MarketClockBucketV1(
                    instrument_id=instrument,
                    venue=venue,
                    session_hour=label,
                    utc_offset_minutes=offset,
                    calendar_version=calendar_version,
                    timezone=timezone,
                    status="READY" if ready else "INSUFFICIENT_DATA",
                    session_count=len(valid),
                    missing_session_count=max(0, len(historical_sessions) - len(valid)),
                    missing_subbar_count=sum(hour.missing_subbars for hour in grouped_hours),
                    mean_abs_return=mean_move,
                    mean_realized_volatility=mean_vol,
                    move_p20=move_p20,
                    move_p80=move_p80,
                    volatility_p20=vol_p20,
                    volatility_p80=vol_p80,
                    alert_candidate=alert,
                    alert_reason=alert_reason,
                    alert_hour_start_ns=(
                        current_hour_start_ns if current is not None and current.finalized else None
                    ),
                    alert_move=current.movement
                    if current is not None and current.finalized
                    else None,
                    source_ids=source_ids,
                    policy_version=policy.policy_version,
                    tile=tile,
                )
            )
    return tuple(output)
