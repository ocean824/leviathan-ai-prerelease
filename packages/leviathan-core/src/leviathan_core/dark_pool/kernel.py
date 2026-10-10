"""Pure, publication-aware dark-print calculations for one half-open window."""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import replace
from datetime import UTC, date, datetime, timedelta, timezone, tzinfo
from decimal import Decimal, DecimalException, Inexact, Overflow, localcontext
from fractions import Fraction
from math import isqrt
from typing import TypeVar

from leviathan_core.numeric import NumericError, Ratio, quotient_final, sqrt_ge

from .finra_adapter import DarkAggregateContextV1, require_dark_context
from .models import (
    _EXACT_CONTEXT,
    _RESULT_ISSUER,
    AggregateContextV1,
    BaselineSampleV1,
    BucketCountV1,
    DarkLensError,
    DarkLensPolicyV1,
    DarkLensResultV1,
    DarkLensSnapshotV1,
    DarkPrintV1,
    ExchangeSessionV1,
    LitTradeV1,
    RankedPrintV1,
    SessionMetricV1,
    _result_hash,
)

_ZERO = Decimal("0")
_TEN_THOUSAND = Decimal("10000")
# Signed 64-bit micro-unit storage boundary; never saturate a notional or rank.
_MAX_NOTIONAL = Decimal("9223372036854.775807")
_ONLINE_WATERMARK_NS = 120_000_000_000
_T = TypeVar("_T", DarkPrintV1, LitTradeV1)


def _local_time(ns: int, exchange_zone: tzinfo) -> datetime:
    try:
        return datetime.fromtimestamp(ns // 1_000_000_000, tz=UTC).astimezone(exchange_zone)
    except (OverflowError, OSError, ValueError) as exc:
        raise DarkLensError(
            "INVALID_TIME", "timestamp is outside supported calendar range"
        ) from exc


def _usable(published_ns: int | None, available_ns: int | None, asof_ns: int) -> bool:
    if published_ns is None or available_ns is None:
        raise DarkLensError("UNKNOWN_PUBLICATION", "point-in-time evidence needs both times")
    if available_ns < published_ns:
        raise DarkLensError("INVALID_TIME", "availability precedes source publication")
    return max(published_ns, available_ns) <= asof_ns


def _event_key(event: DarkPrintV1 | LitTradeV1 | AggregateContextV1) -> str:
    return json.dumps(
        (event.source_id, event.dataset_id, event.venue, event.native_id),
        separators=(",", ":"),
        ensure_ascii=False,
    )


def _latest(
    events: tuple[_T, ...],
    asof_ns: int,
    mode: str,
    window_start_ns: int,
    window_end_ns: int,
) -> tuple[tuple[_T, ...], bool, dict[str, int]]:
    """Pick the latest visible correction per semantic source identity."""
    versions: dict[tuple[str, str], _T] = {}
    late_events: list[_T] = []
    late_keys: set[tuple[str, str]] = set()
    for event in events:
        if not _usable(event.published_ns, event.available_ns, asof_ns):
            continue
        if event.event_ns > asof_ns:
            raise DarkLensError("FUTURE_EVENT", "event timestamp exceeds its visible as-of time")
        if event.available_ns is not None and event.available_ns < event.event_ns:
            raise DarkLensError("INVALID_TIME", "event availability precedes event time")
        is_late = (
            mode == "ONLINE"
            and event.available_ns is not None
            and event.available_ns - event.event_ns > _ONLINE_WATERMARK_NS
        )
        if is_late:
            late_events.append(event)
        key = (_event_key(event), event.correction_id)
        if is_late:
            late_keys.add(key)
        previous = versions.get(key)
        if previous is not None and previous != event:
            raise DarkLensError(
                "CONFLICTING_DUPLICATE", "same semantic correction has two payloads"
            )
        versions[key] = event
    groups: dict[str, dict[str, _T]] = {}
    for event in versions.values():
        groups.setdefault(_event_key(event), {})[event.correction_id] = event
    selected: dict[str, _T] = {}
    depths: dict[str, int] = {}
    for semantic_key, group in groups.items():
        children: set[str] = set()
        for event in group.values():
            if event.correction_id == "0":
                if event.supersedes_id is not None:
                    raise DarkLensError("UNLINKED_CORRECTION", "original cannot supersede another")
                continue
            prior = group.get(event.supersedes_id or "")
            if prior is None or prior.available_ns is None or event.available_ns is None:
                raise DarkLensError("ORPHAN_CORRECTION", "correction needs visible predecessor")
            if prior.available_ns >= event.available_ns or prior.correction_id in children:
                raise DarkLensError("UNLINKED_CORRECTION", "correction chain is not append-only")
            children.add(prior.correction_id)
        if "0" not in group:
            raise DarkLensError("ORPHAN_CORRECTION", "correction needs visible original")
        eligible: list[_T] = []
        for candidate in group.values():
            cursor = candidate
            while (semantic_key, cursor.correction_id) not in late_keys:
                if cursor.correction_id == "0":
                    eligible.append(candidate)
                    break
                cursor = group[cursor.supersedes_id or ""]
        if not eligible:
            continue
        latest = max(eligible, key=lambda item: item.available_ns or 0)
        seen: set[str] = set()
        cursor = latest
        while cursor.correction_id != "0":
            if cursor.correction_id in seen or cursor.supersedes_id not in group:
                raise DarkLensError("UNLINKED_CORRECTION", "correction lineage is incomplete")
            seen.add(cursor.correction_id)
            cursor = group[cursor.supersedes_id]
        selected[semantic_key] = latest
        depths[semantic_key] = len(seen)
    ordered = sorted(selected.values(), key=lambda event: (_event_key(event), event.event_ns))
    pending = any(
        window_start_ns <= late.event_ns < window_end_ns
        or (
            _event_key(late) in selected
            and window_start_ns <= selected[_event_key(late)].event_ns < window_end_ns
        )
        for late in late_events
    )
    return tuple(ordered), pending, depths


def _calendar(
    snapshot: DarkLensSnapshotV1, policy: DarkLensPolicyV1
) -> tuple[ExchangeSessionV1, tzinfo]:
    sessions = [
        session
        for session in snapshot.calendar
        if session.open_ns <= policy.window_start_ns < session.close_ns
    ]
    if len(sessions) != 1:
        raise DarkLensError("MISSING_CALENDAR", "window start must have one trading session")
    session = sessions[0]
    if policy.window_end_ns > session.close_ns:
        raise DarkLensError("INVALID_WINDOW", "window extends beyond the trading session")
    if session.calendar_version != policy.calendar_version:
        raise DarkLensError("INVALID_CALENDAR", "calendar version mismatch")
    return session, _session_zone(session)


def _session_zone(session: ExchangeSessionV1) -> tzinfo:
    """Resolve the offset from versioned injected session data, never the host TZ."""
    if session.utc_offset_minutes is None:
        raise DarkLensError("CALENDAR_OFFSET_UNKNOWN", "calendar must supply UTC offset")
    offset_minutes = session.utc_offset_minutes
    if not -840 <= offset_minutes <= 840:
        raise DarkLensError("INVALID_CALENDAR", "session UTC offset is outside supported range")
    if session.exchange_tz.upper() == "UTC" and offset_minutes != 0:
        raise DarkLensError("INVALID_CALENDAR", "UTC calendar cannot have a nonzero offset")
    exchange_zone = timezone(timedelta(minutes=offset_minutes), session.exchange_tz)
    if _local_time(session.open_ns, exchange_zone).date() != session.trading_day:
        raise DarkLensError("INVALID_CALENDAR", "session day does not match exchange local date")
    return exchange_zone


def _market_type(venue: str, registry: dict[str, str]) -> str:
    market_type = registry.get(venue)
    if market_type is None:
        raise DarkLensError("UNKNOWN_VENUE", "venue is absent from injected registry")
    return market_type


def _validate_event(
    event: DarkPrintV1 | LitTradeV1,
    policy: DarkLensPolicyV1,
    session: ExchangeSessionV1,
    registry: dict[str, str],
) -> bool:
    if event.instrument_id != policy.instrument_id:
        return False
    if (
        event.calendar_version != session.calendar_version
        or event.exchange_tz != session.exchange_tz
    ):
        raise DarkLensError("INVALID_CALENDAR", "observation calendar provenance mismatch")
    if not event.fx_version or not event.split_version:
        raise DarkLensError("INVALID_ADJUSTMENT", "FX and split versions are required")
    if any(code not in policy.allowed_conditions for code in event.condition_codes):
        raise DarkLensError("UNSUPPORTED_CONDITION", "trade condition is not permitted by policy")
    market_type = _market_type(event.venue, registry)
    if isinstance(event, DarkPrintV1) and market_type != "OFF_EXCHANGE":
        raise DarkLensError("INVALID_VENUE", "dark print must be off exchange")
    if event.is_odd_lot and not policy.include_odd_lots:
        return False
    return session.open_ns <= event.event_ns < session.close_ns


def _is_lit(event: LitTradeV1, registry: dict[str, str]) -> bool:
    return _market_type(event.venue, registry) == "LIT" and not event.is_off_exchange


def _adjust(event: DarkPrintV1 | LitTradeV1) -> tuple[Decimal, Decimal, Decimal]:
    exact_size = Fraction(event.size) * Fraction(event.split_factor)
    exact_notional = Fraction(event.price) * Fraction(event.size) * Fraction(event.fx_rate)
    if Ratio(exact_notional.numerator, exact_notional.denominator).gt(_MAX_NOTIONAL):
        raise Overflow
    exact_price = Fraction(event.price) * Fraction(event.fx_rate) / Fraction(event.split_factor)
    with localcontext(_EXACT_CONTEXT):
        size = Decimal(exact_size.numerator) / Decimal(exact_size.denominator)
        notional = Decimal(exact_notional.numerator) / Decimal(exact_notional.denominator)
    price = _fraction_decimal(exact_price)
    return price, size, notional


def _ratio(numerator: Decimal, denominator: Decimal) -> Decimal:
    return quotient_final(Ratio.from_decimals(numerator, denominator), 1)


def _fraction_decimal(value: Fraction) -> Decimal:
    return quotient_final(Ratio(value.numerator, value.denominator), 1)


def _exact_decimal(value: Fraction) -> Decimal:
    with localcontext(_EXACT_CONTEXT):
        return Decimal(value.numerator) / Decimal(value.denominator)


def _exact_sum(values: Iterable[Decimal]) -> Fraction:
    return sum((Fraction(value) for value in values), Fraction(0))


def _z_final(delta: Ratio, variance: Ratio) -> Decimal:
    """Round the final signed z once, using exact squared midpoint comparisons."""
    if delta.numerator == 0:
        return _ZERO
    delta_fraction = Fraction(delta.numerator, delta.denominator)
    variance_fraction = Fraction(variance.numerator, variance.denominator)
    squared = delta_fraction * delta_fraction / variance_fraction
    squared_ratio = Ratio(squared.numerator, squared.denominator)
    numerator, denominator = squared.numerator, squared.denominator
    exponent = len(str(numerator)) - len(str(denominator))
    if (
        numerator < denominator * 10**exponent
        if exponent >= 0
        else numerator * 10 ** (-exponent) < denominator
    ):
        exponent -= 1
    root_exponent = exponent // 2
    if root_exponent > 38 or root_exponent < -38:
        raise DarkLensError("DECIMAL_OUT_OF_BOUNDS", "z exceeds decimal magnitude bounds")
    scale = 33 - root_exponent
    if scale >= 0:
        scaled_num, scaled_den = numerator * 10 ** (2 * scale), denominator
    else:
        scaled_num, scaled_den = numerator, denominator * 10 ** (-2 * scale)
    coefficient = isqrt(scaled_num // scaled_den)
    midpoint = (
        Ratio(2 * coefficient + 1, 2 * 10**scale)
        if scale >= 0
        else Ratio((2 * coefficient + 1) * 10 ** (-scale), 2)
    )
    at_or_above_midpoint = sqrt_ge(squared_ratio, midpoint)
    midpoint_is_exact = squared_ratio.eq(
        Ratio(midpoint.numerator * midpoint.numerator, midpoint.denominator * midpoint.denominator)
    )
    if at_or_above_midpoint and (not midpoint_is_exact or coefficient % 2):
        coefficient += 1
    if coefficient == 10**34:
        coefficient //= 10
        root_exponent += 1
    scale = 33 - root_exponent
    signed = -coefficient if delta.numerator < 0 else coefficient
    final_ratio = Ratio(signed, 10**scale) if scale >= 0 else Ratio(signed * 10 ** (-scale), 1)
    return quotient_final(final_ratio, 1)


def _side(event: DarkPrintV1) -> tuple[str, bool]:
    if event.side != "U":
        return event.side, False
    mid = event.reference_mid
    if mid is None or not mid.is_finite() or mid <= 0:
        return "U", False
    if event.price > mid:
        return "B", True
    if event.price < mid:
        return "S", True
    return "U", True


def _session_intervals(
    session: ExchangeSessionV1, policy: DarkLensPolicyV1, exchange_zone: tzinfo
) -> tuple[tuple[str, int, int], ...]:
    open_end = min(session.open_ns + policy.open_minutes * 60_000_000_000, session.close_ns)
    close_start = max(session.close_ns - policy.close_minutes * 60_000_000_000, open_end)
    day = session.trading_day
    lunch_start_hour, lunch_start_minute = (int(x) for x in policy.lunch_start.split(":"))
    lunch_end_hour, lunch_end_minute = (int(x) for x in policy.lunch_end.split(":"))
    start_local = datetime(
        day.year,
        day.month,
        day.day,
        lunch_start_hour,
        lunch_start_minute,
        tzinfo=exchange_zone,
    )
    end_local = datetime(
        day.year,
        day.month,
        day.day,
        lunch_end_hour,
        lunch_end_minute,
        tzinfo=exchange_zone,
    )
    start_ns = max(int(start_local.timestamp()) * 1_000_000_000, open_end)
    end_ns = min(int(end_local.timestamp()) * 1_000_000_000, close_start)
    intervals = [("open", session.open_ns, open_end)]
    if start_ns < end_ns:
        intervals.append(("lunch", start_ns, end_ns))
    intervals.append(("close", close_start, session.close_ns))
    return tuple(intervals)


def _baseline(
    samples: tuple[BaselineSampleV1, ...],
    calendar: tuple[ExchangeSessionV1, ...],
    session: ExchangeSessionV1,
    exchange_zone: tzinfo,
    policy: DarkLensPolicyV1,
    asof_ns: int,
    divergence: Ratio | None,
) -> tuple[Decimal | None, str | None, tuple[str, ...]]:
    visible_samples = tuple(
        sample for sample in samples if _usable(sample.published_ns, sample.available_ns, asof_ns)
    )
    for sample in visible_samples:
        if (
            sample.instrument_id != policy.instrument_id
            or sample.window_end_ns - sample.window_start_ns
            != policy.window_end_ns - policy.window_start_ns
            or sample.window_family != policy.window_family
            or sample.adjustment_scope != policy.adjustment_scope
        ):
            raise DarkLensError("SCOPE_MISMATCH", "baseline scope does not match policy")
    if divergence is None:
        return None, "DIVERGENCE_INVALID", ()
    prior_sessions: dict[date, ExchangeSessionV1] = {}
    for day in calendar:
        if (
            day.trading_day >= session.trading_day
            or day.calendar_version != session.calendar_version
        ):
            continue
        previous_session = prior_sessions.get(day.trading_day)
        if previous_session is not None and previous_session != day:
            raise DarkLensError("CONFLICTING_CALENDAR", "two sessions for a prior trading day")
        prior_sessions[day.trading_day] = day
    prior_days = sorted(prior_sessions)[-30:]
    expected_time = _local_time(policy.window_start_ns, exchange_zone).time().replace(tzinfo=None)
    by_day: dict[date, BaselineSampleV1] = {}
    for sample in visible_samples:
        if sample.trading_day not in prior_days:
            continue
        prior_session = prior_sessions[sample.trading_day]
        sample_zone = _session_zone(prior_sessions[sample.trading_day])
        if not prior_session.open_ns <= sample.window_start_ns < prior_session.close_ns:
            raise DarkLensError("INVALID_BASELINE", "baseline timestamp outside stated session")
        if sample.window_end_ns > prior_session.close_ns:
            raise DarkLensError("INVALID_BASELINE", "baseline window exceeds stated session")
        if _local_time(sample.window_start_ns, sample_zone).date() != sample.trading_day:
            raise DarkLensError("INVALID_BASELINE", "baseline timestamp has wrong trading day")
        sample_time = _local_time(sample.window_start_ns, sample_zone).time().replace(tzinfo=None)
        if sample_time != expected_time:
            continue
        previous = by_day.get(sample.trading_day)
        if previous is not None and previous != sample:
            raise DarkLensError("CONFLICTING_BASELINE", "multiple baseline values for one day")
        by_day[sample.trading_day] = sample
    values = [sample.divergence for sample in by_day.values()]
    ids = tuple(sorted({sample.source_id for sample in by_day.values()}))
    if len(values) < 10:
        return None, "BASELINE_INSUFFICIENT", ids
    exact_values = [Ratio.from_decimals(value, 1) for value in values]
    value_fractions = [Fraction(value.numerator, value.denominator) for value in exact_values]
    mean = sum(value_fractions, Fraction(0)) / len(value_fractions)
    variance = sum(((value - mean) ** 2 for value in value_fractions), Fraction(0)) / len(
        value_fractions
    )
    if variance == 0:
        return None, "BASELINE_ZERO_VARIANCE", ids
    divergence_fraction = Fraction(divergence.numerator, divergence.denominator)
    delta = divergence_fraction - mean
    return (
        _z_final(
            Ratio(delta.numerator, delta.denominator),
            Ratio(variance.numerator, variance.denominator),
        ),
        None,
        ids,
    )


def _bucket_label(notional: Decimal, thresholds: tuple[Decimal, ...]) -> str:
    floor = _ZERO
    for threshold in thresholds:
        if notional < threshold:
            return f"[{floor},{threshold})"
        floor = threshold
    return f">={floor}"


def _session_metrics(
    intervals: tuple[tuple[str, int, int], ...],
    dark: tuple[tuple[DarkPrintV1, Decimal, Decimal, str], ...],
    lit: tuple[tuple[LitTradeV1, Decimal, Decimal], ...],
    policy: DarkLensPolicyV1,
    trading_day: date,
) -> tuple[SessionMetricV1, ...]:
    result = []
    for label, start_ns, end_ns in intervals:
        in_dark = [item for item in dark if start_ns <= item[0].event_ns < end_ns]
        in_lit = [item for item in lit if start_ns <= item[0].event_ns < end_ns]
        buy_exact = _exact_sum(item[2] for item in in_dark if item[3] == "B")
        sell_exact = _exact_sum(item[2] for item in in_dark if item[3] == "S")
        unknown_exact = _exact_sum(item[2] for item in in_dark if item[3] == "U")
        known_exact = buy_exact + sell_exact
        imbalance = (
            _fraction_decimal((buy_exact - sell_exact) * Fraction(_TEN_THOUSAND) / known_exact)
            if known_exact
            else None
        )
        dp_volume_exact = _exact_sum(item[1] for item in in_dark)
        lit_volume_exact = _exact_sum(item[1] for item in in_lit)
        ratio = _fraction_decimal(dp_volume_exact / lit_volume_exact) if lit_volume_exact else None
        if (
            not known_exact
            or abs(buy_exact - sell_exact) * Fraction(_TEN_THOUSAND)
            < Fraction(policy.pressure_threshold_bp) * known_exact
        ):
            cluster = "Neutral"
        elif buy_exact > sell_exact:
            cluster = "High Buy Pressure"
        else:
            cluster = "High Sell Pressure"
        result.append(
            SessionMetricV1(
                session_id=f"{trading_day.isoformat()}:{label}:{policy.session_rule_version}",
                start_ns=start_ns,
                end_ns=end_ns,
                buy_notional=_exact_decimal(buy_exact),
                sell_notional=_exact_decimal(sell_exact),
                unknown_notional=_exact_decimal(unknown_exact),
                imbalance_bp=imbalance,
                dp_vs_lit_volume_ratio=ratio,
                cluster_label=cluster,
            )
        )
    return tuple(result)


def _digest(result: DarkLensResultV1) -> DarkLensResultV1:
    return replace(result, digest=_result_hash(result), _issuer=_RESULT_ISSUER)


def _calculate_impl(
    snapshot: DarkLensSnapshotV1, policy: DarkLensPolicyV1, asof_ns: int
) -> DarkLensResultV1:
    """Calculate one deterministic as-of lens result without I/O or host clock access."""
    if isinstance(asof_ns, bool) or not isinstance(asof_ns, int) or asof_ns < 0:
        raise DarkLensError("INVALID_TIME", "asof_ns must be UTC nanoseconds")
    registry = {rule.venue: rule.market_type for rule in snapshot.venue_registry}
    session, exchange_zone = _calendar(snapshot, policy)
    dark_candidates = tuple(
        item for item in snapshot.dark_prints if item.instrument_id == policy.instrument_id
    )
    lit_candidates = tuple(
        item for item in snapshot.lit_trades if item.instrument_id == policy.instrument_id
    )
    dark_all, dark_pending, dark_depths = _latest(
        dark_candidates, asof_ns, snapshot.mode, policy.window_start_ns, policy.window_end_ns
    )
    lit_all, lit_pending, lit_depths = _latest(
        lit_candidates, asof_ns, snapshot.mode, policy.window_start_ns, policy.window_end_ns
    )
    dark = tuple(
        event
        for event in dark_all
        if policy.window_start_ns <= event.event_ns < policy.window_end_ns
        and _validate_event(event, policy, session, registry)
    )
    lit = tuple(
        event
        for event in lit_all
        if policy.window_start_ns <= event.event_ns < policy.window_end_ns
        and _validate_event(event, policy, session, registry)
        and _is_lit(event, registry)
    )
    contexts: list[AggregateContextV1] = []
    for aggregate in snapshot.aggregate_context:
        if aggregate.instrument_id != policy.instrument_id:
            continue
        if not _usable(aggregate.published_ns, aggregate.available_ns, asof_ns):
            continue
        if aggregate.event_ns > asof_ns:
            raise DarkLensError("FUTURE_EVENT", "aggregate event exceeds as-of")
        if (
            aggregate.calendar_version != session.calendar_version
            or aggregate.exchange_tz != session.exchange_tz
        ):
            raise DarkLensError("INVALID_CALENDAR", "aggregate calendar provenance mismatch")
        if _market_type(aggregate.venue, registry) != "OFF_EXCHANGE":
            raise DarkLensError("INVALID_VENUE", "aggregate context must be off exchange")
        contexts.append(aggregate)
    print_evidence: tuple[DarkPrintV1 | LitTradeV1, ...] = (*dark, *lit)
    if dark:
        if any(item.source_state == "UNVERIFIED" for item in print_evidence):
            state = "UNVERIFIED"
        elif any(item.source_state == "SYNTHETIC" for item in print_evidence):
            state = "SYNTHETIC"
        else:
            state = "LICENSED_PRINT"
    elif contexts:
        state = "AGGREGATE_ONLY"
    else:
        state = "UNVERIFIED"
    evidence: tuple[DarkPrintV1 | LitTradeV1 | AggregateContextV1, ...] = (*dark, *lit, *contexts)
    lag = max(
        (item.available_ns - item.event_ns for item in evidence if item.available_ns is not None),
        default=None,
    )
    earliest = max(
        (
            max(item.published_ns, item.available_ns)
            for item in evidence
            if item.published_ns is not None and item.available_ns is not None
        ),
        default=None,
    )
    if state == "AGGREGATE_ONLY":
        vintages = ",".join(sorted({context.release_vintage for context in contexts}))
        label = f"AGGREGATE_ONLY delayed context; vintage {vintages}; no print-level signal"
    else:
        label = f"{state} print evidence; observed publication/availability lag {lag} ns; not live"
    source_ids = tuple(sorted({item.source_id for item in evidence}))
    source_event_ids = tuple(sorted(_event_key(item) for item in evidence))
    aggregate_ids = tuple(sorted(_event_key(item) for item in contexts))
    adjustments = tuple(
        sorted({f"fx:{item.fx_version}|split:{item.split_version}" for item in print_evidence})
    )
    intervals = _session_intervals(session, policy, exchange_zone)
    base = DarkLensResultV1(
        instrument_id=policy.instrument_id,
        window_start_ns=policy.window_start_ns,
        window_end_ns=policy.window_end_ns,
        asof_ns=asof_ns,
        revision=snapshot.revision,
        source_state=state,
        delay_label=label,
        observed_lag_ns=lag,
        earliest_usable_ns=earliest,
        source_ids=source_ids,
        source_event_ids=source_event_ids,
        aggregate_context_ids=aggregate_ids,
        adjustment_versions=adjustments,
        min_notional=policy.min_notional,
        policy_version=policy.policy_version,
        bucket_rule_version=policy.bucket_rule_version,
        bucket_scheme=policy.bucket_scheme,
        bucket_thresholds=policy.fixed_thresholds,
        quantile_count=policy.quantile_count,
        include_odd_lots=policy.include_odd_lots,
        counts_low_requested=policy.counts_low,
        venue_filter=policy.venue_filter,
        side_rule_version=policy.side_rule_version,
        calendar_version=session.calendar_version,
        session_rule_version=policy.session_rule_version,
        baseline_version=policy.baseline_version,
        window_id=f"{policy.instrument_id}:{policy.window_start_ns}:{policy.window_end_ns}",
        session_ids=tuple(item[0] for item in intervals),
        recompute_pending=dark_pending or lit_pending,
        _issuer=_RESULT_ISSUER,
    )
    with localcontext(_EXACT_CONTEXT):
        adjusted_dark: list[tuple[DarkPrintV1, Decimal, Decimal, Decimal, str, bool]] = []
        for dark_event in dark:
            price, size, notional = _adjust(dark_event)
            if notional > _MAX_NOTIONAL:
                return _digest(
                    replace(
                        base,
                        valid=False,
                        reason_if_invalid="OVERFLOW",
                        flags=("OVERFLOW",),
                        _issuer=_RESULT_ISSUER,
                    )
                )
            side, inferred = _side(dark_event)
            adjusted_dark.append((dark_event, price, size, notional, side, inferred))
        if _exact_sum(item[3] for item in adjusted_dark) > Fraction(_MAX_NOTIONAL):
            return _digest(
                replace(
                    base,
                    valid=False,
                    reason_if_invalid="OVERFLOW",
                    flags=("OVERFLOW",),
                    _issuer=_RESULT_ISSUER,
                )
            )
        adjusted_lit: list[tuple[LitTradeV1, Decimal, Decimal, Decimal]] = []
        for lit_event in lit:
            price, size, notional = _adjust(lit_event)
            if notional > _MAX_NOTIONAL:
                return _digest(
                    replace(
                        base,
                        valid=False,
                        reason_if_invalid="OVERFLOW",
                        flags=("OVERFLOW",),
                        _issuer=_RESULT_ISSUER,
                    )
                )
            adjusted_lit.append((lit_event, price, size, notional))
        if _exact_sum(item[3] for item in adjusted_lit) > Fraction(_MAX_NOTIONAL):
            return _digest(
                replace(
                    base,
                    valid=False,
                    reason_if_invalid="OVERFLOW",
                    flags=("OVERFLOW",),
                    _issuer=_RESULT_ISSUER,
                )
            )
        qualifying = [item for item in adjusted_dark if item[3] >= policy.min_notional]
        low_count = len(adjusted_dark) - len(qualifying) if policy.counts_low else None
        ranked = sorted(qualifying, key=lambda row: (-row[3], row[0].event_ns, _event_key(row[0])))
        thresholds = policy.fixed_thresholds
        quantile_labels: dict[str, str] = {}
        if policy.bucket_scheme == "quantile" and ranked:
            ordered = sorted(ranked, key=lambda row: (row[3], row[0].event_ns, _event_key(row[0])))
            for ordinal, quantile_row in enumerate(ordered):
                bucket_number = min(
                    policy.quantile_count, ordinal * policy.quantile_count // len(ordered) + 1
                )
                quantile_labels[_event_key(quantile_row[0])] = f"q{bucket_number}"
        buckets: dict[str, tuple[int, Fraction]] = {}
        ranked_rows = []
        for index, dark_row in enumerate(ranked, 1):
            bucket = (
                quantile_labels[_event_key(dark_row[0])]
                if policy.bucket_scheme == "quantile"
                else _bucket_label(dark_row[3], thresholds)
            )
            count, total = buckets.get(bucket, (0, Fraction(0)))
            buckets[bucket] = (count + 1, total + Fraction(dark_row[3]))
            ranked_rows.append(
                RankedPrintV1(
                    rank=index,
                    source_key=_event_key(dark_row[0]),
                    event_ns=dark_row[0].event_ns,
                    venue=dark_row[0].venue,
                    notional=dark_row[3],
                    side=dark_row[4],
                    side_inferred=dark_row[5],
                    bucket=bucket,
                )
            )
        bucket_rows = tuple(
            BucketCountV1(key, count, _exact_decimal(total))
            for key, (count, total) in sorted(buckets.items())
        )
        dp_volume = _exact_decimal(_exact_sum(item[2] for item in adjusted_dark))
        dp_notional = _exact_decimal(_exact_sum(item[3] for item in adjusted_dark))
        lit_volume = _exact_decimal(_exact_sum(item[2] for item in adjusted_lit))
        lit_notional = _exact_decimal(_exact_sum(item[3] for item in adjusted_lit))
        dp_vwap = _ratio(dp_notional, dp_volume) if dp_volume else None
        lit_vwap = _ratio(lit_notional, lit_volume) if lit_volume else None
        if not lit_volume:
            reason = "NO_LIT_DATA"
        elif lit_volume < policy.min_lit_volume:
            reason = "LOW_LIT_VOLUME"
        elif not dp_volume:
            reason = "NO_DARK_DATA"
        else:
            reason = None
        divergence_exact = (
            Fraction(dp_notional)
            / Fraction(dp_volume)
            / (Fraction(lit_notional) / Fraction(lit_volume))
            - 1
            if reason is None and dp_vwap is not None and lit_vwap is not None
            else None
        )
        divergence_ratio = (
            Ratio(divergence_exact.numerator, divergence_exact.denominator)
            if divergence_exact is not None
            else None
        )
        divergence = quotient_final(divergence_ratio, 1) if divergence_ratio is not None else None
        z, z_reason, baseline_ids = _baseline(
            snapshot.baseline_samples,
            snapshot.calendar,
            session,
            exchange_zone,
            policy,
            asof_ns,
            divergence_ratio,
        )
        buy_exact = _exact_sum(item[3] for item in adjusted_dark if item[4] == "B")
        sell_exact = _exact_sum(item[3] for item in adjusted_dark if item[4] == "S")
        known_exact = buy_exact + sell_exact
        imbalance = (
            _fraction_decimal((buy_exact - sell_exact) * Fraction(_TEN_THOUSAND) / known_exact)
            if known_exact
            else None
        )
        session_rows = _session_metrics(
            intervals,
            tuple((item[0], item[2], item[3], item[4]) for item in adjusted_dark),
            tuple((item[0], item[2], item[3]) for item in adjusted_lit),
            policy,
            session.trading_day,
        )
        corrections = sum(dark_depths[_event_key(event)] for event in dark)
        corrections += sum(lit_depths[_event_key(event)] for event in lit)
        return _digest(
            replace(
                base,
                revision=snapshot.revision + corrections,
                source_ids=tuple(sorted(set(source_ids) | set(baseline_ids))),
                ranked_prints=tuple(ranked_rows),
                bucket_counts=bucket_rows,
                counts_low=low_count,
                total_dp_trades=len(adjusted_dark),
                latest_contributing_event_ns=max(
                    (item[0].event_ns for item in adjusted_dark), default=None
                ),
                total_notional=dp_notional,
                total_notional_ranked=_exact_decimal(_exact_sum(item[3] for item in qualifying)),
                avg_trade_size=_ratio(dp_volume, Decimal(len(adjusted_dark)))
                if adjusted_dark
                else None,
                dp_vwap=dp_vwap,
                lit_vwap=lit_vwap,
                divergence=divergence,
                divergence_z=z,
                lit_volume=lit_volume,
                dp_volume=dp_volume,
                buy_sell_imbalance_bp=imbalance,
                session_metrics=session_rows,
                valid=reason is None,
                reason_if_invalid=reason,
                z_reason=z_reason,
                _issuer=_RESULT_ISSUER,
            )
        )


def calculate(
    snapshot: DarkLensSnapshotV1, policy: DarkLensPolicyV1, asof_ns: int
) -> DarkLensResultV1:
    """Calculate in bounded, kernel-owned Decimal contexts."""
    for context in snapshot.aggregate_context:
        if isinstance(context, DarkAggregateContextV1):
            require_dark_context(context)
    try:
        return _calculate_impl(snapshot, policy, asof_ns)
    except Overflow:
        return _digest(
            DarkLensResultV1(
                instrument_id=policy.instrument_id,
                window_start_ns=policy.window_start_ns,
                window_end_ns=policy.window_end_ns,
                asof_ns=asof_ns,
                revision=snapshot.revision,
                source_state="UNVERIFIED",
                delay_label="overflow; no arithmetic signal",
                observed_lag_ns=None,
                earliest_usable_ns=None,
                source_ids=(),
                source_event_ids=(),
                aggregate_context_ids=(),
                adjustment_versions=(),
                min_notional=policy.min_notional,
                policy_version=policy.policy_version,
                bucket_rule_version=policy.bucket_rule_version,
                bucket_scheme=policy.bucket_scheme,
                bucket_thresholds=policy.fixed_thresholds,
                quantile_count=policy.quantile_count,
                include_odd_lots=policy.include_odd_lots,
                counts_low_requested=policy.counts_low,
                venue_filter=policy.venue_filter,
                side_rule_version=policy.side_rule_version,
                calendar_version=policy.calendar_version,
                session_rule_version=policy.session_rule_version,
                baseline_version=policy.baseline_version,
                window_id=f"{policy.instrument_id}:{policy.window_start_ns}:{policy.window_end_ns}",
                session_ids=(),
                valid=False,
                reason_if_invalid="OVERFLOW",
                flags=("OVERFLOW",),
                _issuer=_RESULT_ISSUER,
            )
        )
    except Inexact as exc:
        raise DarkLensError(
            "PRECISION_EXCEEDED", "exact arithmetic exceeds kernel precision"
        ) from exc
    except NumericError as exc:
        code = {
            "MAGNITUDE_OUT_OF_BOUNDS": "DECIMAL_OUT_OF_BOUNDS",
            "DIVISION_BY_ZERO": "INVALID_DECIMAL",
        }.get(exc.code, exc.code)
        raise DarkLensError(code, "numeric output is outside kernel bounds") from exc
    except DecimalException as exc:
        raise DarkLensError("INVALID_DECIMAL", "decimal arithmetic is invalid") from exc
