"""Deterministic, offline earnings and corporate event calculations."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, time, timedelta, tzinfo
from decimal import Decimal, Inexact, localcontext
from fractions import Fraction
from hashlib import sha256
from itertools import pairwise

from .models import (
    DECIMAL_CONTEXT,
    AlertCandidateV1,
    CorporateActionSnapshotV1,
    CorporateEventRevisionV1,
    DpOverlayEvidenceV1,
    EventMarketEvidenceV1,
    EventMetricPolicyV1,
    EventMetricsV1,
    EventOverlayV1,
    EventSnapshotV1,
    ExchangeSessionV1,
    ExpectedMoveWindowV1,
    FlowOverlayEvidenceV1,
    MetricStatus,
    PrecisionExceededError,
    _issue_event_metrics,
    canonical_decimal,
)

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_DAY_NS = 86_400_000_000_000


def _exact_decimal(value: Fraction) -> Decimal:
    """Materialize a stored quantity only if precision preserves it exactly."""
    with localcontext(DECIMAL_CONTEXT) as context:
        context.traps[Inexact] = True
        try:
            result = Decimal(value.numerator) / Decimal(value.denominator)
        except Inexact as exc:
            raise PrecisionExceededError() from exc
    return canonical_decimal(result, "stored quantity", allow_zero=True,
                             allow_negative=True)


def _rounded_fraction(value: Fraction) -> Decimal:
    """Round one final derived quotient in the kernel's documented context."""
    with localcontext(DECIMAL_CONTEXT):
        result = Decimal(value.numerator) / Decimal(value.denominator)
    return canonical_decimal(result, "derived quotient", allow_zero=True,
                             allow_negative=True)


def _quote_key(item: EventMarketEvidenceV1) -> tuple[int, int, str, str]:
    return item.observed_ns, item.available_ns, item.source, item.native_id


def _digest(*parts: object) -> str:
    """Stable content revision for audit and append-only result stores."""
    return sha256(repr(parts).encode("utf-8")).hexdigest()


class AmbiguousEventIdentityError(ValueError):
    """Available revisions cannot be assigned to one stable event safely."""


class QuoteConflictError(ValueError):
    """The same logical quote has incompatible available observations."""


def _utc_datetime(ns: int) -> datetime:
    return _EPOCH + timedelta(microseconds=ns // 1_000)


def _zone(tzdata: Mapping[str, tzinfo], name: str) -> tzinfo:
    try:
        zone = tzdata[name]
    except KeyError as exc:
        raise ValueError(f"timezone {name!r} was not injected") from exc
    if zone is None:
        raise ValueError(f"timezone {name!r} was not injected")
    return zone


def calendar_window(
    *, now_ns: int, exchange_tz: str, tzdata: Mapping[str, tzinfo],
    before_days: int = 7, after_days: int = 2,
) -> tuple[int, int]:
    """Return the default exchange-local calendar-day window as half-open UTC ns."""
    if min(before_days, after_days) < 0:
        raise ValueError("calendar window bounds must be nonnegative")
    zone = _zone(tzdata, exchange_tz)
    today = _utc_datetime(now_ns).astimezone(zone).date()
    start = datetime.combine(today - timedelta(days=before_days), time.min, zone)
    end = datetime.combine(today + timedelta(days=after_days + 1), time.min, zone)
    return _ns(start), _ns(end)


def _ns(value: datetime) -> int:
    delta = value.astimezone(UTC) - _EPOCH
    return ((delta.days * 86_400 + delta.seconds) * 1_000_000 + delta.microseconds) * 1_000


def select_revision(
    revisions: Sequence[CorporateEventRevisionV1], asof_ns: int,
) -> CorporateEventRevisionV1 | None:
    """Select the latest *available* revision, rejecting ambiguous identity and ties."""
    available = [r for r in revisions if r.available_ns <= asof_ns]
    if not available:
        return None
    event_ids = {r.event_id for r in available}
    identities = {(r.source, r.native_id) for r in available if r.native_id}
    mappings = {r.identity_mapping_version for r in available if r.identity_mapping_version}
    if len(event_ids) != 1 or len(identities) > 1 or len(mappings) > 1:
        raise AmbiguousEventIdentityError("conflicting event identity")
    if not identities and not mappings:
        raise AmbiguousEventIdentityError("event lacks stable native ID or reviewed mapping")
    if any(not r.native_id and not r.identity_mapping_version for r in available):
        raise AmbiguousEventIdentityError("revision lacks stable identity evidence")
    # The published lineage must retain the issuer, type, and fiscal period.
    lineage = {(r.issuer_id, r.event_type, r.fiscal_year, r.fiscal_quarter)
               for r in available}
    if len(lineage) != 1:
        raise AmbiguousEventIdentityError("conflicting issuer or fiscal lineage")
    highest = max(r.vendor_revision for r in available)
    tied = [r for r in available if r.vendor_revision == highest]
    if len(set(tied)) != 1:
        raise AmbiguousEventIdentityError("conflicting payloads for vendor revision")
    return tied[0]


def _available_market(
    evidence: Sequence[EventMarketEvidenceV1], asof_ns: int, ticker: str,
) -> list[EventMarketEvidenceV1]:
    latest: dict[tuple[str, str, str, str, str], EventMarketEvidenceV1] = {}
    for item in sorted(evidence, key=lambda x: (x.kind, x.source, x.dataset,
                                                x.schema_version, x.native_id, x.revision,
                                                x.available_ns)):
        if (item.ticker != ticker or item.available_ns > asof_ns
                or item.observed_ns > asof_ns
                or item.feed_state not in ("SYNTHETIC", "ENTITLED")):
            continue
        key = (item.kind, item.source, item.dataset, item.schema_version, item.native_id)
        old = latest.get(key)
        if old is None or item.revision > old.revision:
            latest[key] = item
        elif old.revision == item.revision and old != item:
            raise QuoteConflictError("QUOTE_CONFLICT")
    return sorted(latest.values(), key=lambda x: (x.kind, *_quote_key(x), x.dataset,
                                                  x.schema_version, x.revision))


def _choose_quote(
    candidates: Sequence[EventMarketEvidenceV1], policy: EventMetricPolicyV1,
) -> tuple[EventMarketEvidenceV1 | None, str | None]:
    if not candidates:
        return None, None
    at_time = [x for x in candidates if x.observed_ns == max(y.observed_ns
                                                               for y in candidates)]
    def payload(item: EventMarketEvidenceV1) -> tuple[object, ...]:
        return (item.value, item.option_expiry_ns, item.strike, item.call_bid,
                item.call_ask, item.put_bid, item.put_ask, item.adjustment_version)

    for source in {x.source for x in at_time}:
        if len({payload(x) for x in at_time if x.source == source}) > 1:
            return None, "QUOTE_CONFLICT"
    if len({payload(x) for x in at_time}) > 1:
        ranked = [x for x in at_time if x.source in policy.source_priority]
        if not ranked:
            return None, "QUOTE_CONFLICT"
        best_rank = min(policy.source_priority.index(x.source) for x in ranked)
        at_time = [x for x in ranked if policy.source_priority.index(x.source) == best_rank]
    return max(at_time, key=lambda x: (*_quote_key(x), x.dataset,
                                       x.schema_version, x.revision)), None


def _at_close(
    items: Sequence[EventMarketEvidenceV1], kind: str, close_ns: int,
    max_age_ns: int, policy: EventMetricPolicyV1,
) -> tuple[EventMarketEvidenceV1 | None, bool, str | None]:
    matching = [x for x in items if x.kind == kind and x.observed_ns <= close_ns]
    best, reason = _choose_quote(matching, policy)
    return best, best is not None and close_ns - best.observed_ns > max_age_ns, reason


def _front_week_straddle(
    items: Sequence[EventMarketEvidenceV1], close_ns: int, first_post_close_ns: int | None,
    spot: Decimal, policy: EventMetricPolicyV1,
) -> tuple[EventMarketEvidenceV1 | None, bool, str | None]:
    candidates = [x for x in items if x.kind == "straddle" and x.observed_ns <= close_ns]
    if not candidates or first_post_close_ns is None:
        return None, False, "EXPECTED_MOVE_UNAVAILABLE"
    expiring = [x for x in candidates if x.option_expiry_ns is not None
                and x.option_expiry_ns > first_post_close_ns]
    if not expiring:
        return None, False, "EXPECTED_MOVE_UNAVAILABLE"
    earliest = min(x.option_expiry_ns for x in expiring if x.option_expiry_ns is not None)
    front = [x for x in expiring if x.option_expiry_ns == earliest]
    with_strike = [x for x in front if x.strike is not None]
    if with_strike:
        distance = min(abs(Fraction(x.strike) - Fraction(spot))
                       for x in with_strike if x.strike is not None)
        front = [x for x in with_strike if x.strike is not None
                 and abs(Fraction(x.strike) - Fraction(spot)) == distance]
    selected, reason = _choose_quote(front, policy)
    return selected, selected is not None and close_ns - selected.observed_ns > (
        policy.max_evidence_age_ns
    ), reason


def _iv_rank(
    items: Sequence[EventMarketEvidenceV1], sessions: Sequence[ExchangeSessionV1],
    close_ns: int, policy: EventMetricPolicyV1,
) -> tuple[Decimal | None, int, EventMarketEvidenceV1 | None, str | None]:
    lookback = [s for s in sessions if s.close_ns <= close_ns][-policy.lookback_trading_days:]
    values: list[EventMarketEvidenceV1] = []
    for session in lookback:
        day_items = [x for x in items if x.kind == "iv30d"
                     and session.open_ns <= x.observed_ns <= session.close_ns]
        if day_items:
            selected, reason = _choose_quote(day_items, policy)
            if reason is not None:
                return None, len(values), None, reason
            if selected is not None:
                values.append(selected)
    current = (values[-1] if values and lookback
               and values[-1].observed_ns >= lookback[-1].open_ns else None)
    if current is None:
        return None, len(values), None, "MISSING_IV30D"
    if close_ns - current.observed_ns > policy.max_evidence_age_ns:
        return None, len(values), current, "STALE_IV30D"
    if len(values) < policy.min_iv_samples:
        return None, len(values), current, "INSUFFICIENT_IV_HISTORY"
    count = sum(x.value <= current.value for x in values)
    return Decimal(100 * count) / Decimal(len(values)), len(values), current, None


def _snapshot(
    phase: str, session: ExchangeSessionV1, items: Sequence[EventMarketEvidenceV1],
    sessions: Sequence[ExchangeSessionV1], policy: EventMetricPolicyV1,
) -> EventSnapshotV1:
    rank, count, iv, iv_reason = _iv_rank(items, sessions, session.close_ns, policy)
    closes = [x for x in items if x.kind == "adjusted_close"
              and x.observed_ns == session.close_ns]
    close, close_reason = _choose_quote(closes, policy)
    reasons = tuple(x for x in (
        iv_reason, close_reason,
        "MISSING_ADJUSTED_CLOSE" if close is None and close_reason is None else None,
    ) if x is not None)
    status: MetricStatus = ("STALE" if "STALE_IV30D" in reasons else
                            "MISSING" if close is None and iv is None else
                            "PARTIAL" if reasons else "OK")
    return EventSnapshotV1(
        phase="pre" if phase == "pre" else "post", session_date=session.session_date,
        close_ns=session.close_ns, iv_rank=rank, iv_sample_count=count,
        iv_value=iv.value if iv is not None else None,
        adjusted_close=close.value if close is not None else None,
        status=status, reasons=reasons,
        evidence_ids=tuple(
            f"{x.source}:{x.native_id}:{x.revision}:{x.adjustment_version or '-'}"
            for x in (iv, close) if x is not None
        ),
        available_ns=max((x.available_ns for x in (iv, close) if x is not None),
                         default=None),
    )


def _local(ns: int, zone: tzinfo, name: str) -> str:
    local = _utc_datetime(ns).astimezone(zone)
    rendered = local.isoformat(timespec="microseconds")
    rendered = rendered.replace(
        f".{local.microsecond:06d}", f".{ns % 1_000_000_000:09d}", 1
    )
    return f"{rendered} [{name}]"


def _overlay_items(
    items: Sequence[FlowOverlayEvidenceV1 | DpOverlayEvidenceV1],
    ticker: str, asof_ns: int,
) -> list[FlowOverlayEvidenceV1 | DpOverlayEvidenceV1]:
    latest: dict[tuple[str, ...], FlowOverlayEvidenceV1 | DpOverlayEvidenceV1] = {}
    for item in sorted(items, key=lambda x: (x.observed_ns, x.available_ns, x.source,
                                            x.dataset, x.schema_version, x.metric_name,
                                            x.metric_unit, x.series_id, x.native_id,
                                            x.revision)):
        if (item.ticker != ticker or item.available_ns > asof_ns
                or item.observed_ns > asof_ns
                or item.feed_state not in ("SYNTHETIC", "ENTITLED")):
            continue
        key = (item.source, item.dataset, item.schema_version, item.metric_name,
               item.metric_unit, item.series_id, item.native_id)
        old = latest.get(key)
        if old is None or item.revision > old.revision:
            latest[key] = item
        elif old.revision == item.revision and old != item:
            raise ValueError("conflicting overlay evidence revision")
    return sorted(latest.values(), key=lambda x: (x.observed_ns, x.available_ns,
                                                  x.source, x.dataset, x.schema_version,
                                                  x.metric_name, x.metric_unit, x.series_id,
                                                  x.native_id, x.revision))


def _overlay_series(item: FlowOverlayEvidenceV1 | DpOverlayEvidenceV1) -> tuple[str, ...]:
    return (item.source, item.dataset, item.schema_version, item.metric_name,
            item.metric_unit, item.series_id)


def _overlays(
    kind: str, items: Sequence[FlowOverlayEvidenceV1 | DpOverlayEvidenceV1],
    revision: CorporateEventRevisionV1, sessions: Sequence[ExchangeSessionV1],
    zone: tzinfo, asof_ns: int, policy: EventMetricPolicyV1,
) -> tuple[EventOverlayV1, ...]:
    expected_type = FlowOverlayEvidenceV1 if kind == "flow" else DpOverlayEvidenceV1
    if any(not isinstance(item, expected_type) for item in items):
        raise ValueError(f"{kind} overlay requires its typed upstream evidence")
    before, after = ((policy.flow_window_before_days, policy.flow_window_after_days)
                     if kind == "flow" else (policy.dp_window_before_days,
                                              policy.dp_window_after_days))
    first_day = _utc_datetime(revision.event_start_ns).astimezone(zone).date()
    last_day = _utc_datetime(revision.event_end_ns).astimezone(zone).date()
    visible = _overlay_items(items, revision.ticker, asof_ns)
    result: list[EventOverlayV1] = []
    for item in visible:
        item_day = _utc_datetime(item.observed_ns).astimezone(zone).date()
        if not first_day - timedelta(days=before) <= item_day <= last_day + timedelta(days=after):
            continue
        prior = [s for s in sessions if s.session_date < item_day][-policy.overlay_baseline_days:]
        baseline: list[Decimal] = []
        comparable = [x for x in visible if _overlay_series(x) == _overlay_series(item)]
        for session in prior:
            per_day = [x for x in comparable
                       if session.open_ns <= x.observed_ns <= session.close_ns]
            if per_day:
                baseline.append(per_day[-1].metric_value)
        reason: str | None = None
        z: Decimal | None = None
        crossed = False
        if len(baseline) < policy.min_overlay_samples:
            other_source_baseline = any(
                x not in comparable and any(s.open_ns <= x.observed_ns <= s.close_ns
                                            for s in prior)
                for x in visible
            )
            reason = ("SOURCE_MISMATCH" if other_source_baseline else
                      "INSUFFICIENT_OVERLAY_BASELINE")
        else:
            exact_values = [Fraction(x) for x in baseline]
            mean = sum(exact_values, Fraction(0)) / len(exact_values)
            variance = sum(((x - mean) ** 2 for x in exact_values),
                           Fraction(0)) / len(exact_values)
            if variance == 0:
                reason = "ZERO_OVERLAY_VARIANCE"
            else:
                difference = Fraction(item.metric_value) - mean
                threshold = Fraction(policy.overlay_z_threshold)
                crossed = (difference >= 0 and difference * difference >=
                           threshold * threshold * variance)
                z = (Decimal(difference.numerator) / Decimal(difference.denominator)
                     / (Decimal(variance.numerator) / Decimal(variance.denominator)).sqrt())
        result.append(EventOverlayV1(
            kind="flow" if kind == "flow" else "dp", observed_ns=item.observed_ns,
            z_score=z, threshold_crossed=crossed,
            baseline_count=len(baseline), status="OK" if z is not None else "PARTIAL",
            reason=reason, source_id=(
                f"{item.source}:{item.dataset}:{item.schema_version}:{item.metric_name}:"
                f"{item.metric_unit}:{item.series_id}:{item.native_id}:{item.revision}"
            ),
            policy_version=policy.version,
            metric_value=item.metric_value,
            available_ns=item.available_ns,
            price_band_low=(item.price_band_low if isinstance(item, DpOverlayEvidenceV1)
                            else None),
            price_band_high=(item.price_band_high if isinstance(item, DpOverlayEvidenceV1)
                             else None),
        ))
    return tuple(result)


def _evidence_key(item: EventMarketEvidenceV1) -> str:
    return item.adjustment_version or f"{item.source}:{item.native_id}:{item.revision}"


def _adjusted_pair(
    pre: EventMarketEvidenceV1 | None, post: EventMarketEvidenceV1 | None,
    actions: Sequence[CorporateActionSnapshotV1], asof_ns: int,
) -> tuple[Decimal | None, Decimal | None, int | None, str | None]:
    if pre is None or post is None:
        return None, None, None, "MISSING_ADJUSTED_CLOSE"
    available_ns = max(pre.available_ns, post.available_ns)
    if (pre.adjustment_version and post.adjustment_version
            and pre.adjustment_version == post.adjustment_version):
        return pre.value, post.value, available_ns, None
    key_pre, key_post = _evidence_key(pre), _evidence_key(post)
    visible = [action for action in actions if action.available_ns <= asof_ns]
    action_revisions: dict[tuple[str, str, int], CorporateActionSnapshotV1] = {}
    for action in visible:
        identity = (action.source, action.snapshot_id, action.available_ns)
        prior = action_revisions.get(identity)
        if prior is not None and prior != action:
            return None, None, None, "ADJUSTMENT_VERSION_MISMATCH"
        action_revisions[identity] = action
    matching = [action for action in actions if action.available_ns <= asof_ns
                and key_pre in dict(action.factors) and key_post in dict(action.factors)]
    if not matching:
        return None, None, None, "ADJUSTMENT_VERSION_MISMATCH"
    chosen = max(matching, key=lambda x: (x.available_ns, x.source, x.snapshot_id,
                                          x.basis_version, x.factors))
    factors = dict(chosen.factors)
    return (_exact_decimal(Fraction(pre.value) * Fraction(factors[key_pre])),
            _exact_decimal(Fraction(post.value) * Fraction(factors[key_post])),
            max(available_ns, chosen.available_ns), None)


def _expiry_window(
    pre: ExchangeSessionV1, expiry_ns: int | None,
    sessions: Sequence[ExchangeSessionV1], event_ns: int,
) -> tuple[ExpectedMoveWindowV1 | None, Decimal | None, str | None]:
    if expiry_ns is None:
        return None, None, "EXPIRY_MISSING"
    if (expiry_ns <= pre.close_ns or not sessions
            or expiry_ns > sessions[-1].close_ns + 2 * _DAY_NS):
        return None, None, "WINDOW_MISMATCH"
    end = next((s for s in reversed(sessions) if s.close_ns <= expiry_ns), None)
    anchor = next((i for i, s in enumerate(sessions) if s.close_ns > event_ns), None)
    if end is None or anchor is None:
        return None, None, "WINDOW_MISMATCH"
    start_index = next(i for i, s in enumerate(sessions) if s.session_date == pre.session_date)
    end_index = next(i for i, s in enumerate(sessions) if s.session_date == end.session_date)
    if start_index < max(0, anchor - 7) or end_index > anchor + 2 or end_index < start_index:
        return None, None, "WINDOW_MISMATCH"
    return (ExpectedMoveWindowV1(pre.session_date, end.session_date),
            Decimal(expiry_ns - pre.close_ns) / Decimal(_DAY_NS), None)


def _straddle_midpoint(item: EventMarketEvidenceV1, spot: Decimal,
                       policy: EventMetricPolicyV1) -> tuple[Decimal | None, str | None]:
    quotes = (item.call_bid, item.call_ask, item.put_bid, item.put_ask)
    if item.strike is None or any(x is None for x in quotes):
        return None, "INCOMPLETE_STRADDLE_QUOTE"
    if abs(Fraction(item.strike) - Fraction(spot)) > (
        Fraction(policy.atm_tolerance_relative) * Fraction(spot)
    ):
        return None, "NOT_ATM"
    midpoint = sum((Fraction(x) for x in quotes if x is not None),
                   Fraction(0)) / 2
    if midpoint != Fraction(item.value):
        return None, "QUOTE_CONFLICT"
    return item.value, None


def _alerts(
    revision: CorporateEventRevisionV1, pre: EventSnapshotV1 | None,
    post: EventSnapshotV1 | None, overlays: tuple[EventOverlayV1, ...],
    expected_move: Decimal | None, realized_move: Decimal | None,
    expected_available_ns: int | None, realized_available_ns: int | None,
) -> tuple[AlertCandidateV1, ...]:
    def candidate(kind: str, key: str, scheduled_ns: int,
                  available_ns: int) -> AlertCandidateV1:
        return AlertCandidateV1(
            key=key, kind=kind, event_id=revision.event_id,
            scheduled_ns=scheduled_ns, available_ns=available_ns,
            due_ns=max(scheduled_ns, available_ns),
        )

    if revision.state == "canceled":
        return (candidate("state_change", f"{revision.event_id}:state:"
                          f"{revision.vendor_revision}", revision.published_ns,
                          revision.available_ns),)
    candidates: list[AlertCandidateV1] = []
    if revision.precision == "exact":
        for hours in (24, 1):
            candidates.append(candidate(
                "upcoming", f"{revision.event_id}:upcoming:{hours}h",
                revision.event_start_ns - hours * 3_600_000_000_000,
                revision.available_ns,
            ))
    if revision.state in ("revised", "delayed"):
        candidates.append(candidate(
            "state_change", f"{revision.event_id}:state:{revision.vendor_revision}",
            revision.published_ns, revision.available_ns,
        ))
    for phase, snapshot, move, move_available in (
        ("pre", pre, expected_move, expected_available_ns),
        ("post", post, realized_move, realized_available_ns),
    ):
        if snapshot is not None and snapshot.status == "OK" and move is not None:
            candidates.append(candidate(
                f"{phase}_metrics_ready", f"{revision.event_id}:{phase}_metrics",
                snapshot.close_ns, max(revision.available_ns,
                                       snapshot.available_ns or 0, move_available or 0),
            ))
    for overlay in overlays:
        if overlay.threshold_crossed:
            candidates.append(candidate(
                "anomaly", f"{revision.event_id}:anomaly:{overlay.source_id}",
                overlay.observed_ns, max(overlay.available_ns, revision.available_ns),
            ))
    return tuple(candidates)


def _evaluate_event_impl(
    *, revisions: Sequence[CorporateEventRevisionV1],
    evidence: Sequence[EventMarketEvidenceV1], sessions: Sequence[ExchangeSessionV1],
    tzdata: Mapping[str, tzinfo], requested_tz: str, asof_ns: int,
    policy: EventMetricPolicyV1 | None = None,
    flow_evidence: Sequence[FlowOverlayEvidenceV1] = (),
    dp_evidence: Sequence[DpOverlayEvidenceV1] = (),
    corporate_actions: Sequence[CorporateActionSnapshotV1] = (),
) -> EventMetricsV1:
    """Calculate an as-of event result without I/O, clock reads, or timezone lookup."""
    if policy is None:
        policy = EventMetricPolicyV1()
    requested_zone = _zone(tzdata, requested_tz)
    try:
        revision = select_revision(revisions, asof_ns)
    except AmbiguousEventIdentityError as exc:
        return _empty(asof_ns, policy, "QUARANTINED", str(exc))
    if revision is None:
        return _empty(asof_ns, policy, "MISSING", "NO_AVAILABLE_EVENT_REVISION")
    if revision.feed_state not in ("SYNTHETIC", "ENTITLED"):
        return _empty(asof_ns, policy, "MISSING", f"{revision.feed_state}_EVENT_FEED",
                      revision=revision)
    exchange_zone = _zone(tzdata, revision.exchange_tz)
    ordered = sorted(sessions, key=lambda s: s.close_ns)
    if len({s.session_date for s in ordered}) != len(ordered):
        raise ValueError("duplicate exchange session date")
    if any(_utc_datetime(s.close_ns).astimezone(exchange_zone).date() != s.session_date
           for s in ordered):
        raise ValueError("exchange session date conflicts with injected timezone")
    if any(left.close_ns >= right.open_ns for left, right in pairwise(ordered)):
        raise ValueError("overlapping exchange sessions")
    pre_session = next((s for s in reversed(ordered) if s.close_ns < revision.event_start_ns), None)
    post_session = next((s for s in ordered if s.close_ns > revision.event_end_ns), None)
    try:
        available = _available_market(evidence, asof_ns, revision.ticker)
    except QuoteConflictError:
        return _empty(asof_ns, policy, "QUARANTINED", "QUOTE_CONFLICT", revision)
    pre = (_snapshot("pre", pre_session, available, ordered, policy)
           if pre_session is not None and pre_session.close_ns <= asof_ns else None)
    post = (_snapshot("post", post_session, available, ordered, policy)
            if post_session is not None and post_session.close_ns <= asof_ns else None)
    reasons: list[str] = []
    if pre is None:
        reasons.append("PRE_CLOSE_UNAVAILABLE")
    if post is None:
        reasons.append("POST_CLOSE_UNAVAILABLE")
    if pre is not None:
        reasons.extend(pre.reasons)
    if post is not None:
        reasons.extend(post.reasons)
    if any(x.ticker == revision.ticker and x.available_ns <= asof_ns
           and x.feed_state in ("UNENTITLED", "UNVERIFIED") for x in evidence):
        reasons.append("UNENTITLED_OR_UNVERIFIED_MARKET_FEED")
    if any(x.ticker == revision.ticker and x.available_ns <= asof_ns
           and x.feed_state in ("UNENTITLED", "UNVERIFIED") for x in flow_evidence):
        reasons.append("UNENTITLED_OR_UNVERIFIED_FLOW_FEED")
    if any(x.ticker == revision.ticker and x.available_ns <= asof_ns
           and x.feed_state in ("UNENTITLED", "UNVERIFIED") for x in dp_evidence):
        reasons.append("UNENTITLED_OR_UNVERIFIED_DP_FEED")

    em_relative: Decimal | None = None
    em_relative_exact: Fraction | None = None
    em_currency: Decimal | None = None
    expected_window: ExpectedMoveWindowV1 | None = None
    realized_window: ExpectedMoveWindowV1 | None = None
    tenor_days: Decimal | None = None
    iv_tenor_days: int | None = None
    expected_available_ns: int | None = None
    if pre is not None and pre_session is not None:
        spot, spot_stale, spot_reason = _at_close(
            available, "spot", pre.close_ns, policy.max_evidence_age_ns, policy
        )
        if spot_reason:
            reasons.append(spot_reason)
        elif spot is None:
            reasons.append("MISSING_SPOT")
        elif spot_stale:
            reasons.append("STALE_SPOT")
        else:
            kind = "straddle" if policy.expected_method == "straddle" else "iv30d"
            if kind == "straddle":
                quote, quote_stale, quote_reason = _front_week_straddle(
                    available, pre.close_ns,
                    post_session.close_ns if post_session is not None else None,
                    spot.value, policy
                )
            else:
                quote, quote_stale, quote_reason = _at_close(
                    available, kind, pre.close_ns, policy.max_evidence_age_ns, policy
                )
            if quote_reason:
                reasons.append(quote_reason)
            elif quote is None:
                reasons.append("MISSING_STRADDLE" if kind == "straddle" else "MISSING_IV30D")
            elif quote_stale:
                reasons.append("STALE_STRADDLE" if kind == "straddle" else "STALE_IV30D")
            else:
                expected_window, tenor_days, window_reason = _expiry_window(
                    pre_session, quote.option_expiry_ns, ordered, revision.event_end_ns
                )
                if window_reason:
                    reasons.append(window_reason)
                elif (policy.expected_window is not None
                      and policy.expected_window != expected_window):
                    reasons.append("WINDOW_MISMATCH")
                if expected_window is not None and tenor_days is not None:
                    if kind == "straddle":
                        midpoint, midpoint_reason = _straddle_midpoint(quote, spot.value, policy)
                        if midpoint_reason:
                            reasons.append(midpoint_reason)
                        elif midpoint is not None:
                            em_relative_exact = Fraction(midpoint) / Fraction(spot.value)
                            em_relative = _rounded_fraction(em_relative_exact)
                            em_currency = midpoint
                    elif pre.iv_value is None or "QUOTE_CONFLICT" in pre.reasons:
                        reasons.append("MISSING_OR_CONFLICTING_IV30D_FOR_EM")
                    else:
                        iv_tenor_days = 30
                        em_currency = (spot.value * quote.value
                                       * (tenor_days / Decimal(policy.day_count_basis)).sqrt())
                        em_relative = em_currency / spot.value
                    if em_relative is not None:
                        expected_available_ns = max(spot.available_ns, quote.available_ns)

    realized: Decimal | None = None
    simple_pct: Decimal | None = None
    simple_dollar: Decimal | None = None
    realized_available_ns: int | None = None
    pre_value: Decimal | None = None
    post_value: Decimal | None = None
    if (pre is not None and post is not None
            and pre_session is not None and post_session is not None):
        realized_window = ExpectedMoveWindowV1(pre_session.session_date, post_session.session_date)
        pre_close, pre_conflict = _choose_quote(
            [x for x in available if x.kind == "adjusted_close"
             and x.observed_ns == pre_session.close_ns], policy
        )
        post_close, post_conflict = _choose_quote(
            [x for x in available if x.kind == "adjusted_close"
             and x.observed_ns == post_session.close_ns], policy
        )
        if pre_conflict or post_conflict:
            reasons.append("QUOTE_CONFLICT")
        else:
            pre_value, post_value, realized_available_ns, adjustment_reason = _adjusted_pair(
                pre_close, post_close, corporate_actions, asof_ns
            )
            if adjustment_reason:
                reasons.append(adjustment_reason)
            elif pre_value is not None and post_value is not None:
                ratio = post_value / pre_value
                realized = abs(ratio.ln())
                simple_pct = _rounded_fraction(
                    (Fraction(post_value) - Fraction(pre_value))
                    * 100 / Fraction(pre_value)
                )
                simple_dollar = _exact_decimal(Fraction(post_value) - Fraction(pre_value))

    surprise: Decimal | None = None
    surprise_reason: str | None = None
    if (expected_window is None or realized_window is None
            or expected_window != realized_window
            or (policy.expected_window is not None
                and policy.expected_window != expected_window)):
        surprise_reason = "WINDOW_MISMATCH"
    elif em_relative is None or simple_pct is None:
        surprise_reason = "MISSING_MATCHED_MOVE"
    else:
        assert pre_value is not None and post_value is not None
        surprise = _rounded_fraction(
            abs((Fraction(post_value) - Fraction(pre_value)) / Fraction(pre_value))
            - (em_relative_exact if em_relative_exact is not None else Fraction(em_relative))
        )

    overlays = (_overlays("flow", flow_evidence, revision, ordered, exchange_zone, asof_ns, policy)
                + _overlays("dp", dp_evidence, revision, ordered, exchange_zone, asof_ns, policy))
    if any(x.status != "OK" for x in overlays):
        reasons.append("PARTIAL_OVERLAY")
    status: MetricStatus = ("CANCELED" if revision.state == "canceled" else
                            "UNAVAILABLE" if "EXPECTED_MOVE_UNAVAILABLE" in reasons else
                            "STALE" if any(x.startswith("STALE_") for x in reasons) else
                            "MISSING" if not available else
                            "OK" if not reasons else "PARTIAL")
    alerts = _alerts(revision, pre, post, overlays, em_relative, realized,
                     expected_available_ns, realized_available_ns)
    canonical_actions = tuple(sorted(
        (x for x in corporate_actions if x.available_ns <= asof_ns),
        key=lambda x: (x.available_ns, x.source, x.snapshot_id,
                       x.basis_version, x.factors),
    ))
    result_version = _digest(
        revision, tuple(available), tuple(ordered), canonical_actions, policy,
        pre, post, em_relative, em_currency, expected_window, realized_window,
        tenor_days, realized, simple_pct, simple_dollar, surprise, overlays, alerts,
        status, tuple(dict.fromkeys(reasons)),
    )
    return _issue_event_metrics(
        event_id=revision.event_id, vendor_revision=revision.vendor_revision,
        asof_ns=asof_ns, policy_version=policy.version,
        result_version=result_version,
        status=status,
        reasons=tuple(dict.fromkeys(reasons)), revision=revision, pre=pre, post=post,
        expected_method=policy.expected_method, expected_window=expected_window,
        realized_window=realized_window,
        days_to_window=tenor_days, day_count_basis=policy.day_count_basis,
        iv_tenor_days=iv_tenor_days,
        expected_abs_move_relative=em_relative, expected_abs_move_currency=em_currency,
        realized_abs_log_move=realized, signed_simple_percent=simple_pct,
        signed_dollar_move=simple_dollar, surprise=surprise,
        surprise_unit="relative" if surprise is not None else None,
        surprise_method_id=("abs_simple_relative_minus_expected_relative:v1"
                            if surprise is not None else None),
        surprise_reason=surprise_reason, overlays=overlays, alert_candidates=alerts,
        event_start_exchange_local=_local(revision.event_start_ns, exchange_zone,
                                          revision.exchange_tz),
        event_end_exchange_local=_local(revision.event_end_ns, exchange_zone,
                                        revision.exchange_tz),
        event_start_requested_local=_local(revision.event_start_ns, requested_zone, requested_tz),
        event_end_requested_local=_local(revision.event_end_ns, requested_zone, requested_tz),
    )


def evaluate_event(
    *, revisions: Sequence[CorporateEventRevisionV1],
    evidence: Sequence[EventMarketEvidenceV1], sessions: Sequence[ExchangeSessionV1],
    tzdata: Mapping[str, tzinfo], requested_tz: str, asof_ns: int,
    policy: EventMetricPolicyV1 | None = None,
    flow_evidence: Sequence[FlowOverlayEvidenceV1] = (),
    dp_evidence: Sequence[DpOverlayEvidenceV1] = (),
    corporate_actions: Sequence[CorporateActionSnapshotV1] = (),
) -> EventMetricsV1:
    """Evaluate at one as-of time with an explicit Decimal arithmetic context."""
    with localcontext(DECIMAL_CONTEXT):
        return _evaluate_event_impl(
            revisions=revisions, evidence=evidence, sessions=sessions,
            tzdata=tzdata, requested_tz=requested_tz, asof_ns=asof_ns,
            policy=policy, flow_evidence=flow_evidence, dp_evidence=dp_evidence,
            corporate_actions=corporate_actions,
        )


def _empty(
    asof_ns: int, policy: EventMetricPolicyV1, status: MetricStatus, reason: str,
    revision: CorporateEventRevisionV1 | None = None,
) -> EventMetricsV1:
    return _issue_event_metrics(
        event_id=revision.event_id if revision is not None else None,
        vendor_revision=revision.vendor_revision if revision is not None else None,
        asof_ns=asof_ns,
        policy_version=policy.version, result_version=_digest(revision, policy, status, reason),
        status=status, reasons=(reason,),
        revision=revision, pre=None, post=None, expected_method=None, expected_window=None,
        realized_window=None,
        days_to_window=None, day_count_basis=None, iv_tenor_days=None,
        expected_abs_move_relative=None, expected_abs_move_currency=None,
        realized_abs_log_move=None, signed_simple_percent=None, signed_dollar_move=None,
        surprise=None, surprise_unit=None, surprise_method_id=None,
        surprise_reason=reason, overlays=(), alert_candidates=(),
        event_start_exchange_local=None, event_end_exchange_local=None,
        event_start_requested_local=None, event_end_requested_local=None,
    )
