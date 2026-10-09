"""Deterministic COT vintage selection, aggregation, percentile and tags."""

from collections import defaultdict
from dataclasses import replace
from datetime import date, timedelta
from decimal import (
    ROUND_HALF_EVEN,
    Context,
    Decimal,
    DivisionByZero,
    FloatOperation,
    Inexact,
    InvalidOperation,
    Overflow,
    localcontext,
)
from fractions import Fraction
from typing import Literal

from leviathan_core.macro_cot.models import (
    _COT_RESULT_ISSUE_TOKEN,
    COTMarketMapV1,
    COTPolicyV1,
    COTReportVintageV1,
    COTResultV1,
    COTSnapshotV1,
    COTValidationError,
    canonical_decimal,
    validate_policy_bounds,
)

_FAMILY = "Disaggregated Futures"
_KERNEL_CONTEXT = Context(
    prec=34,
    rounding=ROUND_HALF_EVEN,
    traps=[InvalidOperation, DivisionByZero, Overflow, FloatOperation, Inexact],
)
_DISPLAY_CONTEXT = Context(
    prec=34,
    rounding=ROUND_HALF_EVEN,
    traps=[InvalidOperation, DivisionByZero, Overflow, FloatOperation],
)
_NS_PER_DAY = 86_400_000_000_000
_EPOCH = date(1970, 1, 1)


def _decimal(value: object, name: str, *, nonnegative: bool = False) -> Decimal:
    bounded = canonical_decimal(value, name)
    if nonnegative and bounded < 0:
        raise COTValidationError(f"{name} must be nonnegative")
    return bounded


def _validate_mapping(mapping: COTMarketMapV1, policy: COTPolicyV1) -> None:
    if not mapping.market_id or not mapping.version:
        raise COTValidationError("market_id and mapping version are required")
    if not isinstance(mapping.effective_from, date):
        raise COTValidationError("mapping effective_from must be a date")
    if mapping.effective_to is not None and mapping.effective_to <= mapping.effective_from:
        raise COTValidationError("mapping effective_to must follow effective_from")
    if not mapping.constituent_ids or len(set(mapping.constituent_ids)) != len(
        mapping.constituent_ids
    ):
        raise COTValidationError(
            "constituent_ids must be nonempty and unique", reason_code="MAPPING_AMBIGUOUS"
        )
    if any(not ident or ident != ident.strip() for ident in mapping.constituent_ids):
        raise COTValidationError(
            "constituent_ids contains an invalid identifier", reason_code="MAPPING_AMBIGUOUS"
        )
    codes = mapping.constituent_codes
    if (
        len(codes) != len(mapping.constituent_ids)
        or any(len(pair) != 2 for pair in codes)
        or {ident for ident, _ in codes} != set(mapping.constituent_ids)
        or len({ident for ident, _ in codes}) != len(codes)
        or len({code for _, code in codes}) != len(codes)
        or any(not code or code != code.strip() for _, code in codes)
    ):
        raise COTValidationError(
            "constituent IDs and CFTC codes must form a one-to-one map",
            reason_code="MAPPING_AMBIGUOUS",
        )
    if mapping.driver_weights:
        ids = [driver_id for driver_id, _ in mapping.driver_weights]
        if len(set(ids)) != len(ids) or any(not ident or ident != ident.strip() for ident in ids):
            raise COTValidationError("driver IDs must be nonempty and unique")
        weights = [
            _decimal(weight, "driver weight", nonnegative=True)
            for _, weight in mapping.driver_weights
        ]
        if any(weight > 1 for weight in weights):
            raise COTValidationError("driver weight cannot exceed one")
        if abs(sum((Fraction(weight) for weight in weights), Fraction()) - 1) > Fraction(
            policy.weight_tolerance
        ):
            raise COTValidationError("driver weights must sum to one within tolerance")


def _visible(row: COTReportVintageV1, asof_ns: int) -> bool:
    stamps = (row.published_ns, row.received_ns, row.available_ns)
    if any(stamp is None for stamp in stamps):
        return False
    if any(type(stamp) is not int or stamp < 0 for stamp in stamps if stamp is not None):
        raise COTValidationError("vintage timestamps must be nonnegative UTC nanoseconds")
    published, received, available = stamps
    assert published is not None and received is not None and available is not None
    if max(published, received, available) > asof_ns:
        return False
    if not isinstance(row.report_date, date):
        raise COTValidationError("report_date must be a date")
    report_asof_ns = (row.report_date - _EPOCH).days * _NS_PER_DAY
    if published < report_asof_ns:
        raise COTValidationError(
            "publication precedes report observation date", reason_code="RELEASE_BEFORE_REPORT"
        )
    if published > received or received > available:
        raise COTValidationError("publication, receipt and availability are out of order")
    return True


def _validate_row(row: COTReportVintageV1, policy: COTPolicyV1) -> None:
    if not row.cftc_market_code or not row.constituent_id or not isinstance(row.report_date, date):
        raise COTValidationError("vintage requires a CFTC code, constituent ID and report date")
    if row.report_family != _FAMILY:
        raise COTValidationError("only Disaggregated Futures vintages are supported")
    if row.source not in policy.source_priority:
        raise COTValidationError(
            "unranked source", reason_code="UNRANKED_SOURCE"
        )
    if type(row.revision) is not int or row.revision < 0:
        raise COTValidationError("revision must be a nonnegative integer")
    if type(row.is_preliminary) is not bool:
        raise COTValidationError("is_preliminary must be boolean")
    if row.units != "contracts":
        raise COTValidationError("COT units must be contracts")
    if row.mm_long is None or row.mm_short is None:
        raise COTValidationError("managed-money long and short are required")
    _decimal(row.mm_long, "mm_long", nonnegative=True)
    _decimal(row.mm_short, "mm_short", nonnegative=True)
    _decimal(row.mm_spreading, "mm_spreading", nonnegative=True)
    if _decimal(row.open_interest, "open_interest", nonnegative=True) == 0:
        raise COTValidationError("open_interest must be greater than zero")


def _effective(mapping: COTMarketMapV1, report_date: date) -> bool:
    return report_date >= mapping.effective_from and (
        mapping.effective_to is None or report_date < mapping.effective_to
    )


def _select(
    rows: list[COTReportVintageV1], policy: COTPolicyV1
) -> tuple[COTReportVintageV1, bool, bool]:
    """Prefer finalized rows, then ranked source, then highest revision."""
    source_rank = {source: index for index, source in enumerate(policy.source_priority)}
    finalized = [row for row in rows if not row.is_preliminary]
    pool = finalized or rows
    best_source = min(pool, key=lambda row: source_rank[row.source]).source
    candidates = [row for row in pool if row.source == best_source]
    selected = max(candidates, key=lambda row: row.revision)
    newer_preliminary = bool(
        finalized
        and any(
            row.is_preliminary and row.revision > selected.revision
            for row in rows
        )
    )
    return selected, newer_preliminary, len(rows) > 1


def _display_fraction_decimal(value: Fraction) -> Decimal:
    with localcontext(_DISPLAY_CONTEXT):
        return canonical_decimal(Decimal(value.numerator) / Decimal(value.denominator), "result")


def _aggregate(rows: tuple[COTReportVintageV1, ...]) -> tuple[Decimal, Decimal, Fraction]:
    long = sum((Fraction(row.mm_long) for row in rows if row.mm_long is not None), Fraction())
    short = sum((Fraction(row.mm_short) for row in rows if row.mm_short is not None), Fraction())
    interest = sum((Fraction(row.open_interest) for row in rows), Fraction())
    exact_net = long - short
    net = canonical_decimal(Decimal(exact_net.numerator) / Decimal(exact_net.denominator), "net_mm")
    exact_normalized = exact_net / interest
    return (
        net,
        _display_fraction_decimal(exact_normalized),
        exact_normalized,
    )


def _calculate(snapshot: COTSnapshotV1, policy: COTPolicyV1, asof_ns: int) -> COTResultV1:
    """Calculate one market using only vintages visible at ``asof_ns``.

    The percentile is ``100 * count(normalized_value <= current) / n`` over
    the last ``lookback_reports`` complete, effective-dated report dates,
    including the current report. Ties share the upper rank. The exact Decimal
    value drives tags; only ``percentile_display`` is rounded to one decimal.
    """
    if type(asof_ns) is not int or asof_ns < 0:
        raise COTValidationError("asof_ns must be nonnegative UTC nanoseconds")
    validate_policy_bounds(policy)
    mapping = snapshot.market_map
    _validate_mapping(mapping, policy)

    membership = set(mapping.constituent_ids)
    expected_codes = dict(mapping.constituent_codes)
    visible: list[COTReportVintageV1] = []
    for row in snapshot.vintages:
        if _visible(row, asof_ns):
            visible.append(row)

    if not visible:
        return COTResultV1(
            mapping.market_id, "UNAVAILABLE", asof_ns, mapping.version, policy.version,
            driver_weights=mapping.driver_weights,
            lookback_samples_requested=policy.lookback_reports,
            min_lookback_samples=policy.min_lookback_samples,
            warnings=("NO_PUBLISHED_VINTAGE",), reason_codes=("NO_PUBLISHED_VINTAGE",),
            _issue_token=_COT_RESULT_ISSUE_TOKEN,
        )

    latest_date = max(row.report_date for row in visible)
    if not _effective(mapping, latest_date):
        raise COTValidationError(
            "mapping is not effective for the latest visible report date",
            reason_code="MAPPING_VERSION_NOT_EFFECTIVE",
        )
    pre_mapping_constituents: dict[date, set[str]] = defaultdict(set)
    for row in visible:
        if row.report_date < mapping.effective_from:
            pre_mapping_constituents[row.report_date].add(row.constituent_id)
    pre_mapping_complete = any(
        identifiers == membership for identifiers in pre_mapping_constituents.values()
    )
    visible = [row for row in visible if _effective(mapping, row.report_date)]
    for row in visible:
        if row.constituent_id not in membership:
            raise COTValidationError(
                "unmapped constituent", reason_code="MAPPING_AMBIGUOUS"
            )
        if row.cftc_market_code != expected_codes[row.constituent_id]:
            raise COTValidationError(
                "CFTC code does not match the effective mapping", reason_code="MAPPING_AMBIGUOUS"
            )
        _validate_row(row, policy)

    code_for_id: dict[str, str] = {}
    id_for_code: dict[str, str] = {}
    unique: dict[tuple[str, date, str, int, bool], COTReportVintageV1] = {}
    for row in visible:
        prior_code = code_for_id.setdefault(row.constituent_id, row.cftc_market_code)
        prior_id = id_for_code.setdefault(row.cftc_market_code, row.constituent_id)
        if prior_code != row.cftc_market_code or prior_id != row.constituent_id:
            raise COTValidationError(
                "ambiguous CFTC code to constituent mapping", reason_code="MAPPING_AMBIGUOUS"
            )
        key = (row.constituent_id, row.report_date, row.source, row.revision, row.is_preliminary)
        prior = unique.setdefault(key, row)
        if prior != row:
            raise COTValidationError("conflicting duplicate source/revision vintage")

    by_date: dict[date, dict[str, list[COTReportVintageV1]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for row in unique.values():
        by_date[row.report_date][row.constituent_id].append(row)

    selected: dict[date, tuple[COTReportVintageV1, ...]] = {}
    prelim_flags: dict[date, bool] = {}
    newer_prelim_flags: dict[date, bool] = {}
    revision_flags: dict[date, bool] = {}
    for report_date, constituents in by_date.items():
        chosen: list[COTReportVintageV1] = []
        preliminary = False
        newer_preliminary = False
        revised = False
        for ident in mapping.constituent_ids:
            rows = constituents.get(ident)
            if rows:
                row, newer, has_alternative = _select(rows, policy)
                chosen.append(row)
                preliminary |= row.is_preliminary
                newer_preliminary |= newer
                revised |= has_alternative
        selected[report_date] = tuple(chosen)
        prelim_flags[report_date] = preliminary
        newer_prelim_flags[report_date] = newer_preliminary
        revision_flags[report_date] = revised

    latest_rows = selected[latest_date]
    missing = tuple(sorted(membership - {row.constituent_id for row in latest_rows}))
    base = COTResultV1(
        mapping.market_id,
        "UNAVAILABLE",
        asof_ns,
        mapping.version,
        policy.version,
        driver_weights=mapping.driver_weights,
        report_date=latest_date,
        lookback_samples_requested=policy.lookback_reports,
        min_lookback_samples=policy.min_lookback_samples,
        selected_vintages=latest_rows,
        latest_published_ns=max(row.published_ns or 0 for row in latest_rows),
        latest_received_ns=max(row.received_ns or 0 for row in latest_rows),
        latest_available_ns=max(row.available_ns or 0 for row in latest_rows),
        is_preliminary=prelim_flags[latest_date],
        is_revised=revision_flags[latest_date],
        selected_revision_ids=tuple((row.constituent_id, row.revision) for row in latest_rows),
        newer_preliminary_not_selected=newer_prelim_flags[latest_date],
        _issue_token=_COT_RESULT_ISSUE_TOKEN,
    )
    if missing:
        partial_reasons: tuple[str, ...] = ("MISSING_CONSTITUENTS",)
        if prelim_flags[latest_date]:
            partial_reasons += ("PRELIMINARY_ONLY",)
        return replace(
            base,
            status="DEGRADED",
            warnings=(f"MISSING_CONSTITUENTS:{','.join(missing)}",),
            reason_codes=partial_reasons,
            _issue_token=_COT_RESULT_ISSUE_TOKEN,
        )

    complete_dates = sorted(
        report_date for report_date, rows in selected.items()
        if len(rows) == len(mapping.constituent_ids)
    )
    window_dates = complete_dates[-policy.lookback_reports:]
    values = {report_date: _aggregate(selected[report_date]) for report_date in window_dates}
    net, normalized, exact_normalized = values[latest_date]
    sample_count = len(window_dates)

    previous_date = complete_dates[-2] if len(complete_dates) > 1 else None
    previous_net = None
    previous_exact_normalized = None
    if previous_date is not None:
        previous_net, _, previous_exact_normalized = _aggregate(selected[previous_date])
    current_week = latest_date - timedelta(days=latest_date.weekday())
    previous_week = (
        previous_date - timedelta(days=previous_date.weekday())
        if previous_date is not None else None
    )
    gap = previous_week is not None and (current_week - previous_week).days > 7

    reasons: list[str] = []
    if prelim_flags[latest_date]:
        reasons.append("PRELIMINARY_ONLY")
    if newer_prelim_flags[latest_date]:
        reasons.append("NEWER_PRELIMINARY_NOT_SELECTED")
    if gap:
        reasons.append("MISSING_REPORT_WEEK")
    if sample_count < policy.low_confidence_min_samples:
        reasons.append("LOW_CONFIDENCE")
    if pre_mapping_complete and sample_count < policy.lookback_reports:
        reasons.append("LOOKBACK_TRUNCATED_BY_MAPPING")
    wow_delta_mm = net - previous_net if previous_net is not None else None
    wow_delta_pct_oi = (
        _display_fraction_decimal(exact_normalized - previous_exact_normalized)
        if previous_exact_normalized is not None else None
    )
    if sample_count < policy.min_lookback_samples:
        reasons.append("INSUFFICIENT_HISTORY")
        return replace(
            base,
            status="DEGRADED",
            previous_report_date=previous_date,
            gap=gap,
            net_mm=net,
            net_mm_pct_oi=normalized,
            wow_delta_mm=wow_delta_mm,
            wow_delta_pct_oi=wow_delta_pct_oi,
            sample_count=sample_count,
            lookback_samples_used=sample_count,
            window_start=window_dates[0],
            low_confidence=sample_count < policy.low_confidence_min_samples,
            warnings=tuple(reasons),
            reason_codes=tuple(reasons),
            _issue_token=_COT_RESULT_ISSUE_TOKEN,
        )

    rank = sum(exact <= exact_normalized for _, _, exact in values.values())
    exact_percentile = Fraction(100 * rank, sample_count)
    percentile = _display_fraction_decimal(exact_percentile)
    with localcontext(_DISPLAY_CONTEXT):
        percentile_display = percentile.quantize(Decimal("0.1"), rounding=ROUND_HALF_EVEN)

    contrarian_tag: Literal["contrarian_long", "contrarian_short", "none"]
    if exact_percentile <= Fraction(policy.contrarian_long_max):
        contrarian_tag = "contrarian_long"
    elif exact_percentile >= Fraction(policy.contrarian_short_min):
        contrarian_tag = "contrarian_short"
    else:
        contrarian_tag = "none"
    confirmation_bias: Literal["bias_short_cover", "bias_trend_follow_long", "neutral"]
    if exact_percentile <= Fraction(policy.confirmation_short_cover_max):
        confirmation_bias = "bias_short_cover"
    elif exact_percentile >= Fraction(policy.confirmation_trend_follow_long_min):
        confirmation_bias = "bias_trend_follow_long"
    else:
        confirmation_bias = "neutral"

    return replace(
        base,
        status="OK",
        previous_report_date=previous_date,
        gap=gap,
        net_mm=net,
        net_mm_pct_oi=normalized,
        wow_delta_mm=wow_delta_mm,
        wow_delta_pct_oi=wow_delta_pct_oi,
        sample_count=sample_count,
        lookback_samples_used=sample_count,
        window_start=window_dates[0],
        low_confidence=sample_count < policy.low_confidence_min_samples,
        warnings=tuple(reasons),
        reason_codes=tuple(reasons),
        percentile=percentile,
        percentile_display=percentile_display,
        contrarian_tag=contrarian_tag,
        confirmation_bias=confirmation_bias,
        _issue_token=_COT_RESULT_ISSUE_TOKEN,
    )


def calculate(snapshot: COTSnapshotV1, policy: COTPolicyV1, asof_ns: int) -> COTResultV1:
    """Run a point-in-time replay under a bounded, caller-independent Decimal context."""
    with localcontext(_KERNEL_CONTEXT):
        try:
            return _calculate(snapshot, policy, asof_ns)
        except Inexact as exc:
            raise COTValidationError(
                "exact quantity exceeds working precision", reason_code="PRECISION_EXCEEDED"
            ) from exc
