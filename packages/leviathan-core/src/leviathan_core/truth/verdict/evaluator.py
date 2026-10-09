"""Pure, deterministic evaluation of one immutable truth evidence snapshot."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import fields, is_dataclass
from datetime import datetime
from decimal import ROUND_HALF_EVEN, Context, Decimal, localcontext
from enum import Enum
from typing import Any

from leviathan_core.truth.verdict.models import (
    Action,
    ClockSkewError,
    InvalidTruthInputError,
    ReasonCode,
    Side,
    SourceState,
    TruthEvidenceV1,
    TruthPolicyV1,
    TruthRequestV1,
    TruthSource,
    TruthVerdictV1,
    Verdict,
    _utc,
)

_MISSING = {
    TruthSource.ORDER_BOOK: ReasonCode.ORDERBOOK_MISSING,
    TruthSource.OPTIONS_FLOW: ReasonCode.OPTIONS_MISSING,
    TruthSource.EVENTS: ReasonCode.EVENTS_MISSING,
    TruthSource.SENTIMENT: ReasonCode.SENTIMENT_MISSING,
}
_STALE = {
    TruthSource.ORDER_BOOK: ReasonCode.ORDERBOOK_STALE,
    TruthSource.OPTIONS_FLOW: ReasonCode.OPTIONS_STALE,
    TruthSource.EVENTS: ReasonCode.EVENTS_STALE,
    TruthSource.SENTIMENT: ReasonCode.SENTIMENT_STALE,
}
_KERNEL_CONTEXT = Context(prec=34, rounding=ROUND_HALF_EVEN, Emax=999999, Emin=-999999)
for _signal in _KERNEL_CONTEXT.traps:
    _KERNEL_CONTEXT.traps[_signal] = True


def _canonical(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return {part.name: _canonical(getattr(value, part.name)) for part in fields(value)}
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Decimal):
        rendered = format(value, "f")
        if "." in rendered:
            rendered = rendered.rstrip("0").rstrip(".")
        return "0" if rendered in ("0", "-0") else rendered
    if isinstance(value, datetime):
        return value.isoformat(timespec="microseconds")
    if isinstance(value, (set, frozenset)):
        return sorted(_canonical(item) for item in value)
    if isinstance(value, (tuple, list)):
        return [_canonical(item) for item in value]
    if isinstance(value, Mapping):
        return {str(key): _canonical(item) for key, item in value.items()}
    return value


def _digest(
    request: TruthRequestV1,
    policy: TruthPolicyV1 | None,
    evidence: tuple[TruthEvidenceV1, ...],
    evaluation_ts: datetime,
    missing_policy_verdict: Verdict,
) -> str:
    payload = _canonical(
        {
            "schema": "TruthVerdictV1",
            "request": request,
            "policy": policy,
            "evidence": evidence,
            "evaluation_ts": evaluation_ts,
            "missing_policy_verdict": missing_policy_verdict,
        }
    )
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("ascii")).hexdigest()


def _age_ms(evaluation_ts: datetime, observed_at: datetime) -> int:
    difference = evaluation_ts - observed_at
    if difference.days < 0:
        raise InvalidTruthInputError("source timestamp is later than evaluation time")
    microseconds = (
        difference.days * 86_400_000_000 + difference.seconds * 1_000_000 + difference.microseconds
    )
    return (microseconds + 999) // 1000


def _check_book(
    request: TruthRequestV1, policy: TruthPolicyV1, item: TruthEvidenceV1, hard: set[ReasonCode]
) -> None:
    book = item.order_book
    assert book is not None
    if book.spread_bps > policy.max_spread_bps:
        hard.add(ReasonCode.SPREAD_BREACH)
    if book.depth_near_qty < policy.min_depth_qty or book.depth_far_qty < policy.min_depth_qty:
        hard.add(ReasonCode.DEPTH_BREACH)
    if book.crossed:
        hard.add(ReasonCode.CROSSED_MARKET)
    if book.locked:
        hard.add(ReasonCode.LOCKED_MARKET)
    if book.halt_active:
        hard.add(ReasonCode.HALT_ACTIVE)
    if book.luld_active:
        hard.add(ReasonCode.LULD_ACTIVE)
    if (request.side is Side.BUY and book.imbalance < policy.min_imbalance) or (
        request.side is Side.SELL and book.imbalance > policy.min_imbalance.copy_negate()
    ):
        hard.add(ReasonCode.IMBALANCE_BREACH)
    if book.est_slippage_bps > policy.max_slippage_bps:
        hard.add(ReasonCode.SLIPPAGE_BREACH)


def _check_options(
    request: TruthRequestV1, policy: TruthPolicyV1, item: TruthEvidenceV1, soft: set[ReasonCode]
) -> None:
    options = item.options_flow
    assert options is not None
    if not options.directional:
        soft.add(ReasonCode.FLOW_WEAK)
        return
    aligned = options.flow_score if request.side is Side.BUY else options.flow_score.copy_negate()
    if aligned <= policy.flow_contradiction_gap.copy_negate():
        soft.add(ReasonCode.FLOW_CONTRADICT)
    elif aligned < policy.min_flow_score or options.unusual_volume_ratio < policy.min_uvr:
        soft.add(ReasonCode.FLOW_WEAK)


def evaluate_truth(
    request: TruthRequestV1,
    policy: TruthPolicyV1 | None,
    evidence: Iterable[TruthEvidenceV1],
    *,
    evaluation_ts: datetime,
    missing_policy_verdict: Verdict = Verdict.SOFT_FAIL,
) -> TruthVerdictV1:
    """Evaluate one supplied snapshot; never consult a clock, provider, or route guard."""
    with localcontext(_KERNEL_CONTEXT):
        return _evaluate_truth(request, policy, evidence, evaluation_ts, missing_policy_verdict)


def _evaluate_truth(
    request: TruthRequestV1,
    policy: TruthPolicyV1 | None,
    evidence: Iterable[TruthEvidenceV1],
    evaluation_ts: datetime,
    missing_policy_verdict: Verdict,
) -> TruthVerdictV1:
    if not isinstance(request, TruthRequestV1) or (
        policy is not None and not isinstance(policy, TruthPolicyV1)
    ):
        raise InvalidTruthInputError("request or policy has the wrong type")
    if not isinstance(missing_policy_verdict, Verdict) or missing_policy_verdict not in (
        Verdict.SOFT_FAIL,
        Verdict.HARD_FAIL,
    ):
        raise InvalidTruthInputError("missing_policy_verdict must be SOFT_FAIL or HARD_FAIL")
    now = _utc(evaluation_ts, "evaluation_ts")
    by_source: dict[TruthSource, TruthEvidenceV1] = {}
    try:
        for item in evidence:
            if not isinstance(item, TruthEvidenceV1):
                raise InvalidTruthInputError("evidence has the wrong type")
            if item.source in by_source:
                raise InvalidTruthInputError("duplicate truth source")
            by_source[item.source] = item
    except TypeError:
        raise InvalidTruthInputError("evidence must be iterable") from None
    for source in TruthSource:
        by_source.setdefault(source, TruthEvidenceV1(source, "unprovided", SourceState.MISSING))
    snapshot = tuple(
        by_source[source] for source in sorted(TruthSource, key=lambda source: source.value)
    )
    freshness: dict[TruthSource, int | None] = {}
    timestamps: dict[TruthSource, datetime | None] = {}
    for item in snapshot:
        timestamps[item.source] = item.observed_at
        freshness[item.source] = _age_ms(now, item.observed_at) if item.observed_at else None

    if policy is not None:
        difference = now - request.client_timestamp
        skew_us = abs(
            difference.days * 86_400_000_000
            + difference.seconds * 1_000_000
            + difference.microseconds
        )
        if skew_us > policy.max_clock_skew_ms * 1000:
            raise ClockSkewError("client clock skew exceeds policy bound")

    hard: set[ReasonCode] = set()
    unknown: set[ReasonCode] = set()
    soft: set[ReasonCode] = set()
    notes: set[ReasonCode] = set()
    if policy is None:
        (hard if missing_policy_verdict is Verdict.HARD_FAIL else soft).add(
            ReasonCode.POLICY_MISSING
        )
    else:
        usable_sources = 0
        limits = {
            TruthSource.ORDER_BOOK: policy.orderbook_max_age_ms,
            TruthSource.OPTIONS_FLOW: policy.options_max_age_ms,
            TruthSource.EVENTS: policy.events_max_age_ms,
            TruthSource.SENTIMENT: policy.sentiment_max_age_ms,
        }
        instrument_class = policy.instrument_classes.get(request.instrument_id)
        class_matches = (
            instrument_class is not None and request.asset_class == instrument_class.value
        )
        applicable_sources = (
            policy.applicable_sources_by_class.get(instrument_class)
            if class_matches and instrument_class is not None
            else None
        )
        for item in snapshot:
            if item.state is SourceState.NOT_APPLICABLE:
                authorized = (
                    applicable_sources is not None
                    and item.source not in applicable_sources
                    and item.source not in policy.required_sources
                )
                if not authorized:
                    unknown.add(_MISSING[item.source])
                continue
            age = freshness[item.source]
            failure = (
                _MISSING[item.source]
                if item.state is SourceState.MISSING
                else (
                    _STALE[item.source] if age is not None and age > limits[item.source] else None
                )
            )
            if failure is not None:
                if item.source in policy.required_sources:
                    if policy.allow_degrade:
                        soft.update((failure, ReasonCode.DEGRADE_AUTHORIZED))
                    else:
                        unknown.add(failure)
                continue
            if item.state is not SourceState.AVAILABLE:
                continue
            prior_failures = len(hard) + len(soft)
            if item.source is TruthSource.ORDER_BOOK:
                _check_book(request, policy, item, hard)
            elif item.source is TruthSource.OPTIONS_FLOW:
                _check_options(request, policy, item, soft)
            elif item.source is TruthSource.EVENTS:
                assert item.events is not None
                if item.events.embargo_active:
                    if request.action is Action.EXIT and policy.exit_override:
                        notes.add(ReasonCode.EXIT_DURING_EMBARGO)
                    else:
                        hard.add(ReasonCode.EVENT_EMBARGO)
            else:
                assert item.sentiment is not None
                if not policy.min_sentiment <= item.sentiment.score <= policy.max_sentiment:
                    (hard if policy.on_sentiment_breach is Verdict.HARD_FAIL else soft).add(
                        ReasonCode.SENTIMENT_BREACH
                    )
            if len(hard) + len(soft) == prior_failures and (
                applicable_sources is None or item.source in applicable_sources
            ):
                usable_sources += 1
        if all(item.state is SourceState.NOT_APPLICABLE for item in snapshot):
            unknown.add(ReasonCode.NO_APPLICABLE_EVIDENCE)
        if usable_sources == 0:
            unknown.add(ReasonCode.NO_USABLE_EVIDENCE)
        elif usable_sources < policy.min_usable_sources:
            unknown.add(ReasonCode.INSUFFICIENT_USABLE_EVIDENCE)

    verdict = (
        Verdict.HARD_FAIL
        if hard
        else Verdict.UNKNOWN
        if unknown
        else Verdict.SOFT_FAIL
        if soft
        else Verdict.PASS
    )
    reasons = tuple(sorted(hard | unknown | soft | notes, key=lambda code: code.value))
    return TruthVerdictV1(
        verdict=verdict,
        reason_codes=reasons,
        data_freshness_ms=freshness,
        source_timestamps=timestamps,
        evaluation_ts=now,
        policy_id=policy.policy_id if policy else None,
        policy_version=policy.version if policy else None,
        trace_id=request.request_id,
        hash_id=_digest(request, policy, snapshot, now, missing_policy_verdict),
    )
