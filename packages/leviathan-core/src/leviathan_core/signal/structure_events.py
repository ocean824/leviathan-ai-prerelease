import hashlib
import json
from datetime import UTC, datetime
from decimal import Decimal, localcontext
from typing import Literal

from leviathan_core.signal.signal_models import (
    _DECIMAL_CONTEXT,
    ConfirmedStructurePivot,
    StructureEvaluation,
    StructureEvaluationError,
    StructureEventV1,
    StructureGapNoticeV1,
    StructureSignalV1,
    _quality,
)


def _semantic_hash(payload: dict[str, str | tuple[str, ...]]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _event_id(ts_event: datetime, payload: dict[str, str | tuple[str, ...]]) -> str:
    elapsed = ts_event.astimezone(UTC) - datetime(1970, 1, 1, tzinfo=UTC)
    milliseconds = ((elapsed.days * 86400 + elapsed.seconds) * 1000) + elapsed.microseconds // 1000
    if not 0 <= milliseconds < 2**48:
        raise StructureEvaluationError("EVENT_TIME_OUT_OF_RANGE")
    value = (milliseconds << 80) | int(_semantic_hash(payload)[:20], 16)
    alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    return "".join(alphabet[(value >> shift) & 31] for shift in range(125, -1, -5))


def _canonical_decimal(value: Decimal) -> str:
    with localcontext(_DECIMAL_CONTEXT):
        if value == 0:
            return "0"
    fixed = format(value, "f")
    return fixed.rstrip("0").rstrip(".") if "." in fixed else fixed


def _history_heads(
    history: tuple[StructureEventV1, ...], evaluation: StructureEvaluation
) -> tuple[StructureSignalV1 | None, StructureSignalV1 | None]:
    context = evaluation.context
    signals = tuple(
        event
        for event in history
        if isinstance(event, StructureSignalV1)
        and event.bar_close <= evaluation.bar.close_time
        and event.ts_ingest <= evaluation.observed_at
        and (event.symbol, event.venue, event.timeframe, event.detector_id)
        == (context.symbol, context.venue, context.timeframe, context.detector_id)
        and event.detector_version == context.detector_version
    )
    ids = {event.id for event in signals}
    if len(ids) != len(signals):
        raise StructureEvaluationError("HISTORY_CONFLICT")
    referenced = {event.revision_of for event in signals if event.revision_of is not None}
    heads = tuple(event for event in signals if event.id not in referenced)
    same_bar = tuple(event for event in heads if event.bar_id == evaluation.bar.bar_id)
    if len(same_bar) > 1:
        raise StructureEvaluationError("HISTORY_CONFLICT")
    prior = tuple(
        event
        for event in heads
        if event.bar_id != evaluation.bar.bar_id
        and event.bar_close < evaluation.bar.close_time
        and event.kind != "TOMBSTONE"
    )
    latest = max(prior, key=lambda event: (event.bar_close, event.id), default=None)
    return (same_bar[0] if same_bar else None, latest)


def _pivot(
    evaluation: StructureEvaluation,
) -> tuple[ConfirmedStructurePivot, Literal["bull", "bear"]] | None:
    bar = evaluation.bar
    eligible = tuple(
        pivot
        for pivot in evaluation.pivots
        if pivot.pivot_time < bar.close_time and pivot.confirmed_at <= bar.close_time
    )
    if len({pivot.pivot_id for pivot in eligible}) != len(eligible):
        raise StructureEvaluationError("PIVOT_ID_CONFLICT")
    high = max(
        (pivot for pivot in eligible if pivot.kind == "high"),
        key=lambda pivot: (pivot.pivot_time, pivot.confirmed_at, pivot.pivot_id),
        default=None,
    )
    low = max(
        (pivot for pivot in eligible if pivot.kind == "low"),
        key=lambda pivot: (pivot.pivot_time, pivot.confirmed_at, pivot.pivot_id),
        default=None,
    )
    with localcontext(_DECIMAL_CONTEXT):
        up = high is not None and bar.previous_close <= high.price < bar.close
        down = low is not None and bar.previous_close >= low.price > bar.close
    if up and down:
        raise StructureEvaluationError("AMBIGUOUS_BREAK")
    if up and high is not None:
        return high, "bull"
    if down and low is not None:
        return low, "bear"
    return None


def _key(evaluation: StructureEvaluation, pivot: ConfirmedStructurePivot) -> str:
    context = evaluation.context
    bar = evaluation.bar
    return _semantic_hash(
        {
            "symbol": context.symbol, "venue": context.venue,
            "timeframe": context.timeframe, "detector_id": context.detector_id,
            "detector_version": context.detector_version,
            "pivot_ids": (pivot.pivot_id,),
            "bar_id": bar.bar_id, "input_version": bar.input_version,
            "feature_version": pivot.feature_version,
        }
    )


def _signal(
    evaluation: StructureEvaluation,
    pivot: ConfirmedStructurePivot,
    direction: Literal["bull", "bear"],
    detector_type: Literal["msb", "bos"],
    kind: Literal["INITIAL", "REVISION"],
    revision_of: str | None,
) -> StructureSignalV1:
    context = evaluation.context
    bar = evaluation.bar
    dedupe_key = _key(evaluation, pivot)
    quality = _quality(evaluation)
    signal_id = _event_id(
        bar.close_time,
        {
            "dedupe_key": dedupe_key, "direction": direction,
            "detector_type": detector_type,
            "broken_level": _canonical_decimal(pivot.price),
            "kind": kind, "revision_of": revision_of or "",
            "late_data": str(quality.late_data), "gap": str(quality.gap),
            "stale_input": str(quality.stale_input),
        },
    )
    return StructureSignalV1(
        id=signal_id,
        kind=kind,
        revision_of=revision_of,
        detector_type=detector_type,
        direction=direction,
        broken_level=pivot.price,
        symbol=context.symbol,
        venue=context.venue,
        timeframe=context.timeframe,
        pivot_ids=(pivot.pivot_id,),
        bar_id=bar.bar_id,
        ts_event=bar.close_time,
        ts_ingest=evaluation.observed_at,
        bar_close=bar.close_time,
        detector_id=context.detector_id,
        detector_version=context.detector_version,
        input_version=bar.input_version,
        feature_version=pivot.feature_version,
        finalized=True,
        confidence=Decimal(1),
        quality=quality,
        dedupe_key=dedupe_key,
    )


def _tombstone(evaluation: StructureEvaluation, previous: StructureSignalV1) -> StructureSignalV1:
    bar = evaluation.bar
    dedupe_key = _semantic_hash(
        {"tombstone_of": previous.id, "bar_id": bar.bar_id, "input_version": bar.input_version}
    )
    return StructureSignalV1.model_validate(
        previous.model_dump()
        | {
            "id": _event_id(bar.close_time, {"dedupe_key": dedupe_key, "kind": "TOMBSTONE"}),
            "kind": "TOMBSTONE",
            "revision_of": previous.id,
            "ts_event": bar.close_time,
            "ts_ingest": evaluation.observed_at,
            "bar_close": bar.close_time,
            "input_version": bar.input_version,
            "quality": _quality(evaluation),
            "dedupe_key": dedupe_key,
        }
    )


def _gap_notice(
    evaluation: StructureEvaluation, previous: StructureSignalV1 | None
) -> StructureGapNoticeV1:
    context = evaluation.context
    bar = evaluation.bar
    dedupe_key = _semantic_hash(
        {
            "symbol": context.symbol, "venue": context.venue,
            "timeframe": context.timeframe, "bar_id": bar.bar_id,
            "input_version": bar.input_version,
            "revision_of": previous.id if previous is not None else "",
            "reason": "LATE_BEYOND_WATERMARK",
        }
    )
    return StructureGapNoticeV1(
        id=_event_id(bar.close_time, {"notice_key": dedupe_key}),
        dedupe_key=dedupe_key,
        symbol=context.symbol,
        venue=context.venue,
        timeframe=context.timeframe,
        bar_id=bar.bar_id,
        ts_event=bar.close_time,
        ts_ingest=evaluation.observed_at,
        revision_of=previous.id if previous is not None else None,
        reason="LATE_BEYOND_WATERMARK",
        quality=_quality(evaluation, gap=True),
    )


def evaluate_structure(
    evaluation: StructureEvaluation, history: tuple[StructureEventV1, ...] = ()
) -> tuple[StructureEventV1, ...]:
    """Evaluate a final crossing against immutable, caller-supplied event history."""
    same_bar, prior = _history_heads(history, evaluation)
    candidate = _pivot(evaluation)
    if candidate is not None:
        pivot, direction = candidate
        detector_type: Literal["msb", "bos"] = (
            "bos" if prior is not None and prior.direction == direction else "msb"
        )
        kind: Literal["INITIAL", "REVISION"] = "REVISION" if same_bar is not None else "INITIAL"
        proposed = _signal(
            evaluation,
            pivot,
            direction,
            detector_type,
            kind,
            same_bar.id if same_bar is not None else None,
        )
    else:
        proposed = None
    if (
        same_bar is not None
        and proposed is not None
        and same_bar.kind != "TOMBSTONE"
        and same_bar.dedupe_key == proposed.dedupe_key
        and same_bar.direction == proposed.direction
        and same_bar.broken_level == proposed.broken_level
        and same_bar.detector_type == proposed.detector_type
        and (same_bar.quality.late_data, same_bar.quality.gap, same_bar.quality.stale_input)
        == (proposed.quality.late_data, proposed.quality.gap, proposed.quality.stale_input)
    ):
        return ()
    if (same_bar is not None or evaluation.bar.late_data) and (
        evaluation.observed_at - evaluation.bar.close_time > evaluation.watermark
    ):
        notice = _gap_notice(evaluation, same_bar)
        if any(event.dedupe_key == notice.dedupe_key for event in history):
            return ()
        return (notice,)
    if proposed is None:
        if same_bar is not None and same_bar.kind != "TOMBSTONE":
            return (_tombstone(evaluation, same_bar),)
        return ()
    if same_bar is not None:
        return (proposed,)
    if prior is not None and prior.direction != proposed.direction:
        return (_tombstone(evaluation, prior), proposed)
    return (proposed,)
