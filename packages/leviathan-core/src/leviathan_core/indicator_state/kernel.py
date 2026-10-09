"""Pure finalized-bar indicator recurrences and verified checkpoint replay."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import replace
from decimal import Decimal, DecimalException, Inexact, localcontext
from fractions import Fraction
from typing import cast

from .models import (
    _CONTEXT,
    _RESULT_ISSUER,
    _STATE_TOKEN,
    FinalBarV1,
    IndicatorAvailabilityError,
    IndicatorCheckpointError,
    IndicatorConflictError,
    IndicatorDefinitionV1,
    IndicatorPrecisionExceededError,
    IndicatorResultV1,
    IndicatorStateV1,
    IndicatorValidationError,
    _canonical_decimal,
    _hash_payload,
    _is_digest,
    _nanoseconds,
    _Snapshot,
)

_ZERO = Decimal(0)
_ONE = Decimal(1)
_HUNDRED = Decimal(100)
_NS_PER_UNIT = {
    "ns": 1,
    "us": 1_000,
    "ms": 1_000_000,
    "s": 1_000_000_000,
    "m": 60_000_000_000,
    "h": 3_600_000_000_000,
    "d": 86_400_000_000_000,
    "w": 604_800_000_000_000,
}


def _canonical(value: Decimal) -> Decimal:
    """Keep the fixed decimal128 rounded value in one scale-free representation."""
    return Decimal(_canonical_decimal(value))


def _exact_add(left: Decimal, right: Decimal) -> Decimal:
    """Store a quantity sum only when decimal128 represents it exactly."""
    with localcontext(_CONTEXT) as context:
        context.traps[Inexact] = True
        try:
            return _canonical(left + right)
        except DecimalException:
            raise IndicatorPrecisionExceededError("PRECISION_EXCEEDED") from None


def _exact_sub(left: Decimal, right: Decimal) -> Decimal:
    with localcontext(_CONTEXT) as context:
        context.traps[Inexact] = True
        try:
            return _canonical(left - right)
        except DecimalException:
            raise IndicatorPrecisionExceededError("PRECISION_EXCEEDED") from None


def _exact_mul(left: Decimal, right: Decimal) -> Decimal:
    with localcontext(_CONTEXT) as context:
        context.traps[Inexact] = True
        try:
            return _canonical(left * right)
        except DecimalException:
            raise IndicatorPrecisionExceededError("PRECISION_EXCEEDED") from None


def _rounded_fraction(value: Fraction) -> Decimal:
    """Round an exact rational once when an indicator output is stored."""
    with localcontext(_CONTEXT):
        return _canonical(Decimal(value.numerator) / Decimal(value.denominator))


def _step(
    previous: _Snapshot,
    bar: FinalBarV1,
    definition: IndicatorDefinitionV1,
    *,
    gap: bool,
) -> tuple[_Snapshot, Decimal | None, bool, bool, tuple[str, ...]]:
    """Return snapshot, value, warmup, invalid, and quality flags."""
    kind = definition.kind
    with localcontext(_CONTEXT):
        if kind == "VWAP":
            snapshot = (
                _Snapshot(session_key=bar.session_key)
                if previous.session_key != bar.session_key
                else previous
            )
            if gap:
                snapshot = replace(snapshot, gap_active=True)
            count = snapshot.count + 1
            if bar.high is None or bar.low is None:
                return (
                    replace(snapshot, count=count, gap_active=True),
                    None,
                    False,
                    True,
                    ("INVALID_INPUT", "GAP"),
                )
            if bar.volume is None:
                flags = ("MISSING_VOLUME", "GAP") if snapshot.gap_active else ("MISSING_VOLUME",)
                return replace(snapshot, count=count), None, False, True, flags
            price_sum = _exact_add(_exact_add(bar.high, bar.low), bar.close)
            numerator = _exact_add(snapshot.vwap_num, _exact_mul(price_sum, bar.volume))
            denominator = _exact_add(snapshot.vwap_den, _exact_mul(Decimal(3), bar.volume))
            updated = replace(
                snapshot,
                count=count,
                vwap_num=_canonical(numerator),
                vwap_den=_canonical(denominator),
            )
            if updated.gap_active:
                return updated, None, False, True, ("GAP",)
            if denominator == 0:
                return updated, None, False, True, ("NO_VOLUME",)
            return (
                updated,
                _rounded_fraction(Fraction(numerator) / Fraction(denominator)),
                False,
                False,
                (),
            )

        snapshot = _Snapshot() if gap else previous
        period = definition.period
        assert period is not None
        count = snapshot.count + 1
        if kind == "EMA":
            if count < period:
                updated = replace(
                    snapshot, count=count, seed_sum=_exact_add(snapshot.seed_sum, bar.close)
                )
                return updated, None, True, False, ("WARMUP",)
            if count == period:
                value = _canonical(_exact_add(snapshot.seed_sum, bar.close) / Decimal(period))
            else:
                assert snapshot.value is not None
                # 2/(N+1) is not rounded before multiplying the next close.
                value = _rounded_fraction(
                    (2 * Fraction(bar.close) + (period - 1) * Fraction(snapshot.value))
                    / (period + 1)
                )
            return replace(snapshot, count=count, value=value), value, False, False, ()

        if kind == "RSI":
            if snapshot.prev_close is None:
                return (
                    replace(snapshot, count=count, prev_close=bar.close),
                    None,
                    True,
                    False,
                    ("WARMUP",),
                )
            change = _exact_sub(bar.close, snapshot.prev_close)
            gain = max(change, _ZERO)
            loss = max(-change, _ZERO)
            if count <= period:
                updated = replace(
                    snapshot,
                    count=count,
                    prev_close=bar.close,
                    gain_sum=_exact_add(snapshot.gain_sum, gain),
                    loss_sum=_exact_add(snapshot.loss_sum, loss),
                )
                return updated, None, True, False, ("WARMUP",)
            if count == period + 1:
                gain_average = Fraction(_exact_add(snapshot.gain_sum, gain)) / period
                loss_average = Fraction(_exact_add(snapshot.loss_sum, loss)) / period
            else:
                assert snapshot.avg_gain is not None and snapshot.avg_loss is not None
                gain_average = (
                    (period - 1) * Fraction(snapshot.avg_gain) + Fraction(gain)
                ) / period
                loss_average = (
                    (period - 1) * Fraction(snapshot.avg_loss) + Fraction(loss)
                ) / period
            # Store one rounded average per bar for the next Wilder step, but
            # derive this bar's RSI from the still-exact current averages.
            avg_gain = _rounded_fraction(gain_average)
            avg_loss = _rounded_fraction(loss_average)
            updated = replace(
                snapshot, count=count, prev_close=bar.close, avg_gain=avg_gain, avg_loss=avg_loss
            )
            if gain_average == 0 and loss_average == 0:
                return updated, None, False, True, ("FLAT_NO_MOVEMENT",)
            if loss_average == 0:
                return updated, _HUNDRED, False, False, ()
            if gain_average == 0:
                return updated, _ZERO, False, False, ()
            value = _rounded_fraction(100 * gain_average / (gain_average + loss_average))
            return updated, value, False, False, ()

        # ATR: a missing range breaks the consecutive warmup window.
        if bar.high is None or bar.low is None:
            return _Snapshot(), None, False, True, ("INVALID_INPUT",)
        true_range = _exact_sub(bar.high, bar.low)
        if snapshot.prev_close is not None:
            true_range = max(
                true_range,
                abs(_exact_sub(bar.high, snapshot.prev_close)),
                abs(_exact_sub(bar.low, snapshot.prev_close)),
            )
        if count < period:
            updated = replace(
                snapshot,
                count=count,
                prev_close=bar.close,
                seed_sum=_exact_add(snapshot.seed_sum, true_range),
            )
            return updated, None, True, False, ("WARMUP",)
        if count == period:
            value = _canonical(_exact_add(snapshot.seed_sum, true_range) / Decimal(period))
        else:
            assert snapshot.value is not None
            value = _rounded_fraction(
                ((period - 1) * Fraction(snapshot.value) + Fraction(true_range)) / period
            )
        return (
            replace(snapshot, count=count, prev_close=bar.close, value=value),
            value,
            False,
            False,
            (),
        )


def _duration_ns(timeframe: str) -> int:
    for suffix in ("ns", "us", "ms", "s", "m", "h", "d", "w"):
        if timeframe.endswith(suffix):
            return int(timeframe[: -len(suffix)]) * _NS_PER_UNIT[suffix]
    raise IndicatorValidationError("invalid indicator timeframe")


def _check_bar(bar: FinalBarV1, definition: IndicatorDefinitionV1, asof_ns: int) -> None:
    if not isinstance(bar, FinalBarV1):
        raise IndicatorValidationError("invalid indicator bar")
    for name in (
        "instrument_id",
        "venue",
        "timeframe",
        "source_version",
        "adjustment_version",
        "calendar_version",
    ):
        if getattr(bar, name) != getattr(definition, name):
            raise IndicatorValidationError("indicator input lineage mismatch")
    if (
        not bar.finalized
        or bar.bar_end_ns > asof_ns
        or bar.event_time_ns > asof_ns
        or bar.availability_ns > asof_ns
    ):
        raise IndicatorAvailabilityError("indicator bar is unavailable at cutoff")


def _empty(definition: IndicatorDefinitionV1, asof_ns: int) -> IndicatorStateV1:
    digest = _hash_payload({"definition_hash": definition.semantic_hash, "bars": []})
    return IndicatorStateV1(
        (), (), digest, definition.semantic_hash, None, 0, asof_ns, _token=_STATE_TOKEN
    )


def _snapshot_before(state: IndicatorStateV1, index: int) -> _Snapshot | None:
    if index == 0:
        return _Snapshot()
    checkpoint_index = index - 1
    if checkpoint_index == state._checkpoint_start - 1 and isinstance(  # noqa: SLF001
        state._base_snapshot,  # noqa: SLF001
        _Snapshot,
    ):
        return state._base_snapshot  # noqa: SLF001
    if checkpoint_index >= state._checkpoint_start:  # noqa: SLF001
        offset = checkpoint_index - state._checkpoint_start  # noqa: SLF001
        if offset < len(state._snapshots):  # noqa: SLF001
            candidate = state._snapshots[offset]  # noqa: SLF001
            if isinstance(candidate, _Snapshot):
                return candidate
    return None


def advance(
    previous_state: IndicatorStateV1 | None,
    finalized_bar: FinalBarV1,
    definition: IndicatorDefinitionV1,
    asof_ns: int,
) -> tuple[IndicatorStateV1, IndicatorResultV1]:
    """Advance an immutable prefix, replaying from the prior checkpoint on revision."""
    if not isinstance(definition, IndicatorDefinitionV1):
        raise IndicatorValidationError("invalid indicator definition")
    _nanoseconds(asof_ns)
    _check_bar(finalized_bar, definition, asof_ns)
    old = previous_state if previous_state is not None else _empty(definition, asof_ns)
    if not isinstance(old, IndicatorStateV1) or old.definition_hash != definition.semantic_hash:
        raise IndicatorCheckpointError("indicator checkpoint identity mismatch")
    if asof_ns < old.asof_ns or not _is_digest(old.input_digest):
        raise IndicatorCheckpointError("indicator checkpoint cutoff or digest invalid")
    expected_digest = (
        old.results[-1].input_digest
        if old.results
        else _hash_payload({"definition_hash": old.definition_hash, "bars": []})
    )
    if len(old.bars) != len(old.results) or old.input_digest != expected_digest:
        raise IndicatorCheckpointError("indicator checkpoint digest mismatch")

    bars = list(old.bars)
    index = next(
        (i for i, item in enumerate(bars) if item.bar_end_ns >= finalized_bar.bar_end_ns), len(bars)
    )
    replacement = index < len(bars) and bars[index].bar_end_ns == finalized_bar.bar_end_ns
    if replacement:
        current = bars[index]
        if current.semantic_hash == finalized_bar.semantic_hash:
            return replace(old, asof_ns=asof_ns, _token=_STATE_TOKEN), old.results[index]
        if finalized_bar.availability_ns < current.availability_ns:
            return replace(old, asof_ns=asof_ns, _token=_STATE_TOKEN), old.results[index]
        if finalized_bar.availability_ns == current.availability_ns:
            raise IndicatorConflictError("conflicting indicator bar revision")
        bars[index] = finalized_bar
    else:
        bars.insert(index, finalized_bar)
    # Arrival order alone is not a semantic revision. Only a later-available
    # replacement of an existing bar creates a new result revision.
    revised = replacement
    revision = old.revision + int(revised)
    selected = tuple(bars)

    # Retain one checkpoint before the bounded correction window. If an older
    # bar changes, source bars permit a safe full replay from the beginning.
    start = index
    snapshot = _snapshot_before(old, start)
    if snapshot is None:
        start = 0
        snapshot = _Snapshot()
    results = list(old.results[:start])
    all_snapshots: list[_Snapshot] = (
        list(old._snapshots[: max(0, start - old._checkpoint_start)])  # noqa: SLF001
        if start >= old._checkpoint_start  # noqa: SLF001
        else []
    )
    digest = (
        results[-1].input_digest
        if results
        else _hash_payload({"definition_hash": definition.semantic_hash, "bars": []})
    )
    interval = _duration_ns(definition.timeframe)
    for position in range(start, len(selected)):
        bar = selected[position]
        preceding = selected[position - 1] if position else None
        implicit_gap = (
            preceding is not None
            and preceding.session_key == bar.session_key
            and bar.bar_end_ns - preceding.bar_end_ns > interval
        )
        gap = bar.gap or implicit_gap
        snapshot, value, warmup, invalid, flags = _step(snapshot, bar, definition, gap=gap)
        digest = _hash_payload({"previous": digest, "bar": bar.semantic_hash})
        quality = tuple(
            dict.fromkeys((*(flags), *(("GAP",) if gap else ()), *(("LATE",) if revised else ())))
        )
        result = _RESULT_ISSUER.issue(
            IndicatorResultV1(
                value=value,
                warmup=warmup,
                gap=gap or snapshot.gap_active,
                late=revised,
                invalid=invalid,
                sample_count=snapshot.count,
                bar_end_ns=bar.bar_end_ns,
                bar_id=bar.bar_id,
                input_digest=digest,
                revision=revision,
                definition_hash=definition.semantic_hash,
                quality_flags=quality,
            )
        )
        results.append(result)
        all_snapshots.append(snapshot)

    window = max((definition.period or 0) + 1, 1)
    # The prefix checkpoint is the state immediately before the retained tail.
    checkpoint_start = max(0, len(selected) - window)
    snapshot_start = old._checkpoint_start if start >= old._checkpoint_start else 0  # noqa: SLF001
    offset = checkpoint_start - snapshot_start
    if checkpoint_start == 0:
        base_snapshot = _Snapshot()
    elif offset > 0:
        base_snapshot = all_snapshots[offset - 1]
    else:
        base_snapshot = cast(_Snapshot, old._base_snapshot)  # noqa: SLF001
    retained = tuple(all_snapshots[offset:])
    if len(retained) != len(selected) - checkpoint_start:
        raise IndicatorCheckpointError("indicator checkpoint retention invalid")
    state = IndicatorStateV1(
        bars=selected,
        results=tuple(results),
        input_digest=digest,
        definition_hash=definition.semantic_hash,
        last_bar_id=selected[-1].bar_id,
        revision=revision,
        asof_ns=asof_ns,
        _token=_STATE_TOKEN,
        _snapshots=retained,
        _checkpoint_start=checkpoint_start,
        _base_snapshot=base_snapshot,
    )
    return state, state.results[index]


def _batch_state(
    finalized_bars: Iterable[FinalBarV1],
    definition: IndicatorDefinitionV1,
    asof_ns: int,
) -> IndicatorStateV1:
    if not isinstance(definition, IndicatorDefinitionV1):
        raise IndicatorValidationError("invalid indicator definition")
    _nanoseconds(asof_ns)
    state = _empty(definition, asof_ns)
    for bar in finalized_bars:
        if not isinstance(bar, FinalBarV1):
            raise IndicatorValidationError("invalid indicator bar")
        # An as-of query ignores future-available source revisions entirely.
        if bar.bar_end_ns > asof_ns or bar.event_time_ns > asof_ns or bar.availability_ns > asof_ns:
            continue
        state, _ = advance(state, bar, definition, asof_ns)
    return state


def batch(
    finalized_bars: Iterable[FinalBarV1],
    definition: IndicatorDefinitionV1,
    asof_ns: int,
) -> tuple[IndicatorResultV1, ...]:
    """Compute the same recurrence as advance over deliveries at an as-of cutoff."""
    return _batch_state(finalized_bars, definition, asof_ns).results


def resume(
    checkpoint: IndicatorStateV1,
    verified_prefix: Iterable[FinalBarV1],
    definition: IndicatorDefinitionV1,
    asof_ns: int,
) -> IndicatorStateV1:
    """Use a matching checkpoint, otherwise rebuild safely from verified source bars."""
    _nanoseconds(asof_ns)
    try:
        source = tuple(verified_prefix)
        expected = _batch_state(source, definition, checkpoint.asof_ns)
        current = _batch_state(source, definition, asof_ns)
    except (AttributeError, TypeError, IndicatorValidationError) as exc:
        raise IndicatorCheckpointError("indicator verified prefix invalid") from exc
    match = (
        isinstance(checkpoint, IndicatorStateV1)
        and checkpoint.definition_hash == expected.definition_hash
        and checkpoint.input_digest == expected.input_digest
        and checkpoint.last_bar_id == expected.last_bar_id
        and checkpoint.revision == expected.revision
        and checkpoint.bars == expected.bars
        and checkpoint._snapshots == expected._snapshots  # noqa: SLF001
        and checkpoint._checkpoint_start == expected._checkpoint_start  # noqa: SLF001
        and checkpoint._base_snapshot == expected._base_snapshot  # noqa: SLF001
        and len(checkpoint.results) == len(expected.results)
        and all(
            a.canonical_bytes() == b.canonical_bytes()
            for a, b in zip(checkpoint.results, expected.results, strict=True)
        )
    )
    if asof_ns < checkpoint.asof_ns:
        raise IndicatorCheckpointError("indicator checkpoint cutoff invalid")
    if match and current.input_digest == checkpoint.input_digest:
        return replace(checkpoint, asof_ns=asof_ns, _token=_STATE_TOKEN)
    return current
