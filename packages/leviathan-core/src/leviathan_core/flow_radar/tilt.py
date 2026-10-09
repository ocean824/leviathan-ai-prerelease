from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from decimal import Decimal, DecimalException, Inexact, localcontext
from enum import StrEnum

from .filters import FlowEvaluation, reconcile_evaluations
from .models import (
    FlowError,
    FlowValue,
    OptionSide,
    SessionCalendar,
    checked_decimal,
    kernel_context,
    required_text,
)


class TiltWindow(StrEnum):
    ONE_MINUTE = "1m"
    FIVE_MINUTES = "5m"
    THIRTY_MINUTES = "30m"
    SESSION = "session"


@dataclass(frozen=True, slots=True)
class TiltSnapshot(FlowValue):
    ticker: str
    window: TiltWindow
    as_of_ns: int
    call_notional: Decimal
    put_notional: Decimal
    tilt: Decimal | None
    call_count: int
    put_count: int
    sweep_count: int
    block_count: int
    sweep_share: Decimal | None
    near_ask_share: Decimal | None

    def __post_init__(self) -> None:
        required_text(self.ticker)
        if not isinstance(self.window, TiltWindow):
            raise FlowError("INVALID_TILT_SNAPSHOT")
        checked_decimal(self.call_notional, nonnegative=True)
        checked_decimal(self.put_notional, nonnegative=True)
        for amount in (self.tilt, self.sweep_share, self.near_ask_share):
            if amount is not None:
                checked_decimal(amount)
        for number in (
            self.as_of_ns,
            self.call_count,
            self.put_count,
            self.sweep_count,
            self.block_count,
        ):
            if type(number) is not int or number < 0:
                raise FlowError("INVALID_TILT_SNAPSHOT")
        count = self.call_count + self.put_count
        if self.sweep_count > count or self.block_count > count:
            raise FlowError("INVALID_TILT_SNAPSHOT")
        if self.tilt is not None and not Decimal(-1) <= self.tilt <= Decimal(1):
            raise FlowError("INVALID_TILT_SNAPSHOT")
        for share in (self.sweep_share, self.near_ask_share):
            if share is not None and not Decimal(0) <= share <= Decimal(1):
                raise FlowError("INVALID_TILT_SNAPSHOT")
        if (self.sweep_share is None) != (count == 0):
            raise FlowError("INVALID_TILT_SNAPSHOT")
        try:
            with localcontext(kernel_context()):
                denominator = checked_decimal(self.call_notional + self.put_notional)
        except Inexact as exc:
            raise FlowError("PRECISION_EXCEEDED") from exc
        except DecimalException as exc:
            raise FlowError("ARITHMETIC_OUT_OF_BOUNDS") from exc
        if (self.tilt is None) != (denominator == 0):
            raise FlowError("INVALID_TILT_SNAPSHOT")


def tilt_snapshots(
    evaluations: Iterable[FlowEvaluation],
    ticker: str,
    as_of_ns: int,
    calendar: SessionCalendar,
    *,
    filtered_only: bool = False,
) -> tuple[TiltSnapshot, ...]:
    if not isinstance(ticker, str) or not ticker or type(as_of_ns) is not int or as_of_ns < 0:
        raise FlowError("INVALID_TILT_INPUT")
    if not isinstance(calendar, SessionCalendar) or type(filtered_only) is not bool:
        raise FlowError("INVALID_TILT_INPUT")
    session = calendar.session_for(as_of_ns)
    if session is None:
        raise FlowError("OUTSIDE_SESSION")
    visible: list[FlowEvaluation] = []
    for evaluation in evaluations:
        if not isinstance(evaluation, FlowEvaluation):
            raise FlowError("INVALID_EVALUATION_INPUT")
        if (
            evaluation.print.stamp.event_ns <= as_of_ns
            and evaluation.print.stamp.available_ns <= as_of_ns
        ):
            visible.append(evaluation)
    eligible = tuple(
        evaluation
        for evaluation in reconcile_evaluations(visible).accepted
        if evaluation.print.ticker == ticker
        and evaluation.integrity_ok
        and (not filtered_only or evaluation.accepted)
    )
    intervals = (
        (TiltWindow.ONE_MINUTE, 60_000_000_000),
        (TiltWindow.FIVE_MINUTES, 300_000_000_000),
        (TiltWindow.THIRTY_MINUTES, 1_800_000_000_000),
        (TiltWindow.SESSION, None),
    )
    snapshots: list[TiltSnapshot] = []
    for window, duration_ns in intervals:
        start_ns = (
            session.open_ns if duration_ns is None else max(session.open_ns, as_of_ns - duration_ns)
        )
        selected = tuple(e for e in eligible if start_ns <= e.print.stamp.event_ns <= as_of_ns)
        try:
            with localcontext(kernel_context()):
                call_notional = checked_decimal(
                    sum((e.premium for e in selected if e.print.cp is OptionSide.CALL), Decimal(0)),
                    nonnegative=True,
                )
                put_notional = checked_decimal(
                    sum((e.premium for e in selected if e.print.cp is OptionSide.PUT), Decimal(0)),
                    nonnegative=True,
                )
                denominator = call_notional + put_notional
                numerator = call_notional - put_notional
                count = len(selected)
                sweep_count = sum(e.is_sweep for e in selected)
                block_count = sum(e.is_block for e in selected)
                known_near_ask = tuple(e for e in selected if e.near_ask is not None)
            with localcontext(kernel_context()) as display_context:
                display_context.traps[Inexact] = False
                tilt = None if denominator == 0 else checked_decimal(numerator / denominator)
                sweep_share = (
                    None if count == 0 else checked_decimal(Decimal(sweep_count) / Decimal(count))
                )
                near_ask_share = (
                    None
                    if not known_near_ask
                    else checked_decimal(
                        Decimal(sum(e.near_ask is True for e in known_near_ask))
                        / Decimal(len(known_near_ask))
                    )
                )
        except Inexact as exc:
            raise FlowError("PRECISION_EXCEEDED") from exc
        except DecimalException as exc:
            raise FlowError("ARITHMETIC_OUT_OF_BOUNDS") from exc
        snapshots.append(
            TiltSnapshot(
                ticker,
                window,
                as_of_ns,
                call_notional,
                put_notional,
                tilt,
                sum(e.print.cp is OptionSide.CALL for e in selected),
                sum(e.print.cp is OptionSide.PUT for e in selected),
                sweep_count,
                block_count,
                sweep_share,
                near_ask_share,
            )
        )
    return tuple(snapshots)
