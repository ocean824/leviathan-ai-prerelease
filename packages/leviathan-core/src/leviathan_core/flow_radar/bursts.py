from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import date
from decimal import Decimal, DecimalException, Inexact, localcontext
from hashlib import sha256
from json import dumps

from .filters import FlowEvaluation, reconcile_evaluations
from .models import (
    FlowError,
    FlowValue,
    OptionSide,
    SessionCalendar,
    TradeSide,
    canonical_decimal,
    checked_decimal,
    kernel_context,
    required_text,
)


@dataclass(frozen=True, slots=True)
class BurstPolicy(FlowValue):
    window_ns: int = 8_000_000_000
    max_interarrival_ns: int = 1_500_000_000
    min_count: int = 3
    min_notional: Decimal = Decimal("500000")

    def __post_init__(self) -> None:
        if (
            type(self.window_ns) is not int
            or type(self.max_interarrival_ns) is not int
            or type(self.min_count) is not int
        ):
            raise FlowError("INVALID_BURST_POLICY")
        if (
            not 0 < self.window_ns <= 8_000_000_000
            or not 0 < self.max_interarrival_ns <= 1_500_000_000
            or self.min_count < 1
        ):
            raise FlowError("POLICY_OUT_OF_BOUNDS")
        checked_decimal(self.min_notional, nonnegative=True)


@dataclass(frozen=True, slots=True)
class StrikeLadder(FlowValue):
    version: str
    ticker: str
    expiry: date
    strikes: tuple[Decimal, ...]

    def __post_init__(self) -> None:
        required_text(self.version)
        required_text(self.ticker)
        if type(self.expiry) is not date or not isinstance(self.strikes, tuple):
            raise FlowError("INVALID_STRIKE_LADDER")
        if len(self.strikes) < 2:
            raise FlowError("INVALID_STRIKE_LADDER")
        for strike in self.strikes:
            checked_decimal(strike, positive=True)
        if self.strikes != tuple(sorted(set(self.strikes))):
            raise FlowError("INVALID_STRIKE_LADDER")


@dataclass(frozen=True, slots=True)
class BurstGroup(FlowValue):
    group_id: str
    ticker: str
    cp: OptionSide
    trade_side: TradeSide
    expiry: date
    trading_day: date
    first_ns: int
    last_ns: int
    member_ids: tuple[str, ...]
    total_notional: Decimal
    is_sweep: bool
    strikes: tuple[Decimal, ...]
    strike_ladder_version: str | None

    def __post_init__(self) -> None:
        required_text(self.group_id)
        required_text(self.ticker)
        if (
            not isinstance(self.cp, OptionSide)
            or not isinstance(self.trade_side, TradeSide)
            or type(self.expiry) is not date
            or type(self.trading_day) is not date
            or type(self.first_ns) is not int
            or type(self.last_ns) is not int
            or self.first_ns < 0
            or self.last_ns < self.first_ns
            or type(self.is_sweep) is not bool
        ):
            raise FlowError("INVALID_BURST_GROUP")
        if (
            not isinstance(self.member_ids, tuple)
            or not self.member_ids
            or any(not isinstance(member_id, str) for member_id in self.member_ids)
            or self.member_ids != tuple(sorted(set(self.member_ids)))
        ):
            raise FlowError("INVALID_BURST_GROUP")
        for member_id in self.member_ids:
            required_text(member_id)
        checked_decimal(self.total_notional, nonnegative=True)
        if not isinstance(self.strikes, tuple) or not self.strikes:
            raise FlowError("INVALID_BURST_GROUP")
        for strike in self.strikes:
            checked_decimal(strike, positive=True)
        if self.strikes != tuple(sorted(set(self.strikes))):
            raise FlowError("INVALID_BURST_GROUP")
        if (len(self.strikes) > 1) != (self.strike_ladder_version is not None):
            raise FlowError("INVALID_BURST_GROUP")
        if self.strike_ladder_version is not None:
            required_text(self.strike_ladder_version)


def detect_bursts(
    evaluations: Iterable[FlowEvaluation],
    calendar: SessionCalendar,
    policy: BurstPolicy | None = None,
    *,
    strike_ladders: tuple[StrikeLadder, ...] = (),
) -> tuple[BurstGroup, ...]:
    if not isinstance(calendar, SessionCalendar):
        raise FlowError("INVALID_CALENDAR")
    if policy is None:
        policy = BurstPolicy()
    if not isinstance(policy, BurstPolicy):
        raise FlowError("INVALID_BURST_POLICY")
    if not isinstance(strike_ladders, tuple):
        raise FlowError("INVALID_STRIKE_LADDER")
    ladders: dict[tuple[str, date], StrikeLadder] = {}
    for injected_ladder in strike_ladders:
        if not isinstance(injected_ladder, StrikeLadder):
            raise FlowError("INVALID_STRIKE_LADDER")
        ladder_key = (injected_ladder.ticker, injected_ladder.expiry)
        if ladder_key in ladders:
            raise FlowError("DUPLICATE_STRIKE_LADDER")
        ladders[ladder_key] = injected_ladder
    groups: dict[tuple[str, OptionSide, TradeSide, date, date, Decimal], list[FlowEvaluation]] = {}
    ladder_groups: dict[tuple[str, OptionSide, TradeSide, date, date], list[FlowEvaluation]] = {}
    for evaluation in reconcile_evaluations(evaluations).accepted:
        if not evaluation.accepted:
            continue
        trade = evaluation.print
        session = calendar.session_for(trade.stamp.event_ns)
        if session is None:
            continue
        key = (trade.ticker, trade.cp, trade.trade_side, trade.expiry, session.trading_day)
        groups.setdefault((*key, trade.strike), []).append(evaluation)
        ladder = ladders.get((trade.ticker, trade.expiry))
        if ladder is not None and trade.strike in ladder.strikes:
            ladder_groups.setdefault(key, []).append(evaluation)
    candidates: list[BurstGroup] = []
    pools = [(key[:5], events, None) for key, events in sorted(groups.items())] + [
        (key, events, ladders[(key[0], key[3])]) for key, events in sorted(ladder_groups.items())
    ]
    for (ticker, cp, trade_side, expiry, trading_day), events, ladder in pools:
        events.sort(key=lambda e: (e.print.stamp.event_ns, e.print.record_id))
        for start, first in enumerate(events):
            members = [first]
            for candidate in events[start + 1 :]:
                if candidate.print.stamp.event_ns - first.print.stamp.event_ns > policy.window_ns:
                    break
                if (
                    candidate.print.stamp.event_ns - members[-1].print.stamp.event_ns
                    > policy.max_interarrival_ns
                ):
                    break
                members.append(candidate)
            strikes = tuple(sorted({member.print.strike for member in members}))
            if ladder is not None and len(strikes) > 1:
                positions = {ladder.strikes.index(strike) for strike in strikes}
                if max(positions) - min(positions) + 1 != len(positions):
                    continue
            elif len(strikes) > 1:
                continue
            try:
                with localcontext(kernel_context()):
                    total = checked_decimal(
                        sum((member.premium for member in members), Decimal(0)), nonnegative=True
                    )
            except Inexact as exc:
                raise FlowError("PRECISION_EXCEEDED") from exc
            except DecimalException as exc:
                raise FlowError("ARITHMETIC_OUT_OF_BOUNDS") from exc
            if len(members) < policy.min_count and total < policy.min_notional:
                continue
            member_ids = tuple(sorted(member.print.record_id for member in members))
            payload = dict(
                ticker=ticker,
                cp=cp.value,
                trade_side=trade_side.value,
                expiry=expiry.isoformat(),
                trading_day=trading_day.isoformat(),
                strikes=tuple(canonical_decimal(strike) for strike in strikes),
                strike_ladder_version=ladder.version if len(strikes) > 1 and ladder else None,
                member_ids=member_ids,
            )
            group_id = sha256(
                dumps(payload, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            order_ids = {member.print.common_order_id for member in members}
            venues = {member.print.stamp.venue for member in members}
            is_sweep = any(member.is_sweep for member in members) or (
                len(members) > policy.min_count
                and len(order_ids) == 1
                and None not in order_ids
                and len(venues) > 1
            )
            candidates.append(
                BurstGroup(
                    group_id,
                    ticker,
                    cp,
                    trade_side,
                    expiry,
                    trading_day,
                    first.print.stamp.event_ns,
                    members[-1].print.stamp.event_ns,
                    member_ids,
                    total,
                    is_sweep,
                    strikes,
                    ladder.version if len(strikes) > 1 and ladder else None,
                )
            )
    maximal = [
        group
        for group in candidates
        if not any(set(group.member_ids) < set(other.member_ids) for other in candidates)
    ]
    return tuple(sorted(set(maximal), key=lambda group: (group.first_ns, group.group_id)))
