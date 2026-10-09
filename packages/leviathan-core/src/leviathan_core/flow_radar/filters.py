from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import date
from decimal import Decimal, DecimalException, Inexact, localcontext
from fractions import Fraction

from .models import (
    FlowError,
    FlowValue,
    OpenInterest,
    OptionPrint,
    OptionSide,
    PrintFlag,
    Quote,
    SessionCalendar,
    TradeSide,
    UnderlyingMid,
    checked_decimal,
    kernel_context,
    required_text,
)

NBBO_MAX_AGE_NS = 500_000_000


@dataclass(frozen=True, slots=True)
class FilterPolicy(FlowValue):
    min_premium: Decimal | None = None
    vol_gt_oi: bool = False
    otm_only: bool = False
    near_ask: bool = False
    min_size: Decimal | None = None
    required_cp: OptionSide | None = None
    required_trade_side: TradeSide | None = None
    require_sweep: bool = False
    require_block: bool = False
    otm_buffer: Decimal = Decimal("0.005")
    aggression_threshold: Decimal = Decimal("0.8")
    block_size_threshold: Decimal | None = None

    def __post_init__(self) -> None:
        for enabled in (
            self.vol_gt_oi,
            self.otm_only,
            self.near_ask,
            self.require_sweep,
            self.require_block,
        ):
            if type(enabled) is not bool:
                raise FlowError("INVALID_BOOLEAN")
        for amount in (self.min_premium, self.min_size, self.block_size_threshold):
            if amount is not None:
                checked_decimal(amount, nonnegative=True)
        checked_decimal(self.otm_buffer, nonnegative=True)
        checked_decimal(self.aggression_threshold, nonnegative=True)
        if (
            self.otm_buffer >= 1
            or self.aggression_threshold < Decimal("0.8")
            or self.aggression_threshold > 1
        ):
            raise FlowError("POLICY_OUT_OF_BOUNDS")
        if self.required_cp is not None and not isinstance(self.required_cp, OptionSide):
            raise FlowError("INVALID_SIDE")
        if self.required_trade_side is not None and not isinstance(
            self.required_trade_side, TradeSide
        ):
            raise FlowError("INVALID_SIDE")


@dataclass(frozen=True, slots=True)
class FlowEvaluation(FlowValue):
    print: OptionPrint
    premium: Decimal
    integrity_ok: bool
    accepted: bool
    vol_gt_oi: bool | None
    otm: bool | None
    near_ask: bool | None
    is_sweep: bool
    is_block: bool
    reasons: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.print, OptionPrint):
            raise FlowError("INVALID_EVALUATION")
        checked_decimal(self.premium, nonnegative=True)
        try:
            with localcontext(kernel_context()):
                expected_premium = self.print.price * self.print.multiplier * self.print.size
        except Inexact as exc:
            raise FlowError("PRECISION_EXCEEDED") from exc
        except DecimalException as exc:
            raise FlowError("ARITHMETIC_OUT_OF_BOUNDS") from exc
        if self.premium != expected_premium:
            raise FlowError("INVALID_EVALUATION")
        for status in (self.integrity_ok, self.accepted, self.is_sweep, self.is_block):
            if type(status) is not bool:
                raise FlowError("INVALID_BOOLEAN")
        for state in (self.vol_gt_oi, self.otm, self.near_ask):
            if state is not None and type(state) is not bool:
                raise FlowError("INVALID_BOOLEAN")
        if not isinstance(self.reasons, tuple) or any(
            not isinstance(reason, str) for reason in self.reasons
        ):
            raise FlowError("INVALID_EVALUATION")
        for reason in self.reasons:
            required_text(reason)
        if self.accepted != (self.integrity_ok and not self.reasons):
            raise FlowError("INVALID_EVALUATION")


@dataclass(frozen=True, slots=True)
class Reconciliation(FlowValue):
    accepted: tuple[FlowEvaluation, ...]
    duplicate_keys: tuple[str, ...]
    correction_keys: tuple[str, ...]
    conflict_keys: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.accepted, tuple) or any(
            not isinstance(value, FlowEvaluation) for value in self.accepted
        ):
            raise FlowError("INVALID_RECONCILIATION")
        for keys in (self.duplicate_keys, self.correction_keys, self.conflict_keys):
            if not isinstance(keys, tuple) or any(not isinstance(key, str) for key in keys):
                raise FlowError("INVALID_RECONCILIATION")
            if keys != tuple(sorted(set(keys))):
                raise FlowError("INVALID_RECONCILIATION")
            for key in keys:
                required_text(key)


def _same_contract(
    trade: OptionPrint, ticker: str, expiry: date, strike: Decimal, cp: OptionSide
) -> bool:
    return (
        trade.ticker == ticker
        and trade.expiry == expiry
        and trade.strike == strike
        and trade.cp is cp
    )


def _available(stamp_ns: int, available_ns: int, trade: OptionPrint) -> bool:
    return stamp_ns <= trade.stamp.event_ns and available_ns <= trade.stamp.available_ns


def evaluate_flow(
    trade: OptionPrint,
    calendar: SessionCalendar,
    *,
    underlying: UnderlyingMid | None = None,
    quote: Quote | None = None,
    oi: OpenInterest | None = None,
    policy: FilterPolicy | None = None,
) -> FlowEvaluation:
    if not isinstance(trade, OptionPrint) or not isinstance(calendar, SessionCalendar):
        raise FlowError("INVALID_EVALUATION_INPUT")
    if policy is None:
        policy = FilterPolicy()
    if not isinstance(policy, FilterPolicy):
        raise FlowError("INVALID_POLICY")
    session = calendar.session_for(trade.stamp.event_ns)
    aligned_underlying = (
        underlying is not None
        and isinstance(underlying, UnderlyingMid)
        and underlying.ticker == trade.ticker
        and _available(underlying.stamp.event_ns, underlying.stamp.available_ns, trade)
        and calendar.session_for(underlying.stamp.event_ns) == session
    )
    try:
        with localcontext(kernel_context()):
            premium = checked_decimal(trade.price * trade.multiplier * trade.size, nonnegative=True)
            integrity_ok = (
                session is not None
                and aligned_underlying
                and underlying is not None
                and trade.price <= Decimal(10) * underlying.mid
            )
            otm: bool | None = None
            if aligned_underlying and underlying is not None:
                if trade.cp is OptionSide.CALL:
                    otm = Fraction(trade.strike) > Fraction(underlying.mid) * (
                        1 + Fraction(policy.otm_buffer)
                    )
                else:
                    otm = Fraction(trade.strike) < Fraction(underlying.mid) * (
                        1 - Fraction(policy.otm_buffer)
                    )
            oi_fresh = (
                oi is not None
                and isinstance(oi, OpenInterest)
                and _same_contract(trade, oi.ticker, oi.expiry, oi.strike, oi.cp)
                and _available(oi.stamp.event_ns, oi.stamp.available_ns, trade)
            )
            vol_gt_oi: bool | None = None
            if oi_fresh and oi is not None:
                current_index = (
                    calendar.day_index(session.trading_day) if session is not None else None
                )
                oi_index = calendar.day_index(oi.as_of_day)
                if (
                    current_index is not None
                    and oi_index is not None
                    and 0 <= current_index - oi_index <= 1
                ):
                    vol_gt_oi = trade.size > oi.contracts
            quote_fresh = (
                quote is not None
                and isinstance(quote, Quote)
                and _same_contract(trade, quote.ticker, quote.expiry, quote.strike, quote.cp)
                and _available(quote.stamp.event_ns, quote.stamp.available_ns, trade)
                and trade.stamp.event_ns - quote.stamp.event_ns <= NBBO_MAX_AGE_NS
                and calendar.session_for(quote.stamp.event_ns) == session
            )
            near_ask: bool | None = None
            if quote_fresh and quote is not None:
                spread = quote.ask - quote.bid
                epsilon = min(Fraction(Decimal("0.02")), Fraction(spread) / 5)
                near_ask = trade.trade_side is TradeSide.BUY and (
                    Fraction(trade.price) >= Fraction(quote.ask) - epsilon
                    or (
                        quote.bid <= trade.price <= quote.ask
                        and trade.aggression_score is not None
                        and trade.aggression_score >= policy.aggression_threshold
                    )
                )
    except Inexact as exc:
        raise FlowError("PRECISION_EXCEEDED") from exc
    except DecimalException as exc:
        raise FlowError("ARITHMETIC_OUT_OF_BOUNDS") from exc
    is_sweep = PrintFlag.SWEEP in trade.flags
    is_block = PrintFlag.BLOCK in trade.flags or (
        policy.block_size_threshold is not None
        and PrintFlag.OFF_MARKET in trade.flags
        and trade.size >= policy.block_size_threshold
    )
    reasons: list[str] = []
    if not integrity_ok:
        reasons.append("BASE_INTEGRITY")
    if policy.min_premium is not None and premium < policy.min_premium:
        reasons.append("MIN_PREMIUM")
    if policy.min_size is not None and trade.size < policy.min_size:
        reasons.append("MIN_SIZE")
    if policy.vol_gt_oi and vol_gt_oi is not True:
        reasons.append("VOL_GT_OI_UNKNOWN" if vol_gt_oi is None else "VOL_GT_OI_FALSE")
    if policy.otm_only and otm is not True:
        reasons.append("OTM_UNKNOWN" if otm is None else "OTM_FALSE")
    if policy.near_ask and near_ask is not True:
        reasons.append("NEAR_ASK_UNKNOWN" if near_ask is None else "NEAR_ASK_FALSE")
    if policy.required_cp is not None and trade.cp is not policy.required_cp:
        reasons.append("OPTION_SIDE")
    if (
        policy.required_trade_side is not None
        and trade.trade_side is not policy.required_trade_side
    ):
        reasons.append("TRADE_SIDE")
    if policy.require_sweep and not is_sweep:
        reasons.append("SWEEP_REQUIRED")
    if policy.require_block and not is_block:
        reasons.append("BLOCK_REQUIRED")
    return FlowEvaluation(
        trade,
        premium,
        integrity_ok,
        not reasons,
        vol_gt_oi,
        otm,
        near_ask,
        is_sweep,
        is_block,
        tuple(reasons),
    )


def reconcile_evaluations(evaluations: Iterable[FlowEvaluation]) -> Reconciliation:
    by_key: dict[str, dict[str, FlowEvaluation]] = {}
    duplicates: set[str] = set()
    inconsistent_keys: set[str] = set()
    for evaluation in evaluations:
        if not isinstance(evaluation, FlowEvaluation):
            raise FlowError("INVALID_EVALUATION_INPUT")
        key = evaluation.print.stamp.source_key
        variants = by_key.setdefault(key, {})
        record_id = evaluation.print.record_id
        existing = variants.get(record_id)
        if existing is not None:
            duplicates.add(key)
            if (
                existing.premium != evaluation.premium
                or existing.integrity_ok != evaluation.integrity_ok
                or existing.accepted != evaluation.accepted
                or existing.vol_gt_oi != evaluation.vol_gt_oi
                or existing.otm != evaluation.otm
                or existing.near_ask != evaluation.near_ask
                or existing.is_sweep != evaluation.is_sweep
                or existing.is_block != evaluation.is_block
                or existing.reasons != evaluation.reasons
            ):
                inconsistent_keys.add(key)
            old_stamp = existing.print.stamp
            new_stamp = evaluation.print.stamp
            if (new_stamp.available_ns, new_stamp.ingest_ns or -1, new_stamp.request_id or "") < (
                old_stamp.available_ns,
                old_stamp.ingest_ns or -1,
                old_stamp.request_id or "",
            ):
                variants[record_id] = evaluation
        else:
            variants[record_id] = evaluation
    accepted: list[FlowEvaluation] = []
    corrections: list[str] = []
    conflicts: list[str] = []
    for key, variants in sorted(by_key.items()):
        if key in inconsistent_keys:
            conflicts.append(key)
            continue
        if len(variants) == 1:
            only = next(iter(variants.values()))
            if only.print.stamp.correction_of is None:
                accepted.append(only)
            else:
                conflicts.append(key)
            continue
        referenced = {
            v.print.stamp.correction_of for v in variants.values() if v.print.stamp.correction_of
        }
        terminals = [v for record_id, v in variants.items() if record_id not in referenced]
        if (
            len(terminals) == 1
            and len(referenced) == len(variants) - 1
            and referenced.issubset(variants)
        ):
            accepted.extend(terminals)
            corrections.append(key)
        else:
            conflicts.append(key)
    accepted.sort(key=lambda v: (v.print.stamp.event_ns, v.print.record_id))
    return Reconciliation(
        tuple(accepted), tuple(sorted(duplicates)), tuple(corrections), tuple(conflicts)
    )
