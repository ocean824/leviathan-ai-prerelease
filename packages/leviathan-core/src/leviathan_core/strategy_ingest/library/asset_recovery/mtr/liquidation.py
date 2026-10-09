"""Deterministic, offline MTR liquidation recommendations.

The kernel emits advisory plans only; it cannot close positions, manage a
broker session, or clear the shared HALT authority.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from enum import StrEnum
from fractions import Fraction

from .regime_grid import DEFAULT_SOVEREIGN_CAPS_V1, MtrPortError, SovereignCapsV1


def _bounded_decimal(value: object) -> bool:
    if type(value) is not Decimal or not value.is_finite():
        return False
    exponent = value.as_tuple().exponent
    return (
        type(exponent) is int
        and len(value.as_tuple().digits) <= 64
        and abs(exponent) <= 64
        and abs(value.adjusted()) <= 64
    )


class LiquidationActionV1(StrEnum):
    NONE = "NONE"
    HALT_NEW_ADDS = "HALT_NEW_ADDS"
    CLOSE_WORST_MARGIN_EFFICIENCY = "CLOSE_WORST_MARGIN_EFFICIENCY"
    CLOSE_NON_HEDGE_EXPOSURE = "CLOSE_NON_HEDGE_EXPOSURE"
    PARTIAL_UNWIND = "PARTIAL_UNWIND"
    CLOSE_BASKET = "CLOSE_BASKET"
    WAIT_FOR_LIQUIDITY = "WAIT_FOR_LIQUIDITY"
    MINIMUM_EXPOSURE_CLOSE_AND_HALT = "MINIMUM_EXPOSURE_CLOSE_AND_HALT"
    EMERGENCY_CLOSE_AND_HALT = "EMERGENCY_CLOSE_AND_HALT"
    MANUAL_REVIEW_HALT = "MANUAL_REVIEW_HALT"


_BASKET_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z", re.ASCII)
_LOSS_EPSILON = Decimal("0.001")


@dataclass(frozen=True, slots=True)
class BasketRiskV1:
    basket_id: str
    margin_released: Decimal
    realized_loss_at_close: Decimal
    exposure_units: Decimal
    is_hedge: bool

    def __post_init__(self) -> None:
        if type(self.basket_id) is not str or _BASKET_ID.fullmatch(self.basket_id) is None:
            raise MtrPortError("INPUT_INVALID")
        for name in ("margin_released", "realized_loss_at_close", "exposure_units"):
            value = getattr(self, name)
            if type(value) is not Decimal or not _bounded_decimal(value):
                raise MtrPortError("INPUT_INVALID")
        if self.margin_released < Decimal("0") or self.exposure_units < Decimal("0"):
            raise MtrPortError("INPUT_INVALID")
        if type(self.is_hedge) is not bool:
            raise MtrPortError("INPUT_INVALID")


def margin_efficiency(candidate: BasketRiskV1) -> Fraction:
    """Exact margin-release / absolute-loss ratio with source epsilon floor."""
    if type(candidate) is not BasketRiskV1:
        raise MtrPortError("INPUT_INVALID")
    pain = max(abs(candidate.realized_loss_at_close), _LOSS_EPSILON)
    return Fraction(candidate.margin_released) / Fraction(pain)


def select_worst_margin_efficiency(candidates: tuple[BasketRiskV1, ...]) -> BasketRiskV1:
    """Select by efficiency descending, then basket ID ascending."""
    if (
        type(candidates) is not tuple
        or not candidates
        or any(type(candidate) is not BasketRiskV1 for candidate in candidates)
    ):
        raise MtrPortError("INPUT_INVALID")
    if len({candidate.basket_id for candidate in candidates}) != len(candidates):
        raise MtrPortError("INPUT_INVALID")
    return min(
        candidates,
        key=lambda candidate: (-margin_efficiency(candidate), candidate.basket_id),
    )


def select_largest_non_hedge(candidates: tuple[BasketRiskV1, ...]) -> BasketRiskV1:
    """Select the largest non-hedge exposure, with stable ID tie-break."""
    if (
        type(candidates) is not tuple
        or not candidates
        or any(type(candidate) is not BasketRiskV1 for candidate in candidates)
    ):
        raise MtrPortError("INPUT_INVALID")
    if len({candidate.basket_id for candidate in candidates}) != len(candidates):
        raise MtrPortError("INPUT_INVALID")
    eligible = tuple(candidate for candidate in candidates if not candidate.is_hedge)
    if not eligible:
        raise MtrPortError("NO_NON_HEDGE_CANDIDATE")
    return min(eligible, key=lambda candidate: (-candidate.exposure_units, candidate.basket_id))


def partial_unwind_units(current_units: Decimal) -> Decimal:
    """Return one exact source-sized 25% unwind chunk, without routing it."""
    if not _bounded_decimal(current_units) or current_units <= Decimal("0"):
        raise MtrPortError("INPUT_INVALID")
    return current_units * Decimal("0.25")


@dataclass(frozen=True, slots=True)
class LiquidationInputV1:
    observed_at: datetime
    timeframe: str
    closed_bar: bool
    margin_level_pct: Decimal
    account_drawdown_pct: Decimal
    floating_drawdown_pct: Decimal
    basket_age_days: Decimal
    mae_atr: Decimal
    spread_multiple: Decimal
    trading_hour: bool
    session_gap: bool
    halt_active: bool
    slippage_cap_exceeded: bool = False
    completed_partial_chunks: int = 0

    def __post_init__(self) -> None:
        if type(self.observed_at) is not datetime or self.observed_at.tzinfo is None:
            raise MtrPortError("TIMEZONE_REQUIRED")
        if self.observed_at.utcoffset() is None:
            raise MtrPortError("TIMEZONE_REQUIRED")
        if self.timeframe != "M5" or type(self.closed_bar) is not bool or not self.closed_bar:
            raise MtrPortError("CLOSED_M5_BAR_REQUIRED")
        object.__setattr__(self, "observed_at", self.observed_at.astimezone(UTC))
        for name in (
            "margin_level_pct",
            "account_drawdown_pct",
            "floating_drawdown_pct",
            "basket_age_days",
            "mae_atr",
            "spread_multiple",
        ):
            value = getattr(self, name)
            if type(value) is not Decimal or not _bounded_decimal(value) or value < Decimal("0"):
                raise MtrPortError("INPUT_INVALID")
        if any(
            type(v) is not bool
            for v in (
                self.trading_hour,
                self.session_gap,
                self.halt_active,
                self.slippage_cap_exceeded,
            )
        ):
            raise MtrPortError("INPUT_INVALID")
        if type(self.completed_partial_chunks) is not int or self.completed_partial_chunks < 0:
            raise MtrPortError("INPUT_INVALID")


@dataclass(frozen=True, slots=True)
class LiquidationPlanV1:
    action: LiquidationActionV1
    priority: int | None
    reason: str
    observed_at: datetime
    halt_required: bool
    resume_requires_manual_review: bool


def evaluate_liquidation(
    observation: LiquidationInputV1,
    *,
    caps: SovereignCapsV1 = DEFAULT_SOVEREIGN_CAPS_V1,
) -> LiquidationPlanV1:
    """Return the highest-priority offline action, with sovereign limits first.

    Priority 3 follows ``docs/mtr_liquidation_policy_v0.md``: emit 25% unwind
    chunks and promote to the Priority 2 full-unwind path after four completed
    chunks if floating drawdown still exceeds 8%. The caller owns the counter.
    """
    if type(observation) is not LiquidationInputV1 or type(caps) is not SovereignCapsV1:
        raise MtrPortError("INPUT_INVALID")
    timestamp = observation.observed_at

    def plan(
        action: LiquidationActionV1,
        priority: int | None,
        reason: str,
        *,
        halt: bool = False,
        manual: bool = False,
    ) -> LiquidationPlanV1:
        return LiquidationPlanV1(action, priority, reason, timestamp, halt, manual)

    if observation.halt_active:
        return plan(
            LiquidationActionV1.MANUAL_REVIEW_HALT,
            None,
            "HALT_ACTIVE",
            halt=True,
            manual=True,
        )
    if observation.slippage_cap_exceeded:
        return plan(
            LiquidationActionV1.MANUAL_REVIEW_HALT,
            None,
            "SLIPPAGE_CAP_EXCEEDED",
            halt=True,
            manual=True,
        )
    no_liquidity = (
        observation.spread_multiple > Decimal("3")
        or observation.session_gap
        or not observation.trading_hour
    )
    margin = observation.margin_level_pct
    sovereign_dd_hit = observation.account_drawdown_pct >= caps.max_trailing_drawdown_pct
    if margin < Decimal("300"):
        if no_liquidity:
            if margin <= Decimal("200"):
                return plan(
                    LiquidationActionV1.EMERGENCY_CLOSE_AND_HALT,
                    1,
                    "EMERGENCY_MARGIN_BREACH",
                    halt=True,
                )
            if margin <= Decimal("250"):
                return plan(
                    LiquidationActionV1.MINIMUM_EXPOSURE_CLOSE_AND_HALT,
                    1,
                    "MARGIN_SURVIVAL",
                    halt=True,
                )
            return plan(
                LiquidationActionV1.WAIT_FOR_LIQUIDITY,
                1,
                "MARGIN_LT_300_WAIT",
                halt=sovereign_dd_hit,
            )
        return plan(
            LiquidationActionV1.CLOSE_WORST_MARGIN_EFFICIENCY,
            1,
            "MARGIN_LT_300",
            halt=sovereign_dd_hit,
        )

    if (
        observation.floating_drawdown_pct > Decimal("8")
        and observation.completed_partial_chunks >= 4
    ):
        # Source policy: docs/mtr_liquidation_policy_v0.md, Priority 3.
        # After four 25% chunks, persistent floating DD promotes to the
        # Priority 2 full-unwind path; the caller owns and feeds this counter.
        return plan(
            LiquidationActionV1.CLOSE_NON_HEDGE_EXPOSURE,
            2,
            "FLOATING_DD_ESCALATED_AFTER_4_CHUNKS",
            halt=True,
            manual=True,
        )

    if sovereign_dd_hit:
        return plan(
            LiquidationActionV1.HALT_NEW_ADDS,
            None,
            "SOVEREIGN_TRAILING_DRAWDOWN",
            halt=True,
        )

    # Sovereign trailing drawdown is 8%, below the source account-DD trigger of
    # 12%; if it has not already triggered, the source 12% rule is unreachable.
    if observation.account_drawdown_pct > Decimal("12"):
        return plan(
            LiquidationActionV1.CLOSE_NON_HEDGE_EXPOSURE,
            2,
            "ACCOUNT_DD_GT_12",
            halt=True,
            manual=True,
        )
    if observation.floating_drawdown_pct > Decimal("8"):
        return plan(LiquidationActionV1.PARTIAL_UNWIND, 3, "FLOATING_DD_GT_8")
    if observation.basket_age_days > Decimal("45"):
        return plan(LiquidationActionV1.CLOSE_BASKET, 4, "MAX_AGE")
    if observation.mae_atr > Decimal("10"):
        return plan(LiquidationActionV1.CLOSE_BASKET, 5, "MAX_MAE")
    return plan(LiquidationActionV1.NONE, None, "NO_TRIGGER")
