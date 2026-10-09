"""Market-state transition engine.

Implements docs/market-state-transition-matrix.md: the preferred
transition table, risk-class semantics, policy actions, and the
confidence adjustment formula. Unlisted transitions are UNSTABLE and
require manual review — the matrix is a whitelist, not a suggestion.
"""

from leviathan_core.schemas import MarketState, PolicyAction, TransitionRiskClass
from leviathan_core.schemas.base import LeviathanModel

_S = MarketState
_R = TransitionRiskClass
_P = PolicyAction

# (from, to) -> (risk class, policy action). "None" as from-state = any state.
_MATRIX: dict[tuple[MarketState | None, MarketState], tuple[TransitionRiskClass, PolicyAction]] = {
    (_S.COMPRESSION, _S.BREAKOUT): (_R.STABLE, _P.EVALUATE_NORMALLY),
    (_S.BREAKOUT, _S.TREND_CONTINUATION): (_R.STABLE, _P.EVALUATE_NORMALLY),
    (_S.BREAKOUT, _S.MEAN_REVERSION): (_R.CAUTION, _P.REQUIRE_RETEST_CONFIRMATION),
    (_S.TREND_CONTINUATION, _S.EXPANSION): (_R.STABLE, _P.EVALUATE_NORMALLY),
    (_S.TREND_CONTINUATION, _S.DISTRIBUTION): (_R.CAUTION, _P.REDUCE_SIZE_AND_CONFIDENCE),
    (_S.TREND_CONTINUATION, _S.MEAN_REVERSION): (_R.CAUTION, _P.REDUCE_SIZE_AND_CONFIDENCE),
    (_S.DISTRIBUTION, _S.MEAN_REVERSION): (_R.STABLE, _P.EVALUATE_NORMALLY),
    (_S.ACCUMULATION, _S.BREAKOUT): (_R.STABLE, _P.EVALUATE_NORMALLY),
    (None, _S.EVENT_LOCKED): (_R.UNSTABLE, _P.NO_AUTONOMOUS_TRADE_APPROVAL),
    (_S.EVENT_LOCKED, _S.COMPRESSION): (_R.CAUTION, _P.REQUIRE_RETEST_CONFIRMATION),
    (_S.EVENT_LOCKED, _S.EXPANSION): (_R.UNSTABLE, _P.WAIT_FOR_POST_EVENT_NORMALIZATION),
}

_CONFIDENCE_PENALTY = {_R.STABLE: 0.0, _R.CAUTION: 0.15, _R.UNSTABLE: 0.35}


class StateTransition(LeviathanModel):
    from_state: MarketState
    to_state: MarketState
    risk_class: TransitionRiskClass
    policy_action: PolicyAction


class TransitionEngine:
    def classify(self, from_state: MarketState, to_state: MarketState) -> StateTransition:
        if from_state is to_state:
            risk, policy = _R.STABLE, _P.EVALUATE_NORMALLY
        else:
            entry = _MATRIX.get((None, to_state)) or _MATRIX.get((from_state, to_state))
            risk, policy = entry if entry else (_R.UNSTABLE, _P.MANUAL_REVIEW_REQUIRED)
        return StateTransition(
            from_state=from_state, to_state=to_state, risk_class=risk, policy_action=policy
        )

    def adjust_confidence(self, base_confidence: float, transition: StateTransition) -> float:
        return max(0.0, base_confidence - _CONFIDENCE_PENALTY[transition.risk_class])
