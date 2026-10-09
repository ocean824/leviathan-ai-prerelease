"""Council decision engine — weighted consensus, capital permission.

Deterministic rule-based synthesis of the sensory layers (SIREN signal,
MERMAID session, CHARYBDIS state, SCYLLA truth). Truth carries the
heaviest weight: order book truth outranks chart cosmetics. An LLM
reasoning provider can later replace the scoring internals behind the
same interface; the permission logic and contract guards stay.
"""

from decimal import Decimal

from leviathan_core.contracts import assert_decision_respects_truth
from leviathan_core.schemas import (
    CandidateSetup,
    DecisionPacket,
    Direction,
    EventRisk,
    MarketState,
    Permission,
    PolicyAction,
    StrategyGenome,
    TransitionRiskClass,
    TruthStatus,
    TruthValidationResult,
    new_id,
)
from leviathan_core.state.session_classifier import SessionContext
from leviathan_core.state.transition_engine import StateTransition, TransitionEngine

# Council weights — truth outranks everything (sums to 1.0).
WEIGHT_TRUTH = 0.35
WEIGHT_STATE = 0.25
WEIGHT_SIGNAL = 0.20
WEIGHT_SESSION = 0.20

CONSENSUS_THRESHOLD = 0.75
WAIT_FLOOR = 0.60

_TRUTH_SCORE = {TruthStatus.CONFIRMED: 1.0, TruthStatus.MIXED: 0.5, TruthStatus.REJECTED: 0.0}

_BULLISH_FEATURES = frozenset({"msb_up", "bos_up", "opening_range_break", "accumulation_spring"})
_BEARISH_FEATURES = frozenset({"msb_down", "bos_down", "opening_range_breakdown", "upthrust"})


class CouncilDecisionEngine:
    def __init__(self, transition_engine: TransitionEngine | None = None) -> None:
        self._transitions = transition_engine or TransitionEngine()

    def decide(
        self,
        setup: CandidateSetup,
        truth: TruthValidationResult,
        session: SessionContext,
        prior_state: MarketState = MarketState.COMPRESSION,
        genome: StrategyGenome | None = None,
    ) -> DecisionPacket:
        to_state = setup.state_label or MarketState.COMPRESSION
        transition = self._transitions.classify(prior_state, to_state)

        score = self._consensus_score(setup, truth, session, transition, genome)
        confidence = self._transitions.adjust_confidence(score, transition)
        confidence = max(0.0, min(1.0, confidence + float(truth.sentiment_modifier)))

        permission = self._permission(truth, transition, confidence)
        direction = (
            Direction.FLAT if permission is Permission.REJECT else self._direction(setup, truth)
        )

        decision = DecisionPacket(
            decision_id=new_id("dec"),
            setup_id=setup.setup_id,
            permission=permission,
            direction=direction,
            confidence=Decimal(repr(round(confidence, 4))),
            entry_style=self._entry_style(transition),
            scaling_allowed=(
                permission is Permission.APPROVE
                and confidence >= 0.85
                and transition.risk_class is TransitionRiskClass.STABLE
            ),
            justification=self._justification(score, truth, session, transition),
        )
        assert_decision_respects_truth(decision, truth)
        return decision

    def _consensus_score(
        self,
        setup: CandidateSetup,
        truth: TruthValidationResult,
        session: SessionContext,
        transition: StateTransition,
        genome: StrategyGenome | None,
    ) -> float:
        signal_score = min(1.0, len(setup.signal_features) / 3) if setup.signal_features else 0.0
        if setup.liquidity_features:
            signal_score = min(1.0, signal_score + 0.15)

        state_score = 1.0 if transition.risk_class is TransitionRiskClass.STABLE else (
            0.5 if transition.risk_class is TransitionRiskClass.CAUTION else 0.0
        )
        if genome and setup.state_label and setup.state_label in genome.state_dependencies:
            state_score = min(1.0, state_score + 0.2)

        session_score = session.quality
        if genome and genome.session_dependencies and (
            session.label.value not in genome.session_dependencies
        ):
            session_score *= Decimal("0.5")

        session_score_float = float(session_score)

        return (
            WEIGHT_SIGNAL * signal_score
            + WEIGHT_STATE * state_score
            + WEIGHT_SESSION * session_score_float
            + WEIGHT_TRUTH * _TRUTH_SCORE[truth.truth_status]
        )

    def _permission(
        self, truth: TruthValidationResult, transition: StateTransition, confidence: float
    ) -> Permission:
        if truth.truth_status is TruthStatus.REJECTED:
            return Permission.REJECT
        if truth.event_risk is EventRisk.NO_TRADE or transition.policy_action in (
            PolicyAction.NO_AUTONOMOUS_TRADE_APPROVAL,
            PolicyAction.WAIT_FOR_POST_EVENT_NORMALIZATION,
        ):
            return Permission.SIGNAL_ONLY
        if transition.policy_action is PolicyAction.MANUAL_REVIEW_REQUIRED:
            return Permission.WAIT
        if confidence >= CONSENSUS_THRESHOLD:
            return Permission.APPROVE
        if confidence >= WAIT_FLOOR:
            return Permission.WAIT
        return Permission.REJECT

    def _direction(self, setup: CandidateSetup, truth: TruthValidationResult) -> Direction:
        features = set(setup.signal_features)
        if features & _BULLISH_FEATURES:
            return Direction.LONG
        if features & _BEARISH_FEATURES:
            return Direction.SHORT
        if truth.orderbook_bias.value == "bullish":
            return Direction.LONG
        if truth.orderbook_bias.value == "bearish":
            return Direction.SHORT
        return Direction.FLAT

    def _entry_style(self, transition: StateTransition) -> str:
        if transition.policy_action is PolicyAction.REQUIRE_RETEST_CONFIRMATION:
            return "breakout_retest"
        if transition.to_state is MarketState.BREAKOUT:
            return "breakout"
        if transition.to_state is MarketState.MEAN_REVERSION:
            return "fade_extreme"
        return "confirmation_entry"

    def _justification(
        self,
        score: float,
        truth: TruthValidationResult,
        session: SessionContext,
        transition: StateTransition,
    ) -> str:
        return (
            f"consensus={score:.2f} truth={truth.truth_status.value} "
            f"session={session.label.value}(q={session.quality:.2f}) "
            f"transition={transition.from_state.value}->{transition.to_state.value}"
            f"[{transition.risk_class.value}]"
        )
