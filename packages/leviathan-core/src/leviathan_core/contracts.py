"""Cross-layer contract rules.

These guards encode the non-negotiable pipeline rules from the schema
contract document. They are pure functions so every layer (paper sim,
MT5 bridge, direct broker) enforces identical law.

Rules enforced:
1. Execution may not create its own thesis — an ExecutionIntent can only
   be built from an APPROVED DecisionPacket.
2. Decision may not ignore Truth status — a REJECTED truth result can
   never yield an approve permission.
3. RiskSnapshot must be frozen before ExecutionIntent exists — intents
   must carry the authorizing snapshot's session_id.
4. Instruments must be allowed under the frozen snapshot.
"""

from leviathan_core.schemas import (
    DecisionPacket,
    ExecutionIntent,
    Permission,
    RiskSnapshot,
    TruthStatus,
    TruthValidationResult,
)


class ContractViolationError(Exception):
    """A layer attempted to break pipeline law. Always fatal, never caught silently."""


def assert_decision_respects_truth(
    decision: DecisionPacket, truth: TruthValidationResult
) -> None:
    if decision.setup_id != truth.setup_id:
        raise ContractViolationError(
            f"decision {decision.decision_id} and truth result reference different setups"
        )
    if truth.truth_status is TruthStatus.REJECTED and decision.permission is Permission.APPROVE:
        raise ContractViolationError(
            f"decision {decision.decision_id} approves a setup the Truth Domain rejected"
        )


def assert_trade_is_executable(
    decision: DecisionPacket, risk: RiskSnapshot, instrument: str
) -> None:
    if decision.permission is not Permission.APPROVE:
        raise ContractViolationError(
            f"decision {decision.decision_id} is '{decision.permission}', not approved"
        )
    if instrument not in risk.allowed_instruments:
        raise ContractViolationError(
            f"instrument {instrument!r} is not allowed under risk session {risk.session_id}"
        )


def assert_intent_is_authorized(intent: ExecutionIntent, risk: RiskSnapshot) -> None:
    if intent.risk_session_id != risk.session_id:
        raise ContractViolationError(
            "execution intent was not authorized under the active frozen RiskSnapshot"
        )
    if intent.size > risk.max_position_size:
        raise ContractViolationError(
            f"intent size {intent.size} exceeds frozen max_position_size {risk.max_position_size}"
        )
