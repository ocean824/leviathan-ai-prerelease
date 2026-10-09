"""Truth evidence provider protocol.

Live implementations (Rithmic/Bookmap L2, Unusual Whales options, event
calendars, sentiment) plug in behind this protocol when API keys arrive.
Until then, replay and stub providers serve the paper spine.

Doctrine: missing evidence degrades toward MIXED, never toward
CONFIRMED — absence of truth is not confirmation.
"""

from typing import Protocol

from leviathan_core.schemas import CandidateSetup, TruthValidationResult


class TruthProvider(Protocol):
    def validate(self, setup: CandidateSetup) -> TruthValidationResult: ...


class StaticTruthProvider:
    """Returns a pre-built result; used by tests and fixture replays."""

    def __init__(self, result: TruthValidationResult) -> None:
        self._result = result

    def validate(self, setup: CandidateSetup) -> TruthValidationResult:
        if setup.setup_id != self._result.setup_id:
            raise ValueError("static truth result does not match setup under validation")
        return self._result
