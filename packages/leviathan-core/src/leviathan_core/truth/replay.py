"""ReplayTruthProvider — deterministic truth validation from stored fixtures.

Loads pre-built TruthValidationResult payloads keyed by setup_id. Intended
for paper-spine testing, fixture replay, and backtests where live sources are
not available.

Usage:
    payload = {
        "setup_nq_001": {
            "setup_id": "setup_nq_001",
            "orderbook_bias": "bullish",
            ...
        }
    }
    provider = ReplayTruthProvider(payload)
    result = provider.validate(setup)
"""

from typing import Any

from leviathan_core.schemas import CandidateSetup, TruthValidationResult


class ReplayTruthProvider:
    """Returns pre-built TruthValidationResults keyed by setup_id.

    The ``payload`` dict maps setup_id strings to raw dict representations of
    TruthValidationResult (the same structure as the "truth_validation" block
    in fixture JSON files).  Each dict is validated through the Pydantic model
    at construction time so errors surface early.

    Raises KeyError with a descriptive message if a setup_id not present in
    the payload is requested at validate() time.
    """

    def __init__(self, payload: dict[str, dict[str, Any]]) -> None:
        self._store: dict[str, TruthValidationResult] = {
            setup_id: TruthValidationResult.model_validate(data)
            for setup_id, data in payload.items()
        }

    def validate(self, setup: CandidateSetup) -> TruthValidationResult:
        """Return the stored result for this setup_id.

        Raises:
            KeyError: if setup.setup_id is not in the replay payload.
        """
        result = self._store.get(setup.setup_id)
        if result is None:
            available = ", ".join(sorted(self._store)) or "<empty>"
            raise KeyError(
                f"ReplayTruthProvider: no stored result for setup_id={setup.setup_id!r}. "
                f"Available ids: {available}"
            )
        return result
