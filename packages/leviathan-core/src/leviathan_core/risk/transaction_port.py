"""Durable route-attempt boundary used by the paper replay coordinator.

The core describes the contract; only the application supplies the runtime
adapter.  A claim receipt is returned only after the adapter's commit succeeds.
"""

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Protocol

from leviathan_core.schemas import CandidateSetup, DecisionPacket, RiskVerdict, TradeJournalRecord

CANDIDATE_SCHEMA = "c101-route-candidate-v1"
DRAFT_SCHEMA = "c101-paper-draft-v1"


def candidate_identity(candidate: dict[str, Any]) -> str:
    """Hash a schema-tagged candidate with deterministic JSON, never a caller's digest field."""
    if candidate.get("schema") != CANDIDATE_SCHEMA:
        raise ValueError("unsupported route candidate schema")
    canonical = json.dumps(
        candidate, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ClaimReceipt:
    decision_id: str
    token: str
    version: int
    policy_digest: str
    candidate_identity: str


class RiskDecisionPort(Protocol):
    async def prepare(
        self,
        setup: CandidateSetup,
        decision: DecisionPacket,
        assessment: RiskVerdict,
        evidence: dict[str, Any],
    ) -> None: ...

    async def authorize(self, decision_id: str, paper_draft: dict[str, Any]) -> None: ...

    async def claim(self, decision_id: str, token: str) -> ClaimReceipt | None: ...

    async def complete(
        self,
        receipt: ClaimReceipt | None,
        setup: CandidateSetup,
        decision: DecisionPacket,
        verdict: RiskVerdict,
        journal: TradeJournalRecord,
    ) -> None: ...

    async def read_view(self, decision_id: str) -> dict[str, Any] | None: ...
