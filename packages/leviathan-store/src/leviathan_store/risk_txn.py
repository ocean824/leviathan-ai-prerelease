"""SQLite-authoritative C-101 route transaction adapter.

Each method commits before returning. A raised commit is ambiguous to the
caller; callers must not consume or retry simulation based on that exception.
"""

from datetime import UTC, datetime
from typing import Any, cast

from sqlalchemy import CursorResult, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from leviathan_core.execution.order_models import LedgerIntegrityKey
from leviathan_core.pipeline import PreparedReplay
from leviathan_core.risk.transaction_port import ClaimReceipt, RiskDecisionPort
from leviathan_core.schemas import (
    CandidateSetup,
    DecisionPacket,
    Permission,
    RiskAction,
    RiskVerdict,
    TradeJournalRecord,
    TradeOutcome,
)
from leviathan_core.schemas.journal import require_trade_journal_record
from leviathan_core.schemas.persisted_c101 import _build_terminal_proof
from leviathan_core.schemas.risk import require_risk_verdict
from leviathan_store.repositories import (
    DecisionRepository,
    JournalRepository,
    RiskVerdictRepository,
    SetupRepository,
    decode_route_candidate,
    verified_route_candidate,
    verified_terminal_records,
)
from leviathan_store.tables import DecisionRow, RouteAttemptRow, SetupRow


class RouteTransitionError(RuntimeError):
    """A duplicate or illegal state transition cannot create an outcome."""


def is_valid_council_terminal(
    prepared: PreparedReplay,
    verdict: RiskVerdict,
    journal: TradeJournalRecord,
    *,
    unclaimed: bool,
) -> bool:
    """Allow only the exact council verdict and journal derived from a routable assessment."""
    permission = prepared.decision.permission
    if not unclaimed or permission is Permission.APPROVE:
        return False
    expected_action = RiskAction.WAIT if permission is Permission.WAIT else RiskAction.REJECT
    assessment = prepared.assessment
    return (
        assessment.action in (RiskAction.ALLOW, RiskAction.REDUCE_SIZE)
        and assessment.execution_capable
        and verdict.decision_id == prepared.decision.decision_id
        and verdict.action is expected_action
        and verdict.reason == f"council_permission_{permission.value}"
        and verdict.adjusted_size is None
        and not verdict.execution_capable
        and verdict.findings == assessment.findings
        and verdict.halts_engaged == assessment.halts_engaged
        and journal.outcome is TradeOutcome.BLOCKED
        and journal.decision_id == verdict.decision_id
        and journal.setup_id == prepared.setup.setup_id
        and is_valid_blocked_journal(journal)
        and journal.post_trade_notes
        == (
            f"blocked: permission={permission.value} "
            f"risk={verdict.action.value} reason={verdict.reason} "
            f"halts={','.join(assessment.halts_engaged)}"
        )
    )


def is_valid_blocked_journal(journal: TradeJournalRecord) -> bool:
    """A blocked route has no execution prices or excursion measurements."""
    return (
        journal.outcome is TradeOutcome.BLOCKED
        and journal.entry is None
        and journal.exit is None
        and journal.mae is None
        and journal.mfe is None
    )


class RouteAttemptStore(RiskDecisionPort):
    def __init__(
        self,
        sessions: async_sessionmaker[AsyncSession],
        *,
        integrity_key: LedgerIntegrityKey | None = None,
    ) -> None:
        if integrity_key is not None and type(integrity_key) is not LedgerIntegrityKey:
            raise RouteTransitionError("INVALID_INTEGRITY_KEY")
        self._sessions = sessions
        self._integrity_key = integrity_key

    async def prepare(
        self,
        setup: CandidateSetup,
        decision: DecisionPacket,
        assessment: RiskVerdict,
        evidence: dict[str, Any],
    ) -> None:
        require_risk_verdict(assessment)
        now = datetime.now(UTC)
        raw = evidence.get("candidate")
        digest = raw.get("policy_digest") if isinstance(raw, dict) else None
        if not isinstance(digest, str) or not isinstance(raw, dict):
            raise RouteTransitionError("canonical candidate and policy digest are required")
        try:
            prepared, identity = decode_route_candidate(raw, digest)
        except ValueError as error:
            raise RouteTransitionError("candidate identity is invalid") from error
        if (
            prepared.setup != setup
            or prepared.decision != decision
            or prepared.assessment != assessment
        ):
            raise RouteTransitionError("candidate parents or assessment differ")
        async with self._sessions() as session:
            session.add(
                RouteAttemptRow(
                    decision_id=decision.decision_id,
                    setup_id=setup.setup_id,
                    state="PENDING",
                    version=0,
                    schema_version=1,
                    assessment=assessment.model_dump(mode="json"),
                    evidence={
                        "candidate": prepared.candidate_payload(digest),
                        "candidate_identity": identity,
                    },
                    authorization=None,
                    paper_draft=None,
                    policy_digest=digest,
                    claim_token=None,
                    outcome=None,
                    final_verdict=None,
                    journal_record=None,
                    created_at=now,
                    updated_at=now,
                )
            )
            await session.commit()

    async def authorize(self, decision_id: str, paper_draft: dict[str, Any]) -> None:
        async with self._sessions() as session:
            row = await session.get(RouteAttemptRow, decision_id)
            if row is None:
                raise RouteTransitionError("candidate is not proven paper-actionable")
            try:
                prepared, _ = verified_route_candidate(row)
                expected_draft = prepared.paper_draft(row.policy_digest)
            except ValueError as error:
                raise RouteTransitionError("candidate is not proven paper-actionable") from error
            if not prepared.actionable or paper_draft != expected_draft:
                raise RouteTransitionError("paper draft differs from the prepared candidate")
            changed = cast(
                CursorResult[Any],
                await session.execute(
                    update(RouteAttemptRow)
                    .where(RouteAttemptRow.decision_id == decision_id)
                    .where(RouteAttemptRow.state == "PENDING", RouteAttemptRow.version == 0)
                    .values(
                        state="AUTHORIZED",
                        version=1,
                        paper_draft=expected_draft,
                        authorization={"action": "allow", "historical_only": True},
                        updated_at=datetime.now(UTC),
                    )
                ),
            )
            if changed.rowcount != 1:
                raise RouteTransitionError("authorization requires one pending attempt")
            await session.commit()

    async def claim(self, decision_id: str, token: str) -> ClaimReceipt | None:
        if not token:
            raise ValueError("claim token required")
        async with self._sessions() as session:
            row = await session.get(RouteAttemptRow, decision_id)
            if row is None:
                return None
            try:
                prepared, _ = verified_route_candidate(row)
            except ValueError as error:
                raise RouteTransitionError("committed candidate identity is invalid") from error
            if not prepared.actionable:
                return None
            changed = cast(
                CursorResult[Any],
                await session.execute(
                    update(RouteAttemptRow)
                    .where(RouteAttemptRow.decision_id == decision_id)
                    .where(RouteAttemptRow.state == "AUTHORIZED", RouteAttemptRow.version == 1)
                    .values(
                        state="IN_PROGRESS",
                        version=2,
                        claim_token=token,
                        updated_at=datetime.now(UTC),
                    )
                ),
            )
            if changed.rowcount != 1:
                await session.rollback()
                return None
            await session.commit()
            await session.refresh(row)
            try:
                _, committed_identity = verified_route_candidate(row)
            except ValueError as error:
                raise RouteTransitionError(
                    "committed claim candidate identity is invalid"
                ) from error
            if row.state != "IN_PROGRESS" or row.version != 2 or row.claim_token != token:
                raise RouteTransitionError("committed claim differs from receipt")
        return ClaimReceipt(
            decision_id=decision_id,
            token=token,
            version=2,
            policy_digest=row.policy_digest,
            candidate_identity=committed_identity,
        )

    async def complete(
        self,
        receipt: ClaimReceipt | None,
        setup: CandidateSetup,
        decision: DecisionPacket,
        verdict: RiskVerdict,
        journal: TradeJournalRecord,
    ) -> None:
        require_risk_verdict(verdict)
        require_trade_journal_record(journal)
        if (
            verdict.decision_id != decision.decision_id
            or journal.decision_id != decision.decision_id
            or journal.setup_id != setup.setup_id
            or decision.setup_id != setup.setup_id
        ):
            raise RouteTransitionError("terminal records do not match attempt")
        if receipt is None and verdict.action in (RiskAction.ALLOW, RiskAction.REDUCE_SIZE):
            raise RouteTransitionError("allow outcome requires a confirmed claim")
        executed = receipt is not None and verdict.action in (
            RiskAction.ALLOW,
            RiskAction.REDUCE_SIZE,
        )
        if not executed and not is_valid_blocked_journal(journal):
            raise RouteTransitionError("blocked journal carries execution fields")
        if receipt is not None and (
            receipt.decision_id != decision.decision_id or receipt.version != 2
        ):
            raise RouteTransitionError("invalid confirmed claim receipt")
        now = datetime.now(UTC)
        async with self._sessions() as session:
            row = await session.get(RouteAttemptRow, decision.decision_id)
            if row is None:
                raise RouteTransitionError("attempt is missing")
            try:
                prepared, identity = verified_route_candidate(row)
            except ValueError as error:
                raise RouteTransitionError("committed candidate identity is invalid") from error
            if prepared.setup != setup or prepared.decision != decision:
                raise RouteTransitionError("terminal parents differ from prepared candidate")
            if receipt is None:
                if prepared.actionable:
                    raise RouteTransitionError("unclaimed block differs from assessment")
                if verdict != prepared.assessment and not is_valid_council_terminal(
                    prepared, verdict, journal, unclaimed=True
                ):
                    raise RouteTransitionError("unclaimed block differs from assessment")
            elif (
                receipt.token != row.claim_token
                or receipt.policy_digest != row.policy_digest
                or receipt.candidate_identity != identity
            ):
                raise RouteTransitionError("receipt differs from committed candidate")
            if executed and verdict != prepared.assessment:
                raise RouteTransitionError("executed verdict differs from prepared assessment")
            prior_setup = await session.get(SetupRow, setup.setup_id)
            prior_decision = await session.get(DecisionRow, decision.decision_id)
            if prior_setup is not None and (
                prior_setup.payload != setup.model_dump(mode="json")
                or prior_setup.instrument != setup.instrument
            ):
                raise RouteTransitionError("existing setup payload conflicts with candidate")
            if prior_decision is not None and (
                prior_decision.payload != decision.model_dump(mode="json")
                or prior_decision.setup_id != decision.setup_id
            ):
                raise RouteTransitionError("existing decision payload conflicts with candidate")
            if receipt is None:
                where_state, where_version, next_version = "PENDING", 0, 1
            else:
                where_state, where_version, next_version = "IN_PROGRESS", 2, 3
            terminal_state = "COMPLETED" if executed else "BLOCKED"
            terminal_outcome = {
                "kind": "paper_sim" if executed else "pre_sim_block",
                "journal_outcome": journal.outcome.value,
            }
            if self._integrity_key is None:
                proof: dict[str, Any] = {
                    "schema": "c101.terminal-records",
                    "version": 1,
                    "status": "UNISSUED_PERSISTED",
                }
            else:
                candidate_payload = (
                    row.evidence.get("candidate") if isinstance(row.evidence, dict) else None
                )
                if not isinstance(candidate_payload, dict):
                    raise RouteTransitionError("TERMINAL_CANDIDATE_INVALID")
                document = {
                    "schema": "c101.persisted-terminal.v1",
                    "decision_id": row.decision_id,
                    "setup_id": row.setup_id,
                    "state": terminal_state,
                    "version": next_version,
                    "schema_version": row.schema_version,
                    "policy_digest": row.policy_digest,
                    "claim_token": row.claim_token,
                    "candidate_identity": identity,
                    "outcome": terminal_outcome,
                    "final_verdict": verdict.model_dump(mode="json"),
                    "journal_record": journal.model_dump(mode="json"),
                }
                proof = _build_terminal_proof(self._integrity_key, document)
            changed = cast(
                CursorResult[Any],
                await session.execute(
                    update(RouteAttemptRow)
                    .where(RouteAttemptRow.decision_id == decision.decision_id)
                    .where(RouteAttemptRow.state == where_state)
                    .where(RouteAttemptRow.version == where_version)
                    .where(
                        RouteAttemptRow.claim_token == receipt.token
                        if receipt is not None
                        else RouteAttemptRow.claim_token.is_(None)
                    )
                    .values(
                        state=terminal_state,
                        version=next_version,
                        outcome={**terminal_outcome, "proof": proof},
                        final_verdict=verdict.model_dump(mode="json"),
                        journal_record=journal.model_dump(mode="json"),
                        updated_at=now,
                    )
                ),
            )
            if changed.rowcount != 1:
                raise RouteTransitionError("terminal transition requires an uncompleted attempt")
            if prior_setup is None:
                await SetupRepository(session).add(setup)
            if prior_decision is None:
                await DecisionRepository(session).add(decision, at=now)
            await RiskVerdictRepository(session).add(verdict, at=now)
            await JournalRepository(session).add(journal, at=now)
            await session.commit()

    async def read_view(self, decision_id: str) -> dict[str, Any] | None:
        async with self._sessions() as session:
            row = await session.get(RouteAttemptRow, decision_id)
            if row is None:
                return None
            try:
                verified_route_candidate(row)
            except ValueError as error:
                raise RouteTransitionError("route attempt candidate is inconsistent") from error
            terminal = row.state in ("COMPLETED", "BLOCKED")
            if terminal:
                if self._integrity_key is None:
                    raise RouteTransitionError("INTEGRITY_KEY_UNAVAILABLE")
                records = await verified_terminal_records(session, row, self._integrity_key)
                if records is None:
                    proof = row.outcome.get("proof") if isinstance(row.outcome, dict) else None
                    status = (
                        "UNISSUED_PERSISTED"
                        if not isinstance(proof, dict)
                        or proof.get("status") == "UNISSUED_PERSISTED"
                        else "TERMINAL_PROOF_OR_LINKAGE_INVALID"
                    )
                    raise RouteTransitionError(status)
            outcome = (
                {key: value for key, value in row.outcome.items() if key != "proof"}
                if terminal and isinstance(row.outcome, dict)
                else None
            )
            return {
                "decision_id": decision_id,
                "status": row.state.lower() if terminal else "incomplete",
                "stage": row.state.lower(),
                "final": terminal,
                "assessment": row.assessment,
                "authorization": row.authorization,
                "paper_draft": row.paper_draft,
                "policy_digest": row.policy_digest,
                "outcome": outcome,
                "final_verdict": row.final_verdict if terminal else None,
                "journal_record": row.journal_record if terminal else None,
            }

    async def read_verified_terminal(
        self, decision_id: str
    ) -> tuple[RiskVerdict, TradeJournalRecord] | None:
        """Return the exact issued terminal pair after keyed reload verification."""
        async with self._sessions() as session:
            row = await session.get(RouteAttemptRow, decision_id)
            if row is None or row.state not in ("COMPLETED", "BLOCKED"):
                return None
            if self._integrity_key is None:
                raise RouteTransitionError("INTEGRITY_KEY_UNAVAILABLE")
            try:
                verified_route_candidate(row)
            except ValueError as error:
                code = (
                    "TERMINAL_PARTIAL_INVALID"
                    if any(
                        value is None
                        for value in (row.outcome, row.final_verdict, row.journal_record)
                    )
                    else "TERMINAL_PARENT_INVALID"
                )
                raise RouteTransitionError(code) from error
            records = await verified_terminal_records(session, row, self._integrity_key)
            if records is None:
                proof = row.outcome.get("proof") if isinstance(row.outcome, dict) else None
                status = (
                    "UNISSUED_PERSISTED"
                    if not isinstance(proof, dict) or proof.get("status") == "UNISSUED_PERSISTED"
                    else "TERMINAL_PROOF_OR_LINKAGE_INVALID"
                )
                raise RouteTransitionError(status)
            return records
