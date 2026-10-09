"""Async repositories mediating between Layer-1 contracts and rows.

Each repository takes an :class:`~sqlalchemy.ext.asyncio.AsyncSession`
and knows how to fold a frozen pydantic contract down into a row and
rebuild it on the way out. The rules are uniform:

* **Write** — ``model_dump(mode="json")`` produces the ``payload`` JSON
  (Decimals become strings, so precision survives), and a few scalar
  fields are lifted into indexed columns for querying.
* **Read** — ``model_validate(row.payload)`` rebuilds the exact contract;
  the scalar columns are never trusted as the source of truth.

Three ledgers are **append-only** — :class:`JournalRepository`,
:class:`GenomeRepository.record_validation`, and
:class:`RiskVerdictRepository` — and expose no update or delete methods
by design. History is extended, never rewritten.

Callers own the transaction boundary: repositories ``flush`` so
autoincrement ids and constraints surface immediately, but never
``commit``. Wrap a unit of work in ``async with sessionmaker() as s:``
and commit once at the end.
"""

from collections import Counter
from datetime import datetime
from decimal import Decimal
from typing import Any

from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from leviathan_core.execution.order_models import LedgerIntegrityKey
from leviathan_core.pipeline import PreparedReplay
from leviathan_core.risk.transaction_port import candidate_identity
from leviathan_core.schemas import (
    CandidateSetup,
    DecisionPacket,
    RiskVerdict,
    StrategyGenome,
    TradeJournalRecord,
)
from leviathan_core.schemas.persisted_c101 import _issue_verified_terminal_records
from leviathan_store.tables import (
    DecisionRow,
    GenomeRow,
    GenomeValidationRow,
    JournalRow,
    RiskVerdictRow,
    RouteAttemptRow,
    SetupRow,
)


def decode_route_candidate(
    payload: dict[str, Any], policy_digest: str
) -> tuple[PreparedReplay, str]:
    """Rebuild the full candidate and derive its identity from canonical typed data."""
    raw = payload.get("prepared")
    if not isinstance(raw, dict) or payload.get("policy_digest") != policy_digest:
        raise ValueError("route candidate is incomplete")
    prepared = PreparedReplay.model_validate(raw)
    canonical = prepared.candidate_payload(policy_digest)
    if payload != canonical:
        raise ValueError("route candidate is not canonical")
    if (
        prepared.decision.setup_id != prepared.setup.setup_id
        or prepared.truth.setup_id != prepared.setup.setup_id
        or prepared.assessment.decision_id != prepared.decision.decision_id
        or any(bar.instrument != prepared.setup.instrument for bar in prepared.bars)
    ):
        raise ValueError("route candidate parent or bar identity differs")
    if prepared.actionable:
        snapshot = prepared.risk_snapshot
        if (
            snapshot is None
            or prepared.context is None
            or not prepared.bars
            or len(policy_digest) != 64
            or snapshot.risk_lock_sha256 != policy_digest
            or prepared.setup.instrument not in snapshot.allowed_instruments
            or snapshot.max_position_size
            != (prepared.assessment.adjusted_size or prepared.requested_size)
        ):
            raise ValueError("actionable route candidate lacks risk or replay proof")
        draft = prepared.paper_draft(policy_digest)
        if any(
            Decimal(draft[key]) <= 0
            for key in ("entry_price", "adjusted_size", "stop_loss", "take_profit")
        ):
            raise ValueError("paper draft has invalid order prices or size")
    elif prepared.risk_snapshot is not None:
        raise ValueError("nonactionable candidate has a risk snapshot")
    return prepared, candidate_identity(canonical)


def verified_route_candidate(row: RouteAttemptRow) -> tuple[PreparedReplay, str]:
    """Check persisted candidate, draft, claim stage and row links before use."""
    payload = row.evidence.get("candidate") if isinstance(row.evidence, dict) else None
    if row.schema_version != 1 or not isinstance(payload, dict):
        raise ValueError("route attempt has no supported candidate")
    prepared, identity = decode_route_candidate(payload, row.policy_digest)
    if (
        row.evidence != {"candidate": payload, "candidate_identity": identity}
        or row.decision_id != prepared.decision.decision_id
        or row.setup_id != prepared.setup.setup_id
        or row.assessment != prepared.assessment.model_dump(mode="json")
    ):
        raise ValueError("route attempt candidate identity differs")
    has_draft = row.state in ("AUTHORIZED", "IN_PROGRESS", "COMPLETED") or (
        row.state == "BLOCKED" and row.version == 3
    )
    if has_draft:
        if (
            not prepared.actionable
            or row.paper_draft != prepared.paper_draft(row.policy_digest)
            or row.authorization != {"action": "allow", "historical_only": True}
        ):
            raise ValueError("route authorization differs from candidate")
    elif row.paper_draft is not None or row.authorization is not None:
        raise ValueError("unauthorized attempt has a draft")
    expected_version = {"PENDING": 0, "AUTHORIZED": 1, "IN_PROGRESS": 2, "COMPLETED": 3}.get(
        row.state, row.version if row.state == "BLOCKED" and row.version in (1, 3) else -1
    )
    claimed = row.state in ("IN_PROGRESS", "COMPLETED") or (
        row.state == "BLOCKED" and row.version == 3
    )
    if expected_version < 0 or row.version != expected_version or bool(row.claim_token) != claimed:
        raise ValueError("route attempt claim stage differs")
    terminal = row.state in ("COMPLETED", "BLOCKED")
    final_fields = (row.outcome, row.final_verdict, row.journal_record)
    if (terminal and any(value is None for value in final_fields)) or (
        not terminal and any(value is not None for value in final_fields)
    ):
        raise ValueError("route attempt terminal fields differ")
    return prepared, identity


async def verified_terminal_records(
    session: AsyncSession,
    row: RouteAttemptRow,
    key: LedgerIntegrityKey | None = None,
) -> tuple[RiskVerdict, TradeJournalRecord] | None:
    """Return only a keyed, fully linked and kernel-issued terminal record pair."""
    if row.state not in ("COMPLETED", "BLOCKED"):
        return None
    if type(key) is not LedgerIntegrityKey:
        return None
    try:
        prepared, _ = verified_route_candidate(row)
        verdict = RiskVerdict.model_validate(row.final_verdict)
        journal = TradeJournalRecord.model_validate(row.journal_record)
    except ValueError:
        return None
    if row.state == "BLOCKED":
        # Local import avoids a module cycle: risk_txn uses repository adapters.
        from leviathan_store.risk_txn import is_valid_blocked_journal

        if not is_valid_blocked_journal(journal):
            return None
    valid_unclaimed_terminal = True
    if row.state == "BLOCKED" and row.version == 1 and verdict != prepared.assessment:
        # Local import avoids a module cycle: risk_txn uses repository adapters.
        from leviathan_store.risk_txn import is_valid_council_terminal

        valid_unclaimed_terminal = is_valid_council_terminal(
            prepared, verdict, journal, unclaimed=row.claim_token is None
        )
    expected_outcome = {
        "kind": "paper_sim" if row.state == "COMPLETED" else "pre_sim_block",
        "journal_outcome": journal.outcome.value,
    }
    outcome = row.outcome
    if type(outcome) is not dict or set(outcome) != {"kind", "journal_outcome", "proof"}:
        return None
    if {key: value for key, value in outcome.items() if key != "proof"} != expected_outcome:
        return None
    candidate_payload = row.evidence.get("candidate") if isinstance(row.evidence, dict) else None
    if type(candidate_payload) is not dict:
        return None
    document = {
        "schema": "c101.persisted-terminal.v1",
        "decision_id": row.decision_id,
        "setup_id": row.setup_id,
        "state": row.state,
        "version": row.version,
        "schema_version": row.schema_version,
        "policy_digest": row.policy_digest,
        "claim_token": row.claim_token,
        "candidate_identity": candidate_identity(candidate_payload),
        "outcome": expected_outcome,
        "final_verdict": row.final_verdict,
        "journal_record": row.journal_record,
    }
    setup = await session.get(SetupRow, row.setup_id)
    decision = await session.get(DecisionRow, row.decision_id)
    verdict_rows = (
        await session.scalars(
            select(RiskVerdictRow).where(RiskVerdictRow.decision_id == row.decision_id)
        )
    ).all()
    journal_rows = (
        await session.scalars(select(JournalRow).where(JournalRow.decision_id == row.decision_id))
    ).all()
    if (
        setup is None
        or decision is None
        or setup.payload != prepared.setup.model_dump(mode="json")
        or setup.instrument != prepared.setup.instrument
        or decision.payload != prepared.decision.model_dump(mode="json")
        or decision.setup_id != prepared.setup.setup_id
        or verdict.decision_id != row.decision_id
        or journal.decision_id != row.decision_id
        or journal.setup_id != row.setup_id
        or len(verdict_rows) != 1
        or len(journal_rows) != 1
        or verdict_rows[0].payload != row.final_verdict
        or verdict_rows[0].action != verdict.action.value
        or journal_rows[0].payload != row.journal_record
        or journal_rows[0].setup_id != row.setup_id
        or journal_rows[0].outcome != journal.outcome.value
        or (row.state == "COMPLETED") != (verdict.action.value in ("allow", "reduce_size"))
        or (row.state == "COMPLETED" and verdict != prepared.assessment)
        or not valid_unclaimed_terminal
        or (row.state == "BLOCKED" and journal.outcome.value != "blocked")
    ):
        return None
    try:
        return _issue_verified_terminal_records(key=key, document=document, proof=outcome["proof"])
    except (TypeError, ValueError):
        return None


class GenomeRepository:
    """Current-state genome store plus an append-only validation ledger."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def upsert(self, genome: StrategyGenome, *, at: datetime) -> None:
        """Insert a new genome or overwrite the existing one in place.

        ``created_at`` is preserved on update; ``updated_at`` always moves
        to ``at``.
        """
        row = await self._session.get(GenomeRow, genome.strategy_id)
        payload = genome.model_dump(mode="json")
        if row is None:
            self._session.add(
                GenomeRow(
                    strategy_id=genome.strategy_id,
                    family=genome.family,
                    market=genome.market,
                    timeframe=genome.timeframe,
                    payload=payload,
                    created_at=at,
                    updated_at=at,
                )
            )
        else:
            row.family = genome.family
            row.market = genome.market
            row.timeframe = genome.timeframe
            row.payload = payload
            row.updated_at = at
        await self._session.flush()

    async def get(self, strategy_id: str) -> StrategyGenome | None:
        row = await self._session.get(GenomeRow, strategy_id)
        if row is None:
            return None
        return StrategyGenome.model_validate(row.payload)

    async def list_all(self) -> list[StrategyGenome]:
        result = await self._session.scalars(select(GenomeRow).order_by(GenomeRow.strategy_id))
        return [StrategyGenome.model_validate(row.payload) for row in result]

    async def record_validation(
        self,
        strategy_id: str,
        stage: str,
        passed: bool,
        metrics: dict[str, Any],
        at: datetime,
    ) -> None:
        """Append one RBI validation result. Ledger row — never updated."""
        self._session.add(
            GenomeValidationRow(
                strategy_id=strategy_id,
                stage=stage,
                passed=passed,
                metrics=metrics,
                validated_at=at,
            )
        )
        await self._session.flush()

    async def latest_validation(self, strategy_id: str) -> GenomeValidationRow | None:
        """Most recent validation for a genome, or ``None`` if never validated."""
        result = await self._session.scalars(
            select(GenomeValidationRow)
            .where(GenomeValidationRow.strategy_id == strategy_id)
            .order_by(
                GenomeValidationRow.validated_at.desc(),
                GenomeValidationRow.id.desc(),
            )
            .limit(1)
        )
        return result.first()


class SetupRepository:
    """Candidate setup evidence store."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, setup: CandidateSetup) -> None:
        self._session.add(
            SetupRow(
                setup_id=setup.setup_id,
                instrument=setup.instrument,
                ts=setup.timestamp,
                payload=setup.model_dump(mode="json"),
            )
        )
        await self._session.flush()

    async def get(self, setup_id: str) -> CandidateSetup | None:
        row = await self._session.get(SetupRow, setup_id)
        if row is None:
            return None
        return CandidateSetup.model_validate(row.payload)


class DecisionRepository:
    """Decision Domain output store."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, decision: DecisionPacket, *, at: datetime) -> None:
        self._session.add(
            DecisionRow(
                decision_id=decision.decision_id,
                setup_id=decision.setup_id,
                permission=decision.permission.value,
                direction=decision.direction.value,
                confidence=decision.confidence,
                payload=decision.model_dump(mode="json"),
                created_at=at,
            )
        )
        await self._session.flush()

    async def get(self, decision_id: str) -> DecisionPacket | None:
        row = await self._session.get(DecisionRow, decision_id)
        if row is None:
            return None
        return DecisionPacket.model_validate(row.payload)

    async def list_recent(self, limit: int = 50) -> list[DecisionPacket]:
        result = await self._session.scalars(
            select(DecisionRow)
            .order_by(DecisionRow.created_at.desc(), DecisionRow.decision_id.desc())
            .limit(limit)
        )
        return [DecisionPacket.model_validate(row.payload) for row in result]


class JournalRepository:
    """Append-only journal; raw historical reads include legacy/unverified rows."""

    def __init__(
        self,
        session: AsyncSession,
        *,
        integrity_key: LedgerIntegrityKey | None = None,
    ) -> None:
        self._session = session
        self._integrity_key = integrity_key
        self.undecodable_count = 0

    async def add(self, record: TradeJournalRecord, *, at: datetime) -> None:
        self._session.add(
            JournalRow(
                trade_id=record.trade_id,
                setup_id=record.setup_id,
                decision_id=record.decision_id,
                outcome=record.outcome.value,
                entry=record.entry,
                exit=record.exit,
                mae=record.mae,
                mfe=record.mfe,
                notes=record.post_trade_notes,
                payload=record.model_dump(mode="json"),
                created_at=at,
            )
        )
        await self._session.flush()

    async def get(self, trade_id: str) -> TradeJournalRecord | None:
        row = await self._session.get(JournalRow, trade_id)
        if row is None:
            return None
        return TradeJournalRecord.model_validate(row.payload)

    async def list_recent(self, limit: int = 50) -> list[TradeJournalRecord]:
        """Historical raw rows; do not use as C-101 final-route proof."""
        result = await self._session.scalars(
            select(JournalRow)
            .order_by(JournalRow.created_at.desc(), JournalRow.trade_id.desc())
            .limit(limit)
        )
        self.undecodable_count = 0
        records: list[TradeJournalRecord] = []
        for row in result:
            try:
                records.append(TradeJournalRecord.model_validate(row.payload))
            except ValidationError:
                self.undecodable_count += 1
        return records

    async def list_authoritative_recent(self, limit: int | None = 50) -> list[TradeJournalRecord]:
        """Terminal route rows whose journal and verdict match one transaction."""
        query = (
            select(RouteAttemptRow)
            .where(RouteAttemptRow.state.in_(("COMPLETED", "BLOCKED")))
            .order_by(RouteAttemptRow.updated_at.desc(), RouteAttemptRow.decision_id.desc())
        )
        if limit is not None:
            query = query.limit(limit)
        attempts = await self._session.scalars(query)
        records: list[TradeJournalRecord] = []
        for attempt in attempts:
            if (
                verified := await verified_terminal_records(
                    self._session, attempt, self._integrity_key
                )
            ) is not None:
                records.append(verified[1])
        return records

    async def authoritative_stats(self) -> dict[str, int]:
        records = await self.list_authoritative_recent(limit=None)
        return dict(Counter(record.outcome.value for record in records))

    async def stats(self) -> dict[str, int]:
        """Raw historical counts, including pre-v0.4 legacy/unverified rows.

        Outcomes with zero rows are simply absent from the mapping.
        """
        result = await self._session.execute(
            select(JournalRow.outcome, func.count()).group_by(JournalRow.outcome)
        )
        counts: Counter[str] = Counter()
        for outcome, count in result.all():
            counts[outcome] = count
        return dict(counts)


class RiskVerdictRepository:
    """Append-only raw verdict ledger, including legacy unverified rows.

    ``list_recent`` is historical inspection only. Authoritative final reads
    must use RouteAttemptStore.read_view, which requires a terminal attempt and
    matching journal row; pre-v0.4 rows are never promoted automatically.
    """

    def __init__(
        self,
        session: AsyncSession,
        *,
        integrity_key: LedgerIntegrityKey | None = None,
    ) -> None:
        self._session = session
        self._integrity_key = integrity_key

    async def add(self, verdict: RiskVerdict, *, at: datetime) -> None:
        adjusted_size: Decimal | None = verdict.adjusted_size
        self._session.add(
            RiskVerdictRow(
                decision_id=verdict.decision_id,
                action=verdict.action.value,
                reason=verdict.reason,
                adjusted_size=adjusted_size,
                payload=verdict.model_dump(mode="json"),
                recorded_at=at,
            )
        )
        await self._session.flush()

    async def list_recent(self, limit: int = 50) -> list[RiskVerdict]:
        """Raw historical rows; includes pre-v0.4 legacy/unverified data."""
        result = await self._session.scalars(
            select(RiskVerdictRow)
            .order_by(RiskVerdictRow.recorded_at.desc(), RiskVerdictRow.id.desc())
            .limit(limit)
        )
        return [RiskVerdict.model_validate(row.payload) for row in result]

    async def list_authoritative_recent(self, limit: int = 50) -> list[RiskVerdict]:
        """Only terminal route attempts with matching verdict and journal rows."""
        attempts = await self._session.scalars(
            select(RouteAttemptRow)
            .where(RouteAttemptRow.state.in_(("COMPLETED", "BLOCKED")))
            .order_by(RouteAttemptRow.updated_at.desc(), RouteAttemptRow.decision_id.desc())
            .limit(limit)
        )
        final: list[RiskVerdict] = []
        for attempt in attempts:
            if (
                verified := await verified_terminal_records(
                    self._session, attempt, self._integrity_key
                )
            ) is not None:
                final.append(verified[0])
        return final
