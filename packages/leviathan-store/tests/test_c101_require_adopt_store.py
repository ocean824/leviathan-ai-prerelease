"""C-101 typed write gates and authenticated persisted terminal reloads."""

from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from leviathan_store.engine import create_engine_and_sessionmaker, init_schema
from leviathan_store.risk_txn import RouteAttemptStore, RouteTransitionError
from leviathan_store.tables import JournalRow, RiskVerdictRow, RouteAttemptRow
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from leviathan_core.execution.order_models import LedgerIntegrityKey
from leviathan_core.pipeline import PreparedReplay
from leviathan_core.schemas import CandidateSetup, DecisionPacket, RiskAction, RiskVerdict
from leviathan_core.schemas.enums import TradeOutcome
from leviathan_core.schemas.journal import (
    TradeJournalRecord,
    _issue_trade_journal_record,
    require_trade_journal_record,
)
from leviathan_core.schemas.risk import _issue_risk_verdict, require_risk_verdict
from leviathan_core.schemas.truth import TruthValidationResult
from leviathan_core.seal import SealError
from leviathan_core.state.session_classifier import classify_session

pytestmark = pytest.mark.asyncio
_AT = datetime(2026, 9, 30, 14, tzinfo=UTC)
_POLICY_DIGEST = "a" * 64
_KEY = LedgerIntegrityKey(b"c101-store-adopt-synthetic-integrity-key-0001")


def _records() -> tuple[
    CandidateSetup, DecisionPacket, RiskVerdict, TradeJournalRecord, dict[str, Any]
]:
    setup = CandidateSetup(
        setup_id="setup_store_adopt",
        instrument="NQ",
        timestamp=_AT,
        signal_features=("acceptance",),
    )
    decision = DecisionPacket(
        decision_id="decision_store_adopt",
        setup_id=setup.setup_id,
        permission="reject",
        direction="long",
        confidence=0.5,
        entry_style="paper_market",
        scaling_allowed=False,
        justification="synthetic storage test",
    )
    verdict = _issue_risk_verdict(
        RiskVerdict(
            decision_id=decision.decision_id,
            action=RiskAction.REJECT,
            reason="synthetic_block",
            execution_capable=False,
        )
    )
    journal = _issue_trade_journal_record(
        TradeJournalRecord(
            trade_id="trade_store_adopt",
            setup_id=setup.setup_id,
            decision_id=decision.decision_id,
            outcome=TradeOutcome.BLOCKED,
            post_trade_notes="synthetic blocked route",
        )
    )
    prepared = PreparedReplay(
        setup=setup,
        session=classify_session(_AT),
        range_context=None,
        truth=TruthValidationResult(
            setup_id=setup.setup_id,
            orderbook_bias="neutral",
            options_context="synthetic",
            event_risk="safe",
            sentiment_modifier=0,
            truth_status="confirmed",
        ),
        decision=decision,
        assessment=verdict,
        risk_snapshot=None,
        bars=(),
        context=None,
        requested_size=Decimal("1"),
        stop_loss=None,
        take_profit=None,
    )
    evidence = {"candidate": prepared.candidate_payload(_POLICY_DIGEST)}
    return setup, decision, verdict, journal, evidence


async def _database(tmp_path: Path):  # type: ignore[no-untyped-def]
    db = tmp_path / "c101-store-adopt.sqlite3"
    engine, sessions = create_engine_and_sessionmaker(f"sqlite+aiosqlite:///{db.as_posix()}")
    await init_schema(engine)
    return engine, sessions, db


async def _write_terminal(store: RouteAttemptStore) -> tuple[str, RiskVerdict, TradeJournalRecord]:
    setup, decision, verdict, journal, evidence = _records()
    await store.prepare(setup, decision, verdict, evidence)
    await store.complete(None, setup, decision, verdict, journal)
    return decision.decision_id, verdict, journal


async def test_keyed_terminal_reload_returns_exact_issued_models(tmp_path: Path) -> None:
    engine, sessions, db = await _database(tmp_path)
    store = RouteAttemptStore(sessions, integrity_key=_KEY)
    decision_id, verdict, journal = await _write_terminal(store)
    pair = await store.read_verified_terminal(decision_id)
    assert pair is not None
    assert type(pair[0]) is RiskVerdict and type(pair[1]) is TradeJournalRecord
    assert require_risk_verdict(pair[0]) == verdict
    assert require_trade_journal_record(pair[1]) == journal
    async with sessions() as session:
        row = await session.get(RouteAttemptRow, decision_id)
        assert row is not None and row.outcome is not None
        proof = row.outcome["proof"]
        assert proof["schema"] == "c101.terminal-records"
        assert proof["version"] == 1 and proof["algorithm"] == "hmac-sha256"
        assert len(proof["payload_sha256"]) == len(proof["mac"]) == 64
        assert len((await session.scalars(select(RiskVerdictRow))).all()) == 1
        assert len((await session.scalars(select(JournalRow))).all()) == 1
    await engine.dispose()

    fresh_engine, fresh_sessions = create_engine_and_sessionmaker(
        f"sqlite+aiosqlite:///{db.as_posix()}"
    )
    fresh_pair = await RouteAttemptStore(fresh_sessions, integrity_key=_KEY).read_verified_terminal(
        decision_id
    )
    assert fresh_pair is not None
    assert require_risk_verdict(fresh_pair[0]) == verdict
    assert require_trade_journal_record(fresh_pair[1]) == journal
    await fresh_engine.dispose()


async def test_missing_key_marks_row_unissued_and_never_issues(tmp_path: Path) -> None:
    engine, sessions, _ = await _database(tmp_path)
    store = RouteAttemptStore(sessions)
    decision_id, _, _ = await _write_terminal(store)
    with pytest.raises(RouteTransitionError, match="INTEGRITY_KEY_UNAVAILABLE"):
        await store.read_verified_terminal(decision_id)
    with pytest.raises(RouteTransitionError, match="INTEGRITY_KEY_UNAVAILABLE"):
        await store.read_view(decision_id)
    async with sessions() as session:
        row = await session.get(RouteAttemptRow, decision_id)
        assert row is not None and row.outcome is not None
        assert row.outcome["proof"] == {
            "schema": "c101.terminal-records",
            "version": 1,
            "status": "UNISSUED_PERSISTED",
        }
    await engine.dispose()


async def test_keyed_row_opened_without_key_is_non_authoritative(tmp_path: Path) -> None:
    engine, sessions, db = await _database(tmp_path)
    decision_id, _, _ = await _write_terminal(RouteAttemptStore(sessions, integrity_key=_KEY))
    await engine.dispose()
    fresh_engine, fresh_sessions = create_engine_and_sessionmaker(
        f"sqlite+aiosqlite:///{db.as_posix()}"
    )
    with pytest.raises(RouteTransitionError, match="INTEGRITY_KEY_UNAVAILABLE"):
        await RouteAttemptStore(fresh_sessions).read_verified_terminal(decision_id)
    await fresh_engine.dispose()


async def test_wrong_key_or_modified_proof_is_rejected(tmp_path: Path) -> None:
    engine, sessions, _ = await _database(tmp_path)
    decision_id, _, _ = await _write_terminal(RouteAttemptStore(sessions, integrity_key=_KEY))
    wrong_key = LedgerIntegrityKey(b"different-c101-store-adopt-key-material-0002")
    with pytest.raises(RouteTransitionError, match="TERMINAL_PROOF_OR_LINKAGE_INVALID"):
        await RouteAttemptStore(sessions, integrity_key=wrong_key).read_verified_terminal(
            decision_id
        )
    async with sessions() as session:
        row = await session.get(RouteAttemptRow, decision_id)
        assert row is not None and row.outcome is not None
        row.outcome = {**row.outcome, "proof": {**row.outcome["proof"], "mac": "0" * 64}}
        await session.commit()
    with pytest.raises(RouteTransitionError, match="TERMINAL_PROOF_OR_LINKAGE_INVALID"):
        await RouteAttemptStore(sessions, integrity_key=_KEY).read_verified_terminal(decision_id)
    await engine.dispose()


async def test_unissued_assessment_fails_before_prepare_writes(tmp_path: Path) -> None:
    engine, sessions, _ = await _database(tmp_path)
    setup, decision, verdict, _, evidence = _records()
    unissued = RiskVerdict.model_validate(verdict.model_dump(mode="json"))
    with pytest.raises(SealError):
        await RouteAttemptStore(sessions, integrity_key=_KEY).prepare(
            setup, decision, unissued, evidence
        )
    async with sessions() as session:
        assert (await session.scalars(select(RouteAttemptRow))).all() == []
    await engine.dispose()


async def test_complete_requires_issued_verdict_and_journal_before_transition(
    tmp_path: Path,
) -> None:
    engine, sessions, _ = await _database(tmp_path)
    setup, decision, verdict, journal, evidence = _records()
    store = RouteAttemptStore(sessions, integrity_key=_KEY)
    await store.prepare(setup, decision, verdict, evidence)
    unissued_verdict = RiskVerdict.model_validate(verdict.model_dump(mode="json"))
    with pytest.raises(SealError):
        await store.complete(None, setup, decision, unissued_verdict, journal)
    unissued_journal = TradeJournalRecord.model_validate(journal.model_dump(mode="json"))
    with pytest.raises(SealError):
        await store.complete(None, setup, decision, verdict, unissued_journal)
    async with sessions() as session:
        row = await session.get(RouteAttemptRow, decision.decision_id)
        assert row is not None and row.state == "PENDING" and row.version == 0
        assert row.outcome is None and row.final_verdict is None and row.journal_record is None
        assert (await session.scalars(select(RiskVerdictRow))).all() == []
        assert (await session.scalars(select(JournalRow))).all() == []
    await engine.dispose()


async def test_proofless_legacy_and_partial_terminal_rows_are_rejected(tmp_path: Path) -> None:
    engine, sessions, _ = await _database(tmp_path)
    decision_id, _, _ = await _write_terminal(RouteAttemptStore(sessions, integrity_key=_KEY))
    async with sessions() as session:
        row = await session.get(RouteAttemptRow, decision_id)
        assert row is not None and row.outcome is not None
        row.outcome = {key: value for key, value in row.outcome.items() if key != "proof"}
        await session.commit()
    with pytest.raises(RouteTransitionError, match="UNISSUED_PERSISTED"):
        await RouteAttemptStore(sessions, integrity_key=_KEY).read_verified_terminal(decision_id)

    async with sessions() as session:
        row = await session.get(RouteAttemptRow, decision_id)
        assert row is not None
        row.final_verdict = None
        await session.commit()
    with pytest.raises(RouteTransitionError, match="TERMINAL_PARTIAL_INVALID"):
        await RouteAttemptStore(sessions, integrity_key=_KEY).read_verified_terminal(decision_id)
    await engine.dispose()


async def test_parent_tamper_is_rejected_with_fixed_status(tmp_path: Path) -> None:
    engine, sessions, _ = await _database(tmp_path)
    decision_id, _, _ = await _write_terminal(RouteAttemptStore(sessions, integrity_key=_KEY))
    async with sessions() as session:
        await session.execute(
            update(RouteAttemptRow)
            .where(RouteAttemptRow.decision_id == decision_id)
            .values(setup_id="different-parent")
        )
        await session.commit()
    with pytest.raises(RouteTransitionError, match="TERMINAL_PARENT_INVALID"):
        await RouteAttemptStore(sessions, integrity_key=_KEY).read_verified_terminal(decision_id)
    await engine.dispose()


async def test_complete_commit_failure_rolls_back_terminal_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine, sessions, _ = await _database(tmp_path)
    store = RouteAttemptStore(sessions, integrity_key=_KEY)
    setup, decision, verdict, journal, evidence = _records()
    await store.prepare(setup, decision, verdict, evidence)

    async def fail_commit(session: AsyncSession) -> None:
        await session.rollback()
        raise RuntimeError("synthetic commit failure")

    monkeypatch.setattr(AsyncSession, "commit", fail_commit)
    with pytest.raises(RuntimeError, match="synthetic commit failure"):
        await store.complete(None, setup, decision, verdict, journal)
    monkeypatch.undo()
    async with sessions() as session:
        row = await session.get(RouteAttemptRow, decision.decision_id)
        assert row is not None and row.state == "PENDING" and row.version == 0
        assert row.outcome is None and row.final_verdict is None and row.journal_record is None
        assert (await session.scalars(select(RiskVerdictRow))).all() == []
        assert (await session.scalars(select(JournalRow))).all() == []
    await engine.dispose()
