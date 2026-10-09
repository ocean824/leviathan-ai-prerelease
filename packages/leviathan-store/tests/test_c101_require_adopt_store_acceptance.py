"""Independent black-box acceptance for keyed C-101 terminal persistence."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from leviathan_store.engine import create_engine_and_sessionmaker, init_schema
from leviathan_store.risk_txn import RouteAttemptStore, RouteTransitionError
from leviathan_store.tables import (
    DecisionRow,
    JournalRow,
    RiskVerdictRow,
    RouteAttemptRow,
    SetupRow,
)
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from leviathan_core.execution.order_models import LedgerIntegrityKey
from leviathan_core.pipeline import PreparedReplay
from leviathan_core.schemas import (
    CandidateSetup,
    DecisionPacket,
    RiskAction,
    RiskVerdict,
    TradeJournalRecord,
    TradeOutcome,
)
from leviathan_core.schemas.journal import (
    _issue_trade_journal_record,
    require_trade_journal_record,
)
from leviathan_core.schemas.risk import _issue_risk_verdict, require_risk_verdict
from leviathan_core.schemas.truth import TruthValidationResult
from leviathan_core.seal import SealError
from leviathan_core.state.session_classifier import classify_session

pytestmark = pytest.mark.asyncio

_NOW = datetime(2026, 9, 30, 14, tzinfo=UTC)
_KEY = LedgerIntegrityKey(b"acceptance-only-c101-integrity-key-00000001")
_WRONG_KEY = LedgerIntegrityKey(b"acceptance-only-c101-integrity-key-00000002")
_POLICY_DIGEST = "a" * 64


def _records(
    suffix: str = "one",
) -> tuple[CandidateSetup, DecisionPacket, RiskVerdict, TradeJournalRecord, dict[str, Any]]:
    setup = CandidateSetup(
        setup_id=f"acceptance_setup_{suffix}",
        instrument="NQ",
        timestamp=_NOW,
        signal_features=("synthetic acceptance",),
    )
    decision = DecisionPacket(
        decision_id=f"acceptance_decision_{suffix}",
        setup_id=setup.setup_id,
        permission="reject",
        direction="long",
        confidence=0.5,
        entry_style="paper_market",
        scaling_allowed=False,
        justification="synthetic C-101 acceptance",
    )
    verdict = _issue_risk_verdict(
        RiskVerdict(
            decision_id=decision.decision_id,
            action=RiskAction.REJECT,
            reason="synthetic_acceptance_block",
            execution_capable=False,
        )
    )
    journal = _issue_trade_journal_record(
        TradeJournalRecord(
            trade_id=f"acceptance_trade_{suffix}",
            setup_id=setup.setup_id,
            decision_id=decision.decision_id,
            outcome=TradeOutcome.BLOCKED,
            post_trade_notes="synthetic C-101 acceptance block",
        )
    )
    prepared = PreparedReplay(
        setup=setup,
        session=classify_session(_NOW),
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
    return (
        setup,
        decision,
        verdict,
        journal,
        {"candidate": prepared.candidate_payload(_POLICY_DIGEST)},
    )


async def _database(tmp_path: Path):  # type: ignore[no-untyped-def]
    db_path = tmp_path / "acceptance-c101.sqlite3"
    engine, sessions = create_engine_and_sessionmaker(f"sqlite+aiosqlite:///{db_path.as_posix()}")
    await init_schema(engine)
    return engine, sessions, db_path


async def _prepare(
    store: RouteAttemptStore, suffix: str = "one"
) -> tuple[CandidateSetup, DecisionPacket, RiskVerdict, TradeJournalRecord, dict[str, Any]]:
    values = _records(suffix)
    await store.prepare(values[0], values[1], values[2], values[4])
    return values


async def _assert_no_terminal_writes(sessions: Any, decision_id: str) -> None:
    async with sessions() as session:
        route = await session.get(RouteAttemptRow, decision_id)
        assert route is None or (
            route.state == "PENDING"
            and route.version == 0
            and route.outcome is None
            and route.final_verdict is None
            and route.journal_record is None
        )
        assert (await session.scalars(select(DecisionRow))).all() == []
        assert (await session.scalars(select(SetupRow))).all() == []
        assert (
            await session.scalars(
                select(RiskVerdictRow).where(RiskVerdictRow.decision_id == decision_id)
            )
        ).all() == []
        assert (
            await session.scalars(select(JournalRow).where(JournalRow.decision_id == decision_id))
        ).all() == []


async def _write_terminal(
    store: RouteAttemptStore, suffix: str = "one"
) -> tuple[str, RiskVerdict, TradeJournalRecord]:
    setup, decision, verdict, journal, evidence = _records(suffix)
    await store.prepare(setup, decision, verdict, evidence)
    await store.complete(None, setup, decision, verdict, journal)
    return decision.decision_id, verdict, journal


@pytest.mark.parametrize("key", [None, _KEY])
async def test_direct_and_model_validated_models_are_not_accepted_as_proofs(
    tmp_path: Path, key: LedgerIntegrityKey | None
) -> None:
    engine, sessions, _ = await _database(tmp_path)
    setup, decision, verdict, journal, evidence = _records()
    unissued_verdict = RiskVerdict.model_validate(verdict.model_dump(mode="json"))
    with pytest.raises(SealError):
        require_risk_verdict(unissued_verdict)
    with pytest.raises(SealError):
        await RouteAttemptStore(sessions, integrity_key=key).prepare(
            setup, decision, unissued_verdict, evidence
        )
    await _assert_no_terminal_writes(sessions, decision.decision_id)

    store = RouteAttemptStore(sessions, integrity_key=key)
    values = await _prepare(store)
    setup, decision, verdict, journal, _ = values
    unissued_journal = TradeJournalRecord.model_validate(journal.model_dump(mode="json"))
    with pytest.raises(SealError):
        require_trade_journal_record(unissued_journal)
    with pytest.raises(SealError):
        await store.complete(None, setup, decision, verdict, unissued_journal)
    await _assert_no_terminal_writes(sessions, decision.decision_id)
    await engine.dispose()


@pytest.mark.parametrize("record_kind", ["verdict", "journal"])
@pytest.mark.parametrize("key", [None, _KEY])
async def test_directly_constructed_terminal_records_fail_before_terminal_writes(
    tmp_path: Path, record_kind: str, key: LedgerIntegrityKey | None
) -> None:
    engine, sessions, _ = await _database(tmp_path)
    store = RouteAttemptStore(sessions, integrity_key=key)
    setup, decision, verdict, journal, _ = _records()
    if record_kind == "verdict":
        raw = RiskVerdict(
            decision_id=verdict.decision_id,
            action=verdict.action,
            reason=verdict.reason,
            execution_capable=verdict.execution_capable,
        )
        with pytest.raises(SealError):
            await store.complete(None, setup, decision, raw, journal)
    else:
        raw = TradeJournalRecord(
            trade_id=journal.trade_id,
            setup_id=journal.setup_id,
            decision_id=journal.decision_id,
            outcome=journal.outcome,
            post_trade_notes=journal.post_trade_notes,
        )
        with pytest.raises(SealError):
            await store.complete(None, setup, decision, verdict, raw)
    await _assert_no_terminal_writes(sessions, decision.decision_id)
    await engine.dispose()


@pytest.mark.parametrize("record_kind", ["verdict", "journal"])
@pytest.mark.parametrize("key", [None, _KEY])
async def test_tampered_terminal_records_fail_before_terminal_writes(
    tmp_path: Path, record_kind: str, key: LedgerIntegrityKey | None
) -> None:
    engine, sessions, _ = await _database(tmp_path)
    store = RouteAttemptStore(sessions, integrity_key=key)
    setup, decision, verdict, journal, _ = _records()
    if record_kind == "verdict":
        object.__setattr__(verdict, "reason", "tampered after issue")
        with pytest.raises(SealError):
            await store.complete(None, setup, decision, verdict, journal)
    else:
        object.__setattr__(journal, "post_trade_notes", "tampered after issue")
        with pytest.raises(SealError):
            await store.complete(None, setup, decision, verdict, journal)
    await _assert_no_terminal_writes(sessions, decision.decision_id)
    await engine.dispose()


async def test_keyed_proof_and_typed_values_survive_fresh_engine_reload(tmp_path: Path) -> None:
    engine, sessions, db_path = await _database(tmp_path)
    decision_id, expected_verdict, expected_journal = await _write_terminal(
        RouteAttemptStore(sessions, integrity_key=_KEY)
    )
    async with sessions() as session:
        route = await session.get(RouteAttemptRow, decision_id)
        assert route is not None and route.state == "BLOCKED"
        assert route.outcome is not None
        assert route.outcome["proof"] == {
            "schema": "c101.terminal-records",
            "version": 1,
            "algorithm": "hmac-sha256",
            "payload_sha256": route.outcome["proof"]["payload_sha256"],
            "mac": route.outcome["proof"]["mac"],
        }
        assert route.final_verdict == expected_verdict.model_dump(mode="json")
        assert route.journal_record == expected_journal.model_dump(mode="json")
        assert len((await session.scalars(select(RiskVerdictRow))).all()) == 1
        assert len((await session.scalars(select(JournalRow))).all()) == 1
        assert len((await session.scalars(select(SetupRow))).all()) == 1
        assert len((await session.scalars(select(DecisionRow))).all()) == 1
    await engine.dispose()

    fresh_engine, fresh_sessions = create_engine_and_sessionmaker(
        f"sqlite+aiosqlite:///{db_path.as_posix()}"
    )
    fresh_store = RouteAttemptStore(fresh_sessions, integrity_key=_KEY)
    pair = await fresh_store.read_verified_terminal(decision_id)
    assert pair is not None
    assert type(pair[0]) is RiskVerdict and type(pair[1]) is TradeJournalRecord
    assert require_risk_verdict(pair[0]) == expected_verdict
    assert require_trade_journal_record(pair[1]) == expected_journal
    view = await fresh_store.read_view(decision_id)
    assert view is not None and view["final"] is True
    await fresh_engine.dispose()


async def test_no_key_write_is_explicitly_unissued_in_both_typed_read_paths(
    tmp_path: Path,
) -> None:
    engine, sessions, _ = await _database(tmp_path)
    store = RouteAttemptStore(sessions)
    decision_id, _, _ = await _write_terminal(store)
    async with sessions() as session:
        row = await session.get(RouteAttemptRow, decision_id)
        assert row is not None and row.outcome is not None
        assert row.outcome["proof"] == {
            "schema": "c101.terminal-records",
            "version": 1,
            "status": "UNISSUED_PERSISTED",
        }
    for read in (store.read_view, store.read_verified_terminal):
        with pytest.raises(RouteTransitionError, match="INTEGRITY_KEY_UNAVAILABLE"):
            await read(decision_id)
    await engine.dispose()


async def test_keyed_row_reopened_without_key_never_becomes_authoritative(tmp_path: Path) -> None:
    engine, sessions, db_path = await _database(tmp_path)
    decision_id, _, _ = await _write_terminal(RouteAttemptStore(sessions, integrity_key=_KEY))
    await engine.dispose()
    fresh_engine, fresh_sessions = create_engine_and_sessionmaker(
        f"sqlite+aiosqlite:///{db_path.as_posix()}"
    )
    store_without_key = RouteAttemptStore(fresh_sessions)
    with pytest.raises(RouteTransitionError, match="INTEGRITY_KEY_UNAVAILABLE"):
        await store_without_key.read_verified_terminal(decision_id)
    with pytest.raises(RouteTransitionError, match="INTEGRITY_KEY_UNAVAILABLE"):
        await store_without_key.read_view(decision_id)
    await fresh_engine.dispose()


async def test_wrong_key_rejects_authenticated_terminal(tmp_path: Path) -> None:
    engine, sessions, _ = await _database(tmp_path)
    decision_id, _, _ = await _write_terminal(RouteAttemptStore(sessions, integrity_key=_KEY))
    with pytest.raises(RouteTransitionError, match="TERMINAL_PROOF_OR_LINKAGE_INVALID"):
        await RouteAttemptStore(sessions, integrity_key=_WRONG_KEY).read_verified_terminal(
            decision_id
        )
    await engine.dispose()


@pytest.mark.parametrize("tamper", ["proof", "verdict", "journal", "identity"])
async def test_terminal_proof_payload_and_identity_tampering_fail_closed(
    tmp_path: Path, tamper: str
) -> None:
    engine, sessions, _ = await _database(tmp_path)
    decision_id, _, _ = await _write_terminal(RouteAttemptStore(sessions, integrity_key=_KEY))
    async with sessions() as session:
        row = await session.get(RouteAttemptRow, decision_id)
        assert row is not None and row.outcome is not None
        if tamper == "proof":
            row.outcome = {
                **row.outcome,
                "proof": {**row.outcome["proof"], "mac": "0" * 64},
            }
        elif tamper == "verdict":
            row.final_verdict = {**row.final_verdict, "reason": "changed payload"}
        elif tamper == "journal":
            row.journal_record = {
                **row.journal_record,
                "post_trade_notes": "changed payload",
            }
        else:
            row.evidence = {**row.evidence, "candidate_identity": "0" * 64}
        await session.commit()
    expected_code = (
        "TERMINAL_PARENT_INVALID" if tamper == "identity" else "TERMINAL_PROOF_OR_LINKAGE_INVALID"
    )
    with pytest.raises(RouteTransitionError, match=expected_code):
        await RouteAttemptStore(sessions, integrity_key=_KEY).read_verified_terminal(decision_id)
    await engine.dispose()


async def test_proof_copied_between_decision_ids_is_rejected(tmp_path: Path) -> None:
    engine, sessions, _ = await _database(tmp_path)
    store = RouteAttemptStore(sessions, integrity_key=_KEY)
    first_id, _, _ = await _write_terminal(store, "first")
    second_id, _, _ = await _write_terminal(store, "second")
    async with sessions() as session:
        first = await session.get(RouteAttemptRow, first_id)
        second = await session.get(RouteAttemptRow, second_id)
        assert first is not None and second is not None
        assert first.outcome is not None and second.outcome is not None
        second.outcome = {**second.outcome, "proof": first.outcome["proof"]}
        await session.commit()
    with pytest.raises(RouteTransitionError, match="TERMINAL_PROOF_OR_LINKAGE_INVALID"):
        await store.read_verified_terminal(second_id)
    await engine.dispose()


@pytest.mark.parametrize("tamper", ["parent", "identity", "partial", "proofless"])
async def test_parent_partial_and_legacy_proofless_rows_are_not_issued(
    tmp_path: Path, tamper: str
) -> None:
    engine, sessions, _ = await _database(tmp_path)
    store = RouteAttemptStore(sessions, integrity_key=_KEY)
    decision_id, _, _ = await _write_terminal(store)
    async with sessions() as session:
        row = await session.get(RouteAttemptRow, decision_id)
        assert row is not None and row.outcome is not None
        if tamper == "parent":
            row.setup_id = "unrelated_parent"
        elif tamper == "identity":
            row.evidence = {
                **row.evidence,
                "candidate_identity": "0" * 64,
            }
        elif tamper == "partial":
            row.journal_record = None
        else:
            row.outcome = {key: value for key, value in row.outcome.items() if key != "proof"}
        await session.commit()
    expected_code = {
        "parent": "TERMINAL_PARENT_INVALID",
        "identity": "TERMINAL_PARENT_INVALID",
        "partial": "TERMINAL_PARTIAL_INVALID",
        "proofless": "UNISSUED_PERSISTED",
    }[tamper]
    with pytest.raises(RouteTransitionError, match=expected_code):
        await store.read_verified_terminal(decision_id)
    await engine.dispose()


async def test_terminal_commit_rollback_leaves_only_the_pending_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine, sessions, _ = await _database(tmp_path)
    store = RouteAttemptStore(sessions, integrity_key=_KEY)
    setup, decision, verdict, journal, _ = await _prepare(store)

    async def rollback_commit(session: AsyncSession) -> None:
        await session.rollback()
        raise RuntimeError("synthetic terminal commit failure")

    monkeypatch.setattr(AsyncSession, "commit", rollback_commit)
    with pytest.raises(RuntimeError, match="synthetic terminal commit failure"):
        await store.complete(None, setup, decision, verdict, journal)
    monkeypatch.undo()
    await _assert_no_terminal_writes(sessions, decision.decision_id)
    # A pending row has no terminal pair and cannot be used to manufacture one.
    assert await store.read_verified_terminal(decision.decision_id) is None
    await engine.dispose()
