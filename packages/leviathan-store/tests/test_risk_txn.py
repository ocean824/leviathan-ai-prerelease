"""C-101 durable attempt transitions and additive populated-DB migration."""

import asyncio
from dataclasses import replace
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest
from leviathan_store.engine import create_engine_and_sessionmaker, init_schema
from leviathan_store.repositories import (
    DecisionRepository,
    JournalRepository,
    RiskVerdictRepository,
    SetupRepository,
)
from leviathan_store.risk_txn import RouteAttemptStore, RouteTransitionError
from leviathan_store.tables import (
    DecisionRow,
    JournalRow,
    RiskVerdictRow,
    RouteAttemptRow,
    SchemaMigrationRow,
    SetupRow,
)
from sqlalchemy import insert, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from leviathan_core.execution.order_models import LedgerIntegrityKey
from leviathan_core.pipeline import LiveFlowPipeline, PreparedReplay
from leviathan_core.schemas import (
    Bar,
    CandidateSetup,
    DecisionPacket,
    GateFinding,
    KillState,
    Permission,
    RequiredStream,
    RiskAction,
    RiskGateContext,
    RiskSnapshot,
    RiskVerdict,
    StreamFreshness,
    TradeJournalRecord,
    TruthValidationResult,
)
from leviathan_core.schemas.journal import _issue_trade_journal_record
from leviathan_core.schemas.risk import _issue_risk_verdict
from leviathan_core.state.session_classifier import classify_session

pytestmark = pytest.mark.asyncio
AT = datetime(2026, 9, 30, tzinfo=UTC)
POLICY_DIGEST = "a" * 64
_INTEGRITY_KEY = LedgerIntegrityKey(b"c101-risk-txn-synthetic-integrity-key-0001")


def _contracts() -> tuple[CandidateSetup, DecisionPacket, RiskVerdict, TradeJournalRecord]:
    setup = CandidateSetup(
        setup_id="setup_c101",
        instrument="NQ",
        timestamp=AT,
        signal_features=("breakout",),
    )
    decision = DecisionPacket(
        decision_id="dec_c101",
        setup_id=setup.setup_id,
        permission="approve",
        direction="long",
        confidence=0.8,
        entry_style="paper_market",
        scaling_allowed=False,
        justification="fixture",
    )
    assessment = _issue_risk_verdict(
        RiskVerdict(
            decision_id=decision.decision_id,
            action="allow",
            reason="within_limits",
            execution_capable=True,
        )
    )
    journal = _issue_trade_journal_record(
        TradeJournalRecord(
            trade_id="trade_c101",
            setup_id=setup.setup_id,
            decision_id=decision.decision_id,
            outcome="blocked",
            post_trade_notes="paper limit never filled",
        )
    )
    return setup, decision, assessment, journal


def _issued_verdict(value: RiskVerdict) -> RiskVerdict:
    """Use the documented SEAL-001 producer issuance pattern in storage tests."""
    return _issue_risk_verdict(value)


def _issued_journal(value: TradeJournalRecord) -> TradeJournalRecord:
    """Use the documented SEAL-001 producer issuance pattern in storage tests."""
    return _issue_trade_journal_record(value)


def _candidate(
    setup: CandidateSetup, decision: DecisionPacket, assessment: RiskVerdict
) -> PreparedReplay:
    stream = RequiredStream(stream_id="quotes", symbol=setup.instrument, provider="fixture")
    observed = StreamFreshness(
        stream_id="quotes",
        symbol=setup.instrument,
        provider="fixture",
        source_ts=AT,
        exchange_ts=AT,
        received_at=AT,
    )
    return PreparedReplay(
        setup=setup,
        session=classify_session(setup.timestamp),
        range_context=None,
        truth=TruthValidationResult(
            setup_id=setup.setup_id,
            orderbook_bias="bullish",
            options_context="fixture",
            event_risk="safe",
            sentiment_modifier=0.0,
            truth_status="confirmed",
        ),
        decision=decision,
        assessment=assessment,
        risk_snapshot=RiskSnapshot(
            session_id="session_c101",
            max_daily_drawdown_pct=Decimal("3"),
            max_position_size=assessment.adjusted_size or Decimal("1"),
            allowed_instruments=(setup.instrument,),
            frozen_at=AT,
            risk_lock_sha256=POLICY_DIGEST,
        )
        if assessment.execution_capable and decision.permission is Permission.APPROVE
        else None,
        bars=(
            Bar(
                instrument=setup.instrument,
                timestamp=AT,
                open=Decimal("100"),
                high=Decimal("102"),
                low=Decimal("98"),
                close=Decimal("101"),
            ),
        ),
        context=RiskGateContext(
            as_of=AT, required=(stream,), observed=(observed,), kill=KillState()
        ),
        requested_size=Decimal("1"),
        stop_loss=Decimal("99"),
        take_profit=Decimal("101"),
    )


def _evidence(setup: CandidateSetup, decision: DecisionPacket, assessment: RiskVerdict) -> dict:
    return {"candidate": _candidate(setup, decision, assessment).candidate_payload(POLICY_DIGEST)}


def _council_terminal(
    setup: CandidateSetup,
    decision: DecisionPacket,
    assessment: RiskVerdict,
) -> tuple[RiskVerdict, TradeJournalRecord]:
    pipeline = LiveFlowPipeline.__new__(LiveFlowPipeline)
    return pipeline.block_prepared(_candidate(setup, decision, assessment))


def _draft(setup: CandidateSetup, decision: DecisionPacket, assessment: RiskVerdict) -> dict:
    return _candidate(setup, decision, assessment).paper_draft(POLICY_DIGEST)


async def _opened(tmp_path: Path):  # type: ignore[no-untyped-def]
    db = tmp_path / "risk.db"
    engine, sessions = create_engine_and_sessionmaker(f"sqlite+aiosqlite:///{db.as_posix()}")
    await init_schema(engine)
    return engine, RouteAttemptStore(sessions, integrity_key=_INTEGRITY_KEY), db


async def test_authorize_claim_complete_and_fresh_process_view(tmp_path: Path) -> None:
    engine, store, db = await _opened(tmp_path)
    setup, decision, assessment, journal = _contracts()
    await store.prepare(setup, decision, assessment, _evidence(setup, decision, assessment))
    pending = await store.read_view(decision.decision_id)
    assert pending is not None and pending["final"] is False
    await store.authorize(decision.decision_id, _draft(setup, decision, assessment))
    authorized = await store.read_view(decision.decision_id)
    assert authorized is not None and authorized["stage"] == "authorized"
    assert authorized["authorization"] == {"action": "allow", "historical_only": True}
    assert authorized["final_verdict"] is None

    receipt = await store.claim(decision.decision_id, "claim_one")
    assert receipt is not None and receipt.policy_digest == "a" * 64
    assert receipt.candidate_identity == _candidate(setup, decision, assessment).candidate_identity(
        POLICY_DIGEST
    )
    assert await store.claim(decision.decision_id, "claim_duplicate") is None
    await store.complete(receipt, setup, decision, assessment, journal)
    with pytest.raises(RouteTransitionError):
        await store.complete(receipt, setup, decision, assessment, journal)
    await engine.dispose()

    fresh_engine, fresh_sessions = create_engine_and_sessionmaker(
        f"sqlite+aiosqlite:///{db.as_posix()}"
    )
    fresh = RouteAttemptStore(fresh_sessions, integrity_key=_INTEGRITY_KEY)
    view = await fresh.read_view(decision.decision_id)
    assert view is not None and view["final"] is True
    assert view["status"] == "completed"
    assert view["outcome"] == {"kind": "paper_sim", "journal_outcome": "blocked"}
    assert view["journal_record"]["outcome"] == "blocked"
    async with fresh_sessions() as session:
        assert await RiskVerdictRepository(
            session, integrity_key=_INTEGRITY_KEY
        ).list_authoritative_recent() == [assessment]
        assert await JournalRepository(
            session, integrity_key=_INTEGRITY_KEY
        ).list_authoritative_recent() == [journal]
    await fresh_engine.dispose()


async def test_concurrent_claim_has_one_confirmed_winner(tmp_path: Path) -> None:
    engine, store, _ = await _opened(tmp_path)
    setup, decision, assessment, _ = _contracts()
    await store.prepare(setup, decision, assessment, _evidence(setup, decision, assessment))
    await store.authorize(decision.decision_id, _draft(setup, decision, assessment))
    receipts = await asyncio.gather(
        *(store.claim(decision.decision_id, f"token_{i}") for i in range(8))
    )
    assert sum(receipt is not None for receipt in receipts) == 1
    view = await store.read_view(decision.decision_id)
    assert view is not None and view["stage"] == "in_progress" and not view["final"]
    await engine.dispose()


async def test_unclaimed_allow_cannot_publish_final(tmp_path: Path) -> None:
    engine, store, _ = await _opened(tmp_path)
    setup, decision, assessment, journal = _contracts()
    await store.prepare(setup, decision, assessment, _evidence(setup, decision, assessment))
    with pytest.raises(RouteTransitionError):
        await store.complete(None, setup, decision, assessment, journal)
    view = await store.read_view(decision.decision_id)
    assert view is not None and view["stage"] == "pending" and not view["final"]
    await engine.dispose()


@pytest.mark.parametrize(
    ("permission", "action"),
    [("reject", "reject"), ("wait", "wait"), ("signal_only", "reject")],
)
async def test_council_denial_commits_readable_terminal_block(
    tmp_path: Path,
    permission: str,
    action: str,
) -> None:
    engine, store, db = await _opened(tmp_path)
    setup, decision, assessment, _ = _contracts()
    decision = DecisionPacket.model_validate(
        {
            **decision.model_dump(mode="json"),
            "permission": permission,
        }
    )
    final, journal = _council_terminal(setup, decision, assessment)
    assert final.action.value == action
    assert final.reason == f"council_permission_{permission}"
    await store.prepare(setup, decision, assessment, _evidence(setup, decision, assessment))
    await store.complete(None, setup, decision, final, journal)
    await engine.dispose()

    fresh_engine, fresh_sessions = create_engine_and_sessionmaker(
        f"sqlite+aiosqlite:///{db.as_posix()}"
    )
    fresh = RouteAttemptStore(fresh_sessions, integrity_key=_INTEGRITY_KEY)
    view = await fresh.read_view(decision.decision_id)
    assert view is not None
    assert view["status"] == "blocked" and view["final"] is True
    assert view["assessment"] == assessment.model_dump(mode="json")
    assert view["final_verdict"] == final.model_dump(mode="json")
    assert view["journal_record"] == journal.model_dump(mode="json")
    async with fresh_sessions() as session:
        assert await RiskVerdictRepository(
            session, integrity_key=_INTEGRITY_KEY
        ).list_authoritative_recent() == [final]
        assert await JournalRepository(
            session, integrity_key=_INTEGRITY_KEY
        ).list_authoritative_recent() == [journal]
        assert len((await session.scalars(select(RiskVerdictRow))).all()) == 1
        assert len((await session.scalars(select(JournalRow))).all()) == 1
    await fresh_engine.dispose()


@pytest.mark.parametrize(
    "tamper",
    ["prices", "mae", "mfe", "wrong_notes", "forged_halts"],
)
async def test_council_terminal_rejects_contradictory_journal_before_commit(
    tmp_path: Path,
    tamper: str,
) -> None:
    engine, store, _ = await _opened(tmp_path)
    setup, decision, assessment, _ = _contracts()
    decision = DecisionPacket.model_validate(
        {
            **decision.model_dump(mode="json"),
            "permission": Permission.REJECT.value,
        }
    )
    final, journal = _council_terminal(setup, decision, assessment)
    payload = journal.model_dump(mode="json")
    if tamper == "prices":
        payload.update({"entry": "100", "exit": "101"})
    elif tamper == "mae":
        payload["mae"] = "1"
    elif tamper == "mfe":
        payload["mfe"] = "1"
    elif tamper == "wrong_notes":
        payload["post_trade_notes"] = "risk=allow reason=within_limits"
    else:
        payload["post_trade_notes"] += "forged_halt"
    bad_journal = _issued_journal(TradeJournalRecord.model_validate(payload))

    await store.prepare(setup, decision, assessment, _evidence(setup, decision, assessment))
    with pytest.raises(RouteTransitionError):
        await store.complete(None, setup, decision, final, bad_journal)
    view = await store.read_view(decision.decision_id)
    assert view is not None and view["stage"] == "pending" and view["final"] is False
    await engine.dispose()


async def test_other_blocked_verdict_also_rejects_execution_prices(tmp_path: Path) -> None:
    engine, store, _ = await _opened(tmp_path)
    setup, decision, _, journal = _contracts()
    assessment = _issued_verdict(
        RiskVerdict(
            decision_id=decision.decision_id,
            action=RiskAction.REJECT,
            reason="policy_limit",
        )
    )
    priced_journal = _issued_journal(
        TradeJournalRecord.model_validate(
            {**journal.model_dump(mode="json"), "entry": "100", "exit": "101"}
        )
    )
    await store.prepare(setup, decision, assessment, _evidence(setup, decision, assessment))
    with pytest.raises(RouteTransitionError):
        await store.complete(None, setup, decision, assessment, priced_journal)
    view = await store.read_view(decision.decision_id)
    assert view is not None and view["stage"] == "pending" and view["final"] is False
    await engine.dispose()


@pytest.mark.parametrize(
    "tamper",
    [
        "wrong_reason",
        "wrong_action",
        "wrong_decision",
        "retained_size",
        "execution_capable",
        "changed_findings",
        "changed_halts",
    ],
)
async def test_council_terminal_forgery_stays_pending(
    tmp_path: Path,
    tamper: str,
) -> None:
    engine, store, _ = await _opened(tmp_path)
    setup, decision, assessment, _ = _contracts()
    decision = DecisionPacket.model_validate(
        {
            **decision.model_dump(mode="json"),
            "permission": Permission.WAIT.value,
        }
    )
    final, journal = _council_terminal(setup, decision, assessment)
    if tamper == "wrong_reason":
        final = _issued_verdict(
            RiskVerdict.model_validate(
                {**final.model_dump(mode="json"), "reason": "council_permission_reject"}
            )
        )
    elif tamper == "wrong_action":
        final = _issued_verdict(
            RiskVerdict.model_validate(
                {**final.model_dump(mode="json"), "action": RiskAction.REJECT.value}
            )
        )
    elif tamper == "wrong_decision":
        final = _issued_verdict(
            RiskVerdict.model_validate(
                {**final.model_dump(mode="json"), "decision_id": "other_decision"}
            )
        )
    else:
        field, value = {
            "retained_size": ("adjusted_size", "1"),
            "execution_capable": ("execution_capable", True),
            "changed_findings": ("findings", [GateFinding.GLOBAL_KILL.value]),
            "changed_halts": ("halts_engaged", ["forged_halt"]),
        }[tamper]
        final = _issued_verdict(
            RiskVerdict.model_validate({**final.model_dump(mode="json"), field: value})
        )
    await store.prepare(setup, decision, assessment, _evidence(setup, decision, assessment))
    with pytest.raises(RouteTransitionError):
        await store.complete(None, setup, decision, final, journal)
    view = await store.read_view(decision.decision_id)
    assert view is not None and view["stage"] == "pending" and not view["final"]
    await engine.dispose()


@pytest.mark.parametrize(
    "tamper", ["wrong_reason", "wrong_decision", "claimed", "journal_notes", "journal_prices"]
)
async def test_council_terminal_corruption_is_not_authoritative(
    tmp_path: Path,
    tamper: str,
) -> None:
    engine, store, db = await _opened(tmp_path)
    setup, decision, assessment, _ = _contracts()
    decision = DecisionPacket.model_validate(
        {
            **decision.model_dump(mode="json"),
            "permission": Permission.REJECT.value,
        }
    )
    final, journal = _council_terminal(setup, decision, assessment)
    await store.prepare(setup, decision, assessment, _evidence(setup, decision, assessment))
    await store.complete(None, setup, decision, final, journal)
    await engine.dispose()

    fresh_engine, sessions = create_engine_and_sessionmaker(f"sqlite+aiosqlite:///{db.as_posix()}")
    async with sessions() as session:
        row = await session.get(RouteAttemptRow, decision.decision_id)
        assert row is not None
        if tamper == "claimed":
            row.claim_token = "forged_claim"
        elif tamper in ("journal_notes", "journal_prices"):
            journal_payload = dict(row.journal_record)
            if tamper == "journal_notes":
                journal_payload["post_trade_notes"] = "risk=allow reason=within_limits"
            else:
                journal_payload.update({"entry": "100", "exit": "101"})
            row.journal_record = journal_payload
            journal_row = (await session.scalars(select(JournalRow))).one()
            journal_row.payload = journal_payload
            if tamper == "journal_notes":
                journal_row.notes = journal_payload["post_trade_notes"]
            else:
                journal_row.entry = Decimal("100")
                journal_row.exit = Decimal("101")
        else:
            payload = dict(row.final_verdict)
            payload["reason" if tamper == "wrong_reason" else "decision_id"] = (
                "forged_reason" if tamper == "wrong_reason" else "forged_decision"
            )
            row.final_verdict = payload
            ledger = (await session.scalars(select(RiskVerdictRow))).one()
            ledger.payload = payload
            if tamper == "wrong_reason":
                ledger.reason = "forged_reason"
        await session.commit()
    with pytest.raises(RouteTransitionError):
        await RouteAttemptStore(sessions, integrity_key=_INTEGRITY_KEY).read_view(
            decision.decision_id
        )
    await fresh_engine.dispose()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("instrument", "ES"),
        ("stop_loss", "1"),
        ("take_profit", "999999"),
        ("entry_price", "101"),
        ("order_type", "limit"),
        ("time_in_force", "GTC"),
        ("broker_path", "direct_broker"),
        ("candidate_identity", "0" * 64),
    ],
)
async def test_authorize_rejects_other_instrument_and_order_prices(
    tmp_path: Path, field: str, value: str
) -> None:
    engine, store, _ = await _opened(tmp_path)
    setup, decision, assessment, _ = _contracts()
    await store.prepare(setup, decision, assessment, _evidence(setup, decision, assessment))
    forged = {**_draft(setup, decision, assessment), field: value}
    with pytest.raises(RouteTransitionError):
        await store.authorize(decision.decision_id, forged)
    view = await store.read_view(decision.decision_id)
    assert view is not None and view["stage"] == "pending"
    await engine.dispose()


async def test_complete_rejects_other_setup_for_same_decision_id(tmp_path: Path) -> None:
    engine, store, _ = await _opened(tmp_path)
    setup, decision, assessment, journal = _contracts()
    await store.prepare(setup, decision, assessment, _evidence(setup, decision, assessment))
    await store.authorize(decision.decision_id, _draft(setup, decision, assessment))
    receipt = await store.claim(decision.decision_id, "claim_one")
    assert receipt is not None
    other = setup.model_copy(update={"setup_id": "setup_B", "instrument": "ES"})
    other_decision = decision.model_copy(update={"setup_id": "setup_B"})
    other_journal = _issued_journal(journal.model_copy(update={"setup_id": "setup_B"}))
    with pytest.raises(RouteTransitionError):
        await store.complete(receipt, other, other_decision, assessment, other_journal)
    view = await store.read_view(decision.decision_id)
    assert view is not None and view["stage"] == "in_progress"
    await engine.dispose()


async def test_complete_rejects_rewritten_allow_assessment(tmp_path: Path) -> None:
    engine, store, _ = await _opened(tmp_path)
    setup, decision, assessment, journal = _contracts()
    await store.prepare(setup, decision, assessment, _evidence(setup, decision, assessment))
    await store.authorize(decision.decision_id, _draft(setup, decision, assessment))
    receipt = await store.claim(decision.decision_id, "claim_one")
    assert receipt is not None
    forged = _issued_verdict(
        assessment.model_copy(update={"reason": "other", "adjusted_size": Decimal("2")})
    )
    with pytest.raises(RouteTransitionError, match="executed verdict differs"):
        await store.complete(receipt, setup, decision, forged, journal)
    view = await store.read_view(decision.decision_id)
    assert view is not None and view["stage"] == "in_progress" and not view["final"]
    await engine.dispose()


async def test_complete_rejects_receipt_for_other_candidate(tmp_path: Path) -> None:
    engine, store, _ = await _opened(tmp_path)
    setup, decision, assessment, journal = _contracts()
    await store.prepare(setup, decision, assessment, _evidence(setup, decision, assessment))
    await store.authorize(decision.decision_id, _draft(setup, decision, assessment))
    receipt = await store.claim(decision.decision_id, "claim_one")
    assert receipt is not None
    with pytest.raises(RouteTransitionError, match="receipt differs"):
        await store.complete(
            replace(receipt, candidate_identity="0" * 64), setup, decision, assessment, journal
        )
    view = await store.read_view(decision.decision_id)
    assert view is not None and view["stage"] == "in_progress" and not view["final"]
    await engine.dispose()


@pytest.mark.parametrize(
    "mutation", ["parent", "decision_link", "assessment_link", "snapshot", "bars"]
)
async def test_prepare_rejects_inconsistent_candidate_material(
    tmp_path: Path, mutation: str
) -> None:
    engine, store, _ = await _opened(tmp_path)
    setup, decision, assessment, _ = _contracts()
    candidate = _candidate(setup, decision, assessment)
    supplied_setup = setup
    if mutation == "parent":
        supplied_setup = setup.model_copy(update={"instrument": "ES"})
    elif mutation == "decision_link":
        candidate = candidate.model_copy(
            update={"decision": decision.model_copy(update={"setup_id": "other"})}
        )
    elif mutation == "assessment_link":
        candidate = candidate.model_copy(
            update={"assessment": assessment.model_copy(update={"decision_id": "other"})}
        )
    elif mutation == "snapshot":
        assert candidate.risk_snapshot is not None
        candidate = candidate.model_copy(
            update={
                "risk_snapshot": candidate.risk_snapshot.model_copy(
                    update={"risk_lock_sha256": "b" * 64}
                )
            }
        )
    else:
        candidate = candidate.model_copy(
            update={"bars": (candidate.bars[0].model_copy(update={"instrument": "ES"}),)}
        )
    with pytest.raises(RouteTransitionError):
        await store.prepare(
            supplied_setup,
            decision,
            assessment,
            {"candidate": candidate.candidate_payload(POLICY_DIGEST)},
        )
    assert await store.read_view(decision.decision_id) is None
    await engine.dispose()


@pytest.mark.parametrize("parent", ["setup", "decision"])
async def test_complete_rejects_existing_same_id_parent_payload(
    tmp_path: Path, parent: str
) -> None:
    engine, store, _ = await _opened(tmp_path)
    setup, decision, assessment, journal = _contracts()
    await store.prepare(setup, decision, assessment, _evidence(setup, decision, assessment))
    await store.authorize(decision.decision_id, _draft(setup, decision, assessment))
    receipt = await store.claim(decision.decision_id, "claim_one")
    assert receipt is not None
    async with AsyncSession(engine) as session:
        if parent == "setup":
            await SetupRepository(session).add(setup.model_copy(update={"instrument": "ES"}))
        else:
            await DecisionRepository(session).add(
                decision.model_copy(update={"justification": "other plan"}), at=AT
            )
        await session.commit()
    with pytest.raises(RouteTransitionError, match=r"existing .* payload conflicts"):
        await store.complete(receipt, setup, decision, assessment, journal)
    view = await store.read_view(decision.decision_id)
    assert view is not None and view["stage"] == "in_progress" and not view["final"]
    await engine.dispose()


async def test_pre_simulation_block_links_candidate_and_parents(tmp_path: Path) -> None:
    engine, store, _ = await _opened(tmp_path)
    setup, decision, _, journal = _contracts()
    blocked = _issued_verdict(
        RiskVerdict(
            decision_id=decision.decision_id,
            action="wait",
            reason="risk_block",
            execution_capable=False,
        )
    )
    await store.prepare(setup, decision, blocked, _evidence(setup, decision, blocked))
    with pytest.raises(RouteTransitionError):
        await store.complete(
            None,
            setup,
            decision,
            blocked,
            _issued_journal(journal.model_copy(update={"setup_id": "setup_B"})),
        )
    await store.complete(None, setup, decision, blocked, journal)
    view = await store.read_view(decision.decision_id)
    assert view is not None and view["stage"] == "blocked" and view["final"]
    async with AsyncSession(engine) as session:
        assert await RiskVerdictRepository(
            session, integrity_key=_INTEGRITY_KEY
        ).list_authoritative_recent() == [blocked]
        assert await JournalRepository(
            session, integrity_key=_INTEGRITY_KEY
        ).list_authoritative_recent() == [journal]
    await engine.dispose()


@pytest.mark.parametrize("corruption", ["setup", "decision", "draft", "candidate"])
async def test_authoritative_reads_reject_corrupt_candidate_or_parent(
    tmp_path: Path, corruption: str
) -> None:
    engine, store, _ = await _opened(tmp_path)
    setup, decision, assessment, journal = _contracts()
    await store.prepare(setup, decision, assessment, _evidence(setup, decision, assessment))
    await store.authorize(decision.decision_id, _draft(setup, decision, assessment))
    receipt = await store.claim(decision.decision_id, "claim_one")
    assert receipt is not None
    await store.complete(receipt, setup, decision, assessment, journal)
    async with AsyncSession(engine) as session:
        if corruption == "setup":
            row = await session.get(SetupRow, setup.setup_id)
            assert row is not None
            row.payload = {**row.payload, "instrument": "ES"}
        elif corruption == "decision":
            row = await session.get(DecisionRow, decision.decision_id)
            assert row is not None
            row.payload = {**row.payload, "justification": "other plan"}
        else:
            row = await session.get(RouteAttemptRow, decision.decision_id)
            assert row is not None
            if corruption == "draft":
                assert row.paper_draft is not None
                row.paper_draft = {**row.paper_draft, "instrument": "ES"}
            else:
                row.evidence = {**row.evidence, "candidate_identity": "0" * 64}
        await session.commit()
    with pytest.raises(RouteTransitionError):
        await store.read_view(decision.decision_id)
    async with AsyncSession(engine) as session:
        assert await RiskVerdictRepository(session).list_authoritative_recent() == []
        assert await JournalRepository(session).list_authoritative_recent() == []
    await engine.dispose()


async def test_restart_reads_authorized_and_claimed_as_incomplete(tmp_path: Path) -> None:
    engine, store, db = await _opened(tmp_path)
    setup, decision, assessment, _ = _contracts()
    await store.prepare(setup, decision, assessment, _evidence(setup, decision, assessment))
    await store.authorize(decision.decision_id, _draft(setup, decision, assessment))
    await engine.dispose()

    resumed_engine, resumed_sessions = create_engine_and_sessionmaker(
        f"sqlite+aiosqlite:///{db.as_posix()}"
    )
    resumed = RouteAttemptStore(resumed_sessions, integrity_key=_INTEGRITY_KEY)
    authorized = await resumed.read_view(decision.decision_id)
    assert authorized is not None and authorized["stage"] == "authorized"
    assert authorized["status"] == "incomplete" and authorized["final"] is False
    assert authorized["final_verdict"] is None
    receipt = await resumed.claim(decision.decision_id, "explicit_test_claim")
    assert receipt is not None
    await resumed_engine.dispose()

    final_engine, final_sessions = create_engine_and_sessionmaker(
        f"sqlite+aiosqlite:///{db.as_posix()}"
    )
    claimed = await RouteAttemptStore(final_sessions, integrity_key=_INTEGRITY_KEY).read_view(
        decision.decision_id
    )
    assert claimed is not None and claimed["stage"] == "in_progress"
    assert claimed["status"] == "incomplete" and claimed["final"] is False
    assert claimed["journal_record"] is None
    await final_engine.dispose()


async def test_terminal_journal_constraint_failure_rolls_back_every_final_row(
    tmp_path: Path,
) -> None:
    engine, store, db = await _opened(tmp_path)
    setup, decision, assessment, journal = _contracts()
    await store.prepare(setup, decision, assessment, _evidence(setup, decision, assessment))
    await store.authorize(decision.decision_id, _draft(setup, decision, assessment))
    receipt = await store.claim(decision.decision_id, "claim_one")
    assert receipt is not None
    other_engine, sessions = create_engine_and_sessionmaker(f"sqlite+aiosqlite:///{db.as_posix()}")
    async with sessions() as session:
        session.add(
            JournalRow(
                trade_id=journal.trade_id,
                setup_id="other_setup",
                decision_id="other_decision",
                outcome="blocked",
                entry=None,
                exit=None,
                mae=None,
                mfe=None,
                notes="legacy collision",
                payload={"legacy": True},
                created_at=AT,
            )
        )
        await session.commit()
    with pytest.raises(IntegrityError):
        await store.complete(receipt, setup, decision, assessment, journal)
    view = await store.read_view(decision.decision_id)
    assert view is not None and view["stage"] == "in_progress"
    assert view["final"] is False and view["final_verdict"] is None
    await other_engine.dispose()
    await engine.dispose()


async def test_additive_v1_migration_preserves_populated_legacy_table(tmp_path: Path) -> None:
    db = tmp_path / "populated.db"
    engine, sessions = create_engine_and_sessionmaker(f"sqlite+aiosqlite:///{db.as_posix()}")
    async with engine.begin() as conn:
        await conn.run_sync(RiskVerdictRow.__table__.create)
        await conn.execute(
            insert(RiskVerdictRow).values(
                decision_id="legacy_dec",
                action="allow",
                reason="v03",
                adjusted_size=None,
                payload={"decision_id": "legacy_dec", "action": "allow", "reason": "v03"},
                recorded_at=AT,
            )
        )
    await init_schema(engine)
    await init_schema(engine)  # idempotent bootstrap validates the installed schema.
    async with sessions() as session:
        legacy = await session.scalar(
            select(RiskVerdictRow).where(RiskVerdictRow.decision_id == "legacy_dec")
        )
        migration = await session.get(SchemaMigrationRow, 1)
    assert legacy is not None and legacy.payload["reason"] == "v03"
    assert migration is not None and migration.name == "c101_route_attempts_v1"
    assert (
        await RouteAttemptStore(sessions, integrity_key=_INTEGRITY_KEY).read_view("legacy_dec")
        is None
    )
    await engine.dispose()
