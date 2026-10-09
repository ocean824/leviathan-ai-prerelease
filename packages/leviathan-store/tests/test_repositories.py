"""Round-trip and behaviour tests for every repository.

Runs against a fresh in-memory SQLite/aiosqlite database (see conftest).
The module-level ``pytestmark`` marks every coroutine test as asyncio so
the suite passes whether it is collected under this package's
``asyncio_mode = "auto"`` or the workspace-root runner.
"""

from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from leviathan_store import (
    DecisionRepository,
    GenomeRepository,
    JournalRepository,
    RiskVerdictRepository,
    SetupRepository,
)
from leviathan_store.tables import RouteAttemptRow
from sqlalchemy.ext.asyncio import AsyncSession

from leviathan_core.schemas import (
    CandidateSetup,
    DecisionPacket,
    RiskVerdict,
    StrategyGenome,
    TradeJournalRecord,
)

pytestmark = pytest.mark.asyncio

BASE_TS = datetime(2026, 7, 5, 14, 30, tzinfo=UTC)


def _genome(strategy_id: str = "strat_alpha") -> StrategyGenome:
    return StrategyGenome(
        strategy_id=strategy_id,
        family="orderflow_reversal",
        market="NQ",
        timeframe="5m",
        session_dependencies=("ny_open",),
        entry_conditions=("absorption_at_lvn",),
        exit_conditions=("target_hvn",),
        risk_profile="conservative",
        failure_modes=("chop",),
    )


def _setup(setup_id: str = "setup_1", ts: datetime = BASE_TS) -> CandidateSetup:
    return CandidateSetup(
        setup_id=setup_id,
        instrument="NQ",
        timestamp=ts,
        signal_features=("absorption",),
    )


def _decision(decision_id: str = "dec_1") -> DecisionPacket:
    return DecisionPacket(
        decision_id=decision_id,
        setup_id="setup_1",
        permission="approve",
        direction="long",
        confidence=0.73,
        entry_style="limit_retest",
        scaling_allowed=False,
        justification="Truth confirmed, risk clear.",
    )


def _journal(
    trade_id: str = "trade_1",
    outcome: str = "win",
    entry: Decimal | None = Decimal("18234.250000"),
    exit_: Decimal | None = Decimal("18291.750000"),
) -> TradeJournalRecord:
    return TradeJournalRecord(
        trade_id=trade_id,
        setup_id="setup_1",
        decision_id="dec_1",
        entry=entry,
        exit=exit_,
        mae=Decimal("18220.125000") if entry is not None else None,
        mfe=Decimal("18300.875000") if entry is not None else None,
        outcome=outcome,  # type: ignore[arg-type]
        post_trade_notes="clean execution",
    )


def _verdict(decision_id: str = "dec_1", action: str = "reduce_size") -> RiskVerdict:
    return RiskVerdict(
        decision_id=decision_id,
        action=action,  # type: ignore[arg-type]
        reason="approaching_daily_drawdown_soft_cap",
        adjusted_size=Decimal("1.500000"),
        halts_engaged=(),
    )


# --------------------------------------------------------------------------- genomes


async def test_genome_upsert_and_get_round_trip(session: AsyncSession) -> None:
    repo = GenomeRepository(session)
    original = _genome()
    await repo.upsert(original, at=BASE_TS)
    await session.commit()

    fetched = await repo.get("strat_alpha")
    assert fetched == original


async def test_genome_get_missing_returns_none(session: AsyncSession) -> None:
    repo = GenomeRepository(session)
    assert await repo.get("nope") is None


async def test_genome_upsert_overwrites_in_place(session: AsyncSession) -> None:
    repo = GenomeRepository(session)
    await repo.upsert(_genome(), at=BASE_TS)
    await session.commit()

    revised = _genome().model_copy(update={"timeframe": "15m"})
    await repo.upsert(revised, at=BASE_TS + timedelta(days=1))
    await session.commit()

    fetched = await repo.get("strat_alpha")
    assert fetched is not None
    assert fetched.timeframe == "15m"
    assert len(await repo.list_all()) == 1


async def test_genome_list_all(session: AsyncSession) -> None:
    repo = GenomeRepository(session)
    await repo.upsert(_genome("strat_a"), at=BASE_TS)
    await repo.upsert(_genome("strat_b"), at=BASE_TS)
    await session.commit()

    ids = {g.strategy_id for g in await repo.list_all()}
    assert ids == {"strat_a", "strat_b"}


async def test_latest_validation_picks_newest(session: AsyncSession) -> None:
    repo = GenomeRepository(session)
    await repo.upsert(_genome(), at=BASE_TS)
    await repo.record_validation("strat_alpha", "backtest", True, {"sharpe": 1.2}, BASE_TS)
    await repo.record_validation(
        "strat_alpha", "forward", False, {"sharpe": 0.4}, BASE_TS + timedelta(days=2)
    )
    await session.commit()

    latest = await repo.latest_validation("strat_alpha")
    assert latest is not None
    assert latest.stage == "forward"
    assert latest.passed is False
    assert latest.metrics == {"sharpe": 0.4}


async def test_latest_validation_missing_returns_none(session: AsyncSession) -> None:
    repo = GenomeRepository(session)
    assert await repo.latest_validation("strat_alpha") is None


# ---------------------------------------------------------------------------- setups


async def test_setup_add_and_get_round_trip(session: AsyncSession) -> None:
    repo = SetupRepository(session)
    original = _setup()
    await repo.add(original)
    await session.commit()

    assert await repo.get("setup_1") == original


async def test_setup_get_missing_returns_none(session: AsyncSession) -> None:
    repo = SetupRepository(session)
    assert await repo.get("nope") is None


# ------------------------------------------------------------------------- decisions


async def test_decision_add_and_get_round_trip(session: AsyncSession) -> None:
    repo = DecisionRepository(session)
    original = _decision()
    await repo.add(original, at=BASE_TS)
    await session.commit()

    assert await repo.get("dec_1") == original


async def test_decision_list_recent_orders_newest_first(session: AsyncSession) -> None:
    repo = DecisionRepository(session)
    for i in range(3):
        await repo.add(_decision(f"dec_{i}"), at=BASE_TS + timedelta(minutes=i))
    await session.commit()

    recent = await repo.list_recent(limit=2)
    assert [d.decision_id for d in recent] == ["dec_2", "dec_1"]


# -------------------------------------------------------------------------- journal


async def test_journal_add_and_get_round_trip(session: AsyncSession) -> None:
    repo = JournalRepository(session)
    original = _journal()
    await repo.add(original, at=BASE_TS)
    await session.commit()

    assert await repo.get("trade_1") == original


async def test_journal_preserves_decimal_precision(session: AsyncSession) -> None:
    repo = JournalRepository(session)
    precise = _journal(
        entry=Decimal("18234.250001"),
        exit_=Decimal("18291.999999"),
    )
    await repo.add(precise, at=BASE_TS)
    await session.commit()

    fetched = await repo.get("trade_1")
    assert fetched is not None
    assert fetched.entry == Decimal("18234.250001")
    assert fetched.exit == Decimal("18291.999999")
    # Exact object equality proves every Decimal survived unchanged.
    assert fetched == precise


async def test_journal_blocked_trade_without_prices(session: AsyncSession) -> None:
    repo = JournalRepository(session)
    blocked = _journal(
        trade_id="trade_blocked",
        outcome="blocked",
        entry=None,
        exit_=None,
    )
    await repo.add(blocked, at=BASE_TS)
    await session.commit()

    fetched = await repo.get("trade_blocked")
    assert fetched is not None
    assert fetched.entry is None
    assert fetched == blocked


async def test_journal_stats_counts_by_outcome(session: AsyncSession) -> None:
    repo = JournalRepository(session)
    await repo.add(_journal("t1", "win"), at=BASE_TS)
    await repo.add(_journal("t2", "win"), at=BASE_TS)
    await repo.add(_journal("t3", "loss"), at=BASE_TS)
    await repo.add(_journal("t4", "blocked", entry=None, exit_=None), at=BASE_TS)
    await session.commit()

    assert await repo.stats() == {"win": 2, "loss": 1, "blocked": 1}


async def test_journal_list_recent_orders_newest_first(session: AsyncSession) -> None:
    repo = JournalRepository(session)
    for i in range(3):
        await repo.add(_journal(f"t{i}"), at=BASE_TS + timedelta(minutes=i))
    await session.commit()

    recent = await repo.list_recent(limit=2)
    assert [r.trade_id for r in recent] == ["t2", "t1"]


# --------------------------------------------------------------------- risk verdicts


async def test_risk_verdict_add_and_list_round_trip(session: AsyncSession) -> None:
    repo = RiskVerdictRepository(session)
    original = _verdict()
    await repo.add(original, at=BASE_TS)
    await session.commit()

    recent = await repo.list_recent()
    assert len(recent) == 1
    assert recent[0] == original
    assert recent[0].adjusted_size == Decimal("1.500000")


async def test_risk_verdict_allow_without_adjusted_size(session: AsyncSession) -> None:
    repo = RiskVerdictRepository(session)
    allow = RiskVerdict(
        decision_id="dec_1",
        action="allow",
        reason="within_limits",
        adjusted_size=None,
    )
    await repo.add(allow, at=BASE_TS)
    await session.commit()

    recent = await repo.list_recent()
    assert recent[0].adjusted_size is None
    assert recent[0] == allow


async def test_risk_verdict_list_recent_orders_newest_first(
    session: AsyncSession,
) -> None:
    repo = RiskVerdictRepository(session)
    for i in range(3):
        await repo.add(_verdict(f"dec_{i}", "wait"), at=BASE_TS + timedelta(minutes=i))
    await session.commit()

    recent = await repo.list_recent(limit=2)
    assert [v.decision_id for v in recent] == ["dec_2", "dec_1"]


async def test_authoritative_readers_exclude_legacy_and_unfinished_rows(
    session: AsyncSession,
) -> None:
    legacy_journal = _journal("legacy_trade").model_copy(update={"decision_id": "legacy_dec"})
    legacy_verdict = _verdict("legacy_dec", "allow")
    await JournalRepository(session).add(legacy_journal, at=BASE_TS)
    await RiskVerdictRepository(session).add(legacy_verdict, at=BASE_TS)

    final_journal = _journal("trade_terminal")
    final_verdict = _verdict("dec_1", "reduce_size")
    await JournalRepository(session).add(final_journal, at=BASE_TS)
    await RiskVerdictRepository(session).add(final_verdict, at=BASE_TS)
    attempt = RouteAttemptRow(
        decision_id="dec_1",
        setup_id="setup_1",
        state="AUTHORIZED",
        version=1,
        schema_version=1,
        assessment=final_verdict.model_dump(mode="json"),
        evidence={"policy_digest": "a" * 64},
        authorization={"action": "allow", "historical_only": True},
        paper_draft={"broker_path": "paper_sim"},
        policy_digest="a" * 64,
        claim_token=None,
        outcome=None,
        final_verdict=None,
        journal_record=None,
        created_at=BASE_TS,
        updated_at=BASE_TS,
    )
    session.add(attempt)
    await session.commit()

    assert len(await RiskVerdictRepository(session).list_recent()) == 2
    assert len(await JournalRepository(session).list_recent()) == 2
    assert await RiskVerdictRepository(session).list_authoritative_recent() == []
    assert await JournalRepository(session).list_authoritative_recent() == []

    attempt.state = "COMPLETED"
    attempt.outcome = {"kind": "paper_sim", "journal_outcome": "win"}
    attempt.final_verdict = final_verdict.model_dump(mode="json")
    attempt.journal_record = final_journal.model_dump(mode="json")
    await session.commit()
    # A terminal flag and matching final ledgers cannot promote a row that lacks
    # the canonical candidate, parent pair and claim proof.
    assert await RiskVerdictRepository(session).list_authoritative_recent() == []
    assert await JournalRepository(session).list_authoritative_recent() == []
    assert await JournalRepository(session).authoritative_stats() == {}
