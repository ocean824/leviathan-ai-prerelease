"""Independent HTTP and durable-store acceptance for C101-FIX-002."""

from decimal import Decimal
from typing import Never

import anyio
import pytest
from fastapi.testclient import TestClient
from leviathan_store.repositories import JournalRow, RiskVerdictRow
from leviathan_store.risk_txn import RouteAttemptStore, RouteTransitionError
from leviathan_store.tables import RouteAttemptRow
from sqlalchemy import func, select

from leviathan_core.decision.engine import CouncilDecisionEngine
from leviathan_core.schemas import Permission, RiskAction, TradeJournalRecord


def _force_permission(
    monkeypatch: pytest.MonkeyPatch,
    permission: Permission,
    *,
    decision_id: str | None = None,
) -> None:
    original = CouncilDecisionEngine.decide

    def decide(self: CouncilDecisionEngine, *args: object, **kwargs: object):  # type: ignore[no-untyped-def]
        decision = original(self, *args, **kwargs)  # type: ignore[arg-type]
        candidate = decision.model_dump(mode="json")
        candidate["permission"] = permission.value
        if decision_id is not None:
            candidate["decision_id"] = decision_id
        return type(decision).model_validate(candidate)

    monkeypatch.setattr(CouncilDecisionEngine, "decide", decide)


def _forbid_simulation(monkeypatch: pytest.MonkeyPatch, client: TestClient) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> Never:
        pytest.fail("a terminal council denial must not invoke paper simulation")

    monkeypatch.setattr(client.app.state.leviathan.paper, "simulate", forbidden)


@pytest.mark.parametrize(
    ("permission", "expected_action"),
    [
        (Permission.REJECT, RiskAction.REJECT),
        (Permission.WAIT, RiskAction.WAIT),
        (Permission.SIGNAL_ONLY, RiskAction.REJECT),
    ],
)
def test_council_denial_persists_blocked_terminal_pair_and_no_intent(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    permission: Permission,
    expected_action: RiskAction,
) -> None:
    _force_permission(monkeypatch, permission)
    _forbid_simulation(monkeypatch, client)

    response = client.post("/pipeline/replay")
    body = response.json()
    decision_id = body["decision"]["decision_id"]
    attempt_response = client.get(f"/pipeline/attempts/{decision_id}")
    attempt = attempt_response.json()

    assert response.status_code == 200, body
    assert body["status"] == "blocked" and body["final"] is True
    assert body["intent"] is None
    assert body["verdict"]["action"] == RiskAction.ALLOW.value
    assert body["final_verdict"]["decision_id"] == decision_id
    assert body["final_verdict"]["action"] == expected_action.value
    assert body["final_verdict"]["reason"] == f"council_permission_{permission.value}"
    assert body["final_verdict"]["execution_capable"] is False
    assert body["final_verdict"]["adjusted_size"] is None
    assert body["journal_record"]["decision_id"] == decision_id
    assert body["journal_record"]["outcome"] == "blocked"
    assert attempt_response.status_code == 200
    assert attempt["status"] == "blocked" and attempt["final"] is True
    assert attempt["final_verdict"] == body["final_verdict"]
    assert attempt["journal_record"] == body["journal_record"]


def test_failed_terminal_commit_remains_incomplete_503(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _force_permission(monkeypatch, Permission.REJECT)

    async def fail_complete(_self: RouteAttemptStore, *_args: object, **_kwargs: object) -> Never:
        raise OSError("synthetic terminal transaction failure")

    monkeypatch.setattr(RouteAttemptStore, "complete", fail_complete)
    response = client.post("/pipeline/replay")
    body = response.json()

    assert response.status_code == 503
    assert body["status"] == "incomplete" and body["final"] is False
    assert body["intent"] is None
    assert body["final_verdict"] is None
    assert body["journal_record"] is None
    assert body["audit_sink_failure"] is True


def test_repeated_decision_id_does_not_duplicate_terminal_records(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    decision_id = "acceptance_repeated_decision"
    _force_permission(monkeypatch, Permission.REJECT, decision_id=decision_id)

    first = client.post("/pipeline/replay")
    first_body = first.json()
    repeated = client.post("/pipeline/replay")
    attempt_response = client.get(f"/pipeline/attempts/{decision_id}")

    assert first.status_code == 200
    assert first_body["final"] is True
    assert repeated.status_code == 503
    assert attempt_response.status_code == 200
    assert attempt_response.json()["final_verdict"] == first_body["final_verdict"]
    assert attempt_response.json()["journal_record"] == first_body["journal_record"]


def test_persisted_halt_still_blocks_replay(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = client.app.state.leviathan
    _forbid_simulation(monkeypatch, client)
    state.halts.engage("acceptance_operator_halt")

    response = client.post("/pipeline/replay")
    body = response.json()
    decision_id = body["decision"]["decision_id"]
    attempt = client.get(f"/pipeline/attempts/{decision_id}").json()

    assert response.status_code == 200
    assert body["status"] == "blocked" and body["final"] is True
    assert body["intent"] is None
    assert body["final_verdict"]["action"] == RiskAction.HALT_ALL_TRADING.value
    assert "global_kill_active" in body["final_verdict"]["findings"]
    assert attempt["final_verdict"] == body["final_verdict"]
    assert state.halts.halted


@pytest.mark.parametrize(
    "contradiction",
    [
        {"entry": "100"},
        {"exit": "101"},
        {"post_trade_notes": "risk=allow reason=within_limits"},
    ],
    ids=["entry-price", "exit-price", "notes-claim-allow"],
)
def test_council_terminal_journal_forgery_is_rejected_before_store_write(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    contradiction: dict[str, str],
) -> None:
    _force_permission(monkeypatch, Permission.REJECT)
    original = RouteAttemptStore.complete
    rejected: list[RouteTransitionError] = []

    async def inject_contradictory_journal(
        self: RouteAttemptStore,
        receipt: object,
        setup: object,
        decision: object,
        verdict: object,
        journal: TradeJournalRecord,
    ) -> None:
        payload = journal.model_dump(mode="json")
        payload.update(contradiction)
        invalid = TradeJournalRecord.model_validate(payload)
        try:
            await original(self, receipt, setup, decision, verdict, invalid)  # type: ignore[arg-type]
        except RouteTransitionError as error:
            rejected.append(error)
            raise
        pytest.fail("contradictory council terminal journal was committed")

    monkeypatch.setattr(RouteAttemptStore, "complete", inject_contradictory_journal)
    response = client.post("/pipeline/replay")
    body = response.json()
    decision_id = body["decision"]["decision_id"]
    attempt_response = client.get(f"/pipeline/attempts/{decision_id}")
    attempt = attempt_response.json()

    assert response.status_code == 503
    # The API now rejects unissued journal data before calling storage; the
    # store's own require_* check remains a second boundary for direct callers.
    assert rejected == []
    assert attempt_response.status_code == 200
    assert attempt["final"] is False
    assert attempt["final_verdict"] is None
    assert attempt["journal_record"] is None

    async def terminal_counts() -> tuple[int, int]:
        async with client.app.state.sessionmaker() as session:
            verdict_count = await session.scalar(
                select(func.count())
                .select_from(RiskVerdictRow)
                .where(RiskVerdictRow.decision_id == decision_id)
            )
            journal_count = await session.scalar(
                select(func.count())
                .select_from(JournalRow)
                .where(JournalRow.decision_id == decision_id)
            )
            return int(verdict_count or 0), int(journal_count or 0)

    assert anyio.run(terminal_counts) == (0, 0)


def test_tampered_council_terminal_row_is_never_read_as_final(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _force_permission(monkeypatch, Permission.REJECT)
    completed = client.post("/pipeline/replay")
    body = completed.json()
    assert completed.status_code == 200
    decision_id = body["decision"]["decision_id"]
    journal_record = body["journal_record"]

    async def tamper_terminal_row() -> None:
        async with client.app.state.sessionmaker() as session:
            attempt = await session.get(RouteAttemptRow, decision_id)
            journal = await session.get(JournalRow, journal_record["trade_id"])
            assert attempt is not None and journal is not None
            contradictory = dict(attempt.journal_record)
            contradictory.update(
                {
                    "entry": "100",
                    "exit": "101",
                    "post_trade_notes": "risk=allow reason=within_limits",
                }
            )
            attempt.journal_record = contradictory
            journal.payload = contradictory
            journal.entry = Decimal("100")
            journal.exit = Decimal("101")
            journal.notes = "risk=allow reason=within_limits"
            await session.commit()

    anyio.run(tamper_terminal_row)
    reread = client.get(f"/pipeline/attempts/{decision_id}")

    assert reread.status_code == 503
    assert reread.json()["final"] is False
    assert reread.json()["final_verdict"] is None
    assert reread.json()["journal_record"] is None
