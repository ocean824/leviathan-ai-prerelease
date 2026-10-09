"""Independent API acceptance for the C-101 pipeline issuance boundary."""

from __future__ import annotations

import json
from typing import Any

import anyio
import pytest
from fastapi.testclient import TestClient
from leviathan_store.risk_txn import RouteAttemptStore, RouteTransitionError
from leviathan_store.tables import JournalRow, RiskVerdictRow, RouteAttemptRow
from sqlalchemy import func, select

from leviathan_api.routers import pipeline as pipeline_router
from leviathan_core.execution.order_models import LedgerIntegrityKey
from leviathan_core.pipeline import LiveFlowPipeline, PipelineResult
from leviathan_core.schemas import RiskVerdict, TradeJournalRecord
from leviathan_core.schemas.journal import require_trade_journal_record
from leviathan_core.schemas.risk import require_risk_verdict

_SYNTHETIC_KEY_BYTES = b"pipeline-acceptance-synthetic-key-000000001"
_SYNTHETIC_KEY = LedgerIntegrityKey(_SYNTHETIC_KEY_BYTES)
_PIPELINE_RESULT_FIELDS = {
    "setup",
    "session",
    "range_context",
    "truth",
    "decision",
    "verdict",
    "final_verdict",
    "findings",
    "intent",
    "journal_record",
    "status",
    "final",
    "audit_sink_failure",
    "failure_reason",
}


def _assert_no_private_fields(payload: object) -> None:
    private_names = {"proof", "mac", "integrity_key", "traceback", "exception"}

    def visit(value: object) -> None:
        if isinstance(value, dict):
            assert not (private_names & {str(key).lower() for key in value})
            for nested in value.values():
                visit(nested)
        elif isinstance(value, list):
            for nested in value:
                visit(nested)

    visit(payload)
    encoded = json.dumps(payload, sort_keys=True).lower()
    assert "traceback" not in encoded
    assert _SYNTHETIC_KEY_BYTES.decode() not in encoded


def _database_counts(client: TestClient, decision_id: str) -> dict[str, int]:
    async def count() -> dict[str, int]:
        async with client.app.state.sessionmaker() as session:
            route = await session.get(RouteAttemptRow, decision_id)
            verdicts = await session.scalar(
                select(func.count())
                .select_from(RiskVerdictRow)
                .where(RiskVerdictRow.decision_id == decision_id)
            )
            journals = await session.scalar(
                select(func.count())
                .select_from(JournalRow)
                .where(JournalRow.decision_id == decision_id)
            )
            return {
                "route": int(route is not None),
                "route_state_pending": int(route is not None and route.state == "PENDING"),
                "route_state_in_progress": int(route is not None and route.state == "IN_PROGRESS"),
                "route_terminal_fields": int(
                    route is not None
                    and any(
                        value is not None
                        for value in (route.outcome, route.final_verdict, route.journal_record)
                    )
                ),
                "verdicts": int(verdicts or 0),
                "journals": int(journals or 0),
            }

    return anyio.run(count)


def test_keyless_post_returns_issued_completion_but_later_read_is_unverified(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = client.app.state.leviathan
    state.ledger_integrity_key = None
    issued_results: list[PipelineResult] = []
    original_require = pipeline_router.require_pipeline_result

    def observe_required_result(value: object) -> PipelineResult:
        result = original_require(value)
        issued_results.append(result)
        return result

    monkeypatch.setattr(pipeline_router, "require_pipeline_result", observe_required_result)

    response = client.post("/pipeline/replay")
    body = response.json()
    assert response.status_code == 200
    assert set(body) == _PIPELINE_RESULT_FIELDS
    assert body["status"] == "completed" and body["final"] is True
    assert body["final_verdict"] is not None and body["journal_record"] is not None
    assert body["journal_record"]["outcome"] == "win"
    assert len(issued_results) == 1
    assert issued_results[0].status == "completed" and issued_results[0].final is True
    _assert_no_private_fields(body)

    decision_id = body["decision"]["decision_id"]
    later = client.get(f"/pipeline/attempts/{decision_id}")
    assert later.status_code == 200
    later_body = later.json()
    assert later_body["status"] == "unverified"
    assert later_body["final"] is False
    assert later_body["final_verdict"] is None
    assert later_body["journal_record"] is None
    assert later_body["verification"] == "UNVERIFIED"
    _assert_no_private_fields(later_body)

    with pytest.raises(RouteTransitionError, match="INTEGRITY_KEY_UNAVAILABLE"):
        anyio.run(
            RouteAttemptStore(client.app.state.sessionmaker).read_verified_terminal,
            decision_id,
        )


def test_keyless_terminal_remains_unissued_after_synthetic_key_is_restored(
    client: TestClient,
) -> None:
    state = client.app.state.leviathan
    state.ledger_integrity_key = None
    response = client.post("/pipeline/replay")
    decision_id = response.json()["decision"]["decision_id"]

    state.ledger_integrity_key = _SYNTHETIC_KEY
    later = client.get(f"/pipeline/attempts/{decision_id}")
    body = later.json()

    assert response.status_code == 200
    assert later.status_code == 200
    assert body["status"] == "unverified"
    assert body["verification"] == "UNVERIFIED"
    assert body["reason"] == "UNISSUED_PERSISTED"
    assert body["final"] is False
    assert body["final_verdict"] is None
    assert body["journal_record"] is None
    assert body["audit_sink_failure"] is False
    _assert_no_private_fields(body)


def test_synthetic_key_enables_authoritative_reload_and_keeps_http_shape(
    client: TestClient,
) -> None:
    client.app.state.leviathan.ledger_integrity_key = _SYNTHETIC_KEY

    response = client.post("/pipeline/replay")
    body = response.json()
    assert response.status_code == 200
    assert body["status"] == "completed" and body["final"] is True
    assert body["final_verdict"] is not None and body["journal_record"] is not None
    assert set(body) == _PIPELINE_RESULT_FIELDS
    _assert_no_private_fields(body)

    decision_id = body["decision"]["decision_id"]
    attempt = client.get(f"/pipeline/attempts/{decision_id}")
    assert attempt.status_code == 200
    attempt_body = attempt.json()
    assert attempt_body["status"] == "completed" and attempt_body["final"] is True
    assert attempt_body["final_verdict"] == body["final_verdict"]
    assert attempt_body["journal_record"] == body["journal_record"]
    _assert_no_private_fields(attempt_body)

    async def reload_typed() -> tuple[RiskVerdict, TradeJournalRecord] | None:
        store = RouteAttemptStore(
            client.app.state.sessionmaker,
            integrity_key=_SYNTHETIC_KEY,
        )
        return await store.read_verified_terminal(decision_id)

    typed_pair = anyio.run(reload_typed)
    assert typed_pair is not None
    assert type(typed_pair[0]) is RiskVerdict
    assert type(typed_pair[1]) is TradeJournalRecord
    assert require_risk_verdict(typed_pair[0]) is typed_pair[0]
    assert require_trade_journal_record(typed_pair[1]) is typed_pair[1]
    assert typed_pair[0].model_dump(mode="json") == body["final_verdict"]
    assert typed_pair[1].model_dump(mode="json") == body["journal_record"]


def test_invalid_assessment_is_rejected_before_the_store_handoff(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_prepare_replay = LiveFlowPipeline.prepare_replay
    store_prepare_calls = 0

    def unissue_assessment(self: LiveFlowPipeline, *args: object, **kwargs: object) -> Any:
        prepared = original_prepare_replay(self, *args, **kwargs)
        unissued = RiskVerdict.model_validate(prepared.assessment.model_dump(mode="json"))
        object.__setattr__(prepared, "assessment", unissued)
        return prepared

    original_store_prepare = RouteAttemptStore.prepare

    async def count_store_prepare(self: RouteAttemptStore, *args: object, **kwargs: object) -> None:
        nonlocal store_prepare_calls
        store_prepare_calls += 1
        await original_store_prepare(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(LiveFlowPipeline, "prepare_replay", unissue_assessment)
    monkeypatch.setattr(RouteAttemptStore, "prepare", count_store_prepare)

    response = client.post("/pipeline/replay")
    body = response.json()
    assert response.status_code == 503
    assert body["status"] == "incomplete" and body["final"] is False
    assert body["final_verdict"] is None and body["journal_record"] is None
    assert store_prepare_calls == 0
    _assert_no_private_fields(body)

    async def row_count() -> int:
        async with client.app.state.sessionmaker() as session:
            return int(await session.scalar(select(func.count()).select_from(RouteAttemptRow)) or 0)

    assert anyio.run(row_count) == 0


def test_invalid_terminal_values_do_not_reach_complete_storage(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_consume = LiveFlowPipeline.consume_claimed
    store_complete_calls = 0

    def unissue_terminal(
        self: LiveFlowPipeline, prepared: Any, receipt: Any
    ) -> tuple[RiskVerdict, None, TradeJournalRecord]:
        final, _intent, journal = original_consume(self, prepared, receipt)
        return (
            RiskVerdict.model_validate(final.model_dump(mode="json")),
            None,
            TradeJournalRecord.model_validate(journal.model_dump(mode="json")),
        )

    original_store_complete = RouteAttemptStore.complete

    async def count_store_complete(
        self: RouteAttemptStore, *args: object, **kwargs: object
    ) -> None:
        nonlocal store_complete_calls
        store_complete_calls += 1
        await original_store_complete(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(LiveFlowPipeline, "consume_claimed", unissue_terminal)
    monkeypatch.setattr(RouteAttemptStore, "complete", count_store_complete)

    response = client.post("/pipeline/replay")
    body = response.json()
    assert response.status_code == 503
    assert body["status"] == "incomplete" and body["final"] is False
    assert body["final_verdict"] is None and body["journal_record"] is None
    assert store_complete_calls == 0
    _assert_no_private_fields(body)

    decision_id = body["decision"]["decision_id"]
    counts = _database_counts(client, decision_id)
    assert counts == {
        "route": 1,
        "route_state_pending": 0,
        "route_state_in_progress": 1,
        "route_terminal_fields": 0,
        "verdicts": 0,
        "journals": 0,
    }


def test_missing_attempt_http_status_and_body_remain_private(client: TestClient) -> None:
    response = client.get("/pipeline/attempts/synthetic-unknown-decision")
    assert response.status_code == 404
    assert response.json() == {"decision_id": "synthetic-unknown-decision"}
