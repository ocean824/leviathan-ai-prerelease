"""Independent acceptance probes for the request-scoped OMS submit audit."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from leviathan_store.engine import create_engine_and_sessionmaker, init_schema
from leviathan_store.oms_ledger import open_order_gateway_actor
from leviathan_store.tables import OmsEventRow, OmsLedgerHeadRow, OmsOrderRow
from sqlalchemy import func, insert, select, update
from sqlalchemy.ext.asyncio import AsyncEngine

from leviathan_core.execution.broker_port import (
    BrokerVenue,
    FakeBrokerPort,
    FakeSubmitResult,
)
from leviathan_core.execution.broker_reconciliation import FakeBrokerReconciliation
from leviathan_core.execution.oms import OrderGatewayActor
from leviathan_core.execution.order_models import (
    ClientIdKey,
    LedgerIntegrityKey,
    OMSConflict,
    OMSLedgerCorruption,
    OMSValidationError,
    OrderRequest,
    OrderSnapshot,
    OrderState,
    PaperDispatchEvidence,
)

pytestmark = pytest.mark.asyncio

_CLIENT_KEY = ClientIdKey(b"independent-oms-audit-once-client-key-32")
_INTEGRITY_KEY = LedgerIntegrityKey(b"independent-oms-audit-once-integrity-key")


def _request(account_id: str, intent: str) -> OrderRequest:
    return OrderRequest(
        project_id="leviathan-ai",
        environment="paper",
        account_id=account_id,
        venue=BrokerVenue.ALPACA.value,
        instrument_id="NQ-202612",
        native_contract_id="synthetic-contract",
        side="BUY",
        quantity=Decimal("1"),
        order_type="MARKET",
        time_in_force="DAY",
        client_order_id=_CLIENT_KEY.derive(account_id, intent, 1),
        intent_idempotency_key=intent,
        attempt=1,
        strategy_id="acceptance-strategy",
        risk_policy_digest="a" * 64,
        actor_id="synthetic-operator",
        capability="paper-submit",
    )


def _evidence(order: OrderSnapshot, *, risk_approved: bool = True) -> PaperDispatchEvidence:
    request = order.request
    return PaperDispatchEvidence(
        order_id=order.order_id,
        request_digest=request.digest,
        account_id=request.account_id,
        venue=request.venue,
        strategy_id=request.strategy_id,
        policy_digest=request.risk_policy_digest,
        account_session_verified=True,
        entitled=True,
        feed_fresh=True,
        risk_approved=risk_approved,
        halt_clear=True,
        allowlisted=True,
    )


async def _gateway(
    database: Path,
) -> tuple[OrderGatewayActor, FakeBrokerPort, AsyncEngine]:
    engine, sessions = create_engine_and_sessionmaker(f"sqlite+aiosqlite:///{database}")
    await init_schema(engine)
    reconciliation = FakeBrokerReconciliation()
    broker = FakeBrokerPort(
        reconciliation,
        account_id="paper-submit",
        environment="paper",
        venue=BrokerVenue.ALPACA,
    )
    actor = open_order_gateway_actor(
        sessions,
        broker,
        reconciliation,
        _CLIENT_KEY,
        ledger_key=_INTEGRITY_KEY,
        allow_in_memory=True,
    )
    return actor, broker, engine


async def _dispose(actor: OrderGatewayActor, engine: AsyncEngine) -> None:
    await actor.close()
    await engine.dispose()


async def _seed_history(actor: OrderGatewayActor, count: int) -> None:
    """Add a valid synthetic event suffix in a different account."""
    ledger = actor._ledger
    historical = await actor.create(_request("paper-history", "history-seed"))
    observed_at = datetime.now(UTC)
    async with ledger._sessions() as session:
        order = await session.get(OmsOrderRow, historical.order_id)
        head = await session.get(OmsLedgerHeadRow, ("paper", "paper-history"))
        assert order is not None and head is not None
        largest_id = await session.scalar(select(func.max(OmsEventRow.id)))
        first_id = (largest_id or 0) + 1
        sequence_base = head.sequence_count
        chain = head.head_chain
        key = ledger._integrity_key()
        rows: list[dict[str, Any]] = []
        for sequence in range(1, count + 1):
            event = OmsEventRow(
                id=first_id + sequence - 1,
                order_id=historical.order_id,
                sequence=sequence,
                state=OrderState.CREATED.value,
                code="BROKER_SCOPE_MISMATCH",
                evidence={"discrepancies": ["BROKER_SCOPE_MISMATCH"]},
                recorded_at=observed_at,
                ledger_sequence=sequence_base + sequence,
            )
            event.chain = key.sign(
                bytes.fromhex(chain) + ledger._row_payload(event, exclude=frozenset({"chain"}))
            )
            chain = event.chain
            rows.append(
                {
                    column.name: getattr(event, column.name)
                    for column in OmsEventRow.__table__.columns
                }
            )
        order.version = count
        order.discrepancies = ["BROKER_SCOPE_MISMATCH"]
        order.updated_at = observed_at
        order.chain = key.sign(
            bytes.fromhex(chain) + ledger._row_payload(order, exclude=frozenset({"chain"}))
        )
        await session.execute(insert(OmsEventRow), rows)
        head.sequence_count = sequence_base + count
        head.head_chain = chain
        head.order_cache_digest = ledger._cache_digest([order])
        head.order_count = 1
        head.updated_at = observed_at
        head.anchor = key.sign(ledger._head_payload(head))
        await session.commit()


async def _create_submit_candidate(actor: OrderGatewayActor) -> OrderSnapshot:
    return await actor.create(_request("paper-submit", "submit-candidate"))


@pytest.mark.parametrize("history_rows", [10, 1_000, 10_000])
async def test_submit_uses_one_snapshot_audit_and_at_most_two_total_audits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    history_rows: int,
) -> None:
    actor, broker, engine = await _gateway(tmp_path / f"submit-{history_rows}.db")
    try:
        await _seed_history(actor, history_rows)
        candidate = await _create_submit_candidate(actor)
        broker.queue_submit(FakeSubmitResult(f"synthetic-venue-{history_rows}"))
        ledger = actor._ledger
        audit = ledger._audit_all_oms_rows
        snapshot_method = ledger.verified_submit_snapshot
        mark_method = ledger.mark_submitting
        counts = {"audit": 0, "snapshot": 0, "mark": 0}
        snapshot_audit_counts: list[int] = []
        mark_audit_counts: list[int] = []

        async def counted_audit(session: Any) -> None:
            counts["audit"] += 1
            await audit(session)

        async def counted_snapshot(environment: str, account_id: str) -> Any:
            counts["snapshot"] += 1
            before = counts["audit"]
            result = await snapshot_method(environment, account_id)
            snapshot_audit_counts.append(counts["audit"] - before)
            return result

        async def counted_mark(order_id: str, evidence: PaperDispatchEvidence) -> Any:
            counts["mark"] += 1
            before = counts["audit"]
            result = await mark_method(order_id, evidence)
            mark_audit_counts.append(counts["audit"] - before)
            return result

        monkeypatch.setattr(ledger, "_audit_all_oms_rows", counted_audit)
        monkeypatch.setattr(ledger, "verified_submit_snapshot", counted_snapshot)
        monkeypatch.setattr(ledger, "mark_submitting", counted_mark)
        submitted = await actor.submit(candidate.order_id, _evidence(candidate))

        assert submitted.state is OrderState.WORKING
        assert broker.submit_calls == 1
        assert counts["snapshot"] == 1
        assert snapshot_audit_counts == [1]
        assert counts["mark"] == 1
        assert mark_audit_counts == [1]
        assert counts["audit"] == 2
        assert counts["audit"] <= 2
    finally:
        await _dispose(actor, engine)


@pytest.mark.parametrize("tamper_kind", ["tamper", "reorder", "gap"])
async def test_corrupt_global_history_blocks_submit_without_new_order_rows_or_dispatch(
    tmp_path: Path,
    tamper_kind: str,
) -> None:
    actor, broker, engine = await _gateway(tmp_path / f"corrupt-{tamper_kind}.db")
    try:
        await _seed_history(actor, 10)
        candidate = await _create_submit_candidate(actor)
        async with engine.begin() as connection:
            before_orders = await connection.scalar(select(func.count()).select_from(OmsOrderRow))
            event_ids = list(
                (
                    await connection.execute(
                        select(OmsEventRow.id, OmsEventRow.ledger_sequence)
                        .where(OmsEventRow.order_id != candidate.order_id)
                        .order_by(OmsEventRow.ledger_sequence)
                    )
                ).all()
            )

        history_id = event_ids[1][0]
        if tamper_kind == "tamper":
            async with engine.begin() as connection:
                await connection.execute(
                    update(OmsEventRow)
                    .where(OmsEventRow.id == history_id)
                    .values(code="ALTERED_SYNTHETIC_EVENT")
                )
        elif tamper_kind == "gap":
            async with engine.begin() as connection:
                await connection.execute(
                    update(OmsEventRow)
                    .where(OmsEventRow.id == history_id)
                    .values(ledger_sequence=event_ids[1][1] + 100)
                )
        else:
            first_id, first_sequence = event_ids[1]
            last_id, last_sequence = event_ids[-1]
            temporary = max(sequence for _row_id, sequence in event_ids) + 100
            async with engine.begin() as connection:
                await connection.execute(
                    update(OmsEventRow)
                    .where(OmsEventRow.id == first_id)
                    .values(ledger_sequence=temporary)
                )
                await connection.execute(
                    update(OmsEventRow)
                    .where(OmsEventRow.id == last_id)
                    .values(ledger_sequence=first_sequence)
                )
                await connection.execute(
                    update(OmsEventRow)
                    .where(OmsEventRow.id == first_id)
                    .values(ledger_sequence=last_sequence)
                )

        with pytest.raises(OMSLedgerCorruption) as error:
            await actor.submit(candidate.order_id, _evidence(candidate))

        assert error.value.code == "OMS_LEDGER_CORRUPT"
        assert broker.submit_calls == 0
        assert await actor.get(candidate.order_id) == candidate
        async with engine.connect() as connection:
            after_orders = await connection.scalar(select(func.count()).select_from(OmsOrderRow))
        assert after_orders == before_orders
    finally:
        await _dispose(actor, engine)


async def test_mark_submitting_keeps_its_independent_integrity_check(
    tmp_path: Path,
) -> None:
    actor, broker, engine = await _gateway(tmp_path / "mark-submitting-tamper.db")
    try:
        await _seed_history(actor, 10)
        candidate = await _create_submit_candidate(actor)
        async with engine.begin() as connection:
            await connection.execute(
                update(OmsEventRow)
                .where(OmsEventRow.order_id != candidate.order_id)
                .where(OmsEventRow.sequence == 1)
                .values(code="ALTERED_CREATED_EVENT")
            )
        audit = actor._ledger._audit_all_oms_rows
        audit_calls = 0

        async def counted_audit(session: Any) -> None:
            nonlocal audit_calls
            audit_calls += 1
            await audit(session)

        from leviathan_core.execution.oms import VerifiedSubmitSnapshot

        async def bypass_request_snapshot(_environment: str, _account_id: str) -> Any:
            return VerifiedSubmitSnapshot(
                environment=candidate.request.environment,
                account_id=candidate.request.account_id,
                account_inventory=(candidate,),
                account_identity_inventory=(candidate,),
                account_execution_evidence=(),
                account_fill_corrections=(),
            )

        actor._ledger._audit_all_oms_rows = counted_audit  # type: ignore[method-assign]
        actor._ledger.verified_submit_snapshot = bypass_request_snapshot  # type: ignore[method-assign]
        with pytest.raises(OMSLedgerCorruption) as error:
            await actor.submit(candidate.order_id, _evidence(candidate))

        assert error.value.code == "OMS_LEDGER_CORRUPT"
        assert audit_calls == 1
        assert broker.submit_calls == 0
        current = await actor.get(candidate.order_id)
        assert current is not None and current.state is OrderState.CREATED
    finally:
        await _dispose(actor, engine)


async def test_duplicate_submit_is_idempotent_and_risk_gate_remains_required(
    tmp_path: Path,
) -> None:
    actor, broker, engine = await _gateway(tmp_path / "duplicate-and-risk.db")
    try:
        request = _request("paper-submit", "idempotent-submit")
        candidate = await actor.create(request)
        duplicate = await actor.create(request)
        assert duplicate.order_id == candidate.order_id

        broker.queue_submit(FakeSubmitResult("synthetic-idempotent-venue-order"))
        submitted = await actor.submit(candidate.order_id, _evidence(candidate))
        assert submitted.state is OrderState.WORKING
        with pytest.raises(OMSConflict, match="SUBMIT_ALREADY_ATTEMPTED"):
            await actor.submit(candidate.order_id, _evidence(candidate))
        assert broker.submit_calls == 1

        denied_request = _request("paper-submit", "risk-gate-required")
        denied = await actor.create(denied_request)
        with pytest.raises(OMSValidationError):
            await actor.submit(denied.order_id, _evidence(denied, risk_approved=False))
        assert broker.submit_calls == 1
        rejected = await actor.get(denied.order_id)
        assert rejected is not None
        assert rejected.state is OrderState.RISK_REJECTED
        assert rejected.submit_attempted is False
    finally:
        await _dispose(actor, engine)
