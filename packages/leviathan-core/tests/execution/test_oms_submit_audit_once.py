"""Request-scoped verified OMS inventory used by submit reconciliation."""

from __future__ import annotations

import os
import statistics
import time
from decimal import Decimal
from pathlib import Path
from typing import cast

import pytest
from leviathan_store.engine import create_engine_and_sessionmaker, init_schema
from leviathan_store.oms_ledger import OrderLedger, open_order_gateway_actor

from leviathan_core.execution.broker_port import FakeBrokerPort
from leviathan_core.execution.broker_port_v1 import BrokerVenue
from leviathan_core.execution.broker_reconciliation import FakeBrokerReconciliation
from leviathan_core.execution.oms import VerifiedSubmitSnapshot
from leviathan_core.execution.order_models import (
    ClientIdKey,
    LedgerIntegrityKey,
    OMSValidationError,
    OrderRequest,
)

_INTEGRITY_KEY = LedgerIntegrityKey(b"oms-submit-audit-unit-integrity-key-32-bytes")
_CLIENT_KEY = ClientIdKey(b"oms-submit-audit-unit-client-key-32-bytes")


def make_request() -> OrderRequest:
    return OrderRequest(
        project_id="leviathan-ai",
        environment="paper",
        account_id="paper-audit-1",
        venue=BrokerVenue.IBKR_TWS.value,
        instrument_id="NQ-202612",
        native_contract_id="NQ-202612.demo",
        side="BUY",
        quantity=Decimal("2"),
        order_type="LIMIT",
        time_in_force="DAY",
        client_order_id=_CLIENT_KEY.derive("paper-audit-1", "audit-once", 1),
        intent_idempotency_key="audit-once",
        attempt=1,
        strategy_id="strategy-1",
        risk_policy_digest="a" * 64,
        actor_id="operator-1",
        capability="paper-submit",
        limit_price=Decimal("100"),
    )


@pytest.mark.asyncio
async def test_verified_submit_snapshot_audits_once_and_contains_all_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine, sessions = create_engine_and_sessionmaker(f"sqlite+aiosqlite:///{tmp_path / 'oms.db'}")
    await init_schema(engine)
    reconciliation = FakeBrokerReconciliation()
    broker = FakeBrokerPort(
        reconciliation,
        account_id="paper-audit-1",
        venue=BrokerVenue.IBKR_TWS,
    )
    actor = open_order_gateway_actor(
        sessions,
        broker,
        reconciliation,
        _CLIENT_KEY,
        ledger_key=_INTEGRITY_KEY,
    )
    ledger = cast(OrderLedger, vars(actor)["_ledger"])
    try:
        req = make_request()
        created = await actor.create(req)

        audit_calls = 0
        original_audit = ledger._audit_all_oms_rows

        async def count_audit(session: object) -> None:
            nonlocal audit_calls
            audit_calls += 1
            await original_audit(session)  # type: ignore[arg-type]

        monkeypatch.setattr(ledger, "_audit_all_oms_rows", count_audit)
        snapshot = await ledger.verified_submit_snapshot(req.environment, req.account_id)

        assert type(snapshot) is VerifiedSubmitSnapshot
        assert audit_calls == 1
        assert snapshot.account_inventory == snapshot.account_identity_inventory
        assert snapshot.account_inventory[0].order_id == created.order_id
        assert snapshot.account_execution_evidence == ()
        assert snapshot.account_fill_corrections == ()
    finally:
        await actor.close()
        await engine.dispose()


def test_verified_submit_snapshot_rejects_mismatched_scope() -> None:
    with pytest.raises(OMSValidationError, match="INVALID_VERIFIED_SUBMIT_SNAPSHOT"):
        VerifiedSubmitSnapshot(
            environment="live",
            account_id="account-1",
            account_inventory=(),
            account_identity_inventory=(),
            account_execution_evidence=(),
            account_fill_corrections=(),
        )


@pytest.mark.skipif(
    os.environ.get("LEVIATHAN_RUN_PERF") != "1",
    reason="set LEVIATHAN_RUN_PERF=1 to run the 10k-row submit timing sample",
)
@pytest.mark.asyncio
async def test_submit_10k_rows_reports_five_sample_latency_median_and_max(
    tmp_path: Path,
) -> None:
    """Opt-in wall-clock evidence; structural audit-count checks stay in default tests."""
    from test_oms_submit_audit_once_acceptance import (
        _create_submit_candidate,
        _dispose,
        _evidence,
        _gateway,
        _seed_history,
    )

    from leviathan_core.execution.broker_port import FakeSubmitResult
    from leviathan_core.execution.order_models import OrderState

    elapsed: list[float] = []
    for sample in range(5):
        actor, broker, engine = await _gateway(tmp_path / f"submit-perf-{sample}.db")
        try:
            await _seed_history(actor, 10_000)
            candidate = await _create_submit_candidate(actor)
            broker.queue_submit(FakeSubmitResult(f"perf-venue-{sample}"))
            started = time.perf_counter()
            submitted = await actor.submit(candidate.order_id, _evidence(candidate))
            elapsed.append(time.perf_counter() - started)
            assert submitted.state is OrderState.WORKING
        finally:
            await _dispose(actor, engine)
    median = statistics.median(elapsed)
    maximum = max(elapsed)
    print(
        "OMS_SUBMIT_AUDIT_ONCE_PERF "
        f"history_rows=10000 samples={len(elapsed)} "
        f"median_seconds={median:.6f} max_seconds={maximum:.6f}"
    )
