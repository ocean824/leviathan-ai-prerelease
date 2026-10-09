"""Independent durable OMS ledger acceptance cases."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import ROUND_DOWN, Decimal, Inexact, localcontext
from pathlib import Path

import pytest
from leviathan_store.engine import create_engine_and_sessionmaker, init_schema
from leviathan_store.oms_ledger import OrderLedger
from leviathan_store.tables import (
    OmsEventRow,
    OmsFillCorrectionRow,
    OmsFillRow,
    OmsLedgerHeadRow,
    OmsObservationRow,
    OmsOrderRow,
)
from sqlalchemy import delete, insert, select, update

from leviathan_core.execution.order_models import (
    BrokerObservation,
    ClientIdKey,
    Fill,
    FillCorrection,
    LedgerIntegrityKey,
    OMSConflict,
    OMSLedgerCorruption,
    OMSValidationError,
    OrderRequest,
    OrderState,
    PaperDispatchEvidence,
)

pytestmark = pytest.mark.asyncio
NOW = datetime(2026, 9, 30, 15, 0, tzinfo=UTC)
_INTEGRITY_KEY = LedgerIntegrityKey(b"oms-acceptance-synthetic-key-32-bytes!")
_CLIENT_ID_KEY = ClientIdKey(b"oms-acceptance-client-id-key-32-bytes!")


def _request(
    *,
    client_order_id: str = "ledger-acceptance-1",
    intent_idempotency_key: str | None = None,
    attempt: int = 1,
    tif: str = "DAY",
    expiry: datetime | None = None,
) -> OrderRequest:
    intent_key = intent_idempotency_key or client_order_id
    return OrderRequest(
        project_id="leviathan-ai",
        environment="demo",
        account_id="demo-account-1",
        venue="MT5",
        instrument_id="EURUSD",
        native_contract_id="EURUSD.demo",
        side="BUY",
        quantity=Decimal("1"),
        order_type="MARKET",
        time_in_force=tif,
        client_order_id=_CLIENT_ID_KEY.derive("demo-account-1", intent_key, attempt),
        intent_idempotency_key=intent_key,
        attempt=attempt,
        strategy_id="ledger-acceptance-strategy",
        risk_policy_digest="b" * 64,
        actor_id="synthetic-operator",
        capability="demo-submit",
        expires_at=expiry,
    )


def _evidence(order_id: str, request: OrderRequest) -> PaperDispatchEvidence:
    return PaperDispatchEvidence(
        order_id=order_id,
        request_digest=request.digest,
        account_id=request.account_id,
        venue=request.venue,
        strategy_id=request.strategy_id,
        policy_digest=request.risk_policy_digest,
        account_session_verified=True,
        entitled=True,
        feed_fresh=True,
        risk_approved=True,
        halt_clear=True,
        allowlisted=True,
    )


async def _ledger(path: Path) -> tuple[OrderLedger, object]:
    engine, sessions = create_engine_and_sessionmaker(f"sqlite+aiosqlite:///{path}")
    await init_schema(engine)
    return OrderLedger(sessions, key=_INTEGRITY_KEY), engine


async def _seed_integrity_rows(
    path: Path, client_order_id: str
) -> tuple[OrderLedger, object, OrderRequest, str, Fill, FillCorrection, BrokerObservation]:
    ledger, engine = await _ledger(path)
    request = _request(client_order_id=client_order_id)
    created = await ledger.create(request)
    await ledger.mark_submitting(created.order_id, _evidence(created.order_id, request))
    await ledger.mark_submit_result(created.order_id, OrderState.WORKING, "venue-integrity")
    observation = BrokerObservation(
        observation_id=f"integrity-observation-{client_order_id}",
        environment=request.environment,
        account_id=request.account_id,
        venue=request.venue,
        client_order_id=request.client_order_id,
        status=OrderState.WORKING,
        observed_at=NOW,
        venue_order_id="venue-integrity",
    )
    await ledger.record_observation(created.order_id, observation)
    fill = Fill(
        venue=request.venue,
        account_id=request.account_id,
        execution_id=f"integrity-fill-{client_order_id}",
        quantity=Decimal("0.25"),
        price=Decimal("1.10"),
        occurred_at=NOW + timedelta(seconds=1),
    )
    await ledger.record_fill(created.order_id, fill)
    correction = FillCorrection(
        venue=request.venue,
        account_id=request.account_id,
        execution_id=fill.execution_id,
        correction_id=f"integrity-correction-{client_order_id}",
        revision=1,
        revised_quantity=Decimal("0.20"),
        revised_price=Decimal("1.11"),
        occurred_at=NOW + timedelta(seconds=2),
    )
    await ledger.record_fill_correction(created.order_id, correction)
    return ledger, engine, request, created.order_id, fill, correction, observation


async def test_idempotency_key_and_request_conflict_survive_database_reopen(
    tmp_path: Path,
) -> None:
    database = tmp_path / "durable-oms.db"
    ledger, engine = await _ledger(database)
    request = _request()
    first = await ledger.create(request)
    await engine.dispose()

    reopened, engine = await _ledger(database)
    duplicate = await reopened.create(request)

    assert duplicate.order_id == first.order_id
    assert duplicate.request.digest == first.request.digest
    assert len(await reopened.events(first.order_id)) == 1
    with pytest.raises(OMSConflict, match="IDEMPOTENCY_CONFLICT"):
        await reopened.create(replace(request, quantity=Decimal("2")))
    await engine.dispose()


async def test_crash_after_durable_submit_marker_recovers_unknown_consistently(
    tmp_path: Path,
) -> None:
    database = tmp_path / "crash-between-submit-and-ack.db"
    ledger, engine = await _ledger(database)
    request = _request()
    created = await ledger.create(request)
    marked = await ledger.mark_submitting(
        created.order_id, _evidence(created.order_id, request)
    )
    assert marked.state is OrderState.SUBMITTING
    assert marked.submit_attempted is True
    await engine.dispose()

    reopened, engine = await _ledger(database)
    recovered = await reopened.recover_uncertain()

    assert len(recovered) == 1
    assert recovered[0].order_id == created.order_id
    assert recovered[0].state is OrderState.UNKNOWN_SUBMIT
    assert recovered[0].submit_attempted is True
    assert [event["code"] for event in await reopened.events(created.order_id)].count(
        "OUTBOUND_SUBMIT_COMMITTED"
    ) == 1
    with pytest.raises(OMSConflict, match="SUBMIT_ALREADY_ATTEMPTED"):
        await reopened.mark_submitting(
            created.order_id, _evidence(created.order_id, request)
        )
    await engine.dispose()


async def test_post_gtd_fill_and_discrepancy_are_durable(tmp_path: Path) -> None:
    database = tmp_path / "late-gtd-fill.db"
    ledger, engine = await _ledger(database)
    request = _request(tif="GTD", expiry=NOW)
    created = await ledger.create(request)
    await ledger.mark_submitting(created.order_id, _evidence(created.order_id, request))
    await ledger.mark_submit_result(created.order_id, OrderState.WORKING, "venue-1")
    expired = await ledger.record_observation(
        created.order_id,
        BrokerObservation(
            observation_id="gtd-expiry-observation",
            environment=request.environment,
            account_id=request.account_id,
            venue=request.venue,
            client_order_id=request.client_order_id,
            status=OrderState.EXPIRED,
            observed_at=NOW + timedelta(seconds=1),
            venue_order_id="venue-1",
        ),
    )
    assert expired.state is OrderState.EXPIRED
    fill = Fill(
        venue=request.venue,
        account_id=request.account_id,
        execution_id="gtd-execution-1",
        quantity=Decimal("1"),
        price=Decimal("1.10"),
        occurred_at=NOW + timedelta(seconds=2),
    )
    with pytest.raises(OMSConflict, match="FILL_AFTER_TERMINAL"):
        await ledger.record_fill(created.order_id, fill)
    await engine.dispose()

    reopened, engine = await _ledger(database)
    persisted = await reopened.get(created.order_id)
    assert persisted is not None
    assert persisted.filled_quantity == Decimal("1")
    assert persisted.state is OrderState.EXPIRED
    assert "FILL_AFTER_GTD" in persisted.discrepancies
    assert "FILL_AFTER_TERMINAL" in persisted.discrepancies
    assert "FILL_AFTER_GTD" in persisted.discrepancies
    await engine.dispose()


async def test_execution_ids_dedupe_and_conflicts_do_not_double_count(
    tmp_path: Path,
) -> None:
    ledger, engine = await _ledger(tmp_path / "execution-uniqueness.db")
    request = _request()
    first = await ledger.create(request)
    second_intent = "ledger-acceptance-2"
    second_request = replace(
        request,
        client_order_id=_CLIENT_ID_KEY.derive(request.account_id, second_intent, 1),
        intent_idempotency_key=second_intent,
        attempt=1,
    )
    other = await ledger.create(second_request)
    for order, order_request in ((first, request), (other, second_request)):
        await ledger.mark_submitting(order.order_id, _evidence(order.order_id, order_request))
        await ledger.mark_submit_result(
            order.order_id, OrderState.WORKING, f"venue-{order.order_id}"
        )
    fill = Fill(
        venue=request.venue,
        account_id=request.account_id,
        execution_id="unique-execution-1",
        quantity=Decimal("0.4"),
        price=Decimal("1.10"),
        occurred_at=NOW,
    )

    once = await ledger.record_fill(first.order_id, fill)
    duplicate = await ledger.record_fill(first.order_id, fill)

    assert duplicate.version == once.version
    assert duplicate.filled_quantity == Decimal("0.4")
    with pytest.raises(OMSConflict, match="EXECUTION_ID_CONFLICT"):
        await ledger.record_fill(other.order_id, fill)
    assert (await ledger.get(first.order_id)).filled_quantity == Decimal("0.4")
    await engine.dispose()


async def test_uncertain_close_preserves_fills_and_requires_broker_evidence(
    tmp_path: Path,
) -> None:
    ledger, engine = await _ledger(tmp_path / "uncertain-close.db")
    request = _request()
    created = await ledger.create(request)
    await ledger.mark_submitting(created.order_id, _evidence(created.order_id, request))
    await ledger.mark_submit_result(created.order_id, OrderState.WORKING, "venue-1")
    await ledger.record_fill(
        created.order_id,
        Fill(
            venue=request.venue,
            account_id=request.account_id,
            execution_id="open-execution-1",
            quantity=Decimal("0.25"),
            price=Decimal("1.10"),
            occurred_at=NOW,
        ),
    )
    await ledger.mark_cancel_pending(created.order_id)
    unknown = await ledger.mark_cancel_result(
        created.order_id, OrderState.UNKNOWN_CANCEL
    )

    assert unknown.state is OrderState.UNKNOWN_CANCEL
    assert unknown.filled_quantity == Decimal("0.25")
    assert unknown.cancel_attempted is True
    assert (await ledger.get(created.order_id)).filled_quantity == Decimal("0.25")
    await engine.dispose()


async def test_fill_correction_is_append_only_and_updates_derived_quantity(
    tmp_path: Path,
) -> None:
    ledger, engine = await _ledger(tmp_path / "fill-correction.db")
    request = _request()
    created = await ledger.create(request)
    await ledger.mark_submitting(created.order_id, _evidence(created.order_id, request))
    await ledger.mark_submit_result(created.order_id, OrderState.WORKING, "venue-1")
    original = Fill(
        venue=request.venue,
        account_id=request.account_id,
        execution_id="corrected-execution-1",
        quantity=Decimal("1"),
        price=Decimal("1.10"),
        occurred_at=NOW,
    )
    await ledger.record_fill(created.order_id, original)
    correction = FillCorrection(
        venue=request.venue,
        account_id=request.account_id,
        execution_id=original.execution_id,
        correction_id="correction-revision-1",
        revision=1,
        revised_quantity=Decimal("0.75"),
        revised_price=Decimal("1.11"),
        occurred_at=NOW + timedelta(seconds=1),
    )

    revised = await ledger.record_fill_correction(created.order_id, correction)

    assert revised.state is OrderState.FILLED
    assert revised.filled_quantity == Decimal("0.75")
    assert "FILL_CORRECTION" in revised.discrepancies
    assert await ledger.record_fill_correction(created.order_id, correction) == revised
    second_request = _request(client_order_id="after-filled-correction")
    second = await ledger.create(second_request)
    with pytest.raises(OMSValidationError, match="ACCOUNT_RECONCILE_REQUIRED"):
        await ledger.mark_submitting(second.order_id, _evidence(second.order_id, second_request))
    codes = [event["code"] for event in await ledger.events(created.order_id)]
    assert codes.count("BROKER_FILL") == 1
    assert codes.count("BROKER_FILL_CORRECTION") == 1
    await engine.dispose()


async def test_exact_fill_arithmetic_uses_kernel_precision_and_rejects_rounding(
    tmp_path: Path,
) -> None:
    ledger, engine = await _ledger(tmp_path / "exact-fill-arithmetic.db")
    request = replace(_request(), quantity=Decimal("0.3"))
    created = await ledger.create(request)
    await ledger.mark_submitting(created.order_id, _evidence(created.order_id, request))
    await ledger.mark_submit_result(created.order_id, OrderState.WORKING, "venue-1")

    with localcontext() as ambient:
        ambient.prec = 2
        ambient.rounding = ROUND_DOWN
        ambient.traps[Inexact] = True
        first = Fill(
            venue=request.venue,
            account_id=request.account_id,
            execution_id="exact-fill-1",
            quantity=Decimal("0.1"),
            price=Decimal("1.10"),
            occurred_at=NOW,
        )
        second = Fill(
            venue=request.venue,
            account_id=request.account_id,
            execution_id="exact-fill-2",
            quantity=Decimal("0.2"),
            price=Decimal("1.10"),
            occurred_at=NOW,
        )
        await ledger.record_fill(created.order_id, first)
        exact = await ledger.record_fill(created.order_id, second)
        assert exact.filled_quantity == request.quantity == Decimal("0.3")
        assert exact.state is OrderState.FILLED
        too_precise = Fill(
            venue=request.venue,
            account_id=request.account_id,
            execution_id="exact-fill-beyond-precision",
            quantity=Decimal("1e-35"),
            price=Decimal("1.10"),
            occurred_at=NOW,
        )
        with pytest.raises(OMSValidationError, match="PRECISION_EXCEEDED"):
            await ledger.record_fill(created.order_id, too_precise)

    after_rejected_result = await ledger.get(created.order_id)
    assert after_rejected_result is not None
    assert after_rejected_result.filled_quantity == Decimal("0.3")
    assert after_rejected_result.state is OrderState.FILLED
    await engine.dispose()


@pytest.mark.parametrize("conflict", ["fill_after_rejection", "rejection_after_partial_fill"])
async def test_rejection_fill_conflicts_quarantine_account(
    tmp_path: Path, conflict: str
) -> None:
    ledger, engine = await _ledger(tmp_path / f"{conflict}.db")
    request = _request(client_order_id=f"conflict-{conflict}")
    created = await ledger.create(request)
    await ledger.mark_submitting(created.order_id, _evidence(created.order_id, request))
    if conflict == "fill_after_rejection":
        rejected = await ledger.mark_submit_result(created.order_id, OrderState.REJECTED)
        assert rejected.state is OrderState.REJECTED
        try:
            await ledger.record_fill(
                created.order_id,
                Fill(
                venue=request.venue,
                account_id=request.account_id,
                execution_id=f"rejected-fill-{conflict}",
                quantity=Decimal("1"),
                price=Decimal("1.10"),
                occurred_at=NOW,
                ),
            )
        except OMSConflict as error:
            assert error.code == "FILL_AFTER_TERMINAL"
        expected_filled = Decimal("1")
    else:
        await ledger.mark_submit_result(created.order_id, OrderState.WORKING, "venue-1")
        partial = await ledger.record_fill(
            created.order_id,
            Fill(
                venue=request.venue,
                account_id=request.account_id,
                execution_id=f"partial-fill-{conflict}",
                quantity=Decimal("0.25"),
                price=Decimal("1.10"),
                occurred_at=NOW,
            ),
        )
        assert partial.state is OrderState.PARTIALLY_FILLED
        try:
            await ledger.record_observation(
                created.order_id,
                BrokerObservation(
                observation_id=f"rejected-after-partial-{conflict}",
                environment=request.environment,
                account_id=request.account_id,
                venue=request.venue,
                client_order_id=request.client_order_id,
                status=OrderState.REJECTED,
                observed_at=NOW + timedelta(seconds=1),
                venue_order_id="venue-1",
                ),
            )
        except OMSConflict as error:
            assert error.code == "REJECT_AFTER_FILL"
        expected_filled = Decimal("0.25")

    conflicted = await ledger.get(created.order_id)
    assert conflicted is not None
    expected_state = (
        OrderState.REJECTED
        if conflict == "fill_after_rejection"
        else OrderState.PARTIALLY_FILLED
    )
    expected_discrepancy = (
        "FILL_AFTER_TERMINAL"
        if conflict == "fill_after_rejection"
        else "REJECT_AFTER_FILL"
    )
    assert conflicted.state is expected_state
    assert conflicted.filled_quantity == expected_filled
    assert expected_discrepancy in conflicted.discrepancies

    second_request = _request(client_order_id=f"second-{conflict}")
    second = await ledger.create(second_request)
    with pytest.raises(OMSValidationError, match="ACCOUNT_RECONCILE_REQUIRED"):
        await ledger.mark_submitting(second.order_id, _evidence(second.order_id, second_request))
    assert (await ledger.get(second.order_id)).state is OrderState.RISK_REJECTED
    await engine.dispose()


async def test_stale_working_observation_cannot_resurrect_canceled_order(
    tmp_path: Path,
) -> None:
    ledger, engine = await _ledger(tmp_path / "stale-after-cancel.db")
    request = _request(client_order_id="stale-after-cancel")
    created = await ledger.create(request)
    await ledger.mark_submitting(created.order_id, _evidence(created.order_id, request))
    await ledger.mark_submit_result(created.order_id, OrderState.WORKING, "venue-1")
    canceled = await ledger.record_observation(
        created.order_id,
        BrokerObservation(
            observation_id="cancel-confirmed-at-1500",
            environment=request.environment,
            account_id=request.account_id,
            venue=request.venue,
            client_order_id=request.client_order_id,
            status=OrderState.CANCELED,
            observed_at=NOW,
            venue_order_id="venue-1",
        ),
    )
    assert canceled.state is OrderState.CANCELED

    stale = await ledger.record_observation(
        created.order_id,
        BrokerObservation(
            observation_id="working-observed-at-1459",
            environment=request.environment,
            account_id=request.account_id,
            venue=request.venue,
            client_order_id=request.client_order_id,
            status=OrderState.WORKING,
            observed_at=NOW - timedelta(minutes=1),
            venue_order_id="venue-1",
        ),
    )

    assert stale.state is canceled.state is OrderState.CANCELED
    events = await ledger.events(created.order_id)
    assert events[-1]["state"] == OrderState.CANCELED.value
    assert events[-1]["evidence"]["observation_id"] == "working-observed-at-1459"
    await engine.dispose()


@pytest.mark.parametrize(
    ("row_type", "field", "corrupt_value"),
    [
        ("correction", "revised_quantity", "-1"),
        ("fill", "price", "1E+100000"),
        ("fill", "commission", "-999"),
    ],
)
async def test_corrupt_stored_fill_or_correction_is_typed_and_blocks_account(
    tmp_path: Path, row_type: str, field: str, corrupt_value: str
) -> None:
    ledger, engine = await _ledger(tmp_path / f"corrupt-{field}.db")
    request = _request(client_order_id=f"corrupt-{field}")
    created = await ledger.create(request)
    await ledger.mark_submitting(created.order_id, _evidence(created.order_id, request))
    await ledger.mark_submit_result(created.order_id, OrderState.WORKING, "venue-1")
    fill = Fill(
        venue=request.venue,
        account_id=request.account_id,
        execution_id=f"corruption-source-{field}",
        quantity=Decimal("0.5"),
        price=Decimal("1.10"),
        occurred_at=NOW,
    )
    await ledger.record_fill(created.order_id, fill)
    correction = FillCorrection(
        venue=request.venue,
        account_id=request.account_id,
        execution_id=fill.execution_id,
        correction_id=f"corruption-correction-{field}",
        revision=1,
        revised_quantity=Decimal("0.4"),
        revised_price=Decimal("1.11"),
        occurred_at=NOW + timedelta(seconds=1),
        revised_commission=Decimal("0.01"),
    )
    await ledger.record_fill_correction(created.order_id, correction)
    second_request = _request(client_order_id=f"after-corrupt-{field}")
    second = await ledger.create(second_request)

    async with engine.begin() as connection:
        row_model = OmsFillCorrectionRow if row_type == "correction" else OmsFillRow
        result = await connection.execute(
            update(row_model)
            .where(row_model.order_id == created.order_id)
            .where(row_model.execution_id == fill.execution_id)
            .values(**{field: corrupt_value})
        )
        assert result.rowcount == 1

    with pytest.raises(OMSLedgerCorruption) as corruption:
        await ledger.get(created.order_id)
    assert corruption.value.code == "OMS_LEDGER_CORRUPT"
    assert corruption.value.args == ("OMS_LEDGER_CORRUPT",)
    assert str(corruption.value) == "OMS_LEDGER_CORRUPT"

    with pytest.raises(OMSLedgerCorruption) as blocked:
        await ledger.mark_submitting(second.order_id, _evidence(second.order_id, second_request))
    assert blocked.value.code == "OMS_LEDGER_CORRUPT"
    await engine.dispose()


async def test_persisted_valid_decimal_overfill_is_corruption_and_blocks_account(
    tmp_path: Path,
) -> None:
    database = tmp_path / "persisted-overfill-corruption.db"
    ledger, engine = await _ledger(database)
    request = _request(client_order_id="persisted-overfill-corruption")
    created = await ledger.create(request)
    await ledger.mark_submitting(created.order_id, _evidence(created.order_id, request))
    await ledger.mark_submit_result(created.order_id, OrderState.WORKING, "venue-overfill")
    fill = Fill(
        venue=request.venue,
        account_id=request.account_id,
        execution_id="stored-valid-overfill",
        quantity=Decimal("0.25"),
        price=Decimal("1.10"),
        occurred_at=NOW,
    )
    await ledger.record_fill(created.order_id, fill)
    second_request = _request(client_order_id="after-persisted-overfill")
    second = await ledger.create(second_request)

    async with engine.begin() as connection:
        result = await connection.execute(
            update(OmsFillRow)
            .where(OmsFillRow.order_id == created.order_id)
            .where(OmsFillRow.execution_id == fill.execution_id)
            .values(quantity="2")
        )
        assert result.rowcount == 1
    await engine.dispose()

    reopened, engine = await _ledger(database)
    with pytest.raises(OMSLedgerCorruption) as corruption:
        await reopened.get(created.order_id)
    assert corruption.value.code == "OMS_LEDGER_CORRUPT"
    assert corruption.value.args == ("OMS_LEDGER_CORRUPT",)
    assert str(corruption.value) == "OMS_LEDGER_CORRUPT"

    with pytest.raises(OMSLedgerCorruption, match="OMS_LEDGER_CORRUPT"):
        await reopened.mark_submitting(
            second.order_id, _evidence(second.order_id, second_request)
        )
    await engine.dispose()


async def test_exactly_recorded_overfill_is_visible_and_quarantines_account(
    tmp_path: Path,
) -> None:
    database = tmp_path / "recorded-overfill.db"
    ledger, engine = await _ledger(database)
    request = _request(client_order_id="recorded-overfill")
    created = await ledger.create(request)
    await ledger.mark_submitting(created.order_id, _evidence(created.order_id, request))
    await ledger.mark_submit_result(created.order_id, OrderState.WORKING, "venue-recorded-overfill")
    recorded = await ledger.record_fill(
        created.order_id,
        Fill(
            venue=request.venue,
            account_id=request.account_id,
            execution_id="recorded-overfill-fill",
            quantity=Decimal("1.25"),
            price=Decimal("1.10"),
            occurred_at=NOW,
        ),
    )
    await engine.dispose()

    reopened, engine = await _ledger(database)
    replayed = await reopened.get(created.order_id)
    assert replayed is not None
    assert replayed.state is OrderState.RECONCILE_REQUIRED
    assert replayed.filled_quantity == Decimal("1.25")
    assert "OVERFILL" in replayed.discrepancies
    assert recorded.discrepancies == replayed.discrepancies
    fill_event = next(
        event
        for event in await reopened.events(created.order_id)
        if event["code"] == "BROKER_FILL"
    )
    assert fill_event["evidence"]["overfill_excess"] == "0.25"

    second_request = _request(client_order_id="after-recorded-overfill")
    second = await reopened.create(second_request)
    with pytest.raises(OMSValidationError, match="ACCOUNT_RECONCILE_REQUIRED"):
        await reopened.mark_submitting(
            second.order_id, _evidence(second.order_id, second_request)
        )
    await engine.dispose()


async def test_mismatched_recorded_overfill_excess_is_corruption(
    tmp_path: Path,
) -> None:
    database = tmp_path / "mismatched-overfill-evidence.db"
    ledger, engine = await _ledger(database)
    request = _request(client_order_id="mismatched-overfill-evidence")
    created = await ledger.create(request)
    await ledger.mark_submitting(created.order_id, _evidence(created.order_id, request))
    await ledger.mark_submit_result(created.order_id, OrderState.WORKING, "venue-mismatch-overfill")
    await ledger.record_fill(
        created.order_id,
        Fill(
            venue=request.venue,
            account_id=request.account_id,
            execution_id="mismatched-overfill-fill",
            quantity=Decimal("1.25"),
            price=Decimal("1.10"),
            occurred_at=NOW,
        ),
    )
    second_request = _request(client_order_id="after-mismatched-overfill")
    second = await ledger.create(second_request)

    async with engine.begin() as connection:
        event_result = await connection.execute(
            select(OmsEventRow.id, OmsEventRow.evidence).where(
                OmsEventRow.order_id == created.order_id,
                OmsEventRow.code == "BROKER_FILL",
            )
        )
        event = event_result.first()
        assert event is not None
        event_id, event_evidence = event
        tampered = {**event_evidence, "overfill_excess": "0.24"}
        result = await connection.execute(
            update(OmsEventRow)
            .where(OmsEventRow.id == event_id)
            .values(evidence=tampered)
        )
        assert result.rowcount == 1
    await engine.dispose()

    reopened, engine = await _ledger(database)
    with pytest.raises(OMSLedgerCorruption) as corruption:
        await reopened.get(created.order_id)
    assert corruption.value.code == "OMS_LEDGER_CORRUPT"

    with pytest.raises(OMSLedgerCorruption, match="OMS_LEDGER_CORRUPT"):
        await reopened.mark_submitting(
            second.order_id, _evidence(second.order_id, second_request)
        )
    await engine.dispose()


async def test_malformed_persisted_observation_is_corruption_and_blocks_account(
    tmp_path: Path,
) -> None:
    database = tmp_path / "persisted-observation-corruption.db"
    ledger, engine = await _ledger(database)
    request = _request(client_order_id="persisted-observation-corruption")
    created = await ledger.create(request)
    await ledger.mark_submitting(created.order_id, _evidence(created.order_id, request))
    await ledger.mark_submit_result(created.order_id, OrderState.WORKING, "venue-observation")
    observation = BrokerObservation(
        observation_id="stored-valid-observation",
        environment=request.environment,
        account_id=request.account_id,
        venue=request.venue,
        client_order_id=request.client_order_id,
        status=OrderState.WORKING,
        observed_at=NOW,
        venue_order_id="venue-observation",
    )
    await ledger.record_observation(created.order_id, observation)
    second_request = _request(client_order_id="after-persisted-observation")
    second = await ledger.create(second_request)
    malformed = observation.payload()
    malformed["status"] = "NOT_A_BROKER_STATUS"

    async with engine.begin() as connection:
        result = await connection.execute(
            update(OmsObservationRow)
            .where(OmsObservationRow.order_id == created.order_id)
            .where(OmsObservationRow.observation_id == observation.observation_id)
            .values(evidence=malformed)
        )
        assert result.rowcount == 1
    await engine.dispose()

    reopened, engine = await _ledger(database)
    with pytest.raises(OMSLedgerCorruption) as corruption:
        await reopened.get(created.order_id)
    assert corruption.value.code == "OMS_LEDGER_CORRUPT"
    assert corruption.value.args == ("OMS_LEDGER_CORRUPT",)
    assert str(corruption.value) == "OMS_LEDGER_CORRUPT"

    with pytest.raises(OMSLedgerCorruption, match="OMS_LEDGER_CORRUPT"):
        await reopened.mark_submitting(
            second.order_id, _evidence(second.order_id, second_request)
        )
    await engine.dispose()


@pytest.mark.parametrize("table", ["order", "event", "fill", "correction", "observation"])
async def test_each_persisted_oms_table_replay_corruption_blocks_account(
    tmp_path: Path, table: str
) -> None:
    database = tmp_path / f"replay-corruption-{table}.db"
    ledger, engine = await _ledger(database)
    request = _request(client_order_id=f"replay-corruption-{table}")
    created = await ledger.create(request)
    await ledger.mark_submitting(created.order_id, _evidence(created.order_id, request))
    await ledger.mark_submit_result(created.order_id, OrderState.WORKING, "venue-replay")
    observation = BrokerObservation(
        observation_id=f"valid-observation-{table}",
        environment=request.environment,
        account_id=request.account_id,
        venue=request.venue,
        client_order_id=request.client_order_id,
        status=OrderState.WORKING,
        observed_at=NOW,
        venue_order_id="venue-replay",
    )
    await ledger.record_observation(created.order_id, observation)
    fill = Fill(
        venue=request.venue,
        account_id=request.account_id,
        execution_id=f"valid-fill-{table}",
        quantity=Decimal("0.25"),
        price=Decimal("1.10"),
        occurred_at=NOW + timedelta(seconds=1),
    )
    await ledger.record_fill(created.order_id, fill)
    second_request = _request(client_order_id=f"after-replay-corruption-{table}")
    second = await ledger.create(second_request)

    async with engine.begin() as connection:
        if table == "order":
            result = await connection.execute(
                update(OmsOrderRow)
                .where(OmsOrderRow.order_id == created.order_id)
                .values(request_digest="0" * 64)
            )
        elif table == "event":
            result = await connection.execute(
                update(OmsEventRow)
                .where(OmsEventRow.order_id == created.order_id)
                .where(OmsEventRow.sequence == 1)
                .values(sequence=99)
            )
        elif table == "fill":
            result = await connection.execute(
                update(OmsFillRow)
                .where(OmsFillRow.order_id == created.order_id)
                .where(OmsFillRow.execution_id == fill.execution_id)
                .values(account_id="foreign-account")
            )
        elif table == "correction":
            result = await connection.execute(
                insert(OmsFillCorrectionRow).values(
                    order_id=created.order_id,
                    venue=request.venue,
                    account_id=request.account_id,
                    execution_id="missing-original-execution",
                    correction_id="orphan-correction",
                    revision=1,
                    revised_quantity="0.10",
                    revised_price="1.11",
                    revised_commission="0",
                    occurred_at=NOW + timedelta(seconds=2),
                )
            )
        else:
            mismatched = observation.payload()
            mismatched["client_order_id"] = "different-client-order"
            result = await connection.execute(
                update(OmsObservationRow)
                .where(OmsObservationRow.order_id == created.order_id)
                .where(OmsObservationRow.observation_id == observation.observation_id)
                .values(evidence=mismatched)
            )
        assert result.rowcount == 1
    await engine.dispose()

    reopened, engine = await _ledger(database)
    with pytest.raises(OMSLedgerCorruption) as corruption:
        await reopened.get(created.order_id)
    assert corruption.value.code == "OMS_LEDGER_CORRUPT"
    assert corruption.value.args == ("OMS_LEDGER_CORRUPT",)
    assert str(corruption.value) == "OMS_LEDGER_CORRUPT"
    with pytest.raises(OMSLedgerCorruption, match="OMS_LEDGER_CORRUPT"):
        await reopened.mark_submitting(
            second.order_id, _evidence(second.order_id, second_request)
        )
    await engine.dispose()


@pytest.mark.parametrize("table", ["order", "event", "fill", "correction", "observation"])
async def test_valid_value_mutation_in_each_oms_table_breaks_authenticated_chain(
    tmp_path: Path, table: str
) -> None:
    database = tmp_path / f"valid-value-chain-tamper-{table}.db"
    ledger, engine, _request_value, order_id, fill, correction, observation = (
        await _seed_integrity_rows(database, f"valid-value-{table}")
    )
    second_request = _request(client_order_id=f"after-valid-chain-tamper-{table}")
    second = await ledger.create(second_request)

    async with engine.begin() as connection:
        if table == "order":
            result = await connection.execute(
                update(OmsOrderRow)
                .where(OmsOrderRow.order_id == order_id)
                .values(state=OrderState.WORKING.value)
            )
        elif table == "event":
            result = await connection.execute(
                update(OmsEventRow)
                .where(OmsEventRow.order_id == order_id)
                .where(OmsEventRow.code == "ORDER_CREATED")
                .values(code="RISK_CHECK_STARTED")
            )
        elif table == "fill":
            result = await connection.execute(
                update(OmsFillRow)
                .where(OmsFillRow.order_id == order_id)
                .where(OmsFillRow.execution_id == fill.execution_id)
                .values(price="1.12")
            )
        elif table == "correction":
            result = await connection.execute(
                update(OmsFillCorrectionRow)
                .where(OmsFillCorrectionRow.order_id == order_id)
                .where(OmsFillCorrectionRow.correction_id == correction.correction_id)
                .values(revised_quantity="0.30")
            )
        else:
            result = await connection.execute(
                update(OmsObservationRow)
                .where(OmsObservationRow.order_id == order_id)
                .where(OmsObservationRow.observation_id == observation.observation_id)
                .values(evidence={**observation.payload(), "status": OrderState.CANCELED.value})
            )
        assert result.rowcount == 1
    await engine.dispose()

    reopened, engine = await _ledger(database)
    with pytest.raises(OMSLedgerCorruption) as corruption:
        await reopened.get(order_id)
    assert corruption.value.code == "OMS_LEDGER_CORRUPT"
    assert corruption.value.args == ("OMS_LEDGER_CORRUPT",)
    assert str(corruption.value) == "OMS_LEDGER_CORRUPT"
    with pytest.raises(OMSLedgerCorruption, match="OMS_LEDGER_CORRUPT"):
        await reopened.mark_submitting(
            second.order_id, _evidence(second.order_id, second_request)
        )
    await engine.dispose()


@pytest.mark.parametrize("tamper", ["delete", "reorder", "truncate-tail"])
async def test_deleted_reordered_or_truncated_chain_row_fails_closed(
    tmp_path: Path, tamper: str
) -> None:
    database = tmp_path / f"chain-{tamper}.db"
    ledger, engine, _request_value, order_id, _fill, _correction, _observation = (
        await _seed_integrity_rows(database, f"chain-{tamper}")
    )
    second_request = _request(client_order_id=f"after-chain-{tamper}")
    second = await ledger.create(second_request)
    child_models = (
        OmsEventRow,
        OmsFillRow,
        OmsFillCorrectionRow,
        OmsObservationRow,
    )

    async with engine.begin() as connection:
        if tamper == "delete":
            result = await connection.execute(
                delete(OmsObservationRow)
                .where(OmsObservationRow.order_id == order_id)
            )
            assert result.rowcount == 1
        elif tamper == "reorder":
            first_two = (
                await connection.execute(
                    select(OmsEventRow.id, OmsEventRow.ledger_sequence)
                    .where(OmsEventRow.order_id == order_id)
                    .order_by(OmsEventRow.ledger_sequence)
                    .limit(2)
                )
            ).all()
            assert len(first_two) == 2
            (first_id, first_sequence), (second_id, second_sequence) = first_two
            temporary = max(first_sequence, second_sequence) + 10_000
            await connection.execute(
                update(OmsEventRow).where(OmsEventRow.id == first_id).values(
                    ledger_sequence=temporary
                )
            )
            await connection.execute(
                update(OmsEventRow).where(OmsEventRow.id == second_id).values(
                    ledger_sequence=first_sequence
                )
            )
            result = await connection.execute(
                update(OmsEventRow).where(OmsEventRow.id == first_id).values(
                    ledger_sequence=second_sequence
                )
            )
            assert result.rowcount == 1
        else:
            child_rows = []
            for model in child_models:
                child_rows.extend(
                    (model, row_id, sequence)
                    for row_id, sequence in (
                        await connection.execute(
                            select(model.id, model.ledger_sequence)
                            .where(model.order_id == order_id)
                        )
                    ).all()
                )
            assert child_rows
            model, row_id, highest_sequence = max(child_rows, key=lambda item: item[2])
            result = await connection.execute(
                delete(model).where(model.id == row_id)
            )
            assert result.rowcount == 1
            assert highest_sequence > 0
    await engine.dispose()

    reopened, engine = await _ledger(database)
    with pytest.raises(OMSLedgerCorruption) as corruption:
        await reopened.get(order_id)
    assert corruption.value.code == "OMS_LEDGER_CORRUPT"
    with pytest.raises(OMSLedgerCorruption, match="OMS_LEDGER_CORRUPT"):
        await reopened.mark_submitting(
            second.order_id, _evidence(second.order_id, second_request)
        )
    await engine.dispose()


@pytest.mark.parametrize(
    "tamper",
    [
        "order_chain",
        "event_sequence",
        "event_chain",
        "fill_sequence",
        "fill_chain",
        "correction_sequence",
        "correction_chain",
        "observation_sequence",
        "observation_chain",
        "head_sequence_count",
        "head_chain",
        "head_order_cache_digest",
        "head_order_count",
        "head_anchor",
        "head_updated_at",
    ],
)
async def test_valid_chain_and_head_column_mutation_is_corruption(
    tmp_path: Path, tamper: str
) -> None:
    database = tmp_path / f"chain-metadata-tamper-{tamper}.db"
    ledger, engine, request, order_id, _fill, _correction, _observation = (
        await _seed_integrity_rows(database, f"chain-metadata-{tamper}")
    )
    second_request = _request(client_order_id=f"after-metadata-tamper-{tamper}")
    second = await ledger.create(second_request)

    async with engine.begin() as connection:
        if tamper == "order_chain":
            statement = (
                update(OmsOrderRow)
                .where(OmsOrderRow.order_id == order_id)
                .values(chain="4" * 64)
            )
        elif tamper.startswith("head_"):
            values: dict[str, object]
            if tamper == "head_sequence_count":
                values = {"sequence_count": 99}
            elif tamper == "head_chain":
                values = {"head_chain": "1" * 64}
            elif tamper == "head_order_cache_digest":
                values = {"order_cache_digest": "2" * 64}
            elif tamper == "head_order_count":
                values = {"order_count": 99}
            elif tamper == "head_anchor":
                values = {"anchor": "3" * 64}
            else:
                values = {"updated_at": NOW + timedelta(days=1)}
            statement = (
                update(OmsLedgerHeadRow)
                .where(OmsLedgerHeadRow.environment == request.environment)
                .where(OmsLedgerHeadRow.account_id == request.account_id)
                .values(**values)
            )
        else:
            row_type = {
                "event": OmsEventRow,
                "fill": OmsFillRow,
                "correction": OmsFillCorrectionRow,
                "observation": OmsObservationRow,
            }[tamper.split("_", maxsplit=1)[0]]
            row_id = await connection.scalar(
                select(row_type.id)
                .where(row_type.order_id == order_id)
                .order_by(row_type.ledger_sequence)
                .limit(1)
            )
            assert row_id is not None
            if tamper.endswith("_sequence"):
                statement = (
                    update(row_type)
                    .where(row_type.id == row_id)
                    .values(ledger_sequence=10_000)
                )
            else:
                statement = (
                    update(row_type)
                    .where(row_type.id == row_id)
                    .values(chain="5" * 64)
                )
        result = await connection.execute(statement)
        assert result.rowcount == 1
    await engine.dispose()

    reopened, engine = await _ledger(database)
    with pytest.raises(OMSLedgerCorruption) as corruption:
        await reopened.get(order_id)
    assert corruption.value.code == "OMS_LEDGER_CORRUPT"
    assert corruption.value.args == ("OMS_LEDGER_CORRUPT",)
    assert str(corruption.value) == "OMS_LEDGER_CORRUPT"
    with pytest.raises(OMSLedgerCorruption, match="OMS_LEDGER_CORRUPT"):
        await reopened.mark_submitting(
            second.order_id, _evidence(second.order_id, second_request)
        )
    await engine.dispose()


async def test_missing_integrity_key_fails_closed_on_ledger_read(tmp_path: Path) -> None:
    database = tmp_path / "missing-ledger-key.db"
    keyed, engine = await _ledger(database)
    request = _request(client_order_id="integrity-key-fixture")
    created = await keyed.create(request)
    await engine.dispose()

    engine, sessions = create_engine_and_sessionmaker(f"sqlite+aiosqlite:///{database}")
    await init_schema(engine)
    keyless = OrderLedger(sessions)
    with pytest.raises(OMSLedgerCorruption) as corruption:
        await keyless.get(created.order_id)
    assert corruption.value.code == "OMS_LEDGER_CORRUPT"
    assert corruption.value.args == ("OMS_LEDGER_CORRUPT",)
    assert str(corruption.value) == "OMS_LEDGER_CORRUPT"
    await engine.dispose()
