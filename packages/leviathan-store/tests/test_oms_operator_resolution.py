"""Store-owned validation for append-only venue-conflict resolution rows."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from leviathan_store.oms_ledger import OrderLedger
from leviathan_store.oms_operator_resolution import OmsOperatorResolutionRow

from leviathan_core.execution.order_models import OMSLedgerCorruption


def _row() -> OmsOperatorResolutionRow:
    return OmsOperatorResolutionRow(
        resolution_id="a" * 64,
        environment="paper",
        account_id="ops-resolution-account",
        conflict_id="b" * 64,
        binding_venue="ALPACA",
        binding_environment="paper",
        observation_ids=["observation-1", "observation-2"],
        identity_digest="c" * 64,
        idempotency_digest="d" * 64,
        operator_principal_id="operator.synthetic",
        reason_code="BINDING_VERIFIED",
        broker_revision=7,
        broker_evidence_digest="e" * 64,
        prior_ledger_revision=12,
        resolved_at_ns=1_799_000_000_000_000_000,
        affected_order_ids=["order-1", "order-2"],
        ledger_sequence=13,
        chain="f" * 64,
        recorded_at=datetime(2026, 10, 6, tzinfo=UTC),
    )


def test_resolution_row_validates_account_venue_and_observation_identity() -> None:
    OrderLedger._validate_operator_resolution_row(_row())


@pytest.mark.parametrize(
    "field,value",
    [
        ("binding_venue", ""),
        ("binding_environment", "LIVE"),
        ("observation_ids", []),
        ("observation_ids", ["observation-2", "observation-1"]),
        ("identity_digest", "not-a-digest"),
        ("affected_order_ids", ["order-1", "order-1"]),
    ],
)
def test_resolution_row_rejects_invalid_identity_fields(field: str, value: object) -> None:
    row = _row()
    setattr(row, field, value)
    with pytest.raises(OMSLedgerCorruption):
        OrderLedger._validate_operator_resolution_row(row)
