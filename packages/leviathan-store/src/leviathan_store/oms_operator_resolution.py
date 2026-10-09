"""Append-only, account-chain-sealed OMS operator resolution records."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from leviathan_store.tables import StoreBase


class OmsOperatorResolutionRow(StoreBase):
    """Content-free proof that one exact venue conflict was operator-resolved."""

    __tablename__ = "oms_operator_resolutions"
    __table_args__ = (
        UniqueConstraint("environment", "account_id", "idempotency_digest"),
        UniqueConstraint("environment", "account_id", "ledger_sequence"),
    )

    resolution_id: Mapped[str] = mapped_column(String, primary_key=True)
    environment: Mapped[str] = mapped_column(String, index=True)
    account_id: Mapped[str] = mapped_column(String, index=True)
    conflict_id: Mapped[str] = mapped_column(String)
    binding_venue: Mapped[str] = mapped_column(String)
    binding_environment: Mapped[str] = mapped_column(String)
    observation_ids: Mapped[list[str]] = mapped_column(JSON)
    identity_digest: Mapped[str] = mapped_column(String)
    idempotency_digest: Mapped[str] = mapped_column(String)
    operator_principal_id: Mapped[str] = mapped_column(String)
    reason_code: Mapped[str] = mapped_column(String)
    broker_revision: Mapped[int] = mapped_column(Integer)
    broker_evidence_digest: Mapped[str] = mapped_column(String)
    prior_ledger_revision: Mapped[int] = mapped_column(Integer)
    resolved_at_ns: Mapped[int] = mapped_column(Integer)
    affected_order_ids: Mapped[list[str]] = mapped_column(JSON)
    ledger_sequence: Mapped[int | None] = mapped_column(Integer, nullable=True)
    chain: Mapped[str | None] = mapped_column(String, nullable=True)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


def resolution_table() -> Any:
    """Expose the migration target without exporting ledger write methods."""
    return OmsOperatorResolutionRow.__table__
