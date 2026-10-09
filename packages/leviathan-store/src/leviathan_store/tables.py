"""SQLAlchemy 2.0 table definitions for LEVIATHAN persistence.

Every Layer-1 contract is stored twice over: the full frozen pydantic
object lives in a ``payload`` JSON column (the source of truth for
round-trips), while a handful of scalar columns are lifted out for
indexing and cheap querying. Decimals are serialised as strings inside
the JSON payload (``model_dump(mode="json")``) so no precision is lost
crossing the SQLite/Postgres boundary.

Column types are deliberately dialect-portable — ``String``,
``Numeric``, ``DateTime(timezone=True)``, ``JSON``, ``Integer``,
``Boolean`` — so the same schema stands up unchanged on aiosqlite today
and TimescaleDB once Docker lands.

Three tables are append-only ledgers: ``genome_validations``,
``journal_records``, and ``risk_verdicts``. Their repositories expose no
update or delete methods; history is never rewritten, only extended.
"""

from datetime import datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    Numeric,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class StoreBase(DeclarativeBase):
    """Declarative base for every LEVIATHAN persistence table."""


class GenomeRow(StoreBase):
    """Mutable current-state row for a strategy genome (upsert target)."""

    __tablename__ = "genomes"

    strategy_id: Mapped[str] = mapped_column(String, primary_key=True)
    family: Mapped[str] = mapped_column(String, index=True)
    market: Mapped[str] = mapped_column(String, index=True)
    timeframe: Mapped[str] = mapped_column(String, index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class GenomeValidationRow(StoreBase):
    """Append-only validation ledger for a genome's RBI stages."""

    __tablename__ = "genome_validations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    strategy_id: Mapped[str] = mapped_column(String, index=True)  # references genomes.strategy_id
    stage: Mapped[str] = mapped_column(String, index=True)
    passed: Mapped[bool] = mapped_column(Boolean)
    metrics: Mapped[dict[str, Any]] = mapped_column(JSON)
    validated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class SetupRow(StoreBase):
    """Candidate setup evidence entering the pipeline."""

    __tablename__ = "setups"

    setup_id: Mapped[str] = mapped_column(String, primary_key=True)
    instrument: Mapped[str] = mapped_column(String, index=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)


class DecisionRow(StoreBase):
    """Decision Domain output — capital permission, not prediction."""

    __tablename__ = "decisions"

    decision_id: Mapped[str] = mapped_column(String, primary_key=True)
    setup_id: Mapped[str] = mapped_column(String, index=True)
    permission: Mapped[str] = mapped_column(String, index=True)
    direction: Mapped[str] = mapped_column(String)
    confidence: Mapped[float] = mapped_column(Numeric(6, 5))
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class JournalRow(StoreBase):
    """Append-only post-trade record. Every trade ends here."""

    __tablename__ = "journal_records"

    trade_id: Mapped[str] = mapped_column(String, primary_key=True)
    setup_id: Mapped[str] = mapped_column(String, index=True)
    decision_id: Mapped[str] = mapped_column(String, index=True)
    outcome: Mapped[str] = mapped_column(String, index=True)
    entry: Mapped[Decimal | None] = mapped_column(Numeric(18, 6), nullable=True)
    exit: Mapped[Decimal | None] = mapped_column(Numeric(18, 6), nullable=True)
    mae: Mapped[Decimal | None] = mapped_column(Numeric(18, 6), nullable=True)
    mfe: Mapped[Decimal | None] = mapped_column(Numeric(18, 6), nullable=True)
    notes: Mapped[str] = mapped_column(String, default="")
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class RiskVerdictRow(StoreBase):
    """Append-only sovereign risk verdict ledger."""

    __tablename__ = "risk_verdicts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    decision_id: Mapped[str] = mapped_column(String, index=True)
    action: Mapped[str] = mapped_column(String, index=True)
    reason: Mapped[str] = mapped_column(String)
    adjusted_size: Mapped[Decimal | None] = mapped_column(Numeric(18, 6), nullable=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class RouteAttemptRow(StoreBase):
    """C-101 authoritative lifecycle; one row and one terminal outcome per decision."""

    __tablename__ = "route_attempts"

    decision_id: Mapped[str] = mapped_column(String, primary_key=True)
    setup_id: Mapped[str] = mapped_column(String, index=True)
    state: Mapped[str] = mapped_column(String, index=True)
    version: Mapped[int] = mapped_column(Integer)
    schema_version: Mapped[int] = mapped_column(Integer)
    assessment: Mapped[dict[str, Any]] = mapped_column(JSON)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON)
    authorization: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    paper_draft: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    policy_digest: Mapped[str] = mapped_column(String)
    claim_token: Mapped[str | None] = mapped_column(String, nullable=True)
    outcome: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    final_verdict: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    journal_record: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class SchemaMigrationRow(StoreBase):
    """Applied additive schema steps; checked again at every bootstrap."""

    __tablename__ = "schema_migrations"

    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String)
    applied_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class McpAuditRow(StoreBase):
    """Append-only MCP audit event authenticated by the local HMAC chain."""

    __tablename__ = "mcp_audit_events"
    __table_args__ = (UniqueConstraint("event_id"),)

    sequence: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_id: Mapped[str] = mapped_column(String)
    event_json: Mapped[str] = mapped_column(String)
    scope_project_id: Mapped[str] = mapped_column(String)
    scope_environment: Mapped[str] = mapped_column(String)
    previous_mac: Mapped[str] = mapped_column(String)
    row_mac: Mapped[str] = mapped_column(String)


class McpAuditHeadRow(StoreBase):
    """Durable authenticated tail checkpoint for one configured MCP scope."""

    __tablename__ = "mcp_audit_heads"

    store_id: Mapped[str] = mapped_column(String, primary_key=True)
    scope_project_id: Mapped[str] = mapped_column(String)
    scope_environment: Mapped[str] = mapped_column(String)
    sequence_count: Mapped[int] = mapped_column(Integer)
    chain_tip: Mapped[str] = mapped_column(String)
    checkpoint_mac: Mapped[str] = mapped_column(String)


class OmegaTaskRow(StoreBase):
    """Authenticated durable snapshot for one peer-owned OMEGA task."""

    __tablename__ = "omega_tasks"
    __table_args__ = (
        UniqueConstraint("peer_system", "idempotency_key"),
    )

    peer_system: Mapped[str] = mapped_column(String, primary_key=True)
    task_id: Mapped[str] = mapped_column(String, primary_key=True)
    state: Mapped[str] = mapped_column(String, index=True)
    expires_at_ns: Mapped[int] = mapped_column(Integer, index=True)
    sla_due_at_ns: Mapped[int] = mapped_column(Integer, index=True)
    revision: Mapped[int] = mapped_column(Integer)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)
    row_hmac: Mapped[str] = mapped_column(String)
    idempotency_key: Mapped[str | None] = mapped_column(String, nullable=True)
    request_digest: Mapped[str | None] = mapped_column(String, nullable=True)
    idempotency_expires_at_ns: Mapped[int | None] = mapped_column(Integer, nullable=True)


class OmsOrderRow(StoreBase):
    """Current OMS view; history is retained in the event/fill ledgers below."""

    __tablename__ = "oms_orders"
    __table_args__ = (
        UniqueConstraint("environment", "account_id", "client_order_id"),
        UniqueConstraint("venue", "account_id", "venue_order_id"),
    )

    order_id: Mapped[str] = mapped_column(String, primary_key=True)
    environment: Mapped[str] = mapped_column(String)
    account_id: Mapped[str] = mapped_column(String)
    venue: Mapped[str] = mapped_column(String)
    client_order_id: Mapped[str] = mapped_column(String)
    venue_order_id: Mapped[str | None] = mapped_column(String, nullable=True)
    root_order_id: Mapped[str | None] = mapped_column(String, nullable=True)
    parent_order_id: Mapped[str | None] = mapped_column(String, nullable=True)
    request_digest: Mapped[str] = mapped_column(String)
    request: Mapped[dict[str, Any]] = mapped_column(JSON)
    state: Mapped[str] = mapped_column(String, index=True)
    version: Mapped[int] = mapped_column(Integer)
    submit_attempted: Mapped[bool] = mapped_column(Boolean)
    cancel_attempted: Mapped[bool] = mapped_column(Boolean)
    discrepancies: Mapped[list[str]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    chain: Mapped[str | None] = mapped_column(String, nullable=True)


class OmsEventRow(StoreBase):
    """Append-only sequenced order state and audit evidence."""

    __tablename__ = "oms_order_events"
    __table_args__ = (UniqueConstraint("order_id", "sequence"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    order_id: Mapped[str] = mapped_column(
        String, ForeignKey("oms_orders.order_id", ondelete="RESTRICT"), index=True
    )
    sequence: Mapped[int] = mapped_column(Integer)
    state: Mapped[str] = mapped_column(String)
    code: Mapped[str] = mapped_column(String)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    ledger_sequence: Mapped[int | None] = mapped_column(Integer, nullable=True)
    chain: Mapped[str | None] = mapped_column(String, nullable=True)


class OmsFillRow(StoreBase):
    """Immutable executions keyed by broker identity, never by callback count."""

    __tablename__ = "oms_fills"
    __table_args__ = (UniqueConstraint("venue", "account_id", "execution_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    order_id: Mapped[str] = mapped_column(
        String, ForeignKey("oms_orders.order_id", ondelete="RESTRICT"), index=True
    )
    venue: Mapped[str] = mapped_column(String)
    account_id: Mapped[str] = mapped_column(String)
    execution_id: Mapped[str] = mapped_column(String)
    quantity: Mapped[str] = mapped_column(String)
    price: Mapped[str] = mapped_column(String)
    commission: Mapped[str] = mapped_column(String)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    ledger_sequence: Mapped[int | None] = mapped_column(Integer, nullable=True)
    chain: Mapped[str | None] = mapped_column(String, nullable=True)


class OmsObservationRow(StoreBase):
    """Append-only broker evidence used for reconciliation."""

    __tablename__ = "oms_observations"
    __table_args__ = (UniqueConstraint("venue", "account_id", "observation_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    order_id: Mapped[str] = mapped_column(
        String, ForeignKey("oms_orders.order_id", ondelete="RESTRICT"), index=True
    )
    venue: Mapped[str] = mapped_column(String)
    account_id: Mapped[str] = mapped_column(String)
    observation_id: Mapped[str] = mapped_column(String)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    ledger_sequence: Mapped[int | None] = mapped_column(Integer, nullable=True)
    chain: Mapped[str | None] = mapped_column(String, nullable=True)


class OmsFillCorrectionRow(StoreBase):
    """Versioned immutable revisions; an execution is never deleted on bust."""

    __tablename__ = "oms_fill_corrections"
    __table_args__ = (
        UniqueConstraint("venue", "account_id", "execution_id", "revision"),
        UniqueConstraint("venue", "account_id", "correction_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    order_id: Mapped[str] = mapped_column(
        String, ForeignKey("oms_orders.order_id", ondelete="RESTRICT"), index=True
    )
    venue: Mapped[str] = mapped_column(String)
    account_id: Mapped[str] = mapped_column(String)
    execution_id: Mapped[str] = mapped_column(String)
    correction_id: Mapped[str] = mapped_column(String)
    revision: Mapped[int] = mapped_column(Integer)
    revised_quantity: Mapped[str] = mapped_column(String)
    revised_price: Mapped[str | None] = mapped_column(String, nullable=True)
    revised_commission: Mapped[str] = mapped_column(String)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    ledger_sequence: Mapped[int | None] = mapped_column(Integer, nullable=True)
    chain: Mapped[str | None] = mapped_column(String, nullable=True)


class OmsLedgerHeadRow(StoreBase):
    """Authenticated per-account high-water mark and mutable order-cache anchor."""

    __tablename__ = "oms_ledger_heads"

    environment: Mapped[str] = mapped_column(String, primary_key=True)
    account_id: Mapped[str] = mapped_column(String, primary_key=True)
    sequence_count: Mapped[int] = mapped_column(Integer)
    head_chain: Mapped[str] = mapped_column(String)
    order_cache_digest: Mapped[str] = mapped_column(String)
    order_count: Mapped[int] = mapped_column(Integer)
    anchor: Mapped[str] = mapped_column(String)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    guard_order_id: Mapped[str | None] = mapped_column(String, nullable=True)
    guard_action: Mapped[str | None] = mapped_column(String, nullable=True)
    guard_client_order_id: Mapped[str | None] = mapped_column(String, nullable=True)
    guard_attempt: Mapped[int | None] = mapped_column(Integer, nullable=True)
    guard_revision: Mapped[int | None] = mapped_column(Integer, nullable=True)
    fence_epoch: Mapped[int | None] = mapped_column(Integer, nullable=True)
