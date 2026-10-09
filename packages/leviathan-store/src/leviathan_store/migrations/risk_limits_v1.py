"""Additive RISK-005 schema migration under an injected exclusive-writer lease.

This migration owns only new risk-prefixed tables. It does not alter, inspect,
or create any OMS table. Product-DB WORM and retention controls are separate gates.
"""

from __future__ import annotations

import hashlib

from leviathan_store.risk_limit_events import (
    RISK_LIMITS_METADATA,
    MigrationWriterGuard,
    RiskLimitEventStoreError,
    risk_audit_head,
    risk_limit_migration_versions,
)
from sqlalchemy import insert, inspect, select
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import AsyncEngine

MIGRATION_NAME = "risk_limits_v1"
MIGRATION_VERSION = 1
_GENESIS = hashlib.sha256(b"leviathan.risk005.audit.genesis.v1").hexdigest()


class MigrationWriterCollisionError(RuntimeError):
    """The coordinator's product-database writer slot is already held."""


def _verify_schema(connection: Connection) -> None:
    inspector = inspect(connection)
    expected = {
        "risk_policy_state": {
            "environment",
            "account_id",
            "version",
            "policy_digest",
            "policy_payload",
            "last_event_id",
        },
        "risk_audit_events": {
            "sequence",
            "event_id",
            "correlation_id",
            "attempt_id",
            "actor_ref",
            "action",
            "decision",
            "reason_code",
            "environment",
            "account_id",
            "scope",
            "before_digest",
            "after_digest",
            "source_event_ids",
            "recorded_at_ns",
            "predecessor_hash",
            "event_hash",
        },
        "risk_audit_head": {"head_id", "sequence", "chain_tip"},
        "risk_soft_approval_claims": {"approval_id", "order_digest", "claimed_at_ns", "event_id"},
        "risk_soft_approvals": {
            "approval_id",
            "environment",
            "account_id",
            "strategy_id",
            "venue_id",
            "instrument_id",
            "order_digest",
            "soft_rule_id",
            "policy_version",
            "requester_id",
            "approver_ids",
            "requested_at_ns",
            "expires_at_ns",
            "correlation_id",
            "event_id",
            "consumed_at_ns",
            "consume_event_id",
        },
        "risk_limit_migration_versions": {"version", "name", "applied_at_ns"},
    }
    for table, columns in expected.items():
        if not inspector.has_table(table):
            raise RiskLimitEventStoreError("MIGRATION_REQUIRED")
        found = {item["name"] for item in inspector.get_columns(table)}
        if not columns.issubset(found):
            raise RiskLimitEventStoreError("MIGRATION_REQUIRED")


async def migrate_risk_limits_v1(
    engine: AsyncEngine,
    *,
    writer_guard: MigrationWriterGuard,
    applied_at_ns: int,
) -> None:
    """Create only the dedicated risk schema while holding the global writer slot."""
    if type(applied_at_ns) is not int or applied_at_ns < 0:
        raise RiskLimitEventStoreError("STORE_FAILURE")
    acquired = await writer_guard.acquire("risk_limits_v1")
    if acquired is not True:
        raise MigrationWriterCollisionError("exclusive product database writer slot unavailable")
    try:
        async with engine.begin() as connection:
            await connection.run_sync(RISK_LIMITS_METADATA.create_all)
            await connection.run_sync(_verify_schema)
            head = await connection.scalar(
                select(risk_audit_head.c.head_id).where(risk_audit_head.c.head_id == 1)
            )
            if head is None:
                await connection.execute(
                    insert(risk_audit_head).values(
                        head_id=1,
                        sequence=0,
                        chain_tip=_GENESIS,
                    )
                )
            existing = await connection.scalar(
                select(risk_limit_migration_versions.c.name).where(
                    risk_limit_migration_versions.c.version == MIGRATION_VERSION
                )
            )
            if existing is None:
                await connection.execute(
                    insert(risk_limit_migration_versions).values(
                        version=MIGRATION_VERSION,
                        name=MIGRATION_NAME,
                        applied_at_ns=applied_at_ns,
                    )
                )
            elif existing != MIGRATION_NAME:
                raise RiskLimitEventStoreError("MIGRATION_REQUIRED")
    finally:
        await writer_guard.release("risk_limits_v1")


__all__ = [
    "MIGRATION_NAME",
    "MIGRATION_VERSION",
    "MigrationWriterCollisionError",
    "migrate_risk_limits_v1",
]
