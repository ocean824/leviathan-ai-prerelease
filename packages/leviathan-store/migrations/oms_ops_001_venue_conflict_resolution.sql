-- OMS-OPS-001 additive migration. Resolution rows join the authenticated
-- per-account ADR-0004 chain; the writer allocates ledger_sequence and chain.
CREATE TABLE IF NOT EXISTS oms_operator_resolutions (
    resolution_id VARCHAR PRIMARY KEY,
    environment VARCHAR NOT NULL,
    account_id VARCHAR NOT NULL,
    conflict_id VARCHAR NOT NULL,
    binding_venue VARCHAR NOT NULL,
    binding_environment VARCHAR NOT NULL,
    observation_ids JSON NOT NULL,
    identity_digest VARCHAR NOT NULL,
    idempotency_digest VARCHAR NOT NULL,
    operator_principal_id VARCHAR NOT NULL,
    reason_code VARCHAR NOT NULL,
    broker_revision INTEGER NOT NULL,
    broker_evidence_digest VARCHAR NOT NULL,
    prior_ledger_revision INTEGER NOT NULL,
    resolved_at_ns INTEGER NOT NULL,
    affected_order_ids JSON NOT NULL,
    ledger_sequence INTEGER,
    chain VARCHAR,
    recorded_at TIMESTAMP NOT NULL,
    UNIQUE (environment, account_id, idempotency_digest),
    UNIQUE (environment, account_id, ledger_sequence)
);
CREATE INDEX IF NOT EXISTS ix_oms_operator_resolutions_account
    ON oms_operator_resolutions (environment, account_id);
