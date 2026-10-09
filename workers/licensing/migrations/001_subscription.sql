-- LIC-002 synthetic ledger schema. Apply only to a separately approved Neon database.
-- The local organization registry is deliberately limited to this licensing slice.
BEGIN;

CREATE TABLE licensing_organizations (
  org_id text PRIMARY KEY CHECK (org_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'),
  active boolean NOT NULL DEFAULT false
);

CREATE TABLE licensing_subscriptions (
  org_id text NOT NULL REFERENCES licensing_organizations(org_id) ON DELETE RESTRICT,
  subscription_id text NOT NULL CHECK (subscription_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'),
  revision bigint NOT NULL CHECK (revision > 0),
  status text NOT NULL CHECK (status IN ('ACTIVE','TRIAL','PAST_DUE','PAUSED','CANCELED')),
  term_start_utc_ns bigint NOT NULL CHECK (term_start_utc_ns >= 0),
  term_end_utc_ns bigint NOT NULL CHECK (term_end_utc_ns > term_start_utc_ns),
  seat_limit bigint NOT NULL CHECK (seat_limit >= 0),
  features jsonb NOT NULL CHECK (jsonb_typeof(features) = 'object'),
  limits jsonb NOT NULL CHECK (jsonb_typeof(limits) = 'object'),
  billing_reference text,
  billing_amount_decimal text,
  billing_currency text,
  audit_event_id text NOT NULL,
  PRIMARY KEY (org_id, subscription_id),
  CHECK (billing_reference IS NULL OR
    billing_reference ~ '^(bill_|invoice-)[A-Za-z0-9][A-Za-z0-9_.:-]{0,119}$'),
  CHECK ((billing_amount_decimal IS NULL) = (billing_currency IS NULL)),
  CHECK (billing_amount_decimal IS NULL OR
    (length(billing_amount_decimal) <= 60 AND
     length(split_part(billing_amount_decimal, '.', 1)) <= 39 AND
     length(regexp_replace(regexp_replace(replace(billing_amount_decimal, '.', ''), '^0+', ''), '0+$', '')) <= 34 AND
     billing_amount_decimal ~ '^(0|[1-9][0-9]*)(\.[0-9]{0,17}[1-9])?$')),
  CHECK (billing_currency IS NULL OR billing_currency ~ '^[A-Z]{3}$')
);

CREATE INDEX licensing_subscriptions_org_status_idx
  ON licensing_subscriptions (org_id, status);

CREATE TABLE licensing_subscription_revisions (
  org_id text NOT NULL,
  subscription_id text NOT NULL,
  revision bigint NOT NULL CHECK (revision > 0),
  status text NOT NULL CHECK (status IN ('ACTIVE','TRIAL','PAST_DUE','PAUSED','CANCELED')),
  term_start_utc_ns bigint NOT NULL CHECK (term_start_utc_ns >= 0),
  term_end_utc_ns bigint NOT NULL CHECK (term_end_utc_ns > term_start_utc_ns),
  seat_limit bigint NOT NULL CHECK (seat_limit >= 0),
  features jsonb NOT NULL CHECK (jsonb_typeof(features) = 'object'),
  limits jsonb NOT NULL CHECK (jsonb_typeof(limits) = 'object'),
  billing_reference text,
  billing_amount_decimal text,
  billing_currency text,
  audit_event_id text NOT NULL,
  source_event_id text NOT NULL,
  -- Synthetic source occurred-at; ordered per (org_id, subscription_id).
  created_at_utc_ns bigint NOT NULL CHECK (created_at_utc_ns >= 0),
  PRIMARY KEY (org_id, subscription_id, revision),
  UNIQUE (source_event_id),
  UNIQUE (audit_event_id),
  FOREIGN KEY (org_id, subscription_id)
    REFERENCES licensing_subscriptions(org_id, subscription_id) ON DELETE RESTRICT,
  CHECK ((billing_amount_decimal IS NULL) = (billing_currency IS NULL)),
  CHECK (billing_reference IS NULL OR
    billing_reference ~ '^(bill_|invoice-)[A-Za-z0-9][A-Za-z0-9_.:-]{0,119}$'),
  CHECK (billing_amount_decimal IS NULL OR
    (length(billing_amount_decimal) <= 60 AND
     length(split_part(billing_amount_decimal, '.', 1)) <= 39 AND
     length(regexp_replace(regexp_replace(replace(billing_amount_decimal, '.', ''), '^0+', ''), '0+$', '')) <= 34 AND
     billing_amount_decimal ~ '^(0|[1-9][0-9]*)(\.[0-9]{0,17}[1-9])?$')),
  CHECK (billing_currency IS NULL OR billing_currency ~ '^[A-Z]{3}$')
);

CREATE TABLE licensing_subscription_outbox (
  org_id text NOT NULL,
  subscription_id text NOT NULL,
  revision bigint NOT NULL,
  audit_event_id text NOT NULL,
  source_event_id text NOT NULL,
  created_at_utc_ns bigint NOT NULL CHECK (created_at_utc_ns >= 0),
  status text NOT NULL CHECK (status IN ('ACTIVE','TRIAL','PAST_DUE','PAUSED','CANCELED')),
  PRIMARY KEY (audit_event_id),
  UNIQUE (source_event_id),
  FOREIGN KEY (org_id, subscription_id, revision)
    REFERENCES licensing_subscription_revisions(org_id, subscription_id, revision) ON DELETE RESTRICT
);

-- History and outbox rows are append-only even when the application port is bypassed.
CREATE FUNCTION licensing_reject_history_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'LEDGER_HISTORY_IMMUTABLE' USING ERRCODE = '23514';
END;
$$;

CREATE TRIGGER licensing_revisions_append_only
  BEFORE UPDATE OR DELETE ON licensing_subscription_revisions
  FOR EACH ROW EXECUTE FUNCTION licensing_reject_history_mutation();

CREATE TRIGGER licensing_outbox_append_only
  BEFORE UPDATE OR DELETE ON licensing_subscription_outbox
  FOR EACH ROW EXECUTE FUNCTION licensing_reject_history_mutation();

COMMIT;
