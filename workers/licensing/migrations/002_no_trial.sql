-- LIC-NO-TRIAL-001. Existing trial history requires an explicit operator decision;
-- do not rewrite append-only revision or outbox rows during this migration.
BEGIN;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM licensing_subscriptions WHERE status = 'TRIAL') THEN
    RAISE EXCEPTION 'LIC_NO_TRIAL_MIGRATION_BLOCKED: TRIAL rows exist in licensing_subscriptions';
  END IF;
  IF EXISTS (SELECT 1 FROM licensing_subscription_revisions WHERE status = 'TRIAL') THEN
    RAISE EXCEPTION 'LIC_NO_TRIAL_MIGRATION_BLOCKED: TRIAL rows exist in licensing_subscription_revisions';
  END IF;
  IF EXISTS (SELECT 1 FROM licensing_subscription_outbox WHERE status = 'TRIAL') THEN
    RAISE EXCEPTION 'LIC_NO_TRIAL_MIGRATION_BLOCKED: TRIAL rows exist in licensing_subscription_outbox';
  END IF;
END;
$$;

ALTER TABLE licensing_subscriptions
  DROP CONSTRAINT IF EXISTS licensing_subscriptions_status_check;
ALTER TABLE licensing_subscriptions
  ADD CONSTRAINT licensing_subscriptions_status_check
  CHECK (status IN ('ACTIVE', 'PAST_DUE', 'PAUSED', 'CANCELED'));

ALTER TABLE licensing_subscription_revisions
  DROP CONSTRAINT IF EXISTS licensing_subscription_revisions_status_check;
ALTER TABLE licensing_subscription_revisions
  ADD CONSTRAINT licensing_subscription_revisions_status_check
  CHECK (status IN ('ACTIVE', 'PAST_DUE', 'PAUSED', 'CANCELED'));

ALTER TABLE licensing_subscription_outbox
  DROP CONSTRAINT IF EXISTS licensing_subscription_outbox_status_check;
ALTER TABLE licensing_subscription_outbox
  ADD CONSTRAINT licensing_subscription_outbox_status_check
  CHECK (status IN ('ACTIVE', 'PAST_DUE', 'PAUSED', 'CANCELED'));

-- Append-only history/outbox triggers are intentionally left untouched.
COMMIT;
