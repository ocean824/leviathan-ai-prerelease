-- LIC-WORKER-COMPOSE-001: only the account/auth tables absent from 001/002.
BEGIN;

ALTER TABLE licensing_organizations ADD COLUMN IF NOT EXISTS display_name text;
ALTER TABLE licensing_subscriptions ADD COLUMN IF NOT EXISTS plan_id text NOT NULL DEFAULT 'all_access_v1';
ALTER TABLE licensing_subscriptions ADD COLUMN IF NOT EXISTS created_at_utc_ns bigint NOT NULL DEFAULT 0;
ALTER TABLE licensing_subscriptions ADD COLUMN IF NOT EXISTS updated_at_utc_ns bigint NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS licensing_users (
  org_id text NOT NULL REFERENCES licensing_organizations(org_id) ON DELETE RESTRICT,
  user_id text NOT NULL CHECK (user_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'),
  email text NOT NULL,
  role_id text NOT NULL DEFAULT 'owner',
  password_hash_pbkdf2 text,
  active boolean NOT NULL DEFAULT true,
  owner boolean NOT NULL DEFAULT false,
  totp_enrolled boolean NOT NULL DEFAULT false,
  totp_secret_ciphertext text,
  totp_last_step bigint,
  failed_login_count integer NOT NULL DEFAULT 0 CHECK (failed_login_count >= 0),
  locked_until_utc_ns bigint,
  version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
  created_at_utc_ns bigint NOT NULL CHECK (created_at_utc_ns >= 0),
  PRIMARY KEY (org_id,user_id),
  UNIQUE (email),
  CHECK ((totp_enrolled = false) OR (totp_secret_ciphertext IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS licensing_devices (
  device_id text PRIMARY KEY CHECK (device_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'),
  org_id text NOT NULL,
  user_id text NOT NULL,
  status text NOT NULL CHECK (status IN ('ACTIVE','REVOKED')),
  created_at_utc_ns bigint NOT NULL CHECK (created_at_utc_ns >= 0),
  last_seen_at_utc_ns bigint,
  revoked_at_utc_ns bigint,
  version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
  FOREIGN KEY (org_id,user_id) REFERENCES licensing_users(org_id,user_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS licensing_admin_sessions (
  session_id text PRIMARY KEY CHECK (session_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'),
  token_digest text NOT NULL UNIQUE,
  org_id text NOT NULL,
  user_id text NOT NULL,
  device_id text NOT NULL REFERENCES licensing_devices(device_id) ON DELETE RESTRICT,
  session_kind text NOT NULL DEFAULT 'ADMIN' CHECK (session_kind IN ('ADMIN','USER','TOTP_ENROLLMENT')),
  issued_at_utc_ns bigint NOT NULL,
  expires_at_utc_ns bigint NOT NULL,
  revoked_at_utc_ns bigint,
  UNIQUE (org_id,user_id,session_id),
  FOREIGN KEY (org_id,user_id) REFERENCES licensing_users(org_id,user_id) ON DELETE RESTRICT,
  CHECK (expires_at_utc_ns > issued_at_utc_ns)
);

CREATE TABLE IF NOT EXISTS licensing_totp_enrollments (
  token_digest text PRIMARY KEY,
  org_id text NOT NULL,
  user_id text NOT NULL,
  device_id text NOT NULL,
  expires_at_utc_ns bigint NOT NULL,
  confirmed_at_utc_ns bigint,
  FOREIGN KEY (org_id,user_id) REFERENCES licensing_users(org_id,user_id) ON DELETE RESTRICT,
  FOREIGN KEY (device_id) REFERENCES licensing_devices(device_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS licensing_pending_signups (
  pending_account_id text PRIMARY KEY,
  org_id text NOT NULL UNIQUE REFERENCES licensing_organizations(org_id) ON DELETE RESTRICT,
  owner_email text NOT NULL,
  owner_user_id text NOT NULL,
  device_id text NOT NULL,
  stripe_session_id text UNIQUE,
  stripe_customer_id text,
  status text NOT NULL CHECK (status IN ('PENDING','ACTIVE','CANCELED')),
  idempotency_key text NOT NULL UNIQUE,
  version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
  created_at_utc_ns bigint NOT NULL
);

CREATE TABLE IF NOT EXISTS licensing_audit_events (
  id text PRIMARY KEY,
  org_id text REFERENCES licensing_organizations(org_id) ON DELETE RESTRICT,
  actor text NOT NULL,
  action text NOT NULL,
  resource text NOT NULL,
  digest text NOT NULL,
  created_at_utc_ns bigint NOT NULL CHECK (created_at_utc_ns >= 0)
);

-- First materialization of the LIC-003 role/seat schema for the admin API.
CREATE TABLE IF NOT EXISTS licensing_roles (
  role_id text PRIMARY KEY CHECK (role_id ~ '^[A-Za-z][A-Za-z0-9_.:-]{0,127}$'),
  org_id text REFERENCES licensing_organizations(org_id) ON DELETE RESTRICT,
  immutable boolean NOT NULL DEFAULT false,
  permissions jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(permissions)='array')
);

CREATE TABLE IF NOT EXISTS licensing_seats (
  org_id text NOT NULL REFERENCES licensing_organizations(org_id) ON DELETE RESTRICT,
  subscription_id text NOT NULL,
  seat_id text NOT NULL CHECK (seat_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'),
  user_id text NOT NULL,
  role_id text NOT NULL REFERENCES licensing_roles(role_id) ON DELETE RESTRICT,
  status text NOT NULL CHECK (status IN ('ACTIVE','INVITED','REVOKED')),
  version bigint NOT NULL CHECK (version > 0),
  assigned_at_utc_ns bigint NOT NULL CHECK (assigned_at_utc_ns >= 0),
  updated_at_utc_ns bigint NOT NULL CHECK (updated_at_utc_ns >= assigned_at_utc_ns),
  audit_event_id text NOT NULL,
  PRIMARY KEY (org_id,seat_id),
  FOREIGN KEY (org_id,subscription_id) REFERENCES licensing_subscriptions(org_id,subscription_id) ON DELETE RESTRICT,
  FOREIGN KEY (org_id,user_id) REFERENCES licensing_users(org_id,user_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS licensing_admin_audit (
  audit_event_id text PRIMARY KEY,
  org_id text NOT NULL REFERENCES licensing_organizations(org_id) ON DELETE RESTRICT,
  actor_user_id text NOT NULL,
  target_id text NOT NULL,
  action text NOT NULL CHECK (action IN ('ASSIGN','INVITE','CHANGE_ROLE','REVOKE')),
  before_role_id text,
  after_role_id text NOT NULL,
  before_status text CHECK (before_status IS NULL OR before_status IN ('ACTIVE','INVITED','REVOKED')),
  after_status text NOT NULL CHECK (after_status IN ('ACTIVE','INVITED','REVOKED')),
  occurred_at_utc_ns bigint NOT NULL CHECK (occurred_at_utc_ns >= 0)
);

INSERT INTO licensing_roles(role_id,org_id,immutable,permissions) VALUES
  ('owner',NULL,TRUE,'["*"]'::jsonb),
  ('admin',NULL,TRUE,'["accounts:read","users:write","subscriptions:write","devices:write","audit:read","seats:write"]'::jsonb),
  ('billing',NULL,TRUE,'["subscriptions:read","subscriptions:write","audit:read"]'::jsonb),
  ('auditor',NULL,TRUE,'["accounts:read","users:read","subscriptions:read","devices:read","audit:read"]'::jsonb),
  ('readonly',NULL,TRUE,'["accounts:read","users:read","subscriptions:read","devices:read"]'::jsonb),
  ('service',NULL,TRUE,'["license:read","auth:introspect"]'::jsonb)
ON CONFLICT (role_id) DO NOTHING;

CREATE TABLE IF NOT EXISTS licensing_admin_idempotency (
  org_id text NOT NULL,
  actor_user_id text NOT NULL,
  idempotency_key text NOT NULL,
  request_fingerprint text,
  receipt jsonb,
  command_hash text,
  result_json text,
  created_at_utc_ns bigint NOT NULL DEFAULT ((extract(epoch FROM clock_timestamp()) * 1000000000)::bigint),
  expires_at_utc_ns bigint NOT NULL DEFAULT (((extract(epoch FROM clock_timestamp()) + 2592000) * 1000000000)::bigint),
  PRIMARY KEY (org_id,actor_user_id,idempotency_key),
  FOREIGN KEY (org_id,actor_user_id) REFERENCES licensing_users(org_id,user_id) ON DELETE RESTRICT,
  CHECK ((request_fingerprint IS NOT NULL AND receipt IS NOT NULL)
      OR (command_hash IS NOT NULL AND result_json IS NOT NULL)),
  CHECK (expires_at_utc_ns > created_at_utc_ns)
);

CREATE INDEX IF NOT EXISTS licensing_users_email_idx ON licensing_users(email);
CREATE INDEX IF NOT EXISTS licensing_sessions_user_idx ON licensing_admin_sessions(org_id,user_id);
CREATE INDEX IF NOT EXISTS licensing_pending_status_idx ON licensing_pending_signups(status,created_at_utc_ns);

CREATE OR REPLACE FUNCTION licensing_reject_append_only_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'APPEND_ONLY_IMMUTABLE' USING ERRCODE = '23514';
END;
$$;

CREATE OR REPLACE FUNCTION licensing_reject_immutable_system_role_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.immutable=TRUE AND OLD.org_id IS NULL THEN
    RAISE EXCEPTION 'SYSTEM_ROLE_IMMUTABLE' USING ERRCODE = '23514';
  END IF;
  IF TG_OP='DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS licensing_roles_system_seed_immutable ON licensing_roles;
CREATE TRIGGER licensing_roles_system_seed_immutable
  BEFORE UPDATE OR DELETE ON licensing_roles
  FOR EACH ROW EXECUTE FUNCTION licensing_reject_immutable_system_role_mutation();

DROP TRIGGER IF EXISTS licensing_audit_events_append_only ON licensing_audit_events;
CREATE TRIGGER licensing_audit_events_append_only
  BEFORE UPDATE OR DELETE ON licensing_audit_events
  FOR EACH ROW EXECUTE FUNCTION licensing_reject_append_only_mutation();

DROP TRIGGER IF EXISTS licensing_admin_idempotency_append_only ON licensing_admin_idempotency;
CREATE TRIGGER licensing_admin_idempotency_append_only
  BEFORE UPDATE OR DELETE ON licensing_admin_idempotency
  FOR EACH ROW EXECUTE FUNCTION licensing_reject_append_only_mutation();

DROP TRIGGER IF EXISTS licensing_admin_audit_append_only ON licensing_admin_audit;
CREATE TRIGGER licensing_admin_audit_append_only
  BEFORE UPDATE OR DELETE ON licensing_admin_audit
  FOR EACH ROW EXECUTE FUNCTION licensing_reject_append_only_mutation();

COMMIT;
