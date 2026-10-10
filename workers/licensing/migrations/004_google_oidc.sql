-- AUTH-GOOGLE-001. OAuth state is one-time, bounded, and indexed by hashed state.
BEGIN;
CREATE TABLE IF NOT EXISTS licensing_google_identities (
  provider text NOT NULL CHECK (provider='GOOGLE'),
  subject text NOT NULL CHECK (length(subject) BETWEEN 1 AND 255),
  org_id text NOT NULL,
  user_id text NOT NULL,
  email text NOT NULL,
  email_verified boolean NOT NULL CHECK (email_verified=TRUE),
  created_at_utc_ns bigint NOT NULL CHECK (created_at_utc_ns >= 0),
  last_authenticated_at_utc_ns bigint NOT NULL CHECK (last_authenticated_at_utc_ns >= created_at_utc_ns),
  PRIMARY KEY(provider,subject),
  UNIQUE(org_id,user_id,provider),
  FOREIGN KEY(org_id,user_id) REFERENCES licensing_users(org_id,user_id) ON DELETE RESTRICT
);
CREATE INDEX IF NOT EXISTS licensing_google_identity_email_idx
  ON licensing_google_identities(lower(email));

CREATE TABLE IF NOT EXISTS licensing_google_oauth_transactions (
  state_sha256 text PRIMARY KEY CHECK (state_sha256 ~ '^[0-9a-f]{64}$'),
  flow text NOT NULL CHECK (flow IN ('DESKTOP','WEB')),
  nonce_sha256 text NOT NULL CHECK (nonce_sha256 ~ '^[0-9a-f]{64}$'),
  code_challenge text NOT NULL CHECK (code_challenge ~ '^[A-Za-z0-9_-]{43,128}$'),
  verifier_ciphertext text,
  redirect_uri text NOT NULL CHECK (length(redirect_uri) BETWEEN 1 AND 2048),
  device_id text,
  return_to text,
  created_at_utc_ns bigint NOT NULL CHECK (created_at_utc_ns >= 0),
  expires_at_utc_ns bigint NOT NULL CHECK (expires_at_utc_ns > created_at_utc_ns),
  consumed_at_utc_ns bigint,
  CHECK ((flow='WEB' AND verifier_ciphertext IS NOT NULL)
      OR (flow='DESKTOP' AND verifier_ciphertext IS NULL))
);
CREATE INDEX IF NOT EXISTS licensing_google_oauth_expiry_idx
  ON licensing_google_oauth_transactions(expires_at_utc_ns);
COMMIT;
