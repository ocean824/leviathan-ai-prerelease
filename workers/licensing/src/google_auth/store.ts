import type { PgDriverV1 } from "../adapters/neon_admin.js";
import type { PgQueryV1 } from "../db/repository.js";
import type { GoogleIdentityV1 } from "./oidc.js";

const NS = 1_000_000_000n;
const ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
const HEX_SHA256 = /^[0-9a-f]{64}$/;

export type GoogleOAuthFlowV1 = "DESKTOP" | "WEB";

export interface GoogleOAuthTransactionV1 {
  readonly flow: GoogleOAuthFlowV1;
  readonly state_sha256: string;
  readonly nonce_sha256: string;
  readonly code_challenge: string;
  readonly verifier_ciphertext: string | null;
  readonly redirect_uri: string;
  readonly device_id: string | null;
  readonly return_to: string | null;
  readonly expires_at_utc_ns: string;
}

export interface GoogleLinkedAccountV1 {
  readonly org_id: string;
  readonly user_id: string;
  readonly email: string;
  readonly role_id: string;
  readonly active: boolean;
  readonly totp_enrolled: boolean;
}

export class GoogleAccountLinkErrorV1 extends Error {
  constructor(readonly code: "ACCOUNT_LINK_CONFLICT" | "ACCOUNT_NOT_FOUND" | "ACCOUNT_INACTIVE") {
    super(code);
    this.name = "GoogleAccountLinkErrorV1";
  }
}

export async function sha256HexV1(value: string, cryptoApi: Crypto = globalThis.crypto): Promise<string> {
  const digest = new Uint8Array(await cryptoApi.subtle.digest("SHA-256", new TextEncoder().encode(value)));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export async function createGoogleOAuthTransactionV1(
  driver: PgDriverV1,
  input: {
    readonly flow: GoogleOAuthFlowV1;
    readonly state: string;
    readonly nonce: string;
    readonly code_challenge: string;
    readonly verifier_ciphertext: string | null;
    readonly redirect_uri: string;
    readonly device_id: string | null;
    readonly return_to: string | null;
    readonly now_utc_ns: string;
    readonly ttl_seconds?: number;
  },
): Promise<GoogleOAuthTransactionV1> {
  if (input.state.length < 32 || input.state.length > 256 || input.nonce.length < 32
      || input.nonce.length > 256 || !/^[A-Za-z0-9_-]{43,128}$/.test(input.code_challenge)
      || (input.flow === "WEB" && !input.verifier_ciphertext)
      || (input.flow === "DESKTOP" && input.verifier_ciphertext !== null)
      || (input.device_id !== null && !ID.test(input.device_id))
      || !/^(0|[1-9][0-9]{0,63})$/.test(input.now_utc_ns)) {
    throw new TypeError("INVALID_GOOGLE_OAUTH_TRANSACTION");
  }
  const now = BigInt(input.now_utc_ns);
  const ttl = input.ttl_seconds ?? 600;
  if (!Number.isSafeInteger(ttl) || ttl < 60 || ttl > 900) {
    throw new TypeError("INVALID_GOOGLE_OAUTH_TRANSACTION");
  }
  const stateHash = await sha256HexV1(input.state);
  const nonceHash = await sha256HexV1(input.nonce);
  const expires = (now + BigInt(ttl) * NS).toString();
  await driver.query(
    "INSERT INTO licensing_google_oauth_transactions(state_sha256,flow,nonce_sha256,code_challenge,verifier_ciphertext,redirect_uri,device_id,return_to,created_at_utc_ns,expires_at_utc_ns) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
    [stateHash,input.flow,nonceHash,input.code_challenge,input.verifier_ciphertext,
      input.redirect_uri,input.device_id,input.return_to,input.now_utc_ns,expires],
  );
  return Object.freeze({
    flow: input.flow, state_sha256: stateHash, nonce_sha256: nonceHash,
    code_challenge: input.code_challenge, verifier_ciphertext: input.verifier_ciphertext,
    redirect_uri: input.redirect_uri, device_id: input.device_id, return_to: input.return_to,
    expires_at_utc_ns: expires,
  });
}

export async function readGoogleOAuthTransactionV1(
  driver: PgDriverV1, state: string, flow: GoogleOAuthFlowV1,
): Promise<GoogleOAuthTransactionV1 | null> {
  if (state.length < 32 || state.length > 256) return null;
  const stateHash = await sha256HexV1(state);
  const result = await driver.query<{
    flow: string; state_sha256: string; nonce_sha256: string; code_challenge: string;
    verifier_ciphertext: string | null; redirect_uri: string; device_id: string | null;
    return_to: string | null; expires_at_utc_ns: string; consumed_at_utc_ns: string | null;
  }>(
    "SELECT flow,state_sha256,nonce_sha256,code_challenge,verifier_ciphertext,redirect_uri,device_id,return_to,expires_at_utc_ns::text AS expires_at_utc_ns,consumed_at_utc_ns::text AS consumed_at_utc_ns FROM licensing_google_oauth_transactions WHERE state_sha256=$1",
    [stateHash],
  );
  const row = result.rows[0];
  if (!row || row.flow !== flow || row.consumed_at_utc_ns !== null
      || !HEX_SHA256.test(row.nonce_sha256) || !HEX_SHA256.test(row.state_sha256)
      || !/^[A-Za-z0-9_-]{43,128}$/.test(row.code_challenge)) return null;
  return Object.freeze({
    flow, state_sha256: row.state_sha256, nonce_sha256: row.nonce_sha256,
    code_challenge: row.code_challenge, verifier_ciphertext: row.verifier_ciphertext,
    redirect_uri: row.redirect_uri, device_id: row.device_id,
    return_to: row.return_to, expires_at_utc_ns: row.expires_at_utc_ns,
  });
}

export async function consumeGoogleOAuthTransactionV1(
  driver: PgDriverV1, state: string, flow: GoogleOAuthFlowV1, nowUtcNs: string,
): Promise<GoogleOAuthTransactionV1 | null> {
  if (state.length < 32 || state.length > 256 || !/^(0|[1-9][0-9]{0,63})$/.test(nowUtcNs)) return null;
  const stateHash = await sha256HexV1(state);
  return driver.transaction(async (tx: PgQueryV1) => {
    const result = await tx.query<{
      flow: string; state_sha256: string; nonce_sha256: string; code_challenge: string;
      verifier_ciphertext: string | null; redirect_uri: string; device_id: string | null;
      return_to: string | null; expires_at_utc_ns: string;
    }>(
      "UPDATE licensing_google_oauth_transactions SET consumed_at_utc_ns=$3 WHERE state_sha256=$1 AND flow=$2 AND consumed_at_utc_ns IS NULL AND expires_at_utc_ns>$3 RETURNING flow,state_sha256,nonce_sha256,code_challenge,verifier_ciphertext,redirect_uri,device_id,return_to,expires_at_utc_ns::text AS expires_at_utc_ns",
      [stateHash,flow,nowUtcNs],
    );
    const row = result.rows[0];
    if (!row || !HEX_SHA256.test(row.nonce_sha256) || !HEX_SHA256.test(row.state_sha256)
        || !/^[A-Za-z0-9_-]{43,128}$/.test(row.code_challenge)) return null;
    return Object.freeze({
      flow, state_sha256: row.state_sha256, nonce_sha256: row.nonce_sha256,
      code_challenge: row.code_challenge, verifier_ciphertext: row.verifier_ciphertext,
      redirect_uri: row.redirect_uri, device_id: row.device_id,
      return_to: row.return_to, expires_at_utc_ns: row.expires_at_utc_ns,
    });
  });
}

/**
 * Link only after Google has validated its signature, nonce, audience, expiry and email_verified.
 * The unique provider/subject key plus row locks make concurrent callbacks idempotent and prevent
 * one Google subject from being attached to two licensing users.
 */
export async function linkVerifiedGoogleIdentityV1(
  driver: PgDriverV1,
  identity: GoogleIdentityV1,
  nowUtcNs: string,
): Promise<GoogleLinkedAccountV1> {
  return driver.transaction(async (tx: PgQueryV1) => {
    const priorIdentity = await tx.query<{ org_id: string; user_id: string; email: string }>(
      "SELECT org_id,user_id,email FROM licensing_google_identities WHERE provider='GOOGLE' AND subject=$1 FOR UPDATE",
      [identity.subject],
    );
    let account: GoogleLinkedAccountV1 | undefined;
    const prior = priorIdentity.rows[0];
    if (prior) {
      const user = await tx.query<GoogleLinkedAccountV1>(
        "SELECT org_id,user_id,email,role_id,active,totp_enrolled FROM licensing_users WHERE org_id=$1 AND user_id=$2 FOR UPDATE",
        [prior.org_id,prior.user_id],
      );
      account = user.rows[0];
      if (!account) throw new GoogleAccountLinkErrorV1("ACCOUNT_LINK_CONFLICT");
      await tx.query(
        "UPDATE licensing_google_identities SET email=$3,last_authenticated_at_utc_ns=$4 WHERE provider='GOOGLE' AND subject=$1 AND org_id=$2",
        [identity.subject,account.org_id,identity.email,nowUtcNs],
      );
      if (prior.email.toLowerCase() !== identity.email.toLowerCase()) {
        await tx.query(
          "INSERT INTO licensing_audit_events(id,org_id,actor,action,resource,digest,created_at_utc_ns) VALUES ($1,$2,$3,'auth.google.identity.email_update',$4,$5,$6)",
          ["audit-" + crypto.randomUUID(), account.org_id, account.user_id,
            `google_identity:${await sha256HexV1(identity.subject)}`,
            await sha256HexV1(JSON.stringify([prior.email.toLowerCase(), identity.email.toLowerCase()])), nowUtcNs],
        );
      }
    } else {
      const matched = await tx.query<GoogleLinkedAccountV1>(
        "SELECT org_id,user_id,email,role_id,active,totp_enrolled FROM licensing_users WHERE lower(email)=lower($1) FOR UPDATE",
        [identity.email],
      );
      if (matched.rows.length > 1) throw new GoogleAccountLinkErrorV1("ACCOUNT_LINK_CONFLICT");
      account = matched.rows[0];
      if (!account) throw new GoogleAccountLinkErrorV1("ACCOUNT_NOT_FOUND");
      const inserted = await tx.query<{ org_id: string; user_id: string }>(
        "INSERT INTO licensing_google_identities(provider,subject,org_id,user_id,email,email_verified,created_at_utc_ns,last_authenticated_at_utc_ns) VALUES ('GOOGLE',$1,$2,$3,$4,TRUE,$5,$5) ON CONFLICT(provider,subject) DO NOTHING RETURNING org_id,user_id",
        [identity.subject,account.org_id,account.user_id,identity.email,nowUtcNs],
      );
      if (inserted.rows.length !== 1) {
        const raced = await tx.query<{ org_id: string; user_id: string }>(
          "SELECT org_id,user_id FROM licensing_google_identities WHERE provider='GOOGLE' AND subject=$1 FOR UPDATE",
          [identity.subject],
        );
        if (raced.rows[0]?.org_id !== account.org_id || raced.rows[0]?.user_id !== account.user_id) {
          throw new GoogleAccountLinkErrorV1("ACCOUNT_LINK_CONFLICT");
        }
      } else {
        await tx.query(
          "INSERT INTO licensing_audit_events(id,org_id,actor,action,resource,digest,created_at_utc_ns) VALUES ($1,$2,$3,'auth.google.identity.link',$4,$5,$6)",
          ["audit-" + crypto.randomUUID(), account.org_id, account.user_id,
            `google_identity:${await sha256HexV1(identity.subject)}`,
            await sha256HexV1(JSON.stringify([identity.subject, identity.email.toLowerCase()])), nowUtcNs],
        );
      }
    }
    return Object.freeze(account);
  });
}
