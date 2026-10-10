import { beforeAll, describe, expect, it } from "vitest";
import { verifyGoogleIdentityTokenV1, GoogleIdentityErrorV1 } from "../src/google_auth/oidc.js";
import { createPkcePairV1, encryptWebPkceVerifierV1, decryptWebPkceVerifierV1, pkceChallengeV1 } from "../src/google_auth/pkce.js";
import { consumeGoogleOAuthTransactionV1, createGoogleOAuthTransactionV1, linkVerifiedGoogleIdentityV1, readGoogleOAuthTransactionV1 } from "../src/google_auth/store.js";
import { googleAuthRoutes } from "../src/google_auth/routes.js";
import type { PgDriverV1 } from "../src/adapters/neon_admin.js";
import { decryptTotpSecretV1 } from "../src/adapters/neon_admin.js";

const NOW = 1_800_000_000;
const AUDIENCE = "google-client-id.apps.googleusercontent.com";
const NONCE = "test-nonce-123456789012345678901234";
const KEY_ID = "synthetic-test-key";
let keys: CryptoKeyPair;
let jwk: JsonWebKey;

function b64url(bytes: Uint8Array): string {
  let raw = "";
  for (const byte of bytes) raw += String.fromCharCode(byte);
  return btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function encode(value: unknown): string {
  return b64url(new TextEncoder().encode(JSON.stringify(value)));
}
async function token(claimPatch: Record<string, unknown> = {}, keyPair = keys): Promise<string> {
  const head = encode({ alg: "RS256", kid: KEY_ID, typ: "JWT" });
  const claims = encode({ iss: "https://accounts.google.com", aud: AUDIENCE, exp: NOW + 600, iat: NOW,
    nonce: NONCE, email_verified: true, sub: "google-subject-1", email: "User@example.test", ...claimPatch });
  const input = head + "." + claims;
  const signature = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", keyPair.privateKey,
    new TextEncoder().encode(input)));
  return input + "." + b64url(signature);
}
function fetchJwks(): typeof fetch {
  return async () => new Response(JSON.stringify({ keys: [{ ...jwk, kid: KEY_ID, alg: "RS256", use: "sig" }] }),
    { status: 200, headers: { "Content-Type": "application/json" } });
}

beforeAll(async () => {
  keys = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
  jwk = await crypto.subtle.exportKey("jwk", keys.publicKey);
});

describe("Google OIDC verification", () => {
  it("accepts a signed, verified, nonce-bound identity and hash-only nonce", async () => {
    const idToken = await token();
    const expected = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(NONCE)));
    const nonce_sha256 = Array.from(expected, (byte) => byte.toString(16).padStart(2, "0")).join("");
    const identity = await verifyGoogleIdentityTokenV1(idToken, { audience: AUDIENCE, nonce_sha256,
      now_unix_seconds: NOW, fetcher: fetchJwks() });
    expect(identity).toMatchObject({ subject: "google-subject-1", email: "user@example.test", email_verified: true });
  });

  it("rejects a forged signature", async () => {
    const attacker = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
    await expect(verifyGoogleIdentityTokenV1(await token({}, attacker), { audience: AUDIENCE, nonce: NONCE,
      now_unix_seconds: NOW, fetcher: fetchJwks() })).rejects.toMatchObject({ code: "INVALID_GOOGLE_SIGNATURE" });
  });

  it.each([
    { exp: NOW },
    { aud: "another-client.apps.googleusercontent.com" },
    { email_verified: false },
    { nonce: "different-nonce-123456789012345678" },
  ])("rejects invalid claims", async (patch) => {
    await expect(verifyGoogleIdentityTokenV1(await token(patch), { audience: AUDIENCE, nonce: NONCE,
      now_unix_seconds: NOW, fetcher: fetchJwks() })).rejects.toBeInstanceOf(GoogleIdentityErrorV1);
  });
});

describe("PKCE state", () => {
  it("creates an S256 challenge and binds encrypted web verifier to the transaction", async () => {
    const pair = await createPkcePairV1();
    expect(await pkceChallengeV1(pair.verifier)).toBe(pair.challenge);
    const secret = b64url(crypto.getRandomValues(new Uint8Array(32)));
    const stateHash = "a".repeat(64);
    const cipher = await encryptWebPkceVerifierV1(pair.verifier, stateHash, secret);
    expect(await decryptWebPkceVerifierV1(cipher, stateHash, secret)).toBe(pair.verifier);
    await expect(decryptWebPkceVerifierV1(cipher, "b".repeat(64), secret)).rejects.toThrow("OAUTH_STATE_UNAVAILABLE");
  });
});

class LinkingDriver implements PgDriverV1 {
  linked = false;
  async query<Row>(sql: string, params: readonly unknown[]): Promise<{ rows: Row[] }> {
    if (sql.includes("FROM licensing_google_identities WHERE provider='GOOGLE' AND subject=$1")) {
      return { rows: (this.linked ? [{ org_id: "org-1", user_id: "user-1", email: "user@example.test" }] : []) as Row[] };
    }
    if (sql.includes("FROM licensing_users WHERE lower(email)=lower($1)") || sql.includes("FROM licensing_users WHERE org_id=$1 AND user_id=$2")) {
      return { rows: [{ org_id: "org-1", user_id: "user-1", email: "user@example.test", role_id: "member",
        active: true, totp_enrolled: false }] as Row[] };
    }
    if (sql.startsWith("INSERT INTO licensing_google_identities")) {
      this.linked = true;
      return { rows: [{ org_id: "org-1", user_id: "user-1" }] as Row[] };
    }
    if (sql.startsWith("UPDATE licensing_google_identities")) return { rows: [] };
    if (sql.startsWith("INSERT INTO licensing_audit_events")) return { rows: [] };
    throw new Error("unexpected query");
  }
  transaction<T>(work: (tx: import("../src/db/repository.js").PgQueryV1) => Promise<T>): Promise<T> {
    return work(this);
  }
}

class AdminEnrollmentDriver implements PgDriverV1 {
  row: Record<string, unknown> | null = null;
  deviceId: string | null = null;
  secretCiphertext: string | null = null;
  enrollment: { token_digest: string; session_id: string; device_id: string; expires_at_utc_ns: string } | null = null;
  enrolled = false;
  lastStep: string | null = null;
  readonly orgId = "org-1";
  readonly userId = "user-1";

  async query<Row>(sql: string, params: readonly unknown[]): Promise<{ rows: Row[] }> {
    if (sql.startsWith("INSERT INTO licensing_google_oauth_transactions")) {
      this.row = { state_sha256: params[0], flow: params[1], nonce_sha256: params[2], code_challenge: params[3],
        verifier_ciphertext: params[4], redirect_uri: params[5], device_id: params[6], return_to: params[7],
        expires_at_utc_ns: params[9], consumed_at_utc_ns: null };
      return { rows: [] };
    }
    if (sql.startsWith("SELECT flow,state_sha256")) {
      return { rows: this.row && this.row.state_sha256 === params[0] ? [this.row] as Row[] : [] };
    }
    if (sql.startsWith("UPDATE licensing_google_oauth_transactions")) {
      if (!this.row || this.row.state_sha256 !== params[0] || this.row.flow !== params[1]
          || this.row.consumed_at_utc_ns !== null || BigInt(String(this.row.expires_at_utc_ns)) <= BigInt(String(params[2]))) return { rows: [] };
      this.row.consumed_at_utc_ns = params[2];
      return { rows: [this.row] as Row[] };
    }
    if (sql.includes("FROM licensing_google_identities WHERE provider='GOOGLE' AND subject=$1")) return { rows: [] };
    if (sql.includes("FROM licensing_users WHERE lower(email)=lower($1)")) {
      return { rows: [{ org_id: this.orgId, user_id: this.userId, email: "user@example.test", role_id: "admin",
        owner: true, active: true, totp_enrolled: this.enrolled, totp_secret_ciphertext: this.secretCiphertext,
        totp_last_step: this.lastStep }] as Row[] };
    }
    if (sql.includes("FROM licensing_users WHERE org_id=$1 AND user_id=$2 AND active=TRUE")) {
      return { rows: [{ org_id: this.orgId, user_id: this.userId, email: "user@example.test", role_id: "admin",
        owner: true, active: true, totp_enrolled: this.enrolled, totp_secret_ciphertext: this.secretCiphertext,
        totp_last_step: this.lastStep }] as Row[] };
    }
    if (sql.startsWith("SELECT role_id,owner,totp_enrolled")) {
      return { rows: [{ role_id: "admin", owner: true, totp_enrolled: this.enrolled,
        totp_secret_ciphertext: this.secretCiphertext, totp_last_step: this.lastStep }] as Row[] };
    }
    if (sql.startsWith("INSERT INTO licensing_google_identities")) return { rows: [{ org_id: this.orgId, user_id: this.userId }] as Row[] };
    if (sql.startsWith("UPDATE licensing_google_identities")) return { rows: [] };
    if (sql.startsWith("INSERT INTO licensing_audit_events")) return { rows: [] };
    if (sql.startsWith("INSERT INTO licensing_devices")) {
      this.deviceId = String(params[0]);
      return { rows: [{ device_id: this.deviceId }] as Row[] };
    }
    if (sql.startsWith("UPDATE licensing_users SET totp_secret_ciphertext")) {
      this.secretCiphertext = String(params[2]);
      return { rows: [{ user_id: this.userId }] as Row[] };
    }
    if (sql.startsWith("INSERT INTO licensing_admin_sessions")) {
      if (String(params[4]) !== this.deviceId) throw new Error("wrong enrollment device");
      this.enrollment = { session_id: String(params[0]), token_digest: String(params[1]),
        device_id: String(params[4]), expires_at_utc_ns: String(params[6]) };
      return { rows: [] };
    }
    if (sql.startsWith("SELECT s.org_id,s.user_id,s.device_id,s.expires_at_utc_ns::text")) {
      if (!this.enrollment || params[0] !== this.enrollment.token_digest || params[1] !== this.enrollment.device_id) return { rows: [] };
      return { rows: [{ org_id: this.orgId, user_id: this.userId, device_id: this.deviceId,
        expires_at_utc_ns: this.enrollment.expires_at_utc_ns, session_id: this.enrollment.session_id }] as Row[] };
    }
    if (sql.startsWith("SELECT totp_secret_ciphertext,totp_last_step::text AS totp_last_step")) {
      return { rows: [{ totp_secret_ciphertext: this.secretCiphertext, totp_last_step: this.lastStep,
        totp_enrolled: this.enrolled }] as Row[] };
    }
    if (sql.startsWith("UPDATE licensing_users SET totp_enrolled=TRUE")) {
      this.enrolled = true; this.lastStep = String(params[2]);
      return { rows: [{ user_id: this.userId }] as Row[] };
    }
    if (sql.startsWith("UPDATE licensing_admin_sessions SET revoked_at_utc_ns")) return { rows: [] };
    throw new Error("unexpected query");
  }
  transaction<T>(work: (tx: import("../src/db/repository.js").PgQueryV1) => Promise<T>): Promise<T> {
    return work(this);
  }
}

async function totpCodeAt(secret: string, unixSeconds: number): Promise<string> {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let buffer = 0; let bits = 0; const decoded: number[] = [];
  for (const char of secret) {
    buffer = (buffer << 5) | alphabet.indexOf(char); bits += 5;
    if (bits >= 8) { bits -= 8; decoded.push((buffer >> bits) & 255); }
  }
  const keyBytes = new Uint8Array(decoded);
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const counter = BigInt(Math.floor(unixSeconds / 30)); const message = new Uint8Array(8);
  new DataView(message.buffer).setBigUint64(0, counter, false);
  const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, message));
  const offset = digest[digest.length - 1]! & 15;
  const binary = ((digest[offset]! & 127) << 24) | (digest[offset + 1]! << 16)
    | (digest[offset + 2]! << 8) | digest[offset + 3]!;
  return String(binary % 1_000_000).padStart(6, "0");
}

describe("Google account linking", () => {
  it("links by verified email once and reuses the existing Google subject", async () => {
    const driver = new LinkingDriver();
    const identity = Object.freeze({ subject: "google-subject-1", email: "user@example.test", email_verified: true as const,
      name: null, picture: null });
    expect(await linkVerifiedGoogleIdentityV1(driver, identity, "1800000000000000000")).toMatchObject({ user_id: "user-1" });
    expect(await linkVerifiedGoogleIdentityV1(driver, identity, "1800000001000000000")).toMatchObject({ user_id: "user-1" });
    expect(driver.linked).toBe(true);
  });

  it("fails closed when verified email matches multiple licensing users", async () => {
    const driver = new LinkingDriver();
    const original = driver.query.bind(driver);
    driver.query = async <Row>(sql: string, params: readonly unknown[]) => {
      if (sql.includes("FROM licensing_users WHERE lower(email)=lower($1)")) {
        const account = { org_id: "org-1", user_id: "user-1", email: "user@example.test", role_id: "member",
          active: true, totp_enrolled: false };
        return { rows: [account, { ...account, org_id: "org-2", user_id: "user-2" }] as Row[] };
      }
      return original(sql, params);
    };
    const identity = Object.freeze({ subject: "google-subject-2", email: "user@example.test", email_verified: true as const,
      name: null, picture: null });
    await expect(linkVerifiedGoogleIdentityV1(driver, identity, "1800000000000000000"))
      .rejects.toMatchObject({ code: "ACCOUNT_LINK_CONFLICT" });
  });
});

class StateDriver implements PgDriverV1 {
  row: Record<string, unknown> | null = null;
  async query<Row>(sql: string, params: readonly unknown[]): Promise<{ rows: Row[] }> {
    if (sql.startsWith("INSERT INTO licensing_google_oauth_transactions")) {
      this.row = { state_sha256: params[0], flow: params[1], nonce_sha256: params[2], code_challenge: params[3],
        verifier_ciphertext: params[4], redirect_uri: params[5], device_id: params[6], return_to: params[7],
        expires_at_utc_ns: params[9], consumed_at_utc_ns: null };
      return { rows: [] };
    }
    if (sql.startsWith("SELECT flow,state_sha256")) {
      return { rows: this.row && this.row.state_sha256 === params[0] ? [this.row] as Row[] : [] };
    }
    if (sql.startsWith("UPDATE licensing_google_oauth_transactions")) {
      if (!this.row || this.row.state_sha256 !== params[0] || this.row.flow !== params[1]
          || this.row.consumed_at_utc_ns !== null || BigInt(String(this.row.expires_at_utc_ns)) <= BigInt(String(params[2]))) {
        return { rows: [] };
      }
      this.row.consumed_at_utc_ns = params[2];
      return { rows: [this.row] as Row[] };
    }
    throw new Error("unexpected state query");
  }
  transaction<T>(work: (tx: import("../src/db/repository.js").PgQueryV1) => Promise<T>): Promise<T> {
    return work(this);
  }
}

describe("one-time OAuth state", () => {
  it("stores only state/nonce digests and consumes the transaction once", async () => {
    const driver = new StateDriver();
    const state = "state-value-that-is-long-enough-for-tests-0001";
    const nonce = "nonce-value-that-is-long-enough-for-tests-0001";
    const challenge = "A".repeat(43);
    await createGoogleOAuthTransactionV1(driver, { flow: "DESKTOP", state, nonce, code_challenge: challenge,
      verifier_ciphertext: null, redirect_uri: "http://127.0.0.1:43210/oauth/callback", device_id: "device-1",
      return_to: null, now_utc_ns: "1800000000000000000" });
    expect(JSON.stringify(driver.row)).not.toContain(state);
    expect(JSON.stringify(driver.row)).not.toContain(nonce);
    expect(await readGoogleOAuthTransactionV1(driver, state, "DESKTOP")).toMatchObject({ code_challenge: challenge });
    expect(await consumeGoogleOAuthTransactionV1(driver, state, "DESKTOP", "1800000001000000000")).not.toBeNull();
    expect(await consumeGoogleOAuthTransactionV1(driver, state, "DESKTOP", "1800000002000000000")).toBeNull();
    expect(await consumeGoogleOAuthTransactionV1(driver, state, "DESKTOP", "1800000600000000000")).toBeNull();
  });

  it("returns a Google authorization URL for a validated loopback redirect", async () => {
    const driver = new StateDriver();
    const response = await googleAuthRoutes(new Request("https://worker.test/v1/auth/google/desktop/start", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ device_id: "device-1", redirect_uri: "http://127.0.0.1:42123/oauth/callback",
        code_challenge: "B".repeat(43) }),
    }), { driver, auth: {} as never, desktop_client_id: AUDIENCE, web_client_id: "", web_client_secret: "",
      web_callback_uri: "", web_success_url: "", state_encryption_key: "", now_unix_seconds: () => NOW,
      now_utc_ns: () => "1800000000000000000", request_id: () => "req-1" });
    expect(response?.status).toBe(200);
    const payload = await response!.json() as { data: { authorization_url: string; state: string } };
    const authUrl = new URL(payload.data.authorization_url);
    expect(authUrl.origin + authUrl.pathname).toBe("https://accounts.google.com/o/oauth2/v2/auth");
    expect(authUrl.searchParams.get("redirect_uri")).toBe("http://127.0.0.1:42123/oauth/callback");
    expect(authUrl.searchParams.get("code_challenge_method")).toBe("S256");
    expect(typeof payload.data.state).toBe("string");
  });

  it("requires TOTP enrollment for an admin Google account and accepts one bound confirmation", async () => {
    const driver = new AdminEnrollmentDriver();
    const encryptionKey = btoa(String.fromCharCode(...new Uint8Array(32).fill(7)));
    const deps = { driver, auth: { totp_encryption_key: encryptionKey } as never, desktop_client_id: AUDIENCE,
      web_client_id: "", web_client_secret: "", web_callback_uri: "", web_success_url: "",
      state_encryption_key: "", now_unix_seconds: () => NOW, now_utc_ns: () => "1800000000000000000",
      request_id: () => "request-1", fetcher: fetchJwks() };
    const start = await googleAuthRoutes(new Request("https://worker.test/v1/auth/google/desktop/start", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ device_id: "device-1", redirect_uri: "http://127.0.0.1:42123/oauth/callback",
        code_challenge: "C".repeat(43) }),
    }), deps);
    const startData = await start!.json() as { data: { authorization_url: string; state: string } };
    const authUrl = new URL(startData.data.authorization_url);
    const idToken = await token({ nonce: authUrl.searchParams.get("nonce")! });
    const complete = await googleAuthRoutes(new Request("https://worker.test/v1/auth/google/desktop/complete", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ state: startData.data.state, device_id: "device-1", id_token: idToken }),
    }), deps);
    const enrollment = await complete!.json() as { data: { totp_state: string; enrollment_token: string; otpauth_uri: string } };
    expect(enrollment.data.totp_state).toBe("ENROLLMENT_REQUIRED");
    expect(enrollment.data.otpauth_uri).toMatch(/^otpauth:\/\/totp\//);
    expect(driver.enrollment?.token_digest).not.toBe(enrollment.data.enrollment_token);
    const secret = new URL(enrollment.data.otpauth_uri).searchParams.get("secret")!;
    const confirmation = await googleAuthRoutes(new Request("https://worker.test/v1/auth/google/desktop/totp/confirm", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ device_id: "device-1", enrollment_token: enrollment.data.enrollment_token,
        code: await totpCodeAt(secret, NOW) }),
    }), deps);
    expect(confirmation?.status).toBe(200);
    expect(await confirmation!.json()).toMatchObject({ data: { totp_state: "ENROLLED" } });
    expect(driver.enrolled).toBe(true);
  });
});
