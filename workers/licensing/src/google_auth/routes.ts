import type { AuthApiDependenciesV1 } from "../auth_api/routes.js";
import { issueLicenseSnapshotV1 } from "../auth_api/routes.js";
import type { PgDriverV1 } from "../adapters/neon_admin.js";
import type { SignupDependenciesV1 } from "../signup/models.js";
import { decryptTotpSecretV1, encryptTotpSecretV1, verifyTotpStepV1 } from "../adapters/neon_admin.js";
import { createOAuthSecretsV1, createPkcePairV1, encryptWebPkceVerifierV1, decryptWebPkceVerifierV1, pkceChallengeV1 } from "./pkce.js";
import { googleAuthorizationUrlV1, verifyGoogleIdentityTokenV1 } from "./oidc.js";
import { consumeGoogleOAuthTransactionV1, createGoogleOAuthTransactionV1, linkVerifiedGoogleIdentityV1, readGoogleOAuthTransactionV1, sha256HexV1 } from "./store.js";

const NS = 1_000_000_000n;
const ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
const TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token";
const SAFE_MESSAGE = "Google authentication could not be completed.";
const TOTP_CODE = /^\d{6}$/;

export interface GoogleAuthDependenciesV1 {
  readonly driver: PgDriverV1;
  readonly auth: AuthApiDependenciesV1;
  readonly signup?: SignupDependenciesV1;
  readonly desktop_client_id: string;
  readonly web_client_id: string;
  readonly web_client_secret: string;
  readonly web_callback_uri: string;
  readonly web_success_url: string;
  readonly state_encryption_key: string;
  readonly fetcher?: typeof fetch;
  readonly now_unix_seconds: () => number;
  readonly now_utc_ns: () => string;
  readonly request_id: () => string;
  readonly crypto_api?: Crypto;
}

function json(body: unknown, status = 200, headers: HeadersInit = {}): Response {
  const outputHeaders = new Headers({ "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" });
  new Headers(headers).forEach((value, key) => outputHeaders.set(key, value));
  return new Response(JSON.stringify(body), { status, headers: outputHeaders });
}
function error(code: string, status = 401): Response {
  return json({ schema_version: 1, error: { code, message: SAFE_MESSAGE } }, status);
}
function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}
async function parse(request: Request, required: readonly string[], optional: readonly string[] = []): Promise<Record<string, unknown> | null> {
  if (!/^application\/json(?:\s*;|$)/i.test(request.headers.get("content-type") ?? "")) return null;
  let bytes: Uint8Array;
  try { bytes = new Uint8Array(await request.arrayBuffer()); } catch { return null; }
  if (bytes.byteLength > 8192) return null;
  try {
    const value: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    if (!isRecord(value) || Object.getOwnPropertySymbols(value).length !== 0
        || Object.keys(value).some((key) => !required.includes(key) && !optional.includes(key))
        || required.some((key) => !Object.prototype.hasOwnProperty.call(value, key))) return null;
    return value;
  } catch { return null; }
}
function randomToken(cryptoApi: Crypto, bytes = 32): string {
  const data = cryptoApi.getRandomValues(new Uint8Array(bytes));
  let raw = ""; for (const value of data) raw += String.fromCharCode(value);
  return btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function base32(bytes: Uint8Array): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let buffer = 0; let bits = 0; let output = "";
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte; bits += 8;
    while (bits >= 5) { bits -= 5; output += alphabet[(buffer >> bits) & 31]; }
  }
  if (bits > 0) output += alphabet[(buffer << (5 - bits)) & 31];
  return output;
}
function createTotpSeed(cryptoApi: Crypto): string {
  return base32(cryptoApi.getRandomValues(new Uint8Array(20)));
}
function totpUri(email: string, secret: string): string {
  const issuer = encodeURIComponent("Leviathan AI");
  return `otpauth://totp/${issuer}:${encodeURIComponent(email)}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`;
}
async function ensureGoogleDevice(
  deps: GoogleAuthDependenciesV1, account: { readonly org_id: string; readonly user_id: string }, deviceId: string,
): Promise<boolean> {
  const now = nowNs(deps);
  const inserted = await deps.driver.query<{ device_id: string }>(
    "INSERT INTO licensing_devices(device_id,org_id,user_id,status,created_at_utc_ns,last_seen_at_utc_ns) VALUES ($1,$2,$3,'ACTIVE',$4,$4) ON CONFLICT(device_id) DO NOTHING RETURNING device_id",
    [deviceId, account.org_id, account.user_id, now]);
  if (inserted.rows.length === 1) return true;
  const existing = await deps.driver.query<{ device_id: string; org_id: string; user_id: string; status: string }>(
    "SELECT device_id,org_id,user_id,status FROM licensing_devices WHERE device_id=$1", [deviceId]);
  const row = existing.rows[0];
  return row?.device_id === deviceId && row.org_id === account.org_id
    && row.user_id === account.user_id && row.status === "ACTIVE";
}
function safeLoopbackRedirect(value: unknown): value is string {
  if (typeof value !== "string" || value.length > 2048) return false;
  try {
    const url = new URL(value);
    return url.protocol === "http:" && url.hostname === "127.0.0.1"
      && url.port.length > 0 && url.pathname === "/oauth/callback"
      && url.username === "" && url.password === "" && url.search === "" && url.hash === "";
  } catch { return false; }
}
function nowNs(deps: GoogleAuthDependenciesV1): string { return deps.now_utc_ns(); }
function b64url(bytes: Uint8Array): string {
  let raw = ""; for (const byte of bytes) raw += String.fromCharCode(byte);
  return btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function toBuffer(bytes: Uint8Array): ArrayBuffer { const output = new ArrayBuffer(bytes.length); new Uint8Array(output).set(bytes); return output; }
async function digest(value: string): Promise<string> { return sha256HexV1(value); }
function redirect(location: string): Response {
  return new Response(null, { status: 303, headers: { Location: location, "Cache-Control": "no-store" } });
}
async function checkoutForPendingAccount(
  deps: GoogleAuthDependenciesV1,
  input: { readonly pending_account_id: string; readonly org_id: string;
    readonly org_name: string; readonly owner_email: string; readonly device_id: string },
): Promise<Response> {
  if (!deps.signup) return error("SIGNUP_UNAVAILABLE", 503);
  const checkout = await deps.signup.stripe.createCheckoutSession({
    pending_account_id: input.pending_account_id, org_id: input.org_id,
    org_name: input.org_name, owner_email: input.owner_email, device_id: input.device_id,
    idempotency_key: "google-checkout-" + input.pending_account_id,
    price_id: deps.signup.config.stripe_price_id, success_url: deps.signup.config.success_url,
    cancel_url: deps.signup.config.cancel_url,
  });
  let checkoutUrl: URL;
  try { checkoutUrl = new URL(checkout.checkout_url); } catch { return error("CHECKOUT_UNAVAILABLE", 503); }
  if (checkoutUrl.protocol !== "https:" || checkoutUrl.hostname !== "checkout.stripe.com") return error("CHECKOUT_UNAVAILABLE", 503);
  return redirect(checkoutUrl.toString());
}

async function beginDesktop(request: Request, deps: GoogleAuthDependenciesV1): Promise<Response> {
  const body = await parse(request, ["device_id", "redirect_uri", "code_challenge"]);
  if (!body || typeof body.device_id !== "string" || !ID.test(body.device_id)
      || !safeLoopbackRedirect(body.redirect_uri)
      || typeof body.code_challenge !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(body.code_challenge)
      || !deps.desktop_client_id) return error("INVALID_REQUEST", 400);
  const cryptoApi = deps.crypto_api ?? globalThis.crypto;
  const { state, nonce } = createOAuthSecretsV1(cryptoApi);
  await createGoogleOAuthTransactionV1(deps.driver, { flow: "DESKTOP", state, nonce,
    code_challenge: body.code_challenge, verifier_ciphertext: null, redirect_uri: body.redirect_uri,
    device_id: body.device_id, return_to: null, now_utc_ns: nowNs(deps) });
  const url = googleAuthorizationUrlV1({ client_id: deps.desktop_client_id, redirect_uri: body.redirect_uri,
    state, nonce, code_challenge: body.code_challenge });
  return json({ schema_version: 1, data: { authorization_url: url, state } });
}

async function exchangeWebCode(code: string, verifier: string, deps: GoogleAuthDependenciesV1): Promise<string> {
  const form = new URLSearchParams({ code, client_id: deps.web_client_id, client_secret: deps.web_client_secret,
    redirect_uri: deps.web_callback_uri, grant_type: "authorization_code", code_verifier: verifier });
  let response: Response;
  try { response = await (deps.fetcher ?? fetch)(TOKEN_ENDPOINT, { method: "POST", redirect: "error",
    headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: form }); }
  catch { throw new Error("GOOGLE_TOKEN_UNAVAILABLE"); }
  if (!response.ok) throw new Error("GOOGLE_TOKEN_UNAVAILABLE");
  let payload: unknown;
  try {
    const reader = response.body?.getReader();
    if (!reader) throw new Error("body unavailable");
    const chunks: Uint8Array[] = []; let total = 0;
    while (true) {
      const part = await reader.read();
      if (part.done) break;
      total += part.value.byteLength;
      if (total > 32_768) { await reader.cancel(); throw new Error("body too large"); }
      chunks.push(part.value);
    }
    const bytes = new Uint8Array(total); let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    payload = JSON.parse(text) as unknown;
  } catch { throw new Error("GOOGLE_TOKEN_UNAVAILABLE"); }
  if (!isRecord(payload) || typeof payload.id_token !== "string" || payload.id_token.length > 32_768) {
    throw new Error("GOOGLE_TOKEN_UNAVAILABLE");
  }
  return payload.id_token;
}

async function webStart(request: Request, deps: GoogleAuthDependenciesV1): Promise<Response> {
  const url = new URL(request.url);
  if (request.method !== "GET" || url.searchParams.get("intent") !== "signup"
      || url.searchParams.size !== 1 || !deps.web_client_id || !deps.web_client_secret
      || !validWebConfig(deps)) return error("NOT_CONFIGURED", 503);
  const cryptoApi = deps.crypto_api ?? globalThis.crypto;
  const { state, nonce } = createOAuthSecretsV1(cryptoApi);
  const pair = await createPkcePairV1(cryptoApi);
  const stateHash = await digest(state);
  const verifier = await encryptWebPkceVerifierV1(pair.verifier, stateHash, deps.state_encryption_key, cryptoApi);
  await createGoogleOAuthTransactionV1(deps.driver, { flow: "WEB", state, nonce,
    code_challenge: pair.challenge, verifier_ciphertext: verifier, redirect_uri: deps.web_callback_uri,
    device_id: null, return_to: "signup", now_utc_ns: nowNs(deps) });
  const location = googleAuthorizationUrlV1({ client_id: deps.web_client_id, redirect_uri: deps.web_callback_uri,
    state, nonce, code_challenge: pair.challenge });
  return redirect(location);
}
function validWebConfig(deps: GoogleAuthDependenciesV1): boolean {
  try {
    const callback = new URL(deps.web_callback_uri); const success = new URL(deps.web_success_url);
    return callback.protocol === "https:" && callback.hostname === "leviathan-licensing-worker.ocean824.workers.dev"
      && callback.pathname === "/v1/auth/google/web/callback" && callback.search === "" && callback.hash === ""
      && success.protocol === "https:" && success.hostname === "leviathan-licensing-worker.ocean824.workers.dev"
      && success.pathname === "/v1/signup/success" && success.search === "" && success.hash === ""
      && !success.username && !success.password;
  } catch { return false; }
}

async function webCallback(request: Request, deps: GoogleAuthDependenciesV1): Promise<Response> {
  const url = new URL(request.url);
  const state = url.searchParams.get("state") ?? "";
  const code = url.searchParams.get("code") ?? "";
  if (request.method !== "GET" || url.searchParams.size !== 2 || code.length < 8 || code.length > 4096) {
    return error("INVALID_REQUEST", 400);
  }
  const transaction = await consumeGoogleOAuthTransactionV1(deps.driver, state, "WEB", nowNs(deps));
  if (!transaction?.verifier_ciphertext || !validWebConfig(deps)) return error("OAUTH_STATE_UNAVAILABLE", 400);
  let idToken: string;
  try {
    const verifier = await decryptWebPkceVerifierV1(transaction.verifier_ciphertext, transaction.state_sha256,
      deps.state_encryption_key, deps.crypto_api ?? globalThis.crypto);
    idToken = await exchangeWebCode(code, verifier, deps);
  } catch { return error("GOOGLE_AUTH_UNAVAILABLE", 401); }
  let identity;
  try {
    identity = await verifyGoogleIdentityTokenV1(idToken, { audience: deps.web_client_id,
      nonce_sha256: transaction.nonce_sha256, now_unix_seconds: deps.now_unix_seconds(), fetcher: deps.fetcher,
      crypto_api: deps.crypto_api });
  } catch { return error("GOOGLE_AUTH_UNAVAILABLE", 401); }

  const found = await deps.driver.query<{ org_id: string; user_id: string }>(
    "SELECT org_id,user_id FROM licensing_users WHERE lower(email)=lower($1) LIMIT 1", [identity.email]);
  if (found.rows.length === 0) {
    if (!deps.signup) return error("SIGNUP_UNAVAILABLE", 503);
    const pending = await deps.signup.pending_signups.createPending({ org_name: identity.name?.trim().slice(0, 120) || "Leviathan account",
      owner_email: identity.email, device_id: "google-web-" + transaction.state_sha256.slice(0, 24),
      idempotency_key: "google-" + transaction.state_sha256.slice(0, 48) });
    await linkVerifiedGoogleIdentityV1(deps.driver, identity, nowNs(deps));
    return checkoutForPendingAccount(deps, { pending_account_id: pending.resource_id,
      org_id: pending.org_id, org_name: identity.name?.trim().slice(0, 120) || "Leviathan account",
      owner_email: identity.email, device_id: pending.device_id });
  }
  const account = await linkVerifiedGoogleIdentityV1(deps.driver, identity, nowNs(deps));
  if (!account.active && deps.signup) {
    const pending = await deps.driver.query<{ pending_account_id: string; device_id: string }>(
      "SELECT pending_account_id,device_id FROM licensing_pending_signups WHERE org_id=$1 AND owner_user_id=$2 AND status='PENDING' LIMIT 1",
      [account.org_id, account.user_id]);
    const row = pending.rows[0];
    if (row) return checkoutForPendingAccount(deps, { pending_account_id: row.pending_account_id,
      org_id: account.org_id, org_name: identity.name?.trim().slice(0, 120) || "Leviathan account",
      owner_email: identity.email, device_id: row.device_id });
  }
  if (!account.active) return redirect(deps.web_success_url + (deps.web_success_url.includes("?") ? "&" : "?") + "google_auth=pending");
  return redirect(deps.web_success_url + (deps.web_success_url.includes("?") ? "&" : "?") + "google_auth=complete");
}

async function issueGoogleSession(
  request: Request, body: Record<string, unknown>, deps: GoogleAuthDependenciesV1,
): Promise<Response> {
  const state = body.state; const deviceId = body.device_id; const idToken = body.id_token;
  if (typeof state !== "string" || typeof deviceId !== "string" || !ID.test(deviceId)
      || typeof idToken !== "string" || idToken.length > 32_768) return error("INVALID_REQUEST", 400);
  const pending = await readGoogleOAuthTransactionV1(deps.driver, state, "DESKTOP");
  if (!pending || pending.device_id !== deviceId) return error("OAUTH_STATE_UNAVAILABLE", 401);
  const consumed = await consumeGoogleOAuthTransactionV1(deps.driver, state, "DESKTOP", nowNs(deps));
  if (!consumed) return error("OAUTH_STATE_UNAVAILABLE", 401);
  let identity;
  try {
    identity = await verifyGoogleIdentityTokenV1(idToken, { audience: deps.desktop_client_id,
      nonce_sha256: consumed.nonce_sha256, now_unix_seconds: deps.now_unix_seconds(), fetcher: deps.fetcher,
      crypto_api: deps.crypto_api });
  } catch { return error("GOOGLE_AUTH_UNAVAILABLE", 401); }
  const account = await linkVerifiedGoogleIdentityV1(deps.driver, identity, nowNs(deps));
  if (!account.active) return error("ACCOUNT_INACTIVE", 403);
  const userResult = await deps.driver.query<{ role_id: string; owner: boolean; totp_enrolled: boolean;
    totp_secret_ciphertext: string | null; totp_last_step: string | null }>(
    "SELECT role_id,owner,totp_enrolled,totp_secret_ciphertext,totp_last_step::text AS totp_last_step FROM licensing_users WHERE org_id=$1 AND user_id=$2 AND active=TRUE LIMIT 1",
    [account.org_id, account.user_id]);
  const user = userResult.rows[0]; if (!user) return error("AUTHENTICATION_FAILED", 401);
  const adminRole = user.owner === true || ["admin", "owner"].includes(user.role_id.toLowerCase());
  const bodyTotp = body.totp_code;
  if (user.totp_enrolled && typeof bodyTotp !== "string") return error("TOTP_REQUIRED", 401);
  if (!user.totp_enrolled && adminRole) {
    if (!await ensureGoogleDevice(deps, account, deviceId)) return error("DEVICE_UNAVAILABLE", 403);
    const cryptoApi = deps.crypto_api ?? globalThis.crypto;
    let secret: string;
    if (user.totp_secret_ciphertext) {
      secret = await decryptTotpSecretV1(user.totp_secret_ciphertext, deps.auth.totp_encryption_key,
        account.org_id, account.user_id, cryptoApi);
    } else {
      secret = createTotpSeed(cryptoApi);
      const encrypted = await encryptTotpSecretV1(secret, deps.auth.totp_encryption_key,
        account.org_id, account.user_id, cryptoApi);
      const changed = await deps.driver.query(
        "UPDATE licensing_users SET totp_secret_ciphertext=$3 WHERE org_id=$1 AND user_id=$2 AND totp_enrolled=FALSE AND totp_secret_ciphertext IS NULL RETURNING user_id",
        [account.org_id, account.user_id, encrypted],
      );
      if (changed.rows.length !== 1) return error("TOTP_ENROLLMENT_UNAVAILABLE", 503);
    }
    const enrollmentToken = randomToken(cryptoApi);
    const issued = nowNs(deps);
    const expires = (BigInt(issued) + 300n * NS).toString();
    const sessionId = "session-" + randomToken(cryptoApi, 16);
    await deps.driver.transaction(async (tx) => {
      await tx.query("INSERT INTO licensing_admin_sessions(session_id,token_digest,org_id,user_id,device_id,session_kind,issued_at_utc_ns,expires_at_utc_ns) VALUES ($1,$2,$3,$4,$5,'TOTP_ENROLLMENT',$6,$7)",
        [sessionId, await digest(enrollmentToken), account.org_id, account.user_id, deviceId, issued, expires]);
      await tx.query("INSERT INTO licensing_audit_events(id,org_id,actor,action,resource,digest,created_at_utc_ns) VALUES ($1,$2,$3,'auth.google.totp.enrollment.start',$4,$5,$6)",
        ["audit-" + randomToken(cryptoApi, 16), account.org_id, account.user_id,
          `user:${account.user_id}`, await digest(user.totp_secret_ciphertext ?? "enrollment"), issued]);
    });
    return json({ schema_version: 1, data: { totp_state: "ENROLLMENT_REQUIRED",
      enrollment_token: enrollmentToken, otpauth_uri: totpUri(identity.email, secret) } });
  }
  if (user.totp_enrolled) {
    if (!TOTP_CODE.test(bodyTotp as string) || !user.totp_secret_ciphertext) return error("TOTP_REQUIRED", 401);
    const secret = await decryptTotpSecretV1(user.totp_secret_ciphertext, deps.auth.totp_encryption_key, account.org_id, account.user_id);
    const step = await verifyTotpStepV1(secret, bodyTotp as string, deps.now_unix_seconds(),
      user.totp_last_step === null ? null : BigInt(user.totp_last_step));
    if (step === null) return error("TOTP_REQUIRED", 401);
    const snapshot = await issueLicenseSnapshotV1(deps.auth, account.org_id, deviceId);
    if (!await ensureGoogleDevice(deps, account, deviceId)) return error("DEVICE_UNAVAILABLE", 403);
    const token = randomToken(deps.crypto_api ?? globalThis.crypto);
    const tokenDigest = await digest(token); const issued = nowNs(deps);
    const expires = (BigInt(issued) + BigInt(deps.auth.user_session_ttl_s) * NS).toString();
    const sessionId = "session-" + randomToken(deps.crypto_api ?? globalThis.crypto, 16);
    await deps.driver.transaction(async (tx) => {
      const wrote = await tx.query("UPDATE licensing_users SET totp_last_step=$3 WHERE org_id=$1 AND user_id=$2 AND totp_enrolled=TRUE AND (totp_last_step IS NULL OR totp_last_step<$3) RETURNING user_id",
        [account.org_id, account.user_id, step.toString()]);
      if (wrote.rows.length !== 1) throw new Error("TOTP_REQUIRED");
      await tx.query("INSERT INTO licensing_admin_sessions(session_id,token_digest,org_id,user_id,device_id,session_kind,issued_at_utc_ns,expires_at_utc_ns) VALUES ($1,$2,$3,$4,$5,'USER',$6,$7)",
        [sessionId, tokenDigest, account.org_id, account.user_id, deviceId, issued, expires]);
      await tx.query("INSERT INTO licensing_audit_events(id,org_id,actor,action,resource,digest,created_at_utc_ns) VALUES ($1,$2,$3,'auth.google.session.create',$4,$5,$6)",
        ["audit-" + randomToken(deps.crypto_api ?? globalThis.crypto, 16), account.org_id, account.user_id,
          `session:${sessionId}`, await digest(tokenDigest), issued]);
    }).catch(() => { throw new Error("TOTP_REQUIRED"); });
    return json({ schema_version: 1, data: { principal_id: account.user_id, session_token: token, expires_at_utc_ns: expires,
      license_snapshot: snapshot, totp_state: "ENROLLED" } });
  }

  if (!await ensureGoogleDevice(deps, account, deviceId)) return error("DEVICE_UNAVAILABLE", 403);
  let snapshot;
  try { snapshot = await issueLicenseSnapshotV1(deps.auth, account.org_id, deviceId); }
  catch { return error("ENTITLEMENT_UNAVAILABLE", 403); }
  const token = randomToken(deps.crypto_api ?? globalThis.crypto);
  const tokenDigest = await digest(token); const issued = nowNs(deps);
  const expires = (BigInt(issued) + BigInt(deps.auth.user_session_ttl_s) * NS).toString();
  const sessionId = "session-" + randomToken(deps.crypto_api ?? globalThis.crypto, 16);
  await deps.driver.transaction(async (tx) => {
    await tx.query("INSERT INTO licensing_admin_sessions(session_id,token_digest,org_id,user_id,device_id,session_kind,issued_at_utc_ns,expires_at_utc_ns) VALUES ($1,$2,$3,$4,$5,'USER',$6,$7)",
      [sessionId,tokenDigest,account.org_id,account.user_id,deviceId,issued,expires]);
    await tx.query("INSERT INTO licensing_audit_events(id,org_id,actor,action,resource,digest,created_at_utc_ns) VALUES ($1,$2,$3,'auth.google.session.create',$4,$5,$6)",
      ["audit-" + randomToken(deps.crypto_api ?? globalThis.crypto, 16), account.org_id, account.user_id,
        `session:${sessionId}`, await digest(tokenDigest), issued]);
  });
  return json({ schema_version: 1, data: { principal_id: account.user_id, session_token: token, expires_at_utc_ns: expires,
    license_snapshot: snapshot, totp_state: user.totp_enrolled ? "ENROLLED" : "OPTIONAL" } });
}

async function confirmGoogleTotp(request: Request, deps: GoogleAuthDependenciesV1): Promise<Response> {
  const body = await parse(request, ["device_id", "enrollment_token", "code"]);
  if (!body || typeof body.device_id !== "string" || !ID.test(body.device_id)
      || typeof body.enrollment_token !== "string" || body.enrollment_token.length < 32
      || body.enrollment_token.length > 256 || typeof body.code !== "string" || !TOTP_CODE.test(body.code)) {
    return error("INVALID_REQUEST", 400);
  }
  const deviceId = body.device_id as string;
  const enrollmentToken = body.enrollment_token as string;
  const code = body.code as string;
  const now = nowNs(deps);
  try {
    await deps.driver.transaction(async (tx) => {
      const selected = await tx.query<{ org_id: string; user_id: string; device_id: string;
        expires_at_utc_ns: string; session_id: string }>(
        "SELECT s.org_id,s.user_id,s.device_id,s.expires_at_utc_ns::text AS expires_at_utc_ns,s.session_id FROM licensing_admin_sessions s JOIN licensing_devices d ON d.device_id=s.device_id AND d.status='ACTIVE' WHERE s.token_digest=$1 AND s.device_id=$2 AND s.session_kind='TOTP_ENROLLMENT' AND s.revoked_at_utc_ns IS NULL FOR UPDATE",
        [await digest(enrollmentToken), deviceId]);
      const enrollment = selected.rows[0];
      if (!enrollment || BigInt(enrollment.expires_at_utc_ns) <= BigInt(now)) throw new Error("ENROLLMENT_UNAVAILABLE");
      const userRows = await tx.query<{ totp_secret_ciphertext: string | null; totp_last_step: string | null;
        totp_enrolled: boolean }>(
        "SELECT totp_secret_ciphertext,totp_last_step::text AS totp_last_step,totp_enrolled FROM licensing_users WHERE org_id=$1 AND user_id=$2 AND active=TRUE FOR UPDATE",
        [enrollment.org_id, enrollment.user_id]);
      const user = userRows.rows[0];
      if (!user || user.totp_enrolled || !user.totp_secret_ciphertext) throw new Error("ENROLLMENT_UNAVAILABLE");
      const secret = await decryptTotpSecretV1(user.totp_secret_ciphertext, deps.auth.totp_encryption_key,
        enrollment.org_id, enrollment.user_id);
      const step = await verifyTotpStepV1(secret, code, deps.now_unix_seconds(),
        user.totp_last_step === null ? null : BigInt(user.totp_last_step));
      if (step === null) throw new Error("TOTP_REQUIRED");
      const updated = await tx.query("UPDATE licensing_users SET totp_enrolled=TRUE,totp_last_step=$3 WHERE org_id=$1 AND user_id=$2 AND totp_enrolled=FALSE RETURNING user_id",
        [enrollment.org_id, enrollment.user_id, step.toString()]);
      if (updated.rows.length !== 1) throw new Error("ENROLLMENT_UNAVAILABLE");
      await tx.query("UPDATE licensing_admin_sessions SET revoked_at_utc_ns=$2 WHERE session_id=$1 AND session_kind='TOTP_ENROLLMENT' AND revoked_at_utc_ns IS NULL",
        [enrollment.session_id, now]);
      await tx.query("INSERT INTO licensing_audit_events(id,org_id,actor,action,resource,digest,created_at_utc_ns) VALUES ($1,$2,$3,'auth.google.totp.enrollment.confirm',$4,$5,$6)",
        ["audit-" + randomToken(deps.crypto_api ?? globalThis.crypto, 16), enrollment.org_id, enrollment.user_id,
          `user:${enrollment.user_id}`, await digest(user.totp_secret_ciphertext), now]);
    });
    return json({ schema_version: 1, data: { totp_state: "ENROLLED" } });
  } catch { return error("TOTP_REQUIRED", 401); }
}

export async function googleAuthRoutes(request: Request, deps?: GoogleAuthDependenciesV1): Promise<Response | null> {
  let path: string;
  try { path = new URL(request.url).pathname; } catch { return null; }
  const paths = new Set(["/v1/auth/google/desktop/start", "/v1/auth/google/desktop/complete",
    "/v1/auth/google/desktop/totp/confirm", "/v1/auth/google/web/start", "/v1/auth/google/web/callback"]);
  if (!paths.has(path)) return null;
  if (!deps) return error("NOT_CONFIGURED", 503);
  try {
    if (path === "/v1/auth/google/desktop/start" && request.method === "POST") return await beginDesktop(request, deps);
    if (path === "/v1/auth/google/desktop/complete" && request.method === "POST") {
      const body = await parse(request, ["state", "device_id", "id_token"], ["totp_code"]);
      if (!body) return error("INVALID_REQUEST", 400);
      return await issueGoogleSession(request, body, deps);
    }
    if (path === "/v1/auth/google/desktop/totp/confirm" && request.method === "POST") {
      return await confirmGoogleTotp(request, deps);
    }
    if (path === "/v1/auth/google/web/start" && request.method === "GET") return await webStart(request, deps);
    if (path === "/v1/auth/google/web/callback" && request.method === "GET") return await webCallback(request, deps);
    return error("NOT_FOUND", 404);
  } catch {
    return error("GOOGLE_AUTH_UNAVAILABLE", 503);
  }
}
