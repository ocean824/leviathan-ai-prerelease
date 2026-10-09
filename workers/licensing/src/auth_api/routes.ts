import { canonicalLicenseSnapshotV1 } from "../entitlement/decision.js";
import type { LicenseSnapshotV1 } from "../entitlement/models.js";
import { decryptTotpSecretV1, encryptTotpSecretV1, verifyPasswordPbkdf2V1, verifyTotpStepV1, type PgDriverV1 } from "../adapters/neon_admin.js";
import { authErrorV1, authJsonV1, type AuthResponseContextV1 } from "./handler.js";

const ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
const UINT = /^(0|[1-9][0-9]{0,63})$/;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const TOTP = /^\d{6}$/;
const MAX_BODY = 8192;
const NS = 1_000_000_000n;

export interface AuthApiDependenciesV1 {
  readonly driver: PgDriverV1;
  readonly totp_encryption_key: string;
  readonly signing_private_key: CryptoKey;
  readonly signing_key_id: string;
  readonly user_session_ttl_s: string;
  readonly request_id: () => string;
  readonly now_utc_ns?: () => string;
}

function nowNs(deps: AuthApiDependenciesV1): string { return (deps.now_utc_ns ?? (() => (BigInt(Date.now()) * 1_000_000n).toString()))(); }
function random(prefix: string): string { return `${prefix}-${crypto.randomUUID()}`; }
function b64url(bytes: Uint8Array): string {
  let raw = ""; for (const b of bytes) raw += String.fromCharCode(b);
  return btoa(raw).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"");
}
function bytes(value: Uint8Array): ArrayBuffer { const out = new ArrayBuffer(value.length); new Uint8Array(out).set(value); return out; }
async function sha256(value: string): Promise<string> {
  return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value))),
    (b) => b.toString(16).padStart(2, "0")).join("");
}
function plain(value: unknown): value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value); return proto === Object.prototype || proto === null;
}
function envelope(context: AuthResponseContextV1, data: unknown): Record<string, unknown> {
  return { schema_version: 1, request_id: context.request_id, observed_at_ns: context.observed_at_ns, data };
}
async function parse(request: Request, required: readonly string[], optional: readonly string[] = []): Promise<Record<string, unknown>> {
  if (!request.headers.get("content-type")?.toLowerCase().startsWith("application/json")) throw new Error("INVALID_REQUEST");
  const raw = new Uint8Array(await request.arrayBuffer());
  if (raw.byteLength > MAX_BODY) throw new Error("INVALID_REQUEST");
  const parsed: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw));
  if (!plain(parsed) || Reflect.ownKeys(parsed).some((key) => typeof key !== "string" || (!required.includes(key) && !optional.includes(key)))
      || required.some((key) => !Object.prototype.hasOwnProperty.call(parsed, key))) throw new Error("INVALID_REQUEST");
  return parsed;
}
function credentials(body: Record<string, unknown>): { email: string; password: string; device_id: string } {
  const email = body.email; const password = body.password; const device = body.device_id;
  if (typeof email !== "string" || email.length > 254 || !EMAIL.test(email)
      || typeof password !== "string" || password.length < 12 || password.length > 256
      || typeof device !== "string" || !ID.test(device)) throw new Error("INVALID_REQUEST");
  return { email: email.toLowerCase(), password, device_id: device };
}
async function owner(deps: AuthApiDependenciesV1, email: string) {
  const result = await deps.driver.query<{ org_id: string; user_id: string; password_hash_pbkdf2: string | null; active: boolean; totp_enrolled: boolean; totp_secret_ciphertext: string | null; totp_last_step: string | null }>(
    "SELECT org_id,user_id,password_hash_pbkdf2,active,totp_enrolled,totp_secret_ciphertext,totp_last_step::text AS totp_last_step FROM licensing_users WHERE lower(email)=lower($1) LIMIT 1", [email]);
  return result.rows[0] ?? null;
}
async function verifyPassword(deps: AuthApiDependenciesV1, user: Awaited<ReturnType<typeof owner>>, password: string): Promise<boolean> {
  return verifyPasswordPbkdf2V1(password, user?.password_hash_pbkdf2 ?? null);
}
async function activeDevice(deps: AuthApiDependenciesV1, org: string, user: string, device: string): Promise<boolean> {
  const found = await deps.driver.query("SELECT 1 FROM licensing_devices WHERE org_id=$1 AND user_id=$2 AND device_id=$3 AND status='ACTIVE'", [org,user,device]);
  return found.rows.length === 1;
}
export async function issueLicenseSnapshotV1(deps: AuthApiDependenciesV1, org: string, device: string): Promise<LicenseSnapshotV1> {
  const now = nowNs(deps);
  const result = await deps.driver.query<{ subscription_id: string; revision: string; status: LicenseSnapshotV1["status"]; term_start_utc_ns: string; term_end_utc_ns: string; features: Record<string, boolean>; limits: Record<string, string> }>(
    "SELECT subscription_id,revision::text AS revision,status,term_start_utc_ns::text AS term_start_utc_ns,term_end_utc_ns::text AS term_end_utc_ns,features,limits FROM licensing_subscriptions WHERE org_id=$1 AND status='ACTIVE' AND term_start_utc_ns <= $2 AND term_end_utc_ns > $2 ORDER BY revision DESC LIMIT 1", [org,now]);
  const row = result.rows[0];
  if (!row) throw new Error("LICENSE_UNAVAILABLE");
  const unsigned: LicenseSnapshotV1 = {
    schemaVersion: 1, orgId: org, licenseId: row.subscription_id, subscriptionRevision: row.revision,
    status: row.status, termStartUtcNs: row.term_start_utc_ns, termEndUtcNs: row.term_end_utc_ns,
    issuedAtUtcNs: now, lastOnlineVerifiedUtcNs: now, features: row.features, limits: row.limits,
    audience: "leviathan-desktop", deviceId: device, signingKeyId: deps.signing_key_id,
    signature: { algorithm: "ECDSA_P256_SHA256", value: "" },
  };
  const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, deps.signing_private_key,
    bytes(canonicalLicenseSnapshotV1(unsigned)));
  return Object.freeze({ ...unsigned, signature: { algorithm: "ECDSA_P256_SHA256" as const, value: b64url(new Uint8Array(signature)) } });
}
async function deviceToken(deps: AuthApiDependenciesV1, snapshot: LicenseSnapshotV1): Promise<string> {
  const header = b64url(new TextEncoder().encode(JSON.stringify({ alg: "ES256", typ: "JWT" })));
  const claims = b64url(new TextEncoder().encode(JSON.stringify({ schema_version: 1,
    org_id: snapshot.orgId, device_id: snapshot.deviceId, licence_id: snapshot.licenseId,
    exp_utc_ns: snapshot.termEndUtcNs })));
  const input = `${header}.${claims}`;
  const signature = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, deps.signing_private_key,
    new TextEncoder().encode(input)));
  return `${input}.${b64url(signature)}`;
}

async function session(request: Request, deps: AuthApiDependenciesV1, context: AuthResponseContextV1): Promise<Response> {
  const input = await parse(request, ["email", "password", "device_id"], ["totp_code"]);
  const login = credentials(input);
  const user = await owner(deps, login.email);
  if (!await verifyPassword(deps, user, login.password) || !user || user.active !== true) throw new Error("AUTHENTICATION_FAILED");
  if (!await activeDevice(deps, user.org_id, user.user_id, login.device_id)) throw new Error("AUTHENTICATION_FAILED");
  if (!user.totp_enrolled) {
    return authJsonV1(envelope(context, { totp_state: "ENROLLMENT_REQUIRED" }));
  }
  if (typeof input.totp_code !== "string" || !TOTP.test(input.totp_code) || !user.totp_secret_ciphertext) throw new Error("TOTP_REQUIRED");
  const seed = await decryptTotpSecretV1(user.totp_secret_ciphertext, deps.totp_encryption_key, user.org_id, user.user_id);
  const step = await verifyTotpStepV1(seed, input.totp_code, Math.floor(Number(BigInt(nowNs(deps)) / NS)),
    user.totp_last_step === null ? null : BigInt(user.totp_last_step));
  if (step === null) throw new Error("TOTP_REQUIRED");
  const snapshot = await issueLicenseSnapshotV1(deps, user.org_id, login.device_id);
  const token = b64url(crypto.getRandomValues(new Uint8Array(32)));
  const sessionId = random("session"); const auditId = random("audit"); const issued = nowNs(deps);
  const expires = (BigInt(issued) + BigInt(deps.user_session_ttl_s) * NS).toString();
  const tokenDigest = await sha256(token);
  const deviceJwt = await deviceToken(deps, snapshot);
  await deps.driver.transaction(async (tx) => {
    const accepted = await tx.query("UPDATE licensing_users SET totp_last_step=$3 WHERE org_id=$1 AND user_id=$2 AND totp_enrolled=TRUE AND (totp_last_step IS NULL OR totp_last_step<$3)", [user.org_id,user.user_id,step.toString()]);
    if (accepted.rows.length !== 1) throw new Error("TOTP_REQUIRED");
    await tx.query("INSERT INTO licensing_admin_sessions(session_id,token_digest,org_id,user_id,device_id,session_kind,issued_at_utc_ns,expires_at_utc_ns) VALUES ($1,$2,$3,$4,$5,'USER',$6,$7)",
      [sessionId,tokenDigest,user.org_id,user.user_id,login.device_id,issued,expires]);
    await tx.query("INSERT INTO licensing_audit_events(id,org_id,actor,action,resource,digest,created_at_utc_ns) VALUES ($1,$2,$3,'auth.session.create',$4,$5,$6)",
      [auditId,user.org_id,user.user_id,`session:${sessionId}`,await sha256(tokenDigest),issued]);
  });
  return authJsonV1(envelope(context, { session_token: token, device_token: deviceJwt,
    expires_at_utc_ns: expires, license_snapshot: snapshot, totp_state: "ENROLLED" }));
}

async function beginEnrollment(request: Request, deps: AuthApiDependenciesV1, context: AuthResponseContextV1): Promise<Response> {
  const input = await parse(request, ["email", "password", "device_id"]); const login = credentials(input);
  const user = await owner(deps, login.email);
  if (!await verifyPassword(deps, user, login.password) || !user || user.active !== true
      || !await activeDevice(deps,user.org_id,user.user_id,login.device_id)) throw new Error("AUTHENTICATION_FAILED");
  if (user.totp_enrolled) throw new Error("TOTP_ENROLLMENT_REQUIRED");
  let secret: string;
  if (user.totp_secret_ciphertext) secret = await decryptTotpSecretV1(user.totp_secret_ciphertext,
    deps.totp_encryption_key,user.org_id,user.user_id);
  else {
    const raw = crypto.getRandomValues(new Uint8Array(20));
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; let buffer = 0; let bits = 0; secret = "";
    for (const value of raw) { buffer = (buffer << 8) | value; bits += 8; while (bits >= 5) { bits -= 5; secret += alphabet[(buffer >> bits) & 31]; } }
    if (bits) secret += alphabet[(buffer << (5 - bits)) & 31];
    const encrypted = await encryptTotpSecretV1(secret,deps.totp_encryption_key,user.org_id,user.user_id);
    await deps.driver.transaction(async (tx) => {
      const changed = await tx.query("UPDATE licensing_users SET totp_secret_ciphertext=$3 WHERE org_id=$1 AND user_id=$2 AND totp_enrolled=FALSE AND totp_secret_ciphertext IS NULL RETURNING user_id",
        [user.org_id,user.user_id,encrypted]);
      if (changed.rows.length !== 1) throw new Error("AUTHENTICATION_FAILED");
      const auditId = random("audit");
      await tx.query("INSERT INTO licensing_audit_events(id,org_id,actor,action,resource,digest,created_at_utc_ns) VALUES ($1,$2,$3,'auth.totp.enrollment.start',$4,$5,$6)",
        [auditId,user.org_id,user.user_id,`user:${user.user_id}`,await sha256(encrypted),nowNs(deps)]);
    });
  }
  const opaque = b64url(crypto.getRandomValues(new Uint8Array(32)));
  const tokenDigest = await sha256(opaque); const expires = (BigInt(nowNs(deps)) + 300n * NS).toString();
  const issued = nowNs(deps); const enrollmentSessionId = random("session");
  await deps.driver.query("INSERT INTO licensing_admin_sessions(session_id,token_digest,org_id,user_id,device_id,session_kind,issued_at_utc_ns,expires_at_utc_ns) VALUES ($1,$2,$3,$4,$5,'TOTP_ENROLLMENT',$6,$7)",
    [enrollmentSessionId,tokenDigest,user.org_id,user.user_id,login.device_id,issued,expires]);
  const issuer = encodeURIComponent("Leviathan AI");
  const uri = `otpauth://totp/${issuer}:${encodeURIComponent(login.email)}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`;
  return authJsonV1(envelope(context, { otpauth_uri: uri }), 200,
    { "Set-Cookie": `auth_enrollment=${opaque}; HttpOnly; Secure; SameSite=Strict; Path=/v1/auth/session/totp; Max-Age=300` });
}

async function confirmEnrollment(request: Request, deps: AuthApiDependenciesV1, context: AuthResponseContextV1): Promise<Response> {
  const input = await parse(request, ["code"]);
  if (typeof input.code !== "string" || !TOTP.test(input.code)) throw new Error("INVALID_REQUEST");
  const code = input.code;
  const cookie = request.headers.get("cookie") ?? "";
  const token = cookie.split(";").map((part) => part.trim()).find((part) => part.startsWith("auth_enrollment="))?.slice("auth_enrollment=".length);
  if (!token || token.length > 256) throw new Error("AUTHENTICATION_FAILED");
  const digest = await sha256(token); const now = nowNs(deps);
  await deps.driver.transaction(async (tx) => {
    const rows = await tx.query<{ org_id: string; user_id: string; device_id: string; expires_at_utc_ns: string; session_id: string }>(
      "SELECT e.org_id,e.user_id,e.device_id,e.expires_at_utc_ns::text AS expires_at_utc_ns,e.session_id FROM licensing_admin_sessions e JOIN licensing_devices d ON d.device_id=e.device_id AND d.status='ACTIVE' WHERE e.token_digest=$1 AND e.session_kind='TOTP_ENROLLMENT' AND e.revoked_at_utc_ns IS NULL FOR UPDATE", [digest]);
    const enrollment = rows.rows[0];
    if (!enrollment || BigInt(enrollment.expires_at_utc_ns) <= BigInt(now)) throw new Error("AUTHENTICATION_FAILED");
    const userRows = await tx.query<{ totp_secret_ciphertext: string | null; totp_last_step: string | null; totp_enrolled: boolean }>(
      "SELECT totp_secret_ciphertext,totp_last_step::text AS totp_last_step,totp_enrolled FROM licensing_users WHERE org_id=$1 AND user_id=$2 FOR UPDATE", [enrollment.org_id,enrollment.user_id]);
    const user = userRows.rows[0];
    if (!user || user.totp_enrolled || !user.totp_secret_ciphertext) throw new Error("AUTHENTICATION_FAILED");
    const secret = await decryptTotpSecretV1(user.totp_secret_ciphertext,deps.totp_encryption_key,enrollment.org_id,enrollment.user_id);
    const step = await verifyTotpStepV1(secret,code,Math.floor(Number(BigInt(now)/NS)),
      user.totp_last_step === null ? null : BigInt(user.totp_last_step));
    if (step === null) throw new Error("TOTP_REQUIRED");
    await tx.query("UPDATE licensing_users SET totp_enrolled=TRUE,totp_last_step=$3 WHERE org_id=$1 AND user_id=$2 AND totp_enrolled=FALSE",
      [enrollment.org_id,enrollment.user_id,step.toString()]);
    await tx.query("UPDATE licensing_admin_sessions SET revoked_at_utc_ns=$2 WHERE session_id=$1 AND session_kind='TOTP_ENROLLMENT' AND revoked_at_utc_ns IS NULL", [enrollment.session_id,now]);
    const auditId = random("audit");
    await tx.query("INSERT INTO licensing_audit_events(id,org_id,actor,action,resource,digest,created_at_utc_ns) VALUES ($1,$2,$3,'auth.totp.enrollment.confirm',$4,$5,$6)",
      [auditId,enrollment.org_id,enrollment.user_id,`user:${enrollment.user_id}`,await sha256(user.totp_secret_ciphertext),now]);
  });
  return authJsonV1(envelope(context, { totp_state: "ENROLLED" }), 200,
    { "Set-Cookie": "auth_enrollment=; HttpOnly; Secure; SameSite=Strict; Path=/v1/auth/session/totp; Max-Age=0" });
}

async function deleteSession(request: Request, deps: AuthApiDependenciesV1, context: AuthResponseContextV1): Promise<Response> {
  const authorization = request.headers.get("authorization") ?? ""; const device = request.headers.get("x-device-id") ?? "";
  if (!authorization.startsWith("Bearer ") || !ID.test(device)) throw new Error("AUTHENTICATION_FAILED");
  const digest = await sha256(authorization.slice(7)); const now = nowNs(deps); const auditId = random("audit");
  await deps.driver.transaction(async (tx) => {
    const changed = await tx.query<{ org_id: string; user_id: string; session_id: string }>(
      "UPDATE licensing_admin_sessions SET revoked_at_utc_ns=$3 WHERE token_digest=$1 AND device_id=$2 AND session_kind='USER' AND revoked_at_utc_ns IS NULL RETURNING org_id,user_id,session_id",
      [digest,device,now]);
    const row = changed.rows[0]; if (!row) throw new Error("AUTHENTICATION_FAILED");
    await tx.query("INSERT INTO licensing_audit_events(id,org_id,actor,action,resource,digest,created_at_utc_ns) VALUES ($1,$2,$3,'auth.session.revoke',$4,$5,$6)",
      [auditId,row.org_id,row.user_id,`session:${row.session_id}`,await sha256(digest),now]);
  });
  return authJsonV1(envelope(context, { revoked: true }));
}

export async function authApiRoutes(request: Request, deps?: AuthApiDependenciesV1): Promise<Response | null> {
  let url: URL; try { url = new URL(request.url); } catch { return null; }
  if (!/^\/v1\/auth\/session(?:\/totp\/(?:enroll|confirm))?$/.test(url.pathname)) return null;
  let requestId = "request-unavailable";
  try { const candidate = deps?.request_id(); if (typeof candidate === "string" && ID.test(candidate)) requestId = candidate; } catch { /* fixed fallback */ }
  const context = Object.freeze({ request_id: requestId, observed_at_ns: deps ? nowNs(deps) : "0" });
  if (!deps) return authErrorV1("NOT_CONFIGURED", context, 503);
  try {
    if (url.pathname === "/v1/auth/session" && request.method === "POST") return await session(request,deps,context);
    if (url.pathname === "/v1/auth/session/totp/enroll" && request.method === "POST") return await beginEnrollment(request,deps,context);
    if (url.pathname === "/v1/auth/session/totp/confirm" && request.method === "POST") return await confirmEnrollment(request,deps,context);
    if (url.pathname === "/v1/auth/session" && request.method === "DELETE") return await deleteSession(request,deps,context);
    return authErrorV1("NOT_FOUND", context, 404);
  } catch (error) {
    const code = error instanceof Error && ["INVALID_REQUEST","AUTHENTICATION_FAILED","TOTP_REQUIRED","LICENSE_UNAVAILABLE"].includes(error.message)
      ? error.message : "SESSION_UNAVAILABLE";
    const status = code === "INVALID_REQUEST" ? 400 : code === "LICENSE_UNAVAILABLE" ? 403 : 401;
    return authErrorV1(code,context,status);
  }
}
