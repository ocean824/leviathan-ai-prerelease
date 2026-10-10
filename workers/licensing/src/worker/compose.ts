import { Pool } from "@neondatabase/serverless";
import postgres from "postgres";
import { createNeonAdminAdapterV1, createNeonPgDriverV1, createHyperdrivePgDriverV1, type PgDriverV1 } from "../adapters/neon_admin.js";
import { createNeonSignupAdapterV1 } from "../adapters/neon_signup.js";
import type { AdminApiDependenciesV1 } from "../admin_api/models.js";
import { LicenseDecisionCacheV1 } from "./cache.js";
import { PerLicenseRateLimiterV1 } from "./rate_limit.js";
import { createLicenseWorkerV1, type LicenseWorkerV1 } from "./handler.js";
import type { AuthApiDependenciesV1 } from "../auth_api/routes.js";
import { issueLicenseSnapshotV1 } from "../auth_api/routes.js";
import type { GoogleAuthDependenciesV1 } from "../google_auth/routes.js";

export interface HyperdriveBindingV1 { readonly connectionString: string; }
export interface LicenseWorkerBindingsV1 {
  readonly DATABASE_URL?: string;
  readonly HYPERDRIVE?: HyperdriveBindingV1;
  readonly STRIPE_SECRET_KEY?: string;
  readonly STRIPE_MODE?: "test" | "live";
  readonly STRIPE_WEBHOOK_SECRET?: string;
  readonly STRIPE_PRICE_ID?: string;
  readonly SIGNUP_SUCCESS_URL?: string;
  readonly SIGNUP_CANCEL_URL?: string;
  readonly ADMIN_SESSION_TTL_S?: string;
  readonly USER_SESSION_TTL_S?: string;
  readonly CAPS_APPROVED?: string;
  readonly LICENSE_SIGNING_KEY_ID?: string;
  readonly LICENSE_SIGNING_PRIVATE_KEY_PKCS8?: string;
  readonly LICENSE_VERIFY_PUBLIC_KEY_JWK?: string;
  readonly INTERNAL_SERVICE_TOKEN?: string;
  readonly ADMIN_TOTP_ENCRYPTION_KEY?: string;
  readonly GOOGLE_DESKTOP_CLIENT_ID?: string;
  readonly GOOGLE_WEB_CLIENT_ID?: string;
  readonly GOOGLE_WEB_CLIENT_SECRET?: string;
  readonly GOOGLE_OAUTH_STATE_ENCRYPTION_KEY?: string;
  readonly GOOGLE_WEB_SUCCESS_URL?: string;
}

export interface ComposeOverridesV1 {
  readonly driver?: PgDriverV1;
  readonly fetch?: typeof fetch;
}

function failure(status = 503): Response {
  return new Response(JSON.stringify({ schema_version: 1, error: { code: "NOT_CONFIGURED", message: "Service unavailable." } }),
    { status, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" } });
}
function decodeB64(value: string): Uint8Array {
  const normalized = value.replace(/-/g,"+").replace(/_/g,"/");
  const raw = atob(normalized + "=".repeat((4 - normalized.length % 4) % 4));
  return Uint8Array.from(raw, (char) => char.charCodeAt(0));
}
function toBuffer(value: Uint8Array): ArrayBuffer {
  const copy = new ArrayBuffer(value.length); new Uint8Array(copy).set(value); return copy;
}
function safeEq(a: string, b: string): boolean {
  const x = new TextEncoder().encode(a); const y = new TextEncoder().encode(b);
  let diff = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i += 1) diff |= (x[i] ?? 0) ^ (y[i] ?? 0);
  return diff === 0;
}
function id(prefix: string): string { return `${prefix}-${crypto.randomUUID()}`; }
function utcNs(): string { return (BigInt(Date.now()) * 1_000_000n).toString(); }
async function tokenDigest(token: string): Promise<string> {
  return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token))),
    (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function configured(env: LicenseWorkerBindingsV1): boolean {
  const hasDatabase = Boolean(env.HYPERDRIVE?.connectionString || env.DATABASE_URL);
  const httpsUrls = [env.SIGNUP_SUCCESS_URL, env.SIGNUP_CANCEL_URL]
    .every((value) => typeof value === "string" && value.startsWith("https://"));
  const mode = env.STRIPE_MODE ?? "test";
  const stripeKeyValid = mode === "test" ? /^sk_test_[A-Za-z0-9_]+$/.test(env.STRIPE_SECRET_KEY ?? "")
    : mode === "live" ? /^sk_live_[A-Za-z0-9_]+$/.test(env.STRIPE_SECRET_KEY ?? "") : false;
  return hasDatabase && stripeKeyValid
    && /^whsec_[A-Za-z0-9_-]{8,}$/.test(env.STRIPE_WEBHOOK_SECRET ?? "")
    && /^price_[A-Za-z0-9]+$/.test(env.STRIPE_PRICE_ID ?? "") && httpsUrls
    && /^(?:[6-9][0-9]|[1-8][0-9]{2}|900)$/.test(env.ADMIN_SESSION_TTL_S ?? "")
    && /^(?:[6-9][0-9]|[1-8][0-9]{2}|900)$/.test(env.USER_SESSION_TTL_S ?? "")
    && ["true", "false"].includes(env.CAPS_APPROVED ?? "")
    && Boolean(env.LICENSE_SIGNING_KEY_ID) && Boolean(env.LICENSE_SIGNING_PRIVATE_KEY_PKCS8)
    && Boolean(env.LICENSE_VERIFY_PUBLIC_KEY_JWK) && Boolean(env.INTERNAL_SERVICE_TOKEN)
    && Boolean(env.ADMIN_TOTP_ENCRYPTION_KEY);
}

function makeDriver(env: LicenseWorkerBindingsV1): PgDriverV1 {
  if (env.HYPERDRIVE?.connectionString) {
    return createHyperdrivePgDriverV1(postgres(env.HYPERDRIVE.connectionString, { max: 5 }));
  }
  if (!env.DATABASE_URL) throw new Error("NOT_CONFIGURED");
  return createNeonPgDriverV1(new Pool({ connectionString: env.DATABASE_URL, max: 5 }));
}

function internalFail(status: number): Response {
  return new Response(JSON.stringify({ schema_version: 1, error: { code: status === 401 ? "UNAUTHENTICATED" : "FORBIDDEN" } }),
    { status, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" } });
}

async function verifyInternalDeviceToken(
  request: Request, env: LicenseWorkerBindingsV1, driver: PgDriverV1, publicKey: CryptoKey,
): Promise<Response> {
  if (request.method !== "POST") return internalFail(403);
  const supplied = request.headers.get("x-internal-service-token") ?? "";
  if (!env.INTERNAL_SERVICE_TOKEN || !safeEq(supplied, env.INTERNAL_SERVICE_TOKEN)) return internalFail(403);
  let input: unknown;
  try {
    const bytes = new Uint8Array(await request.arrayBuffer());
    if (bytes.byteLength > 8192) return internalFail(401);
    input = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as unknown;
  } catch { return internalFail(401); }
  if (!input || typeof input !== "object" || Array.isArray(input)
      || Reflect.ownKeys(input).length !== 2 || (input as Record<string, unknown>).schema_version !== 1
      || typeof (input as Record<string, unknown>).device_token !== "string") return internalFail(401);
  const parts = (input as { device_token: string }).device_token.split(".");
  if (parts.length !== 3) return internalFail(401);
  try {
    const header = JSON.parse(new TextDecoder().decode(decodeB64(parts[0]!))) as Record<string, unknown>;
    const claims = JSON.parse(new TextDecoder().decode(decodeB64(parts[1]!))) as Record<string, unknown>;
    if (header.alg !== "ES256" || claims.schema_version !== 1 || typeof claims.device_id !== "string"
        || typeof claims.licence_id !== "string" || typeof claims.org_id !== "string"
        || typeof claims.exp_utc_ns !== "string" || BigInt(claims.exp_utc_ns) <= BigInt(utcNs())) return internalFail(401);
    const verified = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, publicKey, toBuffer(decodeB64(parts[2]!)),
      new TextEncoder().encode(`${parts[0]}.${parts[1]}`));
    if (!verified) return internalFail(401);
    const rows = await driver.query(
      "SELECT 1 FROM licensing_devices d JOIN licensing_organizations o ON o.org_id=d.org_id JOIN licensing_subscriptions s ON s.org_id=d.org_id WHERE d.device_id=$1 AND d.org_id=$2 AND d.status='ACTIVE' AND o.active=TRUE AND s.subscription_id=$3 AND s.status='ACTIVE' AND s.term_start_utc_ns <= $4 AND s.term_end_utc_ns > $4 LIMIT 1",
      [claims.device_id, claims.org_id, claims.licence_id, utcNs()]);
    if (rows.rows.length !== 1) return internalFail(401);
    return new Response(JSON.stringify({ schema_version: 1,
      data: { active: true, device_id: claims.device_id, licence_id: claims.licence_id } }),
      { status: 200, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" } });
  } catch { return internalFail(401); }
}

/** Build all production ports from bindings, or return a fail-closed Worker. */
export async function composeLicenseWorkerV1(
  env: LicenseWorkerBindingsV1, overrides: ComposeOverridesV1 = {},
): Promise<LicenseWorkerV1> {
  if (!configured(env)) return Object.freeze({ fetch: async () => failure() });
  try {
    const publicJwk = JSON.parse(env.LICENSE_VERIFY_PUBLIC_KEY_JWK!) as JsonWebKey;
    if (publicJwk.kty !== "EC" || publicJwk.crv !== "P-256" || typeof publicJwk.x !== "string" || typeof publicJwk.y !== "string") {
      return Object.freeze({ fetch: async () => failure() });
    }
    const publicKey = await crypto.subtle.importKey("jwk", publicJwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    const pkcs8 = decodeB64(env.LICENSE_SIGNING_PRIVATE_KEY_PKCS8!);
    const privateKey = await crypto.subtle.importKey("pkcs8", toBuffer(pkcs8), { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
    const driver = overrides.driver ?? makeDriver(env);
    const adminAdapter = createNeonAdminAdapterV1(driver, env.ADMIN_TOTP_ENCRYPTION_KEY!);
    const signup = createNeonSignupAdapterV1(driver, {
      stripe_secret_key: env.STRIPE_SECRET_KEY!, stripe_mode: env.STRIPE_MODE ?? "test",
      stripe_price_id: env.STRIPE_PRICE_ID!,
      caps_approved: env.CAPS_APPROVED === "true",
    }, overrides.fetch ?? fetch);
    const clock = { nowUtcNs: utcNs, nowUnixSeconds: () => Math.floor(Date.now() / 1000) };
    const admin: AdminApiDependenciesV1 = {
      auth: adminAdapter.auth, authorization: adminAdapter.authorization, store: adminAdapter.store,
      clock: { nowUtcNs: utcNs }, ids: { next: (prefix) => id(prefix) },
      session_policy: { ttl_seconds: env.ADMIN_SESSION_TTL_S!, max_failed_attempts: 5, lockout_seconds: 300 },
    };
    const authApi: AuthApiDependenciesV1 = {
      driver, totp_encryption_key: env.ADMIN_TOTP_ENCRYPTION_KEY!, signing_private_key: privateKey,
      signing_key_id: env.LICENSE_SIGNING_KEY_ID!, user_session_ttl_s: env.USER_SESSION_TTL_S!,
      request_id: () => id("request"), now_utc_ns: utcNs,
    };
    const signupApi = { clock, request_id: () => id("request"),
      config: { stripe_mode: env.STRIPE_MODE ?? "test", stripe_price_id: env.STRIPE_PRICE_ID!,
        stripe_webhook_secret: env.STRIPE_WEBHOOK_SECRET!,
        success_url: env.SIGNUP_SUCCESS_URL!, cancel_url: env.SIGNUP_CANCEL_URL! },
      pending_signups: signup.pending_signups, stripe: signup.stripe, webhook_transactions: signup.webhook_transactions };
    const googleAuthApi: GoogleAuthDependenciesV1 | undefined = env.GOOGLE_DESKTOP_CLIENT_ID
      && env.GOOGLE_WEB_CLIENT_ID && env.GOOGLE_WEB_CLIENT_SECRET
      && env.GOOGLE_OAUTH_STATE_ENCRYPTION_KEY && env.GOOGLE_WEB_SUCCESS_URL
      ? { driver, auth: authApi, signup: signupApi,
        desktop_client_id: env.GOOGLE_DESKTOP_CLIENT_ID, web_client_id: env.GOOGLE_WEB_CLIENT_ID,
        web_client_secret: env.GOOGLE_WEB_CLIENT_SECRET,
        web_callback_uri: "https://leviathan-licensing-worker.ocean824.workers.dev/v1/auth/google/web/callback",
        web_success_url: env.GOOGLE_WEB_SUCCESS_URL,
        state_encryption_key: env.GOOGLE_OAUTH_STATE_ENCRYPTION_KEY,
        fetcher: overrides.fetch ?? fetch, now_unix_seconds: clock.nowUnixSeconds,
        now_utc_ns: utcNs, request_id: () => id("request") }
      : undefined;
    const worker = createLicenseWorkerV1({
      principals: { async resolve(request) {
        const auth = request.headers.get("authorization") ?? "";
        const device = request.headers.get("x-device-id") ?? "";
        if (!auth.startsWith("Bearer ") || auth.length > 520 || !/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(device)) return null;
        const digest = await tokenDigest(auth.slice(7));
        const result = await driver.query<{ org_id: string; user_id: string; device_id: string; role_id: string }>(
          "SELECT s.org_id,s.user_id,s.device_id,u.role_id FROM licensing_admin_sessions s JOIN licensing_users u ON u.org_id=s.org_id AND u.user_id=s.user_id JOIN licensing_devices d ON d.device_id=s.device_id WHERE s.token_digest=$1 AND s.device_id=$2 AND s.session_kind='USER' AND s.revoked_at_utc_ns IS NULL AND s.expires_at_utc_ns>$3 AND u.active=TRUE AND d.status='ACTIVE' LIMIT 1",
          [digest,device,utcNs()]);
        const row = result.rows[0];
        return row ? { schemaVersion: 1, principalId: row.user_id, orgId: row.org_id,
          audience: "leviathan-desktop", deviceId: row.device_id, scopes: ["license:read","auth:introspect"], roles: [row.role_id] } : null;
      } },
      authorization: { async authorize(principal, action, now) {
        if (action !== "license:read" && action !== "auth:introspect") return false;
        const result = await driver.query("SELECT 1 FROM licensing_organizations o JOIN licensing_subscriptions s ON s.org_id=o.org_id WHERE o.org_id=$1 AND o.active=TRUE AND s.status='ACTIVE' AND s.term_start_utc_ns<=$2 AND s.term_end_utc_ns>$2 LIMIT 1",
          [principal.orgId,now]);
        return result.rows.length === 1;
      } },
      licenses: {
        async readCurrent() { return null; },
        async readForDevice(orgId, deviceId) {
          try { return await issueLicenseSnapshotV1(authApi, orgId, deviceId); } catch { return null; }
        },
      }, signingKeys: new Map([[env.LICENSE_SIGNING_KEY_ID!, publicKey]]),
      clock: { nowMonotonicMs: () => performance.now(), nowUtcNs: utcNs }, requestIdFactory: () => id("request"),
      cache: new LicenseDecisionCacheV1(), rateLimiter: new PerLicenseRateLimiterV1(),
      backgroundEligibility: { publishLease: async () => undefined },
      serverPolicy: { lowestTierApiRateLimitRps: "1" }, metrics: { recordRatePolicyDefaulted: () => undefined },
      deadlines: { run: async (_operation, _timeout, invoke) => ({ status: "COMPLETED", value: await invoke(new AbortController().signal) }) },
      adminApi: admin,
      authApi,
      googleAuthApi,
      signupApi,
    });
    return Object.freeze({ fetch: async (request: Request) => {
      const url = new URL(request.url);
      if (url.pathname === "/health" && request.method === "GET") {
        try {
          const probe = await driver.query<{ readonly ok: number }>("SELECT 1 AS ok", []);
          if (probe.rows.length !== 1 || probe.rows[0]?.ok !== 1) return failure();
        } catch { return failure(); }
        return new Response(JSON.stringify({ status: "ok" }), { status: 200,
          headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" } });
      }
      if (url.pathname === "/v1/internal/device-entitlement/verify") {
        return verifyInternalDeviceToken(request, env, driver, publicKey);
      }
      return worker.fetch(request);
    } });
  } catch { return Object.freeze({ fetch: async () => failure() }); }
}

const compositionCache = new WeakMap<object, Promise<LicenseWorkerV1>>();
const workerExport = Object.freeze({
  async fetch(request: Request, env: LicenseWorkerBindingsV1): Promise<Response> {
    let composed = compositionCache.get(env as object);
    if (!composed) { composed = composeLicenseWorkerV1(env); compositionCache.set(env as object, composed); }
    return (await composed).fetch(request);
  },
});
export default workerExport;
