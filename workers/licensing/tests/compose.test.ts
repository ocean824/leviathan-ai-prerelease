import { describe, expect, it } from "vitest";
import { composeLicenseWorkerV1, type LicenseWorkerBindingsV1 } from "../src/worker/compose.js";
import type { PgDriverV1 } from "../src/adapters/neon_admin.js";
import type { PgQueryV1 } from "../src/db/repository.js";

function b64url(bytes: Uint8Array): string {
  let raw = ""; for (const byte of bytes) raw += String.fromCharCode(byte);
  return btoa(raw).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"");
}
function buffer(bytes: Uint8Array): ArrayBuffer { const out = new ArrayBuffer(bytes.length); new Uint8Array(out).set(bytes); return out; }

describe("licensing Worker composition", () => {
  it("fails closed when required bindings are missing", async () => {
    let queries = 0;
    const driver: PgDriverV1 = {
      async query<Row>() { queries += 1; return { rows: [] as Row[] }; },
      async transaction<T>(_work: (tx: PgQueryV1) => Promise<T>): Promise<T> { throw new Error("unexpected transaction"); },
    };
    const worker = await composeLicenseWorkerV1({}, { driver });
    const response = await worker.fetch(new Request("https://worker.test/v1/admin/session", { method: "POST" }));
    expect(response.status).toBe(503);
    expect(await response.json()).toMatchObject({ error: { code: "NOT_CONFIGURED" } });
    expect(queries).toBe(0);
  });

  it("limits device-entitlement verification to the internal token and a valid ES256 service proof", async () => {
    const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    const publicJwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
    const privateBytes = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
    let entitlementReads = 0;
    const driver: PgDriverV1 = {
      async query<Row>() { entitlementReads += 1; return { rows: [{ ok: 1 }] as Row[] }; },
      async transaction<T>(_work: (tx: PgQueryV1) => Promise<T>): Promise<T> { throw new Error("unused"); },
    };
    const bindings: LicenseWorkerBindingsV1 = {
      DATABASE_URL: "postgres://fixture.invalid/db", STRIPE_MODE: "test", STRIPE_SECRET_KEY: "sk_test_fixture",
      STRIPE_WEBHOOK_SECRET: "whsec_fixture_secret", STRIPE_PRICE_ID: "price_fixture",
      SIGNUP_SUCCESS_URL: "https://fixture.invalid/success", SIGNUP_CANCEL_URL: "https://fixture.invalid/cancel",
      ADMIN_SESSION_TTL_S: "900", USER_SESSION_TTL_S: "600", CAPS_APPROVED: "false", LICENSE_SIGNING_KEY_ID: "test-key",
      LICENSE_SIGNING_PRIVATE_KEY_PKCS8: btoa(String.fromCharCode(...privateBytes)),
      LICENSE_VERIFY_PUBLIC_KEY_JWK: JSON.stringify(publicJwk), INTERNAL_SERVICE_TOKEN: "service-fixture-secret",
      ADMIN_TOTP_ENCRYPTION_KEY: btoa(String.fromCharCode(...new Uint8Array(32).fill(1))),
    };
    const worker = await composeLicenseWorkerV1(bindings, { driver });
    const health = await worker.fetch(new Request("https://worker.test/health"));
    expect(health.status).toBe(200);
    expect(await health.json()).toEqual({ status: "ok" });
    const testRejectsLiveKey = await composeLicenseWorkerV1({ ...bindings, STRIPE_SECRET_KEY: "sk_live_fixture" }, { driver });
    expect((await testRejectsLiveKey.fetch(new Request("https://worker.test/health"))).status).toBe(503);
    const liveAcceptsLiveKey = await composeLicenseWorkerV1({ ...bindings,
      STRIPE_MODE: "live", STRIPE_SECRET_KEY: "sk_live_fixture" }, { driver });
    expect((await liveAcceptsLiveKey.fetch(new Request("https://worker.test/health"))).status).toBe(200);
    const liveRejectsTestKey = await composeLicenseWorkerV1({ ...bindings, STRIPE_MODE: "live" }, { driver });
    expect((await liveRejectsTestKey.fetch(new Request("https://worker.test/health"))).status).toBe(503);
    entitlementReads = 0;
    const unauthorized = await worker.fetch(new Request("https://worker.test/v1/internal/device-entitlement/verify", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ schema_version: 1, device_token: "invalid" }),
    }));
    expect(unauthorized.status).toBe(403);
    expect(entitlementReads).toBe(0);

    const header = b64url(new TextEncoder().encode(JSON.stringify({ alg: "ES256", typ: "JWT" })));
    const claims = b64url(new TextEncoder().encode(JSON.stringify({ schema_version: 1, device_id: "device-1",
      licence_id: "license-1", org_id: "org-1", exp_utc_ns: (BigInt(Date.now() + 60_000) * 1_000_000n).toString() })));
    const signed = new TextEncoder().encode(`${header}.${claims}`);
    const signature = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, pair.privateKey, signed));
    const token = `${header}.${claims}.${b64url(signature)}`;
    const allowed = await worker.fetch(new Request("https://worker.test/v1/internal/device-entitlement/verify", {
      method: "POST", headers: { "content-type": "application/json", "x-internal-service-token": "service-fixture-secret" },
      body: JSON.stringify({ schema_version: 1, device_token: token }),
    }));
    expect(allowed.status).toBe(200);
    expect(await allowed.json()).toEqual({ schema_version: 1,
      data: { active: true, device_id: "device-1", licence_id: "license-1" } });
    expect(entitlementReads).toBe(1);
    expect(buffer(new Uint8Array([1])).byteLength).toBe(1);
  });
});
