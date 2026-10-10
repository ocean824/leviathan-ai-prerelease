import { composeLicenseWorkerV1, type LicenseWorkerBindingsV1 } from "../../../workers/licensing/src/worker/compose.js";
import type { PgDriverV1 } from "../../../workers/licensing/src/adapters/neon_admin.js";
import type { PgQueryV1 } from "../../../workers/licensing/src/db/repository.js";

function b64url(bytes: Uint8Array): string {
  let raw = "";
  for (const byte of bytes) raw += String.fromCharCode(byte);
  return btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

const bindings = (privateBytes: Uint8Array, publicJwk: JsonWebKey): LicenseWorkerBindingsV1 => ({
  DATABASE_URL: "postgres://fixture.invalid/db",
  STRIPE_MODE: "test",
  STRIPE_SECRET_KEY: "sk_test_fixture",
  STRIPE_WEBHOOK_SECRET: "whsec_fixture_secret",
  STRIPE_PRICE_ID: "price_fixture",
  SIGNUP_SUCCESS_URL: "https://fixture.invalid/success",
  SIGNUP_CANCEL_URL: "https://fixture.invalid/cancel",
  ADMIN_SESSION_TTL_S: "900",
  USER_SESSION_TTL_S: "600",
  CAPS_APPROVED: "false",
  LICENSE_SIGNING_KEY_ID: "device-test-key",
  LICENSE_SIGNING_PRIVATE_KEY_PKCS8: btoa(String.fromCharCode(...privateBytes)),
  LICENSE_VERIFY_PUBLIC_KEY_JWK: JSON.stringify(publicJwk),
  INTERNAL_SERVICE_TOKEN: "service-fixture-secret",
  ADMIN_TOTP_ENCRYPTION_KEY: btoa(String.fromCharCode(...new Uint8Array(32).fill(1))),
});

async function token(pair: CryptoKeyPair, exp: bigint, badSignature = false): Promise<string> {
  const header = b64url(new TextEncoder().encode(JSON.stringify({ alg: "ES256", typ: "JWT" })));
  const claims = b64url(new TextEncoder().encode(JSON.stringify({
    schema_version: 1,
    device_id: "device-acceptance",
    licence_id: "licence-acceptance",
    org_id: "org-acceptance",
    exp_utc_ns: exp.toString(),
  })));
  const signingInput = `${header}.${claims}`;
  const signature = new Uint8Array(await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" }, pair.privateKey, new TextEncoder().encode(signingInput),
  ));
  if (badSignature) signature[0] ^= 1;
  return `${signingInput}.${b64url(signature)}`;
}

describe("cycle-2 device-token authorization", () => {
  it("rejects bad signatures and expired claims before querying the device registry", async () => {
    const pair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"],
    );
    const publicJwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
    const privateBytes = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
    const env = bindings(privateBytes, publicJwk);
    let queries = 0;
    const driver: PgDriverV1 = {
      async query<Row>() { queries += 1; return { rows: [{ ok: 1 }] as Row[] }; },
      async transaction<T>(_work: (tx: PgQueryV1) => Promise<T>): Promise<T> {
        throw new Error("unexpected transaction");
      },
    };
    const worker = await composeLicenseWorkerV1(env, { driver });
    const request = async (deviceToken: string) => worker.fetch(new Request(
      "https://worker.test/v1/internal/device-entitlement/verify",
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-internal-service-token": "service-fixture-secret",
        },
        body: JSON.stringify({ schema_version: 1, device_token: deviceToken }),
      },
    ));
    const expiry = BigInt(Date.now() + 60_000) * 1_000_000n;
    const invalidSignature = await request(await token(pair, expiry, true));
    expect(invalidSignature.status).toBe(401);
    expect(queries).toBe(0);
    const expired = await request(await token(pair, BigInt(Date.now() - 1_000) * 1_000_000n));
    expect(expired.status).toBe(401);
    expect(queries).toBe(0);
  });

  it("rejects an inactive device even when its token is valid and signed", async () => {
    const pair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"],
    );
    const publicJwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
    const privateBytes = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
    const env = bindings(privateBytes, publicJwk);
    let queries = 0;
    const driver: PgDriverV1 = {
      async query<Row>() { queries += 1; return { rows: [] as Row[] }; },
      async transaction<T>(_work: (tx: PgQueryV1) => Promise<T>): Promise<T> {
        throw new Error("unexpected transaction");
      },
    };
    const worker = await composeLicenseWorkerV1(env, { driver });
    const deviceToken = await token(pair, BigInt(Date.now() + 60_000) * 1_000_000n);
    const response = await worker.fetch(new Request(
      "https://worker.test/v1/internal/device-entitlement/verify",
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-internal-service-token": "service-fixture-secret",
        },
        body: JSON.stringify({ schema_version: 1, device_token: deviceToken }),
      },
    ));
    expect(response.status).toBe(401);
    expect(queries).toBe(1);
  });
});
