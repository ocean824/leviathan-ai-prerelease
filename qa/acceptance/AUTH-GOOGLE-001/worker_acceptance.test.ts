import { describe, expect, it } from "vitest";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { googleAuthorizationUrlV1 } from "../../../workers/licensing/src/google_auth/oidc.js";
import { createPkcePairV1 } from "../../../workers/licensing/src/google_auth/pkce.js";
import { verifyGoogleIdentityTokenV1 } from "../../../workers/licensing/src/google_auth/oidc.js";

const ROOT = resolve(process.cwd(), "../..");
const AUDIENCE = "acceptance-client.apps.googleusercontent.com";
const NONCE = "acceptance-nonce-0123456789abcdef";
const NOW = 1_900_000_000;
const b64url = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");
const encode = (value: unknown) => b64url(new TextEncoder().encode(JSON.stringify(value)));

async function signedToken(patch: Record<string, unknown> = {}, corruptSignature = false) {
  const pair = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
  const publicJwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const header = encode({ alg: "RS256", kid: "acceptance-key" });
  const claims = encode({ iss: "https://accounts.google.com", aud: AUDIENCE, exp: NOW + 300,
    iat: NOW - 10, nonce: NONCE, email_verified: true, sub: "subject-acceptance-1",
    email: "User@example.test", ...patch });
  const input = `${header}.${claims}`;
  const signature = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", pair.privateKey,
    new TextEncoder().encode(input)));
  if (corruptSignature) signature[0] ^= 0xff;
  const fetcher: typeof fetch = async () => new Response(JSON.stringify({ keys: [{ ...publicJwk,
    kid: "acceptance-key", alg: "RS256", use: "sig" }] }), { status: 200 });
  return { token: `${input}.${b64url(signature)}`, fetcher };
}

describe("AUTH-GOOGLE-001 independent Worker acceptance", () => {
  it("builds a PKCE S256 challenge and a loopback desktop authorization URL", async () => {
    const pair = await createPkcePairV1();
    expect(pair.verifier).toMatch(/^[A-Za-z0-9_-]{43,128}$/);
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(pair.verifier)));
    expect(pair.challenge).toBe(b64url(digest));
    const url = new URL(googleAuthorizationUrlV1({ client_id: AUDIENCE, redirect_uri: "http://127.0.0.1:43821/oauth/callback",
      state: "state-acceptance", nonce: NONCE, code_challenge: pair.challenge }));
    expect(url.searchParams.get("redirect_uri")).toBe("http://127.0.0.1:43821/oauth/callback");
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(url.searchParams.get("code_challenge")).toBe(pair.challenge);
  });

  it("uses single-use state and exact redirect matching in the desktop callback", async () => {
    const store = await readFile(resolve(ROOT, "workers/licensing/src/google_auth/store.ts"), "utf8");
    const desktop = await readFile(resolve(ROOT, "apps/desktop/src-tauri/src/google_login.rs"), "utf8");
    expect(store).toContain("consumed_at_utc_ns IS NULL AND expires_at_utc_ns>$3");
    expect(desktop).toContain("TcpListener::bind((\"127.0.0.1\", 0))");
    expect(desktop).toContain("value == &redirect_uri");
    expect(desktop).toContain("key == \"state\" && value == &state");
  });

  it("accepts an RSA-signed Google identity from fake JWKS", async () => {
    const fixture = await signedToken();
    const identity = await verifyGoogleIdentityTokenV1(fixture.token, { audience: AUDIENCE, nonce: NONCE,
      now_unix_seconds: NOW, fetcher: fixture.fetcher });
    expect(identity).toMatchObject({ subject: "subject-acceptance-1", email: "user@example.test", email_verified: true });
  });

  it.each([
    ["issuer", { iss: "https://attacker.invalid" }],
    ["audience", { aud: "other-client.apps.googleusercontent.com" }],
    ["expiry", { exp: NOW - 1 }],
    ["nonce", { nonce: "different-acceptance-nonce" }],
    ["email_verified", { email_verified: false }],
  ])("rejects a token with an invalid %s claim", async (_name, claims) => {
    const fixture = await signedToken(claims);
    await expect(verifyGoogleIdentityTokenV1(fixture.token, { audience: AUDIENCE, nonce: NONCE,
      now_unix_seconds: NOW, fetcher: fixture.fetcher })).rejects.toMatchObject({ code: "INVALID_GOOGLE_CLAIMS" });
  });

  it("rejects a signature that does not verify against the JWKS key", async () => {
    const fixture = await signedToken({}, true);
    await expect(verifyGoogleIdentityTokenV1(fixture.token, { audience: AUDIENCE, nonce: NONCE,
      now_unix_seconds: NOW, fetcher: fixture.fetcher })).rejects.toMatchObject({ code: "INVALID_GOOGLE_SIGNATURE" });
  });

  it("links a verified provider identity by subject and rejects email-only account merging", async () => {
    const store = await readFile(resolve(ROOT, "workers/licensing/src/google_auth/store.ts"), "utf8");
    expect(store).toContain("WHERE provider='GOOGLE' AND subject=$1 FOR UPDATE");
    expect(store).toContain("if (matched.rows.length > 1) throw new GoogleAccountLinkErrorV1(\"ACCOUNT_LINK_CONFLICT\")");
    expect(store).toContain("if (!account) throw new GoogleAccountLinkErrorV1(\"ACCOUNT_NOT_FOUND\")");
  });

  it("issues USER sessions and routes them through the existing compose resolver", async () => {
    const routes = await readFile(resolve(ROOT, "workers/licensing/src/google_auth/routes.ts"), "utf8");
    const compose = await readFile(resolve(ROOT, "workers/licensing/src/worker/compose.ts"), "utf8");
    expect(routes).toContain("'USER'");
    expect(compose).toContain("session_kind='USER'");
    expect(compose).toContain("googleAuthApi");
  });

  it("fails closed when Google route dependencies are missing", async () => {
    const { googleAuthRoutes } = await import("../../../workers/licensing/src/google_auth/routes.js");
    const response = await googleAuthRoutes(new Request("https://worker.test/v1/auth/google/desktop/start", { method: "POST" }));
    expect(response?.status).toBe(503);
    await expect(response?.json()).resolves.toMatchObject({ error: { code: "NOT_CONFIGURED" } });
  });
});
