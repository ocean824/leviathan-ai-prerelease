import { describe, expect, it } from "vitest";
import workerV1, { createDataGatewayV1 } from "../src/handler.js";
import type {
  GatewayDependenciesV1,
  GatewayEnvV1,
  GatewayLogEntryV1,
} from "../src/auth.js";

const DEVICE_TOKEN = "synthetic-device-bearer-for-tests";
const PROVIDER_SECRET = "synthetic-provider-secret-for-tests";
const FRED_PATH = "/v1/fred/fred/series/observations";

type CapturedRequest = { readonly url: URL; readonly init: RequestInit };

class FakeUpstream {
  readonly calls: CapturedRequest[] = [];
  response: () => Response = () => Response.json({ ok: true });

  readonly fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    this.calls.push({ url: new URL(input.toString()), init: init ?? {} });
    return this.response();
  };
}

function gatewayHarness(options: {
  env?: GatewayEnvV1;
  authenticate?: (token: string) => Promise<{ device_id: string; licence_id: string } | null>;
  consume?: (deviceId: string, providerId: string) => Promise<boolean>;
} = {}) {
  const logs: GatewayLogEntryV1[] = [];
  const upstream = new FakeUpstream();
  const dependencies: GatewayDependenciesV1 = {
    entitlement: {
      authenticateDeviceBearer: options.authenticate ?? (async (token) =>
        token === DEVICE_TOKEN ? { device_id: "device-A", licence_id: "licence-A" } : null),
    },
    rateLimiter: {
      consume: async ({ device_id, provider_id }) =>
        options.consume ? options.consume(device_id, provider_id) : true,
    },
    upstreamFetch: upstream.fetch,
    logger: { log: (entry) => logs.push(entry) },
  };
  return {
    gateway: createDataGatewayV1({ env: options.env ?? { PROVIDER__FRED__API_KEY: PROVIDER_SECRET, PROVIDER__MASSIVE__API_KEY: "massive-test-key" }, ...dependencies }),
    logs,
    upstream,
  };
}

function makeRequest(
  path: string,
  options: { token?: string | null; method?: string; headers?: HeadersInit; body?: BodyInit } = {},
): Request {
  const headers = new Headers(options.headers);
  if (options.token === null) headers.delete("authorization");
  else if (options.token !== undefined) headers.set("authorization", `Bearer ${options.token}`);
  else if (!headers.has("authorization")) headers.set("authorization", `Bearer ${DEVICE_TOKEN}`);
  return new Request(`https://gateway.test${path}`, {
    method: options.method ?? "GET",
    headers,
    ...(options.body === undefined ? {} : { body: options.body }),
  });
}

async function readError(response: Response): Promise<unknown> {
  return response.json() as Promise<unknown>;
}

function expectSafeLog(entries: readonly GatewayLogEntryV1[]): void {
  for (const entry of entries) {
    expect(Object.keys(entry).sort()).toEqual([
      "code", "event", "method", "path", "provider_id", "status",
    ]);
    expect(entry.path).not.toContain("?");
    expect(JSON.stringify(entry)).not.toContain(DEVICE_TOKEN);
    expect(JSON.stringify(entry)).not.toContain(PROVIDER_SECRET);
  }
}

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function signedDeviceToken(
  privateKey: CryptoKey,
  claims: Record<string, unknown>,
): Promise<string> {
  const header = base64Url(new TextEncoder().encode(JSON.stringify({ alg: "ES256", typ: "JWT" })));
  const payload = base64Url(new TextEncoder().encode(JSON.stringify(claims)));
  const signingInput = `${header}.${payload}`;
  const signature = new Uint8Array(await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    privateKey,
    new TextEncoder().encode(signingInput),
  ));
  return `${signingInput}.${base64Url(signature)}`;
}

describe("DATA-GATEWAY-001 independent acceptance", () => {
  it("denies absent, invalid, and inactive device entitlements before upstream access", async () => {
    const absent = gatewayHarness();
    const absentResponse = await absent.gateway.fetch(makeRequest(FRED_PATH, { token: null }));
    expect(absentResponse.status).toBe(401);
    expect(await readError(absentResponse)).toEqual({ schema_version: 1, error: { code: "UNAUTHENTICATED" } });
    expect(absent.upstream.calls).toHaveLength(0);

    const invalid = gatewayHarness({ authenticate: async () => null });
    const invalidResponse = await invalid.gateway.fetch(makeRequest(FRED_PATH, { token: "forged-device-token" }));
    expect(invalidResponse.status).toBe(401);
    expect(await readError(invalidResponse)).toEqual({ schema_version: 1, error: { code: "UNAUTHENTICATED" } });
    expect(invalid.upstream.calls).toHaveLength(0);
  });

  it("uses only registered provider, path, and method combinations", async () => {
    const { gateway, upstream } = gatewayHarness();
    const unknownProvider = await gateway.fetch(makeRequest("/v1/not_registered/data"));
    expect(unknownProvider.status).toBe(404);
    expect(await readError(unknownProvider)).toEqual({ schema_version: 1, error: { code: "PROVIDER_NOT_FOUND" } });

    const unknownPath = await gateway.fetch(makeRequest("/v1/fred/admin/keys"));
    expect(unknownPath.status).toBe(403);
    expect(await readError(unknownPath)).toEqual({ schema_version: 1, error: { code: "PATH_NOT_ALLOWED" } });

    const wrongMethod = await gateway.fetch(makeRequest(FRED_PATH, { method: "POST" }));
    expect(wrongMethod.status).toBe(405);
    expect(await readError(wrongMethod)).toEqual({ schema_version: 1, error: { code: "METHOD_NOT_ALLOWED" } });
    expect(upstream.calls).toHaveLength(0);
  });

  it("does not log secret-shaped caller path or method values on denial", async () => {
    const { gateway, logs, upstream } = gatewayHarness();
    const pathResponse = await gateway.fetch(makeRequest(`/v1/fred/private/${PROVIDER_SECRET}`));
    expect(pathResponse.status).toBe(403);
    expect(await readError(pathResponse)).toEqual({ schema_version: 1, error: { code: "PATH_NOT_ALLOWED" } });

    const methodResponse = await gateway.fetch(makeRequest(FRED_PATH, { method: DEVICE_TOKEN }));
    expect(methodResponse.status).toBe(405);
    expect(await readError(methodResponse)).toEqual({ schema_version: 1, error: { code: "METHOD_NOT_ALLOWED" } });
    expectSafeLog(logs);
    expect(upstream.calls).toHaveLength(0);
  });

  it("replaces client authentication and provider query credentials with the server secret", async () => {
    const { gateway, upstream } = gatewayHarness();
    const response = await gateway.fetch(makeRequest(
      `${FRED_PATH}?series_id=GDP&api_key=attacker-key&X-API-KEY=attacker-header-key&token=attacker-token`,
      {
        headers: {
          authorization: `Bearer ${DEVICE_TOKEN}`,
          "x-api-key": "attacker-header-key",
          cookie: "synthetic-cookie=value",
          host: "attacker.example",
          accept: "application/json",
        },
      },
    ));
    expect(response.status).toBe(200);
    expect(upstream.calls).toHaveLength(1);
    const call = upstream.calls[0]!;
    expect(call.url.origin).toBe("https://api.stlouisfed.org");
    expect(call.url.pathname).toBe("/fred/series/observations");
    expect(call.url.searchParams.get("series_id")).toBe("GDP");
    expect(call.url.searchParams.get("api_key")).toBe(PROVIDER_SECRET);
    for (const key of ["token", "X-API-KEY", "x-api-key"]) {
      expect(call.url.searchParams.has(key)).toBe(false);
    }
    const headers = call.init.headers as Headers;
    expect(headers.get("authorization")).toBeNull();
    expect(headers.get("x-api-key")).toBeNull();
    expect(headers.get("cookie")).toBeNull();
    expect(headers.get("host")).toBeNull();
    expect(call.init.redirect).toBe("manual");
  });

  it("strips provider credential keys from Databento form bodies and denies unregistered fields", async () => {
    const { gateway, upstream } = gatewayHarness({ env: { PROVIDER__DATABENTO__API_KEY: PROVIDER_SECRET } });
    const response = await gateway.fetch(makeRequest("/v1/databento/v0/timeseries.get_range", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", authorization: `Bearer ${DEVICE_TOKEN}` },
      body: "dataset=GLBX.MDP3&symbols=ESM6&schema=trades&api_key=attacker&X-API-KEY=attacker&token=attacker",
    }));
    expect(response.status).toBe(200);
    expect(upstream.calls).toHaveLength(1);
    const forwardedBody = String(upstream.calls[0]!.init.body);
    expect(forwardedBody).toContain("dataset=GLBX.MDP3");
    expect(forwardedBody.toLowerCase()).not.toContain("api_key");
    expect(forwardedBody.toLowerCase()).not.toContain("token=");
    const forwardedHeaders = upstream.calls[0]!.init.headers as Headers;
    expect(forwardedHeaders.get("authorization")).toBe(`Basic ${btoa(`${PROVIDER_SECRET}:`)}`);

    const denied = await gateway.fetch(makeRequest("/v1/databento/v0/timeseries.get_range", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: "dataset=GLBX.MDP3&symbols=ESM6&schema=trades&provider_secret=attacker",
    }));
    expect(denied.status).toBe(403);
    expect(await readError(denied)).toEqual({ schema_version: 1, error: { code: "PATH_NOT_ALLOWED" } });
    expect(upstream.calls).toHaveLength(1);
  });

  it("rejects path tricks and never lets a caller-selected host change the provider origin", async () => {
    const { gateway, upstream } = gatewayHarness();
    for (const path of [
      "/v1/fred//attacker.example/fred/series/observations",
      "/v1/fred/@attacker.example/fred/series/observations",
      "/v1/fred/fred/series/%2fadmin",
      "/v1/fred/fred/series/observations/%2e%2e/admin",
      "/v1/fred/fred/series/observations/%252e%252e/admin",
      "/v1/fred/fred/series/observations/%25252e%25252e/admin",
      "/v1/fred/fred/series/observations/%252fadmin",
      "/v1/fred/fred/series/observations/%255cadmin",
      "/v1/fred/fred/series/observations/../../admin",
    ]) {
      const response = await gateway.fetch(makeRequest(path));
      expect([403, 404]).toContain(response.status);
    }
    expect(upstream.calls).toHaveLength(0);
  });

  it("returns fixed NOT_CONFIGURED when a provider secret is absent", async () => {
    const { gateway, upstream, logs } = gatewayHarness({ env: {} });
    const response = await gateway.fetch(makeRequest(FRED_PATH));
    expect(response.status).toBe(503);
    expect(await readError(response)).toEqual({ schema_version: 1, error: { code: "NOT_CONFIGURED" } });
    expect(upstream.calls).toHaveLength(0);
    expectSafeLog(logs);
  });

  it("redacts synthetic secrets from success bodies, upstream errors, redirects, headers, and logs", async () => {
    const { gateway, upstream, logs } = gatewayHarness();
    upstream.response = () => new Response(
      JSON.stringify({ provider: PROVIDER_SECRET, device: DEVICE_TOKEN, encoded: encodeURIComponent(PROVIDER_SECRET) }),
      { status: 200, headers: { "content-type": "application/json" } },
    );
    const success = await gateway.fetch(makeRequest(`${FRED_PATH}?series_id=SECRET_QUERY`));
    const successBody = await success.text();
    expect(success.status).toBe(200);
    expect(successBody).not.toContain(PROVIDER_SECRET);
    expect(successBody).not.toContain(DEVICE_TOKEN);
    expect(successBody).toContain("[REDACTED]");
    expect(success.headers.get("cache-control")).toBe("no-store");

    upstream.response = () => new Response(`upstream echoed ${PROVIDER_SECRET} and ${DEVICE_TOKEN}`, {
      status: 500,
      headers: {
        location: `https://attacker.example/?key=${encodeURIComponent(PROVIDER_SECRET)}`,
        "content-type": `text/plain; ${PROVIDER_SECRET}`,
      },
    });
    const failed = await gateway.fetch(makeRequest(`${FRED_PATH}?series_id=SECRET_QUERY`));
    const failedBody = await failed.text();
    expect(failed.status).toBe(502);
    expect(failedBody).toBe('{"schema_version":1,"error":{"code":"UPSTREAM_ERROR"}}');
    expect(failedBody).not.toContain(PROVIDER_SECRET);
    expect(failed.headers.get("location")).toBeNull();

    upstream.response = () => new Response(`redirect echoed ${PROVIDER_SECRET}`, {
      status: 302,
      headers: { location: `https://attacker.example/path?key=${PROVIDER_SECRET}` },
    });
    const redirect = await gateway.fetch(makeRequest(FRED_PATH));
    const redirectBody = await redirect.text();
    expect(redirect.status).toBe(502);
    expect(redirectBody).toBe('{"schema_version":1,"error":{"code":"UPSTREAM_REDIRECT_DENIED"}}');
    expect(redirect.headers.get("location")).toBeNull();

    const observableHeaders = [
      success.headers.get("location"), success.headers.get("content-type"),
      failed.headers.get("location"), failed.headers.get("content-type"),
      redirect.headers.get("location"), redirect.headers.get("content-type"),
    ];
    const observable = `${successBody}\n${failedBody}\n${redirectBody}\n${JSON.stringify(observableHeaders)}\n${JSON.stringify(logs)}`;
    expect(observable).not.toContain(PROVIDER_SECRET);
    expect(observable).not.toContain(DEVICE_TOKEN);
    expect(observable).not.toContain("SECRET_QUERY");
    expect(observable).not.toContain("attacker.example");
    expectSafeLog(logs);
  });

  it("applies rate limiting independently to each device and provider", async () => {
    const counts = new Map<string, number>();
    const seen: Array<{ device_id: string; provider_id: string }> = [];
    const { gateway, upstream } = gatewayHarness({
      env: { PROVIDER__FRED__API_KEY: PROVIDER_SECRET, PROVIDER__MASSIVE__API_KEY: "massive-secret" },
      authenticate: async (token) => token === "device-token-B"
        ? { device_id: "device-B", licence_id: "licence-B" }
        : { device_id: "device-A", licence_id: "licence-A" },
      consume: async (device_id, provider_id) => {
        seen.push({ device_id, provider_id });
        const key = `${device_id}:${provider_id}`;
        const count = (counts.get(key) ?? 0) + 1;
        counts.set(key, count);
        return count === 1;
      },
    });
    const firstA = await gateway.fetch(makeRequest(FRED_PATH));
    const firstB = await gateway.fetch(makeRequest(FRED_PATH, { token: "device-token-B" }));
    const firstOtherProvider = await gateway.fetch(makeRequest("/v1/massive/v3/trades/AAPL"));
    const limitedA = await gateway.fetch(makeRequest(FRED_PATH));
    expect([firstA.status, firstB.status, firstOtherProvider.status, limitedA.status]).toEqual([200, 200, 200, 429]);
    expect(await readError(limitedA)).toEqual({ schema_version: 1, error: { code: "RATE_LIMITED" } });
    expect(seen).toEqual([
      { device_id: "device-A", provider_id: "fred" },
      { device_id: "device-B", provider_id: "fred" },
      { device_id: "device-A", provider_id: "massive" },
      { device_id: "device-A", provider_id: "fred" },
    ]);
    expect(upstream.calls).toHaveLength(3);
  });

  it("default Worker fails closed without verifier bindings and accepts only correctly signed ES256 device claims", async () => {
    const missing = await workerV1.fetch(new Request(`https://gateway.test${FRED_PATH}`), {});
    expect(missing.status).toBe(503);
    expect(await readError(missing)).toEqual({ schema_version: 1, error: { code: "NOT_CONFIGURED" } });

    const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    const jwk = JSON.stringify(await crypto.subtle.exportKey("jwk", pair.publicKey));
    const now = Math.floor(Date.now() / 1_000);
    const baseClaims = {
      iss: "leviathan-licensing",
      aud: "leviathan-data-gateway",
      entitled: true,
      device_id: "device-JWK",
      sub: "device-JWK",
      licence_id: "licence-JWK",
      iat: now,
      exp: now + 300,
    };
    const validToken = await signedDeviceToken(pair.privateKey, baseClaims);
    const accepted = await workerV1.fetch(
      new Request("https://gateway.test/v1/not_registered/data", { headers: { authorization: `Bearer ${validToken}` } }),
      { LICENSE_VERIFY_PUBLIC_KEY_JWK: jwk },
    );
    expect(accepted.status).toBe(404);
    expect(await readError(accepted)).toEqual({ schema_version: 1, error: { code: "PROVIDER_NOT_FOUND" } });

    const otherPair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    const wrongSignature = await signedDeviceToken(otherPair.privateKey, baseClaims);
    const signatureDenied = await workerV1.fetch(
      new Request(`https://gateway.test${FRED_PATH}`, { headers: { authorization: `Bearer ${wrongSignature}` } }),
      { LICENSE_VERIFY_PUBLIC_KEY_JWK: jwk },
    );
    expect(signatureDenied.status).toBe(401);
    expect(await readError(signatureDenied)).toEqual({ schema_version: 1, error: { code: "UNAUTHENTICATED" } });

    for (const invalidClaims of [
      { ...baseClaims, iss: "attacker" },
      { ...baseClaims, aud: "another-service" },
      { ...baseClaims, entitled: false },
      { ...baseClaims, sub: "another-device" },
      { ...baseClaims, exp: now - 1 },
      { ...baseClaims, iat: now - 86_401, exp: now + 1 },
      { ...baseClaims, iat: now, exp: now + 86_401 },
    ]) {
      const token = await signedDeviceToken(pair.privateKey, invalidClaims);
      const denied = await workerV1.fetch(
        new Request(`https://gateway.test${FRED_PATH}`, { headers: { authorization: `Bearer ${token}` } }),
        { LICENSE_VERIFY_PUBLIC_KEY_JWK: jwk },
      );
      expect(denied.status).toBe(401);
      expect(await readError(denied)).toEqual({ schema_version: 1, error: { code: "UNAUTHENTICATED" } });
    }
  });

  it("default Worker uses the licence service binding and fails closed for missing secret or invalid limiter binding", async () => {
    let licenseCalls = 0;
    const licenseBinding = {
      fetch: async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
        licenseCalls += 1;
        expect(String(input)).toBe("https://license-worker.internal/v1/internal/device-entitlement/verify");
        expect(init?.method).toBe("POST");
        expect(String(init?.body)).toContain(DEVICE_TOKEN);
        expect(init?.redirect).toBe("manual");
        return Response.json({ schema_version: 1, data: { active: true, device_id: "device-A", licence_id: "licence-A" } });
      },
    };
    const missingSecret = await workerV1.fetch(
      new Request(`https://gateway.test${FRED_PATH}`, { headers: { authorization: `Bearer ${DEVICE_TOKEN}` } }),
      { LICENSE_WORKER: licenseBinding },
    );
    expect(missingSecret.status).toBe(503);
    expect(await readError(missingSecret)).toEqual({ schema_version: 1, error: { code: "NOT_CONFIGURED" } });

    const invalidRateBinding = await workerV1.fetch(
      new Request(`https://gateway.test${FRED_PATH}`, { headers: { authorization: `Bearer ${DEVICE_TOKEN}` } }),
      {
        LICENSE_WORKER: licenseBinding,
        RATE_LIMIT: "invalid-binding" as never,
        PROVIDER__FRED__API_KEY: PROVIDER_SECRET,
      },
    );
    expect(invalidRateBinding.status).toBe(503);
    expect(await readError(invalidRateBinding)).toEqual({ schema_version: 1, error: { code: "NOT_CONFIGURED" } });
    expect(licenseCalls).toBe(2);
  });
});
