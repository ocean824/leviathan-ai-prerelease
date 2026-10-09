import { describe, expect, it } from "vitest";
import workerV1, { createDataGatewayV1 } from "../src/handler.js";
import { DATA_GATEWAY_PROVIDERS_V1 } from "../src/providers.js";
import type {
  GatewayDependenciesV1,
  GatewayEnvV1,
  GatewayLogEntryV1,
} from "../src/auth.js";

const DEVICE_TOKEN = "synthetic-device-token";
const PROVIDER_KEY = "synthetic-provider-secret";

class FakeUpstream {
  calls: Array<{ url: URL; init: RequestInit }> = [];
  response = new Response('{"ok":true}', { status: 200, headers: { "content-type": "application/json" } });

  readonly fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    this.calls.push({ url: new URL(input.toString()), init: init ?? {} });
    return this.response;
  };
}

function harness(
  env: GatewayEnvV1 = { PROVIDER__FRED__API_KEY: PROVIDER_KEY },
  overrides: Partial<GatewayDependenciesV1> = {},
) {
  const logs: GatewayLogEntryV1[] = [];
  const upstream = new FakeUpstream();
  const dependencies: GatewayDependenciesV1 = {
    entitlement: { authenticateDeviceBearer: async (token) => token === DEVICE_TOKEN ? { device_id: "device-test-1", licence_id: "licence-test-1" } : null },
    rateLimiter: { consume: async () => true },
    upstreamFetch: upstream.fetch,
    logger: { log: (entry) => logs.push(entry) },
    ...overrides,
  };
  return { gateway: createDataGatewayV1({ env, ...dependencies }), logs, upstream };
}

function request(path: string, headers: HeadersInit = {}, method = "GET"): Request {
  const merged = new Headers({ authorization: `Bearer ${DEVICE_TOKEN}` });
  new Headers(headers).forEach((value, key) => merged.set(key, value));
  return new Request(`https://gateway.test/v1/${path}`, {
    method,
    headers: merged,
  });
}

async function errorBody(response: Response): Promise<{ schema_version: number; error: { code: string } }> {
  return await response.json() as { schema_version: number; error: { code: string } };
}

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

describe("Cloudflare data-gateway deployment health", () => {
  it("reports ready only when an entitlement verifier is bound", async () => {
    const unavailable = await workerV1.fetch(new Request("https://gateway.test/health"), {});
    expect(unavailable.status).toBe(503);
    let verifierCalls = 0;
    const healthy = await workerV1.fetch(new Request("https://gateway.test/health"), {
      LICENSE_WORKER: { async fetch() { verifierCalls += 1; return Response.json({}); } },
    });
    expect(healthy.status).toBe(200);
    expect(await healthy.json()).toEqual({ status: "ok" });
    expect(verifierCalls).toBe(0);
  });
});

describe("Data Gateway Worker", () => {
  it("publishes the closed six-provider registry as deeply frozen policy", () => {
    expect(Object.keys(DATA_GATEWAY_PROVIDERS_V1).sort()).toEqual([
      "bea", "databento", "eia", "fred", "massive", "unusual_whales",
    ]);
    expect(Object.isFrozen(DATA_GATEWAY_PROVIDERS_V1)).toBe(true);
    expect(Object.isFrozen(DATA_GATEWAY_PROVIDERS_V1.fred)).toBe(true);
    expect(Object.isFrozen(DATA_GATEWAY_PROVIDERS_V1.fred?.routes)).toBe(true);
    expect(Object.isFrozen(DATA_GATEWAY_PROVIDERS_V1.fred?.routes[0])).toBe(true);
    expect(Object.isFrozen(DATA_GATEWAY_PROVIDERS_V1.fred?.routes[0]?.query_keys)).toBe(true);
  });

  it("default Worker fails closed when no entitlement verifier binding is configured", async () => {
    const response = await workerV1.fetch(
      new Request("https://gateway.test/v1/fred/fred/series/observations"),
      {},
    );
    expect(response.status).toBe(503);
    expect(await errorBody(response)).toEqual({ schema_version: 1, error: { code: "NOT_CONFIGURED" } });
  });

  it("default Worker uses the named license service binding without logging bearer data", async () => {
    const logs: string[] = [];
    const originalLog = console.log;
    console.log = (...items: unknown[]) => { logs.push(items.join(" ")); };
    try {
      const response = await workerV1.fetch(
        new Request("https://gateway.test/v1/not_a_provider/x?series_id=GDP", {
          headers: { authorization: `Bearer ${DEVICE_TOKEN}` },
        }),
        {
          LICENSE_WORKER: {
            fetch: async (input, init) => {
              expect(String(input)).toBe("https://license-worker.internal/v1/internal/device-entitlement/verify");
              expect(init?.method).toBe("POST");
              expect(String(init?.body)).toContain(DEVICE_TOKEN);
              return Response.json({
                schema_version: 1,
                data: { active: true, device_id: "device-test-1", licence_id: "licence-test-1" },
              });
            },
          },
          PROVIDER__FRED__API_KEY: PROVIDER_KEY,
        },
      );
      expect(response.status).toBe(404);
      expect(await errorBody(response)).toEqual({ schema_version: 1, error: { code: "PROVIDER_NOT_FOUND" } });
      expect(logs.join(" ")).not.toContain(DEVICE_TOKEN);
      expect(logs.join(" ")).not.toContain(PROVIDER_KEY);
      expect(logs.join(" ")).not.toContain("series_id=GDP");
    } finally {
      console.log = originalLog;
    }
  });

  it("default Worker verifies a synthetic ES256 device token with the licence JWK fallback", async () => {
    const pair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"],
    );
    const jwk = JSON.stringify(await crypto.subtle.exportKey("jwk", pair.publicKey));
    const now = Math.floor(Date.now() / 1_000);
    const header = base64Url(new TextEncoder().encode(JSON.stringify({ alg: "ES256", typ: "JWT" })));
    const claims = base64Url(new TextEncoder().encode(JSON.stringify({
      iss: "leviathan-licensing",
      aud: "leviathan-data-gateway",
      entitled: true,
      device_id: "device-test-1",
      sub: "device-test-1",
      licence_id: "licence-test-1",
      iat: now,
      exp: now + 300,
    })));
    const content = `${header}.${claims}`;
    const signature = new Uint8Array(await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      pair.privateKey,
      new TextEncoder().encode(content),
    ));
    const token = `${content}.${base64Url(signature)}`;
    const response = await workerV1.fetch(
      new Request("https://gateway.test/v1/not_a_provider/x", { headers: { authorization: `Bearer ${token}` } }),
      { LICENSE_VERIFY_PUBLIC_KEY_JWK: jwk },
    );
    expect(response.status).toBe(404);
    expect(await errorBody(response)).toEqual({ schema_version: 1, error: { code: "PROVIDER_NOT_FOUND" } });
  });

  it("denies a missing device bearer before calling upstream", async () => {
    const { gateway, upstream } = harness();
    const response = await gateway.fetch(new Request("https://gateway.test/v1/fred/fred/series/observations"));
    expect(response.status).toBe(401);
    expect(await errorBody(response)).toEqual({ schema_version: 1, error: { code: "UNAUTHENTICATED" } });
    expect(upstream.calls).toHaveLength(0);
  });

  it("allows only known providers and path prefixes", async () => {
    const { gateway, upstream } = harness();
    const unknown = await gateway.fetch(request("not_a_provider/data"));
    expect(unknown.status).toBe(404);
    expect(await errorBody(unknown)).toEqual({ schema_version: 1, error: { code: "PROVIDER_NOT_FOUND" } });
    const badPath = await gateway.fetch(request("fred/admin/keys"));
    expect(badPath.status).toBe(403);
    expect(await errorBody(badPath)).toEqual({ schema_version: 1, error: { code: "PATH_NOT_ALLOWED" } });
    expect(upstream.calls).toHaveLength(0);
  });

  it("rejects traversal markers through repeated percent encoding", async () => {
    const { gateway, upstream } = harness();
    for (const path of [
      "fred/fred/series/observations/%252e%252e/admin",
      "fred/fred/series/observations/%25252e%25252e/admin",
      "fred/fred/series/observations/%252fadmin",
      "fred/fred/series/observations/%255cadmin",
    ]) {
      const response = await gateway.fetch(request(path));
      expect(response.status).toBe(403);
      expect(await errorBody(response)).toEqual({ schema_version: 1, error: { code: "PATH_NOT_ALLOWED" } });
    }
    expect(upstream.calls).toHaveLength(0);
  });

  it("strips client credentials and injects the configured server key", async () => {
    const { gateway, upstream } = harness();
    const response = await gateway.fetch(request("fred/fred/series/observations?series_id=GDP&api_key=attacker&x-api-key=attacker2", {
      authorization: `Bearer ${DEVICE_TOKEN}`,
      "x-api-key": "attacker-provider-key",
      cookie: "session=synthetic-cookie",
      accept: "application/json",
    }));
    expect(response.status).toBe(200);
    expect(upstream.calls).toHaveLength(1);
    const call = upstream.calls[0]!;
    expect(call.url.origin).toBe("https://api.stlouisfed.org");
    expect(call.url.searchParams.get("series_id")).toBe("GDP");
    expect(call.url.searchParams.get("api_key")).toBe(PROVIDER_KEY);
    expect(call.url.searchParams.has("x-api-key")).toBe(false);
    expect(call.init.headers).toBeInstanceOf(Headers);
    const headers = call.init.headers as Headers;
    expect(headers.get("authorization")).toBeNull();
    expect(headers.get("x-api-key")).toBeNull();
    expect(headers.get("cookie")).toBeNull();
    expect(call.init.redirect).toBe("manual");
  });

  it("strips credential fields from Databento forms and rejects unknown form fields", async () => {
    const { gateway, upstream } = harness({ PROVIDER__DATABENTO__API_KEY: PROVIDER_KEY });
    const response = await gateway.fetch(new Request(
      "https://gateway.test/v1/databento/v0/timeseries.get_range",
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${DEVICE_TOKEN}`,
          "content-type": "application/x-www-form-urlencoded",
          "x-api-key": "client-provider-key",
        },
        body: "dataset=GLBX.MDP3&symbols=ESM6&token=client-token&Authorization=client-auth&api_key=client-key",
      },
    ));

    expect(response.status).toBe(200);
    expect(upstream.calls).toHaveLength(1);
    const call = upstream.calls[0]!;
    expect(call.url.origin).toBe("https://hist.databento.com");
    expect(call.url.pathname).toBe("/v0/timeseries.get_range");
    expect(call.init.headers).toBeInstanceOf(Headers);
    const headers = call.init.headers as Headers;
    expect(headers.get("authorization")).toBe(`Basic ${btoa(`${PROVIDER_KEY}:`)}`);
    expect(headers.get("x-api-key")).toBeNull();
    expect(String(call.init.body)).toBe("dataset=GLBX.MDP3&symbols=ESM6");
    expect(String(call.init.body)).not.toMatch(/client-token|client-auth|client-key/);

    const unknown = await gateway.fetch(new Request(
      "https://gateway.test/v1/databento/v0/timeseries.get_range",
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${DEVICE_TOKEN}`,
          "content-type": "application/x-www-form-urlencoded",
        },
        body: "dataset=GLBX.MDP3&symbols=ESM6&credential_like_field=never-forward",
      },
    ));
    expect(unknown.status).toBe(403);
    expect(await errorBody(unknown)).toEqual({ schema_version: 1, error: { code: "PATH_NOT_ALLOWED" } });
    expect(upstream.calls).toHaveLength(1);
  });

  it("returns NOT_CONFIGURED when the provider secret is missing", async () => {
    const { gateway, upstream } = harness({});
    const response = await gateway.fetch(request("fred/fred/series/observations?series_id=GDP"));
    expect(response.status).toBe(503);
    expect(await errorBody(response)).toEqual({ schema_version: 1, error: { code: "NOT_CONFIGURED" } });
    expect(upstream.calls).toHaveLength(0);
  });

  it("denies upstream redirects without exposing Location or body", async () => {
    const { gateway, upstream, logs } = harness();
    upstream.response = new Response("synthetic redirect body", {
      status: 302,
      headers: { location: "https://attacker.example/?key=synthetic-provider-secret" },
    });
    const response = await gateway.fetch(request("fred/fred/series/observations?series_id=GDP"));
    const text = await response.text();
    expect(response.status).toBe(502);
    expect(text).toBe('{"schema_version":1,"error":{"code":"UPSTREAM_REDIRECT_DENIED"}}');
    expect(text).not.toContain("attacker.example");
    expect(text).not.toContain("synthetic-provider-secret");
    expect(JSON.stringify(logs)).not.toContain("attacker.example");
    expect(JSON.stringify(logs)).not.toContain("synthetic-provider-secret");
  });

  it("redacts echoed secrets and device tokens in successful response bodies", async () => {
    const { gateway, upstream } = harness();
    upstream.response = new Response(`{"key":"${PROVIDER_KEY}","device":"${DEVICE_TOKEN}"}`, {
      status: 200,
      headers: { "content-type": "application/json" },
    });
    const response = await gateway.fetch(request("fred/fred/series/observations?series_id=GDP"));
    const body = await response.text();
    expect(response.status).toBe(200);
    expect(body).not.toContain(PROVIDER_KEY);
    expect(body).not.toContain(DEVICE_TOKEN);
    expect(body).toContain("[REDACTED]");
  });

  it("applies the device and provider limiter and keeps query strings out of logs", async () => {
    let consumed: unknown;
    const { gateway, logs } = harness(undefined, {
      rateLimiter: { consume: async (input) => { consumed = input; return false; } },
    });
    const response = await gateway.fetch(request("fred/fred/series/observations?series_id=SECRET_QUERY"));
    expect(response.status).toBe(429);
    expect(await errorBody(response)).toEqual({ schema_version: 1, error: { code: "RATE_LIMITED" } });
    expect(consumed).toEqual({ device_id: "device-test-1", provider_id: "fred" });
    expect(JSON.stringify(logs)).not.toContain("SECRET_QUERY");
    expect(logs[0]).toEqual({
      event: "denied",
      code: "RATE_LIMITED",
      provider_id: "fred",
      method: "GET",
      path: "/v1/fred/fred/series/observations",
      status: 429,
    });
  });

  it("redacts provider secrets in caller-controlled log paths and methods", async () => {
    const { gateway, logs } = harness();
    const response = await gateway.fetch(new Request(
      `https://gateway.test/v1/fred/fred/series/observations/${encodeURIComponent(PROVIDER_KEY)}`,
      { method: PROVIDER_KEY, headers: { authorization: `Bearer ${DEVICE_TOKEN}` } },
    ));

    expect(response.status).toBe(405);
    expect(JSON.stringify(logs)).not.toContain(PROVIDER_KEY);
    expect(logs[0]?.method).toBe("OTHER");
    expect(logs[0]?.path).not.toContain(PROVIDER_KEY);
  });

  it("redacts a configured provider secret even when it equals a standard method", async () => {
    const { gateway, logs } = harness({ PROVIDER__FRED__API_KEY: "GET" });
    const response = await gateway.fetch(request("fred/fred/series/observations?series_id=GDP"));

    expect(response.status).toBe(200);
    expect(JSON.stringify(logs)).not.toContain("GET");
    expect(logs[0]?.method).toBe("[REDACTED]");
  });

  it("fails closed for bad path syntax and unsupported methods", async () => {
    const { gateway, upstream } = harness();
    const unsafe = await gateway.fetch(request("fred/fred/series/%2fadmin"));
    expect(unsafe.status).toBe(403);
    const method = await gateway.fetch(request("fred/fred/series/observations", {}, "DELETE"));
    expect(method.status).toBe(405);
    expect(await errorBody(method)).toEqual({ schema_version: 1, error: { code: "METHOD_NOT_ALLOWED" } });
    expect(upstream.calls).toHaveLength(0);
  });
});
