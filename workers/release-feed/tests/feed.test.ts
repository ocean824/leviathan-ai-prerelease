import { describe, expect, it, vi } from "vitest";
import {
  compareSemVer,
  validateTauriManifest,
} from "../src/manifest.js";
import {
  createReleaseFeedHandler,
  type CloudflareReleaseFeedEnv,
  type ClockPort,
  type R2ReadPort,
  type R2TextObjectPort,
} from "../src/handler.js";
import releaseFeedWorker from "../src/handler.js";

const FEED_URL = "https://updates.example.test";
const HOST = "downloads.example.test";
const ROUTE = "/v1/updates/desktop/windows/x86_64/1.2.2";

type FakeObject = R2TextObjectPort;

function streamText(value: string): ReadableStream<Uint8Array> {
  const bytes = new TextEncoder().encode(value);
  return new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(bytes);
      controller.close();
    },
  });
}

class FakeR2 implements R2ReadPort {
  readonly keys: string[] = [];
  failure: Error | null = null;
  value: string | null = null;
  asset: Uint8Array | null = null;
  customMetadata: Readonly<Record<string, string>> | null = null;

  async get(key: string): Promise<FakeObject | null> {
    this.keys.push(key);
    if (this.failure) throw this.failure;
    if (key.startsWith("releases/")) {
      if (this.asset === null) return null;
      const bytes = new Uint8Array(this.asset);
      return { size: bytes.byteLength, body: streamText(new TextDecoder().decode(bytes)), text: async () => "" };
    }
    if (this.value === null) return null;
    return {
      size: new TextEncoder().encode(this.value).byteLength,
      customMetadata: this.customMetadata ?? undefined,
      body: streamText(this.value),
      text: async () => this.value ?? "",
    };
  }
}

class FakeClock implements ClockPort {
  constructor(private readonly instant = new Date("2026-10-06T12:00:00.000Z")) {}

  now(): Date {
    return new Date(this.instant.getTime());
  }
}

function makeManifest(
  version = "1.2.3",
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    version,
    notes: "Release notes",
    pub_date: "2026-10-06T11:59:00Z",
    platforms: {
      "windows-x86_64": {
        url: `https://${HOST}/releases/1.2.3/Leviathan-setup.exe?sig=fake`,
        signature: "untrusted comment: fake test signature\nZmFrZS1zaWduYXR1cmU=",
      },
    },
    ...overrides,
  };
}

function setup(recordEvent?: (event: "FEED_BEHIND_CLIENT") => void): {
  handler: (request: Request) => Promise<Response>;
  r2: FakeR2;
} {
  const r2 = new FakeR2();
  const handler = createReleaseFeedHandler({
    releases: r2,
    now: new FakeClock(),
    allowedArtifactHosts: [HOST],
    cacheTtlSeconds: 60,
    recordEvent,
  });
  return { handler, r2 };
}

function request(path = ROUTE, method = "GET"): Request {
  return new Request(`${FEED_URL}${path}`, { method });
}

describe("release feed worker", () => {
  it("exposes a content-free health check only when runtime bindings are configured", async () => {
    const r2 = new FakeR2();
    const env: CloudflareReleaseFeedEnv = { RELEASES: r2, ALLOWED_ARTIFACT_HOSTS: "", MANIFEST_CACHE_TTL_SECONDS: "60" };
    const healthy = await releaseFeedWorker.fetch(request("/health"), env);
    expect(healthy.status).toBe(200);
    expect(await healthy.json()).toEqual({ status: "ok" });
    const unready = await releaseFeedWorker.fetch(request("/health"), { ...env, MANIFEST_CACHE_TTL_SECONDS: "0" });
    expect(unready.status).toBe(503);
  });

  it("streams only validated immutable release asset keys from R2", async () => {
    const { handler, r2 } = setup();
    r2.asset = new TextEncoder().encode("synthetic installer bytes");
    const response = await handler(request("/releases/desktop/1.2.3/Leviathan-setup.exe"));
    expect(response.status).toBe(200);
    expect(await response.text()).toBe("synthetic installer bytes");
    expect(r2.keys).toEqual(["releases/desktop/1.2.3/Leviathan-setup.exe"]);
    expect(response.headers.get("Cache-Control")).toBe("public, max-age=31536000, immutable");
  });

  it("rejects malformed release asset paths without an R2 lookup", async () => {
    const { handler, r2 } = setup();
    const response = await handler(request("/releases/desktop/../secret"));
    expect(response.status).toBe(404);
    expect(r2.keys).toEqual([]);
  });

  it("serves validated Tauri v2 metadata from the channel-specific R2 key", async () => {
    const { handler, r2 } = setup();
    r2.value = JSON.stringify(makeManifest());

    const response = await handler(request());

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual(makeManifest());
    expect(r2.keys).toEqual(["channels/desktop/latest.json"]);
    expect(response.headers.get("Cache-Control")).toBe(
      "public, max-age=60, s-maxage=60, must-revalidate",
    );
    expect(response.headers.get("Expires")).toBe("Tue, 06 Oct 2026 12:01:00 GMT");
  });

  it("routes both Darwin architectures to their signed manifest entries", async () => {
    const { handler, r2 } = setup();
    const manifest = makeManifest("1.2.3", {
      platforms: {
        "darwin-aarch64": {
          url: `https://${HOST}/releases/1.2.3/LeviathanAI_1.2.3_aarch64.app.tar.gz`,
          signature: "synthetic-arm-signature",
        },
        "darwin-x86_64": {
          url: `https://${HOST}/releases/1.2.3/LeviathanAI_1.2.3_x86_64.app.tar.gz`,
          signature: "synthetic-intel-signature",
        },
      },
    });
    r2.value = JSON.stringify(manifest);

    const arm = await handler(request("/v1/updates/desktop/darwin/aarch64/1.2.2"));
    const intel = await handler(request("/v1/updates/desktop/darwin/x86_64/1.2.2"));

    expect(arm.status).toBe(200);
    expect((await arm.json() as { platforms: Record<string, unknown> }).platforms)
      .toHaveProperty("darwin-aarch64");
    expect(intel.status).toBe(200);
    expect((await intel.json() as { platforms: Record<string, unknown> }).platforms)
      .toHaveProperty("darwin-x86_64");
  });

  it("returns a short-cached 204 when the channel has no manifest", async () => {
    const { handler, r2 } = setup();

    const response = await handler(request());

    expect(response.status).toBe(204);
    expect(await response.text()).toBe("");
    expect(r2.keys).toEqual(["channels/desktop/latest.json"]);
    expect(response.headers.get("Cache-Control")).toContain("max-age=60");
  });

  it("returns marked 204 for a manifest equal to the installed version", async () => {
    const { handler, r2 } = setup();
    r2.value = JSON.stringify(makeManifest("1.2.2"));

    const response = await handler(request());

    expect(response.status).toBe(204);
    expect(response.headers.get("X-Leviathan-Feed")).toBe("no-newer");
    expect(await response.text()).toBe("");
  });

  it("returns marked 204 and a content-free event when the feed is behind the client", async () => {
    const events: string[] = [];
    const { handler, r2 } = setup((event) => events.push(event));
    r2.value = JSON.stringify(makeManifest("1.2.1"));

    const response = await handler(request());

    expect(response.status).toBe(204);
    expect(await response.text()).toBe("");
    expect(response.headers.get("X-Leviathan-Feed")).toBe("no-newer");
    expect(events).toEqual(["FEED_BEHIND_CLIENT"]);
  });

  it("logs only the content-free event when no event sink is injected", async () => {
    const { handler, r2 } = setup();
    const log = vi.spyOn(console, "info").mockImplementation(() => undefined);
    r2.value = JSON.stringify(makeManifest("1.2.1"));

    try {
      const response = await handler(request());
      expect(response.status).toBe(204);
      expect(response.headers.get("X-Leviathan-Feed")).toBe("no-newer");
      expect(log).toHaveBeenCalledExactlyOnceWith("FEED_BEHIND_CLIENT");
    } finally {
      log.mockRestore();
    }
  });

  it("returns no-newer when an older feed lacks the requested platform", async () => {
    const { handler, r2 } = setup();
    r2.value = JSON.stringify(makeManifest("1.2.1", {
      platforms: {
        "linux-aarch64": {
          url: `https://${HOST}/releases/1.2.1/app.tar.gz`,
          signature: "fake-signature",
        },
      },
    }));

    const response = await handler(request());

    expect(response.status).toBe(204);
    expect(await response.text()).toBe("");
    expect(response.headers.get("X-Leviathan-Feed")).toBe("no-newer");
  });

  it("maps each valid channel to its isolated R2 object key", async () => {
    const { handler, r2 } = setup();
    r2.value = JSON.stringify(makeManifest());

    await handler(request("/v1/updates/admin/windows/x86_64/1.2.2"));

    expect(r2.keys).toEqual(["channels/admin/latest.json"]);
  });

  it("rejects unknown channels and methods without reading R2", async () => {
    const { handler, r2 } = setup();

    const channelResponse = await handler(request("/v1/updates/preview/windows/x86_64/1.2.2"));
    const methodResponse = await handler(request(ROUTE, "POST"));

    expect(channelResponse.status).toBe(404);
    expect(await channelResponse.json()).toEqual({ error: { code: "NOT_FOUND" } });
    expect(methodResponse.status).toBe(405);
    expect(methodResponse.headers.get("Allow")).toBe("GET");
    expect(r2.keys).toEqual([]);
  });

  it("rejects malformed route, query string and current version", async () => {
    const { handler, r2 } = setup();

    const malformed = await handler(request("/v1/updates/desktop/windows/x86_64/1.2"));
    const query = await handler(request(`${ROUTE}?debug=1`));
    const invalidVersion = await handler(request("/v1/updates/desktop/windows/x86_64/01.2.3"));

    expect(malformed.status).toBe(400);
    expect(query.status).toBe(400);
    expect(invalidVersion.status).toBe(400);
    expect(await invalidVersion.json()).toEqual({ error: { code: "INVALID_VERSION" } });
    expect(r2.keys).toEqual([]);
  });

  it("does not serve an update for a platform absent from a valid manifest", async () => {
    const { handler, r2 } = setup();
    r2.value = JSON.stringify(makeManifest());

    const response = await handler(request("/v1/updates/desktop/linux/aarch64/1.2.2"));

    expect(response.status).toBe(204);
    expect(r2.keys).toEqual(["channels/desktop/latest.json"]);
  });

  it("rejects malformed JSON and schemas with an empty FEED_INVALID response", async () => {
    const { handler, r2 } = setup();
    r2.value = "not-json with private note text";

    const response = await handler(request());

    expect(response.status).toBe(503);
    expect(await response.text()).toBe("");
    expect(response.headers.get("X-Leviathan-Error")).toBe("FEED_INVALID");
    expect(response.headers.get("Cache-Control")).toBe("no-store");

    r2.value = JSON.stringify({ version: "1.2.3" });
    const invalidShape = await handler(request());
    expect(invalidShape.status).toBe(503);
    expect(await invalidShape.text()).toBe("");
    expect(invalidShape.headers.get("X-Leviathan-Error")).toBe("FEED_INVALID");
  });

  it("rejects absent or empty platform signatures", async () => {
    const { handler, r2 } = setup();
    const withoutSignature = makeManifest();
    const platforms = withoutSignature.platforms as Record<string, Record<string, unknown>>;
    delete platforms["windows-x86_64"].signature;
    r2.value = JSON.stringify(withoutSignature);

    const missing = await handler(request());
    expect(missing.status).toBe(503);
    expect(await missing.text()).toBe("");
    expect(missing.headers.get("X-Leviathan-Error")).toBe("FEED_INVALID");

    r2.value = JSON.stringify(makeManifest("1.2.3", {
      platforms: { "windows-x86_64": { url: `https://${HOST}/a.exe`, signature: "  " } },
    }));
    const empty = await handler(request());
    expect(empty.status).toBe(503);
    expect(await empty.text()).toBe("");
    expect(empty.headers.get("X-Leviathan-Error")).toBe("FEED_INVALID");
  });

  it("rejects disallowed, non-HTTPS, credentialed and fragment URLs", async () => {
    const { handler, r2 } = setup();
    const candidates = [
      "https://attacker.example.test/update.exe",
      `http://${HOST}/update.exe`,
      `https://user@${HOST}/update.exe`,
      `https://${HOST}/update.exe#fragment`,
    ];

    for (const url of candidates) {
      r2.value = JSON.stringify(makeManifest("1.2.3", {
        platforms: { "windows-x86_64": { url, signature: "signature" } },
      }));
      const response = await handler(request());
      expect(response.status).toBe(503);
      expect(await response.text()).toBe("");
      expect(response.headers.get("X-Leviathan-Error")).toBe("FEED_INVALID");
    }
  });

  it("rejects mismatched optional R2 channel metadata without a manifest body", async () => {
    const { handler, r2 } = setup();
    r2.value = JSON.stringify(makeManifest());
    r2.customMetadata = { channel: "admin" };

    const response = await handler(request());

    expect(response.status).toBe(503);
    expect(await response.text()).toBe("");
    expect(response.headers.get("X-Leviathan-Error")).toBe("FEED_INVALID");
  });

  it("returns a typed store error without leaking upstream details", async () => {
    const { handler, r2 } = setup();
    r2.failure = new Error("sensitive R2 diagnostic text");

    const response = await handler(request());

    expect(response.status).toBe(503);
    const body = await response.text();
    expect(body).not.toContain("sensitive R2 diagnostic text");
    expect(JSON.parse(body)).toEqual({ error: { code: "RELEASE_STORE_UNAVAILABLE" } });
  });

  it("compares SemVer precedence including prereleases and ignoring build metadata", () => {
    expect(compareSemVer("1.2.3-alpha.2", "1.2.3-alpha.10")).toBeLessThan(0);
    expect(compareSemVer("1.2.3-alpha", "1.2.3")).toBeLessThan(0);
    expect(compareSemVer("1.2.3+build.2", "1.2.3+build.1")).toBe(0);
    expect(compareSemVer("1.10.0", "1.9.9")).toBeGreaterThan(0);
  });

  it("validates every platform and publication date before selecting a target", () => {
    const hosts = new Set([HOST]);
    expect(() => validateTauriManifest(makeManifest("1.2.3", {
      pub_date: "2026-02-31T00:00:00Z",
    }), hosts)).toThrow();
    expect(() => validateTauriManifest(makeManifest("1.2.3", {
      platforms: {
        "windows-x86_64": { url: `https://${HOST}/a.exe`, signature: "sig" },
        "linux-aarch64": { url: "https://attacker.example.test/a.tar.gz", signature: "sig" },
      },
    }), hosts)).toThrow();
  });

  it("fails closed on invalid cache configuration", async () => {
    const r2 = new FakeR2();
    const handler = createReleaseFeedHandler({
      releases: r2,
      now: new FakeClock(),
      allowedArtifactHosts: [HOST],
      cacheTtlSeconds: 301,
    });

    const response = await handler(request());

    expect(response.status).toBe(503);
    expect(await response.json()).toEqual({ error: { code: "CONFIGURATION_ERROR" } });
    expect(r2.keys).toEqual([]);
  });
});
