from __future__ import annotations

import os
import subprocess
import uuid
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
TESTS = Path(__file__).resolve().parent
FIXTURES = TESTS / "fixtures"

VITEST_SOURCE = r"""
import { describe, expect, it, vi } from "vitest";
import { readFileSync } from "node:fs";
import { createReleaseFeedHandler } from "../src/handler.js";

const desktop = readFileSync(new URL("./fixtures/desktop-latest.json", import.meta.url), "utf8");
const admin = readFileSync(new URL("./fixtures/admin-latest.json", import.meta.url), "utf8");

function setup(values = {}, metadata = {}) {
  const objects = new Map([
    ["channels/desktop/latest.json", desktop],
    ["channels/admin/latest.json", admin],
    ...Object.entries(values),
  ]);
  const metadataByKey = new Map(Object.entries(metadata));
  const get = vi.fn(async (key) => {
    const text = objects.get(key);
    return text === null || text === undefined
      ? null
      : { text: async () => text, customMetadata: metadataByKey.get(key) };
  });
  const put = vi.fn(async () => { throw new Error("write attempted"); });
  const recordEvent = vi.fn();
  const handler = createReleaseFeedHandler({
    releases: { get, put },
    now: { now: () => new Date("2026-10-06T12:00:00.000Z") },
    allowedArtifactHosts: ["downloads.example.test"],
    cacheTtlSeconds: 90,
    recordEvent,
  });
  return { handler, get, put, recordEvent };
}

function request(path, method = "GET") {
  return new Request("https://feed.example.test" + path, { method });
}

async function errorIs(response, status, code) {
  expect(response.status).toBe(status);
  expect(await response.json()).toEqual({ error: { code } });
}

function boundedCache(response) {
  const value = response.headers.get("cache-control");
  expect(value).toBeTruthy();
  const match = value.match(/(?:s-)?max-age=(\d+)/i);
  expect(match).toBeTruthy();
  expect(Number(match[1])).toBeGreaterThanOrEqual(0);
  expect(Number(match[1])).toBeLessThanOrEqual(90);
}

describe("RELEASE-FEED-001 acceptance", () => {
  it.each([
    ["/v1/updates/desktop/windows/x86_64/1.12.2", "channels/desktop/latest.json", "1.12.3"],
    ["/v1/updates/admin/windows/x86_64/2.3.9", "channels/admin/latest.json", "2.4.0"],
  ])("serves the newer v2 manifest for %s", async (path, key, version) => {
    const { handler, get } = setup();
    const response = await handler(request(path));
    expect(response.status).toBe(200);
    expect(response.headers.get("Content-Type")).toContain("application/json");
    expect(get).toHaveBeenCalledExactlyOnceWith(key);
    const body = await response.json();
    expect(body.version).toBe(version);
    expect(body.notes).toEqual(expect.any(String));
    expect(Number.isNaN(Date.parse(body.pub_date))).toBe(false);
    expect(Object.keys(body)).toEqual(["version", "notes", "pub_date", "platforms"]);
    expect(body.platforms["windows-x86_64"]).toMatchObject({
      url: expect.stringMatching(/^https:\/\/downloads\.example\.test\//),
      signature: expect.stringMatching(/^synthetic-signature-/),
    });
    expect(Object.keys(body.platforms["windows-x86_64"]).sort()).toEqual(["signature", "url"]);
    boundedCache(response);
  });

  it("maps requested target and architecture to the platform key", async () => {
    const { handler } = setup();
    const supported = await handler(request("/v1/updates/desktop/darwin/aarch64/1.12.2"));
    expect(supported.status).toBe(200);
    expect((await supported.json()).platforms["darwin-aarch64"]).toBeDefined();
    const unsupported = await handler(request("/v1/updates/desktop/linux/x86_64/1.12.2"));
    expect(unsupported.status).toBe(204);
    expect(await unsupported.text()).toBe("");
    boundedCache(unsupported);
  });

  it.each(["1.12.3"])("returns 204 for equal installed version %s", async (version) => {
    const { handler } = setup();
    const response = await handler(request("/v1/updates/desktop/windows/x86_64/" + version));
    expect(response.status).toBe(204);
    expect(await response.text()).toBe("");
    expect(response.headers.get("X-Leviathan-Feed")).toBe("no-newer");
    boundedCache(response);
  });

  it("compares SemVer numerically and never serves a downgrade", async () => {
    const manifest = JSON.parse(desktop);
    manifest.version = "1.10.0";
    const { handler } = setup({ "channels/desktop/latest.json": JSON.stringify(manifest) });
    const newer = await handler(request("/v1/updates/desktop/windows/x86_64/1.9.9"));
    expect(newer.status).toBe(200);
    expect((await newer.json()).version).toBe("1.10.0");

    const behind = setup();
    const response = await behind.handler(
      request("/v1/updates/desktop/windows/x86_64/1.13.0"),
    );
    expect(response.status).toBe(204);
    expect(response.headers.get("X-Leviathan-Feed")).toBe("no-newer");
    expect(await response.text()).toBe("");
    boundedCache(response);
    expect(behind.recordEvent).toHaveBeenCalledExactlyOnceWith("FEED_BEHIND_CLIENT");
    expect(behind.recordEvent.mock.calls).toEqual([["FEED_BEHIND_CLIENT"]]);
  });

  it.each([
    ["/v1/updates/staging/windows/x86_64/1.0.0", 404, "NOT_FOUND"],
    ["/v1/updates/desktop/windows/x86_64", 404, "NOT_FOUND"],
    ["/v1/updates/desktop/windows/x86_64/1.0.0/extra", 404, "NOT_FOUND"],
    ["/v1/updates/desktop/windows%2Fx86_64/1.0.0", 404, "NOT_FOUND"],
    ["/other/desktop/windows/x86_64/1.0.0", 404, "NOT_FOUND"],
    ["/v1/updates/desktop/windows/x86_64/1.0.0?debug=1", 400, "INVALID_REQUEST"],
    ["/v1/updates/desktop/windows/x86_64/01.2.3", 400, "INVALID_VERSION"],
  ])("rejects invalid channel, route, query, or version: %s", async (path, status, code) => {
    const { handler, get } = setup();
    await errorIs(await handler(request(path)), status, code);
    expect(get).not.toHaveBeenCalled();
  });

  it("rejects malformed JSON and schema as content-free FEED_INVALID", async () => {
    for (const stored of ["{not-json", JSON.stringify({ version: "1.12.3" })]) {
      const { handler } = setup({ "channels/desktop/latest.json": stored });
      const response = await handler(request("/v1/updates/desktop/windows/x86_64/1.12.2"));
      expect(response.status).toBe(503);
      expect(response.headers.get("X-Leviathan-Error")).toBe("FEED_INVALID");
      expect(response.headers.get("Cache-Control")).toBe("no-store");
      expect(await response.text()).toBe("");
    }
  });

  it.each([
    ["missing signature", (() => {
      const value = JSON.parse(desktop);
      delete value.platforms["windows-x86_64"].signature;
      return JSON.stringify(value);
    })(), {}],
    ["URL outside allowed host", (() => {
      const value = JSON.parse(desktop);
      value.platforms["windows-x86_64"].url = "https://attacker.example/releases/1.12.3/app";
      return JSON.stringify(value);
    })(), {}],
    ["non-HTTPS URL", (() => {
      const value = JSON.parse(desktop);
      value.platforms["windows-x86_64"].url = "http://downloads.example.test/releases/1.12.3/app";
      return JSON.stringify(value);
    })(), {}],
    [
      "mismatched R2 channel metadata",
      desktop,
      { "channels/desktop/latest.json": { channel: "admin" } },
    ],
  ])("rejects invalid stored feed metadata: %s", async (_label, stored, metadata) => {
    const { handler } = setup({ "channels/desktop/latest.json": stored }, metadata);
    const response = await handler(request("/v1/updates/desktop/windows/x86_64/1.12.2"));
    expect(response.status).toBe(503);
    expect(response.headers.get("X-Leviathan-Error")).toBe("FEED_INVALID");
    expect(response.headers.get("Cache-Control")).toBe("no-store");
    expect(await response.text()).toBe("");
  });

  it("returns 204 for missing manifest and missing platform", async () => {
    const absent = setup({ "channels/desktop/latest.json": null });
    const noManifest = await absent.handler(request("/v1/updates/desktop/windows/x86_64/1.12.2"));
    expect(noManifest.status).toBe(204);
    expect(await noManifest.text()).toBe("");
    boundedCache(noManifest);

    const manifest = {
      version: "1.12.3",
      notes: "synthetic",
      pub_date: "2026-10-01T12:00:00Z",
      platforms: {
        "linux-aarch64": {
          url: "https://downloads.example.test/releases/1.12.3/linux.tar.gz",
          signature: "synthetic-signature-linux",
        },
      },
    };
    const unsupported = setup({ "channels/desktop/latest.json": JSON.stringify(manifest) });
    const noPlatform = await unsupported.handler(
      request("/v1/updates/desktop/windows/x86_64/1.12.2"),
    );
    expect(noPlatform.status).toBe(204);
    expect(await noPlatform.text()).toBe("");
  });

  it.each(["POST", "PUT", "PATCH", "DELETE"])(
    "allows no mutating method at feed route: %s",
    async (method) => {
    const { handler, get, put } = setup();
    const response = await handler(request("/v1/updates/desktop/windows/x86_64/1.12.2", method));
    expect(response.status).toBe(405);
    expect(response.headers.get("Allow")).toBe("GET");
    expect(get).not.toHaveBeenCalled();
    expect(put).not.toHaveBeenCalled();
  });

  it.each([
    ["POST", "/v1/releases"],
    ["POST", "/upload"],
    ["DELETE", "/v1/updates/admin/windows/x86_64/2.3.9"],
  ])("exposes no upload/mutation route: %s %s", async (method, path) => {
    const { handler, get, put } = setup();
    const response = await handler(request(path, method));
    expect(response.status).toBe(405);
    expect(get).not.toHaveBeenCalled();
    expect(put).not.toHaveBeenCalled();
  });
});
"""


def test_release_feed_acceptance_through_node_vitest() -> None:
    """Drive the TypeScript Worker with fake R2 objects and a fixed clock."""
    assert (PACKAGE / "src/handler.ts").is_file()
    assert (PACKAGE / "src/manifest.ts").is_file()
    assert (PACKAGE / "node_modules/vitest/vitest.mjs").is_file()
    for name in ("desktop-latest.json", "admin-latest.json"):
        assert (FIXTURES / name).is_file()

    spec = TESTS / f"feed_acceptance_generated_{os.getpid()}_{uuid.uuid4().hex}.test.ts"
    spec.write_text(VITEST_SOURCE, encoding="utf-8")
    try:
        result = subprocess.run(
            ["node", "node_modules/vitest/vitest.mjs", "run", str(spec)],
            cwd=PACKAGE,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=180,
            check=False,
        )
    finally:
        spec.unlink(missing_ok=True)

    assert result.returncode == 0, (
        f"Vitest acceptance failed. stdout={result.stdout} stderr={result.stderr}"
    )
    assert "Test Files" in result.stdout and "Tests" in result.stdout
    assert "25 passed" in result.stdout
