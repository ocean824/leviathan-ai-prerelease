import { describe, expect, it, vi } from "vitest";

import {
  createPreferencesClient,
  PreferencesConflictError,
} from "../preferencesClient";
import type {
  PreferencesCachePortV1,
  UserPreferencesV1,
} from "../preferencesClient";

function record(revision = 1): UserPreferencesV1 {
  return {
    schema_version: 1,
    user_scope: "operator-1",
    namespace: "terminal.theme",
    document: { mode: "dark" },
    updated_at_ns: "1800000000000000000",
    revision,
  };
}

function cachePort(): PreferencesCachePortV1 {
  const entries = new Map();
  return {
    get: (key) => entries.get(key),
    set: (key, entry) => entries.set(key, entry),
    delete: (key) => entries.delete(key),
  };
}

describe("PreferencesClient", () => {
  it("uses same-origin no-store requests and labels local cache as non-authoritative", async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(JSON.stringify(record()), { status: 200 }),
    );
    const cache = cachePort();
    const client = createPreferencesClient({ fetchImpl, cache, nowMs: () => 5 });

    const result = await client.get("terminal.theme");

    expect(result).toEqual(record());
    expect(fetchImpl).toHaveBeenCalledWith(
      "/api/preferences/terminal.theme",
      expect.objectContaining({ method: "GET", credentials: "same-origin", cache: "no-store" }),
    );
    expect(client.getCached("terminal.theme")).toEqual({
      source: "local-cache",
      cached_at_ms: 5,
      record: record(),
    });
  });

  it("uses If-Match revision and replaces cache only with server revision", async () => {
    const updated = { ...record(2), document: { mode: "light" } };
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(JSON.stringify(updated), { status: 200 }),
    );
    const client = createPreferencesClient({ fetchImpl, cache: cachePort() });
    const draft = { mode: "light" };

    await expect(client.put("terminal.theme", draft, 1)).resolves.toEqual(updated);
    expect(fetchImpl).toHaveBeenCalledWith(
      "/api/preferences/terminal.theme",
      expect.objectContaining({
        method: "PUT",
        headers: expect.objectContaining({ "If-Match": "1" }),
        body: JSON.stringify({ document: draft }),
      }),
    );
    expect(client.getCached("terminal.theme")?.record.revision).toBe(2);
  });

  it("surfaces the server current record and retains the unsaved conflict draft", async () => {
    const current = { ...record(3), document: { mode: "system" } };
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(JSON.stringify({ error: { code: "REVISION_CONFLICT" }, current }), { status: 409 }),
    );
    const client = createPreferencesClient({ fetchImpl, cache: cachePort() });
    const draft = { mode: "light" };

    let caught: unknown;
    try {
      await client.put("terminal.theme", draft, 2);
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(PreferencesConflictError);
    expect(caught).toMatchObject({ current, draft });
    expect(client.getCached("terminal.theme")?.record).toEqual(current);
    draft.mode = "mutated-after-request";
    expect((caught as PreferencesConflictError).draft).toEqual({ mode: "light" });
  });

  it("clears the local cache only after a successful reset", async () => {
    const fetchImpl = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(new Response(JSON.stringify(record()), { status: 200 }))
      .mockResolvedValueOnce(new Response(null, { status: 204 }));
    const client = createPreferencesClient({ fetchImpl, cache: cachePort() });
    await client.get("terminal.theme");
    await client.delete("terminal.theme");
    expect(client.getCached("terminal.theme")).toBeUndefined();
  });
});
