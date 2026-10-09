import { describe, expect, it, vi } from "vitest";
import {
  createPreferencesClient,
  PreferencesConflictError,
  type LocalPreferencesCacheEntry,
  type PreferencesCachePortV1,
  type UserPreferencesV1,
} from "../preferencesClient";

const record: UserPreferencesV1 = {
  schema_version: 1,
  user_scope: "preferences-user-a",
  namespace: "workspace",
  document: { theme_id: "dark", tabs: ["pipeline", "risk"] },
  updated_at_ns: "1800000000000000000",
  revision: 4,
};

function apiResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

class MemoryPreferencesCache implements PreferencesCachePortV1 {
  readonly entries = new Map<string, LocalPreferencesCacheEntry>();

  get(key: string): LocalPreferencesCacheEntry | undefined {
    return this.entries.get(key);
  }

  set(key: string, entry: LocalPreferencesCacheEntry): void {
    this.entries.set(key, entry);
  }

  delete(key: string): void {
    this.entries.delete(key);
  }
}

describe("TERM-PREF-API-001 preferences client acceptance", () => {
  it("uses same-origin no-store fetches and returns the authenticated server record", async () => {
    const fetchImpl = vi.fn<typeof fetch>(async () => apiResponse(record));
    const cache = new MemoryPreferencesCache();
    const client = createPreferencesClient({ fetchImpl, cache, nowMs: () => 1234 });

    const result = await client.get("workspace");

    expect(result).toEqual(record);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    const [url, init] = fetchImpl.mock.calls[0] ?? [];
    expect(url).toBe("/api/preferences/workspace");
    expect(init?.method).toBe("GET");
    expect(init?.credentials).toBe("same-origin");
    expect(init?.cache).toBe("no-store");
    expect(client.getCached("workspace")).toEqual({
      source: "local-cache",
      cached_at_ms: 1234,
      record,
    });
  });

  it("labels cached data as local-only and never treats it as a server read", async () => {
    const cache = new MemoryPreferencesCache();
    cache.set("workspace", {
      source: "local-cache",
      cached_at_ms: 1000,
      record,
    });
    const fetchImpl = vi.fn<typeof fetch>(async () => {
      throw new TypeError("offline synthetic network failure");
    });
    const client = createPreferencesClient({ fetchImpl, cache });

    const cached = client.getCached("workspace");
    expect(cached?.source).toBe("local-cache");
    expect(cached).not.toHaveProperty("authoritative", true);
    await expect(client.get("workspace")).rejects.toThrow();
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(cache.get("workspace")?.record).toEqual(record);
  });

  it("preserves the unsaved draft and exposes current server state on revision conflict", async () => {
    const current: UserPreferencesV1 = {
      ...record,
      document: { theme_id: "light", tabs: ["risk"] },
      revision: 5,
    };
    const cache = new MemoryPreferencesCache();
    const fetchImpl = vi.fn<typeof fetch>(async () =>
      apiResponse({ error: { code: "REVISION_CONFLICT" }, current }, 409),
    );
    const client = createPreferencesClient({ fetchImpl, cache });
    const draft = { theme_id: "contrast", tabs: ["pipeline", "risk", "journal"] };

    let conflict: PreferencesConflictError | undefined;
    try {
      await client.put("workspace", draft, 4);
    } catch (error) {
      expect(error).toBeInstanceOf(PreferencesConflictError);
      conflict = error as PreferencesConflictError;
    }

    expect(conflict).toBeDefined();
    expect(conflict?.current).toEqual(current);
    expect(conflict?.draft).toEqual(draft);
    expect(conflict?.draft).not.toBe(draft);
    (draft.tabs as string[]).push("mutated-after-submit");
    expect(conflict?.draft.tabs).toEqual(["pipeline", "risk", "journal"]);
    expect(cache.get("workspace")).toEqual({
      source: "local-cache",
      cached_at_ms: expect.any(Number),
      record: current,
    });

    const [url, init] = fetchImpl.mock.calls[0] ?? [];
    expect(url).toBe("/api/preferences/workspace");
    expect(init?.method).toBe("PUT");
    expect(init?.credentials).toBe("same-origin");
    expect(init?.cache).toBe("no-store");
    expect(new Headers(init?.headers).get("if-match")).toBe("4");
    expect(JSON.parse(String(init?.body))).toEqual({
      document: { theme_id: "contrast", tabs: ["pipeline", "risk", "journal"] },
    });
  });
});


