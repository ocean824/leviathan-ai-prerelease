import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { KnowledgeArchiveError, listKnowledgeIngestions } from "../api/knowledgeArchive";
import { KnowledgeArchiveView } from "../views/KnowledgeArchiveView";

function entry(id = "ing-1") {
  return {
    id,
    source_type: "file",
    created_at_ns: "1700000000000000001",
    updated_at_ns: "1700000000000000002",
    tags: ["reviewed"],
    status: "archived",
    data: { note: "PRIVATE_NOTE_BODY", secret: "PRIVATE_SECRET" },
  };
}

function listResponse(items = [entry()], options: { as_of?: string } = {}) {
  return {
    data: items,
    meta: { cursor: null, warnings: [], replacement: { market_data_doc: "read-only", ea_builder_doc: "read-only" } },
    ...options,
  };
}

function response(body: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    text: async () => JSON.stringify(body),
  } as Response;
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

describe("KnowledgeArchiveView", () => {
  it.each([
    "password", "ghp_example", "sk_live", "api-key", "my-private-key",
    "password123", "my-secret2", "hunter2", "acct-123456789",
  ])(
    "rejects unsafe tag filters before fetch: %s",
    async (tag) => {
      const fetcher = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => response(listResponse()));
      await expect(Promise.resolve().then(() => listKnowledgeIngestions({ tag }, fetcher))).rejects.toMatchObject({
        code: "INVALID_QUERY",
      } satisfies Partial<KnowledgeArchiveError>);
      expect(fetcher).not.toHaveBeenCalled();
    },
  );

  it.each(["macro", "fx-majors", "wave-2", "risk", "desk", "risk-control"])(
    "accepts safe tag labels: %s",
    async (tag) => {
      const fetcher = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => response(listResponse()));
      await expect(listKnowledgeIngestions({ tag }, fetcher)).resolves.toBeTruthy();
      expect(fetcher).toHaveBeenCalledTimes(1);
    },
  );

  it("shows a fixed invalid-tag message and performs no request for a denied filter", async () => {
    const fetcher = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => response(listResponse()));
    render(<KnowledgeArchiveView fetcher={fetcher} />);
    expect(await screen.findByRole("button", { name: "View ingestion ing-1" })).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Tag"), { target: { value: "password" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply filters" }));
    expect((await screen.findByRole("alert")).textContent).toBe("Invalid tag filter.");
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(screen.queryByText(/Archive request failed/)).toBeNull();
    expect(screen.queryByText(/No response/)).toBeNull();
  });

  it("replaces each unsafe response tag with a fixed marker and retains safe metadata", async () => {
    const unsafeTagsEntry = {
      ...entry(),
      tags: [
        "safe_tag", "api-gateway", "macro", "fx-majors", "wave-2", "risk", "desk", "risk-control",
        "password", "ghp_example", "sk_live", "password123", "my-secret2", "hunter2", "acct-123456789",
      ],
    };
    const fetcher = vi.fn(async (input: RequestInfo | URL, _init?: RequestInit) => {
      if (String(input).endsWith("/ing-1")) {
        return response({ data: unsafeTagsEntry, meta: { replacement: { market_data_doc: "read-only", ea_builder_doc: "read-only" } } });
      }
      return response(listResponse([unsafeTagsEntry]));
    });
    render(<KnowledgeArchiveView fetcher={fetcher} />);
    expect(await screen.findByText("ing-1 — file — archived")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "View ingestion ing-1" }));
    const detail = await screen.findByRole("region", { name: "Ingestion detail" });
    await waitFor(() => expect(detail.textContent).toContain("[unlisted tag]"));
    expect(detail.textContent).toContain("safe_tag");
    expect(detail.textContent).not.toContain("api-gateway");
    expect(detail.textContent).toContain("macro");
    expect(detail.textContent).toContain("fx-majors");
    expect(detail.textContent).toContain("wave-2");
    expect(detail.textContent).toContain("risk");
    expect(detail.textContent).toContain("desk");
    expect(detail.textContent).toContain("risk-control");
    expect(detail.textContent).not.toContain("password");
    expect(detail.textContent).not.toContain("ghp_example");
    expect(detail.textContent).not.toContain("sk_live");
    expect(detail.textContent).not.toContain("password123");
    expect(detail.textContent).not.toContain("my-secret2");
    expect(detail.textContent).not.toContain("hunter2");
    expect(detail.textContent).not.toContain("123456789");
  });

  it("ignores late list responses and errors after a newer filter request wins", async () => {
    const older = deferred<Response>();
    const newer = deferred<Response>();
    const requests = [older, newer];
    const fetcher = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => {
      const next = requests.shift();
      if (!next) return response(listResponse());
      return next.promise;
    });
    render(<KnowledgeArchiveView fetcher={fetcher} />);
    await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(1));
    fireEvent.change(screen.getByLabelText("Tag"), { target: { value: "new-filter" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply filters" }));
    await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(2));

    await act(async () => newer.resolve(response(listResponse([entry("new-result")]))));
    expect(await screen.findByText("new-result — file — archived")).toBeTruthy();
    await act(async () => older.reject(new Error("old request failed")));
    expect(screen.getByText("new-result — file — archived")).toBeTruthy();
    expect(screen.queryByText("Archive request failed: NETWORK_UNAVAILABLE.")).toBeNull();
  });

  it("ignores late detail and runs results from an older selection", async () => {
    const deferredDetail = new Map<string, ReturnType<typeof deferred<Response>>>();
    const deferredRuns = new Map<string, ReturnType<typeof deferred<Response>>>();
    const fetcher = vi.fn(async (input: RequestInfo | URL, _init?: RequestInit) => {
      const url = String(input);
      if (url.includes("/runs?")) {
        const id = url.match(/ingestions\/([^/]+)\/runs/)?.[1] ?? "unknown";
        const pending = deferred<Response>();
        deferredRuns.set(id, pending);
        return pending.promise;
      }
      if (/\/ingestions\/(?:A|B)$/.test(url)) {
        const id = url.endsWith("/A") ? "A" : "B";
        const pending = deferred<Response>();
        deferredDetail.set(id, pending);
        return pending.promise;
      }
      return response(listResponse([entry("A"), entry("B")]));
    });
    render(<KnowledgeArchiveView fetcher={fetcher} />);
    fireEvent.click(await screen.findByRole("button", { name: "View ingestion A" }));
    await waitFor(() => expect(deferredDetail.has("A") && deferredRuns.has("A")).toBe(true));
    fireEvent.click(screen.getByRole("button", { name: "View ingestion B" }));
    await waitFor(() => expect(deferredDetail.has("B") && deferredRuns.has("B")).toBe(true));

    const detailBody = (id: string) => ({ data: entry(id), meta: { replacement: { market_data_doc: "read-only", ea_builder_doc: "read-only" } } });
    await act(async () => {
      deferredDetail.get("B")?.resolve(response(detailBody("B")));
      deferredRuns.get("B")?.resolve(response(listResponse([entry("run-B")])));
    });
    const detail = await screen.findByRole("region", { name: "Ingestion detail" });
    const runs = screen.getByRole("region", { name: "Ingestion runs" });
    await waitFor(() => expect(detail.textContent).toContain("B"));
    await waitFor(() => expect(runs.textContent).toContain("run-B"));

    await act(async () => {
      deferredDetail.get("A")?.reject(new Error("stale detail failed"));
      deferredRuns.get("A")?.resolve(response(listResponse([entry("run-A")])));
    });
    expect(detail.textContent).toContain("B");
    expect(detail.textContent).not.toContain("NETWORK_UNAVAILABLE");
    expect(runs.textContent).toContain("run-B");
    expect(runs.textContent).not.toContain("run-A");
  });

  it("uses the mounted GET endpoint, encoded filters and displays untimestamped metadata as unverified", async () => {
    const fetcher = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => response(listResponse()));
    render(<KnowledgeArchiveView fetcher={fetcher} clock={() => 1_700_000_000_000} />);

    expect(await screen.findByText("ing-1 — file — archived")).toBeTruthy();
    expect(screen.getByText(/Source timestamp unavailable/)).toBeTruthy();
    expect(screen.getByText(/API-reported metadata; source freshness is unverified/)).toBeTruthy();
    const [url, init] = fetcher.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("/api/v1/knowledge/ingestions?limit=50");
    expect(init.method).toBe("GET");
    expect(screen.queryByText(/PRIVATE_NOTE_BODY|PRIVATE_SECRET/)).toBeNull();

    fireEvent.change(screen.getByLabelText("Tag"), { target: { value: "news_notes" } });
    fireEvent.change(screen.getByLabelText("Source type"), { target: { value: "file" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply filters" }));
    await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(2));
    expect(fetcher.mock.calls[1]?.[0]).toBe("/api/v1/knowledge/ingestions?limit=50&source_type=file&tag=news_notes");
    expect(fetcher.mock.calls.every((call) => call[1]?.method === "GET")).toBe(true);
  });

  it("shows the exact operator-session-unavailable reason for 401", async () => {
    const fetcher = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => response({ error: { code: "UNAUTHORIZED" } }, 401));
    render(<KnowledgeArchiveView fetcher={fetcher} />);
    expect(await screen.findByText(/operator session unavailable/)).toBeTruthy();
    expect(screen.queryByText("UNAUTHORIZED")).toBeNull();
  });

  it("loads allowlisted detail and run metadata without rendering record payloads", async () => {
    const fetcher = vi.fn(async (url: RequestInfo | URL, _init?: RequestInit) => {
      const path = String(url);
      if (path.includes("/runs")) return response(listResponse([entry("run-1")]));
      if (path.endsWith("/ing-1")) return response({ data: entry(), meta: { replacement: { market_data_doc: "read-only", ea_builder_doc: "read-only" } } });
      return response(listResponse());
    });
    render(<KnowledgeArchiveView fetcher={fetcher} clock={() => 1_700_000_000_000} />);
    fireEvent.click(await screen.findByRole("button", { name: "View ingestion ing-1" }));
    expect(await screen.findByText("Ingestion detail")).toBeTruthy();
    expect(await screen.findByText("run-1")).toBeTruthy();
    expect(fetcher.mock.calls.map((call) => call[0])).toContain("/api/v1/knowledge/ingestions/ing-1");
    expect(fetcher.mock.calls.map((call) => call[0])).toContain("/api/v1/knowledge/ingestions/ing-1/runs?limit=50");
    expect(screen.queryByText(/PRIVATE_NOTE_BODY|PRIVATE_SECRET/)).toBeNull();
    expect(fetcher.mock.calls.every((call) => call[1]?.method === "GET")).toBe(true);
  });

  it("does not infer freshness from client receipt or record timestamps", async () => {
    const fetcher = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => response(listResponse()));
    render(<KnowledgeArchiveView fetcher={fetcher} clock={() => 9_999_999_999_999} />);
    expect(await screen.findByText(/Source timestamp unavailable/)).toBeTruthy();
    expect(screen.queryByText(/Source timestamp verified/)).toBeNull();
    expect(screen.queryByText(/Source timestamp is stale/)).toBeNull();
    expect(screen.getByText(/Response received at/)).toBeTruthy();
  });

  it("uses a server timestamp for PanelState freshness and stale transition", async () => {
    vi.useFakeTimers();
    let now = 1_700_000_000_000;
    const fetcher = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => response(listResponse([entry()], { as_of: "2023-11-14T22:13:20.000Z" })));
    const { unmount } = render(<KnowledgeArchiveView fetcher={fetcher} clock={() => now} />);
    await act(async () => { await Promise.resolve(); });
    expect(screen.getByText(/Source timestamp verified/)).toBeTruthy();
    now += 5_001;
    act(() => { vi.advanceTimersByTime(1_000); });
    expect(screen.getByText(/Source timestamp is stale/)).toBeTruthy();
    unmount();
    vi.useRealTimers();
  });

  it("surfaces fixed error codes for malformed responses and service failures", async () => {
    const malformed = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => response({ data: [], meta: {} }));
    const { unmount } = render(<KnowledgeArchiveView fetcher={malformed} />);
    expect(await screen.findByText(/INVALID_RESPONSE/)).toBeTruthy();
    unmount();

    const unavailable = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => response({}, 503));
    render(<KnowledgeArchiveView fetcher={unavailable} />);
    expect(await screen.findByText(/SERVICE_UNAVAILABLE/)).toBeTruthy();
  });
});
