import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { isSafeKnowledgeArchiveTag } from "../api/knowledgeArchive";
import { KnowledgeArchiveView } from "../views/KnowledgeArchiveView";
import {
  archiveDetailResponse,
  archiveListResponse,
  archiveRunsResponse,
  archiveSecretCanaries,
  archiveSourceAsOf,
  forgedArchiveResponse,
} from "./fixtures/knowledgeArchive";

type CapturedRequest = { url: string; method: string };
type StubResponse = { body: unknown; status?: number };
type DeferredRequest = CapturedRequest & {
  resolve: (response: Response) => void;
  reject: (reason: unknown) => void;
};

function jsonResponse(body: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    text: async () => JSON.stringify(body),
  } as Response;
}

function makeFetcher(responder: (url: string) => StubResponse) {
  const requests: CapturedRequest[] = [];
  const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    requests.push({ url, method: init?.method ?? "GET" });
    const result = responder(url);
    return jsonResponse(result.body, result.status ?? 200);
  }) as typeof fetch;
  return { fetcher, requests };
}

function makeDeferredFetcher() {
  const requests: DeferredRequest[] = [];
  const fetcher = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    return new Promise<Response>((resolve, reject) => {
      requests.push({ url, method: init?.method ?? "GET", resolve, reject });
    });
  }) as typeof fetch;
  return { fetcher, requests };
}

async function resolveRequest(request: DeferredRequest, body: unknown, status = 200) {
  await act(async () => {
    request.resolve(jsonResponse(body, status));
    await Promise.resolve();
    await Promise.resolve();
  });
}

async function rejectRequest(request: DeferredRequest, reason: unknown) {
  await act(async () => {
    request.reject(reason);
    await Promise.resolve();
    await Promise.resolve();
  });
}

async function beginAtoBSelection(fetcher: typeof fetch, requests: DeferredRequest[]) {
  render(<KnowledgeArchiveView fetcher={fetcher} />);
  await waitFor(() => expect(requests).toHaveLength(1));
  await resolveRequest(requests[0]!, archiveListResponse({ ids: ["archive-A", "archive-B"] }));
  fireEvent.click(await screen.findByRole("button", { name: "View ingestion archive-A" }));
  await waitFor(() => expect(requests).toHaveLength(3));
  fireEvent.click(screen.getByRole("button", { name: "View ingestion archive-B" }));
  await waitFor(() => expect(requests).toHaveLength(5));
  return {
    detailA: requests[1]!,
    runsA: requests[2]!,
    detailB: requests[3]!,
    runsB: requests[4]!,
  };
}

function assertReadOnly(requests: readonly CapturedRequest[]) {
  expect(requests.length).toBeGreaterThan(0);
  expect(requests.every(({ method }) => method === "GET")).toBe(true);
  expect(requests.every(({ url }) => url.startsWith("/api/v1/knowledge/ingestions"))).toBe(true);
}

function assertNoSensitiveOrRawContent() {
  const rendered = `${document.documentElement.outerHTML} ${document.body.textContent ?? ""}`;
  for (const marker of [
    ...archiveSecretCanaries,
    "SYNTHETIC_PRIVATE_NOTE_BODY_MUST_NOT_RENDER",
    "SYNTHETIC_FORGED_RAW_PAYLOAD_MUST_NOT_RENDER",
  ]) {
    expect(rendered).not.toContain(marker);
  }
}

afterEach(() => {
  vi.useRealTimers();
});

describe("KNOW-ARCHIVE-UI-001 independent acceptance", () => {
  it("keeps a successful response without sourceAsOf unavailable while showing only unverified metadata", async () => {
    const { fetcher, requests } = makeFetcher(() => ({ body: archiveListResponse() }));
    render(<KnowledgeArchiveView fetcher={fetcher} clock={() => 9_999_999_999_999} />);

    expect(await screen.findByText("archive-fixture-001", { exact: false })).toBeTruthy();
    expect(screen.getByText(/Source timestamp unavailable/)).toBeTruthy();
    expect(screen.getByText(/API-reported metadata; source freshness is unverified/)).toBeTruthy();
    expect(screen.queryByText(/Source timestamp verified|Source timestamp is stale/)).toBeNull();
    expect(screen.getByText(/Response received at/)).toBeTruthy();
    assertNoSensitiveOrRawContent();
    assertReadOnly(requests);
  });

  it("encodes bounded created-after and created-before filters on a read-only list request", async () => {
    const { fetcher, requests } = makeFetcher(() => ({ body: archiveListResponse() }));
    render(<KnowledgeArchiveView fetcher={fetcher} />);
    expect(await screen.findByRole("button", { name: "View ingestion archive-fixture-001" })).toBeTruthy();

    fireEvent.change(screen.getByLabelText("Source type"), { target: { value: "api" } });
    fireEvent.change(screen.getByLabelText("Tag"), { target: { value: "news_notes-version" } });
    fireEvent.change(screen.getByLabelText("Created after (ns)"), { target: { value: "1791287997000000000" } });
    fireEvent.change(screen.getByLabelText("Created before (ns)"), { target: { value: "1791287999000000000" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply filters" }));

    await waitFor(() => expect(requests).toHaveLength(2));
    expect(requests[1]?.url).toBe("/api/v1/knowledge/ingestions?limit=50&source_type=api&created_after=1791287997000000000&created_before=1791287999000000000&tag=news_notes-version");
    assertReadOnly(requests);
  });

  it("accepts only the exact safe tag grammar and blocks unsafe tags before fetch", async () => {
    const validTags = [
      "a",
      "safe_tag-9",
      "x".repeat(64),
      "risk",
      "desk",
      "risk-control",
      "macro",
      "fx-majors",
      "wave-2",
    ];
    const invalidTags = [
      "A",
      "a:b",
      "_prefix",
      "-prefix",
      "x".repeat(65),
      "password",
      "ghp_example",
      "sk_live",
      "password123",
      "my-secret2",
      "api-gateway",
      "hunter2",
      "acct-123456789",
    ];
    for (const tag of validTags) expect(isSafeKnowledgeArchiveTag(tag)).toBe(true);
    for (const tag of invalidTags) expect(isSafeKnowledgeArchiveTag(tag)).toBe(false);

    const { fetcher, requests } = makeFetcher(() => ({ body: archiveListResponse() }));
    render(<KnowledgeArchiveView fetcher={fetcher} />);
    expect(await screen.findByRole("button", { name: "View ingestion archive-fixture-001" })).toBeTruthy();
    const initialRequestCount = requests.length;

    for (const tag of [
      "password",
      "ghp_example",
      "sk_live",
      "password123",
      "my-secret2",
      "hunter2",
      "acct-123456789",
    ]) {
      fireEvent.change(screen.getByLabelText("Tag"), { target: { value: tag } });
      fireEvent.click(screen.getByRole("button", { name: "Apply filters" }));
      expect(await screen.findByText("Invalid tag filter.")).toBeTruthy();
      const alerts = screen.getAllByRole("alert");
      expect(alerts).toHaveLength(1);
      expect(alerts[0]?.textContent).toBe("Invalid tag filter.");
      expect(requests).toHaveLength(initialRequestCount);
      expect(document.body.textContent).not.toContain(tag);
    }

    for (const tag of validTags) {
      fireEvent.change(screen.getByLabelText("Tag"), { target: { value: tag } });
      fireEvent.click(screen.getByRole("button", { name: "Apply filters" }));
      await waitFor(() => expect(requests).toHaveLength(initialRequestCount + validTags.indexOf(tag) + 1));
      expect(requests.at(-1)?.url).toBe(`/api/v1/knowledge/ingestions?limit=50&tag=${tag}`);
    }
    expect(screen.queryByText("Invalid tag filter.")).toBeNull();
    assertReadOnly(requests);
  });

  it("replaces each unsafe returned tag with the fixed marker and never renders its raw value", async () => {
    const unsafeTags = [
      "password",
      "ghp_example",
      "sk_live",
      "unsafe tag",
      "api-gateway",
      "password123",
      "my-secret2",
      "hunter2",
      "acct-123456789",
    ];
    const safeTags = ["safe_tag-9", "risk", "desk", "risk-control"];
    const rawTags = [...safeTags, ...unsafeTags];
    const { fetcher, requests } = makeFetcher((url) => {
      if (url.includes("/runs?")) return { body: archiveRunsResponse({ empty: true }) };
      if (url.endsWith("/archive-fixture-001")) {
        return { body: archiveDetailResponse({ tags: rawTags }) };
      }
      return { body: archiveListResponse({ tags: rawTags }) };
    });
    render(<KnowledgeArchiveView fetcher={fetcher} />);
    fireEvent.click(await screen.findByRole("button", { name: "View ingestion archive-fixture-001" }));

    const detail = await screen.findByRole("region", { name: "Ingestion detail" });
    const sanitizedTags = [...safeTags, ...unsafeTags.map(() => "[unlisted tag]")].join(", ");
    expect(within(detail).getByText(sanitizedTags)).toBeTruthy();
    for (const rawTag of unsafeTags) expect(document.body.textContent).not.toContain(rawTag);
    assertReadOnly(requests);
  });

  it("ignores out-of-order list/filter success and error completions", async () => {
    const { fetcher, requests } = makeDeferredFetcher();
    render(<KnowledgeArchiveView fetcher={fetcher} />);
    await waitFor(() => expect(requests).toHaveLength(1));

    fireEvent.change(screen.getByLabelText("Tag"), { target: { value: "filter_old" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply filters" }));
    await waitFor(() => expect(requests).toHaveLength(2));
    fireEvent.change(screen.getByLabelText("Tag"), { target: { value: "filter_current" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply filters" }));
    await waitFor(() => expect(requests).toHaveLength(3));

    await resolveRequest(requests[2]!, archiveListResponse({ id: "list-current" }));
    expect(await screen.findByRole("button", { name: "View ingestion list-current" })).toBeTruthy();
    await resolveRequest(requests[1]!, archiveListResponse({ id: "list-old-filter" }));
    await rejectRequest(requests[0]!, new Error("SYNTHETIC_STALE_LIST_ERROR"));

    expect(screen.getByRole("button", { name: "View ingestion list-current" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "View ingestion list-old-filter" })).toBeNull();
    expect(screen.queryByRole("alert")).toBeNull();
    assertNoSensitiveOrRawContent();
    assertReadOnly(requests);
  });

  it("ignores stale detail success and runs error after selecting A then B", async () => {
    const { fetcher, requests } = makeDeferredFetcher();
    const { detailA, runsA, detailB, runsB } = await beginAtoBSelection(fetcher, requests);

    await resolveRequest(detailB, archiveDetailResponse({ id: "archive-B" }));
    await resolveRequest(runsB, archiveRunsResponse({ id: "run-B" }));
    const detail = await screen.findByRole("region", { name: "Ingestion detail" });
    const runs = screen.getByRole("region", { name: "Ingestion runs" });
    await waitFor(() => expect(within(detail).getByText("archive-B")).toBeTruthy());
    await waitFor(() => expect(within(runs).getByText("run-B")).toBeTruthy());

    await resolveRequest(detailA, archiveDetailResponse({ id: "archive-A" }));
    await rejectRequest(runsA, new Error("SYNTHETIC_STALE_RUNS_ERROR"));

    expect(within(detail).getByText("archive-B")).toBeTruthy();
    expect(within(detail).queryByText("archive-A")).toBeNull();
    expect(within(runs).getByText("run-B")).toBeTruthy();
    expect(within(runs).queryByText("SYNTHETIC_STALE_RUNS_ERROR")).toBeNull();
    expect(within(runs).queryByRole("alert")).toBeNull();
    assertNoSensitiveOrRawContent();
    assertReadOnly(requests);
  });

  it("ignores stale detail error and runs success after selecting A then B", async () => {
    const { fetcher, requests } = makeDeferredFetcher();
    const { detailA, runsA, detailB, runsB } = await beginAtoBSelection(fetcher, requests);

    await resolveRequest(detailB, archiveDetailResponse({ id: "archive-B" }));
    await resolveRequest(runsB, archiveRunsResponse({ id: "run-B" }));
    const detail = await screen.findByRole("region", { name: "Ingestion detail" });
    const runs = screen.getByRole("region", { name: "Ingestion runs" });
    await waitFor(() => expect(within(detail).getByText("archive-B")).toBeTruthy());
    await waitFor(() => expect(within(runs).getByText("run-B")).toBeTruthy());

    await rejectRequest(detailA, new Error("SYNTHETIC_STALE_DETAIL_ERROR"));
    await resolveRequest(runsA, archiveRunsResponse({ id: "run-A" }));

    expect(within(detail).getByText("archive-B")).toBeTruthy();
    expect(within(detail).queryByText("SYNTHETIC_STALE_DETAIL_ERROR")).toBeNull();
    expect(within(detail).queryByRole("alert")).toBeNull();
    expect(within(runs).getByText("run-B")).toBeTruthy();
    expect(within(runs).queryByText("run-A")).toBeNull();
    assertNoSensitiveOrRawContent();
    assertReadOnly(requests);
  });

  it("shows server-timestamped data as fresh, then stale at the operator threshold", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(archiveSourceAsOf));
    const { fetcher } = makeFetcher(() => ({
      body: archiveListResponse({ sourceAsOf: archiveSourceAsOf }),
    }));
    render(<KnowledgeArchiveView fetcher={fetcher} />);

    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(screen.getByText(/Source timestamp verified/)).toBeTruthy();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(5_000);
    });
    expect(screen.getByText(/Source timestamp is stale/)).toBeTruthy();
    assertNoSensitiveOrRawContent();
  });

  it("maps 401 to the fixed operator-session-unavailable state without rendering response details", async () => {
    const { fetcher, requests } = makeFetcher(() => ({
      status: 401,
      body: { error: { code: "UNAUTHORIZED", detail: archiveSecretCanaries[0] } },
    }));
    render(<KnowledgeArchiveView fetcher={fetcher} />);

    expect(await screen.findByText(/operator session unavailable/)).toBeTruthy();
    expect(screen.queryByText("UNAUTHORIZED")).toBeNull();
    assertNoSensitiveOrRawContent();
    assertReadOnly(requests);
  });

  it("uses a typed error and Retry for service failure", async () => {
    const { fetcher, requests } = makeFetcher(() => ({
      status: 503,
      body: { error: { code: "SERVICE_UNAVAILABLE", detail: archiveSecretCanaries[1] } },
    }));
    render(<KnowledgeArchiveView fetcher={fetcher} />);

    expect(await screen.findByText(/Archive request failed: SERVICE_UNAVAILABLE/)).toBeTruthy();
    expect(screen.getByRole("button", { name: "Retry" })).toBeTruthy();
    assertNoSensitiveOrRawContent();
    assertReadOnly(requests);
  });

  it("renders empty results as an empty state, not as archive content", async () => {
    const { fetcher, requests } = makeFetcher(() => ({ body: archiveListResponse({ empty: true }) }));
    render(<KnowledgeArchiveView fetcher={fetcher} />);

    expect(await screen.findByText("No archived ingestions found.")).toBeTruthy();
    expect(screen.queryByRole("list", { name: "Archived ingestions" })).toBeNull();
    expect(screen.queryByText(/archive-fixture-001|private|token/i)).toBeNull();
    assertNoSensitiveOrRawContent();
    assertReadOnly(requests);
  });

  it("fails closed on a forged response and never renders the forged item", async () => {
    const { fetcher, requests } = makeFetcher(() => ({ body: forgedArchiveResponse }));
    render(<KnowledgeArchiveView fetcher={fetcher} />);

    expect(await screen.findByText(/Archive request failed: INVALID_RESPONSE/)).toBeTruthy();
    expect(screen.queryByText(/forged-content-must-not-render/i)).toBeNull();
    expect(screen.queryByRole("list", { name: "Archived ingestions" })).toBeNull();
    assertNoSensitiveOrRawContent();
    assertReadOnly(requests);
  });

  it("loads detail and runs using GET only and displays allowlisted metadata", async () => {
    const { fetcher, requests } = makeFetcher((url) => {
      if (url.includes("/runs?")) return { body: archiveRunsResponse() };
      if (url.endsWith("/archive-fixture-001")) return { body: archiveDetailResponse() };
      return { body: archiveListResponse() };
    });
    render(<KnowledgeArchiveView fetcher={fetcher} />);
    const select = await screen.findByRole("button", { name: "View ingestion archive-fixture-001" });
    fireEvent.click(select);

    expect(await screen.findByText("Ingestion detail")).toBeTruthy();
    expect(await screen.findByText("Ingestion runs")).toBeTruthy();
    expect(screen.getAllByText("archive-fixture-001").length).toBeGreaterThan(0);
    expect(screen.getByText("archive-run-fixture-001", { exact: false })).toBeTruthy();
    assertNoSensitiveOrRawContent();
    assertReadOnly(requests);
    expect(requests.map(({ url }) => url)).toContain("/api/v1/knowledge/ingestions/archive-fixture-001");
    expect(requests.map(({ url }) => url)).toContain("/api/v1/knowledge/ingestions/archive-fixture-001/runs?limit=50");
  });

  it("exposes only read/filter/select/retry controls and no mutation affordances", async () => {
    const { fetcher, requests } = makeFetcher(() => ({ body: archiveListResponse() }));
    render(<KnowledgeArchiveView fetcher={fetcher} />);

    const region = await screen.findByRole("region", { name: "Knowledge Archive" });
    expect(within(region).getByRole("button", { name: "Apply filters" })).toBeTruthy();
    expect(within(region).queryByRole("button", { name: /delete|edit|write|restore|re-ingest|sync/i })).toBeNull();
    expect(within(region).queryByRole("textbox", { name: /note|payload|body|secret/i })).toBeNull();
    assertReadOnly(requests);
  });
});
