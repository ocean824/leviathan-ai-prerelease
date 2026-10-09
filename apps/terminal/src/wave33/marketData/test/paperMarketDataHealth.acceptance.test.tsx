import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { describe, expect, it, vi } from "vitest";
import {
  PAPER_MD_BACKFILL_PATH,
  PAPER_MD_SCHEMA_VERSION,
  PAPER_MD_VENUES_PATH,
  createPaperMarketDataApi,
  type PaperMarketDataFetcher,
} from "../api";
import { PaperMarketDataHealthView } from "../PaperMarketDataHealthView";

const VENUE = "XNYS";
const NEWER_VENUE = "XNAS";
const INSTRUMENT = "AAPL";
const JOB_ID = "job-opaque-42";
const T0 = "1710000000000000001";
const T1 = "1710000000000000999";
const PROVIDER_ERROR_CANARY = "synthetic-provider-detail-should-not-appear";

const venueList = {
  schema_version: PAPER_MD_SCHEMA_VERSION,
  source_state: "AVAILABLE",
  venues: [{
    venue: VENUE,
    type: "trades",
    freshness: "DEGRADED",
    unhealthy: true,
    gap_count: 2,
    last_event_time_ns: "1710000000000000100",
    last_ingest_time_ns: "1710000000000000200",
  }],
};

const newerVenueList = {
  ...venueList,
  venues: venueList.venues.map((row) => ({ ...row, venue: NEWER_VENUE })),
};

const latestSnapshot = {
  schema_version: PAPER_MD_SCHEMA_VERSION,
  source_state: "AVAILABLE",
  gap_state: "DETECTED",
  event: {
    event_id: "123e4567-e89b-42d3-a456-426614174000",
    event_type: "trade",
    event_time_ns: "1710000000000000001",
    source_time_ns: "1710000000000000002",
    ingest_time_ns: "1710000000000000999",
  },
};

const preview = {
  schema_version: PAPER_MD_SCHEMA_VERSION,
  status: "PREVIEW",
  instrument_count: 1,
  type_count: 1,
  max_records: 1000,
  estimated_event_count: 20,
  writes_performed: false,
};

const queued = {
  schema_version: PAPER_MD_SCHEMA_VERSION,
  job_id: JOB_ID,
  status: "QUEUED",
};

const jobStatus = {
  schema_version: PAPER_MD_SCHEMA_VERSION,
  job_id: JOB_ID,
  status: "RUNNING",
  completed_count: 2,
  remaining_count: 8,
  source_state: "AVAILABLE",
  gap_state: "DETECTED",
  last_event_time_ns: "1710000000000000100",
  last_ingest_time_ns: "1710000000000000200",
};

interface FetchCall {
  url: string;
  method: string;
  init: RequestInit;
}

interface FakeFetchOptions {
  venueResponse?: (callIndex: number) => Promise<Response> | Response;
  latestResponse?: (callIndex: number) => Response;
  backfillResponse?: (call: FetchCall) => Promise<Response> | Response;
  statusResponse?: () => Response;
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function makeFakeFetch(options: FakeFetchOptions = {}) {
  const calls: FetchCall[] = [];
  let latestIndex = 0;
  let venueIndex = 0;
  const fetcher = vi.fn<PaperMarketDataFetcher>(async (input, init = {}) => {
    const call: FetchCall = {
      url: String(input),
      method: init.method ?? "GET",
      init,
    };
    calls.push(call);

    if (call.url.startsWith(PAPER_MD_VENUES_PATH)) {
      return options.venueResponse?.(venueIndex++) ?? jsonResponse(venueList);
    }
    if (call.url.startsWith("/api/md/latest")) {
      const index = latestIndex++;
      return options.latestResponse?.(index) ?? jsonResponse(latestSnapshot);
    }
    if (call.url === PAPER_MD_BACKFILL_PATH && call.method === "POST") {
      if (options.backfillResponse) return options.backfillResponse(call);
      const request = JSON.parse(String(call.init.body)) as { dry_run: boolean };
      return request.dry_run ? jsonResponse(preview) : jsonResponse(queued, 202);
    }
    if (call.url.startsWith(`${PAPER_MD_BACKFILL_PATH}/`) && call.method === "GET") {
      return options.statusResponse?.() ?? jsonResponse(jobStatus);
    }
    return jsonResponse({ schema_version: PAPER_MD_SCHEMA_VERSION, error: { code: "NOT_FOUND" } }, 404);
  });
  return { calls, fetcher };
}

function renderView(fetcher: PaperMarketDataFetcher) {
  return render(<PaperMarketDataHealthView api={createPaperMarketDataApi(fetcher)} />);
}

async function fillValidBackfillForm() {
  await screen.findByRole("option", { name: VENUE });
  fireEvent.change(screen.getByRole("textbox", { name: "Backfill instruments" }), {
    target: { value: INSTRUMENT },
  });
  fireEvent.change(screen.getByRole("textbox", { name: "Backfill start time UTC nanoseconds" }), {
    target: { value: T0 },
  });
  fireEvent.change(screen.getByRole("textbox", { name: "Backfill end time UTC nanoseconds" }), {
    target: { value: T1 },
  });
}

function postCalls(calls: FetchCall[]) {
  return calls.filter((call) => call.method === "POST");
}

function selectBackfillTypes(values: string[]) {
  const select = screen.getByRole("listbox", { name: "Backfill data types" }) as HTMLSelectElement;
  for (const option of Array.from(select.options)) option.selected = values.includes(option.value);
  fireEvent.change(select);
}

describe("PAPER-MARKET-DATA-HEALTH-UI-001 independent acceptance", () => {
  it("shows freshness and gap state as text plus icon with live, keyboard-reachable controls", async () => {
    const { calls, fetcher } = makeFakeFetch();
    const { container } = renderView(fetcher);

    const status = await screen.findByRole("status");
    expect(status).toHaveAttribute("aria-live", "polite");
    expect(status).toHaveAttribute("aria-atomic", "true");
    expect(status).toHaveTextContent("Feed freshness: Degraded");
    expect(status).toHaveTextContent("Gap state: UNKNOWN");
    expect([...container.querySelectorAll('span[aria-hidden="true"]')]
      .some((icon) => icon.textContent === "!")).toBe(true);

    const reconnect = screen.getByRole("button", { name: /Reconnect unavailable/i });
    expect(reconnect).toBeDisabled();
    expect(screen.getByText(/no scoped reconnect API is available/i)).toBeInTheDocument();
    expect(screen.getByText(/does not reconnect automatically/i)).toBeInTheDocument();
    expect(reconnect.tagName).toBe("BUTTON");
    expect(reconnect.tabIndex).toBeGreaterThanOrEqual(0);

    expect(calls).toHaveLength(1);
    expect(calls[0]?.url).toBe(`${PAPER_MD_VENUES_PATH}?limit=50`);
    await new Promise((resolve) => setTimeout(resolve, 30));
    expect(calls).toHaveLength(1);
  });

  it("does not let an older venue refresh replace a newer response", async () => {
    let resolveA: (response: Response) => void = () => {};
    let resolveB: (response: Response) => void = () => {};
    const responseA = new Promise<Response>((resolve) => { resolveA = resolve; });
    const responseB = new Promise<Response>((resolve) => { resolveB = resolve; });
    const { calls, fetcher } = makeFakeFetch({
      venueResponse: (callIndex) => callIndex === 0 ? responseA : responseB,
    });
    renderView(fetcher);
    await waitFor(() => expect(calls.filter((call) => call.url.startsWith(PAPER_MD_VENUES_PATH))).toHaveLength(1));

    fireEvent.click(screen.getByRole("button", { name: "Refresh feed health" }));
    await waitFor(() => expect(calls.filter((call) => call.url.startsWith(PAPER_MD_VENUES_PATH))).toHaveLength(2));

    await act(async () => {
      resolveB(jsonResponse(newerVenueList));
      await responseB;
    });
    expect(await screen.findByRole("option", { name: NEWER_VENUE })).toBeInTheDocument();

    await act(async () => {
      resolveA(jsonResponse(venueList));
      await responseA;
    });
    expect(screen.getByRole("option", { name: NEWER_VENUE })).toBeInTheDocument();
    expect(screen.queryByRole("option", { name: VENUE })).not.toBeInTheDocument();
    expect(calls.filter((call) => call.url.startsWith(PAPER_MD_VENUES_PATH))).toHaveLength(2);
  });

  it("does not let an older venue refresh error replace newer successful health", async () => {
    let resolveA: (response: Response) => void = () => {};
    let resolveB: (response: Response) => void = () => {};
    const responseA = new Promise<Response>((resolve) => { resolveA = resolve; });
    const responseB = new Promise<Response>((resolve) => { resolveB = resolve; });
    const { calls, fetcher } = makeFakeFetch({
      venueResponse: (callIndex) => callIndex === 0 ? responseA : responseB,
    });
    renderView(fetcher);
    await waitFor(() => expect(calls.filter((call) => call.url.startsWith(PAPER_MD_VENUES_PATH))).toHaveLength(1));

    fireEvent.click(screen.getByRole("button", { name: "Refresh feed health" }));
    await waitFor(() => expect(calls.filter((call) => call.url.startsWith(PAPER_MD_VENUES_PATH))).toHaveLength(2));

    await act(async () => {
      resolveB(jsonResponse(newerVenueList));
      await responseB;
    });
    expect(await screen.findByRole("option", { name: NEWER_VENUE })).toBeInTheDocument();

    await act(async () => {
      resolveA(jsonResponse({ schema_version: PAPER_MD_SCHEMA_VERSION, error: { code: "SERVICE_UNAVAILABLE" } }, 503));
      await responseA;
    });
    expect(screen.getByRole("option", { name: NEWER_VENUE })).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(calls.filter((call) => call.url.startsWith(PAPER_MD_VENUES_PATH))).toHaveLength(2);
  });

  it("keeps the last successful snapshot marked stale when a later read errors", async () => {
    const { calls, fetcher } = makeFakeFetch({
      latestResponse: (index) => index === 0
        ? jsonResponse(latestSnapshot)
        : jsonResponse({ error: { code: "MARKET_DATA_UNAVAILABLE", message: PROVIDER_ERROR_CANARY } }, 503),
    });
    renderView(fetcher);
    await screen.findByRole("option", { name: VENUE });
    fireEvent.change(screen.getByRole("textbox", { name: "Latest data instrument" }), {
      target: { value: INSTRUMENT },
    });

    const read = screen.getByRole("button", { name: "Read latest" });
    read.focus();
    expect(document.activeElement).toBe(read);
    expect(read.tagName).toBe("BUTTON");
    fireEvent.keyDown(read, { key: "Enter", code: "Enter" });
    fireEvent.click(read);
    expect(await screen.findByText("1710000000000000001")).toBeInTheDocument();
    expect(screen.getByText("1710000000000000999")).toBeInTheDocument();
    expect(screen.getByText("Gap state: DETECTED")).toBeInTheDocument();

    fireEvent.click(read);
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("latest market-data snapshot is unavailable");
    expect(alert).toHaveTextContent("previous snapshot is retained and may be stale");
    expect(alert).not.toHaveTextContent(PROVIDER_ERROR_CANARY);
    expect(screen.getByText("1710000000000000001")).toBeInTheDocument();
    expect(screen.getByText("Gap state: DETECTED")).toBeInTheDocument();
    expect(calls.filter((call) => call.url.startsWith("/api/md/latest"))).toHaveLength(2);
  });

  it("validates the backfill window and renders a dry-run preview without claiming writes", async () => {
    const { calls, fetcher } = makeFakeFetch();
    renderView(fetcher);
    await fillValidBackfillForm();

    const end = screen.getByRole("textbox", { name: "Backfill end time UTC nanoseconds" });
    const previewButton = screen.getByRole("button", { name: "Preview backfill" });
    fireEvent.change(end, { target: { value: T0 } });
    expect(previewButton).toBeDisabled();
    expect(calls.filter((call) => call.method === "POST")).toHaveLength(0);

    fireEvent.change(end, { target: { value: T1 } });
    expect(previewButton).toBeEnabled();
    fireEvent.click(previewButton);

    expect(await screen.findByText(/Preview only; writes performed: no/i)).toBeInTheDocument();
    expect(screen.getByText("Estimated events: 20")).toBeInTheDocument();
    const posts = postCalls(calls);
    expect(posts).toHaveLength(1);
    expect(posts[0]?.url).toBe(PAPER_MD_BACKFILL_PATH);
    expect(posts[0]?.init.credentials).toBe("same-origin");
    expect(posts[0]?.init.cache).toBe("no-store");
    const body = String(posts[0]?.init.body);
    expect(body).toContain('"dry_run":true');
    expect(body).toContain(`"t0_ns":${T0}`);
    expect(body).toContain(`"t1_ns":${T1}`);
  });

  it("queues only when dry run is unchecked, reads status, and shows supplied progress without inventing next-attempt data", async () => {
    const { calls, fetcher } = makeFakeFetch();
    renderView(fetcher);
    await screen.findByRole("option", { name: VENUE });
    fireEvent.change(screen.getByRole("textbox", { name: "Latest data instrument" }), {
      target: { value: INSTRUMENT },
    });
    fireEvent.click(screen.getByRole("button", { name: "Read latest" }));
    expect(await screen.findByText("1710000000000000001")).toBeInTheDocument();
    await fillValidBackfillForm();

    selectBackfillTypes(["trades", "quotes"]);

    fireEvent.click(screen.getByRole("checkbox", { name: "Dry run backfill" }));
    const queueButton = screen.getByRole("button", { name: "Queue backfill" });
    expect(queueButton).toBeEnabled();
    fireEvent.click(queueButton);

    expect(await screen.findByText(`Backfill queued. Opaque job ID: ${JOB_ID}`)).toBeInTheDocument();
    const posts = postCalls(calls);
    expect(posts).toHaveLength(1);
    expect(String(posts[0]?.init.body)).toContain('"dry_run":false');
    expect(JSON.parse(String(posts[0]?.init.body)).types).toEqual(["trades", "quotes"]);
    expect(calls.some((call) => call.url === `${PAPER_MD_BACKFILL_PATH}/${JOB_ID}`)).toBe(false);

    fireEvent.click(screen.getByRole("button", { name: "Read job status" }));
    expect(await screen.findByRole("progressbar", { name: "Backfill progress" })).toHaveAttribute("value", "20");
    expect(screen.getByText(/2 completed, 8 remaining/)).toBeInTheDocument();
    expect(screen.getByText("1710000000000000100")).toBeInTheDocument();
    expect(screen.getByText("1710000000000000200")).toBeInTheDocument();
    expect(screen.queryByText(/Next attempt/)).not.toBeInTheDocument();
    expect(calls.some((call) => call.url === `${PAPER_MD_BACKFILL_PATH}/${JOB_ID}` && call.method === "GET")).toBe(true);
    const normalizedPaths = new Set(calls.map((call) => {
      const path = new URL(call.url, "http://terminal.test").pathname;
      return path.startsWith(`${PAPER_MD_BACKFILL_PATH}/`)
        ? `${PAPER_MD_BACKFILL_PATH}/{job_id}`
        : path;
    }));
    expect(normalizedPaths).toEqual(new Set([
      PAPER_MD_VENUES_PATH,
      "/api/md/latest",
      PAPER_MD_BACKFILL_PATH,
      `${PAPER_MD_BACKFILL_PATH}/{job_id}`,
    ]));
  });

  it("rejects a QUEUED body with HTTP 200 and does not show a queued job", async () => {
    const { calls, fetcher } = makeFakeFetch({
      backfillResponse: () => jsonResponse(queued, 200),
    });
    renderView(fetcher);
    await fillValidBackfillForm();
    fireEvent.click(screen.getByRole("checkbox", { name: "Dry run backfill" }));
    fireEvent.click(screen.getByRole("button", { name: "Queue backfill" }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("The service returned an invalid response.");
    expect(screen.queryByText(`Backfill queued. Opaque job ID: ${JOB_ID}`)).not.toBeInTheDocument();
    expect(postCalls(calls)).toHaveLength(1);
    expect(calls.some((call) => call.url === `${PAPER_MD_BACKFILL_PATH}/${JOB_ID}` && call.method === "GET")).toBe(false);
  });

  it("submits at most one backfill POST for a rapid double click", async () => {
    let releasePost: ((response: Response) => void) | undefined;
    const deferredPost = new Promise<Response>((resolve) => { releasePost = resolve; });
    const { calls, fetcher } = makeFakeFetch({
      backfillResponse: () => deferredPost,
    });
    renderView(fetcher);
    await fillValidBackfillForm();

    const form = screen.getByRole("form", { name: "Backfill request" });
    const previewButton = screen.getByRole("button", { name: "Preview backfill" });
    fireEvent.click(previewButton);
    fireEvent.click(previewButton);
    expect(postCalls(calls)).toHaveLength(1);

    await act(async () => {
      releasePost?.(jsonResponse(preview));
      await deferredPost;
    });
    expect(await screen.findByText(/Preview only; writes performed: no/i)).toBeInTheDocument();
    expect(form.tagName).toBe("FORM");
  });

  it("keeps freshness unknown on source failure and calls only the documented routes", async () => {
    const { calls, fetcher } = makeFakeFetch({
      venueResponse: () => jsonResponse({ error: { code: "SERVICE_UNAVAILABLE" } }, 503),
    });
    renderView(fetcher);

    expect(await screen.findByRole("alert")).toHaveTextContent("Paper market data is unavailable");
    expect(screen.getByText("Feed freshness: Unknown")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Reconnect unavailable/i })).toBeDisabled();
    expect(calls).toHaveLength(1);
    expect(postCalls(calls)).toHaveLength(0);
    await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(1));

    const calledPaths = new Set(calls.map((call) => new URL(call.url, "http://terminal.test").pathname));
    expect([...calledPaths]).toEqual([PAPER_MD_VENUES_PATH]);
    for (const call of calls) {
      expect(call.init.credentials).toBe("same-origin");
      expect(call.init.cache).toBe("no-store");
    }
  });
});
