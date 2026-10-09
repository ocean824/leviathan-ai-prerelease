import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { describe, expect, it, vi } from "vitest";
import {
  PAPER_MD_SCHEMA_VERSION,
  createPaperMarketDataApi,
  type BackfillSubmissionV1,
  type PaperMarketDataApi,
  type PaperMarketDataFetcher,
  type PaperMarketDataType,
  type PaperMarketDataResult,
  type VenueListV1,
} from "../api";
import { PaperMarketDataHealthView } from "../PaperMarketDataHealthView";

const venueData: VenueListV1 = {
  source_state: "AVAILABLE",
  venues: [{
    venue: "XNYS",
    type: "trades",
    freshness: "DEGRADED",
    unhealthy: true,
    gap_count: 2,
    last_event_time_ns: "1710000000000000000",
    last_ingest_time_ns: "1710000000000000100",
  }],
};

function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}

function mockApi(overrides: Partial<PaperMarketDataApi> = {}): PaperMarketDataApi {
  return {
    getVenues: vi.fn<PaperMarketDataApi["getVenues"]>(async () => ({ ok: true as const, data: venueData })),
    getLatest: vi.fn<PaperMarketDataApi["getLatest"]>(async () => ({
      ok: true,
      data: {
        source_state: "AVAILABLE",
        gap_state: "DETECTED",
        event: {
          event_id: "123e4567-e89b-42d3-a456-426614174000",
          event_type: "trade",
          event_time_ns: "1710000000000000001",
          source_time_ns: null,
          ingest_time_ns: "1710000000000000999",
        },
      },
    })),
    mintChartStreamTicket: vi.fn<PaperMarketDataApi["mintChartStreamTicket"]>(async () => ({
      ok: true,
      data: { ticket: "a".repeat(43) },
    })),
    submitBackfill: vi.fn<PaperMarketDataApi["submitBackfill"]>(async () => ({
      ok: true,
      data: {
        status: "PREVIEW",
        instrument_count: 1,
        type_count: 1,
        max_records: 1000,
        estimated_event_count: 20,
        writes_performed: false,
      },
    })),
    getBackfillStatus: vi.fn<PaperMarketDataApi["getBackfillStatus"]>(async () => ({
      ok: true,
      data: {
        job_id: "job-42",
        status: "RUNNING",
        completed_count: 2,
        remaining_count: 8,
        source_state: "AVAILABLE",
        gap_state: "NONE",
        last_event_time_ns: "1710000000000000100",
        last_ingest_time_ns: "1710000000000000200",
      },
    })),
    ...overrides,
  };
}

describe("paper market data API client", () => {
  it("uses bounded GET routes, no-store and preserves nanosecond digits", async () => {
    const fetcher = vi.fn<PaperMarketDataFetcher>(async (input, _init) => {
      const path = String(input);
      if (path.startsWith("/api/ingest/venues")) {
        return jsonResponse({ schema_version: PAPER_MD_SCHEMA_VERSION, ...venueData });
      }
      return new Response(
        `{"schema_version":"${PAPER_MD_SCHEMA_VERSION}","source_state":"AVAILABLE","gap_state":"NONE","event":{"event_id":"123e4567-e89b-42d3-a456-426614174000","event_type":"trade","event_time_ns":1710000000000000001,"source_time_ns":null,"ingest_time_ns":1710000000000000999}}`,
        { headers: { "Content-Type": "application/json" } },
      );
    });
    const api = createPaperMarketDataApi(fetcher as typeof fetch);
    const venues = await api.getVenues({ limit: 50 });
    const latest = await api.getLatest({ venue: "XNYS", instrument: "AAPL", type: "trades" });
    expect(venues.ok).toBe(true);
    expect(latest).toMatchObject({
      ok: true,
      data: { event: { event_time_ns: "1710000000000000001", ingest_time_ns: "1710000000000000999" } },
    });
    expect(fetcher).toHaveBeenCalledTimes(2);
    for (const [, init] of fetcher.mock.calls) {
      expect(init?.credentials).toBe("same-origin");
      expect(init?.cache).toBe("no-store");
      expect(init?.method).toBe("GET");
    }
  });

  it("sends exact UTC nanoseconds as numeric JSON tokens and rejects unsafe forms before fetch", async () => {
    const fetcher = vi.fn<PaperMarketDataFetcher>(async () => jsonResponse({
      schema_version: PAPER_MD_SCHEMA_VERSION,
      status: "PREVIEW",
      instrument_count: 1,
      type_count: 1,
      max_records: 1000,
      estimated_event_count: 0,
      writes_performed: false,
    }));
    const api = createPaperMarketDataApi(fetcher as typeof fetch);
    const request = {
      venue: "XNYS",
      instruments: ["AAPL"],
      types: ["trades"] as PaperMarketDataType[],
      t0_ns: "1710000000000000001",
      t1_ns: "1710000000000000999",
      max_records: 1000,
      dry_run: true,
    };
    const result = await api.submitBackfill(request);
    expect(result.ok).toBe(true);
    const init = fetcher.mock.calls[0]?.[1];
    expect(init?.method).toBe("POST");
    expect(String(init?.body)).toBe('{"venue":"XNYS","instruments":["AAPL"],"types":["trades"],"t0_ns":1710000000000000001,"t1_ns":1710000000000000999,"max_records":1000,"dry_run":true}');
    expect(String(init?.body)).toContain('"t0_ns":1710000000000000001');
    expect(String(init?.body)).toContain('"t1_ns":1710000000000000999');
    await api.submitBackfill({ ...request, instruments: ["not safe"] });
    await api.submitBackfill({ ...request, t0_ns: "01710000000000000001" });
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it("requires HTTP 202 for a queued backfill and rejects a 200 QUEUED body", async () => {
    const queuedResponse = {
      schema_version: PAPER_MD_SCHEMA_VERSION,
      job_id: "job-42",
      status: "QUEUED",
    };
    const fetcher = vi.fn<PaperMarketDataFetcher>(async () => jsonResponse(queuedResponse, 200));
    const api = createPaperMarketDataApi(fetcher);
    const request = {
      venue: "XNYS",
      instruments: ["AAPL"],
      types: ["trades"] as PaperMarketDataType[],
      t0_ns: "1710000000000000001",
      t1_ns: "1710000000000000999",
      max_records: 1000,
      dry_run: false,
    };
    await expect(api.submitBackfill(request)).resolves.toEqual({ ok: false, error: "INVALID_RESPONSE" });

    fetcher.mockResolvedValueOnce(jsonResponse(queuedResponse, 202));
    await expect(api.submitBackfill(request)).resolves.toEqual({
      ok: true,
      data: { job_id: "job-42", status: "QUEUED" },
    });
  });
});

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((accept) => { resolve = accept; });
  return { promise, resolve };
}

function venueResult(freshness: "UNKNOWN" | "DEGRADED"): PaperMarketDataResult<VenueListV1> {
  return {
    ok: true,
    data: {
      source_state: "AVAILABLE",
      venues: [{
        ...venueData.venues[0]!,
        freshness,
        unhealthy: freshness === "DEGRADED",
      }],
    },
  };
}

describe("PaperMarketDataHealthView", () => {
  it("shows unknown state on initial failure and keeps reconnect disabled with a reason", async () => {
    const api = mockApi({
      getVenues: vi.fn<PaperMarketDataApi["getVenues"]>(async () => ({ ok: false, error: "SERVICE_UNAVAILABLE" })),
    });
    render(<PaperMarketDataHealthView api={api} />);
    expect(await screen.findByRole("alert")).toHaveTextContent("Paper market data is unavailable");
    expect(screen.getByText("Feed freshness: Unknown")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /reconnect unavailable/i })).toBeDisabled();
    expect(screen.getByText(/no scoped reconnect API is available/i)).toBeInTheDocument();
    expect(api.getVenues).toHaveBeenCalledTimes(1);
  });

  it("commits only the newest venue refresh and ignores older errors and results", async () => {
    const first = deferred<PaperMarketDataResult<VenueListV1>>();
    const second = deferred<PaperMarketDataResult<VenueListV1>>();
    const third = deferred<PaperMarketDataResult<VenueListV1>>();
    const getVenues = vi.fn<PaperMarketDataApi["getVenues"]>()
      .mockReturnValueOnce(first.promise)
      .mockReturnValueOnce(second.promise)
      .mockReturnValueOnce(third.promise);
    const api = mockApi({ getVenues });
    render(<PaperMarketDataHealthView api={api} />);
    await waitFor(() => expect(getVenues).toHaveBeenCalledTimes(1));
    fireEvent.click(screen.getByRole("button", { name: "Refresh feed health" }));
    fireEvent.click(screen.getByRole("button", { name: "Refresh feed health" }));
    expect(getVenues).toHaveBeenCalledTimes(3);

    await act(async () => { third.resolve(venueResult("DEGRADED")); await third.promise; });
    expect(screen.getByText("Feed freshness: Degraded")).toBeInTheDocument();
    await act(async () => { first.resolve({ ok: false, error: "SERVICE_UNAVAILABLE" }); await first.promise; });
    await act(async () => { second.resolve(venueResult("UNKNOWN")); await second.promise; });
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(screen.getByText("Feed freshness: Degraded")).toBeInTheDocument();
  });

  it("ignores a venue response that resolves after unmount", async () => {
    const pending = deferred<PaperMarketDataResult<VenueListV1>>();
    const getVenues = vi.fn<PaperMarketDataApi["getVenues"]>(() => pending.promise);
    const api = mockApi({ getVenues });
    const { unmount } = render(<PaperMarketDataHealthView api={api} />);
    await waitFor(() => expect(getVenues).toHaveBeenCalledTimes(1));
    unmount();

    let venueRowsRead = false;
    const lateData = Object.defineProperty({ source_state: "AVAILABLE" }, "venues", {
      get() {
        venueRowsRead = true;
        return venueData.venues;
      },
    }) as VenueListV1;
    await act(async () => {
      pending.resolve({ ok: true, data: lateData });
      await pending.promise;
    });
    expect(venueRowsRead).toBe(false);
  });

  it("shows event and ingest clocks separately, and preserves the last snapshot on a later error", async () => {
    const api = mockApi({
      getLatest: vi.fn<PaperMarketDataApi["getLatest"]>()
        .mockResolvedValueOnce({ ok: true, data: {
          source_state: "AVAILABLE",
          gap_state: "DETECTED",
          event: {
            event_id: "123e4567-e89b-42d3-a456-426614174000",
            event_type: "trade",
            event_time_ns: "1710000000000000001",
            source_time_ns: null,
            ingest_time_ns: "1710000000000000999",
          },
        } })
        .mockResolvedValueOnce({ ok: false, error: "NETWORK_UNAVAILABLE" }),
    });
    render(<PaperMarketDataHealthView api={api} />);
    await screen.findByRole("option", { name: "XNYS" });
    fireEvent.change(screen.getByRole("textbox", { name: "Latest data instrument" }), { target: { value: "AAPL" } });
    fireEvent.click(screen.getByRole("button", { name: "Read latest" }));
    expect(await screen.findByText("1710000000000000001")).toBeInTheDocument();
    expect(screen.getByText("1710000000000000999")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Read latest" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("could not be reached");
    expect(screen.getByText("1710000000000000001")).toBeInTheDocument();
    expect(screen.getByText("Gap state: DETECTED")).toBeInTheDocument();
  });

  it("validates, submits a dry-run preview, and does not submit twice while pending", async () => {
    let resolveSubmission: ((value: PaperMarketDataResult<BackfillSubmissionV1>) => void) | undefined;
    const pending = new Promise<PaperMarketDataResult<BackfillSubmissionV1>>((resolve) => { resolveSubmission = resolve; });
    const submitBackfill = vi.fn<PaperMarketDataApi["submitBackfill"]>(() => pending);
    const api = mockApi({ submitBackfill: submitBackfill as PaperMarketDataApi["submitBackfill"] });
    render(<PaperMarketDataHealthView api={api} />);
    await screen.findByRole("option", { name: "XNYS" });
    fireEvent.change(screen.getByRole("textbox", { name: "Backfill instruments" }), { target: { value: "AAPL" } });
    fireEvent.change(screen.getByRole("textbox", { name: "Backfill start time UTC nanoseconds" }), { target: { value: "1710000000000000001" } });
    fireEvent.change(screen.getByRole("textbox", { name: "Backfill end time UTC nanoseconds" }), { target: { value: "1710000000000000999" } });
    const form = screen.getByRole("form", { name: "Backfill request" });
    fireEvent.submit(form);
    fireEvent.submit(form);
    expect(submitBackfill).toHaveBeenCalledTimes(1);
    resolveSubmission?.({ ok: true, data: {
      status: "PREVIEW",
      instrument_count: 1,
      type_count: 1,
      max_records: 1000,
      estimated_event_count: 20,
      writes_performed: false,
    } });
    expect(await screen.findByText(/Preview only; writes performed: no/i)).toBeInTheDocument();
    expect(screen.getByText(/Estimated events: 20/)).toBeInTheDocument();
  });

  it("shows backfill progress only from a returned status and keeps event/ingest times separate", async () => {
    const api = mockApi({
      submitBackfill: vi.fn<PaperMarketDataApi["submitBackfill"]>(async () => ({ ok: true, data: { job_id: "job-42", status: "QUEUED" } })),
    });
    render(<PaperMarketDataHealthView api={api} />);
    await screen.findByRole("option", { name: "XNYS" });
    fireEvent.change(screen.getByRole("textbox", { name: "Backfill instruments" }), { target: { value: "AAPL" } });
    fireEvent.change(screen.getByRole("textbox", { name: "Backfill start time UTC nanoseconds" }), { target: { value: "1710000000000000001" } });
    fireEvent.change(screen.getByRole("textbox", { name: "Backfill end time UTC nanoseconds" }), { target: { value: "1710000000000000999" } });
    fireEvent.click(screen.getByRole("checkbox", { name: "Dry run backfill" }));
    fireEvent.click(screen.getByRole("button", { name: "Queue backfill" }));
    expect(await screen.findByText(/Backfill queued/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Read job status" }));
    expect(await screen.findByRole("progressbar", { name: "Backfill progress" })).toHaveAttribute("value", "20");
    expect(screen.getByText(/1710000000000000100/)).toBeInTheDocument();
    expect(screen.getByText(/1710000000000000200/)).toBeInTheDocument();
  });
});
