import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import {
  createPaperMassCancelApi,
  isSafeMassCancelIdentifier,
  parsePaperMassCancelResponse,
} from "../api";
import type {
  PaperMassCancelOrderResultV1,
  PaperMassCancelPlanV1,
  PaperMassCancelRequestV1,
} from "../api";
import { PaperMassCancelView } from "../PaperMassCancelView";

function plan(environment: "paper" | "live" = "paper"): PaperMassCancelPlanV1 {
  return {
    environment,
    account_id: "paper-account",
    venue: "SIM",
    scope: "ACCOUNT",
    expected_broker_revision: 10,
    requests: [
      {
        order_id: "order-1",
        client_order_id: "client-1",
        venue_order_id: "venue-1",
        instrument_id: "BTC-USD",
        strategy_id: "strategy-1",
        side: "BUY",
        protective_leg: false,
        gtd_expiry_ns: null,
      },
      {
        order_id: "order-2",
        client_order_id: "client-2",
        venue_order_id: "venue-2",
        instrument_id: "ETH-USD",
        strategy_id: "strategy-2",
        side: "SELL",
        protective_leg: true,
        gtd_expiry_ns: 1_800_000_000_000,
      },
      {
        order_id: "order-3",
        client_order_id: "client-3",
        venue_order_id: "venue-3",
        instrument_id: "SOL-USD",
        strategy_id: "strategy-3",
        side: "BUY",
        protective_leg: false,
        gtd_expiry_ns: null,
      },
    ],
  };
}

function result(request: PaperMassCancelRequestV1["requests"][number]): PaperMassCancelOrderResultV1 {
  return {
    order_id: request.order_id,
    idempotency_key: request.idempotency_key,
    lifecycle_state: "CANCELED",
    oms_state: "CANCELED",
    reason_code: "CANCEL_CONFIRMED",
    child_dispatch_stopped: true,
    cancel_sent: true,
    reconciled: true,
    discrepancy_codes: [],
    operator_alert_codes: [],
    fill_execution_ids: [],
  };
}

function apiResponse(
  request: PaperMassCancelRequestV1,
  options: { complete: boolean; next_index: number | null; results?: PaperMassCancelOrderResultV1[] },
): Response {
  const body = {
    request_idempotency_key: request.idempotency_key,
    start_index: request.start_index,
    next_index: options.next_index,
    complete: options.complete,
    results: options.results ?? request.requests.slice(request.start_index, options.next_index ?? request.requests.length).map(result),
  };
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

function requestForApi(): PaperMassCancelRequestV1 {
  return {
    account_id: "paper-account",
    venue: "SIM",
    scope: "ACCOUNT",
    idempotency_key: "root-key",
    expected_broker_revision: 10,
    start_index: 0,
    requests: plan().requests.map((item, index) => ({ ...item, idempotency_key: `item-key-${index}` })),
  };
}

function keys() {
  let index = 0;
  return () => `generated-key-${index++}`;
}

describe("paper mass cancel API", () => {
  it("accepts only bounded ASCII identifier grammar without a trailing line terminator", () => {
    expect(isSafeMassCancelIdentifier("order-1")).toBe(true);
    expect(isSafeMassCancelIdentifier("order-1\n")).toBe(false);
    expect(isSafeMassCancelIdentifier("order-1\r")).toBe(false);
  });

  it("posts the exact paper request using same-origin, no-store credentials", async () => {
    const request = requestForApi();
    const fetcher = vi.fn<typeof fetch>(async () => apiResponse(request, {
      complete: true,
      next_index: null,
      results: request.requests.map(result),
    }));
    const outcome = await createPaperMassCancelApi(fetcher).submit(request);
    expect(outcome.ok).toBe(true);
    expect(fetcher).toHaveBeenCalledOnce();
    const [url, init] = fetcher.mock.calls[0] ?? [];
    expect(url).toBe("/api/paper/mass-cancel/v1");
    expect(init?.method).toBe("POST");
    expect(init?.credentials).toBe("same-origin");
    expect(init?.cache).toBe("no-store");
    expect(JSON.parse(String(init?.body))).toEqual(request);
  });

  it("preserves signed-64-bit expiry nanoseconds exactly in the JSON integer token", async () => {
    const input = requestForApi();
    const exactNs = "1800000000000000123";
    const request = {
      ...input,
      requests: input.requests.map((item, index) => index === 0
        ? { ...item, gtd_expiry_ns: exactNs }
        : item),
    };
    let body = "";
    const fetcher = vi.fn<typeof fetch>(async (_url, init) => {
      body = String(init?.body);
      return apiResponse(request as PaperMassCancelRequestV1, {
        complete: true,
        next_index: null,
        results: request.requests.map(result),
      });
    });
    const outcome = await createPaperMassCancelApi(fetcher).submit(request as PaperMassCancelRequestV1);
    expect(outcome.ok).toBe(true);
    expect(body).toContain(`"gtd_expiry_ns":${exactNs}`);
    expect(body).not.toContain(`"gtd_expiry_ns":"${exactNs}"`);
  });

  it("accepts an incomplete cursor at the final index but never treats it as complete", async () => {
    const request = requestForApi();
    const value = {
      request_idempotency_key: request.idempotency_key,
      start_index: 0,
      next_index: request.requests.length,
      complete: false,
      results: request.requests.map(result),
    };
    expect(parsePaperMassCancelResponse(value, request)?.complete).toBe(false);
    expect(parsePaperMassCancelResponse(value, request)?.next_index).toBe(3);
  });

  it.each([
    { complete: false, next_index: null },
    { complete: true, next_index: 3 },
  ])("rejects inconsistent complete/cursor pair %#", async ({ complete, next_index }) => {
    const request = requestForApi();
    const value = {
      request_idempotency_key: request.idempotency_key,
      start_index: 0,
      next_index,
      complete,
      results: request.requests.map(result),
    };
    expect(parsePaperMassCancelResponse(value, request)).toBeNull();
  });

  it("rejects length and requested-order coverage mismatches", () => {
    const request = requestForApi();
    const valid = {
      request_idempotency_key: request.idempotency_key,
      start_index: 0,
      next_index: 2,
      complete: false,
      results: request.requests.slice(0, 1).map(result),
    };
    expect(parsePaperMassCancelResponse(valid, request)).toBeNull();
    const wrongOrder = {
      ...valid,
      next_index: 1,
      results: [result(request.requests[1]!)],
    };
    expect(parsePaperMassCancelResponse(wrongOrder, request)).toBeNull();
  });

  it("maps network ambiguity and malformed success bodies to UNKNOWN", async () => {
    const request = requestForApi();
    const network = await createPaperMassCancelApi(vi.fn<typeof fetch>(async () => {
      throw new Error("private network detail");
    })).submit(request);
    expect(network).toEqual({ ok: false, error: "OUTCOME_UNKNOWN" });
    const malformed = await createPaperMassCancelApi(vi.fn<typeof fetch>(async () => new Response("{}"))).submit(request);
    expect(malformed).toEqual({ ok: false, error: "OUTCOME_UNKNOWN" });
    expect(JSON.stringify(network)).not.toContain("private network detail");
  });
});

describe("PaperMassCancelView", () => {
  it("requires one explicit confirmation and resumes only with the returned cursor", async () => {
    const calls: PaperMassCancelRequestV1[] = [];
    const fetcher = vi.fn<typeof fetch>(async (_input, init) => {
      const request = JSON.parse(String(init?.body)) as PaperMassCancelRequestV1;
      calls.push(request);
      if (request.start_index === 0) {
        return apiResponse(request, { complete: false, next_index: 2 });
      }
      return apiResponse(request, { complete: true, next_index: null });
    });
    const refreshBrokerRevision = vi.fn().mockResolvedValue(11);
    render(<PaperMassCancelView plan={plan()} fetcher={fetcher} refreshBrokerRevision={refreshBrokerRevision} idempotencyKeyFactory={keys()} />);
    expect(fetcher).not.toHaveBeenCalled();
    const confirm = screen.getByRole("button", { name: "Confirm mass cancel of 3 orders" });
    fireEvent.click(confirm);
    fireEvent.click(confirm);
    await waitFor(() => expect(fetcher).toHaveBeenCalledOnce());
    expect(await screen.findByText("Completed: 2")).toBeTruthy();
    expect(screen.getByText("Remaining: 1")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Resume with returned cursor" })).toBeTruthy();
    expect(screen.getAllByText(/Lifecycle status: CANCELED/)).toHaveLength(2);
    fireEvent.click(screen.getByRole("button", { name: "Resume with returned cursor" }));
    await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(2));
    expect(refreshBrokerRevision).toHaveBeenCalledOnce();
    expect(calls[0]?.start_index).toBe(0);
    expect(calls[1]?.start_index).toBe(2);
    expect(calls[1]?.expected_broker_revision).toBe(11);
    expect(calls[1]?.idempotency_key).toBe(calls[0]?.idempotency_key);
    expect(calls[1]?.requests.map((item) => item.idempotency_key)).toEqual(calls[0]?.requests.map((item) => item.idempotency_key));
    expect(await screen.findByText("Completed: 3")).toBeTruthy();
    expect(screen.getByText("Remaining: 0")).toBeTruthy();
    expect(screen.getByRole("status").textContent).toContain("Complete");
    expect(screen.getAllByRole("article", { name: /Order order-/ })).toHaveLength(3);
  });

  it("shows all returned results but does not mark done when API says incomplete at total", async () => {
    const fetcher = vi.fn<typeof fetch>(async (_input, init) => {
      const request = JSON.parse(String(init?.body)) as PaperMassCancelRequestV1;
      return apiResponse(request, { complete: false, next_index: request.requests.length });
    });
    render(<PaperMassCancelView plan={plan()} fetcher={fetcher} idempotencyKeyFactory={keys()} />);
    fireEvent.click(screen.getByRole("button", { name: "Confirm mass cancel of 3 orders" }));
    expect(await screen.findByText(/All requested orders have results, but the API has not marked the operation complete/)).toBeTruthy();
    expect(screen.getByText("Completed: 3")).toBeTruthy();
    expect(screen.getByText("Remaining: 0")).toBeTruthy();
    expect((screen.getByRole("button", { name: "Resume with returned cursor" }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.queryByText(/Complete: every requested order/)).toBeNull();
  });

  it("stops with UNKNOWN when result identity does not match the requested order", async () => {
    const fetcher = vi.fn<typeof fetch>(async (_input, init) => {
      const request = JSON.parse(String(init?.body)) as PaperMassCancelRequestV1;
      return apiResponse(request, {
        complete: true,
        next_index: null,
        results: request.requests.map((item, index) => index === 1
          ? { ...result(item), order_id: "other-order" }
          : result(item)),
      });
    });
    render(<PaperMassCancelView plan={plan()} fetcher={fetcher} idempotencyKeyFactory={keys()} />);
    fireEvent.click(screen.getByRole("button", { name: "Confirm mass cancel of 3 orders" }));
    expect((await screen.findByRole("alert")).textContent).toContain("Outcome UNKNOWN");
    expect(screen.queryByText(/Complete: every requested order/)).toBeNull();
    expect(screen.queryByRole("button", { name: "Resume with returned cursor" })).toBeNull();
  });

  it("keeps LIVE controls unavailable and sends no request", () => {
    const fetcher = vi.fn<typeof fetch>();
    render(<PaperMassCancelView plan={plan("live")} fetcher={fetcher} idempotencyKeyFactory={keys()} />);
    expect(screen.getByRole("alert").textContent).toContain("LIVE cancellation is unavailable");
    expect(screen.queryByRole("button", { name: /Confirm mass cancel/ })).toBeNull();
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("keeps network ambiguity UNKNOWN with no resume control", async () => {
    const fetcher = vi.fn<typeof fetch>(async () => { throw new Error("transport details"); });
    render(<PaperMassCancelView plan={plan()} fetcher={fetcher} idempotencyKeyFactory={keys()} />);
    fireEvent.click(screen.getByRole("button", { name: "Confirm mass cancel of 3 orders" }));
    expect((await screen.findByRole("alert")).textContent).toContain("Outcome UNKNOWN");
    expect(screen.queryByRole("button", { name: "Resume with returned cursor" })).toBeNull();
    expect(screen.queryByText(/transport details/)).toBeNull();
  });

  it("blocks a second confirmation while the first request is pending", async () => {
    let resolveFetch: ((response: Response) => void) | undefined;
    const fetcher = vi.fn<typeof fetch>(() => new Promise<Response>((resolve) => { resolveFetch = resolve; }));
    render(<PaperMassCancelView plan={plan()} fetcher={fetcher} idempotencyKeyFactory={keys()} />);
    const confirm = screen.getByRole("button", { name: "Confirm mass cancel of 3 orders" });
    fireEvent.click(confirm);
    fireEvent.click(confirm);
    await waitFor(() => expect(fetcher).toHaveBeenCalledOnce());
    const request = JSON.parse(String(fetcher.mock.calls[0]?.[1]?.body)) as PaperMassCancelRequestV1;
    resolveFetch?.(apiResponse(request, { complete: true, next_index: null }));
    await screen.findByText(/Complete: every requested order/);
    expect(fetcher).toHaveBeenCalledOnce();
  });

  it("does not apply an in-flight response to a changed order plan", async () => {
    let resolveFetch: ((response: Response) => void) | undefined;
    const fetcher = vi.fn<typeof fetch>(() => new Promise<Response>((resolve) => { resolveFetch = resolve; }));
    const originalPlan = plan();
    const { rerender } = render(
      <PaperMassCancelView plan={originalPlan} fetcher={fetcher} idempotencyKeyFactory={keys()} />,
    );
    fireEvent.click(screen.getByRole("button", { name: "Confirm mass cancel of 3 orders" }));
    await waitFor(() => expect(fetcher).toHaveBeenCalledOnce());
    const request = JSON.parse(String(fetcher.mock.calls[0]?.[1]?.body)) as PaperMassCancelRequestV1;
    const changedPlan: PaperMassCancelPlanV1 = {
      ...originalPlan,
      venue: "SIM-OTHER",
    };
    rerender(<PaperMassCancelView plan={changedPlan} fetcher={fetcher} idempotencyKeyFactory={keys()} />);
    await act(async () => {
      resolveFetch?.(apiResponse(request, { complete: true, next_index: null }));
    });
    expect((await screen.findByRole("alert")).textContent).toContain("Outcome UNKNOWN");
    expect(screen.queryByText(/Complete: every requested order/)).toBeNull();
    expect(screen.queryByRole("article", { name: /Order order-/ })).toBeNull();
  });

  it("ignores a pending API completion after the view unmounts", async () => {
    let resolveFetch: ((response: Response) => void) | undefined;
    const fetcher = vi.fn<typeof fetch>(() => new Promise<Response>((resolve) => { resolveFetch = resolve; }));
    const { unmount } = render(<PaperMassCancelView plan={plan()} fetcher={fetcher} idempotencyKeyFactory={keys()} />);
    fireEvent.click(screen.getByRole("button", { name: "Confirm mass cancel of 3 orders" }));
    await waitFor(() => expect(fetcher).toHaveBeenCalledOnce());
    const request = JSON.parse(String(fetcher.mock.calls[0]?.[1]?.body)) as PaperMassCancelRequestV1;
    unmount();
    await act(async () => {
      resolveFetch?.(apiResponse(request, { complete: true, next_index: null }));
    });
  });

  it("clears completed results when a different order plan is selected", async () => {
    const fetcher = vi.fn<typeof fetch>(async (_input, init) => {
      const request = JSON.parse(String(init?.body)) as PaperMassCancelRequestV1;
      return apiResponse(request, { complete: true, next_index: null });
    });
    const originalPlan = plan();
    const { rerender } = render(
      <PaperMassCancelView plan={originalPlan} fetcher={fetcher} idempotencyKeyFactory={keys()} />,
    );
    fireEvent.click(screen.getByRole("button", { name: "Confirm mass cancel of 3 orders" }));
    expect(await screen.findByText(/Complete: every requested order/)).toBeTruthy();
    rerender(<PaperMassCancelView plan={{ ...originalPlan, venue: "SIM-OTHER" }} fetcher={fetcher} idempotencyKeyFactory={keys()} />);
    expect(screen.queryByText(/Complete: every requested order/)).toBeNull();
    expect(screen.queryByRole("article", { name: /Order order-/ })).toBeNull();
    expect(screen.getByRole("button", { name: "Confirm mass cancel of 3 orders" })).toBeTruthy();
  });

  it("clears unresolved results and disables resume when the selected plan changes", async () => {
    const fetcher = vi.fn<typeof fetch>(async (_input, init) => {
      const request = JSON.parse(String(init?.body)) as PaperMassCancelRequestV1;
      return apiResponse(request, { complete: false, next_index: 1 });
    });
    const originalPlan = plan();
    const { rerender } = render(
      <PaperMassCancelView
        plan={originalPlan}
        fetcher={fetcher}
        refreshBrokerRevision={vi.fn().mockResolvedValue(11)}
        idempotencyKeyFactory={keys()}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: "Confirm mass cancel of 3 orders" }));
    expect(await screen.findByText("Completed: 1")).toBeTruthy();
    rerender(
      <PaperMassCancelView
        plan={{ ...originalPlan, venue: "SIM-OTHER" }}
        fetcher={fetcher}
        refreshBrokerRevision={vi.fn().mockResolvedValue(12)}
        idempotencyKeyFactory={keys()}
      />,
    );
    expect(screen.getByRole("alert").textContent).toContain("Outcome UNKNOWN");
    expect(screen.queryByRole("article", { name: /Order order-/ })).toBeNull();
    expect(screen.queryByRole("button", { name: "Resume with returned cursor" })).toBeNull();
  });
});
