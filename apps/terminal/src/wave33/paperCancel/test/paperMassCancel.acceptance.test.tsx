/* Independent acceptance for PAPER-MASS-CANCEL-UI-001.
 *
 * Scenarios are driven by an injected fake fetcher. Progress and completion are
 * asserted only from the returned page cursor/results, and no real API is called.
 */
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { PaperMassCancelView } from "../PaperMassCancelView";
import type {
  PaperMassCancelOrderResultV1,
  PaperMassCancelPlanV1,
  PaperMassCancelRequestV1,
  PaperMassCancelResponseV1,
} from "../api";

function makePlan(environment: "paper" | "live" = "paper"): PaperMassCancelPlanV1 {
  return {
    environment,
    account_id: "acct-paper-01",
    venue: "SIM-VENUE",
    scope: "ACCOUNT",
    expected_broker_revision: 44,
    requests: [
      {
        order_id: "order-alpha",
        client_order_id: "client-alpha",
        venue_order_id: "native-alpha",
        instrument_id: "NQ-SYN-01",
        strategy_id: "strategy-syn-01",
        side: "BUY",
        protective_leg: false,
        gtd_expiry_ns: null,
      },
      {
        order_id: "order-beta",
        client_order_id: "client-beta",
        venue_order_id: "native-beta",
        instrument_id: "ES-SYN-01",
        strategy_id: "strategy-syn-02",
        side: "SELL",
        protective_leg: true,
        gtd_expiry_ns: 1_900_000_000_000,
      },
      {
        order_id: "order-gamma",
        client_order_id: "client-gamma",
        venue_order_id: "native-gamma",
        instrument_id: "CL-SYN-01",
        strategy_id: "strategy-syn-03",
        side: "BUY",
        protective_leg: false,
        gtd_expiry_ns: null,
      },
    ],
  };
}

function resultFor(
  request: PaperMassCancelRequestV1["requests"][number],
  state: "CANCELED" | "REJECTED" | "CANCEL_REQUESTED_UNCONFIRMED" = "CANCELED",
): PaperMassCancelOrderResultV1 {
  return {
    order_id: request.order_id,
    idempotency_key: request.idempotency_key,
    lifecycle_state: state,
    oms_state: state === "CANCELED"
      ? "CANCELED"
      : state === "CANCEL_REQUESTED_UNCONFIRMED"
        ? "UNKNOWN_CANCEL"
        : null,
    reason_code: state === "CANCELED" ? "CANCEL_CONFIRMED" : "CANCEL_NOT_CONFIRMED",
    child_dispatch_stopped: true,
    cancel_sent: state !== "REJECTED",
    reconciled: state === "CANCELED",
    discrepancy_codes: [],
    operator_alert_codes: state === "CANCEL_REQUESTED_UNCONFIRMED" ? ["RECONCILE"] : [],
    fill_execution_ids: [],
  };
}

function pageResponse(
  request: PaperMassCancelRequestV1,
  options: {
    complete: boolean;
    next_index: number | null;
    results?: PaperMassCancelOrderResultV1[];
    start_index?: number;
    rootKey?: string;
  },
): Response {
  const start = options.start_index ?? request.start_index;
  const end = options.next_index ?? request.requests.length;
  const results = options.results ?? request.requests.slice(start, end).map((item) => resultFor(item));
  const payload: PaperMassCancelResponseV1 = {
    request_idempotency_key: options.rootKey ?? request.idempotency_key,
    start_index: start,
    next_index: options.next_index,
    complete: options.complete,
    results,
  };
  return new Response(JSON.stringify(payload), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

function requestBody(init: RequestInit | undefined): PaperMassCancelRequestV1 {
  return JSON.parse(String(init?.body)) as PaperMassCancelRequestV1;
}

function deterministicKeys() {
  let ordinal = 0;
  return () => `acceptance-key-${ordinal++}`;
}

describe("PAPER-MASS-CANCEL-UI-001 independent acceptance", () => {
  it("requires one explicit confirmation and displays returned progress and each result", async () => {
    const requests: PaperMassCancelRequestV1[] = [];
    const fetcher = vi.fn<typeof fetch>(async (_input, init) => {
      const request = requestBody(init);
      requests.push(request);
      return pageResponse(request, {
        complete: false,
        next_index: 2,
        results: [
          resultFor(request.requests[0]!, "CANCELED"),
          resultFor(request.requests[1]!, "CANCEL_REQUESTED_UNCONFIRMED"),
        ],
      });
    });

    render(
      <PaperMassCancelView
        plan={makePlan()}
        fetcher={fetcher}
        idempotencyKeyFactory={deterministicKeys()}
      />,
    );
    expect(fetcher).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Confirm mass cancel of 3 orders" }));

    await screen.findByText("Completed: 2");
    expect(fetcher).toHaveBeenCalledOnce();
    expect(screen.getByText("Remaining: 1")).toBeTruthy();
    expect(screen.getByText("Lifecycle status: CANCELED")).toBeTruthy();
    expect(screen.getByText("Lifecycle status: CANCEL_REQUESTED_UNCONFIRMED")).toBeTruthy();
    expect(screen.getByText("OMS status: UNKNOWN_CANCEL")).toBeTruthy();
    expect(screen.getByText("Operator alert codes: RECONCILE")).toBeTruthy();
    expect(screen.getByText("Cancellation has not been marked complete by the API.")).toBeTruthy();
    expect(requests).toHaveLength(1);
    expect(requests[0]?.start_index).toBe(0);
  });

  it("resumes only at the returned cursor with refreshed revision and stable keys/order", async () => {
    const submitted: PaperMassCancelRequestV1[] = [];
    const fetcher = vi.fn<typeof fetch>(async (_input, init) => {
      const request = requestBody(init);
      submitted.push(request);
      return request.start_index === 0
        ? pageResponse(request, { complete: false, next_index: 2 })
        : pageResponse(request, { complete: true, next_index: null });
    });
    const refreshBrokerRevision = vi.fn().mockResolvedValue(45);

    render(
      <PaperMassCancelView
        plan={makePlan()}
        fetcher={fetcher}
        refreshBrokerRevision={refreshBrokerRevision}
        idempotencyKeyFactory={deterministicKeys()}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: "Confirm mass cancel of 3 orders" }));
    await screen.findByText("Completed: 2");
    fireEvent.click(screen.getByRole("button", { name: "Resume with returned cursor" }));

    await screen.findByText("Completed: 3");
    expect(refreshBrokerRevision).toHaveBeenCalledOnce();
    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(submitted.map((request) => request.start_index)).toEqual([0, 2]);
    expect(submitted[1]?.expected_broker_revision).toBe(45);
    expect(submitted[1]?.idempotency_key).toBe(submitted[0]?.idempotency_key);
    expect(submitted[1]?.requests).toEqual(submitted[0]?.requests);
    expect(screen.getByText("Remaining: 0")).toBeTruthy();
    expect(screen.getByRole("status").textContent).toContain("Complete");
    expect(screen.getAllByRole("article", { name: /Order order-/ })).toHaveLength(3);
    expect(screen.queryByRole("button", { name: "Resume with returned cursor" })).toBeNull();
  });

  it("does not report DONE or offer resume for incomplete results at the request total", async () => {
    const fetcher = vi.fn<typeof fetch>(async (_input, init) => {
      const request = requestBody(init);
      return pageResponse(request, {
        complete: false,
        next_index: request.requests.length,
      });
    });
    render(
      <PaperMassCancelView
        plan={makePlan()}
        fetcher={fetcher}
        refreshBrokerRevision={vi.fn().mockResolvedValue(46)}
        idempotencyKeyFactory={deterministicKeys()}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: "Confirm mass cancel of 3 orders" }));

    expect(await screen.findByText("Completed: 3")).toBeTruthy();
    expect(screen.getByText("Remaining: 0")).toBeTruthy();
    expect(screen.getByText(/API has not marked the operation complete/)).toBeTruthy();
    expect(screen.queryByText(/Complete: every requested order/)).toBeNull();
    expect((screen.getByRole("button", { name: "Resume with returned cursor" }) as HTMLButtonElement).disabled).toBe(true);
    expect(fetcher).toHaveBeenCalledOnce();
  });

  it.each([
    {
      label: "short page for returned cursor",
      options: (request: PaperMassCancelRequestV1) => ({
        complete: false,
        next_index: 2,
        results: [resultFor(request.requests[0]!)],
      }),
    },
    {
      label: "complete response with a non-null cursor",
      options: (request: PaperMassCancelRequestV1) => ({
        complete: true,
        next_index: 3,
        results: request.requests.map((item) => resultFor(item)),
      }),
    },
    {
      label: "complete response with incomplete order coverage",
      options: (request: PaperMassCancelRequestV1) => ({
        complete: true,
        next_index: null,
        results: request.requests.slice(0, 2).map((item) => resultFor(item)),
      }),
    },
  ])("keeps malformed progress UNKNOWN: $label", async ({ options }) => {
    const fetcher = vi.fn<typeof fetch>(async (_input, init) => {
      const request = requestBody(init);
      return pageResponse(request, options(request));
    });
    render(
      <PaperMassCancelView
        plan={makePlan()}
        fetcher={fetcher}
        refreshBrokerRevision={vi.fn().mockResolvedValue(47)}
        idempotencyKeyFactory={deterministicKeys()}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: "Confirm mass cancel of 3 orders" }));

    expect((await screen.findByRole("alert")).textContent).toContain("Outcome UNKNOWN");
    expect(screen.queryByText(/Complete: every requested order/)).toBeNull();
    expect(screen.queryByRole("button", { name: "Resume with returned cursor" })).toBeNull();
    expect(fetcher).toHaveBeenCalledOnce();
  });

  it("keeps transport ambiguity UNKNOWN and never renders an inferred success", async () => {
    const privateTransportMessage = "synthetic-transport-failure-detail";
    const fetcher = vi.fn<typeof fetch>(async () => {
      throw new TypeError(privateTransportMessage);
    });
    render(
      <PaperMassCancelView
        plan={makePlan()}
        fetcher={fetcher}
        refreshBrokerRevision={vi.fn().mockResolvedValue(48)}
        idempotencyKeyFactory={deterministicKeys()}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: "Confirm mass cancel of 3 orders" }));

    expect((await screen.findByRole("alert")).textContent).toContain("Outcome UNKNOWN");
    expect(screen.queryByText(/Complete: every requested order/)).toBeNull();
    expect(screen.queryByRole("button", { name: "Resume with returned cursor" })).toBeNull();
    expect(screen.queryByText(new RegExp(privateTransportMessage))).toBeNull();
    expect(fetcher).toHaveBeenCalledOnce();
  });

  it("offers no cancellation controls in LIVE and performs no fetch", () => {
    const fetcher = vi.fn<typeof fetch>();
    render(
      <PaperMassCancelView
        plan={makePlan("live")}
        fetcher={fetcher}
        idempotencyKeyFactory={deterministicKeys()}
      />,
    );
    expect(screen.getByRole("alert").textContent).toContain("LIVE cancellation is unavailable");
    expect(screen.queryByRole("button", { name: /Confirm mass cancel/ })).toBeNull();
    expect(screen.queryByRole("button", { name: /Resume with returned cursor/ })).toBeNull();
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("sends only one POST when confirmation is double-clicked while pending", async () => {
    let releaseResponse: ((response: Response) => void) | undefined;
    const fetcher = vi.fn<typeof fetch>(
      () => new Promise<Response>((resolve) => { releaseResponse = resolve; }),
    );
    render(
      <PaperMassCancelView
        plan={makePlan()}
        fetcher={fetcher}
        idempotencyKeyFactory={deterministicKeys()}
      />,
    );
    const confirm = screen.getByRole("button", { name: "Confirm mass cancel of 3 orders" });
    fireEvent.click(confirm);
    fireEvent.click(confirm);
    await waitFor(() => expect(fetcher).toHaveBeenCalledOnce());
    const request = requestBody(fetcher.mock.calls[0]?.[1]);
    releaseResponse?.(pageResponse(request, { complete: true, next_index: null }));
    await screen.findByText(/Complete: every requested order/);
    expect(fetcher).toHaveBeenCalledOnce();
  });
});
