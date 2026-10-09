import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { createPaperBlotterClient, isCancellablePaperOrder } from "../api";
import type { PaperBlotterClient, PaperSelectedOrderV1 } from "../api";
import type {
  PaperActivityPageV1,
  PaperRiskV1,
  PaperStatusV1,
} from "../../../wave28/api/paperActivity";
import { PaperBlotterView } from "../PaperBlotterView";

const ORDER_ID = "0123456789abcdef0123456789abcdef";

function activity(): PaperActivityPageV1 {
  return {
    schema_version: 1,
    evidence_label: "OMS ledger evidence",
    environment: "paper",
    account_id: "paper-account",
    high_water_sequence: 3,
    items: [
      {
        kind: "ORDER",
        ledger_sequence: 1,
        order: {
          order_id: ORDER_ID,
          venue: "SIM",
          instrument_id: "XYZ",
          side: "BUY",
          state: "PARTIALLY_FILLED",
          quantity: "10",
          filled_quantity: "2",
          discrepancies: [],
          created_at_utc: "2026-10-06T12:00:00Z",
        },
      },
      {
        kind: "FILL",
        ledger_sequence: 2,
        fill: {
          order_id: ORDER_ID,
          execution_id: "exec-1",
          venue: "SIM",
          instrument_id: "XYZ",
          side: "BUY",
          quantity: "2",
          price: "10.25",
          commission: "0",
          occurred_at_utc: "2026-10-06T12:00:01Z",
        },
      },
      {
        kind: "FILL_CORRECTION",
        ledger_sequence: 3,
        correction: {
          order_id: ORDER_ID,
          execution_id: "exec-1",
          correction_id: "corr-1",
          revision: 2,
          revised_quantity: "1",
          revised_price: "10.25",
          revised_commission: "0",
          occurred_at_utc: "2026-10-06T12:00:02Z",
        },
      },
    ],
    next_cursor: null,
    net_filled_units: [{ venue: "SIM", instrument_id: "XYZ", quantity: "1" }],
  };
}

const status: PaperStatusV1 = {
  liveEnabledReported: false,
  recoveryStatus: "READY",
  activationCount: 1,
};
const risk: PaperRiskV1 = {
  haltedReported: false,
  haltCodes: [],
  faultCode: null,
  operatingMode: "PAPER",
  policyReported: true,
};
function selected(overrides: Partial<PaperSelectedOrderV1> = {}): PaperSelectedOrderV1 {
  return {
    order_id: ORDER_ID,
    state: "PARTIALLY_FILLED",
    version: 4,
    environment: "paper",
    account_id: "paper-account",
    venue: "SIM",
    instrument_id: "XYZ",
    strategy_id: "strat-1",
    filled_quantity: "2",
    venue_order_id: "venue-1",
    discrepancies: [],
    submit_attempted: true,
    cancel_attempted: false,
    ...overrides,
  };
}
function response(body: unknown, statusCode = 200): Response {
  return new Response(JSON.stringify(body), { status: statusCode, headers: { "Content-Type": "application/json" } });
}

describe("paper blotter API", () => {
  it("reads only the documented order and risk GETs and posts cancel only when eligible", async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = [];
    const fetcher = vi.fn<typeof fetch>(async (input, init) => {
      const url = String(input);
      calls.push({ url, init });
      if (url.includes("/cancel")) return response(selected({ state: "CANCEL_REQUESTED_UNCONFIRMED", cancel_attempted: true }));
      if (url.endsWith(ORDER_ID)) return response(selected());
      if (url.includes("/activity")) return response(activity());
      if (url.endsWith("/status")) return response({ live_enabled: false, recovery_status: "READY", activation_count: 1 });
      if (url.endsWith("/risk/status")) return response({ halted: false, active_halts: [], fault_code: null, operating_mode: "PAPER", policy: {} });
      return response({}, 404);
    });
    const client = createPaperBlotterClient(fetcher);
    await client.getActivity({ limit: 100 });
    await client.getStatus();
    await client.getRisk();
    const order = await client.getSelectedOrder(ORDER_ID);
    expect(order.ok).toBe(true);
    if (!order.ok) return;
    expect(isCancellablePaperOrder(order.data)).toBe(true);
    const cancelled = await client.cancelOrder(order.data);
    expect(cancelled.ok).toBe(true);
    expect(calls.map(({ url }) => url)).toEqual([
      "/api/orders/activity?limit=100",
      "/api/orders/status",
      "/api/risk/status",
      `/api/orders/${ORDER_ID}`,
      `/api/orders/${ORDER_ID}/cancel`,
    ]);
    expect(calls.at(-1)?.init?.method).toBe("POST");
    expect(calls.at(-1)?.init?.body).toBeUndefined();
  });

  it("refuses to send cancellation outside the server-authorized eligibility envelope", async () => {
    const fetcher = vi.fn<typeof fetch>();
    const client = createPaperBlotterClient(fetcher);
    const result = await client.cancelOrder(selected({ state: "UNKNOWN_CANCEL" }));
    expect(result).toEqual({ ok: false, error: "ORDER_NOT_CANCELLABLE" });
    expect(fetcher).not.toHaveBeenCalled();
    expect(isCancellablePaperOrder(selected({ cancel_attempted: true }))).toBe(false);
    expect(isCancellablePaperOrder(selected({ discrepancies: ["FILL_CORRECTION"] }))).toBe(false);
  });

  it("rejects selected snapshots that do not match the requested order", async () => {
    const fetcher = vi.fn<typeof fetch>(async () => response(selected({ order_id: "fedcba9876543210fedcba9876543210" })));
    const result = await createPaperBlotterClient(fetcher).getSelectedOrder(ORDER_ID);
    expect(result).toEqual({ ok: false, error: "INVALID_RESPONSE" });
  });
});

describe("PaperBlotterView", () => {
  it("groups ledger lineage in sequence, labels unavailable histories, and keeps cancel uncertainty explicit", async () => {
    const order = selected({ state: "CANCEL_REQUESTED_UNCONFIRMED", cancel_attempted: true });
    const client: PaperBlotterClient = {
      getActivity: vi.fn().mockResolvedValue({ ok: true, data: activity() }),
      getStatus: vi.fn().mockResolvedValue({ ok: true, data: status }),
      getRisk: vi.fn().mockResolvedValue({ ok: true, data: risk }),
      getSelectedOrder: vi.fn().mockResolvedValue({ ok: true, data: selected({ state: "UNKNOWN_CANCEL", cancel_attempted: true }) }),
      cancelOrder: vi.fn().mockResolvedValue({ ok: true, data: order }),
    };
    render(<PaperBlotterView client={client} />);
    expect(await screen.findByText(/Risk-event history: unavailable/)).toBeTruthy();
    expect(screen.getByText(/OMS accounting units; these are not broker-confirmed positions/)).toBeTruthy();
    expect(screen.getByText(/2026-10-06T12:00:01Z/)).toBeTruthy();
    expect(screen.getByText(/Historical order state-transition events: unavailable/)).toBeTruthy();
    const ordered = screen.getByRole("list", { name: `Ledger sequence for order ${ORDER_ID}` });
    expect([...ordered.querySelectorAll("li")].map((item) => item.textContent)).toEqual([
      expect.stringContaining("Sequence 1"),
      expect.stringContaining("Sequence 2"),
      expect.stringContaining("Sequence 3"),
    ]);
    fireEvent.click(screen.getByRole("button", { name: "Load selected order details" }));
    expect(await screen.findByText(/Selected order source timestamp: unavailable/)).toBeTruthy();
    expect(screen.getByText(/Cancel unavailable for this order state or discrepancy status/)).toBeTruthy();
    expect(client.cancelOrder).not.toHaveBeenCalled();
  });

  it("shows cancel response state without treating an unconfirmed broker response as confirmation", async () => {
    const client: PaperBlotterClient = {
      getActivity: vi.fn().mockResolvedValue({ ok: true, data: activity() }),
      getStatus: vi.fn().mockResolvedValue({ ok: true, data: status }),
      getRisk: vi.fn().mockResolvedValue({ ok: true, data: risk }),
      getSelectedOrder: vi.fn().mockResolvedValue({ ok: true, data: selected() }),
      cancelOrder: vi.fn().mockResolvedValue({ ok: true, data: selected({ state: "CANCEL_REQUESTED_UNCONFIRMED", cancel_attempted: true }) }),
    };
    render(<PaperBlotterView client={client} />);
    fireEvent.click(await screen.findByRole("button", { name: "Load selected order details" }));
    fireEvent.click(await screen.findByRole("button", { name: "Request cancel" }));
    await waitFor(() => expect(client.cancelOrder).toHaveBeenCalledOnce());
    expect(await screen.findByText(/Current OMS state: CANCEL_REQUESTED_UNCONFIRMED/)).toBeTruthy();
    expect(screen.getByText(/Broker confirmation: UNCONFIRMED/)).toBeTruthy();
  });

  it("fails closed when activity pagination repeats a cursor on empty pages", async () => {
    const firstPage = { ...activity(), next_cursor: "cursor-repeat" };
    const repeatedPage = { ...activity(), items: [], next_cursor: "cursor-repeat" };
    const getActivity = vi.fn()
      .mockResolvedValueOnce({ ok: true, data: firstPage })
      .mockResolvedValue({ ok: true, data: repeatedPage });
    const client: PaperBlotterClient = {
      getActivity,
      getStatus: vi.fn().mockResolvedValue({ ok: true, data: status }),
      getRisk: vi.fn().mockResolvedValue({ ok: true, data: risk }),
      getSelectedOrder: vi.fn(),
      cancelOrder: vi.fn(),
    };
    render(<PaperBlotterView client={client} />);
    expect((await screen.findByRole("alert")).textContent).toContain("The paper activity service is unavailable.");
    expect(getActivity).toHaveBeenCalledTimes(2);
  });

  it("caps distinct empty activity pages and returns the same fixed unavailable state", async () => {
    let page = 0;
    const getActivity = vi.fn(async () => {
      page += 1;
      return {
        ok: true as const,
        data: {
          ...activity(),
          items: page === 1 ? activity().items : [],
          next_cursor: `cursor-${page}`,
        },
      };
    });
    const client: PaperBlotterClient = {
      getActivity,
      getStatus: vi.fn().mockResolvedValue({ ok: true, data: status }),
      getRisk: vi.fn().mockResolvedValue({ ok: true, data: risk }),
      getSelectedOrder: vi.fn(),
      cancelOrder: vi.fn(),
    };
    render(<PaperBlotterView client={client} />);
    expect((await screen.findByRole("alert")).textContent).toContain("The paper activity service is unavailable.");
    expect(getActivity).toHaveBeenCalledTimes(50);
  });
});
