import { fireEvent, render, screen, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { afterEach, describe, expect, it, vi } from "vitest";
import { PaperBlotterView } from "../PaperBlotterView";
import { createPaperBlotterClient } from "../api";

const ORDER_A = "0123456789abcdef0123456789abcdef";
const ORDER_B = "abcdef0123456789abcdef0123456789";
const ORDER_TIME = "2026-10-06T14:30:00.123456Z";
const FILL_TIME = "2026-10-06T14:31:02.000001Z";
const CORRECTION_TIME = "2026-10-06T14:32:03.999999Z";

function order(orderId: string, state = "WORKING", discrepancies: string[] = []) {
  return {
    order_id: orderId,
    venue: "CME",
    instrument_id: "ESZ6",
    side: "BUY",
    state,
    quantity: "3",
    filled_quantity: "2",
    discrepancies,
    created_at_utc: ORDER_TIME,
  };
}

function activityPage(items = [
  { kind: "ORDER", ledger_sequence: 10, order: order(ORDER_A) },
  {
    kind: "FILL",
    ledger_sequence: 20,
    fill: {
      order_id: ORDER_A,
      execution_id: "exec-1",
      venue: "CME",
      instrument_id: "ESZ6",
      side: "BUY",
      quantity: "2",
      price: "5812.25",
      commission: "1.25",
      occurred_at_utc: FILL_TIME,
    },
  },
  {
    kind: "FILL_CORRECTION",
    ledger_sequence: 30,
    correction: {
      order_id: ORDER_A,
      execution_id: "exec-1",
      correction_id: "corr-1",
      revision: 2,
      revised_quantity: "1.5",
      revised_price: "5811.75",
      revised_commission: "1.5",
      occurred_at_utc: CORRECTION_TIME,
    },
  },
  { kind: "ORDER", ledger_sequence: 40, order: order(ORDER_B, "FILLED") },
], nextCursor: string | null = null) {
  return {
    schema_version: 1,
    evidence_label: "OMS ledger evidence",
    environment: "paper",
    account_id: "paper-account-1",
    high_water_sequence: 40,
    items,
    next_cursor: nextCursor,
    net_filled_units: [
      { venue: "CME", instrument_id: "ESZ6", quantity: "1.5" },
    ],
  };
}

function selectedOrder(orderId: string, overrides: Record<string, unknown> = {}) {
  return {
    order_id: orderId,
    state: "WORKING",
    version: 3,
    environment: "paper",
    account_id: "paper-account-1",
    venue: "CME",
    instrument_id: "ESZ6",
    strategy_id: "strategy-1",
    filled_quantity: "2",
    venue_order_id: "venue-order-1",
    discrepancies: [],
    submit_attempted: true,
    cancel_attempted: false,
    ...overrides,
  };
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

type CapturedRequest = { url: string; method: string; body: BodyInit | null | undefined };

function makeFetch(options: {
  selected?: unknown;
  cancelStatus?: number;
  cancelBody?: unknown;
  emptyRepeatedCursor?: string;
} = {}) {
  const requests: CapturedRequest[] = [];
  const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    requests.push({ url, method, body: init?.body });
    if (url.startsWith("/api/orders/activity?")) {
      return jsonResponse(options.emptyRepeatedCursor
        ? activityPage([], options.emptyRepeatedCursor)
        : activityPage());
    }
    if (url === "/api/orders/status") {
      return jsonResponse({ live_enabled: false, recovery_status: "READY", activation_count: 4 });
    }
    if (url === "/api/risk/status") {
      return jsonResponse({ halted: true, active_halts: ["MANUAL_HALT"], operating_mode: "PAPER", fault_code: null, policy: null });
    }
    if (method === "GET" && url === `/api/orders/${ORDER_A}`) {
      return jsonResponse(options.selected ?? selectedOrder(ORDER_A));
    }
    if (method === "POST" && url === `/api/orders/${ORDER_A}/cancel`) {
      return jsonResponse(options.cancelBody ?? selectedOrder(ORDER_A, { state: "CANCEL_PENDING", cancel_attempted: true }), options.cancelStatus ?? 200);
    }
    return jsonResponse({ error: { code: "UNEXPECTED_REQUEST" } }, 500);
  }) as unknown as typeof fetch;
  return { fetcher, requests };
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("PAPER blotter independent acceptance", () => {
  it("groups fill and correction lineage, preserves source times, and keeps OMS units distinct from broker positions", async () => {
    const { fetcher, requests } = makeFetch();
    render(<PaperBlotterView client={createPaperBlotterClient(fetcher)} />);

    expect(await screen.findByRole("heading", { name: "Paper blotter" })).toBeInTheDocument();
    expect(await screen.findByText("Risk-event history: unavailable; this endpoint exposes current status only.")).toBeInTheDocument();

    expect(screen.getByRole("heading", { name: "OMS net filled units" })).toBeInTheDocument();
    expect(screen.getByText("OMS accounting units; these are not broker-confirmed positions.")).toBeInTheDocument();
    expect(screen.getByText("Broker-confirmed positions: unavailable from this endpoint.")).toBeInTheDocument();
    expect(screen.getByText("CME · ESZ6: 1.5")).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: /broker position/i })).not.toBeInTheDocument();

    expect(within(screen.getByRole("article", { name: `Order ${ORDER_A}` })).getByText(
      `Source timestamp (order record): ${ORDER_TIME}`,
    )).toBeInTheDocument();
    const ledger = screen.getByRole("list", { name: `Ledger sequence for order ${ORDER_A}` });
    expect(screen.getByText("Historical order state-transition events: unavailable from the current activity API.")).toBeInTheDocument();

    const rows = within(ledger).getAllByRole("listitem");
    expect(rows).toHaveLength(3);
    expect(rows[0]).toHaveTextContent("Sequence 10: Order record");
    expect(rows[0]).toHaveTextContent(ORDER_TIME);
    expect(rows[1]).toHaveTextContent("Sequence 20: Fill exec-1");
    expect(rows[1]).toHaveTextContent(FILL_TIME);
    expect(rows[2]).toHaveTextContent("Sequence 30: Correction corr-1 for execution exec-1");
    expect(rows[2]).toHaveTextContent(CORRECTION_TIME);
    expect(rows[2]).not.toHaveTextContent("original fill not present");

    expect(screen.getByText("HALT reported")).toBeInTheDocument();
    expect(await screen.findByText("Risk status source timestamp: Source timestamp unavailable")).toBeInTheDocument();
    expect(screen.getByText("Order status source timestamp: Source timestamp unavailable")).toBeInTheDocument();
    expect(requests.map(({ url }) => url).sort()).toEqual([
      "/api/orders/activity?limit=100",
      "/api/orders/status",
      "/api/risk/status",
    ].sort());
    expect(requests.every(({ method }) => method === "GET")).toBe(true);
  });

  it("communicates current order status as text and only sends the eligible selected-order cancel", async () => {
    const { fetcher, requests } = makeFetch();
    render(<PaperBlotterView client={createPaperBlotterClient(fetcher)} />);

    fireEvent.click((await screen.findAllByRole("button", { name: "Load selected order details" }))[0]!);
    expect(await screen.findByText(/Current OMS state: WORKING \(version 3\)/)).toBeInTheDocument();
    expect(screen.getByRole("article", { name: `Order ${ORDER_A}` })).toHaveTextContent(
      "Current OMS snapshot state: WORKING. This is a current snapshot, not historical transition evidence.",
    );
    expect(screen.getByRole("article", { name: `Order ${ORDER_A}` })).toHaveTextContent(
      "Broker confirmation: not established by the OMS ledger snapshot.",
    );
    expect(screen.getByText("Selected order source timestamp: unavailable; the endpoint does not provide one.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Request cancel" })).toBeEnabled();

    fireEvent.click(screen.getByRole("button", { name: "Request cancel" }));
    await screen.findByText(/Current OMS state: CANCEL_PENDING/);

    expect(requests.map(({ url, method }) => `${method} ${url}`).sort()).toEqual([
      "GET /api/orders/activity?limit=100",
      "GET /api/orders/status",
      "GET /api/risk/status",
      `GET /api/orders/${ORDER_A}`,
      `POST /api/orders/${ORDER_A}/cancel`,
    ].sort());
    expect(requests.find(({ url }) => url.endsWith("/cancel"))?.body).toBeUndefined();
    expect(requests.every(({ url, method }) => {
      if (url.endsWith("/cancel")) return method === "POST";
      return method === "GET";
    })).toBe(true);
    expect(requests.filter(({ url }) => url.endsWith("/cancel"))).toHaveLength(1);
  });

  it("never offers cancel for an order with a discrepancy and makes no cancel request", async () => {
    const { fetcher, requests } = makeFetch({
      selected: selectedOrder(ORDER_A, { discrepancies: ["OVERFILL"] }),
    });
    render(<PaperBlotterView client={createPaperBlotterClient(fetcher)} />);

    fireEvent.click((await screen.findAllByRole("button", { name: "Load selected order details" }))[0]!);
    expect(await screen.findByText("Cancel unavailable for this order state or discrepancy status.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Request cancel" })).not.toBeInTheDocument();
    expect(requests.every(({ url }) => !url.endsWith("/cancel"))).toBe(true);
    expect(requests.map(({ url, method }) => `${method} ${url}`).sort()).toEqual([
      "GET /api/orders/activity?limit=100",
      "GET /api/orders/status",
      "GET /api/risk/status",
      `GET /api/orders/${ORDER_A}`,
    ].sort());
  });

  it("does not turn a rejected server cancel into a canceled status claim", async () => {
    const { fetcher } = makeFetch({ cancelStatus: 409, cancelBody: { error: { code: "CANCEL_REJECTED" } } });
    render(<PaperBlotterView client={createPaperBlotterClient(fetcher)} />);

    fireEvent.click((await screen.findAllByRole("button", { name: "Load selected order details" }))[0]!);
    fireEvent.click(await screen.findByRole("button", { name: "Request cancel" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("UNAVAILABLE");
    expect(screen.queryByText(/Current OMS state: CANCELED/)).not.toBeInTheDocument();
  });

  it("stops on a repeated valid activity cursor and shows a fixed unavailable state", async () => {
    const repeatedCursor = `page.${"a".repeat(43)}`;
    const { fetcher, requests } = makeFetch({ emptyRepeatedCursor: repeatedCursor });
    render(<PaperBlotterView client={createPaperBlotterClient(fetcher)} />);

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("UNAVAILABLE");
    expect(alert).toHaveTextContent("The paper activity service is unavailable.");
    expect(within(alert).getByRole("button", { name: "Retry" })).toBeInTheDocument();

    const activityRequests = requests.filter(({ url }) => url.startsWith("/api/orders/activity?"));
    expect(activityRequests).toHaveLength(2);
    expect(new URL(activityRequests[0]!.url, "http://localhost").searchParams.get("cursor")).toBeNull();
    expect(new URL(activityRequests[1]!.url, "http://localhost").searchParams.get("cursor")).toBe(repeatedCursor);
    expect(requests.filter(({ url }) => url === "/api/orders/status" || url === "/api/risk/status")).toHaveLength(2);
    expect(requests.every(({ method }) => method === "GET")).toBe(true);
    expect(screen.queryByRole("heading", { name: "OMS net filled units" })).not.toBeInTheDocument();
  });
});
