import { act, fireEvent, render, screen } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  classifyOrderDisposition,
  orderMonitorClient,
  type ApiResult,
  type OrderMonitorClient,
  type OrderMonitorOrder,
  type OrderMonitorStatus,
} from "../api/orderMonitor";
import { OrderMonitorView } from "../views/OrderMonitorView";

afterEach(() => {
  vi.unstubAllGlobals();
});

const ORDER_ID = "0123456789abcdef0123456789abcdef";
const SECOND_ORDER_ID = "abcdef0123456789abcdef0123456789";

const status: OrderMonitorStatus = {
  live_enabled: false,
  recovery_status: "READY",
  activation_count: 2,
};

function order(state: OrderMonitorOrder["state"]): OrderMonitorOrder {
  return {
    order_id: ORDER_ID,
    state,
    version: 3,
    environment: "paper",
    account_id: "PRIVATE_ACCOUNT_MARKER",
    venue: "TEST_VENUE",
    instrument_id: "TEST_INSTRUMENT",
    strategy_id: "PRIVATE_STRATEGY_MARKER",
    filled_quantity: "1.25",
    venue_order_id: "venue-7",
    discrepancies: ["BROKER_STATE_UNKNOWN", "secret detail must be filtered"],
    submit_attempted: true,
    cancel_attempted: false,
  };
}

describe("Order Monitor API", () => {
  it("uses GET only and encodes the order ID as one path segment", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, _init?: RequestInit) => {
      const path = String(input);
      const body = path.endsWith("/orders/status")
        ? status
        : { ...order("WORKING"), order_id: ORDER_ID };
      return new Response(JSON.stringify(body), { status: 200 });
    });
    vi.stubGlobal("fetch", fetchMock);

    expect(await orderMonitorClient.getStatus()).toEqual({ ok: true, data: status });
    expect(await orderMonitorClient.getOrder(ORDER_ID)).toMatchObject({
      ok: true,
      data: { order_id: ORDER_ID, state: "WORKING" },
    });
    expect(fetchMock).toHaveBeenCalledTimes(2);
    for (const [input, init] of fetchMock.mock.calls) {
      expect(init?.method).toBe("GET");
      expect(String(input)).toMatch(/^\/api\/orders\//);
    }
    expect(String(fetchMock.mock.calls[1]?.[0])).toBe(`/api/orders/${encodeURIComponent(ORDER_ID)}`);
  });

  it("rejects non-UUID order IDs before making a request", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    for (const invalid of ["ord-1", "A".repeat(32), "0123456789abcdef0123456789abcde!", " " + ORDER_ID]) {
      expect(await orderMonitorClient.getOrder(invalid)).toEqual({
        ok: false,
        error: "INVALID_ORDER_ID",
      });
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rejects a status response that claims LIVE is enabled", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(
      JSON.stringify({ ...status, live_enabled: true, secret: "do not show" }),
      { status: 200 },
    )));
    expect(await orderMonitorClient.getStatus()).toEqual({ ok: false, error: "INVALID_RESPONSE" });
  });

  it("returns a fixed authorization code without reading or exposing the response body", async () => {
    const json = vi.fn();
    vi.stubGlobal("fetch", vi.fn(async () => ({
      ok: false,
      status: 403,
      json,
    } as unknown as Response)));
    expect(await orderMonitorClient.getStatus()).toEqual({ ok: false, error: "UNAUTHORIZED" });
    expect(json).not.toHaveBeenCalled();
  });
});

describe("Order Monitor view", () => {
  it("keeps API data unverified and shows local receipt time separately", async () => {
    const client: OrderMonitorClient = {
      getStatus: vi.fn(async () => ({ ok: true as const, data: status })),
      getOrder: vi.fn(async () => ({ ok: true as const, data: order("WORKING") })),
    };
    const clock = vi.fn(() => 1_000);
    render(<OrderMonitorView client={client} clock={clock} />);

    expect(await screen.findByText("UNVERIFIED")).toBeInTheDocument();
    expect(screen.getAllByText("DISABLED")).toHaveLength(2);
    expect(screen.getByText("READY")).toBeInTheDocument();
    expect(screen.getByText(/no source timestamp/i)).toBeInTheDocument();
    expect(screen.getAllByText(/receipt age/i).length).toBeGreaterThan(0);
    expect(screen.queryByRole("button", { name: "Retry read" })).not.toBeInTheDocument();
  });

  it("labels accepted, filled and uncertain outcomes distinctly", async () => {
    expect(classifyOrderDisposition(order("WORKING"))).toBe("ACCEPTED");
    expect(classifyOrderDisposition(order("PARTIALLY_FILLED"))).toBe("ACCEPTED");
    expect(classifyOrderDisposition(order("FILLED"))).toBe("FILLED");
    expect(classifyOrderDisposition(order("UNKNOWN_SUBMIT"))).toBe("UNKNOWN");
  });

  it("shows broker-unconfirmed status while withholding raw and private payload fields", async () => {
    const client: OrderMonitorClient = {
      getStatus: vi.fn(async () => ({ ok: true as const, data: status })),
      getOrder: vi.fn(async () => ({
        ok: true as const,
        data: { ...order("UNKNOWN_SUBMIT"), raw_payload: "RAW_SECRET_MARKER" },
      })),
    };
    render(<OrderMonitorView client={client} clock={() => 10_000} />);
    fireEvent.change(screen.getByLabelText("Order ID"), { target: { value: ORDER_ID } });
    fireEvent.click(screen.getByRole("button", { name: "Read order" }));

    expect(await screen.findByText(/UNKNOWN · BROKER UNCONFIRMED/)).toBeInTheDocument();
    expect(screen.getByText(/broker confirmation is unconfirmed/i)).toBeInTheDocument();
    expect(screen.getByText("BROKER_STATE_UNKNOWN")).toBeInTheDocument();
    expect(screen.queryByText("secret detail must be filtered")).not.toBeInTheDocument();
    expect(screen.queryByText("PRIVATE_ACCOUNT_MARKER")).not.toBeInTheDocument();
    expect(screen.queryByText("PRIVATE_STRATEGY_MARKER")).not.toBeInTheDocument();
    expect(screen.queryByText("RAW_SECRET_MARKER")).not.toBeInTheDocument();
    expect(screen.getAllByRole("button").map((button) => button.textContent)).toEqual(["Read order"]);
  });

  it("rejects invalid order text inline without invoking the client or showing the text", async () => {
    const client: OrderMonitorClient = {
      getStatus: vi.fn(async () => ({ ok: true as const, data: status })),
      getOrder: vi.fn(async () => ({ ok: true as const, data: order("WORKING") })),
    };
    render(<OrderMonitorView client={client} />);
    fireEvent.change(screen.getByLabelText("Order ID"), {
      target: { value: "api_key=PRIVATE_MARKER" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Read order" }));

    expect(await screen.findByText("Enter a valid order ID.")).toBeInTheDocument();
    expect(client.getOrder).not.toHaveBeenCalled();
    expect(screen.queryByText(/PRIVATE_MARKER/)).not.toBeInTheDocument();
  });

  it("drops an older lookup that resolves after the latest lookup", async () => {
    let resolveOld!: (value: ApiResult<OrderMonitorOrder>) => void;
    let resolveNew!: (value: ApiResult<OrderMonitorOrder>) => void;
    const oldRequest = new Promise<ApiResult<OrderMonitorOrder>>((resolve) => {
      resolveOld = resolve;
    });
    const newRequest = new Promise<ApiResult<OrderMonitorOrder>>((resolve) => {
      resolveNew = resolve;
    });
    const client: OrderMonitorClient = {
      getStatus: vi.fn(async () => ({ ok: true as const, data: status })),
      getOrder: vi.fn((id) => id === ORDER_ID ? oldRequest : newRequest),
    };
    render(<OrderMonitorView client={client} />);

    fireEvent.change(screen.getByLabelText("Order ID"), { target: { value: ORDER_ID } });
    fireEvent.click(screen.getByRole("button", { name: "Read order" }));
    fireEvent.change(screen.getByLabelText("Order ID"), { target: { value: SECOND_ORDER_ID } });
    fireEvent.click(screen.getByRole("button", { name: "Read order" }));

    await act(async () => {
      resolveNew({ ok: true, data: { ...order("FILLED"), order_id: SECOND_ORDER_ID } });
    });
    expect(await screen.findByText(SECOND_ORDER_ID)).toBeInTheDocument();

    await act(async () => {
      resolveOld({ ok: true, data: { ...order("WORKING"), order_id: ORDER_ID } });
    });
    expect(screen.getByText(SECOND_ORDER_ID)).toBeInTheDocument();
    expect(screen.queryByText(ORDER_ID)).not.toBeInTheDocument();
  });

  it("keeps LIVE disabled and reports an unavailable gateway without showing raw errors", async () => {
    const client: OrderMonitorClient = {
      getStatus: vi.fn(async () => ({ ok: false as const, error: "UNAUTHORIZED" as const })),
      getOrder: vi.fn(async () => ({ ok: false as const, error: "NOT_FOUND" as const })),
    };
    render(<OrderMonitorView client={client} />);
    expect(await screen.findByText("UNAVAILABLE")).toBeInTheDocument();
    expect(screen.getByText("DISABLED")).toBeInTheDocument();
    expect(screen.getByText("You are not authorized to view order status.")).toBeInTheDocument();
  });
});
