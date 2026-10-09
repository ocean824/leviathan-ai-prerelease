import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import {
  type ApiResult,
  type OrderMonitorClient,
  type OrderMonitorOrder,
  type OrderMonitorStatus,
} from "../api/orderMonitor";
import { OrderMonitorView } from "../views/OrderMonitorView";
import { orderMonitorOrder, orderMonitorStatus } from "./fixtures/orderMonitor";

const ORDER_ID = "0123456789abcdef0123456789abcdef";
const SECOND_ORDER_ID = "fedcba9876543210fedcba9876543210";
const RECEIVED_AT = Date.UTC(2026, 9, 6, 12, 0, 0);

function clientFor(
  order: OrderMonitorOrder = orderMonitorOrder("WORKING"),
): OrderMonitorClient {
  return {
    getStatus: vi.fn(async (): Promise<ApiResult<OrderMonitorStatus>> => ({
      ok: true,
      data: orderMonitorStatus,
    })),
    getOrder: vi.fn(async (): Promise<ApiResult<OrderMonitorOrder>> => ({
      ok: true,
      data: order,
    })),
  };
}

async function lookupOrder(orderId = ORDER_ID): Promise<void> {
  beginOrderLookup(orderId);
  await screen.findByRole("region", { name: "Order snapshot" });
}

function beginOrderLookup(orderId: string): void {
  fireEvent.change(screen.getByRole("textbox", { name: "Order ID" }), {
    target: { value: orderId },
  });
  fireEvent.click(screen.getByRole("button", { name: "Read order" }));
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((resolvePromise) => { resolve = resolvePromise; });
  return { promise, resolve };
}

describe("ORDER-MONITOR-UI-001 independent acceptance", () => {
  it("is read-only, keeps LIVE disabled, and exposes no mutating controls", async () => {
    const client = clientFor();
    render(<OrderMonitorView client={client} clock={() => RECEIVED_AT} />);

    expect(await screen.findByText("DISABLED")).toBeTruthy();
    expect(screen.getByText("READY")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Read order" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: /submit|cancel|amend|flatten/i })).toBeNull();
    expect(screen.queryByRole("link", { name: /submit|cancel|amend|flatten/i })).toBeNull();
    expect(client.getStatus).toHaveBeenCalledTimes(1);
    expect(client.getOrder).not.toHaveBeenCalled();
  });

  it.each([
    { state: "WORKING" as const, label: "ACCEPTED", unconfirmed: false },
    { state: "PARTIALLY_FILLED" as const, label: "ACCEPTED.*PARTIALLY FILLED", unconfirmed: false },
    { state: "FILLED" as const, label: "^FILLED", unconfirmed: false },
    { state: "UNKNOWN_SUBMIT" as const, label: "UNKNOWN.*BROKER UNCONFIRMED", unconfirmed: true },
    { state: "UNKNOWN_CANCEL" as const, label: "UNKNOWN.*BROKER UNCONFIRMED", unconfirmed: true },
    { state: "CANCEL_REQUESTED_UNCONFIRMED" as const, label: "UNKNOWN.*BROKER UNCONFIRMED", unconfirmed: true },
    { state: "RECONCILE_REQUIRED" as const, label: "UNKNOWN.*BROKER UNCONFIRMED", unconfirmed: true },
  ])("labels $state distinctly and preserves broker confirmation uncertainty", async ({
    state,
    label,
    unconfirmed,
  }) => {
    const client = clientFor(orderMonitorOrder(state));
    render(<OrderMonitorView client={client} clock={() => RECEIVED_AT} />);
    await lookupOrder();

    const snapshot = screen.getByRole("region", { name: "Order snapshot" });
    expect(snapshot.querySelector(".order-monitor__disposition")?.textContent).toMatch(
      new RegExp(label),
    );
    expect(within(snapshot).getByText("OMS state").nextElementSibling?.textContent).toBe(state);
    if (unconfirmed) {
      expect(within(snapshot).getByRole("status").textContent).toMatch(/Broker confirmation is unconfirmed/);
    } else {
      expect(within(snapshot).queryByRole("status")).toBeNull();
    }
    expect(client.getOrder).toHaveBeenCalledWith(ORDER_ID);
    expect(screen.queryByRole("button", { name: /submit|cancel|amend|flatten/i })).toBeNull();
  });

  it("keeps source freshness unverified and labels local receipt time separately", async () => {
    const client = clientFor();
    render(<OrderMonitorView client={client} clock={() => RECEIVED_AT} />);

    const gatewayStatus = screen.getByRole("region", { name: "Gateway status" });
    expect(await within(gatewayStatus).findByText("UNVERIFIED")).toBeTruthy();
    expect(within(gatewayStatus).getByText(/source freshness is unverified/)).toBeTruthy();
    expect(within(gatewayStatus).getByText(/Local receipt/)).toBeTruthy();
    expect(within(gatewayStatus).getByText(/Receipt age/)).toBeTruthy();
    expect(screen.getByText(/Local receipt only · not broker time/)).toBeTruthy();
    expect(gatewayStatus.querySelector(".operator-panel__status")?.textContent).toBe("UNVERIFIED");
  });

  it.each(["UNAUTHORIZED", "INVALID_RESPONSE", "GATEWAY_UNAVAILABLE"] as const)(
    "keeps an unavailable status non-green for %s",
    async (error) => {
      const client: OrderMonitorClient = {
        getStatus: vi.fn(async (): Promise<ApiResult<OrderMonitorStatus>> => ({ ok: false, error })),
        getOrder: vi.fn(async (): Promise<ApiResult<OrderMonitorOrder>> => ({
          ok: false,
          error: "NOT_FOUND",
        })),
      };
      render(<OrderMonitorView client={client} clock={() => RECEIVED_AT} />);

      const gatewayStatus = screen.getByRole("region", { name: "Gateway status" });
      expect(await within(gatewayStatus).findByText("UNAVAILABLE")).toBeTruthy();
      expect(within(gatewayStatus).getByRole("status").textContent).not.toMatch(/READY|ACCEPTED|FILLED/);
      expect(screen.getAllByText("DISABLED").length).toBeGreaterThan(0);
    },
  );

  it("uses GET only and filters raw order payload fields before display", async () => {
    const rawCanary = "RAW_BROKER_PAYLOAD_CANARY_91f7";
    const calls: Array<{ url: string; method: string | undefined }> = [];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const url = String(input);
      calls.push({ url, method: init?.method });
      const body = url.endsWith("/orders/status")
        ? orderMonitorStatus
        : {
            ...orderMonitorOrder("FILLED"),
            raw_payload: { broker_response: rawCanary },
            unapproved_debug: rawCanary,
          };
      return new Response(JSON.stringify(body), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    });

    render(<OrderMonitorView clock={() => RECEIVED_AT} />);
    await screen.findByText("READY");
    await lookupOrder();

    expect(calls).toEqual([
      { url: "/api/orders/status", method: "GET" },
      { url: `/api/orders/${ORDER_ID}`, method: "GET" },
    ]);
    expect(document.body.textContent).not.toContain(rawCanary);
    expect(document.body.innerHTML).not.toContain(rawCanary);
    expect(screen.queryByText(/raw_payload|unapproved_debug/i)).toBeNull();
  });

  it("rejects an invalid lookup ID locally without calling the order endpoint", async () => {
    const client = clientFor();
    render(<OrderMonitorView client={client} clock={() => RECEIVED_AT} />);
    fireEvent.change(screen.getByRole("textbox", { name: "Order ID" }), {
      target: { value: "  " },
    });
    fireEvent.click(screen.getByRole("button", { name: "Read order" }));

    await waitFor(() => expect(screen.getByText(/Enter a valid order ID/)).toBeTruthy());
    expect(client.getOrder).not.toHaveBeenCalled();
  });

  it.each([
    "short",
    "ABCDEF0123456789ABCDEF0123456789",
    "0123456789abcdef0123456789abcde!",
    "0123456789abcdef0123456789abcdef/secret",
  ])("rejects malformed order ID %s before a network request without echoing it", async (badId) => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async () => new Response(
      JSON.stringify(orderMonitorStatus),
      { status: 200, headers: { "Content-Type": "application/json" } },
    ));
    render(<OrderMonitorView clock={() => RECEIVED_AT} />);
    const gatewayStatus = screen.getByRole("region", { name: "Gateway status" });
    await within(gatewayStatus).findByText("UNVERIFIED");
    fetchSpy.mockClear();

    beginOrderLookup(badId);
    const validation = await screen.findByRole("status");
    expect(validation.textContent).toMatch(/valid order ID/i);
    expect(validation.textContent).not.toContain(badId);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("encodes a valid order ID before issuing the GET", async () => {
    const encodeSpy = vi.spyOn(globalThis, "encodeURIComponent");
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const body = String(input).endsWith("/orders/status")
        ? orderMonitorStatus
        : orderMonitorOrder("WORKING");
      return new Response(JSON.stringify(body), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    });
    render(<OrderMonitorView clock={() => RECEIVED_AT} />);
    await screen.findByText("READY");
    await lookupOrder();

    expect(encodeSpy).toHaveBeenCalledWith(ORDER_ID);
    expect(fetchSpy).toHaveBeenCalledWith(
      `/api/orders/${encodeURIComponent(ORDER_ID)}`,
      expect.objectContaining({ method: "GET" }),
    );
  });

  it("keeps the newest lookup when an older request resolves last", async () => {
    const older = deferred<ApiResult<OrderMonitorOrder>>();
    const newer = deferred<ApiResult<OrderMonitorOrder>>();
    const client: OrderMonitorClient = {
      getStatus: vi.fn(async (): Promise<ApiResult<OrderMonitorStatus>> => ({
        ok: true,
        data: orderMonitorStatus,
      })),
      getOrder: vi.fn((orderId: string) =>
        orderId === ORDER_ID ? older.promise : newer.promise),
    };
    render(<OrderMonitorView client={client} clock={() => RECEIVED_AT} />);
    await screen.findByText("READY");

    beginOrderLookup(ORDER_ID);
    beginOrderLookup(SECOND_ORDER_ID);
    expect(client.getOrder).toHaveBeenNthCalledWith(1, ORDER_ID);
    expect(client.getOrder).toHaveBeenNthCalledWith(2, SECOND_ORDER_ID);

    newer.resolve({
      ok: true,
      data: orderMonitorOrder("WORKING", { order_id: SECOND_ORDER_ID }),
    });
    const snapshot = await screen.findByRole("region", { name: "Order snapshot" });
    expect(within(snapshot).getByText(SECOND_ORDER_ID)).toBeTruthy();

    older.resolve({
      ok: true,
      data: orderMonitorOrder("FILLED", { order_id: ORDER_ID }),
    });
    await waitFor(() => {
      expect(within(snapshot).getByText(SECOND_ORDER_ID)).toBeTruthy();
      expect(within(snapshot).queryByText(ORDER_ID)).toBeNull();
    });
  });
});
