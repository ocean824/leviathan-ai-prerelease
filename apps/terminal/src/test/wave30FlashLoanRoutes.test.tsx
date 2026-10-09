import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { FlashLoanRoutesView } from "../wave30/FlashLoanRoutesView";
import type { RouteViewV1 } from "../wave30/FlashLoanRoutesTypes";

function route(routeId: string, overrides: Partial<RouteViewV1> = {}): RouteViewV1 {
  return {
    route_id: routeId,
    route_class: "TRIANGULAR",
    atomicity: "ATOMIC",
    chain_id: "chain-1",
    base_token: "token-a",
    quote_token: "token-b",
    hops: [{ venue_id: "venue-a", token_in: "token-a", token_out: "token-b" }],
    venues: ["venue-a"],
    net_profit: "0.125",
    spread_bps: "12.5",
    gas_cost: "0.01",
    loan_size: "10",
    slippage_headroom_bps: "50",
    latency_eta_ms: 30,
    event_time_ns: 800_000_000n,
    age_ns: 200_000_000n,
    age_ms: 200n,
    age_bucket: "FRESH",
    mev_risk: "LOW",
    private_relay_enabled: false,
    liquidity_available: true,
    status: "VIABLE",
    reason_codes: [],
    read_only: true,
    ...overrides,
  };
}

describe("FlashLoanRoutesView", () => {
  it("virtualizes 500 rows and preserves the supplied order", () => {
    const routes = Array.from({ length: 500 }, (_, index) => route(`route-${index}`));
    render(<FlashLoanRoutesView routes={routes} clock={() => 1_000_000_000n} />);

    const list = screen.getByRole("list", { name: "Flash loan routes" });
    expect(within(list).getAllByRole("listitem").length).toBeLessThan(20);
    expect(within(list).getByRole("listitem", { name: "Route route-0; Viable" }).getAttribute("aria-posinset"))
      .toBe("1");
    expect(within(list).queryByRole("listitem", { name: "Route route-499; Viable" })).toBeNull();

    const viewport = screen.getByTestId("flash-loan-routes-viewport");
    Object.defineProperty(viewport, "scrollTop", { configurable: true, value: 200 * 160 });
    fireEvent.scroll(viewport);
    expect(within(list).getByRole("listitem", { name: "Route route-200; Viable" }).getAttribute("aria-posinset"))
      .toBe("201");
    expect(within(list).getAllByRole("listitem").length).toBeLessThan(20);
  });

  it("shows source-event age and specific restrictions while all action controls stay disabled", () => {
    const locked = route("route-locked", {
      route_class: "CEX_DEX",
      status: "FLASH_INELIGIBLE",
      reason_codes: ["CEX_DEX", "LOCK_GAS_LIMIT", "NON_ATOMIC"],
    });
    render(<FlashLoanRoutesView routes={[locked]} clock={() => 1_000_000_000n} />);

    expect(screen.getByRole("status", { name: "Route status: Flash Ineligible" })).toBeTruthy();
    expect(screen.getByRole("status", { name: "Event-time data age: 200 ms; FRESH" })).toBeTruthy();
    expect(screen.getByText(/LOCK_GAS_LIMIT: Gas limit lock is active/)).toBeTruthy();
    expect((screen.getByRole("button", { name: "Execute route-locked" }) as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByRole("button", { name: "Override route-locked" }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByRole("status", { name: "LIVE trading status: DISABLED" })).toBeTruthy();
    expect(screen.getByRole("note").textContent).toContain("Performance and update SLA: UNVERIFIED.");
  });

  it("updates event-time age and bucket only from the injected clock", async () => {
    vi.useFakeTimers();
    let nowNs = 1_000_000_000n;
    const clock = () => nowNs;
    render(<FlashLoanRoutesView routes={[route("route-age")]} clock={clock} />);
    expect(screen.getByRole("status", { name: "Event-time data age: 200 ms; FRESH" })).toBeTruthy();

    await act(async () => {
      nowNs = 1_600_000_000n;
      vi.advanceTimersByTime(250);
    });
    expect(screen.getByRole("status", { name: "Event-time data age: 800 ms; STALE" })).toBeTruthy();
  });

  it("supports arrow and boundary-key movement through virtualized rows", async () => {
    const routes = Array.from({ length: 20 }, (_, index) => route(`route-${index}`));
    render(<FlashLoanRoutesView routes={routes} clock={() => 1_000_000_000n} />);
    const first = screen.getByRole("listitem", { name: "Route route-0; Viable" });
    first.focus();
    fireEvent.keyDown(first, { key: "ArrowDown" });
    await waitFor(() => expect(document.activeElement?.id).toBe("flash-loan-route-1"));

    fireEvent.keyDown(document.activeElement as HTMLElement, { key: "End" });
    await waitFor(() => expect(document.activeElement?.id).toBe("flash-loan-route-19"));
    expect(screen.getByRole("listitem", { name: "Route route-19; Viable" }).getAttribute("aria-posinset"))
      .toBe("20");
  });

  it("replaces unsafe identifiers instead of rendering their raw contents", () => {
    render(<FlashLoanRoutesView
      routes={[route("api-gateway", { chain_id: "risk", base_token: "desk" })]}
      clock={() => 1_000_000_000n}
    />);
    expect(screen.getByRole("listitem", { name: "Route Unlisted value; Viable" })).toBeTruthy();
    expect(screen.getByText("risk")).toBeTruthy();
    expect(screen.getByText("desk / Unlisted value")).toBeTruthy();
    expect(screen.queryByText("api-gateway")).toBeNull();
    expect(screen.getByRole("button", { name: "Execute Unlisted value" })).toBeTruthy();
  });

  it("replaces an unrecognized runtime MEV risk value with a fixed fallback", () => {
    const compromisedRoute = {
      ...route("route-mev-canary"),
      mev_risk: "ghp_SECRET_ROUTE_CANARY",
      status: "ghp_STATUS_ROUTE_CANARY",
      route_class: "ghp_VENUE_KIND_CANARY",
      reason_codes: ["ghp_LOCK_REASON_CANARY"],
      net_profit: "ghp_NUMERIC_ROUTE_CANARY",
      latency_eta_ms: "ghp_LATENCY_ROUTE_CANARY",
    } as unknown as RouteViewV1;
    render(<FlashLoanRoutesView routes={[compromisedRoute]} clock={() => 1_000_000_000n} />);

    expect(screen.getAllByText("Unverified").length).toBeGreaterThanOrEqual(2);
    expect(screen.getByRole("status", { name: "Route status: Unknown" })).toBeTruthy();
    expect(screen.getByText("Unknown restriction")).toBeTruthy();
    for (const canary of [
      "ghp_SECRET_ROUTE_CANARY",
      "ghp_STATUS_ROUTE_CANARY",
      "ghp_VENUE_KIND_CANARY",
      "ghp_LOCK_REASON_CANARY",
      "ghp_NUMERIC_ROUTE_CANARY",
      "ghp_LATENCY_ROUTE_CANARY",
    ]) {
      expect(document.body.innerHTML).not.toContain(canary);
      expect(document.body.textContent).not.toContain(canary);
      expect(document.body.getAttribute("aria-label") ?? "").not.toContain(canary);
    }
  });

  it("announces the empty state without introducing any action surface", () => {
    render(<FlashLoanRoutesView routes={[]} clock={() => 1_000_000_000n} />);
    expect(screen.getByText("No routes are available.")).toBeTruthy();
    expect(screen.queryByRole("button")).toBeNull();
  });
});
