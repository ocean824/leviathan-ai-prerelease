import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { RouteViewV1 } from "../wave30/FlashLoanRoutesTypes";
import { FlashLoanRoutesView } from "../wave30/FlashLoanRoutesView";

const NOW_NS = 1_800_000_000_000_000_000n;

function makeRoute(overrides: Partial<RouteViewV1> = {}): RouteViewV1 {
  return {
    route_id: "route-001",
    route_class: "TRIANGULAR",
    atomicity: "ATOMIC",
    chain_id: "chain-1",
    base_token: "TOKEN-A",
    quote_token: "TOKEN-B",
    hops: [{ venue_id: "venue-1", token_in: "TOKEN-A", token_out: "TOKEN-B" }],
    venues: ["venue-1"],
    net_profit: "1.25",
    spread_bps: "12.5",
    gas_cost: "0.01",
    loan_size: "100.00",
    slippage_headroom_bps: "8.0",
    latency_eta_ms: 42,
    event_time_ns: NOW_NS - 100_000_000n,
    age_ns: 0n,
    age_ms: 0n,
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

function makeRoutes(count: number): RouteViewV1[] {
  return Array.from({ length: count }, (_, index) => makeRoute({
    route_id: `route-${String(index).padStart(3, "0")}`,
    event_time_ns: NOW_NS - BigInt(index) * 1_000_000n,
  }));
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("FLA-ROUTE-UI-001 independent acceptance", () => {
  it("virtualizes 500 routes while exposing list size, route order, and accessible names", () => {
    const routes = makeRoutes(500);
    render(<FlashLoanRoutesView routes={routes} clock={() => NOW_NS} />);

    const list = screen.getByRole("list", { name: "Flash loan routes" });
    const visibleRows = within(list).getAllByRole("listitem");
    expect(visibleRows.length).toBeGreaterThan(0);
    expect(visibleRows.length).toBeLessThan(20);
    expect(visibleRows.length).toBeLessThan(routes.length);
    expect(visibleRows[0]?.getAttribute("aria-label")).toBe("Route route-000; Viable");
    expect(visibleRows[0]?.getAttribute("aria-posinset")).toBe("1");
    expect(visibleRows[0]?.getAttribute("aria-setsize")).toBe("500");
    expect(within(list).getByRole("listitem", { name: "Route route-000; Viable" })).toBeTruthy();
    expect(screen.getByRole("status", { name: "LIVE trading status: DISABLED" })).toBeTruthy();
    expect(screen.getByText("Performance and update SLA: UNVERIFIED.")).toBeTruthy();
  });

  it("derives data age from event_time_ns and the injected clock, ignoring supplied ages", () => {
    const route = makeRoute({
      event_time_ns: NOW_NS - 1_250_000_000n,
      age_ns: 0n,
      age_ms: 0n,
      age_bucket: "FRESH",
    });
    render(<FlashLoanRoutesView routes={[route]} clock={() => NOW_NS} />);

    const row = screen.getByRole("listitem", { name: "Route route-001; Viable" });
    expect(within(row).getByRole("status", { name: "Event-time data age: 1.25 s; STALE" })).toBeTruthy();
    expect(within(row).getByText("Data age: 1.25 s (STALE)")).toBeTruthy();
  });

  it("shows the specific lock reason and exposes a named risk-locked status", () => {
    const route = makeRoute({
      status: "RISK_LOCKED",
      reason_codes: ["LOCK_TOKEN_BLOCKLIST"],
    });
    render(<FlashLoanRoutesView routes={[route]} clock={() => NOW_NS} />);

    const row = screen.getByRole("listitem", { name: "Route route-001; Risk Locked" });
    expect(within(row).getByRole("status", { name: "Route status: Risk Locked" })).toBeTruthy();
    expect(within(row).getByText("LOCK_TOKEN_BLOCKLIST: Token blocklist lock is active")).toBeTruthy();
  });

  it("replaces unknown and canary route fields with fixed labels in text and accessible names", () => {
    const canaries = [
      "ghp_route_canary",
      "ghp_venue_kind_canary",
      "ghp_status_canary",
      "ghp_chain_canary",
      "ghp_base_canary",
      "ghp_quote_canary",
      "ghp_profit_canary",
      "ghp_gas_canary",
      "ghp_latency_canary",
      "ghp_mev_risk_canary",
      "ghp_lock_reason_canary",
    ];
    const route = makeRoute({
      route_id: canaries[0]!,
      route_class: canaries[1]! as RouteViewV1["route_class"],
      status: canaries[2]! as RouteViewV1["status"],
      chain_id: canaries[3]!,
      base_token: canaries[4]!,
      quote_token: canaries[5]!,
      net_profit: canaries[6]!,
      gas_cost: canaries[7]!,
      latency_eta_ms: canaries[8]! as unknown as number,
      mev_risk: canaries[9]! as RouteViewV1["mev_risk"],
      reason_codes: [canaries[10]! as RouteViewV1["reason_codes"][number]],
    });
    const { container } = render(<FlashLoanRoutesView routes={[route]} clock={() => NOW_NS} />);

    const row = screen.getByRole("listitem", { name: "Route Unlisted value; Unknown" });
    expect(within(row).getByRole("status", { name: "Route status: Unknown" })).toBeTruthy();
    expect(within(row).getByText("Unlisted value / Unlisted value")).toBeTruthy();
    expect(within(row).getByText("Unknown restriction")).toBeTruthy();
    expect(within(row).getAllByText("Unverified", { exact: true })).toHaveLength(4);

    const renderedHtml = container.innerHTML;
    for (const canary of canaries) {
      expect(renderedHtml).not.toContain(canary);
      expect(container.textContent).not.toContain(canary);
      for (const labeled of container.querySelectorAll<HTMLElement>("[aria-label]")) {
        expect(labeled.getAttribute("aria-label")).not.toContain(canary);
      }
    }
  });

  it("keeps every Execute and Override control disabled and produces no network or submit effect", () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);
    const submitSpy = vi.fn();
    document.addEventListener("submit", submitSpy);
    const routes = makeRoutes(500);
    const { container, unmount } = render(<FlashLoanRoutesView routes={routes} clock={() => NOW_NS} />);

    const buttons = screen.getAllByRole("button");
    expect(buttons.length).toBeGreaterThan(0);
    for (const button of buttons) {
      expect((button as HTMLButtonElement).disabled).toBe(true);
      expect(button.getAttribute("aria-label")).toMatch(/^(Execute|Override) route-\d{3}$/);
      fireEvent.click(button);
    }
    expect(container.querySelector("form")).toBeNull();
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(submitSpy).not.toHaveBeenCalled();
    document.removeEventListener("submit", submitSpy);
    unmount();
  });

  it("marks CEX-DEX routes Flash Ineligible", () => {
    const route = makeRoute({
      route_id: "cex-dex-001",
      route_class: "CEX_DEX",
      reason_codes: ["CEX_DEX"],
    });
    render(<FlashLoanRoutesView routes={[route]} clock={() => NOW_NS} />);

    const row = screen.getByRole("listitem", { name: "Route cex-dex-001; Flash Ineligible" });
    expect(within(row).getByRole("status", { name: "Route status: Flash Ineligible" })).toBeTruthy();
    expect(within(row).getByText("Flash Ineligible")).toBeTruthy();
  });

  it("preserves supplied ordering and supports ArrowUp, ArrowDown, Home, and End", async () => {
    const routes = [
      makeRoute({ route_id: "route-z" }),
      makeRoute({ route_id: "route-a" }),
      makeRoute({ route_id: "route-m" }),
    ];
    const { rerender } = render(<FlashLoanRoutesView routes={routes} clock={() => NOW_NS} />);
    const list = screen.getByRole("list", { name: "Flash loan routes" });
    const orderedNames = within(list).getAllByRole("listitem").map((row) => row.getAttribute("aria-label"));
    expect(orderedNames).toEqual([
      "Route route-z; Viable",
      "Route route-a; Viable",
      "Route route-m; Viable",
    ]);

    const first = screen.getByRole("listitem", { name: "Route route-z; Viable" });
    first.focus();
    fireEvent.keyDown(first, { key: "ArrowDown" });
    const second = screen.getByRole("listitem", { name: "Route route-a; Viable" });
    await waitFor(() => expect(document.activeElement).toBe(second));

    fireEvent.keyDown(second, { key: "ArrowDown" });
    const third = screen.getByRole("listitem", { name: "Route route-m; Viable" });
    await waitFor(() => expect(document.activeElement).toBe(third));

    fireEvent.keyDown(third, { key: "Home" });
    await waitFor(() => expect(document.activeElement).toBe(first));
    fireEvent.keyDown(first, { key: "End" });
    await waitFor(() => expect(document.activeElement).toBe(third));

    rerender(<FlashLoanRoutesView routes={[...routes]} clock={() => NOW_NS} />);
    const rerenderedList = screen.getByRole("list", { name: "Flash loan routes" });
    expect(within(rerenderedList).getAllByRole("listitem").map((row) => row.getAttribute("aria-label"))).toEqual(orderedNames);
  });
});
