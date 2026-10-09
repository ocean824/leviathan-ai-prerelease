import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { describe, expect, it, vi } from "vitest";
import {
  HALT_ENGAGE_PATH,
  HALT_LIFT_PATH,
  HALT_REASON_OPTIONS,
  HALT_STATUS_PATH,
  createPaperHaltApi,
  type KnownHaltReason,
} from "../api";
import { PaperHaltControlView } from "../PaperHaltControlView";

const APPROVED_REASONS = [
  "omega_kill_signal",
  "operator_halt",
  "operator_hold",
  "risk_limit_breach",
  "stale_data",
  "reconciliation_divergence",
  "audit_sink_failure",
  "tiamat_hash_mismatch",
  "daily_drawdown_breach",
  "weekly_drawdown_breach",
  "trailing_drawdown_breach",
  "legacy_state_unknown",
] as const;
const DYNAMIC_REASON = `omega_kill:${"a".repeat(64)}` as KnownHaltReason;

type CapturedCall = {
  path: string;
  method: string;
  body: unknown;
  init: RequestInit | undefined;
};
type Reply = Response | Promise<Response>;
type Handlers = {
  status?: (call: number) => Reply;
  engage?: () => Reply;
  lift?: () => Reply;
};

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function statusBody(overrides: Record<string, unknown> = {}) {
  return {
    halted: false,
    active_halts: [],
    fault_code: null,
    operating_mode: "research",
    ...overrides,
  };
}

function harness(handlers: Handlers = {}) {
  const calls: CapturedCall[] = [];
  let statusCalls = 0;
  const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit): Reply => {
    const path = String(input);
    const method = (init?.method ?? "GET").toUpperCase();
    let body: unknown;
    if (typeof init?.body === "string") {
      try {
        body = JSON.parse(init.body);
      } catch {
        body = "INVALID_JSON";
      }
    }
    calls.push({ path, method, body, init });
    if (path === HALT_STATUS_PATH && method === "GET") {
      statusCalls += 1;
      return (handlers.status ?? (() => json(statusBody())))(statusCalls);
    }
    if (path === HALT_ENGAGE_PATH && method === "POST") {
      return (handlers.engage ?? (() => json({ halted: true, active_halts: ["operator_halt"] })))();
    }
    if (path === HALT_LIFT_PATH && method === "POST") {
      return (handlers.lift ?? (() => json({ halted: false, active_halts: [] })))();
    }
    return json({ detail: "unexpected route" }, 404);
  });
  return { calls, fetcher: fetchMock as unknown as typeof fetch, fetchMock };
}

function callsAt(calls: CapturedCall[], path: string) {
  return calls.filter((call) => call.path === path);
}

function expectOnlyRiskRoutes(calls: CapturedCall[]) {
  expect(calls.length).toBeGreaterThan(0);
  expect(calls.every((call) => [HALT_STATUS_PATH, HALT_ENGAGE_PATH, HALT_LIFT_PATH].includes(call.path))).toBe(true);
  for (const call of calls) {
    expect(call.init?.cache).toBe("no-store");
    expect(call.init?.credentials).toBe("same-origin");
    if (call.path === HALT_STATUS_PATH) {
      expect(call.method).toBe("GET");
      expect(call.body).toBeUndefined();
    } else {
      expect(call.method).toBe("POST");
      expect(call.body).toEqual({ reason: expect.any(String) });
      expect(Object.keys(call.body as object)).toEqual(["reason"]);
    }
  }
}

describe("PAPER-HALT-OPERATOR-UI-001 independent acceptance", () => {
  it("exposes exactly the approved static engage reasons and posts only one selected reason", async () => {
    expect(HALT_REASON_OPTIONS).toEqual(APPROVED_REASONS);
    const api = harness();
    render(<PaperHaltControlView fetcher={api.fetcher} />);

    const select = await screen.findByRole("combobox", { name: "Reason to engage" });
    expect(within(select).getAllByRole("option").map((option) => (option as HTMLOptionElement).value))
      .toEqual(APPROVED_REASONS);
    fireEvent.change(select, { target: { value: "risk_limit_breach" } });
    fireEvent.click(screen.getByRole("button", { name: "Engage HALT" }));

    await waitFor(() => expect(callsAt(api.calls, HALT_ENGAGE_PATH)).toHaveLength(1));
    expect(callsAt(api.calls, HALT_ENGAGE_PATH)[0]?.body).toEqual({ reason: "risk_limit_breach" });
    expectOnlyRiskRoutes(api.calls);
  });

  it("rejects a dynamic OMEGA reason for engage without sending a request", async () => {
    const api = harness();
    const client = createPaperHaltApi(api.fetcher);
    await expect(client.engage(DYNAMIC_REASON as never)).resolves.toEqual({
      ok: false,
      error: "INVALID_HALT_REASON",
    });
    expect(api.calls).toEqual([]);
  });

  it("requires explicit confirmation for an exact active lift reason; cancel sends nothing", async () => {
    const api = harness({
      status: () => json(statusBody({ halted: true, active_halts: ["operator_hold", DYNAMIC_REASON] })),
    });
    render(<PaperHaltControlView fetcher={api.fetcher} />);
    expect(await screen.findByText("HALT ENGAGED")).toBeTruthy();

    const active = screen.getByRole("region", { name: "Active HALT reasons" });
    const liftButtons = within(active).getAllByRole("button");
    expect(liftButtons).toHaveLength(2);
    expect(liftButtons.map((button) => (button.getAttribute("aria-label") ?? button.textContent ?? "").trim())).toEqual([
      "Lift HALT reason operator_hold",
      `Lift HALT reason ${DYNAMIC_REASON}`,
    ]);
    fireEvent.click(screen.getByRole("button", { name: `Lift HALT reason ${DYNAMIC_REASON}` }));
    const confirmation = screen.getByRole("group", { name: "Confirm HALT lift" });
    expect(within(confirmation).getByRole("button", { name: "Confirm lift" })).toBeTruthy();
    expect(within(confirmation).getByRole("button", { name: "Cancel lift" })).toBeTruthy();
    expect(callsAt(api.calls, HALT_LIFT_PATH)).toHaveLength(0);
    fireEvent.click(within(confirmation).getByRole("button", { name: "Cancel lift" }));
    expect(screen.queryByRole("group", { name: "Confirm HALT lift" })).toBeNull();
    expect(callsAt(api.calls, HALT_LIFT_PATH)).toHaveLength(0);

    fireEvent.click(screen.getByRole("button", { name: `Lift HALT reason ${DYNAMIC_REASON}` }));
    fireEvent.click(within(screen.getByRole("group", { name: "Confirm HALT lift" }))
      .getByRole("button", { name: "Confirm lift" }));
    await waitFor(() => expect(callsAt(api.calls, HALT_LIFT_PATH)).toHaveLength(1));
    expect(callsAt(api.calls, HALT_LIFT_PATH)[0]?.body).toEqual({ reason: DYNAMIC_REASON });
    expectOnlyRiskRoutes(api.calls);
  });

  it("shows pending as unverified within the transition and ignores the mutation receipt", async () => {
    let resolveEngage: ((response: Response) => void) | undefined;
    const mutation = new Promise<Response>((resolve) => { resolveEngage = resolve; });
    const api = harness({
      status: () => json(statusBody()),
      engage: () => mutation,
    });
    render(<PaperHaltControlView fetcher={api.fetcher} />);
    expect(await screen.findByText("NO ACTIVE HALT")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Engage HALT" }));

    expect(await screen.findByText(/HALT status pending \/ unverified/i, {}, { timeout: 5_000 })).toBeTruthy();
    expect(screen.queryByText("NO ACTIVE HALT")).toBeNull();
    expect(screen.queryByText("HALT ENGAGED")).toBeNull();
    expect(screen.getByRole("button", { name: "Engage HALT" })).toBeDisabled();
    expect(screen.getByRole("combobox", { name: "Reason to engage" })).toBeDisabled();
    expect(callsAt(api.calls, HALT_ENGAGE_PATH)).toHaveLength(1);
    expect(screen.getByText(/HALT status pending \/ unverified/i).closest("[aria-live]")).toHaveAttribute("aria-live", "polite");
    expect(screen.getByText(/HALT change pending/i).closest("[aria-live]")).toHaveAttribute("aria-live", "assertive");

    await act(async () => {
      resolveEngage?.(json({ halted: true, active_halts: ["operator_halt"] }));
      await mutation;
    });
    await waitFor(() => {
      expect(callsAt(api.calls, HALT_STATUS_PATH)).toHaveLength(2);
      expect(screen.getByText("NO ACTIVE HALT")).toBeTruthy();
    });
    expect(screen.getByText("NO ACTIVE HALT")).toBeTruthy();
    expect(screen.queryByText("HALT ENGAGED")).toBeNull();
    expectOnlyRiskRoutes(api.calls);
  });

  it("reports a persistence failure and re-fetches instead of drifting committed state", async () => {
    const api = harness({
      status: () => json(statusBody()),
      engage: () => json({ detail: "synthetic private persistence text" }, 503),
    });
    render(<PaperHaltControlView fetcher={api.fetcher} />);
    expect(await screen.findByText("NO ACTIVE HALT")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Engage HALT" }));

    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toMatch(/could not be persisted/i);
    expect(alert.textContent).not.toContain("synthetic private persistence text");
    await waitFor(() => expect(callsAt(api.calls, HALT_STATUS_PATH)).toHaveLength(2));
    expect(screen.getByText("NO ACTIVE HALT")).toBeTruthy();
    expectOnlyRiskRoutes(api.calls);
  });

  it("reports timeout, re-fetches, and never labels an unverified result as no active HALT", async () => {
    vi.useFakeTimers();
    const api = harness({
      status: () => json(statusBody()),
      engage: () => new Promise<Response>(() => undefined),
    });
    render(<PaperHaltControlView fetcher={api.fetcher} />);
    await act(async () => { await Promise.resolve(); await Promise.resolve(); });
    fireEvent.click(screen.getByRole("button", { name: "Engage HALT" }));
    expect(screen.queryByText("NO ACTIVE HALT")).toBeNull();
    await act(async () => { await vi.advanceTimersByTimeAsync(5_000); });

    expect(screen.getByRole("alert").textContent).toMatch(/timed out/i);
    expect(callsAt(api.calls, HALT_STATUS_PATH)).toHaveLength(2);
    expect(screen.getByText("HALT status is unverified.")).toBeTruthy();
    expect(screen.queryByText("NO ACTIVE HALT")).toBeNull();
    expect(screen.queryByText("HALT ENGAGED")).toBeNull();
    expectOnlyRiskRoutes(api.calls);
    vi.useRealTimers();
  });

  it("does not let an older pending status read overwrite the newer post-mutation read", async () => {
    let resolveOldRead: ((response: Response) => void) | undefined;
    const oldRead = new Promise<Response>((resolve) => { resolveOldRead = resolve; });
    const api = harness({
      status: (call) => {
        if (call === 1) return json(statusBody({ halted: true, active_halts: ["operator_hold"] }));
        if (call === 2) return oldRead;
        return json(statusBody({ halted: true, active_halts: ["risk_limit_breach"] }));
      },
      engage: () => json({ halted: true, active_halts: ["stale_data"] }),
    });
    render(<PaperHaltControlView fetcher={api.fetcher} />);
    expect(await screen.findByText("HALT ENGAGED")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Refresh HALT status" }));
    await waitFor(() => expect(callsAt(api.calls, HALT_STATUS_PATH)).toHaveLength(2));

    fireEvent.click(screen.getByRole("button", { name: "Engage HALT" }));
    await waitFor(() => expect(callsAt(api.calls, HALT_STATUS_PATH)).toHaveLength(3));
    await waitFor(() => expect(screen.getByText("HALT ENGAGED")).toBeTruthy());
    expect(screen.getByRole("button", { name: "Lift HALT reason risk_limit_breach" })).toBeTruthy();

    await act(async () => {
      resolveOldRead?.(json(statusBody()));
      await oldRead;
    });
    expect(screen.getByText("HALT ENGAGED")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Lift HALT reason risk_limit_breach" })).toBeTruthy();
    expect(screen.queryByText("NO ACTIVE HALT")).toBeNull();
    expectOnlyRiskRoutes(api.calls);
  });

  it("keeps native keyboard-accessible controls, announces status, and disables LIVE", async () => {
    const api = harness();
    render(<PaperHaltControlView fetcher={api.fetcher} />);
    const select = await screen.findByRole("combobox", { name: "Reason to engage" });
    const engage = screen.getByRole("button", { name: "Engage HALT" });
    const live = screen.getByRole("button", { name: "LIVE trading disabled" });

    expect(select.tagName).toBe("SELECT");
    expect(engage.tagName).toBe("BUTTON");
    expect(select.tabIndex).toBeGreaterThanOrEqual(0);
    expect(engage.tabIndex).toBeGreaterThanOrEqual(0);
    expect(live).toHaveProperty("disabled", true);
    expect(screen.getByRole("status")).toBeTruthy();
    expect(screen.getByRole("status")).toHaveAttribute("aria-live", "polite");
    select.focus();
    expect(document.activeElement).toBe(select);
    fireEvent.keyDown(select, { key: "ArrowDown" });
    expect(select).toHaveFocus();
    expectOnlyRiskRoutes(api.calls);
  });
});
