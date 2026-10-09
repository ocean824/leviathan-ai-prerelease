import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import {
  PAPER_ACTIVATE_PATH,
  PAPER_ENVIRONMENT,
  PAPER_ORDER_STATUS_PATH,
  PAPER_REVOKE_PATH,
  PAPER_RISK_STATUS_PATH,
  createPaperActivationApi,
} from "../../../wave27/api/paperActivation";
import { createPaperSessionApi } from "../api";
import { PaperSessionControlsView } from "../PaperSessionControlsView";

const scope = {
  account_id: "acct-paper-01",
  venue: "venue-paper-01",
  instrument_id: "instrument-paper-01",
  strategy_id: "strategy-paper-01",
};

function response(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

const readyOrders = {
  live_enabled: false,
  recovery_status: "READY",
  activation_count: 2,
};
const clearRisk = {
  halted: false,
  active_halts: [],
  fault_code: null,
  operating_mode: "paper",
};

function makeFetcher(options: {
  orders?: () => Response | Promise<Response>;
  risk?: () => Response | Promise<Response>;
  resume?: () => Response | Promise<Response>;
  pause?: () => Response | Promise<Response>;
} = {}) {
  const fetcher = vi.fn<typeof fetch>(async (input, init) => {
    const path = String(input);
    const method = (init?.method ?? "GET").toUpperCase();
    if (method === "GET" && path === PAPER_ORDER_STATUS_PATH) {
      return (options.orders ?? (() => response(readyOrders)))();
    }
    if (method === "GET" && path === PAPER_RISK_STATUS_PATH) {
      return (options.risk ?? (() => response(clearRisk)))();
    }
    if (method === "POST" && path === PAPER_ACTIVATE_PATH) {
      return (options.resume ?? (() => response({ active: true }, 201)))();
    }
    if (method === "POST" && path === PAPER_REVOKE_PATH) {
      return (options.pause ?? (() => response({ active: false })))();
    }
    throw new Error("Unexpected request");
  });
  return fetcher;
}

async function enterScope() {
  const entries = [
    ["Account ID", "Confirm account ID", scope.account_id],
    ["Venue ID", "Confirm venue ID", scope.venue],
    ["Instrument ID", "Confirm instrument ID", scope.instrument_id],
    ["Strategy ID", "Confirm strategy ID", scope.strategy_id],
  ] as const;
  for (const [label, confirmLabel, value] of entries) {
    fireEvent.change(screen.getByLabelText(label), { target: { value } });
    fireEvent.change(screen.getByLabelText(confirmLabel), { target: { value } });
  }
}

describe("paper session API", () => {
  it("reuses the paper activation API for the exact pause and resume routes", async () => {
    expect(PAPER_ENVIRONMENT).toBe("paper");
    const fetcher = makeFetcher();
    const existingClient = createPaperActivationApi(fetcher);
    const sessionClient = createPaperSessionApi(fetcher);
    expect((await sessionClient.getOrderStatus()).ok).toBe(true);
    expect((await sessionClient.getRiskStatus()).ok).toBe(true);
    expect((await sessionClient.pause(scope)).ok).toBe(true);
    expect((await sessionClient.resume(scope)).ok).toBe(true);
    expect((await existingClient.getOrderStatus()).ok).toBe(true);

    const calls = fetcher.mock.calls.map(([input, init]) => ({
      path: String(input),
      method: (init?.method ?? "GET").toUpperCase(),
      body: typeof init?.body === "string" ? JSON.parse(init.body) as unknown : undefined,
    }));
    expect(calls.map(({ path, method }) => [path, method])).toEqual([
      [PAPER_ORDER_STATUS_PATH, "GET"],
      [PAPER_RISK_STATUS_PATH, "GET"],
      [PAPER_REVOKE_PATH, "POST"],
      [PAPER_ACTIVATE_PATH, "POST"],
      [PAPER_ORDER_STATUS_PATH, "GET"],
    ]);
    expect(calls[2]?.body).toEqual({ environment: "paper", ...scope });
    expect(calls[3]?.body).toEqual({ environment: "paper", ...scope });
  });
});

describe("PaperSessionControlsView", () => {
  it("renders SIM/PAPER and the API-reported aggregate state, with LIVE disabled", async () => {
    render(<PaperSessionControlsView fetcher={makeFetcher()} />);
    expect(screen.getByText("SIM / PAPER")).toBeTruthy();
    expect(screen.getByRole("button", { name: "LIVE environment disabled" })).toHaveProperty("disabled", true);
    expect(screen.getByText(/scope-specific state unavailable/i)).toBeTruthy();
    expect(screen.getByText("Resume re-enables new submissions for this paper scope only.")).toBeTruthy();
    await screen.findByText("Active paper activations (aggregate, API-reported): 2.");
    expect(screen.getByText("Recovery state (aggregate, API-reported): READY.")).toBeTruthy();
  });

  it("re-reads both statuses before resume and refreshes only after the API response", async () => {
    const fetcher = makeFetcher();
    render(<PaperSessionControlsView fetcher={fetcher} />);
    await screen.findByText("Recovery state (aggregate, API-reported): READY.");
    await enterScope();
    fireEvent.click(screen.getByRole("button", { name: "Resume submissions" }));
    await screen.findByText(/Resume accepted by the API for this session at .+; scope-specific state remains unavailable\./);

    expect(fetcher.mock.calls.map(([input, init]) => [String(input), (init?.method ?? "GET").toUpperCase()])).toEqual([
      [PAPER_ORDER_STATUS_PATH, "GET"],
      [PAPER_RISK_STATUS_PATH, "GET"],
      [PAPER_ORDER_STATUS_PATH, "GET"],
      [PAPER_RISK_STATUS_PATH, "GET"],
      [PAPER_ACTIVATE_PATH, "POST"],
      [PAPER_ORDER_STATUS_PATH, "GET"],
      [PAPER_RISK_STATUS_PATH, "GET"],
    ]);
    const post = fetcher.mock.calls[4]?.[1];
    expect(typeof post?.body).toBe("string");
    expect(JSON.parse(String(post?.body))).toEqual({ environment: "paper", ...scope });
    expect(screen.getByText(/scope-specific state unavailable/i)).toBeTruthy();
  });

  it("blocks resume on HALT and leaves pause available for the confirmed scope", async () => {
    const fetcher = makeFetcher({
      risk: () => response({
        halted: true,
        active_halts: ["operator_halt"],
        fault_code: null,
        operating_mode: "paper",
      }),
    });
    render(<PaperSessionControlsView fetcher={fetcher} />);
    await screen.findByText("Risk status: HALT or fault is API-reported.");
    await enterScope();
    expect(screen.getByRole("button", { name: "Resume submissions" })).toHaveProperty("disabled", true);
    expect(screen.getByRole("button", { name: "Pause submissions" })).toHaveProperty("disabled", false);
    fireEvent.click(screen.getByRole("button", { name: "Pause submissions" }));
    await waitFor(() => {
      expect(fetcher.mock.calls.some(([input]) => String(input) === PAPER_REVOKE_PATH)).toBe(true);
    });
    expect(screen.queryByText(/Pause accepted by the API/)).toBeNull();
    expect(fetcher.mock.calls.some(([input]) => String(input) === PAPER_ACTIVATE_PATH)).toBe(false);
  });

  it("keeps pause available while the initial status reads are still loading", async () => {
    let resolveInitialOrders: ((value: Response) => void) | undefined;
    let resolveInitialRisk: ((value: Response) => void) | undefined;
    let initialOrders = true;
    let initialRisk = true;
    const fetcher = makeFetcher({
      orders: () => {
        if (initialOrders) {
          initialOrders = false;
          return new Promise<Response>((resolve) => { resolveInitialOrders = resolve; });
        }
        return response(readyOrders);
      },
      risk: () => {
        if (initialRisk) {
          initialRisk = false;
          return new Promise<Response>((resolve) => { resolveInitialRisk = resolve; });
        }
        return response(clearRisk);
      },
    });
    render(<PaperSessionControlsView fetcher={fetcher} />);
    await enterScope();
    expect(screen.getByRole("button", { name: "Pause submissions" })).toHaveProperty("disabled", false);
    fireEvent.click(screen.getByRole("button", { name: "Pause submissions" }));
    await waitFor(() => {
      expect(fetcher.mock.calls.some(([input]) => String(input) === PAPER_REVOKE_PATH)).toBe(true);
    });
    resolveInitialOrders?.(response(readyOrders));
    resolveInitialRisk?.(response(clearRisk));
    await screen.findByText(/Pause accepted by the API for this session at .+; scope-specific state remains unavailable\./);
  });
  it("disables only resume if the API reports live_enabled", async () => {
    const fetcher = makeFetcher({
      orders: () => response({ ...readyOrders, live_enabled: true }),
    });
    render(<PaperSessionControlsView fetcher={fetcher} />);
    await screen.findByText("LIVE is reported enabled. Resume is disabled.");
    await enterScope();
    expect(screen.getByRole("button", { name: "Pause submissions" })).toHaveProperty("disabled", false);
    expect(screen.getByRole("button", { name: "Resume submissions" })).toHaveProperty("disabled", true);
    fireEvent.click(screen.getByRole("button", { name: "Pause submissions" }));
    await screen.findByText(/Pause accepted by the API for this session at .+; scope-specific state remains unavailable\./);
    expect(fetcher.mock.calls.filter(([input]) => String(input) === PAPER_REVOKE_PATH)).toHaveLength(1);
    expect(fetcher.mock.calls.some(([input]) => String(input) === PAPER_ACTIVATE_PATH)).toBe(false);
  });

  it("does not resume when Enter submits the scope form", async () => {
    const fetcher = makeFetcher();
    render(<PaperSessionControlsView fetcher={fetcher} />);
    await screen.findByText("Recovery state (aggregate, API-reported): READY.");
    await enterScope();
    fireEvent.submit(screen.getByLabelText("Account ID").closest("form") as HTMLFormElement);
    expect(fetcher.mock.calls.some(([input]) => String(input) === PAPER_ACTIVATE_PATH)).toBe(false);
    fireEvent.click(screen.getByRole("button", { name: "Resume submissions" }));
    await screen.findByText(/Resume accepted by the API for this session at .+; scope-specific state remains unavailable\./);
    expect(fetcher.mock.calls.filter(([input]) => String(input) === PAPER_ACTIVATE_PATH)).toHaveLength(1);
  });

  it("timestamps acknowledgements and clears them when a later read reports non-ready recovery", async () => {
    let orderReads = 0;
    const fetcher = makeFetcher({
      orders: () => {
        orderReads += 1;
        return response(orderReads >= 3 ? { ...readyOrders, recovery_status: "FAILED" } : readyOrders);
      },
    });
    render(<PaperSessionControlsView fetcher={fetcher} />);
    await screen.findByText("Recovery state (aggregate, API-reported): READY.");
    await enterScope();
    fireEvent.click(screen.getByRole("button", { name: "Pause submissions" }));
    expect(await screen.findByText(/Pause accepted by the API for this session at .+; scope-specific state remains unavailable\./)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Refresh status" }));
    await screen.findByText("Recovery state (aggregate, API-reported): FAILED.");
    expect(screen.queryByText(/Pause accepted by the API for this session at /)).toBeNull();
  });

  it("uses fixed failure text and never claims success when resume fails", async () => {
    const secret = "SYNTHETIC_SECRET_DO_NOT_RENDER";
    const fetcher = makeFetcher({
      resume: () => response({ detail: secret }, 403),
    });
    const { container } = render(<PaperSessionControlsView fetcher={fetcher} />);
    await screen.findByText("Recovery state (aggregate, API-reported): READY.");
    await enterScope();
    fireEvent.click(screen.getByRole("button", { name: "Resume submissions" }));
    await screen.findByText("The requested paper session action is not authorized.");
    expect(container.textContent).not.toContain(secret);
    expect(screen.queryByText(/Resume accepted by the API/)).toBeNull();
  });

  it("synchronously prevents duplicate actions and exposes the pending state", async () => {
    let resolveResume: ((value: Response) => void) | undefined;
    const resumePending = new Promise<Response>((resolve) => { resolveResume = resolve; });
    const fetcher = makeFetcher({ resume: () => resumePending });
    render(<PaperSessionControlsView fetcher={fetcher} />);
    await screen.findByText("Recovery state (aggregate, API-reported): READY.");
    await enterScope();
    const button = screen.getByRole("button", { name: "Resume submissions" });
    fireEvent.click(button);
    await waitFor(() => {
      expect(fetcher.mock.calls.filter(([input]) => String(input) === PAPER_ACTIVATE_PATH)).toHaveLength(1);
    });
    expect(screen.getByText("Paper session action in progress.")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Pause submissions" })).toHaveProperty("disabled", true);
    fireEvent.submit(button.closest("form") as HTMLFormElement);
    expect(fetcher.mock.calls.filter(([input]) => String(input) === PAPER_ACTIVATE_PATH)).toHaveLength(1);
    resolveResume?.(response({ active: true }, 201));
    await screen.findByText(/Resume accepted by the API for this session at .+; scope-specific state remains unavailable\./);
  });
});
