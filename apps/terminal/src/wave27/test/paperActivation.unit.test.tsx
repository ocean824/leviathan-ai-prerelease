import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import {
  createPaperActivationApi,
  PAPER_ACTIVATE_PATH,
  PAPER_ENVIRONMENT,
  PAPER_ORDER_STATUS_PATH,
  PAPER_REVOKE_PATH,
  PAPER_RISK_STATUS_PATH,
} from "../api/paperActivation";
import { PaperActivationView } from "../views/PaperActivationView";

const orderBody = (extra: Record<string, unknown> = {}) => ({
  live_enabled: false,
  recovery_status: "READY",
  activation_count: 0,
  ...extra,
});

const riskBody = (extra: Record<string, unknown> = {}) => ({
  halted: false,
  active_halts: [],
  fault_code: null,
  operating_mode: "research",
  ...extra,
});

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function gateway(overrides: {
  order?: () => Response;
  risk?: () => Response;
  activation?: () => Response;
  revoke?: () => Response;
} = {}) {
  const fetcher = vi.fn(async (input: RequestInfo | URL, _init?: RequestInit) => {
    const path = String(input);
    if (path === PAPER_ORDER_STATUS_PATH) return (overrides.order ?? (() => jsonResponse(orderBody())))();
    if (path === PAPER_RISK_STATUS_PATH) return (overrides.risk ?? (() => jsonResponse(riskBody())))();
    if (path === PAPER_ACTIVATE_PATH) return (overrides.activation ?? (() => jsonResponse({ active: true })))();
    if (path === PAPER_REVOKE_PATH) return (overrides.revoke ?? (() => jsonResponse({ active: false })))();
    throw new Error("Unexpected request path");
  });
  return fetcher as unknown as typeof fetch & typeof fetcher;
}

async function enterMatchingScope() {
  const fields = [
    ["Account ID", "Confirm account ID", "account-main"],
    ["Venue ID", "Confirm venue ID", "NYSE"],
    ["Instrument ID", "Confirm instrument ID", "EUR_USD"],
    ["Strategy ID", "Confirm strategy ID", "strategy-main"],
  ] as const;
  for (const [label, confirmLabel, value] of fields) {
    fireEvent.change(screen.getByLabelText(label), { target: { value } });
    fireEvent.change(screen.getByLabelText(confirmLabel), { target: { value } });
  }
}

describe("paper activation API", () => {
  it("uses only the four allowed paths and hard-codes the paper wire value", async () => {
    expect(PAPER_ENVIRONMENT).toBe("paper");
    const fetcher = gateway();
    const api = createPaperActivationApi(fetcher);
    const scope = {
      account_id: "account-main",
      venue: "NYSE",
      instrument_id: "EUR_USD",
      strategy_id: "strategy-main",
    };

    expect((await api.getOrderStatus()).ok).toBe(true);
    expect((await api.getRiskStatus()).ok).toBe(true);
    expect((await api.activate(scope)).ok).toBe(true);
    expect((await api.revoke(scope)).ok).toBe(true);

    expect(fetcher.mock.calls.map(([input, init]) => [String(input), init?.method])).toEqual([
      [PAPER_ORDER_STATUS_PATH, "GET"],
      [PAPER_RISK_STATUS_PATH, "GET"],
      [PAPER_ACTIVATE_PATH, "POST"],
      [PAPER_REVOKE_PATH, "POST"],
    ]);
    expect(JSON.parse(String(fetcher.mock.calls[2]?.[1]?.body))).toEqual({
      environment: "paper",
      ...scope,
    });
    expect(JSON.parse(String(fetcher.mock.calls[3]?.[1]?.body))).toEqual({
      environment: "paper",
      ...scope,
    });
    for (const [, init] of fetcher.mock.calls) {
      expect(init?.credentials).toBe("same-origin");
      expect(init?.cache).toBe("no-store");
    }
  });

  it("rejects unsafe identifiers before a mutation request", async () => {
    const fetcher = gateway();
    const api = createPaperActivationApi(fetcher);
    const result = await api.activate({
      account_id: "api-key",
      venue: "NYSE",
      instrument_id: "EUR_USD",
      strategy_id: "strategy-main",
    });
    expect(result).toEqual({ ok: false, error: "INVALID_SCOPE" });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("returns fixed error codes without parsing or exposing response details", async () => {
    const secret = "SYNTHETIC_SECRET_CANARY_99117";
    const api = createPaperActivationApi(gateway({
      order: () => jsonResponse({ detail: secret }, 503),
      risk: () => new Response("not-json", { status: 200 }),
    }));
    expect(await api.getOrderStatus()).toEqual({ ok: false, error: "SERVICE_UNAVAILABLE" });
    expect(await api.getRiskStatus()).toEqual({ ok: false, error: "INVALID_RESPONSE" });
    expect(JSON.stringify([await api.getOrderStatus(), await api.getRiskStatus()])).not.toContain(secret);
  });
});

describe("PaperActivationView", () => {
  it("keeps activation disabled until status and the confirmed scope are ready", async () => {
    const fetcher = gateway();
    render(<PaperActivationView fetcher={fetcher} clock={() => 0} />);
    expect((screen.getByRole("button", { name: "Activate" }) as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByRole("button", { name: "LIVE environment disabled" }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByText(/Scope status: unknown.*API-reported\/unverified/)).toBeTruthy();

    await waitFor(() => expect(screen.getByText(/Recovery status: READY/)).toBeTruthy());
    await enterMatchingScope();
    expect((screen.getByRole("button", { name: "Activate" }) as HTMLButtonElement).disabled).toBe(false);
  });

  it("re-reads both gates before activation and reports only a local session acknowledgement", async () => {
    const fetcher = gateway();
    render(<PaperActivationView fetcher={fetcher} clock={() => 0} />);
    await waitFor(() => expect(screen.getByText(/Recovery status: READY/)).toBeTruthy());
    await enterMatchingScope();
    fireEvent.click(screen.getByRole("button", { name: "Activate" }));

    await screen.findByText(/Activation accepted by the API for this session at/);
    expect(fetcher.mock.calls.map(([input, init]) => [String(input), init?.method])).toEqual([
      [PAPER_ORDER_STATUS_PATH, "GET"],
      [PAPER_RISK_STATUS_PATH, "GET"],
      [PAPER_ORDER_STATUS_PATH, "GET"],
      [PAPER_RISK_STATUS_PATH, "GET"],
      [PAPER_ACTIVATE_PATH, "POST"],
    ]);
    expect(screen.getByText(/Scope status remains API-reported\/unverified/)).toBeTruthy();
    expect(screen.queryByText(/verified scope/i)).toBeNull();
  });

  it("blocks activation for recovery or HALT/fault and leaves revoke available", async () => {
    const fetcher = gateway({
      order: () => jsonResponse(orderBody({ recovery_status: "FAILED" })),
      risk: () => jsonResponse(riskBody({ halted: true, active_halts: ["operator_halt"] })),
    });
    render(<PaperActivationView fetcher={fetcher} />);
    await waitFor(() => expect(screen.getByText(/Recovery status: FAILED/)).toBeTruthy());
    await enterMatchingScope();
    expect((screen.getByRole("button", { name: "Activate" }) as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByRole("button", { name: "Revoke" }) as HTMLButtonElement).disabled).toBe(false);
    fireEvent.click(screen.getByRole("button", { name: "Revoke" }));
    await waitFor(() => expect(fetcher.mock.calls.some(([input]) => String(input) === PAPER_REVOKE_PATH)).toBe(true));
  });

  it("does not echo unsafe values or server response text in validation and failure states", async () => {
    const canary = "SYNTHETIC_SECRET_CANARY_99117";
    const fetcher = gateway({
      activation: () => jsonResponse({ detail: canary }, 403),
    });
    const { container } = render(<PaperActivationView fetcher={fetcher} />);
    await waitFor(() => expect(screen.getByText(/Recovery status: READY/)).toBeTruthy());
    fireEvent.change(screen.getByLabelText("Account ID"), { target: { value: "api-key" } });
    fireEvent.change(screen.getByLabelText("Confirm account ID"), { target: { value: "api-key" } });
    expect((screen.getByRole("button", { name: "Revoke" }) as HTMLButtonElement).disabled).toBe(true);
    expect(await screen.findByText(/Enter a valid matching identifier/)).toBeTruthy();
    expect(container.textContent).not.toContain(canary);
    expect(container.textContent).not.toContain("api-key");
  });

  it("shows fixed unauthorized and malformed status errors without enabling activation", async () => {
    const fetcher = gateway({
      order: () => jsonResponse({ detail: "private server detail" }, 401),
      risk: () => new Response("malformed secret response", { status: 200 }),
    });
    const { container } = render(<PaperActivationView fetcher={fetcher} />);
    await screen.findByText(/operator session is unavailable/i);
    await screen.findByText(/API response could not be verified/i);
    await enterMatchingScope();
    expect((screen.getByRole("button", { name: "Activate" }) as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByRole("button", { name: "Revoke" }) as HTMLButtonElement).disabled).toBe(false);
    expect(container.textContent).not.toContain("private server detail");
    expect(container.textContent).not.toContain("malformed secret response");
  });

  it("rejects multiline clipboard values instead of allowing text-input normalization", async () => {
    const fetcher = gateway();
    const { container } = render(<PaperActivationView fetcher={fetcher} />);
    await waitFor(() => expect(screen.getByText(/Recovery status: READY/)).toBeTruthy());
    fireEvent.paste(screen.getByLabelText("Account ID"), {
      clipboardData: { getData: () => "new\nline", types: ["text/plain"] },
    });
    expect((screen.getByRole("button", { name: "Revoke" }) as HTMLButtonElement).disabled).toBe(true);
    expect(container.textContent).toContain("Enter a valid matching identifier.");
    expect(fetcher).toHaveBeenCalledTimes(2);
  });

  it("does not poll automatically and exposes manual refresh", async () => {
    const fetcher = gateway();
    render(<PaperActivationView fetcher={fetcher} />);
    await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(2));
    expect((screen.getByRole("button", { name: "Refresh status" }) as HTMLButtonElement).disabled).toBe(false);
    fireEvent.click(screen.getByRole("button", { name: "Refresh status" }));
    await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(4));
  });
});
