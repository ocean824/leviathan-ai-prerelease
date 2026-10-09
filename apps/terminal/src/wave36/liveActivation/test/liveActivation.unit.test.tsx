import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import {
  createLiveActivationApi,
  LIVE_ACTIVATION_DISABLE_PATH,
  LIVE_ACTIVATION_ENABLE_PATH,
  LIVE_ACTIVATION_STATUS_PATH,
} from "../api";
import { LiveActivationView } from "../LiveActivationView";

const accountId = "acct-main";
const status = (overrides: Record<string, unknown> = {}) => ({
  effective_state: "OFF",
  verified: true,
  preconditions_verified: true,
  account_id: accountId,
  activation_revision: 0,
  activated_at_ns: null,
  last_verified_at_ns: 1_800_000_000_000_000_000,
  risk_policy_sha256: "a".repeat(64),
  blockers: [],
  startup_state: "OFF",
  open_orders_state: "UNAVAILABLE",
  ...overrides,
});

function response(body: unknown, statusCode = 200): Response {
  return new Response(JSON.stringify(body), {
    status: statusCode,
    headers: { "Content-Type": "application/json" },
  });
}

function fetchRouter(overrides: {
  status?: (url: string) => Response | Promise<Response>;
  enable?: () => Response | Promise<Response>;
  disable?: () => Response | Promise<Response>;
} = {}) {
  const fetcher = vi.fn(async (input: RequestInfo | URL, _init?: RequestInit) => {
    const url = String(input);
    if (url.startsWith(LIVE_ACTIVATION_STATUS_PATH)) {
      return (overrides.status ?? (() => response(status())))(url);
    }
    if (url === LIVE_ACTIVATION_ENABLE_PATH) {
      return (overrides.enable ?? (() => response({ accepted: true, effective_state: "LIVE", activation_revision: 2 })))();
    }
    if (url === LIVE_ACTIVATION_DISABLE_PATH) {
      return (overrides.disable ?? (() => response({ accepted: true, effective_state: "OFF", activation_revision: 3 })))();
    }
    throw new Error("Unexpected route");
  });
  return fetcher as unknown as typeof fetch & typeof fetcher;
}

async function enterAccount() {
  fireEvent.change(screen.getByLabelText("Account ID"), { target: { value: accountId } });
  await waitFor(() => expect((screen.getByRole("button", { name: "Refresh status" }) as HTMLButtonElement).disabled).toBe(false));
  fireEvent.click(screen.getByRole("button", { name: "Refresh status" }));
  await waitFor(() => expect((screen.getByRole("button", { name: "Refresh status" }) as HTMLButtonElement).disabled).toBe(false));
}

describe("LIVE activation API", () => {
  it("uses only the status, enable and disable routes with exact request bodies", async () => {
    const fetcher = fetchRouter();
    const api = createLiveActivationApi(fetcher);
    await api.getStatus(accountId);
    await api.enable(accountId, `ENABLE LIVE ${accountId}`);
    await api.disable(accountId);

    expect(fetcher.mock.calls.map(([url]) => String(url))).toEqual([
      `${LIVE_ACTIVATION_STATUS_PATH}?account_id=${accountId}`,
      LIVE_ACTIVATION_ENABLE_PATH,
      LIVE_ACTIVATION_DISABLE_PATH,
    ]);
    expect(fetcher.mock.calls[0]?.[1]).toMatchObject({ method: "GET", credentials: "same-origin", cache: "no-store" });
    expect(JSON.parse(String(fetcher.mock.calls[1]?.[1]?.body))).toEqual({
      account_id: accountId,
      confirmation: `ENABLE LIVE ${accountId}`,
    });
    expect(JSON.parse(String(fetcher.mock.calls[2]?.[1]?.body))).toEqual({ account_id: accountId });
  });

  it("fails closed on malformed status and refuses unsafe identifiers before fetch", async () => {
    const fetcher = fetchRouter({ status: () => response({ effective_state: "LIVE", verified: false }) });
    const api = createLiveActivationApi(fetcher);
    expect((await api.getStatus(accountId)).ok).toBe(false);
    expect((await api.enable("bad id", "ENABLE LIVE bad id")).ok).toBe(false);
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it("accepts a bounded verified open-order snapshot and rejects malformed rows", async () => {
    const order = {
      order_id: "order-1", instrument_id: "AAPL", side: "BUY", quantity: "1.250",
      status: "PARTIALLY_FILLED", verified_at_ns: 1_800_000_000_000_000_000,
    };
    const fetcher = fetchRouter({ status: () => response(status({ open_orders_state: "VERIFIED", open_orders: [order] })) });
    const api = createLiveActivationApi(fetcher);
    const result = await api.getStatus(accountId);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.data.open_orders).toEqual([order]);

    const malformedFetcher = fetchRouter({ status: () => response(status({
      open_orders_state: "VERIFIED", open_orders: [{ ...order, status: "FILLED" }],
    })) });
    expect((await createLiveActivationApi(malformedFetcher).getStatus(accountId)).ok).toBe(false);
  });
});

describe("LIVE activation view", () => {
  it("shows OFF at startup and only shows LIVE when verified by the API", async () => {
    const fetcher = fetchRouter({ status: () => response(status({ account_id: null, verified: false, preconditions_verified: false, blockers: ["ACCOUNT_NOT_SELECTED"] })) });
    render(<LiveActivationView fetcher={fetcher} />);
    expect(await screen.findByText(/LIVE state is OFF at startup/)).toBeTruthy();
    expect(screen.getByText("OFF")).toBeTruthy();
    expect(screen.queryByText("LIVE (verified)")).toBeNull();
    expect(screen.getByText(/Disabling LIVE prevents new LIVE submissions/)).toBeTruthy();
  });

  it("renders API-verified open orders and the no-cancel/no-flatten notice", async () => {
    const fetcher = fetchRouter({ status: () => response(status({
      open_orders_state: "VERIFIED",
      open_orders: [{ order_id: "order-1", instrument_id: "EUR/USD", side: "BUY", quantity: "1E+2", status: "WORKING", verified_at_ns: 1_800_000_000_000_000_000 }],
    })) });
    render(<LiveActivationView fetcher={fetcher} />);
    await enterAccount();
    expect(await screen.findByText("order-1")).toBeTruthy();
    expect(screen.getByText("1E+2")).toBeTruthy();
    expect(screen.getByText(/does not cancel or flatten existing orders/)).toBeTruthy();
  });

  it("requires fresh verified OFF, matching typed confirmation and owner/API approval to enable", async () => {
    const fetcher = fetchRouter();
    render(<LiveActivationView fetcher={fetcher} clock={() => 1_800_000_000_000} />);
    await enterAccount();
    const enable = screen.getByRole("button", { name: "Enable LIVE" });
    expect((enable as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(screen.getByLabelText("Confirmation phrase"), { target: { value: `ENABLE LIVE ${accountId}` } });
    expect((enable as HTMLButtonElement).disabled).toBe(false);
    fireEvent.click(enable);
    await waitFor(() => expect(fetcher.mock.calls.some(([url]) => String(url) === LIVE_ACTIVATION_ENABLE_PATH)).toBe(true));
    await screen.findByText(/Enable request accepted by the API/);
    const enableCall = fetcher.mock.calls.find(([url]) => String(url) === LIVE_ACTIVATION_ENABLE_PATH);
    expect(JSON.parse(String(enableCall?.[1]?.body))).toEqual({ account_id: accountId, confirmation: `ENABLE LIVE ${accountId}` });
  });

  it("blocks enable for HALT, unknown, unverified or mismatched account states", async () => {
    const cases = [
      status({ blockers: ["HALT_ACTIVE"] }),
      status({ verified: false, preconditions_verified: false }),
      status({ effective_state: "LIVE", verified: false, preconditions_verified: false }),
      status({ account_id: "other-account" }),
    ];
    for (const body of cases) {
      const fetcher = fetchRouter({ status: () => response(body) });
      render(<LiveActivationView fetcher={fetcher} />);
      await enterAccount();
      fireEvent.change(screen.getByLabelText("Confirmation phrase"), { target: { value: `ENABLE LIVE ${accountId}` } });
      expect((screen.getByRole("button", { name: "Enable LIVE" }) as HTMLButtonElement).disabled).toBe(true);
      expect(fetcher.mock.calls.some(([url]) => String(url) === LIVE_ACTIVATION_ENABLE_PATH)).toBe(false);
      cleanup();
    }
  });

  it("keeps the OFF safety request available after a failed status read", async () => {
    const fetcher = fetchRouter({ status: () => response({ error: { code: "EVIDENCE_UNAVAILABLE" } }, 503) });
    render(<LiveActivationView fetcher={fetcher} />);
    fireEvent.change(screen.getByLabelText("Account ID"), { target: { value: accountId } });
    const disable = screen.getByRole("button", { name: "Disable LIVE" });
    expect((disable as HTMLButtonElement).disabled).toBe(false);
    fireEvent.click(disable);
    await waitFor(() => expect(fetcher.mock.calls.some(([url]) => String(url) === LIVE_ACTIVATION_DISABLE_PATH)).toBe(true));
    expect(JSON.parse(String(fetcher.mock.calls.find(([url]) => String(url) === LIVE_ACTIVATION_DISABLE_PATH)?.[1]?.body))).toEqual({ account_id: accountId });
  });

  it("uses a synchronous action lock and never sends a second enable request", async () => {
    let finishEnable!: (value: Response) => void;
    const pendingEnable = new Promise<Response>((resolve) => { finishEnable = resolve; });
    const fetcher = fetchRouter({ enable: () => pendingEnable });
    render(<LiveActivationView fetcher={fetcher} />);
    await enterAccount();
    fireEvent.change(screen.getByLabelText("Confirmation phrase"), { target: { value: `ENABLE LIVE ${accountId}` } });
    const enable = screen.getByRole("button", { name: "Enable LIVE" });
    fireEvent.click(enable);
    fireEvent.click(enable);
    await waitFor(() => expect(fetcher.mock.calls.filter(([url]) => String(url) === LIVE_ACTIVATION_ENABLE_PATH)).toHaveLength(1));
    finishEnable(response({ accepted: true, effective_state: "LIVE", activation_revision: 2 }));
    await screen.findByText(/Enable request accepted by the API/);
  });
});
