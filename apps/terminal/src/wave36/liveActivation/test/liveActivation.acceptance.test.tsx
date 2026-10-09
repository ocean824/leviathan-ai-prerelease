import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  LIVE_ACTIVATION_DISABLE_PATH,
  LIVE_ACTIVATION_ENABLE_PATH,
  LIVE_ACTIVATION_STATUS_PATH,
} from "../api";
import { LiveActivationView } from "../LiveActivationView";

const accountId = "acct-main";

function status(overrides: Record<string, unknown> = {}) {
  return {
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
  };
}

function json(body: unknown, statusCode = 200): Response {
  return new Response(JSON.stringify(body), {
    status: statusCode,
    headers: { "Content-Type": "application/json" },
  });
}

function fakeFetch(statusResponse: () => Response = () => json(status({ account_id: null, verified: false, preconditions_verified: false, blockers: ["ACCOUNT_NOT_SELECTED"] }))) {
  return vi.fn(async (input: RequestInfo | URL, _init?: RequestInit) => {
    const url = String(input);
    if (url.startsWith(LIVE_ACTIVATION_STATUS_PATH)) return statusResponse();
    if (url === LIVE_ACTIVATION_ENABLE_PATH) {
      return json({ accepted: true, effective_state: "LIVE", activation_revision: 2 });
    }
    if (url === LIVE_ACTIVATION_DISABLE_PATH) {
      return json({ accepted: true, effective_state: "OFF", activation_revision: 3 });
    }
    throw new Error(`Unexpected network route: ${url}`);
  }) as unknown as typeof fetch & ReturnType<typeof vi.fn>;
}

afterEach(cleanup);

describe("LIVE activation independent UI acceptance", () => {
  it("renders startup as OFF and treats absent trusted status as unknown, never LIVE", async () => {
    const fetcher = fakeFetch();
    render(<LiveActivationView fetcher={fetcher} />);

    expect(await screen.findByText(/LIVE state is OFF at startup/)).toBeTruthy();
    expect(screen.getByText("OFF")).toBeTruthy();
    expect(screen.queryByText("LIVE (verified)")).toBeNull();
    expect(screen.queryByText(/API-reported LIVE; verified/)).toBeNull();
    expect(fetcher.mock.calls.every(([url]) => String(url).startsWith(LIVE_ACTIVATION_STATUS_PATH))).toBe(true);
  });

  it("never presents a client-visible LIVE claim without verified preconditions", async () => {
    const fetcher = fakeFetch(() => json(status({
      effective_state: "LIVE",
      verified: false,
      preconditions_verified: false,
      blockers: ["HALT_ACTIVE"],
    })));
    render(<LiveActivationView fetcher={fetcher} />);

    // Strict status parsing must fail closed rather than upgrade the unverified claim.
    expect(await screen.findByText(/API response could not be verified/)).toBeTruthy();
    expect(screen.queryByText("LIVE (verified)")).toBeNull();
    expect(screen.queryByText("API-reported LIVE; verified for this session.")).toBeNull();
    expect(screen.getByText("UNKNOWN")).toBeTruthy();
  });

  it("does not send enable when status is unverified even with the exact confirmation phrase", async () => {
    const fetcher = fakeFetch(() => json(status({
      effective_state: "LIVE",
      verified: false,
      preconditions_verified: false,
      blockers: ["HALT_ACTIVE"],
    })));
    render(<LiveActivationView fetcher={fetcher} />);
    fireEvent.change(screen.getByLabelText("Account ID"), { target: { value: accountId } });
    await waitFor(() => expect((screen.getByRole("button", { name: "Refresh status" }) as HTMLButtonElement).disabled).toBe(false));
    fireEvent.click(screen.getByRole("button", { name: "Refresh status" }));
    await waitFor(() => expect(fetcher.mock.calls.filter(([url]) => String(url).startsWith(LIVE_ACTIVATION_STATUS_PATH)).length).toBeGreaterThanOrEqual(2));
    fireEvent.change(screen.getByLabelText("Confirmation phrase"), {
      target: { value: `ENABLE LIVE ${accountId}` },
    });

    expect((screen.getByRole("button", { name: "Enable LIVE" }) as HTMLButtonElement).disabled).toBe(true);
    expect(fetcher.mock.calls.some(([url]) => String(url) === LIVE_ACTIVATION_ENABLE_PATH)).toBe(false);
  });

  it("offers one-call OFF and states that OFF does not cancel or flatten orders", async () => {
    const fetcher = fakeFetch(() => json(status({ account_id: null, verified: false, preconditions_verified: false, blockers: ["ACCOUNT_NOT_SELECTED"] })));
    render(<LiveActivationView fetcher={fetcher} />);

    fireEvent.change(screen.getByLabelText("Account ID"), { target: { value: accountId } });
    const disable = screen.getByRole("button", { name: "Disable LIVE" });
    expect((disable as HTMLButtonElement).disabled).toBe(false);
    expect(screen.getByText(/does not cancel or flatten existing orders/i)).toBeTruthy();
    fireEvent.click(disable);
    await waitFor(() => expect(fetcher.mock.calls.some(([url]) => String(url) === LIVE_ACTIVATION_DISABLE_PATH)).toBe(true));
    const offCall = fetcher.mock.calls.find(([url]) => String(url) === LIVE_ACTIVATION_DISABLE_PATH);
    expect(offCall?.[1]).toMatchObject({ method: "POST", credentials: "same-origin", cache: "no-store" });
    expect(JSON.parse(String(offCall?.[1]?.body))).toEqual({ account_id: accountId });
    expect(fetcher.mock.calls.filter(([url]) => String(url) === LIVE_ACTIVATION_DISABLE_PATH)).toHaveLength(1);
  });

  it("renders verified open LIVE orders separately from activation and states OFF does not cancel them", async () => {
    const order = {
      order_id: "order-1",
      instrument_id: "AAPL",
      side: "BUY",
      quantity: "1.250",
      status: "WORKING",
      verified_at_ns: 1_800_000_000_000_000_000,
    };
    const fetcher = fakeFetch(() => json(status({
      open_orders_state: "VERIFIED",
      open_orders: [order],
    })));
    render(<LiveActivationView fetcher={fetcher} />);
    fireEvent.change(screen.getByLabelText("Account ID"), { target: { value: accountId } });
    await waitFor(() => expect((screen.getByRole("button", { name: "Refresh status" }) as HTMLButtonElement).disabled).toBe(false));
    fireEvent.click(screen.getByRole("button", { name: "Refresh status" }));

    expect(await screen.findByText("order-1")).toBeTruthy();
    expect(screen.getByText("1.250")).toBeTruthy();
    expect(screen.getByText(/Disabling LIVE does not cancel or flatten these orders/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: /cancel|flatten/i })).toBeNull();
    expect(fetcher.mock.calls.map(([url]) => String(url)).every((url) =>
      url.startsWith(LIVE_ACTIVATION_STATUS_PATH),
    )).toBe(true);
  });

  it("labels an unavailable open-order snapshot without inventing an empty result", async () => {
    const fetcher = fakeFetch(() => json(status({ open_orders_state: "UNAVAILABLE" })));
    render(<LiveActivationView fetcher={fetcher} />);
    fireEvent.change(screen.getByLabelText("Account ID"), { target: { value: accountId } });
    await waitFor(() => expect((screen.getByRole("button", { name: "Refresh status" }) as HTMLButtonElement).disabled).toBe(false));
    fireEvent.click(screen.getByRole("button", { name: "Refresh status" }));

    expect(await screen.findByText("Open orders are unknown or unavailable.")).toBeTruthy();
    expect(screen.queryByText("No non-terminal LIVE orders were reported.")).toBeNull();
  });

  it("uses no network routes outside status, enable, and disable", async () => {
    const fetcher = fakeFetch();
    render(<LiveActivationView fetcher={fetcher} />);
    await screen.findByText(/LIVE state is OFF at startup/);
    expect(fetcher.mock.calls.map(([url]) => String(url)).every((url) =>
      url.startsWith(LIVE_ACTIVATION_STATUS_PATH) ||
      url === LIVE_ACTIVATION_ENABLE_PATH ||
      url === LIVE_ACTIVATION_DISABLE_PATH,
    )).toBe(true);
  });
});
