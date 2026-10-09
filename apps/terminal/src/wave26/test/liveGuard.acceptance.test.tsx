import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { LiveGuardView } from "../views/LiveGuardView";
import {
  RAW_PAYLOAD_CANARY,
  NEAR_MISS_HALT_CODES,
  OMEGA_HALT_HASHES,
  OMEGA_HALT_PREFIXES,
  STATIC_HALT_CODES,
  malformedRiskStatus,
  ordersStatusClaimingLiveEnabled,
  ordersStatusWithGateCodes,
  ordersStatusWithUnknownRecovery,
  rawFailurePayload,
  riskStatusWithGateCodes,
  riskStatusWithUnknownGateCodes,
  riskStatusForHaltCodes,
} from "./fixtures/liveGuard";

type Reply = { risk: unknown; orders: unknown; status?: number };

function jsonResponse(body: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: status === 403 ? "Forbidden" : status >= 500 ? "Server Error" : "OK",
    json: async () => body,
  } as Response;
}

function installFetch(reply: Reply) {
  const fetchMock = vi.fn((input: RequestInfo | URL, _init?: RequestInit) => {
    const path = String(input);
    const response = path === "/api/risk/status"
      ? jsonResponse(reply.risk, reply.status)
      : path === "/api/orders/status"
        ? jsonResponse(reply.orders, reply.status)
        : jsonResponse({ detail: "NOT_FOUND" }, 404);
    return Promise.resolve(response);
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

function expectLiveHardDisabled() {
  const visible = document.body.textContent ?? "";
  expect(visible).toContain("LIVE");
  expect(visible).toContain("DISABLED");
  expect(visible).toContain("operator switch and risk limits required");

  const activationWords = /\b(enable|arm|toggle|activate|go live|start live|turn on live)\b/i;
  const controls = document.querySelectorAll(
    "button,input,select,textarea,a,form,[role='button'],[role='switch'],[role='checkbox'],[role='radio']",
  );
  for (const control of controls) {
    const label = [
      control.textContent,
      control.getAttribute("aria-label"),
      control.getAttribute("title"),
      control.getAttribute("value"),
    ].filter(Boolean).join(" ");
    expect(label).not.toMatch(activationWords);
    if (/\blive\b/i.test(label)) {
      const disabled = control.matches(":disabled") || control.getAttribute("aria-disabled") === "true";
      expect(disabled).toBe(true);
    }
  }
  const buttons = [...document.querySelectorAll("button")];
  expect(controls.length).toBe(buttons.length);
  expect(buttons.every((button) => /retry/i.test(button.textContent ?? ""))).toBe(true);
}

function expectOnlySafeGetRequests(fetchMock: ReturnType<typeof installFetch>) {
  expect(fetchMock).toHaveBeenCalled();
  for (const [input, init] of fetchMock.mock.calls) {
    expect(["/api/risk/status", "/api/orders/status"]).toContain(String(input));
    expect((init?.method ?? "GET").toUpperCase()).toBe("GET");
    expect(init?.body).toBeUndefined();
  }
}

function expectNoGreenOrReadyClaim() {
  const visible = document.body.textContent ?? "";
  expect(visible).not.toMatch(/\b(green|ready|fresh|live enabled)\b/i);
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("LIVE-GUARD-UI-001 independent acceptance", () => {
  it("renders hard-disabled LIVE while both endpoints are still loading", () => {
    const fetchMock = vi.fn(() => new Promise<Response>(() => undefined));
    vi.stubGlobal("fetch", fetchMock);
    render(<LiveGuardView />);

    expectLiveHardDisabled();
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expectOnlySafeGetRequests(fetchMock as ReturnType<typeof installFetch>);
  });

  it("keeps LIVE disabled even when the API claims live_enabled=true and exposes no activation control", async () => {
    const fetchMock = installFetch({
      risk: riskStatusWithGateCodes,
      orders: ordersStatusClaimingLiveEnabled,
    });
    render(<LiveGuardView />);

    await waitFor(() => {
      expect(document.body.textContent).toContain("API REPORTED live_enabled TRUE");
      expect(document.body.textContent).toContain("Ignored: LIVE stays DISABLED in this view.");
    });
    expectLiveHardDisabled();
    expectOnlySafeGetRequests(fetchMock);
  });

  it("renders allowlisted gate reason codes without raw policy, path or payload text", async () => {
    const fetchMock = installFetch({
      risk: riskStatusWithGateCodes,
      orders: ordersStatusWithGateCodes,
    });
    render(<LiveGuardView />);

    await screen.findByText(/HALT_STORE_UNAVAILABLE/i);
    const visible = document.body.textContent ?? "";
    expect(visible.toLowerCase()).toContain("operator_hold");
    expect(visible.toLowerCase()).toContain("omega_kill_signal");
    expect(visible).toContain("FAILED");
    expect(visible).not.toContain(RAW_PAYLOAD_CANARY);
    expect(visible).not.toContain("C:/private/");
    expect(visible).not.toContain("17.25");
    expect(visible).not.toContain("23.75");
    expect(visible).not.toContain("0.91");
    expectOnlySafeGetRequests(fetchMock);
  });

  it("maps unrecognized halt, fault, recovery and mode strings to UNRECOGNIZED", async () => {
    const fetchMock = installFetch({
      risk: riskStatusWithUnknownGateCodes,
      orders: ordersStatusWithUnknownRecovery,
    });
    render(<LiveGuardView />);

    await waitFor(() => {
      expect(document.body.textContent).toContain("UNRECOGNIZED");
    });
    const visible = document.body.textContent ?? "";
    expect(visible).toContain("UNRECOGNIZED");
    expect(visible).not.toContain(RAW_PAYLOAD_CANARY);
    expect(visible).not.toContain("CODE_SHAPED_ATTACK");
    expect(visible).not.toContain("ATTACKER_SUPPLIED_FAULT");
    expect(visible).not.toContain("ATTACKER_SUPPLIED_RECOVERY");
    expect(visible).not.toContain("paper");
    expectOnlySafeGetRequests(fetchMock);
  });

  it("renders every backend static halt reason exactly as its canonical code", async () => {
    const fetchMock = installFetch({
      risk: riskStatusForHaltCodes(STATIC_HALT_CODES),
      orders: ordersStatusWithGateCodes,
    });
    render(<LiveGuardView />);

    await waitFor(() => expect(document.body.textContent).toContain("HALT INDICATED"));
    const visible = document.body.textContent ?? "";
    for (const code of STATIC_HALT_CODES) expect(visible).toContain(code);
    expect(visible).not.toContain("UNRECOGNIZED");
    expectLiveHardDisabled();
    expectOnlySafeGetRequests(fetchMock);
  });

  it("shows valid OMEGA halt keys as OMEGA_HALT without exposing their digests", async () => {
    const validOmegaKeys = OMEGA_HALT_PREFIXES.map((prefix, index) =>
      `${prefix}:${OMEGA_HALT_HASHES[index]}`);
    const fetchMock = installFetch({
      risk: riskStatusForHaltCodes(validOmegaKeys),
      orders: ordersStatusWithGateCodes,
    });
    render(<LiveGuardView />);

    await waitFor(() => expect(document.body.textContent).toContain("OMEGA_HALT"));
    const visible = document.body.textContent ?? "";
    expect(visible.match(/OMEGA_HALT/g)).toHaveLength(OMEGA_HALT_PREFIXES.length);
    for (const digest of OMEGA_HALT_HASHES) expect(visible).not.toContain(digest);
    expect(visible).toContain("HALT INDICATED");
    expectLiveHardDisabled();
    expectOnlySafeGetRequests(fetchMock);
  });

  it("maps near-miss OMEGA halt keys to UNRECOGNIZED", async () => {
    const fetchMock = installFetch({
      risk: riskStatusForHaltCodes(NEAR_MISS_HALT_CODES),
      orders: ordersStatusWithGateCodes,
    });
    render(<LiveGuardView />);

    await waitFor(() => expect(document.body.textContent).toContain("HALT INDICATED"));
    const visible = document.body.textContent ?? "";
    expect(visible.match(/UNRECOGNIZED/g)).toHaveLength(NEAR_MISS_HALT_CODES.length);
    expect(visible).not.toContain("OMEGA_HALT");
    for (const code of NEAR_MISS_HALT_CODES) expect(visible).not.toContain(code);
    expectLiveHardDisabled();
    expectOnlySafeGetRequests(fetchMock);
  });

  it("rejects an oversized halt list instead of showing a partial reason set", async () => {
    const fetchMock = installFetch({
      risk: { ...riskStatusWithGateCodes, active_halts: Array.from({ length: 51 }, () => "operator_hold") },
      orders: ordersStatusWithGateCodes,
    });
    render(<LiveGuardView />);

    await waitFor(() => {
      expect(document.body.textContent).toContain("MALFORMED_RESPONSE");
    });
    expect(document.body.textContent).not.toContain("operator_hold");
    expect(document.body.textContent).not.toContain(RAW_PAYLOAD_CANARY);
    expectLiveHardDisabled();
    expectNoGreenOrReadyClaim();
    expectOnlySafeGetRequests(fetchMock);
  });

  it("keeps receipt age separate from missing source time and marks PanelState unavailable", async () => {
    const fetchMock = installFetch({
      risk: riskStatusWithGateCodes,
      orders: ordersStatusWithGateCodes,
    });
    render(<LiveGuardView />);

    await waitFor(() => expect(document.body.textContent).toContain("Source as of"));
    const visible = document.body.textContent ?? "";
    expect(visible).toContain("Response received");
    expect(visible).toContain("Receipt expires");
    expect(visible).toMatch(/Source as of\s*Unavailable/i);
    expect(visible).toContain("no valid source timestamp");
    expect(screen.getByRole("region", { name: "Risk status: unverified API report" })).toBeTruthy();
    expect(screen.getByRole("region", { name: "Order gateway status: unverified API report" })).toBeTruthy();
    expect(screen.getAllByText("No valid source timestamp supplied.").length).toBe(4);
    expectNoGreenOrReadyClaim();
    expectOnlySafeGetRequests(fetchMock);
  });

  it.each([
    ["403 with a raw body", 403, rawFailurePayload],
    ["malformed success data", 200, malformedRiskStatus],
  ])("keeps %s non-green and renders no raw response payload", async (_label, status, badBody) => {
    const fetchMock = installFetch({ risk: badBody, orders: badBody, status });
    render(<LiveGuardView />);

    await waitFor(() => {
      const visible = document.body.textContent ?? "";
      expect(visible).toMatch(status === 403 ? /HTTP_403/i : /MALFORMED_RESPONSE/i);
    });
    expectLiveHardDisabled();
    expectNoGreenOrReadyClaim();
    expect(document.body.textContent ?? "").not.toContain(RAW_PAYLOAD_CANARY);
    expectOnlySafeGetRequests(fetchMock);
  });

  it("maps network failures to a reason code and Retry only repeats read-only GETs", async () => {
    const fetchMock = vi.fn().mockRejectedValue(new Error(`private ${RAW_PAYLOAD_CANARY}`));
    vi.stubGlobal("fetch", fetchMock);
    render(<LiveGuardView />);

    await waitFor(() => expect(document.body.textContent).toContain("NETWORK_ERROR"));
    expectLiveHardDisabled();
    expectNoGreenOrReadyClaim();
    expect(document.body.textContent ?? "").not.toContain(RAW_PAYLOAD_CANARY);
    const retry = screen.getAllByRole("button", { name: /retry/i });
    expect(retry.length).toBeGreaterThan(0);
    fireEvent.click(retry[0]!);
    await waitFor(() => expect(fetchMock.mock.calls.length).toBeGreaterThan(2));
    expectOnlySafeGetRequests(fetchMock as ReturnType<typeof installFetch>);
  });

  it("never treats an expired response receipt as source freshness", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-02T15:00:00.000Z"));
    const requests = new Map<string, number>();
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const path = String(input);
      const count = requests.get(path) ?? 0;
      requests.set(path, count + 1);
      if (count > 0) return new Promise<Response>(() => undefined);
      const data = path === "/api/risk/status"
        ? riskStatusWithGateCodes
        : ordersStatusWithGateCodes;
      return Promise.resolve(jsonResponse(data));
    });
    vi.stubGlobal("fetch", fetchMock);
    render(<LiveGuardView />);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(5_001);
    });

    const visible = document.body.textContent ?? "";
    expect(visible).toMatch(/DELAYED|UNAVAILABLE/i);
    expect(visible).toMatch(/Response receipt expired/i);
    expect(visible).not.toContain("operator_hold");
    expectNoGreenOrReadyClaim();
    expectLiveHardDisabled();
    expectOnlySafeGetRequests(fetchMock as ReturnType<typeof installFetch>);
  });

  it("hides gate reports for stale source timestamps and marks the panels delayed", async () => {
    vi.useFakeTimers();
    const now = new Date("2026-10-06T15:00:00.000Z").getTime();
    vi.setSystemTime(now);
    const fetchMock = installFetch({
      risk: { ...riskStatusWithGateCodes, as_of: now - 6_000 },
      orders: { ...ordersStatusWithGateCodes, as_of: now - 6_000 },
    });
    render(<LiveGuardView />);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    const visible = document.body.textContent ?? "";
    expect(visible).toContain("Source timestamp is outside the freshness window; values are hidden.");
    expect(visible).toContain("DELAYED");
    expect(visible).not.toContain("operator_hold");
    expect(visible).not.toContain("HALT_STORE_UNAVAILABLE");
    expect(visible).not.toContain("FAILED");
    expectLiveHardDisabled();
    expectNoGreenOrReadyClaim();
    expectOnlySafeGetRequests(fetchMock);
  });
});
