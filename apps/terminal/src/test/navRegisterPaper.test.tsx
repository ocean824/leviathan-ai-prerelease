import { afterEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import App from "../App";
import { parseCommand } from "../navigation/commands";
import { REGISTRY, resolveHash, TAB_ENTRIES } from "../navigation/registry";
import { PAPER_ORDER_STATUS_PATH, PAPER_RISK_STATUS_PATH } from "../wave27/api/paperActivation";

function setHash(hash: string) {
  window.history.replaceState({}, "", `/${hash}`);
}

afterEach(() => vi.restoreAllMocks());

describe("NAV-REGISTER-PAPER-001", () => {
  it("registers the integrated views and keeps PAPER activation hidden until integration", () => {
    expect(REGISTRY).toEqual(expect.arrayContaining([
      expect.objectContaining({ code: "PACT", label: "Paper Activity", kind: "tab" }),
      expect.objectContaining({ code: "PAPR", label: "Paper Activation", kind: "tab" }),
      expect.objectContaining({ code: "EAC", label: "EA Template Catalog", kind: "tab" }),
      expect.objectContaining({ code: "FLR", label: "Flash-loan Routes (read-only)", kind: "tab" }),
    ]));
    expect(TAB_ENTRIES.filter(({ code }) => code === "PAPR")).toHaveLength(1);
    expect(parseCommand("PAPR")).toEqual({ type: "navigate", code: "PAPR" });
    expect(parseCommand("/tab PAPR")).toEqual({ type: "navigate", code: "PAPR" });
    expect(resolveHash("#PAPR").code).toBe("PAPR");
  });

  it.each([
    ["PACT", "Paper Activity"],
    ["PAPR", "Paper Activation"],
    ["EAC", "EA Templates"],
    ["FLR", "Flash-loan routes"],
  ])("routes %s to its view", async (code, heading) => {
    const fetcher = vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: false,
      status: 503,
      statusText: "Service Unavailable",
      json: async () => ({ detail: "Unavailable" }),
      text: async () => "Unavailable",
    } as Response);
    setHash(`#${code}`);
    render(<App />);
    expect(await screen.findByRole("heading", { name: heading, level: 2 })).toBeTruthy();
    if (code === "PAPR") {
      await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(2));
      expect(fetcher.mock.calls.map(([input, init]) => [String(input), init?.method ?? "GET"]).sort())
        .toEqual([[PAPER_ORDER_STATUS_PATH, "GET"], [PAPER_RISK_STATUS_PATH, "GET"]].sort());
      expect((screen.getByRole("button", { name: "LIVE environment disabled" }) as HTMLButtonElement).disabled).toBe(true);
      expect((screen.getByRole("button", { name: "Activate" }) as HTMLButtonElement).disabled).toBe(true);
      expect(fetcher.mock.calls.every(([, init]) => init?.method !== "POST")).toBe(true);
    }
  });

  it("uses only the existing PACT and EAC GET endpoints", async () => {
    const fetcher = vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: false,
      status: 503,
      statusText: "Service Unavailable",
      json: async () => ({ detail: "Unavailable" }),
      text: async () => "Unavailable",
    } as Response);

    setHash("#PACT");
    const { unmount } = render(<App />);
    await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(3));
    const calls = fetcher.mock.calls.map(([input, init]) => [String(input), init?.method ?? "GET"]);
    expect(calls.sort()).toEqual([
      ["/api/orders/activity?limit=50", "GET"],
      ["/api/orders/status", "GET"],
      ["/api/risk/status", "GET"],
    ].sort());
    expect(fetcher.mock.calls.every(([, init]) => init?.body === undefined)).toBe(true);
    unmount();

    fetcher.mockClear();
    setHash("#EAC");
    render(<App />);
    await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(1));
    expect(fetcher.mock.calls[0]?.[0]).toBe("/api/v1/ea/templates");
    expect(fetcher.mock.calls[0]?.[1]?.method).toBe("GET");
    expect(fetcher.mock.calls[0]?.[1]?.body).toBeUndefined();
  });

  it("keeps FLR read-only, marks LIVE disabled, and adds no network call", async () => {
    const fetcher = vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("unexpected request"));
    setHash("#FLR");
    render(<App />);

    expect(await screen.findByRole("heading", { name: "Flash-loan routes", level: 2 })).toBeTruthy();
    expect(screen.getByRole("status", { name: "LIVE trading status: DISABLED" })).toBeTruthy();
    expect(screen.getByText("Read-only route display. LIVE remains disabled.")).toBeTruthy();
    expect(screen.getByText("No routes are available.")).toBeTruthy();
    expect(fetcher).not.toHaveBeenCalled();
    expect(screen.getByRole("tab", { name: /FLR Flash-loan Routes/ })).toBeTruthy();
  });

  it("supports bare-code and /tab command navigation for all integrated entries", () => {
    for (const code of ["PACT", "PAPR", "EAC", "FLR"] as const) {
      expect(parseCommand(code.toLowerCase())).toEqual({ type: "navigate", code });
      expect(parseCommand(`/tab ${code.toLowerCase()}`)).toEqual({ type: "navigate", code });
      expect(resolveHash(`#${code.toLowerCase()}`).code).toBe(code);
    }
  });
});
