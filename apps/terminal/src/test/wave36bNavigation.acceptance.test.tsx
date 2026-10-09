import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import App from "../App";
import { REGISTRY, resolveHash } from "../navigation/registry";

type RecordedCall = { url: string; method: string };

function setHash(hash: string) {
  window.history.replaceState({}, "", `/${hash}`);
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  window.history.replaceState({}, "", "/");
});

describe("NAV-WAVE36B-001 independent acceptance", () => {
  it("keeps exactly one LIVE / Live Trading tab in its established registry position", () => {
    const entries = REGISTRY.filter(({ code }) => code === "LIVE");
    expect(entries).toHaveLength(1);
    expect(entries[0]).toMatchObject({ code: "LIVE", label: "Live Trading", kind: "tab" });
    expect(REGISTRY.findIndex(({ code }) => code === "LIVE")).toBe(12);
    expect(resolveHash("#LIVE").code).toBe("LIVE");
  });

  it("deep-links LIVE to activation plus existing configurations with only their status reads", async () => {
    const calls: RecordedCall[] = [];
    const fetcher = vi.fn<typeof fetch>(async (input, init) => {
      calls.push({ url: String(input), method: init?.method ?? "GET" });
      return new Response(JSON.stringify({ error: { code: "DEPENDENCY_UNAVAILABLE" } }), {
        status: 503,
        headers: { "Content-Type": "application/json" },
      });
    });
    vi.stubGlobal("fetch", fetcher);
    setHash("#LIVE");
    render(<App />);

    const workspace = await screen.findByRole("tabpanel", { name: "LIVE Live Trading" });
    expect(within(workspace).getByRole("heading", { name: "LIVE Account Activation" })).toBeTruthy();
    expect(within(workspace).getByRole("heading", { name: "Live Trading" })).toBeTruthy();
    expect(within(workspace).getByText(/LIVE activation starts OFF after every application restart/i)).toBeTruthy();
    expect((within(workspace).getByRole("button", { name: "Enable LIVE" }) as HTMLButtonElement).disabled).toBe(true);
    expect(resolveHash(window.location.hash).code).toBe("LIVE");

    await waitFor(() => expect(calls).toHaveLength(2));
    expect(calls.every(({ method }) => method.toUpperCase() === "GET")).toBe(true);
    expect(calls.map(({ url }) => url).sort()).toEqual([
      "/api/live-activation/status",
      "/api/live-trading/credentials",
    ].sort());
    expect(fetcher).toHaveBeenCalledTimes(2);
  });
});
