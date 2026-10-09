import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import App from "../App";
import { parseCommand } from "../navigation/commands";
import { REGISTRY, resolveHash, TAB_ENTRIES } from "../navigation/registry";

vi.mock("../wave34/connections/api", () => ({
  createConnectionsApi: vi.fn(() => ({
      getCatalog: vi.fn().mockResolvedValue({ ok: false, error: "CONNECTIONS_UNAVAILABLE" }),
      getStatus: vi.fn().mockResolvedValue({ ok: false, error: "CONNECTIONS_UNAVAILABLE" }),
      connect: vi.fn(),
      cancel: vi.fn(),
      disconnect: vi.fn(),
    })),
}));

const wave36Routes = [
  { code: "CONN", label: "Connections", heading: "Connections" },
  { code: "APPR", label: "Appearance", heading: "Appearance" },
  { code: "CHAT", label: "Chat", heading: "Assistant terminal" },
] as const;

function setHash(code: string): void {
  window.history.replaceState({}, "", `/#${code}`);
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("Wave 36 navigation routes", () => {
  it("registers exactly three unique role-neutral tabs with command and deep-link support", () => {
    const allCodes = REGISTRY.map(({ code }) => code);
    expect(new Set(allCodes).size).toBe(allCodes.length);

    for (const route of wave36Routes) {
      const matches = REGISTRY.filter(({ code }) => code === route.code);
      expect(matches).toHaveLength(1);
      expect(matches[0]).toMatchObject({ code: route.code, label: route.label, kind: "tab" });
      expect("role" in matches[0]!).toBe(false);
      expect(TAB_ENTRIES.filter(({ code }) => code === route.code)).toHaveLength(1);
      expect(resolveHash(`#${route.code.toLowerCase()}`).code).toBe(route.code);
      expect(parseCommand(`/tab ${route.code.toLowerCase()}`)).toEqual({ type: "navigate", code: route.code });
    }
  });

  it.each(wave36Routes)("renders $code by tab and direct deep link", async ({ code, heading }) => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(new Response("{}", { status: 503 }));
    vi.stubGlobal("fetch", fetcher);
    setHash("HELP");
    render(<App />);

    fireEvent.click(screen.getByRole("tab", { name: new RegExp(`^${code}\\b`) }));
    let workspace = screen.getByRole("tabpanel");
    expect(await within(workspace).findByRole("heading", { name: heading })).toBeTruthy();
    expect(resolveHash(window.location.hash).code).toBe(code);

    setHash(code.toLowerCase());
    window.dispatchEvent(new HashChangeEvent("hashchange"));
    await waitFor(() => expect(screen.getByRole("tabpanel").getAttribute("aria-label")).toBe(`${code} workspace`));
    workspace = screen.getByRole("tabpanel");
    expect(await within(workspace).findByRole("heading", { name: heading })).toBeTruthy();

    if (code === "APPR") {
      await waitFor(() => expect(fetcher).toHaveBeenCalledWith(
        "/api/preferences/appearance",
        expect.objectContaining({ method: "GET", credentials: "same-origin" }),
      ));
    }
    if (code === "CHAT") {
      expect(within(workspace).getByText("Authentication unavailable")).toBeTruthy();
      expect(within(workspace).getByText(/history and models are not loaded/i)).toBeTruthy();
      expect(fetcher).not.toHaveBeenCalled();
    }
    if (code === "CONN") {
      expect(within(workspace).getByText(/connection service unavailable/i)).toBeTruthy();
      expect(fetcher).not.toHaveBeenCalled();
    }
  });

  it("keeps the appearance offline label explicit when the account preference API is unavailable", async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(new Response("{}", { status: 503 }));
    vi.stubGlobal("fetch", fetcher);
    setHash("APPR");
    render(<App />);

    expect(await screen.findByRole("heading", { name: "Appearance", level: 1 })).toBeTruthy();
    await waitFor(() => expect(screen.getByText(/default appearance; account preferences are unavailable|local cache only/i)).toBeTruthy());
  });

  it("preserves Help fallback for unknown routes", () => {
    setHash("UNKNOWN");
    render(<App />);
    expect(resolveHash("#UNKNOWN").code).toBe("HELP");
    expect(screen.getByRole("heading", { name: "Function directory", level: 2 })).toBeTruthy();
  });
});
