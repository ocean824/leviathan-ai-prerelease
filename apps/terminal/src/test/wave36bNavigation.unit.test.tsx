import { render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import App from "../App";
import { REGISTRY, resolveHash, TAB_ENTRIES } from "../navigation/registry";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("Wave 36B LIVE navigation", () => {
  it("keeps one LIVE tab and its deep link in the existing registry position", () => {
    const liveEntries = REGISTRY.filter(({ code }) => code === "LIVE");
    expect(liveEntries).toHaveLength(1);
    expect(liveEntries[0]).toMatchObject({ code: "LIVE", label: "Live Trading", kind: "tab" });
    expect(TAB_ENTRIES.filter(({ code }) => code === "LIVE")).toHaveLength(1);
    expect(REGISTRY.findIndex(({ code }) => code === "LIVE")).toBe(12);
    expect(resolveHash("#live")).toEqual({ code: "LIVE" });
  });

  it("composes LIVE activation before the existing credential view without extra requests", async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(new Response("{}", { status: 503 }));
    vi.stubGlobal("fetch", fetcher);
    window.history.replaceState({}, "", "/#LIVE");

    render(<App />);

    const workspace = screen.getByRole("tabpanel", { name: "LIVE Live Trading" });
    const activation = await within(workspace).findByRole("region", { name: "Live account activation" });
    const credentials = await within(workspace).findByRole("region", { name: "Credential status" });
    expect(activation.compareDocumentPosition(credentials) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect((within(activation).getByRole("button", { name: "Enable LIVE" }) as HTMLButtonElement).disabled)
      .toBe(true);
    expect(within(activation).getByText("UNKNOWN").parentElement?.textContent)
      .toBe("LIVE status: UNKNOWN");
    expect(within(workspace).getByRole("heading", { name: "Live Trading", level: 2 })).toBeTruthy();
    expect(screen.getByRole("tab", { name: /^LIVE Live Trading$/ })).toBeTruthy();

    await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(2));
    expect(fetcher.mock.calls.map(([input]) => String(input)).sort()).toEqual([
      "/api/live-activation/status",
      "/api/live-trading/credentials",
    ]);
  });
});
