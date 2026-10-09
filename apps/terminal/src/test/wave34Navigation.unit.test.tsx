import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import App from "../App";
import { parseCommand } from "../navigation/commands";
import { REGISTRY, resolveHash, TAB_ENTRIES } from "../navigation/registry";

const wave34Routes = [
  { code: "DATA", label: "Data Sources", heading: "Data sources" },
    { code: "CHRT", label: "Charts", heading: "Market chart" },
  { code: "PORD", label: "Paper Order Ticket", heading: "Paper Order Ticket" },
] as const;

function setHash(code: string): void {
  window.history.replaceState({}, "", `/#${code}`);
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("Wave 34 navigation routes", () => {
  it("registers exactly the three role-neutral tabs with unique codes and deep links", () => {
    const allCodes = REGISTRY.map(({ code }) => code);
    expect(new Set(allCodes).size).toBe(allCodes.length);

    for (const route of wave34Routes) {
      const matches = REGISTRY.filter(({ code }) => code === route.code);
      expect(matches).toHaveLength(1);
      expect(matches[0]).toMatchObject({ code: route.code, label: route.label, kind: "tab" });
      expect("role" in matches[0]!).toBe(false);
      expect(TAB_ENTRIES.filter(({ code }) => code === route.code)).toHaveLength(1);
      expect(resolveHash(`#${route.code.toLowerCase()}`).code).toBe(route.code);
      expect(parseCommand(`/tab ${route.code.toLowerCase()}`)).toEqual({ type: "navigate", code: route.code });
    }

    expect(REGISTRY.filter(({ code, label }) => String(code) === "CONN" || String(label) === "Connections")).toHaveLength(1);
  });

  it.each(wave34Routes)("renders $code by tab and its direct deep link", async ({ code, heading }) => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(new Response("{}", { status: 503 }));
    vi.stubGlobal("fetch", fetcher);
    setHash("HELP");
    render(<App />);

    fireEvent.click(screen.getByRole("tab", { name: new RegExp(`^${code}\\b`) }));
    const workspace = screen.getByRole("tabpanel");
    expect(await within(workspace).findByText(heading)).toBeTruthy();
    expect(resolveHash(window.location.hash).code).toBe(code);

    setHash(code.toLowerCase());
    window.dispatchEvent(new HashChangeEvent("hashchange"));
    await waitFor(() => expect(screen.getByRole("tabpanel").getAttribute("aria-label")).toBe(`${code} workspace`));
    expect(await within(screen.getByRole("tabpanel")).findByText(heading)).toBeTruthy();

    if (code === "DATA") {
      expect(fetcher).toHaveBeenCalledWith("/api/data-sources", expect.anything());
    } else {
      expect(fetcher).not.toHaveBeenCalled();
    }
  });

  it("keeps the charts surface explicitly unavailable without inventing market values", () => {
    setHash("CHRT");
    render(<App />);

    const workspace = screen.getByRole("tabpanel");
    expect(within(workspace).getAllByRole("status").some((node) => /chart snapshot is unavailable/i.test(node.textContent ?? ""))).toBe(true);
    expect(within(workspace).queryByLabelText(/depth heatmap|order-flow footprint/i)).toBeNull();
    expect(within(workspace).queryByText(/\b(?:bid|ask)\s+\d|\b\d+\.\d+\b/i)).toBeNull();
  });

  it("fails closed on the paper ticket because no active-scope read is available", () => {
    const fetcher = vi.fn<typeof fetch>();
    vi.stubGlobal("fetch", fetcher);
    setHash("PORD");
    render(<App />);

    const workspace = screen.getByRole("tabpanel");
    expect(within(workspace).getByRole("heading", { name: "Paper Order Ticket", level: 2 })).toBeTruthy();
    expect(within(workspace).getByRole("status").textContent).toMatch(/does not expose a current scope read/i);
    expect(within(workspace).queryByRole("form")).toBeNull();
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("falls back to Help for an unknown route", () => {
    setHash("UNKNOWN");
    render(<App />);
    expect(resolveHash("#UNKNOWN").code).toBe("HELP");
    expect(screen.getByRole("heading", { name: "Function directory", level: 2 })).toBeTruthy();
  });
});
