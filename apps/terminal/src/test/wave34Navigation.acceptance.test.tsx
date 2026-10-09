import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import App from "../App";
import { REGISTRY, resolveHash, TAB_ENTRIES } from "../navigation/registry";

const addedRoutes = [
  { code: "DATA", label: "Data Sources", heading: "Data sources" },
  { code: "CHRT", label: "Charts", heading: "Market chart" },
  { code: "PORD", label: "Paper Order Ticket", heading: "Paper Order Ticket" },
] as const;

function navigateTo(hash: string): void {
  window.history.replaceState({}, "", `/${hash}`);
  window.dispatchEvent(new HashChangeEvent("hashchange"));
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  window.history.replaceState({}, "", "/");
});

describe("NAV-WAVE34A-001 independent acceptance", () => {
  it("adds exactly DATA, CHRT and PORD as unique role-neutral tabs", () => {
    const codes = REGISTRY.map(({ code }) => code);
    expect(new Set(codes).size).toBe(codes.length);

    for (const route of addedRoutes) {
      const matches = REGISTRY.filter(({ code }) => code === route.code);
      expect(matches).toHaveLength(1);
      expect(matches[0]).toMatchObject({ code: route.code, label: route.label, kind: "tab" });
      expect("role" in matches[0]!).toBe(false);
      expect(TAB_ENTRIES.filter(({ code }) => code === route.code)).toHaveLength(1);
      expect(resolveHash(`#${route.code.toLowerCase()}`).code).toBe(route.code);
    }

    expect(REGISTRY.filter(({ code }) => code === "CONN")).toHaveLength(1);
  });

  it.each(addedRoutes)("renders $code from its deep link and tab", async ({ code, heading }) => {
    const fetchRecorder = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(JSON.stringify({ sources: [] }), { status: 200 }),
    );
    vi.stubGlobal("fetch", fetchRecorder);
    navigateTo(`#${code.toLowerCase()}`);
    render(<App />);

    const panel = screen.getByRole("tabpanel");
    expect(panel.getAttribute("aria-label")).toBe(`${code} workspace`);
    if (code === "CHRT") {
      expect(await within(panel).findByText(heading)).toBeTruthy();
    } else {
      expect(await within(panel).findByRole("heading", { name: heading, level: 2 })).toBeTruthy();
    }
    expect(resolveHash(window.location.hash).code).toBe(code);

    fireEvent.click(screen.getByRole("tab", { name: new RegExp(`^${code}\\b`) }));
    if (code === "CHRT") {
      expect(await within(screen.getByRole("tabpanel")).findByText(heading)).toBeTruthy();
    } else {
      expect(await within(screen.getByRole("tabpanel"))
        .findByRole("heading", { name: heading, level: 2 })).toBeTruthy();
    }
    if (code === "DATA") {
      await waitFor(() => expect(fetchRecorder).toHaveBeenCalledTimes(1));
      expect(fetchRecorder).toHaveBeenCalledWith("/api/data-sources", expect.anything());
    } else {
      expect(fetchRecorder).not.toHaveBeenCalled();
    }
  });

  it("does not fetch while rendering the chart or fail-closed ticket surfaces", async () => {
    const fetchRecorder = vi.fn<typeof fetch>();
    vi.stubGlobal("fetch", fetchRecorder);

    for (const code of ["CHRT", "PORD"] as const) {
      navigateTo(`#${code}`);
      const { unmount } = render(<App />);
      expect(screen.getByRole("tabpanel").getAttribute("aria-label")).toBe(`${code} workspace`);
      await Promise.resolve();
      expect(fetchRecorder).not.toHaveBeenCalled();
      unmount();
    }
  });

  it("keeps Charts unavailable without manufacturing NBBO depth", async () => {
    navigateTo("#CHRT");
    render(<App />);
    const panel = screen.getByRole("tabpanel");
    expect(panel.getAttribute("aria-label")).toBe("CHRT workspace");

    expect(await within(panel).findByText("Market chart")).toBeTruthy();
    expect(within(panel).getAllByText(/chart snapshot is unavailable/i).length).toBeGreaterThan(0);
    expect(within(panel).getByText("Unavailable")).toBeTruthy();
    expect(within(panel).queryByLabelText(/depth heatmap|order-flow footprint|depth ladder/i)).toBeNull();
    expect(within(panel).queryByText(/NBBO only/i)).toBeNull();
    expect(within(panel).queryByText(/\b(?:bid|ask)\s+\d|\b\d+\.\d+\b/i)).toBeNull();
  });

  it("never derives ticket trust or scope from URL parameters and leaves dispatch unavailable", () => {
    const fetchRecorder = vi.fn<typeof fetch>();
    vi.stubGlobal("fetch", fetchRecorder);
    window.history.replaceState(
      {},
      "",
      "/?trustedOperator=true&activePaperScope=%7B%22active%22%3Atrue%7D&instrument=FAKE#PORD",
    );
    render(<App />);

    const panel = screen.getByRole("tabpanel");
    expect(panel.getAttribute("aria-label")).toBe("PORD workspace");
    expect(within(panel).getByRole("heading", { name: "Paper Order Ticket", level: 2 })).toBeTruthy();
    expect(within(panel).getByRole("status").textContent).toMatch(/does not expose a current scope read/i);
    expect(within(panel).queryByRole("form")).toBeNull();
    expect(within(panel).queryByRole("button", { name: /preview|submit|place|create/i })).toBeNull();
    expect(fetchRecorder).not.toHaveBeenCalled();
  });

  it("preserves the Help fallback for unknown deep links", () => {
    navigateTo("#UNKNOWN-WAVE34-CODE");
    render(<App />);

    expect(resolveHash("#UNKNOWN-WAVE34-CODE").code).toBe("HELP");
    expect(screen.getByRole("tab", { name: /^HELP\b/ }).getAttribute("aria-selected")).toBe("true");
    expect(screen.getByRole("heading", { name: "Function directory", level: 2 })).toBeTruthy();
    expect(screen.getByText(/invalid hash/i)).toBeTruthy();
  });
});
