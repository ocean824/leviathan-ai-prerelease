import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import App from "../App";
import { parseCommand } from "../navigation/commands";
import { REGISTRY, resolveHash, TAB_ENTRIES } from "../navigation/registry";

describe("Wave 26 navigation registration", () => {
  it("adds KNOW and LGD while retaining existing navigation codes and one OMON", () => {
    const codes = REGISTRY.map(({ code }) => code);
    expect(new Set(codes).size).toBe(codes.length);
    expect(codes).toEqual(expect.arrayContaining([
      "CC", "INTEL", "QR", "GP", "HP", "OMON", "CURV", "FXC", "WEI", "JRNL",
      "RISK", "GENOME", "LIVE", "PIPE", "HELP", "TODAY", "SYMBOL", "STRATEGY",
      "KNOW", "LGD",
    ]));
    expect(REGISTRY.filter(({ code }) => code === "OMON")).toHaveLength(1);
    expect(TAB_ENTRIES.map(({ code }) => code)).toEqual(expect.arrayContaining(["KNOW", "LGD", "OMON", "LIVE"]));
    expect(REGISTRY.find(({ code }) => code === "KNOW")?.label).toBe("Knowledge Archive");
    expect(REGISTRY.find(({ code }) => code === "LGD")?.label).toBe("Live Guard");
  });

  it("exposes read-only and disabled reasons through the existing help registry data", () => {
    expect(REGISTRY.find(({ code }) => code === "KNOW")?.description).toMatch(/read-only/i);
    expect(REGISTRY.find(({ code }) => code === "KNOW")?.description).toMatch(/content is not displayed/i);
    expect(REGISTRY.find(({ code }) => code === "LGD")?.description).toContain(
      "operator switch and risk limits required",
    );
    expect(REGISTRY.find(({ code }) => code === "OMON")?.description).toMatch(/execution disabled/i);
  });

  it("renders the registered safety descriptions in Help", () => {
    window.history.replaceState({}, "", "/#HELP");
    render(<App />);

    expect(screen.getByText("Read-only archived metadata; archived content is not displayed")).toBeTruthy();
    expect(screen.getByText("LIVE remains disabled; operator switch and risk limits required")).toBeTruthy();
    expect(screen.getByText("Read-only order visibility; execution disabled")).toBeTruthy();
  });

  it.each(["KNOW", "LGD", "OMON"])("resolves %s through hashes and command forms", (code) => {
    expect(resolveHash(`#${code.toLowerCase()}`)).toEqual({ code });
    expect(parseCommand(code.toLowerCase())).toEqual({ type: "navigate", code });
    expect(parseCommand(`/tab ${code.toLowerCase()}`)).toEqual({ type: "navigate", code });
  });

  it("keeps invalid hash behavior on Help", () => {
    expect(resolveHash("#NOT-A-CODE")).toEqual({
      code: "HELP",
      reason: "Invalid hash #NOT-A-CODE. Showing command directory.",
    });
    expect(resolveHash("#%E0%A4%A")).toEqual({
      code: "HELP",
      reason: "Invalid hash encoding. Showing command directory.",
    });
  });

  it.each([
    ["KNOW", "Knowledge Archive"],
    ["LGD", "Live Guard"],
    ["OMON", "Order Monitor"],
  ])("mounts the registered %s view", async (code, label) => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: false,
      status: 503,
      statusText: "Service Unavailable",
      json: async () => ({ detail: "Unavailable" }),
    } as Response);
    window.history.replaceState({}, "", `/#${code}`);

    render(<App />);

    expect(await screen.findByRole("heading", { name: label })).toBeTruthy();
    expect(screen.getByRole("tab", { name: new RegExp(`^${code} ${label}$`) })).toBeTruthy();
  });
});
