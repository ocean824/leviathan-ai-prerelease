import { fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import App from "../App";
import { parseCommand } from "../navigation/commands";
import { REGISTRY, resolveHash, VIEW_ENTRIES } from "../navigation/registry";

const c104Codes = [
  "CC",
  "INTEL",
  "QR",
  "GP",
  "HP",
  "OMON",
  "CURV",
  "FXC",
  "WEI",
  "JRNL",
  "RISK",
  "GENOME",
  "PIPE",
  "HELP",
  "TODAY",
  "SYMBOL",
  "STRATEGY",
];
const newCodes = ["KNOW", "LGD"];
const expectedCodes = [...c104Codes, "LIVE", ...newCodes, "PACT", "PAPR", "EAC", "FLR", "DATA", "CHRT", "PORD", "CONN", "APPR", "CHAT"];

function setHash(hash: string) {
  window.history.replaceState({}, "", `/${hash}`);
}

function workspaceName(code: string) {
  const entry = REGISTRY.find((candidate) => candidate.code === code);
  return entry?.kind === "tab" ? `${entry.code} ${entry.label}` : `${code} workspace`;
}

beforeEach(() => {
  vi.spyOn(globalThis, "fetch").mockResolvedValue({
    ok: false,
    status: 503,
    statusText: "Service Unavailable",
    json: async () => ({ detail: "Synthetic offline response" }),
    text: async () => JSON.stringify({ detail: "Synthetic offline response" }),
  } as Response);
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("UI-NAV-REGISTER-026 independent acceptance", () => {
  it("retains every C-104 and LIVE code and registers no Wave 27 views", () => {
    const codes = REGISTRY.map(({ code }) => code);
    expect(codes).toEqual(expect.arrayContaining(expectedCodes));
    expect(new Set(codes).size).toBe(codes.length);
    expect(codes.sort()).toEqual([...expectedCodes].sort());

    for (const code of expectedCodes) {
      expect(REGISTRY.filter((entry) => entry.code === code)).toHaveLength(1);
      expect(resolveHash(`#${code}`).code).toBe(code);
    }

    expect(VIEW_ENTRIES.map(({ code }) => code).sort()).toEqual([
      "STRATEGY",
      "SYMBOL",
      "TODAY",
    ]);
    expect(REGISTRY.some(({ code, label }) => /wave\s*27|paper activation|export catalog/i.test(`${code} ${label}`) && !(code === "PAPR" && label === "Paper Activation"))).toBe(false);
  });

  it("shows each registered code exactly once in the Help directory", () => {
    setHash("#HELP");
    render(<App />);

    const helpTab = screen.getByRole("tab", { name: /HELP/i });
    fireEvent.click(helpTab);
    const workspace = screen.getByRole("tabpanel");
    for (const code of expectedCodes) {
      expect(within(workspace).getAllByText(code, { exact: true })).toHaveLength(1);
    }
  });

  it.each([
    ["KNOW", "Knowledge Archive"],
    ["LGD", "Live Guard"],
    ["OMON", "Order Monitor"],
  ])("routes %s to its integrated view", async (code, heading) => {
    setHash(`#${code}`);
    render(<App />);

    const workspace = await screen.findByRole("tabpanel", { name: workspaceName(code) });
    expect(within(workspace).getByRole("heading", { name: heading, level: 2 })).toBeTruthy();
    expect(resolveHash(window.location.hash).code).toBe(code);
  });

  it.each(expectedCodes)("restores the existing %s code from its hash", async (code) => {
    setHash(`#${code}`);
    render(<App />);

    expect(await screen.findByRole("tabpanel", { name: workspaceName(code) })).toBeTruthy();
    expect(resolveHash(window.location.hash).code).toBe(code);
  });

  it("keeps the LIVE tab routed to the Live Trading configuration view", async () => {
    setHash("#LIVE");
    render(<App />);

    const workspace = await screen.findByRole("tabpanel", { name: workspaceName("LIVE") });
    expect(within(workspace).getByRole("heading", { name: /Live Trading/i })).toBeTruthy();
    expect(resolveHash(window.location.hash).code).toBe("LIVE");
  });

  it.each(newCodes)("supports bare-code and /tab command parsing for %s", (code) => {
    expect(parseCommand(code.toLowerCase())).toEqual({ type: "navigate", code });
    expect(parseCommand(`/tab ${code.toLowerCase()}`)).toEqual({ type: "navigate", code });
  });

  it.each(newCodes)("navigates to %s from both bare-code and /tab command input", async (code) => {
    render(<App />);
    const input = screen.getByRole("textbox", { name: "Command" });

    fireEvent.change(input, { target: { value: code.toLowerCase() } });
    fireEvent.keyDown(input, { key: "Enter" });
    expect(await screen.findByRole("tabpanel", { name: workspaceName(code) })).toBeTruthy();
    expect(window.location.hash.toUpperCase()).toBe(`#${code}`);

    fireEvent.change(input, { target: { value: `/tab ${code.toLowerCase()}` } });
    fireEvent.keyDown(input, { key: "Enter" });
    expect(await screen.findByRole("tabpanel", { name: workspaceName(code) })).toBeTruthy();
    expect(window.location.hash.toUpperCase()).toBe(`#${code}`);
  });

  it("routes an unknown hash to Help with an explicit reason", async () => {
    setHash("#UNKNOWN-WAVE-26-CODE");
    render(<App />);

    const helpTab = await screen.findByRole("tab", { name: /HELP/i });
    expect(helpTab.getAttribute("aria-selected")).toBe("true");
    expect(await screen.findByText(/invalid hash|unknown hash/i)).toBeTruthy();
    expect(resolveHash("#UNKNOWN-WAVE-26-CODE").code).toBe("HELP");
    expect(resolveHash("#UNKNOWN-WAVE-26-CODE").reason).toBeTruthy();
  });
});
