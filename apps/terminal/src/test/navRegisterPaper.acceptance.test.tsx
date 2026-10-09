import { fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import App from "../App";
import { parseCommand } from "../navigation/commands";
import * as navigationRegistry from "../navigation/registry";
import { REGISTRY, resolveHash, TAB_ENTRIES } from "../navigation/registry";
import { eaTemplateCatalogResponse } from "../wave26/test/fixtures/eaTemplateCatalog";
import {
  haltedPaperRiskStatus,
  paperActivityResponse,
  paperOrderStatus,
} from "./fixtures/paperActivity";

type CapturedRequest = { endpoint: string; method: string };

const PACT_READ_ENDPOINTS = [
  "/api/orders/activity?limit=50",
  "/api/orders/status",
  "/api/risk/status",
] as const;
const EAC_READ_ENDPOINTS = ["/api/v1/ea/templates"] as const;
const PAPR_READ_ENDPOINTS = ["/api/orders/status", "/api/risk/status"] as const;

const registeredViews = [
  { code: "PACT", label: "Paper Activity", heading: "Paper Activity" },
  { code: "PAPR", label: "Paper Activation", heading: "Paper Activation" },
  { code: "EAC", label: "EA Template Catalog", heading: "EA Templates" },
  { code: "FLR", label: "Flash-loan Routes (read-only)", heading: "Flash-loan routes" },
] as const;

const existingViews = [
  ["CC", "Gateway Status"],
  ["JRNL", "Trade Journal"],
  ["RISK", "Sovereign Risk Domain"],
  ["GENOME", "Strategy Genome Registry"],
  ["PIPE", "Pipeline Replay"],
  ["LIVE", "Live Trading"],
] as const;

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function setHash(code: string) {
  window.history.replaceState({}, "", `/#${code}`);
}

function installFakeFetch() {
  const requests: CapturedRequest[] = [];
  const fetcher = vi.fn<typeof fetch>(async (input, init) => {
    const url = new URL(String(input), window.location.origin);
    requests.push({ endpoint: `${url.pathname}${url.search}`, method: init?.method ?? "GET" });
    switch (url.pathname) {
      case "/api/orders/activity":
        return jsonResponse(paperActivityResponse);
      case "/api/orders/status":
        return jsonResponse(paperOrderStatus);
      case "/api/risk/status":
        return jsonResponse(haltedPaperRiskStatus);
      case "/api/v1/ea/templates":
        return jsonResponse(eaTemplateCatalogResponse);
      default:
        return jsonResponse({ error: "UNEXPECTED_TEST_REQUEST" }, 404);
    }
  });
  vi.stubGlobal("fetch", fetcher);
  return { fetcher, requests };
}

function expectOnlyDocumentedReads(requests: readonly CapturedRequest[], allowedEndpoints: readonly string[]) {
  expect(requests.length).toBeGreaterThan(0);
  expect(requests.every(({ method }) => method === "GET")).toBe(true);
  expect(requests.every(({ endpoint }) => allowedEndpoints.includes(endpoint))).toBe(true);
  expect([...new Set(requests.map(({ endpoint }) => endpoint))].sort()).toEqual([...allowedEndpoints].sort());
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("NAV-REGISTER-PAPER-001 independent acceptance", () => {
  it.each(registeredViews)("registers $code as a tab and reaches its view by tab", async ({
    code,
    label,
    heading,
  }) => {
    const { requests } = installFakeFetch();
    setHash("HELP");
    render(<App />);

    const codeValue: string = String(code);
    const entry = REGISTRY.find((candidate) => candidate.code === codeValue);
    expect(entry).toMatchObject({ code: codeValue, label, kind: "tab" });
    expect(TAB_ENTRIES.filter((candidate) => candidate.code === codeValue)).toHaveLength(1);
    expect(resolveHash(`#${codeValue.toLowerCase()}`).code).toBe(codeValue);
    expect(parseCommand(codeValue.toLowerCase())).toEqual({ type: "navigate", code: codeValue });
    expect(parseCommand(`/tab ${codeValue.toLowerCase()}`)).toEqual({ type: "navigate", code: codeValue });

    const tab = screen.getByRole("tab", { name: new RegExp(`^${codeValue}\\b`) });
    expect(tab).toBeTruthy();
    fireEvent.click(tab);
    const workspace = screen.getByRole("tabpanel");
    expect(await within(workspace).findByRole("heading", { name: heading, level: 2 })).toBeTruthy();

    if (codeValue === "PACT") {
      expectOnlyDocumentedReads(requests, PACT_READ_ENDPOINTS);
    } else if (codeValue === "PAPR") {
      expectOnlyDocumentedReads(requests, PAPR_READ_ENDPOINTS);
    } else if (codeValue === "EAC") {
      expectOnlyDocumentedReads(requests, EAC_READ_ENDPOINTS);
    } else {
      expect(requests).toEqual([]);
    }
  }, 15_000);

  it.each(registeredViews)("reaches $code by the keyboard command", async ({ code, heading }) => {
    const { requests } = installFakeFetch();
    setHash("HELP");
    render(<App />);

    const command = screen.getByRole("textbox", { name: "Command" });
    fireEvent.keyDown(window, { key: "k", ctrlKey: true });
    expect(document.activeElement).toBe(command);
    fireEvent.change(command, { target: { value: `/tab ${code.toLowerCase()}` } });
    fireEvent.keyDown(command, { key: "Enter" });

    const workspace = await screen.findByRole("tabpanel");
    expect(await within(workspace).findByRole("heading", { name: heading, level: 2 })).toBeTruthy();
    expect(resolveHash(window.location.hash).code).toBe(code);

    if (code === "PACT") {
      expectOnlyDocumentedReads(requests, PACT_READ_ENDPOINTS);
    } else if (code === "PAPR") {
      expectOnlyDocumentedReads(requests, PAPR_READ_ENDPOINTS);
    } else if (code === "EAC") {
      expectOnlyDocumentedReads(requests, EAC_READ_ENDPOINTS);
    } else {
      expect(requests).toEqual([]);
    }
  }, 15_000);

  it("removes PAPR from reserved metadata after registering it as an active tab", () => {
    expect("RESERVED_NAVIGATION_ENTRIES" in navigationRegistry).toBe(false);
    expect(REGISTRY.filter(({ code }) => code === "PAPR")).toHaveLength(1);
    expect(TAB_ENTRIES.filter(({ code }) => code === "PAPR")).toHaveLength(1);
    expect(resolveHash("#PAPR").code).toBe("PAPR");
    expect(parseCommand("PAPR")).toEqual({ type: "navigate", code: "PAPR" });
  });

  it("keeps FLR live disabled and exposes no enabled execution action", async () => {
    const { requests } = installFakeFetch();
    setHash("FLR");
    render(<App />);

    const workspace = screen.getByRole("tabpanel");
    expect(await within(workspace).findByRole("heading", { name: "Flash-loan routes", level: 2 })).toBeTruthy();
    expect(within(workspace).getByRole("status", { name: "LIVE trading status: DISABLED" })).toBeTruthy();
    expect(within(workspace).queryByRole("button", { name: /execute/i })).toBeNull();
    for (const action of within(workspace).queryAllByRole("button", { name: /execute/i })) {
      expect((action as HTMLButtonElement).disabled).toBe(true);
    }
    expect(within(workspace).queryByRole("form")).toBeNull();
    expect(requests).toEqual([]);
  });

  it.each(existingViews)("still renders the existing %s tab", async (code, heading) => {
    installFakeFetch();
    setHash(code);
    render(<App />);

    const tab = screen.getByRole("tab", { name: new RegExp(`^${code}\\b`) });
    expect(tab).toBeTruthy();
    const workspace = screen.getByRole("tabpanel");
    expect(await within(workspace).findByRole("heading", { name: heading, level: 2 })).toBeTruthy();
  });
});
