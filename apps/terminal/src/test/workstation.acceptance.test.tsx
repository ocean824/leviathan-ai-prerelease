import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import App from "../App";
import { REGISTRY, TAB_ENTRIES, VIEW_ENTRIES, resolveHash } from "../navigation/registry";
import { parseCommand } from "../navigation/commands";
import { PanelCard } from "../components/PanelCard";
import { OPERATOR_STALE_MS, errorPanel } from "../state/panelState";
import { GATEWAY_POLL_MS } from "../state/useGatewaySnapshot";
import { apiResponse } from "./fixtures/api";

function mockDisconnectedApi() {
  return vi.spyOn(globalThis, "fetch").mockResolvedValue({
    ok: false,
    status: 503,
    statusText: "Service Unavailable",
    json: async () => ({ detail: "Gateway disconnected" }),
  } as Response);
}


function liveRiskResponse(as_of?: number) {
  return {
    ...(as_of === undefined ? {} : { as_of }),
    halted: false,
    active_halts: [],
    operating_mode: "LIVE",
    policy: { max_daily_dd_pct: "2", max_open_heat_pct: "4" },
  };
}

function liveHealthResponse(as_of?: number) {
  return {
    ...(as_of === undefined ? {} : { as_of }),
    status: "ok",
    service: "gateway",
    version: "1",
    core_version: "1",
    operating_mode: "LIVE",
    env: "test",
  };
}

function mockLiveControlApi(as_of?: number) {
  return vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
    const url = String(input);
    if (url.includes("/api/health")) return apiResponse(liveHealthResponse(as_of));
    if (url.includes("/api/risk/status")) return apiResponse(liveRiskResponse(as_of));
    if (url.includes("/api/journal/records")) {
      return apiResponse({
        ...(as_of === undefined ? {} : { as_of }),
        records: [],
        stats: {},
      });
    }
    return apiResponse({ detail: "Gateway disconnected" }, 503);
  });
}
function enterCommand(input: string) {
  const command = screen.getByRole("textbox", { name: "Command" });
  fireEvent.change(command, { target: { value: input } });
  fireEvent.keyDown(command, { key: "Enter" });
}

function setHash(hash: string) {
  window.history.replaceState({}, "", `/${hash}`);
}

async function flushGatewayUpdates() {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();
  });
}

describe("C-104 registry and command acceptance", () => {
  beforeEach(() => mockDisconnectedApi());

  it("has one route and one help entry for every registry code, retaining the legacy codes", () => {
    const codes = REGISTRY.map(({ code }) => code);
    expect(new Set(codes).size).toBe(codes.length);
    expect(new Set(TAB_ENTRIES.map(({ code }) => code)).size).toBe(TAB_ENTRIES.length);
    expect(new Set(VIEW_ENTRIES.map(({ code }) => code)).size).toBe(VIEW_ENTRIES.length);
    expect([...TAB_ENTRIES, ...VIEW_ENTRIES].map(({ code }) => code).sort()).toEqual([...codes].sort());

    const legacy = ["CC", "JRNL", "RISK", "GENOME", "PIPE", "HELP"];
    for (const code of legacy) expect(codes).toContain(code);

    render(<App />);
    const help = screen.getByRole("tab", { name: /HELP/i });
    fireEvent.click(help);
    const helpPanel = screen.getByRole("tabpanel");
    for (const code of codes) {
      expect(within(helpPanel).getAllByText(code, { exact: true })).toHaveLength(1);
    }
  });

  it.each(["cc", "JRNL", "risk", "genome", "pipe", "help", "intel", "qr", "gp", "hp", "omon", "curv", "fxc", "wei"]) (
    "routes case-insensitive bare command %s",
    async (code) => {
      render(<App />);
      enterCommand(code);
      await waitFor(() => expect(window.location.hash.toUpperCase()).toBe(`#${code.toUpperCase()}`));
      expect(screen.queryByRole("alert")).toBeNull();
    },
  );

  it.each(["TODAY", "SYMBOL", "STRATEGY"]) ("opens %s view through /tab", async (view) => {
    render(<App />);
    enterCommand(`/tab ${view.toLowerCase()}`);
    await waitFor(() => expect(window.location.hash.toUpperCase()).toBe(`#${view}`));
    expect(screen.getByRole("tabpanel")).toBeTruthy();
  });

  it.each([
    ["/tab intel", "INTEL"],
    ["/TAB OMON", "OMON"],
    ["/tab today", "TODAY"],
    ["/tab symbol", "SYMBOL"],
    ["/tab strategy", "STRATEGY"],
  ])("parses case-insensitive %s", (input, code) => {
    expect(parseCommand(input)).toEqual({ type: "navigate", code });
  });

  it.each(["/tab", "/tab UNKNOWN", "UNKNOWN", "/nonsense"]) (
    "reports invalid navigation without changing selection: %s",
    async (input) => {
      render(<App />);
      const startingHash = window.location.hash;
      enterCommand(input);
      expect(await screen.findByRole("alert")).toBeTruthy();
      expect(window.location.hash).toBe(startingHash);
      expect(screen.getByRole("tabpanel")).toBeTruthy();
    },
  );

  it.each(["aapl", "BRK.B", "BTC-USD", "A1"]) ("accepts symbol token %s", (symbol) => {
    const parsed = parseCommand(`/sym ${symbol}`);
    expect(parsed).toEqual({ type: "symbol", symbol: symbol.toUpperCase() });
  });

  it.each(["/sym", "/sym AAPL!", "/sym AAAAAAAAAAAAAAAAAAAAA"]) ("rejects invalid symbol token %s", (input) => {
    expect(parseCommand(input).type).toBe("error");
  });

  it("opens SYMBOL with a valid ticker and exposes no invented quote or level", async () => {
    render(<App />);
    enterCommand("/sym aapl");
    expect(await screen.findByText(/AAPL selected\. Quote/)).toBeTruthy();
    expect(window.location.hash.toUpperCase()).toBe("#SYMBOL");
    expect(screen.getByText(/AAPL selected\. Quote/)).toBeTruthy();
    expect(screen.queryByText(/(?:bid|ask|last price|support|resistance)\s*[:=]\s*\$?\d/i)).toBeNull();
  });

  it.each([
    ["symbol=AAPL", "symbol"],
    ["venue=XNAS", "venue"],
    ["strategy=mean-reversion", "strategy"],
    ["timeframe=5m", "timeframe"],
  ])("accepts /filter %s", (value, key) => {
    expect(parseCommand(`/filter ${value}`)).toEqual({
      type: "filter",
      key,
      value: value.slice(value.indexOf("=") + 1).toUpperCase(),
    });
  });

  it.each(["/filter account=demo", "/filter symbol", "/filter =AAPL", "/filter symbol="]) (
    "rejects malformed or unsupported filter %s",
    (input) => expect(parseCommand(input).type).toBe("error"),
  );

  it("shows disabled /omega with its reason and makes no order-network call", async () => {
    const fetch = vi.mocked(globalThis.fetch);
    render(<App />);
    enterCommand("/omega status");
    expect(await screen.findByText(/bridge unavailable/i)).toBeTruthy();
    expect(fetch.mock.calls.some(([input]) => /order|execution/i.test(String(input)))).toBe(false);
  });

  it("shows all registered commands and disabled reasons in HELP", () => {
    render(<App />);
    enterCommand("/help");
    const panel = screen.getByRole("tabpanel");
    for (const { code } of REGISTRY) expect(within(panel).getAllByText(code, { exact: true })).toHaveLength(1);
    expect(within(panel).getByText(/\/sym/i)).toBeTruthy();
    expect(within(panel).getByText(/\/filter/i)).toBeTruthy();
    expect(within(panel).getByText(/OMEGA bridge unavailable/i)).toBeTruthy();
  });

  it("keeps /omega visible as a disabled suggestion with its reason", async () => {
    render(<App />);
    const input = screen.getByRole("textbox", { name: "Command" });
    fireEvent.change(input, { target: { value: "/omega" } });
    const option = await screen.findByRole("option");
    expect(option.getAttribute("aria-disabled")).toBe("true");
    expect(option.textContent).toMatch(/bridge unavailable/i);
  });

  it("stores /filter values in global context and keeps them on fixture panels", async () => {
    window.history.replaceState({}, "", "/?fixture=healthy");
    render(<App />);
    enterCommand("/filter venue=xnas");
    enterCommand("/tab today");
    expect(await screen.findByText(/venue=XNAS/)).toBeTruthy();
    const panel = screen.getByRole("region", { name: "Top Flow / DP" });
    expect(within(panel).getByText("Fixture")).toBeTruthy();
    expect(within(panel).queryByText(/\bLive\b/i)).toBeNull();
  });

  it.each([
    ["TODAY", ["Top Flow / DP", "Regime", "Earnings / IV"]],
    ["SYMBOL", ["Levels", "Flow / DP", "IV", "Catalysts"]],
    ["STRATEGY", ["Active Plays", "Edge Health", "Obsidian Updates"]],
  ] as const)("renders named %s sections with unavailable reasons", async (view, sections) => {
    render(<App />);
    enterCommand(`/tab ${view}`);
    for (const title of sections) {
      const panel = await screen.findByRole("region", { name: title });
      expect(panel.textContent).toMatch(/not connected|unavailable|no timestamped/i);
    }
    if (view === "STRATEGY") {
      const control = screen.getByRole("button", { name: /submit update/i });
      expect((control as HTMLButtonElement).disabled).toBe(true);
    }
  });
});

describe("C-104 hash and keyboard acceptance", () => {
  beforeEach(() => mockDisconnectedApi());

  it.each(["#CC", "#INTEL", "#TODAY", "#SYMBOL", "#STRATEGY"]) ("restores valid hash %s", async (hash) => {
    setHash(hash);
    render(<App />);
    await waitFor(() => expect(window.location.hash.toUpperCase()).toBe(hash));
    expect(resolveHash(hash).code).toBe(hash.slice(1));
  });

  it("falls back from an invalid hash to HELP with a visible reason", async () => {
    setHash("#DOES-NOT-EXIST");
    render(<App />);
    expect((await screen.findByRole("tab", { name: /HELP/i })).getAttribute("aria-selected")).toBe("true");
    expect(await screen.findByText(/invalid hash|unknown hash|hash/i)).toBeTruthy();
    expect(resolveHash("#DOES-NOT-EXIST").code).toBe("HELP");
    expect(resolveHash("#DOES-NOT-EXIST").reason).toBeTruthy();
  });

  it("Ctrl/Cmd+K focuses command bar with visible focus", () => {
    render(<App />);
    const input = screen.getByRole("textbox", { name: "Command" });
    input.blur();
    fireEvent.keyDown(document.body, { key: "k", ctrlKey: true });
    expect(input).toBe(document.activeElement);
    expect(getComputedStyle(input).outlineStyle !== "none" || getComputedStyle(input).boxShadow !== "none").toBe(true);

    input.blur();
    fireEvent.keyDown(document.body, { key: "k", metaKey: true });
    expect(input).toBe(document.activeElement);
  });

  it("slash focuses command bar only when an editable field does not own focus", () => {
    render(<App />);
    const input = screen.getByRole("textbox", { name: "Command" });
    input.blur();
    fireEvent.keyDown(document.body, { key: "/" });
    expect(input).toBe(document.activeElement);

    const editable = document.createElement("input");
    document.body.append(editable);
    editable.focus();
    fireEvent.keyDown(editable, { key: "/" });
    expect(editable).toBe(document.activeElement);
    editable.remove();
  });

  it("Esc clears and closes suggestions; arrows move highlight; Enter selects it", async () => {
    render(<App />);
    const input = screen.getByRole("textbox", { name: "Command" });
    fireEvent.change(input, { target: { value: "A" } });
    expect(await screen.findByRole("listbox")).toBeTruthy();
    const options = within(screen.getByRole("listbox")).getAllByRole("option");
    expect(options.length).toBeGreaterThan(0);
    const initial = options.findIndex((option) => option.getAttribute("aria-selected") === "true");
    fireEvent.keyDown(input, { key: "ArrowDown" });
    const changed = within(screen.getByRole("listbox")).getAllByRole("option").findIndex(
      (option) => option.getAttribute("aria-selected") === "true",
    );
    expect(changed).not.toBe(initial);
    fireEvent.keyDown(input, { key: "Enter" });
    await waitFor(() => expect(window.location.hash.toUpperCase()).toBe("#INTEL"));

    fireEvent.change(input, { target: { value: "RISK" } });
    expect(await screen.findByRole("listbox")).toBeTruthy();
    fireEvent.keyDown(input, { key: "Escape" });
    expect((input as HTMLInputElement).value).toBe("");
    expect(screen.queryByRole("listbox")).toBeNull();
  });

  it("uses logical keyboard focus order through command bar, tabs and workspace", () => {
    render(<App />);
    const command = screen.getByRole("textbox", { name: "Command" });
    const tablist = screen.getByRole("tablist");
    const tabs = within(tablist).getAllByRole("tab");
    const workspace = screen.getByRole("tabpanel");
    const focusable = Array.from(document.querySelectorAll("input, button, [tabindex]")).filter(
      (element) => (element as HTMLElement).tabIndex >= 0,
    );
    expect(focusable[0]).toBe(command);
    expect(focusable.slice(1, 1 + tabs.length)).toEqual(tabs);
    expect(command.compareDocumentPosition(tabs[0]) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(tabs[tabs.length - 1].compareDocumentPosition(workspace) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(tablist.getAttribute("aria-label")).toBeTruthy();
    expect(workspace.getAttribute("aria-label")).toBeTruthy();
    expect(tabs[0].getAttribute("aria-controls")).toBe(workspace.id);
  });

  it.each([
    ["Network disconnected", "Connection lost"],
    ["HTTP 500 Internal Server Error", "HTTP 500"],
  ])("shows %s with a reason, last success and Retry without fresh status", (code, reason) => {
    const retry = vi.fn();
    const lastSuccess = Date.now() - 2_000;
    const state = errorPanel("Gateway API", `${code}: ${reason}`, lastSuccess, retry);
    render(<PanelCard title="Market status" eyebrow="SOURCE" state={state} renderData={() => <p>unexpected data</p>} />);
    const panel = screen.getByRole("region", { name: "Market status" });
    expect(panel.textContent).toContain(reason);
    expect(panel.textContent).toContain(new Date(lastSuccess).toLocaleString());
    expect(within(panel).getByText("error")).toBeTruthy();
    expect(within(panel).getByRole("button", { name: "Retry" })).toBeTruthy();
    expect(within(panel).queryByText("fresh")).toBeNull();
    fireEvent.click(within(panel).getByRole("button", { name: "Retry" }));
    expect(retry).toHaveBeenCalledTimes(1);
  });
});

describe("C-104 gateway freshness and control claims", () => {
  beforeEach(() => {
    mockDisconnectedApi();
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-10-05T12:00:00Z"));
  });

  it.each([
    {
      hash: "#RISK",
      endpoint: "/api/risk/status",
      panelName: "Sovereign Risk Domain",
      positiveLabel: "SOVEREIGN NOMINAL",
      forbiddenLiveLabel: /\bLIVE\b/i,
      body: {
        halted: false,
        active_halts: [],
        operating_mode: "PAPER",
        policy: { max_daily_dd_pct: "2", max_open_heat_pct: "4" },
      },
    },
    {
      hash: "#GENOME",
      endpoint: "/api/genomes",
      panelName: "Strategy Genome Registry",
      positiveLabel: "REPORTED NOT STALE",
      forbiddenLiveLabel: /\bLIVE\b/i,
      body: {
        genomes: [{ strategy_id: "acceptance-alpha", family: "trend", market: "equities", timeframe: "1d", stale: false }],
      },
    },
  ])("$panelName does not claim positive source status without as_of and clears after disconnect", async ({
    hash,
    endpoint,
    panelName,
    positiveLabel,
    forbiddenLiveLabel,
    body,
  }) => {
    setHash(hash);
    const requestCounts = new Map<string, number>();
    vi.mocked(globalThis.fetch).mockImplementation(async (input) => {
      const url = String(input);
      if (!url.includes(endpoint)) return apiResponse({ detail: "Gateway disconnected" }, 503);
      const count = (requestCounts.get(url) ?? 0) + 1;
      requestCounts.set(url, count);
      return count === 1
        ? apiResponse(body)
        : apiResponse({ detail: "Gateway disconnected" }, 503);
    });

    render(<App />);
    const panel = screen.getByRole("region", { name: panelName });
    await flushGatewayUpdates();

    expect(panel.textContent).toContain("UNAVAILABLE");
    expect(panel.textContent).toMatch(/No valid source timestamp supplied/i);
    expect(panel.textContent).toMatch(/Source as of Unavailable/i);
    expect(panel.textContent).not.toContain(positiveLabel);
    expect(panel.textContent).not.toMatch(/NOMINAL/i);
    expect(panel.textContent).not.toMatch(forbiddenLiveLabel);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(GATEWAY_POLL_MS);
    });
    await flushGatewayUpdates();

    expect(panel.textContent).toContain("DISCONNECTED");
    expect(panel.textContent).toMatch(/HTTP 503/i);
    expect(panel.textContent).toMatch(/Last successful response received:/i);
    expect(panel.textContent).not.toContain(positiveLabel);
    expect(panel.textContent).not.toMatch(/NOMINAL/i);
    expect(panel.textContent).not.toMatch(forbiddenLiveLabel);
  });

  it.each([
    {
      hash: "#RISK",
      endpoint: "/api/risk/status",
      panelName: "Sovereign Risk Domain",
      positiveLabel: "SOVEREIGN NOMINAL",
      body: {
        halted: false,
        active_halts: [],
        operating_mode: "PAPER",
        policy: { max_daily_dd_pct: "2", max_open_heat_pct: "4" },
      },
    },
    {
      hash: "#GENOME",
      endpoint: "/api/genomes",
      panelName: "Strategy Genome Registry",
      positiveLabel: "REPORTED NOT STALE",
      body: {
        genomes: [{ strategy_id: "acceptance-alpha", family: "trend", market: "equities", timeframe: "1d", stale: false }],
      },
    },
  ])("$panelName shows timestamped success, then disconnect with receipt shown separately", async ({
    hash,
    endpoint,
    panelName,
    positiveLabel,
    body,
  }) => {
    setHash(hash);
    const requestCounts = new Map<string, number>();
    vi.mocked(globalThis.fetch).mockImplementation(async (input) => {
      const url = String(input);
      if (!url.includes(endpoint)) return apiResponse({ detail: "Gateway disconnected" }, 503);
      const count = (requestCounts.get(url) ?? 0) + 1;
      requestCounts.set(url, count);
      return count === 1
        ? apiResponse({ ...body, as_of: Date.now() })
        : apiResponse({ detail: "Gateway disconnected" }, 503);
    });

    render(<App />);
    const panel = screen.getByRole("region", { name: panelName });
    await flushGatewayUpdates();

    expect(panel.textContent).toContain(positiveLabel);
    expect(panel.textContent).toContain("Connection CONNECTED");
    expect(panel.textContent).not.toMatch(/Source as of Unavailable/i);
    expect(panel.textContent).not.toMatch(/\bLIVE\b/i);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(GATEWAY_POLL_MS);
    });
    await flushGatewayUpdates();

    expect(panel.textContent).toContain("DISCONNECTED");
    expect(panel.textContent).toMatch(/HTTP 503/i);
    expect(panel.textContent).toMatch(/Last successful response received:/i);
    expect(panel.textContent).not.toContain(positiveLabel);
    expect(panel.textContent).not.toMatch(/NOMINAL/i);
    expect(panel.textContent).not.toMatch(/\bLIVE\b/i);
  });

  it("Command Center clears timestamped health and risk after a successful response then disconnect", async () => {
    setHash("#CC");
    const requestCounts = new Map<string, number>();
    vi.mocked(globalThis.fetch).mockImplementation(async (input) => {
      const url = String(input);
      const key = ["/api/health", "/api/risk/status", "/api/journal/records"].find((part) => url.includes(part));
      if (!key) return apiResponse({ detail: "Gateway disconnected" }, 503);
      const count = (requestCounts.get(key) ?? 0) + 1;
      requestCounts.set(key, count);
      if (count > 1) return apiResponse({ detail: "Gateway disconnected" }, 503);

      const as_of = Date.now();
      if (key === "/api/health") {
        return apiResponse({
          as_of,
          status: "ok",
          service: "gateway",
          version: "1",
          core_version: "1",
          operating_mode: "PAPER",
          env: "test",
        });
      }
      if (key === "/api/risk/status") {
        return apiResponse({
          as_of,
          halted: false,
          active_halts: [],
          operating_mode: "PAPER",
          policy: { max_daily_dd_pct: "2", max_open_heat_pct: "4" },
        });
      }
      return apiResponse({ as_of, records: [], stats: { trades: 2 } });
    });

    render(<App />);
    const healthPanel = screen.getByRole("region", { name: "Gateway Status" });
    const riskPanel = screen.getByRole("region", { name: "Sovereign Risk" });
    const journalPanel = screen.getByRole("region", { name: "Journal Stats" });
    await flushGatewayUpdates();

    expect(healthPanel.textContent).toContain("REPORTED: OK");
    expect(riskPanel.textContent).toMatch(/SOVEREIGN NOMINAL/i);
    expect(journalPanel.textContent).toContain("TRADES: 2");
    for (const panel of [healthPanel, riskPanel, journalPanel]) {
      expect(panel.textContent).toContain("Connection CONNECTED");
      expect(panel.textContent).not.toMatch(/Source as of Unavailable/i);
    }

    await act(async () => {
      await vi.advanceTimersByTimeAsync(GATEWAY_POLL_MS);
    });
    await flushGatewayUpdates();

    for (const panel of [healthPanel, riskPanel, journalPanel]) {
      expect(panel.textContent).toContain("DISCONNECTED");
      expect(panel.textContent).toMatch(/HTTP 503/i);
      expect(panel.textContent).toMatch(/Last successful response received:/i);
      expect(panel.textContent).toMatch(/Source as of Unavailable/i);
    }
    expect(healthPanel.textContent).not.toContain("REPORTED: OK");
    expect(riskPanel.textContent).not.toMatch(/SOVEREIGN NOMINAL/i);
  });


  it("suppresses untimestamped LIVE risk mode and reports UNAVAILABLE", async () => {
    setHash("#RISK");
    mockLiveControlApi();

    render(<App />);
    const panel = screen.getByRole("region", { name: "Sovereign Risk Domain" });
    await flushGatewayUpdates();

    expect(panel.textContent).toContain("UNAVAILABLE");
    expect(panel.textContent).toMatch(/No valid source timestamp supplied/i);
    expect(panel.textContent).toMatch(/Source as of Unavailable/i);
    expect(panel.textContent).not.toMatch(/\bLIVE\b|NOMINAL/i);
  });

  it("suppresses stale LIVE risk mode and reports delayed source state", async () => {
    setHash("#RISK");
    const staleAsOf = Date.now() - OPERATOR_STALE_MS - 1;
    mockLiveControlApi(staleAsOf);

    render(<App />);
    const panel = screen.getByRole("region", { name: "Sovereign Risk Domain" });
    await flushGatewayUpdates();

    expect(panel.textContent).toMatch(/DELAYED|UNAVAILABLE/i);
    expect(panel.textContent).not.toMatch(/\bLIVE\b|NOMINAL/i);
    expect(panel.textContent).not.toContain("Operating mode");
    expect(panel.textContent).toContain(new Date(staleAsOf).toLocaleString());
  });

  it("renders fresh timestamped LIVE risk mode with gateway source and as-of", async () => {
    setHash("#RISK");
    const asOf = Date.now();
    mockLiveControlApi(asOf);

    render(<App />);
    const panel = screen.getByRole("region", { name: "Sovereign Risk Domain" });
    await flushGatewayUpdates();

    expect(panel.textContent).toContain("SOVEREIGN NOMINAL");
    expect(panel.textContent).toContain("LIVE");
    expect(panel.textContent).toContain("Source Gateway API");
    expect(panel.textContent).toContain("Source as of " + new Date(asOf).toLocaleString());
  });

  it("suppresses untimestamped LIVE modes in Command Center", async () => {
    setHash("#CC");
    mockLiveControlApi();

    render(<App />);
    const healthPanel = screen.getByRole("region", { name: "Gateway Status" });
    const riskPanel = screen.getByRole("region", { name: "Sovereign Risk" });
    await flushGatewayUpdates();

    for (const panel of [healthPanel, riskPanel]) {
      expect(panel.textContent).toContain("UNAVAILABLE");
      expect(panel.textContent).toMatch(/No valid source timestamp supplied/i);
      expect(panel.textContent).toMatch(/Source as of Unavailable/i);
      expect(panel.textContent).not.toMatch(/\bLIVE\b|NOMINAL/i);
    }
  });

  it("suppresses stale LIVE modes in Command Center past the source freshness bound", async () => {
    setHash("#CC");
    const staleAsOf = Date.now() - OPERATOR_STALE_MS - 1;
    mockLiveControlApi(staleAsOf);

    render(<App />);
    const healthPanel = screen.getByRole("region", { name: "Gateway Status" });
    const riskPanel = screen.getByRole("region", { name: "Sovereign Risk" });
    await flushGatewayUpdates();

    for (const panel of [healthPanel, riskPanel]) {
      expect(panel.textContent).toContain("DELAYED");
      expect(panel.textContent).not.toMatch(/\bLIVE\b|NOMINAL/i);
      expect(panel.textContent).toContain(new Date(staleAsOf).toLocaleString());
    }
  });

  it("renders fresh timestamped LIVE modes in Command Center with source and as-of", async () => {
    setHash("#CC");
    const asOf = Date.now();
    mockLiveControlApi(asOf);

    render(<App />);
    const healthPanel = screen.getByRole("region", { name: "Gateway Status" });
    const riskPanel = screen.getByRole("region", { name: "Sovereign Risk" });
    await flushGatewayUpdates();

    expect(healthPanel.textContent).toContain("Operating modeLIVE");
    expect(riskPanel.textContent).toMatch(/SOVEREIGN NOMINAL/i);
    for (const panel of [healthPanel, riskPanel]) {
      expect(panel.textContent).toContain("Source Gateway API");
      expect(panel.textContent).toContain("Source as of " + new Date(asOf).toLocaleString());
    }
  });

  it("removes the F1 help claim or makes F1 open HELP", () => {
    render(<App />);
    const hasF1Claim = /\bF1\b/i.test(document.body.textContent ?? "");
    if (hasF1Claim) {
      fireEvent.keyDown(document.body, { key: "F1" });
      expect(screen.getByRole("tab", { name: /HELP/i }).getAttribute("aria-selected")).toBe("true");
    } else {
      expect(document.body.textContent).not.toMatch(/\bF1\b/i);
    }
  });
});

describe("C-104 operator fixture timing", () => {
  beforeEach(() => {
    mockDisconnectedApi();
    vi.useFakeTimers();
    window.history.replaceState({}, "", "/?fixture=healthy#TODAY");
  });

  it("labels fixture data and changes operator panels from fresh to Delayed at 5 seconds", () => {
    render(<App />);
    const panel = screen.getByRole("region", { name: "Top Flow / DP" });
    expect(within(panel).getByText("Fixture")).toBeTruthy();
    expect(within(panel).queryByText(/\bLive\b/i)).toBeNull();
    expect(within(panel).getByText("fresh")).toBeTruthy();
    act(() => vi.advanceTimersByTime(4_999));
    expect(within(panel).getByText("fresh")).toBeTruthy();
    act(() => vi.advanceTimersByTime(1));
    expect(within(panel).getByText("Delayed")).toBeTruthy();
  });
});



