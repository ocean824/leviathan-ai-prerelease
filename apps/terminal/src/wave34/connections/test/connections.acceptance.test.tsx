import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createConnectionsApi } from "../api";
import { ConnectionsView } from "../ConnectionsView";
import type {
  ApiResult,
  ConnectInitiateV1,
  ConnectionActionResultV1,
  ConnectionEnvironment,
  ConnectionProviderId,
  ConnectionsApi,
  ConnectionsCatalogV1,
  ConnectionsStatusV1,
  ExternalUrlOpenerPort,
} from "../model";

const PROVIDERS: readonly ConnectionProviderId[] = [
  "ibkr", "alpaca", "mt5", "mcp", "snaptrade", "tastytrade", "ctrader", "coinbase",
  "kraken", "binance_us", "forex_com_mt5", "rithmic", "kalshi", "anthropic", "openai", "openai_compatible",
];
const PROVIDER_LABELS: Record<ConnectionProviderId, string> = {
  ibkr: "Interactive Brokers (IBKR)",
  alpaca: "Alpaca",
  mt5: "MetaTrader 5",
  mcp: "Model Context Protocol",
  snaptrade: "SnapTrade",
  tastytrade: "tastytrade",
  ctrader: "cTrader",
  coinbase: "Coinbase",
  kraken: "Kraken",
  binance_us: "Binance.US",
  forex_com_mt5: "FOREX.com MT5",
  rithmic: "Rithmic",
  kalshi: "Kalshi",
  anthropic: "Anthropic",
  openai: "OpenAI",
  openai_compatible: "OpenAI-compatible provider",
};
const CAPABILITIES = [
  "ACCOUNT_READ", "BALANCE_READ", "POSITION_READ", "QUOTE_READ", "HISTORICAL_DATA_READ", "ORDER_SUBMIT",
  "ORDER_CANCEL", "ORDER_STATUS", "STREAMING", "OAUTH_CONNECT", "API_KEY_CONNECT", "MT5_LOGIN_CONNECT", "AI_INFERENCE",
] as const;
const NOW_MS = 1_800_000_000_000;
const CANARY = "synthetic-credential-canary-6f37a2";
const STATE = btoa("s".repeat(32)).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
const REDIRECT = "http://127.0.0.1:43125/callback";
let originalClipboardDescriptor: PropertyDescriptor | undefined;

function makeCatalog(): ConnectionsCatalogV1 {
  return {
    providers: PROVIDERS.map((provider_id, index) => ({
      provider_id,
      capabilities: [CAPABILITIES[index % CAPABILITIES.length]!],
      environments: ["PAPER", "DEMO", "LIVE"],
      auth_method: provider_id === "ibkr" || provider_id === "snaptrade"
        ? "oauth"
        : provider_id === "mt5" ? "mt5_login" : "api_key",
      default_route: provider_id === "ibkr",
    })),
  };
}

function makeStatus(environment: ConnectionEnvironment = "PAPER"): ConnectionsStatusV1 {
  return {
    connections: PROVIDERS.map((provider_id) => ({
      provider_id,
      environment,
      state: "DISCONNECTED",
      configured: false,
    })),
  };
}

function oauthResponse(
  overrides: Partial<Extract<ConnectInitiateV1, { auth_method: "oauth" }>> = {},
): Extract<ConnectInitiateV1, { auth_method: "oauth" }> {
  const authorizationUrl = new URL("https://auth.example.test/authorize");
  authorizationUrl.searchParams.set("state", STATE);
  authorizationUrl.searchParams.set("redirect_uri", REDIRECT);
  return {
    provider_id: "ibkr",
    environment: "PAPER",
    auth_method: "oauth" as const,
    authorization_url: authorizationUrl.href,
    authorization_host: "auth.example.test",
    redirect_uri: REDIRECT,
    state: STATE,
    expires_at_ns: String(BigInt(NOW_MS + 120_000) * 1_000_000n),
    single_use: true as const,
    request_id: "synthetic-oauth-request",
    ...overrides,
  };
}

function apiFixture(overrides: Partial<ConnectionsApi> = {}): ConnectionsApi {
  return {
    getCatalog: vi.fn(async (): Promise<ApiResult<ConnectionsCatalogV1>> => ({ ok: true, data: makeCatalog() })),
    getStatus: vi.fn(async (): Promise<ApiResult<ConnectionsStatusV1>> => ({ ok: true, data: makeStatus() })),
    connect: vi.fn(async (): Promise<ApiResult<ConnectInitiateV1>> => ({ ok: true, data: oauthResponse() })),
    cancel: vi.fn(async (): Promise<ApiResult<ConnectionActionResultV1>> => ({
      ok: true, data: { provider_id: "ibkr", environment: "PAPER", result: "CANCELLED" },
    })),
    disconnect: vi.fn(async (): Promise<ApiResult<ConnectionActionResultV1>> => ({
      ok: true, data: { provider_id: "ibkr", environment: "PAPER", result: "DISCONNECTED" },
    })),
    ...overrides,
  };
}

async function renderReady(props: {
  api?: ConnectionsApi;
  externalUrlOpener?: ExternalUrlOpenerPort;
  clock?: () => number;
} = {}) {
  render(<ConnectionsView {...props} api={props.api ?? apiFixture()} clock={props.clock ?? (() => NOW_MS)} />);
  await screen.findByText("Connection status is current.");
}

afterEach(() => {
  if (originalClipboardDescriptor) Object.defineProperty(navigator, "clipboard", originalClipboardDescriptor);
  else Reflect.deleteProperty(navigator, "clipboard");
  originalClipboardDescriptor = undefined;
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("CONN-004 independent acceptance", () => {
  it("renders every registry provider with its capability, environments, auth route, and status", async () => {
    await renderReady();

    for (const provider of PROVIDERS) {
      const row = screen.getAllByText(provider)[0]!.closest("article");
      expect(row, `missing catalog row for ${provider}`).not.toBeNull();
      expect(within(row!).getAllByText(PROVIDER_LABELS[provider]).length).toBeGreaterThan(0);
      expect(within(row!).getByText("disconnected")).toBeTruthy();
      expect(within(row!).getByText("Environment: PAPER")).toBeTruthy();
      expect(within(row!).getByText(/Capabilities: /)).toBeTruthy();
      expect(within(row!).getByText("Available environments: PAPER, DEMO, LIVE")).toBeTruthy();
      expect(within(row!).getByText(/Authentication: /)).toBeTruthy();
      expect(within(row!).getByText(/Default provider: (Yes|No)/)).toBeTruthy();
    }
    expect(screen.getByText(/Starting Live connections is disabled in this terminal/)).toBeTruthy();
  });

  it("performs only the catalog and status reads at mount", async () => {
    const catalogBody = makeCatalog();
    const statusBody = makeStatus();
    const calls: Array<{ url: string; method: string }> = [];
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = init?.method ?? "GET";
      calls.push({ url, method });
      const body = url.endsWith("/connections/catalog") ? catalogBody : statusBody;
      return new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
    });

    await renderReady({ api: createConnectionsApi(fetcher as typeof fetch) });

    expect(calls).toEqual([
      { url: "/api/connections/catalog", method: "GET" },
      { url: "/api/connections/status", method: "GET" },
    ]);
    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(localStorage.getItem(CANARY)).toBeNull();
    expect(sessionStorage.getItem(CANARY)).toBeNull();
    expect(window.location.href).not.toContain(CANARY);
  });

  it("keeps LIVE initiation disabled with an explanation while permitting cleanup actions", async () => {
    const api = apiFixture({
      getStatus: vi.fn(async (): Promise<ApiResult<ConnectionsStatusV1>> => ({
        ok: true,
        data: {
          connections: PROVIDERS.map((provider_id) => ({
            provider_id,
            environment: "LIVE",
            state: provider_id === "ibkr" ? "PENDING" : provider_id === "alpaca" ? "CONNECTED" : "DISCONNECTED",
            configured: provider_id === "alpaca",
          })),
        },
      })),
    });
    await renderReady({ api });

    expect(screen.getByText(/Starting Live connections is disabled in this terminal/)).toBeTruthy();
    expect(screen.getAllByRole("button", { name: "Connect" }).every((button) => (button as HTMLButtonElement).disabled)).toBe(true);
    expect(screen.getAllByRole("button", { name: "Open credential entry" }).every((button) => (button as HTMLButtonElement).disabled)).toBe(true);
    expect((screen.getByRole("button", { name: "Cancel" }) as HTMLButtonElement).disabled).toBe(false);
    expect((screen.getByRole("button", { name: "Disconnect" }) as HTMLButtonElement).disabled).toBe(false);
    expect(api.connect).not.toHaveBeenCalled();
  });

  it("validates OAuth before opening, never auto-navigates, and offers a copyable URL with expiry", async () => {
    const api = apiFixture();
    const opener = { open: vi.fn(async () => "unavailable" as const) };
    const initialLocation = window.location.href;
    const logSpy = vi.spyOn(console, "log");
    const infoSpy = vi.spyOn(console, "info");
    const warnSpy = vi.spyOn(console, "warn");
    const errorSpy = vi.spyOn(console, "error");
    await renderReady({ api, externalUrlOpener: opener });

    expect(opener.open).not.toHaveBeenCalled();
    expect(window.location.href).toBe(initialLocation);
    fireEvent.click(screen.getAllByRole("button", { name: "Connect" })[0]!);

    const group = await screen.findByRole("group", { name: "Single-use authorization link" });
    const response = oauthResponse();
    const expectedHref = new URL(response.authorization_url).href;
    expect(api.connect).toHaveBeenCalledWith("ibkr");
    expect(opener.open).toHaveBeenCalledTimes(1);
    expect(opener.open).toHaveBeenCalledWith(new URL(expectedHref));
    expect(within(group).getByText(/Single use; expires at/)).toBeTruthy();
    const link = within(group).getByRole("link", { name: "Open authorization link" });
    expect(link.getAttribute("href")).toBe(expectedHref);
    expect(link.getAttribute("target")).toBe("_blank");
    expect(link.getAttribute("rel")).toContain("noopener");
    // The OAuth protocol URL necessarily contains state and redirect_uri; raw state is not separately displayed.
    expect(new URL(link.getAttribute("href")!).searchParams.get("state")).toBe(STATE);
    expect(new URL(link.getAttribute("href")!).searchParams.get("redirect_uri")).toBe(REDIRECT);
    expect(document.body.textContent).not.toContain(`State: ${STATE}`);
    expect(document.body.textContent).not.toContain("synthetic-oauth-request");
    expect(window.location.href).toBe(initialLocation);
    const storedContent = Array.from({ length: localStorage.length }, (_, index) => {
      const key = localStorage.key(index) ?? "";
      return `${key}:${localStorage.getItem(key) ?? ""}`;
    }).concat(Array.from({ length: sessionStorage.length }, (_, index) => {
      const key = sessionStorage.key(index) ?? "";
      return `${key}:${sessionStorage.getItem(key) ?? ""}`;
    })).join("\n");
    expect(storedContent).not.toContain(STATE);
    expect(JSON.stringify([logSpy.mock.calls, infoSpy.mock.calls, warnSpy.mock.calls, errorSpy.mock.calls])).not.toContain(STATE);

    const writeText = vi.fn(async () => undefined);
    originalClipboardDescriptor = Object.getOwnPropertyDescriptor(navigator, "clipboard");
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText } });
    fireEvent.click(within(group).getByRole("button", { name: "Copy link / open it in your browser" }));
    await act(async () => { await Promise.resolve(); });
    expect(writeText).toHaveBeenCalledWith(expectedHref);
    expect(screen.getByText("Authorization link copied.")).toBeTruthy();
  });

  it.each([
    ["mismatched host", { authorization_url: "https://attacker.invalid/authorize" }],
    ["embedded credentials", { authorization_url: "https://user:pass@auth.example.test/authorize" }],
    ["fragment", { authorization_url: "https://auth.example.test/authorize#token" }],
    ["non-loopback redirect", { redirect_uri: "http://attacker.invalid/callback" }],
    ["malformed state", { state: "not-a-canonical-base64url-state" }],
    ["expired link", { expires_at_ns: String(BigInt(NOW_MS - 1) * 1_000_000n) }],
  ] as const)("rejects unsafe OAuth response: %s", async (_name, override) => {
    const api = apiFixture({
      connect: vi.fn(async (): Promise<ApiResult<ConnectInitiateV1>> => ({
        ok: true, data: oauthResponse(override),
      })),
    });
    const opener = { open: vi.fn(async () => "unavailable" as const) };
    await renderReady({ api, externalUrlOpener: opener });
    fireEvent.click(screen.getAllByRole("button", { name: "Connect" })[0]!);

    expect(await screen.findByRole("alert")).toBeTruthy();
    expect(opener.open).not.toHaveBeenCalled();
    expect(api.cancel).toHaveBeenCalledWith("ibkr");
    expect(screen.queryByRole("link", { name: "Open authorization link" })).toBeNull();
    expect(document.body.innerHTML).not.toContain("attacker.invalid");
  });

  it("routes API-key and MT5 providers to credential entry without rendering handles or secret inputs", async () => {
    const handleCanary = "credential-entry-handle-canary-81d4";
    const api = apiFixture({
      connect: vi.fn(async (provider_id: ConnectionProviderId): Promise<ApiResult<ConnectInitiateV1>> => ({
        ok: true,
        data: {
          provider_id,
          environment: "PAPER",
          auth_method: provider_id === "mt5" ? "mt5_login" : "api_key",
          credential_entry_handle: handleCanary,
          credential_value: CANARY,
        } as unknown as ConnectInitiateV1,
      })),
    });
    await renderReady({ api });
    const credentialButtons = screen.getAllByRole("button", { name: "Open credential entry" });
    fireEvent.click(credentialButtons[0]!);
    expect((await screen.findByRole("link", { name: /credential entry/ })).getAttribute("href")).toBe("#LIVE");
    expect(document.body.textContent).not.toContain(handleCanary);
    expect(document.body.textContent).not.toContain(CANARY);
    expect(screen.queryByLabelText(/secret|api key|password/i)).toBeNull();

    fireEvent.click(screen.getAllByRole("button", { name: "Open credential entry" }).find((button) =>
      button.closest("article")?.textContent?.includes("MetaTrader 5"))!);
    expect(await screen.findByRole("link", { name: /MetaTrader 5 credential entry/ })).toBeTruthy();
    expect(document.body.textContent).not.toContain(handleCanary);
    expect(screen.queryByLabelText(/secret|api key|password/i)).toBeNull();
  });

  it("marks stale data and disables changes until refresh", async () => {
    let now = NOW_MS;
    const clock = () => now;
    vi.useFakeTimers();
    render(<ConnectionsView api={apiFixture()} clock={clock} />);
    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(screen.getByText("Connection status is current.")).toBeTruthy();
    now += 6_000;
    await act(async () => { vi.advanceTimersByTime(1_000); });
    expect(screen.getByText("Connection status is stale. Refresh before changing a connection.")).toBeTruthy();
    expect(screen.getAllByRole("button", { name: "Connect" }).every((button) => (button as HTMLButtonElement).disabled)).toBe(true);
  });

  it("keeps unavailable, invalid-response, and empty-catalog states explicit and sanitized", async () => {
    const unavailableApi = apiFixture({
      getCatalog: vi.fn(async (): Promise<ApiResult<ConnectionsCatalogV1>> => ({ ok: false, error: "CONNECTIONS_UNAVAILABLE" })),
    });
    const { unmount } = render(<ConnectionsView api={unavailableApi} clock={() => NOW_MS} />);
    expect((await screen.findByRole("alert")).textContent).toContain("Connection service unavailable.");
    unmount();

    const invalidApi = apiFixture({
      getCatalog: vi.fn(async (): Promise<ApiResult<ConnectionsCatalogV1>> => ({ ok: false, error: "INVALID_RESPONSE" })),
    });
    const second = render(<ConnectionsView api={invalidApi} clock={() => NOW_MS} />);
    expect((await screen.findByRole("alert")).textContent).toContain("Connection service returned an invalid response.");
    second.unmount();

    await renderReady({ api: apiFixture({
      getCatalog: vi.fn(async (): Promise<ApiResult<ConnectionsCatalogV1>> => ({ ok: true, data: { providers: [] } })),
      getStatus: vi.fn(async (): Promise<ApiResult<ConnectionsStatusV1>> => ({ ok: true, data: { connections: [] } })),
    }) });
    expect(screen.getByText("No providers are available in the connection catalog.")).toBeTruthy();
    expect(screen.getByText("The active environment could not be verified. Connection changes are disabled.")).toBeTruthy();
  });

  it("exposes native keyboard-focusable controls and preserves keyboard-triggerable button semantics", async () => {
    await renderReady();
    const connect = screen.getAllByRole("button", { name: "Connect" })[0]! as HTMLButtonElement;
    expect(connect.tagName).toBe("BUTTON");
    expect(connect.tabIndex).toBe(0);
    connect.focus();
    expect(document.activeElement).toBe(connect);
    expect(connect.type).toBe("button");
  });
});
