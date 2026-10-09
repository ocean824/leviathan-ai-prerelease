import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
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

const providerIds: ConnectionProviderId[] = [
  "ibkr", "alpaca", "mt5", "snaptrade", "tastytrade", "ctrader", "coinbase", "kraken", "binance_us", "rithmic", "kalshi",
];
const catalog: ConnectionsCatalogV1 = {
  providers: providerIds.map((provider, index) => ({
    provider_id: provider,
    capabilities: index === 0 ? ["ORDER_SUBMIT", "POSITION_READ"] : ["QUOTE_READ"],
    environments: ["PAPER", "DEMO", "LIVE"],
    auth_method: provider === "ibkr" || provider === "snaptrade" ? "oauth" : provider === "mt5" ? "mt5_login" : "api_key",
    default_route: provider === "snaptrade",
  })),
};
const status = (environment: ConnectionEnvironment = "PAPER"): ConnectionsStatusV1 => ({
  connections: providerIds.map((provider) => ({ provider_id: provider, environment, state: "DISCONNECTED", configured: false })),
});

function apiFixture(overrides: Partial<ConnectionsApi> = {}): ConnectionsApi {
  return {
    getCatalog: vi.fn(async (): Promise<ApiResult<ConnectionsCatalogV1>> => ({ ok: true, data: catalog })),
    getStatus: vi.fn(async (): Promise<ApiResult<ConnectionsStatusV1>> => ({ ok: true, data: status() })),
    connect: vi.fn(async (): Promise<ApiResult<ConnectInitiateV1>> => ({
      ok: true,
      data: {
        provider_id: "ibkr",
        environment: "PAPER",
        auth_method: "oauth",
        authorization_url: `https://auth.ibkr.example/authorize?state=${"A".repeat(43)}&redirect_uri=http%3A%2F%2F127.0.0.1%3A43125%2Fcallback`,
        authorization_host: "auth.ibkr.example",
        redirect_uri: "http://127.0.0.1:43125/callback",
        state: "A".repeat(43),
        expires_at_ns: String((Date.now() + 120_000) * 1_000_000),
        single_use: true,
        request_id: "request-1",
      },
    })),
    cancel: vi.fn(async (): Promise<ApiResult<ConnectionActionResultV1>> => ({
      ok: true, data: { provider_id: "ibkr", environment: "PAPER", result: "CANCELLED" },
    })),
    disconnect: vi.fn(async (): Promise<ApiResult<ConnectionActionResultV1>> => ({
      ok: true, data: { provider_id: "ibkr", environment: "PAPER", result: "DISCONNECTED" },
    })),
    ...overrides,
  };
}

async function renderLoaded(props: { api?: ConnectionsApi; externalUrlOpener?: ExternalUrlOpenerPort } = {}) {
  render(<ConnectionsView {...props} api={props.api ?? apiFixture()} />);
  await screen.findByText("Connection status is current.");
}

describe("ConnectionsView", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("lists each catalog provider, capabilities, environments and status", async () => {
    await renderLoaded();
    for (const id of providerIds) expect(screen.getAllByText(id).length).toBeGreaterThan(0);
    expect(screen.getByText("Interactive Brokers (IBKR)")).toBeTruthy();
    expect(screen.getByText("Capabilities: ORDER_SUBMIT, POSITION_READ")).toBeTruthy();
    expect(screen.getAllByText("Environment: PAPER")).toHaveLength(providerIds.length);
  });

  it("does not call an external opener before an explicit OAuth action and defaults to copyable link", async () => {
    const api = apiFixture();
    const opener = { open: vi.fn(async () => "unavailable" as const) };
    await renderLoaded({ api, externalUrlOpener: opener });
    expect(opener.open).not.toHaveBeenCalled();
    fireEvent.click(screen.getAllByRole("button", { name: "Connect" })[0]!);
    expect(await screen.findByRole("group", { name: "Single-use authorization link" })).toBeTruthy();
    expect(opener.open).toHaveBeenCalledTimes(1);
    expect(screen.getByText(/Single use; expires at/)).toBeTruthy();
    expect(screen.getByRole("link", { name: "Open authorization link" }).getAttribute("href"))
      .toContain("redirect_uri=http%3A%2F%2F127.0.0.1%3A43125%2Fcallback");
    expect(document.body.textContent).not.toContain("A".repeat(43));
  });

  it("rejects OAuth host mismatches and cancels the one-time attempt", async () => {
    const api = apiFixture({
      connect: vi.fn(async (): Promise<ApiResult<ConnectInitiateV1>> => ({
        ok: true,
        data: {
          provider_id: "ibkr", environment: "PAPER", auth_method: "oauth",
          authorization_url: "https://evil.example/authorize", authorization_host: "auth.ibkr.example",
          redirect_uri: "http://127.0.0.1:43125/callback", state: "A".repeat(43),
          expires_at_ns: String((Date.now() + 120_000) * 1_000_000), single_use: true, request_id: "request-2",
        },
      })),
    });
    const opener = { open: vi.fn(async () => "unavailable" as const) };
    await renderLoaded({ api, externalUrlOpener: opener });
    fireEvent.click(screen.getAllByRole("button", { name: "Connect" })[0]!);
    expect(await screen.findByRole("alert")).toBeTruthy();
    expect(opener.open).not.toHaveBeenCalled();
    expect(api.cancel).toHaveBeenCalledWith("ibkr");
    expect(screen.queryByRole("link", { name: "Open authorization link" })).toBeNull();
  });

  it("rejects credentials and fragments in the OAuth URL before opening", async () => {
    const api = apiFixture({
      connect: vi.fn(async (): Promise<ApiResult<ConnectInitiateV1>> => ({
        ok: true,
        data: {
          provider_id: "ibkr", environment: "PAPER", auth_method: "oauth",
          authorization_url: "https://user:password@auth.ibkr.example/authorize#token",
          authorization_host: "auth.ibkr.example", redirect_uri: "http://127.0.0.1:43125/callback",
          state: "A".repeat(43), expires_at_ns: String((Date.now() + 120_000) * 1_000_000),
          single_use: true, request_id: "request-3",
        },
      })),
    });
    const opener = { open: vi.fn(async () => "unavailable" as const) };
    await renderLoaded({ api, externalUrlOpener: opener });
    fireEvent.click(screen.getAllByRole("button", { name: "Connect" })[0]!);
    expect(await screen.findByRole("alert")).toBeTruthy();
    expect(opener.open).not.toHaveBeenCalled();
  });

  it("routes key-based providers to credential entry without rendering a handle or a secret form", async () => {
    const api = apiFixture({
      connect: vi.fn(async (provider: ConnectionProviderId): Promise<ApiResult<ConnectInitiateV1>> => ({
        ok: true,
        data: { provider_id: provider, environment: "PAPER", auth_method: "api_key", credential_entry_handle: "opaque-handle-marker" },
      })),
    });
    await renderLoaded({ api });
    fireEvent.click(screen.getAllByRole("button", { name: "Open credential entry" })[0]!);
    expect((await screen.findByRole("link", { name: /credential entry/ })).getAttribute("href")).toBe("#LIVE");
    expect(document.body.textContent).not.toContain("opaque-handle-marker");
    expect(screen.queryByLabelText(/secret|api key|password/i)).toBeNull();
  });

  it("disables new LIVE connections", async () => {
    await renderLoaded({ api: apiFixture({ getStatus: vi.fn(async (): Promise<ApiResult<ConnectionsStatusV1>> => ({ ok: true, data: status("LIVE") })) }) });
    expect(screen.getAllByRole("button", { name: "Connect" }).every((button) => (button as HTMLButtonElement).disabled)).toBe(true);
    expect(screen.getByText(/Starting Live connections is disabled in this terminal\./)).toBeTruthy();
  });

  it("keeps LIVE initiation disabled while allowing cancellation and disconnection", async () => {
    const liveStatus: ConnectionsStatusV1 = {
      connections: providerIds.map((provider) => ({
        provider_id: provider,
        environment: "LIVE",
        state: provider === "ibkr" ? "PENDING" : provider === "alpaca" ? "CONNECTED" : "DISCONNECTED",
        configured: provider === "alpaca",
      })),
    };
    await renderLoaded({ api: apiFixture({
      getStatus: vi.fn(async (): Promise<ApiResult<ConnectionsStatusV1>> => ({ ok: true, data: liveStatus })),
    }) });
    expect(screen.getAllByRole("button", { name: "Connect" }).every((button) => (button as HTMLButtonElement).disabled)).toBe(true);
    expect((screen.getByRole("button", { name: "Cancel" }) as HTMLButtonElement).disabled).toBe(false);
    expect((screen.getByRole("button", { name: "Disconnect" }) as HTMLButtonElement).disabled).toBe(false);
  });
  it("does not echo API error payloads and marks service unavailability", async () => {
    const fetcher = vi.fn(async () => new Response(JSON.stringify({ detail: "credential=synthetic-secret" }), { status: 503 }));
    const api = createConnectionsApi(fetcher as typeof fetch);
    const result = await api.getCatalog();
    expect(result).toEqual({ ok: false, error: "CONNECTIONS_UNAVAILABLE" });
    expect(JSON.stringify(result)).not.toContain("synthetic-secret");
    render(<ConnectionsView api={apiFixture({
      getCatalog: vi.fn(async (): Promise<ApiResult<ConnectionsCatalogV1>> => ({ ok: false, error: "CONNECTIONS_UNAVAILABLE" })),
    })} />);
    expect((await screen.findByRole("alert")).textContent).toContain("Connection service unavailable.");
  });

  it("fails closed with the default external opener and never navigates automatically", async () => {
    const api = apiFixture();
    const open = vi.spyOn(window, "open").mockImplementation(() => null);
    await renderLoaded({ api });
    expect(open).not.toHaveBeenCalled();
    expect(await (await import("../model")).createFailClosedExternalUrlOpener().open(new URL("https://auth.ibkr.example/")))
      .toBe("unavailable");
    expect(window.open).not.toHaveBeenCalled();
  });
  it("sends only credential-free methods to the frozen API routes", async () => {
    const fetcher = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) =>
      new Response(JSON.stringify({ providers: [] }), { status: 200 }));
    const api = createConnectionsApi(fetcher as typeof fetch);
    await api.getCatalog();
    await api.connect("ibkr");
    await api.cancel("ibkr");
    await api.disconnect("ibkr");
    expect(fetcher).toHaveBeenNthCalledWith(1, "/api/connections/catalog", expect.objectContaining({
      headers: { Accept: "application/json" },
    }));
    expect(fetcher).toHaveBeenNthCalledWith(2, "/api/connections/ibkr/connect", expect.objectContaining({ method: "POST" }));
    expect(fetcher).toHaveBeenNthCalledWith(3, "/api/connections/ibkr/cancel", expect.objectContaining({ method: "POST" }));
    expect(fetcher).toHaveBeenNthCalledWith(4, "/api/connections/ibkr/disconnect", expect.objectContaining({ method: "POST" }));
    expect(fetcher.mock.calls.slice(1).every(([, init]) => init?.body === undefined)).toBe(true);
    expect(JSON.stringify(fetcher.mock.calls)).not.toContain("credential");
  });
});
